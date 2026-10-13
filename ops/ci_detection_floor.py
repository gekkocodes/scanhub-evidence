#!/usr/bin/env python3
"""CI gate (issue #26): detection floor on a pinned benchmark app.

The rules-gate proves rules PARSE; this proves they still DETECT. It runs the
rule corpus directly (OpenGrep, same engine the worker uses) over the pinned
benchmark app source and fails the build when:

  1. total findings drop below the floor, or
  2. any rule that fired in the committed evidence pack stops firing.

Unlike ops/benchmark.py this needs no running ScanHub server, so it works in
plain CI. The floor pack (evidence/juice-shop-floor.json, OpenGrep scope only -
the full-pipeline pack lives in juice-shop-latest.json) is rebaselined
deliberately, never implicitly by CI: run this script with --rebaseline from
a trusted machine (the CI image works: docker run scanhub-ci ... python3
ops/ci_detection_floor.py --rebaseline), review the diff, commit the pack.

Usage: python3 ops/ci_detection_floor.py [--app juice-shop] [--rebaseline]
Requires: docker (or OPENGREP_BIN), network access to codeload.github.com.
"""
import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules")
EVIDENCE = os.path.join(ROOT, "evidence", "juice-shop-floor.json")

# Pinned app sources (master is fine for a floor gate: the floor is derived
# from the committed pack, and drift shows up as a floor miss to triage).
APPS = {
    "juice-shop": "https://codeload.github.com/juice-shop/juice-shop/tar.gz/refs/heads/master",
}

# Mirror of the production SCAN_EXCLUDE default (internal/config/config.go).
EXCLUDES = ("test,tests,__tests__,spec,cypress,fixtures,codefixes,"
            "node_modules,dist,build,coverage,vendor,minified,.git")

FLOOR_RATIO = 0.9  # total findings may not drop below 90% of the pack


def log(msg):
    print(f"[floor] {msg}", flush=True)


def get_source(app, dest):
    url = APPS[app]
    raw = urllib.request.urlopen(url, timeout=600).read()
    log(f"{app} archive: {len(raw)} bytes sha256={hashlib.sha256(raw).hexdigest()[:16]}")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile() or "/node_modules/" in m.name:
                continue
            member_f = tf.extractfile(m)
            if member_f is None:
                continue
            out = os.path.join(dest, m.name)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with member_f, open(out, "wb") as f:
                f.write(member_f.read())
    return dest


def run_opengrep(src_dir):
    _local = os.environ.get("OPENGREP_BIN")
    if _local:
        # Local binary mode: inside act the workspace is a named volume, so
        # nested `-v` host-path mounts would see an empty tree.
        cmd = [_local, "--quiet", "--json", "--config", RULES,
               *[f"--exclude={x}" for x in EXCLUDES.split(",")], src_dir]
    else:
        cmd = ["docker", "run", "--rm",
               "-v", RULES.replace("\\", "/") + ":/rules:ro",
               "-v", src_dir.replace("\\", "/") + ":/src:ro",
               "ipvsix/opengrep:latest", "--quiet", "--json", "--config=/rules",
               *[f"--exclude={x}" for x in EXCLUDES.split(",")], "/src"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    try:
        d = json.loads(p.stdout)
    except Exception:
        log("no JSON from opengrep:")
        print((p.stderr or "")[-2000:])
        sys.exit(1)
    if not d.get("results"):
        # Diagnostic: an empty scan in seconds means wrong mode or empty tree.
        n_src = sum(len(fs) for _, _, fs in os.walk(src_dir))
        n_rules = len([f for f in os.listdir(RULES) if f.endswith((".yaml", ".yml"))])
        log(f"DIAG mode={'local' if _local else 'sibling'} src={src_dir} "
            f"files={n_src} rulefiles={n_rules} rc={p.returncode}")
        log("DIAG stderr tail: " + (p.stderr or "")[-500:])
    errs = [e for e in d.get("errors", []) if "parse error" in str(e).lower()]
    if errs:
        for e in errs:
            log(f"RULE PARSE ERROR: {e.get('rule_id')}")
        sys.exit(1)
    return d.get("results", [])


def rule_id(rule):
    # Engine prefixes rule ids with the config dir ("rules.sh-..."); keep the
    # bare id so pack and CI counts speak the same language.
    return rule.rsplit(".", 1)[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="juice-shop", choices=sorted(APPS))
    ap.add_argument("--rebaseline", action="store_true",
                    help="write the current scan to the evidence pack and exit")
    args = ap.parse_args()

    pack_path = EVIDENCE if args.app == "juice-shop" else \
        os.path.join(ROOT, "evidence", f"{args.app}-latest.json")
    if os.path.exists(pack_path):
        pack = json.load(open(pack_path, encoding="utf-8"))
        baseline = Counter(rule_id(f["rule"]) for f in pack["findings"]
                           if f.get("engine", "opengrep") == "opengrep")
        log(f"baseline pack: {sum(baseline.values())} findings, {len(baseline)} rules")
    elif args.rebaseline:
        baseline = Counter()
        log("no existing pack; rebaselining from scratch")
    else:
        print(f"no evidence pack at {pack_path}")
        sys.exit(1)

    # Temp dir placement depends on the OpenGrep mode. Sibling-container mode
    # needs the path INSIDE the repo workspace (the -v mount resolves on the
    # daemon host). Local-binary mode must use system temp instead: _ci_work
    # is gitignored, and OpenGrep honors .gitignore, so a workspace temp dir
    # gets every file skipped (silent 0 findings).
    if os.environ.get("OPENGREP_BIN"):
        td = tempfile.TemporaryDirectory()
    else:
        work = os.path.join(ROOT, "_ci_work")
        os.makedirs(work, exist_ok=True)
        td = tempfile.TemporaryDirectory(dir=work)
    with td:
        src = get_source(args.app, td.name)
        results = run_opengrep(src)
        if args.rebaseline:
            entries = []
            for r in sorted(results, key=lambda r: (r.get("path", ""),
                                                    (r.get("start") or {}).get("line", 0))):
                extra = r.get("extra", {})
                cwe = (extra.get("metadata") or {}).get("cwe", "")
                if isinstance(cwe, list):
                    cwe = cwe[0] if cwe else ""
                sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
                    extra.get("severity", ""), (extra.get("severity") or "unknown").lower())
                entries.append({
                    "rule": r.get("check_id", r.get("rule_id", "")),
                    "severity": sev,
                    "cwe": str(cwe).lower(),
                    "title": rule_id(r.get("check_id", "")),
                    "message": (extra.get("message") or "").strip(),
                    "file": os.path.relpath(r.get("path", ""), src).replace("\\", "/"),
                    "line": (r.get("start") or {}).get("line", 0),
                    "engine": "opengrep",
                    "verdict": "unreviewed",
                })
            out = {"app": args.app, "generated": __import__("datetime").date.today().isoformat(),
                   "count": len(entries), "findings": entries}
            with open(pack_path, "w", encoding="utf-8") as fh:
                json.dump(out, fh, indent=1)
            log(f"REBASELINED {pack_path}: {len(entries)} findings, "
                f"{len(set(e['rule'] for e in entries))} rules")
            return
    now = Counter(rule_id(r.get("check_id", r.get("rule_id", ""))) for r in results)
    total = sum(now.values())
    log(f"current scan: {total} findings, {len(now)} rules")

    failures = []
    floor = int(sum(baseline.values()) * FLOOR_RATIO)
    if total < floor:
        failures.append(f"total {total} below floor {floor} (pack {sum(baseline.values())})")
    for rule, n in sorted(baseline.items()):
        if now.get(rule, 0) == 0:
            failures.append(f"rule {rule} fired {n}x in pack, now 0")
    if failures:
        print("DETECTION FLOOR FAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    new = [r for r in now if r not in baseline]
    log(f"floor OK ({total} >= {floor}); every pack rule still fires"
        + (f"; new rules firing: {', '.join(sorted(new))}" if new else ""))


if __name__ == "__main__":
    main()
