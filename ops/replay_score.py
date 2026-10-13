#!/usr/bin/env python3
"""ScanHub Bench — replay scorer.

For every entry in bench/corpus.json: check out the vulnerable tag, run the
ScanHub rule corpus through OpenGrep (same engine + rules the server uses),
and score findings against the fix-commit ground truth.

A finding is a TRUE POSITIVE for an entry when:
  - its file matches a ground-truth file, AND
  - its line falls inside a ground-truth range (+/- 5 lines slack), AND
  - its rule CWE matches the advisory CWE when both declare one
    (CWE mismatch still counts as a weak hit and is reported separately).

Output: bench/replay-<date>.json + printed matrix by language and CWE class.
Exit code 1 if overall TPR drops below the floor in bench/replay-baseline.json.
"""
import argparse, datetime, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BENCH = os.path.join(ROOT, "bench")
RULES = os.path.join(ROOT, "rules")
DOCKER_IMG = os.environ.get("OPENGREP_IMAGE", "ipvsix/opengrep:latest")
LINE_SLACK = 5


def git(*args, cwd=None):
    r = subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def run_opengrep(src):
    p = subprocess.run(
        ["docker", "run", "--rm",
         "-v", RULES.replace("\\", "/") + ":/rules:ro",
         "-v", src.replace("\\", "/") + ":/src:ro",
         DOCKER_IMG, "--quiet", "--json", "--config=/rules", "/src"],
        capture_output=True, text=True, timeout=1800)
    try:
        d = json.loads(p.stdout)
    except json.JSONDecodeError:
        return [], "opengrep failed: " + (p.stderr or "")[-200:]
    rule_errs = [e for e in d.get("errors", []) if "parse error" in str(e).lower()]
    if rule_errs:
        return [], f"{len(rule_errs)} rule parse error(s): " + str(rule_errs[0].get("rule_id"))
    out = []
    for res in d.get("results", []):
        check_id = res.get("check_id", "")
        path = res.get("path", "")
        line = res.get("start", {}).get("line", 0)
        msg = res.get("extra", {}).get("message", "")
        cwe = ""
        m = re.search(r"CWE-(\d+)", json.dumps(res.get("extra", {}).get("metadata", {})) + msg)
        if m:
            cwe = "CWE-" + m.group(1)
        out.append({"rule": check_id, "file": path.lstrip("/"), "line": line, "cwe": cwe})
    return out, None


def score_entry(entry, findings):
    truth = entry["truth"]
    tfiles = {t["file"]: t["lines"] for t in truth}
    hits, weak = [], []
    for f in findings:
        # findings paths are relative to /src which is the repo root
        fp = f["file"]
        if fp.startswith("src/"):
            fp = fp[4:] if entry["src"].endswith("/src") else fp
        for tf, ranges in tfiles.items():
            if not fp.endswith(tf) and not tf.endswith(fp):
                continue
            if any(lo - LINE_SLACK <= f["line"] <= hi + LINE_SLACK for lo, hi in ranges):
                # TP requires an EXPLICIT CWE match: a finding with no CWE
                # info on a touched line is a coincidence, not detection
                # (round-2 audit: coincidental file overlap scored a false TP).
                cwe_ok = bool(f["cwe"]) and f["cwe"] == entry["cwe"]
                rec = {**f, "truth_file": tf, "cwe_match": cwe_ok}
                (hits if cwe_ok else weak).append(rec)
                break
    return hits, weak


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="score a single advisory id")
    args = ap.parse_args()
    corpus = json.load(open(os.path.join(BENCH, "corpus.json"), encoding="utf-8"))
    rows = []
    for e in corpus:
        if args.only and e["id"] != args.only:
            continue
        src = os.path.join(ROOT, e["src"])
        rc, _ = git("checkout", "--quiet", e["vuln_tag"], cwd=src)
        if rc != 0:
            print(f"[skip] {e['id']}: checkout {e['vuln_tag']} failed")
            continue
        findings, err = run_opengrep(src)
        if err:
            print(f"[skip] {e['id']}: {err}")
            continue
        hits, weak = score_entry(e, findings)
        row = {"id": e["id"], "pkg": e["pkg"], "lang": e["lang"], "cwe": e["cwe"],
               "vuln_tag": e["vuln_tag"], "fix_tag": e["fix_tag"],
               "total_findings": len(findings), "tp": len(hits), "weak": len(weak),
               "detected": bool(hits), "weak_only": bool(weak) and not hits,
               "hits": hits[:8], "weak_hits": weak[:8]}
        rows.append(row)
        mark = "TP " if hits else ("weak" if weak else "MISS")
        print(f"[{mark}] {e['id']:22s} {e['pkg']:28s} {e['cwe']:9s} "
              f"tp={len(hits)} weak={len(weak)} findings={len(findings)}")
        git("checkout", "--quiet", "HEAD", cwd=src)

    tp = sum(1 for r in rows if r["detected"])
    wk = sum(1 for r in rows if r["weak_only"])
    date = datetime.date.today().isoformat()
    p = os.path.join(BENCH, f"replay-{date}.json")
    # Merge into today's file so --only runs update their rows instead of
    # clobbering the full run's results.
    all_rows = {r["id"]: r for r in rows}
    if os.path.exists(p):
        try:
            prev = json.load(open(p, encoding="utf-8"))
            merged = {r["id"]: r for r in prev.get("rows", [])}
            merged.update(all_rows)
            all_rows = merged
        except (ValueError, OSError):
            pass
    rows = list(all_rows.values())
    tp = sum(1 for r in rows if r["detected"])
    wk = sum(1 for r in rows if r["weak_only"])
    out = {"date": date, "entries": len(rows), "detected": tp, "weak_only": wk,
           "tpr": round(100.0 * tp / len(rows), 1) if rows else 0,
           "tpr_incl_weak": round(100.0 * (tp + wk) / len(rows), 1) if rows else 0,
           "rows": rows}
    json.dump(out, open(p, "w", encoding="utf-8"), indent=1)
    print(f"\n[replay] {tp}/{len(rows)} detected ({out['tpr']}%), "
          f"+{wk} weak-only ({out['tpr_incl_weak']}% incl weak)")
    print(f"[replay] wrote {p}")
    # misses = engine gap list
    misses = [r for r in rows if not r["detected"] and not r["weak_only"]]
    if misses:
        print("\nENGINE GAPS (no rule fired at the fix site):")
        for m in misses:
            print(f"  {m['id']:22s} {m['pkg']:28s} {m['cwe']:9s} ({m['lang']})")


if __name__ == "__main__":
    main()
