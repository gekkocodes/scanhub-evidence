#!/usr/bin/env python3
"""CI precision gate: the rule corpus must produce ZERO findings on the clean
fixture (_fixtures/clean), which holds safe forms mirroring each rule
family's vulnerable shape. A finding here means a rule fires on correct code
- a false positive that would burn customer trust. This is the zero-FP
contract; the smoke gate proves the rules still fire, this gate proves they
do not fire when they should not.

Usage: python3 ops/ci_precision_gate.py   (from repo root)
"""
import json, subprocess, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules")
FIXTURE = os.path.join(ROOT, "_fixtures", "clean")

# OPENGREP_BIN runs a local opengrep binary instead of the sibling container
# (act workspaces are named volumes; nested `-v` mounts see an empty tree).
_local = os.environ.get("OPENGREP_BIN")
if _local:
    p = subprocess.run(
        [_local, "--quiet", "--json", "--config", RULES, FIXTURE],
        capture_output=True, text=True, timeout=600)
else:
    p = subprocess.run(
        ["docker", "run", "--rm",
         "-v", RULES.replace("\\", "/") + ":/rules:ro",
         "-v", FIXTURE.replace("\\", "/") + ":/src:ro",
         "ipvsix/opengrep:latest", "--quiet", "--json", "--config=/rules", "/src"],
        capture_output=True, text=True, timeout=600)
try:
    d = json.loads(p.stdout)
except Exception as e:
    print("no JSON from opengrep:", e)
    print((p.stderr or "")[-2000:])
    sys.exit(1)
errs = [e for e in d.get("errors", []) if "parse error" in str(e).lower()]
if errs:
    for e in errs:
        print("RULE PARSE ERROR:", e.get("rule_id"), str(e.get("message"))[:200])
    sys.exit(1)
results = d.get("results", [])
if results:
    print(f"FAIL: {len(results)} false positive(s) on clean fixture:")
    for r in results:
        loc = r["path"] + ":" + str(r["start"]["line"])
        print("  ", r["check_id"].split(".")[-1], loc,
              r["extra"].get("lines", "").strip()[:90])
    sys.exit(1)
print("precision gate OK: 0 findings on clean fixture")
