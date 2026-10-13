#!/usr/bin/env python3
"""CI gate (issue #26): the rule corpus must parse cleanly and keep firing on
the smoke fixture. A single unparseable rule can silently zero an entire scan
(observed in production), so any parse error fails the build.

Usage: python3 ops/ci_rules_check.py   (from repo root, docker required)
"""
import json, subprocess, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules")
FIXTURE = os.path.join(ROOT, "_fixtures", "rules-smoke")
MIN_FINDINGS = 30

# OPENGREP_BIN runs a local opengrep binary instead of the sibling container:
# inside act the workspace is a named volume, so `-v` host-path mounts from a
# nested container would see an empty tree.
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
n = len(d.get("results", []))
print(f"rules parse OK, smoke findings: {n}")
if n < MIN_FINDINGS:
    print(f"FAIL: smoke fixture must produce >= {MIN_FINDINGS} findings (corpus regression?)")
    sys.exit(1)
