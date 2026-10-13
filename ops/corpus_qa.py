#!/usr/bin/env python3
"""Corpus QA: print the ground-truth lines as they exist in the vuln_tag
checkout. If the lines are unrelated to the CWE (e.g. session middleware for
an open-redirect advisory), the entry's tag or truth is broken and it must not
count in any score. Usage: python ops/corpus_qa.py [--id GHSA-xxx]"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

corpus = json.load(open(os.path.join(ROOT, "bench", "corpus.json"), encoding="utf-8"))
only = sys.argv[sys.argv.index("--id") + 1] if "--id" in sys.argv else None

for e in corpus:
    if only and e["id"] != only:
        continue
    src = os.path.join(ROOT, e["src"])
    subprocess.run(["git", "-C", src, "checkout", "-q", e["vuln_tag"]], capture_output=True)
    head = subprocess.run(["git", "-C", src, "log", "--oneline", "-1"], capture_output=True, text=True).stdout.strip()
    print("=" * 70)
    print(e["id"], e["cwe"], "tag:", e["vuln_tag"], "| head:", head)
    for t in e.get("truth", [])[:3]:
        p = os.path.join(src, t["file"])
        if not os.path.exists(p):
            print("  MISSING:", t["file"])
            continue
        lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
        for lo, hi in t.get("lines", [])[:3]:
            frag = " / ".join(lines[i - 1].strip() for i in range(max(1, lo), min(len(lines), hi) + 1))
            print(f"  {t['file']}:{lo}-{hi}: {frag[:150]}")
