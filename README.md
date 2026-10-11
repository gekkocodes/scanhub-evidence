# THL ScanHub - Detection Evidence (public mirror)

Reproducible detection evidence for [THL ScanHub](https://thehackinglab.com), the independent verifier for AI-generated code.

Every claim ScanHub makes about detection comes from this repo. No curated screenshots, no cherry-picked demos: pinned vulnerable applications, committed evidence packs, and a harness you can run yourself.

## What's here

| Path | What it is |
|---|---|
| `evidence/` | Full findings packs (JSON + Markdown) from benchmark runs, one per app per date |
| `ops/benchmark.py` | The harness: public REST API only, SHA-256-pinned app archive, regression gate |
| `docs/detection-evidence.md` | The proof chain and the honest "what we do NOT claim" section |
| `docs/benchmark-architecture.md` | The 3-tier benchmark design: replay, coverage, precision |
| `evidence/replay-*.json` + `docs/bench-replay.md` | The CVE replay corpus: real CVEs in pinned versions, scored against our rules, published even though the score is low (it is our gap radar, not a detection claim) |

## Headline numbers (verified 2026-10-11)

- **84 findings** on OWASP Juice Shop (48 high, 36 medium), main-source only, zero fixture noise
- **450 findings** on PyGoat across 4 engines (OSV, bandit, opengrep, gitleaks)
- **69 original rules**, MIT-licensed, written from scratch (no restricted third-party rule content)
- **4 candidate false positives** across ScanHub's own codebase under the precision tier, all audited as contextual (the code is safe in context)

## Reproduce it

```
python ops/benchmark.py --url <your-instance> --token <api-token> --app juice-shop
```

The harness pins the benchmark app by SHA-256, uploads it through the public API, waits for the scan, and dumps a findings pack identical to the ones in `evidence/`. If our numbers don't reproduce on your instance, that's a bug and we want to hear about it.

## Why this exists

Anyone can claim "our scanner finds thousands of vulnerabilities." ScanHub publishes the exact inputs, the exact tool invocation, and the full output, including the parts that are unflattering (see the replay-corpus honesty section in `docs/`). If you're evaluating a SAST vendor, ask them for the same.
