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
| `evidence/replay-*.json` + `evidence/corpus.json` + `docs/bench-replay.md` | The CVE replay corpus: real CVEs in pinned versions, scored against our rules, published even though the score is low (it is our gap radar, not a detection claim) |
| `ops/corpus_build.py`, `ops/replay_score.py`, `ops/corpus_qa.py` | The replay pipeline: build the corpus from OSV + fix commits, QA the ground truth, score TPR |

## Headline numbers (verified 2026-10-13)

- **177 findings** on OWASP Juice Shop (20 critical, 69 high, 48 medium, 40 low) = 82 OpenGrep + 89 Trivy dependency advisories + 6 Gitleaks secrets, zero fixture noise
- **450 findings** on PyGoat across 4 engines (OSV, bandit, opengrep, gitleaks)
- **106 original rules**, MIT-licensed, written from scratch (no restricted third-party rule content)
- **CI detection floor**: every push re-scans the pinned app; total below 90% of the committed floor pack (`evidence/juice-shop-floor.json`, 126 findings / 32 rules, OpenGrep scope) or any pack rule dropping to zero fails the build
- **4 candidate false positives** across ScanHub's own codebase under the precision tier, all audited as contextual (the code is safe in context)
- **CVE replay: 1/13 detected** (round 5; 13 QA'd entries across Gitea, Django, Express, marked, serve-static; rounds 3-4 scored 0/13, then targeted rules written from the published miss list moved the number: `gap601` now catches Gitea GHSA-36h2-95gj-w488 with 4 true positives at the fix-commit coordinates). The remaining 12 misses are framework-internal or absence-of-validation fixes that pattern rules structurally cannot reach; we publish this instead of hiding it. The replay corpus is a gap radar that demonstrably closes, not a detection claim. Detection claims rest on the coverage and precision tiers.

## Reproduce it

```
python ops/benchmark.py --url <your-instance> --token <api-token> --app juice-shop
python ops/corpus_build.py && python ops/corpus_qa.py && python ops/replay_score.py
```

The harness pins the benchmark app by SHA-256, uploads it through the public API, waits for the scan, and dumps a findings pack identical to the ones in `evidence/`. If our numbers don't reproduce on your instance, that's a bug and we want to hear about it.

## Why this exists

Anyone can claim "our scanner finds thousands of vulnerabilities." ScanHub publishes the exact inputs, the exact tool invocation, and the full output, including the parts that are unflattering (see the replay-corpus honesty section in `docs/`). If you're evaluating a SAST vendor, ask them for the same.
