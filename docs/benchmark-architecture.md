# Benchmark Architecture (three tiers)

Status: all three tiers operational as of 2026-10-11.

ScanHub's detection claims rest on three independent measurements. Each tier
answers a different objection a security reviewer will raise.

## Tier 1 - Coverage (does it find real vulns?)

Two vulnerable-app benchmarks, run through the full product pipeline
(`ops/benchmark.py`, public REST API only, SHA-256-pinned sources):

| Target | Stack | Findings | Notes |
|---|---|---|---|
| OWASP Juice Shop | Node/Angular | 84 | main-source only, zero fixture noise |
| PyGoat | Django/Python | 450 | 265 OSV dep CVEs + 62 bandit + 18 opengrep + 3 gitleaks |

Different languages, frameworks, and codebases: this kills the
"tuned to one app" objection.

## Tier 2 - Replay (does it find *known* CVEs?)

`ops/corpus_build.py` + `ops/replay_score.py`: real CVEs pinned at
vulnerable versions, ground truth from upstream fix commits (PR-resolved).
Scored per CWE class. Current Gitea round: 0/6 - pattern matching cannot
follow request data across functions. This honest ceiling is what drives
the taint-engine roadmap (issue #32, Joern spike in progress).

## Tier 3 - Precision (does it stay quiet on clean code?)

`ops/precision_score.py` runs the rule corpus over clean codebases and
counts every finding as a candidate false positive for triage.

Current measurement (2026-10-11), ScanHub's own audited source
(~30K lines Go+JS, `cmd/` + `internal/`): **4 candidate FPs, 0 true
positives.** All four are contextual: `template.JS` casts of
server-generated JSON (no user input reaches them) and one `innerHTML`
of a server-rendered partial. The rules fire as "review this" warnings;
none is a real vulnerability.

A vendor that publishes only detection counts is telling half the story.
The precision half is what makes the detection half believable.

## Cross-tool comparison (planned)

The most credible artifact a SAST vendor can publish is a cross-tool
matrix: same pinned corpus, ScanHub vs Semgrep CE vs CodeQL vs Joern,
per-CWE TPR + FP counts, all reproducible. Blocked on: public evidence
mirror (issue #28) and the Joern engine (issue #32).

## Reproducing

```
python ops/benchmark.py --app juice-shop --email ... --password ...
python ops/benchmark.py --app pygoat --email ... --password ...
python ops/replay_score.py
python ops/precision_score.py
```

Evidence packs land in `evidence/` with build + engine + source-hash
fingerprints. The CI gate (`.gitea/workflows/ci.yml`) fails the build on
rule parse errors, smoke-fixture detection drops, or corpus corruption.
