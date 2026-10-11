# ScanHub Bench — CVE replay benchmark

The headline benchmark: real CVEs in pinned vulnerable versions of popular
open-source packages. Ground truth comes from the upstream fix commits, not
from us, so nobody can accuse ScanHub of benchmark-fitting a toy app.

## How it works

1. `ops/corpus_build.py` reads a hand-verified seed list (advisory IDs checked
   against live OSV data), clones each package repo, resolves the fixed
   version tag, and diffs the previous release against the fix. The changed
   source files + line ranges become the ground truth for that CVE.
2. `ops/replay_score.py` checks out each **vulnerable** tag, runs the ScanHub
   rule corpus through OpenGrep (identical engine + rules as production),
   and scores: a finding is a TRUE POSITIVE when it lands within +/-5 lines
   of a ground-truth range in the right file (CWE class must match; CWE
   mismatch counts as weak).
3. Output: `bench/replay-<date>.json` with a per-entry matrix and an
   explicit ENGINE GAPS list: every CVE where no rule fired at the fix site.
   The gap list is the work queue for rule development.

## Commands

```bash
python ops/corpus_build.py            # build/refresh bench/corpus.json
python ops/replay_score.py            # score the whole corpus
python ops/replay_score.py --only GHSA-...   # one entry
```

## Why this beats a single vulnerable app

- Real production code, not challenge-code (this is what customers ship).
- Multi-language: JavaScript, Python, Go today; Ruby/Java/PHP seedable.
- Ground truth authored by the security research community (GHSA/OSV).
- Infinitely extensible: every new CVE is a candidate test case.

## Honesty rules

- The seed list is committed; corpus refreshes must not silently swap entries.
- A rule written AFTER seeing a miss still counts as detected in the run it
  fires; the replay JSON records rule names so audits can trace provenance.
- We publish misses. The gap list ships with the score.

## Round 2: application-level corpus (Gitea)

Corpus pivoted from library-internal CVEs to application-level ones (Gitea
advisories), where vulnerable code lives in request handlers a SAST engine
can actually see. Ground truth upgraded to PR-resolved fix commits where the
advisory carries a PR reference (3 of 6 entries), with test/vendor paths
filtered out.

Result: 0/6 detected, 1 weak-only (coincidental file overlap, not a real
catch). This is the honest, reproducible number.

What the misses teach us:

1. Multi-layer dataflow. Every Gitea fix adds validation between a request
   value and a sink (git argv, redirect target, template render) across
   function boundaries. Pattern-based matching (OpenGrep) sees shapes in one
   or two adjacent statements; it cannot follow request data through
   structs, helpers, and middleware. This is a taint-analysis gap, not a
   rule-writing gap. More patterns will not close it.
2. Ground-truth quality matters. Two entries fall back to tag-to-tag diffs
   (hundreds of changed files), which inflates weak hits with coincidences.
   PR-resolved truth is the standard; entries without PR refs are marked
   truth_mode=tagdiff and should be weighted lower.
3. The benchmark is doing its job: it tells us the ceiling of the current
   engine and points at exactly what to build next.

Roadmap consequence: the headline path to replay TPR is a taint engine.
Joern (Apache 2.0, license-compliant) models CPG dataflow and is the planned
addition (roadmap engine track). Pattern rules stay valuable for the shapes
they do catch (direct SQL concat, exec with request data, template.HTML
casts - see rules/go-web.yaml, all fixture-validated).

## Round 2 results (2026-10-11): breadth beyond Go

Corpus expanded to 12 entries (Django x3, Express x2, marked x1 added).
Score: **0/12 detected, +2 weak-only** (after the scorer fix below).

The first run reported 1 TP (Django CVE-2014-3730 open redirect), but auditing
it showed coincidental file overlap: the rules that fired
(`sh-python-hardcoded-secret`, `sh-python-subprocess-shell-true`) were not
detecting the redirect flaw, they just landed on a ground-truth file with no
CWE info, and the old TP criteria passed CWE-less findings. The scorer now
requires an EXPLICIT CWE match for TP. Honest reading: pattern matching has
not yet caught a replay CVE by its actual flaw shape, in any language.

Round-2 misses share the round-1 diagnosis: the framework fixes are
validation-logic changes (is_safe_url hardening, redirect normalization,
template escaping) whose vulnerable shape is the ABSENCE of a check, not the
presence of a matchable pattern. Pattern rules fundamentally cannot express
"this redirect lacks validation."

Joern follow-up (same day, issue #32): the taint engine does not rescue this
either today. Intra-procedural Go taint works, but inter-procedural field
tracking returns 0 flows on the CVE shapes, and the Python frontend is broken
in-image. See docs/joern-spike.md.

Honest positioning (unchanged, now better evidenced): ScanHub's detection
claims rest on the coverage + precision tiers (Juice Shop 84, PyGoat 450,
4 audited FPs), NOT on replay TPR. The replay corpus stays published as the
engine-gap radar and as proof we measure ourselves against real CVEs.
