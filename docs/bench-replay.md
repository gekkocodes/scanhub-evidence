# ScanHub Bench — CVE replay benchmark

The headline benchmark: real CVEs in pinned vulnerable versions of popular
open-source packages. Ground truth comes from the upstream fix commits, not
from us, so nobody can accuse ScanHub of benchmark-fitting a toy app.

## How it works

1. `ops/corpus_build.py` reads a hand-verified seed list (advisory IDs checked
   against live OSV data), clones each package repo, resolves the EARLIEST
   fixed version tag, extracts the '-' (pre-fix) line texts from the fix
   diff, and locates them by text search in the vulnerable-tag checkout.
   Those located ranges are the ground truth for that CVE. `ops/corpus_qa.py`
   prints them for human verification (see the integrity fix below).
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

## Ground-truth integrity fix (2026-10-13)

QA (`ops/corpus_qa.py`) found the corpus ground truth was broken: truth
ranges came from fix-PR hunk headers, which are coordinates in the PR's BASE
file, not the vulnerable tag. Backported fixes shift every line; the ranges
landed on docstrings, version bumps, and unrelated middleware. Worse,
multi-line advisories (express) pinned the LAST fixed version, so the
"vulnerable" tag already contained the backported fix - the vulnerable code
was not even in the tree. Every replay number above this line was computed
on broken truth and is VOID as a detection measurement (the qualitative
diagnosis - multi-layer dataflow gap - still holds, but the numbers cannot
be cited).

Rebuild rules now enforced by `ops/corpus_build.py`:
1. Truth = the '-' (pre-fix) line TEXTS from the fix diff, located by exact
   stripped-text search in the vulnerable checkout. Unlocatable lines are
   dropped; generic lines (<12 chars, <8 alnum, or >20 matches) are skipped.
2. Multi-line advisories pin the EARLIEST fixed version (express now
   4.19.1 -> 4.19.2, where `res.location` really is vulnerable).
3. tagdiff truth broader than 50 files is rejected outright (one Gitea
   release diff touched 847 files - any same-CWE finding anywhere would
   have scored as a TP).
4. `ops/corpus_qa.py` prints every located line for human verification;
   the rebuilt truth points at the actual vulnerable calls (express
   `lib/response.js:908`, Django `is_safe_url` netloc check, Gitea
   `SaveAddress(form.MirrorAddress)`).

## LLM reachability probe (2026-10-13)

Question: can a single-shot LLM audit close the taint gap the pattern engine
cannot? `ops/reach_probe.py` gives the halogen Qwen node the ground-truth
file plus decoy files from the same tree and demands a structured verdict
(file, line, source->sink flow). Hit = named line inside a ground-truth
range; weak = right file, wrong line; file-level TPR = hit + weak (the
production-relevant number: the shipped artifact is the verdict + trace).

On the corrected corpus, blind mode: **0 exact hits, 2 weak, 16.7%
file-level**. CWE-hinted mode was no better (the "reject unless genuinely
exploitable" instruction made the model conservative: it returned
`vulnerable: false` with high confidence on real CVEs). Solo mode (no
decoys) similar.

Verdict: NOT wired into the worker. When the model commits to a finding the
traces are qualitatively right (it found marked's link-renderer XSS class
and express's res.location flow by name), but recall is too low and
confidence is miscalibrated in both directions. A single-shot file audit is
not a taint engine. The gap stays open honestly: inter-procedural dataflow
remains the missing engine, and neither Joern (spike parked) nor single-shot
LLM closes it today.

## Round 3: corrected-corpus re-score (2026-10-13)

Scored the rebuilt corpus (ground-truth fix above) with the tightened TP
criteria (explicit CWE match required). Seed set also grew: two Django
SQLi advisories (CWE-89 was previously unrepresented) and serve-static's
redirect XSS; the 847-file Gitea tagdiff entry was rejected by the new
breadth cap.

Result: **0/13 detected, 0 weak-only.** The one weak hit in the pre-expansion
run was the j5r2 broad-truth entry (71 "hits" across 847 truth files: the
coincidence bomb the cap now prevents).

Every entry's ground truth was human-QA'd with `ops/corpus_qa.py` before
scoring. That pass caught one truth defect: serve-static's tagdiff dragged
`test/test.js` into truth, so the noise filter now also drops top-level
`test/`, `tests/`, `docs/` and `examples/` directories.

What this means, stated plainly: ScanHub's 69 pattern rules detect **zero**
of 13 real CVE fix sites in Gitea, Django, Express, marked and
serve-static. Every one of these CVEs needs dataflow reasoning (source and
sink in different functions, sanitizer state, framework semantics) that
pattern matching cannot do. This is the honest floor for a pattern-only
engine, and it is why ScanHub's public claims rest on the coverage and
precision tiers, never on replay TPR.

The corpus stays the radar: each MISS names a class a future engine must
earn (SQL string construction in Django backends, redirect sinks,
framework-level XSS). Round 4 belongs to whatever engine closes dataflow -
Joern is parked (see joern-spike.md), single-shot LLM audit is measured and
rejected (see probe below), so the honest answer today is: nobody has, and
we publish that instead of pretending.

## Round 4 (2026-10-13): PR-grade ground truth, same verdict

The corpus builder now resolves `/commit/<sha>` references inside GHSA
advisories, so 8 of 13 entries carry fix coordinates taken from the actual
fix commit instead of tag-diff inference. Re-scored on the rebuilt corpus:
**still 0/13.** The misses are structural (multi-layer dataflow, framework
internals), not labeling artifacts - better truth did not move the number,
which is exactly what a floor measurement should look like when it is real.

The new app-level redirect-sink rules (`rules/redirect-sinks.yaml`, 7 hits
on Juice Shop) target the *misuse* class these CVEs exemplify, but the
corpus entries themselves live in framework internals where pattern rules
structurally cannot reach. The radar stands; the engine that closes it is
still an open question we publish rather than paper over.
