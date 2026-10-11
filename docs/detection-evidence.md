# Detection Evidence - how we prove it

**Audience: customers evaluating ScanHub.** The claim we make is simple:
*ScanHub finds real vulnerabilities in real code, and you can verify that
claim yourself before you pay us a dollar.*

## The proof chain

1. **Public benchmark targets.** We scan well-known, intentionally-vulnerable
   open-source applications (currently [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
   116 published challenges). Anyone can download the same source - its
   SHA-256 is recorded in every evidence pack.
2. **Public REST API only.** The benchmark harness (`ops/benchmark.py`)
   touches ScanHub exactly the way a customer would: create project → upload
   zip → poll scan → fetch findings JSON. No database access, no privileged
   paths, no cherry-picking.
3. **Environment fingerprint.** Each evidence pack records the ScanHub git
   commit, rule count and rule file list, engine versions (OpenGrep, Gitleaks),
   and the benchmark archive hash - so a result can be tied to an exact build.
4. **Reproducible by the buyer.** Run one command against any ScanHub
   instance (yours or a trial account) and you get the same findings file:

   ```bash
   python ops/benchmark.py --url https://your-instance --token <api-token> --app juice-shop
   ```

5. **Regression-gated.** `evidence/<app>-prev.json` is compared on every run;
   a rule change that loses findings fails the harness. Detection quality is
   a tested property, not a vibe.

## Current evidence

| Benchmark | Findings | Rules | Evidence pack |
|---|---|---|---|
| OWASP Juice Shop (master) | 84 (48 high, 36 medium) | 69 original ScanHub rules | `evidence/juice-shop-*.md` |

Rule-by-rule breakdown is inside each evidence pack. The rule corpus is
100% original (MIT); see `LICENSES.md` - we ship no third-party restricted
rule content, so nothing we detect depends on a license a competitor owns.

## What we do NOT claim

- **Not a penetration test.** Static analysis finds vulnerable *patterns*, not
  exploitability. Runtime/business-logic verification is a separate lane
  (DAST integration on the roadmap).
- **Not "all" vulnerabilities.** The benchmark measures what our current rule
  set detects on one codebase; the honest number is "84 findings, mapped to
  rule IDs you can inspect", never "100% coverage".
- **False positives exist.** Every finding carries rule ID, file, line, and
  snippet so a human can confirm in seconds; AI triage (BYO-LLM) pre-sorts
  verdicts, and the fix-verification loop re-scans to prove fixes stuck.

## Sales one-liner

> "Don't take our word for it - here's the script, here's the benchmark app,
> here's our API token. Reproduce our numbers on your laptop before you buy."
