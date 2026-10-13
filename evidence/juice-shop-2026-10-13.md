# ScanHub detection evidence — juice-shop

- **Date:** 2026-10-13
- **ScanHub build:** `03bc66a` @ `http://localhost:8080`
- **Rules:** 86 original ScanHub rules (batch4.yaml, go-web.yaml, go.yaml, iac.yaml, javascript-node.yaml, javascript.yaml, parity2.yaml, parity3.yaml, python-sql.yaml, python.yaml, redirect-sinks.yaml)
- **Engines:** opengrep `1.16.4` · gitleaks `gitleaks version v8.30.1`
- **Benchmark source:** https://codeload.github.com/juice-shop/juice-shop/tar.gz/refs/heads/master (sha256 `528b302ebf8abc48…`)
- **Scan id:** `83b43920-e22d-4e67-b074-eb5ea277ec61`

**Result: 177 findings** — 20 critical, 69 high, 40 low, 48 medium

## Findings by rule

| Rule | Engine | Count |
|---|---|---|
| `AWS-0124` | trivy | 35 |
| `AWS-0104` | trivy | 15 |
| `rules.sh-tf-open-world-ingress` | opengrep | 10 |
| `rules.sh-js-angular-bypass-trust` | opengrep | 9 |
| `rules.sh-js-sendfile-dynamic` | opengrep | 8 |
| `rules.sh-gha-script-injection-broad` | opengrep | 7 |
| `AWS-0054` | trivy | 5 |
| `AWS-0164` | trivy | 5 |
| `AWS-0052` | trivy | 5 |
| `AWS-0053` | trivy | 5 |
| `AWS-0178` | trivy | 5 |
| `rules.sh-js-express-static-dir-listing` | opengrep | 5 |
| `rules.sh-js-open-redirect` | opengrep | 4 |
| `AWS-0037` | trivy | 3 |
| `gitleaks.generic-api-key` | gitleaks | 3 |
| `gitleaks.private-key, trivy.secret.AsymmetricPrivateKey` | gitleaks | 3 |
| `rules.sh-js-nosql-dollar-where` | opengrep | 3 |
| `rules.sh-js-open-redirect-location` | opengrep | 3 |
| `DS-0026` | trivy | 3 |
| `rules.sh-js-jwt-verify-no-algorithms` | opengrep | 2 |
| `rules.sh-js-eval-call` | opengrep | 2 |
| `rules.sh-js-pug-compile-dynamic` | opengrep | 2 |
| `DS-0001` | trivy | 2 |
| `trivy.secret.JWT` | trivy | 2 |
| `rules.sh-js-innerhtml-user` | opengrep | 2 |
| `rules.sh-tf-cloudwatch-unencrypted` | opengrep | 2 |
| `rules.sh-tf-public-subnet` | opengrep | 2 |
| `rules.sh-tf-elb-access-logs-off` | opengrep | 2 |
| `rules.sh-js-nonliteral-regexp` | opengrep | 2 |
| `rules.sh-js-md5-usage` | opengrep | 2 |
| `AWS-0017` | trivy | 2 |
| `rules.sh-gha-curl-pipe-shell` | opengrep | 1 |
| `rules.sh-js-hardcoded-hmac-key` | opengrep | 1 |
| `rules.sh-js-jwt-decode-unverified` | opengrep | 1 |
| `rules.sh-js-path-resolve-user-input` | opengrep | 1 |
| `rules.sh-js-remote-property-injection` | opengrep | 1 |
| `rules.sh-js-sequelize-raw-sql` | opengrep | 1 |
| `rules.sh-js-jwt-decode-unverified, rules.sh-js-jwt-verify-disabled` | opengrep | 1 |
| `rules.sh-js-script-tag-strip-sanitizer` | opengrep | 1 |
| `rules.sh-js-html-inject-concat` | opengrep | 1 |
| `DS-0002` | trivy | 1 |
| `DS-0025` | trivy | 1 |
| `rules.sh-gha-mutable-action-ref` | opengrep | 1 |
| `rules.sh-js-property-chain-walk` | opengrep | 1 |
| `rules.sh-js-hardcoded-secret` | opengrep | 1 |
| `rules.sh-js-prototype-pollution-loop` | opengrep | 1 |
| `rules.sh-js-fetch-user-url` | opengrep | 1 |
| `rules.sh-js-cors-wildcard-middleware` | opengrep | 1 |

## Reproduce

```bash
python ops/benchmark.py --url <your-instance> --token <api-token> --app juice-shop
```

The harness uses only the public REST API. Findings land in `evidence/` for diffing.
