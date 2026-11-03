# M1.5.1 Ubuntu verification (operator reported)

Date: 2026-11-03. Base reviewed remote branch HEAD: `683051fb008f32f3ba0922e7f48a696f7004ce60`.

The owner supplied terminal output from the `feature/m1-5-1-r4-remediation` tracking branch. Commands were run with `set -euo pipefail` and ended with `M1.5.1 ALL CHECKS PASSED`.

| Test | Observed result |
| --- | --- |
| `gofmt -l internal/qazwireexp/sessionlab/*.go` | PASS (no unformatted files) |
| `go test -tags qazwire_exp -count=1 ./...` | PASS |
| `go test -tags qazwire_exp -race -count=1 ./...` | PASS |
| `go vet -tags qazwire_exp ./...` | PASS |
| `go test -count=1 ./...` | PASS |
| `go test -tags qazwire_exp -race -count=100 ./internal/qazwireexp/sessionlab` | PASS (10.307s) |

Evidence source: operator-provided terminal transcript, not independently rerun by reviewer. Exact local SHA was not printed; branch identity inferred from successful tracking checkout and remote HEAD check.

Scope: isolated synthetic concurrency tests, not actual packet encryption or an active VPN implementation. Race testing is not a full formal proof. No production crypto integration, independent KLM approval, or normative conformity is claimed. No merge authorized.
