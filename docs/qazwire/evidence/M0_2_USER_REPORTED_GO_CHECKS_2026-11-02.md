# QazWire M0.2 — Go unit/race/static checks (operator-reported)

**Execution date:** 2026-11-02.  
**Evidence source:** terminal output supplied by project operator from Ubuntu host. **Not independently rerun** in this review environment.  
**Source branch:** `experimental/qalqan-transport-v0.1`.  
**Last printed local checkout SHA before this test set:** `5e07792adee6f619d5f89a5644efafb51c7d6f86` from the preceding M0.1 log. The M0.2 output did not separately print `git rev-parse HEAD`, therefore treating it as the actual exact test SHA is **PENDING** a new capture.  
**Toolchain:** earlier same-host output: Go 1.27.3 linux/amd64.  
**Cryptographic status:** standard WireGuard; no Qalqan code integrated.

## User-reported test commands and outcomes

| Command | Result | Key observations |
| --- | --- | --- |
| `go test -count=1 ./...` | **PASS** | All tested Go packages reported `ok`; packages without tests reported `[no test files]`. `-count=1` bypassed Go test result caching. |
| `go test -race -count=1 ./...` | **PASS** | All tested packages reported `ok`; no race reports from exercised paths. This is **not** proof of race freedom. |
| `go vet ./...` | **PASS (reported)** | No diagnostics printed after the command. Shell exit status was not separately captured; no errors observed in output. |

## Remaining limitations

- `TestWaitPool` is skipped at the beginning of `device/pools_test.go`; the race-enabled test run does **not** exercise that test's internal concurrent workload.
- Missing code coverage, test manifest and forced recompile; race detector covers only executed paths.
- No independently reproduced full traffic/handshake/rekey/replay/packet-tampering suite in this entry. M0 and M0.1 operator results recorded separately.
- Not a cryptographic security proof, certification, or evidence of compliance with ST RK 1073-2025.
- This report records no private keys, credentials, licensed standards or sensitive packet contents.

## Gates

M0 experimental-branch baseline smoke tests: **PASS (operator-reported)** for two userspace peers, userspace↔kernel interop, Go unit tests, vet and race-enabled tests on exercised paths.

M1 implementation: **DESIGN ONLY** pending independent review of `audit/qazwire-protocol-r1`; specifically AE/MAC security bounds and per-key key/message-volume caps.
