# QazWire M1.3 — operator-reported full Go regression verification

**Date:** 2026-11-02  
**Evidence:** terminal output supplied by project operator; **not independently executed in this review environment**.  
**Branch:** `feature/m1-3-reviewed-prefix-api`.  
**Published HEAD and fast-forward target:** `0a596f9413c31093e397185a844dae701527a0c9`; local command output shows fast-forward `2d05d76..0a596f9`. No separate `git rev-parse HEAD` was printed at the test step; exact SHA binding is therefore inferred from the shown fast-forward and stable remote HEAD at review time.  
**Security scope:** syntax-only experimental protocol scaffold, draft disabled provider contracts. Qalqan not implemented and no experimental VPN transport is enabled.

## Verification evidence

| Operator action | Observed output | Result |
| --- | --- | --- |
| `git pull --ff-only` | Fast-forward `2d05d76..0a596f9` with formatting-only changes to two files | PASS |
| `gofmt -l internal/qazwireexp/prefix.go internal/qazwireexp/prefix_test.go` | No filenames printed | PASS (operator output) |
| `go test -tags qazwire_exp -count=1 ./...` | Every tested package `ok`, including `internal/qazwireexp` | PASS |
| `go test -tags qazwire_exp -race -count=1 ./...` | Every tested package `ok`, no races reported | PASS (exercised paths only) |
| `go vet -tags qazwire_exp ./...` | No diagnostics; chained `&&` proceeded | PASS |
| `go test -count=1 ./...` | Every tested package `ok`, no failures | PASS |
| Final shell guard | `M1.3 ALL CHECKS PASSED` | PASS — proves all chained commands returned success codes |

## Source and limitations

The user executed four critical commands chained with `&&`, so the final marker corroborates successful exit status for each. `go test -count=1` bypasses cached Go test results. The presence of the unchanged default-mode suite does not by itself prove bitwise code identity to upstream or security of the protocol.

- Parser methods validate only provisional four-byte prefixes; `UnauthenticatedPrefix` is explicitly not authenticated.
- Provider registry resolves no approved crypto suites; no Qalqan implementation or packet encryption was tested.
- The concurrency `OperationGate` was tested but remains subject to independent Claude R3 review, including potential reentrant shutdown deadlock.
- No live experimental VPN, side-channel assessment, authenticated transport, compliance testing or production security claims are justified.

## Gate status

**M1.3 module regression:** PASS (user-reported)  
**Crypto provider integration:** BLOCKED  
**M2 Qalqan transport integration:** BLOCKED pending R2/R3 issues G-Q1…G-Q8 and independent human crypto review.  
**Merge policy:** all open PRs are drafts; no merge without explicit owner approval.
