# QazWire M1.2 — operator-reported Go integration and concurrency tests

**Date:** 2026-11-02.  
**Source:** Ubuntu terminal output provided by repository owner. Not independently executed in this environment.  
**Branch:** `feature/m1-crypto-provider-contract`.  
**Reviewed branch HEAD at time of run:** `43532ed4e13053bab95a84343400876c76575677` (branch HEAD from prior GitHub state; operator did not print `git rev-parse HEAD` for this run).  
**Protocol status:** stock WireGuard unchanged; build-tagged QazWire provider contracts non-operational, no Qalqan.

## Observed commands

| Command | Terminal evidence | Assessment |
| --- | --- | --- |
| `go test -tags qazwire_exp -count=1 ./...` | All testable packages `ok`, including `internal/qazwireexp` | PASS (operator-reported) |
| `go test -tags qazwire_exp -race -count=1 ./...` | All testable packages `ok`, including `internal/qazwireexp` | PASS (operator-reported) |
| `go vet -tags qazwire_exp ./...` | No messages printed | No issues observed; exact shell exit status not separately captured |
| `go test -tags qazwire_exp -race -count=100 -run '^TestOperationGate' ./internal/qazwireexp` | `ok .../internal/qazwireexp 1.182s` | PASS (operator-reported) |
| `go test -count=1 ./...` (without experimental tag) | All testable packages `ok` | PASS (operator-reported) |

## Limitations and design risks

- The `OperationGate` is a callback admission/draining helper. It **does not store cryptographic material, reserve counters or guarantee key erasure**.
- Race detector covers executed paths only; it cannot prove no deadlock (notably if `CloseAndDrain` is invoked recursively from a `Use` callback), no missed references, or side-channel safety.
- The provider interfaces have no concrete implementation; `ResolveCryptoProvider` denies every profile.
- Claude R2 audit (PR #5) had **not reviewed PR #4** at the time of the auditor's report.
- No modified WireGuard on-wire format, encrypted Qalqan packet or normative compliance test was performed.

## Follow-up review requirements

1. Review R2-PR3-01/02/05 across the stacked M1 PR #3 and PR #4; public header parsing must never imply authentication.
2. Review lease-oriented key lifecycle against `QAZWIRE_KEY_LIFECYCLE_R2.md`, including conflict between invariant KL-2 (do not erase while a lease is active) and KL-10 (emergency erasure independently of outstanding refs).
3. Obtain an owner-approved, quantitatively justified global cryptographic advantage budget before accepting any per-key block/message thresholds.
