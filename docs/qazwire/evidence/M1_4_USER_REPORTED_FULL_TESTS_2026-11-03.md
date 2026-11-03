# QazWire M1.4 — operator-reported Ubuntu full-module test results

**Date of reported execution:** 2026-11-03 (operator local date).  
**Evidence source:** terminal output supplied by the project owner. This run **was not independently executed by the reviewer**.  
**Branch:** `feature/m1-4-synthetic-key-lifecycle`.  
**Published branch HEAD during review:** `430350a1e45ee8099abf6346a01e19f3c8df1a5c`. The operator's transcript shows successful checkout of the new tracking branch, but does not separately print `git rev-parse HEAD`; exact local SHA binding is inferred from the tracked branch state and is **not** a standalone immutable local measurement.

## Checks

All commands below were connected with `&&`. The printed final marker therefore corroborates successful shell exit codes for all commands in that chain.

| Command | Observed output | Status |
| --- | --- | --- |
| `go test -tags qazwire_exp -count=1 ./...` | All testable packages `ok`, including `internal/qazwireexp/keylab` | **PASS** |
| `go test -tags qazwire_exp -race -count=1 ./...` | All testable packages `ok`, no race reports on exercised paths | **PASS** |
| `go vet -tags qazwire_exp ./...` | No diagnostics; subsequent chained command executed | **PASS** |
| `go test -count=1 ./...` | All testable packages `ok`, default/non-experimental mode | **PASS** |
| `go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/keylab` | `ok .../internal/qazwireexp/keylab 1.535s` | **PASS** |
| Shell success marker | `M1.4 ALL CHECKS PASSED` | **PASS** |

## Scope and security limitations

- This test only exercises the **non-cryptographic synthetic `keylab`**: fake processor, synthetic sequence counters, simulated wipe observation, and emergency admission/drain behavior.
- The model includes no actual keys, authenticated encryption or Qalqan, and is not imported into live `device/*` code. A fake provider does not prove safe key zeroization of Go/Rust secret material.
- `-race` is an execution-based detector, not proof against all races, deadlocks, cancellation bugs or side-channel leakage.
- In particular, the model's packet output cut-off is a post-processing state check; its guarantees are **insufficient for actual network egress fencing**. Cancellation cannot interrupt a permanently blocked Go provider; timeout requires **external process/module termination** to meet a strict emergency deadline.
- Potential provider panic during `wipe()`, cross-key rotation, Go toolchain secret ownership, packet replay, multi-user security budgets, handshake limits, and field/cipher domain separation remain untested/unimplemented.
- M1.4 should be treated as **tested research harness**, not approved production KLM. Requires independent Claude R4 review (G-Q10), including CAS/refcount race interleavings.

No code changes, merges, credentials, private keys, test traffic dumps or cryptographic conformity assertions are made by this evidence note.
