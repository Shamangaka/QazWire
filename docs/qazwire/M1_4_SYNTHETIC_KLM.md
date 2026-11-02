# QazWire M1.4 — synthetic key lifecycle research harness

**Status:** DRAFT / RESEARCH ONLY. This is a controlled **non-cryptographic reference model**, not a VPN protocol, cipher, approved crypto provider, or deployable key manager.

**Base:** `feature/m1-3-reviewed-prefix-api` (Draft PR #6). Files are isolated in `internal/qazwireexp/keylab`, with `//go:build qazwire_exp`. No imports from `device/*`, no modifications to ordinary WireGuard. This package exports **no types, constructors, methods or providers** and can only be used internally by its own package tests.

## Scope

This change answers selected findings from Claude [Audit R3, PR #7](https://github.com/Shamangaka/QazWire/pull/7):

1. **One atomic state word:** `closingBit`, `wipingBit`, active-reference count. A CAS admits operations only while open.
2. **No user callbacks while leased:** `sealPacket` owns and releases the internal reference, then invokes a private **synthetic** processor. The caller cannot supply a nonce/counter or a callback.
3. **Unique synthetic tickets:** a monotonic atomic sequence allocated inside the slot, using CAS and an explicit `maxMessages` bound; exhaustion returns a specific error, never wraps.
4. **Nonblocking stage A:** `beginEmergency` immediately prevents admission and schedules finalization when appropriate. Already-running processors can finish, but their output is discarded if they observe closure.
5. **Stage B-C:** `awaitDestroyed(ctx)` waits at most until context cancellation; a wipe is claimed using a CAS and runs **only after active references reach zero**, exactly once. `done` closes after wipe returns.
6. **Stage D is external:** on timeout `errDrainWait` requires process or isolated crypto-module termination by an orchestrator; **no forced key wiping occurs in a running process**.

## Executed local package tests

A separately constructed copy of the two `keylab` files was tested under Go 1.23.2 linux/amd64:

```bash
GO111MODULE=off go test -tags qazwire_exp -count=1 -race ./internal/qazwireexp/keylab
GO111MODULE=off go vet -tags qazwire_exp ./internal/qazwireexp/keylab
gofmt -l internal/qazwireexp/keylab/*.go
```

All commands passed (gofmt produced no output). **Full-repository build and Ubuntu Go 1.27.3 results are PENDING**. Execute on the operator's host:

```bash
cd ~/Документы/QazWire
git fetch origin
git switch --track origin/feature/m1-4-synthetic-key-lifecycle
set -o pipefail
go test -tags qazwire_exp -count=1 ./... 2>&1 | tee m14-tests.log
go test -tags qazwire_exp -race -count=1 ./... 2>&1 | tee m14-race.log
go vet -tags qazwire_exp ./... 2>&1 | tee m14-vet.log
go test -count=1 ./... 2>&1 | tee m14-upstream.log
```

Additional focused tests:

```bash
go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/keylab
```

## What is *not* proven or implemented

- No key material exists in this model; `wipe()` records an event, not verified zeroization.
- `process()` returns a **copy of plaintext**. It is deliberately not cryptography: NEVER attach this harness to production or experimental network send paths.
- Output may have been returned just before shutdown begins; real device egress must independently cut/drain output queues. That property is **not** implemented in this package.
- Callers in this research package could still introduce bypasses if they add new exports. A production KLM needs separate capabilities and a strict package-level construction boundary.
- Authentication-before-release, replay windows, send/receive separation, DoS resilience, counter allocation after crash, and block/MAC verification-volume budgets are NOT implemented.
- If the fake processor panics or `wipe()` fails/hangs, the model provides no recovery guarantee. A real provider must have well-specified non-panicking/destruction semantics and a process-level isolation policy.
- The sampled race tests cannot prove deadlock freedom, no UAF, or constant-time safety. Claude R3's recommended `T-KLM-07..12` and `T-REG-01` suite is only **partially** covered.
- No Qalqan transport implementation. Claude R3's crypto security bounds, multi-target X25519 resource model and G-Q1..G-Q11 remain independent blockers.

**Merge policy:** Do not merge this PR, its base PRs, or any change to `master` without explicit owner approval.
