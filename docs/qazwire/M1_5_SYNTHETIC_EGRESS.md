# QazWire M1.5 — independent synthetic egress cutoff and directed-key lifecycle

**Status:** DRAFT / RESEARCH ONLY. **No real cryptography, keys, VPN session, or Qalqan transport is enabled.** This package exists solely for concurrency and failure-mode research; it must never be connected to a network interface.

## Base and isolation

Stacked on `feature/m1-4-synthetic-key-lifecycle` (PR #8). Changes are restricted to `internal/qazwireexp/sessionlab/` and this document; files contain the `qazwire_exp` build tag. No changes are made to `device/*` or the standard WireGuard implementation.

The complete API is package-private. No exported constructor, concrete provider, cryptographic suite or outbound transport hook is available.

## Research model

- **Directed-key gate:** a single `atomic.Uint64` stores `closingFlag` (bit 63), `finishedFlag` (bit 62, claim to finalize), and the active operation count (bits 0–61). `enter` uses CAS and rejects after closing; `leave` triggers finalization only when the last operation exits. Completion is indicated by closing a channel *after* `wipe` returns.
- **Synthetic ticket sequence:** `next` is a separate monotonic `atomic.Uint64`, with an immutable maximum. `reserve` never resets/wraps. A shutdown that races between the check of `closingFlag` and `next.CompareAndSwap` may **burn** a unique ticket after closure; this is allowed and is explicitly *not* a claim that ticket allocation and shutdown are one linearizable operation.
- **Egress gate:** a separate combined-state atomic controls entry to the *fake* `wire.send`. A packet prepared *before* emergency closure but queued until *after* closure must fail dispatch. Already admitted sends can finish after closure; `awaitDrained` waits for their completion before reporting success.
- **Stage A:** `beginEmergency` closes the egress gate first and the key gate second, asynchronously scheduling finalizers when no operations remain. It does not synchronously invoke a blocked processor or sink.
- **Stage B–C:** `awaitDrained(ctx)` waits for both the egress and key gate. The fake `wipe` event must happen once and strictly after all key users exit; its completion is required for successful return.
- **Stage D:** context deadline returns `errDeadline`, NOT a claim of erasure. A separate orchestrator must isolate/terminate a stuck crypto process/module if a hard deadline is required. No attempt is made to abort an in-progress Go goroutine or wipe active material.
- **Dependency checks:** constructor rejects nil and typed-nil providers/writers and a zero ticket budget.

## Precise safety limits

1. The fake provider's `process` returns a copy of its input plaintext; it is **not encryption**. The fake `wipe` only counts invocations; no real secret is destroyed.
2. Egress admission is linearized at the gate CAS. `beginEmergency` forbids future admissions after its gate closes; an already-admitted `wire.send` can start/finish after that instant if scheduling is adversarial. This API **cannot guarantee physical suppression of all in-flight packets**. Real sockets must support stop/flush/cancel plus clear packet-queue ownership semantics.
3. A state check just before returning a prepared packet **cannot** be the sole output safeguard; the egress gate is an independent, later check. The two gates are not one atomic transaction; intermediate states are allowed and must fail closed at dispatch.
4. A ticket may be reserved and then discarded; it MUST NOT be recycled. Nothing here proves nonce uniqueness across process restarts, key generations or crashes, nor does it implement actual authenticated-header construction.
5. A `wipe()` hang/panic leaves a non-completed close claim. A panic in the goroutine may crash the process. The proper production policy requires separately audited provider behavior and process isolation, not a recovery wrapper that falsely reports a wipe.
6. Packet records have no authenticated type, generation binding or replay rejection. Within the test package they can be manually forged or replayed. No real key ownership, MAC/CTR block-volume budgets, zeroization, receive-path checks or key-rotation protocol are provided.
7. Go `-race` and finite stress runs cannot prove all concurrency interleavings, constant-time behavior or cryptographic security. No on-wire standard changes occur.

## Tests and evidence

Go 1.23.2 linux/amd64 isolated package on a local container:

```bash
GO111MODULE=off go test -tags qazwire_exp -race -count=100 ./internal/qazwireexp/sessionlab
GO111MODULE=off go vet -tags qazwire_exp ./internal/qazwireexp/sessionlab
gofmt -l internal/qazwireexp/sessionlab/*.go
```

All passed; no gofmt filenames were reported. **Exact Git blob IDs of locally tested files match GitHub:**

- `session.go` — `53026fc14964f52223e1757844de4a98e1e74922`
- `session_test.go` — `7b9a88febbe6e1b6a7997753089eeef79d2ac80b`

Test coverage includes: queued packet rejected after emergency, blocked provider with deadline and delayed wipe, in-flight writer drained, 2000 unique synthetic tickets with 16 workers, 50 rounds of concurrent shutdown, wipe blocked without false success, emergency shutdown invoked from mock processor without self-deadlock, and typed-nil dependencies.

Full-module Go 1.27.3 tests on the owner's Ubuntu have **not** been run on this commit.

```bash
cd ~/Документы/QazWire
git fetch origin
git switch --track origin/feature/m1-5-synthetic-egress-lifecycle
set -euo pipefail
test -z "$(gofmt -l internal/qazwireexp/sessionlab/*.go)"
go test -tags qazwire_exp -count=1 ./...
go test -tags qazwire_exp -race -count=1 ./...
go vet -tags qazwire_exp ./...
go test -count=1 ./...
go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/sessionlab
echo 'M1.5 ALL CHECKS PASSED'
```

## Open audit gates

- R4 must adjudicate G-Q9 X25519 multi-target resource model and verify R3 proof assumptions.
- Independently review M1.5 counter shutdown interleavings, all egress cut-off cases, and the relative completion of key wipe vs egress drain.
- A real KLM requires separate send/receive keys, cryptographic provider encapsulation, key generations, one-use ticket objects, receive-side verification/replay accounting, bounded packet queues, and real network egress cancellation.
- Do NOT begin Qalqan transport integration until cryptanalysis, norms and G-Q1…G-Q11 are resolved.

**Merge policy:** This remains a Draft PR, stacked on PR #8. No merge to `master` or feature branches without owner approval.
