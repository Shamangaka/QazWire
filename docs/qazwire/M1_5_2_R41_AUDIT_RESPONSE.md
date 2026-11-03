# QazWire M1.5.2 — independent response to R4.1 (research only)

**BASE:** `feature/m1-5-1-r4-remediation`, reviewed SHA `f5e078c592a3e558912382d0805ec108e07c86f3`. **NO merging; no Qalqan; no real keys or network integration.** The `sessionlab` package remains gated by `qazwire_exp`, unexported and non-cryptographic. This Draft PR contains an *unverified candidate implementation* until the owner's full-module Go/race/vet and independent R4.2 model checks complete.

## Scope

1. **R41-01/02: exclusive lab-provider claim, no immortal process-global registry.** The test-only `processor` contract now requires `claim() bool`; each provider has an embedded `providerClaim` backed by `atomic.Bool`, which can succeed at most once and remains in the provider object itself. Only non-nil pointer providers are accepted; value providers cannot masquerade as wiped objects. Reusing the identical provider across generations or sessions returns `errProviderReuse`. This lab discipline is not a production-safe structural ban on arbitrary providers or copied key material: R4 §7.2's concrete, internally constructed provider is still required.
2. **R41-03: normal retirement ≠ emergency.** Only emergency, poisoned keys and generations superseded by a second rotation receive `discardFlag`. Already-admitted work on the immediately preceding key may finish; `prepare` retries once when it raced with a normal retirement. The remote receive window and protocol compatibility remain **unproved**.
3. **R41-04: grandparent fencing.** On rotation every generation older than the current is marked discard and its queued packets are flushed. `prepare` rechecks generation membership **under `session.mu`** before queuing, so an operation paused across two rotations cannot reintroduce output. Finished generations are pruned. **A hung operation can still pin a generation indefinitely; rotation frequency/backlog limits and external Stage-D remain unimplemented.**
4. **R41-05/06: durable fault state and timeout classification.** Wipe failure latches a monotone session-level fault before `done` closes, independent of prunable generation pointers, and triggers asynchronous emergency. An unconfirmed wipe after deadline is distinguished (`errWipeUnconfirmed` wraps `errDeadline`). A session with latched failure refuses new prepares/rotations and `awaitDrained` returns failure.
5. **R41-07: always copy processor output.** The queue receives a fresh allocation even if returned output is an offset or overlapping view of the caller's input. The caller receives only the one-use handle (`packet.data=nil`). Provider-owned buffers are not cleared by this layer because they may alias caller memory. A production provider needs a stronger ownership/zeroization contract.

### Tests

- Existing tests from PR #9 and #11 (with embedded `providerClaim` in their fake provider types).
- Imported auditor R4.1 regression tests (ported to the one-time claim model) and 300-round stress checks.
- New tests for partial-overlap output, a delayed grandparent operation across two rotations, and reuse of an already-claimed provider.

**No new PASS claim is made:** the full QazWire module on the owner's Ubuntu Go 1.27.3 and an implementation-derived state-space model have NOT yet been run on this branch. The previous M1.5.1 PASS and Claude's R4.1 patch PASS do not transfer to this revision.

### Explicit blockers

- R4.1 report's minimal patch is NOT applied verbatim: its `providersInUse sync.Map` retained strong references to every provider indefinitely, a security-unacceptable pattern with real key objects.
- A one-time claim on an arbitrary test implementation is **not** linear/unique key-material ownership. Production design needs a concrete type that consumes derivation input and disallows copies, with separate measured memory-wipe limitations.
- Retired generations with hung operations remain live; enforce max backlog, bounded Stage-D and a correct receive-side rotation contract before any networking.
- Real `bind.Send`, netns tests, receive-key replay window, actual nonce bounds, key-generation identifiers, output verification and cryptanalysis are entirely outside this package.
- No Go race-detector PASS establishes the absence of races involving `clear()`; strict owned-buffer invariant and external review remain required.
- Formal state exploration of this *revised* implementation has not been performed; no certification or conformity is claimed.

### Ubuntu test commands

```bash
cd ~/Документы/QazWire
git fetch origin
git switch --track origin/feature/m1-5-2-r41-owned-providers
set -euo pipefail
gofmt -w internal/qazwireexp/sessionlab/*.go
go test -tags qazwire_exp -count=1 ./...
go test -tags qazwire_exp -race -count=1 ./...
go vet -tags qazwire_exp ./...
go test -count=1 ./...
go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/sessionlab
echo 'M1.5.2 ALL CHECKS PASSED'
```

Note: `gofmt -w` intentionally formats the working tree; the owner should inspect `git diff` and may commit formatting separately. **Do not run the R4.1 patch on this branch.**

### Requested independent review

Review processor ownership, generation fencing, cancellation and queue-lease release, persistent fault propagation and old-key handling under multiple rotations; rebuild the model for THIS implementation, not the prior M1.5.1 nor Claude's alternate patch. Keep the PR Draft and do not merge without owner approval.
