# QazWire M1.5.1 — R4 remediation in isolated synthetic sessionlab

**Status:** DRAFT / RESEARCH ONLY. **This code does NOT implement encryption, authentication, real key destruction, nonce construction or VPN traffic.** The test processor returns plaintext copies. The whole `sessionlab` package is gated by `//go:build qazwire_exp`, unexported and unreferenced by `device/*`.

**Base:** PR #9, branch `feature/m1-5-synthetic-egress-lifecycle`. This is a stacked experimental change; no merging to any branch without owner approval.

## Changes relative to M1.5

1. **Deadline mandatory** (`errNoDeadline`): `awaitDrained` and per-gate `await` reject nil contexts and contexts with no deadline. Waiting is strictly observational: it no longer initiates emergency shutdown. This prevents accidental unbounded `context.Background()` waits in the API.
2. **Provider poison and failure**: `key.seal` catches synthetic provider panic and turns a `process` error into `errProviderFault`, setting `poisonFlag|closingFlag`. `session.prepare` then begins emergency shutdown. A fake sink panic also triggers emergency shutdown. This is a *research error state*, not a safe production panic recovery policy.
3. **Wipe uncertainty**: a panicking `wipe()` sets `failedFlag`; the completed `done` signal is only published after the failure is recorded, and `awaitDrained` returns `errWipeFailed`, **never success**. A permanently blocked `wipe` still requires external process/module isolation after a deadline. The test harness cannot guarantee real erasure.
4. **One-shot queued ticket and key pinning**: a prepared `packet` contains a private `packetGuard` with an atomic consumed flag and a pointer to its key generation. Its key lease is transferred to the queue and stays active until exactly one successful `dispatch`, explicit `discard` or emergency queue flush. Foreign, missing or reused ticket returns `errTicket` while the gate is open. This prevents a retired generation from being wiped while its prepared synthetic output remains queued.
5. **Egress shutdown and rotation serialization**: the send-admission gate closes first. Emergency then sets `session.closed` and closes **all key generations** under the same management mutex used by `rotate`. Installing another generation after emergency is rejected. The tracked `pending` map is flushed, and each queued lease is released exactly once.
6. **No refcount underflow**: `gate.leave` uses a CAS loop and panics on an unmatched release *before* changing state. This is an intentional fail-stop invariant; it does not claim to recover from arbitrary concurrency misuse.

## Verification evidence

The following two files were tested together as an isolated Go 1.23.2 research package with no external modules:

```bash
GO111MODULE=off go test -tags qazwire_exp -race -count=100 ./...
GO111MODULE=off go vet -tags qazwire_exp ./...
gofmt -l .
```

**Result:** tests PASS, vet PASS, gofmt no unformatted files.

The exact locally tested Git blobs match those uploaded to GitHub:

| File | Git blob SHA |
| --- | --- |
| `internal/qazwireexp/sessionlab/session.go` | `bd3aff6dab336ee9927ac1e04447ad7d82938c89` |
| `internal/qazwireexp/sessionlab/remediation_test.go` | `645f88d8425e419bdd7c497a4b3b2fad43c57b60` |

Tests include one-shot and cross-session ticket rejection, queued discard and emergency flush, key-generation pinning through rotation, provider panic and returned error, wipe panic, required deadline, unmatched release, concurrent dispatch claims, and fake sink panic. **Full QazWire module tests, including the inherited PR #9 `session_test.go` on Ubuntu Go 1.27.3, remain PENDING.**

### Ubuntu verification

```bash
cd ~/Документы/QazWire
git fetch origin
git switch --track origin/feature/m1-5-1-r4-remediation
set -euo pipefail
test -z "$(gofmt -l internal/qazwireexp/sessionlab/*.go)"
go test -tags qazwire_exp -count=1 ./...
go test -tags qazwire_exp -race -count=1 ./...
go vet -tags qazwire_exp ./...
go test -count=1 ./...
go test -tags qazwire_exp -race -count=100 ./internal/qazwireexp/sessionlab
echo "M1.5.1 ALL CHECKS PASSED"
```

## Remaining limitations / open R4 obligations

- **Not the complete R4 KLM.** No independent receive-key object, replay window, authenticating `Open`, MAC verification volume, per-key block-volume accounting, overall `u` budget, trusted key derivation or actual secret memory.
- **Ticket object still an internal research capability, not a production-proof unforgeable nonce object.** No post-crash state, replay protection, network-format binding or proof of nonce uniqueness across recreated keys. `pending` records are in-memory only. Keeping all generations until session teardown also requires memory/time controls before scale testing.
- **Egress limitation:** a writer already admitted before `beginEmergency` may still execute or finish afterward. A real network needs queue cancellation, socket-level shutdown and possibly network-policy fencing. No netns A0/A1 test was run.
- **Context:** bounded waiting is enforced by requiring a deadline, but the *caller* chooses it; there is no globally fixed maximum. A malicious or accidental deadline far in the future remains possible.
- **Test-double panic handling:** `recover` contains a Go panic from fake processors; this does not prove secret erasure or safe post-panic operation. A production system needs fail-stop isolation and verifiable error propagation. Real crashes, memory disclosure and process termination were not exercised.
- **Buffer ownership:** a packet contains a `[]byte`; the caller/test may retain aliases and mutate memory. A production transport requires explicit ownership transfer or immutable buffer objects; the current lab does not enforce it.
- **Formal proof/model checking:** R4's 1.8 million-state reference-model check is NOT a proof of the present implementation. This revised code needs separate independent concurrency review and model-checker coverage.
- **Security compliance:** Qalqan-256 strength BR-01 and normative G-Q2 remain BLOCKED; mathematical X25519 target and PSK requirements still require human review and owner approval.

## Independent review request

Please check that every `seal` lease is paired through queued `dispatch`/`discard`/emergency flush, all shared state interleavings, observable success only after confirmed lab-wipe, mitigation of R4 findings, potential races in queue-owned buffer clearing, and rotation-vs-shutdown. No merge to `master` or other branches without express approval.
