# QazWire M1.6 — structural ownership laboratory (Research Only)

**Branch:** `feature/m1-6-exclusive-key-ownership` (stacked on PR #13 @ `45984d7`). **Not a production crypto or WireGuard implementation.**

## Purpose and implemented properties

M1.6 starts a **new**, isolated package `internal/qazwireexp/klm16` (only built with `-tags qazwire_exp`). It is deliberately NOT wired into `device/` or into a live network. `sessionlab` remains unchanged and unsafe for actual secrets. The new design addresses R4.2 architectural failures **at the synthetic API boundary**, rather than adding a stronger `claim()` to an arbitrary caller-defined provider.

1. **No injectable processor or secret.** `NewLabSession(maxTickets,maxQueuedBytes,maxPinned)` accepts only resource limits. Private `syntheticMaterial` is created by `makeMaterial()`; no exported constructor accepts bytes, a provider interface, a slice of key material, a `wipe()` callback or a `claim()` implementation.
2. **No value-receiver wipe.** The only material type is unexported and `wipe` has pointer receiver. `Session` owns the generation. Completion of `AwaitDestroyed` confirms only that the synthetic wipe routine executed after the final reference, **not that real secrets have been physically erased**.
3. **Uniqueness inside one process.** Material IDs and session IDs use monotonic atomic counters with wrap refusal; generations have monotonic per-session epochs and per-generation one-time ticket numbers. Every accepted laboratory record includes `(SessionID, Epoch, MaterialID, Sequence)`. Although ticket numbers intentionally restart from zero on rotation, material IDs are distinct in this process. **Nothing here constructs a cryptographic nonce or authenticated key derivation.**
4. **Tickets as capabilities.** `Ticket` contains only a private `*ticketState` pointer. Copying the public value does not clone the underlying state; the first `Consume` or `Discard` removes it from the private pending map. Foreign, nil and reused tickets are rejected. Tickets hold a generation reference until consumed, discarded or cancelled.
5. **Bounded synthetic queuing.** `maxTickets` bounds admissions per key generation; `maxQueuedBytes` bounds aggregate queued input bytes, counting owned copies. `maxPinned` is a fail-closed tripwire for older generations with active references. All lifecycle transitions are serialized under `Session.mu`; the fixed synthetic copy takes place outside that lock. The old in-place `s.keys[:0]` pattern is NOT used; pruning allocates a new slice.
6. **Retirement.** Already admitted work from the directly previous generation may complete, unless a second rotation discards that generation. Previous-generation queued entries are flushed on the second rotation; older in-flight operations are rejected when committing to the queue. A stopped or poisoned session admits no more operations; deadlines on `AwaitDestroyed` are compulsory.
7. **No external callback under the lifecycle mutex.** Test-only `beforeQueue` scheduler hooks run outside the mutex and permit deterministic rotation, stalled operation and panic tests. The hook is unexported. A panic in this test hook poisons/stops the synthetic session. The normal package never calls foreign crypto providers or network senders.

## Critical non-guarantees

| Topic | State / blocker |
| --- | --- |
| Cross-process/reboot key identity or nonce uniqueness | **NOT IMPLEMENTED.** Atomic counters reset on reboot. Before real crypto, a handshake-derived, authenticated session/role/direction domain and injective per-key IV mapping are mandatory. Persisted replay or restored keys require independent formal review. |
| AEAD / Qalqan CTR+EMAC, AD, IV, KDF, receiver index | **NOT IMPLEMENTED**. `LabRecord.Data` is PLAINTEXT for offline tests, never an encrypted packet. A session's `Epoch` and `MaterialID` are test labels, not a cryptographic derivation or authenticated header. |
| Receiver authentication or replay window | **NOT IMPLEMENTED**. Current package handles only synthetic outbound completion; no real `Open`. |
| Foreign callbacks and stalled wipes | **NOT IMPLEMENTED**. There is no callback-driven real key operation. A test hook can intentionally hang; Go cannot stop a stuck goroutine or guarantee its material erasure. Stage D requires external process isolation, a supervisor, bounded queues, A0 egress block, coredump/ptrace controls and hard kill. |
| True zeroization, compiler/GC copies, FFI arena | **NOT IMPLEMENTED**. `clear()` only touches synthetic bytes; Go memory and runtime copies are outside current proof. |
| Constant-time guarantees, Qalqan cryptanalysis, regulatory conformity | **BLOCKED** under G-Q1/G-Q2/G-Q3/G-Q8 and the rest of the research gates. |
| Prior sessionlab R42-04/06/07/10 fixes | **PENDING** on the prior lab. This milestone introduces a separate, structurally constrained API; it is not an assertion that M1.5.2 has been repaired. |

## Test plan

`go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/klm16` tests:

- constructor only takes limits, internal material pointer and ID differ for every rotation;
- a copied ticket cannot be replayed; cross-session and invalid tickets fail;
- per-generation sequence restarts while material/epoch identity changes;
- caller mutation after `Prepare` cannot change queued data;
- queued byte budget and explicit discard;
- two rotations drop a stale pending packet without premature wipe;
- paused in-flight operation is retried on current generation;
- Stop with a blocked operation times out without claiming erasure, then drains correctly;
- test-hook panic poisons and prevents further rotation/prepare;
- pinned-generation budget triggers fail-closed while respecting the outstanding reference;
- no retained `*generation` pointers outside the active backing-array slice;
- epoch exhaustion and multithreaded rotation/prepare/consume/discard.

## Deliberate API limits

`Consume` returns a **synthetic plaintext record**, not an egress-send capability. Therefore testing `Consume` does not establish the real R4 egress gate: the actual `bind.Send` path is untouched and R4-T-KLM-25 remains OPEN. Caller must not forward these records to a network. The production `KeyOwner` vs `SendKey` split, secret arena and independent crypto-worker process will be separate milestones.

## Review gates

- Reproducible clean-commit Go tests, `-race`, vet and format (with output manifests).
- Independent negative **external API** compile test and immutable SHA binding.
- Full R4.2 architecture audit; 2+ worker model including poison, retained buffers and stage D.
- **NO-GO for M2** pending cryptanalysis (G-Q1), regulator decision (G-Q2), authenticated nonce/session protocol and real KLM containment.

No merge into `master` without the owner's separate authorization.
