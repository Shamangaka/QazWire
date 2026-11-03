# QazWire M1.6.1 — resource accounting, concurrent lifetime, Stage-D prototype

**Status:** Synthetic laboratory only; `qazwire_exp`. Base: M1.6 Draft PR #16 @ `f602c5afe63eecc81cda26d24199034c90490b99`. This milestone does NOT use Qalqan, cryptography, WireGuard data paths or real key material.

## Why M1.6.1 exists

Reviewing the implementation exposed **a gap not covered by the previous M1.6 PASS**: `Prepare` copied the payload OUTSIDE `Session.mu` before charging it to `pendingBytes`. An unbounded number of threads paused between unlock and commit could allocate private copies, circumventing the queue-byte cap, even if final queue admission was correctly rejected. Another bypass used zero-length payloads: a byte-only budget allowed arbitrarily many ticket objects to remain pending.

The existing negative API compile test rejects attempts by external Go code to dereference and copy the private concrete owner or forge `Ticket.state`. This is a structural property, not a barrier against `unsafe`, runtime memory disclosure, malicious code in the same package, foreign FFI or hardware side channels.

## New implemented controls

- **Reservation before private copy:** `Prepare` atomically checks `pendingBytes + reservedBytes + len(payload) <= maxBytes` under `mu`, increments `reservedBytes` and `inFlight`, then releases `mu` before copying.
- **Bounded outstanding preparations:** a hard synthetic cap `maxInFlightPrepares = 32`; more concurrent `Prepare` return `ErrInFlight`. Production value TBD after capacity planning.
- **Bounded ticket objects even for empty input:** `maxPendingTickets = 1024` includes both pending tickets and in-flight preparations, so empty data never bypasses object count. Return `ErrCapacity` on overflow.
- **All paths release reservations:** successful commit turns reservation into queued byte charge. Shutdown, second rotation, retry, return-on-error and recovered test callback panic release reservations and leases. A holding callback remains accounted until it exits.
- `Snapshot` now exposes `InFlight` and `ReservedBytes` to allow deterministic assertions.
- The LAB-only scheduler hook (`beforeQueue`) pauses operations outside the lifecycle mutex; tests enforce copy-budget, zero-byte ticket bound, in-flight cap, stop-before-commit, consume-before-stop, poison cleanup.

These are bounded logical counters, **not a proven RSS cap**. Heap overhead, Go allocator capacity, already-returned `LabRecord.Data`, caller-owned `payload` and process metadata are not included. Pending and in-flight **data lengths** are counted; a future production implementation requires bounded worker pools, memory allocations and size caps with complete worst-case accounting.

## Stage-D synthetic Linux supervisor

`internal/qazwireexp/staged16/supervisor_linux.go` demonstrates deadline-driven **external process-group** termination using `exec.Command` with no shell:

1. Requires an offset-aware context deadline and a trusted executable path.
2. Launches a synthetic child in a dedicated process group (`Setpgid`) with `Pdeathsig = SIGKILL`.
3. On deadline, sends `SIGKILL` to the process group (negative PGID), falls back to direct child kill and waits for its exit (bounded additional 3s).
4. Reports `Killed`, whether a group kill was attempted, and whether the direct child was reaped. It does **not** claim that all descendants have been reaped or that key material was zeroized.
5. CI tests use only Go's own test binary as the disposable child; test cases include success, nonzero exit, missing deadline, expired deadline and a deliberately hung child.

**Security boundary and unfinished requirements:**

- A SIGKILL cannot zero an address space by itself, clear secrets that were copied before launch, erase register/DRAM remanence, or guarantee zero kernel egress after `kill(2)`. This demonstration is **not a cryptographic sanitization proof**.
- Linux process groups are NOT isolation boundaries: descendants may call `setsid`, escape or create subprocesses. Production containment requires an independently controlled **cgroup v2** (including `cgroup.kill`), namespaces, UID/seccomp and an external supervisor with privilege separation; the group-kill code is only a research baseline.
- `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlock/MADV_DONTDUMP`, A0 network isolation (nftables/netns) and independent proof of no traffic after A0 are **NOT IMPLEMENTED**.
- Stage D cannot be implemented safely as a goroutine inside the same KLM process: a hung foreign routine cannot be forcibly interrupted or its references released by Go.
- On deadlines when the child cannot be reaped within 3s, the supervisor returns `ErrReapUnconfirmed` and must escalate outside this API. No fallback to successful deletion.
- Never run this proof-of-concept against real Qalqan keys or untrusted executable paths.

## Suggested linearization points

| Operation | Atomic transition | Failure behavior |
| --- | --- | --- |
| Prepare admission | `mu`: reserve ticket + generation reference + bytes + in-flight slot | no allocation when budget is exhausted |
| Prepare transfer | `mu`: recheck generation/emergency, convert reservation into pending ticket | release reference and charge, clear private copy |
| Rotate | `mu`: mark earlier generations discard, remove queued tickets, publish fresh material | reject if session stopped or pinned-generation cap reached |
| Stop | `mu`: set stopped, flush queued tickets, mark generations retiring | no new Prepare/Rotate afterwards |
| Consume | `mu`: remove pending ticket, copy synthetic record, release references | reject foreign/reused/discarded tickets |
| AwaitDestroyed | after Stop: wait for each tracked generation's `done` | deadline => not confirmed |

**Excluded from the deterministic Go tests:** compiler/hardware memory erasure, data races in arbitrary external callbacks, fairness across >32 concurrently blocked callers, actual `bind.Send`, receive/replay authentication, nonce uniqueness across restarts, exact memory consumption in RSS, adversarial child process that escapes its group, cgroup Stage D, G-Q1/G-Q2 standards and cryptanalysis.

## Next gates

- Green CI for Go tests `-tags qazwire_exp -race`, `-count=10`, `go vet`, `gofmt`, untagged upstream and external API negative compile checks.
- Follow-up model with two or more workers and explicit reservation/Stop/Rotate state transitions; deterministic tests are NOT an exhaustive model checker.
- Stage-D production architecture must be reviewed before implementation with real key material; A0 packet capture / cgroup tests pending.
- **M2 remains NO-GO**, no merge without owner approval.
