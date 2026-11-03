# QazWire M1.6.2 — R5-01 remediation (Research Only)

**Base:** PR #17 at `aa27727acbb700d622e562da350e684d4b8d11ee`.
**Independent evidence:** Draft PR #18 at `105e2c28135dd8bdf89f61cb0de160557dd6e3ab` (`QAZWIRE_AUDIT_R5.md`).
**Scope:** `internal/qazwireexp/klm16` and regression tooling. **No real secrets, encryption, Qalqan, UDP, WireGuard transport modifications, or production security claims.**

## Defect / linearization

R5-01: `Rotate` counted `g.refs` for all non-current generations **before** invalidating queued tickets on those generations. Since `g.refs` includes both pending tickets and in-flight leases, at `maxPinned=1` the second rotation could close a healthy session with `ErrBacklog` solely because an older ticket was queued. This is a fail-closed **availability** / API-contract defect, not a demonstrated confidentiality break.

Under the session mutex, the new transaction is:

1. Check stopped session and epoch exhaustion.
2. Mark all non-current generations retiring/discarded; discard their pending tickets and release their references.
3. Count the remaining `g.refs` on non-current generations. These now represent **in-flight leases**, not queue tokens.
4. If the count reaches `maxPinned`, stop with `ErrBacklog`; otherwise mint a new synthetic generation, mark old retiring and publish.

The post-flush `maxPinned` check still prevents uncontrolled growth from genuinely stalled workers. If material minting subsequently fails, `stopLocked` remains fail-closed. All steps run under `s.mu`, so external `Prepare` / `Consume` cannot interleave with the queue flush.

## Tests and model

- `TestM162_QueuedGrandparentDoesNotConsumePinnedBudget`: second rotation flushes queued grandparent, remains open, permits current generation.
- `TestM162_GrandparentInFlightStillPoisonsOnBudget`: genuine paused in-flight lease still triggers `ErrBacklog`, queue is flushed first, erasure waits for released lease.
- `TestM162_RepeatedQueuedFlushingAndPruning`: repeated queue flushes do not spuriously stop the session.
- Existing `TestM16_BacklogFailClosedAndNoErasureUnderLease`, M1.6.1 reservation tests, full tagged/untagged regression.
- Exact auditor R5 state-model copy from Draft PR #18, blob `d8eb72aea79f2040736b2fc6fb28b7858330b877`, at `docs/qazwire/tools/r5_klm16_model.py`; CI checks baseline K3 reports the expected counterexample and the `--patched` model K3/K4/K6 reports no violations. This is an **abstract model**, not a Go proof.

## Out of scope / not repaired

- **R5-02:** `reflect` can read / duplicate state within the same Go process. A sealed interface is not an isolation boundary.
- **R5-03/04/05/06/07/08:** `staged16` is still a demonstration only. The proposed PID/user-namespace patch from Draft PR #18 has **not** been applied: it is not a substitute for cgroup v2 containment, a separate launcher/watchdog, and denial of network access.
- **R5-E1:** epoch/material/session IDs reset after restart; no cryptographic nonce domain exists.
- `Prepare` panic while `s.mu` is held, RSS hard limits, secure key erasure, crash dumps, and foreign callbacks remain unproven or unimplemented.

**Next milestone:** M1.7, a separate, synthetic process KLM with a security-boundary specification in `docs/qazwire/M1_7_ISOLATED_KLM_DESIGN.md`. Do not extend `staged16` into production as-is.

**Gate:** full tagged race tests, vet, upstream untagged tests, independent model K3/K4/K6. **M2 / actual Qalqan / production VPN remain NO-GO.** No merge into master without explicit authorization.
