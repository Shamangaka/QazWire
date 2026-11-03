# R4.1 auditor harness (evidence only, not product code)

The leading underscore makes the Go tool ignore this directory; the QazWire module build is
unaffected. Nothing here implements Qalqan or cryptography, and nothing modifies the owner's
branches: `run_r4_1_harness.sh` works on temporary copies of PR #11 (`f5e078c`).

| Path | What it is |
| --- | --- |
| `run_r4_1_harness.sh <repo> [commit]` | Reproduces all R4.1 evidence |
| `sessionlab_blackbox/r41_blackbox_test.go` | 10 tests for the **unmodified** `sessionlab/session.go` (blob `bd3aff6`): demonstrations of R41-01…07 and a stress test of the invariants |
| `sessionlab_fix/session_r41_minimal_fix.patch` | Minimal fix of R41-01…07 (applies with `patch -p1` / `git apply` to `f5e078c`) |
| `sessionlab_fix/r41_fixed_test.go` | 9 tests asserting the corrected behaviour + the same stress test; run on the PATCHED copy together with the owner's 17 tests |
| `model/sessionlab_model.py` | Explicit-state model of the implemented protocol (prepare/seal/dispatch/discard/rotate/beginEmergency/awaitDrained/finish); `--traces`, `--mutants` |
| `model/sessionlab_model_output.txt`, `model/sessionlab_model_mutants.txt` | Recorded outputs |
| `racechk/` | Shows that Go's race detector does not report races on writes made by `clear()` (control case with an indexed write is reported) |

Environment of the recorded runs: Go 1.24.7 linux/amd64, 2 vCPU, Python 3. Model checking is
exhaustive only within its bounds (2–3 workers with one packet each, one rotation, one emergency,
one awaitDrained, two tickets per key). The model of the PATCHED code was not built.
