# R4.2 auditor harness (evidence only, not product code)

The leading underscore makes the Go tool ignore this directory; the QazWire module build is
unaffected. Nothing here implements Qalqan or cryptography, and nothing modifies the owner's
branches: `run_r4_2_harness.sh` works on temporary `git archive` copies of PR #13 (`45984d7`).

| Path | What it is |
| --- | --- |
| `run_r4_2_harness.sh <repo> [commit]` | Reproduces the Go evidence; `MODEL=1` also runs the model (hours on 2 vCPU) |
| `sessionlab_blackbox/r42_blackbox_test.go` | 8 tests for the **unmodified** `sessionlab/session.go` (blob `0305fa2`): R42-01a/b/c, R42-02, R42-03, R42-04, R42-05, R42-10. Each PASSES when the defect is reproduced and logs `CONFIRMED` |
| `sessionlab_instr/make_instrumented.py` | Builds an instrumented copy of `session.go` that only **inserts** `r42hook("prepare:beforeLock")` and `r42hook("onFail:latched")`; fails unless each pattern matches once. Works for the original and for the patched file |
| `sessionlab_instr/r42_interleave_test.go` | Deterministic interleavings on the instrumented **unmodified** copy: R42-07, R42-06, R42-06b |
| `sessionlab_instr/r42_fix_interleave_test.go` | The same interleavings asserting the **fixed** behaviour (FAIL on `45984d7`, PASS on the patch) |
| `sessionlab_fix/session_r42_minimal_fix.patch` | Minimal fix of R42-04/05/06/07/10 (`git apply` / `patch -p1` on `45984d7`). R42-01/02/03 are architectural and deliberately not patched |
| `sessionlab_fix/r42_fix_test.go` | Fix tests for R42-04/05/10 (compile only on the patched copy) |
| `model/m152_model.py` | Explicit-state model of M1.5.2 (`--fast`, `--traces`, `--patched`, `--mutants [names]`) |
| `model/*.txt` | Recorded model outputs (baseline, patched, mutants, traces) |
| `logs/*.txt` | Recorded Go test logs |

Environment of the recorded runs: Go 1.24.7 linux/amd64, 2 vCPU, Python 3. The full QazWire module
(`go build ./...`) was **not** built by the auditor: the Go module proxy is unreachable from the
audit environment. Only `internal/qazwireexp/...` was compiled and tested, as a stand-alone module.
Model checking is exhaustive only within the bounds stated in `QAZWIRE_AUDIT_R4_2.md` §3.3.
