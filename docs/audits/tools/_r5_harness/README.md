# R5 auditor harness (evidence only, not product code)

The leading underscore makes the Go tool ignore this directory; the QazWire module build is
unaffected. Nothing here implements cryptography or touches WireGuard, and nothing modifies an
owner branch: `run_r5_harness.sh` works on temporary `git archive` copies of PR #17 (`aa27727`).

| Path | What it is |
| --- | --- |
| `run_r5_harness.sh <repo> [commit]` | Reproduces the Go evidence; `MODEL=1` also runs the model and the mutation suite |
| `klm16/r5_blackbox_test.go` | R5-01 (false `ErrBacklog`), R5-E1 (identities repeat after restart; spawns the test binary twice) |
| `klm16/r5_external_test.go` | External package `klm16_test`, `reflect` only: R5-02a (read material), R5-02b (clone the sealed owner) |
| `klm16/r5_interleave_test.go` | Deterministic interleavings C1–C5 on the unmodified code (positive evidence) |
| `klm16/r5_fix_test.go` | Fix test for R5-01 (patched copy only) |
| `staged16/r5_staged_test.go` | R5-03 (pipe keeps `Wait` blocked), R5-04 (setsid escape survives), R5-07 (supervisor death), R5-08 (fd/env/limits inheritance); helper modes run as child processes; every created process is killed in `t.Cleanup` |
| `staged16/r5_fix_test.go` | Fix tests for R5-03/04/07/08 (patched copy only) |
| `patches/klm16_r5_fix.patch` | R5-01: count pinned generations after flushing queued tickets |
| `patches/staged16_r5_fix.patch` | R5-03/04/05/06/07 and the environment part of R5-08: no pipes, PID namespace (+ user namespace without root), no signal after reaping |
| `model/klm16_model.py` | Independent explicit-state model of `klm16` (`--patched`, `--traces`, `--mutants`) |
| `model/*.txt` | Recorded model outputs (`aa27727`, patched, mutants, R5-01 trace) |
| `logs/*.txt` | Harness run, verbose patched run, patched `staged16` run as uid 65534 |

Environment of the recorded runs: Go 1.24.7 linux/amd64, Linux 6.18, 2 vCPU, Python 3, root in a
container (the unprivileged user-namespace path of the patch was run separately as uid 65534).
The `staged16` tests need Linux. The full QazWire module was **not** built by the auditor: the Go
module proxy is unreachable from the audit environment. Model checking is exhaustive only within
the bounds stated in `QAZWIRE_AUDIT_R5.md` §5.2.
