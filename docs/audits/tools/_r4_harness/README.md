# R4 auditor harness (evidence only, not product code)

The leading underscore makes the Go tool ignore this directory; `go build/vet/test ./...`
of the QazWire module is unaffected. Nothing here implements Qalqan or any cryptography.
Nothing here modifies the owner's branches: `run_r4_harness.sh` works on temporary copies.

| Path | What it is |
| --- | --- |
| `run_r4_harness.sh <repo> [ref]` | One command to reproduce all R4 evidence against PR #8 (default ref `origin/feature/m1-4-synthetic-key-lifecycle`) |
| `keylab_blackbox/r4_blackbox_test.go` | Tests for the **unmodified** `keylab/slot.go` (package-internal names only). Includes subprocess tests for crashes and a statistical detector for R4-KLM-01 |
| `keylab_instrumented/make_instrumented.py` | Creates a copy of `slot.go` with four `r4hook("<point>")` calls inserted; no original statement is changed or reordered (the script fails if a pattern is not found exactly once) |
| `keylab_instrumented/r4_interleave_test.go` | Deterministic reproduction of the exact interleavings (pause a goroutine at a named point, act, resume) |
| `model/klm_model.py` | Explicit-state model checker (BFS over all interleavings, one step = one atomic operation) for M1.4 and for the proposed M1.5 protocol; `--traces` prints the shortest interleaving per observation, `--mutants` checks that the checker detects injected bugs |
| `model/klm_model_output.txt`, `model/klm_model_mutants.txt` | Recorded outputs |
| `klm15ref/` | Separate Go module: reference model of the M1.5 lifecycle (state word, one-time tickets, poison, wipe states, egress gate, device-level emergency/rotation serialization) with tests T-KLM-13…23 |

Recorded environment: Go 1.24.7 linux/amd64, 2 vCPU (Intel Xeon 2.8 GHz), Python 3, shared VM.
Owner target platform (Ubuntu, Go 1.27.3) was not available to the auditor. Model-checking results
are exhaustive **only within the stated bounds** (2–3 workers, 1–2 emergency callers, one operation
per worker, wipe assumed to terminate).
