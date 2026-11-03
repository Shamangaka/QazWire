# QazWire M1.5 — operator-reported Ubuntu verification

**Date of terminal output:** 2026-11-03 (operator local time); **source:** owner-provided Ubuntu console transcript. These results were NOT independently executed by the reviewer.

**Branch:** `feature/m1-5-synthetic-egress-lifecycle`. The remote branch HEAD verified before this evidence-only commit: `b30da3d13591aeee09b59041419e22e3b33373bc`. Terminal output shows a new remote-tracking branch created and checked out, but does not print `git rev-parse HEAD`; SHA binding is derived from the observed tracking branch and its verified remote head.

## Observed results

Commands were run under `set -euo pipefail`, so the final `M1.5 ALL CHECKS PASSED` marker confirms exit code 0 for the full sequence.

| Command | Terminal evidence | Result |
| --- | --- | --- |
| `go test -tags qazwire_exp -count=1 ./...` | `ok` for all tested packages including `internal/qazwireexp/sessionlab` | **PASS** |
| `go test -tags qazwire_exp -race -count=1 ./...` | All tested packages `ok`, no race reports | **PASS** |
| `go vet -tags qazwire_exp ./...` | No diagnostics; script advanced | **PASS** |
| `go test -count=1 ./...` | All tested default-mode packages `ok` | **PASS** |
| `go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/sessionlab` | `ok .../sessionlab 1.874s` | **PASS** |

## Explicit limits

- This is a **non-cryptographic** synthetic harness. `processor.process` returns a copy of plaintext, not encrypted traffic. No Qalqan algorithm, keys or real network output are connected.
- These tests do not prove no race/deadlock across every schedule and do not remove independent R4 findings: unbounded waits allowed via contexts without deadline, no POISON / WIPE_FAILED transition, no consumed-once packet ticket, and no emergency/rotation serialization.
- An egress gate prevents new synthetic send admissions after shutdown but does not unsend already admitted or kernel-queued packets.
- Full protocol assurance, cryptanalysis of Qalqan, normative applicability and genuine key erasure are **BLOCKED**.

**Disposition:** M1.5 test gate PASS (operator-reported); architecture review PENDING; M2 Qalqan integration BLOCKED; no merges authorized.
