# R3 auditor harness (evidence only, not product code)

The leading underscore makes the Go tool ignore this directory, so `go build ./...`,
`go vet ./...` and `go test ./...` of the QazWire module are unaffected.
Nothing here implements Qalqan or any cryptography.

| Directory | What it is | How it was run by the auditor |
| --- | --- | --- |
| `gate_tests/` | Adversarial tests and benchmarks for `OperationGate` (PR #4) and the prefix parser (PR #6). Package `qazwireexp`, build tag `qazwire_exp`. | Copy the three files into a **copy** of `internal/qazwireexp` at PR #6 HEAD `2d05d76` (gate and contract files are byte-identical to PR #4 HEAD `4825bdd`), then `go test -race -count=1 -tags qazwire_exp -run TestR3 -v` and `go test -run '^$' -bench R3 -cpu 1,2 -tags qazwire_exp`. |
| `klmref/` | Reference model of the staged emergency shutdown that resolves KL-2 vs KL-10 (separate module, no crypto; the provider is an observing stub). | `go vet ./... && go test -race -count=1 -v ./...` (use `-short` for a 100-round stress). |
| `sealed/` | Demonstration that an interface with an unexported method is **not** sealed against embedding by another package. | `go test -count=1 -v ./...` |

Environment of the recorded runs: Go 1.24.7 linux/amd64, 2 vCPU (Intel Xeon 2.8 GHz), shared VM.
Benchmarks on a shared 2-vCPU VM are indicative only. Results on the owner's target
(Ubuntu 24.04 / Go 1.27.3) and on machines with more cores were **not** produced by the auditor.

Do not copy these files into the owner's branches; they are evidence for `QAZWIRE_AUDIT_R3.md`.
