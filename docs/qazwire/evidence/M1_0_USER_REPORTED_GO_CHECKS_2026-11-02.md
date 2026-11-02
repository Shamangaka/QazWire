# QazWire M1.0 — build-tagged protocol boundary baseline checks

**Date:** 2026-11-02  
**Evidence:** terminal output supplied by operator, on Ubuntu host. **Not independently re-executed** in this review.  
**Branch:** `feature/m1-exp-protocol-boundary` (operator switched to its tracking branch).  
**HEAD at review time:** `863b8d623e76771f15714736d18bca380cd75d74`. The user did not print `git rev-parse HEAD` in this particular test log; exact local commit linkage is inferred from the previously published branch and should be rechecked if used as formal evidence.  
**Go toolchain:** previously supplied same-host Go `go1.27.3 linux/amd64`.

## Tests and observations

| Command | Result in operator terminal | Caveats |
| --- | --- | --- |
| `go test -tags qazwire_exp -count=1 ./...` | PASS: all tested packages, including `internal/qazwireexp` | Bypasses Go test result cache; no full coverage report |
| `go test -race -tags qazwire_exp -count=1 ./...` | PASS: all exercised tests including `internal/qazwireexp` | Race detector only checks exercised paths |
| `go vet -tags qazwire_exp ./...` | No diagnostics observed | Exact shell exit status not logged separately; recommend verifying `PIPESTATUS` in strict evidence capture |

## Security interpretation

- `internal/qazwireexp` checks only a **provisional 4-byte syntax prefix**, not packet authentication.
- `RequireApprovedSuite` rejects all profiles: **no experimental crypto or tunnel is operational**.
- WireGuard `device/*` packet processing remains unchanged in this branch.
- This test is **not** evidence of Qalqan implementation, transport security, downgrade resistance of a complete protocol, or compliance with ST RK.
- No fuzzing duration/coverage or standalone package fuzz crash corpus has been captured yet.

## Suggested follow-up checks

```bash
cd ~/Документы/QazWire
git rev-parse HEAD
go test -tags qazwire_exp -run '^TestParsePrefix$|^TestProfilesCannotEnableCrypto$' -count=1 -v ./internal/qazwireexp
go test -tags qazwire_exp -run '^$' -fuzz '^FuzzParsePrefix$' -fuzztime=60s -parallel=2 ./internal/qazwireexp
go test -tags qazwire_exp -cover -count=1 ./internal/qazwireexp
go test -count=1 ./...
```

For `go test -fuzz`, a 60-second clean run is **only a preliminary fuzz smoke test**, not proof of parser correctness or exhaustive input coverage.

**M1 status:** scaffold PASS (operator-reported). Independent R2 protocol/crypto review and end-to-end integration are pending.
