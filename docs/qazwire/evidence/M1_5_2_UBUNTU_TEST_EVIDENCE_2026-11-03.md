# M1.5.2 Ubuntu test evidence — 2026-11-03

**Result:** ALL CHECKS PASSED, **operator-reported** from Ubuntu Go 1.27.3 on local checkout `feature/m1-5-2-r41-owned-providers`.

**Important SHA-binding limitation:** local `git rev-parse HEAD` was previously `30b5efaa8e397201e5e94c8fe631bc31820bd9a1`; the operator then fetched `ed0c3142895143bfc41eb3ed2c95aa536ce2233e` into `origin/feature/m1-5-2-r41-owned-providers` and restored `r41_2_regression_test.go` from the remote branch. The working tree contained locally `gofmt -w`-formatted modifications to `session.go`, `r41_regression_test.go`, and `r41_2_regression_test.go`. **This successful run is against that local formatted mixed working tree, not any single recorded Git commit.** The log alone does not establish reproducibility of the unformatted GitHub branch HEAD. No commit, push, or merge was reported.

## Observed operator results

- Targeted `TestR412_GrandparentInFlightDroppedOnSecondRotation`: **PASS**, 50 repeats with `-race`.
- `test -z "$(gofmt -l internal/qazwireexp/sessionlab/*.go)"`: **PASS**.
- `git diff --check`: **PASS**.
- `go test -tags qazwire_exp -count=1 ./...`: **PASS**.
- `go test -tags qazwire_exp -race -count=1 ./...`: **PASS**.
- `go vet -tags qazwire_exp ./...`: **PASS**.
- `go test -count=1 ./...`: **PASS** (upstream/no experiment).
- `go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/sessionlab`: **PASS**, 5.138 s.

Operator output ended with `M1.5.2 ALL CHECKS PASSED`; attached conversation log filename: `qazwire_m152_final_v2.log`. Initial test expectation mismatch and separate formatting failure were resolved **in the local checkout**.

## Next release gates

1. Publish the exact formatted source of three changed Go files to a committed Git SHA on PR #13 (without introducing untested behavior or modifying `master`). Review the resulting `git diff` to establish formatting-only changes.
2. Rerun full module tests against that **exact, clean Git commit** in the owner's Ubuntu and record local `git rev-parse HEAD`.
3. Independent Claude R4.2 architecture / model-checker review of the actual changed implementation, including provider ownership, two-rotation stale generation, async wipe failure, and buffer aliasing; prior R4.1 model does not prove M1.5.2.
4. KLM release gate and real crypto integration remain BLOCKED; no security or normative conformance claims.

**No merge authorization.**
