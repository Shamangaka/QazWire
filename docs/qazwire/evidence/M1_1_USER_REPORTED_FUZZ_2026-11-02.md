# QazWire M1.1 — prefix parser fuzz smoke-test and coverage

**Date:** 2026-11-02.  
**Source:** Terminal output supplied by the QazWire project operator, **not independently re-executed** in this review environment.  
**Exact reported test checkout SHA:** `e89c8f6ac0eea9c3830528e7044feb08305c1014`.  
**Branch:** `feature/m1-exp-protocol-boundary`.  
**Target package:** `golang.zx2c4.com/wireguard/internal/qazwireexp`, guarded by `qazwire_exp` build tag.  
**Protocol status:** prefix **syntax-only** draft; there is no working experimental cryptographic suite. Original WireGuard is unchanged.

## Operator-observed results

| Check | Command / evidence | Observed result |
| --- | --- | --- |
| Fuzzing | `go test -tags qazwire_exp -run '^$' -fuzz '^FuzzParsePrefix$' -fuzztime=60s -parallel=2 ./internal/qazwireexp` | **PASS**: 7,137,789 fuzz executions over 60.070 s; two fuzz workers; 7 total interesting inputs including corpus; no panic/crash reported |
| Statement coverage | `go test -tags qazwire_exp -cover -count=1 ./internal/qazwireexp` | **PASS**: `coverage: 100.0% of statements` in this small package |
| Upstream compatibility smoke | `go test -count=1 ./...` without `qazwire_exp` build tag | **PASS**: all testable packages passed; packages without tests reported `[no test files]` |

The operator supplied no separate process exit code, coverage profile, fuzz crash corpus or immutable build digest. The Go testing tool printed `PASS` for fuzzing and successful package outputs for the other checks.

## What the result does and does not establish

The experiment confirms that **these exercised test inputs** did not cause a reported failure, and that normal Go unit tests reached all statements in the *small parser package*. These results **do not** prove packet-parsing correctness for all inputs, memory-safety beyond Go's guarantees, branch/path coverage, downgrade resistance, authenticated encryption, or security of an operational QazWire protocol.

Go fuzzing reports 'interesting inputs' based on coverage exploration. The count is **not** a count of vulnerabilities.

**Critical boundary:** `ParsePrefix` is only a four-byte parser. It does not authenticate packet contents, validate complete handshake/transport packet layouts, derive session keys, or receive network packets in a VPN process. `RequireApprovedSuite` rejects every profile; neither Qalqan nor any experimental transport is enabled.

## Next technical gates

1. Independent review of the candidate four-byte header and profile namespace by the Claude R2 auditor (PR #2); avoid freezing provisional wire protocol constants prematurely.
2. Exercise targeted negative assertions for profile mismatches, unassigned IDs, legacy types and malformed/truncated prefixes. Current unit/fuzz seeds cover a subset; full wire-packet validation is not implemented.
3. Document immutable suite registration and packet/handshake domain-separation contracts as *review-only design*, before any crypto provider integration.
4. Keep Qalqan code integration blocked until the EtM/EMAC security bounds and independent conformance tests are adequately reviewed.

No changes to `master` or active `device/*` transport code are made by this evidence record.
