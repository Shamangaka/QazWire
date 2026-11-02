# QazWire M1.3 — addressed independent PR #3 parser-review findings (R2)

**Research-only / review-only:** These changes do **NOT** enable Qalqan or any experimental VPN session. They modify only the `qazwire_exp`-tagged `internal/qazwireexp` package. No change to standard `device/*`, Noise, default WireGuard crypto or network routing.

## Changes

### R2-PR3-01 — bind parser to trusted configuration

`ParsePrefix(packet, expected)` was removed. Callers now construct `NewPrefixParser(profile)` from the intended, trusted device configuration and use `parser.Parse(packet)`. The unexported `expected` field cannot be changed after construction. IDs are validated through the single candidate-profile lookup in `DraftProfile` from M1.2.

**Important limitation:** Go cannot prohibit careless code from deliberately calling `NewPrefixParser(ProfileID(packet[1]))` for each received network packet. The future device constructor MUST create a parser once using trusted configuration and retain it. This design reduces the risk of accidental omission but does not prove end-to-end profile isolation.

### R2-PR3-02 — parsed bytes are NOT authenticated

`UnauthenticatedPrefix` replaces `Prefix`; its fields are private with read-only accessors. A `Parse` success means *only* syntax was recognized, not that a cryptographic sender, profile, key, counter or payload was verified. No `AuthenticatedHeader` type or AEAD/EtM implementation exists.

### R2-PR3-05 — fail-closed provider activation

The M1.2 `ResolveCryptoProvider` is the only proposed provider-resolution path and **has no registered suites**, returning `nil,error` for all 256 possible IDs. The legacy `RequireApprovedSuite` remains as a compatibility-only research guard; it always denies.

**Future gate:** the type system, visibility, key ownership, binding to the authenticated transcript and unforgeable construction of approved `TransportProtector` must be independently reviewed before any `device/*` integration. Current exported Go interfaces could be implemented by arbitrary callers, but no such implementation can be registered or used in the actual VPN.

## Tests on Ubuntu

```bash
cd ~/Документы/QazWire
git fetch origin
git switch --track origin/feature/m1-3-reviewed-prefix-api
set -o pipefail
go test -tags qazwire_exp -count=1 ./... 2>&1 | tee m13-tests.log
go test -tags qazwire_exp -race -count=1 ./... 2>&1 | tee m13-race.log
go vet -tags qazwire_exp ./... 2>&1 | tee m13-vet.log
go test -count=1 ./... 2>&1 | tee m13-upstream.log
go test -tags qazwire_exp -run '^$' -fuzz '^FuzzParsePrefix$' -fuzztime=60s -parallel=2 ./internal/qazwireexp
```

**Status:** This exact GitHub commit has NOT yet undergone full-module testing on Ubuntu; no results may be claimed before execution.

## Outstanding design review

1. Claude R2 needs to review PR #4 (M1.2), particularly the reentrant `CloseAndDrain` deadlock and the discrepancy between KL-2 and KL-10 concerning emergency key zeroization.
2. Strict full-packet lengths depend on type and audited suite overhead; the parser intentionally validates only four bytes, so **it MUST NOT be wired directly into network receive paths**.
3. Cryptographic domain separation and MAC coverage, genuine key-ticket ownership, KAT/constant-time primitives and ST RK normative applicability are unresolved.
