# QazWire M1 — experimental protocol boundary scaffold

**Status: DRAFT / RESEARCH ONLY.** This code **does not** implement Qalqan, change the WireGuard transport, instantiate cryptographic keys, or enable an experimental VPN. It MUST NOT be used to protect any information. The four-byte header values are **provisional** pending review of audit PR #2.

## Scope

- Isolated package `internal/qazwireexp`, built **only** with `-tags qazwire_exp`.
- Four-byte prefix syntax checks and explicit rejection of **standard WireGuard packet types 0x01–0x04**.
- Draft message types `0x11–0x14`, provisional profile IDs `0x01` and `0x02`; reject unknown/zero profiles, mismatches, and nonzero reserved bytes.
- No session can start: `RequireApprovedSuite` returns `ErrNoApprovedSuite` for every ID, including draft ones.
- The unmodified `device/*` code neither imports nor uses this package. Default WireGuard behavior remains unchanged.

## Tests

From the repository root on Ubuntu with a compatible Go toolchain:

```bash
go test -count=1 ./...
go vet ./...
go test -tags qazwire_exp -count=1 ./...
go vet -tags qazwire_exp ./...
go test -race -tags qazwire_exp -count=1 ./...
```

The independent prototype package was locally tested with a stock Go 1.23.2 using:

```bash
GO111MODULE=off go test -tags qazwire_exp -count=1 -race ./internal/qazwireexp
GO111MODULE=off go vet -tags qazwire_exp ./internal/qazwireexp
```

The full repo commands above were **not executed** in the development container (external dependency fetch unavailable). They must run on the operator's Ubuntu, then be recorded as user-reported test evidence.

## Gate before implementation

The prefix parser is **not** a security boundary. It only validates public bytes. A complete new protocol MUST additionally bind profile ID into cryptographic key schedule and handshake transcript, authenticate transport headers, reject unknown suites without fallback, and protect all incoming packet paths. None of this has been implemented here.

Audit R1: https://github.com/Shamangaka/QazWire/pull/2. The audit's proposed CTR + EMAC construction, per-key security bounds and key-lifecycle strategy remain under review. Do not integrate a Qalqan provider into the transport until those blockers are resolved and an owner-approved revision is reviewed. In particular, never interpret the presence of `qazwire_exp` build tags as permission to enable experimental encryption.

## Suggested next gates

1. Independent review of the provisional wire format; freeze a distinct protocol identifier with domain separation of chain key, transcript, cookies and transport KDF.
2. Resolve the per-key and multi-user security bounds for the selected authenticated encryption construction and independent cryptographic vectors.
3. Review the provider interface and key-destruction lifetime model before linking it into `device/*`.
4. Add negative packet-injection/downgrade/replay tests and interop tests between two experimental peers **only after** a reviewed suite exists.
