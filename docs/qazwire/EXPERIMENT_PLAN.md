# QazWire — Experiment Plan v0.1

**Status:** RESEARCH ONLY. Not a cryptographic product, not an SKZI, not certified.  
**Base:** fork of `WireGuard/wireguard-go`, upstream base branch `master`.  
**Project:** QazInfraCrypto is a separate, reusable crypto-library project. No algorithm implementation is imported into this fork yet.

## Objective

Demonstrate a two-node Linux userspace encrypted tunnel using an independently specified, reviewed and tested Kazakhstan-oriented **experimental transport cryptographic profile**, while preserving a clean, working upstream WireGuard baseline for comparison.

**Do not use QazWire experimental builds to protect operational, restricted, personal, or otherwise sensitive traffic.** Use isolated synthetic lab traffic only.

## Boundary and invariants

- The `master` branch remains an upstream-compatible baseline. Work belongs in `experimental/*` branches, reviewed via Draft PR; no automatic merge.
- Standard WireGuard is **not** crypto-agile. Any change to cipher, tag length, transcript, packet encoding, or key derivation produces an **incompatible protocol**, not a compatible WireGuard configuration.
- `WG_STANDARD`: unchanged upstream wire format and cryptographic mechanisms.
- `QAZWIRE_EXPERIMENTAL`: a separate protocol domain, **disabled until a reviewed protocol specification, versioned identifier, algorithm suite, and security tests exist**.
- No opportunistic negotiation, downgrade, plaintext fallback, or implicit conversion of legacy peers to the experimental profile.
- No unapproved Qalqan implementation, generic block-mode wrapper, unauthenticated encryption, ad hoc AEAD, truncated active-attack authentication tags, or plaintext-before-authentication.
- Source, builds and test logs must not contain real private keys, standard PDFs with distribution restrictions, tokens, or production packet captures.

## Milestones and exit criteria

| Gate | Deliverable | Evidence |
| --- | --- | --- |
| M0 (baseline) | Reproducible upstream build and tests, two Linux namespace peers using ordinary WireGuard | `go test ./...`, `go vet ./...`, exact commit & toolchain, synthetic traffic capture, handshake/rekey test log |
| M1 (design) | Experimental profile specification with explicit transcript & key separation; independent AEAD interface and wire-format audit | reviewed spec, threat model, version/domain separation review, negative tests defined |
| M2 (Qalqan transport) | Validated Qalqan primitive + *reviewed* authenticated-encryption construction in data plane, bound to negotiated profile (no silent fallback) | KATs, cross-implementation differential tests, malformed-tag/AAD/replay/nonce tests, independent review |
| M3 (full suite) | Evaluated handshake/KDF/identity choices and protocol redesign as needed | transcript tests, downgrade and unknown-key-share analyses, formal/security review where possible |
| M4 (qualification path) | Product-specific ST RK 1073-2025 clause-level applicability & evidence matrix, legal/provenance review | independent normative review; **not** a certificate or permission to deploy |

## Immediate tasks

1. Run `bash scripts/qazwire-baseline.sh` on Ubuntu with a usable Go toolchain. Archive the report and `git rev-parse HEAD`.
2. Run a **separately approved**, isolated `ip netns` two-peer baseline using stock cryptography. Capture only synthetic packets, latency/throughput and rekey behavior.
3. Prepare an exact inventory of algorithm coupling in `device/noise-protocol.go`, `device/noise-types.go`, `device/send.go`, `device/receive.go`, `device/cookie.go` and transport packet buffer/batching logic.
4. Independently select and justify an authenticated encryption construction compatible with the exact block/key parameters of ST RK 4009-2025; determine required authentication tag size and packet overhead for each intended profile.
5. Before touching `device/*`, define explicit protocol-version binding and negative cross-profile/downgrade tests.

## Open critical dependencies

- ST RK 4009-2025 algorithm implementations are research artifacts outside this repository; correctness, side-channel behavior, licensing, key schedule and secure API are not yet accepted into QazInfraCrypto.
- ST RK 1073-2025 is a target for future assessment (effective 2027-01-01); research does not establish regulatory conformity. The project-wide bilingual clause 4.4 discrepancy remains unresolved.
- L3/L4 MAC-length and entropy-source conditions require detailed verified applicability and independent assessment; a 128-bit WireGuard/Poly1305 tag cannot be silently assumed sufficient.
- Qalqan block cipher alone is **not** an AEAD; a cryptographic design review is a blocking gate before a Qalqan data-plane implementation.
- License/provenance review is required for third-party code, including treatment of any claim to domestic SKZI status.

## References

- Upstream: https://github.com/WireGuard/wireguard-go
- WireGuard protocol: https://www.wireguard.com/protocol/
- QazInfraCrypto: https://github.com/Shamangaka/QazInfraCrypto
- Protocol-specific constraints: `docs/qazwire/PROTOCOL_BOUNDARY_V0_1.md`
