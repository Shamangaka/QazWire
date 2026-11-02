# QazWire protocol boundary and security checklist — Draft v0.1

**Status:** PENDING security design review. **This document specifies no deployable crypto suite.** The present fork builds the *original* WireGuard protocol only.

## Verified source coupling at fork baseline

- `device/noise-protocol.go` fixes `NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"` and `WGIdentifier`; it creates ChaCha20-Poly1305 AEAD objects for handshake messages.
- The transport protocol fixes a 16-byte header and derives `MessageTransportSize` / keepalive size from `poly1305.TagSize`. The handshake message sizes and embedded tags are also fixed.
- `device/send.go` writes an 8-byte transport counter into a 12-byte ChaCha20-Poly1305 nonce; `device/receive.go` reconstructs that nonce.
- `device/noise-types.go` fixes 32-byte public/private/PSK encodings; their suitability for a redesigned handshake is **not** assumed.
- `device/cookie.go` and key derivation are further cryptographic dependencies. Cipher replacement in send/receive alone would NOT produce an isolated protocol.

These observations describe this fork's current source structure, not a formal security proof or exhaustive inventory.

## Experimental profile prerequisites (NOT IMPLEMENTED)

| Field | Required before enabling experiment |
| --- | --- |
| Protocol identifier | A distinct constant and version with domain separation from WireGuard at handshake, transcript, and derived-key layers |
| Suite | Named and immutable for the entire session; no automatic WireGuard fallback |
| Identity / key agreement | Initial candidate: original X25519 only within a specifically documented hybrid experimental suite; no national key-agreement claim |
| KDF / transcript hash | Explicit fixed algorithms and proof they bind version and complete suite; at first may retain BLAKE2s |
| Data protection | Review-selected AEAD or separately analysed Encrypt-then-MAC composition using ST RK 4009-2025, with independent purpose-separated keys |
| Authentication tag | Precisely defined per normative profile, including applicability of ST RK 1073-2025 thresholds; must account for overhead and packet size |
| Nonce/counter | Form, uniqueness scope, limits, retransmissions, key changes, wrap/rollback behavior |
| Associated data | Explicit version, message type, receiver ID, packet counter and any other required header fields; binding and replay semantics reviewed |
| Replay defense | Authenticated packet rejected before plaintext release; replay window and key-index behavior tested |
| Interoperability | Experimental-to-standard handshake fails closed, no fallback; no use of ordinary WG-compatible marketing claims |
| Rekey | Defined byte/message/time limits, nonce lifetimes and key separation; test old-key overlap and key destruction |
| KAT and fuzz tests | National standard vectors, independent implementation, negative mutation tests, fuzzing, panic/overflow bounds |
| Threat model | Active network adversary, endpoint compromise outside cryptographic boundary, replay, downgrade, DoS and traffic analysis clearly distinguished |

## Design gate

No protocol source changes until:

1. Full parameters and the selected authenticated-encryption mode are referenced to the exact normative clauses, with reviewer and applicability status.
2. Packet diagrams, version/discriminator, initiation/response/cookie/transport encodings, AAD and tag sizes are frozen in a reviewed draft.
3. Cryptographic providers have an explicit error-returning, fail-closed API that cannot emit plaintext on authentication failure.
4. Tests cover cross-profile failure, malformed packet lengths, counter exhaustion, independent decryption, and deterministic known-answer vectors.
5. Benchmarks are compared against **the identical upstream revision** with documented CPU, toolchain, MTU and test payloads.

## Audit of earlier assumptions

Do **not** treat an arbitrary replacement for `chacha20poly1305.New` as sufficient. Transport `cipher.AEAD` compatibility does not solve protocol authentication, domain separation, wire-size coupling or normative acceptance.

Do **not** equate an algorithm's name or key length with evidence of a certified SKZI or a particular ST RK 1073-2025 level.

No production key management or physical entropy qualification is provided by this experiment.
