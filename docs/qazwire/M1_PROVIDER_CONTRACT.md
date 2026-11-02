# QazWire M1.2 — draft cryptographic provider contract and key-operation barrier

**Status:** RESEARCH ONLY / DRAFT. **No Qalqan implementation. No experimental tunnel. No claim of SKZI or ST RK compliance.**

## Scope and branch isolation

This is a *stacked* change based on `feature/m1-exp-protocol-boundary` (PR #3). It changes only the build-tagged `internal/qazwireexp` package and this document. The original `device/*`, handshake, IPC, TUN and default `wireguard-go` remain unchanged.

The package is only compiled with `-tags qazwire_exp`. The wire-format bytes, draft profile IDs and authentication tag sizes are **PROVISIONAL** until R2 review of [Audit PR #2](https://github.com/Shamangaka/QazWire/pull/2).

## 1. Read-only candidate profile metadata

`DraftProfile(id)` accepts only:

| ID | Candidate profile name | Provisional authentication tag bytes | Operating status |
| --- | --- | ---: | --- |
| `0x01` | `QWX1-Q256EM-DRAFT` | 32 | **DISABLED** |
| `0x02` | `QWX1-Q128CM-DRAFT` | 16 | **DISABLED** |

ID 0 returns `ErrInvalidProfile`, all other IDs return `ErrUnknownProfile`. The returned metadata contains unexported fields and is returned **by value**, so callers cannot alter the canonical metadata.

**Critical:** metadata is not a promise of cryptographic security, approval for traffic, or regulatory acceptance. The two candidate constructions need formal bounds, independent algorithm analysis and review.

## 2. Fail-closed provider resolution

`ResolveCryptoProvider(profileID)` **always returns `(nil, error)`**:

- ID 0: `ErrInvalidProfile`.
- Known draft IDs 1 and 2: `ErrNoApprovedSuite`.
- All other IDs: `ErrUnknownProfile`.

There is **no registration method**, no provider implementation, no mode negotiation, and no automatic fallback to ChaCha20-Poly1305. `RequireApprovedSuite()` from M1.0 independently remains fail-closed.

`CryptoProvider` and `TransportProtector` are **compile-time design interfaces only**. They have no implementations; the construction of a session, derivation of keys, destruction/secret ownership and integration into packet processing are deliberately **not defined**.

The proposed transport header is a `Header [16]byte` value; the provider contract describes `Seal`, `Open`, `Destroy`. It **does not** enforce authentication, safe in-place buffer reuse, constant-time behavior, or zeroization. Those are future mandatory testable contracts, not accomplished properties.

## 3. Concurrency barrier for a future session

`OperationGate` is a zero-value-initialized admission/drain barrier; it does not hold cryptographic keys:

1. `Use(callback)` accepts a new callback iff the gate is open, increases an in-flight reference counter, executes it **outside** the gate mutex and decrements the counter via `defer` even if the callback panics.
2. `CloseAndDrain()` atomically forbids admission and blocks until all already accepted callbacks return. Multiple concurrent closing calls are idempotent.
3. After `CloseAndDrain()` returns, a future owner **could** invoke a reviewed provider `Destroy()` on the underlying session, provided **all** paths using the key were strictly forced through `Use()` and no raw references escaped callbacks.

This barrier does **not** wipe keys or prevent other references from accessing a provider outside `Use()`. If code bypasses the gate, its safety invariant is invalid. It must not be mistaken for a complete key-management design. **Never call `CloseAndDrain()` from inside a `Use()` callback**: it would deadlock waiting for its own active reference.

### Lifecycle invariants to be reviewed before integration

- No key operation may begin after the close transition.
- Destruction of round keys must occur only after in-flight operations have drained.
- No destroyed key or reinitialized session may be used for an outgoing packet.
- A failed authentication must not expose plaintext, modify replay window state, or cause fallback.
- The provider must own secret storage; caller-facing `[]byte` ownership, copying and zeroization guarantees are currently **BLOCKED**.
- Any provider panic is a defect; the gate releasing its lease does **not** make an unsafe provider panic recoverable or a good protocol error.
- The latest R1 design of CTR + EMAC is **NOT approved**; key/message volume limits need a formal analysis.

## 4. Tests (target Ubuntu 24.04 / Go 1.27.3)

From a checkout of this stacked feature branch:

```bash
go test -tags qazwire_exp -count=1 ./...
go test -tags qazwire_exp -race -count=1 ./...
go vet -tags qazwire_exp ./...
go test -count=1 ./...
```

Supplemental targeted checks:

```bash
go test -tags qazwire_exp -run 'TestDraftProfiles|TestNoCryptoProvider|TestOperationGate' -count=100 ./internal/qazwireexp
go test -tags qazwire_exp -race -run 'TestOperationGate' -count=100 ./internal/qazwireexp
```

Local independent prototype package (Go 1.23.2, no network dependencies) was tested with:

```bash
GO111MODULE=off go test -tags qazwire_exp -count=1 -race ./internal/qazwireexp
GO111MODULE=off go vet -tags qazwire_exp ./internal/qazwireexp
```

**Only the isolated package was executed locally.** Full repository test results require a run on the user's Ubuntu. A green result still does not prove security or implementation correctness under every possible schedule.

## 5. Blocking decisions for M1.3/M2

1. Claude R2 independent review of the draft `Header`, profile identifiers, required AAD semantics, cryptographic domain separation, and API ownership.
2. Rigorous per-key packet/block/byte security advantage bounds and multi-user analysis for Qalqan CTR+EMAC and alternatives.
3. Reviewed key-derivation API with explicit purpose separation, secret lifetimes and no duplicate nonce/counter assignment.
4. Real cryptographic implementation must pass KATs, negative tests, independent differential tests, and side-channel analysis before enabling real traffic.
5. Avoid any production or sensitive data with experimental cipher code; no ST RK 1073-2025 compliance claims without a formal conformity process.

No automatic merges to `master` or to other feature branches.
