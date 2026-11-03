# QazWire R4.2 — immutable GitHub Actions evidence (2026-11-03)

Target owner commit: `45984d70b46c86c87bad85d3825a736c75994f6a`. Audit harness checkout: `audit/qazwire-protocol-r4-2`. **These are negative controls on unmodified research code, not proof of safe VPN operation.**

## Confirmed workflow

**GitHub Actions [run #41591986302](https://github.com/Shamangaka/QazWire/actions/runs/41591986302)** — commit `85f7ed993c76615f4ccadcef106609645c522644`, conclusion `success`, Ubuntu 24.04, Go `go1.24.13 linux/amd64`.

- `m152_model.py`: baseline **HOLD**, **1833** explored states, 46 terminals (only the declared bounds); mutation early-release **VIOLATED**, 1240 explored; skip-egress **VIOLATED**, 1180; disabled grandparent defenses **VIOLATED**, 613.
- Original `sessionlab` `go test -tags qazwire_exp -race -count=1`: **PASS** (11.564s).
- Expected-negative R42-01: **FAIL as intended**: `material alias accepted (err=<nil>)`; checker asserts this string.
- Expected-negative R42-02: **FAIL as intended**: `6 pruned key pointers remain in s.keys backing capacity`; checker asserts this string.
- In a **disposable `git archive` snapshot**, patch `patches/r42_02_clear_retired_capacity.patch` applied. The same R42-02 test then **PASS with `-race`**. Evidence line: `R42-02 PATCHED CONTROL PASS; R42-01 remains a design blocker`.
- No feature-branch writes or merges.

**Additional independent CI:** GitHub Actions [run #41592174563](https://github.com/Shamangaka/QazWire/actions/runs/41592174563), head `d2d25ea41221e6489e022de0ef51bf4ae99ec77f`, conclusion `success`. The new negative `TestR42_01b_WipingOneProviderBreaksAnother` showed that wiping the first provider makes an otherwise-live second session return `sessionlab: synthetic provider fault; key poisoned` when both providers reference the same backing material. This confirms *impact*, not just acceptance of material aliasing. The same run reproduced R42-01, R42-02 and recorded `R42-02 PATCHED CONTROL PASS` after applying the proposed patch **only to a temporary snapshot**.

## Precision and limitations

- R42-01 demonstrates an insufficient contract for **unique material ownership**, not that real Qalqan encryption currently shares keys (no real provider exists in this package).
- R42-02 demonstrates retained Go pointers within backing capacity, not a measurement of physical RAM erasure or actual OS memory disclosure.
- The Python model is a manually designed abstraction. It does not cover multiple workers, provider panic/hang, memory copies, real traffic, or arbitrary scheduling.
- The successful CI run includes a **test-only** application of the proposed R42-02 patch. It must not be reported as a fix already published in PR #13.
- No evidence here establishes security, standards conformance or readiness for M2.
