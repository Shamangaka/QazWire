#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R4 -- corrected adversary resource model (G-Q9).

Everything is in log2.  NOTHING here is evidence that Qalqan, X25519 or the
protocol is secure: generic bounds are upper bounds in idealised models
(generic group model for X25519, ideal cipher for Qalqan, PRF/dual-PRF
assumptions for HKDF-BLAKE2s) plus UNKNOWN assumption terms (BR-01).

Adversary (definition used throughout):
  * uniform, classical, adaptive; sees all public keys and all traffic;
  * T = TOTAL work over the whole system lifetime, all targets and all
    precomputation included (group operations for X25519, block-cipher / hash
    evaluations for symmetric parts); data and online queries are limited by
    protocol limits (per-key sigma, per-key forgery attempts, handshake rate).
  * "per-target budget p" is a different model; it is shown only to explain
    where a factor L may or may not appear.
"""
from math import log2

LOG_L = 252.0          # Curve25519 prime subgroup order l = 2^252 + 2774...8493
U = 40                 # directed keys over the lifecycle (owner's u_max)
N_HS = U - 1           # handshakes: two directed keys per handshake
L_EPH = N_HS + 1       # ephemeral public keys: one per side per handshake
SYSTEM = -64


def lg_add(a, b):      # log2(2^a + 2^b)
    m = max(a, b)
    return m + log2(1 + 2 ** (min(a, b) - m))


def x25519_tight(T, L):
    """GGM, one-of-L DL with TOTAL T group operations (Shoup's argument with L
    linear polynomials in L variables): (T+L+1)^2/(2l) + L/l."""
    return lg_add(2 * lg_add(T, L) - 1 - LOG_L, L - LOG_L)


def x25519_union(T, L):
    """Union bound over L targets, each bounded with the FULL budget T: L*T^2/(2l)."""
    return L + 2 * T - 1 - LOG_L


def x25519_per_target_nonpoolable(p, L):
    """L independent attackers, budget p each, no sharing: L*p^2/(2l) (total work L*p)."""
    return L + 2 * p - 1 - LOG_L


def x25519_per_target_poolable(p, L):
    """Budget p per target but work can be pooled: total T = L*p, tight bound applies."""
    return x25519_tight(p + L, L)


def tmax_tight(share, L):
    lo, hi = 0.0, 200.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if x25519_tight(mid, L) <= share:
            lo = mid
        else:
            hi = mid
    return lo


def tmax_union(share, L):
    return (share + 1 + LOG_L - L) / 2


def sym_multi_target(T, u, k=256):
    """Multi-target key search on k-bit symmetric keys with a common verification
    value (e.g. first keystream block of every session): u*T/2^k."""
    return u + T - k


def hdr(t):
    print(f"\n=== {t} ===")


print(f"System target 2^{SYSTEM}; u = 2^{U} directed keys -> 2^{N_HS} handshakes, "
      f"2^{L_EPH} ephemeral X25519 keys; l = 2^{LOG_L:.0f}")

hdr("Owner's sanity checks (PR #7, G-Q9)")
print(f"  union bound, p = 2^90 total: u * p^2 / 2^252 = 2^{U + 180 - 252}   (owner: 2^-32)")
print(f"  union bound, max p for 2^-64: (252 - 64 - 40)/2 = 2^{(252 - 64 - 40) / 2:.0f}   (owner: 2^74)")
print(f"  same with Shoup's 1/2 factor: 2^{tmax_union(-64, U):.1f}")

hdr("Which inequality applies (X25519, L = 2^40 targets)")
print("  T or p   | tight GGM, total T | union, total T | per-target p, no pooling | per-target p, pooled")
for t in (64, 72, 74, 80, 90, 92, 94, 100):
    print(f"  2^{t:<6} | 2^{x25519_tight(t, L_EPH):7.1f}          | 2^{min(0, x25519_union(t, L_EPH)):6.1f}       |"
          f" 2^{min(0, x25519_per_target_nonpoolable(t, L_EPH)):7.1f}                | 2^{min(0, x25519_per_target_poolable(t, L_EPH)):6.1f}")

hdr("Maximum total budget T for a given X25519 share")
for share in (-64, -66, -68):
    print(f"  share 2^{share}: tight GGM T <= 2^{tmax_tight(share, L_EPH):.1f};"
          f" union bound T <= 2^{tmax_union(share, L_EPH):.1f};"
          f" per-target non-poolable p <= 2^{tmax_union(share, L_EPH):.1f} (total 2^{tmax_union(share, L_EPH) + L_EPH:.1f})")

hdr("Non-uniform (free preprocessing) stress case: Corrigan-Gibbs--Kogan S*T^2 ~ eps*l")
for S, Ton in ((64, 64), (80, 64), (64, 80)):
    print(f"  advice S = 2^{S} bits, online T = 2^{Ton}: eps ~ 2^{S + 2 * Ton - LOG_L:.0f} per instance (log factors ignored)")

hdr("Symmetric multi-target key search (factor u is REAL here)")
for t in (72, 92, 128, 150):
    print(f"  T = 2^{t}: u*T/2^256 = 2^{sym_multi_target(t, U)}; PSK guesses (tested per target) T/2^256 = 2^{t - 256}")

hdr("Proposed system allocation (sum = 2^-64)")
alloc = {"handshake (X25519, PSK/KDF, handshake AEAD, ephemeral collisions)": -66,
         "transport confidentiality, all keys": -66,
         "transport integrity, all keys": -66,
         "reserve (implementation, unmodelled terms)": -66}
tot = None
for k, v in alloc.items():
    tot = v if tot is None else lg_add(tot, v)
    print(f"  {k:66s} 2^{v}")
print(f"  total                                                              2^{tot:.1f}")
per_key = -66 - U
share = per_key - 2
print(f"  per directed key: CA <= 2^{per_key}, IA <= 2^{per_key}; four shares of 2^{share} each")

hdr("Handshake share 2^-66 split into four 2^-68 parts")
print(f"  X25519 (tight GGM): T <= 2^{tmax_tight(-68, L_EPH):.1f};  (union bound): T <= 2^{tmax_union(-68, L_EPH):.1f}")
print(f"  KDF / transport-key multi-target search u*T/2^256 <= 2^-68: T <= 2^{-68 + 256 - U}")
print(f"  PSK search T/2^256 <= 2^-68: T <= 2^{-68 + 256}")
print(f"  ephemeral collisions L^2/(2l) = 2^{2 * L_EPH - 1 - LOG_L:.0f}")

hdr("Transport limits per directed key at share 2^-108 (generic terms only)")
for n, name in ((256, "Qalqan-256 CTR+EMAC*"), (128, "Qalqan-128 CTR+CMAC")):
    se = (share + n + 1) / 2
    sf = (share + n - log2(2.5 if n == 256 else 4)) / 2
    print(f"  {name}: sigma_e <= 2^{se:.2f} blocks; sigma_F <= 2^{sf:.2f} (tag+verify); v <= 2^{share + n}")
print(f"  Qalqan-256: structural max sigma_e = 2^75 -> CTR term 2^{150 - 257} > 2^{share}: RejectAfterBlocks <= 2^74 needed")
print(f"  Qalqan-256 multi-user PRP heuristic u*T/2^256 at T = 2^92: 2^{U + 92 - 256}")
