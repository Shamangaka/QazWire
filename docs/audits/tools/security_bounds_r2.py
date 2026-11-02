#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R2 -- per-key usage limits from published generic bounds.

All bounds are *generic* (information-theoretic, random-permutation model) terms.
Every real-world bound additionally contains Adv^prp_Qalqan(...) terms, which are
UNKNOWN (no independent cryptanalysis of ST RK 4009-2025; BR-01).  Nothing printed
here is evidence that Qalqan or any profile is secure.

Bounds used (see QAZWIRE_SECURITY_BOUNDS_R2.md for sources):
  CTR (distinct counter blocks)   : sigma_e^2 / 2^(n+1)                 PRP/PRF switching
  EMAC* (MAC 2 + padding 2)       : 2 * sigma_F^2 / 2^n                 Petrank-Rackoff (as cited by Black-Rogaway)
  CMAC/OMAC (MAC 5)               : (4 * sigma_F^2 + 1) / 2^n           Iwata-Kurosawa, Indocrypt 2003
  EAX (19772 mech. 4)             : priv 9 sigma^2/2^n ; auth 10.5 sigma^2/2^n + v/2^t   Bellare-Rogaway-Wagner 2004 (*)
  forgery by guessing             : v / 2^t
  (*) original EAX auth proof covers one verification query; multi-query improvement exists (Minematsu et al.),
      constants not used here -> EAX rows are indicative only.
sigma_F counts MAC input blocks of BOTH tag generation and verification (attacker-chosen packets).
"""
from math import log2, sqrt, ceil

MTU_PAYLOAD = 1420          # device.DefaultMTU (device/tun.go:14)
MAX_PAYLOAD = 65535 - 16    # MaxSegmentSize - header (device/queueconstants_default.go:17)
HDR = 16

def blocks(nbytes, n):        # number of n-bit blocks for nbytes
    return ceil(nbytes / (n // 8))

def mac_blocks(payload, n):   # H || C || padding-2 (always >= 1 byte appended)
    return blocks(HDR + payload + 1, n)

def lg(x): return log2(x) if x > 0 else float("-inf")

PROFILES = {
    # name: (n, t, construction)
    "A  Q256 CTR+EMAC (t=256)": (256, 256, "emac"),
    "B  Q128 CTR+CMAC (t=128)": (128, 128, "cmac"),
    "D  Q128 EAX      (t=128)": (128, 128, "eax"),
}
TARGETS = {
    "T_A  CA<=2^-60, IA<=2^-57 per key (TLS/QUIC/CFRG)": (-60, -57),
    "T_B  per key <=2^-72 (system 2^-32 over u=2^40 keys)": (-72, -72),
}

def conf_sigma_max(n, cons, ca_log2):
    c = 9.0 if cons == "eax" else 0.5          # sigma^2 * c / 2^n
    return 0.5 * (ca_log2 + n - log2(c))

def integ_sigma_max(n, cons, ia_log2):
    # split IA budget: half to PRF/collision term, half to guessing term
    budget = ia_log2 - 1
    c = {"emac": 2.0, "cmac": 4.0, "eax": 10.5}[cons]
    return 0.5 * (budget + n - log2(c))

def guess_v_max(t, ia_log2):
    return ia_log2 - 1 + t

print("=== Per-key limits (log2 of total n-bit blocks per key and direction) ===")
for pname, (n, t, cons) in PROFILES.items():
    lP_mtu, lP_max = blocks(MTU_PAYLOAD, n), blocks(MAX_PAYLOAD, n)
    lM_mtu, lM_max = mac_blocks(MTU_PAYLOAD, n), mac_blocks(MAX_PAYLOAD, n)
    print(f"\n{pname}: n={n} t={t}; CTR blocks/packet {lP_mtu} (MTU) .. {lP_max} (max); MAC blocks/packet {lM_mtu} .. {lM_max}")
    for tname, (ca, ia) in TARGETS.items():
        se = conf_sigma_max(n, cons, ca)
        sf = integ_sigma_max(n, cons, ia)
        vg = guess_v_max(t, ia)
        print(f"  {tname}")
        print(f"     confidentiality: sigma_e <= 2^{se:.1f} blocks = 2^{se + log2(n//8):.1f} bytes;"
              f" packets <= 2^{se - lg(lP_max):.1f} (max size) / 2^{se - lg(lP_mtu):.1f} (MTU size)")
        print(f"     integrity (MAC term): sigma_F(tag+verify) <= 2^{sf:.1f} blocks;"
              f" forgery attempts at max size <= 2^{sf - lg(lM_max):.1f}")
        print(f"     integrity (guessing term): v <= 2^{vg:.1f}")
    for L, S in (("L1", 64), ("L2", 96), ("L3", 128), ("L4", 160)):
        lim = n - S
        print(f"  [1073 strength-ratio interpretation, PENDING] {L} (2^{S}): sigma <= 2^{lim} blocks"
              + ("  -> UNREACHABLE (<1 block)" if lim < 0 else ""))

print("\n=== Data volume per key produced at line rate R within RejectAfterTime = 180 s (log2 blocks) ===")
for rate_gbps in (1, 10, 40, 100, 400):
    bits = rate_gbps * 1e9 * 180
    print(f"  {rate_gbps:>4} Gbit/s: n=128 -> 2^{lg(bits/128):.1f}   n=256 -> 2^{lg(bits/256):.1f}")

print("\n=== Re-check of R1 spec section 11 values ===")
s = 35 + 12      # 2^35 packets x 2^12 blocks (Q128)
print(f"  Q128CM R1 limits sigma=2^{s}: CTR term 2^{2*s-129}, CMAC term 2^{lg(4) + 2*s - 128:.0f}  (target T_A needs <= 2^-60 / 2^-57)")
s = 64 + 11      # 2^64 packets x 2^11 blocks (Q256)
print(f"  Q256EM max reachable sigma=2^{s}: CTR term 2^{2*s-257}, EMAC term 2^{lg(2) + 2*s - 256:.0f}  (generic terms only; Adv^prp unknown)")

print("\n=== Multi-user: multi-target exhaustive key search u*p/2^k (k=256) ===")
for u, p in ((2**40, 2**100), (2**50, 2**128)):
    print(f"  u=2^{lg(u):.0f} keys, p=2^{lg(p):.0f} offline evaluations: 2^{lg(u)+lg(p)-256:.0f}")
