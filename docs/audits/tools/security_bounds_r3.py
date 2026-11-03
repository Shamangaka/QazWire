#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R3 -- per-key budgets for the owner's ENGINEERING target
(system advantage <= 2^-64 over u_max = 2^40 directed keys => <= 2^-104 per key),
computed separately for confidentiality (CA) and integrity (IA).

This is NOT a normative requirement and NOT evidence that Qalqan or any profile
is secure.  Every bound below is a *generic* term (random-permutation model)
plus explicitly listed assumption terms whose value is UNKNOWN (BR-01: no
independent cryptanalysis of ST RK 4009-2025).

Budget split per key and direction (each share 2^-106, four shares = 2^-104):
  CA: [CTR switching term] [Adv^prp(K_e)] [Adv^prf_HKDF] [multi-user / key-search reserve]
  IA: [MAC PRF term]       [guessing v/2^t] [Adv^prp(K_m)+Adv^prp(K_m')] [Adv^prf_HKDF]

Generic bounds (sources in QAZWIRE_AUDIT_R3.md section 7):
  CTR                         sigma_e^2 / 2^(n+1)          PRP/PRF switching (BDJR97, BR06)
  EMAC* (MAC 2 + padding 2)   2.5 sigma_F^2 / 2^n          Black-Rogaway, Thm 4 (ECBC, PRF), restricted to padded inputs
  CMAC/OMAC (MAC 5)           (4 sigma_F^2 + 1) / 2^n      Iwata-Kurosawa, Indocrypt 2003 (PRF)
  CMAC (CJN22 Thm 3.1)        4 sigma/2^n + (16 q^2 + q l^2)/2^n  (+ higher-order terms omitted)
  EAX (BRW04)                 priv 9 sigma^2/2^n ; auth 10.5 sigma^2/2^n (single verification query)
  guessing                    v / 2^t
  X25519 generic rho          ~ p^2 / 2^252 (group order ~2^252)
  key search, multi-target    u * p / 2^k
"""
from math import ceil, log2, sqrt

SHARE = -106            # log2 of one budget share
PER_KEY = -104
U_MAX = 40              # log2 directed keys over the system lifecycle
SYSTEM = -64

MTU_PAYLOAD = 1420
MAX_PAYLOAD = 65535 - 16
HDR = 16
REJECT_AFTER_MESSAGES = (1 << 64) - (1 << 13) - 1     # device/constants.go:16
REKEY_AFTER_TIME = 120                                 # device/constants.go:17
REJECT_AFTER_TIME = 180


def blocks(nbytes, n):
    return ceil(nbytes / (n // 8))


def mac_blocks(payload, n):          # H || C || padding method 2
    return blocks(HDR + payload + 1, n)


def lg(x):
    return log2(x) if x > 0 else float("-inf")


def sigma_from_quadratic(c, n, share=SHARE):
    """max sigma with c*sigma^2/2^n <= 2^share"""
    return 0.5 * (share + n - log2(c))


def show(title):
    print(f"\n=== {title} ===")


print(f"Target: system <= 2^{SYSTEM}, u_max = 2^{U_MAX} directed keys -> per key <= 2^{PER_KEY} "
      f"(CA and IA separately); share = 2^{SHARE}")

# ---------------------------------------------------------------- Q256 / A
show("A  Qalqan-256 CTR + EMAC* (t = 256)")
n, t = 256, 256
lp_mtu, lp_max = blocks(MTU_PAYLOAD, n), blocks(MAX_PAYLOAD, n)
lm_mtu, lm_max = mac_blocks(MTU_PAYLOAD, n), mac_blocks(MAX_PAYLOAD, n)
se = sigma_from_quadratic(0.5, n)
sf = sigma_from_quadratic(2.5, n)
print(f"  CTR blocks/packet {lp_mtu} (MTU) .. {lp_max} (max); MAC blocks/packet {lm_mtu} .. {lm_max}")
print(f"  CA  generic CTR term: sigma_e <= 2^{se:.2f} blocks")
smax = lg(REJECT_AFTER_MESSAGES) + lg(lp_max)
print(f"      structural maximum (counter < 2^64 - 2^13 - 1, max packets): sigma_e = 2^{smax:.2f}"
      f" -> term 2^{2 * smax - (n + 1):.2f}")
print(f"  IA  EMAC* PRF term (2.5 sigma^2/2^n): sigma_F(tag + verify) <= 2^{sf:.2f} blocks")
half = sf - 1
print(f"      split equally: sigma_tag <= 2^{half:.2f}, sigma_ver <= 2^{half:.2f}")
print(f"      -> sender packets <= 2^{half - lg(lm_max):.2f} (max size) / 2^{half - lg(lm_mtu):.2f} (MTU);"
      f" receiver verifications likewise")
print(f"  IA  guessing term: v <= 2^{SHARE + t}")
for rate in (1, 10, 100, 400):
    sig = lg(rate * 1e9 * REJECT_AFTER_TIME / n)
    print(f"      reachable within RejectAfterTime at {rate:>3} Gbit/s: sigma = 2^{sig:.1f}"
          f" -> CTR term 2^{2 * sig - (n + 1):.1f}, EMAC term 2^{lg(2.5) + 2 * sig - n:.1f}")
print("  Assumption terms (UNKNOWN, must each be <= 2^-106): Adv^prp_Qalqan-256(K_e; sigma_e), "
      "Adv^prp(K_m; sigma_F) + Adv^prp(K_m'; q), Adv^prf_HKDF-BLAKE2s")

# ---------------------------------------------------------------- Q128 / B, D
show("B  Qalqan-128 CTR + CMAC (t = 128)")
n, t = 128, 128
lp_mtu, lp_max = blocks(MTU_PAYLOAD, n), blocks(MAX_PAYLOAD, n)
lm_mtu, lm_max = mac_blocks(MTU_PAYLOAD, n), mac_blocks(MAX_PAYLOAD, n)
se = sigma_from_quadratic(0.5, n)
print(f"  CTR blocks/packet {lp_mtu} (MTU) .. {lp_max} (max)")
print(f"  CA  sigma_e <= 2^{se:.2f} blocks = {2 ** se * 16 / 1024:.1f} KiB per key;"
      f" packets <= {2 ** se / lp_mtu:.1f} (MTU size); one max-size packet = 2^{lg(lp_max):.2f} blocks"
      f" -> {'EXCEEDS' if lg(lp_max) > se else 'fits'} the CA budget")
# (4 sigma^2 + 1)/2^128 <= 2^-106
s_ik = 0.5 * lg((2 ** (SHARE + n) - 1) / 4)
print(f"  IA  CMAC (IK Indocrypt03): sigma_F <= 2^{s_ik:.2f} blocks (tag + verify)"
      f" = {2 ** s_ik / lm_mtu:.1f} MTU-size MAC computations per key")


def cjn_ok(q, l):
    sigma = q * l
    return (4 * sigma + 16 * q * q + q * l * l) / 2 ** n <= 2 ** SHARE


for l in (lm_mtu, lm_max):
    q = 0
    while cjn_ok(q + 1, l):
        q += 1
    print(f"  IA  CMAC (CJN22 Thm 3.1, leading terms) at l = {l} blocks: q <= {q}"
          + ("  (not even one message)" if q == 0 else ""))
print(f"  IA  guessing: v <= 2^{SHARE + t} forgery attempts per key")
show("D  Qalqan-128 EAX (t = 128), indicative")
print(f"  CA  9 sigma^2/2^128: sigma <= 2^{sigma_from_quadratic(9, n):.2f};"
      f"  IA 10.5 sigma^2/2^128: sigma <= 2^{sigma_from_quadratic(10.5, n):.2f}")

show("Q128 operational consequence at the CA limit (block-based rekey)")
for rate in (0.1, 1, 10):
    bytes_per_s = rate * 1e9 / 8
    rekeys = bytes_per_s / (2 ** se * 16)
    years10 = rekeys * 10 * 365.25 * 86400
    print(f"  {rate:>4} Gbit/s one direction: {rekeys:,.0f} rekeys/s; 10-year single-link key count 2^{lg(years10):.1f}"
          f" (u budget 2^{U_MAX})")

# ---------------------------------------------------------------- tag length
show("Tag length needed for the guessing share alone")
for v in (20, 30, 35, 40, 50):
    print(f"  v_max = 2^{v} attempts per key -> t >= {-SHARE + v} bits")
L = 1500
per_attempt = lg(8 * ceil(L / 16)) - 106
print(f"  Reference: ChaCha20-Poly1305 forgery per attempt at {L} B: 8*ceil(L/16)/2^106 = 2^{per_attempt:.2f}"
      f" (> 2^{PER_KEY}: a single attempt exceeds the per-key IA target)")
for rate in (1, 10, 100):
    pps = rate * 1e9 / 8 / 80              # 80-byte minimal forged datagram on the wire (assumption)
    v = lg(pps * REJECT_AFTER_TIME)
    print(f"  attempts reachable in 180 s at {rate:>3} Gbit/s (80 B datagrams): 2^{v:.1f}"
          f" -> t=128 guessing term 2^{v - 128:.1f}; t=256 -> 2^{v - 256:.1f}")

# ---------------------------------------------------------------- resources
# ERRATUM R4: the section below does not define whether p is a TOTAL or a PER-TARGET budget,
# and leaves no budget for the handshake. Superseded by tools/security_bounds_r4.py
# (QAZWIRE_AUDIT_R4.md section 6). Kept unchanged for traceability.
show("Resource model: the target is meaningless without an adversary work bound p")
p_x = (SYSTEM + 252) / 2
print(f"  X25519 generic rho p^2/2^252 <= 2^{SYSTEM}  =>  p <= 2^{p_x:.0f} group operations (single instance)")
for p in (94, 128, 160):
    print(f"  multi-target key search over u = 2^{U_MAX} 256-bit keys with p = 2^{p}: 2^{U_MAX + p - 256}"
          f" (system target 2^{SYSTEM}); X25519 rho at p = 2^{p}: 2^{min(0, 2 * p - 252)}")

show("u accounting (directed keys)")
sessions = 10 * 365.25 * 86400 / REKEY_AFTER_TIME
print(f"  one continuously active peer pair, rekey every {REKEY_AFTER_TIME} s, 10 years: "
      f"2 x 2^{lg(sessions):.2f} = 2^{lg(2 * sessions):.2f} directed keys")
print(f"  -> u <= 2^{U_MAX} allows 2^{U_MAX - lg(2 * sessions):.2f} = {2 ** U_MAX / (2 * sessions):,.0f}"
      " continuously active pairs over 10 years (forced rekeys consume the same budget)")
hs_rate = 50  # HandshakeInitationRate = time.Second / 50 (device/constants.go:25); responder-side
              # per-peer flood check in ConsumeMessageInitiation (device/noise-protocol.go:405-415)
print(f"  worst case if every handshake succeeds at {hs_rate}/s per peer: 2^{lg(2 * hs_rate * 86400 * 365.25):.1f}"
      " directed keys per peer-year -> u must be enforced, not assumed")
