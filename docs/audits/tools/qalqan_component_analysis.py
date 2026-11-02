#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R1 — auditor-side component analysis of ST RK 4009-2025 (Qalqan).

RESEARCH TOOL, NOT AN IMPLEMENTATION OF QALQAN AND NOT A CONFORMITY TEST.

The licensed standard is NOT included in this repository.  The tool reads the
user's own locally licensed copy, converted with `pdftotext -layout`, and parses
Table 1 (S), Table 3 (S^-1), Table 2 (rotation constants), the Annex A linear-layer
vectors and the Annex A round-key traces.  Nothing from the standard is embedded here.

Checks performed:
  C1  S is a bijection and Table 3 is its inverse; fixed points
  C2  S differential uniformity, max |Walsh|, nonlinearity, algebraic degree
  C3  Linear layer L (formula (1), sequential word update) reproduces Annex A vectors
      for 128/256/512-bit blocks (interpretation check of §6.2)
  C4  Exact byte-wise differential and linear branch numbers of L for Blen=128 (GF(2) algebra)
  C5  Upper bound on byte-wise differential branch number of L for Blen=256/512 (1-active-byte inputs)
  C6  Whether the Annex A round-key traces show the same round-key byte stream for different Blen

Usage:  pdftotext -layout ST_RK_4009-2025.pdf 4009.txt
        python3 -I qalqan_component_analysis.py 4009.txt
"""
import itertools, re, struct, sys

def load(path):
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()

def ru_start(lines):
    # The PDF is bilingual (kk first, then ru).  Use the Russian part, which starts at "Содержание".
    for i, l in enumerate(lines):
        if "Содержание" in l:
            return i
    raise SystemExit("cannot find Russian part")

def grab_table(lines, start, marker):
    idx = next(i for i in range(start, len(lines)) if marker in lines[i])
    vals = []
    for l in lines[idx + 1: idx + 60]:
        t = l.split()
        if len(t) == 17 and re.fullmatch(r"[0-9a-f]", t[0]) and all(re.fullmatch(r"[0-9a-f]{2}", x) for x in t[1:]):
            vals.extend(int(x, 16) for x in t[1:])
        if len(vals) == 256:
            return vals
    raise SystemExit("table not parsed: " + marker)

def grab_rotations(lines, start):
    idx = next(i for i in range(start, len(lines)) if "Таблица 2" in lines[i])
    rot = {}
    for l in lines[idx: idx + 12]:
        m = re.match(r"^\s*(128|256|512)\s+([\d,\s]+)$", l)
        if m:
            rot[int(m.group(1))] = tuple(int(x) for x in m.group(2).replace(",", " ").split())
    assert set(rot) == {128, 256, 512}, rot
    return rot

def grab_linear_vectors(lines, start):
    vecs, i = [], start
    while i < len(lines):
        if "Linear operation:" in lines[i]:
            j = i + 1
            while j < len(lines) and "Nonlinear operation" not in lines[j] and ("Linear operation:" not in lines[j] or j == i):
                m = re.search(r"Input \((128|256|512) bits\):\s*([0-9a-f]*)", lines[j])
                if m:
                    blen = int(m.group(1)); hx = m.group(2); k = j + 1
                    while len(hx) < blen // 4:
                        hx += lines[k].strip(); k += 1
                    mo = None
                    while mo is None:
                        mo = re.search(r"Output \(%d bits\):\s*([0-9a-f]*)" % blen, lines[k]); k += 1
                    ho = mo.group(1)
                    while len(ho) < blen // 4:
                        ho += lines[k].strip(); k += 1
                    vecs.append((blen, hx, ho)); j = k; continue
                j += 1
            i = j
        else:
            i += 1
        if len(vecs) >= 6:
            break
    return vecs

def rotl(x, s, w):
    m = (1 << w) - 1
    return ((x << s) | (x >> (w - s))) & m if s % w else x

def L(block_bytes, rot):
    blen = len(block_bytes) * 8
    w, n = (32, len(block_bytes) // 4) if blen in (128, 256) else (64, 8)
    fmt = "<%d%s" % (n, "I" if w == 32 else "Q")
    words = list(struct.unpack(fmt, block_bytes))
    c = rot[blen]
    for i in range(n):
        acc = words[i]
        for j in range(1, n):
            acc ^= rotl(words[(i + j) % n], c[j - 1], w)
        words[i] = acc
    return struct.pack(fmt, *words)

def sbox_metrics(S):
    par = lambda v: bin(v).count("1") & 1
    du = max(max(cnt) for cnt in ([sum(1 for x in range(256) if S[x] ^ S[x ^ a] == d) for d in range(256)] for a in range(1, 256)))
    maxw = 0
    for b in range(1, 256):
        f = [1 - 2 * par(S[x] & b) for x in range(256)]
        for a in range(256):
            maxw = max(maxw, abs(sum(f[x] * (1 - 2 * par(x & a)) for x in range(256))))
    def deg(tt):
        a = tt[:]
        for i in range(8):
            for x in range(256):
                if x >> i & 1:
                    a[x] ^= a[x ^ (1 << i)]
        return max((bin(x).count("1") for x in range(256) if a[x]), default=0)
    degs = [deg([par(S[x] & b) for x in range(256)]) for b in range(1, 256)]
    return du, maxw, 128 - maxw // 2, min(degs), max(degs)

def gf2_rank(vecs):
    basis, r = {}, 0
    for v in vecs:
        while v:
            h = v.bit_length() - 1
            if h in basis:
                v ^= basis[h]
            else:
                basis[h] = v; r += 1; break
    return r

def branch_numbers_128(rot):
    N = 128
    Lint = lambda v: int.from_bytes(L(v.to_bytes(16, "little"), rot), "little")
    cols = [Lint(1 << i) for i in range(N)]
    rows = [sum(((cols[i] >> r) & 1) << i for i in range(N)) for r in range(N)]
    assert gf2_rank(rows) == N
    tr = [sum(((rows[r] >> c) & 1) << r for r in range(N)) for c in range(N)]
    bm = lambda S: sum(0xFF << (8 * b) for b in S)
    def exists(M, I, J):
        vars_ = [i for i in range(N) if bm(I) >> i & 1]
        eqs = []
        for r in range(N):
            if not (bm(J) >> r & 1):
                e = 0
                for k, i in enumerate(vars_):
                    if M[r] >> i & 1:
                        e |= 1 << k
                eqs.append(e)
        return len(vars_) - gf2_rank(eqs) > 0
    def bn(M):
        for B in range(2, 10):
            for a in range(1, B):
                for I in itertools.combinations(range(16), a):
                    for J in itertools.combinations(range(16), B - a):
                        if exists(M, I, J):
                            return B, I, J
        return None
    return bn(rows), bn(tr)

def one_byte_bound(rot, blen):
    nb = blen // 8; best = None
    for p in range(nb):
        for v in range(1, 256):
            b = bytearray(nb); b[p] = v
            a = 1 + sum(1 for x in L(bytes(b), rot) if x)
            if best is None or a < best[0]:
                best = (a, p, v)
    return best

def round_key_traces(lines, start):
    rk = {}
    i = start
    while i < len(lines):
        m = re.search(r"\*\*\*\*\* Key expansion, key length = 256, block length = 128 \*\*\*\*\*", lines[i])
        if m and "kexp128" not in rk:
            ks = []
            for l in lines[i: i + 80]:
                mm = re.search(r"Round\s+(\d+) key:\s*([0-9a-f]+)", l)
                if mm:
                    ks.append(mm.group(2))
                if len(ks) == 16:
                    break
            rk["kexp128"] = ks
        m2 = re.search(r"\*\*\*\*\* Encryption, key length = 256, block len = (256|512) \*\*\*\*\*", lines[i])
        if m2 and ("enc" + m2.group(1)) not in rk:
            blen = int(m2.group(1)); ks = []; j = i + 1
            while j < len(lines) and len(ks) < 3:
                mm = re.match(r"^\s*Key ?(\d+):\s*([0-9a-f]*)\s*$", lines[j])
                if mm:
                    hx = mm.group(2); k = j + 1
                    while len(hx) < blen // 4:
                        t = lines[k].strip()
                        if re.fullmatch(r"[0-9a-f]+", t):
                            hx += t
                        k += 1
                    ks.append(hx[: blen // 4]); j = k; continue
                j += 1
            rk["enc" + m2.group(1)] = ks
        i += 1
        if len(rk) == 3:
            break
    return rk

def main(path):
    lines = load(path); s = ru_start(lines)
    S = grab_table(lines, s, "Таблица 1 – Нелинейное биективное преобразование")
    IS = grab_table(lines, s, "Таблица 3 – Обратное нелинейное биективное преобразование")
    rot = grab_rotations(lines, s)
    print("C1 bijective=%s inverse_table_ok=%s fixed_points=%d" % (len(set(S)) == 256, all(IS[S[x]] == x for x in range(256)), sum(S[x] == x for x in range(256))))
    du, maxw, nl, dmin, dmax = sbox_metrics(S)
    print("C2 differential_uniformity=%d max_abs_walsh=%d nonlinearity=%d algebraic_degree=[%d,%d]" % (du, maxw, nl, dmin, dmax))
    for blen, hi, ho in grab_linear_vectors(lines, s):
        got = L(bytes.fromhex(hi), rot).hex()
        print("C3 linear KAT blen=%d %s" % (blen, "PASS" if got == ho else "FAIL"))
    d, l = branch_numbers_128(rot)
    print("C4 blen=128 byte branch number: differential=%d (witness in=%s out=%s); linear=%d (witness in=%s out=%s)" % (d[0], d[1], d[2], l[0], l[1], l[2]))
    for blen in (256, 512):
        b = one_byte_bound(rot, blen)
        print("C5 blen=%d upper bound from 1-active-byte inputs: %d (byte %d value %#04x)" % (blen, b[0], b[1], b[2]))
    rk = round_key_traces(lines, s)
    k128 = rk.get("kexp128", [])
    for blen in (256, 512):
        enc = rk.get("enc%d" % blen, [])
        per = blen // 128
        ok = [enc[r] == "".join(k128[r * per:(r + 1) * per]) for r in range(len(enc)) if (r + 1) * per <= len(k128)]
        print("C6 blen=%d round keys 0..%d equal concatenated blen=128 round keys: %s" % (blen, len(ok) - 1, ok))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
