#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R5 -- independent explicit-state model of klm16 (aa27727, klm.go blob 6274939).

Written from klm.go, not from docs/qazwire/tools/m161_bounded_model.py.

Granularity. Every exported method of labSession runs its whole body under
session.mu, so one step = one critical section. Prepare has TWO critical
sections (admission, commit) separated by the unlocked copy/test-hook gap; in
the gap a worker may also HANG forever or PANIC (recover path = third section).

Threads
  W*  worker: Prepare (<= 3 attempts) -> Consume | Discard; optional loop count
  R   rotator: N consecutive Rotate calls
  S   Stop (once)
  A   AwaitDestroyed after Stop: snapshot under mu, then waits for every 'done'

Ground truth is kept separately from the modelled counters, so that the
invariants compare the code's bookkeeping with what actually exists.

Usage: python3 -I klm16_model.py [--patched] [--traces] [K1 K2 ...] | --mutants [names]
"""
import sys
from collections import deque

MUT = None
PATCHED = False   # --patched: model klm16_r5_fix.patch (R5-01: count pinned after the flush)

SAFETY = (
    "bytes_over_budget",        # sum(private copies in gap) + sum(queued) > maxBytes
    "byte_counters_wrong",      # pendingBytes / reservedBytes differ from ground truth
    "slots_over_cap",           # len(pending)+inFlight > maxPendingTickets or inFlight > maxInFlight
    "inflight_counter_wrong",
    "refs_wrong",               # g.refs != queued tickets of g + leases held in the gap
    "wipe_under_lease",         # material wiped while a lease or queued ticket exists
    "record_from_wiped",        # Consume returned a record of a wiped generation
    "stale_pending",            # queued ticket of a discarded / older-than-previous generation
    "stale_record",             # record of a generation that is neither current nor previous
    "dup_record",               # same ticket consumed twice / same (generation, seq) twice
    "dup_material_seq",         # (material, sequence) repeated
    "pending_after_stop",
    "admitted_after_stop",      # Prepare succeeded or Rotate published after Stop
    "unlisted_live_generation", # a non-wiped generation is missing from s.generations
    "await_nil_unsound",        # AwaitDestroyed returned nil while a generation is not wiped
    "backlog_without_inflight", # ErrBacklog although no superseded generation is held by in-flight work
)
OBS = ("await_blocked_by_hung", "prepare_errrotated", "budget_rejected", "capacity_rejected", "backlog_stop")

# ---- state encoding ------------------------------------------------------------------
# gen: (refs, retiring, discard, wiped, next, mat)   -- indexed by epoch-1
# session: gens, listed(tuple of idx), cur, prev, closed, fault, pending(tuple of (tid,g,seq,amt)),
#          pb, rb, infl, recs(tuple of (g,seq)), mseq(tuple of (mat,seq)), nmat, flags
# worker: (pc, loops_left, attempt, g, seq, amt, tid)


def freeze(d):
    return tuple(sorted(d.items()))


class St:
    def __init__(self, t):
        self.__dict__.update(dict(t[0]))
        self.ws = list(t[1])
        self.thr = dict(t[2])

    def key(self):
        d = {k: v for k, v in self.__dict__.items() if k not in ("ws", "thr")}
        return (freeze(d), tuple(self.ws), freeze(self.thr))


def init(cfg):
    d = dict(gens=((0, 0, 0, 0, 0, 1),), listed=(0,), cur=0, prev=-1, closed=0, fault="",
             pending=(), pb=0, rb=0, infl=0, recs=(), mseq=(), nmat=2, ntid=0, flags=())
    ws = tuple(("P", cfg["loops"][i] if "loops" in cfg else 1, 0, -1, -1, cfg["amounts"][i], -1)
               for i in range(len(cfg["workers"])))
    thr = {"R": cfg["rotations"], "S": 1 if cfg["stop"] else 0, "A": 1 if cfg["await"] else 0, "snap": ()}
    return (freeze(d), ws, freeze(thr))


def flag(s, k):
    if k not in s.flags:
        s.flags = tuple(sorted(s.flags + (k,)))


def setgen(s, g, **kw):
    r = list(s.gens[g])
    for k, v in kw.items():
        r[("refs", "retiring", "discard", "wiped", "next", "mat").index(k)] = v
    gl = list(s.gens)
    gl[g] = tuple(r)
    s.gens = tuple(gl)


def G(s, g, k):
    return s.gens[g][("refs", "retiring", "discard", "wiped", "next", "mat").index(k)]


def leases(s, g):
    """ground truth: queued tickets of g + workers holding a lease on g in the gap"""
    n = sum(1 for (_, gg, _, _) in s.pending if gg == g)
    n += sum(1 for w in s.ws if w[0] in ("GAP", "HUNG") and w[3] == g)
    return n


def finish(s, g):
    if MUT == "finish_ignores_refs":
        if G(s, g, "retiring") and not G(s, g, "wiped"):
            if leases(s, g):
                flag(s, "wipe_under_lease")
            setgen(s, g, wiped=1)
        return
    if not G(s, g, "retiring") or G(s, g, "refs") != 0 or G(s, g, "wiped"):
        return
    if leases(s, g):
        flag(s, "wipe_under_lease")
    setgen(s, g, wiped=1)


def release(s, g):
    setgen(s, g, refs=G(s, g, "refs") - 1)
    if MUT != "release_no_finish":
        finish(s, g)


def prune(s):
    if MUT == "prune_drops_live":
        s.listed = tuple(g for g in s.listed if g in (s.cur, s.prev))
        return
    s.listed = tuple(g for g in s.listed if not G(s, g, "wiped") or g in (s.cur, s.prev))


def remove_ticket(s, tid):
    t = [p for p in s.pending if p[0] == tid]
    if not t:
        return
    _, g, _, amt = t[0]
    s.pending = tuple(p for p in s.pending if p[0] != tid)
    s.pb -= amt
    release(s, g)


def stop(s, cause):
    if cause and not s.fault:
        s.fault = cause
    if s.closed:
        return
    s.closed = 1
    if MUT != "stop_no_flush":
        for p in list(s.pending):
            remove_ticket(s, p[0])
    for g in s.listed:
        setgen(s, g, retiring=1, discard=1)
        finish(s, g)


def check(s, cfg):
    """invariants that must hold whenever session.mu is free (every state here)"""
    gap = [w for w in s.ws if w[0] in ("GAP", "HUNG")]
    real = sum(w[5] for w in gap) + sum(p[3] for p in s.pending)
    if real > cfg["maxBytes"]:
        flag(s, "bytes_over_budget")
    if s.pb != sum(p[3] for p in s.pending) or s.rb != sum(w[5] for w in gap):
        flag(s, "byte_counters_wrong")
    if s.infl != len(gap):
        flag(s, "inflight_counter_wrong")
    if len(s.pending) + len(gap) > cfg["maxPend"] or len(gap) > cfg["maxInFlight"]:
        flag(s, "slots_over_cap")
    for g in range(len(s.gens)):
        if G(s, g, "refs") != leases(s, g):
            flag(s, "refs_wrong")
        if G(s, g, "wiped") and leases(s, g):
            flag(s, "wipe_under_lease")
        if not G(s, g, "wiped") and g not in s.listed:
            flag(s, "unlisted_live_generation")
    for (_, g, _, _) in s.pending:
        if G(s, g, "discard") or g not in (s.cur, s.prev):
            flag(s, "stale_pending")
    if s.closed and s.pending:
        flag(s, "pending_after_stop")


def steps(t, cfg):
    s0 = St(t)
    out = []

    def emit(label, s):
        check(s, cfg)
        out.append((label, s.key()))

    def fresh():
        return St(t)

    # ---------------- workers ----------------
    for i, w in enumerate(s0.ws):
        pc, loops, att, g, seq, amt, tid = w
        if pc == "P" and loops > 0:                               # Prepare admission (mu)
            s = fresh()

            def done(s, lab, more=True):
                s.ws[i] = ("P" if more and loops - 1 > 0 else "D", loops - 1, 0, -1, -1, amt, -1)
                emit(f"W{i}: {lab}", s)
            if s.closed:
                done(s, "prepare -> stopped", more=False)
                continue
            used = s.pb if MUT == "admission_ignores_reserved" else s.pb + s.rb
            if amt > cfg["maxBytes"] - used:
                flag(s, "budget_rejected")
                done(s, "prepare -> ErrBudget")
                continue
            slots = len(s.pending) if MUT == "inflight_not_in_capacity" else len(s.pending) + s.infl
            if slots >= cfg["maxPend"]:
                flag(s, "capacity_rejected")
                done(s, "prepare -> ErrCapacity")
                continue
            if s.infl >= cfg["maxInFlight"]:
                done(s, "prepare -> ErrInFlight")
                continue
            cg = s.cur
            if G(s, cg, "next") >= cfg["maxTickets"]:
                done(s, "prepare -> ErrTicketExhausted")
                continue
            sq = G(s, cg, "next")
            setgen(s, cg, next=sq if MUT == "seq_reuse" else sq + 1, refs=G(s, cg, "refs") + 1)
            s.rb += amt
            s.infl += 1
            s.ws[i] = ("GAP", loops, att, cg, sq, amt, -1)
            emit(f"W{i}: admit g{cg} seq {sq} (attempt {att})", s)
        elif pc == "GAP":
            # (a) commit under mu
            s = fresh()
            ok = (not s.closed and not G(s, g, "discard") and g in (s.cur, s.prev))
            if MUT == "commit_no_generation_check":
                ok = not s.closed
            if not ok:
                was_open = not s.closed
                s.ws[i] = ("X",) + w[1:]          # the lease is being returned
                release(s, g)
                s.rb -= amt
                s.infl -= 1
                prune(s)
                if was_open and att < 2:
                    s.ws[i] = ("P", loops, att + 1, -1, -1, amt, -1)
                    emit(f"W{i}: commit rejected g{g} -> retry", s)
                else:
                    if was_open:
                        flag(s, "prepare_errrotated")
                    s.ws[i] = ("P" if loops - 1 > 0 else "D", loops - 1, 0, -1, -1, amt, -1)
                    emit(f"W{i}: commit rejected g{g} -> error", s)
            else:
                s.rb -= amt
                s.infl -= 1
                tid_new = s.ntid
                s.ntid += 1
                s.pending = tuple(sorted(s.pending + ((tid_new, g, seq, amt),)))
                s.pb += amt
                s.ws[i] = ("H", loops, 0, g, seq, amt, tid_new)
                emit(f"W{i}: queued ticket t{tid_new} on g{g}", s)
            # (b) hang forever inside the gap (configured worker only)
            if i in cfg.get("hang", ()):
                s = fresh()
                s.ws[i] = ("HUNG",) + w[1:]
                emit(f"W{i}: HANGS in gap holding g{g}", s)
            # (c) panic in the gap -> recover section
            if i in cfg.get("panic", ()):
                s = fresh()
                s.ws[i] = ("X",) + w[1:]
                release(s, g)
                s.rb -= amt
                s.infl -= 1
                stop(s, "poisoned")
                s.ws[i] = ("D", 0, 0, -1, -1, amt, -1)
                emit(f"W{i}: PANIC -> recover, poison", s)
        elif pc == "H":                                          # Consume or Discard (mu)
            s = fresh()
            mode = cfg["workers"][i]
            nxt = ("P" if loops - 1 > 0 else "D", loops - 1, 0, -1, -1, amt, -1)
            present = any(p[0] == tid for p in s.pending)
            if mode == "consume":
                if s.closed:
                    s.ws[i] = nxt
                    emit(f"W{i}: consume -> stopped", s)
                    continue
                if not present and MUT != "consume_ignores_pending":
                    s.ws[i] = nxt
                    emit(f"W{i}: consume -> ErrTicket", s)
                    continue
                if G(s, g, "discard"):
                    remove_ticket(s, tid)
                    s.ws[i] = nxt
                    emit(f"W{i}: consume -> ErrRotated", s)
                    continue
                if G(s, g, "wiped"):
                    flag(s, "record_from_wiped")
                if g not in (s.cur, s.prev):
                    flag(s, "stale_record")
                if (g, seq) in s.recs:
                    flag(s, "dup_record")
                if (G(s, g, "mat"), seq) in s.mseq:
                    flag(s, "dup_material_seq")
                s.recs = tuple(sorted(s.recs + ((g, seq),)))
                s.mseq = tuple(sorted(s.mseq + ((G(s, g, "mat"), seq),)))
                remove_ticket(s, tid)
                prune(s)
                if MUT == "consume_ignores_pending":
                    s.ws[i] = ("H2", loops, 0, g, seq, amt, tid)   # consumes the same ticket again
                else:
                    s.ws[i] = nxt
                emit(f"W{i}: consume t{tid} -> record g{g}/{seq}", s)
            else:
                if present:
                    remove_ticket(s, tid)
                    prune(s)
                s.ws[i] = nxt
                emit(f"W{i}: discard t{tid}", s)
        elif pc == "H2":                                         # mutant only: replay of a copy
            s = fresh()
            if (g, seq) in s.recs:
                flag(s, "dup_record")
            s.ws[i] = ("D", 0, 0, -1, -1, amt, -1)
            emit(f"W{i}: consume copy of t{tid} again", s)

    # ---------------- rotator ----------------
    if s0.thr["R"] > 0:
        s = fresh()
        s.thr["R"] -= 1
        if s.closed and MUT != "rotate_ignores_closed":
            s.thr["R"] = 0
            emit("R: rotate -> stopped", s)
        else:
            if s.closed:
                flag(s, "admitted_after_stop")
            old = s.cur

            def pinned_count():
                return sum(1 for g in s.listed if g != old and G(s, g, "refs") > 0)

            def inflight_pinned():
                return sum(1 for g in s.listed if g != old and
                           any(w[0] in ("GAP", "HUNG") and w[3] == g for w in s.ws))

            def mark_and_flush():
                for g in s.listed:
                    if g != old:
                        setgen(s, g, retiring=1, discard=1)
                if MUT != "rotate_no_flush":
                    for p in list(s.pending):
                        if p[1] != old:
                            remove_ticket(s, p[0])
            if PATCHED:
                mark_and_flush()
            if pinned_count() >= cfg["maxPinned"]:
                flag(s, "backlog_stop")
                if inflight_pinned() < cfg["maxPinned"]:
                    flag(s, "backlog_without_inflight")
                stop(s, "backlog")
                s.thr["R"] = 0
                emit("R: rotate -> ErrBacklog (stop)", s)
            else:
                if not PATCHED:
                    mark_and_flush()
                setgen(s, old, retiring=1)
                finish(s, old)
                s.gens = s.gens + ((0, 0, 0, 0, 0, s.nmat),)
                s.nmat += 1
                s.prev, s.cur = old, len(s.gens) - 1
                s.listed = s.listed + (s.cur,)
                prune(s)
                emit(f"R: rotate -> current g{s.cur}, previous g{old}", s)

    # ---------------- stop / await ----------------
    if s0.thr["S"] > 0:
        s = fresh()
        s.thr["S"] = 0
        stop(s, "")
        emit("S: Stop", s)
    if s0.thr["A"] == 1 and s0.closed:
        s = fresh()
        s.thr["A"] = 2
        s.thr["snap"] = s.listed
        emit(f"A: snapshot {s.listed}", s)
    if s0.thr["A"] == 2 and all(G(s0, g, "wiped") for g in s0.thr["snap"]):
        s = fresh()
        s.thr["A"] = 0
        if any(not G(s, g, "wiped") for g in range(len(s.gens))):
            flag(s, "await_nil_unsound")
        emit("A: AwaitDestroyed -> nil", s)
    return out


def finals(t, cfg):
    s = St(t)
    msgs = []
    hung = any(w[0] == "HUNG" for w in s.ws)
    if hung:
        if s.thr["A"] == 2:
            msgs.append("obs:await_blocked_by_hung")
        return msgs
    if any(w[0] not in ("D",) for w in s.ws) or s.thr["A"] != 0 and s.closed:
        msgs.append("final:deadlock")
    if s.closed:
        if s.pending or s.rb or s.infl:
            msgs.append("final:resources_after_stop")
        if any(not G(s, g, "wiped") for g in range(len(s.gens))):
            msgs.append("final:generation_not_wiped_after_stop")
    else:
        for g in range(len(s.gens)):
            if g not in (s.cur, s.prev) and not G(s, g, "wiped"):
                msgs.append("final:retired_generation_not_wiped")
        if any(G(s, g, "wiped") and g not in (s.cur, s.prev) for g in s.listed):
            msgs.append("final:wiped_generation_still_listed")
    return msgs


def explore(cfg, label, traces=False, stop_early=False, limit=5_000_000):
    """stop_early (mutants): stop at the first violation other than the baseline
    finding backlog_without_inflight (R5-01), which is reachable without any mutant."""
    t0 = init(cfg)
    st = St(t0)
    check(st, cfg)
    parent = {t0: None}
    q = deque([t0])
    viol, obs, term = {}, {}, 0
    while q:
        t = q.popleft()
        s = St(t)
        for f in s.flags:
            (obs if f in OBS else viol).setdefault(f, t)
        if stop_early and any(k != "backlog_without_inflight" for k in viol):
            break
        succ = steps(t, cfg)
        if not succ:
            term += 1
            for m in finals(t, cfg):
                (obs if m.startswith("obs:") else viol).setdefault(m, t)
            continue
        for lab, n in succ:
            if n not in parent:
                parent[n] = (t, lab)
                q.append(n)
        if len(parent) > limit:
            print(f"!! state limit {limit} reached")
            break

    def trace(t):
        out = []
        while parent[t] is not None:
            t, lab = parent[t]
            out.append(lab)
        return out[::-1]
    print(f"\n### {label}{' [PATCHED]' if PATCHED else ''}{' [mutant ' + MUT + ']' if MUT else ''}")
    print(f"states: {len(parent)}, terminal: {term}")
    for k in SAFETY:
        print(f"  safety {k:28s}: {'VIOLATED' if k in viol else 'holds'}")
    fin = sorted(k for k in viol if k.startswith("final:"))
    print("  final-state properties: " + (", ".join(fin) + " VIOLATED" if fin else "hold"))
    for k in OBS:
        kk = k if k in obs else "obs:" + k
        print(f"  observation {k:24s}: {'REACHABLE' if (k in obs or kk in obs) else 'unreachable'}")
    if traces:
        for k, t in list(viol.items()) + list(obs.items()):
            print(f"  shortest trace for {k}:")
            for n, lab in enumerate(trace(t), 1):
                print(f"    {n:2d}. {lab}")
    return viol, len(parent)


BASE = dict(maxBytes=2, maxTickets=3, maxPinned=2, maxPend=3, maxInFlight=2)
CONFIGS = {
    "K1": (dict(BASE, workers=("consume", "discard"), amounts=(1, 1), rotations=2, stop=True, await_=True),
           "2 workers (consume, discard), 2 rotations, Stop, AwaitDestroyed"),
    "K2": (dict(BASE, workers=("consume", "consume", "discard"), amounts=(1, 1, 1), rotations=1, stop=True,
                await_=True, maxInFlight=1),
           "3 workers, budget 2 bytes, maxInFlight 1, 1 rotation, Stop, Await"),
    "K3": (dict(BASE, workers=("consume",), amounts=(1,), loops=(2,), rotations=3, stop=True, await_=True,
                maxPinned=1),
           "1 worker x2 prepares, 3 rotations, maxPinned 1, Stop, Await"),
    "K4": (dict(BASE, workers=("consume", "consume"), amounts=(1, 1), rotations=2, stop=True, await_=True,
                maxPinned=1, hang=(0,)),
           "worker 0 may hang in the gap, 2 rotations, maxPinned 1, Stop, Await"),
    "K5": (dict(BASE, workers=("consume", "consume"), amounts=(1, 0), rotations=1, stop=False, await_=True,
                panic=(0,)),
           "worker 0 may panic in the gap (poison), 1 rotation, Await"),
    "K6": (dict(BASE, workers=("consume", "discard", "consume"), amounts=(0, 0, 0), rotations=1, stop=True,
                await_=False, maxPend=2),
           "3 zero-length payloads, maxPendingTickets 2, 1 rotation, Stop"),
    "K7": (dict(BASE, workers=("consume", "discard"), amounts=(2, 1), loops=(2, 1), rotations=2, stop=False,
                await_=False),
           "no Stop: 2 workers (one loops twice), 2 rotations; retired generations must be wiped and pruned"),
    "K8": (dict(BASE, workers=("consume", "consume", "discard"), amounts=(1, 1, 0), rotations=2, stop=True,
                await_=True, hang=(2,)),
           "3 workers (one may hang), 2 rotations, maxPinned 2, Stop, Await"),
    "K9": (dict(BASE, workers=("consume", "consume", "discard"), amounts=(1, 0, 1), loops=(2, 2, 1),
                rotations=3, stop=True, await_=True, maxPend=3, maxInFlight=2, maxTickets=2),
           "3 workers (two loop twice), 3 rotations, ticket exhaustion, Stop, Await"),
}
for c in CONFIGS.values():
    c[0]["await"] = c[0].pop("await_")

MUTANTS = {
    "admission_ignores_reserved": "K7", "inflight_not_in_capacity": "K6", "commit_no_generation_check": "K1",
    "finish_ignores_refs": "K1", "stop_no_flush": "K1", "rotate_no_flush": "K1", "release_no_finish": "K1",
    "prune_drops_live": "K8", "rotate_ignores_closed": "K1", "consume_ignores_pending": "K7", "seq_reuse": "K7",
}

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--patched" in args:
        PATCHED = True
    if "--mutants" in args:
        names = [a for a in args if a in MUTANTS] or list(MUTANTS)
        for m in names:
            MUT = m
            cid = MUTANTS[m]
            v, n = explore(CONFIGS[cid][0], f"{cid}: {CONFIGS[cid][1]}", stop_early=True)
            real = sorted(k for k in v if k != "backlog_without_inflight")
            print(f"  => mutant {m} on {cid}: {'KILLED by ' + ','.join(real) if real else 'SURVIVED'} ({n} states)")
        sys.exit(0)
    sel = [a for a in args if a in CONFIGS] or list(CONFIGS)
    for cid in sel:
        explore(CONFIGS[cid][0], f"{cid}: {CONFIGS[cid][1]}", traces="--traces" in args)
