#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R4.2 -- explicit-state model of sessionlab M1.5.2 (PR #13, 45984d7).

Granularity: one step = one atomic operation of session.go (gate CAS/Or, counter
CAS, flag load) or one step of a critical section under session.mu. Lock-free
CAS loops are modelled at their successful CAS. Critical sections that perform
gate operations (rotate, beginEmergency) are split per gate operation / per
queue entry, so lock-free threads interleave with them as in Go.

Threads
  W*   worker: prepare (<= 2 seal attempts) then dispatch | discard | leak
  R    rotator performing N consecutive rotations (fresh provider each time)
  E*   beginEmergency (initial, spawned by prepare on provider fault, or by onFail)
  A    awaitDrained, started once the session is closed; every wait may time out
  F*   finish goroutine of a gate (wipe; may panic -> failedFlag + onFail)

Configuration knobs: number/modes of workers, number of rotations, emergency,
await, maxTickets, wipe-panic generation, provider-panic worker, same material
for consecutive generations (to expose nonce reuse), and MUTANTS (see bottom).

Usage (python3 -I m152_model.py ...):
  --fast C3 C5 ...     hashed DFS over the listed configurations (default: C1..C8, C7s;
                       C1, C2, C7 with two tickets did not finish within the audit budget)
  --traces C4 C6       BFS with shortest interleavings for violations/observations
  --patched            model session_r42_minimal_fix.patch (R42-06, R42-07)
  --timeouts           awaitDrained waits may also time out
  --mutants [names]    mutation testing (stops at the first violation per mutant)
"""
import sys
from collections import deque

MUT = None
PATCHED = False   # --patched: model session_r42_minimal_fix.patch (R42-06 egress-before-latch, R42-07 retry)
TIMEOUTS = False  # awaitDrained waits are blocking in the model; deadlines add no safety-relevant paths
GF = ("closing", "discard", "sup", "poison", "claimed", "failed", "refs", "done", "wiped", "nxt", "active")
SAFETY = (
    "refs_underflow",                 # unpaired leave
    "wipe_with_outstanding_lease",    # premature Lease release / wipe under lease
    "process_after_key_wipe",         # use of destroyed key
    "send_with_wiped_key",            # packet sent after its key was wiped
    "send_after_drain_confirmed",     # send after awaitDrained saw egress drained
    "dup_send",                       # same guard sent twice
    "dup_ticket",                     # same (generation, ticket) twice
    "ticket_after_closing",           # I-5: process() runs with a ticket whose CAS happened after CLOSING
    "stale_enqueued",                 # packet of a non-current/non-previous or discard-marked generation enqueued
    "superseded_claimed_for_send",    # dispatch claims a packet whose generation is discard-marked (lock free)
    "pending_of_discarded_generation",  # (lock free) queue holds a packet of a superseded generation
    "resurrection",                   # session reopened or an old generation became current again
    "await_nil_unsound",              # awaitDrained returned nil while a send/wipe was unfinished or a wipe failed
    "material_ticket_reuse",          # (material, ticket) processed twice  [nonce-reuse class]
)
OBS = ("errclosed_while_open", "dispatch_after_fault_latch", "process_after_session_closed",
       "poisoned_generation_packet_sent")
SC = ("closed", "fwf", "fp", "cur", "prev", "keys", "pending", "mat", "pwiped", "sent", "tickets",
      "mtickets", "stageA", "lock", "maxt", "nk", "rotations_left", "wipe_panic", "same_mat",
      "everclosed") + SAFETY + OBS


def freeze(s):
    return (tuple(sorted((g, tuple(v[f] for f in GF)) for g, v in s["gates"].items())),) + tuple(s[k] for k in SC)


def thaw(t):
    s = {"gates": {g: dict(zip(GF, v)) for g, v in t[0]}}
    s.update(zip(SC, t[1:]))
    return s


def ng():
    return dict(zip(GF, (0,) * len(GF)))


class C:
    def __init__(self, sh, ts):
        self.s, self.t, self.spawn = thaw(sh), list(ts), []

    def flag(self, k):
        self.s[k] = 1

    def start_finish(self, g):
        G = self.s["gates"][g]
        if G["closing"] and G["refs"] == 0 and not G["claimed"]:
            G["claimed"] = 1
            self.spawn.append(("F" + g, "fin", "F0", (("g", g),)))

    def enter(self, g):
        G = self.s["gates"][g]
        if G["closing"]:
            return False
        G["refs"] += 1
        return True

    def leave(self, g):
        G = self.s["gates"][g]
        if G["refs"] == 0:
            self.flag("refs_underflow")
            return
        G["refs"] -= 1
        if G["closing"] and G["refs"] == 0 and MUT != "leave_never_finishes":
            self.start_finish(g)

    def close(self, g, discard=False, poison=False, superseded=False):
        G = self.s["gates"][g]
        G["closing"] = 1
        if discard:
            G["discard"] = 1
        if superseded:
            G["sup"] = 1
        if poison:
            G["discard"] = G["poison"] = 1
        if G["refs"] == 0:
            self.start_finish(g)

    def spawn_emergency(self, tag):
        self.spawn.append((f"E{tag}", "em", "E0", ()))


def init(workers, rotations, emergency, await_, maxt=2, wipe_panic="", provider_panic=(), same_mat=False):
    s = {"gates": {"k0": ng(), "eg": ng()}, "closed": 0, "fwf": 0, "fp": 0, "cur": "k0", "prev": "",
         "keys": ("k0",), "pending": (), "mat": (("k0", "m0"),), "pwiped": (), "sent": (), "tickets": (),
         "mtickets": (), "stageA": 0, "lock": "", "maxt": maxt, "nk": 1, "rotations_left": rotations,
         "wipe_panic": wipe_panic, "same_mat": 1 if same_mat else 0, "everclosed": 0}
    for k in SAFETY + OBS:
        s[k] = 0
    ts = [(f"W{i}", "w", "P0", (("att", 0), ("mode", m), ("pp", 1 if i in provider_panic else 0)))
          for i, m in enumerate(workers)]
    if rotations:
        ts.append(("R", "rot", "R0", ()))
    if emergency:
        ts.append(("E", "em", "E0", ()))
    if await_:
        ts.append(("A", "aw", "A0", ()))
    return freeze(s), tuple(ts)


HOLD = ("S2", "S3", "S4", "S5", "S6", "S7", "S8", "SP", "HELD", "D2", "D3")


def outstanding(s, ts, g):
    n = sum(1 for _, k in s["pending"] if k == g)
    for _, kind, pc, loc in ts:
        L = dict(loc)
        if kind == "w" and L.get("k") == g and pc in HOLD:
            n += 1
    return n


def step(sh, ts, i):
    out = []
    name, kind, pc, loc = ts[i]
    L = dict(loc)
    c = C(sh, ts)
    s = c.s
    free = s["lock"] == ""

    def emit(label, npc=None, **nl):
        L2 = dict(L)
        L2.update(nl)
        c.t[i] = (name, kind, npc, tuple(sorted(L2.items()))) if npc else None
        out.append((f"{name}: {label}", freeze(s), tuple(x for x in c.t if x is not None) + tuple(c.spawn)))

    def timeout():
        out.append((f"{name}: deadline", sh, tuple(x for j, x in enumerate(ts) if j != i)))

    def retry(label):
        if L["att"] == 0:
            emit(label + " -> retry", "P0", att=1)
        else:
            if not s["closed"]:
                c.flag("errclosed_while_open")
            emit(label + " -> errClosed")

    if kind == "w":
        k = L.get("k")
        if pc == "P0":                                      # RLock; closed||latched?; k := s.k
            if not free:
                return out
            if s["closed"] or s["fwf"]:
                emit("prepare: closed/latched -> errClosed")
            else:
                emit(f"prepare: k := {s['cur']} (attempt {L['att']})", "S1", k=s["cur"])
        elif pc == "S1":
            if c.enter(k):
                if s["closed"]:
                    c.flag("process_after_session_closed")
                emit(f"seal({k}): enter", "S2")
            else:
                retry(f"seal({k}): enter refused")
        elif pc == "S2":
            if s["gates"][k]["closing"]:
                c.leave(k)
                retry("reserve: closing")
            else:
                emit("reserve: load next", "S3", n=s["gates"][k]["nxt"])
        elif pc == "S3":
            G = s["gates"][k]
            if L["n"] >= s["maxt"]:
                c.leave(k)
                emit("reserve: exhausted")
            elif G["nxt"] == L["n"]:
                G["nxt"] += 1
                if (k, L["n"]) in s["tickets"]:
                    c.flag("dup_ticket")
                s["tickets"] = tuple(sorted(s["tickets"] + ((k, L["n"]),)))
                emit(f"reserve: CAS -> ticket {L['n']}", "S4", late=1 if G["closing"] else 0)
            else:
                emit("reserve: CAS retry", "S2")
        elif pc == "S4":
            if s["gates"][k]["closing"] and MUT != "no_post_cas_check":
                c.leave(k)
                retry("reserve: closing after CAS (burnt)")
            else:
                emit("reserve: ticket valid", "S5")
        elif pc == "S5":                                    # process() enter
            if s["gates"][k]["wiped"]:
                c.flag("process_after_key_wipe")
            if L.get("late"):
                c.flag("ticket_after_closing")
            m = dict(s["mat"])[k]
            mt = (m, L["n"])
            if mt in s["mtickets"]:
                c.flag("material_ticket_reuse")
            s["mtickets"] = tuple(sorted(s["mtickets"] + (mt,)))
            s["gates"][k]["active"] += 1
            emit(f"process({k}): enter", "SP" if L["pp"] else "S6")
        elif pc == "SP":                                    # provider panic -> recover -> poison
            s["gates"][k]["active"] -= 1
            c.close(k, poison=True)
            emit(f"process({k}): PANIC -> poison", "S7P")
        elif pc == "S7P":
            c.leave(k)
            s["fp"] = 1
            c.spawn_emergency(name)
            emit("seal: leave; prepare: latch poisoned, beginEmergency")
        elif pc == "S6":
            s["gates"][k]["active"] -= 1
            emit(f"process({k}): return", "S7")
        elif pc == "S7":                                    # owned copy; discard check
            if s["gates"][k]["discard"]:
                c.leave(k)
                retry(f"seal({k}): discard -> output cleared")
            else:
                emit(f"seal({k}): lease transferred", "HELD")
        elif pc == "HELD":                                  # Lock; fence; enqueue or burn
            if not free:
                return out
            stale = (k != s["cur"] and k != s["prev"]) or s["gates"][k]["discard"]
            if MUT == "no_generation_fence":
                stale = bool(s["gates"][k]["discard"]) and False
            if s["closed"] or stale:
                c.leave(k)
                if PATCHED and not s["closed"]:
                    retry("prepare: superseded -> burn")      # FIX R42-07
                    return out
                if not s["closed"]:
                    c.flag("errclosed_while_open")
                emit("prepare: closed or superseded -> burn")
            else:
                if (k != s["cur"] and k != s["prev"]) or s["gates"][k]["discard"]:
                    c.flag("stale_enqueued")
                s["pending"] = tuple(sorted(s["pending"] + ((name, k),)))
                emit(f"prepare: pending[{name}] on {k}", {"dispatch": "D0", "discard": "X0", "leak": "LK"}[L["mode"]])
        elif pc == "LK":
            emit("caller drops the packet")
        elif pc == "X0":
            if not free:
                return out
            if any(g == name for g, _ in s["pending"]):
                s["pending"] = tuple(p for p in s["pending"] if p[0] != name)
                c.leave(k)
                emit("discard: delete + leave")
            else:
                emit("discard: absent")
        elif pc == "D0":
            if MUT == "no_egress_gate":
                emit("dispatch: (mutant) no egress gate", "D1")
            elif c.enter("eg"):
                if s["fwf"] and not s["closed"]:
                    c.flag("dispatch_after_fault_latch")
                emit("dispatch: egress enter", "D1")
            else:
                emit("dispatch: egress closed -> errClosed")
        elif pc == "D1":
            if not free:
                return out
            if any(g == name for g, _ in s["pending"]):
                if s["gates"][k]["sup"] or k not in (s["cur"], s["prev"]):
                    c.flag("superseded_claimed_for_send")
                s["pending"] = tuple(p for p in s["pending"] if p[0] != name)
                if MUT == "early_key_leave":
                    c.leave(k)
                emit("dispatch: claim", "D2")
            else:
                if MUT != "no_egress_gate":
                    c.leave("eg")
                emit("dispatch: errTicket")
        elif pc == "D2":
            if s["stageA"]:
                c.flag("send_after_drain_confirmed")
            if s["gates"][k]["wiped"]:
                c.flag("send_with_wiped_key")
            if s["gates"][k]["poison"] and not s["closed"]:
                c.flag("poisoned_generation_packet_sent")
            if name in s["sent"]:
                c.flag("dup_send")
            s["sent"] = tuple(sorted(s["sent"] + (name,)))
            emit(f"wire.send ({k})", "D3")
        elif pc == "D3":
            if MUT != "early_key_leave":
                c.leave(k)
            emit("dispatch: key leave", "D4")
        elif pc == "D4":
            if MUT != "no_egress_gate":
                c.leave("eg")
            emit("dispatch: egress leave")
    elif kind == "rot":
        if pc == "R0":
            if not free:
                return out
            if s["closed"] or s["fwf"]:
                emit("rotate: closed/latched -> errClosed")
            else:
                fresh = f"k{s['nk']}"
                s["nk"] += 1
                s["gates"][fresh] = ng()
                m = dict(s["mat"])
                m[fresh] = m[s["cur"]] if s["same_mat"] else f"m{fresh}"
                s["mat"] = tuple(sorted(m.items()))
                s["lock"] = name
                emit(f"rotate: lock (new {fresh})", "R1", old=s["cur"], fresh=fresh, ix=0)
        elif pc == "R1":                                    # beginDiscard every generation != old
            if L["ix"] < len(s["keys"]):
                g = s["keys"][L["ix"]]
                if g != L["old"] and MUT != "no_discard_older":
                    c.close(g, discard=True, superseded=True)
                    emit(f"rotate: {g}.beginDiscard", "R1", ix=L["ix"] + 1)
                else:
                    emit(f"rotate: skip {g}", "R1", ix=L["ix"] + 1)
            else:
                emit("rotate: discard marks done", "R2")
        elif pc == "R2":                                    # flush queued packets of generations != old
            victims = [p for p in s["pending"] if p[1] != L["old"]]
            if victims and MUT != "no_flush_older":
                g, k = victims[0]
                s["pending"] = tuple(p for p in s["pending"] if p != (g, k))
                c.leave(k)
                emit(f"rotate: flush {g} ({k})", "R2")
            else:
                emit("rotate: flush done", "R3")
        elif pc == "R3":                                    # prune finished; publish fresh
            live = tuple(g for g in s["keys"] if not s["gates"][g]["done"])
            s["prev"], s["cur"] = L["old"], L["fresh"]
            s["keys"] = live + (L["fresh"],)
            emit(f"rotate: prune -> {live}; current {L['fresh']}, previous {L['old']}", "R4")
        elif pc == "R4":
            c.close(L["old"])
            emit(f"rotate: {L['old']}.beginClose", "R5")
        elif pc == "R5":
            s["lock"] = ""
            s["rotations_left"] -= 1
            emit("rotate: unlock", "R0" if s["rotations_left"] > 0 else None)
    elif kind == "em":
        if pc == "E0":
            c.close("eg")
            emit("emergency: egress beginClose", "E1")
        elif pc == "E1":
            if not free:
                return out
            s["closed"] = s["everclosed"] = 1
            s["lock"] = name
            emit("emergency: lock, closed", "E2")
        elif pc == "E2":
            if s["pending"] and MUT != "no_emergency_flush":
                g, k = s["pending"][0]
                s["pending"] = s["pending"][1:]
                c.leave(k)
                emit(f"emergency: flush {g} ({k})", "E2")
            else:
                emit("emergency: flushed", "E3", ix=0)
        elif pc == "E3":
            if L["ix"] < len(s["keys"]):
                c.close(s["keys"][L["ix"]], discard=True)
                emit(f"emergency: {s['keys'][L['ix']]}.beginDiscard", "E3", ix=L["ix"] + 1)
            else:
                s["lock"] = ""
                emit("emergency: unlock")
    elif kind == "aw":
        if pc == "A0":                                      # started after the session is closed
            if not free or not s["closed"]:
                return out
            emit("awaitDrained: snapshot", "A1", snap=s["keys"])
        elif pc == "A1":
            if MUT == "await_skips_egress":
                emit("awaitDrained: (mutant) egress not awaited", "A2", ix=0)
            elif s["gates"]["eg"]["done"]:
                s["stageA"] = 1
                emit("awaitDrained: egress drained", "A2", ix=0)
            if TIMEOUTS:
                timeout()
        elif pc == "A2":
            snap = L["snap"]
            if L["ix"] < len(snap):
                G = s["gates"][snap[L["ix"]]]
                if G["done"]:
                    if G["failed"]:
                        emit("awaitDrained: errWipeFailed")
                    else:
                        emit(f"awaitDrained: {snap[L['ix']]} done", "A2", ix=L["ix"] + 1)
                if TIMEOUTS:
                    timeout()
            else:
                if s["fwf"] and MUT != "await_ignores_latch":
                    emit("awaitDrained: latch -> errWipeFailed")
                else:
                    # ground truth: no claimed-but-unsent packet, every generation finished, no failed wipe
                    bad = any(kd == "w" and pcx == "D2" for _, kd, pcx, _ in ts)
                    bad = bad or any((not G["done"]) or G["failed"] for g, G in s["gates"].items() if g != "eg")
                    if bad:
                        c.flag("await_nil_unsound")
                    emit("awaitDrained: nil")
    elif kind == "fin":
        g = L["g"]
        if pc == "F0":
            if g != "eg":
                if outstanding(s, ts, g) or s["gates"][g]["active"]:
                    c.flag("wipe_with_outstanding_lease")
                s["gates"][g]["wiped"] = 1
                s["pwiped"] = tuple(sorted(set(s["pwiped"]) | {dict(s["mat"])[g]}))
                if s["wipe_panic"] == g:
                    s["gates"][g]["failed"] = 1
                    if PATCHED:                               # FIX R42-06: egress fenced first
                        emit(f"finish({g}): wipe PANIC -> failedFlag", "F3")
                        return out
                    if MUT != "on_fail_no_latch":
                        s["fwf"] = 1
                    emit(f"finish({g}): wipe PANIC -> failedFlag, latch", "F2")
                    return out
            emit(f"finish({g})", "F1")
        elif pc == "F3":                                    # patched onFail: egress beginClose
            c.close("eg")
            emit("onFail: egress beginClose", "F4")
        elif pc == "F4":                                    # patched onFail: latch
            if MUT != "on_fail_no_latch":
                s["fwf"] = 1
            emit("onFail: latch", "F2")
        elif pc == "F2":                                    # onFail: go beginEmergency()
            c.spawn_emergency("f" + g)
            emit("onFail: go beginEmergency", "F1")
        elif pc == "F1":
            s["gates"][g]["done"] = 1
            emit(f"close({g}.done)")
    return out


def lockfree_invariants(s):
    if s["lock"] == "":
        for _, k in s["pending"]:
            # mechanism-independent: older than previous, or marked superseded
            if (s["gates"][k]["sup"] or k not in (s["cur"], s["prev"])) and not s["closed"]:
                s["pending_of_discarded_generation"] = 1
    if s["everclosed"] and not s["closed"]:
        s["resurrection"] = 1
    cur = s["cur"]
    if s["gates"][cur]["closing"] and not s["closed"] and not s["gates"][cur]["poison"]:
        s["resurrection"] = 1   # an already-retired generation is current again


def finals(s, cfg):
    msgs = []
    leak = "leak" in cfg["workers"]
    if s["closed"]:
        if s["pending"] and not leak:
            msgs.append("final: queue not empty after emergency")
        if not leak:
            for g in [x for x in s["gates"] if x != "eg"] + ["eg"]:
                G = s["gates"][g]
                if G["closing"] and (not G["done"] or G["refs"]):
                    msgs.append("final: gate not drained/finished after emergency")
            if s["gates"]["eg"]["refs"]:
                msgs.append("final: egress refs leaked")
    else:
        for g, G in s["gates"].items():
            if g not in ("eg", s["cur"]) and not leak and not G["done"]:
                msgs.append("final: retired generation never finished (no emergency)")
    if any(G["refs"] for g, G in s["gates"].items() if G["done"]):
        msgs.append("final: references on a finished gate")
    return msgs


def explore(cfg, label, traces=False, limit=None):
    st0 = init(**cfg)
    parent = {st0: None}
    q = deque([st0])
    viol, obs, term = {}, {}, 0
    while q:
        st = q.popleft()
        sh, ts = st
        s = thaw(sh)
        lockfree_invariants(s)
        for k in SAFETY:
            if s[k] and k not in viol:
                viol[k] = st
        for k in OBS:
            if s[k] and k not in obs:
                obs[k] = st
        succ = []
        for i in range(len(ts)):
            succ.extend(step(sh, ts, i))
        if not succ:
            term += 1
            if ts:
                viol.setdefault("deadlock", st)
            for m in finals(s, cfg):
                viol.setdefault(m, st)
            continue
        for lab, nsh, nts in succ:
            ns = (nsh, nts)
            if ns not in parent:
                parent[ns] = (st, lab)
                q.append(ns)
        if limit and len(parent) > limit:
            print(f"### {label}: state limit {limit} reached -- INCOMPLETE")
            return viol, obs, len(parent)

    def trace(st):
        p = []
        while parent[st] is not None:
            st, lab = parent[st]
            p.append(lab)
        return p[::-1]

    print(f"\n### {label}")
    print(f"states explored: {len(parent)}, terminal states: {term}")
    for k in SAFETY:
        print(f"  safety {k:34s}: {'VIOLATED' if k in viol else 'holds'}")
    print("  deadlock: " + ("VIOLATED" if "deadlock" in viol else "none"))
    fin = [k for k in viol if k.startswith("final")]
    for k in fin:
        print(f"  {k}: VIOLATED")
    if not fin:
        print("  final-state properties: hold in every terminal state")
    for k in OBS:
        print(f"  observation {k:30s}: {'REACHABLE' if k in obs else 'unreachable'}")
    if traces:
        for k, st in list(viol.items()) + list(obs.items()):
            print(f"\n  shortest interleaving for {k}:")
            for n, lab in enumerate(trace(st), 1):
                print(f"    {n:2d}. {lab}")
    return viol, obs, len(parent)


def explore_fast(cfg, label, stop_early=False):
    """DFS with a set of 64-bit state hashes (no traces). Hash collisions could only
    HIDE states (never invent violations); probability ~ n^2/2^65 is negligible here."""
    st0 = init(**cfg)
    seen = set()
    stack = [st0]
    viol, obs, term = {}, {}, 0
    while stack:
        st = stack.pop()
        h = hash(st)
        if h in seen:
            continue
        seen.add(h)
        sh, ts = st
        s = thaw(sh)
        lockfree_invariants(s)
        for k in SAFETY:
            if s[k]:
                viol.setdefault(k, 1)
        for k in OBS:
            if s[k]:
                obs.setdefault(k, 1)
        if stop_early and viol:
            break
        succ = []
        for i in range(len(ts)):
            succ.extend(step(sh, ts, i))
        if not succ:
            term += 1
            if ts:
                viol.setdefault("deadlock", 1)
            for m in finals(s, cfg):
                viol.setdefault(m, 1)
            if stop_early and viol:
                break
            continue
        for _, nsh, nts in succ:
            ns = (nsh, nts)
            if hash(ns) not in seen:
                stack.append(ns)
    print(f"\n### {label} [fast: hashed DFS{', stop at first violation' if stop_early else ''}]")
    print(f"states explored: {len(seen)}, terminal states: {term}")
    for k in SAFETY:
        print(f"  safety {k:34s}: {'VIOLATED' if k in viol else 'holds'}")
    print("  deadlock: " + ("VIOLATED" if "deadlock" in viol else "none"))
    fin = [k for k in viol if k.startswith("final")]
    for k in fin:
        print(f"  {k}: VIOLATED")
    if not fin:
        print("  final-state properties: hold in every terminal state")
    for k in OBS:
        print(f"  observation {k:30s}: {'REACHABLE' if k in obs else 'unreachable'}")
    return viol, obs, len(seen)


CONFIGS = {
    "C1": (dict(workers=("dispatch", "dispatch"), rotations=2, emergency=True, await_=True),
           "2 workers (dispatch, dispatch) + 2 rotations + emergency + awaitDrained"),
    "C2": (dict(workers=("dispatch", "discard"), rotations=2, emergency=True, await_=True),
           "2 workers (dispatch, discard) + 2 rotations + emergency + awaitDrained"),
    "C3": (dict(workers=("dispatch",), rotations=3, emergency=True, await_=True),
           "1 worker across 3 rotations + emergency + awaitDrained"),
    "C4": (dict(workers=("dispatch", "dispatch"), rotations=2, emergency=False, await_=False),
           "2 workers + 2 rotations, no emergency (retired generations must finish)"),
    "C5": (dict(workers=("dispatch", "dispatch"), rotations=2, emergency=False, await_=True, wipe_panic="k0"),
           "wipe of k0 panics: latch, async emergency, awaitDrained"),
    "C6": (dict(workers=("dispatch", "dispatch"), rotations=1, emergency=False, await_=True, provider_panic=(0,)),
           "provider panic in worker 0 -> poison + emergency + awaitDrained"),
    "C7": (dict(workers=("dispatch", "dispatch", "discard"), rotations=2, emergency=True, await_=False),
           "3 workers + 2 rotations + emergency"),
    "C8": (dict(workers=("dispatch", "dispatch"), rotations=1, emergency=False, await_=False, same_mat=True),
           "consecutive generations built from the SAME material (R42-02)"),
    # Reduced variants (1 ticket per generation) used when the full config exceeds the time budget.
    "C1r": (dict(workers=("dispatch", "dispatch"), rotations=2, emergency=True, await_=True, maxt=1),
            "C1 with maxt=1"),
    "C2r": (dict(workers=("dispatch", "discard"), rotations=2, emergency=True, await_=True, maxt=1),
            "C2 with maxt=1"),
    "C7r": (dict(workers=("dispatch", "dispatch", "discard"), rotations=2, emergency=True, await_=False, maxt=1),
            "C7 with maxt=1"),
    "C7s": (dict(workers=("dispatch", "dispatch", "discard"), rotations=1, emergency=True, await_=False, maxt=1),
            "3 workers + 1 rotation + emergency, maxt=1"),
}
MUTANTS = ("no_generation_fence", "no_flush_older", "no_egress_gate", "early_key_leave",
           "on_fail_no_latch", "await_skips_egress", "no_emergency_flush", "leave_never_finishes",
           "no_post_cas_check", "no_discard_older", "await_ignores_latch")
MUTANT_CFG = {"on_fail_no_latch": "C5", "await_ignores_latch": "C5", "no_discard_older": "C4"}

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--timeouts" in args:
        TIMEOUTS = True
        print("# awaitDrained waits may time out (TIMEOUTS=True)")
    if "--patched" in args:
        PATCHED = True
        print("# model of the PATCHED session (session_r42_minimal_fix.patch)")
    if "--mutants" in args:
        only = [a for a in args if a in MUTANTS]
        for m in only or MUTANTS:
            MUT = m
            cid = MUTANT_CFG.get(m, "C3")
            v, _, n = explore_fast(CONFIGS[cid][0], f"MUTANT {m} on {cid}", stop_early=True)
            print(f"  => mutant {m}: {'KILLED by ' + ','.join(sorted(v)) if v else 'SURVIVED'} ({n} states)", flush=True)
        sys.exit(0)
    traces = "--traces" in args
    fast = "--fast" in args
    sel = [a for a in args if a.startswith("C")] or [c for c in CONFIGS if not c.endswith("r")]
    for cid in sel:
        cfg, label = CONFIGS[cid]
        if fast:
            explore_fast(cfg, f"{cid}: {label}")
        else:
            explore(cfg, f"{cid}: {label}", traces)
