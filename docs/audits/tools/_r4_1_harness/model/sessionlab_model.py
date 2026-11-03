#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R4.1 -- explicit-state model of sessionlab (PR #11, f5e078c).

One step = one atomic operation (gate CAS/Or, counter CAS, flag load) or one step
of a critical section under session.mu. A lock-free gate CAS loop is modelled at
its successful CAS, which is its only observable effect. Critical sections that
perform gate operations (rotate, beginEmergency) are split per gate operation, so
lock-free threads interleave with them exactly as in the Go code.

Threads:
  W*  worker: prepare (seal) then dispatch | discard | leak (keeps the packet)
  R   rotate (fresh provider, or the SAME provider object)
  E   beginEmergency
  A   awaitDrained (every wait may also end by deadline: A never blocks the model)
  F*  finish goroutines spawned by gate.startFinish

Ground truth for premature destruction: at wipe time no lease on that key may be
outstanding (active seal, prepared/pending packet, dispatch before its leave()).
"""
import sys
from collections import deque

MUT = None  # sanity mutants (see --mutants)
FIELDS = ("closing", "claimed", "refs", "done", "wiped", "nxt", "active")
SAFETY = ("refs_underflow", "wipe_with_outstanding_lease", "process_on_wiped_provider",
          "process_after_key_wipe", "send_after_drain_confirmed", "send_with_wiped_key",
          "dup_send", "dup_ticket")
OBS = ("errclosed_while_session_open", "packet_left_pending_after_errclosed")
SCALARS = ("closed", "cur", "keys", "pending", "provider", "pwiped", "sent", "tickets",
           "stageA", "lock", "maxt", "same", "nk") + SAFETY + OBS


def freeze(s):
    gates = tuple(sorted((g, tuple(v[f] for f in FIELDS)) for g, v in s["gates"].items()))
    return (gates,) + tuple(s[k] for k in SCALARS)


def thaw(t):
    s = {"gates": {g: dict(zip(FIELDS, v)) for g, v in t[0]}}
    for k, v in zip(SCALARS, t[1:]):
        s[k] = v
    return s


def new_gate():
    return dict(zip(FIELDS, (0,) * len(FIELDS)))


class Ctx:
    def __init__(self, sh, ts):
        self.s = thaw(sh)
        self.t = list(ts)
        self.spawn = []

    def flag(self, k):
        self.s[k] = 1

    def start_finish(self, gid):
        g = self.s["gates"][gid]
        if g["closing"] and g["refs"] == 0 and not g["claimed"]:
            g["claimed"] = 1
            self.spawn.append(("F" + gid, "fin", "F0", (("gid", gid),)))

    def enter(self, gid):
        g = self.s["gates"][gid]
        if g["closing"]:
            return False
        g["refs"] += 1
        return True

    def leave(self, gid):
        g = self.s["gates"][gid]
        if g["refs"] == 0:
            self.flag("refs_underflow")
            return
        g["refs"] -= 1
        if g["closing"] and g["refs"] == 0:
            self.start_finish(gid)

    def begin_close(self, gid):
        self.s["gates"][gid]["closing"] = 1
        if self.s["gates"][gid]["refs"] == 0:
            self.start_finish(gid)


def init(workers, rotate, emergency, await_, max_t=2, same_provider=False):
    s = {"gates": {"k0": new_gate(), "eg": new_gate()}, "closed": 0, "cur": "k0", "keys": ("k0",),
         "pending": (), "provider": (("k0", "p0"),), "pwiped": (), "sent": (), "tickets": (),
         "stageA": 0, "lock": "", "maxt": max_t, "same": 1 if same_provider else 0, "nk": 1}
    for k in SAFETY + OBS:
        s[k] = 0
    ts = [(f"W{i}", "w", "P0", (("mode", m),)) for i, m in enumerate(workers)]
    if rotate:
        ts.append(("R", "rot", "R0", ()))
    if emergency:
        ts.append(("E", "em", "E0", ()))
    if await_:
        ts.append(("A", "aw", "A0", ()))
    return freeze(s), tuple(ts)


HOLD_PCS = ("SE2", "SE3", "SE4", "SE5", "SE6", "SE7", "HELD", "D2", "D3")


def outstanding(s, ts, gid):
    n = sum(1 for _, k in s["pending"] if k == gid)
    for _, kind, pc, loc in ts:
        L = dict(loc)
        if kind == "w" and L.get("k") == gid and pc in HOLD_PCS:
            n += 1
    return n


def prov(s, k):
    return dict(s["provider"])[k]


def step(sh, ts, i):
    out = []
    name, kind, pc, loc = ts[i]
    L = dict(loc)
    c = Ctx(sh, ts)
    s = c.s
    free = s["lock"] == ""

    def emit(label, npc=None, **nl):
        L2 = dict(L)
        L2.update(nl)
        c.t[i] = (name, kind, npc, tuple(sorted(L2.items()))) if npc else None
        nts = tuple(x for x in c.t if x is not None) + tuple(c.spawn)
        out.append((f"{name}: {label}", freeze(s), nts))

    def deadline():
        nts = tuple(x for j, x in enumerate(ts) if j != i)
        out.append((f"{name}: awaitDrained -> deadline", sh, nts))

    def closed_err(label):
        if not s["closed"]:
            c.flag("errclosed_while_session_open")
        emit(label)

    if kind == "w":
        k = L.get("k")
        if pc == "P0":
            if not free:
                return out
            if s["closed"]:
                emit("prepare: closed -> errClosed")
            else:
                emit(f"prepare: k := s.k ({s['cur']})", "SE1", k=s["cur"])
        elif pc == "SE1":
            if c.enter(k):
                emit("seal: gate.enter", "SE2")
            else:
                closed_err("seal: enter refused -> errClosed")
        elif pc == "SE2":
            if s["gates"][k]["closing"]:
                c.leave(k)
                closed_err("reserve: closing -> errClosed (leave)")
            else:
                emit("reserve: open, load next", "SE3", n=s["gates"][k]["nxt"])
        elif pc == "SE3":
            g = s["gates"][k]
            if L["n"] >= s["maxt"]:
                c.leave(k)
                emit("reserve: exhausted (leave)")
            elif g["nxt"] == L["n"]:
                g["nxt"] += 1
                tk = (k, L["n"])
                if tk in s["tickets"]:
                    c.flag("dup_ticket")
                s["tickets"] = tuple(sorted(s["tickets"] + (tk,)))
                emit(f"reserve: CAS next -> ticket {L['n']}", "SE4")
            else:
                emit("reserve: CAS retry", "SE2")
        elif pc == "SE4":
            if s["gates"][k]["closing"]:
                c.leave(k)
                closed_err("reserve: closing after CAS -> ticket burnt (leave)")
            else:
                emit("reserve: ticket valid", "SE5")
        elif pc == "SE5":
            if prov(s, k) in s["pwiped"]:
                c.flag("process_on_wiped_provider")
            if s["gates"][k]["wiped"]:
                c.flag("process_after_key_wipe")
            s["gates"][k]["active"] += 1
            emit("process(): enter", "SE6")
        elif pc == "SE6":
            s["gates"][k]["active"] -= 1
            emit("process(): return", "SE7")
        elif pc == "SE7":
            if s["gates"][k]["closing"]:
                c.leave(k)
                closed_err("seal: closing after process -> output discarded (leave)")
            else:
                emit("seal: lease transferred to packet", "HELD", g=name)
        elif pc == "HELD":
            if not free:
                return out
            if s["closed"]:
                c.leave(k)
                emit("prepare: closed after seal -> burn (leave)")
            else:
                s["pending"] = tuple(sorted(s["pending"] + ((L["g"], k),)))
                emit("prepare: pending[guard] = pkt", {"dispatch": "D0", "discard": "X0", "leak": "LEAK"}[L["mode"]])
        elif pc == "LEAK":
            emit("caller drops the packet (no dispatch, no discard)")
        elif pc == "X0":
            if not free:
                return out
            if any(g == L["g"] for g, _ in s["pending"]):
                s["pending"] = tuple(p for p in s["pending"] if p[0] != L["g"])
                c.leave(k)
                emit("discard: delete + leave")
            else:
                emit("discard: absent -> no-op")
        elif pc == "D0":
            if MUT == "no_egress_gate":
                c.s["gates"]["eg"]["refs"] += 0
                emit("dispatch: (mutant) no egress gate", "D1")
            elif c.enter("eg"):
                emit("dispatch: egress enter", "D1")
            else:
                if any(g == L["g"] for g, _ in s["pending"]):
                    c.flag("packet_left_pending_after_errclosed")
                emit("dispatch: egress closed -> errClosed")
        elif pc == "D1":
            if not free:
                return out
            if any(g == L["g"] for g, _ in s["pending"]):
                s["pending"] = tuple(p for p in s["pending"] if p[0] != L["g"])
                if MUT == "early_key_leave":
                    c.leave(k)
                emit("dispatch: claim guard (used=true, delete)", "D2")
            else:
                if MUT != "no_egress_gate":
                    c.leave("eg")
                emit("dispatch: errTicket (egress leave)")
        elif pc == "D2":
            if s["stageA"]:
                c.flag("send_after_drain_confirmed")
            if s["gates"][k]["wiped"]:
                c.flag("send_with_wiped_key")
            if L["g"] in s["sent"]:
                c.flag("dup_send")
            s["sent"] = tuple(sorted(s["sent"] + (L["g"],)))
            emit("wire.send", "D3")
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
            if s["closed"] and MUT != "rotate_ignores_closed":
                emit("rotate: closed -> errClosed")
            else:
                old, nk = s["cur"], f"k{s['nk']}"
                s["nk"] += 1
                s["gates"][nk] = new_gate()
                pv = dict(s["provider"])
                pv[nk] = pv[old] if s["same"] else f"p{nk}"
                s["provider"] = tuple(sorted(pv.items()))
                s["cur"], s["keys"], s["lock"] = nk, s["keys"] + (nk,), name
                emit(f"rotate: lock, install {nk}", "R1", old=old)
        elif pc == "R1":
            c.begin_close(L["old"])
            emit(f"rotate: {L['old']}.beginClose", "R2")
        elif pc == "R2":
            s["lock"] = ""
            emit("rotate: unlock")
    elif kind == "em":
        if pc == "E0":
            c.begin_close("eg")
            emit("emergency: egress beginClose", "E1")
        elif pc == "E1":
            if not free:
                return out
            s["closed"], s["lock"] = 1, name
            emit("emergency: lock, closed = true", "E2")
        elif pc == "E2":
            if s["pending"] and MUT != "no_flush":
                g, k = s["pending"][0]
                s["pending"] = s["pending"][1:]
                c.leave(k)
                emit(f"emergency: flush {g} (leave {k})", "E2")
            else:
                emit("emergency: pending flushed", "E3", ki=0)
        elif pc == "E3":
            if L["ki"] < len(s["keys"]):
                k = s["keys"][L["ki"]]
                c.begin_close(k)
                emit(f"emergency: {k}.beginClose", "E3", ki=L["ki"] + 1)
            else:
                s["lock"] = ""
                emit("emergency: unlock")
    elif kind == "aw":
        if pc == "A0":
            if not free:
                return out
            if not s["closed"]:
                emit("awaitDrained: not closed -> errInvalid")
            else:
                emit("awaitDrained: snapshot keys", "A1", snap=s["keys"])
        elif pc == "A1":
            if s["gates"]["eg"]["done"]:
                s["stageA"] = 1
                emit("awaitDrained: egress done (drain confirmed)", "A2", ki=0)
            deadline()
        elif pc == "A2":
            snap = L["snap"]
            if L["ki"] >= len(snap):
                emit("awaitDrained: nil")
            else:
                if s["gates"][snap[L["ki"]]]["done"]:
                    emit(f"awaitDrained: {snap[L['ki']]} done", "A2", ki=L["ki"] + 1)
                deadline()
    elif kind == "fin":
        gid = L["gid"]
        if pc == "F0":
            if gid != "eg":
                if outstanding(s, ts, gid) or s["gates"][gid]["active"]:
                    c.flag("wipe_with_outstanding_lease")
                s["gates"][gid]["wiped"] = 1
                s["pwiped"] = tuple(sorted(set(s["pwiped"]) | {prov(s, gid)}))
            emit(f"finish({gid})", "F1")
        elif pc == "F1":
            s["gates"][gid]["done"] = 1
            emit(f"close({gid}.done)")
    return out


def final_msgs(s, cfg):
    msgs = []
    leak = "leak" in cfg["workers"]
    if s["closed"]:
        if s["pending"]:
            msgs.append("final: pending not empty after emergency")
        for k in s["keys"] + ("eg",):
            g = s["gates"][k]
            if not g["done"] or g["refs"]:
                msgs.append("final: gate not drained/finished after emergency")
    else:
        for k in s["keys"][:-1]:
            if not s["gates"][k]["done"]:
                msgs.append("final: retired key never wiped (no emergency)")
    return msgs


def explore(cfg, label, traces):
    st0 = init(**cfg)
    parent = {st0: None}
    q = deque([st0])
    viol, obs, nterm = {}, {}, 0
    while q:
        st = q.popleft()
        sh, ts = st
        s = thaw(sh)
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
            nterm += 1
            if ts:
                viol.setdefault("deadlock", st)
            for msg in final_msgs(s, cfg):
                viol.setdefault(msg, st)
            continue
        for lab, nsh, nts in succ:
            ns = (nsh, nts)
            if ns not in parent:
                parent[ns] = (st, lab)
                q.append(ns)

    def trace(st):
        p = []
        while parent[st] is not None:
            st, lab = parent[st]
            p.append(lab)
        return p[::-1]

    print(f"\n### {label}")
    print(f"states explored: {len(parent)}, terminal states: {nterm}")
    for k in SAFETY:
        print(f"  safety {k:30s}: {'VIOLATED' if k in viol else 'holds'}")
    print("  deadlock (terminal state with live threads): " + ("VIOLATED" if "deadlock" in viol else "none"))
    finals = [k for k in viol if k.startswith("final")]
    for k in finals:
        print(f"  {k}: VIOLATED")
    if not finals:
        print("  final-state properties: hold in every terminal state")
    for k in OBS:
        print(f"  observation {k:36s}: {'REACHABLE' if k in obs else 'unreachable'}")
    if traces:
        for k, st in list(viol.items()) + list(obs.items()):
            print(f"\n  shortest interleaving for {k}:")
            for n, lab in enumerate(trace(st), 1):
                print(f"    {n:2d}. {lab}")
    return viol, obs


CONFIGS = [
    (dict(workers=("dispatch", "discard"), rotate=True, emergency=True, await_=True),
     "M-1: workers (dispatch, discard) + rotate + emergency + awaitDrained"),
    (dict(workers=("dispatch", "dispatch"), rotate=True, emergency=True, await_=True),
     "M-2: workers (dispatch, dispatch) + rotate + emergency + awaitDrained"),
    (dict(workers=("dispatch", "discard"), rotate=True, emergency=False, await_=False),
     "M-3: workers (dispatch, discard) + rotate, no emergency"),
    (dict(workers=("leak", "dispatch"), rotate=True, emergency=False, await_=False),
     "M-4: leaky worker + rotate, no emergency (R41-04)"),
    (dict(workers=("dispatch", "dispatch"), rotate=True, emergency=False, await_=False, same_provider=True),
     "M-5: rotate re-uses the SAME provider object (R41-01)"),
    (dict(workers=("dispatch", "dispatch", "discard"), rotate=True, emergency=True, await_=False),
     "M-6: three workers (dispatch, dispatch, discard) + rotate + emergency"),
]

if __name__ == "__main__":
    if "--mutants" in sys.argv:
        for mut in ("early_key_leave", "no_egress_gate", "no_flush", "rotate_ignores_closed"):
            MUT = mut
            v, _ = explore(CONFIGS[0][0], f"MUTANT {mut} on M-1", False)
            print(f"  => mutant {mut}: {'KILLED' if v else 'SURVIVED'}")
        sys.exit(0)
    traces = "--traces" in sys.argv
    only = [a for a in sys.argv[1:] if a.startswith("M-")]
    for cfg, label in CONFIGS:
        if only and not any(label.startswith(o + ":") for o in only):
            continue
        explore(cfg, label, traces)
