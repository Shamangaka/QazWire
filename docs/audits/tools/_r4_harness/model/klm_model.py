#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire audit R4 -- explicit-state model checker for the key-lifecycle protocols.

Two models, one step = one atomic operation of the Go code:
  * M14  -- keylab/slot.go of PR #8 (HEAD 17c9ee8), line by line.
  * M15  -- the protocol proposed in QAZWIRE_AUDIT_R4.md section 6
            (CAS-then-check ticket, poison on provider panic, separate egress gate).

Breadth-first search over ALL interleavings of the configured threads gives
(a) exhaustive checking of safety invariants and of the final-state property,
(b) a SHORTEST interleaving for every reachable "observation".

Threads: seal workers (each performs one sealPacket and, on success, one send),
emergency callers, and finalize goroutines spawned dynamically by the protocol.
Go atomics are sequentially consistent, so an interleaving of atomic steps is a
faithful model; non-atomic steps touch only goroutine-local data.
"""
import sys
from collections import deque

# ----------------------------------------------------------------- state helpers
# shared: dict frozen as a sorted tuple; thread: (name, kind, pc, locals-tuple)


def freeze(d):
    return tuple(sorted(d.items()))


def thaw(t):
    return dict(t)


def spawn(threads, kind, name):
    return threads + ((name, kind, "F0", ()),)


# ----------------------------------------------------------------- M1.4 model
MUTATION = None   # sanity check of the checker itself (see --mutants)
SAFETY_14 = ("wipe_while_active", "process_after_wipe", "double_wipe", "dup_ticket", "over_limit")
OBS_14 = ("ticket_after_close", "process_after_close", "ok_return_after_close",
          "send_after_close", "send_after_wipe")


def m14_init(n_seal, n_emerg, max_msgs):
    sh = dict(closing=0, wiping=0, refs=0, next=0, done=0, wipes=0, active=0,
              tickets=frozenset(), nfin=0, max=max_msgs)
    for k in SAFETY_14 + OBS_14:
        sh[k] = 0
    th = tuple((f"S{i}", "seal", "A0", ()) for i in range(n_seal))
    th += tuple((f"E{i}", "emerg", "E0", ()) for i in range(n_emerg))
    return freeze(sh), th


def m14_step(sh, th, idx):
    """Return list of (label, new_shared, new_threads)."""
    s = thaw(sh)
    name, kind, pc, loc = th[idx]
    L = dict(loc)
    rest = th[:idx] + th[idx + 1:]
    out = []

    def go(npc, label, **nl):
        nonlocal rest
        L2 = dict(L)
        L2.update(nl)
        newt = rest[:idx] + ((name, kind, npc, tuple(sorted(L2.items()))),) + rest[idx:]
        out.append((f"{name}: {label}", freeze(s), newt))

    def end(label, extra=()):
        newt = rest + extra
        out.append((f"{name}: {label}", freeze(s), newt))

    def fin_thread():
        s["nfin"] += 1
        return ((f"F{s['nfin']}", "fin", "F0", ()),)

    if kind == "seal":
        if pc == "A0":                      # acquire: s := state.Load()
            if s["closing"] and MUTATION not in ("acquire_ignores_closing", "no_closing_checks"):
                return end("acquire: closing -> errClosed") or out
            go("A1", "acquire: load state (open)", snap=(s["closing"], s["wiping"], s["refs"]))
        elif pc == "A1":                    # state.CompareAndSwap(s, s+1)
            if (s["closing"], s["wiping"], s["refs"]) == L["snap"]:
                s["refs"] += 1
                go("R0", "acquire: CAS ok, refs++")
            else:
                go("A0", "acquire: CAS failed, retry")
        elif pc == "R0":                    # reserve: n := next.Load(); n >= max ?
            if s["next"] >= s["max"]:
                go("REL", "reserve: exhausted", res="err")
            else:
                go("R1", f"reserve: load next={s['next']}", n=s["next"])
        elif pc == "R1":                    # reserve: state.Load()&closing
            if s["closing"] and MUTATION != "no_closing_checks":
                go("REL", "reserve: closing -> errClosed", res="err")
            else:
                go("R2", "reserve: closing==0 observed")
        elif pc == "R2":                    # reserve: next.CompareAndSwap(n, n+1)
            if s["next"] == L["n"] or MUTATION == "ticket_store_not_cas":
                s["next"] += 1
                if L["n"] in s["tickets"]:
                    s["dup_ticket"] = 1
                if s["next"] > s["max"]:
                    s["over_limit"] = 1
                s["tickets"] = s["tickets"] | {L["n"]}
                if s["closing"]:
                    s["ticket_after_close"] = 1
                go("P0", f"reserve: CAS next {L['n']}->{L['n'] + 1} (ticket {L['n']})")
            else:
                go("R0", "reserve: CAS failed, retry")
        elif pc == "P0":                    # process enter
            s["active"] += 1
            if s["closing"]:
                s["process_after_close"] = 1
            if s["wipes"]:
                s["process_after_wipe"] = 1
            go("P1", "process(): enter")
        elif pc == "P1":                    # process exit
            s["active"] -= 1
            go("C0", "process(): return")
        elif pc == "C0":                    # if state.Load()&closing -> discard
            go("REL", "post-check: closing -> discard" if s["closing"] else "post-check: open",
               res="err" if s["closing"] else "ok")
        elif pc == "REL":                   # deferred release: Add(-1)
            s["refs"] -= 1
            extra = ()
            if s["closing"] and s["refs"] == 0 and MUTATION != "release_never_finalizes":
                extra = fin_thread()
            if L["res"] == "ok":
                newt = rest[:idx] + ((name, kind, "RET", tuple(sorted(L.items()))),) + rest[idx:] + extra
                out.append((f"{name}: release refs--" + (" -> go finalize()" if extra else ""), freeze(s), newt))
            else:
                end("release refs--" + (" -> go finalize()" if extra else ""), extra)
        elif pc == "RET":                   # sealPacket returned record to caller
            if s["closing"]:
                s["ok_return_after_close"] = 1
            go("SEND", "sealPacket returned record")
        elif pc == "SEND":                  # caller hands datagram to the network
            if s["closing"]:
                s["send_after_close"] = 1
            if s["wipes"]:
                s["send_after_wipe"] = 1
            end("caller sends datagram")
    elif kind == "emerg":                   # beginEmergency: Or(closing)
        old = s["refs"]
        s["closing"] = 1
        extra = fin_thread() if old == 0 else ()
        end("beginEmergency: Or(closingBit)" + (" -> go finalize()" if extra else ""), extra)
    elif kind == "fin":
        if pc == "F0":
            if not s["closing"] or s["refs"] != 0 or s["wiping"]:
                end("finalize: nothing to do")
            else:
                go("F1", "finalize: load (closing, refs=0)", snap=(s["closing"], s["wiping"], s["refs"]))
        elif pc == "F1":
            if (s["closing"], s["wiping"], s["refs"]) == L["snap"]:
                s["wiping"] = 1
                go("W0", "finalize: CAS wipingBit")
            else:
                go("F0", "finalize: CAS failed")
        elif pc == "W0":
            if s["active"]:
                s["wipe_while_active"] = 1
            if s["wipes"]:
                s["double_wipe"] = 1
            s["wipes"] += 1
            go("W1", "wipe()")
        elif pc == "W1":
            s["done"] = 1
            end("close(done)")
    return out


# ----------------------------------------------------------------- M1.5 model
SAFETY_15 = ("wipe_while_active", "process_after_wipe", "double_wipe", "dup_ticket", "over_limit",
             "valid_ticket_after_close", "send_after_stageA", "unpoisoned_after_panic")
# Allowed behaviours (documented): a ticket may be burnt; admitted work may enter the
# provider after closingBit (its output is discarded); a datagram sealed BEFORE closing
# may be handed to the kernel until stage A completes, possibly after the wipe.
OBS_15 = ("burnt_ticket", "process_after_close", "send_after_close_before_stageA", "send_after_wipe")


def m15_init(n_seal, n_emerg, max_msgs, panic_seal=False):
    sh = dict(closing=0, poison=0, wiping=0, refs=0, next=0, done=0, wipes=0, active=0,
              tickets=frozenset(), nfin=0, max=max_msgs,
              eblocked=0, erefs=0, stageA=0)
    for k in SAFETY_15 + OBS_15:
        sh[k] = 0
    th = tuple((f"S{i}", "seal", "A0", (("panics", 1 if (panic_seal and i == 0) else 0),)) for i in range(n_seal))
    th += tuple((f"E{i}", "emerg", "E0", ()) for i in range(n_emerg))
    return freeze(sh), th


def m15_step(sh, th, idx):
    s = thaw(sh)
    name, kind, pc, loc = th[idx]
    L = dict(loc)
    rest = th[:idx] + th[idx + 1:]
    out = []

    def go(npc, label, **nl):
        L2 = dict(L)
        L2.update(nl)
        newt = rest[:idx] + ((name, kind, npc, tuple(sorted(L2.items()))),) + rest[idx:]
        out.append((f"{name}: {label}", freeze(s), newt))

    def end(label, extra=()):
        out.append((f"{name}: {label}", freeze(s), rest + extra))

    def fin_thread():
        s["nfin"] += 1
        return ((f"F{s['nfin']}", "fin", "F0", ()),)

    if kind == "seal":
        if pc == "A0":
            if s["closing"]:
                return end("acquire: closing -> errClosed") or out
            go("A1", "acquire: load", snap=(s["closing"], s["wiping"], s["refs"]))
        elif pc == "A1":
            if (s["closing"], s["wiping"], s["refs"]) == L["snap"]:
                s["refs"] += 1
                go("R0", "acquire: CAS ok")
            else:
                go("A0", "acquire: CAS retry")
        elif pc == "R0":                    # CAS-then-check: n := next.Load()
            if s["next"] >= s["max"]:
                go("REL", "reserve: exhausted", res="err")
            else:
                go("R1", f"reserve: load next={s['next']}", n=s["next"])
        elif pc == "R1":                    # next.CAS(n, n+1) FIRST
            if s["next"] == L["n"]:
                s["next"] += 1
                if L["n"] in s["tickets"]:
                    s["dup_ticket"] = 1
                if s["next"] > s["max"]:
                    s["over_limit"] = 1
                s["tickets"] = s["tickets"] | {L["n"]}
                go("R2", f"reserve: CAS next (ticket {L['n']})", cas_closing=s["closing"])
            else:
                go("R0", "reserve: CAS retry")
        elif pc == "R2":                    # THEN closing check: monotonic flag => witness
            if s["closing"]:
                s["burnt_ticket"] = 1
                go("REL", "reserve: closing after CAS -> ticket burnt", res="err")
            else:
                if L["cas_closing"]:
                    s["valid_ticket_after_close"] = 1  # impossible: closing is monotonic
                go("P0", "reserve: ticket valid")
        elif pc == "P0":
            s["active"] += 1
            if s["closing"]:
                s["process_after_close"] = 1
            if s["wipes"]:
                s["process_after_wipe"] = 1
            go("P1", "process(): enter")
        elif pc == "P1":                    # provider returns or panics
            s["active"] -= 1
            if L["panics"]:
                s["poison"] = 1             # recover(): poison = closing|poison, output cleared
                s["closing"] = 1
                go("REL", "process(): PANIC -> recover, poison+closing", res="err")
            else:
                go("C0", "process(): return")
        elif pc == "C0":
            go("REL", "post-check: closing -> discard" if s["closing"] else "post-check: open",
               res="err" if s["closing"] else "ok")
        elif pc == "REL":
            s["refs"] -= 1
            extra = fin_thread() if (s["closing"] and s["refs"] == 0) else ()
            if L["res"] == "ok":
                newt = rest[:idx] + ((name, kind, "S0", tuple(sorted(L.items()))),) + rest[idx:] + extra
                out.append((f"{name}: release" + (" -> go finalize()" if extra else ""), freeze(s), newt))
            else:
                end("release" + (" -> go finalize()" if extra else ""), extra)
        # ---- egress gate (independent of the key): acquire egress lease, send, release
        elif pc == "S0":
            if s["eblocked"]:
                end("egress: blocked -> drop record")
            else:
                go("S1", "egress: load (open)", esnap=(s["eblocked"], s["erefs"]))
        elif pc == "S1":
            if (s["eblocked"], s["erefs"]) == L["esnap"]:
                s["erefs"] += 1
                go("S2", "egress: CAS erefs++")
            else:
                go("S0", "egress: CAS retry")
        elif pc == "S2":
            if s["stageA"]:
                s["send_after_stageA"] = 1
            if s["wipes"]:
                s["send_after_wipe"] = 1     # sending ciphertext after wipe is harmless; tracked
            if s["closing"] and not s["stageA"]:
                s["send_after_close_before_stageA"] = 1
            go("S3", "send datagram")
        elif pc == "S3":
            s["erefs"] -= 1
            end("egress: erefs--")
    elif kind == "emerg":
        if pc == "E0":                      # stage A.1: egress gate first
            s["eblocked"] = 1
            go("E1", "emergency: Or(egressBlocked)")
        elif pc == "E1":                    # stage A.2: key admission
            old = s["refs"]
            s["closing"] = 1
            extra = fin_thread() if old == 0 else ()
            newt = rest[:idx] + ((name, kind, "E2", ()),) + rest[idx:] + extra
            out.append((f"{name}: emergency: Or(closingBit)" + (" -> go finalize()" if extra else ""), freeze(s), newt))
        elif pc == "E2":                    # stage A.3: wait for in-flight sends (bounded in impl.)
            if s["erefs"] == 0:
                s["stageA"] = 1
                end("emergency: erefs==0 -> stage A complete")
            # else: blocked (no transition)
    elif kind == "fin":
        if pc == "F0":
            if not s["closing"] or s["refs"] != 0 or s["wiping"]:
                end("finalize: nothing")
            else:
                go("F1", "finalize: load", snap=(s["closing"], s["wiping"], s["refs"]))
        elif pc == "F1":
            if (s["closing"], s["wiping"], s["refs"]) == L["snap"]:
                s["wiping"] = 1
                go("W0", "finalize: CAS wiping")
            else:
                go("F0", "finalize: CAS retry")
        elif pc == "W0":
            if s["active"]:
                s["wipe_while_active"] = 1
            if s["wipes"]:
                s["double_wipe"] = 1
            s["wipes"] += 1
            go("W1", "wipe()")
        elif pc == "W1":
            s["done"] = 1
            end("close(done)")
    return out


# ----------------------------------------------------------------- explorer
def explore(init, step, safety, obs, final_check, label):
    sh0, th0 = init
    start = (sh0, th0)
    parent = {start: None}
    q = deque([start])
    first = {}
    violations = {}
    terminal = 0
    deadlocks = 0
    while q:
        st = q.popleft()
        sh, th = st
        s = thaw(sh)
        for k in safety:
            if s[k] and k not in violations:
                violations[k] = st
        for k in obs:
            if s[k] and k not in first:
                first[k] = st
        succ = []
        for i in range(len(th)):
            succ.extend(step(sh, th, i))
        if not succ:
            terminal += 1
            if th:                          # threads remain but none can move
                deadlocks += 1
                violations.setdefault("deadlock", st)
            msg = final_check(s)
            if msg:
                violations.setdefault(msg, st)
            continue
        for lab, nsh, nth in succ:
            ns = (nsh, nth)
            if ns not in parent:
                parent[ns] = (st, lab)
                q.append(ns)

    def trace(st):
        path = []
        while parent[st] is not None:
            st, lab = parent[st]
            path.append(lab)
        return list(reversed(path))

    print(f"\n### {label}")
    print(f"states explored: {len(parent)}, terminal states: {terminal}")
    for k in safety:
        print(f"  safety {k:28s}: {'VIOLATED' if k in violations else 'holds'}")
    for k in ("deadlock",) + tuple(x for x in violations if x not in safety and x != "deadlock"):
        if k in violations:
            print(f"  {k}: VIOLATED")
    if "deadlock" not in violations:
        print("  no terminal state with blocked threads (no deadlock)")
    fin = [k for k in violations if k.startswith("final")]
    print("  final-state property (closing => exactly one wipe and done closed): "
          + ("VIOLATED" if fin else "holds in every terminal state"))
    for k in obs:
        print(f"  observation {k:24s}: {'REACHABLE' if k in first else 'unreachable'}")
    for k, st in list(violations.items()) + list(first.items()):
        print(f"\n  shortest interleaving for {k}:")
        for n, lab in enumerate(trace(st), 1):
            print(f"    {n:2d}. {lab}")
    return violations, first


def final14(s):
    if s["closing"] and not (s["wipes"] == 1 and s["done"]):
        return "final: closing but not wiped exactly once"
    return None


def final15(s):
    if s["closing"] and not (s["wipes"] == 1 and s["done"]):
        return "final: closing but not wiped exactly once"
    if s["poison"] and not s["closing"]:
        return "unpoisoned_after_panic"
    return None


if __name__ == "__main__":
    if "--mutants" in sys.argv:          # the checker must catch each injected bug
        for MUTATION in ("acquire_ignores_closing", "no_closing_checks", "release_never_finalizes",
                         "ticket_store_not_cas"):
            v, _ = explore(m14_init(2, 1, 2), m14_step, SAFETY_14, OBS_14, final14,
                           f"MUTANT {MUTATION}")
            note = ("SURVIVED: equivalent mutant -- masked by the closing check in reserve()"
                    if MUTATION == "acquire_ignores_closing" else "SURVIVED (checker too weak)")
            print(f"  => mutant {MUTATION}: {'KILLED' if v else note}")
        sys.exit(0)
    traces = "--traces" in sys.argv
    _p = print
    if not traces:
        def quiet(*a, **k):
            if a and isinstance(a[0], str) and (a[0].startswith("    ") or a[0].startswith("\n  shortest")):
                return
            _p(*a, **k)
        print = quiet  # noqa: A001
    for ns, ne, m in ((2, 1, 2), (3, 1, 3), (2, 2, 2)):
        explore(m14_init(ns, ne, m), m14_step, SAFETY_14, OBS_14, final14,
                f"M1.4 keylab: {ns} seal workers, {ne} emergency caller(s), maxMessages={m}")
    for ns, ne, m, pnc in ((2, 1, 2, False), (3, 1, 3, False), (2, 2, 2, False), (2, 1, 2, True)):
        explore(m15_init(ns, ne, m, pnc), m15_step, SAFETY_15, OBS_15, final15,
                f"M1.5 proposal: {ns} seal workers, {ne} emergency caller(s), maxMessages={m}"
                + (", worker S0 provider panics" if pnc else ""))
