#!/usr/bin/env python3
"""R4.2 bounded transition model of QazWire M1.5.2 @45984d7.

This is an independent small-state abstraction, NOT an extracted Go program,
proof of implementation, or cryptographic security verification. Critical
sections (session.mu) are atomic; gate CAS and provider calls are separate.
One synthetic worker, two ordered normal rotations, emergency in two steps,
and asynchronous wipe completion of each generation and egress.
"""
from collections import deque
from typing import NamedTuple

# Key tuple: exists, closing, discard, refs, done, wiped, failed, ticket_used
K0 = (1, 0, 0, 0, 0, 0, 0, 0)
KNEW = (0, 0, 0, 0, 0, 0, 0, 0)
EX, C, D, REF, DONE, WIPE, FAIL, TICKET = range(8)


class S(NamedTuple):
    keys: tuple
    cur: int
    prev: int
    rot: int
    emergency: int  # 0 none, 1 egress blocked, 2 session closed
    egrefs: int
    egdone: int
    worker: int  # 0=start,1=snapshot,2=lease,3=process,4=packet,
                 # 5=queued,6=egress lease,7=sending,8=done
    wk: int
    retries: int
    pending: int
    sent: int
    await_success: int
    bad: str


def initial():
    return S((K0, KNEW, KNEW), 0, -1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, "")


def setkey(s, i, **values):
    k = list(s.keys[i])
    names = {"ex": EX, "close": C, "discard": D, "refs": REF,
             "done": DONE, "wipe": WIPE, "ticket": TICKET}
    for name, val in values.items():
        k[names[name]] = val
    ks = list(s.keys)
    ks[i] = tuple(k)
    return s._replace(keys=tuple(ks))


def dec(s, i):
    k = s.keys[i]
    if k[REF] == 0:
        return s._replace(bad="reference underflow")
    return setkey(s, i, refs=k[REF] - 1)


def check(s):
    if s.bad:
        return s.bad
    for k in s.keys:
        if k[D] and not k[C]:
            return "discard without close"
        if k[WIPE] and k[REF]:
            return "wiped with active reference"
        if k[WIPE] and not k[C]:
            return "wiped before close"
        if k[DONE] and not k[WIPE]:
            return "done without wipe"
    if s.pending and s.wk != s.cur and s.wk != s.prev:
        return "grandparent packet re-enqueued"
    if s.emergency == 2 and s.rot == 3:
        return "rotation after emergency"
    return ""


def successors(s, mutant=""):
    out = []

    def add(label, v):
        bad = check(v)
        if bad:
            v = v._replace(bad=bad)
        out.append((label, v))

    # Each rotation is one session.mu-protected operation; keys indexed 0..2.
    if s.rot < 2 and s.emergency != 2:
        old = s.cur
        fresh = s.rot + 1
        z = s
        for j, k in enumerate(z.keys):
            if k[EX] and j != old and mutant != "grandparent_guards_disabled":
                z = setkey(z, j, close=1, discard=1)
        if z.pending and z.wk != old:
            z = dec(z, z.wk)._replace(pending=0)
        z = setkey(z, old, close=1)
        z = setkey(z, fresh, ex=1)
        z = z._replace(rot=z.rot+1, prev=old, cur=fresh)
        add("rotate: publish %d and retire %d" % (fresh, old), z)
    if s.emergency == 0:
        add("emergency: block egress", s._replace(emergency=1))
    if s.emergency == 1:
        z = s._replace(emergency=2)
        if z.pending:
            z = dec(z, z.wk)._replace(pending=0)
        for j, k in enumerate(z.keys):
            if k[EX]:
                z = setkey(z, j, close=1, discard=1)
        add("emergency: close session; flush queue; discard keys", z)
    if s.emergency >= 1 and s.egrefs == 0 and not s.egdone:
        add("egress: drain completed", s._replace(egdone=1))
    for j, k in enumerate(s.keys):
        if k[EX] and k[C] and k[REF] == 0 and not k[DONE]:
            add("wipe(k%d) + done" % j, setkey(s, j, done=1, wipe=1))
    if (s.emergency == 2 and s.egdone and
            all((not k[EX] or k[DONE]) for k in s.keys)):
        if not s.await_success:
            add("awaitDrained: success", s._replace(await_success=1))

    # One worker with an operation lease and optional queued lease transfer.
    k = s.wk
    if s.worker == 0 and s.emergency != 2:
        add("prepare: read current key", s._replace(worker=1, wk=s.cur))
    elif s.worker == 1:
        if s.keys[k][C]:
            if s.retries == 0 and s.emergency != 2:
                add("closed generation: retry current",
                    s._replace(worker=0, retries=1, wk=-1))
            else:
                add("closed generation: return errClosed",
                    s._replace(worker=8))
        else:
            add("gate.enter: operation lease",
                setkey(s, k, refs=s.keys[k][REF]+1)._replace(worker=2))
    elif s.worker == 2:
        if s.keys[k][C]:
            add("reserve: burnt on close", dec(s, k)._replace(worker=8))
        elif not s.keys[k][TICKET]:
            add("reserve: one ticket",
                setkey(s, k, ticket=1)._replace(worker=3))
    elif s.worker == 3:
        add("provider process: complete", s._replace(worker=4))
    elif s.worker == 4:
        if s.keys[k][D]:
            if s.retries == 0 and s.emergency != 2:
                add("discarded during seal: retry current",
                    dec(s, k)._replace(worker=0, wk=-1, retries=1))
            else:
                add("discarded during seal: return errClosed",
                    dec(s, k)._replace(worker=8))
        elif (s.emergency == 2 or
              (mutant != "grandparent_guards_disabled"
               and k != s.cur and k != s.prev)):
            add("prepare: reject invalid generation under mu",
                dec(s, k)._replace(worker=8))
        else:
            add("prepare: transfer lease into queue",
                s._replace(worker=5, pending=1))
    elif s.worker == 5 and s.pending:
        if s.emergency >= 1 and mutant != "skip_egress_gate":
            add("dispatch: egress closed; no send",
                s._replace(worker=8))
        else:
            eglease = 0 if mutant == "skip_egress_gate" else 1
            add("dispatch: egress enter",
                s._replace(worker=6, egrefs=s.egrefs+eglease))
        add("discard: release queued packet",
            dec(s, k)._replace(worker=8, pending=0))
    elif s.worker == 6:
        if s.pending:
            z = s._replace(pending=0, worker=7)
            if mutant == "early_key_leave":
                z = dec(z, k)
            add("dispatch: atomically claim ticket", z)
        else:
            eglease = 0 if mutant == "skip_egress_gate" else 1
            add("dispatch: packet missing",
                s._replace(worker=8, egrefs=s.egrefs-eglease))
    elif s.worker == 7:
        eglease = 0 if mutant == "skip_egress_gate" else 1
        z = s._replace(worker=8, sent=s.sent+1, egrefs=s.egrefs-eglease)
        if z.emergency >= 1 and z.egdone:
            z = z._replace(bad="send after egress drain confirmation")
        elif z.await_success:
            z = z._replace(bad="send after successful await")
        elif z.keys[k][WIPE]:
            z = z._replace(bad="sent with wiped key")
        if mutant != "early_key_leave":
            z = dec(z, k)
        add("wire.send and release leases", z)
    return out


def bfs(mutant="", max_states=500_000):
    root = initial()
    seen = {root: None}
    todo = deque([root])
    viol = None
    terminals = 0
    while todo:
        s = todo.popleft()
        if s.bad:
            viol = s
            break
        opts = successors(s, mutant)
        if not opts:
            terminals += 1
        for label, nexts in opts:
            if nexts not in seen:
                seen[nexts] = (s, label)
                if len(seen) >= max_states:
                    return "LIMIT", len(seen), None, terminals
                todo.append(nexts)
    if not viol:
        return "HOLD", len(seen), None, terminals
    path = []
    cur = viol
    while seen[cur] is not None:
        cur, label = seen[cur]
        path.append(label)
    path.reverse()
    return "VIOLATED", len(seen), (viol.bad, path), terminals


if __name__ == "__main__":
    mutants = ("", "early_key_leave", "skip_egress_gate",
               "grandparent_guards_disabled")
    expected = ("HOLD", "VIOLATED", "VIOLATED", "VIOLATED")
    observed = []
    for mutant in mutants:
        state, states, detail, terminal = bfs(mutant)
        observed.append(state)
        print(f"{mutant or 'baseline'}: {state}, "
              f"explored={states}, terminals={terminal}")
        if detail:
            print("  property:", detail[0])
            print("  trace:", " => ".join(detail[1]))
    if tuple(observed) != expected:
        raise SystemExit(f"unexpected model result: {observed} != {expected}")

# EXCLUDED: provider failures, multiple workers, overlapping receives, hung
# operations, real sends, OS scheduling fairness and physical secret erasure.
