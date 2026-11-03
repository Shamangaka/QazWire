#!/usr/bin/env python3
"""M1.6.1 bounded logical model, NOT a translated or verified Go program.

Two synthetic Prepare workers, 3 material identities, at most 2 rotations,
one ticket allocation per admitted Prepare, 3 retries maximum, concurrent
Stop/Poison, and empty/positive queue charges. State transitions represent
mu-protected operations or the separate unlocked copy phase.

Excluded: real encryption, Go memory, hardware wipe, Go scheduler fairness,
real network I/O, hung callbacks and Stage-D process isolation.
"""
from collections import deque
from typing import NamedTuple

# Phase: NEW=0, RESERVED=1, COPIED=2, QUEUED=3, DONE=4.
NEW, RESERVED, COPIED, QUEUED, DONE = range(5)
MAX_STATES = 300_000


class Worker(NamedTuple):
    phase: int = NEW
    epoch: int = -1
    tries: int = 0
    seq: int = -1


class State(NamedTuple):
    current: int
    stopped: bool
    poisoned: bool
    counters: tuple
    workers: tuple
    sent: tuple
    error: str = ""


def start():
    return State(0, False, False, (0, 0, 0), (Worker(), Worker()), ())


def derive(s, costs):
    inflight = sum(w.phase in (RESERVED, COPIED) for w in s.workers)
    reserved = sum(costs[i] for i, w in enumerate(s.workers)
                   if w.phase in (RESERVED, COPIED))
    queued = sum(costs[i] for i, w in enumerate(s.workers)
                 if w.phase == QUEUED)
    pending = sum(w.phase == QUEUED for w in s.workers)
    return inflight, reserved, queued, pending


def check(s, costs, budget):
    if s.error:
        return s.error
    inflight, reserved, queued, pending = derive(s, costs)
    if reserved + queued > budget:
        return "bytes exceeded reservation budget"
    if inflight > 2 or inflight + pending > 2:
        return "work slots overflow"
    if s.stopped and pending:
        return "queued packet after stop/poison"
    if any(w.phase == QUEUED and w.epoch < s.current - 1
           for w in s.workers):
        return "grandparent queued"
    if len(s.sent) != len(set(s.sent)):
        return "duplicate material/epoch ticket pair sent"
    if any(n > 3 for n in s.counters):
        return "ticket counter exceeded bound"
    return ""


def neighbors(s, costs, budget, mutant):
    inflight, reserved, queued, pending = derive(s, costs)

    def emit(label, candidate):
        bad = check(candidate, costs, budget)
        if bad:
            candidate = candidate._replace(error=bad)
        return label, candidate

    if not s.stopped and s.current < 2:
        new_epoch = s.current + 1
        workers = tuple(
            w._replace(phase=DONE)
            if w.phase == QUEUED and w.epoch < new_epoch - 1 else w
            for w in s.workers
        )
        yield emit("Rotate", s._replace(current=new_epoch, workers=workers))

    if not s.stopped:
        workers = tuple(w._replace(phase=DONE) if w.phase == QUEUED else w
                        for w in s.workers)
        yield emit("Stop", s._replace(stopped=True, workers=(
            s.workers if mutant == "omit_stop_flush" else workers)))
        yield emit("Poison", s._replace(stopped=True, poisoned=True, workers=workers))

    for i, w in enumerate(s.workers):
        ws = list(s.workers)
        if w.phase == NEW and not s.stopped and w.tries < 3:
            amount = costs[i]
            capacity_used = queued if mutant == "omit_reserved_account" else queued + reserved
            if capacity_used + amount <= budget and inflight < 2 and inflight + pending < 2:
                current_seq = s.counters[s.current]
                if current_seq < 3:
                    nexts = list(s.counters)
                    nexts[s.current] += 1
                    seq = (0 if mutant == "omit_ticket_uniqueness"
                           else current_seq)
                    ws[i] = Worker(RESERVED, s.current, w.tries + 1, seq)
                    yield emit(f"W{i}.Reserve", s._replace(workers=tuple(ws), counters=tuple(nexts)))
        if w.phase == RESERVED:
            ws[i] = w._replace(phase=COPIED)
            yield emit(f"W{i}.Copy", s._replace(workers=tuple(ws)))
        if w.phase == COPIED:
            stale = w.epoch < s.current - 1
            invalid = s.stopped or (stale and mutant != "omit_grandparent_fence")
            if invalid:
                retry = not s.stopped and w.tries < 3
                ws[i] = Worker(NEW if retry else DONE, -1, w.tries)
                yield emit(f"W{i}.FenceReject", s._replace(workers=tuple(ws)))
            else:
                ws[i] = w._replace(phase=QUEUED)
                yield emit(f"W{i}.Queue", s._replace(workers=tuple(ws)))
        if w.phase == QUEUED and not s.stopped:
            ws[i] = w._replace(phase=DONE)
            material_and_ticket = (w.epoch, w.seq)
            yield emit(f"W{i}.Consume", s._replace(
                workers=tuple(ws), sent=s.sent + (material_and_ticket,)))
            yield emit(f"W{i}.Discard", s._replace(workers=tuple(ws)))


def explore(costs, budget, mutant=""):
    initial = start()
    queue = deque([initial])
    seen = {initial: None}
    while queue:
        s = queue.popleft()
        if s.error:
            trace = []
            while seen[s] is not None:
                prev, label = seen[s]
                trace.append(label)
                s = prev
            return "VIOLATION", len(seen), list(reversed(trace))
        for label, candidate in neighbors(s, costs, budget, mutant):
            if candidate in seen:
                continue
            seen[candidate] = (s, label)
            if len(seen) > MAX_STATES:
                return "LIMIT", len(seen), []
            queue.append(candidate)
    return "HOLD", len(seen), []


def main():
    results = []
    for costs, budget in [((2, 1), 2), ((1, 1), 3), ((0, 0), 1)]:
        state, count, trace = explore(costs, budget)
        print(f"baseline costs={costs} budget={budget}: {state}, states={count}")
        results.append(state == "HOLD")
    controls = [
        ("omit_reserved_account", (2, 1), 2),
        ("omit_stop_flush", (1, 1), 3),
        ("omit_grandparent_fence", (1, 1), 3),
        ("omit_ticket_uniqueness", (1, 1), 3),
    ]
    for mutant, costs, budget in controls:
        state, count, trace = explore(costs, budget, mutant)
        print(f"mutant {mutant}: {state}, states={count}, trace={trace}")
        results.append(state == "VIOLATION")
    if not all(results):
        raise SystemExit("M1.6.1 bounded state/mutation checks FAILED")


if __name__ == "__main__":
    main()
