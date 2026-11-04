#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Persistent root *laboratory* nft policy controller, NOT a secure service.

Only operates on a newly created qwdaXXXXXXXX named network namespace.
Root controller remains in the HOST network namespace; nft is always
invoked through "ip netns exec" with fixed arguments. No host nft calls.

The controller binds its monitoring to a single unprivileged worker pidfd.
It revokes permits upon SIGSTOP/exit; killing the controller itself leaves
a bounded (2s) nft permission until it expires. This gap is intentional.
"""
import argparse
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

NS_RE = re.compile(r"^qwda[0-9a-f]{8}$", re.ASCII)
TABLE = "qw_privsep_a0"
GRANT = "privileged_grants"
DEST = "198.18.27.2"
LEASE_SECONDS = 2
RENEW_SECONDS = 0.30
POLL_SECONDS = 0.04

# Strictly fixed policy statements; never derive a nft command from worker IPC.
FLUSH = f"flush set inet {TABLE} {GRANT}\n"
ADD = f"add element inet {TABLE} {GRANT} {{ {DEST} timeout {LEASE_SECONDS}s }}\n"


def validate_ns(name):
    if not NS_RE.fullmatch(name):
        raise ValueError("not a uniquely named M1.7.2d worker lab namespace")
    ns_path = Path("/run/netns") / name
    host = os.stat("/proc/self/ns/net").st_ino
    target = ns_path.stat().st_ino
    if host == target:
        raise ValueError("controller may not execute inside its worker netns")
    return target


def read_status(pid):
    data = {}
    with open(f"/proc/{pid}/status", encoding="ascii") as stream:
        for line in stream:
            if ":" in line:
                key, value = line.split(":", 1)
                data[key] = value.strip()
    return data


def require_worker(pid, ns_ino, fd=None):
    if pid <= 1 or pid == os.getpid():
        raise ValueError("invalid worker pid")
    if fd is not None and pidfd_exited(fd):
        raise RuntimeError("worker exited before identity verification")
    if os.stat(f"/proc/{pid}/ns/net").st_ino != ns_ino:
        raise PermissionError("worker not in the exact lab namespace")
    status = read_status(pid)
    if any(int(uid) != 65534 for uid in status["Uid"].split()):
        raise PermissionError("worker UID is not exclusively 65534")
    if any(int(status[field], 16) != 0 for field in ("CapEff", "CapBnd", "CapAmb")):
        raise PermissionError("worker has capabilities")
    if status["NoNewPrivs"] != "1":
        raise PermissionError("worker missing NoNewPrivs")
    cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
    if b"m172d_worker.py" not in cmd:
        raise PermissionError("unexpected worker executable")
    if fd is not None and pidfd_exited(fd):
        raise RuntimeError("worker exited during identity verification")
    return status["State"].split()[0]


def pidfd_exited(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    result = poll.poll(0)
    if not result:
        return False
    bits = result[0][1]
    if bits & (select.POLLERR | select.POLLNVAL):
        raise RuntimeError("invalid pidfd poll readiness")
    return bool(bits & (select.POLLIN | select.POLLHUP))


def policy(ip_bin, nft_bin, ns, batch, *, timeout=2):
    if batch not in (FLUSH, ADD, FLUSH + ADD):
        raise ValueError("unapproved nft transaction")
    result = subprocess.run(
        [ip_bin, "netns", "exec", ns, nft_bin, "-f", "-"],
        input=batch, text=True, capture_output=True, timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("restricted nft transaction failed: " +
                           result.stderr.strip()[:200])
    return True


def current_grant(ip_bin, nft_bin, ns):
    result = subprocess.run(
        [ip_bin, "netns", "exec", ns, nft_bin, "list", "set", "inet",
         TABLE, GRANT],
        capture_output=True, text=True, timeout=2, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot inspect restricted nft set")
    return DEST in result.stdout


def note(message):
    print(message, flush=True)


def ensure_denied(ip_bin, nft_bin, ns):
    policy(ip_bin, nft_bin, ns, FLUSH)
    if current_grant(ip_bin, nft_bin, ns):
        raise RuntimeError("DENY_VERIFICATION_FAILED")


def pidfd_wait(fd, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if pidfd_exited(fd):
            return True
        time.sleep(POLL_SECONDS)
    return False


def run_controller(ns, worker_pid):
    if os.geteuid() != 0:
        raise PermissionError("privileged lab controller needs explicit sudo")
    ns_ino = validate_ns(ns)
    ip_bin, nft_bin = shutil.which("ip"), shutil.which("nft")
    if not ip_bin or not nft_bin:
        raise FileNotFoundError("ip/nft executable missing")
    fd = os.pidfd_open(worker_pid, 0)
    try:
        state = require_worker(worker_pid, ns_ino, fd)
        if state not in ("R", "S"):
            raise RuntimeError("worker not healthy at startup")
        # At startup always deny before attempting any grant.
        ensure_denied(ip_bin, nft_bin, ns)
        note(f"CONTROLLER_READY_PID={os.getpid()}")
        policy(ip_bin, nft_bin, ns, ADD)
        note("CTRL_ARMED lease=2s")
        stop_requested = False

        def request_stop(_sig, _frame):
            nonlocal stop_requested
            stop_requested = True

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        last = time.monotonic()
        while True:
            cause = None
            if stop_requested:
                cause = "CONTROLLER_SIGTERM"
            elif pidfd_exited(fd):
                cause = "WORKER_EXIT"
            else:
                try:
                    state = require_worker(worker_pid, ns_ino, fd)
                except (OSError, RuntimeError, PermissionError, KeyError, ValueError):
                    cause = "WORKER_IDENTITY_LOST"
                else:
                    if state not in ("R", "S"):
                        cause = "WORKER_STOP_OR_UNEXPECTED_STATE"

            if cause:
                # A0 explicit policy revocation always happens before worker kill.
                note("CTRL_REVOKE_ATTEMPT reason=" + cause)
                ensure_denied(ip_bin, nft_bin, ns)
                note("CTRL_REVOKED reason=" + cause)
                if cause != "CONTROLLER_SIGTERM" and not pidfd_exited(fd):
                    signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
                    note("WORKER_KILL_SENT")
                    if not pidfd_wait(fd):
                        raise RuntimeError("worker termination not confirmed")
                    note("WORKER_EXIT_CONFIRMED")
                return 0

            if time.monotonic() - last >= RENEW_SECONDS:
                # Kernel atomic nft batch: delete the old expiring element and
                # create a new 2s one while monitored worker remains healthy.
                policy(ip_bin, nft_bin, ns, FLUSH + ADD)
                last = time.monotonic()
            time.sleep(POLL_SECONDS)
    except Exception:
        # Best-effort emergency revoke on a normal Python error. SIGKILL,
        # machine crash, kernel stall and host administrator can bypass this.
        try:
            ensure_denied(ip_bin, nft_bin, ns)
            note("CTRL_ERROR_REVOKE_ATTEMPTED")
        except Exception:
            note("CTRL_ERROR_REVOKE_UNCONFIRMED")
        raise
    finally:
        os.close(fd)


def signal_verified(pid, ns, mode, operation):
    if os.geteuid() != 0:
        raise PermissionError("signal test requires explicit sudo")
    ns_ino = validate_ns(ns)
    fd = os.pidfd_open(pid, 0)
    try:
        if mode == "worker":
            require_worker(pid, ns_ino, fd)
            if operation not in ("STOP", "KILL"):
                raise ValueError("unapproved worker signal")
            sig = signal.SIGSTOP if operation == "STOP" else signal.SIGKILL
        else:
            if operation != "KILL":
                raise ValueError("controller signal only permits SIGKILL")
            status = read_status(pid)
            if any(int(uid) != 0 for uid in status["Uid"].split()):
                raise PermissionError("controller is not root")
            if os.stat(f"/proc/{pid}/ns/net").st_ino == ns_ino:
                raise PermissionError("controller is INSIDE worker namespace")
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
            if (b"m172d_controller.py" not in cmd or b"serve" not in cmd or
                    ns.encode("ascii") not in cmd):
                raise PermissionError("target is not this lab controller")
            sig = signal.SIGKILL
        if pidfd_exited(fd):
            raise RuntimeError("refuse signal for exited target")
        signal.pidfd_send_signal(fd, sig, None, 0)
        note(f"PIDFD_SIGNAL_{operation}_SENT target={mode}")
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--ns", required=True)
    serve.add_argument("--worker-pid", type=int, required=True)
    sign = sub.add_parser("signal")
    sign.add_argument("--ns", required=True)
    sign.add_argument("--pid", type=int, required=True)
    sign.add_argument("--target", choices=("worker", "controller"), required=True)
    sign.add_argument("--action", choices=("STOP", "KILL"), required=True)
    args = p.parse_args()
    if args.mode == "serve":
        return run_controller(args.ns, args.worker_pid)
    signal_verified(args.pid, args.ns, args.target, args.action)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        note("LAB_CONTROLLER_FAIL: " + str(exc)[:250])
        raise SystemExit(1)
