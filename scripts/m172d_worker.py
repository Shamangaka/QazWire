#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic unprivileged worker for the isolated M1.7.2d network lab.

No cryptographic keys or VPN transport. The worker must never use sudo or
nftables. It runs under UID 65534 with Linux capabilities fully dropped.
"""
import os
import sys
import time


def validate_unprivileged():
    if os.getuid() != 65534 or os.geteuid() != 65534:
        raise SystemExit("WORKER_DENY: unexpected UID")
    status = {}
    with open("/proc/self/status", encoding="ascii") as stream:
        for line in stream:
            if ":" in line:
                key, value = line.split(":", 1)
                status[key] = value.strip()
    for key in ("CapEff", "CapBnd", "CapAmb"):
        if int(status[key], 16):
            raise SystemExit("WORKER_DENY: nonzero " + key)
    if status.get("NoNewPrivs") != "1":
        raise SystemExit("WORKER_DENY: NoNewPrivs absent")
    if os.getgroups():
        raise SystemExit("WORKER_DENY: supplementary groups")
    return True


def main():
    # SIGSTOP on a command directly supervised by sudo may cause sudo to
    # suspend the parent shell's process group. Detach only AFTER dropping
    # capabilities and UID; the intermediate sudo child then exits.
    # This is a laboratory-specific workaround, not a daemon architecture.
    if "--detach" not in sys.argv[1:]:
        raise SystemExit("WORKER_DENY: explicit --detach required")
    validate_unprivileged()
    pid = os.fork()
    if pid:
        # Return from the process monitored by sudo BEFORE fault injection.
        return 0
    # In the new child, become leader of a new process group and session.
    os.setsid()
    validate_unprivileged()
    if os.getsid(0) != os.getpid() or os.getpgrp() != os.getpid():
        raise SystemExit("WORKER_DENY: not a detached session leader")
    print("WORKER_READY_PID=" + str(os.getpid()), flush=True)

    # The worker is now independent of sudo's job-control monitor.
    # Close inherited stdio to avoid retaining TTY or sudo pseudo-terminal.
    # Printing readiness first ensures owner Bash can read verified PID.
    devnull = os.open(os.devnull, os.O_RDWR)
    try:
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
    finally:
        if devnull > 2:
            os.close(devnull)

    while True:
        time.sleep(0.05)


if __name__ == "__main__":
    raise SystemExit(main())
