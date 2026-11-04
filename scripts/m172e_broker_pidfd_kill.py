#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""PIDFD SIGKILL helper: only this lab's detached UID65533 broker.
Read-only identity checks precede the sole targeted privileged signal.
"""
import argparse
import os
from pathlib import Path
import re
import select
import signal

NS = re.compile(r"^qwfa[0-9a-f]{8}$", re.ASCII)
NONCE = re.compile(r"^[0-9a-f]{8}$", re.ASCII)


def matches_broker_cmdline(raw, nonce):
    # Bash command substitution removes trailing newline bytes.
    source = Path(__file__).with_name(
        "m172e_broker.py"
    ).read_bytes().rstrip(b"\\n")

    expected = b"\\0".join((
        b"/usr/bin/python3",
        b"-B",
        b"-u",
        b"-c",
        source,
        b"serve",
        b"--nonce",
        nonce.encode("ascii"),
    )) + b"\\0"

    return raw == expected


def send(ns, nonce, pid):
    if os.geteuid() != 0:
        raise PermissionError("explicit sudo required")
    if not NS.fullmatch(ns) or not NONCE.fullmatch(nonce):
        raise ValueError("invalid lab namespace/nonce")
    if ns != "qwfa" + nonce or pid <= 1 or pid == os.getpid():
        raise ValueError("invalid lab target")
    path = Path("/run/netns") / ns
    host_inode = os.stat("/proc/self/ns/net").st_ino
    target_inode = path.stat().st_ino
    if host_inode == target_inode:
        raise PermissionError("refuse host network namespace")
    fd = os.pidfd_open(pid, 0)
    try:
        poll = select.poll()
        poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poll.poll(0):
            raise ProcessLookupError("broker already exited")
        if os.stat(f"/proc/{pid}/ns/net").st_ino != target_inode:
            raise PermissionError("broker is outside the exact new lab netns")
        stat = {}
        with open(f"/proc/{pid}/status", encoding="ascii") as stream:
            for line in stream:
                if ":" in line:
                    k, v = line.split(":", 1)
                    stat[k] = v.strip()
        if [int(x) for x in stat["Uid"].split()] != [65533] * 4:
            raise PermissionError("broker UID mismatch")
        if any(int(stat[key], 16) for key in ("CapEff", "CapBnd", "CapAmb")):
            raise PermissionError("broker capabilities are not zero")
        if stat["NoNewPrivs"] != "1":
            raise PermissionError("broker NoNewPrivs missing")
        if os.getsid(pid) != pid or os.getpgid(pid) != pid:
            raise PermissionError("not an isolated broker session leader")
        args = Path(f"/proc/{pid}/cmdline").read_bytes()
        if not matches_broker_cmdline(args, nonce):
            raise PermissionError("broker command identity does not match")
        if not os.path.samefile(f"/proc/{pid}/exe", "/usr/bin/python3"):
            raise PermissionError("broker executable identity does not match")
        if poll.poll(0):
            raise ProcessLookupError("broker disappeared during verification")
        signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        print("BROKER_PIDFD_SIGKILL_SENT", flush=True)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--pid", required=True, type=int)
    args = parser.parse_args()
    send(args.namespace, args.nonce, args.pid)


if __name__ == "__main__":
    main()
