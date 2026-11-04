#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1.7.3a P1: pidfd SIGKILL of exact detached lab broker only."""
import argparse
import os
from pathlib import Path
import re
import select
import signal

BROKER_NS = re.compile(r"^qwhb([0-9a-f]{8})$", re.ASCII)
BROKER_PATH = re.compile(
    r"^/tmp/qazwire-m173a-p1\.[A-Za-z0-9]{8}/ipc/broker\.sock$")


def matches_argv(raw, path):
    source = Path(__file__).with_name("m173a_p1_broker.py").read_bytes().rstrip(b"\n")
    args = (
        b"/usr/bin/python3", b"-B", b"-u", b"-c", source,
        b"serve", b"--socket-path", path.encode("ascii"),
    )
    return raw == b"\0".join(args) + b"\0"


def send(namespace, path, pid):
    if os.geteuid() != 0:
        raise PermissionError("explicit sudo required")
    if not BROKER_NS.fullmatch(namespace) or not BROKER_PATH.fullmatch(path):
        raise ValueError("not an exact lab broker namespace/socket")
    if pid < 2 or pid == os.getpid():
        raise ValueError("invalid PID")
    host_ns = os.stat("/proc/self/ns/net").st_ino
    target_ns = (Path("/run/netns") / namespace).stat().st_ino
    if target_ns == host_ns:
        raise PermissionError("refusing host network namespace")

    pidfd = os.pidfd_open(pid, 0)
    try:
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            raise ProcessLookupError("broker already exited")
        if os.stat(f"/proc/{pid}/ns/net").st_ino != target_ns:
            raise PermissionError("broker not in this namespace")
        status = {}
        with open(f"/proc/{pid}/status", encoding="ascii") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    status[k] = v.strip()
        if [int(x) for x in status["Uid"].split()] != [65533] * 4:
            raise PermissionError("broker UID mismatch")
        if [int(x) for x in status["Gid"].split()] != [65534] * 4:
            raise PermissionError("broker GID mismatch")
        if any(int(status[k], 16) for k in ("CapEff", "CapBnd", "CapAmb")):
            raise PermissionError("broker has capabilities")
        if status["NoNewPrivs"] != "1":
            raise PermissionError("missing NoNewPrivs")
        if os.getsid(pid) != pid or os.getpgid(pid) != pid:
            raise PermissionError("not detached session leader")
        if not matches_argv(Path(f"/proc/{pid}/cmdline").read_bytes(), path):
            raise PermissionError("broker command identity mismatch")
        if not os.path.samefile(f"/proc/{pid}/exe", "/usr/bin/python3"):
            raise PermissionError("broker executable identity mismatch")
        if poller.poll(0):
            raise ProcessLookupError("broker already exited")
        signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
        print("M173A_P1_BROKER_PIDFD_SIGKILL_SENT", flush=True)
    finally:
        os.close(pidfd)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--namespace", required=True)
    p.add_argument("--socket-path", required=True)
    p.add_argument("--pid", type=int, required=True)
    args = p.parse_args()
    send(args.namespace, args.socket_path, args.pid)
