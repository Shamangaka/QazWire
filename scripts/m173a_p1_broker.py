#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1.7.3a P1 offline 3-netns broker lab. NOT VPN, security audit, or production."""
import argparse
import errno
import os
from pathlib import Path
import re
import socket
import stat
import struct

BROKER_UID = 65533
BROKER_GID = 65534
WORKER_UID = 65534
WORKER_GID = 65534
REMOTE = ("198.18.27.2", 44000)
LOCAL = "198.18.27.1"
PREFIX = b"QAZWIRE-M173A-P1:"
TIMEOUT = 0.75
SOCKET_RE = re.compile(r"^/tmp/qazwire-m173a-p1\.[A-Za-z0-9]{8}/ipc/broker\.sock$")
PORTS = (44000, 44001)


def checked_path(path):
    if not SOCKET_RE.fullmatch(path):
        raise ValueError("socket path outside the exact synthetic lab")
    return Path(path)


def verify_identity(uid, gid):
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (
        uid, uid, gid, gid
    ):
        raise PermissionError("unexpected effective/real UID or GID")
    if os.getgroups():
        raise PermissionError("supplementary groups are not allowed")
    with open("/proc/self/status", encoding="ascii") as stream:
        status = dict(line.split(":", 1) for line in stream if ":" in line)
    if any(int(status[x].strip(), 16) for x in ("CapEff", "CapBnd", "CapAmb")):
        raise PermissionError("capabilities must be zero")
    if status["NoNewPrivs"].strip() != "1":
        raise PermissionError("NoNewPrivs must be set")


def close_stdio():
    fd = os.open(os.devnull, os.O_RDWR)
    try:
        for n in (0, 1, 2):
            os.dup2(fd, n)
    finally:
        if fd > 2:
            os.close(fd)


def serve(path):
    checked_path(path)
    verify_identity(BROKER_UID, BROKER_GID)

    directory = Path(path).parent
    metadata = directory.lstat()
    if (not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != BROKER_UID
            or metadata.st_gid != BROKER_GID
            or stat.S_IMODE(metadata.st_mode) != 0o710):
        raise PermissionError("unsafe IPC directory ownership or mode")
    if Path(path).exists() or Path(path).is_symlink():
        raise FileExistsError("IPC socket already exists")

    child = os.fork()
    if child:
        return 0
    os.setsid()
    verify_identity(BROKER_UID, BROKER_GID)
    if os.getsid(0) != os.getpid() or os.getpgid(0) != os.getpid():
        raise PermissionError("not a detached broker session leader")

    # filesystem-path AF_UNIX, not abstract socket (abstract is netns-scoped).
    old_umask = os.umask(0o117)
    try:
        unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix.bind(path)
    finally:
        os.umask(old_umask)
    sockst = Path(path).lstat()
    if (not stat.S_ISSOCK(sockst.st_mode)
            or sockst.st_uid != BROKER_UID or sockst.st_gid != BROKER_GID
            or stat.S_IMODE(sockst.st_mode) != 0o660):
        raise PermissionError("unsafe IPC socket mode")
    unix.listen(8)
    unix.settimeout(0.5)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((LOCAL, 0))
    udp.settimeout(TIMEOUT)

    print(f"P1_BROKER_READY_PID={os.getpid()}", flush=True)
    close_stdio()

    while True:
        try:
            conn, _ = unix.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(TIMEOUT)
            try:
                pid, uid, gid = struct.unpack(
                    "3i", conn.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED,
                        struct.calcsize("3i")))
                if (pid < 2 or uid != WORKER_UID or gid != WORKER_GID):
                    conn.sendall(b"DENY:PEERCRED")
                    continue
                payload = conn.recv(128)
                if (len(payload) != len(PREFIX) + 16
                        or not payload.startswith(PREFIX)
                        or not re.fullmatch(rb"[0-9a-f]{16}", payload[len(PREFIX):])):
                    conn.sendall(b"DENY:FORMAT")
                    continue
                udp.sendto(payload, REMOTE)
                response, addr = udp.recvfrom(128)
                if addr != REMOTE or response != payload:
                    conn.sendall(b"DENY:RESPONSE")
                    continue
                conn.sendall(b"OK:" + payload)
            except (OSError, socket.timeout):
                continue


def direct(uid, gid, port):
    verify_identity(uid, gid)
    if port not in PORTS:
        raise ValueError("invalid port")
    # Worker namespace has ONLY lo; no underlay, no route, no IPv4 source bind.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.sendto(PREFIX + b"direct_test_0000", (REMOTE[0], port))
            s.recvfrom(128)
        except OSError as exc:
            if exc.errno == errno.ENETUNREACH:
                print(f"P1_DIRECT_NO_ROUTE uid={uid} port={port}", flush=True)
                return 12
            print(f"P1_DIRECT_INCONCLUSIVE errno={exc.errno}", flush=True)
            return 13
    print(f"P1_DIRECT_UNEXPECTED_NETWORK uid={uid} port={port}", flush=True)
    return 14


def relay(path, uid, gid, broker_pid):
    checked_path(path)
    verify_identity(uid, gid)
    payload = PREFIX + os.urandom(8).hex().encode("ascii")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(TIMEOUT)
        try:
            conn.connect(path)
            pid, remote_uid, remote_gid = struct.unpack(
                "3i", conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED,
                    struct.calcsize("3i")))
            if (pid != broker_pid or remote_uid != BROKER_UID
                    or remote_gid != BROKER_GID):
                print("P1_IPC_BROKER_IDENTITY_MISMATCH", flush=True)
                return 15
            conn.sendall(payload)
            result = conn.recv(128)
        except PermissionError:
            print("P1_IPC_PATH_DENIED", flush=True)
            return 14
        except (ConnectionRefusedError, FileNotFoundError):
            print("P1_IPC_UNAVAILABLE", flush=True)
            return 12
        except OSError as exc:
            print(f"P1_IPC_INCONCLUSIVE errno={exc.errno}", flush=True)
            return 13
    if uid != WORKER_UID:
        if result == b"DENY:PEERCRED":
            print("P1_IPC_UNAUTHORIZED_PEER_DENIED", flush=True)
            return 14
        print("P1_IPC_UNAUTHORIZED_UNEXPECTED_REPLY", flush=True)
        return 15
    if result == b"OK:" + payload:
        print("P1_CROSS_NETNS_RELAY_ECHO_OK", flush=True)
        return 0
    print("P1_IPC_RESPONSE_UNEXPECTED", flush=True)
    return 15


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("serve")
    a.add_argument("--socket-path", required=True)
    b = sub.add_parser("direct")
    b.add_argument("--uid", type=int, choices=(65533, 65534), required=True)
    b.add_argument("--gid", type=int, choices=(65533, 65534), required=True)
    b.add_argument("--port", type=int, choices=PORTS, required=True)
    c = sub.add_parser("relay")
    c.add_argument("--socket-path", required=True)
    c.add_argument("--uid", type=int, choices=(65532, 65534), required=True)
    c.add_argument("--gid", type=int, choices=(65532, 65534), required=True)
    c.add_argument("--broker-pid", type=int, required=True)
    args = p.parse_args()
    if args.mode == "serve":
        return serve(args.socket_path)
    if args.mode == "direct":
        return direct(args.uid, args.gid, args.port)
    return relay(args.socket_path, args.uid, args.gid, args.broker_pid)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, PermissionError) as exc:
        print(f"P1_BROKER_FAIL:{type(exc).__name__}:{exc}", flush=True)
        raise SystemExit(99)
