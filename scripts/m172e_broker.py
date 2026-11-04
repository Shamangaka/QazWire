#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1.7.2e offline synthetic broker. NOT VPN, encryption, or a secure daemon.

The test broker's UDP socket belongs to UID 65533. nftables allows only this
socket-owner UID to reach 198.18.27.2:44000 inside a new isolated lab netns.
An unprivileged UID65534 worker NEVER has a direct packet permit.
The broker receives small fixed-format messages over an abstract AF_UNIX stream
socket, authenticates SO_PEERCRED UID65534, and never shares its UDP socket FD.
"""
import argparse
import os
import re
import socket
import struct
import sys
import time

BROKER_UID = 65533
WORKER_UID = 65534
LOCAL = "198.18.27.1"
REMOTE = ("198.18.27.2", 44000)
SOCKET_PREFIX = "\0qw_m172e_"
PORTS = (44000, 44001)
NONCE = re.compile(r"^[0-9a-f]{8}$", re.ASCII)
MAX_MESSAGE = 56
PREFIX = b"QWM172E:"
TIMEOUT = 0.65


def address(nonce):
    if not NONCE.fullmatch(nonce):
        raise ValueError("invalid synthetic IPC namespace nonce")
    return SOCKET_PREFIX + nonce


def verify_uid(uid):
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (
        uid, uid, uid, uid
    ):
        raise PermissionError("unexpected broker/worker user or group")
    if os.getgroups():
        raise PermissionError("unexpected supplementary group")
    with open("/proc/self/status", encoding="ascii") as stream:
        status = dict(
            line.split(":", 1) for line in stream if ":" in line
        )
    if any(int(status[x].strip(), 16) for x in ("CapEff", "CapBnd", "CapAmb")):
        raise PermissionError("Linux capabilities must all be zero")
    if status["NoNewPrivs"].strip() != "1":
        raise PermissionError("NoNewPrivs must be 1")


def close_stdio():
    # Do not retain sudo's TTY or an inherited stdio descriptor after
    # detached child reports readiness.
    fd = os.open(os.devnull, os.O_RDWR)
    try:
        for n in (0, 1, 2):
            os.dup2(fd, n)
    finally:
        if fd > 2:
            os.close(fd)


def serve(nonce):
    verify_uid(BROKER_UID)
    child = os.fork()
    if child:
        return 0  # Parent monitored by sudo must exit before broker SIGKILL.
    os.setsid()
    verify_uid(BROKER_UID)
    if os.getsid(0) != os.getpid() or os.getpgid(0) != os.getpid():
        raise PermissionError("broker not detached from sudo job control")

    # AF_UNIX abstract namespace is scoped to a Linux network namespace.
    unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix_sock.bind(address(nonce))
    unix_sock.listen(6)
    unix_sock.settimeout(0.5)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((LOCAL, 0))
    udp_sock.settimeout(TIMEOUT)

    print(f"BROKER_READY_PID={os.getpid()}", flush=True)
    close_stdio()
    while True:
        try:
            conn, _ = unix_sock.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(TIMEOUT)
            try:
                pid, uid, gid = struct.unpack(
                    "3i", conn.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED,
                        struct.calcsize("3i"),
                    ),
                )
                if uid != WORKER_UID or gid != WORKER_UID or pid < 2:
                    conn.sendall(b"DENY:PEERCRED")
                    continue
                payload = conn.recv(MAX_MESSAGE + 1)
                if not (len(PREFIX) + 1 <= len(payload) <= MAX_MESSAGE
                        and payload.startswith(PREFIX)):
                    conn.sendall(b"DENY:FORMAT")
                    continue
                udp_sock.sendto(payload, REMOTE)
                response, peer = udp_sock.recvfrom(512)
                if peer != REMOTE or response != payload:
                    conn.sendall(b"DENY:BAD_ECHO")
                    continue
                conn.sendall(b"OK:" + response)
            except (OSError, socket.timeout):
                # This is a synthetic lab that must not relay arbitrary
                # destinations or expose any file descriptors to the client.
                continue


def send_direct(port):
    verify_uid(WORKER_UID)
    if port not in PORTS:
        raise ValueError("unapproved synthetic port")
    payload = PREFIX + os.urandom(8).hex().encode("ascii")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((LOCAL, 0))
        s.settimeout(TIMEOUT)
        try:
            s.sendto(payload, (REMOTE[0], port))
            result, addr = s.recvfrom(512)
        except PermissionError as exc:
            # Only an explicit kernel permission refusal counts as nft DENY.
            print(f"DIRECT_DENIED port={port} cause={type(exc).__name__}",
                  flush=True)
            return 12
        except OSError as exc:
            print(f"DIRECT_INCONCLUSIVE port={port} cause={type(exc).__name__}",
                  flush=True)
            return 13
    if addr == (REMOTE[0], port) and result == payload:
        print(f"DIRECT_ECHO port={port}", flush=True)
        return 0
    print("DIRECT_INVALID_ECHO", flush=True)
    return 13


def request(nonce, *, expected_uid=WORKER_UID):
    verify_uid(expected_uid)
    payload = PREFIX + os.urandom(8).hex().encode("ascii")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.connect(address(nonce))
            s.sendall(payload)
            response = s.recv(256)
        except (ConnectionRefusedError, FileNotFoundError) as exc:
            print(f"IPC_UNAVAILABLE cause={type(exc).__name__}",
                  flush=True)
            return 12
        except OSError as exc:
            print(f"IPC_INCONCLUSIVE cause={type(exc).__name__}",
                  flush=True)
            return 13
    if expected_uid != WORKER_UID:
        if response == b"DENY:PEERCRED":
            print("IPC_UNAUTHORIZED_PEER_DENIED", flush=True)
            return 14
        print("IPC_UNAUTHORIZED_PEER_UNEXPECTED_REPLY", flush=True)
        return 15
    if response == b"OK:" + payload:
        print("BROKER_RELAY_ECHO_OK", flush=True)
        return 0
    print("IPC_RESPONSE_DENIED_OR_MISMATCH", flush=True)
    return 13


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("serve")
    p.add_argument("--nonce", required=True)
    p = sub.add_parser("direct")
    p.add_argument("--port", type=int, choices=PORTS, required=True)
    p = sub.add_parser("relay")
    p.add_argument("--nonce", required=True)
    p.add_argument("--unauthorized", action="store_true")
    args = parser.parse_args()
    if args.mode == "serve":
        return serve(args.nonce)
    if args.mode == "direct":
        return send_direct(args.port)
    return request(args.nonce, expected_uid=65532 if args.unauthorized else WORKER_UID)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, PermissionError) as exc:
        print(f"BROKER_LAB_FAIL:{type(exc).__name__}:{exc}", flush=True)
        raise SystemExit(99)
