#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QazWire M1.7.2b: NO-SECRETS UDP echo/probe and expiring nft lease renewal.

Run only inside uniquely created offline lab network namespaces. Never
configure host network interfaces or host nftables from this helper.
"""
import argparse
import ipaddress
import os
import select
import socket
import subprocess
import sys
import time

PEER = "198.18.27.2"
WORKER = "198.18.27.1"
PORTS = (44000, 44001)
POLICY_TABLE = "qw_a0"
LEASE_SECONDS = 2
MAGIC = b"QAZWIRE-M172B-PROBE:"


def safe_pidfile(path):
    if not os.path.isabs(path):
        raise ValueError("PID file must be absolute")
    with open(path, "x", encoding="ascii") as f:
        f.write(str(os.getpid()) + "\n")


def serve(pidfile):
    """Two responding UDP ports; only 44000 may ever be permitted."""
    socks = []
    try:
        for port in PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((PEER, port))
            socks.append(s)
        safe_pidfile(pidfile)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            ready, _, _ = select.select(socks, [], [], 0.2)
            for s in ready:
                packet, addr = s.recvfrom(512)
                if packet.startswith(MAGIC) and len(packet) <= 160:
                    s.sendto(packet, addr)
        return 0
    finally:
        for s in socks:
            s.close()


def probe(port, timeout):
    nonce = os.urandom(8).hex().encode("ascii")
    packet = MAGIC + nonce
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((WORKER, 0))
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (PEER, port))
            data, addr = sock.recvfrom(512)
        except (TimeoutError, OSError) as e:
            print(f"NO_ECHO port={port} cause={type(e).__name__}", flush=True)
            return False
        ok = (data == packet and addr == (PEER, port))
        print(f"{'ECHO' if ok else 'MISMATCH'} port={port}", flush=True)
        return ok


def refresh(pidfile, nft_path, period):
    """LAB ONLY: simulates a privileged lease renewer in the worker netns.

    A successful batch deletes and re-adds the *existing* lease atomically.
    This process needs CAP_NET_ADMIN. Production must NOT put CAP_NET_ADMIN
    in the same trust boundary as untrusted transport/KLM code.
    """
    if os.path.basename(nft_path) != "nft":
        raise ValueError("explicit nft binary required")
    batch = (
        "delete element inet qw_a0 allow_dst { 198.18.27.2 }\n"
        "add element inet qw_a0 allow_dst { 198.18.27.2 timeout 2s }\n"
    )
    deadline = time.monotonic() + 30
    first = True
    while time.monotonic() < deadline:
        run = subprocess.run(
            [nft_path, "-f", "-"], input=batch, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if run.returncode:
            print("RENEW_FAILED " + run.stderr.strip(), file=sys.stderr, flush=True)
            return 1
        if first:
            safe_pidfile(pidfile)
            first = False
        time.sleep(period)
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--pidfile", required=True)
    q = sub.add_parser("probe")
    q.add_argument("--port", type=int, choices=PORTS, required=True)
    q.add_argument("--timeout", type=float, default=0.45)
    r = sub.add_parser("refresh")
    r.add_argument("--pidfile", required=True)
    r.add_argument("--nft", required=True)
    r.add_argument("--period", type=float, default=0.25)
    args = p.parse_args()
    if args.mode == "serve":
        return serve(args.pidfile)
    if args.mode == "probe":
        if not 0.05 <= args.timeout <= 2:
            p.error("timeout must be between 0.05 and 2")
        return 0 if probe(args.port, args.timeout) else 1
    if not 0.1 <= args.period <= 0.5:
        p.error("renewal period must be between 0.1 and 0.5")
    return refresh(args.pidfile, args.nft, args.period)


if __name__ == "__main__":
    raise SystemExit(main())
