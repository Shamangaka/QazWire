#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline UDP echo for M1.7.3a P1; use only in a new synthetic peer netns."""
import argparse
from pathlib import Path
import select
import socket
import time

PEER = "198.18.27.2"
PORTS = (44000, 44001)
MAGIC = b"QAZWIRE-M173A-P1:"


def serve(pidfile):
    socks = []
    try:
        for port in PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((PEER, port))
            socks.append(s)
        with Path(pidfile).open("x", encoding="ascii") as f:
            f.write(str(__import__("os").getpid()) + "\n")
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            readable, _, _ = select.select(socks, [], [], 0.2)
            for s in readable:
                data, addr = s.recvfrom(128)
                if (len(data) == len(MAGIC) + 16
                        and data.startswith(MAGIC)):
                    s.sendto(data, addr)
    finally:
        for s in socks:
            s.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--pidfile", required=True)
    args = p.parse_args()
    serve(args.pidfile)
