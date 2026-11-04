#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic unprivileged worker for the isolated M1.7.2d network lab.

No cryptographic keys or VPN transport. The worker must never use sudo or
nftables. It runs under UID 65534 with Linux capabilities fully dropped.
"""
import os
import time


def main():
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
    print("WORKER_READY_PID=" + str(os.getpid()), flush=True)
    while True:
        time.sleep(0.05)


if __name__ == "__main__":
    main()
