# QazWire M0.1 — userspace ↔ kernel WireGuard compatibility test

**STATUS:** Script committed, **NOT EXECUTED** on the user's Ubuntu host at the time of commit.

## Purpose

After M0 confirms two userspace peers exchange packets, independently verify **protocol compatibility** against the Linux kernel WireGuard implementation. This is a reproducible regression test, not a Qalqan or security compliance assessment.

## Preconditions

- Linux with kernel WireGuard support, `iproute2`, `wireguard-tools`, `iputils-ping` and `/dev/net/tun`.
- Capability to create Linux network namespaces and WireGuard interfaces.
- `wireguard-go` binary built from this experimental branch **as a non-root user**, then reviewed before invoking with sudo.

## Usage

```bash
cd ~/Документы/QazWire
git switch experimental/qalqan-transport-v0.1
git pull --ff-only
bash scripts/qazwire-baseline.sh
mkdir -p .qazwire-lab
go build -o .qazwire-lab/wireguard-go .

set -o pipefail
sudo bash scripts/qazwire-kernel-interop-m0.sh "$PWD/.qazwire-lab/wireguard-go" \
  2>&1 | tee kernel-interop-m0.log
```

The script creates two temporary network namespaces and a veth link, builds no binaries, generates and deletes temporary test keys, launches userspace WireGuard in one namespace, and creates an independent **in-kernel WireGuard** peer in the other. It tests bidirectional ICMP, nonzero handshake timestamps and nonzero receive/transmit counters. No host network routes, NAT, DNS or firewall changes are requested. Cleanup runs on success/failure.

**Stop conditions:** if the Linux kernel has no WireGuard support, the test is `BLOCKED`. Do not modify host firewall, kernel security settings, VPN routing or production credentials to make it pass.

## Interpretation

- PASS means protocol-level Linux kernel interoperability under local synthetic traffic.
- It does not establish throughput, robustness, key lifecycle/rekey, anti-replay, AEAD safety, or compliance with ST RK 1073-2025.
- M0.1 does not modify the cryptographic code. Qalqan is not implemented or used.
