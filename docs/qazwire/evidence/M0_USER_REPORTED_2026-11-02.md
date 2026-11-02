# QazWire M0 — reported baseline observation, 2026-11-02

**Evidence source:** console output supplied by the project operator after running `sudo bash scripts/qazwire-netns-lab.sh "$PWD/.qazwire-lab/wireguard-go"`.  
**Evidence status:** USER-REPORTED; reviewed against expected harness output but **not independently reproduced**.
**Exact local commit of compiled binary:** NOT CAPTURED by this log. Do not infer a specific commit SHA for this binary without `git rev-parse HEAD` and a reproducible build digest.
**Protocol:** original WireGuard as implemented by the QazWire fork. **Qalqan was not involved.**

## Reported environment

- OS: Linux; kernel: `7.0.0-38-generic`
- Timestamp (script): `2026-11-02T06:42:56Z`
- Harness: `scripts/qazwire-netns-lab.sh`, 2 temporary namespaces
- Userspace binary: `/home/nurzhan/Документы/QazWire/.qazwire-lab/wireguard-go` (local path, not an artifact or immutable fingerprint)

## Reported results

| Check | Observation | Assessment |
| --- | --- | --- |
| Underlay 192.0.2.1 → 192.0.2.2 | 2/2 ICMP, 0% loss, avg RTT 0.040 ms | PASS (reported) |
| WG tunnel 10.77.0.1 → 10.77.0.2 | 5/5 ICMP, 0% loss, avg RTT 0.844 ms | PASS (reported) |
| WG tunnel 10.77.0.2 → 10.77.0.1 | 3/3 ICMP, 0% loss, avg RTT 0.527 ms | PASS (reported) |
| Handshake (both peers) | Harness printed PASS for both | PASS (reported) |
| Receive/transmit counters | Harness printed PASS for both | PASS (reported) |
| Qalqan authenticated encryption | Not used | NOT TESTED |
| Userspace-to-kernel implementation interop | Not performed | NOT TESTED |
| Rekey / malicious replay rejection | Not performed | NOT TESTED |
| Formal cryptographic or regulatory validation | Not performed | NOT TESTED |

## Scope and cautions

This is a minimal synthetic same-host smoke test, not a network performance benchmark or proof of data confidentiality. Small ICMP counts cannot characterize packet loss, latency distribution or production throughput. The harness checks WireGuard UAPI handshakes and traffic counters but does not provide an independent cryptographic proof.

For the next run, retain a hash of the binary, commit ID, Go toolchain version, exact command and complete console output, with no private keys or personally sensitive traffic.
