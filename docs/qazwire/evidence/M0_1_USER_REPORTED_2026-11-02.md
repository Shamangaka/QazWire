# QazWire M0.1 — userspace to kernel interoperability (operator report)

**Test date (UTC):** 2026-11-02.  
**Evidence status:** USER-REPORTED log from local Ubuntu host; passed assertions are checked against the committed test harness, but the test was **not independently executed by the reviewer**.  
**Protocol:** standard WireGuard protocol; **Qalqan NOT used**.  
**Test script:** `scripts/qazwire-kernel-interop-m0.sh` (in the branch and reviewable).  
**Git checkout:** `experimental/qalqan-transport-v0.1`, `5e07792adee6f619d5f89a5644efafb51c7d6f86` (command output from user).  
**Binary SHA-256:** `e47647d7447d1ee57f63d63e0bcd276040c64d5d8262056dcabb551bca24c599`.  
**Go version:** `go1.27.3 linux/amd64`.  
**Kernel:** `7.0.0-38-generic`.  
**Test start UTC:** `2026-11-02T07:08:58Z`.  
**Source-to-binary verification:** SHA-256 recorded; independent reproducible-build verification not performed. No private keys or packet captures committed.

## Reported results

| Evidence | Operator-observed value | Status |
| --- | --- | --- |
| `go test ./...` | All test packages passed; many results cached | PASS (reported) |
| `go vet ./...` | Exit 0 after atomic-value formatting fix | PASS (reported) |
| `go build -o .qazwire-lab/wireguard-go .` | Exit 0 | PASS (reported) |
| Kernel WireGuard interface creation | Step 1 succeeded | PASS (reported) |
| Userspace QazWire peer startup | Step 2 succeeded | PASS (reported) |
| Userspace → kernel ICMP | 5 sent, 5 received, 0% loss, avg RTT 0.952 ms | PASS (reported) |
| Kernel → userspace ICMP | 3 sent, 3 received, 0% loss, avg RTT 0.552 ms | PASS (reported) |
| Handshake and bidirectional transfer assertions | PASS on both temporary namespaces | PASS (reported) |
| `go test -race ./...` | Not supplied | NOT TESTED |
| Uncached `go test -count=1 ./...` | Not supplied | NOT TESTED |
| Malicious replay and packet mutation | Not performed | NOT TESTED |
| Sustained throughput and timed rekey | Not performed | NOT TESTED |
| Qalqan and ST RK conformity | Not implemented; no conformity assessment | NOT TESTED |

## Interpretation

This is **protocol interoperability** with a separate in-kernel WireGuard implementation, not independent validation of cryptographic security. A few same-host ICMP messages cannot benchmark production latency or loss. The `sudo` password was retried once before successful launch; it is unrelated to the test result.

The test does not establish any special cryptographic, legal or compliance properties of QazWire. The original WireGuard algorithm suite is unchanged. Future experiments must be isolated behind a distinct protocol identity with fail-closed rejection of standard WireGuard peers.

## Suggested next checks

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

Capture only test summaries and immutable build metadata, not private key contents or full local configuration.
