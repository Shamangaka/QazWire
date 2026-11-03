# QazWire M1.7.2b — kernel nftables A0 / isolated network-namespace laboratory

**Status: RESEARCH ONLY; implementation ≠ approval.** Stacked on Draft PR #22 @ `fc5476401f5e978e9a1b81974bbb54dc6c6a42e6`. No real Qalqan, VPN payload, secrets or production firewall is used. No merges into `master`.

## Objective and exact trust boundary

Demonstrate that ordinary **unprivileged direct UDP sockets**, including code that bypasses the M1.7.2a application-level gateway, cannot leave a new worker network namespace while its nftables OUTPUT base chain has `policy drop`. Unlike a Go gate, this packet decision is enforced by the Linux kernel for **traffic traversing this network namespace and hook**.

The test uses two unique named namespaces, a veth pair **created within the worker namespace** and moved to the second one, and no default routes, NAT, physical uplink or access to the host network. Benchmark-only addresses `198.18.27.1/30` and `198.18.27.2/30`. The two test interfaces, `qwa` and `qwb`, are never created in the host network namespace.

A root-run nft configuration operation is directed **only** through `ip netns exec <random-lab-worker-ns> nft ...`. There is no `nft flush ruleset`, no host nftables modification, no host routes/interfaces changed. New named namespaces themselves are visible under `/run/netns` until cleanup. Ubuntu's AppArmor user namespace restriction is not modified. The script explicitly asks the owner to authenticate with `sudo -v` before creating namespaces; it must be run as a non-root user.

## Mechanism

- Kernel policy file: `docs/qazwire/lab/m172b-netns-a0.nft`.
- Dedicated nft table: `inet qw_a0` inside **only** the worker lab network namespace.
- Both INPUT and OUTPUT have `policy drop`; IPv4/IPv6 egress is therefore blocked unless an explicit rule matches.
- Only an expiring set `allow_dst` containing `198.18.27.2` can permit UDP to `198.18.27.2:44000`. Permitted replies are scoped to source `198.18.27.2:44000`. A second echo server on `:44001` is the negative control even when the lease is active.
- The set element is inserted with `timeout 2s` and *not* refreshed by ordinary traffic. After the timeout, packets no longer match the permit. The application-level gate is **not called** by the direct UDP probe.
- The peer runs a temporary two-port UDP echo process in the **other** namespace. Direct client uses `setpriv --reuid ... --clear-groups` to drop root before creating its ordinary socket.
- A laboratory *privileged lease-renewer* can renew this element by atomic nft delete/add batches every 250 ms. Kill the actual renewer with `SIGKILL`, verify it belonged to the worker lab namespace, then measure post-death denial after waiting longer than the TTL.
- A newly launched direct client after the renewer crash must also be denied. The test additionally reports whether a **residual allowance immediately after SIGKILL** remains active.

## Expected host test sequence

1. Create only two unique network namespaces, load nft default-drop policy **before bringing up the veth pair**, start peer echo server.
2. Attempt direct UDP socket to port 44000 (DENY) and 44001 (DENY).
3. Insert 2-second permit; direct UDP to 44000 succeeds (echo received), port 44001 is still denied. This positive control demonstrates basic L3 reachability and the kernel rule's selective effect.
4. Wait >2 seconds without renewal; 44000 returns to DENY.
5. Insert permit; start separate renewal process; verify several direct UDP echoes across >2 seconds.
6. `SIGKILL` the actual renewal process; test immediately (outcome may vary depending on remaining time), then after 3 seconds verify 44000 DENY.
7. Launch a new direct socket client after the crash; still DENY. Delete only the newly created namespaces and their processes.

### Important limitation: watchdog death is NOT instantaneous fail-closed while permit is active

This is a deliberate adversarial finding, **not** a green production gate. If the renewer or watchdog dies while a valid 2-second nft lease exists, kernel rules can still accept matching packets until the lease expires. The test calls this `KNOWN-GAP`. Even a successful test provides only **bounded eventual fail-closed** (subject to actual set timeout semantics and tested scheduler conditions), not zero-packet egress immediately after watchdog SIGKILL.

Additionally, this test's lease-renewer has CAP_NET_ADMIN **inside the same network namespace as the worker**. A compromised privileged worker could rewrite or remove the firewall. The direct UDP probe drops privileges, but this does not prove a production transport or KLM lacks privilege-escalation paths. A real design must separate policy ownership from the untrusted worker, use a distinct identity and capabilities, establish kernel network fencing before worker start, and prove it cannot be bypassed by a worker with the powers in the threat model.

## Verification commands

First inspect the script and policy; execution requires sudo and creates temporary network namespaces:

```bash
bash -n scripts/qazwire-m172b-kernel-a0-netns-lab.sh
python3 -m py_compile scripts/m172b_netns_probe.py scripts/m172b_static_tests.py
python3 scripts/m172b_static_tests.py
# Only after confirming exact branch SHA, deliberately run the privileged host lab:
bash scripts/qazwire-m172b-kernel-a0-netns-lab.sh
```

**Expected outcome, when run on the owner's Ubuntu (not yet demonstrated):**

```text
DENIED port=44000: NO_ECHO ...
DENIED port=44001: NO_ECHO ...
ECHO port=44000
DENIED port=44001: NO_ECHO ...
DENIED port=44000: NO_ECHO ...
SIGKILL issued to synthetic lease renewer ...
DENIED port=44000: NO_ECHO ...
M1.7.2b LAB PASS: kernel nft default-deny, scoped lease, direct-socket enforcement and expiry after renewer SIGKILL
SECURITY LIMIT: active lease may survive SIGKILL up to its TTL. Immediate A0 on watchdog crash NOT PROVEN.
```

The lease renewal process has a 30-second maximum life and the echo server has a 40-second maximum. Cleanup traps stop only processes associated with the two randomly named namespaces, then remove those namespaces. This is a privileged, *locally executed lab script*; it must not be scheduled without explicit owner choice.

## Test coverage and remaining gates

| Requirement | Current status |
| --- | --- |
| Linux network namespace creation | PENDING owner Ubuntu run |
| Kernel nftables default DROP for lab worker egress | PENDING owner Ubuntu run |
| Positive constrained UDP echo to authorized port | PENDING owner Ubuntu run |
| Direct socket bypass of M1.7.2a gate stays denied | PENDING owner Ubuntu run |
| Explicit 2s lease expires without renewal | PENDING owner Ubuntu run |
| Lab lease-renewer SIGKILL → eventual DENY | PENDING owner Ubuntu run |
| Instant DENY upon watchdog SIGKILL while lease active | **NOT IMPLEMENTED / EXPECTED GAP** |
| Watchdog and policy control immune to compromised KLM | **NOT IMPLEMENTED** |
| Real KLM service bound to kernel fence | **NOT IMPLEMENTED** |
| nftables rollback/crash/host reboot/inherited FD review | **NOT IMPLEMENTED** |
| Qalqan and real keys | **NO-GO** |

CI must lint Bash/Python and run offline tests plus complete upstream tagged/untagged Go regression. CI itself does **not** execute `sudo ip netns` nor install nftables rules; the owner's real Ubuntu trial must be separately evidenced with exact SHA. No result from static CI may be described as a kernel-security PASS.

## Sources to check during independent audit

- Linux netfilter nftables [element timeouts](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts), including set element expiration and refresh semantics.
- nftables [sets documentation](https://wiki.nftables.org/wiki-nftables/index.php/Sets).
- nftables [official manual](https://netfilter.org/projects/nftables/manpage.html).
- `ip-netns(8)` for namespace lifecycle and scoped exec.

**Disposition:** At most a kernel-enforced *lab* A0 for a single network namespace when the owner's Ubuntu checks pass. M1.7.2 production-grade independent watchdog isolation remains **NO-GO** until true control-plane separation, immediate A0 semantics and restart/rollback guarantees have independent evidence. R5-02 and R5-E1 remain OPEN; G-Q1/G-Q2 BLOCKED; actual Qalqan and M2 NO-GO. Do not merge without explicit authorization.
