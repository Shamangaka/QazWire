# QazWire M1.7.2c — unprivileged-worker/kernel-A0 separation laboratory

**Classification: RESEARCH-ONLY design + implementation; not a production security boundary.**
Stacked on Draft PR #23 at `7b23297ed0737f4d5147d69cd9173fb3aef3e5e1`.
No Qalqan, actual VPN dataplane, actual keys, production interfaces, packet forwarding, Internet connectivity, secrets, cryptographic standards claims, or merge to `master`.

## Why this experiment exists

M1.7.2b owner Ubuntu test demonstrated real nftables default DROP in a new network namespace, selective UDP delivery, expiry, and a **confirmed** outbound UDP echo immediately after killing the synthetic lease-renewer: an existing nft set element remains permissive for its residual TTL. This is **not** instantaneous watchdog-death fail-closed.

M1.7.2c investigates a distinct question: **Can the untrusted worker be deprived of authority to change the kernel policy while the trusted operator can explicitly grant/revoke narrowly scoped traffic?**

This code does **not** solve watchdog-death revocation. A privileged one-shot command is not equivalent to a protected independent policy controller, and an nft grant is not automatically bound to the creator's lifetime.

## Exact topology and privilege domains

```text
host init network namespace, owner/operator (sudo)
  |
  | explicitly authorized, short-lived: ip netns exec <worker_ns> nft ...
  | no resident CAP_NET_ADMIN controller inside worker ns
  v
kernel nft table inet qw_privsep_a0 inside UNIQUE new worker netns
 OUTPUT policy drop; INPUT policy drop
 expiring grant: 198.18.27.2 UDP/44000 for 8s
  ^
  | ordinary Python UDP socket (NOT the M1.7.2a soft gate)
  |
untrusted test client in same worker netns:
  UID=65534, GID=65534, zero supplementary groups
  CapEff=0, CapBnd=0, CapAmb=0, NoNewPrivs=1
  inherits kernel policy; cannot edit nft set
  |
  +-- veth qwcw --- q w c p -- peer ns 198.18.27.2
                                  local UDP echo 44000/44001
```

The veth pair is **created only inside worker_ns**, then the peer end is moved to a second **unique** new network namespace. There is no host veth or default route and no host nftables calls. No user namespace is required, and Ubuntu's AppArmor unprivileged-userns policy is unchanged. This integration script intentionally calls `sudo -v` and must never run in unattended CI. It creates two new named namespaces and changes nftables only in the newly created worker namespace.

The setpriv `--reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs --reset-env` arguments are validated from the target process's `/proc/self/status`. The target UID is not the owner's regular UID, unlike M1.7.2b.

**Critical remaining gaps:** network namespaces do NOT isolate the filesystem, `/proc`, process metadata, IPC or storage in general. UID 65534 is a shared host identity, not an assigned private service UID. Existing host services might already run as UID 65534. No dedicated mount/PID/IPC namespaces, read-only filesystem, seccomp, AppArmor profile, restricted devices, or physical-memory protections are configured. This experiment makes no claim of secrecy against compromised host root, same-UID processes or shared devices.

## Implemented host-run checks

1. **Safe scope** — generate random `qwca<8hex>` and `qwcb<8hex>` netns names, refuse collisions; install the nft policy **before** raising veth interfaces; no physical uplink, default route, or host firewall write.
2. **Privilege drop** — execute client under UID/GID 65534 with all inherited/ambient/bounding capabilities removed, supplementary groups empty, NoNewPrivs=1. Fail closed if any process-status property differs.
3. **Unauthorized nft mutation** — run `nft add element` through the untrusted process. It **must fail**. Verify the set remains empty.
4. **Direct UDP kernel default-deny** — ordinary untrusted socket to 44000 DENY and 44001 DENY, with no application-level gate.
5. **Trusted explicit grant** — privileged host operator runs scoped nft `add element` to worker netns only; direct UDP to `198.18.27.2:44000` receives echo, 44001 stays denied.
6. **Trusted explicit revocation while grant active** — privileged operator invokes scoped nft `delete element`. A fresh unprivileged direct socket must be denied after the transaction. A second separately executed client must also be denied. This does **not** prove whether a packet already classified/queued before the nft commit can be unsent.
7. **Residual permit after administrative command exit** — privileged one-shot nft process exits while an 8-second grant remains. UDP is still allowed until the permit is revoked/expired. After >8 seconds with no renewer, access must be denied. This independently illustrates why a one-shot controller does not solve watchdog-crash behavior.
8. **Strict cleanup** — reuse the M1.7.2b Linux pidfd-based namespace task termination; verify namespace task lists empty before deleting both names; cleanup failure produces nonzero status. This protects the **new, uniquely named** namespaces only and does not touch existing host network state.

## Reproduction (manual owner approval required)

Read the script and exact SHA. The owner must explicitly approve `sudo` use:

```bash
bash -n scripts/qazwire-m172c-privsep-kernel-a0-lab.sh
python3 scripts/m172c_static_tests.py
bash scripts/qazwire-m172c-privsep-kernel-a0-lab.sh
```

Expected assertions include:

```text
WORKER_UID=65534 GROUPS=[] CapEff=0000000000000000 CapBnd=0000000000000000 CapAmb=0000000000000000 NoNewPrivs=1
UNPRIVILEGED_NFT_MUTATION_DENIED
DENIED port=44000 ...
ECHO port=44000 ...
EXPLICIT_REVOKE_PASS: direct UDP rejected after trusted nft delete
FRESH_WORKER_DENIED
CONFIRMED_LIMIT: kernel permit survives administrative CLI exit until revoked/expired
TTL_EXPIRY_PASS
M1.7.2c LAB PASS: distinct UID no capabilities, unauthorized nft mutation denied, kernel direct UDP A0 and explicit revocation
M1.7.2c CLEANUP PASS
```

These are **expected patterns only**, not observed Ubuntu results. CI must lint/test offline and run full QazWire regressions but must not run sudo/netns/nft. Exact SHA and user-host logs are required before marking LAB VERIFIED.

## What is STILL required for production M1.7.2 (NOT implemented)

- Protected **persistent** policy owner / monitor in its own service UID, cgroup and security policy (not the owner's interactive sudo CLI), separate from the transport and KLM process.
- Safe service-manager lifecycle: initial default DENY before worker creation, PID/cgroup/session identity verification, no packet escape during prepare/arm/restart, deny on controller failure, controlled rollback and offline host reboot/hibernation.
- Failure semantics and security objective: if *immediate* zero-new-packet egress on watchdog SIGKILL is required, an nft element with expiry alone fundamentally does not meet it. Need a kernel mechanism directly bound to monitored state, or an independently live packet mediator that defaults to deny when it dies. Any solution requires packet-race/failure-mode testing and residual in-flight definition. **Even explicit nft delete cannot retract packets already classified or emitted.**
- Actual network isolation covers **every** socket/path of the real worker, no extra network namespace, cap escalation, inherited privileged FD, raw socket, AF_PACKET bypass, or privilege transfer.
- Strong key owner R5-02 and restart key/nonce identities R5-E1; Qalqan mechanism review G-Q1 and regulator G-Q2. None of these are addressed by network policy alone.

**Decision:** M1.7.2c is a privilege-separation laboratory, not a production fail-closed guarantee. Until independently proven, overall M1.7.2 and M2 remain NO-GO. No merge to `master` without separate owner authorization.

## Primary references for independent audit

- Linux `setpriv(1)`: capability set bounding, no-new-privileges, supplementary groups.
- nftables manpage: atomic rule transactions and nft set add/delete elements.
- nftables wiki: element timeout semantics (expiry independent of process lifetime).
- Linux `ip-netns(8)` and cgroup v2: namespace/cgroup identity and failure behavior.
