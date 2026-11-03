# QazWire M1.7.2a — independent process watchdog / synthetic A0 gate

**Status:** SYNTHETIC / RESEARCH ONLY. This is **not** M1.7.2 production containment, actual kernel-enforced egress isolation, cryptography, secure key erasure or an approval to integrate Qalqan. It is stacked on Draft PR #21 @ `7ce111c55f25213e8b386048b507b992ac2b7bd5`.

## Threat model and scope

The user's Ubuntu 24.04 (systemd 255, cgroup v2) has **already verified** termination of two known process identities by cgroup.kill: parent and an independent setsid descendant, with either populated=0 or exact unit deletion plus both pidfds exited. M1.7.2a extends the laboratory by running a **separate watchdog service** in a different cgroup, with a synthetic local Unix IPC gate that remains DENY if the watchdog goes away.

This is an **application-level** gate only. Any process able to send packets outside the gate bypasses it. Same-UID ptrace, malicious local code, host root and kernel attackers are not contained. The heartbeat is an untrusted file timestamp, not authenticated or monotonic across reboot. No firewall, network namespace, production transport, real secret, national cryptographic primitive or packet is used.

## Components

- `cmd/qazwire-cgrouplab` worker `parent` mode now writes a private `pulse` every 40 ms; setsid child remains independent. `SIGSTOP` suspends the parent and pulse without stopping the detached child.
- `watch` mode runs in a **second** user systemd transient service, not inside the worker cgroup. The executable:
  - refuses root, foreign unit path, unexpected `memory.max` and `pids.max`, malformed IDs;
  - verifies worker parent and descendant membership, pins both with pidfd, validates membership again, and opens the target `cgroup.kill` before arming the gate;
  - creates a private 0600 Unix socket in the 0700 test directory. Socket receives `S` and returns `ALLOW\n` or `DENY!\n`; no traffic is transmitted. The gate starts DENY.
  - admits **synthetic** requests only while worker heartbeat is fresh and watcher alive; after stale pulse or exited main process the gate is permanently fenced before cgroup kill is attempted.
  - writes fsynced diagnostic events: `WATCH_READY_GATE_ARMED`, `A0_SOFT_DENY_BEFORE_KILL reason=...`, `CGROUP_KILL_ATTEMPTED`, `KILL_CONFIRMED <proof>`, or `NOT_CONFIRMED`.
  - observes either (a) direct `cgroup.events populated=0` AND both original pidfds exited, or (b) exact cgroup path missing AND both original pidfds exited. Never calls this a physical memory erase.
- `gate` command is a synthetic client: anything other than an exact `ALLOW\n` returns exit code 1 / `A0_SOFT_DENY` — socket missing, error, unsupported response, timeout, or fenced session.
- `scripts/qazwire-m172-watchdog-lab.sh` builds the helper, starts two bounded distinct user systemd services, checks exact PID/cgroup membership, gets `A0_SOFT_ALLOW`, SIGSTOPs the monitored worker, then verifies log order (DENY **before** KILL) and post-fault DENY. Both services are cleaned up at EXIT, including failures. No sudo or nftables modifications.

## Important non-guarantees

1. **Not real A0:** no nftables, cgroup eBPF, interface-bound rule or kernel network policy. No guarantee against bypassing a synthetic proxy. Real A0 must be enforced before worker is started by a privileged component independent of the transport process, with startup default-deny and fail-safe behavior if watchdog itself fails.
2. **Same UID:** distinct cgroups do not create a secrecy or ptrace boundary. A dedicated launcher, distinct service identities, no-new-privileges, kernel-enforced sandbox and segregated IPC are required before handling secrets.
3. **Heartbeat spoofing:** a malicious worker or same-UID process can refresh the pulse. Authentic monotonic lease and kernel process health verification are required later.
4. **Watchdog failure:** the synthetic gate denies after its process/socket disappears only when all lab sending **must use that gate**. Actual VPN egress can bypass it until a kernel firewall is in place.
5. **Liveness:** worker may remain stuck in uninterruptible kernel wait; cgroup.kill is not physical erasure. Report NOT_CONFIRMED on timeout and preserve A0 deny.
6. **No protection from systemd user manager termination**, reboot, kernel faults, pid namespace escape, same-UID tampering or arbitrary userspace fork trees beyond tested known membership. Dedicated privileged monitor required for future threat model.
7. **No cryptography / Qalqan:** neither implementation nor national compliance; M2 stays NO-GO.

## CI tests and owner-host integration

```bash
go test -tags qazwire_exp -race -count=10 ./cmd/qazwire-cgrouplab
go test -tags qazwire_exp -race -count=1 ./...
go vet -tags qazwire_exp ./...
bash -n scripts/qazwire-m172-watchdog-lab.sh
```

On the owner's Ubuntu after confirming the exact SHA:

```bash
bash scripts/qazwire-m172-watchdog-lab.sh
```

Expected trace (the cgroup confirmation suffix can be `POPULATED_ZERO_PLUS_PIDFDS` or `CGROUP_REMOVED_PLUS_PIDFDS`):

```text
WATCH_READY_GATE_ARMED
A0_SOFT_DENY_BEFORE_KILL reason=PULSE_TIMEOUT
CGROUP_KILL_ATTEMPTED
KILL_CONFIRMED CGROUP_REMOVED_PLUS_PIDFDS
M1.7.2a LAB PASS: independent watchdog fenced synthetic gate before cgroup kill; post-fault gate denied
```

CI only exercises model/state-machine and builds; it must **not** attempt kernel egress rules or claim real cgroup tests. Exact SHA and logs required for host evidence.

## Exit criteria for M1.7.2 proper

- Trusted **system** supervisor, separately privileged and protected from compromised worker, begins with persistent default-deny **kernel-enforced** A0 egress; network deny survives watchdog/process crash. No `flush ruleset`, no global firewall side effects.
- Provable binding of worker service to a precisely scoped cgroup and network policy, no arbitrary UID-based grants; no opportunity to emit a VPN packet during launcher/watchdog race. Tests include SIGKILL of worker, SIGSTOP of worker, SIGKILL of watchdog, detached setsid descendant, exit during authorization, failed firewall update and restart with stale state.
- Audited authenticated heartbeat/health/IPC and independently protected configuration, explicit restart policy, distinct UID / core-dump/ptrace protections and review of all inherited FDs.
- Explicit fail-closed verdicts if any of the above unavailable on Ubuntu/AppArmor, and formal protocol nonce/key epoch/replay gates.

**Dispositions:** M1.7.2a becomes LAB VERIFIED only after tagged CI and host test. M1.7.2 full security boundary NOT IMPLEMENTED. R5-02, G-Q1/G-Q2, and M2 remain BLOCKED. No merge to master without authorization.

Primary references: Linux kernel cgroup v2 documentation; systemd systemd-run and resource-control manuals; nftables atomic transaction documentation. None of those sources alone provides the missing production security proof.
