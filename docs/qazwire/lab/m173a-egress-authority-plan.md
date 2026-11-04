# QazWire M1.7.3a — Egress authority isolation (research only)

Status (2026-11-04): **P0 code drafted; privileged lab NOT run on target host**.
Base: M1.7.2e fix commit `77e9695aa059470769817f1a71c41868392dcea6`; see Draft PR #29.
This is not a VPN, encryption, security certification, or a production design.

## Problem

M1.7.2e uses nftables `meta skuid 65533` to permit egress to exactly
`198.18.27.2:44000/UDP` from inside a newly created network namespace.
The rule checks **socket owner UID**, not executable, PID or broker authenticity.
An arbitrary capless process with UID 65533 in the same namespace can therefore
make its own UDP socket and use the allow rule, irrespective of whether the
broker exists. The expected weakness is testable without a malicious payload.

## P0: negative security test to falsify broker-process isolation

Script: `scripts/qazwire-m173a-sameuid-adversary-lab.sh`.
Static tests: `scripts/m173a_p0_static_tests.py`.

- Invoke script only as a human non-root user with **explicit** sudo authorization.
- Require no pre-existing namespaces matching `qwga????????` or `qwgb????????`.
- Create exactly two synthetic, unique isolated namespaces; install **the
  unchanged M1.7.2e nft policy only within the first** before any interface is up.
- Create one veth pair only inside these namespaces; no default route, keys,
  host nft, host physical interface, Internet or VPN.
- Start synthetic UDP echo in the second namespace only.
- UID 65534 (worker) must get **PermissionError** when sending directly to
  44000, and a nonzero exit code. Timeouts are not accepted as proof.
- An unrelated UID 65533 process (not broker) **must get ECHO** at 44000;
  this is the expected **vulnerability reproduction**, not a security pass.
- UID 65533 direct UDP to 44001 must still be explicitly denied.
- Confirm UID 65534 remains denied after the adversarial send.
- Cleanup must affect only the two newly created namespaces; if cleanup fails,
  stop and manually inspect namespaced processes, never mass-kill host tasks.

Expected P0 evidence markers:
```text
M173A_P0_ISOLATED_NFT_DEFAULT_DROP
M173A_P0_WORKER_UID_DENIED
M173A_P0_SAME_UID_BYPASS_CONFIRMED
M173A_P0_PORT_SCOPE_CONFIRMED
M1.7.3a P0 EXPECTED VULNERABILITY REPRODUCED
M1.7.3a P0 CLEANUP PASS
```

**Exit code 0 with these markers means the counterexample reproduced.**
It explicitly does **not** mean that egress confinement is broker-process bound.

## P1: architecture candidate (not implemented in P0)

1. Keep the untrusted worker in a **network namespace with no underlay path**.
   Do not rely on `meta skuid` inside a namespace shared with worker.
2. Put the broker into a **separate network namespace** which alone contains
   the veth-facing allowed underlay endpoint and the exact destination nft
   policy. Place the UDP echo peer in a third new namespace.
3. Use a **filesystem-path AF_UNIX** socket for cross-network-namespace IPC.
   Abstract AF_UNIX socket names are scoped to a network namespace and cannot
   be assumed to work across this boundary. Avoid putting a writable socket
   directory under shared world-writable paths without safe ownership checks.
4. Preserve UID/peer credential verification, request framing, fixed destination,
   no `SCM_RIGHTS`, no socket FD handoff, and fail-closed IPC errors.
5. Avoid reusing the broker UID for worker. Ensure worker cannot `setns` into
   the broker namespace, get access to its sockets via `/proc`, or install its
   own routes. Namespace entry is controlled by capabilities and by access to
   namespace handles; the threat model excludes host root/privileged namespace
   administrators.
6. Add a genuine adversary case: a worker with **arbitrary sockets and both
   allowed and forbidden target ports** still cannot produce an echo without
   broker relay. Require positive relay while the broker is alive; require IPC
   unavailability and direct UDP denial after verified PIDFD termination.
7. Include namespace identity and exact child identity checks, process
   cleanup, and evidence fingerprints in a safe diagnostic runner. Test both
   successful and deliberately failing cleanup paths in unprivileged mocks.

P1 **acceptance criterion**: a process controlled by the worker, with no
ability to enter the broker's network namespace, cannot send a UDP echo directly
to `198.18.27.2:44000`, while authorized broker relay succeeds.

## In-scope threat / out-of-scope assumptions

In scope: capless malicious worker, attacker attempts direct sockets, wrong
ports, forged IPC requests, broker death, namespace route absence.
Out of scope: privileged host root, arbitrary CAP_SYS_ADMIN in host namespaces,
compromised broker code or UID, leaked broker UDP file descriptors, inherited
open socket descriptors before sandboxing, kernel vulnerabilities, in-flight
packet revocation guarantees, and general protection of other host services.
These require separate experiments and controls.

## Review gates

- P0 and P1 must not modify host nft/routing or deploy production VPN.
- P0 demonstration must use a **new branch / new lab script**, not weaken
  or rewrite M1.7.2e established tests.
- Do not report P0 as P1 or as a security fix.
- All local lab logs need exact commit SHAs, private manifests, negative-test
  exit codes, and post-run netns inventory.
- No merge into `main` without explicit owner decision.
