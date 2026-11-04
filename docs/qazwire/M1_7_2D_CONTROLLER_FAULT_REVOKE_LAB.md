# QazWire M1.7.2d — persistent root policy-controller / unprivileged worker laboratory

**RESEARCH ONLY — NOT a hardened system service, production VPN, KLM, A0 guarantee, Qalqan primitive, or standards compliance.**

Stacked on Draft PR #24 at `a8c1ec5e529617d2d64aae25c0be75da321e39c7`. All changes are confined to this draft feature branch. **No merge to master is authorized**.

## Objective

M1.7.2c owner Ubuntu proved: UID 65534 + CapEff/CapBnd/CapAmb=0 + NoNewPrivs=1 cannot change its nft policy; a separately privileged command can explicitly revoke an allowance; the allowance persists after the command exits. M1.7.2d moves the manual grant/revoke cycle into a **running privileged controller** that monitors one independent, unprivileged worker by `pidfd`.

This is a persistence-and-fault-response experiment, **not** a protected controller. In particular, the controller runs as root in the **host network namespace** and executes source code from the owner's checkout, without an immutable installation or systemd hardening. It is controlled by an interactive wrapper, not an audited root service; host root compromise defeats the model.

## Diagram

```text
Host namespace (current non-root owner launches explicit sudo)
  └── persistent root Python controller (separate PID, host netns)
       ├── pidfd-open of specific UID65534 worker
       ├── verify target netns inode and worker status/capability properties
       ├── every 300 ms: nft batch scoped via "ip netns exec qwda<random> nft"
       └── if worker exits or is SIGSTOPed:
            (1) "flush set inet qw_privsep_a0 privileged_grants"
            (2) verify no grant remains
            (3) signal worker SIGKILL through its pidfd
            (4) verify pidfd reports exit
  |
  | exclusively scoped root policy transactions
  v
New worker netns (qwda<8hex>, NO default route/uplink)
  ├── inet qw_privsep_a0, OUTPUT/INPUT policy DROP
  ├── single permit: 198.18.27.2 UDP/44000 timeout 2s
  ├── worker under UID/GID 65534, CapEff=CapBnd=CapAmb=0,
  │   NoNewPrivs=1; no nft privilege
  └── capless direct UDP probe (bypasses all application gates)
       ↕ new-only veth pair
New peer netns (qwdb<8hex>)
  └── synthetic local UDP echo server on 44000, 44001
```

No worker namespace is the host network namespace. The veth pair originates only inside the new worker namespace, with the peer end moved to another new namespace. No host nft table, host route, physical interface, DNS, uplink, userns or AppArmor state is modified intentionally by the script. The script requests sudo for namespace creation and for a root controller; review it before running. It includes a pidfd-based cleanup of tasks in each unique namespace, plus verified attempts to stop its own root controllers.

## Source files

- `scripts/m172d_controller.py`: persistent root controller, strict `qwda[0-9a-f]{8}` namespace allowlist, specific worker pidfd/namespace/UID/caps checks, fixed nft transaction grammar (`flush`, `add`, `flush+add` only), heartbeat substitute via Linux process state polling (SIGSTOP classified as failure). One permit with 2-second timeout refreshed at ~300 ms while worker remains healthy. No socket or arbitrary user-supplied CLI policy, no shell execution in subprocess.
- `scripts/m172d_worker.py`: synthetic sleeping process explicitly checks UID/GID, zero capabilities, no_new_privs and no supplementary groups. It performs no network activity on its own; direct UDP probes run separately using the same capless worker context.
- `scripts/qazwire-m172d-controller-netns-lab.sh`: two isolated netns and two sequential fault scenarios, privileged root controller processes and direct UDP tests, teardown via verified pidfds. The script is **not** installed, scheduled, automatically enabled, or suitable as a service file.
- `scripts/m172d_static_tests.py`: pure offline checks for policy language/namespace naming and the scope of privileged calls.

## Host test cases (explicit owner-run)

**Phase A — worker stop, controller remains live**
1. Kernel DROP is installed before veth interfaces are activated. Direct UDP to both test ports is denied.
2. Spawn PID-pinned worker UID 65534, no caps/no_new_privs, and root controller outside worker namespace.
3. Controller grants an nft 2-second element and keeps refreshing it every 300 ms. Direct UDP to port 44000 is allowed; port 44001 remains denied.
4. A separate privilege-checked helper uses `pidfd_send_signal(SIGSTOP)` on the exact worker. Controller notices the worker's stopped state, revokes its nft grant, verifies that the grant no longer exists, and only then SIGKILLs the worker via pidfd. A direct UDP socket after revocation is denied. The ordered diagnostic markers must be:
   - `CTRL_ARMED lease=2s`
   - `CTRL_REVOKE_ATTEMPT reason=WORKER_STOP_OR_UNEXPECTED_STATE`
   - `CTRL_REVOKED reason=WORKER_STOP_OR_UNEXPECTED_STATE`
   - `WORKER_KILL_SENT`
   - `WORKER_EXIT_CONFIRMED`
5. A fresh direct UDP socket is still denied.

**Phase B — controller SIGKILL, worker stays live**
1. Start a **new** unprivileged worker and separate root controller. The new controller again grants the 2-second allowance, which is refreshed while alive.
2. A separate helper validates the specific root controller process and sends `SIGKILL` through pidfd.
3. Immediately attempt direct UDP. If it succeeds, the script prints `KNOWN_GAP_CONFIRMED`; it cannot be relabeled as full fail-closed.
4. Wait >2 seconds with no renewer; direct UDP is denied, including from a fresh client.
5. Terminate the worker via pidfd and cleanup the two new namespaces.

**No claim is made about packets already classified/queued at the moment of revoke**, or milliseconds of worst-case controller detection. A one-shot local lab observation is not a latency bound.

## Known security failures / architecture gates

| Requirement | Status |
| --- | --- |
| Root controller process separate from worker, live renewal | **HOST PENDING** |
| Unprivileged worker cannot modify nft rule | Prior M1.7.2c LAB VERIFIED |
| Controller detects worker SIGSTOP and explicitly revokes | **HOST PENDING** |
| Controller revokes before SIGKILL of known worker | **HOST PENDING** |
| Direct UDP denied after explicit revoke | **HOST PENDING** |
| Controller SIGKILL automatically revokes in kernel immediately | **NO-GO — known residual TTL window** |
| Protected service manager, root-owned immutable binary/config | **NOT IMPLEMENTED** |
| Distinct host filesystem/IPC/PID confinement, seccomp, AppArmor | **NOT IMPLEMENTED** |
| Unknown child/grandchild cleanup in same cgroup / restarted keys | **NOT IMPLEMENTED** |
| Real VPN worker and Qalqan | **NO-GO** |

Because the controller is root in host netns and runs user-owned checkout files, the current design is deliberately **not a trusted policy authority**. No worker-controlled IPC is exposed in this experiment, but untrusted access to the privileged source path remains a security problem. Service install, code signature, minimal capabilities, no-new-privileges and systemd sandbox must be addressed before any deployment.

A process with `CAP_NET_ADMIN` inside the worker namespace, access to privileged inherited FDs, or access to host root can bypass the policy. User 65534 is a shared host UID, not an isolated unique service account.

**Critical caveat:** the root policy controller can revoke the permit on *worker fault* while it remains alive, but if **the controller itself is killed by SIGKILL**, nothing runs to revoke it. The nft timeout of two seconds is a bounded *eventual* deny under tested conditions, not an instantaneous fail-closed property. This was observed independently in M1.7.2b/c. The script must not conceal or waive this defect.

## Reproduction and evidence discipline

```bash
# From the pinned detached worktree:
bash -n scripts/qazwire-m172d-controller-netns-lab.sh
python3 -m py_compile scripts/m172d_controller.py scripts/m172d_worker.py scripts/m172d_static_tests.py
python3 scripts/m172d_static_tests.py
# The next command requests sudo and creates two temporary netns.
# Execute manually only after reviewing the script:
bash scripts/qazwire-m172d-controller-netns-lab.sh
```

CI is limited to Bash/Python syntax/offline tests and existing full tagged/untagged Go regression. CI MUST NOT run as root or create namespaces / nft rules. The exact SHA, positive and negative kernel UDP probes and cleanup proof must come from the owner's separate Ubuntu test.

**Stop line:** M1.7.2d can be LAB VERIFIED for a *controller-on-worker-fault* scenario. A secure protected independent policy service and immediate A0 on controller SIGKILL remain unproven. R5-02/R5-E1, G-Q1/G-Q2 and M2 are NO-GO. No master merges.

Primary sources: Linux `pidfd_open(2)`/`pidfd_send_signal(2)`; nftables official man page (transactions), nftables wiki (set element expiry); `ip-netns(8)` and `setpriv(1)`.
