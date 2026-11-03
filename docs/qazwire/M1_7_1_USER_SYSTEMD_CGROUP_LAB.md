# QazWire M1.7.1 — user-systemd cgroup-v2 termination lab

**Status: RESEARCH ONLY / SYNTHETIC**. No cryptography, keys, real KLM process, VPN traffic, independent watchdog, egress firewall, production isolation or national standard claim. Builds on Draft PR #20 (M1.7.0) at `23b03e366735bb91ff2056e7ae0190d785047939`.

## Host evidence (owner, Ubuntu 24.04 / systemd 255)

On the owner's local Ubuntu kernel `7.0.0-38-generic` the following is directly observed:

- Unified cgroup v2 mounted at `/sys/fs/cgroup`; `memory`, `pids` controllers are visible and enabled in the current delegated user tree.
- A temporary user transient service created by `systemd-run --user` reported `MemoryMax=134217728`, `TasksMax=32`, `ActiveState=active`.
- Its **non-root** cgroup exposed writable `cgroup.kill`, `cgroup.events populated=1`, `memory.max=134217728`, `pids.max=32`.
- `unshare -Ur /usr/bin/true` failed with `write failed /proc/self/uid_map: Operation not permitted`; `kernel.apparmor_restrict_unprivileged_userns=1`.
- **This is not evidence that any cgroup was actually killed**. This milestone's script provides that missing destructive test on a uniquely-created *synthetic* unit.

**Decision:** use an unprivileged user systemd transient service **without** user namespaces. Do not modify sysctl or AppArmor merely to make a lab pass. Ubuntu 24.04 AppArmor applies restrictions to unprivileged user namespaces, and permission requires targeted AppArmor policy if later justified.

## Concrete lab implementation

`cmd/qazwire-cgrouplab` (Linux + `qazwire_exp` build tag) has three CLI modes:

- `parent <private-dir>`: a Go worker run as the systemd transient service's main process; spawns its own descendant using `Setsid:true`, **without Pdeathsig**, and writes both PIDs into a private 0700 marker directory. Both processes run forever unless killed.
- `escaped`: the descendant; leaves the parent's Unix session/process group via `setsid` but must remain in the same cgroup.
- `kill <cgroup> <unit> <mainpid> <memory-bytes> <task-limit>`: destructive operation intentionally available **only** for a validated transient `qazwire-m171-<16hex>.service` under the calling UID's `user@UID.service` subtree, with `MainPID` belonging to that cgroup, and `memory.max=134217728`, `pids.max=32`. Opens `cgroup.events` first, checks populated=1, writes `1` to `cgroup.kill`, rereads open `cgroup.events` until populated=0 or a 5-second deadline. Any error or missing confirmation is reported **NOT_CONFIRMED**, not success. The file path must use Linux cgroup2fs.

`scripts/qazwire-m171-cgroup-lab.sh` builds the isolated test executable, generates a random unit name, starts the process in its own user systemd transient service with `MemoryMax=128M`, `TasksMax=32`, `NoNewPrivileges=yes` and `KillMode=control-group`; checks parent and `setsid` descendant's /proc cgroup membership and distinct Unix sessions; calls the narrowly-scoped `kill` command; and runs a cleanup trap to stop/reset the test unit.

**Destructive scope**: the script sends `cgroup.kill` only to its uniquely named temporary user service and its descendants. It does **not** kill the terminal, Docker daemon, arbitrary service, system/user manager, or root cgroup. No `sudo`, sysctl changes, user namespaces or nftables changes. It needs a working user systemd manager, writable cgroup.kill and local Go toolchain. Never redirect the `kill` CLI to another workload or run it as root.

## Exact reproduction (Ubuntu)

From detached worktree of this branch, after verifying exact `git rev-parse HEAD`:

```bash
bash scripts/qazwire-m171-cgroup-lab.sh
go test -tags qazwire_exp -race -count=10 ./cmd/qazwire-cgrouplab
go test -tags qazwire_exp -race -count=1 ./...
go vet -tags qazwire_exp ./...
```

Expected integration proof:
1. systemd user service active with 128 MiB and 32-task limits;
2. recorded parent and `setsid` child have **different** sessions but the **same** exact /proc cgroup;
3. `cgroup.kill` writable and kill succeeds without `sudo`;
4. the code observes `cgroup.events populated=0` before reporting PASS;
5. temporary unit and files are removed by EXIT trap, even on error.

**Unit test coverage**: strict parse of cgroup.events, rejection of foreign UID/root/parent cgroup/malformed paths or unit names, private marker directory verification, and PID membership preconditions. CI will run pure unit tests, build the lab, and run full Go regression. CI running in a GitHub Actions runner **will not claim actual cgroup.kill integration**; only the owner's host experiment can provide that evidence.

## Security and availability limitations

- `cgroup.kill` and `populated=0` demonstrate process termination inside the cgroup, **not** physical RAM zeroization, IPC authorization, secrecy from a malicious same-UID process, guaranteed timely recovery from uninterruptible kernel waits, or control of packets already in the network stack.
- The user-manager service and test launcher run as the **same UID**. No separate privileged owner, independent failure domain, pidfd, ptrace or core-dump controls, seccomp, AppArmor confinement profile, network namespace, network egress control, or native key arena.
- If the launcher process dies before the kill command, the cleanup trap will not run. M1.7.2 must implement an independent watchdog / systemd manager policy with `cgroup.kill` and A0 egress fail-closed. `KillMode=control-group` is used as cleanup support but **not** claimed as the independent watchdog.
- `NoNewPrivileges=yes` does not create a sandbox or fix same-UID ptrace. Inherited environment and FDs need their own review.
- The command uses a dedicated unit and validates `MainPID`, cgroup name and resource limits, but these checks are not immune to a powerful local same-UID attacker who can manipulate the user's systemd manager; production needs a privileged launcher, separate service UID and signed policy.
- No user namespaces were requested, so Ubuntu's observed AppArmor block is not bypassed.
- The M1.7.0 synthetic KLM process and M1.7.1 termination probe are **separate** demonstrations; they are not joined into a production lifecycle yet.

## Readiness gate

Only after a clean SHA-pinned Ubuntu cgroup kill test and green CI is M1.7.1 **LAB VERIFIED**. M1.7.2 independent watchdog + real A0 network egress blocking are NOT IMPLEMENTED; R5-02 isolation and R5-E1 restart identity remain OPEN. M2 / actual Qalqan / production VPN / claims of ST RK conformity remain **NO-GO**. No merge into master without owner approval.

Primary references:
- Linux kernel cgroup v2: `Documentation/admin-guide/cgroup-v2.rst` (`cgroup.kill` and `cgroup.events`);
- systemd 255 `systemd-run(1)` and `systemd.resource-control(5)`;
- Ubuntu AppArmor documentation on restricted unprivileged user namespaces.
