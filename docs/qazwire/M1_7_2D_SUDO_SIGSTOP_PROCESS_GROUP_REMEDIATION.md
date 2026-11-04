# QazWire M1.7.2d — SIGSTOP + sudo job-control incident remediation

**Research-only; never a production-root-controller deployment.**

Branch stacked on PR #26 exact HEAD `fbdbfcb8f261c716edfcb3fb471506b14632873f`. Owner's second manual Ubuntu run of the previous lab completed Python offline tests and clean worktree checks, then ran a privileged two-network-namespace experiment through the safe diagnostic runner. It reached `PIDFD_SIGNAL_STOP_SENT target=worker` in Phase A and **made no further progress before the 120-second timeout**. The wrapper printed `M172D_CLASSIFICATION=STOP_TIMEOUT_INCOMPLETE`. No further packet-authorization claim is justified.

## Root-cause hypothesis, based on actual sudo source

The unprivileged worker was originally a long-running command **still managed by sudo** (`sudo ip netns exec ... setpriv python`). The test then sent `SIGSTOP` to its PID. Upstream `sudo` PTTY handling in `src/exec_pty.c`, `suspend_sudo_pty`, contains a `killpg(ec->ppgrp, signo)` path when the monitored command stops. This can stop the **parent shell's entire process group**, not just the intended worker. See:

- https://github.com/sudo-project/sudo/blob/main/src/exec_pty.c
- `sudo(8)` signal-handling notes (SIGSTOP cannot be caught/relayed like SIGTSTP).

The observed halt immediately after the signal is consistent with this path, but the owner has NOT yet provided the process PGID/SID/STAT or root-controller's private log. **The precise cause is not yet independently verified on the owner's machine.**

## Patch strategy

1. The synthetic capless worker now **explicitly requires `--detach`**. After first validating UID/GID 65534, no groups, zero caps and `NoNewPrivs=1`, it forks once; the original process returns and exits under sudo.
2. In the detached child, `os.setsid()` creates a separate session and process group. Security attributes are checked a second time. It writes `WORKER_READY_PID=...` to its private owner-side log and redirects stdin/stdout/stderr to `/dev/null`. It contains no network I/O.
3. The Bash lab **waits for the sudo-managed launcher to exit**, reads the worker PID, then requires SID=PID and PGID=PID before it creates/arms the privileged root controller. If those checks fail, abort rather than inject SIGSTOP into a sudo-managed command.
4. The root controller independently verifies `os.getsid(worker_pid)==worker_pid` and `os.getpgid(worker_pid)==worker_pid` in addition to the existing PIDFD, UID, capability, netns and NoNewPrivs checks.
5. Namespace cleanup will first send `SIGTERM` through individually validated pidfds in each new lab namespace. If tasks remain (including a `SIGSTOP`ed synthetic worker that cannot process SIGTERM), it can escalate to **`SIGKILL` via pidfds restricted to the exact new namespace**, never `pkill`, `killall`, a host PID list, or a host-wide signal. It checks for empty namespace PID lists afterward. This fallback is invoked only during explicit cleanup of exclusively created random lab namespaces.

## Offline tests

`scripts/m172d_detached_worker_tests.py` uses mocks to exercise parent-fork exit, setsid/session checks and stdio close paths; checks source requirements for both shell and controller and the PIDFD-only cleanup escalation; **no actual fork, sudo, signal, nft or ip netns**.

Preceding `scripts/m172d_safe_runner_tests.py` verifies that the diagnostic wrapper records a failed child without closing the interactive parent shell, preserves evidence and checks for orphan namespaces.

## Before future privileged host retry

**STOP** until the prior timed-out lab's state is inspected. Owner must first read:

```bash
set +e
sudo ip netns list
for ns in qwda1d4fa5f2 qwdb1d4fa5f2; do
  sudo ip netns pids "$ns"
done
ps -eo pid,ppid,pgid,sid,user,stat,wchan:24,args | grep -E '[m]172d|[q]wda1d4fa5f2'
cat "$HOME/.local/state/qazwire/m172d-runs/run-20261104-051531-070dfb61b8b4/summary.json"
```

Only after reading exact namespace PID lists and task states may owner authorize a scoped recovery of potentially stopped processes. The repository patch does not modify host state or fix a previously orphaned namespace.

After successful CI on the exact PR SHA, a **new detached worktree** can be used for offline syntax/behavior tests, and only then a separate explicit owner-authorized manual sudo host lab in the safer diagnostic wrapper. The test must prove detached worker SID=PGID=PID, controller revoke before worker SIGKILL, direct UDP default deny, TTL residual failure and complete named namespace teardown. Print the full private log and JSON summary on failures.

**Security limitations unchanged:** a valid nft grant can survive the controller's own `SIGKILL` until its remaining 2-second TTL; no instantaneous A0, no protected or immutable root service, no full process isolation, no actual VPN dataplane, no Qalqan, no network cryptography conformity or production readiness. M1.7.2d HOST FAILED/TIMEOUT on previous SHA; new patch has NOT been verified on owner Ubuntu. No merges to `master` permitted.
