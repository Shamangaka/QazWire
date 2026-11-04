# QazWire M1.7.2d — isolated diagnostic launch after owner-terminal incident

**RESEARCH ONLY. Not a privileged service or proof of secure VPN containment.**

Stacked on Draft PR #25 at `0ac3d8497e8b1b24121eea5bb62ea3f0b493d63e`. M1.7.2d original owner host trial **closed its terminal unexpectedly** and left **two** named lab network namespaces; owner then inspected them, found their PID lists empty and the worker nft set had no grant, explicitly removed both namespace names, and confirmed `sudo ip netns list` empty. Exact cause of terminal exit is **UNRESOLVED**. Prior interactive Bash had `set -e`, and a nonzero lab exit could have caused its parent shell to close. Do **not** equate that hypothesis with a root-cause diagnosis.

## What this PR adds

`scripts/m172d_safe_diagnostic_runner.py` is a **non-root** wrapper around the existing sudo-based isolated two-network-namespace experiment. It does not itself add/delete nft rules, kill other processes or create any network namespace. It is manually run, never automatically scheduled.

1. Enforces a full 40-character pinned exact HEAD SHA and rejects a dirty worktree before any privileged operation.
2. Hashes the five lab scripts/policies and writes their SHA-256 in a diagnostic JSON manifest.
3. Creates a unique private 0700 log folder in `~/.local/state/qazwire/m172d-runs` (child log and summary.json, 0600 under umask).
4. Calls `sudo -v` **explicitly** to obtain interactive owner authorization before launching any privileged child; then verifies there are **no leftover** named `qwda...` or `qwdb...` test network namespaces.
5. Runs the lab's Bash in a **separate process group, same terminal session**, using `subprocess.Popen(process_group=0, stdin=DEVNULL)` and redirecting stdout/stderr to a persistent file. This is intentional: a new session typically loses the controlling TTY and may break the previously validated `sudo -n` credential cache. Process-group isolation reduces signal propagation, but is **not a security sandbox** or a guarantee that an errant privileged process cannot signal the interactive shell.
6. Captures the **real** child exit code, bounded timeout status (120s), console/log evidence, and test netns name state after child exit; on timeout signals only the child Bash PID with SIGTERM, not a broad process group or root controller.
7. Will only print `SCRIPT_REPORTED_PASS_REQUIRES_OWNER_REVIEW` if the child exited 0, no named lab namespace is left, and six expected proof markers are present in its log. Otherwise classifies `STOP_CHILD_NONZERO`, `STOP_NETNS_STATE_CHANGED`, `STOP_TIMEOUT_INCOMPLETE`, or `STOP_MISSING_PROOF_MARKER`; any internal error is `STOP_ERROR`.
8. Prints the final private log and manifest location plus the lab's reported exit code/classification.

### Why wrapper intentionally returns 0

The **wrapper process** intentionally always exits with code **0** even when the **lab child** exits nonzero or times out. This is solely to ensure an interactive shell that has `set -e` enabled does not automatically close its terminal again due to the diagnostic tool's return code. **Never treat wrapper shell return code as PASS.** The only result is the explicit `M172D_CLASSIFICATION`, `lab_child_exit_code`, `lab_timed_out`, and the full saved log. Any `STOP_...` means the host test remains **UNVERIFIED**.

This mechanism is unsuitable for unattended CI or job automation where nonzero failures must propagate. The new offline unit tests exercise the child-exit-42 path, log persistence, namespace parser and missing-proof classification WITHOUT sudo.

## Verification before any host retry

The exact SHA in the CLI must match the current feature branch head, confirmed in GitHub.

```bash
# From a new detached worktree at the pinned exact SHA:
bash -n scripts/qazwire-m172d-controller-netns-lab.sh
python3 -m py_compile scripts/m172d_safe_diagnostic_runner.py scripts/m172d_safe_runner_tests.py
python3 scripts/m172d_safe_runner_tests.py
# Owner reviews BOTH the wrapper and privileged lab before running:
less scripts/m172d_safe_diagnostic_runner.py
less scripts/qazwire-m172d-controller-netns-lab.sh

# Explicit manual privileged lab invocation, only after a separate review:
python3 scripts/m172d_safe_diagnostic_runner.py --expect-sha <EXACT_40CHAR_SHA>
```

The wrapper will first request sudo credentials, verify no `qwda*/qwdb*` pre-existing lab namespace, and then run the test in a separate child process group. It will save `lab-output.log` and `summary.json` in a private run directory regardless of the child result.

After any unexpected failure or timeout, do not automatically rerun. Inspect `summary.json`, full log, and (using read-only commands) named namespace PIDs/ruleset before any specific cleanup. Avoid wildcard `kill`, `pkill`, `ip netns delete`, `nft flush ruleset`, global policy changes or disabling AppArmor. No full host network-state integrity snapshot is produced by this wrapper.

## Explicit non-guarantees

- No production protected root policy service, immutable root-owned installation, distinct service credentials or hardened systemd unit.
- No immediate A0 on controller SIGKILL. A valid nft permit may remain for its 2s TTL; this has been empirically shown by M1.7.2b/c.
- No guaranteed termination of privileged children if the diagnostic launcher itself crashes, and a named network namespace may remain. The wrapper **detects** surviving named namespaces but does not delete them or blindly signal their tasks.
- Namespace names being removed is not proof that every anonymous namespace reference or FDs have been released.
- M1.7.2d **host test remains UNVERIFIED**, no real VPN transport, no actual Qalqan cryptography, no protected key lifecycle, no ST RK compliance. No merges without owner approval.

**Exit criteria:** CI success on the exact SHA and owner-host evidence with unbroken saved log, tested graceful cleanup, negative/positive direct UDP controls, ordered worker revocation, and accurate accounting for controller SIGKILL residual permit. Independent review is still required before any claims beyond a synthetic lab.
