#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1.7.2d fail-preserving diagnostic launcher (research lab ONLY).

Never changes firewall, routes or network namespaces itself. Requires explicit
manual invocation; it wraps the existing sudo-based *lab* shell script.
Deliberately returns shell exit status 0 even when the LAB fails, to prevent
a caller's interactive 'set -e' from closing their terminal. Always report the
actual child exit code in a private JSON manifest and visible diagnostics.

This is NOT an incident-resilient supervisor, security sandbox, or VPN daemon.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

NS_RE = re.compile(r"^qwd[ab][0-9a-f]{8}$", re.ASCII)
SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
REQUIRED_MARKERS = (
    "REVOKE_BEFORE_WORKER_KILL_PASS",
    "A0_EXPLICIT_REVOKE_PASS",
    "POST_CONTROLLER_DEATH_TTL_DENY_PASS",
    "FRESH_DIRECT_SOCKET_DENIED",
    "M1.7.2d LAB PASS:",
    "M1.7.2d CLEANUP PASS",
)
ARTIFACTS = (
    "scripts/qazwire-m172d-controller-netns-lab.sh",
    "scripts/m172d_controller.py",
    "scripts/m172d_worker.py",
    "scripts/m172b_netns_probe.py",
    "docs/qazwire/lab/m172c-privsep-a0.nft",
)


def run_command(argv, *, cwd=None, timeout=15):
    return subprocess.run(
        argv, cwd=cwd, text=True, capture_output=True, timeout=timeout,
        check=True,
    ).stdout.strip()


def namespaces(output):
    """Parse ip netns list; only match the specific m172d namespace prefix."""
    found = set()
    for line in output.splitlines():
        name = line.split(maxsplit=1)[0] if line.strip() else ""
        if NS_RE.fullmatch(name):
            found.add(name)
    return found


def check_git(root, expected_sha):
    sha = run_command(["git", "rev-parse", "HEAD"], cwd=root)
    if sha != expected_sha:
        raise RuntimeError("STOP: worktree HEAD mismatch, refusing privileged lab")
    status = run_command(["git", "status", "--porcelain"], cwd=root)
    if status:
        raise RuntimeError("STOP: dirty worktree, refusing privileged lab")
    return sha


def fingerprints(root):
    checksums = {}
    for rel in ARTIFACTS:
        path = root / rel
        if not path.is_file():
            raise RuntimeError("STOP: missing source asset " + rel)
        checksums[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return checksums


def run_detached_lab(script, root, logfile, timeout=120):
    """Run child bash in a new session, preserving output independently.

    On timeout sends SIGTERM to the exact child bash PID, NOT process group.
    It never SIGKILLs root children, host PIDs or namespace processes.
    A timed-out child may leave resources; operator MUST inspect namespaces.
    """
    with open(logfile, "x", encoding="utf-8") as out:
        proc = subprocess.Popen(
            ["bash", "--noprofile", "--norc", str(script)],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            env=os.environ.copy(),
        )
        try:
            return proc.wait(timeout=timeout), False
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            return proc.poll(), True


def evaluate_log(log, child_code, timed_out, pre, post):
    """Never turn a failed/unknown lab run into a success."""
    if timed_out:
        return "STOP_TIMEOUT_INCOMPLETE"
    if child_code != 0:
        return "STOP_CHILD_NONZERO"
    if pre != post:
        return "STOP_NETNS_STATE_CHANGED"
    if any(marker not in log for marker in REQUIRED_MARKERS):
        return "STOP_MISSING_PROOF_MARKER"
    return "SCRIPT_REPORTED_PASS_REQUIRES_OWNER_REVIEW"


def new_private_run_dir():
    base = Path.home() / ".local" / "state" / "qazwire" / "m172d-runs"
    # Check each directory before using it. This is a local lab convenience,
    # not an adversarially secure filesystem namespace.
    for parent in (Path.home() / ".local", Path.home() / ".local" / "state",
                   Path.home() / ".local" / "state" / "qazwire", base):
        parent.mkdir(mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise RuntimeError("STOP: log directory is a symlink/non-directory")
        st = parent.stat()
        if st.st_uid != os.getuid():
            raise RuntimeError("STOP: log directory has unexpected owner")
    nonce = os.urandom(6).hex()
    folder = base / ("run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                     + "-" + nonce)
    folder.mkdir(mode=0o700)
    return folder


def print_log_tail(path, lines=65):
    if not path.is_file():
        return
    with open(path, "r", encoding="utf-8", errors="replace") as stream:
        recent = stream.readlines()[-lines:]
    print("========== LAB OUTPUT (TAIL) ==========", flush=True)
    for line in recent:
        print(line.rstrip("\n"), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-sha", required=True,
                        help="Pinnned 40-character Git HEAD SHA")
    args = parser.parse_args()
    os.umask(0o077)
    state = {
        "classification": "NOT_RUN",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "expected_sha": args.expect_sha,
        "lab_child_exit_code": None,
        "lab_timed_out": False,
        "before_netns": [],
        "after_netns": [],
    }
    folder = None
    logfile = None
    try:
        if os.geteuid() == 0:
            raise RuntimeError("STOP: invoke the diagnostic wrapper as non-root")
        if not SHA_RE.fullmatch(args.expect_sha):
            raise RuntimeError("STOP: --expect-sha must be exact lowercase 40-char SHA")
        root = Path(__file__).resolve().parent.parent
        lab = root / "scripts" / "qazwire-m172d-controller-netns-lab.sh"
        state["git_head"] = check_git(root, args.expect_sha)
        state["source_sha256"] = fingerprints(root)
        folder = new_private_run_dir()
        logfile = folder / "lab-output.log"
        print("DIAGNOSTIC_DIR=" + str(folder), flush=True)
        print("EXPECTED_SHA=" + args.expect_sha, flush=True)
        # Interactive credential setup is deliberately performed OUTSIDE the
        # separate process session. All child sudo calls use sudo -n.
        print("========== EXPLICIT SUDO AUTHORIZATION ==========", flush=True)
        run_command(["sudo", "-v"], timeout=120)
        before = run_command(["sudo", "-n", "ip", "netns", "list"])
        state["before_netns"] = sorted(namespaces(before))
        if state["before_netns"]:
            raise RuntimeError("STOP: existing qwda/qwdb lab netns: " +
                               ", ".join(state["before_netns"]) +
                               "; investigate before starting new lab")
        print("PRECHECK: no orphan qwda/qwdb namespaces", flush=True)
        state["classification"] = "RUNNING"
        code, timed_out = run_detached_lab(lab, root, logfile)
        state["lab_child_exit_code"] = code
        state["lab_timed_out"] = timed_out
        after = run_command(["sudo", "-n", "ip", "netns", "list"])
        state["after_netns"] = sorted(namespaces(after))
        lab_log = logfile.read_text(encoding="utf-8", errors="replace")
        state["classification"] = evaluate_log(
            lab_log, code, timed_out,
            set(state["before_netns"]), set(state["after_netns"]),
        )
        print_log_tail(logfile)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
        state["classification"] = "STOP_ERROR"
        state["diagnostic_error"] = type(exc).__name__ + ": " + str(exc)[:600]
        if logfile is not None:
            print_log_tail(logfile)
        print("M172D_DIAGNOSTIC_STOP: " + str(exc)[:600], flush=True)
    finally:
        state["completed_utc"] = datetime.now(timezone.utc).isoformat()
        if folder is not None:
            manifest = folder / "summary.json"
            with open(manifest, "x", encoding="utf-8") as stream:
                json.dump(state, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
            print("SUMMARY_JSON=" + str(manifest), flush=True)
            print("LAB_LOG=" + str(logfile), flush=True)
        print("M172D_CLASSIFICATION=" + state["classification"], flush=True)
        if state["classification"] != "SCRIPT_REPORTED_PASS_REQUIRES_OWNER_REVIEW":
            print("M172D_NOT_VERIFIED: do NOT call this a pass; check netns names",
                  flush=True)
        else:
            print("M172D_OWNER_EVIDENCE_REQUIRED: read full log and summary",
                  flush=True)

    # CRITICAL: intentionally return 0 even if lab child fails. The true lab
    # result is persisted in summary.json, and this line appears in stdout.
    # Parent interactive shells which previously set -e therefore stay alive.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
