#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline regression for M1.7.2d sudo SIGSTOP process-group incident.

Every fork, signal, kill, /proc and network operation is mocked or inspected
as static source. This test never calls sudo, nft, ip netns or creates a worker.
"""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def read_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


worker = read_module("m172d_worker_for_tests", "m172d_worker.py")
controller = read_module("m172d_controller_for_tests", "m172d_controller.py")


class DetachedWorkerNoSudoJobControl(unittest.TestCase):
    def test_worker_refuses_run_without_explicit_detach(self):
        with mock.patch.object(worker.sys, "argv", ["worker.py"]):
            with self.assertRaises(SystemExit):
                worker.main()

    def test_parent_exits_without_becoming_long_lived_sudo_child(self):
        with mock.patch.object(worker.sys, "argv", ["-c", "m172d_worker.py", "--detach"]), \
             mock.patch.object(worker, "validate_unprivileged") as validate, \
             mock.patch.object(worker.os, "fork", return_value=5566) as fork, \
             mock.patch.object(worker.os, "setsid") as setsid:
            self.assertEqual(worker.main(), 0)
            validate.assert_called_once()
            fork.assert_called_once()
            setsid.assert_not_called()

    def test_detached_child_verifies_session_identity_and_releases_tty_fds(self):
        class ChildLoopEntered(BaseException):
            pass

        with mock.patch.object(worker.sys, "argv", ["-c", "m172d_worker.py", "--detach"]), \
             mock.patch.object(worker, "validate_unprivileged") as validate, \
             mock.patch.object(worker.os, "fork", return_value=0), \
             mock.patch.object(worker.os, "setsid") as setsid, \
             mock.patch.object(worker.os, "getpid", return_value=5566), \
             mock.patch.object(worker.os, "getsid", return_value=5566), \
             mock.patch.object(worker.os, "getpgrp", return_value=5566), \
             mock.patch.object(worker.os, "open", return_value=7), \
             mock.patch.object(worker.os, "dup2") as dup2, \
             mock.patch.object(worker.os, "close") as close, \
             mock.patch.object(worker.time, "sleep", side_effect=ChildLoopEntered):
            with self.assertRaises(ChildLoopEntered):
                worker.main()
            setsid.assert_called_once()
            self.assertEqual(validate.call_count, 2)
            self.assertEqual([x.args[1] for x in dup2.call_args_list], [0, 1, 2])
            close.assert_called_once_with(7)

    def test_controller_demands_separate_session_and_group(self):
        source = (HERE / "m172d_controller.py").read_text()
        self.assertIn('os.getsid(pid) != pid or os.getpgid(pid) != pid', source)
        self.assertIn('worker must be a detached session/group leader', source)

    def test_shell_waits_for_sudo_launch_process_before_sigstop(self):
        text = (HERE / "qazwire-m172d-controller-netns-lab.sh").read_text()
        self.assertIn("m172d_worker.py --detach", text)
        self.assertIn('wait "$launcher_pid"', text)
        self.assertIn('session=$(ps -o sid= -p "$worker_pid"', text)
        self.assertIn('pgid=$(ps -o pgid= -p "$worker_pid"', text)
        self.assertIn("WORKER_DETACHED_SESSION_LEADER", text)
        self.assertIn('M172D_COMMAND_FAILED', text)

    def test_cleanup_has_pidfd_only_stop_escalation(self):
        source = (HERE / "m172b_netns_probe.py").read_text()
        shell = (HERE / "qazwire-m172d-controller-netns-lab.sh").read_text()
        self.assertIn('signal.pidfd_send_signal(fd, sig, None, 0)', source)
        self.assertIn('sig = signal.SIGKILL if force_kill else signal.SIGTERM', source)
        self.assertIn('cleanup.add_argument("--force-kill", action="store_true")',
                      source)
        self.assertIn('terminate-members --force-kill', shell)
        self.assertIn('sudo -n ip netns pids "$ns"', shell)
        self.assertNotIn("pkill", shell)
        self.assertNotIn("killall", shell)


if __name__ == "__main__":
    unittest.main(verbosity=2)
