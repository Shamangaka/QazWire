#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unprivileged tests for the M1.7.2d diagnostic wrapper; never calls sudo."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
MODULE = HERE / "m172d_safe_diagnostic_runner.py"
spec = importlib.util.spec_from_file_location("m172d_safe_runner", MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SafeDiagnosticRunnerTest(unittest.TestCase):
    def test_namespace_filter_matches_only_this_lab(self):
        output = (
            "qwda0123abcd (id: 1)\n"
            "qwdb0123abcd\n"
            "qwca0123abcd\n"
            "default\n"
            "qwda0123abcg\n"
            "qwda0123abcd-extra\n"
        )
        self.assertEqual(m.namespaces(output), {
            "qwda0123abcd", "qwdb0123abcd",
        })

    def test_reject_incomplete_sha(self):
        for invalid in ("", "abc", "x" * 40, "0" * 39, "0" * 41,
                        "0" * 39 + "\n", "A" * 40):
            self.assertIsNone(m.SHA_RE.fullmatch(invalid))

    def test_real_child_failure_does_not_kill_launcher(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            script = repo / "synthetic-fail.sh"
            logfile = repo / "lab-output.log"
            script.write_text("#!/bin/bash\necho SYNTHETIC_CHILD_FAIL\nexit 42\n",
                              encoding="ascii")
            code, timeout = m.run_detached_lab(script, repo, logfile, timeout=5)
            self.assertFalse(timeout)
            self.assertEqual(code, 42)
            self.assertIn("SYNTHETIC_CHILD_FAIL", logfile.read_text())
            self.assertEqual(m.evaluate_log(logfile.read_text(), code, False,
                                            set(), set()),
                             "STOP_CHILD_NONZERO")

    def test_script_success_does_not_imply_host_pass_without_markers(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            script = repo / "synthetic-success.sh"
            logfile = repo / "lab-output.log"
            script.write_text("#!/bin/bash\necho hello\nexit 0\n", encoding="ascii")
            code, timeout = m.run_detached_lab(script, repo, logfile, timeout=5)
            self.assertEqual(code, 0)
            self.assertFalse(timeout)
            self.assertEqual(m.evaluate_log(logfile.read_text(), code, False,
                                            set(), set()),
                             "STOP_MISSING_PROOF_MARKER")

    def test_change_of_namespace_rejected_even_after_exit_zero(self):
        log = "\n".join(m.REQUIRED_MARKERS)
        self.assertEqual(
            m.evaluate_log(log, 0, False, set(), {"qwda12345678"}),
            "STOP_NETNS_STATE_CHANGED",
        )

    def test_complete_markers_only_request_human_review(self):
        log = "\n".join(m.REQUIRED_MARKERS)
        self.assertEqual(
            m.evaluate_log(log, 0, False, set(), set()),
            "SCRIPT_REPORTED_PASS_REQUIRES_OWNER_REVIEW",
        )

    def test_timeout_always_stop(self):
        self.assertEqual(m.evaluate_log(
            "\n".join(m.REQUIRED_MARKERS), 0, True, set(), set()),
            "STOP_TIMEOUT_INCOMPLETE",
        )

    def test_private_logs_and_manifest(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.object(Path, "home", return_value=Path(home)):
                d = m.new_private_run_dir()
                self.assertTrue(d.is_dir())
                self.assertEqual(d.stat().st_mode & 0o077, 0)
                f = d / "summary.json"
                with f.open("x") as h:
                    json.dump({"lab_child_exit_code": 42}, h)
                self.assertEqual(json.loads(f.read_text())["lab_child_exit_code"], 42)

    def test_no_implicit_test_mode_enters_privileged_lab(self):
        source = MODULE.read_text()
        self.assertIn("process_group=0", source)
        self.assertNotIn("start_new_session=True", source)
        self.assertIn("subprocess.DEVNULL", source)
        self.assertIn("return 0", source)
        self.assertIn('["sudo", "-v"]', source)
        self.assertIn('"STOP: dirty worktree', source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("sudo nft flush ruleset", source)
        self.assertNotIn("killpg", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
