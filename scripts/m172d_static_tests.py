#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1.7.2d offline regression; not a privileged kernel test."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/qazwire-m172d-controller-netns-lab.sh"
CONTROLLER = ROOT / "scripts/m172d_controller.py"

spec = importlib.util.spec_from_file_location("controller", CONTROLLER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class M172DStaticTests(unittest.TestCase):
    def test_constant_bounded_nft_policy_language(self):
        self.assertEqual(m.TABLE, "qw_privsep_a0")
        self.assertEqual(m.DEST, "198.18.27.2")
        self.assertEqual(m.LEASE_SECONDS, 2)
        self.assertLess(m.RENEW_SECONDS, m.LEASE_SECONDS)
        self.assertIn("flush set inet qw_privsep_a0 privileged_grants", m.FLUSH)
        self.assertIn("timeout 2s", m.ADD)
        self.assertNotIn("flush ruleset", m.FLUSH + m.ADD)

    def test_reject_unapproved_nft_batch_even_with_fixed_executables(self):
        with self.assertRaises(ValueError):
            m.policy("/usr/sbin/ip", "/usr/sbin/nft", "qwda12345678",
                     "flush ruleset\n")
        with self.assertRaises(ValueError):
            m.policy("/usr/sbin/ip", "/usr/sbin/nft", "qwda12345678",
                     "add table inet evil\n")

    def test_strict_namespace_identifier(self):
        for s in ["qwda12345678", "qwdaabcdef01"]:
            self.assertTrue(m.NS_RE.fullmatch(s))
        for s in ["", "qwda1", "qwca12345678", "qwda12345678/../../init",
                  "qwda12345678;sudo nft", "qwda12345678\n"]:
            self.assertFalse(m.NS_RE.fullmatch(s), s)

    def test_daemon_has_no_shell_execution_or_host_nft(self):
        s = CONTROLLER.read_text()
        self.assertIn('["netns", "exec"', s.replace('ip_bin, "netns", "exec"', '"netns", "exec"'))
        self.assertIn('"netns", "exec", ns, nft_bin', s)
        self.assertNotIn("shell=True", s)
        self.assertIn("os.pidfd_open(", s)
        self.assertIn("signal.pidfd_send_signal", s)
        self.assertIn('note("CTRL_REVOKED reason=" + cause)', s)
        self.assertIn('note("WORKER_KILL_SENT")', s)

    def test_shell_drops_worker_capabilities_and_labs_only(self):
        s = SCRIPT.read_text()
        self.assertIn('worker_ns="qwda$nonce"', s)
        self.assertIn('peer_ns="qwdb$nonce"', s)
        self.assertIn("--reuid=65534 --regid=65534 --clear-groups", s)
        self.assertIn("--inh-caps=-all --ambient-caps=-all --bounding-set=-all", s)
        self.assertIn("--no-new-privs --reset-env", s)
        self.assertIn('sudo -n ip netns exec "$worker_ns" nft -f "$policy"', s)
        self.assertIn('sudo -n ip netns pids "$ns"', s)
        self.assertIn("CLEANUP_FAILURE", s)
        self.assertIn("KNOWN_GAP_CONFIRMED", s)
        self.assertNotIn("sudo nft flush ruleset", s)
        self.assertNotIn("sudo nft add table", s)
        self.assertNotIn("sudo ip route add", s)

    def test_root_stop_signal_does_not_grant_by_itself(self):
        s = CONTROLLER.read_text()
        self.assertIn('signal.signal(signal.SIGTERM, request_stop)', s)
        self.assertIn('if state not in ("R", "S")', s)
        self.assertIn('if state not in ("R", "S"):', s)
        self.assertIn('policy(ip_bin, nft_bin, ns, FLUSH + ADD)', s)
        self.assertIn('ensure_denied(ip_bin, nft_bin, ns)', s)
        self.assertIn('return state', 'return status["State"].split()[0]')


if __name__ == "__main__":
    unittest.main(verbosity=2)
