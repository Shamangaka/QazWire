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
        self.assertIn('return status["State"].split()[0]', s)


    def test_controller_fault_order_revoke_before_pidfd_kill(self):
        """Executable state-machine test, no root, no networking, no nft."""
        events = []

        def event(message):
            events.append(message)

        def denied(_ip, _nft, _ns):
            events.append("NFT_DEFAULT_DENY_OR_REVOKE")

        def batch(_ip, _nft, _ns, script):
            events.append("NFT_BATCH:" + script.strip())
            return True

        with mock.patch.object(m.os, "geteuid", return_value=0), \
             mock.patch.object(m, "validate_ns", return_value=42), \
             mock.patch.object(m.shutil, "which", side_effect=["/usr/sbin/ip", "/usr/sbin/nft"]), \
             mock.patch.object(m.os, "pidfd_open", return_value=19), \
             mock.patch.object(m.os, "close"), \
             mock.patch.object(m, "require_worker", side_effect=["S", "T"]), \
             mock.patch.object(m, "pidfd_exited", return_value=False), \
             mock.patch.object(m, "ensure_denied", side_effect=denied), \
             mock.patch.object(m, "policy", side_effect=batch), \
             mock.patch.object(m.signal, "signal"), \
             mock.patch.object(m.signal, "pidfd_send_signal",
                               side_effect=lambda *_args: events.append("WORKER_PIDFD_SIGKILL")), \
             mock.patch.object(m, "pidfd_wait", return_value=True), \
             mock.patch.object(m, "note", side_effect=event):
            self.assertEqual(m.run_controller("qwda12345678", 1234), 0)

        def index(fragment):
            for n, line in enumerate(events):
                if fragment in line:
                    return n
            self.fail("missing controller event: " + fragment)

        self.assertLess(index("CTRL_ARMED"), index("CTRL_REVOKE_ATTEMPT"))
        self.assertLess(index("CTRL_REVOKE_ATTEMPT"),
                        index("CTRL_REVOKED"))
        self.assertLess(index("CTRL_REVOKED"), index("WORKER_PIDFD_SIGKILL"))
        self.assertLess(index("WORKER_PIDFD_SIGKILL"),
                        index("WORKER_EXIT_CONFIRMED"))
        self.assertGreaterEqual(sum(x == "NFT_DEFAULT_DENY_OR_REVOKE"
                                    for x in events), 2)

    def test_controller_fails_closed_if_nft_revoke_fails(self):
        """Never report REVOKED or kill worker when nft flush is unverified."""
        events = []
        def deny(_ip, _nft, _ns):
            events.append("DENY_CHECK")
            if len([x for x in events if x == "DENY_CHECK"]) > 1:
                raise RuntimeError("injected nft failure")

        with mock.patch.object(m.os, "geteuid", return_value=0), \
             mock.patch.object(m, "validate_ns", return_value=42), \
             mock.patch.object(m.shutil, "which", side_effect=["/usr/sbin/ip", "/usr/sbin/nft"]), \
             mock.patch.object(m.os, "pidfd_open", return_value=19), \
             mock.patch.object(m.os, "close"), \
             mock.patch.object(m, "require_worker", side_effect=["S", "T"]), \
             mock.patch.object(m, "pidfd_exited", return_value=False), \
             mock.patch.object(m, "ensure_denied", side_effect=deny), \
             mock.patch.object(m, "policy", return_value=True), \
             mock.patch.object(m.signal, "signal"), \
             mock.patch.object(m.signal, "pidfd_send_signal") as kill, \
             mock.patch.object(m, "note", side_effect=events.append):
            with self.assertRaises(RuntimeError):
                m.run_controller("qwda12345678", 1234)
            kill.assert_not_called()
            self.assertNotIn("CTRL_REVOKED reason=WORKER_STOP_OR_UNEXPECTED_STATE", events)
            self.assertIn("CTRL_ERROR_REVOKE_UNCONFIRMED", events)


if __name__ == "__main__":
    unittest.main(verbosity=2)
