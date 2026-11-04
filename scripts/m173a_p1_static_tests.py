#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1.7.3a P1 unprivileged checks: never sudo, nft, or create netns."""
import contextlib
import errno
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "scripts"
LAB = HERE / "qazwire-m173a-p1-separated-netns-lab.sh"
BROKER = HERE / "m173a_p1_broker.py"
KILLER = HERE / "m173a_p1_pidfd_kill.py"
ECHO = HERE / "m173a_p1_echo.py"
POLICY = ROOT / "docs/qazwire/lab/m173a-p1-broker-netns.nft"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


broker = load("m173a_p1_broker_test", BROKER)
killer = load("m173a_p1_pidfd_test", KILLER)
echo_peer = load("m173a_p1_echo_test", ECHO)


class SeparatedNamespaceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = LAB.read_text(encoding="utf-8")
        cls.nft = POLICY.read_text(encoding="utf-8")
        cls.source = BROKER.read_text(encoding="utf-8")

    def test_three_namespace_separation(self):
        for token in ('worker_ns="qwha$nonce"', 'broker_ns="qwhb$nonce"',
                      'peer_ns="qwhc$nonce"',
                      'sudo -n ip netns add "$worker_ns"',
                      'sudo -n ip netns add "$broker_ns"',
                      'sudo -n ip netns add "$peer_ns"',
                      'ip -n "$broker_ns" link add qwhb0',
                      'ip -n "$broker_ns" link set qwhc0 netns "$peer_ns"',
                      'ip -n "$worker_ns" -o link show',
                      'ip -n "$worker_ns" -4 route show table main'):
            self.assertIn(token, self.shell)
        self.assertNotIn('ip -n "$worker_ns" link add', self.shell)
        self.assertNotIn('ip -n "$worker_ns" addr add', self.shell)
        self.assertNotIn('sudo nft flush ruleset', self.shell)

    def test_broker_policy_default_drop_only_inside_broker(self):
        self.assertIn('ip netns exec "$broker_ns" nft -f "$policy"', self.shell)
        self.assertNotIn('ip netns exec "$worker_ns" nft -f "$policy"', self.shell)
        self.assertIn('meta skuid 65533 counter accept', self.nft)
        self.assertNotIn('meta skuid 65534', self.nft)
        self.assertEqual(self.nft.count('policy drop;'), 2)
        self.assertIn('udp dport 44000', self.nft)
        self.assertNotIn('ct state established', self.nft)

    def test_broker_and_echo_use_identical_fixed_magic(self):
        self.assertEqual(broker.PREFIX, echo_peer.MAGIC)
        self.assertEqual(broker.REMOTE, ("198.18.27.2", 44000))
        self.assertEqual(echo_peer.PORTS, (44000, 44001))
        self.assertIn('conn.getsockopt(', self.source)
        self.assertIn('socket.SO_PEERCRED', self.source)
        self.assertIn('pid < 2 or uid != WORKER_UID or gid != WORKER_GID',
                      self.source)
        self.assertNotIn('SCM_RIGHTS', self.source)
        self.assertNotIn('sendmsg(', self.source)

    def test_ipc_file_system_ownership_is_enforced(self):
        for token in ('chown 65533:65534 "$dir/ipc"',
                      'chmod 0710 "$dir/ipc"',
                      'stat -c', '65533:65534:710',
                      '65533:65534:660'):
            self.assertIn(token, self.shell)
        self.assertIn('0o710', self.source)
        self.assertIn('0o660', self.source)
        self.assertIn('0o117', self.source)
        self.assertIn('socket.AF_UNIX', self.source)
        self.assertNotIn('SOCKET_PREFIX = "\\0', self.source)

    def test_exact_limited_socket_path(self):
        valid = "/tmp/qazwire-m173a-p1.ABC123ab/ipc/broker.sock"
        self.assertEqual(str(broker.checked_path(valid)), valid)
        for invalid in ("", "/tmp/broker.sock", "/run/netns/broker.sock",
                        "/tmp/qazwire-m173a-p1.12345678/../socket",
                        "/tmp/qazwire-m173a-p1.1234/ipc/broker.sock"):
            with self.assertRaises(ValueError):
                broker.checked_path(invalid)

    def test_pidfd_command_uses_genuine_nul_framing(self):
        path = "/tmp/qazwire-m173a-p1.ABC123ab/ipc/broker.sock"
        source = BROKER.read_bytes().rstrip(bytes([10]))
        expected_parts = [
            b"/usr/bin/python3", b"-B", b"-u", b"-c", source,
            b"serve", b"--socket-path", path.encode("ascii")
        ]
        cmdline = bytes([0]).join(expected_parts) + bytes([0])
        self.assertEqual(cmdline.count(bytes([0])), 8)
        self.assertTrue(killer.matches_argv(cmdline, path))
        self.assertFalse(killer.matches_argv(cmdline, path.replace("ABC", "BAD")))
        self.assertFalse(killer.matches_argv(cmdline + b"extra\0", path))
        self.assertFalse(killer.matches_argv(
            cmdline.replace(source, b"print('not broker')", 1), path))
        self.assertNotIn("SCM_RIGHTS", KILLER.read_text())

    def test_direct_failure_is_exact_enetunreach(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        fake.sendto.side_effect = OSError(errno.ENETUNREACH, "no route")
        with mock.patch.object(broker, "verify_identity"), \
             mock.patch.object(broker.socket, "socket", return_value=fake):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(broker.direct(65534, 65534, 44000), 12)
        self.assertIn("P1_DIRECT_NO_ROUTE", output.getvalue())
        fake.sendto.side_effect = OSError(errno.EADDRNOTAVAIL, "bad address")
        with mock.patch.object(broker, "verify_identity"), \
             mock.patch.object(broker.socket, "socket", return_value=fake):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(broker.direct(65534, 65534, 44000), 13)
        self.assertIn("P1_DIRECT_INCONCLUSIVE", output.getvalue())

    def test_fail_closed_evidence_and_cleanup(self):
        for token in (
            'EUID == 0 || $# != 0', 'sudo -v', 'sudo -n',
            'M173A_P1_WORKER_NO_UNDERLAY_AND_NO_IPV4_ROUTES',
            'M173A_P1_RELAY_PASS',
            'M173A_P1_DIRECT_AND_IPC_NEGATIVE_CONTROLS_PASS',
            'M173A_P1_AFTER_BROKER_DEATH_FAIL_CLOSED',
            'M1.7.3a P1 CLEANUP PASS',
            'sudo -n ip netns del "$worker_ns"',
            'sudo -n ip netns del "$broker_ns"',
            'sudo -n ip netns del "$peer_ns"',
        ):
            self.assertIn(token, self.shell)
        self.assertNotIn('pkill ', self.shell)
        self.assertNotIn('killall ', self.shell)
        self.assertNotIn('sudo nft ', self.shell)

    def test_untrusted_same_uid_worker_negative_case(self):
        self.assertIn('run_id "$worker_ns" 65533 65533 direct', self.shell)
        self.assertIn('run_id "$worker_ns" 65534 65534 direct', self.shell)
        self.assertIn('run_id "$worker_ns" 65532 65534 relay', self.shell)
        self.assertIn('run_id "$worker_ns" 65532 65532 relay', self.shell)
        self.assertIn("P1_IPC_UNAUTHORIZED_PEER_DENIED", self.source)
        self.assertIn("P1_IPC_PATH_DENIED", self.source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
