#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline-only tests for M1.7.2e broker-owned egress. NEVER calls sudo/nft."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
BROKER = ROOT / "scripts/m172e_broker.py"
KILLER = ROOT / "scripts/m172e_broker_pidfd_kill.py"
POLICY = ROOT / "docs/qazwire/lab/m172e-broker-owned-a0.nft"
LAB = ROOT / "scripts/qazwire-m172e-broker-kernel-a0-netns-lab.sh"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


broker = load("m172e_broker_for_test", BROKER)
killer = load("m172e_killer_for_test", KILLER)


class BrokerOwnedEgressContract(unittest.TestCase):
    def test_socket_owner_policy_denies_all_other_uids(self):
        nft = POLICY.read_text()
        self.assertIn("type filter hook output priority filter; policy drop;", nft)
        self.assertIn("type filter hook input priority filter; policy drop;", nft)
        self.assertIn("meta skuid 65533 counter accept", nft)
        self.assertIn("ip daddr 198.18.27.2 udp dport 44000", nft)
        self.assertNotIn("meta skuid 65534", nft)
        self.assertNotIn("timeout", nft)
        self.assertNotIn("flush ruleset", nft)
        self.assertNotIn("ct state established", nft)

    def test_nonce_is_strict_and_not_a_path(self):
        self.assertTrue(broker.address("1234abcd").startswith("\0qw_m172e_"))
        for value in ("", "1", "A" * 8, "../123456", "x;rm -f", "a" * 9):
            with self.assertRaises(ValueError):
                broker.address(value)

    def test_daemon_parent_exits_before_child_owns_udp(self):
        with mock.patch.object(broker, "verify_uid") as verify, \
             mock.patch.object(broker.os, "fork", return_value=123) as fork, \
             mock.patch.object(broker.os, "setsid") as session:
            self.assertEqual(broker.serve("1234abcd"), 0)
            verify.assert_called_once_with(65533)
            fork.assert_called_once()
            session.assert_not_called()

    def test_denied_direct_socket_is_recognized(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        fake.sendto.side_effect = PermissionError("nft DROP")
        with mock.patch.object(broker, "verify_uid"), \
             mock.patch.object(broker.socket, "socket", return_value=fake):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(broker.send_direct(44000), 12)
        self.assertIn("DIRECT_DENIED port=44000", output.getvalue())

    def test_dead_broker_ipc_cannot_be_reported_as_success(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        fake.connect.side_effect = ConnectionRefusedError("broker dead")
        with mock.patch.object(broker, "verify_uid"), \
             mock.patch.object(broker.socket, "socket", return_value=fake):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(broker.request("1234abcd"), 12)
        self.assertIn("IPC_UNAVAILABLE", output.getvalue())

    def test_unauthorized_peer_uid_is_rejected_before_udp_send(self):
        import struct
        fake_unix = mock.MagicMock()
        fake_unix.__enter__.return_value = fake_unix
        fake_unix.getsockopt.return_value = struct.pack("3i", 4001, 65532, 65532)
        fake_unix_server = mock.MagicMock()
        fake_unix_server.accept.side_effect = [
            (fake_unix, None),
            KeyboardInterrupt(),
        ]
        fake_udp = mock.MagicMock()
        with mock.patch.object(broker, "verify_uid"), \
             mock.patch.object(broker.os, "fork", return_value=0), \
             mock.patch.object(broker.os, "setsid"), \
             mock.patch.object(broker.os, "getsid", return_value=123), \
             mock.patch.object(broker.os, "getpgid", return_value=123), \
             mock.patch.object(broker.os, "getpid", return_value=123), \
             mock.patch.object(broker, "close_stdio"), \
             mock.patch.object(broker.socket, "socket",
                               side_effect=[fake_unix_server, fake_udp]):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    broker.serve("1234abcd")
        fake_unix.sendall.assert_called_once_with(b"DENY:PEERCRED")
        fake_udp.sendto.assert_not_called()

    def test_pidfd_killer_refuses_host_and_unknown_namespace(self):
        for ns, nonce in (("default", "1234abcd"),
                          ("qwfa1234abcd", "00000000"),
                          ("qwfa1234abcd/../", "1234abcd")):
            with mock.patch.object(killer.os, "geteuid", return_value=0):
                with self.assertRaises(ValueError):
                    killer.send(ns, nonce, 1000)

    def test_broker_killer_and_lab_are_strictly_scoped(self):
        shell = LAB.read_text()
        source = KILLER.read_text()
        self.assertIn('worker_ns="qwfa$nonce"', shell)
        self.assertIn('peer_ns="qwfb$nonce"', shell)
        self.assertIn('"$worker_ns" nft -f "$policy"', shell)
        self.assertIn("--reuid=\"$uid\" --regid=\"$uid\" --clear-groups", shell)
        self.assertIn("--inh-caps=-all --ambient-caps=-all --bounding-set=-all", shell)
        self.assertIn("BROKER_RELAY_ECHO_OK", shell)
        self.assertIn("POST_BROKER_SIGKILL_DIRECT_UDP_DENIED", shell)
        self.assertIn("POST_BROKER_SIGKILL_IPC_UNAVAILABLE", shell)
        self.assertIn("M1.7.2e CLEANUP PASS", shell)
        self.assertIn('signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)',
                      source)
        self.assertIn('os.stat(f"/proc/{pid}/ns/net").st_ino != target_inode',
                      source)
        self.assertNotIn("sudo nft flush ruleset", shell)
        self.assertNotIn("pkill ", shell)
        self.assertNotIn("killall ", shell)

    def test_owner_only_broker_uid_and_no_fd_handoff(self):
        src = BROKER.read_text()
        self.assertIn("SO_PEERCRED", src)
        self.assertIn("uid != WORKER_UID or gid != WORKER_UID", src)
        self.assertIn("verify_uid(BROKER_UID)", src)
        self.assertIn("verify_uid(WORKER_UID)", src)
        self.assertIn("udp_sock.sendto(payload, REMOTE)", src)
        self.assertNotIn("sendmsg(", src)
        self.assertNotIn("SCM_RIGHTS", src)
        self.assertNotIn("shell=True", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
