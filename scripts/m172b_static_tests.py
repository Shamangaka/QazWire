#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure offline regressions; not a substitute for nftables/netns host tests."""
import importlib.util
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

spec = importlib.util.spec_from_file_location(
    "m172b_netns_probe", HERE / "m172b_netns_probe.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestM172BStaticContract(unittest.TestCase):
    def test_nft_policy_starts_with_real_kernel_default_deny(self):
        text = (ROOT / "docs/qazwire/lab/m172b-netns-a0.nft").read_text()
        self.assertIn("table inet qw_a0", text)
        self.assertIn("type filter hook output priority 0; policy drop;", text)
        self.assertIn("type filter hook input priority 0; policy drop;", text)
        self.assertIn("ip daddr @allow_dst udp dport 44000 counter accept", text)
        self.assertIn("flags timeout", text)
        self.assertIn("timeout 2s", text)
        self.assertNotIn("flush ruleset", "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        ))
        self.assertNotIn("policy accept", text)

    def test_no_extra_peer_or_proto(self):
        self.assertEqual(module.PEER, "198.18.27.2")
        self.assertEqual(module.WORKER, "198.18.27.1")
        self.assertEqual(module.PORTS, (44000, 44001))
        self.assertEqual(module.LEASE_SECONDS, 2)
        self.assertTrue(module.MAGIC.startswith(b"QAZWIRE-"))

    def test_exclusive_pid_file_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(pathlib.Path(root) / "service.pid")
            module.safe_pidfile(path)
            self.assertTrue(pathlib.Path(path).read_text().strip().isdigit())
            with self.assertRaises(FileExistsError):
                module.safe_pidfile(path)

    def test_pid_file_requires_absolute_path(self):
        with self.assertRaises(ValueError):
            module.safe_pidfile("relative.pid")

    def test_lab_script_scopes_nft_writes_to_namespace(self):
        text = (HERE / "qazwire-m172b-kernel-a0-netns-lab.sh").read_text()
        meaningful = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertIn('sudo -n ip netns exec "$worker_ns" nft -f "$policy"', text)
        self.assertNotIn("sudo nft flush ruleset", meaningful)
        self.assertNotIn("sudo nft add table", meaningful)
        self.assertNotIn("sudo ip route add default", meaningful)
        self.assertIn('--reuid "$uid" --regid "$gid" --clear-groups', text)
        self.assertIn('kill-refresher --pid "$watch_pid"', text)\n        self.assertNotIn("sudo -n kill -KILL", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
