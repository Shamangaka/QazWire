#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure static regressions. These do NOT verify kernel namespace enforcement."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/qazwire-m172c-privsep-kernel-a0-lab.sh"
POLICY = ROOT / "docs/qazwire/lab/m172c-privsep-a0.nft"


class M172CContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf8")
        cls.policy = POLICY.read_text(encoding="utf8")

    def test_no_host_nftables_or_default_route_modifications(self):
        cmds = "\n".join(
            line.strip() for line in self.script.splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn("sudo nft flush ruleset", cmds)
        self.assertNotIn("sudo nft add", cmds)
        self.assertNotIn("sudo ip route add", cmds)
        self.assertIn('sudo -n ip netns exec "$worker_ns" nft -f "$policy"', cmds)
        self.assertIn('sudo -n ip -n "$worker_ns" link add qwcw', cmds)

    def test_kernel_default_drop_and_single_expiring_grant(self):
        p = self.policy
        self.assertIn("table inet qw_privsep_a0", p)
        self.assertEqual(p.count("policy drop;"), 2)
        self.assertIn("flags timeout", p)
        self.assertIn("timeout 8s", p)
        self.assertIn("ip daddr @privileged_grants udp dport 44000", p)
        self.assertNotIn("flush ruleset", "\n".join(
            x for x in p.splitlines() if not x.lstrip().startswith("#")
        ))
        self.assertNotIn("policy accept", p)

    def test_worker_drops_all_linux_privileges(self):
        s = self.script
        self.assertIn("--reuid=65534 --regid=65534 --clear-groups", s)
        self.assertIn("--inh-caps=-all --ambient-caps=-all --bounding-set=-all", s)
        self.assertIn("--no-new-privs --reset-env", s)
        self.assertIn('assert int(f["CapEff"].strip(), 16) == 0', s)
        self.assertIn('assert int(f["CapBnd"].strip(), 16) == 0', s)
        self.assertIn('assert f["NoNewPrivs"].strip() == "1"', s)

    def test_worker_mutation_is_negative_and_revoke_is_explicit(self):
        s = self.script
        self.assertIn('UNPRIVILEGED_NFT_MUTATION_DENIED', s)
        self.assertIn('worker_exec "$(command -v nft)" add element', s)
        self.assertIn('nft delete element', s)
        self.assertIn("EXPLICIT_REVOKE_PASS", s)
        self.assertIn("FRESH_WORKER_DENIED", s)
        self.assertIn("TTL_EXPIRY_PASS", s)

    def test_cleanup_verifies_namespace_tasks_and_names(self):
        s = self.script
        self.assertIn("terminate-members", s)
        self.assertIn('sudo -n ip netns pids "$ns"', s)
        self.assertIn('sudo -n ip netns del "$worker_ns"', s)
        self.assertIn('sudo -n ip netns del "$peer_ns"', s)
        self.assertIn("CLEANUP_FAILURE", s)
        self.assertIn('if (( EUID == 0 ))', s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
