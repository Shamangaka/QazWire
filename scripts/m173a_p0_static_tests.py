#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1.7.3a P0 offline contract tests. No sudo, nft, network or namespaces."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "scripts/qazwire-m173a-sameuid-adversary-lab.sh"
POLICY = ROOT / "docs/qazwire/lab/m172e-broker-owned-a0.nft"
BASELINE = ROOT / "scripts/qazwire-m172e-broker-kernel-a0-netns-lab.sh"


class SameUidAdversaryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = LAB.read_text(encoding="utf-8")
        cls.nft = POLICY.read_text(encoding="utf-8")

    def test_isolated_new_namespaces_only(self):
        for item in ('broker_ns="qwga$nonce"', 'peer_ns="qwgb$nonce"',
                     'sudo -n ip netns add "$broker_ns"',
                     'sudo -n ip netns add "$peer_ns"',
                     'sudo -n ip netns del "$broker_ns"',
                     'sudo -n ip netns del "$peer_ns"'):
            self.assertIn(item, self.lab)
        self.assertNotIn('ip link add qwg0', self.lab)
        self.assertIn('ip -n "$broker_ns" link add qwg0', self.lab)
        self.assertNotIn('sudo nft flush ruleset', self.lab)
        self.assertNotIn('pkill ', self.lab)
        self.assertNotIn('killall ', self.lab)

    def test_kernel_policy_is_same_baseline_with_no_worker_exemption(self):
        self.assertIn('nft -f "$policy"', self.lab)
        self.assertIn('m172e-broker-owned-a0.nft', self.lab)
        self.assertIn('meta skuid 65533 counter accept', self.nft)
        self.assertNotIn('meta skuid 65534', self.nft)
        self.assertIn('policy drop;', self.nft)
        self.assertIn('meta skuid 65533', BASELINE.read_text())

    def test_positive_bypass_proof_and_two_negative_controls(self):
        self.assertIn('run_uid 65534 probe --port 44000', self.lab)
        self.assertIn('run_uid 65533 probe --port 44000', self.lab)
        self.assertIn('run_uid 65533 probe --port 44001', self.lab)
        self.assertIn('M173A_P0_SAME_UID_BYPASS_CONFIRMED', self.lab)
        self.assertIn('M173A_P0_WORKER_UID_DENIED', self.lab)
        self.assertIn('M173A_P0_PORT_SCOPE_CONFIRMED', self.lab)
        self.assertIn('expect_code_and_marker 0 "ECHO port=44000"', self.lab)
        self.assertIn('expect_code_and_marker 1 "NO_ECHO port=44000 cause=PermissionError"', self.lab)

    def test_no_implicit_privileged_run_or_host_routes(self):
        self.assertIn('EUID == 0 || $# != 0', self.lab)
        self.assertIn('sudo -v', self.lab)
        self.assertIn('sudo -n', self.lab)
        self.assertIn('route show default', self.lab)
        self.assertNotRegex(self.lab, r'(?m)^[^#\n]*(?:ip route add|ip -6 route add|ip link set dev eth|wg-quick)')
        self.assertIn('M1.7.3a P0 CLEANUP PASS', self.lab)
        self.assertIn('M1.7.3a P0 EXPECTED VULNERABILITY REPRODUCED', self.lab)
        self.assertNotIn('M1.7.3a SECURITY PASS', self.lab)

    def test_capless_foreign_uid(self):
        for token in ('--reuid="$uid"', '--regid="$uid"', '--clear-groups',
                      '--inh-caps=-all', '--ambient-caps=-all',
                      '--bounding-set=-all', '--no-new-privs'):
            self.assertIn(token, self.lab)
        self.assertIn('-c "$probe_source" "$@"', self.lab)
        self.assertNotIn('-c "$probe_source" m172b_netns_probe.py', self.lab)


if __name__ == "__main__":
    unittest.main(verbosity=2)
