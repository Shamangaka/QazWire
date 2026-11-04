#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# QazWire M1.7.2c: manual, privileged, isolated two-netns research lab.
# NEVER modifies host nftables/routing/interfaces. No production traffic,
# VPN, real keys, Qalqan, or claims of instantaneous watchdog-death A0.
set -euo pipefail

if (( EUID == 0 )); then
    echo "REFUSE: start as non-root; privilege only through explicit sudo" >&2
    exit 1
fi
if (( $# != 0 )); then
    echo "REFUSE: no caller-supplied namespace names or arguments" >&2
    exit 1
fi
for c in sudo ip nft python3 setpriv od mktemp grep; do
    command -v "$c" >/dev/null || { echo "MISSING: $c" >&2; exit 1; }
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
policy="$repo/docs/qazwire/lab/m172c-privsep-a0.nft"
peer_helper="$repo/scripts/m172b_netns_probe.py"
[[ -f "$policy" && -f "$peer_helper" ]] || exit 1
sudo -v

nonce=$(od -An -N4 -tx1 /dev/urandom | tr -d '[:space:]')
[[ "$nonce" =~ ^[0-9a-f]{8}$ ]] || exit 1
worker_ns="qwca$nonce"
peer_ns="qwcb$nonce"
dir=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/qazwire-m172c.XXXXXXXX")
chmod 0700 "$dir"
worker_created=0
peer_created=0

cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    for ns in "$worker_ns" "$peer_ns"; do
        if sudo -n ip netns list | grep -Eq "^$ns( |$)"; then
            # A short-lived privileged helper in THIS unique lab netns opens
            # pidfds and signals only tasks verified in the exact netns.
            sudo -n ip netns exec "$ns" python3 -B "$peer_helper" terminate-members || rc=1
            local drained=0
            for ((k=0; k<40; k++)); do
                if [[ -z "$(sudo -n ip netns pids "$ns" 2>/dev/null)" ]]; then
                    drained=1
                    break
                fi
                sleep 0.1
            done
            if (( drained == 0 )); then
                echo "CLEANUP_FAILURE: lab tasks remain in $ns" >&2
                rc=1
            fi
        fi
    done
    if (( worker_created )); then sudo -n ip netns del "$worker_ns" || rc=1; fi
    if (( peer_created )); then sudo -n ip netns del "$peer_ns" || rc=1; fi
    if sudo -n ip netns list | grep -Eq "^($worker_ns|$peer_ns)( |$)"; then
        echo "CLEANUP_FAILURE: namespace names still registered" >&2
        rc=1
    fi
    rm -rf -- "$dir" || rc=1
    if (( rc == 0 )); then echo "M1.7.2c CLEANUP PASS"; fi
    exit "$rc"
}
trap cleanup EXIT

if sudo -n ip netns list | grep -Eq "^($worker_ns|$peer_ns)( |$)"; then
    echo "REFUSE: random lab netns collision" >&2
    exit 1
fi
echo "========== SCOPE =========="
echo "worker_ns=$worker_ns peer_ns=$peer_ns; no host nftables operations"
echo "Worker runs UID/GID 65534 with no supplementary groups/capabilities"
echo "Privileged policy commands are issued by trusted launcher, not worker"

sudo -n ip netns add "$worker_ns"
worker_created=1
sudo -n ip netns add "$peer_ns"
peer_created=1
echo "========== LOAD KERNEL DROP BEFORE LINK UP =========="
sudo -n ip netns exec "$worker_ns" nft -f "$policy"
sudo -n ip netns exec "$worker_ns" nft list table inet qw_privsep_a0 > "$dir/ruleset.txt"
grep -Fq "policy drop" "$dir/ruleset.txt" || { echo "FAIL missing default drop"; exit 1; }
grep -Fq "privileged_grants" "$dir/ruleset.txt" || { echo "FAIL missing controlled grants"; exit 1; }

# All veth interfaces originate inside the new worker netns, not host netns.
sudo -n ip -n "$worker_ns" link add qwcw type veth peer name qwcp
sudo -n ip -n "$worker_ns" link set qwcp netns "$peer_ns"
sudo -n ip -n "$worker_ns" addr add 198.18.27.1/30 dev qwcw
sudo -n ip -n "$peer_ns" addr add 198.18.27.2/30 dev qwcp
sudo -n ip -n "$worker_ns" link set lo up
sudo -n ip -n "$peer_ns" link set lo up
sudo -n ip -n "$worker_ns" link set qwcw up
sudo -n ip -n "$peer_ns" link set qwcp up
[[ -z "$(sudo -n ip -n "$worker_ns" route show default)" ]] || {
    echo "FAIL unexpected default route" >&2
    exit 1
}

echo "========== START OFFLINE TWO-PORT ECHO PEER =========="
sudo -n ip netns exec "$peer_ns" python3 -B -u "$peer_helper" \
    serve --pidfile "$dir/peer.pid" > "$dir/peer.log" 2>&1 &
for ((i=0; i<60; i++)); do
    [[ -s "$dir/peer.pid" ]] && break
    sleep 0.1
done
[[ -s "$dir/peer.pid" ]] || { echo "FAIL echo peer not ready"; cat "$dir/peer.log"; exit 1; }

# Unlike the original M1.7.2b renewer, NO privileged task remains in the
# worker namespace. Each administrative nft transaction is invoked by the
# trusted host-side launcher; transport probes use an unrelated UID.
worker_exec() {
    sudo -n ip netns exec "$worker_ns" setpriv \
        --reuid=65534 --regid=65534 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs --reset-env "$@"
}

echo "========== CHECK ACTUAL WORKER SECURITY CONTEXT =========="
worker_exec /usr/bin/python3 -c '
import os
f = dict(line.split(":", 1) for line in open("/proc/self/status") if ":" in line)
keys = ("CapEff", "CapBnd", "CapAmb", "NoNewPrivs")
print("WORKER_UID=%d GROUPS=%r %s" %
      (os.getuid(), os.getgroups(), " ".join(k+"="+f[k].strip() for k in keys)), flush=True)
assert os.getuid() == 65534
assert os.getegid() == 65534
assert not os.getgroups()
assert int(f["CapEff"].strip(), 16) == 0
assert int(f["CapBnd"].strip(), 16) == 0
assert int(f["CapAmb"].strip(), 16) == 0
assert f["NoNewPrivs"].strip() == "1"
'
echo "========== ATTEMPT UNAUTHORIZED NFT POLICY MODIFICATION =========="
if worker_exec "$(command -v nft)" add element inet qw_privsep_a0 privileged_grants \
    '{ 198.18.27.2 timeout 8s }' > "$dir/denied-nft.txt" 2>&1; then
    echo "FAIL: unprivileged worker modified trusted nft policy!" >&2
    exit 1
fi
echo "UNPRIVILEGED_NFT_MUTATION_DENIED"
if sudo -n ip netns exec "$worker_ns" nft list set inet qw_privsep_a0 privileged_grants |
    grep -Fq '198.18.27.2'; then
    echo "FAIL: unauthorized nft attempt changed allow set" >&2
    exit 1
fi

# Fresh process per call, each direct UDP socket has UID 65534, zero caps.
direct_probe='
import os, socket, sys
port = int(sys.argv[1])
payload = b"QAZWIRE-M172B-PROBE:" + os.urandom(8).hex().encode("ascii")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.18.27.1", 0))
s.settimeout(0.4)
try:
    s.sendto(payload, ("198.18.27.2", port))
    data, peer = s.recvfrom(512)
except (OSError, TimeoutError) as err:
    print("DENIED port=%d pid=%d cause=%s" % (port, os.getpid(), type(err).__name__))
    sys.exit(1)
if data != payload or peer != ("198.18.27.2", port):
    print("FAIL: invalid echo reply")
    sys.exit(2)
print("ECHO port=%d pid=%d" % (port, os.getpid()))
'
probe() { worker_exec /usr/bin/python3 -c "$direct_probe" "$1"; }
deny() {
    local out
    if out=$(probe "$1" 2>&1); then
        echo "FAIL: direct UDP unexpectedly worked: $out" >&2
        exit 1
    fi
    echo "$out"
}
allow() {
    probe "$1" || { echo "FAIL: expected authorized direct UDP $1" >&2; exit 1; }
}
policy_add() {
    sudo -n ip netns exec "$worker_ns" nft add element \
        inet qw_privsep_a0 privileged_grants '{ 198.18.27.2 timeout 8s }'
}
policy_revoke() {
    sudo -n ip netns exec "$worker_ns" nft delete element \
        inet qw_privsep_a0 privileged_grants '{ 198.18.27.2 }'
}

echo "========== KERNEL DEFAULT DENY FOR UNPRIVILEGED DIRECT SOCKET =========="
deny 44000
deny 44001

echo "========== PRIVILEGED CONTROL-PLANE EXPLICIT GRANT =========="
policy_add
allow 44000
deny 44001
sudo -n ip netns exec "$worker_ns" nft list set inet qw_privsep_a0 privileged_grants |
    grep -F '198.18.27.2' > /dev/null || { echo "FAIL: no live authorization"; exit 1; }

echo "========== EXPLICIT POLICY REVOKE WHILE LEASE STILL LIVE =========="
policy_revoke
deny 44000
echo "EXPLICIT_REVOKE_PASS: direct UDP rejected after trusted nft delete"

echo "========== FRESH UNPRIVILEGED WORKER PROCESS AFTER REVOKE =========="
deny 44000
echo "FRESH_WORKER_DENIED"

echo "========== DEMONSTRATE RESIDUAL TTL EVEN AFTER ADMIN CLI EXITS =========="
policy_add
# The privileged nft CLI has exited before the next probe.
allow 44000
echo "CONFIRMED_LIMIT: kernel permit survives administrative CLI exit until revoked/expired"
sleep 9
deny 44000
echo "TTL_EXPIRY_PASS"

echo "M1.7.2c LAB PASS: distinct UID no capabilities, unauthorized nft mutation denied, kernel direct UDP A0 and explicit revocation"
echo "SECURITY LIMIT: no continuously protected privileged supervisor, no watchdog-crash immediate revoke, no in-flight packet proof."
echo "SECURITY LIMIT: UID 65534 and worker netns still share host filesystem view; no full production sandbox."
