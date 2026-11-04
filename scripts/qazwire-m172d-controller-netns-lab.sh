#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# QazWire M1.7.2d: manual, persistent root policy controller lab.
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
worker_ns="qwda$nonce"
peer_ns="qwdb$nonce"
dir=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/qazwire-m172d.XXXXXXXX")
chmod 0700 "$dir"
worker_created=0
peer_created=0
controller_a=""
controller_b=""
controller="$repo/scripts/m172d_controller.py"
worker_source=$(cat "$repo/scripts/m172d_worker.py")
[[ -f "$controller" && -n "$worker_source" ]] || exit 1

cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    # The persistent root controllers live OUTSIDE worker netns.
    # Terminate only verified controller identities through Linux pidfds.
    for pid in "$controller_a" "$controller_b"; do
        if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
            sudo -n python3 -B "$controller" signal --ns "$worker_ns" \
                --pid "$pid" --target controller --action KILL >/dev/null 2>&1 || true
        fi
    done
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

# Unlike M1.7.2c, policy authorization here belongs to a long-running
# root controller in HOST netns; no privileged renewer is left in worker ns.
# It always calls nft through "ip netns exec" and monitors worker by pidfd.
start_worker() {
    local label=$1
    local logfile="$dir/worker-$label.log"
    worker_exec /usr/bin/python3 -B -u -c "$worker_source" m172d_worker.py \
        >"$logfile" 2>&1 &
    local line=""
    for ((i=0; i<90; i++)); do
        if [[ -s "$logfile" ]]; then
            line=$(grep -m1 '^WORKER_READY_PID=[1-9][0-9]*$' "$logfile" || true)
            [[ -n "$line" ]] && break
        fi
        sleep 0.1
    done
    [[ -n "$line" ]] || { cat "$logfile"; echo "FAIL: worker not ready" >&2; exit 1; }
    worker_pid="${line#WORKER_READY_PID=}"
    sudo -n ip netns pids "$worker_ns" | grep -Fxq "$worker_pid" ||
        { echo "FAIL: worker not in the exact namespace" >&2; exit 1; }
    echo "WORKER_$label PID=$worker_pid"
}

start_controller() {
    local label=$1
    local pid=$2
    local logfile="$dir/ctrl-$label.log"
    sudo -n python3 -B -u "$controller" serve --ns "$worker_ns" \
        --worker-pid "$pid" >"$logfile" 2>&1 &
    local line=""
    for ((i=0; i<90; i++)); do
        if [[ -s "$logfile" ]]; then
            line=$(grep -m1 '^CONTROLLER_READY_PID=[1-9][0-9]*$' "$logfile" || true)
            if grep -q '^LAB_CONTROLLER_FAIL:' "$logfile"; then
                cat "$logfile"; echo "FAIL: controller initialization" >&2
                exit 1
            fi
            if [[ -n "$line" ]] && grep -q '^CTRL_ARMED lease=2s$' "$logfile"; then
                break
            fi
        fi
        sleep 0.1
    done
    [[ -n "$line" ]] && grep -q '^CTRL_ARMED lease=2s$' "$logfile" ||
        { cat "$logfile"; echo "FAIL: root controller not armed" >&2; exit 1; }
    if [[ "$label" == A ]]; then controller_a="${line#CONTROLLER_READY_PID=}"; fi
    if [[ "$label" == B ]]; then controller_b="${line#CONTROLLER_READY_PID=}"; fi
    echo "CONTROLLER_$label PID=${line#CONTROLLER_READY_PID=}"
}

echo "========== INITIAL KERNEL DEFAULT DENY =========="
deny 44000
deny 44001

echo "========== PHASE A: WORKER SIGSTOP -> ROOT CONTROLLER REVOKE =========="
start_worker A
worker_a="$worker_pid"
start_controller A "$worker_a"
allow 44000
deny 44001
sudo -n python3 -B "$controller" signal --ns "$worker_ns" \
    --pid "$worker_a" --target worker --action STOP
phase_a=0
for ((i=0; i<120; i++)); do
    if grep -q '^WORKER_EXIT_CONFIRMED$' "$dir/ctrl-A.log"; then
        phase_a=1
        break
    fi
    sleep 0.1
done
cat "$dir/ctrl-A.log"
if (( phase_a != 1 )); then
    echo "FAIL: controller did not confirm post-fault revoke + worker exit" >&2
    exit 1
fi
python3 - "$dir/ctrl-A.log" <<'PY'
from pathlib import Path
import sys
lines=Path(sys.argv[1]).read_text().splitlines()
events=[
    "CTRL_ARMED lease=2s",
    "CTRL_REVOKE_ATTEMPT reason=WORKER_STOP_OR_UNEXPECTED_STATE",
    "CTRL_REVOKED reason=WORKER_STOP_OR_UNEXPECTED_STATE",
    "WORKER_KILL_SENT",
    "WORKER_EXIT_CONFIRMED",
]
positions=[lines.index(x) for x in events]
assert positions == sorted(positions), "revocation must precede SIGKILL"
print("REVOKE_BEFORE_WORKER_KILL_PASS")
PY
deny 44000
echo "A0_EXPLICIT_REVOKE_PASS"
deny 44000
echo "NEW_DIRECT_SOCKET_DENIED_AFTER_WORKER_FAULT"

echo "========== PHASE B: CONTROLLER SIGKILL -> RESIDUAL KERNEL LEASE =========="
start_worker B
worker_b="$worker_pid"
start_controller B "$worker_b"
allow 44000
sudo -n python3 -B "$controller" signal --ns "$worker_ns" \
    --pid "$controller_b" --target controller --action KILL
echo "CONTROLLER_PIDFD_SIGKILL_SENT"
if probe 44000 >"$dir/after-death.txt" 2>&1; then
    echo "KNOWN_GAP_CONFIRMED: kernel UDP grant survived controller SIGKILL"
else
    echo "immediate packet denied; absence of residual permit is NOT proven"
fi
sleep 3
deny 44000
echo "POST_CONTROLLER_DEATH_TTL_DENY_PASS"
deny 44000
echo "FRESH_DIRECT_SOCKET_DENIED"
sudo -n python3 -B "$controller" signal --ns "$worker_ns" \
    --pid "$worker_b" --target worker --action KILL
echo "M1.7.2d LAB PASS: root controller revoked on worker STOP; unprivileged direct UDP denied after revoke"
echo "SECURITY LIMIT: SIGKILL controller leaves existing kernel grant for residual TTL; no instantaneous A0 guarantee."
echo "SECURITY LIMIT: root controller script and launcher are interactive USER-owned lab files, not hardened production services."
