#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# QazWire M1.7.2e: isolated broker-owned UDP socket fail-closed experiment.
# NOT a VPN or trusted production service. Does NOT modify host nft/routing.
set -Eeuo pipefail
trap 'printf "M172E_FAILED_LINE=%s CHILD_EXIT=%s\n" "$LINENO" "$?" >&2' ERR

if (( EUID == 0 || $# != 0 )); then
    echo "STOP: run as normal user without arguments" >&2
    exit 1
fi
for tool in sudo ip nft python3 setpriv od ps grep; do
    command -v "$tool" >/dev/null || { echo "MISSING $tool" >&2; exit 1; }
done

repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
policy="$repo/docs/qazwire/lab/m172e-broker-owned-a0.nft"
broker="$repo/scripts/m172e_broker.py"
killer="$repo/scripts/m172e_broker_pidfd_kill.py"
helper="$repo/scripts/m172b_netns_probe.py"
[[ -f "$policy" && -f "$broker" && -f "$killer" && -f "$helper" ]] || exit 1

sudo -v
nonce=$(od -An -N4 -tx1 /dev/urandom | tr -d '[:space:]')
[[ "$nonce" =~ ^[0-9a-f]{8}$ ]] || exit 1
worker_ns="qwfa$nonce"
peer_ns="qwfb$nonce"
dir=$(mktemp -d "/tmp/qazwire-m172e.XXXXXXXX")
chmod 0700 "$dir"
worker_created=0
peer_created=0
broker_pid=""
echo "========== SCOPE =========="
echo "worker_ns=$worker_ns peer_ns=$peer_ns"
echo "No host nft, routing, physical interfaces, keys, VPN or Internet."

cleanup() {
    local result=$?
    trap - EXIT
    set +e
    echo "========== SCOPE CLEANUP =========="
    if [[ "$broker_pid" =~ ^[1-9][0-9]*$ ]]; then
        sudo -n python3 -B "$killer" --namespace "$worker_ns" \
            --nonce "$nonce" --pid "$broker_pid" >/dev/null 2>&1 || true
    fi
    for ns in "$worker_ns" "$peer_ns"; do
        if sudo -n ip netns list | grep -Eq "^$ns([[:space:]]|$)"; then
            sudo -n ip netns exec "$ns" python3 -B "$helper" terminate-members || result=1
            local cleared=0
            for ((i=0; i<30; i++)); do
                if [[ -z "$(sudo -n ip netns pids "$ns" 2>/dev/null)" ]]; then
                    cleared=1
                    break
                fi
                sleep 0.1
            done
            if (( cleared == 0 )); then
                echo "LAB_CLEANUP_SCOPE_ESCALATION $ns"
                sudo -n ip netns exec "$ns" python3 -B "$helper" \
                    terminate-members --force-kill || result=1
                for ((i=0; i<50; i++)); do
                    if [[ -z "$(sudo -n ip netns pids "$ns" 2>/dev/null)" ]]; then
                        cleared=1
                        break
                    fi
                    sleep 0.1
                done
            fi
            if (( cleared == 0 )); then
                echo "CLEANUP_FAILURE: namespace processes remain $ns" >&2
                result=1
            fi
        fi
    done
    if (( worker_created )); then
        sudo -n ip netns del "$worker_ns" || result=1
    fi
    if (( peer_created )); then
        sudo -n ip netns del "$peer_ns" || result=1
    fi
    if sudo -n ip netns list | grep -Eq "^($worker_ns|$peer_ns)([[:space:]]|$)"; then
        echo "CLEANUP_FAILURE: lab namespace names remain" >&2
        result=1
    fi
    if (( result == 0 )); then
        rm -rf -- "$dir" || result=1
        if (( result == 0 )); then
            echo "M1.7.2e CLEANUP PASS"
        fi
    fi
    if (( result != 0 )); then
        echo "M1.7.2e FAIL exit=$result; private diagnostics preserved $dir" >&2
    fi
    exit "$result"
}
trap cleanup EXIT

if sudo -n ip netns list | grep -Eq "^($worker_ns|$peer_ns)([[:space:]]|$)"; then
    echo "STOP: random lab namespace collision" >&2
    exit 1
fi
sudo -n ip netns add "$worker_ns"
worker_created=1
sudo -n ip netns add "$peer_ns"
peer_created=1

# Install worker OUTPUT default DROP BEFORE any interfaces are up.
sudo -n ip netns exec "$worker_ns" nft -f "$policy"
sudo -n ip netns exec "$worker_ns" nft list table inet qw_broker_a0 > "$dir/nft.txt"
grep -Fq "meta skuid 65533" "$dir/nft.txt" || {
    echo "FAIL: no broker-socket-only rule" >&2
    exit 1
}
grep -Fq "policy drop" "$dir/nft.txt" || {
    echo "FAIL: missing default DROP" >&2
    exit 1
}

# Veth originated only in the two BRAND NEW network namespaces.
sudo -n ip -n "$worker_ns" link add qwew type veth peer name qwep
sudo -n ip -n "$worker_ns" link set qwep netns "$peer_ns"
sudo -n ip -n "$worker_ns" addr add 198.18.27.1/30 dev qwew
sudo -n ip -n "$peer_ns" addr add 198.18.27.2/30 dev qwep
sudo -n ip -n "$worker_ns" link set lo up
sudo -n ip -n "$peer_ns" link set lo up
sudo -n ip -n "$worker_ns" link set qwew up
sudo -n ip -n "$peer_ns" link set qwep up
[[ -z "$(sudo -n ip -n "$worker_ns" route show default)" ]] || {
    echo "FAIL: worker has a default route" >&2
    exit 1
}
echo "KERNEL_DEFAULT_DROP_LOADED"

sudo -n ip netns exec "$peer_ns" python3 -B -u "$helper" serve \
    --pidfile "$dir/peer.pid" > "$dir/peer.log" 2>&1 &
for ((i=0; i<70; i++)); do
    [[ -s "$dir/peer.pid" ]] && break
    sleep 0.1
done
[[ -s "$dir/peer.pid" ]] || {
    cat "$dir/peer.log"; echo "FAIL echo peer startup" >&2; exit 1;
}

run_uid() {
    local uid=$1
    shift
    sudo -n ip netns exec "$worker_ns" setpriv \
        --reuid="$uid" --regid="$uid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs --reset-env "$@"
}
worker() { run_uid 65534 /usr/bin/python3 -B -u "$broker" "$@"; }
unauthorized() { run_uid 65532 /usr/bin/python3 -B -u "$broker" "$@"; }

expect_code_and_line() {
    local wanted=$1 marker=$2
    shift 2
    local output rc=0
    output=$("$@" 2>&1) || rc=$?
    echo "$output"
    if (( rc != wanted )) || [[ "$output" != *"$marker"* ]]; then
        echo "FAIL: expected exit=$wanted marker=$marker; observed rc=$rc" >&2
        exit 1
    fi
}
echo "========== NO WORKER DIRECT NETWORK BEFORE BROKER =========="
expect_code_and_line 12 "DIRECT_DENIED port=44000" worker direct --port 44000
expect_code_and_line 12 "DIRECT_DENIED port=44001" worker direct --port 44001

echo "========== START DETACHED CAPLESS BROKER UID65533 =========="
# sudo-monitored launcher MUST EXIT before broker SIGKILL. Broker forked child
# is a separate session leader with no inherited TTY/stdout descriptors.
run_uid 65533 /usr/bin/python3 -B -u "$broker" serve --nonce "$nonce" \
    > "$dir/broker.log" 2>&1 &
launcher_pid=$!
found=""
for ((i=0; i<90; i++)); do
    if [[ -s "$dir/broker.log" ]]; then
        found=$(grep -m1 '^BROKER_READY_PID=[1-9][0-9]*$' "$dir/broker.log" || true)
        [[ -n "$found" ]] && break
    fi
    sleep 0.1
done
[[ -n "$found" ]] || { cat "$dir/broker.log"; echo "FAIL broker readiness" >&2; exit 1; }
if ! wait "$launcher_pid"; then
    echo "FAIL: sudo broker launcher did not exit" >&2
    exit 1
fi
broker_pid="$(printf '%s\n' "$found" | cut -d= -f2)"
sid=$(ps -o sid= -p "$broker_pid" | tr -d '[:space:]')
pgid=$(ps -o pgid= -p "$broker_pid" | tr -d '[:space:]')
[[ "$sid" == "$broker_pid" && "$pgid" == "$broker_pid" ]] || {
    echo "FAIL: broker remains in sudo session" >&2; exit 1;
}
sudo -n ip netns pids "$worker_ns" | grep -Fxq "$broker_pid" || {
    echo "FAIL: broker not in worker namespace" >&2; exit 1;
}
echo "BROKER_DETACHED_SESSION_LEADER PID=$broker_pid SID=$sid PGID=$pgid"

echo "========== ALLOW RELAY ONLY; DIRECT SOCKET ALWAYS DENIED =========="
expect_code_and_line 12 "DIRECT_DENIED port=44000" worker direct --port 44000
expect_code_and_line 12 "DIRECT_DENIED port=44001" worker direct --port 44001
expect_code_and_line 0 "BROKER_RELAY_ECHO_OK" worker relay --nonce "$nonce"
expect_code_and_line 14 "IPC_UNAUTHORIZED_PEER_DENIED" \
    unauthorized relay --nonce "$nonce" --unauthorized
echo "BROKER_UID_ONLY_RELAY_PASS"

echo "========== KILL BROKER VIA VERIFIED PIDFD =========="
sudo -n python3 -B "$killer" --namespace "$worker_ns" \
    --nonce "$nonce" --pid "$broker_pid"
sleep 0.15
# Static skuid 65533 rule remains; UID65534 still has no direct grant.
expect_code_and_line 12 "DIRECT_DENIED port=44000" worker direct --port 44000
expect_code_and_line 12 "DIRECT_DENIED port=44001" worker direct --port 44001
expect_code_and_line 12 "IPC_UNAVAILABLE" worker relay --nonce "$nonce"

echo "POST_BROKER_SIGKILL_DIRECT_UDP_DENIED"
echo "POST_BROKER_SIGKILL_IPC_UNAVAILABLE"
echo "M1.7.2e LAB PASS: worker permanently denied direct UDP; broker UID65533 relay and broker death closes IPC"
echo "SECURITY LIMIT: no in-flight proof; leaked broker-owned socket FD or other UID65533 process could bypass."
echo "SECURITY LIMIT: IPC auth is UID-only, not session-bound; host root can change nft. Research only."
