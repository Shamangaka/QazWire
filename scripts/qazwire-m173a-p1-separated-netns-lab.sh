#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# QazWire M1.7.3a P1: separate worker/broker/peer network namespaces.
# Offline synthetic lab ONLY. Never changes host nft, interfaces or routing.
set -Eeuo pipefail
trap 'printf "M173A_P1_FAILED_LINE=%s CHILD_EXIT=%s\n" "$LINENO" "$?" >&2' ERR

if (( EUID == 0 || $# != 0 )); then
    echo "STOP: run as a human non-root user with zero arguments" >&2
    exit 1
fi
for tool in sudo ip nft python3 setpriv od ps grep stat mktemp chmod chown wc; do
    command -v "$tool" >/dev/null || { echo "MISSING $tool" >&2; exit 1; }
done

repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
policy="$repo/docs/qazwire/lab/m173a-p1-broker-netns.nft"
broker="$repo/scripts/m173a_p1_broker.py"
killer="$repo/scripts/m173a_p1_pidfd_kill.py"
echo_peer="$repo/scripts/m173a_p1_echo.py"
helper="$repo/scripts/m172b_netns_probe.py"
for file in "$policy" "$broker" "$killer" "$echo_peer" "$helper"; do
    [[ -f "$file" ]] || { echo "MISSING $file" >&2; exit 1; }
done
broker_source=$(cat "$broker")
[[ -n "$broker_source" ]] || exit 1

sudo -v
if sudo -n ip netns list | grep -Eq '^qwh[abc][0-9a-f]{8}([[:space:]]|$)'; then
    echo "STOP: orphan M1.7.3a P1 namespace found; inspect manually" >&2
    exit 1
fi

nonce=$(od -An -N4 -tx1 /dev/urandom | tr -d '[:space:]')
[[ "$nonce" =~ ^[0-9a-f]{8}$ ]] || exit 1
worker_ns="qwha$nonce"
broker_ns="qwhb$nonce"
peer_ns="qwhc$nonce"
dir=$(mktemp -d "/tmp/qazwire-m173a-p1.XXXXXXXX")
chmod 0711 "$dir"
mkdir -m 0700 "$dir/private"
mkdir -m 0710 "$dir/ipc"
sudo -n chown 65533:65534 "$dir/ipc"
sudo -n chmod 0710 "$dir/ipc"
[[ "$(sudo -n stat -c '%u:%g:%a' "$dir/ipc")" == "65533:65534:710" ]] || exit 1
socket_path="$dir/ipc/broker.sock"
worker_created=0
broker_created=0
peer_created=0
broker_pid=""
echo "M173A_P1_SCOPE worker=$worker_ns broker=$broker_ns peer=$peer_ns"
echo "M173A_P1_NO_HOST_NFT_ROUTES_OR_INTERFACES"

cleanup() {
    local result=$?
    trap - EXIT
    set +e
    echo "========== M1.7.3a P1 CLEANUP =========="
    if [[ "$broker_pid" =~ ^[1-9][0-9]*$ ]]; then
        sudo -n python3 -B "$killer" --namespace "$broker_ns" \
            --socket-path "$socket_path" --pid "$broker_pid" >/dev/null 2>&1 || true
    fi
    for ns in "$worker_ns" "$broker_ns" "$peer_ns"; do
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
                echo "M173A_P1_CLEANUP_SCOPE_ESCALATION $ns"
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
                echo "M173A_P1_CLEANUP_FAILURE: namespace still has tasks $ns" >&2
                result=1
            fi
        fi
    done
    if (( worker_created )); then sudo -n ip netns del "$worker_ns" || result=1; fi
    if (( broker_created )); then sudo -n ip netns del "$broker_ns" || result=1; fi
    if (( peer_created )); then sudo -n ip netns del "$peer_ns" || result=1; fi
    if sudo -n ip netns list | grep -Eq "^($worker_ns|$broker_ns|$peer_ns)([[:space:]]|$)"; then
        echo "M173A_P1_CLEANUP_FAILURE: namespaces remain" >&2
        result=1
    fi
    if (( result == 0 )); then
        sudo -n rm -f -- "$socket_path" || result=1
        sudo -n rmdir -- "$dir/ipc" || result=1
        rm -rf -- "$dir" || result=1
    fi
    if (( result == 0 )); then
        echo "M1.7.3a P1 CLEANUP PASS"
    else
        echo "M1.7.3a P1 FAIL; private diagnostics retained $dir" >&2
    fi
    exit "$result"
}
trap cleanup EXIT

sudo -n ip netns add "$worker_ns"
worker_created=1
sudo -n ip netns add "$broker_ns"
broker_created=1
sudo -n ip netns add "$peer_ns"
peer_created=1

# Policy is installed BEFORE broker interface becomes available.
sudo -n ip netns exec "$broker_ns" nft -f "$policy"
sudo -n ip netns exec "$broker_ns" nft list table inet qw_m173a_p1 > "$dir/private/nft.txt"
grep -Fq "meta skuid 65533" "$dir/private/nft.txt" || exit 1
grep -Fq "policy drop" "$dir/private/nft.txt" || exit 1

# Only broker and peer receive veth. Worker sees lo and no routes.
sudo -n ip -n "$broker_ns" link add qwhb0 type veth peer name qwhc0
sudo -n ip -n "$broker_ns" link set qwhc0 netns "$peer_ns"
sudo -n ip -n "$broker_ns" addr add 198.18.27.1/30 dev qwhb0
sudo -n ip -n "$peer_ns" addr add 198.18.27.2/30 dev qwhc0
for ns in "$worker_ns" "$broker_ns" "$peer_ns"; do
    sudo -n ip -n "$ns" link set lo up
done
sudo -n ip -n "$broker_ns" link set qwhb0 up
sudo -n ip -n "$peer_ns" link set qwhc0 up

[[ "$(sudo -n ip -n "$worker_ns" -o link show | wc -l)" == "1" ]] || {
    echo "STOP: worker has non-loopback network interfaces" >&2
    exit 1
}
[[ -z "$(sudo -n ip -n "$worker_ns" -4 route show table main)" ]] || {
    echo "STOP: worker has IPv4 routes" >&2
    exit 1
}
for ns in "$worker_ns" "$broker_ns" "$peer_ns"; do
    [[ -z "$(sudo -n ip -n "$ns" route show default)" ]] || {
        echo "STOP: unexpected default route in $ns" >&2
        exit 1
    }
done
echo "M173A_P1_WORKER_NO_UNDERLAY_AND_NO_IPV4_ROUTES"
echo "M173A_P1_BROKER_DEFAULT_DROP_LOADED"

sudo -n ip netns exec "$peer_ns" python3 -B -u "$echo_peer" \
    --pidfile "$dir/private/peer.pid" > "$dir/private/peer.log" 2>&1 &
for ((i=0; i<70; i++)); do
    [[ -s "$dir/private/peer.pid" ]] && break
    sleep 0.1
done
[[ -s "$dir/private/peer.pid" ]] || {
    cat "$dir/private/peer.log"
    echo "FAIL: P1 echo peer startup" >&2
    exit 1
}

run_id() {
    local ns=$1 uid=$2 gid=$3
    shift 3
    sudo -n ip netns exec "$ns" setpriv \
        --reuid="$uid" --regid="$gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs --reset-env \
        /usr/bin/python3 -B -u -c "$broker_source" "$@"
}
expect_code_and_marker() {
    local expected=$1 marker=$2
    shift 2
    local output rc=0
    output=$("$@" 2>&1) || rc=$?
    printf '%s\n' "$output"
    if (( rc != expected )) || [[ "$output" != *"$marker"* ]]; then
        echo "M173A_P1_FAIL: expected rc=$expected marker=$marker, got rc=$rc" >&2
        exit 1
    fi
}

echo "========== WORKER DIRECT UDP BEFORE BROKER =========="
expect_code_and_marker 12 "P1_DIRECT_NO_ROUTE uid=65534 port=44000" \
    run_id "$worker_ns" 65534 65534 direct --uid 65534 --gid 65534 --port 44000
expect_code_and_marker 12 "P1_DIRECT_NO_ROUTE uid=65533 port=44000" \
    run_id "$worker_ns" 65533 65533 direct --uid 65533 --gid 65533 --port 44000
echo "M173A_P1_WORKER_DIRECT_DENIED_BEFORE_BROKER"

echo "========== START BROKER IN ITS OWN NETNS =========="
run_id "$broker_ns" 65533 65534 serve --socket-path "$socket_path" \
    > "$dir/private/broker.log" 2>&1 &
launcher_pid=$!
found=""
for ((i=0; i<90; i++)); do
    if [[ -s "$dir/private/broker.log" ]]; then
        found=$(grep -m1 '^P1_BROKER_READY_PID=[1-9][0-9]*$' \
            "$dir/private/broker.log" || true)
        [[ -n "$found" ]] && break
    fi
    sleep 0.1
done
[[ -n "$found" ]] || {
    cat "$dir/private/broker.log"
    echo "FAIL: broker readiness" >&2
    exit 1
}
if ! wait "$launcher_pid"; then
    echo "FAIL: broker launcher did not exit normally" >&2
    exit 1
fi
broker_pid=$(printf '%s\n' "$found" | cut -d= -f2)
sid=$(ps -o sid= -p "$broker_pid" | tr -d '[:space:]')
pgid=$(ps -o pgid= -p "$broker_pid" | tr -d '[:space:]')
[[ "$sid" == "$broker_pid" && "$pgid" == "$broker_pid" ]] || {
    echo "FAIL: broker still in sudo launcher session" >&2
    exit 1
}
sudo -n ip netns pids "$broker_ns" | grep -Fxq "$broker_pid" || {
    echo "FAIL: broker is outside isolated broker netns" >&2
    exit 1
}
[[ "$(sudo -n stat -c '%u:%g:%a' "$socket_path")" == "65533:65534:660" ]] || {
    echo "FAIL: unsafe socket ownership or mode" >&2
    exit 1
}
echo "M173A_P1_DETACHED_BROKER_PID=$broker_pid"

echo "========== AUTHORIZED CROSS-NETNS RELAY =========="
expect_code_and_marker 0 "P1_CROSS_NETNS_RELAY_ECHO_OK" \
    run_id "$worker_ns" 65534 65534 relay --socket-path "$socket_path" \
        --uid 65534 --gid 65534 --broker-pid "$broker_pid"
echo "M173A_P1_RELAY_PASS"

echo "========== INVALID PEER AND DIRECT-NETWORK NEGATIVE TESTS =========="
expect_code_and_marker 14 "P1_IPC_UNAUTHORIZED_PEER_DENIED" \
    run_id "$worker_ns" 65532 65534 relay --socket-path "$socket_path" \
        --uid 65532 --gid 65534 --broker-pid "$broker_pid"
expect_code_and_marker 14 "P1_IPC_PATH_DENIED" \
    run_id "$worker_ns" 65532 65532 relay --socket-path "$socket_path" \
        --uid 65532 --gid 65532 --broker-pid "$broker_pid"
expect_code_and_marker 12 "P1_DIRECT_NO_ROUTE uid=65534 port=44000" \
    run_id "$worker_ns" 65534 65534 direct --uid 65534 --gid 65534 --port 44000
expect_code_and_marker 12 "P1_DIRECT_NO_ROUTE uid=65533 port=44000" \
    run_id "$worker_ns" 65533 65533 direct --uid 65533 --gid 65533 --port 44000
expect_code_and_marker 12 "P1_DIRECT_NO_ROUTE uid=65534 port=44001" \
    run_id "$worker_ns" 65534 65534 direct --uid 65534 --gid 65534 --port 44001
echo "M173A_P1_DIRECT_AND_IPC_NEGATIVE_CONTROLS_PASS"

echo "========== VERIFIED PIDFD BROKER TERMINATION =========="
sudo -n python3 -B "$killer" --namespace "$broker_ns" \
    --socket-path "$socket_path" --pid "$broker_pid"
sleep 0.15
expect_code_and_marker 12 "P1_IPC_UNAVAILABLE" \
    run_id "$worker_ns" 65534 65534 relay --socket-path "$socket_path" \
        --uid 65534 --gid 65534 --broker-pid "$broker_pid"
expect_code_and_marker 12 "P1_DIRECT_NO_ROUTE uid=65534 port=44000" \
    run_id "$worker_ns" 65534 65534 direct --uid 65534 --gid 65534 --port 44000
expect_code_and_marker 12 "P1_DIRECT_NO_ROUTE uid=65533 port=44000" \
    run_id "$worker_ns" 65533 65533 direct --uid 65533 --gid 65533 --port 44000
echo "M173A_P1_AFTER_BROKER_DEATH_FAIL_CLOSED"
echo "M1.7.3a P1 LAB PASS: separate worker has no underlay; only broker relay worked."
echo "SECURITY LIMIT: host root, namespace entry, leaked FD, compromised broker, in-flight traffic not proved."
