#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M1.7.3a P0: prove same-UID egress bypass in *new* offline netns.
# EXPECTED VULNERABILITY REPRODUCTION, not an authorization/mitigation pass.
# Never touches host nftables, host interfaces, routes, Internet or keys.
set -Eeuo pipefail
trap 'printf "M173A_P0_FAILED_LINE=%s CHILD_EXIT=%s\n" "$LINENO" "$?" >&2' ERR

if (( EUID == 0 || $# != 0 )); then
    echo "STOP: run only as unprivileged user, with no arguments" >&2
    exit 1
fi
for tool in sudo ip nft python3 setpriv od grep mktemp chmod; do
    command -v "$tool" >/dev/null || { echo "MISSING $tool" >&2; exit 1; }
done

repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
policy="$repo/docs/qazwire/lab/m172e-broker-owned-a0.nft"
helper="$repo/scripts/m172b_netns_probe.py"
[[ -f "$policy" && -f "$helper" ]] || { echo "MISSING lab assets" >&2; exit 1; }
# Human home may be inaccessible to capless UID65533 / UID65534.
probe_source=$(cat "$helper")
[[ -n "$probe_source" ]] || exit 1

# Human explicitly authorizes sudo; all later privileged calls are -n.
sudo -v
# Do not run if a previous P0 lab left any namespaces.
if sudo -n ip netns list | grep -Eq '^qwg[ab][0-9a-f]{8}([[:space:]]|$)'; then
    echo "STOP: existing qwg[a/b] lab namespace; investigate first" >&2
    exit 1
fi

nonce=$(od -An -N4 -tx1 /dev/urandom | tr -d '[:space:]')
[[ "$nonce" =~ ^[0-9a-f]{8}$ ]] || exit 1
broker_ns="qwga$nonce"
peer_ns="qwgb$nonce"
dir=$(mktemp -d "/tmp/qazwire-m173a-p0.XXXXXXXX")
chmod 0700 "$dir"
broker_created=0
peer_created=0

echo "M173A_P0_SCOPE broker_ns=$broker_ns peer_ns=$peer_ns"
echo "M173A_P0_NO_HOST_NFT_OR_ROUTING"

cleanup() {
    local result=$?
    trap - EXIT
    set +e
    echo "========== M1.7.3a P0 CLEANUP =========="
    for ns in "$broker_ns" "$peer_ns"; do
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
                echo "M173A_P0_SCOPE_ESCALATION $ns"
                sudo -n ip netns exec "$ns" python3 -B "$helper" terminate-members --force-kill || result=1
                for ((i=0; i<50; i++)); do
                    if [[ -z "$(sudo -n ip netns pids "$ns" 2>/dev/null)" ]]; then
                        cleared=1
                        break
                    fi
                    sleep 0.1
                done
            fi
            if (( cleared == 0 )); then
                echo "M173A_P0_CLEANUP_FAILURE: processes in $ns" >&2
                result=1
            fi
        fi
    done
    if (( broker_created )); then
        sudo -n ip netns del "$broker_ns" || result=1
    fi
    if (( peer_created )); then
        sudo -n ip netns del "$peer_ns" || result=1
    fi
    if sudo -n ip netns list | grep -Eq "^($broker_ns|$peer_ns)([[:space:]]|$)"; then
        echo "M173A_P0_CLEANUP_FAILURE: namespaces still present" >&2
        result=1
    fi
    if (( result == 0 )); then
        rm -rf -- "$dir" || result=1
        if (( result == 0 )); then
            echo "M1.7.3a P0 CLEANUP PASS"
        fi
    fi
    if (( result != 0 )); then
        echo "M1.7.3a P0 FAILED; private data preserved: $dir" >&2
    fi
    exit "$result"
}
trap cleanup EXIT

sudo -n ip netns add "$broker_ns"
broker_created=1
sudo -n ip netns add "$peer_ns"
peer_created=1

# Start from default DROP in broker namespace. No worker/netns trust implied.
sudo -n ip netns exec "$broker_ns" nft -f "$policy"
sudo -n ip netns exec "$broker_ns" nft list table inet qw_broker_a0 > "$dir/nft.txt"
grep -Fq "meta skuid 65533" "$dir/nft.txt" || exit 1
grep -Fq "policy drop" "$dir/nft.txt" || exit 1

# Veth is created INSIDE the new netns, not on the host.
sudo -n ip -n "$broker_ns" link add qwg0 type veth peer name qwg1
sudo -n ip -n "$broker_ns" link set qwg1 netns "$peer_ns"
sudo -n ip -n "$broker_ns" addr add 198.18.27.1/30 dev qwg0
sudo -n ip -n "$peer_ns" addr add 198.18.27.2/30 dev qwg1
sudo -n ip -n "$broker_ns" link set lo up
sudo -n ip -n "$peer_ns" link set lo up
sudo -n ip -n "$broker_ns" link set qwg0 up
sudo -n ip -n "$peer_ns" link set qwg1 up
[[ -z "$(sudo -n ip -n "$broker_ns" route show default)" ]] || exit 1
[[ -z "$(sudo -n ip -n "$peer_ns" route show default)" ]] || exit 1
echo "M173A_P0_ISOLATED_NFT_DEFAULT_DROP"

sudo -n ip netns exec "$peer_ns" python3 -B -u "$helper" serve \
    --pidfile "$dir/peer.pid" > "$dir/peer.log" 2>&1 &
for ((i=0; i<70; i++)); do
    [[ -s "$dir/peer.pid" ]] && break
    sleep 0.1
done
[[ -s "$dir/peer.pid" ]] || { cat "$dir/peer.log"; exit 1; }

run_uid() {
    local uid=$1
    shift
    sudo -n ip netns exec "$broker_ns" setpriv \
        --reuid="$uid" --regid="$uid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs --reset-env \
        /usr/bin/python3 -B -u -c "$probe_source" "$@"
}

expect_code_and_marker() {
    local wanted=$1 marker=$2
    shift 2
    local result rc=0
    result=$("$@" 2>&1) || rc=$?
    printf '%s\n' "$result"
    if (( rc != wanted )) || [[ "$result" != *"$marker"* ]]; then
        echo "M173A_P0_FAIL: expected rc=$wanted marker=$marker, observed rc=$rc" >&2
        exit 1
    fi
}

echo "========== NEGATIVE CONTROL: UID65534 =========="
expect_code_and_marker 1 "NO_ECHO port=44000 cause=PermissionError" \
    run_uid 65534 probe --port 44000 --timeout 0.45
echo "M173A_P0_WORKER_UID_DENIED"

echo "========== ADVERSARY: NO BROKER PROCESS, SAME UID =========="
# No broker is running. This synthetic independent process is not the broker,
# but nft meta skuid authorizes its UDP socket purely because UID=65533.
expect_code_and_marker 0 "ECHO port=44000" \
    run_uid 65533 probe --port 44000 --timeout 0.45
echo "M173A_P0_SAME_UID_BYPASS_CONFIRMED"

echo "========== NEGATIVE PORT CONTROL: UID65533 PORT 44001 =========="
expect_code_and_marker 1 "NO_ECHO port=44001 cause=PermissionError" \
    run_uid 65533 probe --port 44001 --timeout 0.45
echo "M173A_P0_PORT_SCOPE_CONFIRMED"

expect_code_and_marker 1 "NO_ECHO port=44000 cause=PermissionError" \
    run_uid 65534 probe --port 44000 --timeout 0.45

echo "M1.7.3a P0 EXPECTED VULNERABILITY REPRODUCED"
echo "SECURITY LIMIT: UID-based nft policy cannot identify a unique broker process."
echo "SECURITY LIMIT: no production, Internet, VPN, host firewall or routing touched."
