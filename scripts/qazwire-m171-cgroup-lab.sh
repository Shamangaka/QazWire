#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M1.7.1 SYNTHETIC cgroup-v2 test on a user's OWN temporary systemd unit.
# Does not use sudo, user namespaces, nftables, real keys or live VPN traffic.
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "REFUSE: do not run as root" >&2
    exit 1
fi
for executable in systemctl systemd-run go stat ps od; do
    command -v "$executable" >/dev/null || { echo "Missing: $executable" >&2; exit 1; }
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
tmp=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/qazwire-m171.XXXXXXXX")
chmod 0700 "$tmp"
unit=""
cleanup() {
    if [[ -n "$unit" ]]; then
        # The user manager independently kills any leftover processes.
        systemctl --user stop "$unit" >/dev/null 2>&1 || true
        systemctl --user reset-failed "$unit" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT

echo "========== BUILD SYNTHETIC CHILD =========="
(
    cd "$repo"
    go build -tags qazwire_exp -o "$tmp/qazwire-cgrouplab" ./cmd/qazwire-cgrouplab
)
nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')
unit="qazwire-m171-${nonce}.service"
echo "unit=$unit"

echo "========== CREATE BOUNDED USER SYSTEMD UNIT =========="
systemd-run --user \
    --unit="${unit%.service}" \
    --property=MemoryAccounting=yes \
    --property=MemoryMax=128M \
    --property=TasksMax=32 \
    --property=NoNewPrivileges=yes \
    --property=KillMode=control-group \
    "$tmp/qazwire-cgrouplab" parent "$tmp"

ready=false
for ((i=0; i<100; i++)); do
    if [[ -s "$tmp/parent.pid" && -s "$tmp/escaped.pid" ]]; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "$ready" != true ]]; then
    echo "FAIL: worker did not publish both process IDs" >&2
    systemctl --user status "$unit" --no-pager || true
    exit 1
fi

parent=$(cat "$tmp/parent.pid")
escaped=$(cat "$tmp/escaped.pid")
mainpid=$(systemctl --user show --value -p MainPID "$unit")
cg=$(systemctl --user show --value -p ControlGroup "$unit")
active=$(systemctl --user show --value -p ActiveState "$unit")
if ! [[ "$parent" =~ ^[1-9][0-9]*$ &&
        "$escaped" =~ ^[1-9][0-9]*$ &&
        "$mainpid" =~ ^[1-9][0-9]*$ &&
        "$mainpid" == "$parent" &&
        "$active" == active ]]; then
    echo "FAIL: systemd MainPID/ActiveState mismatch" >&2
    exit 1
fi
path="/sys/fs/cgroup$cg"
if [[ ! -f "$path/cgroup.kill" || ! -w "$path/cgroup.kill" ]]; then
    echo "FAIL: cgroup.kill missing or not writable" >&2
    exit 1
fi

echo "========== VERIFY PARENT AND SETSID CHILD IN SAME CGROUP =========="
for p in "$parent" "$escaped"; do
    if ! grep -Fxq "0::$cg" "/proc/$p/cgroup"; then
        echo "FAIL: process $p is not inside temporary unit cgroup" >&2
        exit 1
    fi
done
child_sid=$(ps -o sid= -p "$escaped" | tr -d '[:space:]')
parent_sid=$(ps -o sid= -p "$parent" | tr -d '[:space:]')
if [[ "$child_sid" != "$escaped" || "$parent_sid" == "$child_sid" ]]; then
    echo "FAIL: escaped child did not create independent session" >&2
    exit 1
fi
echo "mainpid=$parent, setsid_child=$escaped, child_sid=$child_sid, cgroup=$cg"
echo "memory.max=$(cat "$path/memory.max"), pids.max=$(cat "$path/pids.max")"
echo "before: $(tr '\n' ',' < "$path/cgroup.events")"

echo "========== ISSUE CGROUP.KILL AND VERIFY POPULATED=0 =========="
"$tmp/qazwire-cgrouplab" kill "$cg" "$unit" "$mainpid" "$escaped" 134217728 32

echo "========== RESULT =========="
echo "PASS: verified termination of both tracked processes and an empty or removed temporary cgroup"
echo "LIMIT: no process memory isolation / A0 egress / independent watchdog / real secrets."
echo "cleanup: temporary systemd unit will be stopped and reset by EXIT trap"
