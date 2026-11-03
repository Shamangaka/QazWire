#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M1.7.2a lab: two distinct unprivileged user systemd units, synthetic
# pulse + Unix gate, then intentional SIGSTOP and cgroup.kill.
# No sudo, userns, nftables, real VPN, secret keys or live network changes.
set -euo pipefail

if [[ "$EUID" -eq 0 ]]; then
    echo "REFUSE: no root for synthetic watchdog lab" >&2
    exit 1
fi
for c in systemd-run systemctl go od ps; do
    command -v "$c" >/dev/null || { echo "missing command: $c" >&2; exit 1; }
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
dir=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/qazwire-m172.XXXXXXXX")
chmod 0700 "$dir"
workerUnit=""
watchUnit=""
cleanup() {
    if [[ -n "$watchUnit" ]]; then
        systemctl --user stop "$watchUnit" >/dev/null 2>&1 || true
        systemctl --user reset-failed "$watchUnit" >/dev/null 2>&1 || true
    fi
    if [[ -n "$workerUnit" ]]; then
        systemctl --user stop "$workerUnit" >/dev/null 2>&1 || true
        systemctl --user reset-failed "$workerUnit" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$dir"
}
trap cleanup EXIT

(
    cd "$repo"
    go build -tags qazwire_exp -o "$dir/qazwire-cgrouplab" ./cmd/qazwire-cgrouplab
)
nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')
workerUnit="qazwire-m171-$nonce.service"
watchUnit="qazwire-m172-$nonce.service"
echo "========== START WORKER SERVICE =========="
systemd-run --user --unit="${workerUnit%.service}" \
    --property=MemoryAccounting=yes \
    --property=MemoryMax=128M \
    --property=TasksMax=32 \
    --property=NoNewPrivileges=yes \
    --property=KillMode=control-group \
    "$dir/qazwire-cgrouplab" parent "$dir"
for ((i=0; i<100; i++)); do
    [[ -s "$dir/parent.pid" && -s "$dir/escaped.pid" && -s "$dir/pulse" ]] && break
    sleep 0.1
done
if [[ ! -s "$dir/parent.pid" || ! -s "$dir/escaped.pid" || ! -s "$dir/pulse" ]]; then
    echo "FAIL: worker did not start" >&2
    exit 1
fi
parent=$(cat "$dir/parent.pid")
escaped=$(cat "$dir/escaped.pid")
mainpid=$(systemctl --user show --value -p MainPID "$workerUnit")
cg=$(systemctl --user show --value -p ControlGroup "$workerUnit")
if [[ "$parent" != "$mainpid" || ! "$parent" =~ ^[1-9][0-9]*$ ||
      ! "$escaped" =~ ^[1-9][0-9]*$ || -z "$cg" ]]; then
    echo "FAIL: worker process identity mismatch" >&2
    exit 1
fi
for pid in "$parent" "$escaped"; do
    grep -Fxq "0::$cg" "/proc/$pid/cgroup" || { echo "FAIL: worker PID $pid not in cgroup" >&2; exit 1; }
done
sid=$(ps -o sid= -p "$escaped" | tr -d '[:space:]')
[[ "$sid" == "$escaped" ]] || { echo "FAIL: escaped child did not setsid" >&2; exit 1; }
echo "worker=$parent child=$escaped child_sid=$sid cgroup=$cg"

echo "========== START INDEPENDENT WATCHDOG SERVICE =========="
systemd-run --user --unit="${watchUnit%.service}" \
    --property=MemoryAccounting=yes \
    --property=MemoryMax=128M \
    --property=TasksMax=32 \
    --property=NoNewPrivileges=yes \
    --property=KillMode=control-group \
    "$dir/qazwire-cgrouplab" watch "$cg" "$workerUnit" "$parent" "$escaped" "$dir"
for ((i=0; i<100; i++)); do
    [[ -f "$dir/watch.ready" ]] && break
    sleep 0.1
done
if [[ ! -s "$dir/watch.ready" ]]; then
    echo "FAIL: watchdog did not announce readiness" >&2
    systemctl --user status "$watchUnit" --no-pager || true
    exit 1
fi
watchCg=$(systemctl --user show --value -p ControlGroup "$watchUnit")
if [[ -z "$watchCg" || "$watchCg" == "$cg" || "$watchCg" == "$cg/"* ]]; then
    echo "FAIL: watchdog not isolated from worker cgroup" >&2
    exit 1
fi
echo "watchdog_cgroup=$watchCg"
socket="$dir/watch-gate.sock"
before=$("$dir/qazwire-cgrouplab" gate "$socket")
if [[ "$before" != "A0_SOFT_ALLOW" ]]; then
    echo "FAIL: synthetic gate did not allow healthy worker: $before" >&2
    exit 1
fi
echo "healthy gate: $before"

echo "========== INJECT SIGSTOP INTO WORKER ONLY =========="
# SIGSTOP pauses heartbeat but does not affect separate watchdog service.
kill -STOP "$parent"
passed=false
for ((i=0; i<150; i++)); do
    if [[ -f "$dir/watch.trace" ]] && grep -q '^KILL_CONFIRMED ' "$dir/watch.trace"; then
        passed=true
        break
    fi
    sleep 0.1
done
echo "========== AUDIT TRACE =========="
if [[ -f "$dir/watch.trace" ]]; then cat "$dir/watch.trace"; fi
if [[ "$passed" != true ]]; then
    echo "FAIL: watchdog did not confirm cgroup termination" >&2
    exit 1
fi
mapfile -t events < "$dir/watch.trace"
if [[ "${#events[@]}" -lt 4 ||
      "${events[0]}" != "WATCH_READY_GATE_ARMED" ||
      "${events[1]}" != "A0_SOFT_DENY_BEFORE_KILL reason=PULSE_TIMEOUT" ||
      "${events[2]}" != "CGROUP_KILL_ATTEMPTED" ||
      "${events[3]}" != KILL_CONFIRMED\ * ]]; then
    echo "FAIL: synthetic egress fence was not recorded before kill" >&2
    exit 1
fi
if "$dir/qazwire-cgrouplab" gate "$socket" >/dev/null 2>&1; then
    echo "FAIL: synthetic gate still granted after watchdog-triggered kill" >&2
    exit 1
fi
echo "M1.7.2a LAB PASS: independent watchdog fenced synthetic gate before cgroup kill; post-fault gate denied"
echo "LIMIT: application gate, same UID, no nftables/cgroup firewall, no real keys."
