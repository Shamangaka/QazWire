#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Kernel-enforced A0 research experiment in TWO NEW network namespaces.
# No host nftables writes, no host network routes, no existing interfaces.
# Contains a deliberate, DOCUMENTED post-watchdog-crash expiry window.
set -euo pipefail

if (( EUID == 0 )); then
  echo "REFUSE: invoke as a regular user; sudo is used only for lab namespaces" >&2
  exit 1
fi
for tool in ip nft sudo python3 setpriv mktemp od sha256sum; do
  command -v "$tool" >/dev/null || { echo "MISSING: $tool (no changes made)" >&2; exit 1; }
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
policy="$repo/docs/qazwire/lab/m172b-netns-a0.nft"
helper="$repo/scripts/m172b_netns_probe.py"
[[ -f "$policy" && -f "$helper" ]] || { echo "missing immutable lab assets" >&2; exit 1; }
# Never run with extra inputs or unvalidated caller-supplied namespace names.
if (( $# != 0 )); then
  echo "REFUSE: no positional arguments are accepted" >&2
  exit 1
fi

# This script must NOT disable AppArmor or edit the host ruleset.
# sudo -v is the only interactive privilege operation.
sudo -v
uid=$(id -u)
gid=$(id -g)
(( uid > 0 && gid > 0 )) || { echo "non-root UID/GID required" >&2; exit 1; }
nft_bin=$(command -v nft)
nonce=$(od -An -N4 -tx1 /dev/urandom | tr -d '[:space:]')
[[ "$nonce" =~ ^[0-9a-f]{8}$ ]] || exit 1
worker_ns="qwba${nonce}"
peer_ns="qwbb${nonce}"
dir=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/qazwire-m172b.XXXXXXXX")
chmod 0700 "$dir"
worker_created=0
peer_created=0
cleanup() {
  set +e
  # Terminate ONLY tasks which are still associated with our new namespaces.
  # Never kill a PID based solely on a stale PID file.
  for ns in "$worker_ns" "$peer_ns"; do
    if sudo -n ip netns list | grep -Eq "^$ns( |$)"; then
      sudo -n ip netns pids "$ns" | while read -r pid; do
        [[ "$pid" =~ ^[0-9]+$ ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true
      done
    fi
  done
  if (( worker_created )); then sudo -n ip netns del "$worker_ns" || true; fi
  if (( peer_created )); then sudo -n ip netns del "$peer_ns" || true; fi
  rm -rf -- "$dir"
}
trap cleanup EXIT

if sudo -n ip netns list | grep -Eq "^($worker_ns|$peer_ns)( |$)"; then
  echo "REFUSE: random lab network namespace name collision" >&2
  exit 1
fi
echo "========== LAB SCOPE =========="
echo "worker namespace=$worker_ns, peer namespace=$peer_ns"
echo "address pair=198.18.27.1/30 <-> 198.18.27.2/30 (no default routes)"
echo "host nftables: READ/WRITE NEVER performed by this script"
echo "network namespace creation needs sudo, but user namespace/AppArmor settings stay unchanged"

echo "========== CREATE PRIVATE NETWORK NAMESPACES =========="
sudo -n ip netns add "$worker_ns"
worker_created=1
sudo -n ip netns add "$peer_ns"
peer_created=1

echo "========== LOAD DEFAULT-DROP NFT POLICY BEFORE LINK UP =========="
sudo -n ip netns exec "$worker_ns" nft -f "$policy"
sudo -n ip netns exec "$worker_ns" nft list table inet qw_a0 > "$dir/worker-policy.txt"
grep -Fq "policy drop" "$dir/worker-policy.txt" || { echo "FAIL: missing default drop"; exit 1; }
grep -Fq "allow_dst" "$dir/worker-policy.txt" || { echo "FAIL: missing expiring allow set"; exit 1; }
# Creating the veth pair INSIDE worker_ns ensures no host-netns veth device.
sudo -n ip -n "$worker_ns" link add qwa type veth peer name qwb
sudo -n ip -n "$worker_ns" link set qwb netns "$peer_ns"
sudo -n ip -n "$worker_ns" addr add 198.18.27.1/30 dev qwa
sudo -n ip -n "$peer_ns" addr add 198.18.27.2/30 dev qwb
sudo -n ip -n "$worker_ns" link set lo up
sudo -n ip -n "$peer_ns" link set lo up
sudo -n ip -n "$worker_ns" link set qwa up
sudo -n ip -n "$peer_ns" link set qwb up
# A default route must NEVER be added to either dedicated namespace.
if sudo -n ip -n "$worker_ns" route show default | grep -q .; then
  echo "FAIL: lab worker unexpectedly has a default route" >&2
  exit 1
fi

echo "========== PEER UDP ECHO SERVER (TWO PORTS) =========="
sudo -n ip netns exec "$peer_ns" python3 -B -u "$helper" serve --pidfile "$dir/peer.pid" \
  > "$dir/peer.log" 2>&1 &
for ((i=0; i<50; i++)); do
  [[ -s "$dir/peer.pid" ]] && break
  sleep 0.1
done
[[ -s "$dir/peer.pid" ]] || { echo "FAIL: UDP peer not ready"; cat "$dir/peer.log"; exit 1; }

# The probe is an UNPRIVILEGED ordinary direct UDP socket inside worker_ns.
# It is NOT a client of the M1.7.2a Unix soft gate.
client() {
  local port=$1
  sudo -n ip netns exec "$worker_ns" setpriv \
    --reuid "$uid" --regid "$gid" --clear-groups \
    python3 -B -u "$helper" probe --port "$port" --timeout 0.45
}
denied() {
  local port=$1
  local out
  if out=$(client "$port" 2>&1); then
    echo "FAIL: direct socket unexpectedly received UDP echo port=$port: $out" >&2
    exit 1
  fi
  echo "DENIED port=$port: $out"
}
allowed() {
  local port=$1
  client "$port" || { echo "FAIL: expected UDP echo on port=$port" >&2; exit 1; }
}

echo "========== INITIAL KERNEL DEFAULT DENY =========="
denied 44000
denied 44001

echo "========== SHORT EXPLICIT LEASE (2 SECONDS) =========="
sudo -n ip netns exec "$worker_ns" nft add element inet qw_a0 allow_dst \
  '{ 198.18.27.2 timeout 2s }'
allowed 44000
denied 44001
sleep 3
denied 44000

echo "========== SIMULATED PRIVILEGED LEASE RENEWER =========="
# This is a synthetic fault injection helper, NOT a real protected watchdog:
# it temporarily has CAP_NET_ADMIN inside the isolated worker network ns.
sudo -n ip netns exec "$worker_ns" nft add element inet qw_a0 allow_dst \
  '{ 198.18.27.2 timeout 2s }'
sudo -n ip netns exec "$worker_ns" python3 -B -u "$helper" refresh \
  --pidfile "$dir/renewer.pid" --nft "$nft_bin" --period 0.25 \
  > "$dir/renew.log" 2>&1 &
for ((i=0; i<50; i++)); do
  [[ -s "$dir/renewer.pid" ]] && break
  sleep 0.1
done
if [[ ! -s "$dir/renewer.pid" ]]; then
  echo "FAIL: lease renewal helper did not start" >&2
  cat "$dir/renew.log"
  exit 1
fi
watch_pid=$(cat "$dir/renewer.pid")
[[ "$watch_pid" =~ ^[1-9][0-9]*$ ]] || { echo "bad renewer PID"; exit 1; }
for ((i=0; i<4; i++)); do
  allowed 44000
  sleep 0.5
done
denied 44001

echo "========== SIMULATED WATCHDOG SIGKILL DURING ACTIVE LEASE =========="
# The issuer must belong to our NEW worker network namespace; do not kill a
# PID by its numeric value without that membership verification.
sudo -n ip netns pids "$worker_ns" | grep -Fxq "$watch_pid" || {
  echo "FAIL: renewal process not found in exact test namespace" >&2
  exit 1
}
sudo -n kill -KILL "$watch_pid"
echo "SIGKILL issued to synthetic lease renewer $watch_pid"

# A lease active at the moment of death might remain valid before expiry.
# Report this observable exposure, do NOT describe it as immediate fail-closed.
if client 44000 > "$dir/postkill-immediate.txt" 2>&1; then
  echo "KNOWN-GAP: existing kernel lease may STILL ALLOW immediately after watchdog death"
else
  echo "immediate post-kill direct socket denied (not guaranteed in all races)"
fi
sleep 3
denied 44000
echo "========== NEW CLIENT PROCESS AFTER WATCHDOG FAILURE =========="
denied 44000

echo "M1.7.2b LAB PASS: kernel nft default-deny, scoped lease, direct-socket enforcement and expiry after renewer SIGKILL"
echo "SECURITY LIMIT: active lease may survive SIGKILL up to its TTL. Immediate A0 on watchdog crash NOT PROVEN."
echo "SECURITY LIMIT: privileged lease renewer shares lab worker netns; separate privileged control plane NOT IMPLEMENTED."
echo "CLEANUP: temporary namespaces and lab tasks are removed by EXIT trap."
