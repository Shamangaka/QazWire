#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M0: two independent Linux network namespaces, STOCK wireguard-go only.
# Creates only disposable namespaces, veth links, temporary test keys and TUN devices.
# Research/synthetic packets only. No claim about Qalqan or ST RK conformance.
set -Eeuo pipefail
umask 077

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "Linux required"
[[ "${EUID}" -eq 0 ]] || die "run via sudo; build wireguard-go as an ordinary user first"
[[ $# -eq 1 && "$1" == /* && -x "$1" ]] ||
  die "usage: sudo bash scripts/qazwire-netns-lab.sh /absolute/path/to/wireguard-go"

for cmd in ip wg ping awk mktemp sleep date seq cat tail; do
  command -v "$cmd" >/dev/null 2>&1 || die "missing command: $cmd"
done
[[ -c /dev/net/tun ]] || die "/dev/net/tun unavailable; TUN or CAP_NET_ADMIN may be missing"

BIN="$1"
A="qzw-a-$$"
B="qzw-b-$$"
VETH_A="qva$$"
VETH_B="qvb$$"
WG_A="qwa$$"
WG_B="qwb$$"
PORT_A=51820
PORT_B=51821
TMP="$(mktemp -d -t qazwire-m0.XXXXXXXX)"
created_a=0
created_b=0
PID_A=""
PID_B=""

cleanup() {
  local rc="$1"
  set +e
  if [[ "$rc" -ne 0 ]]; then
    printf '\nFAIL: QazWire M0 namespace test (exit=%s)\n' "$rc" >&2
    for log in "$TMP/a.log" "$TMP/b.log"; do
      if [[ -f "$log" ]]; then
        printf '--- %s (last 15 lines) ---\n' "$log" >&2
        tail -n 15 "$log" >&2
      fi
    done
  fi
  [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null
  [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null
  [[ -n "$PID_A" ]] && wait "$PID_A" 2>/dev/null
  [[ -n "$PID_B" ]] && wait "$PID_B" 2>/dev/null
  [[ "$created_a" -eq 1 ]] && ip netns del "$A" 2>/dev/null
  [[ "$created_b" -eq 1 ]] && ip netns del "$B" 2>/dev/null
  # Remove the veth pair only if a failed setup left its host-side endpoint.
  ip link del "$VETH_A" 2>/dev/null
  ip link del "$VETH_B" 2>/dev/null
  rm -rf -- "$TMP"
}
trap 'cleanup "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'QazWire M0: stock WireGuard userspace, synthetic traffic only\n'
printf 'host=%s kernel=%s timestamp_utc=%s\n' "$(uname -n)" "$(uname -r)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'binary=%s\n' "$BIN"

# Use deliberately isolated test networks; no host routes, NAT, sysctls or firewall modifications.
ip netns add "$A"
created_a=1
ip netns add "$B"
created_b=1
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$A"
ip link set "$VETH_B" netns "$B"
ip -n "$A" link set "$VETH_A" name under0
ip -n "$B" link set "$VETH_B" name under0
for ns in "$A" "$B"; do ip -n "$ns" link set lo up; done
ip -n "$A" addr add 192.0.2.1/30 dev under0
ip -n "$B" addr add 192.0.2.2/30 dev under0
ip -n "$A" link set under0 up
ip -n "$B" link set under0 up

wg genkey > "$TMP/a.key"
wg genkey > "$TMP/b.key"
wg pubkey < "$TMP/a.key" > "$TMP/a.pub"
wg pubkey < "$TMP/b.key" > "$TMP/b.pub"

# Each TUN gets a distinct interface and UAPI socket name even though /run is shared.
ip netns exec "$A" "$BIN" -f "$WG_A" > "$TMP/a.log" 2>&1 &
PID_A=$!
ip netns exec "$B" "$BIN" -f "$WG_B" > "$TMP/b.log" 2>&1 &
PID_B=$!

for i in $(seq 1 60); do
  if ip -n "$A" link show dev "$WG_A" >/dev/null 2>&1 &&
     ip -n "$B" link show dev "$WG_B" >/dev/null 2>&1 &&
     [[ -S "/run/wireguard/$WG_A.sock" && -S "/run/wireguard/$WG_B.sock" ]]; then
    break
  fi
  sleep 0.1
done
ip -n "$A" link show dev "$WG_A" >/dev/null 2>&1 || die "first WireGuard TUN did not start"
ip -n "$B" link show dev "$WG_B" >/dev/null 2>&1 || die "second WireGuard TUN did not start"
[[ -S "/run/wireguard/$WG_A.sock" && -S "/run/wireguard/$WG_B.sock" ]] ||
  die "wireguard-go UAPI sockets unavailable"

ip netns exec "$A" wg set "$WG_A" private-key "$TMP/a.key" listen-port "$PORT_A" \
  peer "$(cat "$TMP/b.pub")" allowed-ips 10.77.0.2/32 endpoint 192.0.2.2:"$PORT_B"
ip netns exec "$B" wg set "$WG_B" private-key "$TMP/b.key" listen-port "$PORT_B" \
  peer "$(cat "$TMP/a.pub")" allowed-ips 10.77.0.1/32 endpoint 192.0.2.1:"$PORT_A"

ip -n "$A" addr add 10.77.0.1/30 dev "$WG_A"
ip -n "$B" addr add 10.77.0.2/30 dev "$WG_B"
ip -n "$A" link set "$WG_A" up
ip -n "$B" link set "$WG_B" up

printf '\n[1/3] Underlay connectivity...\n'
ip netns exec "$A" ping -n -q -c 2 -W 2 192.0.2.2
printf '\n[2/3] Encrypted userspace tunnel connectivity...\n'
ip netns exec "$A" ping -n -q -c 5 -W 2 -I "$WG_A" 10.77.0.2
ip netns exec "$B" ping -n -q -c 3 -W 2 -I "$WG_B" 10.77.0.1

printf '\n[3/3] Handshake and transfer counters...\n'
for spec in "$A $WG_A" "$B $WG_B"; do
  read -r ns iface <<< "$spec"
  ip netns exec "$ns" wg show "$iface" latest-handshakes |
    awk '{if ($2 > 0) good=1} END {exit !good}' ||
      die "$ns: no completed handshake"
  ip netns exec "$ns" wg show "$iface" transfer |
    awk '{if ($2 > 0 && $3 > 0) good=1} END {exit !good}' ||
      die "$ns: no bidirectional transfer"
  printf 'PASS: %s handshake and bidirectional transfer\n' "$ns"
done

printf '\nPASS: stock userspace WireGuard connected two isolated Linux namespaces.\n'
printf 'NOT TESTED: Qalqan, modified wire format, rekey, replay rejection, formal crypto proof or certification.\n'
