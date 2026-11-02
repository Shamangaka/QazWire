#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# QazWire M0.1: wireguard-go (userspace) <-> Linux in-kernel WireGuard.
# Only synthetic packets and disposable isolated namespaces.
set -Eeuo pipefail
umask 077

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "Linux required"
[[ "$EUID" -eq 0 ]] || die "Run as root using sudo (build the binary as ordinary user)."
[[ $# -eq 1 && "$1" == /* && -x "$1" ]] ||
  die "Usage: sudo bash scripts/qazwire-kernel-interop-m0.sh /absolute/path/to/wireguard-go"
[[ -c /dev/net/tun ]] || die "/dev/net/tun is unavailable"

for cmd in ip wg ping mktemp awk sleep date tail; do
  command -v "$cmd" >/dev/null 2>&1 || die "Missing command: $cmd"
done

BIN="$1"
A="qzw-u-$$"
B="qzw-k-$$"
VETH_A="qvu$$"
VETH_B="qvk$$"
WG_A="qwu$$"
WG_B="qwk$$"
PORT_A=51830
PORT_B=51831
TMP="$(mktemp -d -t qazwire-interop.XXXXXXXX)"
created_a=0
created_b=0
pid_a=""

cleanup() {
  local rc="$1"
  set +e
  if [[ "$rc" -ne 0 ]]; then
    printf '\nFAIL: QazWire M0.1 kernel interoperability (exit=%s)\n' "$rc" >&2
    if [[ -f "$TMP/userspace.log" ]]; then
      printf -- '--- userspace log (last 30 lines) ---\n' >&2
      tail -n 30 "$TMP/userspace.log" >&2
    fi
  fi

  [[ -z "$pid_a" ]] || kill "$pid_a" 2>/dev/null
  [[ -z "$pid_a" ]] || wait "$pid_a" 2>/dev/null
  [[ "$created_a" -ne 1 ]] || ip netns del "$A" 2>/dev/null
  [[ "$created_b" -ne 1 ]] || ip netns del "$B" 2>/dev/null
  # veth cleanup also handles failures between creation and netns placement.
  ip link del "$VETH_A" 2>/dev/null
  ip link del "$VETH_B" 2>/dev/null
  rm -f -- "/run/wireguard/$WG_A.sock"
  rm -rf -- "$TMP"
}
trap 'rc=$?; trap - EXIT; cleanup "$rc"; exit "$rc"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'QazWire M0.1: userspace-to-kernel WireGuard interoperability\n'
printf 'kernel=%s timestamp_utc=%s\n' "$(uname -r)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'binary=%s\n' "$BIN"
printf 'No Qalqan, no modifications to host routing/firewall/DNS.\n'

ip netns add "$A"
created_a=1
ip netns add "$B"
created_b=1
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$A"
ip link set "$VETH_B" netns "$B"
ip -n "$A" link set "$VETH_A" name under0
ip -n "$B" link set "$VETH_B" name under0
ip -n "$A" link set lo up
ip -n "$B" link set lo up
ip -n "$A" addr add 198.18.1.1/30 dev under0
ip -n "$B" addr add 198.18.1.2/30 dev under0
ip -n "$A" link set under0 up
ip -n "$B" link set under0 up

printf '\n[1/4] Start kernel WireGuard peer...\n'
ip -n "$B" link add "$WG_B" type wireguard ||
  die "Kernel WireGuard interface could not be created; check kernel module and CAP_NET_ADMIN"
ip -n "$B" link show "$WG_B" >/dev/null

printf '\n[2/4] Start userspace peer...\n'
ip netns exec "$A" "$BIN" -f "$WG_A" > "$TMP/userspace.log" 2>&1 &
pid_a="$!"
ready=0
for (( i=0; i<60; i++ )); do
  if ip netns exec "$A" wg show "$WG_A" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
[[ "$ready" -eq 1 ]] || die "Userspace WireGuard UAPI did not become ready"

wg genkey > "$TMP/a.key"
wg genkey > "$TMP/b.key"
pub_a="$(wg pubkey < "$TMP/a.key")"
pub_b="$(wg pubkey < "$TMP/b.key")"

ip netns exec "$A" wg set "$WG_A" \
  private-key "$TMP/a.key" listen-port "$PORT_A" \
  peer "$pub_b" allowed-ips 10.77.1.2/32 endpoint 198.18.1.2:"$PORT_B"
ip netns exec "$B" wg set "$WG_B" \
  private-key "$TMP/b.key" listen-port "$PORT_B" \
  peer "$pub_a" allowed-ips 10.77.1.1/32 endpoint 198.18.1.1:"$PORT_A"

ip -n "$A" addr add 10.77.1.1/30 dev "$WG_A"
ip -n "$B" addr add 10.77.1.2/30 dev "$WG_B"
ip -n "$A" link set "$WG_A" up
ip -n "$B" link set "$WG_B" up

printf '\n[3/4] Bidirectional ICMP over encrypted tunnel...\n'
ip netns exec "$A" ping -n -q -c 5 -W 2 -I "$WG_A" 10.77.1.2
ip netns exec "$B" ping -n -q -c 3 -W 2 -I "$WG_B" 10.77.1.1

printf '\n[4/4] Confirm completed handshakes and transfer counters...\n'
for spec in "$A $WG_A" "$B $WG_B"; do
  read -r ns iface <<< "$spec"
  ip netns exec "$ns" wg show "$iface" latest-handshakes |
    awk 'NR == 1 && $2 ~ /^[0-9]+$/ && $2 > 0 {ok=1} END {exit !ok}' ||
    die "No completed handshake: $ns"
  ip netns exec "$ns" wg show "$iface" transfer |
    awk 'NR == 1 && $2 > 0 && $3 > 0 {ok=1} END {exit !ok}' ||
    die "Missing bidirectional transfer: $ns"
  printf 'PASS: %s (%s)\n' "$ns" "$iface"
done

printf '\nPASS: QazWire userspace interoperates with kernel WireGuard.\n'
printf 'NOT TESTED: Qalqan, packet tampering/replay rejection, rekey, long-term throughput, certification.\n'
