#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# QazWire M0: standard WireGuard userspace E2E smoke test in isolated netns.
# Requires Linux root, wireguard-tools, iproute2, iputils-ping and /dev/net/tun.
# Changes no routes or network interfaces in the host network namespace.
set -Eeuo pipefail
umask 077

usage() {
  printf 'Usage: sudo bash %s /absolute/path/to/compiled/wireguard-go\n' "$0" >&2
}

if (( EUID != 0 )); then
  printf 'ERROR: This script requires root for Linux network namespaces.\n' >&2
  usage
  exit 1
fi
if (( $# != 1 )) || [[ "$1" != /* ]] || [[ ! -x "$1" ]]; then
  printf 'ERROR: Pass the absolute path to the executable wireguard-go binary.\n' >&2
  usage
  exit 1
fi
WG_GO="$1"
for cmd in ip wg ping mktemp awk sleep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'ERROR: missing command: %s\n' "$cmd" >&2
    exit 1
  fi
done
if [[ ! -c /dev/net/tun ]]; then
  printf 'ERROR: /dev/net/tun is unavailable. No attempt to create it automatically.\n' >&2
  exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/qazwire-m0.XXXXXXXX")"
tag="${workdir##*.}"
ns_a="qwm0a-${tag}"
ns_b="qwm0b-${tag}"
if_a="qwa${tag}"
if_b="qwb${tag}"
veth_a="va${tag}"
veth_b="vb${tag}"
pid_a=''
pid_b=''

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if (( exit_code != 0 )); then
    printf '\nFAIL: QazWire M0 namespace check (exit=%s)\n' "$exit_code" >&2
    if [[ -f "$workdir/peer-a.log" ]]; then
      printf '=== peer A log (tail) ===\n' >&2
      tail -n 30 "$workdir/peer-a.log" >&2 || true
    fi
    if [[ -f "$workdir/peer-b.log" ]]; then
      printf '=== peer B log (tail) ===\n' >&2
      tail -n 30 "$workdir/peer-b.log" >&2 || true
    fi
  fi
  [[ -z "$pid_a" ]] || kill "$pid_a" 2>/dev/null || true
  [[ -z "$pid_b" ]] || kill "$pid_b" 2>/dev/null || true
  [[ -z "$pid_a" ]] || wait "$pid_a" 2>/dev/null || true
  [[ -z "$pid_b" ]] || wait "$pid_b" 2>/dev/null || true
  # Delete only namespaces created for this run. Leave host routes untouched.
  ip netns delete "$ns_a" >/dev/null 2>&1 || true
  ip netns delete "$ns_b" >/dev/null 2>&1 || true
  # Unique socket names used by this invocation only.
  rm -f -- "/run/wireguard/${if_a}.sock" "/run/wireguard/${if_b}.sock"
  rm -rf -- "$workdir"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_device() {
  local namespace="$1" iface="$2"
  local i
  for ((i=0; i<60; i++)); do
    if ip netns exec "$namespace" wg show "$iface" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  printf 'ERROR: userspace UAPI did not become ready: %s/%s\n' "$namespace" "$iface" >&2
  return 1
}

printf '=== QazWire M0: standard WireGuard in Linux network namespaces ===\n'
printf 'binary=%s\n' "$WG_GO"
printf 'namespaces=%s,%s\n' "$ns_a" "$ns_b"
printf 'This script tests stock WireGuard; Qalqan is NOT enabled.\n'

ip netns add "$ns_a"
ip netns add "$ns_b"
ip link add "$veth_a" type veth peer name "$veth_b"
ip link set "$veth_a" netns "$ns_a"
ip link set "$veth_b" netns "$ns_b"
ip -n "$ns_a" link set lo up
ip -n "$ns_b" link set lo up
ip -n "$ns_a" link set "$veth_a" name underlay0
ip -n "$ns_b" link set "$veth_b" name underlay0
ip -n "$ns_a" address add 198.18.0.1/30 dev underlay0
ip -n "$ns_b" address add 198.18.0.2/30 dev underlay0
ip -n "$ns_a" link set underlay0 up
ip -n "$ns_b" link set underlay0 up

printf '\n=== Underlay connectivity ===\n'
ip netns exec "$ns_a" ping -c 2 -W 2 198.18.0.2

wg genkey > "$workdir/peer-a.key"
wg genkey > "$workdir/peer-b.key"
public_a="$(wg pubkey < "$workdir/peer-a.key")"
public_b="$(wg pubkey < "$workdir/peer-b.key")"

# -f ensures one foreground userspace daemon per namespace.
ip netns exec "$ns_a" env LOG_LEVEL=error "$WG_GO" -f "$if_a" > "$workdir/peer-a.log" 2>&1 &
pid_a=$!
ip netns exec "$ns_b" env LOG_LEVEL=error "$WG_GO" -f "$if_b" > "$workdir/peer-b.log" 2>&1 &
pid_b=$!
wait_device "$ns_a" "$if_a"
wait_device "$ns_b" "$if_b"

ip netns exec "$ns_a" wg set "$if_a" \
  listen-port 51871 private-key "$workdir/peer-a.key" \
  peer "$public_b" allowed-ips 10.77.0.2/32 endpoint 198.18.0.2:51872
ip netns exec "$ns_b" wg set "$if_b" \
  listen-port 51872 private-key "$workdir/peer-b.key" \
  peer "$public_a" allowed-ips 10.77.0.1/32 endpoint 198.18.0.1:51871

ip -n "$ns_a" address add 10.77.0.1/30 dev "$if_a"
ip -n "$ns_b" address add 10.77.0.2/30 dev "$if_b"
ip -n "$ns_a" link set "$if_a" up
ip -n "$ns_b" link set "$if_b" up

printf '\n=== Tunnel ping (A -> B) ===\n'
ip netns exec "$ns_a" ping -c 5 -W 2 10.77.0.2
printf '\n=== Tunnel ping (B -> A) ===\n'
ip netns exec "$ns_b" ping -c 3 -W 2 10.77.0.1

printf '\n=== Handshake timestamps ===\n'
handshake_a="$(ip netns exec "$ns_a" wg show "$if_a" latest-handshakes | awk 'NR == 1 {print $2}')"
handshake_b="$(ip netns exec "$ns_b" wg show "$if_b" latest-handshakes | awk 'NR == 1 {print $2}')"
printf 'peer A handshake Unix time=%s\n' "$handshake_a"
printf 'peer B handshake Unix time=%s\n' "$handshake_b"
if [[ ! "$handshake_a" =~ ^[0-9]+$ || ! "$handshake_b" =~ ^[0-9]+$ ]] ||
    (( handshake_a == 0 || handshake_b == 0 )); then
  printf 'ERROR: missing WireGuard handshake on at least one peer.\n' >&2
  exit 1
fi

printf '\n=== Transfer counters (pubkey, received, sent) ===\n'
ip netns exec "$ns_a" wg show "$if_a" transfer
ip netns exec "$ns_b" wg show "$if_b" transfer

printf '\nPASS: baseline userspace WireGuard tunnel, handshake and bidirectional ICMP.\n'
printf 'NOT TESTED: Qalqan, rekey, replay rejection, sustained throughput, normative compliance.\n'
