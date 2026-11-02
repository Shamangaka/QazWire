# QazWire M0 — reproducible Linux two-peer baseline

**STATUS:** Test harness committed, **NOT EXECUTED** on a privileged Ubuntu host as part of the PR. Research only, standard upstream WireGuard crypto.

## Preconditions

Ubuntu 24.04+ or suitable Linux with `iproute2`, `wireguard-tools`, `iputils-ping`, Linux TUN (`/dev/net/tun`) and permission to create network namespaces. A working Go toolchain for the fork's `go.mod`.

The test uses two disposable named Linux network namespaces and a veth underlay; it does **not** modify host routes, DNS, NAT or firewalls. Temporary WireGuard keys are generated with permission 0600 in a temporary directory and cleaned on script exit. Do not use production keys.

## Run

From the **experimental branch**:

```bash
git switch experimental/qalqan-transport-v0.1
bash scripts/qazwire-baseline.sh

sudo apt-get install -y iproute2 wireguard-tools iputils-ping
mkdir -p .qazwire-lab
go build -o .qazwire-lab/wireguard-go .
sudo bash scripts/qazwire-netns-lab.sh "$PWD/.qazwire-lab/wireguard-go"
```

Build `wireguard-go` as your ordinary user, not via `sudo go build`. Run the privileged script only after reviewing the source and verifying the build comes from your intended commit. The lab script invokes the supplied binary as root to create TUN devices. Avoid running any untrusted binaries this way.

The test depends only on local network namespaces at runtime; fetching Go dependencies may require Internet access on the first build.

## Expected outputs

```text
[1/3] Underlay connectivity...
[2/3] Encrypted userspace tunnel connectivity...
[3/3] Handshake and transfer counters...
PASS: ... handshake and bidirectional transfer
PASS: stock userspace WireGuard connected two isolated Linux namespaces.
```

**Passing means only a baseline tunnel and bidirectional byte counters work in a local synthetic lab.** It does not establish Qalqan integration, packet confidentiality proof, rekey/replay protection tests, or compliance with ST RK 1073-2025.

## Troubleshooting

- `Operation not permitted`: missing CAP_NET_ADMIN, network namespaces blocked by container/virtualization or restrictive host policy.
- `/dev/net/tun unavailable`: TUN module/device unavailable; check host permissions.
- `missing command: wg`: install `wireguard-tools`.
- `UAPI sockets unavailable`: confirm no existing `/run/wireguard` socket collision and check per-node daemon logs emitted on failure.
- `ping` fails: check isolation policies and per-namespace interfaces; don't change host firewall for the test.

If termination is unclean, inspect only namespace names beginning with `qzw-a-` or `qzw-b-` that the run actually printed/created before deleting anything. The default exit handler removes both temporary namespaces.

## Regression policy

Run M0 with the **same** build/Go version and unchanged `master` commit before and after any future Qalqan integration. Record git SHA, Go version and `uname -r` to make performance and compatibility claims reproducible.

**Separate code review required before calling this a complete network/cryptographic test suite.**
