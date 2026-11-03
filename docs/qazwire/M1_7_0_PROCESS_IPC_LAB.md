# QazWire M1.7.0 — synthetic out-of-process Unix IPC prototype

**Base:** M1.6.2 Draft PR #19, commit `2da943ea54daf00966823a2c8b7cdc85e5bc2520`.
**Source of security gates:** R5 Draft PR #18 + `M1_7_ISOLATED_KLM_DESIGN.md`.
**Research Only.** This milestone demonstrates an actual separate Linux process and a restricted **synthetic** IPC protocol. It does NOT create a secure process sandbox, real key owner, reliable Stage D, or cryptographic VPN.

## Components and what they actually do

- `internal/qazwireexp/klmproc17/ipc_linux.go`: fixed 20-byte versioned Unix socket request/response frame. No variable-size payloads, key-export opcode, cryptographic primitive, or VPN egress.
- `cmd/qazwire-klmproc-lab/main_linux.go`: independent worker executable. `klm16.NewLabSession()` is invoked inside the worker process, not the caller; no WireGuard `device/` imports or network sockets.
- Four opcodes: `PING` returns worker PID; `STATUS` returns synthetic epoch; `ROTATE` rotates internal *synthetic* material; `STOP` stops server.
- Unknown opcodes are denied, one request per connection; bounded worker connections (8), per-connection 1s deadline, caller deadline required, response version/opcode/request ID validation.
- Unix socket parent must be an existing absolute `0700`-equivalent private directory owned by worker UID, endpoint must not already exist. Socket permission is `0600`; `SO_PEERCRED` checked against process UID. The same-UID lab does **not** defend against same-UID ptrace or malicious local code.
- Scope is Linux with `-tags qazwire_exp`; no impact on untagged upstream.

## Frame format (network byte order)

```text
0..3   magic = "QK17"
4      version = 1
5      opcode 1=PING, 2=STATUS, 3=ROTATE, 4=STOP (reply: opcode|0x80)
6      status 0=OK, 1=UNSUPPORTED, 2=FAILED (request must be 0)
7      reserved = 0
8..11  request_id uint32 (reply must echo)
12..19 value uint64 (request must be 0; reply PID or synthetic epoch)
```

These labels are not authenticated, nonce-safe or restart-unique. No untrusted network data is accepted. An authenticated IPC scheme with distinct UIDs and cgroup-managed lifecycle remains mandatory.

## Negative security boundary statement

**R5-02 is not closed** merely by using a separate process with the same UID. Host root, same-UID debugger/ptrace under permissive host policy, inherited credentials, same-user code, core dumps and compromised kernel are outside this lab's protection. In `TestM17_RealChildProcessUsesVersionedUnixIPC`, process separation is a positive observation, **not** an isolation proof.

**R5-03/04/07 Stage D remain open.** This prototype has no cgroup v2 subtree, independent launcher, watchdog, PID/user/net namespaces, seccomp, `no_new_privs`, A0 firewall, enforced memory or fork limits, or verifiable descendant kill. The child test process is best-effort killed at cleanup. Do not attach a real secret or production transport.

## Reproduction (Ubuntu Linux)

```bash
go test -tags qazwire_exp -race -count=10 ./internal/qazwireexp/klmproc17
go test -tags qazwire_exp -race -count=1 ./...
go vet -tags qazwire_exp ./...
go build -tags qazwire_exp -o /tmp/qazwire-klmproc-lab ./cmd/qazwire-klmproc-lab
```

The tests execute a child Go test binary as a separate OS process, verify PID separation, private socket mode, status/rotate/stop, denied opcode, invalid frame and ID, denied world-searchable socket parent, and shutdown behavior. CI must record exact SHA.

## Next gates (separate PRs; none passed by M1.7.0)

1. **M1.7.1 launcher / cgroup v2:** start inside dedicated delegated cgroup at process creation, `memory.max` / `pids.max`, `cgroup.kill`, verify `cgroup.events populated=0`; no process-group fallbacks. Deny startup when not authorized (including Ubuntu AppArmor namespace restrictions).
2. **M1.7.2 external watcher + egress:** independent failure domain, A0 nftables deny before kill, restart/session fence, test SIGKILL supervisor, `setsid` descendants, retained FDs and fork storm, no real key material.
3. **M1.7.3 credential and memory protections:** separate UID, `SO_PEERCRED` allowlist supplied by launcher, `no_new_privs`, seccomp, dumpability / `RLIMIT_CORE`, restricted `/proc`, minimal environment, FD closing; independent adversarial tests.
4. **Protocol design:** authenticated handshake/roles/key IDs, per-direction nonce and generation binding, replay window, per-key usage limits, restart identities (R5-E1); still no traffic until G-Q1/G-Q2.

**M2 / Qalqan integration / production VPN: NO-GO.** Never merge to `master` without separate approval.
