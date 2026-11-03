# QazWire M1.7 — isolated synthetic KLM / Stage D design gate

**Status:** DESIGN ONLY / RESEARCH ONLY. No deployment, real key material, cryptographic primitive, transport integration, or claim of secure erasure.

**Basis:** independent R5 Draft PR #18 @ `105e2c28135dd8bdf89f61cb0de160557dd6e3ab`; M1.6.2 fixes only R5-01. This document specifies an isolated-process laboratory milestone. Approval to implement or integrate a real KLM is separate.

## Threat model and objective

Aim: protect the future key-worker address space from accidental and malicious code running in the **less-trusted transport process**, subject to Linux kernel enforced process, credential, IPC, and resource controls. Do not equate Go unexported types or `reflect` restrictions with a security boundary.

Out-of-scope attacker powers must be written explicitly for each environment: kernel or hypervisor compromise; host root with access to `/proc`, ptrace, dump facilities, or cgroup controllers; physical RAM acquisition; authorized key worker compromise; hostile code injected into the launcher. A separate PID alone does not prevent same-UID ptrace or privileged host inspection. Cross-restart nonce identity and authenticating network peers are **not solved** by OS process separation.

## Proposed components

```text
                 [independent privileged service manager / watchdog]
                      | owns isolated cgroup v2 and launcher policy
                      | cgroup.kill / restart / health supervision
                      v
[transport process, no keys] -- bounded Unix IPC --> [synthetic klmproc]
      | real egress gate (future)                   | separate UID and address space
      | FAIL CLOSED on crash/timeout                | no network access
      | never imports KLM implementation            | private synthetic state
```

1. **launcher**: policy owner independent of the KLM process; creates a new cgroup v2 subtree with hard `memory.max`, `pids.max`, and bounded CPU usage; starts the worker **inside the target cgroup at creation** (`CLONE_INTO_CGROUP` / Go `UseCgroupFD` if supported), rather than moving a running PID afterward. A systemd system service with cgroup ownership is acceptable for the first integration lab if its kill semantics are separately verified.
2. **isolation**: distinct service UID/GID, restrictive filesystem view, no inherited credential-bearing environment or excess file descriptors; `no_new_privs` and capability drop; no core dumps / non-dumpable process; restricted `/proc`, ptrace and IPC access. PID namespace + user namespace + no-network namespace are defence in depth **only where explicitly authorized and tested**; Ubuntu AppArmor can deny unprivileged user namespace creation. Never disable host-wide namespace restrictions merely to make a test pass.
3. **KLM worker**: separate executable, synthetic material **minted only inside worker**, no transport package import and no native network socket. Initially responds to `HELLO`, `STATUS`, `PREPARE`, `ROTATE`, `STOP` using disposable non-secret test bytes; `ENCRYPT`, `OPEN`, `EXPORT_KEY` or arbitrary command execution are absent.
4. **IPC**: one Unix domain endpoint, explicit major/minor protocol version, short fixed-length header with length cap, bounded payload and queued requests, request ID, direction/epoch fields marked *synthetic*, timeouts, server-side peer-credential check (`SO_PEERCRED`), denial of unrecognized opcodes, and hard rejection of key-material export. Credentials and socket permissions must be checked, not trusted from request parameters. Correctness is tested across reconnects, replayed request IDs and concurrent close.
5. **watchdog**: manages failure independently of transport and KLM. On lease timeout, fatal health failure, or supervisor death: set A0 egress fence, issue **`cgroup.kill`**, verify `cgroup.events` `populated=0` before declaring termination, and require a new authenticated session domain before any restart. A hanging kernel task may delay the observed empty condition: report *not confirmed*, never claim secure erasure.
6. **egress**: future transport gate fails closed even if IPC worker returns late, crashes, or restarts. No packet is emitted using an expired generation. A0 firewall/network-block design needs separate proof before any real traffic. The KLM must be unable to send network packets itself.
7. **memory**: per-process RSS hard cgroup budget plus logical queue/arena budget and length cap. For future secrets, independent evaluation of native/Rust arena, `mlock`, `MADV_DONTDUMP`, zeroization, and Go/FFI copies is required. Memory reclamation / `SIGKILL` is not a proof of physical erasure.

## M1.7 lab deliverables (not implemented by M1.6.2)

- Versioned Unix IPC contract and separate `klmproc` binary with synthetic deterministic test behavior.
- Privilege-minimized launcher and externally owned cgroup v2 on a dedicated lab VM; root required only for narrowly scoped setup.
- Independent watchdog + A0 egress denial demonstration; systemd service unit + policy profile where appropriate.
- Matrix for unsupported cgroup/namespaces/AppArmor combinations: deny startup and return a clear error, **never fall back** to process-group kill while reporting protection.
- Scheduler / fault-injection tests of worker, launcher, and watcher against **real Linux process trees**, with no key material.

## Mandatory adversarial acceptance tests

| Gate | Test stimulus | Expected observation |
| --- | --- | --- |
| P1 | fork child then `setsid`, kill worker | all worker-cgroup processes terminated; `populated=0` |
| P2 | SIGKILL KLM supervisor | independent watchdog fences egress and kills group |
| P3 | fork storm / memory exhaustion | `pids.max` / `memory.max` limits enforced; no bypass |
| P4 | worker inherits FD/env/proc access | forbidden handles and secrets absent, `RLIMIT_CORE=0` and dumpability restricted |
| P5 | blocked IPC / delayed response | bounded deadline; stale result rejected, A0 remains blocked |
| P6 | namespace unavailable under Ubuntu AppArmor | explicit startup refusal; no global `sysctl` changes |
| P7 | worker crash and restart | new synthetic instance distinguished; real nonce/key identities remain BLOCKED |
| P8 | malicious transport tries to inspect worker | denied under stated UID/ptrace/proc/credential threat assumptions |
| P9 | watchdog reports success | `cgroup.events populated=0` observed or status `NOT_CONFIRMED`; never fake an erase guarantee |
| P10 | full Go tree regression | tagged/untagged tests, -race, vet, gofmt, reproducible SHA evidence |

## Protocol specification is a distinct workstream

Before real crypto, independently specify, review and test: per-direction authenticated key identity, binding to handshake and roles, IV/nonce injectivity across generations and restarts, AD including generation, receiver replay window, send/receive synchronization, per-key usage budget (sigma, count and lifetime), all-or-nothing egress authorization, and fail-closed behavior on crash and rollback.

**Gates for M2:** G-Q1 (independent cryptanalysis), G-Q2 (regulator), complete key/nonce/replay protocol and security proof obligations, native secret boundary and containment, clean full builds. Each remains **BLOCKED/PENDING**. Passing M1.7 synthetic tests cannot reopen M2.

## Review principles

Pin exact SHA, test on Ubuntu 24.04 (including AppArmor policy restrictions) and at least one dedicated controlled Linux VM with cgroup delegation. Keep all production security language conditional. Never merge anything to `master` without explicit owner approval. A clean independent audit of the boundary is required before changing this document from DESIGN ONLY.
