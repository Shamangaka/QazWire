# QazWire M1.7.3a P1 — separated network namespaces (offline lab)

**State: implementation drafted, not yet executed on the target host.**
Commit pin required before privileged testing. Does not change production VPN.
Follows P0 counterexample in Draft PR #30; base M1.7.2e fixes in Draft PR #29.

## Topology

\`\`\`text
  worker netns qwhaXXXXXXXX
  - ONLY loopback; no veth, no nonlocal IPv4 route
  - UID65534 / GID65534 worker; separate UID65533 test adversary
          |
          | filesystem AF_UNIX stream pathname, no UDP FD handoff
          | /tmp/qazwire-m173a-p1.XXXXXXXX/ipc/broker.sock
          V
  broker netns qwhbXXXXXXXX
  - UID65533 / GID65534, no caps, NoNewPrivs
  - socket parent directory owned 65533:65534 mode 0710
  - AF_UNIX socket owned 65533:65534 mode 0660
  - SO_PEERCRED admits only worker UID65534/GID65534
  - nft OUTPUT/INPUT default DROP, allow exact synthetic UDP flow
          |
          | veth qwhb0 <-> qwhc0
          V
  peer netns qwhcXXXXXXXX
  - synthetic UDP echo 198.18.27.2:44000
  - 44001 open to test denied port
\`\`\`

Abstract AF_UNIX names are network-namespace scoped, therefore not suitable
for a cross-netns relay by pathname. Filesystem pathname socket requires a
shared reachable mount path; this lab uses a synthetic /tmp directory.

## Expected P1 checks

1. Operator non-root invocation, explicit sudo authorization, no previous
   \`qwha/qwhb/qwhc\` leftovers.
2. Three newly created netns, broker nft installed before underlay veth up.
3. Worker has only loopback and no main-table IPv4 routes; direct UDP for UID
   65534 and an independent process UID65533 results in **ENETUNREACH**.
4. Broker parent exits; detached broker session leader is in exact broker netns,
   UID/GID/capabilities checked by the pidfd helper.
5. Worker can relay exact-size nonce-tagged synthetic payload over pathname
   AF_UNIX to broker. Broker verifies \`SO_PEERCRED\` and performs UDP echo.
6. UID65532/GID65534 (filesystem group permits connect) is denied by broker
   \`SO_PEERCRED\`; UID65532/GID65532 is refused at path permissions.
7. No direct-worker UDP on allowed 44000 or forbidden 44001; verified pidfd
   SIGKILL of broker, after which Unix IPC becomes unavailable and direct
   worker UDP stays unreachable.
8. Cleanup removes only the three new netns and the exact created path.
   No host nft, host routing, keys, Internet, production interfaces or VPN.

Required runtime markers:
\`\`\`text
M173A_P1_WORKER_NO_UNDERLAY_AND_NO_IPV4_ROUTES
M173A_P1_BROKER_DEFAULT_DROP_LOADED
M173A_P1_WORKER_DIRECT_DENIED_BEFORE_BROKER
M173A_P1_DETACHED_BROKER_PID=
M173A_P1_RELAY_PASS
M173A_P1_DIRECT_AND_IPC_NEGATIVE_CONTROLS_PASS
M173A_P1_BROKER_PIDFD_SIGKILL_SENT
M173A_P1_AFTER_BROKER_DEATH_FAIL_CLOSED
M1.7.3a P1 LAB PASS:
M1.7.3a P1 CLEANUP PASS
\`\`\`

Do not treat static tests, log markers alone, or a zero wrapper return code
as independently verified security. Demand exact HEAD, unmodified tree,
correct per-case exit codes, and namespace inventory after cleanup.

## Security limitations

- This design addresses **network topology isolation** under a capless worker
  threat model, not unique-per-process egress authority inside the broker
  namespace. \`meta skuid 65533\` remains defense-in-depth, not process ID.
- A compromised broker, or arbitrary attacker able to run as broker UID in
  broker netns, can still send its permitted UDP traffic.
- Worker and broker share the broker socket's GID to permit pathname IPC;
  this is not equivalent to process-instance authentication or authorization.
- \`SO_PEERCRED\` checks UID/GID; worker instance lifecycle and replay/restart
  policies remain unsolved. \`SO_PEERCRED\` PID check on client is a best-effort
  lab check and not a general authentication primitive.
- Worker must not inherit broker sockets or gain CAP_SYS_ADMIN/setns rights.
  Host root can enter network namespaces, modify nft or replace binaries.
- Worker arbitrary IPC data is strictly bounded in this lab, but production
  framing/rate limiting/DoS protection are not designed here.
- PIDFD kill does not prove immediate revocation of already in-flight UDP.
- Host mount namespace/ACL, full filesystem and cgroup isolation are not
  covered. Worker escape via kernel vulnerabilities remains out of scope.

No automatic merge into main; PR stays Draft pending operator lab results.
