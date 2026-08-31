# Owner-open deployment, lifecycle and emergency-stop runbook

Status: **ACTIVE DESIGN — final entrypoint and target evidence pending**  
Plan revision: `2026-08-29-r6`  
Related gaps: `R5-GAP-PRODUCT-ENTRYPOINT-001`, `R5-GAP-ROOTLINUX-PLACEMENT-001`, `R5-GAP-ANDROID-GRAPH-001`, `R5-GAP-FAULT-MATRIX-001`

## 1. Purpose

This runbook defines the deployable owner-open service graph. It prevents
qualification of one binary or path while Android/init installs another.

The final values remain placeholders until Issues #19, #2 and #13 close. A
placeholder is not installation evidence.

## 2. Canonical install manifest

The product profile must generate one canonical manifest:

```json
{
  "schema": "org.trillionnium.owner-open.install-manifest.v1",
  "source_commit": "<sha>",
  "source_tree": "<tree>",
  "product_entrypoint": {
    "source_target": "<cargo-bin>",
    "installed_path": "<absolute-path>",
    "sha256": "<sha256>",
    "argv": []
  },
  "internal_children": [],
  "provider": {},
  "identity": {},
  "namespaces": {},
  "cgroup": {},
  "sockets": {},
  "stores": {},
  "selinux": {},
  "restart": {},
  "emergency_stop": {}
}
```

Android product files, init, Root Linux packaging, qualification scripts and
evidence all consume this exact manifest.

## 3. Required product topology

Target topology:

```text
Android init/service manager
  -> owner-open product entrypoint
       -> optional same-trust-domain broker
       -> bounded transport
       -> execution core
       -> installed provider/Codex
       -> direct shell / ordinary adb / durable job child
```

Until the entrypoint gap is closed, the package's foundation
`UnavailableProvider` binary must not be installed as the product merely
because it has the shortest name.

## 4. Identity and filesystem contract

The manifest declares:

```text
service UID/GID
supplementary groups
provider UID/home
socket owner/group/mode
descriptor/token owner/mode
event/job/broker store owner/mode
writable overlay/mount
executable and configuration parent ownership
```

Requirements:

- executable/config parents are not writable by the runtime service;
- mutable stores live under a dedicated service-owned directory;
- token, descriptor and private state are regular non-symlink files where the
  protocol requires files;
- hard-link count and owner/mode are verified;
- socket cleanup removes only the exact device/inode created by the service;
- mount ancestry and read-only/read-write boundaries are recorded;
- a same-UID peer is considered inside the same local trust domain.

## 5. Namespace and cgroup contract

The target records:

```text
mount namespace
PID namespace
network namespace
user namespace if used
cgroup v2 path
memory limit
process limit
CPU limit/weight
I/O policy
allowed address families
capability set
no_new_privs/seccomp policy
```

Resource limits are mechanical. They may terminate or reject work when finite
bounds are exhausted; they may not classify command meaning.

Each child process records its cgroup and namespace identity. A child that
escapes the expected cgroup/session is a lifecycle fault.

## 6. Socket and admission contract

Foundation development may use a private filesystem Unix socket. Android
product integration must declare the selected carrier:

```text
filesystem UDS or Android abstract socket
socket name/path
listen owner
peer credential checks
SELinux client/server domains
token/descriptor use
maximum clients/backlog
```

For an abstract socket, filesystem mode does not exist; SELinux and peer
credentials become load-bearing. Documentation must not copy filesystem-UDS
claims to an abstract socket.

## 7. Store layout

Recommended logical separation:

```text
/var/lib/trillionnium/owner-open/turn-events
/var/lib/trillionnium/owner-open/job-events
/var/lib/trillionnium/owner-open/broker-audit
/var/lib/trillionnium/owner-open/transport-events
/run/trillionnium/owner-open/socket-or-descriptor
/run/trillionnium/owner-open/emergency-stop
```

Actual paths are platform-selected and manifest-bound.

Each store defines:

```text
maximum bytes
maximum records
rotation trigger
retention
sync policy
writer lock
corruption quarantine path
repair policy
startup recovery-time budget
ENOSPC behavior
```

A store failure never authorizes an uncertain effect retry.

## 8. Startup sequence

1. Read and validate immutable install manifest.
2. Verify product/internal/provider executable hashes.
3. Validate service identity, mount ancestry, configuration and writable roots.
4. Open and lock stores; record status.
5. Reconcile incomplete durable operations without redispatch.
6. Remove only proven stale socket/descriptor objects.
7. Start internal core/provider process trees under lifecycle guards.
8. Complete upstream protocol handshake.
9. Bind/publish admission endpoint and descriptor epoch.
10. Emit readiness containing exact component identities and store status.

Readiness must not be emitted before the service can accept, persist and
truthfully terminate/reconcile work according to its configured policy.

## 9. Shutdown sequence

Administrative shutdown is distinct from semantic cancellation.

1. Stop new admission.
2. Emit `shutting_down`.
3. Refuse new effectful operations.
4. Continue read-only inspection when possible.
5. Request provider/turn/job cancellation only where explicitly configured.
6. TERM then KILL owned process groups after finite grace.
7. Reap leaders and check process groups observed gone.
8. Flush/sync terminal lifecycle records.
9. Remove only the exact socket/descriptor objects owned by this epoch.
10. Emit or persist shutdown terminal status.

Shutdown does not claim already accepted remote or ADB effects were cancelled
unless a terminal observation proves it.

## 10. Restart and reconciliation

On restart, each durable operation is classified:

```text
accepted + terminal     -> replay terminal
accepted + started/live -> inspect/reconcile
accepted only           -> unknown unless no-effect proof exists
forwarded no terminal   -> unknown_after_disconnect
terminal observed but undurable -> reconciliation_required
```

The supervisor must not automatically resubmit an incomplete operation.

Provider/core/transport/broker restarts are tracked as distinct epochs.
Connection-local live handles do not survive unless a separately qualified
supervisor-owned descriptor transfer mechanism exists.

## 11. Emergency stop

Emergency stop is independent of provider/Codex and normal client protocols.

It must be able to:

- stop new admission;
- set a durable or supervisor-owned inhibit flag;
- terminate the broker, transport, core and provider process groups;
- signal/terminate owned live jobs according to the emergency policy;
- prevent automatic service respawn;
- expose inspection of what was and was not proven stopped;
- require an explicit operator action to clear the inhibit.

It must not:

- claim a remote effect was reversed;
- erase durable evidence;
- reinterpret an uncertain operation as cancelled;
- depend on Codex, MCP or the broker being healthy.

### Emergency-stop states

```text
armed
triggered
admission_closed
termination_requested
processes_observed_gone or cleanup_uncertain
respawn_inhibited
cleared_by_operator
```

L4 proves the normal stop path on device. L5 proves stop during hung provider,
busy output, storage failure and reboot.

## 12. Restart policy

The service manager declares:

```text
restart conditions
restart delay/backoff
maximum restart burst
health/readiness timeout
dependency ordering
inhibit condition
```

Automatic process restart is permitted. Automatic effect redispatch is not.

A restarted Host exposes prior incomplete operations through inspection and
reconciliation.

## 13. Upgrade and rollback

Upgrade evidence binds:

```text
old and new source/tree
old and new install manifests
store schema compatibility
binary/config hashes
drain/quiesce result
backup/checkpoint
migration
first-start reconciliation
rollback path
```

An upgrade must not silently discard or replay accepted operations. If schema
or state cannot be reconciled, the service remains inhibited and read-only
inspection is preferred.

## 14. Observability and health

Readiness/health expose mechanism facts only:

```text
component epoch and executable digest
store status and last durable cursor
active turn/call/job counts
queue/window usage
delivery attachment status
last reconciliation error
emergency-stop state
```

Health must not report semantic success or permission.

Metrics and logs are bounded and must not leak tokens, provider credentials,
unredacted prompts or arbitrary command content unless the owner-selected
evidence policy explicitly permits it.

## 15. Qualification checklist

### L2 target Root Linux

- product entrypoint hash/argv;
- internal child/provider hashes;
- UID/GID/home, cgroup and namespace;
- mount/store/socket identity;
- same-turn shell and pipe/PTY job trace;
- restart/reconnect/no-redispatch;
- emergency-stop process and inhibit state.

### L3 Android image

- clean manifest/project heads and patch series;
- Soong module and installed-file inventory;
- init service/socket/property graph;
- SELinux domain, allow and file-context reports;
- target-files and image hashes;
- no forbidden legacy nodes.

### L4 physical normal path

- device serial/fingerprint/boot ID;
- image and installed manifest identity;
- AiShell connection;
- installed Codex turn;
- shell/job/ordinary-ADB effects;
- emergency stop and explicit recovery.

### L5 fault path

- provider/core/transport/broker/client SIGKILL;
- job descendant and cleanup cuts;
- ENOSPC, fsync failure and record corruption;
- USB loss, adb-server restart and device reboot;
- power-loss/restart reconciliation;
- service-manager restart burst and inhibit behavior.

## 16. Operator go/no-go

Deployment is NO-GO when any of these is true:

```text
manifest hash mismatch
ambiguous product entrypoint
forbidden Android graph node
store required but unavailable
stale descriptor/token epoch
unreconciled operation hidden from inspection
emergency stop cannot inhibit respawn
required L2/L3/L4/L5 evidence absent
public_release requested without L6 authorization
```

Source CI success alone never changes this decision.
