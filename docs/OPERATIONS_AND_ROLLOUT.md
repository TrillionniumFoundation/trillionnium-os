# Trillionnium OS Operations, Deployment and Rollout

Status: **NORMATIVE DESIGN — target evidence pending**

## 1. Canonical install manifest

One immutable manifest binds:

```text
source commit and tree
module and protocol versions
product entrypoint and internal child hashes
provider executable, config and identity
exact argv
UID, GID and supplementary groups
mount, PID, network and user namespaces
cgroup path and resource limits
sockets, tokens and descriptors
event, job, broker and control stores
SELinux domains and file contexts
restart and backoff
emergency-stop inhibit path
state-schema versions and migration plan
```

Android product files, Root Linux packaging, qualification and evidence consume
the same manifest.

## 2. Startup

1. Validate immutable manifest and executable/configuration parents.
2. Verify binary and configuration hashes.
3. Validate identity, namespace, cgroup, mount and writable roots.
4. Open, lock and recover stores.
5. Reconcile incomplete operations without redispatch.
6. Load control epoch and reject stale leases.
7. Start internal processes under lifecycle guards.
8. Complete provider/core/broker handshakes.
9. Publish admission endpoint and readiness.
10. Emit exact component, schema, lease and store identities.

Readiness is false until the service can accept, persist, terminate or
truthfully reconcile work under its configured policy.

## 3. Shutdown and emergency stop

Administrative shutdown is not semantic cancellation.

Normal shutdown:

- stop admission;
- preserve read-only inspection;
- drain where bounded;
- signal and reap owned process groups;
- persist lifecycle results;
- remove only epoch-owned endpoints;
- retain uncertain remote effects as unknown.

Emergency stop is independent of Codex, provider and normal transport. It closes
admission, sets a supervisor-owned inhibit, terminates owned process groups,
prevents respawn and records what was or was not proven stopped. Clearing the
inhibit requires explicit operator action.

## 4. Module rollout

Rollout stages:

```text
build and sign candidate
 -> contract qualification
 -> shadow/read-only deployment
 -> small canary partition
 -> bounded traffic increase
 -> full deployment
```

Every stage has:

- exact module and state versions;
- health and performance thresholds;
- maximum exposure;
- dwell time;
- stop condition;
- rollback target;
- evidence artifact.

## 5. State migration

Migration plans declare:

```text
old and new schema
read/write compatibility matrix
backup or checkpoint
dual-read/dual-write period
fencing and writer order
migration idempotency
verification query
rollback limits
unresolved operation handling
```

An incompatible module never silently starts against unknown state. It remains
inhibited with inspection available.

## 6. Control-plane outage

Modules continue only inside non-expired leases. When authority expires:

- new state-owning or effectful admission stops;
- existing effects continue to truthful terminal or unknown state;
- cleanup and inspection remain available;
- stale writers are fenced;
- the restored controller reconstructs read models and reissues leases;
- no operation is resubmitted automatically.

## 7. Health

Health exposes mechanical facts only:

```text
module and instance ID
binary/config digest
control epoch and lease expiry
state schema
last durable cursor
queue and resource utilization
active turn/call/job counts
last reconciliation error
emergency-stop state
```

It does not claim a command was semantically correct or desirable.

## 8. Rollback

Code rollback and state rollback are separate. Rollback is permitted only when
the prior version can read current state or a verified reverse migration exists.

If safe rollback is impossible, the system fences the new writer, remains
read-only where possible, preserves evidence and requires explicit recovery.
