# ADR: owner-open semantic authority and process topology

Status: **ACTIVE**  
Date: **2026-08-29**  
Plan revision: `2026-08-29-r6`  
Decision scope: R5 owner-open broker, transport, core, provider, runtime, Android and Root Linux integration

## Context

R3 says Codex is the only semantic control plane. The current R5 implementation
uses more than one operating-system process:

```text
client
  -> optional Python connection broker
  -> Rust transport carrier
  -> Rust execution core
  -> external provider/Codex
  -> shell/adb/job child process
```

Without a typed authority boundary, “one Host” can be misread as one process,
while implementation components can accidentally become additional semantic
principals by rewriting a request, selecting a provider/target, interpreting an
error, or retrying an uncertain effect.

The default package also exposes several similarly named binaries. Deployment
must not infer the supported product entrypoint from naming alone.

## Decision

### 1. One semantic principal does not require one process

R5 permits multiple mechanism processes. It permits exactly one semantic
principal for a turn: the selected provider/Codex process.

A mechanism process may enforce byte/count/time/process/storage bounds and may
refuse malformed or mechanically unsafe input. It may not decide whether the
meaning of a valid command is desirable, risky, approved or worth retrying.

### 2. Component authority matrix

| Component | Required role | Permitted transformations | Forbidden decisions |
| --- | --- | --- | --- |
| AiShell/client | render and submit owner intent | construct client envelope and controls | infer terminal success from delivery failure |
| Connection broker | local admission, correlation, bounded fan-out | add broker epoch, exact sequence and ownership metadata | choose tool/target/provider, rewrite argv, retry |
| Transport carrier | frame forwarding, delivery credit, detach/resync | rewrite transport-local sequence/delivery fields only | suppress terminal truth, pause execution, retry |
| Execution core | turn/call/job routing and persistence | canonical Host framing and correlation | reconstruct plan, semantic approval, provider fallback |
| Provider/Codex | semantic reasoning | choose intent/tool/target/command/retry/compensation | bypass mechanical identity and resource bounds |
| Direct runtime/job manager | process mechanics | exact command/argv execution and lifecycle metadata | command allowlists, target substitution, hidden retry |
| Event/job/broker stores | observation and recovery facts | canonical records, hashes and cursors | authorize action from absence of evidence |
| Android/init/Root Linux supervisor | installation and lifecycle | fixed launch argv, identity, cgroup, namespace and restart mechanics | semantic fallback or automatic uncertain-effect replay |
| Emergency stop | inhibit/terminate owner-open lifecycle | stop admission, signal/reap, inhibit respawn | report successful effect cancellation without evidence |

### 3. Request immutability

The following bytes are provider-owned and must be preserved after mechanical
validation:

```text
tool
target_id as provider-selected correlation/routing metadata
command or argv
cwd
environment delta
stdin
timeout request within finite platform bounds
job mode and PTY dimensions
```

A mechanism component may reject malformed or over-bound values. It may not:

```text
insert -s into adb argv
insert a host/port
replace a target
choose a weaker privilege mode
rewrite shell syntax
silently choose another provider
convert a failed effect into a semantic denial
```

### 4. Correlation transformations are explicit

A layer may add only fields in its namespace:

```text
client_seq
broker_epoch
broker_request_id
broker_upstream_seq
host_seq
turn_stream_id
event_id
delivery_cursor
transport_gap
```

Every added field binds the unchanged request digest. A layer must not overload
one sequence field to mean client, broker and Host order simultaneously.

### 5. Retry authority

No mechanism layer may automatically redispatch an effect after:

```text
write/spawn attempt
accepted without terminal
disconnect after possible dispatch
timeout after accepted dispatch
journal failure after possible effect
Host/broker/provider restart with incomplete state
USB or adb-server loss after dispatch
```

A provider may choose a new compensating or retry action only after receiving
and interpreting the conservative observation. The new action uses a new
operation identity unless the protocol explicitly reattaches/replays an exact
known request.

### 6. Product entrypoint

The final product must have one machine-declared entrypoint. Until
`R5-GAP-PRODUCT-ENTRYPOINT-001` is closed, none of the similarly named Cargo
binaries may be assumed to be the final installed product.

The install manifest must bind:

```text
product executable and SHA-256
internal child executable(s) and SHA-256
exact argv
provider executable/config identity
UID/GID/supplementary groups
namespace/cgroup
socket/token/descriptor paths
event/job/broker stores
SELinux domain and file contexts
restart/backoff
emergency-stop inhibit path
```

Android product files, init, qualification and evidence must consume that same
manifest.

## Process lifecycle boundary

Every spawned provider, runtime, job or core child is owned by a lifecycle
guard from successful spawn until observed reap. The guard is responsible for:

```text
process-group/session identity
PID start identity
parent-death behavior where supported
FD closure
TERM-to-KILL escalation
leader reap
descendant/process-group observed-gone result
cleanup-error preservation
```

A leader exit alone is not proof that descendants are gone.

## Persistence boundary

Stores record facts. They are not admission authorities unless a particular
operation requires durable acceptance before effect. For each operation the
protocol must declare:

```text
durable_before_effect
durable_after_effect
continue_when_unavailable
replayable_terminal
uncertain_restart_result
```

Absence, corruption or failure of a store never proves `not_started` after an
effect attempt could have occurred.

## Broker trust boundary

The foundation broker uses same-UID peer credentials plus a private token.
This protects against accidental or differently privileged peers. It does not
provide strong isolation from a process that has already compromised the same
service UID and can read its private files.

Android admission therefore requires explicit SELinux/domain and socket
policy. The descriptor/token epoch must be rotated on broker restart, and stale
descriptors must fail closed.

## Consequences

### Positive

- process decomposition remains possible without multiplying semantic control
  planes;
- exact request ownership and no-redispatch rules become reviewable;
- deployment can distinguish product and internal binaries;
- protocol and fault evidence can be mapped to one authority model.

### Costs

- every field mutation needs namespace and digest review;
- process boundaries require additional audit and fault tests;
- a “helpful” fallback or retry in broker/transport/core is prohibited;
- source tests alone cannot settle installation and supervisor behavior.

## Rejected alternatives

### A single monolithic process

Rejected as a requirement. It would reduce some correlation surfaces but does
not itself guarantee one semantic authority, and it complicates independent
delivery, control and lifecycle supervision.

### Broker as a second planner

Rejected. Shared connection ownership does not authorize the broker to classify
or schedule semantic work.

### Automatic retry after timeout/disconnect

Rejected because the original effect may have started.

### Inferring product entrypoint from executable name

Rejected because the current package contains a foundation unavailable-provider
binary and separate selected transport/core binaries.

## Verification obligations

The gap verifier must require this ADR and the authority terms above. Source and
integration tests must include negative fixtures that attempt to:

- introduce provider fallback;
- rewrite argv or inject ADB routing flags;
- satisfy one request with another request's terminal;
- redispatch after an uncertain crash cut;
- package the unavailable-provider stub as the product entrypoint;
- mark an external evidence lane closed from a source fixture.
