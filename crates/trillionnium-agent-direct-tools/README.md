# Agent direct tools

> **2026-08-27-r3 note:** The canonical owner-open plan at
> [`docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](../../docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
> supersedes the restrictive sections below for the development product.
> Codex must receive direct shell.command/shell.exec and raw adb.exec; the
> seven-command list, risk_guard, typed-only ADB boundary and mandatory
> production-durable authority are migration/release material, not a
> prerequisite for owner-open dogfood. Update this README as the implementation
> lands rather than adding another broker.

> **Reading the remainder:** sections below describe the historical pre-r2/r2
> typed System API/Accessibility and sealed broker implementation. They are
> retained for migration notes and tests only. They do not define the default
> owner-open shell/ADB contract and must not be used as a start gate.

The intended owner-open crate exposes direct tool entrypoints for the one Codex
principal. There is no runtime semantic broker, common backend selector,
Authority hop, approval service, or fallback dispatcher. The current source
snapshot below is still pre-r2 for the ADB/worker path; P0 replaces that path
with raw shell/ADB transport while retaining the same framing primitives:

- `trillionnium-agent-system-api` connects directly to the Android System API
  backend at abstract socket `@trillionnium_system_api`.
- `trillionnium-agent-accessibility` connects directly to the Android
  `AccessibilityService` backend at `@trillionnium_accessibility`.
- `trillionnium-agent-adb` is a pre-r2 engineering/recovery adapter. Its inert,
  typed `android.adb.*` contract and fail-closed production path are migration
  material; the owner-open implementation replaces it with a transparent raw
  ADB client/server path as specified by the canonical plan.

The shared Rust code is serialization, framing, validation, test code, and the
feature-gated trusted-context/operation-journal integration described below.
It does not choose a backend or forward one backend to another.

The historical custody section below names `trillionnium-agent-privilege-broker`
as an admissible producer because it documents the pre-r2 sealed profile. That
binary is itself the old Authority and is not started, linked or required by
the owner-open graph. Its `mutation_unavailable`/HOLD behavior must never be
used as the owner-open shell/ADB result; direct tools execute through the raw
Codex path and return the real process/ADB observation.

## Non-product backend-wire JSON mode

Only the explicit development compatibility lane accepts no arguments. In that
lane, the executable reads one backend-wire JSON object from stdin and writes
one JSON object plus a newline to stdout; requests are capped at 256 KiB.
Production durable binaries accept only `semantic` or `mcp` and reject raw-wire
mode before reading stdin. Empty/default-feature binaries reject before any
mode can read stdin.

System API example:

```sh
printf '%s\n' '{"protocol":"org.trillionnium.agent-system-api.v1","request_id":"req-1","action":"launch_package","package":"com.android.settings","user":0}' |
  trillionnium-agent-system-api
```

Accessibility example:

```sh
printf '%s\n' '{"protocol":"org.trillionnium.agent-accessibility.v2","request_id":"req-2","action":"snapshot","snapshot_mode":"metadata_only","window_id":null}' |
  trillionnium-agent-accessibility
```

Both Android backends use exactly one newline-terminated response frame per
connection. The response must echo the exact `protocol` and `request_id`. The
client allocates at most 1 MiB for the response body and rejects an unterminated,
oversized, mismatched, repeated, or non-closing response.

A bound response with boolean `ok: false` and a bounded snake-case `error` code
is a structured backend outcome, not a transport failure. One-shot mode writes
that original JSON object and exits normally, preserving replay decisions such
as `request_id_conflict`, `request_in_flight`, outcome indeterminacy, and replay
capacity exhaustion. Missing or non-boolean `ok`, a missing/non-string/invalid
error code, contradictory `ok: true` plus `error`, or an error code longer than
128 bytes fails closed.

## Semantic one-shot mode

`semantic` mode accepts only the business action and its bounded parameters:

```sh
printf '%s\n' '{"action":"launch_package","package":"com.android.settings"}' |
  trillionnium-agent-system-api semantic

printf '%s\n' '{"action":"snapshot","snapshot_mode":"metadata_only","window_id":null}' |
  trillionnium-agent-accessibility semantic
```

The model-facing object cannot contain `protocol`, `request_id`, or Android
`user`. The adapter fixes the existing backend protocol, fixes System API calls
to user 0, and injects a backend replay identity before serializing the
unchanged Android wire request. Under `production-durable-hotpath`, that
identity comes from the durable operation journal. The empty/default feature
set intentionally compiles inert System API and Accessibility executables: each
returns a fixed `backend unavailable` error before reading stdin, parsing MCP,
opening a socket, or touching a journal. There is no implicit effect fallback.

The old kernel-random process epoch and checked local sequence are available
only under the explicit non-product `development-compatibility-lane`. That lane
prevents caller-selected identities but is deliberately not restart-stable
exactly-once authority and is forbidden from the production feature graph.
Root-Linux product artifacts explicitly compile
`production-durable-hotpath`; the product and development lanes are
compile-time mutually exclusive. The product lane fails before backend contact
unless kernel launch custody, the binding inbox, and secure journal
provisioning are all present.

The System API action surface is closed to `launch_package` and `open_uri`.
Explicit Android component launch is deliberately unavailable because a
system-server caller must not become a confused deputy for arbitrary exported
components. Validation requires a canonical Android package, a user in
`0..=999`, a bounded request ID, and one of `http`, `https`, `content`, or `geo`
for URI opening. Unknown actions and JSON fields are rejected.

Accessibility batches contain only typed `click`, `set_text`, `scroll`,
`global_action`, or `gesture` elements. A batch cannot contain `snapshot` or
another batch. There are at most 128 elements; gesture points must start at
`at_ms=0`, be strictly ordered, stay within the declared duration, and the sum
of all gesture durations in a batch is at most 60,000 ms.
`set_text` content is bounded to 16,384 UTF-16 code units, matching the
Rust and Android wire validators for both BMP and astral characters.

Every snapshot explicitly selects the closed privacy mode `metadata_only` or
`full_text`; the backend must echo both `action: "snapshot"` and the exact mode.
`metadata_only` requires empty `text` and `content_description` throughout the
tree. `full_text` remains disabled by product policy, and its response validator
would still require password nodes and all descendants to be redacted. Snapshot
successes are accepted only with the exact Accessibility backend/capacity and
`read_only_resampled` replay bindings, a positive generation, one nonnegative
window, and a closed recursive tree. The adapter caps the tree at 1,024 nodes
and depth 32, requires unique 1..512-character ASCII node IDs from the exact
`[A-Za-z0-9._:/-]` domain, one window throughout, bounded
strings (512 Unicode scalar values, never UTF-8 bytes), signed 32-bit
rectangles, and rejects unknown fields or actions. The MCP snapshot schema
advertises the same nonnegative signed-32-bit `window_id` maximum enforced at
runtime.

## Pre-effect product risk guard

System API and Accessibility now evaluate every validated typed request before
opening a backend socket. Product identity comes only from fixed real/effective
UID and GID pair: Codex 5901. Environment variables, model
fields, executable arguments, and raw provider/model names cannot select an
identity or lower risk. Metadata-only snapshots, package launch, Accessibility
scroll, and the Back/Home global actions are the closed default-allow set.
URI opening, full-text snapshots, clicks, text mutation, gestures, and other
sensitive/critical actions return a structured `operation_denied` result while
the OS lease issuer remains unavailable; no backend connection is attempted.

Denials contain closed, non-secret `risk_guard` evidence whose digest binds the
typed action without copying URI, node ID, text, or result material. Backend
responses are forbidden from supplying the reserved `risk_guard` field. An
allowed backend response is not enlarged with adapter evidence: that preserves
the audited 1 MiB MCP delivery boundary after a potentially effectful call.
This guard is a live pre-effect deny/allow boundary, but it does not activate
the journal foundation or claim exactly-once execution.

## MCP stdio mode

The System API and Accessibility binaries also implement a minimal standard MCP
stdio server:

```text
trillionnium-agent-system-api mcp
trillionnium-agent-accessibility mcp
```

The servers implement JSON-RPC 2.0 `initialize`, `notifications/initialized`,
`ping`, `tools/list`, and `tools/call` using one JSON message per line. Each
process exposes exactly one tool:

- `trillionnium_system_api`
- `trillionnium_accessibility`

Every action variant in each advertised input schema has
`additionalProperties: false`; the MCP schemas are the same semantic-only
objects accepted by `semantic` mode and expose no backend envelope fields.
Backend failures are returned as MCP tool results with `isError: true`, while
successful outcomes retain `isError: false`.
`structuredContent` preserves the complete validated backend object. The single
text content block does not copy that body. It is instead this exact compact,
closed binding object, with fields in the shown order:

```json
{"schema":"org.trillionnium.mcp.structured-content-binding.v1","structured_content_sha256":"<64 lowercase hex>","structured_content_bytes":123}
```

The byte count and SHA-256 cover the exact compact UTF-8
`serde_json::to_vec(structuredContent)` bytes. Consumers must reject extra or
missing binding fields, a second content block, a non-text block, a non-object
`structuredContent`, or any byte-count/hash mismatch. This keeps the backend
body in one place and closes Codex 0.144.1's behavior of clearing structured
content when a serialized `CallToolResult` exceeds its 1 MiB output cap.

The adapter enforces a 1,048,576-byte serialized `CallToolResult` cap, reserves
an audited maximum 512-byte binding/envelope overhead, and therefore guarantees
structured content through 1,048,064 bytes. A larger structured object is
accepted only when its actual serialized `CallToolResult` still fits the 1 MiB
cap; cap-minus-one and cap are accepted, while cap-plus-one fails closed.
Transport, peer-authentication, framing, binding, or malformed-response failures
use the bounded generic `direct_tool_error` result and do not crash the
long-running stdio server.

The paired Codex event mirror budgets one JSONL line as 256 KiB request plus
1 MiB `CallToolResult` plus 128 KiB wrapper (1,441,792 bytes), and independently
caps aggregate stdout at 16 MiB. Cross-layer tests carry an approximately
1.04 MB structured result through binding verification, JSONL mirroring, and
evidence ingestion. The larger outer line budget does not weaken this
producer's 1 MiB `CallToolResult` cap or the aggregate 16 MiB boundary.

The size check necessarily occurs after the backend returns. If an effectful
backend ever produces a larger result, the MCP process fails stop without
emitting a replacement tool result. The backend has already returned its exact
structured outcome; only caller delivery is indeterminate. Logs state
`caller_delivery_indeterminate`; a semantic caller must not invent or retry a
backend request identity. Durable journal recovery remains authoritative when
the production hotpath is admitted. The server must never turn that outcome
into a generic failure object or invite execution under a new request ID. The
durable journal reserves bounded terminal-result capacity before allocating an
operation and retains the exact definitive response for restart replay.
Release still remains on HOLD until the root-owned custody producer, secure
first-use provisioner, outer ACK producer, and device recovery path are wired.

## Inert defaults, fixed product endpoints, and explicit development effects

The default/no-feature System API and Accessibility binaries do not consume
stdin or connect to any endpoint. Product builds ignore endpoint environment
variables and use the two compiled abstract-socket names above only after
durable launch-context admission. The Root Linux build helper explicitly uses
`--no-default-features --features
trillionnium-agent-direct-tools/production-durable-hotpath`.

Non-product development builds may explicitly opt in to the ephemeral effect
lane and endpoint redirection:

```sh
cargo build -p trillionnium-agent-direct-tools \
  --no-default-features \
  --features development-compatibility-lane
```

`development-compatibility-lane` enables `dev-overrides`, and only that explicit
lane compiles the pre-journal System API and Accessibility backend calls.
Selecting `dev-overrides` alone does not activate those effects. Development
compatibility builds honor `TRILLIONNIUM_SYSTEM_API_SOCKET`,
`TRILLIONNIUM_ACCESSIBILITY_SOCKET`, or `TRILLIONNIUM_ADB_PATH`. The ADB path
must still be absolute and identify an owner-controlled, executable, non-symlink
regular file.

## Production-compiled direct-operation identity and journal path (runtime HOLD)

`trillionnium-os-types::direct_operation`, `src/trusted_context.rs`, and
`src/operation_journal.rs` implement the pre-effect protocol. Root-Linux
System API and Accessibility artifacts select
`production-durable-hotpath` explicitly while retaining
`--no-default-features`; ADB remains unavailable. The product lane consumes the
fixed launch context, journals PREPARED and exact terminal-result state around
the backend call, and consumes only an exact fixed outer-ACK V3 inbox. It adds
no newly allowed action and is not a broker, backend selector, dispatcher,
Authority hop, or second policy engine.

The stable invocation ID is a domain-separated, length-prefixed digest of the
closed provider/Agent pair, OS task ID, signed provider invocation and session
digests, subject UID, and subject SELinux-domain digest. Egress grants, nonce,
expiry, raw prompts, requests, URIs, text, results, and risk payloads are
deliberately excluded. A provider attempt is separately and deterministically
derived from the measured runtime-lifecycle digest, a non-zero daemon-authored
generation, and a daemon-authored context digest. An arbitrary string with an
`attempt:` prefix is not a valid attempt identity.

The root-authored `DirectOperationBinding` and inbox are now strict schema v3.
In addition to the stable v1 invocation/attempt identities, the top-level
binding carries non-zero lowercase SHA-256 values for the exact
`req-<32lowerhex>` workflow ID, the OS registration identity key, and the
remeasured adapter executable plus the exact ordered authorized-adapter set.
These fields enter the v3 binding digest and are
cross-checked against claims, runtime identity, and durable egress state.
Legacy v1/v2, missing or unknown fields, unauthorized adapter profiles,
zero/uppercase/malformed digests, and a
recovery delivery that swaps any identity fail closed. These fields are never
accepted through MCP, model JSON, argv, environment, or a caller-selected
path. The current OS registration identity digest still equals the executable
digest, however; that is a measured consistency check, not an independently
signed AgentDescriptor identity pin, and product promotion remains HOLD on a
real identity producer. The provider/Agent pair, digest, replay namespace,
UID/GID, SELinux domain, and runtime adapter now come from the generated Rust
`agent_descriptor_registry`; its generator rejects any second production Rust
mirror of those identity literals.

`trillionnium-os-types` also contains a pure, source-only resolver for the first
`system_api/open_uri` capability-lease slice. It accepts only a valid binding
inbox v2 plus the exact OS-authored workflow, task, provider, adapter and action,
then derives the seven-field Android Agent-binding tuple from the generated
descriptor. Workflow hash, inbox digest, provider/Agent pair, identity key and
remeasured executable must all match. The resolver has no transport, service,
URI parser, receipt consumer, acknowledgement or effect call site and does not
activate a lease path.

`trusted_context` derives one of four fixed product state/inbox pairs solely
from effective UID/GID, the compiled adapter kind, and the exact current
adapter SELinux domain:

```text
/var/lib/trillionnium/agent-tools/state/codex/{system-api|accessibility}
/var/lib/trillionnium/agent-tools/inbox/codex/{system-api|accessibility}
```

Codex is fixed to UID/GID 5901. State leaves are
Agent-owned mode `0700`. Inbox leaves are root-owned, Agent-group-readable mode
`0750`; `current-invocation.json` is root-owned mode `0440`. Product traversal
starts at `/`, uses `O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC`, requires every ancestor
to be root-owned and non-group/other-writable, matches every opened directory
entry to its validated device/inode, and keeps the exact state-directory FD
alive. The binding file must be a one-link regular file, exact canonical
one-line JSON, and match the fixed provider/Agent identity. Before publication,
the daemon acquires an in-process provider lifecycle lock and performs the
bounded `/proc` dedicated-UID drain; it retains that guard until supervised
cleanup reports no observed descendants. This serializes same-daemon
publication, but it cannot prove across a daemon crash that no fork/exit chain
retained the old fixed inbox context.

Root-Linux product binaries now compile this intake explicitly. Before parsing
MCP/stdio they require `current-invocation.json`, a separate canonical
root-owned/group-readable mode-`0440`
`/var/lib/trillionnium/agent-tools/inbox/{provider}/{adapter}/kernel-launch-custody-v3.json`,
and live unified-cgroup membership in exactly
`/trillionnium/agents/codex/{system-api|accessibility}`. In the pre-r2 sealed
profile its only admissible producer was
`trillionnium-agent-privilege-broker`. The envelope
binds the exact binding, invocation, delivery attempt, adapter binary kind,
non-zero broker provider-subtree generation, its independent subtree-
reservation evidence digest, boot-ID digest, PID, `/proc` starttime, current
executable SHA-256, exact cgroup, adapter-leaf empty-proof digest, and measured-
exec proof digest. The broker subtree generation is not the daemon attempt
generation. Those live anti-replay fields are re-read before each allowed
effect.
Missing, stale, cross-adapter, noncanonical, or self-inconsistent custody is a
pre-effect runtime HOLD. The current broker/init product does not yet produce
that envelope or fixed cgroup closure, so this is safe wiring, not a working
device vertical slice.

In the production feature build, the untrusted `system_api::call` and
`accessibility::call` entry points are absent. `call_trusted` revalidates fixed
cgroup membership before an allowed effect, derives the fixed process
identity, opens the trusted journal, optionally consumes the fixed
root-authored outer-ACK V3 inbox, canonicalizes the semantic request, and then
requires a fresh typed allocation from an OS-owned per-logical-call authority
before any journal mutation or backend connection. The allocation request
binds the already authenticated binding, invocation, delivery attempt,
provider/Agent pair, adapter and canonical digest, but contains no requested
token/ordinal or model call ID. The returned envelope supplies the OS token and
ordinal and is checked against that exact request. Invocation, task,
delivery-attempt, and binding values never enter model input, MCP JSON,
environment, argv, or a caller-selected file descriptor.

The V3 uncorrelated allocation request explicitly records
`retry_correlation_authority=absent_product_hold`. Its canonical digest is an
integrity binding only: equal request bytes cannot tell a deliberate repeated
action from a crash retry. The separate V3 daemon-owned durable-delivery
contract provides the required correlation shape, but its product authority
and authenticated transport remain unconstructible; the uncorrelated request
must never be wired as an always-new allocator.

Launch custody and logical-call allocation are separate. A long-lived Codex
MCP process may complete `initialize` and `tools/list` once launch custody is
valid; every `tools/call` obtains its own allocation only after its arguments
exist. There is no
`current-tool-call` launch file: such a file could be reused across two
deliberate identical calls. The current daemon/broker has no live allocator
transport and the product authority is deliberately unconstructible, so every
otherwise allowed call currently returns a pre-backend HOLD. Test authorities
exist only under `cfg(test)`.

The adapter cannot select another provider, task file, state path, or journal
through arguments, environment variables, or alternate file descriptors.

Each future Agent/adapter integration must own an independent journal. The
feature-only intake can open it only through `TrustedAdapterContext`, after the
fixed SELinux domain, real/effective UID/GID four-tuple, root-owned inbox, and
complete binding have been validated. The journal has no
public raw path/identity constructor; that constructor exists only under
`cfg(test)`. A missing product journal is a hard activation HOLD, not permission
to mint a replacement epoch. The journal handle also retains and rechecks the
exact state-directory inode authenticated by the context, so pathname
retargeting cannot substitute another store. These values and the runtime
backend `request_id` must never be accepted from model-visible tool arguments.

Before allowing a backend side effect,
`begin_effect_with_identity(os_tool_call_id, adapter_effect_ordinal, canonical)`
either returns exact recovery or atomically persists `PREPARED` and returns the
exact bounded identity
`op:<32-lowerhex-epoch>:<1..i64::MAX-decimal-journal-sequence>:<64-lowerhex-canonical-request-sha256>`.
The digest is never truncated; the maximum representation is 120 bytes.
The logical identity is `(os_tool_call_id, adapter_effect_ordinal)`, never the
canonical digest and never Codex JSON-RPC call metadata. The same
identity plus the same digest recovers exactly; the same identity plus a
different digest or ordinal fails closed. A new contiguous ordinal and new
token may intentionally carry the same canonical digest, so two consecutive
`Back`, `Home`, `scroll`, or package-launch calls remain two effects. New
ordinals must be exactly `0,1,...` within the adapter journal and the proven
live delivery attempt. If the delivery attempt changes while operations
remain, the journal is recovery-only: only an exact known OS token/ordinal and
digest may recover, and no new request ID can be allocated.

Codex MCP JSON-RPC IDs remain outside this
authority because neither has proven stable retry semantics. A future daemon
allocator must durably author and replay the same OS allocation for the same
logical call across provider/adapter restart; the adapter must not infer it
from journal length, canonical content, or a process-local cursor.

`record_result` re-parses the exact backend bytes against the adapter protocol
and prepared request ID, then persists the result digest, exact bounded
`backend_error_code`, and the shared closed outcome class `success`,
`backend_error`, or `indeterminate` before the result may return to the Agent.
For `success` and `backend_error`, journal v5 also stores canonical base64 of
the exact bounded response bytes. A recovered terminal record is revalidated
and returned directly without contacting the backend. `PREPARED` and
`indeterminate` records never expose a terminal replay; they recover through
the backend under the same already-durable operation ID.
That PREPARED/indeterminate retry is not yet an end-to-end Android guarantee:
the real System API and Accessibility services require activation of the same
operation epoch, while replay-sync publication remains unwired. Product effect
integration therefore remains HOLD even after a per-call allocator is built.
The caller cannot pass an outcome class. `request_in_flight`, timeout,
transport failure, malformed JSON/framing, and protocol/request-ID ambiguity
all become `indeterminate`. An `indeterminate` record freezes the journal: it cannot be
overtaken or removed by any acknowledgement. Other active records are removed
only after the fixed trusted-context consumer loads a canonical root-authored
outer-ACK V3 file and matches its exact journal snapshot, allocation binding,
current delivery binding, receipt digest, previous watermark, and
domain-separated authenticated ACK-chain step. Exact replay is idempotent; a
changed or discontinuous ACK is rejected. Combined outer-acknowledgement and
exact-journal validation rejects an indeterminate
outcome, journal sequence zero, journal sequence above `i64::MAX`, wrong tool
identity, non-contiguous adapter effect ordinals, mixed allocating attempts,
unordered evidence, and any raw URI/text/result/risk field. Structural outer
ACK validation is not sufficient: the V3 binding/receipt validators and trusted
context additionally require the exact binding digest, authorized-adapter set,
invocation, delivery attempt, provider/Agent pair and adapter.

Attempt roles are intentionally asymmetric. An outer ACK and acknowledgement
record carry `delivery_provider_attempt_id`, which must match the current
trusted binding. Every prepared operation, journal record, recovery item, and
evidence item carries `allocating_provider_attempt_id`. After attempt A
allocates an effect and attempt B recovers it, B may deliver the ACK while the
exact evidence remains bound to A. The journal requires one uniform allocating
attempt per active evidence set; it must never require A == B.

The file contains identities, epoch/journal-sequence, generated request IDs,
adapter effect ordinals, state, request/result digests, definitive terminal
backend response bytes, outcome classes, backend error codes, bounded
acknowledgement tombstones, and the outer-receipt digest. It never stores raw
requests, `set_text` content, URIs, indeterminate transport bytes, or receipt
bodies. Terminal bytes are bounded to the existing 1 MiB backend frame and a
16 MiB active-journal aggregate; `begin_effect` reserves one maximum frame
before allocating another identity. The store requires a pre-created real
mode-`0700` directory. Journal,
lock, and atomic temporary files are
owner-matched mode-`0600` regular files with one link, opened with
`O_NOFOLLOW|O_CLOEXEC`; publication uses exclusive temporary creation, file
`fsync`, checked rename, directory `fsync`, bounded `flock`, strict bounded
decoding, and fail-stop/reopen behavior when a post-rename directory sync is
uncertain. Acknowledgement identities are never compacted or forgotten. The
bounded reuse index holds activation before capacity exhaustion; this is an
intentional safe availability limit until a permanent authenticated reuse
index exists.

The journal v5 envelope redundantly binds the active invocation, trusted
allocation binding and digest, active allocating attempt, contiguous adapter
effect ordinals, journal-lifetime contiguous journal sequences, unique
canonical digests, and the durable outer-ACK watermark/chain. Its payload
SHA-256 detects accidental corruption only. It is **not authentication against
an attacker in the same UID**, because that
attacker can rewrite both payload and digest. Separate adapter domains and
journal-state labels now exist in source policy, but product activation still
requires enabling them with measured ownership/label/device proof that excludes
the model runtime and agentd, or an OS-held MAC/signature key unavailable to
them. A same-UID file, even with mode `0600`, cannot prove release authenticity.

Product activation remains on HOLD until all of the following are implemented
and tested as one measured closure:

- provider schemas keep path/identity/epoch/delivery-attempt/allocating-attempt/
  adapter-effect-ordinal/journal-sequence/request-ID fields outside model
  control and canonicalize each effect deterministically. Pre-spawn inbox
  publication exists in source; `TrustedAdapterContext` intake, journaled
  backend effect bracketing, exact terminal replay, and outer-ACK consumption
  are compiled into Root product artifacts. Runtime admission remains held
  pending the root-owned kernel-custody envelope producer, fixed cgroup/init
  closure, production daemon ACK publisher, and trusted custody-store
  constructor;
- Codex has vendor-provisioned state paths, ownership,
  SELinux types/domains or an OS-held MAC, startup recovery, bounded-capacity
  handling, secure first-use journal provisioning, a permanent authenticated
  invocation-reuse index (or an approved capacity-HOLD operating policy), and
  exact PlanReady acknowledgement wiring;
- Android backend replay now binds the authenticated descriptor and peer
  UID/domain into separate replay namespaces. Rust and Java also share one
  generated canonical operation-ID contract and six byte-exact golden vectors,
  so the adapter and both SDK backends hash the same peer/protocol/action
  identity. Package-private fixed-binary ACTIVATE/ACK codecs and handlers plus
  separate replay-sync SELinux domains now exist in source, but no authenticated
  control socket, peer-verifying listener, sync-helper binary, launcher or
  daemon publisher is wired. No model, MCP, or ordinary backend request may
  activate an epoch or publish an ACK. A random Agent epoch does not replace
  authenticated caller binding;
- System API and Accessibility define canonical result bytes and map every
  transport/backend ambiguity to `indeterminate` before returning; and
- physical-device kill, power-loss, ENOSPC, label/custody, concurrent restart,
  receipt-loss, and backend replay tests pass for the final filesystem and
  product policy.

Until those gates close, this module is tested source infrastructure only and
must not be represented as product availability, exactly-once execution, or a
release authenticity proof.

## ADB release hold

The default ADB executable is fixed as
`/usr/lib/android-sdk/platform-tools/adb` (not the `/usr/bin/adb` symlink), but
the product binary does not start it. The current signed Root-Linux base archive
also contains no adb client at that path, so adapter installation alone cannot
silently activate ADB. It returns `backend unavailable` until a measured client,
same-device transport, adbd authentication/key custody, and an eng/userdebug
build-property proof are defined.

### Inert wire foundation is not an enabled transport

`src/adb_wire.rs` is a no-I/O Rust foundation for a future device-local adbd
client. It is deliberately not called by `execute_production`, which continues
to validate the request and unconditionally return `backend unavailable`.
Adding this module therefore does **not** make ADB usable in a product build.

The foundation contains only:

- the six-command client closure `CNXN/AUTH/OPEN/OKAY/WRTE/CLSE`;
- strict 24-byte little-endian header, magic, checksum, exact-length, per-frame,
  negotiated-payload, authentication-challenge, and state-transition checks;
- a closed device-service enum containing only `shell,v2,raw:` and `sync:`;
  `root:`, `remount:`, and unknown service strings cannot be passed to the
  session API or represented by a valid `OPEN` frame;
- a single-stream fail-closed state machine with bounded AUTH challenges,
  replay rejection, explicit acknowledgement, and terminal close handling;
- a private-constructor target type representing only
  `127.0.0.1:5555`, plus validation that rejects every request-provided serial,
  hostname, alternate loopback address, or port; and
- a transport trait that requires a non-zero, capped timeout on connect, every
  read/write, and shutdown. Its tests use an in-memory transport only.

### OS-owned transport boundary (source-only)

`adb_wire::transport_boundary` is the next layer above that protocol state
machine. `OsOwnedAdbTransport` accepts only an `AdmittedAdbRequest`; it cannot
be called with model JSON, a serial/host/port selector, a raw command string,
or key material. `AdbAdmissionPolicy` revalidates the typed request against the
OS-selected `DeviceBinding`, finite `KeyRotationPolicy`, current boot and
expiring `AndroidAdbPermissionGrant` tier. Confirmation-required grants are
held until a future issuer receipt exists. Key rotation advances the binding
generation and accepts the previous generation only through its explicit boot
overlap; admission requires `AdbKeyCustody::OsOwned` metadata.

`AdbTransportBroker` provides a bounded, in-memory request-ID ledger for exact
replay and conflict rejection. An indeterminate outcome is retained and
replayed rather than retried. This ledger is intentionally ephemeral and is
not a production reboot/power-loss exactly-once authority. The UDS portion is
only a bounded length-prefixed codec and envelope verifier; tests use
`UnixStream::pair()` and never create a listener. `ProductionAdbTransport::new`
always returns the explicit HOLD marker, so this source layer cannot silently
fall back to the host adb executable or fastboot.

The boundary tests cover admission/tier/binding/rotation, private-key and
transport-selector rejection, exact UDS framing, forged-envelope rejection,
indeterminate replay, and the production HOLD. The evidence record is
[`docs/evidence/2026-08-22-adb-transport-boundary-source-audit.md`](../../docs/evidence/2026-08-22-adb-transport-boundary-source-audit.md).

There is no production `TcpStream`/UDS connector or listener, adb CLI/server launch,
DNS lookup, TLS/ADB dependency, private key, public-key enrollment, Android
property mutation, or real-device test in this foundation. The client always
advertises ADB 1.0 (`0x01000000`). It accepts a peer `CNXN` advertising either
AOSP 1.0 or 1.1 (`0x01000001`), records both the peer-advertised and negotiated
versions, and negotiates `min(client, peer)`, which remains 1.0. Consequently,
every frame still requires the original checksum; a peer's 1.1 advertisement
does not enable checksum skipping. Versions outside that exact two-value set
fail closed. This follows AOSP's `adb.h`, `adb.cpp::send_connect`, and
`transport.cpp::send_packet`: a modern peer advertises its maximum 1.1 while
the initial transport remains at the checksummed minimum for compatibility.
CNXN banners likewise use AOSP's counted, non-NUL-terminated payload, while
the two allowed OPEN service payloads retain ADB's historical trailing NUL.

A fixed loopback value is merely a type-level target constraint—it is not
proof that adbd is listening, that the listener is loopback-only, or that
authentication and SELinux custody exist.

The intended debug-only transport is now a small audited Rust implementation
of the adbd wire protocol against Android's existing
`service.adb.listen_addrs=tcp:localhost:<fixed-port>` support. Avoiding the adb
CLI/server removes one process and one control socket, but it does not satisfy
the release gate by itself. Release enablement still requires all of the
following as one measured debug-build closure:

- a variant-authenticated `eng` or `userdebug` proof that the Agent cannot
  author;
- a root-provisioned, non-agent-writable adb client key and an explicit Android
  authorization state;
- a fixed loopback serial whose `get-state` and device identity match the local
  Android instance;
- measured custody of the Rust adapter and its dynamic runtime; and
- a physical timeout/retry/cleanup test proving that no connection or transport
  survives a terminal tool call.

Until that evidence exists, a host adb executable, a visible USB serial, or a
loopback listener by itself is insufficient and the production path stays
fail-closed.

The `dev-overrides` build is available for host engineering only. Its request
must include:

```json
{
  "version": 1,
  "request_id": "req-adb-1",
  "build_type": "userdebug",
  "enable_token": "trillionnium-adb-eng-userdebug-v1",
  "action": "devices"
}
```

The token is an explicit engineering guard, not an authentication secret. ADB
uses direct argv, a 120-second timeout, separate 1 MiB stdout/stderr caps, strict
serial syntax, closed reboot targets, and normalized absolute transfer paths
that cannot begin with an option or contain `..`.

Android UID/permission/SELinux policy, Accessibility authorization, socket
service ownership, executable custody, and Android build type remain the OS
enforcement boundaries and must be installed by the product integration.
