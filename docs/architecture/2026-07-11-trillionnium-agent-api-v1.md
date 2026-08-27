# Trillionnium Agent API v1

> **SUPERSEDED — HISTORICAL PROVENANCE ONLY (2026-07-20).** This ADR describes
> the former plan/approval/Authority execute/undo architecture. It is not a
> current implementation or release contract. The accepted Direct Agent
> Native decision is
> [`2026-07-20-direct-agent-native-os.md`](2026-07-20-direct-agent-native-os.md),
> and current implementation status is [`../CURRENT_STATE.md`](../CURRENT_STATE.md).

Status: **SUPERSEDED**. The text below is retained unchanged as design-history
evidence and must not override the accepted Direct architecture.

## Definition of AI-native

Trillionnium is AI-native because replaceable built-in agents can perceive
provenance-tagged OS context and request bounded phone actions through an
OS-owned API. It does not require an LLM to execute on the phone.

```text
Codex | OpenClaw | Hepta | future agent
                  |
        Trillionnium Agent API v1
                  |
 task -> context -> plan -> policy -> approval -> capability
                  |
   OS-owned gateway -> Android Authority executor
                  |
        phone action -> receipt -> undo
```

An agent never receives adb, root, arbitrary shell, Binder executor identity,
or receipt-signing keys. Models may run remotely, locally, or in a hybrid
deployment; this does not change the OS trust boundary.

## Stable identity and transport

- API version: `trillionnium.agent-api.v1`
- Root-Linux UDS carrier: `trillionnium.agent-api.uds.v2`
- Root-Linux socket: `/run/trillionnium/agent-api-v2.sock`
- Android executor protocol: `trillionnium.android-agent-gateway.v1`
- Android abstract socket: `trillionnium-agent-gateway-v1`

The historical `org.trillionnium.Agent1` D-Bus service is fully retired. Its
server implementation, development executable, interface XML, activation
file, Cargo features, and Command Center proxy were removed. External Agent
live status and state changes require a client of the authenticated Agent UDS
ABI; no D-Bus compatibility path opens or migrates the production state store.

The required contract is to validate `SO_PEERCRED`, per-frame Linux
`SCM_CREDENTIALS`, and the kernel-provided security context, then bind a stable
`agent_id` to an OS-provisioned immutable UID/GID/domain/identity record. UID
and primary GID are independent kernel-authenticated fields and neither may be
inferred from the other. A claimed domain or identity digest is not an
authentication factor. Executable sampling is an additional policy check, not
proof that the sampled image authored already-buffered bytes.

Every state-changing call, plus each single-use `read_context_grant` or
`read_memory_grant` consumption, is a two-frame exchange on one connection.
The first exact request is an intent; the daemon returns a fresh 256-bit kernel
random nonce and a digest binding that intent to the connected process
generation. The same kernel-authenticated message writer must then return the
exact request with that channel binding before dispatch. A prequeued second
frame, stale nonce, changed request, transferred socket descriptor, missing
credentials, or peer-identity drift fails closed. Non-consuming read-only
calls retain the single-frame form. Tasks are stamped with their owning agent;
plan submission, execution, and cancellation must reject cross-agent use.

The state-change wire sequence is:

```text
agent -> daemon: {protocol, request_id, method, agent_id, payload}
daemon -> agent: {protocol, request_id, type:"channel_binding_challenge",
                  challenge:{schema, nonce, request_sha256}}
agent -> daemon: the exact first request plus
                  channel_binding:{schema, nonce, request_sha256}
daemon -> agent: the normal final response
```

The nonce and request digest are lowercase 64-character hex strings. The
binding payload retains the source-bound
`trillionnium.agent-api.state-change-auth.v1` schema identifier; carrier v2
extends its use to consuming grant reads without changing its canonical
fields. Agents must not predict, cache, or send a channel binding before
receiving the challenge on that same connection.

Carrier v2 has no v1 listener, socket alias, or in-band fallback. A legacy
one-response client therefore fails at connect instead of interpreting a
challenge as a final response. The semantic Agent API remains v1 and is
reported independently by `health`.

## Agent-visible operations

- health and API version
- register or inspect agent identity
- discover versioned OS tools
- create and cancel an owned task
- submit a structured, digest-bound plan
- request execution of one immutable action from an accepted plan
- list task-bound context/memory grant metadata
- consume an explicitly delegated raw context or memory grant once at the ABI
  layer; production UI issuance currently forces `raw_allowed=false`, so no
  production raw grant can be minted

Approval is deliberately not exposed on the agent UDS endpoint. The agent
cannot approve its own plan. Approval remains an OS/UI authority operation.

## Context and memory

Every context reference carries source identity, source kind, capture time,
freshness TTL, privacy class, content digest, and revoke state. The Android OS
UI can delegate an already-registered context or memory record only to an
existing task owned by an OS-provisioned Agent. A grant is bound to user, task,
Agent ID, UID, GID, SELinux domain, executable digest, resource digest, scope,
and TTL. Generic Agents cannot upload raw context through this API.

The source implementation keeps raw context ephemeral and zeroizes it in
daemon memory. Raw memory is encrypted at rest with XChaCha20-Poly1305 while
metadata remains independently queryable. Raw grants are single-use; issue,
consume, revoke, expire, response-loss replay, and crash-after-consume outcomes
are durably audited. A context/memory grant does not itself confer
provider-network authority. Current custody is user-0 internal-alpha scope and
has not been live-promoted or generalized to per-user key/state roots.

## Android tools in v1

The current executable catalog contains two honest Android side effects:

- `android.browser.open_bounded` — launches the exact approved HTTPS target
  and is explicitly not undoable because external browser state cannot be
  restored uniquely;
- `android.notification.post_bounded` — posts one closed `{title, body}`
  notification on the Authority-owned channel and can be undone only by
  cancelling that exact journal-bound notification.

User-selected text-file reads, Authority-owned exact-HTTPS URL capture, and an
explicit single saved-Memory selection materialized as a short-lived Context
inside OS custody are the current read-only Context Service acquisition
methods. Notification, UsageStats, browser-share, and external Memory-import
connectors remain disabled and are
not advertised as available context. Context acquisition is not advertised as
an executor tool because returning already-acquired context is not an Android
side effect. Additional tools enter the executable catalog only after their
platform connector and action-specific undo semantics are implemented.

Each accepted plan action carries a request ID, source ID, context digest, plan
and action IDs, provider-output digest, network scope, and bounded arguments.
Execution accepts only task/plan/action identity; the OS reloads the immutable
arguments and binds approval, capability, Android execution, audit, receipt,
and undo to the same digest set. The Android Authority validates its peer,
consumes a short-lived single-use capability before the side effect, executes
under its separate UID, and returns an attested or verifier-pinned signed
receipt plus an action-specific undo contract.

The internal-alpha verifier-pinned hardware-key mode is not a claim of complete
KeyMint X.509 root-chain or `attestationApplicationId` validation. Those checks
remain a release gate.

## Agent adapters

`supervised-codex-cli` and `supervised-openclaw-cli` are independent adapters.
Both are plan-only and map into the same provider-neutral `AgentPlanSubmission`.
The OpenClaw adapter has no channel binding, no skills, and an empty tool
allowlist. Model-supplied file paths or URIs are discarded and rebuilt from
OS-owned provenance context. OpenClaw packaging and Android integration have
their own custody boundary and are not implied by the Rust source commit.
Hepta will implement the same contract when its canonical runtime snapshot is
available; it will not be emulated by another agent.

### Transitional built-in dispatch convergence

The control plane now has one provider-neutral method dispatcher for task
creation, plan submission, immutable action dispatch, and cancellation.
Kernel-authenticated UDS requests enter that dispatcher as
`KernelUds`; the current daemon-supervised Codex/OpenClaw workflow enters as an
explicit `OsSupervisedProvider`. The latter is bound to the exact current
AgentManifest, an OS-measured executable path identity, an OS-authenticated UI
origin, and a task marker that cannot be supplied through the UDS task path.
Both ports therefore apply the same closed payload parsing, production tool
catalog, task ownership, frozen-plan, policy, and execution transitions for
the methods they invoke. The Android built-in provider path no longer calls
the task-create, plan-submit, or action-run service methods directly.

The durable local workflow contract is
`trillionnium.local-plan-saga.v2`. It stores the measured executable
dev/inode/owner/mode/digest together with the provider result. Restart
authorization compares the immutable AgentManifest fields while deliberately
excluding the OS-authored registration/update timestamps, then independently
requires the current manifest to remain enabled, ready, and on the exact API
version. A legacy v1 in-flight workflow has no durable executable identity and
is therefore marked individually indeterminate; the OS never synthesizes the
missing identity from the current path and one legacy record cannot prevent
the Authority API from reconciling unrelated v2 workflows.

This convergence is a foundation, not proof that the built-in Agents use the
UDS carrier. A pre-spawn path measurement does not prove which file
description the child actually executed, and `OsSupervisedProvider` does not
provide `SO_PEERCRED`, per-frame `SCM_CREDENTIALS`, the carrier challenge, or
the UDS replay identity. Promotion remains HOLD until all of the following are
implemented and exercised on-device:

1. a non-privileged built-in Agent host running under each provisioned Agent
   UID/GID/domain and using the public v2 UDS client for create/submit/run;
2. socket group/SELinux policy that admits only those provisioned hosts;
3. broker/supervisor execution from the exact measured file description
   (`execveat(AT_EMPTY_PATH)`/equivalent) or child runtime evidence binding the
   executed dev/inode/digest to the request principal;
4. removal of the transitional `OsSupervisedProvider` port after Codex and
   OpenClaw pass the same-ABI physical-device ceremony.

## Release gates

Passing source/unit tests, host adapter smokes, an Android Gateway self-test,
or static target-files packaging does not establish a live OS release.
Promotion of any candidate source commit additionally requires:

1. OTA activation with the daemon and both APKs resident under `/system_ext`;
2. live Root-Linux UID/domain to Android Authority execution without adb;
3. A/B rollback and audit/memory migration validation;
4. release keys, SBOM, privacy/telemetry policy, red-team results, vulnerability
   response, agent-update rollback, and support policy;
5. product-sized positive/negative tool conformance and soak metrics.
