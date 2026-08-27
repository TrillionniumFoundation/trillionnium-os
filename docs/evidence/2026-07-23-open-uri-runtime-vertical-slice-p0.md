# Trillionnium P0 `open_uri` runtime vertical slice

Date: 2026-07-23

> **Current-state correction (2026-07-24):** the implicit `ACTION_VIEW`
> consumer described below was an intermediate source checkpoint and is not
> the current or acceptable product boundary. It discarded the approved
> address set before browser DNS/TLS. The production-named consumer now fails
> closed before effect; `ACTION_VIEW` exists only in a test-only fixture. See
> [`2026-07-24-open-uri-consumer-hold-deadline-resolver-device-smoke-p0.md`](2026-07-24-open-uri-consumer-hold-deadline-resolver-device-smoke-p0.md).

## Product boundary

Trillionnium does not run a phone-local LLM. Codex and OpenClaw are built-in,
independently measured OS Agent principals. They request typed OS operations;
the OS owns policy, capability issuance, replay control and effects.

The legacy direct System API v1 remains intentionally unable to execute
`open_uri`, because that request contains a model-facing URI without the
required task, root-journal, execution-token and durable replay bindings. This
change does not relax that denial.

## Implemented runtime bridge

`CapabilityLeaseSystemApiRuntime` is the missing implementation of the
existing `CapabilityLeaseRuntimeFactory.Runtime` interface. It introduces no
new protocol or contract.

- PREPARE converts only an authenticated `PrepareCommand` into the existing
  `CapabilityLeasePendingBroker.PendingOpenUriRequest`.
- The local broker returns the durable handle plus the broker's exact wall and
  elapsed expiration values.
- EXECUTE passes only an authenticated, consumed-or-exact-replay
  `ExecuteCommand` to `CapabilityLeaseSystemApiOpenUriCoordinator`.
- Runtime construction reconciles durable PREPARED records before accepting
  new operations.
- The coordinator retains its order: replay-before-fetch, receipt fetch,
  destination preflight, durable PREPARED, broker ACK, execution-time DNS
  revalidation, effect, durable CONSUMED, exact terminal response.
- A retry of the same execution returns the durable terminal bytes without a
  second broker fetch, ACK, DNS lookup or Android effect.

Relevant sources:

- `trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseSystemApiRuntime.java`
- `trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeasePendingBroker.java`
- `trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseBrokerServiceFacades.java`
- `trillionnium-sdk/tests/CapabilityLeaseSystemApiOpenUriCoordinatorTest.java`

## Historical intermediate Android effect boundary

At this 2026-07-23 checkpoint, `CapabilityLeaseAndroidOpenUriConsumer` was a
concrete Android implementation of the existing approved-destination consumer
boundary. It received only
`CapabilityLeasePublicDestinationPolicyV1.ApprovedDestination`, validated the
exact HTTPS URI shape again and launched one `ACTION_VIEW` intent as
`UserHandle.SYSTEM`. The correction at the top of this file supersedes that
implementation and claim.

It did not parse the Agent wire, resolve task or execution tokens, inspect raw
receipts, own a socket, or accept a `String`/`byte[]` effect argument. The
measured consumer artifact loader and production enrollment pins remained
HOLD, so the class could not be selected by the product runtime factory.

## Validation

- SDK host JUnit at this 2026-07-23 checkpoint: 100/100. Current-source counts
  are recorded in the 2026-07-24 correction linked above.
- The new runtime regression proves one effect on first execution and exact
  terminal replay with zero second effect.
- Android hidden-framework compilation passed for the concrete consumer.
- All eight SDK source, semantics, replay and settings gates passed.
- `trillionnium-os-types`: 67/67.
- `trillionnium-agent-privilege-broker`: 126 passed, 1 ignored; integration
  tests passed.
- `trillionnium-agent-direct-tools` and `trillionniumd` package suites passed.
- Vendor same-ABI: 11/11; disabled trust: 8/8; Direct and OpenClaw product
  contracts passed.
- SELinux broker/issuer/replay-sync: 7/7, 5/5, 7/7.
- AiShell provider-security gate passed.
- Five checked-in generators, `cargo fmt --all -- --check`, and affected
  repository `git diff --check` passed.

## Remaining HOLD

This is a source-integrated vertical slice, not device evidence. Product trust
pins, measured consumer/verifier loaders, live root-route startup, packaged
publisher, broker main wiring and system-server service construction remain
unavailable. Token mutation, authenticated ACK authority, enabled lease trust
and effect authority remain false. No Android socket/syscall/effect path, ADB,
device write, signing, flashing, OTA, commit or release was performed.
