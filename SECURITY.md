# Security Policy

## Supported scope

The repository currently supports an owner-open dogfood development lane. Source and L1 tests are not claims of installed Root Linux, Android image, physical-device, destructive-fault or public-release security.

## Reporting

Report vulnerabilities through a private GitHub Security Advisory. Do not open a public issue containing an exploit, credential, private key, device identifier, target token, unpublished target evidence or a path to arbitrary Root Linux/ADB execution.

Include, where available:

- exact source commit, tree and affected module;
- affected protocol, state schema, process, ADB/Android path, control lease or evidence lane;
- minimal reproduction and raw observation;
- whether an effect may have been attempted;
- whether a process, credential, device or stale writer may remain active;
- whether automatic redispatch or false evidence promotion is possible.

## High-risk boundaries

Treat the following as release-blocking:

- semantic-versus-mechanical authority drift;
- provider credentials, inherited environment or file descriptors;
- process, PTY, cgroup, namespace, cancellation and descendant cleanup;
- effect identity, durability and no-redispatch behavior;
- broker multiplexing, correlation and owner-result isolation;
- control epochs, leases and fencing;
- event-store corruption, replay and state migration;
- Android product graph, init, SELinux, AVB, rollback and OTA;
- ADB routing, target identity and physical-device evidence;
- evidence capture, independent review and release authorization.

## Response

A fix is developed on an exact-source branch, receives the applicable module and independent review, and passes the same qualification as ordinary changes. Any affected evidence identity is revoked and requalified at every level it previously reached. A source fix never promotes a target, device, fault or release claim by itself.

## Disclosure

Coordinate public disclosure only after an exact patched source is available and affected artifacts or evidence have been revoked or marked. The owner-open trust model does not excuse hidden privilege escalation, uncontrolled process survival, credential leakage, stale-writer mutation or fabricated evidence.
