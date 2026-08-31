# Security Policy

## Supported scope

This repository is an active owner-controlled dogfood development lane. The
checked-in source and L1 workflow results are not a claim of installed target,
Android image, physical-device, destructive-fault, or public-release security.
The current claim ceiling is defined by `docs/status/owner-open-r5-status.json`.

## Reporting a vulnerability

Report suspected vulnerabilities through a private GitHub Security Advisory for
this repository. Do not open a public issue when a report contains an exploit,
credential, private key, device identifier, unpublished target evidence, or a
path to arbitrary Root Linux/ADB execution.

Include, where available:

- the exact source commit and tree;
- affected binary, Android module, service, protocol, or evidence lane;
- minimal reproduction steps and observed output;
- whether a process, descendant, credential, device, or signing asset may remain
  exposed after the reproduction;
- whether the issue could cause duplicate or falsely reported effects.

Do not include live provider tokens, ADB private keys, release keys, user data,
or unredacted target evidence in the report body. Arrange an encrypted transfer
through the advisory when such material is essential.

## Response principles

Maintainers will preserve the original report and establish a private fix branch.
A security fix must pass the same exact-head checks as ordinary changes. A fix
must not promote an L2-L6 claim merely because a source test passes. Any affected
qualified identity is revoked and must be requalified at every evidence level it
previously reached.

## High-risk areas

Reports involving the following areas should be treated as release-blocking:

- owner-open peer admission or SELinux identity;
- provider credentials or inherited file descriptors/environment;
- shell, PTY, process-group, cgroup, cancellation, or descendant cleanup;
- ADB argv/routing substitution;
- event/journal corruption, replay, or automatic redispatch;
- Android product graph, init, SELinux, AVB, OTA, rollback, or signing custody;
- evidence capture, target attestation, independent review, or gap promotion.

## Public disclosure

Coordinate public disclosure only after a patched exact source is available and
previously published artifacts have been revoked or explicitly marked affected.
The repository's owner-open profile intentionally grants broad authority to its
configured semantic agent; that accepted product risk does not excuse hidden
privilege escalation, false evidence, credential leakage, or uncontrolled
process survival.
