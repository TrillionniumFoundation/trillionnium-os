# Trillionnium OS Product Semantics

Status: **NORMATIVE**  
Semantic revision: **owner-open-semantic-v1**

## 1. Product definition

Trillionnium OS is an AI-native Android system whose built-in semantic Agent is
Codex. Inference may be off-device; the Android-managed Root Linux environment
contains the provider runtime, direct tools, durable state and development
workspace.

The product loop is:

```text
owner intent
  -> one Codex/provider turn
  -> direct shell, ordinary ADB, System API or Accessibility primitive
  -> mechanical execution substrate
  -> raw observation
  -> the same Codex/provider turn
```

The system may use several operating-system processes. That does not create
several semantic principals.

## 2. Sole semantic authority

Codex/provider owns:

- interpretation of owner intent;
- context and memory selection;
- target, tool, command and argument choice;
- consent language and semantic policy;
- retry, compensation and undo decisions;
- interpretation of observations;
- semantic task decomposition and ordering.

No broker, transport, execution core, scheduler, runtime, store, Android
service or evidence tool may independently perform those decisions.

## 3. Mechanical authority

The substrate may own only mechanisms that cannot be delegated to a stopped or
crashed semantic process:

- process, PTY, pipes, signals and lifecycle;
- framing, correlation, authentication and transport;
- finite admission, memory, file-descriptor, process and I/O limits;
- durable records, replay, cursors and conservative recovery;
- cgroups, namespaces, mounts, identities and restart;
- health, placement, rollout, fencing and emergency stop;
- evidence capture and claim-bound verification.

Mechanical rejection is limited to malformed input, identity conflict, stale
epoch, missing required durability, unavailable resource capacity or platform
failure. It must preserve the raw error and must not rename it as a semantic
approval decision.

## 4. Direct tools

`shell.exec` accepts either a command string or element-preserving arguments.
`adb.exec` accepts ordinary ADB arguments. Unknown or future ADB subcommands
remain transport-valid. No mechanism layer may inject a serial, host, port,
privilege mode, approval tier or alternate command.

If the selected target lacks a requested privilege, is offline, is unauthorized
or returns an error, that observation is returned unchanged for Codex to interpret.

## 5. Uncertain effects

General shell, ADB and external-device operations cannot be promised
exactly-once across every crash boundary. After a spawn, write or remote attempt,
missing terminal evidence is represented as an explicit unknown or reconciliation
state. A mechanism component never guesses success, cancellation or safe retry.

A semantic retry or compensation is a new Codex decision and normally uses a
new operation identity.

## 6. Global coordination without a second Agent

The global control plane may coordinate resource budgets, concurrency slots,
module placement, write ownership, versions and rollout. It may optimize
mechanical utility under hard constraints. It may not choose the semantic
meaning of work.

This distinction is mandatory:

```text
Codex decides what work means and what action to request.
The control plane decides where and when mechanically admissible work may run.
```

## 7. Profiles

Owner-open dogfood intentionally grants broad control to the configured Codex
instance. Safety relies on testing, bounded mechanics, backups, truthful
uncertainty and an out-of-band emergency stop—not a hidden second semantic gate.

A future sealed or public profile may add explicit restrictions, but it must
reuse the same direct-tool and effect identity contracts and must never silently
become the owner-open development default.
