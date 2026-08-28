# R5 Batch E — release-candidate source selection

Status: **release-candidate Python paths selected; exact runner and target evidence open**

## Selected paths

```text
Codex qualification supervisor
  tools/owner-open/supervise_codex_mcp_qualification_release.py

ADB smart-socket relay
  tools/owner-open/adb_smart_socket_relay_release.py

ADB exact-argv qualification
  tools/owner-open/qualify_owner_open_adb_release.py
```

The exact machine selection is
`docs/contracts/owner-open-r5-selected-python-paths-v1.json`.

Earlier implementation cuts remain in Git history and the source tree for audit
and comparison. They are not product-selection inputs and must not be referenced
by release-candidate plans, status promotion or release workflows.

## Closed source defects

The release-candidate selection closes:

1. MCP downstream processes that ignore upstream EOF;
2. qualification cleanup masking the primary result;
3. failure to require exact `qualification-terminal.status=passed`;
4. nonprivate qualification evidence parents;
5. ADB relay transfer/watchdog task leakage;
6. unbounded relay lifecycle observations;
7. unsafe descriptor parent handling;
8. rejection of mechanically valid empty adb arguments;
9. loss of a failed ADB step observation before runner termination;
10. relay/qualifier selection drift across plans and CI.

## Required host-process gate

```text
selected-path verifier and its negative tests
release Codex supervisor process tests
release ADB relay byte/half-close/concurrency tests
release ADB exact-argv/no-retry tests
existing MCP, broker, graph and Rust owner-open closure
```

Only exact output bound to one commit can promote these paths beyond L0.

## Installed Codex gate

The release supervisor must prove:

```text
measured installed Codex and supporting files
dedicated private CODEX_HOME and workspace
temporary MCP registration
exact MCP trace
exact pipe and PTY operation sequence
completed Codex JSONL turn
no hidden effect retry
server removal
exact config restoration
finite process-group teardown
```

## Physical ADB gate

The release ADB qualifier must prove on the target topology:

```text
ordinary measured adb executable
explicit ADB_SERVER_SOCKET
byte-transparent loopback relay
owner-authored exact argv plan
zero implicit serial/host/port selection
binary observation preservation
one spawn per operation ID
no redispatch after timeout or disconnect
USB/authorization/offline/reboot behavior
same-turn Codex continuation
```

## Next critical path

1. run the release workflow and Rust 1.93 closure on one exact commit;
2. fix all runner findings and bind lock/metadata/feature evidence;
3. run installed Codex qualification in target Root Linux;
4. run the physical ADB plan through the selected topology;
5. cut the Android owner-open product graph;
6. integrate init, SELinux, Root Linux placement, AiShell and emergency stop;
7. collect L3-L5 evidence.

No selected source path is a public-release claim.
