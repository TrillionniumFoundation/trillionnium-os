# Owner-Open R5 external-evidence resume runbook

Status: **ACTIVE EXECUTION HANDOFF — plan revision `2026-08-29-r6`**

This runbook starts where exact-source closure ends. It is the single operational
entry point for the remaining L2-L6 evidence lanes. The canonical gap register
and status files remain authoritative; this document does not close a gap by
itself.

## 1. Consume the exact-head resume packet

The permanent workflow `.github/workflows/owner-open-r5-resume-packet.yml`
checks the canonical register and emits an artifact named:

```text
owner-open-r5-resume-<exact-commit-sha>
```

The artifact contains:

```text
resume-packet.json
verify-r5.json
verify-r5-gap-evidence.json
resume-packet-tests.log
SHA256SUMS
```

Before any target run, require all of the following:

1. the artifact commit equals the reviewed PR head;
2. its tree equals `git rev-parse <commit>^{tree}`;
3. `state_counts.OPEN == 0`;
4. the outcome is `RESUME_REQUIRED` or `MODULE_CLOSED_CANDIDATE`;
5. `automatic_redispatch`, `public_release` and every negative claim remain
   unchanged unless the corresponding reviewed evidence lane closes;
6. every input artifact is content-addressed and retained independently.

A resume packet is a handoff. It is not installed-target, Android-image,
physical-device, fault, signing or release evidence.

## 2. Evidence object minimum

Every imported environment observation must bind:

```text
level
kind
source_commit
source_tree
source_lock_sha256
target_or_device_identity
tool_and_artifact_sha256
command_or_operation_identity
raw_log_sha256
result_summary
evidence_sha256
reviewer
synthetic=false
automatic_redispatch=false
```

The reviewer must be independent of the evidence producer for product, fault
and release promotion. A GitHub Actions job reviewing its own output is not an
independent reviewer.

## 3. L2 — installed Codex and target Root Linux

### 3.1 Required target

Use the authorized Root Linux environment that will actually host the selected
Owner-Open runtime. A generic hosted runner, container-only fixture, unpacked
binary probe or local Ubuntu process outside the declared service placement is
not L2.

Record at minimum:

```text
uname -a
cat /etc/os-release
id
cat /proc/self/status
readlink /proc/self/ns/{mnt,pid,user,net,ipc,uts,cgroup}
cat /proc/self/cgroup
mount
service-manager unit identity and properties
exact executable and configuration SHA-256 values
```

Prove the configured UID/GID/groups, namespace, cgroup, filesystem paths,
process group, parent-death behavior, descendant reaping, restart policy and
emergency stop on the actual target.

### 3.2 Installed Codex MCP/job qualification

Use the repository's fail-closed runner:

```text
tools/owner-open/qualify_codex_mcp_jobs.py
```

Run it only with absolute, reviewed paths and a dedicated temporary
`CODEX_HOME`. The canonical command shape is:

```sh
python3 tools/owner-open/qualify_codex_mcp_jobs.py \
  --execute \
  --codex /absolute/path/to/installed/codex \
  --python /absolute/path/to/python3 \
  --trace-proxy /absolute/path/to/trace_mcp_stdio.py \
  --mcp-bridge /absolute/path/to/codex_owner_open_mcp.py \
  --host /absolute/path/to/trillionnium-owner-open-r5-host \
  --core /absolute/path/to/trillionnium-owner-open-r5-core \
  --provider /absolute/path/to/reviewed-provider-adapter \
  --shell /absolute/path/to/configured-shell \
  --job-store /absolute/path/to/dedicated/job-store.json \
  --event-store /absolute/path/to/dedicated/event-store.jsonl \
  --codex-home /absolute/path/to/dedicated/CODEX_HOME \
  --workspace /absolute/path/to/dedicated/workspace \
  --evidence-dir /absolute/path/to/new/evidence-directory \
  --expected-codex-sha256 <sha256> \
  --expected-python-sha256 <sha256> \
  --expected-trace-proxy-sha256 <sha256> \
  --expected-mcp-bridge-sha256 <sha256> \
  --expected-host-sha256 <sha256> \
  --expected-core-sha256 <sha256> \
  --expected-provider-sha256 <sha256> \
  --expected-shell-sha256 <sha256>
```

The run must use real authenticated Codex execution, register the exact MCP
command, complete the required pipe and PTY job sequence in one live turn,
remove the MCP registration, restore the dedicated configuration and retain the
raw Codex JSONL, MCP trace, stderr, command records and terminal object.

A help probe, public release download, fixture model, fake provider, generated
prefix or failed authentication does not close the installed-Codex lane.

### 3.3 L2 promotion scope

Successful reviewed L2 evidence may close only the gaps whose exit level and
acceptance are fully met, including target process lifecycle, stream recovery,
broker correlation, installed Codex and Root Linux placement. It does not close
Android image, physical ADB, destructive faults or public release.

## 4. L3 — clean Android image and product entrypoint

Use a clean, pinned Android source checkout and retain:

```text
repo manifest -r output
all project commit IDs
ordered reviewed patch or commit list
source and dirty-state assertions
Soong module-info and selected package report
init services, sockets and properties
SELinux source, compiled policy and file-context digests
framework/service/app classpath and source-selection report
target-files installed-file inventory
image and target-files SHA-256 values
source-to-image receipt chain
```

Run the strict owner-open graph verifier against the exact source tree:

```sh
python3 tools/verify-owner-open-r5.py --strict-android --json
```

The target-files must contain one selected Owner-Open product entrypoint and no
Authority, lease, P01 high-water, old shell broker/worker or typed ADB semantic
gate in the selected graph. Static overlay text, generated profiles, host-only
rootfs archives and source fixtures do not constitute L3 image inclusion.

Product-entrypoint and Android-graph gaps close only after the clean image and
its inventories are independently reviewed and bound to the exact source
commit/tree.

## 5. L4 — authorized physical ordinary ADB and visible effects

Bind the exact physical device serial, build fingerprint, boot slot, image
identity, ordinary platform-tools ADB executable/server identity and selected
relay identity. Capture raw stdout, stderr and exit status for at least:

```sh
adb devices -l
adb -s "$SERIAL" shell id
adb -s "$SERIAL" shell 'printf owner-open > /data/local/tmp/r5-probe'
adb -s "$SERIAL" shell 'cat /data/local/tmp/r5-probe'
adb -s "$SERIAL" push <reviewed-input> /data/local/tmp/
adb -s "$SERIAL" pull /data/local/tmp/<reviewed-input> <new-output>
```

Also exercise owner-approved install, forward/reverse and reconnect operations,
and retain ordinary raw behavior for unauthorized, offline, multiple-device,
recovery/bootloader and root/remount/reboot success or rejection.

For USB loss, server loss or phone reboot after dispatch, record a terminal
observation or `unknown_after_disconnect`; never automatically dispatch the
command again. Fake ADB, an emulator and source-only relay tests do not close
L4 under the active plan.

## 6. L5 — destructive fault and recovery matrix

Execute the complete declared fault families against the exact L2/L3/L4
artifact set:

```text
provider before/during/after effect
core before/during/after effect
transport disconnect and reconnect
broker accepted/forwarded/result audit failures
client disconnect and slow-client detachment
job process leader and descendant failure
journal ENOSPC, fsync failure, torn write and corruption
ADB server loss and USB unplug
Android service restart and device reboot
controlled power loss or an independently accepted physical equivalent
```

For every cut, retain the last durable record, observed process/device state,
reconciliation decision, cleanup result, cursor/replay outcome and proof that no
uncertain effect was automatically redispatched. Source-level fault injection
and ordinary CI filesystem fixtures remain L1 unless the active evidence
contract explicitly accepts the controlled target environment.

## 7. L6 — signed public release

L6 is separate from engineering completion. Require:

```text
production signing-key custodian approval
artifact signatures and certificate identity
transparency-log inclusion proof
AVB/APEX/OTA cryptographic verification
rollback indexes and downgrade tests
key rotation/recovery procedure
independent security and release review
explicit human public go/no-go authorization
```

Do not set `public_release=true` because source, image, physical or fault tests
are green. The release gap closes only after the signed artifacts, custody,
rollback evidence and human authorization are bound and independently reviewed.

## 8. Import and promote without overclaim

For each candidate evidence package:

1. verify `SHA256SUMS` and all nested hashes;
2. verify source commit/tree and lock identity against the reviewed candidate;
3. verify the target/device/image identity and declared evidence level;
4. reject `synthetic=true`, missing reviewer, stale source or recycled logs;
5. attach the immutable package to the relevant issue and PR;
6. obtain independent review where required;
7. update only the gaps whose full acceptance and exit level are satisfied;
8. run both canonical verifiers and the exact-head resume workflow;
9. retain `zero_gap=false` until every gap is `CLOSED`;
10. retain `public_release=false` until the independently authorized L6 step.

Valid terminal outcomes are:

```text
MODULE_CLOSED_CANDIDATE
RESUME_REQUIRED
SOURCE_WORK_REMAINING
BASE_DRIFT
BLOCKED_UPSTREAM
STOP_CONDITION
```

Never convert missing material, missing authority, workflow approval, device
absence, credential absence or signing absence into a successful evidence
object.
