# Owner-Open R5 / G1 target-evidence operator contract

Status: **repository-controlled handoff; no target evidence is embedded here**.

This document defines the external side of
`.github/workflows/owner-open-r5-target-evidence-capture.yml`.  The workflow is
manual-only, read-only with respect to the repository, and routes exactly one
capture to one independently administered environment.  Merely registering a
runner, installing a harness or uploading an artifact cannot close a gap.

## 1. Fixed lanes

| Evidence kind | Level | Required runner label and environment | Purpose |
|---|---:|---|---|
| `installed_root_linux_process_matrix` | L2 | `owner-open-r5-l2` | Installed UID/GID, namespaces, cgroups, mounts, limits, restart and emergency inhibit |
| `installed_codex_same_turn` | L2 | `owner-open-r5-l2` | Exact installed Codex identity, authenticated provider session, same-turn shell/job observations and no hidden retry |
| `clean_android_target_files` | L3 | `owner-open-r5-l3` | Clean manifest, Soong/init/SELinux/package graph, target-files and installed identity agreement |
| `physical_android_adb` | L4 | `owner-open-r5-l4` | Authorized physical target, ordinary ADB, raw error modes, visible mutation and continued turn |
| `destructive_fault_matrix` | L5 | `owner-open-r5-l5` | Process, storage, USB, reboot and power-loss cuts with bound pre-state and post-restart reconciliation |
| `signed_public_release` | L6 | `owner-open-r5-l6` | Signing custody, transparency, AVB, OTA, anti-rollback and explicit human release authorization |

The environment must require reviewers who are independent of the source
change author.  Repository administrators must not reuse a general-purpose
runner label as one of these fixed labels.

## 2. Immutable runner inputs

For evidence kind `<kind>`, the runner provides:

```text
/opt/owner-open-r5/harnesses/<kind>
/etc/owner-open-r5/attestations/<kind>.json
```

Both paths must be regular, non-symlink, single-link files owned by root and
not writable by group or other.  The harness must be executable.  The target
attestation must be strict JSON and identify the real device, image, runner,
operator/custodian and relevant hardware or signing boundary.  Repository
checkout content may not supply either file.

The runner administrator, target custodian and source author must not all be the
same principal.  L5 fault injection and L6 release custody require separate
human authorization.  The workflow enforces `DESTRUCTIVE-*` and `RELEASE-*`
authorization-reference prefixes, but an appropriately prefixed string is only
a routing prerequisite; it is not proof that the named authority exists.

## 3. Harness command contract

The workflow invokes exactly one fixed harness process:

```text
<fixed-harness>
  --repository <owner/name>
  --evidence-kind <closed choice>
  --evidence-level <L2..L6>
  --source-commit <40 lowercase hex>
  --source-tree <40 lowercase hex>
  --target-attestation <fixed absolute path>
  --authorization-ticket <external reference>
  --synthetic=false
  --output <new private file under RUNNER_TEMP>
```

The harness must not accept an alternative executable, checkout, target,
attestation or output through environment variables, repository files or model
content.  It must fail before target contact when source identity, target
identity, custody, authorization, storage capacity or observation prerequisites
are missing or ambiguous.

A harness may invoke ADB, system tools, controlled power equipment or signing
tools only when those operations are part of its fixed reviewed lane.  It may
not push changes to GitHub, edit the checkout, change branch protection, merge,
create a release or mutate the gap register.

## 4. Raw capture object

The new output file is one strict JSON object with at least these fields:

```json
{
  "schema": "org.trillionnium.target-evidence-observation.v1",
  "repository": "TrillionniumFoundation/trillionnium-os",
  "evidence_kind": "physical_android_adb",
  "evidence_level": "L4",
  "source_commit": "0000000000000000000000000000000000000000",
  "source_tree": "0000000000000000000000000000000000000000",
  "synthetic": false,
  "promotion_authorized": false,
  "public_release": false,
  "raw_observations": []
}
```

The zero values and empty observation list above are shape examples only and
would be rejected as evidence.  Real output must bind the exact workflow input
commit/tree and contain non-empty raw observations.  Each observation carries
its source, timestamp or monotonic order, command/method, bounded stdout/stderr
or structured result, exit/transport status, target identity and artifact
hashes where applicable.  Secrets and private signing bytes are never copied
into the capture.

The workflow wraps the raw object in a content-addressed capture envelope and
sets `CAPTURED_PENDING_INDEPENDENT_REVIEW`.  It deliberately requires
`promotion_authorized=false` and `public_release=false`; authorization is a
later independently administered evidence-intake decision.

## 5. Lane-specific minimum observations

### L2 installed Root Linux process matrix

Retain install manifest and artifact hashes; live executable hash and signer;
UID/GID; SELinux domain where applicable; mount, namespace and cgroup identity;
resource ceilings; process tree; restart with a new epoch; emergency inhibit;
and negative checks for legacy product nodes.  Host-only process simulations
are not installed evidence.

### L2 installed Codex same-turn

Retain provider and executable identity; authenticated session establishment;
one turn that executes a successful shell command, a deliberate failure and a
continued command; exact tool-call/observation correlation; cancellation; and
proof that no substrate layer silently rewrote or redispatched the operation.
Provider text without raw tool events is insufficient.

### L3 clean Android target-files

Bind the resolved manifest, every dirty-state decision, build variant, Soong
module graph, init services, SELinux policy and contexts, package inventory,
target-files digest, image digests and installed identities.  The build must be
reconstructed from the pinned source subject; a copied working-tree overlay or
historical target-files archive is insufficient.

### L4 physical Android ADB

Identify the owner-authorized physical device and transport.  Retain
`adb devices -l`, explicit target selection, successful command output,
unauthorized/offline/disconnect behavior, one visible bounded mutation and the
same turn continuing after observation.  Never inject or substitute a serial.
A simulator, host mock or typed `BackendUnavailable` adapter is not L4.

### L5 destructive fault matrix

Bind pre-cut durable state and an independently controlled fault method.  Cover
process leader/descendant death, provider loss, storage `ENOSPC`, write/fsync
ambiguity, corrupt record or segment, USB disconnect, target reboot and a real
power-loss cut where the target permits.  Retain post-restart reconciliation,
unknown classifications and a redispatch count of zero.  Cleanup success may
not be inferred from leader exit alone.

### L6 signed public release

Bind production key custody without exporting private material; signer and
certificate lineage; transparency record; complete AVB chain; rollback indices
and hardware behavior; signed target-files and OTA hashes; install/update and
rollback-negative observations; release approvers; and explicit public-release
enablement.  Userdebug, test keys, an unsigned BOM, a dry-run or a newly created
unproven key set is not L6.

## 6. Review and gap transition

After capture, an independent verifier must:

1. download immutable artifacts and verify their digests;
2. validate source, tree, workflow, runner, target and authorization identity;
3. reject stale, revoked, synthetic, cross-spliced or incomplete evidence;
4. confirm the evidence level meets every named gap exit criterion;
5. issue a detached attestation under an independently administered trust root;
6. propose a gap transition without rewriting historical evidence;
7. run the normal protected integration path with no administrative bypass.

A changed source commit, tree, target image, harness, attestation, review or
trust root requires a new capture.  Evidence is non-inheritable across those
movements.
