# Rootfs Evidence Factory stage

`package_current_rootfs.py` is the current, version-independent host packager.
It consumes a frozen JSON contract and emits two new files: a deterministic
`tar.zst` rootfs and its custody receipt. It does not update the AOSP vendor
archive, sign an OTA, install to a device, or promote a release claim.

The adjacent `rootfs-packager.contract.template.json` is deliberately not
executable as-is. Its zero hashes, zero sizes, version marker, install path and
AgentManifest values must be replaced from the same frozen source-custody run.
In particular, the AgentManifest `identity_key_sha256` must equal the bound
Codex launcher SHA-256. The current path accepts only the frozen fresh minimal
Bookworm base with its exact build receipt and SPDX document. Every legacy
migration, prune, absolute-symlink rewrite and replacement-hardlink field must
remain empty or null. Historical archives must be rebuilt from the fresh
allowlist; subtracting packages or hot-replacing payloads in an old archive is
forbidden.

## Materialize the disabled common AgentManifest

`materialize_common_codex_agent_manifest.py` is the only current host entry
point for creating the disabled common AgentManifest consumed by the v9 rootfs
contract materializer. It does not accept an identity argument. Instead it
remeasures the complete physical common v5 artifact set, revalidates the common
launcher A/B v4 receipt, and derives the historically named
`identity_key_sha256` from the retained common launcher executable. That field
is an executable measurement, not a public-key digest. The adapter version is
derived from the receipt-bound `trillionnium-codex-agent-VERSION` filename;
health remains `disabled`, both timestamps are zero, and the output is
canonical sort-keys/indent-2/LF JSON published as a single-link mode-0444 file.
The tool compiles the adjacent `materialize_rootfs_contract.py` source bytes
directly and never consults a pre-existing ignored Python bytecode cache.

```text
python3 tools/evidence-factory/materialize_common_codex_agent_manifest.py \
  --template RUN/inputs/rootfs-packager.contract.template.json \
  --common-artifact-set-receipt RUN/common-codex-rootfs-artifact-set.v5.json \
  --common-launcher-ab-receipt RUN/codex-launcher-artifact-set-ab.v4.json \
  --daemon RUN/trillionniumd \
  --codex-launcher RUN/trillionnium-codex-agent-0.144.1 \
  --system-api-tool RUN/trillionnium-agent-system-api \
  --accessibility-tool RUN/trillionnium-agent-accessibility \
  --system-api-replay-sync RUN/trillionnium-system-api-replay-sync \
  --source-date-epoch 1700000000 \
  --output RUN/AgentManifest.json
```

Run the materializer independently against the common A and B physical
artifact directories and require byte-identical, inode-distinct outputs before
using either one below. Do not copy or edit the checked-in Android/vendor
manifest: that file belongs to a historical product branch, while the Android
P0.1 receipt stage separately derives its enabled/ready manifest from the P0.1
launcher SHA-256.

## Materialize a current contract

`materialize_rootfs_contract.py` creates one new contract from the adjacent v9
template and frozen source-custody inputs:

v9 is a deliberate schema break. Historical v6/v7/v8 contracts and receipts remain
historical evidence and are never interpreted with v9 semantics. v9 projects
the common artifact-set's retained-fd compiler and ELF-inspector custody,
stable principal/launcher measurement, required common launcher A/B v4 receipt
and unresolved identity-independence gate into the contract. Its
`common_build_evidence` names those values
`upstream_source_bom_receipt_claim`,
`upstream_receipt_toolchain_snapshot_claim` and
`upstream_receipt_target_compiler_closure_claim`. The
paired `source_bom_claim_authority` and `toolchain_claim_authority` objects say
exactly that these values are copied from a content-hash-bound common v5
receipt and a self-hashed launcher v4 receipt whose claims cross-agree. The
common v5 receipt has no `receipt_id`; its exact bytes and SHA-256 are bound by
the caller. The launcher's `receipt_id` is an unsigned content identifier, not
a signature or attestation. This stage receives no physical source BOM or
toolchain snapshot, does not remeasure a live source graph or snapshot, and
does not requery the effective compiler components. The upstream closure claim
still records `false` for the host process runtime and complete recursive
toolchain closures. Both
identity-independence evidence receipts remain `null` and both
`verified` fields remain `false`, so the contract decision is explicitly
`HOLD_IDENTITY_INDEPENDENCE_EVIDENCE_UNVERIFIED` with
`release_allowed=false`.

```text
python3 tools/evidence-factory/materialize_rootfs_contract.py \
  --template tools/evidence-factory/rootfs-packager.contract.template.json \
  --base-rootfs RUN/base-rootfs.tar.zst \
  --common-artifact-set-receipt RUN/common-codex-rootfs-artifact-set.v5.json \
  --common-launcher-ab-receipt RUN/codex-launcher-artifact-set-ab.v4.json \
  --daemon RUN/trillionniumd \
  --codex-binary RUN/trillionnium-codex-agent-0.144.1 \
  --system-api-tool RUN/trillionnium-agent-system-api \
  --accessibility-tool RUN/trillionnium-agent-accessibility \
  --system-api-replay-sync RUN/trillionnium-system-api-replay-sync \
  --agent-manifest RUN/AgentManifest.json \
  --zstd RUN/host-tools/zstd \
  --source-date-epoch 1700000000 \
  --output RUN/rootfs-contract.json
```

All inputs must be owner-custodied, non-writable regular files with no symlink
components. Daemon, Codex, System API, Accessibility and System API replay-sync
must be executable AArch64 ELF64 files; Codex must have no `PT_INTERP`. The
explicit host `zstd` executable is also mandatory and must be a single-link,
non-writable executable in an owner-controlled, non-symlink directory. The
materialized v9 contract binds both its exact byte size and SHA-256; neither
the materializer nor the packager discovers it through `PATH`. The canonical
common v5 artifact-set receipt and common launcher A/B v4 receipt are separate
required inputs. The rootfs stage binds all five replacement files
byte-for-byte. The two upstream receipts must cross-agree on their source-BOM,
snapshot and effective compiler-closure claims, compiler and ELF-inspector leaf
identities, and path-distinct A/B launcher equality while retaining their
host-only HOLD decisions. Common launcher A/B v4 reports
`same_upstream_source_bom_receipt_claim=true` and
`physical_source_bom_or_live_graph_remeasured_by_this_stage=false`; it also
records the required physical lane/input/toolchain/sysroot/tool-inode
distinctions. None of those receipt claims makes the physical snapshot or
source graph an input to this rootfs stage. Their legacy
descriptor digests are exact constants, literal digest absence is only a
verified scan result, and neither can be promoted into an identity-independence
proof without a new schema carrying real evidence.
The source-set and resolved-manifest bindings remain strict nonzero lowercase
SHA-256 values, but are not revision-specific constants in these downstream tools.
Their exact upstream source-BOM receipt claim must agree across the common v5
receipt, launcher A/B v4 receipt, materialized contract, package receipt and
EROFS admission; any cross-splice fails closed. That is receipt-object
cross-agreement, not a physical source-BOM input or live source-graph
remeasurement by the materializer, packager or preflight.
System API, Accessibility and replay-sync are bound to their exact
`usr/local/bin/` archive paths. The AgentManifest is parsed as strict UTF-8 JSON and
its `identity_key_sha256` must equal the exact Codex launcher SHA-256. The tool
fills all bytes, hashes, install-version and required-field bindings, while
requiring every reusable migration array to remain empty and the nullable
migration field to remain null. It refuses an
existing output (including a symlink) and publishes a read-only, deterministic
JSON file. It materializes only the contract: it does not package a rootfs,
write AOSP/vendor state, access a device, or build/sign an OTA.

The Evidence Factory should treat this as one isolated stage:

1. Copy the custodied base rootfs into an isolated run directory. Never pass
   the AOSP vendor archive as `--output-rootfs`. Remove all write bits from the
   base archive before invoking the packager. Output and receipt parents must
   already exist and contain no symlink components.
2. Use the common AgentManifest materializer against both physical common
   launcher lanes and require byte-identical outputs. Then use the contract
   materializer above to create a new contract with the exact byte
   sizes and SHA-256 values of the base archive, common v5 artifact-set receipt,
   common launcher A/B v4 receipt,
   ARM64 daemon, static ARM64 Codex launcher, ARM64 System API and Accessibility
   tools, ARM64 System API replay-sync, AgentManifest and the frozen host zstd
   executable. A writable `/usr/bin/zstd` is not a frozen input: first place its
   reviewed exact bytes under the run's read-only tool custody.
3. Bind the current packager and the instantiated contract in source custody.
4. Invoke the stage once per output path:

   ```text
   python3 tools/package_current_rootfs.py \
     --contract RUN/rootfs-contract.json \
     --base-rootfs RUN/base-rootfs.tar.zst \
     --fresh-base-receipt RUN/minimal-bookworm-arm64.receipt.json \
     --fresh-base-sbom RUN/minimal-bookworm-arm64.spdx.json \
     --common-artifact-set-receipt RUN/common-codex-rootfs-artifact-set.v5.json \
     --common-launcher-ab-receipt RUN/codex-launcher-artifact-set-ab.v4.json \
     --daemon RUN/trillionniumd \
     --codex-binary RUN/trillionnium-codex-agent-0.144.1 \
     --system-api-tool RUN/trillionnium-agent-system-api \
     --accessibility-tool RUN/trillionnium-agent-accessibility \
     --system-api-replay-sync RUN/trillionnium-system-api-replay-sync \
     --agent-manifest RUN/AgentManifest.json \
     --zstd RUN/host-tools/zstd \
     --output-rootfs RUN/rootfs-current.tar.zst \
     --receipt RUN/rootfs-package-receipt.json
   ```

5. Re-run with a second new output path and require the two rootfs SHA-256
   values to match before downstream target-files construction.

The packager opens and remeasures the contracted zstd for each invocation and
executes the held file descriptor, so pathname replacement cannot select
uncontracted bytes. The receipt binds the packager, contract, zstd
implementation, every input,
every normalized tar member and the compressed output. It permanently records
`host_only=true`, `device_write_performed=false` and
`ota_signing_performed=false`. The v9 package receipt also repeats the exact
common build/launcher A/B evidence and unresolved gate and therefore retains the explicit
HOLD decision and `release_allowed=false`, even when deterministic archive
generation succeeds. A receipt from this stage is therefore artifact
custody, never live-device or release-complete evidence. The v9 package
`receipt_id` is only a SHA-256 content identifier over sort-key, compact,
no-LF UTF-8 JSON with the `receipt_id` field omitted. The required launcher A/B
v4 receipt uses its separately declared sort-key, indent-2, trailing-LF
encoding. These hash domains are explicit and not interchangeable; neither is
a signature, attestation, live receipt or statement of release readiness. The
package receipt's closed `limitations` list also says that any upstream
self-hashed IDs are unsigned content identifiers while the common v5 input is
bound by its exact bytes and SHA-256, the physical snapshot is neither an
input nor remeasured, effective compiler components are not requeried, and no
physical source BOM or live source graph is remeasured by the rootfs packager.

`output_rootfs.decompressed_tar_bytes` and
`output_rootfs.decompressed_tar_sha256` continue to bind the immutable raw tar
inside the published `tar.zst`. The sibling
`output_rootfs.android_staging_filter` object is a deterministic output
closure for the Android staging-only stream. It has exactly four fields:
schema `org.trillionnium.rootfs-tar-staging-filter.v1`, source SHA-256
`dc48c9ce97f1e64a62e45d00350b44801adb7cc0f60f8666b1d5e87696ce6092`,
filtered-stream byte count and filtered-stream SHA-256. The packager does not
discover or execute the Android helper and does not rewrite the raw tar or
published rootfs. It models the pinned C helper's physical tar grammar, exact
four GNU longlink pairs, exact 265-directory fixture, and sole
transformation: each accepted directory header changes from `0555` to `0755`
and receives the C helper's recomputed checksum. Unexpected headers, octal
fields, checksums, directory modes, longlinks, data padding or trailer bytes
fail before publication. The EROFS v9 receipt consumer parses the same pinned
physical grammar and recomputes the filtered SHA-256. A shared differential
corpus runs the C helper, packager model and EROFS model against accepted and
rejected header variants; the consumer also rejects missing, extra or
cross-spliced closure fields.

The historical `package_internal_alpha_rootfs_v9.py` remains available only to
interpret old receipts. It is not an Evidence Factory current-stage entrypoint.

The current Codex EROFS preflight consumes
`packaging/root-linux/rootfs-codex-erofs-admission.v4.json`. v1/v2/v3 remain frozen
historical material. v4 requires the v9 package receipt, common v5 artifact set,
common launcher A/B v4 evidence and the same unresolved identity-independence
gate, then repeats those bindings in its preflight receipt. Its decision remains
a `HOLD_...` value for both the upstream identity proof and the still-missing
label-applying EROFS materializer; it cannot emit an image or authorize release.
Its own closed `limitations` list repeats that same content-hash/self-hashed-ID boundary and
states that EROFS preflight receives no physical snapshot, remeasures no
snapshot, requeries no effective compiler component, and remeasures no physical
source BOM or live source graph.

## Build the reviewed minimal Bookworm base

`minimal-bookworm-rootfs.contract.v1.json` freezes the complete 35-package
Bookworm arm64 closure, exact package versions, Debian snapshot metadata,
archive keyring, host tool hashes, read-only normalization, and non-authorizing
production flags. It is the input to `../build_minimal_bookworm_rootfs.py`;
its output remains a host-only base and must not be copied into the Android
product until the final daemon/provider payload and immutable-image admission
stages are complete.
