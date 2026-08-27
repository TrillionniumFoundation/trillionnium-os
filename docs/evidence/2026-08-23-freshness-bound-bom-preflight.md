# Freshness-bound source/BOM/target preflight — 2026-08-23

This is a host-side, read-only evidence record for the first item in the
AI-agent-native execution plan.  It records a **HOLD**, not a release approval.
No device setting, package, partition, key, signing material, or OTA state was
changed while collecting this evidence.

## Result

The strict source-BOM binding checker and the Android BOM preflight integration
are implemented as opt-in checks.  The focused binding tests and the packaging
gate suite pass (27/27 in this worktree), but the current Android artifacts do
not satisfy the strict gate:

```text
decision: HOLD
exit: 78
holds:
  target_files_missing_META_misc_info.txt
  target_files_source_bom_binding_missing
  signed_metadata_missing
  rollback_evidence_missing
```

The internal dogfood OTA ZIP used for the first bounded check is not a
target-files archive and has no `META/` target-files members.  A separate
target-files archive does exist under the active OUT, but it is an older
2026-08-14 artifact (3,311,305,066 bytes) and is also missing the source-BOM
binding member.  The strict preflight against that archive returned the
following additional holds:

```text
target_avb_test_key_path
avb_*_add_hash_footer_args_missing_rollback_index
target_build_type_not_user
target_build_tags_not_exact_release_keys
target_metadata_contains_userdebug_or_test_keys
target_ota_keys_empty_or_missing
target_files_source_bom_binding_missing
signed_metadata_missing
rollback_evidence_missing
```

The successful A/B installation of the separate dogfood ZIP therefore does not
establish a source-to-target identity, and the older target-files archive cannot
be reused with the current dirty source.

## Source and manifest freshness

- Source-set contract:
  `tools/p0-cross-repo-source-set.v2.json`, SHA-256
  `c267e5a83ee0ae8ae6c60e7c222c87c53d9653d4f009e2c14027082e4711df3d`.
- The checkout's checked-in declaration
  `android/lineage-fogos/.repo/manifests/trillionnium-fogos.xml` contains 1,172
  projects, is 196,655 bytes, and has SHA-256
  `03ea1c84f61a3240af984781813c44ac95b81e0f75ca16024faeeb0ff187c872`.
  It is a declaration snapshot, not proof that `repo manifest -r` completed.
- Repeated bounded attempts to obtain a resolved manifest with `repo
  manifest -r` produced no usable output and timed out while scanning the
  checkout (over 180 seconds).  A bounded run of
  `tools/materialize_cross_repo_source_bom.py` using the declaration snapshot
  also timed out at 180 seconds and produced no candidate JSON.  The source
  BOM is consequently not regenerated or relabelled as fresh.

There is a historical receipt-stage BOM at the active OUT's
`trillionnium/receipt-stage-v1/evidence/source-bom.v2.json` (1,249,792 bytes,
receipt `sha256:40dbe383f79493269a68972f5f918e1b168d77e3ca4b20e6cf1bec57e75e5a6c`,
mtime 2026-08-14).  Its recorded clean graph is retained as historical
evidence only.  Current source is dirty (including the Android identity
contract and sepolicy changes), so that receipt cannot authorize the current
target.

## Active OUT and artifact identity

The active build root is:

`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/android/lineage-fogos/out/target/trillionnium-userdebug-v28-standard-relative-20260814.9YHOOi`

Observed markers demonstrate mixed generations: `system/build.prop` and the
boot/product images are dated 2026-08-14, while source-side Android files and
installable metadata were modified later.  The dogfood OTA staging directory
was generated on 2026-08-23 and contains a 1,356,454,975-byte
`trillionnium_fogos-userdebug-testkeys-1786679844-full.zip`; the end-to-end ZIP
SHA-256 recorded by the installation evidence is
`a993dddefb4d8a909f1d804ac61aaa9a50423347837f2fb4ca131d4d8ed64af5`.
The active OUT's historical target-files path is:

`target/product/fogos/obj/PACKAGING/target_files_intermediates/trillionnium_fogos-target_files.zip`

Its metadata reports 13 `userdebug` build-type entries, `test-keys`, empty
`META/otakeys.txt`, static rollback indices 28, and an AOSP test-key marker.
The OTA metadata identifies a userdebug/test-keys build, but neither this old
target-files archive nor the dogfood OTA carries the required
`META/trillionnium-source-bom-binding.json` member.

The strict binding schema is
`org.trillionnium.android-source-bom-binding.v1`, with authority explicitly
limited to `local_source_provenance_not_release_authority`.  It intentionally
does not claim production signing, hardware attestation, rollback authority,
or device custody.  Target-files writer integration and a fresh exact-clean
rebuild remain required before this check can become a release gate.

## Binding producer added (host-only)

`tools/materialize_android_source_bom_binding.py` now materializes the closed
binding consumed by the Android target-files writer.  It reads the source BOM,
source-set contract, resolved manifest, and receipt-stage descriptor through
bounded `O_NOFOLLOW` descriptors, re-stat's each input after reading, verifies
the source-BOM receipt ID and all byte/digest links, and publishes a new output
with `O_EXCL`.  It refuses a HOLD BOM, stale manifest/contract bytes,
non-canonical JSON, symlinked inputs, or an already-existing output.  The
focused fixture suite is 3/3, and the generated historical fixture was
accepted by `verify_source_bom_binding.py` only as a provenance-shape check;
it is not being embedded into the current target.

The Android `build/make` change remains opt-in through
`TRILLINNIUM_SOURCE_BOM_BINDING_JSON`: the default empty value preserves the
existing target-files recipe, while a supplied binding becomes a prerequisite
and is copied to `META/trillionnium-source-bom-binding.json` only after the
bounded host helper validates it.  No Android build or device write was run.

An attempted parallel HEAD verification of all 1,172 checkouts was stopped
after the external disk left many `git rev-parse` workers in uninterruptible
I/O (`D`) state.  That is evidence of host-storage unavailability, not a
freshness pass; the checked-in declaration remains a declaration snapshot.

## Next safe step

Obtain a real resolved manifest (or fail closed), materialize a new BOM from
the current source, perform an exact-clean target-files build that embeds the
binding member, and bind the resulting target-files digest to OTA metadata.
Only after that identity chain is fresh should the plan proceed to the
read-only init/Agent API observer.  No manual `setprop`, service start, Codex
effect, ADB custody claim, or replay receipt is valid at this stage.

## Post-hardening bounded host checks (22:xx CST)

The following checks were rerun after tightening bounded command cleanup,
symlink-parent rejection, exact descriptor schemas, hardlink/alias rejection,
and durable binding output writes.  They are fixture/source checks only; they
do not establish a fresh Android checkout or target-files artifact:

```text
tools.tests.test_materialize_cross_repo_source_bom                         27/27 PASS
tools.tests.test_materialize_android_source_bom_binding                     3/3 PASS
packaging/android-release-gate/tests (all test_*.py)                       27/27 PASS
tools.tests.test_android_release_ota (strict binding fixture coverage)      44/44 PASS (1 skipped)
android build/make/tools/releasetools/test_embed_source_bom_binding.py      7/7 PASS
agent_direct_product_contract_test.sh                                      PASS
agentd_peer_identity_contract_test.sh                                      PASS (artifact/device HOLD)
agent_operation_epoch_replay_product_hold_contract_test.py                 7/7 PASS
agentd_payload_epoch_high_water_test.py                                    8/8 PASS
rootfs_bootstrap_v9_branch_contract_test.sh                                PASS
```

Additional bounded Rust checks completed in isolated temporary target
directories (which were removed afterward):

```text
cargo test -p trillionnium-agent-direct-tools --lib                         283/283 PASS
cargo test -p trillionnium-agent-api-uds --lib                                9/9 PASS
cargo test -p trillionnium-agent-stdio-proxy --lib                            7/7 PASS
cargo check -p trillionniumd --bin trillionniumd                              PASS (warnings only)
cargo fmt --all -- --check                                                    PASS
```

These compile/unit results validate source behavior only.  They do not imply
that the corresponding binaries are present in the active Android target or
that an authenticated device peer exists.

The host OTA planner now has an explicit strict mode.  Supplying
`--require-source-bom-binding --source-bom-binding-bom <canonical BOM>` makes
it reject a target-files archive before signing/tool inventory work when the
embedded member is absent or does not cross-check against the supplied BOM.
The default remains backwards-compatible for old fixtures; no signing or
device operation was performed.  The 44-test fixture suite covers the strict
path, missing-member failure, alias rejection, and the unchanged default.

The Android `agentd_production_tcb_test.sh` source/self-test gate also completed
with its physical target-files portion explicitly held: the measured Agent
source TCB, tar-filter checks, and bounded target-files verifier self-tests
passed, while no physical target-files materialization was supplied.  This is
source evidence only and does not qualify the active OUT or authorize init
activation.

The bounded `rootfs_bootstrap_transaction_test.sh` and v9 branch contract both
completed with `PASS` on the later host run.  A broad resolved-manifest/
checkout scan remains unproven because the external disk can leave Git workers
in uninterruptible I/O; no timeout is converted into a freshness result.  The
source-to-BOM-to-target-files chain still lacks a current resolved manifest and
a freshly embedded `META/trillionnium-source-bom-binding.json` member.

No device command, property write, service transition, package operation, or
network-state change was performed by these checks.

## Strict preflight re-run (22:xx CST)

The strict read-only CLI was run against the known active-OUT target-files ZIP
and its historical BOM with both binding flags enabled.  It returned exit 78
and `decision: HOLD`; no ADB, signing, private-key read, or file write was
performed.  The concrete binding result was:

```text
target_files_source_bom_binding_missing
signed_metadata_missing
rollback_evidence_missing
target_build_type_not_user
target_build_tags_not_exact_release_keys
target_ota_keys_empty_or_missing
target_avb_test_key_path
```

The archive measured 3,311,305,066 bytes with 14,053 ZIP members.  This is a
freshly observed failure of the strict gate, not a claim that the historical
BOM or target is current; the source-to-target generation mismatch remains the
primary hold.

A fresh bounded `repo manifest -r` retry against the canonical Android checkout
was attempted after the host test runs.  It timed out at 45 seconds (exit 124)
and left a zero-byte output file; no resolved manifest was accepted or
published.  This confirms the storage/I/O blocker is still present rather than
yielding a synthetic declaration-only manifest.

## Trace-isolation hardening (host-only)

`tools/materialize_cross_repo_source_bom.py` now injects `REPO_TRACE=0` into
every bounded subprocess environment.  The local `repo` launcher otherwise
defaults tracing on and appends to `.repo/TRACE_FILE`; that would violate the
tool's read-only measurement contract and add avoidable metadata writes on the
external disk.  The focused regression now reports:

```text
tools.tests.test_materialize_cross_repo_source_bom                         28/28 PASS
tools.tests.test_materialize_android_source_bom_binding                     3/3 PASS
```

This change only constrains host subprocess environment and does not alter the
freshness decision.  A resolved manifest and current exact-clean target-files
artifact are still absent, so init activation and Codex effect/ACK remain
blocked.

The Git symbolic-HEAD probe was also moved off `subprocess.run(timeout=...)`
onto the same bounded runner.  Detached HEAD's normal return code `1` is
explicitly allowed and still yields an empty ref; storage-I/O cleanup therefore
cannot turn a bounded HOLD into an unbounded wait.  Its focused exit-code
fixture passed alongside the trace-isolation test.

A post-hardening bounded `repo manifest -r --no-local-manifests` probe was then
run with a 100-second process-group limit and `REPO_TRACE=0`.  It failed closed
at the limit with no bytes published, and no child Git processes remained after
cleanup.  The external-disk metadata path is therefore still the active
freshness blocker; no declaration-only XML was promoted to resolved evidence.

## Low-I/O recheck and pinned-manifest candidate audit (2026-08-24 CST)

After stale diagnostic workers were terminated, the canonical external volume
was rechecked as `/dev/sdd1`, UUID
`63df6e1a-baf3-4680-8bbb-8019fb025341`, mounted read-write at
`/data/toshiba-dev`.  A low-priority, five-minute
`repo manifest -r --no-local-manifests` attempt with `REPO_TRACE=0` again
returned a timeout with zero output.  The process group was cleaned up; no
manifest bytes were published and no device operation was attempted.

The committed `trillionnium-fogos.xml` declaration was audited without
running `repo manifest`: it contains 1,172 unique projects, every project has
an explicit 40-hex revision, and it has no include, submanifest,
remove-project, extend-project, or repo-hooks elements.  Its manifest.git
commit/blob also matches the checked-out declaration.  This makes it a useful
candidate input for a future low-I/O resolver, but it does not prove every
checked-out worktree's HEAD, index, dirty, ignored, or symlink state.  The
`.repo/.repo_localsyncstate.json` file contains timestamps only and is not a
resolved revision snapshot; `.repo/project.list` is stale and is not the
project set.

The existing production BOM path intentionally remains PASS-only:
`require_clean=true` and `require_no_ignored=true` for all 23 contract trees;
downstream Android binding and OTA verification also require
`PASS_LOCAL_EXACT_CLEAN_GRAPH`.  A separate dirty-source dogfood provenance
lane would need a new schema and verifier with `authority=false`; no such lane
was introduced in this recheck, and no production gate was weakened.

The device and Gnirehtet relay were left unchanged.  No init/property/service
activation, Codex turn, effect/ACK, ADB custody transition, install, reboot,
or flash was performed.

## Provenance hardening note (2026-08-24 CST)

The source-BOM materializer's `--resolved-manifest` test/fixture input is
currently labeled `supplied_regular_file`; the parser validates XML shape and
exact revision syntax, but that label alone does not prove the bytes came from
`repo manifest -r`.  This is a host-tool hardening gap, not an authorization
grant: the current dirty checkout still produces `HOLD`, and no supplied
declaration was used for a binding or target.  A future fix should require
`local_repo_manifest_r` (or a separately verified resolver receipt) for the
production lane while preserving explicit fixture/dogfood lanes with
`release_allowed=false`; it must not weaken the existing clean/ignored gates.

## Low-I/O pinned-manifest resolver and receipt binding (2026-08-24 CST)

The external volume still has kernel `usb-storage`/`jbd2`/flush workers in
uninterruptible I/O, so another bounded `repo manifest -r` walk would be
unproductive.  A new host-only resolver,
`tools/resolve_repo_manifest_low_io.py`, was added instead.  It has a narrower
and explicit proof obligation: the manifest must contain no dynamic composition
elements (`include`, `submanifest`, `remove-project`, `extend-project`, or
`repo-hooks`), every project revision must be an exact SHA, and every checked
out project's `.git/HEAD` (including symbolic refs and packed refs) must
resolve to the declared SHA.  It reads metadata directly, performs a final
manifest stability read, and publishes nothing on mismatch or I/O failure.

Against the canonical Android checkout (`/dev/sdd1`, 1,172 projects), the
resolver completed in roughly nine seconds and produced:

```text
decision: PASS_LOCAL_PINNED_MANIFEST_HEADS
producer: local_repo_manifest_direct_pinned
project_count: 1172
manifest_bytes: 196655
manifest_sha256: 03ea1c84f61a3240af984781813c44ac95b81e0f75ca16024faeeb0ff187c872
release_allowed: false
```

This is a provenance-bound source-resolution candidate, not a release or
device-authority claim.  `materialize_cross_repo_source_bom.py` now accepts it
only with `--resolved-manifest-receipt
--require-resolved-manifest-provenance`; the receipt schema, digest, checkout
path, project observations, and canonical receipt ID are checked.  A regular
supplied XML without a receipt remains accepted only by the fixture/dogfood
lane and is rejected by the strict flag.

The strict BOM was then run with the real resolver output.  It reached the
source-state gates and returned `HOLD_LOCAL_SOURCE_GRAPH` (exit 2), rather than
timing out or promoting a declaration-only manifest.  The concrete blockers
were:

```text
project_ignored_paths_present:android_build_make
project_ignored_paths_present:control_plane
project_ignored_paths_present:vendor_trillionnium
project_nonignored_worktree_dirty:ai_authority
project_nonignored_worktree_dirty:ai_shell
project_nonignored_worktree_dirty:android_build_make
project_nonignored_worktree_dirty:control_plane
project_nonignored_worktree_dirty:device_sepolicy
project_nonignored_worktree_dirty:trillionnium_sdk
project_nonignored_worktree_dirty:vendor_trillionnium
```

Thus the resolved-manifest I/O blocker is genuinely narrowed/cleared for this
checkout, while the clean/ignored source gate remains correctly held.  No
dirty files were changed, no declaration was relabelled as a clean BOM, and no
device, network, init, or OTA operation was performed.

## Fresh strict preflight handoff (2026-08-24 01:29 CST)

The strict BOM produced from the resolver receipt was written to the external
temporary staging path with SHA-256
`53e441ba8f16369a5d76be7e20a604faaebf15e16cfffa357b71eadb1995d998`.
Its embedded resolved-manifest observation is the non-authorizing
`local_repo_manifest_direct_pinned` receipt above (`196655` bytes,
`03ea1c84f61a3240af984781813c44ac95b81e0f75ca16024faeeb0ff187c872`).

The independent Android BOM preflight returned exit `78` / `HOLD` without a
target archive.  It reported the source graph dirty/ignored blockers above,
plus the expected absence of target-files, signed metadata, and rollback
evidence.  No signing, private-key access, ADB effect, or file publication was
performed by that verifier.

## Direct repo resolver recovery (2026-08-24 01:37 CST)

After stale scan workers were removed and `REPO_TRACE=0` was enforced, the
materializer's own bounded `repo manifest -r` lane completed against the
canonical checkout.  It produced a real `local_repo_manifest_r` observation:

```text
bytes: 195467
sha256: 9a0c8be03881096bde3e4413e58429c90f9c11dc06d3a2a5407d1b234828732d
project_count: 1172
all_revisions_exact: true
declared_checkout_revision_drift_count: 0
```

The resulting strict BOM remained `HOLD_LOCAL_SOURCE_GRAPH` with the same ten
dirty/ignored source-state blockers.  This is the strongest current freshness
result: the real repo resolver is no longer the blocker, while the clean/zero-
ignored gate remains intact and all dirty worktree changes are preserved.

## Latest bounded receipt-bound rerun (2026-08-24 01:43 CST)

The latest independently rerun host-only path used
`tools/resolve_repo_manifest_low_io.py` plus the strict materializer receipt
flags.  It returned `PASS_LOCAL_PINNED_MANIFEST_HEADS` for 1,172 projects
(`196655` bytes, SHA-256
`03ea1c84f61a3240af984781813c44ac95b81e0f75ca16024faeeb0ff187c872`,
producer `local_repo_manifest_direct_pinned`, `release_allowed=false`) and
the materializer returned exit `2` / `HOLD_LOCAL_SOURCE_GRAPH`.  The ten
source-state blockers were unchanged from the preceding section.  This
receipt-bound rerun is non-authorizing evidence and does not replace the
historical `local_repo_manifest_r` observation above; no device, ADB, init,
network, signing, or OTA action was taken.
