# Owner-open R5 exact source closeout evidence

Date: **2026-08-28**  
Evidence level: **L1 / HOST_TESTED**  
Claim ceiling: **`EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX`**  
Public release: **false**  
Automatic redispatch: **false**

## 1. Exact identity

| Field | Value |
| --- | --- |
| Repository | `TrillionniumFoundation/trillionnium-os` |
| Development branch | `codex/owner-open-r5-tool-loop-20260827` |
| Closeout base commit | `668c031ba4533dc482866fd2da37b61118b92bf8` |
| Validated and pushed source commit | `fa1d287103c46aff35cf5e95addbc18da8a92063` |
| Workflow | `owner-open R5 strict source closeout v15` |
| Workflow run | `33186972324` |
| Workflow job | `98902377009` |
| Evidence artifact | `owner-open-r5-source-closeout-v15-668c031ba4533dc482866fd2da37b61118b92bf8-1` |
| Artifact ID | `9692313160` |
| Artifact ZIP SHA-256 | `b4756c407108235db2afe6f0a73b26851ca77716a9d9728395770f3d4047a2c4` |
| Candidate manifest | `tools/owner-open/r5-source-closeout-v15-files.txt` |
| Exact repair applicator | `tools/owner-open/apply_r5_rust_closeout_v15.py` |

The workflow checked out the exact base, applied the chained exact-preimage
repairs, formatted the tree, required the resulting diff to equal the sorted
31-file manifest, created one clean local candidate commit, qualified that exact
candidate, and pushed only after every gate passed. The pushed commit equals the
locally qualified candidate commit.

The temporary closeout workflow was deliberately retired after landing. The
applicator chain, manifests, Actions run, logs and artifact remain the audit and
reproduction trail.

## 2. Gates and observed results

### 2.1 Candidate and source integrity

Passed:

- manifest exists, is sorted and has no duplicate path;
- every declared path exists before repair;
- `cargo fmt --all` and `cargo fmt --all -- --check`;
- `git diff --check`;
- actual changed paths exactly equal the 31-file manifest;
- staged paths exactly equal the manifest;
- candidate commit paths exactly equal the manifest;
- worktree is clean after candidate creation;
- candidate patch, stat, path inventory and copied source files were captured;
- evidence `SHA256SUMS` verified successfully.

No broad Clippy suppression or warning downgrade was introduced. The source was
repaired until the complete default graph passed with warnings denied.

### 2.2 Python source closure

Command:

```sh
PYTHONWARNINGS=error::ResourceWarning \
  python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
```

Observed result:

```text
Ran 680 tests
OK (skipped=5)
```

The complete exercised suite includes graph, selected path, broker, MCP,
qualification lifecycle, process supervision, Android contract, rootfs,
packaging, evidence, ADB relay/exact-argv, persistence and production-retirement
fixtures.

### 2.3 Generated source and R5 graph

Passed:

```sh
python3 tools/generate-owner-open-types.py --check
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
```

The R5 verifier returned `ok: true`, the selected default Cargo members and Host
binary roots matched the reviewed graph, and forbidden source marker hits were
empty.

The verifier also emitted an intentional **Android integration hold**: the
audited Android overlay still selects forbidden legacy owner-open nodes. That
warning is preserved as an L3 blocker and is not converted into a source
failure or a false Android pass.

### 2.4 Rust source closure

Commands:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Observed result:

- complete default all-target test closure passed;
- complete default all-target Clippy closure passed;
- warnings were denied;
- focused pipe EOF, configured-journal fail-closed, live inspect, stream window,
  runtime, registry, provider, event-store, job-runtime and Host gates passed;
- locked Cargo metadata and the complete feature tree were captured.

The qualified default closure contains:

```text
apps/trillionnium-owner-open-host
crates/trillionnium-owner-open-call-registry
crates/trillionnium-owner-open-event-store
crates/trillionnium-owner-open-job-registry
crates/trillionnium-owner-open-job-runtime
crates/trillionnium-owner-open-provider-jsonl
crates/trillionnium-owner-open-runtime
crates/trillionnium-owner-open-stream-window
crates/trillionnium-owner-open-tool-bridge
crates/trillionnium-owner-open-turn-loop
crates/trillionnium-owner-open-types
```

The selected Host binaries are:

```text
trillionnium-owner-open-host    -> src/main.rs
trillionnium-owner-open-r5-core -> src/bin/r5_control_host_v7.rs
trillionnium-owner-open-r5-host -> src/bin/r5_transport_host.rs
```

## 3. Closed blocker inventory

This evidence closes the repository-internal source/CI blockers for:

- exact Cargo default graph and Host binary selection;
- generated type freshness and R5 graph regressions;
- same-turn provider/tool callback fixtures;
- active turn and targeted tool cancellation;
- client-output detach without effect cancellation;
- completed replay and conservative incomplete recovery;
- configured journal unavailable fail-closed behavior;
- durable pipe and PTY job controls;
- pipe close-stdin EOF completion;
- completed and uncertain job no-redispatch semantics;
- read-only turn/call/job inspection;
- bounded stream credit, pause/resume and resynchronization;
- multi-connection broker admission, owner result isolation, bounded observation
  broadcast and disconnect truth;
- connection-bound MCP live controls and exact-byte trace lifecycle;
- complete Python ResourceWarning closure for the exercised suite;
- complete Rust formatting, tests and Clippy closure;
- transient diagnostic/repair/landing workflow cleanup.

## 4. Explicit skips and why they are not passes

The five Python skips require material outside this exact source checkout:

1. `test_real_aosp_development_material_matches_fixed_denylists` —
   `TRILLIONNIUM_ANDROID_SOURCE_ROOT` was not set.
2. `test_exact_cargo_build_rs_cannot_read_out_of_bom_sentinel` — the exact
   shell-exec Rust toolchain root, Zig toolchain root and Cargo home were not
   supplied.
3. `P01DaemonReceiptBuildIntegrationTests.setUpClass` — a built v8 P01 artifact
   set was not supplied through `TRILLIONNIUM_P01_TEST_ARTIFACT_SET`.
4. `test_android_staging_filter_c_packager_erofs_differential_corpus` — the
   pinned Android staging-filter C source was not present.
5. the superseded `ReleaseCodexSupervisorPreflightTest` glue was skipped because
   the selected v2 release path owns that coverage.

The first four remain external-material evidence holds. The fifth is a
superseded fixture path with current v2 coverage; it is not used to claim an
installed Codex or device result.

## 5. Android graph hold

The exact source verifier preserved the following selected-overlay warning:

```text
TrillionniumAiAuthority
TrillionniumCapabilityLeaseIssuer
trillionnium-agent-adb
trillionnium-agent-egress-guard
trillionnium-agent-egress-launcher
trillionnium-agent-egress-probe
trillionnium-agent-operation-epoch-replay-hold-contract
trillionnium-agent-operation-journal-v3-promotion-contract
trillionnium-agentd-materialization-p01-userdebug
trillionnium-capability-lease-trust-config
trillionnium-direct-operation-custody-high-water
trillionnium-direct-operation-custody-high-water-ready-gate
trillionnium-p01-final-artifact-set-v5
trillionnium-p01-receipt-stage-custody-evidence
trillionnium-p01-receipt-stage-evidence
trillionnium-p01-runtime-config
trillionnium-shell-exec-artifact-set-v1
trillionnium-shell-exec-broker-userdebug
trillionnium-shell-exec-worker-userdebug
```

These nodes must be removed from the selected Android owner-open product graph
before strict Android cutover and L3 qualification.

## 6. Evidence boundary and nonclaims

This package proves an exact repository source candidate at L1. It does not
prove:

- execution against the actual installed target Root Linux Codex binary;
- executable identity, installed version, help bytes, credentials or native
  provider behavior;
- target Root Linux UID/GID, namespace or cgroup placement;
- a deployed ARM64 adb client or transparent relay;
- clean Android target files, init, SELinux or abstract-socket admission;
- a physical shell, job or ordinary ADB effect;
- crash, ENOSPC, USB loss, reboot or power-loss conformance;
- signed L6 public-release qualification.

Those facts require their real binaries, build outputs, credentials, target
environment or physical device. Missing external inputs remain explicit holds;
they are never synthesized as successful evidence.
