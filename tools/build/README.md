# Selected Host/Core build reproducibility

`verify_host_reproducibility.py` builds the selected
`trillionnium-owner-open-r5-host` and `trillionnium-owner-open-r5-core` release
binaries twice and compares their complete file sizes and SHA-256 byte digests.
Both builds use one clean source commit, Rust/Cargo **1.93.0**, the committed
`Cargo.lock`, and separate, initially empty target directories. A successful
report proves that these two local builds produced matching bytes under the
recorded inputs. It does not qualify an installation, an Android device, an
image, a signature, a release, or an L2-or-higher lane.

## Prerequisites

- Linux with an ELF-capable C linker, `ar`, Git, and Python 3.10 or newer.
- Existing native Rust 1.93.0 compiler and Cargo executables. Pass their actual
  toolchain paths; a rustup proxy is not the compiler input to this recipe.
- An existing Cargo dependency cache containing every locked dependency. The
  verifier never installs tools or downloads dependencies.
- A pristine Git checkout, including no untracked **or ignored** files. Keep
  build targets, reports, logs, Python bytecode, and other generated files outside
  the checkout. The tool refuses a dirty tree instead of assigning its build to
  a clean commit. `--expected-commit` should be the full reviewed commit ID.
- No `.cargo/config` or `.cargo/config.toml` at the repository root, any ancestor,
  or the supplied Cargo home. Such configuration is outside the fixed recipe
  and is rejected; the tool does not modify or delete it.

The working implementation checkout may be dirty while changes are being
reviewed. Run this verifier only after those changes exist in a clean reviewed
commit and checkout. It neither commits changes nor creates or switches branches.

## Run

Run from the clean checkout, replacing the example absolute paths and commit:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build/verify_host_reproducibility.py \
  --repo-root /work/reviewed-checkout \
  --expected-commit FULL_REVIEWED_COMMIT_SHA \
  --cargo /tools/rust/1.93.0/bin/cargo \
  --rustc /tools/rust/1.93.0/bin/rustc \
  --cc /usr/bin/cc \
  --ar /usr/bin/ar \
  --cargo-home /work/existing-cargo-cache \
  --build-root /work/host-reproducibility-run-001 \
  --output /work/host-reproducibility-run-001.json
```

The build root and report must not exist yet. Their parent directories must
already exist, and both must be outside the source checkout; the build root
must also be outside the supplied dependency cache. Repeated runs need new
paths. Each Cargo invocation has a 30-minute deadline by default; use
`--timeout-seconds` to select 1–7200 seconds **per build**.

The tool runs the equivalent of this command for each distinct target directory:

```text
cargo build --locked --offline --frozen --release \
  --manifest-path <checkout>/Cargo.toml --target-dir <target-a-or-b> \
  -p trillionnium-owner-open-host \
  --bin trillionnium-owner-open-r5-host \
  --bin trillionnium-owner-open-r5-core
```

It supplies a finite recorded environment instead of inheriting shell flags or
credentials. The recipe sets `SOURCE_DATE_EPOCH` to the source commit timestamp,
UTC/C locale, one Cargo build job, and disabled incremental compilation. It
uses explicit compiler, linker, and archiver paths; removes the GNU linker
build ID; and remaps the checkout, target, private Cargo home, and shared cache
paths to common virtual paths. The two private Cargo homes expose only the
existing registry/Git cache directories through symlinks, not Cargo credentials
or configuration. The offline dependency cache is shared between the builds and
can receive ordinary Cargo cache metadata writes.

## Results and failure behavior

The JSON report includes the source commit/tree, commit timestamp, lockfile and
manifest identities, direct tool hashes and versions, platform and Rust sysroot,
verifier identity, complete build commands and environments, elapsed times,
raw-log identities, and both binary identities. Source and direct tool identities
are checked before and after each build. Reports and logs are created privately;
the report has a canonical JSON SHA-256 digest computed before adding the
`report_digest` field.

The build root retains both targets, both private Cargo homes, and the complete
combined Cargo output in `cargo-a.log` and `cargo-b.log`. Each log is bounded to
32 MiB. A timeout or logging bound stops the verifier's process group; any
partial raw log remains available for diagnosis. A missing cache dependency,
failed build, source/tool identity drift, missing/non-ELF artifact, or preflight
failure cannot produce a passing gate. No previous successful build is reused.

| Exit | Gate | Meaning |
| --- | --- | --- |
| `0` | `PASS_TWO_LOCAL_BUILDS_IDENTICAL` | Both successful local builds have matching Host and Core file sizes and SHA-256 digests. |
| `2` | `FAIL_ARTIFACT_DIFFERENCE` | Both builds finished, but at least one binary differs. |
| `2` | `FAIL_VERIFICATION` | A required input, build, identity, or artifact check failed. |

If the report path itself is invalid or already exists, the command exits `2`
without replacing it. Argument parsing failures also exit `2`.

## Scope of the evidence

This is a same-host source build check with a shared offline dependency cache.
The report records direct compiler/Cargo/linker/archiver bytes, not recursive
identities of the entire Rust sysroot, system linker dependencies, runtime
libraries, or dependency cache trees. Matching binaries and path remapping do
not establish a hermetic build, trusted dependencies, independent-builder
attestation, cross-host reproducibility, or reproducibility across toolchains.
No performance threshold is measured here; use the separate real product
baseline in `tools/perf` for that purpose.

## Contract tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools.tests.test_verify_host_reproducibility -v
```

These small tests check the fixed build recipe and failure gates, including
artifact differences, failed builds, missing hashes/artifacts, source/tool
identity changes, dirty or moved source, ambient configuration, and a wrong
toolchain. They do not execute Cargo or substitute for a real dual-build report.
