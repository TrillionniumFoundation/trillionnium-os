# v149 GNU core independent rebuild addendum

This addendum supplements the frozen source commit
`029ec7e095865805d6e7e491c4ebabc17c3dee73`. The 344-file source archive and its
manifest remain unchanged. It records new work on the GNU **r5 core binary**;
it does not rebuild the complete 931-entry rootfs or deploy anything to a phone.

## Observed result

The final fresh build, **r5**, reproduced the entire retained GNU core ELF
**byte for byte**. Cargo compiled it in **33.772 seconds**, exited 0, and all three
QEMU fixtures passed. The 1,455-file source inventory was unchanged before and
after every attempt. No result was deployed.

| Attempt | Inner Cargo result | QEMU | Full ELF identity |
|---|---|---|---|
| r1 | Exit 101; missing locked `ryu-js 0.2.2` | Not run | No generated core |
| r2 | Exit 101; missing locked `serde_jcs 0.2.0` | Not run | No generated core |
| r3 | Exit 101; missing locked `thiserror 2.0.20` | Not run | No generated core |
| r4 | Exit 0; 40.569 seconds | 3/3 pass | Different from retained core |
| r5, original path namespace | Exit 0; 33.772 seconds | 3/3 pass | Exact retained SHA256 |

The r5 core is **2,757,408 bytes**, SHA256
`7046846404871ceffe1cc3241fc6aa2da6c281eb8832595dc26b283e307b4031`.
The complete measured tool-input manifest also matches the historical file,
SHA256 `f18f5c440de9dd33348a9fde2bd2699fbcbaf5d0707e1b11715598262ad28c2b`.
The r5 run began at **2026-11-03 11:25:46.523 UTC** and completed all gates at
**11:26:31.541 UTC**. Its durable job finished with exit code 0.

The preserved r4 core SHA256 is
`f77048cd4bf383b540b45cee500ff7b9a81f1d6f48b152f8fadfb833faaba3b6`.
The r4 and r5 receipts remain separate, including the earlier non-identical
result. Their source inventories are exactly equal. The r1–r3 summaries include
the hashes and locations of the complete retained failed-attempt receipts.

`CURRENT-ROOTFS-BINDING.json` confirms that the exact r5 core and all eight
measured runtime ELF inputs match entries in the frozen integration manifest for
the existing 931-entry image, SHA256
`5b17d4e356525e02ebd9354e74b4a5334678837ccc5a1895b3507eaa01264cda`.
This is a source/build/runtime-manifest binding; the image itself was not rebuilt.

The authoritative attempt outcomes, generated binary identity, exact historical
input comparison and QEMU results are in the receipts supplied with this
addendum. A failed attempt remains a failed attempt even if its outer job launcher
returned successfully. The inner Cargo status and the final driver receipt are
the relevant build results.

## Source and inputs

The source was exported again from the public Git commit
`4b687742fca939bc32122857f21067ec28d30a23`, then the four documented overlays were
applied with before/after SHA256 checks. The resulting source tree has **1,455
files**. The original 407-file source inventory matched, and all 24 Cargo
workspace members were present. Offline locked Cargo metadata resolved 24
packages without modifying Cargo.lock.

The build host is the configured Linux desktop. It retains the original Rust
**1.95.0** toolchain and AArch64 GNU target standard library, GNU **13.3** cross
compiler/sysroot, host GCC13, readelf and QEMU **8.2.2**. The source driver copies
the GNU inputs and target standard library into a fresh owned output directory.
After compilation it compares those complete inventories and the measured host
tools against the historical input manifest. A mismatch is a failed historical
input gate, not silently accepted as an exact reproduction.

Eight runtime ELF files were copied from the existing measured rootfs extraction
and checked against the historical public library manifest. There are seven
unique library basenames because the loader is present at two paths. Only the
new owned fixture loader copy receives execute permission. The original runtime
files and their modes remain untouched. The ELF runtime is Ubuntu GLIBC **2.39**;
the old directory name containing “bookworm” is not its actual runtime identity.

## Registry recovery and failed attempts

The original registry is mounted read-only. A new registry overlay borrows
existing index/cache/source material and owns any newly recovered archives or
unpacked sources. Three early offline attempts stopped at missing archives:
`ryu-js 0.2.2`, `serde_jcs 0.2.0`, and `thiserror 2.0.20`. These attempts did not
compile the core or execute QEMU; their source inventories remained unchanged.

The recovery acquired only five required Linux build archives from the official
`static.crates.io` URLs and verified every archive against the existing frozen
Cargo.lock checksum:

| Crate | Version | Bytes | SHA256 |
|---|---|---:|---|
| ryu-js | 0.2.2 | 47,497 | `6518fc26bced4d53678a22d6e423e9d8716377def84545fe328236e3af070e7f` |
| serde_jcs | 0.2.0 | 12,614 | `d3a60f3fda61525e439ef6d67422118f11e986566997d9021c56867ad814a0aa` |
| syn | 3.0.5 | 313,222 | `12df2e0110f65b775f769bb17ef989067a1d931b2eb822bd4346631eeada89f9` |
| thiserror | 2.0.20 | 28,969 | `ec86235f5fcc2a73650310756d2ac5b138a5780bbbdfae3eeccec992c435ba4f` |
| thiserror-impl | 2.0.20 | 21,436 | `bc04cd3e1236dd4a98afca4569f2deb3f120e5422a4023be2cb683f8486292af` |

The total downloaded archive size is **423,738 bytes**. Unrelated Windows, WASM
and EFI packages were not recovered. Two aliases in the owned source overlay
were removed to permit a fresh unpack of the verified thiserror archives; their
original global registry targets were not modified.

A separate offline, locked, network-isolated `cargo tree` check selected
`trillionnium-owner-open-host`, target `aarch64-unknown-linux-gnu`, and normal/build
edges. It returned a 103-line dependency graph with exit code 0 and no stderr.
This establishes the selected package graph/cache precondition; only the later
release compiler invocation establishes a fresh build.

The build receipt's `dependency_downloads: 0` refers to the isolated compiler
process. The five earlier, separately measured recovery downloads are explicitly
recorded above and in their own receipts.

## Reproduction procedure

1. Prepare the complete fixed source plus four overlays with the parent source
   archive's `backend/prepare_workspace.py`. Do not use its small historical
   `source7` intake directory as a standalone Cargo workspace.
2. Supply the exact GNU13/Rust1.95 inputs and the eight runtime files described
   in the input manifests. No compiler, standard-library or runtime binary is
   redistributed in this addendum.
3. Create a private Cargo registry overlay. Reuse existing verified registry
   content read-only; place any missing archives only in this owned overlay,
   after matching the frozen Cargo.lock checksums. The recovery receipts give
   exact official URLs and identities. Do not enable network access during the
   compiler invocation or modify the original registry to make it pass.
4. Run the driver in a new directory with the same isolation shown by the launch
   intent: read-only root, a single writable owned session directory, isolated
   namespaces/network, private `/tmp`, source outside the writable directory,
   and `--die-with-parent` so children cannot outlive the build.

The driver interface is:

```sh
python3 rebuild_gnu_core.py \
  --source /absolute/prepared/workspace \
  --out /absolute/new-session/build \
  --historical-builder /absolute/addendum/historical-build-script.py \
  --historical-inputs /absolute/addendum/inputs/historical-tool-inputs.json \
  --rust-toolchain /absolute/rust-1.95.0-toolchain \
  --runtime-libs /absolute/measured-public-libs
```

Set `CARGO_HOME` to the owned registry overlay for that subprocess. The driver
creates another private Cargo home and fresh target directory inside the output.
The original recipe supplies exactly the release command and link settings:

```sh
cargo build --release --frozen --locked --offline \
  --target aarch64-unknown-linux-gnu \
  -p trillionnium-owner-open-host \
  --bin trillionnium-owner-open-r5-core
```

The run uses four Cargo jobs/CPUs, an 8 GiB virtual-address-space limit inherited
by each child process, a 180-second Cargo timeout, and 15-second limits for each
QEMU fixture. It snapshots source before and after. The new driver preserves
the frozen historical builder bytes and executes only its compiler/link/ELF
portion after four checked path substitutions; its old runtime probes are
replaced by the corrected private-loader checks.

### Reproducing the recorded binary path identity

The relocated r4 build was valid but did not reproduce the historical bytes.
Read-only ELF section comparisons found eight differing sections, including
`.text` and `.rodata`. The read-only data contained the same 22 Cargo registry
source paths with a different absolute prefix: each r4 prefix was 46 bytes
shorter, a total of 1,012 bytes. Replacing only that exact prefix in the analysis
made every non-NUL byte match; the remaining difference was 12 NUL bytes of
alignment padding. No ELF was patched by this analysis.

The original builder, input manifest and embedded paths all identified the same
historical namespace:

```text
/home/qian-qi/Documents/Codex/2026-10-15/rog-moto-razr-60-ultra-p0/work/latecancel-source-review
  proposed-4b687742/                     # read-only source mount
  gnu-actual239-r1/cargo-home/           # fresh private Cargo home
  gnu-actual239-r1/target/               # fresh compiler output
```

The one final r5 attempt placed the verified source and a new owned output at
these names **only inside bubblewrap**. A private tmpfs hid the historical
Documents path inside that mount namespace; the actual writable output was
`/home/qian-qi/razr60-independent-gnu-session-v149-20261103/r5-canonical-base`.
The source was mounted read-only. The historical host directory was absent
before and after the run. The compiler recipe, source, tool bytes and flags were
unchanged, and no strip/patch/postprocessing step was introduced.

`receipts/r5/BUILD-LAUNCH-R5-INTENT.json` records the actual complete argument
vector and namespace mapping. `executed-launch-r5.py` is the exact one-shot
launcher used for this host-bound attempt; it refuses existing output and reads
the preserved r4 intent. It is an execution record, not a general installer.
To reproduce the exact retained bytes in a new run, use a fresh owned physical
output with the same recorded namespace, inputs, and driver arguments. Merely
relocating the Cargo home to an arbitrary path reproduces the r4 limitation.

`PATH-IDENTITY-ANALYSIS.json` records the measured path difference and final
whole-ELF equality. Restoring the recorded namespace was sufficient to close
the byte-identity gap. The r4 result remains in the evidence unchanged.

## Interpreting the result

The expected retained runtime core SHA256 is
`7046846404871ceffe1cc3241fc6aa2da6c281eb8832595dc26b283e307b4031`.
The receipt reports the newly generated SHA256 and the equality result
separately; a successful compilation alone must not be presented as bit identity.

The runtime checks establish that the generated AArch64 ELF's required symbol
versions are present in the eight exact runtime files. QEMU then checks help
startup and two fresh in-memory inactive cancellation fixtures. Both cancellation
fixtures must return `no_active_turn`, preserve broker correlation and state that
no cancellation was requested. They do not use a user session or model provider.

These are host build/ABI/QEMU results. They do not constitute a successful real
model task, a physical phone control test, a fresh r5-host rebuild, or a complete
rootfs reconstruction. No APK, Magisk module, device state, host service, firmware
or existing toolchain is changed by this work.
