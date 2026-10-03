# Host performance measurements

`run_product_baseline.py` measures the selected owner-open Host and Core
executables with real local processes, shell output, pipe/PTY jobs, event/job
stores, and the source broker. The provider is a small deterministic shell
fixture. It does not log in to Codex, contact a network or device, register an
MCP server, sign, install or publish anything.

`run_global_baseline.py` remains the schema/report probe used by the existing
G1 machine contracts. Its simulated workloads are not product measurements;
its old artifact cannot be used as this tool's `--previous` input.

## Build and run

Build outside the checkout so source qualification stays clean:

```sh
export CARGO_TARGET_DIR=/absolute/outside-checkout/cargo-target
cargo build --locked --release -p trillionnium-owner-open-host \
  --bin trillionnium-owner-open-r5-host --bin trillionnium-owner-open-r5-core

python3 -I -c "$TRILLIONNIUM_AUTHENTICATED_PYTHON_LOADER_V1" \
  "$PWD/tools/owner-open/authenticated_python_bootstrap.py" \
  cfa3971d8932c00525a616ba84d6e67be33a166b3d3ca01a6071743b68efaf96 \
  "$PWD/tools/perf/run_product_baseline.py" \
  tools/perf/run_product_baseline.py \
  69a0adb3006f76d22a0a2d4a44441de7f8d574b3729d55b17b0d6048fbb47d6a \
  -- \
  --host "$CARGO_TARGET_DIR/release/trillionnium-owner-open-r5-host" \
  --core "$CARGO_TARGET_DIR/release/trillionnium-owner-open-r5-core" \
  --build-profile release \
  --repetitions 10 --warmup 1 --require-clean-source \
  --output /absolute/outside-checkout/product-baseline.json
```


### Authenticated entrypoint boundary

`TRILLIONNIUM_AUTHENTICATED_PYTHON_LOADER_V1` is a separately reviewed,
operator-controlled inline `python -I -c` source value. It is the first trust
anchor and is not read from a mutable repository pathname. The inline loader
walks the bootstrap path from `/` with descriptor-relative `O_NOFOLLOW` opens,
checks the exact bootstrap digest above, and compiles those same captured bytes.
The bootstrap repeats that operation for the exact launcher digest and injects
an attestation before any launcher code executes.

The repository's canonical source-level loader implementation is exercised by
`tools/tests/authenticated_python_bootstrap_fixture.py`; copying that test file
by pathname is not an evidence-producing invocation. Production and controlled
performance runners must provision the reviewed inline source through their
protected configuration and retain the exact command bytes with the report.
Direct invocation such as `python3 tools/perf/run_product_baseline.py` fails
closed and cannot emit an admitted artifact. Any bootstrap, launcher, facade or
nested implementation change produces a new manifest and requires a new
baseline.

The output parent must exist; the output must not exist. The artifact is private
mode 0600. `--scratch-parent /controlled/filesystem` chooses the scratch storage
used for measured persistence; otherwise the system temporary directory is used.
Each sample gets a fresh private directory and reclaims it after measuring and
reaping its carriers. Existing event/job stores are never consumed.

Process ownership requires Linux `waitid(..., WNOWAIT)` and default
`SIGCHLD` disposition before spawning. The runner must be the exclusive reaper
of its direct children. Both product collection and broker startup retain their
original session leader through TERM/KILL, bounded membership observations and
final reaping, including when the leader exits before a descendant holding a
pipe. The authenticated facade preserves inherited execution descriptors and
uses the same cleanup implementation as the core. stdin is nonblocking and
shares the stdout/stderr selector deadline; a legal input larger than an
available pipe cannot block before the timeout loop starts.

Membership observations require a complete same-namespace `/proc` view, the
retained anchor, at most 131072 directory entries, 4096 bytes per process stat
and the cleanup phase deadline. Missing transient processes may disappear;
unreadable or invalid observations cannot produce successful cleanup. A partial
scan at the deadline triggers escalation or failure. Real fixtures cover a
leader exiting with held stdout, TERM refusal, output flooding, normal cleanup,
4096-byte stdin pipes with unread and fully delivered inputs, and isolated
`SIGCHLD=SIG_IGN` rejection. They verify exact descendant pidfds, final leader
reaping and descriptor counts. A real terminal-process fixture injects a reaper
error: pipes still close, the retained anchor remains available for reconciliation
and the error cannot become a successful sample. This does not prove cleanup of descendants that
escape their original session/group, defeat an external reaper, or provide a
hard bound on a kernel syscall stuck in uninterruptible I/O. Protected runner
and installed process-tree evidence remain separate requirements. These changes
also require a fresh implementation manifest and baseline.

Use explicit host/core paths. Before any workload, the tool opens each selected
Host, Core, Python and shell executable once, reads and hashes those admitted
bytes, and writes them to owner-only, single-link execution files in a private
custody directory. Workloads execute only those private copies. Replacing or
restoring an original pathname therefore cannot substitute different bytes for
the admitted executable; any source-path movement still fails the final report.

The public evidence-producing entrypoint is the separately authenticated
inline-loader → bootstrap → launcher chain. The launcher payload is deliberately
small and cannot be executed directly. It walks every
facade path component from the filesystem root with descriptor-relative opens and
`O_NOFOLLOW`, verifies a fixed facade SHA-256, compiles those same bytes, and only
then transfers control. The authenticated facade applies the same component-wise
open discipline to each registered repository Python source. Its closed implementation
manifest covers the launcher, authenticated facade, private core, Root Linux
supervisor and the broker entrypoint plus its ten transitive sibling sources.
The broker workload imports private copies of that complete captured closure.
Missing, changed, symlinked or additional custody files refuse startup; there is
no repository import path or `PYTHONPATH` fallback. The system Python standard
library remains an interpreter dependency; this repository manifest does not
independently attest that runtime. The same custody check runs before
reporting results. Adding these previously omitted broker sources changes the
implementation identity and requires a new baseline; older artifacts cannot
establish a comparison against this harness. The report additionally records the
source
commit/tree, dirty tracked diff and untracked inputs, lockfile, Python and shell
identities. Changing any manifest member changes comparison identity; changing a
source path during a run fails it. A dirty but stable checkout is allowed unless
`--require-clean-source` is supplied. These identities do not attest that
caller-supplied binaries were built from that source; CI must retain the actual
build command, toolchain identity and build logs alongside the measurement.
`--build-profile` is the caller's declared Cargo profile, not ELF introspection.

Storage comparison uses the actual scratch directory descriptor's mount ID,
device, filesystem ID/type/flags, boot and mount namespace. A bounded kernel
mount record binds the effective mount's root, source, options and overlay
backing paths by digest without publishing those paths or possible mount-source
credentials. Random scratch paths are excluded: ordinary directories on the
same mount remain comparable. Different mounts, options, filesystem identities,
boots or namespaces reject comparison. The native `fstatfs` layout is supported
only on Linux LP64 x86-64/aarch64; unsupported or incomplete observations are
recorded as unavailable and cannot supply a comparison pass.

The report's comparison identity must exactly project its environment,
configuration, Python/shell/harness digests, implementation/bootstrap/policy
digests and fixed execution custody. Repetitions and warmup counts are excluded
from configuration equality; each artifact still supplies all its declared raw
samples and comparisons require at least five measured samples per workload.
Host/Core subject bytes may change between candidates. Older artifacts without
the complete storage identity require a fresh baseline. These are start/end,
same-boot observations, not continuous storage monitoring or independent
physical-device provenance: device-mapper remapping, cloned filesystem IDs or
changes restored between snapshots still require an independent custodian and
controlled runner. Self-reported metadata and self-hashes grant no such authority.

## What is actually measured

| Workload | Measurement and correctness condition |
| --- | --- |
| `short_turn` | Fresh Host→Core→fixture provider→shell callback, durable store and exact returned bytes. Includes process startup. |
| `concurrent_turns` | Several independent sessions/stores started concurrently. Batch wall time and each session's raw timing. This is not a shared-core admission benchmark. |
| `large_output` | Default 256 KiB of real tool stdout through selected Host/Core; byte equality and successful, untruncated terminal required. |
| `slow_consumer` | Same real output, read in 4096-byte chunks with configurable pacing. Measures end-to-end delivery including client delay. It does not test the protocol's explicit zero-credit mode. |
| `pipe_job` | Real local pipe job, durable job journal, exact output and successful job terminal. Provider must remain unused. |
| `pty_job` | Same through an actual PTY. |
| `restart_replay` | Complete once, then start new Host/Core against the same store and exact turn bytes. Measures only the second process run. Event IDs must replay identically, with no second provider start or marker effect. This is clean-restart recovery, not crash or fsync-ambiguity qualification. |
| `broker_inspect` | Several authenticated Unix clients issue distinct absent-job inspections through one real broker/Host/Core. Exact expected missing-job errors and correct client/job ownership are required. Measures the first connect/authentication and concurrent request batch after descriptor publication. Upstream Host/Core startup and hello precede publication, but remaining broker worker startup may overlap the measurement. This is a negative read-only workload, not concurrent effect execution or a warmed steady-state benchmark. |

Each sample retains nanosecond wall time, operation count, exact output hashes
and byte counts, observed frame kinds/hashes and correctness results. Direct
Host sessions also retain client-observed frame timestamps; broker observations
currently have no per-frame timestamps. Client observation time does not identify
when the Host emitted a frame or separate producer work from reader scheduling.
Full output content is not retained. Concurrent session/client timings and replay
setup observations are retained separately; only the declared measurement phase
contributes to its workload summary. Throughput is completed operations divided
by the sum of measured batch wall times. Warmup samples are retained and excluded
from P50/P95/P99/min/max/standard-deviation and throughput summaries.

CPU/RSS, peak FD/thread/process counts, I/O/fsync counts, queue/lock wait,
fairness and unknown rate currently have `value: null`, `status: unavailable` and
an explanation. No missing measurement is replaced with zero or an ideal value.
Observed output/store byte counts are not disk-I/O amplification or fsync counts.

`collect_linux_resource_snapshot.py` records seven raw cgroup v2 counters:
CPU usage, charged current/peak memory, cumulative read/write bytes and
current/peak task counts. Run the observer outside a dedicated workload cgroup
while that cgroup still exists:

```sh
python3 tools/perf/collect_linux_resource_snapshot.py \
  --cgroup /sys/fs/cgroup/controlled-workload.service \
  --seconds 2 --require-all-cgroup-counters \
  --output /existing/private/resource-snapshot.json
```

The output must be new and its parent private. Descriptor-bound, bounded
sequential reads retain raw bytes, inode identities and explicit unavailable
values for the other 19 resources. Charged cgroup memory is not RSS, and kernel
task counts are not distinct process or per-process thread peaks. Cumulative
CPU/I/O is not a per-operation delta. The collector does not reset peaks,
establish workload/source identity, produce an atomic snapshot or supply L2
qualification. The caller must preserve the cgroup and independently bind its
placement and sample boundaries. Completion after the observation/publication
deadline returns failure even if the final file has become visible; preserve
that file for inspection instead of reusing its path as a successful sample.
Run the collector as a standalone observer and retain its actual process
termination. Regular counter and report files have native `FileIO` ownership;
cleanup retries the same object rather than a released descriptor number.
Directory traversal records both parent and child across closure, with one
close attempt per raw descriptor. A close exception can leave that attempt
unknown, so it never retries a possibly reused number. Abort the observer
then; the kernel retires its descriptor table on process exit. An interrupted
long-lived library caller has no descriptor-closure guarantee and must not be
reused for further observations.

## Comparison and CI decisions

Keep a reviewed baseline on a controlled performance runner, then use:

```sh
python3 -I -c "$TRILLIONNIUM_AUTHENTICATED_PYTHON_LOADER_V1" \
  "$PWD/tools/owner-open/authenticated_python_bootstrap.py" \
  cfa3971d8932c00525a616ba84d6e67be33a166b3d3ca01a6071743b68efaf96 \
  "$PWD/tools/perf/run_product_baseline.py" \
  tools/perf/run_product_baseline.py \
  69a0adb3006f76d22a0a2d4a44441de7f8d574b3729d55b17b0d6048fbb47d6a \
  -- \
  --host "$CARGO_TARGET_DIR/release/trillionnium-owner-open-r5-host" \
  --core "$CARGO_TARGET_DIR/release/trillionnium-owner-open-r5-core" \
  --build-profile release --repetitions 10 --warmup 1 \
  --require-clean-source --require-comparison \
  --previous /absolute/retained/product-baseline.json \
  --max-regression-percent 25 \
  --output /absolute/new/product-candidate.json
```

The previous artifact must have the correct schema/content digest, no correctness
failures, every configured raw sample and a summary exactly recomputable from
those samples. Duplicate keys, nonfinite values, duplicate/missing samples and
widened release claims are rejected. Content hashes are not independent
signatures; the runner/custodian must control which baseline is admitted.

Comparisons require the same machine-ID hash, kernel, CPU model/count/affinity/
governors, scratch filesystem type, Python/shell bytes, closed implementation
manifest, reviewed gate-policy version, build-profile label, workloads and
workload parameters. Binary and source identities may change
because those are the candidate under test. Hosted runners with different
machine identities are deliberately not comparable; do not disable this check
to reuse a convenient old green result. The tool does not control host load,
thermal state or storage topology, so run in a controlled environment and inspect
variance. Changing the harness requires a new baseline.

At least five measured repetitions per workload in both artifacts are needed.
The gate rejects any observed P50 or P95 increase beyond the reviewed policy's
fixed 25% threshold. `--max-regression-percent` remains only as a compatibility
input and must equal that policy value; a caller cannot weaken it. Any threshold
or metric change requires a separately reviewed source-policy change and a new
baseline identity. This is an explicit deterministic regression rule, not a claim of statistical
significance; nearest-rank P95 and P99 both equal the maximum with ten measured
samples and cannot establish a population percentile or product SLO. Select
repeat counts and the reviewed threshold before running on the actual runner;
retain failed comparisons rather than changing the threshold or selecting later
green runs. Changing instrumentation requires a new baseline identity.

| Gate | Exit behavior |
| --- | --- |
| `FAIL_CORRECTNESS` | Exit 2 even if timings improved. |
| `FAIL_REGRESSION` | Exit 2. |
| `INCOMPATIBLE_BASELINE` | Exit 2; no comparison pass. |
| `PASS_COMPARISON` | Exit 0, host-source comparison only. |
| `BASELINE_RECORDED_NO_COMPARISON` | Exit 0 for baseline capture; `passed=false`. With `--require-comparison`, exit 2. |
| `INSUFFICIENT_REPETITIONS` | `passed=false`; with `--require-comparison`, exit 2. |

A normal source CI can run a one-repetition smoke without a previous artifact
and retain the report, but it must label that as correctness/measurement smoke,
not a performance comparison pass. A separate controlled performance job uses
the comparison command. Both remain `L1_HOST_SOURCE_BENCHMARK_ONLY`; neither
promotes installed Root Linux, Android, physical-device, fault or release gaps.

## Tests

```sh
python3 -m unittest tools.tests.test_run_product_baseline -v

TRILLIONNIUM_PERF_HOST="$CARGO_TARGET_DIR/release/trillionnium-owner-open-r5-host" \
TRILLIONNIUM_PERF_CORE="$CARGO_TARGET_DIR/release/trillionnium-owner-open-r5-core" \
python3 -m unittest tools.tests.test_run_product_baseline -v
```

The first command tests artifact integrity, raw-summary consistency, the closed
implementation manifest, immutable gate policy, finite input bounds,
correctness-before-performance and no-overwrite behavior. It also performs
hostile parent- and final-component substitution tests proving that the launcher
never executes a facade under the wrong digest, imported Python executes only the
bytes read through its admitted descriptor, and Host/Core/Python/shell path swaps
cannot change the private bytes
actually executed or yield a passing source-selection check.
The second additionally exercises all eight workloads against the explicitly
provided real binaries. Missing environment variables produce an explicit skip
only for this optional integration test; the benchmark CLI cannot skip a selected
workload or silently replace a product executable with a mock.


## Controlled three-batch qualification

`performance_qualification.py` validates the retained comparison packet after
raw batch capture. The required order is `A1/A2/A3` for a same-binary baseline,
then `C1/C2/C3` for the candidate. Every batch contains WL-01 through WL-10,
both cold-start and steady-state phases, at least 50 raw repetitions, complete
stage/resource observation objects, an immutable environment/source identity
and a content digest. No outlier may be deleted.

```sh
python3 tools/perf/performance_qualification.py \
  --level L2_INSTALLED \
  --baseline /retained/A1.json --baseline /retained/A2.json --baseline /retained/A3.json \
  --candidate /retained/C1.json --candidate /retained/C2.json --candidate /retained/C3.json \
  --output /new/private/performance-qualification.json
```

The verifier refuses candidate comparison when either batch set is unstable.
The authoritative thresholds and sampling semantics come only from
`performance_qualification_policy_registry.v1.json`; every batch and report
binds the registry version and exact byte SHA-256, so a producer cannot widen a
tolerance in its payload. A separately recomputed work-contract SHA-256 binds
all workload-configuration digests and per-sample operation denominators across
A1/A2/A3 and C1/C2/C3. The gate covers median/P95/P99 latency, normalized
throughput, raw-derived unknown rate and fairness. An observed unknown-rate
counter must agree with the raw outcome bit, and L2 rejects any unknown outcome.
Inputs use nonblocking/no-follow descriptor acquisition and must be
singly-linked regular files before reads.

In L2 mode the verifier also rejects any unavailable applicable stage or core
resource. The L1 mode exists for hostile source fixtures and returns a
source-only status; it cannot promote installed, physical-device,
destructive-fault, signing or release evidence. WL-11 and WL-12 remain explicit
L4/L5 holds in every report.

Contract tests:

```sh
python3 -m unittest tools.tests.test_performance_qualification -v
```
