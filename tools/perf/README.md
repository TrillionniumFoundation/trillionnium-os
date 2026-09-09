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
  2ab7c93fa12e88325e8d280782b043f0fe9c1af5e7597e15639f5c50836de8cc \
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
open discipline to every behavior-bearing Python source. Its closed implementation
manifest covers the launcher, authenticated facade, private core, Root Linux
supervisor and source broker. The broker workload executes a private script made
from the same admitted snapshot. The report additionally records the source
commit/tree, dirty tracked diff and untracked inputs, lockfile, Python and shell
identities. Changing any manifest member changes comparison identity; changing a
source path during a run fails it. A dirty but stable checkout is allowed unless
`--require-clean-source` is supplied. These identities do not attest that
caller-supplied binaries were built from that source; CI must retain the actual
build command, toolchain identity and build logs alongside the measurement.
`--build-profile` is the caller's declared Cargo profile, not ELF introspection.

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

## Comparison and CI decisions

Keep a reviewed baseline on a controlled performance runner, then use:

```sh
python3 -I -c "$TRILLIONNIUM_AUTHENTICATED_PYTHON_LOADER_V1" \
  "$PWD/tools/owner-open/authenticated_python_bootstrap.py" \
  cfa3971d8932c00525a616ba84d6e67be33a166b3d3ca01a6071743b68efaf96 \
  "$PWD/tools/perf/run_product_baseline.py" \
  tools/perf/run_product_baseline.py \
  2ab7c93fa12e88325e8d280782b043f0fe9c1af5e7597e15639f5c50836de8cc \
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
