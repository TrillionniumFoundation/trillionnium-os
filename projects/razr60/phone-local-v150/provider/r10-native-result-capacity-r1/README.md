# Native-result and evidence-capacity candidate

This directory contains a new source candidate and local synthetic regressions.
It does not update frozen acceptance inputs, install a provider, or qualify the
fixed 19-case phone/model combination.

## Provenance and changes

The baseline is the complete 15-file checkpoint08 provider source recovered from
commit `cd156bebb6b883497877f17821738d0a9bf3e774`:

`projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/checkpoint08/archive/COMPLETED-WORK.tar.xz`

Archive member prefix:

`actual_epoch_material_generation01/output-readback01/originals/provider/source/`

`SOURCE-SEAL.json` lists every baseline and candidate byte digest. Thirteen source
files are byte-for-byte unchanged. The two substantive changes are:

- `phone_observation_tools.py`: successful native results must contain
  `accepted, started, output*, terminal` in that order. Both terminal copies use
  the same strict success validator; booleans/floats cannot stand in for integer
  exit codes or byte counts, and numeric zero cannot stand in for boolean
  `output_truncated=false`. Missing event kinds reject through `ProviderError`.
  Zero-output and multiple-output successful sequences remain accepted.
- `daily_phone_local.py`: the capacity scanner pins enumerated recognized
  temporary files with open descriptors, checks the surviving canonical file
  against that identity, and counts a stable bounded scan. The existing daily
  atomic record and replacement writers coordinate creation/rename with snapshot
  acquisition. The dependency pin for the changed observation module is updated.

No deployment config, service manifest, device payload, model weight, executor
client or private credential is included as a deployable configuration here.

## Exact rename handling

The scanner records `DirEntry.inode()` and the parent device, then opens each
recognized temporary without following symlinks while its own writers cannot
rename that entry. It retains the descriptor until the directory scan completes;
an unlinked inode therefore cannot be recycled to satisfy the rename check.

After a temporary disappears, its canonical target must be a regular file with
one link and the same identity as the still-open temporary descriptor. A direct
unlink, absent target, unrelated old canonical, replacement inode, symlink or
hard link rejects. A missing path without a captured identity also rejects.
Temporary/canonical aliases are normalized only while that exact identity is
still pinned; equal inode numbers at unrelated paths are not silently deduplicated.

A proven rename invalidates that scan's totals. A fresh scan removes any count of
an overwritten old canonical and counts the surviving target once. Changes in
the daemon's atomic-writer generation, or an active writer, likewise prevent
committing the pass. Continuous competition rejects after three attempts.

The total traversal budget is 200,000 entries, including directories and empty
directories. Each directory snapshot receives the remaining shared budget before
enumeration. At most 256 temporary descriptors may be pinned for one directory;
partial acquisition and all error paths close their descriptors. The original
byte reservation, file-count gate and free-space reserve in `serve` remain.

The shared lock covers metadata enumeration and the writers' create/rename
primitives. Data writes, fsync, network operations and process waits are outside
it. The daily callback covers inherited adapter/PhoneTools atomic records. The
HTTP worker, ledger and cleanup observer use their existing exclusive direct
writes; this process-local lock is not represented as cross-process filesystem
snapshot protection. An uncoordinated disappearance before its identity can be
pinned fails closed.

## Regression entry point

On Linux with Python 3.12 or later:

```sh
python3 -I -B tests/run_regressions.py --output /tmp/native-capacity-result.json
```

The working directory may be outside this candidate. `--output` is optional;
without it the only persistent output is JSON on stdout. All case files, sparse
capacity fixtures, synthetic keys and process receipts live in a disposable
temporary directory. Bytecode writing is disabled. Exit status is zero only for
a passing suite.

For a reproducible before/after comparison, supply the exact recovered baseline:

```sh
python3 -I -B tests/run_regressions.py \
  --baseline-source /absolute/path/to/checkpoint08/provider/source \
  --output /tmp/native-capacity-before-after.json
```

The harness verifies all 15 source files against the appropriate seal, then
imports the real `daily_phone_local` module and executes its dependency checks.
It never removes or bypasses `PARENTS`, extracts the implementation through AST,
or treats a stub as the production scanner.

The retained r7-r3 host runner functions are extended directly:

- NEG10 retains the original image budget and binding negatives.
- NEG11 keeps the original corruption tests and adds nine lifecycle/type
  counterexamples. Each mutation exercises native parsing and valid synthetic
  screenshot/text/return/input payloads. A separate audit uses actual
  `PhoneTools.map` and `prepare` with Chinese, emoji and a literal newline.
- NEG12 and NEG13 retain their original partial-completion and one-use-contract
  admission cases.
- NEG14 retains the original rename, missing canonical, EACCES, orphan-spawn,
  sparse capacity and cleanup cases. Added cases cover deletion, stale canonical,
  target replacement, links, identity changes before open, rename before/after
  counting, cross-directory entry limits, descriptor limits, bounded repeated
  renames, both actual daily writer callbacks and fsync lock independence.

Race injection schedules real filesystem operations around the actual scanner;
it does not manufacture successful stat results. The service tests invoke the
real `serve` entry and its capacity function in owned subprocesses with synthetic
arguments. They do not invoke the deployment configuration loader or install its
fixed-path executor dependency. That limitation is explicit in the result JSON.

The harness runs inside the existing host/container environment and does not
claim to create a new namespace. For the real EACCES test, a fully privileged
root run delegates the disposable service tree to an unprivileged UID; a root
process already lacking DAC override capabilities can run it directly. Each
owned service process is waited, its process group is independently checked
absent, and descriptor/thread baselines are verified.

## Observed result on the final source seal

The complete local run passed five retained case functions with 383 assertions:

| Case | Assertions | Result |
| --- | ---: | --- |
| NEG10 | 16 | PASS |
| NEG11 | 251 | PASS |
| NEG12 | 28 | PASS |
| NEG13 | 17 | PASS |
| NEG14 | 71 | PASS |

The baseline admitted eight malformed native envelopes as verified text facts;
the candidate rejects all eight. A missing event kind changes from `KeyError`
to the intended `ProviderError`. The valid mapped Unicode input still admits
one fact. The baseline tolerated both unlink variants and returned no size for
a valid rename; the candidate rejects unlink and counts the surviving renamed
record's bytes. These are local regression observations, not phone business
samples or closure of installed lifecycle gates.


## Independent review and CI discovery

The frozen final source was independently reviewed with 12 tests, all passing.
`qualification/independent-review-final-results.json` records the exact 15 source
hashes, 24 lifecycle permutations, 29 terminal/event mutations, real rename and
unlink schedules, descriptor and traversal limits, and writer-lock behavior.
The final alias-timing regression also failed against the preceding candidate;
`temporary-rename-baseline-proof.json` preserves that observation. This is a
separate implementation review, not an approval by a GitHub reviewer.

`qualification/host-regression-result.json` retains the complete before/after
regression run: five cases, 383 assertions, and 2.064 seconds on the local Linux
host. No real model request, phone call, or native dispatch occurred. The service
checks call the actual `serve` function with synthetic arguments; the deployment
configuration loader is not exercised.

The existing G1 workflow discovers
`tools/tests/test_razr60_native_result_capacity.py`. It executes the candidate
runner in a subprocess with a temporary working/output directory. The targeted
CI discovery test passed locally in 2.316 seconds; the candidate remained byte
identical, and no Python bytecode files were written. This local check is not a
claim that all repository CI checks have passed. No workflow gate is changed.

To repeat the independent review without writing into the checkout, copy
`qualification/review_candidate_final.py` into a temporary directory and run it
with the absolute candidate `source/` path as its first argument. It writes its
result JSON beside the copied script. The primary regression runner already
keeps all transient writes outside the checkout.

## Publication and adoption boundary

The publication parent is checkpoint09 commit
`a87b2fc4b99880e3820d2fffd285943777ac4057`. That commit only appends checkpoint09
materials to the source provenance commit; this repair preserves those materials
and does not modify any frozen checkpoint. The candidate source provenance
remains checkpoint08 at `cd156bebb6b883497877f17821738d0a9bf3e774`.

The current phone attempt must be reconciled through its original scope and
collector. A later runtime must bind this candidate into its full source,
service, helper, policy, configuration and device combination before any new
fixed19 qualification. A `provider_failed` terminal, host-only tests, and source
review do not provide whole-case credit. The fixed19 qualification flag here
remains false; this source package is not a deployed runtime.
