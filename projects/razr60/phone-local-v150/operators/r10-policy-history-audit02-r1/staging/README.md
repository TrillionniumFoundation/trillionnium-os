# Audit02 source staging: execution preparation

This package is a reviewable **unexecuted** create-only staging request. It is
separate from the frozen 12-file audit02 preparation and does not change that
package. The stager creates source data only; it never imports or executes the
three payload files, starts an auditor or subprocess, invokes the phone, or uses
the network. The staging idempotency key has not been consumed by this work.

## Exact inputs and request

`stage_sources_once.py` is the complete standard-library-only script.
`SOURCE-PAYLOAD.json` contains the three previously reviewed bodies as canonical
base64 data. The stager pins the complete 114,386-byte transport and each decoded
body, then verifies the exact source manifest. `SOURCE-PINS.json` records those
same source descriptors and the independent audit02 package inventory hash.

`process-start.NOT-EXECUTED.json` is the complete concrete controller request:

- Host `mac`, executable `/usr/bin/python3`, arguments `-I -B -c <complete script>`.
- The complete payload JSON is supplied on stdin; it is below 1 MiB.
- The existing Mac evidence root is the working directory.
- Controller timeout: 30 seconds.
- Unique staging key: `hepta-cp09-audit02-source-stage-dirguard-4b572de398a74ce0`.

The stager binds the three fixed child directories under the existing evidence
root. Before creating anything, all three must be absent according to no-follow
metadata and the complete initial BASE name list:

| Purpose | Fixed name |
| --- | --- |
| Source | `epoch-policy-history-audit-source-1ad3-02-dirguard-4b572de398a74ce0` |
| Auditor output | `epoch-policy-history-audit-1ad3-02-dirguard-4b572de398a74ce0` |
| Caller output | `epoch-policy-history-audit-owned-1ad3-02-dirguard-4b572de398a74ce0` |

Only the source directory is created. An existing directory, ordinary file,
symlink, dangling symlink or any other existing target causes rejection. The
stager does not delete, rename or adopt an existing path, and it never selects
another suffix.

## Identity, publication and readback

The script opens every parent from `/` using held directory descriptors and
no-follow opens. The actual Mac entry requires uid 501 and a private mode-0700
BASE. Each opened parent must agree with its current pathname in all nine
metadata fields. Parent depth and simultaneous owned descriptors are bounded.

The source directory is created once with mode 0700 and its parent is fsynced.
Each of the three source leaves is opened with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode
0600, and must be an ordinary single-link file. The held write descriptor and
named leaf must match before and after a complete bounded write and fsync.
The directory is fsynced after each file. Its exact member set is checked before
each subsequent write.

After closing each write descriptor, the stager independently opens and reads
the complete file, comparing its bytes and full9 metadata with the actual write
descriptor's recorded identity. This rejects even a same-byte replacement
between writing and the first read. Once all three leaves are complete, the
script reopens the entire canonical parent chain and source directory and reads
all three files again. Both complete readback records must agree. The stager
writes 85,649 source bytes and reads 171,298 source bytes on the valid path.

Every ordinary ancestor retains its original full9 metadata. BASE retains its
device, inode, complete mode, uid and gid; current held/named BASE full9 must
still agree. Its complete final names must equal its complete initial names plus
the sole declared source directory. Both output destinations must still be
absent. The source directory retains its first five identity fields during its
own member additions and its complete final full9 during the second readback.
Every completed source leaf retains full9 and one link. The receipt makes no
claim that BASE full9 stayed constant across the known directory addition.

## Complete names and resource bounds

BASE names are enumerated incrementally with `os.scandir(fd)`. Each observed
entry consumes the shared entry budget; the count and canonical UTF-8 JSON byte
charge are checked before appending its name. Oversized, nonreversible or
unexpected data fails closed. The script reserves room for the exact known
source-name addition before mkdir.

The receipt retains the complete before/after name lists using the previously
reviewed maximal-prefix/suffix encoding. Its rows are complete reversible data;
the accompanying byte count and digest verify that data. Both canonical expanded
name bytes and encoded name bytes are charged, together with the final receipt,
against one 512 KiB bound. The charge describes canonical data, not kernel dirent
bytes or an exact measurement of Python object memory. No name list is replaced
by a hash or truncated into an apparent complete snapshot.

| Resource | Bound |
| --- | ---: |
| Operation deadline / alarm | 18 seconds |
| Failure cleanup and receipt reservation | At most 1 additional second |
| Controller timeout | 30 seconds |
| stdin | 262,144 bytes; exact valid payload 114,386 |
| Decoded single source / combined bodies | 65,536 / 131,072 bytes |
| Actual source writes | At most 85,649 bytes |
| Physical source reads | 171,304 bytes, including six possible one-byte growth probes |
| Parent depth / simultaneous owned FDs | 24 / 64 |
| Complete BASE names per snapshot | 4,096 |
| Total observed directory entries | 8,256 |
| One basename, strict UTF-8 | 1,024 bytes |
| Canonical names + encoded names + receipt | 524,288 bytes |
| stdout receipt | 262,144 bytes |

An alarm cannot be swallowed as an ordinary `OSError` during descriptor cleanup.
Acquisition, ownership registration, close and scandir-context operations each
receive an in-flight marker before the syscall or bookkeeping transition. The
marker clears only after definite completion. Any asynchronous exception retains
the unresolved operation, so an empty descriptor list cannot falsely prove
closure. Unknown numeric descriptors are not blindly closed again.
A terminal failure retains partial files and reports the phase, observed names,
completed-file records, counters and cleanup errors available at that point.
There is no staging retry. A close error does not produce a false
`owned_fds_closed=true` claim. If terminal reporting itself cannot finish, the
controller's independent bounded completion and captured originals remain
necessary to classify the result.

## Local regressions

From this package directory:

```sh
python3 -I -B tests/run_regressions.py --output /tmp/stager-regressions.json
```

`--output` is optional; otherwise the report goes to stdout. The 25 cases passed
in 0.644 seconds. The complete stager module and exact pinned payload were loaded.
Tests rebind only BASE, its three child paths and expected uid to private local
fixtures, then restore them. They exercise the real staging code, writes, fsyncs,
both readback passes, name codec and descriptor cleanup. The original source and
payload remain unchanged.

Disposable fixtures live beneath the package's exclusive test directory and are
removed after each local test. An earlier shared-`/tmp` run correctly hit an
unrelated ancestor full9 change during parallel activity; its original report is
retained as `evidence/LOCAL-STAGER-REGRESSIONS-PARENT-RACE.json`. The production
ancestor guard was not changed or bypassed to resolve that test-environment race.

Cases include all three preexisting targets, a dangling target symlink, changed
transport, an unexpected BASE member, changed ancestor metadata, source
membership and mode changes, directory replacement, a leaf hard link, a same-byte
leaf replacement before first read, a real seven-byte partial write followed by
EIO, and count, byte, FD and deadline bounds. A separate local Python process
checks that the unmodified production entry rejects a non-Mac host before any
staging action; the stager itself starts no subprocess.
Four required interruption cases also inject an alarm before direct and bulk
close, after an actual open but before registration, and during scandir context
acquisition. They confirm that the alarm propagates and unresolved ownership
produces `owned_fds_closed=false`, including cases where the actual FD remains
open. Only the test harness closes its known synthetic descriptors afterward.

One local synthetic tree uses the complete retained cp09 set of 1,577 names plus
40 explicitly synthetic names. Its 1,617 → 1,618 transition is preserved exactly:
151,972 expanded bytes, 90,936 encoded bytes and a 96,797-byte receipt, totalling
339,705 charged bytes. This tests capacity with real retained name data; it is
not a current Mac namespace observation. The original local test report is
`evidence/LOCAL-STAGER-REGRESSIONS.json`.

## Execution gate and authority

Root and an independent reviewer must review this frozen script, the exact
payload, pins and complete request. Current same-family process observations and
coordination are supplied separately; this package does not assert that they
have been obtained or that the filesystem is globally quiet. The script keeps
strict source and parent checks and may reject a real concurrent change.

After any actual staging job, preserve its exact request, start, status and
complete stdout/stderr records. Root will then use a separate read operation to
obtain the complete two source bodies and manifest with their actual metadata,
verify the manifest and exact member set, and review them independently. The
stager's own descriptors or success message are insufficient authority to start
audit02. This package performs no audit, establishes no new epoch or lease and
grants no phone acceptance credit.

`evidence/BASELINE-STAGER.py.original` preserves the cp09 stage02 source used as
design reference. This new script is a separately reviewed implementation: it
adds all-three-target absence, incremental enumeration limits, write-descriptor
identity binding, tighter time limits, explicit failure retention and stronger
per-step identity checks. It is not presented as a mechanical rename of the
older script.
