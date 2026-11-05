# Owned output directory identity guard

This is a guard-only review candidate derived from checkpoint09 at commit
`a87b2fc4b99880e3820d2fffd285943777ac4057`. It preserves the frozen checkpoint and
does not dispatch the historical audit, modify its old output, or call the phone.

## Source change and preserved checks

The complete `audit_policy_history_once.py` changes one comparison in
`OwnedOutput.check`, from a fixed first-six-field prefix to the first five fields.
Three comment lines explain the distinction. `OWNED-DIRECTORY.patch` is the exact
diff; `SOURCE-SEAL.json` binds the 30,233-byte original and 30,473-byte candidate.

The fixed fields remain device, inode, complete type/permission mode, uid and gid.
Directory link count, size and timestamps can change when the owner creates its
declared output members. These changing counters are still compared in the
current held-versus-named full-nine-field check. The following checks remain
unchanged in the original complete source:

- The held directory and current canonical pathname must have equal full9.
- Directory entries must exactly equal the registered member set.
- Existing output leaves must retain their complete recorded full9; creation
  requires a regular file with one link and the exact written size.
- Complete output readback verifies bytes, SHA256 and held/named leaf metadata.
- Reopened parent chains and their full9 observations must still match.
- Private ownership/mode, no-follow opens, create-only publication, budgets,
  fixed production entry checks, historical pins and all failure paths remain.

The caller's existing `OwnedStore.check` already uses the same five-field fixed
directory identity. The candidate does not change that caller here.

## Actual Mac observation

A separately reviewed, bounded probe created exactly one new private directory
and one ordinary `INTENT.json` file. It only read metadata of the historical
evidence root to establish the same filesystem device. It did not enter the old
audit directory or invoke `verify_adoption`.

| Field | Empty directory | After its one declared file |
| --- | ---: | ---: |
| device | 16777233 | 16777233 |
| inode | 591657460 | 591657460 |
| mode | 16832 (`040700`) | 16832 (`040700`) |
| uid / gid | 501 / 0 | 501 / 0 |
| link count | 2 | 3 |
| directory size | 64 | 96 |

The current held/named full9 values matched in both observations. The directory's
mtime and ctime also changed; its first five fields stayed equal. The leaf was an
ordinary file with one link. The old first-six-field predicate evaluated false,
and the five-field predicate evaluated true with the exact `INTENT.json` member set.

The sole probe job was `1a1adfca913-fc05-5c66`, with idempotency key
`hepta-cp09-owned-dir-probe-acceptanceaudit-01-4b572de398a74ce0`. The controller
reported exit 0, durable complete output, 1,821 stdout bytes, zero stderr bytes,
both EOFs, no truncation and no timeout. The owned descriptors closed. Its new
directory and file remain at `/private/tmp/hepta-cp09-owned-dir-probe-4b572de398a74ce0`.
The exact command, script, raw controller records and original stdout are retained
under `evidence/`; the stdout SHA256 is
`ca9f9df8ff993ad3a2f3390d88a6a51a8a290783385d7432a9d97f035f3eb3af`.

This proves the platform mechanism that rejects a valid own-member creation.
The historical audit01 failed at its first check after writing INTENT and before
its readback: 60,466 physical bytes equals two complete 30,233-byte source reads.
Its retained checkpoint does not contain the failing directory's initial,
current-held, current-named or member-set operands. The exact historical failing
subpredicate therefore remains unproved; a new probe does not fill those old gaps.

## Complete-class regressions

Run from any working directory:

```sh
python3 -I -B tests/run_regressions.py --output /tmp/owned-output-guard-result.json
```

`--output` is optional; otherwise results go only to stdout. The full sealed
auditor module is imported. Tests instantiate its real `Budget` and
`OwnedOutput`, create and write actual files, call `check`, perform complete
readback, and verify descriptor cleanup. `module.OUT` alone is temporarily bound
to a new synthetic private directory and restored after each case. Production
`main`, the historical verifier and all phone paths are not called. No source pin,
entry condition or budget is removed to load the test.

The recorded Mac counter test derives its link-count increment from the retained
Mac observation and its current member count from real `os.listdir(fd)`, not
`self.members`. Only the directory counter is projected; all constructor, writes,
canonical-path operations and leaf checks run on real files. It exercises two
writes and readbacks and is explicitly labelled as a host projection, not an
actual Mac execution of the candidate.

Seventeen tests passed. They include real directory replacement, directory
symlink, permission change, extra/missing member, leaf hard link, same-byte leaf
replacement, leaf symlink and parent-chain changes. Additional targeted metadata
faults verify each of the five fixed fields and current held/named full9 equality.
The original local result is `evidence/LOCAL-GUARD-REGRESSIONS.json`. A separate
agent copied the frozen candidate and independently reran all 17 successfully.

## Deployment status

The guard-only source retains the old fixed entry paths and original historical
pins for a minimal review. Its production main is not a new audit02 entry.
Preparing audit02 requires a separate source/output namespace, a caller with the
real new auditor byte/hash pin, a new exact two-source manifest, independent
staging readback, review, and current same-family process observations. None of
those future actions is authorized by a self-reported source hash or by these
local test results. A successful future history audit still grants no phone
case credit, fresh nonce, lease, component or business qualification.


## Existing G1 discovery

The repository wrapper `tools/tests/test_razr60_owned_output_directory.py` invokes
this candidate regression runner in a temporary directory. It verifies all 17
cases, the complete auditor import and class exercise, unchanged source bytes,
and that production main, historical verification and phone access remain unused.
No workflow gate is changed. The separate independent review and rerun originals
are retained under `evidence/`.
