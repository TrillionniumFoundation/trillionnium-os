# RAZR60 audit02: actual host history reconciliation

The first owned audit failed after creating its intent because it treated the
owned directory's creation-time link count as immutable. The separately reviewed
directory fix now has an actual Mac execution result: audit02 called the original
policy adoption verifier once, rechecked all 554 verification originals, and
returned zero. Its owned caller obtained the original child wait result and both
stream EOFs. This closes the historical host reconciliation step; it does not
qualify a phone case or grant fresh phone clearance.

## Preserved preparation and actual execution

- `preparation/` is the frozen two-source mechanical cascade. Only the reviewed
  directory guard, three fixed output/source names, and dependent literal pins
  differ from the CP09 source. Historical verifier/adoption pins and budgets are
  preserved. The 24 local checks include the complete prepared auditor class.
- `staging/` is the frozen create-only source transport. It creates exactly one
  new private source directory and three pinned files. It retains partial failure
  outputs and never switches to a fresh suffix. The 25 local checks include real
  filesystem races, partial writes, source/name budgets, and interrupted FD
  acquisition/closure.
- `independent-readback/` contains the separate, read-only complete-byte/full9
  observer used after actual staging. It never imports or runs the staged code.
- `reports/` binds the actual results and independent reviews to their source and
  original-output hashes. Complete private controller originals and the original
  readset are retained separately.

Files named `NOT-EXECUTED` and preparation seals retain their original state at
preparation time. Their exact bytes were the reviewed requests subsequently used
for the distinct actual operations recorded below. No frozen preparation record
has been rewritten to imply it was originally an execution receipt.

| Actual operation | Durable job | Result |
| --- | --- | --- |
| Create-only staging | `1a1ae23a6b0-fc05-5db1` | Exit 0, 98,719-byte complete stdout, empty stderr; exactly the fixed source directory added |
| Independent full-byte/full9 readback | `1a1ae27645a-fc05-5dcc` | Exit 0; all three files equal the reviewed 85,649 bytes and retain the staged identities |
| Owned history audit | `1a1ae2ae6c3-fc05-5ddb` | Exit 0; child 44954 exited 0, original wait returned, both EOFs and reader join obtained |

The auditor ran for 8.530 seconds and read 64,571,299 bytes within its 67,108,864
byte ceiling. It verified 554 original descriptors representing 31,518,321 bytes,
with 332 distinct SHA-pinned bodies totaling 23,893,406 bytes. The readset includes
555 input paths and the actual Mac metadata bookends; it explicitly does not claim
all input FDs were held for the entire audit or that this was an atomic snapshot.

The source directory leaf identities and full9 metadata were independently
observed before execution. The caller then rechecked source bodies, source
metadata and its own output members. No policy was written, no phone process or
task was started, no nonce or lease was created, and no signal or automatic retry
was used. The old failed audit01 remains a failed original observation.

## Interrupted descriptor ownership

The stager review exposed another concrete failure-reporting defect: an alarm
could interrupt `open` before FD registration or `close` after registration was
removed, leaving a live descriptor while reporting all FDs closed. The final
source records an in-flight operation before the syscall, clears it only after
the ownership transition finishes, and retains uncertainty on any exception.
It does not retry an ambiguous numeric FD. Four fault cases cover `open`, single
close, bulk close and `scandir` acquisition; none reports false closure.

## Validation and scope

Ordinary `tools/tests` discovery includes
`test_razr60_policy_history_audit02.py`, which runs the complete preparation and
staging regression entry points on isolated local fixtures. It does not contact
the Mac or phone. The actual Mac outcomes above are separate from those tests.

The fixed 19-case qualification remains **0/19** at this checkpoint. In
particular, the original policy summary still says `service_start_admitted=false`,
and the audit result says `fresh_phone_clearance=false`. Current phone policy,
the final runtime/source binding, and the user's business/physical scenarios must
be verified in their own actual execution scopes.
