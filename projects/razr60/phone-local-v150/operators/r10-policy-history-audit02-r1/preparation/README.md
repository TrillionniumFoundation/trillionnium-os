# Policy history audit02: local preparation

This directory prepares a separate, fixed audit02 namespace for the reviewed
owned-directory guard correction. It is **not staged or executed**. The original
checkpoint09 and the guard-only candidate remain unchanged. No phone task is
dispatched, and this preparation does not establish current source or process
authority on the Mac.

## Exact source changes

The auditor begins with the independently reviewed guard-only source
`88d441ff38197993e4b0b08812f68c8729bd61f5a4c53027f5617a1187cbadf6`.
Only its fixed source and output paths change for audit02. The caller begins with
the complete checkpoint09 source
`0aa5342c32d28105b5229ad0f4128068f45ffc80c79498fa29c09cad6b96f4e1`.
Only its three source/output namespace constants and literal auditor byte/SHA256
pin change. `PREPARED-SOURCE.patch` shows the complete diff from checkpoint09,
including the already reviewed guard correction.

The source directory is the exact three-member set in `source/`: the auditor,
caller and `SOURCE-MANIFEST.json`. The manifest describes only the two source
files. Its actual hash is supplied in `process-start.NOT-EXECUTED.json`; the
caller separately checks the manifest, the actual source bodies, the auditor
literal pin, the complete source directory membership and final full9/body
bookends. The preparation seal records both old and new source descriptors.

The fixed tag is `02-dirguard-4b572de398a74ce0`. Under the existing Mac evidence
root, the three distinct target directory names are:

- `epoch-policy-history-audit-source-1ad3-02-dirguard-4b572de398a74ce0`
- `epoch-policy-history-audit-1ad3-02-dirguard-4b572de398a74ce0`
- `epoch-policy-history-audit-owned-1ad3-02-dirguard-4b572de398a74ce0`

Their absence has not been observed by this preparation. They must remain
create-only destinations. Existing outputs are retained and cause rejection;
there is no automatic suffix, replay or retry.

## Preserved work and bounds

All historical input paths and pins remain exact. The original 126,796-byte
verifier is still loaded by its fixed SHA256 and called once through
`verify_adoption` with complete original byte bodies. The 554 verification
originals and 555-path domain, original boot binding, expected summary and
callback coverage requirements are unchanged. Full reads and all final metadata
and byte bookends remain in place.

The auditor/child/caller/controller time limits remain 90/100/120/150 seconds.
The auditor retains its 32 MiB unique-body pool and 64 MiB physical-read pool;
its unchanged conservative complete-read forecast is 66,992,038 bytes, leaving
116,826 bytes within that bound. The longer names do not add path depth. Caller
read, metadata, capture and output limits also remain unchanged.

The caller still requires an actual child identity, wait and worker join, both
EOFs, complete retained streams, an exact successful output closure, source
bookends and the declared parent-directory transition. Existing parent identity
and closed-member-set checks are preserved. A concurrent writer may cause a real
failure; no global quiet interval is assumed.

## Local verification

From this preparation directory:

```sh
python3 -I -B tests/verify_preparation.py --output /tmp/audit02-preparation-result.json
```

`--output` is optional and defaults to stdout. The checker imports both complete
prepared sources without invoking their production entries. Reversing the
declared path/pin changes reconstructs each baseline byte for byte and reproduces
the independently known old SHA256 values. It checks the actual source manifest,
caller literal pin, fixed launch arguments, unchanged historical pins and budget
forecast.

The same 17 complete-class guard cases are then applied to the prepared auditor.
They use real private directories, files, readback and descriptor cleanup, plus
the explicitly labelled projection of the recorded Mac directory link-count
change. The copied test support is byte-identical to the reviewed guard runner;
its original `main` and loader are not invoked. No historical verifier, production
main, Mac process or phone call is made by these tests. The report cannot satisfy
the live preconditions below.

The retained local run passed all 24 cases in 0.139 seconds: seven preparation
closure checks and the 17 complete-class guard cases. Its original report is
`evidence/LOCAL-PREPARATION-REGRESSIONS.json`.

## Remaining execution prerequisites

The next owner must first check current same-family auditor/caller processes and
coordinate any existing successor. If a corrected auditor is already active,
provide these compatible reviewed inputs rather than launching a duplicate.

With that observation recorded, stage the exact three source files only into the
fixed new source directory, preserving private ownership, modes, ordinary
single-link leaves and canonical no-follow parent checks. Independently read
back complete bodies and full9 metadata, verify the exact manifest and source
hashes, and confirm the actual audit/caller output paths do not already exist.
Review must bind these observations and the concrete controller request; a
self-reported source hash is insufficient authority.

Only after those facts and review exist may the one prepared controller request
be issued. Its idempotency key has not been consumed by this work. Preserve all
controller request/start/status/read originals and the caller's exact child,
stream and join records. Any failure or unknown result remains evidence and
does not authorize an automatic second execution. A successful audit still
grants zero phone case credit, no fresh nonce or lease, and no component or
business qualification.
