# Root operator: original visual and Unicode evidence on provider r6

This is a host-prepared read-only capture/export wrapper. It has not run on the phone. It generates no nonce or request, never registers or sends a task, and does not call a model, slot endpoint, sidecar health/inspect/execute, UI, or service-control operation. Only Root may invoke the phone phases.

The existing health gate, current frozen combination, original sender guard, one-use task contract, and fixed 19 protocol remain unchanged. Capture completeness is an evidence requirement; it is not a new business success definition.

## Inputs and fixed sources

The operator consumes one already-created material directory and the actual completed sender's label. Accepted cases are E2E-01 (visual) and E2E-02 (Unicode). It derives the original run and exact five-field scope from the original Pocket4 SEND-NATIVE-LATENCY.json, verifies the raw provider-start bytes retained by that observation, and independently finds the same unique owner request in the actual production provider evidence.

The frozen source binding is provider-r6 seal 26eb35e366cbc577408fe2662dc6c34d8a80f786bd46c584c43b5c9e2f7382a3. The production config 0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755 and service manifest ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2 are unchanged.

Business collection uses the original sealed collector 5719479507cd6f2366bb8848cb28a6f4a8d175a2ebc91332c77da2239b4fe899, native auditor da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf, and pure business reparser 0f9ccb8a9a29981af7eaca69624d00793d9e88bcfd5e1fbff71296a1c40bdfa6. The collector supports the existing explicit --source-seal and --source-seal-sha256 override. No frozen collector or production runtime source is changed.

The transport is the existing Root run_cycle03.py call_phone function, pinned 630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6, which verifies the original Pocket4 phone_once actor 179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22. Only its one explicit read request interface is used, with a new exclusive operation label for each capture/chunk. No component launcher, model HTTP kind, or sender is invoked.

## Exact commands after the actual business terminal

Set B150 to the existing Main project root. Set MATERIAL to the actual fresh material directory, LABEL to its actual sender label, and OUT to a new private directory under B150. These must refer to the already submitted task; do not generate replacement material for capture.

A local-only preview can be run after materialization:

    python3 -B "$B150/business-r6-original-export-r2/export_business_once.py" preview \
      --material "$MATERIAL" --sender-label "$LABEL" --out "$OUT"

Root's capture/export command is:

    python3 -B "$B150/business-r6-original-export-r2/export_business_once.py" capture \
      --material "$MATERIAL" --sender-label "$LABEL" --out "$OUT" \
      --execute-read-once

It makes one bounded original snapshot operation, then bounded read-only archive-chunk operations. It never reissues the capture. No phone installation of the three collector files is needed: the capture script is byte-pinned and passed through the existing Root GNU chroot execution path.

After export, collection is entirely on Main:

    python3 -B "$B150/business-r6-original-export-r2/export_business_once.py" collect \
      --material "$MATERIAL" --sender-label "$LABEL" --out "$OUT"

Use a different already-submitted material/label/new OUT for Unicode. The sender used for Unicode must be admitted against the actually verified visual terminal, not an older health. This operator does not generate a sender previous summary or write a fixed19 result.

## Captured original scope

The phone snapshot reads only the selected original production run and its bound state:

- The exact original provider-in/out, terminal, HTTP round records, model input images, semantic/dispatch/result files, task contract and outcome, and every other regular file in that same run.
- The exact accepted claim and the selected request's original task-contract template and consumed binding.
- Actual deployed provider-r6 seal, all 13 production Python source files, config, service manifest and client-r6 source. The API key path is not followed; no key or user draft file is opened.
- For every actual original tool.call: only its original r6 action directory, stdout/stderr, intent/receipt/pending, client claim/result/transport-r6 phase directory and matching action-ledger entries. Optional absent originals retain true ENOENT observations. Unknown or missing receipts are never converted into safe success.
- All native JSONL raw lines matching the complete five-field scope, with original offsets, line hashes and source segment hashes. They are not re-encoded. A filtered turn is not proof of the whole global journal.

The actual source root is /var/lib/trillionnium/owner-open/phone-local-v150/provider-r6/source. The production action journal is /var/lib/trillionnium/owner-open/phone-local-v150/executor-r6; no component or legacy sidecar journal is substituted.

A new private phone snapshot is created only under /var/lib/trillionnium/owner-open/phone-local-v150/business-original-captures-r6/<existing-task-nonce>. Existing directories/files are never overwritten. The resulting archive contains original bytes and a capture manifest; it does not contain weights, rootfs, full SELinux policy, unrelated claim contents or unrelated native record contents.

Every source read uses no-follow, single-link regular-file checks, bounded EOF reads and named identity rechecks. Directories and all read files are checked again after capture. This is a stable per-file snapshot, not an atomic whole-filesystem transaction.

## Bounds and uncertain transport results

Capture is limited to 768 originals / 64 MiB retained bytes / 128 MiB native scan. Phone capture has 50 seconds, finalization another 15 seconds, and the original phone command has a 75-second bound. Archive reads use 1 MiB chunks and an 8-second phone read bound; each request is at most 10 seconds.

The host capture-plus-export phase has an absolute 480-second bound. An explicit export-resume phase has 360 seconds, with no new chunk initiated after 300 seconds. Host collection has a 90-second child bound and 120-second phase bound. Root should allow 550 seconds for capture/export and 140 seconds for collection at the outer job layer.

Any uncertain call stops. The exclusive original operation label and request remain in Main/Pocket4; inspect that same operation before considering further read-only recovery. Never run capture again with another label, remove its directory, or make a new task for the old action.

An archive export interrupted after confirmed local chunks may be continued with the explicit export phase against the same material/label/OUT:

    python3 -B "$B150/business-r6-original-export-r2/export_business_once.py" export \
      --material "$MATERIAL" --sender-label "$LABEL" --out "$OUT" \
      --execute-read-once

This reuses the retained capture result and exact archive identity, verifies existing confirmed chunks, and only reads missing chunks. It does not recapture or execute an effect. If a missing local chunk has an uncertain existing phone operation, the exclusive request gate stops rather than sending it again; Root must inspect that original operation. A completed or partially unpacked archive is not automatically overwritten or restarted.

## Revision r2: retain real process terminals

The r1 sources and original 12 host checks remain unchanged at their original path. Root identified two missing process-exit conjunctions in that wrapper. This revision changes only the new operator path and those conjunctions; the phone capture and chunk source bytes are identical.

CAPTURE-TERMINAL.json preserves the actual original phone process return code and binds the retained operation bytes and original capture stdout hash. Export and collection independently read that original operation back. A phone capture exit other than integer zero prevents complete-original classification, while its partial archive may still be exported for diagnosis.

The final proof_complete and complete_business_success flags, and the successful host return, also require the actual frozen collector child to exit zero. The raw collector report, its raw success flags and the actual child return code are retained separately. A raw PASS report followed by a nonzero child exit cannot qualify the task.

Only one focused negative scenario was added: an actual synthetic host child emits raw PASS fields and exits nonzero; both collector-nonzero and recorded-capture-nonzero routes must remain nonqualifying. No old broad fixture suite, phone request or model call is repeated.

## Interpretation

The raw frozen collector REPORT.json is preserved. COLLECTOR-RESULT.json only permits complete_business_success when both the complete original capture/export and the unchanged collector's full proof/business gates pass. A partial capture keeps unconfirmed_original_capture even if copied subset data otherwise looks successful. Process exit0 alone is never the business result.

The original classifier preserves complete_success, partial, failed, cancelled and unconfirmed distinctions. A joined worker exit127 remains a failure. Client transport phase files are preserved for inspection; this wrapper does not add a claim that the existing collector independently audits every phase.

Read the full report and raw receipts before proceeding. Model-directed business UI effects remain distinct from HEPTA entry/input/Send/draft-restoration orchestration. This operator performs zero UI orchestration itself.

## Host validation and publication

The included focused synthetic host checks verify immutable reads, rejection of symlinks/path traversal/duplicate destinations, exact native/raw archive copies and the capture-completeness fence. They make zero phone/model calls and have no fixed19 qualification credit.

The reusable source and aggregate validation report can be reviewed separately. Actual requests, Unicode text, captures/screenshots, sender/draft records, live identities, private phase records and full source seals with instance recovery details are private original evidence; do not recursively publish output directories.
