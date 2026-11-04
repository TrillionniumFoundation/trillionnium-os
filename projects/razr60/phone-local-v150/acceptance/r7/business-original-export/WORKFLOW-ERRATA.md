# Workflow erratum: business capture already exports

This note corrects the execution sequence in the sealed README. The sealed Python sources, README and source seal remain unchanged. This is a documentation correction, not a runtime or acceptance-rule change.

## Correct normal sequence

Use the same existing material, actual sender label and private output directory for these **three** phases:

```sh
python3 -B export_business_once.py preview --material <existing-r7-material> --sender-label <actual-label> --out <new-private-output>
python3 -B export_business_once.py capture --material <existing-r7-material> --sender-label <actual-label> --out <same-output> --execute-read-once
python3 -B export_business_once.py collect --material <existing-r7-material> --sender-label <actual-label> --out <same-output>
```

The capture phase calls export_originals(a) before returning. It already transfers the original archive in bounded chunks, verifies it, unpacks it and writes EXPORT-RESULT.json. A successful capture phase therefore advances directly to the host-only collect phase. Do not add an export command after a successful capture command.

## Separate export phase

The command-line export phase exists for an independently reviewed incomplete-transfer recovery. It is not a fourth normal step. Before using it, inspect the original capture/process result, retained chunk receipts, archive metadata and local files. An unknown capture must not be resubmitted or replaced with a fresh request. An existing originals.tar.gz is opened with O_EXCL and is deliberately not overwritten.

When all chunks already exist and match, a duplicate export reads those local chunks and then rejects the existing archive. That rejection does not replay the business task. It does not erase a completed capture and must not be confused with the original task's business outcome. Preserve the duplicate command's actual failure alongside the original successful capture; execute only the still-uncompleted collect phase after verifying the original export.

## Qualification is unchanged

Original capture actor and phone exits must both be integer zero, complete original evidence must be present, the actual collector process must exit zero, and all original business postconditions must hold. A successful transfer or collector process alone does not make the business task successful. Partial archives and original failure reports remain available for diagnosis.

Source reviewed: export_business_once.py, 27,792 bytes, SHA256 ae14894ce52be620da7672269e765f28687f101465c31c01dccab28af43e6a01. Historical README SHA256 997317f0e8d7bc6add12e1b6dac597255197a49fdc323eb6fd9c3519765650a8. Original source seal SHA256 39780446dea65a87baaa3531ed37d5a147e6a37b35152729a6726b0f146ccade. This erratum is separate from that immutable seal.
