# R6 bound01 recovery reconciliation

This is a read-only review of existing jobs. No phone command, retry, signal, installation, or remote write was performed.

## Result

- Earlier `recovery02-fresh`: Pocket4 job `1a1b33a7191-fc05-813f` exited 0, phone rc 0. Existing independent reader `1a1b33b9725-fc05-814c` exited 0 and reports `EXACT_UNSTARTED_RECOVERY_INDEPENDENTLY_VERIFIED_NO_CASE_CREDIT`.
- Its verified scope is 67 files, 9 directories, 76 ordered removals. All 14 original lock descriptors were closed; 67 file and 13 directory descriptors were closed; FD names returned to `0,1,2,3`. The complete 44-root baseline projection (3,823 entries, 44,353,573 file bytes) was preserved.
- Later separate `recovery02`: Pocket4 job `1a1b3426151-fc05-8186` host exit 0 wrapped phone rc 1. It is `PRE_MUTATION_REJECTED`: `exact staged home in actual private shared parent`. Zero effect attempts, zero file/directory removals, 14 locks released, FD baseline restored.
- The later reader `1a1b3456b55-fc05-81a2` exited 1 and correctly retained incomplete status. Host process exit 0 must not replace phone rc 1.

Both records remain valid within their individual scopes. The later rejection does not undo the earlier verified cleanup. Neither record grants NEG-01/NEG-02 or fixed19 credit, proves current owner/liveness, proves current continuous locks, or settles the separate Mac bound02 UNKNOWN job.

## Evidence and fidelity

`jobs/*.status.original.mcp.json` and `jobs/*.read.original.mcp.json` preserve the returned tool payloads. Metadata files are explicitly redacted: the private idempotency key and configured SSH target are removed. Original metadata hashes and versions remain in `EVIDENCE-DESCRIPTORS.json`. Integer-bearing original JSON text is preserved without parsing/re-serialization, avoiding timestamp precision loss.

Both public host-verification reports, the later phone recovery/preflight packets, and the earlier actual reader stdin source were read completely and saved with their original bytes. No private XML body, user draft body, credential, or secret key is included. `fresh-reader.stdin.original.py` was inspected, not executed.

The earlier 933,670-byte actor result was fingerprinted in full by `file_info`; its SHA256 matches the original reader binding. Only byte ranges 0–262144 and 868134–933670 were transferred during this review; the entire result was not re-imported or revalidated independently a second time. The historical complete reader execution and its report are reconciled here. Its report expressly records that the after inventory is a complete projection/hash, with no separate raw after-inventory file.

The later reader stdin retrieval did not complete; no claim of its source review is made. Current process liveness and new component admission remain separate work.
