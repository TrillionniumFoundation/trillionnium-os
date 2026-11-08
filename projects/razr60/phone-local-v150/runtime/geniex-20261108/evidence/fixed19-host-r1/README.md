# Fixed19 independent host attempt R1

This directory freezes the source and current execution status of a new, independent host-only attempt against the original `stock16-phone-local-fixed-set-r4` definition. It is not a replacement for the original acceptance ledger.

## Current result

**No fixed19 case has a confirmed result from this attempt.** Python source compilation passed locally. The remote `process_start`, directory inspection, job listing and same-key reconciliation all returned connector error `-32603: Internal error`. No job ID or terminal evidence was returned. The start outcome is unknown; the error does not establish that the command never ran.

The exact structured request is retained in the shared scratch file `fixed19_host_r1_process_request.json`; its SHA is recorded in `STATUS.json`. Any recovery must use that request and the original stable idempotency key. No new-key duplicate, reset of a claim, or replacement evidence directory is authorized by this record.

## What the runner covers

| Original ID | Implementation ready | Observed execution result | Remaining limit |
|---|---|---|---|
| NEG-10 | Four fresh identities and original screenshot guards | Unknown start outcome | Requires actual private-source execution |
| NEG-11 | Original parser with independently malformed synthetic envelopes | Unknown start outcome | Synthetic evidence remains explicitly labelled |
| NEG-12 | Original task contract, ledger, parser and failed business terminal | Unknown start outcome | Requires actual private-source execution |
| NEG-13 | Original one-time template race, wrong scope and reuse checks | Unknown start outcome | Requires actual private-source execution |
| NEG-14 | Rename, I/O, capacity and local fixture cleanup subset | Unknown start outcome | Retained orphan-spawn and whole worker/serve cleanup are not covered; no full PASS is possible from this implementation |
| NEG-04–09 | Not implemented by this runner | Not requested | Includes original HTTP lifecycle and disposable effect counters; NEG-04/05/07/08/09 also require separate physical follow-up |

The runner requires the actual private r9 source closure plus the explicit R3 profile overlay. It verifies the overlay, original source pins and pinned helper before executing. The local environment does not contain that full exact private closure; public r7 and old private files have not been substituted. The previously reported broker and private unit suites are separate evidence and are not counted as fixed19 cases.

Each selected case uses a fresh nonce and original durable owner admission, claims and validation where applicable. All synthetic receipts, counters and semantic fixtures remain labelled. No real phone, model inference, external provider or UI action is used. Production claims, ledgers and source are not edited.

`STATUS.json` contains the exact original host postconditions with null observed results, source hashes, counts and recovery constraints. `CONNECTOR-RESPONSES.json` preserves the four actual connector responses. `MANIFEST.json` binds this frozen record to the runner source.
