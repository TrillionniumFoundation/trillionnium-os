# r5 business evidence collector, revision 1

This independent host/GNU-chroot evidence tool adapts the frozen r4 collector to provider r5 and the dedicated r6 executor. It never sends a request, connects to a socket, inspects an executor through IPC, invokes a model, or reruns a phone tool. It writes only a new private output directory.

## Frozen inputs and narrow change

The runtime provider, client, policy, original receipts and fixed 19-case protocol are unchanged.

- Provider source seal: `f3685aadb004882a3f087e42d43d374bd24564ad56eb472cb638b2f88e96935f`.
- Production config: `0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755`.
- Phone service inputs: `ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2`.
- r6 client: `500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f`, deployed as `tool_client_r6.py`.
- Original collector: `623f0c2c6a93e585d494bb02b736808904938154d2c06e209e1155ada4b7f4eb`.
- Independent health collector remains `e79b4c01d653bc0ea6d752c6aa9a8541addce936d174c71f4e1eb69819901121`; use that version for HEALTH.

The diff changes the three default bindings, the exact r6 client path, and original r6 intent/claim/receipt validation. It requires the correct bootstrap, executor and worker contexts; shell UID/GID 2000 with no supplementary groups; the handshake after worker exec; one dispatch; matching original instance/time; joined child and absent process group. Missing intent/claim, a pending receipt or mismatched identity cannot establish a safe terminal. The terminal predicate is copied exactly from the frozen r5 runtime and checked by AST comparison.

The original native record hashes, exact raw streams, model requests and images, three-message business prompt, one-use contract, effect ledger and App postconditions remain unchanged. Reversing the compatibility substitutions recovers the old collector byte for byte.

## Result interpretation

A nonzero process exit can be a safely known terminal while remaining a failed execution. Component03 exit 127 is such a failure. Full business success still needs the original exit 0, matching native/raw execution evidence, genuine model terminal and cleanup, all declared App postconditions, exact Unicode or visual receipts, HEPTA return, and an entire-request contract. A summary string or an empty local directory proves none of those conditions.

The collector process exit code records whether collection raised an issue. It is not a business-success flag. Read `REPORT.json`: `proof_complete`, `complete_business_success`, `task_classification`, individual checks and issues must be reported accurately. A receipt phase chain is not independently re-audited by this revision; no such extra claim is made.

## Read-only use after an actual terminal

Use the matching full frozen combination and a fresh original request. Root alone may stage these three Python files and run the collector inside the existing GNU environment. The provider source path must be the frozen r5 source. The sidecar journal is the production `executor-r6` directory containing `actions/`, not the old sidecar or component-test journal.

```sh
/usr/bin/python3 -B "$COLLECTOR/collect_business_evidence.py" \
  --provider-state "$STATE/provider-state" \
  --run-dir "$ACTUAL_RUN" \
  --request-file "$FRESH_MATERIAL/request.txt" \
  --selected-scope-file "$ACTUAL_SCOPE" \
  --native-journal /var/lib/trillionnium/owner-open/turn-events.jsonl.segments \
  --sidecar-journal "$STATE/executor-r6" \
  --client-receipts "$STATE/client-receipts" \
  --source-seal "$STATE/provider-r5/SOURCE-SEAL-v150-r5.json" \
  --source-seal-sha256 f3685aadb004882a3f087e42d43d374bd24564ad56eb472cb638b2f88e96935f \
  --provider-source "$STATE/provider-r5/source" \
  --config-file "$STATE/local-config-r5.json" \
  --service-manifest "$STATE/PHONE-SERVICE-INPUTS-v150-r3.json" \
  --nonce "$FRESH_NONCE" --case-id "$CASE_ID" --out "$NEW_PRIVATE_OUTPUT"
```

Here `STATE=/var/lib/trillionnium/owner-open/phone-local-v150`; `CASE_ID` is E2E-01 or E2E-02. `ACTUAL_SCOPE` contains exactly the five fields from the accepted provider/native turn, optionally under `scope`. Obtain it from the original sender/accepted claim, never from guessed task identifiers. `ACTUAL_RUN` retains the original run basename. Do not reuse a health, component or prior business scope.

The same command may run on a host against exact read-only copies with corresponding path arguments. Raw native JSONL lines must be copied without re-encoding. The collector stores the original bytes it consumed under `raw/`, indexed by SHA-256; derivations are separate. Preserve the entire new output directory and its REPORT, original request/postconditions/material/combination, and the original sender timing and restoration receipts. Keep raw evidence private.

## Validation and limits

Sixteen focused synthetic checks passed on the host with a real successful, durable job terminal and empty stderr. They exercise the newly changed r6 boundaries and reverse-source equality. The independent integration review found no mandatory changes. This is evidence-tool validation, not a new phone/model request, fixed19 result, daily-use qualification or proof that the next module starts.

`ROOT-BUSINESS-ROUTE.md` is an operator plan. Its commands must not be executed before Root has the new module combination and a fresh successful health terminal. No nonce or task was generated while preparing this package.
