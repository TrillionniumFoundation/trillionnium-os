# Native executor component original verifier r1

This is a host-only verifier for the frozen component provider r3 and r6 client. It never connects to a phone, opens a socket, runs subprocesses, submits a task, contacts a model or changes a service. It reads exported original files and creates one new private report. Use the original bytes; never replace failed or incomplete records with reconstructed success records.

## Exact command

The input directory is a new private export assembled by Root after the actual scope is known. Resolve all directory paths to canonical real paths. The report parent must already exist; the output filename must be unused.

```sh
/opt/homebrew/opt/python@3.14/bin/python3.14 -B \
  "/operator-workspace/razr60/phone-local-v150/component-original-verifier-r1/verify_component_originals.py" \
  --request-file "/ABSOLUTE/NEW_EXPORT/request.txt" \
  --contract-file "/ABSOLUTE/NEW_EXPORT/contract.json" \
  --contract-sha256 "ROOT_SELECTED_RAW_CONTRACT_SHA256" \
  --scope-file "/ABSOLUTE/NEW_EXPORT/scope.json" \
  --component-root "/ABSOLUTE/NEW_EXPORT/component-root" \
  --executor-root "/ABSOLUTE/NEW_EXPORT/executor-root" \
  --native-records "/ABSOLUTE/NEW_EXPORT/native-records.json" \
  --provider-source "/operator-workspace/razr60/phone-local-v150/component-probe-r6-r3/component_probe_provider.py" \
  --client-source "/operator-workspace/razr60/phone-local-v150/client-r6/tool_client_r6.py" \
  --out "/ABSOLUTE/NEW_EXPORT/COMPONENT-INDEPENDENT-REPORT-01.json"
```

Exit 0 means this component's complete exported evidence passed the listed checks. Exit 2 means failed or incomplete independent verification. Missing files, malformed records, unknown effects, a native failed/cancelled terminal, an uncommitted receipt or incomplete transport phases remain failures; the checker does not repair or retry them.

## Export requirements

The machine-readable EXPORT-SPEC.json describes the fixed paths and placeholders. NONCE comes from the new contract. RUN comes from the original nonce claim's run_dir; ACTION comes from its action_id and is independently re-derived from the exact owner request, nonce and five-field scope. Never select the most recent unrelated run.

The component root is the exported counterpart of:
`/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6`

The executor root is the exported counterpart of:
`/data/trillionnium/owner-open/state/phone-local-v150/executor-r6-component-01`

Preserve the component's registered contract, one-use claim, service attempt, ready/health/service-ended records, selected evidence run, selected client claim/result and entire transport phase directory. Preserve failure, temporary and duplicate-inspection records if they exist. Preserve the executor action directory's original intent, receipt, stdout, stderr and any receipt.pending. The root-relative layout must match EXPORT-SPEC.json.

Every original file is copied byte for byte, including JSON whitespace and final newlines. Record source path, bytes, SHA-256 and original stat identity in the export's own inventory; obtain the source hash and destination hash separately. Keep binary output files binary. Do not print private request text or the user's preserved draft. All export directories and files should be private, and files must be regular, single-link, non-symlink files. A truncated connector response is not a complete export.

Export the original selected native WAL lines separately without changing bytes. The authoritative phone journal is `/data/trillionnium/owner-open/state/turn-events.jsonl.segments/*.jsonl`. Select by all five scope fields, in original store order; include every selected record from accepted through end. Derive native-records.json as an array of those parsed complete records only for the verifier. Keep the raw rows and their raw-byte hashes alongside it. A filtered turn does not establish unseen global WAL predecessors.

scope.json is exactly the actual session_id, profile_id, task_id, turn_id and turn_stream_id JSON object. It is not the human-readable ready.scope string. The owner's UTF8 request SHA and native request envelope SHA are separate values and must not be substituted for one another.

The checker needs actual service-ended-NONCE.json. A provider success claim before the service and native terminal are observed is insufficient. Do not start a replacement service to obtain missing evidence.

## Verified layers

The verifier binds the source bytes, raw contract and exact owner request; the original nonce claim and fixed printf command; one native shell.exec call with its accepted/started/terminal lifecycle; original executor intent, strict completed receipt and raw output; client one-use claim and all 15 durable transport phases; original provider outcome; and the actual native completed turn.

The r6 receipt must show the fixed executor instance, bootstrap peer, worker domain, shell UID/GID 2000 with cleared supplementary groups, dispatch_count 1, the verified worker-entry handshake, wait/join and process-group absence. Native exit 0 and unchanged raw streams are required separately. No SID or NNP receipt field is invented; those properties are enforced in the separately pinned runtime source.

The frozen native auditor verifies its original Rust-compatible payload and record hashes, turn/host sequence and selected frame identity. Native stdout/stderr must match the provider and executor original bytes. The original receipt's raw byte hash and the provider's canonical-JSON-plus-newline receipt hash are reported as distinct domains.

The client phase chain must show peer authentication before first send, exact request and response frames, the complete 15-phase progression and a matching original response. Missing or corrupted transport records cannot be treated as completed execution.

## Scope limits

A passing report grants only this native executor component result. business_qualified, daily_use_qualified and fixed19_case_credit remain false. The no-model statement covers this pinned component provider and its fixed stdout-only tool, not all traffic on the device. Operator task-entry UI and preservation/restoration of the user's draft are separate evidence.

The supplied contract pins offline policy inputs. The actual live policy's separate Root audit is not replaced by this checker. Effect-group cleanup is checked; parent/provider lease retirement remains a separate obligation. Input files are stable individually and rechecked at the end; no filesystem-wide atomic snapshot is claimed.

## Validation and provenance

The final verifier is 29,737 bytes, SHA-256 6955bb4c2aed3063a7e2af354aae44a871ea9868369af7dd3ee638792f902a6f. It uses the unchanged native_journal_audit.py, SHA-256 da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf.

Eleven focused host-only synthetic checks passed. The real host job exited 0 with complete durable output and no stderr. The first fixture draft had a wrong assertion about the number of report groups (9 instead of the actual 8); it was retained, then corrected in the test. No production verifier condition was relaxed for that assertion. Host checks do not grant physical component or fixed-19 credit.

An independent focused review checked the final source against the frozen provider, client, runtime and auditor. It confirmed the strict PID bounds and the 15 transport fences. See HOST-CHECKS-01.json, HOST-TEST-JOB-TERMINAL.json and FOCUSED-REVIEW.json. SOURCE-SEAL-component-original-verifier-r1.json pins this support bundle. No phone/model call was made while creating or testing it.
