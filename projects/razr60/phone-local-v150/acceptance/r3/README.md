# v150-r3 acceptance support

These helpers prepare fresh material and verify retained evidence. They do not submit a task, call a model, operate a phone, inspect a live sidecar, or replay an action. The production provider remains frozen.

## Frozen inputs

- Production source seal: `17a438628070a7fffd9d9c3f92221c00ca92134c3dd91532eb5008fe2cf30564`.
- Fixed 19-case protocol: `provider-r3/qa/fixed-acceptance-set.json`, SHA256 `2f7504ebb49a4441ae8736b055c82441ff7b82f74254ff7a329b10dd09e24a2f`.
- Service inputs: `PHONE-SERVICE-INPUTS-v150-r2.json`, SHA256 `a2fe45cff43f7270a43e4d0738ef921812cb534e66ae45fe7b33970612488362`.
- The runtime, model, executor, config and original claim pins remain in those manifests. These helpers never read the API key.

## Prepare fresh material

`materialize_case.py health|visual|unicode --out NEW_DIRECTORY` creates private, exclusive files. Unicode accepts `--text-file EXACT_UTF8_FILE`; otherwise it generates new mixed Unicode text with an independent random marker. A fresh 32-lowercase-hex nonce is generated unless Root supplies `--nonce`. Requests are not trimmed or given an added final newline. A directory cannot be reused.

Preparation is not registration or dispatch. Root registers health with the frozen `provider-r3/register_health_contract.py` using `--state`, `--request-file`, `--session-id`, `--profile-id` and `--nonce`. Business cases use `provider-r3/register_task_contract.py` and additionally `--postconditions-file` and `--coverage entire_request`. Root alone may register, send, operate the device, and collect the actual evidence.

Visual E2E-01 requires a fresh challenge and one screenshot-grounded tap. Before that tap, hierarchy/challenge-code reads are forbidden. After it, public challenge/receipt text must match, then HEPTA must be foreground. Unicode E2E-02 preserves exact bytes, requires editor and public readback plus public receipt, then HEPTA. All existing one-use, maximum-tool, maximum-round and no-replay guards remain active.

## Collect one selected turn

Keep `collect_turn_evidence.py`, `native_journal_audit.py` and `business_fact_recheck.py` in the same directory. Python 3.12+ standard library is sufficient. Use a new process and a new private output directory each time. Select the exact five fields: session_id, profile_id, task_id, turn_id and turn_stream_id.

```sh
/usr/bin/python3 -B HELPER_DIR/collect_turn_evidence.py \
  --provider-state STATEBASE/provider-state \
  --request-file EXACT_REQUEST_FILE \
  --selected-scope-file ACTUAL_SCOPE_JSON \
  --native-journal ACTUAL_RAW_JSONL_OR_SEGMENT_DIRECTORY \
  --sidecar-journal STATEBASE/sidecar \
  --client-receipts STATEBASE/client-receipts \
  --source-seal ACTUAL_SOURCE_SEAL_FILE \
  --source-seal-sha256 17a438628070a7fffd9d9c3f92221c00ca92134c3dd91532eb5008fe2cf30564 \
  --provider-source STATEBASE/provider-r3/source \
  --config-file STATEBASE/local-config-r3.json \
  --service-manifest ACTUAL_SERVICE_INPUTS_FILE \
  --nonce FRESH_NONCE --case-id HEALTH_OR_FIXED_CASE_ID --out NEW_OUTPUT_DIRECTORY
```

`STATEBASE` inside the existing GNU rootfs is `/var/lib/trillionnium/owner-open/phone-local-v150`. Actual installed seal and journal locations must be supplied by Root. A copied host snapshot is also supported with `--run-dir COPIED_ORIGINAL_RUN_BASENAME`; preserve the original claim, run, contract, ledger, sidecar and client evidence. `--native-journal` may be repeated. Supply original raw JSONL bytes, not a JSON wrapper around records.

The output includes `REPORT.json` and exact input bytes under `raw/<sha256>`. Per-file reads reject symlinks, hardlinks, changing files and oversized evidence; a final metadata check detects later changes. This is not a filesystem-wide atomic snapshot. An incomplete or inconsistent report remains unconfirmed. The report's fields determine qualification; process exit 0 alone is insufficient.

### What is independently checked

- Exact request UTF-8 bytes, original claim, selected full scope and provider sequences.
- Native payload and record hashes using the frozen Rust field ordering; selected turn sequences and supplied adjacent global links. Missing global records are not a complete journal-chain proof. Float payloads are not claimed verified because Python and Rust number serialization may differ.
- Every native tool's accepted/start/result identities, original raw stdout/stderr byte streams, terminal lengths, sidecar command/action receipt, client receipt and durable action ledger.
- Model HTTP request/response byte hashes, model identity, original owner text, actual current image bytes, terminal finish reason, one-attempt evidence, joined worker and observed idle slot.
- Business facts are re-parsed from original native receipts with byte-pinned frozen pure parsers into the new output directory. No command mapper or executor is invoked.

For r3 HEALTH, the one-use contract supplies the expected fresh nonce. The raw model summary must equal it, while the native/provider summary retains the existing `[无动作；业务未独立验证] ` prefix. These are separate checks. A health pass requires zero tools, one request and the actual native completed terminal. It is not business qualification.

Failure/cancel diagnostics can make native stderr differ from sidecar stderr; that difference is retained explicitly and never counted as complete success. A safe original execution terminal is separate from business success. Phone inference residency still requires independent actual process/service evidence. Unknown monetary cost, energy and native end-to-end latency remain unknown; cross-host clocks are not subtracted.

## Aggregate the fixed 19

`aggregate_protocol.py --protocol PROTOCOL_JSON --attempts ROOT_OWNED_ATTEMPTS_JSON --out NEW_REPORT_JSON` hashes supplied evidence, retains all 19 cases and separates model E2E, component, isolated host and physical native-task layers. The input is a JSON array with one object per attempt:

```json
{
  "attempt_id": "unique-attempt-id",
  "case_id": "E2E-01",
  "layer": "model_e2e",
  "protocol_result": "PASS",
  "task_outcome": "complete_success",
  "candidate_manifest_sha256": "17a438628070a7fffd9d9c3f92221c00ca92134c3dd91532eb5008fe2cf30564",
  "nonce": "fresh-nonce-from-this-attempt",
  "evidence": [{"path": "retained-evidence.json", "sha256": "EXACT_SHA256"}],
  "collector_report": {"path": "collector/REPORT.json", "sha256": "EXACT_SHA256"}
}
```

`protocol_result` is PASS/FAIL/BLOCKED/NOT_RUN. `task_outcome` is complete_success/partial/failed/cancelled/unconfirmed/not_run. Blocked or unrun cases need `reason` and `task_outcome=not_run`. Non-model PASS also needs explicit evidence-backed `assertions` objects containing exactly `name` and `passed: true`; the aggregator checks the references, while Root remains responsible for those semantic assertions. A model E2E PASS needs a matching collector report with `complete_business_success=true`.

Optional `recovery` records require status complete/partial/failed/unconfirmed, `original_action_receipt_read=true`, and `old_action_replayed=false`. Recovery is counted separately without changing the original terminal. Optional `resources` must reflect actual measurements, not inferred zeros. Historical combinations are excluded from current denominators.

NEG-04/05/07/08/09 need both the protocol's isolated layer and actual physical native-task evidence. Missing layers remain BLOCKED. Model quality denominators exclude health, direct component tests, isolated fixtures, blocked cases and historical runs. Latency quantiles are descriptive with explicit sample counts; unavailable usage/cost stays null. One 19-case suite cannot establish general daily reliability, so this helper never declares daily-use qualification.

## Verification and publication boundaries

`test_acceptance_support.py` performs bounded offline integrity checks with synthetic byte records plus retained historical native record hashes. It executes no synthetic shell command and grants no current phone, model or business qualification. The final support manifest records helper hashes and host-only validation outputs.

Publish only these helper sources, this README, their hash manifest and sanitized validation metadata. Actual requests, text, screenshots, raw tool streams, live claim contents, API-key files and private acceptance runs remain private.
