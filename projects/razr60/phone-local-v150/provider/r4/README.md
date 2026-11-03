# Phone-local provider v150-r4

r4 fixes the observed r3 business-decision argument shape failure by constraining each typed operation before decoding. The r3 visual failure remains a real historical native provider_failed result with zero tool dispatches. r1/r2/r3 are retained without edits.

## Narrow change

`provider_phone_local.py` adds `business_decision_schema()` and uses it only for non-health model requests. `daily_phone_local.py` updates the corresponding source byte pin. All other production sources are unchanged. The original receive, emit, decision mapping, original-action inspection, durable ledger, cancellation, postconditions, text and screenshot guards remain in force.

The selected llama.cpp v0.8.0 parser compiles oneOf as a union. Every alternative is therefore a complete object with required fields, additionalProperties=false, and disjoint kind/tool constants; public read variants are also separated by exact tuple length. No shared properties are placed beside oneOf. Fixed heterogeneous arrays use prefixItems without items. The matching minItems/maxItems express that same exact length for standard JSON Schema validation; the pinned converter itself implements prefixItems as an exact tuple.

- Tool call kind, tool name, task_status and per-round call_id are constrained to their actual typed values.
- open_app admits exactly one of the approved registry aliases. Labels, package names and fuzzy corrections do not become aliases.
- All tools except input_text have an empty command. screenshot takes exactly ["0"], return_hepta exactly [].
- observe uses an approved package. input_text retains three typed string arguments and a freely generated Unicode command; requested text is never copied into the grammar.
- read_text admits one to five resource IDs. Before a visual contract has a verified selection, observe and read_text are omitted from the actionable schema; the original mapper guards remain. Verified selection restores public readback choices. The existing mapper still verifies uniqueness and the original observation/visual-read restrictions.
- tap is offered only for the current round's validated, unexpired image and is bound to that screenshot's call ID. Coordinates remain model-selected canonical strings from 0 through 1000. A contracted visual task cannot gain a second selection branch after a prior tap.
- Round 8 offers only a final decision. A final decision has no action fields and a legal completed/partial/failed/unknown status.

The existing r3 health contract is unchanged: one-use exact request/session/profile/nonce binding, final-only schema, ordinary free summary string followed by independent exact nonce validation, zero phone tools and sidecar inspections, one real HTTP request with joined worker and idle slot, and an independently required native completed terminal.

## Unchanged runtime and limits

Phone model endpoint remains 127.0.0.1:18087, model alias gui-owl-1.5-2b-phone-q4km, one inference slot, 1024 image tokens, 256 completion tokens, 7 tools / 8 rounds / 300 seconds per turn. r5 tool execution retains UID/GID2000 within its owned process group. The private config content and service input manifest are unchanged.

New source installation directory: /var/lib/trillionnium/owner-open/phone-local-v150/provider-r4/source

New configuration installation pathname: /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r4.json

Common state remains /var/lib/trillionnium/owner-open/phone-local-v150/provider-state. Preserve every consumed live claim, binding and original action receipt. The unchanged 17-item seed inventory never replaces the live inventory. No old request, text or ambiguous effect is retried.

## Verification and qualification

`tests/schema_shape_checks.py` is host-only. It checks the actual observed invalid open-app shape, strict aliases and empty commands, exact call IDs and array sizes, freely selected Unicode values, current-image binding and coordinate limits, final-round restrictions, unchanged source pins and unchanged health behavior. Its independent schema subset validator is not presented as proof of the phone converter; the pinned C++ conversion evidence is recorded separately.

These tests run no model, phone, shell action, sidecar, or production service. A structurally valid decision does not prove a correct visual choice, exact business result, HEPTA return or successful cancellation. Root must use new nonces, requests and once-only contracts for new native health/business qualification. Preserve all fixed 19 cases and their required layers; report real FAIL or BLOCKED without increasing budgets.

Source seals and private native reports have separate roles. Actual request text, screenshot content, API-key material and private live claim contents are excluded from public source publication.
