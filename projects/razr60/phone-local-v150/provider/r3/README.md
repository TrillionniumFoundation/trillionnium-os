# RAZR phone-local provider v150 r3

This isolated revision adds an operator-registered, one-use health contract to frozen r2. It does not change ordinary business tools or their budgets. R1/r2 source, attempted tasks and their outcomes remain intact.

## Hard health boundary

The private template binds the exact UTF-8 request SHA256, selected session/profile and one fresh nonce. The first admitted turn consumes it through an exclusive durable binding to the original semantic task/turn. Reusing the request with a replacement stream/task cannot authorize another attempt.

A bound health request uses a final-only JSON schema: turn.complete, tool=none, empty command/call_id/argv and task_status=completed. Summary is an ordinary string, with no const/enum/pattern containing the answer. The provider independently requires summary to equal the new nonce. Both model-decision mapping and native tool emission reject every tool call. Health also skips pending-action sidecar inspection.

Before requesting completion, the provider verifies exactly one HTTP attempt with HTTP200/stop, raw request/response hashes, the original exact owner request, the unforced summary schema, the returned decision, joined worker, absent worker process group and observed idle phone slot. Cancellation, output-budget exhaustion, wrong nonce or missing cleanup cannot pass. The native completed journal terminal must still be checked independently.

## Register without sending

Inside the existing GNU rootfs, use the operator helper:

```sh
/usr/bin/python3 -B /var/lib/trillionnium/owner-open/phone-local-v150/provider-r3/register_health_contract.py \
  --state /var/lib/trillionnium/owner-open/phone-local-v150/provider-state \
  --request-file /var/lib/trillionnium/owner-open/phone-local-v150/acceptance/health-03.request.txt \
  --session-id "$HEPTA_SELECTED_SESSION_ID" \
  --profile-id "$HEPTA_SELECTED_PROFILE_ID" \
  --nonce "$HEPTA_FRESH_HEALTH_NONCE"
```

Root must supply the actual selected session/profile and the nonce appearing exactly once in that fresh request. The staged request must be canonical, owned by the registering user and mode0600. The helper only registers files; it never sends the UI task or contacts the model.

Durable template and one-use binding paths are provider-state/health-contracts/templates/<request-sha>.json and provider-state/health-contracts/bindings/<request-sha>.json. Each accepted run retains health-contract.json and health-outcome.json alongside the original provider/native/HTTP evidence. provider_checks_passed is insufficient without the matching native completed terminal and zero tools.

## Frozen combination and state

The production entry is phone-local-v150/provider-r3/source/daily_phone_local.py with the separate local-config-r3.json. It uses the same Root-approved service inputs, r5 controlled UID/GID2000 child execution, local model and client as r2. Config bytes remain unchanged; its pathname is new. The common provider-state is preserved, including all 18 currently existing claims. The historical seed still contains exactly the same 17 entries; nothing is reseeded by deleting live state.

Limits remain 8 rounds/7 tools for ordinary business, 256 completion tokens, 120s per model round, 300s per turn, one worker and the same prompt/image bounds. A registered health request permits one model round and zero phone tools. This is a semantic admission rule, not an increase in budgets.

Thirty narrow host assertions cover exact request/scope binding, duplicate/concurrent consumption, independent nonce verification, both zero-dispatch fences, missing/invalid terminals, cancellation, unjoined workers, busy slots and unforced schema. Synthetic fixtures are not real model or phone acceptance. The unchanged fixed19 protocol remains required before expanding support claims.
