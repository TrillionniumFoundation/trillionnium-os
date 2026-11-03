# RAZR phone-local provider v150 r2 — prompt source freeze

This isolated revision preserves v150 r1 and the common durable provider state. Its only behavior change is the model request layout. The original exact owner request is the text block of the final `role=user` message. Execution context and compact verified history are supplied in a separate preceding message; that history omits the duplicate owner request. The context carries the SHA256 of the exact owner UTF-8 bytes.

The current verified JPEG, when present, remains the only image attached to the final message. The system policy, JSON decision schema, typed tool mapper, allowed apps, screenshot/focus guards, one-use task contracts, action ledger, cancellation fences, HTTP worker and server-slot cleanup checks remain unchanged. The existing 24,576-byte prompt bound now explicitly includes policy + metadata + exact owner text. Limits remain 8 model rounds, 7 tool calls, 256 completion tokens, 120 seconds per model round and 300 seconds per turn.

## Evidence behind this change

The first real r1 native health task received its exact owner request. Its HTTP request SHA was `1ea9f03f8bf7f161fb9ff4f0e9e4b3c6a422c2876a58ee88ce6b0060366e526c`; the original request text SHA was `59f3b2485a3d7eb4ef3d3cb5041880efeef65daa03e484d3818ada0ec125dd32`. These are separate domains from the native TurnRequest envelope SHA.

The phone model returned HTTP 200 and finish_reason=stop in 8.101823955 seconds (601 prompt tokens, 73 completion tokens). It proposed an unrelated phone.open_app with invalid typed arguments despite the no-device instruction. Mapping rejected that decision before any native tool dispatch. The native turn ended provider_failed with zero tool effects. This is retained as a real instruction/argument failure, not reclassified as lost input or quota failure.

The r2 layout is an improvement hypothesis. The 16 host-only checks in `tests/prompt_layout_checks.py` validate exact owner bytes, separation, unchanged policy and limits, image cardinality, closed rejection on changed/multiple owner messages, and Python 3.12 syntax. They use the original health evidence as offline input without replaying the request or the proposed action. They do not establish model success.

## Source and deployment boundary

`PROMPT-SOURCE-SEAL-v150-r2.json` freezes all 11 runtime source files and both operator helpers. Only provider_phone_local.py changes behavior; daily_phone_local.py changes its child-source byte pin. `PROMPT-LAYOUT.diff` is the exact difference from r1.

The production config is now sealed against Root's r5 service-input manifest SHA256 a2fe45cff43f7270a43e4d0738ef921812cb534e66ae45fe7b33970612488362. Its SHA256 is 0e3b3e1448a45f7948501518441fc3b18b808c238958fe43860c54c8ef4b689d. local-config.phone.parent-r1.json remains only the old reference. The new production target is /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r2.json, with the API key path unchanged. This configuration seal does not claim live acceptance. The startup source target is /var/lib/trillionnium/owner-open/phone-local-v150/provider-r2/source/daily_phone_local.py.

Keep `/var/lib/trillionnium/owner-open/phone-local-v150/provider-state` and every existing claim, consumed contract binding and original action receipt. Never clear state to admit a reused nonce, stream, task or action. The bootstrap host_codex label remains compatibility metadata; actual residency must be demonstrated from the installed service/process evidence.

## Unicode executor prerequisite

The fixed UnicodeInput v148-r2 helper requires Android UID2000 before observation. Its effectiveText uses isShowingHintText: a displayed hint represents an empty editor, while a real draft equal to the hint string remains real text. The only helper command is set-text; '-' is the empty UTF-8 input sentinel. Expected '-' and replacement '-' can return already_exact without ACTION_SET_TEXT if the actual editor is empty; any different actual draft is rejected and preserved.

The root sidecar r4 cannot qualify this helper by directly executing it as UID0. Root is preparing r5 with a controlled child credential drop in the same owned PID/process group. Its raw execution, cancellation, join, process-group absence and Unicode public result must be validated independently. No guard is removed here.
