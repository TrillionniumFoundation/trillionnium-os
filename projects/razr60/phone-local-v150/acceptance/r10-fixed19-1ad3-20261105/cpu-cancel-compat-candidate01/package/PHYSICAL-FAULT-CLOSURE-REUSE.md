# Physical NEG04/NEG05/NEG07: exact reuse boundary and remaining inputs

The existing `signal_fault_once_r10.py` is a concrete physical fault actor. Its validated plan schema is `hepta.r10.signal-fault-plan.v1`; its only allowed cases are NEG04, NEG05 and NEG07. Its result `ONE_PIDFD_ACTION_RETURNED` explicitly has `physical_case_pass: false`. It proves one narrowly owned signal action, not the subsequent complete lifecycle.

The current-source host layer is separately executable and, when backed by the actual retained P4 proof, independently qualified. A host counter or its model fixture does not supply the physical layer.

## Reusable originals and logic

| Existing source | Reuse for fault closure | Restriction |
| --- | --- | --- |
| `negative_originals.py` | Bounded strict JSON, exact descriptors/full9 metadata, one-gzip regular-only complete archive, final readback, source/retained mapping, new repaired Root phase/capture verification | Its existing `assemble()` is NEG08/09-specific. Do not broaden its case list or bypass its final-dependency gate. |
| `ledger_prefix_negative.py` | Complete current-task intent-prefix reconstruction and preserved baseline/auxiliary checks | Preserve all original source, scope, before/after census and chain bindings. A selected native subset is insufficient. |
| `close_cpu_negative.complete_native`, `FrozenSnapshot`, effect/guard reconstruction | Full captured native WAL prefix, transport frame matching, source-backed read-only projections, no later task dispatch | Fault-specific expected terminals and original signal records must be explicit; `native_status == cancelled`, one Cancel and CPU eligibility are not fault evidence. |
| Existing current P4/phone collectors | Their exact actual raw file collection and archive binding machinery, if a separately reviewed fault plan/source adapts the supported case/schema and field set | Current CPU capture schemas, `actor_originals`, `negative-cancel-actor` and cancellation-specific records cannot be renamed to signal-fault records. |
| Original protocol `c573959e…` | The three exact contracts, limits and six metrics | No extra condition requiring an unknown effect to become success; known later facts remain separate from the earlier unknown wire outcome. |
| Current signal-fault package | Original `INTENT.json`, `PRE-SIGNAL.json`, action result/failure, process identity, held-pidfd fence and optional fresh public page read | Capture a complete original actor directory and final stability. The one-action receipt alone is not a closure. |

## Generation pins that a fault closure must freeze

Use the final **fault package** manifest and its exact eight runtime members, not the cancellation UI package's manifest/source set. The shared `active_runtime_r10.py` is the same finalized byte generation for both operators, but its manifest membership is different. Preserve `signal_fault_once_r10.py` and `observe_carrier_r10.py` actor logic, all pidfd-only controls, 30-second actor bound, 8/12-second CAS/read bounds, 262144-byte unpack bound, and the sub-65536-byte exclusive ADB envelope.

The final fault dependency template must identify the actual repaired Root source (seven-slot inverse to `50a5…`), signal-fault package, shared active source, runtime package, consumer, readiness, actual policy/adoption, original configuration `780754…`, service `2739…`, combination, original protocol, reviewed sender, fault-capable phone collector, fault-capable P4 collector and fault-specific closer. The currently read CPU four-source package does not supply the last three fault-specific source identities. They must be derived/reviewed and pinned before an actual fault plan is accepted. No future policy hash can be filled from an offline candidate.

## Required concrete plan and capture differences

The existing signal actor's exact plan already binds `operation_id`, fresh `nonce`, boot, exact owner bytes/hash, five-field current/previous scopes, original run, four READY role identities, release pins, runtime binding, app scope and task template. NEG04 has no probe or Android-helper action; NEG05/07 restrict the first action to an approved disposable probe. NEG05 additionally binds independently sampled stock shell/busybox bytes and a fresh read-only page observation. NEG07 binds the actual running r6 worker, original intent/receipt, worker domain/credentials and exact command.

A fault closure plan must retain that exact actor plan, complete actor original directory and exact outer Root phone execution phase, including the separate `OUTPUT-CAPTURE.json`. It must also retain the one original sender's intent/result/capture and whole natural-task archive, complete phone task/native/ledger/model originals, final selected identity and draft restoration, actual policy/boot/Enforcing/READY bookends, and all terminal or explicit unknown observations. No second Send, cancellation tap or unrelated service signal is part of this fault plan.

| Case | Actor input/phase | Required original closure behavior |
| --- | --- | --- |
| NEG04 | One held-pidfd SIGTERM to the exact carrier after consumed admission and before any native call; `calls == []`, no tool results | Complete original task/native prefixes show zero dispatch/effects; consumed semantic identity remains; no replacement stream request or effect; business false; an unobserved transport terminal stays unknown. Retain actual model/worker cleanup and restoration as separate facts. |
| NEG05 | One held-pidfd SIGTERM after the one original probe action starts and before its provider result; retain the actor's new public page read and the actual r6 running intent/receipt | Exact original action binding and full prefix bound effects to at most one. Original wire unknown is not rewritten by a later r6 receipt/public fact; no repeated semantic identity or further dispatch. Cleanup/state uncertainty remains explicit. |
| NEG07 | One held-pidfd SIGSTOP to the exact current r6 worker; the original r6 timeout owner handles the stopped child, without a follow-up CONT from the actor | Retain the actual original result deadline and timeout-owner process/receipt cleanup; no second effect. Capture a before-late terminal/unknown and provider-stream/claim fence, then the later original result/receipt separately and a final unchanged fence. A final archive alone cannot invent the missing before-late observation. |

The NEG07 before/after visibility fence is a **new required original observation**, not just a source pin. It must come from a bounded reviewed collector over the actual existing task and be retained as raw bytes with original full9 metadata and complete directory observations. The host fixture's `PRE-LATE-*` originals cannot stand in for it.

The physical fault closer must emit an explicitly separate `physical_native_task` receipt only after those original contracts and six metric groups verify. The old CPU closer's `qualification_receipt()` intentionally remains limited to actual CPU-eligible NEG08/09. The positive AC `KINDS` list remains unchanged. No fixture, phase intent, pidfd return or source-only template is labelled physical PASS here.
