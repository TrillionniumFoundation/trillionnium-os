# Offline phone action candidate — 2026-11-08

This change addresses concrete failures in the phone-local controller: repeated
app launch, missing navigation gestures, and budgets too small for ordinary
multi-step instructions. It is a source candidate, not a claim of device
acceptance or a replacement for the installed r9 cancellation protocol.

## Behavior

- Hide all aliases of an app while a fresh trusted observation shows that app
  is already foreground. Permit returning to it after a verified transition to
  a different foreground, with a new execution-time page and viewport guard.
- Add typed `phone.swipe`, `phone.long_press`, `phone.back`, and `phone.home`.
  Each requires the current turn's current screenshot, validated coordinates
  where applicable, matching pixels, unlocked focus, and the qualified display.
  A successful input receipt does not prove the requested app outcome.
- Allow a confirmed action in a later genuine user turn, including a later turn
  in the same task as emitted by the installed UI. The new durable claim must
  bind the original `turn.start` UTF-8 bytes and identity. Reconnection, a new
  call ID, an invented hash, or a process-only inspection does not qualify.
  Unresolved UNKNOWN effects still inhibit mutations globally.
- Retain the existing executor wire protocol; the model cannot submit shell
  commands or arbitrary keycodes.

## Explicit ordinary-operation profile

Merge these fields into a complete, instance-bound private configuration:

```json
{
  "schema": "hepta.phone-local-provider.v150.2",
  "operation_profile": "daily-local-24-v1",
  "context_tokens": 8192,
  "max_prompt_bytes": 24576
}
```

This is a configuration excerpt, not an independently deployable config. The
existing endpoint, model, authentication-file reference, manifest, approved-app
registry, and executor bindings are still required.

| Bound | Existing/fixed contracts | `daily-local-24-v1` |
| --- | ---: | ---: |
| Tools | 7 | 24 |
| Model rounds, including final-only round | 8 | 25 |
| Total deadline | 300 s | 300 s |
| Per-model deadline ceiling | 120 s | 120 s |
| Cumulative encoded image bytes | 393,216 | 4,718,592 |

Model and executor deadlines are also bounded by the remaining task deadline.
The runtime records the chosen profile and validates actual `/slots` context
size. Historical fixed-contract budgets and evidence are unchanged.

## Validation

Run from the repository root:

```sh
python3 -m unittest discover -s projects/razr60/phone-local-v150/provider/r7/tests -v
python3 projects/razr60/phone-local-v150/client/r6/test_client_r6.py
```

The reviewed source snapshot passed 28 provider host tests and the original 61
client checks. The tests include the original duplicate-open failure, typed
gesture guards, original-result validation, real new user-turn admission,
tamper rejection, UNKNOWN inhibition, deadlines, image budgets, context size,
and preservation of fixed-contract behavior. These are host tests and must not
be counted as phone GUI or offline standalone acceptance.

## Deployment boundary

The public `retirement_recovery.py` is an instance-redacted projection. An actual
deployment must preserve the real instance bindings and regenerate explicit
source pins. Installed r9 adds `ledger_round_evidence.py`, `model_slot_cleanup.py`,
and additional phone tools; overwriting it wholesale with r7 would lose those
features. Merge and validate the actual private source separately.

The independent upstream OpenCL build under `runtime/opencl-20261108` does not
implement Hepta's request/slot/cancellation receipt extensions. Do not replace
the production model process with it merely because a GPU benchmark passes.
Device acceptance still requires valid local vision, cancellation and slot
cleanup, unlocked real app tasks, and observed operation without an external
model. No old UNKNOWN request may be replayed or rewritten as success.
