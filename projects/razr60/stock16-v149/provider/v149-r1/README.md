# HEPTA Stock Android 16 provider v149 candidate

This directory is a reviewable candidate derived from the exact deployed v148-r5 sources. It has not been installed or exercised against a real phone or model by the source author. Root owns deployment and real-device qualification. No APK, native binary, Unicode helper JAR, screenshot codec JAR, rootfs, bridge protocol, account or selected model is changed here.

## Changes and acceptance meaning

`model_health.py` classifies original CLI `error` and `turn.failed` events into usage limit, authentication, rate limit, request rejection, transport, timeout or unknown failure. The exact known disabled Code Mode item notice and the existing bounded same-process timeout diagnostics remain permitted. A quota failure reaches the existing `turn.fail.error` field as `[usage_limit_exceeded] 模型额度已用尽…`. Raw CLI events remain in the round evidence. No failure is automatically retried and no accepted identity is released.

`state/model-health.json` records the last observed availability separately from `ready.json`, whose scope is transport readiness. A successful request already in flight when a failure is observed cannot clear that failure. Only a later-started validated model decision can clear it. These observations do not predict the next request or prove task success. The service does not probe, change account or change model automatically.

The model's structured response adds `task_status`: `in_progress` for a tool call; `completed`, `partial`, `failed` or `unknown` for completion. This is the model/provider decision schema only. Native wire frames retain their existing fields. `partial`, `failed` and `unknown` use `turn.fail`. A trusted task contract that is not fully satisfied also uses `turn.fail`, so the current phone client receives a failure terminal instead of a successful completion label. All terminals retain a `business-outcome.json` sidecar. With no trusted contract, a model-completed flow has an explicit **业务未独立验证** summary and `business_verified=false`.

## Explicit phone operations

| Model tool | Arguments | Verification |
| --- | --- | --- |
| `phone.return_hepta` | Empty `command`, empty `argv` | Launches the fixed `org.trillionnium.owneropen/.OwnerOpenShellActivity` once. Captures `am` status immediately, requires the successful target in the launch receipt and the actual focused/resumed HEPTA activity on qualified display 0. Returning is explicit; completion never launches an activity automatically. |
| `phone.read_text` | Empty `command`; `argv=[package, view_id, ...]`, one to five unique public IDs | Takes one bounded `uiautomator` XML snapshot at a unique owned path. Requires stable before/after viewport and page focus, unique enabled non-password text nodes, matching package and valid inner-screen bounds. Original XML/native result hashes and exact UTF8 text hashes are retained. It does not read app-private files. |
| `phone.screenshot` | Existing `command=''`, `argv=['0']` | The unchanged codec JSON is enclosed with stable, qualified before/after page focus. The original native bytes remain intact. The actual JPEG is still attached only to the immediately following decision. |
| `phone.tap` | Existing `[screenshot_call_id, encoded_x, encoded_y]` | Requires the bound viewport and page focus, a newly captured PNG whose SHA256 exactly equals the decision's original PNG, then a second focus/viewport check before input. A mismatch exits before input. The image is consumed. |

Page parsing uses the **complete** `dumpsys window` output filtered to `Display: mDisplayId=…` sections, focus/app/keyguard fields and the global `mTopFocusedDisplayId`. The external display's `null` focus does not hide the inner display's actual focus. `dumpsys window windows` is insufficient on this device. `topResumedActivity` is checked separately.

The existing Unicode helper proves an editor's exact readback at the time of input. It does not prove submission or a business receipt. To qualify a confirm-and-read-back task, observe the app's public result after confirmation with `phone.read_text` and require its exact expected value in the task contract.

## Registering a real UI task before its turn ID exists

The service owns private `state/task-contracts/{templates,bindings}` directories. The operator may register one exact UTF8 request, with a fresh nonce appearing exactly once, for the currently known session and profile. The generated task/turn IDs are bound atomically at `turn.start`, after the durable semantic identity claim. A private `O_EXCL` binding record consumes that template permanently. A new turn or stream cannot consume it again. Templates and consumed bindings are retained, including after quota failure or cancellation. Do not delete a binding to retry an old request; a newly authorized task must use a fresh nonce.

Example registration command, with actual absolute paths and the real session/profile supplied by Root:

```sh
/opt/homebrew/opt/python@3.14/bin/python3.14 -B /ABSOLUTE/CANDIDATE/register_task_contract.py \
  --state '/Users/qianqi/Library/Application Support/HEPTA/provider/state/provider' \
  --request-file /ABSOLUTE/NEW_REQUEST.txt \
  --postconditions-file /ABSOLUTE/POSTCONDITIONS.json \
  --session-id ACTUAL_SESSION_ID \
  --profile-id ACTUAL_PROFILE_ID \
  --nonce ACTUAL_FRESH_NONCE_16_TO_64_CHARS \
  --coverage entire_request
```

This command performs no model or phone operation. Its request file must contain exactly the bytes that the UI sends, including any newline; do not append an unintended terminal newline. Unknown requests gain no contract. A matching template with an incorrect known scope is rejected before a model decision or phone dispatch. Files must be regular, single-link, owned by the operator and mode `0600`; directories must be canonical, owned and mode `0700`. Read identity is checked before and after reading. A symlink, changed file or duplicate JSON key is rejected.

For a known semantic identity, the operator can instead supply `task-contracts/<identity_key>.json` with schema `hepta.task-contract.v149.1`, the exact four-field `identity`, `request_sha256`, `coverage` and `postconditions`. `identity_key` is SHA256 of compact JSON `[session_id,profile_id,task_id,turn_id]`. Stream ID is retained as transport evidence but is not a new semantic identity.

`coverage=entire_request` is an operator assertion that the listed conditions cover the full requested task. A subset must use `declared_postconditions_only` (the registration helper's default). Even if that subset passes, it cannot set `business_verified=true` or emit a successful business completion. A task asking for more than “return to HEPTA” must not be qualified by a return-only contract.

## Supported postconditions

| Kind | Meaning |
| --- | --- |
| `foreground_hepta` | The last tool result independently confirms actual HEPTA focus/resumption on qualified display 0. Later unrelated tool results make an older foreground receipt insufficient. |
| `text_readback_exact` | The focused Unicode helper observed the exact expected UTF8 hash in an editor at input time. This does not prove confirmation or persistence. |
| `public_text_exact` | A unique public view in a focused app was independently read from UI XML and its exact UTF8 hash matches. A later observation of that same view supersedes an older one. |
| `visual_receipt_matches_challenge` | After a confirmed screenshot-bound typed tap, one public UI snapshot contains both the challenge and result. The challenge must be its literal trusted prefix plus exactly one eight-character uppercase hexadecimal code. The receipt must equal its literal trusted prefix plus that same code. A later mismatched pair supersedes an older match. |

The actual qualified control probe package is `org.trillionnium.hepta.controlprobe`, with `.VisualChallengeActivity` and `.TextEntryActivity`. `examples/visual-postconditions.json` uses its public IDs. For a Unicode task, separately require the intended editor readback, public `unicode_readback`, public `unicode_receipt` with its exact source-defined expected value, and the requested final navigation. Do not infer a receipt from native `exit0`, helper success or a model summary.

The visual contract also prevents `phone.read_text` from reading its declared challenge view before a confirmed typed visual tap. Generic owner-open tools remain available for authorized operations; tool traces must still be reviewed when qualifying genuine model vision. This candidate does not prove that a new real model used the pixels correctly.

## Offline validation

From any working directory, using this candidate's actual absolute path:

```sh
python3 -B /ABSOLUTE/CANDIDATE/tests/offline_v149_checks.py
python3 -B /ABSOLUTE/CANDIDATE/tests/offline_phone_tools_checks.py
python3 -B /ABSOLUTE/CANDIDATE/tests/offline_capacity_race_checks.py
```

The production source uses Python's standard library only. The image fixture test uses macOS `sips` when present, otherwise Pillow. It generates a synthetic local PNG/JPEG; no fixture image is presented as a new phone/model image. The v149 test invokes disposable local CLI and Android-command shims to exercise actual streaming, shell mapping, cleanup and legacy wire terminals. It never invokes real Codex, `adb`, a live service or a phone. The original v148-r5 source bytes are in `baseline/`, and `CHANGES.patch` provides the complete source diff.

The local validation artifacts report 96 v149 checks, 35 adapted image/Unicode boundary checks and 25 capacity checks. The previous retained real codec sample is not shipped as a new live result; this is why the image suite contains 35 rather than the audit's original 36 checks. Independent host reruns are required before deployment.

## Deployment and remaining qualification

Copy the entire eight-file `source/` directory as one version. `daily_provider.py` pins all imported provider modules. Preserve the existing CLI binary pin, gpt-6.1-sol selection, service state, all accepted claims, joined/spawn receipts, task bindings, app/helper artifacts and recovery baseline. The unchanged bridge and OpenAI-compatible protocol module are included at their exact v148-r5 hashes. Start through the existing resident `daily_provider.py` entrypoint. Root must perform the service switch and real-device tests; this directory does not contain an automatic deploy/retry script.

Real-device checks still needed include current Android window dump formatting; deterministic launch plus actual focus; exact Unicode/newline public readback after confirmation; snapshot-bound text/receipt checks; pixel/focus mismatch with zero input; and foreground verification after return. `stay_on_while_plugged_in` must be restored to this task's observed baseline **2**, not a value copied from a historical test.

The exact-PNG guard is conservative. A clock, caret, animation or other pixel change may reject a safe-looking action. There remains an unavoidable interval between the final observation and input; the guard is not an atomic Android UI transaction. Only the observed inner display 0, portrait 1224×2992 configuration is qualified. No external-display, folded-state or alternate-rotation acceptance is claimed.

Root's fresh approved-channel health observation reported `usage_limit_exceeded`. The complete new LLM visual/Unicode flows therefore remain blocked pending model availability and new independently observed runs. Offline checks, direct device checks and historical r4/r5 evidence must remain separately labelled.
