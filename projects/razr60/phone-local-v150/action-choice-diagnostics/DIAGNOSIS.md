# Local code6 prompt and action-selection review

Status: work in progress, source review plus an isolated host-only prompt renderer. The analysis did not change the code6 controller, compact candidate, Android app or phone. The renderer does not run a model and cannot execute a phone action. The exact code6 source and sanitized failed task matrix are checkpointed in the sibling `android-local` directory at repository commit `3f1f6018b48ef82cc968d0cf006188e0a84bf463`.

## Finding

There is no evidence in the reviewed wrapper and pinned SDK sources of swapped system/user roles, double chat-template application, automatic prompt truncation, or stale KV history crossing these one-process requests. There are concrete observation and output-design problems. The reduced compact JSON fixes copying burden, but observed compact failures demonstrate that it has not fixed goal understanding.

The recovered fixed-frame results are: canonical image 2/3 (previously recorded device result), canonical text 1/3, compact image 1/3, compact text 2/3. In compact mode all six outputs had the intended compact shape, yet the wrong search page selected its own current package in both modes. The real four-task matrix passed 0/4 in the retained completed matrix. These are small controlled samples, not estimated general success rates.

## Serialization and SDK contract checked

`EngineInferenceAdapter.generate` constructs `Request(prompt, system, image, ...)` in the same order as the `LocalModelEngine.Request` constructor. The engine writes exact UTF-8 prompt and system bytes into different files and passes distinct `--prompt-file` and `--system-file` arguments. Native `worker-upstream.c` creates one system message and one user message, calls one VLM chat-template function, then passes that formatted result to one generate call. The image is a separate VLM media item and a matching generation image path.

Pinned source chain:

- GenieX `071f609995470bdb0e0769ab964754adfaab7e47` uses qairt-plugin gitlink `ab24abb1f66cb3d8fe624cb8649ec23bd36da41c`.
- qairt-plugin uses geniex-proc gitlink `6b68dd0de5b9a84c316cc3babfe9f2477d9c6079`.
- [QAIRT VLM C API adapter](https://github.com/qualcomm/GenieX/blob/071f609995470bdb0e0769ab964754adfaab7e47/sdk/plugins/qairt/src/vlm.cpp) recognizes system/user roles, retains supplied system content and only injects a default if no initial system message exists.
- [Qwen3 pipeline factory](https://github.com/qualcomm/geniex-qairt-plugin/blob/ab24abb1f66cb3d8fe624cb8649ec23bd36da41c/models/qwen3_vl/qwen3_vl.h) selects Qwen2VLProcessor with Qwen3 bundle dimensions/patch/normalization overrides.
- [Processor template](https://github.com/qualcomm/geniex-proc/blob/6b68dd0de5b9a84c316cc3babfe9f2477d9c6079/src/processors/qwen2vl.cpp) emits ChatML system, user, then assistant generation prefix. It puts image markers before user text even though the public C contents array originally lists text first. Thus this wrapper's array order does not put the owner's question before the image in the final token stream.

The QAIRT processor uses its fixed ChatML formatter rather than loading the bundle's Jinja chat template through Tokenizer. The no-tools, non-thinking system/user shape is consistent with this SDK's official Qwen3 example. There is no current proof that this template choice is the failure cause. `enable_thinking=false` does not add a hidden reasoning task. The pipeline also prepends configured BOS on its first request; this is a pinned SDK behavior, not extra formatting added by the Hepta wrapper. Do not alter the qualified bundle or native runtime based on speculation about this token.

The worker records a hash of the formatted prompt, not its bytes. A future diagnostic can retain the exact formatted prompt in the existing private request directory and compare it to the pinned formatter output. No such runtime patch was made here. This would be a serialization check, not an additional phone action.

## Concrete deficiencies

### 1. Fixed square vision loses phone-text detail

The pinned implementation selects fixed dimensions when both configured fixed
height and width are positive, then calls `resize_image` with those dimensions.
The Qwen3 factory populates those fixed fields from bundle metadata. This is
explicit source evidence, not a deduction from the tensor shape alone:

- [Qwen3 factory, lines 165–170](https://github.com/qualcomm/geniex-qairt-plugin/blob/ab24abb1f66cb3d8fe624cb8649ec23bd36da41c/models/qwen3_vl/qwen3_vl.h#L165-L170).
- [Fixed-size preprocessing branch and resize call, lines 84–95](https://github.com/qualcomm/geniex-proc/blob/6b68dd0de5b9a84c316cc3babfe9f2477d9c6079/src/processors/qwen2vl.cpp#L84-L95).

With the recorded 512×512 configuration and this source path, a portrait input
is resized to a square; the horizontal and vertical scales are `512/width` and
`512/height`. That can reduce the readability of small interface text. This is
a source-derived inference about preprocessing: the deployed processed tensor
was not captured here, and no OCR-loss percentage was measured. Large colored
button-location probes do not establish readable phone text or reliable page
recognition. This cannot explain every failure because text-only negative-page
probes failed as well.

### 2. Actionable-node ranking removes scene facts

Controller `prompt` sorts by `nodeScore` and presents at most 16 nodes, reducing further for its conservative byte bound. The model sees only `[id,label,bounds,flags]`. It loses class, view ID, enabled/focused state, the distinction between field value and field purpose, parent/child structure and readable page order.

Ordinary short read-only text scores 7; an ordinary short clickable button scores 11. A computed result that is not a literal substring of the original instruction can therefore be ranked below a full keypad of clickable buttons. Page titles, confirmation text and state text need their own observation channel; they cannot compete only by clickability.

`PhoneObservation.Node` does not expose checked/selected values to the model, even though `nodeSignature` includes them for freshness. That prevents generic semantic verification of some switch/selection tasks. `label()` prefers text over description and child text; once an edit field contains a value, the current projection can lose the field's explanatory label. These are observation limitations, not a reason to relax action validation.

### 3. Output mixes content selection with metadata copying

The real failure output combines `open`, current launcher package and a node ID. Another compact failure opens the currently observed search package, which is not the desired launchable target. Those fields serve different roles in the free-form schema. The model is repeatedly copying a salient package rather than selecting a valid transition. UUID removal alone leaves this ambiguity intact.

### 4. Completion example text is copied without grounding

Recovered results repeat generic completion-summary examples from the system prompt. A search-results page is still reported done under the canonical prompt when the requested goal is a different page. No raw UI, original task payload or model response is included in this public projection. A schema-shaped answer is not completion evidence. Preserve `model_reported_done`; never promote that result to independently verified success.

### 5. History and repair can reinforce the wrong answer

Recent history retains an action name and coarse outcome/package fields but generally omits the clicked label or exact entered value. It therefore loses useful progress information. The bounded format repair includes the complete rejected output; the recovered matrix repeats the same invalid object on both greedy attempts. This is observed repetition, not proof that rejected-output inclusion alone caused it. A selector should present the remaining legal choices and a short error, without showing another malformed action as an attractive template.

## One proposed generic architecture

Use a trusted snapshot to create **separate scene facts and a numbered menu of currently legal actions**. The model selects a menu number and, only for a text-entry item, supplies the exact text. It does not generate a package, node ID, observation ID, action name or coordinate.

1. Retain the original OWNER bytes and hash. Present the owner's task in Chinese followed by clearly quoted untrusted scene data.
2. Preserve page facts in reading order: visible headings/body/status/results; field labels separately from values; focus, enabled, checkable/checked/selected; observed window title if available. Do not infer a page title from package names. Keep complete source observation and explicit coverage.
3. Build action descriptors only from current capabilities: launchable apps excluding the current package; enabled visible non-password nodes with actual supported click/type/scroll actions; back/home/bounded wait. Each descriptor binds the current task, observation, package, node reference, geometry and signature in trusted code.
4. Give the model concise Chinese descriptions and integers, for example `{"choice":7}` or `{"choice":4,"text":"用户要求的原文"}`. Parse one strict JSON object; unknown/duplicate fields and invalid indices are errors. Never execute code from a choice or label.
5. Resolve a selected number only in the immutable pending request's descriptor table. Construct the existing validated ActionDecision from trusted values. Keep every existing lease, cancellation, foreground, tree/node/pixel and post-observation check. Do not resolve against a newer global menu.
6. Include a **request goal review** option, not an automatically successful done option. Capture a fresh final observation and require stated visible evidence. A second same-model judgment is corroboration, not independent verification. Production must keep uncertain completion explicit; benchmark success still uses the test operator's independent UI predicates.
7. Use text scene facts for ordinary labelled-node decisions; retain the original screenshot as evidence. Use vision for genuinely visual or unlabelled situations. A visual branch still needs the exact image transform and coordinate gates. This is a generic capability split, not task-specific scripting.

The menu does not need to contain every installed app on every step. A separately bounded app-selection phase may choose among the complete catalogue when needed, and subsequent steps can retain the chosen destination as a hypothesis. Never silently drop the only relevant app or rewrite the owner's task. If a complete necessary scene/menu exceeds the honest budget, request additional observation/pagination or stop; do not silently truncate semantics and still claim success.

This reduces output entropy and invalid parameter combinations. It does not establish that the current generic Qwen4B model understands negative goal states. If the pending six YES/NO goal probes also fail the search-page contrast, prefer testing the purpose-trained GUI model rather than treating further JSON changes as a semantic cure.

## Host-only candidate

`SYSTEM.txt` is a 606-byte Chinese selector instruction. `render_choice_probe.py` converts one preserved Controller diagnostic record into a numbered **probe** menu with trusted binding data in a separate file. It does no inference, does not execute actions and does not modify Android code.

The input is already the old lossy projection. The renderer explicitly records missing-node/app counts and missing full capabilities, preserves all supplied labels and the exact OWNER without further truncation, and rejects admission by the existing raw/NFC UTF-8 upper-bound method when necessary. Its descriptors are not an Android execution authorization: production would need full fresh action lists rather than the legacy c/t/s flags.

The real diagnostic input and its deterministic rendering remain private and
are excluded from this source directory. No screenshot, raw UI, original owner
task, model response, operator path or device identifier is published. The
renderer and selector prompt have not passed a semantic model or phone-action
qualification. Their current purpose is to isolate action selection from
metadata copying in controlled inference-only comparisons.
