# Root-only native task sender r4

This is the versioned successor of the unchanged sender-r3. It admits the exact
retired Visual04 failure using its actual additive resolution; preserves the
original nonempty user draft; and optionally waits for the fixed component-r2
provider. It never starts that provider, performs a TCP probe, or sends a task
during build-only preparation.

The final source passed 34 original-certificate/draft/one-Send host checks and
35 fixed-rendezvous host checks. The test job ended with exit0, complete durable
output and no truncation. All fixtures used synthetic draft text and zero
phone/model/socket/external-process calls. This is not phone qualification.

## Files and frozen inputs

The three runtime source files stay together at the B150 root:
- send_new_native_task_r4.py
- sender_retirement_guard_r4.py
- sender_component_ready_r4.py

The source seal is sender-r4-validation/SOURCE-SEAL-sender-r4.json. It binds the
two focused test sources, two actual test reports, final diff, this plan, and
the durable host test terminal. Generated actor previews, request files,
preserved draft files, raw screenshots/UI dumps and private runtime receipts
are deliberately not part of the reusable source package.

The sender reads the existing, hash-pinned control_send_once.py and
decode_client_state.py from the frozen v146/v147 sibling directories. The
retirement helper additionally reads the exact FINAL-PROOF-01.json, before.json
and selected-native-records.json already mirrored under retirement-recovery-r2.
These private evidence originals are not copied into the source package.

Fixed retired original:
- Action: fc7bd6d939fb740a6403a04521fbb057.
- Original intent SHA256: 37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417.
- Final proof SHA256: 2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e.
- Actual resolution: 1237 bytes, SHA256 7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433.

Only the exact old scope and original failed native request receive retirement
admission. No prior success is invented. Old claims, original intent, client
failure, native failure and proof remain unchanged. A new unresolved effect
blocks the sender. The gate independently checks the seven original native
record hashes, using the frozen auditor's actual Rust preimage field order.

## Prepare local inputs

Root retains one immutable preservation JSON with:
- exact_utf8_b64: the actual original nonempty draft bytes, encoded as base64;
- utf8_sha256: SHA256 of those exact decoded UTF-8 bytes.

Keep that file private. Do not use any old empty-editor proof. The sender
rejects an empty preservation value and refuses a new request identical to the
preserved draft. It copies the original draft only into private actor/receipt
files; public output omits both the draft and its direct SHA256.

REQUEST is the exact new owner-request text file, including its exact newline
bytes. PREVIOUS_REPORT is the independently read original current task report.
For the first post-retirement task, use the actual Visual04 report, not a
different healthy turn or a relabelled success.

RESOLUTION is the exact Root-created resolution mirrored at:
ondevice-contract-review-v150/retirement-resolution-r4-01/pocket4/RESOLUTION.json

Use a new label matching [a-z0-9-]{1,70}. Generated .actor.py, .local-once.json and
Pocket4 output directories are exclusive creations. A missing/unknown sender
result is not permission to rerun its label, request or action.

## Production mode

On Main, with B150 as the existing absolute project directory:

    python3 -B "$B150/send_new_native_task_r4.py" LABEL REQUEST PREVIOUS_REPORT \
      --preserved-draft PRESERVATION_JSON \
      --retirement-resolution RESOLUTION_JSON

Without --execute-once this only generates a private LABEL.preview.actor.py.
The generated actor is compiled but never executed. The summary says
BUILT_ONLY_NO_PHONE. The preview contains private material and must not be
published.

For the one authorized real Root execution, use the same inputs and append:

    --execute-once

Production uses only provider-state/evidence. It has no component readiness
wait and rejects --component-contract. --reset-probe remains an explicit
production-only inherited option; do not use it for health or the component
qualification task.

The pre-Send interval has one original 150-second Pocket4 monotonic deadline.
The sender rechecks retirement/global action state, exact selected native
identity, original Inspect/terminal, request freshness and the exact draft.
Only one tap(send) exists in the generated actor. The deadline is checked
again after persistence of the Send intent, immediately before the tap.

After that tap, including an unknown tap result, it only observes this exact
owner-request SHA and the actual resulting five-field scope. It never taps
Send again. The original terminal observation budget is335seconds, with
bounded individual reads. Observation records raw native terminal bytes and
separates owner UTF-8 SHA from the native request-envelope SHA.

An exit0 from this operator helper means its observation/cleanup completed.
It does not mean the business task succeeded. Read native_status and run the
independent native/provider/effect collector.

## Fixed component-r2 mode and Root rendezvous

This mode is for the separately reviewed, zero-model native executor component
probe only. Its single fixed printf effect is admitted by the real native
shell.exec path. Task-entry UI actions are separately counted; no App business
capability is inferred.

Frozen component source:
- /var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/source-r2/component_probe_provider.py
- 27226bytes, SHA256 ff65efc41c30027d0066ddd6fdf3120278c83ccdbe56d7e24922ed96782d2118.

Root prepares a new contract/request with component-probe-r6-r2/prepare_component_probe.py,
using the actual currently selected session/profile, actual parent executor
instance, exact retirement proof and actual resolution. The preparation helper
creates local files only. Retain its new nonce and raw contract SHA.

Before starting the sender, Root installs the exact contract at:
STATE/contracts/NONCE.json
where STATE=/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6.

STATE, contracts and claims must already be canonical root-owned0700
directories, even while waiting for the provider to start. Root also prepares
the provider's evidence and client-receipts directories as required. Verify
existing state; do not delete claims or journals. Contract, ready, attempt and
source files must be root-owned regular files with no group/other permissions.
The source may be0400 or0600; mutable records are private0600.

Use the same sender CLI, with:

    --evidence-root component \
    --component-contract NEW_COMPONENT_CONTRACT_JSON \
    --execute-once

The contract owner bytes must exactly equal REQUEST and its session/profile
must equal the selected original report. The contract is fixed to the new r6
endpoint/client, exact source-r2, policy pins and actual retirement certificate.
There is no arbitrary command, socket, evidence directory or launcher hook.

The ordered coordination is:

1. The sender completes its original UI/Inspect/draft/scope/freshness/retirement
   prechecks. It saves the private Pocket4 marker:
   /operator-workspace/pocket4/codex-hepta-natural-LABEL-root-v150/COMPONENT-PREPARED-NO-SEND.json
   Marker state must be PREPARED_NO_SEND with the intended new owner/nonce/
   contract/source pins, send_attempt_count0 and the original remaining budget.
2. Root reads that marker and launches the separately reviewed component-r2
   provider once. Do not start the provider before the marker. The sender
   itself never launches it. The exact launcher argv is:
   ["/data/adb/magisk/busybox","chroot","/data/trillionnium/owner-open/root",
    "/usr/bin/python3","-B",
    "/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/source-r2/component_probe_provider.py",
    "--contract",
    "/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/contracts/NONCE.json",
    "--contract-sha256","EXACT_RAW_CONTRACT_SHA"]
   Preserve this post-chroot Python argv; it is checked through /proc.
3. The sender only reads STATE/ready-NONCE.json and fixed related files.
   It checks exact owner/nonce/source/contract/executor-instance, a live PID
   and startticks twice, exact cmdline, the matching one-use service attempt,
   no consumed claim and no service-ended record. It reads complete file/proc
   contents to EOF and rejects inconsistent metadata.
4. ready.scope is the provider's descriptive string. It is not the native
   five-field scope. Session/profile are bound by the raw pinned contract;
   the actual task/turn/stream identity appears only after real acceptance.
5. The provider's actual phone CLOCK_MONOTONIC timestamps retain its70second
   total service limit and original40second accept window. The first observed
   ready must retain at least25seconds, then the sender rechecks the selected
   identity, draft and global retirement gate. The final ready must retain at
   least15seconds. Both gates conservatively subtract the entire Pocket4 read
   duration and subsequent elapsed time. No wall-clock/mtime approximation is
   used to extend the accept interval; contract expiry is also checked.
6. The final instance/PID/startticks/ready raw hash must match the first ready.
   Immediately before its only Send, the sender checks both the original
  150second pre-Send deadline and remaining component margin again.
7. Missing ready, malformed evidence, a changed/consumed service or an
   exhausted interval means zero Send. The script records the actual failure,
   attempts only permitted draft cleanup, and never restarts the provider.
   Root must inspect that same original attempt and retire it by its reviewed
   plan. Any future attempt requires separately prepared fresh material.

The readiness check is an observation, not a reservation of the listener.
Another connection or a process exit after the check can still cause failure.
The sender reports the actual original native outcome and does not retry.

Component evidence selection is exactly STATE/evidence. The sender also checks
the fixed production evidence root for a collision of the new owner text.
No user-supplied evidence directory can be opened through this option.

## Original draft cleanup and unknown outcomes

After a confirmed original task terminal, cleanup first records the actual
foreground privately, separately from model return/business evidence. It
verifies the new selected scope, checks the global unresolved-effect gate,
opens the exact HEPTA activity and restores the original draft using the frozen
Unicode helper's expected-text compare-and-set.

The only accepted visible baselines are the current new request, actual empty
effectiveText, or the exact already-restored original. A hint is tested with
the helper's empty effectiveText CAS; a real user-entered string equal to the
hint fails that CAS and remains untouched. Any changed user draft is preserved.

If the input action is unconfirmed, the task terminal is unknown, scope changed
or the effect gate is unresolved, cleanup is deferred. The private original
is retained. A deferred restore is not labelled restored and triggers a nonzero
sender exit. Never blindly retry an input or restore after an unknown outcome.

The original preserved draft is never submitted. Operator cleanup never earns
credit for HEPTA return or a model business postcondition. The public summary
contains only restore state, attempt count and original_draft_submitted=false.

## Review and remaining qualification

Root and the independent research agent reviewed the final sender/ready helper.
The focused review found no new replay, dispatch or arbitrary-launch path.
No production provider/core/model budget was changed. sender-r3, provider-r1
through-r5, original reports, old claims and the original failed task remain
unchanged.

The next real gate is one fresh Root-owned component task followed by the
independent native/output/receipt/SELinux-domain audit. A component PASS does
not establish App permissions, GUI model accuracy, Unicode business completion,
the fixed19case protocol, folding states, reboot persistence or daily-use
qualification. Production health requires its own new one-use request afterward.
