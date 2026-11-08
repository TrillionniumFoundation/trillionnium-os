# Native NPU startup and fixed-19 acceptance plan

This is an execution plan, not an acceptance result. `PLAN.json` retains all 19
original case IDs, their original postconditions and their original order. **No
case is recorded as passed by this plan.** The host backend, tokenizer and private
provider suites, static installation, and synthetic-image model checks each have
their own evidence and do not count as fixed-19 passes.

The definition is `provider-r5/qa/fixed-acceptance-set.json`, source set
`stock16-phone-local-fixed-set-r4`, SHA-256
`c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0`.
The original protocol SHA-256 is
`07433e17cb71592a011a54c787ac61947b727ec5ae6f507bca22f8fa6dfb0736`.
The source definition is retained unchanged. Historical attempts and their failed,
unknown or not-run outcomes must remain separate from every new attempt.

## What is already prepared

The R3 candidate has been copied to fresh phone paths, with 78 model/runtime
artifacts (4,630,850,230 bytes) and 28 private provider/configuration/launcher files.
All copied artifact sizes and SHA-256 values passed. New artifacts are root-owned
and readable/traversable by the shell worker; the request stage is owned by
UID/GID 2000 with mode 0700; private provider/configuration files remain private.
The public evidence is `../static-install-r3/PUBLIC-SUMMARY.json`.

That installation is **unselected and inactive**. It has not started the GNUroot,
bound the new stage, started a provider or executor, cleared the owner stop,
modified old claims, or operated a phone application. R3's real full-directory
model decisions failed the original strict schema and cannot be promoted.

The new provider path is concrete: `--geniex-config` selects the native QAIRT
backend before the existing CPU HTTP path. The NPU path does not require CPU
`READY`, `model.identity` or slot-cleanup bindings. The CPU path retains those
requirements. The final launcher must reference the exact qualified source and
configuration hashes; a file merely present on disk is not a selected backend.

## Startup constraints observed after installation

The device's fixed-path `stock16-backend-init.source.rc` audit copy was read in
full and matched its independently reported SHA-256:
`a2f43dc3a9fe8db8d47dcaf6a1c435b8a53232dfce378593ab8830fec49275ca`
(4,305 bytes). The file explicitly states that an audit-copy measurement does
not attest which init source was effectively loaded. The findings below are
therefore source observations requiring effective-init and namespace checks;
they are not a claim that a stopped service has executed this configuration.

The copy describes an EROFS root mounted read-only, a writable state bind remounted
`nosuid,nodev,noexec`, read-only proc/dev binds, and then a recursive private mount
tree. The bootstrap service has `namespace mnt` and capabilities `SYS_CHROOT KILL`.
It is not given `SYS_ADMIN` to perform additional mounts. Stopping it is followed
by init-owned unmounts. The existing native bootstrap source likewise validates
the immutable root and exact writable-state inode; it does not create its own
mounts.

This exposes a concrete gap in the installed R3 instructions: creating a new
`/run/hepta-geniex-stage` inside a mounted read-only root, then binding it late
from an unrelated shell mount namespace, has not been established to work.
The R3 bind script has **not** been executed. Its mount/inode checks must remain
strict; do not execute it merely because its shell syntax passed.

The correction must be a new reviewed startup candidate. It must identify a
pre-existing or demonstrably writable target, establish the bind in the namespace
the bootstrap will actually inherit before its private namespace is created,
and verify the same stage device/inode, UID/GID and mode from both views. A
dedicated target below the existing writable state view is a possible design,
subject to checking the effective init sequence. A nested bind on the Android
state source followed by a non-recursive state bind must not be assumed to carry
that nested mount into GNUroot. A new SELinux rule, `runcon`, substituted UID,
permissive mode, or change to global device-node permissions is not a substitute
for this integration.

## Activation order and evidence gates

1. **Freeze the usable source and model protocol.** Bind the selected SDK/plugin,
   model, counter, worker, source, tokenizer, formatter and configuration hashes.
   Demonstrate complete strict-schema decisions for the actual provider prompt,
   including current observations and allowed actions. Do not repair generated
   JSON, fill omitted arguments, discard earlier failures or raise the compiled
   4096-token context. Any grammar-enabled SDK change needs its own positive and
   failure checks before the provider may select it.

2. **Finish host qualification on that exact private r9 overlay.** Run the actual
   selector without a CPU binding/READY/identity file, the original strict parser
   and business tail, the original private regression suite, and the real r6 host
   supervisor. Cover user cancellation, session expiry, native timeout and the
   frozen worker's own deadline separately. A native terminal can prove process
   cleanup while still yielding an unusable model result. A missing terminal or
   missing waitpid/group-absence proof retains UNKNOWN and forbids redispatch.

3. **Prepare the legal mount and controller selection while stopped.** Read the
   effective init imports and current mount topology, pin the exact original
   bytes, and generate the reviewed change plus an inverse rollback. Keep the
   original provider state, executor state, retained claims and UNKNOWN records.
   Create a fresh activation identity; never reuse a consumed per-boot startup
   claim. Inspect an existing target instead of deleting it or stacking a mount.
   The selected provider command must include the actual `--geniex-config` path.
   Restoring the GNU substrate must not restart an old CPU model module.

4. **Restore only the qualified new path.** Preserve the original stop file bytes,
   SHA and metadata in a durable recovery record before any deliberate change.
   The current repair/install/test request authorizes necessary reversible
   restoration; the observed scripts do not require a separate rearm token.
   Re-read the stop property, active process identities and original claims at
   the point of restoration. Record the change as a new activation, not as
   evidence that the earlier stop never existed. Unknown process/effect state is
   reconciled against its original identity, not cleared for convenience.

5. **Prove the actual worker domain before admitting phone actions.** Through the
   legitimate bootstrap caller and existing native executor, run a bounded pure
   local model request with UID/GID 2000, cleared supplementary groups and the
   exact `trillionnium_owner_open_phone_worker` domain. Require original native
   command/input bindings, waitpid and process-group-absence proof plus the
   independent GenieX result and counter checks. Root-only model success and DAC
   readability do not establish FastRPC/SELinux/ioctl capability. If this fails,
   keep action admission closed and preserve the original native result.

6. **Run fresh component cases, then the four model E2Es, then lifecycle negatives.**
   Confirm the phone's actual current keyguard, display, rotation and viewport.
   Use new disposable visual/text challenge nonces and actual public app receipts.
   Record host and physical results separately, including cases blocked by a
   prerequisite. The final completion claim requires the requested public app
   result and entire-request coverage; a model summary, shell exit zero or native
   process cleanup cannot supply that evidence.

The phone was observed unlocked and awake during this work; a previously observed
lockscreen is not a current blanket blocker. Recheck it immediately before each
physical case. The existing stop has remained unchanged throughout static
installation. Its original content is `owner-authorized emergency stop` followed
by LF, SHA-256
`ff6401f96ef8d2206e61e9fdf6d75d1dd11fe25f5696d7f6996b6647023fdb07`.

## Test applicability

| Original ID | Required execution and evidence | Native backend adaptation |
| --- | --- | --- |
| E2E-01 | Real fresh visual challenge; one screenshot-bound choice; same-snapshot public receipt; requested return | Original image bytes are staged and SHA-bound to counter/worker/native evidence instead of HTTP transport. No second attempt to guess. |
| E2E-02 | Real fresh exact UTF-8 entry, confirmation, public text receipt and requested return | Keep original input helper and typed receipt; local model transport changes only. LF and emoji must survive byte-for-byte. |
| E2E-03 | Real fresh calculator expression and independently verified visible result, then requested return | Do not substitute a mental answer or a 24-tool profile for the original seven-tool contract. |
| E2E-04 | Read an actual public system-setting field without changing it | No forced return unless requested; verify text and focus independently. |
| COMP-01 | Real direct return operation, launch output and actual focus/resumed activity | Component pass only; it is not a model E2E. |
| NEG-01 | Real controlled focus change after screenshot, rejection before input, zero public effect | Existing viewport/focus guard unchanged. |
| NEG-02 | Real same-viewport pixel change, exact PNG mismatch, rejection before input | Existing original-pixel guard unchanged. |
| NEG-03 | Original-shaped unsupported-display/rotation fixture; separately labelled physical follow-up | A fixture cannot qualify an external display or physical fold/rotation. |
| NEG-04 | Host disconnect before dispatch, plus fresh installed lifecycle follow-up | Close the original native request if model work is active; preserve consumed owner identity and zero phone effects. |
| NEG-05 | Host disconnect after effect starts, plus disposable physical effect counter | Phone-action UNKNOWN remains global. A cleaned model process does not resolve an uncertain phone action. |
| NEG-06 | Real host supervisor and controlled SDK hold for each model deadline | Native timeout and worker deadline must produce original `model_timeout`, after independently proving cleanup. |
| NEG-07 | Delayed original phone-executor result, plus installed lifecycle follow-up | No late-result upgrade of UNKNOWN and no second effect. Model cleanup is unrelated evidence. |
| NEG-08 | Host cancel before dispatch / during generation / at result acceptance, plus physical follow-up | Cancellation ordering wins when accepted first; real native cleanup; no automatic navigation. |
| NEG-09 | Host cancel after one effect, plus physical follow-up | Keep exactly the observed effect; no next input, forced return or whole-task success. |
| NEG-10 | Original image byte/expiry/round/call boundary fixtures | Preserve fixed19 image limits; 3584-token admission is an added check, not a replacement. |
| NEG-11 | Original malformed phone receipts and separately added malformed model receipts | Validate exact integer/boolean types, identity, Base64, sizes, hashes and terminals; no facts from corrupt evidence. |
| NEG-12 | Input-only or partial coverage followed by model `completed` | Original business parser must emit `business_not_verified`; NPU success does not satisfy app receipts. |
| NEG-13 | Exact contract O_EXCL/concurrency/scope/reuse fixtures | Accepted ordinary new UI turns are separate from reused template/nonce/stream identities. |
| NEG-14 | Exact rename race, capacity, unreadable evidence and real resource cleanup | Only documented atomic temporary names are tolerated; no blanket `.new` ignore or claim deletion. |

The original accounting is **11 host cases (NEG-04 through NEG-14), four component
cases (COMP-01 and NEG-01 through NEG-03), and four model E2Es**. NEG-04, NEG-05,
NEG-07, NEG-08 and NEG-09 additionally require the listed installed lifecycle
follow-ups; those follow-ups are not five extra IDs or automatic host passes.

## Budgets and protocol differences

Registered fixed19 tasks retain seven sequential tools, eight model rounds,
300 seconds total, a maximum single encoded image of 196,608 bytes, a turn image
budget of 393,216 bytes, minimum next-image allowance of 65,536 bytes and the
120-second image-age rule. The ordinary 24-tool profile cannot silently replace
these limits. Freshly verify the originally qualified display-0 portrait
1224-by-2992 geometry before a physical claim.

The old per-model-round HTTP default was 120 seconds. This native candidate uses
a 55-second worker deadline within a 60-second r6 supervision bound and retains
the separately bounded transport/cleanup allowance. The counter and generation
run within the same supervised process group. QAIRT is compiled for at most
4096 context tokens: admission is at most 3584 prompt tokens with 256 generation
tokens and 256 reserved tokens. The counter reproduces the pinned SDK formatter;
successful generation must additionally match its formatted-prompt SHA and report
SDK prompt tokens in **[counter upper bound - 1, counter upper bound]**. This
permits the documented zero-or-one BOS difference; it is not a claim that the
counter is an identical full token-ID transcript.

Original postconditions mentioning HTTP/HTTP-client cleanup are retained verbatim
inside `PLAN.json` for comparison. The corresponding adaptation explicitly
replaces those transport facts with the original supervised native request,
counter, worker and process cleanup evidence. It does not create a CPU safe point,
invent token IDs, relax action evidence, or mark the old protocol as run unchanged.

Checkpoint `9383657` had a documented NEG-06 classification gap. A separately
tested timeout correction may be merged into the final qualified source; its
host suite result alone remains preparation evidence until this original case is
run and recorded with the required identity and postconditions.

## Rollback order

For the currently unselected installation, no running-service rollback is needed.
Keep its artifacts and evidence. For a later selected candidate, first close new
turn admission, request cancellation on the original active request, and inspect
that same native identity until waitpid/process-group-absence is established.
Missing cleanup evidence retains UNKNOWN; it is not an invitation to restart.
Record the observed terminal before stopping only the owned provider/controller
process groups. Unmount only the exact recorded new bind, from the owning mount
namespace and only after its users are gone; then restore the exact prior
selection/configuration bytes if that prior path is itself eligible. Do not
automatically restart a retired CPU model. Never delete old claims, shorten the
original evidence history, or use a new stream as a retry of an uncertain effect.
