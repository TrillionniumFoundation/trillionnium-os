# Code 6: reason-first decisions and full-hash acceleration

This candidate retains the fixed local GenieX/llama runtime, model identities,
ordinary app UID, no INTERNET permission, observation-bound tool dispatch,
explicit completion evidence, cancellation and interrupted-session latch.
It has not been declared a completed phone-agent qualification.

## Reasoning before action selection

The generated action grammar emits the bounded reason field before the action
field. The model can describe the current screen before choosing the constrained
action. Every action still binds the current observation, package and permitted
arguments. The parser, finite candidate set, repeat rejection and dispatch
checks remain in force. Prompt changes describe progress fields explicitly and
ask the model to choose an action from the current observation.

## Action-specific observation freshness

Every action still requires a current observation ID, bounded observation age
and the same foreground window, package, rotation and bounds. Open, home,
find_app and wait do not additionally require an identical whole-tree digest;
unrelated changing clock text should not invalidate those non-node actions.
Back, click, type, scroll and done retain the complete tree identity requirement.
Click/type/scroll retain their existing node checks and click pixel validation.

## Complete SHA-256 on every invocation

The worker still opens the pinned model read-only with no symlink following,
checks private ownership/mode/size, reads and hashes every byte through the held
file descriptor, compares the full pinned SHA, rechecks metadata, seeks that
same descriptor to the beginning and loads it through its descriptor path.
There is no model digest cache, metadata-only shortcut or skipped verification.

`native/sha256-dispatch.h` replaces only the generated hash primitive. The
vendored `worker-upstream.c` stays byte-identical. Portable compression is the
same upstream implementation. On little-endian Android AArch64 the dispatcher
checks `getauxval(AT_HWCAP) & HWCAP_SHA2`; only the noinline target("sha2")
function contains hardware SHA instructions. All other cases use the portable
path. SHA2 is a CPU integrity primitive and is separate from neural NPU/GPU
execution. Bulk input processing also avoids a memcpy for every full block.

The actual NDK build disassembles the unstripped executable and refuses SHA
instructions outside that target function. New diagnostic receipt fields record
the selected hash backend, fully read byte count and hardware/portable block
counts (including SHA padding blocks). Existing phase timing measures the actual
hash interval. No speedup is assumed from the implementation alone.

`native/tests/sha256_probe.c` is an independent read-only Android qualifier:

```sh
hepta-sha256-probe --self-test --require-sha2
hepta-sha256-probe --file /absolute/private/fixture.bin --require-sha2
hepta-sha256-probe --file /absolute/private/fixture.bin --portable --chunk 65
hepta-sha256-probe --bench 134217728 --require-sha2
hepta-sha256-probe --bench 134217728 --portable
```

Self-test covers published SHA vectors, boundary lengths, deliberately unaligned
buffers, seven chunk sizes and hardware/portable comparisons. The host gate
independently checks all pattern digests and real file reads against Python
hashlib, plus a length beyond 2^32 input bits. Host success alone does not prove
the ARM hardware path was executed; the phone qualifier must report that fact.

## Private prompt and exact token evidence

The worker writes `formatted-prompt.txt`, `formatted-input-ids.le32` and
`prompt-evidence.json` in the same private request directory using the existing
create-only, owner/mode-checked, no-symlink and renameat2 no-replace protocol.
Metadata binds the request nonce, model hash, source input hashes, formatted
text hash, exact direct token ID hash/count and fixed runtime sources.
These diagnostics do not change the prompt, tokenizer, grammar or sampler.

MiniCPM and Spark export the same input-ID array passed to generation. Original
LFM3 retains its existing prompt-text semantics and exports an explicitly empty
ID file with `input_ids_will_be_passed_directly=false`. The native receipt gains
only a small diagnostic object, preserving its bounded parse size. Evidence
publication failure stops before generation. Partial sidecars do not establish
generation completion and do not authorize an action.

Raw prompt or UI evidence is never written to logcat, source archives or Git.
Only implementation and synthetic host contracts belong to this source tree.
