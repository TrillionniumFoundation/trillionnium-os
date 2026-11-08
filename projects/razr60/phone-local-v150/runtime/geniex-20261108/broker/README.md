# Candidate QAIRT backend for the existing Hepta provider

This directory adds an explicit `--geniex-config` backend to a separately
generated provider source candidate. It does not start a service, mount GNUroot,
change the owner stop, unlock the phone, change a UID or SELinux policy, or remove
an existing claim. The frozen `../worker.c` remains unchanged.

## Actual integration path

`apply_provider_overlay.py` reads an existing provider source directory and
creates a new source directory. For the installed r9 source this operation must
run on pocket4: its private instance bindings stay there. The builder retains
the original r9 ledger-prefix preparation, accepted request identity, schema
binding and recovery guards. It inserts the new branch only at model transport
selection, and reuses the original strict JSON / `normalize_mobile_use` /
`_decision` tail. Removing the two explicit insertions must recover the exact
original completion-method AST; the overlay manifest records that check.

The generated `daily_phone_local.py` selects the backend only when started with
`--geniex-config /absolute/private/config.json`. Without that selector the old
HTTP/CPU branch and its receipt protocol remain in place. The new branch never
reports a CPU safe point, fabricates token IDs, starts an HTTP model server or
uses an external model endpoint.

The new profile is `daily-qairt-4096-process60-v1`: 24 tools, 25 model rounds, a
300-second total task deadline, a 55-second model-process deadline and a
60-second native supervision ceiling. Existing registered fixed19 contracts
keep their original seven-tool/eight-round budget. The adapter compares the
complete supervision/inspection allowance against the remaining **task**
deadline; it does not compare that allowance against the 55-second generation
cap. An accepted UI cancel, shutdown, transport failure or task deadline closes
the active native request and triggers inspection of that original request.

## Token admission happens before model creation

The official selected tokenizer has an NFC normalizer. This backend does not
substitute raw UTF-8 bytes or Python normalization for its actual tokenization.
The new native `token_count.c` uses the four exported Rust tokenizer C functions
from the pinned official QAIRT `libgeniex-proc.so`. It reproduces the fixed
Qwen2VL processor's actual text formatting and image split, counts those exact
text segments with `add_special_tokens=false`, and adds the fixed 256 image
tokens, two vision boundaries when an image exists, and a conservative bound
of one BOS token. The evidence labels this as a segment count plus a BOS upper
bound, not an assertion that every final SDK token ID was reproduced.

The supervised command verifies the counter, tokenizer library, tokenizer JSON
and frozen worker hashes, then runs:

```text
counter with the exact staged inputs and a 3584-token ceiling
    && exec frozen single-request GenieX worker
```

The counter runs inside the same native process group. Its nonzero exit prevents
model creation. The original native sidecar owns the group, tracks the leader,
waits for children and proves the group absent. After that proof the provider
independently reads the counter's original JSON, verifies its request/input/
artifact/formatter bindings and arithmetic, and verifies that the SDK-reported
prompt count lies in `[counter_upper_bound - 1, counter_upper_bound]` and that
the worker's formatted-prompt SHA-256 equals the independently reconstructed
SDK formatter bytes. The one-token interval accounts only for the pinned
pipeline's optional BOS token; a missing image-token block cannot pass. The compiled context is 4096;
generation is capped at 256 and another 256 tokens remain reserved. QAIRT model
creation still uses `n_ctx=0` and `n_gpu_layers=0`, because those values select
the bundle's compiled contexts rather than inventing an 8192 context.

`prompt_budget.py` retains the exact owner text as the final prompt segment and
retains the complete semantic transcript, postconditions and current image. It
projects repeated schema descriptions into short action signatures and shared
current screenshot constants. The full original decoder schema remains in the
request record and is still authoritative. No history or user instruction is
silently truncated to fit.

## Two independent result gates

Native process completion is not model success. The new receipt first requires
the exact r6 action ID, command hash and executor instance; real fork/handshake,
UID/GID/domain checks; `waitpid`; no lost process identity; and an absent process
group. For usable text it additionally requires exit zero, no disconnect, the
original counter's successful admission, the frozen worker's matching inputs,
one generate attempt, all applicable SDK return codes zero, complete UTF-8 raw
output, EOS or stop-sequence termination, no truncation/deadline/signal, and a
completion acceptance that precedes cancellation.

The provider then applies its unchanged strict action parser. A syntactically
incomplete JSON answer cannot authorize an action, even if both native and SDK
inference completed successfully. A valid model decision is still subject to
the existing current viewport, focus, lockscreen, observed-node, screenshot,
no-replay, exact text readback and postcondition gates.

An SDK abort (including the observed QAIRT grammar SIGABRT), exit 134, or absent
worker output is a failed model result when native cleanup is proven. It does
not become an unresolved phone action merely because the model process failed.
Missing native termination proof remains `unknown`, consumes the request ID and
blocks fresh backend requests until the original request is independently
resolved. Existing native UNKNOWN/recovery gates are also retained. No automatic
retry occurs under either outcome.

Grammar is disabled for QAIRT in this candidate. The real v0.10.0 discriminator
test aborted with `Grammar constraint violated: EOG token not allowed`. The
files in `grammars/` are retained test inputs, not enabled production settings.
The compact policy uses a complete unrelated JSON example; actual output must
still pass the original strict parser without adding braces or extracting a
convenient substring.

## Configuration and deployment prerequisites

The configuration schema is `hepta.provider-geniex-native.v1`. Its top-level
fields are exactly `schema`, `base_provider_config_sha256`, `model_id`,
`backend`, `tokenizer_gnu_path`, `tokenizer_config_gnu_path`,
`template_contract`, and `deployment_binding`. The existing provider config
and native executor bindings are hashed and retained. The effective model and
operation-profile selection receives a distinct hash in readiness metadata.

The backend fields are the exact `BackendConfig` dataclass fields. All program,
library and model paths must be explicit canonical absolute paths. The model
entry is the selected bundle's `genie_config.json` and its tokenizer is the
same directory's `tokenizer.json`; a bare bundle directory is not a valid QAIRT
entry. Runtime private library directories precede `/system/lib64`, which
precedes `/vendor/lib64`. The official library artifact used for the counter is
SHA-256 `7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d`.

Production staging is a new dedicated shell-owned 0700 directory under
`/data/local/tmp/hepta-geniex-stage-<fresh-instance>`, explicitly bound into
GNUroot at `/run/hepta-geniex-stage`. A deployment manifest must record the
actual instance, both paths and observed directory device/inode identity.
Configuration rejects a missing or mismatched mapping. It does not assume the
old `/var/lib` mapping and does not change any existing state-directory mode.
The provider owns its separate 0700 evidence directory; staged inputs and
outputs remain 0600 and owned by the supervisor's fixed execution UID 2000.

The current device has not qualified this backend under the exact production
`trillionnium_owner_open_phone_worker` domain. Root-only model tests do not
establish that permission. The existing r6 supervisor also requires an exact
bootstrap-domain caller for execute; a Magisk caller is restricted to health
and inspect. No alternate UID, `runcon`, permissive mode, device-node chmod or
new policy is supplied here. The existing owner stop and absent GNUroot mount
remain deployment gates. The phone was subsequently observed unlocked and awake;
the earlier lockscreen observation is not a current deployment blocker.

## Tests

```sh
python broker/tests/test_backend.py --unit-only
HEPTA_QAIRT_BUNDLE=/absolute/verified/bundle python broker/tests/test_backend.py
python broker/tests/test_token_count.py
```

The full backend suite compiles the real r6 supervisor and worker with their
explicit `HEPTA_TESTING` host identity, plus the frozen GenieX worker and new
counter linked to host-only SDK/tokenizer fixtures. Actual sockets, fork,
setsid, disconnect cancellation, native timeout, waitpid, process-group cleanup
and durable claims are exercised. The selector probe runs generated
`daily.main(--geniex-config)` through accepted owner frames to the original
typed parser; it never starts a listener or emits a phone action. Host evidence
is labelled `host_fixture` and the production validator rejects those contexts.
This suite does not establish phone SELinux permissions, model quality, NPU
execution or end-to-end app completion. Those require separate device evidence.

Some cloud environments prohibit AF_UNIX sockets. `--unit-only` is explicit for
that case; it is not a replacement for the full suite on a host with sockets.
