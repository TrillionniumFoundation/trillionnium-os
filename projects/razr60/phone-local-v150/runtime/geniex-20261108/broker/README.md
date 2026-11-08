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

The original v1 profile keeps QAIRT grammar disabled: its official v0.10.0
discriminator aborted with `Grammar constraint violated: EOG token not allowed`.
The separate v2 candidate explicitly selects the reviewed R2 core and requires
a schema-derived output grammar. It has not been promoted to production.
Both versions retain the original strict parser; neither repairs output or
extracts a convenient JSON substring.

### Explicit v2 grammar candidate

`hepta.provider-geniex-native.v2` adds a pinned `schema_compiler` descriptor and
the backend fields `grammar_profile`, `core_android`, `core_sha256` and
`schema_compiler_sha256`. The current profile is
`qairt-output-grammar-core-r2-v1`, with core SHA-256
`06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d`.
The core must belong to the configured plugin directory and first private
library search directory. The counter command verifies its exact bytes before
any model process. The original profile cannot silently enable grammar.

The reviewed standard-library Python converter is copied from
`../schema-grammar-python-r1/python_schema_grammar.py` to the new private
candidate as `schema_grammar.py`; the original daily source-pin check verifies
it before import. Its source digest is
`c230e076ae61c87a744c49b160a456c039d47441784ad3ccc2c6465bc67453a8`.
It accepts only the reviewed closed mobile-action and health-schema subset,
rejects unknown features, and binds original schema bytes, canonical schema,
grammar bytes and compiler source in a conversion proof. This proof does not
pretend a separate compiler process ran. The existing GNU state mount remains
`noexec`; the converter runs within the already selected Python interpreter.

The grammar preserves the allowed JSON values using a conservative fixed-order
serialization language. It is not a claim to accept every JSON spelling.
All currently allowed App aliases remain in the prompt, along with the exact
owner text, full semantic history, observations and postconditions. The
unrelated click example is absent from the grammar profile. Grammar bytes are
loaded separately from model context; the 3584/256/256 budget is unchanged.
The unchanged parser and typed mapper still validate every generated result.

Actual isolated R2 phone tests passed the grammar discriminator, text recovery
and two constrained synthetic image decisions. Malformed grammar still caused
an SDK abort rather than a graceful error result, so the five-case suite was
not wholly successful. The original runtime, stop and retained claims remain
unchanged. These results establish neither production-domain access nor App
operation qualification.

## Configuration and deployment prerequisites

The original configuration schema is `hepta.provider-geniex-native.v1`. Its top-level
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

The deployment candidate uses a new shell-owned 0700 staging directory under
its private state instance, exposed through a new Android alias
`/data/local/tmp/hepta-geniex-stage-<fresh-instance>`. The existing GNU state
bind exposes the same ordinary directory without a nested mount or a write to
the immutable root's `/run`. The deployment manifest must record the actual
instance, explicit paths and observed directory device/inode identity across
all views. Configuration rejects a missing or mismatched mapping and does not
change any existing state-directory mode. This mapping is prepared but has
not been activated on the phone.
The provider owns its separate 0700 evidence directory; staged inputs and
outputs remain 0600 and owned by the supervisor's fixed execution UID 2000.

The current device has not qualified this backend under the exact production
`trillionnium_owner_open_phone_worker` domain. Root-only model tests do not
establish that permission. The existing r6 supervisor also requires an exact
bootstrap-domain caller for execute; a Magisk caller is restricted to health
and inspect. No alternate UID, `runcon`, permissive mode, device-node chmod or
unreviewed policy is enabled by this backend. A separate init-owned startup
and narrowly scoped staging-policy candidate is under review. The existing
owner stop and absent GNUroot mount
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

### Timeout classification follow-up

The R3 checkpoint incorrectly merged a proven native supervisor timeout with
accepted cancellation, so the provider could report `unknown_model_failure`
instead of its existing `model_timeout` category. The follow-up preserves the
original native cleanup validation and distinguishes three outcomes: an
accepted owner cancellation remains cancelled; a proven supervisor timeout is
`model_timeout`; a frozen worker deadline is `model_timeout` only when its exit
124 is accompanied by original metadata bound to the request, process, model,
SDK and exact input hashes. Exit 124 without that metadata remains a failure.
No timeout outcome accepts model text or authorizes a phone action. Missing
native termination proof remains UNKNOWN and blocks later backend requests.

`evidence/host-timeout-r1/HOST-VALIDATION.json` records 23/23 complete backend
tests and 38/38 original private r9 regressions on pocket4. The selector probe
ran six scenarios for both the public and actual private source candidates:
valid output, malformed output, session deadline, native timeout, owner cancel
and worker deadline. The host-only deadlines were shortened to 500/1500 ms;
production profile parsing retained 55/60 seconds. The source binding/import
check also passed. These results preserve, rather than replace, the earlier
R2 reports and do not confer the original fixed-19 phone qualification.

### Grammar integration regression

`evidence/host-grammar-python-r2/HOST-VALIDATION.json` records 27/27 complete
backend tests and 38/38 unchanged original private r9 regressions. The selector
probe covered six outcomes for each public/private v1/v2 combination: valid
output, malformed JSON, task deadline, native timeout, owner cancellation and
frozen worker deadline. The actual converter executed against generated
private schemas; the native model SDK in this host suite was an explicit stub
and did not enforce GBNF. These results validate integration and failure
handling, not model accuracy or phone execution.

The converter's separate 18/18 host suite includes an independent C++ GBNF
recognizer and 4515 integer-boundary cases. A further private comparison used
the two real r9 action schemas with all 53 registered App entries and found
agreement for 1075 tested JSON values. Their original bytes were retained.
The original phone proc library also constructed both generated grammars in
CPU-only probes, without loading QNN or a model. The original fixed19 phone
qualification counter remains 0/19 until its exact tests are executed.


The fresh full-catalogue R2 phone check subsequently passed both constrained
model samples: first open at 964 counted/SDK prompt tokens and a click after
three synthetic prior actions at 1991/1991. Original strict parsing and
semantics passed without output repair. The model processes took 13.445 and
17.098 seconds, excluding the separate approximately one-second counters.
These are two samples with all 53 registered App entries, not 53 executed App
tests; zero UI actions were dispatched. The report is
`../evidence/qairt-catalogue-grammar-r1/PUBLIC-SUMMARY.json`. The malformed-grammar
negative and production/fixed19 qualification status remain unchanged.
