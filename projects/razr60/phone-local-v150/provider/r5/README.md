# Phone-local provider v150-r5

This isolated revision follows frozen v150-r4 source seal
700e5fb07e5ad250f4df5bd0452660b03dd0138b89718343e10e895c4db50d35.
Old sources, claims, consumed contracts, native failures, client receipts and
action intents remain unchanged.

## Changes

A: Health now uses an independent short system message plus the exact original
owner message. Its existing one-use contract still requires final-only JSON,
zero tools, one actual HTTP attempt, freely generated exact nonce, HTTP stop,
worker join and idle-slot evidence. The grammar does not force the answer nonce.

B: Business prompts list only tools in the same request's constrained schema.
All four global app aliases remain, with complete component identities including
distinct activities sharing a package. The model chooses the app, screenshot
coordinates, requested text and final status. Per-task authorization change C is
not included. The original typed mapper, visual one-tap, Unicode one-input,
return, postcondition and cancellation guards are unchanged.

Executor configuration admits only tool_client_r6.py at the state root, SHA
500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f.
No ADB or old endpoint fallback is permitted. New action intents use v150.2 and
bind the r6 endpoint/client. Legacy pending actions are never inspected on r6.
R6 receipt closure requires actual executor/worker domains, shell UID/GID2000,
cleared supplementary groups, verified worker handshake, one dispatch, child
join, absent process group and no lost wait identity. This proves only execution
termination; business success still requires its original public postconditions.

Identical original helper JAR bytes use a new readonly subtree:
- /data/local/tmp/hepta-phone-executor-v150-r6/helpers/unicode-input-v148r2.jar
- /data/local/tmp/hepta-phone-executor-v150-r6/helpers/screen-codec-v148r1.jar

Old helper/model/key files, permissions, labels and original PNG/XML expected
paths remain unchanged. New labels/public-tool permissions are independent
deployment inputs, not inferred from this source seal.

## Original-action recovery

Original action fc7bd6d939fb740a6403a04521fbb057 retains its original intent SHA
37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417.
Its native task remains provider_failed with original exit71 and error bytes.
The independent frozen verifier and separate Root review produced final proof
2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e.

The proof binds the actual live original actions FD, unchanged complete journal,
direct ENOENT, original client/native bytes, complete Unix-table EOF, retired
executor/group identities and disabled old services. Its trust boundary is the
reviewed sole-Root operating history; it does not prove absence of arbitrary
privileged tampering.

resolve_retired_action.py admits only this pinned proof and original intent.
It takes the existing provider daemon.lock exclusively/nonblocking and the
global ledger lock. --check-only validates without appending the resolution.
The explicit write retains exact proof bytes with O_EXCL and appends one v150.2
resolution state confirmed_not_executed_after_executor_retirement.
It does not invent a sidecar receipt or effect_started event. A crash between
the two appends may reuse only the identical original proof. Later ledger scans
revalidate its bindings. Existing claims and the failed task remain intact.
Old requests, text and actions are not replayed or retargeted; future tasks
require fresh identities/contracts and the pinned new executor.

## Operator entry

GNU state remains
/var/lib/trillionnium/owner-open/phone-local-v150/provider-state.
Keep all live claims and consumed bindings. The retained17 seed does not replace
the 24 accumulated live claims observed at retirement.

With Root's independent preflight complete and provider stopped:

/usr/bin/python3 -B /var/lib/trillionnium/owner-open/phone-local-v150/provider-r5/resolve_retired_action.py --state /var/lib/trillionnium/owner-open/phone-local-v150/provider-state --config /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r5.json --action-id fc7bd6d939fb740a6403a04521fbb057 --proof /var/lib/trillionnium/owner-open/phone-local-v150/retirement-r4-02/FINAL-PROOF-01.json --proof-sha256 2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e --check-only

The separately reviewed append uses the same command without --check-only.
Neither path contacts the executor or dispatches any phone action.
Read the exact retained proof and resolution back before new admission.

The independently sealed module owns the resident argv in SOURCE-SEAL-v150-r5.
It must check the actual retirement gate, source/config/runtime/policy pins and
single-worker boundary. It must not reset claims or automatically submit tasks.

## Validation and limits

66 focused host checks passed, with zero sockets/model requests/phone actions:
prompt/grammar available-action consistency, exact original owner text, unchanged
critical guards, r6-only configuration, legacy no-retargeting, negative proof
predicates, real temporary-ledger two-append crash recovery, old-task no-replay,
and exact r6 terminal credentials/process conditions.
The final check validates the actual final proof against the original intent,
imports all pinned production sources and checks Python3.12 syntax.
Host fixtures are synthetic and are not physical qualification.

The fixed19 protocol and limits remain:7 tools,8 model rounds,300s total,
120s/model round,256 completion tokens,24576 prompt bytes,1 inference slot.
Native r6 IPC/worker, public App permissions, fresh r5 model health, visual and
Unicode tasks, fault recovery, fold states, cold boot and unplugged operation
still require their actual qualification evidence. Historical failures retain
their original combination and status.
