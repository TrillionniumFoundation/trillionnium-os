# Phone-local provider v150-r6-r2

This is the minimal runtime source-pin closure after the real r6-r1 startup failure.
It does not change the health parser fix, decision prompt, schema, mapper, action ledger, budgets, cancellation, receipts or postconditions.

## Exact cause and change

The installed r6 health_contracts.py is 00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d.
The r6 daily entry still expected the old health hash 9f2d87bc567c7b169d0d4d07635ab233ccef6da45ba8f547c8af7751f3686c44 in its PARENTS table.
Thus correct deployment bytes were rejected before the provider could start.

Only that one hash literal changes in source/daily_phone_local.py.
New daily: 19,981 bytes, SHA256 0999a3609a89520ed8e1f550fa28c86959137d1edb98994f7ad78fe35db42a57.
Reverse substitution is byte-exact to the frozen old daily 5ef7c55a...
The other 12 production files, four operator helpers, fixed 19 protocol and configuration bytes are unchanged.
The previous provider-r6 directory and its failed startup originals remain immutable.

## Runtime dependency closure

validation/RUNTIME-PIN-CLOSURE.json inventories all 13 production and four helper Python files.
The actual 12 PARENTS entries match their actual sibling SHA256 values; WORKER_SHA matches the actual worker too.
No old health hash remains in those 17 files.
Unchanged external hashes identify the helper JARs, executor client and original retirement proof/receipts.

The actual 6,273-byte PHONE-SERVICE-INPUTS-v150-r3.json ccb7... does not contain provider-source paths or hashes.
The actual 1,305-byte configuration 0eb7... binds that manifest and the unchanged executor client; it does not bind the daily or health source.
Both therefore remain byte-identical.
The module provider role-expectations row pins the unchanged GNU Python ELF, not the daily file.
The module launcher, payload/source seal and installer ready checks must bind this new source/config path.
ready.json source_sha256 is computed by the actual entry as sha(__file__) and must now equal 0999a360...

## Real host entry checks

validation/REAL-ENTRY-PREFLIGHT.json records actual isolated executions of original code:
1. Old daily --help reproduces RuntimeError: protocol source pin differs.
2. New daily --help executes all 13 production modules and exits 0.
3. New daily main reads the unchanged real config and executes its argument, endpoint, model, resource, App and executor-schema validation. A trace boundary stops before the first external phone-client filesystem lookup.

No runtime function is replaced with a test implementation. An audit fence rejects network/socket, process launch, state mutation and private-key access.
The successful candidate checks execute the real source-pin gate and actual import chain.
The original expected-failure case is retained as an original failure; the harness exit 0 means its expected outcome was observed.
No key was read, no state/claim directory was created, no service listener was opened, no phone/model call or nonce was made.

These host checks do not establish actual phone startup or client/key availability.
Root must install the new immutable combination and observe its real READY/terminal independently.

## Installation targets

GNU source:
 /var/lib/trillionnium/owner-open/phone-local-v150/provider-r6-r2/source
GNU config:
 /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r6-r2.json

The common provider-state and all historical claims, failed native turns and action receipts remain unchanged.
The exact startup argv is in SOURCE-SEAL-v150-r6-r2.json.
The payload archive contains 22 regular files and is independently read back; its manifest is separate to avoid a circular hash.

A new health uses a new nonce only after Root's real startup review.
Old health inputs and actions are never replayed.
