# Source-freeze and controller semantics for a future preparation contract

This package implements an offline verifier for complete source-freeze originals, the original host controller, and the separately identified retained R10 failure reader. It checks supplied original bytes and metadata relationships. It grants no fresh execution, nonce creation, reservation, phone action, production adoption, installation or fixed19 credit.

The frozen R10 source and every sealed topology candidate remain unchanged. The earlier `preparer-next-generation` package remains an inert derivation of the reviewed 27,261-byte preparer. This package adds executable **verification functions**; it does not turn that inert file into a runnable preparer.

## Implemented checks

`verify_freeze_bundle` consumes an exact contract, separately bound complete membership-plan bytes, every required original byte string, and explicit file/directory observations. The source-freeze result cannot select its own members. The contract binds the source plan; the plan binds every frozen member and original input. All duplicate path identities must agree. A file cannot also be a directory ancestor. Absolute paths, traversal, aliases and NUL-containing paths are rejected where inappropriate.

The verifier checks complete original-byte identities and supplied full9 before/after/named identities, including nanosecond timestamps and excluding access time. Frozen files must be regular, private and single-link. All frozen directories and their exact sorted child lists must have stable private directory identities. Supplied observations are checked for consistency; this pure function does not authenticate the observer or establish that those observations are live.

The source-freeze format retains the current fixed layout: runtime 38 members, root chain 3 members and shared material 17 members. All six inherited admission sources must be present. `dependencies/DEPENDENCIES.json` is an actual bound frozen member, and the freeze's dependency-manifest descriptor must equal that member. This checks its exact bytes; the verifier explicitly does not claim to reverify all runtime import/deployment semantics.

The current freezer source must match its retained `FREEZER-SOURCE.original.py` copy. `FREEZE-RESULT.json` and `DERIVATION.json` must contain identical bytes. Exact payload accounting includes both terminal copies and retains the 32 MiB whole-directory limit. The manifest/combination/root `PKG`/source-parent record links and historical cardinalities must agree. History does not become current source credit. Qualification, automatic retry and rollback-admission claims retain their original limits.

`verify_controller` checks the original request, start, status and complete stream-read records. The request and launched job must agree on exact host, executable, source path/hash argument list and idempotency key. A reused launch, unknown launch, failed terminal, cancellation, timeout, automatic retry, incomplete output or nondurable output is rejected. Both stdout and stderr must have canonical bytes, exact offset/size/seen/stored counts, durable EOF, no truncation and no stream error. Stderr must be empty. The full stdout summary must bind the exact freeze, runtime/root manifests, combination and complete-directory byte count.

`require_new_generation` rejects the actual old R10 root, freeze, freezer, controller and idempotency identity, as well as old or declared consumed labels. `verify_new_freeze_with_provider` invokes this guard before its provider. It then performs two complete explicit byte/full9 reads, copies mutable metadata at the first bookend and rejects changed or nonprimitive observations. It returns material for the full verifier, with no complete-tree or provider-authenticity claim. The provider is a supplied capability; this function does not open files itself.

`verify_retained_r10_context` actually loads the exact sealed R10 reader through its pinned loader and invokes the complete retained-failure verification. Its envelope identifies this wrapper, that reader and that loader separately. The original phone terminal, phone-stage producer terminal, phone-stage writes and global effects remain `null`. The original nonce stays consumed. Retirement, replay, lease refresh, new nonce and fresh execution remain false. The old R6/R7/R8/R9 chain remains required and is not replaced by this context.

## Evidence and its limits

The portable suite uses explicitly synthetic source/controller originals. It exercises full positive source-freeze semantics and targeted rejections for missing members, six-source omissions, manifest cardinality, duplicate members, root-package identity, source tampering, controller identity/terminal/streams, accounting, full9 changes, impossible file/directory topology, nonprimitive directory names, stale labels, old-generation reuse and actual/declaration source mismatch. Synthetic originals are not host execution evidence.

The real retained R10 reference uses the independently fixed historical `FREEZE-RESULT.json` identity `651b4dd0f4f1c32b1928d58480e1adc3f2fcf104884db44b4eac52a0c625ba6d`, its 32,010-byte freezer source, and its 8,823-byte original controller. The replay harness reads the actual existing files without executing that freezer or preparer. Its historical membership adapter is generated from that fixed historical freeze and is kept as a new private audit original. It is **not** an independently reviewed future-generation source plan.

The actual replay checks 170 payload files, two terminal copies and 1,917 original inputs, then rereads every required path and the complete directory census. The exact final implementation, job, counts, byte totals and report hashes are recorded in the public safe report. Earlier report identities remain historical evidence. The old actual tuple must also fail the new-generation entry with zero provider calls.

The retained R10 context replay separately uses all 13 exact original roles, including the complete 125-file/126-member archive and original controller records. Its full nested result is compared with the independently loaded sealed reader. Only identities and safe summaries are public; original archives, raw request bodies and full private readsets stay outside this package.

These host readbacks do not measure a phone-stage budget. They do not prove a successful new freeze or new controller. There is no real new-generation positive fixture in this delivery.

## Reproduce the public verification

Run from this package directory, with the sibling retained-failure package at the published relative location:

```bash
python3 -B tools/verify_candidate.py
python3 -B tests/test_freeze_semantics.py --retained-base ../retained-r10-failure-v1
```

The portable tests do not open any private retained fixture or phone connection. They do not execute the reviewed production freezer or preparer. Default test output goes to stdout; an optional report path must be new.

For explicitly authorized private host reference work, `tools/replay_actual_r10_freeze.py` requires a new audit output directory. It reads only the fixed historical freeze and its complete bound source/input set. `tools/replay_retained_r10_context.py` requires an explicitly supplied private fixture directory. Neither tool is run by CI. Their full source is public so the evidence procedure can be inspected.

## Data and implementation still required for production

The new generation must supply an independently reviewed actual source/membership plan and matching freezer/controller originals. The current 38/3/17 layout and six inherited admission modules remain the verified contract; a changed layout needs its own explicit corresponding contract. The actual runtime source construction, import/deployment closure and policy adoption must be bound to that new combination.

A complete current phone preservation and producer/namespace disposition for the failed R10 attempt is still absent from this verifier. The retained host failure result supplies neither that disposition nor fresh authority. Future admission must preserve the R6/R7/R8/R9 chain and consume the new R10 failure facts without converting unknown effects into zero.

The production preparation path still needs the actual selected predecessor/NEG ordering, complete fresh input and preview, live identity and protected-draft CAS, existing fresh namespace checks, complete one-shot reservation and consumed nonce/label checks. The current inherited phone-stage budget and remaining-lease conditions must be enforced in their real execution positions. Those runtime consumers and side-effect adapters are not implemented by the pure functions in this package. The UNBOUND template cannot enable them by filling fields.

Independent GitHub approval, production source adoption, actual runtime qualification, formal BUILD, installation, independent health/business evidence and separately admitted rollback remain separate gates. Internal code review and source CI do not supply those facts.
