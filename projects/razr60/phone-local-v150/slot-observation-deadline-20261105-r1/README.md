# Slot-observation deadline source candidate

This review package repairs the provider's synchronous `GET /slots` observation.
The existing two-second socket timeout limits an idle gap; a server that sends
header or body bytes slowly can keep the call alive beyond two seconds. That
observation is used before inference and in recovery-related paths.

The candidate keeps one monotonic deadline across connection setup, sending,
header reads and body reads. It recomputes the remaining timeout before every
underlying socket read, and rejects a late complete response. An expired
observation remains `observed=false`, `idle=false`, with cleanup unknown and
`automatic_retry=false`. A socket close never proves server-side inference
retirement. The normal validated idle/busy response shape is unchanged.

Both the slot observation and the inference HTTP worker also reject a response
that ends before its declared `Content-Length`, even when the available bytes
form valid JSON. The worker preserves the exact partial bytes, returns its
existing `transport_error_result_unknown` state, keeps inference completion
unknown and does not retry. Its ordinary complete response behavior is retained.

## Public source and private source boundaries

The original `inspect_single_slot` function is byte-identical in the already
public [r7 provider](../provider/r7/source/provider_phone_local.py) and the
retained private provider whose full-source SHA256 starts with `082b02a4`.
`reference/` retains that exact function. `source/` contains only the reviewed
replacement and its four supporting definitions. The worker's original and
repaired `once` definitions are selected separately. The complete original
worker is byte-identical in public r7 and the retained private source set.
Standard-library imports and a direct-entry refusal surround these selections.
This is a source projection, not a complete provider or worker package.

[PROJECTION.json](PROJECTION.json) records complete-source hashes, exact selected
definition hashes, the two accepted three-file source sets, public dependency
origins and every published file digest. Whole-source hashes are provenance
references. No private binding table, device serial, key, user request, phone
log, deployment archive or complete private source set is included.

The [slot delta](changes/slot-observation.PUBLIC.patch) and
[worker delta](changes/http-worker.PUBLIC.patch) reconstruct their candidate
projections from the respective baseline projections. They are not patches to
apply blindly to frozen private source files.

## Reproduce the local checks

With Python 3.9 or newer and Git on a Unix host:

```sh
python3 -I -B tests/test_slot_deadline_projection.py
python3 -I -B tests/test_source_application.py
```

The test server binds only to numeric loopback and accepts one synthetic HTTP
request per case. It uses a temporary fixture-only key file. It does not contact a
phone, model or production service. The suite preserves both original slow
response failures, verifies the repaired header/body deadlines, and checks fast
idle and busy results, exact patch reconstruction and direct-entry refusals.
Every finite fixture server is joined; no signal, retry or model dispatch is
used. [HOST-FIXTURES.PUBLIC.json](HOST-FIXTURES.PUBLIC.json) records the local
results without ephemeral ports, process IDs, key bytes or private paths. Worker
cases exercise synthetic POST bodies and complete or truncated responses against
the same local fixture; they never invoke a model or native phone operation.

The source-application suite uses the parent tree's unchanged public r7 files.
Its optional `--private-source-dir` accepts the retained private set only for
local byte reconstruction checks; those bytes and paths are never included in
the result. All generated full-source outputs are temporary. The retained
[application summary](SOURCE-APPLICATION-CHECKS.PUBLIC.json) distinguishes which
source sets were actually checked.

## Apply to one accepted source set, without modifying it

The [source application tool](apply_source_candidate.py) accepts only these
three-file inputs, identified by their complete SHA256 values in `PROJECTION.json`:

| Input set | Provider before | Accepted daily source |
| --- | --- | --- |
| Public r7 | `8f57e86e…` | Its exact public r7 daily source |
| Retained private current | `082b02a4…` | Its exact retained private daily source |

```sh
python3 -I -B apply_source_candidate.py \
  --provider /operator/source/provider_phone_local.py \
  --daily /operator/source/daily_phone_local.py \
  --worker /operator/source/phone_local_http_worker.py \
  --output /operator/new-slot-deadline-source
```

The tool never imports or runs a provider or worker. It validates all three
original hashes, the selected-definition hashes and all expected output hashes
before writing anything. It writes only three new source files and a local application
receipt in a new directory; it refuses existing output, unknown input, mixed
input sets and output inside this publication package. In `daily_phone_local.py`,
only the provider/worker entries in `PARENTS` and `WORKER_SHA` change. All other
parent pins remain untouched. Both accepted sets use original worker SHA256
`a1f1c94f…`; the worker input is mandatory and cannot be inferred from another run.

**Generated complete sources can retain private bindings. Keep them local and
exclude them from publication.** This package intentionally contains only their
hashes and selected definitions. The private current output and the public r7
output are different complete sources, so their hashes are not interchangeable.

This source operation does not rebuild a package, revise a running combination,
apply SELinux policy, deploy, restart, retire an unknown operation or authorize a
replay. Full combination review and fresh physical acceptance are still needed
before adoption. Reverting an unadopted candidate means discarding the separate
output; the input and current runtime have not been changed.

## Qualification and timing limits

This is a D3 resource/lifecycle and D5 source-evidence candidate. It changes no
wire schema, task grammar, native effect authorization or existing physical
checkpoint. Host regressions add **zero** phone, model-health, component,
fixed-nineteen, business, cold-start or daily-use qualification. It is not a
production deployment or a complete fifteen-file runtime seal.

The deadline governs the observed HTTP socket work; local key-file access,
unpreemptible operating-system calls, scheduler delays and cleanup are not a
hard real-time wall-clock guarantee. A finite test margin accommodates local
scheduling and is reported as such. No end-to-end cancellation or remote
retirement proof is inferred from these measurements.
