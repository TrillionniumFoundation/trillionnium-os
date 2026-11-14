# Native Xiaomi login navigation boundary

The portable fixtures describe a complete 13-node public native login form.
They are explicitly synthetic: task and observation IDs, lease, window,
display, installed UID, capture time, geometry and hashes are deterministic
test values. The literal return control, public login labels, empty phone
placeholder and unchecked agreement state model the supported UI structure.
No device receipt, private source path or screenshot is included. Node and
frame hashes are synthetic values; the observation-record hash binds the exact
portable JSON bytes. `fixtures/PROVENANCE.json` records this boundary and the
three fixture file hashes. This page does not prove that public browsing
requires login.

The parser offers only the actual `com.xiaomi.shop:id/back` node labelled
`返回`. The Session requires a fresh model decision and reserves one return
attempt. Its Domain offers that node click or failure reporting, without global
Back, waiting, credentials, agreement or external account actions. A persistent
or recurring login page after a reserved effect admits only failure reporting
and asks the user to handle the current page.

The only reservation release uses the private original Attempt's actual
action-execution projection: same task/model/observation/authorization/window/
display/generation, unretired current callback, explicit no-effect/no-return/
null acceptance, drained worker and original bounded clock. The release is
journaled before state changes. A fresh observation after drain and a new model
run are then mandatory. Boolean stale flags never release the reservation.

The gate compiles the actual parser, Session, Domain, grammar and completion
gate, and extracts actual Controller receipt projection and
scope/background/target-refresh service bodies verbatim. Tests carry explicit
JSON nulls through that real projection into the Session. A present null or
nonobject native action guard must reject the projection and retain the login
reservation; a present object guard must also retain that reservation.
Cases cover complete/missing/duplicated/unknown controls, account
exclusion, current targets/windows/packages, persistent login, reservation
identity/timing, ambiguous effects, durable write failure, stale replay, Stop,
and preservation of the separately proved query/card/detail completion chain.

Android endpoints, every capture, model callback and worker receipt, the
installed verifier, clock, journal failure and cleanup are explicit host
fixtures. No phone, model, credential, consent, login or return click runs.
A host effect counter is not Android dispatch evidence.

```sh
python3 -B tests/native-xiaomi-login/run_host.py \
  --source /absolute/component --output /absolute/fresh-output \
  --java-home /absolute/full-jdk17 --json-jar /absolute/json-20240303.jar
```

The optional `--previous-source` accepts the exact frozen c8a1 baseline. Its
real parser must compile, then fail the wanted capability probe at runtime with
the `unrecognized_native_page` result. Compile failure does not count
as that negative control. Reports retain source/tools before/after hashes,
stdout/stderr, all generated files and extraction records, individual case
records, combined `CASES.json`, and `RESULT.json`.
