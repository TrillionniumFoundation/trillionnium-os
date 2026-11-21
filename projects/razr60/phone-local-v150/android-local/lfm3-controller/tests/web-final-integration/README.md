# Bounded fresh decisions and read-only price observation

Two independently reviewed changes address different failures in saved phone
evidence. Neither changes the model, native runtime, task deadline, display
ownership rules or final business-completion contract.

## A page changed before the proposed click

The controller previously stopped when an otherwise authenticated capture
returned `unavailable` with the exact reason `DOM changed across visual
callback`. The observed failure happened before the executor, an action permit,
a query reservation or a native action had begun.

The new typed refusal is available only for that exact terminal response and
the same original task, authorization, lease, display, window, helper instance,
document epoch, observation, action object and model run. Existing or uncertain
dispatch/query state refuses this recovery. Its claim is consumed once. It is
recorded as an undispatched pre-dispatch refusal, never an executor outcome.

The controller uses the existing stale-round limit and original deadline,
obtains a fresh observation, and returns to the model for a new decision. It
does not replay the previous action. Cancellation, a third stale refusal, a
changed identity, other capture failures and evidence-write failures retain
their failure paths.

## One observed footer change during a natural-price request

A separate read-only observation scope describes two complete, observed footer
IMG records under one fixed certificate link. It requires the exact four-frame
visibility exchange, otherwise identical IMG records, unchanged link and
ancestors, unchanged DOM membership, separate geometry from the selected card
and all other observed controls, and unchanged selected-region style/hit/overlay
evidence. Unobserved listeners, image sources, global pixel visibility and
unobserved CSS are not proved by this scope.

This entry point is limited to the existing natural-price-only contract. The
original historical requests for a single unit, specifications and price
conditions remain outside this exception. Original legacy capture replays
must remain rejected; changing a test purpose creates a synthetic case, not a
passing replay of the original task.

The owned service independently validates the original captures and complete
native observations. The result does not grant action authority. Existing
action preparation, native dispatch, quote recheck, completion comparison,
target/display ownership and lease gates remain mandatory and strict.

## Verification scope

`HOST-VALIDATION.json` records the final input hashes, component gates and
combined gates. Counts distinguish production-method/control-flow tests with
mocked boundaries, pure-Java receipt verification, synthetic policy cases,
optional original-data replay and source-wiring checks. They are not phone
business-success rates, current Binder authorization, live native-action
qualification or a claim that arbitrary apps work.

The pre-dispatch runner is portable with JDK 17 and the pinned JSON dependency:

```sh
python3 tests/web-pre-dispatch/run_predispatch_host.py \
  --source . --output /tmp/hepta-predispatch-check \
  --java-home "$JAVA_HOME" --json-jar "$HEPTA_JSON_JAR"
```

An optional `--baseline-source` enables the expected behavioral red. An
optional `--actual-helper` supplies original private helper artifacts for
read-only replay; the runner does not publish those artifacts. Default tests
use synthetic inputs.

Android build, original signer verification and actual phone outcomes are
recorded separately. Earlier failed phone tasks stay failed. Native and Stop
qualification from earlier APKs applies only to their recorded scope and the
separately verified unchanged native inputs; no new device result is inferred
from host tests.
