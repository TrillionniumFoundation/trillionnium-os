# Failure cleanup for an already-owned sender

This package makes one host recovery change reviewable without publishing a production launcher or its environment bindings. It contains exact extracted definitions, a public diff, a local process fixture, and a hash-pinned full-source transformation helper.

## The failure being addressed

The coordinator could reject an early component phase while its already-started sender was still finishing. Its failure handler immediately stopped output capture. That preserved an honest unknown state, but lost the opportunity to observe the original child's exit and the remaining stdout/stderr within its existing budget.

The candidate gives that one already-owned sender a bounded drain before the readers are stopped. The original phase failure remains the Root result.

## Behavior and control exits

The failure handler verifies that the sender tuple, owned-child map and capture object refer to the same original `Popen`. An already stopped/finalized capture, expired original deadline, or mismatched handle remains unknown. No new child is started by the drain.

The unchanged join implementation uses `min(original execution deadline, now + 30 seconds)`. Complete host output requires the original child wait, both pipe EOFs, capture-worker join, persistence and original output identity checks. A nonzero sender return code is retained. Host output completion does not establish a phone terminal or cleanup.

An initial `KeyboardInterrupt` or `SystemExit` skips the drain. A control exception raised from the drain join is retained as the same exception object while owned readers are closed. `main()` writes the original phase failure and a control-exit summary, then raises that original control exception with the phase failure as its explicit cause. `SystemExit.code` is preserved. An ordinary drain error keeps the original phase error as the exception that propagates.

## Public extraction and provenance

`reference/host_transport.py` and `source/host_transport.py` are **host-only fixtures, not production launchers**. Their selected 17 global definitions and six `Chain` methods are sliced from the exact full sources without reformatting. Every included definition has byte and AST fingerprints in `PROJECTION.json`.

The production constructor, run body, admission logic, environment bindings and remote methods are absent. The sole admission stub raises an error; direct execution of either public fragment also refuses. The test harness supplies only local fixture admission, construction and a failing run body. `changes/public.patch` is the diff between these two public fixtures; it must not be applied to an older public launcher.

| Source | SHA256 | Bytes |
| --- | --- | ---: |
| Required private full baseline | `dcb380efb71ddf76db046eeac34be745928c773b2071da82776a39956bce215b` | 72,674 |
| Current private full candidate | `37742ec5b5bec83d6060743560bc1b732b5ce8d30a74bc15184f4220534a98d4` | 76,328 |
| Public reference fixture | `f37c5b11a0d29bfac82665f4297facf968c887ec285efe061a5f0db299f428fd` | 30,142 |
| Public candidate fixture | `b4940660de4ef6639cd4fdbf947ea46dd5d21daa2817c498adb2d1a19ae6610e` | 33,717 |

The earlier `48e676fb…` candidate is superseded: review found that its drain caught control exits and then re-raised the older phase exception. This package includes the correction and targeted regressions. No other baseline, including an older published launcher, is accepted by the full-source helper.

## Run the public local fixture

Choose a new output directory outside this package for raw local records, and set `DRAIN_FIXTURE_OUT` to that directory. From this package:

```sh
python3 tests/test_control_exit.py \
  --source source/host_transport.py \
  --source-sha256 b4940660de4ef6639cd4fdbf947ea46dd5d21daa2817c498adb2d1a19ae6610e \
  --out "$DRAIN_FIXTURE_OUT"
```

The six cases cover `KeyboardInterrupt` and `SystemExit(23)` after the actual join is entered, an ordinary drain error, both initial control exits, and a completed sender after the original phase failure. The harness uses real local children, audits process starts, and refuses network access and signal calls. It distinguishes its later natural child cleanup from any wait proven by the production failure handler.

`HOST-FIXTURES.PUBLIC.json` contains safe summaries of six full-source cases, six public-extraction cases and seven transformation/entry checks. An independent reviewer separately reran the two during-drain control cases and verified the six-case author descriptors without relabelling them as independent executions. Raw test records remain outside the package. The earlier eight-case evidence, including the actual 30-second wait-cap run, is labelled as evidence for the superseded source. Deadline and join logic did not change in the control-exit correction; that long case was not repeated.

## Produce a private full candidate

Only an operator already holding the exact private full baseline can use this helper. Set `PRIVATE_BASELINE` to that source and `PRIVATE_CANDIDATE` to a new private output path outside this package:

```sh
python3 apply_source_candidate.py \
  --source "$PRIVATE_BASELINE" \
  --out "$PRIVATE_CANDIDATE"
```

The helper checks the entire input size and hash, compares the selected original definitions with the exact public reference, applies the two definition replacements and one constant addition, and checks the entire output size and hash before exclusive creation. It rejects a public fragment or superseded candidate as input, rejects output inside this package, and never overwrites an existing output. Keep the generated full source outside the publication allowlist. Creating that file does not execute, install, freeze or adopt it.

## Qualification boundary

These are Linux host controls and source transformation checks. They grant no Mac or phone end-to-end qualification, no native recovery closure and no business success. They cannot reconstruct a lost historical owner wait or diagnose an underlying provider rejection without its original records. The 30-second cap bounds the wait; the existing lack of a hard real-time bound for filesystem, spawn and cleanup remains explicit.
