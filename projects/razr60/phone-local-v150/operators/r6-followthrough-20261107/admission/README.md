# R6 original-attempt admission guard — source-only candidate

This candidate prevents a successor plan or Root entry from skipping the unresolved original `bound02` job while reusing the older, valid `final04` closed predecessor. It preserves the original `launch_unknown` outcome and grants no execution or qualification. The Mac frozen sources have not been changed.

## Problem and change

The frozen coordinator validates the supplied closed predecessor, but does not consult an authoritative record of attempts already made after that predecessor. Its output-directory reservation only prevents reuse of the same directory. Changing a label/nonce/output can therefore avoid that reservation while still presenting the older predecessor. The actual `successor02` preparer already selects `bound02`; the older GitHub checkpoint preparer selects `bound01` and is not the baseline used here.

`original_attempt_admission.py` retains one exact known unresolved original identity, including the controller request digest, PLAN/REQUEST hashes, nonce, boot/session/profile, runtime package, combination, and executed Root source. `ORIGINAL-ATTEMPTS.json` is a hash-pinned source-review blocker register. It is explicitly **not** a complete census of runtime jobs. Removing the required record, replacing it with another recovery, changing a successor nonce, or supplying a terminal/eligibility boolean cannot unlock this source. No disposition verifier or override exists in the candidate.

The guard reports the original terminal and original effect counts as `null`. The original cancellation request is recorded separately: one request was observed to time out without a cancellation receipt; signal count remains `null`, and termination/fencing is unproven. The earlier `bound01` sender's zero Send count and unconfirmed draft outcome remain a separate record. They are not used to infer `bound02` counts, or to infer zero UI effects.

## Entry coverage

| Actual function | New check occurs before |
| --- | --- |
| Coordinator `main()` | PLAN reads, original preview output, and execution |
| Coordinator `validate_plan()` | Any prior/plan admission reads |
| `Chain.__init__()` | Output-directory creation and original PLAN write |
| `Chain.run()` | Fresh lease creation and any child dispatch |
| Preparer `main()` | Helper loading and original preview/create path |
| Preparer `selected_context()` | Freeze/helper context reads |
| Preparer `create()` | Namespace reservation, nonce generation, and writes |

Both entry sources load the same hash-pinned guard through exact source bytes, without an ordinary import or bytecode substitution. The guard reads a stable, canonical, single-link original register and verifies its complete byte count and SHA256. Missing or invalid evidence produces a blocked decision.

The original `validate_current_prior()` is byte-identical: 6,303 bytes, SHA256 `e61d28c825c20cc92da82f2be29fbd64aafbd94221a90e28cb27076b30e973f3`. For both complete programs, removing only the new guard definition and its constant-stage calls leaves the original AST unchanged. Existing terminal/closure, source-parent, inventory, retirement, and NEG-01 → NEG-02 gates have not been relaxed.

The retained Root baseline also exactly matches the [already published PR112 Root source at commit 22e6105c2effe102c0f120a906752003aedfb37d](https://github.com/TrillionniumFoundation/trillionnium-os/blob/22e6105c2effe102c0f120a906752003aedfb37d/projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/checkpoint10/R6-root-final01/root-chain/source/run_component_root_once.py), Git blob `74ef273e628b70bead31650c22ae5f334cd3d1c1`. Its embedded transport configuration is retained existing public source. The `successor02` preparer was read directly from the Mac in this session; it is not claimed to be an existing same-named Git file. It contains source and fixed descriptors, without the private draft body. No complete private-evidence capture is included in this package.

## Exact source derivation

| File | Role | Bytes | SHA256 |
| --- | --- | ---: | --- |
| `reference/run_component_root_once.py` | Actual frozen Mac Root baseline | 78,567 | `53c2e7c26c960d76ac5d3201420d33f13fb06c241d30d40fc7b2b7577e690257` |
| `reference/prepare_native_bound_components_r6_fc33_successor02.py` | Actual Mac bound02 preparer baseline | 20,902 | `ff7f83db52bd067ffd6c41ebfd734a5414245c6e48224266da35fd2c37b9f77c` |
| `run_component_root_once.py` | Guarded Root candidate | 79,408 | `66324bd333190b2dbfc62a4ef6badc1f4e6829ff3bba6f551e39eacaeb53c3be` |
| `prepare_native_bound_components_r6_fc33_successor02.py` | Guarded preparer candidate | 21,567 | `df4d2a40d2df631cc598b6b79b6b6a095a3350287ad3925b62a6b9072d75751f` |
| `original_attempt_admission.py` | Shared admission evaluator | 10,422 | `e268d050959228423003717a63e57106d608cd763d5d977b3f376982e8e9da0b` |
| `ORIGINAL-ATTEMPTS.json` | Fixed reviewed blocker register | 2,943 | `331e135d43cbe8dc8fa4136ff2b1af40a2fb2fab1e83ed71533e2d29df3dde70` |
| `current_check.py` | CURRENT consistency checker | 3,887 | `b0015fb4455bf87c97e99a206c65235456cc9e7a8e9986fa9fbe2719d8bb1a59` |

`derive_guarded_sources.py` accepts only these exact full baselines and exact sidecars. It validates fixed output hashes, compiles the new sources, checks AST equivalence, and checks the unchanged predecessor function before creating a new local output directory. It never overwrites an existing output. From this directory, choose a new local output path:

```sh
python3 -I -B derive_guarded_sources.py --out /absolute/new/local-output-directory
```

`SOURCE-DERIVATION.json` records the actual derivation and checks. `changes/` contains the two minimal source patches. Apply neither patch to a different baseline.

## Single CURRENT decision

The project's authoritative `CURRENT.json` must contain the boolean `execution_eligible: false` and an `original_attempt_admission` object equal to the complete result of `evaluate_current()`. [CURRENT.fragment.json](CURRENT.fragment.json) contains those actual fields for merging into the project document. It is a fragment and does not replace the project CURRENT page.

The checker verifies its guard source pin, recomputes the decision with the same `evaluate_current()` used by both entry sources, and compares it with the stored CURRENT decision. It also requires top-level `execution_eligible` to be the boolean `false`.

```sh
python3 -I -B current_check.py --current /absolute/path/to/project/CURRENT.json
```

Exit **2** means the CURRENT document is consistent and blocked. Exit **3** means missing/invalid evidence or an inconsistent CURRENT. There is no success exit granting execution. Additional project status fields can remain in CURRENT, but cannot alter this admission decision.

The checker validates only the original-attempt admission subtree and top-level execution eligibility. It does not validate the remainder of the CURRENT page, BUILD/install/READY evidence, or the fixed 19-item ledger; those retain their existing readers.

## Host verification and existing CI

The local regression suite exercises the actual derived entry functions and four local CLI paths: coordinator preview/execute and preparer preview/create. The CLI fixtures install an audit hook that refuses child starts, network access, signals, and filesystem mutations by the candidate before observing its admission exception. Other cases cover a new nonce with the `final04` predecessor, deletion/duplication of the mandatory record, both bound01 recoveries used against bound02, forged terminals/fencing/zero counts, missing and changed registers, unconfirmed draft state, and CURRENT drift.

```sh
python3 -I -B tests/test_original_attempt_admission.py
```

For a new preserved test record, add `--report /absolute/new/report.json`. The author run is `verification/HOST-TESTS.author01.json`: **23 tests passed**, with no remote job or phone call. These are host source regression results, not phone execution or deployment evidence.

The test module provides `load_suite()` for the repository's existing `unittest discover -s tools/tests -p 'test*.py'` job. A wrapper can import this module by file path and return its `load_suite()` from the wrapper's `load_tests()` hook. `CI-WRAPPER.example.py` provides the repository-relative version; no new workflow is needed.

## Adoption and remaining disposition

The source package has not been refrozen or installed, and live enforcement has not been proven. The complete original frozen package/source manifests still describe the old bytes. A future adopted package must explicitly bind the new guard/register and actual entry sources; this candidate does not rewrite those manifests or claim a new runtime combination.

This patch intentionally establishes a hold, not a settlement. The existing historical retained-unstarted-stage and executor-retirement readers accept only their exact reviewed identities. A bound02 disposition would require its own verified original producer fence, retained original UNKNOWN outcome, complete effect/draft accounting, and reader/inventory/late-boundary integration. Directory absence, an elapsed timeout, the cancellation timeout, and a limited provider read with no match do not supply that proof.

The authoritative outcome remains `BLOCKED_ORIGINAL_ATTEMPT_UNRESOLVED`. The current original must not be replayed, relabelled as unexecuted, or replaced with a recovery for another identity.
