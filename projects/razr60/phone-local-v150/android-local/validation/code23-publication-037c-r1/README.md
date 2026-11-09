# Code23 public source and qualification boundary

This publication builds on commit
`cc4a7035760383a126e4510002139d88667e0b97`, preserving its published Code21
history, owner-confirmed recovery and privacy derivative. The added source
combines the reviewed deadline repair, experimental LFM/Qwen registrations,
and the click-policy delta from `47be96088bb43d42af4ae107c849f97d56b1be4d`.
It does not move the parent or any other feature branch.

## Source identities

- Retained frozen Code23 r2 source manifest:
  `e445eec726a79a5d4340fff33125c6db9210f839885b8985175ba3dde26a07eb`.
- Public derivative source manifest:
  `5559ef2ad8e9b7e8d886dfc9f3bf6b4cce2fde7170a7cb40ba0b6ce1061a8b4f`.
- Version: 23 / `0.23.0-local-deadline-moe-qwen`.
- Membership: 1,109 files plus the source manifest.

`SOURCE-MAPPING.json` records the exact relationship. All 86 Java/native source
files in the listed production/native scope and all 188 recorded host-test
inputs are byte-identical to the frozen candidate. The public derivative keeps
four existing Code21 privacy-safe validator/reference files and the historical
Code21 `HOST-CHECKS.json`. Those five differences are explicit; the public
manifest is not relabelled as the original retained build source.

No phone screenshot, private prompt, device identifier, credential, private
signing material, or raw diagnostic session is added. Synthetic tests remain
ordinary repository source. The separate host summary preserves the original
result identities without publishing host environment or raw phone evidence.

## Behavior

Each action cancellation token now includes the original task deadline and
per-wait retirement. Only the first callback owns the result. A received real
action acknowledgement is persisted before Stop or deadline ends subsequent
work. The existing eight-second missing-receipt path remains unknown/blocked;
there is no late-callback replay or fabricated clean result.

Full direct labels and descriptions are classified with the existing execution
policy before display truncation. Prompt click capability, finite grammar and
post-parse validation use the same eligibility. The fresh executor policy and
existing editable-field exception remain. The newer event-history and
same-state no-effect protections are retained, rather than replacing the full
controller with the older PR121 file. The bounded-descendant-text limitation
remains explicit.

The closed registry adds `lfm2.5-8b-a1b-q4_0` and `qwen35-4b-q4_0` with exact
artifact hashes, sizes and architecture identities. Existing defaults remain
unchanged. These profiles are experimental, text-only, and not qualified by
registration. Qwen is an identified Unsloth conversion; availability thresholds
are admission policies, not measured RAM results. No network permission or
external-model fallback is added.

## Evidence and CI

The frozen candidate passed 69 host gates, including 199 Python tests, 25 action
deadline contracts, and 19 synthetic click-policy scenarios. The original 18
click scenarios remain and an additional case exercises the actual pure
same-state guard through the merged projection. Registry contracts run in
Java, native C and Python. `HOST-SUMMARY.json` identifies that actual host run;
the public derivative was not represented as a separate full host rerun.

These checks do not establish Android callback scheduling, model compatibility,
NPU execution, semantic action quality, ordinary lifecycle behavior, or phone
task success. The click-policy repair is not asserted to solve an observed
valid-domain model error.

The first publication commit retains strict older CI helpers. They do not admit
this new manifest. A separate successor commit will version the exact-source
helpers and preserve all compiler, native/runtime, ABI and current-run receipt
checks. An old-pin rejection remains a rejection; no prior green run is reused
as fresh qualification. This work remains Draft and does not merge or deploy.
