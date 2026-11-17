# Observation seal and mismatch diagnostics

This change extends the existing diagnostic record for a background native observation. It does not accept a graph, publish a screenshot, authorize an action, renew a deadline, or relax a window or task check.

## Why these fields exist

An observation can reach the screenshot stage and still fail either its screenshot-to-graph check or its later publication check. A phase duration and a changed graph hash show where the observation stopped, but do not identify which seal condition failed or which retained paths differed. The added fields report the values already used by that decision.

The diagnostic is evidence about an observation attempt. It is not evidence that a shopping or travel task succeeded.

## Contract

`last_pair_seal` records the original seal predicates in their original Java short-circuit order. A boolean records an evaluated predicate; null means that predicate was not evaluated. In particular, an absent later value must not be interpreted as false, and recording a predicate does not evaluate any later predicate. The three event equality checks record the exact two operands used by the existing comparison. `seal_created` becomes true only after the original private seal was constructed.

`last_publication_check` identifies whether the existing branch checked the frozen owned window or the full observed graph. Its event watermark and final decision booleans come from values already computed by that branch. They do not select a different branch.

`last_read_mismatch` retains only the latest existing screenshot-graph or saved-graph mismatch event. The record compares two existing immutable `GraphStamp` values only when package, background generation, owner, display, and window identities match. It records an explicit fixed reason when a value is unavailable or an identity differs. A stale read without a complete returned stamp is not replaced by a new read.

The difference is the existing bounded hash-based path difference, with no selected action node. Its existing limits remain eight reported node differences and 512 retained nodes per stamp. A partial retained stamp is never described as a complete tree. The count and truncation fields distinguish more events from the single retained mismatch. The latest seal, publication check, and mismatch are separate latest records; a later capture may have no mismatch, so these fields must not be treated as an atomic joint proof.

No node text or screenshot pixels are added by these observation fields. Temporary stamp references are discarded on reset, replaced on capture, and released at terminal status. Snapshots deep-copy the added nested value maps so a consumer cannot rewrite the tracker.

The existing 16 KiB serialized diagnostic ceiling remains. If the optional nested read difference would exceed that ceiling, the snapshot omits that difference and records the omission while retaining its mismatch and truncation metadata. The existing final size check still applies; an unavailable diagnostic must never replace the original observation result.

## Unchanged behavior and boundaries

The original predicate order, full-graph and frozen-window branches, event counters, root ownership checks, publication fence, stability budget, and screenshot scheduling remain. The Ctrip observation change adds no graph read, screenshot, platform call, UI input, retry, or new effect. It retains and compares bounded values from reads that already occurred.

The combined candidate also contains the separately tested Xiaomi early target-signature refusal diagnostic. That helper can obtain one subsequent bounded complete census after the original target signature has already failed. It still returns the original stale refusal. The rejected refresh and the later census are explicitly not an atomic pair; see `../native-action-integration/EARLY-REFUSAL-DIAGNOSTICS.md`. The Ctrip no-additional-read statement does not erase that separate helper's behavior.

A more capable model cannot make an expired or changed target current. This patch does not permit rotating search hints, remove the early target signature check, or treat all dynamic page changes as harmless.

## Host verification

The existing `tests/observation-diagnostics/run_host.py` entry point compiles actual Service observation, callback and snapshot methods, the real pure tracker, and the actual Controller consumer. Android graph, clock, callback, authorization and filesystem endpoints are explicit host fakes.

The added cases cover short-circuit behavior, exact event operands, bounded path differences, wrong package/generation/owner/display/window, absent or wrong-stage stamps, reset and terminal reference release, nested snapshot immutability, and explicit byte-limit omission. Extracted-pipeline cases check original read and screenshot counts, unchanged stale refusal and file cleanup, the unsealed branch, and unavailable or foreign-window stamps.

The existing native action integration entry point continues to execute the Xiaomi refusal cases. Canonical CI must run these existing entry points on the final complete source; targeted host success does not qualify Android scheduling, the installed package, profile cleanup, device latency, or business completion. No private phone dump is included in the new observation fixtures.

## What a later behavioral change would require

For Xiaomi, the current action comparator also protects the query entry, hint subtree, signatures, and semantic facts. Skipping only the earlier signature refusal would not establish safe hint equivalence. A future narrow policy needs actual same-worker evidence that the installed-version target, owned task/window, original live reference, geometry, capabilities and relevant ancestors remain the same, with every changed field explained. Both the initial and later action checks would need a separately reviewed consistent rule.

For Ctrip, actual new records can distinguish a failed seal predicate, unavailable complete read, identity change, event fence failure, and bounded retained content difference. They cannot by themselves prove that omitted nodes or events were harmless. Any later fix must preserve the owned-window identity and action freshness checks. This diagnostic change does not extend the settling or total observation deadline.
