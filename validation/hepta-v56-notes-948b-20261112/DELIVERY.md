# Validation-only delivery for root review

Proposed repository destination: `validation/hepta-v56-notes-948b-20261112/`.
This directory is outside `projects/razr60/phone-local-v150/android-local/lfm3-controller/`.
Publishing these files must not change canonical production commit 5da3c83fe46edb2617934a92c06a10608accb68e's component tree 24e8d82d4befdab6f4f32ef7efeba7faad345a04 or production SOURCE-MANIFEST a0835cd66f81f3c4c770b92256742b90188b0664c6a274c29086bae03d1c39ec.

## What this delivery contains

It contains the actual offline generators, strict artifact/config binder, semantic scroll gate, audit scripts, minimal source diffs, current README, exact hash references, and original output JSON from checks that were actually run. The signed APK, receipt, fresh package UID, physical display and runtime remain unknown. Nothing here is a sealed runnable phone bundle or evidence of a v56 phone pass.

The 14 complete original inputs, three historical derived verifiers, historical full phone result/replay data, canonical source copies and all original screenshots remain in the private working cache. They are deliberately not included. Public provenance and exact expected bytes/hashes are in references/SOURCE-REFERENCES.json. Some referenced evidence records bind an original hash without embedding the original source; do not assume every required byte can be recovered from the public package alone.

## How paths are interpreted

Pass the private reviewed working cache as `--root` when running prepare_v56_sources.py, seal_v56_notes.py or the audit scripts. The copied scripts need that cache's exact BASELINE-CLOSURE.json, source-stage-v56-r1, reviewed-v54-replay, github-originals and canonical-v56 paths; these are inputs, not generated defaults. The public `references/` records describe those private inputs but do not silently replace them. The published scripts can live outside the cache. No download or device operation occurs automatically.

Runtime schema correction r3 requires exactly schema/model_profile/compute/context_tokens/threads and schema hepta.local-runtime.v2, plus the real canonical threads range 1..8. Its 16 negative controls are separate from the earlier 112-function source-preservation review, four rejecting CLI probes, 19 historical-context controls and 14 extra image/input controls. Those counts must not be summed into a phone suite pass.

## Approval and handoff

Root reviews MANIFEST.json, source diffs and actual result JSON first. qualcomm_backend may publish the exact approved file set to the component-external validation path. This preparation did not push or modify the parent freeze. After publication, verify every file's Git blob and complete SHA, and verify the production component tree is unchanged.

A final runnable bundle still requires the real signed receipt and APK full-byte hash, actual build source inventory, source semantics review, and fresh device identity under normal cooperative ownership. The current CANDIDATE-TEMPLATE-background-r1.json is intentionally unsealed and must not be filled using historical device defaults. See README.md for the ordinary preparation/Start sequence and semantic-main-screen conditions.
