# Settings homepage oracle — review candidate

This is an unadopted host validation change. It does not change an APK, configure a phone, send a task, or provide a deployment input. It is intended for review before a new suite is frozen. The publication commit is a storage base, **not** a claim that the exact oracle source baseline exists at that commit.

## Problem and change

The Motorola Settings home screen can hide its large title after scrolling. The previous oracle required both the literal title `设置` and the search entry `搜索设置` in the final XML. Two retained historical cases reached a real homepage but failed that visible-title predicate.

The patch changes only `core_assertions.py` and `core_phone_suite.py`. Four future templates—`settings_home`, `search_return_home`, `ordered_navigation`, and `cross_app`—keep the search-entry text predicate and stop requiring the collapsible title. Their instructions, action requirements, and visit order are unchanged. The other five templates are unchanged.

A new mandatory homepage oracle then requires all of these independent conditions:

1. The original owner instruction, task identity, terminal model-issued `done`, native raw bytes, app/model receipt, and original prompt bytes bind to the same request. A claimed success message alone is insufficient.
2. The complete terminal before/after observations are stable and belong to an observed active Settings root. The original native prompt must bind its size, IME state, complete node projection, and the six window fields actually projected to the model: scope, root bounds, bounds, type, title, and root class.
3. The independent WMS capture identifies one visible `.Settings` base application on the top-focused display. It must have the matching frame, visible view, a ready and drawn surface, and no occlusion. Explicit alpha fields must be opaque; missing alpha fields are not represented as a measured opacity value.
4. Other visible app windows, dialogs, notification shade, IME, overlays, and wallpaper on that display are rejected. Status/navigation bars are allowed only with the expected SystemUI owner and window identity, full-width thin top/bottom edge geometry, and no intersection with the verified search entry and the categories counted as evidence. A window type name alone cannot qualify an overlay as harmless.
5. The independent XML has one matching Settings root and the four specific homepage containers in the correct ancestor relationship. Its clickable search entry and at least three distinct top-level category titles must agree in label and bounds with the terminal observation **and** the original native prompt. Active search input and child-page toolbars are rejected.

The parser also rejects contradictory WMS window types, duplicate activity/surface records, missing or truncated evidence, unstable terminal observations, and changed raw/prompt/action bytes. Repeated identical `ty` values in normal per-rotation attributes remain valid. Global WMS footer records are excluded from individual window parsing.

This page oracle supplements the existing owner/nonce, native-runtime, APK/model identity, action-effect, sequence, and cleanup gates. `evaluate_one` continues to downgrade only a base pass; it cannot upgrade a failed or unfinished underlying task.

## What is included

- A minimal production logic patch with exact before/after file hashes.
- Existing core host regression tests with complete synthetic homepage evidence.
- Additional homepage and evidence-binding tests.
- A fixture generator that constructs fictional windows, XML, prompts, and receipts from scratch.
- A host runner, sanitized validation summaries, a synthetic passing log, and a limited independent review record.

**No real phone XML, screenshots, WMS dumps, prompts, app inventories, task/run identifiers, or raw model outputs are included.** Full production driver files are also omitted. The runner takes the exact pinned source/driver files as inputs and applies the patch only to fresh copies in a new output directory.

## Reproduce the public tests

Provide the two exact baseline source files and four driver files listed in `BASELINE.json`. Python 3.10+ and Git are required. The runner rejects other bytes before applying the patch.

```bash
python3 -B run_validation.py \
  --source-dir ../core-baseline \
  --drivers ../v27-drivers \
  --output ../homepage-synthetic-output
```

The default mode generates every fixture byte locally. It runs 77 test methods with 34 successful subtests, then separately checks the two homepage positives and the System SubSettings negative. This exercises parsing and binding; fictional native receipts are **not** evidence of a real native execution.

An authorized holder of the retained private snapshot can run the same production code and portable tests against it:

```bash
python3 -B run_validation.py \
  --source-dir ../core-baseline \
  --drivers ../v27-drivers \
  --output ../homepage-private-output \
  --external-fixtures ../private-evidence/fixtures
```

The private manifest defaults to `EVIDENCE-SOURCES.json` beside the `fixtures` directory; `--external-manifest` can specify another location. Its SHA must equal the pinned digest in `BASELINE.json`. All 36 retained files are checked before and after replay. Originals are read-only; negative mutations affect temporary copies. ADB, network connection, and subprocess calls are blocked during fixture generation, tests, and evidence replay. Git is used only before those guards to apply the patch to isolated local source copies.

`--output` must be a new directory outside this capsule. Private-mode output may contain temporary private evidence, so keep that output private. The distributable JSON summary deliberately omits raw content, node labels, absolute paths, and task/run IDs.

## Validated results and limits

Both the public synthetic run and the optional private run passed **77 methods and 34 subtests** with zero failures, errors, or skipped tests. Both used the same production source hashes. Patch application was checked and byte-compared to the pinned proposed source.

| Retained historical case | Independent page replay |
|---|---|
| `core-settings-home-01` | Complete visible scrolled homepage; accepted |
| `core-cross-app-01` | Complete visible scrolled homepage; accepted |
| `core-search-return-home-01` | System `.SubSettings` visible while actual `.Settings` hidden and without a surface; rejected |

The private replay concerns historical version 27 evidence and its pinned one-shot driver. The original formal nine-case result remains **2 pass / 7 fail**. No old result or frozen plan is rewritten. New templates must be frozen into a new plan before any separately authorized device run.

The independent reviewer inspected the production chain and the final hardening changes without executing tests. The reviewer found no new blocker in that limited host review; this is not a formal non-author GitHub approval.

This capsule does not qualify a current APK, warm worker, GPU/NPU runtime, offline networking, all apps, Stop/recovery, screen-off or folded use, sustained thermal behavior, or a new nine-case run. Its page layout and WMS assumptions are specific to the observed Motorola Chinese Settings UI. Unsupported layouts or recording schemas should remain unverified until separately supported and tested. Pixel-level visual occlusion beyond the retained WMS/XML is outside this oracle.
