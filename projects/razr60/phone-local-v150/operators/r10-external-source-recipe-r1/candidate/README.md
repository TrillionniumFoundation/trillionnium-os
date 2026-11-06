# Fixed external source recipe: consumer structure candidate

State: **UNBOUND_SOURCE_ONLY_NOT_INSTALLABLE**. This package changes the source-proof data transport. It neither applies a policy nor runs a phone case, a source cascade, a release builder, or any fixture runtime/provider member.

## Problem and change

The measured 32-member runtime byte assembly and repaired shared 17 require a 96,950-byte canonical inverse recipe, compressed to 29,690 bytes and encoded as 37,113 Base85 characters. Embedding that packet into the 122,789-byte preview22 release helper would produce a 160,190-byte source, exceeding its existing 131,072-byte limit by 29,118 bytes.

The candidate instead reserves one source-frozen `EPOCH_SOURCE_RECIPE_DESCRIPTOR` containing a canonical absolute path, exact byte length, and SHA-256. The recipe is a separate JSON **data original**; it is not a runtime module and does not change the fixed 32 runtime members or the fixed 17 shared members. The test packet is 37,393 bytes. Its deployment descriptor remains `None` until the complete actual runtime generation and its authorities are reviewed.

All three full consumer files contain the same pure verifier. Its `recipe_raw` argument is mandatory and keyword-only. The verifier checks those immutable bytes against the descriptor in the reviewed consumer source, rejects duplicate JSON keys, nonfinite numbers, noncanonical JSON, unknown fields, malformed or oversized data, and then retains the complete existing two-stage inverse:

1. Current exact runtime32 / shared17 / combination to the fixed pre-epoch codec generation `de120154…`.
2. That exact codec generation to actual closed902 `31da1d92…`, followed by the existing historical `67dc4047… / c50a219e… / 54b1d9ae…` proof view.

The old inverse range, removed-span digest, reconstructed byte, source-size, decompression, and exact membership checks remain. No executable source compression or evaluation of reconstructed historical sources is introduced. The proof schema is version 2 and includes the exact recipe descriptor.

## Every entry is wired

| Entry | New data path | Execution boundary |
| --- | --- | --- |
| Release helper | `source_recipe` is an exact component-input field, collected into the existing bundle original pool and required by the bundle's closed inventory. | The pure gate runs before `validate_component` loads runtime sources. `component_modules` independently repeats the same gate immediately before its first runtime `exec`. |
| Component constructor | The plan includes the source-frozen descriptor. `collect` reads it through the same decoded pool, observation map, and final bookend as other originals. | Both the initial pure gate and subsequent `component_modules` receive the same immutable recipe bytes, runtime32, combination, and shared17. |
| Cascade | `epoch_recipe_original` matches the frozen finalization descriptor to the source constant and uses the existing `original/read/OBSERVED/recheck` path. | The four original source domains plus the fixed recipe are verified before current runtime modules are loaded. The source view passed to the release loader includes all five immutable inputs. |
| Interface | The same recipe loader uses the existing `original/read/SEEN` path. The delivered helper's literal descriptor must equal the independently bound interface descriptor. | The interface compares the delivered helper's pure result with its own complete result and passes the same inputs to the loader gate. |
| Source preparer | `EPOCH_SOURCE_INPUTS` now has five exact descriptors. Its CLI descriptor must equal those source-bound inputs; the imported cascade independently checks the recipe authority. | It retains the recipe original in its create-only source output, with the existing source observation and reread sequence. |

Changed exact envelopes are component input v8, construction plan v9, construction result v8, finalization v4, and source increment proof v2. Old envelopes cannot silently omit the new original. The source pin cascade updates the two changed template pins, the two generator source descriptors, the generator manifest, and the preparer's manifest pin. The untouched 17 template pins are checked against the complete previously fetched 19-template manifest in the regression suite.

## Limits and physical reading semantics

The existing 32 MiB limits are **decoded original/source pools**, not a universal physical disk-read ceiling. This candidate does not reinterpret them or add a new cumulative physical-read cap. The recipe's complete file bytes join the source gate's 32 MiB input total and the release/constructor decoded original pool. The existing recipe inner-data bounds remain: at most 65,536 Base85 characters, 52,428 compressed bytes, and 262,144 decoded recipe bytes. The external JSON original has its own stricter 65,536-byte file limit.

| Reader / scope | Existing guard retained | Direct recipe-file reads added by the reviewed normal path |
| --- | --- | --- |
| Release `prepare_bundle` | Per original 16 MiB, 32 MiB decoded pool, 32 MiB serialized bundle, shared 150-second component verification deadline; canonical path, no-follow leaf, regular single-link file, full9 held/named equality and final reread. | One collection plus one final bookend: 2 reads, at most 131,072 returned file bytes. |
| Constructor `build` | Same helper reader, decoded pool and 150-second deadline; observation identities and final reread. | Initial collection, later descriptor closure collection, final bookend: 3 reads, at most 196,608 returned file bytes. |
| Cascade `read` | Per original 16 MiB; exact source/package/descriptor closures; canonical path, no-follow leaf, single-link regular file, full9 held/named equality; `OBSERVED` and final `recheck`. No cumulative physical-byte counter or enclosing deadline is present in this reader. | One source-input read plus final `recheck`: 2 reads, at most 131,072 returned file bytes. |
| Interface `read` | Per original 16 MiB; fixed descriptor/closed source sets; canonical/no-follow/single-link/full9; `SEEN` and final loop. No cumulative physical-byte counter or enclosing deadline is present in this reader. | One source-input read plus final loop: 2 reads, at most 131,072 returned file bytes. |
| Preparer `Originals.read` | Existing per-original 64 MiB maximum, separately tighter source/current descriptor bounds and exact manifest counts; canonical/no-follow/single-link/full9 and `seen` rereads. | Preview: 2 input reads. Execute path: 3 input reads plus one readback of the newly written recipe copy, at most 262,144 returned file bytes for these four reads. |

Each existing file reader requests its declared byte size plus one byte to detect growth. The figures above describe returned bytes on the successful exact-size path; maximum requested bytes include one additional byte per listed read. For the included 37,393-byte test packet, the direct input totals are 74,786 / 112,179 / 74,786 / 74,786 bytes respectively, and the preparer execute path including its new-copy readback is 149,572 bytes. Recipe bytes carried in a serialized bundle or other output are also subject to that existing output's bounds and readbacks; they are not claimed to be physically free through hash deduplication. Unrelated pre-existing descriptor aliases retain their old read behavior.

This scope deliberately preserves the existing readers rather than replacing them with a new filesystem or resource subsystem. No claim of a newly proved whole-host physical-byte bound is made.

## Validation

Run from any directory:

```sh
python -B /absolute/path/to/external-recipe-consumers-r1/tests/run_regressions.py --output /temporary/path/report.json
```

The report must be outside this candidate; the default is JSON on stdout. The candidate remains unchanged. The local result is **19 test groups passed**, distinct from the user's fixed 19 acceptance cases, for which this package grants **zero** credit.

The suite imports the complete three consumer files after explicit test-only literal binding. It verifies the actual retained 32 + 17 byte fixture through all inverse stages, tests source-frozen descriptor substitution, strict/canonical packet parsing, unchanged decoder bounds, exact source membership and charging the new original to the existing decoded pool. It exercises the actual filesystem readers with real files, symlinks, hard links, atomic replacement, and full bookends; checks bundle closure; and demonstrates rejection before runtime execution. The constructor test reaches the existing publication-closure refusal after a successful byte gate. The cascade/interface tests verify their recipe refusal ordering before the unchanged history-input gate.

One transport test substitutes only the later semantic validator to isolate `prepare_bundle` collection and reread behavior; its result is expressly transport-only and grants no qualification. The loader test intercepts its first `exec` before any runtime body runs. The suite does not claim a successful complete release, cascade, interface, or phone execution.

## Remaining actual integration

The supplied runtime fixture is a byte-proof assembly only: its new action, protocol and publication authorities are not all bound, and its historical artifact/policy fields are deliberately retained rather than guessed. The fixture must never be staged as a runtime. Actual policy/apply/adoption originals, final32 authorities, artifact metadata, remaining root/template source generation, complete case execution wiring and capacity admission still need the ongoing full19 integration.

The final recipe can be generated only after those exact runtime and shared bytes are fixed. The descriptor must then be frozen in all three consumer sources through a separately reviewable mechanical change, followed by the source pin cascade. Neither the runtime CLI nor this candidate may choose a replacement recipe or substitute caller-supplied authority. This source structure candidate removes one measured integration obstacle; it is not an installation authorization.
