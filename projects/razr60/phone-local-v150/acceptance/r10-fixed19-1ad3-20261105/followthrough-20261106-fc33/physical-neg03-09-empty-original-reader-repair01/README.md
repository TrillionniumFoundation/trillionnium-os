# Source-publication empty-original reader repair

The second NEG-03–09 source-only publication stopped while the current, complete policy-adoption verifier read a legitimate empty original. The rejection was in the publisher's caller-supplied reader. The adoption proof and the 15 production sources did not change.

This package preserves that failure, an independent read-only accounting of the partially published input tree, the exact small reader repair, and four actual host controls. Root subsequently identified a separate component-sender UI problem and selected an R6 runtime successor. Consequently, no R5 source03 publisher or execution request was generated or published. The reader repair is retained for the later, explicitly bound R6 source03 package.

## Observed publication failure and retained tree

The actual failed publisher was `19652 / b1ae10610b16aeb4620ec6f66362d3945e1f2a40717465303b24724e03b4eb81`. Its controller job `1a1b27082de-fc05-7e06` ended with exit 1, complete durable stdout of 0 bytes and stderr of 3,742 bytes. The entire request, start, authoritative status, read, and transport receipts are preserved in `SOURCE02-FAILED-PUBLICATION-CONTROLLER.original.json`.

Independent read-only job `1a1b275aef3-fc05-7e16` completed with exit 0, 3,408 stdout bytes, no stderr, and both EOFs. It read the exact source02 input publication: 181 files, 55 directories, and 3,599,838 bytes. All 177 prepared members matched their complete payload bodies, and all 180 members named by the terminal input derivation matched. `DERIVATION.json` was `68265 / 0ff96cd5c32759b0ffe08db0200f31ac135af1e4ec64104c5b55292787599cec`. The intended derived-source directory was `ENOENT` with a parent metadata bookend. The 187 original paths, totaling 7,010,322 bytes, were all rechecked. The old publication was not rerun or cleaned up.

The read-only inspection also reread the three empty originals listed in the selected adoption proof: `original-016.bin`, `original-017.bin`, and `original-035.bin`. All had length zero, the exact empty SHA256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, and the same complete nine-field file metadata previously retained in the successful 130-original adoption control.

## Exact repair and why the earlier positive did not cover it

The previous three adoption controls used `physical_fault_common.Originals.read`, which accepts an exact typed integer length of zero. Publication instead passed the projected material reader, which required a strictly positive length. The same full constructor's read-only reproduction now identifies `original-016.bin` as the first rejected descriptor. No earlier result is reclassified as publisher coverage.

The executed `read()` function changes only:

```python
0 < desc['bytes'] <= 16777216
```

to:

```python
0 <= desc['bytes'] <= 16777216
```

Its exact-key dictionary check, exact `int` type check, 16 MiB ceiling, canonical parent, `O_NOFOLLOW`, regular-file/single-link check, full reads, byte count, SHA256, full9 bookends, and stable admitted-original book remain unchanged. A zero-length descriptor must therefore still match actual zero bytes and their exact hash. The original frozen material publisher is not modified: only this caller's extracted reader function is projected.

`SOURCE-READER.patch` contains the one-character executed-reader change and its complete original. `SOURCE-READER-PROJECTOR.patch` adjusts the caller's existing exact substitution and proof to record both bounds. The selected projector is `1345 / ecd6139f9161bc18d59eee16bd58f3f3de478f39643e3967d12c84167ad753c8`; the resulting reader is `1053 / 529da5df943c53763a07cc232f0bf585250ba76b6b88f76643900224dfb94b03`. The projection proves complete inverse to the original reviewed function `1051 / cb57f96ca4260c9cc3b1166c754af84d05d00b48cddc8b3db255daa62e8ce5ed`.

## Actual narrow host controls

Job `1a1b278cf52-fc05-7e28` executed `test_publisher_reader.py` (`13463 / 21b38bb81d414cffddf9ae052255947fd8136f8f1d426a7e7041c49f92322914`) once on the known Mac host. It completed with exit 0, complete durable stdout of 1,022 bytes, no stderr, both EOFs, and no automatic retry. The four controls are separate from the earlier three adoption controls and do not create additional acceptance-case passes.

| Control | Actual result |
| --- | --- |
| Original publisher reader with the actual full source02 bound constructor | Reproduced `bounded typed source descriptor` at the exact empty `original-016.bin` descriptor. |
| Candidate publisher reader with that same actual full constructor | Completed `derive_negative_sources` entirely in memory, including complete policy-adoption verification, source-chain rederivation, actual runtime38 and production15 pins, and every source inverse. |
| Empty descriptor whose length is `False` | Rejected by the precise type gate; the original book did not change. |
| Actual empty file with an explicitly wrong SHA256 | Rejected by the byte/hash gate; the original book did not change. |

The positive constructor read and rechecked 337 unique original paths totaling 20,789,662 bytes, including all three empty originals. It produced an in-memory plan for 11 source families and 172 files totaling 3,023,400 bytes. The seven physical-case templates retained all actual plan, scope, nonce, BUILD, READY, and dispatch slots as `None`. No derived file tree was published; the source02 derived directory remained absent.

The actual `RESULT.json` is `5749 / d7d2fd5a91839e66ca2816ffc6b8273239280caccb2e8287e898fde267bc64b7`. The constructor report is `854 / d9217973904f580b824adc37b0106e602c545b381ed7ce3e666cecdc559549a7`. Its complete original-file book is `172333 / e26df10680664d00e6f6043b76eb93d243f9f2b9aafb87dfb7b8ff7a39a26b6b`; all three binary-read carriers are preserved and share one immutable version token. The actual controls use a write-restricted audit hook: only their new, fixed host report files may be created. They forbid source publication, process creation, sockets, signals, removal, and namespace changes after the owned output directory is created.

## R6 successor boundary

`R6-REBINDING-REQUIREMENTS.json` identifies the actual descriptors needed for the successor: the complete R6 runtime and root graph, the actual release source-chain constructor and inputs, the corresponding consumer/readiness bodies, the observed materializer location, the revised complete reference index, and fresh source03 output namespaces. Unknown descriptors and actual BUILD/installation/READY remain null. `R6-SOURCE-INPUTS.UNBOUND.template.json` is deliberately non-executable and does not pretend to be a bound input.

The negative-source constructor currently fixes the R5 runtime/root pins and exact revision in two places. Those must be derived from complete observed R6 originals. The closure reader also verifies that the root source normalizes through exactly seven selected literal slots to its reviewed parent. A new root body, if any, requires its own exact review and template pin; it must not be accepted by weakening that inverse. The business sender `send_new_native_task_r5.py` is distinct from the component sender being repaired and is not changed by name similarity.

Production15, COMBINATION `7969a11b…`, actual policy `69aa6433…`, and adoption `98b5db3d…` remain unchanged. This package grants no real phone, native, model, case, BUILD, or READY qualification. The actual source01 and source02 failures remain preserved.
