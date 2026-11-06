# Coordinator phase compatibility

The previously published coordinator used `dict(phase=phase, **result)` even though the actual frozen `OwnedCapture.run_phase_original()` result already contains `phase`. The original expression raises `TypeError` after the first child has joined. The isolated reproduction ran the exact frozen capture source with one harmless local host child and then evaluated the original coordinator statement against that real returned object.

The candidate changes exactly one line to `receipts.append({**result,'phase':phase})`. This preserves every other returned field, leaves the child's original result object and result file unchanged, and records the logical coordinator phase. The complete inverse restores all 20,208 original bytes. The candidate is 20,206 bytes, SHA256 `54f7a6c1fd7e9ff1b82e82f4947639bca1745d334f7512bbf92d796bb32987fa`.

Ten checks belong to the isolated capture interface reproduction. Five separate checks belong to the pure publisher derivation, including refusal of three empty originals. They are source controls, not E2E task passes, and are not combined with any business acceptance count.

Root actually published the eight-file host source package once with job `1a1b278051c-fc05-7e23`. An independent read-only job `1a1b27b8628-fc05-7e38` read all eight files, all 112,114 original bytes, their complete nine-field metadata, full EOF, and every directory member. The complete terminal output was retained through two contiguous controller reads. The actual source files match the reviewed preview exactly. No controls were rerun during that readback.

The actual package is under `followthrough-fc33-e2e-coordinator-compat01` in the Mac project directory. The prior 49-file E2E package, its six operators, the fifteen production sources, the original sender and every existing task original remain unchanged. This compatibility package does not start a registration, Send, model request or phone action.

At this checkpoint Root is preparing an R6 component runtime after separately observing the original sender's fixed two-dismissal loop leave the tools menu open. This package preserves the independently established coordinator fix. Its existing R5 dependency binding is not a final R6 runtime, BUILD, installation or READY qualification. Later source propagation must bind the actual R6 originals and the reviewed business sender correction; unknown actual case and installation slots remain unbound.

## Reproduction

`reproduce_and_derive.py --out <new local directory>` runs one isolated host capture probe and reproduces the original duplicate-keyword failure. It never runs a coordinator phase, registration, sender or phone transport. The source pins are checked before loading the original capture module.

`prepare_publication_request.py` derives the preview and request from all complete retained parent source files and rejects empty source bodies. Its fixed output filenames are create-only; preserve the existing results and choose an isolated copy of this directory for another reproduction.

`actual-readback/verify_actual_archive.py` validates both actual durable controller records, decodes the bounded complete transfer, checks all eight real originals against the preview, and verifies the byte inverse. Its local evidence outputs are also create-only.

The publication request's idempotency key is consumed. The archived `REQUEST.json` is an original record, not permission to launch another publication or task.
