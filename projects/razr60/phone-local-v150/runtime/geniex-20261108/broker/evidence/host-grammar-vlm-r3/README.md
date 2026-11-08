# R3 VLM profile host validation

The new `qairt-output-grammar-core-r2-vlm-r3-v1` source candidate passed all 31 backend tests and all 38 original private r9 regressions on pocket4. The actual private candidate's pinned imports also passed. The run used a fresh candidate source directory and fresh host evidence, and did not contact the phone or dispatch an App action.

The 31 backend tests include public and actual private provider selector probes for v1, R2, and R3. Each selector checks six outcomes: typed success, malformed JSON, task deadline, native timeout, owner cancellation, and worker deadline. These are subcases of the suite, not additional independent tests to add to the total. The host fixture executes the real r6 supervisor and original worker with a host SDK fixture; it does not enforce grammar or qualify the Android NPU runtime.

The R3 configuration binds the actual `libgeniex_vlm.so` SHA `773e23de3f892d2cd9c468e7b0af32e6c254af341d4ed0e7ef0eda95f6ee1d73` and unchanged R2 core SHA `06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d`. A changed VLM fails before either counter or worker starts, and the test verifies the real native exit and process-group cleanup. The original R2 JSON remains readable and derives the original VLM pin; this extra guard belongs to the new source only and does not change the meaning of older R2 evidence.

Durable pocket4 job: `1a1bb7a0fdb-13c47-29c`; idempotency key: `hepta-native-grammar-vlm-hosttest-r3-baba4377-20261108`. The job succeeded with exit 0, synchronized complete output, and confirmed terminal publication. The input pack SHA is `baba43778559889dc572358ea1addefcf78af24ce8b0bb704d93a5b13ede2a8d`. `RESULT.json` SHA is `f8271799169d811c5310e9ad66c9a18bd2725c845efb55001e9cc0e9ed74b708`; all saved stream bytes were checked against its original remote hashes.

These results do not close the original fixed19 physical acceptance cases and do not authorize reusing any prior READY, claim, receipt, or model request.
