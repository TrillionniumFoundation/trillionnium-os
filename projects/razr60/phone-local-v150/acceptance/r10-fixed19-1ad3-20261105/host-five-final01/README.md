# Host lifecycle actual evidence — checkpoint 03

Five host-isolated layers passed once on the actual P4 host: NEG04, NEG05, NEG07, NEG08, and NEG09. The source manifest is `32299b1bd9015e107a9492b6ab1e8baacfea86bfe4d990b265d10eae7ab2475b`; the input manifest is `c423b4b663a7237e81ed6111922eeef76b85cffa65c603a5361ec3c3f53227b1`. Production files are the exact current fifteen-source set, run with the recorded isolated host fixtures.

The actual run completed in 6.733764537028037 seconds. Each case preserved its terminal, one HTTP request, semantic claim, raw output, input-effect counter, worker join and namespace cleanup evidence. NEG07 retained the four before-late originals before admitting the later receipt. A second action only verified originals and archived them; no case was replayed.

`evidence/HOST-FIVE-ORIGINALS.tar.gz` contains all 476 original files (973331 raw bytes). Its 210615 compressed bytes have SHA256 `5a1fb2b0f826e3e9af3ce691c6e043f6a6669c7470aad1ddd9afb99e404ecf87`. `ORIGINAL-FILES.json` preserves original metadata; copied filesystem metadata is not represented as original metadata. `LOCAL-BYTE-VERIFICATION.json` records every archive member's exact bytes and digest.

The two preparation archives and the extracted `package/` and `inputs/` files are byte-exact frozen material used on P4, rather than snapshots of a subsequently edited working directory. `DELIVERY.original.json` is the historical pre-execution delivery receipt; its zero-run count describes its creation time. The actual execution receipts under `evidence/` supersede that preparation state.

## Qualification boundaries

This is five host-layer passes, not five completed acceptance cases. Physical follow-up remains required for every case. Future deployment binding and the bound-server CPU drain branch are not qualified by this run. Current whole-case progress remains 0/19. No historical pass is inherited.

## Existing live02 transaction

A separately started, fixed live02 transaction applied the policy once and captured all originals. Root's followthrough observed that completed output and started no duplicate driver. The actual exported policy is 2667740 bytes, SHA256 `f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70`, different from the offline candidate. Complete post-live comparison and adoption remain required.

The actual transaction used driver `574e639f...`, verifier `5cd18af1...`, and original transport `860aaf74...`. It did not consume the separately prepared 0374 transport/UTF8 live fork. Host-five execution did use the exact repaired 0374 capture transport. The prior post-retention finalization stopped at exact-field validation with no phone, retention, or comparison calls; its originals are retained.
