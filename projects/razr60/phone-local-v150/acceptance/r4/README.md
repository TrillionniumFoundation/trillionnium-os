# Acceptance support for provider v150-r4

Use the three files in collector-r4/ together. They derive from the frozen v150-r3 support manifest SHA256 64b145e0f6979b1b33a407aca6abb1dc22598abbbca277483f82118eca10d971.

The only collector logic change is the health-schema detector: schema.get('properties', {}) accepts a business schema whose root is oneOf. Such a schema is not treated as a health schema. The independent health predicates, exact nonce check, native display prefix, raw-byte verification, failure handling, business fact reparse and no-replay rules remain unchanged. Existing r3 helpers and reports are retained.

Run collector-r4/collect_turn_evidence.py with the same arguments documented in the original acceptance/README.md, explicitly selecting the r4 source seal and its exact SHA256, provider-r4/source, local-config-r4.json and the unchanged service input manifest. The collector's historical default seal is not the current selection; always pass --source-seal-sha256 for r4.

Use a new output directory and the actual five-field scope. A root oneOf is accepted only as a schema shape; it does not grant business qualification. Actual native tool streams, original sidecar receipts, current image binding, postconditions and foreground return must still all match. Original failed native/provider error text is never normalized to turn a failed report into a pass.

The materializer copy differs only in the candidate source seal metadata. It generates new nonces and exact text, never registers or dispatches. Its health summary remains an ordinary string in the separate frozen provider health schema; the nonce is not inserted into that grammar. Root remains the only phone/model/operator.

The fixed19 aggregator is reused by its frozen byte hash. Point it at provider-r4/qa/fixed-acceptance-set.json; do not combine r3 failure samples with r4 success denominators. Keep historical outcomes in a separate retained section.

These helpers perform no phone, model, socket or sidecar request. Their own compatibility checks are not fixed19 cases or daily-use qualification. Publish only helper sources, compatibility diff, manifest, README and hash-only validation metadata; actual requests, images and raw turn evidence remain private.
