# Source constructor interface

Input schema: hepta.reviewed-release-source-chain-inputs.v1. Exact fields: schema, material, consumer, output_root.

material has exact3 descriptors for combination, source_seal, configuration, service, shared, source_inputs, derivation and producer. The first seven must use the unchanged actual material layout in MATERIAL_NAMES. producer is the complete actual material builder source descriptor already recorded by SOURCE-INPUTS.json. The constructor rederives the full source graph from the frozen R4 originals and all 15 complete production files. Only daily_phone_local.py, phone_local_tools.py, phone_observation_tools.py, provider_codex_host.py and provider_phone_local.py may change; all five must change. The daily file may differ only in its four actual dependency digests.

consumer has source and runtime_package exact3 descriptors. Its five literal identities/counters must agree with the actual material and package. The constructor does not reinterpret the consumer's policy or historical-closure semantics; that source must be reviewed separately. output_root is an explicit canonical absolute source-output namespace. No function writes there.

After the complete actual input JSON is retained and its descriptor is reviewed, construct an exact RHS binding with the existing Changes helper: require literal(template, 'FROZEN_INPUTS') is None, set that RHS to the actual descriptor, and finish to obtain the complete inverse. Do not use any fixture descriptor for this operation.

Call the source-bound module:

```python
result = derive_reviewed_source_chain(actual_inputs_raw, read_pinned=verified_full9_original_reader)
```

The callback must verify the source original identity and bookends, and return complete bytes for each exact descriptor. The constructor independently verifies lengths/hashes and repeats every read before returning.

result.files maps relative paths to complete source bytes. It contains the source-bound builder/consumer/installer/readiness/activation fragment, formal input, release reader, exact8 reader, protocol, still-unbound install/retention readers, unchanged retention producer and two owner module previews. It contains no release archive, BUILD-RESULT or actual success identity. result.changes provides the full parent/candidate pins and exact forward/inverse source transformations. result.source_binding contains the new source relationships only.

Publish this candidate through the existing reviewed fresh-directory source publication route after review. The future real builder command remains the original exact command shape supplied by the derived release reader's expected_build_command; actual retirement, component boundary and policy adoption remain mandatory for a sealed build.

Installation stdout and retained files remain source-specific: stage/start stdout is json.dumps(result, sort_keys=True) plus LF; files use the installer's original pretty sorted JSON serializer. The new retention producer still uses fixed installation roles, complete original bytes and bounded chunks; this constructor changes its reader source references only.
