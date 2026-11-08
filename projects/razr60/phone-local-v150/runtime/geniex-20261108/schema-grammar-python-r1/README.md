# Reviewed Python schema to GBNF compiler

This is an independent, single-module implementation of the already reviewed Hepta schema subset. It is read by the existing Python interpreter. It launches no native executable, creates no process, loads no model and performs no phone action. It requires no additional package. The deployment reason is concrete: the actual GNU state mount is `MS_NOEXEC`; a fully static binary in that mount still cannot execute. This implementation does not modify mount flags, rootfs, service permissions or the frozen model worker.

The C++ reference implementation in the sibling `schema-grammar-r1` directory remains frozen as an independent oracle. Its host executable SHA is `02e822631e002b2d210cc6b6eea57937c0961d114cfc01e278c06a61a56ad03f`; its reference upstream commit is `19cce6919992fdffd92e0ac152caaf1e2b8f254e`. The production Python module has no dependency on those files or that executable.

## Frozen API and trust boundary

```python
grammar_bytes, proof = convert_schema(
    original_schema_bytes,
    compiler_source_sha256=fixed_reviewed_source_sha256,
)
```

The module is `python_schema_grammar.py`, 15,177 bytes, SHA `c230e076ae61c87a744c49b160a456c039d47441784ad3ccc2c6465bc67453a8`. The provider overlay may copy identical bytes to `schema_grammar.py`. The caller must verify the source before importing it, include it in the protected source closure/PARENTS, and bind the compiler kind explicitly in configuration. A self-hash after import cannot make an untrusted loader safe. The function independently checks its regular source file, link count, write permissions, byte bound, full SHA and unchanged file identity at every conversion.

Input is the complete original schema bytes, up to 65,536 bytes. Parsing rejects duplicate object keys, invalid UTF-8, nonfinite values and isolated surrogate strings. Every node must match the supported subset; unknown keywords and unsupported combinations fail before any grammar is returned. GBNF is bounded to 65,536 bytes. The function does not write files or invoke subprocesses.

The returned proof uses `hepta.schema-gbnf-conversion.v1`, with the original byte length/SHA, canonical schema SHA, GBNF length/SHA and root, subset and root schema kind. It identifies `compiler_kind: reviewed_python_source`, `compiler_source_sha256`, `conversion_completed: true`, `input_bytes_preserved: true`, and the reference converter commit. It does not invent process exit, child wait, ELF or SDK evidence. `model_loaded`, `native_action_authorized` and `production_receipt` are false.

## Supported value constraints

The mobile root is a complete `oneOf` of reviewed `mobile_use` envelopes. Objects are closed and every property must be required. All supplied branches, enumerated App aliases/packages, action constants, current screenshot constants, text limits and coordinate/duration bounds remain represented. Repeated subtrees may reuse a grammar rule; no branch or enum member is selected away. Distinct actions are mutually exclusive; repeated `read_text` alternatives must have distinct exact tuple lengths, making union generation sound for the original `oneOf`.

The reviewed recursive nodes are string constants and display zero; string enums of at most 64 unique members; closed objects with at most 16 required fields; exact tuples of length 1–5; string lengths with minima 0 or 1 and maxima up to 4096; the two original ASCII package/view-ID patterns; and exactly the integer intervals 0–1000, 100–1500 and 500–1500. Structure is bounded to depth 24 and 2048 nodes.

The health root is a separate exact seven-field terminal schema. It requires the existing `turn.complete` / `none` / empty command and call ID / empty argv / `completed` constants, with summary length up to 1024. A nonce cannot be encoded into this grammar through a constant or additional keyword. The original health parser still checks the actual requested nonce independently.

## Deliberately conservative JSON serialization

This compiler is sound for its generated serialization subset; it does not claim to generate every legal serialization of the schema's values. It fixes object properties in their declared order, allows at most one ASCII space at each grammar whitespace position, and uses canonical unsigned decimal integers. For example, JSON `-0`, a different property order or additional formatting whitespace may be valid JSON values but is not generated.

Generic string repetition counts one decoded Unicode scalar per unit. Direct UTF-8 astral characters are allowed. Standard JSON escapes and non-surrogate `\u` escapes count as one unit. All surrogate escapes, including legal UTF-16 surrogate pairs, are rejected; the same astral value remains expressible directly in UTF-8. Raw DEL is also represented through its legal escape. The two ASCII patterns emit their literal ASCII form rather than every possible escaped spelling. These restrictions prevent a two-escape surrogate pair from defeating a JSON-schema character length bound.

The original strict schema parser, typed action mapper, observation checks, cancellation and native receipt remain mandatory. Grammar does not prove action semantics, authorize an App operation, enforce uniqueness absent from the original schema, or prove that generation finished normally. An EOS, valid grammar prefix, process completion or conversion proof alone is not a successful phone action.

## Verification completed

`tests/test_python_converter.py` reuses the frozen C++ suite's public semantic corpus. It compares the generated Python grammar against both an independent direct JSON-value schema interpreter and the independently generated C++ grammar. The recognizer parses actual GBNF into a test-only acyclic Unicode regular expression; it is not the production proc parser.

The final host run passed 18 tests, including 4515 integer cases, 3694 accepted and 1293 rejected values, 17 invalid schema mutations, all 53 synthetic App aliases, complete 13/18-branch schemas, missing/extra fields, exact tuples, nested whitespace, property order, Chinese, astral Unicode, escaped strings, all surrogate escape boundaries, source hashes/modes and truthful proof fields. A complete public 18-branch grammar is 10,058 bytes. Raw logs and the report are in `evidence/`.

The separate pocket4 job `1a1bb4e8797-13c47-1c9` then processed both original r9-generated R5 fixture schemas, bound to their unchanged existing manifest SHA. The 11,517-byte / 13-branch schema and 14,223-byte / 18-branch schema produced 7667-byte and 9659-byte grammars. All 636 valid and 439 invalid canonical values agreed across the original schema interpreter, Python GBNF and frozen C++ oracle. Measured conversion times on that host were about 1.54 and 1.19 milliseconds. The job terminated successfully with exit 0 and empty stderr. Private schema bytes and generated private grammars remain on pocket4; only hashes and counts are in the public summary.

Those fixtures describe host-created semantic histories; they do not assert that any phone operation occurred. No model was loaded and no phone was accessed by these tests. Actual `geniex-proc` grammar construction and the full native/provider/model/App path require separate runtime evidence. At this checkpoint, proc construction of these two exact grammar files is still pending.

## Reproduce the public host differential

Build the sibling frozen C++ oracle according to its README, then run:

```sh
HEPTA_SCHEMA_CONVERTER=/absolute/path/to/hepta-schema-gbnf \
  python3 tests/test_python_converter.py
```

The production component is the one Python module. The test-only private-fixture script has explicit fixed input/source pins and create-only independent outputs; it must not be treated as a launcher or a production receipt generator.
