# Standalone schema-to-GBNF candidate, 2026-11-08

Status: independent candidate; no production provider, frozen worker or installed
R3 source is changed by this directory. It performs only CPU text conversion.
No model, tokenizer, QNN, GenieX processor or UI executor is linked or loaded.

## Chosen route and provenance

The fixed llama.cpp tree at commit
19cce6919992fdffd92e0ac152caaf1e2b8f254e contains the C++ converter and does not
contain the former standalone json_schema_to_grammar.py. Its remaining
pydantic_models_to_grammar.py imports pydantic and docstring_parser; its dictionary
adapter does not preserve all current schema constraints, so it is not used.

SOURCE-PINS.json binds all twelve copied upstream files to Git blob SHA1 and
full SHA256, including the MIT license and nlohmann 3.12.0 single header.
The compiled upstream closure is exactly five C++ files and their five headers:
json-schema-to-grammar, json-schema, json, trie and common Unicode utilities.
The JSON header is byte-identical to the already present r6 vendor copy.
support.cpp contains only the exact string_join, string_split and string_repeat
bodies from pinned common/common.cpp. compat/common.h exposes these helpers and
the original recursion bound 128. compat/ggml.h supplies a fatal JSON invariant
macro; no ggml implementation is linked.

The original upstream files remain unchanged. build.py verifies their complete
hashes and applies two small, checked patches to a build-directory copy:

- fail-closed-warnings.patch changes incomplete-conversion warnings into errors.
- scalar-string.patch makes each generic string grammar unit one Unicode scalar.
  It rejects surrogate code points and surrogate Unicode escapes; directly
  encoded astral characters remain available.

The CLI has no filename or model arguments. It reads at most 65536 original
schema bytes from stdin and writes only a successful, at-most-65536-byte GBNF
to stdout. An invalid schema exits 65 with zero grammar output. Invalid UTF-8 in
a diagnostic is replaced only in the diagnostic; the original schema or model
output is never repaired.

## Strictly admitted schemas

The normal root must be the complete original mobile_use oneOf schema. Every
alternative is a closed object whose complete property set is required. The
mobile envelope, known action field signatures and fixed types are checked.
Action constants distinguish alternatives; the only repeated action is
read_text, distinguished by exact view_ids tuple lengths 1 through 5. This makes
the upstream union interpretation of oneOf sound for this admitted subset.

Supported constraint forms are deliberately limited:

- Text constants, string enums with all original choices, and display constant 0.
- Explicitly closed objects with every property required.
- Exact prefixItems tuples, with minItems=maxItems=tuple length. items combined
  with prefixItems, uniqueness constraints and unknown keywords are rejected.
- The exact package and view-ID ASCII patterns used by the existing provider.
  A pattern combined with a string length constraint is rejected.
- Finite string maxima through 4096; minima are only 0 or 1, as in the current
  provider. Larger minima are rejected rather than broadening the interface.
- Integer intervals 0..1000, 100..1500 and 500..1500.
- No external references, allOf, arbitrary regexes or optional properties.

The separate health root is accepted only when it exactly matches the existing
seven-field, closed, all-required legacy health contract: terminal kind, tool
none, empty call_id/command, completed status, empty argv, and a free summary
with maxLength 1024. Its grammar cannot embed a nonce, expose a tool or prefill
an answer. The original one-use health contract remains responsible for checking
that the actual model summary equals its new requested nonce.

The original schema bytes are passed unchanged to the official converter.
No action, enum, branch, bound or required field is removed.

## Semantics and limits

This is a sound, conservative serialization language for the reviewed schema
subset, not a claim of equality with every JSON serialization admitted by JSON
Schema. The converter fixes object field order and restricts whitespace.
For a valid Unicode scalar value, direct UTF-8 is available; generic strings
also allow ordinary JSON escapes and non-surrogate Unicode escapes. A legal
JSON escaped UTF-16 pair is deliberately rejected even though its directly
encoded astral value is accepted. Lone surrogates are rejected. This prevents
the upstream two-escape-versus-one-scalar length ambiguity.

String repetition now counts decoded scalar units. The host differential tests
exercise direct astral characters, a one-character upper bound, escaped pairs,
lone surrogates, ASCII control escapes, quote/backslash escaping, Chinese and
combining sequences. They also exhaust every integer from -2 through 1502 for
the three reviewed intervals, all required fields, unknown fields, exact tuple
lengths, the full synthetic 53-app enum, wrong screenshot IDs and all 18 action
alternatives.

The independent host recognizer parses the emitted GBNF and interprets its
finite acyclic rules as Unicode regexes. It is test-only and is not used by the
provider. Its finite differential corpus does not replace actual geniex-proc
Grammar parsing and on-device generation. Those are still required.

Grammar does not prove that a coordinate targets the requested control, that a
view is unique/current, that a task succeeded or that an old effect is safe to
repeat. The original strict JSON/schema parser, typed mapper, observation
guards, action ledger, UNKNOWN gate and native receipts remain authoritative.
For example, duplicate read_text IDs are admitted by the original schema and
still require the separate typed uniqueness guard; this candidate does not
claim otherwise.

## Runtime API and byte binding

convert_schema.py has no third-party Python dependencies. The stable API is:

    grammar_bytes, proof = convert_schema(
        original_schema_bytes,
        executable=absolute_static_executable_path,
        executable_sha256=fixed_executable_sha256,
        timeout=3.0,
    )

The caller chooses the original complete schema serialization and retains its
bytes. The helper independently rejects duplicate JSON keys, hashes a held
regular executable descriptor, checks matching CPU architecture and verifies
that its ELF has no PT_INTERP and no DT_NEEDED. It then executes that exact
descriptor with an empty loader environment. A nonzero exit, any stderr,
oversize grammar or timeout raises and supplies no grammar. Timeout cleanup
kills and waits for the pure converter subprocess; it is not an executor or a
production process receipt.

Proof contains original byte length/SHA, canonical schema SHA, grammar
length/SHA, converter SHA, upstream commit, root_schema_kind
(mobile_use or health_final_only), returncode, child_waited, input_sent_unchanged
and the observed static ELF contract. native_action_authorized and
production_receipt are false. The CLI wrapper writes the complete original
schema, grammar and proof into a new 0700 output directory using create-only
0600 files. It never overwrites prior output.

Per request, the provider must bind this proof and original schema to the same
request/round, stage and hash the generated grammar, and keep the frozen
worker's grammar input hash binding. The unchanged real geniex-proc Grammar
must parse the GBNF again. A tested SDK hash and a separate grammar profile are
required; the old official profile must continue rejecting grammar.

## Host build and tests

Build in a new directory (each attempt retains its own evidence):

    python3 build.py --static --out /absolute/new-build-directory

Run the host-only differential suite:

    HEPTA_SCHEMA_CONVERTER=/absolute/new-build-directory/hepta-schema-gbnf \
        python3 tests/test_converter.py

The final host run passed 15 tests: 4515 integer cases, 3554 accepted values,
1292 rejected values and 17 rejected schema mutations. The synthetic full
53-app/18-alternative grammar is 31742 bytes. These are host fixtures, not
actual phone operations or the private r9 catalogue test.
Evidence is in evidence/; the exact build manifest identifies the executable.

An earlier host build exposed one omitted string_repeat dependency; it was
added from the same pinned helper source. An earlier malformed-input test found
that an invalid UTF-8 parser diagnostic could throw while encoding the error.
The final adapter replaces invalid diagnostic bytes and still returns no
grammar. Earlier binaries/build folders are retained separately.

## Android / GNUroot execution

Use the existing authorized NDK compiler, no new SDK dependency:

    python3 build.py --android --static \
        --cxx /Users/qianqi/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android28-clang++ \
        --out /absolute/new-arm64-build-directory

The flags are -std=c++17 -O2 -static -static-libstdc++, plus warnings.
The static ELF requirement solves the missing Android dynamic linker inside
GNUroot without assuming any /system bind mount. It does not prove SELinux or
mount execution permission. After the build, inspect the real ELF machine,
PT_INTERP and DT_NEEDED, then run a pure conversion on Android and in the actual
GNUroot execution location. Compare the full grammar SHA and source-schema SHA.
If GNUroot is not running or its execution path is not established, that probe
must remain pending; do not create mounts just to make a test pass.

The actual private 53-app schemas, actual on-device proc parser, NPU generation
and end-to-end Hepta app operation are separate gates. This component does not
raise the 3584-token admission limit or shorten owner text, observations or
history.
