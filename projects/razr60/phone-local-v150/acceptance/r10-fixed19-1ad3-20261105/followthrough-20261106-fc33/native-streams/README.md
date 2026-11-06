# Current-source native_streams candidate

This package preserves the exact current provider source and a minimal candidate. It is a host-reviewed source candidate; it has not been deployed, adopted into a new source combination, or qualified by a phone task.

## Exact inputs and outputs

| File | Bytes | SHA256 |
| --- | ---: | --- |
| reference/phone_observation_tools.original.py | 43445 | 2c5ebb75e34fcce4c14638939809dade1f6d129504270930c8f94e2c2ce15b66 |
| source/phone_observation_tools.py | 43954 | 22580b8aa22d5c0ab4040888872e642a5176042023dd7bcf50e67efe51248409 |
| reference/daily_phone_local.original.py | 22059 | ca23c60bbb4114960c6a571492cacd9e0bdc3404191409ac78bcf0c34a06c1d0 |
| source/daily_phone_local.py | 22059 | 689db3908014940a1e39689b966d30ab16ac6f9c0d7892becf1718b9840c824f |

The input observation source was read in full from the current frozen component's shared/provider/source directory. Its current screenshot codec path, diagnostic helper, and all other increments are retained byte-for-byte. The observation candidate changes only native_streams. The daily candidate changes only the corresponding PARENTS hash; this is necessary because its loader pins its dependencies.

## Parser changes and evidence

The current original accepted output before started, unqualified event kinds, and boolean/floating values equal to integer exit code zero. Python dictionary equality also accepted differing field types in the repeated terminal event, such as False versus 0 and 0.0 versus 0.

The candidate requires an exact integer zero exit code, an event kind string drawn from accepted/started/output/terminal, and the successful order accepted, started, zero or more output events, terminal. It compares the terminal event to the top terminal by value and by the exact type of every corresponding field. Malformed list/dict event kinds now produce ProviderError. Existing byte counts, identities, sequences, decoding, truncation, and nonzero checks remain in place.

The checked Rust enum and JSONL encoder at commit 744fc422a28bd6f505701503bf0d113ab49d4634 contain exactly those four event variants. There are no queued or progress variants in that published source. Successful execution emits started before output-reader threads. See evidence/WIRE-CONTRACT.json for exact source paths, Git blob IDs, SHA256 digests, and excerpts. This establishes the checked source contract; it does not claim a newly verified installed binary.

The full native terminal wire schema has eight flat fields. This patch preserves prior acceptance of a historical minimal terminal and does not add a complete schema validator or recursively validate future nested fields.

## Runnable host regression

Run with Python 3, using a fresh output path:

    python3 -I -B test_native_streams_regression.py --result-json /absolute/fresh-result.json

The script verifies all four source pins, extracts only the selected AST definitions, and tests the real functions without importing provider main. It has no phone, dispatch, or model execution path.

The recorded Mac run passed 42/42: 28 parser cases with original-versus-candidate outcomes, four PhoneTools.map image guards, eight selected rename/filesystem/callback checks, one FD/thread/owned-temporary-tree baseline check, and one exact source-preservation check. It preserved Chinese, emoji, and a literal LF in the valid multichunk output.

Script: 19996 bytes, SHA256 26c1028f3b8c882680f0d530d5cb7ad9eec038e09b7bf1cc27e9c943e00f5e84.
Result: 21377 bytes, SHA256 b0650028495995a2f361b5245fc16cab0a29ab635ef321bf2bc9270812d56bb6.
Mac job: 1a1b10f1643-fc05-7572, exit 0, complete durable output, no truncation.

NEG-10 covers byte-budget exhaustion, expiry, foreign image identity, and an old round at map time. NEG-14 includes two actual os.replace operations, missing/unknown paths, missing parent, a symlink, actual ENOTDIR, and same-object propagation from a synthetic EACCES callback. The callback is not a claim of physical filesystem EACCES. Resource observations concern host file descriptors, threads, and the test-owned temporary tree. RSS is recorded as a high-water mark; no return-to-baseline RSS claim is made. Full capacity exhaustion, process-group cleanup, and phone lifecycle checks are outside this run.

An earlier Linux script and two observed Linux runs passed 42 checks before the scratch executor became unavailable. Their exact files were not recovered during this preservation operation. The Mac script in this package was reconstructed and independently executed; its hash and evidence are explicitly separate.

## Reproducible derivation

Preview and verify the derivation without writing:

    python3 -I -B build_candidate.py

Produce the exact candidate and patch files into a directory that does not yet exist:

    python3 -I -B build_candidate.py --out /absolute/fresh-source-directory

The builder verifies both original pins, asserts each replacement occurs once, verifies the resulting candidate hashes, verifies the inverse daily hash change, parses both sources, and writes using create-only semantics. No provider imports, deployment, device effects, or historical seal changes occur.

## Runtime inventory

evidence/runtime37-hash-summary.json preserves the safe projection of an actual Mac read-only hash verification. runtime/MANIFEST.json declares 37 files: 21 reference files and 16 source files, totaling 3157174 bytes. Including the 46685-byte manifest itself gives 38 objects and 3203859 bytes. Every declared file matched its bytes/hash with stable before/after/named metadata; the manifest reread was unchanged. The exact raw readback digest is retained in the summary, while full metadata and historical inventories stay in the private preservation directory.

This 37-file runtime list and the combination's 15 production source entries have different scopes. The observed manifest pin is 72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515; the current combination pin is 02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708. The summary records its observation time and does not assert that later phone work has not changed state.

## Acceptance boundary

These selected host regressions do not close whole NEG-10, NEG-11, or NEG-14 cases. No current-combination NEG-12 or NEG-13 result is supplied by this package. Historical candidate regressions pinned to earlier seals cannot be promoted automatically. The candidate changes a source pin, so any future phone use requires explicit new-combination derivation/adoption and the applicable physical evidence.

Keep this package under the independent followthrough candidate directory. Do not overwrite host-five historical inputs, their SOURCE-SEAL, or the frozen current component. SOURCE-MANIFEST.json records the publishable package contents. The parent operator owns any repository commit or subsequent adoption.
