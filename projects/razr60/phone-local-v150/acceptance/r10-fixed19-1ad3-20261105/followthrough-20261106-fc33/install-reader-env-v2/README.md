# Install reader: type checks plus actual GNU environment v2

State: HOST_SOURCE_CANDIDATE_UNBOUND. This package is an offline host source candidate. BUILD, installation, READY, new role identities, operation nonces and fixed19 credit are all zero.

## Exact selected source pair

| File | Bytes | SHA256 |
| --- | ---: | --- |
| source/verify_install_start_ready_UNBOUND.py | 35031 | d1de5b63f24cee899c47f7c3019ac4d7939d6212c9c798f812dc0266a97b569f |
| source/install_ready_execution_protocol.py | 12782 | 79f2a227e0d0c991bcc08c9edf6d5916faed798c358f27906d53a226beeda353 |

The reader is derived in two commuting ways:
1. Type-check reader c42ada3af944cb6f8191d1ff8700107b01ea81414a15d25a4740925b6743d681 plus the one existing protocol descriptor change.
2. Environment reader 66fe421093482d4ce9338b1646584e94ac10600bc1edb8a711b9362d63dbddf3 plus the three already reviewed strict-type edits.

Both produce identical complete bytes; reversing each edit recovers its exact parent. The protocol body is the existing v2 body unchanged. The v2 derivation's original request d8bcef88 was read again with O_NOFOLLOW, original full9 metadata bookends and complete bytes/SHA, and its shell argument prefix exactly matched the selected GNU environment.

The reader still has FROZEN_INPUTS=None and FROZEN_EXECUTION_PLAN=None. Its public API rejects before JSON parsing, source import or callback. The source-only synthetic fixtures do not bind these public slots.

## One candidate, one current regression result: 72

The current Mac execution reran all 64 portable cases against d1de plus 79f2, reran all 3 original controller/phone return-code cases against d1de, then ran 5 environment-merge checks against this same source pair. The total 72 is 64 + 3 + 5 in this run. It is not an accumulation of earlier c42 results, an additional 72 physical cases, or qualification of any phone flow.

The 64 portable cases contain all original 43 controls plus 21 additional type/LF checks. The 5 merge checks establish unchanged guard text, exact actual environment prefix, and unchanged bootstrap/spec/dispatch/timeout for each of stage/start/ready with only the reviewed prefix changed. All three exact request encodings retain LF and remain under the unchanged wire limit.

Evidence:
- evidence/RESULT.json: 72 PASS_SOURCE_ONLY, source pair, 5 merge cases and explicit actual zero counts.
- evidence/mac-merged-controls01/RESULT.json: all 64 portable cases and source pins.
- evidence/mac-merged-controls01/original43/RESULT.json: all original 43 cases within that same portable run.
- validation/CONTROLLER-PHONE-RC-RESULT.json: all 3 return-code cases, with internally consistent bytes/text.
- evidence/operations/: original controller start/status/read records of host source construction and current validation.
- evidence/portable.stdout and evidence/phone-rc.stdout: complete raw host test outputs.

The 4 Linux procfs guard execution controls are explicitly skipped on Mac. No retained Mac result is claimed for those controls, and no previous Linux result is summed into 72. Original guard text is unchanged and the source checks pass.

## Reproduction

On a Mac with Python 3, use a fresh output path:
```sh
python3 -I -B reproduce.py --out /absolute/fresh/install-reader-env-v2
```
The script verifies the retained manifest, copies only the required source/reference/test files to the fresh directory, repeats the exact parent-source merge checks, and runs all current controls. It neither calls the phone nor imports the production provider.

For the original Mac input derivation, `build_candidate.py --out /absolute/fresh/derived-source` reads its explicitly pinned parent paths. Its default parents are the type candidate and the original environment-v2 package. It also re-reads the actual environment reference request. It creates host files only; it never starts the actor or installation.

The completed candidate resides at:
`/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-fc33-env-v2-type-checks-candidate01`.

See ENTRYPOINTS-AND-INPUT-GAPS.md for the existing freezer/preparer/BUILD/installer/READY entrypoints, source tuple propagation, and actual missing inputs. Changing the native production tuple requires a separately reviewed new formal source chain. This host reader's retained old release/exact8 descriptors have not been rebound to an unbuilt release.

## Scope

Historical contracts are retained as references with their old pins unchanged. CANDIDATE-MANIFEST.json and PACKAGE-MANIFEST.json identify this actual candidate. No private authorization or credential content is included. The code is source preparation and validation, with no phone operations, installation, service changes, new formal identities, automatic replay or qualification promotion.
