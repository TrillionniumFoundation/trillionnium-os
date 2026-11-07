# R9 source publication and exact restoration

This directory makes the reviewed R9 source set available for source review and byte-exact restoration. It contains 13 modules read back from the frozen R9 deployment plus the retained **unbound** R9 preparer. It does not replace the active admission protocol, private evidence ledger, actual bound preparer, or full deployment dependency closure.

## Provenance and integration scope

The predecessor is [PR #112](https://github.com/TrillionniumFoundation/trillionnium-os/pull/112), at source head `22e6105c2effe102c0f120a906752003aedfb37d`. Its protected integration target is `integration/razr60-r9-20261107`, initially at `ca3f26100c57579bcb740488e4a7f9ec8b912e4d`. This publication is an additive source-review candidate on that predecessor. It does not merge unrelated branch history or change branch protection.

None of these 14 original source blobs is present byte-for-byte in the predecessor tree. Existing PR #112 checks therefore do not qualify these R9 source bytes. `SOURCE-PROVENANCE.json` records the original source hashes, actual source readback, and predecessor relationship. `SOURCE-MANIFEST.json` binds every public review file to its original SHA-256, byte count, Git blob identity, literal replacement spans, and private restoration input.

| Material | Purpose |
| --- | --- |
| `sources/` | Fourteen readable Python source views, stored as `.py.txt` to keep them distinct from runnable deployment inputs. |
| `expanded/` | Nine readable views of embedded Python or JSON payloads. Their hashes are tied to the embedded public payloads. |
| `SOURCE-MANIFEST.json` | Full original/public source mapping and exact private binding identity. |
| `SANITIZATION-VERIFICATION.json` | Literal substitution inventory and publication boundary. |
| `RECONSTRUCTION-VERIFICATION.json` | Actual complete restoration and refusal-case results. |
| `verify_public_archive.py` | Public member, normalized AST, replacement-span, and embedded-payload verification. |
| `reconstruct_sources.py` | Create-only restoration of all 14 originals; it never runs restored source. |

## Why the public view differs from the original bytes

This repository is public. The frozen source contains private account paths, device identity literals, request identities, runtime job identities, private addresses, and email identities. Only those identity literals are replaced. The replacement inventory is explicit; control flow, operators, numeric constants, guard structure, and original 64-character SHA-256 pins remain in the review view. Embedded source payloads receive the same treatment and also have readable expanded views.

The public view preserves source structure for review, but its substituted string values are not operational bindings. It must not be copied into an active runtime. The restoration utility reverses only the declared byte spans, authenticates the private literals, checks the complete original hash of each restored file, and verifies the original/public AST relationship. This is how the exact reviewed bytes are recovered without treating documentary placeholders as valid device or request identities.

The private binding is `R9-PRIVATE-SOURCE-LITERAL-BINDING.json`, SHA-256 `403d2f78146e5e8b91c91681d6664e7b1bdc1ccfb4f4c9eb7c4e650b821fe0c1`, 104449 bytes. It is retained separately in the private evidence package and must not be committed here. The public manifest uses salted commitments for individual private spans; the salt and original spans are only in the private binding.

## Verify the public archive

Use Python 3.12 or newer from this directory (verified on Python 3.12 and 3.14):

```sh
python3 verify_public_archive.py \
  --expected-manifest-sha256 5e8f476f160559fbe7e4b22c6d964905299d996ecf4e78ff315f56cf2de59a20
```

The versioned AST normalizer retains every semantic field and empty list. Python 3.12 uses its original dump format; Python 3.13 and newer explicitly include empty lists. No unknown field is dropped. Python 3.9 is rejected because it lacks fields in the pinned proof format.

The verifier reads and parses source as data. It checks all 14 source files, all 9 expanded payloads, the 258 declared replacement spans, normalized public AST identities, and embedded payload links. It neither imports those source modules nor contacts a device. The private binding is not required for this check.

## Restore the exact originals privately

Obtain the pinned private binding through the authorized private evidence channel. Choose an output directory that does not exist, whose parent already exists:

```sh
python3 reconstruct_sources.py \
  --manifest SOURCE-MANIFEST.json \
  --expected-manifest-sha256 5e8f476f160559fbe7e4b22c6d964905299d996ecf4e78ff315f56cf2de59a20 \
  --private-binding /private/evidence/R9-PRIVATE-SOURCE-LITERAL-BINDING.json \
  --output /private/review/r9-originals
```

The utility verifies all inputs and reconstructs all 14 files in memory before creating the output directory. It refuses an existing output path, mismatched pins, changed public members, and source symlinks. It creates the output root with mode `0700`, each source file with mode `0600`, and a `RESTORE-RESULT.json` recording the exact restored identities. An I/O failure during final publication can leave a partial newly created directory; the utility will not overwrite it on a subsequent invocation.

The successful verification restored **856082 original bytes across all 14 files**, with every original SHA-256 matching. Existing-output, incorrect manifest pin, tampered private binding, tampered public source, and symlink cases were also checked. No restored source was executed. The verification receipts describe source restoration only.

## Qualification boundary

This package is a source-review candidate. It is not an adopted deployment, a fresh admission, a native NEG pass, a complete fixed19 qualification, an installable BUILD, or a READY/health result. The frozen R9 actual native attempt encountered the existing-listener identity guard; this publication gives it no success credit. The subsequent transport candidate is a different source version and is intentionally outside this set.

Adoption still requires the exact candidate head/base checks, an eligible independent review of the actual source, complete deployment and dependency identity, and the original protocol's fresh runtime evidence. Restoration of the private bytes does not supply any of those runtime admissions or authorize execution.
