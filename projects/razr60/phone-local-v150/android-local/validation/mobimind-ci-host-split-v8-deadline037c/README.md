# Exact MNN runtime with real macOS and Linux CI stages

The runtime is compiled on macOS, then its exact original payload is independently
verified and assembled on Linux. The three installed runtime pins remain unchanged. An independent source-bound helper
admits only the exact Code19 deadline037c candidate source. No producer string, compiler signature, ELF section,
or runtime receipt is rewritten to make a hash match.

## Actual compiler containers

The original Mac and the official SDK-manager installation both report NDK r28b
(`28.1.13356709`) and the same Android clang build. Their 172,733,264-byte universal
Mach-O containers have different whole-file SHA-256 values:

- Original machine: `ff1800041e683dd1c51ce470a291669a67d6cdee1258c409db33c4124dd175f6`.
- Official SDK-manager CI installation: `9f980ecd6dd9e20641589dfd653b2cccbc3f09808f0809387e9673747285a3b3`.

The qualifier accepts neither a version string alone nor arbitrary containers. It
requires one of these exact container hashes and reads the two actual
`LC_CODE_SIGNATURE` ranges. Their offsets and lengths must match the original.
Every byte outside those exact ranges, including Mach-O load commands, architecture
headers, machine code, strings, and padding, is hashed in original order and must
equal the original `60fb4530371a6b738056db82f1a5896bf3b36fd19abe5f8c4be3e9e712052975`.
It also records each slice and section hash, signature-blob hashes, the actual full
container hash, source properties, architecture, and unmodified compiler version.
Failure preserves the observation and stops before the MNN build. This is a
read-only comparison; it does not remove, replace, or validate the trust chain of
code signatures. A successful comparison establishes the precise byte boundary,
not a general claim that similarly named compilers are interchangeable.

The comparison alone never qualifies a runtime. The deadline037c source-bound rebuild helper
`5f2a6a8f8ebd729abf4dd5d75d89af80feaa87180f9b3ea6ff32358d7a07c5c3`
must actually rebuild MNN and the worker, and all three complete output files must
match the original runtime SHA-256 values. Otherwise it exits nonzero and does not
publish the original runtime directory.

## Same-workflow transfer

After the original runtime verifier succeeds, the producer binds the new build
receipt, read-only compiler observation, frozen source manifest, exact source HEAD,
workflow run ID, and run attempt. The Linux consumer reruns the original runtime
verifier, checks the same source/helper/compiler contracts, reconstructs this
binding, and requires a closed set of bundle members. Only then can the Linux
assembler consume the three unchanged ELF files and unchanged original receipt.
The artifact is a short-lived transfer inside the current workflow. The compiler
observation is CI step evidence, not hardware remote attestation. This does not
claim that the MNN files were compiled on Linux or that phone functionality passed.

The previous v1 workflow and its compiler mismatch remain in Git history. Existing
Linux rebuild failure evidence also remains; compiler identity is not suppressed to
make the earlier cross-host mismatch disappear.

## Source revision boundary

This independent directory binds only app manifest
`fdab3c67d726aa44c19c9efe4d65cc845ee433dbabe2d97f7fe7fb07b92bcec7` and
`../mobimind-runtime-rebuild-v8-deadline037c/rebuild_exact_runtime.py`.
The app patch was introduced at commit
`a08f23614f48581f4bb23238e0c5bf2430b7d411`, based on frozen Code19 commit
`fdb7eca8d3a434c515da547365fcc47bb2f510d3` and app manifest
`9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69`.

Both v7 helper directories remain byte-for-byte unchanged. The compiler qualifier
is copied without modification. The transfer implementation differs from v7 only
in its exact app manifest and rebuild-helper SHA-256. All native/runtime/compiler
pins and every transfer, receipt, source/run/attempt, strict-type, file-identity,
and closed-membership check are unchanged. Reports from the original frozen
Code19 build and reports with unknown source/helper hashes are rejected.

The workflow passes its actual checked-out HEAD, run ID, and attempt to both
producer and consumer, including on later commits containing these CI helpers.
The historical app-patch commit is documentation of provenance, not a replacement
for the current workflow identity. Each new helper directory has its own complete
`SOURCE-MANIFEST.json`; the consumer pins the exact rebuild helper bytes.

## Regressions and limits

From this directory run:

```sh
python -B -m unittest -v test_deadline_source_binding.py
```

The workflow runs these tests before compiler installation and native rebuild.
They check the actual candidate source closure, reproduce v7's refusal, reject
modified/missing/unlisted/symlinked source members, verify both new helper
manifests, pin all seven frozen v7 files, and prove exact implementation equality
outside the explicit source/helper/label substitutions. The same proof covers all
native build options, compiler rules, ELF checks, and runtime pins. Real CLI
negative tests exercise producer and consumer rejection before runtime access.
Synthetic report objects test only the report-field contract and are never
written as build receipts or admitted as runtime bundles.

For an isolated sparse review tree, the tests alone accept an explicit local app
path through `HEPTA_CI_BINDING_APP_SOURCE`; the production helpers do not consult
this variable and still verify the entire exact pinned source. In the repository
CI checkout the default app path is the sibling `lfm3-controller` directory.

A passing local contract run does not prove a successful macOS native rebuild,
Linux assembly, installed APK identity, model inference, or phone task completion.
Those require fresh, separately evidenced workflow and device runs. No phone
command or package upgrade is performed by these helpers or tests.
