# Exact MNN runtime with real macOS and Linux CI stages

The runtime is compiled on macOS, then its exact original payload is independently
verified and assembled on Linux. The three installed runtime pins remain unchanged. A new source-bound helper
admits the frozen public Code20 source. No producer string, compiler signature, ELF section,
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

The comparison alone never qualifies a runtime. The public Code20 source-bound rebuild helper
`961594375f7a8c6967426695b38f478106c09fa02e8c60b52eda3061f816d65d`
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

This v8 binds only public Code20 manifest `1873ca6ecf998b7f3d3e447de2c9af5004c53c870042e2faef28be94265b40f4` and
`../mobimind-runtime-rebuild-v8/rebuild_exact_runtime.py`. The prior v7 helpers
and Code19 results remain preserved. The compiler qualifier is byte-identical
to v7, and all three original complete runtime SHA-256 pins remain unchanged.
A Code19 build receipt is rejected for this public Code20 transfer.

public Code20 phone qualification remains separate from this CI binding. Source
verification, host checks, and packaging cannot establish task completion.
