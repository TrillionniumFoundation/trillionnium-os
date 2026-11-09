# Exact MNN runtime with real macOS and Linux CI stages

The runtime is compiled on macOS, then its exact original payload is independently
verified and assembled on Linux. The three installed runtime pins and the frozen
Code14 source remain unchanged. No producer string, compiler signature, ELF section,
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

The comparison alone never qualifies a runtime. The unchanged rebuild helper
`62309fa20e51186f37f59e6aba1ea8ace08fb086131b61b47383f89e3c42e861`
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
