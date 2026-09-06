# Owner-open ARM64 adb artifact qualification

This directory qualifies one **ordinary Linux ARM64 adb client** for the r4 W3
Root Linux payload. It does not build, download, install, start or contact adb.

## Inputs

1. the candidate executable;
2. a metadata JSON matching
   `owner-open-adb-arm64-artifact.schema.json`;
3. raw `adb version` output captured while that exact candidate runs on a Linux
   ARM64 environment.

## Verification

```sh
python3 packaging/owner-open-adb/verify_arm64_adb.py \
  --artifact out/adb \
  --metadata out/adb-artifact.json \
  --version-output out/adb-version.txt \
  --json
```

The verifier checks:

- real single-link executable regular file;
- no group/world write bit;
- bounded size and stable inode/metadata while read;
- ELF64, little endian, executable/PIE and `EM_AARCH64`;
- exact SHA-256 and byte size;
- fixed Root Linux install path `/usr/bin/adb` and mode `0755`;
- recorded source kind, revision/version, provenance, license, build/package
  command and toolchain/repository;
- exact digest of non-empty output identifying Android Debug Bridge;
- claims limited to a qualified ordinary source artifact.

A pass means only:

```text
QUALIFIED_SOURCE_ARTIFACT_ONLY
```

It does not prove rootfs or Android image inclusion, a working server/tunnel, an
integrated Codex turn, a physical device effect or release qualification.

## Capture order

1. Build or obtain the candidate from the pinned source/package.
2. Copy it into a read-only staging directory and make it mode `0755`.
3. On Linux ARM64, run the exact staged binary with `version`; capture stdout and
   stderr according to the build recipe without rewriting it.
4. Compute candidate and version-output hashes.
5. Author the closed metadata document with all product/device/release claims
   false.
6. Run the verifier from a separate process.
7. Bind the accepted report and inputs into the Root Linux BOM.
8. Only after a clean payload build, inspect `/usr/bin/adb` inside the rootfs and
   repeat the hash/version check.

The pre-r3 typed `trillionnium-agent-adb` binary cannot satisfy this workflow.
