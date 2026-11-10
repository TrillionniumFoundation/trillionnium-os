# Preserve the original runtime's actual build host

The first Code14 Linux CI compiled the fixed source successfully and rejected
the resulting MNN and worker files because their full hashes differed from the
original macOS-built runtime. The C++ library matched. Those failures and
comparison artifacts remain unchanged; they do not qualify alternate binaries.

The original macOS runtime contains genuine compiler-identification strings
for both the prebuilt Android CRT and the actual macOS compiler. The Linux
compiler has different build-configuration markers. No producer or `.comment`
identity is overridden, stripped, or edited here. The exact extent of the Linux
section differences is not claimed merely from matching file-size differences.

The workflow therefore builds the fixed public source on macOS with the actual
pinned NDK r28b compiler, using the existing path-reproducible helper. The three
original whole-file hashes must all match before the job can provide runtime
inputs. A short-lived artifact within the same workflow transfers the three
files, the unchanged original receipt, the distinct new build receipt and a
binding to the exact source HEAD, workflow run ID and attempt.

Linux continues to run the original source closure, host contracts, Android
Java/DEX and GenieX arm64 compilation. It downloads only the current workflow's
named artifact and independently rechecks all original runtime bytes and
receipts before assembly. The consumer also verifies that the new build receipt
records the actual macOS compiler and this exact App/helper closure. A mismatch
fails assembly. It does not fall back to an old binary or a functionally similar
build.

The artifact is an inter-job build input, not a public release or a binary
committed to the repository. It contains no signing key, model weight or phone
capture. The original App source, native payload pins and acceptance assertions
remain unchanged. A successful combined job means macOS rebuilt the MNN
runtime and Linux verified/assembled it; it never means Linux compiled
byte-identical MNN files.
