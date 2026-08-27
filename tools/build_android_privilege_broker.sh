#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_NDK_REVISION="27.3.13750724"
readonly ANDROID_API_LEVEL="35"
readonly TARGET_TRIPLE="aarch64-linux-android"
readonly PACKAGE="trillionnium-agent-privilege-broker"

fail() {
  echo "build_android_privilege_broker: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || \
  fail "only the reviewed linux-x86_64 NDK host is supported"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
ndk_root="${ANDROID_NDK_ROOT:-}"
[[ -n "$ndk_root" ]] || fail "ANDROID_NDK_ROOT is required"
ndk_root="$(cd -- "$ndk_root" && pwd -P)"

source_properties="$ndk_root/source.properties"
[[ -f "$source_properties" && ! -L "$source_properties" ]] || \
  fail "NDK source.properties must be a regular non-symlink file"
actual_revision="$({
  sed -n 's/^Pkg\.Revision = //p' "$source_properties"
} | sed -n '1p')"
[[ "$actual_revision" == "$EXPECTED_NDK_REVISION" ]] || \
  fail "NDK revision mismatch: expected $EXPECTED_NDK_REVISION, got ${actual_revision:-missing}"
[[ "$(sed -n 's/^Pkg\.Revision = //p' "$source_properties" | wc -l)" == "1" ]] || \
  fail "NDK revision field must occur exactly once"

tool_bin="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"
linker="$tool_bin/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
llvm_ar="$tool_bin/llvm-ar"
readelf="$tool_bin/llvm-readelf"
for tool in "$linker" "$llvm_ar" "$readelf"; do
  [[ -x "$tool" ]] || fail "required NDK tool is absent: $tool"
  resolved_tool="$(readlink -f -- "$tool")"
  [[ -x "$resolved_tool" && "$resolved_tool" == "$tool_bin/"* ]] || \
    fail "required NDK tool resolves outside the pinned toolchain: $tool"
done

target_dir="${TRILLIONNIUM_ANDROID_TARGET_DIR:-$repo_root/target/android-ndk-r27d-api35}"
[[ -n "$target_dir" && "$target_dir" != "/" ]] || fail "unsafe target directory"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker"
export CC_aarch64_linux_android="$linker"
export AR_aarch64_linux_android="$llvm_ar"
export LC_ALL=C
export TZ=UTC

cargo build \
  --frozen \
  --manifest-path "$repo_root/Cargo.toml" \
  --target-dir "$target_dir" \
  --package "$PACKAGE" \
  --release \
  --target "$TARGET_TRIPLE"

binary="$target_dir/$TARGET_TRIPLE/release/$PACKAGE"
[[ -f "$binary" && -x "$binary" && ! -L "$binary" ]] || \
  fail "Cargo did not produce the exact regular executable"

elf="$($readelf -h -l -d "$binary")"
require_elf_text() {
  case "$elf" in
    *"$1"*) ;;
    *) fail "ELF contract missing: $1" ;;
  esac
}

require_elf_text "Class:                             ELF64"
require_elf_text "Data:                              2's complement, little endian"
require_elf_text "Type:                              DYN (Shared object file)"
require_elf_text "Machine:                           AArch64"
require_elf_text "Requesting program interpreter: /system/bin/linker64"
require_elf_text "GNU_RELRO"
require_elf_text "FLAGS_1)    NOW PIE"

stack_line="$(printf '%s\n' "$elf" | sed -n '/GNU_STACK/p')"
[[ "$stack_line" == *" RW "* && "$stack_line" != *" RWE "* ]] || \
  fail "GNU_STACK must be writable and non-executable"
case "$elf" in
  *"(RPATH)"*|*"(RUNPATH)"*|*"(TEXTREL)"*)
    fail "RPATH, RUNPATH, or TEXTREL is forbidden"
    ;;
esac

mapfile -t needed < <(
  printf '%s\n' "$elf" |
    sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
    sort
)
[[ "${#needed[@]}" == "2" && "${needed[0]}" == "libc.so" && "${needed[1]}" == "libdl.so" ]] || \
  fail "unexpected DT_NEEDED closure: ${needed[*]:-empty}"

binary_sha256="$(sha256sum "$binary" | sed -n 's/ .*//p')"
[[ "$binary_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "invalid output SHA-256"

printf 'ANDROID_BROKER_BINARY=%s\n' "$binary"
printf 'ANDROID_BROKER_SHA256=%s\n' "$binary_sha256"
printf 'ANDROID_BROKER_NDK_REVISION=%s\n' "$EXPECTED_NDK_REVISION"
printf 'ANDROID_BROKER_API_LEVEL=%s\n' "$ANDROID_API_LEVEL"
