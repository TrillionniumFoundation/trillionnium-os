#!/bin/bash
set -euo pipefail

fail() {
  echo "build-root-linux-arm64: $*" >&2
  exit 1
}

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <output-directory>" >&2
  exit 2
fi

readonly TARGET_TRIPLE="aarch64-unknown-linux-gnu"
readonly MAX_GLIBC="2.36"
readonly EXPECTED_INTERPRETER="/lib/ld-linux-aarch64.so.1"
readonly EXPECTED_DIRECT_NEEDED=$'libgcc_s.so.1\nlibc.so.6'
readonly EXPECTED_DAEMON_NEEDED=$'libgcc_s.so.1\nlibm.so.6\nlibc.so.6'
# This digest binds the reviewed, sanitized, non-writable Cargo dependency
# closure. Changing the cache requires a source review. It does not approve
# the cache's origin or custody.
readonly SOURCE_FIXED_CARGO_HOME_MANIFEST_SHA256="711d39583b0004485a9e226442f1476a203a32601fac061198c9d6f933520b63"
# This location-independent digest binds every regular-file byte, path,
# symlink target and stable POSIX lstat field in the private toolchain tree.
# Its material origin and custody still require independent approval.
readonly SOURCE_FIXED_PRIVATE_TOOLCHAIN_MANIFEST_SHA256="8ee268e616feb4d5d9cb07ba363d4966c88bfb915d2d0147014cbed6d45a05d2"
readonly SOURCE_FIXED_LINKER_SHA256="eb7dfc1dcdf23188d8ff8d82a8ab630b0842c0a2ecc8256fc677830e2217b074"
readonly SOURCE_FIXED_ARCHIVER_SHA256="19dd4f149741f577657fa54ffe0673b5cd71493fa016b5a19ede31c7a0b73009"
readonly SOURCE_FIXED_RUSTC_SHA256="df13f58759c0662831983e3a6501c63c1fc12ea60ec4e1d1ac35e5fe43c500c0"
readonly SOURCE_FIXED_CARGO_SHA256="eff12bab37b9d9e01324db4583eaf55b2cd82ac3008a7e59876e4cd2e9a028f5"
readonly SOURCE_FIXED_SYSROOT_LIBC_SHA256="e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0"
readonly SOURCE_FIXED_SYSROOT_LOADER_SHA256="17538b8f9889a470c061f69a8fea8124da89627311cd16546c133a89f09056df"
readonly SOURCE_FIXED_SYSROOT_LIBGCC_S_SHA256="c39939ec474dd03d9a8aa657d85fa71a8f879a3159bf1a5d19dff3b4788dfba2"
readonly SOURCE_FIXED_SYSROOT_LIBM_SHA256="3c4cb3be0b974edf05f023f85ab15107fb5afc2687163593d0d4cf8e80c17b39"
readonly HOST_TOOL_NAMES=(
  as
  awk
  bash
  basename
  env
  file
  find
  grep
  install
  ld
  mkdir
  readlink
  readelf
  realpath
  sed
  sha256sum
  sort
  stat
  tail
  xargs
)

HOST_TOOLS_DIRECTORY="${TRILLIONNIUM_ROOT_LINUX_HOST_TOOLS_DIRECTORY:-}"
[[ -n "$HOST_TOOLS_DIRECTORY" ]] ||
  fail "TRILLIONNIUM_ROOT_LINUX_HOST_TOOLS_DIRECTORY is required"
[[ "$HOST_TOOLS_DIRECTORY" = /* ]] ||
  fail "host tools directory must be absolute"
[[ -d "$HOST_TOOLS_DIRECTORY" && ! -L "$HOST_TOOLS_DIRECTORY" ]] ||
  fail "host tools directory must be real and non-symlink"
[[ ! -w "$HOST_TOOLS_DIRECTORY" ]] ||
  fail "host tools directory must not be writable"

shopt -s dotglob nullglob
host_tool_entries=("$HOST_TOOLS_DIRECTORY"/*)
shopt -u dotglob nullglob
[[ "${#host_tool_entries[@]}" -eq "${#HOST_TOOL_NAMES[@]}" ]] ||
  fail "host tools directory must contain exactly the fixed tool-name closure"
for name in "${HOST_TOOL_NAMES[@]}"; do
  path="$HOST_TOOLS_DIRECTORY/$name"
  [[ -f "$path" && -x "$path" && ! -L "$path" && ! -w "$path" ]] ||
    fail "host tool must be an executable, non-writable regular file: $path"
done
for path in "${host_tool_entries[@]}"; do
  name="${path##*/}"
  allowed=false
  for expected in "${HOST_TOOL_NAMES[@]}"; do
    if [[ "$name" == "$expected" ]]; then
      allowed=true
      break
    fi
  done
  "$allowed" || fail "unexpected host tool: $path"
done

readonly HOST_AWK="$HOST_TOOLS_DIRECTORY/awk"
readonly HOST_BASENAME="$HOST_TOOLS_DIRECTORY/basename"
readonly HOST_ENV="$HOST_TOOLS_DIRECTORY/env"
readonly HOST_FILE="$HOST_TOOLS_DIRECTORY/file"
readonly HOST_FIND="$HOST_TOOLS_DIRECTORY/find"
readonly HOST_GREP="$HOST_TOOLS_DIRECTORY/grep"
readonly HOST_INSTALL="$HOST_TOOLS_DIRECTORY/install"
readonly HOST_MKDIR="$HOST_TOOLS_DIRECTORY/mkdir"
readonly HOST_READLINK="$HOST_TOOLS_DIRECTORY/readlink"
readonly HOST_READELF="$HOST_TOOLS_DIRECTORY/readelf"
readonly HOST_REALPATH="$HOST_TOOLS_DIRECTORY/realpath"
readonly HOST_SED="$HOST_TOOLS_DIRECTORY/sed"
readonly HOST_SHA256SUM="$HOST_TOOLS_DIRECTORY/sha256sum"
readonly HOST_SORT="$HOST_TOOLS_DIRECTORY/sort"
readonly HOST_STAT="$HOST_TOOLS_DIRECTORY/stat"
readonly HOST_TAIL="$HOST_TOOLS_DIRECTORY/tail"
readonly HOST_XARGS="$HOST_TOOLS_DIRECTORY/xargs"

HOST_TOOLS_DIRECTORY="$("$HOST_REALPATH" -e "$HOST_TOOLS_DIRECTORY")"
readonly HOST_TOOLS_DIRECTORY
export PATH="$HOST_TOOLS_DIRECTORY"
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD

readonly FIXED_HOST_BASH="$("$HOST_REALPATH" -e "$HOST_TOOLS_DIRECTORY/bash")"
readonly ACTUAL_HOST_BASH="$("$HOST_REALPATH" -e "/proc/$$/exe")"
[[ "$ACTUAL_HOST_BASH" == "$FIXED_HOST_BASH" ]] ||
  fail "actual Bash interpreter is not the fixed host tool: $ACTUAL_HOST_BASH"
[[ "/proc/$$/exe" -ef "$FIXED_HOST_BASH" ]] ||
  fail "actual Bash interpreter inode is not the fixed host tool"
readonly ACTUAL_HOST_BASH_SHA256="$(
  "$HOST_SHA256SUM" "/proc/$$/exe" |
    "$HOST_AWK" '{print $1}'
)"
printf 'host_interpreter path=%s actual_interpreter_sha256=%s\n' \
  "$ACTUAL_HOST_BASH" \
  "$ACTUAL_HOST_BASH_SHA256"

WORKSPACE="$(cd "${BASH_SOURCE[0]%/*}/../../.." && pwd -P)"
OUTPUT_DIRECTORY="$("$HOST_REALPATH" -m "$1")"
readonly CARGO_HOME_MANIFEST_TOOL="$WORKSPACE/crates/trillionnium-agent-direct-tools/tools/canonical-root-linux-cargo-home-manifest.sh"
readonly PRIVATE_TOOLCHAIN_MANIFEST_TOOL="$WORKSPACE/crates/trillionnium-agent-direct-tools/tools/canonical-root-linux-toolchain-manifest.sh"
PRIVATE_TOOLCHAIN_ROOT="${TRILLIONNIUM_ROOT_LINUX_PRIVATE_TOOLCHAIN_ROOT:-}"
LINKER="${TRILLIONNIUM_AARCH64_LINUX_GNU_LINKER:-}"
SYSROOT="${TRILLIONNIUM_AARCH64_LINUX_GNU_SYSROOT:-}"
ARCHIVER="${TRILLIONNIUM_AARCH64_LINUX_GNU_AR:-}"
CARGO="${TRILLIONNIUM_ROOT_LINUX_CARGO:-}"
RUSTC="${TRILLIONNIUM_ROOT_LINUX_RUSTC:-}"
HOST_LINKER="${TRILLIONNIUM_ROOT_LINUX_HOST_LINKER:-}"
HOST_ARCHIVER="${TRILLIONNIUM_ROOT_LINUX_HOST_AR:-}"

[[ -n "$PRIVATE_TOOLCHAIN_ROOT" ]] ||
  fail "TRILLIONNIUM_ROOT_LINUX_PRIVATE_TOOLCHAIN_ROOT is required"
[[ -n "$LINKER" ]] ||
  fail "TRILLIONNIUM_AARCH64_LINUX_GNU_LINKER is required"
[[ -n "$SYSROOT" ]] ||
  fail "TRILLIONNIUM_AARCH64_LINUX_GNU_SYSROOT is required"
[[ -n "$ARCHIVER" ]] ||
  fail "TRILLIONNIUM_AARCH64_LINUX_GNU_AR is required"
[[ -n "$CARGO" ]] ||
  fail "TRILLIONNIUM_ROOT_LINUX_CARGO is required"
[[ -n "$RUSTC" ]] ||
  fail "TRILLIONNIUM_ROOT_LINUX_RUSTC is required"
[[ -n "$HOST_LINKER" ]] ||
  fail "TRILLIONNIUM_ROOT_LINUX_HOST_LINKER is required"
[[ -n "$HOST_ARCHIVER" ]] ||
  fail "TRILLIONNIUM_ROOT_LINUX_HOST_AR is required"
[[ -n "${CARGO_HOME:-}" ]] || fail "an explicit private CARGO_HOME is required"
[[ -n "${CARGO_TARGET_DIR:-}" ]] ||
  fail "an explicit fresh CARGO_TARGET_DIR is required"
[[ -n "${SOURCE_DATE_EPOCH:-}" ]] ||
  fail "SOURCE_DATE_EPOCH is required"
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] ||
  fail "SOURCE_DATE_EPOCH must be a positive integer"

for path in "$LINKER" "$ARCHIVER" "$CARGO" "$RUSTC" "$HOST_LINKER" "$HOST_ARCHIVER"; do
  [[ "$path" = /* ]] || fail "tool path must be absolute: $path"
  [[ -f "$path" && -x "$path" && ! -L "$path" ]] ||
    fail "tool must be an executable regular non-symlink: $path"
done
for path in "$PRIVATE_TOOLCHAIN_ROOT" "$SYSROOT" "$CARGO_HOME"; do
  [[ "$path" = /* ]] || fail "directory path must be absolute: $path"
  [[ -d "$path" && ! -L "$path" ]] ||
    fail "directory must be real and non-symlink: $path"
done
[[ -f "$CARGO_HOME_MANIFEST_TOOL" && ! -L "$CARGO_HOME_MANIFEST_TOOL" ]] ||
  fail "canonical Cargo-home manifest tool is missing or a symlink"
[[ -f "$PRIVATE_TOOLCHAIN_MANIFEST_TOOL" && ! -L "$PRIVATE_TOOLCHAIN_MANIFEST_TOOL" ]] ||
  fail "canonical private-toolchain manifest tool is missing or a symlink"
[[ "$CARGO_TARGET_DIR" = /* ]] ||
  fail "CARGO_TARGET_DIR must be absolute"
[[ ! -e "$CARGO_TARGET_DIR" && ! -L "$CARGO_TARGET_DIR" ]] ||
  fail "CARGO_TARGET_DIR must not preexist"
[[ ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]] ||
  fail "output directory must not preexist"

PRIVATE_TOOLCHAIN_ROOT="$("$HOST_REALPATH" -e "$PRIVATE_TOOLCHAIN_ROOT")"
SYSROOT="$("$HOST_REALPATH" -e "$SYSROOT")"
CARGO_HOME="$("$HOST_REALPATH" -e "$CARGO_HOME")"
LINKER="$("$HOST_REALPATH" -e "$LINKER")"
ARCHIVER="$("$HOST_REALPATH" -e "$ARCHIVER")"
CARGO="$("$HOST_REALPATH" -e "$CARGO")"
RUSTC="$("$HOST_REALPATH" -e "$RUSTC")"
HOST_LINKER="$("$HOST_REALPATH" -e "$HOST_LINKER")"
HOST_ARCHIVER="$("$HOST_REALPATH" -e "$HOST_ARCHIVER")"
CARGO_TARGET_DIR="$("$HOST_REALPATH" -m "$CARGO_TARGET_DIR")"

for path in "$LINKER" "$ARCHIVER" "$CARGO" "$RUSTC" "$SYSROOT"; do
  case "$path" in
    "$PRIVATE_TOOLCHAIN_ROOT"/*) ;;
    *) fail "private build input escapes the manifested toolchain: $path" ;;
  esac
done
[[ "$EUID" -eq 1000 ]] ||
  fail "private-toolchain read-only proof requires the fixed runtime uid 1000"
TOOLCHAIN_MOUNT_OPTIONS="$(
  "$HOST_AWK" -v target="$PRIVATE_TOOLCHAIN_ROOT" \
    '$5 == target { print $6 }' /proc/self/mountinfo
)"
[[ -n "$TOOLCHAIN_MOUNT_OPTIONS" && "$TOOLCHAIN_MOUNT_OPTIONS" != *$'\n'* ]] ||
  fail "private toolchain must be one exact mount point"
case ",$TOOLCHAIN_MOUNT_OPTIONS," in
  *,ro,*) ;;
  *) fail "private toolchain mount is not read-only" ;;
esac
for path in "$PRIVATE_TOOLCHAIN_ROOT" "$LINKER" "$ARCHIVER" "$CARGO" "$RUSTC" "$SYSROOT"; do
  [[ ! -w "$path" ]] ||
    fail "private-toolchain mount input is writable for runtime uid 1000: $path"
done

case "$OUTPUT_DIRECTORY/" in
  "$CARGO_TARGET_DIR/"*|"$CARGO_TARGET_DIR/") fail "output overlaps Cargo target" ;;
esac
case "$CARGO_TARGET_DIR/" in
  "$OUTPUT_DIRECTORY/"*|"$OUTPUT_DIRECTORY/") fail "Cargo target overlaps output" ;;
esac
for writable_path in "$CARGO_TARGET_DIR" "$OUTPUT_DIRECTORY"; do
  case "$writable_path/" in
    "$PRIVATE_TOOLCHAIN_ROOT/"*) fail "writable output overlaps private toolchain" ;;
  esac
done

require_source_fixed_sha256() {
  local description="$1"
  local path="$2"
  local expected="$3"
  local observed
  observed="$("$HOST_SHA256SUM" "$path" | "$HOST_AWK" '{print $1}')"
  [[ "$observed" == "$expected" ]] ||
    fail "$description digest does not match the source-fixed digest: $observed"
}

require_source_fixed_sha256 linker "$LINKER" "$SOURCE_FIXED_LINKER_SHA256"
require_source_fixed_sha256 archiver "$ARCHIVER" "$SOURCE_FIXED_ARCHIVER_SHA256"
require_source_fixed_sha256 rustc "$RUSTC" "$SOURCE_FIXED_RUSTC_SHA256"
require_source_fixed_sha256 cargo "$CARGO" "$SOURCE_FIXED_CARGO_SHA256"

[[ "$("$LINKER" -dumpmachine)" == "aarch64-linux-gnu" ]] ||
  fail "linker target is not aarch64-linux-gnu"
LINKER_SYSROOT="$("$LINKER" -print-sysroot)"
[[ -n "$LINKER_SYSROOT" && -d "$LINKER_SYSROOT" ]] ||
  fail "linker did not report a usable sysroot"
[[ "$("$HOST_REALPATH" -e "$LINKER_SYSROOT")" == "$SYSROOT" ]] ||
  fail "linker sysroot does not match the explicit sysroot"

SYSROOT_LIBC="$SYSROOT/lib/aarch64-linux-gnu/libc.so.6"
SYSROOT_LOADER="$SYSROOT/lib/ld-linux-aarch64.so.1"
SYSROOT_LIBGCC_S="$("$LINKER" -print-file-name=libgcc_s.so.1)"
SYSROOT_LIBM="$SYSROOT/lib/aarch64-linux-gnu/libm.so.6"
[[ -f "$SYSROOT_LIBC" ]] || fail "sysroot libc is missing"
[[ -e "$SYSROOT_LOADER" ]] || fail "sysroot AArch64 loader is missing"
[[ -f "$SYSROOT_LIBM" ]] || fail "sysroot libm is missing"
for provider in \
  "$SYSROOT_LIBC" \
  "$SYSROOT_LOADER" \
  "$SYSROOT_LIBGCC_S" \
  "$SYSROOT_LIBM"; do
  [[ -e "$provider" ]] || fail "runtime provider is missing: $provider"
  provider_real="$("$HOST_REALPATH" -e "$provider")"
  case "$provider_real" in
    "$SYSROOT"/*) ;;
    *) fail "runtime provider escapes the explicit sysroot: $provider_real" ;;
  esac
done
SYSROOT_LIBC="$("$HOST_REALPATH" -e "$SYSROOT_LIBC")"
SYSROOT_LOADER="$("$HOST_REALPATH" -e "$SYSROOT_LOADER")"
SYSROOT_LIBGCC_S="$("$HOST_REALPATH" -e "$SYSROOT_LIBGCC_S")"
SYSROOT_LIBM="$("$HOST_REALPATH" -e "$SYSROOT_LIBM")"
readonly SYSROOT_LIBC SYSROOT_LOADER SYSROOT_LIBGCC_S SYSROOT_LIBM
for path in "$SYSROOT_LIBC" "$SYSROOT_LOADER" "$SYSROOT_LIBGCC_S" "$SYSROOT_LIBM"; do
  [[ ! -w "$path" ]] ||
    fail "private-toolchain runtime provider is writable for runtime uid 1000: $path"
done
require_source_fixed_sha256 \
  sysroot-libc "$SYSROOT_LIBC" "$SOURCE_FIXED_SYSROOT_LIBC_SHA256"
require_source_fixed_sha256 \
  sysroot-loader "$SYSROOT_LOADER" "$SOURCE_FIXED_SYSROOT_LOADER_SHA256"
require_source_fixed_sha256 \
  sysroot-libgcc-s "$SYSROOT_LIBGCC_S" "$SOURCE_FIXED_SYSROOT_LIBGCC_S_SHA256"
require_source_fixed_sha256 \
  sysroot-libm "$SYSROOT_LIBM" "$SOURCE_FIXED_SYSROOT_LIBM_SHA256"

max_glibc() {
  local binary="$1"
  local maximum
  maximum="$(
    "$HOST_READELF" --version-info "$binary" |
      "$HOST_GREP" -oE 'GLIBC_[0-9]+\.[0-9]+' |
      "$HOST_SED" 's/^GLIBC_//' |
      "$HOST_SORT" -Vu |
      "$HOST_TAIL" -n 1
  )"
  [[ -n "$maximum" ]] || fail "no GLIBC version requirements found: $binary"
  printf '%s' "$maximum"
}

version_at_most() {
  local observed="$1"
  local allowed="$2"
  [[ "$(
    printf '%s\n%s\n' "$observed" "$allowed" |
      "$HOST_SORT" -Vu |
      "$HOST_TAIL" -n 1
  )" == "$allowed" ]]
}

SYSROOT_MAX_GLIBC="$(max_glibc "$SYSROOT_LIBC")"
version_at_most "$SYSROOT_MAX_GLIBC" "$MAX_GLIBC" ||
  fail "sysroot exports GLIBC_$SYSROOT_MAX_GLIBC, newer than GLIBC_$MAX_GLIBC"
SYSROOT_LIBM_MAX_GLIBC="$(max_glibc "$SYSROOT_LIBM")"
version_at_most "$SYSROOT_LIBM_MAX_GLIBC" "$MAX_GLIBC" ||
  fail "sysroot libm exports GLIBC_$SYSROOT_LIBM_MAX_GLIBC, newer than GLIBC_$MAX_GLIBC"

for variable in \
  RUSTFLAGS \
  RUSTDOCFLAGS \
  RUSTC_WRAPPER \
  RUSTC_WORKSPACE_WRAPPER \
  CARGO_ENCODED_RUSTFLAGS \
  CARGO_BUILD_RUSTC_WRAPPER \
  CC \
  AR \
  CFLAGS \
  CFLAGS_aarch64_unknown_linux_gnu \
  CFLAGS_AARCH64_UNKNOWN_LINUX_GNU \
  CPPFLAGS \
  CPPFLAGS_aarch64_unknown_linux_gnu \
  CPPFLAGS_AARCH64_UNKNOWN_LINUX_GNU \
  LDFLAGS \
  PKG_CONFIG_PATH; do
  [[ -z "${!variable:-}" ]] ||
    fail "ambient build flag is forbidden: $variable"
done
[[ -z "${TRILLIONNIUM_ROOT_LINUX_CARGO_HOME_MANIFEST_SHA256:-}" ]] ||
  fail "caller-supplied Cargo-home digests are forbidden; the closure is source-fixed"
[[ -z "${TRILLIONNIUM_ROOT_LINUX_PRIVATE_TOOLCHAIN_MANIFEST_SHA256:-}" ]] ||
  fail "caller-supplied private-toolchain digests are forbidden; the closure is source-fixed"
for config in \
  "$WORKSPACE/.cargo/config" \
  "$WORKSPACE/.cargo/config.toml" \
  "$CARGO_HOME/config" \
  "$CARGO_HOME/config.toml"; do
  [[ ! -e "$config" && ! -L "$config" ]] ||
    fail "ambient Cargo config is forbidden: $config"
done

"$HOST_MKDIR" -m 0700 "$CARGO_TARGET_DIR"
[[ -z "$("$HOST_FIND" "$CARGO_TARGET_DIR" -mindepth 1 -print -quit)" ]] ||
  fail "new Cargo target is not empty"

readonly CARGO_HOME_MANIFEST_TOOL_SHA256="$(
  "$HOST_SHA256SUM" "$CARGO_HOME_MANIFEST_TOOL" |
    "$HOST_AWK" '{print $1}'
)"
readonly PRIVATE_TOOLCHAIN_MANIFEST_TOOL_SHA256="$(
  "$HOST_SHA256SUM" "$PRIVATE_TOOLCHAIN_MANIFEST_TOOL" |
    "$HOST_AWK" '{print $1}'
)"
readonly PREBUILD_PRIVATE_TOOLCHAIN_MANIFEST="$CARGO_TARGET_DIR/private-toolchain.prebuild.manifest0"
"$FIXED_HOST_BASH" "$PRIVATE_TOOLCHAIN_MANIFEST_TOOL" "$PRIVATE_TOOLCHAIN_ROOT" \
  >"$PREBUILD_PRIVATE_TOOLCHAIN_MANIFEST"
readonly PREBUILD_PRIVATE_TOOLCHAIN_MANIFEST_SHA256="$(
  "$HOST_SHA256SUM" "$PREBUILD_PRIVATE_TOOLCHAIN_MANIFEST" |
    "$HOST_AWK" '{print $1}'
)"
[[ "$PREBUILD_PRIVATE_TOOLCHAIN_MANIFEST_SHA256" == "$SOURCE_FIXED_PRIVATE_TOOLCHAIN_MANIFEST_SHA256" ]] ||
  fail "private-toolchain closure digest does not match the source-fixed digest"
readonly PREBUILD_CARGO_HOME_MANIFEST="$CARGO_TARGET_DIR/cargo-home.prebuild.manifest0"
"$FIXED_HOST_BASH" "$CARGO_HOME_MANIFEST_TOOL" "$CARGO_HOME" \
  >"$PREBUILD_CARGO_HOME_MANIFEST"
readonly PREBUILD_CARGO_HOME_MANIFEST_SHA256="$(
  "$HOST_SHA256SUM" "$PREBUILD_CARGO_HOME_MANIFEST" |
    "$HOST_AWK" '{print $1}'
)"
[[ "$PREBUILD_CARGO_HOME_MANIFEST_SHA256" == "$SOURCE_FIXED_CARGO_HOME_MANIFEST_SHA256" ]] ||
  fail "Cargo-home closure digest does not match the source-fixed digest"

readonly REMAPPED_WORKSPACE="/usr/src/trillionnium-os"
readonly REMAPPED_SYSROOT="/opt/trillionnium-bookworm-sysroot"
readonly REMAPPED_CARGO_HOME="/opt/trillionnium-cargo-home"
readonly REMAPPED_CARGO_TARGET_DIR="/opt/trillionnium-cargo-target"
for source_path in \
  "$WORKSPACE" \
  "$PRIVATE_TOOLCHAIN_ROOT" \
  "$SYSROOT" \
  "$CARGO_HOME" \
  "$CARGO_TARGET_DIR"; do
  for remapped_path in \
    "$REMAPPED_WORKSPACE" \
    "$REMAPPED_SYSROOT" \
    "$REMAPPED_CARGO_HOME" \
    "$REMAPPED_CARGO_TARGET_DIR"; do
    [[ "$remapped_path" != *"$source_path"* ]] ||
      fail "remap destination contains a source build path: $remapped_path"
  done
done
readonly FIXED_RUSTFLAGS="-C link-arg=-Wl,-rpath-link,$SYSROOT/lib/aarch64-linux-gnu -C link-arg=-Wl,-rpath-link,$SYSROOT/usr/lib/aarch64-linux-gnu -C link-arg=-Wl,--as-needed -C link-arg=-Wl,--build-id=sha1 -C link-arg=-Wl,-z,relro,-z,now --remap-path-prefix=$WORKSPACE=$REMAPPED_WORKSPACE --remap-path-prefix=$SYSROOT=$REMAPPED_SYSROOT --remap-path-prefix=$CARGO_HOME=$REMAPPED_CARGO_HOME --remap-path-prefix=$CARGO_TARGET_DIR=$REMAPPED_CARGO_TARGET_DIR"

cd "$WORKSPACE"
"$HOST_ENV" -i \
  PATH="$HOST_TOOLS_DIRECTORY" \
  HOME="$CARGO_HOME" \
  LC_ALL=C \
  TZ=UTC \
  ZERO_AR_DATE=1 \
  CARGO_NET_OFFLINE=true \
  CARGO_HOME="$CARGO_HOME" \
  CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  RUSTC="$RUSTC" \
  CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
  CARGO_PROFILE_RELEASE_DEBUG=0 \
  CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false \
  CARGO_PROFILE_RELEASE_INCREMENTAL=false \
  CARGO_PROFILE_RELEASE_STRIP=symbols \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$HOST_LINKER" \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$LINKER" \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$FIXED_RUSTFLAGS" \
  CC_x86_64_unknown_linux_gnu="$HOST_LINKER" \
  AR_x86_64_unknown_linux_gnu="$HOST_ARCHIVER" \
  CC_aarch64_unknown_linux_gnu="$LINKER" \
  AR_aarch64_unknown_linux_gnu="$ARCHIVER" \
  LIBSQLITE3_SYS_USE_PKG_CONFIG=0 \
  PKG_CONFIG_ALLOW_CROSS=1 \
  PKG_CONFIG_SYSROOT_DIR="$SYSROOT" \
  PKG_CONFIG_LIBDIR="$SYSROOT/usr/lib/aarch64-linux-gnu/pkgconfig:$SYSROOT/usr/share/pkgconfig" \
  PKG_CONFIG_PATH= \
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  "$CARGO" build \
    --release \
    --locked \
    --offline \
    --no-default-features \
    --features trillionnium-agent-direct-tools/production-durable-hotpath \
    --target "$TARGET_TRIPLE" \
    -p trillionnium-agent-direct-tools \
    -p trillionniumd

readonly POSTBUILD_CARGO_HOME_MANIFEST="$CARGO_TARGET_DIR/cargo-home.postbuild.manifest0"
"$FIXED_HOST_BASH" "$CARGO_HOME_MANIFEST_TOOL" "$CARGO_HOME" \
  >"$POSTBUILD_CARGO_HOME_MANIFEST"
readonly POSTBUILD_CARGO_HOME_MANIFEST_SHA256="$(
  "$HOST_SHA256SUM" "$POSTBUILD_CARGO_HOME_MANIFEST" |
    "$HOST_AWK" '{print $1}'
)"
[[ "$POSTBUILD_CARGO_HOME_MANIFEST_SHA256" == "$SOURCE_FIXED_CARGO_HOME_MANIFEST_SHA256" ]] ||
  fail "Cargo-home closure changed during the build"

readonly POSTBUILD_PRIVATE_TOOLCHAIN_MANIFEST="$CARGO_TARGET_DIR/private-toolchain.postbuild.manifest0"
"$FIXED_HOST_BASH" "$PRIVATE_TOOLCHAIN_MANIFEST_TOOL" "$PRIVATE_TOOLCHAIN_ROOT" \
  >"$POSTBUILD_PRIVATE_TOOLCHAIN_MANIFEST"
readonly POSTBUILD_PRIVATE_TOOLCHAIN_MANIFEST_SHA256="$(
  "$HOST_SHA256SUM" "$POSTBUILD_PRIVATE_TOOLCHAIN_MANIFEST" |
    "$HOST_AWK" '{print $1}'
)"
[[ "$POSTBUILD_PRIVATE_TOOLCHAIN_MANIFEST_SHA256" == "$SOURCE_FIXED_PRIVATE_TOOLCHAIN_MANIFEST_SHA256" ]] ||
  fail "private-toolchain closure changed during the build"

"$HOST_MKDIR" -m 0755 "$OUTPUT_DIRECTORY"
for name in system-api accessibility adb; do
  source_path="$CARGO_TARGET_DIR/$TARGET_TRIPLE/release/trillionnium-agent-$name"
  [[ -f "$source_path" ]] || fail "built Direct tool is missing: $source_path"
  "$HOST_INSTALL" -m 0755 "$source_path" "$OUTPUT_DIRECTORY/trillionnium-agent-$name"
done
source_path="$CARGO_TARGET_DIR/$TARGET_TRIPLE/release/trillionnium-system-api-replay-sync"
[[ -f "$source_path" ]] || fail "built replay-sync publisher is missing: $source_path"
"$HOST_INSTALL" -m 0755 "$source_path" "$OUTPUT_DIRECTORY/trillionnium-system-api-replay-sync"
for name in system-api-operation-replay-sync accessibility-operation-replay-sync; do
  source_path="$CARGO_TARGET_DIR/$TARGET_TRIPLE/release/trillionnium-$name"
  [[ -f "$source_path" ]] || fail "built operation replay-sync helper is missing: $source_path"
  "$HOST_INSTALL" -m 0755 "$source_path" "$OUTPUT_DIRECTORY/trillionnium-$name"
done
source_path="$CARGO_TARGET_DIR/$TARGET_TRIPLE/release/trillionniumd"
[[ -f "$source_path" ]] || fail "built daemon is missing: $source_path"
"$HOST_INSTALL" -m 0755 "$source_path" "$OUTPUT_DIRECTORY/trillionniumd"

verify_elf() {
  local binary="$1"
  local expected_needed="$2"
  local description interpreter needed dynamic maximum stack build_id

  description="$("$HOST_FILE" -b "$binary")"
  [[ "$description" == *"ELF 64-bit LSB pie executable, ARM aarch64"* ]] ||
    fail "artifact is not an AArch64 PIE executable: $binary: $description"
  [[ "$description" == *", stripped" ]] ||
    fail "artifact is not stripped: $binary"

  interpreter="$(
    "$HOST_READELF" -W -l "$binary" |
      "$HOST_SED" -n 's/.*Requesting program interpreter: \(.*\)]/\1/p'
  )"
  [[ "$interpreter" == "$EXPECTED_INTERPRETER" ]] ||
    fail "unexpected interpreter for $binary: $interpreter"

  dynamic="$("$HOST_READELF" -W -d "$binary")"
  needed="$(
    printf '%s\n' "$dynamic" |
      "$HOST_SED" -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p'
  )"
  [[ "$needed" == "$expected_needed" ]] ||
    fail "unexpected DT_NEEDED closure for $binary: ${needed//$'\n'/,}"
  [[ "$dynamic" == *"(FLAGS_1)"*"NOW PIE"* ]] ||
    fail "artifact lacks BIND_NOW or PIE: $binary"
  for forbidden in RPATH RUNPATH TEXTREL; do
    [[ "$dynamic" != *"($forbidden)"* ]] ||
      fail "artifact contains forbidden $forbidden: $binary"
  done

  "$HOST_READELF" -W -l "$binary" | "$HOST_GREP" -q 'GNU_RELRO' ||
    fail "artifact lacks GNU_RELRO: $binary"
  stack="$("$HOST_READELF" -W -l "$binary" | "$HOST_AWK" '$1 == "GNU_STACK" { print }')"
  [[ -n "$stack" && "$stack" != *" RWE "* ]] ||
    fail "artifact has a missing or executable GNU_STACK: $binary"
  if "$HOST_READELF" -W -S "$binary" | "$HOST_GREP" -Eq '\.(z?debug)($|_)'; then
    fail "artifact contains debug sections: $binary"
  fi

  maximum="$(max_glibc "$binary")"
  version_at_most "$maximum" "$MAX_GLIBC" ||
    fail "artifact requires GLIBC_$maximum, newer than GLIBC_$MAX_GLIBC: $binary"
  build_id="$(
    "$HOST_READELF" -n "$binary" |
      "$HOST_SED" -n 's/^[[:space:]]*Build ID: \([0-9a-f]*\)$/\1/p'
  )"
  [[ "$build_id" =~ ^[0-9a-f]{40}$ ]] ||
    fail "artifact lacks one SHA-1 GNU build ID: $binary"

  for forbidden_path in \
    "$WORKSPACE" \
    "$PRIVATE_TOOLCHAIN_ROOT" \
    "$SYSROOT" \
    "$CARGO_HOME" \
    "$CARGO_TARGET_DIR"; do
    if "$HOST_GREP" -aFq "$forbidden_path" "$binary"; then
      fail "artifact leaks build path $forbidden_path: $binary"
    fi
  done

  printf 'artifact=%s sha256=%s max_glibc=%s build_id=%s needed=%s\n' \
    "$("$HOST_BASENAME" "$binary")" \
    "$("$HOST_SHA256SUM" "$binary" | "$HOST_AWK" '{print $1}')" \
    "$maximum" \
    "$build_id" \
    "${needed//$'\n'/,}"
}

printf 'build_contract=path-closed-cache-toolchain-content-pinned-measured-host-tcb hermetic=false host_userspace_rootfs_content_addressed_external_lane_required=true host_runtime_pinned=false host_kernel_pinned=false host_cpu_pinned=false host_filesystem_semantics_pinned=false dependency_cache_content_pinned=true dependency_cache_independently_approved=false private_toolchain_content_pinned=true private_toolchain_independently_approved=false\n'
printf 'cargo_home_closure schema=v2 manifest_sha256=%s manifest_tool_sha256=%s prebuild_postbuild_equal=true symlink_escape_gate=true non_writable_gate=true single_filesystem_gate=true single_link_regular_files_gate=true\n' \
  "$SOURCE_FIXED_CARGO_HOME_MANIFEST_SHA256" \
  "$CARGO_HOME_MANIFEST_TOOL_SHA256"
printf 'private_toolchain_closure schema=v1 manifest_sha256=%s manifest_tool_sha256=%s prebuild_postbuild_equal=true full_regular_file_content=true symlink_targets_recorded=true stable_posix_lstat_recorded=true runtime_readonly_mount=true runtime_uid=%s selected_paths_not_writable=true\n' \
  "$SOURCE_FIXED_PRIVATE_TOOLCHAIN_MANIFEST_SHA256" \
  "$PRIVATE_TOOLCHAIN_MANIFEST_TOOL_SHA256" \
  "$EUID"
for name in "${HOST_TOOL_NAMES[@]}"; do
  path="$HOST_TOOLS_DIRECTORY/$name"
  printf 'host_tool name=%s sha256=%s\n' \
    "$name" \
    "$("$HOST_SHA256SUM" "$path" | "$HOST_AWK" '{print $1}')"
done
printf 'toolchain linker_sha256=%s archiver_sha256=%s rustc_sha256=%s cargo_sha256=%s host_linker_sha256=%s host_archiver_sha256=%s sysroot_libc_sha256=%s sysroot_loader_sha256=%s sysroot_libgcc_s_sha256=%s sysroot_libm_sha256=%s eight_private_leaf_digests_source_fixed=true sysroot_max_glibc=%s sysroot_libm_max_glibc=%s contract_max_glibc=%s\n' \
  "$("$HOST_SHA256SUM" "$LINKER" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$ARCHIVER" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$RUSTC" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$CARGO" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$HOST_LINKER" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$HOST_ARCHIVER" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$SYSROOT_LIBC" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$SYSROOT_LOADER" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$SYSROOT_LIBGCC_S" | "$HOST_AWK" '{print $1}')" \
  "$("$HOST_SHA256SUM" "$SYSROOT_LIBM" | "$HOST_AWK" '{print $1}')" \
  "$SYSROOT_MAX_GLIBC" \
  "$SYSROOT_LIBM_MAX_GLIBC" \
  "$MAX_GLIBC"
for binary in \
  "$OUTPUT_DIRECTORY/trillionnium-agent-system-api" \
  "$OUTPUT_DIRECTORY/trillionnium-agent-accessibility" \
  "$OUTPUT_DIRECTORY/trillionnium-agent-adb" \
  "$OUTPUT_DIRECTORY/trillionnium-system-api-replay-sync" \
  "$OUTPUT_DIRECTORY/trillionnium-system-api-operation-replay-sync" \
  "$OUTPUT_DIRECTORY/trillionnium-accessibility-operation-replay-sync"; do
  verify_elf "$binary" "$EXPECTED_DIRECT_NEEDED"
done
verify_elf "$OUTPUT_DIRECTORY/trillionniumd" "$EXPECTED_DAEMON_NEEDED"
