#!/bin/bash
set -euo pipefail

fail() {
  echo "canonical-root-linux-toolchain-manifest: $*" >&2
  exit 1
}

[[ $# -eq 1 ]] || fail "usage: $0 <private-toolchain-root>"
[[ "$1" = /* ]] || fail "private toolchain root must be absolute"
[[ -d "$1" && ! -L "$1" ]] ||
  fail "private toolchain root must be a real, non-symlink directory"

readonly ROOT="$(realpath -e -- "$1")"
export LC_ALL=C
export TZ=UTC

cd "$ROOT"

unsupported="$(
  find -P . -mindepth 1 \
    ! -type f ! -type d ! -type l \
    -print -quit
)"
[[ -z "$unsupported" ]] ||
  fail "unsupported private-toolchain entry: ${unsupported#./}"

# This location-independent NUL-framed manifest binds every path, regular-file
# byte, symlink target and stable POSIX lstat field in the private toolchain.
# It deliberately records write-mode bits and absolute or escaping link text
# rather than treating either as a content failure. Runtime immutability is a
# separate read-only-mount gate in build-root-linux-arm64.sh.
printf 'trillionnium.root-linux.private-toolchain.canonical-manifest.v1\0'
printf 'root-directory-lstat\0'
stat --printf='%f\0%u\0%g\0%Y\0' -- .
printf 'paths\0'
find -P . -mindepth 1 -printf '%P\0' |
  sort -z
printf 'directory-paths\0'
find -P . -mindepth 1 -type d -printf '%P\0' |
  sort -z
printf 'directory-lstat\0'
find -P . -mindepth 1 -type d -printf '%P\0' |
  sort -z |
  xargs -0 -r stat --printf='%f\0%u\0%g\0%Y\0' --
printf 'regular-file-paths\0'
find -P . -mindepth 1 -type f -printf '%P\0' |
  sort -z
printf 'regular-file-lstat\0'
find -P . -mindepth 1 -type f -printf '%P\0' |
  sort -z |
  xargs -0 -r stat --printf='%f\0%u\0%g\0%s\0%Y\0%h\0' --
printf 'regular-file-sha256\0'
find -P . -mindepth 1 -type f -printf '%P\0' |
  sort -z |
  xargs -0 -r sha256sum -b -z --
printf 'symlink-paths\0'
find -P . -mindepth 1 -type l -printf '%P\0' |
  sort -z
printf 'symlink-lstat\0'
find -P . -mindepth 1 -type l -printf '%P\0' |
  sort -z |
  xargs -0 -r stat --printf='%f\0%u\0%g\0%s\0%Y\0%h\0' --
printf 'symlink-targets\0'
find -P . -mindepth 1 -type l -printf '%P\0' |
  sort -z |
  xargs -0 -r readlink -z --
