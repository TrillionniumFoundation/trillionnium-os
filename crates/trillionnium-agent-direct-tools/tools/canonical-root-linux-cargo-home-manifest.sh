#!/bin/bash
set -euo pipefail

fail() {
  echo "canonical-root-linux-cargo-home-manifest: $*" >&2
  exit 1
}

[[ $# -eq 1 ]] || fail "usage: $0 <cargo-home>"
[[ "$1" = /* ]] || fail "Cargo home must be absolute"
[[ -d "$1" && ! -L "$1" ]] ||
  fail "Cargo home must be a real, non-symlink directory"

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
  fail "unsupported Cargo-home entry: ${unsupported#./}"

writable="$(
  find -P . -mindepth 0 \( -type f -o -type d \) -perm /222 -print -quit
)"
[[ -z "$writable" ]] ||
  fail "Cargo-home closure contains a write-enabled entry: ${writable#./}"

multiply_linked="$(
  find -P . -mindepth 1 -type f -links +1 -print -quit
)"
[[ -z "$multiply_linked" ]] ||
  fail "Cargo-home closure contains a multiply linked file: ${multiply_linked#./}"

devices="$(
  find -P . -mindepth 0 -printf '%D\n' |
    sort -u
)"
[[ "$devices" != *$'\n'* ]] ||
  fail "Cargo-home closure crosses a filesystem boundary"

while IFS= read -r -d '' link; do
  resolved="$(realpath -e -- "$link")" ||
    fail "Cargo-home closure contains a dangling symlink: ${link#./}"
  case "$resolved" in
    "$ROOT"|"$ROOT"/*) ;;
    *)
      fail "Cargo-home symlink escapes the closure: ${link#./}"
      ;;
  esac
done < <(
  find -P . -mindepth 1 -type l -printf '%P\0' |
    sort -z
)

# This is a NUL-framed manifest. Paths and link targets are never escaped or
# line-delimited, so whitespace, newlines, leading dashes and backslashes
# cannot alias another entry. Filesystem-dependent directory size/link-count
# values are deliberately excluded; regular-file link count is fixed to one
# by the gate above.
printf 'trillionnium.root-linux.cargo-home.canonical-manifest.v2\0'
printf 'root-directory-lstat\0'
stat --printf='%f\0%u\0%g\0%Y\0' -- .
printf 'paths\0'
find -P . -mindepth 1 -printf '%P\0' |
  sort -z
printf 'directory-lstat\0'
find -P . -mindepth 1 -type d -printf '%P\0' |
  sort -z |
  xargs -0 -r stat --printf='%f\0%u\0%g\0%Y\0' --
printf 'regular-file-lstat\0'
find -P . -mindepth 1 -type f -printf '%P\0' |
  sort -z |
  xargs -0 -r stat --printf='%f\0%u\0%g\0%s\0%Y\0%h\0' --
printf 'symlink-lstat\0'
find -P . -mindepth 1 -type l -printf '%P\0' |
  sort -z |
  xargs -0 -r stat --printf='%f\0%u\0%g\0%s\0%Y\0%h\0' --
printf 'regular-file-sha256\0'
find -P . -mindepth 1 -type f -printf '%P\0' |
  sort -z |
  xargs -0 -r sha256sum -b -z --
printf 'symlink-targets\0'
find -P . -mindepth 1 -type l -printf '%P\0' |
  sort -z |
  xargs -0 -r readlink -z --
