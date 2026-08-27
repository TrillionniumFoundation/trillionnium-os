#!/usr/bin/env python3
"""Build and verify the exact-source AArch64 Codex provider payload.

The public build command accepts a provider name, a frozen builder profile,
an output directory, and a download cache.  It deliberately has no binary,
source-tree, compiler, sysroot, flag, patch, or environment override.

Each invocation builds one candidate in a digest-pinned container and emits a
closed, self-hashed builder receipt.  ``reconcile`` accepts exactly two
different frozen profiles, re-verifies every retained artifact, requires
byte equality for the provider payload and exact ABI/security equality for
the runtime closure, and emits a receipt retaining both namespaced runtime
candidates.  These receipts remain non-authorizing inputs: all
product/admission/effect fields are fixed false.
"""

from __future__ import annotations

import argparse
import array
import ctypes
import difflib
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from urllib.parse import urlparse
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

SUPERVISOR_PROTOCOL_MAGIC = 0x54505331
SUPERVISOR_PROTOCOL_VERSION = 1
SUPERVISOR_KIND_HELLO = 1
SUPERVISOR_KIND_INIT = 2
SUPERVISOR_KIND_CID_REQUEST = 3
SUPERVISOR_KIND_CID_RESPONSE = 4
SUPERVISOR_KIND_READY = 5
SUPERVISOR_ROLE_SUCCESS = 1
SUPERVISOR_ROLE_FAILURE = 2
SUPERVISOR_INIT_FD_COUNT = 6
SUPERVISOR_HELLO_FORMAT = "<IHHII16s"
SUPERVISOR_INIT_FORMAT = "<IHHII32sIIII"
SUPERVISOR_CID_REQUEST_FORMAT = "<IHHII32s64s"
SUPERVISOR_CID_RESPONSE_FORMAT = "<IHHII32sI64s"
SUPERVISOR_READY_FORMAT = "<IHHII32sIIIQQ64s128s"
SUPERVISOR_ALLOWED_MESSAGE_FLAGS = 0

DIRECTORY = Path(__file__).resolve().parent
RECIPE_PATH = DIRECTORY / "provider-payload-recipe-v1.json"
CONTAINERFILE_PATH = DIRECTORY / "Containerfile"
BUILD_CONTEXT_PATHS = (
    "build_provider_payload.py",
    "Containerfile",
    "provider-payload-recipe-v1.json",
    "include/trillionnium_provider_post_exec_bootstrap.h",
    "src/provider_post_exec_bootstrap.c",
    "src/provider_post_exec_entry.S",
)

RECIPE_SCHEMA = "trillionnium.provider-exact-source-payload-recipe.v2"
BUILDER_RECEIPT_SCHEMA = "trillionnium.provider-exact-source-builder-receipt.v3"
REPRODUCIBILITY_RECEIPT_SCHEMA = (
    "trillionnium.provider-exact-source-reproducibility-receipt.v3"
)
FAILURE_RECEIPT_SCHEMA = (
    "trillionnium.provider-exact-source-build-failure-receipt.v3"
)
RECEIPT_DIGEST_DOMAIN = b"org.trillionnium.provider-exact-source-builder-receipt.v3\0"
REPRODUCIBILITY_DIGEST_DOMAIN = (
    b"org.trillionnium.provider-exact-source-reproducibility-receipt.v3\0"
)
RUNTIME_ABI_CONTRACT_DIGEST_DOMAIN = (
    b"org.trillionnium.provider-runtime-abi-contract.v2\0"
)
RUNTIME_BUNDLE_INVENTORY_DIGEST_DOMAIN = (
    b"org.trillionnium.provider-runtime-bundle-inventory.v2\0"
)
FAILURE_DIGEST_DOMAIN = (
    b"org.trillionnium.provider-exact-source-build-failure-receipt.v3\0"
)
BUILD_CONTEXT_SCHEMA = "trillionnium.provider-deterministic-build-context.v1"
BUILD_CONTEXT_MEMBER_MANIFEST_DOMAIN = (
    b"org.trillionnium.provider-build-context-member-manifest.v1\0"
)
TARGET_ARCHITECTURE = "aarch64-unknown-linux"
PROVIDERS = ("codex",)
BUILDER_PROFILES = ("amd64-cross", "arm64-native")
CONTAINER_NOFILE_ULIMIT = "65536:65536"
CONTAINER_PIDS_LIMIT = "4096"
CONTAINER_MEMORY_LIMIT = "24g"
CONTAINER_CPU_LIMIT = "8"
CONTAINER_SHM_SIZE = "1g"
CONTAINER_TMPFS = "/tmp:rw,nosuid,nodev,mode=1777,size=1073741824"
CONTAINER_NAME_PREFIX = "trillionnium-provider-"
CONTAINER_NAME_MAX_BYTES = 128
CONTAINER_CIDFILE_NAME = "container.cid"
CONTAINER_CIDFILE_CUSTODY_PREFIX = ".trillionnium-provider-cid-"
CONTAINER_CIDFILE_MOUNT = "/run/trillionnium-provider-container-custody"
CONTAINER_CIDFILE_PATH = (
    f"{CONTAINER_CIDFILE_MOUNT}/{CONTAINER_CIDFILE_NAME}"
)
CONTAINER_PROXY_ENVIRONMENT_NAMES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)
STAGE_ROLES = (
    "provider_output_stage",
    "failure_evidence_stage",
    "container_cidfile_custody",
)
CODEX_TARGET_TOOLCHAIN_WRAPPERS = {
    "linker": (
        "aarch64-linux-musl-cargo-linker",
        b"""#!/bin/bash
set -euo pipefail
args=()
pending_argument=
map_path=
linker_threads_seen=0
rust_libc_seen=0
rust_libunwind_seen=0
input_args=("$@")
input_count=${#input_args[@]}
if [[ "${input_count}" -lt 5 ]]; then
  echo "Rust self-contained CRT sequence is missing" >&2
  exit 2
fi
case "${input_args[0]}" in
  /usr/local/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o)
    rust_crt_root=/usr/local/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained
    ;;
  /usr/local/rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o)
    rust_crt_root=/usr/local/rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained
    ;;
  *)
    echo "Rust self-contained crt1.o root is missing or unexpected" >&2
    exit 2
    ;;
esac
if [[ \
  "${input_args[0]}" != "${rust_crt_root}/crt1.o" || \
  "${input_args[1]}" != "${rust_crt_root}/crti.o" || \
  "${input_args[2]}" != "${rust_crt_root}/crtbegin.o" || \
  "${input_args[$((input_count - 2))]}" != "${rust_crt_root}/crtend.o" || \
  "${input_args[$((input_count - 1))]}" != "${rust_crt_root}/crtn.o" \
]]; then
  echo "Rust self-contained CRT sequence is missing, mixed, or out of order" >&2
  exit 2
fi
rust_crt_argument_count=0
for arg in "${input_args[@]}"; do
  case "${arg}" in
    "${rust_crt_root}/crt1.o"|\
    "${rust_crt_root}/crti.o"|\
    "${rust_crt_root}/crtbegin.o"|\
    "${rust_crt_root}/crtend.o"|\
    "${rust_crt_root}/crtn.o")
      rust_crt_argument_count=$((rust_crt_argument_count + 1))
      ;;
    */crt0.o|*/crt1.o|*/Scrt1.o|*/rcrt1.o|*/gcrt1.o|*/Mcrt1.o|\
    */crt2.o|*/crti.o|*/crtbegin.o|*/crtbeginS.o|*/crtbeginT.o|\
    */crtend.o|*/crtendS.o|*/crtn.o)
      echo "unexpected or aliased target CRT object: ${arg}" >&2
      exit 2
      ;;
  esac
done
if [[ "${rust_crt_argument_count}" -ne 5 ]]; then
  echo "Rust self-contained CRT sequence is duplicated or ambiguous" >&2
  exit 2
fi
closed_path_component() {
  local value="$1"
  [[ "${value}" == /* ]] || return 1
  [[ "${value}" != *//* ]] || return 1
  [[ "${value}" != */../* && "${value}" != */.. && "${value}" != ../* ]] || return 1
  [[ "${value}" != */./* && "${value}" != */. && "${value}" != ./* ]] || return 1
}
allowed_search_path() {
  local value="$1"
  closed_path_component "${value}" || return 1
  case "${value}" in
    /output/.work/*|\
    /usr/local/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib|\
    /usr/local/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/*|\
    /usr/local/rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib|\
    /usr/local/rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/*)
      return 0
      ;;
  esac
  return 1
}
allowed_link_input() {
  local value="$1"
  closed_path_component "${value}" || return 1
  case "${value}" in
    /output/.work/*.o|/output/.work/*.a|/output/.work/*.rlib|\
    /usr/local/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/*.rlib|\
    /usr/local/rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/*.rlib)
      return 0
      ;;
  esac
  return 1
}
for arg in "$@"; do
  if [[ -n "${pending_argument}" ]]; then
    case "${pending_argument}" in
      target)
        if [[ "${arg}" != aarch64-unknown-linux-musl && "${arg}" != aarch64-linux-musl ]]; then
          echo "target linker target value is outside the closed allowlist: ${arg}" >&2
          exit 2
        fi
        ;;
      search)
        if ! allowed_search_path "${arg}"; then
          echo "target linker search path is outside the closed allowlist: ${arg}" >&2
          exit 2
        fi
        args+=("-L" "${arg}")
        ;;
      output)
        if ! closed_path_component "${arg}" || [[ "${arg}" != /output/.work/* ]]; then
          echo "target linker output path is outside the closed allowlist: ${arg}" >&2
          exit 2
        fi
        args+=("-o" "${arg}")
        ;;
      *)
        echo "internal closed linker parser state is invalid" >&2
        exit 2
        ;;
    esac
    pending_argument=
    continue
  fi
  case "${arg}" in
    --target|-target)
      pending_argument=target
      continue
      ;;
    --target=aarch64-unknown-linux-musl|--target=aarch64-linux-musl|\
    -target=aarch64-unknown-linux-musl|-target=aarch64-linux-musl)
      continue
      ;;
    -L)
      pending_argument=search
      continue
      ;;
    -o)
      pending_argument=output
      continue
      ;;
    -Wl,-Map,/output/.work/build/final.map)
      map_path=/output/.work/build/final.map
      args+=("-Wl,--print-map")
      continue
      ;;
    -Wl,--threads=1)
      linker_threads_seen=$((linker_threads_seen + 1))
      continue
      ;;
    -Wl,--threads=*)
      echo "unsupported target linker thread contract: ${arg}" >&2
      exit 2
      ;;
    -lc)
      rust_libc_seen=$((rust_libc_seen + 1))
      args+=("${rust_crt_root}/libc.a")
      continue
      ;;
    -lunwind)
      rust_libunwind_seen=$((rust_libunwind_seen + 1))
      args+=("${rust_crt_root}/libunwind.a")
      continue
      ;;
    -Wl,-lc|*/libc.a)
      echo "unexpected target libc alias: ${arg}" >&2
      exit 2
      ;;
    -Wl,-lunwind|*/libunwind.a)
      echo "unexpected target libunwind alias: ${arg}" >&2
      exit 2
      ;;
    "${rust_crt_root}/crt1.o"|\
    "${rust_crt_root}/crti.o"|\
    "${rust_crt_root}/crtbegin.o"|\
    "${rust_crt_root}/crtend.o"|\
    "${rust_crt_root}/crtn.o")
      args+=("${arg}")
      continue
      ;;
    -Wl,--as-needed|-Wl,-Bstatic|-Wl,-Bdynamic|\
    -Wl,--eh-frame-hdr|-Wl,--gc-sections|-Wl,--build-id=sha1|\
    -Wl,-e,trillionnium_provider_post_final_exec_entry|\
    -Wl,-z,noexecstack|-Wl,-z,relro|-Wl,-z,now|\
    -Wl,-z,relro,-z,now|-Wl,-O1|\
    -nostartfiles|-static|-no-pie|-nodefaultlibs|-pthread)
      args+=("${arg}")
      continue
      ;;
    *)
      if allowed_link_input "${arg}"; then
        args+=("${arg}")
        continue
      fi
      echo "target linker argument is outside the closed allowlist: ${arg}" >&2
      exit 2
      ;;
  esac
done
if [[ -n "${pending_argument}" ]]; then
  echo "malformed target linker argument" >&2
  exit 2
fi
if [[ "${linker_threads_seen}" -ne 1 ]]; then
  echo "target linker thread contract must appear exactly once" >&2
  exit 2
fi
if [[ "${rust_libc_seen}" -ne 1 ]]; then
  echo "Rust self-contained libc contract must appear exactly once" >&2
  exit 2
fi
if [[ "${rust_libunwind_seen}" -ne 1 ]]; then
  echo "Rust self-contained libunwind contract must appear exactly once" >&2
  exit 2
fi
for rust_crt_component in \
  crt1.o crti.o crtbegin.o crtend.o crtn.o libc.a libunwind.a
do
  rust_crt_path="${rust_crt_root}/${rust_crt_component}"
  if [[ ! -f "${rust_crt_path}" || -L "${rust_crt_path}" ]]; then
    echo "Rust self-contained CRT/libc component is not a regular file: ${rust_crt_path}" >&2
    exit 2
  fi
done
affinity=$(/usr/bin/taskset -pc "$$")
affinity=${affinity##*: }
first_range=${affinity%%,*}
first_cpu=${first_range%%-*}
case "${first_cpu}" in
  ''|*[!0-9]*)
    echo "cannot derive one allowed CPU for the target linker" >&2
    exit 2
    ;;
esac
if [[ -n "${map_path}" ]]; then
  /usr/bin/taskset --cpu-list "${first_cpu}" \
    /opt/zig/zig cc -target aarch64-linux-musl -nostdlib \
    "${args[@]}" -fno-sanitize=undefined >"${map_path}"
  [[ -s "${map_path}" ]] || {
    echo "target linker emitted an empty final map" >&2
    exit 2
  }
else
  exec /usr/bin/taskset --cpu-list "${first_cpu}" \
    /opt/zig/zig cc -target aarch64-linux-musl -nostdlib \
    "${args[@]}" -fno-sanitize=undefined
fi
""",
    ),
    "cc": (
        "aarch64-linux-musl-gcc",
        b"""#!/bin/bash
set -euo pipefail
args=()
skip_next=0
pending_include=0
for arg in "$@"; do
  if [[ "${pending_include}" -eq 1 ]]; then
    pending_include=0
    if [[ "${arg}" == /usr/include || "${arg}" == /usr/include/* ]]; then
      args+=("-idirafter" "${arg}")
    else
      args+=("-I" "${arg}")
    fi
    continue
  fi
  if [[ "${skip_next}" -eq 1 ]]; then
    skip_next=0
    continue
  fi
  case "${arg}" in
    --target)
      skip_next=1
      continue
      ;;
    --target=*|-target=*)
      continue
      ;;
    -target)
      skip_next=1
      continue
      ;;
    -I)
      pending_include=1
      continue
      ;;
    -I/usr/include|-I/usr/include/*)
      args+=("-idirafter" "${arg#-I}")
      continue
      ;;
    -Wp,-U_FORTIFY_SOURCE)
      args+=("-U_FORTIFY_SOURCE")
      continue
      ;;
  esac
  args+=("${arg}")
done
if [[ "${skip_next}" -ne 0 || "${pending_include}" -ne 0 ]]; then
  echo "malformed target or include compiler argument" >&2
  exit 2
fi
exec /opt/zig/zig cc -target aarch64-linux-musl \
  "${args[@]}" -fno-sanitize=undefined
""",
    ),
    "cxx": (
        "aarch64-linux-musl-g++",
        b"""#!/bin/bash
set -euo pipefail
args=()
skip_next=0
pending_include=0
for arg in "$@"; do
  if [[ "${pending_include}" -eq 1 ]]; then
    pending_include=0
    if [[ "${arg}" == /usr/include || "${arg}" == /usr/include/* ]]; then
      args+=("-idirafter" "${arg}")
    else
      args+=("-I" "${arg}")
    fi
    continue
  fi
  if [[ "${skip_next}" -eq 1 ]]; then
    skip_next=0
    continue
  fi
  case "${arg}" in
    --target)
      skip_next=1
      continue
      ;;
    --target=*|-target=*)
      continue
      ;;
    -target)
      skip_next=1
      continue
      ;;
    -I)
      pending_include=1
      continue
      ;;
    -I/usr/include|-I/usr/include/*)
      args+=("-idirafter" "${arg#-I}")
      continue
      ;;
    -Wp,-U_FORTIFY_SOURCE)
      args+=("-U_FORTIFY_SOURCE")
      continue
      ;;
  esac
  args+=("${arg}")
done
if [[ "${skip_next}" -ne 0 || "${pending_include}" -ne 0 ]]; then
  echo "malformed target or include compiler argument" >&2
  exit 2
fi
exec /opt/zig/zig c++ -target aarch64-linux-musl \
  "${args[@]}" -fno-sanitize=undefined
""",
    ),
    "ar": (
        "aarch64-linux-musl-ar",
        b"#!/bin/sh\nset -eu\nexec /opt/zig/zig ar \"$@\"\n",
    ),
    "ranlib": (
        "aarch64-linux-musl-ranlib",
        b"#!/bin/sh\nset -eu\nexec /opt/zig/zig ranlib \"$@\"\n",
    ),
}

FALSE_AUTHORITY_FIELDS = (
    "product_active",
    "listener_backend_wired",
    "admission_wired",
    "confers_effect_authority",
)
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_SOURCE_BYTES = 4 * 1024 * 1024 * 1024
MAX_DEPENDENCY_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_FAILURE_DIAGNOSTIC_BYTES = 512 * 1024
MAX_COMPLETE_INSPECTION_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_BUILD_CONTEXT_TAR_BYTES = 32 * 1024 * 1024
EXPECTED_RECIPE_TOP_LEVEL_KEYS = {
    "schema",
    "target_architecture",
    "source_date_epoch",
    *FALSE_AUTHORITY_FIELDS,
    "builder",
    "bootstrap",
    "providers",
}
EXPECTED_BUILDER_RECEIPT_KEYS = {
    "schema",
    "provider",
    "target_architecture",
    "source_date_epoch",
    "recipe",
    "builder",
    "container",
    "source",
    "bootstrap",
    "build",
    "final_elf",
    "elf_contract",
    "retained_fd_contract",
    "source_checkpoint",
    *FALSE_AUTHORITY_FIELDS,
    "receipt_sha256",
}
EXPECTED_REPRODUCIBILITY_KEYS = {
    "schema",
    "provider",
    "target_architecture",
    "source_date_epoch",
    "recipe",
    "source",
    "bootstrap",
    "build_recipe",
    "builders",
    "equal_outputs",
    "runtime_candidates",
    "selected_runtime_profile",
    "final_elf",
    "retained_fd_contract",
    "source_checkpoint",
    *FALSE_AUTHORITY_FIELDS,
    "receipt_sha256",
}
EXPECTED_BUILDER_KEYS = {
    "profile",
    "platform",
    "base_image",
    "canonical_base_image",
    "base_platform_manifest_sha256",
    "built_image_id",
    "build_context",
    "image_build_network",
    "retained_artifact_resolver",
    "rust_version",
    "zig_version",
    "compiler",
    "bootstrap_compiler",
    "assembler",
    "linker",
    "build_driver",
}
EXPECTED_SOURCE_KEYS = {
    "repository_url",
    "version",
    "annotated_tag",
    "annotated_tag_object_sha1",
    "dereferenced_commit_sha1",
    "source_tree_sha1",
    "source_archive",
    "pristine_upstream_source_proven",
    "build_source_derived",
    "lockfiles",
    "patched_sources",
    "derived_build_source",
    "dependency_assets",
}
EXPECTED_CODEX_DERIVED_BUILD_SOURCE_KEYS = {
    "schema",
    "pristine_source_tree_sha1",
    "transformation",
    "workspace_version",
    "workspace_package_count",
    "workspace_package_names_sha256",
    "upstream_lock",
    "derived_lock",
    "lock_patch",
    "pre_build_source_inventory_sha256",
    "post_build_source_inventory_sha256",
    "cargo_metadata_command",
}
EXPECTED_CODEX_DEPENDENCY_ASSET_KEYS = {
    "source_archive",
    "tag_object",
    "commit_object",
    "source_member_manifest",
    "source_logical_symlinks",
    "cargo_vendor_archive",
    "cargo_vendor_member_manifest",
    "cargo_vendor_contract",
    "cargo_source_config",
    "rusty_v8_archive",
    "rusty_v8_binding",
    "rusty_v8_checksums",
    "rusty_v8_contract",
}
EXPECTED_BOOTSTRAP_RECEIPT_KEYS = {
    "public_header",
    "freestanding_core_source",
    "mechanism_source",
    "core_object",
    "mechanism_object",
    "preprocessed_source",
    "macro_dump",
    "relocation_manifest",
    "object_closure",
    "filter",
    "expected_filter_instruction_count",
}
EXPECTED_BUILD_RECEIPT_KEYS = {
    "working_directory",
    "resource_contract",
    "environment",
    "command",
    "compiler_arguments",
    "externally_supplied_definitions",
    "ordered_provider_objects",
    "link_map",
    "final_link_provenance",
    "dependency_manifest",
    "runtime_closure_manifest",
    "runtime_closure",
    "target_static_libraries",
    "target_toolchain_wrappers",
    "container_network",
    "container_proxy_environment",
}
EXPECTED_RETAINED_FD_CONTRACT = {
    "consumer_must_open_from_fixed_root",
    "allowed_path_resolvers",
    "component_walk_directory_flags",
    "rejects_absolute_empty_dot_and_dotdot_segments",
    "required_open_flags",
    "required_file_type",
    "required_link_count",
    "required_owner",
    "forbidden_mode_bits_octal",
    "requires_executable_bit",
    "requires_immutable_inode_or_read_only_mount",
    "builder_receipt_is_not_custody_authority",
}
EXPECTED_CODEX_ELF_CONTRACT_KEYS = {
    "elf_type",
    "entry_address",
    "bootstrap_core",
    "filter",
    "has_symbol_table",
    "has_writable_executable_segment",
    "gnu_stack_executable",
    "mechanism",
    "controlled_entry",
    "controlled_entry_section",
    "original_start",
    "has_dynamic_segment",
    "has_preinit_array",
}
EXPECTED_CODEX_RECIPE_KEYS = {
    "provider_wire_name",
    "version",
    "repository_url",
    "annotated_tag",
    "annotated_tag_object_sha1",
    "dereferenced_commit_sha1",
    "source_tree_sha1",
    "expected_uid",
    "expected_gid",
    "source_subdirectory",
    "lockfiles",
    "source_archive",
    "source_identity",
    "derived_lock",
    "cargo_vendor",
    "cargo_source_config",
    "rusty_v8",
    "cargo_package",
    "cargo_binary",
    "cargo_target",
    "build_jobs",
    "cargo_profile",
    "linker_threads",
    "link_entry_symbol",
    "original_entry_symbol",
    "required_final_elf_type",
    "required_dynamic_segment",
    "required_symbol_table",
}
EXPECTED_PINNED_CACHE_ARTIFACT_KEYS = {
    "filename",
    "byte_length",
    "sha256",
}
EXPECTED_PINNED_REMOTE_CACHE_ARTIFACT_KEYS = {
    *EXPECTED_PINNED_CACHE_ARTIFACT_KEYS,
    "url",
}
EXPECTED_CODEX_SOURCE_IDENTITY_KEYS = {
    "tag_object",
    "commit_object",
    "source_member_manifest",
    "logical_symlinks",
    "source_root_name",
    "source_entry_count",
    "source_inventory_sha256",
}
EXPECTED_CODEX_DERIVED_LOCK_KEYS = {
    "upstream_relative_path",
    "workspace_version",
    "workspace_package_count",
    "workspace_package_names_sha256",
    "transformation",
    "derived_sha256",
    "patch_sha256",
}
EXPECTED_CODEX_CARGO_VENDOR_KEYS = {
    "archive",
    "member_manifest",
    "root_name",
    "entry_count",
    "inventory_sha256",
}
EXPECTED_CODEX_RUSTY_V8_KEYS = {
    "crate_version",
    "crate_checksum_sha256",
    "target",
    "variant",
    "resolved_features",
    "archive_uncompressed_byte_length",
    "archive_uncompressed_sha256",
    "release_prerelease",
    "release_immutable",
    "upstream_signature_proven",
    "github_attestation_proven",
    "archive",
    "binding",
    "checksums",
}
EXPECTED_TARGET_STATIC_LIBRARY_KEYS = {
    "name",
    "policy",
    "linker_archive_path",
    "archive_source_path",
    "archive",
    "archive_architecture",
    "consumed_members",
    "link_map_member_references",
    "link_map_member_reference_count",
    "post_link_archive_sha256",
    "consumption_proof_sha256",
    "consumed",
}
EXPECTED_NORMALIZED_TARGET_STATIC_LIBRARY_KEYS = (
    EXPECTED_TARGET_STATIC_LIBRARY_KEYS - {"archive_source_path"}
)
EXPECTED_EQUAL_OUTPUT_KEYS = {
    "source",
    "resource_contract",
    "bootstrap_core_sha256",
    "mechanism_sha256",
    "filter_sha256",
    "link_map",
    "link_map_sha256",
    "final_link_provenance",
    "dependency_manifest",
    "dependency_manifest_sha256",
    "runtime_abi_contract_sha256",
    "target_static_libraries",
    "target_toolchain_wrappers",
    "final_elf_sha256",
    "final_elf_bytes",
    "elf_contract",
}
EXPECTED_RUNTIME_CANDIDATE_KEYS = {
    "profile",
    "platform",
    "base_platform_manifest_sha256",
    "runtime_closure_manifest",
    "bundle_inventory_sha256",
    "abi_contract_sha256",
}
EXPECTED_REPRODUCIBILITY_BUILDER_KEYS = {
    "profile",
    "platform",
    "base_platform_manifest_sha256",
    "built_image_id",
    "builder_receipt_sha256",
    "image_build_network",
    "retained_artifact_resolver",
    "container",
    "build_context",
}
EXPECTED_BUILD_CONTEXT_KEYS = {
    "schema",
    "transport",
    "context_operand",
    "dockerfile_member",
    "tar_sha256",
    "tar_byte_length",
    "member_manifest_sha256",
    "members",
    "memfd_seals",
    "same_uid_mutable_path_context_read",
}
EXPECTED_BUILD_CONTEXT_MEMBER_KEYS = {
    "path",
    "type",
    "mode",
    "byte_length",
    "sha256",
}
EXPECTED_CONTAINER_KEYS = {
    "attempt_id_sha256",
    "requested_output",
    "cache_root",
    "name",
    "id",
    "image_reference",
    "build_context",
    "network",
    "command",
    "run_invoked",
    "completed_zero",
    "cidfile",
    "client_disconnect_does_not_imply_container_stop",
}
EXPECTED_CONTAINER_CIDFILE_KEYS = {
    "host_path",
    "container_path",
    "custody_directory_path",
    "custody_directory_identity",
    "state",
    "creation_authority",
    "pre_run_absent_no_symlink",
    "container_id_cidfile_observed",
    "read_during_container_execution",
    "captured_after_exit_via_fixed_fd",
    "container_id_cross_checked",
    "unlinked_after_capture",
    "custody_directory_fsynced",
    "output_parent_fsynced",
    "cleanup_tombstone",
    "controller_exit_before_cleanup_preserves_cidfile",
}
CONTAINER_CIDFILE_STATES = (
    "not_prepared",
    "custody_preparation_rejected",
    "prepared_not_invoked",
    "pre_run_entry_rejected",
    "pending_launcher_capture",
    "captured_after_success",
    "captured_after_zero_exit_without_crosscheck",
    "captured_after_failed_run",
    "absent_after_failed_run",
    "retained_untrusted",
    "cleanup_incomplete",
)
FORBIDDEN_ARGUMENT_FRAGMENTS = (
    "provider_post_exec_bootstrap_fixture_adapter.h",
    "provider_post_exec_bootstrap_fixture.c",
    "linux_provider_post_exec_test_kernel.rs",
    "TRILLIONNIUM_BOOTSTRAP_",
    "TRILLIONNIUM_PROVIDER_BOOTSTRAP_TEST",
    "FAULT_",
)
FORBIDDEN_ARGUMENT_PREFIXES = (
    "-include",
    "-imacros",
    "-fplugin",
    "-specs",
    "--specs",
)
SYS_OPENAT2 = 437
RENAME_NOREPLACE = 1
AT_FDCWD = -100
AT_SYMLINK_FOLLOW = 0x400
AT_EMPTY_PATH = 0x1000
PUBLICATION_JOURNAL_SCHEMA = "trillionnium.provider-publication-journal.v3"
PUBLICATION_JOURNAL_MAX_BYTES = 64 * 1024
PUBLICATION_CUSTODY_ROOT = Path(
    "/var/lib/trillionnium-release-custody/provider-publication-v1"
)
# Unit tests replace this with a private 0700 directory.  Product code never
# assigns it; without the fixed root-owned custody above publication is HOLD.
PUBLICATION_TEST_ONLY_CUSTODY_DIRECTORY: Path | None = None
PUBLICATION_TREE_SEAL_SCHEMA = "trillionnium.provider-publication-tree-seal.v1"
PUBLICATION_TREE_SEAL_MAX_MEMBERS = 16_384
PUBLICATION_TREE_SEAL_MAX_REGULAR_BYTES = 8 * 1024 * 1024 * 1024
PUBLICATION_CANDIDATE_DIGEST_DOMAIN = (
    b"org.trillionnium.provider-publication-candidate.v1\0"
)
PUBLICATION_OPERATION_ID_DOMAIN = (
    b"org.trillionnium.provider-publication-operation.v1\0"
)
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
REQUIRED_RETAINED_OPEN_FLAGS = (
    "O_RDONLY",
    "O_CLOEXEC",
    "O_NOFOLLOW",
    "O_NONBLOCK",
)
RETAINED_COMPONENT_WALK_DIRECTORY_FLAGS = (
    "O_RDONLY",
    "O_DIRECTORY",
    "O_CLOEXEC",
    "O_NOFOLLOW",
)
RETAINED_ARTIFACT_RESOLVER_OPENAT2 = (
    "openat2:RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS"
)
RETAINED_ARTIFACT_RESOLVER_COMPONENT_WALK = (
    "dirfd-component-walk:O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW"
)
ALLOWED_RETAINED_ARTIFACT_RESOLVERS = (
    RETAINED_ARTIFACT_RESOLVER_OPENAT2,
    RETAINED_ARTIFACT_RESOLVER_COMPONENT_WALK,
)
STATIC_LIBRARY_CONSUMPTION_DOMAIN = (
    b"org.trillionnium.target-static-library-consumption.v1\0"
)
class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


class BuildError(RuntimeError):
    """Fail-closed build or receipt validation failure."""


class CommandFailure(BuildError):
    """A bounded, structured command failure suitable for local evidence."""

    def __init__(
        self,
        arguments: Sequence[str],
        return_code: int,
        output_tail: str,
        output_truncated: bool,
    ) -> None:
        self.arguments = list(arguments)
        self.return_code = return_code
        self.output_tail = output_tail
        self.output_truncated = output_truncated
        super().__init__(
            f"command failed ({return_code}): {' '.join(arguments)}\n"
            f"{output_tail}"
        )


class PublicationFailure(BuildError):
    """A publication failure that preserves whether the final name was installed."""

    def __init__(
        self,
        message: str,
        *,
        destination_installed: bool,
        destination_identity_preserved: bool,
        parent_fsync_completed: bool,
    ) -> None:
        self.destination_installed = destination_installed
        self.destination_identity_preserved = destination_identity_preserved
        self.parent_fsync_completed = parent_fsync_completed
        super().__init__(message)


class CombinedBuildFailure(BuildError):
    """Preserve a primary failure together with a secondary build failure."""

    def __init__(
        self,
        primary_error: Exception,
        secondary_error: Exception,
        *,
        candidate_stage: Mapping[str, Any] | None = None,
    ) -> None:
        self.primary_error = primary_error
        self.secondary_error = secondary_error
        self.candidate_stage = (
            dict(candidate_stage) if candidate_stage is not None else None
        )
        super().__init__(
            f"{primary_error}\nsecondary build failure: {secondary_error}"
        )


class ContextualBuildFailure(BuildError):
    """Preserve non-error cleanup state while retaining the primary failure."""

    def __init__(
        self,
        primary_error: Exception,
        *,
        candidate_stage: Mapping[str, Any] | None = None,
        cleanup_tombstones: Sequence[Mapping[str, Any]] = (),
    ) -> None:
        self.primary_error = primary_error
        self.candidate_stage = (
            dict(candidate_stage) if candidate_stage is not None else None
        )
        self.cleanup_tombstones = [
            dict(tombstone) for tombstone in cleanup_tombstones
        ]
        super().__init__(str(primary_error))


class ContainerCustodyError(BuildError):
    """Carry the last closed custody projection without deleting uncertain paths."""

    def __init__(
        self,
        message: str,
        container_projection: Mapping[str, Any],
    ) -> None:
        self.container_projection = json.loads(
            json.dumps(container_projection)
        )
        super().__init__(message)


def _set_process_dumpable_zero() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE failed")


def _set_descriptor_cloexec(descriptor: int) -> None:
    fcntl.fcntl(
        descriptor,
        fcntl.F_SETFD,
        fcntl.fcntl(descriptor, fcntl.F_GETFD) | fcntl.FD_CLOEXEC,
    )


class _ContainerCidfileCustody:
    """Pinned descriptors for one deterministic, launcher-owned cidfile parent."""

    def __init__(
        self,
        *,
        output_parent: Path,
        path: Path,
        identity: tuple[int, int],
        parent_descriptor: int,
        directory_descriptor: int,
        root_name_bound: bool = False,
    ) -> None:
        self.output_parent = output_parent
        self.path = path
        self.cidfile_path = path / CONTAINER_CIDFILE_NAME
        self.identity = identity
        self.parent_descriptor = parent_descriptor
        self.directory_descriptor = directory_descriptor
        self.root_name_bound = root_name_bound

    def close(self) -> None:
        if self.directory_descriptor >= 0:
            os.close(self.directory_descriptor)
            self.directory_descriptor = -1
        if self.parent_descriptor >= 0:
            os.close(self.parent_descriptor)
            self.parent_descriptor = -1


class _SupervisedBuildClient:
    """One-shot capability client; it never selects or publishes a host path."""

    def __init__(
        self,
        *,
        socket_descriptor: int,
        exec_builder_descriptor: int,
        supervisor_pid: int,
        source_root: Path,
        output: Path,
        cache: Path,
        success_host_path: Path,
        failure_host_path: Path,
    ) -> None:
        if (
            socket_descriptor < 3
            or exec_builder_descriptor < 3
            or socket_descriptor == exec_builder_descriptor
            or supervisor_pid <= 1
            or os.getppid() != supervisor_pid
            or os.getuid() == 0
            or os.geteuid() == 0
        ):
            raise BuildError("supervised builder identity or inherited socket is invalid")
        self.supervisor_pid = supervisor_pid
        self.exec_builder_descriptor = exec_builder_descriptor
        _set_descriptor_cloexec(exec_builder_descriptor)
        self.source_root = source_root
        self.output = output
        self.cache = cache
        self.success_host_path = success_host_path
        self.failure_host_path = failure_host_path
        self.socket = socket.socket(fileno=socket_descriptor)
        _set_descriptor_cloexec(socket_descriptor)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        if self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
            raise BuildError("supervisor capability is not one SOCK_SEQPACKET socket")
        peer_pid, peer_uid, peer_gid = struct.unpack(
            "3i",
            self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
        )
        if (peer_pid, peer_uid, peer_gid) != (supervisor_pid, 0, 0):
            raise BuildError("supervisor socket creator identity is not exact root")
        self.challenge = b""
        self.output_parent_descriptor = -1
        self.success_descriptor = -1
        self.failure_descriptor = -1
        self.builder_descriptor = -1
        self.recipe_descriptor = -1
        self.containerfile_descriptor = -1
        self.cid_descriptor = -1
        self.ready_sent = False

    @staticmethod
    def _header(kind: int, size: int) -> tuple[int, int, int, int, int]:
        return (
            SUPERVISOR_PROTOCOL_MAGIC,
            SUPERVISOR_PROTOCOL_VERSION,
            kind,
            size,
            0,
        )

    def _send(self, content: bytes, descriptors: Sequence[int] = ()) -> None:
        ancillary = []
        if descriptors:
            rights = array.array("i", descriptors)
            ancillary.append(
                (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())
            )
        sent = self.socket.sendmsg([content], ancillary)
        if sent != len(content):
            raise BuildError("supervisor capability frame was partially sent")

    def _receive(
        self,
        *,
        expected_kind: int,
        expected_size: int,
        expected_descriptor_count: int,
    ) -> tuple[bytes, list[int]]:
        ancillary_size = socket.CMSG_SPACE(12) + socket.CMSG_SPACE(
            max(expected_descriptor_count, 1) * array.array("i").itemsize
        )
        content, ancillary, flags, _ = self.socket.recvmsg(
            expected_size + 1,
            ancillary_size,
        )
        descriptors: list[int] = []
        credentials: list[tuple[int, int, int]] = []
        try:
            if flags != SUPERVISOR_ALLOWED_MESSAGE_FLAGS or len(content) != expected_size:
                raise BuildError("supervisor frame is truncated or has unknown flags")
            for level, kind, value in ancillary:
                if level != socket.SOL_SOCKET:
                    raise BuildError("supervisor frame has an unknown ancillary level")
                if kind == socket.SCM_CREDENTIALS:
                    if len(value) != 12:
                        raise BuildError("supervisor credentials have the wrong size")
                    credentials.append(struct.unpack("3i", value))
                elif kind == socket.SCM_RIGHTS:
                    if len(value) % array.array("i").itemsize:
                        raise BuildError("supervisor rights payload is malformed")
                    received = array.array("i")
                    received.frombytes(value)
                    descriptors.extend(received.tolist())
                else:
                    raise BuildError("supervisor frame has unknown ancillary data")
            if credentials != [(self.supervisor_pid, 0, 0)]:
                raise BuildError("supervisor frame credentials are not exact root")
            if len(descriptors) != expected_descriptor_count:
                raise BuildError("supervisor frame has a missing or extra SCM_RIGHTS FD")
            for descriptor in descriptors:
                _set_descriptor_cloexec(descriptor)
            if (
                len(content) < 16
                or struct.unpack_from("<I", content, 0)[0] != SUPERVISOR_PROTOCOL_MAGIC
                or struct.unpack_from("<H", content, 4)[0]
                != SUPERVISOR_PROTOCOL_VERSION
                or struct.unpack_from("<H", content, 6)[0] != expected_kind
                or struct.unpack_from("<I", content, 8)[0] != expected_size
                or struct.unpack_from("<I", content, 12)[0] != 0
            ):
                raise BuildError("supervisor frame header is malformed")
            return content, descriptors
        except Exception:
            for descriptor in descriptors:
                os.close(descriptor)
            raise

    @staticmethod
    def _require_directory_fd(
        descriptor: int,
        *,
        uid: int,
        gid: int,
        mode: int,
        label: str,
    ) -> os.stat_result:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != uid
            or value.st_gid != gid
            or stat.S_IMODE(value.st_mode) != mode
        ):
            raise BuildError(f"{label} descriptor identity or ownership is invalid")
        return value

    def start(self) -> None:
        _set_process_dumpable_zero()
        hello_size = struct.calcsize(SUPERVISOR_HELLO_FORMAT)
        self._send(
            struct.pack(
                SUPERVISOR_HELLO_FORMAT,
                *self._header(SUPERVISOR_KIND_HELLO, hello_size),
                bytes(16),
            )
        )
        init_size = struct.calcsize(SUPERVISOR_INIT_FORMAT)
        content, descriptors = self._receive(
            expected_kind=SUPERVISOR_KIND_INIT,
            expected_size=init_size,
            expected_descriptor_count=SUPERVISOR_INIT_FD_COUNT,
        )
        (
            _,
            _,
            _,
            _,
            _,
            challenge,
            descriptor_count,
            worker_pid,
            worker_uid,
            worker_gid,
        ) = struct.unpack(SUPERVISOR_INIT_FORMAT, content)
        if (
            challenge == bytes(32)
            or descriptor_count != SUPERVISOR_INIT_FD_COUNT
            or (worker_pid, worker_uid, worker_gid)
            != (os.getpid(), os.getuid(), os.getgid())
        ):
            for descriptor in descriptors:
                os.close(descriptor)
            raise BuildError("supervisor INIT binding is malformed")
        self.challenge = challenge
        (
            self.output_parent_descriptor,
            self.success_descriptor,
            self.failure_descriptor,
            self.builder_descriptor,
            self.recipe_descriptor,
            self.containerfile_descriptor,
        ) = descriptors
        parent = self._require_directory_fd(
            self.output_parent_descriptor,
            uid=0,
            gid=0,
            mode=0o700,
            label="root output parent",
        )
        success = self._require_directory_fd(
            self.success_descriptor,
            uid=os.getuid(),
            gid=os.getgid(),
            mode=0o700,
            label="success candidate",
        )
        failure = self._require_directory_fd(
            self.failure_descriptor,
            uid=os.getuid(),
            gid=os.getgid(),
            mode=0o700,
            label="failure candidate",
        )
        if (
            parent.st_dev != success.st_dev
            or parent.st_dev != failure.st_dev
            or (success.st_dev, success.st_ino) == (failure.st_dev, failure.st_ino)
            or self.success_host_path.parent != self.output.parent
            or self.failure_host_path.parent != self.output.parent
            or self.success_host_path.parent != self.failure_host_path.parent
            or re.fullmatch(
                rf"\.{re.escape(self.output.name)}\.[a-f0-9]{{8}}",
                self.success_host_path.name,
            )
            is None
            or re.fullmatch(
                rf"\.{re.escape(self.output.name)}\.failure\.[a-f0-9]{{8}}",
                self.failure_host_path.name,
            )
            is None
        ):
            raise BuildError("supervised candidate topology is not one distinct local set")
        named_sources = (
            (self.builder_descriptor, self.source_root / "build_provider_payload.py"),
            (self.recipe_descriptor, self.source_root / "provider-payload-recipe-v1.json"),
            (self.containerfile_descriptor, self.source_root / "Containerfile"),
        )
        for descriptor, path in named_sources:
            opened = os.fstat(descriptor)
            named = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino)
                != (named.st_dev, named.st_ino)
                or stat.S_IMODE(opened.st_mode) & 0o022
            ):
                raise BuildError("retained supervised source input is unsafe or rebound")
        inherited_builder = os.fstat(self.exec_builder_descriptor)
        received_builder = os.fstat(self.builder_descriptor)
        if (
            inherited_builder.st_dev,
            inherited_builder.st_ino,
        ) != (
            received_builder.st_dev,
            received_builder.st_ino,
        ):
            raise BuildError("executed and INIT-retained builder inodes differ")
        global DIRECTORY, RECIPE_PATH, CONTAINERFILE_PATH
        DIRECTORY = self.source_root
        RECIPE_PATH = DIRECTORY / "provider-payload-recipe-v1.json"
        CONTAINERFILE_PATH = DIRECTORY / "Containerfile"
        _retained_verification_sources(
            self.builder_descriptor,
            self.recipe_descriptor,
            self.containerfile_descriptor,
        )

    @property
    def success_path(self) -> Path:
        return Path(f"/proc/{os.getpid()}/fd/{self.success_descriptor}")

    @property
    def failure_path(self) -> Path:
        return Path(f"/proc/{os.getpid()}/fd/{self.failure_descriptor}")

    def allocate_container_custody(
        self,
        attempt_id: str,
    ) -> _ContainerCidfileCustody:
        attempt = _require_hex(attempt_id, 64, "supervised container attempt")
        request_size = struct.calcsize(SUPERVISOR_CID_REQUEST_FORMAT)
        self._send(
            struct.pack(
                SUPERVISOR_CID_REQUEST_FORMAT,
                *self._header(SUPERVISOR_KIND_CID_REQUEST, request_size),
                self.challenge,
                attempt.encode("ascii"),
            )
        )
        response_size = struct.calcsize(SUPERVISOR_CID_RESPONSE_FORMAT)
        content, descriptors = self._receive(
            expected_kind=SUPERVISOR_KIND_CID_RESPONSE,
            expected_size=response_size,
            expected_descriptor_count=1,
        )
        (
            _,
            _,
            _,
            _,
            _,
            challenge,
            descriptor_count,
            response_attempt,
        ) = struct.unpack(SUPERVISOR_CID_RESPONSE_FORMAT, content)
        if (
            challenge != self.challenge
            or descriptor_count != 1
            or response_attempt != attempt.encode("ascii")
        ):
            os.close(descriptors[0])
            raise BuildError("supervisor CID response is cross-spliced")
        descriptor = descriptors[0]
        expected_path = _container_cidfile_custody_path(self.output, attempt)
        opened = self._require_directory_fd(
            descriptor,
            uid=os.getuid(),
            gid=os.getgid(),
            mode=0o700,
            label="container cidfile custody",
        )
        if opened.st_dev != os.fstat(self.output_parent_descriptor).st_dev:
            os.close(descriptor)
            raise BuildError("container cidfile custody crosses output filesystem")
        with _scandir_fd(descriptor) as iterator:
            if next(iterator, None) is not None:
                os.close(descriptor)
                raise BuildError("container cidfile custody is not initially empty")
        self.cid_descriptor = os.dup(descriptor)
        _set_descriptor_cloexec(self.cid_descriptor)
        return _ContainerCidfileCustody(
            output_parent=self.output.parent,
            path=expected_path,
            identity=(opened.st_dev, opened.st_ino),
            parent_descriptor=os.dup(self.output_parent_descriptor),
            directory_descriptor=descriptor,
            root_name_bound=True,
        )

    def ready(
        self,
        *,
        role: int,
        descriptor: int,
        worker_status: int,
        container_name: str,
        container_id: str | None,
    ) -> None:
        if self.ready_sent or role not in {
            SUPERVISOR_ROLE_SUCCESS,
            SUPERVISOR_ROLE_FAILURE,
        }:
            raise BuildError("supervised candidate READY is duplicated or malformed")
        if (
            not isinstance(worker_status, int)
            or worker_status not in {0, 1}
            or (role == SUPERVISOR_ROLE_SUCCESS) != (worker_status == 0)
            or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", container_name) is None
            or len(container_name.encode("ascii")) >= 128
        ):
            raise BuildError("supervised READY outcome or container name is malformed")
        encoded_id = bytes(64)
        if container_id is not None:
            _require_hex(container_id, 64, "supervised READY container id")
            encoded_id = container_id.encode("ascii")
        opened = os.fstat(descriptor)
        expected = (
            os.fstat(self.success_descriptor)
            if role == SUPERVISOR_ROLE_SUCCESS
            else os.fstat(self.failure_descriptor)
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise BuildError("supervised READY candidate FD is not the allocated inode")
        size = struct.calcsize(SUPERVISOR_READY_FORMAT)
        content = struct.pack(
            SUPERVISOR_READY_FORMAT,
            *self._header(SUPERVISOR_KIND_READY, size),
            self.challenge,
            role,
            worker_status,
            1,
            opened.st_dev,
            opened.st_ino,
            encoded_id,
            container_name.encode("ascii").ljust(128, b"\0"),
        )
        self._send(content, [descriptor])
        self.ready_sent = True


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(
    path: Path,
    maximum: int = MAX_ARTIFACT_BYTES,
    *,
    allow_empty: bool = False,
) -> str:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or (metadata.st_size == 0 and not allow_empty)
            or metadata.st_size > maximum
        ):
            raise BuildError(f"artifact is not one bounded regular file: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise BuildError(f"artifact changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _read_retained_regular_fd(
    descriptor: int, maximum: int, label: str
) -> tuple[bytes, str]:
    if descriptor < 3:
        raise BuildError(f"{label} FD is not an inherited data FD")
    try:
        retained = os.dup(descriptor)
    except OSError as error:
        raise BuildError(f"{label} FD is unavailable") from error
    try:
        before = os.fstat(retained)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise BuildError(f"{label} FD is not one bounded regular inode")
        content = bytearray()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                retained, min(1024 * 1024, before.st_size - offset), offset
            )
            if not chunk:
                raise BuildError(f"{label} FD ended before its recorded length")
            content.extend(chunk)
            offset += len(chunk)
        if os.pread(retained, 1, before.st_size):
            raise BuildError(f"{label} FD exceeded its recorded length")
        after = os.fstat(retained)
        if _fd_identity(before) != _fd_identity(after):
            raise BuildError(f"{label} FD changed while being measured")
        value = bytes(content)
        return value, hashlib.sha256(value).hexdigest()
    finally:
        os.close(retained)


def _retained_verification_sources(
    builder_descriptor: int,
    recipe_descriptor: int,
    containerfile_descriptor: int,
) -> dict[str, Any]:
    descriptors = (
        builder_descriptor,
        recipe_descriptor,
        containerfile_descriptor,
    )
    if any(value < 3 for value in descriptors) or len(set(descriptors)) != 3:
        raise BuildError(
            "retained builder/recipe/Containerfile FDs must be distinct data FDs"
        )
    builder_bytes, builder_sha256 = _read_retained_regular_fd(
        builder_descriptor, MAX_BUILD_CONTEXT_TAR_BYTES, "retained builder"
    )
    recipe_bytes, recipe_sha256 = _read_retained_regular_fd(
        recipe_descriptor, MAX_RECEIPT_BYTES, "retained recipe"
    )
    containerfile_bytes, containerfile_sha256 = _read_retained_regular_fd(
        containerfile_descriptor,
        MAX_BUILD_CONTEXT_TAR_BYTES,
        "retained Containerfile",
    )
    if not builder_bytes.startswith(b"#!/usr/bin/env python3\n"):
        raise BuildError("retained builder bytes have the wrong identity")
    try:
        recipe_value = json.loads(recipe_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("retained recipe FD is malformed JSON") from error
    if not isinstance(recipe_value, dict):
        raise BuildError("retained recipe FD top level is not an object")
    return {
        "recipe": _validate_recipe_value(recipe_value),
        "builder_sha256": builder_sha256,
        "recipe_sha256": recipe_sha256,
        "containerfile_sha256": containerfile_sha256,
    }


def _git_object_sha1(kind: str, content: bytes) -> str:
    if kind not in {"blob", "commit", "tag"}:
        raise BuildError("unsupported retained Git object kind")
    header = f"{kind} {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _validate_pinned_cache_artifact(
    value: Any,
    label: str,
    *,
    remote: bool = False,
    maximum: int = MAX_SOURCE_ARCHIVE_BYTES,
) -> None:
    expected = (
        EXPECTED_PINNED_REMOTE_CACHE_ARTIFACT_KEYS
        if remote
        else EXPECTED_PINNED_CACHE_ARTIFACT_KEYS
    )
    _expect_keys(value, expected, label)
    filename = value["filename"]
    if (
        not isinstance(filename, str)
        or not filename
        or filename != PurePosixPath(filename).name
        or "\0" in filename
    ):
        raise BuildError(f"{label} filename is unsafe")
    byte_length = value["byte_length"]
    if (
        not isinstance(byte_length, int)
        or isinstance(byte_length, bool)
        or byte_length <= 0
        or byte_length > maximum
    ):
        raise BuildError(f"{label} byte length is invalid")
    _require_hex(value["sha256"], 64, f"{label}.sha256")
    if remote and (
        not isinstance(value["url"], str)
        or not value["url"].startswith("https://")
        or "\0" in value["url"]
    ):
        raise BuildError(f"{label} URL is unsafe")


def _codex_lock_patch_bytes(upstream: bytes, derived: bytes) -> bytes:
    try:
        before = upstream.decode("utf-8")
        after = derived.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildError("Codex Cargo.lock is not UTF-8") from error
    patch = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="codex-rs/Cargo.lock.upstream",
            tofile="codex-rs/Cargo.lock.derived",
        )
    ).encode("utf-8")
    if not patch:
        raise BuildError("Codex derived Cargo.lock patch is empty")
    return patch


def _derive_codex_lock_bytes(
    upstream: bytes, rule: Mapping[str, Any]
) -> tuple[bytes, bytes, list[str]]:
    _expect_keys(rule, EXPECTED_CODEX_DERIVED_LOCK_KEYS, "Codex derived lock")
    if (
        rule["upstream_relative_path"] != "codex-rs/Cargo.lock"
        or rule["workspace_version"] != "0.144.1"
        or rule["workspace_package_count"] != 132
        or rule["transformation"]
        != "source_less_workspace_package_version_0.0.0_to_0.144.1_only"
    ):
        raise BuildError("Codex derived lock rule drifted")
    _require_hex(
        rule["workspace_package_names_sha256"],
        64,
        "Codex derived lock package names",
    )
    _require_hex(rule["derived_sha256"], 64, "Codex derived lock")
    _require_hex(rule["patch_sha256"], 64, "Codex derived lock patch")
    try:
        parsed = tomllib.loads(upstream.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise BuildError("Codex upstream Cargo.lock is malformed") from error
    packages = parsed.get("package")
    if not isinstance(packages, list):
        raise BuildError("Codex upstream Cargo.lock package list is malformed")
    names = sorted(
        package.get("name")
        for package in packages
        if isinstance(package, dict)
        and "source" not in package
        and package.get("version") == "0.0.0"
    )
    if (
        len(names) != rule["workspace_package_count"]
        or any(not isinstance(name, str) or not name for name in names)
        or len(set(names)) != len(names)
        or _sha256_bytes(_json_bytes(names))
        != rule["workspace_package_names_sha256"]
    ):
        raise BuildError("Codex upstream workspace package inventory drifted")

    package_pattern = re.compile(
        rb"(?ms)^\[\[package\]\]\n.*?(?=^\[\[package\]\]\n|\Z)"
    )
    changed: list[str] = []

    def replace_package(match: re.Match[bytes]) -> bytes:
        block = match.group(0)
        try:
            value = tomllib.loads(block.decode("utf-8"))["package"][0]
        except (
            UnicodeDecodeError,
            KeyError,
            IndexError,
            TypeError,
            tomllib.TOMLDecodeError,
        ) as error:
            raise BuildError("Codex Cargo.lock package block is malformed") from error
        if "source" in value or value.get("version") != "0.0.0":
            return block
        name = value.get("name")
        if name not in names:
            raise BuildError("Codex lock transformation package set drifted")
        marker = b'version = "0.0.0"\n'
        if block.count(marker) != 1:
            raise BuildError("Codex lock package has ambiguous version syntax")
        changed.append(name)
        return block.replace(
            marker,
            f'version = "{rule["workspace_version"]}"\n'.encode("ascii"),
            1,
        )

    derived = package_pattern.sub(replace_package, upstream)
    if sorted(changed) != names:
        raise BuildError("Codex lock transformation did not cover the exact package set")
    patch = _codex_lock_patch_bytes(upstream, derived)
    if (
        _sha256_bytes(derived) != rule["derived_sha256"]
        or _sha256_bytes(patch) != rule["patch_sha256"]
    ):
        raise BuildError("Codex derived lock or patch digest drifted")
    return derived, patch, names


def _verify_codex_workspace_manifests(
    source: Path, expected_names: Sequence[str], workspace_version: str
) -> None:
    root_manifest = source / "codex-rs" / "Cargo.toml"
    try:
        root = tomllib.loads(root_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise BuildError("Codex workspace manifest is malformed") from error
    if root.get("workspace", {}).get("package", {}).get("version") != workspace_version:
        raise BuildError("Codex workspace version drifted")
    inherited: set[str] = set()
    for manifest in source.rglob("Cargo.toml"):
        if manifest.is_symlink() or not manifest.is_file():
            raise BuildError("Codex workspace manifest is missing or aliased")
        try:
            value = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise BuildError(f"Codex package manifest is malformed: {manifest}") from error
        package = value.get("package")
        if not isinstance(package, dict):
            continue
        version = package.get("version")
        if (
            isinstance(version, dict)
            and version.get("workspace") is True
            and set(version) == {"workspace"}
        ):
            name = package.get("name")
            if not isinstance(name, str) or not name or name in inherited:
                raise BuildError("Codex inherited workspace package name is ambiguous")
            inherited.add(name)
    if inherited != set(expected_names):
        raise BuildError("Codex manifest/lock workspace package set drifted")


def _fd_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_retained_artifact_resolver(value: Any, context: str) -> str:
    if value not in ALLOWED_RETAINED_ARTIFACT_RESOLVERS:
        raise BuildError(f"{context} retained-artifact resolver is not allowed")
    return value


def _retained_fd_contract() -> dict[str, Any]:
    return {
        "consumer_must_open_from_fixed_root": True,
        "allowed_path_resolvers": list(ALLOWED_RETAINED_ARTIFACT_RESOLVERS),
        "component_walk_directory_flags": list(
            RETAINED_COMPONENT_WALK_DIRECTORY_FLAGS
        ),
        "rejects_absolute_empty_dot_and_dotdot_segments": True,
        "required_open_flags": list(REQUIRED_RETAINED_OPEN_FLAGS),
        "required_file_type": "regular",
        "required_link_count": 1,
        "required_owner": {"uid": 0, "gid": 0},
        "forbidden_mode_bits_octal": "7022",
        "requires_executable_bit": True,
        "requires_immutable_inode_or_read_only_mount": True,
        "builder_receipt_is_not_custody_authority": True,
    }


def _open_fixed_root(root: Path) -> int:
    flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
    )
    try:
        descriptor = os.open(root, flags)
    except OSError as error:
        raise BuildError(f"retained root is unavailable or aliased: {root}") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise BuildError(f"retained root is not a directory: {root}")
    return descriptor


def _validated_beneath_parts(logical_path: str) -> tuple[str, ...]:
    if (
        not isinstance(logical_path, str)
        or not logical_path
        or "\0" in logical_path
    ):
        raise BuildError("retained artifact logical path is unsafe")
    parts = tuple(logical_path.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise BuildError("retained artifact logical path is unsafe")
    return parts


def _openat_component_walk(
    root_descriptor: int,
    logical_path: str,
    parts: Sequence[str],
) -> int:
    current_descriptor = root_descriptor
    current_is_owned = False
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    final_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                directory_flags,
                dir_fd=current_descriptor,
            )
            if current_is_owned:
                os.close(current_descriptor)
            current_descriptor = next_descriptor
            current_is_owned = True
        try:
            return os.open(
                parts[-1],
                final_flags,
                dir_fd=current_descriptor,
            )
        except OSError as error:
            raise BuildError(
                f"retained artifact is absent, aliased, or escaped: {logical_path}"
            ) from error
    except OSError as error:
        raise BuildError(
            f"retained artifact is absent, aliased, or escaped: {logical_path}"
        ) from error
    finally:
        if current_is_owned:
            os.close(current_descriptor)


def _open_beneath_with_resolver(
    root_descriptor: int, logical_path: str
) -> tuple[int, str]:
    parts = _validated_beneath_parts(logical_path)
    try:
        encoded = logical_path.encode("utf-8")
    except UnicodeEncodeError as error:
        raise BuildError("retained artifact logical path is unsafe") from error
    how = _OpenHow(
        flags=(
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
        ),
        mode=0,
        resolve=(
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
        ),
    )
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        ctypes.c_long(SYS_OPENAT2),
        ctypes.c_int(root_descriptor),
        ctypes.c_char_p(encoded),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if result < 0:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOSYS:
            return (
                _openat_component_walk(
                    root_descriptor,
                    logical_path,
                    parts,
                ),
                RETAINED_ARTIFACT_RESOLVER_COMPONENT_WALK,
            )
        if error_number == errno.EINVAL:
            raise BuildError(
                "openat2 retained-artifact policy was rejected; "
                "component-walk fallback is forbidden"
            )
        raise BuildError(
            f"retained artifact is absent, aliased, or escaped: {logical_path}"
        ) from OSError(error_number, os.strerror(error_number))
    return int(result), RETAINED_ARTIFACT_RESOLVER_OPENAT2


def _openat2_beneath(root_descriptor: int, logical_path: str) -> int:
    descriptor, _resolver = _open_beneath_with_resolver(
        root_descriptor, logical_path
    )
    return descriptor


def _measure_retained_artifact_resolver(
    root: Path, logical_path: str
) -> str:
    root_descriptor = _open_fixed_root(root)
    try:
        descriptor, resolver = _open_beneath_with_resolver(
            root_descriptor, logical_path
        )
        os.close(descriptor)
        return resolver
    finally:
        os.close(root_descriptor)


def _validated_logical_path(artifact: Mapping[str, Any]) -> str:
    if set(artifact) != {"logical_path", "byte_length", "sha256"}:
        raise BuildError("artifact receipt field set drifted")
    logical = artifact["logical_path"]
    try:
        _validated_beneath_parts(logical)
    except BuildError as error:
        raise BuildError("artifact logical path is unsafe") from error
    byte_length = artifact["byte_length"]
    if (
        not isinstance(byte_length, int)
        or isinstance(byte_length, bool)
        or byte_length <= 0
        or byte_length > MAX_ARTIFACT_BYTES
    ):
        raise BuildError(f"artifact byte length is invalid: {logical}")
    _require_hex(artifact["sha256"], 64, f"{logical}.sha256")
    return logical


def _copy_descriptor_bytes(
    source_descriptor: int, destination_descriptor: int
) -> tuple[int, str]:
    os.lseek(source_descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(source_descriptor, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ARTIFACT_BYTES:
            raise BuildError("retained artifact exceeds its byte bound")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(destination_descriptor, view)
            view = view[written:]
    os.fsync(destination_descriptor)
    return total, digest.hexdigest()


def _copy_retained_artifact(
    root_descriptor: int,
    artifact: Mapping[str, Any],
    private_root: Path,
    *,
    mode: int = 0o400,
) -> Path:
    logical = _validated_logical_path(artifact)
    source_descriptor = _openat2_beneath(root_descriptor, logical)
    destination = private_root.joinpath(*PurePosixPath(logical).parts)
    private_root.chmod(0o700)
    current = private_root
    for part in PurePosixPath(logical).parts[:-1]:
        current = current / part
        if not current.exists():
            current.mkdir(mode=0o700)
        current.chmod(0o700)
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or current.is_symlink():
            raise BuildError("private retained-artifact parent is aliased")
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != artifact["byte_length"]
        ):
            raise BuildError(
                f"retained artifact is not one exact regular inode: {logical}"
            )
        destination_descriptor = os.open(
            destination,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
        )
        try:
            byte_length, digest = _copy_descriptor_bytes(
                source_descriptor, destination_descriptor
            )
            after = os.fstat(source_descriptor)
            if _fd_identity(before) != _fd_identity(after):
                raise BuildError(
                    f"retained artifact identity changed while copying: {logical}"
                )
            if (
                byte_length != artifact["byte_length"]
                or digest != artifact["sha256"]
            ):
                raise BuildError(
                    f"retained artifact bytes or digest drifted: {logical}"
                )
            os.fchmod(destination_descriptor, mode)
        finally:
            os.close(destination_descriptor)
    finally:
        os.close(source_descriptor)
    if _artifact(destination, logical) != artifact:
        raise BuildError(f"private retained-artifact copy drifted: {logical}")
    return destination


@contextmanager
def _retained_artifact_snapshots_from_fd(
    root_descriptor: int, artifacts: Iterable[Mapping[str, Any]]
) -> Iterable[dict[str, Path]]:
    root_metadata = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise BuildError("pinned retained root descriptor is not a directory")
    with tempfile.TemporaryDirectory(
        prefix="provider-retained-verification."
    ) as temporary:
        private_root = Path(temporary)
        copies: dict[str, Path] = {}
        identities: dict[str, Mapping[str, Any]] = {}
        for artifact in artifacts:
            logical = _validated_logical_path(artifact)
            previous = identities.setdefault(logical, artifact)
            if previous != artifact:
                raise BuildError(
                    "receipt gives one retained path divergent identities"
                )
            if logical not in copies:
                copies[logical] = _copy_retained_artifact(
                    root_descriptor, artifact, private_root
                )
        yield copies


@contextmanager
def _retained_artifact_snapshots(
    root: Path, artifacts: Iterable[Mapping[str, Any]]
) -> Iterable[dict[str, Path]]:
    root_descriptor = _open_fixed_root(root)
    try:
        with _retained_artifact_snapshots_from_fd(
            root_descriptor, artifacts
        ) as copies:
            yield copies
    finally:
        os.close(root_descriptor)


def _artifact_path(
    copies: Mapping[str, Path], artifact: Mapping[str, Any]
) -> Path:
    logical = _validated_logical_path(artifact)
    path = copies.get(logical)
    if path is None or _artifact(path, logical) != artifact:
        raise BuildError(f"private retained artifact is absent or drifted: {logical}")
    return path


def _read_bounded_fd(
    descriptor: int, logical_path: str, maximum: int
) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise BuildError(f"input is not one bounded regular inode: {logical_path}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    after = os.fstat(descriptor)
    if _fd_identity(before) != _fd_identity(after):
        raise BuildError(f"input identity changed while reading: {logical_path}")
    if len(content) != before.st_size or len(content) > maximum:
        raise BuildError(f"input length drifted or exceeds its bound: {logical_path}")
    return bytes(content)


def _read_json_from_fixed_root_fd(
    root_descriptor: int,
    logical_path: str,
    maximum: int = MAX_RECEIPT_BYTES,
) -> dict[str, Any]:
    if (
        not logical_path
        or logical_path != str(PurePosixPath(logical_path))
        or PurePosixPath(logical_path).is_absolute()
        or ".." in PurePosixPath(logical_path).parts
    ):
        raise BuildError("fixed-root JSON path is unsafe")
    if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
        raise BuildError("pinned JSON root descriptor is not a directory")
    descriptor = _openat2_beneath(root_descriptor, logical_path)
    try:
        content = _read_bounded_fd(descriptor, logical_path, maximum)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError(f"malformed JSON: {logical_path}") from error
    if not isinstance(value, dict):
        raise BuildError(f"JSON top level must be an object: {logical_path}")
    return value


def _read_json_from_fixed_root(
    root: Path, logical_path: str, maximum: int = MAX_RECEIPT_BYTES
) -> dict[str, Any]:
    root_descriptor = _open_fixed_root(root)
    try:
        return _read_json_from_fixed_root_fd(
            root_descriptor, logical_path, maximum
        )
    finally:
        os.close(root_descriptor)


def _fixed_root_entry_exists_fd(
    root_descriptor: int, logical_path: str
) -> bool:
    if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
        raise BuildError("pinned entry root descriptor is not a directory")
    try:
        descriptor = _openat2_beneath(root_descriptor, logical_path)
    except BuildError as error:
        cause = error.__cause__
        if isinstance(cause, OSError) and cause.errno == errno.ENOENT:
            return False
        raise
    try:
        return stat.S_ISREG(os.fstat(descriptor).st_mode)
    finally:
        os.close(descriptor)


def _fixed_root_entry_exists(root: Path, logical_path: str) -> bool:
    root_descriptor = _open_fixed_root(root)
    try:
        return _fixed_root_entry_exists_fd(root_descriptor, logical_path)
    finally:
        os.close(root_descriptor)


def _domain_digest(domain: bytes, fields: Iterable[bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    return digest.hexdigest()


def _artifact(path: Path, logical_path: str) -> dict[str, Any]:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise BuildError(f"artifact must be a regular non-symlink: {path}")
    return {
        "logical_path": logical_path,
        "byte_length": metadata.st_size,
        "sha256": _sha256_file(path),
    }


def _stage_artifact(
    source: Path, output: Path, logical_path: str, mode: int = 0o444
) -> dict[str, Any]:
    pure = PurePosixPath(logical_path)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise BuildError(f"unsafe staged artifact path: {logical_path}")
    destination = output.joinpath(*pure.parts)
    if destination.exists() or destination.is_symlink():
        raise BuildError(f"refusing to overwrite staged artifact: {logical_path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination, follow_symlinks=False)
    destination.chmod(mode)
    return _artifact(destination, logical_path)


@contextmanager
def _expect_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise BuildError(f"{name} field set drifted; missing={missing}; extra={extra}")


def _require_hex(value: Any, length: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or value == "0" * length
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise BuildError(f"{name} is not a nonzero lowercase hexadecimal digest")
    return value


def _require_false_authority_fields(value: Mapping[str, Any], name: str) -> None:
    for field in FALSE_AUTHORITY_FIELDS:
        if value.get(field) is not False:
            raise BuildError(f"{name}.{field} must remain false")


def _source_checkpoint_projection(
    provider_name: str, provider: Mapping[str, Any]
) -> None:
    if provider_name != "codex" or provider.get("provider_wire_name") != "codex":
        raise BuildError("provider source-checkpoint identity drifted")
    return None


def _verify_source_checkpoint_projection(
    provider_name: str,
    provider: Mapping[str, Any],
    value: Any,
    label: str,
) -> None:
    if value != _source_checkpoint_projection(provider_name, provider):
        raise BuildError(f"{label} source-checkpoint projection drifted")


def _read_json(path: Path, maximum: int = MAX_RECEIPT_BYTES) -> dict[str, Any]:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise BuildError(f"JSON input is not one bounded regular file: {path}")
        content = bytearray()
        while len(content) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > maximum:
            raise BuildError(f"JSON input exceeds its bound: {path}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError(f"malformed JSON: {path}") from error
    if not isinstance(value, dict):
        raise BuildError(f"JSON top level must be an object: {path}")
    return value




def _validate_recipe_value(recipe: dict[str, Any]) -> dict[str, Any]:
    _expect_keys(recipe, EXPECTED_RECIPE_TOP_LEVEL_KEYS, "recipe")
    if (
        recipe["schema"] != RECIPE_SCHEMA
        or recipe["target_architecture"] != TARGET_ARCHITECTURE
        or recipe["source_date_epoch"] != 1_783_900_800
        or set(recipe["providers"]) != set(PROVIDERS)
        or tuple(recipe["builder"]["profiles"]) != BUILDER_PROFILES
    ):
        raise BuildError(
            "frozen recipe identity or closed provider/profile set drifted"
        )
    _require_false_authority_fields(recipe, "recipe")

    builder = recipe["builder"]
    _expect_keys(
        builder,
        {
            "base_image",
            "canonical_base_image",
            "amd64_manifest_sha256",
            "arm64_manifest_sha256",
            "debian_snapshot",
            "image_build_network",
            "rust_version",
            "zig_version",
            "zig_archives",
            "profiles",
        },
        "recipe.builder",
    )
    if (
        builder["base_image"] != "public.ecr.aws/docker/library/rust@sha256:"
        "6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1"
        or builder["canonical_base_image"] != "docker.io/library/rust@sha256:"
        "6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1"
        or builder["debian_snapshot"] != "20260713T000000Z"
        or builder["image_build_network"] != "default"
        or builder["rust_version"] != "1.95.0"
        or builder["zig_version"] != "0.14.0"
    ):
        raise BuildError(
            "frozen builder base, network, snapshot, Rust, or Zig pin drifted"
        )
    for architecture in ("amd64", "arm64"):
        archive = builder["zig_archives"].get(architecture)
        if not isinstance(archive, dict) or set(archive) != {"url", "sha256"}:
            raise BuildError(f"closed Zig archive recipe drifted for {architecture}")
        if not archive["url"].startswith("https://ziglang.org/download/0.14.0/"):
            raise BuildError(f"Zig source URL drifted for {architecture}")
        _require_hex(archive["sha256"], 64, f"zig.{architecture}.sha256")

    bootstrap = recipe["bootstrap"]
    _expect_keys(
        bootstrap,
        {
            "expected_filter_instruction_count",
            "public_header",
            "freestanding_core",
            "codex_entry",
            "codex_compiler_arguments",
            "externally_supplied_definitions",
        },
        "recipe.bootstrap",
    )
    if bootstrap["expected_filter_instruction_count"] != 37 or bootstrap[
        "externally_supplied_definitions"
    ] != ["TRILLIONNIUM_EXPECTED_UID", "TRILLIONNIUM_EXPECTED_GID"]:
        raise BuildError("bootstrap filter or definition closure drifted")
    for name in ("public_header", "freestanding_core", "codex_entry"):
        source = bootstrap[name]
        if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
            raise BuildError(f"bootstrap source shape drifted: {name}")
        path = DIRECTORY / source["path"]
        if not path.is_file() or path.is_symlink():
            raise BuildError(f"bootstrap source is missing or aliased: {path}")
        if _sha256_file(path) != source["sha256"]:
            raise BuildError(f"bootstrap source digest drifted: {path}")
    _validate_arguments(bootstrap["codex_compiler_arguments"])

    codex = recipe["providers"]["codex"]
    _expect_keys(codex, EXPECTED_CODEX_RECIPE_KEYS, "recipe.providers.codex")
    if (
        codex["repository_url"] != "https://github.com/openai/codex"
        or codex["annotated_tag"] != "rust-v0.144.1"
        or codex["annotated_tag_object_sha1"]
        != "db75c19352d29ef29c17dbcf73a7244f1b1a8d10"
        or codex["dereferenced_commit_sha1"]
        != "44918ea10c0f99151c6710411b4322c2f5c96bea"
        or codex["source_tree_sha1"] != "6c4d9c247f20ef879c8572eec76798edf9e96425"
        or codex["expected_uid"] != 5901
        or codex["expected_gid"] != 5901
    ):
        raise BuildError("exact upstream source pins drifted")
    if (
        codex["build_jobs"] != 2
        or codex["linker_threads"] != 1
        or codex["cargo_profile"]
        != {
            "name": "release",
            "debug": "none",
            "incremental": False,
            "lto": False,
            "codegen_units": 4,
            "strip": False,
        }
    ):
        raise BuildError("provider low-resource build contract drifted")
    _validate_pinned_cache_artifact(
        codex["source_archive"], "Codex source archive"
    )
    _expect_keys(
        codex["source_identity"],
        EXPECTED_CODEX_SOURCE_IDENTITY_KEYS,
        "Codex source identity",
    )
    for kind in ("tag_object", "commit_object"):
        _validate_pinned_cache_artifact(
            codex["source_identity"][kind],
            f"Codex {kind}",
        )
    for kind in ("source_member_manifest", "logical_symlinks"):
        _validate_pinned_cache_artifact(
            codex["source_identity"][kind],
            f"Codex {kind}",
        )
    if (
        codex["source_identity"]["source_root_name"] != "codex-rust-v0.144.1"
        or codex["source_identity"]["source_entry_count"] != 6_164
        or codex["source_identity"]["source_inventory_sha256"]
        != "14740f0fabf57f7828f7e1c82bcc9039b3d4af129d3261a66a6fabc8d0d3240c"
    ):
        raise BuildError("Codex source archive inventory contract drifted")
    derived_lock = codex["derived_lock"]
    _expect_keys(
        derived_lock,
        EXPECTED_CODEX_DERIVED_LOCK_KEYS,
        "Codex derived lock",
    )
    if (
        derived_lock["upstream_relative_path"] != "codex-rs/Cargo.lock"
        or derived_lock["workspace_version"] != "0.144.1"
        or derived_lock["workspace_package_count"] != 132
        or derived_lock["workspace_package_names_sha256"]
        != "509b6546a5bef3fd496dd33f130a2edf5a489a5bef25966abe034de3826ae177"
        or derived_lock["transformation"]
        != "source_less_workspace_package_version_0.0.0_to_0.144.1_only"
        or derived_lock["derived_sha256"]
        != "3e1588323284356881cc454122e1e4fd256226ae112351b0303d1ef115626e24"
        or derived_lock["patch_sha256"]
        != "9adcbff90fa1b60eaa38902612550f7df482442f2645043b21f611220ca2d06c"
    ):
        raise BuildError("Codex derived Cargo.lock closure drifted")
    _expect_keys(
        codex["cargo_vendor"],
        EXPECTED_CODEX_CARGO_VENDOR_KEYS,
        "Codex Cargo vendor",
    )
    _validate_pinned_cache_artifact(
        codex["cargo_vendor"]["archive"],
        "Codex Cargo vendor archive",
        maximum=MAX_DEPENDENCY_ARCHIVE_BYTES,
    )
    _validate_pinned_cache_artifact(
        codex["cargo_vendor"]["member_manifest"],
        "Codex Cargo vendor member manifest",
    )
    if (
        not isinstance(codex["cargo_vendor"]["root_name"], str)
        or codex["cargo_vendor"]["root_name"]
        != PurePosixPath(codex["cargo_vendor"]["root_name"]).name
        or not codex["cargo_vendor"]["root_name"]
        or codex["cargo_vendor"]["entry_count"] != 86_464
        or codex["cargo_vendor"]["inventory_sha256"]
        != "c27ba4545cb62119dadfb5cb44b85b15c5b4ae020581ff99cf2555aca828aa17"
    ):
        raise BuildError("Codex Cargo vendor inventory drifted")
    _validate_pinned_cache_artifact(
        codex["cargo_source_config"], "Codex Cargo source config"
    )
    _expect_keys(codex["rusty_v8"], EXPECTED_CODEX_RUSTY_V8_KEYS, "Codex rusty_v8")
    if (
        codex["rusty_v8"]["crate_version"] != "149.2.0"
        or codex["rusty_v8"]["crate_checksum_sha256"]
        != "46dccf61a364b61bbaac70a8ba64a1a1006e87123b7d62eaeec999a3ba31ecdb"
        or codex["rusty_v8"]["target"] != "aarch64-unknown-linux-musl"
        or codex["rusty_v8"]["variant"] != "release"
        or codex["rusty_v8"]["resolved_features"]
        != {
            "codex-cli": [],
            "codex-code-mode": [],
            "codex-core": [],
            "v8": ["default", "use_custom_libcxx"],
        }
        or codex["rusty_v8"]["archive_uncompressed_byte_length"] != 151_804_540
        or codex["rusty_v8"]["archive_uncompressed_sha256"]
        != "3295c376bd7b3e88de238cd5cbc7fabc22342c18479c28b45ad84112ce1b8616"
        or codex["rusty_v8"]["release_prerelease"] is not True
        or codex["rusty_v8"]["release_immutable"] is not False
        or codex["rusty_v8"]["upstream_signature_proven"] is not False
        or codex["rusty_v8"]["github_attestation_proven"] is not False
    ):
        raise BuildError("Codex rusty_v8 build or provenance contract drifted")
    for name in ("archive", "binding", "checksums"):
        artifact = codex["rusty_v8"][name]
        _validate_pinned_cache_artifact(
            artifact,
            f"Codex rusty_v8 {name}",
            remote=True,
        )
        if not artifact["url"].startswith(
            "https://github.com/openai/codex/releases/download/"
            "rusty-v8-v149.2.0/"
        ):
            raise BuildError("Codex rusty_v8 release URL drifted")
    if (
        codex["rusty_v8"]["archive"]["sha256"]
        != "889155b099a2eac05a13175994257ef3a6140201bb411b74b50333f42b608717"
        or codex["rusty_v8"]["binding"]["sha256"]
        != "5db3ec0783531d12862a3f38dd5a679273550e67962260b81f07e612a68a0c24"
        or codex["rusty_v8"]["checksums"]["sha256"]
        != "f6a6b2b9838b4c6259a6362ce235d4ff9ef74f389460da0c67d01f4ea3f5dff2"
        ):
            raise BuildError("Codex rusty_v8 release digest drifted")
    if codex["required_symbol_table"] is not True:
        raise BuildError("Codex recipe may not accept a stripped final payload")
    return recipe


def load_recipe() -> dict[str, Any]:
    return _validate_recipe_value(_read_json(RECIPE_PATH))


def _validate_arguments(arguments: Any) -> None:
    if not isinstance(arguments, list) or not arguments:
        raise BuildError("build argument list is empty or malformed")
    for argument in arguments:
        if not isinstance(argument, str) or not argument or "\0" in argument:
            raise BuildError("build argument is empty or malformed")
        if argument.startswith(FORBIDDEN_ARGUMENT_PREFIXES) or any(
            fragment in argument for fragment in FORBIDDEN_ARGUMENT_FRAGMENTS
        ):
            raise BuildError(f"fixture or override argument is forbidden: {argument}")


def _container_proxy_environment() -> list[dict[str, str]]:
    return [
        {"name": name, "value": ""}
        for name in CONTAINER_PROXY_ENVIRONMENT_NAMES
    ]


def _provider_container_environment_bindings() -> list[str]:
    return [
        *(f"{name}=" for name in CONTAINER_PROXY_ENVIRONMENT_NAMES),
        "HOME=/output/.home",
        "CARGO_HOME=/output/.cargo-home",
        "CARGO_TARGET_DIR=/output/.work/target",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "TMPDIR=/tmp",
    ]


def _provider_container_environment_arguments() -> list[str]:
    return [
        argument
        for binding in _provider_container_environment_bindings()
        for argument in ("--env", binding)
    ]


def _provider_container_isolation_arguments() -> list[str]:
    return [
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        CONTAINER_PIDS_LIMIT,
        "--memory",
        CONTAINER_MEMORY_LIMIT,
        "--memory-swap",
        CONTAINER_MEMORY_LIMIT,
        "--cpus",
        CONTAINER_CPU_LIMIT,
        "--shm-size",
        CONTAINER_SHM_SIZE,
        "--tmpfs",
        CONTAINER_TMPFS,
        "--ulimit",
        f"nofile={CONTAINER_NOFILE_ULIMIT}",
    ]


def _provider_container_inner_arguments(
    *,
    provider_name: str,
    profile: str,
    image_id: str,
    recipe_sha256: str,
    builder_sha256: str,
    containerfile_sha256: str,
    attempt_id: str,
    output: Path | str,
    cache: Path | str,
    container_name: str,
    cidfile_host_path: Path | str,
    build_context_tar_sha256: str,
    build_context_tar_byte_length: int,
    build_context_member_manifest_sha256: str,
) -> list[str]:
    if provider_name not in PROVIDERS or profile not in BUILDER_PROFILES:
        raise BuildError("container provider or profile is outside the closed set")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise BuildError("container run image is not one immutable image ID")
    for label, digest in (
        ("recipe", recipe_sha256),
        ("builder", builder_sha256),
        ("Containerfile", containerfile_sha256),
        ("attempt", attempt_id),
    ):
        _require_hex(digest, 64, f"{label} SHA-256")
    input_identity = _container_input_identity(
        recipe_sha256,
        builder_sha256,
        containerfile_sha256,
    )
    expected_attempt = _build_attempt_identity(
        input_identity,
        provider_name,
        profile,
        output,
        cache,
    )
    if attempt_id != expected_attempt or container_name != _container_name(attempt_id):
        raise BuildError("container attempt or name does not match frozen inputs")
    expected_cidfile = (
        _container_cidfile_custody_path(output, attempt_id)
        / CONTAINER_CIDFILE_NAME
    )
    cidfile_value = _validated_attempt_path(
        cidfile_host_path,
        "container cidfile host path",
    )
    if cidfile_value != str(expected_cidfile):
        raise BuildError("container cidfile host path drifted")
    _require_hex(
        build_context_tar_sha256,
        64,
        "build context tar SHA-256",
    )
    _require_hex(
        build_context_member_manifest_sha256,
        64,
        "build context member manifest SHA-256",
    )
    if (
        isinstance(build_context_tar_byte_length, bool)
        or not isinstance(build_context_tar_byte_length, int)
        or build_context_tar_byte_length <= 0
        or build_context_tar_byte_length > MAX_BUILD_CONTEXT_TAR_BYTES
    ):
        raise BuildError("build context tar byte length is malformed")
    return [
        "--provider",
        provider_name,
        "--builder-profile",
        profile,
        "--builder-image-id",
        image_id,
        "--recipe-sha256",
        recipe_sha256,
        "--builder-sha256",
        builder_sha256,
        "--containerfile-sha256",
        containerfile_sha256,
        "--build-context-tar-sha256",
        build_context_tar_sha256,
        "--build-context-tar-byte-length",
        str(build_context_tar_byte_length),
        "--build-context-member-manifest-sha256",
        build_context_member_manifest_sha256,
        "--build-attempt-id",
        attempt_id,
        "--requested-output",
        _validated_attempt_path(output, "requested output"),
        "--cache-root",
        _validated_attempt_path(cache, "cache root"),
        "--container-name",
        container_name,
        "--container-cidfile-host",
        cidfile_value,
        "--container-cidfile",
        CONTAINER_CIDFILE_PATH,
    ]


def _one_command_option_value(
    command: Sequence[str],
    option: str,
    context: str,
) -> str:
    indexes = [
        index
        for index, argument in enumerate(command)
        if argument == option
    ]
    if (
        len(indexes) != 1
        or indexes[0] + 1 >= len(command)
        or command[indexes[0] + 1].startswith("--")
    ):
        raise BuildError(f"{context} has an ambiguous {option} option")
    return command[indexes[0] + 1]


def _validated_container_run_user(value: str) -> str:
    match = re.fullmatch(r"([1-9][0-9]*):([1-9][0-9]*)", value)
    if match is None or any(
        int(component) > 0xFFFFFFFF for component in match.groups()
    ):
        raise BuildError("container run user is not one non-root numeric identity")
    return value


def _validated_container_stage_path(
    value: Path | str,
    output: Path | str,
) -> str:
    rendered = _validated_attempt_path(value, "container output stage")
    output_value = _validated_attempt_path(output, "requested output")
    stage = PurePosixPath(rendered)
    requested = PurePosixPath(output_value)
    prefix = f".{requested.name}."
    suffix = stage.name.removeprefix(prefix)
    if (
        stage.parent != requested.parent
        or not stage.name.startswith(prefix)
        or re.fullmatch(r"[a-z0-9_]{8}", suffix) is None
    ):
        raise BuildError("container output stage is outside its closed attempt path")
    return rendered


def _provider_container_command(
    *,
    engine: str,
    provider_name: str,
    profile: str,
    image_id: str,
    recipe_sha256: str,
    builder_sha256: str,
    containerfile_sha256: str,
    attempt_id: str,
    output: Path | str,
    cache: Path | str,
    stage: Path | str,
    container_name: str,
    cidfile_host_path: Path | str,
    run_user: str,
    build_context_tar_sha256: str,
    build_context_tar_byte_length: int,
    build_context_member_manifest_sha256: str,
) -> list[str]:
    if engine != "docker":
        raise BuildError("provider container engine is not the closed Docker CLI")
    output_value = _validated_attempt_path(output, "requested output")
    cache_value = _validated_attempt_path(cache, "cache root")
    stage_value = _validated_container_stage_path(stage, output_value)
    user_value = _validated_container_run_user(run_user)
    inner_arguments = _provider_container_inner_arguments(
        provider_name=provider_name,
        profile=profile,
        image_id=image_id,
        recipe_sha256=recipe_sha256,
        builder_sha256=builder_sha256,
        containerfile_sha256=containerfile_sha256,
        attempt_id=attempt_id,
        output=output_value,
        cache=cache_value,
        container_name=container_name,
        cidfile_host_path=cidfile_host_path,
        build_context_tar_sha256=build_context_tar_sha256,
        build_context_tar_byte_length=build_context_tar_byte_length,
        build_context_member_manifest_sha256=(
            build_context_member_manifest_sha256
        ),
    )
    recipe = load_recipe()
    if profile not in BUILDER_PROFILES:
        raise BuildError("provider container profile is outside the closed set")
    command = [
        engine,
        "run",
        *_provider_container_isolation_arguments(),
        "--rm",
        "--name",
        container_name,
        "--cidfile",
        _validated_attempt_path(
            cidfile_host_path,
            "container cidfile host path",
        ),
        "--platform",
        recipe["builder"]["profiles"][profile]["platform"],
        "--user",
        user_value,
        "--mount",
        f"type=bind,src={cache_value},dst=/cache,readonly",
        "--mount",
        f"type=bind,src={stage_value},dst=/output",
        "--mount",
        (
            "type=bind,"
            f"src={Path(cidfile_host_path).parent},"
            f"dst={CONTAINER_CIDFILE_MOUNT},readonly"
        ),
    ]
    command.extend(_provider_container_environment_arguments())
    if provider_name == "codex":
        vendor_root = (
            Path(cache_value)
            / recipe["providers"]["codex"]["cargo_vendor"]["root_name"]
        )
        _validated_attempt_path(vendor_root, "Codex vendor mount")
        command.extend(
            [
                "--mount",
                (
                    f"type=bind,src={vendor_root},"
                    "dst=/opt/trillionnium/cargo-vendor,readonly"
                ),
            ]
        )
    command.extend([image_id, *inner_arguments])
    return command


def _validate_provider_container_command(
    command: Any,
    context: str,
) -> None:
    _validate_arguments(command)
    isolation = _provider_container_isolation_arguments()
    if (
        len(command) < 2 + len(isolation)
        or command[0] != "docker"
        or command[1] != "run"
        or command[2 : 2 + len(isolation)] != isolation
    ):
        raise BuildError(f"{context} uses an ambiguous container option")
    name = _one_command_option_value(command, "--name", context)
    cidfile_host_path = _one_command_option_value(
        command,
        "--cidfile",
        context,
    )
    run_user = _one_command_option_value(command, "--user", context)
    provider_indexes = [
        index
        for index, argument in enumerate(command)
        if argument == "--provider"
    ]
    if len(provider_indexes) != 1 or provider_indexes[0] < 1:
        raise BuildError(f"{context} internal launcher suffix is ambiguous")
    provider_index = provider_indexes[0]
    image_reference = command[provider_index - 1]
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_reference) is None:
        raise BuildError(f"{context} does not run an immutable image ID")
    suffix = command[provider_index:]
    if len(suffix) != 30:
        raise BuildError(f"{context} internal launcher suffix drifted")
    values = {
        suffix[index]: suffix[index + 1]
        for index in range(0, len(suffix), 2)
    }
    if len(values) != 15:
        raise BuildError(f"{context} internal launcher options are duplicated")
    output_mounts = [
        value
        for index, argument in enumerate(command[:-1])
        if argument == "--mount"
        for value in [command[index + 1]]
        if value.startswith("type=bind,src=")
        and value.endswith(",dst=/output")
    ]
    if len(output_mounts) != 1:
        raise BuildError(f"{context} output stage mount is ambiguous")
    stage = output_mounts[0].removeprefix(
        "type=bind,src="
    ).removesuffix(",dst=/output")
    try:
        expected_command = _provider_container_command(
            engine=command[0],
            provider_name=values["--provider"],
            profile=values["--builder-profile"],
            image_id=values["--builder-image-id"],
            recipe_sha256=values["--recipe-sha256"],
            builder_sha256=values["--builder-sha256"],
            containerfile_sha256=values["--containerfile-sha256"],
            attempt_id=values["--build-attempt-id"],
            output=values["--requested-output"],
            cache=values["--cache-root"],
            stage=stage,
            container_name=values["--container-name"],
            cidfile_host_path=values["--container-cidfile-host"],
            run_user=run_user,
            build_context_tar_sha256=values[
                "--build-context-tar-sha256"
            ],
            build_context_tar_byte_length=int(
                values["--build-context-tar-byte-length"]
            ),
            build_context_member_manifest_sha256=values[
                "--build-context-member-manifest-sha256"
            ],
        )
    except (KeyError, ValueError) as error:
        raise BuildError(f"{context} internal launcher option set drifted") from error
    if (
        command != expected_command
        or image_reference != values["--builder-image-id"]
        or name != values["--container-name"]
        or cidfile_host_path != values["--container-cidfile-host"]
        or values.get("--container-cidfile") != CONTAINER_CIDFILE_PATH
        or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name) is None
        or len(name.encode("ascii")) > CONTAINER_NAME_MAX_BYTES
    ):
        raise BuildError(f"{context} immutable lifecycle arguments drifted")


def _verify_container_projection(
    value: Any,
    *,
    provider_name: str,
    profile: str,
    recipe_sha256: str,
    builder_sha256: str,
    containerfile_sha256: str,
    image_reference: str | None,
    expected_build_context: Mapping[str, Any] | None = None,
    allow_pending: bool = False,
    allow_failure_states: bool = False,
) -> None:
    if not isinstance(value, dict):
        raise BuildError("container lifecycle projection is malformed")
    _expect_keys(value, EXPECTED_CONTAINER_KEYS, "container lifecycle projection")
    cidfile = value["cidfile"]
    if not isinstance(cidfile, dict):
        raise BuildError("container cidfile custody projection is malformed")
    _expect_keys(
        cidfile,
        EXPECTED_CONTAINER_CIDFILE_KEYS,
        "container cidfile custody projection",
    )
    _verify_build_context_receipt(value["build_context"])
    if (
        expected_build_context is not None
        and value["build_context"] != expected_build_context
    ):
        raise BuildError("container builder-context projection drifted")
    output = _validated_attempt_path(
        value["requested_output"],
        "container requested output",
    )
    cache = _validated_attempt_path(
        value["cache_root"],
        "container cache root",
    )
    input_identity = _container_input_identity(
        recipe_sha256,
        builder_sha256,
        containerfile_sha256,
    )
    expected_attempt = _build_attempt_identity(
        input_identity,
        provider_name,
        profile,
        output,
        cache,
    )
    expected_custody = _container_cidfile_custody_path(
        output,
        expected_attempt,
    )
    if (
        value["attempt_id_sha256"] != expected_attempt
        or value["name"] != _container_name(expected_attempt)
        or value["image_reference"] != image_reference
        or value["network"] != "none"
        or value["client_disconnect_does_not_imply_container_stop"] is not True
        or cidfile["host_path"]
        != str(expected_custody / CONTAINER_CIDFILE_NAME)
        or cidfile["container_path"] != CONTAINER_CIDFILE_PATH
        or cidfile["custody_directory_path"] != str(expected_custody)
        or cidfile["creation_authority"] != "container_engine_only"
        or cidfile[
            "controller_exit_before_cleanup_preserves_cidfile"
        ]
        is not True
    ):
        raise BuildError("container lifecycle input identity drifted")
    container_id = value["id"]
    if container_id is not None and (
        not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
    ):
        raise BuildError("container lifecycle ID is malformed")
    for name in (
        "run_invoked",
        "completed_zero",
    ):
        if not isinstance(value[name], bool):
            raise BuildError("container execution booleans are malformed")
    for name in (
        "pre_run_absent_no_symlink",
        "container_id_cidfile_observed",
        "read_during_container_execution",
        "captured_after_exit_via_fixed_fd",
        "container_id_cross_checked",
        "unlinked_after_capture",
        "custody_directory_fsynced",
        "output_parent_fsynced",
    ):
        if not isinstance(cidfile[name], bool):
            raise BuildError("container cidfile custody booleans are malformed")
    identity = cidfile["custody_directory_identity"]
    if identity is not None and (
        not isinstance(identity, dict)
        or set(identity) != {"device", "inode"}
        or any(
            isinstance(identity[name], bool)
            or not isinstance(identity[name], int)
            or identity[name] <= 0
            for name in ("device", "inode")
        )
    ):
        raise BuildError("container cidfile custody identity is malformed")
    command = value["command"]
    if command is not None:
        _validate_provider_container_command(
            command,
            "receipt container command",
        )
        if (
            _one_command_option_value(command, "--name", "receipt command")
            != value["name"]
            or _one_command_option_value(
                command,
                "--cidfile",
                "receipt command",
            )
            != cidfile["host_path"]
            or _one_command_option_value(
                command,
                "--build-context-tar-sha256",
                "receipt command",
            )
            != value["build_context"]["tar_sha256"]
            or _one_command_option_value(
                command,
                "--build-context-tar-byte-length",
                "receipt command",
            )
            != str(value["build_context"]["tar_byte_length"])
            or _one_command_option_value(
                command,
                "--build-context-member-manifest-sha256",
                "receipt command",
            )
            != value["build_context"]["member_manifest_sha256"]
        ):
            raise BuildError("receipt container command lifecycle identity drifted")
    state = cidfile["state"]
    if state not in CONTAINER_CIDFILE_STATES:
        raise BuildError("container cidfile custody state is outside the closed set")
    tombstone = cidfile["cleanup_tombstone"]
    if tombstone is not None:
        if not isinstance(tombstone, dict):
            raise BuildError("container cidfile cleanup tombstone is malformed")
        _expect_keys(
            tombstone,
            {
                "state",
                "role",
                "requested_path",
                "expected_identity",
                "observed_identity",
                "mode",
                "empty",
                "same_uid_concurrent_child_name_replacement_proven",
                "same_uid_concurrent_retained_stage_path_replacement_proven",
            },
            "container cidfile cleanup tombstone",
        )
        path, tombstone_identity = _validate_stage_identity_record(
            tombstone,
            "container cidfile cleanup tombstone",
        )
        if (
            tombstone["state"] != "empty_cleanup_tombstone_retained"
            or tombstone["role"] != "container_cidfile_custody"
            or path != expected_custody
            or identity
            != {
                "device": tombstone_identity[0],
                "inode": tombstone_identity[1],
            }
            or tombstone["mode"] != "0500"
            or tombstone["empty"] is not True
            or tombstone[
                "same_uid_concurrent_child_name_replacement_proven"
            ]
            is not False
            or tombstone[
                "same_uid_concurrent_retained_stage_path_replacement_proven"
            ]
            is not False
        ):
            raise BuildError("container cidfile cleanup tombstone drifted")
    exact_state_contracts: dict[str, dict[str, Any]] = {
        "not_prepared": {
            "identity": None,
            "id": None,
            "run": False,
            "completed": False,
            "command": None,
            "flags": (False, False, False, False, False, False, False, False),
            "tombstone": None,
        },
        "custody_preparation_rejected": {
            "identity": None,
            "id": None,
            "run": False,
            "completed": False,
            "command": None,
            "flags": (False, False, False, False, False, False, False, False),
            "tombstone": None,
        },
        "prepared_not_invoked": {
            "identity": "present",
            "id": None,
            "run": False,
            "completed": False,
            "command": "present",
            "flags": (True, False, False, False, False, False, False, False),
            "tombstone": None,
        },
        "pending_launcher_capture": {
            "identity": "present",
            "id": "present",
            "run": True,
            "completed": False,
            "command": None,
            "flags": (True, True, True, False, False, False, False, False),
            "tombstone": None,
        },
        "captured_after_success": {
            "identity": "present",
            "id": "present",
            "run": True,
            "completed": True,
            "command": "present",
            "flags": (True, True, True, True, True, True, True, True),
            "tombstone": "present",
        },
        "captured_after_zero_exit_without_crosscheck": {
            "identity": "present",
            "id": "present",
            "run": True,
            "completed": True,
            "command": "present",
            "flags": (True, True, False, True, False, True, True, True),
            "tombstone": "present",
        },
        "captured_after_failed_run": {
            "identity": "present",
            "id": "present",
            "run": True,
            "completed": False,
            "command": "present",
            "flags": (True, True, False, True, False, True, True, True),
            "tombstone": "present",
        },
        "absent_after_failed_run": {
            "identity": "present",
            "id": None,
            "run": True,
            "completed": False,
            "command": "present",
            "flags": (True, False, False, False, False, False, True, True),
            "tombstone": "present",
        },
    }
    if state == "pre_run_entry_rejected":
        if (
            identity is None
            or container_id is not None
            or value["run_invoked"]
            or value["completed_zero"]
            or command is None
            or cidfile["pre_run_absent_no_symlink"]
            or any(
                cidfile[name]
                for name in (
                    "container_id_cidfile_observed",
                    "read_during_container_execution",
                    "captured_after_exit_via_fixed_fd",
                    "container_id_cross_checked",
                    "unlinked_after_capture",
                    "custody_directory_fsynced",
                    "output_parent_fsynced",
                )
            )
            or tombstone is not None
        ):
            raise BuildError("pre-run cidfile rejection semantics drifted")
    elif state in exact_state_contracts:
        contract = exact_state_contracts[state]
        observed_flags = (
            cidfile["pre_run_absent_no_symlink"],
            cidfile["container_id_cidfile_observed"],
            cidfile["read_during_container_execution"],
            cidfile["captured_after_exit_via_fixed_fd"],
            cidfile["container_id_cross_checked"],
            cidfile["unlinked_after_capture"],
            cidfile["custody_directory_fsynced"],
            cidfile["output_parent_fsynced"],
        )
        if (
            (identity is None) != (contract["identity"] is None)
            or (container_id is None) != (contract["id"] is None)
            or value["run_invoked"] is not contract["run"]
            or value["completed_zero"] is not contract["completed"]
            or (command is None) != (contract["command"] is None)
            or observed_flags != contract["flags"]
            or (tombstone is None) != (contract["tombstone"] is None)
        ):
            raise BuildError(f"container cidfile state semantics drifted: {state}")
    else:
        if not allow_failure_states:
            raise BuildError("builder receipt contains a failed cidfile custody state")
        if (
            state not in {"retained_untrusted", "cleanup_incomplete"}
            or identity is None
            or not value["run_invoked"]
            or command is None
            or tombstone is not None
            or cidfile["container_id_cross_checked"]
            and not cidfile["captured_after_exit_via_fixed_fd"]
            or cidfile["unlinked_after_capture"]
            and not cidfile["captured_after_exit_via_fixed_fd"]
            or cidfile["output_parent_fsynced"]
            and not cidfile["custody_directory_fsynced"]
        ):
            raise BuildError("failed cidfile custody state is contradictory")
    if state == "pending_launcher_capture" and not allow_pending:
        raise BuildError("pending container custody is not a final builder receipt")
    if state == "captured_after_success" and allow_failure_states:
        pass
    elif state not in {"pending_launcher_capture", "captured_after_success"} and (
        not allow_failure_states
    ):
        raise BuildError("builder receipt container custody is not final")


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
    maximum_output: int = 128 * 1024,
    require_complete_output: bool = False,
    stdin_descriptor: int | None = None,
    pass_descriptors: Sequence[int] = (),
) -> str:
    _validate_arguments(list(arguments))
    if (
        isinstance(maximum_output, bool)
        or not isinstance(maximum_output, int)
        or maximum_output <= 0
    ):
        raise BuildError("command output limit must be one positive integer")
    if stdin_descriptor is not None:
        if (
            isinstance(stdin_descriptor, bool)
            or not isinstance(stdin_descriptor, int)
            or stdin_descriptor < 0
            or not stat.S_ISREG(os.fstat(stdin_descriptor).st_mode)
        ):
            raise BuildError("command stdin descriptor is not one fixed regular inode")
    if (
        not isinstance(pass_descriptors, Sequence)
        or isinstance(pass_descriptors, (str, bytes))
        or any(
            isinstance(descriptor, bool)
            or not isinstance(descriptor, int)
            or descriptor < 0
            or not stat.S_ISREG(os.fstat(descriptor).st_mode)
            for descriptor in pass_descriptors
        )
        or len(set(pass_descriptors)) != len(pass_descriptors)
    ):
        raise BuildError("passed command descriptors are not distinct regular inodes")
    process = subprocess.Popen(
        list(arguments),
        cwd=cwd,
        env=dict(environment) if environment is not None else None,
        stdin=(
            stdin_descriptor
            if stdin_descriptor is not None
            else subprocess.DEVNULL
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        pass_fds=tuple(pass_descriptors),
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise BuildError("command output pipe was not created")
    output_tail = bytearray()
    output_truncated = False
    complete_output_exceeded = False
    try:
        while True:
            chunk = process.stdout.read1(64 * 1024)
            if not chunk:
                break
            output_tail.extend(chunk)
            if len(output_tail) > maximum_output:
                output_truncated = True
                del output_tail[: len(output_tail) - maximum_output]
                if require_complete_output and not complete_output_exceeded:
                    complete_output_exceeded = True
                    process.kill()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    return_code = process.wait()
    output = bytes(output_tail).decode("utf-8", errors="replace")
    if complete_output_exceeded:
        raise BuildError(
            "command output exceeded the complete-output limit "
            f"({maximum_output} bytes): {' '.join(arguments)}"
        )
    if return_code != 0:
        raise CommandFailure(
            arguments,
            return_code,
            output,
            output_truncated,
        )
    return output


def _write_bytes(path: Path, content: bytes, mode: int = 0o444) -> None:
    if path.exists() or path.is_symlink():
        raise BuildError(f"refusing to overwrite build artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _download_exact(
    url: str,
    expected_sha256: str,
    destination: Path,
    *,
    expected_bytes: int | None = None,
    allow_github_release_redirect: bool = False,
) -> None:
    if destination.exists():
        if (
            destination.is_symlink()
            or _sha256_file(destination, MAX_SOURCE_ARCHIVE_BYTES) != expected_sha256
            or (
                expected_bytes is not None
                and destination.stat(follow_symlinks=False).st_size != expected_bytes
            )
        ):
            raise BuildError(
                f"cached source archive failed its exact digest: {destination}"
            )
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{destination.name}.",
        dir=destination.parent,
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
        digest = hashlib.sha256()
        total = 0
        request = urllib.request.Request(
            url, headers={"User-Agent": "trillionnium-builder/1"}
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                final_url = response.geturl()
                redirect_valid = final_url == url
                if allow_github_release_redirect and final_url != url:
                    parsed = urlparse(final_url)
                    redirect_valid = (
                        parsed.scheme == "https"
                        and parsed.hostname
                        in {
                            "release-assets.githubusercontent.com",
                            "objects.githubusercontent.com",
                        }
                    )
                if not redirect_valid:
                    raise BuildError(
                        "source archive redirected away from its exact pinned URL"
                    )
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_SOURCE_ARCHIVE_BYTES:
                        raise BuildError("source archive exceeds its fixed bound")
                    digest.update(chunk)
                    temporary.write(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise
    if (
        total == 0
        or digest.hexdigest() != expected_sha256
        or (expected_bytes is not None and total != expected_bytes)
    ):
        temporary_path.unlink(missing_ok=True)
        raise BuildError("downloaded source archive digest mismatch")
    os.replace(temporary_path, destination)
    destination.chmod(0o444)


def _safe_extract_tar_xz(
    archive: Path,
    destination: Path,
    *,
    allowed_symlink_suffixes: Mapping[str, str] | None = None,
) -> Path:
    return _safe_extract_tar_archive(
        archive,
        destination,
        mode="r:xz",
        allowed_symlink_suffixes=allowed_symlink_suffixes,
    )


def _safe_extract_tar_archive(
    archive: Path,
    destination: Path,
    *,
    mode: str,
    allowed_symlink_suffixes: Mapping[str, str] | None = None,
) -> Path:
    if mode not in {"r:", "r:xz"}:
        raise BuildError("unsupported frozen source archive format")
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive, mode=mode) as bundle:
        members = bundle.getmembers()
        if not members or len(members) > 100_000:
            raise BuildError("source archive member inventory is empty or unbounded")
        roots: set[str] = set()
        seen_paths: set[PurePosixPath] = set()
        extracted_bytes = 0
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise BuildError(f"unsafe source archive member: {member.name}")
            if pure in seen_paths:
                raise BuildError(f"duplicate source archive member: {member.name}")
            seen_paths.add(pure)
            roots.add(pure.parts[0])
            member_mode = member.mode & 0o7777
            if not member.issym() and (
                member_mode != member.mode
                or member_mode & 0o7022
                or (
                    member.isdir()
                    and member_mode != 0o755
                )
                or (
                    member.isfile()
                    and member_mode not in {0o644, 0o755}
                )
            ):
                raise BuildError(
                    f"unsafe source archive member mode: {member.name}"
                )
            if member.issym():
                relative = str(PurePosixPath(*pure.parts[1:]))
                target = PurePosixPath(member.linkname)
                expected = (
                    allowed_symlink_suffixes.get(relative)
                    if allowed_symlink_suffixes is not None
                    else None
                )
                if (
                    expected is None
                    or member.linkname != expected
                    or target.is_absolute()
                    or ".." in target.parts
                ):
                    raise BuildError(
                        f"unapproved source archive symlink: {member.name}"
                    )
            elif not (member.isfile() or member.isdir()):
                raise BuildError(f"non-regular source archive member: {member.name}")
            if member.isfile():
                extracted_bytes += member.size
                if extracted_bytes > MAX_EXTRACTED_SOURCE_BYTES:
                    raise BuildError("source archive expanded bytes exceed the fixed bound")
        if len(roots) != 1:
            raise BuildError("source archive does not have one closed root")
        directories = sorted(
            (member for member in members if member.isdir()),
            key=lambda member: len(PurePosixPath(member.name).parts),
        )
        for member in directories:
            extracted = destination.joinpath(*PurePosixPath(member.name).parts)
            extracted.mkdir(parents=True, exist_ok=True, mode=0o700)
            if extracted.is_symlink():
                raise BuildError(f"source archive directory is aliased: {member.name}")
        for member in (member for member in members if member.isfile()):
            extracted = destination.joinpath(*PurePosixPath(member.name).parts)
            extracted.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if any(
                parent.is_symlink()
                for parent in (extracted, *extracted.parents)
                if parent != destination.parent
            ):
                raise BuildError(f"source archive file path is aliased: {member.name}")
            source = bundle.extractfile(member)
            if source is None:
                raise BuildError(f"source archive file is unreadable: {member.name}")
            descriptor = os.open(
                extracted,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            copied = 0
            try:
                with source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > member.size:
                            raise BuildError(
                                f"source archive file exceeds its header size: {member.name}"
                            )
                        view = memoryview(chunk)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise BuildError(
                                    f"source archive file write failed: {member.name}"
                                )
                            view = view[written:]
                if copied != member.size:
                    raise BuildError(
                        f"source archive file size mismatch: {member.name}"
                    )
            finally:
                os.close(descriptor)
            extracted.chmod(member.mode & 0o777)
        for member in (member for member in members if member.issym()):
            extracted = destination.joinpath(*PurePosixPath(member.name).parts)
            extracted.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.symlink(member.linkname, extracted)
        for member in reversed(directories):
            extracted = destination.joinpath(*PurePosixPath(member.name).parts)
            extracted.chmod(member.mode & 0o777)
    root = destination / next(iter(roots))
    if not root.is_dir() or root.is_symlink():
        raise BuildError("source archive root is missing or aliased")
    for relative, target in (allowed_symlink_suffixes or {}).items():
        link = root.joinpath(*PurePosixPath(relative).parts)
        if not link.is_symlink() or os.readlink(link) != target:
            raise BuildError(f"approved source archive symlink is absent: {relative}")
    return root


def _vendor_member_inventory(root: Path) -> tuple[list[dict[str, Any]], str]:
    if not root.is_dir() or root.is_symlink():
        raise BuildError("Codex Cargo vendor root is absent or aliased")
    entries: list[dict[str, Any]] = [
        {
            "path": ".",
            "kind": "directory",
            "mode": f"{stat.S_IMODE(root.lstat().st_mode):04o}",
        }
    ]
    paths = sorted(
        root.rglob("*"),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    for path in paths:
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        entry: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if stat.S_ISDIR(metadata.st_mode):
            entry["kind"] = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            entry.update(
                {
                    "kind": "regular",
                    "byte_length": metadata.st_size,
                    "sha256": _sha256_file(path, allow_empty=True),
                }
            )
        elif stat.S_ISLNK(metadata.st_mode):
            entry.update({"kind": "symlink", "target": os.readlink(path)})
        else:
            raise BuildError(f"Codex Cargo vendor special file: {relative}")
        entries.append(entry)
        if len(entries) > 100_000:
            raise BuildError("Codex Cargo vendor inventory exceeds its fixed bound")
    encoded = json.dumps(
        entries,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return entries, _sha256_bytes(encoded)


def _verify_and_restore_codex_source_archive(
    root: Path,
    member_manifest_path: Path,
    logical_symlinks_path: Path,
    provider: Mapping[str, Any],
) -> None:
    member_manifest = _read_json(
        member_manifest_path,
        maximum=4 * 1024 * 1024,
    )
    logical = _read_json(logical_symlinks_path)
    _expect_keys(
        member_manifest,
        {
            "schema",
            "root_name",
            "entry_count",
            "inventory_sha256",
            "archive_allowed_symlinks",
            "entries",
        },
        "Codex source member manifest",
    )
    _expect_keys(
        logical,
        {"schema", "archive_allowed_symlinks", "entry_count", "entries"},
        "Codex logical symlink manifest",
    )
    logical_entries = logical["entries"]
    if (
        logical["schema"] != "trillionnium.codex-source-logical-symlinks.v1"
        or logical["archive_allowed_symlinks"] != []
        or logical["entry_count"] != 1
        or not isinstance(logical_entries, list)
        or len(logical_entries) != logical["entry_count"]
    ):
        raise BuildError("Codex logical symlink closure drifted")
    logical_by_path: dict[str, Mapping[str, Any]] = {}
    for entry in logical_entries:
        if not isinstance(entry, dict):
            raise BuildError("Codex logical symlink entry is malformed")
        _expect_keys(
            entry,
            {
                "path",
                "target",
                "byte_length",
                "sha256",
                "git_mode",
                "git_oid",
                "materialized_in_archive_as",
                "materialized_mode",
            },
            "Codex logical symlink entry",
        )
        path_value = entry["path"]
        target = entry["target"]
        if (
            not isinstance(path_value, str)
            or PurePosixPath(path_value).is_absolute()
            or ".." in PurePosixPath(path_value).parts
            or not isinstance(target, str)
            or PurePosixPath(target).is_absolute()
            or ".." in PurePosixPath(target).parts
            or entry["materialized_in_archive_as"] != "regular"
            or entry["materialized_mode"] != "0644"
            or entry["git_mode"] != "120000"
            or entry["git_oid"]
            != _git_object_sha1("blob", target.encode("utf-8"))
            or path_value in logical_by_path
        ):
            raise BuildError("Codex logical symlink entry is unsafe or drifted")
        logical_by_path[path_value] = entry

    entries: list[dict[str, Any]] = [
        {
            "path": ".",
            "kind": "directory",
            "mode": f"{stat.S_IMODE(root.lstat().st_mode):04o}",
        }
    ]
    for path in sorted(
        root.rglob("*"),
        key=lambda value: value.relative_to(root).as_posix().encode("utf-8"),
    ):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        entry: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if stat.S_ISDIR(metadata.st_mode):
            entry["kind"] = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            content = path.read_bytes()
            logical_entry = logical_by_path.get(relative)
            git_mode = (
                logical_entry["git_mode"]
                if logical_entry is not None
                else ("100755" if metadata.st_mode & 0o111 else "100644")
            )
            entry.update(
                {
                    "kind": "regular",
                    "byte_length": len(content),
                    "sha256": _sha256_bytes(content),
                    "git_mode": git_mode,
                    "git_oid": _git_object_sha1("blob", content),
                }
            )
            if logical_entry is not None and (
                len(content) != logical_entry["byte_length"]
                or entry["sha256"] != logical_entry["sha256"]
                or content != logical_entry["target"].encode("utf-8")
            ):
                raise BuildError("Codex materialized logical symlink bytes drifted")
        else:
            raise BuildError(f"Codex source archive special file: {relative}")
        entries.append(entry)
        if len(entries) > 10_000:
            raise BuildError("Codex source inventory exceeds its fixed bound")
    encoded = json.dumps(
        entries,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if (
        member_manifest["schema"]
        != "trillionnium.codex-source-member-manifest.v1"
        or member_manifest["archive_allowed_symlinks"] != []
        or member_manifest["root_name"]
        != provider["source_identity"]["source_root_name"]
        or member_manifest["entry_count"]
        != provider["source_identity"]["source_entry_count"]
        or member_manifest["inventory_sha256"]
        != provider["source_identity"]["source_inventory_sha256"]
        or len(entries) != member_manifest["entry_count"]
        or _sha256_bytes(encoded) != member_manifest["inventory_sha256"]
        or entries != member_manifest["entries"]
    ):
        raise BuildError("Codex source archive member inventory drifted")

    for relative, entry in logical_by_path.items():
        link = root.joinpath(*PurePosixPath(relative).parts)
        target_path = link.parent.joinpath(*PurePosixPath(entry["target"]).parts)
        if (
            link.is_symlink()
            or not link.is_file()
            or target_path.is_symlink()
            or not target_path.is_file()
        ):
            raise BuildError("Codex logical symlink source/target is unsafe")
        link.unlink()
        os.symlink(entry["target"], link)
        if not link.is_symlink() or os.readlink(link) != entry["target"]:
            raise BuildError("Codex logical symlink restoration drifted")


def _verify_vendor_member_manifest(
    root: Path,
    manifest_path: Path,
    provider: Mapping[str, Any],
) -> str:
    manifest = _read_json(manifest_path, maximum=32 * 1024 * 1024)
    _expect_keys(
        manifest,
        {"schema", "root_name", "entry_count", "inventory_sha256", "entries"},
        "Codex Cargo vendor member manifest",
    )
    entries, digest = _vendor_member_inventory(root)
    if (
        manifest["schema"] != "trillionnium.cargo-vendor-member-manifest.v1"
        or manifest["root_name"] != provider["cargo_vendor"]["root_name"]
        or manifest["entry_count"] != provider["cargo_vendor"]["entry_count"]
        or manifest["inventory_sha256"]
        != provider["cargo_vendor"]["inventory_sha256"]
        or len(entries) != manifest["entry_count"]
        or digest != manifest["inventory_sha256"]
        or entries != manifest["entries"]
    ):
        raise BuildError("Codex Cargo vendor member inventory drifted")
    return digest


def _materialize_codex_vendor_cache(
    cache: Path,
    provider: Mapping[str, Any],
) -> Path:
    destination = cache / provider["cargo_vendor"]["root_name"]
    manifest = cache / provider["cargo_vendor"]["member_manifest"]["filename"]
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_dir():
            raise BuildError("Codex Cargo vendor cache root is unsafe")
        _verify_vendor_member_manifest(destination, manifest, provider)
        return destination
    archive = cache / provider["cargo_vendor"]["archive"]["filename"]
    with tempfile.TemporaryDirectory(
        prefix=".trillionnium-cargo-vendor.",
        dir=cache,
    ) as temporary:
        temporary_root = Path(temporary)
        extracted = _safe_extract_tar_archive(
            archive,
            temporary_root / "extracted",
            mode="r:",
        )
        if extracted.name != provider["cargo_vendor"]["root_name"]:
            raise BuildError("Codex Cargo vendor archive root drifted")
        _verify_vendor_member_manifest(extracted, manifest, provider)
        os.replace(extracted, destination)
    if destination.is_symlink() or not destination.is_dir():
        raise BuildError("Codex Cargo vendor cache publication drifted")
    return destination


def _read_pinned_cache_bytes(
    cache: Path, artifact: Mapping[str, Any], label: str
) -> bytes:
    path = _verify_pinned_cache_path(cache, artifact, label)
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        return _read_bounded_fd(
            descriptor,
            artifact["filename"],
            MAX_SOURCE_ARCHIVE_BYTES,
        )
    finally:
        os.close(descriptor)


def _verify_pinned_cache_path(
    cache: Path,
    artifact: Mapping[str, Any],
    label: str,
    *,
    maximum: int = MAX_SOURCE_ARCHIVE_BYTES,
) -> Path:
    path = cache / artifact["filename"]
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat(follow_symlinks=False).st_size != artifact["byte_length"]
        or _sha256_file(path, maximum) != artifact["sha256"]
    ):
        raise BuildError(f"{label} cache artifact drifted")
    return path


def _verify_source_identity_objects(
    cache: Path, provider: Mapping[str, Any], label: str
) -> None:
    tag = _read_pinned_cache_bytes(
        cache,
        provider["source_identity"]["tag_object"],
        f"{label} tag object",
    )
    commit = _read_pinned_cache_bytes(
        cache,
        provider["source_identity"]["commit_object"],
        f"{label} commit object",
    )
    _verify_source_identity_bytes(tag, commit, provider, label)


def _verify_source_identity_bytes(
    tag: bytes, commit: bytes, provider: Mapping[str, Any], label: str
) -> None:
    if (
        _git_object_sha1("tag", tag) != provider["annotated_tag_object_sha1"]
        or _git_object_sha1("commit", commit)
        != provider["dereferenced_commit_sha1"]
    ):
        raise BuildError(f"{label} retained Git object identity drifted")
    tag_lines = tag.decode("utf-8", errors="strict").splitlines()
    commit_lines = commit.decode("utf-8", errors="strict").splitlines()
    if (
        len(tag_lines) < 4
        or tag_lines[0] != f"object {provider['dereferenced_commit_sha1']}"
        or tag_lines[1] != "type commit"
        or tag_lines[2] != f"tag {provider['annotated_tag']}"
        or not commit_lines
        or commit_lines[0] != f"tree {provider['source_tree_sha1']}"
    ):
        raise BuildError(f"{label} retained tag/commit object binding drifted")


def _git_worktree_sha1(
    source: Path, metadata_root: Path, environment: Mapping[str, str]
) -> str:
    metadata_root.mkdir(parents=True, exist_ok=False)
    git_dir = metadata_root / "tree.git"
    index = metadata_root / "tree.index"
    _run(
        ["git", "init", "--bare", str(git_dir)],
        cwd=metadata_root,
        environment=environment,
    )
    git_environment = dict(environment)
    git_environment.update(
        {
            "GIT_DIR": str(git_dir),
            "GIT_WORK_TREE": str(source),
            "GIT_INDEX_FILE": str(index),
        }
    )
    _run(
        [
            "git",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.filemode=true",
            "add",
            "--all",
            "--force",
            "--",
            ".",
        ],
        cwd=source,
        environment=git_environment,
        maximum_output=512 * 1024,
    )
    return _run(
        ["git", "write-tree"],
        cwd=source,
        environment=git_environment,
    ).strip()


def _replace_exact_regular_file(
    path: Path, expected: bytes, replacement: bytes
) -> None:
    if path.is_symlink() or not path.is_file():
        raise BuildError(f"derived source input is absent or aliased: {path}")
    before = path.stat(follow_symlinks=False)
    if before.st_nlink != 1 or path.read_bytes() != expected:
        raise BuildError(f"derived source input bytes drifted: {path}")
    temporary = path.with_name(f".{path.name}.trillionnium-derived")
    _write_bytes(temporary, replacement, mode=stat.S_IMODE(before.st_mode))
    os.replace(temporary, path)
    parent_descriptor = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    if _sha256_file(path) != _sha256_bytes(replacement):
        raise BuildError(f"derived source input replacement drifted: {path}")


def _source_inventory_digest(source: Path) -> str:
    entries: list[dict[str, Any]] = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            entries.append({"path": relative, "kind": "directory", "mode": mode})
        elif stat.S_ISREG(metadata.st_mode):
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "mode": mode,
                    "byte_length": metadata.st_size,
                    "sha256": _sha256_file(
                        path,
                        MAX_SOURCE_ARCHIVE_BYTES,
                        allow_empty=True,
                    ),
                }
            )
        elif stat.S_ISLNK(metadata.st_mode):
            entries.append(
                {
                    "path": relative,
                    "kind": "symlink",
                    "mode": mode,
                    "target": os.readlink(path),
                }
            )
        else:
            raise BuildError(f"Codex source contains a special file: {relative}")
        if len(entries) > 100_000:
            raise BuildError("Codex source inventory exceeds its fixed bound")
    return _sha256_bytes(_json_bytes(entries))


def _verify_cargo_source_config(path: Path, vendor_root: Path) -> None:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise BuildError("Codex Cargo source config is malformed") from error
    if "net" in value:
        raise BuildError("Codex Cargo source config may not carry an unfrozen net table")
    sources = value.get("source")
    if not isinstance(sources, dict) or "vendored-sources" not in sources:
        raise BuildError("Codex Cargo source replacement is incomplete")
    vendored = sources["vendored-sources"]
    if vendored != {"directory": str(vendor_root)}:
        raise BuildError("Codex Cargo vendor directory binding drifted")
    for name, source in sources.items():
        if name == "vendored-sources":
            continue
        if not isinstance(source, dict) or source.get("replace-with") != (
            "vendored-sources"
        ):
            raise BuildError("Codex Cargo source is not replaced by the vendor root")


def _verify_rusty_v8_checksum_contract(
    checksums: Path,
    archive: Path,
    binding: Path,
    provider: Mapping[str, Any],
) -> None:
    expected = (
        f"{provider['rusty_v8']['archive']['sha256']}  {archive.name}\n"
        f"{provider['rusty_v8']['binding']['sha256']}  {binding.name}\n"
    ).encode("ascii")
    if checksums.read_bytes() != expected:
        raise BuildError("Codex rusty_v8 checksum pair drifted")
    digest = hashlib.sha256()
    total = 0
    try:
        with gzip.open(archive, "rb") as decompressed:
            while True:
                chunk = decompressed.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    raise BuildError("Codex rusty_v8 archive expands beyond its bound")
                digest.update(chunk)
    except (OSError, EOFError) as error:
        raise BuildError("Codex rusty_v8 archive is not one valid gzip stream") from error
    if (
        total != provider["rusty_v8"]["archive_uncompressed_byte_length"]
        or digest.hexdigest()
        != provider["rusty_v8"]["archive_uncompressed_sha256"]
    ):
        raise BuildError("Codex rusty_v8 expanded archive identity drifted")


def _verify_codex_metadata_features(
    output: str, provider: Mapping[str, Any]
) -> None:
    start = output.find('{"packages"')
    if start < 0:
        raise BuildError("Codex frozen Cargo metadata output is missing")
    try:
        metadata = json.loads(output[start:])
    except json.JSONDecodeError as error:
        raise BuildError("Codex frozen Cargo metadata output is malformed") from error
    packages = metadata.get("packages")
    nodes = metadata.get("resolve", {}).get("nodes")
    if not isinstance(packages, list) or not isinstance(nodes, list):
        raise BuildError("Codex frozen Cargo metadata resolution is absent")
    id_to_name = {
        package.get("id"): package.get("name")
        for package in packages
        if isinstance(package, dict)
        and isinstance(package.get("id"), str)
        and isinstance(package.get("name"), str)
    }
    expected = provider["rusty_v8"]["resolved_features"]
    observed: dict[str, list[str]] = {}
    for resolution in nodes:
        if not isinstance(resolution, dict):
            continue
        name = id_to_name.get(resolution.get("id"))
        if name not in expected:
            continue
        features = resolution.get("features")
        if (
            not isinstance(features, list)
            or any(not isinstance(feature, str) for feature in features)
            or name in observed
        ):
            raise BuildError("Codex Cargo feature resolution is ambiguous")
        observed[name] = sorted(features)
    if observed != expected:
        raise BuildError(
            f"Codex Cargo/V8 resolved feature closure drifted: {observed}"
        )


def _prepare_codex_source(
    source_parent: Path,
    work: Path,
    provider: Mapping[str, Any],
    environment: Mapping[str, str],
) -> tuple[Path, dict[str, Any]]:
    cache = Path("/cache")
    archive = _verify_pinned_cache_path(
        cache,
        provider["source_archive"],
        "Codex source archive",
    )
    _verify_source_identity_objects(cache, provider, "Codex")
    source_member_manifest = _verify_pinned_cache_path(
        cache,
        provider["source_identity"]["source_member_manifest"],
        "Codex source member manifest",
    )
    source_logical_symlinks = _verify_pinned_cache_path(
        cache,
        provider["source_identity"]["logical_symlinks"],
        "Codex source logical symlinks",
    )
    source = _safe_extract_tar_xz(
        archive,
        source_parent / "codex-extracted",
    )
    if source.name != provider["source_identity"]["source_root_name"]:
        raise BuildError("Codex source archive root name drifted")
    _verify_and_restore_codex_source_archive(
        source,
        source_member_manifest,
        source_logical_symlinks,
        provider,
    )
    tree = _git_worktree_sha1(
        source,
        work / "codex-source-tree-measurement",
        environment,
    )
    if tree != provider["source_tree_sha1"]:
        raise BuildError("Codex extracted source tree identity drifted")
    upstream_lock = source / provider["derived_lock"]["upstream_relative_path"]
    upstream_bytes = upstream_lock.read_bytes()
    if (
        _sha256_bytes(upstream_bytes)
        != provider["lockfiles"]["codex-rs/Cargo.lock"]
    ):
        raise BuildError("Codex upstream Cargo.lock digest drifted")
    derived, patch, names = _derive_codex_lock_bytes(
        upstream_bytes,
        provider["derived_lock"],
    )
    _verify_codex_workspace_manifests(
        source,
        names,
        provider["derived_lock"]["workspace_version"],
    )
    upstream_copy = work / "codex-upstream-Cargo.lock"
    patch_path = work / "codex-derived-Cargo.lock.patch"
    _write_bytes(upstream_copy, upstream_bytes)
    _write_bytes(patch_path, patch)
    _replace_exact_regular_file(upstream_lock, upstream_bytes, derived)

    vendor_archive = _verify_pinned_cache_path(
        cache,
        provider["cargo_vendor"]["archive"],
        "Codex Cargo vendor archive",
        maximum=MAX_DEPENDENCY_ARCHIVE_BYTES,
    )
    vendor_member_manifest = _verify_pinned_cache_path(
        cache,
        provider["cargo_vendor"]["member_manifest"],
        "Codex Cargo vendor member manifest",
    )
    vendor_root = Path("/opt/trillionnium/cargo-vendor")
    if vendor_root.name != provider["cargo_vendor"]["root_name"]:
        raise BuildError("Codex Cargo vendor mount root drifted")
    vendor_inventory = _verify_vendor_member_manifest(
        vendor_root,
        vendor_member_manifest,
        provider,
    )
    config_bytes = _read_pinned_cache_bytes(
        cache,
        provider["cargo_source_config"],
        "Codex Cargo source config",
    )
    cargo_config = work / "cargo-source-config.toml"
    _write_bytes(cargo_config, config_bytes)
    _verify_cargo_source_config(cargo_config, vendor_root)
    rusty_v8_archive = _verify_pinned_cache_path(
        cache,
        provider["rusty_v8"]["archive"],
        "Codex rusty_v8 archive",
    )
    rusty_v8_binding = _verify_pinned_cache_path(
        cache,
        provider["rusty_v8"]["binding"],
        "Codex rusty_v8 binding",
    )
    rusty_v8_checksums = _verify_pinned_cache_path(
        cache,
        provider["rusty_v8"]["checksums"],
        "Codex rusty_v8 checksums",
    )
    _verify_rusty_v8_checksum_contract(
        rusty_v8_checksums,
        rusty_v8_archive,
        rusty_v8_binding,
        provider,
    )
    inventory = _source_inventory_digest(source)
    return source, {
        "upstream_lock": upstream_copy,
        "derived_lock": upstream_lock,
        "lock_patch": patch_path,
        "workspace_package_names": names,
        "source_inventory_sha256": inventory,
        "source_archive": archive,
        "tag_object": cache
        / provider["source_identity"]["tag_object"]["filename"],
        "commit_object": cache
        / provider["source_identity"]["commit_object"]["filename"],
        "source_member_manifest": source_member_manifest,
        "source_logical_symlinks": source_logical_symlinks,
        "cargo_vendor_archive": vendor_archive,
        "cargo_vendor_member_manifest": vendor_member_manifest,
        "cargo_vendor_root": vendor_root,
        "cargo_vendor_inventory_sha256": vendor_inventory,
        "cargo_source_config": cargo_config,
        "rusty_v8_archive": rusty_v8_archive,
        "rusty_v8_binding": rusty_v8_binding,
        "rusty_v8_checksums": rusty_v8_checksums,
    }


def _prefetch(provider_name: str, cache: Path, recipe: Mapping[str, Any]) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink() or not cache.is_dir():
        raise BuildError("source cache may not be a symlink")
    provider = recipe["providers"][provider_name]
    if provider_name != "codex":
        raise BuildError("provider prefetch is outside the Codex singleton")
    required = [
            ("source archive", provider["source_archive"], MAX_SOURCE_ARCHIVE_BYTES),
            (
                "tag object",
                provider["source_identity"]["tag_object"],
                MAX_SOURCE_ARCHIVE_BYTES,
            ),
            (
                "commit object",
                provider["source_identity"]["commit_object"],
                MAX_SOURCE_ARCHIVE_BYTES,
            ),
            (
                "source member manifest",
                provider["source_identity"]["source_member_manifest"],
                MAX_SOURCE_ARCHIVE_BYTES,
            ),
            (
                "source logical symlinks",
                provider["source_identity"]["logical_symlinks"],
                MAX_SOURCE_ARCHIVE_BYTES,
            ),
            (
                "Cargo vendor archive",
                provider["cargo_vendor"]["archive"],
                MAX_DEPENDENCY_ARCHIVE_BYTES,
            ),
            (
                "Cargo vendor member manifest",
                provider["cargo_vendor"]["member_manifest"],
                MAX_SOURCE_ARCHIVE_BYTES,
            ),
            (
                "Cargo source config",
                provider["cargo_source_config"],
                MAX_SOURCE_ARCHIVE_BYTES,
            ),
    ]
    for label, artifact, maximum in required:
        path = cache / artifact["filename"]
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat(follow_symlinks=False).st_size != artifact["byte_length"]
            or _sha256_file(path, maximum) != artifact["sha256"]
            or path.stat(follow_symlinks=False).st_mode & 0o022
        ):
            raise BuildError(
                "required pinned Codex cache artifact is absent or drifted: "
                f"{label}: {path}"
            )
    _materialize_codex_vendor_cache(cache, provider)
    for name in ("archive", "binding", "checksums"):
        artifact = provider["rusty_v8"][name]
        _download_exact(
            artifact["url"],
            artifact["sha256"],
            cache / artifact["filename"],
            expected_bytes=artifact["byte_length"],
            allow_github_release_redirect=True,
        )


def _container_input_identity(
    recipe_sha256: str, builder_sha256: str, containerfile_sha256: str
) -> str:
    for label, value in (
        ("recipe", recipe_sha256),
        ("builder", builder_sha256),
        ("Containerfile", containerfile_sha256),
    ):
        _require_hex(value, 64, f"{label} SHA-256")
    return _domain_digest(
        b"org.trillionnium.provider-builder-container-inputs.v1\0",
        [
            recipe_sha256.encode("ascii"),
            builder_sha256.encode("ascii"),
            containerfile_sha256.encode("ascii"),
        ],
    )


def _validated_attempt_path(value: Path | str, label: str) -> str:
    rendered = str(value)
    pure = PurePosixPath(rendered)
    if (
        not rendered
        or not pure.is_absolute()
        or rendered != str(pure)
        or ".." in pure.parts
        or any(character in rendered for character in ("\0", "\n", "\r", ","))
        or len(os.fsencode(rendered)) > 4096
    ):
        raise BuildError(f"{label} is not one normalized absolute mount path")
    return rendered


def _build_attempt_identity(
    input_identity: str,
    provider_name: str,
    profile: str,
    output: Path | str,
    cache: Path | str,
) -> str:
    _require_hex(input_identity, 64, "container input identity")
    if provider_name not in PROVIDERS or profile not in BUILDER_PROFILES:
        raise BuildError("build attempt provider or profile is outside the closed set")
    output_value = _validated_attempt_path(output, "requested output")
    cache_value = _validated_attempt_path(cache, "cache root")
    return _domain_digest(
        b"org.trillionnium.provider-build-attempt.v2\0",
        [
            input_identity.encode("ascii"),
            provider_name.encode("ascii"),
            profile.encode("ascii"),
            output_value.encode("utf-8"),
            cache_value.encode("utf-8"),
        ],
    )


def _container_name(attempt_id: str) -> str:
    _require_hex(attempt_id, 64, "build attempt id")
    name = f"{CONTAINER_NAME_PREFIX}{attempt_id}"
    if (
        len(name.encode("ascii")) > CONTAINER_NAME_MAX_BYTES
        or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name) is None
    ):
        raise BuildError("deterministic container name is outside its closed syntax")
    return name


def _container_cidfile_custody_path(
    output: Path | str,
    attempt_id: str,
) -> Path:
    output_value = _validated_attempt_path(output, "requested output")
    _require_hex(attempt_id, 64, "build attempt id")
    name = f"{CONTAINER_CIDFILE_CUSTODY_PREFIX}{attempt_id}"
    if len(os.fsencode(name)) > 255:
        raise BuildError("deterministic cidfile custody name is too long")
    path = Path(output_value).parent / name
    _validated_attempt_path(path, "container cidfile custody path")
    return path


def _container_custody_identity_record(
    identity: tuple[int, int] | None,
) -> dict[str, int] | None:
    if identity is None:
        return None
    if (
        len(identity) != 2
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in identity
        )
    ):
        raise BuildError("container cidfile custody identity is malformed")
    return {"device": identity[0], "inode": identity[1]}


def _new_container_projection(
    *,
    input_identity: str,
    provider_name: str,
    profile: str,
    output: Path | str,
    cache: Path | str,
    image_reference: str | None,
    build_context: Mapping[str, Any],
) -> dict[str, Any]:
    output_value = _validated_attempt_path(output, "requested output")
    cache_value = _validated_attempt_path(cache, "cache root")
    attempt_id = _build_attempt_identity(
        input_identity,
        provider_name,
        profile,
        output_value,
        cache_value,
    )
    custody_path = _container_cidfile_custody_path(
        output_value,
        attempt_id,
    )
    if (
        image_reference is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", image_reference) is None
    ):
        raise BuildError("container image reference is not one immutable image ID")
    _verify_build_context_receipt(build_context)
    return {
        "attempt_id_sha256": attempt_id,
        "requested_output": output_value,
        "cache_root": cache_value,
        "name": _container_name(attempt_id),
        "id": None,
        "image_reference": image_reference,
        "build_context": json.loads(json.dumps(build_context)),
        "network": "none",
        "command": None,
        "run_invoked": False,
        "completed_zero": False,
        "cidfile": {
            "host_path": str(custody_path / CONTAINER_CIDFILE_NAME),
            "container_path": CONTAINER_CIDFILE_PATH,
            "custody_directory_path": str(custody_path),
            "custody_directory_identity": None,
            "state": "not_prepared",
            "creation_authority": "container_engine_only",
            "pre_run_absent_no_symlink": False,
            "container_id_cidfile_observed": False,
            "read_during_container_execution": False,
            "captured_after_exit_via_fixed_fd": False,
            "container_id_cross_checked": False,
            "unlinked_after_capture": False,
            "custody_directory_fsynced": False,
            "output_parent_fsynced": False,
            "cleanup_tombstone": None,
            "controller_exit_before_cleanup_preserves_cidfile": True,
        },
        "client_disconnect_does_not_imply_container_stop": True,
    }


def _copy_container_projection(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def _container_image_tag(
    recipe_sha256: str,
    builder_sha256: str,
    containerfile_sha256: str,
    profile: str,
) -> str:
    identity = _container_input_identity(
        recipe_sha256, builder_sha256, containerfile_sha256
    )
    return f"trillionnium-provider-builder:{identity[:24]}-{profile}"


def _verify_remote_base_manifest(
    engine: str, profile: str, recipe: Mapping[str, Any]
) -> None:
    builder = recipe["builder"]
    value = _run(
        [
            engine,
            "buildx",
            "imagetools",
            "inspect",
            builder["base_image"],
            "--format",
            "{{json .Manifest}}",
        ],
        cwd=DIRECTORY,
    )
    try:
        manifest = json.loads(value)
    except json.JSONDecodeError as error:
        raise BuildError(
            "container engine returned malformed OCI manifest JSON"
        ) from error
    expected_index = builder["base_image"].rsplit("@sha256:", 1)[-1]
    platform = builder["profiles"][profile]["platform"]
    os_name, architecture = platform.split("/", 1)
    candidates = [
        item
        for item in manifest.get("manifests", [])
        if item.get("platform", {}).get("os") == os_name
        and item.get("platform", {}).get("architecture") == architecture
    ]
    if (
        manifest.get("digest") != f"sha256:{expected_index}"
        or len(candidates) != 1
        or candidates[0].get("digest")
        != f"sha256:{builder['profiles'][profile]['manifest_sha256']}"
    ):
        raise BuildError(
            "remote OCI index/platform manifest differs from the frozen recipe"
        )


def _snapshot_build_context() -> dict[str, bytes]:
    snapshots: dict[str, bytes] = {}
    for logical_path in BUILD_CONTEXT_PATHS:
        path = DIRECTORY.joinpath(*PurePosixPath(logical_path).parts)
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            snapshots[logical_path] = _read_bounded_fd(
                descriptor,
                logical_path,
                MAX_ARTIFACT_BYTES,
            )
        finally:
            os.close(descriptor)
    return snapshots


def _build_context_member_payloads(
    snapshots: Mapping[str, bytes],
) -> tuple[list[str], dict[str, tuple[bytes, int]]]:
    if set(snapshots) != set(BUILD_CONTEXT_PATHS) or any(
        not isinstance(snapshots[path], bytes)
        for path in BUILD_CONTEXT_PATHS
    ):
        raise BuildError("deterministic build-context snapshot set drifted")
    members: dict[str, tuple[bytes, int]] = {
        logical_path: (
            snapshots[logical_path],
            0o555 if logical_path == "build_provider_payload.py" else 0o444,
        )
        for logical_path in BUILD_CONTEXT_PATHS
    }
    # Docker's stdin-tar mode consumes its default Dockerfile from the tar
    # itself.  The alias is byte-identical to the retained Containerfile and
    # avoids any host-path Dockerfile read.
    members["Dockerfile"] = (snapshots["Containerfile"], 0o444)
    directory_names = sorted(
        {
            str(parent)
            for name in members
            for parent in PurePosixPath(name).parents
            if str(parent) != "."
        },
        key=os.fsencode,
    )
    return directory_names, members


def _deterministic_build_context_tar(
    snapshots: Mapping[str, bytes],
) -> bytes:
    directory_names, members = _build_context_member_payloads(
        snapshots
    )
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream,
        mode="w",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for name in directory_names:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o555
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.size = 0
            archive.addfile(info)
        for name in sorted(members, key=os.fsencode):
            content, mode = members[name]
            info = tarfile.TarInfo(name)
            info.type = tarfile.REGTYPE
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    content = stream.getvalue()
    if not content or len(content) > MAX_BUILD_CONTEXT_TAR_BYTES:
        raise BuildError("deterministic build-context tar exceeds its closed bound")
    return content


def _build_context_receipt(
    snapshots: Mapping[str, bytes],
) -> dict[str, Any]:
    directory_names, members = _build_context_member_payloads(
        snapshots
    )
    tar_bytes = _deterministic_build_context_tar(snapshots)
    member_manifest = [
        *(
            {
                "path": name,
                "type": "directory",
                "mode": "0555",
                "byte_length": 0,
                "sha256": None,
            }
            for name in directory_names
        ),
        *(
            {
                "path": name,
                "type": "file",
                "mode": f"{mode:04o}",
                "byte_length": len(content),
                "sha256": _sha256_bytes(content),
            }
            for name, (content, mode) in sorted(
                members.items(),
                key=lambda item: os.fsencode(item[0]),
            )
        ),
    ]
    return {
        "schema": BUILD_CONTEXT_SCHEMA,
        "transport": "sealed_memfd_stdin_ustar",
        "context_operand": "-",
        "dockerfile_member": "Dockerfile",
        "tar_sha256": _sha256_bytes(tar_bytes),
        "tar_byte_length": len(tar_bytes),
        "member_manifest_sha256": _domain_digest(
            BUILD_CONTEXT_MEMBER_MANIFEST_DOMAIN,
            [_json_bytes(member_manifest)],
        ),
        "members": member_manifest,
        "memfd_seals": [
            "F_SEAL_SHRINK",
            "F_SEAL_GROW",
            "F_SEAL_WRITE",
            "F_SEAL_SEAL",
        ],
        "same_uid_mutable_path_context_read": False,
    }


def _verify_build_context_receipt(
    value: Any,
    *,
    snapshots: Mapping[str, bytes] | None = None,
) -> None:
    if not isinstance(value, dict):
        raise BuildError("builder context receipt is malformed")
    _expect_keys(value, EXPECTED_BUILD_CONTEXT_KEYS, "builder context receipt")
    members = value["members"]
    if not isinstance(members, list) or not members:
        raise BuildError("builder context member manifest is malformed")
    observed_paths: list[str] = []
    for member in members:
        if not isinstance(member, dict):
            raise BuildError("builder context member is malformed")
        _expect_keys(
            member,
            EXPECTED_BUILD_CONTEXT_MEMBER_KEYS,
            "builder context member",
        )
        path = member["path"]
        if (
            not isinstance(path, str)
            or not path
            or path != str(PurePosixPath(path))
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or path in observed_paths
        ):
            raise BuildError("builder context member path is unsafe or duplicated")
        observed_paths.append(path)
        if member["type"] == "directory":
            if (
                member["mode"] != "0555"
                or member["byte_length"] != 0
                or member["sha256"] is not None
            ):
                raise BuildError("builder context directory member drifted")
        elif member["type"] == "file":
            if (
                member["mode"] not in {"0444", "0555"}
                or isinstance(member["byte_length"], bool)
                or not isinstance(member["byte_length"], int)
                or member["byte_length"] <= 0
            ):
                raise BuildError("builder context file member drifted")
            _require_hex(
                member["sha256"],
                64,
                "builder context member SHA-256",
            )
        else:
            raise BuildError("builder context member type is outside the closed set")
    expected_directory_paths, expected_payloads = (
        _build_context_member_payloads(
            {
                path: b"placeholder"
                for path in BUILD_CONTEXT_PATHS
            }
        )
    )
    expected_paths = [
        *expected_directory_paths,
        *sorted(expected_payloads, key=os.fsencode),
    ]
    by_path = {member["path"]: member for member in members}
    if (
        observed_paths != expected_paths
        or any(
            by_path[name]["type"] != "directory"
            for name in expected_directory_paths
        )
        or any(
            by_path[name]["type"] != "file"
            or by_path[name]["mode"]
            != (
                "0555"
                if name == "build_provider_payload.py"
                else "0444"
            )
            for name in expected_payloads
        )
        or by_path["Dockerfile"]["sha256"]
        != by_path["Containerfile"]["sha256"]
        or by_path["Dockerfile"]["byte_length"]
        != by_path["Containerfile"]["byte_length"]
    ):
        raise BuildError("builder context closed member inventory drifted")
    if (
        value["schema"] != BUILD_CONTEXT_SCHEMA
        or value["transport"] != "sealed_memfd_stdin_ustar"
        or value["context_operand"] != "-"
        or value["dockerfile_member"] != "Dockerfile"
        or value["same_uid_mutable_path_context_read"] is not False
        or value["memfd_seals"]
        != [
            "F_SEAL_SHRINK",
            "F_SEAL_GROW",
            "F_SEAL_WRITE",
            "F_SEAL_SEAL",
        ]
        or isinstance(value["tar_byte_length"], bool)
        or not isinstance(value["tar_byte_length"], int)
        or value["tar_byte_length"] <= 0
        or value["tar_byte_length"] > MAX_BUILD_CONTEXT_TAR_BYTES
        or value["member_manifest_sha256"]
        != _domain_digest(
            BUILD_CONTEXT_MEMBER_MANIFEST_DOMAIN,
            [_json_bytes(members)],
        )
    ):
        raise BuildError("builder context transport contract drifted")
    _require_hex(value["tar_sha256"], 64, "builder context tar SHA-256")
    if snapshots is not None and value != _build_context_receipt(snapshots):
        raise BuildError("builder context receipt differs from frozen snapshot bytes")


def _verify_build_context_lifecycle_inputs(
    value: Mapping[str, Any],
    *,
    recipe_sha256: str,
    builder_sha256: str,
    containerfile_sha256: str,
) -> None:
    # Every terminal builder, failure, and reproducibility verifier reaches
    # this helper.  Rebuild the complete deterministic context from the
    # verifier's frozen closure instead of trusting a self-consistent receipt
    # that only cross-binds the three launcher lifecycle files.
    _verify_build_context_receipt(
        value,
        snapshots=_snapshot_build_context(),
    )
    expected = {
        "provider-payload-recipe-v1.json": recipe_sha256,
        "build_provider_payload.py": builder_sha256,
        "Containerfile": containerfile_sha256,
        "Dockerfile": containerfile_sha256,
    }
    observed = {
        member["path"]: member["sha256"]
        for member in value["members"]
        if member["type"] == "file"
        and member["path"] in expected
    }
    if observed != expected:
        raise BuildError(
            "builder context members differ from frozen lifecycle inputs"
        )


def _sealed_build_context_descriptor(content: bytes) -> int:
    if (
        not isinstance(content, bytes)
        or not content
        or len(content) > MAX_BUILD_CONTEXT_TAR_BYTES
        or not hasattr(os, "memfd_create")
    ):
        raise BuildError("sealed build-context input is unavailable or malformed")
    required = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_SEAL",
        "F_SEAL_SHRINK",
        "F_SEAL_GROW",
        "F_SEAL_WRITE",
    )
    if any(not hasattr(fcntl, name) for name in required):
        raise BuildError("kernel memfd sealing contract is unavailable")
    descriptor = os.memfd_create(
        "trillionnium-provider-build-context",
        flags=(
            getattr(os, "MFD_CLOEXEC", 0x0001)
            | getattr(os, "MFD_ALLOW_SEALING", 0x0002)
        ),
    )
    try:
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise BuildError("short write into sealed build-context input")
            remaining = remaining[written:]
        seals = (
            fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_SEAL
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != seals:
            raise BuildError("build-context memfd seal set drifted")
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != len(content)
        ):
            raise BuildError("sealed build-context inode length drifted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception as error:
        os.close(descriptor)
        if not test_only and isinstance(error, OSError):
            raise BuildError(
                "root-owned publication custody is unavailable; source-only HOLD"
            ) from error
        raise


def _sha256_fixed_fd_content(descriptor: int, byte_length: int) -> str:
    if (
        isinstance(byte_length, bool)
        or not isinstance(byte_length, int)
        or byte_length <= 0
        or byte_length > MAX_BUILD_CONTEXT_TAR_BYTES
    ):
        raise BuildError("fixed-FD content length is outside its closed bound")
    digest = hashlib.sha256()
    offset = 0
    while offset < byte_length:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, byte_length - offset),
            offset,
        )
        if not chunk:
            raise BuildError("fixed-FD content ended before its recorded length")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, byte_length):
        raise BuildError("fixed-FD content exceeds its recorded length")
    return digest.hexdigest()


def _build_container_image(
    engine: str,
    profile: str,
    recipe: Mapping[str, Any],
    recipe_sha256: str,
    input_snapshots: Mapping[str, bytes],
    expected_builder_sha256: str,
    expected_containerfile_sha256: str,
) -> tuple[str, str, str, str, dict[str, Any]]:
    builder = recipe["builder"]
    profile_value = builder["profiles"][profile]
    platform = profile_value["platform"]
    target_arch = platform.rsplit("/", 1)[-1]
    zig_amd64 = builder["zig_archives"]["amd64"]
    zig_arm64 = builder["zig_archives"]["arm64"]
    if set(input_snapshots) != set(BUILD_CONTEXT_PATHS):
        raise BuildError("sealed builder context snapshot set drifted")
    builder_sha256 = _sha256_bytes(
        input_snapshots["build_provider_payload.py"]
    )
    containerfile_sha256 = _sha256_bytes(
        input_snapshots["Containerfile"]
    )
    if (
        builder_sha256 != expected_builder_sha256
        or containerfile_sha256 != expected_containerfile_sha256
        or _sha256_bytes(
            input_snapshots["provider-payload-recipe-v1.json"]
        )
        != recipe_sha256
    ):
        raise BuildError("sealed builder context identity drifted")
    build_context_tar = _deterministic_build_context_tar(
        input_snapshots
    )
    build_context_record = _build_context_receipt(input_snapshots)
    _verify_build_context_receipt(
        build_context_record,
        snapshots=input_snapshots,
    )
    build_context_tar_sha256 = build_context_record["tar_sha256"]
    tag = _container_image_tag(
        recipe_sha256,
        builder_sha256,
        containerfile_sha256,
        profile,
    )
    _verify_remote_base_manifest(engine, profile, recipe)
    arguments = [
        engine,
        "build",
        "--pull",
        "--no-cache",
        "--quiet",
        "--network",
        builder["image_build_network"],
        "--platform",
        platform,
        "--tag",
        tag,
        "--build-arg",
        f"BASE_IMAGE={builder['base_image']}",
        "--build-arg",
        f"DEBIAN_SNAPSHOT={builder['debian_snapshot']}",
        "--build-arg",
        f"ZIG_AMD64_URL={zig_amd64['url']}",
        "--build-arg",
        f"ZIG_AMD64_SHA256={zig_amd64['sha256']}",
        "--build-arg",
        f"ZIG_ARM64_URL={zig_arm64['url']}",
        "--build-arg",
        f"ZIG_ARM64_SHA256={zig_arm64['sha256']}",
        "-",
    ]
    context_descriptor = _sealed_build_context_descriptor(
        build_context_tar
    )
    try:
        context_before = os.fstat(context_descriptor)
        build_output = _run(
            arguments,
            cwd=DIRECTORY,
            maximum_output=512 * 1024,
            require_complete_output=True,
            stdin_descriptor=context_descriptor,
        )
        if re.fullmatch(r"sha256:[0-9a-f]{64}\n?", build_output) is None:
            raise BuildError(
                "Docker build did not return exactly one immutable image ID"
            )
        produced_image_id = build_output.removesuffix("\n")
        context_after = os.fstat(context_descriptor)
        required_seals = (
            fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_SEAL
        )
        # A rejected write to a sealed memfd can still advance its timestamps
        # on Linux.  Object identity, shape, seals, and the complete byte
        # digest are the security invariants; timestamps are not content
        # authority.
        if (
            _fd_identity(context_before)[:7]
            != _fd_identity(context_after)[:7]
            or context_after.st_size != len(build_context_tar)
            or fcntl.fcntl(
                context_descriptor,
                fcntl.F_GET_SEALS,
            )
            != required_seals
            or _sha256_fixed_fd_content(
                context_descriptor,
                len(build_context_tar),
            )
            != build_context_tar_sha256
        ):
            raise BuildError("sealed builder context changed during Docker build")
    finally:
        os.close(context_descriptor)
    observed_tag_image_id = _run(
        [engine, "image", "inspect", "--format", "{{.Id}}", tag],
        cwd=DIRECTORY,
    ).strip()
    if (
        re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            observed_tag_image_id,
        )
        is None
        or observed_tag_image_id != produced_image_id
    ):
        raise BuildError(
            "mutable builder tag no longer names the produced immutable image ID"
        )
    if target_arch not in {"amd64", "arm64"}:
        raise BuildError("unsupported frozen builder target architecture")
    return (
        tag,
        produced_image_id,
        builder_sha256,
        containerfile_sha256,
        build_context_record,
    )


def _failure_receipt_hash(receipt: Mapping[str, Any]) -> str:
    unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    }
    return _domain_digest(FAILURE_DIGEST_DOMAIN, [_json_bytes(unsigned)])


@contextmanager
def _scandir_fd(directory_descriptor: int) -> Iterable[Any]:
    """Iterate one borrowed directory FD without duplicating or closing it.

    ``os.scandir`` does not take ownership of an integer path argument.  A
    bare ``os.scandir(os.dup(fd))`` therefore leaks one descriptor per scan,
    which is fatal for recursive cleanup and evidence-tree verification under
    a bounded RLIMIT_NOFILE.  Reusing the caller-owned descriptor keeps it
    alive for later ``DirEntry.stat`` calls without creating a descriptor that
    this context would have to retain past iteration.
    """

    with os.scandir(directory_descriptor) as iterator:
        yield iterator


def _fsync_tree_fd(root_descriptor: int) -> None:
    root_before = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_before.st_mode):
        raise BuildError("publication root descriptor is not a directory")

    with _scandir_fd(root_descriptor) as iterator:
        entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
    for entry in entries:
        before = entry.stat(follow_symlinks=False)
        if stat.S_ISREG(before.st_mode):
            if before.st_nlink != 1:
                raise BuildError("publication tree contains a multiply-linked file")
            descriptor = os.open(
                entry.name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | os.O_NONBLOCK,
                dir_fd=root_descriptor,
            )
            try:
                if _fd_identity(before) != _fd_identity(os.fstat(descriptor)):
                    raise BuildError(
                        "publication file identity changed before fsync"
                    )
                os.fsync(descriptor)
                if _fd_identity(before) != _fd_identity(os.fstat(descriptor)):
                    raise BuildError(
                        "publication file identity changed during fsync"
                    )
            finally:
                os.close(descriptor)
        elif stat.S_ISDIR(before.st_mode):
            descriptor = os.open(
                entry.name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=root_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if _fd_identity(before) != _fd_identity(opened):
                    raise BuildError(
                        "publication directory identity changed before fsync"
                    )
                _fsync_tree_fd(descriptor)
                after = os.fstat(descriptor)
                if _fd_identity(opened) != _fd_identity(after):
                    raise BuildError(
                        "publication directory identity changed during fsync"
                    )
            finally:
                os.close(descriptor)
        else:
            raise BuildError("publication tree contains a special or aliased entry")
    os.fsync(root_descriptor)
    root_after = os.fstat(root_descriptor)
    if _fd_identity(root_before) != _fd_identity(root_after):
        raise BuildError("publication root identity changed during fsync")


def _renameat2_noreplace(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    for label, name in (
        ("source", source_name),
        ("destination", destination_name),
    ):
        if (
            not name
            or name != PurePosixPath(name).name
            or "\0" in name
        ):
            raise BuildError(f"unsafe publication {label} name")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise BuildError("renameat2 no-replace publication is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        source_name.encode("utf-8"),
        parent_descriptor,
        destination_name.encode("utf-8"),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise BuildError(
            "atomic no-replace publication failed: "
            f"{os.strerror(error_number)}"
        )


def _rename_publication_journal_noreplace(
    custody_descriptor: int,
    source_name: str,
    archive_name: str,
    _rename: Any = _renameat2_noreplace,
) -> None:
    # Keep the custody transition distinct from the artifact rename boundary.
    # Tests fault-inject those two barriers independently.
    _rename(
        custody_descriptor,
        source_name,
        archive_name,
    )


def _publication_target_key(
    parent_identity: os.stat_result,
    output: Path,
) -> str:
    output_name = output.name
    if (
        not output_name
        or output_name != PurePosixPath(output_name).name
        or "\0" in output_name
        or len(output_name.encode("utf-8")) > 160
    ):
        raise BuildError("publication output name cannot bind a durable journal")
    binding = {
        "parent_device": parent_identity.st_dev,
        "parent_inode": parent_identity.st_ino,
        "canonical_output_path": str(
            output.parent.resolve(strict=True) / output_name
        ),
        "output_name": output_name,
    }
    return hashlib.sha256(
        b"org.trillionnium.provider-publication-target.v1\0"
        + _json_bytes(binding)
    ).hexdigest()


def _publication_journal_names(target_key: str) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{64}", target_key):
        raise BuildError("publication target key is malformed")
    return (
        f"{target_key}.active-intent-v1.json",
        f"{target_key}.active-rename-attempted-v1.json",
    )


def _publication_lock_name(target_key: str) -> str:
    _publication_journal_names(target_key)
    return f"{target_key}.publication-lock-v1"


def _publication_resolved_name(
    target_key: str,
    operation_id: str,
) -> str:
    _publication_journal_names(target_key)
    if not re.fullmatch(r"[0-9a-f]{64}", operation_id):
        raise BuildError("publication operation ID cannot name resolved custody")
    return f"{target_key}.{operation_id}.resolved-v1.json"


def _publication_archive_names(
    target_key: str,
    operation_id: str,
) -> tuple[str, str]:
    _publication_resolved_name(target_key, operation_id)
    return (
        f"{target_key}.{operation_id}.archived-intent-v1.json",
        f"{target_key}.{operation_id}.archived-rename-attempted-v1.json",
    )


def _open_publication_custody_fd() -> tuple[int, Path, bool]:
    test_only = PUBLICATION_TEST_ONLY_CUSTODY_DIRECTORY is not None
    path = (
        PUBLICATION_TEST_ONLY_CUSTODY_DIRECTORY
        if test_only
        else PUBLICATION_CUSTODY_ROOT
    )
    if path is None:
        raise BuildError("publication custody selection is unavailable")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute != path or not absolute.is_absolute() or ".." in absolute.parts:
        raise BuildError("publication custody path is not canonical and absolute")
    if test_only and not absolute.exists():
        absolute.mkdir(mode=0o700)
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
    )
    descriptor = os.open(absolute.anchor, flags)
    try:
        if not test_only:
            anchor_metadata = os.fstat(descriptor)
            if (
                anchor_metadata.st_uid != 0
                or anchor_metadata.st_gid != 0
                or stat.S_IMODE(anchor_metadata.st_mode) & 0o022
            ):
                raise BuildError(
                    "publication custody ancestor is not root-owned and immutable "
                    "to non-root; source-only HOLD"
                )
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            if not test_only:
                component_metadata = os.fstat(descriptor)
                if (
                    component_metadata.st_uid != 0
                    or component_metadata.st_gid != 0
                    or stat.S_IMODE(component_metadata.st_mode) & 0o022
                ):
                    raise BuildError(
                        "publication custody ancestor is not root-owned and immutable "
                        "to non-root; source-only HOLD"
                    )
        metadata = os.fstat(descriptor)
        expected_uid = os.geteuid() if test_only else 0
        expected_gid = os.getegid() if test_only else 0
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
        ):
            raise BuildError(
                "publication custody is not the exact root-owned 0700 authority; "
                "source-only HOLD"
            )
        if not test_only and os.geteuid() != 0:
            raise BuildError(
                "root-owned publication custody cannot be mutated by this builder; "
                "source-only HOLD"
            )
        return descriptor, absolute, test_only
    except Exception as error:
        os.close(descriptor)
        if not test_only and isinstance(error, OSError):
            raise BuildError(
                "root-owned publication custody is unavailable; source-only HOLD"
            ) from error
        raise


def _require_publication_custody_identity_fd(
    custody_path: Path,
    custody_descriptor: int,
    *,
    test_only: bool,
) -> None:
    rebound, rebound_path, rebound_test_only = _open_publication_custody_fd()
    try:
        if rebound_path != custody_path or rebound_test_only != test_only:
            raise BuildError("publication custody selection changed")
        expected = os.fstat(custody_descriptor)
        observed = os.fstat(rebound)
        if (
            expected.st_dev,
            expected.st_ino,
            stat.S_IFMT(expected.st_mode),
        ) != (
            observed.st_dev,
            observed.st_ino,
            stat.S_IFMT(observed.st_mode),
        ):
            raise BuildError("publication custody path was rebound")
    finally:
        os.close(rebound)


def _require_publication_lock_identity_fd(
    custody_descriptor: int,
    lock_name: str,
    lock_descriptor: int,
    expected_identity: tuple[int, ...],
) -> None:
    opened = os.fstat(lock_descriptor)
    try:
        named = os.stat(
            lock_name,
            dir_fd=custody_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise BuildError("publication single-flight lock name was detached") from error
    if (
        _fd_identity(opened) != expected_identity
        or _fd_identity(named) != expected_identity
        or not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or opened.st_uid != os.geteuid()
        or opened.st_size != 0
    ):
        raise BuildError("publication single-flight lock identity drifted")


def _acquire_publication_lock_fd(
    custody_descriptor: int,
    target_key: str,
) -> tuple[int, str, tuple[int, ...]]:
    lock_name = _publication_lock_name(target_key)
    flags = (
        os.O_RDWR
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    created = False
    try:
        descriptor = os.open(
            lock_name,
            flags | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=custody_descriptor,
        )
        created = True
    except FileExistsError:
        descriptor = os.open(lock_name, flags, dir_fd=custody_descriptor)
    try:
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(custody_descriptor)
        metadata = os.fstat(descriptor)
        identity = _fd_identity(metadata)
        _require_publication_lock_identity_fd(
            custody_descriptor,
            lock_name,
            descriptor,
            identity,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BuildError(
                "publication output already has an active single-flight operation"
            ) from error
        _require_publication_lock_identity_fd(
            custody_descriptor,
            lock_name,
            descriptor,
            identity,
        )
        return descriptor, lock_name, identity
    except Exception:
        os.close(descriptor)
        raise


def _publication_tree_seal_fd(root_descriptor: int) -> dict[str, Any]:
    root = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root.st_mode):
        raise BuildError("publication tree seal root is not a directory")
    member_count = 0
    regular_bytes = 0
    digest = hashlib.sha256()
    digest.update(b"org.trillionnium.provider-publication-tree-seal.v1\0")

    def record(value: Mapping[str, Any]) -> None:
        nonlocal member_count
        member_count += 1
        if member_count > PUBLICATION_TREE_SEAL_MAX_MEMBERS:
            raise BuildError("publication tree seal member count exceeds its bound")
        digest.update(_json_bytes(dict(value)))

    record(
        {
            "kind": "directory",
            "path": ".",
            "mode": stat.S_IMODE(root.st_mode),
            "uid": root.st_uid,
            "gid": root.st_gid,
        }
    )

    def walk(directory_descriptor: int, prefix: str) -> None:
        nonlocal regular_bytes
        before_directory = os.fstat(directory_descriptor)
        with _scandir_fd(directory_descriptor) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            if (
                not entry.name
                or entry.name in {".", ".."}
                or "/" in entry.name
                or "\0" in entry.name
            ):
                raise BuildError("publication tree seal encountered an unsafe name")
            logical = f"{prefix}/{entry.name}" if prefix else entry.name
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                descriptor = os.open(
                    entry.name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=directory_descriptor,
                )
                try:
                    opened = os.fstat(descriptor)
                    if _fd_identity(opened) != _fd_identity(metadata):
                        raise BuildError(
                            "publication directory changed while sealing"
                        )
                    record(
                        {
                            "kind": "directory",
                            "path": logical,
                            "mode": stat.S_IMODE(opened.st_mode),
                            "uid": opened.st_uid,
                            "gid": opened.st_gid,
                        }
                    )
                    walk(descriptor, logical)
                    if _fd_identity(os.fstat(descriptor)) != _fd_identity(opened):
                        raise BuildError(
                            "publication directory changed during sealing"
                        )
                finally:
                    os.close(descriptor)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise BuildError(
                    "publication tree seal rejects aliased or special entries"
                )
            if metadata.st_size < 0 or metadata.st_size > MAX_ARTIFACT_BYTES:
                raise BuildError("publication tree member exceeds its byte bound")
            descriptor = os.open(
                entry.name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | os.O_NONBLOCK,
                dir_fd=directory_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if _fd_identity(opened) != _fd_identity(metadata):
                    raise BuildError("publication file changed while sealing")
                file_digest = hashlib.sha256()
                offset = 0
                while offset < opened.st_size:
                    chunk = os.pread(
                        descriptor,
                        min(1024 * 1024, opened.st_size - offset),
                        offset,
                    )
                    if not chunk:
                        raise BuildError(
                            "publication file ended before its sealed length"
                        )
                    file_digest.update(chunk)
                    offset += len(chunk)
                if os.pread(descriptor, 1, opened.st_size):
                    raise BuildError("publication file grew while sealing")
                if _fd_identity(os.fstat(descriptor)) != _fd_identity(opened):
                    raise BuildError("publication file changed during sealing")
                regular_bytes += opened.st_size
                if regular_bytes > PUBLICATION_TREE_SEAL_MAX_REGULAR_BYTES:
                    raise BuildError(
                        "publication tree regular bytes exceed their bound"
                    )
                record(
                    {
                        "kind": "file",
                        "path": logical,
                        "mode": stat.S_IMODE(opened.st_mode),
                        "uid": opened.st_uid,
                        "gid": opened.st_gid,
                        "bytes": opened.st_size,
                        "sha256": file_digest.hexdigest(),
                    }
                )
            finally:
                os.close(descriptor)
        if _fd_identity(os.fstat(directory_descriptor)) != _fd_identity(
            before_directory
        ):
            raise BuildError("publication directory changed while sealing children")

    walk(root_descriptor, "")
    if _fd_identity(os.fstat(root_descriptor)) != _fd_identity(root):
        raise BuildError("publication root changed during tree sealing")
    return {
        "schema": PUBLICATION_TREE_SEAL_SCHEMA,
        "member_count": member_count,
        "regular_bytes": regular_bytes,
        "root_mode": stat.S_IMODE(root.st_mode),
        "root_uid": root.st_uid,
        "root_gid": root.st_gid,
        "sha256": digest.hexdigest(),
    }


def _publication_candidate_digest(tree_seal: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        PUBLICATION_CANDIDATE_DIGEST_DOMAIN + _json_bytes(dict(tree_seal))
    ).hexdigest()


def _publication_operation_id(
    *,
    parent_identity: os.stat_result,
    stage_name: str,
    output_name: str,
    stage_identity: os.stat_result,
    candidate_digest: str,
    target_key: str,
) -> str:
    binding = {
        "parent_device": parent_identity.st_dev,
        "parent_inode": parent_identity.st_ino,
        "stage_name": stage_name,
        "output_name": output_name,
        "stage_device": stage_identity.st_dev,
        "stage_inode": stage_identity.st_ino,
        "candidate_digest": candidate_digest,
        "target_key": target_key,
    }
    return hashlib.sha256(
        PUBLICATION_OPERATION_ID_DOMAIN + _json_bytes(binding)
    ).hexdigest()


def _publication_journal_payload(
    *,
    state: str,
    target_key: str,
    parent_identity: os.stat_result,
    stage_name: str,
    output_name: str,
    stage_identity: os.stat_result,
    tree_seal: Mapping[str, Any],
    candidate_digest: str,
    operation_id: str,
) -> dict[str, Any]:
    if state not in {"intent", "rename_attempted"}:
        raise BuildError("publication journal state is not closed")
    if not re.fullmatch(r"[0-9a-f]{64}", target_key):
        raise BuildError("publication journal target key is malformed")
    return {
        "schema": PUBLICATION_JOURNAL_SCHEMA,
        "state": state,
        "target_key": target_key,
        "parent_device": parent_identity.st_dev,
        "parent_inode": parent_identity.st_ino,
        "stage_name": stage_name,
        "output_name": output_name,
        "stage_device": stage_identity.st_dev,
        "stage_inode": stage_identity.st_ino,
        "canonical_tree_seal": dict(tree_seal),
        "candidate_digest": candidate_digest,
        "operation_id": operation_id,
        "product_active": False,
        "admission_wired": False,
        "confers_effect_authority": False,
    }


def _publication_resolved_payload(
    attempted_payload: Mapping[str, Any],
    *,
    outcome: str,
) -> dict[str, Any]:
    if outcome not in {"committed", "aborted"}:
        raise BuildError("publication resolution outcome is not closed")
    if attempted_payload.get("state") != "rename_attempted":
        raise BuildError("publication resolution lacks rename-attempted custody")
    resolved = dict(attempted_payload)
    resolved["state"] = "resolved"
    resolved["outcome"] = outcome
    return resolved


def _publication_journal_identity(metadata: os.stat_result) -> tuple[int, ...]:
    # A no-replace rename legitimately changes ctime.  The retained journal
    # identity therefore binds every stable inode/content attribute but not
    # ctime; canonical bytes are re-read before every state transition.
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _create_publication_journal_fd(
    custody_descriptor: int,
    name: str,
    payload: Mapping[str, Any],
) -> tuple[int, ...]:
    content = _json_bytes(dict(payload))
    if len(content) > PUBLICATION_JOURNAL_MAX_BYTES:
        raise BuildError("publication journal exceeds its fixed byte bound")
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | os.O_NOFOLLOW,
        0o400,
        dir_fd=custody_descriptor,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BuildError("short write while creating publication journal")
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size != len(content)
            or metadata.st_uid != os.geteuid()
        ):
            raise BuildError("publication journal inode contract drifted")
        named = os.stat(name, dir_fd=custody_descriptor, follow_symlinks=False)
        if _publication_journal_identity(named) != _publication_journal_identity(
            metadata
        ):
            raise BuildError("publication journal name changed during creation")
        os.fsync(custody_descriptor)
        return _publication_journal_identity(metadata)
    finally:
        os.close(descriptor)


def _read_publication_journal_fd(
    custody_descriptor: int,
    name: str,
) -> tuple[dict[str, Any], tuple[int, ...]]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=custody_descriptor,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_size <= 0
            or metadata.st_size > PUBLICATION_JOURNAL_MAX_BYTES
        ):
            raise BuildError("durable publication journal inode is unsafe")
        content = _read_bounded_fd(
            descriptor,
            name,
            PUBLICATION_JOURNAL_MAX_BYTES,
        )
        try:
            value = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BuildError("durable publication journal is malformed") from error
        if not isinstance(value, dict) or _json_bytes(value) != content:
            raise BuildError("durable publication journal is noncanonical")
        named = os.stat(name, dir_fd=custody_descriptor, follow_symlinks=False)
        if _publication_journal_identity(named) != _publication_journal_identity(
            metadata
        ):
            raise BuildError("durable publication journal name changed while reading")
        return value, _publication_journal_identity(metadata)
    finally:
        os.close(descriptor)


def _require_publication_journal_name_identity_fd(
    custody_descriptor: int,
    name: str,
    expected_identity: tuple[int, ...],
) -> None:
    try:
        observed = os.stat(
            name,
            dir_fd=custody_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise BuildError(
            "publication journal name was detached; permanent HOLD"
        ) from error
    if _publication_journal_identity(observed) != expected_identity:
        raise BuildError("publication journal name identity changed")


def _archive_publication_journal_exact_fd(
    custody_descriptor: int,
    source_name: str,
    archive_name: str,
    expected_identity: tuple[int, ...],
) -> tuple[int, ...]:
    _require_publication_journal_name_identity_fd(
        custody_descriptor,
        source_name,
        expected_identity,
    )
    try:
        _rename_publication_journal_noreplace(
            custody_descriptor,
            source_name,
            archive_name,
        )
    except Exception as error:
        source_matches = False
        archive_matches = False
        try:
            _require_publication_journal_name_identity_fd(
                custody_descriptor,
                source_name,
                expected_identity,
            )
            source_matches = True
        except (FileNotFoundError, BuildError):
            pass
        try:
            _require_publication_journal_name_identity_fd(
                custody_descriptor,
                archive_name,
                expected_identity,
            )
            archive_matches = True
        except (FileNotFoundError, BuildError):
            pass
        if archive_matches and not source_matches:
            os.fsync(custody_descriptor)
            return expected_identity
        raise BuildError(
            "publication journal archive result is commit-unknown; permanent HOLD"
        ) from error
    _require_publication_journal_name_identity_fd(
        custody_descriptor,
        archive_name,
        expected_identity,
    )
    try:
        os.stat(source_name, dir_fd=custody_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise BuildError("publication journal remained live after archive")
    os.fsync(custody_descriptor)
    return expected_identity


def _scan_publication_custody_records_fd(
    custody_descriptor: int,
    target_key: str,
    output_name: str,
) -> dict[str, tuple[dict[str, Any], tuple[int, ...]]]:
    records: dict[str, tuple[dict[str, Any], tuple[int, ...]]] = {}
    for name in sorted(os.listdir(custody_descriptor), key=os.fsencode):
        if not name.endswith(".json"):
            continue
        value, identity = _read_publication_journal_fd(
            custody_descriptor,
            name,
        )
        if value.get("schema") != PUBLICATION_JOURNAL_SCHEMA:
            raise BuildError(
                "publication custody contains an unknown record schema; "
                "permanent HOLD"
            )
        if value.get("target_key") != target_key:
            continue
        if value.get("output_name") != output_name:
            raise BuildError(
                "publication custody target binding drifted; permanent HOLD"
            )
        records[name] = (value, identity)
    return records


def _named_directory_matches_fd(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
) -> bool:
    try:
        observed = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(observed.st_mode) and (
        observed.st_dev,
        observed.st_ino,
    ) == (expected.st_dev, expected.st_ino)


def _publish_directory_noreplace(
    stage: Path,
    output: Path,
    expected_stage_identity: tuple[int, int],
    verifier: Any | None = None,
) -> None:
    if stage.parent.resolve(strict=True) != output.parent.resolve(strict=True):
        raise BuildError("publication stage and output do not share one parent")
    parent_descriptor = os.open(
        output.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    parent_identity = os.fstat(parent_descriptor)
    custody_descriptor = -1
    custody_path = PUBLICATION_CUSTODY_ROOT
    custody_test_only = False
    lock_descriptor = -1
    lock_name = ""
    lock_identity: tuple[int, ...] | None = None

    def require_parent_path_identity() -> None:
        try:
            observed = os.stat(output.parent, follow_symlinks=False)
        except OSError as error:
            raise BuildError("publication parent path is no longer reachable") from error
        if (
            not stat.S_ISDIR(parent_identity.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or (parent_identity.st_dev, parent_identity.st_ino)
            != (observed.st_dev, observed.st_ino)
        ):
            raise BuildError("publication parent path was rebound")

    stage_descriptor = -1
    destination_installed = False
    parent_fsync_completed = False
    target_key = _publication_target_key(parent_identity, output)
    intent_name, attempted_name = _publication_journal_names(target_key)
    intent_identity: tuple[int, ...] | None = None
    attempted_identity: tuple[int, ...] | None = None
    resolved_identity: tuple[int, ...] | None = None
    resolved_name = ""
    archive_intent_name = ""
    archive_attempted_name = ""
    expected_intent: dict[str, Any] | None = None
    expected_attempted: dict[str, Any] | None = None

    def entry_exists(name: str) -> bool:
        try:
            os.stat(name, dir_fd=custody_descriptor, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def require_custody_and_lock() -> None:
        _require_publication_custody_identity_fd(
            custody_path,
            custody_descriptor,
            test_only=custody_test_only,
        )
        _require_publication_lock_identity_fd(
            custody_descriptor,
            lock_name,
            lock_descriptor,
            lock_identity,
        )

    def resolve_and_archive(outcome: str) -> None:
        nonlocal intent_identity, attempted_identity, resolved_identity
        if expected_attempted is None or not resolved_name:
            raise BuildError("publication resolution was requested before admission")
        resolved_payload = _publication_resolved_payload(
            expected_attempted,
            outcome=outcome,
        )
        require_custody_and_lock()
        if resolved_identity is None:
            if entry_exists(resolved_name):
                observed, resolved_identity = _read_publication_journal_fd(
                    custody_descriptor,
                    resolved_name,
                )
                if observed != resolved_payload:
                    raise BuildError(
                        "publication resolved archive conflicts with this operation; "
                        "permanent HOLD"
                    )
            else:
                resolved_identity = _create_publication_journal_fd(
                    custody_descriptor,
                    resolved_name,
                    resolved_payload,
                )
        _require_publication_journal_name_identity_fd(
            custody_descriptor,
            resolved_name,
            resolved_identity,
        )
        os.fsync(custody_descriptor)
        if attempted_identity is not None:
            _archive_publication_journal_exact_fd(
                custody_descriptor,
                attempted_name,
                archive_attempted_name,
                attempted_identity,
            )
            attempted_identity = None
        if intent_identity is not None:
            _archive_publication_journal_exact_fd(
                custody_descriptor,
                intent_name,
                archive_intent_name,
                intent_identity,
            )
            intent_identity = None
        require_custody_and_lock()

    try:
        require_parent_path_identity()
        (
            custody_descriptor,
            custody_path,
            custody_test_only,
        ) = _open_publication_custody_fd()
        _require_publication_custody_identity_fd(
            custody_path,
            custody_descriptor,
            test_only=custody_test_only,
        )
        lock_descriptor, lock_name, lock_identity = (
            _acquire_publication_lock_fd(custody_descriptor, target_key)
        )
        require_parent_path_identity()
        try:
            stage_descriptor = os.open(
                stage.name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            stage_descriptor = os.open(
                output.name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
        stage_identity = os.fstat(stage_descriptor)
        if (
            not stat.S_ISDIR(stage_identity.st_mode)
            or (stage_identity.st_dev, stage_identity.st_ino)
            != expected_stage_identity
        ):
            raise BuildError("publication stage identity is not pinned")
        source_is_stage = _named_directory_matches_fd(
            parent_descriptor,
            stage.name,
            stage_identity,
        )
        destination_is_stage = _named_directory_matches_fd(
            parent_descriptor,
            output.name,
            stage_identity,
        )
        if source_is_stage == destination_is_stage:
            raise BuildError(
                "publication candidate is not retained under exactly one fixed name"
            )
        destination_installed = destination_is_stage
        _fsync_tree_fd(stage_descriptor)
        require_parent_path_identity()
        require_custody_and_lock()
        if verifier is not None:
            verifier(stage_descriptor)
        require_parent_path_identity()
        source_is_stage = _named_directory_matches_fd(
            parent_descriptor,
            stage.name,
            stage_identity,
        )
        destination_is_stage = _named_directory_matches_fd(
            parent_descriptor,
            output.name,
            stage_identity,
        )
        if source_is_stage == destination_is_stage:
            raise BuildError(
                "publication candidate name changed before journal admission"
            )
        tree_seal = _publication_tree_seal_fd(stage_descriptor)
        candidate_digest = _publication_candidate_digest(tree_seal)
        operation_id = _publication_operation_id(
            parent_identity=parent_identity,
            stage_name=stage.name,
            output_name=output.name,
            stage_identity=stage_identity,
            candidate_digest=candidate_digest,
            target_key=target_key,
        )

        expected_intent = _publication_journal_payload(
            state="intent",
            target_key=target_key,
            parent_identity=parent_identity,
            stage_name=stage.name,
            output_name=output.name,
            stage_identity=stage_identity,
            tree_seal=tree_seal,
            candidate_digest=candidate_digest,
            operation_id=operation_id,
        )
        expected_attempted = _publication_journal_payload(
            state="rename_attempted",
            target_key=target_key,
            parent_identity=parent_identity,
            stage_name=stage.name,
            output_name=output.name,
            stage_identity=stage_identity,
            tree_seal=tree_seal,
            candidate_digest=candidate_digest,
            operation_id=operation_id,
        )
        resolved_name = _publication_resolved_name(target_key, operation_id)
        archive_intent_name, archive_attempted_name = (
            _publication_archive_names(target_key, operation_id)
        )
        expected_resolved_committed = _publication_resolved_payload(
            expected_attempted,
            outcome="committed",
        )
        expected_resolved_aborted = _publication_resolved_payload(
            expected_attempted,
            outcome="aborted",
        )
        records = _scan_publication_custody_records_fd(
            custody_descriptor,
            target_key,
            output.name,
        )
        allowed_names = {
            intent_name,
            attempted_name,
            resolved_name,
            archive_intent_name,
            archive_attempted_name,
        }
        unexpected_names = set(records) - allowed_names
        if unexpected_names:
            raise BuildError(
                "publication custody contains another or rebound operation; "
                "permanent HOLD"
            )

        if intent_name in records:
            intent_value, intent_identity = records[intent_name]
            if intent_value != expected_intent:
                raise BuildError(
                    "durable publication intent belongs to another operation; "
                    "permanent HOLD"
                )
        if attempted_name in records:
            attempted_value, attempted_identity = records[attempted_name]
            if attempted_value != expected_attempted:
                raise BuildError(
                    "durable publication attempt belongs to another operation; "
                    "permanent HOLD"
                )
        if attempted_identity is not None and intent_identity is None:
            raise BuildError(
                "durable publication rename-attempted state lacks its intent; "
                "permanent HOLD"
            )
        if archive_intent_name in records:
            archive_intent, _ = records[archive_intent_name]
            if archive_intent != expected_intent:
                raise BuildError(
                    "archived publication intent belongs to another operation; "
                    "permanent HOLD"
                )
        if archive_attempted_name in records:
            archive_attempted, _ = records[archive_attempted_name]
            if archive_attempted != expected_attempted:
                raise BuildError(
                    "archived publication attempt belongs to another operation; "
                    "permanent HOLD"
                )
        resolved_outcome: str | None = None
        if resolved_name in records:
            resolved_value, resolved_identity = records[resolved_name]
            if resolved_value == expected_resolved_committed:
                resolved_outcome = "committed"
            elif resolved_value == expected_resolved_aborted:
                resolved_outcome = "aborted"
            else:
                raise BuildError(
                    "publication resolved archive conflicts with this operation; "
                    "permanent HOLD"
                )
        elif archive_intent_name in records or archive_attempted_name in records:
            raise BuildError(
                "publication active state was archived without a resolved record; "
                "permanent HOLD"
            )
        if resolved_outcome == "aborted":
            raise BuildError(
                "publication operation was durably resolved aborted; permanent HOLD"
            )

        if records:
            source_is_stage = _named_directory_matches_fd(
                parent_descriptor,
                stage.name,
                stage_identity,
            )
            destination_is_stage = _named_directory_matches_fd(
                parent_descriptor,
                output.name,
                stage_identity,
            )
            if source_is_stage and not destination_is_stage:
                destination_installed = False
            elif destination_is_stage and not source_is_stage:
                destination_installed = True
            else:
                raise PublicationFailure(
                    "durable publication custody cannot reconcile the pinned stage "
                    "under exactly one fixed name; permanent HOLD",
                    destination_installed=destination_is_stage,
                    destination_identity_preserved=destination_is_stage,
                    parent_fsync_completed=False,
                )
            if resolved_outcome == "committed" and not destination_installed:
                raise BuildError(
                    "resolved committed publication lost its exact output; "
                    "permanent HOLD"
                )

        if not destination_installed:
            if intent_identity is None:
                intent_identity = _create_publication_journal_fd(
                    custody_descriptor,
                    intent_name,
                    expected_intent,
                )
            if attempted_identity is None:
                attempted_identity = _create_publication_journal_fd(
                    custody_descriptor,
                    attempted_name,
                    expected_attempted,
                )
            require_parent_path_identity()
            require_custody_and_lock()
            _require_publication_journal_name_identity_fd(
                custody_descriptor,
                intent_name,
                intent_identity,
            )
            _require_publication_journal_name_identity_fd(
                custody_descriptor,
                attempted_name,
                attempted_identity,
            )
            if _publication_tree_seal_fd(stage_descriptor) != tree_seal:
                raise BuildError(
                    "publication candidate changed after durable journal admission"
                )
            try:
                _renameat2_noreplace(parent_descriptor, stage.name, output.name)
            except Exception as rename_error:
                source_is_stage = _named_directory_matches_fd(
                    parent_descriptor,
                    stage.name,
                    stage_identity,
                )
                destination_is_stage = _named_directory_matches_fd(
                    parent_descriptor,
                    output.name,
                    stage_identity,
                )
                if destination_is_stage and not source_is_stage:
                    destination_installed = True
                elif source_is_stage and not destination_is_stage:
                    resolve_and_archive("aborted")
                    raise
                else:
                    require_custody_and_lock()
                    _require_publication_journal_name_identity_fd(
                        custody_descriptor,
                        intent_name,
                        intent_identity,
                    )
                    _require_publication_journal_name_identity_fd(
                        custody_descriptor,
                        attempted_name,
                        attempted_identity,
                    )
                    raise PublicationFailure(
                        "atomic no-replace publication result is commit-unknown; "
                        "durable rename-attempted journal retained for permanent HOLD",
                        destination_installed=destination_is_stage,
                        destination_identity_preserved=destination_is_stage,
                        parent_fsync_completed=False,
                    ) from rename_error
            else:
                destination_installed = True

        require_parent_path_identity()
        require_custody_and_lock()
        destination_identity = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (stage_identity.st_dev, stage_identity.st_ino) != (
            destination_identity.st_dev,
            destination_identity.st_ino,
        ):
            raise BuildError("published directory identity differs from pinned stage")
        if verifier is not None:
            verifier(stage_descriptor)
        if _publication_tree_seal_fd(stage_descriptor) != tree_seal:
            raise BuildError("published directory differs from its journaled tree seal")
        os.fsync(parent_descriptor)
        parent_fsync_completed = True
        require_parent_path_identity()
        final_descriptor = os.open(
            output.name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            final_identity = os.fstat(final_descriptor)
            if (stage_identity.st_dev, stage_identity.st_ino) != (
                final_identity.st_dev,
                final_identity.st_ino,
            ):
                raise BuildError(
                    "published name changed after parent fsync"
                )
            if verifier is not None:
                verifier(final_descriptor)
            if _publication_tree_seal_fd(final_descriptor) != tree_seal:
                raise BuildError(
                    "published directory changed during final tree-seal verification"
                )
        finally:
            os.close(final_descriptor)
        os.fsync(parent_descriptor)
        require_parent_path_identity()
        final_path_identity = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (stage_identity.st_dev, stage_identity.st_ino) != (
            final_path_identity.st_dev,
            final_path_identity.st_ino,
        ):
            raise BuildError("published name changed after final verification")
        require_custody_and_lock()
        resolve_and_archive("committed")
    except Exception as error:
        if destination_installed:
            if expected_attempted is not None and resolved_name:
                try:
                    resolve_and_archive("committed")
                except Exception:
                    # The original failure remains primary.  Exact active or
                    # resolved custody is intentionally retained for restart;
                    # a conflicting/missing record is a permanent HOLD.
                    pass
            destination_identity_preserved = False
            try:
                observed_destination = os.stat(
                    output.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                destination_identity_preserved = (
                    observed_destination.st_dev,
                    observed_destination.st_ino,
                ) == (
                    stage_identity.st_dev,
                    stage_identity.st_ino,
                )
            except OSError:
                pass
            if not parent_fsync_completed:
                try:
                    os.fsync(parent_descriptor)
                    parent_fsync_completed = True
                except OSError:
                    pass
            raise PublicationFailure(
                f"publication failed after installing the final name: {error}",
                destination_installed=True,
                destination_identity_preserved=(
                    destination_identity_preserved
                ),
                parent_fsync_completed=parent_fsync_completed,
            ) from error
        raise
    finally:
        if stage_descriptor >= 0:
            os.close(stage_descriptor)
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        if custody_descriptor >= 0:
            os.close(custody_descriptor)
        os.close(parent_descriptor)


def _failure_exception_tree(error: Exception) -> Iterable[Exception]:
    pending = [error]
    seen: set[int] = set()
    while pending:
        candidate = pending.pop()
        identity = id(candidate)
        if identity in seen:
            continue
        seen.add(identity)
        yield candidate
        if isinstance(candidate, CombinedBuildFailure):
            pending.extend(
                [candidate.secondary_error, candidate.primary_error]
            )
        elif isinstance(candidate, ContextualBuildFailure):
            pending.append(candidate.primary_error)


def _bounded_failure_diagnostic(error: Exception) -> tuple[bytes, bool]:
    content = (str(error) or type(error).__name__).encode(
        "utf-8", errors="replace"
    )
    command_output_truncated = any(
        isinstance(candidate, CommandFailure)
        and candidate.output_truncated
        for candidate in _failure_exception_tree(error)
    )
    newline_bytes = 0 if content.endswith(b"\n") else 1
    truncated = (
        len(content) + newline_bytes > MAX_FAILURE_DIAGNOSTIC_BYTES
    )
    if truncated:
        marker = b"[truncated to bounded diagnostic tail]\n"
        tail_bytes = MAX_FAILURE_DIAGNOSTIC_BYTES - len(marker) - 1
        if tail_bytes < 0:
            raise BuildError("failure diagnostic bound is smaller than its marker")
        raw_tail = content[-tail_bytes:] if tail_bytes else b""
        utf8_tail = raw_tail.decode("utf-8", errors="ignore").encode("utf-8")
        content = marker + utf8_tail + b"\n"
    elif newline_bytes:
        content += b"\n"
    if len(content) > MAX_FAILURE_DIAGNOSTIC_BYTES:
        raise BuildError("failure diagnostic exceeded its strict byte bound")
    return content, truncated or command_output_truncated


def _failure_tree_inventory_fd(
    root_descriptor: int,
    prefix: str = "",
) -> dict[str, tuple[str, int, int, tuple[int, ...]]]:
    if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
        raise BuildError("failure evidence root descriptor is not a directory")
    scan_descriptor = os.open(
        ".",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=root_descriptor,
    )
    try:
        inventory: dict[str, tuple[str, int, int, tuple[int, ...]]] = {}
        with _scandir_fd(scan_descriptor) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            if (
                not entry.name
                or entry.name in {".", ".."}
                or "/" in entry.name
                or "\0" in entry.name
            ):
                raise BuildError("failure evidence entry name is unsafe")
            logical = f"{prefix}/{entry.name}" if prefix else entry.name
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(metadata.st_mode):
                inventory[logical] = (
                    "file",
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_nlink,
                    _fd_identity(metadata),
                )
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise BuildError(
                    "failure evidence tree contains a special or aliased entry"
                )
            inventory[logical] = (
                "directory",
                stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink,
                _fd_identity(metadata),
            )
            descriptor = os.open(
                entry.name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=scan_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if (metadata.st_dev, metadata.st_ino) != (
                    opened.st_dev,
                    opened.st_ino,
                ):
                    raise BuildError("failure evidence directory identity changed")
                nested = _failure_tree_inventory_fd(descriptor, logical)
                if set(inventory).intersection(nested):
                    raise BuildError("failure evidence path inventory is ambiguous")
                inventory.update(nested)
            finally:
                os.close(descriptor)
        return inventory
    finally:
        os.close(scan_descriptor)


def _verify_failure_output_fd(
    root_descriptor: int,
    expected_failure_output: Path,
    *,
    retained_stage_descriptors: Mapping[tuple[int, int], int] | None = None,
) -> dict[str, Any]:
    root_before = os.fstat(root_descriptor)
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or stat.S_IMODE(root_before.st_mode) != 0o500
    ):
        raise BuildError("failure evidence root mode or type drifted")
    receipt = _read_json_from_fixed_root_fd(
        root_descriptor,
        "provider-build-failure-receipt.json",
    )
    expected_keys = {
        "schema",
        "attempt_id_sha256",
        "provider",
        "builder_profile",
        "target_architecture",
        "failed_phase",
        "completed_phases",
        "requested_output",
        "cache_root",
        "container_engine",
        "inputs",
        "image",
        "container",
        "cause",
        "candidate_stage_retained",
        "candidate_stage",
        "cleanup_tombstones",
        "build_succeeded",
        "builder_output_verified",
        "success_output_published",
        "success_output_parent_fsync_completed",
        "failure_receipt_is_not_builder_receipt",
        "failure_receipt_is_not_execution_attestation",
        *FALSE_AUTHORITY_FIELDS,
        "receipt_sha256",
    }
    _expect_keys(receipt, expected_keys, "failure receipt")
    if (
        receipt["schema"] != FAILURE_RECEIPT_SCHEMA
        or receipt["provider"] not in PROVIDERS
        or receipt["builder_profile"] not in BUILDER_PROFILES
        or receipt["target_architecture"] != TARGET_ARCHITECTURE
        or receipt["container_engine"] != "docker"
        or receipt["receipt_sha256"] != _failure_receipt_hash(receipt)
    ):
        raise BuildError("failure receipt identity or self-hash drifted")
    _require_hex(receipt["attempt_id_sha256"], 64, "failure attempt id")
    _require_false_authority_fields(receipt, "failure receipt")
    phases = (
        "prefetch",
        "image",
        "stage",
        "container",
        "verify",
        "cleanup",
        "publish",
    )
    if receipt["failed_phase"] not in phases:
        raise BuildError("failure receipt phase is outside the closed set")
    phase_index = phases.index(receipt["failed_phase"])
    if receipt["completed_phases"] != list(phases[:phase_index]):
        raise BuildError("failure receipt completed-phase prefix drifted")
    expected_build_succeeded = "container" in receipt["completed_phases"]
    expected_verified = "verify" in receipt["completed_phases"]
    published = receipt["success_output_published"]
    parent_fsync_completed = receipt["success_output_parent_fsync_completed"]
    candidate_stage = receipt["candidate_stage"]
    cleanup_tombstones = receipt["cleanup_tombstones"]
    if not isinstance(cleanup_tombstones, list):
        raise BuildError("failure cleanup tombstones are malformed")
    _expect_keys(
        candidate_stage,
        {
            "state",
            "role",
            "requested_path",
            "expected_identity",
            "observed_identity",
            "same_uid_concurrent_retained_stage_path_replacement_proven",
        },
        "failure candidate stage",
    )
    candidate_state = candidate_stage["state"]
    if candidate_state not in {
        "not_retained",
        "retained_at_owned_path",
        "empty_cleanup_tombstone_retained",
        "owned_path_identity_ambiguous",
    }:
        raise BuildError("failure candidate stage state drifted")
    candidate_role = candidate_stage["role"]
    if (
        candidate_stage[
            "same_uid_concurrent_retained_stage_path_replacement_proven"
        ]
        is not False
        or (
            candidate_role is not None
            and candidate_role not in STAGE_ROLES
        )
    ):
        raise BuildError("failure candidate stage role drifted")
    expected_candidate_retained = candidate_state in {
        "retained_at_owned_path",
        "empty_cleanup_tombstone_retained",
    }
    if expected_candidate_retained:
        _validate_stage_identity_record(
            candidate_stage,
            "retained candidate stage",
        )
        if (
            candidate_role not in STAGE_ROLES
            or (
                candidate_state == "empty_cleanup_tombstone_retained"
                and not any(
                    isinstance(tombstone, Mapping)
                    and tombstone.get("requested_path")
                    == candidate_stage["requested_path"]
                    and tombstone.get("expected_identity")
                    == candidate_stage["expected_identity"]
                    for tombstone in cleanup_tombstones
                )
            )
        ):
            raise BuildError("retained candidate stage context drifted")
    elif candidate_state == "not_retained":
        requested_path = candidate_stage["requested_path"]
        if requested_path is None:
            if (
                candidate_role is not None
                or candidate_stage["expected_identity"] is not None
                or candidate_stage["observed_identity"] is not None
            ):
                raise BuildError(
                    "absent candidate stage identity is contradictory"
                )
        elif (
            not isinstance(requested_path, str)
            or not Path(requested_path).is_absolute()
            or candidate_role not in STAGE_ROLES
            or not isinstance(candidate_stage["expected_identity"], dict)
            or candidate_stage["observed_identity"] is not None
        ):
            raise BuildError("removed candidate stage identity is malformed")
    else:
        if (
            not isinstance(candidate_stage["requested_path"], str)
            or not Path(candidate_stage["requested_path"]).is_absolute()
            or candidate_role not in STAGE_ROLES
            or not isinstance(candidate_stage["expected_identity"], dict)
            or not isinstance(candidate_stage["observed_identity"], dict)
            or candidate_stage["expected_identity"]
            == candidate_stage["observed_identity"]
        ):
            raise BuildError("ambiguous candidate stage identity is malformed")
    cleanup_tombstone_keys: set[tuple[str, int, int]] = set()
    for tombstone in cleanup_tombstones:
        if not isinstance(tombstone, Mapping):
            raise BuildError("failure cleanup tombstone is malformed")
        _expect_keys(
            tombstone,
            {
                "state",
                "role",
                "requested_path",
                "expected_identity",
                "observed_identity",
                "mode",
                "empty",
                "same_uid_concurrent_child_name_replacement_proven",
                "same_uid_concurrent_retained_stage_path_replacement_proven",
            },
            "failure cleanup tombstone",
        )
        path, identity = _validate_stage_identity_record(
            tombstone,
            "failure cleanup tombstone",
        )
        tombstone_key = (str(path), identity[0], identity[1])
        if (
            tombstone["state"] != "empty_cleanup_tombstone_retained"
            or tombstone["role"] not in STAGE_ROLES
            or tombstone["mode"] != "0500"
            or tombstone["empty"] is not True
            or tombstone[
                "same_uid_concurrent_child_name_replacement_proven"
            ]
            is not False
            or tombstone[
                "same_uid_concurrent_retained_stage_path_replacement_proven"
            ]
            is not False
            or tombstone_key in cleanup_tombstone_keys
        ):
            raise BuildError("failure cleanup tombstone contract drifted")
        cleanup_tombstone_keys.add(tombstone_key)
    if (
        receipt["candidate_stage_retained"] is not expected_candidate_retained
        or receipt["build_succeeded"] is not expected_build_succeeded
        or receipt["builder_output_verified"] is not expected_verified
        or not isinstance(published, bool)
        or not isinstance(parent_fsync_completed, bool)
        or published
        is not (
            receipt["failed_phase"] == "publish"
            and isinstance(receipt.get("cause"), dict)
            and receipt["cause"].get("destination_installed") is True
            and receipt["cause"].get("destination_identity_preserved") is True
        )
        or (
            parent_fsync_completed
            and (
                not isinstance(receipt.get("cause"), dict)
                or receipt["cause"].get("destination_installed") is not True
            )
        )
        or receipt["failure_receipt_is_not_builder_receipt"] is not True
        or receipt["failure_receipt_is_not_execution_attestation"] is not True
    ):
        raise BuildError("failure receipt outcome semantics drifted")
    requested_output_value = _validated_attempt_path(
        receipt["requested_output"],
        "failure requested output",
    )
    cache_root_value = _validated_attempt_path(
        receipt["cache_root"],
        "failure cache root",
    )
    requested_output = Path(requested_output_value)
    receipt_failure_output = requested_output.with_name(
        f"{requested_output.name}.failure"
    )
    if (
        not requested_output.is_absolute()
        or receipt_failure_output.resolve(strict=False)
        != expected_failure_output.resolve(strict=False)
        or cache_root_value != receipt["cache_root"]
    ):
        raise BuildError("failure receipt path identity drifted")
    _expect_keys(
        receipt["inputs"],
        {
            "recipe",
            "builder",
            "containerfile",
            "container_input_identity_sha256",
        },
        "failure receipt inputs",
    )
    expected_input_paths = {
        "recipe": "inputs/provider-payload-recipe-v1.json",
        "builder": "inputs/build_provider_payload.py",
        "containerfile": "inputs/Containerfile",
    }
    for name, logical_path in expected_input_paths.items():
        artifact = receipt["inputs"][name]
        if artifact.get("logical_path") != logical_path:
            raise BuildError("failure receipt input logical path drifted")
    input_identity = _container_input_identity(
        receipt["inputs"]["recipe"]["sha256"],
        receipt["inputs"]["builder"]["sha256"],
        receipt["inputs"]["containerfile"]["sha256"],
    )
    if (
        receipt["inputs"]["container_input_identity_sha256"] != input_identity
        or receipt["attempt_id_sha256"]
        != _build_attempt_identity(
            input_identity,
            receipt["provider"],
            receipt["builder_profile"],
            requested_output_value,
            cache_root_value,
        )
    ):
        raise BuildError("failure receipt container input identity drifted")
    _expect_keys(
        receipt["image"],
        {"expected_tag", "image_id", "build_context"},
        "failure image",
    )
    _verify_build_context_lifecycle_inputs(
        receipt["image"]["build_context"],
        recipe_sha256=receipt["inputs"]["recipe"]["sha256"],
        builder_sha256=receipt["inputs"]["builder"]["sha256"],
        containerfile_sha256=receipt["inputs"]["containerfile"]["sha256"],
    )
    image_id = receipt["image"]["image_id"]
    if (
        receipt["image"]["expected_tag"]
        != _container_image_tag(
            receipt["inputs"]["recipe"]["sha256"],
            receipt["inputs"]["builder"]["sha256"],
            receipt["inputs"]["containerfile"]["sha256"],
            receipt["builder_profile"],
        )
        or (
            image_id is not None
            and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        )
        or (image_id is not None)
        != ("image" in receipt["completed_phases"])
    ):
        raise BuildError("failure receipt image identity drifted")
    _verify_container_projection(
        receipt["container"],
        provider_name=receipt["provider"],
        profile=receipt["builder_profile"],
        recipe_sha256=receipt["inputs"]["recipe"]["sha256"],
        builder_sha256=receipt["inputs"]["builder"]["sha256"],
        containerfile_sha256=receipt["inputs"]["containerfile"]["sha256"],
        image_reference=image_id,
        expected_build_context=receipt["image"]["build_context"],
        allow_failure_states=True,
    )
    if (
        receipt["container"]["completed_zero"] is not expected_build_succeeded
        or receipt["container"]["attempt_id_sha256"]
        != receipt["attempt_id_sha256"]
        or (
            receipt["container"]["cidfile"]["cleanup_tombstone"] is not None
            and receipt["container"]["cidfile"]["cleanup_tombstone"]
            not in cleanup_tombstones
        )
    ):
        raise BuildError("failure container execution semantics drifted")
    _expect_keys(
        receipt["cause"],
        {
            "exception_type",
            "secondary_exception_type",
            "errno",
            "return_code",
            "command",
            "destination_installed",
            "destination_identity_preserved",
            "parent_fsync_completed",
            "diagnostic",
            "diagnostic_truncated",
        },
        "failure cause",
    )
    cause_command = receipt["cause"]["command"]
    if cause_command is not None:
        _validate_arguments(cause_command)
        if (
            receipt["failed_phase"] == "container"
            and cause_command != receipt["container"]["command"]
        ):
            raise BuildError(
                "container failure cause command differs from its canonical "
                "lifecycle command"
            )
    secondary_exception_type = receipt["cause"]["secondary_exception_type"]
    if secondary_exception_type is not None and (
        not isinstance(secondary_exception_type, str)
        or not secondary_exception_type
        or "\0" in secondary_exception_type
    ):
        raise BuildError("failure secondary exception identity is malformed")
    if receipt["cause"]["errno"] is not None and (
        not isinstance(receipt["cause"]["errno"], int)
        or isinstance(receipt["cause"]["errno"], bool)
        or receipt["cause"]["errno"] <= 0
    ):
        raise BuildError("failure errno is malformed")
    diagnostic = receipt["cause"]["diagnostic"]
    if diagnostic.get("logical_path") != "diagnostics/failure.txt":
        raise BuildError("failure diagnostic logical path drifted")
    if (
        diagnostic["byte_length"] <= 0
        or diagnostic["byte_length"] > MAX_FAILURE_DIAGNOSTIC_BYTES
        or not isinstance(receipt["cause"]["diagnostic_truncated"], bool)
        or not isinstance(receipt["cause"]["destination_installed"], bool)
        or not isinstance(
            receipt["cause"]["destination_identity_preserved"],
            bool,
        )
        or (
            receipt["cause"]["destination_identity_preserved"]
            and not receipt["cause"]["destination_installed"]
        )
        or receipt["cause"]["parent_fsync_completed"]
        is not parent_fsync_completed
    ):
        raise BuildError("failure diagnostic bytes or bound drifted")
    if isinstance(receipt["cause"]["return_code"], int) != (
        cause_command is not None
    ):
        raise BuildError("failure command return-code semantics drifted")
    expected_inventory = {
        "inputs": ("directory", 0o500),
        "inputs/provider-payload-recipe-v1.json": ("file", 0o400),
        "inputs/build_provider_payload.py": ("file", 0o400),
        "inputs/Containerfile": ("file", 0o400),
        "diagnostics": ("directory", 0o500),
        "diagnostics/failure.txt": ("file", 0o400),
        "provider-build-failure-receipt.json": ("file", 0o400),
    }
    pinned_stage_records = list(cleanup_tombstones)
    if expected_candidate_retained:
        pinned_stage_records.append(candidate_stage)
    with _pinned_stage_records(
        pinned_stage_records,
        retained_descriptors=retained_stage_descriptors,
    ):
        observed_inventory = _failure_tree_inventory_fd(root_descriptor)
        if set(observed_inventory) != set(expected_inventory):
            raise BuildError("failure evidence tree has missing or extra entries")
        for logical, (kind, mode) in expected_inventory.items():
            (
                observed_kind,
                observed_mode,
                link_count,
                _,
            ) = observed_inventory[logical]
            if (
                observed_kind != kind
                or observed_mode != mode
                or (kind == "file" and link_count != 1)
            ):
                raise BuildError(
                    "failure evidence entry mode, type, or links drifted"
                )
        retained_inputs = [
            receipt["inputs"][name]
            for name in ("recipe", "builder", "containerfile")
        ]
        with _retained_artifact_snapshots_from_fd(
            root_descriptor,
            [*retained_inputs, diagnostic],
        ) as copies:
            for artifact in [*retained_inputs, diagnostic]:
                logical = artifact["logical_path"]
                if _artifact(copies[logical], logical) != artifact:
                    raise BuildError("failure evidence retained bytes drifted")
        if published:
            published_descriptor = _open_fixed_root(requested_output)
            try:
                _verify_builder_output_fd(published_descriptor)
            finally:
                os.close(published_descriptor)
        final_receipt = _read_json_from_fixed_root_fd(
            root_descriptor,
            "provider-build-failure-receipt.json",
        )
        final_inventory = _failure_tree_inventory_fd(root_descriptor)
        if final_receipt != receipt or final_inventory != observed_inventory:
            raise BuildError(
                "failure evidence receipt or tree changed during verification"
            )
        root_after = os.fstat(root_descriptor)
        if _fd_identity(root_before) != _fd_identity(root_after):
            raise BuildError(
                "failure evidence root identity changed during verification"
            )
    return receipt


def _verify_failure_output(
    root: Path,
    expected_failure_output: Path | None = None,
) -> dict[str, Any]:
    expected_root = (
        expected_failure_output
        if expected_failure_output is not None
        else root
    )
    root_descriptor = _open_fixed_root(root)
    try:
        return _verify_failure_output_fd(root_descriptor, expected_root)
    finally:
        os.close(root_descriptor)


def _seal_failure_tree(root: Path) -> None:
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise BuildError("failure evidence stage is not one real directory")
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in root.rglob("*"):
        child = path.lstat()
        if stat.S_ISLNK(child.st_mode):
            raise BuildError("failure evidence stage contains a symlink")
        if stat.S_ISREG(child.st_mode):
            if child.st_nlink != 1:
                raise BuildError(
                    "failure evidence stage contains a multiply-linked file"
                )
            path.chmod(0o400)
        elif not stat.S_ISDIR(child.st_mode):
            raise BuildError("failure evidence stage contains a special entry")
    for path in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        path.chmod(0o500)
    root.chmod(0o500)


def _create_owned_stage(parent: Path, prefix: str) -> tuple[Path, tuple[int, int]]:
    resolved_parent = parent.resolve(strict=True)
    stage = Path(tempfile.mkdtemp(prefix=prefix, dir=resolved_parent))
    if stage.parent != resolved_parent:
        raise BuildError("private stage escaped its resolved parent")
    metadata = stage.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stage.is_symlink():
        raise BuildError("private stage is not one real directory")
    stage.chmod(0o700)
    return stage, (metadata.st_dev, metadata.st_ino)


def _remove_directory_contents_fd(root_descriptor: int) -> None:
    os.fchmod(root_descriptor, 0o700)
    with _scandir_fd(root_descriptor) as iterator:
        entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISREG(metadata.st_mode):
            descriptor = os.open(
                entry.name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | os.O_NONBLOCK,
                dir_fd=root_descriptor,
            )
            try:
                if _fd_identity(metadata) != _fd_identity(os.fstat(descriptor)):
                    raise BuildError(
                        "private stage file identity changed during cleanup"
                    )
            finally:
                os.close(descriptor)
            os.unlink(entry.name, dir_fd=root_descriptor)
            continue
        if stat.S_ISLNK(metadata.st_mode):
            current = os.stat(
                entry.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if _fd_identity(metadata) != _fd_identity(current):
                raise BuildError(
                    "private stage symlink identity changed during cleanup"
                )
            os.unlink(entry.name, dir_fd=root_descriptor)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise BuildError(
                "private stage contains a special or aliased entry; "
                "refusing cleanup"
            )
        os.chmod(
            entry.name,
            0o700,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        descriptor = os.open(
            entry.name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise BuildError(
                    "private stage directory identity changed during cleanup"
                )
            _remove_directory_contents_fd(descriptor)
        finally:
            os.close(descriptor)
        os.rmdir(entry.name, dir_fd=root_descriptor)
    os.fsync(root_descriptor)


def _cleanup_owned_stage(
    stage: Path,
    identity: tuple[int, int],
) -> dict[str, Any]:
    resolved_parent = stage.parent.resolve(strict=True)
    if stage.parent != resolved_parent or stage.name != PurePosixPath(stage.name).name:
        raise BuildError("private cleanup target is outside its resolved parent")
    parent_descriptor = os.open(
        resolved_parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    stage_descriptor = -1
    try:
        try:
            stage_descriptor = os.open(
                stage.name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError as error:
            raise BuildError(
                "private stage name disappeared before owned cleanup"
            ) from error
        except OSError as error:
            raise BuildError(
                "private stage name is not one openable real directory"
            ) from error
        opened = os.fstat(stage_descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
        ):
            raise BuildError(
                "private stage name no longer identifies this build attempt; "
                "refusing cleanup"
            )
        os.fchmod(stage_descriptor, 0o700)
        # Linux has no unlink-by-open-directory-fd operation.  Children are
        # verified immediately before their name-based removal, but this does
        # not prove resistance to a malicious same-UID process concurrently
        # replacing a child name.  Keep the now-empty root inode as a sealed
        # tombstone instead of exposing the final stat-to-rmdir name race.
        _remove_directory_contents_fd(stage_descriptor)
        final_name_identity = os.stat(
            stage.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (final_name_identity.st_dev, final_name_identity.st_ino) != identity:
            raise BuildError("private stage name changed after content cleanup")
        os.fchmod(stage_descriptor, 0o500)
        with _scandir_fd(stage_descriptor) as iterator:
            if next(iterator, None) is not None:
                raise BuildError("private stage is not empty after content cleanup")
        os.fsync(stage_descriptor)
        os.fsync(parent_descriptor)
        return {
            "state": "empty_cleanup_tombstone_retained",
            "requested_path": str(stage),
            "expected_identity": {
                "device": identity[0],
                "inode": identity[1],
            },
            "observed_identity": {
                "device": final_name_identity.st_dev,
                "inode": final_name_identity.st_ino,
            },
            "mode": "0500",
            "empty": True,
            "same_uid_concurrent_child_name_replacement_proven": False,
            "same_uid_concurrent_retained_stage_path_replacement_proven": (
                False
            ),
        }
    finally:
        if stage_descriptor >= 0:
            os.close(stage_descriptor)
        os.close(parent_descriptor)


def _prepare_container_cidfile_custody(
    output: Path,
    attempt_id: str,
) -> _ContainerCidfileCustody:
    expected_path = _container_cidfile_custody_path(output, attempt_id)
    resolved_parent = output.parent.resolve(strict=True)
    if expected_path.parent != resolved_parent:
        raise BuildError("container cidfile custody escaped the resolved output parent")
    parent_descriptor = -1
    directory_descriptor = -1
    created = False
    try:
        parent_descriptor = os.open(
            resolved_parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        parent_opened = os.fstat(parent_descriptor)
        parent_named = os.stat(resolved_parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or (parent_opened.st_dev, parent_opened.st_ino)
            != (parent_named.st_dev, parent_named.st_ino)
        ):
            raise BuildError("output parent identity changed before cidfile custody")
        try:
            # mkdirat has the atomic no-replace semantics required here; unlike
            # a temporary name, this deterministic name is also the orphan locator.
            os.mkdir(expected_path.name, 0o700, dir_fd=parent_descriptor)
            created = True
        except FileExistsError as error:
            raise BuildError(
                f"container cidfile custody already exists: {expected_path}"
            ) from error
        os.fsync(parent_descriptor)
        directory_descriptor = os.open(
            expected_path.name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(directory_descriptor)
        named = os.stat(
            expected_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (named.st_dev, named.st_ino)
            or opened.st_uid != os.getuid()
        ):
            raise BuildError("container cidfile custody identity is not pinned")
        os.fchmod(directory_descriptor, 0o700)
        with _scandir_fd(directory_descriptor) as iterator:
            if next(iterator, None) is not None:
                raise BuildError("new container cidfile custody is not empty")
        os.fsync(directory_descriptor)
        os.fsync(parent_descriptor)
        custody = _ContainerCidfileCustody(
            output_parent=resolved_parent,
            path=expected_path,
            identity=(opened.st_dev, opened.st_ino),
            parent_descriptor=parent_descriptor,
            directory_descriptor=directory_descriptor,
        )
        _assert_container_cidfile_absent(custody)
        parent_descriptor = -1
        directory_descriptor = -1
        return custody
    except BuildError:
        raise
    except OSError as error:
        detail = (
            "after installing its deterministic directory"
            if created
            else "before installing its deterministic directory"
        )
        raise BuildError(
            f"container cidfile custody preparation failed {detail}: {error}"
        ) from error
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _verify_named_container_custody(
    custody: _ContainerCidfileCustody,
    *,
    expected_mode: int = 0o700,
) -> os.stat_result:
    if (
        custody.parent_descriptor < 0
        or custody.directory_descriptor < 0
        or custody.path.parent != custody.output_parent
        or custody.path.name != PurePosixPath(custody.path.name).name
        or custody.cidfile_path
        != custody.path / CONTAINER_CIDFILE_NAME
    ):
        raise BuildError("container cidfile custody descriptor set is closed or unsafe")
    opened = os.fstat(custody.directory_descriptor)
    parent_opened = os.fstat(custody.parent_descriptor)
    if custody.root_name_bound:
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or opened.st_uid != os.getuid()
            or not stat.S_ISDIR(parent_opened.st_mode)
            or parent_opened.st_uid != 0
            or (opened.st_dev, opened.st_ino) != custody.identity
        ):
            raise BuildError(
                "root-name-bound container custody fixed FD drifted"
            )
        return opened
    parent_named = os.stat(
        custody.output_parent,
        follow_symlinks=False,
    )
    named = os.stat(
        custody.path.name,
        dir_fd=custody.parent_descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or opened.st_uid != os.getuid()
        or not stat.S_ISDIR(parent_opened.st_mode)
        or not stat.S_ISDIR(parent_named.st_mode)
        or (parent_opened.st_dev, parent_opened.st_ino)
        != (parent_named.st_dev, parent_named.st_ino)
        or (opened.st_dev, opened.st_ino) != custody.identity
        or (named.st_dev, named.st_ino) != custody.identity
        or not stat.S_ISDIR(named.st_mode)
    ):
        raise BuildError("container cidfile custody name or fixed FD drifted")
    return opened


def _assert_container_cidfile_absent(
    custody: _ContainerCidfileCustody,
) -> None:
    _verify_named_container_custody(custody)
    with _scandir_fd(custody.directory_descriptor) as iterator:
        entries = list(iterator)
    if entries:
        raise BuildError(
            "container cidfile must be strictly absent before engine creation"
        )
    try:
        os.stat(
            CONTAINER_CIDFILE_NAME,
            dir_fd=custody.directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise BuildError(
        "container cidfile must be absent and may not be a pre-existing symlink"
    )


def _read_live_container_id(
    cidfile_path: Path,
) -> tuple[str, tuple[int, int]]:
    if cidfile_path != Path(CONTAINER_CIDFILE_PATH):
        raise BuildError("in-container cidfile path is outside the closed mount")
    root_descriptor = _open_fixed_root(cidfile_path.parent)
    try:
        root_before = os.fstat(root_descriptor)
        descriptor = _openat2_beneath(
            root_descriptor,
            CONTAINER_CIDFILE_NAME,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_uid not in {0, os.getuid()}
            ):
                raise BuildError("container cidfile mode or owner is unsafe")
            content = _read_bounded_fd(
                descriptor,
                CONTAINER_CIDFILE_NAME,
                64,
            )
        finally:
            os.close(descriptor)
        root_after = os.fstat(root_descriptor)
        if _fd_identity(root_before) != _fd_identity(root_after):
            raise BuildError("container cidfile custody changed while reading")
    finally:
        os.close(root_descriptor)
    if re.fullmatch(rb"[0-9a-f]{64}", content) is None:
        raise BuildError("container cidfile is not exactly one 64hex container ID")
    return content.decode("ascii"), (root_before.st_dev, root_before.st_ino)


def _open_captured_container_id(
    custody: _ContainerCidfileCustody,
) -> tuple[str, int, os.stat_result] | None:
    _verify_named_container_custody(custody)
    try:
        named_before = os.stat(
            CONTAINER_CIDFILE_NAME,
            dir_fd=custody.directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(named_before.st_mode)
        or named_before.st_nlink != 1
        or stat.S_IMODE(named_before.st_mode) & 0o022
        or named_before.st_uid not in {0, os.getuid()}
    ):
        raise BuildError("container cidfile is not one safe regular inode")
    descriptor = os.open(
        CONTAINER_CIDFILE_NAME,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=custody.directory_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if _fd_identity(named_before) != _fd_identity(opened):
            raise BuildError("container cidfile identity changed before fixed-FD read")
        content = _read_bounded_fd(
            descriptor,
            CONTAINER_CIDFILE_NAME,
            64,
        )
        named_after = os.stat(
            CONTAINER_CIDFILE_NAME,
            dir_fd=custody.directory_descriptor,
            follow_symlinks=False,
        )
        if (
            _fd_identity(opened) != _fd_identity(os.fstat(descriptor))
            or _fd_identity(opened) != _fd_identity(named_after)
        ):
            raise BuildError("container cidfile identity changed during capture")
        if re.fullmatch(rb"[0-9a-f]{64}", content) is None:
            raise BuildError(
                "container cidfile is not exactly one 64hex container ID"
            )
        return content.decode("ascii"), descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _seal_container_cidfile_custody(
    custody: _ContainerCidfileCustody,
) -> dict[str, Any]:
    _verify_named_container_custody(custody)
    with _scandir_fd(custody.directory_descriptor) as iterator:
        if next(iterator, None) is not None:
            raise BuildError("container cidfile custody is not empty at sealing")
    os.fchmod(custody.directory_descriptor, 0o500)
    opened = _verify_named_container_custody(custody, expected_mode=0o500)
    os.fsync(custody.directory_descriptor)
    os.fsync(custody.parent_descriptor)
    return {
        "state": "empty_cleanup_tombstone_retained",
        "role": "container_cidfile_custody",
        "requested_path": str(custody.path),
        "expected_identity": {
            "device": custody.identity[0],
            "inode": custody.identity[1],
        },
        "observed_identity": {
            "device": opened.st_dev,
            "inode": opened.st_ino,
        },
        "mode": "0500",
        "empty": True,
        "same_uid_concurrent_child_name_replacement_proven": False,
        "same_uid_concurrent_retained_stage_path_replacement_proven": False,
    }


def _finalize_container_cidfile_custody(
    custody: _ContainerCidfileCustody,
    container_projection: Mapping[str, Any],
    *,
    command: Sequence[str],
    completed_zero: bool,
    expected_container_id: str | None,
    captured_state: str,
    allow_absent: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    projection = _copy_container_projection(container_projection)
    cidfile = projection["cidfile"]
    projection["command"] = list(command)
    projection["run_invoked"] = True
    projection["completed_zero"] = completed_zero
    cidfile["custody_directory_identity"] = (
        _container_custody_identity_record(custody.identity)
    )
    cidfile["pre_run_absent_no_symlink"] = True
    descriptor = -1
    try:
        captured = _open_captured_container_id(custody)
        if captured is None:
            if not allow_absent:
                raise BuildError(
                    "container engine returned without its required cidfile"
                )
            cidfile["state"] = "absent_after_failed_run"
            os.fsync(custody.directory_descriptor)
            cidfile["custody_directory_fsynced"] = True
            os.fsync(custody.parent_descriptor)
            cidfile["output_parent_fsynced"] = True
            tombstone = _seal_container_cidfile_custody(custody)
            cidfile["cleanup_tombstone"] = tombstone
            return projection, tombstone
        observed_id, descriptor, opened = captured
        projection["id"] = observed_id
        cidfile["container_id_cidfile_observed"] = True
        cidfile["captured_after_exit_via_fixed_fd"] = True
        cidfile["read_during_container_execution"] = (
            expected_container_id is not None
        )
        if (
            expected_container_id is not None
            and observed_id != expected_container_id
        ):
            raise BuildError(
                "in-container and launcher-captured container IDs differ"
            )
        cidfile["container_id_cross_checked"] = (
            expected_container_id is not None
        )
        named = os.stat(
            CONTAINER_CIDFILE_NAME,
            dir_fd=custody.directory_descriptor,
            follow_symlinks=False,
        )
        if _fd_identity(named) != _fd_identity(opened):
            raise BuildError("container cidfile name changed before unlink")
        os.unlink(
            CONTAINER_CIDFILE_NAME,
            dir_fd=custody.directory_descriptor,
        )
        cidfile["unlinked_after_capture"] = True
        try:
            os.stat(
                CONTAINER_CIDFILE_NAME,
                dir_fd=custody.directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise BuildError("container cidfile name reappeared after unlink")
        unlinked = os.fstat(descriptor)
        if (
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_gid,
                opened.st_size,
            )
            != (
                unlinked.st_dev,
                unlinked.st_ino,
                unlinked.st_mode,
                unlinked.st_uid,
                unlinked.st_gid,
                unlinked.st_size,
            )
            or unlinked.st_nlink != 0
            or os.pread(descriptor, 65, 0)
            != observed_id.encode("ascii")
        ):
            raise BuildError("unlinked container cidfile inode changed")
        os.fsync(custody.directory_descriptor)
        cidfile["custody_directory_fsynced"] = True
        os.fsync(custody.parent_descriptor)
        cidfile["output_parent_fsynced"] = True
        tombstone = _seal_container_cidfile_custody(custody)
        cidfile["cleanup_tombstone"] = tombstone
        cidfile["state"] = captured_state
        return projection, tombstone
    except Exception as error:
        cidfile["state"] = (
            "cleanup_incomplete"
            if cidfile["unlinked_after_capture"]
            else "retained_untrusted"
        )
        raise ContainerCustodyError(
            f"container cidfile custody failed closed: {error}",
            projection,
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _candidate_stage_state(
    stage: Path | None,
    identity: tuple[int, int] | None,
    role: str | None = None,
) -> dict[str, Any]:
    if stage is None or identity is None:
        return {
            "state": "not_retained",
            "role": None,
            "requested_path": None,
            "expected_identity": None,
            "observed_identity": None,
            "same_uid_concurrent_retained_stage_path_replacement_proven": (
                False
            ),
        }
    expected = {"device": identity[0], "inode": identity[1]}
    try:
        metadata = stage.lstat()
    except FileNotFoundError:
        return {
            "state": "not_retained",
            "role": role,
            "requested_path": str(stage),
            "expected_identity": expected,
            "observed_identity": None,
            "same_uid_concurrent_retained_stage_path_replacement_proven": (
                False
            ),
        }
    observed = {"device": metadata.st_dev, "inode": metadata.st_ino}
    if (
        stat.S_ISDIR(metadata.st_mode)
        and not stage.is_symlink()
        and (metadata.st_dev, metadata.st_ino) == identity
    ):
        state = "retained_at_owned_path"
    else:
        state = "owned_path_identity_ambiguous"
    return {
        "state": state,
        "role": role,
        "requested_path": str(stage),
        "expected_identity": expected,
        "observed_identity": observed,
        "same_uid_concurrent_retained_stage_path_replacement_proven": False,
    }


def _cleanup_tombstone_with_role(
    tombstone: Mapping[str, Any],
    role: str,
) -> dict[str, Any]:
    result = dict(tombstone)
    result["role"] = role
    return result


def _candidate_stage_from_cleanup_tombstone(
    tombstone: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "state": tombstone["state"],
        "role": tombstone["role"],
        "requested_path": tombstone["requested_path"],
        "expected_identity": tombstone["expected_identity"],
        "observed_identity": tombstone["observed_identity"],
        "same_uid_concurrent_retained_stage_path_replacement_proven": (
            tombstone[
                "same_uid_concurrent_retained_stage_path_replacement_proven"
            ]
        ),
    }


def _validate_stage_identity_record(
    record: Mapping[str, Any],
    label: str,
) -> tuple[Path, tuple[int, int]]:
    expected_identity = record.get("expected_identity")
    observed_identity = record.get("observed_identity")
    requested_path = record.get("requested_path")
    if (
        not isinstance(requested_path, str)
        or not Path(requested_path).is_absolute()
        or not isinstance(expected_identity, dict)
        or set(expected_identity) != {"device", "inode"}
        or not all(
            isinstance(expected_identity[key], int)
            and not isinstance(expected_identity[key], bool)
            and expected_identity[key] >= 0
            for key in ("device", "inode")
        )
        or observed_identity != expected_identity
    ):
        raise BuildError(f"{label} identity is malformed")
    return (
        Path(requested_path),
        (expected_identity["device"], expected_identity["inode"]),
    )


@contextmanager
def _pinned_stage_records(
    records: Sequence[Mapping[str, Any]],
    retained_descriptors: Mapping[tuple[int, int], int] | None = None,
) -> Iterable[None]:
    handles: list[
        tuple[int, int, str, tuple[int, int], bool]
    ] = []
    seen: set[tuple[str, int, int]] = set()
    try:
        for record in records:
            path, identity = _validate_stage_identity_record(
                record,
                "retained stage",
            )
            key = (str(path), identity[0], identity[1])
            if key in seen:
                continue
            seen.add(key)
            retained_descriptor = (
                None
                if retained_descriptors is None
                else retained_descriptors.get(identity)
            )
            if retained_descriptor is not None:
                stage_descriptor = os.dup(retained_descriptor)
                opened = os.fstat(stage_descriptor)
                tombstone = (
                    record.get("state")
                    == "empty_cleanup_tombstone_retained"
                )
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != identity
                ):
                    os.close(stage_descriptor)
                    raise BuildError("retained stage FD identity drifted")
                if tombstone:
                    if (
                        record.get("mode") != "0500"
                        or record.get("empty") is not True
                        or stat.S_IMODE(opened.st_mode) != 0o500
                    ):
                        os.close(stage_descriptor)
                        raise BuildError("retained cleanup tombstone FD drifted")
                    with _scandir_fd(stage_descriptor) as iterator:
                        if next(iterator, None) is not None:
                            os.close(stage_descriptor)
                            raise BuildError("retained cleanup tombstone is not empty")
                handles.append((-1, stage_descriptor, "", identity, tombstone))
                continue
            resolved_parent = path.parent.resolve(strict=True)
            if (
                path.parent != resolved_parent
                or path.name != PurePosixPath(path.name).name
            ):
                raise BuildError("retained stage escaped its resolved parent")
            parent_descriptor = os.open(
                resolved_parent,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
            )
            stage_descriptor = -1
            try:
                before = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or (before.st_dev, before.st_ino) != identity
                ):
                    raise BuildError(
                        "retained stage is absent, aliased, or replaced"
                    )
                stage_descriptor = os.open(
                    path.name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=parent_descriptor,
                )
                opened = os.fstat(stage_descriptor)
                if (opened.st_dev, opened.st_ino) != identity:
                    raise BuildError(
                        "retained stage identity changed while opening"
                    )
                tombstone = (
                    record.get("state")
                    == "empty_cleanup_tombstone_retained"
                )
                if tombstone:
                    if (
                        record.get("mode") != "0500"
                        or record.get("empty") is not True
                        or record.get(
                            "same_uid_concurrent_child_name_replacement_proven"
                        )
                        is not False
                        or record.get(
                            "same_uid_concurrent_retained_stage_path_replacement_proven"
                        )
                        is not False
                        or stat.S_IMODE(opened.st_mode) != 0o500
                    ):
                        raise BuildError(
                            "cleanup tombstone contract drifted"
                        )
                    with _scandir_fd(stage_descriptor) as iterator:
                        if next(iterator, None) is not None:
                            raise BuildError(
                                "cleanup tombstone is not empty"
                            )
                handles.append(
                    (
                        parent_descriptor,
                        stage_descriptor,
                        path.name,
                        identity,
                        tombstone,
                    )
                )
                parent_descriptor = -1
                stage_descriptor = -1
            finally:
                if stage_descriptor >= 0:
                    os.close(stage_descriptor)
                if parent_descriptor >= 0:
                    os.close(parent_descriptor)
        yield
        for (
            parent_descriptor,
            stage_descriptor,
            name,
            identity,
            tombstone,
        ) in handles:
            final_opened = os.fstat(stage_descriptor)
            final_name = (
                final_opened
                if parent_descriptor < 0
                else os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            if (
                not stat.S_ISDIR(final_name.st_mode)
                or (final_name.st_dev, final_name.st_ino) != identity
                or (final_opened.st_dev, final_opened.st_ino) != identity
            ):
                raise BuildError(
                    "retained stage path identity changed during verification"
                )
            if tombstone:
                if (
                    stat.S_IMODE(final_opened.st_mode) != 0o500
                    or stat.S_IMODE(final_name.st_mode) != 0o500
                ):
                    raise BuildError(
                        "cleanup tombstone mode changed during verification"
                    )
                with _scandir_fd(stage_descriptor) as iterator:
                    if next(iterator, None) is not None:
                        raise BuildError(
                            "cleanup tombstone changed during verification"
                        )
    finally:
        for parent_descriptor, stage_descriptor, _, _, _ in reversed(
            handles
        ):
            os.close(stage_descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)


def _primary_and_secondary_failure(
    error: Exception,
) -> tuple[Exception, Exception | None]:
    if isinstance(error, ContextualBuildFailure):
        return _primary_and_secondary_failure(error.primary_error)
    if isinstance(error, CombinedBuildFailure):
        primary, nested_secondary = _primary_and_secondary_failure(
            error.primary_error
        )
        secondary, _ = _primary_and_secondary_failure(
            error.secondary_error
        )
        return primary, nested_secondary or secondary
    return error, None


def _failure_candidate_stage(
    error: Exception,
) -> dict[str, Any] | None:
    if isinstance(error, CombinedBuildFailure):
        if error.candidate_stage is not None:
            return dict(error.candidate_stage)
        return _failure_candidate_stage(error.primary_error)
    if isinstance(error, ContextualBuildFailure):
        if error.candidate_stage is not None:
            return dict(error.candidate_stage)
        return _failure_candidate_stage(error.primary_error)
    return None


def _failure_cleanup_tombstones(
    error: Exception,
) -> list[dict[str, Any]]:
    if isinstance(error, ContextualBuildFailure):
        return [
            *_failure_cleanup_tombstones(error.primary_error),
            *(dict(value) for value in error.cleanup_tombstones),
        ]
    if isinstance(error, CombinedBuildFailure):
        return [
            *_failure_cleanup_tombstones(error.primary_error),
            *_failure_cleanup_tombstones(error.secondary_error),
        ]
    return []


def _persist_build_failure(
    *,
    provider_name: str,
    profile: str,
    output: Path,
    cache: Path,
    engine: str,
    failed_phase: str,
    completed_phases: Sequence[str],
    recipe_sha256: str,
    builder_sha256: str,
    containerfile_sha256: str,
    input_snapshots: Mapping[str, bytes],
    expected_image_tag: str,
    image_id: str | None,
    container_command: Sequence[str] | None,
    success_output_published: bool,
    success_output_parent_fsync_completed: bool,
    publication_destination_installed: bool,
    publication_destination_identity_preserved: bool,
    error: Exception,
    candidate_stage: Mapping[str, Any] | None = None,
    cleanup_tombstones: Sequence[Mapping[str, Any]] = (),
    container_projection: Mapping[str, Any] | None = None,
    direct_stage: Path | None = None,
    direct_stage_identity: tuple[int, int] | None = None,
    direct_retained_stage_descriptors: (
        Mapping[tuple[int, int], int] | None
    ) = None,
) -> Path:
    failure_output = output.with_name(f"{output.name}.failure")
    if failure_output.exists() or failure_output.is_symlink():
        raise BuildError(f"failure evidence already exists: {failure_output}")
    diagnostic_bytes, diagnostic_truncated = _bounded_failure_diagnostic(error)
    primary_error, secondary_error = _primary_and_secondary_failure(error)
    error_candidate_stage = _failure_candidate_stage(error)
    candidate_stage_value = (
        error_candidate_stage
        if error_candidate_stage is not None
        else (
            dict(candidate_stage)
            if candidate_stage is not None
            else _candidate_stage_state(None, None)
        )
    )
    cleanup_tombstone_values: list[dict[str, Any]] = []
    cleanup_tombstone_keys: set[tuple[str, int, int]] = set()
    for value in [
        *(dict(item) for item in cleanup_tombstones),
        *_failure_cleanup_tombstones(error),
    ]:
        path, identity = _validate_stage_identity_record(
            value,
            "cleanup tombstone",
        )
        key = (str(path), identity[0], identity[1])
        if key in cleanup_tombstone_keys:
            continue
        cleanup_tombstone_keys.add(key)
        cleanup_tombstone_values.append(value)
    if (direct_stage is None) != (direct_stage_identity is None):
        raise BuildError("direct failure candidate descriptor set is incomplete")
    if direct_stage is None:
        stage, stage_identity = _create_owned_stage(
            output.parent,
            f".{failure_output.name}.",
        )
    else:
        stage = direct_stage
        stage_identity = direct_stage_identity
        opened = stage.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != stage_identity
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise BuildError("direct failure candidate identity or mode drifted")
        with os.scandir(stage) as iterator:
            if next(iterator, None) is not None:
                raise BuildError("direct failure candidate is not initially empty")
    stage_owned: Path | None = stage
    active_error: Exception | None = None
    try:
        for directory_name in ("inputs", "diagnostics"):
            directory = stage / directory_name
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        snapshot_inputs = {
            "recipe": (
                "provider-payload-recipe-v1.json",
                "inputs/provider-payload-recipe-v1.json",
            ),
            "builder": (
                "build_provider_payload.py",
                "inputs/build_provider_payload.py",
            ),
            "containerfile": (
                "Containerfile",
                "inputs/Containerfile",
            ),
        }
        if set(input_snapshots) != set(BUILD_CONTEXT_PATHS):
            raise BuildError("failure evidence input snapshot set drifted")
        inputs: dict[str, Any] = {}
        for name, (source_logical, retained_logical) in snapshot_inputs.items():
            destination = stage.joinpath(
                *PurePosixPath(retained_logical).parts
            )
            _write_bytes(
                destination,
                input_snapshots[source_logical],
                mode=0o400,
            )
            inputs[name] = _artifact(destination, retained_logical)
        if (
            inputs["recipe"]["sha256"] != recipe_sha256
            or inputs["builder"]["sha256"] != builder_sha256
            or inputs["containerfile"]["sha256"] != containerfile_sha256
        ):
            raise BuildError("failure evidence input snapshot drifted")
        input_identity = _container_input_identity(
            recipe_sha256, builder_sha256, containerfile_sha256
        )
        inputs["container_input_identity_sha256"] = input_identity
        attempt_id = _build_attempt_identity(
            input_identity,
            provider_name,
            profile,
            output,
            cache,
        )
        if container_projection is None:
            container_projection_value = _new_container_projection(
                input_identity=input_identity,
                provider_name=provider_name,
                profile=profile,
                output=output,
                cache=cache,
                image_reference=image_id,
                build_context=_build_context_receipt(input_snapshots),
            )
        else:
            container_projection_value = _copy_container_projection(
                container_projection
            )
        expected_container_command = (
            list(container_command)
            if container_command is not None
            else None
        )
        if (
            container_projection_value["command"]
            != expected_container_command
        ):
            raise BuildError(
                "failure container command differs from its lifecycle projection"
            )
        diagnostic = stage / "diagnostics/failure.txt"
        _write_bytes(diagnostic, diagnostic_bytes, mode=0o400)
        cause_command = (
            list(primary_error.arguments)
            if isinstance(primary_error, CommandFailure)
            else None
        )
        receipt: dict[str, Any] = {
            "schema": FAILURE_RECEIPT_SCHEMA,
            "attempt_id_sha256": attempt_id,
            "provider": provider_name,
            "builder_profile": profile,
            "target_architecture": TARGET_ARCHITECTURE,
            "failed_phase": failed_phase,
            "completed_phases": list(completed_phases),
            "requested_output": str(output),
            "cache_root": str(cache),
            "container_engine": engine,
            "inputs": inputs,
            "image": {
                "expected_tag": expected_image_tag,
                "image_id": image_id,
                "build_context": container_projection_value[
                    "build_context"
                ],
            },
            "container": container_projection_value,
            "cause": {
                "exception_type": type(primary_error).__name__,
                "secondary_exception_type": (
                    type(secondary_error).__name__
                    if secondary_error is not None
                    else None
                ),
                "errno": (
                    primary_error.errno
                    if isinstance(primary_error, OSError)
                    else None
                ),
                "return_code": (
                    primary_error.return_code
                    if isinstance(primary_error, CommandFailure)
                    else None
                ),
                "command": cause_command,
                "destination_installed": publication_destination_installed,
                "destination_identity_preserved": (
                    publication_destination_identity_preserved
                ),
                "parent_fsync_completed": (
                    success_output_parent_fsync_completed
                ),
                "diagnostic": _artifact(
                    diagnostic, "diagnostics/failure.txt"
                ),
                "diagnostic_truncated": diagnostic_truncated,
            },
            "candidate_stage_retained": (
                candidate_stage_value["state"]
                in {
                    "retained_at_owned_path",
                    "empty_cleanup_tombstone_retained",
                }
            ),
            "candidate_stage": candidate_stage_value,
            "cleanup_tombstones": cleanup_tombstone_values,
            "build_succeeded": "container" in completed_phases,
            "builder_output_verified": "verify" in completed_phases,
            "success_output_published": success_output_published,
            "success_output_parent_fsync_completed": (
                success_output_parent_fsync_completed
            ),
            "failure_receipt_is_not_builder_receipt": True,
            "failure_receipt_is_not_execution_attestation": True,
            "product_active": False,
            "listener_backend_wired": False,
            "admission_wired": False,
            "confers_effect_authority": False,
            "receipt_sha256": "",
        }
        receipt["receipt_sha256"] = _failure_receipt_hash(receipt)
        _write_bytes(
            stage / "provider-build-failure-receipt.json",
            _json_bytes(receipt),
            mode=0o400,
        )
        _seal_failure_tree(stage)
        _verify_failure_output(stage, failure_output)
        if direct_stage is None:
            _publish_directory_noreplace(
                stage,
                failure_output,
                stage_identity,
                verifier=lambda descriptor: _verify_failure_output_fd(
                    descriptor,
                    failure_output,
                ),
            )
        else:
            descriptor = os.open(
                stage,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                _fsync_tree_fd(descriptor)
                _verify_failure_output_fd(
                    descriptor,
                    failure_output,
                    retained_stage_descriptors=(
                        direct_retained_stage_descriptors
                    ),
                )
            finally:
                os.close(descriptor)
        stage_owned = None
    except Exception as publication_error:
        active_error = publication_error
        if (
            isinstance(publication_error, PublicationFailure)
            and publication_error.destination_installed
            and publication_error.destination_identity_preserved
        ):
            stage_owned = None
        raise
    finally:
        if stage_owned is not None:
            try:
                tombstone = _cleanup_tombstone_with_role(
                    _cleanup_owned_stage(stage_owned, stage_identity),
                    "failure_evidence_stage",
                )
            except Exception as cleanup_error:
                if active_error is not None:
                    raise CombinedBuildFailure(
                        active_error,
                        cleanup_error,
                        candidate_stage=_candidate_stage_state(
                            stage_owned,
                            stage_identity,
                            "failure_evidence_stage",
                        ),
                    ) from active_error
                raise
            if active_error is not None:
                raise ContextualBuildFailure(
                    active_error,
                    cleanup_tombstones=[tombstone],
                ) from active_error
    if direct_stage is None:
        _verify_failure_output(failure_output)
    else:
        descriptor = os.open(
            direct_stage,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            _verify_failure_output_fd(
                descriptor,
                failure_output,
                retained_stage_descriptors=direct_retained_stage_descriptors,
            )
        finally:
            os.close(descriptor)
    return failure_output


def _public_build(
    provider_name: str,
    profile: str,
    output: Path,
    cache: Path,
    engine: str,
    *,
    supervised: _SupervisedBuildClient | None = None,
) -> None:
    recipe = load_recipe()
    if provider_name not in PROVIDERS or profile not in BUILDER_PROFILES:
        raise BuildError("provider or builder profile is outside the frozen set")
    input_snapshots = _snapshot_build_context()
    try:
        snapshot_recipe = json.loads(
            input_snapshots["provider-payload-recipe-v1.json"].decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("snapshotted provider recipe is malformed") from error
    if snapshot_recipe != recipe:
        raise BuildError("provider recipe changed while freezing build inputs")
    recipe_sha256 = _sha256_bytes(
        input_snapshots["provider-payload-recipe-v1.json"]
    )
    builder_sha256 = _sha256_bytes(
        input_snapshots["build_provider_payload.py"]
    )
    containerfile_sha256 = _sha256_bytes(
        input_snapshots["Containerfile"]
    )
    for source in recipe["bootstrap"].values():
        if (
            isinstance(source, dict)
            and set(source) == {"path", "sha256"}
            and source["path"] in input_snapshots
            and _sha256_bytes(input_snapshots[source["path"]])
            != source["sha256"]
        ):
            raise BuildError("bootstrap source snapshot differs from frozen recipe")
    if supervised is None:
        output = output.resolve(strict=False)
        cache = cache.resolve(strict=False)
    else:
        output = output.absolute()
        cache = cache.resolve(strict=True)
        if output != supervised.output or cache != supervised.cache:
            raise BuildError("supervised logical output or cache drifted")
    failure_output = output.with_name(f"{output.name}.failure")
    if supervised is None:
        if output.exists() or output.is_symlink():
            raise BuildError(f"output directory already exists: {output}")
        if failure_output.exists() or failure_output.is_symlink():
            raise BuildError(f"failure evidence already exists: {failure_output}")
        output.parent.mkdir(parents=True, exist_ok=True)
    _validated_attempt_path(output, "requested output")
    _validated_attempt_path(cache, "cache root")
    expected_image_tag = _container_image_tag(
        recipe_sha256,
        builder_sha256,
        containerfile_sha256,
        profile,
    )
    input_identity = _container_input_identity(
        recipe_sha256,
        builder_sha256,
        containerfile_sha256,
    )
    build_context_record = _build_context_receipt(input_snapshots)
    _verify_build_context_receipt(
        build_context_record,
        snapshots=input_snapshots,
    )
    container_projection = _new_container_projection(
        input_identity=input_identity,
        provider_name=provider_name,
        profile=profile,
        output=output,
        cache=cache,
        image_reference=None,
        build_context=build_context_record,
    )
    completed_phases: list[str] = []
    failed_phase = "prefetch"
    image_id: str | None = None
    container_arguments: list[str] | None = None
    success_output_published = False
    success_output_parent_fsync_completed = False
    publication_destination_installed = False
    publication_destination_identity_preserved = False
    cleanup_tombstones: list[dict[str, Any]] = []
    failure_candidate_stage = _candidate_stage_state(None, None)
    try:
        _prefetch(provider_name, cache, recipe)
        completed_phases.append("prefetch")
        failed_phase = "image"
        (
            image_tag,
            candidate_image_id,
            observed_builder_sha256,
            observed_containerfile_sha256,
            observed_build_context,
        ) = _build_container_image(
            engine,
            profile,
            recipe,
            recipe_sha256,
            input_snapshots,
            builder_sha256,
            containerfile_sha256,
        )
        if (
            image_tag != expected_image_tag
            or observed_builder_sha256 != builder_sha256
            or observed_containerfile_sha256 != containerfile_sha256
            or observed_build_context != build_context_record
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                candidate_image_id,
            )
            is None
        ):
            raise BuildError("builder image input identity drifted")
        image_id = candidate_image_id
        container_projection = _new_container_projection(
            input_identity=input_identity,
            provider_name=provider_name,
            profile=profile,
            output=output,
            cache=cache,
            image_reference=image_id,
            build_context=build_context_record,
        )
        completed_phases.append("image")

        failed_phase = "stage"
        if supervised is None:
            stage, stage_identity = _create_owned_stage(
                output.parent,
                f".{output.name}.",
            )
        else:
            stage = supervised.success_path
            opened_stage = os.fstat(supervised.success_descriptor)
            stage_identity = (opened_stage.st_dev, opened_stage.st_ino)
            with os.scandir(stage) as iterator:
                if next(iterator, None) is not None:
                    raise BuildError("supervised success candidate is not initially empty")
        completed_phases.append("stage")
        failed_phase = "container"
        stage_owned: Path | None = stage
        stage_error: Exception | None = None
        try:
            custody: _ContainerCidfileCustody | None = None
            attempt_id = container_projection["attempt_id_sha256"]
            try:
                try:
                    custody = (
                        _prepare_container_cidfile_custody(
                            output,
                            attempt_id,
                        )
                        if supervised is None
                        else supervised.allocate_container_custody(attempt_id)
                    )
                except Exception:
                    container_projection["cidfile"][
                        "state"
                    ] = "custody_preparation_rejected"
                    raise
                container_projection["cidfile"].update(
                    {
                        "custody_directory_identity": (
                            _container_custody_identity_record(
                                custody.identity
                            )
                        ),
                        "state": "prepared_not_invoked",
                        "pre_run_absent_no_symlink": True,
                    }
                )
                container_arguments = _provider_container_command(
                    engine=engine,
                    provider_name=provider_name,
                    profile=profile,
                    image_id=image_id,
                    recipe_sha256=recipe_sha256,
                    builder_sha256=builder_sha256,
                    containerfile_sha256=containerfile_sha256,
                    attempt_id=attempt_id,
                    output=output,
                    cache=cache,
                    stage=(
                        stage
                        if supervised is None
                        else supervised.success_host_path
                    ),
                    container_name=container_projection["name"],
                    cidfile_host_path=custody.cidfile_path,
                    run_user=f"{os.getuid()}:{os.getgid()}",
                    build_context_tar_sha256=build_context_record[
                        "tar_sha256"
                    ],
                    build_context_tar_byte_length=build_context_record[
                        "tar_byte_length"
                    ],
                    build_context_member_manifest_sha256=(
                        build_context_record[
                            "member_manifest_sha256"
                        ]
                    ),
                )
                container_projection["command"] = list(container_arguments)
                _validate_provider_container_command(
                    container_arguments,
                    "provider container command",
                )
                try:
                    _assert_container_cidfile_absent(custody)
                except Exception:
                    container_projection["cidfile"].update(
                        {
                            "state": "pre_run_entry_rejected",
                            "pre_run_absent_no_symlink": False,
                        }
                    )
                    raise
                container_projection["run_invoked"] = True
                try:
                    _run(
                        container_arguments,
                        cwd=DIRECTORY,
                        maximum_output=512 * 1024,
                    )
                except Exception as run_error:
                    try:
                        (
                            container_projection,
                            custody_tombstone,
                        ) = _finalize_container_cidfile_custody(
                            custody,
                            container_projection,
                            command=container_arguments,
                            completed_zero=False,
                            expected_container_id=None,
                            captured_state="captured_after_failed_run",
                            allow_absent=True,
                        )
                        cleanup_tombstones.append(custody_tombstone)
                    except ContainerCustodyError as custody_error:
                        container_projection = (
                            custody_error.container_projection
                        )
                        raise CombinedBuildFailure(
                            run_error,
                            custody_error,
                        ) from run_error
                    raise
                container_projection["completed_zero"] = True
                completed_phases.append("container")
                failed_phase = "verify"
                try:
                    pending_receipt = _verify_pending_container_output(
                        stage,
                        custody,
                    )
                except Exception as pending_error:
                    try:
                        (
                            container_projection,
                            custody_tombstone,
                        ) = _finalize_container_cidfile_custody(
                            custody,
                            container_projection,
                            command=container_arguments,
                            completed_zero=True,
                            expected_container_id=None,
                            captured_state=(
                                "captured_after_zero_exit_without_crosscheck"
                            ),
                            allow_absent=False,
                        )
                        cleanup_tombstones.append(custody_tombstone)
                    except ContainerCustodyError as custody_error:
                        container_projection = (
                            custody_error.container_projection
                        )
                        raise CombinedBuildFailure(
                            pending_error,
                            custody_error,
                        ) from pending_error
                    raise
                try:
                    (
                        container_projection,
                        custody_tombstone,
                    ) = _finalize_container_cidfile_custody(
                        custody,
                        container_projection,
                        command=container_arguments,
                        completed_zero=True,
                        expected_container_id=pending_receipt["container"][
                            "id"
                        ],
                        captured_state="captured_after_success",
                        allow_absent=False,
                    )
                    cleanup_tombstones.append(custody_tombstone)
                except ContainerCustodyError as custody_error:
                    container_projection = (
                        custody_error.container_projection
                    )
                    raise
                _rewrite_builder_container_projection(
                    stage,
                    pending_receipt,
                    container_projection,
                )
            finally:
                if custody is not None:
                    custody.close()
            _verify_builder_output(stage)
            completed_phases.append("verify")
            failed_phase = "cleanup"
            for private in (
                stage / ".home",
                stage / ".cargo-home",
                stage / ".work",
            ):
                if private.exists():
                    shutil.rmtree(private)
            completed_phases.append("cleanup")
            failed_phase = "publish"
            if supervised is None:
                _publish_directory_noreplace(
                    stage,
                    output,
                    stage_identity,
                    verifier=_verify_builder_output_fd,
                )
            else:
                _fsync_tree_fd(supervised.success_descriptor)
                _verify_builder_output_fd(supervised.success_descriptor)
                supervised.ready(
                    role=SUPERVISOR_ROLE_SUCCESS,
                    descriptor=supervised.success_descriptor,
                    worker_status=0,
                    container_name=container_projection["name"],
                    container_id=container_projection["id"],
                )
            stage_owned = None
            success_output_published = supervised is None
            success_output_parent_fsync_completed = supervised is None
            completed_phases.append("publish")
        except Exception as error:
            stage_error = error
            if (
                isinstance(error, PublicationFailure)
                and error.destination_installed
            ):
                if error.destination_identity_preserved:
                    stage_owned = None
                else:
                    stage_owned = None
                    raise CombinedBuildFailure(
                        error,
                        BuildError(
                            "published candidate identity was replaced"
                        ),
                        candidate_stage=_candidate_stage_state(
                            output,
                            stage_identity,
                            "provider_output_stage",
                        ),
                    ) from error
            raise
        finally:
            if stage_owned is not None and supervised is None:
                try:
                    tombstone = _cleanup_tombstone_with_role(
                        _cleanup_owned_stage(stage_owned, stage_identity),
                        "provider_output_stage",
                    )
                    cleanup_tombstones.append(tombstone)
                    failure_candidate_stage = (
                        _candidate_stage_from_cleanup_tombstone(tombstone)
                    )
                except Exception as cleanup_error:
                    if stage_error is not None:
                        raise CombinedBuildFailure(
                            stage_error,
                            cleanup_error,
                            candidate_stage=_candidate_stage_state(
                                stage_owned,
                                stage_identity,
                                "provider_output_stage",
                            ),
                        ) from stage_error
                    raise
    except Exception as error:
        primary_error, _ = _primary_and_secondary_failure(error)
        if (
            isinstance(primary_error, PublicationFailure)
            and failed_phase == "publish"
        ):
            publication_destination_installed = (
                primary_error.destination_installed
            )
            publication_destination_identity_preserved = (
                primary_error.destination_identity_preserved
            )
            success_output_published = (
                primary_error.destination_installed
                and primary_error.destination_identity_preserved
            )
            success_output_parent_fsync_completed = (
                primary_error.parent_fsync_completed
            )
        try:
            _persist_build_failure(
                provider_name=provider_name,
                profile=profile,
                output=output,
                cache=cache,
                engine=engine,
                failed_phase=failed_phase,
                completed_phases=completed_phases,
                recipe_sha256=recipe_sha256,
                builder_sha256=builder_sha256,
                containerfile_sha256=containerfile_sha256,
                input_snapshots=input_snapshots,
                expected_image_tag=expected_image_tag,
                image_id=image_id,
                container_command=container_arguments,
                success_output_published=success_output_published,
                success_output_parent_fsync_completed=(
                    success_output_parent_fsync_completed
                ),
                publication_destination_installed=(
                    publication_destination_installed
                ),
                publication_destination_identity_preserved=(
                    publication_destination_identity_preserved
                ),
                error=error,
                candidate_stage=failure_candidate_stage,
                cleanup_tombstones=cleanup_tombstones,
                container_projection=container_projection,
                direct_stage=(
                    None if supervised is None else supervised.failure_path
                ),
                direct_stage_identity=(
                    None
                    if supervised is None
                    else (
                        os.fstat(supervised.failure_descriptor).st_dev,
                        os.fstat(supervised.failure_descriptor).st_ino,
                    )
                ),
                direct_retained_stage_descriptors=(
                    None
                    if supervised is None
                    or supervised.cid_descriptor < 0
                    else {
                        (
                            os.fstat(supervised.cid_descriptor).st_dev,
                            os.fstat(supervised.cid_descriptor).st_ino,
                        ): supervised.cid_descriptor
                    }
                ),
            )
        except Exception as evidence_error:
            raise CombinedBuildFailure(error, evidence_error) from error
        if supervised is not None:
            supervised.ready(
                role=SUPERVISOR_ROLE_FAILURE,
                descriptor=supervised.failure_descriptor,
                worker_status=1,
                container_name=container_projection["name"],
                container_id=container_projection["id"],
            )
        raise


def _base_environment(recipe: Mapping[str, Any]) -> dict[str, str]:
    return {
        "HOME": "/output/.home",
        "CARGO_HOME": "/output/.cargo-home",
        "CARGO_TARGET_DIR": "/output/.work/target",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": str(recipe["source_date_epoch"]),
        "PATH": "/opt/zig:/usr/local/bin:/usr/bin:/bin",
        "RUSTUP_HOME": "/usr/local/rustup",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def _provider_resource_contract(
    provider_name: str,
    provider: Mapping[str, Any],
) -> dict[str, Any]:
    if provider_name != "codex":
        raise BuildError(f"provider has no frozen resource contract: {provider_name}")
    return {
        "build_jobs": provider["build_jobs"],
        "cargo_profile": dict(provider["cargo_profile"]),
        "linker_threads": provider["linker_threads"],
    }


def _codex_profile_environment(
    provider: Mapping[str, Any],
) -> dict[str, str]:
    profile = provider["cargo_profile"]
    name = profile["name"]
    if name != "release":
        raise BuildError("Codex Cargo profile name is not frozen")
    prefix = f"CARGO_PROFILE_{name.upper()}_"
    debug = {"none": "0"}.get(profile["debug"])
    if debug is None:
        raise BuildError("Codex Cargo debug profile is not frozen")
    if not isinstance(profile["incremental"], bool):
        raise BuildError("Codex Cargo incremental profile is malformed")
    if not isinstance(profile["lto"], bool):
        raise BuildError("Codex Cargo LTO profile is malformed")
    if (
        not isinstance(profile["codegen_units"], int)
        or isinstance(profile["codegen_units"], bool)
        or profile["codegen_units"] <= 0
    ):
        raise BuildError("Codex Cargo codegen-unit profile is malformed")
    if not isinstance(profile["strip"], bool):
        raise BuildError("Codex Cargo strip profile is malformed")
    incremental = str(profile["incremental"]).lower()
    return {
        "CARGO_INCREMENTAL": "1" if profile["incremental"] else "0",
        f"{prefix}CODEGEN_UNITS": str(profile["codegen_units"]),
        f"{prefix}DEBUG": debug,
        f"{prefix}INCREMENTAL": incremental,
        f"{prefix}LTO": str(profile["lto"]).lower(),
        f"{prefix}STRIP": str(profile["strip"]).lower(),
    }


def _codex_rust_flags(
    provider: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    link_map: Path,
) -> list[str]:
    return [
        "-C",
        f"link-arg={bootstrap['core']}",
        "-C",
        f"link-arg={bootstrap['mechanism']}",
        "-C",
        "link-arg=-Wl,-e,trillionnium_provider_post_final_exec_entry",
        "-C",
        f"link-arg=-Wl,-Map,{link_map}",
        "-C",
        "link-arg=-Wl,--build-id=sha1",
        "-C",
        f"link-arg=-Wl,--threads={provider['linker_threads']}",
        "-C",
        "link-arg=-Wl,-z,noexecstack",
        "--remap-path-prefix=/output/.work=/usr/src/trillionnium-provider",
        "--remap-path-prefix=/output/.cargo-home=/usr/src/cargo-home",
    ]


def _codex_build_command(
    cargo_executable: Path,
    cargo_config: str,
    provider: Mapping[str, Any],
) -> list[str]:
    return [
        str(cargo_executable),
        "--config",
        cargo_config,
        "build",
        "--jobs",
        str(provider["build_jobs"]),
        "--frozen",
        "--release",
        "--target",
        provider["cargo_target"],
        "--package",
        provider["cargo_package"],
        "--bin",
        provider["cargo_binary"],
    ]


def _codex_toolchain_paths(
    rust_version: str,
    profile: str,
) -> tuple[Path, Path]:
    host_triples = {
        "amd64-cross": "x86_64-unknown-linux-gnu",
        "arm64-native": "aarch64-unknown-linux-gnu",
    }
    host_triple = host_triples.get(profile)
    if host_triple is None:
        raise BuildError("Codex builder profile has no frozen Rust host triple")
    toolchain = (
        Path("/usr/local/rustup/toolchains")
        / f"{rust_version}-{host_triple}"
        / "bin"
    )
    return toolchain / "cargo", toolchain / "rustc"


def _expected_provider_build_command(
    recipe: Mapping[str, Any],
    provider_name: str,
    profile: str,
) -> list[str]:
    provider = recipe["providers"][provider_name]
    if provider_name != "codex":
        raise BuildError(
            f"provider has no frozen expected build command: {provider_name}"
        )
    cargo_executable, _rustc_executable = _codex_toolchain_paths(
        recipe["builder"]["rust_version"],
        profile,
    )
    return _codex_build_command(
        cargo_executable,
        "/output/.work/cargo-source-config.toml",
        provider,
    )


def _codex_target_toolchain_wrapper_paths(
    root: Path,
) -> dict[str, tuple[Path, bytes]]:
    return {
        role: (root / filename, content)
        for role, (filename, content) in CODEX_TARGET_TOOLCHAIN_WRAPPERS.items()
    }


def _static_library_consumption_projection(
    value: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "name": value["name"],
        "policy": value["policy"],
        "linker_archive_path": value["linker_archive_path"],
        "archive": value["archive"],
        "archive_architecture": value["archive_architecture"],
        "consumed_members": value["consumed_members"],
        "link_map_member_references": value["link_map_member_references"],
        "link_map_member_reference_count": value[
            "link_map_member_reference_count"
        ],
        "post_link_archive_sha256": value["post_link_archive_sha256"],
        "consumed": value["consumed"],
    }


def _normalized_static_library(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **_static_library_consumption_projection(value),
        "consumption_proof_sha256": value["consumption_proof_sha256"],
    }


def _normalized_static_libraries(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [_normalized_static_library(value) for value in values]


def _bootstrap_compile_arguments(
    recipe: Mapping[str, Any], provider: Mapping[str, Any]
) -> list[str]:
    arguments = list(recipe["bootstrap"]["codex_compiler_arguments"])
    arguments.extend(
        [
            "-I",
            "/recipe/include",
            f"-DTRILLIONNIUM_EXPECTED_UID={provider['expected_uid']}",
            f"-DTRILLIONNIUM_EXPECTED_GID={provider['expected_gid']}",
        ]
    )
    return arguments


def _compile_bootstrap(
    recipe: Mapping[str, Any],
    provider_name: str,
    profile: str,
    build: Path,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    provider = recipe["providers"][provider_name]
    if provider_name != "codex":
        raise BuildError("bootstrap compiler is outside the Codex singleton")
    compiler = ["/opt/zig/zig", "cc"]
    arguments = _bootstrap_compile_arguments(recipe, provider)
    _validate_arguments(arguments)

    core = build / "provider-post-exec-bootstrap.o"
    preprocessed = build / "provider-post-exec-bootstrap.i"
    macros = build / "provider-post-exec-bootstrap.macros"
    core_source = "/recipe/src/provider_post_exec_bootstrap.c"
    _run(
        [*compiler, *arguments, "-E", core_source, "-o", str(preprocessed)],
        cwd=build,
        environment=environment,
    )
    _run(
        [*compiler, *arguments, "-dM", "-E", core_source, "-o", str(macros)],
        cwd=build,
        environment=environment,
    )
    _run(
        [*compiler, *arguments, "-c", core_source, "-o", str(core)],
        cwd=build,
        environment=environment,
    )
    mechanism = build / "provider-post-exec-entry.o"
    mechanism_source = "/recipe/src/provider_post_exec_entry.S"
    _run(
        [*compiler, *arguments, "-c", mechanism_source, "-o", str(mechanism)],
        cwd=build,
        environment=environment,
    )

    relocations = build / "provider-post-exec-bootstrap.relocations"
    relocation_output = _run(
        ["readelf", "--relocs", "--wide", str(core)],
        cwd=build,
        environment=environment,
    )
    _write_bytes(relocations, relocation_output.encode("utf-8"))
    sections = _run(
        ["readelf", "--sections", "--wide", str(core)],
        cwd=build,
        environment=environment,
    )
    symbols = _run(
        ["readelf", "--symbols", "--wide", str(core)],
        cwd=build,
        environment=environment,
    )
    undefined = [
        line
        for line in symbols.splitlines()
        if re.search(r"\bUND\b", line) and not re.match(r"\s*0:", line)
    ]
    forbidden_sections = [
        name
        for name in (".tdata", ".tbss", ".plt", ".plt.got", ".got", ".got.plt")
        if re.search(rf"\b{re.escape(name)}\b", sections)
    ]
    if (
        undefined
        or forbidden_sections
        or "__stack_chk" in symbols
        or "IFUNC" in symbols
    ):
        raise BuildError(
            "freestanding bootstrap object retained undefined/TLS/PLT/GOT/"
            "stack-protector/IFUNC state"
        )
    return {
        "compiler_command": compiler,
        "compiler_arguments": arguments,
        "core": core,
        "mechanism": mechanism,
        "preprocessed": preprocessed,
        "macros": macros,
        "relocations": relocations,
        "closure": {
            "undefined_symbol_count": 0,
            "tls_section_count": 0,
            "plt_section_count": 0,
            "got_section_count": 0,
            "ifunc_symbol_count": 0,
            "init_dependency_count": 0,
            "preinit_dependency_count": 0,
            "stack_protector_reference_count": 0,
            "unexpected_relocation_count": 0,
        },
    }


def _codex_build(
    recipe: Mapping[str, Any],
    profile: str,
    source: Path,
    build: Path,
    bootstrap: Mapping[str, Any],
    environment: dict[str, str],
    codex_inputs: dict[str, Any],
) -> tuple[Path, Path, list[str], dict[str, str]]:
    provider = recipe["providers"]["codex"]
    cargo_executable, rustc_executable = _codex_toolchain_paths(
        recipe["builder"]["rust_version"],
        profile,
    )
    link_map = build / "final.map"
    target_toolchain = build / "target-toolchain"
    target_toolchain.mkdir()
    wrappers = _codex_target_toolchain_wrapper_paths(target_toolchain)
    for path, content in wrappers.values():
        _write_bytes(path, content, mode=0o555)
    linker_wrapper = wrappers["linker"][0]
    rust_flags = _codex_rust_flags(provider, bootstrap, link_map)
    build_environment = dict(environment)
    build_environment.update(
        {
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": str(linker_wrapper),
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(rust_flags),
            "CARGO_NET_OFFLINE": "true",
            "AWS_LC_SYS_CMAKE_BUILDER": "0",
            "AWS_LC_SYS_NO_JITTER_ENTROPY": "1",
            "CC_aarch64_unknown_linux_musl": str(wrappers["cc"][0]),
            "CXX_aarch64_unknown_linux_musl": str(wrappers["cxx"][0]),
            "AR_aarch64_unknown_linux_musl": str(wrappers["ar"][0]),
            "RANLIB_aarch64_unknown_linux_musl": str(wrappers["ranlib"][0]),
            "CFLAGS_aarch64_unknown_linux_musl": (
                "-pthread -Wno-error=frame-larger-than"
            ),
            "CXXFLAGS_aarch64_unknown_linux_musl": (
                "-pthread -Wno-error=frame-larger-than"
            ),
            "CMAKE_GENERATOR": "Ninja",
            "HOST_CC": "/usr/bin/gcc",
            "HOST_CXX": "/usr/bin/g++",
            "HOST_AR": "/usr/bin/ar",
            "HOST_RANLIB": "/usr/bin/ranlib",
            "PATH": (
                f"{target_toolchain}:{cargo_executable.parent}:"
                f"{environment['PATH']}"
            ),
            "RUSTUP_HOME": "/usr/local/rustup",
            "RUSTUP_TOOLCHAIN": recipe["builder"]["rust_version"],
            "RUSTC": str(rustc_executable),
            "RUSTY_V8_ARCHIVE": str(codex_inputs["rusty_v8_archive"]),
            "RUSTY_V8_SRC_BINDING_PATH": str(codex_inputs["rusty_v8_binding"]),
            **_codex_profile_environment(provider),
        }
    )
    cargo_config = str(codex_inputs["cargo_source_config"])
    metadata_command = [
        str(cargo_executable),
        "--config",
        cargo_config,
        "metadata",
        "--frozen",
        "--format-version",
        "1",
        "--filter-platform",
        provider["cargo_target"],
    ]
    metadata_output = _run(
        metadata_command,
        cwd=source / provider["source_subdirectory"],
        environment=build_environment,
        maximum_output=32 * 1024 * 1024,
    )
    _verify_codex_metadata_features(metadata_output, provider)
    codex_inputs["cargo_metadata_command"] = metadata_command
    command = _codex_build_command(cargo_executable, cargo_config, provider)
    _run(
        command,
        cwd=source / provider["source_subdirectory"],
        environment=build_environment,
        maximum_output=1024 * 1024,
    )
    post_inventory = _source_inventory_digest(source)
    if post_inventory != codex_inputs["source_inventory_sha256"]:
        raise BuildError("Codex derived source changed during the frozen build")
    if (
        _sha256_file(
            codex_inputs["derived_lock"],
            MAX_SOURCE_ARCHIVE_BYTES,
        )
        != provider["derived_lock"]["derived_sha256"]
    ):
        raise BuildError("Codex derived Cargo.lock changed during the frozen build")
    codex_inputs["post_build_source_inventory_sha256"] = post_inventory
    post_vendor_inventory = _verify_vendor_member_manifest(
        codex_inputs["cargo_vendor_root"],
        codex_inputs["cargo_vendor_member_manifest"],
        provider,
    )
    if post_vendor_inventory != codex_inputs["cargo_vendor_inventory_sha256"]:
        raise BuildError("Codex Cargo vendor tree changed during the frozen build")
    codex_inputs["post_build_vendor_inventory_sha256"] = post_vendor_inventory
    final_elf = (
        Path(build_environment["CARGO_TARGET_DIR"])
        / provider["cargo_target"]
        / "release"
        / provider["cargo_binary"]
    )
    if not link_map.is_file():
        raise BuildError("Codex linker did not emit the required link map")
    return final_elf, link_map, command, build_environment


def _readelf(path: Path, *arguments: str) -> str:
    return _run(
        ["readelf", *arguments, str(path)],
        cwd=path.parent,
        maximum_output=MAX_COMPLETE_INSPECTION_OUTPUT_BYTES,
        require_complete_output=True,
    )


def _inventory_sha256(lines: Iterable[str]) -> str:
    normalized = "".join(f"{line.rstrip()}\n" for line in lines).encode("utf-8")
    return _sha256_bytes(b"org.trillionnium.elf-inventory.v1\0" + normalized)


def _symbol_facts(symbols: str, name: str) -> dict[str, Any]:
    tables: dict[str, list[dict[str, Any]]] = {
        ".dynsym": [],
        ".symtab": [],
    }
    current_table: str | None = None
    for line in symbols.splitlines():
        table_match = re.match(r"^Symbol table '([^']+)' contains ", line)
        if table_match is not None:
            current_table = (
                table_match.group(1)
                if table_match.group(1) in tables
                else None
            )
            continue
        fields = line.split()
        if len(fields) < 8 or fields[-1] != name or not fields[0].endswith(":"):
            continue
        # GNU readelf names STT_SECTION rows after their section.  A section
        # such as `.text.<symbol>` can therefore produce a SECTION row whose
        # displayed name is byte-for-byte identical to the real FUNC symbol.
        # Likewise, an undefined dynsym presentation is not a definition.
        # Count only defined program symbols here; identical symtab/dynsym
        # presentations are deduplicated below.
        if fields[3] in {"SECTION", "FILE"} or fields[6] == "UND":
            continue
        if current_table is None:
            raise BuildError(
                f"final ELF {name} definition is outside .symtab/.dynsym"
            )
        try:
            tables[current_table].append(
                {
                    "address": int(fields[1], 16),
                    "size": int(fields[2], 10),
                    "type": fields[3],
                    "binding": fields[4],
                    "visibility": fields[5],
                    "section": fields[6],
                }
            )
        except ValueError as error:
            raise BuildError(
                f"final ELF contains a malformed {name} symbol row"
            ) from error
    if any(len(matches) > 1 for matches in tables.values()):
        raise BuildError(f"final ELF must contain exactly one {name} symbol")
    matches = [
        table_matches[0]
        for table_matches in tables.values()
        if table_matches
    ]
    if not matches or any(match != matches[0] for match in matches[1:]):
        raise BuildError(f"final ELF must contain exactly one {name} symbol")
    return matches[0]


def _is_nonpreemptible_definition(
    symbol: Mapping[str, Any],
    expected_type: str,
) -> bool:
    # GNU ld may internalize a GLOBAL/HIDDEN definition that is linked
    # directly into an executable as LOCAL/DEFAULT.  Both final-ELF
    # presentations are non-preemptible; GLOBAL/DEFAULT is not.  Callers that
    # require a stronger pre-link-object identity must verify it separately.
    return (
        symbol["type"] == expected_type
        and (
            (
                symbol["binding"] == "GLOBAL"
                and symbol["visibility"] == "HIDDEN"
            )
            or (
                symbol["binding"] == "LOCAL"
                and symbol["visibility"] in {"DEFAULT", "HIDDEN"}
            )
        )
    )


def _new_section_memfd(label: str) -> int:
    memfd_create = getattr(os, "memfd_create", None)
    cloexec = getattr(os, "MFD_CLOEXEC", None)
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
    if memfd_create is None or cloexec is None or allow_sealing is None:
        raise BuildError("sealed private ELF-section extraction is unavailable")
    descriptor = -1
    try:
        descriptor = memfd_create(
            f"trillionnium-provider-{label}",
            cloexec | allow_sealing,
        )
        os.fchmod(descriptor, 0o600)
        return descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise BuildError("sealed private ELF-section extraction is unavailable") from error


def _measure_section_memfd(
    descriptor: int,
    label: str,
    *,
    allow_empty: bool = False,
) -> tuple[os.stat_result, str]:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 0
        or before.st_size < 0
        or (before.st_size == 0 and not allow_empty)
        or before.st_size > MAX_ARTIFACT_BYTES
    ):
        raise BuildError(f"private {label} is not one bounded anonymous inode")
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            raise BuildError(f"private {label} ended before its recorded length")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, before.st_size):
        raise BuildError(f"private {label} exceeds its recorded length")
    after = os.fstat(descriptor)
    if _fd_identity(before) != _fd_identity(after):
        raise BuildError(f"private {label} changed while measured")
    return after, digest.hexdigest()


def _seal_section_memfd(
    descriptor: int,
    label: str,
) -> tuple[os.stat_result, str]:
    os.fchmod(descriptor, 0o400)
    before, digest = _measure_section_memfd(descriptor, label)
    required_seals = (
        fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_SEAL
    )
    try:
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required_seals)
    except OSError as error:
        raise BuildError(f"private {label} could not be sealed") from error
    after, after_digest = _measure_section_memfd(descriptor, label)
    if (
        fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != required_seals
        or _fd_identity(before) != _fd_identity(after)
        or digest != after_digest
    ):
        raise BuildError(f"private {label} changed while sealing")
    return after, digest


def _measure_named_source_fd(
    descriptor: int,
    path: Path,
    expected: os.stat_result,
    expected_sha256: str,
) -> None:
    observed = os.fstat(descriptor)
    try:
        named = path.stat(follow_symlinks=False)
    except OSError as error:
        raise BuildError("ELF section source name became unavailable") from error
    if (
        _fd_identity(observed) != _fd_identity(expected)
        or _fd_identity(named) != _fd_identity(expected)
    ):
        raise BuildError("ELF section source identity changed during extraction")
    digest = hashlib.sha256()
    offset = 0
    while offset < expected.st_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, expected.st_size - offset),
            offset,
        )
        if not chunk:
            raise BuildError("ELF section source ended before its recorded length")
        digest.update(chunk)
        offset += len(chunk)
    try:
        named_after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise BuildError("ELF section source name became unavailable") from error
    if (
        os.pread(descriptor, 1, expected.st_size)
        or digest.hexdigest() != expected_sha256
        or _fd_identity(os.fstat(descriptor)) != _fd_identity(expected)
        or _fd_identity(named_after) != _fd_identity(expected)
    ):
        raise BuildError("ELF section source bytes changed during extraction")


def _link_unnamed_fd_noreplace(
    source_descriptor: int,
    parent_descriptor: int,
    destination_name: str,
) -> None:
    if (
        not destination_name
        or destination_name != PurePosixPath(destination_name).name
        or "\0" in destination_name
    ):
        raise BuildError("ELF section destination name is unsafe")
    source = os.fstat(source_descriptor)
    if not stat.S_ISREG(source.st_mode) or source.st_nlink != 0:
        raise BuildError("ELF section publication source is not unnamed")
    parent = os.fstat(parent_descriptor)
    if not stat.S_ISDIR(parent.st_mode):
        raise BuildError("ELF section publication parent is not retained")
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = getattr(libc, "linkat", None)
    if linkat is None:
        raise BuildError("retained-inode no-replace publication is unavailable")
    linkat.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    )
    linkat.restype = ctypes.c_int
    destination_bytes = destination_name.encode("utf-8")
    result = linkat(
        source_descriptor,
        b"",
        parent_descriptor,
        destination_bytes,
        AT_EMPTY_PATH,
    )
    if result != 0:
        empty_path_errno = ctypes.get_errno()
        if empty_path_errno not in {
            errno.EPERM,
            errno.EINVAL,
            errno.ENOENT,
            errno.ENOSYS,
        }:
            raise BuildError(
                "retained-inode no-replace publication failed: "
                f"{os.strerror(empty_path_errno)}"
            )
        proc_source = f"/proc/self/fd/{source_descriptor}".encode("ascii")
        result = linkat(
            AT_FDCWD,
            proc_source,
            parent_descriptor,
            destination_bytes,
            AT_SYMLINK_FOLLOW,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            raise BuildError(
                "retained-inode no-replace publication failed: "
                f"{os.strerror(error_number)}"
            )
    linked = os.fstat(source_descriptor)
    named = os.stat(
        destination_name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if (
        linked.st_dev != source.st_dev
        or linked.st_ino != source.st_ino
        or linked.st_nlink != 1
        or named.st_dev != linked.st_dev
        or named.st_ino != linked.st_ino
    ):
        raise BuildError("retained-inode publication identity drifted")


def _extract_section(path: Path, section: str, destination: Path) -> None:
    if (
        re.fullmatch(r"\.[A-Za-z0-9_.-]{1,127}", section) is None
        or destination.name != PurePosixPath(destination.name).name
        or not destination.name
        or "\0" in destination.name
    ):
        raise BuildError("ELF section extraction arguments are unsafe")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_descriptor = -1
    input_descriptor = -1
    output_descriptor = -1
    section_descriptor = -1
    parent_descriptor = -1
    destination_descriptor = -1
    unnamed_created = False
    stage_identity: tuple[int, ...] | None = None
    destination_published = False
    try:
        source_descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        source_before = os.fstat(source_descriptor)
        try:
            named_before = path.stat(follow_symlinks=False)
        except OSError as error:
            raise BuildError("ELF section source name is unavailable") from error
        if (
            not stat.S_ISREG(source_before.st_mode)
            or source_before.st_nlink != 1
            or source_before.st_size <= 0
            or source_before.st_size > MAX_ARTIFACT_BYTES
            or _fd_identity(named_before) != _fd_identity(source_before)
        ):
            raise BuildError("ELF section source is not one bounded regular inode")

        input_descriptor = _new_section_memfd("section-input")
        copied_bytes, source_sha256 = _copy_descriptor_bytes(
            source_descriptor,
            input_descriptor,
        )
        if copied_bytes != source_before.st_size:
            raise BuildError("ELF section source length changed while retained")
        _measure_named_source_fd(
            source_descriptor,
            path,
            source_before,
            source_sha256,
        )
        input_before, input_sha256 = _seal_section_memfd(
            input_descriptor,
            "ELF input copy",
        )
        if (
            input_before.st_size != source_before.st_size
            or input_sha256 != source_sha256
        ):
            raise BuildError("private ELF section input differs from its source")

        output_descriptor = _new_section_memfd("section-objcopy-output")
        section_descriptor = _new_section_memfd("section-bytes")
        objcopy = shutil.which("aarch64-linux-gnu-objcopy") or shutil.which(
            "objcopy"
        )
        if objcopy is None or not Path(objcopy).is_absolute():
            raise BuildError("ELF section extractor is unavailable")
        _run(
            [
                objcopy,
                "--dump-section",
                f"{section}=/proc/self/fd/{section_descriptor}",
                f"/proc/self/fd/{input_descriptor}",
                f"/proc/self/fd/{output_descriptor}",
            ],
            cwd=Path("/"),
            pass_descriptors=(
                input_descriptor,
                output_descriptor,
                section_descriptor,
            ),
        )
        _measure_named_source_fd(
            source_descriptor,
            path,
            source_before,
            source_sha256,
        )
        input_after, input_after_sha256 = _measure_section_memfd(
            input_descriptor,
            "ELF input copy",
        )
        required_seals = (
            fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_SEAL
        )
        if (
            _fd_identity(input_after) != _fd_identity(input_before)
            or input_after_sha256 != input_sha256
            or fcntl.fcntl(input_descriptor, fcntl.F_GET_SEALS)
            != required_seals
        ):
            raise BuildError("private ELF section input changed during objcopy")
        _seal_section_memfd(output_descriptor, "objcopy output")
        section_before, section_sha256 = _seal_section_memfd(
            section_descriptor,
            "extracted section",
        )

        parent_descriptor = os.open(
            destination.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        parent_before = os.fstat(parent_descriptor)
        parent_named = destination.parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or _fd_identity(parent_named) != _fd_identity(parent_before)
        ):
            raise BuildError("ELF section destination parent is aliased")
        temporary_flag = getattr(os, "O_TMPFILE", None)
        if not isinstance(temporary_flag, int):
            raise BuildError("unnamed ELF section staging is unavailable")
        destination_descriptor = os.open(
            ".",
            os.O_RDWR
            | temporary_flag
            | os.O_CLOEXEC
            | os.O_NONBLOCK,
            0o400,
            dir_fd=parent_descriptor,
        )
        unnamed_created = True
        stage_opened = os.fstat(destination_descriptor)
        stage_identity = _fd_identity(stage_opened)
        if (
            not stat.S_ISREG(stage_opened.st_mode)
            or stage_opened.st_nlink != 0
            or stage_opened.st_size != 0
        ):
            raise BuildError("unnamed ELF section staging inode is unsafe")
        copied_bytes, copied_sha256 = _copy_descriptor_bytes(
            section_descriptor,
            destination_descriptor,
        )
        os.fchmod(destination_descriptor, 0o400)
        stage_after = os.fstat(destination_descriptor)
        stage_identity = _fd_identity(stage_after)
        if (
            not stat.S_ISREG(stage_after.st_mode)
            or stage_after.st_nlink != 0
            or copied_bytes != section_before.st_size
            or copied_sha256 != section_sha256
        ):
            raise BuildError("unnamed ELF section staging inode drifted")
        _measure_named_source_fd(
            source_descriptor,
            path,
            source_before,
            source_sha256,
        )
        _link_unnamed_fd_noreplace(
            destination_descriptor,
            parent_descriptor,
            destination.name,
        )
        destination_published = True
        os.fsync(parent_descriptor)
        published_after = os.fstat(destination_descriptor)
        stage_identity = _fd_identity(published_after)
        named_destination = os.stat(
            destination.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        parent_after = os.fstat(parent_descriptor)
        parent_named_after = destination.parent.stat(follow_symlinks=False)
        if (
            _fd_identity(named_destination) != stage_identity
            or _fd_identity(parent_after)[:6] != _fd_identity(parent_before)[:6]
            or _fd_identity(parent_named_after)[:6]
            != _fd_identity(parent_after)[:6]
        ):
            raise BuildError("extracted ELF section changed during publication")
        _measure_named_source_fd(
            source_descriptor,
            path,
            source_before,
            source_sha256,
        )
    except OSError as error:
        raise BuildError("fail-closed ELF section extraction failed") from error
    finally:
        cleanup_error: BaseException | None = None
        operation_failed = sys.exc_info()[0] is not None
        if unnamed_created and destination_descriptor >= 0:
            try:
                stage_identity = _fd_identity(os.fstat(destination_descriptor))
            except OSError as error:
                cleanup_error = error
        if (
            unnamed_created
            and operation_failed
            and stage_identity is not None
            and parent_descriptor >= 0
        ):
            try:
                link_count = os.fstat(destination_descriptor).st_nlink
                if link_count == 1:
                    try:
                        named = os.stat(
                            destination.name,
                            dir_fd=parent_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError as error:
                        raise BuildError(
                            "linked ELF section inode lost its fixed name; "
                            "permanent HOLD"
                        ) from error
                    if _fd_identity(named) != stage_identity:
                        raise BuildError(
                            "ELF section cleanup name was rebound; permanent HOLD"
                        )
                    os.unlink(destination.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                elif link_count != 0:
                    raise BuildError(
                        "ELF section staging link count drifted; permanent HOLD"
                    )
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        for descriptor in (
            destination_descriptor,
            section_descriptor,
            output_descriptor,
            input_descriptor,
            source_descriptor,
            parent_descriptor,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as error:
                    if cleanup_error is None:
                        cleanup_error = error
        if cleanup_error is not None:
            raise BuildError(
                "ELF section extraction cleanup was not exact; permanent HOLD"
            ) from cleanup_error


def _verify_filter_object_binding(
    final_elf: Path, core_object: Path, work: Path
) -> str:
    final_filter = work / "final-provider-filter.bin"
    core_filter = work / "core-provider-filter.bin"
    _extract_section(final_elf, ".trillionnium.provider_filter", final_filter)
    _extract_section(core_object, ".trillionnium.provider_filter", core_filter)
    final_sha256 = _sha256_file(final_filter)
    if (
        final_filter.stat().st_size != 37 * 8
        or core_filter.stat().st_size != 37 * 8
        or final_sha256 != _sha256_file(core_filter)
    ):
        raise BuildError(
            "final ELF filter bytes differ from the retained bootstrap object"
        )
    return final_sha256


def _elf_virtual_bytes(path: Path, address: int, size: int) -> bytes:
    if address <= 0 or size <= 0 or size > 1024 * 1024:
        raise BuildError("requested ELF virtual range is empty or unbounded")
    identity, programs = _elf_identity_and_program_headers(path)
    end_address = address + size
    if end_address <= address:
        raise BuildError("requested ELF virtual range overflowed")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        before = os.fstat(descriptor)
        matches: list[bytes] = []
        for program in programs:
            segment_end = program["address"] + program["file_size"]
            if (
                program["type"] == 1
                and address >= program["address"]
                and end_address <= segment_end
            ):
                start = program["offset"] + address - program["address"]
                if start + size > before.st_size:
                    raise BuildError("ELF virtual range exceeds its file mapping")
                value = os.pread(descriptor, size, start)
                if len(value) != size:
                    raise BuildError("ELF virtual range ended early")
                matches.append(value)
        if _fd_identity(os.fstat(descriptor)) != identity:
            raise BuildError("ELF changed while reading a virtual range")
    finally:
        os.close(descriptor)
    if len(matches) != 1:
        raise BuildError("ELF virtual range does not have one exact PT_LOAD mapping")
    return matches[0]


def _elf_identity_and_program_headers(
    path: Path,
) -> tuple[tuple[int, ...], list[dict[str, int]]]:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        before = os.fstat(descriptor)
        header = os.pread(descriptor, 64, 0)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_ARTIFACT_BYTES
            or len(header) != 64
            or header[:7] != b"\x7fELF\x02\x01\x01"
            or header[7:16] != b"\0" * 9
            or struct.unpack_from("<H", header, 16)[0] != 2
            or struct.unpack_from("<H", header, 18)[0] != 183
            or struct.unpack_from("<I", header, 20)[0] != 1
            or struct.unpack_from("<H", header, 52)[0] != 64
        ):
            raise BuildError("final payload is not exact AArch64 ELF64 ET_EXEC")
        program_offset = struct.unpack_from("<Q", header, 32)[0]
        section_offset = struct.unpack_from("<Q", header, 40)[0]
        program_entry_size = struct.unpack_from("<H", header, 54)[0]
        program_count = struct.unpack_from("<H", header, 56)[0]
        section_entry_size = struct.unpack_from("<H", header, 58)[0]
        section_count = struct.unpack_from("<H", header, 60)[0]
        section_string_index = struct.unpack_from("<H", header, 62)[0]
        if (
            program_entry_size != 56
            or program_count == 0
            or program_count > 256
            or program_offset + program_count * 56 > before.st_size
            or section_entry_size != 64
            or section_count == 0
            or section_count > 65_535
            or section_string_index >= section_count
            or section_offset + section_count * 64 > before.st_size
        ):
            raise BuildError("final ELF header tables are malformed")
        table = os.pread(descriptor, program_count * 56, program_offset)
        if len(table) != program_count * 56:
            raise BuildError("final ELF program header table ended early")
        programs = []
        for index in range(program_count):
            offset = index * 56
            program = {
                "type": struct.unpack_from("<I", table, offset)[0],
                "flags": struct.unpack_from("<I", table, offset + 4)[0],
                "offset": struct.unpack_from("<Q", table, offset + 8)[0],
                "address": struct.unpack_from("<Q", table, offset + 16)[0],
                "file_size": struct.unpack_from("<Q", table, offset + 32)[0],
                "memory_size": struct.unpack_from("<Q", table, offset + 40)[0],
                "alignment": struct.unpack_from("<Q", table, offset + 48)[0],
            }
            alignment = program["alignment"]
            if (
                program["file_size"] > program["memory_size"]
                or program["offset"] + program["file_size"] > before.st_size
                or program["address"] + program["memory_size"] > 1 << 64
                or alignment not in {0, 1}
                and alignment & (alignment - 1) != 0
                or alignment > 1
                and program["offset"] % alignment
                != program["address"] % alignment
            ):
                raise BuildError("final ELF program header range is malformed")
            programs.append(program)
        loads = [program for program in programs if program["type"] == 1]
        for index, left in enumerate(loads):
            left_start = left["address"] & ~0xFFF
            left_end = (left["address"] + left["memory_size"] + 0xFFF) & ~0xFFF
            for right in loads[index + 1 :]:
                right_start = right["address"] & ~0xFFF
                right_end = (
                    right["address"] + right["memory_size"] + 0xFFF
                ) & ~0xFFF
                if (
                    max(left_start, right_start) < min(left_end, right_end)
                    and (left["flags"] | right["flags"]) & 3 == 3
                ):
                    raise BuildError(
                        "final ELF overlapping load pages combine write and execute"
                    )
        after = os.fstat(descriptor)
        if _fd_identity(before) != _fd_identity(after):
            raise BuildError("final ELF changed while reading its headers")
        return _fd_identity(after), programs
    finally:
        os.close(descriptor)


def _inspect_final_elf(
    path: Path,
    provider_name: str,
    core_object: Path,
    build: Path,
    recipe: Mapping[str, Any],
    mechanism_object: Path | None = None,
) -> dict[str, Any]:
    build.mkdir(parents=True, exist_ok=True)
    provider = recipe["providers"][provider_name]
    header = _readelf(path, "--file-header", "--wide")
    sections = _readelf(path, "--sections", "--wide")
    symbols = _readelf(path, "--symbols", "--wide")
    programs = _readelf(path, "--program-headers", "--wide")
    if "Machine:" not in header or "AArch64" not in header:
        raise BuildError("final payload is not an AArch64 ELF")
    if ".symtab" not in sections:
        raise BuildError("stripped final payloads are forbidden")
    entry_match = re.search(r"Entry point address:\s*(0x[0-9a-fA-F]+)", header)
    type_match = re.search(r"Type:\s+([A-Z]+)", header)
    if entry_match is None or type_match is None:
        raise BuildError("final ELF header is malformed")
    entry = int(entry_match.group(1), 16)
    filter_path = build / "provider-filter.bin"
    _extract_section(path, ".trillionnium.provider_filter", filter_path)
    filter_size = filter_path.stat().st_size
    expected_size = recipe["bootstrap"]["expected_filter_instruction_count"] * 8
    if filter_size != expected_size:
        raise BuildError("final ELF seccomp filter instruction count drifted")

    bootstrap = _symbol_facts(
        symbols, "trillionnium_provider_post_final_exec_bootstrap"
    )
    if not _is_nonpreemptible_definition(bootstrap, "FUNC"):
        raise BuildError("bootstrap symbol preemption/type contract drifted")
    common = {
        "elf_type": type_match.group(1),
        "entry_address": entry,
        "bootstrap_core": bootstrap,
        "filter": _artifact(filter_path, "build/provider-filter.bin"),
        "has_symbol_table": True,
        "has_writable_executable_segment": bool(
            re.search(r"\bLOAD\b.*\bRWE\b", programs)
        ),
        "gnu_stack_executable": bool(re.search(r"\bGNU_STACK\b.*\bRWE\b", programs)),
    }
    if common["has_writable_executable_segment"] or common["gnu_stack_executable"]:
        raise BuildError("final ELF has writable executable memory or executable stack")

    if provider_name == "codex":
        entry_symbol = _symbol_facts(
            symbols, "trillionnium_provider_post_final_exec_entry"
        )
        original = _symbol_facts(symbols, "_start")
        if (
            type_match.group(1) != "EXEC"
            or "INTERP" in programs
            or ".dynamic" in sections
            or ".preinit_array" in sections
            or entry_symbol["address"] != entry
            or entry_symbol["size"] != 32
            or not _is_nonpreemptible_definition(entry_symbol, "FUNC")
            or original["address"] == 0
            or bootstrap["address"] in {entry, original["address"]}
        ):
            raise BuildError("Codex controlled-entry ELF contract failed")
        entry_bytes = build / "provider-entry.bin"
        _write_bytes(
            entry_bytes,
            _elf_virtual_bytes(path, entry_symbol["address"], entry_symbol["size"]),
        )
        common.update(
            {
                "mechanism": "controlled_entry_before_crt",
                "controlled_entry": entry_symbol,
                "controlled_entry_section": _artifact(
                    entry_bytes, "build/provider-entry.bin"
                ),
                "original_start": original,
                "has_dynamic_segment": False,
                "has_preinit_array": False,
            }
        )
    else:
        raise BuildError("final ELF inspection is outside the Codex singleton")
    return common














def _runtime_abi_contract(
    provider_name: str,
    elf_contract: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    interpreter = elf_contract.get("interpreter")
    needed_order = elf_contract.get("needed_order", [])
    if (
        provider_name not in PROVIDERS
        or elf_contract.get("has_dynamic_segment") is not False
        or entries != []
        or interpreter is not None
        or needed_order != []
    ):
        raise BuildError("provider runtime ABI contract must be fully static")
    return {
        "schema": "trillionnium.provider-runtime-abi-contract.v2",
        "provider": provider_name,
        "target_architecture": TARGET_ARCHITECTURE,
        "final_interpreter": None,
        "final_needed_order": [],
        "entries": [],
    }


def _runtime_abi_contract_sha256(
    provider_name: str,
    elf_contract: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
) -> str:
    return _domain_digest(
        RUNTIME_ABI_CONTRACT_DIGEST_DOMAIN,
        [_json_bytes(_runtime_abi_contract(provider_name, elf_contract, entries))],
    )


def _runtime_bundle_inventory_sha256(
    entries: Sequence[Mapping[str, Any]],
) -> str:
    if entries != []:
        raise BuildError("fully-static runtime bundle cannot contain DSOs")
    return _domain_digest(
        RUNTIME_BUNDLE_INVENTORY_DIGEST_DOMAIN,
        [_json_bytes([])],
    )


def _runtime_closure_manifest_value(
    provider_name: str, entries: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    if entries != []:
        raise BuildError("fully-static runtime closure cannot contain DSOs")
    if provider_name != "codex":
        raise BuildError("provider runtime closure identity drifted")
    return {
        "schema": "trillionnium.codex-static-runtime-closure.v1",
        "static": True,
        "interpreter": None,
        "dso_entries": [],
    }










def _path_measurement(source: Path) -> dict[str, Any]:
    path = source.resolve(strict=True)
    return {
        "source_path": str(path),
        "byte_length": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _source_receipt(
    provider_name: str,
    provider: Mapping[str, Any],
    source: Path,
    output: Path,
    codex_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if provider_name != "codex" or codex_inputs is None:
        raise BuildError("Codex source receipt inputs are incomplete or ambiguous")
    if provider_name == "codex":
        source_archive = _stage_artifact(
            codex_inputs["source_archive"],
            output,
            f"source/{provider['source_archive']['filename']}",
        )
        upstream_lock = _stage_artifact(
            codex_inputs["upstream_lock"],
            output,
            "source/upstream/codex-rs/Cargo.lock",
        )
        derived_lock = _stage_artifact(
            codex_inputs["derived_lock"],
            output,
            "source/derived/codex-rs/Cargo.lock",
        )
        rust_toolchain = _stage_artifact(
            source / "codex-rs/rust-toolchain.toml",
            output,
            "source/pristine/codex-rs/rust-toolchain.toml",
        )
        lock_patch = _stage_artifact(
            codex_inputs["lock_patch"],
            output,
            "build/codex-derived-Cargo.lock.patch",
        )
        dependency_assets = {
            "source_archive": source_archive,
            "tag_object": _stage_artifact(
                codex_inputs["tag_object"],
                output,
                f"source/git/{provider['source_identity']['tag_object']['filename']}",
            ),
            "commit_object": _stage_artifact(
                codex_inputs["commit_object"],
                output,
                    f"source/git/{provider['source_identity']['commit_object']['filename']}",
            ),
            "source_member_manifest": _stage_artifact(
                codex_inputs["source_member_manifest"],
                output,
                (
                    "source/manifests/"
                    f"{provider['source_identity']['source_member_manifest']['filename']}"
                ),
            ),
            "source_logical_symlinks": _stage_artifact(
                codex_inputs["source_logical_symlinks"],
                output,
                (
                    "source/manifests/"
                    f"{provider['source_identity']['logical_symlinks']['filename']}"
                ),
            ),
            "cargo_vendor_archive": dict(provider["cargo_vendor"]["archive"]),
            "cargo_vendor_member_manifest": _stage_artifact(
                codex_inputs["cargo_vendor_member_manifest"],
                output,
                (
                    "source/dependencies/"
                    f"{provider['cargo_vendor']['member_manifest']['filename']}"
                ),
            ),
            "cargo_vendor_contract": {
                "root_name": provider["cargo_vendor"]["root_name"],
                "entry_count": provider["cargo_vendor"]["entry_count"],
                "pre_build_inventory_sha256": codex_inputs[
                    "cargo_vendor_inventory_sha256"
                ],
                "post_build_inventory_sha256": codex_inputs[
                    "post_build_vendor_inventory_sha256"
                ],
                "cache_bind_mount_read_only": True,
                "archive_retained_in_builder_output": False,
            },
            "cargo_source_config": _stage_artifact(
                codex_inputs["cargo_source_config"],
                output,
                (
                    "source/dependencies/"
                    f"{provider['cargo_source_config']['filename']}"
                ),
            ),
            "rusty_v8_archive": _stage_artifact(
                codex_inputs["rusty_v8_archive"],
                output,
                f"source/dependencies/{provider['rusty_v8']['archive']['filename']}",
            ),
            "rusty_v8_binding": _stage_artifact(
                codex_inputs["rusty_v8_binding"],
                output,
                f"source/dependencies/{provider['rusty_v8']['binding']['filename']}",
            ),
            "rusty_v8_checksums": _stage_artifact(
                codex_inputs["rusty_v8_checksums"],
                output,
                (
                    "source/dependencies/"
                    f"{provider['rusty_v8']['checksums']['filename']}"
                ),
            ),
            "rusty_v8_contract": {
                key: provider["rusty_v8"][key]
                for key in (
                    "crate_version",
                    "crate_checksum_sha256",
                    "target",
                    "variant",
                    "resolved_features",
                    "archive_uncompressed_byte_length",
                    "archive_uncompressed_sha256",
                    "release_prerelease",
                    "release_immutable",
                    "upstream_signature_proven",
                    "github_attestation_proven",
                )
            },
        }
        derived_build_source = {
            "schema": "trillionnium.codex-derived-build-source.v1",
            "pristine_source_tree_sha1": provider["source_tree_sha1"],
            "transformation": provider["derived_lock"]["transformation"],
            "workspace_version": provider["derived_lock"]["workspace_version"],
            "workspace_package_count": provider["derived_lock"][
                "workspace_package_count"
            ],
            "workspace_package_names_sha256": provider["derived_lock"][
                "workspace_package_names_sha256"
            ],
            "upstream_lock": upstream_lock,
            "derived_lock": derived_lock,
            "lock_patch": lock_patch,
            "pre_build_source_inventory_sha256": codex_inputs[
                "source_inventory_sha256"
            ],
            "post_build_source_inventory_sha256": codex_inputs[
                "post_build_source_inventory_sha256"
            ],
            "cargo_metadata_command": codex_inputs["cargo_metadata_command"],
        }
        return {
            "repository_url": provider["repository_url"],
            "version": provider["version"],
            "annotated_tag": provider["annotated_tag"],
            "annotated_tag_object_sha1": provider["annotated_tag_object_sha1"],
            "dereferenced_commit_sha1": provider["dereferenced_commit_sha1"],
            "source_tree_sha1": provider["source_tree_sha1"],
            "source_archive": source_archive,
            "pristine_upstream_source_proven": True,
            "build_source_derived": True,
            "lockfiles": [upstream_lock, derived_lock, rust_toolchain],
            "patched_sources": [lock_patch],
            "derived_build_source": derived_build_source,
            "dependency_assets": dependency_assets,
        }

def _copy_final_artifacts(
    final_elf: Path,
    link_map: Path,
    bootstrap: Mapping[str, Any],
    output: Path,
) -> tuple[Path, Path, Path, Path]:
    if final_elf.name != "codex":
        raise BuildError("final artifact name is outside the Codex singleton")
    final_target = output / "codex"
    link_map_target = output / "final.map"
    core_target = output / "provider-post-exec-bootstrap.o"
    mechanism_target = output / bootstrap["mechanism"].name
    for source, destination, mode in (
        (final_elf, final_target, 0o555),
        (link_map, link_map_target, 0o444),
        (bootstrap["core"], core_target, 0o444),
        (bootstrap["mechanism"], mechanism_target, 0o444),
    ):
        shutil.copyfile(source, destination, follow_symlinks=False)
        destination.chmod(mode)
    return final_target, link_map_target, core_target, mechanism_target


def _builder_receipt_hash(receipt: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return _domain_digest(RECEIPT_DIGEST_DOMAIN, [_json_bytes(unsigned)])


def _verify_pending_container_output(
    stage: Path,
    custody: _ContainerCidfileCustody,
) -> dict[str, Any]:
    receipt = _verify_builder_output(
        stage,
        allow_pending_container_custody=True,
    )
    projection = receipt["container"]
    if projection["cidfile"]["custody_directory_identity"] != (
        _container_custody_identity_record(custody.identity)
    ):
        raise BuildError(
            "in-container cidfile custody identity differs from launcher FD"
        )
    return receipt


def _rewrite_builder_container_projection(
    stage: Path,
    pending_receipt: Mapping[str, Any],
    final_projection: Mapping[str, Any],
) -> dict[str, Any]:
    root_descriptor = _open_fixed_root(stage)
    receipt_descriptor = -1
    sync_descriptor = -1
    try:
        sync_descriptor = os.open(
            ".",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        if (
            os.fstat(sync_descriptor).st_dev,
            os.fstat(sync_descriptor).st_ino,
        ) != (
            os.fstat(root_descriptor).st_dev,
            os.fstat(root_descriptor).st_ino,
        ):
            raise BuildError("builder receipt root identity is not pinned")
        named_before = os.stat(
            "provider-builder-receipt.json",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        receipt_descriptor = os.open(
            "provider-builder-receipt.json",
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=root_descriptor,
        )
        opened_before = os.fstat(receipt_descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or stat.S_IMODE(opened_before.st_mode) != 0o600
            or opened_before.st_nlink != 1
            or opened_before.st_uid != os.getuid()
            or _fd_identity(named_before) != _fd_identity(opened_before)
        ):
            raise BuildError(
                "pending builder receipt is not one private pinned inode"
            )
        content = _read_bounded_fd(
            receipt_descriptor,
            "provider-builder-receipt.json",
            MAX_RECEIPT_BYTES,
        )
        try:
            observed_pending = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BuildError("pending builder receipt is malformed") from error
        if observed_pending != pending_receipt:
            raise BuildError("pending builder receipt changed before finalization")
        final_receipt = dict(observed_pending)
        final_receipt["container"] = _copy_container_projection(
            final_projection
        )
        final_receipt["receipt_sha256"] = _builder_receipt_hash(final_receipt)
        final_bytes = _json_bytes(final_receipt)
        if len(final_bytes) > MAX_RECEIPT_BYTES:
            raise BuildError("final builder receipt exceeds its strict byte bound")
        os.lseek(receipt_descriptor, 0, os.SEEK_SET)
        os.ftruncate(receipt_descriptor, 0)
        remaining = memoryview(final_bytes)
        while remaining:
            written = os.write(receipt_descriptor, remaining)
            if written <= 0:
                raise BuildError("short write while finalizing builder receipt")
            remaining = remaining[written:]
        os.fchmod(receipt_descriptor, 0o444)
        os.fsync(receipt_descriptor)
        opened_after = os.fstat(receipt_descriptor)
        named_after = os.stat(
            "provider-builder-receipt.json",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        immutable_before = (
            opened_before.st_dev,
            opened_before.st_ino,
            opened_before.st_nlink,
            opened_before.st_uid,
            opened_before.st_gid,
        )
        immutable_after = (
            opened_after.st_dev,
            opened_after.st_ino,
            opened_after.st_nlink,
            opened_after.st_uid,
            opened_after.st_gid,
        )
        if (
            immutable_before != immutable_after
            or opened_after.st_size != len(final_bytes)
            or stat.S_IMODE(opened_after.st_mode) != 0o444
            or _fd_identity(opened_after) != _fd_identity(named_after)
        ):
            raise BuildError("builder receipt identity changed during finalization")
        os.fsync(sync_descriptor)
        verified = _verify_builder_output_fd(root_descriptor)
        if verified != final_receipt:
            raise BuildError("final builder receipt verification projection drifted")
        return verified
    finally:
        if receipt_descriptor >= 0:
            os.close(receipt_descriptor)
        if sync_descriptor >= 0:
            os.close(sync_descriptor)
        os.close(root_descriptor)


def _container_build(
    provider_name: str,
    profile: str,
    builder_image_id: str,
    expected_recipe_sha256: str,
    expected_builder_sha256: str,
    expected_containerfile_sha256: str,
    expected_build_context_tar_sha256: str,
    expected_build_context_tar_byte_length: int,
    expected_build_context_member_manifest_sha256: str,
    expected_attempt_id: str,
    requested_output: str,
    cache_root: str,
    expected_container_name: str,
    expected_cidfile_host_path: str,
    container_cidfile_path: str,
) -> None:
    recipe = load_recipe()
    if provider_name not in PROVIDERS or profile not in BUILDER_PROFILES:
        raise BuildError("provider or builder profile is outside the frozen set")
    recipe_sha256 = _sha256_file(RECIPE_PATH)
    if recipe_sha256 != expected_recipe_sha256:
        raise BuildError("mounted recipe differs from the outer frozen recipe")
    if (
        _sha256_file(Path(__file__).resolve()) != expected_builder_sha256
        or _sha256_file(CONTAINERFILE_PATH) != expected_containerfile_sha256
    ):
        raise BuildError("container builder input identity drifted")
    input_identity = _container_input_identity(
        expected_recipe_sha256,
        expected_builder_sha256,
        expected_containerfile_sha256,
    )
    _require_hex(builder_image_id.removeprefix("sha256:"), 64, "builder_image_id")
    computed_attempt_id = _build_attempt_identity(
        input_identity,
        provider_name,
        profile,
        requested_output,
        cache_root,
    )
    expected_cidfile = (
        _container_cidfile_custody_path(
            requested_output,
            computed_attempt_id,
        )
        / CONTAINER_CIDFILE_NAME
    )
    if (
        expected_attempt_id != computed_attempt_id
        or expected_container_name != _container_name(computed_attempt_id)
        or expected_cidfile_host_path != str(expected_cidfile)
        or container_cidfile_path != CONTAINER_CIDFILE_PATH
    ):
        raise BuildError("in-container lifecycle arguments drifted")
    container_id, custody_identity = _read_live_container_id(
        Path(container_cidfile_path)
    )
    container_build_context = _build_context_receipt(
        _snapshot_build_context()
    )
    if (
        container_build_context["tar_sha256"]
        != expected_build_context_tar_sha256
        or container_build_context["tar_byte_length"]
        != expected_build_context_tar_byte_length
        or container_build_context["member_manifest_sha256"]
        != expected_build_context_member_manifest_sha256
    ):
        raise BuildError(
            "in-container deterministic build-context identity drifted"
        )
    container_projection = _new_container_projection(
        input_identity=input_identity,
        provider_name=provider_name,
        profile=profile,
        output=requested_output,
        cache=cache_root,
        image_reference=builder_image_id,
        build_context=container_build_context,
    )
    container_projection["id"] = container_id
    container_projection["run_invoked"] = True
    container_projection["cidfile"].update(
        {
            "custody_directory_identity": (
                _container_custody_identity_record(custody_identity)
            ),
            "state": "pending_launcher_capture",
            "pre_run_absent_no_symlink": True,
            "container_id_cidfile_observed": True,
            "read_during_container_execution": True,
        }
    )
    expected_machine = "x86_64" if profile == "amd64-cross" else "aarch64"
    if os.uname().machine != expected_machine:
        raise BuildError(
            f"builder profile {profile} requires {expected_machine}, "
            f"observed {os.uname().machine}"
        )
    output = Path("/output")
    work = output / ".work"
    source_parent = work / "source"
    build = work / "build"
    source_parent.mkdir(parents=True)
    build.mkdir(parents=True)
    environment = _base_environment(recipe)
    provider = recipe["providers"][provider_name]
    bootstrap = _compile_bootstrap(recipe, provider_name, profile, build, environment)
    source, codex_inputs = _prepare_codex_source(
        source_parent,
        work,
        provider,
        environment,
    )
    final_elf, link_map, command, build_environment = _codex_build(
        recipe,
        profile,
        source,
        build,
        bootstrap,
        environment,
        codex_inputs,
    )

    elf_contract = _inspect_final_elf(
        final_elf,
        provider_name,
        bootstrap["core"],
        build,
        recipe,
        mechanism_object=bootstrap["mechanism"],
    )
    if (
        _verify_filter_object_binding(
            final_elf, bootstrap["core"], build / "filter-binding"
        )
        != elf_contract["filter"]["sha256"]
    ):
        raise BuildError("final ELF filter measurement is internally inconsistent")
    final_target, link_target, core_target, mechanism_target = _copy_final_artifacts(
        final_elf, link_map, bootstrap, output
    )
    link_provenance_artifact = None
    target_static_libraries: list[dict[str, Any]] = []
    target_toolchain_wrappers: list[dict[str, Any]] = []
    wrapper_paths = _codex_target_toolchain_wrapper_paths(build / "target-toolchain")
    for role in sorted(wrapper_paths):
        wrapper_path, expected_content = wrapper_paths[role]
        if wrapper_path.read_bytes() != expected_content:
            raise BuildError(
                f"Codex target toolchain wrapper drifted: {role}"
            )
        target_toolchain_wrappers.append(
            _stage_artifact(
                wrapper_path,
                output,
                f"build/target-toolchain/{wrapper_path.name}",
                mode=0o555,
            )
        )
    closure_manifest = output / "runtime-closure.json"
    closure_entries = []
    _write_bytes(
        closure_manifest,
        _json_bytes(_runtime_closure_manifest_value(provider_name, [])),
    )

    source_value = _source_receipt(
        provider_name,
        provider,
        source,
        output,
        codex_inputs,
    )
    recipe_artifacts = {
        "file": _stage_artifact(
            RECIPE_PATH, output, "recipe/provider-payload-recipe-v1.json"
        ),
        "containerfile": _stage_artifact(
            CONTAINERFILE_PATH, output, "recipe/Containerfile"
        ),
        "builder": _stage_artifact(
            Path(__file__).resolve(),
            output,
            "recipe/build_provider_payload.py",
            mode=0o555,
        ),
    }
    bootstrap_inputs = [
        _stage_artifact(
            DIRECTORY / item["path"],
            output,
            f"bootstrap/{item['path']}",
        )
        for item in (
            recipe["bootstrap"]["public_header"],
            recipe["bootstrap"]["freestanding_core"],
            recipe["bootstrap"]["codex_entry"],
        )
    ]
    preprocessed_artifact = _stage_artifact(
        bootstrap["preprocessed"],
        output,
        "build/provider-post-exec-bootstrap.i",
    )
    macro_artifact = _stage_artifact(
        bootstrap["macros"],
        output,
        "build/provider-post-exec-bootstrap.macros",
    )
    relocation_artifact = _stage_artifact(
        bootstrap["relocations"],
        output,
        "build/provider-post-exec-bootstrap.relocations",
    )
    filter_artifact = _stage_artifact(
        build / "provider-filter.bin", output, "build/provider-filter.bin"
    )
    elf_contract["filter"] = filter_artifact
    elf_contract["controlled_entry_section"] = _stage_artifact(
        build / "provider-entry.bin", output, "build/provider-entry.bin"
    )
    dependency_manifest = output / "build-dependencies.json"
    runtime_abi_contract_sha256 = _runtime_abi_contract_sha256(
        provider_name, elf_contract, closure_entries
    )
    dependencies = [
        source_value["lockfiles"],
        bootstrap_inputs,
    ]
    _write_bytes(
        dependency_manifest,
        _json_bytes(
            {
                "schema": "trillionnium.provider-build-dependencies.v4",
                "source_archive": source_value["source_archive"],
                "source_lockfiles": dependencies[0],
                "source_patches": source_value["patched_sources"],
                "derived_build_source": source_value["derived_build_source"],
                "dependency_assets": source_value["dependency_assets"],
                "bootstrap_sources": dependencies[1],
                "runtime_abi_contract_sha256": runtime_abi_contract_sha256,
                "target_static_libraries": _normalized_static_libraries(
                    target_static_libraries
                ),
            }
        ),
    )
    environment_receipt = [
        {"name": name, "value": value}
        for name, value in sorted(build_environment.items())
        if name
        in {
            "AR",
            "AR_host",
            "AR_target",
            "AWS_LC_SYS_NO_JITTER_ENTROPY",
            "AWS_LC_SYS_CMAKE_BUILDER",
            "AR_aarch64_unknown_linux_musl",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_HOME",
            "CARGO_INCREMENTAL",
            "CARGO_NET_OFFLINE",
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
            "CARGO_PROFILE_RELEASE_DEBUG",
            "CARGO_PROFILE_RELEASE_INCREMENTAL",
            "CARGO_PROFILE_RELEASE_LTO",
            "CARGO_PROFILE_RELEASE_STRIP",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER",
            "CARGO_TARGET_DIR",
            "CC",
            "CC_aarch64_unknown_linux_musl",
            "CC_host",
            "CC_target",
            "CFLAGS",
            "CFLAGS_aarch64_unknown_linux_musl",
            "CFLAGS_host",
            "CXX",
            "CXX_aarch64_unknown_linux_musl",
            "CXX_host",
            "CXX_target",
            "CXXFLAGS",
            "CXXFLAGS_aarch64_unknown_linux_musl",
            "CXXFLAGS_host",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "HOME",
            "HOST_AR",
            "HOST_CC",
            "HOST_CXX",
            "HOST_RANLIB",
            "LANG",
            "LC_ALL",
            "LINK",
            "LINK_host",
            "LINK_target",
            "PATH",
            "RANLIB_aarch64_unknown_linux_musl",
            "RANLIB",
            "RANLIB_host",
            "RANLIB_target",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "RUSTC",
            "RUSTY_V8_ARCHIVE",
            "RUSTY_V8_SRC_BINDING_PATH",
            "SOURCE_DATE_EPOCH",
            "TZ",
            "ZIG_GLOBAL_CACHE_DIR",
            "ZIG_LOCAL_CACHE_DIR",
            "CMAKE_GENERATOR",
        }
    ]
    compiler_command = bootstrap["compiler_command"]
    compiler_executable = (
        Path(compiler_command[0]).resolve(strict=True)
        if Path(compiler_command[0]).is_absolute()
        else Path(shutil.which(compiler_command[0]) or "")
    )
    cargo_executable, rustc_executable = _codex_toolchain_paths(
        recipe["builder"]["rust_version"],
        profile,
    )
    primary_compiler = _path_measurement(rustc_executable)
    bootstrap_compiler = _path_measurement(compiler_executable)
    assembler = _path_measurement(compiler_executable)
    linker = _path_measurement(compiler_executable)
    build_driver = _path_measurement(cargo_executable)
    retained_artifact_resolver = _measure_retained_artifact_resolver(
        output, final_target.name
    )
    receipt: dict[str, Any] = {
        "schema": BUILDER_RECEIPT_SCHEMA,
        "provider": provider["provider_wire_name"],
        "target_architecture": TARGET_ARCHITECTURE,
        "source_date_epoch": recipe["source_date_epoch"],
        "recipe": recipe_artifacts,
        "builder": {
            "profile": profile,
            "platform": recipe["builder"]["profiles"][profile]["platform"],
            "base_image": recipe["builder"]["base_image"],
            "canonical_base_image": recipe["builder"]["canonical_base_image"],
            "base_platform_manifest_sha256": recipe["builder"]["profiles"][profile][
                "manifest_sha256"
            ],
            "built_image_id": builder_image_id,
            "build_context": container_build_context,
            "image_build_network": recipe["builder"]["image_build_network"],
            "retained_artifact_resolver": retained_artifact_resolver,
            "rust_version": recipe["builder"]["rust_version"],
            "zig_version": recipe["builder"]["zig_version"],
            "compiler": primary_compiler,
            "bootstrap_compiler": bootstrap_compiler,
            "assembler": assembler,
            "linker": linker,
            "build_driver": build_driver,
        },
        "container": container_projection,
        "source": source_value,
        "bootstrap": {
            "public_header": bootstrap_inputs[0],
            "freestanding_core_source": bootstrap_inputs[1],
            "mechanism_source": bootstrap_inputs[2],
            "core_object": _artifact(core_target, "provider-post-exec-bootstrap.o"),
            "mechanism_object": _artifact(mechanism_target, mechanism_target.name),
            "preprocessed_source": preprocessed_artifact,
            "macro_dump": macro_artifact,
            "relocation_manifest": relocation_artifact,
            "object_closure": bootstrap["closure"],
            "filter": elf_contract["filter"],
            "expected_filter_instruction_count": recipe["bootstrap"][
                "expected_filter_instruction_count"
            ],
        },
        "build": {
            "working_directory": "/output/.work",
            "resource_contract": _provider_resource_contract(
                provider_name, provider
            ),
            "environment": environment_receipt,
            "command": command,
            "compiler_arguments": bootstrap["compiler_arguments"],
            "externally_supplied_definitions": recipe["bootstrap"][
                "externally_supplied_definitions"
            ],
            "ordered_provider_objects": [
                _artifact(core_target, "provider-post-exec-bootstrap.o"),
                _artifact(mechanism_target, mechanism_target.name),
            ],
            "link_map": _artifact(link_target, "final.map"),
            "final_link_provenance": link_provenance_artifact,
            "dependency_manifest": _artifact(
                dependency_manifest, "build-dependencies.json"
            ),
            "runtime_closure_manifest": _artifact(
                closure_manifest, "runtime-closure.json"
            ),
            "runtime_closure": closure_entries,
            "target_static_libraries": target_static_libraries,
            "target_toolchain_wrappers": target_toolchain_wrappers,
            "container_network": "none",
            "container_proxy_environment": _container_proxy_environment(),
        },
        "final_elf": _artifact(final_target, final_target.name),
        "elf_contract": elf_contract,
        "retained_fd_contract": _retained_fd_contract(),
        "source_checkpoint": _source_checkpoint_projection(
            provider_name, provider
        ),
        "product_active": False,
        "listener_backend_wired": False,
        "admission_wired": False,
        "confers_effect_authority": False,
        "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = _builder_receipt_hash(receipt)
    _write_bytes(
        output / "provider-builder-receipt.json",
        _json_bytes(receipt),
        mode=0o600,
    )
    _verify_builder_output(
        output,
        allow_pending_container_custody=True,
    )


def _retained_artifacts(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, dict):
        if set(value) == {"logical_path", "byte_length", "sha256"}:
            yield value
        else:
            for child in value.values():
                yield from _retained_artifacts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _retained_artifacts(child)


def _verify_runtime_closure(
    copies: Mapping[str, Path],
    entries: Any,
    manifest_artifact: Mapping[str, Any],
    provider_name: str,
    elf_contract: Mapping[str, Any],
    profile: str | None,
) -> None:
    if provider_name not in PROVIDERS:
        raise BuildError("runtime closure provider is not frozen")
    if profile is not None and profile not in BUILDER_PROFILES:
        raise BuildError("runtime closure builder profile is not frozen")
    if elf_contract.get("has_dynamic_segment") is not False:
        raise BuildError("dynamic runtime closure receipts are forbidden")
    if entries != []:
        raise BuildError("fully-static runtime closure cannot contain DSOs")
    manifest_logical_path = manifest_artifact.get("logical_path")
    if (
        not isinstance(manifest_logical_path, str)
        or PurePosixPath(manifest_logical_path).name != "runtime-closure.json"
    ):
        raise BuildError("runtime closure manifest logical path drifted")
    manifest = _read_json(_artifact_path(copies, manifest_artifact))
    if manifest != _runtime_closure_manifest_value(provider_name, []):
        raise BuildError("static runtime closure receipt drifted")


def _verify_dependency_manifest(
    copies: Mapping[str, Path],
    manifest_artifact: Mapping[str, Any],
    source_archive: Mapping[str, Any] | None,
    source_lockfiles: Sequence[Mapping[str, Any]],
    source_patches: Sequence[Mapping[str, Any]],
    derived_build_source: Mapping[str, Any] | None,
    dependency_assets: Mapping[str, Any],
    bootstrap_sources: Sequence[Mapping[str, Any]],
    runtime_abi_contract_sha256: str,
    target_static_libraries: Sequence[Mapping[str, Any]],
) -> None:
    manifest = _read_json(_artifact_path(copies, manifest_artifact))
    expected = {
        "schema": "trillionnium.provider-build-dependencies.v4",
        "source_archive": source_archive,
        "source_lockfiles": source_lockfiles,
        "source_patches": source_patches,
        "derived_build_source": derived_build_source,
        "dependency_assets": dependency_assets,
        "bootstrap_sources": bootstrap_sources,
        "runtime_abi_contract_sha256": runtime_abi_contract_sha256,
        "target_static_libraries": _normalized_static_libraries(
            target_static_libraries
        ),
    }
    if manifest != expected:
        raise BuildError(
            "retained dependency manifest differs from its complete receipt inputs"
        )


def _verify_codex_retained_source_contract(
    copies: Mapping[str, Path],
    receipt: Mapping[str, Any],
    provider: Mapping[str, Any],
    recipe: Mapping[str, Any],
) -> None:
    source = receipt["source"]
    derived = source["derived_build_source"]
    assets = source["dependency_assets"]
    upstream_path = _artifact_path(copies, derived["upstream_lock"])
    derived_path = _artifact_path(copies, derived["derived_lock"])
    patch_path = _artifact_path(copies, derived["lock_patch"])
    derived_bytes, patch_bytes, names = _derive_codex_lock_bytes(
        upstream_path.read_bytes(),
        provider["derived_lock"],
    )
    if (
        derived_path.read_bytes() != derived_bytes
        or patch_path.read_bytes() != patch_bytes
    ):
        raise BuildError("retained Codex derived lock evidence drifted")

    tag_path = _artifact_path(copies, assets["tag_object"])
    commit_path = _artifact_path(copies, assets["commit_object"])
    _verify_source_identity_bytes(
        tag_path.read_bytes(),
        commit_path.read_bytes(),
        provider,
        "Codex",
    )
    cargo_config = _artifact_path(copies, assets["cargo_source_config"])
    _verify_cargo_source_config(
        cargo_config,
        Path("/opt/trillionnium/cargo-vendor"),
    )
    _verify_rusty_v8_checksum_contract(
        _artifact_path(copies, assets["rusty_v8_checksums"]),
        _artifact_path(copies, assets["rusty_v8_archive"]),
        _artifact_path(copies, assets["rusty_v8_binding"]),
        provider,
    )

    source_archive = _artifact_path(copies, source["source_archive"])
    with tempfile.TemporaryDirectory(
        prefix="provider-codex-source-verify."
    ) as temporary:
        temporary_root = Path(temporary)
        extracted = _safe_extract_tar_xz(
            source_archive,
            temporary_root / "source",
        )
        _verify_and_restore_codex_source_archive(
            extracted,
            _artifact_path(copies, assets["source_member_manifest"]),
            _artifact_path(copies, assets["source_logical_symlinks"]),
            provider,
        )
        tree = _git_worktree_sha1(
            extracted,
            temporary_root / "tree-measurement",
            _base_environment(recipe),
        )
        if tree != provider["source_tree_sha1"]:
            raise BuildError("retained Codex source archive tree drifted")
        _verify_codex_workspace_manifests(
            extracted,
            names,
            provider["derived_lock"]["workspace_version"],
        )
        upstream_relative = provider["derived_lock"]["upstream_relative_path"]
        if (
            _sha256_file(
                extracted / upstream_relative,
                MAX_SOURCE_ARCHIVE_BYTES,
            )
            != provider["lockfiles"][upstream_relative]
        ):
            raise BuildError("retained Codex pristine source lock drifted")


def _verify_codex_target_toolchain_wrappers(
    copies: Mapping[str, Path],
    artifacts: Any,
) -> None:
    if not isinstance(artifacts, list):
        raise BuildError("Codex target toolchain wrapper inventory is malformed")
    expected: list[dict[str, Any]] = []
    expected_contents: list[bytes] = []
    for role in sorted(CODEX_TARGET_TOOLCHAIN_WRAPPERS):
        filename, content = CODEX_TARGET_TOOLCHAIN_WRAPPERS[role]
        expected.append(
            {
                "logical_path": f"build/target-toolchain/{filename}",
                "byte_length": len(content),
                "sha256": _sha256_bytes(content),
            }
        )
        expected_contents.append(content)
    if artifacts != expected:
        raise BuildError("Codex target toolchain wrapper inventory drifted")
    for artifact, content in zip(
        artifacts, expected_contents, strict=True
    ):
        if _artifact_path(copies, artifact).read_bytes() != content:
            raise BuildError("retained Codex target toolchain wrapper drifted")


def _verify_builder_output_fd(
    root_descriptor: int,
    *,
    allow_pending_container_custody: bool = False,
    preloaded_receipt: dict[str, Any] | None = None,
    verification_sources: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = preloaded_receipt
    if receipt is None:
        receipt = _read_json_from_fixed_root_fd(
            root_descriptor, "provider-builder-receipt.json"
        )
    elif not isinstance(receipt, dict):
        raise BuildError("preloaded builder receipt is not one JSON object")
    _expect_keys(receipt, EXPECTED_BUILDER_RECEIPT_KEYS, "builder receipt")
    if (
        receipt["schema"] != BUILDER_RECEIPT_SCHEMA
        or receipt["provider"] not in PROVIDERS
        or receipt["target_architecture"] != TARGET_ARCHITECTURE
    ):
        raise BuildError("builder receipt identity drifted")
    _require_false_authority_fields(receipt, "builder receipt")
    expected_hash = _builder_receipt_hash(receipt)
    if receipt["receipt_sha256"] != expected_hash:
        raise BuildError("builder receipt self-hash mismatch")
    recipe = (
        load_recipe()
        if verification_sources is None
        else verification_sources["recipe"]
    )
    if verification_sources is not None and (
        receipt["recipe"]["file"]["sha256"]
        != verification_sources["recipe_sha256"]
        or receipt["recipe"]["containerfile"]["sha256"]
        != verification_sources["containerfile_sha256"]
        or receipt["recipe"]["builder"]["sha256"]
        != verification_sources["builder_sha256"]
    ):
        raise BuildError(
            "retained builder/recipe/Containerfile custody drifted"
        )
    provider_name = receipt["provider"]
    provider = recipe["providers"][provider_name]
    _verify_source_checkpoint_projection(
        provider_name,
        provider,
        receipt["source_checkpoint"],
        "builder receipt",
    )
    _expect_keys(
        receipt["recipe"],
        {"file", "containerfile", "builder"},
        "receipt.recipe",
    )
    _expect_keys(receipt["builder"], EXPECTED_BUILDER_KEYS, "receipt.builder")
    _expect_keys(receipt["source"], EXPECTED_SOURCE_KEYS, "receipt.source")
    _expect_keys(
        receipt["bootstrap"],
        EXPECTED_BOOTSTRAP_RECEIPT_KEYS,
        "receipt.bootstrap",
    )
    _expect_keys(receipt["build"], EXPECTED_BUILD_RECEIPT_KEYS, "receipt.build")
    _expect_keys(
        receipt["retained_fd_contract"],
        EXPECTED_RETAINED_FD_CONTRACT,
        "receipt.retained_fd_contract",
    )
    _expect_keys(
        receipt["elf_contract"],
        EXPECTED_CODEX_ELF_CONTRACT_KEYS,
        "receipt.elf_contract",
    )
    source_expected = {
        key: provider[key]
        for key in (
            "repository_url",
            "version",
            "annotated_tag",
            "annotated_tag_object_sha1",
            "dereferenced_commit_sha1",
            "source_tree_sha1",
        )
    }
    if (
        any(
            receipt["source"].get(key) != value
            for key, value in source_expected.items()
        )
        or receipt["source"].get("pristine_upstream_source_proven") is not True
        or receipt["source"].get("build_source_derived") is not True
        or not isinstance(receipt["source"].get("lockfiles"), list)
        or not receipt["source"]["lockfiles"]
        or not isinstance(receipt["source"].get("patched_sources"), list)
    ):
        raise BuildError("builder receipt source pin mismatch")
    if provider_name == "codex":
        archive = receipt["source"].get("source_archive")
        derived = receipt["source"].get("derived_build_source")
        assets = receipt["source"].get("dependency_assets")
        codex_cargo, codex_rustc = _codex_toolchain_paths(
            recipe["builder"]["rust_version"],
            receipt["builder"].get("profile"),
        )
        if (
            not isinstance(archive, dict)
            or archive.get("sha256") != provider["source_archive"]["sha256"]
            or archive.get("byte_length")
            != provider["source_archive"]["byte_length"]
            or len(receipt["source"]["patched_sources"]) != 1
            or not isinstance(derived, dict)
            or not isinstance(assets, dict)
        ):
            raise BuildError("Codex pristine/derived source receipt is incomplete")
        _expect_keys(
            derived,
            EXPECTED_CODEX_DERIVED_BUILD_SOURCE_KEYS,
            "Codex derived build source receipt",
        )
        _expect_keys(
            assets,
            EXPECTED_CODEX_DEPENDENCY_ASSET_KEYS,
            "Codex dependency assets receipt",
        )
        if (
            derived["schema"] != "trillionnium.codex-derived-build-source.v1"
            or derived["pristine_source_tree_sha1"] != provider["source_tree_sha1"]
            or derived["transformation"]
            != provider["derived_lock"]["transformation"]
            or derived["workspace_version"]
            != provider["derived_lock"]["workspace_version"]
            or derived["workspace_package_count"]
            != provider["derived_lock"]["workspace_package_count"]
            or derived["workspace_package_names_sha256"]
            != provider["derived_lock"]["workspace_package_names_sha256"]
            or derived["pre_build_source_inventory_sha256"]
            != derived["post_build_source_inventory_sha256"]
            or derived["cargo_metadata_command"]
            != [
                str(codex_cargo),
                "--config",
                "/output/.work/cargo-source-config.toml",
                "metadata",
                "--frozen",
                "--format-version",
                "1",
                "--filter-platform",
                provider["cargo_target"],
            ]
            or derived["lock_patch"] != receipt["source"]["patched_sources"][0]
            or assets["source_archive"] != archive
        ):
            raise BuildError("Codex derived source semantics drifted")
        _require_hex(
            derived["pre_build_source_inventory_sha256"],
            64,
            "Codex derived source inventory",
        )
        expected_asset_pins = {
            "tag_object": provider["source_identity"]["tag_object"],
            "commit_object": provider["source_identity"]["commit_object"],
            "source_member_manifest": provider["source_identity"][
                "source_member_manifest"
            ],
            "source_logical_symlinks": provider["source_identity"][
                "logical_symlinks"
            ],
            "cargo_vendor_archive": provider["cargo_vendor"]["archive"],
            "cargo_vendor_member_manifest": provider["cargo_vendor"][
                "member_manifest"
            ],
            "cargo_source_config": provider["cargo_source_config"],
            "rusty_v8_archive": provider["rusty_v8"]["archive"],
            "rusty_v8_binding": provider["rusty_v8"]["binding"],
            "rusty_v8_checksums": provider["rusty_v8"]["checksums"],
        }
        for name, pin in expected_asset_pins.items():
            artifact = assets[name]
            if (
                not isinstance(artifact, dict)
                or artifact.get("byte_length") != pin["byte_length"]
                or artifact.get("sha256") != pin["sha256"]
            ):
                raise BuildError(f"Codex dependency asset pin drifted: {name}")
        if assets["cargo_vendor_contract"] != {
            "root_name": provider["cargo_vendor"]["root_name"],
            "entry_count": provider["cargo_vendor"]["entry_count"],
            "pre_build_inventory_sha256": provider["cargo_vendor"][
                "inventory_sha256"
            ],
            "post_build_inventory_sha256": provider["cargo_vendor"][
                "inventory_sha256"
            ],
            "cache_bind_mount_read_only": True,
            "archive_retained_in_builder_output": False,
        }:
            raise BuildError("Codex Cargo vendor receipt contract drifted")
        if assets["rusty_v8_contract"] != {
            key: provider["rusty_v8"][key]
            for key in (
                "crate_version",
                "crate_checksum_sha256",
                "target",
                "variant",
                "resolved_features",
                "archive_uncompressed_byte_length",
                "archive_uncompressed_sha256",
                "release_prerelease",
                "release_immutable",
                "upstream_signature_proven",
                "github_attestation_proven",
            )
        }:
            raise BuildError("Codex rusty_v8 receipt contract drifted")

    profile = receipt["builder"].get("profile")
    if profile not in BUILDER_PROFILES:
        raise BuildError("builder receipt profile is not frozen")
    _validate_retained_artifact_resolver(
        receipt["builder"].get("retained_artifact_resolver"),
        "builder receipt",
    )
    expected_profile = recipe["builder"]["profiles"][profile]
    if (
        receipt["builder"].get("base_image") != recipe["builder"]["base_image"]
        or receipt["builder"].get("canonical_base_image")
        != recipe["builder"]["canonical_base_image"]
        or receipt["builder"].get("platform") != expected_profile["platform"]
        or receipt["builder"].get("base_platform_manifest_sha256")
        != expected_profile["manifest_sha256"]
        or receipt["builder"].get("image_build_network")
        != recipe["builder"]["image_build_network"]
        or receipt["builder"].get("rust_version") != recipe["builder"]["rust_version"]
        or receipt["builder"].get("zig_version") != recipe["builder"]["zig_version"]
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", receipt["builder"].get("built_image_id", "")
        )
        is None
    ):
        raise BuildError("builder receipt base image pin mismatch")
    lifecycle_inputs = receipt["recipe"]
    if any(
        not isinstance(lifecycle_inputs[name], dict)
        or not isinstance(lifecycle_inputs[name].get("sha256"), str)
        for name in ("file", "builder", "containerfile")
    ):
        raise BuildError("builder receipt lifecycle input artifacts are malformed")
    _verify_build_context_lifecycle_inputs(
        receipt["builder"]["build_context"],
        recipe_sha256=lifecycle_inputs["file"]["sha256"],
        builder_sha256=lifecycle_inputs["builder"]["sha256"],
        containerfile_sha256=lifecycle_inputs["containerfile"]["sha256"],
    )
    _verify_container_projection(
        receipt["container"],
        provider_name=provider_name,
        profile=profile,
        recipe_sha256=lifecycle_inputs["file"]["sha256"],
        builder_sha256=lifecycle_inputs["builder"]["sha256"],
        containerfile_sha256=lifecycle_inputs["containerfile"]["sha256"],
        image_reference=receipt["builder"]["built_image_id"],
        expected_build_context=receipt["builder"]["build_context"],
        allow_pending=allow_pending_container_custody,
    )
    for tool_name in (
        "compiler",
        "bootstrap_compiler",
        "assembler",
        "linker",
        "build_driver",
    ):
        tool = receipt["builder"][tool_name]
        if set(tool) != {"source_path", "byte_length", "sha256"}:
            raise BuildError(f"builder {tool_name} measurement shape drifted")
        if (
            not isinstance(tool["source_path"], str)
            or not tool["source_path"].startswith("/")
            or not isinstance(tool["byte_length"], int)
            or tool["byte_length"] <= 0
        ):
            raise BuildError(f"builder {tool_name} measurement is malformed")
        _require_hex(tool["sha256"], 64, f"builder.{tool_name}.sha256")
    if provider_name == "codex":
        expected_tool_paths = {
            "compiler": str(codex_rustc),
            "bootstrap_compiler": "/opt/zig/zig",
            "assembler": "/opt/zig/zig",
            "linker": "/opt/zig/zig",
            "build_driver": str(codex_cargo),
        }
    else:
        raise BuildError("builder tool path is outside the Codex singleton")
    if any(
        receipt["builder"][name]["source_path"] != expected_path
        for name, expected_path in expected_tool_paths.items()
    ):
        raise BuildError("builder tool source path drifted")

    closure = receipt["bootstrap"].get("object_closure")
    expected_zero_closure = {
        "undefined_symbol_count",
        "tls_section_count",
        "plt_section_count",
        "got_section_count",
        "ifunc_symbol_count",
        "init_dependency_count",
        "preinit_dependency_count",
        "stack_protector_reference_count",
        "unexpected_relocation_count",
    }
    if (
        not isinstance(closure, dict)
        or set(closure) != expected_zero_closure
        or any(value != 0 for value in closure.values())
        or receipt["bootstrap"].get("expected_filter_instruction_count") != 37
    ):
        raise BuildError("bootstrap object closure or filter count drifted")
    if (
        receipt["build"].get("working_directory") != "/output/.work"
        or receipt["build"].get("resource_contract")
        != _provider_resource_contract(provider_name, provider)
        or receipt["build"].get("container_network") != "none"
        or receipt["build"].get("container_proxy_environment")
        != _container_proxy_environment()
        or receipt["build"].get("externally_supplied_definitions")
        != recipe["bootstrap"]["externally_supplied_definitions"]
        or receipt["build"].get("compiler_arguments")
        != _bootstrap_compile_arguments(recipe, provider)
    ):
        raise BuildError(
            "build working directory, definition, or compiler recipe drifted"
        )
    _validate_arguments(receipt["build"]["command"])
    _validate_arguments(receipt["build"]["compiler_arguments"])
    if not isinstance(
        receipt["build"].get("ordered_provider_objects"), list
    ) or receipt["build"]["ordered_provider_objects"] != [
        receipt["bootstrap"]["core_object"],
        receipt["bootstrap"]["mechanism_object"],
    ]:
        raise BuildError("provider object link order drifted")
    environment = receipt["build"].get("environment")
    if not isinstance(environment, list) or not environment:
        raise BuildError("builder environment receipt is empty or malformed")
    names: set[str] = set()
    for binding in environment:
        if (
            not isinstance(binding, dict)
            or set(binding) != {"name", "value"}
            or not isinstance(binding["name"], str)
            or not isinstance(binding["value"], str)
            or not binding["name"]
            or "\0" in binding["name"]
            or "\0" in binding["value"]
            or binding["name"].startswith("LD_")
            or binding["name"] in names
        ):
            raise BuildError("builder environment receipt is ambiguous or unsafe")
        names.add(binding["name"])
    if not {"PATH", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH"}.issubset(names):
        raise BuildError("builder environment omits its deterministic baseline")
    if provider_name == "codex":
        recorded_environment = {
            binding["name"]: binding["value"] for binding in environment
        }
        wrapper_root = Path("/output/.work/build/target-toolchain")
        expected_codex_environment = {
            "AR_aarch64_unknown_linux_musl": str(
                wrapper_root / CODEX_TARGET_TOOLCHAIN_WRAPPERS["ar"][0]
            ),
            "AWS_LC_SYS_CMAKE_BUILDER": "0",
            "CC_aarch64_unknown_linux_musl": str(
                wrapper_root / CODEX_TARGET_TOOLCHAIN_WRAPPERS["cc"][0]
            ),
            "CFLAGS_aarch64_unknown_linux_musl": (
                "-pthread -Wno-error=frame-larger-than"
            ),
            "CMAKE_GENERATOR": "Ninja",
            "CXX_aarch64_unknown_linux_musl": str(
                wrapper_root / CODEX_TARGET_TOOLCHAIN_WRAPPERS["cxx"][0]
            ),
            "CXXFLAGS_aarch64_unknown_linux_musl": (
                "-pthread -Wno-error=frame-larger-than"
            ),
            "HOST_AR": "/usr/bin/ar",
            "HOST_CC": "/usr/bin/gcc",
            "HOST_CXX": "/usr/bin/g++",
            "HOST_RANLIB": "/usr/bin/ranlib",
            "PATH": (
                f"{wrapper_root}:{codex_cargo.parent}:"
                f"{_base_environment(recipe)['PATH']}"
            ),
            "RANLIB_aarch64_unknown_linux_musl": str(
                wrapper_root / CODEX_TARGET_TOOLCHAIN_WRAPPERS["ranlib"][0]
            ),
        }
        expected_codex_environment.update(
            _codex_profile_environment(provider)
        )
        expected_rust_flags = _codex_rust_flags(
            provider,
            {
                "core": Path(
                    "/output/.work/build/provider-post-exec-bootstrap.o"
                ),
                "mechanism": Path(
                    "/output/.work/build/provider-post-exec-entry.o"
                ),
            },
            Path("/output/.work/build/final.map"),
        )
        if (
            any(
                recorded_environment.get(name) != value
                for name, value in expected_codex_environment.items()
            )
            or recorded_environment.get("CARGO_NET_OFFLINE") != "true"
            or recorded_environment.get("RUSTUP_HOME") != "/usr/local/rustup"
            or recorded_environment.get("RUSTUP_TOOLCHAIN")
            != recipe["builder"]["rust_version"]
            or recorded_environment.get("RUSTC") != str(codex_rustc)
            or recorded_environment.get(
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
            )
            != str(
                wrapper_root / CODEX_TARGET_TOOLCHAIN_WRAPPERS["linker"][0]
            )
            or recorded_environment.get("CARGO_ENCODED_RUSTFLAGS")
            != "\x1f".join(expected_rust_flags)
            or recorded_environment.get("RUSTY_V8_ARCHIVE")
            != (
                "/cache/"
                f"{provider['rusty_v8']['archive']['filename']}"
            )
            or recorded_environment.get("RUSTY_V8_SRC_BINDING_PATH")
            != (
                "/cache/"
                f"{provider['rusty_v8']['binding']['filename']}"
            )
            or receipt["build"]["command"]
            != _codex_build_command(
                codex_cargo,
                "/output/.work/cargo-source-config.toml",
                provider,
            )
        ):
            raise BuildError(
                "Codex frozen offline low-resource build contract drifted"
            )

    retained_contract = receipt["retained_fd_contract"]
    if retained_contract != _retained_fd_contract():
        raise BuildError("retained-FD consumer contract drifted")
    if receipt["final_elf"].get("logical_path") != "codex":
        raise BuildError("final ELF logical identity drifted")
    if receipt["build"]["final_link_provenance"] is not None:
        raise BuildError("final-link provenance provider scope drifted")
    if (
        receipt["elf_contract"].get("has_symbol_table") is not True
        or receipt["elf_contract"].get("has_writable_executable_segment") is not False
        or receipt["elf_contract"].get("gnu_stack_executable") is not False
    ):
        raise BuildError(
            "final ELF receipt admits stripped or executable-writable state"
        )
    expected_recipe_sha256 = (
        _sha256_file(RECIPE_PATH)
        if verification_sources is None
        else verification_sources["recipe_sha256"]
    )
    expected_containerfile_sha256 = (
        _sha256_file(CONTAINERFILE_PATH)
        if verification_sources is None
        else verification_sources["containerfile_sha256"]
    )
    expected_builder_sha256 = (
        _sha256_file(Path(__file__).resolve())
        if verification_sources is None
        else verification_sources["builder_sha256"]
    )
    if (
        receipt["recipe"]["file"]["sha256"] != expected_recipe_sha256
        or receipt["recipe"]["containerfile"]["sha256"]
        != expected_containerfile_sha256
        or receipt["recipe"]["builder"]["sha256"]
        != expected_builder_sha256
    ):
        raise BuildError(
            "retained recipe, Containerfile, or builder differs from checked-in source"
        )
    bootstrap_expected = [
        (
            receipt["bootstrap"]["public_header"],
            recipe["bootstrap"]["public_header"],
        ),
        (
            receipt["bootstrap"]["freestanding_core_source"],
            recipe["bootstrap"]["freestanding_core"],
        ),
        (
            receipt["bootstrap"]["mechanism_source"],
            recipe["bootstrap"]["codex_entry"],
        ),
    ]
    for actual, expected in bootstrap_expected:
        if actual["sha256"] != expected["sha256"]:
            raise BuildError(
                "retained bootstrap source digest differs from frozen recipe"
            )
    lockfiles = {
        artifact.get("logical_path"): artifact
        for artifact in receipt["source"]["lockfiles"]
        if isinstance(artifact, dict)
    }
    if provider_name == "codex":
        expected_lock_hashes = {
            "source/upstream/codex-rs/Cargo.lock": provider["lockfiles"][
                "codex-rs/Cargo.lock"
            ],
            "source/derived/codex-rs/Cargo.lock": provider["derived_lock"][
                "derived_sha256"
            ],
            "source/pristine/codex-rs/rust-toolchain.toml": provider["lockfiles"][
                "codex-rs/rust-toolchain.toml"
            ],
        }
        if (
            set(lockfiles) != set(expected_lock_hashes)
            or any(
                lockfiles[path].get("sha256") != digest
                for path, digest in expected_lock_hashes.items()
            )
            or receipt["source"]["derived_build_source"]["upstream_lock"]
            != lockfiles["source/upstream/codex-rs/Cargo.lock"]
            or receipt["source"]["derived_build_source"]["derived_lock"]
            != lockfiles["source/derived/codex-rs/Cargo.lock"]
        ):
            raise BuildError("Codex pristine/derived lockfile inventory drifted")
    else:
        raise BuildError("lockfile inventory is outside the Codex singleton")
    retained = list(_retained_artifacts(receipt))
    by_logical_path: dict[str, Mapping[str, Any]] = {}
    for artifact in retained:
        logical = artifact["logical_path"]
        previous = by_logical_path.setdefault(logical, artifact)
        if previous != artifact:
            raise BuildError("builder receipt gives one path divergent identities")
    with _retained_artifact_snapshots_from_fd(
        root_descriptor, by_logical_path.values()
    ) as copies:
        if provider_name == "codex":
            _verify_codex_target_toolchain_wrappers(
                copies,
                receipt["build"]["target_toolchain_wrappers"],
            )
            _verify_codex_retained_source_contract(
                copies,
                receipt,
                provider,
                recipe,
            )
        if receipt["build"]["target_static_libraries"] != []:
            raise BuildError("Codex target static-library receipt must be empty")
        _verify_runtime_closure(
            copies,
            receipt["build"]["runtime_closure"],
            receipt["build"]["runtime_closure_manifest"],
            provider_name,
            receipt["elf_contract"],
            profile,
        )
        _verify_dependency_manifest(
            copies,
            receipt["build"]["dependency_manifest"],
            receipt["source"]["source_archive"],
            receipt["source"]["lockfiles"],
            receipt["source"]["patched_sources"],
            receipt["source"]["derived_build_source"],
            receipt["source"]["dependency_assets"],
            [
                receipt["bootstrap"]["public_header"],
                receipt["bootstrap"]["freestanding_core_source"],
                receipt["bootstrap"]["mechanism_source"],
            ],
            _runtime_abi_contract_sha256(
                provider_name,
                receipt["elf_contract"],
                receipt["build"]["runtime_closure"],
            ),
            receipt["build"]["target_static_libraries"],
        )
        final_path = _artifact_path(copies, receipt["final_elf"])
        core_path = _artifact_path(copies, receipt["bootstrap"]["core_object"])
        mechanism_path = _artifact_path(
            copies, receipt["bootstrap"]["mechanism_object"]
        )
        with tempfile.TemporaryDirectory(prefix="provider-elf-verify.") as temporary:
            inspected = _inspect_final_elf(
                final_path,
                provider_name,
                core_path,
                Path(temporary),
                recipe,
                mechanism_object=mechanism_path,
            )
            if (
                _verify_filter_object_binding(
                    final_path, core_path, Path(temporary) / "filter-binding"
                )
                != inspected["filter"]["sha256"]
            ):
                raise BuildError(
                    "retained final filter measurement is inconsistent"
                )
        if receipt["elf_contract"] != inspected:
            raise BuildError(
                "retained final ELF contract differs from re-inspection"
            )
    return receipt


def _verify_builder_output(
    root: Path,
    *,
    allow_pending_container_custody: bool = False,
) -> dict[str, Any]:
    root_descriptor = _open_fixed_root(root)
    try:
        return _verify_builder_output_fd(
            root_descriptor,
            allow_pending_container_custody=(
                allow_pending_container_custody
            ),
        )
    finally:
        os.close(root_descriptor)


def _equal_output_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "source": receipt["source"],
        "resource_contract": receipt["build"]["resource_contract"],
        "bootstrap_core_sha256": receipt["bootstrap"]["core_object"]["sha256"],
        "mechanism_sha256": receipt["bootstrap"]["mechanism_object"]["sha256"],
        "filter_sha256": receipt["bootstrap"]["filter"]["sha256"],
        "link_map": receipt["build"]["link_map"],
        "link_map_sha256": receipt["build"]["link_map"]["sha256"],
        "final_link_provenance": receipt["build"].get("final_link_provenance"),
        "dependency_manifest": receipt["build"]["dependency_manifest"],
        "dependency_manifest_sha256": receipt["build"]["dependency_manifest"]["sha256"],
        "runtime_abi_contract_sha256": _runtime_abi_contract_sha256(
            receipt["provider"],
            receipt["elf_contract"],
            receipt["build"]["runtime_closure"],
        ),
        "target_static_libraries": _normalized_static_libraries(
            receipt["build"]["target_static_libraries"]
        ),
        "target_toolchain_wrappers": receipt["build"][
            "target_toolchain_wrappers"
        ],
        "final_elf_sha256": receipt["final_elf"]["sha256"],
        "final_elf_bytes": receipt["final_elf"]["byte_length"],
        "elf_contract": receipt["elf_contract"],
    }


def _reproducibility_receipt_hash(receipt: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return _domain_digest(REPRODUCIBILITY_DIGEST_DOMAIN, [_json_bytes(unsigned)])


def _reconcile(builder_roots: Sequence[Path], output: Path) -> None:
    if len(builder_roots) != 2:
        raise BuildError("reconciliation requires exactly two builder outputs")
    roots = [path.absolute() for path in builder_roots]
    root_descriptors: list[int] = []
    try:
        for root in roots:
            root_descriptors.append(_open_fixed_root(root))
        _reconcile_from_fds(root_descriptors, output)
    finally:
        for descriptor in reversed(root_descriptors):
            os.close(descriptor)


def _runtime_candidate_artifact_paths(
    receipt: Mapping[str, Any],
) -> set[str]:
    if receipt["build"]["runtime_closure"] != []:
        raise BuildError("fully-static runtime candidate cannot contain DSOs")
    manifest = receipt["build"]["runtime_closure_manifest"]
    if not isinstance(manifest, Mapping) or not isinstance(
        manifest.get("logical_path"), str
    ):
        raise BuildError("runtime candidate manifest artifact is malformed")
    return {manifest["logical_path"]}


def _stage_runtime_candidate(
    stage: Path,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    profile = receipt["builder"]["profile"]
    if profile not in BUILDER_PROFILES:
        raise BuildError("runtime candidate profile is not frozen")
    entries = receipt["build"]["runtime_closure"]
    if entries != []:
        raise BuildError("fully-static runtime candidate cannot contain DSOs")
    manifest_logical_path = (
        f"runtime-candidates/{profile}/runtime-closure.json"
    )
    manifest_path = stage / manifest_logical_path
    _write_bytes(
        manifest_path,
        _json_bytes(
            _runtime_closure_manifest_value(
                receipt["provider"], []
            )
        ),
    )
    return {
        "profile": profile,
        "platform": receipt["builder"]["platform"],
        "base_platform_manifest_sha256": receipt["builder"][
            "base_platform_manifest_sha256"
        ],
        "runtime_closure_manifest": _artifact(
            manifest_path, manifest_logical_path
        ),
        "bundle_inventory_sha256": _runtime_bundle_inventory_sha256(
            []
        ),
        "abi_contract_sha256": _runtime_abi_contract_sha256(
            receipt["provider"], receipt["elf_contract"], []
        ),
    }


def _reconcile_builder_receipt_preflight_fd(
    root_descriptor: int,
    recipe: Mapping[str, Any],
) -> dict[str, Any]:
    builder_receipt = "provider-builder-receipt.json"
    reproducibility_receipt = "provider-reproducibility-receipt.json"
    failure_receipt = "provider-build-failure-receipt.json"
    if (
        not _fixed_root_entry_exists_fd(root_descriptor, builder_receipt)
        or _fixed_root_entry_exists_fd(
            root_descriptor, reproducibility_receipt
        )
        or _fixed_root_entry_exists_fd(root_descriptor, failure_receipt)
    ):
        raise BuildError(
            "reconciliation preflight requires exactly one builder receipt kind"
        )
    receipt = _read_json_from_fixed_root_fd(
        root_descriptor,
        builder_receipt,
        MAX_RECEIPT_BYTES,
    )
    provider_name = receipt.get("provider")
    if (
        receipt.get("schema") != BUILDER_RECEIPT_SCHEMA
        or provider_name not in PROVIDERS
        or "source_checkpoint" not in receipt
    ):
        raise BuildError(
            "reconciliation builder receipt preflight identity is malformed"
        )
    _verify_source_checkpoint_projection(
        provider_name,
        recipe["providers"][provider_name],
        receipt["source_checkpoint"],
        "reconciliation builder receipt preflight",
    )
    return receipt


def _reconcile_from_fds(
    root_descriptors: Sequence[int], output: Path
) -> None:
    if len(root_descriptors) != 2:
        raise BuildError("reconciliation requires exactly two pinned roots")
    identities = []
    for descriptor in root_descriptors:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise BuildError("reconciliation root descriptor is not a directory")
        identities.append((metadata.st_dev, metadata.st_ino))
    if identities[0] == identities[1]:
        raise BuildError("reconciliation requires two different retained roots")
    recipe = load_recipe()
    preflight_receipts = [
        _reconcile_builder_receipt_preflight_fd(descriptor, recipe)
        for descriptor in root_descriptors
    ]
    receipts = [
        _verify_builder_output_fd(
            descriptor,
            preloaded_receipt=preloaded_receipt,
        )
        for descriptor, preloaded_receipt in zip(
            root_descriptors, preflight_receipts, strict=True
        )
    ]
    for receipt, preloaded_receipt in zip(
        receipts, preflight_receipts, strict=True
    ):
        if receipt is not preloaded_receipt or any(
            receipt.get(field) != preloaded_receipt.get(field)
            for field in ("schema", "provider", "source_checkpoint")
        ):
            raise BuildError(
                "full builder verification did not consume its preflight receipt"
            )
    paired = sorted(
        zip(receipts, root_descriptors, strict=True),
        key=lambda pair: BUILDER_PROFILES.index(pair[0]["builder"]["profile"]),
    )
    receipts = [pair[0] for pair in paired]
    root_descriptors = [pair[1] for pair in paired]
    profiles = [receipt["builder"]["profile"] for receipt in receipts]
    if (
        profiles[0] == profiles[1]
        or set(profiles) != set(BUILDER_PROFILES)
        or receipts[0]["builder"]["built_image_id"]
        == receipts[1]["builder"]["built_image_id"]
        or receipts[0]["builder"]["base_platform_manifest_sha256"]
        == receipts[1]["builder"]["base_platform_manifest_sha256"]
    ):
        raise BuildError("builder identities are not the frozen independent 2/2 set")
    for field in (
        "provider",
        "target_architecture",
        "source_date_epoch",
        "recipe",
        "bootstrap",
        "retained_fd_contract",
        "source_checkpoint",
    ):
        if receipts[0][field] != receipts[1][field]:
            raise BuildError(f"independent builder {field} projections differ")
    projections = [_equal_output_projection(receipt) for receipt in receipts]
    if projections[0] != projections[1]:
        raise BuildError(
            "independent builder payload or runtime ABI outputs differ"
        )
    if output.exists() or output.is_symlink():
        raise BuildError(f"reconciled output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}.", dir=output.parent
    ) as temporary:
        stage = Path(temporary)
        stage_metadata = os.stat(stage, follow_symlinks=False)
        if not stat.S_ISDIR(stage_metadata.st_mode):
            raise BuildError("reconciliation stage is not one pinned directory")
        stage_identity = (stage_metadata.st_dev, stage_metadata.st_ino)
        runtime_artifact_paths = _runtime_candidate_artifact_paths(receipts[0])
        retained = [
            artifact
            for artifact in _retained_artifacts(receipts[0])
            if artifact["logical_path"] not in runtime_artifact_paths
        ]
        copied: set[str] = set()
        with _retained_artifact_snapshots_from_fd(
            root_descriptors[0], retained
        ) as copies:
            for artifact in retained:
                logical = artifact["logical_path"]
                if logical in copied:
                    continue
                copied.add(logical)
                source_path = _artifact_path(copies, artifact)
                mode = (
                    0o555
                    if logical == receipts[0]["final_elf"]["logical_path"]
                    else 0o444
                )
                _stage_artifact(source_path, stage, logical, mode=mode)
        runtime_candidates = [
            _stage_runtime_candidate(stage, receipt_value)
            for receipt_value in receipts
        ]
        if (
            [candidate["profile"] for candidate in runtime_candidates]
            != list(BUILDER_PROFILES)
            or any(
                candidate["abi_contract_sha256"]
                != projections[0]["runtime_abi_contract_sha256"]
                for candidate in runtime_candidates
            )
        ):
            raise BuildError("runtime candidate ABI projection drifted")
        final_name = receipts[0]["final_elf"]["logical_path"]
        final_artifact = _artifact(stage / final_name, final_name)
        receipt: dict[str, Any] = {
            "schema": REPRODUCIBILITY_RECEIPT_SCHEMA,
            "provider": receipts[0]["provider"],
            "target_architecture": TARGET_ARCHITECTURE,
            "source_date_epoch": receipts[0]["source_date_epoch"],
            "recipe": receipts[0]["recipe"],
            "source": receipts[0]["source"],
            "bootstrap": receipts[0]["bootstrap"],
            "build_recipe": {
                "command": receipts[0]["build"]["command"],
                "compiler_arguments": receipts[0]["build"]["compiler_arguments"],
                "externally_supplied_definitions": receipts[0]["build"][
                    "externally_supplied_definitions"
                ],
                "resource_contract": receipts[0]["build"][
                    "resource_contract"
                ],
                "container_network": receipts[0]["build"][
                    "container_network"
                ],
                "container_proxy_environment": receipts[0]["build"][
                    "container_proxy_environment"
                ],
            },
            "builders": [
                {
                    "profile": receipt_value["builder"]["profile"],
                    "platform": receipt_value["builder"]["platform"],
                    "base_platform_manifest_sha256": receipt_value["builder"][
                        "base_platform_manifest_sha256"
                    ],
                    "built_image_id": receipt_value["builder"]["built_image_id"],
                    "build_context": receipt_value["builder"][
                        "build_context"
                    ],
                    "builder_receipt_sha256": receipt_value["receipt_sha256"],
                    "image_build_network": receipt_value["builder"][
                        "image_build_network"
                    ],
                    "retained_artifact_resolver": receipt_value["builder"][
                        "retained_artifact_resolver"
                    ],
                    "container": receipt_value["container"],
                }
                for receipt_value in receipts
            ],
            "equal_outputs": projections[0],
            "runtime_candidates": runtime_candidates,
            "selected_runtime_profile": "arm64-native",
            "final_elf": final_artifact,
            "retained_fd_contract": receipts[0]["retained_fd_contract"],
            "source_checkpoint": receipts[0]["source_checkpoint"],
            "product_active": False,
            "listener_backend_wired": False,
            "admission_wired": False,
            "confers_effect_authority": False,
            "receipt_sha256": "",
        }
        receipt["receipt_sha256"] = _reproducibility_receipt_hash(receipt)
        _write_bytes(
            stage / "provider-reproducibility-receipt.json", _json_bytes(receipt)
        )
        _publish_directory_noreplace(
            stage,
            output,
            stage_identity,
            verifier=_verify_reproducibility_output_fd,
        )


def _verify_reproducibility_build_recipe(
    receipt: Mapping[str, Any],
    equal_outputs: Mapping[str, Any],
    recipe: Mapping[str, Any],
) -> None:
    provider_name = receipt["provider"]
    if provider_name != "codex":
        raise BuildError(
            "reproducibility build recipe is outside the Codex singleton"
        )
    provider = recipe["providers"][provider_name]
    build_recipe = receipt["build_recipe"]
    _expect_keys(
        build_recipe,
        {
            "command",
            "compiler_arguments",
            "externally_supplied_definitions",
            "resource_contract",
            "container_network",
            "container_proxy_environment",
        },
        "reproducibility build_recipe",
    )
    expected_resource_contract = _provider_resource_contract(
        provider_name, provider
    )
    expected_command = _expected_provider_build_command(
        recipe,
        provider_name,
        receipt["builders"][0]["profile"],
    )
    if (
        equal_outputs["resource_contract"] != expected_resource_contract
        or build_recipe["resource_contract"] != expected_resource_contract
        or build_recipe["container_network"] != "none"
        or build_recipe["container_proxy_environment"]
        != _container_proxy_environment()
        or build_recipe["command"] != expected_command
        or build_recipe["compiler_arguments"]
        != _bootstrap_compile_arguments(recipe, provider)
        or build_recipe["externally_supplied_definitions"]
        != recipe["bootstrap"]["externally_supplied_definitions"]
    ):
        raise BuildError(
            "reproducibility low-resource build recipe drifted"
        )
    _validate_arguments(build_recipe["command"])
    _validate_arguments(build_recipe["compiler_arguments"])


def _verify_reproducibility_builders(
    builders: Any,
    recipe: Mapping[str, Any],
    provider_name: str | None = None,
    lifecycle_inputs: Mapping[str, Any] | None = None,
) -> None:
    if not isinstance(builders, list) or len(builders) != 2:
        raise BuildError("reproducibility receipt 2/2 builder set drifted")
    profiles: set[str] = set()
    for builder in builders:
        if not isinstance(builder, dict):
            raise BuildError("reproducibility builder identity is malformed")
        _expect_keys(
            builder,
            EXPECTED_REPRODUCIBILITY_BUILDER_KEYS,
            "reproducibility builder identity",
        )
        profile = builder["profile"]
        if profile not in BUILDER_PROFILES:
            raise BuildError("reproducibility builder profile is not frozen")
        profiles.add(profile)
        expected_profile = recipe["builder"]["profiles"][profile]
        if (
            builder["platform"] != expected_profile["platform"]
            or builder["base_platform_manifest_sha256"]
            != expected_profile["manifest_sha256"]
            or builder["image_build_network"]
            != recipe["builder"]["image_build_network"]
            or not isinstance(builder["built_image_id"], str)
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}", builder["built_image_id"]
            )
            is None
        ):
            raise BuildError("reproducibility builder identity drifted")
        _require_hex(
            builder["builder_receipt_sha256"],
            64,
            "reproducibility builder receipt hash",
        )
        _validate_retained_artifact_resolver(
            builder["retained_artifact_resolver"],
            "reproducibility receipt",
        )
        _verify_build_context_receipt(builder["build_context"])
        container = builder["container"]
        if not isinstance(container, dict) or not isinstance(
            container.get("command"),
            list,
        ):
            raise BuildError(
                "reproducibility builder container projection is incomplete"
            )
        command = container["command"]
        command_provider = _one_command_option_value(
            command,
            "--provider",
            "reproducibility container command",
        )
        if (
            provider_name is not None
            and command_provider != provider_name
        ):
            raise BuildError(
                "reproducibility container provider projection drifted"
            )
        if lifecycle_inputs is not None:
            _verify_build_context_lifecycle_inputs(
                builder["build_context"],
                recipe_sha256=lifecycle_inputs["file"]["sha256"],
                builder_sha256=lifecycle_inputs["builder"]["sha256"],
                containerfile_sha256=lifecycle_inputs[
                    "containerfile"
                ]["sha256"],
            )
            expected_lifecycle_hashes = {
                "--recipe-sha256": lifecycle_inputs["file"]["sha256"],
                "--builder-sha256": lifecycle_inputs["builder"]["sha256"],
                "--containerfile-sha256": lifecycle_inputs[
                    "containerfile"
                ]["sha256"],
            }
            if any(
                _one_command_option_value(
                    command,
                    option,
                    "reproducibility container command",
                )
                != expected
                for option, expected in expected_lifecycle_hashes.items()
            ):
                raise BuildError(
                    "reproducibility container input projection drifted"
                )
        _verify_container_projection(
            container,
            provider_name=command_provider,
            profile=profile,
            recipe_sha256=_one_command_option_value(
                command,
                "--recipe-sha256",
                "reproducibility container command",
            ),
            builder_sha256=_one_command_option_value(
                command,
                "--builder-sha256",
                "reproducibility container command",
            ),
            containerfile_sha256=_one_command_option_value(
                command,
                "--containerfile-sha256",
                "reproducibility container command",
            ),
            image_reference=builder["built_image_id"],
            expected_build_context=builder["build_context"],
        )
    if profiles != set(BUILDER_PROFILES):
        raise BuildError("reproducibility receipt 2/2 builder set drifted")
    if (
        len({builder["built_image_id"] for builder in builders}) != 2
        or len(
            {
                json.dumps(
                    builder["build_context"],
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for builder in builders
            }
        )
        != 1
        or len(
            {
                builder["base_platform_manifest_sha256"]
                for builder in builders
            }
        )
        != 2
    ):
        raise BuildError(
            "reproducibility receipt builder identities are not independent"
        )


def _runtime_candidate_manifest_entries(
    copies: Mapping[str, Path],
    candidate: Mapping[str, Any],
    provider_name: str,
) -> list[dict[str, Any]]:
    manifest = _read_json(
        _artifact_path(copies, candidate["runtime_closure_manifest"])
    )
    if manifest != _runtime_closure_manifest_value(provider_name, []):
        raise BuildError("fully-static runtime candidate manifest drifted")
    return []


def _verify_runtime_candidate_headers(
    candidates: Any,
    selected_runtime_profile: Any,
    builders: Sequence[Mapping[str, Any]],
    equal_outputs: Mapping[str, Any],
) -> None:
    if (
        not isinstance(candidates, list)
        or len(candidates) != 2
        or selected_runtime_profile != "arm64-native"
        or any(not isinstance(candidate, dict) for candidate in candidates)
    ):
        raise BuildError("runtime candidate selection set drifted")
    by_profile = {builder["profile"]: builder for builder in builders}
    if [candidate.get("profile") for candidate in candidates] != list(
        BUILDER_PROFILES
    ):
        raise BuildError("runtime candidate profile order drifted")
    for candidate in candidates:
        _expect_keys(
            candidate,
            EXPECTED_RUNTIME_CANDIDATE_KEYS,
            "runtime candidate",
        )
        profile = candidate["profile"]
        manifest_artifact = candidate["runtime_closure_manifest"]
        if (
            not isinstance(profile, str)
            or not isinstance(manifest_artifact, dict)
            or set(manifest_artifact)
            != {"logical_path", "byte_length", "sha256"}
        ):
            raise BuildError("runtime candidate identity is malformed")
        builder = by_profile.get(profile)
        expected_manifest_path = (
            f"runtime-candidates/{profile}/runtime-closure.json"
        )
        if (
            builder is None
            or candidate["platform"] != builder["platform"]
            or candidate["base_platform_manifest_sha256"]
            != builder["base_platform_manifest_sha256"]
            or manifest_artifact["logical_path"]
            != expected_manifest_path
            or candidate["abi_contract_sha256"]
            != equal_outputs["runtime_abi_contract_sha256"]
        ):
            raise BuildError("runtime candidate builder cross-binding drifted")
        _require_hex(
            candidate["bundle_inventory_sha256"],
            64,
            "runtime candidate bundle inventory",
        )
        _require_hex(
            candidate["abi_contract_sha256"],
            64,
            "runtime candidate ABI contract",
        )


def _verify_runtime_candidates(
    copies: Mapping[str, Path],
    candidates: Sequence[Mapping[str, Any]],
    provider_name: str,
    elf_contract: Mapping[str, Any],
    equal_outputs: Mapping[str, Any],
) -> None:
    for candidate in candidates:
        entries = _runtime_candidate_manifest_entries(
            copies, candidate, provider_name
        )
        _verify_runtime_closure(
            copies,
            entries,
            candidate["runtime_closure_manifest"],
            provider_name,
            elf_contract,
            candidate["profile"],
        )
        if (
            candidate["bundle_inventory_sha256"]
            != _runtime_bundle_inventory_sha256(entries)
            or candidate["abi_contract_sha256"]
            != _runtime_abi_contract_sha256(
                provider_name, elf_contract, entries
            )
            or candidate["abi_contract_sha256"]
            != equal_outputs["runtime_abi_contract_sha256"]
        ):
            raise BuildError("runtime candidate inventory or ABI digest drifted")


def _verify_reproducibility_output_fd(
    root_descriptor: int,
    *,
    verification_sources: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = _read_json_from_fixed_root_fd(
        root_descriptor, "provider-reproducibility-receipt.json"
    )
    _expect_keys(receipt, EXPECTED_REPRODUCIBILITY_KEYS, "reproducibility receipt")
    builders = receipt["builders"]
    if (
        receipt["schema"] != REPRODUCIBILITY_RECEIPT_SCHEMA
        or receipt["provider"] not in PROVIDERS
        or receipt["target_architecture"] != TARGET_ARCHITECTURE
    ):
        raise BuildError("reproducibility receipt identity or 2/2 set drifted")
    recipe = (
        load_recipe()
        if verification_sources is None
        else verification_sources["recipe"]
    )
    if verification_sources is not None:
        if not isinstance(receipt["recipe"], dict):
            raise BuildError("reconciled recipe projection is malformed")
        _expect_keys(
            receipt["recipe"],
            {"file", "containerfile", "builder"},
            "reconciled recipe projection",
        )
        if (
            receipt["recipe"]["file"].get("sha256")
            != verification_sources["recipe_sha256"]
            or receipt["recipe"]["containerfile"].get("sha256")
            != verification_sources["containerfile_sha256"]
            or receipt["recipe"]["builder"].get("sha256")
            != verification_sources["builder_sha256"]
        ):
            raise BuildError(
                "reconciled retained builder/recipe/Containerfile custody drifted"
            )
    _verify_source_checkpoint_projection(
        receipt["provider"],
        recipe["providers"][receipt["provider"]],
        receipt["source_checkpoint"],
        "reproducibility receipt",
    )
    _verify_reproducibility_builders(
        builders,
        recipe,
        receipt["provider"],
        receipt["recipe"],
    )
    _require_false_authority_fields(receipt, "reproducibility receipt")
    retained_contract = receipt["retained_fd_contract"]
    if not isinstance(retained_contract, dict):
        raise BuildError("reproducibility retained-FD contract is malformed")
    _expect_keys(
        retained_contract,
        EXPECTED_RETAINED_FD_CONTRACT,
        "reproducibility retained-FD contract",
    )
    if retained_contract != _retained_fd_contract():
        raise BuildError("reproducibility retained-FD contract drifted")
    if receipt["receipt_sha256"] != _reproducibility_receipt_hash(receipt):
        raise BuildError("reproducibility receipt self-hash mismatch")
    if not isinstance(receipt["equal_outputs"], dict):
        raise BuildError("reproducibility equality output is malformed")
    _expect_keys(
        receipt["equal_outputs"],
        EXPECTED_EQUAL_OUTPUT_KEYS,
        "reproducibility equal_outputs",
    )
    final_link_provenance = receipt["equal_outputs"][
        "final_link_provenance"
    ]
    if final_link_provenance is not None:
        raise BuildError(
            "reproducibility final-link provenance provider scope drifted"
        )
    _require_hex(
        receipt["equal_outputs"]["runtime_abi_contract_sha256"],
        64,
        "reproducibility runtime ABI contract",
    )
    _verify_runtime_candidate_headers(
        receipt["runtime_candidates"],
        receipt["selected_runtime_profile"],
        builders,
        receipt["equal_outputs"],
    )
    by_logical_path: dict[str, Mapping[str, Any]] = {}
    for artifact in _retained_artifacts(receipt):
        logical = artifact["logical_path"]
        previous = by_logical_path.setdefault(logical, artifact)
        if previous != artifact:
            raise BuildError(
                "reproducibility receipt gives one path divergent identities"
            )
    with _retained_artifact_snapshots_from_fd(
        root_descriptor, by_logical_path.values()
    ) as manifest_copies:
        candidate_entries = [
            _runtime_candidate_manifest_entries(
                manifest_copies,
                candidate,
                receipt["provider"],
            )
            for candidate in receipt["runtime_candidates"]
        ]
    for entries in candidate_entries:
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(
                entry.get("file"), dict
            ):
                raise BuildError("runtime candidate entry artifact is malformed")
            artifact = entry["file"]
            logical = artifact.get("logical_path")
            if not isinstance(logical, str):
                raise BuildError("runtime candidate artifact path is malformed")
            previous = by_logical_path.setdefault(logical, artifact)
            if previous != artifact:
                raise BuildError(
                    "runtime candidates give one path divergent identities"
                )
    with _retained_artifact_snapshots_from_fd(
        root_descriptor, by_logical_path.values()
    ) as copies:
        final_path = _artifact_path(copies, receipt["final_elf"])
        equal_outputs = receipt["equal_outputs"]
        core_path = _artifact_path(
            copies, receipt["bootstrap"]["core_object"]
        )
        mechanism_path = _artifact_path(
            copies, receipt["bootstrap"]["mechanism_object"]
        )
        if equal_outputs["final_elf_sha256"] != _sha256_file(final_path):
            raise BuildError(
                "reconciled final ELF differs from 2/2 equality output"
            )
        if (
            equal_outputs["link_map_sha256"]
            != equal_outputs["link_map"]["sha256"]
            or equal_outputs["dependency_manifest_sha256"]
            != equal_outputs["dependency_manifest"]["sha256"]
        ):
            raise BuildError(
                "reconciled link-map or dependency-manifest identity drifted"
            )
        provider = recipe["providers"][receipt["provider"]]
        _verify_reproducibility_build_recipe(
            receipt,
            equal_outputs,
            recipe,
        )
        _verify_codex_target_toolchain_wrappers(
            copies,
            equal_outputs["target_toolchain_wrappers"],
        )
        _verify_codex_retained_source_contract(
            copies,
            receipt,
            provider,
            recipe,
        )
        if equal_outputs["target_static_libraries"] != []:
            raise BuildError("Codex target static-library equality must be empty")
        _verify_runtime_candidates(
            copies,
            receipt["runtime_candidates"],
            receipt["provider"],
            equal_outputs["elf_contract"],
            equal_outputs,
        )
        _verify_dependency_manifest(
            copies,
            equal_outputs["dependency_manifest"],
            receipt["source"]["source_archive"],
            receipt["source"]["lockfiles"],
            receipt["source"]["patched_sources"],
            receipt["source"]["derived_build_source"],
            receipt["source"]["dependency_assets"],
            [
                receipt["bootstrap"]["public_header"],
                receipt["bootstrap"]["freestanding_core_source"],
                receipt["bootstrap"]["mechanism_source"],
            ],
            equal_outputs["runtime_abi_contract_sha256"],
            equal_outputs["target_static_libraries"],
        )
        with tempfile.TemporaryDirectory(
            prefix="provider-reconciled-verify."
        ) as temporary:
            facts = _inspect_final_elf(
                final_path,
                receipt["provider"],
                core_path,
                Path(temporary),
                recipe,
                mechanism_object=mechanism_path,
            )
        if facts != equal_outputs["elf_contract"]:
            raise BuildError(
                "reconciled final ELF contract differs from 2/2 output"
            )
    return receipt


def _verify_reproducibility_output(root: Path) -> dict[str, Any]:
    root_descriptor = _open_fixed_root(root)
    try:
        return _verify_reproducibility_output_fd(root_descriptor)
    finally:
        os.close(root_descriptor)


def _verify_any_output_fd(
    root_descriptor: int,
    *,
    verification_sources: Mapping[str, Any] | None = None,
) -> str:
    root = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root.st_mode):
        raise BuildError("provider output descriptor is not one directory")
    builder_receipt_exists = _fixed_root_entry_exists_fd(
        root_descriptor, "provider-builder-receipt.json"
    )
    reproducibility_receipt_exists = _fixed_root_entry_exists_fd(
        root_descriptor, "provider-reproducibility-receipt.json"
    )
    if builder_receipt_exists == reproducibility_receipt_exists:
        raise BuildError("output must contain exactly one fixed-root receipt kind")
    if builder_receipt_exists:
        return _verify_builder_output_fd(
            root_descriptor,
            verification_sources=verification_sources,
        )["schema"]
    return _verify_reproducibility_output_fd(
        root_descriptor,
        verification_sources=verification_sources,
    )["schema"]


def _verify_supervised_candidate_fd(
    *,
    role: str,
    candidate_descriptor: int,
    expected_output: Path,
    builder_descriptor: int,
    recipe_descriptor: int,
    containerfile_descriptor: int,
    retained_stage_descriptors: Sequence[int],
) -> str:
    descriptors = [
        candidate_descriptor,
        builder_descriptor,
        recipe_descriptor,
        containerfile_descriptor,
        *retained_stage_descriptors,
    ]
    if (
        any(value < 3 for value in descriptors)
        or len(descriptors) != len(set(descriptors))
        or role not in {"success", "failure"}
    ):
        raise BuildError("supervised verifier inherited FD set is ambiguous")
    for descriptor in descriptors:
        _set_descriptor_cloexec(descriptor)
    verification_sources = _retained_verification_sources(
        builder_descriptor,
        recipe_descriptor,
        containerfile_descriptor,
    )
    root_descriptor = os.dup(candidate_descriptor)
    try:
        if role == "success":
            if retained_stage_descriptors:
                raise BuildError("success verification has unexpected retained-stage FDs")
            return _verify_builder_output_fd(
                root_descriptor,
                verification_sources=verification_sources,
            )["schema"]
        retained: dict[tuple[int, int], int] = {}
        for descriptor in retained_stage_descriptors:
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino)
            if not stat.S_ISDIR(opened.st_mode) or identity in retained:
                raise BuildError("retained failure-stage FD set is malformed")
            retained[identity] = descriptor
        receipt = _read_json_from_fixed_root_fd(
            root_descriptor,
            "provider-build-failure-receipt.json",
        )
        if (
            receipt.get("inputs", {}).get("builder", {}).get("sha256")
            != verification_sources["builder_sha256"]
            or receipt.get("inputs", {}).get("recipe", {}).get("sha256")
            != verification_sources["recipe_sha256"]
            or receipt.get("inputs", {}).get("containerfile", {}).get("sha256")
            != verification_sources["containerfile_sha256"]
        ):
            raise BuildError("failure candidate is not bound to retained source FDs")
        referenced_identities = {
            identity
            for record in receipt.get("cleanup_tombstones", [])
            for _, identity in [_validate_stage_identity_record(
                record,
                "supervised failure retained stage",
            )]
        }
        if set(retained) != referenced_identities:
            raise BuildError("failure retained-stage FD set is missing or excessive")
        expected_failure = expected_output.with_name(
            f"{expected_output.name}.failure"
        )
        return _verify_failure_output_fd(
            root_descriptor,
            expected_failure,
            retained_stage_descriptors=retained,
        )["schema"]
    finally:
        os.close(root_descriptor)


def _verify_container_absent(
    engine: str,
    container_name: str,
    container_id: str | None,
) -> None:
    if (
        engine != "docker"
        or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", container_name) is None
        or len(container_name.encode("ascii")) > CONTAINER_NAME_MAX_BYTES
    ):
        raise BuildError("container absence query is outside the closed set")
    if container_id is not None:
        _require_hex(container_id, 64, "container absence ID")
    version = _run(
        [engine, "version", "--format", "{{.Server.Version}}"],
        cwd=DIRECTORY,
        maximum_output=4096,
        require_complete_output=True,
    ).strip()
    if not version or len(version) > 256 or "\n" in version:
        raise BuildError("container daemon liveness response is malformed")
    observed = _run(
        [
            engine,
            "ps",
            "-a",
            "--no-trunc",
            "--format",
            "{{.ID}}\t{{.Names}}",
        ],
        cwd=DIRECTORY,
        maximum_output=512 * 1024,
        require_complete_output=True,
    )
    for line in observed.splitlines():
        fields = line.split("\t")
        if (
            len(fields) != 2
            or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None
            or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", fields[1])
            is None
        ):
            raise BuildError("container daemon inventory response is malformed")
        if fields[1] == container_name or (
            container_id is not None and fields[0] == container_id
        ):
            raise BuildError("provider build container remains present")


def _plan(provider_name: str, profile: str) -> dict[str, Any]:
    recipe = load_recipe()
    if provider_name != "codex":
        raise BuildError("build plan is outside the Codex singleton")
    provider = recipe["providers"][provider_name]
    source_closure = {
        "archive": provider["source_archive"],
        "derived_lock": provider["derived_lock"],
        "cargo_vendor": provider["cargo_vendor"],
        "cargo_source_config": provider["cargo_source_config"],
        "rusty_v8": provider["rusty_v8"],
        "cargo_frozen": True,
        "cargo_offline": True,
        "container_network": "none",
        "vendor_mount_read_only": True,
    }
    return {
        "schema": "trillionnium.provider-exact-source-build-plan.v1",
        "provider": provider["provider_wire_name"],
        "builder_profile": profile,
        "platform": recipe["builder"]["profiles"][profile]["platform"],
        "base_image": recipe["builder"]["base_image"],
        "canonical_base_image": recipe["builder"]["canonical_base_image"],
        "image_build_network": recipe["builder"]["image_build_network"],
        "container_network": "none",
        "container_proxy_environment": _container_proxy_environment(),
        "resource_contract": _provider_resource_contract(
            provider_name, provider
        ),
        "source": {
            "repository_url": provider["repository_url"],
            "annotated_tag": provider["annotated_tag"],
            "annotated_tag_object_sha1": provider["annotated_tag_object_sha1"],
            "dereferenced_commit_sha1": provider["dereferenced_commit_sha1"],
            "source_tree_sha1": provider["source_tree_sha1"],
            "closure": source_closure,
        },
        "accepts_external_binary": False,
        "accepts_external_source_tree": False,
        "accepts_flag_or_environment_override": False,
        "requires_unstripped_final_elf": True,
        "source_checkpoint": _source_checkpoint_projection(
            provider_name, provider
        ),
        "product_active": False,
        "listener_backend_wired": False,
        "admission_wired": False,
        "confers_effect_authority": False,
    }


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_recipe = subparsers.add_parser(
        "verify-recipe", help="validate the checked-in frozen recipe and source digests"
    )
    validate_recipe.set_defaults(handler="verify_recipe")

    plan = subparsers.add_parser(
        "plan", help="print the non-authorizing frozen build plan"
    )
    plan.add_argument("--provider", required=True, choices=PROVIDERS)
    plan.add_argument("--builder-profile", required=True, choices=BUILDER_PROFILES)
    plan.set_defaults(handler="plan")

    build = subparsers.add_parser(
        "build", help="build one source-derived payload in one frozen container"
    )
    build.add_argument("--provider", required=True, choices=PROVIDERS)
    build.add_argument("--builder-profile", required=True, choices=BUILDER_PROFILES)
    build.add_argument("--output-dir", required=True, type=Path)
    build.add_argument("--cache-dir", required=True, type=Path)
    build.add_argument(
        "--container-engine",
        choices=("docker",),
        default="docker",
        help="closed container engine surface; no arbitrary command override",
    )
    build.set_defaults(handler="build")

    verify = subparsers.add_parser(
        "verify", help="re-measure one builder or reconciled output"
    )
    verify.add_argument("--output-dir", required=True, type=Path)
    verify.set_defaults(handler="verify")

    verify_fd = subparsers.add_parser(
        "_verify-retained-fd",
        help=argparse.SUPPRESS,
    )
    verify_fd.add_argument("--output-fd", required=True, type=int)
    verify_fd.add_argument("--builder-fd", required=True, type=int)
    verify_fd.add_argument("--recipe-fd", required=True, type=int)
    verify_fd.add_argument("--containerfile-fd", required=True, type=int)
    verify_fd.set_defaults(handler="verify_fd")

    supervised = subparsers.add_parser(
        "_supervised-build",
        help=argparse.SUPPRESS,
    )
    supervised.add_argument("--provider", required=True, choices=PROVIDERS)
    supervised.add_argument(
        "--builder-profile",
        required=True,
        choices=BUILDER_PROFILES,
    )
    supervised.add_argument("--output-dir", required=True, type=Path)
    supervised.add_argument("--cache-dir", required=True, type=Path)
    supervised.add_argument("--source-root", required=True, type=Path)
    supervised.add_argument("--success-host-path", required=True, type=Path)
    supervised.add_argument("--failure-host-path", required=True, type=Path)
    supervised.add_argument("--socket-fd", required=True, type=int)
    supervised.add_argument("--exec-builder-fd", required=True, type=int)
    supervised.add_argument("--supervisor-pid", required=True, type=int)
    supervised.add_argument(
        "--container-engine",
        choices=("docker",),
        default="docker",
    )
    supervised.set_defaults(handler="supervised_build")

    supervised_verify = subparsers.add_parser(
        "_verify-supervised-candidate-fd",
        help=argparse.SUPPRESS,
    )
    supervised_verify.add_argument(
        "--role",
        required=True,
        choices=("success", "failure"),
    )
    supervised_verify.add_argument("--candidate-fd", required=True, type=int)
    supervised_verify.add_argument("--expected-output", required=True, type=Path)
    supervised_verify.add_argument("--builder-fd", required=True, type=int)
    supervised_verify.add_argument("--recipe-fd", required=True, type=int)
    supervised_verify.add_argument("--containerfile-fd", required=True, type=int)
    supervised_verify.add_argument(
        "--retained-stage-fd",
        type=int,
        action="append",
        default=[],
    )
    supervised_verify.set_defaults(handler="supervised_verify")

    container_absent = subparsers.add_parser(
        "_verify-container-absent",
        help=argparse.SUPPRESS,
    )
    container_absent.add_argument(
        "--container-engine",
        choices=("docker",),
        default="docker",
    )
    container_absent.add_argument("--container-name", required=True)
    container_absent.add_argument("--container-id")
    container_absent.set_defaults(handler="container_absent")

    reconcile = subparsers.add_parser(
        "reconcile", help="require exact equality from both frozen builder profiles"
    )
    reconcile.add_argument(
        "--builder-output", required=True, type=Path, action="append"
    )
    reconcile.add_argument("--output-dir", required=True, type=Path)
    reconcile.set_defaults(handler="reconcile")

    internal = subparsers.add_parser("_container-build", help=argparse.SUPPRESS)
    internal.add_argument("--provider", required=True, choices=PROVIDERS)
    internal.add_argument("--builder-profile", required=True, choices=BUILDER_PROFILES)
    internal.add_argument("--builder-image-id", required=True)
    internal.add_argument("--recipe-sha256", required=True)
    internal.add_argument("--builder-sha256", required=True)
    internal.add_argument("--containerfile-sha256", required=True)
    internal.add_argument("--build-context-tar-sha256", required=True)
    internal.add_argument("--build-context-tar-byte-length", required=True, type=int)
    internal.add_argument(
        "--build-context-member-manifest-sha256",
        required=True,
    )
    internal.add_argument("--build-attempt-id", required=True)
    internal.add_argument("--requested-output", required=True)
    internal.add_argument("--cache-root", required=True)
    internal.add_argument("--container-name", required=True)
    internal.add_argument("--container-cidfile-host", required=True)
    internal.add_argument("--container-cidfile", required=True)
    internal.set_defaults(handler="container_build")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    candidate_arguments = sys.argv[1:] if arguments is None else list(arguments)
    if candidate_arguments and candidate_arguments[0] in {
        "_supervised-build",
        "_verify-supervised-candidate-fd",
        "_verify-container-absent",
    }:
        try:
            _set_process_dumpable_zero()
            script_descriptor = re.fullmatch(
                r"/proc/(?:self|[1-9][0-9]*)/fd/([3-9]|[1-9][0-9]+)",
                __file__,
            )
            if script_descriptor is not None:
                _set_descriptor_cloexec(int(script_descriptor.group(1)))
        except OSError as error:
            print(f"provider payload builder: {error}", file=sys.stderr)
            return 1
    args = parse_args(arguments)
    try:
        if args.handler == "verify_recipe":
            recipe = load_recipe()
            print(
                json.dumps(
                    {
                        "decision": "PASS_FROZEN_RECIPE_ONLY_NOT_PRODUCT_ACTIVE",
                        "recipe_sha256": _sha256_file(RECIPE_PATH),
                        "providers": sorted(recipe["providers"]),
                    },
                    sort_keys=True,
                )
            )
        elif args.handler == "plan":
            print(
                json.dumps(_plan(args.provider, args.builder_profile), sort_keys=True)
            )
        elif args.handler == "build":
            _public_build(
                args.provider,
                args.builder_profile,
                args.output_dir,
                args.cache_dir,
                args.container_engine,
            )
            print(
                json.dumps(
                    {
                        "decision": "PASS_SINGLE_BUILDER_CANDIDATE_NOT_PRODUCT_ACTIVE",
                        "output": str(args.output_dir.resolve()),
                    },
                    sort_keys=True,
                )
            )
        elif args.handler == "verify":
            root = args.output_dir.absolute()
            root_descriptor = _open_fixed_root(root)
            try:
                kind = _verify_any_output_fd(root_descriptor)
            finally:
                os.close(root_descriptor)
            print(
                json.dumps(
                    {
                        "decision": "PASS_STRUCTURAL_RECEIPT_ONLY_NOT_PRODUCT_ACTIVE",
                        "schema": kind,
                    },
                    sort_keys=True,
                )
            )
        elif args.handler == "verify_fd":
            source_descriptors = (
                args.builder_fd,
                args.recipe_fd,
                args.containerfile_fd,
            )
            if (
                args.output_fd < 3
                or any(value < 3 for value in source_descriptors)
                or len({args.output_fd, *source_descriptors}) != 4
            ):
                raise BuildError(
                    "retained output/builder/recipe/Containerfile FDs must be "
                    "four distinct inherited data FDs"
                )
            verification_sources = _retained_verification_sources(
                *source_descriptors
            )
            try:
                root_descriptor = os.dup(args.output_fd)
            except OSError as error:
                raise BuildError("retained provider output FD is unavailable") from error
            try:
                kind = _verify_any_output_fd(
                    root_descriptor,
                    verification_sources=verification_sources,
                )
            finally:
                os.close(root_descriptor)
            print(
                json.dumps(
                    {
                        "decision": (
                            "PASS_RETAINED_FD_STRUCTURAL_RECEIPT_ONLY_"
                            "NOT_PRODUCT_ACTIVE"
                        ),
                        "schema": kind,
                    },
                    sort_keys=True,
                )
            )
        elif args.handler == "supervised_build":
            client = _SupervisedBuildClient(
                socket_descriptor=args.socket_fd,
                exec_builder_descriptor=args.exec_builder_fd,
                supervisor_pid=args.supervisor_pid,
                source_root=args.source_root.absolute(),
                output=args.output_dir.absolute(),
                cache=args.cache_dir.resolve(strict=True),
                success_host_path=args.success_host_path.absolute(),
                failure_host_path=args.failure_host_path.absolute(),
            )
            client.start()
            _public_build(
                args.provider,
                args.builder_profile,
                args.output_dir,
                args.cache_dir,
                args.container_engine,
                supervised=client,
            )
        elif args.handler == "supervised_verify":
            kind = _verify_supervised_candidate_fd(
                role=args.role,
                candidate_descriptor=args.candidate_fd,
                expected_output=args.expected_output.absolute(),
                builder_descriptor=args.builder_fd,
                recipe_descriptor=args.recipe_fd,
                containerfile_descriptor=args.containerfile_fd,
                retained_stage_descriptors=args.retained_stage_fd,
            )
            print(
                json.dumps(
                    {
                        "decision": (
                            "PASS_ONE_SHOT_RETAINED_FD_CANDIDATE_"
                            "NOT_PRODUCT_ACTIVE"
                        ),
                        "schema": kind,
                    },
                    sort_keys=True,
                )
            )
        elif args.handler == "container_absent":
            _verify_container_absent(
                args.container_engine,
                args.container_name,
                args.container_id,
            )
            print(
                json.dumps(
                    {
                        "decision": (
                            "PASS_CONTAINER_ABSENT_LIVE_QUERY_"
                            "NOT_PRODUCT_ACTIVE"
                        )
                    },
                    sort_keys=True,
                )
            )
        elif args.handler == "reconcile":
            _reconcile(args.builder_output, args.output_dir.resolve(strict=False))
            print(
                json.dumps(
                    {
                        "decision": "PASS_2_OF_2_REPRODUCIBLE_NOT_PRODUCT_ACTIVE",
                        "output": str(args.output_dir.resolve()),
                    },
                    sort_keys=True,
                )
            )
        elif args.handler == "container_build":
            _container_build(
                args.provider,
                args.builder_profile,
                args.builder_image_id,
                _require_hex(args.recipe_sha256, 64, "recipe_sha256"),
                _require_hex(args.builder_sha256, 64, "builder_sha256"),
                _require_hex(
                    args.containerfile_sha256,
                    64,
                    "containerfile_sha256",
                ),
                _require_hex(
                    args.build_context_tar_sha256,
                    64,
                    "build_context_tar_sha256",
                ),
                args.build_context_tar_byte_length,
                _require_hex(
                    args.build_context_member_manifest_sha256,
                    64,
                    "build_context_member_manifest_sha256",
                ),
                _require_hex(
                    args.build_attempt_id,
                    64,
                    "build_attempt_id",
                ),
                _validated_attempt_path(
                    args.requested_output,
                    "requested_output",
                ),
                _validated_attempt_path(
                    args.cache_root,
                    "cache_root",
                ),
                args.container_name,
                _validated_attempt_path(
                    args.container_cidfile_host,
                    "container_cidfile_host",
                ),
                _validated_attempt_path(
                    args.container_cidfile,
                    "container_cidfile",
                ),
            )
        else:
            raise AssertionError("unreachable command")
    except (BuildError, OSError, subprocess.SubprocessError) as error:
        print(f"provider payload builder: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
