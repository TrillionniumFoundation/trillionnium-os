#!/usr/bin/env python3
"""Fail-closed verifier for the external Android Codex receipt stage.

The custody phase must run on the original OUT_DIR files because sbox copies
inputs and therefore cannot preserve the original hard-link count.  The
publication phase runs inside sbox, repeats every byte/semantic check, and
requires the self-hashed custody attestation created by the first phase.
"""

from __future__ import annotations

import argparse
import copy
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable, Mapping, Sequence


EXPECTED_ROLES = (
    "common_daemon",
    "common_codex_launcher",
    "codex_runtime",
    "common_system_api",
    "common_accessibility",
    "common_replay_sync",
    "p01_daemon",
    "p01_codex_launcher",
    "p01_system_api",
    "p01_replay_sync",
    "p01_high_water",
    "p01_shell_tool",
    "p01_shell_broker",
    "p01_shell_worker",
    "shell_artifact_set",
    "rootfs_archive",
    "fresh_base_receipt",
    "fresh_base_sbom",
    "source_bom",
    "resolved_manifest",
    "common_artifact_set",
    "p01_final_artifact_set",
    "rootfs_contract",
    "rootfs_receipt",
    "p01_runtime_config",
    "p01_agent_manifest",
    "root_linux_manifest",
)

SHELL_ARTIFACT_SET_SCHEMA = "org.trillionnium.shell-exec-artifact-set.v1"
# A local userdebug handset may opt into a dirty-source dogfood receipt.  This
# schema is deliberately distinct from the clean source BOM and is accepted
# only when the caller passes the explicit verifier switch below.
USERDEBUG_DOGFOOD_SOURCE_BOM_SCHEMA = (
    "org.trillionnium.userdebug-dogfood-source-bom.v1"
)
USERDEBUG_DOGFOOD_SOURCE_BOM_DECISION = (
    "PASS_USERDEBUG_DIRTY_DOGFOOD_SNAPSHOT"
)
# The control builder publishes only this closed product feature set.  Android
# admission owns the same exact ordered closure rather than trusting a receipt
# to select Cargo features.
EXPECTED_SHELL_ARTIFACT_SET_FEATURES = ("android-product",)

# The v1 binding closure is code-owned, not selected by the external receipt
# or its tracked data contract. Exact order is part of the canonical receipt.
EXPECTED_CLAIMS = ({'artifact_field': 'bytes',
  'artifact_role': 'common_daemon',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/daemon/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_daemon',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/daemon/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_codex_launcher',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/codex_launcher/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_codex_launcher',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/codex_launcher/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_system_api',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/system_api_tool/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_system_api',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/system_api_tool/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/accessibility_tool/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/accessibility_tool/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_replay_sync',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/replay_sync_helper/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_replay_sync',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/artifacts/replay_sync_helper/sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'codex_runtime',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/inputs/codex_runtime_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'source_bom',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/source_bom/file_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'resolved_manifest',
  'evidence_role': 'common_artifact_set',
  'json_pointer': '/source_bom/resolved_manifest_sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_daemon',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/daemon/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_daemon',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/daemon/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_codex_launcher',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/codex_launcher/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_codex_launcher',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/codex_launcher/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_system_api',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/system_api_tool/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_system_api',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/system_api_tool/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_replay_sync',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/replay_sync_helper/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_replay_sync',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/replay_sync_helper/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_high_water',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/high_water_authority/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_high_water',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/artifacts/high_water_authority/sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'source_bom',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/source_bom/file_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'resolved_manifest',
  'evidence_role': 'p01_final_artifact_set',
  'json_pointer': '/source_bom/resolved_manifest_sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_shell_tool',
  'evidence_role': 'shell_artifact_set',
  'json_pointer': '/artifacts/0/size_bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_shell_tool',
  'evidence_role': 'shell_artifact_set',
  'json_pointer': '/artifacts/0/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_shell_broker',
  'evidence_role': 'shell_artifact_set',
  'json_pointer': '/artifacts/1/size_bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_shell_broker',
  'evidence_role': 'shell_artifact_set',
  'json_pointer': '/artifacts/1/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'p01_shell_worker',
  'evidence_role': 'shell_artifact_set',
  'json_pointer': '/artifacts/2/size_bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_shell_worker',
  'evidence_role': 'shell_artifact_set',
  'json_pointer': '/artifacts/2/sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'source_bom',
  'evidence_role': 'shell_artifact_set',
  'json_pointer': '/source_bom_sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_daemon',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/daemon/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_daemon',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/daemon/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_codex_launcher',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/codex/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_codex_launcher',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/codex/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_system_api',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/system_api_tool/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_system_api',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/system_api_tool/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/accessibility_tool/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/accessibility_tool/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_replay_sync',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/system_api_replay_sync/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_replay_sync',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/system_api_replay_sync/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_artifact_set',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/common_artifact_set_receipt/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_artifact_set',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/inputs/common_artifact_set_receipt/sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'source_bom',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/common_build_evidence/upstream_source_bom_receipt_claim/file_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'resolved_manifest',
  'evidence_role': 'rootfs_contract',
  'json_pointer': '/common_build_evidence/upstream_source_bom_receipt_claim/resolved_manifest_sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'rootfs_archive',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/output_rootfs/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'rootfs_archive',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/output_rootfs/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'rootfs_contract',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/contract/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'rootfs_contract',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/contract/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'fresh_base_receipt',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/fresh_base_provenance/receipt/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'fresh_base_receipt',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/fresh_base_provenance/receipt/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'fresh_base_sbom',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/fresh_base_provenance/sbom/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'fresh_base_sbom',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/fresh_base_provenance/sbom/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_artifact_set',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/common_artifact_set_receipt/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_artifact_set',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/common_artifact_set_receipt/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_daemon',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/daemon/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_daemon',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/daemon/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_codex_launcher',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/codex_launcher/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_codex_launcher',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/codex_launcher/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_system_api',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/system_api_tool/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_system_api',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/system_api_tool/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/accessibility_tool/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/accessibility_tool/sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'common_replay_sync',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/system_api_replay_sync/bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_replay_sync',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/inputs/system_api_replay_sync/sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'source_bom',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/common_build_evidence/upstream_source_bom_receipt_claim/file_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'resolved_manifest',
  'evidence_role': 'rootfs_receipt',
  'json_pointer': '/common_build_evidence/upstream_source_bom_receipt_claim/resolved_manifest_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_codex_launcher',
  'evidence_role': 'p01_agent_manifest',
  'json_pointer': '/identity_key_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_daemon',
  'evidence_role': 'p01_runtime_config',
  'json_pointer': '/TRILLIONNIUM_DAEMON_PAYLOAD_SHA256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_system_api',
  'evidence_role': 'p01_runtime_config',
  'json_pointer': '/TRILLIONNIUM_SYSTEM_API_EXPECTED_SHA256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'p01_runtime_config',
  'json_pointer': '/TRILLIONNIUM_ACCESSIBILITY_EXPECTED_SHA256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_codex_launcher',
  'evidence_role': 'p01_runtime_config',
  'json_pointer': '/TRILLIONNIUM_CODEX_EXPECTED_SHA256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_replay_sync',
  'evidence_role': 'p01_runtime_config',
  'json_pointer': '/TRILLIONNIUM_P01_REPLAY_SYNC_SHA256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'rootfs_archive',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_archive_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'rootfs_contract',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_package_contract_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'rootfs_receipt',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_package_receipt_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_artifact_set',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_common_artifact_set_sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'fresh_base_receipt',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_fresh_base_receipt_bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'fresh_base_receipt',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_fresh_base_receipt_sha256'},
 {'artifact_field': 'bytes',
  'artifact_role': 'fresh_base_sbom',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_fresh_base_sbom_bytes'},
 {'artifact_field': 'sha256',
  'artifact_role': 'fresh_base_sbom',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/rootfs_fresh_base_sbom_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_daemon',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/root_linux_archive_daemon_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_replay_sync',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/root_linux_archive_replay_sync_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_system_api',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/root_linux_archive_system_api_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_accessibility',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/root_linux_archive_accessibility_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'common_codex_launcher',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/root_linux_archive_codex_launcher_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'codex_runtime',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/codex_runtime_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_daemon',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/agentd_payload_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_codex_launcher',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/codex_integrity_launcher_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_system_api',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/agent_system_api_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_replay_sync',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/agent_system_api_replay_sync_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_replay_sync',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/p01_system_api_device_replay_sync_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_high_water',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/p01_direct_operation_custody_high_water_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_runtime_config',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/p01_runtime_config_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_agent_manifest',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/p01_agent_manifest_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'source_bom',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/source_bom_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'resolved_manifest',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/resolved_manifest_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'p01_final_artifact_set',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/p01_final_artifact_set_sha256'},
 {'artifact_field': 'sha256',
  'artifact_role': 'shell_artifact_set',
  'evidence_role': 'root_linux_manifest',
  'json_pointer': '/shell_exec_v1_artifact_set_sha256'})

CONTRACT_SCHEMA = "org.trillionnium.android.receipt-stage.contract.v1"
STAGE_SCHEMA = "org.trillionnium.android.receipt-stage.v1"
CUSTODY_SCHEMA = "org.trillionnium.android.receipt-stage-custody.v1"
STAGE_DECISION = "PASS_HOST_ONLY_ANDROID_USERDEBUG_RECEIPT_STAGE"
STAGE_ROOT = "trillionnium/receipt-stage-v1"
HOLD = "HOLD"
COMPACT_RECEIPT_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-compact-no-lf-without-receipt_id)"
)
PRETTY_RECEIPT_SCOPES = {
    "sha256(canonical-json-utf8-without-receipt_id)",
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)",
}
SHA256_HEX_LEN = 64
MAX_INPUT_BYTES = 1 << 30
MAX_ROOTFS_TAR_BYTES = 1 << 36
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
STAGING_FILTER_SCHEMA = "org.trillionnium.rootfs-tar-staging-filter.v1"
STAGING_FILTER_SOURCE_SHA256 = (
    "dc48c9ce97f1e64a62e45d00350b44801adb7cc0f60f8666b1d5e87696ce6092"
)
MAX_ELF_PROGRAM_HEADERS = 128
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2
PF_R = 4
DT_NULL = 0
DT_NEEDED = 1
SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH = (
    "usr/local/bin/trillionnium-agent-shell"
)
SHELL_EXEC_STANDARD_ALLOWLIST_PATH = (
    "etc/trillionnium/shell-exec-standard-allowlist.v1.json"
)
SHELL_EXEC_STANDARD_ALLOWLIST_SCHEMA = (
    "org.trillionnium.shell-exec.standard-executable-policy.v1"
)
SHELL_EXEC_STANDARD_ALLOWLIST_PROFILE = "standard"
SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES = (
    "/bin/echo",
    "/bin/false",
    "/bin/sleep",
    "/bin/true",
    "/bin/uname",
    "/usr/bin/id",
    "/usr/bin/printf",
)
SHELL_EXEC_STANDARD_ALLOWLIST_BYTES = 793


class StageError(RuntimeError):
    """A stage input, custody boundary, or output failed closed."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pretty_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def compact_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StageError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> object:
    raise StageError(f"non-finite JSON constant: {value}")


def parse_json(raw: bytes, label: str, *, canonical: bool = True) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StageError(f"{label} is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (json.JSONDecodeError, StageError) as error:
        if isinstance(error, StageError):
            raise
        raise StageError(f"{label} is not strict JSON: {error}") from error
    if type(value) is not dict:
        raise StageError(f"{label} must be a JSON object")
    if canonical and raw != pretty_json(value):
        raise StageError(f"{label} is not canonical sort-keys indent-2 LF JSON")
    return value


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise StageError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise StageError(
            f"{label} keys drifted: missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def lower_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != SHA256_HEX_LEN
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise StageError(f"{label} must be a lowercase SHA-256")
    return value


def positive_bytes(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value <= MAX_INPUT_BYTES:
        raise StageError(f"{label} must be an integer in [1, {MAX_INPUT_BYTES}]")
    return value


def clean_relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value or "\\" in value:
        raise StageError(f"{label} must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise StageError(f"{label} is not a clean relative path")
    if str(path) != value:
        raise StageError(f"{label} is not normalized")
    return value


def clean_install_path(value: object, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value.startswith("/") or "\\" in value:
        raise StageError(f"{label} must be null or an absolute POSIX path")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts[1:]) or str(path) != value:
        raise StageError(f"{label} is not normalized")
    return value


def mode_string(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_ctime_ns,
    )


def inode_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def directory_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    # Directory size, link count, and ctime legitimately change when unrelated
    # parallel build actions create children.  Custody needs the opened inode,
    # owner, group, type, and permission bits to remain exact.
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


@dataclass
class RetainedDirectory:
    fd: int
    name: str | None
    initial: os.stat_result


@dataclass
class RetainedDirectoryPath:
    path: str
    label: str
    directories: list[RetainedDirectory]

    @classmethod
    def acquire(
        cls, path: str, label: str, *, create: bool = False
    ) -> "RetainedDirectoryPath":
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise StageError(f"{label} must be an absolute normalized path")
        components = path.split(os.sep)[1:]
        if any(component in {"", ".", ".."} for component in components):
            raise StageError(f"{label} has invalid path components")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        retained: list[RetainedDirectory] = []
        try:
            root_fd = os.open(os.sep, flags)
            root_stat = os.fstat(root_fd)
            validate_directory_policy(root_stat, f"{label} root")
            retained.append(RetainedDirectory(root_fd, None, root_stat))
            current_fd = root_fd
            for index, component in enumerate(components):
                try:
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, 0o755, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                child_stat = os.fstat(child_fd)
                validate_directory_policy(
                    child_stat,
                    f"{label} component /{'/'.join(components[: index + 1])}",
                )
                retained.append(RetainedDirectory(child_fd, component, child_stat))
                current_fd = child_fd
            return cls(path=path, label=label, directories=retained)
        except BaseException:
            for directory in reversed(retained):
                os.close(directory.fd)
            raise

    @property
    def fd(self) -> int:
        return self.directories[-1].fd

    def assert_stable(self) -> None:
        for index, directory in enumerate(self.directories):
            current = os.fstat(directory.fd)
            if directory_identity(current) != directory_identity(directory.initial):
                raise StageError(f"{self.label} retained chain changed")
            if index:
                parent = self.directories[index - 1]
                lexical = os.stat(
                    directory.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                if directory_identity(lexical) != directory_identity(
                    directory.initial
                ):
                    raise StageError(f"{self.label} lexical chain changed")

    def close(self) -> None:
        failures: list[OSError] = []
        for directory in reversed(self.directories):
            try:
                os.close(directory.fd)
            except OSError as error:
                failures.append(error)
        if failures:
            raise StageError(
                f"{self.label} retained directory close failed: {failures[0]}"
            )


def group_is_private(gid: int, owner_uid: int) -> bool:
    """Return true only when a writable group cannot name another local user."""
    try:
        group = grp.getgrgid(gid)
        owner = pwd.getpwuid(owner_uid).pw_name
        primary_users = {
            account.pw_name for account in pwd.getpwall() if account.pw_gid == gid
        }
    except KeyError:
        return False
    named_users = set(group.gr_mem) | primary_users
    return named_users <= {owner}


def validate_directory_policy(value: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise StageError(f"{label} is not a directory")
    if value.st_uid not in {0, os.geteuid()}:
        raise StageError(f"{label} is not root- or build-user-owned")
    mode = stat.S_IMODE(value.st_mode)
    if mode & stat.S_ISVTX or mode & 0o002:
        raise StageError(f"{label} is sticky or world-writable")
    if mode & 0o020 and not (
        value.st_uid == os.geteuid()
        and value.st_gid == os.getegid()
        and group_is_private(value.st_gid, value.st_uid)
    ):
        raise StageError(f"{label} is shared group-writable")


@dataclass
class RetainedInput:
    path: str
    label: str
    fd: int
    initial: os.stat_result
    directories: list[RetainedDirectory]
    basename: str
    data: bytes

    @classmethod
    def acquire(
        cls,
        path: str,
        label: str,
        *,
        strict_chain: bool = True,
        strict_file: bool = True,
    ) -> "RetainedInput":
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise StageError(f"{label} path must be absolute and normalized")
        components = path.split(os.sep)[1:]
        if not components or any(component in {"", ".", ".."} for component in components):
            raise StageError(f"{label} path components are invalid")
        basename = os.path.basename(path)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directories: list[RetainedDirectory] = []
        fd = -1
        try:
            root_fd = os.open(os.sep, directory_flags)
            root_stat = os.fstat(root_fd)
            if strict_chain:
                validate_directory_policy(root_stat, f"{label} path root")
            directories.append(RetainedDirectory(root_fd, None, root_stat))
            current_fd = root_fd
            for index, component in enumerate(components[:-1]):
                child_fd = os.open(component, directory_flags, dir_fd=current_fd)
                child_stat = os.fstat(child_fd)
                if strict_chain:
                    validate_directory_policy(
                        child_stat,
                        f"{label} path component /{'/'.join(components[: index + 1])}",
                    )
                directories.append(
                    RetainedDirectory(child_fd, component, child_stat)
                )
                current_fd = child_fd
            before = os.stat(basename, dir_fd=current_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise StageError(
                    f"{label} must be a regular file, not a symlink or special file"
                )
            if strict_file:
                if before.st_uid not in {0, os.geteuid()}:
                    raise StageError(f"{label} is not root- or build-user-owned")
                if before.st_mode & 0o002:
                    raise StageError(f"{label} must not be world-writable")
                if before.st_mode & 0o020 and not (
                    before.st_uid == os.geteuid()
                    and before.st_gid == os.getegid()
                    and group_is_private(before.st_gid, before.st_uid)
                ):
                    raise StageError(f"{label} must not be shared group-writable")
                if before.st_nlink != 1:
                    raise StageError(f"{label} must have exactly one hard link")
            if before.st_size <= 0 or before.st_size > MAX_INPUT_BYTES:
                raise StageError(f"{label} size is outside the accepted range")
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(basename, flags, dir_fd=current_fd)
            held = os.fstat(fd)
            if stat_identity(held) != stat_identity(before):
                raise StageError(f"{label} changed while opening")
            chunks: list[bytes] = []
            remaining = held.st_size
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise StageError(f"{label} was truncated while reading")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise StageError(f"{label} grew while reading")
            data = b"".join(chunks)
            return cls(
                path=path,
                label=label,
                fd=fd,
                initial=held,
                directories=directories,
                basename=basename,
                data=data,
            )
        except BaseException:
            if fd >= 0:
                os.close(fd)
            for directory in reversed(directories):
                os.close(directory.fd)
            raise

    def _assert_directory_chain(self) -> None:
        for index, directory in enumerate(self.directories):
            current_directory = os.fstat(directory.fd)
            if directory_identity(current_directory) != directory_identity(
                directory.initial
            ):
                raise StageError(f"{self.label} retained directory chain changed")
            if index:
                parent = self.directories[index - 1]
                lexical = os.stat(
                    directory.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                if directory_identity(lexical) != directory_identity(
                    directory.initial
                ):
                    raise StageError(f"{self.label} lexical directory chain changed")

    def assert_stable(self) -> None:
        # Bracket the complete retained-FD read with held inode, parent-chain,
        # and pathname checks.  Identical replacement bytes and mode are not
        # sufficient: the pathname must still name the originally retained
        # inode after the read finishes.
        held_before = os.fstat(self.fd)
        if stat_identity(held_before) != stat_identity(self.initial):
            raise StageError(f"{self.label} retained inode changed")
        self._assert_directory_chain()
        parent_fd = self.directories[-1].fd
        lexical_before = os.stat(
            self.basename, dir_fd=parent_fd, follow_symlinks=False
        )
        if stat_identity(lexical_before) != stat_identity(self.initial):
            raise StageError(f"{self.label} pathname identity changed")
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = self.initial.st_size
        while remaining:
            chunk = os.read(self.fd, min(1024 * 1024, remaining))
            if not chunk:
                raise StageError(f"{self.label} retained bytes were truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(self.fd, 1) or digest.hexdigest() != sha256(self.data):
            raise StageError(f"{self.label} retained bytes changed")
        post_read_failures: list[str] = []
        try:
            held_after = os.fstat(self.fd)
        except BaseException as error:
            post_read_failures.append(f"retained inode unavailable: {error}")
        else:
            if stat_identity(held_after) != stat_identity(self.initial):
                post_read_failures.append("retained inode changed")
            if (
                not stat.S_ISREG(held_after.st_mode)
                or held_after.st_mode != self.initial.st_mode
                or held_after.st_nlink != self.initial.st_nlink
                or held_after.st_size != self.initial.st_size
            ):
                post_read_failures.append("retained metadata changed")
        try:
            self._assert_directory_chain()
        except BaseException as error:
            post_read_failures.append(f"retained parent chain changed: {error}")
        try:
            lexical_after = os.stat(
                self.basename, dir_fd=parent_fd, follow_symlinks=False
            )
        except BaseException as error:
            post_read_failures.append(f"pathname unavailable: {error}")
        else:
            if stat_identity(lexical_after) != stat_identity(self.initial):
                post_read_failures.append("pathname identity changed")
            if (
                not stat.S_ISREG(lexical_after.st_mode)
                or lexical_after.st_mode != self.initial.st_mode
                or lexical_after.st_nlink != self.initial.st_nlink
                or lexical_after.st_size != self.initial.st_size
            ):
                post_read_failures.append("pathname metadata changed")
        if post_read_failures:
            raise StageError(
                f"{self.label} post-read stability check failed: "
                + "; ".join(post_read_failures)
            )

    def close(self) -> None:
        errors: list[OSError] = []
        for fd in [self.fd] + [item.fd for item in reversed(self.directories)]:
            try:
                os.close(fd)
            except OSError as error:
                errors.append(error)
        if errors:
            raise StageError(f"{self.label} retained descriptor close failed: {errors[0]}")


@dataclass
class PublishedOutput:
    path: str
    label: str
    basename: str
    parent: RetainedDirectoryPath
    fd: int
    initial: os.stat_result
    expected_sha256: str
    expected_bytes: int
    expected_mode: int

    @classmethod
    def publish(
        cls,
        path: str,
        label: str,
        raw: bytes,
        mode: int,
        parent: RetainedDirectoryPath,
    ) -> "PublishedOutput":
        basename = os.path.basename(path)
        if os.path.dirname(path) != parent.path or basename in {"", ".", ".."}:
            raise StageError(f"{label} does not belong to its retained output parent")
        parent.assert_stable()
        try:
            os.stat(basename, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise StageError(f"{label} output target already exists")

        temporary = f".receipt-stage.{secrets.token_hex(16)}"
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = -1
        linked = False
        cleanup_errors: list[BaseException] = []
        try:
            fd = os.open(temporary, flags, 0o600, dir_fd=parent.fd)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise StageError(f"{label} temporary output write stalled")
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
            os.link(
                temporary,
                basename,
                src_dir_fd=parent.fd,
                dst_dir_fd=parent.fd,
                follow_symlinks=False,
            )
            linked = True
            os.unlink(temporary, dir_fd=parent.fd)
            temporary = ""
            os.fsync(parent.fd)
            initial = os.fstat(fd)
            if (
                not stat.S_ISREG(initial.st_mode)
                or stat.S_IMODE(initial.st_mode) != mode
                or initial.st_nlink != 1
                or initial.st_size != len(raw)
                or initial.st_uid not in {0, os.geteuid()}
            ):
                raise StageError(f"{label} published inode metadata drifted")
            result = cls(
                path=path,
                label=label,
                basename=basename,
                parent=parent,
                fd=fd,
                initial=initial,
                expected_sha256=sha256(raw),
                expected_bytes=len(raw),
                expected_mode=mode,
            )
            result.assert_stable()
            return result
        except BaseException as primary:
            if linked and fd >= 0:
                try:
                    current = os.stat(
                        basename, dir_fd=parent.fd, follow_symlinks=False
                    )
                    if inode_identity(current) == inode_identity(os.fstat(fd)):
                        os.unlink(basename, dir_fd=parent.fd)
                    else:
                        raise StageError(
                            f"{label} cleanup refused a replaced output pathname"
                        )
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    cleanup_errors.append(error)
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent.fd)
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    cleanup_errors.append(error)
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as error:
                    cleanup_errors.append(error)
            if cleanup_errors:
                raise StageError(
                    f"{label} publication failed: {primary}; cleanup also failed: "
                    + "; ".join(str(error) for error in cleanup_errors)
                ) from primary
            raise

    def assert_stable(self) -> None:
        # Bracket the complete descriptor read with both held-inode and
        # pathname checks.  A pathname replacement that happens after the
        # pre-read openat check must not be able to survive the final gate,
        # even when the replacement has identical bytes and metadata.
        self.parent.assert_stable()
        held_before = os.fstat(self.fd)
        if stat_identity(held_before) != stat_identity(self.initial):
            raise StageError(f"{self.label} retained published inode changed")
        lexical_before = os.stat(
            self.basename, dir_fd=self.parent.fd, follow_symlinks=False
        )
        if stat_identity(lexical_before) != stat_identity(self.initial):
            raise StageError(f"{self.label} published pathname identity changed")
        if (
            not stat.S_ISREG(held_before.st_mode)
            or stat.S_IMODE(held_before.st_mode) != self.expected_mode
            or held_before.st_nlink != 1
            or held_before.st_size != self.expected_bytes
        ):
            raise StageError(f"{self.label} published bytes or metadata changed")
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = self.expected_bytes
        while remaining:
            chunk = os.read(self.fd, min(1024 * 1024, remaining))
            if not chunk:
                raise StageError(f"{self.label} published bytes were truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        if (
            os.read(self.fd, 1)
            or digest.hexdigest() != self.expected_sha256
        ):
            raise StageError(f"{self.label} published bytes or metadata changed")
        post_read_failures: list[str] = []
        held_after = os.fstat(self.fd)
        if stat_identity(held_after) != stat_identity(self.initial):
            post_read_failures.append("retained published inode changed")
        if (
            not stat.S_ISREG(held_after.st_mode)
            or stat.S_IMODE(held_after.st_mode) != self.expected_mode
            or held_after.st_nlink != 1
            or held_after.st_size != self.expected_bytes
        ):
            post_read_failures.append("retained published metadata changed")
        try:
            self.parent.assert_stable()
        except BaseException as error:
            post_read_failures.append(f"retained output parent changed: {error}")
        try:
            lexical_after = os.stat(
                self.basename, dir_fd=self.parent.fd, follow_symlinks=False
            )
        except BaseException as error:
            post_read_failures.append(f"published pathname unavailable: {error}")
        else:
            if stat_identity(lexical_after) != stat_identity(self.initial):
                post_read_failures.append("published pathname identity changed")
            if (
                not stat.S_ISREG(lexical_after.st_mode)
                or stat.S_IMODE(lexical_after.st_mode) != self.expected_mode
                or lexical_after.st_nlink != 1
                or lexical_after.st_size != self.expected_bytes
            ):
                post_read_failures.append("published pathname metadata changed")
        if post_read_failures:
            raise StageError(
                f"{self.label} post-read stability check failed: "
                + "; ".join(post_read_failures)
            )

    def cleanup(self) -> None:
        self.parent.assert_stable()
        try:
            lexical = os.stat(
                self.basename, dir_fd=self.parent.fd, follow_symlinks=False
            )
        except FileNotFoundError:
            return
        if inode_identity(lexical) != inode_identity(self.initial):
            raise StageError(f"{self.label} cleanup refused a replaced pathname")
        os.unlink(self.basename, dir_fd=self.parent.fd)
        os.fsync(self.parent.fd)

    def close(self) -> None:
        os.close(self.fd)


def forbid_hash_pins(value: object, label: str = "contract") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"sha256", "bytes", "receipt_id"}:
                raise StageError(f"{label} contains forbidden artifact pin field {key}")
            forbid_hash_pins(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            forbid_hash_pins(child, f"{label}[{index}]")


def validate_contract(raw: bytes) -> dict[str, object]:
    contract = parse_json(raw, "receipt-stage contract")
    exact_keys(
        contract,
        {
            "claims",
            "cross_bindings",
            "custody_receipt_schema",
            "decision",
            "public_release_allowed",
            "release_authority",
            "role_specs",
            "schema",
            "stage_receipt_id_scope",
            "stage_receipt_schema",
            "stage_root",
        },
        "receipt-stage contract",
    )
    if (
        contract["schema"] != CONTRACT_SCHEMA
        or contract["stage_receipt_schema"] != STAGE_SCHEMA
        or contract["custody_receipt_schema"] != CUSTODY_SCHEMA
        or contract["stage_receipt_id_scope"] != COMPACT_RECEIPT_SCOPE
        or contract["decision"] != STAGE_DECISION
        or contract["release_authority"] != HOLD
        or contract["public_release_allowed"] is not False
        or contract["stage_root"] != STAGE_ROOT
    ):
        raise StageError("receipt-stage contract header drifted")
    forbid_hash_pins(contract)

    role_specs = contract["role_specs"]
    if type(role_specs) is not list or len(role_specs) != len(EXPECTED_ROLES):
        raise StageError("receipt-stage contract role set drifted")
    roles: list[str] = []
    seen_paths: set[str] = set()
    seen_outputs: set[str] = set()
    seen_tags: set[str] = set()
    for index, candidate in enumerate(role_specs):
        label = f"contract.role_specs[{index}]"
        expected_spec_keys = {
            "document_schema",
            "install_path",
            "kind",
            "mode",
            "output_filename",
            "required_false_fields",
            "role",
            "semantic",
            "stage_path",
            "tag",
        }
        if type(candidate) is dict and "install_paths" in candidate:
            expected_spec_keys.add("install_paths")
        spec = exact_keys(
            candidate,
            expected_spec_keys,
            label,
        )
        role = spec["role"]
        if type(role) is not str or role not in EXPECTED_ROLES:
            raise StageError(f"{label}.role is unknown")
        roles.append(role)
        kind = spec["kind"]
        if kind not in {
            "agent_manifest",
            "elf",
            "env",
            "json",
            "kv",
            "spdx",
            "xml",
            "zstd",
        }:
            raise StageError(f"{label}.kind is invalid")
        expected_mode = "0555" if kind == "elf" else "0444"
        if spec["mode"] != expected_mode:
            raise StageError(f"{label}.mode must be {expected_mode}")
        if (kind in {"json", "spdx"}) != (
            type(spec["document_schema"]) is str
        ):
            raise StageError(f"{label}.document_schema does not match its kind")
        if type(spec["semantic"]) is not str or not spec["semantic"]:
            raise StageError(f"{label}.semantic is invalid")
        stage_path = clean_relative_path(spec["stage_path"], f"{label}.stage_path")
        if stage_path in seen_paths:
            raise StageError("receipt-stage contract has duplicate stage paths")
        seen_paths.add(stage_path)
        output = clean_relative_path(
            spec["output_filename"], f"{label}.output_filename"
        )
        if "/" in output or output in seen_outputs:
            raise StageError("receipt-stage contract output filenames are invalid")
        seen_outputs.add(output)
        tag = spec["tag"]
        if tag != "." + role or tag in seen_tags:
            raise StageError(f"{label}.tag must be the role-prefixed output tag")
        seen_tags.add(tag)
        primary_install_path = clean_install_path(
            spec["install_path"], f"{label}.install_path"
        )
        if "install_paths" in spec:
            install_paths = spec["install_paths"]
            if (
                type(install_paths) is not list
                or len(install_paths) < 2
                or install_paths[0] != primary_install_path
                or len(set(install_paths)) != len(install_paths)
            ):
                raise StageError(
                    f"{label}.install_paths must be an ordered unique dual-path set"
                )
            for path_index, install_path in enumerate(install_paths):
                if clean_install_path(
                    install_path, f"{label}.install_paths[{path_index}]"
                ) is None:
                    raise StageError(f"{label}.install_paths may not contain null")
        false_fields = spec["required_false_fields"]
        if type(false_fields) is not list or any(
            type(pointer) is not str or not pointer.startswith("/")
            for pointer in false_fields
        ):
            raise StageError(f"{label}.required_false_fields is invalid")
    if tuple(roles) != EXPECTED_ROLES:
        raise StageError("receipt-stage contract role order drifted")

    claims = contract["claims"]
    if type(claims) is not list or tuple(claims) != EXPECTED_CLAIMS:
        raise StageError(
            f"receipt-stage contract fixed {len(EXPECTED_CLAIMS)}-claim closure drifted"
        )
    seen_claims: set[tuple[str, str, str, str]] = set()
    by_role = {spec["role"]: spec for spec in role_specs}
    for index, candidate in enumerate(claims):
        label = f"contract.claims[{index}]"
        claim = exact_keys(
            candidate,
            {"artifact_field", "artifact_role", "evidence_role", "json_pointer"},
            label,
        )
        artifact_role = claim["artifact_role"]
        evidence_role = claim["evidence_role"]
        field = claim["artifact_field"]
        pointer = claim["json_pointer"]
        if artifact_role not in by_role or evidence_role not in by_role:
            raise StageError(f"{label} references an unknown role")
        if by_role[evidence_role]["kind"] not in {
            "agent_manifest",
            "env",
            "json",
            "kv",
        }:
            raise StageError(f"{label}.evidence_role is not structured evidence")
        if field not in {"bytes", "sha256"}:
            raise StageError(f"{label}.artifact_field is invalid")
        if type(pointer) is not str or not pointer.startswith("/"):
            raise StageError(f"{label}.json_pointer is invalid")
        identity = (evidence_role, pointer, artifact_role, field)
        if identity in seen_claims:
            raise StageError("receipt-stage contract has a duplicate claim")
        seen_claims.add(identity)

    cross_bindings = exact_keys(
        contract["cross_bindings"],
        {
            "all_evidence_same_resolved_manifest",
            "all_evidence_same_source_bom",
            "codex_runtime_matches_common_artifact_set",
            "common_rootfs_artifacts_match_common_artifact_set",
            "fresh_base_evidence_matches_rootfs_receipt",
            "p01_agent_manifest_matches_launcher",
            "p01_artifacts_match_p01_final_artifact_set",
            "p01_runtime_configuration_matches_stage",
            "root_linux_manifest_matches_stage",
            "rootfs_archive_matches_rootfs_receipt",
            "rootfs_contract_matches_rootfs_receipt",
            "shell_artifacts_match_shell_artifact_set",
        },
        "contract.cross_bindings",
    )
    if any(value is not True for value in cross_bindings.values()):
        raise StageError("receipt-stage contract cross bindings must all be true")
    return contract


def json_pointer(value: object, pointer: str, label: str) -> object:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise StageError(f"{label} is not an absolute JSON pointer")
    current = value
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise StageError(f"{label} does not resolve: missing {token!r}")
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                raise StageError(f"{label} does not resolve: invalid index {token!r}")
            current = current[int(token)]
        else:
            raise StageError(f"{label} traverses a scalar")
    return current


def validate_self_hash(document: Mapping[str, object], label: str) -> None:
    if "receipt_id" not in document:
        return
    receipt_id = document["receipt_id"]
    if type(receipt_id) is not str:
        raise StageError(f"{label}.receipt_id is malformed")
    scope = document.get("receipt_id_scope")
    preimage = copy.deepcopy(document)
    del preimage["receipt_id"]
    if receipt_id.startswith("sha256:") and scope == COMPACT_RECEIPT_SCOPE:
        encoded = compact_json(preimage)
        expected = "sha256:" + sha256(encoded)
        lower_sha256(receipt_id[7:], f"{label}.receipt_id")
    elif receipt_id.startswith("sha256:") and scope in PRETTY_RECEIPT_SCOPES:
        encoded = pretty_json(preimage)
        expected = "sha256:" + sha256(encoded)
        lower_sha256(receipt_id[7:], f"{label}.receipt_id")
    elif not receipt_id.startswith("sha256:") and scope is None:
        lower_sha256(receipt_id, f"{label}.receipt_id")
        encoded = compact_json(preimage)
        expected = sha256(encoded)
    else:
        raise StageError(f"{label}.receipt_id_scope is unsupported")
    if receipt_id != expected:
        raise StageError(f"{label}.receipt_id does not bind its canonical preimage")


def reject_release_authority(value: object, label: str = "$") -> None:
    forbidden_true = {
        "device_write_authorized",
        "ota_authorized",
        "public_release_allowed",
        "release_allowed",
        "release_promotion_performed",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            if key in forbidden_true and child is True:
                raise StageError(f"{label}.{key} must remain false")
            reject_release_authority(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_release_authority(child, f"{label}[{index}]")


def validate_elf(raw: bytes, label: str) -> None:
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise StageError(f"{label} is not an ELF file")
    if raw[4] != 2 or raw[5] != 1 or raw[6] != 1:
        raise StageError(f"{label} must be little-endian ELF64 version 1")
    elf_type, machine, version = struct.unpack_from("<HHI", raw, 16)
    if elf_type not in {2, 3} or machine != 183 or version != 1:
        raise StageError(f"{label} must be an AArch64 ET_EXEC/ET_DYN ELF")
    lowered = raw.lower()
    for marker in (b"openclaw", b"open_claw", b"5902"):
        if marker in lowered:
            raise StageError(f"{label} contains retired Agent-provider bytes")


def validate_fully_static_elf(raw: bytes, label: str) -> None:
    """Mirror the control builder's static hardened AArch64 ELF admission."""

    validate_elf(raw, label)
    if raw[7] not in {0, 3} or raw[8] != 0 or any(raw[9:16]):
        raise StageError(f"{label} has an unsupported ELF identification ABI")
    (
        _elf_type,
        _machine,
        _version,
        entry,
        program_offset,
        section_offset,
        flags,
        header_bytes,
        program_entry_bytes,
        program_count,
        section_entry_bytes,
        section_count,
        section_names,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if flags != 0 or header_bytes != 64 or entry == 0:
        raise StageError(f"{label} has an invalid AArch64 ELF header or entry point")
    if (
        not 1 <= program_count <= MAX_ELF_PROGRAM_HEADERS
        or program_entry_bytes != 56
    ):
        raise StageError(f"{label} has an unsupported or empty program-header table")
    program_bytes = program_entry_bytes * program_count
    if (
        program_offset < header_bytes
        or program_offset > len(raw)
        or program_bytes > len(raw) - program_offset
    ):
        raise StageError(f"{label} has an out-of-bounds program-header table")
    if section_count == 0:
        if section_offset != 0 or section_entry_bytes != 0 or section_names != 0:
            raise StageError(
                f"{label} uses unsupported extended/partial section metadata"
            )
    elif (
        section_entry_bytes != 64
        or section_names >= section_count
        or section_offset < header_bytes
        or section_offset > len(raw)
        or section_entry_bytes * section_count > len(raw) - section_offset
    ):
        raise StageError(f"{label} has an invalid section-header table")

    load_segments: list[tuple[int, int, int, int, int]] = []
    executable_loads: list[tuple[int, int]] = []
    dynamic_count = 0
    stack_count = 0
    for index in range(program_count):
        offset = program_offset + index * program_entry_bytes
        (
            segment_type,
            segment_flags,
            segment_offset,
            segment_address,
            physical_address,
            file_bytes,
            memory_bytes,
            alignment,
        ) = struct.unpack_from("<IIQQQQQQ", raw, offset)
        if segment_flags & ~0x7:
            raise StageError(
                f"{label} program header {index} has unknown permission flags"
            )
        if file_bytes > memory_bytes:
            raise StageError(
                f"{label} program header {index} has p_filesz greater than p_memsz"
            )
        if segment_address + memory_bytes > 1 << 64:
            raise StageError(
                f"{label} program header {index} address range wraps uint64"
            )
        if segment_offset > len(raw) or file_bytes > len(raw) - segment_offset:
            raise StageError(
                f"{label} program header {index} reaches outside the file"
            )
        if alignment not in {0, 1}:
            if alignment & (alignment - 1):
                raise StageError(
                    f"{label} program header {index} has non-power-of-two alignment"
                )
            if segment_offset % alignment != segment_address % alignment:
                raise StageError(
                    f"{label} program header {index} has incongruent alignment"
                )
        if segment_type == PT_INTERP:
            raise StageError(f"{label} contains PT_INTERP")
        if segment_type == PT_LOAD:
            if memory_bytes == 0 or file_bytes == 0:
                raise StageError(f"{label} contains an empty PT_LOAD")
            if not segment_flags & PF_R:
                raise StageError(f"{label} contains a non-readable PT_LOAD")
            if segment_flags & PF_W and segment_flags & PF_X:
                raise StageError(f"{label} contains a writable-executable PT_LOAD")
            load_segments.append(
                (
                    segment_offset,
                    segment_address,
                    file_bytes,
                    memory_bytes,
                    segment_flags,
                )
            )
            if segment_flags & PF_X:
                executable_loads.append(
                    (segment_address, segment_address + file_bytes)
                )
        elif segment_type == PT_DYNAMIC:
            dynamic_count += 1
            if dynamic_count > 1 or file_bytes == 0 or file_bytes % 16:
                raise StageError(f"{label} has an invalid PT_DYNAMIC segment")
            terminated = False
            for dynamic_offset in range(
                segment_offset, segment_offset + file_bytes, 16
            ):
                dynamic_tag = struct.unpack_from("<q", raw, dynamic_offset)[0]
                if dynamic_tag == DT_NULL:
                    terminated = True
                    break
                if dynamic_tag == DT_NEEDED:
                    raise StageError(f"{label} contains DT_NEEDED")
            if not terminated:
                raise StageError(f"{label} PT_DYNAMIC is not DT_NULL terminated")
        elif segment_type == PT_GNU_STACK:
            stack_count += 1
            if (
                stack_count > 1
                or segment_flags != PF_W | PF_R
                or segment_offset != 0
                or segment_address != 0
                or physical_address != 0
                or file_bytes != 0
                or memory_bytes != 0
            ):
                raise StageError(
                    f"{label} has an executable or malformed PT_GNU_STACK"
                )

    if not load_segments or not executable_loads:
        raise StageError(f"{label} lacks an executable PT_LOAD")
    if not any(start <= entry < end for start, end in executable_loads):
        raise StageError(f"{label} entry point is outside every executable PT_LOAD")
    if stack_count != 1:
        raise StageError(
            f"{label} must carry exactly one non-executable PT_GNU_STACK"
        )
    if dynamic_count:
        dynamic_header = next(
            struct.unpack_from(
                "<IIQQQQQQ", raw, program_offset + index * program_entry_bytes
            )
            for index in range(program_count)
            if struct.unpack_from(
                "<I", raw, program_offset + index * program_entry_bytes
            )[0]
            == PT_DYNAMIC
        )
        dynamic_offset = dynamic_header[2]
        dynamic_address = dynamic_header[3]
        dynamic_bytes = dynamic_header[5]
        if not any(
            load_address <= dynamic_address
            and dynamic_address + dynamic_bytes
            <= load_address + load_file_bytes
            and load_offset <= dynamic_offset
            and dynamic_offset + dynamic_bytes <= load_offset + load_file_bytes
            and dynamic_address - load_address == dynamic_offset - load_offset
            for (
                load_offset,
                load_address,
                load_file_bytes,
                _load_memory_bytes,
                _segment_flags,
            ) in load_segments
        ):
            raise StageError(
                f"{label} PT_DYNAMIC is not file-backed by a matching PT_LOAD"
            )


def validate_shell_artifact_set(
    document: Mapping[str, object],
    entries: Mapping[str, Mapping[str, object]],
    artifacts: Mapping[str, "RetainedInput"],
) -> None:
    exact_keys(
        document,
        {
            "artifact_set_sha256",
            "artifacts",
            "build",
            "revision",
            "schema",
            "source_bom_sha256",
            "status",
        },
        "shell artifact set",
    )
    if (
        document.get("schema") != SHELL_ARTIFACT_SET_SCHEMA
        or document.get("revision") != 1
        or document.get("status") != "product_candidate"
    ):
        raise StageError("shell artifact-set identity or product status drifted")
    build = exact_keys(
        document.get("build"),
        {
            "cargo_version",
            "features",
            "locked",
            "profile",
            "rustc_version",
            "target",
        },
        "shell artifact set build",
    )
    if (
        build.get("target") != "aarch64-unknown-linux-musl"
        or build.get("profile") != "release"
        or build.get("locked") is not True
        or build.get("features") != list(EXPECTED_SHELL_ARTIFACT_SET_FEATURES)
    ):
        raise StageError("shell artifact-set build closure drifted")
    for field in ("rustc_version", "cargo_version"):
        value = build.get(field)
        if (
            type(value) is not str
            or not value
            or len(value.encode()) > 256
            or "\x00" in value
            or "\n" in value
            or "\r" in value
        ):
            raise StageError(f"shell artifact-set {field} is invalid")

    expected_artifacts = (
        (
            "tool",
            "p01_shell_tool",
            "/system_ext/bin/trillionnium-agent-shell",
        ),
        (
            "broker",
            "p01_shell_broker",
            "/system_ext/bin/trillionnium-shell-exec-broker-userdebug",
        ),
        (
            "worker",
            "p01_shell_worker",
            "/system_ext/bin/trillionnium-shell-exec-worker-userdebug",
        ),
    )
    artifact_documents = document.get("artifacts")
    if type(artifact_documents) is not list or len(artifact_documents) != 3:
        raise StageError("shell artifact set must bind exactly three ELFs")
    for index, (expected_role, stage_role, installed_path) in enumerate(
        expected_artifacts
    ):
        item = exact_keys(
            artifact_documents[index],
            {
                "dt_needed",
                "elf_machine",
                "elf_type",
                "installed_path",
                "pt_interp",
                "role",
                "sha256",
                "size_bytes",
                "source_binary",
                "source_package",
            },
            f"shell artifact set artifacts[{index}]",
        )
        for field in ("source_package", "source_binary"):
            value = item.get(field)
            if (
                type(value) is not str
                or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None
            ):
                raise StageError(
                    f"shell artifact set artifacts[{index}].{field} is invalid"
                )
        raw = artifacts[stage_role].data
        elf_type = struct.unpack_from("<H", raw, 16)[0]
        expected_elf_type = {2: "ET_EXEC", 3: "ET_DYN"}.get(elf_type)
        validate_fully_static_elf(raw, stage_role)
        if (
            item.get("role") != expected_role
            or item.get("installed_path") != installed_path
            or item.get("sha256") != entries[stage_role]["sha256"]
            or item.get("size_bytes") != entries[stage_role]["bytes"]
            or item.get("elf_machine") != "AArch64"
            or item.get("elf_type") != expected_elf_type
            or item.get("pt_interp") is not None
            or item.get("dt_needed") != []
        ):
            raise StageError(
                f"shell artifact set artifacts[{index}] does not exactly bind {stage_role}"
            )

    if document.get("source_bom_sha256") != entries["source_bom"]["sha256"]:
        raise StageError("shell artifact set does not bind the staged source BOM")
    artifact_set_sha = lower_sha256(
        document.get("artifact_set_sha256"), "shell artifact-set SHA"
    )
    preimage = copy.deepcopy(dict(document))
    del preimage["artifact_set_sha256"]
    if artifact_set_sha != sha256(compact_json(preimage)):
        raise StageError("shell artifact_set_sha256 does not bind its canonical preimage")


def validate_xml(raw: bytes, label: str) -> None:
    if b"<!DOCTYPE" in raw.upper():
        raise StageError(f"{label} must not contain a DOCTYPE")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise StageError(f"{label} is not well-formed XML: {error}") from error
    if root.tag.split("}")[-1] != "manifest":
        raise StageError(f"{label} root element must be manifest")


def validate_spdx(document: Mapping[str, object], label: str) -> None:
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
        or document.get("name") != "trillionnium-root-linux-minimal-bookworm-arm64"
        or type(document.get("packages")) is not list
    ):
        raise StageError(f"{label} SPDX identity or package inventory drifted")
    reject_release_authority(document, label)


KV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
KV_VALUE = re.compile(r"[A-Za-z0-9_./:@,+-]+")


def parse_kv(raw: bytes, label: str, *, require_sorted: bool) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StageError(f"{label} is not UTF-8") from error
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise StageError(f"{label} must be LF-terminated text without CR or NUL")
    result: dict[str, str] = {}
    observed: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        key, separator, value = line.partition("=")
        if (
            not separator
            or KV_KEY.fullmatch(key) is None
            or KV_VALUE.fullmatch(value) is None
            or key in result
        ):
            raise StageError(f"{label} line {line_number} is invalid or duplicated")
        result[key] = value
        observed.append(key)
    if not result:
        raise StageError(f"{label} must not be empty")
    if require_sorted and observed != sorted(observed):
        raise StageError(f"{label} keys must be bytewise sorted")
    return result


def inventory_sha256(document: Mapping[str, object], path: str) -> str:
    output = document.get("output_rootfs")
    if type(output) is not dict or type(output.get("members")) is not list:
        raise StageError("rootfs receipt lacks the public member inventory")
    matches = [
        item
        for item in output["members"]
        if type(item) is dict and item.get("path") == path
    ]
    if len(matches) != 1:
        raise StageError(f"rootfs receipt inventory lacks exact member {path}")
    return lower_sha256(matches[0].get("sha256"), f"rootfs member {path}")


def rootfs_manifest_bindings(
    document: Mapping[str, object], entries: Mapping[str, Mapping[str, object]]
) -> dict[str, str]:
    output = exact_keys(
        document.get("output_rootfs"),
        {
            "android_staging_filter",
            "bytes",
            "decompressed_tar_bytes",
            "decompressed_tar_sha256",
            "filename",
            "member_count",
            "members",
            "sha256",
            "total_regular_bytes",
        },
        "rootfs receipt output_rootfs",
    )
    archive_bytes = positive_bytes(output["bytes"], "rootfs archive bytes")
    archive_sha = lower_sha256(output["sha256"], "rootfs archive SHA")
    if (
        output["filename"] != "rootfs-current.tar.zst"
        or archive_bytes != entries["rootfs_archive"]["bytes"]
        or archive_sha != entries["rootfs_archive"]["sha256"]
    ):
        raise StageError("rootfs receipt output does not bind the staged archive")
    raw_bytes = output["decompressed_tar_bytes"]
    if type(raw_bytes) is not int or not 0 < raw_bytes <= MAX_ROOTFS_TAR_BYTES:
        raise StageError("rootfs decompressed tar byte count is invalid")
    raw_sha = lower_sha256(
        output["decompressed_tar_sha256"], "rootfs decompressed tar SHA"
    )
    staging_filter = exact_keys(
        output["android_staging_filter"],
        {"bytes", "schema", "sha256", "source_sha256"},
        "rootfs receipt output_rootfs.android_staging_filter",
    )
    filtered_bytes = staging_filter["bytes"]
    filtered_sha = lower_sha256(
        staging_filter["sha256"], "Android staging-filter output SHA"
    )
    filter_source_sha = lower_sha256(
        staging_filter["source_sha256"], "Android staging-filter source SHA"
    )
    if (
        staging_filter["schema"] != STAGING_FILTER_SCHEMA
        or filter_source_sha != STAGING_FILTER_SOURCE_SHA256
        or type(filtered_bytes) is not int
        or filtered_bytes != raw_bytes
    ):
        raise StageError("Android staging-filter receipt binding drifted")

    members = output["members"]
    member_count = output["member_count"]
    total_regular_bytes = output["total_regular_bytes"]
    if (
        type(members) is not list
        or type(member_count) is not int
        or member_count <= 0
        or len(members) != member_count
        or type(total_regular_bytes) is not int
        or total_regular_bytes < 0
        or total_regular_bytes > MAX_ROOTFS_TAR_BYTES
    ):
        raise StageError("rootfs receipt member inventory summary is invalid")
    by_path: dict[str, dict[str, object]] = {}
    observed_paths: list[str] = []
    observed_regular_bytes = 0
    directory_count = 0
    for index, candidate in enumerate(members):
        label = f"rootfs receipt output_rootfs.members[{index}]"
        entry_type = candidate.get("type") if type(candidate) is dict else None
        expected_keys = {"bytes", "digest_scope", "mode", "path", "sha256", "type"}
        if entry_type in {"symlink", "hardlink"}:
            expected_keys.add("link_target")
        item = exact_keys(candidate, expected_keys, label)
        path = item["path"]
        if path != ".":
            clean_relative_path(path, f"{label}.path")
        if path in by_path:
            raise StageError("rootfs receipt member inventory has duplicate paths")
        if item["type"] not in {"directory", "file", "hardlink", "symlink"}:
            raise StageError(f"{label}.type is invalid")
        mode = item["mode"]
        if type(mode) is not str or re.fullmatch(r"[0-7]{4}", mode) is None:
            raise StageError(f"{label}.mode is invalid")
        size = item["bytes"]
        if type(size) is not int or not 0 <= size <= MAX_ROOTFS_TAR_BYTES:
            raise StageError(f"{label}.bytes is invalid")
        lower_sha256(item["sha256"], f"{label}.sha256")
        if type(item["digest_scope"]) is not str or not item["digest_scope"]:
            raise StageError(f"{label}.digest_scope is invalid")
        if item["type"] == "directory":
            directory_count += 1
            if mode != "0555" or size != 0 or item["sha256"] != EMPTY_SHA256:
                raise StageError(f"{label} directory normalization drifted")
        elif item["type"] == "file":
            observed_regular_bytes += size
            if mode not in {"0444", "0555"}:
                raise StageError(f"{label} regular-file mode drifted")
        by_path[path] = item
        observed_paths.append(path)
    if observed_paths != sorted(observed_paths, key=lambda value: value.encode("utf-8")):
        raise StageError("rootfs receipt member inventory order drifted")
    if observed_regular_bytes != total_regular_bytes:
        raise StageError("rootfs receipt total regular byte count drifted")

    shell_placeholder = by_path.get(SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH)
    if (
        shell_placeholder is None
        or shell_placeholder["type"] != "file"
        or shell_placeholder["mode"] != "0555"
        or shell_placeholder["bytes"] != 0
        or shell_placeholder["sha256"] != EMPTY_SHA256
        or shell_placeholder["digest_scope"] != "file-content"
    ):
        raise StageError(
            "rootfs receipt lacks the exact empty 0555 shell bind placeholder"
        )

    if SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES != tuple(
        sorted(
            SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES,
            key=lambda value: value.encode("utf-8"),
        )
    ) or len(set(SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES)) != len(
        SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
    ):
        raise StageError("internal shell executable allowlist path closure drifted")
    allowlist_entries: list[dict[str, str]] = []
    for absolute_path in SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES:
        member = by_path.get(absolute_path[1:])
        digest = (
            lower_sha256(
                member.get("sha256"),
                f"rootfs shell allowlist member {absolute_path}",
            )
            if isinstance(member, dict)
            else None
        )
        if (
            member is None
            or member["type"] != "file"
            or member["mode"] != "0555"
            or type(member["bytes"]) is not int
            or member["bytes"] <= 0
            or member["digest_scope"] != "file-content"
            or digest in {EMPTY_SHA256, "0" * SHA256_HEX_LEN}
        ):
            raise StageError(
                "rootfs shell allowlist member is not an exact nonempty 0555 "
                f"regular file: {absolute_path}"
            )
        assert digest is not None
        allowlist_entries.append({"path": absolute_path, "sha256": digest})
    allowlist_raw = compact_json(
        {
            "schema": SHELL_EXEC_STANDARD_ALLOWLIST_SCHEMA,
            "profile": SHELL_EXEC_STANDARD_ALLOWLIST_PROFILE,
            "entries": allowlist_entries,
        }
    )
    if len(allowlist_raw) != SHELL_EXEC_STANDARD_ALLOWLIST_BYTES:
        raise StageError("internal canonical shell executable allowlist size drifted")
    shell_allowlist = by_path.get(SHELL_EXEC_STANDARD_ALLOWLIST_PATH)
    if (
        shell_allowlist is None
        or shell_allowlist["type"] != "file"
        or shell_allowlist["mode"] != "0444"
        or shell_allowlist["bytes"] != len(allowlist_raw)
        or shell_allowlist["sha256"] != sha256(allowlist_raw)
        or shell_allowlist["digest_scope"] != "file-content"
    ):
        raise StageError(
            "rootfs receipt shell executable allowlist does not bind the exact "
            "canonical 7-entry policy"
        )

    fresh = exact_keys(
        exact_keys(
            document.get("inputs"),
            set(document["inputs"]) if type(document.get("inputs")) is dict else set(),
            "rootfs receipt inputs",
        ).get("fresh_base_provenance"),
        {
            "allowlist",
            "archive_subtraction_or_hot_replacement_performed",
            "build_contract",
            "builder",
            "fresh_archive_exact_match",
            "package_count",
            "product_admission_allowed",
            "receipt",
            "sbom",
            "snapshot_timestamp",
            "source_date_epoch",
        },
        "rootfs receipt fresh-base provenance",
    )
    if (
        fresh["fresh_archive_exact_match"] is not True
        or fresh["archive_subtraction_or_hot_replacement_performed"] is not False
        or fresh["product_admission_allowed"] is not False
    ):
        raise StageError("rootfs fresh-base provenance posture drifted")

    def provenance_descriptor(
        value: object, label: str, schema: str, filename: str
    ) -> dict[str, object]:
        descriptor = exact_keys(
            value,
            {"bytes", "filename", "mode", "receipt_id", "schema", "sha256"}
            if label.endswith("receipt")
            else {"bytes", "filename", "mode", "schema", "sha256"},
            label,
        )
        if (
            descriptor["schema"] != schema
            or descriptor["filename"] != filename
            or descriptor["mode"] not in {"0444", "0644"}
        ):
            raise StageError(f"{label} identity drifted")
        positive_bytes(descriptor["bytes"], f"{label}.bytes")
        lower_sha256(descriptor["sha256"], f"{label}.sha256")
        if label.endswith("receipt"):
            lower_sha256(descriptor["receipt_id"], f"{label}.receipt_id")
        return descriptor

    fresh_receipt = provenance_descriptor(
        fresh["receipt"],
        "fresh base receipt",
        "org.trillionnium.root-linux.minimal-bookworm-receipt.v1",
        "minimal-bookworm-arm64.receipt.json",
    )
    fresh_sbom = provenance_descriptor(
        fresh["sbom"],
        "fresh base SBOM",
        "SPDX-2.3",
        "minimal-bookworm-arm64.spdx.json",
    )
    package_count = fresh["package_count"]
    if type(package_count) is not int or not 0 < package_count <= 10_000:
        raise StageError("fresh base package count is invalid")
    status = by_path.get("var/lib/dpkg/status")
    if status is None or status["type"] != "file":
        raise StageError("rootfs receipt lacks the dpkg status inventory member")
    archive_agent_manifest = by_path.get(
        "etc/trillionnium/agents/agent-codex-direct-v1.json"
    )
    if (
        archive_agent_manifest is None
        or archive_agent_manifest["type"] != "file"
        or archive_agent_manifest["mode"] != "0444"
        or archive_agent_manifest["digest_scope"] != "file-content"
        or archive_agent_manifest["bytes"] <= 0
    ):
        raise StageError(
            "rootfs receipt lacks the normalized common AgentManifest inventory member"
        )
    if (
        fresh_receipt["bytes"] != entries["fresh_base_receipt"]["bytes"]
        or fresh_receipt["sha256"] != entries["fresh_base_receipt"]["sha256"]
        or fresh_sbom["bytes"] != entries["fresh_base_sbom"]["bytes"]
        or fresh_sbom["sha256"] != entries["fresh_base_sbom"]["sha256"]
    ):
        raise StageError("rootfs receipt does not bind the staged fresh-base evidence")
    return {
        "rootfs_archive": "rootfs-current.tar.zst",
        "rootfs_archive_bytes": str(archive_bytes),
        "rootfs_archive_directory_count": str(directory_count),
        "rootfs_archive_payload_directory_mode": "0555",
        "rootfs_archive_sha256": archive_sha,
        "rootfs_dpkg_package_count": str(package_count),
        "rootfs_dpkg_status_sha256": str(status["sha256"]),
        "rootfs_filtered_tar_sha256": filtered_sha,
        "rootfs_filtered_tar_size": str(filtered_bytes),
        "rootfs_fresh_base_receipt_bytes": str(fresh_receipt["bytes"]),
        "rootfs_fresh_base_receipt_path": "/system_ext/etc/trillionnium/linux/"
        + str(fresh_receipt["filename"]),
        "rootfs_fresh_base_receipt_schema": str(fresh_receipt["schema"]),
        "rootfs_fresh_base_receipt_sha256": str(fresh_receipt["sha256"]),
        "rootfs_fresh_base_sbom_bytes": str(fresh_sbom["bytes"]),
        "rootfs_fresh_base_sbom_path": "/system_ext/etc/trillionnium/linux/"
        + str(fresh_sbom["filename"]),
        "rootfs_fresh_base_sbom_schema": str(fresh_sbom["schema"]),
        "rootfs_fresh_base_sbom_sha256": str(fresh_sbom["sha256"]),
        "rootfs_raw_tar_sha256": raw_sha,
        "rootfs_raw_tar_size": str(raw_bytes),
        "root_linux_archive_agent_manifest_sha256": str(
            archive_agent_manifest["sha256"]
        ),
        "rootfs_tar_staging_filter_schema": STAGING_FILTER_SCHEMA,
        "rootfs_tar_staging_filter_source_sha256": filter_source_sha,
    }


def closure_sha256(records: Sequence[tuple[str, str]]) -> str:
    raw = "".join(f"{digest}  {path}\n" for digest, path in records).encode()
    return sha256(raw)


def expected_agent_manifest(
    entries: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    return {
        "adapter": "supervised-codex-cli",
        "adapter_version": "0.144.1",
        "agent_id": "agent-codex-direct-v1",
        "api_version": "trillionnium.agent-api.v1",
        "enabled": True,
        "health": "ready",
        "identity_key_sha256": entries["p01_codex_launcher"]["sha256"],
        "network_policy": "per_request",
        "peer_gid": 5901,
        "peer_uid": 5901,
        "registered_at_unix_ms": 0,
        "selinux_domain": "u:r:trillionnium_codex_agent:s0",
        "updated_at_unix_ms": 0,
    }


def validate_agent_manifest(
    document: Mapping[str, object], entries: Mapping[str, Mapping[str, object]]
) -> None:
    expected = expected_agent_manifest(entries)
    exact_keys(document, set(expected), "P01 AgentManifest")
    if document != expected:
        raise StageError("P01 AgentManifest semantic fields drifted")


def derive_runtime_bindings(
    documents: Mapping[str, Mapping[str, object]],
    entries: Mapping[str, Mapping[str, object]],
) -> tuple[dict[str, str], dict[str, str]]:
    common = documents["common_artifact_set"]
    rootfs = documents["rootfs_receipt"]
    fresh_receipt = documents["fresh_base_receipt"]
    fresh_sbom = documents["fresh_base_sbom"]
    common_inputs = common.get("inputs")
    if type(common_inputs) is not dict:
        raise StageError("common artifact set lacks its runtime input binding")
    codex_runtime_sha = lower_sha256(
        entries["codex_runtime"]["sha256"], "staged Codex runtime SHA"
    )
    if common_inputs.get("codex_runtime_sha256") != codex_runtime_sha:
        raise StageError("common artifact set does not bind the staged Codex runtime")
    rootfs_inputs = rootfs.get("inputs")
    fresh_provenance = (
        rootfs_inputs.get("fresh_base_provenance")
        if type(rootfs_inputs) is dict
        else None
    )
    if type(fresh_provenance) is not dict:
        raise StageError("rootfs receipt lacks fresh-base provenance")
    receipt_descriptor = fresh_provenance.get("receipt")
    sbom_descriptor = fresh_provenance.get("sbom")
    if (
        type(receipt_descriptor) is not dict
        or receipt_descriptor.get("receipt_id") != fresh_receipt.get("receipt_id")
        or receipt_descriptor.get("schema") != fresh_receipt.get("schema")
        or type(sbom_descriptor) is not dict
        or sbom_descriptor.get("schema") != fresh_sbom.get("spdxVersion")
    ):
        raise StageError("fresh-base evidence identity differs from rootfs receipt")
    daemon_closure = closure_sha256(
        (
            (entries["p01_daemon"]["sha256"], "usr/bin/trillionniumd"),
            (
                inventory_sha256(
                    rootfs, "lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
                ),
                "lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
            ),
            (
                inventory_sha256(rootfs, "lib/aarch64-linux-gnu/libc.so.6"),
                "lib/aarch64-linux-gnu/libc.so.6",
            ),
            (
                inventory_sha256(rootfs, "lib/aarch64-linux-gnu/libm.so.6"),
                "lib/aarch64-linux-gnu/libm.so.6",
            ),
            (
                inventory_sha256(rootfs, "lib/aarch64-linux-gnu/libgcc_s.so.1"),
                "lib/aarch64-linux-gnu/libgcc_s.so.1",
            ),
        )
    )
    codex_closure = closure_sha256(
        (
            (
                entries["p01_codex_launcher"]["sha256"],
                "usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin/codex",
            ),
            (
                codex_runtime_sha,
                "usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin/codex.real",
            ),
            (
                entries["p01_system_api"]["sha256"],
                "usr/local/bin/trillionnium-agent-system-api",
            ),
            (
                entries["common_accessibility"]["sha256"],
                "usr/local/bin/trillionnium-agent-accessibility",
            ),
        )
    )
    expected_config: dict[str, str] = {
        "TRILLIONNIUM_ACCESSIBILITY_EXPECTED_SHA256": entries[
            "common_accessibility"
        ]["sha256"],
        "TRILLIONNIUM_AGENT_BINDING_INBOX_INTEGRATION": "p01_provider_hot_path_userdebug_only",
        "TRILLIONNIUM_AGENT_OPERATION_JOURNAL_INTEGRATION": "p01_direct_operation_custody_userdebug_only",
        "TRILLIONNIUM_AGENT_OUTER_ACK_INTEGRATION": "p01_source_host_complete_device_evidence_hold_userdebug_only",
        "TRILLIONNIUM_CODEX_EXPECTED_SHA256": entries["p01_codex_launcher"]["sha256"],
        "TRILLIONNIUM_CODEX_RUNTIME_CLOSURE_SHA256": codex_closure,
        "TRILLIONNIUM_CODEX_RUNTIME_EXPECTED_SHA256": codex_runtime_sha,
        "TRILLIONNIUM_DAEMON_PAYLOAD_SHA256": entries["p01_daemon"]["sha256"],
        "TRILLIONNIUM_DAEMON_RUNTIME_CLOSURE_SHA256": daemon_closure,
        "TRILLIONNIUM_P01_AUTHORITY_KEY_PROFILE": "userdebug_local_hardware_v1",
        "TRILLIONNIUM_P01_REPLAY_SYNC_SHA256": entries["p01_replay_sync"]["sha256"],
        "TRILLIONNIUM_P01_USERDEBUG_ENABLED": "1",
        "TRILLIONNIUM_PAYLOAD_MANIFEST": "/system_ext/etc/trillionnium/linux/manifest.txt",
        "TRILLIONNIUM_SYSTEM_API_EXPECTED_SHA256": entries["p01_system_api"]["sha256"],
    }
    required_manifest: dict[str, str] = {
        "agent_binding_inbox_integration": "p01_provider_hot_path_userdebug_only",
        "agent_operation_journal_integration": "p01_direct_operation_custody_userdebug_only",
        "agent_outer_ack_integration": "p01_source_host_complete_device_evidence_hold_userdebug_only",
        "agent_system_api_build_variants": "userdebug",
        "agentd_build_variants": "userdebug",
        "agentd_runtime_closure_sha256": daemon_closure,
        "android_receipt_stage_schema": STAGE_SCHEMA,
        "codex_runtime_closure_sha256": codex_closure,
        "codex_runtime_sha256": codex_runtime_sha,
        "p01_accessibility_authorized": "false_hold",
        "p01_android_ack_transport": "source_wired_device_evidence_hold",
        "p01_binding_schema": "trillionnium.direct-operation.binding.v3",
        "p01_daemon_custody_ack_compact_retire": "complete_source_host_userdebug_only",
        "p01_external_authority_device_evidence": "hold_not_run",
        "p01_final_artifact_set_schema": "org.trillionnium.p01-userdebug-final-daemon-artifact-set.v5",
        "p01_hardware_rollback_anchor": "hold_not_implemented",
        "p01_physical_device_evidence": "hold_not_run",
        "p01_product_variant": "userdebug",
        "p01_release_allowed": "false_userdebug_only",
        "p01_sealed_replay_authority_handoff": "complete_source_host_userdebug_only",
        "public_release_allowed": "false",
        "root_linux_overlay_transaction_roles": "p01_daemon,p01_system_api,p01_replay_sync,p01_high_water,p01_codex_launcher,p01_shell_tool",
        "shell_exec_v1_android_shell_fallback": "forbidden",
        "shell_exec_v1_artifact_set": "required_control_owned_v1_feature_closure_unlocked_hold",
        "shell_exec_v1_artifact_set_path": "/system_ext/etc/trillionnium/p01-userdebug/trillionnium-shell-exec-artifact-set-v1.json",
        "shell_exec_v1_artifact_set_schema": SHELL_ARTIFACT_SET_SCHEMA,
        "shell_exec_v1_broker_build_variants": "userdebug",
        "shell_exec_v1_broker_sha256": entries["p01_shell_broker"]["sha256"],
        "shell_exec_v1_broker_signed_source": "/system_ext/bin/trillionnium-shell-exec-broker-userdebug",
        "shell_exec_v1_effect_authority": "false_host_only_wiring",
        "shell_exec_v1_mcp_tool": "trillionnium_shell_exec",
        "shell_exec_v1_profile": "standard",
        "shell_exec_v1_cgroup_isolation": "false_device_evidence_hold",
        "shell_exec_v1_command_string_mode": "forbidden_v1",
        "shell_exec_v1_ready_gate": "pending_no_publisher_device_evidence_hold",
        "shell_exec_v1_rootfs_bind_target": "required_new_rootfs_package_absent_v20",
        "shell_exec_v1_root_linux_namespace_entry_verified": "false_device_evidence_hold",
        "shell_exec_v1_seccomp_isolation": "false_device_evidence_hold",
        "shell_exec_v1_socket": "@trillionnium_shell_exec",
        "shell_exec_v1_target": "root_linux",
        "shell_exec_v1_tool_rootfs_path": "/usr/local/bin/trillionnium-agent-shell",
        "shell_exec_v1_tool_sha256": entries["p01_shell_tool"]["sha256"],
        "shell_exec_v1_tool_signed_source": "/system_ext/bin/trillionnium-agent-shell",
        "shell_exec_v1_transport_protocol": "org.trillionnium.shell-exec.transport.v1",
        "shell_exec_v1_worker_gid": "5903",
        "shell_exec_v1_worker_listener": "absent",
        "shell_exec_v1_worker_sha256": entries["p01_shell_worker"]["sha256"],
        "shell_exec_v1_worker_signed_source": "/system_ext/bin/trillionnium-shell-exec-worker-userdebug",
        "shell_exec_v1_worker_uid": "5903",
        "rootfs_common_artifact_set_schema": "org.trillionnium.common-codex-rootfs-artifact-set.v5",
        "rootfs_package_contract_schema": "org.trillionnium.rootfs-package.contract.v9",
        "rootfs_package_receipt_schema": "org.trillionnium.rootfs-package.receipt.v9",
    }
    required_manifest.update(rootfs_manifest_bindings(rootfs, entries))
    return expected_config, required_manifest


def validate_runtime_documents(
    documents: Mapping[str, Mapping[str, object]],
    entries: Mapping[str, Mapping[str, object]],
) -> None:
    config = documents["p01_runtime_config"]
    manifest = documents["root_linux_manifest"]
    expected_config, required_manifest = derive_runtime_bindings(documents, entries)
    if config != expected_config:
        raise StageError("P01 runtime environment is not exactly derived from staged evidence")
    for key, expected in required_manifest.items():
        if manifest.get(key) != expected:
            raise StageError(f"root-linux manifest semantic field {key} drifted")


def validate_source_bom(
    document: Mapping[str, object],
    source_descriptor: Mapping[str, object],
    manifest_descriptor: Mapping[str, object],
    *,
    allow_userdebug_dogfood: bool = False,
) -> None:
    schema = document.get("schema")
    if schema == USERDEBUG_DOGFOOD_SOURCE_BOM_SCHEMA:
        if not allow_userdebug_dogfood:
            raise StageError("userdebug dogfood source BOM requires explicit opt-in")
        if document.get("decision") != USERDEBUG_DOGFOOD_SOURCE_BOM_DECISION:
            raise StageError("userdebug dogfood source BOM decision is invalid")
        posture = document.get("posture")
        if type(posture) is not dict or any(
            posture.get(key) is not False
            for key in (
                "signed",
                "release_pin_published",
                "build_authorized",
                "ota_authorized",
                "device_write_authorized",
                "public_release_allowed",
                "release_allowed",
                "effect_authority",
            )
        ):
            raise StageError("userdebug dogfood source BOM posture is authorizing")
        inventory = document.get("project_inventory")
        if type(inventory) is not dict or not inventory.get("blockers"):
            raise StageError("userdebug dogfood source BOM lacks project blockers")
        for inventory_name in ("artifacts", "trees"):
            inventory = document.get(inventory_name)
            if type(inventory) is not list:
                raise StageError(
                    f"userdebug dogfood source BOM {inventory_name} inventory is malformed"
                )
            for item in inventory:
                if type(item) is not dict or item.get("failures", []) not in ([], None):
                    raise StageError(
                        f"userdebug dogfood source BOM {inventory_name} has a failed input"
                    )
    elif (
        schema != "org.trillionnium.local-cross-repo-source-bom.v2"
        or document.get("decision") != "PASS_LOCAL_EXACT_CLEAN_GRAPH"
        or document.get("blockers") != []
        or document.get("artifacts") != []
    ):
        raise StageError("source BOM is not the exact clean, artifact-free source graph")
    validate_self_hash(document, "source BOM")
    source_set = exact_keys(
        document.get("source_set"),
        set(document["source_set"]) if type(document.get("source_set")) is dict else set(),
        "source BOM source_set",
    )
    manifest = exact_keys(
        document.get("resolved_manifest"),
        set(document["resolved_manifest"])
        if type(document.get("resolved_manifest")) is dict
        else set(),
        "source BOM resolved_manifest",
    )
    if (
        source_set.get("sha256") != source_descriptor["source_set_sha256"]
        or manifest.get("sha256") != manifest_descriptor["sha256"]
        or manifest.get("bytes") != manifest_descriptor["bytes"]
        or document.get("receipt_id") != source_descriptor["receipt_id"]
    ):
        raise StageError("source BOM descriptor or resolved-manifest binding drifted")


def validate_stage(
    contract: Mapping[str, object],
    receipt_input: RetainedInput,
    artifacts: Mapping[str, RetainedInput],
    *,
    allow_userdebug_dogfood: bool = False,
) -> tuple[dict[str, object], dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    receipt = parse_json(receipt_input.data, "external receipt-stage receipt")
    exact_keys(
        receipt,
        {
            "artifacts",
            "claims",
            "contract_schema",
            "cross_bindings",
            "decision",
            "public_release_allowed",
            "receipt_id",
            "receipt_id_scope",
            "release_authority",
            "resolved_manifest",
            "schema",
            "source_bom",
        },
        "external receipt-stage receipt",
    )
    if (
        receipt["schema"] != contract["stage_receipt_schema"]
        or receipt["contract_schema"] != contract["schema"]
        or receipt["receipt_id_scope"] != contract["stage_receipt_id_scope"]
        or receipt["decision"] != contract["decision"]
        or receipt["release_authority"] != contract["release_authority"]
        or receipt["public_release_allowed"] is not False
        or receipt["claims"] != contract["claims"]
        or receipt["cross_bindings"] != contract["cross_bindings"]
    ):
        raise StageError("external receipt-stage header, claims, or HOLD posture drifted")
    validate_self_hash(receipt, "external receipt-stage receipt")

    specs = {spec["role"]: spec for spec in contract["role_specs"]}
    entries_raw = receipt["artifacts"]
    if type(entries_raw) is not list or len(entries_raw) != len(EXPECTED_ROLES):
        raise StageError("external receipt-stage artifact set drifted")
    entries: dict[str, dict[str, object]] = {}
    documents: dict[str, dict[str, object]] = {}
    observed_order: list[str] = []
    for index, candidate in enumerate(entries_raw):
        label = f"receipt.artifacts[{index}]"
        expected_entry_keys = {
            "bytes",
            "document_schema",
            "install_path",
            "kind",
            "mode",
            "role",
            "semantic",
            "sha256",
            "stage_path",
            "tag",
        }
        candidate_role = candidate.get("role") if type(candidate) is dict else None
        candidate_spec = specs.get(candidate_role)
        if candidate_spec is not None and "install_paths" in candidate_spec:
            expected_entry_keys.add("install_paths")
        entry = exact_keys(
            candidate,
            expected_entry_keys,
            label,
        )
        role = entry["role"]
        if role not in specs or role in entries:
            raise StageError(f"{label}.role is unknown or duplicated")
        observed_order.append(role)
        spec = specs[role]
        contract_fields = [
            "document_schema",
            "install_path",
            "kind",
            "mode",
            "role",
            "semantic",
            "stage_path",
            "tag",
        ]
        if "install_paths" in spec:
            contract_fields.append("install_paths")
        for field in contract_fields:
            dogfood_schema_override = (
                field == "document_schema"
                and role == "source_bom"
                and allow_userdebug_dogfood
                and entry[field] == USERDEBUG_DOGFOOD_SOURCE_BOM_SCHEMA
            )
            if entry[field] != spec[field] and not dogfood_schema_override:
                raise StageError(f"{label}.{field} differs from the tracked contract")
        expected_bytes = positive_bytes(entry["bytes"], f"{label}.bytes")
        expected_sha = lower_sha256(entry["sha256"], f"{label}.sha256")
        physical = artifacts[role]
        if mode_string(physical.initial.st_mode) != entry["mode"]:
            raise StageError(f"{role} filesystem mode differs from the receipt")
        if len(physical.data) != expected_bytes or sha256(physical.data) != expected_sha:
            raise StageError(f"{role} bytes do not match the self-hashed stage receipt")
        if entry["kind"] == "elf":
            validate_elf(physical.data, role)
            if role in {"p01_shell_broker", "p01_shell_worker"}:
                validate_fully_static_elf(physical.data, role)
        elif entry["kind"] == "zstd":
            if not physical.data.startswith(b"\x28\xb5\x2f\xfd"):
                raise StageError("rootfs archive does not have the Zstandard frame magic")
        elif entry["kind"] == "xml":
            validate_xml(physical.data, role)
        elif entry["kind"] == "json":
            document = parse_json(physical.data, role)
            if document.get("schema") != entry["document_schema"]:
                raise StageError(f"{role} document schema differs from the receipt contract")
            validate_self_hash(document, role)
            reject_release_authority(document, role)
            for pointer in spec["required_false_fields"]:
                if json_pointer(document, pointer, f"{role}{pointer}") is not False:
                    raise StageError(f"{role}{pointer} must remain false")
            documents[role] = document
        elif entry["kind"] == "spdx":
            document = parse_json(physical.data, role)
            if document.get("spdxVersion") != entry["document_schema"]:
                raise StageError(f"{role} SPDX schema differs from the receipt contract")
            validate_spdx(document, role)
            documents[role] = document
        elif entry["kind"] == "agent_manifest":
            documents[role] = parse_json(physical.data, role)
        elif entry["kind"] == "env":
            documents[role] = parse_kv(physical.data, role, require_sorted=True)
        elif entry["kind"] == "kv":
            documents[role] = parse_kv(physical.data, role, require_sorted=False)
        else:  # pragma: no cover - contract validation makes this unreachable
            raise StageError(f"{role} has an unsupported kind")
        entries[role] = entry
    if tuple(observed_order) != EXPECTED_ROLES:
        raise StageError("external receipt-stage artifact order drifted")

    source_descriptor = exact_keys(
        receipt["source_bom"],
        {
            "artifact_role",
            "bytes",
            "receipt_id",
            "resolved_manifest_sha256",
            "schema",
            "sha256",
            "source_set_sha256",
        },
        "receipt.source_bom",
    )
    manifest_descriptor = exact_keys(
        receipt["resolved_manifest"],
        {"artifact_role", "bytes", "sha256"},
        "receipt.resolved_manifest",
    )
    if (
        source_descriptor["artifact_role"] != "source_bom"
        or source_descriptor["schema"] != entries["source_bom"]["document_schema"]
        or source_descriptor["bytes"] != entries["source_bom"]["bytes"]
        or source_descriptor["sha256"] != entries["source_bom"]["sha256"]
        or source_descriptor["resolved_manifest_sha256"]
        != entries["resolved_manifest"]["sha256"]
        or manifest_descriptor["artifact_role"] != "resolved_manifest"
        or manifest_descriptor["bytes"] != entries["resolved_manifest"]["bytes"]
        or manifest_descriptor["sha256"] != entries["resolved_manifest"]["sha256"]
    ):
        raise StageError("stage source-BOM or resolved-manifest descriptor drifted")
    lower_sha256(source_descriptor["source_set_sha256"], "source_set_sha256")
    if (
        type(source_descriptor["receipt_id"]) is not str
        or not source_descriptor["receipt_id"].startswith("sha256:")
    ):
        raise StageError("stage source BOM receipt_id is malformed")
    validate_source_bom(
        documents["source_bom"],
        source_descriptor,
        manifest_descriptor,
        allow_userdebug_dogfood=allow_userdebug_dogfood,
    )
    validate_shell_artifact_set(
        documents["shell_artifact_set"], entries, artifacts
    )

    validate_agent_manifest(documents["p01_agent_manifest"], entries)

    for index, claim in enumerate(contract["claims"]):
        evidence_role = claim["evidence_role"]
        artifact_role = claim["artifact_role"]
        field = claim["artifact_field"]
        actual = json_pointer(
            documents[evidence_role],
            claim["json_pointer"],
            f"claim[{index}]",
        )
        expected = entries[artifact_role][field]
        if specs[evidence_role]["kind"] in {"env", "kv"}:
            expected = str(expected)
        if actual != expected:
            raise StageError(
                f"claim[{index}] cross-binding failed: {evidence_role} "
                f"does not bind {artifact_role}.{field}"
            )

    common = documents["common_artifact_set"]
    p01 = documents["p01_final_artifact_set"]
    rootfs_contract = documents["rootfs_contract"]
    rootfs_receipt = documents["rootfs_receipt"]
    if (
        common.get("product_variant") != "common"
        or p01.get("product_variant") != "userdebug"
        or p01.get("non_product_conformance_only") is not True
        or (
            rootfs_contract.get("admission", {}).get("decision")
            if type(rootfs_contract.get("admission")) is dict
            else None
        )
        != "HOLD_IDENTITY_INDEPENDENCE_EVIDENCE_UNVERIFIED"
        or rootfs_receipt.get("decision")
        != "HOLD_IDENTITY_INDEPENDENCE_EVIDENCE_UNVERIFIED"
    ):
        raise StageError("common, P01, or rootfs semantic posture drifted")
    validate_runtime_documents(documents, entries)
    return receipt, entries, documents


def custody_preimage(
    contract: Mapping[str, object],
    receipt: Mapping[str, object],
    receipt_input: RetainedInput,
    entries: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    return {
        "artifacts": [
            {
                "bytes": entries[role]["bytes"],
                "mode": entries[role]["mode"],
                "role": role,
                "sha256": entries[role]["sha256"],
                "source_link_count": 1,
            }
            for role in EXPECTED_ROLES
        ],
        "metadata": {
            "all_original_stage_files_opened_with_nofollow": True,
            "all_original_stage_files_regular": True,
            "all_original_stage_files_single_link": True,
            "all_original_stage_pathnames_stable_through_copy": True,
            "all_retained_bytes_reread_exact": True,
        },
        "public_release_allowed": False,
        "receipt_id_scope": COMPACT_RECEIPT_SCOPE,
        "release_authority": HOLD,
        "schema": contract["custody_receipt_schema"],
        "stage_receipt": {
            "bytes": len(receipt_input.data),
            "receipt_id": receipt["receipt_id"],
            "sha256": sha256(receipt_input.data),
        },
    }


def build_custody_receipt(
    contract: Mapping[str, object],
    receipt: Mapping[str, object],
    receipt_input: RetainedInput,
    entries: Mapping[str, Mapping[str, object]],
) -> bytes:
    value = custody_preimage(contract, receipt, receipt_input, entries)
    value["custody_id"] = "sha256:" + sha256(compact_json(value))
    return pretty_json(value)


def validate_custody_receipt(
    raw: bytes,
    contract: Mapping[str, object],
    receipt: Mapping[str, object],
    receipt_input: RetainedInput,
    entries: Mapping[str, Mapping[str, object]],
) -> None:
    value = parse_json(raw, "receipt-stage custody attestation")
    exact_keys(
        value,
        {
            "artifacts",
            "custody_id",
            "metadata",
            "public_release_allowed",
            "receipt_id_scope",
            "release_authority",
            "schema",
            "stage_receipt",
        },
        "receipt-stage custody attestation",
    )
    custody_id = value["custody_id"]
    if type(custody_id) is not str or not custody_id.startswith("sha256:"):
        raise StageError("receipt-stage custody_id is malformed")
    preimage = copy.deepcopy(value)
    del preimage["custody_id"]
    if custody_id != "sha256:" + sha256(compact_json(preimage)):
        raise StageError("receipt-stage custody_id does not bind its canonical preimage")
    expected = parse_json(
        build_custody_receipt(contract, receipt, receipt_input, entries),
        "expected receipt-stage custody attestation",
    )
    if value != expected:
        raise StageError("receipt-stage custody attestation differs from the original gate")


def parse_role_paths(values: Sequence[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        role, separator, path = item.partition("=")
        if not separator or role not in EXPECTED_ROLES or role in result or not path:
            raise StageError(f"{label} has an invalid or duplicate role mapping: {item!r}")
        result[role] = path
    if set(result) != set(EXPECTED_ROLES):
        raise StageError(f"{label} does not contain the exact receipt-stage role set")
    return result


def resolve_cli_path(path: str, label: str) -> str:
    """Resolve clean Soong-relative paths without accepting traversal syntax."""
    if not path or "\x00" in path:
        raise StageError(f"{label} path must be non-empty and normalized")
    # RuleBuilder's sbox rewrites declared relative inputs and outputs with an
    # explicit ``./`` prefix.  Accept exactly that generated prefix, remove it
    # before normalization, and continue to reject repeated dot components,
    # traversal, duplicate separators, and every other non-canonical spelling.
    if not os.path.isabs(path) and path.startswith("./"):
        path = path[2:]
    if not path or os.path.normpath(path) != path:
        raise StageError(f"{label} path must be non-empty and normalized")
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise StageError(f"{label} path could not be resolved to a normalized absolute path")
    return path


def validate_input_output_paths(
    *,
    phase: str,
    contract_path: str,
    receipt_path: str,
    custody_input: str | None,
    input_paths: Mapping[str, str],
    receipt_output: str,
    custody_output: str,
    output_paths: Mapping[str, str],
    specs: Mapping[str, Mapping[str, object]],
) -> None:
    named_inputs = {
        "contract": contract_path,
        "receipt": receipt_path,
        **{f"artifact:{role}": path for role, path in input_paths.items()},
    }
    if custody_input is not None:
        named_inputs["custody"] = custody_input
    named_outputs = {
        "receipt": receipt_output,
        "custody": custody_output,
        **{f"artifact:{role}": path for role, path in output_paths.items()},
    }
    for label, path in {**named_inputs, **named_outputs}.items():
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise StageError(f"{label} path must be absolute and normalized")
    if len(set(named_outputs.values())) != len(named_outputs):
        raise StageError("receipt-stage output paths must be distinct")
    input_values = set(named_inputs.values())
    if any(path in input_values for path in named_outputs.values()):
        raise StageError("receipt-stage outputs must not alias lexical input paths")
    for output in named_outputs.values():
        if not os.path.lexists(output):
            continue
        for input_path in input_values:
            try:
                if os.path.samefile(output, input_path):
                    raise StageError("receipt-stage outputs must not alias input inodes")
            except FileNotFoundError:
                continue

    if phase == "custody":
        stage_root = os.path.dirname(receipt_path)
        if os.path.basename(receipt_path) != "receipt-stage.v1.json":
            raise StageError("external stage receipt filename drifted")
        if not stage_root.endswith(os.sep + STAGE_ROOT):
            raise StageError("external receipt does not live in the fixed OUT_DIR stage subtree")
        for role, path in input_paths.items():
            expected = os.path.join(stage_root, specs[role]["stage_path"])
            if path != expected:
                raise StageError(f"external stage path for {role} drifted")
        for output in named_outputs.values():
            if os.path.commonpath((stage_root, output)) == stage_root:
                raise StageError("receipt-stage outputs must be outside the external stage subtree")


def atomic_write(path: str, raw: bytes, mode: int) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".receipt-stage.", dir=parent)
    try:
        with os.fdopen(fd, "wb", closefd=True) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--phase", choices=("custody", "publish"), required=True)
    value.add_argument(
        "--allow-userdebug-dogfood",
        action="store_true",
        help="accept the explicit non-authorizing userdebug dogfood source BOM",
    )
    value.add_argument("--contract", required=True)
    value.add_argument("--receipt", required=True)
    value.add_argument("--receipt-output", required=True)
    value.add_argument("--artifact-in", action="append", default=[])
    value.add_argument("--artifact-out", action="append", default=[])
    value.add_argument("--custody-input")
    value.add_argument("--custody-output", required=True)
    return value


def run(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    input_paths = {
        role: resolve_cli_path(path, f"artifact input {role}")
        for role, path in parse_role_paths(args.artifact_in, "--artifact-in").items()
    }
    output_paths = {
        role: resolve_cli_path(path, f"artifact output {role}")
        for role, path in parse_role_paths(args.artifact_out, "--artifact-out").items()
    }
    args.contract = resolve_cli_path(args.contract, "contract")
    args.receipt = resolve_cli_path(args.receipt, "receipt")
    args.receipt_output = resolve_cli_path(args.receipt_output, "receipt output")
    args.custody_output = resolve_cli_path(args.custody_output, "custody output")
    if args.custody_input is not None:
        args.custody_input = resolve_cli_path(args.custody_input, "custody input")
    if args.phase == "custody" and args.custody_input is not None:
        raise StageError("custody phase must not accept a prior custody attestation")
    if args.phase == "publish" and args.custody_input is None:
        raise StageError("publish phase requires the custody attestation")

    retained: list[RetainedInput] = []
    output_parents: dict[str, RetainedDirectoryPath] = {}
    published: list[PublishedOutput] = []
    errors: list[tuple[str, BaseException]] = []
    try:
        contract_input = RetainedInput.acquire(
            args.contract,
            "receipt-stage contract",
        )
        retained.append(contract_input)
        contract = validate_contract(contract_input.data)
        specs = {spec["role"]: spec for spec in contract["role_specs"]}
        validate_input_output_paths(
            phase=args.phase,
            contract_path=args.contract,
            receipt_path=args.receipt,
            custody_input=args.custody_input,
            input_paths=input_paths,
            receipt_output=args.receipt_output,
            custody_output=args.custody_output,
            output_paths=output_paths,
            specs=specs,
        )
        receipt_input = RetainedInput.acquire(args.receipt, "receipt-stage receipt")
        retained.append(receipt_input)
        if mode_string(receipt_input.initial.st_mode) != "0444":
            raise StageError("receipt-stage receipt mode must be 0444")
        artifact_inputs: dict[str, RetainedInput] = {}
        for role in EXPECTED_ROLES:
            item = RetainedInput.acquire(input_paths[role], f"stage artifact {role}")
            retained.append(item)
            artifact_inputs[role] = item
        receipt, entries, _ = validate_stage(
            contract,
            receipt_input,
            artifact_inputs,
            allow_userdebug_dogfood=args.allow_userdebug_dogfood,
        )

        custody_raw: bytes
        if args.phase == "custody":
            custody_raw = build_custody_receipt(
                contract, receipt, receipt_input, entries
            )
        else:
            custody_input = RetainedInput.acquire(
                args.custody_input, "receipt-stage custody attestation"
            )
            retained.append(custody_input)
            if mode_string(custody_input.initial.st_mode) != "0444":
                raise StageError("receipt-stage custody attestation mode must be 0444")
            validate_custody_receipt(
                custody_input.data, contract, receipt, receipt_input, entries
            )
            custody_raw = custody_input.data

        for item in retained:
            item.assert_stable()

        output_plan: list[tuple[str, str, bytes, int]] = [
            (
                output_paths[role],
                f"published stage artifact {role}",
                artifact_inputs[role].data,
                int(entries[role]["mode"], 8),
            )
            for role in EXPECTED_ROLES
        ]
        output_plan += [
            (
                args.receipt_output,
                "published receipt-stage receipt",
                receipt_input.data,
                0o444,
            ),
            (
                args.custody_output,
                "published receipt-stage custody attestation",
                custody_raw,
                0o444,
            ),
        ]
        for path, label, _, _ in output_plan:
            parent_path = os.path.dirname(path)
            if parent_path not in output_parents:
                output_parents[parent_path] = RetainedDirectoryPath.acquire(
                    parent_path, f"{label} parent", create=True
                )
            parent = output_parents[parent_path]
            parent.assert_stable()
            try:
                os.stat(
                    os.path.basename(path),
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise StageError(f"{label} output target already exists")
        for path, label, raw, mode in output_plan:
            parent = output_parents[os.path.dirname(path)]
            published.append(PublishedOutput.publish(path, label, raw, mode, parent))

        # First complete gate while every input and output descriptor is held.
        for item in retained:
            item.assert_stable()
        for item in published:
            item.assert_stable()
    except BaseException as error:
        errors.append(("primary verification/publication", error))

    # Input custody must tear down before the genuinely final output gate.  A
    # close error remains fatal but cannot skip the output revalidation.
    for item in reversed(retained):
        try:
            item.close()
        except BaseException as error:
            errors.append((f"input teardown {item.label}", error))

    for item in published:
        try:
            item.assert_stable()
        except BaseException as error:
            errors.append((f"final output gate {item.label}", error))

    cleanup_performed = False
    if errors:
        cleanup_performed = True
        for item in reversed(published):
            try:
                item.cleanup()
            except BaseException as error:
                errors.append((f"failure cleanup {item.label}", error))

    output_close_failed = False
    for item in reversed(published):
        try:
            item.close()
        except BaseException as error:
            output_close_failed = True
            errors.append((f"output teardown {item.label}", error))

    # A descriptor-close failure discovered only during output teardown still
    # converts the action to a clean failure while retained parents remain.
    if output_close_failed and not cleanup_performed:
        for item in reversed(published):
            try:
                item.cleanup()
            except BaseException as error:
                errors.append((f"post-teardown failure cleanup {item.label}", error))

    for path, parent in reversed(list(output_parents.items())):
        try:
            parent.close()
        except BaseException as error:
            errors.append((f"output parent teardown {path}", error))

    if errors:
        primary_phase, primary = errors[0]
        secondary = "; ".join(
            f"{phase}: {error}" for phase, error in errors[1:]
        )
        message = f"{primary_phase}: {primary}"
        if secondary:
            message += f"; secondary failures: {secondary}"
        raise StageError(message) from primary
    return 0


def main() -> int:
    try:
        return run()
    except (OSError, StageError, ValueError) as error:
        print(f"receipt-stage verification denied: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
