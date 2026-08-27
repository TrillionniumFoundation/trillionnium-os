#!/usr/bin/env python3
"""Build a host-signed full A/B OTA from one Android target-files ZIP.

The signing policy is an explicit JSON contract.  Dry-run mode validates the
target-files/product/key maps without reading private material.  Execution is
fail closed: all non-PRESIGNED APEX payloads must have an explicit replacement,
every AVB key-bearing partition must be mapped, private material is copied into
a temporary 0700 boundary, the Android password file is 0600, and all temporary
material is removed before returning.

The receipt contains only public metadata, handles and SHA-256 measurements. It
never records source secret paths, passphrases or private-key bytes.  A
``userdebug`` result is always a non-release result.  A ``user`` result is only
a host-produced release candidate: this tool does not prove locked-green device
state, hardware antirollback, or EROFS/fs-verity state.  It does not build
target-files, install an OTA, write a device, upload an artifact, or authorize a
public release.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import ssl
import stat
import subprocess
import tempfile
import time
from typing import Iterator, Mapping, Sequence
import zipfile


CONFIG_SCHEMA = "org.trillionnium.android-release-signing-config.v1"
RECEIPT_SCHEMA = "org.trillionnium.android-release-ota-receipt.v2"
RELEASE_BOUNDARIES_SCHEMA = "org.trillionnium.android-release-boundaries.v1"
BUILD_TYPES = frozenset({"user", "userdebug"})
DRY_RUN_USER_PASS = (
    "PASS_HOST_SIGNING_PREFLIGHT_USER_RELEASE_CANDIDATE_BOUNDARIES_HOLD"
)
DRY_RUN_USERDEBUG_PASS = "PASS_HOST_SIGNING_PREFLIGHT_USERDEBUG_NON_RELEASE"
DRY_RUN_MATERIAL_USER_PASS = (
    "PASS_HOST_SIGNING_MATERIAL_PREFLIGHT_USER_RELEASE_CANDIDATE_BOUNDARIES_HOLD"
)
DRY_RUN_MATERIAL_USERDEBUG_PASS = (
    "PASS_HOST_SIGNING_MATERIAL_PREFLIGHT_USERDEBUG_NON_RELEASE"
)
EXECUTION_USER_PASS = (
    "PASS_HOST_SIGNED_FULL_AB_OTA_USER_RELEASE_CANDIDATE_BOUNDARIES_HOLD"
)
EXECUTION_USERDEBUG_PASS = "PASS_HOST_SIGNED_FULL_AB_OTA_USERDEBUG_NON_RELEASE"
EXECUTION_DENY = "DENY_RELEASE_OTA_PIPELINE_FAILED_CLOSED"
DRY_RUN_SUCCESS_DECISIONS = {
    False: {
        "user": DRY_RUN_USER_PASS,
        "userdebug": DRY_RUN_USERDEBUG_PASS,
    },
    True: {
        "user": DRY_RUN_MATERIAL_USER_PASS,
        "userdebug": DRY_RUN_MATERIAL_USERDEBUG_PASS,
    },
}
EXECUTION_SUCCESS_DECISIONS = {
    "user": EXECUTION_USER_PASS,
    "userdebug": EXECUTION_USERDEBUG_PASS,
}
RELEASE_BOUNDARY_KEYS = {
    "schema",
    "evidence_scope",
    "build_classification",
    "release_eligibility",
    "release_ready",
    "device_evidence_collected",
    "locked_green_device",
    "hardware_antirollback",
    "erofs_fsverity",
    "device_ota_install",
    "public_release",
}
EXPECTED_RELEASE_BOUNDARIES = {
    "user": {
        "schema": RELEASE_BOUNDARIES_SCHEMA,
        "evidence_scope": "HOST_TARGET_FILES_SIGNING_AND_OTA_PACKAGING_ONLY",
        "build_classification": "USER_RELEASE_CANDIDATE_HOST_ONLY",
        "release_eligibility": "HOLD_DEVICE_RELEASE_BOUNDARIES_NOT_PROVEN",
        "release_ready": False,
        "device_evidence_collected": False,
        "locked_green_device": "HOLD_NOT_PROVEN_BY_HOST_PIPELINE",
        "hardware_antirollback": "HOLD_NOT_PROVEN_BY_HOST_PIPELINE",
        "erofs_fsverity": "HOLD_NOT_PROVEN_BY_HOST_PIPELINE",
        "device_ota_install": "HOLD_NOT_PERFORMED_BY_HOST_PIPELINE",
        "public_release": "HOLD_NOT_AUTHORIZED",
    },
    "userdebug": {
        "schema": RELEASE_BOUNDARIES_SCHEMA,
        "evidence_scope": "HOST_TARGET_FILES_SIGNING_AND_OTA_PACKAGING_ONLY",
        "build_classification": "USERDEBUG_NON_RELEASE_HOST_SIGNED_ARTIFACT",
        "release_eligibility": "DENY_USERDEBUG_NON_RELEASE",
        "release_ready": False,
        "device_evidence_collected": False,
        "locked_green_device": "HOLD_NOT_PROVEN_BY_HOST_PIPELINE",
        "hardware_antirollback": "HOLD_NOT_PROVEN_BY_HOST_PIPELINE",
        "erofs_fsverity": "HOLD_NOT_PROVEN_BY_HOST_PIPELINE",
        "device_ota_install": "HOLD_NOT_PERFORMED_BY_HOST_PIPELINE",
        "public_release": "HOLD_NOT_AUTHORIZED",
    },
}
EXPECTED_ROLLBACK_POLICY = {
    "scope": "source_and_target_files_expected_values_only",
    "hardware_high_water_proven": False,
    "hardware_programming_authorized": False,
}
DRY_RUN_RECEIPT_KEYS = {
    "schema",
    "decision",
    "build_type",
    "dry_run",
    "private_material_read",
    "material",
    "plan",
    "release_boundaries",
    "signing_performed",
    "ota_generated",
    "device_write_performed",
    "public_upload_performed",
    "public_release_authorized",
}
EXECUTION_RECEIPT_KEYS = {
    "schema",
    "decision",
    "build_type",
    "dry_run",
    "config_sha256",
    "plan",
    "release_boundaries",
    "material",
    "signed_target_files",
    "signed_target_cryptography",
    "signed_full_ab_ota",
    "quarantined_partial_outputs",
    "commands",
    "secret_source_paths_recorded",
    "private_key_contents_recorded",
    "plaintext_passphrases_recorded",
    "transient_password_file_retained",
    "transient_material_retained",
    "device_write_performed",
    "public_upload_performed",
    "public_release_authorized",
    "error",
}
DEFAULT_CONFIG = Path(__file__).with_name("android_release_signing_fogos.v1.json")
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_TARGET_BYTES = 16 * 1024 * 1024 * 1024
MAX_ZIP_ENTRIES = 1_000_000
MAX_METADATA_MEMBER_BYTES = 32 * 1024 * 1024
MAX_APEX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_AVB_IMAGE_BYTES = 256 * 1024 * 1024
MAX_AVB_PUBLIC_KEY_BYTES = 64 * 1024
MAX_SANITIZED_LOG_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BOM_BYTES = 16 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_BOM_BINDING_CHECKER = (
    Path(__file__).resolve().parents[1]
    / "packaging"
    / "android-release-gate"
    / "verify_source_bom_binding.py"
)
PORTABLE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
PRODUCT_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}")
APEX_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\.apex")
AVB_PARTITION = re.compile(r"[a-z][a-z0-9_]{0,63}")
AVB_ALGORITHM = re.compile(r"SHA(?:256|512)_RSA(?:2048|4096|8192)")
MAX_AVB_ROLLBACK_INDEX = (1 << 64) - 1
MAX_AVB_ROLLBACK_INDEX_LOCATION = 31
KNOWN_AOSP_DEVELOPMENT_CERTIFICATE_SHA256 = frozenset(
    {
        "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
        "28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd",
        "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8",
        "465983f7791f2abeb43ea2cbdc7f21a8260b72bc08a55c839fc1a43bc741a81e",
        "e1dbadce60dc080d15b58a014b0dcf9400e24de23fa00b287a5a982bfebda2ee",
        "abf21f9e2af1d881cc673fddcefa6ed9c269a437bd64b279cf45844cfd589126",
        "a6ccc500ff0e7421200eb66a7fe174ef1b00e52ca91727070cbedf061ff76c35",
        "fae9122a8721d6e2a196d2224dffcf773c9127e2bb956cbddb40b009192ffdfd",
        "ce7b2b47ae2b7552c8f92cc29124279883041fb623a5f194a82c9bf15d492aa0",
    }
)
KNOWN_AOSP_DEVELOPMENT_APK_PRIVATE_KEY_SHA256 = frozenset(
    {
        "a471fd99794def737b9f824032a78a80e59e0bd1a0333f1696fed1a117854a6f",
        "e32e232318d819932340f87efc5390eb2f1453b70093bebae9ec067be50ea39e",
        "ab578e1fcc9297cc33202dd1806bd33575c405a5daba34d096da7d7fe30752fc",
        "b1b50ff711c9c137593d16b970540d27187fe569ff110da32062c5324ee7b007",
        "23a018823d64aabecf2c91da0cef7f7bedf06df67122f88e202bb9f4b3d62970",
        "1ad8ef556870edb70f69a9d3c112544c07de5162ba440d84d33f8bb0c5962875",
        "dbc66a830a79a95438016ca5dce12ae624f90d82ab32f5b8b84357b6cc40ba04",
        "561dae618ceeb3b97fe92d71c7af8c30b05bfcda661dbb29dcb3883a772c4685",
        "495675d32e89a149d5abe191f4e9c0e218b9068714e9b53a7c91e164a0741a23",
    }
)
KNOWN_AOSP_DEVELOPMENT_AVB_PUBLIC_KEY_SHA256 = frozenset(
    {
        "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c",
        "2bed47451bc698e9e82d92a6668bd03ab6cf8dd1a144341cb7f426f20b2879cf",
        "7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6",
        "e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614",
    }
)
KNOWN_AOSP_DEVELOPMENT_AVB_PRIVATE_KEY_SHA256 = frozenset(
    {
        "f1d5765a2bdfb92fb08aee021107c7ac1a7a3f590dafd853771c85375ef0fbd7",
        "c7011836c52fdeb024f4b5865620133bb3e15df4452bf5bfe709150e289aa21c",
        "6a224754880a57ab9cbd308267cd157d94cf05a1c8cb851aec4090e045d24121",
        "a7a9b2eaa8a39867e6c0592b522f4e79210fad5bdfdb618eca1637b95d9983ec",
    }
)
RETIRED_PROVIDER_HOME_NAME = "open" + "claw"
SECRET_PATH_RE = re.compile(
    r"/(?:[^\s\x00]+/)*(?:\."
    + re.escape(RETIRED_PROVIDER_HOME_NAME)
    + r"/)?secrets(?:/[^\s\x00]*)?"
)


class ReleaseError(RuntimeError):
    """A release-signing precondition or postcondition failed."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def measure_file(path: Path, label: str, maximum: int = MAX_TARGET_BYTES) -> dict[str, object]:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError as error:
        raise ReleaseError(f"unable to open stable regular file: {label}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ReleaseError(f"invalid regular-file boundary: {label}")
        digest = hashlib.sha256()
        observed = 0
        while True:
            block = os.read(descriptor, 8 * 1024 * 1024)
            if not block:
                break
            observed += len(block)
            digest.update(block)
        after = os.fstat(descriptor)
        if observed != before.st_size or _identity(before) != _identity(after):
            raise ReleaseError(f"file changed while measured: {label}")
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    if stat.S_ISLNK(current.st_mode) or _identity(current) != _identity(before):
        raise ReleaseError(f"pathname changed while measured: {label}")
    return {
        "bytes": before.st_size,
        "sha256": digest.hexdigest(),
        "identity": _identity(before),
    }


def assert_measurement(path: Path, baseline: Mapping[str, object], label: str) -> None:
    current = measure_file(path, label)
    if current != baseline:
        raise ReleaseError(f"{label} changed after initial measurement")


def sha256_file(path: Path) -> str:
    return str(measure_file(path, path.name)["sha256"])


def strict_regular_bytes(path: Path, label: str, maximum: int) -> bytes:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError as error:
        raise ReleaseError(f"unable to open stable regular file: {label}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ReleaseError(f"invalid regular-file boundary: {label}")
        chunks: list[bytes] = []
        observed = 0
        while observed <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not block:
                break
            chunks.append(block)
            observed += len(block)
        after = os.fstat(descriptor)
        if observed != before.st_size or _identity(before) != _identity(after):
            raise ReleaseError(f"file changed while read: {label}")
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    if stat.S_ISLNK(current.st_mode) or _identity(current) != _identity(before):
        raise ReleaseError(f"pathname changed while read: {label}")
    return b"".join(chunks)


def _has_symlink_component(path: Path) -> bool:
    """Reject aliases for strict provenance inputs."""

    current = Path(os.sep)
    try:
        for component in Path(os.path.abspath(os.fspath(path))).parts[1:]:
            current /= component
            if current.is_symlink():
                return True
    except OSError:
        return True
    return False


def inspect_required_source_bom_binding(
    target_files: Path, source_bom: Path
) -> dict[str, object]:
    """Require and cross-check the target-files source-BOM binding.

    The source-BOM binding is an additive provenance check.  It is deliberately
    loaded only by the explicit strict CLI mode so existing host-signing and
    fixture invocations retain their historical behavior.  The sibling
    inspector is read-only and receives BOM bytes rather than a path, keeping
    its cross-check independent of path aliases and avoiding a second mutable
    read during ZIP inspection.
    """

    if _has_symlink_component(source_bom):
        raise ReleaseError("source-BOM binding BOM path contains a symlink")
    source_bom_bytes = strict_regular_bytes(
        source_bom, "source-BOM binding BOM", MAX_SOURCE_BOM_BYTES
    )
    checker = SOURCE_BOM_BINDING_CHECKER
    if checker.is_symlink() or not checker.is_file():
        raise ReleaseError("source-BOM binding checker is unavailable")
    spec = importlib.util.spec_from_file_location(
        "_trillionnium_release_source_bom_binding", checker
    )
    if spec is None or spec.loader is None:
        raise ReleaseError("source-BOM binding checker is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        inspect = module.inspect_target_files_source_bom_binding
        report = inspect(
            target_files,
            require_binding=True,
            expected_bom_bytes=source_bom_bytes,
        )
    except (AttributeError, OSError, RuntimeError, ValueError, TypeError) as error:
        raise ReleaseError(f"source-BOM binding preflight failed: {error}") from error
    if not isinstance(report, Mapping):
        raise ReleaseError("source-BOM binding preflight returned an invalid report")
    if report.get("valid") is not True:
        holds = report.get("holds")
        if isinstance(holds, list):
            detail = ",".join(str(item) for item in holds)
        else:
            detail = "invalid report"
        raise ReleaseError(f"source-BOM binding preflight failed: {detail}")
    return {
        "required": True,
        "present": report.get("present") is True,
        "valid": True,
        "member": report.get(
            "member", "META/trillionnium-source-bom-binding.json"
        ),
        "binding_id": report.get("binding_id"),
        "source_bom_receipt_id": report.get("source_bom_receipt_id"),
        "source_bom": {
            "bytes": len(source_bom_bytes),
            "sha256": sha256_bytes(source_bom_bytes),
        },
    }


def _identity(item: os.stat_result) -> tuple[int, ...]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, object], bytes]:
    raw = strict_regular_bytes(path, "signing config", MAX_CONFIG_BYTES)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ReleaseError(f"non-finite JSON value: {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("signing config is not strict UTF-8 JSON") from error
    if type(value) is not dict:
        raise ReleaseError("signing config must be an object")
    return value, raw


def exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ReleaseError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        raise ReleaseError(
            f"{label} keys differ: missing={sorted(keys - actual)} "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def require_build_type(value: object, label: str = "build type") -> str:
    if type(value) is not str or value not in BUILD_TYPES:
        raise ReleaseError(f"{label} is outside the closed set {sorted(BUILD_TYPES)}")
    return value


def dry_run_decision(build_type: object, private_material_read: object) -> str:
    normalized = require_build_type(build_type)
    if type(private_material_read) is not bool:
        raise ReleaseError("private-material-read state must be boolean")
    return DRY_RUN_SUCCESS_DECISIONS[private_material_read][normalized]


def execution_decision(build_type: object, error: object) -> str:
    normalized = require_build_type(build_type)
    if error is None:
        return EXECUTION_SUCCESS_DECISIONS[normalized]
    if type(error) is not str:
        raise ReleaseError("execution error must be null or a public string")
    return EXECUTION_DENY


def release_boundaries(build_type: object) -> dict[str, object]:
    normalized = require_build_type(build_type)
    return dict(EXPECTED_RELEASE_BOUNDARIES[normalized])


def validate_receipt(value: object) -> dict[str, object]:
    """Validate the exact v2 receipt shape and non-authorizing semantics."""

    if type(value) is not dict:
        raise ReleaseError("release OTA receipt must be an object")
    dry_run = value.get("dry_run")
    if type(dry_run) is not bool:
        raise ReleaseError("release OTA receipt dry_run must be boolean")
    receipt = exact_object(
        value,
        DRY_RUN_RECEIPT_KEYS if dry_run else EXECUTION_RECEIPT_KEYS,
        "release OTA receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise ReleaseError("unsupported release OTA receipt schema")

    build_type = require_build_type(receipt["build_type"], "receipt build type")
    plan = receipt["plan"]
    if type(plan) is not dict:
        raise ReleaseError("release OTA receipt plan must be an object")
    input_facts = plan.get("input_target_files")
    if type(input_facts) is not dict or input_facts.get("build_type") != build_type:
        raise ReleaseError("receipt build type is not bound to input target-files")
    if (
        plan.get("device_write_performed") is not False
        or plan.get("public_upload_performed") is not False
    ):
        raise ReleaseError("receipt plan exceeds the host-only evidence scope")
    if plan.get("rollback_policy") != EXPECTED_ROLLBACK_POLICY:
        raise ReleaseError("receipt overstates rollback or hardware authority")
    source_binding = plan.get("source_bom_binding")
    if source_binding is not None:
        if (
            type(source_binding) is not dict
            or source_binding.get("required") is not True
            or source_binding.get("present") is not True
            or source_binding.get("valid") is not True
            or source_binding.get("member")
            != "META/trillionnium-source-bom-binding.json"
        ):
            raise ReleaseError("receipt source-BOM binding projection is invalid")
        source_identity = source_binding.get("source_bom")
        if (
            type(source_identity) is not dict
            or type(source_identity.get("bytes")) is not int
            or source_identity["bytes"] <= 0
            or not isinstance(source_identity.get("sha256"), str)
            or HEX64.fullmatch(source_identity["sha256"]) is None
        ):
            raise ReleaseError("receipt source-BOM binding digest is invalid")

    boundaries = exact_object(
        receipt["release_boundaries"],
        RELEASE_BOUNDARY_KEYS,
        "receipt release_boundaries",
    )
    if boundaries != EXPECTED_RELEASE_BOUNDARIES[build_type]:
        raise ReleaseError(
            "receipt release boundaries differ from the exact build-type closed set"
        )
    if (
        receipt["device_write_performed"] is not False
        or receipt["public_upload_performed"] is not False
        or receipt["public_release_authorized"] is not False
    ):
        raise ReleaseError("release OTA receipt overstates external authority")

    if dry_run:
        private_material_read = receipt["private_material_read"]
        expected_decision = dry_run_decision(build_type, private_material_read)
        if receipt["decision"] != expected_decision:
            raise ReleaseError("dry-run decision is outside its build-type closed set")
        if (
            receipt["signing_performed"] is not False
            or receipt["ota_generated"] is not False
        ):
            raise ReleaseError("dry-run receipt claims host artifact production")
        if (receipt["material"] is None) == private_material_read:
            raise ReleaseError("dry-run material projection does not match read state")
    else:
        expected_decision = execution_decision(build_type, receipt["error"])
        if receipt["decision"] != expected_decision:
            raise ReleaseError("execution decision is outside its build-type closed set")
        for field in (
            "secret_source_paths_recorded",
            "private_key_contents_recorded",
            "plaintext_passphrases_recorded",
            "transient_password_file_retained",
            "transient_material_retained",
        ):
            if receipt[field] is not False:
                raise ReleaseError(f"release OTA receipt has forbidden true field: {field}")
        if receipt["error"] is None:
            for field in (
                "material",
                "signed_target_files",
                "signed_target_cryptography",
                "signed_full_ab_ota",
            ):
                if type(receipt[field]) is not dict:
                    raise ReleaseError(f"successful execution receipt lacks {field}")
            if (
                receipt["signed_target_files"].get("build_type") != build_type
                or receipt["signed_full_ab_ota"].get("build_type") != build_type
            ):
                raise ReleaseError(
                    "successful execution receipt artifacts changed the build type"
                )
    return receipt


def portable_relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 1024:
        raise ReleaseError(f"{label} must be a bounded relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or "\\" in value:
        raise ReleaseError(f"{label} must be a canonical relative path")
    if any(part in {"", ".", ".."} or not PORTABLE_NAME.fullmatch(part) for part in path.parts):
        raise ReleaseError(f"{label} must be a portable relative path")
    return value


def portable_filename(value: object, label: str) -> str:
    path = portable_relative_path(value, label)
    if "/" in path:
        raise ReleaseError(f"{label} must be a filename, not a path")
    return path


def validate_config(value: dict[str, object]) -> dict[str, object]:
    root = exact_object(value, {"schema", "product", "tools", "signing"}, "config")
    if root["schema"] != CONFIG_SCHEMA:
        raise ReleaseError("unsupported release-signing config schema")

    product = exact_object(
        root["product"],
        {"device", "allowed_build_types", "require_ab_update"},
        "config.product",
    )
    if type(product["device"]) is not str or not PRODUCT_NAME.fullmatch(product["device"]):
        raise ReleaseError("config.product.device is invalid")
    allowed_types = product["allowed_build_types"]
    if (
        type(allowed_types) is not list
        or not allowed_types
        or any(
            type(item) is not str or item not in BUILD_TYPES for item in allowed_types
        )
        or len(set(allowed_types)) != len(allowed_types)
    ):
        raise ReleaseError("config.product.allowed_build_types is invalid")
    if product["require_ab_update"] is not True:
        raise ReleaseError("the release pipeline requires an A/B product")

    tools = exact_object(
        root["tools"],
        {
            "sign_target_files_apks",
            "ota_from_target_files",
            "check_ota_package_signature",
            "avbtool",
            "apksigner",
        },
        "config.tools",
    )
    for name, path in tools.items():
        tools[name] = portable_relative_path(path, f"config.tools.{name}")

    signing = exact_object(
        root["signing"],
        {
            "apk_key_mappings",
            "ota_key_alias",
            "avb",
            "apex_payload_keys",
            "rollback_policy",
        },
        "config.signing",
    )
    rollback_policy = exact_object(
        signing["rollback_policy"],
        {
            "scope",
            "hardware_high_water_proven",
            "hardware_programming_authorized",
        },
        "config.signing.rollback_policy",
    )
    if rollback_policy != EXPECTED_ROLLBACK_POLICY:
        raise ReleaseError(
            "rollback indices are source/target-files expectations only; "
            "hardware authority must remain unproven and unauthorized"
        )
    ota_alias = portable_filename(signing["ota_key_alias"], "config.signing.ota_key_alias")
    apk_map = signing["apk_key_mappings"]
    if type(apk_map) is not dict or not apk_map:
        raise ReleaseError("config.signing.apk_key_mappings must be non-empty")
    normalized_apk: dict[str, str] = {}
    for source, alias in sorted(apk_map.items()):
        source_path = portable_relative_path(source, "APK source key")
        alias_name = portable_filename(alias, f"APK key alias for {source_path}")
        normalized_apk[source_path] = alias_name
    if ota_alias not in set(normalized_apk.values()):
        raise ReleaseError("OTA key alias must be included in APK key mappings")

    avb = signing["avb"]
    if type(avb) is not dict or not avb:
        raise ReleaseError("config.signing.avb must be non-empty")
    normalized_avb: dict[str, dict[str, object]] = {}
    for partition, candidate in sorted(avb.items()):
        if type(partition) is not str or not AVB_PARTITION.fullmatch(partition):
            raise ReleaseError(f"invalid AVB partition: {partition}")
        item = exact_object(
            candidate,
            {
                "algorithm",
                "expected_flags",
                "key",
                "rollback_index",
                "rollback_index_location",
            },
            f"AVB mapping {partition}",
        )
        algorithm = item["algorithm"]
        if type(algorithm) is not str or not AVB_ALGORITHM.fullmatch(algorithm):
            raise ReleaseError(f"invalid AVB algorithm for {partition}")
        expected_flags = item["expected_flags"]
        if type(expected_flags) is not int or expected_flags != 0:
            raise ReleaseError(f"AVB flags must be exactly zero for {partition}")
        rollback_index = item["rollback_index"]
        if (
            type(rollback_index) is not int
            or not 0 <= rollback_index <= MAX_AVB_ROLLBACK_INDEX
        ):
            raise ReleaseError(f"invalid AVB rollback index for {partition}")
        rollback_location = item["rollback_index_location"]
        if (
            type(rollback_location) is not int
            or not 0 <= rollback_location <= MAX_AVB_ROLLBACK_INDEX_LOCATION
        ):
            raise ReleaseError(f"invalid AVB rollback index location for {partition}")
        normalized_avb[partition] = {
            "algorithm": algorithm,
            "expected_flags": expected_flags,
            "key": portable_filename(item["key"], f"AVB key for {partition}"),
            "rollback_index": rollback_index,
            "rollback_index_location": rollback_location,
        }
    if len({item["key"] for item in normalized_avb.values()}) != len(normalized_avb):
        raise ReleaseError("AVB partitions must use distinct configured key handles")
    if "vbmeta" not in normalized_avb:
        raise ReleaseError("AVB mapping must include the top-level vbmeta partition")
    if normalized_avb["vbmeta"]["rollback_index_location"] != 0:
        raise ReleaseError("top-level vbmeta rollback index location must be zero")
    chained_locations = [
        item["rollback_index_location"]
        for partition, item in normalized_avb.items()
        if partition != "vbmeta"
    ]
    if any(location == 0 for location in chained_locations) or len(
        set(chained_locations)
    ) != len(chained_locations):
        raise ReleaseError("chained AVB rollback index locations must be unique and nonzero")

    apex = signing["apex_payload_keys"]
    if type(apex) is not dict or not apex:
        raise ReleaseError("config.signing.apex_payload_keys must be non-empty")
    normalized_apex: dict[str, str] = {}
    for package, key in sorted(apex.items()):
        if type(package) is not str or not APEX_NAME.fullmatch(package):
            raise ReleaseError(f"invalid APEX package name: {package}")
        normalized_apex[package] = portable_filename(key, f"APEX key for {package}")
    if len(set(normalized_apex.values())) != len(normalized_apex):
        raise ReleaseError("non-PRESIGNED APEX packages must use distinct payload keys")

    return {
        "schema": CONFIG_SCHEMA,
        "product": {
            "device": product["device"],
            "allowed_build_types": list(allowed_types),
            "require_ab_update": True,
        },
        "tools": dict(tools),
        "signing": {
            "apk_key_mappings": normalized_apk,
            "ota_key_alias": ota_alias,
            "avb": normalized_avb,
            "apex_payload_keys": normalized_apex,
            "rollback_policy": dict(EXPECTED_ROLLBACK_POLICY),
        },
    }


def parse_properties(raw: str, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, raw_line in enumerate(raw.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ReleaseError(f"malformed {label} line {line_number}")
        key, value = line.split("=", 1)
        if not key or key in result:
            raise ReleaseError(f"duplicate or empty {label} key: {key}")
        result[key] = value
    return result


def parse_apex_keys(raw: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            fields = dict(token.split("=", 1) for token in shlex.split(line))
        except (ValueError, TypeError) as error:
            raise ReleaseError(f"malformed apexkeys line {line_number}") from error
        expected = {
            "name",
            "public_key",
            "private_key",
            "container_certificate",
            "container_private_key",
            "partition",
        }
        if set(fields) != expected:
            raise ReleaseError(f"apexkeys line {line_number} has unexpected fields")
        name = fields["name"]
        if name in result or not APEX_NAME.fullmatch(name):
            raise ReleaseError(f"duplicate or invalid APEX name: {name}")
        result[name] = fields
    if not result:
        raise ReleaseError("target-files has no APEX key inventory")
    return result


def safe_zip_member(name: str) -> None:
    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        raise ReleaseError("target-files contains an unsafe ZIP member")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseError("target-files contains a non-canonical ZIP member")


def read_bounded_member(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise ReleaseError(f"target-files is missing {name}") from error
    if not 0 <= info.file_size <= MAX_METADATA_MEMBER_BYTES:
        raise ReleaseError(f"target-files member is too large: {name}")
    return archive.read(info)


def parse_avb_image_args(raw: object, label: str) -> dict[str, int]:
    if type(raw) is not str:
        raise ReleaseError(f"target-files is missing {label}")
    try:
        tokens = shlex.split(raw)
    except ValueError as error:
        raise ReleaseError(f"malformed {label}") from error
    observed: dict[str, int] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {
            "--set_hashtree_disabled_flag",
            "--set_verification_disabled_flag",
        }:
            raise ReleaseError(f"{label} disables AVB verification")
        matched_name: str | None = None
        value: str | None = None
        for name in ("flags", "rollback_index"):
            option = f"--{name}"
            if token == option:
                if index + 1 >= len(tokens):
                    raise ReleaseError(f"{label} has an option without a value: {option}")
                matched_name = name
                value = tokens[index + 1]
                index += 1
                break
            if token.startswith(option + "="):
                matched_name = name
                value = token[len(option) + 1 :]
                break
        if matched_name is not None:
            if matched_name in observed:
                raise ReleaseError(f"{label} repeats --{matched_name}")
            try:
                parsed = int(str(value), 0)
            except ValueError as error:
                raise ReleaseError(f"{label} has an invalid --{matched_name}") from error
            if not 0 <= parsed <= MAX_AVB_ROLLBACK_INDEX:
                raise ReleaseError(f"{label} has an out-of-range --{matched_name}")
            observed[matched_name] = parsed
        index += 1
    if "rollback_index" not in observed:
        raise ReleaseError(f"{label} has no explicit rollback index")
    observed.setdefault("flags", 0)
    return observed


def parse_rollback_location(raw: object, label: str) -> int:
    if type(raw) is not str:
        raise ReleaseError(f"target-files is missing {label}")
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise ReleaseError(f"target-files has an invalid {label}") from error
    if not 0 <= value <= MAX_AVB_ROLLBACK_INDEX_LOCATION:
        raise ReleaseError(f"target-files has an out-of-range {label}")
    return value


def inspect_target_files(
    path: Path,
    config: Mapping[str, object],
    *,
    signed: bool,
    measurement: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError("target-files must be a non-symlink regular file")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_ENTRIES:
                raise ReleaseError("target-files ZIP entry count is invalid")
            names: set[str] = set()
            for info in infos:
                safe_zip_member(info.filename)
                if info.filename in names:
                    raise ReleaseError(f"duplicate target-files ZIP member: {info.filename}")
                names.add(info.filename)
            bad = archive.testzip()
            if bad is not None:
                raise ReleaseError(f"target-files ZIP CRC failed: {bad}")
            misc = parse_properties(
                read_bounded_member(archive, "META/misc_info.txt").decode("utf-8"),
                "misc_info",
            )
            apex = parse_apex_keys(
                read_bounded_member(archive, "META/apexkeys.txt").decode("utf-8")
            )
            build_prop_name = (
                "SYSTEM/build.prop"
                if "SYSTEM/build.prop" in names
                else "SYSTEM/system/build.prop"
            )
            props = parse_properties(
                read_bounded_member(archive, build_prop_name).decode("utf-8"),
                "SYSTEM build.prop",
            )
    except (zipfile.BadZipFile, UnicodeError) as error:
        raise ReleaseError("target-files is not a valid metadata ZIP") from error

    product = config["product"]
    assert isinstance(product, Mapping)
    expected_device = product["device"]
    observed_device = props.get("ro.product.device") or props.get("ro.product.system.device")
    build_type = props.get("ro.build.type") or props.get("ro.system.build.type")
    build_tags = props.get("ro.build.tags") or props.get("ro.system.build.tags")
    fingerprint = props.get("ro.build.fingerprint") or props.get("ro.system.build.fingerprint")
    if observed_device != expected_device:
        raise ReleaseError(
            f"target device mismatch: expected {expected_device}, observed {observed_device}"
        )
    if build_type not in product["allowed_build_types"]:
        raise ReleaseError(f"target build type is not allowed: {build_type}")
    tag_set = set((build_tags or "").split(","))
    if signed:
        if "release-keys" not in tag_set or {"test-keys", "dev-keys"} & tag_set:
            raise ReleaseError("signed target-files does not have exact release-key posture")
        if fingerprint is None or not fingerprint.endswith(f":{build_type}/release-keys"):
            raise ReleaseError("signed target-files fingerprint is not release-key bound")
    else:
        if "release-keys" in tag_set or not ({"test-keys", "dev-keys"} & tag_set):
            raise ReleaseError("input target-files must be an unsigned test/dev-key build")
    if misc.get("ab_update") != "true" or misc.get("avb_enable") != "true":
        raise ReleaseError("target-files is not an AVB-enabled A/B product")

    signing = config["signing"]
    assert isinstance(signing, Mapping)
    configured_apex = set(signing["apex_payload_keys"])
    observed_apex = {
        name for name, item in apex.items() if item["private_key"] != "PRESIGNED"
    }
    if configured_apex != observed_apex:
        raise ReleaseError(
            "APEX payload mapping is not complete: "
            f"missing={sorted(observed_apex - configured_apex)} "
            f"unexpected={sorted(configured_apex - observed_apex)}"
        )
    avb = signing["avb"]
    assert isinstance(avb, Mapping)
    observed_avb = {
        match.group(1)
        for key in misc
        if (match := re.fullmatch(r"avb_([a-z0-9_]+)_key_path", key))
    }
    if set(avb) != observed_avb:
        raise ReleaseError(
            "AVB mapping is not complete: "
            f"missing={sorted(observed_avb - set(avb))} "
            f"unexpected={sorted(set(avb) - observed_avb)}"
        )
    for partition, item in avb.items():
        observed_algorithm = misc.get(f"avb_{partition}_algorithm")
        if observed_algorithm != item["algorithm"]:
            raise ReleaseError(
                f"AVB algorithm mismatch for {partition}: {observed_algorithm}"
            )
    observed_avb_policy: dict[str, dict[str, int]] = {}
    for partition, item in sorted(avb.items()):
        policy = parse_avb_image_args(
            misc.get(f"avb_{partition}_args"), f"avb_{partition}_args"
        )
        location = (
            0
            if partition == "vbmeta"
            else parse_rollback_location(
                misc.get(f"avb_{partition}_rollback_index_location"),
                f"avb_{partition}_rollback_index_location",
            )
        )
        if policy["flags"] != item["expected_flags"]:
            raise ReleaseError(
                f"AVB flags mismatch for {partition}: {policy['flags']}"
            )
        if policy["rollback_index"] != item["rollback_index"]:
            raise ReleaseError(
                f"AVB rollback index mismatch for {partition}: "
                f"{policy['rollback_index']}"
            )
        if location != item["rollback_index_location"]:
            raise ReleaseError(
                f"AVB rollback index location mismatch for {partition}: {location}"
            )
        observed_avb_policy[partition] = {
            "flags": policy["flags"],
            "rollback_index": policy["rollback_index"],
            "rollback_index_location": location,
        }

    return {
        "device": observed_device,
        "build_type": build_type,
        "build_tags": sorted(tag_set),
        "fingerprint": fingerprint,
        "ab_update": True,
        "avb_enabled": True,
        "avb_partitions": sorted(observed_avb),
        "avb_policy": observed_avb_policy,
        "apex_non_presigned": sorted(observed_apex),
        "apex_non_presigned_count": len(observed_apex),
        "zip_entry_count": len(names),
        "bytes": (
            measurement["bytes"] if measurement is not None else path.stat().st_size
        ),
        "sha256": (
            measurement["sha256"] if measurement is not None else sha256_file(path)
        ),
    }


def resolve_tool(
    tool_root: Path, relative: str, *, strip_android_out_prefix: bool = False
) -> Path:
    root = Path(os.path.abspath(os.fspath(tool_root)))
    configured = PurePosixPath(relative)
    if strip_android_out_prefix:
        if not configured.parts or configured.parts[0] != "out" or len(configured.parts) == 1:
            raise ReleaseError(
                "--android-out requires every configured host tool to start with out/"
            )
        configured = PurePosixPath(*configured.parts[1:])
    candidate = Path(os.path.abspath(os.fspath(root / str(configured))))
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ReleaseError("configured host tool escapes tool root") from error
    if candidate.is_symlink() or not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ReleaseError(f"Android host tool is unavailable: {relative}")
    return candidate


def tool_inventory(
    tool_root: Path,
    config: Mapping[str, object],
    *,
    strip_android_out_prefix: bool = False,
) -> dict[str, object]:
    tools = config["tools"]
    assert isinstance(tools, Mapping)
    result: dict[str, object] = {}
    for name, relative in sorted(tools.items()):
        path = resolve_tool(
            tool_root,
            str(relative),
            strip_android_out_prefix=strip_android_out_prefix,
        )
        result[name] = {"relative_path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)}
    return result


def private_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        info = os.lstat(absolute)
    except OSError as error:
        raise ReleaseError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ReleaseError(f"{label} must be a real directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ReleaseError(f"{label} must not be group/world accessible")
    return absolute


def owned_private_directory(path: Path, label: str, *, empty: bool) -> Path:
    absolute = private_directory(path, label)
    info = os.lstat(absolute)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ReleaseError(f"{label} must be owned by the caller with mode 0700")
    if empty:
        with os.scandir(absolute) as entries:
            try:
                next(entries)
            except StopIteration:
                pass
            else:
                raise ReleaseError(f"{label} must be empty")
    return absolute


def read_private_file(path: Path, label: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError as error:
        raise ReleaseError(f"private material is unavailable: {label}") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 1 <= info.st_size <= maximum
        ):
            raise ReleaseError(f"private material boundary is invalid: {label}")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) != info.st_size:
            raise ReleaseError(f"private material changed while read: {label}")
        return raw
    finally:
        os.close(descriptor)


def required_material(config: Mapping[str, object]) -> dict[str, set[str]]:
    signing = config["signing"]
    assert isinstance(signing, Mapping)
    aliases = set(signing["apk_key_mappings"].values())
    apk_files: set[str] = set()
    for alias in aliases:
        apk_files.update({f"{alias}.x509.pem", f"{alias}.pk8", f"{alias}.passphrase"})
    avb_files = {item["key"] for item in signing["avb"].values()}
    apex_files = set(signing["apex_payload_keys"].values())
    return {"apk": apk_files | avb_files, "apex": apex_files}


def derive_avb_public_key_digests(
    config: Mapping[str, object],
    key_root: Path,
    apex_root: Path,
    avbtool: Path,
    scratch_root: Path | None,
) -> tuple[dict[str, str], dict[str, str]]:
    runtime_parent = (
        owned_private_directory(scratch_root, "release scratch directory", empty=True)
        if scratch_root is not None
        else Path(tempfile.gettempdir()).resolve()
    )
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        temporary = tempfile.TemporaryDirectory(
            prefix="trillionnium-release-key-check.", dir=runtime_parent
        )
        runtime = Path(temporary.name).resolve()
        if runtime.parent != runtime_parent:
            raise ReleaseError("temporary key-check boundary escaped its parent")
        os.chmod(runtime, 0o700)
        signing = config["signing"]
        assert isinstance(signing, Mapping)
        avb_digests: dict[str, str] = {}
        apex_digests: dict[str, str] = {}
        sources = (
            (
                "avb",
                sorted(
                    (partition, item["key"])
                    for partition, item in signing["avb"].items()
                ),
                key_root,
                avb_digests,
            ),
            (
                "apex",
                sorted(signing["apex_payload_keys"].items()),
                apex_root,
                apex_digests,
            ),
        )
        output_index = 0
        for kind, entries, source_root, destination in sources:
            for logical_name, handle in entries:
                output = runtime / f"public-key-{output_index}.avbpubkey"
                output_index += 1
                private_check(
                    [
                        str(avbtool),
                        "extract_public_key",
                        "--key",
                        str(source_root / str(handle)),
                        "--output",
                        str(output),
                    ],
                    runtime,
                    120,
                    f"{kind} public-key derivation for {logical_name}",
                )
                public_bytes = strict_regular_bytes(
                    output,
                    f"derived {kind} public key for {logical_name}",
                    MAX_AVB_PUBLIC_KEY_BYTES,
                )
                digest = require_non_development_avb_public_key(
                    public_bytes, str(logical_name)
                )
                destination[str(logical_name)] = digest
        return avb_digests, apex_digests
    finally:
        if temporary is not None:
            target = Path(temporary.name).resolve()
            if target.parent != runtime_parent or not target.name.startswith(
                "trillionnium-release-key-check."
            ):
                raise ReleaseError("refusing unsafe key-check cleanup")
            temporary.cleanup()


def validate_material(
    config: Mapping[str, object],
    key_dir: Path,
    apex_key_dir: Path,
    avbtool: Path | None = None,
    scratch_root: Path | None = None,
) -> dict[str, object]:
    key_root = private_directory(key_dir, "APK/AVB key directory")
    apex_root = private_directory(apex_key_dir, "APEX key directory")
    required = required_material(config)
    signing = config["signing"]
    assert isinstance(signing, Mapping)
    avb_handles = {item["key"] for item in signing["avb"].values()}
    for name in sorted(required["apk"]):
        raw = read_private_file(key_root / name, f"APK/AVB handle {name}")
        if name.endswith(".pk8"):
            require_non_development_apk_private_key(raw, name)
        if name in avb_handles:
            require_non_development_avb_private_key(raw, name)
    for name in sorted(required["apex"]):
        raw = read_private_file(apex_root / name, f"APEX handle {name}")
        require_non_development_avb_private_key(raw, name)
    ota_alias = signing["ota_key_alias"]
    certificate_digests: dict[str, str] = {}
    for alias in sorted(set(signing["apk_key_mappings"].values())):
        digest = require_non_development_certificate(
            read_private_file(key_root / f"{alias}.x509.pem", f"certificate for {alias}"),
            str(alias),
        )
        certificate_digests[str(alias)] = digest
    passphrases: list[str] = []
    for alias in sorted(set(signing["apk_key_mappings"].values())):
        raw = read_private_file(key_root / f"{alias}.passphrase", f"passphrase for {alias}")
        try:
            value = raw.decode("utf-8").strip()
        except UnicodeError as error:
            raise ReleaseError(f"passphrase for {alias} is not UTF-8") from error
        if not value or "\n" in value or "\r" in value:
            raise ReleaseError(f"passphrase for {alias} is empty or multiline")
        passphrases.append(value)
    avb_digests: dict[str, str] = {}
    apex_digests: dict[str, str] = {}
    if avbtool is not None:
        avb_digests, apex_digests = derive_avb_public_key_digests(
            config, key_root, apex_root, avbtool, scratch_root
        )
    return {
        "key_handles": sorted(required["apk"]),
        "apex_key_handles": sorted(required["apex"]),
        "apk_certificate_sha256": certificate_digests,
        "avb_public_key_sha256": avb_digests,
        "apex_public_key_sha256": apex_digests,
        "ota_certificate_sha256": certificate_digests[str(ota_alias)],
        "passphrases": passphrases,
    }


@contextmanager
def staged_material(
    config: Mapping[str, object],
    key_dir: Path,
    apex_key_dir: Path,
    avbtool: Path | None = None,
    scratch_root: Path | None = None,
) -> Iterator[dict[str, object]]:
    material = validate_material(
        config, key_dir, apex_key_dir, avbtool=avbtool, scratch_root=scratch_root
    )
    runtime_parent = (
        owned_private_directory(scratch_root, "release scratch directory", empty=True)
        if scratch_root is not None
        else Path(tempfile.gettempdir()).resolve()
    )
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        temporary = tempfile.TemporaryDirectory(
            prefix="trillionnium-release-signing.", dir=runtime_parent
        )
        runtime = Path(temporary.name).resolve()
        if runtime.parent != runtime_parent:
            raise ReleaseError("temporary signing boundary escaped its parent")
        os.chmod(runtime, 0o700)
        staged = runtime / "material"
        staged.mkdir(mode=0o700)
        key_root = private_directory(key_dir, "APK/AVB key directory")
        apex_root = private_directory(apex_key_dir, "APEX key directory")
        required = required_material(config)
        for name in sorted(required["apk"]):
            destination = staged / name
            destination.write_bytes(read_private_file(key_root / name, f"APK/AVB handle {name}"))
            os.chmod(destination, 0o600)
        for name in sorted(required["apex"]):
            destination = staged / name
            if destination.exists():
                raise ReleaseError(f"duplicate staged key filename: {name}")
            destination.write_bytes(read_private_file(apex_root / name, f"APEX handle {name}"))
            os.chmod(destination, 0o600)
        signing = config["signing"]
        password_file = runtime / "android-password-file"
        rows = ["# transient Trillionnium release signing password file"]
        for alias in sorted(set(signing["apk_key_mappings"].values())):
            password = read_private_file(
                key_root / f"{alias}.passphrase", f"passphrase for {alias}"
            ).decode("utf-8").strip()
            rows.append(f"[[[  {password}  ]]] {staged / alias}")
        password_file.write_text("\n".join(rows) + "\n", encoding="utf-8")
        os.chmod(password_file, 0o600)
        yield {
            "runtime": runtime,
            "material": staged,
            "password_file": password_file,
            "passphrases": material["passphrases"],
            "apk_certificate_sha256": material["apk_certificate_sha256"],
            "avb_public_key_sha256": material["avb_public_key_sha256"],
            "apex_public_key_sha256": material["apex_public_key_sha256"],
            "ota_certificate_sha256": material["ota_certificate_sha256"],
        }
    finally:
        if temporary is not None:
            target = Path(temporary.name).resolve()
            if target.parent != runtime_parent or not target.name.startswith(
                "trillionnium-release-signing."
            ):
                raise ReleaseError("refusing unsafe temporary-boundary cleanup")
            temporary.cleanup()


def signing_command(
    tools: Mapping[str, Path],
    config: Mapping[str, object],
    material: Path,
    unsigned_target: Path,
    signed_target: Path,
) -> list[str]:
    signing = config["signing"]
    command = [
        str(tools["sign_target_files_apks"]),
        "--replace_ota_keys",
        "--tag_changes=-test-keys,-dev-keys,+release-keys",
    ]
    for source, alias in sorted(signing["apk_key_mappings"].items()):
        command.extend(["--key_mapping", f"{source}={material / alias}"])
    ota_alias = signing["ota_key_alias"]
    for package, key in sorted(signing["apex_payload_keys"].items()):
        command.extend(["--extra_apks", f"{package}={material / ota_alias}"])
        command.extend(["--extra_apex_payload_key", f"{package}={material / key}"])
    for partition, item in sorted(signing["avb"].items()):
        command.extend(
            [
                f"--avb_{partition}_algorithm",
                item["algorithm"],
                f"--avb_{partition}_key",
                str(material / item["key"]),
            ]
        )
    command.extend([str(unsigned_target), str(signed_target)])
    return command


def ota_command(
    tools: Mapping[str, Path],
    config: Mapping[str, object],
    material: Path,
    signed_target: Path,
    output_ota: Path,
    metadata: Path,
) -> list[str]:
    signing = config["signing"]
    return [
        str(tools["ota_from_target_files"]),
        "--output_metadata_path",
        str(metadata),
        "-k",
        str(material / signing["ota_key_alias"]),
        str(signed_target),
        str(output_ota),
    ]


def redacted_command(command: Sequence[str], runtime: Path | None = None) -> list[str]:
    result: list[str] = []
    for argument in command:
        value = argument
        if runtime is not None:
            value = value.replace(str(runtime), "<transient-signing-boundary>")
        result.append(value)
    return result


class Sanitizer:
    def __init__(self, paths: Sequence[Path], passphrases: Sequence[str]) -> None:
        self.paths = sorted({str(path) for path in paths}, key=len, reverse=True)
        self.passphrases = sorted({item for item in passphrases if item}, key=len, reverse=True)
        self.in_private_key = False

    def line(self, value: str) -> str:
        if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
            self.in_private_key = True
            return "<redacted-private-key-material>\n"
        if self.in_private_key:
            if "-----END " in value and "PRIVATE KEY-----" in value:
                self.in_private_key = False
            return ""
        result = value
        for path in self.paths:
            result = result.replace(path, "<redacted-secret-boundary>")
        for passphrase in self.passphrases:
            result = result.replace(passphrase, "<redacted-passphrase>")
        return SECRET_PATH_RE.sub("<redacted-secret-path>", result)


def run_sanitized(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: int,
    raw_log: Path,
    output_log: Path,
    sanitizer: Sanitizer,
    display_command: Sequence[str],
) -> tuple[int, float]:
    started = time.monotonic()
    with raw_log.open("wb") as raw_handle:
        os.chmod(raw_log, 0o600)
        try:
            completed = subprocess.run(
                list(command),
                cwd=cwd,
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=raw_handle,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
            )
            return_code = completed.returncode
        except subprocess.TimeoutExpired as error:
            return_code = 124
            raw_handle.write(f"\nprocess timed out after {timeout}s: {error}\n".encode("utf-8"))
    written = 0
    with raw_log.open("r", encoding="utf-8", errors="replace") as source, output_log.open(
        "w", encoding="utf-8"
    ) as destination:
        header = "command=" + shlex.join(display_command) + "\n"
        destination.write(header)
        written += len(header.encode("utf-8"))
        for line in source:
            sanitized = sanitizer.line(line)
            encoded = sanitized.encode("utf-8")
            if written + len(encoded) > MAX_SANITIZED_LOG_BYTES:
                destination.write("<sanitized-log-truncated>\n")
                break
            destination.write(sanitized)
            written += len(encoded)
    return return_code, time.monotonic() - started


def cert_digest_from_pem(raw: bytes) -> str:
    try:
        der = ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise ReleaseError("certificate is not PEM encoded") from error
    return sha256_bytes(der)


def require_non_development_certificate(raw: bytes, label: str) -> str:
    digest = cert_digest_from_pem(raw)
    if digest in KNOWN_AOSP_DEVELOPMENT_CERTIFICATE_SHA256:
        raise ReleaseError(f"AOSP development signing certificate is forbidden: {label}")
    return digest


def require_non_development_apk_private_key(raw: bytes, label: str) -> str:
    digest = sha256_bytes(raw)
    if digest in KNOWN_AOSP_DEVELOPMENT_APK_PRIVATE_KEY_SHA256:
        raise ReleaseError(f"AOSP development APK private key is forbidden: {label}")
    return digest


def require_non_development_avb_private_key(raw: bytes, label: str) -> str:
    digest = sha256_bytes(raw)
    if digest in KNOWN_AOSP_DEVELOPMENT_AVB_PRIVATE_KEY_SHA256:
        raise ReleaseError(f"AOSP development AVB private key is forbidden: {label}")
    return digest


def require_non_development_avb_public_key(raw: bytes, label: str) -> str:
    digest = sha256_bytes(raw)
    if digest in KNOWN_AOSP_DEVELOPMENT_AVB_PUBLIC_KEY_SHA256:
        raise ReleaseError(f"AOSP development AVB key is forbidden: {label}")
    return digest


def extract_zip_member(
    archive: zipfile.ZipFile,
    member: str,
    destination: Path,
    maximum: int,
) -> None:
    info = archive.getinfo(member)
    if not 1 <= info.file_size <= maximum:
        raise ReleaseError(f"verification member has invalid size: {member}")
    observed = 0
    with archive.open(info) as source, destination.open("xb") as output:
        os.chmod(destination, 0o600)
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            observed += len(block)
            if observed > maximum:
                raise ReleaseError(f"verification member exceeded bound: {member}")
            output.write(block)
    if observed != info.file_size:
        raise ReleaseError(f"verification member changed size: {member}")


def private_check(command: Sequence[str], cwd: Path, timeout: int, label: str) -> str:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseError(f"{label} could not complete") from error
    if completed.returncode != 0:
        raise ReleaseError(f"{label} failed closed")
    return completed.stdout


def parse_avb_info(raw: str, label: str) -> dict[str, object]:
    patterns = {
        "algorithm": re.compile(r"^Algorithm:\s+(\S+)\s*$", re.MULTILINE),
        "rollback_index": re.compile(r"^Rollback Index:\s+(\d+)\s*$", re.MULTILINE),
        "flags": re.compile(r"^Flags:\s+(\d+)\s*$", re.MULTILINE),
    }
    values: dict[str, object] = {}
    for field, pattern in patterns.items():
        matches = pattern.findall(raw)
        if len(matches) != 1:
            raise ReleaseError(f"AVB info for {label} lacks one exact {field}")
        value: object = matches[0]
        if field != "algorithm":
            value = int(str(value), 10)
        values[field] = value
    return values


def verify_signed_payload_keys(
    signed_target: Path,
    config: Mapping[str, object],
    material: Path,
    tools: Mapping[str, Path],
    runtime: Path,
    expected_container_cert_sha256: str,
) -> dict[str, object]:
    verification = runtime / "signed-payload-verification"
    verification.mkdir(mode=0o700)
    signing = config["signing"]
    apex_results: dict[str, object] = {}
    avb_results: dict[str, object] = {}
    avb_public_paths: dict[str, Path] = {}
    avb_public_digests: dict[str, str] = {}
    for index, (partition, item) in enumerate(sorted(signing["avb"].items())):
        public_key = verification / f"avb-public-{index}.avbpubkey"
        private_check(
            [
                str(tools["avbtool"]),
                "extract_public_key",
                "--key",
                str(material / item["key"]),
                "--output",
                str(public_key),
            ],
            runtime,
            120,
            f"AVB public-key derivation for {partition}",
        )
        public_bytes = strict_regular_bytes(
            public_key,
            f"derived AVB public key for {partition}",
            MAX_AVB_PUBLIC_KEY_BYTES,
        )
        public_digest = require_non_development_avb_public_key(
            public_bytes, f"signed target {partition}"
        )
        avb_public_paths[partition] = public_key
        avb_public_digests[partition] = public_digest
    try:
        with zipfile.ZipFile(signed_target) as archive:
            names = set(archive.namelist())
            for index, (package, key_name) in enumerate(
                sorted(signing["apex_payload_keys"].items())
            ):
                base = package.removesuffix(".apex")
                candidates = sorted(
                    name
                    for name in names
                    if PurePosixPath(name).name in {package, f"{base}.capex"}
                )
                if len(candidates) != 1:
                    raise ReleaseError(
                        f"signed target has ambiguous APEX artifact for {package}"
                    )
                artifact = verification / f"apex-{index}"
                extract_zip_member(
                    archive, candidates[0], artifact, MAX_APEX_MEMBER_BYTES
                )
                try:
                    with zipfile.ZipFile(artifact) as apex_archive:
                        observed_public_key = read_bounded_member(
                            apex_archive, "apex_pubkey"
                        )
                except zipfile.BadZipFile as error:
                    raise ReleaseError(f"signed APEX is not a ZIP: {package}") from error
                expected_public_key = verification / f"apex-{index}.avbpubkey"
                private_check(
                    [
                        str(tools["avbtool"]),
                        "extract_public_key",
                        "--key",
                        str(material / key_name),
                        "--output",
                        str(expected_public_key),
                    ],
                    runtime,
                    120,
                    f"APEX payload key derivation for {package}",
                )
                expected_public_bytes = expected_public_key.read_bytes()
                expected_public_digest = require_non_development_avb_public_key(
                    expected_public_bytes, f"signed APEX payload {package}"
                )
                if observed_public_key != expected_public_bytes:
                    raise ReleaseError(
                        f"signed APEX payload public key mismatch: {package}"
                    )
                signer_output = private_check(
                    [str(tools["apksigner"]), "verify", "--print-certs", str(artifact)],
                    runtime,
                    300,
                    f"APEX container signature verification for {package}",
                )
                certificate = re.search(
                    r"certificate SHA-256 digest:\s*([0-9A-Fa-f:]{64,95})",
                    signer_output,
                )
                observed_certificate = (
                    re.sub(r"[^0-9a-f]", "", certificate.group(1).lower())
                    if certificate
                    else None
                )
                if observed_certificate != expected_container_cert_sha256:
                    raise ReleaseError(
                        f"signed APEX container certificate mismatch: {package}"
                    )
                apex_results[package] = {
                    "artifact_member": candidates[0],
                    "payload_public_key_sha256": expected_public_digest,
                    "container_certificate_sha256": observed_certificate,
                }

            avb_images: dict[str, Path] = {}
            for index, (partition, item) in enumerate(sorted(signing["avb"].items())):
                member = f"IMAGES/{partition}.img"
                if member not in names:
                    raise ReleaseError(f"signed target is missing AVB image {member}")
                image = verification / f"avb-{index}.img"
                extract_zip_member(archive, member, image, MAX_AVB_IMAGE_BYTES)
                avb_images[partition] = image

            for partition, item in sorted(signing["avb"].items()):
                member = f"IMAGES/{partition}.img"
                image = avb_images[partition]
                verify_command = [
                    str(tools["avbtool"]),
                    "verify_image",
                    "--image",
                    str(image),
                    "--key",
                    str(material / item["key"]),
                ]
                if partition == "vbmeta":
                    for chained, chained_item in sorted(signing["avb"].items()):
                        if chained == "vbmeta":
                            continue
                        verify_command.extend(
                            [
                                "--expected_chain_partition",
                                f"{chained}:{chained_item['rollback_index_location']}:"
                                f"{avb_public_paths[chained]}",
                            ]
                        )
                private_check(
                    verify_command,
                    runtime,
                    300,
                    f"AVB image verification for {partition}",
                )
                observed_info = parse_avb_info(
                    private_check(
                        [
                            str(tools["avbtool"]),
                            "info_image",
                            "--image",
                            str(image),
                        ],
                        runtime,
                        120,
                        f"AVB image inspection for {partition}",
                    ),
                    partition,
                )
                if observed_info["algorithm"] != item["algorithm"]:
                    raise ReleaseError(f"signed AVB algorithm mismatch for {partition}")
                if observed_info["flags"] != item["expected_flags"]:
                    raise ReleaseError(f"signed AVB flags mismatch for {partition}")
                if observed_info["rollback_index"] != item["rollback_index"]:
                    raise ReleaseError(f"signed AVB rollback index mismatch for {partition}")
                avb_results[partition] = {
                    "artifact_member": member,
                    "algorithm": item["algorithm"],
                    "expected_flags": item["expected_flags"],
                    "flags": observed_info["flags"],
                    "image_sha256": sha256_file(image),
                    "key_handle": item["key"],
                    "public_key_sha256": avb_public_digests[partition],
                    "rollback_index": observed_info["rollback_index"],
                    "rollback_index_location": item["rollback_index_location"],
                }
    except zipfile.BadZipFile as error:
        raise ReleaseError("signed target is not a valid ZIP during payload verification") from error
    return {
        "apex": apex_results,
        "apex_count": len(apex_results),
        "all_apex_payload_keys_exact": len(apex_results)
        == len(signing["apex_payload_keys"]),
        "all_apex_container_certificates_exact": len(apex_results)
        == len(signing["apex_payload_keys"]),
        "avb": avb_results,
        "avb_partition_count": len(avb_results),
        "all_avb_images_verified": len(avb_results) == len(signing["avb"]),
    }


def verify_signed_ota(
    ota: Path,
    metadata_path: Path,
    expected_device: str,
    expected_build_type: str,
    expected_cert_sha256: str,
) -> dict[str, object]:
    expected_build_type = require_build_type(expected_build_type, "expected OTA build type")
    if not ota.is_file() or ota.is_symlink():
        raise ReleaseError("signed OTA was not produced")
    with zipfile.ZipFile(ota) as archive:
        names = set(archive.namelist())
        required = {"payload.bin", "payload_properties.txt", "META-INF/com/android/otacert"}
        if not required.issubset(names):
            raise ReleaseError(f"signed OTA is missing members: {sorted(required - names)}")
        cert_sha = cert_digest_from_pem(
            read_bounded_member(archive, "META-INF/com/android/otacert")
        )
    if cert_sha != expected_cert_sha256:
        raise ReleaseError("signed OTA certificate does not match configured OTA key")
    metadata = parse_properties(metadata_path.read_text(encoding="utf-8"), "OTA metadata")
    devices = set(metadata.get("pre-device", "").split(","))
    if expected_device not in devices:
        raise ReleaseError("OTA metadata device does not match configured device")
    if metadata.get("ota-type") != "AB":
        raise ReleaseError("OTA is not a full A/B package")
    post_build = metadata.get("post-build")
    if post_build is None or not post_build.endswith(
        f":{expected_build_type}/release-keys"
    ):
        raise ReleaseError("OTA post-build fingerprint is not build-type/release-key bound")
    if metadata.get("ota-wipe") == "yes" or metadata.get("ota-downgrade") == "yes":
        raise ReleaseError("OTA unexpectedly requests wipe or downgrade semantics")
    return {
        "bytes": ota.stat().st_size,
        "sha256": sha256_file(ota),
        "certificate_sha256": cert_sha,
        "ota_type": "AB",
        "pre_device": sorted(devices),
        "post_build": post_build,
        "build_type": expected_build_type,
        "wipe": False,
        "downgrade": False,
    }


def no_secret_evidence(paths: Sequence[Path], forbidden: Sequence[str]) -> None:
    patterns = (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"\[\[\[\s+.+\s+\]\]\]"),
        SECRET_PATH_RE,
    )
    for path in paths:
        if not path.exists():
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        if any(value and value in raw for value in forbidden):
            raise ReleaseError(f"secret leak guard failed for {path.name}")
        if any(pattern.search(raw) for pattern in patterns):
            raise ReleaseError(f"secret-pattern guard failed for {path.name}")


def ensure_output_dir(path: Path, names: Sequence[str]) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    absolute = owned_private_directory(
        absolute, "release output directory", empty=True
    )
    collisions = [name for name in names if (absolute / name).exists() or (absolute / name).is_symlink()]
    if collisions:
        raise ReleaseError(f"refusing to overwrite release outputs: {collisions}")
    return absolute


def public_plan(
    config: Mapping[str, object], input_facts: Mapping[str, object], inventory: Mapping[str, object]
) -> dict[str, object]:
    signing = config["signing"]
    return {
        "device": config["product"]["device"],
        "input_target_files": dict(input_facts),
        "tool_inventory": inventory,
        "apk_key_mappings": dict(sorted(signing["apk_key_mappings"].items())),
        "ota_key_alias": signing["ota_key_alias"],
        "avb_mappings": dict(sorted(signing["avb"].items())),
        "rollback_policy": dict(EXPECTED_ROLLBACK_POLICY),
        "apex_payload_mappings": dict(sorted(signing["apex_payload_keys"].items())),
        "apex_mapping_complete": True,
        "avb_mapping_complete": True,
        "full_ab_ota": True,
        "wipe_user_data": False,
        "incremental_ota": False,
        "device_write_performed": False,
        "public_upload_performed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--android-root", type=Path, required=True)
    parser.add_argument(
        "--tool-root",
        type=Path,
        help="Root containing the configured host-tool paths; defaults to Android root.",
    )
    parser.add_argument(
        "--android-out",
        type=Path,
        help=(
            "Exact Android OUT_DIR. Configured out/... tool paths are resolved "
            "relative to this directory after removing the leading out/."
        ),
    )
    parser.add_argument("--target-files", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--scratch-dir",
        type=Path,
        help="Pre-created empty caller-owned 0700 directory for transient material.",
    )
    parser.add_argument("--artifact-prefix", default="trillionnium-release")
    parser.add_argument("--key-dir", type=Path)
    parser.add_argument("--apex-key-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--require-source-bom-binding",
        action="store_true",
        help=(
            "require and cross-check META/trillionnium-source-bom-binding.json "
            "against --source-bom-binding-bom before signing"
        ),
    )
    parser.add_argument(
        "--source-bom-binding-bom",
        type=Path,
        help=(
            "canonical source BOM bytes used by the strict target-files "
            "binding check (requires --require-source-bom-binding)"
        ),
    )
    parser.add_argument(
        "--validate-key-material",
        action="store_true",
        help="In dry-run mode, validate private handles without staging or signing.",
    )
    parser.add_argument("--sign-timeout", type=int, default=10_800)
    parser.add_argument("--ota-timeout", type=int, default=10_800)
    args = parser.parse_args(argv)

    if not PORTABLE_NAME.fullmatch(args.artifact_prefix):
        raise ReleaseError("artifact prefix is invalid")
    if args.validate_key_material and not args.dry_run:
        raise ReleaseError("--validate-key-material only applies to --dry-run")
    if args.require_source_bom_binding and args.source_bom_binding_bom is None:
        raise ReleaseError(
            "--source-bom-binding-bom is required with "
            "--require-source-bom-binding"
        )
    if not args.require_source_bom_binding and args.source_bom_binding_bom is not None:
        raise ReleaseError(
            "--source-bom-binding-bom requires --require-source-bom-binding"
        )
    if args.tool_root is not None and args.android_out is not None:
        raise ReleaseError("--tool-root and --android-out are mutually exclusive")
    config_value, config_raw = load_json(args.config)
    config = validate_config(config_value)
    android_root = Path(os.path.abspath(os.fspath(args.android_root)))
    if android_root.is_symlink() or not android_root.is_dir():
        raise ReleaseError("Android root must be a real directory")
    configured_tool_root = (
        args.android_out
        if args.android_out is not None
        else args.tool_root if args.tool_root is not None else android_root
    )
    tool_root = Path(os.path.abspath(os.fspath(configured_tool_root)))
    if tool_root.is_symlink() or not tool_root.is_dir():
        raise ReleaseError("tool root must be a real directory")
    target_files = Path(os.path.abspath(os.fspath(args.target_files)))
    target_baseline = measure_file(target_files, "input target-files")
    source_bom_binding: dict[str, object] | None = None
    if args.require_source_bom_binding:
        source_bom_binding = inspect_required_source_bom_binding(
            target_files,
            Path(os.path.abspath(os.fspath(args.source_bom_binding_bom))),
        )
    input_facts = inspect_target_files(
        target_files, config, signed=False, measurement=target_baseline
    )
    build_type = require_build_type(input_facts["build_type"], "input build type")
    boundaries = release_boundaries(build_type)
    assert_measurement(target_files, target_baseline, "input target-files")
    strip_android_out_prefix = args.android_out is not None
    inventory = tool_inventory(
        tool_root,
        config,
        strip_android_out_prefix=strip_android_out_prefix,
    )
    tool_paths = {
        name: resolve_tool(
            tool_root,
            str(relative),
            strip_android_out_prefix=strip_android_out_prefix,
        )
        for name, relative in config["tools"].items()
    }
    tool_baselines = {
        name: measure_file(path, f"Android host tool {name}")
        for name, path in tool_paths.items()
    }
    for name, baseline in tool_baselines.items():
        if baseline["sha256"] != inventory[name]["sha256"]:
            raise ReleaseError(f"Android host tool {name} changed during preflight")
    plan = public_plan(config, input_facts, inventory)
    plan["config_sha256"] = sha256_bytes(config_raw)
    if source_bom_binding is not None:
        plan["source_bom_binding"] = source_bom_binding

    key_dir = args.key_dir
    if key_dir is None and os.environ.get("TRILLIONNIUM_RELEASE_KEY_DIR"):
        key_dir = Path(os.environ["TRILLIONNIUM_RELEASE_KEY_DIR"])
    apex_key_dir = args.apex_key_dir
    if apex_key_dir is None and os.environ.get("TRILLIONNIUM_RELEASE_APEX_KEY_DIR"):
        apex_key_dir = Path(os.environ["TRILLIONNIUM_RELEASE_APEX_KEY_DIR"])
    if key_dir is not None:
        key_dir = Path(os.path.abspath(os.fspath(key_dir)))
    if apex_key_dir is not None:
        apex_key_dir = Path(os.path.abspath(os.fspath(apex_key_dir)))
    scratch_root: Path | None = None
    if args.scratch_dir is not None:
        scratch_root = owned_private_directory(
            Path(os.path.abspath(os.fspath(args.scratch_dir))),
            "release scratch directory",
            empty=True,
        )

    if args.dry_run:
        material_public: dict[str, object] | None = None
        decision = dry_run_decision(build_type, False)
        if args.validate_key_material:
            if key_dir is None or apex_key_dir is None:
                raise ReleaseError("private key directories are required for material validation")
            if scratch_root is None:
                raise ReleaseError(
                    "--scratch-dir is required for private material validation"
                )
            material = validate_material(
                config,
                key_dir,
                apex_key_dir,
                avbtool=tool_paths["avbtool"],
                scratch_root=scratch_root,
            )
            material_public = {
                "key_handles": material["key_handles"],
                "apex_key_handles": material["apex_key_handles"],
                "apk_certificate_sha256": material["apk_certificate_sha256"],
                "avb_public_key_sha256": material["avb_public_key_sha256"],
                "apex_public_key_sha256": material["apex_public_key_sha256"],
                "ota_certificate_sha256": material["ota_certificate_sha256"],
            }
            decision = dry_run_decision(build_type, True)
        assert_measurement(target_files, target_baseline, "input target-files")
        for name, path in tool_paths.items():
            assert_measurement(path, tool_baselines[name], f"Android host tool {name}")
        result = {
            "schema": RECEIPT_SCHEMA,
            "decision": decision,
            "build_type": build_type,
            "dry_run": True,
            "private_material_read": args.validate_key_material,
            "material": material_public,
            "plan": plan,
            "release_boundaries": boundaries,
            "signing_performed": False,
            "ota_generated": False,
            "device_write_performed": False,
            "public_upload_performed": False,
            "public_release_authorized": False,
        }
        validate_receipt(result)
        print(canonical_json_bytes(result).decode("utf-8"), end="")
        return 0

    if args.output_dir is None:
        raise ReleaseError("--output-dir is required outside dry-run mode")
    if key_dir is None or apex_key_dir is None:
        raise ReleaseError("private key directories are required for signing")
    if scratch_root is None:
        raise ReleaseError("--scratch-dir is required outside dry-run mode")

    filenames = {
        "signed_target": f"{args.artifact_prefix}-signed-target_files.zip",
        "ota": f"{args.artifact_prefix}-full-ota.zip",
        "metadata": f"{args.artifact_prefix}-ota-metadata.txt",
        "receipt": f"{args.artifact_prefix}-signing-receipt.json",
        "sign_log": f"{args.artifact_prefix}-sign-target-files.sanitized.log",
        "ota_log": f"{args.artifact_prefix}-ota.sanitized.log",
        "verify_log": f"{args.artifact_prefix}-ota-signature-check.sanitized.log",
    }
    working_names = {
        name: f"{filename}.partial"
        for name, filename in filenames.items()
        if name in {"signed_target", "ota", "metadata"}
    }
    output = ensure_output_dir(
        args.output_dir, [*filenames.values(), *working_names.values()]
    )
    paths = {name: output / filename for name, filename in filenames.items()}
    working = {name: output / filename for name, filename in working_names.items()}
    error: str | None = None
    sign_rc = ota_rc = verify_rc = 99
    sign_seconds = ota_seconds = verify_seconds = 0.0
    signed_facts: dict[str, object] | None = None
    signed_crypto_facts: dict[str, object] | None = None
    ota_facts: dict[str, object] | None = None
    material_public: dict[str, object] | None = None
    passphrases: list[str] = []
    source_secret_paths = [key_dir, apex_key_dir]

    resolved_tools = tool_paths
    try:
        with staged_material(
            config,
            key_dir,
            apex_key_dir,
            avbtool=resolved_tools["avbtool"],
            scratch_root=scratch_root,
        ) as staged:
            runtime = staged["runtime"]
            material_path = staged["material"]
            password_file = staged["password_file"]
            passphrases = list(staged["passphrases"])
            cert_sha = str(staged["ota_certificate_sha256"])
            material_public = {
                "key_handles": sorted(required_material(config)["apk"]),
                "apex_key_handles": sorted(required_material(config)["apex"]),
                "apk_certificate_sha256": staged["apk_certificate_sha256"],
                "avb_public_key_sha256": staged["avb_public_key_sha256"],
                "apex_public_key_sha256": staged["apex_public_key_sha256"],
                "ota_certificate_sha256": cert_sha,
            }
            sanitizer = Sanitizer(
                [*source_secret_paths, runtime, material_path, password_file], passphrases
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "ANDROID_PW_FILE": str(password_file),
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "PYTHONHASHSEED": "0",
                    "TMPDIR": str(runtime),
                    "TMP": str(runtime),
                    "TEMP": str(runtime),
                }
            )
            sign = signing_command(
                resolved_tools, config, material_path, target_files, working["signed_target"]
            )
            assert_measurement(target_files, target_baseline, "input target-files")
            assert_measurement(
                resolved_tools["sign_target_files_apks"],
                tool_baselines["sign_target_files_apks"],
                "Android host tool sign_target_files_apks",
            )
            sign_rc, sign_seconds = run_sanitized(
                sign,
                cwd=android_root,
                env=environment,
                timeout=args.sign_timeout,
                raw_log=runtime / "sign.raw.log",
                output_log=paths["sign_log"],
                sanitizer=sanitizer,
                display_command=redacted_command(sign, runtime),
            )
            assert_measurement(target_files, target_baseline, "input target-files")
            assert_measurement(
                resolved_tools["sign_target_files_apks"],
                tool_baselines["sign_target_files_apks"],
                "Android host tool sign_target_files_apks",
            )
            if sign_rc != 0:
                raise ReleaseError(f"sign_target_files_apks failed rc={sign_rc}")
            signed_facts = inspect_target_files(working["signed_target"], config, signed=True)
            if signed_facts["build_type"] != build_type:
                raise ReleaseError("signed target-files changed the input build type")
            for tool_name in ("avbtool", "apksigner"):
                assert_measurement(
                    resolved_tools[tool_name],
                    tool_baselines[tool_name],
                    f"Android host tool {tool_name}",
                )
            signed_crypto_facts = verify_signed_payload_keys(
                working["signed_target"],
                config,
                material_path,
                resolved_tools,
                runtime,
                cert_sha,
            )
            for tool_name in ("avbtool", "apksigner"):
                assert_measurement(
                    resolved_tools[tool_name],
                    tool_baselines[tool_name],
                    f"Android host tool {tool_name}",
                )

            ota = ota_command(
                resolved_tools,
                config,
                material_path,
                working["signed_target"],
                working["ota"],
                working["metadata"],
            )
            assert_measurement(target_files, target_baseline, "input target-files")
            assert_measurement(
                resolved_tools["ota_from_target_files"],
                tool_baselines["ota_from_target_files"],
                "Android host tool ota_from_target_files",
            )
            ota_rc, ota_seconds = run_sanitized(
                ota,
                cwd=android_root,
                env=environment,
                timeout=args.ota_timeout,
                raw_log=runtime / "ota.raw.log",
                output_log=paths["ota_log"],
                sanitizer=sanitizer,
                display_command=redacted_command(ota, runtime),
            )
            assert_measurement(target_files, target_baseline, "input target-files")
            assert_measurement(
                resolved_tools["ota_from_target_files"],
                tool_baselines["ota_from_target_files"],
                "Android host tool ota_from_target_files",
            )
            if ota_rc != 0 or not working["metadata"].is_file():
                raise ReleaseError(f"ota_from_target_files failed rc={ota_rc}")
            ota_facts = verify_signed_ota(
                working["ota"],
                working["metadata"],
                config["product"]["device"],
                build_type,
                cert_sha,
            )
            if ota_facts["post_build"] != signed_facts["fingerprint"]:
                raise ReleaseError(
                    "OTA post-build fingerprint differs from signed target-files"
                )
            verify = [
                str(resolved_tools["check_ota_package_signature"]),
                str(material_path / f"{config['signing']['ota_key_alias']}.x509.pem"),
                str(working["ota"]),
            ]
            assert_measurement(
                resolved_tools["check_ota_package_signature"],
                tool_baselines["check_ota_package_signature"],
                "Android host tool check_ota_package_signature",
            )
            verify_rc, verify_seconds = run_sanitized(
                verify,
                cwd=android_root,
                env=environment,
                timeout=1800,
                raw_log=runtime / "verify.raw.log",
                output_log=paths["verify_log"],
                sanitizer=sanitizer,
                display_command=redacted_command(verify, runtime),
            )
            assert_measurement(target_files, target_baseline, "input target-files")
            assert_measurement(
                resolved_tools["check_ota_package_signature"],
                tool_baselines["check_ota_package_signature"],
                "Android host tool check_ota_package_signature",
            )
            if verify_rc != 0:
                raise ReleaseError(f"OTA package signature verification failed rc={verify_rc}")
        for name, path in resolved_tools.items():
            assert_measurement(path, tool_baselines[name], f"Android host tool {name}")
        assert_measurement(target_files, target_baseline, "input target-files")
        promoted: list[str] = []
        try:
            for name in ("signed_target", "ota", "metadata"):
                os.replace(working[name], paths[name])
                promoted.append(name)
        except OSError as publish_error:
            for name in reversed(promoted):
                if paths[name].exists() and not working[name].exists():
                    os.replace(paths[name], working[name])
            raise ReleaseError("failed to publish the verified release output set") from publish_error
    except Exception as exception:  # fail closed and emit a public-only receipt
        sanitizer = Sanitizer(source_secret_paths, passphrases)
        error = sanitizer.line(str(exception)).strip()

    partial_outputs = []
    for name, path in sorted(working.items()):
        if path.is_file() and not path.is_symlink():
            partial_size = path.stat().st_size
            partial_outputs.append(
                {
                    "kind": name,
                    "path": path.name,
                    "bytes": partial_size,
                    "sha256": (
                        sha256_file(path)
                        if partial_size > 0
                        else hashlib.sha256(b"").hexdigest()
                    ),
                    "quarantined": True,
                }
            )
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "decision": execution_decision(build_type, error),
        "build_type": build_type,
        "dry_run": False,
        "config_sha256": sha256_bytes(config_raw),
        "plan": plan,
        "release_boundaries": boundaries,
        "material": material_public,
        "signed_target_files": signed_facts,
        "signed_target_cryptography": signed_crypto_facts,
        "signed_full_ab_ota": ota_facts,
        "quarantined_partial_outputs": partial_outputs,
        "commands": {
            "sign_target_files_apks": {"rc": sign_rc, "seconds": round(sign_seconds, 3)},
            "ota_from_target_files": {"rc": ota_rc, "seconds": round(ota_seconds, 3)},
            "check_ota_package_signature": {"rc": verify_rc, "seconds": round(verify_seconds, 3)},
        },
        "secret_source_paths_recorded": False,
        "private_key_contents_recorded": False,
        "plaintext_passphrases_recorded": False,
        "transient_password_file_retained": False,
        "transient_material_retained": False,
        "device_write_performed": False,
        "public_upload_performed": False,
        "public_release_authorized": False,
        "error": error,
    }
    validate_receipt(receipt)
    paths["receipt"].write_bytes(canonical_json_bytes(receipt))
    evidence = [paths["receipt"], paths["sign_log"], paths["ota_log"], paths["verify_log"]]
    no_secret_evidence(evidence, [*passphrases, *(str(path) for path in source_secret_paths)])
    print(
        canonical_json_bytes(
            {
                "decision": receipt["decision"],
                "build_type": build_type,
                "receipt": str(paths["receipt"]),
                "release_boundaries": boundaries,
                "device_write_performed": False,
                "public_release_authorized": False,
            }
        ).decode("utf-8"),
        end="",
    )
    return 0 if error is None else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"error: {error}") from None
