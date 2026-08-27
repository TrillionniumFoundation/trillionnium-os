#!/usr/bin/env python3
"""Audit the Android KeyMint, rollback, and Accessibility source surfaces.

This is deliberately a host/source guard.  It never talks to adb, opens a device
node, reads a key/certificate artifact, or changes a product/runtime state.  A
source tree can prove that the contracts are wired together, but it cannot prove
that a particular handset has a hardware-backed KeyMint instance, an OS-owned
monotonic rollback producer, or a live Accessibility grant.  Those conditions
therefore remain ``HOLD`` until an independently attested producer supplies the
missing evidence.

The default exit status is zero for a structurally valid audit, even when the
result is HOLD.  ``--require-ready`` turns a HOLD into exit status 2 for callers
that want an activation gate.  Unexpected source drift or malformed contracts
return exit status 1.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


MAX_SOURCE_BYTES = 2 * 1024 * 1024
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


class AuditError(Exception):
    """An unexpected source/contract error which must fail the guard."""


def _read_fixed(path: Path) -> str:
    """Read one known source file without following a symlink."""

    if not path.is_absolute():
        raise AuditError(f"non-absolute source path: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise AuditError(f"missing or unreadable source {path}: {error}") from error
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_SOURCE_BYTES
        ):
            raise AuditError(f"source outside regular-file boundary: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(fd)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_before != stable_after:
            raise AuditError(f"source changed while inspected: {path}")
        if len(value) != before.st_size or len(value) > MAX_SOURCE_BYTES:
            raise AuditError(f"source size drifted while inspected: {path}")
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AuditError(f"source is not UTF-8: {path}") from error
    finally:
        os.close(fd)


def _resolve_root(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    configured = os.environ.get("ANDROID_BUILD_TOP")
    if configured:
        candidates.append(Path(configured))
    # Direct source invocation has a stable, shallow layout:
    # <android-root>/trillionnium-sdk/tools/<this-file>.
    candidates.extend(Path(__file__).resolve().parents)
    for candidate in candidates:
        root = candidate.resolve()
        if (root / "trillionnium-sdk/Android.bp").is_file() and (
            root / "hardware/interfaces/security/keymint/aidl/default/Android.bp"
        ).is_file():
            return root
    shown = ", ".join(str(path) for path in candidates[:5])
    raise AuditError(f"Android source root not found (checked {shown})")


def _load_contract(root: Path, explicit: str | None) -> dict[str, Any]:
    path = Path(explicit) if explicit else root / (
        "trillionnium-sdk/contracts/android-security-surface-v1.json"
    )
    try:
        value = json.loads(_read_fixed(path))
    except json.JSONDecodeError as error:
        raise AuditError(f"invalid security-surface contract JSON: {path}") from error
    if not isinstance(value, dict):
        raise AuditError("security-surface contract must be an object")
    required = {
        "contract_schema",
        "activation_policy",
        "keymint",
        "rollback",
        "accessibility",
        "forbidden_runtime_actions",
    }
    if set(value) != required:
        raise AuditError("security-surface contract has an unexpected schema")
    if value["contract_schema"] != "org.trillionnium.android-security-surface.contract.v1":
        raise AuditError("security-surface contract schema drifted")
    if value["activation_policy"] != "fail_closed":
        raise AuditError("security-surface activation policy must be fail_closed")
    if value["forbidden_runtime_actions"] != [
        "adb",
        "flash",
        "fastboot",
        "install",
        "reboot",
        "sideload",
        "wipe",
    ]:
        raise AuditError("forbidden runtime action list drifted")
    for section in ("keymint", "rollback", "accessibility"):
        if not isinstance(value[section], dict):
            raise AuditError(f"security-surface section is not an object: {section}")
    return value


def _contains(source: str, *needles: str) -> bool:
    return all(needle in source for needle in needles)


def _module_block(source: str, kind: str, name: str) -> str:
    """Return one shallow Blueprint module without scanning unrelated files."""

    pattern = re.compile(rf"(?m)^{re.escape(kind)}\s*\{{")
    for match in pattern.finditer(source):
        depth = 0
        in_string = False
        escaped = False
        for index in range(match.end() - 1, len(source)):
            char = source[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    block = source[match.start() : index + 1]
                    if re.search(
                        rf"(?m)^\s*name:\s*\"{re.escape(name)}\",\s*$", block
                    ):
                        return block
                    break
    raise AuditError(f"missing Blueprint module {kind} {name}")


def _result_template(root: Path) -> dict[str, Any]:
    return {
        "schema": "org.trillionnium.android-security-surface.result.v1",
        "android_root": str(root),
        "result": "FAIL",
        "surfaces": {},
        "hold_reasons": [],
        "errors": [],
    }


def audit(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    """Audit only the fixed source paths named below."""

    result = _result_template(root)
    sdk = root / "trillionnium-sdk"
    keymint_default = root / "hardware/interfaces/security/keymint/aidl/default"
    fogos = root / "device/motorola/fogos"
    common = root / "vendor/trillionnium/config/common.mk"

    # Deliberately no key blobs, certificates, private keys, target files, or
    # output artifacts are read here.
    files = {
        "keymint_xml": keymint_default / "android.hardware.security.keymint-service.xml",
        "keymint_bp": keymint_default / "Android.bp",
        "keymint_cpp": keymint_default / "service.cpp",
        "device_manifest": fogos / "manifest.xml",
        "device_board": fogos / "BoardConfig.mk",
        "proprietary_firmware_index": fogos / "proprietary-firmware.txt",
        "common": common,
        "sdk_bp": sdk / "Android.bp",
        "access_manifest": sdk / "packages/TrillionniumAgentAccessibility/AndroidManifest.xml",
        "access_bp": sdk / "packages/TrillionniumAgentAccessibility/Android.bp",
        "access_config": sdk / (
            "packages/TrillionniumAgentAccessibility/res/xml/agent_accessibility_service.xml"
        ),
        "access_service": sdk / (
            "packages/TrillionniumAgentAccessibility/src/org/trillionnium/"
            "agentaccessibility/AgentAccessibilityService.java"
        ),
        "rollback_proof": sdk / (
            "trillionnium/lib/main/java/org/trillionnium/platform/internal/"
            "CapabilityLeaseRollbackEpochStateProof.java"
        ),
        "enrollment": sdk / (
            "trillionnium/lib/main/java/org/trillionnium/platform/internal/"
            "CapabilityLeaseBrokerProductEnrollment.java"
        ),
        "runtime_factory": sdk / (
            "trillionnium/lib/main/java/org/trillionnium/platform/internal/"
            "CapabilityLeaseRuntimeFactory.java"
        ),
    }
    text = {name: _read_fixed(path) for name, path in files.items()}

    keymint_contract = contract["keymint"]
    if not _contains(
        text["keymint_xml"],
        f"<name>{keymint_contract['hal_name']}</name>",
        f"<version>{keymint_contract['minimum_aidl_version']}</version>",
        f"<fqname>{keymint_contract['service_instance']}</fqname>",
    ):
        raise AuditError("KeyMint default VINTF fragment is missing the required AIDL service")
    keymint_module = _module_block(
        text["keymint_bp"], "cc_binary", "android.hardware.security.keymint-service"
    )
    if not _contains(
        keymint_module,
        'relative_install_path: "hw"',
        "vendor: true",
        "android.hardware.security.keymint-service.xml",
    ):
        raise AuditError("KeyMint default service Blueprint ownership drifted")
    if not _contains(text["keymint_cpp"], "AndroidKeyMintDevice", "addService", "SecurityLevel"):
        raise AuditError("KeyMint default service source lacks its registration boundary")
    software_default = "SecurityLevel::SOFTWARE" in text["keymint_cpp"]
    device_manifest_has_keymint = (
        f"<name>{keymint_contract['hal_name']}</name>" in text["device_manifest"]
    )
    avb_index_present = bool(
        re.search(r"(?m)^BOARD_AVB_ROLLBACK_INDEX\s*:=\s*[1-9][0-9]*\s*$", text["device_board"])
    )
    firmware_mentions_keymaster = "keymaster.mbn:keymaster.img;AB" in text[
        "proprietary_firmware_index"
    ]
    result["surfaces"]["keymint"] = {
        "source_contract": "PASS",
        "default_security_level": "SOFTWARE" if software_default else "UNKNOWN",
        "device_manifest_owner": "PASS" if device_manifest_has_keymint else "HOLD",
        "avb_rollback_index_present": avb_index_present,
        "proprietary_keymaster_firmware_indexed": firmware_mentions_keymaster,
        "hardware_attestation_evidence": "MISSING",
    }
    if software_default:
        result["hold_reasons"].append("keymint_default_is_software_not_hardware_backed")
    if not device_manifest_has_keymint:
        result["hold_reasons"].append("keymint_device_manifest_owner_missing")
    if firmware_mentions_keymaster:
        result["hold_reasons"].append("proprietary_keymaster_firmware_is_not_attestation_evidence")
    result["hold_reasons"].append("keymint_live_hardware_attestation_unavailable")

    rollback_contract = contract["rollback"]
    proof = text["rollback_proof"]
    if not _contains(
        proof,
        f'STATUS = "{rollback_contract["proof_status"]}"',
        "No producer exists yet",
        "private VerifiedState(",
    ):
        raise AuditError("rollback proof source no longer advertises its unavailable producer")
    if not _contains(
        text["enrollment"],
        "CapabilityLeaseRollbackEpochStateProof.STATUS",
        "throw new SecurityException",
    ):
        raise AuditError("enrollment must fail closed while rollback proof is unavailable")
    if not _contains(
        text["runtime_factory"],
        "rollbackEpochProof == null",
        "capability_lease_rollback_epoch_proof_unavailable",
    ):
        raise AuditError("runtime factory rollback gate drifted")
    result["surfaces"]["rollback"] = {
        "proof_source": "PASS",
        "os_owned_monotonic_producer": "MISSING",
        "avb_index_present_but_not_enrollment_proof": avb_index_present,
    }
    result["hold_reasons"].append("rollback_os_owned_monotonic_producer_unavailable")
    result["hold_reasons"].append("rollback_live_counter_attestation_unavailable")

    accessibility_contract = contract["accessibility"]
    access_module = _module_block(
        text["access_bp"], "android_app", accessibility_contract["module"]
    )
    if not _contains(access_module, "system_ext_specific: true"):
        raise AuditError("Accessibility APK must remain system_ext-specific")
    if not _contains(
        text["access_manifest"],
        f'package="{accessibility_contract["package"]}"',
        f'android:name="{accessibility_contract["service"]}"',
        f'android:permission="{accessibility_contract["bind_permission"]}"',
        'android:exported="true"',
        "android.accessibilityservice.AccessibilityService",
    ):
        raise AuditError("Accessibility service manifest contract drifted")
    if 'android:isAccessibilityTool="true"' not in text["access_config"]:
        raise AuditError("Accessibility service must declare isAccessibilityTool")
    if not _contains(
        text["access_service"],
        "activateIfAuthorized",
        "isSystemUserExplicitlyAuthorized",
        "UserHandle.USER_SYSTEM",
        "new ComponentName(this, AgentAccessibilityService.class)",
        "authorizationUsableOrStop",
        "dispatchGesture",
    ):
        raise AuditError("Accessibility service authorization/dispatch guard drifted")
    owner_count = len(re.findall(r"\bTrillionniumAgentAccessibility\b", text["sdk_bp"]))
    common_count = len(re.findall(r"\bTrillionniumAgentAccessibility\b", text["common"]))
    platform_block = _module_block(
        text["sdk_bp"], "java_library", "org.trillionnium.platform"
    )
    if common_count != 1 or '"TrillionniumAgentAccessibility"' in platform_block:
        raise AuditError("Accessibility product ownership is ambiguous or cross-partition")
    result["surfaces"]["accessibility"] = {
        "source_contract": "PASS",
        "product_owner": "PASS",
        "live_service_binding": "MISSING",
        "explicit_user_authorization_gate": "PASS",
        "module_reference_count_in_sdk_blueprint": owner_count,
        "product_owner_reference_count": common_count,
    }
    result["hold_reasons"].append("accessibility_live_service_binding_unverified")

    # A HOLD is the expected, safe result until the missing external evidence is
    # supplied by an independent device attestation/ownership process.
    result["hold_reasons"] = sorted(set(result["hold_reasons"]))
    result["result"] = "HOLD" if result["hold_reasons"] else "READY"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--android-root", help="Android source root")
    parser.add_argument("--contract", help="security-surface contract JSON")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="return 2 unless every external evidence gate is ready",
    )
    args = parser.parse_args(argv)
    try:
        root = _resolve_root(args.android_root)
        contract = _load_contract(root, args.contract)
        result = audit(root, contract)
    except AuditError as error:
        payload = {
            "schema": "org.trillionnium.android-security-surface.result.v1",
            "result": "FAIL",
            "errors": [str(error)],
        }
        if args.as_json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print("RESULT=FAIL")
            print(f"ERROR={error}")
        return 1

    if args.as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"RESULT={result['result']}")
        for name, surface in result["surfaces"].items():
            print(f"{name.upper()}={surface}")
        for reason in result["hold_reasons"]:
            print(f"HOLD_REASON={reason}")
    if args.require_ready and result["result"] != "READY":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
