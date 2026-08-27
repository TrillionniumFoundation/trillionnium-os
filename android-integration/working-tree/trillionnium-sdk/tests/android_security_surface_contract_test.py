#!/usr/bin/env python3
"""Host contract test for the read-only Android security-surface guard."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REQUIRED_HOLD_REASONS = {
    "accessibility_live_service_binding_unverified",
    "keymint_live_hardware_attestation_unavailable",
    "rollback_os_owned_monotonic_producer_unavailable",
}

COPIED_INPUTS = (
    "hardware/interfaces/security/keymint/aidl/default/android.hardware.security.keymint-service.xml",
    "hardware/interfaces/security/keymint/aidl/default/Android.bp",
    "hardware/interfaces/security/keymint/aidl/default/service.cpp",
    "device/motorola/fogos/manifest.xml",
    "device/motorola/fogos/BoardConfig.mk",
    "device/motorola/fogos/proprietary-firmware.txt",
    "vendor/trillionnium/config/common.mk",
    "trillionnium-sdk/Android.bp",
    "trillionnium-sdk/tools/verify_android_security_surfaces.py",
    "trillionnium-sdk/packages/TrillionniumAgentAccessibility/Android.bp",
    "trillionnium-sdk/packages/TrillionniumAgentAccessibility/AndroidManifest.xml",
    "trillionnium-sdk/packages/TrillionniumAgentAccessibility/res/xml/agent_accessibility_service.xml",
    "trillionnium-sdk/packages/TrillionniumAgentAccessibility/src/org/trillionnium/agentaccessibility/AgentAccessibilityService.java",
    "trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseRollbackEpochStateProof.java",
    "trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseBrokerProductEnrollment.java",
    "trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseRuntimeFactory.java",
    "trillionnium-sdk/contracts/android-security-surface-v1.json",
)


def source_root() -> Path:
    configured = os.environ.get("ANDROID_BUILD_TOP")
    if configured:
        return Path(configured).resolve()
    # Direct source invocation only; no recursive discovery is permitted.
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "trillionnium-sdk/Android.bp").is_file():
            return candidate
    raise AssertionError("ANDROID_BUILD_TOP is required for a staged host test")


def run_guard(root: Path, require_ready: bool = False) -> tuple[int, dict]:
    tool = root / "trillionnium-sdk/tools/verify_android_security_surfaces.py"
    contract = root / "trillionnium-sdk/contracts/android-security-surface-v1.json"
    command = [
        sys.executable,
        str(tool),
        "--android-root",
        str(root),
        "--contract",
        str(contract),
        "--json",
    ]
    if require_ready:
        command.append("--require-ready")
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"guard did not emit JSON: rc={completed.returncode} "
            f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
        ) from error
    return completed.returncode, payload


def copy_inputs(source: Path, destination: Path) -> None:
    for relative in COPIED_INPUTS:
        source_path = source / relative
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination_path)


def main() -> None:
    root = source_root()
    rc, payload = run_guard(root)
    assert rc == 0, payload
    assert payload["result"] == "HOLD", payload
    assert payload["surfaces"]["keymint"]["source_contract"] == "PASS", payload
    assert payload["surfaces"]["rollback"]["proof_source"] == "PASS", payload
    assert payload["surfaces"]["accessibility"]["product_owner"] == "PASS", payload
    assert REQUIRED_HOLD_REASONS <= set(payload["hold_reasons"]), payload

    ready_rc, ready_payload = run_guard(root, require_ready=True)
    assert ready_rc == 2, ready_payload
    assert ready_payload["result"] == "HOLD", ready_payload

    # A source-only mutation of the authorization gate must fail the audit; it
    # must never silently turn into a READY result.
    with tempfile.TemporaryDirectory(prefix="trillionnium-security-surface-") as raw:
        mutated = Path(raw)
        copy_inputs(root, mutated)
        service = mutated / (
            "trillionnium-sdk/packages/TrillionniumAgentAccessibility/src/org/trillionnium/"
            "agentaccessibility/AgentAccessibilityService.java"
        )
        service.write_text(
            service.read_text(encoding="utf-8").replace(
                "activateIfAuthorized", "authorizeNow"
            ),
            encoding="utf-8",
        )
        drift_rc, drift_payload = run_guard(mutated)
        assert drift_rc == 1, drift_payload
        assert drift_payload["result"] == "FAIL", drift_payload

    print("PASS: Android security surfaces audit HOLD and source drift fails closed")


if __name__ == "__main__":
    main()
