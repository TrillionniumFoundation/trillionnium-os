#!/usr/bin/env python3
"""Collect a bounded, read-only Android device smoke receipt.

This helper is deliberately not an installer or a test driver.  The command
vocabulary is fixed in source and every invocation is made as ``adb -s
<allowlisted-serial> ...``.  No push, install, root, reboot, fastboot,
property-write, activity launch, or service-control operation is implemented.
The resulting receipt is evidence of package integrity plus device
connectivity/environment only; it is not evidence that newly built Android
code was installed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Iterable


SCHEMA = "org.trillionnium.android-ci.device-smoke.v1"
SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_CAPTURE_BYTES = 16 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
DEFAULT_PACKAGES = (
    "org.trillionnium.aishell",
    "org.trillionnium.capabilitylease",
)

# Keep this list reviewable.  Adding a command here is a source change that
# must remain read-only and must not turn this receipt into an installation or
# release claim.
READ_ONLY_COMMANDS = (
    "version",
    "get-state",
    "shell getprop <key>",
    "shell getenforce",
    "shell id -u",
    "shell pm path <package>",
)
PROPERTY_KEYS = (
    "ro.product.device",
    "ro.build.type",
    "ro.build.version.sdk",
    "ro.build.fingerprint",
    "ro.boot.slot_suffix",
    "ro.boot.verifiedbootstate",
)


class SmokeError(RuntimeError):
    """Raised when a required read-only precondition is invalid."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _validate_digest(value: str | None, pattern: re.Pattern[str], label: str) -> str | None:
    if value is None:
        return None
    if pattern.fullmatch(value) is None:
        raise SmokeError(f"{label} must be lowercase hexadecimal")
    if value == "0" * len(value):
        raise SmokeError(f"{label} must not be all zeroes")
    return value


def _validate_serial(serial: str) -> str:
    if SERIAL_RE.fullmatch(serial) is None:
        raise SmokeError("device serial contains unsupported characters or length")
    return serial


def _validate_package(package: str) -> str:
    if PACKAGE_RE.fullmatch(package) is None:
        raise SmokeError(f"invalid Android package name: {package!r}")
    return package


def _adb_path(path: Path) -> Path:
    candidate = str(path)
    if "/" not in candidate:
        located = shutil.which(candidate)
        if located is None:
            raise SmokeError(f"ADB executable is not on PATH: {candidate}")
        path = Path(located)
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise SmokeError(f"ADB executable is unavailable: {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise SmokeError(f"ADB path is not an executable regular file: {path}")
    return resolved


def _capture(value: str) -> str:
    value = value.replace("\x00", "\\0")
    if len(value.encode("utf-8", errors="replace")) <= MAX_CAPTURE_BYTES:
        return value
    encoded = value.encode("utf-8", errors="replace")[:MAX_CAPTURE_BYTES]
    return encoded.decode("utf-8", errors="replace") + "…[truncated]"


def _run_adb(adb: Path, serial: str | None, arguments: list[str], timeout: float) -> dict[str, Any]:
    command = [str(adb)]
    if serial is not None:
        command.extend(["-s", serial])
    command.extend(arguments)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
    except OSError as error:
        return {
            "argv": command,
            "returncode": None,
            "stdout": "",
            "stderr": _capture(str(error)),
            "timed_out": False,
            "spawn_error": True,
            "seconds": round(time.monotonic() - started, 3),
        }
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # ``adb`` can leave a child transport helper behind.  It is started in
        # its own process group so a timeout cannot leak a command into the
        # next device job.
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        stdout, stderr = process.communicate()
        return {
            "argv": command,
            "returncode": None,
            "stdout": _capture(stdout or ""),
            "stderr": _capture(stderr or ""),
            "timed_out": True,
            "seconds": round(time.monotonic() - started, 3),
        }
    return {
        "argv": command,
        "returncode": process.returncode,
        "stdout": _capture(stdout),
        "stderr": _capture(stderr),
        "timed_out": False,
        "seconds": round(time.monotonic() - started, 3),
    }


def _successful(observation: dict[str, Any]) -> bool:
    return observation.get("returncode") == 0 and not observation.get("timed_out")


def _write_exclusive(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise SmokeError(f"refusing to overwrite receipt: {path}")
    parent = path.parent
    if parent.exists() or parent.is_symlink():
        if parent.is_symlink() or not parent.is_dir():
            raise SmokeError(f"receipt parent is not a real directory: {parent}")
    else:
        raise SmokeError(f"receipt parent does not exist: {parent}")
    if len(data) > MAX_RECEIPT_BYTES:
        raise SmokeError("receipt exceeds size ceiling")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise SmokeError(f"cannot write receipt {path}: {error}") from error


def _package_observations(
    adb: Path,
    serial: str,
    packages: tuple[str, ...],
    timeout: float,
    observations: list[dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    package_results: dict[str, dict[str, Any]] = {}
    passed = True
    for package in packages:
        observation = _run_adb(adb, serial, ["shell", "pm", "path", package], timeout)
        observation["operation"] = "package_path"
        observation["package"] = package
        observations.append(observation)
        present = _successful(observation) and any(
            line.startswith("package:") for line in observation["stdout"].splitlines()
        )
        package_results[package] = {"present": present, "observation_index": len(observations) - 1}
        passed = passed and present
    return package_results, passed


def _collect(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    serial = _validate_serial(args.serial)
    adb = _adb_path(Path(args.adb))
    source_commit = _validate_digest(args.source_commit, SHA1_RE, "source_commit")
    source_tree = _validate_digest(args.source_tree, SHA1_RE, "source_tree")
    package_digest = _validate_digest(
        args.source_package_sha256, SHA256_RE, "source_package_sha256"
    )
    repository = args.repository
    if repository is not None:
        if REPOSITORY_RE.fullmatch(repository) is None:
            raise SmokeError("repository must be OWNER/REPOSITORY")
    packages = tuple(
        _validate_package(value)
        for value in (args.package if args.package else DEFAULT_PACKAGES)
    )
    if len(set(packages)) != len(packages):
        raise SmokeError("duplicate package names are not allowed")
    if args.state_samples < 1 or args.state_samples > 10:
        raise SmokeError("state_samples must be between 1 and 10")
    if not math.isfinite(args.state_interval) or args.state_interval < 0 or args.state_interval > 10:
        raise SmokeError("state_interval must be between 0 and 10 seconds")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 120:
        raise SmokeError("timeout must be between 0 and 120 seconds")

    observations: list[dict[str, Any]] = []
    version = _run_adb(adb, None, ["version"], args.timeout)
    version["operation"] = "adb_version"
    observations.append(version)
    passed = _successful(version)

    state_values: list[str] = []
    for _ in range(args.state_samples):
        state = _run_adb(adb, serial, ["get-state"], args.timeout)
        state["operation"] = "get_state"
        observations.append(state)
        state_values.append(state["stdout"].strip())
        passed = passed and _successful(state) and state["stdout"].strip() == "device"
        if args.state_interval:
            time.sleep(args.state_interval)

    properties: dict[str, str] = {}
    for key in PROPERTY_KEYS:
        observation = _run_adb(adb, serial, ["shell", "getprop", key], args.timeout)
        observation["operation"] = "getprop"
        observation["property"] = key
        observations.append(observation)
        value = observation["stdout"].strip()
        properties[key] = value
        passed = passed and _successful(observation) and bool(value)

    if TOKEN_RE.fullmatch(args.expected_product_device) is None:
        raise SmokeError("expected_product_device must be a simple token")
    expected_device = args.expected_product_device
    expected_build_type = args.expected_build_type
    if TOKEN_RE.fullmatch(expected_build_type) is None:
        raise SmokeError("expected_build_type must be a non-empty token")
    if not args.expected_sdk.isdigit() or int(args.expected_sdk) <= 0:
        raise SmokeError("expected_sdk must be a positive decimal token")
    passed = passed and properties["ro.product.device"] == expected_device
    passed = passed and properties["ro.build.type"] == expected_build_type
    passed = passed and properties["ro.build.version.sdk"] == args.expected_sdk

    enforcing = _run_adb(adb, serial, ["shell", "getenforce"], args.timeout)
    enforcing["operation"] = "getenforce"
    observations.append(enforcing)
    enforcing_value = enforcing["stdout"].strip()
    passed = passed and _successful(enforcing) and enforcing_value in {"Enforcing", "Permissive"}

    uid = _run_adb(adb, serial, ["shell", "id", "-u"], args.timeout)
    uid["operation"] = "shell_uid"
    observations.append(uid)
    uid_value = uid["stdout"].strip()
    passed = passed and _successful(uid) and uid_value.isdigit()

    package_results, package_passed = _package_observations(
        adb, serial, packages, args.timeout, observations
    )
    passed = passed and package_passed

    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "version": 1,
        "captured_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "qualification": "READ_ONLY_DEVICE_SMOKE",
        "claim_ceiling": (
            "PACKAGE_INTEGRITY_AND_DEVICE_CONNECTIVITY_ONLY; "
            "NO_NEW_ANDROID_BUILD_OR_INSTALL_CLAIM"
        ),
        "source": {
            "repository": repository,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "source_package_sha256": package_digest,
        },
        "device": {
            "serial": serial,
            "expected": {
                "ro.product.device": expected_device,
                "ro.build.type": expected_build_type,
                "ro.build.version.sdk": args.expected_sdk,
            },
            "state_samples": state_values,
            "properties": properties,
            "selinux_mode": enforcing_value,
            "shell_uid": uid_value,
            "packages": package_results,
        },
        "adb": {
            "path": str(adb),
            "read_only_command_vocabulary": list(READ_ONLY_COMMANDS),
        },
        "mutation": {
            "performed": False,
            "install_performed": False,
            "reboot_performed": False,
            "flash_or_fastboot_performed": False,
        },
        "observations": observations,
        "result": "PASS_READ_ONLY" if passed else "FAIL_READ_ONLY",
    }
    return receipt, 0 if passed else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb", help="absolute or PATH-resolved adb executable")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--repository", default=None)
    parser.add_argument("--source-commit")
    parser.add_argument("--source-tree")
    parser.add_argument("--source-package-sha256")
    parser.add_argument("--expected-product-device", default="fogos")
    parser.add_argument("--expected-build-type", default="userdebug")
    parser.add_argument("--expected-sdk", default="36")
    parser.add_argument("--package", action="append", help="required package; repeatable")
    parser.add_argument("--state-samples", type=int, default=3)
    parser.add_argument("--state-interval", type=float, default=0.2)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        receipt, status = _collect(args)
    except SmokeError as error:
        print(f"android-ci-device-smoke: {error}", file=sys.stderr)
        return 2
    encoded = _canonical_json(receipt) + b"\n"
    if args.output is not None:
        try:
            _write_exclusive(args.output, encoded)
        except SmokeError as error:
            print(f"android-ci-device-smoke: {error}", file=sys.stderr)
            return 2
    print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
