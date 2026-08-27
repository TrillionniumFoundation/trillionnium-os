#!/usr/bin/env python3
"""Read-only Android P0.1 device conformance evidence collector.

This tool intentionally has no device mutation implementation.  Optional action
flags produce plans in the evidence object; they never execute an effect,
restart a service, reboot a device, or change adbd privilege.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat as stat_module
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


SCHEMA = "org.trillionnium.android-p01-device-conformance-evidence.v1"
CONTRACT_SCHEMA = "org.trillionnium.android-p01-device-conformance-contract.v1"
MANIFEST_PATH = "/system_ext/etc/trillionnium/linux/manifest.txt"
EGRESS_EVIDENCE_PATH = (
    "/data/trillionnium/root-linux/receipts/broker/"
    "agent-egress-boot-evidence-v2.json"
)
HIGH_WATER_SOCKET = (
    "/data/trillionnium/root-linux/rootfs/run/trillionnium/"
    "direct-operation-custody-high-water-v2.sock"
)
HIGH_WATER_STATE = (
    "/data/trillionnium/root-linux/rootfs/var/lib/trillionnium/"
    "direct-operation-custody/high-water-authority-v2/authority-state-v2.json"
)
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
PROC_SOURCE = "/proc"
PROC_ROOT_TARGET = "/data/trillionnium/root-linux/rootfs/proc"

MAX_COMMAND_OUTPUT = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_LOCAL_IMAGE_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MANIFEST_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
REMOTE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/+:-]{1,1023}$")
PROC_PATH_RE = re.compile(r"^/proc/[1-9][0-9]*/(?:stat|status|attr/current|cgroup|mountinfo)$")
OUTPUT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RETIRED_PROVIDER_TOKEN = "open" + "claw"

REQUIRED_MANIFEST_KEYS = frozenset(
    {
        "p01_product_variant",
        "p01_binding_schema",
        "p01_system_api_device_conformance_sha256",
        "p01_system_api_device_replay_sync_path",
        "p01_system_api_device_replay_sync_sha256",
        "p01_daemon_binding_custody_predispatch_wired",
        "p01_daemon_logical_delivery_admission_wired",
        "p01_daemon_direct_tool_call_prepared_ack_wired",
        "p01_sealed_replay_authority_handoff",
        "p01_daemon_custody_ack_compact_retire",
        "p01_android_ack_transport",
        "p01_external_authority_device_evidence",
        "p01_hardware_rollback_anchor",
        "p01_physical_device_evidence",
        "p01_release_allowed",
        "p01_accessibility_authorized",
        "p01_windowscompat",
        "agent_outer_ack_integration",
        "agentd_payload_sha256",
        "agent_system_api_sha256",
        "codex_integrity_launcher_sha256",
        "codex_runtime_sha256",
        "agent_accessibility_sha256",
    }
)

EXPECTED_RELEASE_BOUNDARIES = {
    "daemon_custody_ack_closure": "complete_source_host_userdebug_only",
    "android_ack_transport": "source_wired_device_evidence_hold",
    "external_authority_evidence": "hold_not_run",
    "hardware_rollback_resistance": "hold_not_implemented",
    "physical_device_effect_evidence": "hold_not_run",
    "release_allowed": "false_userdebug_only",
}

PROPERTY_KEYS = frozenset(
    {
        "ro.product.device",
        "ro.build.type",
        "ro.build.fingerprint",
        "ro.system_ext.build.fingerprint",
        "ro.boot.slot_suffix",
        "ro.boot.verifiedbootstate",
        "ro.boot.vbmeta.device_state",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.digest",
        "ro.boot.veritymode",
        "ro.boot.avb_version",
        "sys.trillionnium.rootlinux.prepare",
        "sys.trillionnium.agentd.desired",
        "sys.trillionnium.agent_egress_guard",
        "init.svc.trillionnium_root_linux_bootstrap",
        "init.svc.trillionnium_agent_egress_guard",
        "init.svc.trillionnium_direct_operation_custody_high_water",
        "init.svc.trillionnium_root_linux_daemon",
        "init.svc_debug_pid.trillionnium_direct_operation_custody_high_water",
        "init.svc_debug_pid.trillionnium_root_linux_daemon",
    }
)


class ConformanceError(RuntimeError):
    """A fail-closed input, execution, or evidence error."""


class AdbCommandError(ConformanceError):
    """A bounded read-only adb operation failed."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _strict_json_loads(data: bytes, *, maximum: int, label: str) -> Any:
    if len(data) > maximum:
        raise ConformanceError(f"{label} exceeds the {maximum}-byte bound")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ConformanceError(f"{label} is not strict UTF-8") from exc

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConformanceError(f"{label} has duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ConformanceError(f"{label} contains non-finite number {value}")
            ),
        )
    except ConformanceError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ConformanceError(f"{label} is not strict JSON: {exc}") from exc


def parse_manifest(data: bytes) -> dict[str, str]:
    if len(data) > MAX_MANIFEST_BYTES:
        raise ConformanceError("manifest exceeds size bound")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ConformanceError("manifest is not strict UTF-8") from exc
    if "\x00" in text or "\r" in text:
        raise ConformanceError("manifest contains forbidden NUL or CR")
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise ConformanceError(f"manifest line {line_number} is empty")
        if line.startswith("#"):
            continue
        if line.count("=") != 1:
            raise ConformanceError(
                f"manifest line {line_number} is not one key=value fact"
            )
        key, value = line.split("=", 1)
        if not MANIFEST_KEY_RE.fullmatch(key):
            raise ConformanceError(f"manifest line {line_number} has invalid key")
        if not value or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise ConformanceError(f"manifest line {line_number} has invalid value")
        if key in result:
            raise ConformanceError(f"manifest has duplicate key {key!r}")
        result[key] = value
    if not result:
        raise ConformanceError("manifest is empty")
    return result


def _path_components_are_not_symlinks(path: Path) -> None:
    if not path.is_absolute():
        raise ConformanceError(f"path must be absolute: {path}")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            mode = os.lstat(current).st_mode
        except OSError as exc:
            raise ConformanceError(f"cannot inspect path component {current}: {exc}") from exc
        if stat_module.S_ISLNK(mode):
            raise ConformanceError(f"symlink path component is forbidden: {current}")


def measure_regular_file(
    path_value: str | os.PathLike[str],
    *,
    maximum: int,
    executable: bool = False,
) -> dict[str, Any]:
    path = Path(path_value)
    _path_components_are_not_symlinks(path)
    before = os.lstat(path)
    if not stat_module.S_ISREG(before.st_mode):
        raise ConformanceError(f"not a regular file: {path}")
    if executable and not before.st_mode & 0o111:
        raise ConformanceError(f"file is not executable: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ConformanceError(f"cannot securely open {path}: {exc}") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if not stat_module.S_ISREG(opened.st_mode):
            raise ConformanceError(f"opened object is not regular: {path}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ConformanceError(f"file identity changed while opening: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ConformanceError(f"file exceeds size bound: {path}")
            digest.update(chunk)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after_fd = (
        after_fd.st_dev,
        after_fd.st_ino,
        after_fd.st_size,
        after_fd.st_mtime_ns,
    )
    identity_after_path = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
    )
    if identity_before != identity_after_fd or identity_before != identity_after_path:
        raise ConformanceError(f"file changed while measuring: {path}")
    if total != before.st_size:
        raise ConformanceError(f"short or expanded read while measuring: {path}")
    return {
        "path": str(path),
        "size": total,
        "sha256": digest.hexdigest(),
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": f"{stat_module.S_IMODE(before.st_mode):04o}",
    }


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        process.kill()


def run_bounded(
    argv: Sequence[str],
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    maximum_output: int = MAX_COMMAND_OUTPUT,
) -> tuple[int, bytes, bytes]:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise ConformanceError("invalid subprocess argv")
    if timeout_seconds <= 0 or maximum_output <= 0:
        raise ConformanceError("invalid subprocess bound")
    process = subprocess.Popen(
        list(argv),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    streams: dict[int, bytearray] = {
        process.stdout.fileno(): bytearray(),
        process.stderr.fileno(): bytearray(),
    }
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise ConformanceError("subprocess timed out")
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                streams[key.fd].extend(chunk)
                total = sum(len(value) for value in streams.values())
                if total > maximum_output:
                    _kill_process_group(process)
                    raise ConformanceError("subprocess output exceeded bound")
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except BaseException:
        _kill_process_group(process)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return return_code, bytes(streams[process.stdout.fileno()]), bytes(
        streams[process.stderr.fileno()]
    )


def _validate_serial(serial: str) -> str:
    if not SERIAL_RE.fullmatch(serial) or serial.startswith("-"):
        raise ConformanceError("adb serial has an invalid shape")
    return serial


def _validate_remote_path(path: str) -> str:
    if not REMOTE_PATH_RE.fullmatch(path) or "//" in path or "/../" in path:
        raise ConformanceError(f"invalid fixed remote path: {path!r}")
    return path


class AdbClient:
    """Only the fixed read-only adb vocabulary needed by this collector."""

    def __init__(
        self,
        adb_path: str,
        serial: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._measurement = measure_regular_file(
            adb_path, maximum=256 * 1024 * 1024, executable=True
        )
        self.adb_path = self._measurement["path"]
        self.serial = _validate_serial(serial)
        self.timeout_seconds = timeout_seconds
        self.command_audit: list[dict[str, Any]] = []

    @property
    def adb_measurement(self) -> Mapping[str, Any]:
        return self._measurement

    def _recheck_adb(self) -> None:
        current = measure_regular_file(
            self.adb_path, maximum=256 * 1024 * 1024, executable=True
        )
        for key in ("sha256", "size", "device", "inode"):
            if current[key] != self._measurement[key]:
                raise ConformanceError("adb executable identity changed during collection")

    def _run(
        self, operation: str, tail: Sequence[str], *, maximum: int = MAX_COMMAND_OUTPUT
    ) -> bytes:
        self._recheck_adb()
        argv = [self.adb_path, "-s", self.serial, *tail]
        return_code, stdout, stderr = run_bounded(
            argv, timeout_seconds=self.timeout_seconds, maximum_output=maximum
        )
        self.command_audit.append(
            {
                "sequence": len(self.command_audit) + 1,
                "operation": operation,
                "read_only_argv": list(tail),
                "exit_code": return_code,
                "stdout_bytes": len(stdout),
                "stdout_sha256": _sha256_bytes(stdout),
                "stderr_bytes": len(stderr),
                "stderr_sha256": _sha256_bytes(stderr),
            }
        )
        self._recheck_adb()
        if return_code != 0:
            raise AdbCommandError(
                f"adb read-only operation {operation!r} failed with exit {return_code}"
            )
        return stdout

    def get_state(self) -> str:
        return self._run("get_state", ["get-state"], maximum=4096).decode(
            "utf-8", "strict"
        ).strip()

    def getprop(self, key: str) -> str:
        if key not in PROPERTY_KEYS:
            raise ConformanceError(f"unapproved property read: {key}")
        return self._run(
            f"getprop:{key}", ["shell", "getprop", key], maximum=16384
        ).decode("utf-8", "strict").strip()

    def getenforce(self) -> str:
        return self._run("getenforce", ["shell", "getenforce"], maximum=4096).decode(
            "utf-8", "strict"
        ).strip()

    def shell_uid(self) -> int:
        value = self._run("shell_uid", ["shell", "id", "-u"], maximum=4096).decode(
            "ascii", "strict"
        ).strip()
        if not value.isdigit():
            raise AdbCommandError("adb shell uid was not numeric")
        return int(value)

    def cat(self, path: str, *, maximum: int = MAX_JSON_BYTES) -> bytes:
        _validate_remote_path(path)
        if path not in fixed_remote_paths() and not PROC_PATH_RE.fullmatch(path):
            raise ConformanceError(f"unapproved remote file read: {path}")
        return self._run(f"cat:{path}", ["exec-out", "cat", path], maximum=maximum)

    def sha256(self, path: str) -> str:
        _validate_remote_path(path)
        if path not in artifact_remote_paths():
            raise ConformanceError(f"unapproved remote hash read: {path}")
        output = self._run(
            f"sha256:{path}", ["shell", "sha256sum", path], maximum=4096
        ).decode("ascii", "strict").strip()
        fields = output.split()
        if len(fields) != 2 or fields[1] != path or not SHA256_RE.fullmatch(fields[0]):
            raise AdbCommandError(f"malformed sha256sum output for {path}")
        return fields[0]

    def stat(self, path: str) -> dict[str, Any]:
        _validate_remote_path(path)
        if path not in fixed_remote_paths() and not PROC_PATH_RE.fullmatch(path):
            raise ConformanceError(f"unapproved remote stat: {path}")
        format_string = "%F|%s|%a|%u|%g|%d|%i|%h|%C"
        output = self._run(
            f"stat:{path}",
            ["shell", "stat", "-c", format_string, path],
            maximum=16384,
        ).decode("utf-8", "strict").strip()
        fields = output.split("|", 8)
        if len(fields) != 9:
            raise AdbCommandError(f"malformed stat output for {path}")
        file_type, size, mode, uid, gid, device, inode, links, context = fields
        numeric = (size, uid, gid, device, inode, links)
        if any(not value.isdigit() for value in numeric) or not re.fullmatch(
            r"[0-7]{3,4}", mode
        ):
            raise AdbCommandError(f"invalid stat numeric field for {path}")
        return {
            "file_type": file_type,
            "size": int(size),
            "mode": mode.zfill(4),
            "uid": int(uid),
            "gid": int(gid),
            "device": int(device),
            "inode": int(inode),
            "links": int(links),
            "selinux_context": context,
        }


@dataclass
class EvidenceLayer:
    name: str
    checks: list[dict[str, Any]] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)

    def add(
        self,
        check_id: str,
        status: str,
        *,
        expected: Any = None,
        observed: Any = None,
        detail: str | None = None,
    ) -> None:
        if status not in {"PASS", "HOLD", "FAIL"}:
            raise AssertionError(f"invalid check status: {status}")
        item: dict[str, Any] = {"id": check_id, "status": status}
        if expected is not None:
            item["expected"] = expected
        if observed is not None:
            item["observed"] = observed
        if detail is not None:
            item["detail"] = detail
        self.checks.append(item)

    def exact(self, check_id: str, observed: Any, expected: Any) -> None:
        self.add(
            check_id,
            "PASS" if observed == expected else "FAIL",
            expected=expected,
            observed=observed,
        )

    def hold(self, check_id: str, detail: str, *, observed: Any = None) -> None:
        self.add(check_id, "HOLD", observed=observed, detail=detail)

    def fail(self, check_id: str, detail: str, *, observed: Any = None) -> None:
        self.add(check_id, "FAIL", observed=observed, detail=detail)

    @property
    def decision(self) -> str:
        statuses = {check["status"] for check in self.checks}
        if "FAIL" in statuses:
            return "FAIL"
        if "HOLD" in statuses:
            return "HOLD"
        return "PASS"

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "checks": self.checks,
            "observations": self.observations,
        }


@dataclass(frozen=True)
class ArtifactSpec:
    name: str
    source: str
    context: str | None
    root_target: str | None = None


ARTIFACT_SPECS = (
    ArtifactSpec(
        "p01_launcher",
        "/system_ext/bin/trillionniumd",
        "u:object_r:trillionnium_agentd_exec:s0",
    ),
    ArtifactSpec(
        "p01_core",
        "/system_ext/bin/trillionniumd-p01-core",
        None,
    ),
    ArtifactSpec(
        "daemon_payload",
        "/system_ext/bin/trillionnium-agentd-payload",
        "u:object_r:trillionnium_agentd_payload_exec:s0",
        "/data/trillionnium/root-linux/rootfs/usr/bin/trillionniumd",
    ),
    ArtifactSpec(
        "system_api",
        "/system_ext/bin/trillionnium-agent-system-api",
        "u:object_r:trillionnium_agent_system_api_exec:s0",
        "/data/trillionnium/root-linux/rootfs/usr/local/bin/trillionnium-agent-system-api",
    ),
    ArtifactSpec(
        "p01_replay_helper",
        "/system_ext/bin/trillionnium-system-api-device-conformance-replay-sync",
        "u:object_r:trillionnium_agent_system_api_operation_replay_sync_exec:s0",
        "/data/trillionnium/root-linux/rootfs/usr/local/bin/trillionnium-system-api-device-conformance-replay-sync",
    ),
    ArtifactSpec(
        "high_water",
        "/system_ext/bin/trillionnium-direct-operation-custody-high-water",
        "u:object_r:trillionnium_direct_operation_custody_high_water_exec:s0",
    ),
    ArtifactSpec(
        "codex_launcher",
        "/system_ext/bin/trillionnium-codex-agent-0.144.1",
        "u:object_r:trillionnium_codex_agent_exec:s0",
        "/data/trillionnium/root-linux/rootfs/usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin/codex",
    ),
    ArtifactSpec(
        "codex_runtime",
        "/system_ext/bin/trillionnium-codex-runtime-0.144.1",
        "u:object_r:trillionnium_codex_runtime_exec:s0",
        "/data/trillionnium/root-linux/rootfs/usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin/codex.real",
    ),
    ArtifactSpec(
        "accessibility",
        "/system_ext/bin/trillionnium-agent-accessibility",
        "u:object_r:trillionnium_agent_accessibility_exec:s0",
        "/data/trillionnium/root-linux/rootfs/usr/local/bin/trillionnium-agent-accessibility",
    ),
)


CONTRACT_KEYS = frozenset(
    {
        "schema",
        "product",
        "variant",
        "upstream_evidence",
        "manifest_sha256",
        "system_ext_image_sha256",
        "required_manifest_facts",
        "artifact_sha256",
        "release_boundaries",
        "authorizes_device_mutation",
    }
)

MANIFEST_ARTIFACT_BINDINGS = {
    "agentd_payload_sha256": "daemon_payload",
    "agent_system_api_sha256": "system_api",
    "p01_system_api_device_conformance_sha256": "system_api",
    "p01_system_api_device_replay_sync_sha256": "p01_replay_helper",
    "codex_integrity_launcher_sha256": "codex_launcher",
    "codex_runtime_sha256": "codex_runtime",
    "agent_accessibility_sha256": "accessibility",
}


def parse_expectation_contract(data: bytes) -> dict[str, Any]:
    contract = _strict_json_loads(
        data, maximum=MAX_JSON_BYTES, label="device conformance expectation contract"
    )
    if not isinstance(contract, dict):
        raise ConformanceError("expectation contract top level is not an object")
    if set(contract) != CONTRACT_KEYS:
        missing = sorted(CONTRACT_KEYS - set(contract))
        extra = sorted(set(contract) - CONTRACT_KEYS)
        raise ConformanceError(
            f"expectation contract key set mismatch; missing={missing}, extra={extra}"
        )
    if contract["schema"] != CONTRACT_SCHEMA:
        raise ConformanceError("expectation contract schema mismatch")
    product = contract["product"]
    if not isinstance(product, str) or not re.fullmatch(
        r"[A-Za-z0-9._-]{1,64}", product
    ):
        raise ConformanceError("expectation contract product has invalid shape")
    if contract["variant"] != "userdebug":
        raise ConformanceError("expectation contract variant must be userdebug")
    if contract["authorizes_device_mutation"] is not False:
        raise ConformanceError("expectation contract must deny device mutation")
    upstream = contract["upstream_evidence"]
    if not isinstance(upstream, dict) or set(upstream) != {"kind", "sha256"}:
        raise ConformanceError("expectation contract upstream evidence is malformed")
    if upstream["kind"] not in {
        "target_files",
        "cross_repo_bom",
        "signed_release_bom",
    }:
        raise ConformanceError("expectation contract upstream evidence kind is invalid")
    if not isinstance(upstream["sha256"], str) or not SHA256_RE.fullmatch(
        upstream["sha256"]
    ) or upstream["sha256"] == "0" * 64:
        raise ConformanceError("expectation contract upstream SHA-256 is invalid")
    manifest_sha = contract["manifest_sha256"]
    if not isinstance(manifest_sha, str) or not SHA256_RE.fullmatch(
        manifest_sha
    ) or manifest_sha == "0" * 64:
        raise ConformanceError("expectation contract manifest SHA-256 is invalid")
    image_sha = contract["system_ext_image_sha256"]
    if not isinstance(image_sha, str) or not SHA256_RE.fullmatch(
        image_sha
    ) or image_sha == "0" * 64:
        raise ConformanceError("expectation contract system_ext image SHA-256 is invalid")
    facts = contract["required_manifest_facts"]
    if not isinstance(facts, dict):
        raise ConformanceError("expectation contract manifest facts are not an object")
    missing_facts = REQUIRED_MANIFEST_KEYS - set(facts)
    if missing_facts:
        raise ConformanceError(
            f"expectation contract lacks required manifest facts: {sorted(missing_facts)}"
        )
    for key, value in facts.items():
        if not isinstance(key, str) or not MANIFEST_KEY_RE.fullmatch(key):
            raise ConformanceError("expectation contract has invalid manifest fact key")
        if not isinstance(value, str) or not value or any(
            ord(character) < 0x20 or ord(character) > 0x7E for character in value
        ):
            raise ConformanceError(
                f"expectation contract has invalid manifest value for {key}"
            )
        if RETIRED_PROVIDER_TOKEN in key.casefold() or RETIRED_PROVIDER_TOKEN in value.casefold():
            raise ConformanceError(
                "expectation contract retains a retired Provider manifest fact"
            )
    exact_manifest_facts = {
        "p01_product_variant": "userdebug",
        "p01_binding_schema": "trillionnium.direct-operation.binding.v3",
        "p01_system_api_device_replay_sync_path": (
            "/system_ext/bin/trillionnium-system-api-device-conformance-replay-sync"
        ),
        "p01_sealed_replay_authority_handoff": (
            "complete_source_host_userdebug_only"
        ),
        "p01_daemon_custody_ack_compact_retire": (
            "complete_source_host_userdebug_only"
        ),
        "p01_android_ack_transport": "source_wired_device_evidence_hold",
        "p01_external_authority_device_evidence": "hold_not_run",
        "p01_hardware_rollback_anchor": "hold_not_implemented",
        "p01_physical_device_evidence": "hold_not_run",
        "p01_release_allowed": "false_userdebug_only",
        "p01_accessibility_authorized": "false_hold",
        "p01_windowscompat": "research_only_not_implemented",
        "agent_outer_ack_integration": (
            "p01_source_host_complete_device_evidence_hold_userdebug_only"
        ),
    }
    for key, expected in exact_manifest_facts.items():
        if facts.get(key) != expected:
            raise ConformanceError(
                f"expectation contract manifest fact {key} is not {expected!r}"
            )
    hashes = contract["artifact_sha256"]
    expected_names = {spec.name for spec in ARTIFACT_SPECS}
    if not isinstance(hashes, dict) or set(hashes) != expected_names:
        raise ConformanceError(
            "expectation contract artifact hash set does not match fixed product paths"
        )
    for name, value in hashes.items():
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
            raise ConformanceError(
                f"expectation contract artifact hash is invalid for {name}"
            )
    for manifest_key, artifact_name in MANIFEST_ARTIFACT_BINDINGS.items():
        if facts.get(manifest_key) != hashes[artifact_name]:
            raise ConformanceError(
                f"expectation contract cross-binding mismatch: {manifest_key}"
            )
    if contract["release_boundaries"] != EXPECTED_RELEASE_BOUNDARIES:
        raise ConformanceError(
            "expectation contract release boundaries are not the exact reviewed P0.1 boundary"
        )
    return contract


def load_expectation_contract(
    path: str | os.PathLike[str],
    expected_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not SHA256_RE.fullmatch(expected_sha256):
        raise ConformanceError(
            "expected conformance contract hash must be lowercase SHA-256"
        )
    measurement = measure_regular_file(path, maximum=MAX_JSON_BYTES)
    if measurement["sha256"] != expected_sha256:
        raise ConformanceError("expectation contract SHA-256 does not match its pin")
    descriptor = os.open(
        measurement["path"],
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        data = bytearray()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_JSON_BYTES:
                raise ConformanceError("expectation contract exceeds size bound")
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        opened.st_dev != measurement["device"]
        or opened.st_ino != measurement["inode"]
        or opened.st_size != measurement["size"]
        or _sha256_bytes(bytes(data)) != measurement["sha256"]
    ):
        raise ConformanceError("expectation contract changed after measurement")
    return parse_expectation_contract(bytes(data)), measurement


def artifact_remote_paths() -> frozenset[str]:
    paths = {spec.source for spec in ARTIFACT_SPECS}
    paths.update(spec.root_target for spec in ARTIFACT_SPECS if spec.root_target)
    return frozenset(paths)


def fixed_remote_paths() -> frozenset[str]:
    paths = set(artifact_remote_paths())
    paths.update(
        {
            MANIFEST_PATH,
            EGRESS_EVIDENCE_PATH,
            HIGH_WATER_SOCKET,
            HIGH_WATER_STATE,
            BOOT_ID_PATH,
            PROC_SOURCE,
            PROC_ROOT_TARGET,
        }
    )
    return frozenset(paths)


def _expected_artifact_hash(
    spec: ArtifactSpec, contract: Mapping[str, Any]
) -> str:
    hashes = contract.get("artifact_sha256")
    if not isinstance(hashes, dict):
        raise ConformanceError("validated contract artifact hash map is unavailable")
    value = hashes.get(spec.name)
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ConformanceError(f"contract lacks valid hash for {spec.name}")
    return value


def _read_call(
    layer: EvidenceLayer,
    check_id: str,
    callback: Callable[[], Any],
    *,
    missing_status: str = "HOLD",
) -> Any | None:
    try:
        return callback()
    except (ConformanceError, OSError, UnicodeError) as exc:
        layer.add(check_id, missing_status, detail=str(exc))
        return None


def _parse_proc_start_time(data: bytes) -> int:
    text = data.decode("ascii", "strict").strip()
    close = text.rfind(")")
    if close < 1:
        raise ConformanceError("malformed /proc stat comm field")
    fields = text[close + 1 :].strip().split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise ConformanceError("malformed /proc stat starttime")
    return int(fields[19])


def _parse_proc_status(data: bytes) -> tuple[list[int], list[int]]:
    uid: list[int] | None = None
    gid: list[int] | None = None
    for line in data.decode("utf-8", "strict").splitlines():
        if line.startswith("Uid:"):
            fields = line.split()[1:]
            if len(fields) == 4 and all(item.isdigit() for item in fields):
                uid = [int(item) for item in fields]
        elif line.startswith("Gid:"):
            fields = line.split()[1:]
            if len(fields) == 4 and all(item.isdigit() for item in fields):
                gid = [int(item) for item in fields]
    if uid is None or gid is None:
        raise ConformanceError("process status lacks strict Uid/Gid rows")
    return uid, gid


def _unescape_mount_field(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value
    )


def parse_mountinfo(data: bytes) -> dict[str, dict[str, Any]]:
    text = data.decode("utf-8", "strict")
    result: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if "-" not in fields:
            raise ConformanceError(f"mountinfo line {line_number} lacks separator")
        separator = fields.index("-")
        if separator < 6 or len(fields) < separator + 4:
            raise ConformanceError(f"mountinfo line {line_number} is truncated")
        mount_point = _unescape_mount_field(fields[4])
        if mount_point in result:
            raise ConformanceError(f"duplicate mount point in mountinfo: {mount_point}")
        result[mount_point] = {
            "root": _unescape_mount_field(fields[3]),
            "mount_options": sorted(set(fields[5].split(","))),
            "filesystem": fields[separator + 1],
            "source": _unescape_mount_field(fields[separator + 2]),
            "super_options": sorted(set(fields[separator + 3].split(","))),
        }
    return result


ROOTFS_HOST_PREFIX = "/data/trillionnium/root-linux/rootfs"


def mountinfo_view_candidates(host_target: str) -> tuple[str, ...]:
    """Return host-root and daemon-chroot spellings for one mount target."""
    if host_target == ROOTFS_HOST_PREFIX:
        return (host_target, "/")
    if host_target.startswith(ROOTFS_HOST_PREFIX + "/"):
        return (host_target, host_target[len(ROOTFS_HOST_PREFIX) :])
    return (host_target,)


def find_mountinfo_entry(
    mountinfo: Mapping[str, dict[str, Any]], host_target: str
) -> tuple[str, dict[str, Any]] | None:
    matches = [
        (candidate, mountinfo[candidate])
        for candidate in mountinfo_view_candidates(host_target)
        if candidate in mountinfo
    ]
    if len(matches) > 1:
        raise ConformanceError(
            f"mountinfo contains both host and chroot spellings for {host_target}"
        )
    return matches[0] if matches else None


class DeviceCollector:
    def __init__(
        self,
        client: Any,
        *,
        contract: Mapping[str, Any],
        contract_measurement: Mapping[str, Any],
        system_ext_image: str | None = None,
        action_requests: Mapping[str, bool] | None = None,
    ) -> None:
        self.client = client
        self.contract = parse_expectation_contract(_canonical_json_bytes(contract))
        self.contract_measurement = dict(contract_measurement)
        self.expected_device = self.contract["product"]
        self.system_ext_image = system_ext_image
        self.action_requests = dict(action_requests or {})
        self.layers: dict[str, EvidenceLayer] = {}
        self.manifest: dict[str, str] = {}
        self.shell_uid: int | None = None

    def _layer(self, name: str) -> EvidenceLayer:
        layer = EvidenceLayer(name)
        self.layers[name] = layer
        return layer

    def collect_contract(self) -> None:
        layer = self._layer("measured_expectation_contract")
        required_measurement_keys = {"path", "size", "sha256", "device", "inode", "mode"}
        if not required_measurement_keys.issubset(self.contract_measurement):
            layer.fail(
                "contract_measurement",
                "expectation contract measurement is incomplete",
            )
            return
        digest = self.contract_measurement.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            layer.fail(
                "contract_measurement",
                "expectation contract measurement SHA-256 is invalid",
            )
            return
        layer.add("contract_measurement", "PASS")
        layer.observations.update(
            {
                "measurement": self.contract_measurement,
                "schema": self.contract["schema"],
                "upstream_evidence": self.contract["upstream_evidence"],
                "manifest_sha256": self.contract["manifest_sha256"],
                "system_ext_image_sha256": self.contract[
                    "system_ext_image_sha256"
                ],
                "release_boundaries": self.contract["release_boundaries"],
                "authorizes_device_mutation": False,
            }
        )

    def collect_identity(self) -> None:
        layer = self._layer("device_identity_and_verified_boot")
        state = _read_call(layer, "adb_state_readable", self.client.get_state, missing_status="FAIL")
        if state is not None:
            layer.exact("adb_state", state, "device")
        values: dict[str, str] = {}
        for key in (
            "ro.product.device",
            "ro.build.type",
            "ro.build.fingerprint",
            "ro.system_ext.build.fingerprint",
            "ro.boot.slot_suffix",
            "ro.boot.verifiedbootstate",
            "ro.boot.vbmeta.device_state",
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.digest",
            "ro.boot.veritymode",
            "ro.boot.avb_version",
        ):
            value = _read_call(
                layer,
                f"property_read:{key}",
                lambda key=key: self.client.getprop(key),
                missing_status="FAIL",
            )
            if value is not None:
                values[key] = value
        layer.observations["properties"] = values
        if "ro.product.device" in values:
            layer.exact("product_device", values["ro.product.device"], self.expected_device)
        if "ro.build.type" in values:
            layer.exact("build_type", values["ro.build.type"], "userdebug")
        fingerprint = values.get("ro.build.fingerprint")
        if fingerprint is not None:
            valid = (
                1 <= len(fingerprint) <= 512
                and f"/{self.expected_device}:" in fingerprint
                and ":userdebug/" in fingerprint
            )
            layer.add(
                "fingerprint_shape",
                "PASS" if valid else "FAIL",
                expected="bounded fingerprint for expected device and userdebug",
                observed=fingerprint,
            )
        system_ext_fingerprint = values.get("ro.system_ext.build.fingerprint")
        if fingerprint is not None and system_ext_fingerprint is not None:
            layer.exact("system_ext_fingerprint", system_ext_fingerprint, fingerprint)
        slot = values.get("ro.boot.slot_suffix")
        if slot is not None:
            layer.add(
                "active_slot",
                "PASS" if slot in {"_a", "_b"} else "FAIL",
                expected=["_a", "_b"],
                observed=slot,
            )
        verified = values.get("ro.boot.verifiedbootstate")
        if verified is not None:
            if verified == "green":
                layer.add("verified_boot_state", "PASS", expected="green", observed=verified)
            elif verified == "orange":
                layer.hold("verified_boot_state", "bootloader is unlocked", observed=verified)
            else:
                layer.fail("verified_boot_state", "verified boot is not green", observed=verified)
        device_state = values.get("ro.boot.vbmeta.device_state")
        if device_state is not None:
            if device_state == "locked":
                layer.add("vbmeta_device_state", "PASS", expected="locked", observed=device_state)
            elif device_state == "unlocked":
                layer.hold("vbmeta_device_state", "vbmeta device state is unlocked", observed=device_state)
            else:
                layer.fail("vbmeta_device_state", "unknown vbmeta state", observed=device_state)
        flash_locked = values.get("ro.boot.flash.locked")
        if flash_locked is not None:
            if flash_locked == "1":
                layer.add("flash_locked", "PASS", expected="1", observed=flash_locked)
            elif flash_locked == "0":
                layer.hold("flash_locked", "flash lock reports unlocked", observed=flash_locked)
            else:
                layer.fail("flash_locked", "invalid flash lock property", observed=flash_locked)
        digest = values.get("ro.boot.vbmeta.digest")
        if digest is not None:
            layer.add(
                "vbmeta_digest_shape",
                "PASS" if SHA256_RE.fullmatch(digest) else "FAIL",
                expected="lowercase SHA-256",
                observed=digest,
            )
        if "ro.boot.veritymode" in values:
            layer.exact("verity_mode", values["ro.boot.veritymode"], "enforcing")

    def collect_manifest(self) -> None:
        layer = self._layer("manifest_unique_truth")
        raw = _read_call(
            layer,
            "manifest_read",
            lambda: self.client.cat(MANIFEST_PATH, maximum=MAX_MANIFEST_BYTES),
            missing_status="FAIL",
        )
        if raw is None:
            return
        manifest_sha256 = _sha256_bytes(raw)
        layer.observations.update(
            {"path": MANIFEST_PATH, "size": len(raw), "sha256": manifest_sha256}
        )
        layer.exact(
            "manifest_contract_digest",
            manifest_sha256,
            self.contract["manifest_sha256"],
        )
        try:
            self.manifest = parse_manifest(raw)
        except ConformanceError as exc:
            layer.fail("manifest_parse", str(exc))
            return
        layer.add("manifest_parse", "PASS", observed=f"{len(self.manifest)} unique facts")
        retired_facts = sorted(
            key
            for key, value in self.manifest.items()
            if RETIRED_PROVIDER_TOKEN in key.casefold()
            or RETIRED_PROVIDER_TOKEN in value.casefold()
        )
        layer.add(
            "retired_provider_absent",
            "PASS" if not retired_facts else "FAIL",
            expected=[],
            observed=retired_facts,
        )
        expected_facts = self.contract["required_manifest_facts"]
        observed = {key: self.manifest.get(key) for key in expected_facts}
        layer.observations["p01_facts"] = observed
        for key, expected in expected_facts.items():
            if key not in self.manifest:
                layer.fail(f"manifest_fact:{key}", "required fact is absent")
            else:
                layer.exact(f"manifest_fact:{key}", self.manifest[key], expected)

    def collect_host_image(self) -> None:
        layer = self._layer("optional_host_system_ext_image")
        if self.system_ext_image is None:
            layer.add("host_image_not_requested", "PASS", observed="not supplied")
            return
        try:
            measurement = measure_regular_file(
                self.system_ext_image, maximum=MAX_LOCAL_IMAGE_BYTES
            )
        except ConformanceError as exc:
            layer.fail("host_image_measurement", str(exc))
            return
        layer.observations["measurement"] = measurement
        layer.add("host_image_measurement", "PASS")
        layer.exact(
            "host_image_expected_hash",
            measurement["sha256"],
            self.contract["system_ext_image_sha256"],
        )

    def collect_artifacts(self) -> None:
        layer = self._layer("system_ext_artifact_measurements")
        if not self.manifest:
            layer.fail("artifact_expectations", "valid manifest is unavailable")
            return
        observed_hashes: dict[str, str] = {}
        for spec in ARTIFACT_SPECS:
            try:
                expected_hash = _expected_artifact_hash(spec, self.contract)
            except ConformanceError as exc:
                layer.fail(f"expected_hash:{spec.name}", str(exc))
                continue
            observed_hash = _read_call(
                layer,
                f"hash_read:{spec.name}",
                lambda spec=spec: self.client.sha256(spec.source),
                missing_status="FAIL",
            )
            if observed_hash is not None:
                observed_hashes[spec.name] = observed_hash
                layer.exact(f"hash:{spec.name}", observed_hash, expected_hash)
            source_stat = _read_call(
                layer,
                f"stat_read:{spec.name}",
                lambda spec=spec: self.client.stat(spec.source),
                missing_status="HOLD",
            )
            if source_stat is not None:
                layer.exact(f"owner:{spec.name}", [source_stat["uid"], source_stat["gid"]], [0, 0])
                layer.exact(f"mode:{spec.name}", source_stat["mode"], "0755")
                if spec.context is not None:
                    layer.exact(
                        f"selinux_context:{spec.name}",
                        source_stat["selinux_context"],
                        spec.context,
                    )
        layer.observations["artifact_hashes"] = observed_hashes
        if len(observed_hashes) == len(ARTIFACT_SPECS):
            layer.observations["artifact_closure_sha256"] = _sha256_bytes(
                _canonical_json_bytes(observed_hashes)
            )

    def collect_init_and_selinux(self) -> None:
        layer = self._layer("init_selinux_and_service_state")
        enforcing = _read_call(layer, "getenforce_read", self.client.getenforce, missing_status="FAIL")
        if enforcing is not None:
            layer.exact("selinux_enforcing", enforcing, "Enforcing")
        expected_properties = {
            "sys.trillionnium.rootlinux.prepare": "0",
            "sys.trillionnium.agentd.desired": "1",
            "sys.trillionnium.agent_egress_guard": "ready",
            "init.svc.trillionnium_root_linux_bootstrap": "stopped",
            "init.svc.trillionnium_agent_egress_guard": "stopped",
            "init.svc.trillionnium_direct_operation_custody_high_water": "running",
            "init.svc.trillionnium_root_linux_daemon": "running",
        }
        observed: dict[str, str] = {}
        for key, expected in expected_properties.items():
            value = _read_call(
                layer,
                f"service_property_read:{key}",
                lambda key=key: self.client.getprop(key),
                missing_status="FAIL",
            )
            if value is not None:
                observed[key] = value
                layer.exact(f"service_property:{key}", value, expected)
        layer.observations["properties"] = observed
        uid = _read_call(layer, "adbd_shell_uid_read", self.client.shell_uid, missing_status="HOLD")
        if uid is not None:
            self.shell_uid = uid
            if uid == 0:
                layer.add("preexisting_adbd_root", "PASS", expected=0, observed=uid)
            else:
                layer.hold(
                    "preexisting_adbd_root",
                    "privileged /data and process evidence cannot be collected; adb root is forbidden",
                    observed=uid,
                )

    def _collect_process(
        self,
        layer: EvidenceLayer,
        service: str,
        expected_domain: str,
    ) -> tuple[int | None, bytes | None]:
        pid_key = f"init.svc_debug_pid.{service}"
        pid_text = _read_call(
            layer,
            f"pid_property_read:{service}",
            lambda: self.client.getprop(pid_key),
        )
        if pid_text is None:
            return None, None
        if not re.fullmatch(r"[1-9][0-9]{0,9}", pid_text):
            layer.fail(f"pid_shape:{service}", "init debug PID is not a positive decimal", observed=pid_text)
            return None, None
        pid = int(pid_text)
        base = f"/proc/{pid}"
        stat_before = _read_call(layer, f"proc_stat_before:{service}", lambda: self.client.cat(f"{base}/stat", maximum=65536))
        status = _read_call(layer, f"proc_status:{service}", lambda: self.client.cat(f"{base}/status", maximum=65536))
        domain = _read_call(layer, f"proc_domain:{service}", lambda: self.client.cat(f"{base}/attr/current", maximum=65536))
        cgroup = _read_call(layer, f"proc_cgroup:{service}", lambda: self.client.cat(f"{base}/cgroup", maximum=65536))
        stat_after = _read_call(layer, f"proc_stat_after:{service}", lambda: self.client.cat(f"{base}/stat", maximum=65536))
        if stat_before is not None and stat_after is not None:
            try:
                before_start = _parse_proc_start_time(stat_before)
                after_start = _parse_proc_start_time(stat_after)
            except ConformanceError as exc:
                layer.fail(f"pid_identity:{service}", str(exc))
            else:
                layer.exact(f"pid_identity:{service}", after_start, before_start)
        if status is not None:
            try:
                uid, gid = _parse_proc_status(status)
            except ConformanceError as exc:
                layer.fail(f"process_credentials:{service}", str(exc))
            else:
                layer.exact(f"process_uid:{service}", uid, [0, 0, 0, 0])
                layer.exact(f"process_gid:{service}", gid, [0, 0, 0, 0])
        if domain is not None:
            observed_domain = domain.decode("utf-8", "strict").strip()
            layer.exact(f"process_domain:{service}", observed_domain, expected_domain)
        if cgroup is not None:
            cgroup_text = cgroup.decode("utf-8", "strict").strip()
            dedicated = bool(cgroup_text) and "trillionnium" in cgroup_text.lower() and cgroup_text != "0::/"
            if dedicated:
                layer.add(f"dedicated_cgroup:{service}", "PASS", observed=cgroup_text)
            else:
                layer.hold(
                    f"dedicated_cgroup:{service}",
                    "dedicated live cgroup custody is not proven",
                    observed=cgroup_text,
                )
        return pid, cgroup

    def collect_privileged_runtime(self) -> None:
        mounts_layer = self._layer("root_linux_read_only_bind_mounts")
        process_layer = self._layer("process_identity_and_cgroup")
        egress_layer = self._layer("egress_boot_evidence")
        high_water_layer = self._layer("high_water_authority")
        if self.shell_uid != 0:
            reason = "preexisting adbd is not root; verifier will not invoke adb root"
            for layer in (mounts_layer, process_layer, egress_layer, high_water_layer):
                layer.hold("privileged_evidence_unavailable", reason, observed=self.shell_uid)
            return

        daemon_pid, _ = self._collect_process(
            process_layer,
            "trillionnium_root_linux_daemon",
            "u:r:trillionnium_agentd:s0",
        )
        self._collect_process(
            process_layer,
            "trillionnium_direct_operation_custody_high_water",
            "u:r:trillionnium_direct_operation_custody_high_water:s0",
        )

        mountinfo: dict[str, dict[str, Any]] = {}
        if daemon_pid is None:
            mounts_layer.hold("daemon_mountinfo", "daemon PID is unavailable")
        else:
            raw_mountinfo = _read_call(
                mounts_layer,
                "daemon_mountinfo_read",
                lambda: self.client.cat(f"/proc/{daemon_pid}/mountinfo", maximum=MAX_JSON_BYTES),
            )
            if raw_mountinfo is not None:
                try:
                    mountinfo = parse_mountinfo(raw_mountinfo)
                except ConformanceError as exc:
                    mounts_layer.fail("daemon_mountinfo_parse", str(exc))
                else:
                    mounts_layer.add("daemon_mountinfo_parse", "PASS", observed=len(mountinfo))

        for spec in ARTIFACT_SPECS:
            if spec.root_target is None:
                continue
            try:
                expected_hash = _expected_artifact_hash(spec, self.contract)
            except ConformanceError as exc:
                mounts_layer.fail(f"bind_expectation:{spec.name}", str(exc))
                continue
            source_stat = _read_call(mounts_layer, f"bind_source_stat:{spec.name}", lambda spec=spec: self.client.stat(spec.source))
            target_stat = _read_call(mounts_layer, f"bind_target_stat:{spec.name}", lambda spec=spec: self.client.stat(spec.root_target or ""))
            target_hash = _read_call(mounts_layer, f"bind_target_hash:{spec.name}", lambda spec=spec: self.client.sha256(spec.root_target or ""))
            if target_hash is not None:
                mounts_layer.exact(f"bind_hash:{spec.name}", target_hash, expected_hash)
            if source_stat is not None and target_stat is not None:
                mounts_layer.exact(
                    f"bind_same_inode:{spec.name}",
                    [target_stat["device"], target_stat["inode"]],
                    [source_stat["device"], source_stat["inode"]],
                )
                mounts_layer.exact(f"bind_owner:{spec.name}", [target_stat["uid"], target_stat["gid"]], [0, 0])
                mounts_layer.exact(f"bind_mode:{spec.name}", target_stat["mode"], "0755")
                if spec.context is not None:
                    mounts_layer.exact(
                        f"bind_context:{spec.name}",
                        target_stat["selinux_context"],
                        spec.context,
                    )
            if mountinfo:
                try:
                    located_mount = find_mountinfo_entry(
                        mountinfo, spec.root_target or ""
                    )
                except ConformanceError as exc:
                    mounts_layer.fail(f"bind_mount_entry:{spec.name}", str(exc))
                    continue
                if located_mount is None:
                    mounts_layer.fail(f"bind_mount_entry:{spec.name}", "exact mountpoint is absent")
                else:
                    mount_path, mount = located_mount
                    mounts_layer.add(
                        f"bind_mount_entry:{spec.name}",
                        "PASS",
                        expected=list(
                            mountinfo_view_candidates(spec.root_target or "")
                        ),
                        observed=mount_path,
                    )
                    flags = set(mount["mount_options"]) | set(mount["super_options"])
                    for required_flag in ("ro", "nosuid", "nodev"):
                        mounts_layer.add(
                            f"bind_flag:{spec.name}:{required_flag}",
                            "PASS" if required_flag in flags else "FAIL",
                            expected=required_flag,
                            observed=sorted(flags),
                        )
        proc_source_stat = _read_call(
            mounts_layer,
            "proc_source_stat",
            lambda: self.client.stat(PROC_SOURCE),
        )
        proc_target_stat = _read_call(
            mounts_layer,
            "proc_target_stat",
            lambda: self.client.stat(PROC_ROOT_TARGET),
        )
        if proc_source_stat is not None and proc_target_stat is not None:
            mounts_layer.exact(
                "proc_same_inode",
                [proc_target_stat["device"], proc_target_stat["inode"]],
                [proc_source_stat["device"], proc_source_stat["inode"]],
            )
        proc_target = PROC_ROOT_TARGET
        if mountinfo:
            try:
                located_proc_mount = find_mountinfo_entry(mountinfo, proc_target)
            except ConformanceError as exc:
                mounts_layer.fail("proc_mount_entry", str(exc))
            else:
                if located_proc_mount is None:
                    mounts_layer.fail(
                        "proc_mount_entry", "exact rootfs /proc mount is absent"
                    )
                else:
                    proc_mount_path, proc_mount = located_proc_mount
                    mounts_layer.add(
                        "proc_mount_entry",
                        "PASS",
                        expected=list(mountinfo_view_candidates(proc_target)),
                        observed=proc_mount_path,
                    )
                    flags = set(proc_mount["mount_options"]) | set(
                        proc_mount["super_options"]
                    )
                    for required_flag in ("ro", "nosuid", "nodev", "noexec"):
                        mounts_layer.add(
                            f"proc_mount_flag:{required_flag}",
                            "PASS" if required_flag in flags else "FAIL",
                            expected=required_flag,
                            observed=sorted(flags),
                        )

        self._collect_egress(egress_layer)
        self._collect_high_water(high_water_layer)

    def _collect_egress(self, layer: EvidenceLayer) -> None:
        raw = _read_call(layer, "egress_evidence_read", lambda: self.client.cat(EGRESS_EVIDENCE_PATH, maximum=MAX_JSON_BYTES))
        boot_id_raw = _read_call(layer, "boot_id_read", lambda: self.client.cat(BOOT_ID_PATH, maximum=4096))
        if raw is None:
            return
        try:
            receipt = _strict_json_loads(raw, maximum=MAX_JSON_BYTES, label="egress evidence")
        except ConformanceError as exc:
            layer.fail("egress_evidence_parse", str(exc))
            return
        if not isinstance(receipt, dict):
            layer.fail("egress_evidence_shape", "top level is not an object")
            return
        layer.observations.update({"path": EGRESS_EVIDENCE_PATH, "size": len(raw), "sha256": _sha256_bytes(raw)})
        layer.exact("egress_schema", receipt.get("schema"), "org.trillionnium.agent-egress-boot-evidence.v2")
        layer.hold(
            "codex_only_egress_authority_contract",
            (
                "no reviewed Codex-only egress receipt producer and schema are "
                "bound; candidate observations cannot authorize a PASS"
            ),
            observed=receipt.get("decision"),
        )
        if boot_id_raw is not None:
            try:
                boot_id = boot_id_raw.decode("ascii", "strict").strip()
            except UnicodeError as exc:
                layer.fail("boot_id_shape", str(exc))
            else:
                valid = bool(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id))
                layer.add("boot_id_shape", "PASS" if valid else "FAIL", observed=boot_id)
                layer.exact("egress_boot_binding", receipt.get("boot_id_sha256"), _sha256_bytes(boot_id.encode("ascii")))
        artifacts = receipt.get("artifacts")
        if not isinstance(artifacts, dict):
            layer.fail("egress_artifacts", "artifacts object is absent")
        else:
            layer.exact("egress_artifact_set", sorted(artifacts), ["codex"])
            expected_pairs = {
                "codex": ("agent-codex-direct-v1", self.manifest.get("codex_integrity_launcher_sha256")),
            }
            for name, (agent_id, expected_hash) in expected_pairs.items():
                item = artifacts.get(name)
                if not isinstance(item, dict):
                    layer.fail(f"egress_artifact:{name}", "artifact evidence is absent")
                    continue
                layer.exact(f"egress_agent_id:{name}", item.get("agent_id"), agent_id)
                for key in ("expected_sha256", "source_sha256", "target_sha256"):
                    layer.exact(f"egress_hash:{name}:{key}", item.get(key), expected_hash)
                for key in ("same_inode", "mount_read_only", "mount_nosuid", "mount_nodev"):
                    layer.exact(f"egress_flag:{name}:{key}", item.get(key), True)
        firewall = receipt.get("firewall")
        if not isinstance(firewall, dict):
            layer.fail("egress_firewall", "firewall evidence is absent")
        else:
            for family in ("ipv4", "ipv6"):
                family_map = firewall.get(family)
                valid = (
                    isinstance(family_map, dict)
                    and set(family_map) == {"agent-codex-direct-v1"}
                )
                layer.add(f"egress_firewall:{family}", "PASS" if valid else "FAIL")

    def _collect_high_water(self, layer: EvidenceLayer) -> None:
        socket_stat = _read_call(layer, "high_water_socket_stat", lambda: self.client.stat(HIGH_WATER_SOCKET))
        if socket_stat is not None:
            layer.exact("high_water_socket_type", socket_stat["file_type"], "socket")
            layer.exact("high_water_socket_mode", socket_stat["mode"], "0600")
            layer.exact("high_water_socket_owner", [socket_stat["uid"], socket_stat["gid"]], [0, 0])
            layer.exact(
                "high_water_socket_context",
                socket_stat["selinux_context"],
                "u:object_r:trillionnium_direct_operation_custody_high_water_socket:s0",
            )
        raw = _read_call(layer, "high_water_state_read", lambda: self.client.cat(HIGH_WATER_STATE, maximum=MAX_JSON_BYTES))
        if raw is None:
            return
        try:
            state = _strict_json_loads(raw, maximum=MAX_JSON_BYTES, label="high-water state")
        except ConformanceError as exc:
            layer.fail("high_water_state_parse", str(exc))
            return
        if not isinstance(state, dict):
            layer.fail("high_water_state_shape", "top level is not an object")
            return
        layer.observations.update({"state_size": len(raw), "state_sha256": _sha256_bytes(raw)})
        layer.exact(
            "high_water_state_schema",
            state.get("schema"),
            "trillionnium.direct-operation-custody-high-water-authority.v2",
        )
        state_digest = state.get("state_sha256")
        valid_digest = isinstance(state_digest, str) and bool(SHA256_RE.fullmatch(state_digest)) and state_digest != "0" * 64
        layer.add(
            "high_water_embedded_state_digest",
            "PASS" if valid_digest else "FAIL",
            expected="nonzero lowercase SHA-256",
            observed=state_digest,
        )
        # Hardware rollback resistance is a production-promotion boundary, not
        # a claim made by this userdebug P0.1 baseline.  Keep it visible without
        # making an otherwise complete read-only userdebug observation
        # impossible to distinguish from missing device evidence.
        layer.observations["production_release_boundary"] = {
            "decision": "HOLD_HARDWARE_ROLLBACK_RESISTANCE_NOT_PROVEN",
            "detail": (
                "state is ordinary encrypted /data evidence; RPMB/KeyMint "
                "rollback resistance is not proven"
            ),
        }

    def action_plans(self) -> dict[str, Any]:
        plans: dict[str, Any] = {}
        templates = {
            "settings_effect": {
                "codex_trigger_interface": "absent_closed_hold",
                "effect_executed": False,
                "decision": "HOLD_NO_STABLE_AGENT_TRIGGER_INTERFACE",
            },
            "ack_compact_retire": {
                "android_ack_executed": False,
                "journal_compacted": False,
                "inbox_retired": False,
                "daemon_custody_source_closure": (
                    "complete_source_host_userdebug_only"
                ),
                "decision": "HOLD_PLAN_ONLY_PHYSICAL_DEVICE_EVIDENCE_NOT_COLLECTED",
            },
            "service_restart": {
                "service_restart_executed": False,
                "decision": "HOLD_MANUAL_MUTATION_OUTSIDE_VERIFIER",
            },
            "reboot": {
                "reboot_executed": False,
                "decision": "HOLD_MANUAL_MUTATION_OUTSIDE_VERIFIER",
            },
            "power_loss": {
                "power_loss_executed": False,
                "decision": "HOLD_MANUAL_PHYSICAL_TEST_OUTSIDE_VERIFIER",
            },
        }
        for name, template in templates.items():
            requested = bool(self.action_requests.get(name, False))
            plans[name] = {
                "requested": requested,
                "mode": "dry_run_plan_only" if requested else "not_requested",
                **template,
            }
        return plans

    def collect(self) -> dict[str, Any]:
        self.collect_contract()
        self.collect_identity()
        self.collect_manifest()
        self.collect_host_image()
        self.collect_artifacts()
        self.collect_init_and_selinux()
        self.collect_privileged_runtime()
        layer_dict = {name: layer.as_dict() for name, layer in self.layers.items()}
        baseline_decisions = [layer.decision for layer in self.layers.values()]
        if "FAIL" in baseline_decisions:
            decision = "FAIL_CLOSED_READ_ONLY_BASELINE"
        elif "HOLD" in baseline_decisions:
            decision = "HOLD_INCOMPLETE_READ_ONLY_EVIDENCE"
        else:
            decision = "PASS_READ_ONLY_BASELINE_P01_EFFECT_HOLD"
        command_audit = list(getattr(self.client, "command_audit", []))
        return {
            "schema": SCHEMA,
            "decision": decision,
            "generated_at_utc": _datetime.datetime.now(
                _datetime.timezone.utc
            ).isoformat(timespec="seconds"),
            "scope": {
                "product": self.expected_device,
                "variant": "userdebug",
                "collector_mode": "strict_read_only",
                "p01_effect_closure": (
                    "daemon_custody_complete_physical_device_evidence_hold"
                ),
            },
            "safety": {
                "device_write_performed": False,
                "flash_performed": False,
                "adb_root_performed": False,
                "settings_effect_performed": False,
                "android_ack_performed": False,
                "service_restart_performed": False,
                "reboot_performed": False,
                "power_loss_performed": False,
            },
            "layers": layer_dict,
            "release_boundaries": self.contract["release_boundaries"],
            "action_plans": self.action_plans(),
            "command_audit": command_audit,
            "evidence_sha256": "computed_over_object_without_this_field",
        }


def finalize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    copy = dict(evidence)
    copy.pop("evidence_sha256", None)
    evidence["evidence_sha256"] = _sha256_bytes(_canonical_json_bytes(copy))
    return evidence


def _open_output_parent(parent: Path) -> int:
    if not parent.is_absolute():
        raise ConformanceError("output path must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise ConformanceError("invalid output parent component")
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_new_output(path_value: str | os.PathLike[str], data: bytes) -> None:
    path = Path(path_value)
    if not path.is_absolute():
        raise ConformanceError("output path must be absolute")
    if not OUTPUT_NAME_RE.fullmatch(path.name):
        raise ConformanceError("output filename has an invalid shape")
    try:
        parent_fd = _open_output_parent(path.parent)
    except OSError as exc:
        raise ConformanceError(f"cannot securely open output parent: {exc}") from exc
    descriptor: int | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise ConformanceError(f"refusing to create output: {exc}") from exc
        opened = os.fstat(descriptor)
        if not stat_module.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ConformanceError("new output is not one singly linked regular file")
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise ConformanceError("short output write")
            written += count
        os.fsync(descriptor)
        os.fsync(parent_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _resolve_adb(value: str | None) -> str:
    if value is not None:
        return value
    discovered = shutil.which("adb")
    if discovered is None:
        raise ConformanceError("adb was not found; supply an absolute --adb path")
    return discovered


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect strict read-only Android P0.1 device evidence"
    )
    parser.add_argument("--adb", help="absolute, non-symlink adb executable")
    parser.add_argument("--serial", required=True, help="exact adb device serial")
    parser.add_argument(
        "--contract",
        required=True,
        help="absolute measured expectation-contract JSON path",
    )
    parser.add_argument(
        "--expected-contract-sha256",
        required=True,
        help="independently supplied lowercase SHA-256 pin for --contract",
    )
    parser.add_argument("--system-ext-image", help="optional host system_ext.img")
    parser.add_argument("--output", help="new absolute evidence JSON path; never overwritten")
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--plan-settings-effect", action="store_true")
    parser.add_argument("--plan-ack-compact-retire", action="store_true")
    parser.add_argument("--plan-service-restart", action="store_true")
    parser.add_argument("--plan-reboot", action="store_true")
    parser.add_argument("--plan-power-loss", action="store_true")
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    _validate_serial(args.serial)
    if not SHA256_RE.fullmatch(args.expected_contract_sha256):
        raise ConformanceError(
            "expected conformance contract hash must be lowercase SHA-256"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _validate_args(args)
        contract, contract_measurement = load_expectation_contract(
            args.contract, args.expected_contract_sha256
        )
        client = AdbClient(_resolve_adb(args.adb), args.serial)
        collector = DeviceCollector(
            client,
            contract=contract,
            contract_measurement=contract_measurement,
            system_ext_image=args.system_ext_image,
            action_requests={
                "settings_effect": args.plan_settings_effect,
                "ack_compact_retire": args.plan_ack_compact_retire,
                "service_restart": args.plan_service_restart,
                "reboot": args.plan_reboot,
                "power_loss": args.plan_power_loss,
            },
        )
        evidence = finalize_evidence(collector.collect())
        encoded = json.dumps(evidence, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        if args.output:
            write_new_output(args.output, encoded)
        else:
            sys.stdout.buffer.write(encoded)
        return 0 if evidence["decision"].startswith("PASS_") else 2
    except (ConformanceError, OSError, UnicodeError) as exc:
        print(f"android_p01_device_conformance: FAIL_CLOSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
