#!/usr/bin/env python3
"""Run the trusted desktop-only Android build and device smoke lane.

The control repository is small; the Android checkout is not.  This tool
therefore treats the canonical external disk as part of the build contract and
fails closed when the disk, manifest, project heads, overlay, build output, or
device identity is not exactly what the workflow expects.

The ``run`` command performs one serialized transaction:

1. validate the GitHub control checkout and the pinned 1,172-project Android
   manifest;
2. validate and materialize the checked-in ``android-integration/working-tree``
   overlay, retaining recoverable backups of files that would change;
3. build the fixed ``trillionnium_fogos-bp4a-userdebug`` target and its four
   installable Trillionnium APKs, then verify the target-files ZIP and APK
   package/signature metadata; and
4. run a bounded, allowlisted ``adb install`` plus launcher/package smoke on
   the one approved handset.

Only the final APK install and the fixed app launch/force-stop operations are
device mutations.  There is deliberately no ``adb root``, ``push``, remount,
reboot, fastboot, OTA, partition, shell command supplied by the repository, or
automatic cleanup.  Framework, APEX, kernel, sepolicy, and other system-image
changes still require a separately reviewed image/OTA lane; this APK lane does
not pretend to update those bytes.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Iterable, Iterator, Sequence
import xml.etree.ElementTree as ET
import zipfile


SCHEMA = "org.trillionnium.android-ci.desktop-build-device.v1"
MATERIALIZATION_SCHEMA = "org.trillionnium.android-ci.desktop-materialization.v1"
FAILURE_SCHEMA = "org.trillionnium.android-ci.desktop-failure.v1"

DEFAULT_EXTERNAL_ROOT = Path("/data/toshiba-dev/TrillionniumOS")
DEFAULT_ANDROID_ROOT = (
    DEFAULT_EXTERNAL_ROOT
    / "rootfs/home/qian-qi/android/lineage-fogos"
)
DEFAULT_RUNS_ROOT = DEFAULT_EXTERNAL_ROOT / ".android-ci-runs"
DEFAULT_LOCK = DEFAULT_EXTERNAL_ROOT / ".android-ci-desktop.lock"
EXTERNAL_UUID = "63df6e1a-baf3-4680-8bbb-8019fb025341"
MANIFEST_REL = Path(".repo/manifests/trillionnium-fogos.xml")
CONTROL_MANIFEST_REL = Path(
    "android-integration/manifest/manifests/trillionnium-fogos.xml"
)
CAPTURE_REL = Path("android-integration/manifest/CAPTURE.txt")
STATUS_REL = Path("android-integration/PROJECT_STATUS.tsv")
OVERLAY_ROOT_REL = Path("android-integration/working-tree")
PRODUCT = "trillionnium_fogos-bp4a-userdebug"
PRODUCT_DEVICE = "fogos"
BUILD_TYPE = "userdebug"
SDK = "36"
ALLOWED_SERIAL = "ZY32JLVHGN"
DEFAULT_ADB = Path("/opt/android-sdk/platform-tools/adb")
MIN_FREE_GIB = 400
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_LOG_BYTES = 128 * 1024 * 1024
MAX_APK_BYTES = 512 * 1024 * 1024
MAX_TARGET_FILES_BYTES = 32 * 1024 * 1024 * 1024
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
PORTABLE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._+@=-]+$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")

# These are the only APKs that this lane may install.  They are all selected
# by vendor/trillionnium/config/common.mk in the userdebug product.  The
# target-files archive remains the source of bytes; a path found elsewhere is
# rejected.
APK_SPECS: tuple[dict[str, str], ...] = (
    {
        "module": "TrillionniumAiShell",
        "package": "org.trillionnium.aishell",
        "activity": "org.trillionnium.aishell/.AiShellActivity",
    },
    {
        "module": "TrillionniumAiAuthority",
        "package": "org.trillionnium.aiauthority",
        "activity": "",
    },
    {
        "module": "TrillionniumCapabilityLeaseIssuer",
        "package": "org.trillionnium.capabilitylease",
        "activity": "",
    },
    {
        "module": "TrillionniumAgentAccessibility",
        "package": "org.trillionnium.agentaccessibility",
        "activity": "",
    },
)
BUILD_TARGETS: tuple[str, ...] = (
    *(item["module"] for item in APK_SPECS),
    "TrillionniumAiShellAgentProviderSecurityContractTest",
    "TrillionniumAiAuthoritySecurityContractsTest",
    "TrillionniumCapabilityLeaseIssuerContractTest",
    "TrillionniumAgentAccessibilityContractTest",
    "target-files-package",
)


class CiError(RuntimeError):
    """A malformed input, unsafe path, failed gate, or build/device error."""


@dataclass(frozen=True)
class OverlayEntry:
    project: str
    project_head: str
    status: str
    path: str
    sha256: str

    @property
    def relative_path(self) -> str:
        return f"{self.project}/{self.path}"


@dataclass(frozen=True)
class SourceContext:
    control_root: Path
    android_root: Path
    external_root: Path
    run_root: Path
    source_commit: str
    source_tree: str
    capture: dict[str, str]
    entries: tuple[OverlayEntry, ...]
    overlay_digest: str
    manifest_sha256: str
    project_heads: dict[str, str]
    free_bytes: int


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _assert_no_symlink_components(path: Path, *, allow_missing_final: bool = False) -> None:
    """Reject symlinked parents before a path is opened or replaced."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor or os.sep)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for index, component in enumerate(parts):
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_final and index == len(parts) - 1:
                return
            # A missing parent is safe to create later; subsequent components
            # cannot currently be a symlink below it.
            return
        except OSError as error:
            raise CiError(f"cannot inspect path component {current}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise CiError(f"symlinked path component is forbidden: {current}")


def _assert_relative(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise CiError(f"{label} is not a portable relative path")
    if value.startswith("/") or value.endswith("/"):
        raise CiError(f"{label} must be relative and canonical")
    pieces = value.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise CiError(f"{label} contains an unsafe component")
    if any(PORTABLE_COMPONENT_RE.fullmatch(piece) is None for piece in pieces):
        raise CiError(f"{label} contains an unsupported component")
    return value


def _assert_under(parent: Path, child: Path, label: str) -> None:
    parent_abs = Path(os.path.abspath(os.fspath(parent)))
    child_abs = Path(os.path.abspath(os.fspath(child)))
    try:
        child_abs.relative_to(parent_abs)
    except ValueError as error:
        raise CiError(f"{label} escapes the external project root: {child_abs}") from error


def _regular_file(path: Path, label: str, *, maximum: int | None = None) -> os.stat_result:
    _assert_no_symlink_components(path)
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise CiError(f"{label} is unavailable: {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CiError(f"{label} must be a non-symlink regular file: {path}")
    if metadata.st_nlink != 1:
        raise CiError(f"{label} must not be a hard-link alias: {path}")
    if maximum is not None and not 1 <= metadata.st_size <= maximum:
        raise CiError(f"{label} size is outside the allowed range: {path}")
    return metadata


def sha256_file(path: Path, label: str, *, maximum: int | None = None) -> str:
    before = _regular_file(path, label, maximum=maximum)
    digest = hashlib.sha256()
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise CiError(f"cannot open {label}: {path}: {error}") from error
    observed = 0
    try:
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            observed += len(block)
            if maximum is not None and observed > maximum:
                raise CiError(f"{label} grew beyond its size ceiling: {path}")
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    if _identity(before) != _identity(after) or observed != before.st_size:
        raise CiError(f"{label} changed while measured: {path}")
    return digest.hexdigest()


def _read_text(path: Path, label: str, maximum: int = MAX_CAPTURE_BYTES) -> str:
    _regular_file(path, label, maximum=maximum)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CiError(f"cannot read {label}: {path}: {error}") from error
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CiError(f"{label} is not UTF-8: {path}") from error


def _write_exclusive(path: Path, value: Any, *, mode: int = 0o600) -> None:
    _assert_no_symlink_components(path.parent)
    if path.exists() or path.is_symlink():
        raise CiError(f"refusing to overwrite receipt: {path}")
    if not path.parent.is_dir():
        raise CiError(f"receipt parent is not a directory: {path.parent}")
    encoded = canonical_json(value)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise CiError(f"cannot write receipt {path}: {error}") from error


def _capture_output(value: str, maximum: int = MAX_CAPTURE_BYTES) -> str:
    value = value.replace("\x00", "\\0")
    raw = value.encode("utf-8", errors="replace")
    if len(raw) <= maximum:
        return value
    return raw[:maximum].decode("utf-8", errors="replace") + "…[truncated]"


def _run_checked(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise CiError(f"command timed out: {' '.join(command)}") from error
    except OSError as error:
        raise CiError(f"cannot execute {' '.join(command)}: {error}") from error
    return completed.returncode, completed.stdout, completed.stderr


def _git(
    cwd: Path,
    arguments: Sequence[str],
    *,
    timeout: float = 90.0,
    strip_output: bool = True,
) -> str:
    rc, stdout, stderr = _run_checked(["git", *arguments], cwd=cwd, timeout=timeout)
    if rc != 0:
        detail = _capture_output(stderr.strip() or stdout.strip())
        raise CiError(f"git {' '.join(arguments)} failed in {cwd}: {detail}")
    return stdout.strip() if strip_output else stdout.rstrip("\n")


def _read_capture(control_root: Path) -> dict[str, str]:
    path = control_root / CAPTURE_REL
    raw = _read_text(path, "manifest capture", maximum=64 * 1024)
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] in values:
            raise CiError("manifest capture has duplicate or malformed fields")
        values[fields[0]] = fields[1]
    required = {
        "checkout_root",
        "manifest_file",
        "manifest_sha256",
        "project_count",
        "captured_at",
    }
    if set(values) != required:
        raise CiError(
            f"manifest capture keys differ: missing={sorted(required - set(values))} "
            f"unknown={sorted(set(values) - required)}"
        )
    if SHA256_RE.fullmatch(values["manifest_sha256"]) is None:
        raise CiError("manifest capture SHA-256 is malformed")
    if values["manifest_file"] != str(MANIFEST_REL):
        raise CiError("manifest capture points at an unexpected manifest path")
    if values["project_count"] != "1172":
        raise CiError("the desktop lane only accepts the frozen 1,172-project manifest")
    return values


def _load_overlay(control_root: Path) -> tuple[tuple[OverlayEntry, ...], dict[str, str]]:
    path = control_root / STATUS_REL
    _regular_file(path, "overlay status", maximum=8 * 1024 * 1024)
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream, delimiter="\t")
            expected = {"project", "project_head", "status", "path", "sha256"}
            if set(reader.fieldnames or ()) != expected:
                raise CiError("overlay status header is not the reviewed schema")
            rows: list[OverlayEntry] = []
            seen: set[str] = set()
            heads: dict[str, str] = {}
            for raw in reader:
                if any(value is None for value in raw.values()):
                    raise CiError("overlay status contains a short row")
                project = _assert_relative(raw["project"], "overlay project")
                relative = _assert_relative(raw["path"], "overlay path")
                head = raw["project_head"]
                if SHA1_RE.fullmatch(head) is None:
                    raise CiError(f"overlay project head is malformed: {project}")
                digest = raw["sha256"]
                if SHA256_RE.fullmatch(digest) is None:
                    raise CiError(f"overlay digest is malformed: {project}/{relative}")
                key = f"{project}/{relative}"
                if key in seen:
                    raise CiError(f"duplicate overlay path: {key}")
                seen.add(key)
                previous = heads.setdefault(project, head)
                if previous != head:
                    raise CiError(f"project head changes inside overlay: {project}")
                rows.append(OverlayEntry(project, head, raw["status"], relative, digest))
    except OSError as error:
        raise CiError(f"cannot read overlay status: {path}: {error}") from error
    if not rows:
        raise CiError("overlay status is empty")
    return tuple(rows), heads


def _overlay_digest(entries: Sequence[OverlayEntry]) -> str:
    value = [
        {
            "path": entry.relative_path,
            "project_head": entry.project_head,
            "status": entry.status,
            "sha256": entry.sha256,
        }
        for entry in sorted(entries, key=lambda item: item.relative_path)
    ]
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _validate_control_checkout(
    control_root: Path,
    expected_commit: str | None,
) -> tuple[str, str]:
    _assert_no_symlink_components(control_root)
    if not control_root.is_dir():
        raise CiError(f"control checkout is not a directory: {control_root}")
    commit = _git(control_root, ["rev-parse", "--verify", "HEAD^{commit}"])
    tree = _git(control_root, ["rev-parse", "--verify", "HEAD^{tree}"])
    if SHA1_RE.fullmatch(commit) is None or SHA1_RE.fullmatch(tree) is None:
        raise CiError("control checkout returned an invalid Git identity")
    if expected_commit:
        if COMMIT_RE.fullmatch(expected_commit) is None:
            raise CiError("expected source commit is malformed")
        if not commit.startswith(expected_commit):
            raise CiError(f"control checkout is {commit}, expected {expected_commit}")
    dirty = _git(control_root, ["status", "--porcelain=v1", "--untracked-files=all"])
    if dirty:
        raise CiError("control checkout is dirty; refusing to build unreviewed bytes")
    return commit, tree


def _mounted_uuid(path: Path) -> str:
    rc, stdout, stderr = _run_checked(
        ["findmnt", "-no", "UUID", "-T", str(path)], timeout=15.0
    )
    if rc != 0:
        raise CiError(f"findmnt could not identify the external mount: {_capture_output(stderr)}")
    value = stdout.strip()
    if not value:
        raise CiError(f"findmnt returned no UUID for {path}")
    return value


def _free_bytes(path: Path) -> int:
    try:
        stats = os.statvfs(path)
    except OSError as error:
        raise CiError(f"cannot stat filesystem for {path}: {error}") from error
    return int(stats.f_bavail) * int(stats.f_frsize)


def _verify_manifest(
    control_root: Path,
    android_root: Path,
    capture: dict[str, str],
) -> str:
    manifest = android_root / MANIFEST_REL
    frozen = control_root / CONTROL_MANIFEST_REL
    expected = capture["manifest_sha256"]
    if sha256_file(frozen, "frozen control manifest", maximum=64 * 1024 * 1024) != expected:
        raise CiError("control manifest does not match CAPTURE.txt")
    if sha256_file(manifest, "Android manifest", maximum=64 * 1024 * 1024) != expected:
        raise CiError("Android checkout manifest does not match the pinned capture")
    try:
        root = ET.fromstring(manifest.read_bytes())
    except (OSError, ET.ParseError) as error:
        raise CiError(f"Android manifest is not valid XML: {manifest}") from error
    projects = root.findall("project")
    if len(projects) != int(capture["project_count"]):
        raise CiError(
            f"Android manifest has {len(projects)} projects, expected {capture['project_count']}"
        )
    pointer = android_root / ".repo/manifest.xml"
    if pointer.is_symlink():
        target = pointer.resolve(strict=False)
        if not str(target).startswith(str((android_root / ".repo").resolve()) + os.sep):
            raise CiError(".repo/manifest.xml symlink escapes .repo")
    if not pointer.exists():
        raise CiError("Android checkout has no .repo/manifest.xml pointer")
    pointer_sha = sha256_file(
        pointer,
        "resolved Android manifest pointer",
        maximum=64 * 1024 * 1024,
    )
    if pointer_sha != expected:
        # Repo normally keeps a small include wrapper at .repo/manifest.xml;
        # the captured revision is the included manifest itself.  Accept only
        # that exact one-file include, never an arbitrary manifest assembled
        # by the runner.
        try:
            pointer_root = ET.fromstring(pointer.read_bytes())
        except (OSError, ET.ParseError) as error:
            raise CiError(".repo/manifest.xml is neither the pinned manifest nor a valid include wrapper") from error
        includes = pointer_root.findall("include")
        if len(includes) != 1 or includes[0].attrib.get("name") != "trillionnium-fogos.xml":
            raise CiError(".repo/manifest.xml include wrapper is not the pinned fogos manifest")
    return expected


def _project_status_paths(
    project_dir: Path,
    expected: set[str],
    *,
    require_all: bool = False,
) -> dict[str, str]:
    output = _git(
        project_dir,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        timeout=180.0,
        strip_output=False,
    )
    actual: dict[str, str] = {}
    for line in output.splitlines():
        if len(line) < 4:
            raise CiError(f"malformed Git status in {project_dir}: {line!r}")
        status = line[:2]
        value = line[3:]
        if " -> " in value:
            value = value.split(" -> ", 1)[1]
        # Python bytecode is deliberately outside the checked-in Android
        # overlay and is harmless build-tool noise.  The source tree may have
        # been inspected by a local test before the CI job starts.
        if "__pycache__" in value.split("/") and value.endswith(".pyc"):
            continue
        value = _assert_relative(value, f"Git status path in {project_dir}")
        actual[value] = status
    unknown = set(actual) - expected
    missing = expected - set(actual)
    if unknown or (require_all and missing):
        raise CiError(
            f"undeclared Android dirty paths in {project_dir}: "
            f"unknown={sorted(unknown)} missing={sorted(missing) if require_all else []}"
        )
    return actual


def _verify_project_heads(
    android_root: Path,
    entries: Sequence[OverlayEntry],
    *,
    require_overlay_status: bool = False,
) -> dict[str, str]:
    grouped: dict[str, set[str]] = {}
    expected_heads: dict[str, str] = {}
    for entry in entries:
        grouped.setdefault(entry.project, set()).add(entry.path)
        expected_heads[entry.project] = entry.project_head
    observed: dict[str, str] = {}
    for project, expected_paths in sorted(grouped.items()):
        project_dir = android_root / project
        _assert_no_symlink_components(project_dir)
        if not project_dir.is_dir():
            raise CiError(f"Android project directory is missing: {project_dir}")
        head = _git(project_dir, ["rev-parse", "--verify", "HEAD^{commit}"], timeout=180.0)
        if head != expected_heads[project]:
            raise CiError(
                f"Android project {project} is at {head}, expected {expected_heads[project]}"
            )
        _project_status_paths(
            project_dir,
            expected_paths,
            require_all=require_overlay_status,
        )
        observed[project] = head
    return observed


def _verify_overlay_sources(
    control_root: Path,
    entries: Sequence[OverlayEntry],
) -> None:
    overlay_root = control_root / OVERLAY_ROOT_REL
    for entry in entries:
        source = overlay_root / entry.project / entry.path
        _assert_under(overlay_root, source, "overlay source")
        if sha256_file(source, f"overlay source {entry.relative_path}", maximum=512 * 1024 * 1024) != entry.sha256:
            raise CiError(f"overlay source digest mismatch: {entry.relative_path}")


def _machine_snapshot() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node(),
    }


def _validate_adb_path(path: Path) -> Path:
    candidate = path
    if "/" not in str(candidate):
        located = shutil.which(str(candidate))
        if located is None:
            raise CiError(f"ADB executable is not on PATH: {candidate}")
        candidate = Path(located)
    resolved = candidate.resolve(strict=True)
    metadata = _regular_file(resolved, "ADB executable")
    if not os.access(resolved, os.X_OK) or not stat.S_ISREG(metadata.st_mode):
        raise CiError(f"ADB executable is not executable: {candidate}")
    return resolved


def _validate_roots(
    external_root: Path,
    android_root: Path,
    control_root: Path,
    run_root: Path,
    *,
    skip_mount_check: bool,
    min_free_gib: int,
) -> int:
    if min_free_gib < 0:
        raise CiError("minimum free space cannot be negative")
    _assert_no_symlink_components(external_root)
    _assert_under(external_root, android_root, "Android root")
    _assert_under(external_root, control_root, "control root")
    _assert_under(external_root, run_root, "run root")
    if not external_root.is_dir() or not android_root.is_dir() or not control_root.is_dir():
        raise CiError("external, Android, or control root is not a directory")
    if not skip_mount_check:
        if _mounted_uuid(external_root).lower() != EXTERNAL_UUID:
            raise CiError("external root is not mounted from the canonical UUID")
        if _mounted_uuid(android_root).lower() != EXTERNAL_UUID:
            raise CiError("Android root is not on the canonical external UUID")
    free = _free_bytes(external_root)
    required = min_free_gib * 1024 * 1024 * 1024
    if free < required:
        raise CiError(
            f"external disk has {free / 1024**3:.1f} GiB free; "
            f"the full build gate requires {min_free_gib} GiB"
        )
    return free


def _active_build_processes(external_root: Path) -> list[dict[str, Any]]:
    """Find an existing Android build before changing the shared checkout."""

    matches: list[dict[str, Any]] = []
    estate_text = str(external_root)
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return matches
    executable_names = {"ninja", "make", "m", "soong_ui", "soong_ui.bash"}
    for item in entries:
        if not item.name.isdigit():
            continue
        pid = int(item.name)
        if pid == os.getpid():
            continue
        try:
            raw = (item / "cmdline").read_bytes().replace(b"\x00", b" ")
            command = raw.decode("utf-8", errors="replace").strip()
            executable = os.path.basename(os.readlink(item / "exe"))
            cwd = os.readlink(item / "cwd")
        except (OSError, UnicodeError):
            continue
        if not command:
            continue
        path_hit = estate_text in command or estate_text in cwd or "g1-android-shadow" in command
        if not path_hit:
            continue
        is_build = executable in executable_names
        if executable in {"bash", "sh"}:
            is_build = (
                "soong_ui.bash" in command
                or "target-files-package" in command
                or "ninja -d" in command
            )
        if is_build:
            matches.append({"pid": pid, "executable": executable, "command": _capture_output(command)})
    return matches


def _acquire_lock(path: Path) -> int:
    _assert_no_symlink_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_symlink_components(path.parent)
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError) as error:
        try:
            os.close(descriptor)  # type: ignore[possibly-undefined]
        except (OSError, UnboundLocalError):
            pass
        raise CiError(f"another desktop Android lane holds the lock: {path}") from error
    return descriptor


def _release_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _preflight(
    *,
    control_root: Path,
    android_root: Path,
    external_root: Path,
    run_root: Path,
    expected_commit: str | None,
    min_free_gib: int,
    skip_mount_check: bool,
    check_active_build: bool = True,
) -> SourceContext:
    free = _validate_roots(
        external_root,
        android_root,
        control_root,
        run_root,
        skip_mount_check=skip_mount_check,
        min_free_gib=min_free_gib,
    )
    if check_active_build:
        active = _active_build_processes(external_root)
        if active:
            raise CiError(
                "an Android build is already active; refusing to mutate the checkout: "
                + json.dumps(active, ensure_ascii=True, sort_keys=True)
            )
    source_commit, source_tree = _validate_control_checkout(control_root, expected_commit)
    capture = _read_capture(control_root)
    entries, _ = _load_overlay(control_root)
    _verify_overlay_sources(control_root, entries)
    manifest_sha = _verify_manifest(control_root, android_root, capture)
    heads = _verify_project_heads(android_root, entries)
    required = (
        android_root / "build/envsetup.sh",
        android_root / "build/soong/soong_ui.bash",
        android_root / "device/motorola/fogos/AndroidProducts.mk",
        android_root / "device/motorola/fogos/trillionnium_fogos.mk",
    )
    for path in required:
        if not path.exists():
            raise CiError(f"required Android build entrypoint is missing: {path}")
    return SourceContext(
        control_root=control_root,
        android_root=android_root,
        external_root=external_root,
        run_root=run_root,
        source_commit=source_commit,
        source_tree=source_tree,
        capture=capture,
        entries=entries,
        overlay_digest=_overlay_digest(entries),
        manifest_sha256=manifest_sha,
        project_heads=heads,
        free_bytes=free,
    )


def _copy_regular(source: Path, destination: Path, label: str) -> None:
    source_meta = _regular_file(source, f"{label} source", maximum=512 * 1024 * 1024)
    _assert_no_symlink_components(destination.parent)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_symlink_components(destination.parent)
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise CiError(f"{label} destination is not a regular file: {destination}")
    temporary = destination.parent / f".android-ci-{os.getpid()}-{time.time_ns()}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            stat.S_IMODE(source_meta.st_mode) or 0o600,
        )
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.chmod(temporary, stat.S_IMODE(source_meta.st_mode))
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise CiError(f"cannot materialize {label}: {error}") from error


def _materialize(ctx: SourceContext) -> dict[str, Any]:
    backup_root = ctx.run_root / "backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    changed: list[dict[str, Any]] = []
    for entry in ctx.entries:
        source = ctx.control_root / OVERLAY_ROOT_REL / entry.project / entry.path
        destination = ctx.android_root / entry.project / entry.path
        _assert_under(ctx.control_root / OVERLAY_ROOT_REL, source, "overlay source")
        _assert_under(ctx.android_root, destination, "Android destination")
        _assert_no_symlink_components(destination.parent)
        current_digest: str | None = None
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file():
                raise CiError(f"Android destination is not a regular file: {destination}")
            current_digest = sha256_file(
                destination,
                f"existing Android file {entry.relative_path}",
                maximum=512 * 1024 * 1024,
            )
        if current_digest == entry.sha256:
            continue
        backup: str | None = None
        if destination.exists():
            backup_path = backup_root / entry.relative_path
            _assert_under(backup_root, backup_path, "backup path")
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            _copy_regular(destination, backup_path, f"backup {entry.relative_path}")
            backup = str(backup_path)
        _copy_regular(source, destination, f"overlay {entry.relative_path}")
        after = sha256_file(
            destination,
            f"materialized Android file {entry.relative_path}",
            maximum=512 * 1024 * 1024,
        )
        if after != entry.sha256:
            raise CiError(f"materialized overlay digest mismatch: {entry.relative_path}")
        changed.append(
            {
                "path": entry.relative_path,
                "previous_sha256": current_digest,
                "new_sha256": after,
                "backup": backup,
            }
        )
    # The post-materialization status is part of the source contract: every
    # declared overlay path must now be present, while no unrelated dirty path
    # may have appeared during the copy.
    _verify_project_heads(ctx.android_root, ctx.entries, require_overlay_status=True)
    receipt = {
        "schema": MATERIALIZATION_SCHEMA,
        "version": 1,
        "captured_at_utc": now_utc(),
        "source": {
            "commit": ctx.source_commit,
            "tree": ctx.source_tree,
            "manifest_sha256": ctx.manifest_sha256,
            "overlay_sha256": ctx.overlay_digest,
        },
        "android_root": str(ctx.android_root),
        "changed": changed,
        "changed_count": len(changed),
        "claim_ceiling": "CHECKED_IN_OVERLAY_MATERIALIZED_WITH_RECOVERABLE_BACKUPS",
    }
    _write_exclusive(ctx.run_root / "materialization.json", receipt)
    return receipt


def _limited_log(path: Path) -> tuple[Any, list[int], Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("wb")
    state = [0]

    def write(data: bytes) -> None:
        if state[0] >= MAX_LOG_BYTES:
            return
        remaining = MAX_LOG_BYTES - state[0]
        chunk = data[:remaining]
        stream.write(chunk)
        state[0] += len(chunk)

    return (stream, state, write)


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass


def _run_build(ctx: SourceContext, adb_path: Path, jobs: int, timeout_minutes: int) -> dict[str, Any]:
    if jobs < 1 or jobs > 48:
        raise CiError("build jobs must be between 1 and 48")
    if timeout_minutes < 1 or timeout_minutes > 72 * 60:
        raise CiError("build timeout must be between 1 minute and 72 hours")
    log_path = ctx.run_root / "build.log"
    log_stream, log_state, write_log = _limited_log(log_path)
    build_started = time.time_ns()
    product_out = ctx.android_root / "out/target/product" / PRODUCT_DEVICE
    target_dir = product_out / "obj/PACKAGING/target_files_intermediates"
    before: dict[str, tuple[int, int, int]] = {}
    if target_dir.is_dir():
        for candidate in target_dir.iterdir():
            if candidate.name.endswith(".zip") and "target_files" in candidate.name:
                if candidate.is_symlink() or not candidate.is_file():
                    raise CiError(f"unsafe pre-existing target-files candidate: {candidate}")
                metadata = candidate.stat()
                before[candidate.name] = (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    run_root = ctx.run_root
    tmp_root = run_root / "tmp"
    home_root = run_root / "home"
    cache_root = run_root / "cache"
    ccache_root = run_root / "ccache"
    for directory in (tmp_root, home_root, cache_root, ccache_root):
        directory.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home_root),
            "TMPDIR": str(tmp_root),
            "TMP": str(tmp_root),
            "TEMP": str(tmp_root),
            "XDG_CACHE_HOME": str(cache_root),
            "CCACHE_DIR": str(ccache_root),
            "ANDROID_BUILD_TOP": str(ctx.android_root),
            "OUT_DIR": str(ctx.android_root / "out"),
            "ANDROID_ROOT": str(ctx.android_root),
            "ANDROID_ADB_PATH": str(adb_path),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    quoted_targets = " ".join(BUILD_TARGETS)
    command_script = (
        "set -Eeuo pipefail\n"
        f"cd {shlex_quote(str(ctx.android_root))}\n"
        "source build/envsetup.sh\n"
        f"lunch {PRODUCT}\n"
        f"m -j{jobs} {quoted_targets}\n"
    )
    process = subprocess.Popen(
        ["bash", "--noprofile", "--norc", "-c", command_script],
        cwd=ctx.android_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout_minutes * 60
    try:
        assert process.stdout is not None
        while True:
            line = process.stdout.readline()
            if line:
                write_log(line)
                try:
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                except (BrokenPipeError, OSError):
                    pass
            elif process.poll() is not None:
                break
            elif time.monotonic() >= deadline:
                _terminate_process_group(process)
                raise CiError("Android build timed out; process group was terminated")
        returncode = process.wait()
    finally:
        log_stream.flush()
        os.fsync(log_stream.fileno())
        log_stream.close()
    if returncode != 0:
        raise CiError(f"Android build failed with exit code {returncode}")
    if not target_dir.is_dir():
        raise CiError(f"target-files output directory is missing: {target_dir}")
    candidates = sorted(
        candidate
        for candidate in target_dir.iterdir()
        if candidate.name.endswith(".zip") and "target_files" in candidate.name
    )
    if len(candidates) != 1:
        raise CiError(f"expected exactly one target-files archive, found {len(candidates)}")
    target = candidates[0]
    metadata = _regular_file(target, "target-files archive", maximum=MAX_TARGET_FILES_BYTES)
    previous = before.get(target.name)
    if previous is not None and (
        previous[0] == metadata.st_ino
        and previous[1] == metadata.st_size
        and previous[2] >= build_started
    ):
        raise CiError("target-files archive was not refreshed by this build")
    target_sha = sha256_file(target, "target-files archive", maximum=MAX_TARGET_FILES_BYTES)
    zip_members = _verify_target_files_zip(target)
    apks = _extract_and_verify_apks(ctx, target, zip_members)
    receipt = {
        "schema": "org.trillionnium.android-ci.desktop-build.v1",
        "version": 1,
        "captured_at_utc": now_utc(),
        "source": {
            "commit": ctx.source_commit,
            "tree": ctx.source_tree,
            "manifest_sha256": ctx.manifest_sha256,
            "overlay_sha256": ctx.overlay_digest,
            "project_heads": ctx.project_heads,
        },
        "product": {
            "lunch": PRODUCT,
            "device": PRODUCT_DEVICE,
            "build_type": BUILD_TYPE,
            "sdk": SDK,
            "jobs": jobs,
            "targets": list(BUILD_TARGETS),
        },
        "target_files": {
            "path": str(target),
            "size": metadata.st_size,
            "sha256": target_sha,
            "zip_member_count": len(zip_members),
        },
        "apks": apks,
        "log": {"path": str(log_path), "bytes_retained": log_state[0]},
        "claim_ceiling": "UNSIGNED_USERDEBUG_TARGET_FILES_AND_APK_METADATA_VERIFIED",
    }
    _write_exclusive(ctx.run_root / "build-receipt.json", receipt)
    return receipt


def shlex_quote(value: str) -> str:
    """Small local shell quoting helper (keeps the build command reviewable)."""

    return "'" + value.replace("'", "'\\''") + "'"


def _verify_target_files_zip(path: Path) -> tuple[zipfile.ZipInfo, ...]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = tuple(archive.infolist())
            if not infos or len(infos) > 1_000_000:
                raise CiError("target-files ZIP member count is outside the safe range")
            names: set[str] = set()
            for info in infos:
                name = info.filename
                if name in names:
                    raise CiError(f"duplicate target-files ZIP member: {name}")
                names.add(name)
                normalized_name = name[:-1] if name.endswith("/") else name
                if normalized_name.startswith("/") or "\\" in normalized_name or any(
                    piece in {"", ".", ".."} for piece in normalized_name.split("/")
                ):
                    raise CiError(f"unsafe target-files ZIP member: {name}")
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise CiError(f"symlink target-files ZIP member: {name}")
                if info.flag_bits & 0x1:
                    raise CiError(f"encrypted target-files ZIP member: {name}")
            for required in ("META/misc_info.txt", "META/apkcerts.txt"):
                if required not in names:
                    raise CiError(f"target-files ZIP is missing {required}")
            bad = archive.testzip()
            if bad is not None:
                raise CiError(f"target-files ZIP CRC failed at {bad}")
            return infos
    except zipfile.BadZipFile as error:
        raise CiError(f"target-files archive is not a valid ZIP: {path}") from error


def _locate_tool(android_root: Path, names: Sequence[str]) -> Path:
    candidates: list[Path] = []
    for base in (
        android_root / "out/host/linux-x86/bin",
        android_root / "prebuilts/build-tools/linux-x86/bin",
        Path("/opt/android-sdk/build-tools/36.1.0"),
        Path("/opt/android-sdk/build-tools/35.0.1"),
        Path("/opt/android-sdk/build-tools/34.0.0"),
    ):
        candidates.extend(base / name for name in names)
    for candidate in candidates:
        if candidate.exists() and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    for name in names:
        located = shutil.which(name)
        if located:
            return Path(located).resolve()
    raise CiError(f"required Android host tool is unavailable: {', '.join(names)}")


def _apk_badging(aapt2: Path, apk: Path) -> tuple[str, str | None]:
    rc, stdout, stderr = _run_checked(
        [str(aapt2), "dump", "badging", str(apk)], timeout=60.0
    )
    if rc != 0:
        raise CiError(f"aapt2 could not inspect {apk.name}: {_capture_output(stderr)}")
    match = re.search(r"^package: name='([^']+)'(?: versionCode='([^']+)')?", stdout, re.MULTILINE)
    if match is None:
        raise CiError(f"aapt2 returned no package metadata for {apk.name}")
    return match.group(1), match.group(2)


def _apk_signing(apksigner: Path, apk: Path) -> dict[str, Any]:
    rc, stdout, stderr = _run_checked(
        [str(apksigner), "verify", "--verbose", "--print-certs", str(apk)],
        timeout=120.0,
    )
    combined = stdout + "\n" + stderr
    if rc != 0:
        raise CiError(f"apksigner rejected {apk.name}: {_capture_output(combined)}")
    digests = sorted(
        set(
            match.lower()
            for match in re.findall(
                r"certificate SHA-256 digest:\s*([0-9A-Fa-f:]+)", combined
            )
        )
    )
    if not digests:
        raise CiError(f"apksigner returned no certificate digest for {apk.name}")
    return {
        "verified": True,
        "certificate_sha256": digests,
        "output": _capture_output(combined),
    }


def _extract_and_verify_apks(
    ctx: SourceContext,
    target: Path,
    infos: Sequence[zipfile.ZipInfo],
) -> list[dict[str, Any]]:
    names = [info.filename for info in infos]
    by_name = {info.filename: info for info in infos}
    aapt2 = _locate_tool(ctx.android_root, ("aapt2",))
    apksigner = _locate_tool(ctx.android_root, ("apksigner",))
    output_root = ctx.run_root / "apks"
    output_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    try:
        archive = zipfile.ZipFile(target, "r")
    except (OSError, zipfile.BadZipFile) as error:
        raise CiError(f"cannot reopen target-files archive: {target}") from error
    with archive:
        for spec in APK_SPECS:
            module = spec["module"]
            suffix = f"/{module}/{module}.apk"
            matches = [name for name in names if name.endswith(suffix)]
            if len(matches) != 1:
                raise CiError(
                    f"target-files must contain exactly one {module} APK, found {matches}"
                )
            member = matches[0]
            info = by_name[member]
            if info.file_size < 1 or info.file_size > MAX_APK_BYTES:
                raise CiError(f"APK member size is unsafe: {member}")
            destination = output_root / f"{module}.apk"
            if destination.exists() or destination.is_symlink():
                raise CiError(f"refusing to overwrite extracted APK: {destination}")
            with archive.open(info, "r") as source, destination.open("xb") as output:
                remaining = info.file_size
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise CiError(f"short ZIP member while extracting {member}")
                    output.write(block)
                    remaining -= len(block)
                output.flush()
                os.fsync(output.fileno())
            package, version_code = _apk_badging(aapt2, destination)
            if package != spec["package"] or PACKAGE_RE.fullmatch(package) is None:
                raise CiError(
                    f"{module} APK package is {package!r}, expected {spec['package']!r}"
                )
            signing = _apk_signing(apksigner, destination)
            digest = sha256_file(destination, f"extracted {module} APK", maximum=MAX_APK_BYTES)
            results.append(
                {
                    "module": module,
                    "package": package,
                    "version_code": version_code,
                    "target_files_member": member,
                    "path": str(destination),
                    "size": info.file_size,
                    "sha256": digest,
                    "signing": signing,
                }
            )
    return results


def _run_adb(
    adb: Path,
    serial: str,
    arguments: Sequence[str],
    *,
    timeout: float = 45.0,
) -> dict[str, Any]:
    command = [str(adb), "-s", serial, *arguments]
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
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
            "stderr": _capture_output(str(error)),
            "timed_out": False,
            "seconds": round(time.monotonic() - started, 3),
        }
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        stdout, stderr = process.communicate()
        return {
            "argv": command,
            "returncode": None,
            "stdout": _capture_output(stdout or ""),
            "stderr": _capture_output(stderr or ""),
            "timed_out": True,
            "seconds": round(time.monotonic() - started, 3),
        }
    return {
        "argv": command,
        "returncode": process.returncode,
        "stdout": _capture_output(stdout),
        "stderr": _capture_output(stderr),
        "timed_out": False,
        "seconds": round(time.monotonic() - started, 3),
    }


def _adb_ok(observation: dict[str, Any]) -> bool:
    return observation.get("returncode") == 0 and not observation.get("timed_out")


def _device_preflight(adb: Path, serial: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if serial != ALLOWED_SERIAL:
        raise CiError("device serial is not the fixed repository allowlist entry")
    observations: list[dict[str, Any]] = []
    version = _run_adb(adb, serial, ["version"])
    version["operation"] = "adb_version"
    observations.append(version)
    if not _adb_ok(version):
        raise CiError("adb version probe failed")
    states: list[str] = []
    for _ in range(3):
        state = _run_adb(adb, serial, ["get-state"])
        state["operation"] = "get_state"
        observations.append(state)
        states.append(state["stdout"].strip())
        if not _adb_ok(state) or state["stdout"].strip() != "device":
            raise CiError(f"device is not ready: state samples={states!r}")
    keys = (
        "ro.product.device",
        "ro.build.type",
        "ro.build.version.sdk",
        "ro.build.fingerprint",
        "ro.boot.slot_suffix",
        "ro.boot.verifiedbootstate",
        "sys.boot_completed",
        "ro.bootmode",
    )
    properties: dict[str, str] = {}
    for key in keys:
        observation = _run_adb(adb, serial, ["shell", "getprop", key])
        observation["operation"] = "getprop"
        observation["property"] = key
        observations.append(observation)
        value = observation["stdout"].strip()
        properties[key] = value
        if not _adb_ok(observation) or (not value and key != "ro.bootmode"):
            raise CiError(f"required device property is unavailable: {key}")
    if properties["ro.product.device"] != PRODUCT_DEVICE:
        raise CiError("connected device product does not match fogos")
    if properties["ro.build.type"] != BUILD_TYPE or properties["ro.build.version.sdk"] != SDK:
        raise CiError("connected device build type or SDK does not match the product lane")
    if properties["sys.boot_completed"] != "1":
        raise CiError("connected device has not completed boot")
    if properties["ro.bootmode"] not in {"", "unknown", "normal"}:
        raise CiError(f"device is in an unsafe boot mode: {properties['ro.bootmode']}")
    enforcing = _run_adb(adb, serial, ["shell", "getenforce"])
    enforcing["operation"] = "getenforce"
    observations.append(enforcing)
    if not _adb_ok(enforcing) or enforcing["stdout"].strip() not in {"Enforcing", "Permissive"}:
        raise CiError("SELinux mode probe failed")
    uid = _run_adb(adb, serial, ["shell", "id", "-u"])
    uid["operation"] = "shell_uid"
    observations.append(uid)
    if not _adb_ok(uid) or not uid["stdout"].strip().isdigit():
        raise CiError("shell UID probe failed")
    battery = _run_adb(adb, serial, ["shell", "dumpsys", "battery"])
    battery["operation"] = "battery_read"
    observations.append(battery)
    data_space = _run_adb(adb, serial, ["shell", "df", "-k", "/data"])
    data_space["operation"] = "device_data_space_read"
    observations.append(data_space)
    logcat = _run_adb(adb, serial, ["shell", "logcat", "-d", "-t", "200"])
    logcat["operation"] = "baseline_logcat"
    observations.append(logcat)
    return observations, properties


def _package_dump(adb: Path, serial: str, package: str) -> dict[str, Any]:
    observation = _run_adb(adb, serial, ["shell", "dumpsys", "package", package])
    observation["operation"] = "package_dump"
    observation["package"] = package
    return observation


def _device_install_and_test(
    ctx: SourceContext,
    build_receipt: dict[str, Any],
    adb: Path,
    serial: str,
) -> dict[str, Any]:
    observations, properties = _device_preflight(adb, serial)
    apk_records = build_receipt["apks"]
    by_package = {record["package"]: record for record in apk_records}
    installed: list[dict[str, Any]] = []
    for spec in APK_SPECS:
        package = spec["package"]
        record = by_package[package]
        apk_path = Path(record["path"])
        _assert_under(ctx.run_root / "apks", apk_path, "APK install path")
        if apk_path.name != f"{record['module']}.apk" or not apk_path.is_file():
            raise CiError(f"APK install path is not the fixed extracted artifact: {apk_path}")
        path_probe = _run_adb(adb, serial, ["shell", "pm", "path", package])
        path_probe["operation"] = "package_path_before_install"
        path_probe["package"] = package
        observations.append(path_probe)
        dump_before = _package_dump(adb, serial, package)
        observations.append(dump_before)
        install = _run_adb(
            adb,
            serial,
            ["install", "-r", "-d", "--no-streaming", str(apk_path)],
            timeout=180.0,
        )
        install["operation"] = "apk_install"
        install["package"] = package
        install["artifact_sha256"] = record["sha256"]
        observations.append(install)
        if not _adb_ok(install) or "success" not in install["stdout"].lower():
            raise CiError(f"adb install failed for {package}")
        path_after = _run_adb(adb, serial, ["shell", "pm", "path", package])
        path_after["operation"] = "package_path_after_install"
        path_after["package"] = package
        observations.append(path_after)
        if not _adb_ok(path_after) or "package:" not in path_after["stdout"]:
            raise CiError(f"package-manager readback failed for {package}")
        dump_after = _package_dump(adb, serial, package)
        observations.append(dump_after)
        if not _adb_ok(dump_after) or package not in dump_after["stdout"]:
            raise CiError(f"package dump readback failed for {package}")
        installed.append(
            {
                "package": package,
                "artifact_sha256": record["sha256"],
                "path_before": path_probe["stdout"].strip(),
                "path_after": path_after["stdout"].strip(),
            }
        )
    shell_package = "org.trillionnium.aishell"
    force_stop = _run_adb(adb, serial, ["shell", "am", "force-stop", shell_package])
    force_stop["operation"] = "launcher_force_stop"
    force_stop["package"] = shell_package
    observations.append(force_stop)
    if not _adb_ok(force_stop):
        raise CiError("AiShell force-stop smoke failed")
    launch = _run_adb(
        adb,
        serial,
        ["shell", "am", "start", "-W", "-n", "org.trillionnium.aishell/.AiShellActivity"],
        timeout=90.0,
    )
    launch["operation"] = "launcher_start"
    launch["package"] = shell_package
    observations.append(launch)
    if not _adb_ok(launch) or "status: ok" not in launch["stdout"].lower():
        raise CiError("AiShell launcher activity did not start successfully")
    pid = _run_adb(adb, serial, ["shell", "pidof", shell_package])
    pid["operation"] = "launcher_pid_read"
    pid["package"] = shell_package
    observations.append(pid)
    final_logcat = _run_adb(adb, serial, ["shell", "logcat", "-d", "-t", "300"])
    final_logcat["operation"] = "post_test_logcat"
    observations.append(final_logcat)
    receipt = {
        "schema": "org.trillionnium.android-ci.desktop-device-test.v1",
        "version": 1,
        "captured_at_utc": now_utc(),
        "source": {
            "commit": ctx.source_commit,
            "tree": ctx.source_tree,
            "manifest_sha256": ctx.manifest_sha256,
            "overlay_sha256": ctx.overlay_digest,
            "target_files_sha256": build_receipt["target_files"]["sha256"],
        },
        "device": {
            "serial": serial,
            "properties": properties,
            "packages": installed,
        },
        "adb": {
            "path": str(adb),
            "allowlisted_mutations": [
                "install -r -d --no-streaming fixed APK",
                "shell am force-stop org.trillionnium.aishell",
                "shell am start -W -n org.trillionnium.aishell/.AiShellActivity",
            ],
            "forbidden_operations": [
                "root",
                "push",
                "remount",
                "reboot",
                "fastboot",
                "flash",
                "sideload",
                "shell setprop",
            ],
        },
        "mutation": {
            "install_performed": True,
            "launcher_started": True,
            "reboot_performed": False,
            "flash_or_fastboot_performed": False,
        },
        "observations": observations,
        "result": "PASS_APK_INSTALL_AND_LAUNCH_SMOKE",
        "claim_ceiling": (
            "FOUR_ALLOWLISTED_USERDEBUG_APKS_INSTALLED_AND_PACKAGE_READBACK_VERIFIED; "
            "AISHELL_LAUNCHER_SMOKE_ONLY; NO_SYSTEM_IMAGE_OR_OTA_CLAIM"
        ),
    }
    _write_exclusive(ctx.run_root / "device-receipt.json", receipt)
    return receipt


def _source_receipt(ctx: SourceContext) -> dict[str, Any]:
    return {
        "schema": "org.trillionnium.android-ci.desktop-source.v1",
        "version": 1,
        "captured_at_utc": now_utc(),
        "source": {
            "commit": ctx.source_commit,
            "tree": ctx.source_tree,
            "manifest_sha256": ctx.manifest_sha256,
            "overlay_sha256": ctx.overlay_digest,
            "project_heads": ctx.project_heads,
            "overlay_count": len(ctx.entries),
        },
        "paths": {
            "control_root": str(ctx.control_root),
            "android_root": str(ctx.android_root),
            "run_root": str(ctx.run_root),
        },
        "disk": {
            "external_uuid": EXTERNAL_UUID,
            "free_bytes_at_preflight": ctx.free_bytes,
        },
        "machine": _machine_snapshot(),
        "claim_ceiling": "EXACT_CONTROL_COMMIT_AND_PINNED_ANDROID_OVERLAY_VALIDATED",
    }


def _run_transaction(args: argparse.Namespace) -> int:
    external_root = Path(args.external_root).absolute()
    android_root = Path(args.android_root).absolute()
    control_root = Path(args.control_root).absolute()
    run_root = Path(args.run_root).absolute()
    phase = "startup"
    lock_descriptor: int | None = None
    storage_verified = False
    try:
        # Check the mount before creating the run directory or lock.  Otherwise
        # a missing external mount could make those paths on the system
        # filesystem, violating the desktop lane's no-main-disk contract.
        _assert_no_symlink_components(external_root)
        if not args.skip_mount_check:
            if _mounted_uuid(external_root).lower() != EXTERNAL_UUID:
                raise CiError("external root is not mounted from the canonical UUID")
            if _mounted_uuid(android_root).lower() != EXTERNAL_UUID:
                raise CiError("Android root is not on the canonical external UUID")
        _assert_under(external_root, run_root, "run root")
        _assert_under(external_root, Path(args.lock_path).absolute(), "lock path")
        _assert_no_symlink_components(run_root.parent)
        storage_verified = True
        run_root.mkdir(parents=True, exist_ok=True)
        _assert_no_symlink_components(run_root)
        (run_root / "logs").mkdir(exist_ok=True)
        lock_descriptor = _acquire_lock(Path(args.lock_path).absolute())
        phase = "preflight"
        adb = _validate_adb_path(Path(args.adb))
        expected_commit = args.source_commit or os.environ.get("GITHUB_SHA")
        context = _preflight(
            control_root=control_root,
            android_root=android_root,
            external_root=external_root,
            run_root=run_root,
            expected_commit=expected_commit,
            min_free_gib=args.min_free_gib,
            skip_mount_check=args.skip_mount_check,
        )
        _write_exclusive(run_root / "source-receipt.json", _source_receipt(context))
        phase = "materialize"
        _materialize(context)
        phase = "build"
        build_receipt = _run_build(context, adb, args.jobs, args.build_timeout_minutes)
        phase = "device-preflight-install-test"
        _device_install_and_test(context, build_receipt, adb, args.serial)
        final = {
            "schema": SCHEMA,
            "version": 1,
            "captured_at_utc": now_utc(),
            "result": "PASS_APK_INSTALL_AND_LAUNCH_SMOKE",
            "source_commit": context.source_commit,
            "source_tree": context.source_tree,
            "manifest_sha256": context.manifest_sha256,
            "overlay_sha256": context.overlay_digest,
            "target_files_sha256": build_receipt["target_files"]["sha256"],
            "device_serial": args.serial,
            "paths_external": True,
            "claim_ceiling": (
                "DESKTOP_EXTERNAL_DISK_BUILD_TO_ALLOWLISTED_APK_INSTALL_AND_AISHELL_SMOKE; "
                "NO_OTA_FLASH_OR_SYSTEM_IMAGE_CLAIM"
            ),
        }
        _write_exclusive(run_root / "final-receipt.json", final)
        print(json.dumps(final, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    except CiError as error:
        failure = {
            "schema": FAILURE_SCHEMA,
            "version": 1,
            "captured_at_utc": now_utc(),
            "result": "FAIL_CLOSED",
            "phase": phase,
            "error": str(error),
            "paths": {
                "external_root": str(external_root),
                "android_root": str(android_root),
                "control_root": str(control_root),
                "run_root": str(run_root),
            },
            "mutation": {
                "install_attempted": phase == "device-preflight-install-test",
                "reboot_performed": False,
                "flash_or_fastboot_performed": False,
            },
        }
        if storage_verified:
            try:
                _write_exclusive(run_root / "failure.json", failure)
            except CiError:
                pass
        print(f"android-ci-desktop-build: {error}", file=sys.stderr)
        return 2
    finally:
        if lock_descriptor is not None:
            _release_lock(lock_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "materialize", "run"))
    parser.add_argument("--external-root", default=str(DEFAULT_EXTERNAL_ROOT))
    parser.add_argument("--android-root", default=str(DEFAULT_ANDROID_ROOT))
    parser.add_argument("--control-root", required=True)
    parser.add_argument("--run-root", default=None)
    parser.add_argument("--lock-path", default=str(DEFAULT_LOCK))
    parser.add_argument("--adb", default=os.environ.get("ANDROID_ADB_PATH", str(DEFAULT_ADB)))
    parser.add_argument("--serial", default=os.environ.get("ANDROID_DEVICE_SERIAL", ALLOWED_SERIAL))
    parser.add_argument("--source-commit", default=None)
    parser.add_argument("--min-free-gib", type=int, default=MIN_FREE_GIB)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--build-timeout-minutes", type=int, default=2160)
    parser.add_argument(
        "--skip-mount-check",
        action="store_true",
        help="test-only escape hatch; never use this in the GitHub workflow",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    if args.run_root is None:
        args.run_root = str(
            Path(args.external_root) / ".android-ci-runs" / f"manual-{os.getpid()}"
        )
    if args.command == "run":
        return _run_transaction(args)
    external_root = Path(args.external_root).absolute()
    android_root = Path(args.android_root).absolute()
    control_root = Path(args.control_root).absolute()
    run_root = Path(args.run_root).absolute()
    try:
        lock: int | None = None
        if args.command == "materialize":
            # The mount and containment checks in _preflight run before this
            # directory is created; keep even materialize-only invocations
            # from placing a run directory on the system filesystem.
            _assert_no_symlink_components(external_root)
            _assert_under(external_root, android_root, "Android root")
            _assert_under(external_root, control_root, "control root")
            _assert_under(external_root, run_root, "run root")
            if not args.skip_mount_check:
                if _mounted_uuid(external_root).lower() != EXTERNAL_UUID:
                    raise CiError("external root is not mounted from the canonical UUID")
                if _mounted_uuid(android_root).lower() != EXTERNAL_UUID:
                    raise CiError("Android root is not on the canonical external UUID")
            _assert_no_symlink_components(run_root.parent)
            run_root.mkdir(parents=True, exist_ok=True)
            _assert_no_symlink_components(run_root)
            # Hold the same exclusive lock while validating and copying.  A
            # preflight performed before the lock could race another local
            # materializer and invalidate its hashes.
            lock_path = Path(args.lock_path).absolute()
            _assert_under(external_root, lock_path, "lock path")
            lock = _acquire_lock(lock_path)
        try:
            context = _preflight(
                control_root=control_root,
                android_root=android_root,
                external_root=external_root,
                run_root=run_root,
                expected_commit=args.source_commit or os.environ.get("GITHUB_SHA"),
                min_free_gib=args.min_free_gib,
                skip_mount_check=args.skip_mount_check,
                check_active_build=True,
            )
            if args.command == "materialize":
                result = _materialize(context)
            else:
                result = _source_receipt(context)
        finally:
            if lock is not None:
                _release_lock(lock)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    except CiError as error:
        print(f"android-ci-desktop-build: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
