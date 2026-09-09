"""Test helpers for the authenticated Python bootstrap and launcher payloads.

The helper mirrors the documented isolated inline loader.  It is test support,
not an evidence authority: production admission retains the exact inline command,
bootstrap digest, launcher digest and resulting report.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_PATH = ROOT / "tools/owner-open/authenticated_python_bootstrap.py"
BOOTSTRAP_LOGICAL_PATH = "tools/owner-open/authenticated_python_bootstrap.py"
OUTER_LOADER_POLICY = "python-isolated-inline-descriptor-loader-v1"
BOOTSTRAP_SCHEMA = "org.trillionnium.authenticated-python-bootstrap.v1"
BOOTSTRAP_POLICY_VERSION = "2026-09-09-v1"
BOOTSTRAP_TRANSPORT = "captured-bootstrap-and-launcher-bytes-v1"


OUTER_LOADER_SOURCE = r'''
import hashlib
import os
from pathlib import Path
import stat
import sys

policy = "python-isolated-inline-descriptor-loader-v1"
bootstrap_path = Path(os.path.abspath(sys.argv[1]))
expected = sys.argv[2]
components = bootstrap_path.parts[1:]
directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
current = os.open("/", directory_flags)
try:
    for component in components[:-1]:
        if component in {"", ".", ".."}:
            raise SystemExit("bootstrap path is not normalized")
        child = os.open(component, directory_flags, dir_fd=current)
        os.close(current)
        current = child
    descriptor = os.open(components[-1], file_flags, dir_fd=current)
finally:
    os.close(current)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 8 * 1024 * 1024:
        raise SystemExit("bootstrap file is not an admitted regular source")
    source = bytearray()
    offset = 0
    while offset < before.st_size:
        block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not block:
            raise SystemExit("short bootstrap read")
        source.extend(block)
        offset += len(block)
    after = os.fstat(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise SystemExit("bootstrap descriptor changed")
finally:
    os.close(descriptor)
raw = bytes(source)
digest = hashlib.sha256(raw).hexdigest()
if digest != expected:
    raise SystemExit(f"bootstrap digest mismatch: {digest}")
identity = {"path": "tools/owner-open/authenticated_python_bootstrap.py", "size": len(raw), "sha256": digest}
namespace = {
    "__name__": "__main__",
    "__file__": str(bootstrap_path),
    "__package__": "",
    "_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE": raw,
    "_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY": identity,
    "_TRILLIONNIUM_BOOTSTRAP_FILE_PATH": str(bootstrap_path),
    "_TRILLIONNIUM_OUTER_LOADER_POLICY": policy,
}
backup = os.environ.get("TRILLIONNIUM_TEST_RESTORE_BACKUP")
if backup:
    def restore(selected, _descriptor):
        selected_path = Path(selected)
        selected_path.unlink()
        os.replace(backup, selected_path)
    namespace["_TRILLIONNIUM_TEST_AFTER_LAUNCHER_OPEN"] = restore
sys.argv = [str(bootstrap_path), *sys.argv[3:]]
exec(compile(raw, "tools/owner-open/authenticated_python_bootstrap.py", "exec", dont_inherit=True), namespace)
'''.strip()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def identity(path: Path, logical_path: str) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    return raw, {"path": logical_path, "size": len(raw), "sha256": sha256(raw)}


def load_authenticated_module(name: str, launcher: Path, logical_path: str) -> ModuleType:
    bootstrap_source, bootstrap_identity = identity(BOOTSTRAP_PATH, BOOTSTRAP_LOGICAL_PATH)
    launcher_source, launcher_identity = identity(launcher, logical_path)
    attestation = {
        "schema": BOOTSTRAP_SCHEMA,
        "policy_version": BOOTSTRAP_POLICY_VERSION,
        "transport": BOOTSTRAP_TRANSPORT,
        "outer_loader_policy": OUTER_LOADER_POLICY,
        "bootstrap": dict(bootstrap_identity),
        "launcher": dict(launcher_identity),
        "direct_path_execution": False,
        "automatic_redispatch": False,
        "public_release": False,
    }
    module = ModuleType(name)
    module.__file__ = str(launcher.resolve())
    module.__package__ = ""
    module.__dict__.update({
        "_TRILLIONNIUM_BOOTSTRAP_SOURCE": launcher_source,
        "_TRILLIONNIUM_BOOTSTRAP_IDENTITY": dict(launcher_identity),
        "_TRILLIONNIUM_BOOTSTRAP_ATTESTATION": attestation,
        "_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE": bootstrap_source,
        "_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY": dict(bootstrap_identity),
        "_TRILLIONNIUM_BOOTSTRAP_FILE_PATH": str(BOOTSTRAP_PATH.resolve()),
    })
    sys.modules[name] = module
    try:
        exec(compile(launcher_source, logical_path, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def run_authenticated(
    launcher: Path,
    logical_path: str,
    launcher_args: list[str],
    *,
    restore_backup: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    bootstrap_source = BOOTSTRAP_PATH.read_bytes()
    launcher_digest = sha256(launcher.read_bytes()) if restore_backup is None else sha256(restore_backup.read_bytes())
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
    if restore_backup is not None:
        env["TRILLIONNIUM_TEST_RESTORE_BACKUP"] = str(restore_backup)
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            OUTER_LOADER_SOURCE,
            str(BOOTSTRAP_PATH),
            sha256(bootstrap_source),
            str(launcher),
            logical_path,
            launcher_digest,
            "--",
            *launcher_args,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
