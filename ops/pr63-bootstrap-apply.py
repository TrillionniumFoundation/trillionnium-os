#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE_COMMIT = "d323a685c752b5bccc045a82728fd0c93c015163"
BASE_TREE = "2cab1b1cfebf15a4d995ea4705e21dc675531c05"
PREDECESSOR_COMMIT = "0b2228aae3512650340cd50c84f52daf10e3649a"
PREDECESSOR_TREE = "61e43db3904b0d08e10a3e49e6cce47a4d7edade"
BOOTSTRAP_LOGICAL_PATH = "tools/launch/verified_python_bootstrap_v1.py"
MANIFEST_LOGICAL_PATH = "tools/verified-python-entrypoints.v1.json"

BOOTSTRAP_SOURCE = r'''#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any

SCHEMA = "org.trillionnium.verified-python-bootstrap.v1"
MANIFEST_SCHEMA = "org.trillionnium.verified-python-entrypoints.v1"
BOOTSTRAP_LOGICAL_PATH = "tools/launch/verified_python_bootstrap_v1.py"
MANIFEST_LOGICAL_PATH = "tools/verified-python-entrypoints.v1.json"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024


class BootstrapError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise BootstrapError(f"non-finite JSON constant: {value}")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def normalized_relative(value: Any, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a nonempty string")
    require("\x00" not in value and "\\" not in value, f"{label} is not normalized")
    pure = PurePosixPath(value)
    require(not pure.is_absolute(), f"{label} must be repository-relative")
    require("." not in pure.parts and ".." not in pure.parts, f"{label} is unsafe")
    require(value == pure.as_posix(), f"{label} is not POSIX-normalized")
    return value


def absolute_root(value: str) -> Path:
    require(value and "\x00" not in value, "repository root is invalid")
    path = Path(os.path.abspath(value))
    require(path.is_absolute() and path != Path("/"), "repository root is invalid")
    return path


def open_nofollow(path: Path) -> tuple[int, Path]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    require(absolute.is_absolute() and absolute != Path("/"), f"invalid path: {path}")
    components = absolute.parts[1:]
    require(bool(components), f"empty path: {path}")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = os.open("/", directory_flags)
    try:
        for component in components[:-1]:
            require(component not in {"", ".", ".."}, f"unsafe component in {absolute}")
            child = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = child
        leaf = components[-1]
        require(leaf not in {"", ".", ".."}, f"unsafe leaf in {absolute}")
        descriptor = os.open(leaf, file_flags, dir_fd=current)
        return descriptor, absolute
    finally:
        os.close(current)


def read_descriptor(descriptor: int, *, limit: int, label: str) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(0 < before.st_size <= limit, f"{label} size is outside the bound")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        require(bool(block), f"short read from {label}")
        chunks.append(block)
        offset += len(block)
    after = os.fstat(descriptor)
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"{label} changed while open",
    )
    return b"".join(chunks), before


def snapshot(path: Path, logical_path: str, *, limit: int) -> tuple[bytes, dict[str, Any]]:
    descriptor, _ = open_nofollow(path)
    try:
        raw, metadata = read_descriptor(descriptor, limit=limit, label=logical_path)
    finally:
        os.close(descriptor)
    return raw, {
        "path": logical_path,
        "size": len(raw),
        "sha256": digest(raw),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
    }


def command_source() -> bytes:
    raw = Path("/proc/self/cmdline").read_bytes()
    parts = raw.rstrip(b"\0").split(b"\0")
    try:
        index = parts.index(b"-c")
    except ValueError as error:
        raise BootstrapError("canonical bootstrap requires CPython -c execution") from error
    require(index + 1 < len(parts), "missing -c command source")
    return parts[index + 1]


def re_full_sha(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def exact_identity(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == {"path", "size", "sha256"}, f"{label} keys drifted")
    path = normalized_relative(value["path"], f"{label}.path")
    size = value["size"]
    sha = value["sha256"]
    require(isinstance(size, int) and not isinstance(size, bool) and 0 < size <= MAX_SOURCE_BYTES,
            f"{label}.size is invalid")
    require(isinstance(sha, str) and re_full_sha(sha), f"{label}.sha256 is invalid")
    return {"path": path, "size": size, "sha256": sha}


def load_manifest(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw, identity = snapshot(root / MANIFEST_LOGICAL_PATH, MANIFEST_LOGICAL_PATH, limit=MAX_MANIFEST_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, BootstrapError) as error:
        raise BootstrapError(f"entrypoint manifest is not strict JSON: {error}") from error
    require(isinstance(value, dict), "entrypoint manifest root must be an object")
    require(
        set(value) == {"schema", "bootstrap", "entrypoints", "claim_ceiling", "public_release"},
        "entrypoint manifest keys drifted",
    )
    require(value["schema"] == MANIFEST_SCHEMA, "entrypoint manifest schema is unsupported")
    require(
        value["claim_ceiling"] == "SOURCE_LAUNCH_AUTHENTICATION_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY",
        "entrypoint manifest claim ceiling widened",
    )
    require(value["public_release"] is False, "entrypoint manifest cannot authorize release")
    bootstrap = exact_identity(value["bootstrap"], "bootstrap")
    entrypoints = value["entrypoints"]
    require(isinstance(entrypoints, dict) and set(entrypoints) == {"product-baseline", "host-reproducibility"},
            "entrypoint set drifted")
    normalized = {key: exact_identity(item, f"entrypoints.{key}") for key, item in entrypoints.items()}
    manifest_report = {"path": MANIFEST_LOGICAL_PATH, "size": len(raw), "sha256": digest(raw)}
    return {
        "schema": value["schema"],
        "bootstrap": bootstrap,
        "entrypoints": normalized,
        "claim_ceiling": value["claim_ceiling"],
        "public_release": False,
    }, manifest_report


def main() -> int:
    require(len(sys.argv) >= 4, "usage: python -I -c BOOTSTRAP REPOSITORY ENTRYPOINT -- [ARGS]")
    root = absolute_root(sys.argv[1])
    entrypoint = sys.argv[2]
    require(sys.argv[3] == "--", "missing argument separator")
    forwarded = sys.argv[4:]

    source = command_source()
    source_identity = {"path": BOOTSTRAP_LOGICAL_PATH, "size": len(source), "sha256": digest(source)}
    manifest, manifest_identity = load_manifest(root)
    require(source_identity == manifest["bootstrap"], "executed bootstrap bytes are not admitted")
    require(entrypoint in manifest["entrypoints"], "unknown verified Python entrypoint")
    admitted = manifest["entrypoints"][entrypoint]

    descriptor, launcher_path = open_nofollow(root / admitted["path"])
    hook_used = False
    try:
        hook = os.environ.get("TRILLIONNIUM_BOOTSTRAP_TEST_SYNC_FDS")
        if hook:
            hook_used = True
            parts = hook.split(":")
            require(len(parts) == 2 and all(part.isdecimal() for part in parts), "invalid test sync fds")
            ready_fd, continue_fd = map(int, parts)
            os.write(ready_fd, b"OPEN\n")
            require(os.read(continue_fd, 1) == b"1", "test sync continuation missing")
        launcher_source, metadata = read_descriptor(descriptor, limit=MAX_SOURCE_BYTES, label=admitted["path"])
    finally:
        os.close(descriptor)
    launcher_identity = {
        "path": admitted["path"],
        "size": len(launcher_source),
        "sha256": digest(launcher_source),
    }
    require(launcher_identity == admitted, "opened launcher bytes are not admitted")

    code = compile(launcher_source, admitted["path"], "exec", dont_inherit=True)
    namespace: dict[str, Any] = {
        "__name__": "__main__",
        "__file__": str(launcher_path),
        "__package__": None,
        "__cached__": None,
        "_TRILLIONNIUM_BOOTSTRAP_AUTHENTICATED": True,
        "_TRILLIONNIUM_BOOTSTRAP_SCHEMA": SCHEMA,
        "_TRILLIONNIUM_BOOTSTRAP_SOURCE": source,
        "_TRILLIONNIUM_BOOTSTRAP_IDENTITY": source_identity,
        "_TRILLIONNIUM_ENTRYPOINT_MANIFEST_IDENTITY": manifest_identity,
        "_TRILLIONNIUM_LAUNCHER_SOURCE": launcher_source,
        "_TRILLIONNIUM_LAUNCHER_IDENTITY": launcher_identity,
        "_TRILLIONNIUM_LAUNCHER_PATH": str(launcher_path),
        "_TRILLIONNIUM_BOOTSTRAP_TEST_HOOK_USED": hook_used,
    }
    sys.argv = [str(launcher_path), *forwarded]
    exec(code, namespace)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BootstrapError as error:
        print(f"verified Python bootstrap failed: {error}", file=sys.stderr)
        raise SystemExit(2)
'''

TEST_SOURCE = r'''from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "tools/launch/verified_python_bootstrap_v1.py"
MANIFEST = ROOT / "tools/verified-python-entrypoints.v1.json"
ENTRYPOINTS = {
    "product-baseline": ROOT / "tools/perf/run_product_baseline.py",
    "host-reproducibility": ROOT / "tools/build/verify_host_reproducibility.py",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(entrypoint: str, root: Path = ROOT, *args: str) -> list[str]:
    return [sys.executable, "-I", "-c", BOOTSTRAP.read_text(encoding="utf-8"), str(root), entrypoint, "--", *args]


class VerifiedPythonBootstrapTest(unittest.TestCase):
    def test_manifest_binds_exact_bootstrap_and_launchers(self) -> None:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(value["bootstrap"]["sha256"], sha(BOOTSTRAP))
        self.assertEqual(value["bootstrap"]["size"], BOOTSTRAP.stat().st_size)
        for entrypoint, path in ENTRYPOINTS.items():
            self.assertEqual(value["entrypoints"][entrypoint]["sha256"], sha(path))
            self.assertEqual(value["entrypoints"][entrypoint]["size"], path.stat().st_size)
        self.assertFalse(value["public_release"])

    def test_direct_path_execution_fails_closed(self) -> None:
        for path in ENTRYPOINTS.values():
            completed = subprocess.run([sys.executable, str(path), "--help"], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("verified Python bootstrap", completed.stderr)

    def test_canonical_bootstrap_runs_both_help_paths(self) -> None:
        for entrypoint in ENTRYPOINTS:
            completed = subprocess.run(command(entrypoint, ROOT, "--help"), cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("usage:", completed.stdout.lower())

    def test_mutated_command_source_is_rejected(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8") + "\n# mutation\n"
        completed = subprocess.run(
            [sys.executable, "-I", "-c", source, str(ROOT), "product-baseline", "--", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=20,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("executed bootstrap bytes are not admitted", completed.stderr)

    def test_pre_interpreter_swap_restore_cannot_execute_unadmitted_launcher(self) -> None:
        reviewed = ENTRYPOINTS["product-baseline"].read_bytes()
        hostile = b"from pathlib import Path\nPath('/tmp/pr63-hostile-bootstrap-marker').write_text('ran')\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tools/launch").mkdir(parents=True)
            (root / "tools/perf").mkdir(parents=True)
            shutil.copy2(BOOTSTRAP, root / "tools/launch/verified_python_bootstrap_v1.py")
            launcher = root / "tools/perf/run_product_baseline.py"
            launcher.write_bytes(hostile)
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            manifest["entrypoints"]["product-baseline"] = {
                "path": "tools/perf/run_product_baseline.py",
                "size": len(reviewed),
                "sha256": hashlib.sha256(reviewed).hexdigest(),
            }
            (root / "tools/verified-python-entrypoints.v1.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            ready_read, ready_write = os.pipe()
            continue_read, continue_write = os.pipe()
            env = {"PATH": os.environ.get("PATH", ""), "TRILLIONNIUM_BOOTSTRAP_TEST_SYNC_FDS": f"{ready_write}:{continue_read}"}
            marker = Path("/tmp/pr63-hostile-bootstrap-marker")
            marker.unlink(missing_ok=True)
            process = subprocess.Popen(
                command("product-baseline", root, "--help"), cwd=root, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                pass_fds=(ready_write, continue_read),
            )
            os.close(ready_write)
            os.close(continue_read)
            self.assertEqual(os.read(ready_read, 5), b"OPEN\n")
            replacement = launcher.with_name("reviewed.tmp")
            replacement.write_bytes(reviewed)
            os.replace(replacement, launcher)
            os.write(continue_write, b"1")
            os.close(ready_read)
            os.close(continue_write)
            stdout, stderr = process.communicate(timeout=20)
            self.assertNotEqual(process.returncode, 0, stdout)
            self.assertIn("opened launcher bytes are not admitted", stderr)
            self.assertFalse(marker.exists())

    def test_import_only_identity_is_non_authorizing(self) -> None:
        for index, path in enumerate(ENTRYPOINTS.values()):
            spec = importlib.util.spec_from_file_location(f"_bootstrap_import_{index}", path)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            identity = getattr(module, "_TRILLIONNIUM_LAUNCHER_IDENTITY")
            self.assertFalse(identity["authenticated"])
            self.assertEqual(identity["claim_ceiling"], "IMPORT_ONLY_NO_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
'''


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def launcher_tail(*, bootstrap_sha: str, bootstrap_size: int, logical_path: str) -> str:
    return f'''
def __launcher_command_source() -> bytes:
    try:
        raw = __LauncherPath("/proc/self/cmdline").read_bytes()
    except OSError as error:
        raise RuntimeError(f"cannot read canonical bootstrap command source: {{error}}") from error
    parts = raw.rstrip(b"\\0").split(b"\\0")
    try:
        index = parts.index(b"-c")
    except ValueError as error:
        raise RuntimeError("verified Python bootstrap requires CPython -c execution") from error
    if index + 1 >= len(parts):
        raise RuntimeError("verified Python bootstrap command source is missing")
    return parts[index + 1]


__bootstrap_authenticated = globals().get("_TRILLIONNIUM_BOOTSTRAP_AUTHENTICATED") is True
if __name__ == "__main__" and not __bootstrap_authenticated:
    raise RuntimeError(
        "direct pathname execution is disabled for evidence-producing operation; "
        "use the verified Python bootstrap through CPython -I -c"
    )

if __bootstrap_authenticated:
    if globals().get("_TRILLIONNIUM_BOOTSTRAP_SCHEMA") != "org.trillionnium.verified-python-bootstrap.v1":
        raise RuntimeError("verified Python bootstrap schema differs")
    if globals().get("_TRILLIONNIUM_BOOTSTRAP_TEST_HOOK_USED") is not False:
        raise RuntimeError("test-hook bootstrap execution cannot produce evidence")
    __bootstrap_source = globals().get("_TRILLIONNIUM_BOOTSTRAP_SOURCE")
    __bootstrap_identity = globals().get("_TRILLIONNIUM_BOOTSTRAP_IDENTITY")
    __manifest_identity = globals().get("_TRILLIONNIUM_ENTRYPOINT_MANIFEST_IDENTITY")
    __injected_launcher_source = globals().get("_TRILLIONNIUM_LAUNCHER_SOURCE")
    __injected_launcher_identity = globals().get("_TRILLIONNIUM_LAUNCHER_IDENTITY")
    if not isinstance(__bootstrap_source, bytes) or not isinstance(__bootstrap_identity, dict):
        raise RuntimeError("verified Python bootstrap identity is missing")
    __actual_command_source = __launcher_command_source()
    if __actual_command_source != __bootstrap_source:
        raise RuntimeError("bootstrap command source differs from injected source")
    if len(__bootstrap_source) != {bootstrap_size} or __launcher_hashlib.sha256(__bootstrap_source).hexdigest() != "{bootstrap_sha}":
        raise RuntimeError("bootstrap source is not the reviewed trust anchor")
    if __bootstrap_identity != {{
        "path": "tools/launch/verified_python_bootstrap_v1.py",
        "size": {bootstrap_size},
        "sha256": "{bootstrap_sha}",
    }}:
        raise RuntimeError("bootstrap identity differs from reviewed trust anchor")
    if not isinstance(__manifest_identity, dict) or set(__manifest_identity) != {{"path", "size", "sha256"}}:
        raise RuntimeError("entrypoint manifest identity is invalid")
    if not isinstance(__injected_launcher_source, bytes) or not isinstance(__injected_launcher_identity, dict):
        raise RuntimeError("captured launcher identity is missing")
    if __launcher_hashlib.sha256(__injected_launcher_source).hexdigest() != __injected_launcher_identity.get("sha256"):
        raise RuntimeError("captured launcher digest differs")
    if len(__injected_launcher_source) != __injected_launcher_identity.get("size"):
        raise RuntimeError("captured launcher size differs")
    if __injected_launcher_identity.get("path") != "{logical_path}":
        raise RuntimeError("captured launcher path differs")
    __launcher_path = __launcher_absolute(__LauncherPath(__file__))
    __launcher_source = __injected_launcher_source
    __launcher_identity = {{
        **__injected_launcher_identity,
        "bootstrap": dict(__bootstrap_identity),
        "entrypoint_manifest": dict(__manifest_identity),
        "authenticated": True,
        "claim_ceiling": "SOURCE_LAUNCH_AUTHENTICATION_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY",
    }}
else:
    __launcher_path = __launcher_absolute(__LauncherPath(__file__))
    __launcher_source, __launcher_identity, _ = __launcher_snapshot(
        __launcher_path, __LAUNCHER_LOGICAL_PATH
    )
    __launcher_identity = {{
        **__launcher_identity,
        "authenticated": False,
        "claim_ceiling": "IMPORT_ONLY_NO_EVIDENCE",
    }}

__facade_path = __launcher_path.with_name(__FACADE_FILENAME)
__facade_source, __facade_identity, __facade_code = __launcher_authenticate_facade(__facade_path)

globals().update({{
    "_TRILLIONNIUM_LAUNCHER_SOURCE": __launcher_source,
    "_TRILLIONNIUM_LAUNCHER_IDENTITY": dict(__launcher_identity),
    "_TRILLIONNIUM_LAUNCHER_PATH": str(__launcher_path),
    "_TRILLIONNIUM_FACADE_SOURCE": __facade_source,
    "_TRILLIONNIUM_FACADE_IDENTITY": dict(__facade_identity),
    "_TRILLIONNIUM_FACADE_PATH": str(__facade_path),
}})
exec(__facade_code, globals())
'''


def replace_launcher(path: Path, *, bootstrap_sha: str, bootstrap_size: int, logical_path: str) -> None:
    source = path.read_text(encoding="utf-8")
    marker = 'if "_TRILLIONNIUM_BOOTSTRAP_SOURCE" in globals():'
    index = source.find(marker)
    if index < 0:
        raise SystemExit(f"launcher tail marker missing in {path}")
    path.write_text(source[:index] + launcher_tail(
        bootstrap_sha=bootstrap_sha,
        bootstrap_size=bootstrap_size,
        logical_path=logical_path,
    ).lstrip("\n"), encoding="utf-8")


def append_readme(path: Path, entrypoint: str) -> None:
    marker = "## Authenticated Python launch boundary"
    source = path.read_text(encoding="utf-8")
    if marker in source:
        return
    section = f'''\n\n## Authenticated Python launch boundary\n\nEvidence-producing execution must use the reviewed generic bootstrap as CPython\ncommand source; direct pathname execution of the launcher fails closed:\n\n```sh\npython3 -I -c "$(cat tools/launch/verified_python_bootstrap_v1.py)" \\\n  "$PWD" {entrypoint} -- --help\n```\n\nThe bootstrap descriptor-walks every path component with `O_NOFOLLOW`, checks\nthe strict entrypoint manifest, hashes and compiles the same opened launcher\nbytes, and injects the bootstrap, manifest, and launcher identities. The\nlauncher independently verifies the actual kernel command source before loading\nthe facade. Import-only use is marked `IMPORT_ONLY_NO_EVIDENCE` and cannot\nestablish a measurement, installed-target, device, signing, or release claim.\n'''
    path.write_text(source.rstrip() + section + "\n", encoding="utf-8")


def canonical_paths_digest(paths: list[str]) -> str:
    hasher = hashlib.sha256()
    for path in sorted(paths):
        hasher.update(path.encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def canonical_changes_digest(changes: list[dict[str, object]]) -> str:
    hasher = hashlib.sha256()
    for change in sorted(changes, key=lambda item: str(item["path"])):
        hasher.update(json.dumps(change, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def observed_changes(root: Path) -> list[dict[str, object]]:
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), "diff", "--name-status", "-M", BASE_COMMIT],
        check=True, capture_output=True, text=True,
    )
    changes: list[dict[str, object]] = []
    mapping = {"A": "added", "M": "modified", "D": "removed", "T": "changed"}
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        code = fields[0]
        if code.startswith("R"):
            changes.append({"path": fields[2], "status": "renamed", "previous_path": fields[1]})
        else:
            status = mapping.get(code[:1])
            if status is None or len(fields) != 2:
                raise SystemExit(f"unsupported git diff status: {line}")
            changes.append({"path": fields[1], "status": status, "previous_path": None})
    changes.sort(key=lambda item: str(item["path"]))
    return changes


def update_review_index(root: Path) -> None:
    path = root / "governance/pr41-review-index.v1.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    changes = observed_changes(root)
    paths = [str(item["path"]) for item in changes]
    expected_paths = [
        "governance/pr41-review-index.v1.json",
        "tools/build/README.md",
        "tools/build/_verify_host_reproducibility_core.py",
        "tools/build/_verify_host_reproducibility_facade.py",
        "tools/build/verify_host_reproducibility.py",
        "tools/launch/verified_python_bootstrap_v1.py",
        "tools/perf/README.md",
        "tools/perf/_run_product_baseline_core.py",
        "tools/perf/_run_product_baseline_facade.py",
        "tools/perf/run_product_baseline.py",
        "tools/tests/test_product_baseline_process_group_cleanup.py",
        "tools/tests/test_run_product_baseline.py",
        "tools/tests/test_verified_python_bootstrap.py",
        "tools/tests/test_verify_host_reproducibility.py",
        "tools/verified-python-entrypoints.v1.json",
    ]
    if paths != expected_paths:
        raise SystemExit(f"unexpected final review inventory: {paths}")
    value["base"] = {"commit": BASE_COMMIT, "tree": BASE_TREE}
    value["review_predecessor"] = {"commit": PREDECESSOR_COMMIT, "tree": PREDECESSOR_TREE}
    value["changed_paths"] = paths
    value["changes"] = changes
    value["expected"] = {
        "path_count": len(paths),
        "paths_sha256": canonical_paths_digest(paths),
        "change_count": len(changes),
        "changes_sha256": canonical_changes_digest(changes),
    }
    value["slices"] = [
        {
            "id": "ci-evidence-and-authority",
            "security_domain": "ci-evidence-and-authority",
            "accountable_owner": "ProfHepta",
            "independent_reviewers": ["Franksudoman"],
            "review_order": 1,
            "paths": ["governance/pr41-review-index.v1.json"],
        },
        {
            "id": "source-tooling-and-verification",
            "security_domain": "source-tooling-and-verification",
            "accountable_owner": "ProfHepta",
            "independent_reviewers": ["Tomasrgbsf"],
            "review_order": 2,
            "paths": paths[1:],
        },
    ]
    value["automatic_redispatch"] = False
    value["integration_authorized"] = False
    value["promotion_authorized"] = False
    value["public_release"] = False
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply.py REPOSITORY")
    root = Path(sys.argv[1]).resolve()
    if not (root / ".git").exists():
        raise SystemExit("repository checkout missing .git")
    if subprocess.check_output(["git", "--no-replace-objects", "-C", str(root), "rev-parse", "HEAD"], text=True).strip() != PREDECESSOR_COMMIT:
        raise SystemExit("target head moved")
    if subprocess.check_output(["git", "--no-replace-objects", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True).strip() != PREDECESSOR_TREE:
        raise SystemExit("target tree moved")

    bootstrap_path = root / BOOTSTRAP_LOGICAL_PATH
    bootstrap_path.parent.mkdir(parents=True, exist_ok=True)
    bootstrap_path.write_text(BOOTSTRAP_SOURCE, encoding="utf-8")
    bootstrap_raw = bootstrap_path.read_bytes()
    bootstrap_sha = sha(bootstrap_raw)

    perf_launcher = root / "tools/perf/run_product_baseline.py"
    build_launcher = root / "tools/build/verify_host_reproducibility.py"
    replace_launcher(perf_launcher, bootstrap_sha=bootstrap_sha, bootstrap_size=len(bootstrap_raw), logical_path="tools/perf/run_product_baseline.py")
    replace_launcher(build_launcher, bootstrap_sha=bootstrap_sha, bootstrap_size=len(bootstrap_raw), logical_path="tools/build/verify_host_reproducibility.py")

    manifest = {
        "schema": "org.trillionnium.verified-python-entrypoints.v1",
        "bootstrap": {"path": BOOTSTRAP_LOGICAL_PATH, "size": len(bootstrap_raw), "sha256": bootstrap_sha},
        "entrypoints": {
            "product-baseline": {"path": "tools/perf/run_product_baseline.py", "size": perf_launcher.stat().st_size, "sha256": sha(perf_launcher.read_bytes())},
            "host-reproducibility": {"path": "tools/build/verify_host_reproducibility.py", "size": build_launcher.stat().st_size, "sha256": sha(build_launcher.read_bytes())},
        },
        "claim_ceiling": "SOURCE_LAUNCH_AUTHENTICATION_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY",
        "public_release": False,
    }
    (root / MANIFEST_LOGICAL_PATH).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "tools/tests/test_verified_python_bootstrap.py").write_text(TEST_SOURCE, encoding="utf-8")
    append_readme(root / "tools/perf/README.md", "product-baseline")
    append_readme(root / "tools/build/README.md", "host-reproducibility")
    update_review_index(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
