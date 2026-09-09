"""Contract and process-lifecycle tests for Host reproducibility builds."""
from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "build/verify_host_reproducibility.py"
SPEC = importlib.util.spec_from_file_location("host_reproducibility", PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)


def builds() -> list[dict]:
    item = {"exit_code": 0, "source_before": {"commit": "a", "lock": "locked"},
            "source_after": {"commit": "a", "lock": "locked"},
            "tools_before": {"rustc": "1.93.0"}, "tools_after": {"rustc": "1.93.0"},
            "artifacts": {name: {"size": 16, "sha256": "a" * 64} for name in VERIFY.BINARIES}}
    return [copy.deepcopy(item), copy.deepcopy(item)]


def live_task(pid: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return False
    fields = raw.rsplit(b")", 1)[1].split()
    return bool(fields) and fields[0] not in (b"Z", b"X")


def wait_not_live(pid: int) -> None:
    deadline = time.monotonic() + 3.0
    while live_task(pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    if live_task(pid):
        raise AssertionError(f"build descendant {pid} survived cleanup")


def split_group_script(*, flood: bool) -> str:
    child_body = (
        "chunk = b'x' * 4096\n"
        "while True:\n"
        "    os.write(1, chunk)\n"
        if flood
        else
        "while True:\n"
        "    time.sleep(1)\n"
    )
    return f'''\
import os
from pathlib import Path
import signal
import sys
import time

path = Path(sys.argv[1])
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    path.write_text(str(os.getpid()), encoding="ascii")
    {child_body.replace(chr(10), chr(10) + "    ").rstrip()}
while not path.exists():
    time.sleep(0.001)
os._exit(0)
'''


class HostReproducibilityTests(unittest.TestCase):
    def test_only_two_successful_identical_builds_pass(self) -> None:
        self.assertTrue(VERIFY.compare_artifacts(builds())["passed"])
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.compare_artifacts(builds()[:1])

    def test_artifact_difference_has_failure_gate(self) -> None:
        value = builds()
        value[1]["artifacts"][VERIFY.BINARIES[0]]["sha256"] = "b" * 64
        result = VERIFY.compare_artifacts(value)
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "FAIL_ARTIFACT_DIFFERENCE")

    def test_build_failure_source_or_tool_drift_missing_artifact_cannot_pass(self) -> None:
        changes = [lambda b: b[1].update(exit_code=101),
                   lambda b: b[0]["source_after"].update(lock="changed"),
                   lambda b: b[1]["source_before"].update(commit="moved"),
                   lambda b: b[1]["tools_after"].update(rustc="other"),
                   lambda b: b[0]["artifacts"].pop(VERIFY.BINARIES[0]),
                   lambda b: [item["artifacts"][VERIFY.BINARIES[0]].pop("sha256") for item in b]]
        for change in changes:
            with self.subTest(change=change):
                value = builds()
                change(value)
                with self.assertRaises(VERIFY.VerificationError):
                    VERIFY.compare_artifacts(value)

    def test_implementation_manifest_binds_facade_core_and_cleanup_sources(self) -> None:
        manifest = VERIFY.implementation_manifest()
        self.assertEqual([item["path"] for item in manifest["files"]],
                         list(VERIFY.IMPLEMENTATION_PATHS))
        VERIFY.validate_implementation_manifest(manifest)
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory)
            for relative in VERIFY.IMPLEMENTATION_PATHS:
                source = VERIFY.CORE.ROOT / relative
                destination = copied_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            with mock.patch.object(VERIFY.CORE, "ROOT", copied_root), \
                 mock.patch.object(VERIFY.CORE, "PINNED_IMPLEMENTATION_FILES", None):
                before = VERIFY.live_implementation_manifest()
                target = copied_root / VERIFY.IMPLEMENTATION_PATHS[-1]
                target.write_bytes(target.read_bytes() + b"\n# identity mutation\n")
                after = VERIFY.live_implementation_manifest()
        self.assertNotEqual(before["manifest_sha256"], after["manifest_sha256"])
        core_source = Path(VERIFY.CORE_PATH).read_text(encoding="utf-8")
        self.assertIn('"implementation_manifest": implementation', core_source)

    def test_snapshot_loader_executes_the_admitted_bytes_after_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module_path = root / "module.py"
            safe = b"VALUE = 'safe'\n"
            module_path.write_bytes(safe)

            def swap(path: Path) -> None:
                path.write_text("raise RuntimeError('hostile path bytes executed')\n")

            with mock.patch.object(VERIFY, "REPOSITORY_ROOT", root):
                module, loaded, identity = VERIFY._load_snapshot(
                    "host_reproducibility_snapshot_test",
                    module_path,
                    "module.py",
                    before_exec=swap,
                )
            self.assertEqual(loaded, safe)
            self.assertEqual(module.VALUE, "safe")
            self.assertEqual(identity["sha256"], VERIFY.sha256(safe))
            sys.modules.pop("host_reproducibility_snapshot_test", None)

    def test_descriptor_pinned_tool_survives_source_swap_but_reports_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "python-source"
            custody = root / "custody"
            custody.mkdir(mode=0o700)
            shutil.copyfile(sys.executable, source)
            source.chmod(0o700)
            pin = VERIFY.PinnedTool(source, custody, "python")
            try:
                source.write_bytes(b"#!/bin/sh\nexit 98\n")
                source.chmod(0o700)
                result = subprocess.run(
                    [str(pin.execution_path), "-I", "-c", "print('descriptor-safe')"],
                    pass_fds=(pin.descriptor,),
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.stdout.strip(), "descriptor-safe")
                pin.assert_descriptor()
                with self.assertRaisesRegex(VERIFY.VerificationError, "selected tool"):
                    pin.assert_source_selection()
            finally:
                pin.close()

    def test_recipe_is_fixed_offline_and_remaps_both_build_paths(self) -> None:
        tools = {
            name: {"path": f"/tools/original/{name}",
                   "execution_path": f"/custody/{name}"}
            for name in ("cargo", "rustc", "cc", "ar")
        }
        for label in ("a", "b"):
            command, env = VERIFY.recipe(Path("/source"), Path(f"/tmp/target-{label}"),
                Path(f"/tmp/home-{label}"), Path("/cache"), tools, {"source_date_epoch": "123"})
            for flag in ("--locked", "--offline", "--frozen", "--release"):
                self.assertIn(flag, command)
            self.assertEqual(command[0], "/custody/cargo")
            self.assertEqual(env["RUSTC"], "/custody/rustc")
            self.assertEqual(env["CC"], "/custody/cc")
            self.assertEqual(env["AR"], "/custody/ar")
            self.assertEqual(env["SOURCE_DATE_EPOCH"], "123")
            self.assertEqual(env["CARGO_INCREMENTAL"], "0")
            self.assertIn(f"--remap-path-prefix=/tmp/target-{label}=/build/target", env["CARGO_ENCODED_RUSTFLAGS"])
            self.assertIn(f"--remap-path-prefix=/tmp/home-{label}=/build/cargo-home", env["CARGO_ENCODED_RUSTFLAGS"])
            self.assertNotIn("RUSTUP_TOOLCHAIN", env)

    def test_ambient_cargo_config_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, cache = root / "repo", root / "cache"
            repo.mkdir()
            cache.mkdir()
            (cache / "config.toml").write_text("[build]\nrustflags=['unexpected']\n")
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.reject_ambient_config(repo, cache)

    def test_fixed_toolchain_version_rejected_before_build(self) -> None:
        paths = [Path("/cargo"), Path("/rustc"), Path("/cc"), Path("/ar")]
        with mock.patch.object(VERIFY.CORE, "file_identity", return_value={"path": "/tool", "sha256": "x"}), \
             mock.patch.object(VERIFY.CORE, "query", side_effect=["cargo 1.95.0 (x)", "rustc 1.93.0 (x)\nrelease: 1.93.0"]):
            with self.assertRaisesRegex(VERIFY.VerificationError, "Cargo must"):
                VERIFY.toolchain_identity(*paths, Path("/repo"))

    def test_dirty_or_moved_source_is_rejected(self) -> None:
        with mock.patch.object(VERIFY.CORE, "query", side_effect=["/repo", "head", " M Cargo.toml"]):
            with self.assertRaisesRegex(VERIFY.VerificationError, "source must be clean"):
                VERIFY.source_identity(Path("/repo"))
        with mock.patch.object(VERIFY.CORE, "query", side_effect=["/repo", "moved"]):
            with self.assertRaisesRegex(VERIFY.VerificationError, "expected commit"):
                VERIFY.source_identity(Path("/repo"), "reviewed")

    def run_split_group(self, *, flood: bool, timeout: float) -> tuple[Path, Path, float]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        child_path = root / "child"
        log = root / "cargo.log"
        started = time.monotonic()
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.run_build(
                [sys.executable, "-c", split_group_script(flood=flood), str(child_path)],
                dict(os.environ),
                root,
                log,
                timeout,
            )
        elapsed = time.monotonic() - started
        child = int(child_path.read_text(encoding="ascii"))
        wait_not_live(child)
        return root, log, elapsed

    def test_timeout_cleans_child_after_leader_exit_and_next_build_is_clean(self) -> None:
        root, _, elapsed = self.run_split_group(flood=False, timeout=1.0)
        self.assertLess(elapsed, 5.0)
        result = VERIFY.run_build(
            [sys.executable, "-c", "pass"],
            dict(os.environ),
            root,
            root / "next.log",
            2,
        )
        self.assertEqual(result["exit_code"], 0)

    def test_log_bound_cleans_child_after_leader_exit(self) -> None:
        with mock.patch.object(VERIFY.CORE, "MAX_LOG_BYTES", 1024):
            _, log, elapsed = self.run_split_group(flood=True, timeout=2)
        self.assertLess(elapsed, 5.0)
        self.assertLessEqual(log.stat().st_size, 1024)


if __name__ == "__main__":
    unittest.main()
