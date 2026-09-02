"""Tests for the exact source-package producer/consumer contract."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "android_ci_source_package.py"
SPEC = importlib.util.spec_from_file_location("android_ci_source_package", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


class SourcePackageTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE)

    def _repo(self, root: Path) -> str:
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "android-ci-test")
        self._git(root, "config", "user.email", "android-ci-test@example.invalid")
        (root / "README.md").write_text("fixture\n", encoding="utf-8")
        (root / "nested").mkdir()
        (root / "nested" / "input.txt").write_text("input\n", encoding="utf-8")
        self._git(root, "add", "README.md", "nested/input.txt")
        self._git(root, "commit", "-qm", "fixture")
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()

    def test_create_and_verify_binds_exact_commit_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            output = Path(directory) / "out"
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(output),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )
            manifest_path = output / "trillionnium-os-source.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["source_commit"], commit)
            self.assertEqual(manifest["archive"]["member_count"], 2)
            self.assertEqual(
                tool.main(
                    [
                        "verify",
                        "--manifest",
                        str(manifest_path),
                        "--expected-repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )

    def test_dirty_checkout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            (root / "README.md").write_text("changed\n", encoding="utf-8")
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(Path(directory) / "out"),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                2,
            )

    def test_archive_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            output = Path(directory) / "out"
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(output),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )
            archive = output / "trillionnium-os-source.tar.gz"
            archive.write_bytes(archive.read_bytes() + b"tamper")
            self.assertEqual(
                tool.main(["verify", "--manifest", str(output / "trillionnium-os-source.json")]),
                2,
            )

    def test_sidecar_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            output = Path(directory) / "out"
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(output),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )
            sidecar = output / "trillionnium-os-source.tar.gz.sha256"
            sidecar.write_text("0" * 64 + "  trillionnium-os-source.tar.gz\n", encoding="ascii")
            self.assertEqual(
                tool.main(["verify", "--manifest", str(output / "trillionnium-os-source.json")]),
                2,
            )


if __name__ == "__main__":
    unittest.main()
