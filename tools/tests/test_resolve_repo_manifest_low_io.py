#!/usr/bin/env python3
"""Tests for the direct, fail-closed pinned-manifest resolver."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
SCRIPT = TOOLS / "resolve_repo_manifest_low_io.py"


def load_module():
    spec = importlib.util.spec_from_file_location("low_io_manifest", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RESOLVER = load_module()


class LowIoManifestResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="trillionnium-lowio-test.")
        self.root = Path(self.temporary.name) / "android"
        (self.root / ".repo/manifests").mkdir(parents=True)
        (self.root / ".repo/projects").mkdir(parents=True)
        self.projects = {
            "foo": "a" * 40,
            "nested/bar": "b" * 40,
        }
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<manifest>",
            '  <remote name="fixture" fetch="https://example.invalid"/>',
        ]
        for path, revision in self.projects.items():
            worktree = self.root / path
            worktree.mkdir(parents=True)
            gitdir = self.root / ".repo/projects" / (path + ".git")
            gitdir.mkdir(parents=True)
            (gitdir / "HEAD").write_text(revision + "\n", encoding="ascii")
            (worktree / ".git").symlink_to(
                Path("../" * len(path.split("/"))) / ".repo/projects" / (path + ".git"),
                target_is_directory=True,
            )
            lines.append(
                f'  <project name="Fixture/{path}" path="{path}" '
                f'revision="{revision}" remote="fixture"/>'
            )
        lines.append("</manifest>")
        self.manifest = self.root / ".repo/manifests/fixture.xml"
        self.manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_all_heads_exact_emits_non_authorizing_receipt(self) -> None:
        raw, receipt = RESOLVER.resolve(self.root, self.manifest)
        self.assertEqual(raw, self.manifest.read_bytes())
        self.assertEqual(receipt["decision"], RESOLVER.PASS)
        self.assertFalse(receipt["release_allowed"])
        self.assertEqual(receipt["project_count"], 2)
        self.assertEqual(receipt["producer"], "local_repo_manifest_direct_pinned")

    def test_head_mismatch_fails_closed(self) -> None:
        (self.root / ".repo/projects/foo.git/HEAD").write_text(
            "c" * 40 + "\n", encoding="ascii"
        )
        with self.assertRaisesRegex(RESOLVER.ResolverError, "differs"):
            RESOLVER.resolve(self.root, self.manifest)

    def test_dynamic_manifest_composition_fails_closed(self) -> None:
        dynamic = self.root / ".repo/manifests/dynamic.xml"
        dynamic.write_text(
            self.manifest.read_text(encoding="utf-8").replace(
                "</manifest>", "  <include name=\"other.xml\"/>\n</manifest>"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RESOLVER.ResolverError, "dynamic"):
            RESOLVER.resolve(self.root, dynamic)

    def test_main_publishes_outputs_outside_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trillionnium-lowio-output.") as out:
            output_root = Path(out)
            status = RESOLVER.main(
                [
                    "--android-root",
                    str(self.root),
                    "--manifest",
                    str(self.manifest),
                    "--resolved-manifest",
                    str(output_root / "resolved.xml"),
                    "--receipt",
                    str(output_root / "receipt.json"),
                ]
            )
            self.assertEqual(status, 0)
            receipt = json.loads((output_root / "receipt.json").read_text())
            self.assertEqual(receipt["decision"], RESOLVER.PASS)
            self.assertEqual(
                (output_root / "resolved.xml").read_bytes(),
                self.manifest.read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
