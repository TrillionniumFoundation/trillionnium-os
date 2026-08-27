#!/usr/bin/env python3
"""Tests for the deterministic source-evidence migration index."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
SCRIPT = TOOLS / "materialize_evidence_migration_index.py"


def load_module():
    spec = importlib.util.spec_from_file_location("evidence_migration_index", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INDEX = load_module()


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


class EvidenceMigrationIndexTests(unittest.TestCase):
    def test_repository_index_is_current(self) -> None:
        actual = json.loads(INDEX.DEFAULT_OUTPUT.read_text(encoding="utf-8"))
        self.assertEqual(actual, INDEX.build_index())

    def test_only_tracked_files_enter_a_source_set(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="trillionnium-evidence-index-test."
        ) as temporary:
            root = Path(temporary)
            git(root, "init", "-q")
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "tracked.json").write_text('{"ok":true}\n', encoding="utf-8")
            (evidence / "untracked.txt").write_text("exclude\n", encoding="utf-8")
            git(root, "add", "evidence/tracked.json")
            value = INDEX.build_index(root, (("fixture", "evidence"),))
            self.assertEqual(value["totals"]["entries"], 1)
            self.assertEqual(value["entries"][0]["path"], "evidence/tracked.json")
            self.assertEqual(value["source_sets"][0]["extension_counts"], {".json": 1})


if __name__ == "__main__":
    unittest.main()
