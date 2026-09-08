from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/g1-synthetic-merge.yml"
EXACT_HEAD_WORKFLOW = ROOT / ".github/workflows/g1-exact-head-source.yml"
CANONICAL_NAME = "g1-synthetic-merge"
CANONICAL_EMAIL = "g1-synthetic-merge@invalid"
CANONICAL_DATE = "2000-01-01T00:00:00Z"
CANONICAL_EPOCH = "946684800 +0000"


class SyntheticMergeIdentityTest(unittest.TestCase):
    def git(
        self,
        root: Path,
        *args: str,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
    ) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            input=stdin,
            env=env,
        )
        return completed.stdout.strip()

    def canonical_commit(
        self,
        root: Path,
        tree: str,
        base: str,
        head: str,
        empty_home: Path,
    ) -> str:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "HOME": str(empty_home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": CANONICAL_NAME,
            "GIT_AUTHOR_EMAIL": CANONICAL_EMAIL,
            "GIT_AUTHOR_DATE": CANONICAL_DATE,
            "GIT_COMMITTER_NAME": CANONICAL_NAME,
            "GIT_COMMITTER_EMAIL": CANONICAL_EMAIL,
            "GIT_COMMITTER_DATE": CANONICAL_DATE,
        }
        message = f"G1 synthetic merge {base} + {head}\n"
        return self.git(
            root,
            "--no-replace-objects",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "i18n.commitEncoding=UTF-8",
            "commit-tree",
            tree,
            "-p",
            base,
            "-p",
            head,
            env=env,
            stdin=message,
        )

    @staticmethod
    def expected_object_id(tree: str, base: str, head: str) -> str:
        message = f"G1 synthetic merge {base} + {head}\n"
        payload = (
            f"tree {tree}\n"
            f"parent {base}\n"
            f"parent {head}\n"
            f"author {CANONICAL_NAME} <{CANONICAL_EMAIL}> {CANONICAL_EPOCH}\n"
            f"committer {CANONICAL_NAME} <{CANONICAL_EMAIL}> {CANONICAL_EPOCH}\n"
            f"\n"
            f"{message}"
        ).encode("utf-8")
        header = f"commit {len(payload)}\0".encode("ascii")
        return hashlib.sha1(header + payload).hexdigest()

    def test_workflow_fixes_every_commit_identity_field(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        for literal in (
            "env -i",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_GLOBAL=/dev/null",
            f"GIT_AUTHOR_NAME={CANONICAL_NAME}",
            f"GIT_AUTHOR_EMAIL={CANONICAL_EMAIL}",
            f"GIT_AUTHOR_DATE={CANONICAL_DATE}",
            f"GIT_COMMITTER_NAME={CANONICAL_NAME}",
            f"GIT_COMMITTER_EMAIL={CANONICAL_EMAIL}",
            f"GIT_COMMITTER_DATE={CANONICAL_DATE}",
            "-c commit.gpgSign=false",
            "-c i18n.commitEncoding=UTF-8",
            "recomputed_merge_commit=\"$(canonical_commit)\"",
            "test \"$merge_commit\" = \"$recomputed_merge_commit\"",
        ):
            self.assertIn(literal, source)

    def test_required_context_is_owned_by_synthetic_attempt(self) -> None:
        synthetic = WORKFLOW.read_text(encoding="utf-8")
        exact_head = EXACT_HEAD_WORKFLOW.read_text(encoding="utf-8")
        required = "name: L1 exact-source-head aggregate candidate"
        self.assertEqual(synthetic.count(required), 1)
        self.assertNotIn(required, exact_head)
        self.assertIn("  source-admission:\n", synthetic)
        self.assertIn("      - synthetic-merge\n", synthetic)
        self.assertIn("    if: ${{ always() }}\n", synthetic)
        self.assertIn(
            "SYNTHETIC_RESULT: ${{ needs.synthetic-merge.result }}", synthetic
        )
        self.assertIn('test "$SYNTHETIC_RESULT" = success', synthetic)
        self.assertIn(
            "name: L1 exact-head direct-source aggregate", exact_head
        )

    def test_same_tree_and_ordered_parents_produce_one_commit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            home = Path(temporary) / "empty-home"
            root.mkdir()
            home.mkdir(mode=0o700)
            self.git(root, "init")
            self.git(root, "config", "user.name", "ambient-one")
            self.git(root, "config", "user.email", "ambient-one@invalid")
            (root / "payload").write_text("base\n", encoding="utf-8")
            self.git(root, "add", "payload")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD^{commit}")
            (root / "payload").write_text("head\n", encoding="utf-8")
            self.git(root, "add", "payload")
            self.git(root, "commit", "-m", "head")
            head = self.git(root, "rev-parse", "HEAD^{commit}")
            tree = self.git(root, "rev-parse", "HEAD^{tree}")

            first = self.canonical_commit(root, tree, base, head, home)
            time.sleep(1.05)
            self.git(root, "config", "user.name", "ambient-two")
            self.git(root, "config", "user.email", "ambient-two@invalid")
            second = self.canonical_commit(root, tree, base, head, home)

            self.assertEqual(first, second)
            self.assertEqual(first, self.expected_object_id(tree, base, head))
            self.assertEqual(
                self.git(root, "rev-parse", f"{first}^1"),
                base,
            )
            self.assertEqual(
                self.git(root, "rev-parse", f"{first}^2"),
                head,
            )
            self.assertEqual(
                self.git(root, "rev-parse", f"{first}^{{tree}}"),
                tree,
            )


if __name__ == "__main__":
    unittest.main()
