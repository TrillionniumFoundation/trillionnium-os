from __future__ import annotations

from pathlib import Path
import re
import unittest


WORKFLOW_ROOT = Path(__file__).resolve().parents[2] / ".github" / "workflows"
DIRECT_VERIFIER = re.compile(
    r"^\s*python3\s+tools/verify-owner-open-r5(?:-gap-evidence)?\.py(?:\s|$)"
)
RUN_KEY = re.compile(r"^(?P<indent>\s*)run:\s*(?P<value>.*)$")
GIT_CHECK = re.compile(r"\bgit\s+(?P<args>[^#\r\n]*)")
GIT_CHECK_COMMAND = re.compile(r"\b(?:rev-parse|status|diff)\b")


def workflow_paths() -> list[Path]:
    return sorted(WORKFLOW_ROOT.glob("owner-open*.yml"))


def run_blocks(path: Path) -> list[tuple[int, str]]:
    """Return (line number, shell text) for YAML ``run`` values.

    This intentionally handles only the small subset needed by GitHub Actions:
    an inline ``run: command`` or a literal/folded block (``run: |``/``>``).
    Keeping the check stdlib-only means it also runs in the bare Python setup
    used by the workflows; actionlint remains the complete YAML parser.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = RUN_KEY.match(lines[index])
        if match is None:
            index += 1
            continue
        line_number = index + 1
        value = match.group("value").strip()
        if value not in {"|", ">", "|-", ">-", "|+", ">+"}:
            blocks.append((line_number, value))
            index += 1
            continue
        key_indent = len(match.group("indent").expandtabs(2))
        body: list[str] = []
        index += 1
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip():
                candidate_indent = len(candidate) - len(candidate.lstrip(" "))
                if candidate_indent <= key_indent:
                    break
            body.append(candidate)
            index += 1
        blocks.append((line_number, "\n".join(body)))
    return blocks


def verifier_commands(block: str) -> list[str]:
    """Extract each direct verifier command and its shell continuations."""
    lines = block.splitlines()
    commands: list[str] = []
    index = 0
    while index < len(lines):
        if DIRECT_VERIFIER.match(lines[index]) is None:
            index += 1
            continue
        command_lines = [lines[index].strip()]
        while command_lines[-1].rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            command_lines.append(lines[index].strip())
        commands.append("\n".join(command_lines))
        index += 1
    return commands


class OwnerOpenWorkflowExactHeadTest(unittest.TestCase):
    def test_direct_verifier_invocations_bind_checkout_pair(self) -> None:
        paths = workflow_paths()
        self.assertTrue(paths, f"no owner-open workflows found under {WORKFLOW_ROOT}")
        invocations: list[str] = []
        for path in paths:
            for line_number, block in run_blocks(path):
                commands = verifier_commands(block)
                for command in commands:
                    with self.subTest(workflow=path.name, line=line_number):
                        self.assertIn(
                            '--expected-commit "$SOURCE_HEAD_SHA"',
                            command,
                        )
                        self.assertIn(
                            '--expected-tree "$SOURCE_HEAD_TREE"',
                            command,
                        )
                        invocations.append(command)
                        self.assertRegex(
                            block,
                            r'SOURCE_HEAD_TREE="\$\(git\s+--no-replace-objects\s+'
                            r'rev-parse\s+HEAD\^\{tree\}\)"',
                        )
        self.assertGreaterEqual(
            len(invocations),
            1,
            "no direct owner-open R5 verifier invocation was found",
        )

    def test_head_status_and_diff_checks_disable_replacement_objects(self) -> None:
        paths = workflow_paths()
        self.assertTrue(paths, f"no owner-open workflows found under {WORKFLOW_ROOT}")
        checked = 0
        for path in paths:
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = GIT_CHECK.search(line)
                if match is None:
                    continue
                command = GIT_CHECK_COMMAND.search(match.group("args"))
                if command is None:
                    continue
                checked += 1
                with self.subTest(workflow=path.name, line=line_number):
                    prefix = match.group("args")[: command.start()]
                    self.assertIn(
                        "--no-replace-objects",
                        prefix.split(),
                        "exact-head/status/diff git checks must ignore replace refs",
                    )
        self.assertGreaterEqual(checked, 1, "no git exact-head/status/diff check found")


if __name__ == "__main__":
    unittest.main()
