from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SUPERVISOR = (
    Path(__file__).resolve().parents[1]
    / "owner-open"
    / "supervise_codex_mcp_qualification.py"
)

FAKE_CODEX = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

log = Path(os.environ["FAKE_CODEX_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\n")
if sys.argv[1:3] == ["mcp", "remove"]:
    raise SystemExit(0)
raise SystemExit(0)
'''

FAKE_QUALIFIER = r'''#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import time

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--evidence-dir", required=True, type=Path)
parser.add_argument("--codex-home", required=True, type=Path)
args, _rest = parser.parse_known_args()
args.evidence_dir.mkdir(mode=0o700)
(args.codex_home / "config.toml").write_text("mutated=true\n", encoding="utf-8")
status = os.environ.get("FAKE_QUALIFIER_STATUS", "passed")
(args.evidence_dir / "qualification-terminal.json").write_text(
    json.dumps({"status": status, "automatic_redispatch": False}),
    encoding="utf-8",
)
if os.environ.get("FAKE_QUALIFIER_HANG") == "1":
    time.sleep(60)
raise SystemExit(int(os.environ.get("FAKE_QUALIFIER_RC", "0")))
'''


class SuperviseCodexMcpQualificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.home = self.root / "codex-home"
        self.workspace = self.root / "workspace"
        self.home.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        self.original = b"original=true\n"
        (self.home / "config.toml").write_bytes(self.original)
        (self.home / "config.toml").chmod(0o600)
        self.codex = self.root / "codex"
        self.qualifier = self.root / "qualifier.py"
        self.log = self.root / "codex-log.jsonl"
        self.codex.write_text(FAKE_CODEX, encoding="utf-8")
        self.qualifier.write_text(FAKE_QUALIFIER, encoding="utf-8")
        self.codex.chmod(0o700)
        self.qualifier.chmod(0o600)
        self.environment = os.environ.copy()
        self.environment["FAKE_CODEX_LOG"] = str(self.log)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def command(self, evidence: Path, timeout: float = 5) -> list[str]:
        return [
            str(Path(sys.executable).resolve()),
            str(SUPERVISOR),
            "--execute",
            "--python",
            str(Path(sys.executable).resolve()),
            "--qualifier",
            str(self.qualifier),
            "--codex",
            str(self.codex),
            "--codex-home",
            str(self.home),
            "--workspace",
            str(self.workspace),
            "--evidence-dir",
            str(evidence),
            "--server-name",
            "qualification-fixture",
            "--timeout",
            str(timeout),
            "--cleanup-timeout",
            "2",
            "--",
            "--trace-proxy",
            str(self.root / "trace.py"),
        ]

    def run_supervisor(self, evidence: Path, **environment: str) -> subprocess.CompletedProcess[bytes]:
        env = self.environment.copy()
        env.update(environment)
        return subprocess.run(
            self.command(evidence, timeout=float(environment.get("TEST_TIMEOUT", "5"))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=12,
            check=False,
        )

    def assert_restored(self, evidence: Path) -> dict:
        self.assertEqual((self.home / "config.toml").read_bytes(), self.original)
        self.assertFalse((self.home / ".trillionnium-qualification-supervisor.lock").exists())
        report_path = evidence.parent / f"{evidence.name}.supervisor.json"
        self.assertTrue(report_path.exists())
        return json.loads(report_path.read_text())

    def test_pass_requires_inner_pass_and_exact_config_restoration(self) -> None:
        evidence = self.root / "evidence-pass"
        completed = self.run_supervisor(evidence)
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        report = self.assert_restored(evidence)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["cleanup"]["config_restored"])
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertIn(["mcp", "remove", "qualification-fixture"], calls)

    def test_zero_exit_with_failed_cleanup_terminal_is_not_a_pass(self) -> None:
        evidence = self.root / "evidence-failed-cleanup"
        completed = self.run_supervisor(
            evidence, FAKE_QUALIFIER_STATUS="failed_cleanup"
        )
        self.assertNotEqual(completed.returncode, 0)
        report = self.assert_restored(evidence)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["claim_ceiling"], "QUALIFICATION_FAILED_NO_PROMOTION")

    def test_hung_inner_qualifier_is_killed_and_config_is_restored(self) -> None:
        evidence = self.root / "evidence-hang"
        started = time.monotonic()
        completed = self.run_supervisor(
            evidence,
            FAKE_QUALIFIER_HANG="1",
            TEST_TIMEOUT="0.3",
        )
        self.assertLess(time.monotonic() - started, 8)
        self.assertNotEqual(completed.returncode, 0)
        report = self.assert_restored(evidence)
        self.assertTrue(report["inner_process"]["timed_out"])
        self.assertFalse(report["automatic_redispatch"])

    def test_forwarded_core_arguments_cannot_override_supervised_paths(self) -> None:
        evidence = self.root / "evidence-override"
        command = self.command(evidence)
        command.extend(["--codex-home", str(self.root / "other")])
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"may not override --codex-home", completed.stderr)
        self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
