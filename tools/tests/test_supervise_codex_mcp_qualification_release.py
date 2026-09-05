from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1] / "owner-open"
SUPERVISOR = ROOT / "supervise_codex_mcp_qualification_release.py"

FAKE_CODEX = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
log = Path(os.environ["FAKE_CODEX_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\n")
raise SystemExit(0)
'''

FAKE_QUALIFIER = r'''#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import time
parser=argparse.ArgumentParser(add_help=False)
parser.add_argument("--evidence-dir", required=True, type=Path)
parser.add_argument("--codex-home", required=True, type=Path)
args,_=parser.parse_known_args()
args.evidence_dir.mkdir(mode=0o700)
(args.codex_home / "config.toml").write_text("mutated=true\n", encoding="utf-8")
(args.evidence_dir / "qualification-terminal.json").write_text(
    json.dumps({"status": os.environ.get("FAKE_STATUS", "passed")}),
    encoding="utf-8",
)
if os.environ.get("FAKE_HANG") == "1":
    time.sleep(60)
raise SystemExit(int(os.environ.get("FAKE_RC", "0")))
'''


class ReleaseCodexQualificationSupervisorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.python = self.root / "python"
        shutil.copyfile(Path(sys.executable).resolve(), self.python)
        self.python.chmod(0o700)
        self.home = self.root / "home"
        self.workspace = self.root / "workspace"
        self.evidence_parent = self.root / "evidence"
        for path in (self.home, self.workspace, self.evidence_parent):
            path.mkdir(mode=0o700)
        self.original = b"original=true\n"
        (self.home / "config.toml").write_bytes(self.original)
        (self.home / "config.toml").chmod(0o600)
        self.codex = self.root / "codex"
        self.qualifier = self.root / "qualifier.py"
        self.codex.write_text(FAKE_CODEX, encoding="utf-8")
        self.qualifier.write_text(FAKE_QUALIFIER, encoding="utf-8")
        self.codex.chmod(0o700)
        self.qualifier.chmod(0o600)
        self.log = self.root / "codex.log"
        self.environment = os.environ.copy()
        self.environment["FAKE_CODEX_LOG"] = str(self.log)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def command(self, evidence: Path, timeout: str = "5") -> list[str]:
        return [
            str(Path(sys.executable).resolve()),
            str(SUPERVISOR),
            "--execute",
            "--python",
            str(self.python),
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
            "release-qualification",
            "--timeout",
            timeout,
            "--cleanup-timeout",
            "2",
            "--",
            "--trace-proxy",
            str(self.root / "trace.py"),
        ]

    def run_command(
        self, evidence: Path, *, timeout: str = "5", **environment: str
    ):
        env = self.environment.copy()
        env.update(environment)
        return subprocess.run(
            self.command(evidence, timeout),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=12,
            check=False,
        )

    def report(self, evidence: Path) -> dict:
        path = evidence.parent / f"{evidence.name}.supervisor.json"
        self.assertTrue(path.exists())
        return json.loads(path.read_text())

    def assert_restored(self) -> None:
        self.assertEqual((self.home / "config.toml").read_bytes(), self.original)
        self.assertFalse((self.home / ".trillionnium-qualification-supervisor.lock").exists())

    def test_success_requires_passed_terminal_and_restored_config(self) -> None:
        evidence = self.evidence_parent / "pass"
        completed = self.run_command(evidence)
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        self.assert_restored()
        report = self.report(evidence)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["cleanup"]["config_restored"])
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertIn(["mcp", "remove", "release-qualification"], calls)

    def test_inner_zero_exit_with_nonpassed_terminal_fails(self) -> None:
        evidence = self.evidence_parent / "nonpass"
        completed = self.run_command(evidence, FAKE_STATUS="failed_cleanup")
        self.assertNotEqual(completed.returncode, 0)
        self.assert_restored()
        report = self.report(evidence)
        self.assertEqual(report["claim_ceiling"], "QUALIFICATION_FAILED_NO_PROMOTION")

    def test_timeout_kills_group_and_restores_config(self) -> None:
        evidence = self.evidence_parent / "timeout"
        started = time.monotonic()
        completed = self.run_command(evidence, timeout="1", FAKE_HANG="1")
        self.assertLess(time.monotonic() - started, 8)
        self.assertNotEqual(completed.returncode, 0)
        self.assert_restored()
        report = self.report(evidence)
        self.assertTrue(report["inner_process"]["timed_out"])
        self.assertFalse(report["automatic_redispatch"])

    def test_nonprivate_evidence_parent_is_rejected(self) -> None:
        shared = self.root / "shared"
        shared.mkdir(mode=0o755)
        # Preserve the intentionally hostile mode under a restrictive umask.
        shared.chmod(0o755)
        evidence = shared / "evidence"
        completed = subprocess.run(
            self.command(evidence),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"evidence parent must be private", completed.stderr)
        self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
