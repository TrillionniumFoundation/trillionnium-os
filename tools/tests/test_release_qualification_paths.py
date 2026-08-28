from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.tests import test_adb_smart_socket_relay_selected as relay_suite
from tools.tests import test_qualify_owner_open_adb_selected as adb_suite

ROOT = Path(__file__).resolve().parents[1] / "owner-open"
RELEASE_RELAY = ROOT / "adb_smart_socket_relay_release.py"
RELEASE_QUALIFIER = ROOT / "qualify_owner_open_adb_release.py"


class ReleaseAdbRelayTest(relay_suite.SelectedAdbSmartSocketRelayTest):
    RELAY = RELEASE_RELAY


class ReleaseAdbQualificationTest(adb_suite.SelectedAdbQualificationTest):
    RELAY = RELEASE_RELAY
    QUALIFIER = RELEASE_QUALIFIER


class ReleaseCodexSupervisorPreflightTest(unittest.TestCase):
    def test_shared_evidence_parent_is_rejected_before_inner_execution(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="r5-release-supervisor-"))
        try:
            root.chmod(0o700)
            home = root / "home"
            workspace = root / "workspace"
            home.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            codex = root / "codex"
            qualifier = root / "qualifier.py"
            codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            qualifier.write_text("raise SystemExit(99)\n", encoding="utf-8")
            codex.chmod(0o700)
            qualifier.chmod(0o600)
            shared = root / "shared"
            shared.mkdir(mode=0o755)
            completed = subprocess.run(
                [
                    str(Path(sys.executable).resolve()),
                    str(ROOT / "supervise_codex_mcp_qualification_release.py"),
                    "--execute",
                    "--python",
                    str(Path(sys.executable).resolve()),
                    "--qualifier",
                    str(qualifier),
                    "--codex",
                    str(codex),
                    "--codex-home",
                    str(home),
                    "--workspace",
                    str(workspace),
                    "--evidence-dir",
                    str(shared / "evidence"),
                    "--server-name",
                    "release-preflight",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"evidence parent must be private", completed.stderr)
            self.assertFalse((shared / "evidence").exists())
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
