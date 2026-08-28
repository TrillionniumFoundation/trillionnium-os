from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

from tools.tests import test_adb_smart_socket_relay_selected as relay_suite
from tools.tests import test_qualify_owner_open_adb_selected as adb_suite

ROOT = Path(__file__).resolve().parents[1] / "owner-open"
RELEASE_RELAY = ROOT / "adb_smart_socket_relay_release.py"
RELEASE_QUALIFIER = ROOT / "qualify_owner_open_adb_release.py"
RELEASE_SUPERVISOR = ROOT / "supervise_codex_mcp_qualification_release.py"

class ReleaseAdbRelayV2Test(relay_suite.SelectedAdbSmartSocketRelayTest):
    RELAY = RELEASE_RELAY

    def test_arbitrary_bytes_and_half_close_are_preserved(self) -> None:
        child, descriptor, events = self.start_relay()
        payload = (
            b"0012host:transport-any"
            b"000chost:version"
            b"\x00\xffunknown-service\n"
            + os.urandom(131072)
        )
        terminal = None
        try:
            self.assertEqual(self.exchange(descriptor, payload), payload)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                records = [
                    json.loads(line)
                    for line in events.read_text().splitlines()
                ]
                terminal = next(
                    (
                        item
                        for item in records
                        if item["kind"] == "connection_terminal"
                    ),
                    None,
                )
                if terminal is not None:
                    break
                time.sleep(0.02)
        finally:
            _stdout, stderr = self.stop_relay(child)
        self.assertEqual(stderr, b"")
        self.assertEqual(
            descriptor["selected_entry"],
            "tools/owner-open/adb_smart_socket_relay_release.py",
        )
        self.assertTrue(descriptor["byte_transparent"])
        self.assertFalse(descriptor["adb_protocol_parsed"])
        self.assertFalse(descriptor["argv_or_serial_injected"])
        if terminal is None:
            self.fail(
                "relay did not durably record connection_terminal before shutdown"
            )
        self.assertEqual(terminal["client_to_upstream_bytes"], len(payload))
        self.assertEqual(terminal["upstream_to_client_bytes"], len(payload))
        self.assertFalse(terminal["payload_logged"])
        self.assertNotIn("raw_line_base64", events.read_text())


class ReleaseAdbQualificationV2Test(adb_suite.SelectedAdbQualificationTest):
    RELAY = RELEASE_RELAY
    QUALIFIER = RELEASE_QUALIFIER


class ReleaseSupervisorV2PreflightTest(unittest.TestCase):
    def test_release_supervisor_requires_private_evidence_parent(self) -> None:
        import tempfile
        import shutil

        root = Path(tempfile.mkdtemp(prefix="r5-release-supervisor-v2-"))
        try:
            root.chmod(0o700)
            home = root / "home"
            workspace = root / "workspace"
            shared = root / "shared"
            home.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            shared.mkdir(mode=0o755)
            codex = root / "codex"
            qualifier = root / "qualifier.py"
            codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            qualifier.write_text("raise SystemExit(99)\n", encoding="utf-8")
            codex.chmod(0o700)
            qualifier.chmod(0o600)
            completed = subprocess.run(
                [
                    str(Path(sys.executable).resolve()),
                    str(RELEASE_SUPERVISOR),
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
                    "release-v2-preflight",
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
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
