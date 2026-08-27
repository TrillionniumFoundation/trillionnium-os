from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import textwrap
import time
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools/owner-open-adb-relay-bootstrap.py"
spec = importlib.util.spec_from_file_location("owner_open_adb_relay_bootstrap", SCRIPT)
assert spec is not None and spec.loader is not None
relay = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = relay
spec.loader.exec_module(relay)


class OwnerOpenAdbRelayBootstrapTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.executable = self.root / "fake-adb"
        self.executable.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/python3
                import json
                import sys
                import time

                if sys.argv[1:] == ["sleep"]:
                    time.sleep(5)
                elif sys.argv[1:] == ["large"]:
                    sys.stdout.buffer.write(b"x" * 128)
                else:
                    sys.stdout.write(json.dumps(sys.argv[1:]))
                    sys.stderr.buffer.write(b"stderr\\x00bytes")
                """
            ),
            encoding="utf-8",
        )
        self.executable.chmod(0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def config(self, **overrides: int) -> relay.RelayConfig:
        values = {
            "adb_executable": self.executable,
            "default_timeout_ms": 1_000,
            "kill_grace_ms": 20,
            "output_limit_bytes": 1024,
        }
        values.update(overrides)
        return relay.RelayConfig(**values)

    def request(self, argv: list[str], **extra: object) -> bytes:
        value: dict[str, object] = {
            "protocol": relay.PROTOCOL,
            "protocol_version": relay.PROTOCOL_VERSION,
            "request_id": "request-1",
            "argv": argv,
        }
        value.update(extra)
        return json.dumps(value).encode("utf-8")

    def test_duplicate_members_fail_before_execution(self) -> None:
        with self.assertRaises(relay.DuplicateMemberError):
            relay.decode_request_line(
                b'{"protocol":"a","protocol":"b","request_id":"r","argv":[]}'
            )

    def test_exact_unknown_argv_is_executed_without_injection(self) -> None:
        argv = ["future-subcommand", "--future-flag", "a b"]
        result = relay.process_line(self.request(argv, opaque={"kept": True}), self.config())
        self.assertEqual(result["status"], "exited")
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["serial_host_port_or_privilege_injected"])
        self.assertEqual(result["argv"], argv)
        observed = json.loads(base64.b64decode(result["stdout_base64"]))
        self.assertEqual(observed, argv)
        self.assertEqual(base64.b64decode(result["stderr_base64"]), b"stderr\x00bytes")
        self.assertEqual(result["request_extensions"], {"opaque": {"kept": True}})

    def test_empty_argv_preserves_ordinary_client_behavior(self) -> None:
        result = relay.process_line(self.request([]), self.config())
        self.assertEqual(result["status"], "exited")
        self.assertEqual(json.loads(base64.b64decode(result["stdout_base64"])), [])

    def test_spawned_jsonl_process_preserves_exact_argv(self) -> None:
        argv = ["devices", "-l"]
        completed = subprocess.run(
            [sys.executable, os.fspath(SCRIPT), "--adb", os.fspath(self.executable), "--once"],
            input=self.request(argv) + b"\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        response = json.loads(completed.stdout)
        self.assertEqual(response["status"], "exited")
        self.assertEqual(response["argv"], argv)
        self.assertFalse(response["serial_host_port_or_privilege_injected"])

    def test_timeout_terminates_the_process_group(self) -> None:
        started = time.monotonic()
        result = relay.process_line(self.request(["sleep"], timeout_ms=30), self.config())
        self.assertEqual(result["status"], "timed_out")
        self.assertTrue(result["timed_out"])
        self.assertLess(time.monotonic() - started, 2)

    def test_zero_timeout_uses_owner_configured_default(self) -> None:
        result = relay.process_line(
            self.request(["sleep"], timeout_ms=0),
            self.config(default_timeout_ms=30),
        )
        self.assertEqual(result["status"], "timed_out")

    def test_output_is_read_with_an_explicit_cap(self) -> None:
        result = relay.process_line(
            self.request(["large"]), self.config(output_limit_bytes=16)
        )
        self.assertEqual(result["stdout_bytes"], 128)
        self.assertTrue(result["stdout_truncated"])
        self.assertEqual(len(base64.b64decode(result["stdout_base64"])), 16)

    def test_writable_or_symlink_executable_is_rejected(self) -> None:
        self.executable.chmod(0o722)
        with self.assertRaises(relay.RelayError):
            relay.validate_executable(self.executable)
        self.executable.chmod(0o700)
        link = self.root / "adb-link"
        link.symlink_to(self.executable)
        with self.assertRaises(relay.RelayError):
            relay.validate_executable(link)


if __name__ == "__main__":
    unittest.main()
