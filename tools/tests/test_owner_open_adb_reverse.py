#!/usr/bin/env python3
"""Host-only contract tests for the W3-A adb reverse bootstrap."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/owner-open/prepare-adb-reverse-v1.sh"
SERIAL = "ZY32JLVHGN"


class OwnerOpenAdbReverseBootstrapTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "reverse-state"
        self.log = self.root / "adb.log"
        self.started = self.root / "adb-started"
        self.adb = self.bin / "adb"
        self.ss = self.bin / "ss"
        self._write_executable(
            self.adb,
            r'''#!/bin/sh
set -eu
: "${FAKE_ADB_STATE:?}"
: "${FAKE_ADB_LOG:?}"
: "${FAKE_ADB_STARTED:?}"
printf 'ANDROID_ADB_SERVER_ADDRESS=%s ANDROID_ADB_SERVER_PORT=%s ADB_SERVER_PORT=%s ADB_SERVER_SOCKET=%s %s\n' \
  "${ANDROID_ADB_SERVER_ADDRESS-}" "${ANDROID_ADB_SERVER_PORT-}" \
  "${ADB_SERVER_PORT-}" "${ADB_SERVER_SOCKET-}" "$*" >>"$FAKE_ADB_LOG"
case "${1-}" in
  version)
    printf '%s\n' 'Android Debug Bridge version 1.0.41' 'Version 35.0.2-test'
    exit 0
    ;;
  devices)
    if [ "${FAKE_ADB_DEVICE_PRESENT:-1}" = 1 ]; then
      printf '%s\n' 'List of devices attached' "${FAKE_ADB_SERIAL} device product:test model:test transport_id:1"
    else
      printf '%s\n' 'List of devices attached'
    fi
    exit 0
    ;;
  start-server)
    : >"$FAKE_ADB_STARTED"
    exit 0
    ;;
esac
if [ "${1-}" = -s ] && [ "${2-}" = "$FAKE_ADB_SERIAL" ] && [ "${3-}" = reverse ]; then
  case "${4-}" in
    --remove)
      rm -f "$FAKE_ADB_STATE"
      exit 0
      ;;
    --list)
      if [ -f "$FAKE_ADB_STATE" ]; then
        cat "$FAKE_ADB_STATE"
      fi
      exit 0
      ;;
    tcp:*)
      printf '%s %s %s\n' "$FAKE_ADB_SERIAL" "$4" "$5" >"$FAKE_ADB_STATE"
      exit 0
      ;;
  esac
fi
printf 'unexpected fake adb invocation: %s\n' "$*" >&2
exit 2
''',
        )
        self._write_executable(
            self.ss,
            "#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 128 127.0.0.1:5037 0.0.0.0:*'\n",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_executable(self, path: Path, content: str) -> None:
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run_script(self, *arguments: str, extra_env: dict[str, str] | None = None):
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin}:{env.get('PATH', '')}",
                "FAKE_ADB_STATE": str(self.state),
                "FAKE_ADB_LOG": str(self.log),
                "FAKE_ADB_STARTED": str(self.started),
                "FAKE_ADB_SERIAL": SERIAL,
            }
        )
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(SCRIPT), *arguments],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def _path_without_ss(self) -> str:
        """Build a minimal PATH that retains script dependencies but no ss."""
        path = self.root / "path-without-ss"
        path.mkdir()
        for name in ("bash", "awk", "cat", "rm"):
            target = shutil.which(name)
            self.assertIsNotNone(target, name)
            (path / name).symlink_to(target)
        return str(path)

    def test_apply_creates_only_the_exact_mapping_and_bounded_evidence(self) -> None:
        evidence = self.root / "evidence.json"
        result = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
            "--device-port",
            "15037",
            "--host-port",
            "5037",
            "--evidence",
            str(evidence),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ADB_SERVER_SOCKET=tcp:127.0.0.1:15037\n")
        self.assertEqual(
            self.state.read_text(encoding="utf-8"),
            f"{SERIAL} tcp:15037 tcp:5037\n",
        )
        log = self.log.read_text(encoding="utf-8")
        self.assertIn(f"-s {SERIAL} reverse tcp:15037 tcp:5037", log)
        self.assertNotIn("-s android:diagnostic", log)

        document = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(
            document["schema"],
            "org.trillionnium.owner-open.adb-reverse-bootstrap-evidence.v1",
        )
        self.assertEqual(document["serial"], SERIAL)
        self.assertEqual(document["adb_server_socket"], "tcp:127.0.0.1:15037")
        self.assertFalse(document["integrated_codex_turn_proven"])
        self.assertFalse(document["physical_effect_proven"])
        self.assertFalse(document["release_evidence"])
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)

    def test_nondefault_host_port_is_bound_to_every_adb_invocation(self) -> None:
        self._write_executable(
            self.ss,
            "#!/bin/sh\nprintf '%s\n' 'LISTEN 0 128 127.0.0.1:15038 0.0.0.0:*'\n",
        )
        result = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
            "--device-port",
            "15037",
            "--host-port",
            "15038",
            extra_env={"ADB_SERVER_PORT": "5037"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.state.read_text(encoding="utf-8"),
            f"{SERIAL} tcp:15037 tcp:15038\n",
        )
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("ADB_SERVER_SOCKET=tcp:127.0.0.1:15038", log)
        self.assertNotIn("ADB_SERVER_SOCKET=tcp:127.0.0.1:5037", log)
        self.assertIn("ANDROID_ADB_SERVER_PORT= ", log)
        self.assertIn("ADB_SERVER_PORT= ", log)

    def test_listener_probe_runs_after_adb_start_server(self) -> None:
        self._write_executable(
            self.ss,
            r'''#!/bin/sh
set -eu
: "${FAKE_ADB_STARTED:?}"
[ -f "$FAKE_ADB_STARTED" ] || {
  printf '%s\n' 'listener probe ran before adb start-server' >&2
  exit 42
}
printf '%s\n' 'LISTEN 0 128 127.0.0.1:5037 0.0.0.0:*'
''',
        )
        result = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.started.exists())

    def test_missing_ss_is_fail_closed(self) -> None:
        self.ss.unlink()
        result = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
            extra_env={"PATH": self._path_without_ss()},
        )
        self.assertEqual(result.returncode, 69, result.stderr)
        self.assertIn("ss is required", result.stderr)
        self.assertFalse(self.state.exists())

    def test_ss_probe_failure_is_fail_closed(self) -> None:
        self._write_executable(
            self.ss,
            "#!/bin/sh\nprintf '%s\\n' 'synthetic ss failure' >&2\nexit 1\n",
        )
        result = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
        )
        self.assertEqual(result.returncode, 69, result.stderr)
        self.assertIn("listener probe failed", result.stderr)
        self.assertFalse(self.state.exists())

    def test_ipv6_loopback_listener_spellings_are_accepted(self) -> None:
        for endpoint in ("[::1]:15038", "::1:15038"):
            with self.subTest(endpoint=endpoint):
                self._write_executable(
                    self.ss,
                    f"#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 128 {endpoint} 0.0.0.0:*'\n",
                )
                result = self.run_script(
                    "--serial",
                    SERIAL,
                    "--apply",
                    "--adb",
                    str(self.adb),
                    "--device-port",
                    "15037",
                    "--host-port",
                    "15038",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    self.state.read_text(encoding="utf-8"),
                    f"{SERIAL} tcp:15037 tcp:15038\n",
                )

    def test_ipv6_nonloopback_listener_requires_acknowledgement(self) -> None:
        self._write_executable(
            self.ss,
            "#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 128 [::]:15038 0.0.0.0:*'\n",
        )
        denied = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
            "--host-port",
            "15038",
        )
        self.assertEqual(denied.returncode, 77, denied.stderr)
        self.assertIn("non-loopback listener", denied.stderr)
        self.assertFalse(self.state.exists())

    def test_remove_deletes_only_the_requested_reverse_endpoint(self) -> None:
        self.state.write_text(f"{SERIAL} tcp:15037 tcp:5037\n", encoding="utf-8")
        result = self.run_script(
            "--serial",
            SERIAL,
            "--remove",
            "--adb",
            str(self.adb),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())
        self.assertIn(
            f"-s {SERIAL} reverse --remove tcp:15037",
            self.log.read_text(encoding="utf-8"),
        )

    def test_action_and_exact_serial_are_mandatory(self) -> None:
        missing_action = self.run_script("--serial", SERIAL, "--adb", str(self.adb))
        self.assertEqual(missing_action.returncode, 64)
        self.assertIn("select exactly one", missing_action.stderr)

        absent = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
            extra_env={"FAKE_ADB_DEVICE_PRESENT": "0"},
        )
        self.assertEqual(absent.returncode, 66)
        self.assertIn("absent or ambiguous", absent.stderr)
        self.assertFalse(self.state.exists())

    def test_nonloopback_server_listener_requires_explicit_acknowledgement(self) -> None:
        self._write_executable(
            self.ss,
            "#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 128 0.0.0.0:5037 0.0.0.0:*'\n",
        )
        denied = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
        )
        self.assertEqual(denied.returncode, 77)
        self.assertIn("non-loopback listener", denied.stderr)
        self.assertFalse(self.state.exists())

        accepted = self.run_script(
            "--serial",
            SERIAL,
            "--apply",
            "--adb",
            str(self.adb),
            "--allow-nonloopback-server",
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_ports_and_serial_are_strictly_bounded(self) -> None:
        for arguments in (
            ("--serial", "../../bad", "--apply"),
            ("--serial", SERIAL, "--apply", "--device-port", "0"),
            ("--serial", SERIAL, "--apply", "--host-port", "65536"),
            ("--serial", SERIAL, "--apply", "--host-port", "not-a-port"),
        ):
            result = self.run_script(*arguments, "--adb", str(self.adb))
            self.assertEqual(result.returncode, 64, (arguments, result.stderr))
            self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
