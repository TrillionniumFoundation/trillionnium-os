"""Host-side tests for the bounded read-only Android smoke collector."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "android_ci_device_smoke.py"
SPEC = importlib.util.spec_from_file_location("android_ci_device_smoke", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


FAKE_ADB = """#!/usr/bin/env python3
import sys

args = sys.argv[1:]
if args == ["version"]:
    print("Android Debug Bridge version 1.0.41")
    raise SystemExit(0)
if len(args) >= 3 and args[:2] == ["-s", "SERIAL"]:
    args = args[2:]
if args == ["get-state"]:
    print("device")
    raise SystemExit(0)
if args[:2] == ["shell", "getprop"]:
    values = {
        "ro.product.device": "fogos",
        "ro.build.type": "userdebug",
        "ro.build.version.sdk": "36",
        "ro.build.fingerprint": "fixture/fogos:16/test:userdebug/test-keys",
        "ro.boot.slot_suffix": "_a",
        "ro.boot.verifiedbootstate": "orange",
    }
    print(values[args[2]])
    raise SystemExit(0)
if args == ["shell", "getenforce"]:
    print("Enforcing")
    raise SystemExit(0)
if args == ["shell", "id", "-u"]:
    print("2000")
    raise SystemExit(0)
if args[:3] == ["shell", "pm", "path"]:
    print("package:/system_ext/app/Fixture/Fixture.apk")
    raise SystemExit(0)
print("unexpected command", args, file=sys.stderr)
raise SystemExit(64)
"""


class DeviceSmokeTests(unittest.TestCase):
    def _fake_adb(self, directory: Path) -> Path:
        path = directory / "adb"
        path.write_text(FAKE_ADB, encoding="utf-8")
        path.chmod(0o755)
        return path

    def _arguments(self, adb: Path, output: Path) -> list[str]:
        return [
            "--adb",
            str(adb),
            "--serial",
            "SERIAL",
            "--repository",
            "Example/fixture",
            "--source-commit",
            "a" * 40,
            "--source-tree",
            "c" * 40,
            "--source-package-sha256",
            "b" * 64,
            "--output",
            str(output),
        ]

    def test_success_receipt_is_explicitly_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "receipt.json"
            result = tool.main(self._arguments(self._fake_adb(root), receipt_path))
            self.assertEqual(result, 0)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["result"], "PASS_READ_ONLY")
            self.assertFalse(receipt["mutation"]["performed"])
            self.assertEqual(receipt["device"]["properties"]["ro.product.device"], "fogos")
            self.assertEqual(len(receipt["device"]["state_samples"]), 3)
            commands = [
                token
                for observation in receipt["observations"]
                for token in observation["argv"]
            ]
            self.assertFalse(set(commands) & {"install", "push", "root", "reboot", "fastboot"})

    def test_wrong_product_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adb = self._fake_adb(root)
            receipt_path = root / "receipt.json"
            arguments = self._arguments(adb, receipt_path)
            arguments.extend(["--expected-product-device", "other"])
            self.assertEqual(tool.main(arguments), 2)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["result"], "FAIL_READ_ONLY")

    def test_invalid_serial_is_rejected_before_adb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = self._arguments(self._fake_adb(root), root / "receipt.json")
            arguments[arguments.index("SERIAL")] = "bad serial"
            self.assertEqual(tool.main(arguments), 2)
            self.assertFalse((root / "receipt.json").exists())

    def test_subprocess_captures_both_streams_and_exit_status(self) -> None:
        observation = tool._run_adb(
            Path(sys.executable),
            None,
            ["-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)"],
            5,
        )
        self.assertEqual(observation["returncode"], 7)
        self.assertEqual(observation["stdout"], "out\n")
        self.assertEqual(observation["stderr"], "err\n")
        self.assertFalse(observation["timed_out"])
        self.assertFalse(observation["output_limit_exceeded"])

    def test_subprocess_output_is_bounded_while_streaming(self) -> None:
        observation = tool._run_adb(
            Path(sys.executable),
            None,
            ["-c", "import os\nwhile True: os.write(1, b'x' * 4096)"],
            5,
        )
        self.assertTrue(observation["output_limit_exceeded"])
        self.assertFalse(observation["timed_out"])
        self.assertIsNone(observation["returncode"])
        self.assertFalse(tool._successful(observation))
        self.assertLessEqual(len(observation["stdout"].encode()), tool.MAX_CAPTURE_BYTES + 32)

    def test_subprocess_bounds_combined_stdout_and_stderr(self) -> None:
        observation = tool._run_adb(
            Path(sys.executable),
            None,
            ["-c", "import os; os.write(1, b'o'*20000); os.write(2, b'e'*20000)"],
            5,
        )
        self.assertTrue(observation["output_limit_exceeded"])
        self.assertFalse(tool._successful(observation))

    def test_timeout_still_applies_after_output_pipes_close(self) -> None:
        observation = tool._run_adb(
            Path(sys.executable),
            None,
            ["-c", "import os,time; os.close(1); os.close(2); time.sleep(5)"],
            0.2,
        )
        self.assertTrue(observation["timed_out"])
        self.assertIsNone(observation["returncode"])
        self.assertLess(observation["seconds"], 2)

    def test_oversized_adb_result_writes_failure_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adb = root / "adb"
            adb.write_text(
                "#!/usr/bin/env python3\nimport os\nos.write(1, b'x' * 100000)\n",
                encoding="utf-8",
            )
            adb.chmod(0o755)
            output = root / "receipt.json"
            with mock.patch("sys.stdout"):
                self.assertEqual(tool.main(self._arguments(adb, output)), 2)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["result"], "FAIL_READ_ONLY")
            self.assertTrue(all(item["output_limit_exceeded"] for item in receipt["observations"]))

    def test_capture_setup_failures_reap_process_and_close_pipes(self) -> None:
        for failure in ("selector", "blocking", "register"):
            with self.subTest(failure=failure):
                processes = []
                original_popen = tool.subprocess.Popen

                def spawn(*args, **kwargs):
                    process = original_popen(*args, **kwargs)
                    processes.append(process)
                    return process

                selector = mock.Mock()
                if failure == "register":
                    selector.register.side_effect = OSError("register failed")
                with mock.patch.object(tool.subprocess, "Popen", side_effect=spawn), \
                     mock.patch.object(
                         tool.selectors, "DefaultSelector", return_value=selector,
                         side_effect=OSError("EMFILE") if failure == "selector" else None,
                     ), \
                     mock.patch.object(
                         tool.os, "set_blocking",
                         side_effect=OSError("blocking failed") if failure == "blocking" else None,
                     ):
                    observation = tool._run_adb(
                        Path(sys.executable), None,
                        ["-c", "import time; time.sleep(20)"], 5,
                    )
                self.assertTrue(observation["capture_error"])
                self.assertFalse(tool._successful(observation))
                self.assertEqual(len(processes), 1)
                self.assertIsNotNone(processes[0].poll())
                self.assertTrue(processes[0].stdout.closed)
                self.assertTrue(processes[0].stderr.closed)
                if failure != "selector":
                    selector.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
