"""Host-side tests for the bounded read-only Android smoke collector."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
