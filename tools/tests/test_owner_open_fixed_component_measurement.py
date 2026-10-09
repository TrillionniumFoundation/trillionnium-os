"""Real host descriptor regression for the fixed Android component reader."""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class FixedComponentBehavior(unittest.TestCase):
    def test_real_descriptor_negative_and_property_publication_paths(self):
        compiler = shutil.which(os.environ.get("CXX", "g++"))
        configured = os.environ.get("TRILLIONNIUM_JSONCPP_ROOT")
        if not compiler or not configured:
            self.skipTest("CXX and TRILLIONNIUM_JSONCPP_ROOT required for real native host fixture")
        jsoncpp = Path(configured)
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            binary = scratch / "fixed-measurement"
            source = ROOT / "tools/tests/native/owner_open_fixed_component_measurement_test.cpp"
            command = [compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                       "-I" + str(jsoncpp / "include"), str(source)]
            command += [str(jsoncpp / "src/lib_json" / name) for name in
                        ("json_reader.cpp", "json_value.cpp", "json_writer.cpp")]
            command += ["-lcrypto", "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            profile = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/config/profile-codex-host-relay-v1.json"
            run = subprocess.run([str(binary), str(scratch), str(profile)], capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("actual_host_descriptor_property_checks=", run.stdout)
            self.assertIn("android_property_server_tested=0", run.stdout)
            self.assertIn("phone_operations=0", run.stdout)
            print(run.stdout, end="")

if __name__ == "__main__":
    unittest.main()
