"""Exercise the real CLI parser and scalar projection without contacting a phone."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import model_profiles
import phone_acceptance as acceptance
import phone_inventory as inventory


class ProfileCliTests(unittest.TestCase):
    def argv(self, profile=None):
        args = [
            "phone_acceptance.py", "--adb", "/not-executed/adb",
            "--adb-port", "17389", "--serial", "SYNTHETIC",
            "run-task", "--case-id", "profile-parser-only",
            "--instruction", "打开设置。", "--evidence-root", "/not-created",
        ]
        if profile is not None:
            args.extend(["--expected-model-profile", profile])
        return args

    def test_every_registered_profile_reaches_task_dispatch_unchanged(self):
        for name in model_profiles.PROFILES:
            with self.subTest(profile=name), patch.object(sys, "argv", self.argv(name)), \
                    patch.object(acceptance, "run_task", return_value=23) as dispatch, \
                    patch.object(acceptance, "Adb", side_effect=AssertionError("no device access")):
                self.assertEqual(acceptance.main(), 23)
                dispatch.assert_called_once()
                self.assertEqual(dispatch.call_args.args[0].expected_model_profile, name)

    def test_omitted_profile_keeps_the_registered_default(self):
        with patch.object(sys, "argv", self.argv()), \
                patch.object(acceptance, "run_task", return_value=23) as dispatch, \
                patch.object(acceptance, "Adb", side_effect=AssertionError("no device access")):
            self.assertEqual(acceptance.main(), 23)
            dispatch.assert_called_once()
            self.assertEqual(dispatch.call_args.args[0].expected_model_profile,
                             model_profiles.DEFAULT_PROFILE)

    def test_unknown_profiles_fail_before_task_dispatch(self):
        for name in ("unknown-model", "lfm3-1x7b-qad-q4_0",
                     "qwen3.5-9b-q4_0-extra", "../LFM3-1.7B-QAD-Q4_0.gguf"):
            with self.subTest(profile=name), patch.object(sys, "argv", self.argv(name)), \
                    patch.object(acceptance, "run_task") as dispatch, \
                    patch.object(acceptance, "Adb", side_effect=AssertionError("no device access")), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                acceptance.main()
            self.assertEqual(error.exception.code, 2)
            dispatch.assert_not_called()


class ProfileProjectionTests(unittest.TestCase):
    @staticmethod
    def config(profile=None):
        result = {"schema": "hepta.local-runtime.v1", "compute": "npu",
                  "context_tokens": 4096, "threads": 4}
        if profile is not None:
            result.update(schema="hepta.local-runtime.v2", model_profile=profile)
        return result

    def project_on_host(self, values):
        # Execute the unchanged read-only phone projection script against a private
        # synthetic host fixture, including its actual sed -E allowlist and hashes.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "files/model/runtime-config.json"
            source.parent.mkdir(parents=True)
            original = (json.dumps(dict(values, private_note="DO_NOT_EXPORT"), indent=2) + "\n").encode()
            source.write_bytes(original)
            source.chmod(0o600)
            result = subprocess.run(["sh", "-c", inventory.CONFIG_SCRIPT], cwd=root,
                                    capture_output=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(source.read_bytes(), original)
            self.assertNotIn(b"DO_NOT_EXPORT", result.stdout)
            self.assertNotIn(b"private_note", result.stdout)
            return result.stdout

    def parse(self, raw):
        return inventory.parse_projection(raw, inventory.CONFIG_KEYS,
                                          "hepta.local-runtime.v1", os.getuid())

    def test_every_registered_v2_profile_survives_complete_projection(self):
        for name in model_profiles.PROFILES:
            with self.subTest(profile=name):
                expected = self.config(name)
                parsed = self.parse(self.project_on_host(expected))
                self.assertEqual(parsed["status"], "OBSERVED_PROJECTION")
                self.assertEqual(parsed["values"], expected)
                self.assertFalse(parsed["full_source_json_validated"])
                self.assertFalse(parsed["inference_claims_independently_verified"])

    def test_unknown_profiles_are_not_exported_and_v2_remains_unverified(self):
        for name in ("unknown-model", "lfm3-1x7b-qad-q4_0",
                     "qwen3.5-9b-q4_0-extra", "qwen3.5-9b-q4_0|unknown"):
            with self.subTest(profile=name):
                raw = self.project_on_host(self.config(name))
                self.assertNotIn(b'"model_profile"', raw)
                with self.assertRaises(acceptance.DriverError):
                    self.parse(raw)

    def test_v1_keeps_no_implicit_profile(self):
        expected = self.config()
        parsed = self.parse(self.project_on_host(expected))
        self.assertEqual(parsed["values"], expected)
        self.assertNotIn("model_profile", parsed["values"])

    def test_other_config_enum_limits_remain_closed(self):
        for key, value in (("compute", "cpu"), ("context_tokens", 2048), ("threads", 9)):
            with self.subTest(field=key):
                values = self.config(model_profiles.DEFAULT_PROFILE)
                values[key] = value
                raw = self.project_on_host(values)
                with self.assertRaises(acceptance.DriverError):
                    self.parse(raw)


if __name__ == "__main__":
    unittest.main()
