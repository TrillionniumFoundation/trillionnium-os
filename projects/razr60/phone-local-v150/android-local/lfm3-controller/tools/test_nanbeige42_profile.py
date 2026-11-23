"""Closed Nanbeige artifact through the real host consumers, with no device IO."""
import contextlib
import copy
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import model_profiles as profiles
import phone_acceptance as acceptance
import phone_suite as suite
import test_model_profiles as existing

NAME = "nanbeige4.2-3b-q4_k_m"
EXPECTED = {
    "file": "Nanbeige_Nanbeige4.2-3B-Q4_K_M.gguf", "bytes": 2684023968,
    "sha256": "b92d2e35c9876b0c4bc671996360204f4149d0546c23d5954d5eb3b106c81f24",
    "architecture": "nanbeige", "exact": True,
}


class Nanbeige42ProfileTests(unittest.TestCase):
    def native(self, context=4096):
        value = existing.ProfileTests().native()
        value.update(model_profile=NAME, model_sha256_verified=EXPECTED["sha256"],
                     model_architecture=EXPECTED["architecture"], model_bytes_verified=EXPECTED["bytes"])
        tokens = context - 512
        value["prompt_budget"].update(model_contract_sha256=EXPECTED["sha256"], context_tokens=context,
                                     prompt_tokens_exact=tokens, input_ids_count=tokens, total_context_tokens=context)
        value["profile"]["prompt_tokens"] = tokens
        return value

    def plan(self, compute="npu", context=4096):
        return {"schema": suite.SCHEMA, "suite_id": "synthetic-nanbeige-contract",
                "candidate": {"package": acceptance.PACKAGE, "apk_sha256": None, "version_code": 30,
                              "model_sha256": EXPECTED["sha256"], "model_profile": NAME,
                              "compute": compute, "context_tokens": context, "threads": 4},
                "cases": [{"case_id": "synthetic-unexecuted", "instruction": "打开设置。",
                           "expected_package": "com.android.settings", "expected_visible_text": ["设置"],
                           "text_match": "exact", "required_actions": [{"action": "open", "package": "com.android.settings"}],
                           "setup_home": True, "timeout_seconds": 540}]}

    def test_exact_registry_values_and_unchanged_default(self):
        self.assertEqual(profiles.profile(NAME), EXPECTED)
        self.assertEqual(profiles.DEFAULT_PROFILE, "lfm3-1.7b-qad-q4_0")
        self.assertEqual(list(profiles.PROFILES)[-1], NAME)
        snapshot = profiles.profile(NAME)
        snapshot["sha256"] = "0" * 64
        self.assertEqual(profiles.profile(NAME), EXPECTED)
        root = Path(__file__).resolve().parents[1]
        native = (root / "native/model-profile.h").read_text()
        java = (root / "src/org/trillionnium/hepta/local/ModelProfile.java").read_text()
        row = ('{"' + NAME + '","' + EXPECTED["file"] + '","' + EXPECTED["sha256"]
               + '","nanbeige",UINT64_C(2684023968),true}')
        self.assertIn(row, native)
        self.assertIn('"bartowski/Nanbeige_Nanbeige4.2-3B-GGUF","210b0d6d6c1046044c7ea9d16c9ce3b5716ec2d2"', java)
        self.assertIn('"' + EXPECTED["sha256"] + '","nanbeige",true,6L<<30)', java)

    def test_existing_plan_contract_accepts_both_explicit_contexts_without_qualifying(self):
        for compute in ("npu", "gpu"):
            for context in (4096, 8192):
                with self.subTest(compute=compute, context=context):
                    result = suite.validate_plan(self.plan(compute, context))
                    self.assertTrue(result["valid"])
                    self.assertFalse(result["runnable"])
                    self.assertFalse(result["phone_contacted"])
                    with self.assertRaises(acceptance.DriverError):
                        suite.validate_plan(self.plan(compute, context), require_runnable=True)

    def test_actual_plan_rejects_cross_bound_or_unbounded_inputs(self):
        for key, value in (("model_sha256", profiles.profile("orvena-4b-q4_k_m")["sha256"]),
                           ("model_profile", "nanbeige"), ("compute", "cpu"),
                           ("context_tokens", 131072), ("context_tokens", True), ("threads", 9)):
            with self.subTest(field=key, value=value):
                plan = self.plan()
                plan["candidate"][key] = value
                with self.assertRaises(acceptance.DriverError):
                    suite.validate_plan(plan)
        plan = self.plan()
        plan["candidate"]["model_path"] = "/tmp/arbitrary.gguf"
        with self.assertRaises(acceptance.DriverError):
            suite.validate_plan(plan)

    def test_existing_exact_native_proof_accepts_only_bound_same_ids(self):
        for context in (4096, 8192):
            with self.subTest(context=context):
                value = self.native(context)
                self.assertTrue(acceptance.native_budget_valid(value, context, NAME))
                for other in (profiles.DEFAULT_PROFILE, "orvena-4b-q4_k_m", "bonsai2-9b-q2_0"):
                    self.assertFalse(acceptance.native_budget_valid(value, context, other))
                for field in ("model_sha256_verified", "model_architecture", "model_bytes_verified",
                              "model_metadata_unchanged", "chat_template_enable_thinking", "automatic_cpu_fallback"):
                    invalid = copy.deepcopy(value)
                    invalid[field] = None
                    self.assertFalse(acceptance.native_budget_valid(invalid, context, NAME), field)
                for field in ("checked", "admitted", "is_exact_token_count", "input_ids_sha256",
                              "input_ids_passed_directly", "tokenizer_source_commit", "reserved_tokens"):
                    invalid = copy.deepcopy(value)
                    invalid["prompt_budget"].pop(field)
                    self.assertFalse(acceptance.native_budget_valid(invalid, context, NAME), field)
                invalid = copy.deepcopy(value)
                count = context - 511
                invalid["prompt_budget"].update(prompt_tokens_exact=count, input_ids_count=count,
                                                total_context_tokens=context + 1)
                invalid["profile"]["prompt_tokens"] = count
                self.assertFalse(acceptance.native_budget_valid(invalid, context, NAME))
                invalid = copy.deepcopy(value)
                invalid["profile"]["prompt_tokens"] -= 1
                self.assertFalse(acceptance.native_budget_valid(invalid, context, NAME))

    def test_real_cli_preserves_fixed_profile_and_does_not_accept_aliases(self):
        base = ["phone_acceptance.py", "--adb", "/not-executed/adb", "--adb-port", "17389",
                "--serial", "SYNTHETIC", "run-task", "--case-id", "synthetic-contract",
                "--instruction", "打开设置。", "--evidence-root", "/not-created",
                "--expected-context", "4096", "--expected-model-profile"]
        with patch.object(sys, "argv", base + [NAME]), patch.object(acceptance, "run_task", return_value=23) as run, \
                patch.object(acceptance, "Adb", side_effect=AssertionError("no phone")):
            self.assertEqual(acceptance.main(), 23)
            self.assertEqual(run.call_args.args[0].expected_model_profile, NAME)
        for name in ("nanbeige", "Nanbeige4.2-3B", "../" + EXPECTED["file"]):
            with self.subTest(name=name), patch.object(sys, "argv", base + [name]), \
                    patch.object(acceptance, "run_task") as run, contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                acceptance.main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
