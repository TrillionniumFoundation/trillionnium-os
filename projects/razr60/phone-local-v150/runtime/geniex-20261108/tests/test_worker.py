#!/usr/bin/env python3
"""Host contract/fault tests; these are not Android/NPU validation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PIN_HEADER_SHA = "c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40"


class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="hepta-geniex-host-build-")
        cls.binary = Path(cls.build.name) / "worker-host-stub"
        assert hashlib.sha256((ROOT / "vendor/geniex.h").read_bytes()).hexdigest() == PIN_HEADER_SHA
        command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O2",
                   "-isystem", str(ROOT / "vendor"), str(ROOT / "worker.c"), str(ROOT / "tests/stub_geniex.c"), "-o", str(cls.binary)]
        subprocess.run(command, check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-geniex-host-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.prompt = self.private("prompt", b"Answer only 42.")
        self.model = self.private("model.gguf", b"host fixture, never a real model")
        self.mmproj = self.private("mmproj.gguf", b"host fixture")
        self.result = self.root / "result.json"
        self.raw = self.root / "text.bin"
        self.trace = self.root / "trace"
        self.env = {**os.environ, "STUB_TRACE": str(self.trace)}

    def private(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def args(self, overrides=None, extra=()):
        flags = {"--request-id": "ab" * 16, "--mode": "llm", "--runtime": "llama_cpp", "--compute": "npu",
                 "--model": str(self.model), "--prompt-file": str(self.prompt), "--result-file": str(self.result),
                 "--text-file": str(self.raw), "--ctx-size": "8192"}
        flags.update(overrides or {})
        return [str(self.binary)] + [part for pair in flags.items() for part in pair] + list(extra)

    def run_worker(self, case="success", overrides=None, extra=(), env=None):
        actual = {**self.env, "STUB_CASE": case, **(env or {})}
        process = subprocess.run(self.args(overrides, extra), env=actual, capture_output=True, timeout=10)
        self.assertEqual(process.stdout, b"", process.stdout)
        metadata = json.loads(self.result.read_bytes()) if self.result.exists() else None
        return process, metadata

    def test_complete_preserves_original_utf8_bytes_and_hashes(self):
        value = '{"结果":"蓝色按钮在上方"}\n'
        prompt = "请描述当前图片，不要执行动作。".encode()
        self.prompt.write_bytes(prompt)
        process, result = self.run_worker(env={"STUB_TEXT": value, "STUB_EXPECT_CTX": "8192"})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(result["generation_complete"])
        self.assertEqual(self.raw.read_bytes(), value.encode())
        self.assertEqual(result["raw_text_sha256"], hashlib.sha256(value.encode()).hexdigest())
        self.assertEqual(result["input_sha256"]["prompt"], hashlib.sha256(prompt).hexdigest())
        self.assertEqual(result["formatted_prompt_sha256"], hashlib.sha256(b"S:\nU:" + prompt).hexdigest())
        self.assertEqual(result["profile"]["prompt_tokens"], 789)
        self.assertEqual(result["sdk_rc"]["generate"], 0)
        self.assertEqual(result["generate_attempt_count"], 1)
        self.assertEqual(self.trace.read_text().splitlines().count("generate"), 1)
        self.assertFalse(result["production_receipt"])
        self.assertFalse(result["process_exit_observed"])
        self.assertFalse(result["native_action_authorized"])
        self.assertEqual(result["n_ctx_create"], 8192)
        self.assertEqual(result["power_mode_create"], 6)
        self.assertEqual(result["power_mode_name"], "sustained_high_performance")
        self.assertEqual(result["device_resolved"], "HTP0")
        self.assertIn(b"SDK debug stdout", process.stderr)
        self.assertEqual(self.result.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.result.stat().st_nlink, 1)
        self.assertFalse(list(self.root.glob("*.pending")))

    def test_explicit_vlm_cpu_encoder_and_image_bound_to_hash(self):
        image = self.private("image.png", b"fixture bytes (stub does not decode)")
        system = self.private("system", "只输出JSON。".encode())
        grammar = self.private("grammar", b'root ::= "42"')
        process, result = self.run_worker(overrides={"--mode": "vlm", "--mmproj": str(self.mmproj),
            "--vit-device": "CPU", "--image": str(image), "--system-file": str(system), "--grammar-file": str(grammar)},
            env={"STUB_EXPECT_CTX": "8192", "STUB_EXPECT_VIT": "CPU", "STUB_EXPECT_IMAGE": "yes", "STUB_EXPECT_GRAMMAR": grammar.read_text()})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(result["input_sha256"]["image"], hashlib.sha256(image.read_bytes()).hexdigest())
        self.assertEqual(result["vit_device_requested"], "CPU")
        self.assertFalse(result["image_token_bounds_exposed_by_abi"])

    def test_qairt_zero_create_config(self):
        bundle = self.root / "bundle"
        bundle.mkdir(mode=0o700)
        process, result = self.run_worker(overrides={"--runtime": "qairt", "--mode": "vlm", "--model": str(bundle), "--ctx-size": "0"})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual((result["n_ctx_create"], result["n_gpu_layers_create"]), (0, 0))
        self.assertEqual(result["device_resolved"], "NPU")

    def test_nonterminal_stop_reasons_do_not_complete(self):
        for case in ("length", "user", "context_length", "unknown", "missing_stop"):
            with self.subTest(case=case):
                self.result.unlink(missing_ok=True); self.raw.unlink(missing_ok=True)
                process, result = self.run_worker(case)
                self.assertEqual(process.returncode, 70)
                self.assertFalse(result["generation_complete"])
                self.assertEqual(result["sdk_rc"]["generate"], 0)
                self.assertEqual(self.raw.read_bytes(), b"42")

    def test_stop_sequence_complete(self):
        process, result = self.run_worker("stop_sequence")
        self.assertEqual(process.returncode, 0)
        self.assertEqual(result["stop_reason"], "stop_sequence")

    def test_negative_generate_rc_wins_even_with_eos(self):
        process, result = self.run_worker("generate_fail_with_text")
        self.assertEqual(process.returncode, 70)
        self.assertEqual(result["sdk_rc"]["generate"], -119)
        self.assertEqual(result["stop_reason"], "eos")
        self.assertFalse(result["generation_complete"])

    def test_failed_generate_without_full_text_keeps_callback_prefix(self):
        process, result = self.run_worker("generate_fail", env={"STUB_TEXT": "已输出的前缀"})
        self.assertEqual(process.returncode, 70)
        self.assertEqual(self.raw.read_bytes(), "已输出的前缀".encode())
        self.assertEqual(result["raw_text_source"], "callback_prefix")
        self.assertTrue(result["raw_text_truncated"])
        self.assertFalse(result["generation_complete"])

    def test_output_bound_preserves_prefix_and_never_completes(self):
        process, result = self.run_worker("output_large")
        self.assertEqual(process.returncode, 70)
        self.assertEqual(self.raw.read_bytes(), b"x" * (1024 * 1024))
        self.assertEqual(result["raw_text_sha256"], hashlib.sha256(self.raw.read_bytes()).hexdigest())
        self.assertTrue(result["raw_text_truncated"])
        self.assertTrue(result["callback_limit_observed"])
        self.assertFalse(result["generation_complete"])

    def test_invalid_utf8_is_preserved_but_unusable(self):
        process, result = self.run_worker("output_invalid")
        self.assertEqual(process.returncode, 70)
        self.assertEqual(self.raw.read_bytes(), b"\xff")
        self.assertFalse(result["raw_text_utf8"])

    def test_lifecycle_attempts_preserve_exact_rc_or_null(self):
        cases = {
            "version_bad": ("resolve", None), "version_invalid": ("resolve", None),
            "resolve_fail": ("resolve", -113), "log_fail": ("set_log_level", -110),
            "init_fail": ("init", -111), "create_fail": ("create", -114),
            "create_null": ("destroy", None), "create_partial": ("destroy", 0),
            "template_fail": ("template", -117), "template_invalid": ("generate", None),
            "template_large": ("generate", None), "coerce": ("init", None),
        }
        for case, (field, expected) in cases.items():
            with self.subTest(case=case):
                self.result.unlink(missing_ok=True); self.raw.unlink(missing_ok=True)
                process, result = self.run_worker(case)
                self.assertEqual(process.returncode, 70, process.stderr)
                self.assertEqual(result["sdk_rc"][field], expected)
                self.assertIsNone(result["sdk_rc"]["generate"])
                self.assertIsNone(result["profile"])
                self.assertEqual(result["generate_attempt_count"], 0)

    def test_destroy_and_deinit_failure_do_not_complete(self):
        for case, field, code in (("destroy_fail", "destroy", -116), ("deinit_fail", "deinit", -112)):
            with self.subTest(case=case):
                self.result.unlink(missing_ok=True); self.raw.unlink(missing_ok=True)
                process, result = self.run_worker(case)
                self.assertEqual(process.returncode, 70)
                self.assertEqual(result["sdk_rc"][field], code)
                self.assertFalse(result["generation_complete"])

    def test_cancel_fence_at_create_last_token_and_destroy(self):
        for case, calls in (("signal_create", 0), ("signal_last_token", 1), ("signal_destroy", 1)):
            with self.subTest(case=case):
                self.result.unlink(missing_ok=True); self.raw.unlink(missing_ok=True)
                process, result = self.run_worker(case)
                self.assertEqual(process.returncode, 128 + signal.SIGTERM)
                self.assertEqual(result["signal_observed"], signal.SIGTERM)
                self.assertEqual(result["generate_attempt_count"], calls)
                self.assertFalse(result["generation_complete"])

    def test_real_host_signal_and_waitpid_observation(self):
        env = {**self.env, "STUB_CASE": "wait_for_term"}
        child = subprocess.Popen(self.args(), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.trace.exists() and "waiting\n" in self.trace.read_text():
                break
            time.sleep(0.01)
        else:
            self.fail("stub never entered generation")
        child.send_signal(signal.SIGTERM)
        stdout, stderr = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 128 + signal.SIGTERM, stderr)
        self.assertEqual(stdout, b"")
        result = json.loads(self.result.read_bytes())
        self.assertFalse(result["generation_complete"])
        self.assertFalse(result["process_exit_observed"])
        self.assertEqual(result["pid"], child.pid)

    def test_hard_killed_host_process_has_no_complete_result(self):
        child = subprocess.Popen(self.args(), env={**self.env, "STUB_CASE": "hard_hang"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.trace.exists() and "generate\n" in self.trace.read_text():
                break
            time.sleep(0.01)
        else:
            self.fail("stub never entered generation")
        child.kill(); child.communicate(timeout=3)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertFalse(self.result.exists())
        self.assertTrue(list(self.root.glob("*.pending")))

    def test_cooperative_deadline_cannot_complete(self):
        process, result = self.run_worker("deadline", overrides={"--timeout-ms": "10"})
        self.assertEqual(process.returncode, 124)
        self.assertTrue(result["deadline_observed"])
        self.assertFalse(result["generation_complete"])

    def test_input_replacement_metadata_rejects_output(self):
        process, result = self.run_worker("input_changed", env={"STUB_PROMPT_PATH": str(self.prompt)})
        self.assertEqual(process.returncode, 70)
        self.assertFalse(result["input_metadata_unchanged"])
        self.assertFalse(result["generation_complete"])

    def test_nonfinite_profile_fields_remain_valid_json(self):
        process, result = self.run_worker("nonfinite")
        self.assertEqual(process.returncode, 0)
        self.assertIsNone(result["profile"]["prefill_tokens_per_second"])
        self.assertIsNone(result["profile"]["decode_tokens_per_second"])

    def test_repeat_result_never_overwrites_or_generates(self):
        process, _ = self.run_worker()
        self.assertEqual(process.returncode, 0)
        before = self.result.read_bytes()
        calls_before = self.trace.read_bytes()
        process, _ = self.run_worker()
        self.assertEqual(process.returncode, 73)
        self.assertEqual(self.result.read_bytes(), before)
        self.assertEqual(self.trace.read_bytes(), calls_before)

    def test_unknown_duplicate_and_incompatible_cli_flags_reject_before_sdk(self):
        vectors = [({}, ("--remote-url", "https://example.com")), ({}, ("--compute", "cpu")),
                   ({"--ctx-size": "8192junk"}, ()), ({"--ctx-size": "99999999999999999999999999"}, ()),
                   ({"--request-id": "../path"}, ()), ({"--max-tokens": "0"}, ()),
                   ({"--runtime": "qairt", "--ctx-size": "8192"}, ()),
                   ({"--runtime": "qairt", "--ctx-size": "0", "--compute": "gpu"}, ()),
                   ({"--mode": "llm", "--vit-device": "CPU"}, ()),
                   ({"--mode": "vlm", "--mmproj": str(self.mmproj), "--vit-device": "unknown"}, ())]
        for overrides, extra in vectors:
            with self.subTest(overrides=overrides, extra=extra):
                process, result = self.run_worker(overrides=overrides, extra=extra)
                self.assertEqual(process.returncode, 64)
                self.assertIsNone(result)
                self.assertFalse(self.trace.exists())

    def test_prompt_bounds_utf8_and_ownership_mode(self):
        for data, mode in ((b"", 0o600), (b"a" * 65537, 0o600), (b"a\0b", 0o600), (b"\xed\xa0\x80", 0o600), (b"valid", 0o644)):
            with self.subTest(size=len(data), mode=mode):
                self.prompt.write_bytes(data); self.prompt.chmod(mode)
                process, result = self.run_worker()
                self.assertEqual(process.returncode, 65)
                self.assertIsNone(result)
                self.assertFalse(self.trace.exists())

    def test_maximum_prompt_and_empty_output_sha(self):
        data = b"abc" * 21845 + b"x"
        self.assertEqual(len(data), 65536)
        self.prompt.write_bytes(data)
        process, result = self.run_worker(env={"STUB_TEXT": ""})
        self.assertEqual(process.returncode, 0)
        self.assertEqual(result["input_sha256"]["prompt"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["raw_text_sha256"], hashlib.sha256(b"").hexdigest())

    def test_symlink_and_nonprivate_output_are_rejected(self):
        link = self.root / "prompt-link"
        link.symlink_to(self.prompt)
        process, _ = self.run_worker(overrides={"--prompt-file": str(link)})
        self.assertEqual(process.returncode, 65)
        self.root.chmod(0o755)
        process, _ = self.run_worker()
        self.assertEqual(process.returncode, 73)
        self.assertFalse(self.trace.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
