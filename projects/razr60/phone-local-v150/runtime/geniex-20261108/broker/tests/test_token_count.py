#!/usr/bin/env python3
"""Real C process/file/ABI regression tests with an explicit host-only stub.

No phone, Android library, real tokenizer, model, NPU or network is used here.
The fixture reports bytes as synthetic token counts to make ABI/format/boundary
assertions deterministic. Real Qwen tokenizer/SDK equivalence is a device gate.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

BROKER = Path(__file__).resolve().parents[1]
HEAD = b"<|im_start|>system\n"
MIDDLE = b"<|im_end|>\n<|im_start|>user\n"
TAIL = b"<|im_end|>\n<|im_start|>assistant\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(**fields):
    return json.dumps({"hepta_tokenizer_host_fixture_v1": fields}, separators=(",", ":")).encode()


class TokenCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_temp = tempfile.TemporaryDirectory(prefix="hepta-token-count-build-")
        cls.build = Path(cls.build_temp.name).resolve()
        cls.binary = cls.build / "token-count-host"
        cls.library = cls.build / "tokenizer-host-fixture.so"
        cls.missing_library = cls.build / "missing-symbol-host-fixture.so"
        cc = shutil.which("cc")
        if not cc:
            raise RuntimeError("C compiler required")
        flags = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
        for argv in (
            flags + [str(BROKER / "token_count.c"), "-ldl", "-o", str(cls.binary)],
            flags + ["-shared", "-fPIC", str(BROKER / "tests/tokenizer_stub.c"), "-o", str(cls.library)],
            flags + ["-shared", "-fPIC", "-DHEPTA_FIXTURE_OMIT_ENCODE", str(BROKER / "tests/tokenizer_stub.c"), "-o", str(cls.missing_library)],
        ):
            subprocess.run(argv, check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.build_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-token-count-case-")
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.prompt_raw = "  点击蓝色按钮；保留换行\n以及 e\u0301 / \u0344 / 😀。  ".encode()
        self.system_raw = b"Use only current verified observations."
        self.prompt = self.write("prompt.txt", self.prompt_raw)
        self.system = self.write("system.txt", self.system_raw)
        self.tokenizer = self.write("tokenizer.fixture.json", b'{"fixture":true}')
        self.image = self.write("image.fixture.png", b"\x89PNG\r\n\x1a\nHOST FIXTURE, NOT DECODED")
        self.result = self.root / "count.json"
        self.request_id = "a" * 32

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def args(self, *, image=False, library=None):
        library = library or self.library
        argv = [str(self.binary), "--request-id", self.request_id,
                "--library", str(library), "--library-sha256", sha(library.read_bytes()),
                "--tokenizer", str(self.tokenizer), "--tokenizer-sha256", sha(self.tokenizer.read_bytes()),
                "--prompt-file", str(self.prompt), "--system-file", str(self.system),
                "--result-file", str(self.result), "--max-prompt", "3584"]
        if image:
            argv += ["--image", str(self.image)]
        return argv

    def run_count(self, *, image=False, argv=None, env=None):
        process = subprocess.run(argv or self.args(image=image), capture_output=True, timeout=5,
                                 env={**os.environ, **(env or {})})
        value = json.loads(self.result.read_bytes()) if self.result.exists() else None
        return process, value

    def test_no_image_uses_one_complete_formatter_segment_and_preserves_raw_unicode(self):
        capture = self.root / "segments.fixture"
        process, value = self.run_count(env={"HEPTA_TOKENIZER_FIXTURE_CAPTURE": str(capture)})
        expected = HEAD + self.system_raw + MIDDLE + self.prompt_raw + TAIL
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, b"")
        self.assertEqual(value["schema"], "hepta.geniex-token-count.v1")
        self.assertTrue(value["success"] and value["input_unchanged"] and value["raw_input_preserved"])
        self.assertEqual(value["segment_token_counts"], [len(expected)])
        self.assertEqual(value["segment_sha256"], [sha(expected)])
        self.assertEqual(value["segment_utf8_bytes"], [len(expected)])
        self.assertEqual(value["prompt_tokens_upper_bound"], len(expected) + 1)
        self.assertEqual(value["formatter_overhead_utf8_bytes"], len(HEAD + MIDDLE + TAIL))
        self.assertEqual(capture.read_bytes(), str(len(expected)).encode() + b"\n" + expected + b"\n")
        self.assertEqual(self.prompt.read_bytes(), self.prompt_raw)
        self.assertEqual(value["input_sha256"], {"prompt": sha(self.prompt_raw), "system": sha(self.system_raw), "image": None})
        self.assertEqual(value["input_bytes"], {"prompt": len(self.prompt_raw), "system": len(self.system_raw), "image": 0})
        self.assertEqual(value["tokenizer_sha256"], sha(self.tokenizer.read_bytes()))
        self.assertEqual(value["library_sha256"], sha(self.library.read_bytes()))
        self.assertFalse(value["ffi_add_special_tokens"] or value["is_exact_token_count"] or value["model_loaded"] or value["native_receipt"])
        self.assertGreater(value["pid"], 0)
        self.assertEqual(value["pgid"], os.getpgrp())
        self.assertEqual(value["sid"], os.getsid(0))
        self.assertEqual(self.result.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.result.stat().st_nlink, 1)

    def test_image_counts_exact_marker_segments_and_fixed_vision_block(self):
        process, value = self.run_count(image=True)
        segments = [HEAD + self.system_raw + MIDDLE, self.prompt_raw + TAIL]
        self.assertEqual(process.returncode, 0)
        self.assertEqual(value["segment_token_counts"], list(map(len, segments)))
        self.assertEqual(value["segment_sha256"], list(map(sha, segments)))
        self.assertEqual(value["image_pad_tokens"], 256)
        self.assertEqual(value["vision_boundary_tokens"], 2)
        self.assertEqual(value["bos_token_upper_bound"], 1)
        self.assertEqual(value["prompt_tokens_upper_bound"], sum(map(len, segments)) + 259)
        self.assertEqual(value["input_sha256"]["image"], sha(self.image.read_bytes()))

    def test_exact_3584_bound_is_admitted(self):
        self.tokenizer.write_bytes(fixture(forced_count=3583))
        process, value = self.run_count()
        self.assertEqual(process.returncode, 0)
        self.assertEqual(value["prompt_tokens_upper_bound"], 3584)
        self.assertEqual([value[k] for k in ("context_tokens", "generation_tokens", "reserved_tokens")], [4096, 256, 256])

    def test_3585_rejected_before_generation(self):
        self.tokenizer.write_bytes(fixture(forced_count=3584))
        process, value = self.run_count()
        self.assertEqual(process.returncode, 2)
        self.assertEqual(value["status"], "oversize")
        self.assertFalse(value["success"])
        self.assertEqual(value["prompt_tokens_upper_bound"], 3585)

    def test_image_bound_includes_both_boundaries_and_bos(self):
        self.tokenizer.write_bytes(fixture(forced_count=1663))
        process, value = self.run_count(image=True)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(value["prompt_tokens_upper_bound"], 3585)

    def test_reserved_image_marker_in_either_input_rejected(self):
        for path in (self.prompt, self.system):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"<__image__>")
                process, value = self.run_count()
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(value["error"], "reserved_image_marker_in_text")
                self.assertEqual(value["segment_token_counts"], [])
                self.result.unlink()
                path.write_bytes(original)

    def test_malformed_utf8_nul_and_empty_text_rejected(self):
        for raw in (b"\xff", b"a\0b", b"", b"\xed\xa0\x80"):
            with self.subTest(raw=raw):
                self.prompt.write_bytes(raw)
                process, value = self.run_count()
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(value["status"], "error")
                self.assertFalse(value["input_unchanged"])
                self.result.unlink()

    def test_full_64k_text_preserved_and_one_extra_byte_rejected(self):
        self.tokenizer.write_bytes(fixture(forced_count=100))
        self.prompt.write_bytes(b"X" * 65536)
        process, value = self.run_count()
        self.assertEqual(process.returncode, 0)
        self.assertEqual(value["input_bytes"]["prompt"], 65536)
        self.assertEqual(value["input_sha256"]["prompt"], sha(b"X" * 65536))
        self.result.unlink()
        self.prompt.write_bytes(b"X" * 65537)
        process, value = self.run_count()
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(value["error"], "input_file_invalid")

    def test_artifact_pin_mismatch_rejected(self):
        for field in ("--library-sha256", "--tokenizer-sha256"):
            with self.subTest(field=field):
                argv = self.args()
                argv[argv.index(field) + 1] = "0" * 64
                process, value = self.run_count(argv=argv)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(value["error"], "artifact_sha256_mismatch")
                self.result.unlink()

    def test_symlink_hardlink_permissions_and_noncanonical_input_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.prompt)
        for path in (link, Path(str(self.root) + "/../" + self.root.name + "/prompt.txt")):
            argv = self.args(); argv[argv.index("--prompt-file") + 1] = str(path)
            process, value = self.run_count(argv=argv)
            self.assertNotEqual(process.returncode, 0)
            self.result.unlink()
        link.unlink(); os.link(self.prompt, link)
        process, _ = self.run_count(); self.assertNotEqual(process.returncode, 0); self.result.unlink()
        link.unlink(); self.prompt.chmod(0o644)
        process, _ = self.run_count(); self.assertNotEqual(process.returncode, 0)

    def test_cli_rejects_unknown_duplicate_and_unapproved_limit(self):
        variants = [self.args() + ["--unknown", "x"], self.args() + ["--request-id", "b" * 32]]
        changed = self.args(); changed[changed.index("--max-prompt") + 1] = "3585"; variants.append(changed)
        changed = self.args(); changed[changed.index("--request-id") + 1] = "A" * 32; variants.append(changed)
        for argv in variants:
            process, value = self.run_count(argv=argv)
            self.assertEqual(process.returncode, 64)
            self.assertIsNone(value)

    def test_existing_result_never_overwritten(self):
        self.result.write_bytes(b'{"existing":true}')
        before = self.result.read_bytes()
        process, _ = self.run_count()
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.result.read_bytes(), before)

    def test_result_directory_must_be_private(self):
        other = self.root / "public"
        other.mkdir(mode=0o755)
        # mkdir's mode is filtered by the host umask (pocket4 uses 077).
        # Establish and verify the intended nonprivate negative precondition.
        other.chmod(0o755)
        self.assertEqual(other.stat().st_mode & 0o777, 0o755)
        self.result = other / "count.json"
        process, value = self.run_count()
        self.assertNotEqual(process.returncode, 0)
        self.assertIsNone(value)

    def test_invalid_or_missing_ffi_result_rejected(self):
        for mode in ("null_handle", "bad_result", "negative_id"):
            with self.subTest(mode=mode):
                self.tokenizer.write_bytes(fixture(**{mode: True}))
                process, value = self.run_count()
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse(value["success"])
                self.result.unlink()
        process, value = self.run_count(argv=self.args(library=self.missing_library))
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(value["error"], "tokenizer_ffi_symbol_missing")

    def test_real_sigabrt_has_no_success_result(self):
        self.tokenizer.write_bytes(fixture(abort=True))
        process, value = self.run_count()
        self.assertEqual(process.returncode, -signal.SIGABRT)
        self.assertIsNone(value)

    def test_three_second_alarm_has_no_success_result(self):
        self.tokenizer.write_bytes(fixture(hold=True))
        process, value = self.run_count()
        self.assertEqual(process.returncode, -signal.SIGALRM)
        self.assertIsNone(value)

    def test_input_change_during_count_rejected(self):
        process, value = self.run_count(env={"HEPTA_TOKENIZER_FIXTURE_MUTATE": str(self.prompt)})
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(value["error"], "input_changed")
        self.assertFalse(value["input_unchanged"])

    def test_concurrent_result_publication_is_create_only(self):
        process = subprocess.run(self.args(), capture_output=True, timeout=5,
            env={**os.environ, "HEPTA_TOKENIZER_FIXTURE_RACE_RESULT": str(self.result)})
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.result.read_bytes(), b"preexisting result wins")

    def test_invalid_image_rejected(self):
        self.image.write_bytes(b"not a PNG or JPEG")
        process, value = self.run_count(image=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(value["error"], "image_format_invalid")

    def test_real_vocabulary_words_cannot_enable_host_fixture_faults(self):
        self.tokenizer.write_bytes(b'{"model":{"vocab":{"abort":1,"hold":2,"null_handle":3,"negative_id":4}},"forced_count":99999}')
        process, value = self.run_count()
        self.assertEqual(process.returncode, 0)
        self.assertEqual(value["segment_token_counts"], [len(HEAD + self.system_raw + MIDDLE + self.prompt_raw + TAIL)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
