"""Host rejection tests for the separate MNN packaging provenance.

Tiny payload fixtures test rejection mechanics only. They do not qualify a
runtime; the actual three Android binaries are verified during real assembly.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import verify_mobimind_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]


class MobiMindLinkerPolicyTests(unittest.TestCase):
    # Parser/rejection fixtures only. Assembly supplies the actual pinned ELF's
    # readelf output; these lines do not substitute for Android ELF evidence.
    DYNAMIC = """
  0x000000000000001d (RUNPATH) Library runpath: [$ORIGIN]
  0x0000000000000001 (NEEDED) Shared library: [libMNN.so]
  0x0000000000000001 (NEEDED) Shared library: [libc++_shared.so]
  0x0000000000000001 (NEEDED) Shared library: [libandroid.so]
"""

    def test_origin_direct_dependency_policy(self):
        result = runtime.verify_worker_linker_policy(self.DYNAMIC)
        self.assertEqual(result["worker_runpath"], "$ORIGIN")
        self.assertFalse(result["global_ld_library_path_required"])
        self.assertFalse(result["runtime_resolution_proven"])

    def test_global_transitive_ambiguous_and_missing_paths_are_rejected(self):
        invalid = [self.DYNAMIC.replace("$ORIGIN", "$ORIGIN:/vendor/lib64"),
                   self.DYNAMIC.replace("(RUNPATH)", "(RPATH)"),
                   self.DYNAMIC + "(RUNPATH) [$ORIGIN]\n",
                   self.DYNAMIC + "(RPATH) [$ORIGIN]\n",
                   self.DYNAMIC + "(RUNPATH) malformed\n",
                   self.DYNAMIC.replace("(RUNPATH)", "(OTHER)")]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                runtime.verify_worker_linker_policy(value)

    def test_each_private_library_must_be_a_unique_direct_dependency(self):
        for name in ("libMNN.so", "libc++_shared.so"):
            for value in (self.DYNAMIC.replace(name, "unrelated.so"),
                          self.DYNAMIC + "(NEEDED) [" + name + "]\n"):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    runtime.verify_worker_linker_policy(value)


class MobiMindPackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self):
        path = self.root / "fixture.so"
        data = b"explicit host-only payload fixture"
        path.write_bytes(data)
        return path, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def test_exact_source_java_and_packaging_pins_agree(self):
        pins = runtime.load_pins(ROOT)
        self.assertFalse(pins["geniex_release_members"])
        self.assertEqual(len(pins["libraries"]), 3)

    def test_payload_bytes_are_verified(self):
        path, pin = self.fixture()
        self.assertEqual(runtime._verify_payload(path, pin), path.read_bytes())
        path.write_bytes(b"changed payload of the same length"[:pin["bytes"]])
        with self.assertRaises(RuntimeError):
            runtime._verify_payload(path, pin)

    def test_truncation_and_extension_are_rejected(self):
        path, pin = self.fixture()
        data = path.read_bytes()
        for changed in (data[:-1], data + b"x"):
            path.write_bytes(changed)
            with self.assertRaises(RuntimeError):
                runtime._verify_payload(path, pin)

    def test_symlink_and_hardlink_are_rejected(self):
        path, pin = self.fixture()
        link = self.root / "link.so"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            runtime._verify_payload(link, pin)
        link.unlink()
        os.link(path, link)
        with self.assertRaises(RuntimeError):
            runtime._verify_payload(path, pin)

    def test_mismatched_java_pin_rejected(self):
        java_relative = "src/org/trillionnium/hepta/local/MobiMindPins.java"
        for relative in ("native/mobimind-runtime-pins.json", java_relative):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        java = self.root / java_relative
        java.write_text(java.read_text().replace("2186768L", "2186769L"))
        with self.assertRaisesRegex(RuntimeError, "sizes differ"):
            runtime.load_pins(self.root)

    def test_unrelated_prior_build_receipt_is_rejected_before_elf_reads(self):
        (self.root / "BUILD-RECEIPT.json").write_text("{}\n")
        with self.assertRaisesRegex(RuntimeError, "receipt pin differs"):
            runtime.verify_mobimind_runtime(ROOT, self.root)

    def test_preserved_source_manifest_and_build_receipt_identity(self):
        pins = runtime.load_pins(ROOT)
        receipt = ROOT / "provenance/mobimind-worker-r4-build.json"
        self.assertEqual(hashlib.sha256(receipt.read_bytes()).hexdigest(), pins["build_receipt_sha256"])
        manifest = ROOT / "provenance/mobimind-worker-r4/SOURCE-MANIFEST.json"
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), pins["worker_source_manifest_sha256"])
        original = json.loads(receipt.read_text())
        self.assertEqual(original["probe_archive_sha256"], pins["worker_source_archive_sha256"])
        self.assertFalse(original["http_resource_support"])


if __name__ == "__main__":
    unittest.main()
