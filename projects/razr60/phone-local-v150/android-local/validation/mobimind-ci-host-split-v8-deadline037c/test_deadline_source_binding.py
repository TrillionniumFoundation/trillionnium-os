"""Exact-source admission regressions; never build, download, or contact a phone.

The real candidate tree is checked, including its complete membership. Synthetic
rebuild reports below exercise rejection contracts only, not runtime qualification.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
VALIDATION = HERE.parent
REPOSITORY = HERE.parents[5]
APP = Path(os.environ.get("HEPTA_CI_BINDING_APP_SOURCE", HERE.parents[1] / "lfm3-controller")).resolve()
REBUILD = VALIDATION / "mobimind-runtime-rebuild-v8-deadline037c"
OLD_REBUILD = VALIDATION / "mobimind-runtime-rebuild-v7"
OLD_SPLIT = VALIDATION / "mobimind-ci-host-split-v7"
OLD_APP_SHA = "9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69"
APP_SHA = "fdab3c67d726aa44c19c9efe4d65cc845ee433dbabe2d97f7fe7fb07b92bcec7"
OLD_HELPER_SHA = "b585c1654ce91888bc4906b32fbe8ac1ace22987f445d1af25994d084f19dc78"
FROZEN = {
    "mobimind-runtime-rebuild-v7/README.md": "99343b1745f6802723c11844d5a5da4025196da7e979481cb9fe5e8841aec972",
    "mobimind-runtime-rebuild-v7/SOURCE-MANIFEST.json": "5411a0d941e5e9ee83fd2fc0527bfcb1cb906b6ae46d802aedc1b609c20f58a1",
    "mobimind-runtime-rebuild-v7/rebuild_exact_runtime.py": OLD_HELPER_SHA,
    "mobimind-ci-host-split-v7/README.md": "3f465c12bff6011622a1b9a98492cc95b52517efe4e9a06f8ca3bd09a2fd2772",
    "mobimind-ci-host-split-v7/SOURCE-MANIFEST.json": "db9ee99f9ac616a09e11ef259207a921f9b614a4b3cda703bef65400cc43ffeb",
    "mobimind-ci-host-split-v7/qualify_macos_compiler.py": "4a20e508438286517659b51ed27829d64dfdf6ee8d22967d6d970ad0a602ae5f",
    "mobimind-ci-host-split-v7/verify_ci_runtime_bundle.py": "29799c12fe3bc4f73a7aff9803ec010788a7fcf30b6a8bd83b38a5fe7df6dae6",
}
WORKFLOW_SHA = "015bff2c95340735d74b617f927f72b25f8a13a996321e508f2cd34f73e6f7a0"
WORKFLOW_STEP = (
    "      - name: Verify exact deadline candidate CI helper contracts\n"
    "        working-directory: projects/razr60/phone-local-v150/android-local/validation/mobimind-ci-host-split-v8-deadline037c\n"
    "        run: python -B -m unittest -v test_deadline_source_binding.py\n"
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class DeadlineSourceBindingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load(REBUILD / "rebuild_exact_runtime.py", "deadline037c_rebuild")
        cls.old_helper = load(OLD_REBUILD / "rebuild_exact_runtime.py", "frozen_v7_rebuild")
        cls.consumer = load(HERE / "verify_ci_runtime_bundle.py", "deadline037c_consumer")

    def copy_app(self, directory):
        return Path(shutil.copytree(APP, Path(directory) / "app",
                                   ignore=shutil.ignore_patterns("out", ".git", "keys", "__pycache__")))

    def test_candidate_complete_source_is_admitted(self):
        self.assertEqual(sha(APP / "SOURCE-MANIFEST.json"), APP_SHA)
        self.assertEqual(self.helper.verify_frozen_source(APP), APP)

    def test_frozen_v7_reproduces_original_ci_refusal(self):
        with self.assertRaisesRegex(ValueError, "only the unmodified frozen Code19 r1"):
            self.old_helper.verify_frozen_source(APP)

    def test_even_semantically_equal_unpinned_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SOURCE-MANIFEST.json").write_bytes((APP / "SOURCE-MANIFEST.json").read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "only the exact Code19 deadline037c"):
                self.helper.verify_frozen_source(root)

    def test_modified_native_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_app(directory)
            path = root / "native/mobimind-runtime-pins.json"
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "frozen source changed: native/mobimind-runtime-pins.json"):
                self.helper.verify_frozen_source(root)

    def test_unlisted_source_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_app(directory)
            (root / "unlisted-source.py").write_text("# not admitted\n")
            with self.assertRaisesRegex(ValueError, "unlisted or missing frozen source member"):
                self.helper.verify_frozen_source(root)

    def test_missing_source_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_app(directory)
            (root / "native/mobimind-runtime-pins.json").unlink()
            with self.assertRaisesRegex(ValueError, "frozen source changed: native/mobimind-runtime-pins.json"):
                self.helper.verify_frozen_source(root)

    def test_symlinked_member_with_identical_bytes_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_app(directory)
            path = root / "native/mobimind-runtime-pins.json"
            outside = Path(directory) / "same-bytes.json"
            outside.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "frozen source changed: native/mobimind-runtime-pins.json"):
                self.helper.verify_frozen_source(root)

    def test_all_frozen_v7_files_remain_exact(self):
        for relative, expected in FROZEN.items():
            with self.subTest(path=relative):
                self.assertEqual(sha(VALIDATION / relative), expected)

    def test_rebuild_diff_is_only_exact_source_admission_and_labels(self):
        text = (REBUILD / "rebuild_exact_runtime.py").read_text()
        replacements = (
            (APP_SHA, OLD_APP_SHA),
            ("only the exact Code19 deadline037c candidate source is admitted",
             "only the unmodified frozen Code19 r1 source is admitted"),
            ("r8-code19-deadline037c-source", "r7-code19-source"),
        )
        for current, original in replacements:
            self.assertEqual(text.count(current), 1)
            text = text.replace(current, original)
        self.assertEqual(text.encode(), (OLD_REBUILD / "rebuild_exact_runtime.py").read_bytes())

    def test_consumer_diff_is_only_source_and_helper_identity(self):
        text = (HERE / "verify_ci_runtime_bundle.py").read_text()
        for current, original in ((APP_SHA, OLD_APP_SHA),
                                  (sha(REBUILD / "rebuild_exact_runtime.py"), OLD_HELPER_SHA)):
            self.assertEqual(text.count(current), 1)
            text = text.replace(current, original)
        self.assertEqual(text.encode(), (OLD_SPLIT / "verify_ci_runtime_bundle.py").read_bytes())

    def test_compiler_qualifier_remains_byte_identical(self):
        self.assertEqual((HERE / "qualify_macos_compiler.py").read_bytes(),
                         (OLD_SPLIT / "qualify_macos_compiler.py").read_bytes())

    def test_helper_manifests_close_every_new_file(self):
        for root, schema in ((REBUILD, "hepta.mnn-fixed-source-rebuild-helper.v8"),
                             (HERE, "hepta.mnn-ci-host-split-source.v8")):
            with self.subTest(root=root.name):
                manifest = json.loads((root / "SOURCE-MANIFEST.json").read_bytes())
                self.assertEqual(manifest["schema"], schema)
                self.assertEqual(manifest["app_source_manifest_sha256"], APP_SHA)
                for flag in ("app_source_modified", "compiler_identity_overridden", "runtime_pins_modified"):
                    self.assertIs(manifest[flag], False)
                actual = {str(p.relative_to(root)) for p in root.rglob("*")
                          if p.is_file() and p.name != "SOURCE-MANIFEST.json"
                          and "__pycache__" not in p.parts}
                self.assertEqual(set(manifest["files"]), actual)
                for name, record in manifest["files"].items():
                    self.assertEqual((root / name).stat().st_size, record["bytes"])
                    self.assertEqual(sha(root / name), record["sha256"])

    def test_producer_and_consumer_pins_close(self):
        self.assertEqual(self.helper.APP_MANIFEST_SHA, APP_SHA)
        self.assertEqual(self.consumer.APP_SHA, APP_SHA)
        self.assertEqual(self.consumer.HELPER_SHA, sha(REBUILD / "rebuild_exact_runtime.py"))

    def test_workflow_only_retargets_helpers_and_adds_prebuild_contracts(self):
        text = (REPOSITORY / ".github/workflows/hepta-local-android.yml").read_text()
        self.assertEqual(text.count(WORKFLOW_STEP), 1)
        self.assertLess(text.index(WORKFLOW_STEP), text.index("      - name: Install and identify"))
        self.assertEqual(text.count("mobimind-runtime-rebuild-v8-deadline037c/"), 3)
        self.assertEqual(text.count("mobimind-ci-host-split-v8-deadline037c/"), 3)
        self.assertNotIn("mobimind-runtime-rebuild-v7/", text)
        self.assertNotIn("mobimind-ci-host-split-v7/", text)
        text = text.replace(WORKFLOW_STEP, "")
        for name in ("mobimind-ci-host-split", "mobimind-runtime-rebuild"):
            text = text.replace(name + "-v8-deadline037c/", name + "-v7/")
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), WORKFLOW_SHA)

    def report_fixture(self):
        # This fixture is not a build receipt and is never written to a bundle.
        return {
            "source_build_completed": True, "original_runtime_byte_identity": True,
            "original_assembler_allowed": True, "mnn_library_rebuilt": True,
            "worker_rebuilt": True, "original_receipt_copied_unchanged": True,
            "phone_contacted": False, "pins_modified": False,
            "elf_rewritten": False, "app_source_modified": False,
            "state": "exact_original_runtime_rebuilt", "process_exit_code": 0,
            "app_manifest_sha256": APP_SHA, "helper_sha256": self.consumer.HELPER_SHA,
            "ndk_revision_observed": "28.1.13356709",
            "toolchain": {"host_tag": "darwin-x86_64",
                          "clang_sha256": "9f980ecd6dd9e20641589dfd653b2cccbc3f09808f0809387e9673747285a3b3"},
        }

    def test_report_field_contract_accepts_exact_candidate_pair(self):
        self.consumer.check_report(self.report_fixture())

    def test_report_field_contract_rejects_old_and_unknown_source_or_helper(self):
        for key, bad in (("app_manifest_sha256", OLD_APP_SHA), ("app_manifest_sha256", "0" * 64),
                         ("helper_sha256", OLD_HELPER_SHA), ("helper_sha256", "0" * 64)):
            with self.subTest(key=key, bad=bad):
                report = self.report_fixture()
                report[key] = bad
                with self.assertRaisesRegex(ValueError, "rebuild source/helper differs"):
                    self.consumer.check_report(report)

    def test_native_completion_and_mutation_report_guards_remain_strict(self):
        for key in ("source_build_completed", "original_runtime_byte_identity", "original_assembler_allowed",
                    "mnn_library_rebuilt", "worker_rebuilt", "original_receipt_copied_unchanged",
                    "phone_contacted", "pins_modified", "elf_rewritten", "app_source_modified"):
            for invalid in (None, 1):
                with self.subTest(key=key, invalid=invalid):
                    report = self.report_fixture()
                    report[key] = invalid
                    with self.assertRaises(ValueError):
                        self.consumer.check_report(report)

    def test_compiler_revision_container_and_host_report_guards_remain_strict(self):
        for modification in ({"ndk_revision_observed": "28.2.13676358"},
                             {"toolchain": {"host_tag": "linux-x86_64"}},
                             {"toolchain": {"host_tag": "darwin-x86_64", "clang_sha256": "0" * 64}},
                             {"process_exit_code": False}):
            with self.subTest(modification=modification):
                report = self.report_fixture()
                report.update(copy.deepcopy(modification))
                with self.assertRaises(ValueError):
                    self.consumer.check_report(report)

    def run_consumer(self, operation, helper, app):
        return subprocess.run(
            [sys.executable, "-B", str(HERE / "verify_ci_runtime_bundle.py"), operation,
             "--app-source", str(app), "--rebuild-helper", str(helper),
             "--bundle", str(HERE / "no-fixture-runtime-bundle"),
             "--source-head", "a08f23614f48581f4bb23238e0c5bf2430b7d411",
             "--run-id", "42582322495", "--run-attempt", "1"],
            capture_output=True, text=True, timeout=30, check=False)

    def test_both_transport_modes_reject_old_helper_before_runtime_access(self):
        for operation in ("bind", "verify"):
            with self.subTest(operation=operation):
                result = self.run_consumer(operation, OLD_REBUILD / "rebuild_exact_runtime.py", APP)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("pinned rebuild helper changed", result.stdout)
                self.assertIs(json.loads(result.stdout)["original_assembler_allowed"], False)

    def test_both_transport_modes_reject_tampered_helper_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / "helper.py"
            helper.write_bytes((REBUILD / "rebuild_exact_runtime.py").read_bytes() + b"\n")
            for operation in ("bind", "verify"):
                with self.subTest(operation=operation):
                    result = self.run_consumer(operation, helper, APP)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("pinned rebuild helper changed", result.stdout)

    def test_both_transport_modes_reject_unknown_source_before_runtime_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SOURCE-MANIFEST.json").write_text("{}\n")
            for operation in ("bind", "verify"):
                with self.subTest(operation=operation):
                    result = self.run_consumer(operation, REBUILD / "rebuild_exact_runtime.py", root)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("only the exact Code19 deadline037c candidate", result.stdout)

    def test_complete_runtime_hash_gate_still_rejects_nonmatching_bytes(self):
        pins = json.loads((APP / "native/mobimind-runtime-pins.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for member in pins["libraries"]:
                (root / member["source_name"]).write_bytes(b"not the pinned runtime\n")
            rows, accepted, _ = self.helper.compare_payloads(root, pins)
            self.assertEqual(len(rows), 3)
            self.assertIs(accepted, False)
            self.assertTrue(all(row["exact_original_bytes"] is False for row in rows))


if __name__ == "__main__":
    unittest.main()
