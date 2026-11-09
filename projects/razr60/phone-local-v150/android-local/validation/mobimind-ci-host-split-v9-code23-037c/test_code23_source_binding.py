"""Public Code23 exact-source admission regressions; never build, download, or contact a phone.

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
REBUILD = VALIDATION / "mobimind-runtime-rebuild-v9-code23-037c"
OLD_REBUILD = VALIDATION / "mobimind-runtime-rebuild-v8"
OLD_SPLIT = VALIDATION / "mobimind-ci-host-split-v8"
OLD_APP_SHA = "f4af9855da4e62a2eeaa1cc8d734082c6c31d17f95d001b58b412dbd7604978a"
APP_SHA = "5559ef2ad8e9b7e8d886dfc9f3bf6b4cce2fde7170a7cb40ba0b6ce1061a8b4f"
OLD_HELPER_SHA = "cf3a6d9251fc37a68a8dc80016def8ea1456b045172ca5480dabc754e057d8b8"
FROZEN = {'mobimind-ci-host-split-v8/qualify_macos_compiler.py': '4a20e508438286517659b51ed27829d64dfdf6ee8d22967d6d970ad0a602ae5f', 'mobimind-ci-host-split-v8/verify_ci_runtime_bundle.py': '840b81cf3796ed85481468a442aec76a05ba3ada5e88234dc8c3ad49f497a040', 'mobimind-runtime-rebuild-v8/rebuild_exact_runtime.py': 'cf3a6d9251fc37a68a8dc80016def8ea1456b045172ca5480dabc754e057d8b8', 'ui-venus-runtime-rebuild-v1/README.md': 'fc85c7edc378f5ce129204afbc24ffb177131b7f70d6ded4993dc6175db31477', 'ui-venus-runtime-rebuild-v1/rebuild_and_verify.py': '88004d863c30d7f45dbede09794cd1c788de33eab0d6118b5f15488e40eb82de', 'ui-venus-runtime-rebuild-v1/test_rebuild_and_verify.py': 'd1237cf4ea33038b9a42eacadb5dcebc6c83873077677c416facb93fd5cd87a0'}
WORKFLOW_SHA = '52d3cae5096132dd23d1501d10d9dd97efd8a8e5beaad36ff91a97a8fe0c4083'
WORKFLOW_STEP = '      - name: Verify exact public Code23 CI source and helper binding contracts\n        working-directory: projects/razr60/phone-local-v150/android-local/validation/mobimind-ci-host-split-v9-code23-037c\n        run: python -B -m unittest -v test_code23_source_binding.py\n'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Code23SourceBindingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load(REBUILD / "rebuild_exact_runtime.py", "code23_rebuild")
        cls.old_helper = load(OLD_REBUILD / "rebuild_exact_runtime.py", "frozen_v8_rebuild")
        cls.consumer = load(HERE / "verify_ci_runtime_bundle.py", "code23_consumer")

    def copy_app(self, directory):
        return Path(shutil.copytree(APP, Path(directory) / "app",
                                   ignore=shutil.ignore_patterns("out", ".git", "keys", "__pycache__")))

    def test_candidate_complete_source_is_admitted(self):
        self.assertEqual(sha(APP / "SOURCE-MANIFEST.json"), APP_SHA)
        self.assertEqual(self.helper.verify_frozen_source(APP), APP)

    def test_frozen_v8_rejects_this_new_source(self):
        with self.assertRaisesRegex(ValueError, "only the unmodified frozen Code19 r1"):
            self.old_helper.verify_frozen_source(APP)

    def test_even_semantically_equal_unpinned_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SOURCE-MANIFEST.json").write_bytes((APP / "SOURCE-MANIFEST.json").read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "only the exact public Code23 037c"):
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

    def test_all_frozen_v8_and_ui_v1_files_remain_exact(self):
        for relative, expected in FROZEN.items():
            with self.subTest(path=relative):
                self.assertEqual(sha(VALIDATION / relative), expected)

    def test_rebuild_diff_is_only_exact_source_admission_and_labels(self):
        text = (REBUILD / "rebuild_exact_runtime.py").read_text()
        replacements = (
            (APP_SHA, OLD_APP_SHA),
            ("only the exact public Code23 037c source is admitted",
             "only the unmodified frozen Code19 r1 source is admitted"),
            ("r9-code23-037c-public-source", "r7-code19-source"),
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
        for root, schema in ((REBUILD, "hepta.mnn-fixed-source-rebuild-helper.v9-code23-037c"),
                             (HERE, "hepta.mnn-ci-host-split-source.v9-code23-037c"),
                             (VALIDATION / "ui-venus-runtime-rebuild-v2-code23-037c", "hepta.ui-venus-runtime-source.v2-code23-037c")):
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
        text = text.replace(WORKFLOW_STEP, "")
        for current, original in (
                ("mobimind-runtime-rebuild-v9-code23-037c", "mobimind-runtime-rebuild-v8"),
                ("mobimind-ci-host-split-v9-code23-037c", "mobimind-ci-host-split-v8"),
                ("ui-venus-runtime-rebuild-v2-code23-037c", "ui-venus-runtime-rebuild-v1")):
            self.assertIn(current, text)
            self.assertNotIn(original + "/", text)
            text = text.replace(current, original)
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
             "--source-head", "a" * 40,
             "--run-id", "19", "--run-attempt", "1"],
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
                    self.assertIn("only the exact public Code23 037c source", result.stdout)

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


    def test_ui_candidate_closure_is_admitted_and_old_helper_rejects(self):
        current = load(VALIDATION / "ui-venus-runtime-rebuild-v2-code23-037c/rebuild_and_verify.py", "ui_code23_binding")
        prior = load(VALIDATION / "ui-venus-runtime-rebuild-v1/rebuild_and_verify.py", "ui_frozen_v1_binding")
        self.assertEqual(current.frozen_app(APP)[0], APP)
        with self.assertRaisesRegex(ValueError, "complete App source identity differs"):
            prior.frozen_app(APP)

    def test_ui_rebuild_and_transport_diff_is_only_exact_app_identity(self):
        current = (VALIDATION / "ui-venus-runtime-rebuild-v2-code23-037c/rebuild_and_verify.py").read_text()
        self.assertEqual(current.count(APP_SHA), 1)
        self.assertEqual(current.replace(APP_SHA, OLD_APP_SHA).encode(),
                         (VALIDATION / "ui-venus-runtime-rebuild-v1/rebuild_and_verify.py").read_bytes())
        self.assertEqual((VALIDATION / "ui-venus-runtime-rebuild-v2-code23-037c/test_rebuild_and_verify.py").read_bytes(),
                         (VALIDATION / "ui-venus-runtime-rebuild-v1/test_rebuild_and_verify.py").read_bytes())

    def test_ui_unknown_source_rejected_before_runtime_or_compiler_access(self):
        current = load(VALIDATION / "ui-venus-runtime-rebuild-v2-code23-037c/rebuild_and_verify.py", "ui_code23_unknown")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SOURCE-MANIFEST.json").write_bytes((APP / "SOURCE-MANIFEST.json").read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "complete App source identity differs"):
                current.frozen_app(root)


if __name__ == "__main__":
    unittest.main()
