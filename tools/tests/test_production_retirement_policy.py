#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LOADER = ROOT / "tools/production_retirement_policy.py"
POLICY_PATH = ROOT / "packaging/production-retirement-policy-v1.json"


def load_module():
    spec = importlib.util.spec_from_file_location("production_retirement_policy_test", LOADER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load retirement policy module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionRetirementPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.policy = self.module.load_policy(POLICY_PATH)
        self.temporary = tempfile.TemporaryDirectory(prefix="retirement-policy-test.")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in self.policy["android_app_source"]["roots"]:
            (self.root / relative / "src").mkdir(parents=True)
        vendor_scope = self.policy["android_vendor"]
        self.vendor_root = self.root / vendor_scope["roots"][0]
        for relative in vendor_scope["source_marker_files"]:
            target = self.vendor_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.name == "common.mk":
                target.write_text(
                    "PRODUCT_PACKAGES += \\\n    trillionnium-root-linux-run\n",
                    encoding="utf-8",
                )
            elif target.name == "Android.bp":
                target.write_text(
                    'sh_binary {\n    name: "trillionnium-root-linux-run",\n}\n',
                    encoding="utf-8",
                )
            else:
                target.write_text("active headless runtime\n", encoding="utf-8")
        for relative in vendor_scope["negative_cleanup_files"]:
            target = self.vendor_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "# Negative cleanup only; never product reachability.\n"
                "rm -f /usr/bin/trillionnium-command-center /usr/bin/trillionnium-shell\n",
                encoding="utf-8",
            )

    def scan(self):
        return self.module.android_source_violations(self.root, self.policy)

    def vendor_scan(self):
        return self.module.android_vendor_source_violations(self.root, self.policy)

    def graph_scan(self):
        return self.module.android_vendor_product_graph_violations(
            self.root, self.policy
        )

    def test_policy_loader_rejects_unknown_fields(self) -> None:
        mutated = copy.deepcopy(self.policy)
        mutated["unexpected"] = []
        path = self.root / "invalid-policy.json"
        path.write_text(json.dumps(mutated), encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.RetirementPolicyError, "top level is not closed"
        ):
            self.module.load_policy(path)

    def test_policy_loader_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        duplicate = self.root / "duplicate-policy.json"
        duplicate.write_text('{"schema":"first","schema":"second"}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.RetirementPolicyError, "duplicate policy key"
        ):
            self.module.load_policy(duplicate)

        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                nonfinite = self.root / "nonfinite-policy.json"
                nonfinite.write_text(
                    f'{{"schema":{constant}}}\n', encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    self.module.RetirementPolicyError, "non-finite policy number"
                ):
                    self.module.load_policy(nonfinite)

    def test_scanner_requires_both_configured_app_roots(self) -> None:
        missing = self.root / self.policy["android_app_source"]["roots"][1]
        (missing / "src").rmdir()
        missing.rmdir()
        self.assertTrue(
            any("required scoped app root is absent" in item for item in self.scan())
        )

    def test_unrelated_system_messenger_and_plain_message_are_allowed(self) -> None:
        framework = self.root / "frameworks/base/core/java/android/os/Messenger.java"
        framework.parent.mkdir(parents=True)
        framework.write_text("import android.os.Messenger;\n", encoding="utf-8")
        scoped = (
            self.root
            / self.policy["android_app_source"]["roots"][0]
            / "src/HandlerOnly.java"
        )
        scoped.write_text("Message.obtain(handler, 1);\n", encoding="utf-8")
        self.assertEqual(self.scan(), [])

    def test_every_scoped_identifier_is_rejected(self) -> None:
        target = (
            self.root
            / self.policy["android_app_source"]["roots"][0]
            / "src/Legacy.java"
        )
        for field in (
            "class_identifiers",
            "manifest_identifiers",
            "module_identifiers",
            "protocol_identifiers",
            "messenger_constructs",
        ):
            for identifier in self.policy["android_app_source"][field]:
                with self.subTest(field=field, identifier=identifier):
                    target.write_text(identifier, encoding="utf-8")
                    self.assertTrue(self.scan())
        target.unlink()

    def test_every_retired_android_source_path_is_rejected(self) -> None:
        app_root = self.root / self.policy["android_app_source"]["roots"][0]
        for relative in self.policy["android_app_source"]["relative_paths"]:
            with self.subTest(relative=relative):
                target = app_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"fixture")
                self.assertTrue(self.scan())
                target.unlink()

    def test_model_artifact_predicate_covers_every_closed_extension_and_native_name(self) -> None:
        artifacts = self.policy["model_artifacts"]
        for extension in artifacts["weight_extensions"]:
            self.assertEqual(
                self.module.retired_model_artifact_reason(
                    f"models/candidate{extension}", self.policy
                ),
                "model weight extension",
            )
        for basename in artifacts["native_module_basenames"]:
            self.assertEqual(
                self.module.retired_model_artifact_reason(
                    f"usr/lib/{basename}", self.policy
                ),
                "retired local-model native module",
            )

    def test_negative_cleanup_file_is_required_but_not_a_reachable_marker_scope(self) -> None:
        self.assertEqual(self.vendor_scan(), [])
        cleanup = self.vendor_root / self.policy["android_vendor"][
            "negative_cleanup_files"
        ][0]
        cleanup.unlink()
        self.assertTrue(
            any("required regular file is absent" in item for item in self.vendor_scan())
        )

    def test_every_retired_vendor_source_path_and_marker_is_rejected(self) -> None:
        vendor = self.policy["android_vendor"]
        for relative in vendor["retired_source_paths"]:
            with self.subTest(relative=relative):
                target = self.vendor_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("retired\n", encoding="utf-8")
                self.assertTrue(self.vendor_scan())
                target.unlink()

        marker_file = self.vendor_root / vendor["source_marker_files"][-1]
        original = marker_file.read_bytes()
        try:
            for marker in vendor["retired_content_markers"]:
                with self.subTest(marker=marker):
                    marker_file.write_text(marker, encoding="utf-8")
                    self.assertTrue(
                        any("retired vendor marker" in item for item in self.vendor_scan())
                    )
        finally:
            marker_file.write_bytes(original)

    def test_every_retired_module_is_rejected_from_make_and_soong_graphs(self) -> None:
        vendor = self.policy["android_vendor"]
        make = self.vendor_root / "config/common.mk"
        blueprint = self.vendor_root / "prebuilt/common/Android.bp"
        original_make = make.read_text(encoding="utf-8")
        original_blueprint = blueprint.read_text(encoding="utf-8")
        try:
            for module in vendor["retired_modules"]:
                with self.subTest(graph="make", module=module):
                    make.write_text(
                        f"PRODUCT_PACKAGES_DEBUG += \\\n    {module}\n",
                        encoding="utf-8",
                    )
                    self.assertTrue(
                        any(module in item for item in self.graph_scan())
                    )
                    make.write_text(original_make, encoding="utf-8")
                with self.subTest(graph="soong", module=module):
                    blueprint.write_text(
                        f'sh_binary {{\n    name: "{module}",\n}}\n',
                        encoding="utf-8",
                    )
                    self.assertTrue(
                        any(module in item for item in self.graph_scan())
                    )
                    blueprint.write_text(original_blueprint, encoding="utf-8")
        finally:
            make.write_text(original_make, encoding="utf-8")
            blueprint.write_text(original_blueprint, encoding="utf-8")

    def test_fresh_staged_root_rejects_every_retired_path_and_broken_symlink(self) -> None:
        stage = self.root / "fresh-stage"
        stage.mkdir()
        self.assertEqual(self.module.staged_root_violations(stage, self.policy), [])
        for relative in self.policy["android_vendor"]["retired_partition_paths"]:
            with self.subTest(relative=relative):
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"retired")
                self.assertTrue(
                    self.module.staged_root_violations(stage, self.policy)
                )
                target.unlink()
        broken = stage / self.policy["android_vendor"]["retired_partition_paths"][0]
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.symlink_to("/definitely/missing/retired")
        self.assertTrue(self.module.staged_root_violations(stage, self.policy))
        broken.unlink()
        canonical = PurePosixPath(
            self.policy["android_vendor"]["retired_partition_paths"][0]
        )
        lower = stage / PurePosixPath(
            canonical.parts[0].casefold(), *canonical.parts[1:]
        )
        lower.parent.mkdir(parents=True, exist_ok=True)
        lower.write_bytes(b"retired lower-case product root")
        self.assertTrue(self.module.staged_root_violations(stage, self.policy))


if __name__ == "__main__":
    unittest.main()
