"""Regression tests for real deferred Android product inheritance macros.

Unrelated audio/version includes are empty and SDK is disabled. These local
source tests deliberately do not claim a complete Kati/Soong or image build.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).with_name("fixtures") / "android_product_inheritance"
SPEC = importlib.util.spec_from_file_location("common_base_generation_test", ROOT / "tools/generate-owner-open-common-base.py")
assert SPEC is not None and SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)
CONFIG = Path("vendor/trillionnium/config")
OVERLAY = ROOT / "android-integration/working-tree"


class ProductInheritanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="owner-open-inheritance-")
        self.root = Path(self.temp.name)
        for rel in (
            CONFIG / "common.mk", CONFIG / "common_owner_open.mk",
            CONFIG / "common_owner_open_base.mk",
            Path("vendor/trillionnium/owner-open/product.mk"),
        ):
            destination = self.root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(OVERLAY / rel, destination)
        for rel in (CONFIG / "version.mk", Path("vendor/trillionnium/audio/audio.mk")):
            destination = self.root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("# Unrelated empty fixture include.\n")
        for name in ("node_fns.mk", "inherit-product.mk"):
            shutil.copy2(FIXTURES / name, self.root / name)
        profile = json.loads((ROOT / "android-integration/owner-open-profile/profile-v2.json").read_text())
        self.forbidden = set(profile["forbidden_product_packages"]) | {"TrillionniumAiShell", "init.trillionnium-system_ext.rc"}
        common = (OVERLAY / CONFIG / "common.mk").read_text()
        runtime = common[common.index(GENERATOR.START):common.index(GENERATOR.END)]
        self.legacy = set(re.findall(r"(?m)^    ([A-Za-z0-9_.+-]+)(?: \\)?$", runtime)) | self.forbidden

    def tearDown(self) -> None:
        self.temp.cleanup()

    def evaluate(self, variant: str = "userdebug", opt_in: str | None = "true") -> dict[str, set[str]]:
        opt_in_line = "" if opt_in is None else f"TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT := {opt_in}\n"
        makefile = f"TARGET_BUILD_VARIANT := {variant}\n" + opt_in_line + """TARGET_DISABLE_TRILLIONNIUM_SDK := true
_product_var_list := PRODUCT_PACKAGES PRODUCT_PACKAGES_DEBUG PRODUCT_SYSTEM_EXT_PROPERTIES PRODUCT_PRODUCT_PROPERTIES PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG
_product_single_value_vars := PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG
include node_fns.mk
include inherit-product.mk
$(call import-nodes,PRODUCTS,vendor/trillionnium/config/common_owner_open.mk,$(_product_var_list),$(_product_single_value_vars))
$(info PACKAGES=$(PRODUCTS.vendor/trillionnium/config/common_owner_open.mk.PRODUCT_PACKAGES))
$(info DEBUG_PACKAGES=$(PRODUCTS.vendor/trillionnium/config/common_owner_open.mk.PRODUCT_PACKAGES_DEBUG))
$(info SYSTEM_EXT_PROPERTIES=$(PRODUCTS.vendor/trillionnium/config/common_owner_open.mk.PRODUCT_SYSTEM_EXT_PROPERTIES))
$(info POLICY_DIRS=$(SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS))
.PHONY: all
all:
\t@:
"""
        (self.root / "Makefile").write_text(makefile)
        result = subprocess.run(["make", "--no-print-directory", "all"], cwd=self.root, capture_output=True, text=True, timeout=15,
                                env={"PATH": os.environ["PATH"], "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(result.returncode, 0, result.stderr)
        values = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep and key in {"PACKAGES", "DEBUG_PACKAGES", "SYSTEM_EXT_PROPERTIES", "POLICY_DIRS"}:
                values[key] = set(value.split())
        self.assertEqual(set(values), {"PACKAGES", "DEBUG_PACKAGES", "SYSTEM_EXT_PROPERTIES", "POLICY_DIRS"})
        self.assertFalse(any(word.startswith("@inherit:") for words in values.values() for word in words))
        return values

    def test_old_sibling_filter_cannot_remove_deferred_common_packages(self) -> None:
        supplement = self.root / CONFIG / "common_owner_open.mk"
        supplement.write_text(supplement.read_text().replace("config/common_owner_open_base.mk", "config/common.mk"))
        values = self.evaluate()
        actual = values["PACKAGES"] | values["DEBUG_PACKAGES"]
        self.assertTrue(self.forbidden <= actual)

    def test_inheritance_macro_fixture_matches_pinned_dependency(self) -> None:
        provenance = json.loads((FIXTURES / "provenance.json").read_text())
        manifest = ET.parse(ROOT / "android-integration/manifest/manifests/trillionnium-fogos.xml")
        projects = [p for p in manifest.findall("project") if p.get("path") == "build/make"]
        self.assertEqual(len(projects), 1)
        self.assertEqual(projects[0].get("name"), provenance["repository"])
        self.assertEqual(projects[0].get("revision"), provenance["commit"])
        for binding in provenance["fixture_files"]:
            raw = (FIXTURES / binding["file"]).read_bytes()
            self.assertEqual(len(raw), binding["bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), binding["sha256"])
            self.assertIn(b"Licensed under the Apache License, Version 2.0", raw)

    def test_source_product_matrix_excludes_complete_retained_runtime(self) -> None:
        for variant in ("user", "userdebug", "eng"):
            for opt_in in (None, "false", "true", "TRUE-or-1"):
                with self.subTest(variant=variant, opt_in=opt_in):
                    values = self.evaluate(variant, opt_in)
                    actual = values["PACKAGES"] | values["DEBUG_PACKAGES"]
                    self.assertEqual(actual.intersection(self.legacy), set())
                    self.assertIn("TrillionniumOwnerOpenShell", actual)
                    self.assertIn("trillionnium-owner-open-init-rc", actual)
                    allowed = variant in {"userdebug", "eng"} and opt_in == "true"
                    self.assertEqual("adb_root" in actual, allowed)
                    self.assertEqual("vendor/trillionnium/owner-open/sepolicy/adbroot" in values["POLICY_DIRS"], allowed)
                    self.assertIn("ro.adb.secure=" + ("0" if variant == "eng" else "1"), values["SYSTEM_EXT_PROPERTIES"])

    def test_generated_base_preserves_shared_android_source_exactly(self) -> None:
        source = (OVERLAY / CONFIG / "common.mk").read_text()
        self.assertEqual(GENERATOR.render(source), (OVERLAY / CONFIG / "common_owner_open_base.mk").read_text())
        rendered = GENERATOR.render(source)
        self.assertIn("\n".join(("PRODUCT_PACKAGES += " + chr(92), "    TrillionniumSettingsProvider")), rendered)
        self.assertIn("# Backup Tool", rendered)
        self.assertNotIn("init.trillionnium-system_ext.rc", rendered)
        self.assertNotIn("TrillionniumAiAuthority", rendered)

    def test_ambiguous_or_reversed_source_boundaries_are_rejected(self) -> None:
        source = (OVERLAY / CONFIG / "common.mk").read_text()
        for invalid in (source + GENERATOR.START, source.replace(GENERATOR.END, ""), GENERATOR.END + source.replace(GENERATOR.END, ""), source + GENERATOR.LEGACY_INIT):
            with self.subTest(invalid=invalid[-100:]):
                with self.assertRaises(GENERATOR.GenerationError):
                    GENERATOR.render(invalid)

    def test_preserved_platform_init_does_not_select_legacy_services(self) -> None:
        text = (OVERLAY / "vendor/trillionnium/owner-open/init/trillionnium-owner-open.rc").read_text()
        self.assertIn("export TERMINFO /system_ext/etc/terminfo", text)
        self.assertIn("service trillionnium-bugreport /system/bin/dumpstate -d -p -z", text)
        self.assertIn("keycodes 114 115 116", text)
        self.assertNotRegex(text, r"(?m)^service trillionnium_(?:root_linux|agent_egress|direct_operation|shell_exec)")
        self.assertNotIn("sys.trillionnium.rootlinux.prepare", text)


if __name__ == "__main__":
    unittest.main()
