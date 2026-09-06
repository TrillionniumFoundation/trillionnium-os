#!/usr/bin/env python3
"""Guard the explicit fogos dogfood adbd-root opt-in boundary.

This test is source-only: it does not enable anything on a live device.  The
purpose is to prevent a future refactor from turning the local test switch
into a global userdebug or user/release policy.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[5]
COMMON = ROOT / "vendor" / "trillionnium" / "config" / "common.mk"
PRODUCT = ROOT / "device" / "motorola" / "fogos" / "trillionnium_fogos.mk"
OWNER_OPEN_PRODUCT = ROOT / "vendor" / "trillionnium" / "owner-open" / "product.mk"
ADBROOT_POLICY = OWNER_OPEN_PRODUCT.parent / "sepolicy" / "adbroot"


class DogfoodUserdebugAdbRootContractTest(unittest.TestCase):
    def test_common_policy_is_opt_in_and_userdebug_only(self) -> None:
        common = COMMON.read_text(encoding="utf-8")
        # The audit snapshot intentionally carries only the dirty Android
        # overlay, so the device-product file may be absent there.  A full
        # Android checkout must still prove the fogos opt-in at this path.
        product = PRODUCT.read_text(encoding="utf-8") if PRODUCT.is_file() else ""
        self.assertIn("TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT", common)
        self.assertIn(
            "ifneq ($(TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT),true)", common
        )
        if product:
            self.assertIn("TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT := true", product)
        self.assertIn("TARGET_BUILD_VARIANT", common)
        self.assertNotIn("PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG := false", common)

    def test_release_build_does_not_get_an_adb_root_override(self) -> None:
        common = COMMON.read_text(encoding="utf-8")
        # The override is consumed only by build/make's userdebug policy; this
        # source contract must not turn on WITH_SU or alter user properties.
        policy = common.split("TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT", 1)[1]
        policy = policy.split("endif", 1)[0]
        self.assertNotIn("WITH_SU", policy)
        self.assertNotIn("PRODUCT_PRODUCT_PROPERTIES += ro.debuggable=1", policy)

    def test_owner_open_adb_root_is_explicit_dogfood_only(self) -> None:
        product = OWNER_OPEN_PRODUCT.read_text(encoding="utf-8")
        guard = "ifeq ($(TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT),true)"
        variant_guard = "ifneq ($(filter userdebug eng,$(TARGET_BUILD_VARIANT)),)"
        self.assertIn(guard, product)
        self.assertIn(variant_guard, product)
        start = product.index(guard)
        end = product.index("\nendif\nendif", start)
        guarded = product[start:end]
        self.assertRegex(guarded, r"(?m)^PRODUCT_PACKAGES \+= \\\n\s+adb_root$")
        self.assertRegex(
            guarded,
            r"(?m)^SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS \+= \\\n\s+vendor/trillionnium/owner-open/sepolicy/adbroot$",
        )
        # There is exactly one active package entry, and it is inside both
        # guards; comments mentioning the command do not count as wiring.
        self.assertEqual(len(re.findall(r"(?m)^\s+adb_root\s*$", product)), 1)
        self.assertNotIn("PRODUCT_PACKAGES_DEBUG", guarded)

    def test_owner_open_adb_root_selinux_contract_is_complete(self) -> None:
        expected = {
            "adbroot.te": (
                "type adbroot, domain, coredomain;",
                "add_service(adbroot, adbroot_service)",
                "set_prop(adbroot, ctl_adbd_prop)",
            ),
            "adbd.te": (
                "allow adbd adbroot:binder call;",
                "allow adbd adbroot_service:service_manager find;",
            ),
            "file.te": (
                "type adbroot_data_file, file_type, data_file_type, core_data_file_type;",
            ),
            "file_contexts": (
                "/(system_ext|system/system_ext)/bin/adb_root",
                "/data/adbroot(/.*)?",
            ),
            "service.te": ("type adbroot_service, service_manager_type;",),
            "service_contexts": (
                "adbroot_service                           u:object_r:adbroot_service:s0",
            ),
            "system_server.te": (
                "allow system_server adbroot_service:service_manager find;",
            ),
        }
        self.assertEqual(set(path.name for path in ADBROOT_POLICY.iterdir()), set(expected))
        for name, snippets in expected.items():
            text = (ADBROOT_POLICY / name).read_text(encoding="utf-8")
            for snippet in snippets:
                self.assertIn(snippet, text)


if __name__ == "__main__":
    unittest.main()
