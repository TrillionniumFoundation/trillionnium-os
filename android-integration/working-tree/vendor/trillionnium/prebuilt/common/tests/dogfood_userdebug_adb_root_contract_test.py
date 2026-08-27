#!/usr/bin/env python3
"""Guard the explicit fogos dogfood adbd-root opt-in boundary.

This test is source-only: it does not enable anything on a live device.  The
purpose is to prevent a future refactor from turning the local test switch
into a global userdebug or user/release policy.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[5]
COMMON = ROOT / "vendor" / "trillionnium" / "config" / "common.mk"
PRODUCT = ROOT / "device" / "motorola" / "fogos" / "trillionnium_fogos.mk"


class DogfoodUserdebugAdbRootContractTest(unittest.TestCase):
    def test_common_policy_is_opt_in_and_userdebug_only(self) -> None:
        common = COMMON.read_text(encoding="utf-8")
        product = PRODUCT.read_text(encoding="utf-8")
        self.assertIn("TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT", common)
        self.assertIn(
            "ifneq ($(TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT),true)", common
        )
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


if __name__ == "__main__":
    unittest.main()
