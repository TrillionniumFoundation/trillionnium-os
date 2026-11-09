"""Fail-closed static contract tests for OEM BTFM codec dependency restoration."""
from pathlib import Path
import re
import unittest
ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open"
class SunBtfmContract(unittest.TestCase):
    def setUp(self):
        self.init=(BASE/"init/trillionnium-sun-btfm-modprobe.rc").read_text()
        self.bp=(BASE/"Android.bp").read_text()
        self.product=(BASE/"product.mk").read_text()
    def test_exact_guard_sun_android17_only(self):
        self.assertIn("on property:ro.boot.product.vendor.sku=sun && property:ro.build.version.sdk=37",self.init)
        self.assertEqual(self.init.count("on property:"),1)
        self.assertNotIn("sys.boot_completed",self.init)
    def test_missing_oem_dai_backends_loaded_in_serial_order(self):
        lines=[s.strip() for s in self.init.splitlines() if s.strip() and not s.lstrip().startswith("#")]
        self.assertEqual(len(lines),2)
        self.assertEqual(lines[1],"exec u:r:vendor_modprobe:s0 -- /vendor/bin/modprobe -b -s -d /vendor_dlkm/lib/modules -a btfmcodec btfm_slim_codec bt_fm_swr")
        self.assertTrue(lines[0].startswith("on property:"))
    def test_no_ready_forgery_or_security_bypass(self):
        for banned in ["setprop","ready=1","Watchdog","chmod","chown","setenforce","SELINUX=permissive","insmod ","rmmod","modprobe -r","reboot","stop ","restart","/data/"]:
            self.assertNotIn(banned,self.init)
    def test_soc_qualified_module_wired_into_real_product(self):
        block=re.search(r'prebuilt_etc \{\s*name: "trillionnium-sun-btfm-modprobe-init-rc",.+?\}',self.bp,re.S)
        self.assertIsNotNone(block)
        self.assertIn('src: "init/trillionnium-sun-btfm-modprobe.rc"',block.group())
        self.assertIn('filename: "trillionnium-sun-btfm-modprobe.rc"',block.group())
        self.assertIn('sub_dir: "init"',block.group())
        self.assertIn('system_ext_specific: true',block.group())
        self.assertIn("trillionnium-sun-btfm-modprobe-init-rc",self.product)
    def test_original_rootlinux_owner_init_unchanged_by_fix(self):
        original=(BASE/"init/trillionnium-owner-open.rc").read_text()
        self.assertIn("trillionnium.owner_open.ready 0",original)
        self.assertIn("trillionnium_owner_open_bootstrap",original)
        self.assertNotIn("btfm_slim_codec",original)
if __name__=="__main__":unittest.main()
