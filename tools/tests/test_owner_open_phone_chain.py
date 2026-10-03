"""Closed source rewrites and the actual Fogos entry using licensed Make macros.

Hardware/core products, unrelated audio/version files are empty fixtures, and
SDK is disabled. This does not qualify complete Kati/Soong or installed images.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import types
import unittest

ROOT = Path(__file__).absolute().parents[2]
TOOL = ROOT / 'tools/generate-owner-open-phone-config.py'
GEN = types.ModuleType('phone_generator')
GEN.__file__ = str(TOOL)
exec(compile(TOOL.read_bytes(), str(TOOL), 'exec'), GEN.__dict__)
OVERLAY = ROOT / 'android-integration/working-tree'
FIXTURES = Path(__file__).with_name('fixtures')
BEFORE = (FIXTURES / 'private_fogos_before.mk').read_bytes()


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        config = self.root / GEN.PREFIX
        config.mkdir(parents=True)
        for row in GEN.RULES:
            for name in row[:2]:
                shutil.copyfile(ROOT / (GEN.PREFIX + name), config / name)
        (self.root / 'tools').mkdir()
        shutil.copyfile(ROOT / 'tools/owner-open-phone-chain.v1.json',
                        self.root / 'tools/owner-open-phone-chain.v1.json')

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_sources_and_generated_files(self):
        result = GEN.check(self.root)
        self.assertTrue(result['ok'])
        self.assertFalse(result['actual_product_graph_qualified'])

    def test_only_inherit_edges_differ(self):
        for baseline, owner, old, new, *_ in GEN.RULES:
            before = (self.root / (GEN.PREFIX + baseline)).read_bytes()
            after = (self.root / (GEN.PREFIX + owner)).read_bytes()
            self.assertEqual(before.replace(GEN.inherit(old).encode(), GEN.inherit(new).encode()), after)

    def test_baseline_mutation_rejected_without_output_changes(self):
        for baseline, owner, *_ in GEN.RULES:
            with self.subTest(baseline=baseline):
                path = self.root / (GEN.PREFIX + baseline)
                before = path.read_bytes()
                output = self.root / (GEN.PREFIX + owner)
                unchanged = output.read_bytes()
                path.write_bytes(before + b'# changed\n')
                with self.assertRaises(ValueError):
                    GEN.check(self.root, write=True)
                self.assertEqual(output.read_bytes(), unchanged)
                path.write_bytes(before)

    def test_owner_wrong_inherit_or_app_removal_rejected(self):
        for changed in (b'# missing ordinary configuration\n',
                        (self.root / (GEN.PREFIX + 'common_owner_open_mobile.mk')).read_bytes()
                        .replace(b'common_owner_open.mk)', b'common.mk)')):
            p = self.root / (GEN.PREFIX + 'common_owner_open_mobile.mk')
            p.write_bytes(changed)
            with self.assertRaises(ValueError):
                GEN.check(self.root)

    def test_write_restores_exact_owner_files_leaves_all_baselines(self):
        snapshots = {self.root / (GEN.PREFIX + row[0]):
                     (self.root / (GEN.PREFIX + row[0])).read_bytes() for row in GEN.RULES}
        for row in GEN.RULES:
            (self.root / (GEN.PREFIX + row[1])).unlink()
        self.assertTrue(GEN.check(self.root, write=True)['ok'])
        self.assertEqual(snapshots, {p: p.read_bytes() for p in snapshots})

    def test_rule_metadata_path_or_digest_mutation_rejected(self):
        p = self.root / 'tools/owner-open-phone-chain.v1.json'
        original = p.read_bytes()
        for key, value in [('baseline', '../../outside'), ('owner_output', GEN.PREFIX + 'common.mk'),
                           ('baseline_sha256', '0' * 64), ('owner_sha256', '0' * 64)]:
            with self.subTest(key=key):
                data = json.loads(original)
                data['rules'][0][key] = value
                p.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    GEN.check(self.root, write=True)
                p.write_bytes(original)

    def test_duplicate_metadata_rejected(self):
        p = self.root / 'tools/owner-open-phone-chain.v1.json'
        p.write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaises(ValueError):
            GEN.check(self.root)

    def test_source_symlink_hardlink_and_fifo_rejected(self):
        p = self.root / 'source'
        p.write_bytes(b'abc')
        alias = self.root / 'alias'
        alias.symlink_to(p)
        with self.assertRaises(ValueError):
            GEN.read_source(alias, time.monotonic() + 5)
        os.link(p, self.root / 'link')
        with self.assertRaises(ValueError):
            GEN.read_source(p, time.monotonic() + 5)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            GEN.read_source(fifo, time.monotonic() + 5)

    def test_parent_alias_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root / 'tools', target_is_directory=True)
        with self.assertRaises(OSError):
            GEN.read_source(alias / 'owner-open-phone-chain.v1.json', time.monotonic() + 5)

    def test_oversize_and_deadline_rejected(self):
        p = self.root / 'large'
        p.write_bytes(b'x' * (128 * 1024 + 1))
        with self.assertRaises(ValueError):
            GEN.read_source(p, time.monotonic() + 5)
        with self.assertRaises(TimeoutError):
            GEN.check(self.root, seconds=0)


class FogosEntryTests(unittest.TestCase):
    def test_exact_private_fogos_rewrite_retains_other_bytes(self):
        rewritten = GEN.rewrite_fogos_private_product(BEFORE)
        restored = rewritten.replace(GEN.inherit('common_owner_open_full_phone.mk').encode(),
                                     GEN.inherit('common_full_phone.mk').encode()) + GEN.FOGOS_REMOVED_SUFFIX
        self.assertEqual(restored, BEFORE)
        self.assertIn(b'ifeq ($(TARGET_BUILD_VARIANT),userdebug)\nTRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT := true', rewritten)
        self.assertNotIn(b'owner-open/product.mk', rewritten)

    def test_already_rewritten_or_changed_private_product_rejected(self):
        for body in [BEFORE + b'# changed\n', GEN.rewrite_fogos_private_product(BEFORE),
                     BEFORE.replace(b'common_full_phone.mk)', b'common_owner_open.mk)')]:
            with self.subTest(sha=hashlib.sha256(body).hexdigest()), self.assertRaises(ValueError):
                GEN.rewrite_fogos_private_product(body)


class ActualMakeInheritanceTests(unittest.TestCase):
    def test_exact_licensed_fixture_inputs(self):
        telephony = FIXTURES / 'owner_open_phone_chain'
        provenance = json.loads((telephony / 'provenance.json').read_bytes())
        body = (telephony / provenance['fixture_file']).read_bytes()
        self.assertEqual((len(body), hashlib.sha256(body).hexdigest()),
                         (provenance['bytes'], provenance['sha256']))
        self.assertEqual(provenance['license']['identifier'], 'Apache-2.0')
        notice = provenance['license']['notice_utf8'].encode('utf-8')
        self.assertEqual((len(notice), hashlib.sha256(notice).hexdigest()),
                         (provenance['license']['bytes'], provenance['license']['sha256']))
        self.assertEqual(provenance['git_blob'],
                         hashlib.sha1(('blob ' + str(len(body)) + '\0').encode() + body).hexdigest())
        macros = FIXTURES / 'android_product_inheritance'
        data = json.loads((macros / 'provenance.json').read_bytes())
        for row in data['fixture_files']:
            fixture = (macros / row['file']).read_bytes()
            self.assertEqual((len(fixture), hashlib.sha256(fixture).hexdigest()),
                             (row['bytes'], row['sha256']))
            self.assertIn(b'Licensed under the Apache License, Version 2.0', fixture)

    def evaluate(self, variant, corrected):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in [
                *(Path(GEN.PREFIX).relative_to('android-integration/working-tree') / row[i]
                  for row in GEN.RULES for i in (0, 1)),
                Path('vendor/trillionnium/config/common.mk'),
                Path('vendor/trillionnium/config/common_owner_open.mk'),
                Path('vendor/trillionnium/config/common_owner_open_base.mk'),
                Path('vendor/trillionnium/owner-open/product.mk'),
            ]:
                p = root / relative
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(OVERLAY / relative, p)
            telephony = root / 'vendor/trillionnium/config/telephony.mk'
            telephony.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(FIXTURES / 'owner_open_phone_chain/telephony.mk', telephony)
            for rel in ['vendor/trillionnium/config/version.mk',
                        'vendor/trillionnium/audio/audio.mk',
                        'vendor/trillionnium/config/aosp_audio.mk',
                        'vendor/trillionnium/config/trillionnium_audio.mk',
                        'device/motorola/fogos/device.mk',
                        'build/target/product/core_64_bit.mk',
                        'build/target/product/full_base_telephony.mk']:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('# Explicit unrelated source-mechanism fixture stub.\n')
            for name in ['node_fns.mk', 'inherit-product.mk']:
                shutil.copyfile(FIXTURES / 'android_product_inheritance' / name, root / name)
            product = root / 'device/motorola/fogos/trillionnium_fogos.mk'
            product.write_bytes(GEN.rewrite_fogos_private_product(BEFORE) if corrected else BEFORE)
            variables = 'PRODUCT_PACKAGES PRODUCT_PACKAGES_DEBUG PRODUCT_PRODUCT_PROPERTIES PRODUCT_SYSTEM_EXT_PROPERTIES PRODUCT_COPY_FILES PRODUCT_NAME PRODUCT_DEVICE PRODUCT_MODEL PRODUCT_BRAND PRODUCT_MANUFACTURER PRODUCT_PACKAGE_OVERLAYS PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS'
            makefile = 'TARGET_BUILD_VARIANT := ' + variant + '\n' + '''TARGET_DISABLE_TRILLIONNIUM_SDK := true
SRC_TARGET_DIR := build/target
_product_var_list := ''' + variables + '''
_product_single_value_vars := PRODUCT_NAME PRODUCT_DEVICE PRODUCT_MODEL PRODUCT_BRAND PRODUCT_MANUFACTURER
include node_fns.mk
include inherit-product.mk
$(call import-nodes,PRODUCTS,device/motorola/fogos/trillionnium_fogos.mk,$(_product_var_list),$(_product_single_value_vars))
$(info PACKAGES=$(PRODUCTS.device/motorola/fogos/trillionnium_fogos.mk.PRODUCT_PACKAGES))
$(info DEBUG_PACKAGES=$(PRODUCTS.device/motorola/fogos/trillionnium_fogos.mk.PRODUCT_PACKAGES_DEBUG))
$(info PRODUCT_PROPERTIES=$(PRODUCTS.device/motorola/fogos/trillionnium_fogos.mk.PRODUCT_PRODUCT_PROPERTIES))
$(info PRODUCT_NAME=$(PRODUCTS.device/motorola/fogos/trillionnium_fogos.mk.PRODUCT_NAME))
.PHONY: all
all:
\t@:
'''
            (root / 'Makefile').write_text(makefile)
            result = subprocess.run(['make', '--no-print-directory', 'all'], cwd=root,
                                    capture_output=True, text=True, timeout=15,
                                    env={'PATH': os.environ['PATH'], 'LANG': 'C', 'LC_ALL': 'C'})
            self.assertEqual(result.returncode, 0, result.stderr)
            fields = {}
            for line in result.stdout.splitlines():
                if '=' in line:
                    name, value = line.split('=', 1)
                    if name in ('PACKAGES', 'DEBUG_PACKAGES', 'PRODUCT_PROPERTIES', 'PRODUCT_NAME'):
                        fields[name] = set(value.split())
            return fields

    def test_real_fogos_entry_ordinary_phone_retention_and_legacy_exclusion_all_variants(self):
        common = (OVERLAY / 'vendor/trillionnium/config/common.mk').read_text()
        start = common.index('# Built-in headless Trillionnium root Linux payload.')
        end = common.index('PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST +=', start)
        legacy = set(re.findall(r'(?m)^    ([A-Za-z0-9_.+-]+)(?: \\)?$', common[start:end])) | {'init.trillionnium-system_ext.rc'}
        required = {'trillionnium-owner-open-rootfs-image', 'trillionnium-owner-open-rootfs-manifest',
                    'trillionnium-owner-open-rootfs-digest', 'trillionnium-owner-open-bootstrap',
                    'trillionnium-owner-open-emergency-stop', 'trillionnium-owner-open-ingress',
                    'trillionnium-owner-open-init-rc', 'trillionnium-owner-open-profile-config',
                    'TrillionniumOwnerOpenShell'}
        ordinary = {'AvatarPicker', 'LatinIME', 'Launcher3QuickStep', 'Launcher3Overlay',
                    'ThemePicker', 'QuickAccessWallet', 'Camelot', 'Etar', 'Recorder', 'Seedvault',
                    'Aperture', 'AudioFX', 'sensitive_pn.xml', 'apns-conf.xml', 'messaging', 'Stk'}
        for variant in ['user', 'userdebug', 'eng']:
            with self.subTest(variant=variant):
                old, new = self.evaluate(variant, False), self.evaluate(variant, True)
                self.assertTrue(legacy & (old['PACKAGES'] | old['DEBUG_PACKAGES']))
                self.assertFalse(legacy & (new['PACKAGES'] | new['DEBUG_PACKAGES']))
                self.assertLessEqual(required, new['PACKAGES'])
                self.assertLessEqual(ordinary, old['PACKAGES'])
                self.assertLessEqual(ordinary, new['PACKAGES'])
                self.assertEqual(old['PRODUCT_NAME'], new['PRODUCT_NAME'])
                self.assertIn('ro.support_one_handed_mode?=true', new['PRODUCT_PROPERTIES'])
                self.assertIn('ro.config.ringtone=Orion.ogg', new['PRODUCT_PROPERTIES'])
                self.assertIn('ro.config.notification_sound=Argon.ogg', new['PRODUCT_PROPERTIES'])
                self.assertEqual('adb_root' in new['PACKAGES'], variant == 'userdebug')


if __name__ == '__main__':
    unittest.main()
