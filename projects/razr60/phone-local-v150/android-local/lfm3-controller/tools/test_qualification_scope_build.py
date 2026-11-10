"""Actual build asset generation and real ZIP assembly block, without Android tools."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile
import struct
from build_identity import source_inputs, actual_build_identity

ROOT=Path(__file__).resolve().parents[1]


class ScopeBuildIdentityTests(unittest.TestCase):
    def minimal(self, root):
        for name in ('AndroidManifest.xml','build_mac.py','assemble_pocket4.py','tools/build_identity.py',
                     'tools/verify_runtime.py','tools/fetch_pinned_runtime.py','tools/model_profiles.py',
                     'tools/verify_mobimind_runtime.py','tools/verify_ui_venus_runtime.py',
                     'provenance/mobimind-worker-r4-build.json','provenance/mobimind-worker-r4/SOURCE-MANIFEST.json',
                     'src/example/QualificationScope.java','src/example/Service.java','native/worker.c','res/values/strings.xml'):
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic '+name)
        (root/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="32"/>')
        return {'source_inputs':source_inputs(root)}

    def test_exact_map_version_and_determinism(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);receipt=self.minimal(root);one=actual_build_identity(root,receipt)
            self.assertEqual(one,actual_build_identity(root,receipt));value=json.loads(one)
            self.assertEqual(value['version_code'],32);self.assertEqual(value['source_inputs'],receipt['source_inputs'])
            self.assertEqual(value['schema'],'hepta.actual-build-inputs.v1')

    def test_stale_mac_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);receipt=self.minimal(root);(root/'src/example/Service.java').write_text('changed actual dispatch')
            with self.assertRaises(RuntimeError):actual_build_identity(root,receipt)

    def test_historical_root_manifest_neither_identity_nor_cycle(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);receipt=self.minimal(root);one=actual_build_identity(root,receipt)
            (root/'SOURCE-MANIFEST.json').write_text('{"historical":"old-v30"}')
            (root/'assets').mkdir();(root/'assets/hepta-build-identity.json').write_bytes(one)
            self.assertEqual(actual_build_identity(root,receipt),one)
            (root/'SOURCE-MANIFEST.json').write_text('different copied history')
            self.assertEqual(actual_build_identity(root,receipt),one)
            self.assertFalse(any(r['path'].startswith('assets/') or r['path']=='SOURCE-MANIFEST.json' for r in receipt['source_inputs']))

    def test_manifest_race_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);receipt=self.minimal(root)
            def observed(_):
                (root/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="99"/>')
                return receipt['source_inputs']
            with mock.patch('build_identity.source_inputs',side_effect=observed):
                with self.assertRaisesRegex(RuntimeError,'Manifest changed'):actual_build_identity(root,receipt)

    def test_actual_java_collection_in_complete_synthetic_tree(self):
        # The review cache need not contain visual provenance. Never synthesize a
        # production identity from that partial cache; here only surrounding
        # build metadata is synthetic and all actual Java inputs are copied.
        import shutil
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.minimal(root)
            shutil.rmtree(root/'src');shutil.copytree(ROOT/'src',root/'src')
            inputs=source_inputs(root);paths={r['path'] for r in inputs}
            for name in ('QualificationScope','QualificationScopeConfig','HeptaAccessibilityService','LocalTaskController','LocalTaskSession','MainActivity'):
                self.assertIn('src/org/trillionnium/hepta/local/'+name+'.java',paths)
            self.assertNotIn('SOURCE-MANIFEST.json',paths)
            for name in ('tools/build_identity.py','assemble_pocket4.py','build_mac.py','AndroidManifest.xml'):self.assertIn(name,paths)
            self.assertEqual(json.loads(actual_build_identity(root,{'source_inputs':inputs}))['source_inputs'],inputs)

    def test_missing_required_provenance_cannot_create_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);receipt=self.minimal(root)
            (root/'provenance/mobimind-worker-r4-build.json').unlink()
            with self.assertRaisesRegex(RuntimeError,'existing regular'):actual_build_identity(root,receipt)

    def zip_block(self):
        tree=ast.parse((ROOT/'assemble_pocket4.py').read_text())
        blocks=[n for n in tree.body if isinstance(n,ast.With) and "base.apk" in ast.get_source_segment((ROOT/'assemble_pocket4.py').read_text(),n).splitlines()[0]]
        self.assertEqual(len(blocks),1)
        return compile(ast.Module(body=blocks,type_ignores=[]),'actual-assembly-zip-block','exec')

    def package(self,duplicate=False):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);(out/'dex').mkdir();(out/'dex/classes.dex').write_bytes(b'synthetic dex')
            asset=b'{"synthetic":"verified source-input asset"}\n';name='assets/hepta-build-identity.json'
            with zipfile.ZipFile(out/'base.apk','w') as z:
                z.writestr('resources.arsc',b'synthetic resources')
                if duplicate:z.writestr(name,b'stale identity')
            env={'zipfile':zipfile,'OUT':out,'UNSIGNED':out/'unsigned.apk','actual_build_asset':asset,'actual_build_asset_name':name,'libraries':{},'struct':struct}
            if duplicate:
                with self.assertRaisesRegex(RuntimeError,'preexisting'):exec(self.zip_block(),env)
            else:
                exec(self.zip_block(),env)
                with zipfile.ZipFile(out/'unsigned.apk') as z:
                    self.assertEqual(z.read(name),asset);self.assertEqual(z.namelist().count(name),1)
                    self.assertEqual(z.read('classes.dex'),b'synthetic dex')
    def test_actual_zip_assembly_includes_exact_asset(self):self.package()
    def test_actual_zip_assembly_refuses_preexisting_identity(self):self.package(True)


if __name__=='__main__':unittest.main()
