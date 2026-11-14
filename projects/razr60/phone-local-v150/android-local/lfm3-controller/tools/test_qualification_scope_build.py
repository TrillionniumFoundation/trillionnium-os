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
from build_identity import (source_inputs, actual_build_identity, build_configuration, selected_variant,
                            claim_build_output, compiled_debuggable, verify_source_inputs)

ROOT=Path(__file__).resolve().parents[1]


class ScopeBuildIdentityTests(unittest.TestCase):
    def minimal(self, root):
        for name in ('AndroidManifest.xml','build_mac.py','assemble_pocket4.py','tools/build_identity.py',
                     'tools/verify_runtime.py','tools/fetch_pinned_runtime.py','tools/model_profiles.py',
                     'tools/verify_mobimind_runtime.py','tools/verify_ui_venus_runtime.py',
                     'provenance/mobimind-worker-r4-build.json','provenance/mobimind-worker-r4/SOURCE-MANIFEST.json',
                     'src/example/QualificationScope.java','src/example/Service.java','native/worker.c','res/values/strings.xml'):
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic '+name)
        (root/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="32"><application android:debuggable="false"/></manifest>')
        return {'source_inputs':source_inputs(root),'build_configuration':build_configuration(root,'release')}

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
            self.assertEqual(json.loads(actual_build_identity(root,{'source_inputs':inputs,'build_configuration':build_configuration(root,'release')}))['source_inputs'],inputs)

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


class BuildFlavorTests(unittest.TestCase):
    def fixture(self, root, variant='release'):
        receipt=ScopeBuildIdentityTests().minimal(root)
        receipt['build_configuration']=build_configuration(root,variant)
        return receipt

    def test_release_default_and_explicit_diagnostic(self):
        self.assertEqual(selected_variant({}),'release')
        self.assertEqual(selected_variant({'HEPTA_BUILD_VARIANT':'diagnostic'}),'diagnostic')
        for invalid in ('','debug','Release',True,None):
            with self.subTest(invalid=invalid),self.assertRaises(RuntimeError):
                selected_variant({'HEPTA_BUILD_VARIANT':invalid})

    def test_source_manifest_must_explicitly_disable_debugging(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root)
            source=(root/'AndroidManifest.xml').read_text()
            for changed in (source.replace('debuggable="false"','debuggable="true"'),
                            source.replace(' android:debuggable="false"',''),
                            source.replace('</manifest>','<application android:debuggable="false"/></manifest>')):
                (root/'AndroidManifest.xml').write_text(changed)
                with self.assertRaises(RuntimeError):build_configuration(root,'diagnostic')

    def test_same_sources_have_distinct_bound_flavor_assets(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);release=self.fixture(root)
            diagnostic={'source_inputs':release['source_inputs'],
                        'build_configuration':build_configuration(root,'diagnostic')}
            one=actual_build_identity(root,release);two=actual_build_identity(root,diagnostic)
            self.assertNotEqual(one,two)
            self.assertEqual(json.loads(one)['source_inputs'],json.loads(two)['source_inputs'])
            self.assertIs(json.loads(one)['build_configuration']['debuggable'],False)
            self.assertIs(json.loads(two)['build_configuration']['debuggable'],True)
            self.assertEqual(json.loads(one)['build_configuration']['aapt2_link_flags'],[])
            self.assertEqual(json.loads(two)['build_configuration']['aapt2_link_flags'],['--debug-mode'])

    def test_current_receipt_cannot_omit_or_mislabel_configuration(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);receipt=self.fixture(root)
            malformed=[{'source_inputs':receipt['source_inputs']}]
            for key,value in (('debuggable',0),('debuggable',True),('variant','diagnostic'),
                              ('manifest_source_sha256','0'*64),('aapt2_link_flags',['--debug-mode'])):
                item=json.loads(json.dumps(receipt));item['build_configuration'][key]=value;malformed.append(item)
            for item in malformed:
                with self.subTest(item=item),self.assertRaises(RuntimeError):verify_source_inputs(root,item)
                with self.subTest(item=item),self.assertRaises(RuntimeError):actual_build_identity(root,item)

    def test_output_marker_keeps_variants_separate_and_allows_same_variant_transport(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            release,release_pin=claim_build_output(root,'release',{})
            diagnostic,diagnostic_pin=claim_build_output(root,'diagnostic',{})
            self.assertNotEqual(release,diagnostic);self.assertNotEqual(release_pin,diagnostic_pin)
            (diagnostic/'base.apk').write_bytes(b'host transport fixture')
            self.assertEqual(claim_build_output(root,'diagnostic',{'HEPTA_BUILD_OUT':str(diagnostic)}),
                             (diagnostic,diagnostic_pin))
            with self.assertRaises(RuntimeError):claim_build_output(root,'release',{'HEPTA_BUILD_OUT':str(diagnostic)})
            unmarked=root/'unmarked';unmarked.mkdir();(unmarked/'base.apk').write_bytes(b'unknown output')
            with self.assertRaises(RuntimeError):claim_build_output(root,'release',{'HEPTA_BUILD_OUT':str(unmarked)})

    def test_actual_apk_boolean_renderings_are_strict(self):
        # Pinned P4 AAPT2 renders TYPE_INT_BOOLEAN as an unquoted word. Other
        # pinned SDK AAPT2 dumps retain the explicit Android value type.
        for namespace in ('android','http://schemas.android.com/apk/res/android'):
            for value,expected in (('false',False),('true',True),
                                   ('(type 0x12)0x0',False),('(type 0x12)0xffffffff',True)):
                dump='      E: application (line=17)\n        A: '+namespace+':debuggable(0x0101000f)='+value+'\n'
                with self.subTest(namespace=namespace,value=value):
                    self.assertIs(compiled_debuggable(dump),expected)

    def test_compiled_namespace_hostname_is_literal(self):
        for hostname in ('schemasXandroid.com', 'schemas.androidXcom', 'schemasXandroidXcom'):
            for value in ('false', 'true', '(type 0x12)0x0', '(type 0x12)0xffffffff'):
                dump=('      E: application (line=17)\n        A: http://'+hostname+
                      '/apk/res/android:debuggable(0x0101000f)='+value+'\n')
                with self.subTest(hostname=hostname,value=value),self.assertRaises(RuntimeError):
                    compiled_debuggable(dump)

    def test_missing_ambiguous_string_or_child_debug_flags_fail(self):
        head='      E: application (line=17)\n'
        attr='        A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=true\n'
        invalid=[head,head+attr+attr,head+attr+head+attr,
                 head+'          E: activity (line=18)\n'+attr,
                 head+attr.replace('=true','=\"true\"'),
                 head+attr.replace('=true','=(type 0x03)0x0'),
                 head+attr.replace('=true','=1'),
                 head+attr.replace('0x0101000f','0x01010010'),
                 attr+head,head+attr.replace('        A:','      A:')]
        for dump in invalid:
            with self.subTest(dump=dump),self.assertRaises(RuntimeError):compiled_debuggable(dump)


if __name__=='__main__':unittest.main()
