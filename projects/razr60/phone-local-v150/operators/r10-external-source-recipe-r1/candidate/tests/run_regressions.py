#!/usr/bin/env python3
"""Local byte-gate/transport tests. Never execute fixture runtime/provider code."""
import argparse
import ast
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest import mock
import zlib

ROOT=Path(__file__).resolve().parents[1]
FIX=ROOT/'tests/fixtures'
CONSUMERS=('templates/release_boundaries.py',
           'source/derive_final_cascade_property_r8.py',
           'source/write_final_seal_interface_property_r8.py')


def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def pretty(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def descriptor(path,raw):return dict(path=str(path),**pin(raw))


def source_bound_module(rel, constants=None):
    """Test-only literal binding; import the complete otherwise unchanged file."""
    raw=(ROOT/rel).read_text()
    for name,value in (constants or {}).items():
        nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign)
            and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
        assert len(nodes)==1,(rel,name)
        n=nodes[0];lines=raw.splitlines(keepends=True)
        raw=''.join(lines[:n.lineno-1])+name+' = '+repr(value)+'\n'+''.join(lines[n.end_lineno:])
    module=types.ModuleType('test_only_'+Path(rel).stem)
    module.__file__=str(ROOT/rel)
    exec(compile(raw,module.__file__,'exec',optimize=0),module.__dict__)
    return module


def fixture():
    mraw=(FIX/'runtime32/MANIFEST.json').read_bytes();manifest=json.loads(mraw)
    sources={r['path']:(FIX/'runtime32'/r['path']).read_bytes() for r in manifest['files']}
    shared_manifest=(FIX/'shared17/SHARED-MATERIALS.json').read_bytes()
    shared={r['path']:(FIX/'shared17'/r['path']).read_bytes() for r in json.loads(shared_manifest)['files']}
    return mraw,sources,(FIX/'COMBINATION.TEST-ONLY.json').read_bytes(),shared,shared_manifest


class NoRuntimeExecution(BaseException):pass


class ExternalRecipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs=fixture()
        cls.recipe=(FIX/'EPOCH-SOURCE-RECIPE.TEST-ONLY.json').read_bytes()
        cls.recipe_path=FIX/'EPOCH-SOURCE-RECIPE.TEST-ONLY.json'
        cls.recipe_row=descriptor(cls.recipe_path,cls.recipe)

    def module(self,rel,*,raw=None,path=None,extra=None):
        raw=self.recipe if raw is None else raw
        path=self.recipe_path if path is None else path
        return source_bound_module(rel,dict(EPOCH_SOURCE_RECIPE_DESCRIPTOR=descriptor(path,raw),**(extra or {})))

    def test_01_unbound_all_three_refuse(self):
        for rel in CONSUMERS:
            with self.subTest(consumer=rel):
                m=source_bound_module(rel)
                with self.assertRaisesRegex(ValueError,'not frozen'):
                    m.verify_epoch_runtime_increment(*self.inputs[:4],recipe_raw=self.recipe)

    def test_02_full32_shared17_inverse_all_three(self):
        proofs=[]
        for rel in CONSUMERS:
            with self.subTest(consumer=rel):
                m=self.module(rel)
                proof=m.verify_epoch_runtime_increment(*self.inputs[:4],recipe_raw=self.recipe)
                history=m.epoch_historical_runtime_view(*self.inputs[:4],recipe_raw=self.recipe)
                self.assertEqual(proof['source_recipe'],self.recipe_row)
                self.assertEqual([x['name'] for x in proof['inverse_stages']],
                    ['exact_pre_epoch_codec_source','actual_closed902_runtime'])
                self.assertEqual(proof['runtime_source_count'],32)
                self.assertEqual(proof['shared_material_count'],17)
                self.assertEqual(pin(history[0]),{'bytes':16808,'sha256':'67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'})
                self.assertFalse(proof['source_execution_performed'])
                self.assertFalse(proof['current_head_admission_verified_here'])
                proofs.append(proof)
        self.assertTrue(all(x==proofs[0] for x in proofs))

    def test_03_wrong_or_mutable_recipe_rejected(self):
        for rel in CONSUMERS:
            for raw in (self.recipe+b' ',self.recipe[:-1],bytearray(self.recipe),None):
                with self.subTest(consumer=rel,kind=type(raw).__name__,size=None if raw is None else len(raw)):
                    with self.assertRaises(ValueError):
                        self.module(rel).verify_epoch_runtime_increment(*self.inputs[:4],recipe_raw=raw)

    def test_04_descriptor_fields_types_and_path(self):
        mutations=[None,dict(self.recipe_row,bytes=True),dict(self.recipe_row,bytes=1.0),
            dict(self.recipe_row,bytes=65537),dict(self.recipe_row,path='relative/recipe'),
            dict(self.recipe_row,path='/a/../recipe'),dict(self.recipe_row,path='//a/recipe'),
            dict(self.recipe_row,path='/a//recipe'),dict(self.recipe_row,path='/a/./recipe'),
            dict(self.recipe_row,path='/a/recipe\0'),dict(self.recipe_row,sha256='0'*63),
            dict(self.recipe_row,extra=False)]
        for row in mutations:
            with self.subTest(row=row):
                m=source_bound_module(CONSUMERS[0],{'EPOCH_SOURCE_RECIPE_DESCRIPTOR':row})
                with self.assertRaises(ValueError):m._esi_data(self.recipe)

    def test_05_packet_strict_canonical_and_exact_fields(self):
        packet=json.loads(self.recipe)
        bad=[self.recipe.replace(b'{',b'{"schema":"duplicate",',1),
             self.recipe.replace(b'{',b'{"extra":NaN,',1),pretty(packet),
             canonical(dict(packet,extra=False)),canonical(dict(packet,base85='!')),b'[]\n']
        for raw in bad:
            for rel in CONSUMERS:
                with self.subTest(consumer=rel,pin=pin(raw)):
                    with self.assertRaises((ValueError,TypeError,KeyError)):
                        self.module(rel,raw=raw)._esi_data(raw)

    def test_06_existing_decoder_bounds_and_one_stream_remain(self):
        packet=json.loads(self.recipe)
        variants=[]
        q=copy.deepcopy(packet);q['decoded']['bytes']=True;variants.append(q)
        q=copy.deepcopy(packet);q['decoded']['bytes']=262145;variants.append(q)
        q=copy.deepcopy(packet);q['compressed']['bytes']=False;variants.append(q)
        q=copy.deepcopy(packet);q['base85']+='0'*65537;variants.append(q)
        compressed=base64.b85decode(packet['base85'])+zlib.compress(b'{}')
        q=copy.deepcopy(packet);q['base85']=base64.b85encode(compressed).decode();q['compressed']=pin(compressed);variants.append(q)
        for q in variants:
            raw=canonical(q)
            with self.subTest(pin=pin(raw)):
                with self.assertRaises(ValueError):self.module(CONSUMERS[0],raw=raw)._esi_data(raw)

    def test_07_closed32_and17_unchanged(self):
        mr,src,co,shared,_=self.inputs;m=self.module(CONSUMERS[0])
        for altered in (dict(src,**{'source/extra.py':b'pass\n'}),{k:v for k,v in src.items() if k!='source/component_common.py'}):
            with self.assertRaises(ValueError):m.verify_epoch_runtime_increment(mr,altered,co,shared,recipe_raw=self.recipe)
        altered=dict(shared);altered['provider/source/daily_phone_local.py']+=b'\n'
        with self.assertRaises(ValueError):m.verify_epoch_runtime_increment(mr,src,co,altered,recipe_raw=self.recipe)

    def test_08_recipe_is_charged_to_existing_decoded_pool(self):
        mr,src,co,shared,_=self.inputs
        src=dict(src);manifest=json.loads(mr)
        # Keep source+manifest+shared strictly below 32 MiB, then the newly
        # explicit recipe original alone takes the actual public gate over.
        names=[name for name in src if name.endswith('.json')][:2]
        self.assertEqual(len(names),2)
        baseline=len(mr)+len(co)+sum(map(len,src.values()))+sum(map(len,shared.values()))
        extra=32*1024*1024-1000-baseline
        first=extra//2
        for name,count in zip(names,(first,extra-first)):src[name]+=b' '*count
        manifest['files']=[dict(path=r['path'],**pin(src[r['path']])) for r in manifest['files']]
        mr=pretty(manifest)
        self.assertLess(len(mr)+len(co)+sum(map(len,src.values()))+sum(map(len,shared.values())),32*1024*1024)
        packet=json.loads(self.recipe)
        decoded=json.loads(zlib.decompress(base64.b85decode(packet['base85'])))
        decoded['current']['runtime']=pin(mr)
        body=canonical(decoded);packed=zlib.compress(body,9)
        packet.update(decoded=pin(body),compressed=pin(packed),base85=base64.b85encode(packed).decode())
        raw=canonical(packet)
        m=self.module(CONSUMERS[0],raw=raw)
        with self.assertRaisesRegex(ValueError,'original whole pool'):
            m.verify_epoch_runtime_increment(mr,src,co,shared,recipe_raw=raw)

    def test_09_caller_recipe_substitution_refused_before_reader(self):
        for rel in CONSUMERS:
            m=self.module(rel);reads=[]
            for row in (dict(self.recipe_row,path='/another/EPOCH-SOURCE-RECIPE.json'),
                        dict(self.recipe_row,sha256='0'*64),None):
                with self.subTest(consumer=rel,row=row):
                    with self.assertRaises(ValueError):
                        m.epoch_recipe_original({'source_recipe':row},lambda r:reads.append(r))
                    self.assertEqual(reads,[])

    def test_10_real_readers_full_bytes_and_bookends(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td).resolve()/'EPOCH-SOURCE-RECIPE.json';p.write_bytes(self.recipe)
            row=descriptor(p,self.recipe)
            h=self.module(CONSUMERS[0],path=p)
            first,meta=h.read_pinned(row);second,after=h.read_pinned(row)
            self.assertEqual(first,second);self.assertEqual(meta,after)
            d=self.module(CONSUMERS[1],path=p)
            self.assertEqual(d.epoch_recipe_original({'source_recipe':row},d.original),self.recipe)
            d.recheck();self.assertIn(str(p),d.OBSERVED)
            i=self.module(CONSUMERS[2],path=p)
            self.assertEqual(i.epoch_recipe_original({'source_recipe':row},lambda r:i.original(r)[1]),self.recipe)
            for r,identity in tuple(i.SEEN.values()):
                i.read(r['path'],r['bytes'],r['sha256']);self.assertEqual(i.SEEN[r['path']][1],identity)

    def test_11_real_readers_symlink_hardlink_and_replacement(self):
        for rel in CONSUMERS:
            with tempfile.TemporaryDirectory() as td,self.subTest(consumer=rel):
                root=Path(td).resolve();p=root/'recipe';p.write_bytes(self.recipe)
                m=self.module(rel,path=p);row=descriptor(p,self.recipe)
                def read():
                    if rel==CONSUMERS[0]:return m.read_pinned(row)
                    if rel==CONSUMERS[1]:return m.original(row)
                    return m.original(row)[1]
                os.link(p,root/'alias')
                with self.assertRaises(ValueError):read()
                (root/'alias').unlink();p.unlink();p.symlink_to(self.recipe_path)
                with self.assertRaises((ValueError,OSError)):read()
                p.unlink();p.write_bytes(self.recipe);before=read()
                replacement=root/'replacement';replacement.write_bytes(self.recipe);os.replace(replacement,p)
                if rel==CONSUMERS[0]:self.assertNotEqual(before[1],read()[1])
                else:
                    with self.assertRaises(ValueError):read()

    def test_12_prepare_bundle_recipe_transport_and_recheck(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();p=root/'recipe';p.write_bytes(self.recipe);row=descriptor(p,self.recipe)
            c=root/'component';craw=pretty({'source_recipe':row});c.write_bytes(craw)
            q=root/'policy';qraw=pretty({});q.write_bytes(qraw)
            h=self.module(CONSUMERS[0],path=p);reads=[];reader=h.read_pinned
            def observe(r):reads.append(dict(r));return reader(r)
            # Isolate only the original transport. The complete consumer's
            # semantic entry is tested separately; this stub grants no state.
            def transport_only(raw,digest,**kw):
                self.assertEqual(pin(raw)['sha256'],digest);b=h.strict(raw)
                value=h.input_value(b,'component');self.assertEqual(value['source_recipe'],row)
                h._esi_data(h.original_from(b,h._esi_recipe_match(value['source_recipe'])))
                self.assertEqual(set(b['originals']),{row['sha256']})
                self.assertEqual(h.decoded_bundle_budget(b),len(craw)+len(qraw)+len(self.recipe))
                return {'transport_only':True,'component_qualified':False}
            with mock.patch.object(h,'read_pinned',observe),mock.patch.object(h,'validate_bundle',transport_only):
                _,state=h.prepare_bundle(descriptor(c,craw),descriptor(q,qraw),actual_context='mac')
            self.assertFalse(state['component_qualified'])
            self.assertEqual([r for r in reads if r['path']==str(p)],[row,row])

    def test_13_prepare_bundle_detects_recipe_replacement_at_bookend(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();p=root/'recipe';p.write_bytes(self.recipe);row=descriptor(p,self.recipe)
            c=root/'component';craw=pretty({'source_recipe':row});c.write_bytes(craw)
            q=root/'policy';qraw=pretty({});q.write_bytes(qraw)
            h=self.module(CONSUMERS[0],path=p)
            def transport_only(*a,**kw):
                replacement=root/'replacement';replacement.write_bytes(self.recipe);os.replace(replacement,p)
                return {}
            with mock.patch.object(h,'validate_bundle',transport_only):
                with self.assertRaisesRegex(ValueError,'changed while preparing'):
                    h.prepare_bundle(descriptor(c,craw),descriptor(q,qraw),actual_context='mac')

    def test_14_bundle_rejects_undeclared_original_before_runtime(self):
        h=self.module(CONSUMERS[0]);component=pretty({'source_recipe':self.recipe_row});policy=pretty({})
        bundle={'schema':'hepta.r10.release-boundary-bundle.v2','inputs':{
            'component':{'descriptor':descriptor('/component',component),'raw_b64':base64.b64encode(component).decode()},
            'policy':{'descriptor':descriptor('/policy',policy),'raw_b64':base64.b64encode(policy).decode()}},
            'originals':{self.recipe_row['sha256']:h.pack_original(self.recipe),pin(b'extra')['sha256']:h.pack_original(b'extra')}}
        raw=pretty(bundle)
        with self.assertRaisesRegex(ValueError,'original inventory differs'):
            h.validate_bundle(raw,pin(raw)['sha256'],actual_context='mac')

    def test_15_module_loader_repeats_pure_gate_before_first_exec(self):
        mr,src,co,shared,_=self.inputs
        state={'actual_context':'mac','package_manifest_raw':mr,'package_sources':src,
            'component_combination_raw':co,'shared_runtime_originals':shared,'epoch_source_recipe_raw':self.recipe}
        h=self.module(CONSUMERS[0],extra={'PACKAGE_SHA':pin(mr)['sha256']})
        calls=[]
        def never_execute(*a,**kw):calls.append(True);raise NoRuntimeExecution()
        with mock.patch.object(h,'exec',never_execute,create=True):
            with self.assertRaises(NoRuntimeExecution):
                with h.component_modules(state,actual_context='mac'):pass
            self.assertEqual(len(calls),1)
            for raw in (None,self.recipe+b' ',bytearray(self.recipe)):
                calls.clear();bad=dict(state,epoch_source_recipe_raw=raw)
                with self.assertRaises(ValueError):
                    with h.component_modules(bad,actual_context='mac'):pass
                self.assertEqual(calls,[])

    def test_16_cascade_and_interface_reject_recipe_before_history_gate(self):
        for rel in CONSUMERS[1:]:
            with self.subTest(consumer=rel):
                m=self.module(rel);reads=[]
                frozen={'source_recipe':self.recipe_row,'policy_history_input':{}}
                def reader(row):reads.append(row);return self.recipe
                with self.assertRaisesRegex(ValueError,'history input differ'):
                    m.epoch_cascade_source_inputs(frozen,self.inputs[0],self.inputs[1],reader)
                self.assertEqual(reads,[self.recipe_row])
                reads.clear()
                with self.assertRaisesRegex(ValueError,'size or digest differs'):
                    m.epoch_cascade_source_inputs(frozen,self.inputs[0],self.inputs[1],lambda r:self.recipe+b' ')

    def test_17_constructor_gate_precedes_publication_and_exec(self):
        mr,src,co,shared,sm=self.inputs
        h=self.module(CONSUMERS[0],extra={'PACKAGE_SHA':pin(mr)['sha256'],'CURRENT_COMBINATION_SHA':pin(co)['sha256'],
            'SHARED_MATERIALS_SHA':pin(sm)['sha256']})
        c=source_bound_module('templates/make_component_boundary_inputs.py',
            {'PACKAGE_SHA':pin(mr)['sha256'],'SHARED_SHA':pin(sm)['sha256']})
        with tempfile.TemporaryDirectory() as td:
            plan={'schema':c.SCHEMA,'package_manifest':descriptor(FIX/'runtime32/MANIFEST.json',mr),
                'combination':descriptor(FIX/'COMBINATION.TEST-ONLY.json',co),
                'shared_materials':descriptor(FIX/'shared17/SHARED-MATERIALS.json',sm),
                'source_recipe':self.recipe_row,'cases':[{}],'epoch_publication_originals':[],
                'epoch_publication_inputs':None,'retirement_descriptor':None,'retirement_originals':None,
                'policy_adoption':None,'policy_history_input':None,'legacy_ancestor':None,
                'pre_policy_ancestor':None,'environment_parent_ancestor':None,'property_parent_ancestors':None}
            with self.assertRaisesRegex(ValueError,'publication host original closure'):
                c.build(h,plan,Path(td).resolve()/'fresh-output')
            plan['source_recipe']=dict(self.recipe_row,sha256='0'*64)
            with self.assertRaisesRegex(ValueError,'cannot substitute'):
                c.build(h,plan,Path(td).resolve()/'fresh-output')

    def test_18_mechanical_pins_and_existing19_template_manifest(self):
        p=source_bound_module('preparer/prepare_final_cascade.py')
        d=source_bound_module(CONSUMERS[1])
        data={p.GENERATOR_MANIFEST['path']:(ROOT/'GENERATOR-SOURCE-MANIFEST.json').read_bytes(),
              p.TEMPLATE_MANIFEST['path']:(FIX/'TEMPLATE-SOURCE-MANIFEST.original.json').read_bytes()}
        for name,value in p.TEMPLATE_OVERRIDES.items():data[value['successor']['path']]=(ROOT/'templates'/name).read_bytes()
        class Originals:
            def read(self,row):
                raw=data[row['path']]
                if pin(raw)!={k:row[k] for k in ('bytes','sha256')}:raise ValueError('fixture pin mismatch')
                return raw
        p.validate_source_manifests(Originals(),d)
        self.assertEqual({k:p.SOURCE[k] for k in ('bytes','sha256')},pin((ROOT/CONSUMERS[1]).read_bytes()))
        self.assertEqual({k:p.INTERFACE[k] for k in ('bytes','sha256')},pin((ROOT/CONSUMERS[2]).read_bytes()))
        for name in ('release_boundaries.py','make_component_boundary_inputs.py'):
            self.assertEqual(d.TEMPLATE_PINS[name],pin((ROOT/'templates'/name).read_bytes()))

    def test_19_all_gate_calls_supply_recipe_and_helpers_fit(self):
        for rel in (*CONSUMERS,'templates/make_component_boundary_inputs.py'):
            raw=(ROOT/rel).read_bytes();self.assertLessEqual(len(raw),131072)
            tree=ast.parse(raw)
            aliases={n.lineno for fn in tree.body if isinstance(fn,ast.FunctionDef)
                and fn.name=='epoch_cascade_source_inputs' for n in ast.walk(fn) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Name) and n.func.id in ('gate','history_gate')}
            for n in ast.walk(tree):
                if isinstance(n,ast.Call):
                    name=n.func.id if isinstance(n.func,ast.Name) else n.func.attr if isinstance(n.func,ast.Attribute) else None
                    if name in ('verify_epoch_runtime_increment','epoch_historical_runtime_view','_esi_checked') or n.lineno in aliases:
                        self.assertIn('recipe_raw',[k.arg for k in n.keywords],(rel,n.lineno,name))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path)
    args=parser.parse_args();started=time.monotonic()
    before={str(p.relative_to(ROOT)):pin(p.read_bytes()) for p in ROOT.rglob('*') if p.is_file()}
    stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ExternalRecipeTests))
    after={str(p.relative_to(ROOT)):pin(p.read_bytes()) for p in ROOT.rglob('*') if p.is_file()}
    unchanged=before==after
    report={'schema':'hepta.external-recipe-local-regressions.v1','state':'PASS' if result.wasSuccessful() and unchanged else 'FAIL',
        'passed':result.testsRun-len(result.failures)-len(result.errors),'failed':len(result.failures)+len(result.errors),
        'tests_run':result.testsRun,'elapsed_seconds':time.monotonic()-started,'candidate_unchanged':unchanged,
        'full_consumer_files_imported':list(CONSUMERS),'fixture_runtime_members':32,'fixture_shared_members':17,
        'runtime_or_provider_source_executions':0,'phone_calls':0,'case_credit':0,'ready_claim':False,
        'test_scope':'Pure byte gate, unchanged real original readers/bookends, constructor pre-exec refusal, transport isolation and mechanical source pin cascade; no successful complete release/cascade/interface run.',
        'log':stream.getvalue()}
    raw=pretty(report)
    if args.output:
        assert ROOT not in args.output.resolve().parents,'report must stay outside candidate'
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(raw)
    print(raw.decode(),end='')
    return 0 if report['state']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
