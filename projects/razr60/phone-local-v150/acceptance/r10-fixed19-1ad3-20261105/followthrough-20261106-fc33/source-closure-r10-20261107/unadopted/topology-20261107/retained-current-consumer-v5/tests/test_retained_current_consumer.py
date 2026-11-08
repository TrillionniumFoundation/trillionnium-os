#!/usr/bin/env python3
"""Portable exact-source, actual selected-reader and new consumer-gate checks.

These tests do not claim to replay the private complete Mac original set.
"""
from __future__ import annotations
import argparse
import ast
import copy
import json
from pathlib import Path
import types
import unittest

PACKAGE=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--base',type=Path,required=True)
parser.add_argument('--v3',type=Path);parser.add_argument('--v4',type=Path);parser.add_argument('--report',type=Path)
options,_=parser.parse_known_args();BASE=options.base.resolve()
V3=options.v3.resolve() if options.v3 else BASE/'source-parent-v3'
V4=options.v4.resolve() if options.v4 else BASE/'source-parent-consumer-v4'
RAW=(PACKAGE/'candidate/retained_current_consumer.py').read_bytes()
LOADER_RAW=(PACKAGE/'candidate/bound_loader.py').read_bytes()
loader=types.ModuleType('portable_v5_loader');exec(compile(LOADER_RAW,'<portable-v5-loader>','exec'),loader.__dict__)
candidate=loader.load_bound(RAW,RAW)
V4_RAW=(V4/'candidate/source_parent_consumer.py').read_bytes()
V4_LOADER=(V4/'candidate/bound_loader.py').read_bytes()
V3_RAW=(V3/'candidate/source_parent_reader.py').read_bytes();V3_LOADER=(V3/'candidate/bound_loader.py').read_bytes()
V2_RAW=(BASE/'candidate/derived/reader_selector.py').read_bytes()
V2_LOADER=(BASE/'candidate/derived/bound_selector_loader.py').read_bytes()
ORIGINAL=(BASE/'originals/late_boundary.r10.original.py').read_bytes()
ADAPTER=(PACKAGE/'originals/retained_transport_r9_adapter.original.py').read_bytes()
INVENTORY=candidate.function_source((BASE/'candidate/derived/source_parent_inventory_value.py').read_bytes(),'inventory_value')
SCOPE=candidate.function_source((BASE/'candidate/derived/retained_r8_verify_complete_scope.py').read_bytes(),'verify_complete_scope')
v4=candidate.module(V4_LOADER,'portable_v4_loader').load_bound(V4_RAW,V4_RAW)
V4_CURRENT,V4_TRANSFORM=v4.derive_source(ORIGINAL,INVENTORY)
CURRENT,CURRENT_TRANSFORM=candidate.derive_current(V4_CURRENT)
DERIVED_ADAPTER,ADAPTER_TRANSFORM=candidate.derive_adapter(ADAPTER)
COUNTERS={'source_binding_rejections':0,'constructor_rejections':0,'new_envelope_acceptances':0,
          'new_envelope_rejections':0,'actual_selected_reader_rejections_before_provider':0,
          'wrong_in_process_producer_rejections':0,'uncached_outer_calls':0}


def actual_reader(kind):
    loader=candidate.module(V2_LOADER,'portable_actual_v2_loader')
    selected=loader.make_selector(selector_source=V2_RAW,implementation_source=V2_RAW,
                                  inventory_function=INVENTORY,scope_function=SCOPE)
    paths={'r7-reader':'verify_retained_preaccept_r7.original.py','r8-reader':'verify_retained_staged_r8.original.py',
           'r9-reader':'verify_retained_transport_r9.original.py'}
    raw=(BASE/'originals'/paths[kind]).read_bytes()
    built={'r7-reader':selected.r7_reader,'r8-reader':selected.r8_reader,'r9-reader':selected.r9_reader}[kind](raw)
    return candidate.RetainedReader(kind,built,selected,candidate.pin(RAW)),built,selected


class SourceTests(unittest.TestCase):
    def reject(self,fn):
        with self.assertRaises(ValueError):fn()
        COUNTERS['source_binding_rejections']+=1
    def test_actual_constructor_binding(self):
        self.assertEqual(candidate.pin(RAW),loader.CONSTRUCTOR_PIN)
        self.assertEqual(candidate.__constructor_loaded_source__,RAW)
        for actual,declared in ((RAW+b'\n',RAW),(RAW[:-1],RAW),(RAW,RAW+b'\n'),(RAW,b'unrelated'),(RAW.decode(),RAW),(RAW,None)):
            self.reject(lambda a=actual,b=declared:loader.load_bound(a,b))
    def test_frozen_dependency_pins_and_actual_v4_base(self):
        self.assertEqual(candidate.pin(V4_CURRENT),candidate.V4_DERIVED_CURRENT)
        self.assertEqual(candidate.pin(V4_RAW),candidate.V4_CONSTRUCTOR)
        self.assertEqual(candidate.pin(V4_LOADER),candidate.V4_LOADER)
        self.assertEqual(candidate.pin(V3_RAW),candidate.V3_CONSTRUCTOR)
        self.assertEqual(candidate.pin(V3_LOADER),candidate.V3_LOADER)
        self.assertEqual(candidate.pin(V2_RAW),candidate.V2_SELECTOR)
        self.assertEqual(candidate.pin(V2_LOADER),candidate.V2_LOADER)
        self.assertEqual(candidate.pin(ORIGINAL),candidate.FROZEN_CURRENT)
        self.assertEqual(candidate.pin(ADAPTER),candidate.ORIGINAL_ADAPTER)
    def test_whole_byte_inverse_and_pinned_sites(self):
        self.assertEqual(candidate.derive_current(V4_CURRENT),(CURRENT,CURRENT_TRANSFORM))
        self.assertEqual(candidate.derive_adapter(ADAPTER),(DERIVED_ADAPTER,ADAPTER_TRANSFORM))
        self.assertTrue(CURRENT_TRANSFORM['whole_byte_inverse_verified'])
        self.assertTrue(ADAPTER_TRANSFORM['whole_byte_inverse_verified'])
        self.assertEqual(len(CURRENT_TRANSFORM['replacements']),15)
        self.assertEqual(len(ADAPTER_TRANSFORM['replacements']),5)
        for raw in (V4_CURRENT+b'\n',V4_CURRENT[:-1]):self.reject(lambda r=raw:candidate.derive_current(r))
        for raw in (ADAPTER+b'\n',ADAPTER[:-1]):self.reject(lambda r=raw:candidate.derive_adapter(r))
    def test_v4_selected_outer_guards_unchanged(self):
        names=('reviewed_source_parent_records','_source_parent_original','exact_descriptor','current_context',
               'boundary_from_original','closed_boundary_originals','source_parent_boundary_from_original',
               'source_parent_closed_boundary_originals','require_failed_ancestor_tail','inventory_value')
        for name in names:self.assertEqual(candidate.function_source(CURRENT,name),candidate.function_source(V4_CURRENT,name))
        for name in ('consumer_execution_source_sha256','consumer_frozen_data_source_sha256'):
            self.assertEqual(candidate.function_source(CURRENT,name),candidate.function_source(V4_CURRENT,name))
        self.assertNotIn(b'def reviewed_source_sha256(',CURRENT)
    def test_adapter_old_descriptor_explicitly_data_only(self):
        self.assertNotIn(b'self.adapter_source',DERIVED_ADAPTER)
        self.assertIn(b'self.historical_adapter_source',DERIVED_ADAPTER)
        self.assertIn(b"value['runtime_adapter']==self.historical_adapter_source",DERIVED_ADAPTER)
        self.assertIn(b"'retained_failed_transport_runtime_adapter':self.historical_adapter_source",DERIVED_ADAPTER)
        original_literals={};derived_literals={}
        for raw,out in ((ADAPTER,original_literals),(DERIVED_ADAPTER,derived_literals)):
            for node in ast.parse(raw).body:
                if isinstance(node,ast.Assign):
                    for target in node.targets:
                        if isinstance(target,ast.Name):
                            try:out[target.id]=ast.literal_eval(node.value)
                            except (ValueError,TypeError):pass
        self.assertEqual(original_literals,derived_literals)
        self.assertEqual(candidate.function_source(ADAPTER,'descriptor',class_name='Adapter'),
                         candidate.function_source(DERIVED_ADAPTER,'descriptor',class_name='Adapter'))
        self.assertEqual(candidate.function_source(ADAPTER,'read_pinned',class_name='Adapter'),
                         candidate.function_source(DERIVED_ADAPTER,'read_pinned',class_name='Adapter'))
    def test_constructor_pin_faults_before_proof_provider(self):
        calls=[]
        params=dict(current_source=ORIGINAL,historical_sources={},historical_adapter_source=ADAPTER,
            v4_constructor_source=V4_RAW,v4_loader_source=V4_LOADER,v3_constructor_source=V3_RAW,v3_loader_source=V3_LOADER,
            v2_selector_source=V2_RAW,v2_loader_source=V2_LOADER,inventory_function=INVENTORY,scope_function=SCOPE,
            read_stage_original=lambda row:calls.append(row),read_retained_original=lambda row:calls.append(row),implementation_source=RAW)
        for name in ('implementation_source','current_source','historical_adapter_source','v4_constructor_source','v4_loader_source',
                     'v3_constructor_source','v3_loader_source','v2_selector_source','v2_loader_source'):
            with self.assertRaises(ValueError):candidate.construct(**{**params,name:params[name]+b'\n'})
            COUNTERS['constructor_rejections']+=1
        for change in ({'read_stage_original':None},{'read_retained_original':None},{}):
            with self.assertRaises(ValueError):candidate.construct(**{**params,**change})
            COUNTERS['constructor_rejections']+=1
        self.assertEqual(calls,[])


class RealSelectedReaderTests(unittest.TestCase):
    def test_actual_standalone_readers_reject_before_original_provider(self):
        entries={'r7-reader':'verify_retained_preaccept_archive','r8-reader':'verify_retained_staged_archive',
                 'r9-reader':'verify_retained_transport_archive'}
        for kind,entry in entries.items():
            reader,built,selector=actual_reader(kind);calls=[]
            with self.assertRaises(ValueError):
                candidate.consume_reader_call(reader,kind,entry,None,read_pinned=lambda row:calls.append(row))
            self.assertEqual(calls,[])
            self.assertNotEqual(built.__reference_source_identity__,built.__derived_implementation_identity__)
            self.assertEqual(reader.provenance()['actual_derived_reader_source'],built.__derived_implementation_identity__)
            self.assertIn('UNADOPTED',built.__file__)
            COUNTERS['actual_selected_reader_rejections_before_provider']+=1
    def test_wrong_producer_type_and_method_rejected_before_call(self):
        class FalseProducer:
            def __getattr__(self,name):raise AssertionError('unbound producer cannot run')
        for fn in (lambda:candidate.consume_reader_call(FalseProducer(),'r7-reader','verify_retained_preaccept_archive',None),
                   lambda:candidate.consume_adapter_call(FalseProducer(),'verify'),
                   lambda:candidate.consume_reader_call(actual_reader('r7-reader')[0],'r9-reader','verify_retained_transport_archive',None),
                   lambda:candidate.consume_reader_call(actual_reader('r7-reader')[0],'r7-reader','observe_current_absence')):
            with self.assertRaises(ValueError):fn()
            COUNTERS['wrong_in_process_producer_rejections']+=1


class EnvelopeTests(unittest.TestCase):
    def test_new_result_data_shapes_and_unknown(self):
        provenance={'schema':'EXPLICIT_SYNTHETIC_ENVELOPE_UNIT_ONLY'}
        for kind,method,value in [('r9-runtime-adapter','verify',{'global_unknown_effect_count':None,'native_terminal':None}),
            ('r9-reader','validate_private_preservation',True),('r9-runtime-adapter','source_parent_inventory',({}, {}, 'synthetic'))]:
            envelope=candidate.result_envelope(kind,method,value,provenance)
            self.assertEqual(candidate.decode_result(envelope,kind=kind,method=method,expected_provenance=provenance),value)
            COUNTERS['new_envelope_acceptances']+=1
    def test_new_result_schema_claim_and_identity_rejections(self):
        provenance={'schema':'EXPLICIT_SYNTHETIC_ENVELOPE_UNIT_ONLY','source':'1'*64}
        original=candidate.result_envelope('r9-runtime-adapter','verify',{},provenance)
        changes=[('schema','old'),('producer_kind','r7-reader'),('method','source_parent_inventory'),
            ('historical_result_is_old_execution_attestation',True),('production_adopted',True),('runtime_admission',True),
            ('current_native_case_credit',False),('current_native_case_credit',1),('whole_stage_budget_verified',True),
            ('historical_result',[]),('execution_provenance',{'schema':provenance['schema'],'source':'2'*64})]
        faults=[]
        for key,value in changes:
            bad=copy.deepcopy(original);bad[key]=value;faults.append((bad,'verify'))
        faults.extend([(None,'verify'),({**original,'extra':None},'verify'),
            ({k:v for k,v in original.items() if k!='execution_provenance'},'verify'),
            (candidate.result_envelope('r9-runtime-adapter','preserve',False,provenance),'preserve'),
            (candidate.result_envelope('r9-runtime-adapter','source_parent_inventory',[{}, {}, 'synthetic'],provenance),'source_parent_inventory'),
            (candidate.result_envelope('r9-runtime-adapter','source_parent_inventory',({}, {}),provenance),'source_parent_inventory')])
        for bad,method in faults:
            with self.assertRaises(ValueError):
                candidate.decode_result(bad,kind='r9-runtime-adapter',method=method,expected_provenance=provenance)
            COUNTERS['new_envelope_rejections']+=1
    def test_outer_current_envelope_does_not_cache_or_promote(self):
        calls=[]
        def spy(*args,**kwargs):calls.append((args,kwargs));return {'historical_qualified':True,'UNKNOWN':None}
        current=candidate.CurrentConsumer({name:spy for name in candidate.METHODS},{'schema':'EXPLICIT_SYNTHETIC_WRAPPER_ONLY'})
        for _ in range(2):
            result=current.retained_failed_transport()
            self.assertFalse(result['historical_result_is_old_execution_attestation'])
            self.assertFalse(result['runtime_admission']);self.assertFalse(result['production_adopted'])
            self.assertFalse(result['whole_stage_budget_verified']);self.assertEqual(result['current_native_case_credit'],0)
            self.assertIsNone(result['historical_result']['UNKNOWN']);COUNTERS['uncached_outer_calls']+=1
        self.assertEqual(len(calls),2)
        with self.assertRaises(AttributeError):current._methods={}
        with self.assertRaises(AttributeError):current.verify_current(None)
    def test_errors_keep_original_type_and_message(self):
        def reject():raise ValueError('explicit synthetic original rejection')
        current=candidate.CurrentConsumer({name:reject for name in candidate.METHODS},{'schema':'EXPLICIT_SYNTHETIC_WRAPPER_ONLY'})
        with self.assertRaisesRegex(ValueError,'^explicit synthetic original rejection$'):current.retained_preaccept()


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(SourceTests),
        unittest.defaultTestLoader.loadTestsFromTestCase(RealSelectedReaderTests),
        unittest.defaultTestLoader.loadTestsFromTestCase(EnvelopeTests)]))
    report={'schema':'hepta.UNADOPTED.retained-current-portable-tests.v5','state':'PASS' if result.wasSuccessful() else 'FAIL',
        'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'counters':COUNTERS,
        'constructor_source':candidate.pin(RAW),'bound_loader_source':candidate.pin(LOADER_RAW),
        'actual_current_source':candidate.pin(CURRENT),'actual_adapter_source':candidate.pin(DERIVED_ADAPTER),
        'private_complete_actual_original_replay_claimed_by_CI':False,'production_adopted':False,'runtime_admission':False,
        'current_native_case_credit':0,'complete_production_IO_metering_verified':False,'whole_stage_budget_verified':False}
    raw=candidate.encoded(report)
    if options.report:
        with options.report.open('xb') as stream:stream.write(raw)
    print(raw.decode(),end='')
    raise SystemExit(0 if result.wasSuccessful() else 1)
