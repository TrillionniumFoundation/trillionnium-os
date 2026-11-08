#!/usr/bin/env python3
"""Portable source, binding, envelope, and whole-module helper differential tests.

Reports are written only to a new explicit --report path. Frozen v1/v2 files
and saved results are never modified. Private full-reader validation has its
own replay harness and is not implied by synthetic cases.
"""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import types
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--base', type=Path, required=True)
parser.add_argument('--report', type=Path)
options, unittest_args = parser.parse_known_args()
BASE = options.base.resolve()
sys.path.insert(0, str(BASE/'tests'))
import harness
import test_inventory_topology as inventory_suite

RAW = (PACKAGE/'candidate/source_parent_reader.py').read_bytes()
LOADER_RAW = (PACKAGE/'candidate/bound_loader.py').read_bytes()
loader = types.ModuleType('portable_bound_loader')
exec(compile(LOADER_RAW, '<portable-bound-loader>', 'exec'), loader.__dict__)
candidate = loader.load_bound(RAW, RAW)
ORIGINAL = (BASE/'originals/source_parent_late_boundary_r4.original.py').read_bytes()
INVENTORY = candidate.function_source((BASE/'candidate/derived/source_parent_inventory_value.py').read_bytes(), 'inventory_value')
DERIVED, CONSTRUCTION = candidate.derive_source(ORIGINAL, INVENTORY)
CONTRACT_COUNTERS = {'source_binding_rejections': 0, 'guarded_constructor_rejections': 0,
                     'new_envelope_cases': 0}


def source_literals(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:result[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):pass
    return result


class SourceConstructionTests(unittest.TestCase):
    def reject(self, call):
        with self.assertRaises(ValueError):call()
        CONTRACT_COUNTERS['source_binding_rejections'] += 1

    def test_loader_binds_actual_compiled_source(self):
        self.assertEqual(candidate.pin(RAW), loader.CONSTRUCTOR_PIN)
        self.assertEqual(candidate.__constructor_loaded_source__, RAW)
        for actual, declared in ((RAW+b'\n', RAW), (RAW[:-1], RAW), (RAW, RAW+b'\n'),
                                 (RAW, b'unrelated implementation'), (RAW.decode(), RAW), (RAW, None)):
            self.reject(lambda a=actual,d=declared:loader.load_bound(a,d))

    def test_source_and_function_pins_are_mandatory(self):
        for original, function in ((ORIGINAL+b'\n',INVENTORY), (ORIGINAL[:-1],INVENTORY),
                                   (ORIGINAL,INVENTORY+b'\n'), (ORIGINAL,INVENTORY[:-1])):
            self.reject(lambda a=original,b=function:candidate.derive_source(a,b))
        again, receipt = candidate.derive_source(ORIGINAL, INVENTORY)
        self.assertEqual((again, receipt), (DERIVED, CONSTRUCTION))
        self.assertTrue(receipt['whole_byte_inverse_verified'])
        self.assertNotEqual(candidate.pin(ORIGINAL), candidate.pin(DERIVED))

    def test_frozen_dependency_contract_and_context(self):
        current = (BASE/'originals/late_boundary.r10.original.py').read_bytes()
        constants = source_literals(current)
        self.assertEqual(candidate.DEPENDENCIES, constants['SOURCE_PARENT_READER_DEPENDENCIES'])
        self.assertEqual(candidate.COMBINATION, constants['SOURCE_PARENT_COMBINATION_SHA256'])
        self.assertEqual(candidate.PACKAGE, constants['SOURCE_PARENT_PACKAGE_SHA256'])
        self.assertEqual(candidate.POLICY, constants['SOURCE_PARENT_POLICY_SHA256'])
        self.assertEqual(candidate.POLICY_ADOPTION, constants['SOURCE_PARENT_POLICY_ADOPTION_SHA256'])
        for altered in ({}, {'unexpected':b''}, {name:b'' for name in candidate.DEPENDENCIES}):
            with self.assertRaises(ValueError):
                candidate.construct(sources=altered, inventory_function=INVENTORY,
                                    read_pinned=lambda row:b'', implementation_source=RAW)
            CONTRACT_COUNTERS['guarded_constructor_rejections'] += 1

    def test_getter_names_and_provenance_are_separate(self):
        parsed = ast.parse(DERIVED)
        top_names = {node.name for node in parsed.body if isinstance(node,ast.FunctionDef)}
        self.assertNotIn('reviewed_source_sha256', top_names)
        self.assertIn('source_parent_historical_data_source_sha256', top_names)
        self.assertIn('source_parent_execution_source_sha256', top_names)
        self.assertNotIn(b"'schema': 'hepta.native-guard.current-property-parent-reader.v1'", DERIVED)
        self.assertNotIn(b"'schema': 'hepta.native-guard.current-inventory-composition.v1'", DERIVED)
        calls = [n for n in ast.walk(parsed) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        self.assertEqual(sum(n.func.id=='source_parent_historical_data_source_sha256' for n in calls),7)
        self.assertEqual(sum(n.func.id=='source_parent_execution_source_sha256' for n in calls),2)
        # Exact old attributes and nested historical getter keep their original roles.
        self.assertIn(b'old.reviewed_source_sha256 = historical_publisher_source_sha256', DERIVED)
        old_literals = source_literals(ORIGINAL)
        new_literals = source_literals(DERIVED)
        self.assertEqual(new_literals['_PROPERTY_INVENTORY_BUILTINS'], old_literals['_PROPERTY_INVENTORY_BUILTINS'])
        self.assertEqual(new_literals['_PROPERTY_CURRENT_INVENTORY_PIN'], candidate.DERIVED_INVENTORY)

    def test_static_closure_excludes_disabled_entries(self):
        original = CONSTRUCTION['original_call_graph']
        derived = CONSTRUCTION['derived_call_graph']
        self.assertEqual((original['reachable_function_count'],original['reachable_class_count']),(55,1))
        self.assertEqual((derived['reachable_function_count'],derived['reachable_class_count']),(56,1))
        for graph in (original,derived):
            self.assertFalse({'main','publish','verify_current'} & set(graph['reachable_names']))
            self.assertTrue(graph['not_a_claim_of_complete_dynamic_IO_metering'])
        for name in candidate.METHODS:
            old_node = ast.parse(candidate.function_source(ORIGINAL,name)).body[0]
            new_node = ast.parse(candidate.function_source(DERIVED,name)).body[0]
            self.assertEqual(ast.dump(old_node,include_attributes=False), ast.dump(new_node,include_attributes=False))

    def test_new_envelope_recomputes_and_preserves_unknown(self):
        # Unit test of envelope transport only; these spies cannot grant any
        # complete-reader, historical-proof, or actual runtime PASS.
        calls=[]
        def spy(*args,**kwargs):
            calls.append((args,kwargs))
            return {'historical_component_qualified':True,'native_terminal':None,
                    'global_unknown_effect_count':None,'original_sender_wait':'UNKNOWN_UNCHANGED'}
        reader = candidate.DerivedSourceParentReader({name:spy for name in candidate.METHODS},
            {'schema':'synthetic-envelope-test','historical_reader_functions_changed':True})
        for _ in range(2):
            result=reader.boundary_from_original(b'unit-only', original_descriptor={},
                combination_sha256='0'*64,package_sha256='1'*64)
            self.assertEqual(result['schema'],'hepta.UNADOPTED.derived-source-parent-result.v1')
            self.assertIsNone(result['historical_result']['global_unknown_effect_count'])
            self.assertIsNone(result['historical_result']['native_terminal'])
            self.assertFalse(result['historical_result_is_old_execution_attestation'])
            self.assertFalse(result['runtime_admission'])
            self.assertFalse(result['production_adopted'])
            self.assertFalse(result['whole_stage_budget_verified'])
            self.assertEqual(result['current_native_case_credit'],0)
            CONTRACT_COUNTERS['new_envelope_cases'] += 1
        self.assertEqual(len(calls),2)
        with self.assertRaises(AttributeError):reader._methods={}
        p=reader.provenance();p['schema']='mutated-copy'
        self.assertNotEqual(reader.provenance(),p)


class WholeModuleInventoryTests(inventory_suite.TopologyDifferentialTests):
    @classmethod
    def setUpClass(cls):
        names=source_literals(ORIGINAL)['_PROPERTY_INVENTORY_BUILTINS']
        self_builtins=__builtins__ if isinstance(__builtins__,dict) else vars(__builtins__)
        def restricted(raw):
            ns={'C':harness.original_common(),'Path':Path,'re':re,'stat':stat,
                '__builtins__':{name:self_builtins[name] for name in names}}
            exec(compile(candidate.function_source(raw,'inventory_value'),'<restricted-property-helper>','exec'),ns)
            return ns['inventory_value']
        cls.original=restricted(ORIGINAL)
        cls.candidate=restricted(DERIVED)
        cls.real=harness.fixtures()

    def test_exact_declared_source_change(self):
        self.assertEqual(candidate.function_source(DERIVED,'inventory_value'),INVENTORY)
        self.assertEqual(candidate.pin(INVENTORY),candidate.DERIVED_INVENTORY)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(SourceConstructionTests),
        unittest.defaultTestLoader.loadTestsFromTestCase(WholeModuleInventoryTests)]))
    report={'schema':'hepta.UNADOPTED.source-parent-portable-tests.v1',
        'state':'PASS' if result.wasSuccessful() else 'FAIL','tests_run':result.testsRun,
        'source_constructor':candidate.pin(RAW),'bound_loader':candidate.pin(LOADER_RAW),
        'derived_source':candidate.pin(DERIVED),'source_contract_cases':CONTRACT_COUNTERS,
        'inventory_differential':inventory_suite.REPORT,
        'synthetic_only':os.environ.get('HEPTA_TOPOLOGY_SYNTHETIC_ONLY')=='1',
        'skips':[{'test':str(t),'reason':why} for t,why in result.skipped],
        'failures':[{'test':str(t),'traceback':tb} for t,tb in result.failures+result.errors],
        'python':sys.version,'platform':platform.platform(),
        'private_complete_reader_test_performed':False,'runtime_admission':False,
        'production_adopted':False,'whole_stage_budget_verified':False}
    text=json.dumps(report,sort_keys=True,ensure_ascii=False,indent=2)+'\n'
    if options.report:
        with options.report.open('x',encoding='utf-8') as output:output.write(text)
    print(text,end='')
    raise SystemExit(0 if result.wasSuccessful() else 1)
