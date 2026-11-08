#!/usr/bin/env python3
"""Portable constructor, actual consumer-gate and in-module inventory tests."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import types
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--base', type=Path, required=True)
parser.add_argument('--v3', type=Path)
parser.add_argument('--report', type=Path)
options, _ = parser.parse_known_args()
BASE = options.base.resolve(); V3 = options.v3.resolve() if options.v3 else BASE / 'source-parent-v3'
sys.path.insert(0, str(BASE / 'tests'))
import harness
import test_inventory_topology as inventory_suite

RAW = (PACKAGE / 'candidate/source_parent_consumer.py').read_bytes()
LOADER_RAW = (PACKAGE / 'candidate/bound_loader.py').read_bytes()
loader = types.ModuleType('portable_consumer_loader')
exec(compile(LOADER_RAW, '<portable-consumer-loader>', 'exec'), loader.__dict__)
candidate = loader.load_bound(RAW, RAW)
ORIGINAL = (BASE / 'originals/late_boundary.r10.original.py').read_bytes()
INVENTORY = candidate.function_source((BASE / 'candidate/derived/source_parent_inventory_value.py').read_bytes(), 'inventory_value')
DERIVED, CONSTRUCTION = candidate.derive_source(ORIGINAL, INVENTORY)
V3_RAW = (V3 / 'candidate/source_parent_reader.py').read_bytes()
V3_LOADER = (V3 / 'candidate/bound_loader.py').read_bytes()
COUNTERS = {'source_binding_rejections': 0, 'constructor_rejections': 0,
            'consumer_envelope_rejections': 0, 'consumer_envelope_acceptances': 0, 'outer_envelope_calls': 0}


def literals(raw):
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        values[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass
    return values


def consumer_gate():
    provenance = {'schema': 'EXPLICIT_SYNTHETIC_GATE_UNIT_ONLY', 'source_hash': '1' * 64}
    common = harness.original_common()
    common.encoded = candidate.encoded
    ns = {'C': common,
          '__UNADOPTED_source_parent_expected_provenance__': candidate.encoded(provenance)}
    exec(compile(candidate.function_source(DERIVED, 'consume_source_parent_envelope'),
                 '<actual-new-envelope-consumer>', 'exec'), ns)
    return ns['consume_source_parent_envelope'], provenance


def envelope(method, result, provenance):
    return {'schema': 'hepta.UNADOPTED.derived-source-parent-result.v1', 'method': method,
            'historical_result': result, 'execution_provenance': provenance,
            'historical_result_is_old_execution_attestation': False, 'production_adopted': False,
            'runtime_admission': False, 'current_native_case_credit': 0, 'whole_stage_budget_verified': False}


class ConsumerSourceTests(unittest.TestCase):
    def reject(self, fn):
        with self.assertRaises(ValueError):
            fn()
        COUNTERS['source_binding_rejections'] += 1

    def test_actual_constructor_source_bound_before_compile(self):
        self.assertEqual(candidate.pin(RAW), loader.CONSTRUCTOR_PIN)
        self.assertEqual(candidate.__constructor_loaded_source__, RAW)
        for actual, declared in ((RAW + b'\n', RAW), (RAW[:-1], RAW), (RAW, RAW + b'\n'),
                                 (RAW, b'unrelated code'), (RAW.decode(), RAW), (RAW, None)):
            self.reject(lambda a=actual, b=declared: loader.load_bound(a, b))

    def test_deterministic_inverse_and_source_pins(self):
        self.assertEqual(candidate.derive_source(ORIGINAL, INVENTORY), (DERIVED, CONSTRUCTION))
        self.assertTrue(CONSTRUCTION['whole_byte_inverse_verified'])
        self.assertNotEqual(candidate.pin(ORIGINAL), candidate.pin(DERIVED))
        for source, function in ((ORIGINAL + b'\n', INVENTORY), (ORIGINAL[:-1], INVENTORY),
                                 (ORIGINAL, INVENTORY + b'\n'), (ORIGINAL, INVENTORY[:-1])):
            self.reject(lambda a=source, b=function: candidate.derive_source(a, b))

    def test_outer_record_and_dispatch_guard_bodies_preserved(self):
        for name in ('reviewed_source_parent_records', '_source_parent_original', 'exact_descriptor',
                     'current_context', 'boundary_from_original', 'closed_boundary_originals'):
            self.assertEqual(candidate.function_source(ORIGINAL, name), candidate.function_source(DERIVED, name))
        for name in ('source_parent_boundary_from_original', 'source_parent_closed_boundary_originals',
                     'require_failed_ancestor_tail'):
            self.assertTrue(CONSTRUCTION['guard_function_pins'][name]['only_explicit_result_consumption_changed'])
        selected = [node for node in ast.walk(ast.parse(DERIVED)) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'consume_source_parent_envelope']
        self.assertEqual(len(selected), 4)

    def test_separate_data_and_execution_identities(self):
        parsed = ast.parse(DERIVED)
        names = {node.name for node in parsed.body if isinstance(node, ast.FunctionDef)}
        self.assertNotIn('reviewed_source_sha256', names)
        self.assertTrue({'consumer_frozen_data_source_sha256', 'consumer_execution_source_sha256'} <= names)
        calls = [node.func.id for node in ast.walk(parsed) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertEqual(calls.count('consumer_frozen_data_source_sha256'), 8)
        self.assertEqual(calls.count('consumer_execution_source_sha256'), 2)
        self.assertNotIn(b"'schema': 'hepta.native-guard.exact-source-parent-reader.v1'", DERIVED)
        self.assertNotIn(b"'schema': 'hepta.native-guard.current-inventory-composition.v1'", DERIVED)
        self.assertNotIn(b"'schema': 'hepta.native-guard.current-property-parent-reader.v1'", DERIVED)
        before, after = literals(ORIGINAL), literals(DERIVED)
        self.assertEqual(after['SOURCE_PARENT_RECORDS'], before['SOURCE_PARENT_RECORDS'])
        self.assertEqual(after['SOURCE_PARENT_READER_DEPENDENCIES'], before['SOURCE_PARENT_READER_DEPENDENCIES'])
        self.assertEqual(after['_PROPERTY_CURRENT_INVENTORY_PIN'], candidate.DERIVED_INVENTORY)
        self.assertEqual(after['_PROPERTY_INVENTORY_BUILTINS'], before['_PROPERTY_INVENTORY_BUILTINS'])

    def test_no_disabled_mutation_entry_in_static_closure(self):
        for key in ('original_call_graph', 'derived_call_graph'):
            graph = CONSTRUCTION[key]
            self.assertFalse({'main', 'publish', 'verify_current', 'chain_originals', 'retired_originals',
                              'current_inventory', 'verify_current_package'} & set(graph['reachable_names']))
            self.assertTrue(graph['not_full_production_IO_metering'])

    def test_constructor_rejects_unbound_inputs_before_original_provider(self):
        calls = []
        params = dict(current_source=ORIGINAL, sources={}, v3_constructor_source=V3_RAW,
                      v3_loader_source=V3_LOADER, inventory_function=INVENTORY,
                      read_pinned=lambda row: calls.append(row), implementation_source=RAW)
        changes = ({'implementation_source': RAW + b'\n'}, {'current_source': ORIGINAL + b'\n'},
                   {'v3_constructor_source': V3_RAW + b'\n'}, {'v3_loader_source': V3_LOADER + b'\n'},
                   {'read_pinned': None}, {}, {'sources': {'unexpected': b''}})
        for change in changes:
            with self.assertRaises(ValueError):
                candidate.construct(**{**params, **change})
            COUNTERS['constructor_rejections'] += 1
        self.assertEqual(calls, [])

    def test_actual_new_consumer_envelope_gate(self):
        gate, provenance = consumer_gate()
        cases = [('boundary_from_original', {'UNKNOWN': None}),
                 ('closed_boundary_originals', ({}, {}, {})), ('require_failed_ancestor_tail', None)]
        for method, value in cases:
            self.assertEqual(gate(envelope(method, value, provenance), method), value)
            COUNTERS['consumer_envelope_acceptances'] += 1
        base = envelope('boundary_from_original', {}, provenance)
        changes = [('schema', 'old'), ('method', 'closed_boundary_originals'),
                   ('historical_result_is_old_execution_attestation', True), ('production_adopted', True),
                   ('runtime_admission', True), ('current_native_case_credit', False),
                   ('current_native_case_credit', 1), ('whole_stage_budget_verified', True),
                   ('execution_provenance', {**provenance, 'source_hash': '2' * 64}), ('historical_result', [])]
        for key, value in changes:
            bad = copy.deepcopy(base); bad[key] = value
            with self.assertRaises(ValueError):
                gate(bad, 'boundary_from_original')
            COUNTERS['consumer_envelope_rejections'] += 1
        for bad in (None, {**base, 'extra': None}, {k: v for k, v in base.items() if k != 'execution_provenance'},
                    envelope('closed_boundary_originals', [{}, {}, {}], provenance),
                    envelope('closed_boundary_originals', ({}, {}), provenance),
                    envelope('require_failed_ancestor_tail', {}, provenance)):
            method = bad['method'] if isinstance(bad, dict) and 'method' in bad else 'boundary_from_original'
            with self.assertRaises(ValueError):
                gate(bad, method)
            COUNTERS['consumer_envelope_rejections'] += 1

    def test_outer_envelope_reexecutes_without_credit_promotion(self):
        calls = []
        def spy(*args, **kwargs):
            calls.append((args, kwargs))
            return {'historical_component_qualified': True, 'unknown_effects': None}
        consumer = candidate.GuardedSourceParentConsumer({name: spy for name in candidate.METHODS},
            {'schema': 'EXPLICIT_SYNTHETIC_TRANSPORT_ONLY'})
        for _ in range(2):
            result = consumer.source_parent_boundary_from_original(b'synthetic', original_descriptor={})
            self.assertFalse(result['production_adopted']); self.assertFalse(result['runtime_admission'])
            self.assertFalse(result['historical_result_is_old_execution_attestation'])
            self.assertFalse(result['whole_stage_budget_verified']); self.assertEqual(result['current_native_case_credit'], 0)
            self.assertIsNone(result['guarded_historical_result']['unknown_effects'])
            COUNTERS['outer_envelope_calls'] += 1
        self.assertEqual(len(calls), 2)
        with self.assertRaises(AttributeError):
            consumer._methods = {}
        p = consumer.provenance(); p['schema'] = 'changed'
        self.assertNotEqual(p, consumer.provenance())


class CurrentInventoryTests(inventory_suite.TopologyDifferentialTests):
    @classmethod
    def setUpClass(cls):
        allowed = literals(ORIGINAL)['_PROPERTY_INVENTORY_BUILTINS']
        builtins = __builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)
        def restricted(raw):
            ns = {'C': harness.original_common(), 'Path': Path, 're': re, 'stat': stat,
                  '__builtins__': {key: builtins[key] for key in allowed}}
            exec(compile(candidate.function_source(raw, 'inventory_value'), '<actual-derived-current-inventory>', 'exec'), ns)
            return ns['inventory_value']
        cls.original = restricted(ORIGINAL); cls.candidate = restricted(DERIVED); cls.real = harness.fixtures()

    def test_exact_declared_source_change(self):
        self.assertEqual(candidate.function_source(DERIVED, 'inventory_value'), INVENTORY)
        self.assertEqual(candidate.pin(INVENTORY), candidate.DERIVED_INVENTORY)


if __name__ == '__main__':
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(ConsumerSourceTests),
                               unittest.defaultTestLoader.loadTestsFromTestCase(CurrentInventoryTests)])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {'schema': 'hepta.UNADOPTED.consumer-portable-tests.v4',
              'state': 'PASS' if result.wasSuccessful() else 'FAIL', 'tests': result.testsRun,
              'skipped': len(result.skipped), 'failures': len(result.failures), 'errors': len(result.errors),
              'counters': COUNTERS, 'constructor_source': candidate.pin(RAW), 'bound_loader_source': candidate.pin(LOADER_RAW),
              'frozen_current_source': candidate.pin(ORIGINAL), 'derived_current_source': candidate.pin(DERIVED),
              'inventory_suite_counters': {key: inventory_suite.REPORT[key] for key in
                  ('inventory_comparisons', 'topology_comparisons', 'accepted', 'rejected')},
              'private_complete_consumer_fixture_claimed_by_CI': False, 'production_adopted': False,
              'runtime_admission': False, 'current_native_case_credit': 0,
              'complete_production_IO_metering_verified': False, 'whole_stage_budget_verified': False}
    raw = candidate.encoded(report)
    if options.report:
        with options.report.open('xb') as stream:
            stream.write(raw)
    sys.stdout.buffer.write(raw)
    raise SystemExit(0 if result.wasSuccessful() else 1)
