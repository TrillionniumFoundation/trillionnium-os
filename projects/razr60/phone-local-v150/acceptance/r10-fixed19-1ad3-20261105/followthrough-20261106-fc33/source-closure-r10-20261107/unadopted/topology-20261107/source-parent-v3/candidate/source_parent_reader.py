"""UNADOPTED complete source-parent reader with separate execution identity.

This is an offline construction candidate. Historical publisher hashes remain
data anchors, while the derived module, constructor, and helper have their own
identities. No frozen source, receipt, original global, budget, or admission
policy is modified. Results use a new envelope and never assert that the old
implementation executed unmodified.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys
import types

ORIGINAL_SOURCE = {'bytes': 153138, 'sha256': '27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4'}
ORIGINAL_COMMON = {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}
ORIGINAL_INVENTORY = {'bytes': 3788, 'sha256': '086dedcdc7ac8d1627e1c2592ed7a9f130a4395dd4b27e9bc86a512c91af06f1'}
DERIVED_INVENTORY = {'bytes': 3827, 'sha256': '0356d2bd56da36267a72bfb732125eb8807dc6ff32c47789ba8cbc1b523e7f51'}
COMBINATION = '02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'
PACKAGE = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'
POLICY = '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
POLICY_ADOPTION = '98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'
REFERENCE = 'reference/source_parent_late_boundary_r4.py'
METHODS = ('boundary_from_original', 'closed_boundary_originals', 'require_failed_ancestor_tail')

# Byte-for-byte dependency pins from the frozen current source_parent_reader.
DEPENDENCIES = {
    'reference/attempt05-AFTER-INVENTORY.original.json': {'bytes': 664638, 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'},
    'reference/attempt05-CLOSURE.original.json': {'bytes': 164095, 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'},
    'reference/attempt05-SIDE-PROOF.original.json': {'bytes': 4650, 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'},
    'reference/component_common_r5.py': {'bytes': 18133, 'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'},
    'reference/diag02-AFTER-INVENTORY.original.json': {'bytes': 1031582, 'sha256': '10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d'},
    'reference/diag02-CLOSURE.original.json': {'bytes': 253127, 'sha256': 'e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035'},
    'reference/diag02-SIDE-PROOF.original.json': {'bytes': 8439, 'sha256': 'a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd'},
    'reference/environment_parent_late_boundary_r6.py': {'bytes': 53502, 'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'},
    'reference/non_native_attempt05.py': {'bytes': 19740, 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'},
    'reference/non_native_diag02.py': {'bytes': 29504, 'sha256': '296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6'},
    'reference/policy_parent_late_boundary_r4.py': {'bytes': 35730, 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'},
    'reference/property_parent_late_boundary_r7.py': {'bytes': 62434, 'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'},
    'reference/retained_unstarted_stage_final02.py': {'bytes': 62662, 'sha256': 'bc6faf1c7ae2b7e3d44be3d4fe19e4272073073f8df283397ef37c177ca25850'},
    REFERENCE: ORIGINAL_SOURCE,
    'source/component_common.py': ORIGINAL_COMMON,
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    need(type(raw) is bytes, 'constructor requires exact immutable bytes')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def function_source(raw, name):
    source = raw.decode('utf-8', 'strict')
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(nodes) == 1, 'one exact top-level function: ' + name)
    node = nodes[0]
    return ''.join(source.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).encode('utf-8')


def call_graph(raw):
    """Conservative module-name/reference graph; dynamic edges are explicit."""
    tree = ast.parse(raw.decode('utf-8', 'strict'))
    definitions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    edges = {name: sorted({n.id for n in ast.walk(node) if isinstance(n, ast.Name)} & set(definitions))
             for name, node in definitions.items()}
    seen = set()
    pending = list(METHODS)
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        pending.extend(edges[name])
    return {'entry_points': list(METHODS), 'reachable_names': sorted(seen),
            'reachable_count': len(seen),
            'reachable_function_count': sum(isinstance(definitions[name], ast.FunctionDef) for name in seen),
            'reachable_class_count': sum(isinstance(definitions[name], ast.ClassDef) for name in seen),
            'edges': {name: edges[name] for name in sorted(seen)},
            'static_only': True,
            'dynamic_edges': ['fresh property-parent reader methods',
                              'fresh environment/policy-parent reader methods',
                              'fresh sidebranch verify_sidebranch and preservation',
                              'retained-stage verify_retained_unstarted_stage',
                              'caller-supplied exact prior-inventory reader'],
            'not_a_claim_of_complete_dynamic_IO_metering': True}


def derive_source(original, inventory_function):
    need(pin(original) == ORIGINAL_SOURCE, 'exact historical source-parent bytes before derivation')
    need(pin(inventory_function) == DERIVED_INVENTORY, 'fixed derived inventory function')
    old_inventory = function_source(original, 'inventory_value')
    need(pin(old_inventory) == ORIGINAL_INVENTORY, 'exact historical inventory function')
    old_getter = function_source(original, 'reviewed_source_sha256')
    new_getter = b'''def source_parent_historical_data_source_sha256():
    # A data publisher anchor, never this derived execution identity.
    raw = globals().get('__historical_source_parent_bytes__')
    C.need(type(raw) is bytes and len(raw) == 153138
           and C.sha(raw) == '27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4',
           'exact historical source-parent data anchor differs')
    return '27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4'


def source_parent_execution_source_sha256():
    raw = globals().get('__derived_source_parent_bytes__')
    expected = globals().get('__derived_source_parent_descriptor__')
    C.need(type(raw) is bytes and type(expected) is dict
           and set(expected) == {'bytes', 'sha256'}
           and C.descriptor(raw) == expected,
           'actual derived source-parent execution bytes differ')
    return expected['sha256']
'''
    changes = []
    current = original

    def replace(label, old, new):
        nonlocal current
        old = old.encode() if isinstance(old, str) else old
        new = new.encode() if isinstance(new, str) else new
        need(current.count(old) == 1 and new not in current, 'one reversible derivation site: ' + label)
        current = current.replace(old, new, 1)
        changes.append((label, old, new))

    replace('separate-historical-and-execution-getters', old_getter, new_getter)
    # AST identifies unqualified getter calls only. Attributes on exact nested
    # historical modules and JSON field names remain untouched.
    source = current.decode('utf-8')
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line.encode('utf-8')))
    nodes = [n for n in ast.walk(ast.parse(source))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == 'reviewed_source_sha256']
    need(len(nodes) == 9, 'exact historical publisher getter call-site count')
    renamed = current
    rename_spans = []
    for node in sorted(nodes, key=lambda n: (n.func.lineno, n.func.col_offset), reverse=True):
        a = offsets[node.func.lineno - 1] + node.func.col_offset
        b = offsets[node.func.end_lineno - 1] + node.func.end_col_offset
        need(renamed[a:b] == b'reviewed_source_sha256', 'exact getter name span')
        renamed = renamed[:a] + b'source_parent_historical_data_source_sha256' + renamed[b:]
        rename_spans.append([a, b])
    # One whole-byte step permits a deterministic inverse without token
    # rewriting unrelated names or the nested property reader's local getter.
    replace('nine-historical-data-anchor-call-sites', current, renamed)
    replace('inventory-root-prefix-predicate', old_inventory, inventory_function)
    replace('property-helper-new-pin',
            "_PROPERTY_CURRENT_INVENTORY_PIN = " + repr(ORIGINAL_INVENTORY),
            "_PROPERTY_CURRENT_INVENTORY_PIN = " + repr(DERIVED_INVENTORY))
    replace('property-composition-execution-source',
            '    current_source = source_parent_historical_data_source_sha256()\n',
            '    current_source = source_parent_execution_source_sha256()\n')
    replace('sidebranch-composition-execution-source',
            "        'current_composing_source_sha256': source_parent_historical_data_source_sha256(),\n",
            "        'current_composing_source_sha256': source_parent_execution_source_sha256(),\n")
    replace('sidebranch-composition-new-schema',
            "'schema': 'hepta.native-guard.current-inventory-composition.v1'",
            "'schema': 'hepta.UNADOPTED.derived-source-parent-sidebranch-composition.v1'")
    replace('property-composition-new-schema',
            "'schema': 'hepta.native-guard.current-property-parent-reader.v1'",
            "'schema': 'hepta.UNADOPTED.derived-source-parent-property-reader.v1'")
    replace('property-composition-new-mode',
            "'mode': 'CURRENT_R8_MEMBERSHIP_WITH_BYTE_EXACT_R7_ORIGINAL'",
            "'mode': 'UNADOPTED_DERIVED_SOURCE_PARENT_WITH_BYTE_EXACT_R7_ORIGINAL'")
    replace('property-helper-new-module-name',
            "'__name__': 'current_r8_property_parent_inventory'",
            "'__name__': 'UNADOPTED_derived_source_parent_property_inventory'")
    reverse = current
    for label, old, new in reversed(changes):
        need(reverse.count(new) == 1, 'unique whole-byte inverse: ' + label)
        reverse = reverse.replace(new, old, 1)
    need(reverse == original, 'whole-byte inverse recovers every frozen source byte')
    compile(current, '<UNADOPTED-derived-source-parent-construction>', 'exec')
    return current, {'original_source': pin(original), 'derived_source': pin(current),
        'original_inventory_function': pin(old_inventory), 'derived_inventory_function': pin(inventory_function),
        'replacements': [{'site': label, 'old': pin(old), 'new': pin(new)} for label, old, new in changes],
        'getter_call_count': len(nodes), 'getter_byte_spans_before_rename': list(reversed(rename_spans)),
        'whole_byte_inverse_verified': True, 'original_call_graph': call_graph(original),
        'derived_call_graph': call_graph(current)}


class DerivedSourceParentReader:
    """Three immutable entry bindings returning a new, explicit result schema."""
    __slots__ = ('_methods', '_provenance')

    def __init__(self, methods, provenance):
        need(set(methods) == set(METHODS) and all(callable(v) for v in methods.values()),
             'three exact derived reader methods required')
        object.__setattr__(self, '_methods', types.MappingProxyType(dict(methods)))
        object.__setattr__(self, '_provenance', encoded(provenance))

    def __setattr__(self, name, value):
        raise AttributeError('derived source-parent reader is immutable')

    def provenance(self):
        return json.loads(self._provenance)

    def _result(self, name, args, kwargs):
        # Recompute the complete validation on every call. Nothing is cached.
        historical_result = self._methods[name](*args, **kwargs)
        return {'schema': 'hepta.UNADOPTED.derived-source-parent-result.v1',
                'method': name, 'historical_result': historical_result,
                'execution_provenance': self.provenance(),
                'historical_result_is_old_execution_attestation': False,
                'production_adopted': False, 'runtime_admission': False,
                'current_native_case_credit': 0, 'whole_stage_budget_verified': False}

    def boundary_from_original(self, raw, *, original_descriptor, combination_sha256, package_sha256):
        return self._result('boundary_from_original', (raw,), dict(original_descriptor=original_descriptor,
            combination_sha256=combination_sha256, package_sha256=package_sha256))

    def closed_boundary_originals(self, raw, inventory_raw, closure_raw, *, original_descriptor,
                                 combination_sha256, package_sha256):
        return self._result('closed_boundary_originals', (raw, inventory_raw, closure_raw),
            dict(original_descriptor=original_descriptor, combination_sha256=combination_sha256,
                 package_sha256=package_sha256))

    def require_failed_ancestor_tail(self, values):
        return self._result('require_failed_ancestor_tail', (values,), {})


def construct(*, sources, inventory_function, read_pinned, implementation_source):
    """Pure source construction; supplied original reader is an explicit boundary.

    The separately pinned loader must bind implementation_source to the exact
    bytes used to compile this constructor. This callable is offline only and
    cannot establish phone read freshness, full I/O accounting, or adoption.
    """
    need(type(sources) is dict and set(sources) == set(DEPENDENCIES), 'exact fifteen historical source dependencies')
    for name, expected in DEPENDENCIES.items():
        need(pin(sources[name]) == expected, 'exact historical dependency pin: ' + name)
    need(callable(read_pinned), 'explicit retained-original reader required')
    need(type(implementation_source) is bytes
         and implementation_source == globals().get('__constructor_loaded_source__'),
         'declared constructor source must equal actual bound compiled bytes')
    identity = pin(implementation_source)
    original = sources[REFERENCE]
    derived, transformation = derive_source(original, inventory_function)
    derived_pin = pin(derived)
    overlay = dict(sources)
    # Unlike exact-source-parent-reader.v1, this slot identifies new code.
    # The unchanged source-parent reference remains a historical data anchor.
    overlay['source/late_boundary.py'] = derived
    present = 'component_common' in sys.modules
    saved = sys.modules.get('component_common')
    old_path = sys.path[:]
    old_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        common = types.ModuleType('component_common')
        common.__file__ = '<exact-source-parent-common:' + ORIGINAL_COMMON['sha256'] + '>'
        common.__reviewed_source_sha256__ = ORIGINAL_COMMON['sha256']
        sys.modules['component_common'] = common
        exec(compile(sources['source/component_common.py'], common.__file__, 'exec'), common.__dict__)
        selected = types.ModuleType('UNADOPTED_derived_source_parent_' + derived_pin['sha256'][:16])
        selected.__file__ = '<UNADOPTED-derived-source-parent:sha256=' + derived_pin['sha256'] + '>'
        selected.__historical_source_parent_bytes__ = original
        selected.__derived_source_parent_bytes__ = derived
        selected.__derived_source_parent_descriptor__ = derived_pin
        selected.__reviewed_package_sources__ = overlay
        selected.__retained_stage_read_pinned__ = read_pinned
        exec(compile(derived, selected.__file__, 'exec'), selected.__dict__)
        need(selected.C is common
             and '__reviewed_source_sha256__' not in selected.__dict__
             and 'reviewed_source_sha256' not in selected.__dict__
             and selected.source_parent_historical_data_source_sha256() == ORIGINAL_SOURCE['sha256']
             and selected.source_parent_execution_source_sha256() == derived_pin['sha256']
             and selected.REVIEWED_CURRENT_COMBINATION_SHA256 == COMBINATION
             and selected.REVIEWED_CURRENT_POLICY_SHA256 == POLICY
             and selected.REVIEWED_CURRENT_POLICY_ADOPTION_SHA256 == POLICY_ADOPTION
             and selected.MAX_CHAIN == 11, 'distinct derived execution and unchanged historical data identities')
        need(selected.__reviewed_package_sources__['source/late_boundary.py'] == derived
             and selected.__reviewed_package_sources__[REFERENCE] == original,
             'derived execution overlay and historical reference must remain separate')
        for name in METHODS:
            need(getattr(selected, name).__globals__ is selected.__dict__, 'fresh derived method globals: ' + name)
        for name in ('main', 'publish', 'verify_current'):
            selected.__dict__.pop(name, None)
        provenance = {'schema': 'hepta.UNADOPTED.derived-source-parent-reader.v1',
            'constructor_source': identity, 'historical_publisher_data_source': dict(ORIGINAL_SOURCE),
            'actual_derived_execution_source': derived_pin, 'common_source': dict(ORIGINAL_COMMON),
            'source_dependency_pins': {k: dict(v) for k, v in DEPENDENCIES.items()},
            'historical_combination_sha256': COMBINATION, 'historical_package_sha256': PACKAGE,
            'historical_policy_sha256': POLICY, 'historical_policy_adoption_sha256': POLICY_ADOPTION,
            'module_name': selected.__name__, 'module_file': selected.__file__,
            'fresh_derived_module_globals': True, 'original_source_bytes_changed': False,
            'historical_reader_functions_changed': True, 'historical_publisher_data_identity_changed': False,
            'old_source_slot_overlay': False, 'source_slot_contains_actual_derived_bytes': True,
            'nested_property_reader_composes_derived_helper': True,
            'nested_property_composition_has_new_schema_and_helper_pin': True,
            'inherited_nested_module_compositions_retained': True,
            'preexisting_external_module_globals_modified': False,
            'source_construction_and_historical_data_validation_only': True,
            'input_provider': 'explicit caller-supplied retained-stage original reader',
            'input_provider_implementation_attested_by_constructor': False,
            'validation_result_cache': False, 'live_observation_cache': False,
            'disabled_entries': ['main', 'publish', 'verify_current'], 'methods': list(METHODS),
            'transformation': transformation, 'production_adopted': False,
            'runtime_admission': False, 'current_native_case_credit': 0,
            'complete_production_IO_metering_verified': False, 'whole_stage_budget_verified': False}
        return DerivedSourceParentReader({name: getattr(selected, name) for name in METHODS}, provenance)
    finally:
        sys.path[:] = old_path
        sys.dont_write_bytecode = old_dwb
        if present:
            sys.modules['component_common'] = saved
        else:
            sys.modules.pop('component_common', None)
