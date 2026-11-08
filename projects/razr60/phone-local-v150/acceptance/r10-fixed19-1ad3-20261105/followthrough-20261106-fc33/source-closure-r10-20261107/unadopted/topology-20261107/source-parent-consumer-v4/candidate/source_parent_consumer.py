"""Unadopted current-consumer integration for the separately identified v3 reader.

The exact outer source-parent record, full9, outcome, closure and chain guards
execute in a new derived module. Historical data identities remain data anchors;
new reader envelopes are explicitly checked before their data is consumed.
No frozen module, source, receipt, runtime selection, budget or admission changes.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
import types

FROZEN_CURRENT_SOURCE = {'bytes': 259866, 'sha256': 'f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7'}
V3_CONSTRUCTOR = {'bytes': 19589, 'sha256': '8f1eeb66110127ee295d356b3f365ea209969c689c6a80bfdb0ad1520658fd42'}
V3_LOADER = {'bytes': 1023, 'sha256': '845404b6ea78bd209c4cdf05d6c87453bda9ded4d46d6d42c6bd83757527a5ca'}
COMMON = {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}
ORIGINAL_INVENTORY = {'bytes': 3788, 'sha256': '086dedcdc7ac8d1627e1c2592ed7a9f130a4395dd4b27e9bc86a512c91af06f1'}
DERIVED_INVENTORY = {'bytes': 3827, 'sha256': '0356d2bd56da36267a72bfb732125eb8807dc6ff32c47789ba8cbc1b523e7f51'}
METHODS = ('source_parent_boundary_from_original', 'source_parent_closed_boundary_originals',
           'require_failed_ancestor_tail', 'boundary_from_original', 'closed_boundary_originals', 'inventory_value')
UNCHANGED_GUARDS = ('reviewed_source_parent_records', '_source_parent_original', 'exact_descriptor',
                    'current_context', 'source_parent_boundary_from_original',
                    'source_parent_closed_boundary_originals', 'require_failed_ancestor_tail')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    need(type(raw) is bytes, 'exact immutable source bytes required')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def function_source(raw, name):
    text = raw.decode('utf-8', 'strict')
    found = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(found) == 1, 'one exact top-level function: ' + name)
    node = found[0]
    return ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).encode()


def call_graph(raw):
    tree = ast.parse(raw)
    nodes = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    edges = {name: sorted({n.id for n in ast.walk(node) if isinstance(n, ast.Name)} & set(nodes))
             for name, node in nodes.items()}
    seen = set(); pending = list(METHODS)
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name); pending.extend(edges[name])
    return {'entry_points': list(METHODS), 'reachable_names': sorted(seen),
            'reachable_function_count': sum(isinstance(nodes[n], ast.FunctionDef) for n in seen),
            'reachable_class_count': sum(isinstance(nodes[n], ast.ClassDef) for n in seen),
            'edges': {name: edges[name] for name in sorted(seen)},
            'static_name_reference_overapproximation': True,
            'dynamic_edges': ['fresh bound v3 constructor and reader methods',
                              'unchanged non-source-parent historical dispatch readers',
                              'explicit retained-stage original callback'],
            'not_full_production_IO_metering': True}


NEW_FACTORY = b'''def source_parent_reader():
    # This is a new selector contract; never exact-source-parent-reader.v1.
    factory = globals().get('__UNADOPTED_source_parent_reader_factory__')
    expected = globals().get('__UNADOPTED_source_parent_expected_provenance__')
    C.need(callable(factory) and type(expected) is bytes,
           'bound derived source-parent factory and complete provenance required')
    reader = factory()
    C.need(C.encoded(reader.provenance()) == expected,
           'actual derived source-parent construction provenance differs')
    return reader


def consume_source_parent_envelope(envelope, method):
    # Code identity is checked independently of historical data and outcome.
    C.need(type(envelope) is dict and set(envelope) == {
        'schema', 'method', 'historical_result', 'execution_provenance',
        'historical_result_is_old_execution_attestation', 'production_adopted',
        'runtime_admission', 'current_native_case_credit', 'whole_stage_budget_verified'},
        'exact derived source-parent result envelope required')
    C.need(method in ('boundary_from_original', 'closed_boundary_originals',
                      'require_failed_ancestor_tail')
           and envelope['schema'] == 'hepta.UNADOPTED.derived-source-parent-result.v1'
           and envelope['method'] == method,
           'derived source-parent result method or schema differs')
    C.need(envelope['historical_result_is_old_execution_attestation'] is False
           and envelope['production_adopted'] is False and envelope['runtime_admission'] is False
           and type(envelope['current_native_case_credit']) is int
           and envelope['current_native_case_credit'] == 0
           and envelope['whole_stage_budget_verified'] is False,
           'derived source-parent result cannot promote history, adoption, budget or current credit')
    expected = globals().get('__UNADOPTED_source_parent_expected_provenance__')
    C.need(type(expected) is bytes and type(envelope['execution_provenance']) is dict
           and C.encoded(envelope['execution_provenance']) == expected,
           'derived source-parent result execution provenance differs')
    result = envelope['historical_result']
    if method == 'boundary_from_original':
        C.need(type(result) is dict, 'derived boundary data projection must be an object')
    elif method == 'closed_boundary_originals':
        C.need(type(result) is tuple and len(result) == 3
               and all(type(value) is dict for value in result),
               'derived closure data projection must be the original three-object tuple')
    else:
        C.need(result is None, 'derived full-tail data projection must preserve the original None result')
    return result
'''

NEW_IDENTITY = b'''def consumer_frozen_data_source_sha256():
    # The frozen R10 publisher is a historical DATA anchor, not executed code.
    raw = globals().get('__frozen_current_data_source__')
    C.need(type(raw) is bytes and len(raw) == 259866
           and C.sha(raw) == 'f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7',
           'exact frozen current historical data anchor differs')
    return 'f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7'


def consumer_execution_source_sha256():
    raw = globals().get('__derived_consumer_source__')
    expected = globals().get('__derived_consumer_source_descriptor__')
    C.need(type(raw) is bytes and type(expected) is dict and set(expected) == {'bytes', 'sha256'}
           and C.descriptor(raw) == expected, 'actual derived current consumer bytes differ')
    return expected['sha256']
'''


def derive_source(original, inventory_function):
    need(pin(original) == FROZEN_CURRENT_SOURCE, 'exact frozen current source before consumer derivation')
    need(pin(inventory_function) == DERIVED_INVENTORY, 'exact v1 current/v3 historical inventory candidate')
    original_inventory = function_source(original, 'inventory_value')
    need(pin(original_inventory) == ORIGINAL_INVENTORY, 'exact current inventory before derivation')
    current = original; changes = []

    def replace(site, old, new):
        nonlocal current
        old = old.encode() if isinstance(old, str) else old
        new = new.encode() if isinstance(new, str) else new
        need(current.count(old) == 1 and new not in current, 'one reversible consumer site: ' + site)
        current = current.replace(old, new, 1); changes.append((site, old, new))

    replace('new-explicit-reader-selector-and-envelope-consumer',
            function_source(original, 'source_parent_reader'), NEW_FACTORY)
    replace('separate-frozen-data-and-new-execution-identities',
            function_source(original, 'reviewed_source_sha256'), NEW_IDENTITY)
    text = current.decode(); lines = text.splitlines(keepends=True); offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line.encode()))
    nodes = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == 'reviewed_source_sha256']
    need(len(nodes) == 10, 'exact ten frozen-current publisher call sites')
    renamed = current
    for node in sorted(nodes, key=lambda n: (n.func.lineno, n.func.col_offset), reverse=True):
        a = offsets[node.func.lineno - 1] + node.func.col_offset
        b = offsets[node.func.end_lineno - 1] + node.func.end_col_offset
        need(renamed[a:b] == b'reviewed_source_sha256', 'exact frozen-current publisher name span')
        renamed = renamed[:a] + b'consumer_frozen_data_source_sha256' + renamed[b:]
    replace('ten-frozen-publisher-data-anchor-calls', current, renamed)
    replace('current-inventory-root-prefix-predicate', original_inventory, inventory_function)
    replace('current-property-helper-new-pin',
            '_PROPERTY_CURRENT_INVENTORY_PIN = ' + repr(ORIGINAL_INVENTORY),
            '_PROPERTY_CURRENT_INVENTORY_PIN = ' + repr(DERIVED_INVENTORY))
    replace('property-composition-execution-identity',
            '    current_source = consumer_frozen_data_source_sha256()\n',
            '    current_source = consumer_execution_source_sha256()\n')
    replace('sidebranch-composition-execution-identity',
            "        'current_composing_source_sha256': consumer_frozen_data_source_sha256(),\n",
            "        'current_composing_source_sha256': consumer_execution_source_sha256(),\n")
    replace('property-composition-new-schema',
            "'schema': 'hepta.native-guard.current-property-parent-reader.v1'",
            "'schema': 'hepta.UNADOPTED.consumer-property-parent-reader.v1'")
    replace('sidebranch-composition-new-schema',
            "'schema': 'hepta.native-guard.current-inventory-composition.v1'",
            "'schema': 'hepta.UNADOPTED.consumer-sidebranch-composition.v1'")
    sites = [
        ('outer-boundary-consumes-new-envelope',
         "    value = source_parent_reader().boundary_from_original(raw, original_descriptor=original_descriptor,\n"
         "        combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)\n",
         "    value = consume_source_parent_envelope(source_parent_reader().boundary_from_original(\n"
         "        raw, original_descriptor=original_descriptor, combination_sha256=SOURCE_PARENT_COMBINATION_SHA256,\n"
         "        package_sha256=SOURCE_PARENT_PACKAGE_SHA256), 'boundary_from_original')\n"),
        ('outer-closure-consumes-new-envelope',
         "    checked, inventory, closure = source_parent_reader().closed_boundary_originals(\n"
         "        raw, inventory_raw, closure_raw, original_descriptor=original_descriptor,\n"
         "        combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)\n",
         "    checked, inventory, closure = consume_source_parent_envelope(source_parent_reader().closed_boundary_originals(\n"
         "        raw, inventory_raw, closure_raw, original_descriptor=original_descriptor,\n"
         "        combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256),\n"
         "        'closed_boundary_originals')\n"),
        ('tail-prefix-consumes-new-envelope',
         "        checked = old.boundary_from_original(raw, original_descriptor=record['boundary'],\n"
         "            combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)\n",
         "        checked = consume_source_parent_envelope(old.boundary_from_original(\n"
         "            raw, original_descriptor=record['boundary'], combination_sha256=SOURCE_PARENT_COMBINATION_SHA256,\n"
         "            package_sha256=SOURCE_PARENT_PACKAGE_SHA256), 'boundary_from_original')\n"),
        ('tail-check-consumes-new-envelope',
         "    old.require_failed_ancestor_tail(history)\n",
         "    consume_source_parent_envelope(old.require_failed_ancestor_tail(history), 'require_failed_ancestor_tail')\n"),
    ]
    for site, old, new in sites:
        replace(site, old, new)
    reverse = current
    for site, old, new in reversed(changes):
        need(reverse.count(new) == 1, 'unique consumer inverse: ' + site)
        reverse = reverse.replace(new, old, 1)
    need(reverse == original, 'consumer inverse recovers every original frozen byte')
    guard_pins = {}
    for name in ('reviewed_source_parent_records', '_source_parent_original', 'exact_descriptor',
                 'current_context', 'boundary_from_original', 'closed_boundary_originals'):
        before = function_source(original, name); after = function_source(current, name)
        need(before == after, 'outer record/full9/dispatch guard body must stay byte-exact: ' + name)
        guard_pins[name] = pin(before)
    # Within the three consuming functions only the four explicit calls differ.
    for name in ('source_parent_boundary_from_original', 'source_parent_closed_boundary_originals',
                 'require_failed_ancestor_tail'):
        before = function_source(original, name); after = function_source(current, name)
        restored = after
        for site, old, new in reversed(sites):
            old = old.encode(); new = new.encode()
            if new in restored:
                need(restored.count(new) == 1, 'one guarded consumer call: ' + site)
                restored = restored.replace(new, old, 1)
        need(restored == before, 'consumer guard body changed outside explicit envelope consumption: ' + name)
        guard_pins[name] = {'original': pin(before), 'derived': pin(after),
                            'only_explicit_result_consumption_changed': True}
    compile(current, '<UNADOPTED-current-source-parent-consumer>', 'exec')
    return current, {'frozen_source': pin(original), 'derived_source': pin(current),
        'whole_byte_inverse_verified': True, 'frozen_publisher_call_count': len(nodes),
        'original_current_inventory_function': pin(original_inventory),
        'derived_current_inventory_function': pin(inventory_function),
        'guard_function_pins': guard_pins,
        'replacements': [{'site': site, 'original': pin(old), 'derived': pin(new)}
                         for site, old, new in changes],
        'original_call_graph': call_graph(original), 'derived_call_graph': call_graph(current)}


class GuardedSourceParentConsumer:
    __slots__ = ('_methods', '_provenance')

    def __init__(self, methods, provenance):
        need(set(methods) == set(METHODS) and all(callable(x) for x in methods.values()),
             'six exact current consumer, dispatch and inventory entries')
        object.__setattr__(self, '_methods', types.MappingProxyType(dict(methods)))
        object.__setattr__(self, '_provenance', encoded(provenance))

    def __setattr__(self, name, value):
        raise AttributeError('guarded source-parent consumer is immutable')

    def provenance(self):
        return json.loads(self._provenance)

    def _result(self, name, args, kwargs):
        result = self._methods[name](*args, **kwargs)
        return {'schema': 'hepta.UNADOPTED.guarded-source-parent-consumer-result.v1',
                'method': name, 'guarded_historical_result': result,
                'consumer_execution_provenance': self.provenance(),
                'historical_result_is_old_execution_attestation': False,
                'production_adopted': False, 'runtime_admission': False,
                'current_native_case_credit': 0, 'whole_stage_budget_verified': False}

    def source_parent_boundary_from_original(self, raw, *, original_descriptor):
        return self._result('source_parent_boundary_from_original', (raw,),
                            dict(original_descriptor=original_descriptor))

    def source_parent_closed_boundary_originals(self, raw, inventory_raw, closure_raw, *, original_descriptor):
        return self._result('source_parent_closed_boundary_originals', (raw, inventory_raw, closure_raw),
                            dict(original_descriptor=original_descriptor))

    def require_failed_ancestor_tail(self, values):
        return self._result('require_failed_ancestor_tail', (values,), {})

    def inventory_value(self, value):
        return self._result('inventory_value', (value,), {})

    def boundary_from_original(self, raw, *, original_descriptor, combination_sha256, package_sha256):
        return self._result('boundary_from_original', (raw,), dict(original_descriptor=original_descriptor,
            combination_sha256=combination_sha256, package_sha256=package_sha256))

    def closed_boundary_originals(self, raw, inventory_raw, closure_raw, *, original_descriptor,
                                 combination_sha256, package_sha256):
        return self._result('closed_boundary_originals', (raw, inventory_raw, closure_raw),
            dict(original_descriptor=original_descriptor, combination_sha256=combination_sha256,
                 package_sha256=package_sha256))


def construct(*, current_source, sources, v3_constructor_source, v3_loader_source,
              inventory_function, read_pinned, implementation_source):
    need(type(implementation_source) is bytes
         and implementation_source == globals().get('__constructor_loaded_source__'),
         'declared consumer constructor source must equal actual bound compiled bytes')
    need(pin(current_source) == FROZEN_CURRENT_SOURCE, 'exact frozen current consumer source')
    need(pin(v3_constructor_source) == V3_CONSTRUCTOR and pin(v3_loader_source) == V3_LOADER,
         'exact separately bound v3 constructor and loader sources')
    need(type(sources) is dict and callable(read_pinned), 'explicit dependency bytes and original reader required')
    supplied = dict(sources)
    loader = types.ModuleType('UNADOPTED_v4_exact_v3_bound_loader')
    loader.__file__ = '<UNADOPTED-v3-bound-loader:' + V3_LOADER['sha256'] + '>'
    exec(compile(v3_loader_source, loader.__file__, 'exec'), loader.__dict__)
    producer = loader.load_bound(v3_constructor_source, v3_constructor_source)

    def fresh_reader():
        # No result cache: validate source pins and construct fresh globals on
        # every consumer selection; all historical validation then runs anew.
        return producer.construct(sources=dict(supplied), inventory_function=inventory_function,
            read_pinned=read_pinned, implementation_source=v3_constructor_source)

    expected_provenance = fresh_reader().provenance()
    expected_provenance_raw = encoded(expected_provenance)
    derived, transformation = derive_source(current_source, inventory_function); derived_pin = pin(derived)
    need(pin(supplied['source/component_common.py']) == COMMON, 'same exact current component common source')
    overlay = dict(supplied); overlay['source/late_boundary.py'] = derived
    old_path = sys.path[:]; old_dwb = sys.dont_write_bytecode
    present = 'component_common' in sys.modules; saved = sys.modules.get('component_common')
    try:
        sys.dont_write_bytecode = True
        common = types.ModuleType('component_common')
        common.__file__ = '<exact-component-common:' + COMMON['sha256'] + '>'
        common.__reviewed_source_sha256__ = COMMON['sha256']
        sys.modules['component_common'] = common
        exec(compile(supplied['source/component_common.py'], common.__file__, 'exec'), common.__dict__)
        selected = types.ModuleType('UNADOPTED_guarded_source_parent_consumer_' + derived_pin['sha256'][:16])
        selected.__file__ = '<UNADOPTED-guarded-source-parent-consumer:' + derived_pin['sha256'] + '>'
        selected.__frozen_current_data_source__ = current_source
        selected.__derived_consumer_source__ = derived
        selected.__derived_consumer_source_descriptor__ = derived_pin
        selected.__UNADOPTED_source_parent_reader_factory__ = fresh_reader
        selected.__UNADOPTED_source_parent_expected_provenance__ = expected_provenance_raw
        selected.__reviewed_package_sources__ = overlay
        selected.__retained_stage_read_pinned__ = read_pinned
        exec(compile(derived, selected.__file__, 'exec'), selected.__dict__)
        need(selected.C is common and '__reviewed_source_sha256__' not in selected.__dict__
             and 'reviewed_source_sha256' not in selected.__dict__
             and selected.consumer_frozen_data_source_sha256() == FROZEN_CURRENT_SOURCE['sha256']
             and selected.consumer_execution_source_sha256() == derived_pin['sha256'],
             'separate frozen publisher data and actual new consumer execution identities')
        need(selected.__reviewed_package_sources__['source/late_boundary.py'] == derived,
             'current consumer source slot must contain its actual derived bytes')
        for name in METHODS:
            need(getattr(selected, name).__globals__ is selected.__dict__, 'fresh current consumer globals: ' + name)
        for name in ('main', 'publish', 'verify_current', 'chain_originals', 'retired_originals',
                     'current_inventory', 'verify_current_package'):
            selected.__dict__.pop(name, None)
        provenance = {'schema': 'hepta.UNADOPTED.guarded-source-parent-consumer.v1',
            'constructor_source': pin(implementation_source), 'frozen_current_publisher_data_source': dict(FROZEN_CURRENT_SOURCE),
            'actual_derived_consumer_execution_source': derived_pin, 'common_source': dict(COMMON),
            'v3_bound_loader_source': dict(V3_LOADER), 'v3_reader_provenance': expected_provenance,
            'module_name': selected.__name__, 'module_file': selected.__file__,
            'fresh_derived_module_globals': True, 'frozen_source_bytes_changed': False,
            'historical_publisher_data_identity_changed': False, 'old_execution_receipt_reused': False,
            'source_parent_result_envelope_explicitly_consumed': True,
            'current_inventory_candidate_selected': True, 'outer_exact_record_full9_guard_preserved': True,
            'source_construction_provenance_bound_once': True, 'source_construction_per_selection': True,
            'validation_result_cache': False, 'live_observation_cache': False,
            'preexisting_external_module_globals_modified': False,
            'inherited_fresh_nested_module_compositions_retained': True,
            'source_slot_contains_actual_derived_bytes': True,
            'methods': list(METHODS), 'transformation': transformation,
            'disabled_entries': ['main', 'publish', 'verify_current', 'chain_originals', 'retired_originals',
                                 'current_inventory', 'verify_current_package'],
            'original_input_provider_implementation_attested': False,
            'new_current_prefix_qualification_verified': False,
            'production_adopted': False, 'runtime_admission': False, 'current_native_case_credit': 0,
            'complete_production_IO_metering_verified': False, 'whole_stage_budget_verified': False}
        return GuardedSourceParentConsumer({name: getattr(selected, name) for name in METHODS}, provenance)
    finally:
        sys.path[:] = old_path; sys.dont_write_bytecode = old_dwb
        if present:
            sys.modules['component_common'] = saved
        else:
            sys.modules.pop('component_common', None)
