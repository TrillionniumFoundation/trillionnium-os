#!/usr/bin/env python3
"""Pure reviewed source propagation for fixed NEG-03 through NEG-09.

The public API refuses before any callback while FROZEN_INPUTS is None.  A
bound call consumes complete reviewed source originals and returns only source
bytes, proofs and unbound case templates.  It never publishes, imports a phone
actor main, creates a nonce, signals, launches a model, or dispatches a task.

Actual freeze admission, sealed BUILD and four-role READY remain separate
prerequisites at the unchanged physical operator entries.
"""
import ast
import copy
import difflib
import hashlib
import json
from pathlib import PurePosixPath as Path
import re
import types

FROZEN_INPUTS = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-negative-source-binding-r6-03/SOURCE-INPUTS.json', 'bytes': 2537, 'sha256': 'b7cb09d2083e8a055dd4d62f11a54a0bf8ea2ac6b506dc6072f109204f6855ee'}
INPUT_SCHEMA = 'hepta.fc33.negative-source-inputs.v1'
REFERENCE_INDEX = (38297, '9a1138f1a843814588107054057048810183f94ecb29725b46ebc40f8b560bed')
CHAIN_TEMPLATE = (33827, '4c8f32d518c4cf17308f561587eeaf12702b8b9addf0bd8e5ad335a33e941835')
CONSUMER_TEMPLATE = (249798, '016d25b5467c96f96f25f7b2d9d606e40ea18a72421e549d0ab630a01f9c2349')
RUNTIME_PIN = (59400, '270357b7649af61414d31580b3c1eaddc47174bd1bac3c8adfc02934a92c8cf5')
ROOT_MANIFEST_PIN = (51678, '9da8d53ebfba3e11f2406c0a59964923ff4709052fad2d5df3d2eaff8b7ec8a4')
ROOT_SOURCE_PIN = (78567, '53c2e7c26c960d76ac5d3201420d33f13fb06c241d30d40fc7b2b7577e690257')
COMBINATION_SHA = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'
POLICY_SHA = '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
ADOPTION_SHA = '98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'
MATERIALIZER_PIN = (24834, 'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290')
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
P4 = Path('/home/alex/razr60-local-model-v150')
PARENT = 'reference/cpu-negative-capture-generation-final01/package/validation/parent-source-fixtures/'
FAULT = 'reference/physical-fault-final01/package/'
PHYSICAL = 'reference/component-physical-final02/package/'
CPU = 'reference/cpu-cancel-compat-candidate01/package/'
HOST = 'reference/host-five-final01/package/'
HOST06 = 'reference/r7-r3-host-negative/namespace-service-r1/'
HASH = re.compile('[0-9a-f]{64}\\Z')
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    need(type(raw) is bytes, 'complete bytes required')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def exact_pin(raw, pair):
    need(pin(raw) == dict(zip(('bytes', 'sha256'), pair)), 'reviewed complete source pin differs')
    return raw


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate source input key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite source input'))


def absolute(value):
    need(type(value) is str and '\0' not in value, 'canonical absolute source path')
    path = Path(value)
    need(path.is_absolute() and str(path) == value and '..' not in path.parts,
         'canonical absolute source path')
    return path


def relative(value):
    need(type(value) is str and re.fullmatch('[A-Za-z0-9._/-]{1,1024}', value)
         and not value.startswith('/') and all(p not in ('', '.', '..') for p in value.split('/')),
         'closed relative member path')
    return value


def descriptor(row):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'exact source descriptor')
    absolute(row['path'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE
         and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'bounded source descriptor')
    return row


def located(path, raw):
    return {'path': str(absolute(str(path))), **pin(raw)}


class Originals:
    def __init__(self, callback):
        need(callable(callback), 'pinned full9 original reader required')
        self.callback, self.rows, self.total = callback, {}, 0

    def read(self, row, maximum=MAX_FILE):
        descriptor(row)
        need(row['bytes'] <= maximum, 'source-specific byte bound')
        raw = self.callback(dict(row))
        need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'complete original differs')
        old = self.rows.get(row['path'])
        need(old is None or old == (row, raw), 'original changed between reads')
        if old is None:
            self.total += len(raw)
            need(self.total <= MAX_TOTAL, 'source construction pool bound')
            self.rows[row['path']] = (dict(row), raw)
        return raw

    def recheck(self):
        for row, raw in self.rows.values():
            need(self.callback(dict(row)) == raw, 'original changed at final bookend')


def assignment(raw, name):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, 'one explicit source assignment: ' + name)
    return nodes[0]


def literal(raw, name):
    return ast.literal_eval(assignment(raw, name).value)


class Changes:
    def __init__(self, raw):
        self.original, self.text, self.edits = raw, raw.decode(), []

    def once(self, before, after):
        need(type(before) is str and type(after) is str and before != after
             and self.text.count(before) == 1, 'one complete transformation anchor')
        self.text = self.text.replace(before, after, 1)
        self.edits.append({'before': before, 'after': after})

    def rhs(self, name, value, *, expression=False):
        raw = self.text.encode()
        node = assignment(raw, name)
        lines = raw.splitlines(keepends=True)
        start = sum(map(len, lines[:node.lineno-1])) + node.col_offset
        end = sum(map(len, lines[:node.end_lineno-1])) + node.end_col_offset
        value_start = sum(map(len, lines[:node.value.lineno-1])) + node.value.col_offset
        replacement = value if expression else repr(value)
        before, after = raw[start:end].decode(), raw[start:value_start].decode() + replacement
        if before != after:
            self.once(before, after)

    def finish(self):
        raw = self.text.encode()
        compile(raw, '<negative-source-candidate>', 'exec')
        restored = self.text
        for row in reversed(self.edits):
            need(restored.count(row['after']) == 1, 'one inverse anchor')
            restored = restored.replace(row['after'], row['before'], 1)
        need(restored.encode() == self.original, 'whole source byte inverse')
        return raw, {'parent': pin(self.original), 'candidate': pin(raw),
                     'edits': self.edits, 'complete_inverse': True}


def module(raw, name):
    result = types.ModuleType(name)
    result.__file__ = '<pinned-source/' + name + '>'
    exec(compile(raw, result.__file__, 'exec'), result.__dict__)
    return result


def rows(files):
    return [{'path': relative(name), **pin(raw)} for name, raw in sorted(files.items())]


def manifest_members(pool, row, field='files'):
    raw = pool.read(row)
    value = strict(raw)
    members = value[field]
    need(type(members) is list and 0 < len(members) <= 128
         and len({r['path'] for r in members}) == len(members), 'unique complete source manifest')
    root = absolute(row['path']).parent
    files = {}
    for member in members:
        need(type(member) is dict and set(member) == {'path', 'bytes', 'sha256'}, 'exact source member')
        name = relative(member['path'])
        files[name] = pool.read(dict(member, path=str(root / name)))
    return raw, value, files


class References:
    def __init__(self, pool, root):
        self.pool, self.root = pool, absolute(root)
        raw = pool.read({'path': str(self.root / 'REVIEWED-INPUTS.json'),
                         **dict(zip(('bytes', 'sha256'), REFERENCE_INDEX))})
        value = strict(raw)
        need(value['schema'] == 'fc33.negative-operator-reviewed-reference-set.v1'
             and value['historical_git_commit'] == '744fc422a28bd6f505701503bf0d113ab49d4634'
             and value['candidate_sources_are_not_qualification'] is True, 'reviewed reference family')
        members = value['files']
        need(len(members) == 172 and len({r['path'] for r in members}) == 172, 'complete reviewed input inventory')
        self.index = {r['path']: r for r in members}

    def read(self, name):
        relative(name)
        need(name in self.index, 'unreviewed negative source reference')
        return self.pool.read(dict(self.index[name], path=str(self.root / name)))

    def package(self, prefix, leaf='MANIFEST.json', field='files'):
        raw = self.read(prefix + leaf)
        value = strict(raw)
        members = value[field]
        need(type(members) is list and len({r['path'] for r in members}) == len(members), 'reference manifest member identity')
        files = {r['path']: self.read(prefix + relative(r['path'])) for r in members}
        need(rows(files) == sorted(members, key=lambda r: r['path']), 'complete parent package byte match')
        return value, files, raw


def _admit_sources(value, pool):
    keys = {'schema', 'reference_root', 'release_source_chain', 'root_manifest', 'actual_policy',
            'policy_adoption', 'materializer', 'output_root', 'host_neg06_namespace'}
    need(type(value) is dict and set(value) == keys and value['schema'] == INPUT_SCHEMA,
         'exact reviewed negative source input')
    out = absolute(value['output_root'])
    need(out.parent == B and re.fullmatch('fc33-negative-sources-[a-z0-9-]{6,60}', out.name),
         'new explicit project source namespace')
    host_namespace = absolute(value['host_neg06_namespace'])
    need(host_namespace.parent == P4 and re.fullmatch('fc33-neg06-[a-z0-9-]{6,60}', host_namespace.name),
         'existing reviewed P4 destination only')
    source_chain = value['release_source_chain']
    need(type(source_chain) is dict and set(source_chain) == {'constructor', 'inputs'}, 'exact source-chain originals')
    chain_raw = pool.read(source_chain['constructor'])
    need(literal(chain_raw, 'FROZEN_INPUTS') == source_chain['inputs'], 'source-chain constructor must bind these real source inputs')
    inverse = Changes(chain_raw)
    inverse.rhs('FROZEN_INPUTS', None)
    exact_pin(inverse.finish()[0], CHAIN_TEMPLATE)
    chain_inputs_raw = pool.read(source_chain['inputs'])
    chain_inputs = strict(chain_inputs_raw)
    chain = module(chain_raw, 'reviewed_release_source_chain')
    constructed = chain.derive_reviewed_source_chain(chain_inputs_raw, read_pinned=pool.read)
    need(constructed['report']['actual_execution_slots_unbound'] is True
         and constructed['report']['BUILD'] is False and constructed['report']['READY'] is False,
         'source-only chain cannot imply BUILD or READY')
    runtime_row = chain_inputs['consumer']['runtime_package']
    runtime_raw, runtime, runtime_files = manifest_members(pool, runtime_row)
    exact_pin(runtime_raw, RUNTIME_PIN)
    need(runtime['revision'] == 'r10-r1-fc33-native-bound-v3-r6' and len(runtime_files) == 38,
         'exact reviewed R6 runtime graph')
    consumer_raw = constructed['files']['source/release_boundaries.py']
    inverse = Changes(consumer_raw)
    inverse.rhs('PACKAGE_SHA', None)
    exact_pin(inverse.finish()[0], CONSUMER_TEMPLATE)
    need(constructed['consumer_runtime'] == {'runtime_sha256': RUNTIME_PIN[1], 'package_file_count': 38,
         'chain_length': 12, 'role_budget': 42}, 'reviewed R6 counters cannot be inferred from an old graph')
    chain_out = absolute(chain_inputs['output_root'])
    consumer = located(chain_out / 'source/release_boundaries.py', consumer_raw)
    readiness = constructed['source_binding']['readiness']
    need(pool.read(consumer) == consumer_raw and pool.read(readiness) == constructed['files']['source/collect_r10_readiness.py'],
         'actual source-chain publication must match complete constructed sources')
    material = chain_inputs['material']
    combination_raw = pool.read(material['combination'])
    need(pin(combination_raw)['sha256'] == COMBINATION_SHA, 'current reviewed 7969 combination')
    combination = strict(combination_raw)
    config_raw, service_raw = pool.read(material['configuration']), pool.read(material['service'])
    need(pin(config_raw) == combination['configuration'] and pin(service_raw) == combination['service_inputs'],
         'same complete current configuration and service')
    shared_raw, shared, shared_files = manifest_members(pool, material['shared'])
    production = {Path(name).name: raw for name, raw in shared_files.items() if name.startswith('provider/source/')}
    need(len(production) == 15 and len(shared_files) == 17 and
         [{'path': 'production/' + name, **pin(raw)} for name, raw in sorted(production.items())] == combination['production_files'],
         'same complete fifteen-source and shared17 material')
    root_raw, root_manifest, root_files = manifest_members(pool, value['root_manifest'])
    exact_pin(root_raw, ROOT_MANIFEST_PIN)
    coordinator = exact_pin(root_files['source/run_component_root_once.py'], ROOT_SOURCE_PIN)
    need(root_manifest['frozen_component_package_sha256'] == RUNTIME_PIN[1]
         and root_manifest['current_combination_sha256'] == COMBINATION_SHA,
         'root transport belongs to the same reviewed source graph')
    policy_raw, adoption_raw = pool.read(value['actual_policy']), pool.read(value['policy_adoption'])
    need(pin(policy_raw)['sha256'] == POLICY_SHA and pin(adoption_raw)['sha256'] == ADOPTION_SHA,
         'same actual retained policy and explicit adoption originals')
    exact_pin(pool.read(value['materializer']), MATERIALIZER_PIN)
    references = References(pool, value['reference_root'])
    common = module(references.read('candidate/templates/physical-fault/physical_fault_common.py'), 'negative_generation_admission')
    generation = dict(runtime_package=runtime_row, consumer=consumer, readiness=readiness,
        actual_policy=value['actual_policy'], policy_adoption=value['policy_adoption'], combination_sha256=COMBINATION_SHA)
    # The current consumer-pinned pure verifier checks the complete retained
    # parent adoption, actual export, full rule and its one declared delta.
    # That verification grants no BUILD, READY or physical qualification.
    common.generation_inputs(generation, pool)
    return dict(out=out, host_namespace=host_namespace, references=references, production=production,
        material=material, combination=combination, combination_raw=combination_raw,
        config_raw=config_raw, service_raw=service_raw, consumer=consumer, readiness=readiness,
        policy=pin(policy_raw), adoption=value['policy_adoption'], runtime=runtime_row,
        root_manifest=value['root_manifest'], root_files=root_files, root_source=coordinator,
        materializer=value['materializer'], source_chain=source_chain, generation=generation)


def _construct(binding):
    r, out = binding['references'], binding['out']
    production = binding['production']
    production_sha = {name: pin(raw)['sha256'] for name, raw in sorted(production.items())}
    source_pins_raw = enc(production_sha)
    changes, packages = {}, {}

    def changed(label, raw, values, substitutions=()):
        c = Changes(raw)
        for name, value in values.items():
            c.rhs(name, value)
        for before, after in substitutions:
            c.once(before, after)
        body, proof = c.finish()
        changes[label] = proof
        return body

    def generated_descriptor(family, name, raw):
        return located(out / family / name, raw)

    ui_mf, ui, ui_old = r.package(PARENT + 'ui/')
    fault_mf, fault, fault_old = r.package(PARENT + 'fault/', field='runtime_sources')
    component_mf, component, component_old = r.package(PARENT + 'component/')
    need(ui['source/active_runtime_r10.py'] == fault['source/active_runtime_r10.py'], 'one shared original active source')
    active = changed('shared/active_runtime_r10.py', ui['source/active_runtime_r10.py'], {
        'CONSUMER_SHA': binding['consumer']['sha256'], 'READINESS_SHA': binding['readiness']['sha256'],
        'CONFIG_SHA': pin(binding['config_raw'])['sha256'], 'SERVICE_SHA': pin(binding['service_raw'])['sha256'],
        'POLICY_SHA': binding['policy']['sha256'], 'ADOPTION_SHA': binding['adoption']['sha256']})
    observer = r.read('candidate/shared/observe_cancel_phase_r10.py')
    for family in (ui, fault):
        family['source/active_runtime_r10.py'] = active
        family['source/observe_cancel_phase_r10.py'] = observer
        family['source/production-pins.json'] = source_pins_raw
    ui_mf.update(files=rows(ui), revision='fc33-native-v3-source-only',
        parent_candidate_manifest_sha256=pin(ui_old)['sha256'],
        expected_live_policy_sha256=binding['policy']['sha256'],
        reviewed_policy_adoption_sha256=binding['adoption']['sha256'],
        reviewed_boundary_consumer_sha256=binding['consumer']['sha256'],
        reviewed_readiness_sha256=binding['readiness']['sha256'],
        reviewed_component_runtime_manifest_sha256=RUNTIME_PIN[1],
        reviewed_production_source_pins=production_sha,
        reviewed_final_consumer_manifest_sha256=None,
        reviewed_release_source_chain_constructor_sha256=binding['source_chain']['constructor']['sha256'],
        reviewed_release_source_chain_input_sha256=binding['source_chain']['inputs']['sha256'],
        shared_observer_manifest_sha256=None,
        shared_observer_manifest_relationship='one shared active source with six exact dependency literals; separately reviewed observer compatibility',
        reviewed_observer_source_sha256=pin(observer)['sha256'],
        actual_runtime_ready=False, physical_qualification=False)
    ui['MANIFEST.json'] = enc(ui_mf)
    fault_mf.update(runtime_sources=rows(fault), parent_candidate_manifest_sha256=pin(fault_old)['sha256'],
        expected_live_policy_sha256=binding['policy']['sha256'],
        reviewed_policy_adoption_sha256=binding['adoption']['sha256'],
        reviewed_boundary_consumer_sha256=binding['consumer']['sha256'],
        reviewed_readiness_sha256=binding['readiness']['sha256'],
        reviewed_component_runtime_sha256=RUNTIME_PIN[1], actual_task_bound=False,
        reviewed_final_consumer_manifest_sha256=None,
        reviewed_release_source_chain_constructor_sha256=binding['source_chain']['constructor']['sha256'],
        reviewed_release_source_chain_input_sha256=binding['source_chain']['inputs']['sha256'],
        shared_materials_sha256=binding['material']['shared']['sha256'],
        actual_r10_ready_bound=False, physical_case_pass=False)
    fault['MANIFEST.json'] = enc(fault_mf)
    packages.update(ui=ui, fault=fault)
    context = Changes(component['source/component_source_context.py'])
    context.rhs('MATERIALIZER', 'Path(' + repr(binding['materializer']['path']) + ')', expression=True)
    context.rhs('CONSUMER', 'Path(' + repr(binding['consumer']['path']) + ')', expression=True)
    for name, value in {
        'CONSUMER_PIN': (binding['consumer']['bytes'], binding['consumer']['sha256']),
        'READINESS_PIN': (binding['readiness']['bytes'], binding['readiness']['sha256']),
        'RUNTIME_SHA': RUNTIME_PIN[1], 'POLICY_SHA': binding['policy']['sha256'],
        'ADOPTION_SHA': binding['adoption']['sha256'],
        'SOURCE_PINS': {name: (len(production[name]), production_sha[name])
                        for name in literal(component['source/component_source_context.py'], 'SOURCE_PINS')}
    }.items():
        context.rhs(name, value)
    component['source/component_source_context.py'], changes['component/context'] = context.finish()
    component['source/verify_unqualified_geometry_fixture.py'] = r.read('candidate/component/verify_unqualified_geometry_fixture.py')
    original_interface = component['INTERFACE.json']
    old_root = str(B / 'fixed19-comp01-neg03-r7-source-candidate01').encode()
    new_root = str(out / 'component').encode()
    old_runtime = b'683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
    need(original_interface.count(old_root) == 3 and original_interface.count(old_runtime) == 1, 'exact original component interface')
    interface = original_interface.replace(old_root, new_root).replace(old_runtime, RUNTIME_PIN[1].encode())
    need(interface.replace(new_root, old_root).replace(RUNTIME_PIN[1].encode(), old_runtime) == original_interface,
         'complete component interface inverse')
    previous_interface = strict(interface)
    interface_value = copy.deepcopy(previous_interface)
    need((json.dumps(strict(original_interface), ensure_ascii=False, indent=2) + '\n').encode() == original_interface,
         'original ordered interface serializer')
    interface_value['production_sources'] = [located(
        absolute(binding['material']['shared']['path']).parent / 'provider/source' / Path(row['path']).name,
        production[Path(row['path']).name]) for row in previous_interface['production_sources']]
    interface_value['comp01'].update(state='HISTORICAL_DIRECT_REFERENCE_ONLY_NOT_CURRENT_NATIVE_COMPATIBILITY',
        formal_current_route='Actual E2E mapped/native phone.return_hepta with launch, Activity, focus and top-resumed originals',
        current_combination_qualification=False)
    interface_value['neg03']['native_fixture_scope'] = 'Explicit synthetic five-field scope and current full native schema; no actual native scope claimed'
    inverse_interface = copy.deepcopy(interface_value)
    for key in ('production_sources', 'comp01', 'neg03'):
        inverse_interface[key] = previous_interface[key]
    need((json.dumps(inverse_interface, ensure_ascii=False, indent=2) + '\n').encode() == interface,
         'complete production/interface metadata inverse')
    interface = (json.dumps(interface_value, ensure_ascii=False, indent=2) + '\n').encode()
    changes['component/INTERFACE.json'] = {'parent': pin(original_interface), 'candidate': pin(interface),
        'changed_fields': ['three package paths', 'runtime pin', 'production_sources', 'comp01 historical route', 'neg03 synthetic scope'],
        'complete_inverse': True}
    component['INTERFACE.json'] = interface
    component_mf['files'] = rows(component)
    component['MANIFEST.json'] = enc(component_mf)
    packages['component'] = component
    cpu = changed('cpu/cpu_cancel_originals.py', r.read(PARENT + 'cpu/source.original.py'), {
        'UI_PACKAGE_SHA': pin(ui['MANIFEST.json'])['sha256'],
        'OPERATOR_SOURCES': {Path(n).name: pin(b)['sha256'] for n, b in ui.items() if n.startswith('source/')},
        'CONFIG_SHA': pin(binding['config_raw'])['sha256'], 'SERVICE_SHA': pin(binding['service_raw'])['sha256'],
        'POLICY_SHA': binding['policy']['sha256'], 'ADOPTION_SHA': binding['adoption']['sha256']},
        [("provider['source_sha256']=='f42fa1f3268d2a2c00e49610d356b440d1e32722fbe2af877580fb6eb180f712'",
          "provider['source_sha256']==" + repr(production_sha['daily_phone_local.py']))])
    p4 = changed('p4/capture_p4_cancel_originals.py', r.read(PARENT + 'p4/source.original.py'), {
        'REVIEWED_OPERATOR_PACKAGE_SHA256': pin(ui['MANIFEST.json'])['sha256'],
        'REVIEWED_ACTIVE_SOURCE_SHA256': pin(active)['sha256'], 'REVIEWED_CPU_VERIFIER_SOURCE_SHA256': pin(cpu)['sha256']})
    phone_final = {'runtime_package_sha256': RUNTIME_PIN[1], 'consumer_sha256': binding['consumer']['sha256'],
        'readiness_sha256': binding['readiness']['sha256'], 'ui_package_sha256': pin(ui['MANIFEST.json'])['sha256'],
        'active_source_sha256': pin(active)['sha256'], 'cpu_verifier_sha256': pin(cpu)['sha256'],
        'policy_adoption_sha256': binding['adoption']['sha256'], 'live_policy': binding['policy'],
        'configuration_sha256': pin(binding['config_raw'])['sha256'], 'service_inputs_sha256': pin(binding['service_raw'])['sha256']}
    phone = changed('phone/capture_negative_originals.py', r.read(PARENT + 'phone/source.original.py'), {'FINAL_DEPENDENCIES': phone_final})
    for family, name, body in [('cpu', 'cpu_cancel_originals.py', cpu), ('p4', 'capture_p4_cancel_originals.py', p4),
                               ('phone', 'capture_negative_originals.py', phone)]:
        files = {'source/' + name: body}
        files['SOURCE-MANIFEST.json'] = enc({'schema': 'hepta.r10.property-negative-literal-source-package.v1',
            'state': 'SOURCE_PINS_BOUND_ACTUAL_CASE_AND_CAPTURE_NOT_EXECUTED', 'files': rows(files),
            'physical_qualification': False, 'phone_calls': 0, 'model_requests': 0, 'new_nonces': 0})
        packages[family] = files
    sender = r.read('candidate/templates/sender/send_new_native_task_r5_fc33_r6.py')
    sender_source = located(B / 'send_new_native_task_r5_fc33_r6.py', sender)
    need(r.pool.read(sender_source) == sender, 'actual complete reviewed R6 sender publication')
    source_rows = {family: generated_descriptor(family, name, body) for family, name, body in (
        ('cpu', 'source/cpu_cancel_originals.py', cpu), ('phone', 'source/capture_negative_originals.py', phone),
        ('p4', 'source/capture_p4_cancel_originals.py', p4))}
    source_rows.update(sender=sender_source,
        root_transport=located(absolute(binding['root_manifest']['path']).parent / 'source/run_component_root_once.py', binding['root_source']))
    final = {'schema': 'hepta.r10.cpu-negative-final-dependencies.v1',
        'sources': {name: {k: row[k] for k in ('bytes', 'sha256')} for name, row in source_rows.items()},
        'live_policy': binding['policy'], 'ui_package_sha256': pin(ui['MANIFEST.json'])['sha256'],
        'active_sha256': pin(active)['sha256'], 'runtime_package_sha256': RUNTIME_PIN[1],
        'consumer_sha256': binding['consumer']['sha256'], 'readiness_sha256': binding['readiness']['sha256'],
        'policy_adoption_sha256': binding['adoption']['sha256'], 'configuration_sha256': pin(binding['config_raw'])['sha256'],
        'service_inputs_sha256': pin(binding['service_raw'])['sha256'], 'combination_sha256': COMBINATION_SHA}
    negative = changed('closure/negative_originals.py', r.read('candidate/templates/closure/negative_originals.py'), {'FINAL_DEPENDENCIES': final})
    assembly = module(negative, 'bound_negative_source_assembly')
    need(assembly.final_dependencies() == final, 'actual closed source dependency schema')
    assembly.root_source(binding['root_source'], r.read(CPU + 'reference/root-Q2-53b5.original.py'))
    closer = r.read(CPU + 'source/close_cpu_negative.py')
    root = changed('closure/root_cpu_negative.py', r.read(CPU + 'source/root_cpu_negative.py'),
                   {'PURE_MODULES': {'negative_originals': pin(negative), 'close_cpu_negative': pin(closer)}})
    ledger_negative = r.read(CPU + 'source/ledger_prefix_negative.py')
    complete_closure_sources = dict(source_rows)
    for name, reference in {
        'ledger_parent': FAULT + 'reference/ledger_prefix_audit.original.py',
        'business': FAULT + 'reference/collect_business_evidence.original.py',
        'positive_closer': FAULT + 'reference/close_original_r10.original.py',
        'protocol': FAULT + 'reference/original-protocol.json',
        'cleanup': FAULT + 'reference/model_slot_cleanup.py',
        'postconditions': FAULT + 'reference/task_postconditions.py',
        'root_transport_parent': CPU + 'reference/root-Q2-53b5.original.py'
    }.items():
        complete_closure_sources[name] = located(r.root / reference, r.read(reference))
    complete_closure_sources.update(
        ledger_negative=generated_descriptor('closure', 'source/ledger_prefix_negative.py', ledger_negative),
        configuration=binding['material']['configuration'], service=binding['material']['service'])
    need(set(complete_closure_sources) == assembly.SOURCE_NAMES, 'complete current closure source callback interface')
    closure = {'source/negative_originals.py': negative, 'source/root_cpu_negative.py': root,
               'source/close_cpu_negative.py': closer, 'source/ledger_prefix_negative.py': ledger_negative,
               'FINAL-DEPENDENCIES.json': enc(final), 'HOST-PHASE.template.json': r.read(CPU + 'HOST-PHASE.template.json'),
               'CLOSURE-SOURCE-INPUTS.json': enc({'schema': 'hepta.r10.cpu-negative-generated-source-inputs.v1',
                    'dependency_sources': source_rows, 'complete_source_inputs': complete_closure_sources, 'actual_case_plan': None,
                    'root_capture_manifest': binding['root_manifest'], 'phone_calls': 0, 'physical_case_pass': False})}
    closure['SOURCE-MANIFEST.json'] = enc({'schema': 'hepta.r10.cpu-negative-host-closure-source-package.v1',
        'state': 'SOURCE_PINS_BOUND_ACTUAL_CASE_AND_CAPTURE_NOT_EXECUTED', 'files': rows(closure),
        'runtime_sources': rows({n: b for n, b in closure.items() if n.startswith('source/')}),
        'future_dependencies_frozen': True, 'cases': ['NEG-08', 'NEG-09'], 'actual_cases': 0,
        'phone_calls': 0, 'physical_case_pass': False})
    packages['closure'] = closure
    fault_mf, physical_fault, fault_source_old = r.package(FAULT, 'SOURCE-MANIFEST.json')
    physical_fault['source/physical_fault_common.py'] = r.read('candidate/templates/physical-fault/physical_fault_common.py')
    name = 'source/prepare_physical_fault.py'
    physical_fault[name] = changed('physical-fault/' + name, physical_fault[name], {},
        [("S.B/'send_new_native_task_r5.py'", "S.B/'send_new_native_task_r5_fc33_r6.py'")])
    final = {'fault_package_sha256': pin(fault['MANIFEST.json'])['sha256'], 'active_source_sha256': pin(active)['sha256'],
        'runtime_package_sha256': RUNTIME_PIN[1], 'consumer_sha256': binding['consumer']['sha256'],
        'readiness_sha256': binding['readiness']['sha256'], 'policy_adoption_sha256': binding['adoption']['sha256'],
        'combination_sha256': COMBINATION_SHA, 'live_policy': binding['policy']}
    watch = {k: v for k, v in final.items() if k not in ('combination_sha256', 'live_policy')}
    watch['live_policy_sha256'] = final['live_policy']['sha256']
    phone_final = {k: v for k, v in final.items() if k != 'combination_sha256'}
    phone_final.update(fault_verifier_sha256=pin(physical_fault['source/verify_physical_fault.py'])['sha256'],
                      configuration_sha256=pin(binding['config_raw'])['sha256'], service_inputs_sha256=pin(binding['service_raw'])['sha256'])
    for name, value in {'physical_fault_common.py': final, 'watch_physical_fault_once.py': watch,
                        'capture_fault_phone.py': phone_final, 'capture_fault_p4.py': {'sender_sha256': pin(sender)['sha256']}}.items():
        path = 'source/' + name
        need(literal(physical_fault[path], 'FINAL_DEPENDENCIES') is None, 'original unbound source slot')
        substitutions = [("FINAL_DEPENDENCIES['sender_sha256']=='5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'",
                          "FINAL_DEPENDENCIES['sender_sha256']=='f90c6ffbf3278b22bf3a48bf055c5ca1cf43c3073c5cc7a852dd09a4cf2eab73'")] if name == 'capture_fault_p4.py' else ()
        physical_fault[path] = changed('physical-fault/' + path, physical_fault[path],
                                       {'FINAL_DEPENDENCIES': value}, substitutions)
    # The unchanged registered-plan preparer reads this exact source-only
    # dependency contract.  It is generated here from retained actual source
    # descriptors, not copied from a historical freeze/READY receipt.
    freeze_input = dict(schema='hepta.physical-fault.freeze-inputs.v1',
        out=str(out / 'physical-fault'), runtime_package=binding['runtime'],
        fault_package=generated_descriptor('fault', 'MANIFEST.json', fault['MANIFEST.json']),
        consumer=binding['consumer'], readiness=binding['readiness'],
        actual_policy=binding['generation']['actual_policy'], policy_adoption=binding['adoption'],
        combination_sha256=COMBINATION_SHA)
    physical_fault['FREEZE-INPUT.original.json'] = enc(freeze_input)
    physical_fault['CANDIDATE-SOURCE-MANIFEST.original.json'] = fault_source_old
    physical_fault['FINALIZATION.json'] = enc({
        'schema': 'hepta.physical-fault.source-finalization.v1',
        'state': 'EXACT_SOURCE_DEPENDENCIES_BOUND_BY_REVIEWED_CONSTRUCTOR',
        'source_constructor_input': FROZEN_INPUTS, 'final_dependencies': final,
        'legacy_freezer_not_executed': True, 'actual_runtime_freeze_admission': None,
        'actual_BUILD': None, 'actual_READY': None, 'phone_calls': 0,
        'physical_case_pass': False, 'whole_case_pass': False})
    fault_mf.update(files=rows(physical_fault), final_dependencies=final,
        state='ACTUAL_DEPENDENCIES_FROZEN_NO_CASE_EXECUTED', physical_case_pass=False,
        source_only_constructor_replaces_legacy_freeze_entry=True)
    physical_fault['SOURCE-MANIFEST.json'] = enc(fault_mf)
    packages['physical-fault'] = physical_fault
    physical_mf, physical, physical_old = r.package(PHYSICAL, 'SOURCE-MANIFEST.json')
    physical['source/physical_component_common.py'] = r.read('candidate/templates/physical-component/physical_component_common.py')
    physical_mf.update(files=rows(physical), current_component_cases=['NEG-03'],
        formal_COMP01_route='E2E production native return; historical direct helper is not current qualification',
        physical_case_pass=False)
    physical['SOURCE-MANIFEST.json'] = enc(physical_mf)
    packages['physical-component'] = physical
    host_mf, host, unused = r.package(HOST, 'SOURCE-MANIFEST.json')
    support = changed('host-five/lifecycle_support.py', host['source/lifecycle_support.py'], {
        'CONFIG_SHA': pin(binding['config_raw'])['sha256'], 'SERVICE_SHA': pin(binding['service_raw'])['sha256'],
        'PRODUCTION_PINS': production_sha})
    host['source/lifecycle_support.py'] = support
    host['source/run_fault_cases.py'] = changed('host-five/run_fault_cases.py', host['source/run_fault_cases.py'],
        {'SUPPORT_SHA': pin(support)['sha256']}, [
            ("ready['source_sha256']=='f42fa1f3268d2a2c00e49610d356b440d1e32722fbe2af877580fb6eb180f712'",
             "ready['source_sha256']==" + repr(production_sha['daily_phone_local.py']))])
    host_mf.update(files=rows(host), physical_case_pass=False, actual_current_cases=0)
    host['SOURCE-MANIFEST.json'] = enc(host_mf)
    packages['host-five'] = host
    packages['host-neg06'] = _host06(binding, r, changed)
    # Current executable plans contain no scope, labels, nonce, BUILD, READY or
    # target process identity.  Root binds each original once after real gates.
    plans = _unbound_plans(packages, binding)
    files = {family + '/' + name: raw for family, package in packages.items() for name, raw in package.items()}
    files.update({'plans/' + name: enc(value) for name, value in plans.items()})
    for name, raw in files.items():
        relative(name)
        if name.endswith('.py'):
            compile(raw, '<source-only/' + name + '>', 'exec')
    need(len(files) <= 256 and sum(map(len, files.values())) <= 32 * 1024 * 1024, 'bounded complete source candidate family')
    return {'files': files, 'changes': changes, 'packages': {name: rows(package) for name, package in packages.items()},
            'report': {'schema': 'hepta.fc33.negative-source-construction.v1',
                'state': 'SOURCE_ONLY_ACTUAL_PHYSICAL_PLANS_UNBOUND', 'combination_sha256': COMBINATION_SHA,
                'runtime_package_sha256': RUNTIME_PIN[1], 'production_sources': 15, 'runtime_files': 38,
                'new_native_scopes': 0, 'new_nonces': 0, 'phone_calls': 0, 'model_calls': 0,
                'actual_freeze_admission': None, 'actual_BUILD': None, 'actual_READY': None,
                'physical_cases_executed': [], 'host_cases_executed': [], 'fixed19_credit': 0,
                'all_source_inverses_exact': True, 'original_signal_cancel_and_transport_bodies_unchanged': True,
                'formal_COMP01_uses_E2E_native_return': True}}


def _host06(binding, references, changed):
    config, service = binding['config_raw'], binding['service_raw']
    production = binding['production']
    client = references.read(HOST + 'reference/tool_client_r6.py')
    protocol = references.read(FAULT + 'reference/original-protocol.json')
    seal = references.pool.read(binding['material']['source_seal'])
    inputs = {'provider/source/' + name: raw for name, raw in production.items()}
    inputs.update({'provider/SOURCE-SEAL.json': seal, 'combination.json': binding['combination_raw'],
        'production-config.json': config, 'production-service.json': service, 'client/tool_client_r6.py': client,
        'protocol.json': protocol, 'original-protocol.json': protocol})
    input_manifest = enc({'schema': 'hepta.fc33.neg06.namespace-source-inputs.v1',
        'all_inputs_are_source_or_explicit_synthetic_fixture': True,
        'files': [{'name': name, **pin(raw)} for name, raw in sorted(inputs.items())],
        'phone_calls': 0, 'physical_qualification': False})
    runner = changed('host-neg06/service_negative_runner.py', references.read(HOST06 + 'service_negative_runner.py'), {
        'SEAL_SHA': pin(seal)['sha256'], 'COMBO_SHA': COMBINATION_SHA,
        'COMBO_CANONICAL': pin(canonical(binding['combination']))['sha256'], 'PROTOCOL_SHA': pin(protocol)['sha256']}, [
        ("ready['source_sha256']=='92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3'",
         "ready['source_sha256']==" + repr(pin(production['daily_phone_local.py'])['sha256'])),
        ("'cases':['NEG-06','NEG-14']", "'cases':['NEG-06']"),
        ("'all_13_source_pins_verified':True", "'all_15_source_pins_verified':True"),
        ("x['id'] in ('NEG-06','NEG-14')", "x['id']=='NEG-06'"),
        ("[('NEG-06',neg06),('NEG-14',neg14)]", "[('NEG-06',neg06)]"),
        ('Original NEG06/14 host_isolated requirements only;', 'Original NEG06 host_isolated requirements only;')])
    outer = Changes(references.read(HOST06 + 'execute_namespace_once.py'))
    outer.rhs('BASE', 'Path(' + repr(str(binding['host_namespace'])) + ')', expression=True)
    outer.rhs('HARNESS', "BASE/'source'", expression=True)
    outer.rhs('INPUTS', "BASE/'inputs'", expression=True)
    outer.rhs('MANIFEST_SHA', pin(input_manifest)['sha256'])
    outer_raw, proof = outer.finish()
    # Keep this proof as a complete original inverse inside the source package.
    files = {'source/execute_namespace_once.py': outer_raw, 'source/service_negative_runner.py': runner,
        'source/fixture_server.py': references.read(HOST06 + 'fixture_server.py'),
        'OUTER-SOURCE-DERIVATION.json': enc(proof), 'inputs/MANIFEST.json': input_manifest}
    files.update({'inputs/' + name: raw for name, raw in inputs.items()})
    files['SOURCE-MANIFEST.json'] = enc({'schema': 'hepta.fc33.neg06.host-source-package.v1',
        'state': 'SOURCE_ONLY_NOT_EXECUTED', 'files': rows(files), 'publication_namespace': str(binding['host_namespace']),
        'case': 'NEG-06', 'required_protocol_layer': 'host_isolated', 'phone_calls': 0, 'real_model_requests': 0,
        'actual_namespace_execution': None, 'bound_real_server_cleanup_qualified': False,
        'no_namespace_free_fallback': True, 'source_pin_generation_does_not_qualify_case': True})
    return files


def _unbound_plans(packages, binding):
    plans = {}
    shared = {'schema': 'hepta.fc33.negative-root-execution-template.v1', 'actual_plan': None,
        'actual_freeze_admission': None, 'actual_sealed_BUILD': None, 'actual_four_role_READY': None,
        'registered_owner_request': None, 'nonce': None, 'previous_closed_selection': None,
        'exact_preserved_draft': None, 'fresh_owned_label': None, 'actual_scope': None,
        'automatic_retry': False, 'root_is_only_phone_dispatcher': True,
        'combination_sha256': COMBINATION_SHA, 'runtime_package_sha256': RUNTIME_PIN[1]}
    routes = {
        'NEG-03': ('physical-component', 'source/run_physical_component_once.py',
                   ['same-source six-axis synthetic fixture', 'actual live baseline', 'one rotation', 'guard refusal', 'one exact restore', 'complete original closer']),
        'NEG-04': ('physical-fault', 'source/run_physical_fault_once.py',
                   ['original watch armed', 'one fresh Send', 'zero-dispatch identity recheck', 'one owned carrier pidfd SIGTERM', 'full terminal and cleanup closure']),
        'NEG-05': ('physical-fault', 'source/run_physical_fault_once.py',
                   ['original watch armed', 'one fresh Send', 'first effect independent public observation', 'one owned carrier pidfd SIGTERM', 'unknown remains unknown and no replay']),
        'NEG-06': ('host-neg06', 'source/execute_namespace_once.py',
                   ['fresh owned host namespace', 'one deterministic held HTTP request', 'original bounded timeout', 'zero dispatch', 'direct child wait and original process-group absence']),
        'NEG-07': ('physical-fault', 'source/run_physical_fault_once.py',
                   ['original watch armed', 'one fresh Send', 'one exact worker pidfd SIGSTOP', 'original result deadline', 'durable four-file pre-late fence', 'late original result', 'unchanged terminal and at-most-one effect']),
        'NEG-08': ('ui', 'source/cancel_native_once_r10.py',
                   ['reuse only the pinned preserved-UI route and shell methods', 'one fresh Send', 'original model active and zero dispatch', 'one selected-task UI Cancel', 'phone and P4 full original archives', 'independent CPU and native closure']),
        'NEG-09': ('ui', 'source/cancel_native_once_r10.py',
                   ['reuse only the pinned preserved-UI route and shell methods', 'one fresh Send', 'one independently confirmed original effect', 'explicit operator-only navigation to Cancel UI', 'one selected-task UI Cancel', 'no provider follow-up', 'phone and P4 full original archives', 'independent CPU and native closure'])}
    for case, (family, entry, phases) in routes.items():
        value = copy.deepcopy(shared)
        value.update(case_id=case, entry_source=located(binding['out'] / family / entry, packages[family][entry]),
                     ordered_original_phases=phases, case_qualified=False, actual_argv=None,
                     host_isolated_required=case in ('NEG-04', 'NEG-05', 'NEG-06', 'NEG-07', 'NEG-08', 'NEG-09'),
                     physical_native_task_required=case in ('NEG-04', 'NEG-05', 'NEG-07', 'NEG-08', 'NEG-09'),
                     external_display_test_is_fixture_only=case == 'NEG-03')
        plans[case + '.template.json'] = value
    return plans


def derive_negative_sources(inputs_raw, *, read_pinned):
    need(FROZEN_INPUTS is not None, 'UNBOUND_NEGATIVE_SOURCE_INPUTS_NO_IO')
    descriptor(FROZEN_INPUTS)
    need(pin(inputs_raw) == {k: FROZEN_INPUTS[k] for k in ('bytes', 'sha256')}, 'exact reviewed negative source input')
    pool = Originals(read_pinned)
    need(pool.read(FROZEN_INPUTS) == inputs_raw, 'original source construction input')
    result = _construct(_admit_sources(strict(inputs_raw), pool))
    pool.recheck()
    result['report'].update(original_count=len(pool.rows), original_bytes=pool.total,
                            complete_originals_rechecked=True)
    return result


if __name__ == '__main__':
    raise SystemExit('UNBOUND source-construction API only; Root supplies actual admission and dispatch')
