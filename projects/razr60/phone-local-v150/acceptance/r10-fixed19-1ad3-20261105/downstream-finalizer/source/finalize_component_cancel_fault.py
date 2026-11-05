#!/usr/bin/env python3
"""Create three source packages from exact old sources and already verified R8 pins.

This program does not import or execute product sources, verify a policy adoption
from its complete evidence, admit a live runtime, operate a phone, or award a case.
Default invocation performs no input reads. Explicit execution creates one fresh
private output tree; incomplete output is retained and is never retried in place.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
PLAN_SCHEMA = 'hepta.r8.downstream-source-finalization-plan.v1'
BASES = {
    'component': ('fixed19-comp01-neg03-r7-source-candidate01', 1469,
        '669b344d40cda3412f0eae806b1db53585342d07eee154fd766913ae889b59ce',
        'hepta.fixed19.comp01-neg03.source-package.v1', 'files'),
    'cancel': ('cancel-native-r10-r1-host-candidate05', 4262,
        '65720e417594205b45172fe509f3419d607d3dbf1e579b2a17faa8b40315ca10',
        'hepta.r10.native-cancel-operator-package.v1', 'files'),
    'fault': ('fault-signal-r10-r1-operator-final05', 2517,
        'fff728422175cc90a9e818b3b32da873c70c95de269994ebe9c097b770cfc619',
        'hepta.r10.signal-fault-package.v1', 'runtime_sources'),
}
OLD = {
    'runtime': '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c',
    'consumer': 'a791a7493fe8544aa44b910dd627f405f71678a048f9df94df91529a54fdf703',
    'readiness': '345723406df0c523ab55b167bb52f5ceb9432d387ffe3b4aa5b1e5442465e392',
    'policy': '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7',
    'adoption': 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
    'active': 'f1a68fcc420799a7221019afdcda046a8d297b23d674e1e2642e888df26635dd',
    'context': '2f5e6169f66017bee29b32a4f05d9cb8a0936e01c36b7b1f59aa015ba1ffb02d',
}
MATERIALIZER = (24834, 'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290')
ACTUAL_LIMITS = {'runtime_manifest': 262144, 'consumer': 131072,
    'readiness': 65536, 'final_consumer_manifest': 262144, 'policy': 8*1024*1024,
    'adoption': 16*1024*1024, 'materializer': 65536}
COMPONENT_MEMBERS = {'COMP01-PLAN.template.json', 'NEG03-PLAN.template.json',
    'INTERFACE.json', 'reference/host_negative_runner.original.py',
    'reference/original-protocol.json', 'source/component_source_context.py',
    'source/prepare_direct_return_component.py', 'source/verify_unqualified_geometry_fixture.py'}
CANCEL_MEMBERS = {'source/'+name for name in ('active_runtime_r10.py',
    'cancel_native_once_r10.py', 'cancel_phase.py', 'decode_client_state.py',
    'native_journal_audit.py', 'observe_cancel_phase_r10.py',
    'production-pins.json', 'reviewed_page_projection.py')}
FAULT_MEMBERS = (CANCEL_MEMBERS - {'source/cancel_native_once_r10.py',
    'source/decode_client_state.py'}) | {'source/observe_carrier_r10.py',
    'source/signal_fault_once_r10.py'}
MEMBERS = {'component': COMPONENT_MEMBERS, 'cancel': CANCEL_MEMBERS, 'fault': FAULT_MEMBERS}
META_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
    'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
        allow_nan=False)+'\n').encode('utf-8')


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def descriptor(path, raw):
    return {'path': str(path), **pin(raw)}


def metadata(st):
    return tuple(getattr(st, name) for name in META_FIELDS)


def absolute(path):
    need(isinstance(path, str) and 0 < len(path.encode('utf-8')) <= 4096
        and '\x00' not in path, 'bounded path string required')
    result = Path(path)
    need(result.is_absolute() and str(result) == path and '..' not in result.parts,
        'canonical absolute path required')
    return result


def relpath(path):
    need(isinstance(path, str) and path, 'relative member required')
    result = Path(path)
    need(not result.is_absolute() and str(result) == path
        and all(part not in ('', '.', '..') for part in result.parts), 'unsafe relative member')
    return result


def exact_descriptor(value, limit):
    need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'},
        'exact3 original descriptor required')
    absolute(value['path'])
    need(type(value['bytes']) is int and 0 < value['bytes'] <= limit
        and isinstance(value['sha256'], str)
        and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'bounded original pin required')
    return value


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self, row, limit):
        exact_descriptor(row, limit)
        path = absolute(row['path'])
        need(path.resolve(strict=True) == path, 'original symlink/noncanonical path rejected')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == row['bytes'], 'original type/link/size differs')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes']+1)
            need(pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}
                and metadata(before) == metadata(os.fstat(fd)) == metadata(path.lstat()),
                'original bytes or identity changed: '+str(path))
        finally:
            os.close(fd)
        record = {**row, 'metadata': list(metadata(before))}
        need(str(path) not in self.seen or self.seen[str(path)] == record,
            'original replaced across reads')
        self.seen[str(path)] = record
        return raw

    def recheck(self):
        for row in tuple(self.seen.values()):
            self.read({key: row[key] for key in ('path', 'bytes', 'sha256')}, row['bytes'])


def table(rows):
    need(type(rows) is list and 1 <= len(rows) <= 128, 'bounded manifest inventory required')
    result = {}
    for row in rows:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'exact manifest row required')
        relpath(row['path'])
        need(row['path'] not in result and type(row['bytes']) is int
            and 0 < row['bytes'] <= 16*1024*1024
            and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']),
            'manifest duplicate or invalid member pin')
        result[row['path']] = row
    return result


def load_base(originals, name, row):
    fixed = BASES[name]
    need((row.get('bytes'), row.get('sha256')) == fixed[1:3], 'unreviewed base manifest: '+name)
    raw = originals.read(row, 262144)
    value = strict(raw)
    need(value.get('schema') == fixed[3], 'base schema differs')
    files = table(value[fixed[4]])
    need(set(files) == MEMBERS[name], 'base inventory differs')
    if name == 'component':
        need(set(value) == {'schema', 'state', 'files'}
            and value['state'] == 'HOST_SOURCE_CANDIDATE_NOT_EXECUTED', 'component base state differs')
    root = Path(row['path']).parent
    loaded = {key: originals.read({'path': str(root/key), 'bytes': member['bytes'],
        'sha256': member['sha256']}, 262144) for key, member in files.items()}
    for key, body in loaded.items():
        if key.endswith('.py'):
            compile(body, key, 'exec', dont_inherit=True)
    return raw, value, loaded


def assignments(raw):
    tree = ast.parse(raw.decode('utf-8'))
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            need(name not in result, 'duplicate top-level source constant: '+name)
            result[name] = node
    return tree, result


def literal(raw, name):
    _, rows = assignments(raw)
    need(name in rows, 'required literal absent: '+name)
    try:
        return ast.literal_eval(rows[name].value)
    except (ValueError, TypeError):
        raise ValueError('required source constant is not a literal: '+name)


def rewrite(raw, expressions):
    """Replace RHS byte spans, preserving every other byte and every other AST node."""
    old_tree, rows = assignments(raw)
    need(set(expressions) <= set(rows), 'dependency constant absent')
    lines = raw.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1]+len(line))
    spans = []
    for name, expression in expressions.items():
        value = rows[name].value
        replacement = expression.encode('utf-8')
        ast.parse(expression, mode='eval')
        start = offsets[value.lineno-1]+value.col_offset
        end = offsets[value.end_lineno-1]+value.end_col_offset
        spans.append((start, end, replacement))
    result = raw
    for start, end, replacement in sorted(spans, reverse=True):
        result = result[:start]+replacement+result[end:]
    new_tree, new_rows = assignments(result)
    for name in expressions:
        need(ast.dump(new_rows[name].value, include_attributes=False)
            == ast.dump(ast.parse(expressions[name], mode='eval').body, include_attributes=False),
            'new source literal differs')
    for tree in (old_tree, new_tree):
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in expressions:
                    node.value = ast.Constant(value=None)
    need(ast.dump(old_tree, include_attributes=False) == ast.dump(new_tree, include_attributes=False),
        'unrelated product AST changed')
    compile(result, '<pin-only-derived-source>', 'exec', dont_inherit=True)
    return result


def validate_actual(originals, plan):
    actual = plan['actual']
    need(type(actual) is dict and set(actual) == set(ACTUAL_LIMITS), 'exact actual dependency inventory required')
    raw = {key: originals.read(actual[key], limit) for key, limit in ACTUAL_LIMITS.items()}
    for key in ('consumer', 'readiness', 'materializer'):
        compile(raw[key], actual[key]['path'], 'exec', dont_inherit=True)
    need((len(raw['materializer']), sha(raw['materializer'])) == MATERIALIZER,
        'materializer logic must remain byte-identical b251')
    validate_actual_bindings(actual, raw, plan['expected_final_consumer_schema'])
    return raw


def validate_actual_bindings(actual, raw, schema):
    """Check source relationships after exact bytes have been read; do not award adoption."""
    for key, oldkey in (('runtime_manifest', 'runtime'), ('consumer', 'consumer'),
            ('readiness', 'readiness'), ('policy', 'policy'), ('adoption', 'adoption')):
        need(actual[key]['sha256'] != OLD[oldkey], 'new actual R8 generation required: '+key)
    need(literal(raw['consumer'], 'PACKAGE_SHA') == actual['runtime_manifest']['sha256']
        and literal(raw['consumer'], 'CURRENT_POLICY_SHA') == actual['policy']['sha256']
        and literal(raw['consumer'], 'CURRENT_POLICY_ADOPTION_SHA') == actual['adoption']['sha256'],
        'consumer runtime/policy/adoption literal differs')
    need(literal(raw['readiness'], 'BOUNDARY_CONSUMER_SHA256') == actual['consumer']['sha256'],
        'readiness does not bind actual consumer')
    runtime = strict(raw['runtime_manifest'])
    need(type(runtime) is dict and runtime.get('revision') == 'r10-r1-operator-r8'
        and len(table(runtime.get('files'))) == 32
        and runtime.get('current_policy_sha256') == actual['policy']['sha256']
        and runtime.get('explicit_policy_adoption_sha256') == actual['adoption']['sha256']
        and runtime.get('actual_combination_generated') is True,
        'actual R8 runtime manifest pins/state differ')
    final = strict(raw['final_consumer_manifest'])
    need(schema == 'hepta.r10.final-boundary-consumers.v8' and final.get('schema') == schema,
        'explicit actual final-consumer schema differs')
    need(final.get('component_package_sha256') == actual['runtime_manifest']['sha256']
        and final.get('actual_policy_adoption_sha256') == actual['adoption']['sha256'],
        'final-consumer manifest runtime/adoption differs')
    members = table(final.get('files'))
    final_root = Path(actual['final_consumer_manifest']['path']).parent
    for key, rel in (('consumer', 'source/release_boundaries.py'),
                     ('readiness', 'source/collect_r10_readiness.py')):
        need(rel in members and members[rel] == {'path': rel, **pin(raw[key])}
            and actual[key]['path'] == str(final_root/rel), 'final-consumer source member differs: '+key)
    adoption = strict(raw['adoption'])
    need(type(adoption) is dict
        and adoption.get('schema') == 'hepta.runtime-properties-r10.policy-adoption.v1'
        and adoption.get('release_id') == 'v150-r10-r1' and adoption.get('boot_id') == BOOT
        and adoption.get('actual_export') == actual['policy'], 'actual exported policy adoption differs')
    decision = adoption.get('root_decision')
    need(type(decision) is dict
        and decision.get('schema') == 'hepta.root.runtime-properties-policy-adoption-decision.v1'
        and decision.get('decision') == 'ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY'
        and decision.get('actual_policy_sha256') == actual['policy']['sha256']
        and all(decision.get(key) is False for key in
            ('automatic_adoption', 'service_start_admitted', 'component_qualified')),
        'explicit Root actual-export decision missing')
    for key, source in (('root_scope_decision_sha256', 'root_scope_decision'),
                        ('post_live_comparison_sha256', 'post_live_comparison'),
                        ('pre_live_expectation_sha256', 'pre_live_expectation')):
        row = exact_descriptor(adoption.get(source), 32*1024*1024)
        need(decision.get(key) == row['sha256'], 'adoption decision source link differs: '+key)
    boundary = adoption.get('pre_policy_boundary')
    need(type(boundary) is dict and decision.get('prior_boundary_sha256') == boundary.get('sha256')
        and isinstance(decision.get('prior_boundary_sha256'), str)
        and re.fullmatch('[0-9a-f]{64}', decision['prior_boundary_sha256'])
        and isinstance(decision.get('actual_live_binding_sha256'), str)
        and re.fullmatch('[0-9a-f]{64}', decision['actual_live_binding_sha256']),
        'adoption boundary/live-binding pin missing')
    atoms = decision.get('permission_atoms')
    need(type(atoms) is list and len(atoms) == 44
        and all(type(atom) is list and len(atom) == 5
            and all(isinstance(value, str) and value for value in atom) for atom in atoms)
        and len({tuple(atom) for atom in atoms}) == 44, '44 explicit permission atoms required')


def path_expression(path):
    value = Path(path)
    try:
        return 'B/'+repr(str(value.relative_to(B)))
    except ValueError:
        return 'Path('+repr(str(value))+')'


def entrypoints(root, package_pins):
    comp = str(root/'component/source')
    cancel_pin = package_pins['cancel']['sha256']
    fault_pin = package_pins['fault']['sha256']
    component_args = ['--plan', '<exact-actual-plan-path>', '--plan-sha256', '<actual-plan-sha256>',
        '--package-manifest-sha256', package_pins['component']['sha256'], '--out', '<fresh-private-host-output>']
    return {
        'schema': 'hepta.r8.downstream-source-entrypoints.v1',
        'state': 'SOURCE_ENTRYPOINT_MAP_NO_CASE_EXECUTED',
        'case_execution_or_physical_pass': False,
        'required_two_layer_cases': {
            'cases': ['NEG-04', 'NEG-05', 'NEG-07', 'NEG-08', 'NEG-09'],
            'protocol_sha256': 'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0',
            'required_layers': ['host_isolated', 'physical_native_task'],
            'host_lifecycle_entry_in_reviewed_three_packages': None,
            'gap': 'The retained host_negative_runner.original.py covers NEG-10/11/12/13 only. Neither these physical actors nor the separate host transport regression harness substitutes for the five original host lifecycle acceptance cases.',
        },
        'component': {
            'case': 'COMP-01', 'environment': 'Mac host',
            'command': ['/usr/bin/python3', '-I', '-B', comp+'/prepare_direct_return_component.py',
                '--mode', '<baseline-request|prepare-return|verify-return>']+component_args+['--execute-host-once'],
            'prerequisites': ['actual sealed release with new qualified NEG-01 and NEG-02 originals',
                'actual explicit operator identity and fresh nonce', 'exact baseline/prepared/return original descriptors'],
            'available_behavior': 'Prepare one original production return mapping; verify original launch/focus/viewport receipt.',
            'missing_physical_closure_entry': 'This package has no Root once-dispatch, complete transport termination, restoration or final COMP-01 closure assembler.',
            'entry_always_awards_case_pass': False,
        },
        'geometry_fixture': {
            'case': 'NEG-03', 'environment': 'isolated host fixture',
            'command': ['/usr/bin/python3', '-I', '-B', comp+'/verify_unqualified_geometry_fixture.py']
                +component_args+['--execute-host-fixture-once'],
            'physical_test': False, 'effect_dispatches': 0,
            'available_behavior': 'Six synthetic single-field display/rotation/size and return-viewport mutations, with positive controls and rejected subsequent tap.',
            'missing_physical_entry': 'No actual external-display/rotation setup, input-before-rejection capture or physical NEG-03 closure entry exists in this reviewed package.',
        },
        'cancel': {
            'cases': ['NEG-08', 'NEG-09'], 'environment': 'P4 reviewed host, exact staged package',
            'package': package_pins['cancel'],
            'command': ['python3', '-I', '-B', '<P4-exact-staged-cancel-package>/source/cancel_native_once_r10.py',
                '--plan', '<actual-new-native-task-plan>', '--package', '<P4-exact-staged-cancel-package>/MANIFEST.json',
                '--package-sha256', cancel_pin, '--out', '/home/alex/razr60-local-model-v150/cancel-native-r10/<plan.label>', '--execute-once'],
            'prerequisites': ['current actual READY/release seal and complete original runtime binding',
                'new original task five-field scope and exact owner request/nonce',
                'P4 preserved UI helper 6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b and configuration',
                'NEG-08 before dispatch; NEG-09 after one original approved open_app and independently observed effect'],
            'available_behavior': 'One durable selected-CAS HEPTA Cancel tap, followed by bounded original model/native drain observation.',
            'missing_closure_entry': 'Actual-task plan/host assembler and independent complete-original late/global closure assembler are not delivered by this package.',
            'entry_result_physical_case_pass': False,
        },
        'signal_fault': {
            'cases': {'NEG-04': 'SIGTERM original carrier before dispatch',
                'NEG-05': 'SIGTERM original carrier after original effect and fresh public effect read',
                'NEG-07': 'SIGSTOP exact r6 sidecar worker; original timeout owner performs cleanup'},
            'environment': 'native Android Magisk root, exact staged or inline reviewed package',
            'package': package_pins['fault'],
            'command': ['<reviewed-native-Python>', '-I', '-B', '<exact-staged-fault-package>/source/signal_fault_once_r10.py',
                '--plan-b64', '<base64-exact-actual-plan>', '--manifest-sha256', fault_pin, '--execute-signal-once'],
            'prerequisites': ['actual current release, READY, five-field native task scope, four role identities and carrier edges',
                'held pidfd and immediate start-identity/domain/phase revalidation; no numeric-PID fallback'],
            'available_behavior': 'One durable intent and one exact pidfd action; returned or unknown never automatically retries.',
            'missing_closure_entry': 'The actor does not assemble final native counters, full transport termination, cleanup or independent physical case closure.',
            'entry_result_physical_case_pass': False,
        },
        'unchanged_limits': {'source_consumer_bytes': 131072, 'observer_unpacked_bytes': 262144,
            'exclusive_adb_bytes_less_than': 65536, 'observer_seconds': 8, 'shell_seconds': 12,
            'boundary_union_bytes': 33554432},
        'out_of_scope': ['No AC positive KINDS expansion to NEG-08/NEG-09.',
            'CPU/P4/phone collectors and other fixed-19 cases retain their separate finalization and evidence requirements.'],
    }


def prepare(originals, plan, plan_raw):
    need(type(plan) is dict and set(plan) == {'schema', 'base_packages', 'actual',
        'expected_final_consumer_schema', 'output_root'} and plan['schema'] == PLAN_SCHEMA,
        'exact source finalization plan required')
    need(type(plan['base_packages']) is dict and set(plan['base_packages']) == set(BASES),
        'exact three reviewed base packages required')
    need(type(plan['actual']) is dict and set(plan['actual']) == set(ACTUAL_LIMITS),
        'exact actual dependency inventory required')
    root = absolute(plan['output_root'])
    need(root.parent.resolve(strict=True) == root.parent, 'canonical existing output parent required')
    for row in list(plan['base_packages'].values())+list(plan['actual'].values()):
        need(type(row) is dict and isinstance(row.get('path'), str), 'no future/null input accepted')
        path = absolute(row['path'])
        need(root != path and root not in path.parents, 'output cannot contain an input original')
    bases = {key: load_base(originals, key, plan['base_packages'][key]) for key in BASES}
    validate_actual(originals, plan)
    return derive_sources(originals, plan, plan_raw, bases)


def derive_sources(originals, plan, plan_raw, bases):
    """Derive bytes after validation; recheck retained originals before returning."""
    root = absolute(plan['output_root'])
    actual = plan['actual']
    context = bases['component'][2]['source/component_source_context.py']
    active = bases['cancel'][2]['source/active_runtime_r10.py']
    need(sha(context) == OLD['context'] and sha(active) == OLD['active']
        and active == bases['fault'][2]['source/active_runtime_r10.py'],
        'reviewed context or shared active bytes differ')
    need(literal(context, 'MATERIALIZER_PIN') == MATERIALIZER
        and literal(context, 'CONSUMER_PIN') == (58505, OLD['consumer'])
        and literal(context, 'READINESS_PIN') == (16405, OLD['readiness']), 'original context pins differ')
    for name, key in (('RUNTIME_SHA', 'runtime'), ('POLICY_SHA', 'policy'), ('ADOPTION_SHA', 'adoption')):
        need(literal(context, name) == OLD[key], 'original context literal differs')
    active_expressions = {name: repr(actual[key]['sha256']) for name, key in
        (('CONSUMER_SHA', 'consumer'), ('READINESS_SHA', 'readiness'),
         ('POLICY_SHA', 'policy'), ('ADOPTION_SHA', 'adoption'))}
    for name, key in (('CONSUMER_SHA', 'consumer'), ('READINESS_SHA', 'readiness'),
                       ('POLICY_SHA', 'policy'), ('ADOPTION_SHA', 'adoption')):
        need(literal(active, name) == OLD[key], 'original active pin differs')
    new_active = rewrite(active, active_expressions)
    context_expressions = {
        'MATERIALIZER': path_expression(actual['materializer']['path']),
        'CONSUMER': path_expression(actual['consumer']['path']),
        'CONSUMER_PIN': repr((actual['consumer']['bytes'], actual['consumer']['sha256'])),
        'READINESS_PIN': repr((actual['readiness']['bytes'], actual['readiness']['sha256'])),
        'RUNTIME_SHA': repr(actual['runtime_manifest']['sha256']),
        'POLICY_SHA': repr(actual['policy']['sha256']), 'ADOPTION_SHA': repr(actual['adoption']['sha256'])}
    new_context = rewrite(context, context_expressions)
    packages = {key: dict(value[2]) for key, value in bases.items()}
    packages['component']['source/component_source_context.py'] = new_context
    for key in ('cancel', 'fault'):
        packages[key]['source/active_runtime_r10.py'] = new_active
    interface = strict(packages['component']['INTERFACE.json'])
    old_component_root = str(B/BASES['component'][0])
    need(interface['package_root'] == old_component_root
        and interface['sealed_release_required']['component_runtime_sha256'] == OLD['runtime'],
        'original component interface differs')
    interface['package_root'] = str(root/'component')
    interface['sealed_release_required']['component_runtime_sha256'] = actual['runtime_manifest']['sha256']
    for key, name in (('comp01', 'prepare_direct_return_component.py'),
                      ('neg03', 'verify_unqualified_geometry_fixture.py')):
        need(interface[key]['cli'][3] == old_component_root+'/source/'+name, 'component CLI path differs')
        interface[key]['cli'][3] = str(root/'component/source'/name)
    packages['component']['INTERFACE.json'] = encoded(interface)
    package_pins = {}
    changes = {}
    for key in BASES:
        value = copy.deepcopy(bases[key][1])
        if key != 'component':
            value.update(expected_live_policy_sha256=actual['policy']['sha256'],
                reviewed_boundary_consumer_sha256=actual['consumer']['sha256'],
                reviewed_readiness_sha256=actual['readiness']['sha256'],
                reviewed_policy_adoption_sha256=actual['adoption']['sha256'],
                reviewed_final_consumer_manifest_sha256=actual['final_consumer_manifest']['sha256'],
                parent_candidate_manifest_sha256=plan['base_packages'][key]['sha256'])
            runtime_key = 'reviewed_component_runtime_manifest_sha256' if key == 'cancel' else 'reviewed_component_runtime_sha256'
            value[runtime_key] = actual['runtime_manifest']['sha256']
        if key == 'cancel':
            value['revision'] = 'host-source-R8-four-actual-dependency-pins-bound'
            value['shared_observer_manifest_relationship'] = 'immutable_observer_ancestor_retained_active_four_actual_dependency_literals_derived'
        value[BASES[key][4]] = [{'path': name, **pin(body)} for name, body in sorted(packages[key].items())]
        changes[key] = [name for name, body in packages[key].items() if body != bases[key][2][name]]
        need(set(changes[key]) == ({'source/component_source_context.py', 'INTERFACE.json'}
            if key == 'component' else {'source/active_runtime_r10.py'}), 'unexpected product file change')
        packages[key]['MANIFEST.json'] = encoded(value)
        package_pins[key] = descriptor(root/key/'MANIFEST.json', packages[key]['MANIFEST.json'])
    outputs = {key+'/'+name: body for key, files in packages.items() for name, body in files.items()}
    outputs['originals/FINALIZATION-PLAN.original.json'] = plan_raw
    for key in BASES:
        outputs['originals/'+key+'-MANIFEST.original.json'] = bases[key][0]
    outputs['originals/component_source_context.original.py'] = context
    outputs['originals/active_runtime_r10.original.py'] = active
    outputs['ENTRYPOINTS.json'] = encoded(entrypoints(root, package_pins))
    provenance = {
        'schema': 'hepta.r8.downstream-source-derivation.v1',
        'state': 'SOURCE_DERIVATION_ONLY_NO_CASE_EXECUTED',
        'bases': plan['base_packages'], 'actual_dependencies': actual,
        'new_packages': package_pins, 'changed_product_files': changes,
        'context_rhs_names': sorted(context_expressions), 'active_rhs_names': sorted(active_expressions),
        'shared_active_is_same_bytes_in_both_packages': True, 'shared_active': pin(new_active),
        'all_other_source_and_reference_bytes_preserved': True,
        'complete_adoption_independently_reverified_by_this_tool': False,
        'adoption_precondition': 'The supplied actual adoption descriptor must already be independently verified by Root using the original property-policy verifier. This tool checks raw identity and selected cross-links only.',
        'runtime_or_current_component_originals_requalified_by_this_tool': False,
        'actual_ready_bound': False, 'case_runs': 0, 'phone_calls': 0, 'model_requests': 0,
        'native_submissions': 0, 'policy_writes': 0, 'new_nonces': 0,
        'physical_case_pass': False, 'automatic_retry': False,
    }
    outputs['DERIVATION.json'] = encoded(provenance)
    originals.recheck()
    return root, outputs, package_pins, provenance


class CreateOnlyTree:
    """Hold created directories/files; reject path substitution before publishing receipt."""
    def __init__(self, root):
        self.root = root
        self.dirs = {}
        self.files = {}
        need(root.parent.resolve(strict=True) == root.parent, 'output parent changed')
        root.mkdir(mode=0o700)
        fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
        self.dirs['.'] = fd
        try:
            self._dircheck('.')
        except BaseException:
            self.close()
            raise

    def _dircheck(self, rel):
        fd = self.dirs[rel]
        st = os.fstat(fd)
        path = self.root if rel == '.' else self.root/rel
        named = path.lstat()
        need(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
            and st.st_uid == os.geteuid()
            and (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid)
                == (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid),
            'held output directory replaced')

    def directory(self, rel):
        if rel == '.':
            return self.dirs['.']
        if rel in self.dirs:
            self._dircheck(rel)
            return self.dirs[rel]
        path = relpath(rel)
        parent = self.directory(str(path.parent))
        os.mkdir(path.name, 0o700, dir_fd=parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=parent)
        self.dirs[rel] = fd
        os.fsync(parent)
        self._dircheck(rel)
        return fd

    def put(self, rel, raw):
        path = relpath(rel)
        parent = self.directory(str(path.parent))
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent)
        self.files[rel] = (fd, raw)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fsync(parent)
        self.filecheck(rel)

    def filecheck(self, rel):
        fd, expected = self.files[rel]
        st = os.fstat(fd)
        named = (self.root/rel).lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600
            and st.st_uid == os.geteuid() and metadata(st) == metadata(named), 'held output file replaced')
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            actual = stream.read(len(expected)+1)
        need(actual == expected and metadata(st) == metadata(os.fstat(fd)) == metadata((self.root/rel).lstat()),
            'written source or held inode changed')

    def check(self):
        for rel in self.dirs:
            self._dircheck(rel)
            expected = {Path(name).name for name in self.files if str(Path(name).parent) == rel}
            expected |= {Path(name).name for name in self.dirs if name != '.' and str(Path(name).parent) == rel}
            need(set(os.listdir(self.dirs[rel])) == expected, 'output inventory changed')
        for rel in self.files:
            self.filecheck(rel)

    def close(self):
        for fd, _ in self.files.values():
            os.close(fd)
        for fd in reversed(list(self.dirs.values())):
            os.close(fd)
        self.files.clear()
        self.dirs.clear()


def execute(originals, root, outputs, packages, provenance, plan_descriptor):
    writer = None
    try:
        originals.recheck()
        writer = CreateOnlyTree(root)
        for name in sorted(outputs, key=lambda value: (value.endswith('/MANIFEST.json'), value)):
            writer.put(name, outputs[name])
        writer.check()
        originals.recheck()
        result = {
            'schema': 'hepta.r8.downstream-source-finalization-result.v1',
            'state': 'SOURCE_PACKAGES_CREATED_WAITING_ACTUAL_SEAL_READY_CASES_AND_CLOSURE',
            'plan': plan_descriptor, 'packages': packages,
            'derivation': descriptor(root/'DERIVATION.json', outputs['DERIVATION.json']),
            'entrypoints': descriptor(root/'ENTRYPOINTS.json', outputs['ENTRYPOINTS.json']),
            'outputs': [{'path': name, **pin(body)} for name, body in sorted(outputs.items())],
            'originals': sorted(originals.seen.values(), key=lambda row: row['path']),
            'actual_dependencies': provenance['actual_dependencies'],
            'case_runs': 0, 'phone_calls': 0, 'model_requests': 0, 'policy_writes': 0,
            'new_nonces': 0, 'actual_ready_bound': False, 'physical_case_pass': False,
            'complete_adoption_independently_reverified_by_this_tool': False, 'automatic_retry': False,
        }
        result_raw = encoded(result)
        writer.put('FINALIZATION.json', result_raw)
        writer.check()
        fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {'state': result['state'], 'result': descriptor(root/'FINALIZATION.json', result_raw),
            'packages': packages, 'phone_calls': 0, 'physical_case_pass': False}
    finally:
        if writer is not None:
            writer.close()


def plan_from_delivery(originals, delivery_row, output_root):
    """Resolve actual descriptors from the exact published cascade receipt, never guesses."""
    delivery = strict(originals.read(delivery_row, 262144))
    need(type(delivery) is dict
        and delivery.get('schema') == 'hepta.property-policy.final-boundary-cascade-delivery.v1'
        and delivery.get('state') == 'HOST_ONLY_PUBLISHED'
        and delivery.get('phone_calls') == 0 and delivery.get('nonce_generated') is False
        and delivery.get('final_release_generated') is False
        and delivery.get('new_component_qualification') is False
        and delivery.get('module_replacement_reapplied') is False,
        'exact completed source-only cascade delivery required')
    frozen = delivery.get('reviewed_finalization')
    need(type(frozen) is dict and frozen.get('schema') == 'hepta.property-policy.final-pin-freeze.v1',
        'cascade actual finalization missing')
    adoption_row = exact_descriptor(frozen.get('policy_adoption'), ACTUAL_LIMITS['adoption'])
    adoption = strict(originals.read(adoption_row, ACTUAL_LIMITS['adoption']))
    policy_row = exact_descriptor(adoption.get('actual_export'), ACTUAL_LIMITS['policy'])
    need(frozen.get('actual_policy') == {key: policy_row[key] for key in ('bytes', 'sha256')},
        'cascade actual policy is not adoption actual_export')
    fc_row = exact_descriptor(delivery.get('consumer'), ACTUAL_LIMITS['final_consumer_manifest'])
    ac_row = exact_descriptor(delivery.get('acceptance'), 262144)
    ac = strict(originals.read(ac_row, 262144))
    fc_root, ac_root = Path(fc_row['path']).parent, Path(ac_row['path']).parent
    need(Path(fc_row['path']).name == Path(ac_row['path']).name == 'MANIFEST.json',
        'actual cascade manifest paths differ')
    runtime_sources = delivery.get('runtime_sources')
    need(type(runtime_sources) is dict, 'cascade runtime source descriptors missing')
    actual = {'runtime_manifest': frozen['runtime_manifest'], 'adoption': adoption_row,
        'policy': policy_row, 'final_consumer_manifest': fc_row}
    for key, name in (('consumer', 'release_boundaries.py'), ('readiness', 'collect_r10_readiness.py')):
        row = runtime_sources.get(name)
        need(type(row) is dict and set(row) == {'bytes', 'sha256'}, 'cascade runtime member pin differs')
        actual[key] = {'path': str(fc_root/'source'/name), **row}
    materializer = delivery.get('materializer')
    need(type(materializer) is dict and set(materializer) == {'bytes', 'sha256'},
        'cascade materializer descriptor missing')
    ac_members = table(ac.get('files'))
    need(ac_members.get('operator/materialize_case_r10.py')
        == {'path': 'operator/materialize_case_r10.py', **materializer},
        'acceptance manifest materializer differs from cascade delivery')
    actual['materializer'] = {'path': str(ac_root/'operator/materialize_case_r10.py'), **materializer}
    return {'schema': PLAN_SCHEMA,
        'base_packages': {key: {'path': str(B/value[0]/'MANIFEST.json'), 'bytes': value[1],
            'sha256': value[2]} for key, value in BASES.items()},
        'actual': actual, 'expected_final_consumer_schema': 'hepta.r10.final-boundary-consumers.v8',
        'output_root': str(absolute(output_root))}


def create_plan_from_delivery(args):
    need(args.delivery_result_desc and args.prepare_out and args.output_root,
        'delivery-result exact3 descriptor, fresh prepare-out and output-root required')
    need(not args.plan and not args.plan_sha256, 'prepare-plan mode derives the plan; no supplied plan accepted')
    originals = Originals()
    delivery_row = strict(args.delivery_result_desc)
    plan = plan_from_delivery(originals, delivery_row, args.output_root)
    raw = encoded(plan)
    root, outputs, packages, provenance = prepare(originals, plan, raw)
    need(not root.exists() and not root.is_symlink(), 'create-only package output already exists')
    prep = absolute(args.prepare_out)
    need(prep != root and prep not in root.parents and root not in prep.parents,
        'plan and source-output roots must be separate')
    need(all(prep != Path(path) and prep not in Path(path).parents for path in originals.seen),
        'plan output cannot contain an original')
    row = descriptor(prep/'FINALIZATION-PLAN.json', raw)
    entry = {'executable': '/usr/bin/python3', 'argv': ['-I', '-B', str(Path(__file__).resolve()),
        '--plan', row['path'], '--plan-sha256', row['sha256'], '--execute-source-finalization-once'],
        'phone_calls': 0, 'physical_case_pass': False}
    writer = None
    try:
        originals.recheck()
        writer = CreateOnlyTree(prep)
        writer.put('FINALIZATION-PLAN.json', raw)
        writer.put('EXECUTION-ENTRY.json', encoded(entry))
        writer.put('PREPARATION.json', encoded({
            'schema': 'hepta.r8.downstream-source-plan-preparation.v1',
            'state': 'ACTUAL_SOURCE_PLAN_CREATED_NO_SOURCE_PACKAGES_PUBLISHED',
            'cascade_delivery': delivery_row, 'plan': row, 'entry': entry,
            'planned_packages': packages, 'planned_file_count': len(outputs)+1,
            'actual_dependencies': provenance['actual_dependencies'],
            'complete_adoption_independently_reverified_by_this_tool': False,
            'phone_calls': 0, 'case_runs': 0, 'physical_case_pass': False}))
        originals.recheck()
        writer.check()
    finally:
        if writer is not None:
            writer.close()
    return {'state': 'ACTUAL_SOURCE_PLAN_CREATED_NO_SOURCE_PACKAGES_PUBLISHED',
        'plan': row, 'entry': entry, 'planned_packages': packages,
        'phone_calls': 0, 'physical_case_pass': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan')
    parser.add_argument('--plan-sha256')
    parser.add_argument('--delivery-result-desc')
    parser.add_argument('--prepare-out')
    parser.add_argument('--output-root')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--validate-source-plan', action='store_true')
    mode.add_argument('--execute-source-finalization-once', action='store_true')
    mode.add_argument('--prepare-source-plan-once', action='store_true')
    args = parser.parse_args(argv)
    if not (args.validate_source_plan or args.execute_source_finalization_once or args.prepare_source_plan_once):
        print(json.dumps({'state': 'SOURCE_ONLY_NO_INPUTS_READ', 'phone_calls': 0,
            'case_runs': 0, 'physical_case_pass': False, 'actual_inputs_required': list(ACTUAL_LIMITS)}, sort_keys=True))
        return 0
    os.umask(0o077)
    try:
        if args.prepare_source_plan_once:
            print(json.dumps(create_plan_from_delivery(args), sort_keys=True))
            return 0
        need(not args.delivery_result_desc and not args.prepare_out and not args.output_root,
            'delivery preparation arguments are valid only in prepare-plan mode')
        need(args.plan and args.plan_sha256, 'explicit plan path and SHA required')
        path = absolute(args.plan)
        row = {'path': str(path), 'bytes': path.lstat().st_size, 'sha256': args.plan_sha256}
        originals = Originals()
        raw = originals.read(row, 65536)
        root, outputs, packages, provenance = prepare(originals, strict(raw), raw)
        need(not root.exists() and not root.is_symlink(), 'create-only output already exists')
        if args.validate_source_plan:
            answer = {'state': 'VALIDATED_SOURCE_PLAN_NO_OUTPUT_CREATED', 'plan': row,
                'planned_packages': packages, 'planned_file_count': len(outputs)+1,
                'phone_calls': 0, 'physical_case_pass': False,
                'complete_adoption_independently_reverified_by_this_tool': False}
        else:
            answer = execute(originals, root, outputs, packages, provenance, row)
        print(json.dumps(answer, sort_keys=True))
        return 0
    except BaseException as error:
        print(json.dumps({'state': 'HELD_OR_PARTIAL_SOURCE_OUTPUT_NO_RETRY',
            'error_type': type(error).__name__, 'error': str(error)[:1200],
            'phone_calls': 0, 'physical_case_pass': False, 'automatic_retry': False}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
