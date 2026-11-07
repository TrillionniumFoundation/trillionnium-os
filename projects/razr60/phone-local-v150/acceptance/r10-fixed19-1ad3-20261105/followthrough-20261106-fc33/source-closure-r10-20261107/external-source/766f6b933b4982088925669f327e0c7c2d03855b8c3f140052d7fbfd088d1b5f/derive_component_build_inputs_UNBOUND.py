#!/usr/bin/env python3
"""Construct current component inputs and a BUILD request from actual originals.

This entry never runs the BUILD request, opens a phone transport, or executes a
captured command. Both actual current ROOT-RESULT descriptors are required.
The actual source-chain install helper remains unchanged and UNBOUND.
"""
import argparse
import ast
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import types

FROZEN_INPUTS = None
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
SOURCE_ROOT = B + '/followthrough-fc33-release-source-chain-r5-derived01'
SOURCE_DERIVATION = {'path': SOURCE_ROOT + '/DERIVATION.json', 'bytes': 44922,
    'sha256': '09ea015625df33e992160a2b58569079586a2b501087a6c23e51e3f869b1ca37'}
RUNTIME = {'path': B + '/native-guard-r10-r1-operator-fc33-native-v3-r5/runtime/MANIFEST.json',
    'bytes': 57078, 'sha256': '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'}
RETIREMENT_INPUTS = {'path': B + '/r10-final-seal-preparation-r1/ACTUAL-BUILDER-RETIREMENT-INPUTS.json',
    'bytes': 2414, 'sha256': '1cd133d03c687d671aa87b3a813379020e0779941ebdd638de2b5b79652cdf4f'}
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
SCHEMA = 'hepta.fc33.actual-component-build-construction-inputs.v1'
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
OLD_ROOT = B + '/native-guard-root-chains-r10-r1/'
OLD04 = OLD_ROOT + 'root-r10-neg01-20261104-04'
OLD06 = OLD_ROOT + 'root-r10-neg01-20261105-06'
OLD = {
    'pre_policy': {
        'root_result': {'path': OLD04 + '/ROOT-RESULT.json', 'bytes': 10980,
            'sha256': 'c92382e0841375fc0a1fb19ff0271381ac044f1dad01427342fca4e4f6e9c638'},
        'package_manifest': {'path': B + '/native-guard-r10-r1-operator-r4/runtime/MANIFEST.json',
            'bytes': 5284, 'sha256': '1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996'},
        'combination': {'path': OLD04 + '/material/tree/inputs/COMBINATION.json', 'bytes': 4702,
            'sha256': '7f5929ae709239f8a5d92314146d2b63151bb06746d160da7961a3de29c486af'},
        'previous': {'path': OLD04 + '/ACTUAL-PREVIOUS-INPUT.json', 'bytes': 1428,
            'sha256': '7ed4ccc75cc4ebc999af0da37e10e3d10173c2bf93e66f01b01042b890a4d9a4'},
    },
    'environment': {
        'root_result': {'path': OLD06 + '/ROOT-RESULT.json', 'bytes': 32600,
            'sha256': 'ed2e22f27b72951621802add6a1d68950ea94721d052b25dd5d59ebc95be5c93'},
        'package_manifest': {'path': B + '/native-guard-r10-r1-operator-r6/runtime/MANIFEST.json',
            'bytes': 11495, 'sha256': '4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e'},
        'combination': {'path': OLD06 + '/material/tree/inputs/COMBINATION.json', 'bytes': 4702,
            'sha256': 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'},
        'previous': {'path': OLD06 + '/ACTUAL-PREVIOUS-INPUT.json', 'bytes': 1428,
            'sha256': '5ef37523f24a78dbce66da496c7f61897d989630a18739945279b8d0383415e9'},
        'recovery_result': {'path': OLD06 + '/RECOVERY-RESULT.json', 'bytes': 2724,
            'sha256': 'ea74dc212a1edf1c9f4395ce72a8be8ec7a7f184b9f28321d68ece270fc4aa12'},
        'recovery_source': {'path': B + '/native-guard-attempt06-recovery-source-r1/source/resume_failed_component06.py',
            'bytes': 26606, 'sha256': '50a4e759486632d0fc129bb08e0101f526542a8a577b47d3474497da3d9b6237'},
        'recovery_intent': {'path': OLD06 + '/RECOVERY-INTENT.json', 'bytes': 90530,
            'sha256': '2db02625a51939dfbcaa1127d10976f253aa12e8ee9fa8c8c95c196f73ceefa2'},
        'original_root_failure': {'path': OLD06 + '/ROOT-FAILURE.json', 'bytes': 17357,
            'sha256': '4db667e2036cfcfee95f48ee3a58ed7f930cd0807402433afc7ad220da83fc7d'},
    },
}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    need(type(raw) is bytes, 'complete bytes required')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def same(a, b):
    return canonical(a) == canonical(b)


def strict(raw):
    need(type(raw) is bytes and len(raw) <= MAX_FILE, 'bounded complete JSON bytes')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def exact(value, keys, why):
    need(type(value) is dict and set(value) == set(keys), why)
    return value


def path(value):
    need(type(value) is str and value and not any(c in value for c in '\0\r\n\t'),
         'plain canonical absolute path')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts,
         'canonical absolute path')
    return p


def descriptor(row, *, metadata=False, maximum=MAX_FILE):
    keys = ('path', 'bytes', 'sha256', 'metadata') if metadata else ('path', 'bytes', 'sha256')
    exact(row, keys, 'exact original descriptor')
    path(row['path'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= maximum
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'typed bounded original byte pin')
    if metadata:
        m = row['metadata']
        need(type(m) is list and len(m) == 9 and all(type(n) is int for n in m)
             and stat.S_ISREG(m[2]) and m[5] == 1 and m[6] == row['bytes'],
             'complete original file full9')
    return row


def located(name, raw):
    return dict(path=str(name), **pin(raw))


class Pool:
    def __init__(self, callback):
        need(callable(callback), 'explicit complete original byte reader')
        self.callback, self.rows, self.total = callback, {}, 0

    def read(self, row, maximum=MAX_FILE):
        descriptor(row, maximum=maximum)
        raw = self.callback(dict(row))
        need(type(raw) is bytes and pin(raw) == {k: row[k] for k in ('bytes', 'sha256')},
             'actual original bytes differ')
        key = row['path']
        if key in self.rows:
            old, body = self.rows[key]
            need(same(old, row) and body == raw, 'original path changed between references')
        else:
            need(len(self.rows) < 4096 and self.total + len(raw) <= MAX_TOTAL,
                 'complete original pool bound')
            self.rows[key] = (dict(row), raw)
            self.total += len(raw)
        return raw

    def recheck(self):
        for row, body in list(self.rows.values()):
            need(self.callback(dict(row)) == body, 'actual original changed during construction')


def source_module(raw, row, name):
    need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact full source bytes')
    module = types.ModuleType(name)
    module.__file__ = row['path']
    exec(compile(raw, row['path'], 'exec'), module.__dict__)
    return module


def source_context(pool):
    report = strict(pool.read(SOURCE_DERIVATION, 65536))
    need(report['state'] == 'SOURCE_CANDIDATES_ONLY_ACTUAL_EXECUTION_UNBOUND'
         and report['actual_execution_slots_unbound'] is True
         and report['BUILD'] is False and report['install'] is False and report['READY'] is False,
         'actual published source-chain family')
    rows = report['files']
    need(type(rows) is list and len(rows) == 20 and len({row['path'] for row in rows}) == 20,
         'complete actual published source descriptor inventory')
    selected = {str(path(row['path']).relative_to(SOURCE_ROOT)): descriptor(row) for row in rows}
    def load(name):
        row = selected['source/' + name + '.py']
        return source_module(pool.read(row, 512 * 1024), row, 'reviewed_' + name)
    consumer = load('release_boundaries')
    release = load('verify_final_release_inputs')
    need(consumer.PACKAGE_SHA == RUNTIME['sha256'] == release.RUNTIME
         and release.FIXED['CONSUMER'] == selected['source/release_boundaries.py'],
         'same published consumer and actual runtime')
    return consumer, release, selected


def runtime_sources(pool, consumer):
    raw = pool.read(RUNTIME, 131072)
    manifest = strict(raw)
    files = manifest['files']
    need(type(files) is list and len(files) == consumer.PACKAGE_FILE_COUNT
         and len({row['path'] for row in files}) == len(files), 'complete actual frozen package members')
    copies, bodies = [], {}
    root = path(RUNTIME['path']).parent
    for row in files:
        exact(row, ('path', 'bytes', 'sha256'), 'exact package member')
        rel = PurePosixPath(row['path'])
        need(not rel.is_absolute() and str(rel) == row['path'] and '..' not in rel.parts,
             'relative frozen runtime member')
        copy = dict(row, path=str(root / rel))
        bodies[row['path']] = pool.read(copy)
        copies.append({'name': row['path'], 'copy': copy})
    return manifest, copies, bodies


def history_seed(pool, consumer, release, manifest, copies, bodies):
    """Derive fixed history fields; this does not qualify either new current case."""
    with consumer.component_modules({'package_sources': bodies}) as modules:
        late = modules['late_boundary']
        late.validate_current_package_manifest(manifest)
        branches = late.non_native_sidebranches()
        value = dict(schema='hepta.r10.component-boundary-inputs.v10', release_id='v150-r10-r1',
            boot_id=BOOT, component_package_manifest=RUNTIME, component_package_files=copies,
            component_combination=release.FIXED['COMBINATION'], latest_boundary=None,
            publish_result=None, originals=None, retirement=late.LEGACY_RETIREMENT,
            non_native_sidebranch=branches[0]['binding'],
            non_native_sidebranches=[row['binding'] for row in branches],
            retained_unstarted_stage=manifest['retained_unstarted_stage'])
        for name, record, schema, field in (
                ('pre_policy', late.reviewed_pre_policy_ancestor(),
                 'hepta.r10.fixed-pre-policy-component-ancestor.v1', 'pre_policy_ancestor'),
                ('environment', late.reviewed_environment_parent_ancestor(),
                 'hepta.r10.fixed-environment-parent-component-ancestor.v1', 'environment_parent_ancestor')):
            spec = strict(encoded(OLD[name]))
            result = strict(pool.read(spec['root_result'], 65536))
            steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
            need(len(steps) == 1, 'one actual historical publication step')
            spec.update(publication_operation=steps[0]['stdout'], publication_stderr=steps[0]['stderr'])
            value[field] = dict(schema=schema, boundary=record['boundary'], **spec)
        value['property_parent_ancestors'] = [dict(
            schema='hepta.r10.fixed-property-parent-component-ancestor.v1', attempt=attempt,
            boundary=record['boundary'], **consumer.property_parent_proof_spec(attempt))
            for attempt, record in zip(('attempt08', 'attempt07'), late.reviewed_property_parent_ancestors())]
        for field, name, record in (
                ('diagnostic_parent_ancestor', 'failed902', late.reviewed_diagnostic_parent_ancestor()),
                ('codec_diagnostic_parent_ancestor', 'failed6077', late.reviewed_codec_diagnostic_parent_ancestor())):
            value[field] = dict(schema='hepta.r10.fixed-diagnostic-parent-component-ancestor.v1',
                               boundary=record['boundary'], **consumer.diagnostic_parent_proof_spec(name))
        for field, name, record in (
                ('stack_diagnostic_parent_ancestor', 'failed820', late.reviewed_stack_diagnostic_parent_ancestor()),
                ('v3_runtime_diagnostic_ancestor', 'v3runtime', late.reviewed_v3_runtime_diagnostic_ancestor())):
            value[field] = dict(schema='hepta.r10.fixed-current-diagnostic-history.v1',
                               boundary=record['boundary'], **consumer.current_diagnostic_proof_spec(name))
        need(set(value) == consumer.COMPONENT_FIELDS, 'derived exact component input keys')
        parents = late.reviewed_source_parent_records()
        need(len(parents) == manifest['source_parent_native_boundary_count'], 'actual source-parent count')
    return value


def archive_projection(source, common):
    """Use only the exact frozen archive parser and zero helper, without its CLI/imports."""
    tree = ast.parse(source)
    wanted = {'zero', 'archive_files'}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    need({n.name for n in nodes} == wanted and len(nodes) == 2, 'complete exact archive parser projection')
    namespace = dict(C=common, MAX=64 * 1024 * 1024, gzip=gzip, io=io, tarfile=tarfile,
                     Path=PurePosixPath, stat=stat, base64=base64)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<frozen-original-archive-parser>', 'exec'), namespace)
    return namespace['archive_files']


class PhoneOriginals:
    def __init__(self):
        self.candidates, self.used = {}, {}

    def add(self, row, raw):
        descriptor(row, metadata=True)
        need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'complete phone original byte pin')
        key = canonical(row)
        need(key not in self.candidates or self.candidates[key] == raw,
             'same complete phone descriptor has different bytes')
        self.candidates[key] = raw

    def read(self, row):
        descriptor(row, metadata=True)
        key = canonical(row)
        need(key in self.candidates, 'actual phone original omitted: ' + row['path'])
        prior = self.used.get(row['path'])
        need(prior is None or same(prior, row), 'selected phone path changed full descriptor')
        self.used[row['path']] = dict(row)
        return self.candidates[key]


def collect_case(case_id, root_row, pool, consumer, bodies, phone):
    raw = pool.read(root_row, 1024 * 1024)
    result = strict(raw)
    root = path(root_row['path']).parent
    need(path(root_row['path']).name == 'ROOT-RESULT.json'
         and root.parent == PurePosixPath(OLD_ROOT)
         and result.get('state') == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
         and result.get('component_qualified') is True and result.get('native_status') == 'completed'
         and result.get('automatic_retry') is False and result.get('business_qualified') is False
         and result.get('four_role_qualification') is False
         and type(result.get('model_requests')) is int and result['model_requests'] == 0,
         'one actual completed current component Root result required')
    previous_row = descriptor(result['previous'])
    need(path(previous_row['path']) == root / 'ACTUAL-PREVIOUS-INPUT.json', 'actual closed previous namespace')
    previous = strict(pool.read(previous_row, 65536))
    boundary_row = descriptor(result['late_boundary'], metadata=True)
    need(same(previous['late_boundary'], boundary_row) and previous['component_qualified'] is True,
         'Root result and actual previous boundary agree')
    boundary_raw = pool.read(dict(path=str(root / 'LATE-BOUNDARY.original.json'),
                                 **{k: boundary_row[k] for k in ('bytes', 'sha256')}))
    boundary = strict(boundary_raw)
    need(boundary['case_id'] == case_id and boundary['package_sha256'] == RUNTIME['sha256']
         and boundary['combination_sha256'] == consumer.CURRENT_COMBINATION_SHA
         and boundary['component_qualified'] is True and boundary['native_status'] == 'completed',
         'historical or other tuple cannot occupy a new case slot')
    phone.add(boundary_row, boundary_raw)
    closure_row = descriptor(previous['closed_component'])
    need(path(closure_row['path']) == root / 'CLOSURE.json'
         and {k: closure_row[k] for k in ('bytes', 'sha256')} ==
             {k: boundary['closure'][k] for k in ('bytes', 'sha256')}, 'actual closure byte binding')
    closure_raw = pool.read(closure_row)
    closure = strict(closure_raw)
    phone.add(boundary['closure'], closure_raw)
    inventory_raw = pool.read(dict(path=str(root / 'INVENTORY.json'),
                                  **{k: boundary['inventory'][k] for k in ('bytes', 'sha256')}))
    phone.add(boundary['inventory'], inventory_raw)
    archive_row = dict(path=str(root / 'ORIGINALS.tar.gz'),
                       **{k: closure['archive'][k] for k in ('bytes', 'sha256')})
    archive_raw = pool.read(archive_row)
    with consumer.component_modules({'package_sources': bodies}) as modules:
        parser = archive_projection(bodies['source/close_component.py'], modules['component_common'])
        capture, files = parser(archive_raw, closure['capture']['sha256'])
    need(pin(files['CAPTURE.json']) == closure['capture'], 'whole original capture identity')
    for item in capture['files'].values():
        if item['kind'] == 'original_file_bytes':
            row = dict(path=item['source_path'], bytes=item['bytes'], sha256=item['sha256'],
                       metadata=item['source_metadata'])
            phone.add(row, files[item['path']])
    lease_item = capture['files']['home/LEASE.json']
    lease_row = dict(path=lease_item['source_path'], bytes=lease_item['bytes'],
                     sha256=lease_item['sha256'], metadata=lease_item['source_metadata'])
    need(lease_row['path'] == closure['lease_source_path']
         and lease_row['sha256'] == closure['lease_sha256'], 'actual full original LEASE from that capture')
    phone.read(lease_row)
    steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
    need(len(steps) == 1 and type(steps[0].get('returncode')) is int
         and steps[0]['returncode'] == 0 and steps[0].get('automatic_retry') is False,
         'one completed actual current publication')
    operation = strict(pool.read(steps[0]['stdout']))
    need(pool.read(steps[0]['stderr']) == b'' and type(operation['actor_rc']) is int
         and operation['actor_rc'] == 0 and type(operation['wrapper']['phone']['rc']) is int
         and operation['wrapper']['phone']['rc'] == 0, 'complete current original publisher outputs')
    publish_raw = operation['wrapper']['phone']['stdout'].encode('utf-8')
    published = strict(publish_raw)
    need(same(published['boundary'], boundary_row)
         and published['state'] == 'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED',
         'actual inner publication stdout, never regenerated JSON')
    return {'root_result': root_row, 'boundary': boundary_row, 'closure': closure_row,
            'archive': archive_row, 'lease': lease_row, 'publish_raw': publish_raw}


def validate_inputs(value):
    exact(value, ('schema', 'case_results', 'output_root', 'build_output_root',
                  'build_idempotency_key', 'build_timeout_seconds'), 'exact construction input')
    need(value['schema'] == SCHEMA, 'construction family')
    exact(value['case_results'], ('NEG-01', 'NEG-02'), 'two actual current case slots')
    for name in ('NEG-01', 'NEG-02'):
        need(value['case_results'][name] is not None, 'UNBOUND_ACTUAL_CURRENT_' + name + '_NO_IO')
        descriptor(value['case_results'][name], maximum=1024 * 1024)
    output = path(value['output_root']); build = path(value['build_output_root'])
    need(output.parent == build.parent == PurePosixPath(B) and output != build,
         'two explicit separate fresh host output namespaces')
    key = value['build_idempotency_key']
    need(type(key) is str and 1 <= len(key.encode()) <= 128, 'one explicit original BUILD controller key')
    need(type(value['build_timeout_seconds']) is int and 1 <= value['build_timeout_seconds'] <= 300,
         'finite original host BUILD timeout')
    return value


def derive_component_build_inputs(inputs_raw, *, read_pinned):
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_COMPONENT_BUILD_INPUTS_NO_IO')
    descriptor(FROZEN_INPUTS, maximum=65536)
    need(type(inputs_raw) is bytes and pin(inputs_raw) ==
         {k: FROZEN_INPUTS[k] for k in ('bytes', 'sha256')}, 'exact bound construction input bytes')
    value = validate_inputs(strict(inputs_raw))
    pool = Pool(read_pinned)
    consumer, release, source_rows = source_context(pool)
    manifest, copies, bodies = runtime_sources(pool, consumer)
    component = history_seed(pool, consumer, release, manifest, copies, bodies)
    phone = PhoneOriginals()
    cases = {name: collect_case(name, value['case_results'][name], pool, consumer, bodies, phone)
             for name in ('NEG-01', 'NEG-02')}
    # Traverse only original descriptors. The existing consumer below validates
    # every original schema, scope, predecessor and historical/current boundary.
    current = cases['NEG-02']['boundary']; chain = []
    while current is not None:
        need(len(chain) < consumer.CURRENT_COMPONENT_CHAIN_LENGTH, 'bounded complete original chain')
        raw = phone.read(current); boundary = strict(raw)
        phone.read(boundary['inventory']); phone.read(boundary['closure'])
        chain.append(current); current = boundary['prior_boundary']
    need(len(chain) == consumer.CURRENT_COMPONENT_CHAIN_LENGTH
         and same(chain[1], cases['NEG-01']['boundary']), 'two current cases in actual continuous order')
    for row in component['retirement'].values():
        phone.read(row)
    with consumer.component_modules({'package_sources': bodies}) as modules:
        retained = modules['late_boundary'].retained_unstarted_stage(read_pinned=phone.read)
        need(same(retained['binding'], component['retained_unstarted_stage']), 'actual retained-stage original reader')
    files = {}
    def add(name, raw):
        need(name not in files, 'one created output per relative name')
        files[name] = raw
        return located(PurePosixPath(value['output_root']) / name, raw)
    originals = []
    by_digest = {}
    for original in sorted(phone.used.values(), key=lambda row: row['path']):
        raw = phone.read(original)
        copy = by_digest.get(original['sha256'])
        if copy is None:
            copy = add('originals/' + original['sha256'] + '.original', raw)
            by_digest[original['sha256']] = copy
        originals.append(dict(phone=original, copy=copy))
    component.update(latest_boundary=cases['NEG-02']['boundary'], originals=originals,
                     publish_result=add('originals/PUBLISH-RESULT.original.json', cases['NEG-02']['publish_raw']))
    component_raw = consumer.encode(component)
    component_row = add('COMPONENT-BOUNDARY-INPUTS.json', component_raw)
    retirement_raw = pool.read(RETIREMENT_INPUTS, 65536)
    retirement = strict(retirement_raw)
    for name in ('report', 'operator', 'ancestor_retirement', 'failed_predecessor'):
        pool.read(retirement[name])
    for row in retirement.get('original_operation_evidence', []):
        pool.read({k: row[k] for k in ('path', 'bytes', 'sha256')})
    need(retirement['report']['sha256'] == component['retirement']['proof']['sha256'],
         'actual builder retirement report is the same original component retirement')
    # Build the exact existing pure bundle; no filesystem monkeypatching and no
    # fake successful fixture. New output bytes are in this private proposal map.
    proposed = {str(PurePosixPath(value['output_root']) / n): b for n, b in files.items()}
    def read(row):
        if row['path'] in proposed:
            body = proposed[row['path']]
            need(pin(body) == {k: row[k] for k in ('bytes', 'sha256')}, 'proposed exact input bytes')
            return body
        return pool.read(row)
    policy_raw = pool.read(release.FIXED['ADOPTION'])
    policy = strict(policy_raw)
    original_map = {}
    for selected in (component, policy):
        for row in consumer.descriptors(selected):
            body = read(row); packed = consumer.pack_original(body)
            need(row['sha256'] not in original_map or same(original_map[row['sha256']], packed),
                 'complete bundle duplicate digest')
            original_map[row['sha256']] = packed
    bundle = {'schema': 'hepta.r10.release-boundary-bundle.v2', 'inputs': {
        'component': {'descriptor': component_row, 'raw_b64': base64.b64encode(component_raw).decode()},
        'policy': {'descriptor': release.FIXED['ADOPTION'], 'raw_b64': base64.b64encode(policy_raw).decode()}},
        'originals': original_map}
    bundle_raw = consumer.encode(bundle)
    state = consumer.validate_bundle(bundle_raw, consumer.sha(bundle_raw))
    need(state['component_input_sha256'] == component_row['sha256']
         and state['retirement_sha256'] == retirement['report']['sha256'],
         'original consumer actual component and retirement verdict')
    args = ['-I', '-B', release.FIXED['BUILDER']['path'], '--inputs', release.FIXED['FORMAL']['path'],
            '--inputs-sha256', release.FIXED['FORMAL']['sha256'], '--output', value['build_output_root'],
            '--retirement-inputs', RETIREMENT_INPUTS['path'], '--retirement-inputs-sha256', RETIREMENT_INPUTS['sha256'],
            '--component-boundary-inputs', component_row['path'], '--component-boundary-inputs-sha256', component_row['sha256'],
            '--policy-adoption-inputs', release.FIXED['ADOPTION']['path'], '--policy-adoption-inputs-sha256', release.FIXED['ADOPTION']['sha256'],
            '--shared-materials', release.FIXED['SHARED']['path'], '--shared-materials-sha256', release.FIXED['SHARED']['sha256']]
    request = dict(host='mac', executable='/usr/bin/python3', args=args,
                   idempotency_key=value['build_idempotency_key'], timeout_seconds=value['build_timeout_seconds'])
    request_row = add('requests/BUILD.REQUEST.json', encoded(request))
    add('reference/CONSTRUCTION-INPUTS.original.json', inputs_raw)
    pool.recheck()
    report = dict(schema='hepta.fc33.actual-component-build-inputs-derived.v1',
        state='ACTUAL_COMPONENT_INPUTS_VERIFIED_BUILD_NOT_EXECUTED',
        source_derivation=SOURCE_DERIVATION, runtime=RUNTIME, source_consumer=release.FIXED['CONSUMER'],
        component_boundary_inputs=component_row, retirement_inputs=RETIREMENT_INPUTS,
        build_request=request_row, build_output_root=value['build_output_root'],
        case_results=value['case_results'], chain_length=len(state['chain']),
        current_case_order=[row[0]['case_id'] for row in state['chain'][:2]],
        current_component_qualification_from_actual_closed_originals_only=True,
        historical_source_parent_qualification_inherited=False,
        consumer_bundle_byte_pin=pin(bundle_raw), selected_phone_original_count=len(originals),
        source_file_count=len(copies), all_originals_bookended=True,
        actual_original_files=len(pool.rows), actual_original_bytes=pool.total,
        phone_calls=0, BUILD_executed=False, actual_BUILD=None, actual_install=None, actual_READY=None,
        native_dispatches=0, business_qualified=False, whole_case_pass=False,
        files=[located(PurePosixPath(value['output_root']) / name, body) for name, body in sorted(files.items())])
    files['DERIVATION.json'] = encoded(report)
    return {'files': files, 'report': report, 'build_request': request}


def meta(info):
    return [getattr(info, name) for name in META]


class HostReader:
    """Actual host originals only; no device namespace or network capability."""
    def __init__(self):
        self.observed = {}

    def __call__(self, row):
        descriptor(row)
        p = Path(row['path'])
        need(PurePosixPath(B) in path(row['path']).parents and p.resolve(strict=True) == p,
             'canonical original under this explicit host project')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['bytes'],
                 'single-link complete host original')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes'] + 1)
                need(stream.read(1) == b'', 'complete original EOF')
            need(meta(before) == meta(os.fstat(fd)) == meta(p.lstat())
                 and pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'complete host original full9 and pin')
            if row['path'] in self.observed:
                need(self.observed[row['path']] == meta(before), 'host original full9 changed between reads')
            self.observed[row['path']] = meta(before)
            return raw
        finally:
            os.close(fd)


def main():
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_COMPONENT_BUILD_INPUTS_NO_IO')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish-host-inputs-once', action='store_true', required=True)
    args = parser.parse_args()
    reader = HostReader()
    raw = reader(FROZEN_INPUTS)
    result = derive_component_build_inputs(raw, read_pinned=reader)
    output = Path(strict(raw)['output_root'])
    need(output.parent.resolve(strict=True) == output.parent, 'actual original host output parent')
    publish_material(output, result['files'])
    print(json.dumps({'state': result['report']['state'], 'derivation': located(output / 'DERIVATION.json', result['files']['DERIVATION.json']),
                      'build_request': result['report']['build_request'], 'BUILD_executed': False, 'phone_calls': 0}, sort_keys=True))


# The held-dirfd publisher is appended as an exact reviewed function derivative.

def publish_material(out,files):
 """Create a complete host artifact through held directory FDs; terminal JSON is last."""
 need(isinstance(out,Path)and out.is_absolute(),'absolute fresh material output')
 need(type(files)is dict and 'DERIVATION.json'in files,'complete material map with terminal record')
 directories=('', 'originals', 'source', 'requests', 'reference')
 for name,raw in files.items():
  need(type(name)is str and name and not any(c in name for c in '\0\r\n\t'),'plain material member')
  p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
  need(not p.is_absolute()and str(p)==name and p.name and '..'not in p.parts
   and parent in directories and name not in directories and type(raw)is bytes,'closed relative material file')
 out.mkdir(mode=0o700);created=out.lstat();handles={};identities={};members={n:set()for n in directories};observed={}
 def close_all():
  primary=sys.exc_info()[1];errors=[]
  for fd in reversed(list(handles.values())):
   try:os.close(fd)
   except BaseException as error:errors.append(error)
  if errors:
   if primary is not None:raise primary from errors[0]
   raise errors[0]
 def verify_directory(name):
  info=os.fstat(handles[name])
  if name=='':path_info=out.lstat()
  else:
   p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
   path_info=os.stat(p.name,dir_fd=handles[parent],follow_symlinks=False)
  need(stat.S_ISDIR(path_info.st_mode)and stat.S_IMODE(path_info.st_mode)==0o700
   and meta(info)[:5]==meta(path_info)[:5]==identities[name],'same owned material directory identity')
  need(set(os.listdir(handles[name]))==members[name],'exact known material directory membership')
 def verify_directories():
  for name in handles:verify_directory(name)
 def owner(name):
  p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
  return parent,p.name
 def readback(name,expected,first=False):
  parent,base=owner(name);verify_directories()
  fd=os.open(base,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=handles[parent])
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode)and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,'private single-link material output')
   with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(len(expected)+1)
   need(raw==expected and meta(before)==meta(os.fstat(fd))
    ==meta(os.stat(base,dir_fd=handles[parent],follow_symlinks=False)),'complete created material full9/byte readback')
   if first:observed[name]=meta(before)
   else:need(observed[name]==meta(before),'created material changed before terminal publication')
  finally:os.close(fd)
  verify_directories()
 def put(name,raw):
  parent,base=owner(name);verify_directories()
  fd=os.open(base,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=handles[parent])
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  members[parent].add(base);verify_directories();readback(name,raw,True)
 try:
  handles['']=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  identities['']=meta(created)[:5];verify_directory('')
  for name in directories[1:]:
   p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent);verify_directories()
   os.mkdir(p.name,mode=0o700,dir_fd=handles[parent]);members[parent].add(p.name)
   first=os.stat(p.name,dir_fd=handles[parent],follow_symlinks=False)
   handles[name]=os.open(p.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=handles[parent])
   identities[name]=meta(first)[:5];verify_directories()
  for name,raw in sorted(files.items()):
   if name!='DERIVATION.json':put(name,raw)
  for name in sorted(observed):readback(name,files[name])
  for name in reversed(directories):os.fsync(handles[name])
  verify_directories()
  put('DERIVATION.json',files['DERIVATION.json'])
  os.fsync(handles['']);verify_directories()
 finally:close_all()


if __name__ == '__main__':
    main()
