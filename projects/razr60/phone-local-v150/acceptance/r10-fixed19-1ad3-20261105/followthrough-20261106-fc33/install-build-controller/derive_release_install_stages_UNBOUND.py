#!/usr/bin/env python3
"""Progressive host construction from actual BUILD, actor and retention originals.

Each stage consumes a single pinned input document and emits complete next-step
inputs/requests. No request is dispatched by this module. Actual stage, start,
READY and capture commands come only from the already published protocols.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types
import zlib

FROZEN_INPUTS = None
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
PACKAGE_ROOT = B + '/followthrough-fc33-install-build-controller01'
HELPER = {'path': PACKAGE_ROOT + '/source/derive_component_build_inputs_UNBOUND.py',
    'bytes': 34048, 'sha256': '766f6b933b4982088925669f327e0c7c2d03855b8c3f140052d7fbfd088d1b5f'}
P4_OBSERVER = {'path': PACKAGE_ROOT + '/source/observe_p4_install_phase_UNBOUND.py',
    'bytes': 8346, 'sha256': 'e07d8e48fb81c6f80cf688b991c1d3fd2d939af85137df3f99104160cf628d32'}
CONTROLLER_READER = {'path': PACKAGE_ROOT + '/source/verify_host_controller_originals.py',
    'bytes': 16570, 'sha256': 'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'}
SCHEMA = 'hepta.fc33.release-install-stage-construction-inputs.v1'
STAGES = ('actual_build', 'install_plan', 'ingest_phase', 'phase_authority',
          'retention_first', 'ingest_capture', 'retention_remaining', 'retention_finish',
          'exact8_inputs', 'final_install_reader')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def bytepin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load_source(row, read_pinned, name):
    raw = read_pinned(dict(row))
    need(type(raw) is bytes and bytepin(raw) == {k: row[k] for k in ('bytes', 'sha256')},
         'exact complete reviewed constructor source')
    module = types.ModuleType(name); module.__file__ = row['path']
    exec(compile(raw, row['path'], 'exec'), module.__dict__)
    return module, raw


def bind_none(raw, bindings):
    """Only explicit None RHSs change; every original source byte has an inverse."""
    tree = ast.parse(raw)
    lines = raw.splitlines(keepends=True); changes = []
    for name, value in bindings.items():
        nodes = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
        need(len(nodes) == 1 and nodes[0].lineno == nodes[0].end_lineno
             and ast.literal_eval(nodes[0].value) is None, 'exact one original None literal: ' + name)
        node = nodes[0]; original = lines[node.lineno-1]
        # This order is explicit across construction and JSON transport.
        if type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}:
            value = {key: value[key] for key in ('path', 'bytes', 'sha256')}
        replacement = (name + ' = ' + repr(value) + '\n').encode()
        lines[node.lineno-1] = replacement
        changes.append(dict(line=node.lineno, before=original.decode(), after=replacement.decode()))
    candidate = b''.join(lines); reverse = candidate.splitlines(keepends=True)
    for item in changes:
        reverse[item['line']-1] = item['before'].encode()
    need(b''.join(reverse) == raw, 'complete source byte inverse')
    compile(candidate, '<bound-exact-original-inputs>', 'exec')
    return candidate, dict(parent=bytepin(raw), candidate=bytepin(candidate), changes=changes, complete_inverse=True)


def no_unknown(value):
    if value is None:
        raise ValueError('UNBOUND_ACTUAL_STAGE_INPUT_NO_IO')
    if type(value) is dict:
        for item in value.values():
            no_unknown(item)
    elif type(value) is list:
        for item in value:
            no_unknown(item)


class Context:
    def __init__(self, value, read_pinned, host_metadata):
        self.H, self.helper_raw = load_source(HELPER, read_pinned, 'reviewed_component_constructor')
        H = self.H
        H.exact(value, ('schema', 'stage', 'output_root', 'actual'), 'exact progressive stage input')
        need(value['schema'] == SCHEMA and value['stage'] in STAGES, 'one known progressive stage')
        no_unknown(value['actual'])
        root = H.path(value['output_root'])
        need(root.parent == PurePosixPath(B), 'one explicit new host output namespace')
        self.value, self.root, self.callback, self.host_metadata = value, root, read_pinned, host_metadata
        self.pool = H.Pool(read_pinned)
        self.pool.read(HELPER)
        self.consumer, self.release, self.sources = H.source_context(self.pool)
        self.files, self.extra, self.loaded = {}, {}, {}
        self.install = self.load('verify_install_start_ready_UNBOUND')
        need(self.install.FROZEN_INPUTS is None and self.install.FROZEN_EXECUTION_PLAN is None,
             'keep the exact published UNBOUND install helper for retention')
        self.protocol = self.load('install_ready_execution_protocol')

    def load(self, name):
        if name not in self.loaded:
            row = self.sources['source/' + name + '.py']
            self.loaded[name] = self.H.source_module(self.pool.read(row), row, 'reviewed_stage_' + name)
        return self.loaded[name]

    def add(self, name, raw):
        need(name not in self.files and type(raw) is bytes, 'one complete new output file')
        self.files[name] = raw
        return self.H.located(self.root / name, raw)

    def json(self, row, maximum=64 * 1024 * 1024):
        return self.H.strict(self.pool.read(row, maximum))

    def original_catalog(self, rows):
        """Add full9 for actual already-read host files, never proposed output inodes."""
        H, R = self.H, self.install
        need(callable(self.host_metadata), 'actual host full9 reader required for original maps')
        selected = {}
        def add(row):
            H.exact(row, ('namespace', 'original', 'retained'), 'complete actual original mapping')
            R.descriptor(row['original']); R.descriptor(row['retained'], metadata=True)
            need(row['namespace'] in ('host','pocket4','phone_gnu','phone_android')
                 and H.same({k:row['original'][k] for k in ('bytes','sha256')},
                            {k:row['retained'][k] for k in ('bytes','sha256')}),
                 'one exact typed original and retained byte pin')
            key = R.encoded(row['original'])
            if key in selected:
                previous = selected[key]
                need(previous['namespace'] == row['namespace'], 'conflicting original namespace')
                if not H.same(previous, row):
                    first = self.callback(previous['retained'])
                    second = self.callback(row['retained'])
                    need(type(first) is bytes and first == second
                         and bytepin(first) == {k:row['original'][k] for k in ('bytes','sha256')},
                         'both actual retained aliases have complete equal bytes and original identity')
            else:
                selected[key] = row
        for row in rows:
            add(row)
        for row, body in list(self.pool.rows.values()):
            metadata = self.host_metadata(dict(row))
            retained = dict(row, metadata=metadata)
            R.descriptor(retained, metadata=True)
            need(self.callback(retained) == body, 'actual retained host full9 and whole bytes')
            add(dict(namespace='host', original=dict(row), retained=retained))
        result = list(selected.values())
        R.Originals(result, self.callback)
        return result

    def phase_carriers(self, rows, phases):
        H = self.H
        H.exact(rows, phases, 'exact already completed phases')
        records, mapping = {}, []
        for phase in phases:
            carrier = self.json(rows[phase], 4 * 1024 * 1024)
            need(carrier['schema'] == 'hepta.fc33.install-phase-original-carrier.v1'
                 and carrier['phase'] == phase, 'actual selected phase carrier')
            records[phase] = carrier['originals']; mapping.extend(carrier['original_map'])
        return records, mapping

    def verify_release_and_plan(self, release_row, plan_row):
        raw = self.pool.read(release_row, 1024 * 1024)
        value = self.H.strict(raw)
        verdict = self.release.verify_final_release_inputs(raw, read_pinned=self.pool.read)
        plan_raw = self.pool.read(plan_row, 65536); plan = self.H.strict(plan_raw)
        self.protocol.validate_plan(plan, verdict, value)
        need(plan['release_inputs_sha256'] == bytepin(raw)['sha256'], 'same actual release input in plan')
        archive = self.pool.read(value['release_archive'])
        projection = self.release.project_installer(self.pool.read(value['installer_source']), value['release_archive'], archive)
        manifest, blobs = projection['load_release'](PurePosixPath(value['release_archive']['path']),
            value['release_archive']['sha256'], verdict['release_pins']['component_boundary_inputs_sha256'],
            verdict['release_pins']['policy_adoption_inputs_sha256'])
        return value, verdict, plan, manifest, blobs

    def finish(self, state):
        self.pool.recheck()
        report = dict(schema='hepta.fc33.release-install-stage-construction.v1', state=state,
            stage=self.value['stage'], input_source_chain=self.H.SOURCE_DERIVATION,
            immutable_install_helper=self.sources['source/verify_install_start_ready_UNBOUND.py'],
            source_slots_in_immutable_helper_remain_None=True,
            phone_calls=0, actor_dispatches=0, automatic_retry=False, business_qualified=False,
            fixed19_credit=0, all_originals_bookended=True, actual_original_files=len(self.pool.rows),
            actual_original_bytes=self.pool.total, **self.extra)
        report['files'] = [self.H.located(self.root / name, raw) for name, raw in sorted(self.files.items())]
        self.files['DERIVATION.json'] = self.H.encoded(report)
        return dict(files=self.files, report=report)


def actual_build(ctx, actual):
    H, A = ctx.H, ctx.release
    H.exact(actual, ('component_construction', 'build_result', 'build_process'), 'actual BUILD originals only')
    before = ctx.json(actual['component_construction'], 1024 * 1024)
    need(before['state'] == 'ACTUAL_COMPONENT_INPUTS_VERIFIED_BUILD_NOT_EXECUTED'
         and before['runtime'] == H.RUNTIME, 'same original component input preparation')
    build_raw = ctx.pool.read(actual['build_result'], 1024 * 1024); build = H.strict(build_raw)
    need(build.get('state') == 'SEALED_ACTUAL_RETIREMENT_BOUND', 'actual sealed BUILD result, never a fixture assertion')
    archive = build['archive']; archive_raw = ctx.pool.read(archive)
    projection = A.project_installer(ctx.pool.read(A.FIXED['INSTALLER']), archive, archive_raw)
    manifest, blobs = projection['load_release'](PurePosixPath(archive['path']), archive['sha256'],
        before['component_boundary_inputs']['sha256'], A.FIXED['ADOPTION']['sha256'])
    root = H.path(actual['build_result']['path']).parent
    writes = {row['target']: row for row in manifest['writes']}
    def target(name):
        need(name in writes, 'actual archive omitted target')
        return blobs[writes[name]['member']]
    shared = H.strict(ctx.pool.read(A.FIXED['SHARED']))
    shared_root = H.path(A.FIXED['SHARED']['path']).parent
    value = dict(schema=A.SCHEMA, boot_id=A.BOOT, release_id='v150-r10-r1',
        builder_source=A.FIXED['BUILDER'], installer_source=A.FIXED['INSTALLER'],
        formal_inputs=A.FIXED['FORMAL'], combination=A.FIXED['COMBINATION'], shared_materials=A.FIXED['SHARED'],
        shared_originals=[{'name': r['path'], 'copy': dict(path=str(shared_root/r['path']), bytes=r['bytes'], sha256=r['sha256'])}
                          for r in shared['files']],
        component_boundary_inputs=before['component_boundary_inputs'], policy_adoption=A.FIXED['ADOPTION'],
        retirement_inputs=before['retirement_inputs'], build_result=actual['build_result'], release_archive=archive,
        release_manifest=H.located(root/'release.json', blobs['release.json']),
        production_source_seal=H.located(root/'provider/SOURCE-SEAL-v150-r10.json', target(A.A+'/provider-r10-r1/SOURCE-SEAL-v150-r10.json')),
        module_manifest=H.located(root/'module/MODULE-MANIFEST-v150-r10-r1.json', target(A.MODULE+'/MODULE-MANIFEST-v150-r10-r1.json')),
        module_binding=H.located(root/'module/seal-binding.json', target(A.MODULE+'/seal-binding.json')),
        build_process=actual['build_process'])
    raw = H.encoded(value)
    verdict = A.verify_final_release_inputs(raw, read_pinned=ctx.pool.read)
    row = ctx.add('ACTUAL-RELEASE-INPUTS.json', raw)
    ctx.add('ACTUAL-RELEASE-VERDICT.json', H.encoded(verdict))
    ctx.extra.update(release_inputs=row, actual_build_result=actual['build_result'], actual_install=None, actual_READY=None)
    return ctx.finish('ACTUAL_BUILD_VERIFIED_INSTALLATION_NOT_STARTED')


def observer_values(ctx, plan, phase, mode, expected, identity, spec_path):
    H = ctx.H
    template = ctx.pool.read(P4_OBSERVER, 65536)
    value = dict(schema='hepta.fc33.p4-install-phase-file-observation.v1', phase=phase, mode=mode,
        actor=plan['actor'], request_path=identity['request_path'],
        request_base64=base64.b64encode(expected['request_raw']).decode(), request_pin=bytepin(expected['request_raw']),
        actor_operation_dir=expected['actor_operation_dir'])
    raw = H.encoded(value)
    spec_row = H.located(spec_path, raw)
    bound, change = bind_none(template, {'FROZEN_SPEC': spec_row})
    bootstrap = ('import base64\n_SOURCE=base64.b64decode('+repr(base64.b64encode(bound).decode())+',validate=True)\n'
        '_INPUT=base64.b64decode('+repr(base64.b64encode(raw).decode())+',validate=True)\n'
        '_NS={"__name__":"reviewed_p4_host_file_observer","__file__":'+repr(P4_OBSERVER['path'])+'}\n'
        'exec(compile(_SOURCE,_NS["__file__"],"exec"),_NS)\n_NS["run_bound"](_INPUT)\n')
    request = dict(host='pocket4', executable='/usr/bin/python3', args=['-I','-B','-'], stdin=bootstrap,
        idempotency_key=identity['idempotency_key']+'-host-'+mode, timeout_seconds=60)
    need(len(request['idempotency_key'].encode()) <= 128, 'separate finite one-use observation key')
    return spec_row, raw, change, request


def observer_spec(ctx, plan, phase, mode, expected, *, identity=None, member=None):
    identity = plan['phases'][phase] if identity is None else identity
    member = phase if member is None else member
    name = 'requests/'+member+'.'+mode+'.SPEC.json'
    spec_row, raw, change, request = observer_values(ctx, plan, phase, mode, expected, identity, ctx.root/name)
    need(ctx.H.same(ctx.add(name, raw), spec_row), 'one actual observer specification path')
    request_row = ctx.add('requests/'+member+'.'+mode+'.CONTROLLER.json', ctx.H.encoded(request))
    ctx.add('reference/'+member+'.'+mode+'.SOURCE-CHANGE.json', ctx.H.encoded(change))
    return request_row


def expected_observer(ctx, row, plan, phase, mode, expected, identity):
    suffix = '.'+mode+'.CONTROLLER.json'
    need(type(row['path']) is str and row['path'].endswith(suffix), 'exact derived observer request member')
    path = row['path'][:-len(suffix)] + '.'+mode+'.SPEC.json'
    spec, raw, unused, request = observer_values(ctx, plan, phase, mode, expected, identity, path)
    need(ctx.pool.read(spec, 131072) == raw and ctx.pool.read(row, 131072) == ctx.H.encoded(request),
         'observer source, exact binding/specification and request fully rederived')
    return request


def install_plan(ctx, actual):
    H, P, A = ctx.H, ctx.protocol, ctx.release
    H.exact(actual, ('release_inputs', 'actor_path', 'delivery_directory', 'identity_prefix',
                     'request_directory', 'phase_timeouts'), 'explicit actual BUILD and selected future phase identities')
    release_raw = ctx.pool.read(actual['release_inputs'], 1024 * 1024); release_inputs = H.strict(release_raw)
    release = A.verify_final_release_inputs(release_raw, read_pinned=ctx.pool.read)
    prefix = actual['identity_prefix']
    need(type(prefix) is str and re.fullmatch('[A-Za-z0-9_-]{1,60}', prefix), 'finite explicit one-use phase prefix')
    directory = P.path(actual['delivery_directory']); request_dir = P.path(actual['request_directory'])
    need(PurePosixPath(P.GNU) in directory.parents
         and (request_dir == PurePosixPath(P.P4) or PurePosixPath(P.P4) in request_dir.parents),
         'selected private original GNU delivery and P4 request directories')
    H.exact(actual['phase_timeouts'], P.PHASES, 'all three finite original phase timeouts')
    phases = {name: dict(label=prefix+'-'+name, request_path=str(request_dir/(prefix+'-'+name+'.request.json')),
              idempotency_key=prefix+'-'+name, timeout_seconds=actual['phase_timeouts'][name]) for name in P.PHASES}
    plan = dict(schema=P.PLAN_SCHEMA, boot_id=P.BOOT, release_id='v150-r10-r1',
        release_inputs_sha256=bytepin(release_raw)['sha256'], actor=dict(path=actual['actor_path'], **P.ACTOR_PIN),
        actor_python='/usr/bin/python3', actor_cwd=P.P4,
        archive=dict(path=str(directory/'phone-release-v150-r10-r1.tar.gz'),
                     **{k: release_inputs['release_archive'][k] for k in ('bytes','sha256')}),
        installer=dict(path=str(directory/'install_phone_release_r10.py'), **P.INSTALLER_PIN), phases=phases)
    P.validate_plan(plan, release, release_inputs)
    archive = ctx.pool.read(release_inputs['release_archive']); installer = ctx.pool.read(release_inputs['installer_source'])
    projection = A.project_installer(installer, release_inputs['release_archive'], archive)
    manifest, unused = projection['load_release'](PurePosixPath(release_inputs['release_archive']['path']),
        release_inputs['release_archive']['sha256'], release['release_pins']['component_boundary_inputs_sha256'],
        release['release_pins']['policy_adoption_inputs_sha256'])
    plan_row = ctx.add('EXECUTION-PLAN.json', H.encoded(plan))
    requests = {}
    for name in P.PHASES:
        expected = P.expected_phase(plan, name, release, release_inputs, manifest['_boundary']['retirement_sha256'])
        request_row = ctx.add('requests/'+name+'.request.json', expected['request_raw'])
        dispatch = ctx.add('requests/'+name+'.DISPATCH.json', H.encoded(expected['dispatch']))
        before = observer_spec(ctx, plan, name, 'prepare', expected)
        after = observer_spec(ctx, plan, name, 'collect', expected)
        requests[name] = dict(request=request_row, dispatch=dispatch, before_observer=before, after_observer=after,
                              actor_operation_dir=expected['actor_operation_dir'], wire_bytes=expected['wire_bytes'])
    ctx.extra.update(release_inputs=actual['release_inputs'], execution_plan=plan_row, phase_requests=requests,
        actual_stage=None, actual_start=None, actual_READY=None, actual_install=None,
        delivery_sources=dict(archive=release_inputs['release_archive'], installer=release_inputs['installer_source']),
        delivery_destinations=dict(archive=plan['archive'], installer=plan['installer']))
    return ctx.finish('ACTUAL_BUILD_BOUND_PHASE_REQUESTS_DERIVED_NOT_DISPATCHED')


def decode_observation(ctx, controller_row, expected_request):
    H = ctx.H
    record = ctx.json(controller_row, 16 * 1024 * 1024)
    need(H.same(record['request'], expected_request), 'actual P4 observer request equals exact derived source/spec')
    reader, unused = load_source(CONTROLLER_READER, ctx.pool.read, 'reviewed_complete_host_controller_reader')
    job, status, outputs = reader.controller(record, code=0, complete=True)
    transfer = H.strict(outputs['stdout'])
    need(outputs['stderr'] == b'' and transfer['schema'] == 'hepta.fc33.p4-install-phase-original-transfer.v1'
         and transfer['phone_calls'] == 0 and transfer['actor_executed'] is False, 'actual host-only P4 observer output')
    compressed = base64.b64decode(transfer['raw_zlib_base64'], validate=True)
    decoder = zlib.decompressobj(); raw = decoder.decompress(compressed, 12 * 1024 * 1024 + 1)
    need(len(raw) <= 12 * 1024 * 1024 and decoder.eof and not decoder.unused_data
         and not decoder.unconsumed_tail and bytepin(raw) == transfer['original'],
         'whole bounded P4 observation carrier')
    value = H.strict(raw)
    need(value['schema'] == 'hepta.fc33.p4-install-phase-original-files.v1'
         and value['phone_calls'] == 0 and value['actor_executed'] is False
         and value['source_full9_bookended'] is True and value['qualified'] is False,
         'actual original file observation without phase qualification')
    need(value['mode'] in ('prepare','collect')
         and value['request_created_here'] is (value['mode'] == 'prepare'),
         'exact original observation write classification')
    files = {}
    for item in value['files']:
        H.exact(item, ('role','original','raw_base64','eof'), 'complete retained P4 observation file')
        H.descriptor(item['original'], metadata=True)
        body = base64.b64decode(item['raw_base64'], validate=True)
        need(item['eof'] is True and base64.b64encode(body).decode() == item['raw_base64']
             and bytepin(body) == {k:item['original'][k] for k in ('bytes','sha256')}
             and item['role'] not in files, 'complete actual P4 source bytes/full9')
        files[item['role']] = (item['original'], body)
    value['_controller_authority'] = dict(created_unix_ms=job['created_unix_ms'], terminal_unix_ms=status['at_unix_ms'])
    return value, files


def ingest_phase(ctx, actual):
    H = ctx.H
    H.exact(actual, ('plan_construction','phase','actor_controller','before_observer','after_observer'), 'actual one phase and original controller observations')
    report = ctx.json(actual['plan_construction'], 1024 * 1024)
    need(report['state'] == 'ACTUAL_BUILD_BOUND_PHASE_REQUESTS_DERIVED_NOT_DISPATCHED', 'actual plan construction record')
    phase = actual['phase']; need(phase in ctx.protocol.PHASES, 'one original phase')
    release_inputs, release, plan, manifest, unused = ctx.verify_release_and_plan(report['release_inputs'], report['execution_plan'])
    expected = ctx.protocol.expected_phase(plan, phase, release, release_inputs, manifest['_boundary']['retirement_sha256'])
    requests = report['phase_requests'][phase]
    before, first = decode_observation(ctx, actual['before_observer'], expected_observer(ctx,
        requests['before_observer'], plan, phase, 'prepare', expected, plan['phases'][phase]))
    after, last = decode_observation(ctx, actual['after_observer'], expected_observer(ctx,
        requests['after_observer'], plan, phase, 'collect', expected, plan['phases'][phase]))
    need(before['mode'] == 'prepare' and after['mode'] == 'collect'
         and before['phase'] == after['phase'] == phase
         and set(first) == {'actor','request'} and set(last) == {'actor','request','intent','baseline','result'},
         'actual pre-dispatch and post-terminal file observations')
    need(H.same(first['actor'][0], last['actor'][0]) and first['actor'][1] == last['actor'][1]
         and H.same(first['request'][0], last['request'][0]) and first['request'][1] == last['request'][1] == expected['request_raw'],
         'same original actor and request across the actual call')
    record = ctx.json(actual['actor_controller'], 4 * 1024 * 1024)
    need(H.same(record['request'], expected['dispatch']), 'original dispatched actor request exact')
    reader, unused = load_source(CONTROLLER_READER, ctx.pool.read, 'reviewed_actor_controller_transport_reader')
    job, status, streams = reader.controller(record, code=0, complete=True)
    need(before['_controller_authority']['terminal_unix_ms'] <= job['created_unix_ms']
         and status['at_unix_ms'] <= after['_controller_authority']['created_unix_ms'],
         'actual host observations surround the one original actor invocation')
    # The complete existing install reader separately checks the actor summary,
    # inner phone rc, guard and phase effect. Here preserve the original bytes.
    result = H.strict(last['result'][1]); phone = result['phone']
    need(type(phone['stdout']) is str and type(phone['stderr']) is str, 'complete original actor phone streams')
    stdout, stderr = phone['stdout'].encode(), phone['stderr'].encode()
    need(stderr.startswith(ctx.protocol.RECEIPT_PREFIX), 'actual phase source guard receipt')
    line, separator, tail = stderr[len(ctx.protocol.RECEIPT_PREFIX):].partition(b'\n')
    need(separator and not tail, 'one complete actual guard receipt')
    guard = H.strict(line); source_row = guard['source']
    ctx.install.descriptor(source_row, metadata=True)
    need({k:source_row[k] for k in ('path','bytes','sha256')} == expected['spec']['source'], 'same actual guard source')
    source_host = ctx.release.FIXED['READINESS' if phase=='ready' else 'INSTALLER']
    source_raw = ctx.pool.read(source_host)
    need(bytepin(source_raw) == {k:source_row[k] for k in ('bytes','sha256')}, 'guard-attested exact original source bytes')
    raw_root = str(ctx.root) + '-originals'; files = {}; origins = {}; specs = {}
    def add(name, raw, namespace=None, original=None):
        relative = 'originals/'+name
        need(relative not in files, 'one retained phase original')
        files[relative] = raw
        row = H.located(PurePosixPath(raw_root)/relative, raw)
        if original is not None:
            origins[relative] = dict(namespace=namespace, original=original)
        return row
    for role, (original, raw) in last.items():
        add('p4-'+role+'.original', raw, 'pocket4', original)
        specs[role] = original
    # A separate pre-observation is retained even when its actor bytes and full9
    # equal the post-observation; the observer controllers remain pinned above.
    specs['actor_before'] = first['actor'][0]
    process = {}
    for name in ('dispatch','start','status','read'):
        body = record['request'] if name == 'dispatch' else record[name]
        row = add('controller-'+name+'.original.json', H.encoded(body))
        origins['originals/controller-'+name+'.original.json'] = dict(namespace='host', original=row)
        process[name] = row
    stdout_row = add('phone-stdout.original', stdout)
    stderr_row = add('phone-stderr.original', stderr)
    origins['originals/phone-stdout.original'] = dict(namespace='host', original=stdout_row)
    origins['originals/phone-stderr.original'] = dict(namespace='host', original=stderr_row)
    add('guard-attested-source.original.py', source_raw, 'phone_gnu', source_row)
    originals = dict(process=process, actor_source_before=specs['actor_before'], actor_source_after=specs['actor'],
        request=specs['request'], intent=specs['intent'], baseline=specs['baseline'], result=specs['result'],
        phone_stdout=stdout_row, phone_stderr=stderr_row)
    files['DERIVATION.json'] = H.encoded(dict(schema='hepta.fc33.phase-originals-materialization.v1',
        phase=phase, source_controller=actual['actor_controller'], actual_original_observations=dict(before=actual['before_observer'],after=actual['after_observer']),
        original_specs=origins, files=[H.located(PurePosixPath(raw_root)/n,b) for n,b in sorted(files.items())],
        phase_qualification='PENDING_EXISTING_INSTALL_READER', phone_calls=0, actor_dispatches=0))
    ctx.pool.recheck()
    return dict(materialize_phase=True, raw_output_root=raw_root, raw_files=files, origins=origins,
        phase=phase, originals=originals, release_inputs=report['release_inputs'], execution_plan=report['execution_plan'],
        input_originals=actual, output_root=str(ctx.root), actual_controller_job=job['id'] if type(job)is dict else job)


def phase_authority(ctx, actual):
    H, R = ctx.H, ctx.install
    H.exact(actual, ('release_inputs','execution_plan','phase','phase_carriers'), 'completed phase authority bindings')
    phase = actual['phase']; need(phase in ('stage','start'), 'only stage/start original retention authority')
    order = ('stage',) if phase == 'stage' else ('stage','start')
    records, mapping = ctx.phase_carriers(actual['phase_carriers'], order)
    ctx.verify_release_and_plan(actual['release_inputs'], actual['execution_plan'])
    retention = ctx.load('verify_install_retention_UNBOUND')
    ctx.pool.read(retention.PRODUCER)
    catalog = ctx.original_catalog(mapping)
    value = dict(schema=retention.AUTH_SCHEMA, phase=phase, release_inputs=actual['release_inputs'],
        execution_plan=actual['execution_plan'], phases=records, original_map=catalog)
    raw = H.encoded(value); row = ctx.add('PHASE-AUTHORITY.json', raw)
    source_row = ctx.sources['source/verify_install_retention_UNBOUND.py']; parent = ctx.pool.read(source_row)
    source, change = bind_none(parent, {'FROZEN_PHASE_AUTHORITY': row})
    selected = H.source_module(source, H.located(ctx.root/'source/verify_phase_retention_BOUND.py', source), 'actual_phase_retention_candidate')
    scope_raw = selected.derive_scope_from_actual_phase(raw, read_pinned=ctx.callback)
    scope = ctx.add('RETENTION-SCOPE.json', scope_raw)
    bound = ctx.add('source/verify_phase_retention_BOUND.py', source)
    ctx.add('reference/RETENTION-SOURCE-CHANGE.json', H.encoded(change))
    ctx.extra.update(phase=phase, phase_authority=row, scope=scope, phase_retention_reader=bound,
        release_inputs=actual['release_inputs'], execution_plan=actual['execution_plan'], actual_captures=None,
        actual_install=None, actual_READY=None)
    return ctx.finish('ACTUAL_PHASE_VERIFIED_RETENTION_SCOPE_DERIVED_NOT_CAPTURED')


# Retention and final-reader stages are defined below. No operation dispatcher is
# part of this source; publication writes only newly created host artifact trees.

def retention_context(ctx, authority_report_row):
    """Reload only the exact original reader plus its one reviewed literal."""
    H = ctx.H
    report = ctx.json(authority_report_row, 4 * 1024 * 1024)
    need(report['state'] == 'ACTUAL_PHASE_VERIFIED_RETENTION_SCOPE_DERIVED_NOT_CAPTURED',
         'actual phase authority construction record')
    parent_row = ctx.sources['source/verify_install_retention_UNBOUND.py']
    parent = ctx.pool.read(parent_row)
    expected_source, change = bind_none(parent, {'FROZEN_PHASE_AUTHORITY': report['phase_authority']})
    actual_source = ctx.pool.read(report['phase_retention_reader'])
    need(actual_source == expected_source, 'complete original retention reader single-literal inverse')
    T = H.source_module(actual_source, report['phase_retention_reader'], 'actual_verified_phase_retention_reader')
    authority_raw = ctx.pool.read(report['phase_authority'], 4 * 1024 * 1024)
    scope_raw, context = T._derive_authority(authority_raw, ctx.callback)
    need(scope_raw == ctx.pool.read(report['scope'], 32768), 'complete scope independently rederived from actual phase')
    return T, context, report, scope_raw


def capture_identity(ctx, context, prefix, directory, suffix):
    need(type(prefix) is str and re.fullmatch('[A-Za-z0-9_-]{1,52}', prefix),
         'explicit finite capture identity prefix')
    p = context['P'].path(directory)
    need(PurePosixPath(context['P'].P4) in p.parents or p == PurePosixPath(context['P'].P4),
         'explicit established P4 request directory')
    label = prefix + '-' + context['authority_value']['phase'] + '-' + suffix
    identity = dict(label=label, request_path=str(p / (label + '.request.json')), idempotency_key=label)
    context['C'].exact(identity, ('label','request_path','idempotency_key'), 'fresh complete capture identity')
    for field in identity:
        need(identity[field] not in {v[field] for v in context['plan']['phases'].values()},
             'capture identity separate from all original install phases')
    return identity


def capture_request(ctx, T, context, scope_raw, op_raw, identity, number):
    T.lease(context['C'], context['P'], identity)
    expected = T.expected_operation(context['C'], context['P'], context['template'], scope_raw,
                                    op_raw, identity, context['plan'])
    member = 'capture-' + str(number).zfill(2)
    operation = ctx.add('requests/' + member + '.OPERATION.json', op_raw)
    request = ctx.add('requests/' + member + '.request.json', expected['request_raw'])
    dispatch = ctx.add('requests/' + member + '.DISPATCH.json', ctx.H.encoded(expected['dispatch']))
    phase = context['authority_value']['phase']
    before = observer_spec(ctx, context['plan'], phase, 'prepare', expected, identity=identity, member=member)
    after = observer_spec(ctx, context['plan'], phase, 'collect', expected, identity=identity, member=member)
    return dict(number=number, identity=identity, operation=operation, request=request,
        dispatch=dispatch, before_observer=before, after_observer=after,
        actor_operation_dir=expected['actor_operation_dir'], wire_bytes=expected['wire_bytes'])


def retention_first(ctx, actual):
    H = ctx.H
    H.exact(actual, ('phase_authority_construction','identity_prefix','request_directory'),
            'actual authority and explicit one-use first-manifest identity')
    T, context, report, scope_raw = retention_context(ctx, actual['phase_authority_construction'])
    identity = capture_identity(ctx, context, actual['identity_prefix'], actual['request_directory'], 'manifest-first')
    entry = capture_request(ctx, T, context, scope_raw, context['C'].manifest_operation(), identity, 0)
    ctx.extra.update(phase_authority_construction=actual['phase_authority_construction'],
        phase=report['phase'], phase_authority=report['phase_authority'], scope=report['scope'],
        capture_requests=[entry], actual_first_capture=None, actual_install=None, actual_READY=None)
    return ctx.finish('ACTUAL_PHASE_BOUND_FIRST_RETENTION_MANIFEST_REQUEST_NOT_DISPATCHED')


def read_capture_plan(ctx, row):
    plan = ctx.json(row, 4 * 1024 * 1024)
    need(plan['state'] in ('ACTUAL_PHASE_BOUND_FIRST_RETENTION_MANIFEST_REQUEST_NOT_DISPATCHED',
                          'ACTUAL_FIRST_MANIFEST_VERIFIED_REMAINING_CAPTURE_REQUESTS_NOT_DISPATCHED'),
         'actual derived retention capture request plan')
    T, context, authority, scope_raw = retention_context(ctx, plan['phase_authority_construction'])
    need(ctx.H.same(plan['phase_authority'], authority['phase_authority'])
         and ctx.H.same(plan['scope'], authority['scope']) and plan['phase'] == authority['phase'],
         'same original phase/scope in capture request plan')
    entries = plan['capture_requests']
    need(type(entries) is list and 1 <= len(entries) <= 36, 'finite complete capture requests')
    seen = {field: set() for field in ('label','request_path','idempotency_key')}
    for number, entry in enumerate(entries):
        need(type(entry['number']) is int and entry['number'] == number, 'exact sequential capture request numbers')
        T.lease(context['C'], context['P'], entry['identity'])
        for field in seen:
            v = entry['identity'][field]
            need(v not in seen[field] and v not in {x[field] for x in context['plan']['phases'].values()},
                 'all capture and installation identities are distinct')
            seen[field].add(v)
        op_raw = ctx.pool.read(entry['operation'], 32768)
        expected = T.expected_operation(context['C'], context['P'], context['template'], scope_raw,
                                        op_raw, entry['identity'], context['plan'])
        need(ctx.pool.read(entry['request'], 65536) == expected['request_raw']
             and ctx.H.same(ctx.json(entry['dispatch'], 65536), expected['dispatch'])
             and entry['actor_operation_dir'] == expected['actor_operation_dir']
             and type(entry['wire_bytes']) is int and entry['wire_bytes'] == expected['wire_bytes'],
             'each capture request byte-for-byte rederived from original protocol')
    need(ctx.pool.read(entries[0]['operation'], 32768) == context['C'].manifest_operation(),
         'first original capture is the manifest operation')
    return plan, T, context, authority, scope_raw


def capture_carrier(ctx, row, entry):
    carrier = ctx.json(row, 4 * 1024 * 1024)
    need(carrier['schema'] == 'hepta.fc33.retention-capture-original-carrier.v1'
         and ctx.H.same(carrier['identity'], entry['identity'])
         and ctx.H.same(carrier['operation'], entry['operation']),
         'exact original operation carrier and identity')
    return carrier


def verify_first_capture(ctx, plan, T, context, scope_raw, carrier_row):
    entry = plan['capture_requests'][0]
    carrier = capture_carrier(ctx, carrier_row, entry)
    catalog = ctx.original_catalog(context['authority_value']['original_map'] + carrier['original_map'])
    pool = ctx.install.Originals(catalog, ctx.callback)
    expected = T.expected_operation(context['C'], context['P'], context['template'], scope_raw,
        context['C'].manifest_operation(), entry['identity'], context['plan'])
    raw, observed = T.verify_capture_actor(ctx.install, context['C'], carrier['originals'], expected,
                                            entry['identity'], context['plan'], pool)
    need(context['last_phase']['authority']['terminal_unix_ms'] <= observed['created_unix_ms'],
         'actual phase completed before the original first capture')
    context['C'].validate_manifest(scope_raw, raw)
    pool.recheck()
    return raw, carrier


def retention_remaining(ctx, actual):
    H = ctx.H
    H.exact(actual, ('first_capture_plan','first_capture_carrier','identity_prefix','request_directory'),
            'actual first original capture, explicit remaining capture identities')
    plan, T, context, authority, scope_raw = read_capture_plan(ctx, actual['first_capture_plan'])
    need(len(plan['capture_requests']) == 1, 'first-manifest plan only')
    first_raw, carrier = verify_first_capture(ctx, plan, T, context, scope_raw, actual['first_capture_carrier'])
    operations = context['C'].chunk_operations(scope_raw, first_raw) + [context['C'].manifest_operation()]
    entries = list(plan['capture_requests'])
    for number, op_raw in enumerate(operations, 1):
        suffix = 'manifest-last' if number == len(operations) else 'chunk-' + str(number).zfill(2)
        identity = capture_identity(ctx, context, actual['identity_prefix'], actual['request_directory'], suffix)
        need(all(identity[k] != entry['identity'][k] for entry in entries for k in identity),
             'fresh exact identity for each remaining operation')
        entries.append(capture_request(ctx, T, context, scope_raw, op_raw, identity, number))
    need(4 <= len(entries) <= 36, 'unchanged complete bounded retention operation count')
    ctx.extra.update(phase_authority_construction=plan['phase_authority_construction'],
        phase=authority['phase'], phase_authority=authority['phase_authority'], scope=authority['scope'],
        first_capture_plan=actual['first_capture_plan'], first_capture_carrier=actual['first_capture_carrier'],
        first_manifest=bytepin(first_raw), capture_requests=entries,
        actual_remaining_captures=None, actual_install=None, actual_READY=None)
    return ctx.finish('ACTUAL_FIRST_MANIFEST_VERIFIED_REMAINING_CAPTURE_REQUESTS_NOT_DISPATCHED')


def ingest_capture(ctx, actual):
    H = ctx.H
    H.exact(actual, ('capture_plan','operation_index','actor_controller','before_observer','after_observer'),
            'one actual retention operation and original host observations')
    plan, T, context, authority, scope_raw = read_capture_plan(ctx, actual['capture_plan'])
    number = actual['operation_index']
    need(type(number) is int and 0 <= number < len(plan['capture_requests']), 'exact original capture index')
    entry = plan['capture_requests'][number]
    op_raw = ctx.pool.read(entry['operation'], 32768)
    expected = T.expected_operation(context['C'], context['P'], context['template'], scope_raw,
                                    op_raw, entry['identity'], context['plan'])
    before, first = decode_observation(ctx, actual['before_observer'], expected_observer(ctx,
        entry['before_observer'], context['plan'], plan['phase'], 'prepare', expected, entry['identity']))
    after, last = decode_observation(ctx, actual['after_observer'], expected_observer(ctx,
        entry['after_observer'], context['plan'], plan['phase'], 'collect', expected, entry['identity']))
    need(before['mode'] == 'prepare' and after['mode'] == 'collect'
         and before['phase'] == after['phase'] == plan['phase']
         and set(first) == {'actor','request'} and set(last) == {'actor','request','intent','baseline','result'}
         and H.same(first['actor'][0], last['actor'][0]) and first['actor'][1] == last['actor'][1]
         and H.same(first['request'][0], last['request'][0])
         and first['request'][1] == last['request'][1] == expected['request_raw'],
         'complete actual capture actor/request before-and-after identity')
    record = ctx.json(actual['actor_controller'], 4 * 1024 * 1024)
    need(H.same(record['request'], expected['dispatch']), 'one exact original capture actor dispatch')
    reader, unused = load_source(CONTROLLER_READER, ctx.pool.read, 'actual_capture_controller_transport')
    job, status, streams = reader.controller(record, code=0, complete=True)
    need(before['_controller_authority']['terminal_unix_ms'] <= job['created_unix_ms']
         and status['at_unix_ms'] <= after['_controller_authority']['created_unix_ms'],
         'actual host observations surround the original capture operation')
    result = H.strict(last['result'][1]); phone = result['phone']
    need(type(phone['stdout']) is str and type(phone['stderr']) is str
         and len(phone['stdout'].encode()) <= context['C'].MAX_RECORD,
         'complete original bounded capture response, never a reconstructed result')
    raw_root = str(ctx.root) + '-originals'; files = {}; origins = {}; specs = {}
    def add(name, raw, namespace=None, original=None):
        relative = 'originals/' + name
        need(relative not in files, 'one retained actual capture original')
        files[relative] = raw
        row = H.located(PurePosixPath(raw_root) / relative, raw)
        origins[relative] = dict(namespace=namespace or 'host', original=original if original is not None else row)
        return row
    for role, (original, raw) in last.items():
        add('p4-' + role + '.original', raw, 'pocket4', original); specs[role] = original
    process = {}
    for name in ('dispatch','start','status','read'):
        body = record['request'] if name == 'dispatch' else record[name]
        process[name] = add('controller-' + name + '.original.json', H.encoded(body))
    stdout = add('phone-stdout.original', phone['stdout'].encode())
    stderr = add('phone-stderr.original', phone['stderr'].encode())
    originals = dict(process=process, actor_source_before=first['actor'][0], actor_source_after=specs['actor'],
        request=specs['request'], intent=specs['intent'], baseline=specs['baseline'], result=specs['result'],
        phone_stdout=stdout, phone_stderr=stderr)
    files['DERIVATION.json'] = H.encoded(dict(schema='hepta.fc33.capture-originals-materialization.v1',
        phase=plan['phase'], identity=entry['identity'], operation=entry['operation'], source_controller=actual['actor_controller'],
        original_specs=origins, files=[H.located(PurePosixPath(raw_root)/n,b) for n,b in sorted(files.items())],
        qualification='PENDING_EXISTING_RETENTION_READER', phone_calls=0, actor_dispatches=0))
    ctx.pool.recheck()
    return dict(materialize_phase=True, raw_output_root=raw_root, raw_files=files, origins=origins,
        phase=plan['phase'], originals=originals, identity=entry['identity'], operation=entry['operation'],
        phase_authority_construction=plan['phase_authority_construction'], input_originals=actual,
        output_root=str(ctx.root), actual_controller_job=job['id'])


def retention_finish(ctx, actual):
    H = ctx.H
    H.exact(actual, ('capture_plan','capture_carriers','retention_output_root'),
            'complete actual capture sequence and new retained originals namespace')
    plan, T, context, authority, scope_raw = read_capture_plan(ctx, actual['capture_plan'])
    need(plan['state'] == 'ACTUAL_FIRST_MANIFEST_VERIFIED_REMAINING_CAPTURE_REQUESTS_NOT_DISPATCHED'
         and type(actual['capture_carriers']) is list
         and len(actual['capture_carriers']) == len(plan['capture_requests'])
         and H.same(actual['capture_carriers'][0], plan['first_capture_carrier']),
         'all actual operation originals, preserving the original first capture')
    output = H.path(actual['retention_output_root'])
    need(output.parent == PurePosixPath(B) and output != ctx.root, 'separate fresh retained full-original namespace')
    operations, mapping = [], list(context['authority_value']['original_map'])
    for row, entry in zip(actual['capture_carriers'], plan['capture_requests']):
        carrier = capture_carrier(ctx, row, entry)
        operations.append(dict(identity=entry['identity'], originals=carrier['originals']))
        mapping.extend(carrier['original_map'])
    catalog = ctx.original_catalog(mapping)
    value = dict(schema=T.INPUT_SCHEMA, phase_authority=authority['phase_authority'], scope=authority['scope'],
                 operations=operations, original_map=catalog)
    raw = H.encoded(value); row = ctx.add('RETENTION-INPUTS.json', raw)
    parent = ctx.pool.read(ctx.sources['source/verify_install_retention_UNBOUND.py'])
    source, change = bind_none(parent, {'FROZEN_PHASE_AUTHORITY': authority['phase_authority'],
                                      'FROZEN_RETENTION_INPUTS': row})
    bound_row = ctx.add('source/verify_install_retention_BOUND.py', source)
    bound = H.source_module(source, bound_row, 'actual_completed_installation_retention')
    verified = bound.verify_retention_inputs(raw, read_pinned=ctx.callback)
    ctx.add('reference/RETENTION-SOURCE-CHANGE.json', H.encoded(change))
    ctx.extra.update(phase=plan['phase'], phase_authority=authority['phase_authority'], scope=authority['scope'],
        retention_inputs=row, retention_reader=bound_row, retention_output_root=str(output),
        retained_originals=None, actual_install=None, actual_READY=None,
        original_operation_count=verified['original_operation_count'])
    result = ctx.finish('ACTUAL_COMPLETE_RETENTION_OPERATIONS_VERIFIED_PUBLICATION_PENDING')
    result.update(materialize_retention=True, retention_reader=bound, retention_inputs_raw=raw,
                  retention_output_root=str(output), callback=ctx.callback)
    return result


def retention_originals(ctx, rows):
    """Reverify both actual capture sequences before selecting the five originals."""
    H = ctx.H
    H.exact(rows, ('stage','start'), 'two actual completed retention constructions')
    mapping, selected = [], {}
    parent = ctx.pool.read(ctx.sources['source/verify_install_retention_UNBOUND.py'])
    for phase in ('stage','start'):
        report = ctx.json(rows[phase], 4 * 1024 * 1024)
        need(report['state'] == 'ACTUAL_INSTALLATION_ORIGINAL_BYTES_RETAINED'
             and report['phase'] == phase, 'actual complete phase retention publication')
        inputs = report['retention_inputs']; authority = report['phase_authority']
        expected, unused = bind_none(parent, {'FROZEN_PHASE_AUTHORITY': authority,
                                            'FROZEN_RETENTION_INPUTS': inputs})
        source_raw = ctx.pool.read(report['retention_reader'])
        need(source_raw == expected, 'complete retention reader inverse to same published source')
        T = H.source_module(source_raw, report['retention_reader'], 'verified_actual_retention_' + phase)
        verified = T.verify_retention_inputs(ctx.pool.read(inputs, 4 * 1024 * 1024), read_pinned=ctx.callback)
        result = ctx.json(report['retained_originals'], 65536)
        need(result['schema'] == 'hepta.install-original-retention.retained.v1'
             and result['state'] == 'COMPLETE_INSTALLATION_ORIGINAL_BYTES_RETAINED'
             and H.same(result['scope'], verified['scope_pin'])
             and H.same(result['installation_generation'], verified['scope']['installation_generation'])
             and type(result['original_operation_count']) is int
             and result['original_operation_count'] == verified['original_operation_count']
             and result['actual_install_or_READY_qualified'] is False,
             'actual retained publication matches all original capture operations')
        expected_rows = {row['path']: row for row in verified['files']}
        observed_rows = result['original_map']
        need(type(observed_rows) is list and len(observed_rows) == len(expected_rows),
             'complete original retention role set')
        seen = set()
        for row in observed_rows:
            H.exact(row, ('namespace','original','retained'), 'actual retained original/full9 mapping')
            original = row['original']; name = original['path']
            need(name in expected_rows and name not in seen and row['namespace'] == 'phone_gnu',
                 'only exact selected installation originals')
            expected_row = expected_rows[name]
            need(H.same(original, {k:expected_row[k] for k in ('path','bytes','sha256','metadata')}),
                 'actual full original descriptor equals independently reassembled manifest')
            ctx.install.descriptor(row['retained'], metadata=True)
            need(ctx.callback(row['retained']) == verified['bodies'][expected_row['role']],
                 'actual retained full bytes equal the original capture reassembly')
            role = expected_row['role']; need(role not in selected, 'one source for every installation role')
            selected[role] = original; mapping.append(row); seen.add(name)
    H.exact(selected, ('install_intent','staged','preservation','start_intent','started'),
            'all five actual complete installation originals')
    return selected, mapping


def installed_catalog(ctx, row):
    value = ctx.json(row, 4 * 1024 * 1024)
    need(type(value) is list and 1 <= len(value) <= 128,
         'actual explicitly retained installed-original map; no path-only placeholders')
    for item in value:
        ctx.H.exact(item, ('namespace','original','retained'), 'one original installed-file mapping')
        need(item['namespace'] == 'phone_gnu', 'actual GNU observation namespace for installed resident originals')
        ctx.install.descriptor(item['original'], metadata=True)
        ctx.install.descriptor(item['retained'], metadata=True)
    ctx.install.Originals(value, ctx.callback)
    return value


def exact8_inputs(ctx, actual):
    H, R = ctx.H, ctx.install
    H.exact(actual, ('release_inputs','execution_plan','phase_carriers','retention_constructions','installed_original_map'),
            'actual complete release, phases, retained installation and installed resident originals')
    release_inputs, release, plan, manifest, blobs = ctx.verify_release_and_plan(actual['release_inputs'], actual['execution_plan'])
    phases, mapping = ctx.phase_carriers(actual['phase_carriers'], R.PHASES)
    five, retained = retention_originals(ctx, actual['retention_constructions'])
    mapping.extend(retained); mapping.extend(installed_catalog(ctx, actual['installed_original_map']))
    E = ctx.load('verify_resident_output_bindings')
    catalog = ctx.original_catalog(mapping); pool = R.Originals(catalog, ctx.callback)
    verified_phases = {name:R.verify_phase(name, phases[name], plan, release, release_inputs,
        manifest['_boundary']['retirement_sha256'], ctx.protocol, pool) for name in R.PHASES}
    for a,b in (('stage','start'),('start','ready')):
        need(verified_phases[a]['authority']['terminal_unix_ms'] <= verified_phases[b]['authority']['created_unix_ms'],
             'actual complete phase order before origin derivation')
    R.verify_install_originals(five, release, release_inputs, (manifest,blobs), verified_phases, pool)
    def original(path):
        found = [row['original'] for row in catalog if row['namespace'] == 'phone_gnu'
                 and row['original']['path'] == path and 'metadata' in row['original']]
        need(len(found) == 1, 'one exact actual installed original for ' + path)
        return found[0]
    value = dict(schema=E.SCHEMA, release_inputs=actual['release_inputs'],
        ready=dict(source=original(E.READY_PATH), original=phases['ready']['phone_stdout']),
        module_originals={key:original(E.MODULE+'/'+name) for key,name in
            (('manifest','MODULE-MANIFEST-v150-r10-r1.json'),('binding','seal-binding.json'),
             ('service','service.sh'),('helper','resident_owner_terminal.py'))},
        role_identity_originals={role:original(E.CLAIM+'/'+role+'.identity') for role in E.FOUR},
        child_bindings={role:original(E.CLAIM+'/owner-'+role+'.bind.json') for role in E.ROLES})
    raw = H.encoded(value)
    verdict = E.verify_resident_output_bindings(raw, read_pinned=pool.read)
    need(pool.read(value['ready']['original'], 1024 * 1024) == verified_phases['ready']['phone_stdout'],
         'exact8 uses the original actual READY actor stdout')
    pool.recheck()
    row = ctx.add('EIGHT-STREAM-INPUTS.json', raw)
    ctx.add('EIGHT-STREAM-VERDICT.json', H.encoded(verdict))
    map_row = ctx.add('ORIGINAL-MAP.json', H.encoded(catalog))
    ctx.extra.update(release_inputs=actual['release_inputs'], execution_plan=actual['execution_plan'],
        eight_stream_inputs=row, original_map=map_row, phase_carriers=actual['phase_carriers'],
        retention_constructions=actual['retention_constructions'], installed_original_map=actual['installed_original_map'],
        actual_install_qualified_by_this_constructor=False, actual_READY_qualified_by_this_constructor=False)
    return ctx.finish('ACTUAL_EIGHT_STREAM_INPUTS_VERIFIED_FINAL_INSTALL_READER_NOT_YET_BOUND')


def final_install_reader(ctx, actual):
    H, R = ctx.H, ctx.install
    H.exact(actual, ('exact8_construction',), 'actual exact8 input construction original')
    report = ctx.json(actual['exact8_construction'], 4 * 1024 * 1024)
    need(report['state'] == 'ACTUAL_EIGHT_STREAM_INPUTS_VERIFIED_FINAL_INSTALL_READER_NOT_YET_BOUND',
         'actual exact8 construction state')
    ctx.verify_release_and_plan(report['release_inputs'], report['execution_plan'])
    phases, mapping = ctx.phase_carriers(report['phase_carriers'], R.PHASES)
    five, retained = retention_originals(ctx, report['retention_constructions'])
    mapping.extend(retained); mapping.extend(ctx.json(report['original_map'], 4 * 1024 * 1024))
    ctx.pool.read(report['eight_stream_inputs'], 1024 * 1024)
    ctx.pool.read(ctx.sources['source/verify_resident_output_bindings.py'])
    catalog = ctx.original_catalog(mapping)
    value = dict(schema=R.SCHEMA, release_inputs=report['release_inputs'], eight_stream_inputs=report['eight_stream_inputs'],
        execution_plan=report['execution_plan'], phases=phases, install_originals=five, original_map=catalog)
    raw = H.encoded(value); row = ctx.add('INSTALL-START-READY-INPUTS.json', raw)
    parent_row = ctx.sources['source/verify_install_start_ready_UNBOUND.py']; parent = ctx.pool.read(parent_row)
    source, change = bind_none(parent, {'FROZEN_INPUTS': row, 'FROZEN_EXECUTION_PLAN': report['execution_plan']})
    bound_row = ctx.add('source/verify_install_start_ready_BOUND.py', source)
    bound = H.source_module(source, bound_row, 'actual_final_install_start_ready_reader')
    verdict = bound.verify_install_start_ready_originals(raw, read_pinned=ctx.callback)
    verdict_row = ctx.add('INSTALL-START-READY-VERDICT.json', H.encoded(verdict))
    ctx.add('reference/INSTALL-SOURCE-CHANGE.json', H.encoded(change))
    ctx.extra.update(release_inputs=report['release_inputs'], execution_plan=report['execution_plan'],
        actual_install_inputs=row, actual_install_reader=bound_row, actual_install_verdict=verdict_row,
        immutable_unbound_install_helper=parent_row,
        qualification_scope=verdict['READY_qualification_scope'])
    # The final verdict, not the constructor's own state, expresses the exact
    # execution qualification. No current health or business task is run here.
    return ctx.finish('ACTUAL_INSTALL_START_READY_READER_BOUND_AND_ORIGINALS_VERIFIED')


def input_value(raw):
    need(type(raw) is bytes and len(raw) <= 4 * 1024 * 1024, 'bounded complete stage construction input')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate construction input key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite construction input'))


def exact_descriptor(row):
    need(type(row) is dict and set(row) in ({'path','bytes','sha256'}, {'path','bytes','sha256','metadata'})
         and type(row['path']) is str and type(row['bytes']) is int and 0 <= row['bytes'] <= 64 * 1024 * 1024
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'typed complete actual host descriptor')
    p = PurePosixPath(row['path'])
    need(p.is_absolute() and str(p) == row['path'] and '..' not in p.parts
         and not any(c in row['path'] for c in '\0\r\n\t') and PurePosixPath(B) in p.parents,
         'canonical actual host source namespace')
    if 'metadata' in row:
        m = row['metadata']
        need(type(m) is list and len(m) == 9 and all(type(n) is int and n >= 0 for n in m)
             and m[1] > 0 and stat.S_ISREG(m[2]) and m[5] == 1 and m[6] == row['bytes'],
             'complete typed actual retained host full9')
    return row


def derive_release_install_stage(inputs_raw, *, read_pinned, host_metadata):
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_RELEASE_INSTALL_STAGE_NO_IO')
    exact_descriptor(FROZEN_INPUTS)
    need(set(FROZEN_INPUTS) == {'path','bytes','sha256'} and type(inputs_raw) is bytes
         and bytepin(inputs_raw) == {k:FROZEN_INPUTS[k] for k in ('bytes','sha256')},
         'exact whole separately bound stage construction input')
    value = input_value(inputs_raw)
    need(type(value) is dict and set(value) == {'schema','stage','output_root','actual'}
         and value['schema'] == SCHEMA and value['stage'] in STAGES, 'closed known stage construction input')
    no_unknown(value)
    need(callable(read_pinned) and callable(host_metadata), 'actual whole-byte/full9 original readers')
    ctx = Context(value, read_pinned, host_metadata)
    functions = {name: globals()[name] for name in STAGES}
    result = functions[value['stage']](ctx, value['actual'])
    result['_context'] = ctx
    return result


class HostOriginals:
    """Read only existing, exact Mac originals and check their actual full9."""
    def __init__(self):
        self.observed = {}

    def __call__(self, row):
        exact_descriptor(row)
        p = Path(row['path']); need(p.resolve(strict=True) == p, 'host original without symlink ancestors')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            metadata = lambda info: [getattr(info, name) for name in
                ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
            first = metadata(before)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['bytes'],
                 'single-link full actual original')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes'] + 1); need(stream.read(1) == b'', 'actual complete host EOF')
            need(first == metadata(os.fstat(fd)) == metadata(p.lstat())
                 and bytepin(raw) == {k:row[k] for k in ('bytes','sha256')}, 'actual host bytes/full9 bookends')
            if 'metadata' in row:
                need(first == row['metadata'], 'actual retained original full9')
            if row['path'] in self.observed:
                need(first == self.observed[row['path']], 'original host full9 unchanged across reads')
            self.observed[row['path']] = first
            return raw
        finally:
            os.close(fd)

    def metadata(self, row):
        self(row)
        return list(self.observed[row['path']])


def publish_ingested(result, reader):
    ctx = result['_context']; H = ctx.H
    raw_root, root = Path(result['raw_output_root']), Path(result['output_root'])
    need(raw_root.parent == root.parent == Path(B) and raw_root != root,
         'two distinct explicit new host original/carrier namespaces')
    H.publish_material(raw_root, result['raw_files'])
    mapping = []
    for relative, origin in sorted(result['origins'].items()):
        raw = result['raw_files'][relative]
        retained = H.located(raw_root/relative, raw)
        retained['metadata'] = reader.metadata(retained)
        need(reader(retained) == raw, 'actual just-published original full bytes/full9')
        mapping.append(dict(**origin, retained=retained))
    capture = 'identity' in result
    value = dict(schema=('hepta.fc33.retention-capture-original-carrier.v1' if capture
                         else 'hepta.fc33.install-phase-original-carrier.v1'),
        phase=result['phase'], originals=result['originals'], original_map=mapping,
        actual_controller_job=result['actual_controller_job'], input_originals=result['input_originals'],
        phone_calls=0, actor_dispatches=0, qualification='PENDING_EXISTING_COMPLETE_READER')
    if capture:
        value.update(identity=result['identity'], operation=result['operation'],
                     phase_authority_construction=result['phase_authority_construction'])
    else:
        value.update(release_inputs=result['release_inputs'], execution_plan=result['execution_plan'])
    name = 'CAPTURE-CARRIER.json' if capture else 'PHASE-CARRIER.json'
    raw = H.encoded(value); row = H.located(root/name, raw)
    terminal = dict(schema='hepta.fc33.actual-actor-originals-retained.v1',
        state='ACTUAL_ACTOR_AND_HOST_FILE_ORIGINALS_RETAINED_COMPLETE_READER_PENDING',
        carrier=row, raw_originals_root=str(raw_root), files=[row],
        phone_calls=0, actor_dispatches=0, actual_install=None, actual_READY=None)
    H.publish_material(root, {name:raw, 'DERIVATION.json':H.encoded(terminal)})
    return terminal


def main():
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_RELEASE_INSTALL_STAGE_NO_IO')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish-host-inputs-once', action='store_true', required=True)
    parser.parse_args()
    reader = HostOriginals(); raw = reader(FROZEN_INPUTS)
    result = derive_release_install_stage(raw, read_pinned=reader, host_metadata=reader.metadata)
    ctx = result['_context']; H = ctx.H
    need(Path(B).resolve(strict=True) == Path(B), 'actual exact host publication parent')
    if result.get('materialize_phase'):
        report = publish_ingested(result, reader)
    else:
        report = result['report']
        if result.get('materialize_retention'):
            T = result['retention_reader']
            retained = T.retain_installation_originals(result['retention_inputs_raw'],
                Path(result['retention_output_root']), read_pinned=reader)
            row = H.located(PurePosixPath(result['retention_output_root'])/'RETENTION-RESULT.json', T.canonical(retained))
            need(reader(row) == T.canonical(retained), 'actual retained result read back completely')
            report['retained_originals'] = row
            report['state'] = 'ACTUAL_INSTALLATION_ORIGINAL_BYTES_RETAINED'
            result['files']['DERIVATION.json'] = H.encoded(report)
        H.publish_material(Path(ctx.root), result['files'])
    terminal = H.located(ctx.root/'DERIVATION.json', H.encoded(report))
    need(reader(terminal) == H.encoded(report), 'actual terminal bytes/full9 rechecked after publication')
    print(json.dumps(dict(state=report['state'], derivation=terminal, phone_calls=0,
                         actor_dispatches=0, automatic_retry=False), sort_keys=True))


if __name__ == '__main__':
    main()
