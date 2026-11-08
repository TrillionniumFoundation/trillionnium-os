#!/usr/bin/env python3
"""Prepare exact requests for the four existing E2E entries; never dispatch.

No nonce, challenge, text marker or arithmetic operand is allocated here.
The original materializer allocates those only if Root later runs its request.
COMP-01 is a second judgment of an original E2E return, never a fifth Send.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import types

FROZEN_INPUTS = None
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
PACKAGE = B + '/followthrough-fc33-e2e-execution-controller01'
GATE = {'path': PACKAGE + '/source/verify_actual_installation_for_cases.py',
    'bytes': 6985, 'sha256': '0ce146fa85e665868e47eeb7ea927ebbba08d66ff9bc07c9f09eea42c96eb211'}
E2E = B + '/followthrough-fc33-e2e-bound-source-r5-01'
BINDING = {'path': E2E + '/BINDING.json', 'bytes': 60062,
    'sha256': '00a6cc4850c40cc710d348480f0d6b2871a145c89ee6801bd195432659a8da15'}
SCHEMA = 'hepta.fc33.e2e.original-entry-request-construction.v1'
SETUP_SCHEMA = 'hepta.fc33.e2e.actual-case-setup.v1'
STAGES = ('materialize_request', 'prepare_request', 'dispatch_request')
CASES = {'E2E-01': ('visual', '视觉挑战'), 'E2E-02': ('unicode', 'Unicode验证'),
         'E2E-03': ('calculator', '计算器'), 'E2E-04': ('settings', 'settings_about')}
COMMON_FILES = {'MATERIALIZATION-INTENT.json', 'request.txt', 'postconditions.json',
                'app-scope.json', 'combination.json', 'release-build-result.json', 'REGISTRATION-ARGV.json'}
EXTRAS = {'visual': set(), 'unicode': {'expected-text.txt', 'expected-public-receipt.txt'},
          'calculator': {'runtime-route-qualification.json', 'expected-expression.txt', 'expected-result.txt'},
          'settings': {'runtime-route-qualification.json', 'independent-public-reference.json'}}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def bytepin(raw):
    need(type(raw) is bytes, 'complete raw bytes required')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def strict(raw):
    need(type(raw) is bytes and len(raw) <= 4 * 1024 * 1024, 'bounded complete input bytes')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, 'nonfinite JSON'))


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def exact(value, keys, why):
    need(type(value) is dict and set(value) == set(keys), why)
    return value


def descriptor(row):
    exact(row, ('path', 'bytes', 'sha256'), 'one complete explicit original descriptor')
    p = host_path(row['path'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= 64 * 1024 * 1024
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'typed bounded complete original byte pin')
    return p


def host_path(value):
    need(type(value) is str and not any(c in value for c in '\0\r\n\t'), 'plain host path')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts
         and PurePosixPath(B) in p.parents, 'canonical child of the actual project root')
    return p


def no_unknown(value):
    need(value is not None, 'UNBOUND_ACTUAL_E2E_INPUT_NO_IO')
    if type(value) is dict:
        for item in value.values():
            no_unknown(item)
    elif type(value) is list:
        for item in value:
            no_unknown(item)


def load(row, callback, name):
    descriptor(row)
    raw = callback(dict(row))
    need(bytepin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact reviewed full source')
    module = types.ModuleType(name); module.__file__ = row['path']
    exec(compile(raw, row['path'], 'exec'), module.__dict__)
    return module, raw


def original_entry_request(row, source, argv, key, timeout):
    """Embed the exact original source as the sole executable Python body."""
    descriptor(row)
    need(bytepin(source) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact entry source bytes')
    need(type(argv) is list and all(type(v) is str and '\0' not in v for v in argv), 'literal argv strings')
    need(type(key) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{5,127}', key), 'explicit one-use operation key')
    need(type(timeout) is int and 1 <= timeout <= 3600, 'finite original operation budget')
    program = ('import base64,hashlib,sys\n'
        '_SOURCE=base64.b64decode(' + repr(base64.b64encode(source).decode()) + ',validate=True)\n'
        'assert len(_SOURCE)==' + repr(row['bytes']) + ' and hashlib.sha256(_SOURCE).hexdigest()==' + repr(row['sha256']) + '\n'
        'sys.dont_write_bytecode=True\n'
        'sys.argv=' + repr([row['path']] + argv) + '\n'
        '_NS={"__name__":"__main__","__file__":' + repr(row['path']) + '}\n'
        'exec(compile(_SOURCE,_NS["__file__"],"exec"),_NS)\n')
    need(len(program.encode()) <= 1024 * 1024, 'actual controller stdin bound')
    return dict(host='mac', executable='/usr/bin/python3', args=['-I', '-B', '-'],
                stdin=program, timeout_seconds=timeout, idempotency_key=key)


class Context:
    def __init__(self, value, callback):
        self.value, self.callback = value, callback
        self.G, unused = load(GATE, callback, 'reviewed_e2e_actual_installation_gate')
        self.S = self.G.load_stage(callback)
        self.H, unused = self.S.load_source(self.S.HELPER, callback, 'reviewed_e2e_host_constructor_helper')
        self.pool = self.H.Pool(callback)
        self.pool.read(GATE)
        setup_raw = self.pool.read(value['setup'], 65536)
        self.setup = self.H.strict(setup_raw)
        a = self.setup
        exact(a, ('schema', 'case_id', 'actual_installation', 'previous', 'preserved_draft',
                  'retirement_resolution', 'material_directory', 'workflow_directory',
                  'sender_label', 'operation_keys'), 'exact actual per-case setup')
        no_unknown(a)
        need(a['schema'] == SETUP_SCHEMA and a['case_id'] in CASES, 'one of the four original E2E cases')
        self.case, (self.kind, self.alias) = a['case_id'], CASES[a['case_id']]
        for key in ('actual_installation', 'previous', 'preserved_draft', 'retirement_resolution'):
            descriptor(a[key])
        self.root = host_path(value['output_root'])
        self.material, self.workflow = (host_path(a[key]) for key in ('material_directory', 'workflow_directory'))
        need(self.root.parent == PurePosixPath(B) and self.material != self.workflow
             and all(x not in y.parents for x, y in ((self.root, self.material), (self.material, self.root),
                 (self.root, self.workflow), (self.workflow, self.root), (self.material, self.workflow), (self.workflow, self.material))),
             'separate explicit owned request, material and workflow namespaces')
        need(type(a['sender_label']) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,69}', a['sender_label']),
             'original explicit sender label')
        exact(a['operation_keys'], ('materialize', 'prepare', 'dispatch'), 'three existing entry operation keys')
        keys = a['operation_keys']
        need(all(type(k) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{5,127}', k) for k in keys.values())
             and len(set(keys.values())) == 3, 'separate literal one-use entry keys')
        self.installed = self.G.verify_actual_installation(a['actual_installation'], read_pinned=callback)
        binding = self.H.strict(self.pool.read(BINDING, 131072))
        need(binding['schema'] == 'hepta.fc33.e2e.actual-source-binding.v1'
             and binding['state'] == 'SOURCE_BOUND_TASK_EXECUTION_UNBOUND'
             and binding['source_combination_sha256'] == self.G.COMBINATION,
             'actual published E2E source family')
        rows = binding['files']
        need(type(rows) is list and len(rows) == 48 and len({r['path'] for r in rows}) == 48,
             'all actual published E2E source members')
        self.rows, self.bodies = {}, {}
        for row in rows:
            relative = str(host_path(row['path']).relative_to(E2E))
            self.rows[relative], self.bodies[relative] = row, self.pool.read(row, 4 * 1024 * 1024)
        self.binding = binding
        self.core = self.module('operator-chain/root_acceptance_r10.py', 'reviewed_e2e_request_core')
        self.mat = self.module('operator/materialize_case_r10.py', 'reviewed_e2e_request_materializer')
        self.coordinator = self.module('source/run_fixed19_e2e_root_once.py', 'reviewed_e2e_request_coordinator')
        need(self.core.READINESS_SHA == self.installed['source_files']['source/collect_r10_readiness.py']['sha256'],
             'E2E operator uses the same actual installed readiness source')
        self.build = self.installed['build_result']
        self.release_dir = host_path(self.build['path']).parent
        need(host_path(self.build['path']).name == 'BUILD-RESULT.json', 'actual original BUILD directory entry')
        # This is the original host-only release validator, unchanged.
        self.release = self.mat.validate_release(Path(self.release_dir), self.build['sha256'])
        need(self.release['report_raw'] == self.installed['build_raw'], 'same complete BUILD original in both readers')
        self.core.verify_ready(self.installed['ready'], self.release)
        shared = self.H.strict(self.bodies['shared/SHARED-MATERIALS.json'])
        supplied = {'provider/source/' + name: raw for name, raw in self.release['source'].items()}
        supplied.update({'local-config-r10-r1.json': self.release['config_raw'],
                         'PHONE-SERVICE-INPUTS-v150-r10-r1.json': self.release['service_raw']})
        need(len(shared['files']) == len(supplied) == 17
             and set(supplied) == {r['path'] for r in shared['files']}, 'same complete shared17 source set')
        for row in shared['files']:
            body = supplied[row['path']]
            need(body == self.bodies['shared/' + row['path']]
                 and bytepin(body) == {k: row[k] for k in ('bytes', 'sha256')}, 'all actual release/E2E shared bytes equal')
        self.previous = self.H.strict(self.pool.read(a['previous'], 262144))
        self.core.check_previous(self.previous)
        # Keep private contents in memory only; outputs contain descriptors.
        draft = self.H.strict(self.pool.read(a['preserved_draft'], 131072))
        exact_text = base64.b64decode(draft['exact_utf8_b64'], validate=True)
        exact_text.decode('utf-8', errors='strict')
        need(exact_text and bytepin(exact_text)['sha256'] == draft['utf8_sha256'], 'same nonempty original private draft')
        self.pool.read(a['retirement_resolution'], 262144)
        self.files, self.extra = {}, {}

    def module(self, relative, name):
        return self.H.source_module(self.bodies[relative], self.rows[relative], name)

    def add(self, name, raw):
        need(name not in self.files and type(raw) is bytes, 'one complete new request artifact')
        self.files[name] = raw
        return self.H.located(self.root / name, raw)

    def request(self, relative, argv, key, timeout):
        return original_entry_request(self.rows[relative], self.bodies[relative], argv, key, timeout)

    def controller(self, row, expected):
        record = self.H.strict(self.pool.read(row, 8 * 1024 * 1024))
        need(self.H.same(record['request'], expected), 'actual controller request is the exact derived original entry')
        R, unused = self.S.load_source(self.S.CONTROLLER_READER, self.pool.read, 'reviewed_e2e_controller_originals')
        job, status, streams = R.controller(record, code=0, complete=True)
        need(job['host'] == expected['host'] and job['executable'] == expected['executable']
             and self.H.same(job['args'], expected['args'])
             and job['idempotency_key'] == expected['idempotency_key']
             and streams['stderr'] == b'', 'same exact successful original host operation')
        value = self.H.strict(streams['stdout'])
        return value, dict(job_id=job['id'], created_unix_ms=job['created_unix_ms'], terminal_unix_ms=status['at_unix_ms'])

    def finish(self, state):
        self.installed['recheck_originals'](); self.pool.recheck()
        report = dict(schema=SCHEMA, stage=self.value['stage'], state=state,
            construction_inputs=FROZEN_INPUTS, setup=self.value['setup'], case_id=self.case, kind=self.kind,
            actual_installation=self.setup['actual_installation'], actual_BUILD=self.build,
            actual_READY_original=self.installed['ready_original'], actual_READY_host=self.installed['ready_host'],
            source_binding=BINDING, source_chain=self.installed['source_chain'],
            original_materializer=self.rows['operator/materialize_case_r10.py'],
            original_operator=self.rows['operator-chain/root_acceptance_r10.py'],
            original_coordinator=self.rows['source/run_fixed19_e2e_root_once.py'],
            return_requested=self.case != 'E2E-04', phone_calls=0, model_requests=0, native_dispatches=0,
            new_nonces=0, automatic_retry=False, case_pass=False, fixed19_credit=0,
            COMP01_is_shared_return_evidence_not_another_execution=True,
            READY_qualification_scope=self.installed['verdict']['READY_qualification_scope'],
            all_originals_bookended=True, **self.extra)
        report['files'] = [self.H.located(self.root / name, raw) for name, raw in sorted(self.files.items())]
        self.files['DERIVATION.json'] = enc(report)
        return dict(files=self.files, report=report, _context=self)


def materialize_argv(ctx):
    identity = ctx.previous['identity']
    return [ctx.kind, '--release-dir', str(ctx.release_dir), '--build-result-sha256', ctx.build['sha256'],
        '--out', str(ctx.material), '--session-id', identity['session_id'], '--profile-id', identity['profile_id'],
        '--allowed-app', ctx.alias]


def materialize_request_value(ctx):
    return ctx.request('operator/materialize_case_r10.py', materialize_argv(ctx),
                       ctx.setup['operation_keys']['materialize'], 120)


def materialize_request(ctx, actual):
    exact(actual, (), 'materialization has no fabricated material/controller input')
    row = ctx.add('requests/MATERIALIZE.CONTROLLER.json', enc(materialize_request_value(ctx)))
    ctx.extra.update(request=row, expected_material=str(ctx.material / 'material.json'),
        actual_nonce=None, actual_material=None, actual_context=None, actual_e2e=None)
    return ctx.finish('ACTUAL_INSTALL_VERIFIED_ORIGINAL_MATERIALIZER_REQUEST_NOT_RUN')


def actual_material(ctx, controller):
    summary, authority = ctx.controller(controller, materialize_request_value(ctx))
    need(summary['state'] == 'fresh_bytes_only_no_registration_no_send' and summary['case'] == ctx.case
         and type(summary['phone_calls']) is int and summary['phone_calls'] == 0
         and type(summary['model_requests']) is int and summary['model_requests'] == 0
         and summary['automatic_replay'] is False, 'original host-only materializer terminal')
    rows = summary['files']
    need(type(rows) is list and len({r['path'] for r in rows}) == len(rows), 'unique original material members')
    bodies, selected = {}, {}
    for row in rows:
        p = descriptor(row)
        need(p.parent == ctx.material, 'exact original owned material directory')
        selected[p.name], bodies[p.name] = row, ctx.pool.read(row, 262144)
    need(set(bodies) == COMMON_FILES | EXTRAS[ctx.kind] | {'material.json'}, 'complete original per-case material files')
    m = ctx.H.strict(bodies['material.json']); request = bodies['request.txt']
    need(m['schema'] == 'hepta.fresh-acceptance-material.v150.r10.1'
         and m['case'] == ctx.case and m['kind'] == ctx.kind
         and m['nonce'] == summary['nonce'] and re.fullmatch('[0-9a-f]{32}', m['nonce'])
         and m['request_sha256'] == summary['request_sha256'] == bytepin(request)['sha256']
         and request.decode('utf-8').count(m['nonce']) == 1
         and m['release_build_result_sha256'] == ctx.build['sha256']
         and bodies['release-build-result.json'] == ctx.installed['build_raw']
         and bodies['combination.json'] == ctx.release['binding_raw'], 'one actual original task bound to this installed release')
    need(ctx.H.same(m['files'], [r for r in rows if r['path'] != selected['material.json']['path']]),
         'material metadata preserves the exact original file order and descriptors')
    scope = ctx.mat.validate_material_app_scope(m, request, bodies['app-scope.json'], ctx.H.strict(ctx.release['config_raw']))
    need([r['alias'] for r in scope['apps']] == [ctx.alias], 'only the selected original case app alias')
    conditions = ctx.H.strict(bodies['postconditions.json'])
    returns = [r for r in conditions if r['kind'] == 'foreground_hepta']
    need(len(returns) == (0 if ctx.case == 'E2E-04' else 1), 'original requested return differs')
    if ctx.case == 'E2E-04':
        need(m['return_requested'] is False and m['only_public_readonly_navigation'] is True,
             'Settings original read-only no-return request')
    if ctx.case == 'E2E-02':
        text = bodies['expected-text.txt']; decoded = text.decode('utf-8', errors='strict')
        receipt = ('HEPTA_UNICODE_READBACK\nsha256=' + bytepin(text)['sha256']
            + '\ncodepoints=' + str(len(decoded)) + '\nutf8_bytes=' + str(len(text))).encode()
        need(b'\n' in text and b'\r' not in text and text in request
             and bodies['expected-public-receipt.txt'] == receipt
             and m['text_utf8_sha256'] == bytepin(text)['sha256'], 'exact original Unicode/LF and independently derived receipt')
    if ctx.case == 'E2E-03':
        arithmetic = exact(m['arithmetic'], ('a', 'b', 'c'), 'original three arithmetic operands')
        need(all(type(n) is int and 11 <= n <= 29 for n in arithmetic.values()), 'original integer operand bounds')
        a, b, c = (arithmetic[k] for k in ('a', 'b', 'c'))
        expression = ('(' + str(a) + '×' + str(b) + ')+' + str(c)).encode()
        need(bodies['expected-expression.txt'] == expression and expression in request
             and bodies['expected-result.txt'] == str(a * b + c).encode(), 'independent arithmetic agrees with the actual original operands')
    remote, argv = ctx.mat.registration_argv(m, ctx.previous['identity']['session_id'], ctx.previous['identity']['profile_id'])
    plan = ctx.H.strict(bodies['REGISTRATION-ARGV.json'])
    need(plan['schema'] == 'hepta.r10.registration-plan.v1' and ctx.H.same(plan['argv'], argv)
         and plan['phone_case_directory'] == remote, 'exact original selected registration scope')
    return selected['material.json'], m, authority


def prepare_argv(ctx):
    a = ctx.setup; ready = ctx.installed['ready_host']
    arguments = ['prepare']
    for flag, value in (
        ('project-dir', B), ('materializer', ctx.rows['operator/materialize_case_r10.py']['path']),
        ('release-dir', str(ctx.release_dir)), ('material', str(ctx.material)),
        ('previous-input', a['previous']['path']), ('ready-input', ready['path']),
        ('preserved-draft', a['preserved_draft']['path']), ('retirement-resolution', a['retirement_resolution']['path']),
        ('collector-package', E2E + '/collector-package'), ('out', str(ctx.workflow)),
        ('build-result-sha256', ctx.build['sha256']), ('previous-sha256', a['previous']['sha256']),
        ('ready-sha256', ready['sha256']), ('preserved-draft-sha256', a['preserved_draft']['sha256']),
        ('retirement-resolution-sha256', a['retirement_resolution']['sha256']),
        ('operator-manifest-sha256', ctx.rows['operator-chain/SOURCE-MANIFEST.json']['sha256']),
        ('collector-package-sha256', ctx.rows['collector-package/MANIFEST.json']['sha256']), ('sender-label', a['sender_label'])):
        arguments.extend(['--' + flag, value])
    return arguments


def prepare_request_value(ctx):
    return ctx.request('operator-chain/root_acceptance_r10.py', prepare_argv(ctx),
                       ctx.setup['operation_keys']['prepare'], 120)


def prepare_request(ctx, actual):
    exact(actual, ('materialization_controller',), 'actual materialization original only')
    material, meta, authority = actual_material(ctx, actual['materialization_controller'])
    row = ctx.add('requests/PREPARE-CONTEXT.CONTROLLER.json', enc(prepare_request_value(ctx)))
    ctx.extra.update(request=row, materialization_controller=actual['materialization_controller'],
        materialization_authority=authority, actual_material=material, actual_nonce=meta['nonce'],
        expected_context=str(ctx.workflow / 'ROOT-CONTEXT.json'), actual_context=None, actual_e2e=None)
    return ctx.finish('ACTUAL_MATERIAL_VERIFIED_ORIGINAL_CONTEXT_REQUEST_NOT_RUN')


def dispatch_request(ctx, actual):
    exact(actual, ('materialization_controller', 'prepare_controller'), 'actual materialization and context originals only')
    material, meta, material_auth = actual_material(ctx, actual['materialization_controller'])
    summary, prepare_auth = ctx.controller(actual['prepare_controller'], prepare_request_value(ctx))
    need(material_auth['terminal_unix_ms'] <= prepare_auth['created_unix_ms'], 'original preparation followed materialization')
    need(summary['state'] == 'HOST_ONLY_OPERATOR_CONTEXT_PREPARED' and summary['case'] == ctx.case
         and type(summary['phone_calls']) is int and summary['phone_calls'] == 0
         and type(summary['model_requests']) is int and summary['model_requests'] == 0
         and summary['new_nonce_generated'] is False, 'original context preparation without registration/send')
    row = summary['context']; descriptor(row)
    need(row['path'] == str(ctx.workflow / 'ROOT-CONTEXT.json'), 'exact original workflow context path')
    raw = ctx.pool.read(row, 1048576); context = ctx.H.strict(raw)
    actual_context, release = ctx.core.load_context(Path(row['path']), row['sha256'])
    need(ctx.H.same(actual_context, context) and context['nonce'] == meta['nonce']
         and context['sender_label'] == ctx.setup['sender_label']
         and context['case'] == ctx.case and ctx.H.same(context['inputs']['material'], material),
         'same complete original context and one materialized task')
    for name, expected in (('previous', ctx.setup['previous']), ('ready', ctx.installed['ready_host']),
                           ('preserved_draft', ctx.setup['preserved_draft']),
                           ('retirement_resolution', ctx.setup['retirement_resolution']), ('build_result', ctx.build)):
        need(ctx.H.same(context['inputs'][name], expected), 'same actual setup original in context: ' + name)
    plan = dict(schema='hepta.fixed19.e2e.coordinator-plan.v1', case_id=ctx.case,
        coordinator_sha256=ctx.rows['source/run_fixed19_e2e_root_once.py']['sha256'],
        operator_manifest=ctx.rows['operator-chain/SOURCE-MANIFEST.json'],
        capture_source=ctx.rows['reference/owned_capture.source.original.py'],
        shared_materials=ctx.rows['shared/SHARED-MATERIALS.json'], context=row,
        output=str(ctx.workflow / 'owned-coordinator'))
    plan_raw = enc(plan); plan_row = ctx.add('ROOT-PLAN.json', plan_raw)
    # The original validator is read-only. No execute() or child phase is called.
    checked = ctx.coordinator.validate_plan(plan_raw, Path(plan_row['path']))
    need(ctx.H.same(checked[0], plan) and ctx.H.same(checked[1], context), 'unchanged original coordinator accepts the exact plan')
    argv = ['--plan', plan_row['path'], '--plan-sha256', plan_row['sha256'], '--execute-e2e-once']
    timeout = sum(seconds for unused, seconds in ctx.coordinator.PHASES) + 110
    request = ctx.request('source/run_fixed19_e2e_root_once.py', argv, ctx.setup['operation_keys']['dispatch'], timeout)
    dispatch = ctx.add('requests/E2E-ONCE.CONTROLLER.json', enc(request))
    ctx.extra.update(request=dispatch, root_plan=plan_row, actual_material=material,
        actual_context=row, actual_nonce=meta['nonce'], actual_e2e=None,
        materialization_controller=actual['materialization_controller'], prepare_controller=actual['prepare_controller'],
        materialization_authority=material_auth, prepare_authority=prepare_auth,
        original_six_phases=[{'name': name, 'timeout_seconds': seconds} for name, seconds in ctx.coordinator.PHASES],
        shared_COMP01_eligible=self_eligible(ctx.case),
        next_previous_path=str(ctx.workflow / 'closure' / 'ACTUAL-PREVIOUS-INPUT.json'))
    return ctx.finish('ACTUAL_CONTEXT_VERIFIED_ORIGINAL_E2E_PLAN_NOT_DISPATCHED')


def self_eligible(case):
    return case in ('E2E-01', 'E2E-02', 'E2E-03')


def derive_e2e_requests(inputs_raw, *, read_pinned):
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_E2E_REQUEST_INPUTS_NO_IO')
    descriptor(FROZEN_INPUTS)
    need(bytepin(inputs_raw) == {k: FROZEN_INPUTS[k] for k in ('bytes', 'sha256')}, 'exact separately bound input bytes')
    value = strict(inputs_raw)
    exact(value, ('schema', 'stage', 'setup', 'output_root', 'actual'), 'exact one known host construction stage')
    need(value['schema'] == SCHEMA and value['stage'] in STAGES, 'one of three original-entry construction stages')
    no_unknown(value); descriptor(value['setup'])
    ctx = Context(value, read_pinned)
    need(ctx.pool.read(FROZEN_INPUTS) == inputs_raw, 'same complete actual bound input original')
    return globals()[value['stage']](ctx, value['actual'])


def require_fresh_entry_names(ctx, stage):
    """Before host publication, reject names consumed by an original attempt."""
    if stage == 'materialize_request':
        targets = [Path(ctx.material), Path(ctx.workflow)]
    elif stage == 'prepare_request':
        targets = [Path(ctx.workflow)]
    else:
        targets = []  # Original coordinator.validate_plan checked all six phase paths.
    for path in targets:
        need(path.parent.resolve(strict=True) == path.parent and not path.exists() and not path.is_symlink(),
             'already used case output; inspect its original attempt')
    for suffix in ('.preview.actor.py', '.actor.py', '.local-once.json', '.send-result.json'):
        path = Path(B) / (ctx.setup['sender_label'] + suffix)
        need(not path.exists() and not path.is_symlink(), 'sender label already has an original attempt')


def main():
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_E2E_REQUEST_INPUTS_NO_IO')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish-host-requests-once', action='store_true', required=True)
    parser.parse_args()
    # Only this fixed source is read before construction; it creates no files.
    from os import O_RDONLY, O_NOFOLLOW, O_CLOEXEC, open as os_open, close as os_close, fdopen, fstat
    import stat
    def bootstrap(row):
        descriptor(row); path = Path(row['path'])
        need(path.resolve(strict=True) == path, 'canonical reviewed source path')
        fd = os_open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        try:
            first = fstat(fd)
            names = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            meta = lambda st: [getattr(st, name) for name in names]
            need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == row['bytes'], 'original source shape')
            with fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes'] + 1)
            need(meta(first) == meta(fstat(fd)) == meta(path.lstat())
                 and bytepin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact original source full9 and bytes')
            return raw
        finally:
            os_close(fd)
    G, unused = load(GATE, bootstrap, 'reviewed_e2e_request_bootstrap')
    S = G.load_stage(bootstrap); reader = S.HostOriginals()
    raw = reader(FROZEN_INPUTS)
    result = derive_e2e_requests(raw, read_pinned=reader)
    ctx = result['_context']; require_fresh_entry_names(ctx, ctx.value['stage'])
    ctx.H.publish_material(Path(ctx.root), result['files'])
    terminal = ctx.H.located(ctx.root / 'DERIVATION.json', enc(result['report']))
    need(reader(terminal) == enc(result['report']), 'complete published request construction readback')
    print(json.dumps(dict(state=result['report']['state'], derivation=terminal,
        case_id=ctx.case, request=result['report']['request'], phone_calls=0,
        model_requests=0, native_dispatches=0, new_nonces=0, case_pass=False), sort_keys=True))


if __name__ == '__main__':
    main()
