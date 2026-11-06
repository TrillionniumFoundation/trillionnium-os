#!/usr/bin/env python3
"""Offline candidate regressions using retained NEG10-14 case functions.

The complete source set is hash-checked and daily_phone_local is imported with
its real PARENTS checks. These are local synthetic regression results, never a
fixed-19 qualification or an attestation of installed phone/model behavior.
"""
import argparse
import copy
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import traceback
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parent
EXTRA_MUTATIONS = ('output_before_started', 'unknown_event', 'boolean_exit_code',
                   'floating_exit_code', 'nested_boolean_exit_code', 'nested_floating_count',
                   'nested_integer_truncation', 'nested_floating_truncation', 'missing_kind')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_runner(name):
    spec = importlib.util.spec_from_file_location(name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_source(source):
    seal = json.loads((CANDIDATE/'SOURCE-SEAL.json').read_text())
    expected = seal['production_files'] if source.resolve() == (CANDIDATE/'source').resolve() else seal['baseline']['production_files']
    assert sorted(p.name for p in source.glob('*.py')) == sorted(Path(row['path']).name for row in expected)
    rows = []
    for row in expected:
        path = source/Path(row['path']).name
        assert path.is_file() and not path.is_symlink()
        digest = sha(path)
        assert digest == row['sha256'] and path.stat().st_size == row['bytes'], (path.name, 'source seal differs')
        rows.append({'path': path.name, 'sha256': digest, 'bytes': path.stat().st_size})
    return rows


def import_sources(source):
    rows = verify_source(source)
    sys.path.insert(0, str(source))
    # This import executes all fourteen dependency-pin checks. Never bypass,
    # patch, AST-extract or replace daily_phone_local.PARENTS in this harness.
    daily = importlib.import_module('daily_phone_local')
    for name in ('daily_phone_local', 'phone_observation_tools', 'phone_task_guards',
                 'task_postconditions', 'provider_codex_host', 'provider_openai_compatible'):
        assert Path(importlib.import_module(name).__file__).resolve().parent == source.resolve()
    return daily, rows


def component_child(source, work):
    daily, rows = import_sources(source)
    runner = load_runner('host_negative_runner')
    runner.OUT = work
    runner.OBS = importlib.import_module('phone_observation_tools')
    runner.GUARDS = importlib.import_module('phone_task_guards')
    runner.CONTRACT = importlib.import_module('task_postconditions')
    runner.CODEX = importlib.import_module('provider_codex_host')
    runner.OPENAI = importlib.import_module('provider_openai_compatible')
    sys.addaudithook(runner.audit)
    cases = []
    for case_id, fn in zip(runner.IDS, (runner.neg10, runner.neg11, runner.neg12, runner.neg13)):
        evidence = runner.Evidence(work/case_id)
        before = runner.resources()
        error = None
        try:
            fn(evidence)
        except BaseException as exc:
            error = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
        after = runner.resources()
        checks = [('file descriptor baseline restored', after['open_fd_count'] == before['open_fd_count']),
                  ('thread baseline restored', after['thread_count'] == before['thread_count']),
                  ('no socket/process/outside-write attempt', not runner.AUDIT)]
        evidence.checks.extend({'name': name, 'passed': bool(passed)} for name, passed in checks)
        cases.append({'id': case_id, 'passed': error is None and all(x['passed'] for x in evidence.checks),
                      'assertions': evidence.checks, 'observations': evidence.observations,
                      'error': error, 'resources': {'before': before, 'after': after}})
    assert rows == verify_source(source)
    return {'scope': 'retained component case functions with extended native mutations',
            'cases': cases, 'source_pins_checked': len(rows), 'source_unchanged': True,
            'phone_calls': 0, 'real_model_requests': 0, 'native_dispatches': 0}


def synthetic_config():
    binding = importlib.import_module('retirement_recovery').EXECUTOR_BINDING
    return {'schema': 'hepta.phone-local-provider.v150.1',
            'endpoint': 'http://127.0.0.1:18099/v1/chat/completions',
            'api_key_file': '/synthetic-placeholder-overwritten-by-config-tree',
            'model': 'synthetic-fixture-no-real-inference',
            'service_manifest_sha256': '0'*64, 'max_tokens': 32, 'max_prompt_bytes': 4096,
            'approved_apps': {'synthetic': {'component': 'org.example.hepta.synthetic/.FixtureActivity',
                                           'label': 'Synthetic host-only fixture'}},
            'inference_location': 'phone', 'expected_parallel_slots': 1,
            'executor': {'mode': 'phone_local_sidecar', 'python': '/usr/bin/python3',
                         'client_path': binding['client_path'], 'client_sha256': binding['client_sha256'],
                         'timeout_ms': 1000}}


def serve_fixture(args):
    daily, _rows = import_sources(args.source)
    cfg = json.loads(args.config.read_text())
    # Directly exercise serve's retained orphan/capacity gates. No adapter is
    # admitted, no executor is installed, and the deployment-config loader is
    # outside this fixture's scope. The real source/worker pins still execute.
    values = types.SimpleNamespace(state=args.state, evidence=args.state/'evidence',
        cwd=args.state/'empty-cwd', config=args.config, port=args.port, workers=1, timeout=1,
        max_evidence_bytes=args.max_evidence_bytes, retained_claims=args.retained_claims,
        retained_claims_sha256=args.retained_claims_sha256, worker=args.source/'phone_local_http_worker.py',
        local_config=cfg, local_config_sha256=sha(args.config), model=cfg['model'], slot_cleanup_binding=None)
    daily.serve(values)
    raise AssertionError('negative serve fixture unexpectedly returned successfully')


def service_child(source, work):
    daily, rows = import_sources(source)
    runner = load_runner('service_negative_runner')
    runner.DAILY = daily
    runner.OPENAI = importlib.import_module('provider_openai_compatible')
    runner.SOURCE = source
    runner.WORK = work
    runner.SUITE = work/'synthetic-suite'
    runner.SUITE.mkdir(mode=0o700)
    runner.write(runner.SUITE/'production-config.json', synthetic_config())
    def fixture_argv(directory, state, seed, port):
        return [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--source', str(source),
                '--serve-fixture', '--state', str(state), '--config', str(directory/'config.json'),
                '--port', str(port), '--retained-claims', str(directory/'retained.json'),
                '--retained-claims-sha256', seed['sha256']]
    runner.daemon_argv = fixture_argv
    evidence = runner.Evidence('NEG-14')
    before = runner.resources()
    error = None
    try:
        runner.neg14(evidence)
    except BaseException as exc:
        error = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
    finally:
        for child in reversed(runner.OWNED):
            if not child.joined:
                try:
                    child.join(timeout=2, stop=True)
                except BaseException as exc:
                    error = error or {'type': type(exc).__name__, 'message': 'owned cleanup: '+str(exc)}
    after = runner.resources()
    evidence.checks.extend([
        {'name': 'file descriptor baseline restored', 'passed': after['fd_count'] == before['fd_count']},
        {'name': 'thread baseline restored', 'passed': after['thread_count'] == before['thread_count']},
        {'name': 'all owned children waited and process groups absent',
         'passed': all(x.joined and x.result['group_after']['members'] == []
                       and x.result['group_after']['kernel'] == 'ESRCH' for x in runner.OWNED)}])
    assert rows == verify_source(source)
    return {'scope': 'extended retained NEG14 plus original orphan/sparse-capacity serve gates',
            'deployment_config_loader_exercised': False,
            'new_namespace_created': False, 'permission_test_effective_uid': os.geteuid(),
            'cases': [{'id': 'NEG-14', 'passed': error is None and all(x['passed'] for x in evidence.checks),
                       'assertions': evidence.checks, 'observations': evidence.observations, 'error': error,
                       'resources': {'before': before, 'after': after}}],
            'source_pins_checked': len(rows), 'source_unchanged': True, 'phone_calls': 0,
            'real_model_requests': 0, 'native_dispatches': 0, 'owned_process_count': len(runner.OWNED)}


def audit_child(source, work):
    daily, rows = import_sources(source)
    runner = load_runner('host_negative_runner')
    observation = importlib.import_module('phone_observation_tools')
    outcomes = []
    for scenario in ('valid',)+EXTRA_MUTATIONS:
        directory = work/scenario
        directory.mkdir(mode=0o700)
        writes = []
        phone = observation.PhoneTools(directory, lambda path, value: writes.append((str(path), value)))
        phone.bind(runner.identity())
        call_id = 'audit_'+secrets.token_hex(12)
        phone.map({'call_id': call_id, 'tool': 'phone.input_text', 'command': '中文 🌟\n精确读回',
                   'argv': [runner.PACKAGE, runner.EDITOR, '']})
        call = phone.calls[call_id]
        reply = runner.native(call_id, runner.canonical(runner.input_payload(call)), call['wire_tool'])
        if scenario != 'valid':
            runner.mutate_native(reply, scenario)
        error = None
        try:
            runner.prepare_one(phone, call, reply)
            accepted = True
        except BaseException as exc:
            accepted = False
            error = {'type': type(exc).__name__, 'message': str(exc)}
        outcomes.append({'scenario': scenario, 'accepted': accepted,
                         'verified_fact_count': len(phone.verified_facts), 'error': error})
    rename_outcomes = []
    for scenario in ('rename', 'unlink', 'unlink_with_old_canonical'):
        root = work/('rename-'+scenario)
        root.mkdir(mode=0o700)
        directory = root/('20261105-000000-'+secrets.token_hex(16))
        directory.mkdir(mode=0o700)
        temporary = directory/'local-01.request.json.new'
        target = directory/'local-01.request.json'
        if scenario == 'unlink_with_old_canonical': target.write_bytes(b'old')
        temporary.write_bytes(b'synthetic temporary payload')
        def operation(snapshot=None):
            if scenario == 'rename': os.replace(temporary, target)
            else: temporary.unlink()
            try:
                value = daily.evidence_item_size(temporary, root, snapshot) if snapshot is not None else daily.evidence_item_size(temporary, root)
                return {'accepted': True, 'returned_size': value, 'error': None}
            except BaseException as exc:
                return {'accepted': False, 'returned_size': None,
                        'error': {'type': type(exc).__name__, 'message': str(exc)}}
        if hasattr(daily, 'evidence_snapshot'):
            with daily.evidence_snapshot(directory, root) as snapshot:
                result = operation(snapshot)
        else:
            assert temporary in list(directory.iterdir())
            result = operation()
        rename_outcomes.append({'scenario': scenario, **result})
    assert rows == verify_source(source)
    return {'source_pins_checked': len(rows), 'native_pipeline': outcomes, 'rename_helpers': rename_outcomes,
            'phone_calls': 0, 'real_model_requests': 0, 'native_dispatches': 0}


def child_process(mode, source, work):
    cmd = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child', mode,
           '--source', str(source), '--work', str(work)]
    kwargs = {}
    # Actual EACCES is part of NEG14. A root-run regression delegates only this
    # disposable work tree to an unprivileged child; it does not modify host
    # identities, production paths or the source tree.
    status_path = Path('/proc/self/status')
    effective_caps = None
    if status_path.is_file():
        effective_caps = int(next(line.split()[1] for line in status_path.read_text().splitlines()
                                  if line.startswith('CapEff:')), 16)
    dac_override = effective_caps is None or bool(effective_caps & ((1 << 1) | (1 << 2)))
    if mode == 'service' and os.geteuid() == 0 and dac_override:
        os.chown(work, 65534, 65534)
        os.chmod(work, 0o700)
        os.chmod(work.parent, 0o755)
        kwargs.update(user=65534, group=65534, extra_groups=[])
    proc = subprocess.run(cmd, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=90, **kwargs)
    try:
        result = json.loads(proc.stdout)
    except (ValueError, TypeError):
        result = {'unparsed_stdout': proc.stdout[-4000:]}
    return {'returncode': proc.returncode, 'result': result, 'stderr': proc.stderr[-8000:]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional result JSON outside the repository; default stdout only.')
    parser.add_argument('--source', type=Path, default=CANDIDATE/'source')
    parser.add_argument('--baseline-source', type=Path, help='Optional exact cp08 source set for before/after observations.')
    parser.add_argument('--child', choices=('components', 'service', 'audit'), help=argparse.SUPPRESS)
    parser.add_argument('--work', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--serve-fixture', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--state', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--config', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--port', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--retained-claims', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--retained-claims-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--max-evidence-bytes', type=int, default=1024*1024*1024, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.source = args.source.resolve()
    os.umask(0o077)
    if args.serve_fixture:
        serve_fixture(args)
    if args.child:
        result = {'components': component_child, 'service': service_child, 'audit': audit_child}[args.child](args.source, args.work)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if all(case['passed'] for case in result.get('cases', [])) else 1
    before = verify_source(args.source)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='hepta-native-capacity-regression-') as tmp:
        root = Path(tmp)
        groups = {}
        for mode in ('components', 'service', 'audit'):
            work = root/mode
            work.mkdir(mode=0o700)
            groups[mode] = child_process(mode, args.source, work)
        if args.baseline_source:
            work = root/'before'
            work.mkdir(mode=0o700)
            groups['baseline_audit'] = child_process('audit', args.baseline_source.resolve(), work)
        after = verify_source(args.source)
    cases = [case for mode in ('components', 'service') for case in groups[mode]['result'].get('cases', [])]
    audit = groups['audit']['result']
    audited = audit.get('native_pipeline', [])
    strict_audit = (len(audited) == 1+len(EXTRA_MUTATIONS) and audited[0]['accepted']
                    and audited[0]['verified_fact_count'] == 1
                    and all(not row['accepted'] and row['verified_fact_count'] == 0
                            and row['error']['type'] == 'ProviderError' for row in audited[1:]))
    passed = (before == after and len(cases) == 5 and all(case['passed'] for case in cases)
              and all(group['returncode'] == 0 for group in groups.values()) and strict_audit)
    result = {'schema': 'hepta.native-result-capacity.regression.v1', 'status': 'PASS' if passed else 'FAIL',
              'passed': sum(case['passed'] for case in cases), 'failed': sum(not case['passed'] for case in cases),
              'source_manifest_sha256': sha(CANDIDATE/'SOURCE-SEAL.json'), 'source_unchanged': before == after,
              'strict_native_pipeline_audit_passed': strict_audit, 'groups': groups,
              'elapsed_seconds': time.monotonic()-started, 'phone_calls': 0, 'real_model_requests': 0,
              'native_dispatches': 0, 'new_namespace_created': False, 'fixed19_qualification': False,
              'scope': 'Local synthetic parser/admission/capacity regressions; actual source pins and filesystem/process cleanup.'}
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)+'\n'
    if args.output:
        args.output.resolve().write_text(text)
    print(text, end='')
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
