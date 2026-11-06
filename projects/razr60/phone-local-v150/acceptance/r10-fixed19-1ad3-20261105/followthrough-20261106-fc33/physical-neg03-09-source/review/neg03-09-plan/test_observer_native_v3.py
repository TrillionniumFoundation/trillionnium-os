#!/usr/bin/env python3
"""Real observer/parser consumers with explicit synthetic on-disk originals.

No live observer, actor, adapter, model, transport or dispatcher is constructed.
Only BASE in the isolated observer modules points to the owned host fixture.
"""
import base64
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import sys
import threading
import types

ROOT = Path(__file__).resolve().parent
PACKAGE = ROOT.parent / 'source-audit-v3'
ORIGINAL = ROOT / 'reference/physical-fault-final01/package/validation/operator-source-fixture/source'
CANDIDATE = ROOT / 'candidate/shared/observe_cancel_phase_r10.py'
PINS = {
    'observer_original': (17449, '0418a96677d6561ef44f03a59f62997fb616ca0f091285c9ab9bf7cfb4885cb9'),
    'observer_candidate': (17507, '5d9839ae004a91857b5f9ca978d25fb0b13087c0af57d0ea850a842e6f28d540'),
    'fixture_helpers': (40884, 'dbbfece5877955b68a98770af41a9010365990b3fdbe29a8c9c37e648ec6756a'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def put(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as handle:
        handle.write(enc(value))


def checked(path, wanted):
    raw = path.read_bytes()
    assert (len(raw), sha(raw)) == wanted
    return raw


def load(raw, name, path, register=False):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    if register:
        assert name not in sys.modules
        sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def resources():
    u = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'fd_count': len(os.listdir('/proc/self/fd')),
            'thread_ids': sorted(t.ident for t in threading.enumerate()),
            'child_cpu': [u.ru_utime, u.ru_stime]}


def no_external(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in {
            'os.system', 'os.fork', 'os.posix_spawn', 'os.exec', 'os.kill', 'os.killpg'}:
        raise AssertionError('excluded effect: ' + event)


def main():
    assert len(sys.argv) == 2
    output = Path(sys.argv[1])
    assert output.is_absolute() and output.parent.resolve() == output.parent
    os.umask(0o077)
    output.mkdir(mode=0o700)
    sys.dont_write_bytecode = True
    sys.addaudithook(no_external)
    before = resources()
    helper_path = PACKAGE / 'test_shared_business_admission_v3.py'
    helper = load(checked(helper_path, PINS['fixture_helpers']), 'native_v3_fixture_helpers', helper_path)
    source_pins, originals = helper.verify_sources(PACKAGE)
    sys.path.insert(0, str(PACKAGE / 'candidate/source'))
    daily = importlib.import_module('daily_phone_local')
    obs = importlib.import_module('phone_observation_tools')
    guards = importlib.import_module('phone_task_guards')
    helper.OBS = obs
    helper.GUARDS = guards
    imported = []
    for row in source_pins['files']:
        if row['path'].startswith('candidate/source/'):
            module = importlib.import_module(Path(row['path']).stem)
            assert Path(module.__file__).resolve() == PACKAGE / row['path']
            assert sha(Path(module.__file__).read_bytes()) == row['sha256']
            imported.append(row)
    assert len(imported) == 15 and len(daily.PARENTS) == 14
    for name in ('active_runtime_r10', 'cancel_phase'):
        path = ORIGINAL / (name + '.py')
        load(path.read_bytes(), name, path, register=True)
    old = load(checked(ORIGINAL / 'observe_cancel_phase_r10.py', PINS['observer_original']),
               'observer_original_host_control', ORIGINAL / 'observe_cancel_phase_r10.py')
    new = load(checked(CANDIDATE, PINS['observer_candidate']), 'observer_candidate_host_control', CANDIDATE)
    base = output / 'synthetic-phone-files'
    old.BASE = new.BASE = base
    run = base / 'provider-state/evidence/synthetic-run'
    action = '1234567890abcdef1234567890abcdef'
    call_id = 'synthetic-observer-native-v3'
    scope = {name: 'synthetic-' + name for name in
             ('session_id', 'profile_id', 'task_id', 'turn_id', 'turn_stream_id')}
    component = 'org.example.hepta.synthetic/.FixtureActivity'
    command = b': synthetic parser fixture; never executed'
    wire = obs.native_bound_call({'call_id': call_id, 'tool': 'shell.exec', 'argv': [
        '/usr/bin/python3', str(base / 'tool_client_r6.py'), 'execute', '--action-id', action,
        '--command-b64', base64.b64encode(command).decode(), '--timeout-ms', '60000']}, scope)
    semantic = {'call_id': call_id, 'capture_id': action, 'semantic_tool': 'phone.open_app',
                'alias': 'synthetic-probe', 'component': component, 'wire_call': wire, 'turn': scope}
    put(run / ('semantic-' + sha(call_id.encode()) + '.json'), semantic)
    put(run / 'task-app-scope.json', {'apps': [{'alias': 'synthetic-probe', 'component': component}]})
    put(base / ('provider-state/evidence/action-ledger/' + action + '.intent.json'), {
        'action_id': action, 'command_sha256': sha(command),
        'semantic_identity': {key: scope[key] for key in old.KEYS[:-1]}, 'automatic_replay': False})
    receipt = {'terminal': True, 'state': 'completed', 'executor_revision': 6,
               'executor_context': 'u:r:trillionnium_owner_open_phone_executor:s0',
               'peer_context': 'u:r:trillionnium_owner_open_bootstrap:s0',
               'execution_context': 'u:r:trillionnium_owner_open_phone_worker:s0',
               'execution_credentials_scope': 'android_shell_uid2000',
               'handshake_stage': 'worker_entry_after_exec_transition',
               'execution_supplementary_group_count': 0, 'dispatch_count': 1,
               'pid': 12345, 'pgid': 12345, 'waitpid_identity_lost': False,
               'action_id': action, 'command_sha256': sha(command), 'can_redispatch': False}
    for key in ('effect_started', 'process_group_established', 'waitpid_joined', 'process_group_absent',
                'execution_credentials_verified', 'supplementary_groups_cleared', 'worker_domain_verified'):
        receipt[key] = True
    for key in ('required_execution_uid', 'required_execution_gid', 'execution_uid', 'execution_euid',
                'execution_gid', 'execution_egid'):
        receipt[key] = 2000
    put(base / ('executor-r6/actions/' + action + '/receipt.json'), receipt)
    payload = {'schema': 'hepta.local-app-open.v150.2', 'operation_id': action,
               'launch_exit_code': 0, 'launch_flags': guards.APP_OPEN_FLAGS,
               'observation_attempts': 2, 'observation_stable': True,
               'launch_b64': helper.b64('Status: ok\nActivity: ' + component + '\n'),
               'page_b64': helper.b64(helper.page(component)), 'viewport_b64': helper.b64(helper.viewport())}
    result = helper.native(call_id, enc(payload), 'shell.exec', wire_call=wire, scope=scope)
    outgoing = [{'kind': 'tool.call', 'call': wire}]
    cases = []

    def passed(name, **value):
        cases.append({'name': name, 'passed': True, **value})

    try:
        old.dispatches(run, scope, [result], outgoing)
    except TypeError as error:
        assert 'expected_call' in str(error) and 'expected_scope' in str(error)
        passed('original_consumer_missing_keywords_reproduced', error=str(error))
    else:
        raise AssertionError('original interface defect not reproduced')
    calls, read_originals = new.dispatches(run, scope, [result], outgoing)
    assert len(calls) == 1 and calls[0]['verified_app_open'] is True
    assert calls[0]['verified_component'] == guards.component(component) and len(read_originals) == 3
    passed('candidate_full_observer_to_native_v3_and_public_app_parser', calls=calls,
           retained_original_count=len(read_originals))
    bad = copy.deepcopy(result)
    bad['registry']['request_sha256'] = 'f' * 64
    bad_scope = dict(scope, task_id='synthetic-different-task')
    wrong_scope = helper.native(call_id, enc(payload), 'shell.exec', wire_call=wire, scope=bad_scope)
    wrong_target_wire = dict(wire, target_id='synthetic-wrong-target')
    wrong_target = helper.native(call_id, enc(payload), 'shell.exec', wire_call=wrong_target_wire, scope=scope)
    for name, value in [('wrong_request_hash', bad), ('self_consistent_wrong_scope', wrong_scope),
                        ('self_consistent_wrong_result_target', wrong_target)]:
        try:
            new.dispatches(run, scope, [value], outgoing)
        except obs.ProviderError as error:
            passed(name, error=str(error))
        else:
            raise AssertionError('corrupt native result accepted: ' + name)
    changed = copy.deepcopy(outgoing)
    changed[0]['call']['argv'][6] = helper.b64(b': changed fixture command')
    try:
        new.dispatches(run, scope, [result], changed)
    except ValueError as error:
        assert str(error) == 'semantic original differs'
        passed('existing_semantic_wire_gate_preserved', error=str(error))
    else:
        raise AssertionError('semantic mismatch accepted')
    assert before == resources()
    assert helper.verify_sources(PACKAGE)[1] == originals
    checked(CANDIDATE, PINS['observer_candidate'])
    checked(ORIGINAL / 'observe_cancel_phase_r10.py', PINS['observer_original'])
    passed('complete_fifteen_source_pins_and_resource_baseline', before=before, after=resources())
    record = {'schema': 'fc33.physical-observer-native-v3-controls.v1', 'status': 'PASS',
              'passed': len(cases), 'total': len(cases), 'cases': cases,
              'script': {'path': str(Path(__file__).resolve()), **pin(Path(__file__).read_bytes())},
              'source_pins': PINS, 'imported_current_production': imported,
              'daily_fourteen_parent_verifier_executed': True,
              'limits': {'all_phone_files_native_frames_and_public_receipts_synthetic': True,
                         'actual_functions': ['observe_cancel_phase.dispatches', 'native_bound_call',
                                              'native_streams', 'require_r6_terminal', 'verify_app_open',
                                              'validate_viewport'],
                         'live_active_runtime_or_phase_observation_executed': False,
                         'PhoneLocalAdapter_constructed': False, 'validate_executor_bypassed': False,
                         'phone_calls': 0, 'native_dispatches': 0, 'model_requests': 0,
                         'actual_BUILD': None, 'actual_READY': None,
                         'whole_NEG03_through_NEG09_qualified': False}}
    put(output / 'RESULT.json', record)
    raw = (output / 'RESULT.json').read_bytes()
    print(json.dumps({'status': 'PASS', 'passed': len(cases),
                      'result': {'path': str(output / 'RESULT.json'), **pin(raw)}}, sort_keys=True))


if __name__ == '__main__':
    main()
