#!/usr/bin/env python3
"""Host-only run of all original six geometry axes on current complete sources.

Synthetic inputs are explicitly retained. No actual release/READY admission is
substituted or claimed: run_fixtures is called as a pure regression entry.
The actual entry main still requires sealed_sources and real release originals.
"""
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
REFERENCE = ROOT / 'reference/cpu-negative-capture-generation-final01/package/validation/parent-source-fixtures/component/source'
ASSETS = ROOT / 'reference/component-physical-final02/package/reference/geometry-assets'
CANDIDATE = ROOT / 'candidate/component/verify_unqualified_geometry_fixture.py'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, size, digest):
    raw = path.read_bytes()
    assert len(raw) == size and sha(raw) == digest
    return raw


def load(raw, name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def resources():
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'fd_count': len(os.listdir('/proc/self/fd')),
            'thread_ids': sorted(t.ident for t in threading.enumerate()),
            'child_cpu': [child.ru_utime, child.ru_stime]}


def main():
    assert len(sys.argv) == 2
    out = Path(sys.argv[1])
    assert out.is_absolute() and out.parent.resolve(strict=True) == out.parent
    os.umask(0o077)
    out.mkdir(mode=0o700)
    sys.dont_write_bytecode = True
    def no_external(event, args):
        if event.startswith(('socket.', 'subprocess.')) or event in {
                'os.system', 'os.fork', 'os.posix_spawn', 'os.exec', 'os.kill', 'os.killpg'}:
            raise AssertionError('excluded effect: ' + event)
    sys.addaudithook(no_external)
    before = resources()
    helper_path = PACKAGE / 'test_shared_business_admission_v3.py'
    helper = load(checked(helper_path, 40884, 'dbbfece5877955b68a98770af41a9010365990b3fdbe29a8c9c37e648ec6756a'), 'native_fixture_source', helper_path)
    pins, originals = helper.verify_sources(PACKAGE)
    sys.path.insert(0, str(PACKAGE / 'candidate/source'))
    daily = importlib.import_module('daily_phone_local')
    obs = importlib.import_module('phone_observation_tools')
    guards = importlib.import_module('phone_task_guards')
    provider = importlib.import_module('provider_openai_compatible')
    imported = []
    for row in pins['files']:
        if row['path'].startswith('candidate/source/'):
            module = importlib.import_module(Path(row['path']).stem)
            assert Path(module.__file__).resolve() == PACKAGE / row['path']
            assert sha(Path(module.__file__).read_bytes()) == row['sha256']
            imported.append(row)
    assert len(imported) == 15 and len(daily.PARENTS) == 14
    old_path = REFERENCE / 'verify_unqualified_geometry_fixture.py'
    old = load(checked(old_path, 18636, '3cbc0d9d77629c2183f706fc897075a16952e4cb586f16fef29a65e521c81487'), 'old_geometry_fixture', old_path)
    new = load(checked(CANDIDATE, 24236, '5ae3f51d89d8e1d36be07846b34b09f652fdf39db0db0eee98ed0f194c720a2d'), 'new_geometry_fixture', CANDIDATE)
    context_path = REFERENCE / 'component_source_context.py'
    C = load(checked(context_path, 15724, '2f5e6169f66017bee29b32a4f05d9cb8a0936e01c36b7b1f59aa015ba1ffb02d'), 'original_component_context', context_path)
    assets = {name: checked(ASSETS / ('synthetic.' + ('jpg' if name == 'jpeg' else name)), size, digest)
              for name, (size, digest) in new.ASSETS.items()}
    old_root = C.fresh_directory(out / 'original-fixture-failure')
    try:
        old.run_fixtures(C, obs, guards, provider, old_root, 'synthetic-old-interface-reproduction', assets)
    except provider.ProviderError as error:
        assert str(error) == 'phone native binding lacks the accepted turn scope'
        reproduced = {'expected_failure': True, 'type': type(error).__name__, 'message': str(error)}
    else:
        raise AssertionError('original native scope incompatibility was not reproduced')
    root = C.fresh_directory(out / 'candidate-fixture')
    evidence = new.run_fixtures(C, obs, guards, provider, root, 'synthetic-current-native-geometry', assets)
    assert len(evidence.rows) == 6 and all(row['passed'] is True for row in evidence.checks)
    assert before == resources()
    assert helper.verify_sources(PACKAGE)[1] == originals
    report = {'schema': 'fc33.geometry-native-v3-host-controls.v1', 'status': 'PASS',
        'original_scope_failure': reproduced, 'production_source_count': len(imported),
        'production_source_pins': imported, 'geometry_axes': evidence.rows,
        'check_count': len(evidence.checks), 'checks': evidence.checks,
        'before': before, 'after': resources(), 'input_receipts_and_scope_synthetic': True,
        'full_production_consumers_called': ['PhoneTools.map', 'PhoneTools.prepare', 'native_streams',
            'validate_viewport', 'phone_task_guards.verify_return'],
        'actual_BUILD_or_READY_supplied': False, 'sealed_sources_called': False,
        'actual_entry_admission_unchanged': True, 'physical_test': False, 'phone_calls': 0,
        'model_calls': 0, 'dispatches': 0, 'formal_NEG03_qualification': False,
        'formal_COMP01_qualification': False, 'direct_return_helper_unchanged': True}
    row = C.put(out / 'RESULT.json', C.encode(report))
    print(json.dumps({'status': 'PASS', 'axes': 6, 'checks': len(evidence.checks), 'result': row,
                      'physical_qualification': False}, sort_keys=True))


if __name__ == '__main__':
    main()
