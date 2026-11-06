#!/usr/bin/env python3
"""Pure source/entry compatibility controls; no actual task, BUILD or READY is invented."""
import ast
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE / 'candidate01'
denied_events = []


def audit(event, arguments):
    if event.startswith(('socket.', 'subprocess.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn',
        'os.kill', 'os.killpg', 'ctypes.dlopen',
    }:
        denied_events.append(event)
        raise RuntimeError('host control attempted an external effect: ' + event)


sys.addaudithook(audit)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def load(path, name):
    raw = path.read_bytes()
    value = types.ModuleType(name)
    value.__file__ = str(path)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


checks = []


def check(name, ok, detail=None):
    if not ok:
        raise AssertionError(name)
    checks.append({'name': name, 'passed': True, 'detail': detail})


def reject(name, call, expected):
    try:
        call()
    except (ValueError, RuntimeError) as error:
        check(name, expected in str(error), {'error_type': type(error).__name__, 'detail': str(error)})
    else:
        raise AssertionError(name + ': accepted')


class Snapshot:
    def __init__(self, values):
        self.values = values
        self.reads = []

    def read(self, path):
        name = Path(path).name
        self.reads.append(name)
        return self.values[name]


def main():
    report = json.loads((ROOT / 'CANDIDATE-SOURCES.json').read_bytes())
    for row in report['files']:
        raw = (ROOT / row['path']).read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
        if row['path'].endswith('.py'):
            ast.parse(raw, filename=row['path'])
    check('all_46_candidate_members_complete_and_python_parse', len(report['files']) == 46)
    collector_dir = ROOT / 'collector-package/collector'
    journal = load(collector_dir / 'native_journal_audit.py', 'native_journal_audit')
    assert callable(journal.strict_loads)
    api = load(collector_dir / 'mobile_use_evidence.py', 'reviewed_e2e_mobile_evidence')
    source = {p.name: p.read_bytes() for p in (ROOT / 'shared/provider/source').glob('*.py')}
    seal = json.loads((ROOT / 'source-origin/SOURCE-SEAL.json').read_bytes())
    snap = Snapshot(source)
    projection = api.load_projection_api(snap, Path('/synthetic-readonly-source'), seal)
    check('actual_fifteen_sources_and_seven_fragments_load',
          len(projection['verified_source_pins']) == 15
          and set(projection['verified_source_pins']) == set(source)
          and set(snap.reads) == set(source)
          and projection['projection_provider_source_sha256'] == sha(source['provider_phone_local.py']))
    check('reviewed_map_equals_actual_source_manifest',
          api.REVIEWED_HELPER_SOURCE_PINS == report['reviewed_production_source_pins'])
    parent = json.loads((ROOT / 'reference/PARENT-COLLECTOR-MANIFEST.original.json').read_bytes())
    changed = report['changed_production_pin_names']
    for name in changed:
        old = (HERE.parent / 'source-audit-v3/reference/production' / name).read_bytes()
        assert sha(old) == parent['reviewed_production_source_pins'][name]
        altered = copy.deepcopy(seal)
        for row in altered['production_files']:
            if Path(row['path']).name == name:
                row.update(bytes=len(old), sha256=sha(old))
        stale = dict(source, **{name: old})
        reject('old_source_rejected_' + name,
               lambda altered=altered, stale=stale: api.load_projection_api(
                   Snapshot(stale), Path('/synthetic-readonly-source'), altered), 'not reviewed')
    short = copy.deepcopy(seal)
    short['production_files'].pop()
    reject('missing_production_member_rejected',
           lambda: api.load_projection_api(Snapshot(source), Path('/synthetic-readonly-source'), short),
           'complete r10 source inventory')
    duplicate = copy.deepcopy(seal)
    duplicate['production_files'][-1] = duplicate['production_files'][0]
    reject('duplicate_production_member_rejected',
           lambda: api.load_projection_api(Snapshot(source), Path('/synthetic-readonly-source'), duplicate),
           'source pin identity differs')
    original_fragment_pin = api.PROJECTION_FRAGMENTS_SHA256
    api.PROJECTION_FRAGMENTS_SHA256 = '0' * 64
    reject('projection_fragment_hash_remains_enforced',
           lambda: api.load_projection_api(Snapshot(source), Path('/synthetic-readonly-source'), seal),
           'projection function/constant bytes are not reviewed')
    api.PROJECTION_FRAGMENTS_SHA256 = original_fragment_pin
    core = load(ROOT / 'operator-chain-template/root_acceptance_r10.py', 'reviewed_e2e_operator')
    manifest_path = ROOT / 'collector-package/MANIFEST.json'
    _, manifest, selected = core.manifest_sources(manifest_path, sha(manifest_path.read_bytes()), 'collector')
    check('original_operator_accepts_complete_current_collector_manifest',
          set(selected) == core.COLLECTOR_NAMES and len(selected) == 7
          and manifest['reviewed_production_source_pins'] == report['reviewed_production_source_pins'])
    check('operator_waits_for_actual_readiness_source', core.READINESS_SHA is None)
    check('original_materializer_identity_retained',
          core.MATERIALIZER_SHA == sha((ROOT / 'operator/materialize_case_r10.py').read_bytes()))
    coordinator = load(ROOT / 'coordinator/run_fixed19_e2e_root_once_UNBOUND.py', 'reviewed_e2e_coordinator')
    check('coordinator_exact_actual_shared_source_pin',
          coordinator.SHARED_PIN == report['shared_materials'])
    reject('unbound_coordinator_rejects_before_context_or_output',
           lambda: coordinator.validate_plan(b'{}', Path('/synthetic-never-created-plan')),
           'UNBOUND_E2E_OPERATOR_MANIFEST_NO_EXECUTION')
    argv = sys.argv
    try:
        sys.argv = [coordinator.__file__]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = coordinator.main()
        preview = json.loads(stdout.getvalue())
        check('coordinator_preview_has_six_phases_and_zero_effects',
              code == 0 and preview['state'] == 'SOURCE_PREVIEW_UNBOUND'
              and preview['phone_calls'] == 0 and preview['new_nonce_generated'] is False
              and preview['phase_order'] == ['register', 'sender_preview', 'sender_execute',
                                              'capture_export', 'collect', 'close'])
    finally:
        sys.argv = argv
    binder = load(HERE / 'bind_e2e_sources_UNBOUND.py', 'reviewed_e2e_source_binder')
    check('binder_is_explicitly_unbound', binder.FROZEN_INPUTS is None)
    try:
        sys.argv = [binder.__file__, '--bind-source-once']
        reject('unbound_binder_rejects_before_any_publication', binder.main,
               'UNBOUND_ACTUAL_SOURCE_INPUTS_NO_PUBLICATION')
    finally:
        sys.argv = argv
    ready = (ROOT / 'reference/readiness.original.py').read_bytes()
    consumer_template = (HERE.parent / 'R5-release-consumer/source/release_boundaries.py').read_bytes()
    check('consumer_parent_complete_pin_available', binder.pin(consumer_template) == binder.CONSUMER_TEMPLATE_PIN)
    # These are parser substitution fixtures, not a release or a READY receipt.
    synthetic_hash = 'a' * 64
    altered_ready = binder.replace_literal(ready, 'BOUNDARY_CONSUMER_SHA256', binder.OLD_CONSUMER_SHA,
                                           synthetic_hash)
    check('readiness_single_literal_inverse_preserves_entire_source',
          binder.replace_literal(altered_ready, 'BOUNDARY_CONSUMER_SHA256', synthetic_hash,
                                 binder.OLD_CONSUMER_SHA) == ready)
    altered_consumer = binder.replace_literal(consumer_template, 'PACKAGE_SHA', None, synthetic_hash)
    check('consumer_single_literal_inverse_preserves_entire_source',
          binder.replace_literal(altered_consumer, 'PACKAGE_SHA', synthetic_hash, None) == consumer_template)
    check('no_external_effect_attempted', denied_events == [])
    output = {
        'schema': 'hepta.fc33.e2e.source-controls.v1',
        'state': 'PASS_SOURCE_CONTROLS_ACTUAL_EXECUTION_UNBOUND',
        'candidate_manifest': binder.descriptor(ROOT / 'CANDIDATE-SOURCES.json',
                                                (ROOT / 'CANDIDATE-SOURCES.json').read_bytes()),
        'source': binder.descriptor(Path(__file__), Path(__file__).read_bytes()),
        'binder': binder.descriptor(HERE / 'bind_e2e_sources_UNBOUND.py',
                                   (HERE / 'bind_e2e_sources_UNBOUND.py').read_bytes()),
        'checks': checks, 'check_count': len(checks), 'external_effect_attempts': denied_events,
        'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0, 'new_nonces': 0,
        'actual_BUILD': None, 'actual_READY': None, 'actual_context': None,
        'actual_source_binding': None, 'fixed19_credit': 0,
        'synthetic_values_are_not_release_or_runtime_evidence': True,
    }
    path = HERE / 'SOURCE-CONTROLS.json'
    with path.open('xb') as stream:
        stream.write(enc(output))
    print(json.dumps({'state': output['state'], 'checks': len(checks),
                      'result': binder.descriptor(path, path.read_bytes()), 'phone_calls': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
