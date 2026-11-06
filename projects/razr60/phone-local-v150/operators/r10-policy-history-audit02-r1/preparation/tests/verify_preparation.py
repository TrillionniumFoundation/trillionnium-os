#!/usr/bin/env python3
"""Verify local audit02 source closure and exercise its complete OwnedOutput.

This does not stage files, invoke production main, read historical originals,
launch a Mac job, or acquire authority from its own source descriptors.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OLD_AUDITOR_SHA = '039f442f855ce27dc8c6f517785a4ca763b7729f1a5f17151f6a3deb2a99ef21'
OLD_CALLER_SHA = '0aa5342c32d28105b5229ad0f4128068f45ffc80c79498fa29c09cad6b96f4e1'
GUARD_AUDITOR_SHA = '88d441ff38197993e4b0b08812f68c8729bd61f5a4c53027f5617a1187cbadf6'
GUARD_TEST_SHA = 'e07d8717051bf34eb4af309b2a8f1de13230530493611217d5a59a18b76a475c'
PROBE_SHA = 'ca9f9df8ff993ad3a2f3390d88a6a51a8a290783385d7432a9d97f035f3eb3af'
TAG = '02-dirguard-4b572de398a74ce0'
BASE = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/'
            'stock16-hepta-local-model-Root-v150-r1')
SOURCE_ROOT = BASE/('epoch-policy-history-audit-source-1ad3-'+TAG)
AUDIT_OUT = BASE/('epoch-policy-history-audit-1ad3-'+TAG)
CALLER_OUT = BASE/('epoch-policy-history-audit-owned-1ad3-'+TAG)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replace_once(raw, old, new):
    assert raw.count(old) == 1, (old, raw.count(old))
    return raw.replace(old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    seal = json.loads((ROOT/'PREPARATION-SEAL.json').read_bytes())
    paths = {name: ROOT/'source'/name for name in
             ('audit_policy_history_once.py', 'run_policy_history_owned_once.py', 'SOURCE-MANIFEST.json')}
    before = {name: path.read_bytes() for name, path in paths.items()}
    manifest = json.loads(before['SOURCE-MANIFEST.json'])
    request = json.loads((ROOT/'process-start.NOT-EXECUTED.json').read_bytes())
    auditor = load('complete_prepared_policy_auditor', paths['audit_policy_history_once.py'])
    caller = load('complete_prepared_policy_caller', paths['run_policy_history_owned_once.py'])
    support_path = ROOT/'tests/guard_regression_cases.py'
    assert sha(support_path.read_bytes()) == GUARD_TEST_SHA
    guard_cases = load('unchanged_reviewed_guard_cases', support_path)
    probe_raw = (ROOT/'evidence/MAC-PROBE-stdout.original').read_bytes()
    assert sha(probe_raw) == PROBE_SHA
    probe = json.loads(probe_raw)
    rows = []

    def run(name, fn):
        try:
            observation = fn()
            rows.append({'name': name, 'passed': True, 'observation': observation})
        except BaseException as error:
            rows.append({'name': name, 'passed': False, 'error_type': type(error).__name__,
                         'error': str(error), 'traceback': traceback.format_exc()})

    def source_closure():
        assert sorted(path.name for path in (ROOT/'source').iterdir()) == sorted(paths)
        assert set(manifest) == {'schema', 'target_root', 'files'}
        assert manifest['schema'] == 'hepta.native-guard.policy-history-owned-source.v1'
        assert manifest['target_root'] == str(SOURCE_ROOT)
        assert len(manifest['files']) == 2
        assert manifest['files'] == seal['prepared_sources']
        for row in manifest['files']:
            assert set(row) == {'path', 'bytes', 'sha256'}
            assert row['path'] in before and row['path'] != 'SOURCE-MANIFEST.json'
            assert type(row['bytes']) is int and 0 < row['bytes'] <= caller.SOURCE_LIMIT
            assert row['bytes'] == len(before[row['path']])
            assert row['sha256'] == sha(before[row['path']])
        assert len({row['path'] for row in manifest['files']}) == 2
        assert seal['source_manifest']['bytes'] == len(before['SOURCE-MANIFEST.json'])
        assert seal['source_manifest']['sha256'] == sha(before['SOURCE-MANIFEST.json'])
        return {'closed_source_members': sorted(paths), 'manifest_sha256': sha(before['SOURCE-MANIFEST.json'])}

    def auditor_changes_exact():
        restored = before['audit_policy_history_once.py']
        for stem in ('epoch-policy-history-audit-source-1ad3-', 'epoch-policy-history-audit-1ad3-'):
            restored = replace_once(restored, (stem+TAG).encode(), (stem+'01').encode())
        assert len(restored) == 30473 and sha(restored) == GUARD_AUDITOR_SHA
        comment = (b'        # Own member creation can change directory nlink, size and timestamps.\n'
                   b'        # Keep device/inode/type+permissions/uid/gid fixed; current held/named\n'
                   b'        # full9, the exact member set and every leaf\'s full9/nlink checks remain.\n')
        restored = replace_once(restored, comment, b'')
        restored = replace_once(restored, b'current[:5] == self.identity[:5]',
                                b'current[:6] == self.identity[:6]')
        assert len(restored) == 30233 and sha(restored) == OLD_AUDITOR_SHA
        return {'full_byte_reconstruction_of_baseline': True, 'changes': 'one reviewed guard plus two fixed paths'}

    def caller_changes_exact():
        restored = before['run_policy_history_owned_once.py']
        for stem in ('epoch-policy-history-audit-source-1ad3-', 'epoch-policy-history-audit-1ad3-',
                     'epoch-policy-history-audit-owned-1ad3-'):
            restored = replace_once(restored, (stem+TAG).encode(), (stem+'01').encode())
        restored = replace_once(restored, ("'bytes':"+str(len(before['audit_policy_history_once.py']))).encode(),
                                b"'bytes':30233")
        restored = replace_once(restored, sha(before['audit_policy_history_once.py']).encode(),
                                OLD_AUDITOR_SHA.encode())
        assert len(restored) == 54438 and sha(restored) == OLD_CALLER_SHA
        return {'full_byte_reconstruction_of_baseline': True, 'changes': 'three fixed paths and actual auditor byte/SHA pin'}

    def fixed_binding():
        assert auditor.BASE == caller.BASE == BASE
        assert caller.SOURCE_ROOT == SOURCE_ROOT
        assert auditor.SOURCE == SOURCE_ROOT/'audit_policy_history_once.py'
        assert caller.SOURCE == SOURCE_ROOT/'run_policy_history_owned_once.py'
        assert caller.MANIFEST == SOURCE_ROOT/'SOURCE-MANIFEST.json'
        assert auditor.OUT == caller.AUDIT_OUT == AUDIT_OUT
        assert caller.OUT == CALLER_OUT
        assert len({SOURCE_ROOT, AUDIT_OUT, CALLER_OUT}) == 3
        pin = {'path': str(auditor.SOURCE), 'bytes': len(before['audit_policy_history_once.py']),
               'sha256': sha(before['audit_policy_history_once.py'])}
        assert caller.AUDITOR == pin
        assert caller.ARGV == ['/usr/bin/python3', '-I', '-B', str(auditor.SOURCE),
                               '--execute-fixed-history-audit-once']
        return {'caller_literal_matches_actual_auditor': True, 'remote_path_absence_observed': False}

    def unchanged_pins_and_budgets():
        assert auditor.ADOPTION == {'path': str(BASE/'policy-runtime-properties-r10-live-02/POLICY-ADOPTION.json'),
            'bytes': 208226, 'sha256': '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'}
        assert auditor.VERIFIER == {'path': str(BASE/'policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/source/policy_runtime_properties_verifier.py'),
            'bytes': 126796, 'sha256': '74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}
        assert auditor.BOOT == 'f8019f83-20a7-4f18-bea1-51c980621e4d'
        assert auditor.LIMITS['seconds'] == 90 and caller.CHILD_SECONDS == 100 and caller.CALLER_SECONDS == 120
        assert auditor.LIMITS['physical_read_bytes'] == 64*1024*1024
        assert auditor.LIMITS['original_unique_bytes'] == 32*1024*1024
        assert auditor.LIMITS['original_paths'] == 555
        assert caller.READ_LIMIT == 16*1024*1024 and caller.SOURCE_LIMIT == 131072
        assert caller.METADATA_LIMIT == 512*1024 and caller.HOST_OUTPUT_LIMIT == 65536
        assert auditor.EXPECTED_SUMMARY['verification_original_count'] == 554
        assert auditor.EXPECTED_SUMMARY['verification_original_bytes'] == 31518321
        return {'auditor_child_caller_seconds': [90, 100, 120], 'original_verifier_pin_retained': True}

    def budget_forecast():
        forecast = (31518321*2 + auditor.ADOPTION['bytes']*2 + auditor.LIMITS['source_bytes']*3
                    + 2*auditor.LIMITS['output_total_bytes'])
        assert forecast == 66992038 and forecast <= auditor.LIMITS['physical_read_bytes']
        assert 2*(len(auditor.SOURCE.parts)-1)+9 <= 64
        assert len(before['audit_policy_history_once.py']) <= auditor.LIMITS['source_bytes']
        assert len(before['run_policy_history_owned_once.py']) <= caller.SOURCE_LIMIT
        return {'physical_read_forecast': forecast, 'remaining_bytes': auditor.LIMITS['physical_read_bytes']-forecast}

    def process_template():
        assert set(request) == {'host', 'executable', 'args', 'cwd', 'timeout_seconds', 'idempotency_key'}
        assert request['host'] == 'mac' and request['executable'] == '/usr/bin/python3'
        assert request['args'] == ['-I', '-B', str(caller.SOURCE), '--source-manifest-sha256',
                                  sha(before['SOURCE-MANIFEST.json']), '--execute-fixed-owned-history-once']
        assert request['cwd'] == str(BASE) and request['timeout_seconds'] == 150
        assert request['idempotency_key'] == 'hepta-cp09-policy-history-audit02-dirguard-4b572de398a74ce0'
        assert seal['state'] == 'PREPARED_NOT_STAGED_NOT_EXECUTED'
        assert seal['idempotency_key_consumed'] is False and seal['historical_verifier_called'] is False
        assert len(seal['pre_execution_facts_missing']) == 5
        return {'template_sha256': sha((ROOT/'process-start.NOT-EXECUTED.json').read_bytes()),
                'process_started_by_this_test': False, 'live_preconditions_satisfied_by_this_test': False}

    for name, fn in [('exact_two_source_manifest', source_closure),
                     ('auditor_exact_mechanical_delta', auditor_changes_exact),
                     ('caller_exact_mechanical_delta', caller_changes_exact),
                     ('fixed_paths_and_literal_pin', fixed_binding),
                     ('historical_pins_and_budgets', unchanged_pins_and_budgets),
                     ('physical_read_and_fd_forecast', budget_forecast),
                     ('nonexecuted_process_template', process_template)]:
        run(name, fn)
    bindings = {key: getattr(auditor, key) for key in
                ('BASE', 'SOURCE', 'OUT', 'ADOPTION', 'VERIFIER', 'BOOT', 'LIMITS', 'EXPECTED_SUMMARY')}
    for name, fn in guard_cases.cases(auditor, probe):
        run('prepared_auditor_'+name, fn)
    assert all(getattr(auditor, key) == value for key, value in bindings.items())
    assert all(path.read_bytes() == before[name] for name, path in paths.items())
    report = {'schema': 'hepta.policy-history-audit02-preparation-regressions.v1',
              'status': 'PASS' if all(row['passed'] for row in rows) else 'FAIL',
              'passed': sum(row['passed'] for row in rows), 'failed': sum(not row['passed'] for row in rows),
              'cases': rows, 'whole_modules_imported': ['auditor', 'caller'],
              'real_prepared_auditor_class_exercised': True, 'source_bytes_unchanged': True,
              'historical_verifier_called': False, 'production_main_called': False,
              'remote_staging_performed': False, 'mac_jobs_started': 0, 'phone_calls': 0,
              'live_preconditions_satisfied_by_this_test': False,
              'pre_execution_facts_missing': seal['pre_execution_facts_missing'],
              'elapsed_seconds': time.monotonic()-started}
    raw = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False)+'\n'
    if args.output:
        args.output.write_text(raw)
    print(raw, end='')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
