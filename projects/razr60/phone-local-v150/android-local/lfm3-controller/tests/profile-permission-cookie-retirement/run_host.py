#!/usr/bin/env python3
"""Strict host gate for retained permission-cookie retirement; no Android transport."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

FIXTURE_SHA = '06dbf806886ffde8834afa20bc3444db31214e2ecb7e75bb1c6f96b7e78c9837'
SOURCE_RESULT_SHA = '6484c4c15146e59717d2d8b136a7ee35aa470431419ccd1b306e217f970cf682'
EXPECTED_ASSERTIONS = 316
EXPECTED_NAMES = ["saved root transition keeps strict equality false and requires a fresh after-leaf read","retained pair resamples the whole graph after its launch cookie retires","unclaimed leaf cannot gain the retained cookie-retirement exception","private retained Binder and both original cookie anchors are required","root or leaf immutable identity and unknown presentation changes still refuse","unpaired different duplicate or reordered cookie changes cannot request retry","retry pins the complete after-cookie sets and never accepts the earlier unstable pair","fresh complete retry reruns task scope global membership and component guards","original deadline cancellation and three-sample ceiling remain effective","ordinary observe window permission input and cleanup never acquire cookie retry"]
EMPTY_SHA = hashlib.sha256(b'').hexdigest()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def fixture_java(fixture, output):
    value = json.loads(fixture.read_text())
    if value['leaf']['after'] is not None or value['leaf_count'] != -1:
        raise RuntimeError('Unsaved real after-leaf must remain explicitly unknown')
    lines = ['package org.trillionnium.hepta.background;',
             'import java.util.List;',
             '/** Exact saved primitive rows. Arguments are explicitly synthetic live objects. */',
             'final class ObservedPermissionPairFixture {',
             '    static final String SHA="' + FIXTURE_SHA + '";']
    for method, data in (('rootBefore', value['root']['before']),
                         ('rootAfter', value['root']['after']),
                         ('leafBefore', value['leaf']['before'])):
        args = [data[k] for k in ('task_id', 'display_id', 'user_id', 'parent_task_id',
                                 'full_uid', 'top_activity_info_uid', 'activity_count')]
        rendered = [str(v) for v in args] + ['token', 'cookies']
        rendered += [json.dumps(data[k], ensure_ascii=True) for k in ('intent', 'base', 'top', 'real', 'orig')]
        rendered += [str(data[k]).lower() for k in ('running', 'visible')]
        lines += ['    static BackgroundOwnedSingleTask.Task ' + method + '(Object token,List<Object> cookies){',
                  '        return new BackgroundOwnedSingleTask.Task(' + ','.join(rendered) + ');', '    }']
    lines.append('}')
    generated = output / 'ObservedPermissionPairFixture.java'
    generated.write_text('\n'.join(lines) + '\n')
    return generated

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'java-home', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source, jdk, output = args.source.resolve(), args.java_home.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    fixture = here / 'fixtures/observed-pair.json'
    provenance = here / 'fixtures/PROVENANCE.json'
    test = here / 'ProfilePermissionCookieRetirementHostTest.java'
    original = source / 'tests/profile-permission-transient/run_host.py'
    tracked = sorted(set(list((source / 'src').rglob('*.java'))
                         + list((source / 'tests/profile-permission-transient').rglob('*'))
                         + [source / 'tests/profile-broker/ProfileBrokerHostTest.java',
                            Path(__file__).resolve(), fixture, provenance, test, here / 'README.md', here / 'CASE-CONTRACT.json']))
    tracked = [p for p in tracked if p.is_file()]
    result = {'schema': 'hepta.profile-permission-cookie-retirement-canonical-host.v1',
              'all_pass': False, 'phone_contacted': False, 'android_build': False,
              'business_success_claimed': False, 'stages': []}
    pins = {}
    def run(name, argv):
        begin = time.monotonic()
        p = subprocess.run(argv, capture_output=True, timeout=60)
        (output / (name + '.stdout')).write_bytes(p.stdout)
        (output / (name + '.stderr')).write_bytes(p.stderr)
        result['stages'].append({'name': name, 'exit_code': p.returncode,
                                 'elapsed_seconds': time.monotonic() - begin,
                                 'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(),
                                 'stderr_sha256': hashlib.sha256(p.stderr).hexdigest()})
        if p.returncode != 0 or p.stderr:
            raise RuntimeError(name + ' failed; inspect preserved raw output')
        return p.stdout
    try:
        pins = {str(p.relative_to(source)): sha(p) for p in tracked}
        result['source_inputs'] = pins
        contract = json.loads((here / 'CASE-CONTRACT.json').read_text())
        expected_contract = {'schema': 'hepta.profile-permission-cookie-retirement-case-contract.v1',
            'cases': len(EXPECTED_NAMES), 'assertions': EXPECTED_ASSERTIONS, 'case_names': EXPECTED_NAMES,
            'case_names_sha256': hashlib.sha256('\n'.join(EXPECTED_NAMES).encode()).hexdigest(),
            'fixture_sha256': FIXTURE_SHA,
            'stages': ['original-permission-and-state', 'compile-cookie-retirement', 'cookie-retirement'],
            'original_permission': {'cases': 16, 'assertions': 348},
            'original_state_settle': {'cases': 29, 'assertions': 626}}
        if contract != expected_contract:
            raise RuntimeError('Frozen case contract differs')
        result['case_contract_sha256'] = sha(here / 'CASE-CONTRACT.json')
        if sha(fixture) != FIXTURE_SHA:
            raise RuntimeError('Saved primitive diagnostic fixture changed')
        prov = json.loads(provenance.read_text())
        if (prov['source_result_sha256'] != SOURCE_RESULT_SHA
                or prov['task_id'] != '08be409289364962bb5ea506a51c344b'
                or prov['actual_after_leaf_available'] is not False
                or prov['fixture_sha256'] != FIXTURE_SHA):
            raise RuntimeError('Real/synthetic provenance boundary changed')
        result['fixture'] = {'sha256': FIXTURE_SHA, 'bytes': fixture.stat().st_size,
                             'source_result_sha256': SOURCE_RESULT_SHA,
                             'actual_root_before_after_and_leaf_before': True,
                             'actual_after_leaf_available': False,
                             'test_after_leaf_synthetic': True,
                             'binders_cookies_clock_synthetic': True,
                             'coordinator_ids_explicitly_remapped_to_existing_host_rig': True}
        original_output = output / 'original'
        stdout = run('original-permission-and-state', [sys.executable, '-B', str(original),
                     '--source', str(source), '--java-home', str(jdk), '--output', str(original_output)])
        legacy = json.loads((original_output / 'RESULT.json').read_text())
        if json.loads(stdout) != legacy:
            raise RuntimeError('Original runner stdout/result binding differs')
        if (legacy.get('all_pass') is not True
                or legacy.get('source_inputs_unchanged') is not True
                or legacy.get('private_actual_unchanged') is not True
                or legacy.get('phone_contacted') is not False
                or legacy.get('synthetic_summary', {}).get('cases') != 16
                or legacy.get('synthetic_summary', {}).get('assertions') != 348
                or legacy.get('state_settle_summary', {}).get('cases') != 29
                or legacy.get('state_settle_summary', {}).get('assertions') != 626
                or [s['name'] for s in legacy['stages']] != ['compile', 'synthetic', 'state-settle']
                or any(s['exit_code'] != 0 or s['stderr_sha256'] != EMPTY_SHA for s in legacy['stages'])):
            raise RuntimeError('Original permission/state regression is not complete')
        result['original_result_sha256'] = sha(original_output / 'RESULT.json')
        result['original_summaries'] = {k: legacy[k] for k in ('synthetic_summary', 'state_settle_summary')}
        result['original_runner_sha256'] = sha(original)
        generated = fixture_java(fixture, output)
        result['generated_fixture_adapter_sha256'] = sha(generated)
        classes = original_output / 'classes'
        run('compile-cookie-retirement', [str(jdk / 'bin/javac'), '--release', '8', '-encoding', 'UTF-8',
            '-Xlint:all,-options', '-Werror', '-proc:none', '-cp', str(classes), '-d', str(classes), str(generated), str(test)])
        stdout = run('cookie-retirement', [str(jdk / 'bin/java'), '-cp', str(classes),
                     'org.trillionnium.hepta.background.ProfilePermissionCookieRetirementHostTest', str(fixture)])
        lines = stdout.decode('utf-8').splitlines()
        summaries = [json.loads(line) for line in lines if line.startswith('{')]
        names = [line[5:] for line in lines if line.startswith('PASS ')]
        if len(summaries) != 1 or len(lines) != len(EXPECTED_NAMES) + 1:
            raise RuntimeError('Cookie-retirement stdout is missing or duplicated')
        summary = summaries[0]
        result['summary'] = summary
        if (summary.get('schema') != 'hepta.profile-permission-cookie-retirement-host.v1'
                or summary.get('passed') is not True or summary.get('cases') != len(EXPECTED_NAMES)
                or summary.get('assertions') != EXPECTED_ASSERTIONS
                or summary.get('case_names') != EXPECTED_NAMES or names != EXPECTED_NAMES
                or summary.get('fixture_sha256') != FIXTURE_SHA
                or any(summary.get(k) is not True for k in
                    ('real_coordinator_executed', 'real_platform_pair_executed', 'after_leaf_synthetic',
                     'binders_and_cookies_synthetic'))
                or any(summary.get(k) is not False for k in
                    ('phone_contacted', 'business_success_claimed', 'android_build'))):
            raise RuntimeError('Exact cookie-retirement result contract differs')
        result['case_names_sha256'] = hashlib.sha256('\n'.join(names).encode()).hexdigest()
        result['source_inputs_unchanged'] = pins == {str(p.relative_to(source)): sha(p) for p in tracked}
        result['all_pass'] = result['source_inputs_unchanged'] and len(result['stages']) == 3
    except Exception as error:
        result['error_type'] = type(error).__name__
        result['error'] = str(error)
        if pins:
            result['source_inputs_unchanged'] = pins == {str(p.relative_to(source)): sha(p) for p in tracked}
    (output / 'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: result.get(k) for k in ('schema', 'all_pass', 'error', 'source_inputs_unchanged',
                                                'summary', 'stages')}, sort_keys=True))
    return 0 if result['all_pass'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
