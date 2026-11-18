#!/usr/bin/env python3
"""Pure-JVM permission-transient gate; synthetic by default, optional private exact replay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

SYNTHETIC_SHA = '7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0'
ACTUAL_SHA = '6e945458e4af25724f189ff477ebb4ab19a58099762d3d6827c3d42728c4d2fb'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'java-home', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--real-dump', type=Path,
                        help='Additional exact private replay; file must remain outside the source tree')
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    fixture = here / 'fixtures/synthetic-activities.txt'
    background = source / 'src/org/trillionnium/hepta/background'
    names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol', 'PublicOwnGroupPolicy', 'FixedIntentTools',
             'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask', 'ProfileTaskPolicy',
             'ProfileOwnedTask', 'ProfilePermissionTransient', 'ProfileDisplayCustody']
    files = [background / (name + '.java') for name in names]
    files += [source / 'tests/profile-broker/ProfileBrokerHostTest.java',
              here / 'ProfilePermissionTransientHostTest.java', here / 'ProfileStateSettleHostTest.java']
    broker = background / 'BackgroundDisplayBroker.java'
    session = source / 'src/org/trillionnium/hepta/local/BackgroundSession.java'
    tracked = files + [Path(__file__).resolve(), fixture, here / 'README.md', broker, session]
    result = {'schema': 'hepta.profile-permission-transient-canonical-host.v1',
              'all_pass': False, 'phone_contacted': False, 'android_build': False,
              'android_adapters_compiled': False, 'java_release': 8,
              'taskinfo_fixtures_synthetic': True, 'real_dump_requested': args.real_dump is not None,
              'source_inputs': {}, 'stages': []}
    pins = {}
    private = None
    private_pin = None

    def run(name, argv):
        start = time.monotonic()
        ran = subprocess.run(argv, capture_output=True, timeout=45)
        (output / (name + '.stdout')).write_bytes(ran.stdout)
        (output / (name + '.stderr')).write_bytes(ran.stderr)
        result['stages'].append({'name': name, 'exit_code': ran.returncode,
                                'elapsed_seconds': time.monotonic() - start,
                                'stdout_sha256': hashlib.sha256(ran.stdout).hexdigest(),
                                'stderr_sha256': hashlib.sha256(ran.stderr).hexdigest()})
        if ran.returncode or ran.stderr:
            raise RuntimeError(name + ' failed; see stage stdout/stderr')
        return ran.stdout

    try:
        pins = {str(path.relative_to(source)): sha(path) for path in tracked}
        result['source_inputs'] = pins
        broker_text = broker.read_text()
        state = broker_text.split('} else if ("state".equals(r.operation)) {', 1)[1].split(
            '} else if(config.profileTarget!=null&&"launch".equals(r.operation)) {', 1)[0]
        state_call = ('if(profileOwnedTask!=null&&!profileOwnedTask.observeStateUntil(Math.min(r.deadline,expires)-100))'
                      'throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_OBSERVED");')
        # The new scope has a distinct permission-preparation state operation.
        # Check its exact selector before projecting ONLY the legacy null-scope
        # branch to the original literal. Keep the original 1800 ms assertion
        # below; this source projection grants no transport/display authority.
        session_text = session.read_text()
        state_selector = 'publicOwnGroupScope!=null&&permissionPreparing?"prepare_state":"state"'
        current_verify = ('void verifyRemote()throws Exception{requireActive();accept(call('
                          + state_selector + ',null,1800),true);requireActive();}')
        if (session_text.count(current_verify) != 1
                or session_text.count('call(' + state_selector + ',null,1800)') != 1):
            raise RuntimeError('Exact scope-guarded state/preparation request wiring differs')
        legacy_session_text = session_text.replace(
            'call(' + state_selector + ',null,1800)', 'call("state",null,1800)', 1)
        if (state_call not in state or broker_text.count('.observeStateUntil(') != 1
                or 'if(profileOwnedTask.observe()){observed=true;break;}' not in broker_text
                or 'profileOwnedTask.window(r.windowId,r.observedTaskId,Math.min(r.deadline,expires))' not in broker_text
                or 'accept(call("state",null,1800),true)' not in legacy_session_text):
            raise RuntimeError('State-only original-request wiring differs')
        result['state_settle_wiring'] = {'state_only': True, 'state_request_budget_ms': 1800,
                                        'response_margin_ms': 100, 'new_rpc': False,
                                        'coordinator_compiled_and_executed': False,
                                        'android_broker_wiring_static_only': True}
        result['state_settle_wiring']['legacy_projection_scope'] = 'publicOwnGroupScope == null'
        result['state_settle_wiring']['exact_new_selector_checked'] = state_selector
        result['state_settle_wiring']['new_scope_coordinator_execution_claimed'] = False
        if fixture.stat().st_size != 2306 or sha(fixture) != SYNTHETIC_SHA:
            raise RuntimeError('Synthetic fixture pin differs')
        result['synthetic_fixture'] = {'bytes': 2306, 'sha256': SYNTHETIC_SHA, 'kind': 'authored_synthetic'}
        if args.real_dump is not None:
            private = args.real_dump.resolve(strict=True)
            if private == source or source in private.parents:
                raise RuntimeError('Private actual dump must remain outside source')
            private_pin = sha(private)
            if private.stat().st_size != 91980 or private_pin != ACTUAL_SHA:
                raise RuntimeError('Explicit private actual fixture pin differs')
            result['private_actual_fixture'] = {'bytes': 91980, 'sha256': ACTUAL_SHA,
                                                'kind': 'actual_saved_bytes', 'copied_into_source': False}
        classes = output / 'classes'
        run('compile', [str(args.java_home / 'bin/javac'), '--release', '8', '-encoding', 'UTF-8',
                        '-Xlint:all,-options', '-Werror', '-proc:none', '-d', str(classes)]
            + [str(path) for path in files])
        cases = [('synthetic', fixture)]
        if private is not None:
            cases.append(('actual', private))
        for kind, path in cases:
            stdout = run(kind, [str(args.java_home / 'bin/java'), '-cp', str(classes),
                               'org.trillionnium.hepta.background.ProfilePermissionTransientHostTest',
                               str(path), kind])
            summaries = [json.loads(line) for line in stdout.decode('utf-8').splitlines()
                         if line.startswith('{')]
            if len(summaries) != 1:
                raise RuntimeError(kind + ' summary missing or duplicated')
            summary = summaries[0]
            expected_sha = SYNTHETIC_SHA if kind == 'synthetic' else ACTUAL_SHA
            if not (summary.get('passed') is True and summary.get('cases') == 16
                    and summary.get('fixture_kind') == kind
                    and summary.get('fixture_sha256') == expected_sha
                    and summary.get('taskinfo_fixtures_synthetic') is True
                    and summary.get('phone_contacted') is False
                    and summary.get('android_build') is False):
                raise RuntimeError(kind + ' result contract differs')
            result[kind + '_summary'] = summary
        stdout = run('state-settle', [str(args.java_home / 'bin/java'), '-cp', str(classes),
                                     'org.trillionnium.hepta.background.ProfileStateSettleHostTest', str(fixture)])
        summaries = [json.loads(line) for line in stdout.decode('utf-8').splitlines()
                     if line.startswith('{')]
        if len(summaries) != 1:
            raise RuntimeError('State settle summary missing or duplicated')
        settled = summaries[0]
        names = settled.get('case_names')
        if not (settled.get('schema') == 'hepta.profile-state-settle-host-tests.v1'
                and settled.get('passed') is True and settled.get('cases') == 21
                and type(names) is list and len(names) == 21 and len(set(names)) == 21
                and type(settled.get('assertions')) is int and settled['assertions'] > 0
                and settled.get('fixture_sha256') == SYNTHETIC_SHA
                and settled.get('real_coordinator_executed') is True
                and settled.get('framework_and_clock_synthetic') is True
                and settled.get('phone_contacted') is False and settled.get('android_build') is False):
            raise RuntimeError('State settle result contract differs')
        result['state_settle_summary'] = settled
        result['state_settle_wiring']['coordinator_compiled_and_executed'] = True
        result['source_inputs_unchanged'] = pins == {str(path.relative_to(source)): sha(path) for path in tracked}
        result['private_actual_unchanged'] = private is None or sha(private) == private_pin
        expected_stages = 4 if private is not None else 3
        result['all_pass'] = (len(result['stages']) == expected_stages
                              and result['source_inputs_unchanged'] and result['private_actual_unchanged'])
    except Exception as error:
        result['error_type'] = type(error).__name__
        result['error'] = str(error)
    (output / 'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
