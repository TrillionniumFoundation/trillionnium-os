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



def pair_probe(background, output):
    """Compile the actual bracket method with explicit synthetic organizer/clock surfaces."""
    platform = background / 'ProfileTaskPlatform.java'
    text = platform.read_text()
    start = '    private void requireSamePermissionPair('
    end = '    @Override public void createRoot('
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError('Permission pair method extraction is ambiguous')
    if (text.count('requireSamePermissionPair(root,leaf,before,started);') != 1
            or text.count('requireSamePermissionPair(root,leaf,after,started);recheck(false);') != 1):
        raise RuntimeError('Both actual permission proof brackets must use the classifier')
    method = text[text.index(start):text.index(end)]
    prefix = """package org.trillionnium.hepta.background;
import java.util.List;
/** Synthetic organizer and monotonic clock; actual production bracket method below. */
final class PermissionPairProbe {
    final ProfileTarget expected;
    final Organizer organizer;
    static final class SystemClock {
        static long time;
        static long elapsedRealtime(){return time;}
    }
    static final class Organizer {
        final List<BackgroundOwnedSingleTask.Task> rootRows,leafRows;
        final Object rootToken;
        int rootReads,childReads;
        long afterChildClock=-1;
        Organizer(List<BackgroundOwnedSingleTask.Task> rootRows,List<BackgroundOwnedSingleTask.Task> leafRows,Object rootToken){
            this.rootRows=rootRows;this.leafRows=leafRows;this.rootToken=rootToken;
        }
        List<BackgroundOwnedSingleTask.Task> roots(){rootReads++;return rootRows;}
        List<BackgroundOwnedSingleTask.Task> children(Object token){
            if(!rootToken.equals(token))throw new AssertionError("unowned child query");
            childReads++;if(afterChildClock>=0)SystemClock.time=afterChildClock;return leafRows;
        }
    }
    PermissionPairProbe(ProfileTarget expected,List<BackgroundOwnedSingleTask.Task> roots,
            List<BackgroundOwnedSingleTask.Task> leaves,Object token){
        this.expected=expected;organizer=new Organizer(roots,leaves,token);SystemClock.time=1100;
    }
    void check(BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,
            ProfilePermissionTransient.Authority authority,long started)throws Exception{
        requireSamePermissionPair(root,leaf,authority,started);
    }
"""
    raw = (prefix + method + '}\n').encode()
    path = output / 'PermissionPairProbe.java'
    with path.open('xb') as stream:
        stream.write(raw)
    return path, {'source_sha256': sha(platform),
                  'method_sha256': hashlib.sha256(method.encode()).hexdigest(),
                  'generated_probe_sha256': hashlib.sha256(raw).hexdigest(),
                  'framework_surface_synthetic': True}

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
    names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol', 'FixedIntentTools',
             'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask', 'ProfileTaskPolicy',
             'ProfileOwnedTask', 'ProfilePermissionTransient', 'ProfileDisplayCustody']
    files = [background / (name + '.java') for name in names]
    files += [source / 'tests/profile-broker/ProfileBrokerHostTest.java',
              here / 'ProfilePermissionTransientHostTest.java',
              here / 'ProfilePermissionReadRetryHostTest.java']
    tracked = files + [Path(__file__).resolve(), fixture, here / 'README.md',
                       background / 'ProfileTaskPlatform.java']
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
        probe, result['pair_bracket_extraction'] = pair_probe(background, output)
        classes = output / 'classes'
        run('compile', [str(args.java_home / 'bin/javac'), '--release', '8', '-encoding', 'UTF-8',
                        '-Xlint:all,-options', '-Werror', '-proc:none', '-d', str(classes)]
            + [str(path) for path in files] + [str(probe)])
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
            if not (summary.get('passed') is True and summary.get('cases') == 12
                    and summary.get('fixture_kind') == kind
                    and summary.get('fixture_sha256') == expected_sha
                    and summary.get('taskinfo_fixtures_synthetic') is True
                    and summary.get('phone_contacted') is False
                    and summary.get('android_build') is False):
                raise RuntimeError(kind + ' result contract differs')
            result[kind + '_summary'] = summary
        retry_stdout = run('read-retry', [str(args.java_home / 'bin/java'), '-cp', str(classes),
                           'org.trillionnium.hepta.background.ProfilePermissionReadRetryHostTest',
                           str(fixture)])
        retry_summaries = [json.loads(line) for line in retry_stdout.decode('utf-8').splitlines()
                           if line.startswith('{')]
        if len(retry_summaries) != 1:
            raise RuntimeError('Read-retry summary missing or duplicated')
        retry_summary = retry_summaries[0]
        if not (retry_summary.get('passed') is True and retry_summary.get('cases') == 21
                and retry_summary.get('fixture_sha256') == SYNTHETIC_SHA
                and retry_summary.get('taskinfo_and_framework_fixtures_synthetic') is True
                and retry_summary.get('real_pair_bracket_method_extracted') is True
                and retry_summary.get('phone_contacted') is False
                and retry_summary.get('android_build') is False):
            raise RuntimeError('Read-retry result contract differs')
        result['read_retry_summary'] = retry_summary
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
