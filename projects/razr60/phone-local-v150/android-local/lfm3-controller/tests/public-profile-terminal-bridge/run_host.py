#!/usr/bin/env python3
"""Run the actual public-profile producer/consumer/controller/native terminal chain.

The controller bridge and its unchanged value-copy helpers are extracted verbatim;
the Android Activity/controller loop is not compiled. The actual full pure native
query/session/terminal, BackgroundSession and ProfileOwnedTask are compiled. All
Android, socket, model callback, installed and worker facts are explicit host IO.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
LEGACY_SHA = '0451f19a8e4b55dfc2abefc1cbe59f4cde74f5899faca1f722a79608aa5acf47'
CONTRACTS = {'legacy': (1, 28, 'ad7777f8f55f49c6fdf31b255460e7526ce4449eaec94a2378ce3e7f6ebdf864'), 'candidate': (33, 412, '5f2b560320c45a07a342a67ef1e8e703b2cf390494ca1406ebe549814322312d')}

EXTRA = ['NativeCtripFormObservation', 'ObservationCaptureEvidence', 'PromptActionDomain', 'NativeAppEvidence', 'NativeAppDomain', 'NativeAppSession',
         'NativeXiaomiSearchInputObservation', 'NativeActionSnapshotCheck', 'NativeAppObservation', 'NativeCtripFlightPage', 'NativeXiaomiProductPage',
         'NativeSearchPlanning', 'NativeSearchRole', 'NativeSearchDecision', 'NativeSearchSession', 'NativeOrderPreviewManual']


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def ref(path):
    value = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(value), 'sha256': sha(value)}


def put(path, value):
    with path.open('xb') as stream:
        stream.write(value)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory(source):
    result = {}
    for path in sorted(source.rglob('*')):
        need(not path.is_symlink(), 'source symlink refused')
        if path.is_file():
            result[str(path.relative_to(source))] = dict(ref(path), mode=path.stat().st_mode & 0o777)
    return result


def extract_bridge(source, output):
    original = source / 'src/org/trillionnium/hepta/local/LocalTaskController.java'
    raw = original.read_text()
    first = '    private static java.util.Map<String,Object> nativeProfileCleanup('
    second = '    private static java.util.Map<String,Object> completionFixed('
    end = '    private static final class ModelAnswer '
    need(raw.count(first) == raw.count(second) == raw.count(end) == 1, 'nonunique real controller bridge/copy helpers')
    a, b, c = raw.index(first), raw.index(second), raw.index(end)
    need(a < b < c, 'real bridge helper order changed')
    current, helpers = raw[a:b], raw[b:c]
    # The newly adjacent planning/model/dispatch runtime is not a cleanup-copy helper.
    # Preserve all original bridge/copy method bytes, and execute new typed paths only
    # in their separate actual Session/producer gates.
    search_start='    private static final String NATIVE_SEARCH_SYSTEM='
    need(raw.count(search_start)==1,'one complete new search runtime boundary')
    search_at=raw.index(search_start)
    need(b<search_at<c,'new search runtime is adjacent after original cleanup-copy helpers')
    search_runtime=raw[search_at:c]
    need(helpers.count(search_runtime)==1,'one exact search-only block in legacy cleanup fixture')
    helpers=helpers.replace(search_runtime,'',1)
    helper_signatures=('    private static java.util.Map<String,Object> completionFixed(',
                       '    private static java.util.Map<String,Object> completionMap(',
                       '    private static Object completionValue(')
    need(all(helpers.count(signature)==1 for signature in helper_signatures)
         and 'NativeSearch' not in helpers and 'NATIVE_SEARCH' not in helpers,
         'exact original cleanup-copy helpers without search runtime required')
    call = 'TaskCompletionGate.Check terminal=completion.terminalNativeCheck(activeNativeTask,finalFrame,terminalOwnerFrame,'
    need(raw.count(call) == raw.count('nativeProfileCleanup(backgroundCleanup)') == 1, 'actual controller native terminal bridge disconnected')
    call_start = raw.index(call)
    call_end = raw.index(');', call_start) + 2
    callsite = raw[call_start:call_end]
    need('nativeProfileCleanup(backgroundCleanup)' in callsite, 'bridge not used by actual native terminal call')
    old = source / 'tests/public-profile-terminal-bridge/legacy-r17-native-profile-cleanup.java.inc'
    legacy = old.read_bytes()
    need(sha(legacy) == LEGACY_SHA, 'exact immutable R17 bridge reproduction changed')
    text = ('package org.trillionnium.hepta.local;\nimport org.json.JSONObject;import org.json.JSONArray;\n'
            'final class ControllerProfileCleanupFixture {\n'
            ' static java.util.Map<String,Object> current(BackgroundSession.Cleanup c){return Current.nativeProfileCleanup(c);}\n'
            ' static java.util.Map<String,Object> legacy(BackgroundSession.Cleanup c){return Legacy.nativeProfileCleanup(c);}\n'
            ' private static final class Current {\n' + current + helpers + '}\n'
            ' private static final class Legacy {\n' + legacy.decode() + helpers + '}\n}\n')
    path = output / 'ControllerProfileCleanupFixture.java'
    put(path, text.encode())
    evidence = {'source': ref(original), 'actual_method_sha256': sha(current.encode()),
                'unchanged_copy_helpers_sha256': sha(helpers.encode()), 'legacy_exact_r17_method': ref(old),
                'actual_terminal_callsite': callsite, 'actual_terminal_callsite_sha256': sha(callsite.encode()),
                'generated': ref(path), 'verbatim_method_and_helpers': True,
                'full_android_controller_compiled_or_executed': False,
                'new_search_runtime_excluded_sha256': sha(search_runtime.encode()),
                'excluded_search_runtime_start': search_start, 'copy_helper_signatures': list(helper_signatures),
                'new_search_controller_execution_claimed': False}
    return path, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'java-home', 'json-jar'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source, out, jdk, jar = [path.resolve() for path in (args.source, args.output, args.java_home, args.json_jar)]
    need(source.is_dir() and not out.exists() and source not in out.parents, 'fresh output outside source required')
    need(jar.stat().st_size == 78332 and sha(jar.read_bytes()) == JSON_SHA, 'existing pinned JSON dependency changed')
    need((jdk / 'lib/ct.sym').is_file(), 'full JDK with real --release 8 APIs required')
    before = inventory(source)
    out.mkdir(parents=True, mode=0o700)
    env = dict(os.environ)
    for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH', 'PYTHONPATH'):
        env.pop(key, None)
    env.update(PATH=str(jdk / 'bin') + os.pathsep + '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    report = {'schema': 'hepta.public-profile-terminal-bridge-host.v1', 'all_pass': False,
              'strict_release8': True, 'phone_operations': 0, 'android_runtime': False, 'native_model_executed': False,
              'full_android_controller_compiled_or_executed': False, 'controller_bridge_verbatim_extraction': True,
              'actual_profile_owned_task_producer': True, 'actual_background_session_consumer': True,
              'actual_native_session_terminal': True, 'framework_model_installed_and_worker_io_synthetic': True,
              'source_before': before, 'stages': [], 'cases': {},
              'tools_before': [ref(p) for p in (jdk / 'bin/java', jdk / 'bin/javac', jdk / 'lib/modules', jar)]}

    def run(name, argv):
        started = time.monotonic()
        result = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=180)
        put(out / (name + '.stdout'), result.stdout)
        put(out / (name + '.stderr'), result.stderr)
        report['stages'].append({'name': name, 'argv': list(map(str, argv)), 'exit_code': result.returncode,
                                 'elapsed_seconds': time.monotonic() - started,
                                 'stdout': ref(out / (name + '.stdout')), 'stderr': ref(out / (name + '.stderr'))})
        if result.returncode:
            print(result.stdout.decode('utf-8', 'replace')[-4000:])
            print(result.stderr.decode('utf-8', 'replace')[-14000:])
        need(result.returncode == 0, 'actual stage failed: ' + name)

    try:
        bg = load(source / 'tests/background-session/prepare_fixture.py', 'public_profile_bridge_android_io')
        files, projection = bg.prepare(source, out / 'android-io-fixture', include_terminal=False)
        fixture = out / 'android-io-fixture'
        # Full actual new Session classes need this type, but no new dispatch is run.
        service_port=fixture/'org/trillionnium/hepta/local/HeptaAccessibilityService.java'
        calendar_closure_path=source/'tests/native-search-planning/host_closure.py'
        calendar_closure=load(calendar_closure_path,'terminal_calendar_refusing_types')
        calendar_paths,calendar_boundary=calendar_closure.calendar_legacy_closure(source,service_port)
        report['native_calendar_legacy_type_boundary']=calendar_boundary
        report['native_calendar_legacy_helper']=ref(calendar_closure_path)
        service_before=service_port.read_bytes();service_text=service_before.decode('utf-8')
        need(files.count(service_port)==1 and service_text.endswith('}')
                and 'class ActionOutcome' not in service_text and 'class NativeSearchReadRetryProof' not in service_text
                and 'class NativeSearchNoEffectReplanProof' not in service_text
                and 'class NativeSearchSamplingExhaustionProof' not in service_text
                and 'class NativeSearchFinalCensusResampleProof' not in service_text,
                'one original Service type port without new dispatch/retry types required')
        outcome_port="""    public static final class ActionOutcome {
        public final boolean accepted=false,dispatched=false,stale=true;
        public final String detail=null;
        public final org.json.JSONObject taskAuthorization=null,actionExecution=null;
        private ActionOutcome(){throw new AssertionError("native search dispatch is outside the legacy terminal fixture");}
    }"""
        retry_port="""    public static final class NativeSearchReadRetryProof {
        private NativeSearchReadRetryProof(){throw new AssertionError("native search retry proof is outside the legacy terminal fixture");}
    }
    public static final class NativeSearchSamplingExhaustionProof {
        private NativeSearchSamplingExhaustionProof(){throw new AssertionError("native sampling successor proof is outside the legacy terminal fixture");}
        public void close(){throw new AssertionError("No sampling successor authority in legacy terminal fixture");}
    }"""
        no_effect_port="""    public static final class NativeSearchNoEffectReplanProof {
        private NativeSearchNoEffectReplanProof(){throw new AssertionError("native search successor proof is outside the legacy terminal fixture");}
        void requireOriginal(NativeSearchSession session,NativeSearchSession.Attempt attempt,long now,boolean closed){throw new AssertionError("No successor authority in legacy terminal fixture");}
        void requireOutcome(ActionOutcome outcome){throw new AssertionError("No successor outcome in legacy terminal fixture");}
        void requirePublishedPlanning(NativeSearchSession session,NativeSearchPlanning planning){throw new AssertionError("No successor publication in legacy terminal fixture");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("No successor evidence in legacy terminal fixture");}
    }"""
        final_census_port="""    static final class NativeSearchFinalCensusResampleProof {
        private NativeSearchFinalCensusResampleProof(){throw new AssertionError("actual final-census producer unavailable in this pure gate");}
        void consume(NativeSearchSession.Attempt attempt,NativeSearchRole role,long now){throw new AssertionError("no final-census replacement authority");}
    }
"""
        type_ports=outcome_port+chr(10)+retry_port+chr(10)+no_effect_port+chr(10)+final_census_port
        service_after=(service_text[:-1]+chr(10)+type_ports+chr(10)+'}').encode('utf-8')
        need(service_after.decode('utf-8').replace(chr(10)+type_ports+chr(10),'',1)==service_text,
                'original Service port changed outside the refusing type boundary')
        service_port.write_bytes(service_after)
        report['native_search_type_boundary']={'original_service_sha256':sha(service_before),
                'compiled_service_sha256':sha(service_after),'type_block_sha256':sha(outcome_port.encode()),
                'original_service_bytes_reversible':True,'constructor_always_throws':True,
                'accepted_and_dispatched_always_false':True,'authority_and_execution_always_null':True,
                'new_search_path_executed':False,'retry_proof_type_block_sha256':sha(retry_port.encode()),
                'retry_proof_constructor_always_throws':True,'retry_authority_executed':False,
                'no_effect_proof_type_block_sha256':sha(no_effect_port.encode()),
                'no_effect_proof_constructor_and_authority_always_throw':True,'no_effect_successor_executed':False,
                'final_census_proof_type_block_sha256':sha(final_census_port.encode()),
                'final_census_proof_private_constructor_and_consume_always_throw':True,
                'final_census_resampling_executed':False}
        (fixture / 'android/os/Process.java').write_text('package android.os;public final class Process {public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n')
        io = fixture / 'android/system/Os.java'
        body, seam = io.read_text(), 'r.st_uid=((Number)a.get("uid")).intValue();'
        need(body.count(seam) == 1, 'original Android UID fixture seam changed')
        io.write_text(body.replace(seam, seam + 'if(r.st_uid==' + str(os.getuid()) + ')r.st_uid=10481;'))
        files = [path for path in files if not (fixture / 'org/json') in path.parents]
        query = load(source / 'tests/web-flight/run_query_host_tests.py', 'public_profile_bridge_native_closure')
        files += [source / path for path in query.PURE_PATHS if path not in
                  ('tests/web-flight/WebFlightQueryHostTest.java', 'tests/native-app/legacy-boundary/NativeAppSession.java')]
        files += [source / ('src/org/trillionnium/hepta/local/' + name + '.java') for name in EXTRA]
        files += [source / 'src/org/trillionnium/hepta/background/PublicPersonalNotesCustody.java']
        files += [source / path for path in (
            'tests/profile-broker/ProfileBrokerHostTest.java',
            'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java',
            'tests/public-own-group-policy/PersonalNotesCustodyHostTest.java',
            'tests/public-profile-history/ForegroundConcurrencyHostTest.java',
            'tests/public-profile-cleanup/PublicProfileCleanupHostTest.java',
            'tests/native-app-fixtures/NativeXmlFixture.java',
            'tests/native-app-provider/NativeAppProviderHostTest.java',
            'tests/public-profile-terminal-bridge/PublicProfileBridgeProducer.java',
            'tests/public-profile-terminal-bridge/PublicProfileTerminalBridgeHostTest.java')]
        bridge, extraction = extract_bridge(source, out)
        files.append(bridge)
        actual_calendar_names={p.name for p in calendar_paths if source in p.parents}
        files=[p for p in files if not (p.parent==service_port.parent
               and (p.name in actual_calendar_names or p.name=='NativeAppSession.java'))]
        files += calendar_paths
        files = list(dict.fromkeys(path.resolve() for path in files))
        need(all(path.is_file() for path in files), 'complete actual compile closure required')
        report.update(android_io_projection=projection, controller_bridge=extraction, compile_inputs=[ref(path) for path in files])
        put(out / 'BOUNDARIES.json', json_bytes({'android_io': projection, 'controller_bridge': extraction,
              'producer': 'Full ProfileOwnedTask.cleanupEvidence with full PublicProfileRecentHistory; no constructed replacement cleanup algorithm',
              'native_terminal': 'Full NativeAppSession and TaskCompletionGate with original saved XML and explicit host model/worker callbacks',
              'phone_operations': 0}))
        classes = out / 'classes'
        classes.mkdir()
        run('compile', [jdk / 'bin/javac', '--release', '8', '-encoding', 'UTF-8', '-proc:none', '-Xlint:all,-options', '-Werror',
                        '-classpath', jar, '-d', classes, *files])
        for mode in ('legacy', 'candidate'):
            cases = out / (mode + '-CASES.json')
            run(mode, [jdk / 'bin/java', '-cp', str(classes) + os.pathsep + str(jar),
                       'org.trillionnium.hepta.local.PublicProfileTerminalBridgeHostTest',
                       source / 'tests/native-app-provider/fixtures', cases, mode])
            value = json.loads(cases.read_bytes())
            report['cases'][mode] = value
        for mode, (count, assertions, names_sha) in CONTRACTS.items():
            value = report['cases'][mode]
            names = value.get('case_names')
            actual_sha = sha(json.dumps(names, ensure_ascii=False, separators=(',', ':')).encode())
            emitted=(out/(mode+'.stdout')).read_text().splitlines()
            summaries=[line for line in emitted if line.startswith('{')]
            need(len(summaries)==1 and json.loads(summaries[0])==value
                 and [line[5:] for line in emitted if line.startswith('PASS ')]==names,
                 'actual Java stdout and case file differ: '+mode)
            value['case_names_sha256'] = actual_sha
            need(value.get('schema') == 'hepta.public-profile-terminal-bridge-cases.v1' and value.get('all_pass') is True
                 and type(value.get('cases')) is int and value['cases'] == count
                 and type(value.get('assertions')) is int and value['assertions'] == assertions
                 and type(names) is list and len(names) == len(set(names)) == count and actual_sha == names_sha,
                 'exact new integration case contract differs: ' + mode)
            need(value.get('phone_operations') == 0 and value.get('android_runtime') is False
                 and value.get('native_model_executed') is False, 'host boundary changed')
        need(report['cases']['legacy'].get('old_bridge_full_terminal_reproduced') is True
             and report['cases']['legacy'].get('full_native_terminal_calls') == 1, 'legacy counterexample did not reach full terminal')
        need(report['cases']['candidate'].get('real_nested_consumer_refusals') == 11
             and report['cases']['candidate'].get('full_native_terminal_calls') == 17, 'real consumer/full-terminal coverage missing')
        report['source_inputs_unchanged'] = inventory(source) == before
        report['tools_after'] = [ref(Path(row['path'])) for row in report['tools_before']]
        report['tools_unchanged'] = report['tools_after'] == report['tools_before']
        need(report['source_inputs_unchanged'] and report['tools_unchanged'], 'source or pinned tool inputs changed')
        report['all_pass'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        put(out / 'RESULT.json', json_bytes(report))
    print(json.dumps({'all_pass': report['all_pass'], 'result': ref(out / 'RESULT.json'),
                      'cases': {name: {k: value.get(k) for k in ('cases', 'assertions', 'case_names_sha256', 'real_nested_consumer_refusals', 'full_native_terminal_calls')}
                                for name, value in report['cases'].items()}, 'error': report.get('error')}, ensure_ascii=False))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
