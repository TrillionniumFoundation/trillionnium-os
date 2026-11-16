#!/usr/bin/env python3
"""Narrow ProfileTarget producer / full native terminal regression; host only.

The optional actual collection is read in place, never copied into the source.
It supplies historical frame/outcome/worker/cleanup facts, not fresh Android
authority. All production classes except the one candidate are baseline bytes.
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
TARGET = 'src/org/trillionnium/hepta/background/ProfileTarget.java'
EXTRA = ['PromptActionDomain','NativeAppEvidence','NativeAppDomain','NativeAppSession',
         'NativeActionSnapshotCheck','NativeAppObservation','NativeCtripFlightPage','NativeXiaomiProductPage']

def require(ok, message):
    if not ok:
        raise AssertionError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def record(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}

def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def actual_inputs(root):
    if root is None:
        return []
    rels = ['task/owner.json','task/native-app-binding.json','task/background-binding.json',
            'task/native-app-outcome-01.json','task/step-01-before.json','task/step-01-after.json',
            'task/background-cleanup.json']
    attempt = json.loads((root / rels[3]).read_text())['attempt']
    run = attempt['model_run_id']
    require(len(run) == 32 and all(c in '0123456789abcdef' for c in run), 'invalid original model run')
    rels += [f'runs/{run}/raw-text.txt', f'runs/{run}/app-receipt.json']
    worker = json.loads((root / rels[-1]).read_text())['worker_generation']
    require(len(worker) == 32 and all(c in '0123456789abcdef' for c in worker), 'invalid original worker generation')
    rels.append(f'runs/{worker}/app-session-receipt.json')
    return [record(root / rel) for rel in rels]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=Path, help='Complete joint candidate source; no baseline replay or class substitution')
    ap.add_argument('--baseline-source', type=Path)
    ap.add_argument('--candidate-source', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--java-home', type=Path, required=True)
    ap.add_argument('--json-jar', type=Path, required=True)
    ap.add_argument('--actual-collection', type=Path)
    args = ap.parse_args()
    candidate_only = args.source is not None
    if candidate_only:
        require(args.baseline_source is None and args.candidate_source is None, 'choose --source or the baseline/candidate pair')
        baseline = candidate = args.source.resolve()
    else:
        require(args.baseline_source is not None and args.candidate_source is not None, 'baseline and candidate sources required')
        baseline, candidate = args.baseline_source.resolve(), args.candidate_source.resolve()
    out, jdk, jar = [p.resolve() for p in (args.output, args.java_home, args.json_jar)]
    original = args.actual_collection.resolve() if args.actual_collection else None
    own = Path(__file__).resolve().parent
    require(not out.exists() and baseline not in out.parents and candidate not in out.parents,
            'fresh output outside source required')
    require(jar.stat().st_size == 78332 and sha(jar.read_bytes()) == JSON_SHA, 'JSON dependency differs')
    original_before = actual_inputs(original)
    source_before = {str(p): record(p) for p in (baseline/TARGET, candidate/TARGET, own/'ProfileTerminalEvidenceHostTest.java', Path(__file__).resolve())}
    before_bytes = (baseline/TARGET).read_bytes()
    changed_bytes = (candidate/TARGET).read_bytes()
    old = b'v.put("signer_sha256",signerSha256);'
    new = b'v.put("signer_sha256",Collections.unmodifiableList(new java.util.ArrayList<String>(signerSha256)));'
    if not candidate_only:
        require(before_bytes.count(old) == 1 and changed_bytes.count(new) == 1,
                'single approved producer expression required')
        require(changed_bytes.replace(new, old) == before_bytes, 'candidate has another production change')
    joint_inputs = []
    if candidate_only:
        joint_paths = [baseline/TARGET] + [baseline/('src/org/trillionnium/hepta/local/'+name+'.java')
            for name in ('NativeCtripFlightPage','NativeAppSession','LocalTaskController')]
        joint_inputs = [record(p) for p in joint_paths]
        source_before.update({str(p):record(p) for p in joint_paths})
    out.mkdir(parents=True, mode=0o700)
    report = {'schema': 'hepta.profile-terminal-evidence-host.v1', 'all_pass': False,
              'baseline_source': str(baseline), 'candidate_overlay_source': str(candidate),
              'source_before': source_before, 'original_inputs_before': original_before,
              'source_mode': 'joint_candidate_only' if candidate_only else 'baseline_and_single_producer_overlay',
              'baseline_red_repeated': not candidate_only, 'joint_production_inputs': joint_inputs,
              'full_android_controller_compiled_or_executed': False,
              'phone_operations': 0, 'model_executed': False, 'android_runtime': False,
              'business_verified': False, 'stages': [], 'variants': {},
              'boundary': 'Complete production TaskCompletionGate/NativeAppSession/ProfileTarget. Android IO uses existing explicit host fixture. Optional original saved JSON is immutable historical input, not current authority.'}
    env = dict(os.environ)
    env['PATH'] = str(jdk/'bin') + os.pathsep + env.get('PATH','')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):
        env.pop(key, None)
    report['tools_before'] = [record(p) for p in (jdk/'bin/java', jdk/'bin/javac', jdk/'lib/modules', jar)]

    def run(name, argv, expected):
        start = time.monotonic()
        result = subprocess.run(list(map(str,argv)), cwd=out, env=env, capture_output=True, timeout=120)
        for suffix, data in (('stdout', result.stdout), ('stderr', result.stderr)):
            (out/(name+'.'+suffix)).write_bytes(data)
        report['stages'].append({'name':name, 'argv':list(map(str,argv)), 'exit_code':result.returncode,
                                 'expected_exit_code':expected, 'seconds':time.monotonic()-start,
                                 'stdout_sha256':sha(result.stdout),'stderr_sha256':sha(result.stderr)})
        require(result.returncode == expected, 'actual stage failed: '+name)

    try:
        query = load(baseline/'tests/web-flight/run_query_host_tests.py', 'profile_terminal_query_closure')
        bg = load(baseline/'tests/background-session/prepare_fixture.py', 'profile_terminal_background_fixture')
        bgfiles, bgrecord = bg.prepare(baseline, out/'platform-fixture')
        bgfiles = [p for p in bgfiles if not (p.parent.name == 'json' and p.parent.parent.name == 'org') and 'terminal' not in p.parts]
        paths = [baseline/p for p in query.PURE_PATHS if p not in
                 ('tests/web-flight/WebFlightQueryHostTest.java', 'tests/native-app/legacy-boundary/NativeAppSession.java')] + bgfiles
        paths += [baseline/('src/org/trillionnium/hepta/local/'+name+'.java') for name in EXTRA]
        paths += [own/'ProfileTerminalEvidenceHostTest.java']
        paths = list(dict.fromkeys(p.resolve() for p in paths))
        matches = [p for p in paths if p.name == 'ProfileTarget.java']
        require(matches == [baseline/TARGET], 'actual unique baseline ProfileTarget required')
        report['background_fixture'] = bgrecord
        report['shared_compile_inputs'] = [record(p) for p in paths if p != baseline/TARGET]
        for mode in (('candidate',) if candidate_only else ('baseline','candidate')):
            variant = out/mode
            variant.mkdir()
            classes = variant/'classes'
            classes.mkdir()
            actual_paths = [candidate/TARGET if mode == 'candidate' and p == baseline/TARGET else p for p in paths]
            report['variants'][mode] = {'compile_inputs':[record(p) for p in actual_paths]}
            run(mode+'-compile', [jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none',
                 '-Xlint:all,-options','-Werror','-classpath',jar,'-d',classes,*actual_paths],0)
            cases = variant/'CASES.json'
            run(mode+'-cases', [jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),
                 'org.trillionnium.hepta.local.ProfileTerminalEvidenceHostTest',mode,cases,original or '-'],3 if mode == 'baseline' else 0)
            value = json.loads(cases.read_text())
            if mode == 'baseline':
                require(value.get('expected_baseline_red') is True and value.get('full_terminal_called') is (original is not None),
                        'baseline must hit exact semantic failure, not compilation or setup failure')
            else:
                require(value.get('all_pass') is True and value.get('actual_saved_shape_replayed') is (original is not None),
                        'candidate cases not complete')
            report['variants'][mode]['result'] = value
            report['variants'][mode]['result_file'] = record(cases)
        report['all_pass'] = True
    except Exception as error:
        report['error'] = type(error).__name__+': '+str(error)
        raise
    finally:
        report['original_inputs_after'] = actual_inputs(original)
        report['source_after'] = {p:record(Path(p)) for p in source_before}
        report['shared_compile_inputs_after'] = [record(Path(row['path'])) for row in report.get('shared_compile_inputs',[])]
        report['tools_after'] = [record(Path(row['path'])) for row in report['tools_before']]
        report['original_inputs_unchanged'] = report['original_inputs_before'] == report['original_inputs_after']
        report['source_unchanged'] = report['source_before'] == report['source_after']
        report['shared_compile_inputs_unchanged'] = report.get('shared_compile_inputs',[]) == report['shared_compile_inputs_after']
        report['tools_unchanged'] = report['tools_before'] == report['tools_after']
        report['all_pass'] = report['all_pass'] and all(report[k] for k in
            ('original_inputs_unchanged','source_unchanged','shared_compile_inputs_unchanged','tools_unchanged'))
        write_json(out/'RESULT.json',report)
        print(json.dumps({'all_pass':report['all_pass'],'result':str(out/'RESULT.json'),'sha256':sha((out/'RESULT.json').read_bytes())}))

if __name__ == '__main__':
    main()
