#!/usr/bin/env python3
"""Execute the actual bounded failed-read issuer against explicit host Android IO.

Observer, gates and lifecycle execute verbatim on a real serial executor.
Synthetic graph values, screenshot IO and clock are host endpoints; this does
not qualify a phone, pixels, business completion or Session action authority.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
PKG = Path('src/org/trillionnium/hepta/local')
TEST = Path('tests/native-observation-retry')
OWN = ['run_host.py', 'ReadRetryPipelineCases.fragment', 'README.md']

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def generate(source, output, h, events):
    extracted = events.generate(source, output, h)
    path = output/'ObserverPipelineHost.java'
    text = path.read_text()
    original_main = h.body(text, '    public static void main(String[] args)throws Exception{')
    text = events.replace(text, original_main, (source/TEST/'ReadRetryPipelineCases.fragment').read_text())
    # Instrument only the fake Android Handler, outside every extracted body.
    # The callback can run before the real read Runnable returns from post().
    text = events.replace(text,
        '        synchronized boolean post(Runnable runnable){return postDelayed(runnable,0);}',
        '        volatile Runnable afterWorkerPost;\n'
        '        boolean post(Runnable runnable){boolean posted=postDelayed(runnable,0);\n'
        '            Runnable hook=afterWorkerPost;if(!isMain()&&hook!=null)hook.run();return posted;}')
    path.write_text(text)
    extracted['schema'] = 'hepta.native-observation-retry-extraction.v1'
    extracted['worker_return_race_instrumentation'] = 'synthetic Handler.post only; callback queued before read Runnable returns'
    extracted['all_extracted_production_bodies_unchanged'] = True
    return extracted

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--java-home', type=Path, required=True)
    ap.add_argument('--json-jar', type=Path, required=True)
    a = ap.parse_args()
    source = a.source.resolve(); output = a.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    h = module(source/'tests/observation-diagnostics/run_host.py', 'read_retry_host_helpers')
    events = module(source/'tests/native-observation-events/run_host.py', 'read_retry_native_event_helpers')
    jdk = a.java_home.resolve(); java = jdk/'bin/java'; javac = jdk/'bin/javac'; jar = a.json_jar.resolve()
    tools = [java, javac, jdk/'lib/modules', jdk/'lib/ct.sym', jar]
    if not all(p.is_file() for p in tools):
        raise RuntimeError('complete strict JDK17 and JSON closure required')
    if jar.stat().st_size != 78332 or h.sha(jar.read_bytes()) != '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':
        raise RuntimeError('pinned JSON jar required')
    sources = [source/PKG/n for n in events.JAVA]
    inputs = sources + [source/PKG/'LocalTaskController.java', source/PKG/'NativeAppSession.java']
    inputs += [source/'tests/native-observation-events'/n for n in events.OWN]
    inputs += [source/'tests/observation-pipeline/ObserverPipelineHost.template', source/'tests/observation-diagnostics/run_host.py']
    inputs += [source/TEST/name for name in OWN] + tools
    before = [h.meta(p) for p in inputs]; tool_before = [h.meta(p) for p in tools]
    result = {'schema':'hepta.native-observation-retry-host-gate.v1', 'all_pass':False, 'steps':[],
        'input_before':before, 'tools_before':tool_before, 'android_execution':False, 'phone_execution':False,
        'phone_operations':0, 'sdk_loaded':False, 'model_executed':False, 'business_completion_verified':False,
        'compiler_contract':'JDK17 --release 8 -encoding UTF-8 -Xlint:all -Werror',
        'boundary':'Actual observer and serial read executor; Android collected values, screenshot and clock are host IO. Session authority is qualified by its separate actual-production gate.'}
    try:
        generated = output/'generated'; generated.mkdir()
        h.save(output/'EXTRACTION.json', generate(source, generated, h, events))
        classes = output/'classes'; classes.mkdir()
        compiled = [p for p in sources if p.name not in ('HeptaAccessibilityService.java', 'PhoneObservation.java')]
        compiled += [source/'tests/native-observation-events/EventChecks.java', generated/'ObserverPipelineHost.java']
        argv = [str(javac), '--release', '8', '-encoding', 'UTF-8', '-Xlint:all', '-Werror', '-cp', str(jar), '-d', str(classes)] + list(map(str, compiled))
        step = h.stage('compile', argv, output); result['steps'].append(step)
        if step['exit_code'] != 0:
            raise RuntimeError('actual read retry compilation failed')
        step = h.stage('service-cases', [str(java), '-cp', str(classes)+os.pathsep+str(jar),
            'org.trillionnium.hepta.local.ObserverPipelineHost', str(output/'SERVICE-CASES.json')], output)
        result['steps'].append(step)
        if step['exit_code'] != 0:
            raise RuntimeError('actual read retry lifecycle cases failed')
        cases = json.loads((output/'SERVICE-CASES.json').read_text())
        if cases['all_pass'] is not True or cases['cases'] != len(cases['case_names']) or len(set(cases['case_names'])) != cases['cases']:
            raise RuntimeError('complete unique service case identities required')
        result.update(cases=cases, case_records={'SERVICE-CASES.json':h.meta(output/'SERVICE-CASES.json')},
            extraction_file=h.meta(output/'EXTRACTION.json'), generated_files={p.name:h.meta(p) for p in sorted(generated.glob('*.java'))}, all_pass=True)
    except Exception as error:
        result['error'] = {'type':type(error).__name__, 'message':str(error)}
    finally:
        result['input_after'] = [h.meta(p) for p in inputs]; result['tools_after'] = [h.meta(p) for p in tools]
        result['inputs_unchanged'] = result['input_after'] == before
        result['tools_unchanged'] = result['tools_after'] == tool_before
        result['all_pass'] = result['all_pass'] and result['inputs_unchanged'] and result['tools_unchanged']
        h.save(output/'RESULT.json', result)
    print(json.dumps({'all_pass':result['all_pass'], 'result':h.meta(output/'RESULT.json')}))
    return 0 if result['all_pass'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
