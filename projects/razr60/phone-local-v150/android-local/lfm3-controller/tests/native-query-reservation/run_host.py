#!/usr/bin/env python3
"""Real Session/lifetime regression. No phone, network, SDK or model operations."""
import argparse, hashlib, importlib.util, json, os, subprocess, sys, time
from pathlib import Path
PKG = Path('src/org/trillionnium/hepta/local')
TEST = Path('tests/native-query-reservation')
JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
OLD_SESSION_SHA = '2f9dae5d39804f725aabc2df666f288f53760f120c3853db1a259fa11b1c9815'
OLD_COMPARATOR_SHA = '4d5366a8fe0b603405ade16b2592c21d1fcb6d972d0e8c8105788cdf26cf72ce'
OLD_PROJECTION_SOURCE_SHA = '2ed95fc33228322199058e4a24133cb69b161ccd281ae5c383dd34d72e31bb59'
def sha(raw): return hashlib.sha256(raw).hexdigest()
def need(value, reason):
    if not value: raise RuntimeError(reason)
def meta(path):
    path = Path(path).absolute(); raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw), mode=path.stat().st_mode & 0o777)
def source_files(source):
    rows = []
    for path in sorted(source.rglob('*')):
        need(not path.is_symlink(), 'no source symlinks')
        if path.is_file() and '__pycache__' not in path.parts: rows.append(path)
    return rows
def write(path, text):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream: stream.write(text.encode() if isinstance(text, str) else text)
def save(path, value): write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
def stage(name, argv, out, env):
    started = time.monotonic_ns()
    with (out/(name+'.stdout')).open('xb') as stdout, (out/(name+'.stderr')).open('xb') as stderr:
        run = subprocess.run(list(map(str, argv)), cwd=out, env=env, stdout=stdout, stderr=stderr, timeout=150, check=False)
    return dict(name=name, argv=list(map(str, argv)), exit_code=run.returncode, elapsed_ns=time.monotonic_ns()-started,
                stdout=meta(out/(name+'.stdout')), stderr=meta(out/(name+'.stderr')))
def main():
    parser = argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'): parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--previous-source', type=Path)
    parser.add_argument('--previous-projection-source', type=Path)
    args = parser.parse_args(); source=args.source.resolve(); out=args.output.absolute(); jdk=args.java_home.resolve(); jar=args.json_jar.resolve()
    need(source.is_dir() and not out.exists() and source not in out.parents, 'fresh output outside source')
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    need(all(p.is_file() for p in tools), 'full JDK17 and JSON dependency')
    need(jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA, 'pinned JSON jar')
    inputs=source_files(source)+tools
    old=args.previous_source.resolve() if args.previous_source else None
    if old:
        need(sha((old/PKG/'NativeAppSession.java').read_bytes())==OLD_SESSION_SHA, 'exact R13 old Session')
        need(sha((old/PKG/'NativeActionSnapshotCheck.java').read_bytes())==OLD_COMPARATOR_SHA, 'exact R13 old comparator')
        inputs+=source_files(old)
    old_projection=args.previous_projection_source.resolve()/PKG/'LocalTaskController.java' if args.previous_projection_source else None
    if old_projection:
        need(sha(old_projection.read_bytes())==OLD_PROJECTION_SOURCE_SHA, 'exact original Controller projection source')
        inputs.append(old_projection)
    before=[meta(p) for p in inputs]; out.mkdir(parents=True,mode=0o700); sys.dont_write_bytecode=True
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'): env.pop(key,None)
    report=dict(schema='hepta.native-query-reservation-host-gate.v1',all_pass=False,input_before=before,steps=[],
                phone_operations=0,android_execution=False,model_executed=False,business_completion_verified=False,platform_dispatch_executed=False)
    try:
        integration=module(source/'tests/native-action-integration/run_host.py','query_reservation_existing_closure')
        extractor=module(source/'tests/observation-diagnostics/run_host.py','query_reservation_body_extractor')
        generated=out/'generated';generated.mkdir();integration.generate(source,generated)
        controller=(source/PKG/'LocalTaskController.java').read_text()
        projection=extractor.body(controller,'    private static java.util.Map<String,Object> nativeQueryExecution(JSONObject raw)throws Exception{')
        call_start=controller.index('                if(activeNativeTask!=null)activeNativeTask.modelActionOutcome(')
        call=controller[call_start:controller.index(';',call_start)+1]
        need(call.count('nativeQueryExecution(outcome.actionExecution)')==1, 'actual Controller forwards only same service outcome')
        bridge='package org.trillionnium.hepta.local;\nimport org.json.JSONObject;\nfinal class NativeQueryControllerBridge {\n'+projection+'\nstatic java.util.Map<String,Object> project(JSONObject value)throws Exception{return nativeQueryExecution(value);}\n}\n'
        write(generated/'NativeQueryControllerBridge.java',bridge)
        paths,bg=integration.sources(source,out);paths.append(source/TEST/'NativeQueryReservationHostTest.java')
        paths=list(dict.fromkeys(p.resolve() for p in paths))
        extraction=dict(schema='hepta.native-query-reservation-extraction.v1',bodies_verbatim=True,
                        controller_source=meta(source/PKG/'LocalTaskController.java'),projection_bytes=len(projection.encode()),projection_sha256=sha(projection.encode()),
                        actual_controller_call=call,actual_controller_call_sha256=sha(call.encode()),background_fixture=bg,
                        boundary='Actual production Session/action-state machine plus verbatim Controller scalar projection; original provider/year XML. Models, journal and Android endpoints remain explicit host fixtures.')
        save(out/'EXTRACTION.json',extraction);report['compile_inputs']=[meta(p) for p in paths]
        classes=out/'classes';classes.mkdir();cp=str(classes)+os.pathsep+str(jar)
        flags=['--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar]
        commands=[('compile',[jdk/'bin/javac',*flags,'-d',classes,*paths]),
                  ('reservation-cases',[jdk/'bin/java','-cp',cp,'org.trillionnium.hepta.local.NativeQueryReservationHostTest',source,out/'CASES.json'])]
        for name,argv in commands:
            result=stage(name,argv,out,env);report['steps'].append(result);need(result['exit_code']==0,'actual stage failed: '+name)
        cases=json.loads((out/'CASES.json').read_text())
        need(cases['all_pass'] and cases['cases']==len(cases['case_names'])==len(set(cases['case_names'])) and cases['assertions']>0,'complete unique actual cases')
        if old:
            previous=out/'previous-classes';previous.mkdir()
            old_paths=[old/p.relative_to(source) if p.is_relative_to(source/PKG) else p for p in paths]
            report['previous_compile_inputs']=[meta(p) for p in old_paths];report['previous_steps']=[]
            result=stage('previous-compile',[jdk/'bin/javac',*flags,'-d',previous,*old_paths],out,env)
            report['previous_steps'].append(result);need(result['exit_code']==0,'previous actual production compilation')
            old_cp=str(previous)+os.pathsep+str(jar)
            previous_tests=[
                ('previous-reservation','NativeQueryReservationHostTest','pre-effect stale query reservation must be released'),
                ('previous-carousel','NativeCarouselCurrentnessHostTest','change outside proved disjoint branch')]
            for name,main_name,needle in previous_tests:
                result=stage(name,[jdk/'bin/java','-cp',old_cp,'org.trillionnium.hepta.local.'+main_name,source,out/(name+'-CASES.json'),'legacy'],out,env)
                report['previous_steps'].append(result)
                need(result['exit_code']==1 and needle in (out/(name+'.stderr')).read_text(), 'exact original failure must reproduce: '+name)
            report['previous_failures_reproduced']=True
        if old_projection:
            previous=out/'previous-projection-classes';previous.mkdir()
            old_method=extractor.body(old_projection.read_text(),'    private static java.util.Map<String,Object> nativeQueryExecution(JSONObject raw)throws Exception{')
            old_bridge=out/'previous-projection-generated/NativeQueryControllerBridge.java'
            write(old_bridge,'package org.trillionnium.hepta.local;\nimport org.json.JSONObject;\nfinal class NativeQueryControllerBridge {\n'+old_method+'\nstatic java.util.Map<String,Object> project(JSONObject value)throws Exception{return nativeQueryExecution(value);}\n}\n')
            previous_paths=[old_bridge if p==generated/'NativeQueryControllerBridge.java' else p for p in paths]
            need(sum(p==old_bridge for p in previous_paths)==1,'replace precisely the actual Controller bridge')
            report['previous_projection']=dict(source=meta(old_projection),method_sha256=sha(old_method.encode()),generated_file=meta(old_bridge),
                compile_inputs=[meta(p) for p in previous_paths],steps=[])
            result=stage('previous-projection-compile',[jdk/'bin/javac',*flags,'-d',previous,*previous_paths],out,env)
            report['previous_projection']['steps'].append(result);need(result['exit_code']==0,'old projection with current production compiles')
            result=stage('previous-projection-cases',[jdk/'bin/java','-cp',str(previous)+os.pathsep+str(jar),
                'org.trillionnium.hepta.local.NativeQueryReservationHostTest',source,out/'previous-projection-CASES.json','previous-projection'],out,env)
            report['previous_projection']['steps'].append(result)
            need(result['exit_code']==1 and 'present non-object native guard must reject complete projection' in (out/'previous-projection-cases.stderr').read_text(),
                'original Controller must actually fail the non-object guard regression')
            report['previous_projection']['failure_reproduced']=True
        report.update(cases=cases,cases_file=meta(out/'CASES.json'),case_records={'CASES.json':meta(out/'CASES.json')},
                      extraction_file=meta(out/'EXTRACTION.json'),generated_files={str(p.relative_to(generated)):meta(p) for p in sorted(generated.rglob('*.java'))},all_pass=True)
    except Exception as error: report['error']=dict(type=type(error).__name__,message=str(error))
    finally:
        report['input_after']=[meta(p) for p in inputs];report['inputs_unchanged']=report['input_after']==before
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'];save(out/'RESULT.json',report)
    print(json.dumps(dict(all_pass=report['all_pass'],result=meta(out/'RESULT.json'),error=report.get('error'))))
    return 0 if report['all_pass'] else 1
if __name__=='__main__': raise SystemExit(main())
