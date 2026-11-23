#!/usr/bin/env python3
"""Pinned observed DOM in synthetic flight-stage envelopes; no device access.
Four private originals are explicit inputs. Full CASES.json stays in the private
output directory; RESULT.json publishes only hashes, counts and scope.
"""
import argparse, hashlib, importlib.util, json, os, signal, subprocess, sys, time
from pathlib import Path

def sha(raw): return hashlib.sha256(raw).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
    for n in ('output','java-home','json-jar','calendar-dom','calendar-ax','home-capture','original-prompt'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    paths=(a.source,a.output,a.java_home,a.json_jar,a.calendar_dom,a.calendar_ax,a.home_capture,a.original_prompt)
    if any(not v.is_absolute() or any(x.is_symlink() for x in (v,*v.parents)) for v in paths):
        raise ValueError('absolute ordinary paths required')
    if a.output.exists() or a.source==a.output or a.source in a.output.parents:
        raise ValueError('exclusive output outside source required')
    loader=a.source/'tests/web-flight/run_query_host_tests.py'
    spec=importlib.util.spec_from_file_location('query_fixture_factories',loader)
    q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
    original={}
    def bound(path):
        value=q.read(path);original[path]=value;return value[0]
    bound(loader)
    sources={n:bound(a.source/n) for n in q.PURE_PATHS}
    raw=sources[q.RETAINED_QUERY['path']]
    q.need(len(raw)==q.RETAINED_QUERY['bytes'] and sha(raw)==q.RETAINED_QUERY['sha256'],'unchanged query factories')
    generated=[];factories=[]
    for pin in q.FACTORY_SPECS:
        raw,record=q.factory_projection(bound(a.source/pin['path']),pin)
        generated.append((pin['generated']['path'],raw));factories.append(record)
    session=bound(a.source/'src/org/trillionnium/hepta/local/WebFlightSession.java');methods=[]
    for pin in q.METHOD_PINS:
        text=q.java_block(session,pin['signature'])
        q.need(len(text.encode())==pin['bytes'] and sha(text.encode())==pin['sha256'],'unchanged compiled dispatch boundary')
        methods.append(text)
    generated.append(('generated/org/trillionnium/hepta/local/WebFlightDispatchProjection.java',
                      q.PROJECTION.replace('/* EXACT_METHODS */','\n'.join(methods)).encode()))
    test=a.source/'tests/web-flight/WebFlightHomeGoalHostTest.java';test_raw=bound(test)
    q.need(sha(test_raw)=='c9d52a9ac22a8f88321b8702e076b8d37e312edf7409027f87e7a98e39b8040d','reviewed stage test')
    jar=bound(a.json_jar)
    q.need(sha(jar)=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','pinned host JSON')
    fixtures=[('calendar_dom',a.calendar_dom,'f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa'),
              ('calendar_ax',a.calendar_ax,'59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec'),
              ('home_capture',a.home_capture,'73e20002f8f2cea161084681f558504d8afb58d09e8e2812ce8ff22a96b7a6c5'),
              ('original_prompt',a.original_prompt,'85d6d118b66375f368c3fbcb26ea66aed6f1b58a8f2083e2f6bb22d51f472b14')]
    for name,path,pin in fixtures:q.need(sha(bound(path))==pin,'original fixture hash: '+name)
    a.output.mkdir(parents=True,mode=0o700,exist_ok=False);classes=a.output/'classes';classes.mkdir()
    r=dict(schema='hepta.flight-home-goal-portable-host.v1',all_pass=False,phone_actions=0,
           actual_model_executed=False,actual_query_executed=False,business_verified=False,
           original_query_test_main_executed=False,
           fixture_scope='Pinned original DOM/AX/prompt with synthetic task, receipt, native and outcome envelopes.',
           test_sha256=sha(test_raw),json_dependency_sha256=sha(jar),factory_projections=factories,steps=[])
    try:
        factory_paths=[]
        for name,raw in generated:
            target=a.output/name;q.put(target,raw);factory_paths.append(target)
        commands=[('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none',
                   '-classpath',a.json_jar,'-d',classes,*[a.source/n for n in q.PURE_PATHS],*factory_paths,test]),
                  ('stages',[a.java_home/'bin/java','-Xmx768m','-cp',str(classes)+os.pathsep+str(a.json_jar),
                   'org.trillionnium.hepta.local.WebFlightHomeGoalHostTest',a.calendar_dom,a.calendar_ax,
                   a.home_capture,a.original_prompt,a.output/'CASES.json'])]
        for name,command in commands:
            start=time.monotonic()
            child=subprocess.Popen(list(map(str,command)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,start_new_session=True)
            try:out,err=child.communicate(timeout=120)
            except BaseException:
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    try:os.killpg(child.pid,sig)
                    except ProcessLookupError:pass
                out,err=child.communicate(timeout=10)
                q.put(a.output/(name+'.stdout'),out);q.put(a.output/(name+'.stderr'),err)
                raise
            q.put(a.output/(name+'.stdout'),out);q.put(a.output/(name+'.stderr'),err)
            r['steps'].append(dict(name=name,exit_code=child.returncode,seconds=time.monotonic()-start,
                                  stdout_sha256=sha(out),stderr_sha256=sha(err)))
            q.need(child.returncode==0,'host command failed: '+name)
        raw=(a.output/'CASES.json').read_bytes();cases=json.loads(raw)
        q.need(cases['all_pass'] is True and cases['stages_count']==16 and cases['assertions']==31,'exact stage count')
        checks=cases['desired_home_checks']
        q.need(len(checks)==3 and all(v['pass'] is True for v in checks),'three desired homepage checks')
        q.need(cases['task_receipt_native_and_model_outcomes_synthetic'] is True and cases['phone_actions']==0
               and not cases['actual_model_executed'] and not cases['actual_query_executed']
               and not cases['business_verified'],'host scope')
        r.update(all_pass=True,stages=16,assertions=31,desired_home_checks=3,desired_home_checks_passed=3,
                 private_cases_sha256=sha(raw))
    except Exception as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        r['originals_unchanged']=all(q.read(path)==value for path,value in original.items())
        r['all_pass'] &= r['originals_unchanged']
        r['all_bound_inputs']=[dict(role=str(path.relative_to(a.source)) if a.source in path.parents else
                                   next((n for n,f,_ in fixtures if f==path),'json_dependency'),
                                   bytes=len(v[0]),sha256=sha(v[0])) for path,v in original.items()]
        raw=q.enc(r);q.put(a.output/'RESULT.json',raw)
        print(json.dumps(dict(all_pass=r['all_pass'],stages=r.get('stages'),assertions=r.get('assertions'),
                              desired_home_checks=r.get('desired_home_checks'),error=r.get('error'),result_sha256=sha(raw))))
    return 0 if r['all_pass'] else 1
if __name__=='__main__':
    sys.dont_write_bytecode=True
    raise SystemExit(main())
