#!/usr/bin/env python3
"""New calendar protocol only: actual private bytes/classes, explicit host platform ports."""
import argparse, hashlib, importlib.util, json, os, stat, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode=True

def sha(raw): return hashlib.sha256(raw).hexdigest()
def record(path):
    p=Path(path).resolve();raw=p.read_bytes()
    return {'path':str(p),'bytes':len(raw),'sha256':sha(raw),'mode':stat.S_IMODE(p.stat().st_mode)}
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('source','output','java-home','json-jar'): parser.add_argument('--'+key,required=True,type=Path)
    a=parser.parse_args();source=a.source.resolve();out=a.output.resolve();jdk=a.java_home.resolve();jar=a.json_jar.resolve()
    if out.exists() or source in out.parents: raise RuntimeError('fresh independent output required')
    out.mkdir(parents=True,mode=0o700)
    closure_path=source/'tests/native-search-planning/host_closure.py';closure=module(closure_path,'calendar_actual_shared_closure')
    if sha(jar.read_bytes())!=closure.JSON_SHA: raise RuntimeError('actual pinned JSON jar required')
    test=source/'tests/native-calendar-date-protocol/NativeCalendarDateProtocolHostTest.java'
    paths,provenance=closure.prepare(source,out/'closure',(test,))
    extra=[source/('src/org/trillionnium/hepta/local/'+name+'.java') for name in ('NativeCalendarDateEnvelope','NativeCalendarDateIntent','NativeCalendarDateProtocol',
        'LocalInference','LocalRuntimeConfig','ModelProfile','MobiMindPrivateFiles','MobiMindContract','MobiMindPins','UiVenusInputContract','UiVenusPins','VlmPins')]
    paths=list(dict.fromkeys(paths+extra))
    recognizer_path=source/'tests/action-grammar/gbnf_recognizer.py'
    originals=list(dict.fromkeys([Path(r['path']) for r in provenance['production_inputs']]+extra+[test,Path(__file__).resolve(),recognizer_path]))
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jar,Path(sys.executable).resolve()]
    before=[record(p) for p in originals];tool_before=[record(p) for p in tools]
    report={'schema':'hepta.native-calendar-protocol-focus.v1','all_pass':False,'source':str(source),'scope':'host_only_unconnected_protocol',
       'source_inputs_before':before,'tools_before':tool_before,'closure':provenance,'compile_inputs':[record(p) for p in paths],
       'stages':[],'phone_actions':0,'model_runs':0,'actual_service_or_broker_tested':False,'actual_session_offer_tested':False,
       'date_or_business_verified':False,'started_host_wall_ms':int(time.time()*1000)}
    classes=out/'classes';classes.mkdir();env=dict(os.environ);env['PATH']=str(jdk/'bin')+':/usr/bin:/bin';env['PYTHONDONTWRITEBYTECODE']='1'
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'): env.pop(key,None)
    try:
        for name,argv in [('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',classes,*paths]),
                          ('protocol',[jdk/'bin/java','-Djava.awt.headless=true','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeCalendarDateProtocolHostTest',out,out/'work'])]:
            started=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=120)
            (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            report['stages'].append({'name':name,'argv':list(map(str,argv)),'cwd':str(out),'exit_code':p.returncode,
                'elapsed_seconds':time.monotonic()-started,'stdout':record(out/(name+'.stdout')),'stderr':record(out/(name+'.stderr'))})
            if p.returncode: raise RuntimeError('actual stage failed: '+name)
        cases=json.loads((out/'CASES.json').read_text());report['cases']=cases
        if cases['all_pass'] is not True or cases['cases']!=20: raise RuntimeError('exact necessary case count/pass differs')
        recognizer=module(recognizer_path,'calendar_independent_gbnf').Recognizer((out/'calendar.gbnf').read_text())
        vectors=json.loads((out/'GRAMMAR-VECTORS.json').read_text())['vectors'];checks=[]
        for vector in vectors:
            actual=recognizer.accepts(vector['raw']);checks.append({'name':vector['name'],'expected':vector['expected'],'actual':actual})
        grammar={'schema':'hepta.calendar-gbnf-host.v1','all_pass':all(c['expected']==c['actual'] for c in checks),'vectors':len(checks),'checks':checks,
                 'grammar':record(out/'calendar.gbnf'),'input_vectors':record(out/'GRAMMAR-VECTORS.json'),'recognizer':record(recognizer_path),
                 'native_sampler_or_model_executed':False}
        (out/'GRAMMAR-RESULT.json').write_text(json.dumps(grammar,ensure_ascii=False,indent=2)+'\n');report['grammar']=record(out/'GRAMMAR-RESULT.json')
        if not grammar['all_pass']: raise RuntimeError('independent emitted GBNF recognition failed')
        report['all_pass']=True
    except Exception as error:
        report['error']=type(error).__name__+': '+str(error)
        if (out/'CASES.json').exists(): report['cases']=json.loads((out/'CASES.json').read_text())
    finally:
        report['source_inputs_after']=[record(p) for p in originals];report['tools_after']=[record(p) for p in tools]
        report['source_inputs_unchanged']=report['source_inputs_before']==report['source_inputs_after'];report['tools_unchanged']=report['tools_before']==report['tools_after']
        report['all_pass']=report['all_pass'] and report['source_inputs_unchanged'] and report['tools_unchanged'];report['finished_host_wall_ms']=int(time.time()*1000)
        report['artifacts']=[record(p) for p in out.rglob('*') if p.is_file() and p.name!='RESULT.json']
        (out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'cases':report.get('cases',{}).get('cases'),'assertions':report.get('cases',{}).get('assertions'),'result':str(out/'RESULT.json')}))
    return 0 if report['all_pass'] else 1
if __name__=='__main__': raise SystemExit(main())
