#!/usr/bin/env python3
"""Actual Ctrip calendar and Session host regression; original provider cases retained."""
import argparse,hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path

JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
PREVIOUS_SHA='1dd0766728e030e8a3d747898244aabe0c8800cab723ab04e185cb1856f124f9'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,why):
    if not ok:raise RuntimeError(why)
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(raw)
def meta(path):
    raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def inventory(source):
    result={}
    for p in sorted(source.rglob('*')):
        need(not p.is_symlink(),'source symlink')
        if p.is_file() and '__pycache__' not in p.parts:result[str(p.relative_to(source))]={'bytes':p.stat().st_size,'sha256':sha(p.read_bytes()),'mode':p.stat().st_mode&0o777}
    return result
def main():
    a=argparse.ArgumentParser();a.add_argument('--source',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--java-home',type=Path,required=True);a.add_argument('--json-jar',type=Path,required=True);args=a.parse_args()
    source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve();jar=args.json_jar.resolve();own=source/'tests/native-ctrip-calendar'
    need(source.is_dir() and not out.exists() and source not in out.parents,'fresh output outside source');need(jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA,'fixed org.json')
    before=inventory(source);tools={str(p):meta(p) for p in (jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar)}
    out.mkdir(parents=True,mode=0o700);env=dict(os.environ);env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+':'+env.get('PATH','');env['PYTHONDONTWRITEBYTECODE']='1'
    for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
    report={'schema':'hepta.native-ctrip-calendar-gate.v1','all_pass':False,'inputs_before':before,'tools_before':tools,'stages':[],'phone_operations':0,'android_runtime':False,'model_executed':False,'business_verified':False}
    def run(name,argv):
        start=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=180)
        stdout=out/(name+'.stdout');stderr=out/(name+'.stderr');write(stdout,p.stdout);write(stderr,p.stderr)
        report['stages'].append({'name':name,'argv':list(map(str,argv)),'exit_code':p.returncode,'seconds':time.monotonic()-start,'stdout':meta(stdout),'stderr':meta(stderr)})
        if p.returncode:print(p.stdout.decode('utf-8','replace')[-12000:]);print(p.stderr.decode('utf-8','replace')[-18000:])
        need(p.returncode==0,'actual stage failed: '+name)
    try:
        provenance=json.loads((own/'fixtures/PROVENANCE.json').read_text());
        for row in provenance['files']:
            p=own/row['path'];need(p.stat().st_size==row['bytes'] and sha(p.read_bytes())==row['sha256'],'original fixture pin differs '+row['path'])
        previous=own/'previous-f842/NativeCtripFlightPage.java.txt';need(sha(previous.read_bytes())==PREVIOUS_SHA,'exact previous source')
        provider=load(source/'tests/native-app-provider/run_host.py','calendar_retained_provider');query=load(source/'tests/web-flight/run_query_host_tests.py','calendar_query_closure');bg=load(source/'tests/background-session/prepare_fixture.py','calendar_background_fixture')
        bgfiles,bgrecord=bg.prepare(source,out/'platform-fixture');bgfiles=[p for p in bgfiles if not (p.parent.name=='json' and p.parent.parent.name=='org') and 'terminal' not in p.parts]
        paths=[source/p for p in query.PURE_PATHS if p not in ('tests/web-flight/WebFlightQueryHostTest.java','tests/native-app/legacy-boundary/NativeAppSession.java')]+bgfiles
        paths += [source/('src/org/trillionnium/hepta/local/'+name+'.java') for name in provider.EXTRA_SOURCES]
        paths += [source/'tests/native-app-fixtures/NativeXmlFixture.java',source/'tests/native-app-provider/NativeAppProviderHostTest.java',own/'NativeCtripCalendarHostTest.java']
        paths=list(dict.fromkeys(p.resolve() for p in paths));report['compile_inputs']=[meta(p) for p in paths]
        write(out/'BOUNDARIES.json',(json.dumps({'schema':'hepta.native-ctrip-calendar-boundaries.v1','background_fixture':bgrecord,'actual_foreground_xml_not_background_frame':True,'host_noderef_window_lease_task_dispatch_modelled':True,'fixture_provenance_sha256':sha((own/'fixtures/PROVENANCE.json').read_bytes())},ensure_ascii=False,indent=2)+'\n').encode())
        classes=out/'classes';classes.mkdir();flags=['--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror']
        run('compile',[jdk/'bin/javac',*flags,'-classpath',jar,'-d',classes,*paths])
        run('retained-provider-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeAppProviderHostTest',source/'tests/native-app-provider/fixtures',out/'RETAINED-PROVIDER-CASES.json'])
        retained=json.loads((out/'RETAINED-PROVIDER-CASES.json').read_text());need(retained['all_pass'] is True and retained['cases']==39 and retained['assertions']==315 and retained['case_names']==provider.EXPECTED_NAMES,'all retained 39/315 cases exact')
        run('calendar-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeCtripCalendarHostTest',own/'fixtures',source/'tests/native-app-provider/fixtures',out/'CALENDAR-CASES.json'])
        current=json.loads((out/'CALENDAR-CASES.json').read_text());need(current['all_pass'] is True and current['phone_operations']==0 and current['business_verified'] is False and current['bound_background_frame_actual'] is False,'calendar cases and host boundary')
        oldsource=out/'previous-src/org/trillionnium/hepta/local/NativeCtripFlightPage.java';write(oldsource,previous.read_bytes());oldclasses=out/'previous-classes';oldclasses.mkdir()
        run('previous-compile',[jdk/'bin/javac',*flags,'-classpath',str(classes)+os.pathsep+str(jar),'-d',oldclasses,oldsource,own/'LegacyCalendarReplayHostTest.java'])
        run('previous-replay',[jdk/'bin/java','-cp',str(oldclasses)+os.pathsep+str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.LegacyCalendarReplayHostTest',own/'fixtures',out/'PREVIOUS-CASES.json'])
        old=json.loads((out/'PREVIOUS-CASES.json').read_text());need(old['all_pass'] is True and old['cases']==1 and old['assertions']==2,'previous actual rejection reproduced')
        cases={'schema':'hepta.native-ctrip-calendar-composition-host.v1','all_pass':True,'cases':retained['cases']+current['cases']+old['cases'],'assertions':retained['assertions']+current['assertions']+old['assertions'],'case_names':retained['case_names']+current['case_names']+old['case_names'],'retained_provider':retained,'calendar':current,'previous_f842':old,'phone_operations':0,'business_verified':False}
        write(out/'CASES.json',(json.dumps(cases,ensure_ascii=False,indent=2)+'\n').encode());report['cases']=cases;report['case_records']={p.name:meta(p) for p in [out/'CASES.json',out/'CALENDAR-CASES.json',out/'RETAINED-PROVIDER-CASES.json',out/'PREVIOUS-CASES.json']};report['all_pass']=True
    except Exception as exc:report['failure']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        after=inventory(source);report['inputs_after']=after;report['inputs_unchanged']=before==after;report['tools_after']={p:meta(Path(p)) for p in tools};report['tools_unchanged']=tools==report['tools_after'];report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged']
        write(out/'RESULT.json',(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode());print(json.dumps({'all_pass':report['all_pass'],'cases':report.get('cases',{}).get('cases'),'assertions':report.get('cases',{}).get('assertions'),'failure':report.get('failure'),'result':meta(out/'RESULT.json')}))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
