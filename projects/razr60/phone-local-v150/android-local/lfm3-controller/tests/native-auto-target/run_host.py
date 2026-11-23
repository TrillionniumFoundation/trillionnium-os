#!/usr/bin/env python3
"""Actual auto-target values, UI Start and old model-settings transaction.
Android visibility/package preferences, process inventory, model-asset verification
and final task scheduling are explicit ports. No Android/model/input qualification.
"""
import argparse, ast, hashlib, importlib.util, json, os, subprocess, time
from pathlib import Path


def sha(raw): return hashlib.sha256(raw).hexdigest()
def need(ok, why):
    if not ok: raise RuntimeError(why)
def module(path, name):
    spec=importlib.util.spec_from_file_location(name,path); value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def write(path, raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f: f.write(raw)
def ref(path):
    raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def prepare(source, out):
    query=module(source/'tests/web-flight/run_query_host_tests.py','auto_query')
    bg=module(source/'tests/background-session/prepare_fixture.py','auto_background')
    ports=module(source/'tests/native-auto-target/host_ports.py','auto_ports')
    pkg=source/'src/org/trillionnium/hepta/local'
    fixture=out/'generated';files,background=bg.prepare(source,fixture)
    files=[p for p in files if not (p.parent.name=='json' and p.parent.parent.name=='org')]
    actual=[source/p for p in query.PURE_PATHS if p!='tests/web-flight/WebFlightQueryHostTest.java']
    names=['BackgroundUiPreferences','BackgroundAutoTargetPreferences','BackgroundAutoTargetResolver',
           'LocalRuntimeConfig','ModelProfile','LocalModelSettings','RuntimeConfigTransaction','ModelFileVerifier',
           'MobiMindPrivateFiles','MobiMindContract','MobiMindPins','VlmPins','VlmResultContract']
    actual += [pkg/(n+'.java') for n in names]
    # The default old client boundary must not shadow the actual automatic producer.
    old_auto=source/'tests/native-app/legacy-boundary/BackgroundAutoTargetResolver.java'
    need(files.count(old_auto)==1 and (pkg/'BackgroundAutoTargetResolver.java') in actual,
         'one refusing old-domain input replaced by the actual automatic resolver')
    files=[p for p in files if p!=old_auto]
    # Original route's private refusing Calendar extension, identical literal.
    route=(source/'tests/native-app-routing/run_host.py').read_text()
    main=next(n for n in ast.parse(route).body if isinstance(n,ast.FunctionDef) and n.name=='main')
    literal={}
    for n in ast.walk(main):
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('calendar_shape','envelope_raw'):
            literal[n.targets[0].id]=ast.literal_eval(n.value)
    need(set(literal)=={'calendar_shape','envelope_raw'},'exact route compiler shapes required')
    legacy=source/'tests/native-app/legacy-boundary/NativeAppSession.java';raw=legacy.read_bytes();end=raw.rfind(b'\n}')
    need(end>=0 and b'class CalendarOffer' not in raw,'legacy Session boundary')
    session=fixture/'auto-types/NativeAppSession.java';write(session,raw[:end]+literal['calendar_shape']+raw[end:])
    envelope=fixture/'auto-types/NativeCalendarDateEnvelope.java';write(envelope,literal['envelope_raw'])
    actual=[session if p==legacy else p for p in actual]
    actual += [envelope,pkg/'NativeSearchDecision.java',source/'tests/native-app/legacy-boundary/NativeSearchPlanning.java',source/'tests/native-app/legacy-boundary/NativeSearchSession.java']
    generated_local=fixture/'org/trillionnium/hepta/local'
    files=[p for p in files if not (p.parent==generated_local and p.name in ('NativeAppSession.java','MobiMindContract.java'))]
    # Real host file IO fixture from original transaction gate, not JSON success.
    for name in ('Os.java','OsConstants.java','StructStat.java','ErrnoException.java'):
        target=fixture/'android/system'/name
        original=source/'tests/local-model-settings/fixtures/android/system'/name
        text=original.read_text()
        if name=='OsConstants.java':
            need(text.count('ENOENT=2,EPIPE=32,O_RDONLY=0,O_WRONLY=1,')==1,'exact original transaction constants port')
            text=text.replace('ENOENT=2,EPIPE=32,O_RDONLY=0,O_WRONLY=1,','ENOENT=2,EEXIST=17,EPIPE=32,O_RDONLY=0,O_WRONLY=1,O_RDWR=2,',1)
        if name=='Os.java':
            text=text.replace('public final class Os {','public final class Os {\n public static void remove(String p)throws java.io.IOException{java.nio.file.Files.delete(java.nio.file.Paths.get(p));}',1)
        target.write_text(text)
    # Keep the transaction fixture's explicit Android UID surrogate paired with
    # its Os mapping; the generic background fixture instead uses the host UID.
    (fixture/'android/os/Process.java').write_bytes((source/'tests/local-model-settings/fixtures/android/os/Process.java').read_bytes())
    generated=ports.prepare(source,fixture,query.java_block)
    files+=generated['files']
    for p in generated['replaced']:
        files=[x for x in files if x!=p]+[p]
    files=list(dict.fromkeys(Path(p).resolve() for p in actual+files))
    # No new authority instance is forged by the old Calendar compiler shapes.
    metadata={'background_fixture':background,'excluded_refusing_auto_compiler_input':ref(old_auto),'actual_full_sources':[ref(p) for p in actual if source in p.parents],
              'extraction':generated['extraction'],'ports':generated['ports'],
              'calendar_private_refusing_shape_sha256':sha(literal['calendar_shape']),
              'task_schedule_is_explicit_capture_port':True,'model_asset_and_process_inventory_are_ports':True}
    return files,metadata


def main():
    p=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve();out=a.output.resolve();jdk=a.java_home.resolve();jar=a.json_jar.resolve()
    need(source.is_dir() and not out.exists() and source not in out.parents,'fresh output outside source')
    need(sha(jar.read_bytes())=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','fixed JSON jar')
    out.mkdir(parents=True);before={str(x.relative_to(source)):ref(x) for x in sorted(source.rglob('*')) if x.is_file() and '__pycache__' not in x.parts and not x.name.startswith('.hepta-lock-')}
    record={'schema':'hepta.automatic-target-host.v1','all_pass':False,'stages':[], 'inputs_before':before,
            'phone_operations':0,'android_runtime':False,'model_inference':False,'business_verified':False}
    env=dict(os.environ,PATH=str(jdk/'bin')+':'+os.environ.get('PATH',''),PYTHONDONTWRITEBYTECODE='1')
    for key in ('CLASSPATH','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):env.pop(key,None)
    def run(name,argv):
        start=time.monotonic();r=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=100)
        write(out/(name+'.stdout'),r.stdout);write(out/(name+'.stderr'),r.stderr)
        record['stages'].append({'name':name,'argv':list(map(str,argv)),'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start,'stdout':ref(out/(name+'.stdout')),'stderr':ref(out/(name+'.stderr'))})
        if r.returncode:print(r.stdout.decode(errors='replace')[-8000:]);print(r.stderr.decode(errors='replace')[-18000:]);raise RuntimeError(name+' failed')
    try:
        inputs,metadata=prepare(source,out);inputs.append(source/'tests/native-auto-target/AutomaticTargetHostTest.java')
        record['extraction']=metadata;record['compile_inputs_before']=[ref(x) for x in inputs]
        classes=out/'classes';classes.mkdir();empty=out/'empty';empty.mkdir()
        run('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-sourcepath',empty,'-cp',jar,'-d',classes,*inputs])
        run('cases',[jdk/'bin/java','-Dhepta.fixture.host_uid='+str(os.getuid()),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.AutomaticTargetHostTest',out/'cases'])
        result=json.loads((out/'cases/RESULT.json').read_text());record['cases']=result;need(result['all_pass'],'all cases must pass')
        record['compile_inputs_after']=[ref(x) for x in inputs];need(record['compile_inputs_after']==record['compile_inputs_before'],'compile inputs changed')
        record['all_pass']=True
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    finally:
        after={str(x.relative_to(source)):ref(x) for x in sorted(source.rglob('*')) if x.is_file() and '__pycache__' not in x.parts and not x.name.startswith('.hepta-lock-')}
        record['source_unchanged']=before==after;record['all_pass']=record['all_pass'] and record['source_unchanged']
        write(out/'RESULT.json',(json.dumps(record,ensure_ascii=False,indent=2)+'\n').encode())
        print(json.dumps({'all_pass':record['all_pass'],'error':record.get('error'),'result':ref(out/'RESULT.json')},ensure_ascii=False))
    return 0 if record['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
