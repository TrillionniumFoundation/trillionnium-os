#!/usr/bin/env python3
"""Actual private Adapter proof to one-use Session registry; no model or Android execution."""
import argparse,hashlib,importlib.util,json,os,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
def sha(b):return hashlib.sha256(b).hexdigest()
def ref(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b),'mode':stat.S_IMODE(p.stat().st_mode)}
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for key in ('source','output','java-home','json-jar'):ap.add_argument('--'+key,type=Path,required=True)
 a=ap.parse_args();S=a.source.resolve();O=a.output.resolve();J=a.java_home.resolve();jar=a.json_jar.resolve()
 if O.exists() or S in O.parents:raise RuntimeError('fresh independent output required')
 O.mkdir(mode=0o700,parents=True)
 if sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('real pinned JSON jar required')
 tools=[J/'bin/java',J/'bin/javac',J/'lib/modules',J/'lib/ct.sym',jar,Path(sys.executable).resolve()]
 original=[];report={'schema':'hepta.calendar-private-model-registry-focus.v1','all_pass':False,'source':str(S),'phone_actions':0,'model_executions':0,'stages':[],'started_host_wall_ms':int(time.time()*1000)}
 try:
  helper=S/'tests/native-calendar-date-model/run_host.py'
  spec=importlib.util.spec_from_file_location('calendar_actual_model_fixture',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  paths,original,closure=module.prepare(S,O)
  test=S/'tests/native-calendar-date-registry/NativeCalendarDateRegistryHostTest.java'
  paths.append(test);original=list(dict.fromkeys(original+[helper,test,Path(__file__).resolve()]))
  report['closure']=closure;report['actual_model_fixture_helper']=ref(helper)
  report['source_inputs_before']=[ref(p) for p in original];report['compile_inputs']=[ref(p) for p in paths];report['tools_before']=[ref(p) for p in tools]
  C=O/'classes';C.mkdir();env={**os.environ,'PATH':str(J/'bin')+':/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'}
  for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
  stages=[('compile',[J/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',C,*paths]),
   ('registry',[J/'bin/java','-Djava.awt.headless=true','-cp',str(C)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeCalendarDateRegistryHostTest',O,O/'work',S/'tests/vlm-contract/fixtures/gui-owl-chat-template.jinja'])]
  for name,argv in stages:
   start=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=O,env=env,capture_output=True,timeout=120)
   for kind,data in [('stdout',p.stdout),('stderr',p.stderr)]:(O/(name+'.'+kind)).write_bytes(data)
   report['stages'].append({'name':name,'argv':list(map(str,argv)),'cwd':str(O),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start,'stdout':ref(O/(name+'.stdout')),'stderr':ref(O/(name+'.stderr'))})
   if p.returncode:raise RuntimeError('actual stage failed: '+name)
  report['cases']=json.loads((O/'CASES.json').read_text())
  if not report['cases']['all_pass'] or report['cases']['cases']!=14:raise RuntimeError('all exact necessary registry cases required')
  report['all_pass']=True
 except Exception as e:report['error']=type(e).__name__+': '+str(e)
 finally:
  if original and 'source_inputs_before' in report:
   report['source_inputs_after']=[ref(p) for p in original];report['tools_after']=[ref(p) for p in tools]
   report['source_inputs_unchanged']=report['source_inputs_before']==report['source_inputs_after'];report['tools_unchanged']=report['tools_before']==report['tools_after']
   report['all_pass'] &= report['source_inputs_unchanged'] and report['tools_unchanged']
  if (O/'CASES.json').exists():report['cases']=json.loads((O/'CASES.json').read_text())
  report['finished_host_wall_ms']=int(time.time()*1000);report['artifacts']=[ref(p) for p in O.rglob('*') if p.is_file() and p.name!='RESULT.json']
  (O/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'cases':report.get('cases',{}).get('cases'),'assertions':report.get('cases',{}).get('assertions'),'result':str(O/'RESULT.json')}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
