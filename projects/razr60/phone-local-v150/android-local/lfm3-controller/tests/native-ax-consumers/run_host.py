#!/usr/bin/env python3
"""Actual typed capture consumers on bounded synthetic host values."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
PKG=Path('src/org/trillionnium/hepta/local')
BG=Path('src/org/trillionnium/hepta/background')
TEST=Path('tests/native-ax-consumers')
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
def sha(b):return hashlib.sha256(b).hexdigest()
def meta(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def need(ok,why):
 if not ok:raise RuntimeError(why)
def write(p,b):
 if isinstance(b,str):b=b.encode()
 with p.open('xb') as f:f.write(b)
def main():
 ap=argparse.ArgumentParser()
 for x in ['source','output','java-home','json-jar']:ap.add_argument('--'+x,required=True,type=Path)
 ap.add_argument('--capture-helper',type=Path)
 a=ap.parse_args();src=a.source.resolve();out=a.output.absolute();jdk=a.java_home.resolve();jar=a.json_jar.resolve()
 helper=(a.capture_helper or src/PKG/'ObservationCaptureEvidence.java').resolve()
 need(src.is_dir() and not out.exists() and src not in out.parents,'fresh output outside source required')
 need(jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA,'pinned actual JSON jar required')
 paths=[src/PKG/(x+'.java') for x in ['NativeAppEvidence','NativeActionSnapshotCheck','NativeCtripFormObservation','ObservedChildText','ObservedTargetLabels']]
 paths += [src/BG/(x+'.java') for x in ['ProfileIdentity','ProfileTarget','WindowOwnership']]
 paths += [helper,src/TEST/'NativeAxConsumersHostTest.java']
 tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
 need(all(p.is_file() for p in paths+tools),'actual source/full JDK inputs required')
 inputs=[meta(p) for p in paths+[src/TEST/'run_host.py']];toolrows=[meta(p) for p in tools]
 out.mkdir(parents=True,mode=0o700);classes=out/'classes';classes.mkdir()
 env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
 for k in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH']:env.pop(k,None)
 report={'schema':'hepta.native-ax-consumers-host-gate.v1','all_pass':False,'inputs_before':inputs,'tools_before':toolrows,'stages':[],
   'actual_capture_helper_source':meta(helper),'consumer_classes_compiled':['NativeAppEvidence','NativeActionSnapshotCheck'],
   'synthetic_census_and_platform_values':True,'android_execution':False,'phone_operations':0,'model_executed':False,
   'business_completion_verified':False,'controller_adapter_and_session_full_gate_pending':True}
 try:
  commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',classes,*paths]),
   ('cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeAxConsumersHostTest',out/'CASES.json'])]
  for name,cmd in commands:
   started=time.monotonic();r=subprocess.run(list(map(str,cmd)),cwd=out,env=env,capture_output=True,timeout=120)
   write(out/(name+'.stdout'),r.stdout);write(out/(name+'.stderr'),r.stderr)
   report['stages'].append({'name':name,'argv':list(map(str,cmd)),'exit_code':r.returncode,'seconds':time.monotonic()-started,'stdout':meta(out/(name+'.stdout')),'stderr':meta(out/(name+'.stderr'))})
   if r.returncode:print(r.stderr.decode('utf-8','replace')[-10000:])
   need(r.returncode==0,'actual stage failed: '+name)
  cases=json.loads((out/'CASES.json').read_text())
  need(cases['schema']=='hepta.native-ax-consumers-host.v1' and cases['all_pass'] is True and cases['cases']==61
    and len(cases['case_names'])==len(set(cases['case_names']))==61 and cases['assertions']>=61,'complete unique focused matrix required')
  need(cases['phone_operations']==0 and cases['android_execution'] is False and cases['model_executed'] is False
    and cases['platform_dispatch_executed'] is False and cases['business_completion_verified'] is False,'host boundary differs')
  report.update(all_pass=True,cases=cases,cases_file=meta(out/'CASES.json'))
 except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
 finally:
  report['inputs_after']=[meta(p) for p in paths+[src/TEST/'run_host.py']];report['tools_after']=[meta(p) for p in tools]
  report['inputs_unchanged']=report['inputs_after']==inputs;report['tools_unchanged']=report['tools_after']==toolrows
  report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged']
  write(out/'RESULT.json',json.dumps(report,indent=2,sort_keys=True)+'\n')
  print(json.dumps({'all_pass':report['all_pass'],'cases':report.get('cases',{}).get('cases'),'assertions':report.get('cases',{}).get('assertions'),'result':meta(out/'RESULT.json'),'error':report.get('error')}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
