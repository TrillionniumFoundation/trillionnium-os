#!/usr/bin/env python3
"""Actual coordinator + original pair extractor; synthetic framework rows and clocks."""
import argparse,hashlib,importlib.util,json,os,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
def meta(p):
 p=Path(p).resolve();raw=p.read_bytes()
 return {'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(p.stat().st_mode)}
def write_json(p,value):
 with Path(p).open('x',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
def module(path):
 spec=importlib.util.spec_from_file_location('actual_permission_pair_generator',path)
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def main():
 ap=argparse.ArgumentParser()
 for key in ('source','output','java-home'):ap.add_argument('--'+key,type=Path,required=True)
 ap.add_argument('--negative-control',action='store_true')
 a=ap.parse_args();s=a.source.resolve(strict=True);o=a.output.resolve();jdk=a.java_home.resolve(strict=True)
 if o.exists() or s==o or s in o.parents:raise RuntimeError('fresh outside-source output required')
 if Path(__file__).resolve()!=s/'tests/profile-permission-launch-cookie-exit/run_host.py':raise RuntimeError('runner/source mismatch')
 o.mkdir(parents=True,mode=0o700)
 env=dict(os.environ)
 cleared=['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH','PYTHONHOME','HEPTA_ADMISSION_SOURCE','HEPTA_TEST_JAVA','HEPTA_TEST_JAVAC']
 for key in cleared:env.pop(key,None)
 env['PYTHONDONTWRITEBYTECODE']='1'
 bg=s/'src/org/trillionnium/hepta/background';old=s/'tests/profile-permission-transient';here=Path(__file__).resolve().parent
 names=['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','FixedIntentTools','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask','ProfilePermissionTransient','ProfileDisplayCustody']
 files=[bg/(name+'.java') for name in names]+[s/'tests/profile-broker/ProfileBrokerHostTest.java',old/'ProfilePermissionTransientHostTest.java',here/'ProfilePermissionLaunchCookieExitHostTest.java']
 fixture=old/'fixtures/synthetic-activities.txt'
 tracked=files+[Path(__file__).resolve(),fixture,old/'run_host.py',bg/'ProfileTaskPlatform.java',
  s/'tests/profile-permission-ready-confirmation/run_host.py',s/'tests/profile-permission-ready-confirmation/ProfileReadyConfirmationHostTest.java',
  old/'ProfileStateSettleHostTest.java',bg/'BackgroundDisplayBroker.java',s/'src/org/trillionnium/hepta/local/BackgroundSession.java']
 sources=[meta(p) for p in tracked];tools=[meta(jdk/p) for p in ['bin/java','bin/javac','lib/modules','lib/ct.sym']]
 result={'schema':'hepta.profile-permission-launch-cookie-exit-gate.v1','all_pass':False,'source':str(s),'negative_control':a.negative_control,
  'source_inputs':sources,'tools_before':tools,'environment_cleared':cleared,'stages':[],'phone_operations':0,'android_build':False,'framework_ports_synthetic':True}
 def run(name,argv):
  started=time.monotonic()
  with (o/(name+'.stdout')).open('xb') as out,(o/(name+'.stderr')).open('xb') as err:
   completed=subprocess.run(list(map(str,argv)),cwd=s,env=env,stdout=out,stderr=err,timeout=180)
  row={'name':name,'argv':list(map(str,argv)),'cwd':str(s),'exit_code':completed.returncode,'elapsed_seconds':time.monotonic()-started,'stdout':meta(o/(name+'.stdout')),'stderr':meta(o/(name+'.stderr'))}
  result['stages'].append(row);return row
 try:
  if not a.negative_control:
   legacy=run('original-ready-16-29-114',[sys.executable,'-B',s/'tests/profile-permission-ready-confirmation/run_host.py','--source',s,'--java-home',jdk,'--output',o/'original-ready'])
   previous=json.loads((o/'original-ready/RESULT.json').read_text());result['original_ready_result']=meta(o/'original-ready/RESULT.json')
   if legacy['exit_code']!=0 or previous.get('all_pass') is not True or previous['retained_gate']['permission_cases']!=16 or previous['retained_gate']['state_cases']!=29 or previous['ready_summary']['cases']!=114:
    raise RuntimeError('original 16/29/114 entry did not pass unchanged')
   result['original_case_counts']={'permission':16,'state':29,'ready':114}
  generated_dir=o/'generated';generated_dir.mkdir()
  generated,receipt=module(old/'run_host.py').prepare_permission_pair_adapters(bg/'ProfileTaskPlatform.java',generated_dir)
  result['actual_pair_extraction']=receipt;compile_paths=files+generated
  result['compile_inputs_before']=[meta(p) for p in compile_paths]
  stage=run('compile-current-cases',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-Xlint:all,-options','-Werror','-proc:none','-d',o/'classes']+compile_paths)
  if stage['exit_code']!=0 or stage['stderr']['bytes']!=0:raise RuntimeError('actual new cases javac failed')
  argv=[jdk/'bin/java','-ea','-cp',o/'classes','org.trillionnium.hepta.background.ProfilePermissionLaunchCookieExitHostTest',fixture,o/'CASES.json']
  if a.negative_control:argv.append('positive-only')
  stage=run('new-lifecycle-cases',argv)
  cases=json.loads((o/'CASES.json').read_text());result['case_result']=cases;result['cases_file']=meta(o/'CASES.json')
  result['compile_inputs_after']=[meta(p) for p in compile_paths]
  if a.negative_control:
   result['expected_old_semantic_rejection']=bool(stage['exit_code']==1 and stage['stderr']['bytes']==0 and cases['cases']==4 and cases['all_pass'] is False and len(cases['results'])==4 and all(x.get('passed') is False and x.get('refusal_code')=='PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ' for x in cases['results']))
   result['boundary']='Deliberate old-production negative control: javac succeeded; the same four positive lifecycle cases remain failed, not a business or test PASS.'
  else:
   result['all_pass']=bool(stage['exit_code']==0 and stage['stderr']['bytes']==0 and cases['all_pass'] is True and cases['cases']==45 and len(cases['results'])==45 and len({x['name'] for x in cases['results']})==45 and all(x.get('passed') is True for x in cases['results']))
 except Exception as error:
  result['error']=str(error);result['error_type']=type(error).__name__
 finally:
  result['source_inputs_after']=[meta(p) for p in tracked];result['tools_after']=[meta(jdk/p) for p in ['bin/java','bin/javac','lib/modules','lib/ct.sym']]
  result['source_inputs_unchanged']=sources==result['source_inputs_after'];result['tools_unchanged']=tools==result['tools_after']
  result['inputs_unchanged']=result.get('compile_inputs_before')==result.get('compile_inputs_after')
  result['all_pass']=bool(result['all_pass'] and result['source_inputs_unchanged'] and result['tools_unchanged'] and result['inputs_unchanged'])
  write_json(o/'RESULT.json',result)
 okay=result.get('expected_old_semantic_rejection') is True if a.negative_control else result['all_pass']
 print(json.dumps({'all_pass':result['all_pass'],'negative_control':a.negative_control,'expected_old_semantic_rejection':result.get('expected_old_semantic_rejection'),'cases':(result.get('case_result') or {}).get('cases'),'assertions':(result.get('case_result') or {}).get('assertions'),'result':meta(o/'RESULT.json')}))
 return 0 if okay and result['source_inputs_unchanged'] and result['tools_unchanged'] and result['inputs_unchanged'] else 1
if __name__=='__main__':raise SystemExit(main())
