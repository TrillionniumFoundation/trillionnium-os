#!/usr/bin/env python3
"""Actual pure census + existing identity gates; optional explicit old-source semantic red."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--source-root',type=Path,required=True)
 ap.add_argument('--candidate-root',type=Path)
 ap.add_argument('--baseline-processes',type=Path)
 ap.add_argument('--expected-processes',required=True)
 ap.add_argument('--jdk-bin',type=Path,required=True)
 ap.add_argument('--json-jar',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True)
 a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 if sha(a.json_jar)!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON jar pin differs')
 bg=a.source_root/'src/org/trillionnium/hepta/background'
 candidate=(a.candidate_root or a.source_root)/'src/org/trillionnium/hepta/background/ProfileRecoveryProcesses.java'
 if sha(candidate)!=a.expected_processes:raise RuntimeError('Candidate process source differs')
 names=['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','FixedIntentTools','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask','ProfilePermissionTransient','ProfileDisplayCustody','ProfilePrelaunchRecovery']
 common=[bg/(n+'.java') for n in names]
 legacy=a.source_root/'tests/profile-recovery/ProfileRecoveryHostTest.java'
 test=Path(__file__).with_name('ProfileRecoveryCensusHostTest.java')
 business=test.with_name('BusinessRecoveryCensusHostTest.java')
 empty=test.with_name('EmptyCommandRowHostTest.java')
 files=common+[legacy,test,business,empty,candidate]+([a.baseline_processes] if a.baseline_processes else [])
 pins={str(p):sha(p) for p in files}
 result={'schema':'hepta.census-retry-host-validation.v1','all_pass':False,'phone_contacted':False,'android_runtime':False,
  'source_inputs':pins,'stages':[],'framework_proc_boundary':'synthetic; actual production census and original proof validator'}
 def run(name,argv):
  start=time.monotonic();r=subprocess.run([str(x) for x in argv],capture_output=True,timeout=45)
  (a.output/(name+'.stdout')).write_bytes(r.stdout);(a.output/(name+'.stderr')).write_bytes(r.stderr)
  result['stages'].append({'name':name,'argv':[str(x) for x in argv],'exit_code':r.returncode,
   'elapsed_s':round(time.monotonic()-start,6),'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()})
  return r
 def compile_sources(label,processes):
  classes=a.output/(label+'-classes');classes.mkdir()
  r=run(label+'-compile',[a.jdk_bin/'javac','--release','8','-Xlint:all,-options','-Werror','-proc:none',
   '-encoding','UTF-8','-cp',a.json_jar,'-d',classes,*common,processes,legacy,test]+([business,empty] if label=='candidate' else []))
  if r.returncode or r.stderr:raise RuntimeError(label+' compile failed')
  return str(classes)+':'+str(a.json_jar)
 def java(label,cp,klass,*args):
  return run(label,[a.jdk_bin/'java','-cp',cp,'org.trillionnium.hepta.background.'+klass,*args])
 try:
  if a.baseline_processes:
   if sha(a.baseline_processes)!='53d9aae0dbbd136d95b3ce3f2a468f30b1781e3c48d541614513384e1f9fa1c1':raise RuntimeError('Explicit original baseline pin differs')
   oldcp=compile_sources('baseline',a.baseline_processes)
   r=java('baseline-one-vanished',oldcp,'ProfileRecoveryCensusHostTest','one-vanished')
   old=json.loads(r.stdout)
   if not(r.returncode==1 and not r.stderr and old['passed'] is False and old['observed_recovery'] is False
    and old['enumerations']==1 and old['typed_process_gone_available'] is False and old['error_type']=='java.io.IOException'):
    raise RuntimeError('Old semantic-red result differs')
   result['baseline_red']=old
  cp=compile_sources('candidate',candidate)
  r=java('candidate-one-vanished',cp,'ProfileRecoveryCensusHostTest','one-vanished')
  one=json.loads(r.stdout)
  if r.returncode or r.stderr or one['passed'] is not True or one['enumerations']!=2 or one['typed_process_gone_available'] is not True:
   raise RuntimeError('Candidate one-disappearance case failed')
  result['candidate_green']=one
  r=java('candidate-census',cp,'ProfileRecoveryCensusHostTest')
  census=json.loads(r.stdout)
  if r.returncode or r.stderr or census['passed'] is not True:raise RuntimeError('Census boundary gate failed')
  result['census']=census
  r=java('business-census',cp,'BusinessRecoveryCensusHostTest')
  business=json.loads(r.stdout)
  if r.returncode or r.stderr or business.get('passed') is not True:raise RuntimeError('Business census cases failed')
  result['business_census']=business
  r=java('empty-command-complete-rows',cp,'EmptyCommandRowHostTest')
  empty_rows=json.loads(r.stdout)
  if r.returncode or r.stderr or empty_rows.get('passed') is not True:raise RuntimeError('Empty-command complete-row gate failed')
  result['empty_command_rows']=empty_rows
  r=java('candidate-legacy',cp,'ProfileRecoveryHostTest')
  legacy_result=json.loads(r.stdout)
  if r.returncode or r.stderr or legacy_result['passed'] is not True:raise RuntimeError('Existing identity/proof gate failed')
  result['legacy']=legacy_result
  result['source_inputs_unchanged']=pins=={str(p):sha(p) for p in files}
  if not result['source_inputs_unchanged']:raise RuntimeError('Source changed during host checks')
  result['all_pass']=True
 except Exception as error:result['error']=type(error).__name__+': '+str(error)
 (a.output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'all_pass':result['all_pass'],'result':str(a.output/'RESULT.json'),
  'result_sha256':sha(a.output/'RESULT.json'),'census':result.get('census'),'legacy':result.get('legacy'),'error':result.get('error')},indent=2))
 return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
