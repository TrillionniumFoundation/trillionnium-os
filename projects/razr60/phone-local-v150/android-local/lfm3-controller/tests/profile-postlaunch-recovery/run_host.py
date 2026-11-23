#!/usr/bin/env python3
"""Actual postlaunch policy + unchanged prelaunch/census gates. No Android or phone operations."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for n in ('source','java-home','json-jar','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--actual-lease',type=Path)
 a=p.parse_args();s=a.source.resolve();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
 assert sha(a.json_jar)=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
 bg=s/'src/org/trillionnium/hepta/background'
 names=['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','FixedIntentTools','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask','ProfilePermissionTransient','ProfileDisplayCustody','ProfilePrelaunchRecovery','ProfilePostlaunchRecovery','ProfileRecoveryProcesses']
 files=[bg/(n+'.java') for n in names]+[s/'tests/profile-recovery/ProfileRecoveryHostTest.java',s/'tests/profile-recovery-census/ProfileRecoveryCensusHostTest.java',Path(__file__).with_name('ProfilePostlaunchRecoveryHostTest.java')]
 pins={str(x.relative_to(s)):sha(x) for x in files};classes=o/'classes';classes.mkdir();cp=str(classes)+':'+str(a.json_jar)
 commands=[('compile',[str(a.java_home/'bin/javac'),'--release','8','-encoding','UTF-8','-Xlint:all,-options','-Werror','-proc:none','-cp',str(a.json_jar),'-d',str(classes),*[str(x) for x in files]])]
 for stage,klass in [('legacy','ProfileRecoveryHostTest'),('census','ProfileRecoveryCensusHostTest'),('postlaunch','ProfilePostlaunchRecoveryHostTest')]:
  argv=[str(a.java_home/'bin/java'),'-cp',cp,'org.trillionnium.hepta.background.'+klass]
  if stage=='postlaunch' and a.actual_lease:argv.append(str(a.actual_lease))
  commands.append((stage,argv))
 out={'schema':'hepta.profile-postlaunch-host-validation.v1','all_pass':False,'source_inputs':pins,'stages':[],'phone_contacted':False,'android_runtime':False,'clock_and_inventory_fixtures_synthetic':True}
 if a.actual_lease:out['actual_lease_sha256']=sha(a.actual_lease)
 for name,argv in commands:
  started=time.monotonic();r=subprocess.run(argv,capture_output=True,timeout=45)
  (o/(name+'.stdout')).write_bytes(r.stdout);(o/(name+'.stderr')).write_bytes(r.stderr)
  out['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_s':time.monotonic()-started,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()})
  if r.returncode:break
  if name!='compile':out[name]=json.loads(r.stdout)
 out['inputs_unchanged']=pins=={str(x.relative_to(s)):sha(x) for x in files}
 if a.actual_lease:out['actual_lease_unchanged']=out['actual_lease_sha256']==sha(a.actual_lease)
 out['all_pass']=len(out['stages'])==4 and all(x['exit_code']==0 for x in out['stages']) and out['inputs_unchanged'] and out.get('actual_lease_unchanged',True)
 (o/'RESULT.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps(out));return 0 if out['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
