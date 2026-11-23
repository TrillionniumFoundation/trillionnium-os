#!/usr/bin/env python3
"""Full production BackgroundSession/client; owned process and Android IO are explicit fakes."""
import argparse,hashlib,importlib.util,json,subprocess,time,os
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for n in ('source','java-home','json-jar','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();s=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 assert sha(a.json_jar)=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
 sp=importlib.util.spec_from_file_location('bg_fixture',s/'tests/background-session/prepare_fixture.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
 f=out/'fixture';files,record=m.prepare(s,f);files=[v for v in files if '/org/json/' not in str(v)]
 # Real pinned org.json is used; only Android boundary fixtures are adapted.
 v=f/'android/provider/Settings.java';t=v.read_text()
 assert t.count('public static int getInt(Object resolver,String key,int fallback){return boot;}')==1
 v=f/'android/os/Looper.java';t=v.read_text();old='public static Looper myLooper(){return L;}';assert t.count(old)==1
 v.write_text(t.replace(old,'public static boolean worker;public static Looper myLooper(){return worker?null:L;}'))
 (f/'android/os/Process.java').write_text('package android.os;public final class Process {private Process(){}public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n')
 v=f/'android/system/Os.java';t=v.read_text();old='r.st_uid=((Number)a.get("uid")).intValue();';assert t.count(old)==1
 v.write_text(t.replace(old,old+f'if(r.st_uid=={os.getuid()})r.st_uid=10481;'))
 t=v.read_text();old='public static String failFsyncPath;';assert t.count(old)==1
 t=t.replace(old,old+'public static boolean corruptRecoveryArchiveOnSync;')
 old='if(fd.valid())fd.sync();';assert t.count(old)==1
 t=t.replace(old,old+'if(corruptRecoveryArchiveOnSync&&path.endsWith(".journal.json")){corruptRecoveryArchiveOnSync=false;Files.write(Paths.get(path),new byte[]{1});}')
 v.write_text(t)
 client=s/'src/org/trillionnium/hepta/local/ProfileRecoveryClient.java';raw=client.read_text()
 seam='new ProcessBuilder("su","-c",command).redirectErrorStream(true).start()';assert raw.count(seam)==1
 projected=f/'org/trillionnium/hepta/local/ProfileRecoveryClient.java';projected.write_text(raw.replace(seam,'FakeRecoveryProcess.start(command)'));files.append(projected)
 bg=s/'src/org/trillionnium/hepta/background'
 files += [bg/(n+'.java') for n in ['BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfilePrelaunchRecovery','ProfileRecoveryProcesses']]
 files += [s/'tests/background-session'/n for n in ['BackgroundSessionHostTest.java','ProfileSessionHostTest.java']]
 files += [s/'tests/profile-recovery'/n for n in ['ProfileRecoveryHostTest.java','ProfileRecoverySessionHostTest.java','FakeRecoveryProcess.java','RecoveryProofFixture.java']]
 files=list(dict.fromkeys(files));classes=out/'classes';classes.mkdir()
 pins={str(v.relative_to(s)) if s in v.parents else 'fixture/'+str(v.relative_to(f)):sha(v) for v in files};cp=str(classes)+':'+str(a.json_jar)
 commands=[('compile',[str(a.java_home/'bin/javac'),'--release','8','-encoding','UTF-8','-Xlint:all,-options','-Werror','-proc:none','-cp',str(a.json_jar),'-d',str(classes),*[str(v) for v in files]]),
 ('legacy-profile',[str(a.java_home/'bin/java'),'-cp',cp,'org.trillionnium.hepta.local.ProfileSessionHostTest',str(out/'LEGACY-CASES.json')]),
 ('recovery-client',[str(a.java_home/'bin/java'),'-cp',cp,'org.trillionnium.hepta.local.ProfileRecoverySessionHostTest'])]
 result={'schema':'hepta.profile-recovery-client-host-validation.v1','all_pass':False,'stages':[],'source_inputs':pins,'production_client_sha256':sha(client),
 'projection_single_owned_process_factory_replacement':True,'android_controller_uid_mapping':{'host_uid':os.getuid(),'fixture_uid':10481},
 'phone_contacted':False,'android_runtime':False,'root_process_started':False,'directory_fsync_surrogate':True}
 for name,argv in commands:
  start=time.monotonic();r=subprocess.run(argv,capture_output=True,timeout=50,cwd=out)
  (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
  result['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start})
  if r.returncode:break
 if len(result['stages'])==3 and all(v['exit_code']==0 for v in result['stages']):
  result['legacy']=json.loads((out/'LEGACY-CASES.json').read_text());result['recovery']=json.loads((out/'recovery-client.stdout').read_text())
  result['all_pass']=result['legacy']['all_pass'] and result['recovery']['passed']
 result['production_inputs_unchanged']=all(sha(v)==pins[str(v.relative_to(s))] for v in files if s in v.parents) and sha(client)==result['production_client_sha256']
 result['all_pass']=result['all_pass'] and result['production_inputs_unchanged']
 (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'all_pass':result['all_pass'],'stages':result['stages'],'legacy':result.get('legacy'),'recovery':result.get('recovery')}))
 return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
