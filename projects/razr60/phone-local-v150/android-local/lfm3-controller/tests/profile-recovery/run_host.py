#!/usr/bin/env python3
"""Bounded host-only checks of the actual prelaunch recovery policy and proc parser."""
import argparse, hashlib, json, subprocess, time
from pathlib import Path
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--source',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True)
    ap.add_argument('--json-jar',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--actual-lease',type=Path)
    ap.add_argument('--actual-stats',type=Path)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    if sha(a.json_jar)!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed': raise RuntimeError('JSON jar pin differs')
    bg=a.source/'src/org/trillionnium/hepta/background'
    names=['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','FixedIntentTools','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask','ProfilePermissionTransient','ProfileDisplayCustody','ProfilePrelaunchRecovery','ProfileRecoveryProcesses']
    files=[bg/(n+'.java') for n in names]+[Path(__file__).with_name('ProfileRecoveryHostTest.java')]
    pins={str(p.relative_to(a.source)):sha(p) for p in files}
    classes=a.output/'classes';classes.mkdir()
    commands=[('compile',[str(a.java_home/'bin/javac'),'--release','8','-Xlint:all,-options','-Werror','-encoding','UTF-8','-cp',str(a.json_jar),'-d',str(classes),*[str(p) for p in files]]),
              ('policy-proc',[str(a.java_home/'bin/java'),'-cp',str(classes)+':'+str(a.json_jar),'org.trillionnium.hepta.background.ProfileRecoveryHostTest'])]
    if a.actual_lease: commands[-1][1].append(str(a.actual_lease))
    if a.actual_stats:
        if not a.actual_lease: raise RuntimeError('actual stats requires explicit actual lease position')
        commands[-1][1].append(str(a.actual_stats))
    result={'schema':'hepta.profile-recovery-host-validation.v1','all_pass':False,'source_inputs':pins,'stages':[],'phone_contacted':False,'android_runtime':False,'framework_process_fixtures_synthetic':True}
    for name,argv in commands:
        start=time.monotonic();r=subprocess.run(argv,capture_output=True,timeout=45)
        (a.output/(name+'.stdout')).write_bytes(r.stdout);(a.output/(name+'.stderr')).write_bytes(r.stderr)
        result['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start})
        if r.returncode: break
    if len(result['stages'])==2 and all(x['exit_code']==0 for x in result['stages']):
        result['summary']=json.loads((a.output/'policy-proc.stdout').read_text())
        result['source_inputs_unchanged']=pins=={str(p.relative_to(a.source)):sha(p) for p in files}
        result['all_pass']=result['summary']['passed'] and result['source_inputs_unchanged']
    if a.actual_lease: result['private_actual_lease_sha256']=sha(a.actual_lease)
    if a.actual_stats: result['private_actual_stat_sha256']=sha(a.actual_stats)
    (a.output/'RESULT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False))
    return 0 if result['all_pass'] else 1
if __name__=='__main__': raise SystemExit(main())
