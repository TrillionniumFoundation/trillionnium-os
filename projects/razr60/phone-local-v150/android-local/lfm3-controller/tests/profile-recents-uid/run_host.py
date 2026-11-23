#!/usr/bin/env python3
"""Run existing profile coordinator and UID parser regressions; no device calls."""
import argparse, hashlib, json, subprocess
from pathlib import Path

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source',type=Path,required=True)
    ap.add_argument('--candidate-policy',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True)
    ap.add_argument('--actual-recents',type=Path)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    src=a.source.resolve()/'src/org/trillionnium/hepta/background'
    existing=a.source.resolve()/'tests/profile-broker/ProfileBrokerHostTest.java'
    test=Path(__file__).with_name('ProfileRecentUidHostTest.java')
    names=['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','FixedIntentTools',
           'BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask','ProfilePermissionTransient','ProfileDisplayCustody']
    before={str(p):sha(p) for p in [src/(n+'.java') for n in names]+[existing,test,a.candidate_policy]}
    actual_sha=sha(a.actual_recents) if a.actual_recents else None
    result={'schema':'hepta.profile-recent-uid-regression.v1','phone_contacted':False,
            'android_build_performed':False,'actual_recents_sha256':actual_sha,
            'baseline_policy_sha256':sha(src/'ProfileTaskPolicy.java'),
            'candidate_policy_sha256':sha(a.candidate_policy),'test_sha256':sha(test),
            'runner_sha256':sha(Path(__file__)),'steps':[]}
    def run(name,cmd):
        r=subprocess.run([str(x) for x in cmd],capture_output=True,text=True,timeout=60)
        (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
        row={'name':name,'exit':r.returncode,'stdout_sha256':sha(out/(name+'.stdout')),
             'stderr_sha256':sha(out/(name+'.stderr'))}
        if r.returncode==0 and r.stdout.strip().startswith('{'):
            row['summary']=json.loads(r.stdout.splitlines()[0])
        result['steps'].append(row)
        return r
    passed=False
    try:
        classes={}
        for label,policy in [('baseline',src/'ProfileTaskPolicy.java'),('candidate',a.candidate_policy)]:
            dest=out/label;dest.mkdir()
            inputs=[policy if n=='ProfileTaskPolicy' else src/(n+'.java') for n in names]+[existing,test]
            r=run(label+'-compile',[a.java_home/'bin/javac','-J-XX:ActiveProcessorCount=2','-J-Xmx512m',
                '-encoding','UTF-8','--release','8','-d',dest]+inputs)
            if r.returncode:raise RuntimeError(label+' compilation failed')
            classes[label]=dest
        r=run('existing-profile-coordinator',[a.java_home/'bin/java','-cp',classes['candidate'],
            'org.trillionnium.hepta.background.ProfileBrokerHostTest'])
        if r.returncode:raise RuntimeError('existing profile gate failed')
        r=run('uid-synthetic',[a.java_home/'bin/java','-cp',classes['candidate'],
            'org.trillionnium.hepta.background.ProfileRecentUidHostTest'])
        if r.returncode:raise RuntimeError('UID synthetic gate failed')
        if a.actual_recents:
            r=run('actual-baseline-red',[a.java_home/'bin/java','-cp',classes['baseline'],
                'org.trillionnium.hepta.background.ProfileRecentUidHostTest','actual',a.actual_recents])
            result['baseline_actual_expected_red']=(r.returncode!=0 and 'PROFILE_RECENT_USER_UNKNOWN' in r.stderr)
            if not result['baseline_actual_expected_red']:raise RuntimeError('actual baseline did not reproduce precise failure')
            r=run('actual-candidate-green',[a.java_home/'bin/java','-cp',classes['candidate'],
                'org.trillionnium.hepta.background.ProfileRecentUidHostTest','actual',a.actual_recents])
            if r.returncode:raise RuntimeError('actual candidate replay failed')
        passed=True
    except Exception as error:
        result['error']=str(error)
    result['inputs_unchanged']=all(sha(Path(p))==digest for p,digest in before.items())
    result['actual_original_unchanged']=(a.actual_recents is None or sha(a.actual_recents)==actual_sha)
    result['passed']=passed and result['inputs_unchanged'] and result['actual_original_unchanged']
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1

if __name__=='__main__':
    raise SystemExit(main())
