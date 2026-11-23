#!/usr/bin/env python3
"""Actual public recents policy and ownership coordinator; exact archived recents, no device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
ACTUAL={'before-recents.txt':'bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a',
        'after-recents.txt':'5755f3c99126d9f093272b7b73cce47a74049d5398110a1c8d97465e1952c4f3'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser()
    for name in ('source','java-home','json-jar','actual-recents','output'):ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--java8-syntax-only',action='store_true',help='Draft only; formal gate requires actual --release 8.')
    ap.add_argument('--retained-original-task',type=Path)
    ap.add_argument('--verified-retirement',type=Path)
    a=ap.parse_args();s=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if sha(a.json_jar)!=JSON_SHA:raise RuntimeError('actual org.json pin differs')
    if {n:sha(a.actual_recents/n) for n in ACTUAL}!=ACTUAL:raise RuntimeError('archived recents pins differ')
    if bool(a.retained_original_task)!=bool(a.verified_retirement):
        ap.error('supply both capture directories for the retained display replay')
    bg=s/'src/org/trillionnium/hepta/background'
    names=['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','FixedIntentTools',
           'BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask',
           'ProfilePermissionTransient','ProfileDisplayCustody','PublicOwnGroupPhysicalFence','PublicProfileRecentHistory']
    files=[bg/(n+'.java') for n in names]+[s/'tests/profile-broker/ProfileBrokerHostTest.java',Path(__file__).with_name('PublicProfileHistoryHostTest.java')]
    diagnostic=s/'tests/profile-broker/ProfileRootRefusalHostTest.java'
    tracked=files+[Path(__file__).resolve(),bg/'ProfileTaskPlatform.java',bg/'BackgroundDisplayBroker.java',diagnostic]
    replay=Path(__file__).with_name('RetainedActualHistoryHostTest.java')
    projection=Path(__file__).with_name('retained_4bd1_projection.py')
    if a.retained_original_task:
        files.append(replay)
        tracked.extend([replay,projection])
    pins={str(p):sha(p) for p in tracked};classes=out/'classes';classes.mkdir()
    cp=str(classes)+os.pathsep+str(a.json_jar.resolve());jdk=a.java_home.resolve()/'bin'
    diagnostic_classes=out/'root-diagnostic-classes';diagnostic_classes.mkdir()
    diagnostic_cp=str(diagnostic_classes)+os.pathsep+cp
    flags=['-source','8','-target','8'] if a.java8_syntax_only else ['--release','8']
    commands=[('compile',[str(jdk/'javac'),*flags,'-Xlint:all,-options','-Werror','-proc:none','-encoding','UTF-8','-cp',str(a.json_jar.resolve()),'-d',str(classes),*map(str,files)]),
              ('history',[str(jdk/'java'),'-cp',cp,'org.trillionnium.hepta.background.PublicProfileHistoryHostTest',str(a.actual_recents.resolve())]),
              ('legacy-private',[str(jdk/'java'),'-cp',cp,'org.trillionnium.hepta.background.ProfileBrokerHostTest']),
              ('root-diagnostic-compile',[str(jdk/'javac'),*flags,'-Xlint:all,-options','-Werror','-proc:none','-encoding','UTF-8','-cp',cp,'-d',str(diagnostic_classes),str(diagnostic)]),
              ('root-diagnostic',[str(jdk/'java'),'-cp',diagnostic_cp,'org.trillionnium.hepta.background.ProfileRootRefusalHostTest'])]
    if a.retained_original_task:
        evidence=out/'retained-originals.json'
        commands.extend([('retained-projection',[sys.executable,'-B',str(projection),str(a.retained_original_task.resolve()),str(a.verified_retirement.resolve()),str(evidence)]),
                         ('retained-history',[str(jdk/'java'),'-cp',cp,'org.trillionnium.hepta.background.RetainedActualHistoryHostTest',str(evidence)])])
    result={'schema':'hepta.public-profile-history-host-validation.v1','all_pass':False,'strict_release8':not a.java8_syntax_only,
            'source_inputs':pins,'actual_archived_recents_inputs':ACTUAL,'json_jar_sha256':JSON_SHA,
            'phone_contacted':False,'android_runtime':False,'framework_and_clock_fixtures_synthetic':True,'stages':[]}
    for name,argv in commands:
        started=time.monotonic();run=subprocess.run(argv,capture_output=True,timeout=60)
        (out/(name+'.stdout')).write_bytes(run.stdout);(out/(name+'.stderr')).write_bytes(run.stderr)
        result['stages'].append({'stage':name,'argv':argv,'exit_code':run.returncode,'elapsed_seconds':time.monotonic()-started,
            'stdout_sha256':hashlib.sha256(run.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(run.stderr).hexdigest()})
        if run.returncode:break
        if name not in ('compile','root-diagnostic-compile','retained-projection'):result[name]=json.loads(run.stdout.decode('utf-8').splitlines()[0])
    result['inputs_unchanged']=pins=={str(p):sha(p) for p in tracked}
    result['archived_recents_unchanged']=ACTUAL=={n:sha(a.actual_recents/n) for n in ACTUAL}
    result['all_pass']=len(result['stages'])==len(commands) and all(x['exit_code']==0 for x in result['stages']) and result['inputs_unchanged'] and result['archived_recents_unchanged']
    (out/'RESULT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_pass':result['all_pass'],'strict_release8':result['strict_release8'],'result':str(out/'RESULT.json'),
                      'history':result.get('history'),'legacy_private':result.get('legacy-private'),
                      'root_diagnostic':result.get('root-diagnostic')},ensure_ascii=False))
    return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
