#!/usr/bin/env python3
"""Actual target parser and full BackgroundSession.Selection with explicit, unused Android IO fakes."""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('actual_background_selection_fixture',Path(__file__).with_name('prepare_fixture.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    files,extraction=m.prepare(source,out/'fixture')
    pkg=source/'src/org/trillionnium/hepta/local'
    files += [pkg/'BackgroundTaskTarget.java',pkg/'NotesOwnerIntent.java',pkg/'web/WebFlightGoal.java',pkg/'web/WebShoppingGoal.java',
              Path(__file__).with_name('BackgroundTaskTargetHostTest.java')]
    files=list(dict.fromkeys(files));classes=out/'classes';classes.mkdir()
    before={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    compiler=shutil.which('javac');java=shutil.which('java')
    if not compiler or not java:raise RuntimeError('existing JDK required')
    stages=[]
    commands=[('compile',[compiler,'--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-d',str(classes),*map(str,files)]),
              ('target-selection',[java,'-cp',str(classes),'org.trillionnium.hepta.local.BackgroundTaskTargetHostTest',str(out/'CASES.json')])]
    env=dict(os.environ)
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    for name,argv in commands:
        started=time.monotonic();r=subprocess.run(argv,cwd=out,env=env,capture_output=True,timeout=90)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        stages.append({'name':name,'argv':argv,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-started})
        if r.returncode:
            (out/'RESULT.json').write_text(json.dumps({'all_pass':False,'stages':stages},indent=2)+'\n')
            print(r.stderr.decode('utf-8',errors='replace')[-12000:]);return r.returncode
    after={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    if before!=after:raise RuntimeError('actual source changed during target checks')
    cases=json.loads((out/'CASES.json').read_text())
    if cases['all_pass'] is not True or cases['cases']<20 or cases['phone_actions']!=0:raise RuntimeError('target cases not complete')
    result={'schema':'hepta.background-owner-target-host-validation.v1','all_pass':True,'cases':cases,
            'compiler_contract':'Java8 API release','source_inputs':before,'source_inputs_unchanged':True,
            'stages':stages,'fixture':extraction,'android_runtime':False,'phone_actions':0,'preferences_written':False}
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'all_pass':True,'cases':cases['cases'],'assertions':cases['assertions']}));return 0
if __name__=='__main__':raise SystemExit(main())
