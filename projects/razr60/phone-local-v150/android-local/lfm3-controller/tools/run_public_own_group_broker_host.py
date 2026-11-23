#!/usr/bin/env python3
"""Actual pure broker policy/state/parser tests; inert ports, no phone/Android claim."""
import argparse,hashlib,json,pathlib,shutil,subprocess

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=pathlib.Path);parser.add_argument('--output',type=pathlib.Path,required=True);parser.add_argument('--java-home',type=pathlib.Path);parser.add_argument('--release8',action='store_true');args=parser.parse_args()
    root=pathlib.Path(__file__).resolve().parent;candidate=(args.source or root.parent).resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    bg=candidate/'src/org/trillionnium/hepta/background'
    names=['BrokerProtocol','PublicPermissionControllerUi','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','BackgroundOwnedTaskPolicy',
           'BackgroundOwnedSingleTask','ProfileTaskPolicy','PublicOwnGroupPolicy',
           'PublicOwnGroupSurfaceRetirement','PublicOwnGroupTaskFence','PublicOwnGroupPhysicalFence','PublicPersonalNotesCustody']
    tests=['PublicSurfaceRetirementHostTest','PublicTaskFenceHostTest','PublicPhysicalAuditHostTest','PersonalNotesCustodyHostTest']
    files=[bg/(name+'.java') for name in names]+[candidate/'tests/public-own-group-policy'/(name+'.java') for name in tests]
    pins={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    classes=out/'classes';classes.mkdir()
    if args.java_home:
        java_cmd=str(args.java_home.resolve()/'bin/java');javac=str(args.java_home.resolve()/'bin/javac')
        if not pathlib.Path(java_cmd).is_file() or not pathlib.Path(javac).is_file():raise SystemExit('Specified Java home must provide both java and javac')
        compiler=[javac]
    else:
        java_cmd=shutil.which('java') or 'java';compiler=[shutil.which('javac')] if shutil.which('javac') else [java_cmd,'-m','jdk.compiler/com.sun.tools.javac.Main']
    flags=['--release','8','-Xlint:all'] if args.release8 else ['-source','8','-target','8','-Xlint:all,-options']
    commands=[('compile',compiler+flags+['-Werror','-encoding','UTF-8','-d',str(classes),*map(str,files)])]
    commands += [(name,[java_cmd,'-cp',str(classes),'org.trillionnium.hepta.background.'+name]) for name in tests]
    report={'schema':'hepta.public-own-group.broker-policy-host.v1','status':'NOT_DEPLOYED','phone_contacted':False,
            'android_binder_surface_or_task_api_executed':False,'production_pure_classes_tested':True,
            'compiler_contract':'Java8 API release' if args.release8 else 'supplemental Java8 syntax/class target; Mac API compile required',
            'source_sha256':pins,'stages':[],'old_legacy_sources_modified':False}
    for name,argv in commands:
        run=subprocess.run(argv,capture_output=True,text=True,timeout=30)
        (out/(name+'.stdout')).write_text(run.stdout);(out/(name+'.stderr')).write_text(run.stderr)
        stage={'name':name,'exit_code':run.returncode};report['stages'].append(stage)
        if name!='compile' and run.returncode==0:stage['result']=json.loads(run.stdout.strip().splitlines()[-1])
        print(name,run.returncode,run.stdout[-500:].strip())
        if run.returncode:print(run.stderr[-8000:]);break
    report['source_unchanged']=all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==sha for p,sha in pins.items())
    report['passed']=len(report['stages'])==len(commands) and all(s['exit_code']==0 for s in report['stages']) and report['source_unchanged']
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'output':str(out)}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
