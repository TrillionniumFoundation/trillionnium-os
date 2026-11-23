#!/usr/bin/env python3
"""Actual installed-identity evidence; existing controlled Android compilation fixture."""
import argparse, hashlib, importlib.util, json, subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--java-home',type=Path,required=True)
    p.add_argument('--baseline-file',type=Path)
    p.add_argument('--expect-null-dereference',action='store_true')
    a=p.parse_args();source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    assert bool(a.baseline_file)==a.expect_null_dereference
    spec=importlib.util.spec_from_file_location('profile_installed_fixture',source/'tests/qualification-scope/prepare_fixture.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    files,extraction=m.prepare(source,out/'fixture')
    actual=[x for x in files if x.name=='QualificationScopeConfig.java'];assert len(actual)==1
    if a.baseline_file:files=[a.baseline_file.resolve() if f==actual[0] else f for f in files]
    files.append(Path(__file__).with_name('ProfileInstalledEvidenceHostTest.java'))
    pins={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    classes=out/'classes';classes.mkdir();stages=[]
    commands=[('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-d',classes,*files]),
              ('evidence',[a.java_home/'bin/java','-cp',classes,'org.trillionnium.hepta.local.ProfileInstalledEvidenceHostTest'])]
    good=False
    for name,argv in commands:
        r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        stages.append({'name':name,'exit_code':r.returncode})
        if name=='compile' and r.returncode:break
        if name=='evidence':
            if a.expect_null_dereference:
                good=(r.returncode!=0 and b'NullPointerException' in r.stderr and b'CompletionInstalledIdentity.evidence' in r.stderr)
            else:good=r.returncode==0 and json.loads(r.stdout)['assertions']==5
    assert pins=={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    result={'schema':'hepta.profile-installed-evidence-host.v1','all_pass':good,'expected_baseline_null_dereference':a.expect_null_dereference,
            'stages':stages,'source_inputs':pins,'actual_constructor_and_evidence':True,'phone_actions':0,'package_manager_called':False,
            'fixture_extraction_sha256':hashlib.sha256((out/'fixture/EXTRACTION.json').read_bytes()).hexdigest()}
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'all_pass':good,'stages':stages,'expected_baseline_null_dereference':a.expect_null_dereference}))
    return 0 if good else 1

if __name__=='__main__':raise SystemExit(main())
