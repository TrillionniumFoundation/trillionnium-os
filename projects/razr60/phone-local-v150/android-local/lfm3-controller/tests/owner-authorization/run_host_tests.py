#!/usr/bin/env python3
"""Independent actual Owner authorization wiring tests; all Android/model IO is fake.

Run only the new test main. The existing scope fixture supplies production extraction
and shared Android IO fakes; its old 87 cases are not rerun by this entry.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import types


def digest(path):
    raw=Path(path).read_bytes()
    return {'path':str(Path(path).resolve()),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',help='Run only one exact named independent case')
    parser.add_argument('--release8',action='store_true',help='Require Java 8 API release gate, without fallback')
    args=parser.parse_args()
    source=args.source.resolve();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    helper=source/'tests/qualification-scope/prepare_fixture.py'
    helper_raw=helper.read_bytes();helper_identity=digest(helper)
    module=types.ModuleType('owner_authorization_actual_scope_fixture')
    module.__file__=str(helper)
    # Execute the already-read source bytes, never an import cache.
    exec(compile(helper_raw,str(helper),'exec'),module.__dict__)
    files,extraction=module.prepare(source,output/'fixture')
    original_test=Path(__file__).with_name('OwnerAuthorizationWiringHostTest.java')
    test_raw=original_test.read_bytes();test_copy=output/original_test.name;test_copy.write_bytes(test_raw)
    files=[*files,test_copy]
    source_inputs=[digest(path) for path in files]
    classes=output/'classes';classes.mkdir()
    compiler=[shutil.which('javac')] if shutil.which('javac') else ['java','-m','jdk.compiler/com.sun.tools.javac.Main']
    flags=['--release','8'] if args.release8 else ['-source','8','-target','8']
    lint='-Xlint:all' if args.release8 else '-Xlint:all,-options'
    command=compiler+flags+['-encoding','UTF-8',lint,'-Werror','-d',str(classes),*map(str,files)]
    stages=[]
    validation={'schema':'hepta.owner-auth-independent-wiring-validation.v1','status':'not_run',
        'compiler_contract':'Java 8 API release, syntax and class target' if args.release8 else 'Java 8 syntax and class target on available JDK; not Java 8 API release or Android build proof',
        'source_identity':extraction['source_files'],'fixture_helper':helper_identity,
        'compiled_inputs':source_inputs,'test_source_sha256':hashlib.sha256(test_raw).hexdigest(),
        'recreated_independent_test_source':True,'prior_parser_results_reexecuted':False,
        'phone_operations':False,'native_inference':False,'android_runtime':False,'stages':stages}
    for name,argv in [('compile',command),('owner-wiring-tests',['java','-cp',str(classes),'org.trillionnium.hepta.local.OwnerAuthorizationWiringHostTest',str(output/'cases')]+([args.case] if args.case else []))]:
        start=time.monotonic()
        run=subprocess.run(argv,capture_output=True,text=True,timeout=90)
        stdout=output/(name+'.stdout');stderr=output/(name+'.stderr')
        stdout.write_text(run.stdout);stderr.write_text(run.stderr)
        stages.append({'name':name,'argv':argv,'exit_code':run.returncode,'elapsed_seconds':time.monotonic()-start,
            'stdout_sha256':digest(stdout)['sha256'],'stderr_sha256':digest(stderr)['sha256']})
        if run.returncode:
            validation['status']='failed'
            if (output/'cases/RESULT.json').is_file():
                actual=json.loads((output/'cases/RESULT.json').read_text());validation['java_tests_passed']=actual['passed'];validation['java_tests_failed']=actual['failed']
            (output/'VALIDATION.json').write_text(json.dumps(validation,ensure_ascii=False,indent=2)+'\n')
            print(run.stdout[-6000:]);print(run.stderr[-8000:]);return run.returncode
    actual=json.loads((output/'cases/RESULT.json').read_text())
    if helper.read_bytes()!=helper_raw or original_test.read_bytes()!=test_raw:
        raise RuntimeError('helper or test source changed during execution')
    for before in source_inputs:
        if digest(before['path'])!=before:raise RuntimeError('compiled source changed during execution: '+before['path'])
    validation.update(status='passed',java_tests_passed=actual['passed'],java_tests_failed=actual['failed'],source_inputs_unchanged=True,
        extraction_sha256=digest(output/'fixture/EXTRACTION.json')['sha256'],result_sha256=digest(output/'cases/RESULT.json')['sha256'])
    (output/'VALIDATION.json').write_text(json.dumps(validation,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({key:validation[key] for key in ['status','java_tests_passed','java_tests_failed','compiler_contract','result_sha256']},indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())
