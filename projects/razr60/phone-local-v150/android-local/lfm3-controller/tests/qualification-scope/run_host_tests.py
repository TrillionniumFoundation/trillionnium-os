#!/usr/bin/env python3
"""Bounded host-only production dispatch/config/controller qualification-scope tests."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2]);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--release8',action='store_true',help='Require Java 8 API release gate; never fall back')
    args=parser.parse_args();source=args.source.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('scope_fixture',Path(__file__).with_name('prepare_fixture.py'));fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    files,extraction=fixture.prepare(source,out/'fixture');classes=out/'classes';classes.mkdir()
    compiler=[shutil.which('javac')] if shutil.which('javac') else ['java','-m','jdk.compiler/com.sun.tools.javac.Main']
    # Match the locally available stripped JDK capability explicitly; full release/API
    # checking remains a separate v32/JDK17 Android build gate, never silently weakened.
    compile_args=compiler+(['--release','8'] if args.release8 else ['-source','8','-target','8'])+['-encoding','UTF-8','-Xlint:all,-options','-Werror','-d',str(classes),*map(str,files)]
    records=[]
    for name,command in [('compile',compile_args),('production-tests',['java','-cp',str(classes),'org.trillionnium.hepta.local.QualificationScopeHostTest',str(out/'cases')])]:
        start=time.monotonic();result=subprocess.run(command,text=True,capture_output=True,timeout=90)
        (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
        records.append({'name':name,'exit_code':result.returncode,'elapsed_seconds':time.monotonic()-start})
        if result.returncode:
            (out/'VALIDATION.json').write_text(json.dumps({'status':'failed','stages':records,'scope':'host only'},indent=2)+'\n');print(result.stdout[-3000:]);print(result.stderr[-9000:]);return result.returncode
    result=json.loads((out/'cases/RESULT.json').read_text())
    validation={'schema':'hepta.scope-host-validation.v1','status':'passed','stages':records,'java_tests_passed':result['passed'],
        'compiler_contract':'Java 8 API release, syntax and class target' if args.release8 else 'Java 8 syntax and class target; this stripped JDK does not provide a Java 8 API --release gate',
        'phone_operations':False,'native_inference':False,'android_runtime':False,'source_identity':extraction['source_files'],
        'extraction_sha256':hashlib.sha256((out/'fixture/EXTRACTION.json').read_bytes()).hexdigest()}
    (out/'VALIDATION.json').write_text(json.dumps(validation,indent=2)+'\n');print(json.dumps(validation,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
