#!/usr/bin/env python3
"""Bind the actual macOS UI-Venus source rebuild to this workflow; verify on Linux."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, platform
from pathlib import Path

APP_SHA='1873ca6ecf998b7f3d3e447de2c9af5004c53c870042e2faef28be94265b40f4'
HELPER_SHA='2832f6db1133e5e462819e055e65fd88c6f5943df8570623b4c4021b71fbfd28'
CURRENT='CURRENT-CI-SOURCE.json'
NEW_REPORT='NEW-BUILD-RECEIPT.json'
COMPILER='COMPILER-IDENTITY.json'

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def require(value,message):
    if value is not True:raise ValueError(message)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('bind','verify'))
    parser.add_argument('--app-source',type=Path,required=True)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--source-head',required=True)
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--run-attempt',required=True)
    parser.add_argument('--compiler-identity',type=Path)
    args=parser.parse_args()
    helper_path=Path(__file__).with_name('rebuild_exact_runtime.py')
    require(hashlib.sha256(helper_path.read_bytes()).hexdigest()==HELPER_SHA,'UI-Venus rebuild helper changed')
    helper=load(helper_path,'ui_venus_exact_rebuild')
    _,shared=helper.dependencies()
    expected=shared.source_identity(args.source_head,args.run_id,args.run_attempt)
    app=helper.verify_frozen_source(args.app_source)
    require(helper.APP_SHA==APP_SHA,'public source pin differs')
    bundle=args.bundle.resolve(strict=True);runtime=bundle/'runtime'
    require(not runtime.is_symlink() and runtime.is_dir(),'real runtime directory required')
    original=helper.runtime_api(app).verify_ui_venus_runtime(app,runtime)
    require({p.name for p in runtime.iterdir()}=={helper.WORKER,'BUILD-RECEIPT.json'},'unexpected UI-Venus runtime member')
    report_bytes=shared.read(bundle/NEW_REPORT);report=shared.obj(report_bytes)
    helper.check_report(report,app)
    if args.operation=='bind':
        require(args.compiler_identity is not None,'producer actual compiler identity required')
        compiler_bytes=shared.read(args.compiler_identity)
    else:
        require(args.compiler_identity is None,'consumer must use bound compiler identity')
        compiler_bytes=shared.read(bundle/COMPILER)
    compiler=shared.obj(compiler_bytes);shared.check_compiler(report,compiler)
    binding={'schema':'hepta.ci.ui-venus-mac-runtime-transfer.v1',**expected,
      'app_source_manifest_sha256':APP_SHA,'rebuild_helper_sha256':HELPER_SHA,
      'new_build_receipt_sha256':hashlib.sha256(report_bytes).hexdigest(),
      'compiler_identity_sha256':hashlib.sha256(compiler_bytes).hexdigest(),
      'actual_compiler_container_sha256':compiler['macho']['sha256'],
      'runtime_build_host':'macOS','runtime_build_host_tag':'darwin-x86_64','runtime_compiled_on_linux':False,
      'original_worker_bytes':helper.WORKER_BYTES,'original_worker_sha256':helper.WORKER_SHA,
      'original_build_receipt_sha256':helper.ORIGINAL_RECEIPT_SHA,
      'original_payload_fully_verified':True,'compiler_bytes_outside_signatures_identical':True}
    if args.operation=='bind':
        require(platform.system()=='Darwin','producer binding must run on actual macOS build host')
        for name,data in ((COMPILER,compiler_bytes),(CURRENT,(json.dumps(binding,indent=2)+'\n').encode())):
            with (bundle/name).open('xb') as stream:
                os.chmod(bundle/name,0o600);stream.write(data);stream.flush();os.fsync(stream.fileno())
    else:
        require(platform.system()=='Linux','consumer qualification must run on Linux')
        current=shared.obj(shared.read(bundle/CURRENT))
        require(type(current) is dict and json.dumps(current,sort_keys=True)==json.dumps(binding,sort_keys=True),
                'UI-Venus artifact belongs to another source/run/attempt/build')
        require({p.name for p in bundle.iterdir()}=={'runtime',CURRENT,NEW_REPORT,COMPILER},'unexpected transfer member')
    print(json.dumps({**binding,'operation':args.operation,'verifier_host':platform.system(),
                      'original_assembler_allowed':True,'runtime_directory':str(runtime)}))
    return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'state':'rejected','original_assembler_allowed':False,'error':type(error).__name__+': '+str(error)}))
        raise SystemExit(2)
