#!/usr/bin/env python3
"""Run real C++17 hash and file-binding contracts, without model or phone access."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True,type=Path);args=parser.parse_args()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    cxx=shutil.which('g++') or shutil.which('clang++')
    if not cxx:raise RuntimeError('Existing C++17 compiler required')
    def sources():
        return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ('native','tests','evidence') for p in sorted((ROOT/folder).rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts}
    original=sources()
    report={'schema':'hepta.mobimind.r4-host-checks.v1','all_pass':False,'scope':'host_only',
        'android_executed':False,'phone_tested':False,'model_inference_performed':False,'checks':[],
        'source_inputs':original}
    def run(name,argv,timeout=120):
        p=subprocess.run(list(map(str,argv)),cwd=ROOT,capture_output=True,timeout=timeout)
        (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
        report['checks'].append({'name':name,'argv':list(map(str,argv)),'exit_code':p.returncode,
            'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()})
        if p.returncode:raise RuntimeError(name+': '+p.stderr.decode('utf-8','replace')[-3000:])
        return p
    try:
        common=[cxx,'-std=c++17','-Wall','-Wextra','-Wpedantic','-Werror','-O2','-I',ROOT/'native']
        run('util-compile',common+[ROOT/'tests/util_contract.cpp','-o',out/'util-contract'])
        run('util-contract',[out/'util-contract'])
        run('sha-compile',common+[ROOT/'tests/sha_probe.cpp','-o',out/'sha-probe'])
        self_test=run('sha-self-test',[out/'sha-probe','--self-test'])
        summary=json.loads(self_test.stdout)
        report['host_runtime_hwcap_sha2']=summary['runtime_hwcap_sha2']
        report['host_hardware_blocks_observed']=summary['hardware_blocks_observed']
        run('sha-hashlib-differential',[sys.executable,ROOT/'tests/check_sha_equivalence.py','--probe',out/'sha-probe'])
        run('pinned-runtime-patch-contracts',[sys.executable,'-m','unittest','discover','-s',ROOT/'tests','-p','test_*.py','-v'])
        if sources()!=original:raise RuntimeError('Host source changed during checks')
        report['all_pass']=True
    except Exception as error:
        report['error']=str(error)
    finally:
        (out/'HOST-CHECKS.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report.get(k) for k in ('all_pass','scope','android_executed','phone_tested','host_runtime_hwcap_sha2','error')}))
    return 0 if report['all_pass'] else 1

if __name__=='__main__':sys.exit(main())
