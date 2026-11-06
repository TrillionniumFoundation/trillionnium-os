#!/usr/bin/env python3
"""Reproduce the selected unbound source and controls in an isolated host tree."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def read(path,expected=None):
    raw=path.read_bytes()
    if expected is not None:
        assert pin(raw)=={key:expected[key] for key in ('bytes','sha256')},str(path)
    return raw


def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(raw)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime',type=Path,default=HERE.parent/'R5-root/runtime')
    args=parser.parse_args()
    expected=json.loads(read(HERE/'DERIVATION.json'))
    runtime_raw=read(args.runtime/'MANIFEST.json',expected['observed_runtime_source_candidate'])
    assert runtime_raw==read(HERE/'references/runtime-MANIFEST.candidate.json')
    runtime=json.loads(runtime_raw)
    old_result=read(HERE/'validation/RESULT.json')
    with tempfile.TemporaryDirectory(prefix='consumer-r5-source-repro-') as directory:
        review=Path(directory)/'review';target=review/'R5-release-consumer'
        for name in ('derive_consumer_candidate.py','current_prefix_replacement.py',
                     'run_consumer_source_controls.py','references/release_boundaries.original.py'):
            write(target/name,read(HERE/name))
        write(review/'R5-root/runtime/MANIFEST.json',runtime_raw)
        for row in runtime['files']:
            assert str(Path(row['path']))==row['path'] and '..' not in Path(row['path']).parts
            assert not Path(row['path']).is_absolute()
            write(review/'R5-root/runtime'/row['path'],read(args.runtime/row['path'],row))
        for source,destination in (
            ('references/shared-v3-original-transfer.json','shared-v3-original-transfer.json'),
            ('references/SOURCE-PARENT-RECORDS.actual.json','R5-agent-late/SOURCE-PARENT-RECORDS.json'),
            ('references/NEG01-BOUNDARY.actual.json','R5-agent-late/history-inputs/NEG01-BOUNDARY.original.json')):
            write(review/destination,read(HERE/source))
        runs=[]
        for name in ('derive_consumer_candidate.py','run_consumer_source_controls.py'):
            result=subprocess.run([sys.executable,'-I','-B',str(target/name)],
                                  capture_output=True,check=False,timeout=30)
            assert result.returncode==0,(name,result.returncode,result.stderr.decode())
            assert result.stderr==b'',(name,result.stderr.decode())
            runs.append({'script':name,'exit_code':result.returncode,
                         'stdout':result.stdout.decode(),'stderr':result.stderr.decode()})
        assert read(target/'source/release_boundaries.py')==read(HERE/'source/release_boundaries.py')
        assert read(target/'validation/RESULT.json')==old_result
        report={'schema':'hepta.fc33.release-consumer-isolated-reproduction.v1',
            'source':pin(read(target/'source/release_boundaries.py')),'result':pin(old_result),
            'controls':json.loads(old_result)['count'],'same_source_and_result_bytes':True,
            'actual_BUILD':False,'actual_install':False,'actual_READY':False,'phone_calls':0,
            'runs':runs}
    print(json.dumps(report,sort_keys=True,indent=2))


if __name__=='__main__':main()
