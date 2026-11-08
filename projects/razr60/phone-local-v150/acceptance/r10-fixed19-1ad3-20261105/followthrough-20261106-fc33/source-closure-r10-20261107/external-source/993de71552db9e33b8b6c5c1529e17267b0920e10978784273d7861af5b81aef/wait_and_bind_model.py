#!/usr/bin/env python3
"""Read-only startup observation followed by one actual-model binding operation.

The service creates a new boot directory and copies its original model claim
once. This helper never starts a model, submits an inference or retries work.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent/'source'))
from model_slot_cleanup import get_json, private_bytes, require, verify_identity
from phone_local_http_worker import strict_json

BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')


def put(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    require(len(raw)<=16*1024*1024,'startup observation record exceeds bound')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    require(private_bytes(path,16*1024*1024)==raw,'startup record readback differs')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--config-sha256',required=True)
    parser.add_argument('--server-sha256',required=True)
    parser.add_argument('--model-claim-sha256',required=True)
    parser.add_argument('--runtime-dir',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    require(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'root owner required')
    for value in (args.config_sha256,args.server_sha256,args.model_claim_sha256):
        require(re.fullmatch('[0-9a-f]{64}',value) is not None,'exact input digest required')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot),'boot format')
    runtime=args.runtime_dir
    require(runtime==BASE/'model-runtime-r10-r1'/boot and runtime.resolve(strict=True)==runtime,
            'canonical boot runtime directory required')
    for path in (runtime,runtime/'bindings',runtime/'receipts'):
        info=path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
                stat.S_IMODE(info.st_mode)==0o700,'private runtime directory metadata differs')
    require(not list((runtime/'bindings').iterdir()),'new startup bindings directory not empty')
    require(not (runtime/'STARTUP-INTENT.json').exists(),'startup operation already consumed')
    config_raw=private_bytes(args.config)
    require(hashlib.sha256(config_raw).hexdigest()==args.config_sha256,'configuration changed')
    config=strict_json(config_raw)
    claim=runtime/'model.identity';claim_raw=private_bytes(claim,128)
    require(hashlib.sha256(claim_raw).hexdigest()==args.model_claim_sha256,'original model claim copy differs')
    claim_text=claim_raw.decode('ascii').strip()
    require(re.fullmatch('[1-9][0-9]*(?::[1-9][0-9]*){3}',claim_text),'model claim format')
    pid,pgid,sid,start_ticks=map(int,claim_text.split(':'))
    require(pid==pgid==sid,'owned model session required')
    identity=dict(schema='hepta.llama-server-identity.v1',boot_id=boot,pid=pid,
                  pgid=pgid,sid=sid,start_ticks=start_ticks)
    binding=dict(schema='hepta.model-cleanup-binding.v1',server_identity=identity,
                 model_claim=str(claim),model_claim_sha256=args.model_claim_sha256,
                 server_binary_sha256=args.server_sha256,server_domain='u:r:magisk:s0',
                 endpoint=config['endpoint'])
    verify_identity(binding,hash_binary=True)
    put(runtime/'STARTUP-INTENT.json',dict(schema='hepta.model-startup-observation.v1',
        server_identity=identity,observation_maximum_read_only_gets=120,
        binding_maximum_read_only_gets=7,maximum_total_read_only_gets=127,
        maximum_observation_seconds=120,
        maximum_binding_invocations=1,model_requests=0,service_starts=0))
    observed=[];started=time.monotonic();deadline=started+120.0
    try:
        ready=False
        while time.monotonic()<deadline and len(observed)<120:
            verify_identity(binding)
            slot,receipt=get_json(config,'/slots',min(deadline,time.monotonic()+1.0))
            row={'elapsed_seconds':time.monotonic()-started,'receipt':receipt}
            observed.append(row)
            if receipt.get('complete') is True and receipt.get('http_status')==200 and receipt.get('error') is None:
                require(isinstance(slot,list) and len(slot)==1 and isinstance(slot[0],dict),
                        'startup slot inventory differs')
                row['slot']=slot[0]
                require(slot[0].get('is_processing') is False,'new model unexpectedly processing')
                ready=True
            if ready:break
            time.sleep(min(1.0,max(0.0,deadline-time.monotonic())))
        require(ready,'read-only model startup observation deadline reached')
        verify_identity(binding,hash_binary=True)
        require(private_bytes(args.config)==config_raw and private_bytes(claim,128)==claim_raw,
                'startup inputs changed during readiness observation')
        argv=[sys.executable,'-B',str(Path(__file__).with_name('bind_slot_cleanup.py')),
              '--config',str(args.config),'--config-sha256',args.config_sha256,
              '--model-claim',str(claim),'--server-sha256',args.server_sha256,
              '--server-domain','u:r:magisk:s0','--output-dir',str(runtime/'bindings'),
              '--require-image-cancel']
        put(runtime/'BIND-INTENT.json',dict(one_invocation=True,server_identity=identity,
            model_requests=0,phone_actions=0,require_image_cancel=True))
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=12)
        require(result.returncode==0 and not result.stderr,'actual model binding refused: '+result.stderr.decode('utf8','replace')[:1024])
        bound=strict_json(result.stdout)
        require(bound.get('state')=='BOUND' and bound.get('server_identity')==identity,'binding result identity differs')
        binding_path=Path(bound['path'])
        require(binding_path.parent==runtime/'bindings','binding output path differs')
        bound_raw=private_bytes(binding_path)
        require(hashlib.sha256(bound_raw).hexdigest()==bound['sha256'] and strict_json(bound_raw)==binding,
                'actual binding readback differs')
        verify_identity(binding,hash_binary=True)
        report=dict(schema='hepta.model-startup-bound.v1',state='READY_BOUND_IMAGE_CANCEL_REQUIRED',
                    server_identity=identity,binding=bound,observation_gets=observed,
                    elapsed_seconds=time.monotonic()-started,model_requests=0,task_submissions=0,
                    model_restarts=0,automatic_retry=False)
        put(runtime/'READY-BOUND.json',report)
        print(json.dumps({'state':report['state'],'binding_path':str(binding_path),
                          'binding_sha256':bound['sha256'],'read_only_gets':len(observed)+bound['read_only_gets'],
                          'model_requests':0,'task_submissions':0},sort_keys=True))
    except BaseException as error:
        put(runtime/'STARTUP-FAILURE.json',dict(state='ORIGINAL_STARTUP_FAILED_NO_RETRY',
            error_type=type(error).__name__,error=str(error),observations=observed,
            server_identity=identity,model_requests=0,task_submissions=0,automatic_retry=False))
        raise


if __name__=='__main__':main()
