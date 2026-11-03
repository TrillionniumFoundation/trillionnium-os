#!/usr/bin/env python3
"""Operator-only read-only sidecar inspection before unblocking new mutations.

This command never calls execute, never resubmits an effect, and never rewrites a
task terminal. A resolved process outcome is not a verified business outcome.
"""
import argparse, hashlib, importlib.util, json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'source'))
from provider_phone_local import load_local_config
from action_ledger import ActionLedger

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--state',type=Path,required=True)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--action-id',required=True)
    args=p.parse_args()
    config,_=load_local_config(args.config)
    if config['executor']['mode']!='phone_local_sidecar':
        raise RuntimeError('sidecar inspection requires the actual phone-local executor configuration')
    ledger=ActionLedger(args.state/'evidence',args.state/'evidence')
    selected=[v for v,d,r in ledger.intents() if v['action_id']==args.action_id and r is None]
    if len(selected)!=1:raise RuntimeError('one unresolved original action is required')
    original=selected[0]
    path=Path(config['executor']['client_path'])
    if hashlib.sha256(path.read_bytes()).hexdigest()!=config['executor']['client_sha256']:
        raise RuntimeError('tool client byte pin differs')
    spec=importlib.util.spec_from_file_location('reviewed_sidecar_client',path)
    client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
    inspected=client.inspect(args.action_id,original['command_sha256'],False)
    ledger.resolve_inspected(args.action_id,inspected)
    print(json.dumps({'action_id':args.action_id,'original_effect_state':inspected['receipt']['state'],
                      'inspection_only':True,'effects_dispatched':0,'original_terminal_unchanged':True,
                      'business_verified':False,'new_task_requires_new_nonce_and_remaining_work_only':True}))
if __name__=='__main__':main()
