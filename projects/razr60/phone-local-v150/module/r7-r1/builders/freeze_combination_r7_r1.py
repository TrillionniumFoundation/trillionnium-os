#!/usr/bin/env python3
"""Freeze exact r7 combination metadata only; no nonce, registration, task or phone."""
import argparse,hashlib,json,types
from pathlib import Path
D=Path(__file__).resolve().parent;B=D.parent
def sha(x):return hashlib.sha256(x).hexdigest()
def read(p,pin=None):
 b=p.read_bytes()
 if pin is not None:assert sha(b)==pin
 return b
def enc(v):return (json.dumps(v,ensure_ascii=False,indent=2)+'\n').encode()
def new(p,b):
 with p.open('xb') as f:f.write(b)
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
p=argparse.ArgumentParser()
p.add_argument('--aggregator-sha256',required=True)
p.add_argument('--pending-sha256',required=True)
args=p.parse_args()
assert args.aggregator_sha256=='c3b91281a1076ac6fd782fe722eeedae7384817dcbd89060e94b095be48ce083'
assert args.pending_sha256=='dc88ad11acd82dd777783d473f0f8ce4a007c38829852bd830d485e0ff49b303'
ap=B/'acceptance-r7/aggregate_protocol_r7.py'
ar=read(ap,args.aggregator_sha256)
m=types.ModuleType('frozen_r7_aggregator');m.__file__=str(ap)
exec(compile(ar,str(ap),'exec'),m.__dict__)
combo=json.loads(read(B/'acceptance-r7/COMBINATION-PENDING.json',args.pending_sha256))
module=D/'sealed-module-v150-r7-r1/module/MODULE-MANIFEST-v150-r7-r1.json'
module_raw=read(module);manifest=json.loads(module_raw)
assert manifest['provider_source_seal_sha256']==combo['provider_source_seal_sha256']
assert manifest['configuration_sha256']==combo['provider_config_sha256']
assert manifest['service_inputs_sha256']==combo['service_inputs_sha256']
combo.update(state='frozen',module_manifest_sha256=sha(module_raw),
 policy_rules_manifest_sha256='01eb1a6e50948bfa6f0dff0ebd40357d0f4858c6787f9ea25a68fc8cc2c48fd8',
 live_policy_snapshot_sha256='05756784090a574be850a068576fbded2842f3fa8c1af0aa5b430f875c78a31f',
 live_policy_semantic_audit_sha256='8f5425f59c30635445cbfafbdc9fddbf8c3645dbef83e36c413f5931a21acd80',
 native_and_apps_manifest_sha256='f61f5f794763d5c51285712cc926566ab8fde05d0166d16e6fc5d2de701d8bf8')
cp=D/'COMBINATION-FROZEN-v150-r7-module-r1.json'
pin=new(cp,enc(combo))
selected=m.load_combination(cp,pin['sha256'])
assert selected['frozen'] is True
protocol,protocol_sha,_=m.validate_protocol()
assert len(protocol['cases'])==19
report={'schema':'hepta.combination-freeze.v150.r7.1','combination':pin,
 'combination_sha256':selected['combination_sha256'],'module_manifest_sha256':sha(module_raw),
 'fixed19_objects_unchanged':True,'protocol_sha256':protocol_sha,'sample_count':0,
 'source_manifest_is_traceability_not_qualification':True,'old_health_failure_not_reclassified':True,
 'installation_observed_by_builder':False,'new_health_observed_by_builder':False,
 'phone_calls':0,'model_requests':0,'new_nonce':False}
reportpin=new(D/'COMBINATION-VALIDATION-r7-r1.json',enc(report))
print(json.dumps({'combination':pin,'validation':reportpin,'canonical_combination_sha256':selected['combination_sha256'],'fixed19_count':19,'phone_calls':0,'model_requests':0,'new_nonce':False}))
