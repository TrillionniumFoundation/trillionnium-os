#!/usr/bin/env python3
"""Host-only exact r7-r2 combination freeze. No nonce, phone, registration or model call."""
import argparse,hashlib,json,os,re,types
from pathlib import Path
D=Path(__file__).resolve().parent;B=D.parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(p,pin=None):
 p=Path(p);assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1
 raw=p.read_bytes()
 if pin is not None:assert sha(raw)==pin
 return raw
def enc(v):return (json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
def new(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
ap=argparse.ArgumentParser()
ap.add_argument('--aggregator-sha256',required=True)
ap.add_argument('--pending-sha256',required=True)
a=ap.parse_args()
assert a.aggregator_sha256=='14a283c4262627e6c5a6d175bf28b966e5ae170e5f6ba7ca0cc9c2b8905e1be0'
assert a.pending_sha256=='f906a2ab09863bdcb82fa4cd909492a86297e7af9d778dfba34010da84a6047a'
A=B/'acceptance-r7-r2';ar=read(A/'aggregate_protocol_r7.py',a.aggregator_sha256)
m=types.ModuleType('frozen_r7_r2_aggregator');m.__file__=str(A/'aggregate_protocol_r7.py')
exec(compile(ar,m.__file__,'exec'),m.__dict__)
combo=json.loads(read(A/'COMBINATION-PENDING-v150-r7-module-r2.json',a.pending_sha256))
assert combo['release']=='v150-r7-r2' and combo['schema']=='hepta.acceptance-combination.v150.r7.1'
bundle=json.loads(read(D/'sealed-module-v150-r7-r2/BUNDLE.json'))
M=D/'sealed-module-v150-r7-r2/module'
mr=read(M/'MODULE-MANIFEST-v150-r7-r2.json',bundle['module_manifest']['sha256']);v=json.loads(mr)
assert v['provider_source_seal_sha256']==combo['provider_source_seal_sha256']=='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
assert v['configuration_sha256']==combo['provider_config_sha256']
assert v['service_inputs_sha256']==combo['service_inputs_sha256']
assert v['native_apps_manifest_sha256']==combo['native_and_apps_manifest_sha256']
assert v['policy_source_sha256']=='e9ffb955ba3872d7b3c453729ef8b6e52b8679f86f05496d25a1b735f9bed7a2'
assert v['live_policy_sha256']=='439ebd30f0e003cc4b0f5c08cade8c59b922eedcd3a3302169323a7f0397f089'
assert v['live_policy_semantic_audit_sha256']=='38761d1076ed1dca8bf01e245bf17d184b445af401f686b4c77421cd6db5f0a5'
rulesraw=read(M/'evidence/R7-R2-POLICY-RULES-MANIFEST.json',v['policy_rules_manifest_sha256'])
auditraw=read(M/'evidence/R7-R2-ACTUAL-LIVE-POLICY-AUDIT.json',v['live_policy_semantic_audit_sha256'])
audit=json.loads(auditraw);assert audit['status']=='PASS' and audit['check_count']==audit['passed_count']==26
combo.update(state='frozen',module_manifest_sha256=sha(mr),policy_rules_manifest_sha256=sha(rulesraw),
 live_policy_snapshot_sha256=v['live_policy_sha256'],live_policy_semantic_audit_sha256=sha(auditraw))
path=D/'COMBINATION-FROZEN-v150-r7-module-r2.json';pin=new(path,enc(combo))
selected=m.load_combination(path,pin['sha256']);assert selected['frozen'] is True
protocol,protocol_sha,_=m.validate_protocol();assert len(protocol['cases'])==19
assert protocol_sha=='a9f314c4f2b6a7f05cbe7cc129ffcecef709f1f00b01b2dc5d08b0b6360b64e4'
report={'schema':'hepta.combination-freeze.v150.r7.2','combination':pin,'combination_sha256':selected['combination_sha256'],
 'module_manifest_sha256':sha(mr),'protocol_sha256':protocol_sha,'fixed19_count':19,
 'formal_protocol_preserves_all_original_cases_limits_geometry_and_layer_gates':True,
 'older_source_bundle_qa_copy_is_historical_not_current_normative':True,
 'provider_model_executor_native_and_budgets_unchanged':True,
 'current_combination_sample_count':0,'old_r7_r1_failures_preserved':True,
 'installation_observed_by_builder':False,'new_health_observed_by_builder':False,
 'phone_calls':0,'model_requests':0,'new_nonce':False}
rp=new(D/'COMBINATION-VALIDATION-r7-r2.json',enc(report))
print(json.dumps({'combination':pin,'validation':rp,'canonical_combination_sha256':selected['combination_sha256'],'fixed19_count':19,'phone_calls':0,'model_requests':0,'new_nonce':False}))
