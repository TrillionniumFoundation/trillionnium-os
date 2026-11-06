"""Construct an independent operator candidate; no host publication or tasks."""
from pathlib import Path
import ast
import base64
import copy
import difflib
import hashlib
import json
import zlib

D=Path(__file__).resolve().parent
OUT=D/'candidate01'
OLD=D.parent/'R5-negative-source-binding01'

def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def enc(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
def put(name,raw):
    path=OUT/name;path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():assert path.read_bytes()==raw,name
    else:path.write_bytes(raw)
def function(raw,name):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name]
    assert len(nodes)==1
    node=nodes[0]
    return b''.join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])

payload_raw=(OLD/'transport/SOURCE-PAYLOAD.zlib').read_bytes()
assert pin(payload_raw)=={'bytes':711272,'sha256':'324bf65adb34b22e870ab8d791216ffcc50f360685934ab7696694b866b5a873'}
payload=json.loads(zlib.decompress(payload_raw))
rows={r['path']:r for r in payload['files']}
def body(name):
    value=payload['blobs'][rows[name]['sha256']]
    raw=value['content'].encode()if value['encoding']=='utf-8'else base64.b64decode(value['content'],validate=True)
    assert pin(raw)=={k:rows[name][k]for k in('bytes','sha256')}
    return raw

member='candidate/templates/physical-fault/physical_fault_common.py'
original=body('inputs/'+member)
old_generation=function(original,'generation_inputs')
head=old_generation[:old_generation.index(b"    need(adoption.get('schema')")]
before=b"    adoption=strict(originals.read(plan['policy_adoption'],16*1024*1024))"
after=b"    adoption_raw=originals.read(plan['policy_adoption'],16*1024*1024)\n    adoption=strict(adoption_raw)"
assert head.count(before)==1
head=head.replace(before,after,1)
new_generation=head+b'''    need(adoption.get('schema')=='hepta.parent-dir.policy-adoption.v1' and
         adoption.get('release_id')=='v150-parent-dir-getattr-r1' and adoption.get('boot_id')==BOOT and
         adoption.get('actual_export')==plan['actual_policy'],'actual_current_parent_dir_adoption_descriptor_relationship')
    # The current consumer pins the complete file-callback-only adoption
    # verifier. Its exact proof validates the retained parent, complete rule,
    # one declared getattr delta, actual live capture and full post-live proof.
    # This is the same API used by that consumer, never a schema union or a
    # fabricated top-level list of the old generation's permission atoms.
    verifier_sha=literal(consumer,'POLICY_VERIFIER_SHA')
    verifier_bytes=literal(consumer,'POLICY_VERIFIER_BYTES')
    need(type(verifier_sha)is str and re.fullmatch('[0-9a-f]{64}',verifier_sha) and
         type(verifier_bytes)is int and 0<verifier_bytes<=131072,'exact_current_adoption_verifier_source_pin')
    matches=[row for row in adoption['verification_originals'] if type(row)is dict and
             row.get('sha256')==verifier_sha and row.get('bytes')==verifier_bytes]
    need(len(matches)==1,'one_current_consumer_reviewed_adoption_verifier_original')
    verifier_raw=originals.read(matches[0],131072)
    need(len(verifier_raw)==verifier_bytes and sha(verifier_raw)==verifier_sha,
         'complete_current_adoption_verifier_original')
    verifier=module(verifier_raw,matches[0]['path'],'negative_current_policy_adoption')
    summary=verifier.verify_adoption(adoption_raw,read_pinned=originals.read)
    need(summary['current_adoption_sha256']==sha(adoption_raw)==plan['policy_adoption']['sha256'] and
         summary['runtime_policy']=={'bytes':len(policy),'sha256':sha(policy)} and
         summary['full_rule']==adoption['full_rule'] and
         summary['root_scope_decision_sha256']==literal(consumer,'CURRENT_SCOPE_DECISION_SHA'),
         'actual_current_adoption_complete_proof_matches_consumer_and_export')
    need(summary['root_decision']==adoption['root_decision'] and
         summary['current_policy_adoption']['schema']=='hepta.parent-dir.policy-adoption.v1' and
         summary['current_policy_adoption']['boot_id']==BOOT and
         summary['service_start_admitted']is False and summary['component_qualified']is False and
         type(summary['phone_calls'])is int and summary['phone_calls']==0 and
         type(summary['policy_writes'])is int and summary['policy_writes']==0,
         'strict_actual_adoption_verification_does_not_grant_runtime_admission')
    return runtime
'''
old_admit=function(original,'admit')
before=b'''    need(adoption.get('schema')=='hepta.runtime-properties-r10.policy-adoption.v1' and
         adoption.get('actual_export')==plan['actual_policy'] and
         adoption.get('root_decision',{}).get('decision')=='ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY' and
         adoption['root_decision'].get('actual_policy_sha256')==plan['actual_policy']['sha256'],
         'actual_policy_adoption_descriptor_relationship')'''
after=b'''    need(adoption.get('schema')=='hepta.parent-dir.policy-adoption.v1' and
         adoption.get('release_id')=='v150-parent-dir-getattr-r1' and
         adoption.get('actual_export')==plan['actual_policy'] and
         adoption.get('root_decision',{}).get('schema')=='hepta.root.parent-dir.actual-policy-adoption-decision.v1' and
         adoption['root_decision'].get('decision')=='ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY' and
         adoption['root_decision'].get('actual_policy_sha256')==plan['actual_policy']['sha256'],
         'actual_current_parent_dir_adoption_descriptor_relationship')'''
assert old_admit.count(before)==1
new_admit=old_admit.replace(before,after,1)
assert original.count(old_generation)==original.count(old_admit)==1
candidate=original.replace(old_generation,new_generation,1).replace(old_admit,new_admit,1)
assert candidate.replace(new_generation,old_generation,1).replace(new_admit,old_admit,1)==original
compile(candidate,'<independent-current-adoption-operator>','exec')
unchanged=[]
for node in ast.parse(original).body:
    if isinstance(node,ast.FunctionDef)and node.name not in ('generation_inputs','admit'):
        assert function(original,node.name)==function(candidate,node.name)
        unchanged.append(node.name)
put('reference/physical_fault_common.original.py',original)
put('source/physical_fault_common.py',candidate)
put('COMMON.patch',''.join(difflib.unified_diff(original.decode().splitlines(True),candidate.decode().splitlines(True),
    fromfile='reference/physical_fault_common.original.py',tofile='source/physical_fault_common.py')).encode())

old_index_raw=body('inputs/REVIEWED-INPUTS.json');old_index=json.loads(old_index_raw)
assert enc(old_index)==old_index_raw
new_index=copy.deepcopy(old_index)
items=[row for row in new_index['files']if row['path']==member];assert len(items)==1
old_member=copy.deepcopy(items[0]);items[0].update(pin(candidate))
new_index_raw=enc(new_index)
inverse=copy.deepcopy(new_index)
next(row for row in inverse['files']if row['path']==member).update(old_member)
assert enc(inverse)==old_index_raw and len(new_index['files'])==171
put('reference/REVIEWED-INPUTS.original.json',old_index_raw)
put('source/REVIEWED-INPUTS.json',new_index_raw)
put('REFERENCE-INDEX.patch',''.join(difflib.unified_diff(old_index_raw.decode().splitlines(True),new_index_raw.decode().splitlines(True),
    fromfile='reference/REVIEWED-INPUTS.original.json',tofile='source/REVIEWED-INPUTS.json')).encode())

old_constructor=(OLD/'reference/derive_negative_sources_UNBOUND.py').read_bytes()
assert pin(old_constructor)=={'bytes':43142,'sha256':'d539cb12c5b3d99f4b6066de148f11db78d3ad4210bc034669ebc1bc99c44903'}
before=("REFERENCE_INDEX = "+repr((len(old_index_raw),sha256:=hashlib.sha256(old_index_raw).hexdigest()))).encode()
after=("REFERENCE_INDEX = "+repr((len(new_index_raw),hashlib.sha256(new_index_raw).hexdigest()))).encode()
assert old_constructor.count(before)==1
new_constructor=old_constructor.replace(before,after,1)
assert new_constructor.replace(after,before,1)==old_constructor
compile(new_constructor,'<independent-current-adoption-negative-constructor>','exec')
put('reference/derive_negative_sources_UNBOUND.original.py',old_constructor)
put('source/derive_negative_sources_UNBOUND.py',new_constructor)
put('CONSTRUCTOR.patch',''.join(difflib.unified_diff(old_constructor.decode().splitlines(True),new_constructor.decode().splitlines(True),
    fromfile='reference/derive_negative_sources_UNBOUND.original.py',tofile='source/derive_negative_sources_UNBOUND.py')).encode())

report={'schema':'hepta.fc33.negative-operator-current-adoption-source-derivation.v1',
    'state':'INDEPENDENT_OPERATOR_CANDIDATE_NO_PUBLICATION_OR_ACTUAL_TASK',
    'common':{'parent':pin(original),'candidate':pin(candidate),'changed_functions':['generation_inputs','admit'],
        'unchanged_functions':unchanged,'complete_inverse':True},
    'reference_index':{'parent':pin(old_index_raw),'candidate':pin(new_index_raw),'only_member_changed':member,
        'files':171,'complete_inverse':True},
    'constructor':{'parent':pin(old_constructor),'candidate':pin(new_constructor),
        'only_literal_changed':'REFERENCE_INDEX','complete_inverse':True,'FROZEN_INPUTS':None},
    'api':'actual current consumer-pinned verifier.verify_adoption(adoption_raw,read_pinned=originals.read)',
    'policy_verifier':{'bytes':65591,'sha256':'6a3a9f8278ccf4b29724d9d034b4a349127a77d0adfd4daa8066ef6aa8d6c35b'},
    'schema_union_allowed':False,'old_adoption_or_current_originals_changed':False,
    'production15_changed':False,'runtime38_changed':False,
    'actual_positive_control':None,'actual_publication':None,'actual_BUILD':None,'actual_READY':None,
    'phone_calls':0,'native_dispatches':0,'model_requests':0}
put('DERIVATION.json',enc(report))
print(json.dumps({'common':pin(candidate),'index':pin(new_index_raw),'constructor':pin(new_constructor),
    'whole_inverse':True,'executed_or_published':False},sort_keys=True))
