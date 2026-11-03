#!/usr/bin/env python3
"""Narrow synthetic prompt-layout checks only. No actual request materialization."""
import copy,hashlib,importlib.util,json,sys
from pathlib import Path
D=Path(__file__).resolve().parent
sys.path.insert(0,str(D))
raw=(D/'collect_health_evidence.py').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='e79b4c01d653bc0ea6d752c6aa9a8541addce936d174c71f4e1eb69819901121'
spec=importlib.util.spec_from_file_location('r5_health_collection_tested',D/'collect_health_evidence.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
checks=[]
owner=b'HOST_FIXTURE_ONLY_NO_REGISTRATION_0123456789'
good={'messages':[{'role':'system','content':m.R5_HEALTH_POLICY},{'role':'user','content':owner.decode()}]}
def reject(value,reason,health=True):
 try:m.prompt_layout(value,owner,health)
 except (ValueError,KeyError,TypeError,IndexError):checks.append(reason);return
 raise AssertionError(reason)
assert m.prompt_layout(good,owner,True)=='r5_health_exact_owner_only';checks.append('r5_minimal_health_exact_owner_pass')
bad=copy.deepcopy(good);bad['messages'][0]['content']+='changed';reject(bad,'changed_system_policy_rejected')
bad=copy.deepcopy(good);bad['messages'][1]['content']+='\n';reject(bad,'owner_byte_change_rejected')
reject(good,'nonhealth_two_message_admission_rejected',False)
oldseal=m.SEAL;m.SEAL='0'*64
try:reject(good,'wrong_source_seal_rejected')
finally:m.SEAL=oldseal
bad=copy.deepcopy(good);bad['messages'][1]['content']=[{'type':'text','text':owner.decode()},{'type':'image_url','image_url':{'url':'data:image/jpeg;base64,AA=='}}]
reject(bad,'image_or_content_projection_rejected')
bad=copy.deepcopy(good);bad['messages'][0]['extra']='not_original';reject(bad,'extra_message_fields_rejected')
metadata={'owner_request_utf8_sha256':hashlib.sha256(owner).hexdigest(),'transcript':[]}
legacy={'messages':[{'role':'system','content':'legacy'},{'role':'user','content':json.dumps(metadata)},{'role':'user','content':[{'type':'text','text':owner.decode()}]}]}
assert m.prompt_layout(legacy,owner,True)=='r2_explicit_owner_last';checks.append('original_r2_branch_unchanged')
legacy={'messages':[{'role':'system','content':'legacy'},{'role':'user','content':[{'type':'text','text':json.dumps({'transcript':[{'role':'user','content':owner.decode()}]})}]}]}
# Only nonminimal legacy uses the old branch; a two-message r1 input must not
# bypass the r5-only exact form, so construct its original third inert message.
legacy['messages'].append({'role':'assistant','content':'legacy_count_fixture'})
assert m.prompt_layout(legacy,owner,False)=='r1_owner_in_context_transcript';checks.append('original_projection_branch_body_unchanged')
static=json.loads((D/'LAYOUT-REVISION-CHECK.json').read_bytes())
assert static['exact_reverse_to_frozen_r4'] and static['all_non_layout_proof_gates_unchanged'];checks.append('reverse_diff_keeps_all_terminal_nonce_slot_native_gates')
report={'schema':'hepta.r5-health-collector.host-layout-checks.v1','status':'PASS','checks':checks,'count':len(checks),
'phone_calls':0,'model_requests':0,'actual_request_materialization':False,'task_registrations':0,'health_qualification':False}
m.write_new(D/'HOST-LAYOUT-CHECKS-01.json',m.json_bytes(report))
print(json.dumps(report,sort_keys=True))
