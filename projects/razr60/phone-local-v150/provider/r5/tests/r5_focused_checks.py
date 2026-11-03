#!/usr/bin/env python3
"""Host-only focused r5 checks. No phone, socket, model or actual tool execution."""
import ast,base64,copy,hashlib,importlib,json,os,secrets,sys,tempfile,threading,time
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source'))
import provider_phone_local as p
import phone_local_tools as t
import phone_observation_tools as obs
import action_ledger as l
import retirement_recovery as r
from task_postconditions import write_exclusive
from health_contracts import final_only_schema
from provider_openai_compatible import ProviderError
checks=[]
def check(name,value):
 if not value:raise AssertionError(name)
 checks.append(name)
def reject(name,fn):
 try:fn()
 except (ProviderError,ValueError,RuntimeError,FileExistsError,AssertionError):check(name,True)
 else:raise AssertionError(name+' unexpectedly admitted')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()
parent=ROOT.parent/'provider-r4'
for path in sorted((ROOT/'source').glob('*.py')):
 ast.parse(path.read_text(),feature_version=(3,12))
check('python312_all_production_source_syntax',True)
def astnode(path,name):
 tree=ast.parse(path.read_text())
 parts=name.split('.')
 for part in parts:
  tree=next(n for n in tree.body if getattr(n,'name',None)==part)
 return ast.dump(tree,include_attributes=False)
for name in ['business_decision_schema','PhoneLocalAdapter._decision','PhoneLocalAdapter.emit']:
 check('original_guard_unchanged_'+name,astnode(ROOT/'source/provider_phone_local.py',name)==astnode(parent/'source/provider_phone_local.py',name))
for name in ['provider_codex_host.py','provider_openai_compatible.py','phone_task_guards.py',
             'phone_local_http_worker.py','model_health.py','task_postconditions.py','health_contracts.py']:
 check('frozen_parent_bytes_unchanged_'+name,(ROOT/'source'/name).read_bytes()==(parent/'source'/name).read_bytes())
check('Unicode_helper_new_readonly_path',obs.INPUT_JAR=='/data/local/tmp/hepta-phone-executor-v150-r6/helpers/unicode-input-v148r2.jar')
check('screen_helper_new_readonly_path',obs.SCREEN_JAR=='/data/local/tmp/hepta-phone-executor-v150-r6/helpers/screen-codec-v148r1.jar')
old_ob=(parent/'source/phone_observation_tools.py').read_text()
new_ob=(ROOT/'source/phone_observation_tools.py').read_text()
check('only_helper_paths_changed_in_observation_mapper',
 new_ob==old_ob.replace('/data/local/tmp/hepta-unicode-v148-r2/input.jar',obs.INPUT_JAR).replace('/data/local/tmp/hepta-screen-v148-r1/codec.jar',obs.SCREEN_JAR))
executor={'mode':'phone_local_sidecar','python':'/usr/bin/python3','client_path':r.EXECUTOR_BINDING['client_path'],
          'client_sha256':r.EXECUTOR_BINDING['client_sha256'],'timeout_ms':60000}
check('r6_exact_executor_configuration',t.validate_executor(executor,verify_files=False)==executor)
reject('legacy_adb_fallback_rejected',lambda:t.validate_executor({'mode':'adb_legacy'},verify_files=False))
reject('old_client_path_rejected',lambda:t.validate_executor(dict(executor,client_path='/var/lib/trillionnium/owner-open/phone-local-v150/tool_client.py'),verify_files=False))
reject('wrong_client_pin_rejected',lambda:t.validate_executor(dict(executor,client_sha256='0'*64),verify_files=False))
apps=json.loads((parent/'local-config.phone.production.json').read_bytes())['approved_apps']
phone=SimpleNamespace(calls={},verified_facts={},local_observations={},latest=None,visual_read_constraints=[])
owner='SYNTHETIC_HOST_ONLY_'+secrets.token_hex(8)+'\n文本 🧪'
messages=[{'role':'system','content':'not forwarded'},{'role':'user','content':owner}]
scope={'allowed_call_id':'r01_'+'1'*16,'round':1,'tools_remaining':7,
 'approved_apps':{alias:{'label':v['label'],'package':v['component'].split('/')[0],'component':v['component']} for alias,v in apps.items()},
 'prior_action_inspections_no_old_text':[],'postconditions':None}
health=p.compose_local_messages(messages,messages,phone,scope,[],24576,decision_schema=final_only_schema(p.SCHEMA),health_mode=True)
check('health_has_only_minimal_policy_and_exact_owner',len(health)==2 and health[1]=={'role':'user','content':owner} and health[0]['content']==p.HEALTH_POLICY)
check('health_no_app_catalog_or_tool_inventory',all(alias not in health[0]['content'] for alias in apps) and 'phone.open_app' not in health[0]['content'])
check('health_nonce_not_forced_by_grammar',final_only_schema(p.SCHEMA)['properties']['summary'].get('type')=='string' and 'const' not in final_only_schema(p.SCHEMA)['properties']['summary'] and 'enum' not in final_only_schema(p.SCHEMA)['properties']['summary'])
reject('health_rejects_any_image',lambda:p.compose_local_messages(messages,messages,phone,scope,[{'type':'image_url','image_url':{'url':'data:image/jpeg;base64,AA=='}}],24576,decision_schema=final_only_schema(p.SCHEMA),health_mode=True))
schema=p.business_decision_schema(scope['allowed_call_id'],1,phone,apps)
business=p.compose_local_messages(messages,messages,phone,scope,[],24576,decision_schema=schema)
metadata=json.loads(business[1]['content'])
check('business_exact_owner_last_once',business[2]['content']==[{'type':'text','text':owner}] and owner not in business[0]['content'] and owner not in business[1]['content'])
check('all_approved_components_visible_without_new_scope',metadata['approved_apps']==scope['approved_apps'] and len(metadata['approved_apps'])==4)
check('same_package_activities_remain_distinct',metadata['approved_apps']['视觉挑战']['component']!=metadata['approved_apps']['Unicode验证']['component'])
check('business_owner_utf8_hash_bound',metadata['owner_request_utf8_sha256']==sha(owner.encode()))
check('no_tap_hint_without_current_image','phone.tap:' not in business[0]['content'])
phone.visual_read_constraints=[{'package':'org.trillionnium.hepta.controlprobe'}]
visual_schema=p.business_decision_schema(scope['allowed_call_id'],1,phone,apps)
visual_policy=p.business_policy(visual_schema)
check('visual_hidden_branches_not_in_prompt','phone.observe:' not in visual_policy and 'phone.read_text:' not in visual_policy)
phone.latest={'call_id':'shot-host-only','attached_round':1,'received_monotonic':time.monotonic(),'encoded_size':[100,200]}
current_schema=p.business_decision_schema(scope['allowed_call_id'],1,phone,apps)
current_policy=p.business_policy(current_schema)
check('current_tap_hint_uses_same_grammar_image','phone.tap:' in current_policy and 'shot-host-only' in current_policy)
phone.calls={'old':{'semantic_tool':'phone.tap'}}
check('spent_visual_selection_not_in_prompt','phone.tap:' not in p.business_policy(p.business_decision_schema(scope['allowed_call_id'],1,phone,apps)))
check('round8_final_prompt_has_no_tools',all(name+':' not in p.business_policy(p.business_decision_schema('r08_'+'8'*16,8,phone,apps)) for name in p.TOOL_HINTS))
phone.calls={}
with tempfile.TemporaryDirectory(prefix='hepta-r5-host-') as tmp:
 root=Path(tmp).resolve()
 evidence=root/'evidence';evidence.mkdir(mode=0o700)
 run=evidence/'synthetic-run';run.mkdir(mode=0o700)
 ledger=l.ActionLedger(evidence,run)
 identity={'session_id':'synthetic-session','profile_id':'synthetic-profile','task_id':'synthetic-task','turn_id':'synthetic-turn'}
 effect={'semantic_tool':'phone.open_app','component':apps['设置']['component']}
 intent={'schema':'hepta.action-intent.v150.1','action_id':r.ACTION_ID,
 'semantic_identity':identity,'call_id':'synthetic-original-call','semantic_tool':'phone.open_app','wire_tool':'shell.exec',
 'effect_fingerprint':l.fingerprint(effect),'command_sha256':r.COMMAND_SHA256,'run_dir':str(run),
 'state':'reserved_before_native_dispatch_result_unknown','created_utc':'2026-01-01T00:00:00+00:00','automatic_replay':False}
 intent_path=ledger.directory/(r.ACTION_ID+'.intent.json')
 write_exclusive(intent_path,intent);original_intent=intent_path.read_bytes()
 record={**effect,'capture_id':'1'*32,'call_id':'synthetic-next-call','wire_call':{'tool':'shell.exec','argv':['/usr/bin/python3',r.EXECUTOR_BINDING['client_path'],'execute','--action-id','1'*32,'--command-b64',base64.b64encode(b'printf synthetic_fixture_only').decode(),'--timeout-ms','3000']}}
 reject('legacy_unknown_blocks_new_mutation',lambda:ledger.reserve(record,dict(identity,turn_id='fresh-synthetic-turn')))
 fake=object.__new__(p.PhoneLocalAdapter);fake.local_config={'executor':executor};fake.action_ledger=ledger
 fake.inspected_actions=set();fake.recovery_observations=[];fake.cancelled=threading.Event()
 fake.receive=lambda **kwargs:None;fake.run_dir=run;events=[];fake.atomic_record=lambda path,value:events.append(value)
 p.PhoneLocalAdapter._inspect_pending(fake)
 check('legacy_pending_never_inspected_on_new_endpoint',events and events[0]['new_executor_inspection_attempted'] is False and not fake.recovery_observations[0]['resolved_process_outcome'])
 reject('unqualified_automatic_proof_cannot_resolve',lambda:ledger.resolve_retired(r.ACTION_ID,b'{}',r.EXECUTOR_BINDING))
 check('failed_resolution_left_original_intent_and_no_resolution',intent_path.read_bytes()==original_intent and not (ledger.directory/(r.ACTION_ID+'.resolution.json')).exists())
 production_pins=(r.INTENT_SHA256,r.PROOF_SHA256,l.PROOF_SHA256)
 r.INTENT_SHA256=sha(original_intent)
 proof={'schema':'hepta.executor-retirement-proof.v150.1','state':r.PROOF_STATE,'action_id':r.ACTION_ID,
 'intent_sha256':r.INTENT_SHA256,'command_sha256':r.COMMAND_SHA256,'verifier_sha256':r.VERIFIER_SHA256,
 'artifact_sha256':dict(r.ORIGINAL_ARTIFACTS),'retired_executor':dict(r.ORIGINAL_EXECUTOR),
 'automatic_checks_pass':True,'external_review_verified':True,'eligible_for_new_version_resolution':True,
 'original_task_terminal_unchanged':True,'resolution_written':False,'business_verified':False,
 'automatic_replay':False,'old_claims_edited':False,'external_review_original_sha256':'9'*64,
 'external_evidence':[{'fixture':'synthetic host validator only'}],
 'details':{'native_hash_verification':{'status':'PASS'},'native_terminal':{'exit_code':71},
 'original_request_scope':dict(identity,turn_stream_id='synthetic-stream')}}
 raw=encoded(proof);r.PROOF_SHA256=l.PROOF_SHA256=sha(raw)
 for key,value in [('automatic_checks_pass',False),('external_review_verified',False),
                   ('eligible_for_new_version_resolution',False),('business_verified',True),
                   ('automatic_replay',True),('original_task_terminal_unchanged',False),
                   ('old_claims_edited',True),('state','not_found'),('action_id','0'*32),
                   ('verifier_sha256','0'*64)]:
  changed=dict(proof);changed[key]=value;bad=encoded(changed);r.PROOF_SHA256=l.PROOF_SHA256=sha(bad)
  reject('invalid_proof_field_rejected_'+key,lambda bad=bad:r.validate_proof(bad,intent,sha(original_intent)))
 r.PROOF_SHA256=l.PROOF_SHA256=sha(raw)
 reject('different_proof_bytes_rejected',lambda:ledger.resolve_retired(r.ACTION_ID,raw+b' ',r.EXECUTOR_BINDING))
 reject('old_executor_cannot_unlock_future_work',lambda:ledger.resolve_retired(r.ACTION_ID,raw,dict(r.EXECUTOR_BINDING,endpoint='hepta_phone_local_v150')))
 # Exercise the real two-append crash boundary in an isolated temporary ledger.
 original_write=l.write_exclusive
 def interrupted(path,value):
  if path.name.endswith('.resolution.json'):raise RuntimeError('SYNTHETIC CRASH AFTER PROOF FSYNC')
  return original_write(path,value)
 l.write_exclusive=interrupted
 reject('crash_after_proof_does_not_resolve',lambda:ledger.resolve_retired(r.ACTION_ID,raw,r.EXECUTOR_BINDING))
 retained=ledger.directory/(r.ACTION_ID+'.retirement-proof.json');retained_stat=retained.stat()
 check('crash_retains_exact_proof_and_pending_original',retained.read_bytes()==raw and ledger.intents()[0][2] is None and intent_path.read_bytes()==original_intent)
 l.write_exclusive=original_write
 resolved=ledger.resolve_retired(r.ACTION_ID,raw,r.EXECUTOR_BINDING)
 check('additive_retirement_schema_not_sidecar_success',resolved['schema']=='hepta.action-resolution.v150.2' and resolved['state']==r.RESOLUTION_STATE and resolved['business_verified'] is False and 'effect_started' not in resolved)
 check('same_retained_proof_reused_without_overwrite',retained.stat().st_ino==retained_stat.st_ino and retained.stat().st_mtime_ns==retained_stat.st_mtime_ns)
 check('ledger_scan_revalidates_pinned_retirement_proof',ledger.intents()[0][2]==resolved)
 reject('duplicate_resolution_never_overwrites',lambda:ledger.resolve_retired(r.ACTION_ID,raw,r.EXECUTOR_BINDING))
 reject('same_old_task_cannot_retry_effect_with_new_call_id',lambda:ledger.reserve(record,identity))
 ledger.reserve(record,dict(identity,turn_id='fresh-synthetic-turn'))
 new_intent=json.loads((ledger.directory/('1'*32+'.intent.json')).read_bytes())
 check('fresh_intent_has_explicit_r6_binding',new_intent['schema']=='hepta.action-intent.v150.2' and new_intent['executor_binding']==r.EXECUTOR_BINDING)
 check('original_intent_remains_byte_identical',intent_path.read_bytes()==original_intent)
 # Damaging a private retained proof cannot silently reopen admission.
 retained.write_bytes(raw+b' ');os.chmod(retained,0o600)
 reject('retained_proof_tamper_blocks_ledger',ledger.intents)
 r.INTENT_SHA256,r.PROOF_SHA256,l.PROOF_SHA256=production_pins
receipt={'terminal':True,'state':'completed','executor_revision':6,
'executor_context':'u:r:trillionnium_owner_open_phone_executor:s0',
'peer_context':'u:r:trillionnium_owner_open_bootstrap:s0',
'execution_context':'u:r:trillionnium_owner_open_phone_worker:s0',
'execution_credentials_scope':'android_shell_uid2000','handshake_stage':'worker_entry_after_exec_transition',
'waitpid_identity_lost':False,'execution_supplementary_group_count':0,'dispatch_count':1,'pid':1234,'pgid':1234}
for key in ('effect_started','process_group_established','waitpid_joined','process_group_absent',
            'execution_credentials_verified','supplementary_groups_cleared','worker_domain_verified'):receipt[key]=True
for key in ('required_execution_uid','required_execution_gid','execution_uid','execution_euid','execution_gid','execution_egid'):receipt[key]=2000
r.require_r6_terminal(receipt);check('r6_authentic_worker_terminal_shape_accepted',True)
for key,value in [('terminal',1),('peer_context','u:r:magisk:s0'),('worker_domain_verified',False),
                  ('execution_uid',0),('waitpid_identity_lost',True),('process_group_absent',False),
                  ('dispatch_count',True),('handshake_stage','parent_before_worker')]:
 reject('unsafe_r6_terminal_rejected_'+key,lambda key=key,value=value:r.require_r6_terminal(dict(receipt,**{key:value})))
report={'schema':'hepta.phone-local-r5-host-validation.v150.1','checks_passed':len(checks),'checks':checks,
'phone_calls':0,'model_calls':0,'socket_connections':0,'real_actions_dispatched':0,
'physical_qualification':False,'synthetic_resolution_fixture_only':True,'old_frozen_sources_modified':False,
'source_files':[{'path':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,'sha256':sha(path.read_bytes())}
 for path in sorted((ROOT/'source').glob('*.py'))]}
out=ROOT/'validation/HOST-CHECKS-01.json'
with out.open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
print(json.dumps(report,indent=2))
