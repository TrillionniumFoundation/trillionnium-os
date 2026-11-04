#!/usr/bin/env python3
"""Host-only r7-r3 module seal. Exact actual retirement and new live policy evidence required."""
from pathlib import Path
import argparse,ast,base64,copy,hashlib,json,os,re,tarfile,types
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r7-r2-finalization-r1/sealed-module-v150-r7-r2'
BOOT='<INSTANCE_UUID_REQUIRED>'
H='/data/trillionnium/owner-open/state/phone-local-v150'
IDS={role:['<INSTANCE_PID_REQUIRED>','<INSTANCE_PGID_REQUIRED>','<INSTANCE_SID_REQUIRED>','<INSTANCE_START_TICKS_REQUIRED>'] for role in ('supervisor','model','sidecar','provider')}
SOURCE='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
FULL='30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8'
DELTA='a844e622896f84e3fb535ccb1315e21b48a5bcbf2d78a8ae05be9c4b3f174662'
OFFLINE='47cbc252a6db847f7a37dd124e8732acea48e38368da2a6ff3b1916a142918c6'
OLDLIVE='439ebd30f0e003cc4b0f5c08cade8c59b922eedcd3a3302169323a7f0397f089'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(p,pin=None,size=None):
 p=Path(p);assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1,str(p)
 raw=p.read_bytes()
 if pin is not None:assert re.fullmatch('[0-9a-f]{64}',pin) and sha(raw)==pin,(str(p),'hash')
 if size is not None:assert len(raw)==size,(str(p),'bytes')
 return raw
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def put(p,raw,mode=0o600):
 p=Path(p);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if isinstance(raw,str):raw=raw.encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'bytes':len(raw),'sha256':sha(raw)}
def actual(desc):
 assert set(desc)=={'path','bytes','sha256'}
 p=Path(desc['path']).resolve(strict=True);assert p.is_relative_to(B.resolve(strict=True))
 return read(p,desc['sha256'],desc['bytes'])
def zero(value):return type(value) is int and value==0
def actual_job(desc):
 raw=actual(desc);v=json.loads(raw)
 assert v['state']=='succeeded' and zero(v['exit_code'])
 assert v['output_complete'] is True and v['output_durable'] is True and v['terminal_publication_confirmed'] is True
 assert v['timed_out'] is False and v['cancelled'] is False and v['automatic_retry'] is False
 return raw,v
def actual_operation(desc):
 raw=actual(desc);v=json.loads(raw)
 assert zero(v['actor_rc']) and v['wrapper']['status']=='command_exited' and zero(v['wrapper']['phone']['rc'])
 assert v['wrapper']['phone']['stderr']==''
 return raw,v
def all_pins(value):
 out=set()
 def walk(v):
  if isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v):out.add(v)
  elif isinstance(v,dict):
   for x in v.values():walk(x)
  elif isinstance(v,list):
   for x in v:walk(x)
 walk(value);return out
ap=argparse.ArgumentParser()
ap.add_argument('--inputs',type=Path,required=True);ap.add_argument('--inputs-sha256',required=True)
ap.add_argument('--seal-host-candidate-once',action='store_true',required=True)
a=ap.parse_args();iraw=read(a.inputs,a.inputs_sha256);i=json.loads(iraw)
assert i['schema']=='hepta.module-r7-r3.actual-finalization-inputs.v1' and i['root_reviewed_actual_inputs'] is True
oldraw=read(OLD/'module/MODULE-MANIFEST-v150-r7-r2.json','1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd',32052)
for row in json.loads(oldraw)['files']:read(OLD/'module'/row['path'],row['sha256'],row['bytes'])
binding=json.loads(read(OLD/'module/seal-binding.json','<PRIVATE_BOUND_SHA256_001_REQUIRED>',52196))
assert binding['boot_id']==BOOT and binding['provider_source_seal_sha256']==SOURCE
# Root's original failed task closures and exact original stop/capture process outcomes.
r=i['retirement'];qraw=actual(r['report']);quiet=json.loads(qraw)
oraw=actual(r['operator_result']);operator=json.loads(oraw)
craw=actual(r['capture']);capture=json.loads(craw)
wraw,wrapper=actual_operation(r['operation']);jraw,j=actual_job(r['host_terminal'])
cwraw,cw=actual_operation(r['capture_operation']);cjraw,cj=actual_job(r['capture_host_terminal'])
assert wrapper['wrapper']['phone']['stdout'].encode()==oraw
assert cw['wrapper']['phone']['stdout'].encode()==craw
assert quiet['schema']=='hepta.r7-r2-retirement-observation.v1'
assert quiet['state']=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED' and quiet['boot_id']==BOOT
assert quiet['original_role_identities']==IDS and quiet['global_pending_clear'] is True and quiet['server_lock_now_unheld'] is True
assert quiet['original_effect_count']==4 and quiet['original_business_status']=='provider_failed'
for name in ('old_claims_deleted','old_task_terminal_rewritten','operator_waitpid_join_claim','automatic_restart','automatic_replay'):assert quiet[name] is False,name
assert zero(quiet['model_requests']) and zero(quiet['ui_actions'])
assert quiet['signal']['target_identity']==IDS['supervisor'] and quiet['signal']['via']=='pidfd' and quiet['signal']['signal']=='SIGTERM'
assert type(quiet['signal']['attempts']) is int and quiet['signal']['attempts'] in (0,1)
scans=quiet['two_independent_censuses'];assert len(scans)==2 and scans[0]['monotonic_ns']<scans[1]['monotonic_ns']
assert all(x['members']==[] and x['kernel_group_absence']=={str(v[0]):'ESRCH' for v in IDS.values()} for x in scans)
assert operator['state']=='R7_R2_RETIRED_ORIGINALS_PRESERVED' and operator['retirement_sha256']==sha(qraw)
assert operator['operator_waitpid_join_claim'] is False and operator['live_policy_unchanged'] is True and operator['automatic_replay'] is False
assert zero(operator['new_model_requests']) and zero(operator['new_task_submissions'])
assert type(operator['supervisor_original_exit_code']) is int and 0<=operator['supervisor_original_exit_code']<=255
assert capture['state']=='ORIGINAL_CAPTURE_COMPLETE' and capture['complete'] is True and capture['issues']==[] and capture['read_only'] is True
captured={}
for row in capture['files']:
 name=row['path'];assert re.fullmatch(r'[A-Za-z0-9._/-]+',name) and '..' not in Path(name).parts and name not in captured
 raw=base64.b64decode(row['data_base64'],validate=True);assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
 captured[name]=raw
assert captured['RETIREMENT.json']==qraw and captured['OPERATOR-RESULT.json']==oraw
assert captured['original-service/exit-code']==(str(operator['supervisor_original_exit_code'])+'\n').encode()
for name in ('model.stop','sidecar.stop','provider.stop','terminal-scope'):assert 'original-service/'+name in captured
state=quiet['preserved_state']
assert state['executor_actions']==binding['original_production_journal']['executor_actions'] and state['executor_actions_empty'] is False
assert state['executor_server_lock']['dev']==65086 and state['executor_server_lock']['ino']==140464 and state['executor_server_lock']['bytes']==0
boundraw=read(B/'module-r7-r3-retirement-operator-r1/BOUND-INPUTS.json','<PRIVATE_BOUND_SHA256_002_REQUIRED>',33385);bound=json.loads(boundraw)
probe=read(B/'module-r7-r3-retirement-operator-r1/retirement_probe.py','<PRIVATE_BOUND_SHA256_003_REQUIRED>',50182)
tree=ast.parse(probe);nodes=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BOUND' for t in n.targets)]
assert len(nodes)==1 and ast.literal_eval(nodes[0])==bound
expected_cases={c['action_id']:c for c in bound['cases']}
assert len(expected_cases)==4 and len({c['case_key'] for c in bound['cases']})==4
assert set(state['executor_original_actions'])==set(expected_cases)
for action_id,action in state['executor_original_actions'].items():
 case=expected_cases[action_id]
 assert action['state']==case['expected_receipt_state'] and action['exit_code']==case['expected_exit_code']
 assert action['waitpid_joined'] is True and action['process_group_absent'] is True
 assert set(action['files'])=={'intent.json','receipt.json','stdout.bin','stderr.bin'}
 assert action['files']['receipt.json']['sha256']==case['receipt_sha256']
assert sorted((c['expected_receipt_state'],str(c['expected_exit_code'])) for c in expected_cases.values())==[('completed','68'),('completed','68'),('timed_out','None'),('timed_out','None')]
# The actual new kernel serialization is independent of the offline serialization.
p=i['policy'];live=actual(p['live_binary']);auditraw=actual(p['live_audit']);audit=json.loads(auditraw)
applyraw=actual(p['apply_report']);apply=json.loads(applyraw);rulesraw=actual(p['rules_manifest']);rules=json.loads(rulesraw)
pwr,pw=actual_operation(p['apply_operation']);pjr,pj=actual_job(p['apply_host_terminal'])
ajr,aj=actual_job(p['audit_host_terminal'])
assert len(live)==2667536 and sha(live)!=OLDLIVE
assert audit['status']=='PASS' and audit['check_count']==audit['passed_count']==24
assert {sha(live),OFFLINE,OLDLIVE}.issubset(all_pins(audit))
assert {FULL,DELTA,OFFLINE,sha(live),sha(auditraw),sha(applyraw)}.issubset(all_pins(rules))
assert sha(live) in all_pins(apply) and OLDLIVE in all_pins(apply)
assert any(v is True for k,v in apply.items() if 'enforc' in k.lower()) or 'Enforcing' in applyraw.decode()
offline_report=actual(p['offline_full_report'])
assert len(offline_report)==1693 and sha(offline_report)=='70583b36b3f447654f3193772cfd6af6f2b491b49c3ffd1735f84d35d4eea745'
assert OFFLINE in all_pins(json.loads(offline_report))
offline_pair_report=actual(p['offline_pair_report'])
assert sha(offline_pair_report)=='b2be862708d3e36b8431e0eedffc9de3b0be67f602ae5087e24d30b5e951ac02'
offline_value=json.loads(offline_pair_report);assert offline_value['status']=='PASS' and offline_value['check_count']==offline_value['passed_count']==44
# All production source, config, helpers and runtime inputs remain the same.
provider_dir=B/'provider-r7';sealraw=read(provider_dir/'SOURCE-SEAL-v150-r7.json',SOURCE,13783);seal=json.loads(sealraw)
providerraw=read(provider_dir/'PHONE-PAYLOAD-MANIFEST-v150-r7.json','09eac79336b7ea7b2f81252cafa4dd621bf58e898bc58eef9cd9519624510986',9620);provider=json.loads(providerraw)
archive_path=B/'provider-r7-phone-payload.tar.gz';praw=read(archive_path,'b2c676b4599928183e52f98061ff7df3cf508882be6111dfa10331526b0326b2',92352)
assert provider['source_seal_sha256']==SOURCE and len(provider['files'])==22 and len(seal['production_files'])==13
assert seal['phone_service_inputs_sha256']==binding['service_inputs_sha256'] and seal['configuration']['sha256']==binding['configuration_sha256']
for row in seal['production_files']+seal['operator_helpers']:read(provider_dir/row['path'],row['sha256'],row['bytes'])
entryraw=read(provider_dir/'validation/REAL-ENTRY-PREFLIGHT.json','24a1bb229668b65f8b073def057602aa628e35808e7dba1987c5b44d51538fce',7438)
entry=json.loads(entryraw);assert entry['state']=='HOST_ENTRY_PIN_CLOSURE_CONFIRMED' and entry['actual_source_used_without_function_substitution'] is True
srcprep=json.loads(read(D/'SOURCE-PREPARATION.json'));assert srcprep['unsealed'] is True and srcprep['old_module_manifest_sha256']==sha(oldraw)
source_rows={x['path']:x for x in srcprep['files']}
for row in source_rows.values():read(D/row['path'],row['sha256'],row['bytes'])
assert sha(read(D/'module-root/sepolicy.rule'))==FULL
census=read(D/'activation-payload/proc_and_original_gate.py','bebb33aca72dcb955c45e0b871d21b16e1b89ce6c7fb312c4ddee8e9ed367e33',4929)
# No output is created until every actual input above has been admitted.
out=D/'sealed-module-v150-r7-r3';out.mkdir(mode=0o700);module=out/'module';module.mkdir(mode=0o700)
for name,row in source_rows.items():
 if name.startswith('module-root/'):put(module/name.split('/',1)[1],read(D/name),0o700 if name.endswith('/service.sh') else 0o600)
for path in sorted((OLD/'module/evidence').rglob('*')):
 if path.is_file():put(module/'evidence'/path.relative_to(OLD/'module/evidence'),read(path))
evidence={'R7-R2-RETIREMENT.json':qraw,'R7-R2-RETIREMENT-OPERATOR.json':oraw,'R7-R2-RETIREMENT-CAPTURE.json':craw,
 'R7-R2-RETIREMENT-OPERATION.json':wraw,'R7-R2-RETIREMENT-HOST-TERMINAL.json':jraw,
 'R7-R2-RETIREMENT-CAPTURE-OPERATION.json':cwraw,'R7-R2-RETIREMENT-CAPTURE-HOST-TERMINAL.json':cjraw,
 'R7-R3-ACTUAL-LIVE-POLICY-APPLY.json':applyraw,'R7-R3-ACTUAL-LIVE-POLICY-AUDIT.json':auditraw,
 'R7-R3-POLICY-RULES-MANIFEST.json':rulesraw,'R7-R3-POLICY-APPLY-OPERATION.json':pwr,
 'R7-R3-POLICY-APPLY-HOST-TERMINAL.json':pjr,'R7-R3-POLICY-AUDIT-HOST-TERMINAL.json':ajr,
 'R7-R3-FULL-POLICY-OFFLINE-REPORT.json':offline_report,'R7-R3-PAIRED-POLICY-OFFLINE-SEMANTIC-REPORT.json':offline_pair_report,'R7-R3-ACTUAL-FINALIZATION-INPUTS.json':iraw}
for name,raw in evidence.items():put(module/'evidence'/name,raw)
put(module/'activation-inputs.tsv',BOOT+'\t'+sha(live)+'\n')
binding['module_id']='trillionnium_hepta_phone_local_v150_r7_r3';binding['module_attempt']=binding['module_release']='v150-r7-r3'
binding['previous_module_must_remain_disabled']='trillionnium_hepta_phone_local_v150_r7_r2'
binding['history_path']='/data/adb/trillionnium-hepta-phone-local-v150-r7-r3'
binding['executor_log_root']=H+'/executor-r6/module-history-r7-r3'
binding['policy_source_sha256']=FULL;binding['policy_rules_manifest_sha256']=sha(rulesraw)
binding['policy_full_parser_output_sha256']=OFFLINE;binding['policy_full_parser_report_sha256']=sha(offline_report)
binding['live_policy_sha256']=sha(live);binding['live_policy_semantic_audit_sha256']=sha(auditraw);binding['live_policy_application_sha256']=sha(applyraw)
binding['policy_scope']='Actual three Binder and dump-pipe permissions only; all other policy content preserved by actual live audit. Fresh health/business remain unqualified.'
binding['original_production_journal']=copy.deepcopy(state)
binding['current_boot_r7_r2_retirement']={'result_sha256':sha(qraw),'operator_sha256':sha(oraw),'capture_sha256':sha(craw),
 'actual_operation_sha256':sha(wraw),'actual_host_job_terminal_sha256':sha(jraw),'host_actor_phone_exit_codes':[0,0,0],
 'android_result_path':H+'/module-retire-r7-r2-for-r7-r3-01/RETIREMENT.json',
 'android_operator_path':H+'/module-retire-r7-r2-for-r7-r3-01/OPERATOR-RESULT.json',
 'original_role_identities':IDS,'original_supervisor_exit_code':operator['supervisor_original_exit_code'],
 'all_four_groups_absent_two_censuses_and_kernel_esrch':True,'operator_waitpid_join_claim':False,
 'original_timed_out_actions_preserved':2,'original_completed_exit68_actions_preserved':2,'original_effect_count':4,'old_tasks_not_replayed':True}
parent_census_path=binding['census_fix']['path']
assert parent_census_path==H+'/module-r7-activation-r2/proc_and_original_gate.py'
assert binding['census_fix']['bytes']==4905 and binding['census_fix']['sha256']=='12a74aa99d56d780f6e3a6e420d5480db35ab7399b58f9b3b840839741be46e8'
parent_census_rows=[row for row in binding['payloads'] if row['path']==parent_census_path]
assert len(parent_census_rows)==1
new_census_path=H+'/module-r7-activation-r3/proc_and_original_gate.py'
assert not any(row['path']==new_census_path for row in binding['payloads'])
binding['census_fix'].update(path=new_census_path,bytes=len(census),sha256=sha(census),retired_groups=binding['census_fix']['retired_groups']+[x[0] for x in IDS.values()])
parent_census_rows[0].update(path=new_census_path,bytes=len(census),sha256=sha(census))
assert sum(row['path']==new_census_path for row in binding['payloads'])==1
assert not any(row['path']==parent_census_path for row in binding['payloads'])
binding['payloads'].sort(key=lambda x:x['path']);assert len(binding['payloads'])==44 and len({x['path'] for x in binding['payloads']})==44
binding['reviewed_for_installation']=False;binding['host_source_and_input_review_complete']=True;binding['phone_installation_authorized_by_host_seal']=False
binding['existing_provider_source_config_not_overwritten']=True
binding['qualification'].update(current_boot_ready='not_started',new_zero_tool_health='not_run_new_nonce_required',business19='not_run_on_final_combination')
binding['scope']='r7-r3 changes only module namespace and the independently audited three Binder and dump-pipe permissions. Provider, model, executor, native core and budgets remain unchanged. Current nonempty safe-terminal action journal is retained.'
for path in sorted((module/'evidence').iterdir()):binding['source_evidence'][path.name]={'bytes':path.stat().st_size,'sha256':sha(read(path))}
put(module/'seal-binding.json',enc(binding))
put(module/'payload-inputs.sha256',''.join(x['sha256']+'  '+x['path']+'\n' for x in binding['payloads']))
artifacts={str(p.relative_to(module)):sha(read(p)) for p in (module/'evidence').iterdir() if p.is_file()}
artifacts[H+'/module-r5-activation/activation_original_gate.py']='23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e'
artifacts[binding['census_fix']['path']]=sha(census)
artifacts[H+'/module-retire-r7-r2-for-r7-r3-01/RETIREMENT.json']=sha(qraw)
artifacts[H+'/module-retire-r7-r2-for-r7-r3-01/OPERATOR-RESULT.json']=sha(oraw)
artifacts[binding['current_boot_retirement_evidence']['android_result_path']]=binding['current_boot_retirement_evidence']['result_sha256']
for row in provider['files']:artifacts[row['android_target']]=row['sha256']
put(module/'activation-artifacts.sha256',''.join(pin+'  '+name+'\n' for name,pin in sorted(artifacts.items())))
put(out/'activation-payload/proc_and_original_gate.py',census)
# Keep exact provider bytes for reproduction; the installer must only verify existing copies.
payload_dir=out/'provider-payload';payload_dir.mkdir(mode=0o700)
with tarfile.open(archive_path,'r:gz') as t:
 members=t.getmembers();assert len({m.name for m in members})==len(members)
 assert all((m.isfile() or m.isdir()) and not m.name.startswith('/') and '..' not in Path(m.name).parts for m in members)
 files={m.name:m for m in members if m.isfile()};assert set(files)=={r['archive_path'] for r in provider['files']}
 for row in provider['files']:
  raw=t.extractfile(files[row['archive_path']]).read();assert len(raw)==row['bytes'] and sha(raw)==row['sha256'];put(payload_dir/row['archive_path'],raw)
put(payload_dir/'provider-payload.sha256',''.join(r['sha256']+'  '+r['archive_path']+'\n' for r in provider['files']))
manifest={'schema':'hepta.phone-local.module-manifest.v150.r7.attempt3','module_id':binding['module_id'],'module_attempt':'v150-r7-r3',
 'provider_source_seal_sha256':SOURCE,'configuration_sha256':binding['configuration_sha256'],'service_inputs_sha256':binding['service_inputs_sha256'],
 'native_apps_manifest_sha256':binding['native_apps_manifest_sha256'],'policy_source_sha256':FULL,'policy_rules_manifest_sha256':sha(rulesraw),
 'live_policy_sha256':sha(live),'live_policy_semantic_audit_sha256':sha(auditraw),'files':[],'payload_files':binding['payloads'],
 'new_activation_payload':{'path':binding['census_fix']['path'],'bytes':len(census),'sha256':sha(census)},
 'included_provider_payload_manifest_sha256':sha(providerraw),'included_provider_archive_sha256':sha(praw),'included_provider_files':provider['files'],
 'provider_payload_mode':'verify_existing_only_no_overwrite','r7_r2_actual_retirement_sha256':sha(qraw),'r7_r2_operator_result_sha256':sha(oraw),
 'r7_r2_original_supervisor_exit_code':operator['supervisor_original_exit_code'],'original_actions_preserved_count':4,'original_actions_empty':False,
 'r7_entry_preflight_sha256':sha(entryraw),'original_task_and_draft_closure_required_before_install':True,'phone_installation_authorized_by_host_seal':False,
 'prior_claims_logs_and_failed_tasks_preserved':True,'cold_boot_qualified':False,'business19_qualified':False,'new_health_observed':False}
for path in sorted(module.rglob('*')):
 if path.is_file():raw=read(path);manifest['files'].append({'path':str(path.relative_to(module)),'bytes':len(raw),'sha256':sha(raw)})
mp=put(module/'MODULE-MANIFEST-v150-r7-r3.json',enc(manifest))
sp=put(module/'module-inputs.sha256',''.join(sha(read(p))+'  '+str(p.relative_to(module))+'\n' for p in sorted(module.rglob('*')) if p.is_file()))
put(module/'SEALED','HEPTA_PHONE_LOCAL_V150_R7_R3_REVIEWED_INPUTS_BOUND\n')
def owned_filter(member):
 assert member.isfile() or member.isdir()
 member.uid=member.gid=0;member.uname=member.gname='root';member.mtime=0
 member.mode=0o700 if member.isdir() or member.name=='module/service.sh' else 0o600
 member.pax_headers={}
 return member
archive=D/'sealed-module-v150-r7-r3.tar.gz'
with tarfile.open(archive,'x:gz',format=tarfile.PAX_FORMAT) as t:
 for name in ('module','activation-payload','provider-payload'):t.add(out/name,arcname=name,recursive=True,filter=owned_filter)
araw=read(archive)
with tarfile.open(archive,'r:gz') as t:
 members=t.getmembers();assert len({m.name for m in members})==len(members)
 for m in members:
  assert m.uid==m.gid==0 and m.uname==m.gname=='root'
  assert m.mode==(0o700 if m.isdir() or m.name=='module/service.sh' else 0o600)
 actual_files={m.name:m for m in members if m.isfile()}
 expected={str(p.relative_to(out)):p for name in ('module','activation-payload','provider-payload') for p in (out/name).rglob('*') if p.is_file()}
 assert set(actual_files)==set(expected)
 for name,path in expected.items():assert t.extractfile(actual_files[name]).read()==read(path)
bundle={'schema':'hepta.phone-local.module-bundle.v150.r7.attempt3','archive':{'file':archive.name,'bytes':len(araw),'sha256':sha(araw)},
 'module_manifest':mp,'module_input_sums':sp,'module_id':binding['module_id'],'activation_payload':manifest['new_activation_payload'],
 'existing_provider_file_count':22,'new_provider_file_count':0,'total_existing_and_new_payloads':44,
 'provider_payload_mode':'verify_existing_only_no_overwrite','tar_all_members_root_owned_prescribed_modes':True,
 'old_api_keys_helpers_original_gate_journals_claims_service_inputs_not_overwritten':True,
 'phone_installation':False,'service_start':False,'model_requests':0}
bp=put(out/'BUNDLE.json',enc(bundle))
print(json.dumps({'status':'SEALED_HOST_ONLY_NEW_ATTEMPT','archive':bundle['archive'],'manifest':mp,'sums':sp,'bundle':bp,'payloads':44,'provider_existing_verified':22,'phone_calls':0,'model_requests':0}))
