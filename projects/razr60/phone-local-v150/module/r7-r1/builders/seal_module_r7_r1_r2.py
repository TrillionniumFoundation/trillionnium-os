#!/usr/bin/env python3
"""Host-only r7 sealing from frozen provider and actual old-service observations. No phone or nonce."""
import argparse,copy,hashlib,json,os,shlex,tarfile
from pathlib import Path
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r6-r2-finalization-r1/sealed-module-v150-r6-r2'
def sha(x):return hashlib.sha256(x).hexdigest()
def read(p,pin=None,size=None):
 p=Path(p);assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1,str(p)
 raw=p.read_bytes()
 if pin is not None:assert sha(raw)==pin,(str(p),'sha256')
 if size is not None:assert len(raw)==size,(str(p),'bytes')
 return raw
def enc(v):return (json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
def put(p,raw,mode=0o600):
 p=Path(p);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if isinstance(raw,str):raw=raw.encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'bytes':len(raw),'sha256':sha(raw)}
ap=argparse.ArgumentParser()
ap.add_argument('--provider-seal-sha256',required=True)
ap.add_argument('--provider-manifest-sha256',required=True)
ap.add_argument('--provider-archive-sha256',required=True)
for name in ('quiescence-json','quiescence-sha256','quiescence-operation','quiescence-operation-sha256','quiescence-job-terminal','quiescence-job-terminal-sha256','quiescence-job-id'):
 ap.add_argument('--'+name,required=True)
args=ap.parse_args()
assert args.provider_seal_sha256=='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
assert args.provider_manifest_sha256=='09eac79336b7ea7b2f81252cafa4dd621bf58e898bc58eef9cd9519624510986'
assert args.provider_archive_sha256=='b2c676b4599928183e52f98061ff7df3cf508882be6111dfa10331526b0326b2'
assert args.quiescence_sha256=='<ROOT_REVIEWED_QUIESCENCE_SHA256_REQUIRED>'
assert args.quiescence_operation_sha256=='<ROOT_REVIEWED_QUIESCENCE_OPERATION_SHA256_REQUIRED>'
assert args.quiescence_job_terminal_sha256=='<ROOT_REVIEWED_QUIESCENCE_HOST_TERMINAL_SHA256_REQUIRED>'
assert args.quiescence_job_id=='<ROOT_REVIEWED_QUIESCENCE_JOB_ID_REQUIRED>'
def under_project(p):
 p=Path(p).resolve(strict=True);assert p.is_relative_to(B.resolve(strict=True));return p

oldmanifest=read(OLD/'module/MODULE-MANIFEST-v150-r6-r2.json','9e5a8c3f9a5a7f4426d109beba1073edcfa2dfe4712760e446054b04906afb4a',27396)
for row in json.loads(oldmanifest)['files']:read(OLD/'module'/row['path'],row['sha256'],row['bytes'])
binding=json.loads(read(OLD/'module/seal-binding.json','af9b7077a57cbced1f2a484a9cd83eee6576be8e41a5c0cfc3715bf6ca8a965b',25797))
qraw=read(under_project(args.quiescence_json),args.quiescence_sha256);quiet=json.loads(qraw)
wraw=read(under_project(args.quiescence_operation),args.quiescence_operation_sha256);wrapper=json.loads(wraw)
traw=read(under_project(args.quiescence_job_terminal),args.quiescence_job_terminal_sha256);terminal=json.loads(traw)
assert terminal['job_id']==args.quiescence_job_id and terminal['exit_code']==0 and terminal['state']=='succeeded'
assert terminal['output_complete'] is True and terminal['output_durable'] is True and terminal['terminal_publication_confirmed'] is True
assert terminal['timed_out'] is False and terminal['cancelled'] is False and terminal['automatic_retry'] is False
assert wrapper['actor_rc']==0 and wrapper['wrapper']['status']=='command_exited' and wrapper['wrapper']['phone']['rc']==0
assert wrapper['wrapper_sha256']=='c5184e15ca115ce43bfae02dc8c56005ed65f717fb7cc76cdb9e5cb9c4b9dc78'
assert shlex.split(wrapper['wrapper']['phone']['command'])==['/debug_ramdisk/su','-c',read(D/'actual-r6-r2-quiescence-inputs/read_current_quiescence.sh','1878ae7f25e6400d68ffc4ce75dbf34ea980afc9adcd0dcc4c679a4f44d0cf12',14983).decode()]
assert wrapper['wrapper']['phone']['stderr']=='' and wrapper['wrapper']['phone']['stdout'].encode()==qraw
assert quiet['schema']=='hepta.module-r6-r2.read-only-quiescence.v1'
assert quiet['state']=='FOUR_ORIGINAL_GROUPS_ABSENT_ORIGINAL_STATE_PRESERVED' and quiet['boot_id']==binding['boot_id']
for k in ('state_and_originals_equal_before_after_read','outer_exit_zero_required'):assert quiet[k] is True,k
for k in ('signals_sent','model_requests','tool_execute_requests','task_submissions','state_or_claim_writes'):assert quiet[k]==0,k
assert quiet['operator_waitpid_join_claim'] is False and quiet['automatic_retry'] is False
assert quiet['next_task_or_install_authorized_by_this_report'] is False and quiet['worker_or_full_effect_quiescence_claim'] is False
assert quiet['user_draft_read_or_write'] is False and quiet['audit_denied_events']==[]
ids={'supervisor':[0,0,0,8842520],'model':[0,0,0,8842729],'sidecar':[0,0,0,8842796],'provider':[0,0,0,8842858]}
assert quiet['original_role_identities']==ids
scans=quiet['two_independent_censuses'];assert len(scans)==2 and scans[0]['monotonic_ns']<scans[1]['monotonic_ns']
assert all(x['members']==[] and x['kernel_group_absence']=={str(v[0]):'ESRCH' for v in ids.values()} for x in scans)
assert quiet['original_stopped_ready']['value']=={'schema':'hepta.daily-provider.ready.v1','pid':'<INSTANCE_PID_REQUIRED>','instance':'<INSTANCE_ID_REQUIRED>','accepting':False}
assert quiet['original_service']['module_pins']['MODULE-MANIFEST-v150-r6-r2.json']['sha256']==sha(oldmanifest)
exit_status=quiet['original_supervisor_exit_status'];exit_value=quiet['original_supervisor_exit_code']
if exit_status=='OBSERVED_ORIGINAL_EXIT_RECORD':
 assert type(exit_value) is int and 0<=exit_value<=255
 assert quiet['original_service']['history_files']['exit-code']['text']==str(exit_value)+'\n'
else:
 assert exit_status in ('UNKNOWN_MISSING_ORIGINAL_RECORD','UNKNOWN_NONCANONICAL_ORIGINAL_RECORD') and exit_value is None
journal=quiet['preserved_state']
assert journal['executor_actions']==binding['original_production_journal']['executor_actions']
assert journal['executor_server_lock']==binding['original_production_journal']['executor_server_lock']
assert journal['executor_actions_empty'] is True
provider_dir=B/'provider-r7'
sealraw=read(provider_dir/'SOURCE-SEAL-v150-r7.json',args.provider_seal_sha256)
seal=json.loads(sealraw)
providerraw=read(provider_dir/'PHONE-PAYLOAD-MANIFEST-v150-r7.json',args.provider_manifest_sha256)
provider=json.loads(providerraw)
assert provider['source_seal_sha256']==sha(sealraw)
archive_path=B/'provider-r7-phone-payload.tar.gz'
praw=read(archive_path,args.provider_archive_sha256)
assert seal['phone_service_inputs_sha256']==binding['service_inputs_sha256']
assert seal['configuration']['sha256']==binding['configuration_sha256']
assert seal['configuration_target_path']=='/var/lib/trillionnium/owner-open/phone-local-v150/local-config-r7.json'
assert seal['start_argv_inside_existing_gnu_rootfs'][2]=='/var/lib/trillionnium/owner-open/phone-local-v150/provider-r7/source/daily_phone_local.py'
assert all(row['android_target'].startswith('/data/trillionnium/owner-open/state/phone-local-v150/provider-r7/') or row['android_target']=='/data/trillionnium/owner-open/state/phone-local-v150/local-config-r7.json' for row in provider['files'])
assert len({row['android_target'] for row in provider['files']})==len(provider['files'])==22
assert len(seal['production_files'])==13
assert {r['path']:r['sha256'] for r in seal['production_files']}['source/daily_phone_local.py']=='92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3'
assert {r['path']:r['sha256'] for r in seal['production_files']}['source/provider_phone_local.py']=='8f57e86ec66e4588e2e6f43ea761f17e9ae02361791995ff2f5831a16e46dbe6'
assert len(praw)==92352

srcprep=json.loads(read(D/'SOURCE-PREPARATION.json'))
assert srcprep['old_module_manifest_sha256']==sha(oldmanifest) and srcprep['unsealed'] is True
source_rows={r['path']:r for r in srcprep['files']}
for row in source_rows.values():read(D/row['path'],row['sha256'],row['bytes'])
census=read(D/'activation-payload/proc_and_original_gate.py','0adb90db6fc4eab253ab9f96641d1ea5f689372dfdde31c9d39760d3d6c35897',4881)
out=D/'sealed-module-v150-r7-r1';out.mkdir(mode=0o700)
module=out/'module';module.mkdir(mode=0o700)
for name,row in source_rows.items():
 if name.startswith('module-root/'):put(module/name.split('/',1)[1],read(D/name,row['sha256'],row['bytes']),0o700 if name.endswith('/service.sh') else 0o600)
for path in sorted((OLD/'module/evidence').rglob('*')):
 if path.is_file():put(module/'evidence'/path.relative_to(OLD/'module/evidence'),read(path))
put(module/'activation-inputs.tsv',read(OLD/'module/activation-inputs.tsv'))
put(module/'evidence/R6-R2-ACTUAL-SERVICE-QUIESCENCE.json',qraw)
put(module/'evidence/R6-R2-ACTUAL-SERVICE-QUIESCENCE-OPERATION.json',wraw)
put(module/'evidence/R6-R2-ACTUAL-SERVICE-QUIESCENCE-HOST-TERMINAL.json',traw)
for name,pin in [('read_current_quiescence.py','58e3d66a22ebdedc399233eadd74f37db8fd8d1ba4139d2eb4e3d4b3ef1741f7'),('read_current_quiescence.sh','1878ae7f25e6400d68ffc4ce75dbf34ea980afc9adcd0dcc4c679a4f44d0cf12'),('SOURCE-SEAL.json','1a95171e5e0960043e9e99e3e6a9ff0462d377753948ed7ff355e9931986f143')]:
 put(module/'evidence'/('R6-R2-QUIESCENCE-'+name),read(D/'actual-r6-r2-quiescence-inputs'/name,pin))
entryraw=read(B/'provider-r7/validation/REAL-ENTRY-PREFLIGHT.json','24a1bb229668b65f8b073def057602aa628e35808e7dba1987c5b44d51538fce',7438)
entry=json.loads(entryraw)
assert entry['state']=='HOST_ENTRY_PIN_CLOSURE_CONFIRMED' and entry['actual_source_used_without_function_substitution'] is True
assert entry['production_file_count']==13 and entry['phone_calls']==entry['model_requests']==entry['socket_operations']==0
for case in entry['cases']:
 assert case['actual_process_exit_code']==0 and case['result']['all_13_source_files_executed'] is True and case['result']['forbidden_operation_attempts']==[]
 assert case['result']['source_bytes_before_and_after']=={r['path'].split('/')[-1]:r['sha256'] for r in seal['production_files']}
put(module/'evidence/R7-REAL-ENTRY-PREFLIGHT.json',entryraw)
for filename,pin in [('HOST-ENTRY-JOB-TERMINAL.json','7ec0935be06e6c681e22e3b99ee684a34b980c0754637ae97f3cf7ceb85513a0'),('PACKAGING-JOB-TERMINAL.json','90ff68460472825884300c1d5d431f4bcd1c8fc453ccc7ca4b4612bfddf2d104')]:
 raw=read(B/'provider-r7/validation'/filename,pin,729);status=json.loads(raw)
 assert status['state']=='succeeded' and status['exit_code']==0 and status['output_complete'] is True and status['output_durable'] is True
 put(module/'evidence'/('R7-'+filename),raw)
put(module/'evidence/R7-PROVIDER-SOURCE-SEAL.json',sealraw)
put(module/'evidence/R7-PROVIDER-PAYLOAD-MANIFEST.json',providerraw)
binding['module_id']='trillionnium_hepta_phone_local_v150_r7_r1'
binding['module_attempt']='v150-r7-r1';binding['module_release']='v150-r7-r1'
binding['provider_source_seal_sha256']=sha(sealraw)
binding['previous_module_must_remain_disabled']='trillionnium_hepta_phone_local_v150_r6_r2'
binding['current_boot_r6_r2_service_quiescence']={
 'result_sha256':sha(qraw),'result_bytes':len(qraw),'module_evidence_path':'evidence/R6-R2-ACTUAL-SERVICE-QUIESCENCE.json',
 'actual_operation_sha256':sha(wraw),'phone_wrapper_sha256':wrapper['wrapper_sha256'],
 'actual_host_job_terminal_sha256':sha(traw),'actual_host_job_id':args.quiescence_job_id,
 'host_actor_and_phone_exit_codes':[0,0,0],'original_exit_code':exit_value,'original_exit_record_status':exit_status,
 'original_role_identities':ids,'all_four_groups_absent_two_censuses_and_kernel_esrch':True,
 'no_new_request_or_tool':True,'original_claims_and_service_records_preserved':True,
 'operator_waitpid_join_claim':False,'worker_or_full_effect_quiescence_claim':False,
 'task_native_http_worker_and_draft_closure_is_a_separate_root_gate':True}
binding['inherited_latest_fields_scope']='latest_health/latest_component are historical r5 records; not current r6-r2 or r7 outcomes.'
binding['parent_historical_reviewed_for_installation']=binding['reviewed_for_installation']
binding['reviewed_for_installation']=False
binding['host_source_and_input_review_complete']=True
binding['phone_installation_authorized_by_host_seal']=False
binding['original_task_and_draft_closure_required_before_install']=True
binding['r7_entry_preflight']={'evidence':'evidence/R7-REAL-ENTRY-PREFLIGHT.json','sha256':sha(entryraw),'scope':entry['preflight_boundary'],'phone_qualified':False}
binding['history_path']='/data/adb/trillionnium-hepta-phone-local-v150-r7-r1'
binding['executor_log_root']='/data/trillionnium/owner-open/state/phone-local-v150/executor-r6/module-history-r7-r1'
binding['census_fix'].update(path='/data/trillionnium/owner-open/state/phone-local-v150/module-r7-activation-r1/proc_and_original_gate.py',bytes=len(census),sha256=sha(census),retired_groups=binding['census_fix']['retired_groups']+[0,0,0,0])
binding['roles']['provider']['argv']=['/data/adb/magisk/busybox','chroot','/data/trillionnium/owner-open/root']+seal['start_argv_inside_existing_gnu_rootfs']
binding['scope']='Host-sealed current-boot r7 named JSON model action mapping. Independent fresh model health and business acceptance remain required. All prior failures, partial stops and r6-r2 service stop records are preserved; actual service group quiescence does not replace original task/HTTP-worker/native receipt/draft closure.'
old_payloads=binding['payloads']
payloads=[copy.deepcopy(x) for x in old_payloads if not (x['path'].startswith('/data/trillionnium/owner-open/state/phone-local-v150/provider-r6-r2/') or x['path']=='/data/trillionnium/owner-open/state/phone-local-v150/local-config-r6-r2.json')]
for row in payloads:
 if row['path']=='/data/trillionnium/owner-open/state/phone-local-v150/module-r6-activation-r2/proc_and_original_gate.py':
  row.update(path=binding['census_fix']['path'],bytes=len(census),sha256=sha(census))
payloads.extend({'path':r['android_target'],'bytes':r['bytes'],'sha256':r['sha256']} for r in provider['files'])
payloads.sort(key=lambda x:x['path'])
assert len({x['path'] for x in payloads})==len(payloads)==44
assert all(not x['path'].endswith(('/api.key','/llama-api.key')) for x in payloads)
binding['payloads']=payloads
binding['qualification'].update(current_boot_ready='not_started',new_zero_tool_health='not_run_new_nonce_required',business19='not_run_on_final_combination')
for path in sorted((module/'evidence').iterdir()):
 binding['source_evidence'][path.name]={'bytes':path.stat().st_size,'sha256':sha(read(path))}
put(module/'seal-binding.json',enc(binding))
put(module/'payload-inputs.sha256',''.join(x['sha256']+'  '+x['path']+'\n' for x in payloads))
artifacts={str(p.relative_to(module)):sha(read(p)) for p in (module/'evidence').iterdir() if p.is_file()}
artifacts['/data/trillionnium/owner-open/state/phone-local-v150/module-r5-activation/activation_original_gate.py']='23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e'
artifacts[binding['census_fix']['path']]=sha(census)
artifacts[binding['current_boot_retirement_evidence']['android_result_path']]=binding['current_boot_retirement_evidence']['result_sha256']
for row in provider['files']:artifacts[row['android_target']]=row['sha256']
put(module/'activation-artifacts.sha256',''.join(pin+'  '+name+'\n' for name,pin in sorted(artifacts.items())))
put(out/'activation-payload/proc_and_original_gate.py',census)
payload_dir=out/'provider-payload';payload_dir.mkdir(mode=0o700)
with tarfile.open(archive_path,'r:gz') as t:
 members=t.getmembers()
 assert len({m.name for m in members})==len(members)
 assert all((m.isfile() or m.isdir()) and not m.name.startswith('/') and '..' not in Path(m.name).parts for m in members)
 files={m.name:m for m in members if m.isfile()}
 assert set(files)=={r['archive_path'] for r in provider['files']}
 for row in provider['files']:
  name=row['archive_path'];m=files[name]
  assert not name.startswith('/') and '..' not in Path(name).parts and m.size==row['bytes']
  raw=t.extractfile(m).read();assert sha(raw)==row['sha256'] and len(raw)==row['bytes'];put(payload_dir/name,raw)
put(payload_dir/'provider-payload.sha256',''.join(r['sha256']+'  '+r['archive_path']+'\n' for r in provider['files']))
manifest={'schema':'hepta.phone-local.module-manifest.v150.r7.attempt1','module_id':binding['module_id'],'module_attempt':'v150-r7-r1',
 'scope':'Frozen current-boot inputs for fresh bounded zero-tool health; installation/model/business/coldboot are independent.',
 'provider_source_seal_sha256':sha(sealraw),'configuration_sha256':binding['configuration_sha256'],'service_inputs_sha256':binding['service_inputs_sha256'],
 'native_apps_manifest_sha256':binding['native_apps_manifest_sha256'],'policy_source_sha256':binding['policy_source_sha256'],
 'live_policy_sha256':binding['live_policy_sha256'],'live_policy_semantic_audit_sha256':binding['live_policy_semantic_audit_sha256'],
 'files':[],'payload_files':payloads,'new_activation_payload':{'path':binding['census_fix']['path'],'bytes':len(census),'sha256':sha(census)},
 'included_provider_payload_manifest_sha256':sha(providerraw),'included_provider_archive_sha256':sha(praw),'included_provider_files':provider['files'],
 'r6_r2_actual_service_quiescence_sha256':sha(qraw),'r6_r2_supervisor_original_exit_code':exit_value,'r6_r2_supervisor_original_exit_record_status':exit_status,'historical_r5_health_status':'provider_failed','historical_r6_r1_startup_status':'failed',
 'r7_entry_preflight_sha256':sha(entryraw),'original_task_and_draft_closure_required_before_install':True,'phone_installation_authorized_by_host_seal':False,
 'old_partial_retirement_preserved':True,'old_supervisor_exit_code_fabricated':False,'prior_claims_and_logs_preserved':True,
 'cold_boot_qualified':False,'business19_qualified':False,'new_health_observed':False}
for path in sorted(module.rglob('*')):
 if path.is_file():
  raw=read(path);manifest['files'].append({'path':str(path.relative_to(module)),'bytes':len(raw),'sha256':sha(raw)})
mp=put(module/'MODULE-MANIFEST-v150-r7-r1.json',enc(manifest))
sums=''.join(sha(read(p))+'  '+str(p.relative_to(module))+'\n' for p in sorted(module.rglob('*')) if p.is_file())
sp=put(module/'module-inputs.sha256',sums)
put(module/'SEALED','HEPTA_PHONE_LOCAL_V150_R7_R1_REVIEWED_INPUTS_BOUND\n')
archive=D/'sealed-module-v150-r7-r1.tar.gz'
with tarfile.open(archive,'x:gz') as t:
 for name in ('module','activation-payload','provider-payload'):t.add(out/name,arcname=name,recursive=True)
araw=read(archive)
with tarfile.open(archive,'r:gz') as t:
 members={m.name:m for m in t.getmembers() if m.isfile()}
 expected={str(p.relative_to(out)):p for name in ('module','activation-payload','provider-payload') for p in (out/name).rglob('*') if p.is_file()}
 assert set(members)==set(expected)
 for name,path in expected.items():assert t.extractfile(members[name]).read()==read(path)
bundle={'schema':'hepta.phone-local.module-bundle.v150.r7.attempt1',
 'archive':{'file':archive.name,'bytes':len(araw),'sha256':sha(araw)},'module_manifest':mp,'module_input_sums':sp,
 'module_id':binding['module_id'],'activation_payload':manifest['new_activation_payload'],
 'new_provider_file_count':len(provider['files']),'total_existing_and_new_payloads':len(payloads),
 'old_api_keys_helpers_original_gate_journals_claims_service_inputs_not_overwritten':True,
 'phone_installation':False,'service_start':False,'model_requests':0}
bp=put(out/'BUNDLE.json',enc(bundle))
print(json.dumps({'status':'SEALED_HOST_ONLY_NEW_ATTEMPT','archive':bundle['archive'],'manifest':mp,'sums':sp,'bundle':bp,'payloads':len(payloads),'provider_files':len(provider['files']),'phone_calls':0,'model_requests':0}))
