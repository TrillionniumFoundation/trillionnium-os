import json,hashlib,pathlib,datetime
R=pathlib.Path('/workspace/scratch/fc33eac909ab')
P='projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/'
D=R/'review/checkpoint09';D.mkdir(exist_ok=False)
def j(p):return json.loads((R/p).read_text())
def desc(p):
 b=(R/p).read_bytes();return {'path':p,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def write(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
s=j('review/checkpoint08/STATE.json');s['schema']='hepta.fc33.fixed19-followthrough.checkpoint09.v1'
s['recorded_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
s['repository_base_commit']='7f3cdf7f0664e3656278e0da554eda91fdc28469'
rec=j('review/R5-final05-recovery02/HOST-VERIFICATION.PUBLIC.original.json')
assert rec['owned_recovery_closed'] is True and rec['host_validation_error'] is None
s['current_foreign_blocker']['owned_recovery_closed']=True
s['current_foreign_blocker']['remains_current_blocker']=False
s['current_foreign_blocker']['parent_readonly02'].update(state='ACTUAL_PARENT_RECONCILIATION_INDEPENDENTLY_IMPORTED',host_import_job='1a1b25a2cd2-fc05-7da7',host_import_exit_code=0,public_original=desc('review/R5-final05-parent-reconcile-probe02/ROOT-HOST-VERIFICATION.PUBLIC.original.json'))
s['current_foreign_blocker']['new_recovery02_preparation']['dispatched']=True
s['current_foreign_blocker']['recovery02']={'state':rec['state'],'actual_phone_job':'1a1b2682281-fc05-7dec','host_import_job':'1a1b268f9f4-fc05-7df0','phone_rc':rec['phone_rc'],'actual_result':rec['actual_result'],'checks':rec['checks'],'public_host_verification':desc('review/R5-final05-recovery02/HOST-VERIFICATION.PUBLIC.original.json'),'original_failed_case_qualification':rec['original_failed_case_qualification'],'historical_unknowns_upgraded':rec['historical_unknowns_upgraded'],'fixed19_credit':0}
s['prior_current_tuple_attempts']=[s['current_attempt']]
start=j('review/R5-SUCCESSOR02-ROOT-CONTROLLER.original.json')
st=json.loads(start['status']['content'][0]['text']);rr=json.loads(start['read']['content'][0]['text'])
failure_envelope=j('review/R5-SUCCESSOR02-FAILURE-READ.original.mcp.json')
fr=json.loads(failure_envelope['content'][0]['text'])['files'][0];f=json.loads(fr['text'])
assert st['exit_code']==1 and st['output_complete'] and st['output_durable'] and rr['stdout']['eof'] and rr['stderr']['eof']
s['current_attempt']={'label':'root-r10-neg01-fc33-bound02','nonce':'4fce1e327941e723a4f1d4c838acf684','nonce_generation_count':1,'nonce_permanently_consumed':True,'plan_sha256':'fc72f0c6547b00f7cd1da8306db130d98663d1fb48a951784b7410a8a7d23ac9','root_job':st['job_id'],'root_exit_code':st['exit_code'],'root_stdout_bytes':rr['stdout']['size'],'root_stderr_bytes':rr['stderr']['size'],'root_output_complete':st['output_complete'],'root_output_durable':st['output_durable'],'automatic_retry':False,'state':'FAILED_AT_SENDER_PREPARED_AFTER_SUCCESSFUL_PRIVATE_STAGE','failure':{k:fr[k] for k in ('path','size','sha256')},'failure_detail':f['detail'],'root_fixture_attempts':f['root_fixture_attempts'],'host_cleanup':f['host_cleanup'],'sender_public_summary':{'rc':2,'state':'PRE_SEND_OR_ACTOR_FAILURE','send_attempt_count':0,'draft_restore_attempts':1,'draft_state':'ORIGINAL_DRAFT_RESTORED','independent_underlying_host_originals_review_pending':True},'component_qualified':False,'business_qualified':False,'owned_stage_recovery_not_yet_closed':True,'no_new_nonce_until_originals_and_owned_scope_resolved':True,'controller':desc('review/R5-SUCCESSOR02-ROOT-CONTROLLER.original.json')}
n=j('review/R5-negative-source-binding02/ROOT-ACTUAL-PUBLICATION-CONTROLLER.original.json');ns=json.loads(n['status']['content'][0]['text'])
s['negative_source_publication02']={'job_id':ns['job_id'],'exit_code':ns['exit_code'],'state':'FAILED_AT_REVIEWED_SOURCE_READER_TYPED_DESCRIPTOR_BOUND','stdout_bytes':ns['log_bytes']['stdout']['stored'],'stderr_bytes':ns['log_bytes']['stderr']['stored'],'output_complete':ns['output_complete'],'output_durable':ns['output_durable'],'automatic_retry':False,'exact_descriptor_and_partial_output_independent_diagnosis_pending':True,'original_failure_retained':True,'phone_calls':0,'nonce_generated':False,'actual_BUILD':None,'actual_READY':None,'controller':desc('review/R5-negative-source-binding02/ROOT-ACTUAL-PUBLICATION-CONTROLLER.original.json')}
s['actual_e2e_source_archive']={'state':'ORIGINAL49_AND_COMPLETE_CONTROLLER_READBACK_ARCHIVED','source_files':49,'archive_files':64,'archive_bytes':7002712,'git_map':desc('review/R5-actual-e2e-bound-source/GIT-BLOB-MAP.json'),'business_qualification':False,'actual_BUILD':None,'actual_READY':None,'operator_phase_dictionary_duplicate_keyword_fix_under_review':True}
s['actual_install_build_controller_source']={'state':'ACTUAL27_SOURCE_FILES_PUBLISHED_AND_INDEPENDENTLY_READ','publication_job':'1a1b25d70f9-fc05-7db5','readback_job':'1a1b25f8f91-fc05-7dc2','files':27,'bytes':170416,'derivation_sha256':'8d7df81d1c3da3ce4f87e68c33e3b31aafa2503e658acb203655083e6505719d','package_sha256':'cf50a27c818510234731ac0922925e77d5b2575c86525842d7b6bd14aa7944b8','git_map':desc('review/install-build-controller/GIT-BLOB-MAP.json'),'actual_BUILD':None,'actual_install':None,'actual_READY':None}
s['remaining_actual_dependencies']=['Independently resolve actual NEG01 bound02 sender failure and recover only its new owned scope; do not replay consumed identity','Fresh successful current R5 NEG01 then NEG02 with real ordered closure and late inventory','Finish exact NEG03-09 source reader compatibility and E2E operator phase handling without changing production tuple','Actual sealed BUILD, installation, complete stage/start original retention and READY','E2E01-04, production/native COMP01 and NEG03-09 actual protocol outcomes','Bind already executed final-source NEG10-14 host originals to actual installed15-source tuple']
s['publication_notes'].append('Recovery02 is independently closed with zero fixed19 credit. New bound02 sender failure remains failed; its staged files were actually created. No missing receipt is treated as zero effect.')
write(D/'STATE.json',s)
(D/'README.md').write_text('''# Fixed19 follow-through — checkpoint09

工作继续，当前最终组合尚无新整项关闭，未宣称19/19通过。

## 已取得的实际结果

final05 recovery02 实际完成，独立主机读取器复核：97文件、10目录、107次有序删除、18最终缺失状态；44个原受保护根、3823项、44,353,573字节完整内容保持，15组锁和实测FD基线收尾。恢复不增加业务或组件用例信用，历史未知监督器wait未升级。

E2E现有49源码和安装控制器27源码已实际发布并完整独立读回。其完整证据包分别64和85个文件；实际BUILD、安装、READY仍未产生。准备的输入模板保持未知值为None。

## 本次实际失败及继续路径

NEG01 bound02唯一新nonce已消费。phone-stage成功，sender-preview成功，发送器公开终态rc2/send0/草稿恢复1，随后sender-prepared等待失败。Root没有启动fixture或模型。底层sender原件和本次新暂存范围仍须独立核对与恢复；不能重放本次身份或将缺回执解释为无效果。

NEG源码source02实际发布也失败，位置为当前完整策略验证器调用原件读取器时的typed descriptor bound。失败原件保留，精确descriptor及半目录诊断继续；没有手机任务、nonce、BUILD或READY。

E2E operator发现phase重复关键字兼容问题，最小修复评审中；原49文件保留，未执行E2E。

所有旧失败、未知和源候选状态快照按原字节保留。公开包没有私有手机result包、草稿、XML和foreign正文。精确当前状态见STATE.json；源码控制记录不能替代实际任务资格。
''')
entries={}
for mp in ['review/R5-actual-e2e-bound-source/GIT-BLOB-MAP.json','review/install-build-controller/GIT-BLOB-MAP.json','review/R5-negative-source-binding02.GITHUB-BLOBS.json']:
 m=j(mp)
 for row in m['files']:
  path=row.get('git_path',row.get('path'));local=pathlib.Path(row['local_path']);local=local if local.is_absolute() else R/local
  b=local.read_bytes();assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
  assert hashlib.sha1(('blob '+str(len(b))+'\0').encode()+b).hexdigest()==row['blob_sha']
  e={'path':path,'mode':'100644','type':'blob','sha':row['blob_sha']}
  if path in entries:assert entries[path]==e
  entries[path]=e
m=j('review/R5-final05-recovery02/GIT-BLOB-MAP.json')
for row in m['files']:
 b=pathlib.Path(row['local_path']).read_bytes();assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
 assert hashlib.sha1(('blob '+str(len(b))+'\0').encode()+b).hexdigest()==row['actual_blob_sha']
for e in m['tree_entries']:
 e=dict(e);e['path']=P+'recovery02-actual-public/'+e['path'];assert e['path'] not in entries;entries[e['path']]=e
write(D/'EXISTING-ACTUAL-TREE-ENTRIES.json',list(entries.values()))
extra=['review/R5-SUCCESSOR02-ACTUAL-PLAN-CONTROLLER.original.json','review/R5-SUCCESSOR02-ACTUAL-PLAN-READ.original.mcp.json','review/R5-SUCCESSOR02-ROOT-CONTROLLER.original.json','review/R5-SUCCESSOR02-FAILURE-READ.original.mcp.json','review/R5-SUCCESSOR02-SENDER-SMALL-READ.original.mcp.json','review/R5-negative-source-binding02/ROOT-ACTUAL-PUBLICATION-CONTROLLER.original.json','review/R5-negative-source-binding02.GITHUB-BLOBS.json','review/R5-final05-recovery02/GIT-BLOB-MAP.json','review/R5-actual-e2e-bound-source/GIT-BLOB-MAP.json','review/install-build-controller/GIT-BLOB-MAP.json','review/prepare_checkpoint09.py','review/checkpoint09/STATE.json','review/checkpoint09/README.md']
out=[]
for p in extra:
 d=desc(p);d['local_path']=str(R/p);d['git_path']=P+'checkpoint09/'+p.removeprefix('review/');out.append(d)
write(D/'NEW-BLOB-INPUTS.json',out)
print(json.dumps({'existing_actual_entries':len(entries),'new_blob_inputs':len(out),'state':desc('review/checkpoint09/STATE.json')}))
