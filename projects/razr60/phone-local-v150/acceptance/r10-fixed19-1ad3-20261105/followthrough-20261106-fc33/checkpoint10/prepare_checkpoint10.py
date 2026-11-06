import json,hashlib,pathlib,datetime
R=pathlib.Path('/workspace/scratch/fc33eac909ab')
P='projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/'
D=R/'review/checkpoint10'
B='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
def j(p):return json.loads((R/p).read_text())
def desc(p):
 b=(R/p).read_bytes();return dict(path=p,bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def write(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
def payload(env):return json.loads(env['content'][0]['text'])
def controller(p,expected):
 x=j(p);s=payload(x['status']);r=payload(x['read'])
 assert s['exit_code']==expected and s['output_complete'] and s['output_durable'] and not s['timed_out'] and not s['automatic_retry'] and r['stdout']['eof'] and r['stderr']['eof']
 return dict(job_id=s['job_id'],exit_code=s['exit_code'],stdout_bytes=r['stdout']['size'],stderr_bytes=r['stderr']['size'],output_complete=True,output_durable=True,automatic_retry=False,controller=desc(p)),r
D.mkdir(exist_ok=True)
assert not any(D.iterdir()), "checkpoint directory must be empty before complete generation"
old=j('review/checkpoint09/STATE.json')
freeze,fr=controller('review/R6-runtime-freeze01/ROOT-ACTUAL-FREEZE-CONTROLLER.original.json',0)
freeze['actual_output']=json.loads(fr['stdout']['text'])
freeze['actual_argv_isolated_flag']=False
freeze['actual_argv_review']=desc('review/R6-lease-budget-review/R6-FREEZE-ACTUAL-ARGV-REVIEW.json')
rec=j('review/R5-neg01-bound02-recovery01/host-reader/HOST-VERIFICATION.PUBLIC.original.json')
assert rec['owned_recovery_closed'] is True and rec['host_validation_error'] is None
root,rr=controller('review/R6-component-preparer01/ROOT-NEG01-EXECUTION-CONTROLLER.original.json',1)
failure_row=payload(j('review/R6-component-preparer01/ROOT-NEG01-FAILURE-READ.original.mcp.json'))['files'][0]
failure=json.loads(failure_row['text'])
actor_row=payload(j('review/R6-component-preparer01/ROOT-NEG01-ACTOR-FAILURE-READ.original.mcp.json'))['files'][0]
actor=json.loads(actor_row['text'])
neg,nr=controller('review/R6-negative-source-binding03/ROOT-ACTUAL-PUBLICATION-CONTROLLER.original.json',0)
neg.update(actual_output=json.loads(nr['stdout']['text']),independent_full_source_archive_pending=True)
case,cr=controller('review/R6-case-controller-source-fix01/publication/ROOT-ACTUAL-DERIVE-CONTROLLER.original.json',0)
case.update(actual_output=json.loads(cr['stdout']['text']),prior_failed_job_retained='1a1b2a31057-fc05-7f16',whole_source_inverse=True,independent_archive_pending=True)
state=dict(schema='hepta.fc33.fixed19-followthrough.checkpoint10.v1',scope='USER_REQUESTED_ALL_19_CURRENT_TUPLE_QUALIFICATION_CONTINUES',recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),repository_base_commit='53df13a34a4281e18fd6d7153a338ae57a78c418',prior_immutable_state=desc('review/checkpoint09/STATE.json'),prior_states_and_failures_not_rewritten=True)
state['current_tuple']=dict(combination_sha256='7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411',runtime_manifest=dict(path=B+'/native-guard-r10-r1-operator-fc33-native-v3-r6/runtime/MANIFEST.json',bytes=59400,sha256='270357b7649af61414d31580b3c1eaddc47174bd1bac3c8adfc02934a92c8cf5'),root_manifest=dict(path=B+'/native-guard-r10-r1-operator-fc33-native-v3-r6/root-chain/SOURCE-MANIFEST.json',bytes=51678,sha256='9da8d53ebfba3e11f2406c0a59964923ff4709052fad2d5df3d2eaff8b7ec8a4'),shared_manifest_sha256='cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1',production15_unchanged_from_R5=True,runtime_members=38,shared_members=17,source_parent_count=1,maximum_native_chain=12,maximum_component_roles=42,inventory_roots_before_new_cases=44,inventory_roots_after_two_new_cases=50)
state['actual_R6_runtime_freeze']=freeze
state['R6_source_review']=dict(assembly=desc('review/R6-root-final01/ASSEMBLY.json'),six_source_changes_only=True,initial_scope_lease_seconds=900,minimum_prelaunch_margin_seconds=510,component_sender_timeout_seconds=660,listener_seconds=420,native_turn_seconds=300,native_setup_bridge_seconds=120,native_setup_root_seconds=135,one_send_one_fork_unchanged=True,business_sender=dict(path=B+'/send_new_native_task_r5_fc33_r6.py',bytes=41355,sha256='f90c6ffbf3278b22bf3a48bf055c5ca1cf43c3073c5cc7a852dd09a4cf2eab73'))
state['closed_R5_bound02_owned_recovery']=dict(state=rec['state'],owned_recovery_closed=True,public=desc('review/R5-neg01-bound02-recovery01/host-reader/HOST-VERIFICATION.PUBLIC.original.json'),phone_job='1a1b29971ae-fc05-7ed9',independent_reader_job='1a1b29fbca1-fc05-7f00',actual_result=rec['actual_result'],checks=rec['checks'],files_removed=78,directories_removed=9,operations=87,final_absences=18,protected_roots=44,protected_entries=3823,protected_complete_bytes=44353573,fd_baseline_restored=True,fixed19_credit=0,original_failed_case_qualification=rec['original_failed_case_qualification'])
state['current_attempt']=dict(label='root-r10-neg01-fc33-r6-bound01',nonce='5f94c6a88805eefb0e2320cae5265d46',nonce_permanently_consumed=True,plan_sha256='c702b537ef3dc894b1f6b4dd6691a995fb0763ab6fa83613711d75e90a587109',root=root,state='FAILED_BEFORE_SENDER_PREPARED_AT_INITIAL_UI_DUMP',actor_failure={k:actor_row[k] for k in ('path','size','sha256')},actor_failure_detail=actor,root_failure={k:failure_row[k] for k in ('path','size','sha256')},root_fixture_attempts=failure['root_fixture_attempts'],initial_wake_collapse_and_activity_launch_occurred=True,sender_reported_send_attempts=0,sender_reported_restore_attempts=0,sender_reported_restore_state='RESTORE_NOT_AUTOMATED_INPUT_OUTCOME_UNCONFIRMED',no_zero_effect_inference_from_absent_receipts=True,exit137_cause_unknown=True,owned_recovery_closed=False,independent_host_original_preservation_and_exact_scope_recovery_in_progress=True,no_old_identity_replay=True,current_runtime_tuple_unchanged=True,component_qualified=False,business_qualified=False)
state['actual_R6_source_stages']=dict(release=dict(job_id='1a1b29c82c3-fc05-7eec',exit_code=0,derivation_sha256='d965569c4f53d2835b442c9e2c5edc5a7a85f1fbab24a50769033dcf876954db',consumer_sha256='95e37e85471ee88042126aca0c0a9c878689e1d5c08256f471457d161bafc6d0',readiness_sha256='87d9302eb80b04d80b973d50c44302c2f831a617ba797e63b4f0472cec58c611'),controllers=dict(job_id='1a1b29f7d36-fc05-7efd',exit_code=0,derivation_sha256='897294862510d7805bd92d4fd24544f185e23d8dd75532aada3643b5c5c4d514',files=7),e2e_sources=dict(job_id='1a1b29fa87e-fc05-7eff',exit_code=0,binding_sha256='6e770848dcebe85a5bdbd3bdb49a8e70e7baceea99ad54edbe09a00b6c2a8827',files=49,coordinator_sha256='69bdd4e00b364d9e8451d0c3306f29474240478d8e992064e3d4b4e99f48c30b'),case_controller=case,all_actual_BUILD_READY_and_case_inputs_unbound=True,phone_calls=0)
state['actual_NEG03_09_source03']=neg
state['final_source_NEG10_NEG14']=old['final_source_NEG10_NEG14']
state['final_source_NEG10_NEG14']['R6_production15_unchanged']=True
state['historical_NEG01']=old['preserved_NEG01']
state.update(new_whole_cases_closed=[],current_tuple_component_cases_closed=[],full19_qualified=False,actual_BUILD=None,actual_install=None,actual_READY=None)
state['remaining_actual_dependencies']=['Complete preservation and exact recovery of R6 bound01 unstarted scope without upgrading failed/unknown states','New R6 NEG01 and ordered NEG02 real guard/closure/late inventory','Actual sealed BUILD, installation and complete four-role READY originals','Four original E2E tasks with their complete requested conditions and same real native COMP01 return evidence','NEG03-09 original protocol layers, cancellation/disconnect/timeout results and cleanup','Bind complete NEG10-14 host evidence to actual BUILD and independently observed installed15 sources']
write(D/'STATE.json',state)
(D/'README.md').write_text('''# Fixed19 follow-through — checkpoint10

工作继续。当前 R6 正式组合尚未取得新整项资格，不宣称19/19通过。

R5 bound02 的未启动暂存已独立恢复闭合：78文件、9目录、87次精确删除与18处最终缺失；44个受保护根的3823项、44,353,573字节完整内容一致，FD回到实测基线。恢复不计业务或组件通过。

R6 runtime/root 已真实冻结，保留生产15源码；完成 modal 关闭逻辑与同一初始租期、发送及初始化时间预算的精确更改。真实 freeze argv 没有 -I/-B，原回执与专门评审保留，不虚构该标志。

新的 R6 NEG01 bound01 在首次 uiautomator dump 返回137/Killed后失败，未到发送步骤。原nonce永久消费，实际初始唤醒/收起/Activity启动已发生；缺少后续回执不能被推断为零效果。退出137的原因尚未知，暂存保全及精确恢复继续，同一R6组合保持。

R6 release、安装控制器、E2E源码及四原用例控制器均实际派生成功。第四段原先因嵌套descriptor键序失败，完整原件保留；一处规范化修复通过实际相同binder全字节验证后，仅新第四段执行成功。NEG03–09共11源码族、7未绑定执行模板已实际发布，尚无物理任务资格。E2E phase兼容及空原件reader修复的全部实际控制原件一并保存，组数不混加。

下一步完成当前暂存恢复，继续同组合NEG01/02、BUILD/安装/READY、四E2E与COMP、各负例物理或原协议规定层。NEG10–14已具备最终生产源码的主机证据，仅待实际BUILD与安装源码绑定。不新增RSS或模型槽位门槛。

公开包排除私有XML、草稿与phone结果包；完整原件引用保留。STATE.json记录实际边界，历史失败与未知状态不改写。
''')
entries={}
def add(e):
 assert e['mode']=='100644' and e['type']=='blob' and e['path'].startswith(P)
 if e['path'] in entries:assert entries[e['path']]==e
 entries[e['path']]=e
def check(local,n,sha,git):
 b=pathlib.Path(local).read_bytes();assert len(b)==n and hashlib.sha256(b).hexdigest()==sha
 assert hashlib.sha1(('blob '+str(n)+'\0').encode()+b).hexdigest()==git
for path,pre in [('review/R5-neg01-bound02-recovery01/GIT-BLOB-MAP.json',P+'recovery-r5-bound02-actual-public/'),('review/R6-checkpoint10-public-blobs01/GIT-BLOB-MAP.json',P+'checkpoint10/')]:
 m=j(path)
 for row in m['files']:check(row['local_path'],row['bytes'],row['sha256'],row['git_blob_sha'])
 for e in m['tree_entries']:add(dict(e,path=pre+e['path']))
m=j('review/e2e-coordinator-phase-compat/GIT-BLOB-MAP.json')
for row in m['files']:check(R/'review/e2e-coordinator-phase-compat'/row['relative_path'],row['bytes'],row['sha256'],row['blob_sha'])
for e in m['tree']:add(e)
m=j('review/R5-negative-source-empty-original-repair01.GITHUB-BLOBS.json')
for row in m['files']:
 check(row['local_path'],row['bytes'],row['sha256'],row['blob_sha']);add(dict(path=row['relative_path'],mode='100644',type='blob',sha=row['blob_sha']))
m=j('review/R6-negative-source-binding03/GIT-BLOB-MAP.json')
for row in m['files']:check(R/'review/R6-negative-source-binding03'/row['path'],row['bytes'],row['sha256'],row['blob_sha'])
for e in m['tree_entries']:add(e)
for path,remote,sha in [
 ('review/R5-neg01-bound02-recovery01/GIT-BLOB-MAP.json',P+'recovery-r5-bound02-actual-public/GIT-BLOB-MAP.json','266730a713be9330935ac0361a5756ee689461d4'),
 ('review/R6-checkpoint10-public-blobs01/GIT-BLOB-MAP.json',P+'checkpoint10/R6-checkpoint10-public-blobs01/GIT-BLOB-MAP.json','37fdeaa5aa68d48411b8685dbc1546a5101e43ab'),
 ('review/e2e-coordinator-phase-compat/GIT-BLOB-MAP.json',P+'e2e-coordinator-phase-compat/GIT-BLOB-MAP.json','53eb561bb59cf4e68fb4318b5450132edbe0f04c'),
 ('review/R6-negative-source-binding03/GIT-BLOB-MAP.json',P+'physical-neg03-09-r6-source03/GIT-BLOB-MAP.json','fdb2b5485de762f0c9119b48f935332ce2f25126'),
 ('review/R6-negative-source-binding03/PUBLIC-WHITELIST.json',P+'physical-neg03-09-r6-source03/PUBLIC-WHITELIST.json','4e6becf12eaf6441472ff5f552b9a5419b478990')]:
 d=desc(path);check(R/path,d['bytes'],d['sha256'],sha);add(dict(path=remote,mode='100644',type='blob',sha=sha))
write(D/'EXISTING-ACTUAL-TREE-ENTRIES.json',list(entries.values()))
extra=['review/R5-negative-source-empty-original-repair01.GITHUB-BLOBS.json','review/prepare_checkpoint10.py','review/checkpoint10/STATE.json','review/checkpoint10/README.md']
for directory,pattern in [('review/R6-component-preparer01','ROOT-NEG01-*'),('review/R6-negative-source-binding03','ROOT-*'),('review/R6-source-rebind/publication','ROOT-*'),('review/R6-source-rebind/actual-stages','ROOT-*')]:
 extra.extend(str(p.relative_to(R))for p in sorted((R/directory).glob(pattern))if p.is_file())
extra.extend(str(p.relative_to(R))for p in sorted((R/'review/R6-case-controller-source-fix01').rglob('*'))if p.is_file() and not p.name.startswith('GIT-'))
out=[]
for p in sorted(set(extra)):
 remote=P+'checkpoint10/'+p.removeprefix('review/')
 if remote in entries:continue
 d=desc(p);out.append(dict(d,local_path=str(R/p),git_path=remote))
write(D/'NEW-BLOB-INPUTS.json',out)
print(json.dumps(dict(existing_actual_entries=len(entries),new_blob_inputs=len(out),state=desc('review/checkpoint10/STATE.json'))))
