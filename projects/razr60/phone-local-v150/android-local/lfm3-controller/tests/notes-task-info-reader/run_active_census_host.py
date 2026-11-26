#!/usr/bin/env python3
"""Run the complete actual Reader/Custody with the recorded Notes transition shape.
All Android/Binder IO is inert; an optional exact terminal independently binds
the minimized topology, without pretending it contains complete TaskInfo rows."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,stat,subprocess,sys,time
sys.dont_write_bytecode=True
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
ACTUAL_SHA='9a42f76cfd0249bf1cfcb587bcdff9b2c533c0877df1520127cb107b299712a3'
EXPECTED_CASES=["recorded_569_two_two_one_discard_then_coherent_actual_reader","known_two_one_one_discard_then_coherent_actual_reader","contraction_between_discarded_activity_samples_requires_third_complete_read","unrelated_physical_root_change_does_not_expand_owned_fence","coherent_active_frame_keeps_original_single_read_path","authorized_new_root_in_coherent_frame_keeps_existing_registration_path","no_custodian_cannot_spend_active_disappearance_permission","unobserved_target_root_cannot_create_active_permission","previously_unresolved_custodian_never_revives","retired_custodian_cannot_read_active_transition","retirement_during_first_triple_prevents_retry_and_publication","unknown_during_first_triple_prevents_retry_and_publication","new_launch_during_first_triple_invalidates_frozen_owner","new_observation_during_first_triple_invalidates_frozen_owner","same_timestamp_new_observed_root_invalidates_closed_identity_map","retirement_during_final_coherent_triple_cannot_publish","root_empty_is_not_active_absence_or_cleanup_proof","new_unobserved_root_is_not_discarded_as_motion","middle_growth_is_not_monotone_disappearance","removed_root_reappearance_during_retry_is_refused","departing_id_as_foreign_leaf_is_not_absent","departing_original_token_must_be_known_before_discard","survivor_coherent_replacement_after_discard_is_still_refused","malformed_global_census_remains_unknown","partial_organizer_read_never_becomes_disappearance","original_outer_deadline_prevents_retry","original_1500ms_frame_budget_prevents_retry","three_complete_samples_are_absolute_contraction_budget","active_snapshot_constructor_is_private_and_has_no_release_or_input_port","departing_task_on_display_0_is_escape_not_absence","departing_task_on_display_1_is_escape_not_absence","departing_task_on_display_206_is_escape_not_absence","survivor_original_token_must_remain_exact","survivor_original_cookie_must_remain_exact","survivor_original_uid_must_remain_exact","survivor_original_user_must_remain_exact","survivor_original_display_must_remain_exact","survivor_original_parent_must_remain_exact","survivor_original_component_must_remain_exact"]
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def raw(path):
 need(path.is_absolute() and path.resolve()==path,'absolute regular input required')
 a=path.lstat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,'regular independent input required')
 data=path.read_bytes();b=path.lstat()
 need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'input changed while read')
 return data
def ref(path):
 data=raw(path);return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def put(path,value):
 with path.open('x',encoding='utf-8') as f:json.dump(value,f,indent=2,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
def bind_actual(path,expected):
 data=raw(path);need(len(data)==5903 and hashlib.sha256(data).hexdigest()==ACTUAL_SHA,'exact recorded broker required')
 terminal=json.loads(data);failure=terminal['personal_notes_task_info_diagnostics']['first_runtime_failure'];row=failure['actual_root_read_failure']
 before=row['before_all_roots'];middle=row['owned_display_roots'];after=row['after_all_roots']
 need(len(before)==len(middle)==2 and len(after)==1,'recorded 2/2/1 topology')
 by_id={r['task_id']:r for r in before};survivor=after[0]['task_id'];departing=next(i for i in by_id if i!=survivor)
 need(set(by_id)=={survivor,departing} and {r['task_id']for r in middle}==set(by_id),'exact known root set')
 for r in before+middle+after:
  need(r==by_id[r['task_id']] and r['user_id']==0 and r['effective_uid']==10382 and r['display_id']==706 and r['launch_cookie_count']==0,'recorded identity-equality fields')
 need(terminal['state']==expected['terminal_state'] and terminal['reason']==expected['terminal_reason'],'terminal failure is retained')
 need(failure['phase']==expected['runtime_phase'] and failure['reason']==expected['runtime_reason'],'runtime failure retained')
 need(row['stage']==expected['census_stage'] and row['sample_attempt']==expected['sample_attempt'] and row['previously_pinned_ids'] is None,'original reader stage retained')
 normalized=lambda rows:['survivor'if r['task_id']==survivor else'departing'for r in rows]
 need((normalized(before),normalized(middle),normalized(after))==(expected['before'],expected['middle'],expected['after']),'minimized topology exact')
 need(terminal['personal_notes_cleanup']['failure']==expected['cleanup_reason'] and terminal['personal_notes_cleanup']['release_api_entered'] is False,'separate cleanup refusal retained')
 return dict(original=ref(path),minimized_projection_matches=True,recorded_topology=True,complete_taskinfo_or_live_binder_reconstructed=False,phone_operations=0)
def main():
 ap=argparse.ArgumentParser()
 for name in ('source','output','java-home','json-jar'):ap.add_argument('--'+name,type=Path,required=True)
 ap.add_argument('--actual-broker-terminal',type=Path)
 a=ap.parse_args();s=a.source.resolve(strict=True);out=a.output.absolute();jdk=a.java_home.resolve(strict=True);jar=a.json_jar.resolve(strict=True)
 own=s/'tests/notes-task-info-reader';need(Path(__file__).resolve()==own/'run_active_census_host.py','run current source runner')
 need(s not in out.parents and out!=s,'output outside source');out.mkdir(parents=True,exist_ok=False)
 need(ref(jar)['sha256']==JSON_SHA,'fixed JSON jar')
 projection=own/'active-root-transition.json';minimum=json.loads(raw(projection))
 need(minimum['source_broker_sha256']==ACTUAL_SHA and minimum['source_broker_bytes']==5903 and minimum['complete_taskinfo_rows_recorded'] is False,'minimized source scope')
 actual=None
 if a.actual_broker_terminal is not None:actual=bind_actual(a.actual_broker_terminal.resolve(strict=True),minimum)
 capture=own/'synthetic-notes-census.json'
 need(ref(capture)['sha256']=='8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201' and ref(capture)['bytes']==18714,'unchanged synthetic Android task fields')
 fixture=own/'prepare_fixture.py'
 need(ref(fixture)['sha256']=='884478f84b67f4c8679f60997d96ad6ea5389a657d2e39585854f078f453686d','unchanged original inert Android ports')
 spec=importlib.util.spec_from_file_location('notes_active_read_fixture',fixture);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 stubs=module.prepare(out/'android-host-ports')
 bg=s/'src/org/trillionnium/hepta/background'
 production=['BrokerProtocol','PublicPermissionControllerUi','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','PublicOwnGroupTaskFence','PublicOwnGroupPolicy','PublicOwnGroupPhysicalFence','PublicPersonalNotesCustody','BackgroundTaskOrganizer','PublicPersonalNotesReader']
 files=[bg/(n+'.java')for n in production]+[s/'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java',own/'NotesTaskInfoReaderHostTest.java',own/'NotesActiveCensusHostTest.java']+stubs
 tracked=list(dict.fromkeys(files+[fixture,Path(__file__).resolve(),projection,capture,jar,jdk/'bin/java',jdk/'bin/javac',jdk/'lib/ct.sym']))
 if actual is not None:tracked.append(Path(actual['original']['path']))
 before=[ref(p)for p in tracked];classes=out/'classes';classes.mkdir()
 report=dict(schema='hepta.notes-active-census-gate.v1',all_pass=False,actual_record_binding=actual,recorded_topology_projection=ref(projection),compiled_complete_production=[ref(bg/(n+'.java'))for n in production],inputs_before=before,stages=[],phone_operations=0,android_runtime=False,synthetic_android_and_binder_io=True,complete_recorded_taskinfo_claimed=False)
 env=dict(os.environ)
 for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH'):env.pop(k,None)
 env.update(JAVA_HOME=str(jdk),PATH=str(jdk/'bin')+':/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
 commands=[
 ('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-proc:none','-cp',jar,'-d',classes,*files]),
 ('original-reader-cases',[jdk/'bin/java','-ea','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.background.NotesTaskInfoReaderHostTest',capture,'synthetic_derived_fixture']),
 ('active-census-cases',[jdk/'bin/java','-ea','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.background.NotesActiveCensusHostTest',capture,projection])]
 try:
  for label,argv in commands:
   argv=list(map(str,argv));start=time.monotonic()
   with(out/(label+'.stdout')).open('xb')as so,(out/(label+'.stderr')).open('xb')as se:process=subprocess.run(argv,cwd=s,env=env,stdout=so,stderr=se,timeout=120)
   stage=dict(name=label,argv=argv,exit_code=process.returncode,elapsed_seconds=time.monotonic()-start,stdout=ref(out/(label+'.stdout')),stderr=ref(out/(label+'.stderr')))
   report['stages'].append(stage);print(json.dumps({'stage':label,'exit_code':process.returncode}),flush=True)
   if label=='original-reader-cases' and process.returncode==0:
    old=json.loads(raw(out/(label+'.stdout')).decode().splitlines()[-1]);report['original_reader_cases']=old
    need(old['cases']==71 and old['assertions']==238 and old['all_pass'],'original 71 unchanged')
    for k,n,c in [('empty_activity',14,59),('first_root_bootstrap',22,116),('taskinfo_stability',12,60)]:
     need(old[k]['cases']==n and old[k]['assertions']==c,'original '+k+' unchanged')
     if k!='first_root_bootstrap':need(old[k]['all_pass'] is True,'original '+k+' pass flag')
   if label=='active-census-cases':
    cases=json.loads(raw(out/(label+'.stdout')).decode().splitlines()[-1]);report['active_cases']=cases
    need(cases['schema']=='hepta.notes-active-census-host.v1' and cases['cases']==len(EXPECTED_CASES)==39,'all active cases executed')
    need(len(cases['case_results'])==39 and {r['name']for r in cases['case_results']}==set(EXPECTED_CASES),'exact active case set')
    need(cases['maximum_complete_samples']==3 and cases['maximum_frame_ms']==1500 and cases['phone_operations']==cases['dispatch_calls']==cases['intent_redispatches']==0,'budget and authority scope')
    need(cases['all_pass'] and all(r['passed']for r in cases['case_results']),'active census case failed')
   need(process.returncode==0,label+' failed')
  report['all_pass']=True
 except BaseException as error:report['error']=type(error).__name__+': '+str(error)
 finally:
  report['inputs_after']=[ref(p)for p in tracked];report['inputs_unchanged']=report['inputs_before']==report['inputs_after'];report['all_pass'] &= report['inputs_unchanged']
  put(out/'RESULT.json',report)
 print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'result':ref(out/'RESULT.json')}),flush=True)
 return 0 if report['all_pass']else 1
if __name__=='__main__':raise SystemExit(main())
