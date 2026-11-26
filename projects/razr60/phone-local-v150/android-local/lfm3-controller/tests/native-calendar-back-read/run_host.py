#!/usr/bin/env python3
"""Actual BACK callback/Session/Controller consumer plus all original read-retry cases."""
import argparse, hashlib, importlib.util, json, os, sys
from pathlib import Path
PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-observation-read-retry')

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
EXPECTED_PENDING_NAMES=['pending_actual_loop_observes_before_next_model', 'pending_no_new_model_at_original_absolute_deadline', 'pending_successful_reads_never_renew_first_transition', 'pending_total_task_cap_clips_read_before_transition', 'pending_request_retains_original_12_second_cap', 'pending_failed_read_does_not_mint_or_spend_a_retry', 'pending_old_observation_is_not_replayed', 'pending_model_guard_refuses_before_any_read', 'pending_currentness_and_queue_guards_run_before_new_read', 'pending_cancellation_after_success_callback_blocks_model', 'pending_installed_identity_change_blocks_model', 'pending_original_96_successful_observation_limit_is_shared', 'pending_completed_transition_needs_no_additional_read', 'pending_non_native_loop_keeps_original_model_route', 'failed_dispatched_action_no_pending_keeps_original_raw_diagnostic', 'pending_outcome_journal_failure_cannot_start_read', 'pending_unknown_action_drain_cannot_start_observation', 'pending_deadline_clock_cannot_precede_original_outcome', 'pending_read_context_binds_original_owner_objects', 'pending_expired_context_never_submits_read_or_model', 'pending_new_observation_id_must_also_advance_capture_clock', 'pending_intent_io_failure_prevents_read_and_model']
def need(value,why):
    if not value:raise RuntimeError(why)
def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):ap.add_argument('--'+name,type=Path,required=True)
    args=ap.parse_args();source=args.source.resolve();out=args.output.absolute();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    sys.dont_write_bytecode=True
    common=load(source/'tests/native-query-reservation/run_host.py','retry_consumer_common')
    extractor=load(source/'tests/observation-diagnostics/run_host.py','retry_consumer_extract')
    fixture=load(source/'tests/native-stale-recovery/run_host.py','retry_consumer_fixture')
    need(source.is_dir() and not out.exists() and source not in out.parents,'fresh output outside source')
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    need(all(p.is_file() for p in tools),'complete JDK17 and JSON dependency')
    need(jar.stat().st_size==78332 and common.sha(jar.read_bytes())==common.JSON_SHA,'pinned real JSON jar')
    inputs=common.source_files(source)+tools;before=[common.meta(p) for p in inputs];out.mkdir(parents=True,mode=0o700)
    report={'schema':'hepta.native-observation-controller-retry-gate.v1','all_pass':False,'input_before':before,'steps':[],
      'phone_operations':0,'android_execution':False,'model_executed':False,'business_completion_verified':False}
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    try:
        paths,bridge_extraction=fixture.generate(source,source,out,common)
        controller=(source/PKG/'LocalTaskController.java').read_text(encoding='utf-8')
        service=(source/PKG/'HeptaAccessibilityService.java').read_text(encoding='utf-8')
        need(controller.count('nativeObservationRetryUsed=false;')==1,'one budget reset at task entry')
        run_task=extractor.body(controller,'    private void runTask(String taskId,String instruction,String expectedScopeSha256,TaskAuthorization.Gate authorization,BackgroundSession.Selection backgroundSelection){')
        need(run_task.count('nativeObservationRetryUsed=false;')==1,'budget reset belongs to actual task entry')
        need(run_task.count('long deadline=SystemClock.elapsedRealtime()+MAX_TASK_MS;')==1,'one original task deadline')
        need(run_task.count('awaitAfterStaleNativeAction(')==1,'one recovery callsite')
        stale=run_task[run_task.index('                if(outcome.stale&&!outcome.dispatched){'):]
        need(stale.index('awaitAfterStaleNativeAction(')<stale.index('                if(!outcome.accepted){'),'recovery only in un-dispatched stale branch')
        need(run_task.count('awaitInitialNativeObservation(')==1,'one initial native entry')
        need(run_task.index('awaitInitialNativeObservation(')<run_task.index('taskSteps: while(')<run_task.index('awaitModel('),'initial entry before first model loop')
        need(run_task.count('initialNativeObservationRetryUsed=false;')==1,'one independent initial budget reset')
        need(run_task.count('awaitPostEffectNativeObservation(')==1,'one post-effect observation callsite')
        need(run_task.index('activeNativeTask.modelActionOutcome(')<run_task.index('awaitPostEffectNativeObservation('),'durable outcome precedes post-effect read')
        anchors={
          'private_census_holder':'    private static final class FailedCensusDiagnostic {',
          'pending_require':'    private void requirePendingNativeObservation(',
          'pending_wrapper':'    private PhoneObservation awaitPendingNativeTransition(',
          'post_context':'    private static final class PostEffectNativeObservation {',
          'post_failure':'    private static final class PostEffectNativeObservationFailure extends IllegalStateException {',
          'post_require':'    private void requirePostEffectNativeObservation(',
          'post_wrapper':'    private PhoneObservation awaitPostEffectNativeObservation(',
          'await_action':'    private HeptaAccessibilityService.ActionOutcome awaitAction(',
          'native_query_execution':'    private static java.util.Map<String,Object> nativeQueryExecution(',
          'cleanup_unknown':'    private static final class CleanupUnknown extends Exception {',
          'initial_context':'    private static final class InitialNativeObservation {',
          'initial_failure':'    private static final class InitialNativeObservationFailure extends IllegalStateException {',
          'initial_require':'    private void requireInitialNativeObservation(',
          'initial_wrapper':'    private PhoneObservation awaitInitialNativeObservation(',
          'retry_failure':'    private static final class NativeObservationTransientFailure extends IllegalStateException {',
          'retry_wrapper':'    private PhoneObservation awaitAfterStaleNativeAction(',
          'await_observation':'    private PhoneObservation awaitObservation(final String id,final File directory,final TaskAuthorization.Gate authorization,final long deadline)throws Exception{',
          'await_observation_request':'    private PhoneObservation awaitObservation(final String id,final File directory,final TaskAuthorization.Gate authorization,final long deadline,\n',
          'await_raw':'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline)throws Exception{',
          'await_raw_request':'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline,\n            HeptaAccessibilityService.NativeObservationRetryProof retryProof)throws Exception{',
          'await_raw_calendar':'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline,\n            HeptaAccessibilityService.NativeObservationRetryProof retryProof,final CalendarFreshWait calendar)throws Exception{',
          'record':'    private static void record(File directory,String name,JSONObject value)throws Exception{'}
        methods={key:extractor.body(controller,anchor) for key,anchor in anchors.items()}
        methods['pending_loop_prefix']=extractor.section(controller,'            taskSteps: while(steps<MAX_STEPS){','                // Includes fresh observations after stale/undispatched proposals.')
        # This gate exercises actual query/pending reads, not manual fixture IO.
        # Retain the real manual-detail predicate, but make its separate route
        # explicitly unavailable rather than inventing live pixel/file authority.
        manual_anchor='                if(activeNativeTask!=null&&activeNativeTask.manualFixtureDetailReady(observation.id)){'
        manual_branch=extractor.body(controller,manual_anchor)
        need(len(manual_branch.encode())==688 and common.sha(manual_branch.encode())=='5bbc084c3f5adae4447ecb0863c99fa895f2ccc99820bf27b03b70e2a666c129',
             'exact complete manual-only task-loop branch required')
        manual_port=manual_anchor+'\n                    throw new AssertionError("manual fixture route is outside the retry consumer gate");\n                }'
        need(methods['pending_loop_prefix'].count(manual_branch)==1,'one actual manual route in pending prefix')
        methods['pending_model_guard']=extractor.section(controller,'        final boolean searchProtocol=grammar!=null&&NativeSearchDecision.SCHEMA.equals(grammar.schema);','        final LocalRuntimeConfig runtime=inference.configuration();')
        need(run_task.count('awaitPendingNativeTransition(')==1 and run_task.index('awaitPendingNativeTransition(')<run_task.index('awaitModel('),
             'actual main loop must finish pending observation before model planning')
        methods['service_proof']=extractor.body(service,'    static final class NativeObservationRetryProof {')
        methods['initial_service_proof']=extractor.body(service,'    static final class InitialObservationRetryProof {')
        methods['post_service_proof']=extractor.body(service,'    static final class PostEffectObservationRetryProof {')
        template=(source/TEST/'ControllerReadRetryHost.template').read_text(encoding='utf-8')
        for key,body in methods.items():
            marker='{{'+key+'}}';need(template.count(marker)==1,'unique marker '+key)
            compiled_body=body
            if key=='await_raw_calendar':
                need(body.count('LocalTaskController.this')==1,'one explicit enclosing Controller reference')
                compiled_body=body.replace('LocalTaskController.this','ControllerReadRetryHost.this',1)
                need(compiled_body.replace('ControllerReadRetryHost.this','LocalTaskController.this',1)==body,
                     'exact enclosing-name-only inverse')
            if key=='pending_loop_prefix':
                compiled_body=body.replace(manual_branch,manual_port,1)
                need(compiled_body.count(manual_port)==1 and compiled_body.replace(manual_port,manual_branch,1)==body,
                     'whole pending prefix inverse after fail-only manual route')
            template=template.replace(marker,compiled_body,1)
        need('{{' not in template,'all actual methods inserted')
        back=load(source/'tests/native-calendar-back-read/prepare.py','calendar_back_prepare')
        back_other=back.extend_other_generated(source,out,extractor,common)
        template=back.extend_template(source,template,extractor,controller,out,common)
        generated=out/'generated/ControllerReadRetryHost.java';common.write(generated,template)
        paths=list(dict.fromkeys([*paths,generated,source/PKG/'ObservationStabilityGate.java',source/PKG/'ActionExecutionState.java',source/PKG/'NativeOrderPreviewManual.java']))
        extraction={'schema':'hepta.native-observation-controller-retry-extraction.v1','bodies_verbatim':False,
          'all_bodies_verbatim_except_explicit_enclosing_class_name':False,
          'all_bodies_verbatim_except_enclosing_name_and_fail_only_manual_route':True,
          'manual_route':{'original_branch_bytes':len(manual_branch.encode()),
            'original_branch_sha256':common.sha(manual_branch.encode()),'compiled_port_sha256':common.sha(manual_port.encode()),
            'original_detail_predicate_verbatim':True,'whole_pending_prefix_inverse_equal':True,
            'body_always_throws':True,'manual_authority_created':False,'manual_behavior_executed':False,
            'actual_manual_value_class_compiled':common.meta(source/PKG/'NativeOrderPreviewManual.java')},
          'enclosing_class_mapping':{'method':'await_raw_calendar','from':'LocalTaskController.this',
            'to':'ControllerReadRetryHost.this','occurrences':1,'inverse_bytes_equal':True},
          'calendar_route':{'private_unconstructible_type_only_ports':True,'methods_always_throw':True,
            'all_original_calls_pass_null':True,'calendar_authority_created':False,'calendar_behavior_executed':False},
          'source_files':{name:common.meta(source/PKG/name) for name in ('LocalTaskController.java','HeptaAccessibilityService.java','NativeAppSession.java')},
          'methods':{name:{'bytes':len(body.encode()),'sha256':common.sha(body.encode())} for name,body in methods.items()},
          'task_entry_source_sha256':common.sha(run_task.encode()),'one_task_budget_reset':True,'one_original_task_deadline':True,
          'recovery_only_in_actual_stale_undispatched_branch':True,'uses_actual_Session_private_permit':True,
          'actual_create_new_write_fsync_executed':True,'producer_Android_read_schedule_is_fake':True,
          'actual_Service_drain_qualification_is_separate':True,'business_completion_verified':False,
          'post_effect_actual_awaitAction_finally_and_projection':True,'post_effect_actual_ActionExecutionState_and_Session':True,
          'post_effect_platform_action_endpoint_is_synthetic':True,'post_effect_private_proof_class_is_verbatim':True,
          'post_effect_producer_qualification_is_separate':True,'post_effect_original_task_and_transition_caps_retained':True}
        common.save(out/'CONSUMER-EXTRACTION.json',extraction)
        classes=out/'classes';classes.mkdir();report['compile_inputs']=[common.meta(p) for p in paths]
        for name,argv in [('compile',[jdk/'bin/javac','-J-Xmx768m','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',classes,*paths]),
          ('consumer-cases',[jdk/'bin/java','-Xmx512m','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ControllerReadRetryHost',source,out/'CASES.json',out/'private-io'])]:
            step=common.stage(name,argv,out,env);report['steps'].append(step);need(step['exit_code']==0,'actual stage failed: '+name)
        cases=json.loads((out/'CASES.json').read_text(encoding='utf-8'))
        need(cases['all_pass'] and cases['cases']==len(cases['case_names'])==len(set(cases['case_names'])) and cases['assertions']>0,'complete unique real cases')
        need(all(name in cases['case_names'] for name in EXPECTED_PENDING_NAMES),'all actual pending-loop regression identities required')
        report['calendar_back_test_extraction']=common.meta(out/'BACK-TEST-EXTRACTION.json');report['other_actual_await_helpers']=back_other
        report.update(all_pass=True,cases=cases,cases_file=common.meta(out/'CASES.json'),case_records={'CASES.json':common.meta(out/'CASES.json')},
          extraction_file=common.meta(out/'CONSUMER-EXTRACTION.json'),bridge_extraction_file=common.meta(out/'EXTRACTION.json'),
          generated_files={str(p.relative_to(out/'generated')):common.meta(p) for p in sorted((out/'generated').rglob('*.java'))})
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['input_after']=[common.meta(p) for p in inputs];report['inputs_unchanged']=before==report['input_after'];report['all_pass']=report['all_pass'] and report['inputs_unchanged']
        common.save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'cases':report.get('cases'),'error':report.get('error'),'result':str(out/'RESULT.json')}));return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
