#!/usr/bin/env python3
"""Verbatim Controller retry consumer with real Session permit; synthetic read IO."""
import argparse, hashlib, importlib.util, json, os, sys
from pathlib import Path
PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-observation-read-retry')

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
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
        anchors={
          'retry_failure':'    private static final class NativeObservationTransientFailure extends IllegalStateException {',
          'retry_wrapper':'    private PhoneObservation awaitAfterStaleNativeAction(',
          'await_observation':'    private PhoneObservation awaitObservation(final String id,final File directory,final TaskAuthorization.Gate authorization,final long deadline)throws Exception{',
          'await_observation_request':'    private PhoneObservation awaitObservation(final String id,final File directory,final TaskAuthorization.Gate authorization,final long deadline,\n',
          'await_raw':'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline)throws Exception{',
          'await_raw_request':'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline,\n',
          'record':'    private static void record(File directory,String name,JSONObject value)throws Exception{'}
        methods={key:extractor.body(controller,anchor) for key,anchor in anchors.items()}
        methods['service_proof']=extractor.body(service,'    static final class NativeObservationRetryProof {')
        template=(source/TEST/'ControllerReadRetryHost.template').read_text(encoding='utf-8')
        for key,body in methods.items():
            marker='{{'+key+'}}';need(template.count(marker)==1,'unique marker '+key);template=template.replace(marker,body,1)
        need('{{' not in template,'all actual methods inserted')
        generated=out/'generated/ControllerReadRetryHost.java';common.write(generated,template)
        paths=list(dict.fromkeys([*paths,generated,source/PKG/'ObservationStabilityGate.java']))
        extraction={'schema':'hepta.native-observation-controller-retry-extraction.v1','bodies_verbatim':True,
          'source_files':{name:common.meta(source/PKG/name) for name in ('LocalTaskController.java','HeptaAccessibilityService.java','NativeAppSession.java')},
          'methods':{name:{'bytes':len(body.encode()),'sha256':common.sha(body.encode())} for name,body in methods.items()},
          'task_entry_source_sha256':common.sha(run_task.encode()),'one_task_budget_reset':True,'one_original_task_deadline':True,
          'recovery_only_in_actual_stale_undispatched_branch':True,'uses_actual_Session_private_permit':True,
          'actual_create_new_write_fsync_executed':True,'producer_Android_read_schedule_is_fake':True,
          'actual_Service_drain_qualification_is_separate':True,'business_completion_verified':False}
        common.save(out/'CONSUMER-EXTRACTION.json',extraction)
        classes=out/'classes';classes.mkdir();report['compile_inputs']=[common.meta(p) for p in paths]
        for name,argv in [('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',classes,*paths]),
          ('consumer-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ControllerReadRetryHost',source,out/'CASES.json',out/'private-io'])]:
            step=common.stage(name,argv,out,env);report['steps'].append(step);need(step['exit_code']==0,'actual stage failed: '+name)
        cases=json.loads((out/'CASES.json').read_text(encoding='utf-8'))
        need(cases['all_pass'] and cases['cases']==len(cases['case_names'])==len(set(cases['case_names'])) and cases['assertions']>0,'complete unique real cases')
        report.update(all_pass=True,cases=cases,cases_file=common.meta(out/'CASES.json'),case_records={'CASES.json':common.meta(out/'CASES.json')},
          extraction_file=common.meta(out/'CONSUMER-EXTRACTION.json'),bridge_extraction_file=common.meta(out/'EXTRACTION.json'),
          generated_files={str(p.relative_to(out/'generated')):common.meta(p) for p in sorted((out/'generated').rglob('*.java'))})
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['input_after']=[common.meta(p) for p in inputs];report['inputs_unchanged']=before==report['input_after'];report['all_pass']=report['all_pass'] and report['inputs_unchanged']
        common.save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'cases':report.get('cases'),'error':report.get('error'),'result':str(out/'RESULT.json')}));return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
