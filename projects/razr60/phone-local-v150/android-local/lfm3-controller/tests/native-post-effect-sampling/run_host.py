#!/usr/bin/env python3
"""Actual HA post-effect sampling producer plus unchanged original observer cases.

Android graph/pixel/window IO and the observer's Session carrier are explicit ports.
This runner neither publishes a device qualification nor replays an action. The
unchanged read-retry gate separately executes actual NAS/LTC durable consumption.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-post-effect-sampling')
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'

def need(value,why):
    if not value:raise RuntimeError(why)

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def sha(raw):return hashlib.sha256(raw).hexdigest()

def snapshot(source):
    result=[]
    for path in sorted(source.rglob('*')):
        need(not path.is_symlink(),'no source symlink')
        if path.is_file():
            raw=path.read_bytes();result.append({'relative_path':str(path.relative_to(source)),
                'bytes':len(raw),'sha256':sha(raw),'mode':path.stat().st_mode&0o777})
    return result

def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();jdk=a.java_home.resolve();jar=a.json_jar.resolve()
    need(source.is_dir() and source not in out.parents and not out.exists(),'fresh output outside source')
    sys.dont_write_bytecode=True
    events=load(source/'tests/native-observation-events/run_host.py','post_sampling_events')
    h=events.helper(source)
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    need(all(p.is_file() for p in tools),'complete actual toolchain')
    need(jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA,'pinned JSON jar')
    roots=[source/PKG/'NativeAppEvidence.java']+[source/PKG/n for n in events.JAVA]
    roots += [source/events.TEST/n for n in events.OWN]
    roots += [source/'tests/observation-pipeline/ObserverPipelineHost.template',
        source/'tests/observation-diagnostics/run_host.py',source/TEST/'run_host.py',source/TEST/'SamplingCases.fragment']
    before=[h.meta(p) for p in roots];tools_before=[h.meta(p) for p in tools];whole_before=snapshot(source)
    out.mkdir(parents=True,mode=0o700)
    report={'schema':'hepta.post-effect-sampling-host.v1','all_pass':False,'stages':[],
        'source':str(source),'input_before':before,'tools_before':tools_before,
        'source_before':whole_before,'phone_operations':0,'android_execution':False,'model_executed':False,
        'business_completion_verified':False,'original_settle_ms':10000,'original_capture_margin_ms':2000,
        'original_transition_ms':15000,'deadline_extended':False,'action_replayed':False,
        'boundary':'Actual HA observer/admission/catches/serial drain/private proof/new capture; Graph, Android node refresh, window, pixels and Session permit are explicit host IO ports. Actual NAS/LTC durable consumer is a separate unchanged gate.'}
    try:
        generated=out/'generated';generated.mkdir()
        extraction=events.generate(source,generated,h)
        extraction=events.add_saved_graph_seed_cases(source,generated,h,extraction)
        service=(source/PKG/'HeptaAccessibilityService.java').read_text()
        host=generated/'ObserverPipelineHost.java';old=host.read_text()
        # The shared old scheduling port only gained the typed field/overload.
        # This specific gate executes the complete production exception class.
        port=h.body(old,'    static final class StaleObservation extends IllegalStateException {')
        actual=h.body(service,'    private static final class StaleObservation extends IllegalStateException {')
        text=events.replace(old,port,actual)
        guard='if(background!=null&&node!=root&&!node.refresh())throw new StaleObservation("后台子节点已不可用，需重新观察",true);'
        need(service.count(guard)==1,'one actual typed descendant refresh throw')
        cases=(source/TEST/'SamplingCases.fragment').read_text()
        need(cases.count('{{actual_descendant_guard}}')==1,'one explicit Android refresh port')
        cases=cases.replace('{{actual_descendant_guard}}','        '+guard,1)
        marker='    public static void main(String[] args)throws Exception{'
        text=events.replace(text,marker,cases+'\n'+marker)
        call='        observationIo.executor.shutdown();EventChecks.finish(args[0]);'
        replacement='        postEffectSamplingCases();\n'+call
        text=events.replace(text,call,replacement)
        inverse=events.replace(text,replacement,call)
        inverse=events.replace(inverse,cases+'\n'+marker,marker)
        inverse=events.replace(inverse,actual,port)
        need(inverse==old,'all old generated cases/production bodies retained byte for byte')
        host.write_text(text,encoding='utf-8')
        exact_methods={name:h.body(service,anchor) for name,anchor in {
            'typed_stale_exception':'    private static final class StaleObservation extends IllegalStateException {',
            'request':'    private static final class ObservationRequest {',
            'sample_worker':'    private void sampleObservation(',
            'accept_sample':'    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents,CtripFormSampleRead formRead){',
            'screenshot_worker':'    private void processScreenshot(',
            'candidate':'    private PostEffectSamplingRetry postEffectSamplingCandidate(',
            'activation':'    private void activateObservationRequest(',
            'post_admission':'    private synchronized void admitPostEffectObservation(',
            'post_owner':'    private synchronized boolean postEffectObservationOwner(',
            'pending_event':'    private void notePostEffectSamplingEvent(',
            'pending_clear':'    private void discardPostEffectSampling(',
            'new_drain':'    private void failPostEffectObservationAfterReadDrain(final ObservationRequest request,String error,final PostEffectSamplingRetry sampling){',
            'old_late_event':'    private boolean postEffectLateEventReadFailure(',
        }.items()}
        for name,body in exact_methods.items():need(body in text,'actual method must occur verbatim in compiled host: '+name)
        stop=h.body(service,'    private void requestStop() {')
        release=h.body(service,'    public synchronized void releaseTask(String taskId) {')
        need('discardPostEffectSamplingForTask(task)' in stop and 'discardPostEffectSamplingForTask(taskId)' in release,
             'production stop/release clear exact task pending')
        extraction.update(post_effect_sampling={
            'actual_methods':{k:{'bytes':len(v.encode()),'sha256':sha(v.encode())} for k,v in exact_methods.items()},
            'actual_child_refresh_guard':guard,'actual_child_guard_sha256':sha(guard.encode()),
            'actual_exception_class':True,'old_generated_fixture_inverse_equal':True,
            'old_case_files_unchanged_in_source':True,'new_cases':h.meta(source/TEST/'SamplingCases.fragment'),
            'actual_serial_executor_and_private_producer':True,'proof_not_constructed_in_new_cases':True,
            'stop_release_callsite_checked_not_full_android_lifecycle_execution':True,
            'stop_source_sha256':sha(stop.encode()),'release_source_sha256':sha(release.encode()),
            'session_permit_is_explicit_io_carrier':True,'complete_real_session_consumer_separate':True})
        h.save(out/'EXTRACTION.json',extraction)
        classes=out/'classes';classes.mkdir()
        sources=[source/PKG/n for n in events.JAVA if n not in ('HeptaAccessibilityService.java','PhoneObservation.java')]
        sources += [source/events.TEST/'EventChecks.java',host]
        report['compile_inputs_before']=[h.meta(p) for p in sources]
        for name,argv in [
            ('compile',[str(jdk/'bin/javac'),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes),*map(str,sources)]),
            ('cases',[str(jdk/'bin/java'),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObserverPipelineHost',str(out/'CASES.json')])]:
            stage=h.stage(name,argv,out);report['stages'].append(stage)
            need(stage['exit_code']==0,'actual '+name+' stage failed')
        cases_result=json.loads((out/'CASES.json').read_text())
        need(cases_result['all_pass'] and cases_result['cases']==len(set(cases_result['case_names'])),'complete unique actual cases')
        new_names=[n for n in cases_result['case_names'] if n.startswith('post_sampling_')]
        need(new_names and len(new_names)<cases_result['cases'],'old and new cases both actually executed')
        report.update(all_pass=True,cases=cases_result,new_case_names=new_names,new_case_count=len(new_names),
            retained_original_case_count=cases_result['cases']-len(new_names),cases_file=h.meta(out/'CASES.json'),
            extraction_file=h.meta(out/'EXTRACTION.json'),generated_files=[h.meta(host)])
        report['compile_inputs_after']=[h.meta(p) for p in sources]
        need(report['compile_inputs_before']==report['compile_inputs_after'],'compile sources immutable')
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['input_after']=[h.meta(p) for p in roots];report['tools_after']=[h.meta(p) for p in tools]
        report['source_after']=snapshot(source)
        report['inputs_unchanged']=before==report['input_after'];report['tools_unchanged']=tools_before==report['tools_after']
        report['source_unchanged']=whole_before==report['source_after']
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged'] and report['source_unchanged']
        h.save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'new_case_count':report.get('new_case_count'),'error':report.get('error'),'result':h.meta(out/'RESULT.json')}))
    return 0 if report['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())
