#!/usr/bin/env python3
"""Actual full-census sampling worker plus original observer and Gate boundaries.
Android/Binder/clock and the existing Session IO carrier remain synthetic.
The old 75395 full pair is counterfactual input, never a reconstructed defb pair.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import traceback
sys.dont_write_bytecode=True
PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-ctrip-form-sampling')
GATE_SHA='2abe6a4074be6c75514755c741d10792e78e80d914e7ae063e1f43ce470d0992'
SESSION_SHA='48c3802e762baabc170056645f060df779be12ae6c9344ce4972ef55448091e4'
SERVICE_CASES=["complete_pair","archived_complete_pair","historic_boundary_future_content","same_keys","ordinary_scope","initial_scope","native_ax_scope","first_incomplete","first_not_form","protected_date","protected_query","ancestor_changed","direct_sibling_clickable_readonly_control","nested_clickable_child_rejected","missing_child","pending_child","truncated_graph","ime_unknown","window_changed","generation_changed","profile_token_changed","read_clock_reversed","missing_graph","typed_child_failure","event_content","event_other_display","event_unknown","event_untyped","event_boundary","event_foreign_window","event_foreign_package","queued_content","queued_boundary","authorization_replaced","controller_replaced","background_released","cancelled","permit_retired","installed_version_changed","unsupported_goal","parallel_action","settle_expiry","pure_value_lifecycle","capture_retry_clears_pair","classified_interval","equal_key_interval","diagnostic_bounds","late_window_failure","late_unknown_event","history_limit_exact","history_limit_exceeded","queued_content_diagnostic_finished"]
ACTUAL_MEMBERS=[
    '    private static final class CtripFormSample {',
    '    private static final class CtripFormSampleRead {',
    '    private boolean ctripFormSamplingOwner(',
    '    private static boolean sameObservationWatermark(',
    '    private static Map<String,Object> ctripSampleKey(',
    '    private static void recordCtripSampling(',
    '    private CtripFormSampleRead readCtripFormSample(',
    '    private boolean ctripFormSampleCurrent(',
    '    private static void recordCtripSampleRefusal(',
    '    private static Map<String,Object> ctripSamplingCensus(',
    '    private static Map<String,Object> ctripSamplingHistory(',
    '    private static Map<String,Object> ctripSamplingProof(',
    '    private boolean ctripSamplingProofCurrent(',
    '    private static Map<String,Object> ctripSamplingSummary(',
    '    private void sampleObservation(final ObservationRequest request){',
    '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents,CtripFormSampleRead formRead){',
    '    private void noteObservationEvent(int displayId,int windowId,String packageName,boolean contentType,int sdkEventType){',
    '    private synchronized void admitPostEffectObservation(',
    '    private synchronized boolean postEffectObservationOwner(',
    '    private void requireObservationWork(',
    '    private boolean nativeObservationRecheckAllowed(',
    '    private NativeActionSnapshotCheck.Snapshot nativeCtripFormSnapshot(',
    '    private void processScreenshot(',
    '    private void captureObservation(',
    '    private void persistCtripFormHistory(',
    '    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){',
]
def need(value,message):
    if not value:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(path):
    p=Path(path);st=p.lstat()
    need(stat.S_ISREG(st.st_mode) and not p.is_symlink(),'regular immutable input '+str(p))
    raw=p.read_bytes()
    return {'path':str(p.resolve()),'bytes':len(raw),'sha256':sha(raw),'mode':format(stat.S_IMODE(st.st_mode),'04o')}
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as out:json.dump(value,out,ensure_ascii=False,indent=2,sort_keys=True);out.write('\n')
    path.chmod(0o644)
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def inventory(root):
    rows=[]
    for p in sorted(root.rglob('*')):
        need(not p.is_symlink(),'no unrecorded source links')
        if p.is_file():
            row=meta(p);row['relative']=str(p.relative_to(root));rows.append(row)
    return rows
def prepare(source,out):
    coherent=module(source/'tests/native-ctrip-coherent-census/run_host.py','sampling_coherent_generation')
    edge_path=source/'tests/native-ctrip-form-observation/scope_predecessor.py'
    edge_proof=module(edge_path,'sampling_edge_refusal_proof')
    for relative,expected in coherent.PROTECTED.items():
        raw=(source/relative).read_bytes()
        if Path(relative).name=='ObservationStabilityGate.java':
            need(len(raw)==5544 and sha(raw)==GATE_SHA,'actual complete reviewed Gate')
        elif Path(relative).name=='NativeActionSnapshotCheck.java':
            need(sha(edge_proof.edge_predecessor(raw))==expected,'exact whole proper-edge proof-copy predecessor')
        else:need(sha(raw)==expected,'unchanged complete classifier and original cases '+relative)
    need(sha((source/PKG/'NativeAppSession.java').read_bytes())==SESSION_SHA,'original real Session OPEN contract remains whole-byte unchanged')
    base=out/'coherent-dependency'
    h,compiled,source_inputs,legacy=coherent.prepare(source,base)
    old_host=base/'generated/ObserverPipelineHost.java';raw=old_host.read_text()
    need(raw.endswith('}\n'),'complete original generated host')
    generated=out/'generated';generated.mkdir()
    fragment=source/TEST/'CtripFormSamplingCases.fragment'
    actual=raw[:-2]+fragment.read_text()+'\n}\n'
    host=generated/'ObserverPipelineHost.java'
    with host.open('x',encoding='utf-8',newline='') as target:target.write(actual)
    host.chmod(0o644)
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    members=[]
    for anchor in ACTUAL_MEMBERS:
        body=h.body(service,anchor)
        need(actual.count(body)==1,'actual complete production member once '+anchor)
        members.append({'anchor':anchor,'bytes':len(body.encode()),'sha256':sha(body.encode())})
    worker=h.body(service,'    private void sampleObservation(final ObservationRequest request){')
    need('formRead=readCtripFormSample(request,graph,previous,formStart,formEnd,formCompletedAt,formEpoch);' in worker,
         'real serial worker produces the current classified read')
    need('acceptSample(request,sampled,failure,events,unknownEvents,sampledForm);' in worker,
         'actual worker calls six-argument accept, not legacy null delegate')
    compiled=[host if p==old_host else p for p in compiled]
    compiled += [source/TEST/'CtripFormSamplingGateHostTest.java',source/TEST/'CtripFormSamplingHostTest.java']
    need(len(compiled)==len(set(map(str,compiled))),'unique actual compile inputs')
    source_inputs += [source/TEST/n for n in ('run_host.py','CtripFormSamplingCases.fragment','CtripFormSamplingGateHostTest.java','CtripFormSamplingHostTest.java')]
    source_inputs += [source/PKG/'NativeAppSession.java']
    if edge_path not in source_inputs:source_inputs.append(edge_path)
    extraction={
        'schema':'hepta.ctrip-form-sampling-extraction.v1','coherent_dependency_extraction':meta(base/'EXTRACTION.json'),
        'unchanged_generated_base':meta(old_host),'compiled_sampling_host':meta(host),'added_fixture':meta(fragment),
        'actual_production_members':members,'complete_gate_source':meta(source/PKG/'ObservationStabilityGate.java'),
        'whole_original_session_contract':meta(source/PKG/'NativeAppSession.java'),
        'real_worker_to_six_argument_accept':True,'android_bfs_execution':False,
        'existing_session_io_carrier_synthetic':True,'actual_session_entered_receipt_proved':False,
        'no_authority_ports_added_or_changed':True,'original_68_cases_unchanged':True,
        'base_generated_file_preserved_not_overwritten':True,
        'phone_operations':0,'business_completion_claimed':False}
    save(out/'EXTRACTION.json',extraction)
    return h,compiled,source_inputs,legacy
def read_cases(path,count,names=None):
    value=json.loads(path.read_text())
    actual=value.get('case_names')
    need(value.get('all_pass') is True and value.get('cases')==count,'actual all-pass case count '+str(path))
    need(isinstance(actual,list) and len(actual)==len(set(actual))==count,'complete unique case names')
    if names is not None:need(set(actual)==set(names),'exact case inventory')
    return {'report':meta(path),'cases':count,'assertions':value['assertions'],'case_names':actual}
def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar','actual-pair'):ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--actual-pair-sha256',required=True);ap.add_argument('--actual-pair-bytes',type=int,required=True)
    args=ap.parse_args();source=args.source.resolve();out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    jdk=args.java_home.resolve();jar=args.json_jar.resolve();pair=args.actual_pair.resolve()
    pair_before=meta(pair);need((pair_before['bytes'],pair_before['sha256'])==(args.actual_pair_bytes,args.actual_pair_sha256),'exact full historical private input')
    need((jar.stat().st_size,sha(jar.read_bytes()))==(78332,'3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'),'original pinned JSON tool')
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    before=inventory(source);tool_before=[meta(p) for p in tools];save(out/'SOURCE-INVENTORY-BEFORE.json',before)
    report={'schema':'hepta.ctrip-form-sampling-host.v1','all_pass':False,'source_root':str(source),
            'source_inventory_before':meta(out/'SOURCE-INVENTORY-BEFORE.json'),'tools_before':tool_before,
            'historical_private_pair':pair_before,'stages':[],'declared_gate_cases':22,'declared_worker_cases':len(SERVICE_CASES),
            'declared_legacy_observer_cases':68,'legacy_coherent_43_executed':False,'legacy_child_41_executed':False,
            'android_execution':False,'native_inference_executed':False,'phone_operations':0,'action_dispatches':0,
            'existing_session_io_carrier_synthetic':True,'actual_session_entered_receipt_proved':False,
            'defb_missing_census_or_events_reconstructed':False,'phone_efficacy_proved':False,
            'business_completion_claimed':False}
    try:
        h,compiled,source_inputs,legacy=prepare(source,out)
        report['compile_inputs_before']=[meta(p) for p in compiled];report['source_inputs_before']=[meta(p) for p in source_inputs]
        report['extraction']=meta(out/'EXTRACTION.json')
        classes=out/'classes';classes.mkdir()
        command=[str(jdk/'bin/javac'),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,compiled))
        step=h.stage('compile',command,out);report['stages'].append(step);need(step['exit_code']==0,'strict original production closure compilation')
        common=[str(jdk/'bin/java'),'-ea','-Dhepta.ctrip.form.fixture='+str(source/'tests/native-ctrip-form-observation/form-region-nodes.json'),
                '-Dhepta.ctrip.coherent.actual='+str(pair),'-cp',str(classes)+os.pathsep+str(jar)]
        stages=[
            ('gate-cases','CtripFormSamplingGateHostTest','GATE-CASES.json',22,None),
            ('sampling-worker-cases','CtripFormSamplingHostTest','WORKER-CASES.json',len(SERVICE_CASES),['sampling_worker_'+v for v in SERVICE_CASES]),
            ('legacy-observer-cases','ObserverIntegrationHostTest','LEGACY-CASES.json',68,legacy)]
        for name,main_class,filename,count,names in stages:
            path=out/filename
            step=h.stage(name,common+['org.trillionnium.hepta.local.'+main_class,str(path)],out);report['stages'].append(step)
            if path.is_file():report[name+'_actual_report']=meta(path)
            if name=='sampling-worker-cases':
                report['retained_host_sampling_history']=[meta(p) for p in sorted((out/'sampling-history').glob('*.json'))]
            need(step['exit_code']==0,'actual '+name)
            report[name]=read_cases(path,count,names)
        report['compile_inputs_after']=[meta(p) for p in compiled];report['source_inputs_after']=[meta(p) for p in source_inputs]
        need(report['compile_inputs_before']==report['compile_inputs_after'],'actual compile inputs unchanged')
        need(report['source_inputs_before']==report['source_inputs_after'],'actual generating inputs unchanged')
        report['all_pass']=True
    except Exception as failure:
        report['error']={'type':type(failure).__name__,'message':str(failure),'traceback':traceback.format_exc()}
    finally:
        after=inventory(source);save(out/'SOURCE-INVENTORY-AFTER.json',after)
        report['source_inventory_after']=meta(out/'SOURCE-INVENTORY-AFTER.json');report['source_unchanged']=after==before
        report['tools_after']=[meta(p) for p in tools];report['historical_private_pair_after']=meta(pair)
        report['all_pass']=report['all_pass'] and after==before and report['tools_after']==tool_before and report['historical_private_pair_after']==pair_before
        save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'report':meta(out/'RESULT.json'),'error':report.get('error')},ensure_ascii=False))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
