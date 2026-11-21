#!/usr/bin/env python3
"""Actual observer scheduling + native completeness predicates against explicit host IO.

No Android traversal, task admission, screenshot pixel accuracy or action qualification
is claimed. The original observer methods and CollectionStats execute verbatim;
already-collected graph/NodeRef values, selection, looper and screenshot IO are fakes.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path

PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-observation-events')
JAVA=['HeptaAccessibilityService.java','PhoneObservation.java','ObservationDiagnostics.java',
      'ObservationStabilityGate.java','ActionExecutionState.java','TaskCancellationQueue.java',
      'ObservedWindowMetadata.java','ObservationState.java','ImeVisibility.java']
OWN=['run_host.py','EventChecks.java','EventPipelineCases.fragment','SavedGraphSeedCases.fragment','PublicationRecheckCases.fragment']

def helper(source):
    p=source/'tests/observation-diagnostics/run_host.py'
    spec=importlib.util.spec_from_file_location('observer_existing_host_util',p)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def replace(text,before,after):
    if text.count(before)!=1:raise RuntimeError('nonunique fixture boundary '+before[:80])
    return text.replace(before,after,1)

def generate(source,out,h):
    service=(source/PKG/JAVA[0]).read_text();phone=(source/PKG/JAVA[1]).read_text()
    parts={
      'observation_callback':h.section(service,'    public interface ObservationCallback','    public interface Cancellation'),
      'diagnostic':h.section(service,'    private String diagnosticTask;','    /** Each observation owns'),
      'acquire':h.section(service,'    public synchronized boolean acquireTask(','    public synchronized void releaseTask('),
      'recovery_idle':h.section(service,'    synchronized boolean recoveryControllerIdle(','    synchronized void retireControllerAfterAcknowledgement('),
      'action_pending':h.section(service,'    boolean actionWorkPending()','    void retireActionWork('),
      'cancellation_pending':h.section(service,'    boolean nativeCancellationWorkPending()','    boolean requestNativeCancellation('),
      'background_lock':h.section(service,'    private boolean locked(BackgroundSession background)','    private int rotation('),
      'observation':h.section(service,'    /** Each observation owns','    synchronized void bindQualificationScope('),
      'complete_native':h.body(service,'    private static boolean completeNativeObservationGraph(Graph graph){'),
      'collection_stats':h.body(phone,'    public static final class CollectionStats {')}
    template=(source/'tests/observation-pipeline/ObserverPipelineHost.template').read_text()
    for name,value in parts.items():
        if name not in ('complete_native','collection_stats'):template=replace(template,'{{'+name+'}}',value)
    original_main=h.body(template,'    public static void main(String[] args)throws Exception{')
    template=replace(template,original_main,parts['complete_native']+'\n'+(source/TEST/'EventPipelineCases.fragment').read_text())
    # Explicit IO carriers only. Production bodies above are never rewritten.
    template=replace(template,'import java.util.*;','import java.util.*;\nimport org.json.JSONArray;\nimport org.json.JSONException;')
    template=replace(template,'        final Object state=new Object(),windowMetadata=new Object(),rows=new Object(),collectionStats=new Object();',
        '        ObservationState state;ObservedWindowMetadata windowMetadata;PhoneObservation.CollectionStats collectionStats;\n'
        '        final List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();')
    template=replace(template,'        final String backgroundBootstrapPackage="fixture.notes";final List<String> backgroundAllowedPackages=Collections.singletonList("fixture.notes");',
        '        String backgroundBootstrapPackage="fixture.notes";List<String> backgroundAllowedPackages=Collections.singletonList("fixture.notes");')
    template=replace(template,'    static final class Graph {',
        '    static final class NodeRef {String appTreeSignature;NodeRef(String value){appTreeSignature=value;}}\n    static final class Graph {')
    node='''    static final class Node {
            String id,packageName,nativeTreePath,observedAppTreeSignature;boolean selectionStateObserved=true;
            Node(String id,String pkg,String path,String sig){this.id=id;packageName=pkg;nativeTreePath=path;observedAppTreeSignature=sig;}
        }
'''
    template=replace(template,'    static final class PhoneObservation {','    static final class PhoneObservation {\n'+parts['collection_stats']+'\n'+node)
    template=replace(template,'        JSONObject(String raw){throw new AssertionError("observer scheduling fixture cannot construct Selection provenance");}',
        '        JSONObject(){value=new org.json.JSONObject();}\n'
        '        JSONObject put(String key,Object object)throws JSONException{value.put(key,object);return this;}\n'
        '        JSONObject(String raw)throws JSONException{value=new org.json.JSONObject(raw);}')
    if '{{' in template:raise RuntimeError('unfilled host boundary')
    # Assert the live hook lies after actual metadata/state hashing. It has no action-copy producer.
    call='graph.nativeObservationComplete=nativeEvidence&&completeNativeObservationGraph(graph);'
    if service.count(call)!=1 or service.index(call)<service.index('graph.digest=sha(graph.windowMetadata.bindFreshness('):raise RuntimeError('actual collector hook missing')
    copy=h.body(service,'        Graph copyForAction(String nodeId,WebRegionNativeBridge region){')
    if 'nativeObservationComplete=' in copy:raise RuntimeError('partial action copy must not inherit completeness')
    branch='''}else if(!graph.digest.equals(now.digest)){
                    if(work!=null&&work.nativeGuard!=null){
                        try{compareNativeAction(taskId,expected,action,now,work);work.nativeActionRevalidated=true;}
                        catch(ProfileOwnershipViolation identityChanged){throw identityChanged;}
                        catch(Exception mismatch){recordStaleDiagnostic(work,graph,now,action.nodeId);
                            return "stale:原生目的复核失败："+message(mismatch);}
                    }else{recordStaleDiagnostic(work,graph,now,action.nodeId);return "stale:目标窗口内容已变化";}
                }'''
    # The reviewed history source now requires the same native guard even when
    # its historical whole-tree digest happens to match. Prove the only call-site
    # change against the complete legacy branch above; execute actual bodies.
    legacy_condition='}else if(!graph.digest.equals(now.digest)){'
    history_condition='}else if(expected.capture!=null&&expected.capture.formHistory()||!graph.digest.equals(now.digest)){'
    if branch.count(legacy_condition)!=1:raise RuntimeError('exact legacy guard condition required')
    actual_branch=branch.replace(legacy_condition,history_condition,1)
    if actual_branch.count(history_condition)!=1 or actual_branch.replace(history_condition,legacy_condition,1)!=branch:
        raise RuntimeError('history call-site inverse must preserve the original native guard and fallback')
    if service.count(actual_branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')
    h.write(out/'ObserverPipelineHost.java',template)
    return {'schema':'hepta.native-observation-events-extraction.v1','bodies_verbatim':True,
        'methods':{n:{'bytes':len(s.encode()),'sha256':h.sha(s.encode())} for n,s in parts.items()},
        'original_pipeline_main_unchanged_in_source':True,'action_copies_do_not_carry_native_observation_completeness':True,
        'default_whole_graph_action_refusal_retained':True,'production_collector_hook':call,
        'boundary':'Actual observer/CollectionStats/metadata/state/gate code; synthetic collected Graph/NodeRef and Selection carriers, clock, callback, Android screenshot IO. No Android/currentness, pixels or action qualification.',
        'final_saved_read_event_watermark_is_conservative':True,'unbounded_continuous_events_not_claimed_live':True}


def add_saved_graph_seed_cases(source,out,h,extraction):
    # Called only by this existing runner. Other original fixture consumers keep generate() unchanged.
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    case_source=(source/TEST/'SavedGraphSeedCases.fragment').read_text()+'\n'+(source/TEST/'PublicationRecheckCases.fragment').read_text()
    factory=h.body(service,'    private static FrozenObservationWindow frozenObservationWindow(Graph graph){')
    path=out/'ObserverPipelineHost.java';text=path.read_text()
    text=replace(text,'        long readStartedElapsedMs,readCompletedElapsedMs;',
        '        long readStartedElapsedMs,readCompletedElapsedMs;\n'
        '        List<Object> nativeActionNodes;Map<String,Object> nativeActionWindows;int nativeActionWidth,nativeActionHeight;')
    text=replace(text,'    private static FrozenObservationWindow frozenObservationWindow(Graph graph){return null;}',factory)
    boundary=h.body(text,'    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){')
    text=replace(text,boundary,
        '    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){\n'
        '        if(seedFrozenRead==null)throw new AssertionError("legacy fixture cannot supply current frozen-window IO");\n'
        '        return seedFrozenRead.read(request,identity);\n    }')
    text=replace(text,'    public static void main(String[] args)throws Exception{',case_source+'\n    public static void main(String[] args)throws Exception{')
    text=replace(text,'        observationIo.executor.shutdown();EventChecks.finish(args[0]);',
        '        savedGraphSeedCases();\n        savedGraphSeedAdditionalCases();\n        savedGraphSeedProfileCases();\n        publicationRecheckCases();\n        observationIo.executor.shutdown();EventChecks.finish(args[0]);')
    evidence=(source/PKG/'NativeAppEvidence.java').read_text()
    profile_parts={
        'same_owner':h.body(evidence,'    static boolean sameProfileOwner(WindowOwnership a,WindowOwnership b){'),
        'target':h.body(evidence,'    static void requireProfileTarget(ProfileTarget expected,WindowOwnership actual){'),
        'need':h.body(evidence,'    static void need(boolean yes,String why){'),
        'owner_guard':h.body(service,'    private static void requireSameProfileOwner(WindowOwnership original,WindowOwnership actual){'),
        'owner_exception':h.body(service,'    private static final class ProfileOwnershipViolation extends IllegalStateException {')}
    text=replace(text,h.body(text,'    static final class WindowOwnership {'),"    /** Synthetic fields; production equality/target predicates below are verbatim. */\n    static final class ProfileIdentity {final int userId=10;final long serial=10;}\n    static final class ProfileTarget {final String sha256=EventChecks.OWNER;final ProfileIdentity profile=new ProfileIdentity();final int fullUid=1010367;}\n    static final class WindowOwnership {\n        final String targetSha256,generation,taskTokenId;final int displayId,taskId,parentTaskId,userId,fullUid,windowId;final long userSerial;\n        WindowOwnership(String change){\n            targetSha256=\"target\".equals(change)?EventChecks.repeat('d',64):EventChecks.OWNER;\n            generation=\"generation\".equals(change)?\"99999999-2222-3333-4444-555555555555\":EventChecks.GENERATION;\n            taskTokenId=\"token\".equals(change)?\"replacement-held-token\":\"original-held-token\";\n            displayId=\"display\".equals(change)?10:9;taskId=\"task\".equals(change)?1000006:1000005;\n            parentTaskId=\"parent\".equals(change)?1368:1367;userId=\"user\".equals(change)?11:10;\n            userSerial=\"serial\".equals(change)?11:10;fullUid=\"uid\".equals(change)?1010368:1010367;windowId=7;\n        }\n        Map<String,Object> evidence(){throw new AssertionError(\"synthetic profile fields are not device proof\");}\n    }\n")
    text=replace(text,h.body(text,'    static final class NativeAppEvidence {'),
        '    static final class NativeAppEvidence {\n'+profile_parts['same_owner']+'\n'+profile_parts['target']+'\n'+profile_parts['need']+'\n    }')
    text=replace(text,h.body(text,'    static void requireSameProfileOwner(WindowOwnership before,WindowOwnership after){'),
        profile_parts['owner_exception']+'\n'+profile_parts['owner_guard'])
    text=replace(text,'        Object profileTarget(){return null;} // Explicit scheduling fixture has no profile selection.',
        '        ProfileTarget profile;ProfileTarget profileTarget(){return profile;} // Explicit synthetic selection only.')
    text=replace(text,'        synchronized boolean post(Runnable runnable){return postDelayed(runnable,0);}',
        '        volatile Runnable afterWorkerPost;\n'
        '        boolean post(Runnable runnable){boolean posted=postDelayed(runnable,0);\n'
        '            Runnable hook=afterWorkerPost;if(!isMain()&&hook!=null)hook.run();return posted;}')
    extraction['saved_graph_profile_predicates']={key:{'bytes':len(value.encode()),'sha256':h.sha(value.encode())} for key,value in profile_parts.items()}
    extraction['profile_fields_synthetic_not_device_ownership']=True
    path.write_text(text,encoding='utf-8')
    extraction['saved_graph_seed_cases']={
        'existing_runner_executes_new_cases':True,
        'original_event_cases_preserved':h.meta(source/TEST/'EventPipelineCases.fragment'),
        'new_cases':h.meta(source/TEST/'SavedGraphSeedCases.fragment'),
        'publication_recheck_cases':h.meta(source/TEST/'PublicationRecheckCases.fragment'),
        'frozen_window_factory_verbatim':{'bytes':len(factory.encode()),'sha256':h.sha(factory.encode())},
        'no_production_body_rewritten':True,'extra_android_values_are_synthetic':True,
        'whole_actual_observer_section_includes_seed_and_capture':True}
    return extraction

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True);ap.add_argument('--json-jar',type=Path,required=True);a=ap.parse_args()
    source=a.source.resolve();output=a.output.absolute();output.mkdir(parents=True,exist_ok=False);h=helper(source)
    jdk=a.java_home.resolve();java=jdk/'bin/java';javac=jdk/'bin/javac';jar=a.json_jar.resolve()
    tools=[java,javac,jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    if not all(p.is_file() for p in tools):raise RuntimeError('strict JDK17 and JSON closure required')
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON pin')
    inputs=[source/PKG/'NativeAppEvidence.java']+[source/PKG/n for n in JAVA]+[source/TEST/n for n in OWN]+[
        source/'tests/observation-pipeline/ObserverPipelineHost.template',source/'tests/observation-diagnostics/run_host.py']+tools
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    r={'schema':'hepta.native-observation-events-host-gate.v1','all_pass':False,'stages':[],
       'input_before':before,'tools_before':tool_before,'compiler_contract':'JDK17 --release 8 -Xlint:all -Werror',
       'android_execution':False,'phone_execution':False,'sdk_loaded':False,'model_executed':False,
       'business_completion_verified':False,'action_guard_changed':True,'native_action_guard_qualification_claimed':False,'deadline_expanded':True,
       'observation_budget':{'settle_ms':10000,'capture_margin_ms':2000,'total_ms':12000,
           'task_deadline_caps_total':True,'retry_renews_deadline':False,'legacy_explicit_ten_second_cases_retained':True}}
    try:
        generated=output/'generated';generated.mkdir();extraction=generate(source,generated,h);extraction=add_saved_graph_seed_cases(source,generated,h,extraction);h.save(output/'EXTRACTION.json',extraction)
        classes=output/'classes';classes.mkdir()
        sources=[source/PKG/n for n in JAVA if n not in ('HeptaAccessibilityService.java','PhoneObservation.java')]
        sources += [source/TEST/'EventChecks.java',generated/'ObserverPipelineHost.java']
        argv=[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))
        s=h.stage('compile',argv,output);r['stages'].append(s)
        if s['exit_code']!=0:raise RuntimeError('actual observer fixture compilation failed')
        s=h.stage('cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObserverPipelineHost',str(output/'CASES.json')],output);r['stages'].append(s)
        if s['exit_code']!=0:raise RuntimeError('actual observer event cases failed')
        cases=json.loads((output/'CASES.json').read_text())
        if cases['all_pass'] is not True or cases['cases']!=len(cases['case_names']) or len(set(cases['case_names']))!=cases['cases']:raise RuntimeError('complete unique cases required')
        r.update(cases=cases,cases_file=h.meta(output/'CASES.json'),extraction_file=h.meta(output/'EXTRACTION.json'),
            generated_files={p.name:h.meta(p) for p in sorted(generated.glob('*.java'))},all_pass=True)
    except Exception as error:r['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        r['input_after']=[h.meta(p) for p in inputs];r['tools_after']=[h.meta(p) for p in tools]
        r['inputs_unchanged']=before==r['input_after'];r['tools_unchanged']=tool_before==r['tools_after']
        r['all_pass']=r['all_pass'] and r['inputs_unchanged'] and r['tools_unchanged'];h.save(output/'RESULT.json',r)
    print(json.dumps({'all_pass':r['all_pass'],'result':h.meta(output/'RESULT.json')}));return 0 if r['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())
