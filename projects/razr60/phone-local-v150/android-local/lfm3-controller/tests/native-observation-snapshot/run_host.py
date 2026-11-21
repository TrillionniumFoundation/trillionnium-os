#!/usr/bin/env python3
"""Execute the production observer and sealed-history policy with explicit host Android IO.

The source observer bodies, seal/value comparison, completeness policy and deep-freeze
producer execute verbatim. Android graph/root/window enumeration, pixels, clock and
authorization endpoints are controlled fakes. This does not qualify a phone or SDK.
"""
import argparse, importlib.util, json, os
from pathlib import Path
PKG=Path('src/org/trillionnium/hepta/local')
HERE=Path(__file__).resolve().parent
BUNDLE=HERE.parents[1]
JAVA=['HeptaAccessibilityService.java','PhoneObservation.java','LocalTaskController.java',
      'ObservationDiagnostics.java','ObservationStabilityGate.java','ActionExecutionState.java','ObservedChildText.java','ObservedScrollActions.java','ObservedImeEnter.java',
      'TaskCancellationQueue.java','ObservedWindowMetadata.java','ObservationState.java','ImeVisibility.java','NativeAppEvidence.java']
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def once(text,before,after):
    if text.count(before)!=1:raise RuntimeError('nonunique fixture boundary '+before[:100])
    return text.replace(before,after,1)
def generate(source,out,h):
    service=(source/PKG/JAVA[0]).read_text();phone=(source/PKG/JAVA[1]).read_text();evidence=(source/PKG/'NativeAppEvidence.java').read_text()
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
      'collection_stats':h.body(phone,'    public static final class CollectionStats {'),
      'immutable_map':h.body(evidence,'    static Map<String,Object> immutableMap(Map<String,Object> source){'),
      'immutable_value':h.body(evidence,'    private static Object immutableValue(Object value,int depth){')}
    template=(BUNDLE/'tests/observation-pipeline/ObserverPipelineHost.template').read_text()
    for key in ('observation_callback','diagnostic','acquire','recovery_idle','action_pending','cancellation_pending','background_lock','observation'):
        template=once(template,'{{'+key+'}}',parts[key])
    main=h.body(template,'    public static void main(String[] args)throws Exception{')
    extra=parts['complete_native']+'\n'+parts['immutable_map']+'\n'+parts['immutable_value']+'\n'
    extra+='    static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}\n'
    extra+='    static void need(boolean yes,String why){if(!yes)throw new IllegalArgumentException(why);}\n'
    template=once(template,main,extra+(HERE/'SnapshotPipelineCases.fragment').read_text())
    template=once(template,'import java.util.*;','import java.util.*;\nimport org.json.JSONArray;\nimport org.json.JSONException;')
    template=once(template,'        final Object state=new Object(),windowMetadata=new Object(),rows=new Object(),collectionStats=new Object();',
        '        ObservationState state;ObservedWindowMetadata windowMetadata;PhoneObservation.CollectionStats collectionStats;\n'
        '        final List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();')
    template=once(template,'        final String backgroundBootstrapPackage="fixture.notes";final List<String> backgroundAllowedPackages=Collections.singletonList("fixture.notes");',
        '        String backgroundBootstrapPackage="fixture.notes";List<String> backgroundAllowedPackages=Collections.singletonList("fixture.notes");')
    template=once(template,'        long readStartedElapsedMs,readCompletedElapsedMs;',
        '        long readStartedElapsedMs,readCompletedElapsedMs;\n'
        '        List<Object> nativeActionNodes;Map<String,Object> nativeActionWindows;int nativeActionWidth,nativeActionHeight;')
    template=once(template,'    static final class Graph {',
        '    static final class NodeRef {String appTreeSignature;NodeRef(String value){appTreeSignature=value;}}\n    static final class Graph {')
    node='''    static final class Node {
        String id,packageName,nativeTreePath,observedAppTreeSignature;boolean selectionStateObserved=true;
        Node(String id,String pkg,String path,String sig){this.id=id;packageName=pkg;nativeTreePath=path;observedAppTreeSignature=sig;}
    }
'''
    template=once(template,'    static final class PhoneObservation {','    static final class PhoneObservation {\n'+parts['collection_stats']+'\n'+node)
    template=once(template,'        JSONObject(String raw){throw new AssertionError("observer scheduling fixture cannot construct Selection provenance");}',
        '        JSONObject(){value=new org.json.JSONObject();}\n'
        '        JSONObject put(String key,Object object)throws JSONException{value.put(key,object);return this;}\n'
        '        JSONObject(String raw)throws JSONException{value=new org.json.JSONObject(raw);}')
    feature='    private static final class FrozenObservationWindow {' in service
    policy_source=service if feature else (BUNDLE/PKG/JAVA[0]).read_text()
    factory=h.body(policy_source,'    private static FrozenObservationWindow frozenObservationWindow(Graph graph){')
    parts['frozen_factory']=factory
    template=once(template,'    private static FrozenObservationWindow frozenObservationWindow(Graph graph){return null;}',factory)
    if not feature:
        # Compilation-only carrier bridge. No old production observer body is altered;
        # the old pipeline never calls this type/factory and must fail the positive history case.
        carrier=h.body(policy_source,'    private static final class FrozenObservationWindow {')
        template=once(template,'    interface GraphBudget {void check();}',carrier+'\n    interface GraphBudget {void check();}')
    fake=h.body(template,'    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){')
    template=once(template,fake,'''    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){
        expect(!isMain(),"identity Android IO on main");windowChecks.incrementAndGet();
        if(windowHook!=null)windowHook.run();requireObservationWork(request);
        if("missing".equals(windowFailure))throw new NoActiveWindow();
        if(windowFailure!=null)throw new StaleObservation("synthetic frozen-window failure");
        requireTaskAuthorization(request.taskId,taskAuthorization);return windowValue;
    }''')
    template=once(template,'        expect(owns(task)&&authorization!=null&&authorization==taskAuthorization,"retired fixture authorization");',
        '        if(!owns(task)||!authorizationReady||authorization==null||authorization!=taskAuthorization)throw new IllegalStateException("retired fixture authorization");')
    if '{{' in template:raise RuntimeError('unfilled fixture')
    if feature:
        adapter=h.body(service,'    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){')
        for forbidden in ('readGraph(', 'getChild(', 'getChildCount(', 'getText(', 'getContentDescription(', 'nodeSignature('):
            if forbidden in adapter:raise RuntimeError('identity adapter accidentally requires content: '+forbidden)
        for required in ('selectedRoot(', 'isVisibleToUser()', 'readWindowMetadata(', 'readNativeActionWindows(', 'getRealMetrics(', 'requireTaskAuthorization(', 'root.recycle()'):
            if required not in adapter:raise RuntimeError('identity IO contract missing '+required)
        parts['identity_android_adapter_pinned_not_executed']=adapter
    h.write(out/'ObserverPipelineHost.java',template)
    return {'schema':'hepta.native-observation-snapshot-extraction.v1','feature_present':feature,
        'production_observer_bodies_verbatim':True,'source_root':str(source),'test_bundle_root':str(BUNDLE),
        'r17_counterfactual_unused_carrier_bridge':not feature,
        'methods':{k:{'bytes':len(v.encode()),'sha256':h.sha(v.encode())} for k,v in parts.items()},
        'boundary':'Actual observer, pair seal, window value comparator, native completeness and recursive evidence freeze. Android graph/root/window IO, permission endpoint, pixels and clock are explicit fakes; Android adapter is pinned and checked for content-free reads but not run on Android.',
        'actual_phone_observation_full_class_executed':feature,'actual_phone_observation_android_boundary':'Rect value-only fixture; pinned real JSON',
        'phone_execution':False,'android_execution':False,'action_freshness_relaxed':False,'deadline_expanded':False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True);ap.add_argument('--json-jar',type=Path,required=True);a=ap.parse_args()
    source=a.source.resolve();output=a.output.absolute();output.mkdir(parents=True,exist_ok=False)
    h=load(BUNDLE/'tests/observation-diagnostics/run_host.py','snapshot_host_helpers')
    jdk=a.java_home.resolve();java=jdk/'bin/java';javac=jdk/'bin/javac';jar=a.json_jar.resolve()
    tools=[java,javac,jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    if not all(p.is_file() for p in tools):raise RuntimeError('JDK17/JSON closure unavailable')
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON pin')
    own=[HERE/n for n in ('run_host.py','SnapshotChecks.java','SnapshotPipelineCases.fragment','ObservationEvidenceHost.java')]
    rect=source/'tests/qualification-scope/fixtures/android/graphics/Rect.java'
    inputs=[source/PKG/n for n in JAVA]+own+[rect,BUNDLE/'tests/observation-pipeline/ObserverPipelineHost.template',BUNDLE/'tests/observation-diagnostics/run_host.py']
    inputs += [BUNDLE/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('ProfileIdentity','ProfileTarget','WindowOwnership')]
    if source!=BUNDLE:inputs.append(BUNDLE/PKG/JAVA[0])
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    result={'schema':'hepta.native-observation-snapshot-host.v1','all_pass':False,'stages':[],
        'input_before':before,'tools_before':tool_before,'source_root':str(source),'test_bundle_root':str(BUNDLE),
        'compiler_contract':'JDK17 --release 8 -Xlint:all -Werror','phone_execution':False,'android_execution':False,
        'sdk_loaded':False,'model_executed':False,'business_completion_verified':False,
        'action_freshness_relaxed':False,'deadline_expanded':False}
    try:
        generated=output/'generated';generated.mkdir();extraction=generate(source,generated,h);h.save(output/'EXTRACTION.json',extraction)
        classes=output/'classes';classes.mkdir()
        sources=[source/PKG/n for n in JAVA if n not in ('HeptaAccessibilityService.java','LocalTaskController.java','NativeAppEvidence.java')]
        # Full current PhoneObservation carries real immutable profile types; the scheduling carrier above remains fail-only for profile.
        sources += [BUNDLE/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('ProfileIdentity','ProfileTarget','WindowOwnership')]
        sources += [HERE/'SnapshotChecks.java',HERE/'ObservationEvidenceHost.java',rect,generated/'ObserverPipelineHost.java']
        result['stages'].append(h.stage('compile',[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources)),output))
        if result['stages'][-1]['exit_code']!=0:raise RuntimeError('production observer fixture compilation failed')
        result['stages'].append(h.stage('cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObserverPipelineHost',str(output/'CASES.json')],output))
        if (output/'CASES.json').is_file():result['cases']=json.loads((output/'CASES.json').read_text());result['cases_file']=h.meta(output/'CASES.json')
        if result['stages'][-1]['exit_code']!=0:raise RuntimeError('snapshot pipeline cases failed')
        cases=result['cases']
        if cases['all_pass'] is not True or cases['cases']!=len(cases['case_names']) or len(set(cases['case_names']))!=cases['cases'] or set(cases['case_assertions'])!=set(cases['case_names']):raise RuntimeError('complete unique case accounting required')
        result.update(all_pass=True,extraction_file=h.meta(output/'EXTRACTION.json'),generated_files={p.name:h.meta(p) for p in generated.glob('*.java')})
    except Exception as error:result['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        result['input_after']=[h.meta(p) for p in inputs];result['tools_after']=[h.meta(p) for p in tools]
        result['inputs_unchanged']=before==result['input_after'];result['tools_unchanged']=tool_before==result['tools_after']
        result['all_pass']=result['all_pass'] and result['inputs_unchanged'] and result['tools_unchanged'];h.save(output/'RESULT.json',result)
    print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'result':h.meta(output/'RESULT.json')}))
    return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
