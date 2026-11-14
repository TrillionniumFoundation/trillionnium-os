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
OWN=['run_host.py','EventChecks.java','EventPipelineCases.fragment']

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
                        catch(Exception mismatch){recordStaleDiagnostic(work,graph,now,action.nodeId);
                            return "stale:原生目的复核失败："+message(mismatch);}
                    }else{recordStaleDiagnostic(work,graph,now,action.nodeId);return "stale:目标窗口内容已变化";}
                }'''
    if service.count(branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')
    h.write(out/'ObserverPipelineHost.java',template)
    return {'schema':'hepta.native-observation-events-extraction.v1','bodies_verbatim':True,
        'methods':{n:{'bytes':len(s.encode()),'sha256':h.sha(s.encode())} for n,s in parts.items()},
        'original_pipeline_main_unchanged_in_source':True,'action_copies_do_not_carry_native_observation_completeness':True,
        'default_whole_graph_action_refusal_retained':True,'production_collector_hook':call,
        'boundary':'Actual observer/CollectionStats/metadata/state/gate code; synthetic collected Graph/NodeRef and Selection carriers, clock, callback, Android screenshot IO. No Android/currentness, pixels or action qualification.',
        'final_saved_read_event_watermark_is_conservative':True,'unbounded_continuous_events_not_claimed_live':True}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True);ap.add_argument('--json-jar',type=Path,required=True);a=ap.parse_args()
    source=a.source.resolve();output=a.output.absolute();output.mkdir(parents=True,exist_ok=False);h=helper(source)
    jdk=a.java_home.resolve();java=jdk/'bin/java';javac=jdk/'bin/javac';jar=a.json_jar.resolve()
    tools=[java,javac,jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    if not all(p.is_file() for p in tools):raise RuntimeError('strict JDK17 and JSON closure required')
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON pin')
    inputs=[source/PKG/n for n in JAVA]+[source/TEST/n for n in OWN]+[
        source/'tests/observation-pipeline/ObserverPipelineHost.template',source/'tests/observation-diagnostics/run_host.py']+tools
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    r={'schema':'hepta.native-observation-events-host-gate.v1','all_pass':False,'stages':[],
       'input_before':before,'tools_before':tool_before,'compiler_contract':'JDK17 --release 8 -Xlint:all -Werror',
       'android_execution':False,'phone_execution':False,'sdk_loaded':False,'model_executed':False,
       'business_completion_verified':False,'action_guard_changed':True,'native_action_guard_qualification_claimed':False,'deadline_expanded':False}
    try:
        generated=output/'generated';generated.mkdir();extraction=generate(source,generated,h);h.save(output/'EXTRACTION.json',extraction)
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
