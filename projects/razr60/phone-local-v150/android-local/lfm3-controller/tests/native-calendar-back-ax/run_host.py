#!/usr/bin/env python3
"""Actual AX worker/private handoff plus original observer with explicit SDK IO.
This is a host source bridge. The separate Calendar BACK Controller gate supplies the real Session returned/drained
handoff/durable-outcome/once consumer; this suite executes the actual AX producer for both closed permit types.
"""
import argparse, importlib.util, json, os, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
BUNDLE=HERE.parents[1]
PKG=Path('src/org/trillionnium/hepta/local')

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def once(text,before,after):
    if text.count(before)!=1:raise RuntimeError('unique AX bridge boundary: '+before[:100])
    return text.replace(before,after,1)

def throw_expression(service,message):
    lines=[line for line in service.splitlines() if 'throw new StaleObservation("'+message+'"' in line]
    if len(lines)!=1:raise RuntimeError('unique actual throw-site: '+message)
    return lines[0].split('throw ',1)[1].split(';',1)[0]

def generate(source,out,h):
    empty=load(BUNDLE/'tests/native-ax-observation/run_empty_loading_host.py','transient_empty_base')
    snap=load(BUNDLE/'tests/native-observation-snapshot/run_host.py','transient_snapshot_base')
    meta=empty.generate(source,out,h,snap);path=out/'ObserverPipelineHost.java';text=path.read_text()
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    actual_stale=h.body(service,'    private static final class StaleObservation extends IllegalStateException {')
    if text.count(actual_stale)!=1:raise RuntimeError('actual StaleObservation must occur exactly once')
    fingerprint=h.body(service,'    private static String postEffectChildWindowFingerprint(')
    evidence=(source/PKG/'NativeAppEvidence.java').read_text()
    value_members={name:h.body(evidence,anchor) for name,anchor in {
        'fingerprint':'    static String fingerprint(',
        'canonical':'    private static void canonical(',
        'hash':'    static String hash(',
        'need':'    static void need(',
    }.items()}
    # The current legacy AX generator now emits these same real members.
    # Require their exact bytes; never insert a second copy or accept a port.
    for name,member in {'child_window_fingerprint':fingerprint,**value_members}.items():
        if text.count(member)!=1:raise RuntimeError('actual AX bridge dependency must occur exactly once: '+name)
    if text.count('import java.security.NoSuchAlgorithmException;')!=1:
        raise RuntimeError('actual AX bridge hash import must occur exactly once')
    # Compile the exact real close loop. Its node.recycle endpoint is an explicit
    # reference-counted SDK fake; the actual loop and actual request retirement run.
    actual_graph=h.body(service,'    private static final class Graph {')
    actual_close=h.body(actual_graph,'        void close(){')
    compiled_close=actual_close.replace('void close()','void releaseActualSdkReferences()',1)
    if compiled_close.replace('void releaseActualSdkReferences()','void close()',1)!=actual_close:raise RuntimeError('close name-only inverse')
    text=once(text,'        synchronized void close(){expect(!closed,"graph closed twice "+serial);closed=true;}',
        '        synchronized void close(){expect(!closed,"graph closed twice "+serial);releaseActualSdkReferences();closed=true;}\n'+compiled_close)
    text=once(text,'    static final class NodeRef {String appTreeSignature;NodeRef(String value){appTreeSignature=value;}}',
        '    static final class SdkNode {static final List<SdkNode> made=Collections.synchronizedList(new ArrayList<SdkNode>());int recycles;'
        'SdkNode(){made.add(this);}void recycle(){expect(++recycles==1,"SDK ref recycled twice");}}\n'
        '    static final class NodeRef {final SdkNode node=new SdkNode();String appTreeSignature;NodeRef(String value){appTreeSignature=value;}}')
    # The existing Handler is the explicit main/worker IO boundary. Retain a
    # read-only reference to actual queued AX product for resource assertions,
    # and let one test hold the worker after its main callback has been posted.
    text=once(text,'        synchronized boolean post(Runnable runnable){return postDelayed(runnable,0);}',
        '''        volatile Runnable afterWorkerPost;volatile NativeAxProduct axProduct;
        private NativeAxProduct findAxProduct(Object closure,int depth){
            if(closure==null||depth>3)return null;
            for(java.lang.reflect.Field field:closure.getClass().getDeclaredFields())try{
                field.setAccessible(true);
                if(field.getType()==NativeAxProduct.class){
                    Object value=field.get(closure);if(value!=null)return (NativeAxProduct)value;
                }
                if(field.isSynthetic()&&field.getName().startsWith("this$")
                        &&Runnable.class.isAssignableFrom(field.getType())){
                    NativeAxProduct found=findAxProduct(field.get(closure),depth+1);if(found!=null)return found;
                }
            }catch(ReflectiveOperationException impossible){throw new AssertionError(impossible);}
            return null;
        }
        boolean post(Runnable runnable){
            boolean accepted;
            synchronized(this){
                accepted=postDelayed(runnable,0);
                if(accepted&&!isMain()){
                    NativeAxProduct captured=findAxProduct(runnable,0);
                    if(captured!=null)axProduct=captured;
                }
            }
            if(accepted&&!isMain()&&afterWorkerPost!=null)afterWorkerPost.run();
            return accepted;
        }''')
    # The real Android adapter reads a fresh complete window/profile census.
    # Here only its transport is synthetic; its actual historical proof registry
    # and typed target check execute against the returned independently made proof.
    text=once(text,'        requireTaskAuthorization(request.taskId,taskAuthorization);return windowValue;',
        '''        requireTaskAuthorization(request.taskId,taskAuthorization);
        if(windowValue!=null&&windowValue.profileWindow!=null){
            request.background.requireHistoricalProfileWindow(windowValue.profileWindow,windowValue.windowId,
                    windowValue.profileWindow.taskId,SystemClock.now);
            NativeAppEvidence.requireProfileTarget(request.background.profileTarget(),windowValue.profileWindow);
        }
        return windowValue;''')
    messages={
        'root':'后台根节点已不可用，需重新观察',
        'child':'后台子节点已不可用，需重新观察',
        'slot':'后台子树已变化，需重新观察',
        'hard_identity':'profile 同任务窗口在完整读取中换代',
        'hard_unknown':'文本AX观察的模型或任务绑定已退休',
    }
    throws={kind:throw_expression(service,message) for kind,message in messages.items()}
    fault='    static void actualAxReadFailure(String kind){\n        String nativePath="0/0";int index=0;\n'
    for kind,expression in throws.items():fault+='        if("'+kind+'".equals(kind))throw '+expression+';\n'
    fault+='        throw new AssertionError("unknown synthetic SDK fault");\n    }\n'
    original_main=h.body(text,'    public static void main(String[] args)throws Exception{')
    text=once(text,original_main,original_main.replace('public static void main(', 'static void legacyAxMain(',1))
    fragment=(HERE/'AxTransientReadCases.fragment').read_text()
    # Session is an explicit IO carrier here. The companion suite exercises the
    # actual private Session and Controller before this Service can be reached.
    # Reconstruct the unchanged synthetic OPEN carrier before the existing two-mode IO extension.
    # The shared observer-only template has a closed BACK type; this dedicated suite still
    # exercises its original explicit synthetic OPEN/BACK carrier and actual Service body.
    template_raw=(source/'tests/observation-pipeline/ObserverPipelineHost.template').read_bytes()
    if __import__('hashlib').sha256(template_raw).hexdigest()!='a7ec7dcd36a7e15ab3f5a97606a1082b341cd94e6069ae047281da573e3291ab':
        raise RuntimeError('exact current shared observer BACK type boundary')
    back_types='        // Type-only BACK ABI. The original synthetic OPEN IO carrier remains below.\n        static abstract class PostActionReadAccess {\n            private PostActionReadAccess(){}\n            abstract void requireCurrent();\n            abstract long transitionDeadline();\n            abstract void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int display);\n            abstract void admit(boolean retry);\n            abstract boolean admitted(boolean retry);\n        }\n        static final class CalendarBackReadPermit extends PostActionReadAccess {\n            private CalendarBackReadPermit(){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            void requireCurrent(){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            long transitionDeadline(){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int display){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            void admit(boolean retry){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            boolean admitted(boolean retry){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n        }\n'
    text=once(text,back_types,'')
    text=once(text,'        static final class PostEffectReadPermit extends PostActionReadAccess {','        static final class PostEffectReadPermit {')
    port=h.body(text,'        static final class PostEffectReadPermit {')
    base=port.replace('static final class PostEffectReadPermit','static class PostActionReadAccess',1).replace(
        'PostEffectReadPermit(NativeAppSession owner,','PostActionReadAccess(NativeAppSession owner,',1)
    if base.replace('static class PostActionReadAccess','static final class PostEffectReadPermit',1).replace(
        'PostActionReadAccess(NativeAppSession owner,','PostEffectReadPermit(NativeAppSession owner,',1)!=port:
        raise RuntimeError('Session host carrier exact inverse')
    subclasses=''
    for name in ('PostEffectReadPermit','CalendarBackReadPermit'):
        subclasses+='\n        static final class '+name+' extends PostActionReadAccess {\n'+name+'''(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int display,long transition){
            super(owner,authorization,task,selection,generation,display,transition);
        }}\n'''
    text=once(text,port,base+subclasses)
    oldcase='    static void axCase(String name,Case body)throws Exception{SnapshotChecks.run(name,()->test(name,body));}'
    newcase='''    static boolean calendarBackMode;
    static void axCase(String name,Case body)throws Exception{
        final String actual=calendarBackMode?"back_"+name:name;
        SnapshotChecks.run(actual,()->test(actual,body));
    }'''
    text=once(text,oldcase,newcase)
    fragment=once(fragment,'final NativeAppSession.PostEffectReadPermit permit;',
        'final NativeAppSession.PostActionReadAccess permit;')
    fragment=once(fragment,'permit=new NativeAppSession.PostEffectReadPermit(nativeTask,f.taskAuthorization,f.lease,bg().selection,bg().generation,9,transition);',
        '''permit=calendarBackMode?new NativeAppSession.CalendarBackReadPermit(nativeTask,f.taskAuthorization,f.lease,bg().selection,bg().generation,9,transition)
                :new NativeAppSession.PostEffectReadPermit(nativeTask,f.taskAuthorization,f.lease,bg().selection,bg().generation,9,transition);''')
    fragment=once(fragment,'try{axTransientCases(args.length>1&&"counterfactual".equals(args[1]));}',
        'try{axTransientCases(false);calendarBackMode=true;axTransientCases(false);}')
    text=once(text,'    static void legacyAxMain(String[] args)throws Exception{',fault+fragment+'\n    static void legacyAxMain(String[] args)throws Exception{')
    path.write_text(text)
    actual_members={}
    for name,anchor in {
        'proof':'    static final class PostEffectObservationRetryProof {',
        'handoff':'    private static final class PostEffectSamplingRetry {',
        'request':'    private static final class ObservationRequest {',
        'ax_product':'    private static final class NativeAxProduct {',
        'ax_worker':'    private void submitNativeAxPair(',
        'ax_main':'    private void acceptNativeAxObservation(',
        'stale':'    private static final class StaleObservation extends IllegalStateException {',
        'fresh_adapter':'    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){',
    }.items():
        body=h.body(service,anchor);actual_members[name]={'bytes':len(body.encode()),'sha256':h.sha(body.encode())}
        if name!='fresh_adapter' and text.count(body)!=1:raise RuntimeError('actual complete member not present exactly once: '+name)
    for anchor in [
        '    private static final class PostEffectAxWindowCheck {',
        '    private PostEffectAxWindowCheck recheckPostEffectAxWindow(',
        '    private PostEffectSamplingRetry postEffectAxReadCandidate(',
    ]:
        if anchor in service:
            body=h.body(service,anchor)
            if text.count(body)!=1:raise RuntimeError('new actual member missing in host')
            actual_members[anchor]={'bytes':len(body.encode()),'sha256':h.sha(body.encode())}
    meta.update(
        schema='hepta.native-ax-transient-read-extraction.v1',
        actual_members=actual_members,actual_throw_expressions=throws,
        actual_fingerprint_value_members={k:{'bytes':len(v.encode()),'sha256':h.sha(v.encode())} for k,v in value_members.items()},
        actual_graph_close={'bytes':len(actual_close.encode()),'sha256':h.sha(actual_close.encode()),'name_only_inverse':True},
        legacy_main_preserved_unexecuted={'bytes':len(original_main.encode()),'sha256':h.sha(original_main.encode())},
        native_ax_worker_and_main_and_private_proof_unchanged=True,
        fresh_android_window_transport_is_synthetic=True,actual_historical_profile_and_target_checks=True,
        sdk_recycle_is_counted_fake=True,actual_graph_close_loop_executed=True,
        session_permit_is_explicit_observer_io_port=True,real_session_consumer_is_separate_gate=True,
        phone_operations=0,android_execution=False,model_executed=False,action_endpoint_invocations=0)
    return meta

def main():
    ap=argparse.ArgumentParser()
    for n in ('source','output','java-home','json-jar'):ap.add_argument('--'+n,type=Path,required=True)
    ap.add_argument('--counterfactual',action='store_true');ap.add_argument('--generate-only',action='store_true')
    a=ap.parse_args();source=a.source.resolve();out=a.output.absolute()
    if out.exists() or source in out.parents:raise RuntimeError('new output outside input source')
    out.mkdir(parents=True,mode=0o700)
    sys.dont_write_bytecode=True
    h=load(BUNDLE/'tests/observation-diagnostics/run_host.py','ax_transient_helpers')
    snap=load(BUNDLE/'tests/native-observation-snapshot/run_host.py','ax_transient_sources')
    jar=a.json_jar.resolve();java=a.java_home/'bin/java';javac=a.java_home/'bin/javac'
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON pin')
    deps=[source/PKG/n for n in snap.JAVA]+[source/PKG/n for n in
          ('NativeXiaomiSearchInputObservation.java','NativeCtripFormObservation.java','NativeActionSnapshotCheck.java','ObservedTargetLabels.java')]
    deps+=h.png_sources(source)
    profiles=[source/'src/org/trillionnium/hepta/background'/(n+'.java') for n in ('ProfileIdentity','ProfileTarget','WindowOwnership')]
    rect=source/'tests/qualification-scope/fixtures/android/graphics/Rect.java'
    fixtures=[BUNDLE/'tests/native-observation-snapshot'/n for n in ('SnapshotChecks.java','ObservationEvidenceHost.java')]
    fixtures+=[BUNDLE/'tests/native-ax-observation/ActualAxPhoneChecks.java']
    extraction_files=[BUNDLE/p for p in (
        'tests/observation-diagnostics/run_host.py','tests/observation-pipeline/ObserverPipelineHost.template',
        'tests/native-observation-snapshot/run_host.py','tests/native-observation-snapshot/SnapshotPipelineCases.fragment',
        'tests/native-ax-observation/run_host.py','tests/native-ax-observation/AxPipelineCases.fragment',
        'tests/native-ax-observation/run_empty_loading_host.py','tests/native-ax-observation/EmptyLoadingCases.fragment')]
    inputs=list(dict.fromkeys(deps+profiles+fixtures+[rect,*extraction_files,HERE/'run_host.py',HERE/'AxTransientReadCases.fragment',
        source/PKG/'BackgroundSession.java',source/PKG/'NativeCtripFlightPage.java',source/PKG/'NativeAppGoal.java']))
    tools=[java,javac,a.java_home/'lib/modules',a.java_home/'lib/ct.sym',jar]
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    report={'schema':'hepta.native-ax-transient-read-host.v1','all_pass':False,'stages':[],'input_before':before,'tools_before':tool_before,
        'counterfactual':a.counterfactual,'generation_only':a.generate_only,'phone_operations':0,'android_execution':False,
        'model_executed':False,'business_completion_verified':False,'deadline_expanded':False,'action_freshness_relaxed':False}
    try:
        generated=out/'generated';generated.mkdir();meta=generate(source,generated,h);h.save(out/'EXTRACTION.json',meta)
        sources=list(dict.fromkeys([p for p in deps if p.name not in ('HeptaAccessibilityService.java','LocalTaskController.java','NativeAppEvidence.java')]
            +profiles+fixtures+[rect,generated/'ObserverPipelineHost.java']))
        report['compile_inputs']=[h.meta(p) for p in sources];report['extraction_file']=h.meta(out/'EXTRACTION.json')
        report['generated_file']=h.meta(generated/'ObserverPipelineHost.java')
        if not a.generate_only:
            classes=out/'classes';classes.mkdir()
            compile_argv=[str(javac),'-J-Xmx512m','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))
            run_argv=[str(java),'-Xmx512m','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObserverPipelineHost',str(out/'CASES.json')]
            if a.counterfactual:run_argv.append('counterfactual')
            report['stages'].append(h.stage('compile',compile_argv,out))
            if report['stages'][-1]['exit_code']!=0:raise RuntimeError('actual AX transient bridge compile failed')
            report['stages'].append(h.stage('cases',run_argv,out))
            if (out/'CASES.json').exists():report['cases']=json.loads((out/'CASES.json').read_text());report['cases_file']=h.meta(out/'CASES.json')
            if report['stages'][-1]['exit_code']!=0:raise RuntimeError('actual AX transient bridge cases failed')
            cases=report['cases']
            if cases['all_pass'] is not True or cases['cases']!=len(set(cases['case_names'])) or cases['cases']!=len(cases['case_names']):raise RuntimeError('case accounting')
        report['all_pass']=True
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['input_after']=[h.meta(p) for p in inputs];report['tools_after']=[h.meta(p) for p in tools]
        report['inputs_unchanged']=before==report['input_after'];report['tools_unchanged']=tool_before==report['tools_after']
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged'];h.save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'cases':report.get('cases',{}).get('cases'),'result':h.meta(out/'RESULT.json')}))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
