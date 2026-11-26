#!/usr/bin/env python3
"""Actual AX worker/private handoff plus original observer with explicit SDK IO.
This is a host source bridge. The separate Controller retry gate supplies the real
Session entered-OPEN/durable-outcome/once budget consumer; no Phone is invoked.
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
    base=load(BUNDLE/'tests/native-ax-transient-read/run_host.py','sampling_pair_ax_base')
    meta=base.generate(source,out,h);path=out/'ObserverPipelineHost.java';text=path.read_text()
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    pair_anchor='    /** Ctrip native post-effect observation only; no deadline, permit or action is created. */'
    feature=pair_anchor in service
    real_helpers=None;port=None
    if feature:
        real_helpers=h.section(service,pair_anchor,'    private void sampleObservation(final ObservationRequest request){')
        projected,boundary=h.native_ax_sampling_legacy_parts(service,{'observation':real_helpers})
        port=projected['observation']
        text=once(text,port,real_helpers)
    # Original producer and all prior AX cases remain compiled. Main selects only
    # the new sampling-pair suite; legacy suites execute separately unchanged.
    old_main=h.body(text,'    public static void main(String[] args)throws Exception{')
    text=once(text,old_main,old_main.replace('public static void main(', 'static void legacyTransientMain(',1))
    # Explicit Session transport port, identical OPEN ownership/admission checks
    # under a distinct closed BACK type. Actual BACK consumer is a separate gate.
    back=h.body(text,'        static final class CalendarBackReadPermit extends PostActionReadAccess {')
    opened=h.body(text,'        static final class PostEffectReadPermit extends PostActionReadAccess {')
    replacement=opened.replace('PostEffectReadPermit','CalendarBackReadPermit')
    text=once(text,back,replacement)
    handler=r'''        volatile Runnable samplePosted;volatile Graph sampleGraph;
        volatile int legacySampleArity;final AtomicInteger legacyDeliveries=new AtomicInteger();
        private ObservationRequest sampleRequest(Object closure,int depth){
            if(closure==null||depth>3)return null;
            for(java.lang.reflect.Field field:closure.getClass().getDeclaredFields())try{
                field.setAccessible(true);Object value=field.get(closure);
                if(field.getType()==ObservationRequest.class&&value!=null)return (ObservationRequest)value;
                if(field.isSynthetic()&&field.getName().startsWith("this$")&&Runnable.class.isAssignableFrom(field.getType())){
                    ObservationRequest found=sampleRequest(value,depth+1);if(found!=null)return found;
                }
            }catch(ReflectiveOperationException unavailable){throw new AssertionError(unavailable);}
            return null;
        }
        private Runnable sampleDelivery(Runnable original){
            boolean sample=false;ObservationRequest request=null;Graph graph=null;String error=null;
            CtripFormSampleRead form=null;long events=0,unknown=0;
            try{
                for(java.lang.reflect.Field field:original.getClass().getDeclaredFields()){
                    field.setAccessible(true);Object value=field.get(original);String name=field.getName();
                    if(field.getType().getSimpleName().equals("NativeAxSampleRead"))sample=true;
                    if(field.getType()==ObservationRequest.class)request=(ObservationRequest)value;
                    if(field.getType()==Graph.class)graph=(Graph)value;
                    if(field.getType()==CtripFormSampleRead.class)form=(CtripFormSampleRead)value;
                    if(field.getType()==String.class&&name.endsWith("$failure"))error=(String)value;
                    if(field.getType()==long.class&&name.endsWith("$events"))events=field.getLong(original);
                    if(field.getType()==long.class&&name.endsWith("$unknownEvents"))unknown=field.getLong(original);
                }
            }catch(ReflectiveOperationException unavailable){throw new AssertionError(unavailable);}
            if(!sample)return original;
            if(request==null)request=sampleRequest(original,0);
            sampleGraph=graph;if(samplePosted!=null)samplePosted.run();
            if(legacySampleArity==0)return original;
            final ObservationRequest r=request;final Graph g=graph;final String failure=error;
            final CtripFormSampleRead formRead=form;final long ev=events,un=unknown;final int arity=legacySampleArity;
            expect(r!=null,"actual queued sample request");
            return new Runnable(){public void run(){
                legacyDeliveries.incrementAndGet();
                if(arity==5)live.acceptSample(r,g,failure,ev,un);
                else if(arity==6)live.acceptSample(r,g,failure,ev,un,formRead);
                else throw new AssertionError("only explicit old callback signatures");
            }};
        }
        boolean post(Runnable runnable){
            runnable=sampleDelivery(runnable);'''
    text=once(text,'        boolean post(Runnable runnable){',handler)
    fragment=(HERE/'SamplingPairCases.fragment').read_text()
    text=once(text,'    static void legacyTransientMain(String[] args)throws Exception{',
              fragment+'\n    static void legacyTransientMain(String[] args)throws Exception{')
    # All actual request/callback/worker/AX members remain complete current source.
    actual={}
    anchors=['    private void sampleObservation(final ObservationRequest request){',
             '    private static final class ObservationRequest {',
             '    private static final class NativeAxProduct {',
             '    private void captureNativeAxObservation(final ObservationRequest request){',
             '    private void submitNativeAxPair(',
             '    private void acceptNativeAxObservation(']
    if feature:
        anchors+=['    private static final class NativeAxSample {',
                  '    private static final class NativeAxSampleRead {',
                  '    private static final class NativeAxSamplePair {']
    for anchor in anchors:
        member=h.body(service,anchor)
        if text.count(member)!=1:raise RuntimeError('complete actual member missing: '+anchor)
        actual[anchor]={'bytes':len(member.encode()),'sha256':h.sha(member.encode())}
    if feature and text.count(real_helpers)!=1:raise RuntimeError('complete actual pair helpers not restored')
    path.write_text(text);os.chmod(path,0o600)
    meta.update(schema='hepta.native-ax-sampling-pair-extraction.v1',actual_members=actual,
        actual_sampling_pair_feature=feature,actual_helper_sha256=None if real_helpers is None else h.sha(real_helpers.encode()),
        explicit_no_pair_legacy_port_removed=feature,actual_seven_argument_callback_unchanged=feature,
        previous_case_fragments_retained_unchanged=True,legacy_cases_selected_by_separate_original_runners=True,
        synthetic_graph_and_window_and_session_io=True,real_current_receipt_consumer=True,
        model_executed=False,phone_operations=0,android_execution=False,action_endpoint_invocations=0)
    return meta

def main():
    ap=argparse.ArgumentParser()
    for n in ('source','output','java-home','json-jar'):ap.add_argument('--'+n,type=Path,required=True)
    ap.add_argument('--counterfactual',action='store_true');ap.add_argument('--generate-only',action='store_true')
    ap.add_argument('--recorded-original',type=Path,required=True)
    a=ap.parse_args();source=a.source.resolve();out=a.output.absolute()
    if out.exists() or source in out.parents:raise RuntimeError('new output outside input source')
    out.mkdir(parents=True,mode=0o700)
    sys.dont_write_bytecode=True
    h=load(BUNDLE/'tests/observation-diagnostics/run_host.py','ax_transient_helpers')
    snap=load(BUNDLE/'tests/native-observation-snapshot/run_host.py','ax_transient_sources')
    jar=a.json_jar.resolve();java=a.java_home/'bin/java';javac=a.java_home/'bin/javac'
    original=a.recorded_original.resolve()
    if original.stat().st_size!=558755 or h.sha(original.read_bytes())!='e0d028dfc678f457fbd26c4d6085abca5b0bba836bae8625a1c62200a6091d35':raise RuntimeError('exact unpublished 8120 complete-pair original required')
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
    inputs=list(dict.fromkeys(deps+profiles+fixtures+[rect,*extraction_files,HERE/'run_host.py',HERE/'SamplingPairCases.fragment',original,
        BUNDLE/'tests/native-ax-transient-read/run_host.py',BUNDLE/'tests/native-ax-transient-read/AxTransientReadCases.fragment',
        source/PKG/'BackgroundSession.java',source/PKG/'NativeCtripFlightPage.java',source/PKG/'NativeAppGoal.java']))
    tools=[java,javac,a.java_home/'lib/modules',a.java_home/'lib/ct.sym',jar]
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    report={'schema':'hepta.native-ax-sampling-pair-host.v1','all_pass':False,'stages':[],'input_before':before,'tools_before':tool_before,
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
            run_argv=[str(java),'-Xmx512m','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObserverPipelineHost',str(out/'CASES.json'),str(original)]
            if a.counterfactual:run_argv.append('counterfactual')
            report['stages'].append(h.stage('compile',compile_argv,out))
            if report['stages'][-1]['exit_code']!=0:raise RuntimeError('actual sampling callback/AX bridge compile failed')
            report['stages'].append(h.stage('cases',run_argv,out))
            if (out/'CASES.json').exists():report['cases']=json.loads((out/'CASES.json').read_text());report['cases_file']=h.meta(out/'CASES.json')
            if report['stages'][-1]['exit_code']!=0:raise RuntimeError('actual sampling callback/AX cases failed')
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
