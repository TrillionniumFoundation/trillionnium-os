#!/usr/bin/env python3
"""Actual initial request factory, seven-argument callback and original AX receipt consumer.
This host source bridge never invents an effect permit. Its SDK, clock, task and
profile transport are explicit host IO; the failed 6b67 raw pair stays a negative.
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
    base=load(BUNDLE/'tests/native-ax-sampling-pair/run_host.py','initial_pair_original_sampling_base')
    meta=base.generate(source,out,h);path=out/'ObserverPipelineHost.java';text=path.read_text()
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    original_main=h.body(text,'    public static void main(String[] args)throws Exception{')
    text=once(text,original_main,original_main.replace('public static void main(', 'static void legacyPostEffectSamplingMain(',1))
    fragment=(HERE/'InitialSamplingPairCases.fragment').read_text()
    text=once(text,'    static void legacyPostEffectSamplingMain(String[] args)throws Exception{',
              fragment+'\n    static void legacyPostEffectSamplingMain(String[] args)throws Exception{')
    actual={}
    anchors=['    void observeInitialNative(final Object controller,final Object nativeTask,final String taskId,',
             '    private synchronized void admitInitialObservation(',
             '    private synchronized void recordObservationAdmission(',
             '    private synchronized boolean initialObservationOwner(',
             '    private synchronized void bindNativeAxObservationRequest(',
             '    private static final class NativeAxSample {',
             '    private static boolean nativeAxEqual(',
             '    private boolean recheckNativeAxPublication(',
             '    private void acceptNativeAxObservation(']
    feature='    private boolean nativeAxInitialSamplingOwner(' in service
    if feature:anchors+=['    private boolean nativeAxInitialSamplingOwner(',
                         '    private boolean nativeAxPostEffectSamplingOwner(']
    for anchor in anchors:
        member=h.body(service,anchor)
        if text.count(member)!=1:raise RuntimeError('complete actual initial/publication member missing: '+anchor)
        actual[anchor]={'bytes':len(member.encode()),'sha256':h.sha(member.encode())}
    path.write_text(text);os.chmod(path,0o600)
    meta.update(schema='hepta.native-initial-ax-sampling-extraction.v1',
        actual_initial_members=actual,actual_initial_sampling_feature=feature,
        actual_initial_request_factory_and_admission_and_ordinal=True,
        actual_seven_argument_callback=True,whole_census_equality_unchanged=True,
        original_receipt_and_late_event_recheck_unchanged=True,
        stable_case_is_two_independent_host_reads_of_recorded_before_values=True,
        recorded_different_before_after_pair_is_negative_only=True,
        actual_phone_stable_pair_claimed=False,synthetic_clock_scope_profile_sdk_io=True,
        previous_post_effect_case_fragment_retained_unchanged=True,
        previous_main_retained_unexecuted={'bytes':len(original_main.encode()),'sha256':h.sha(original_main.encode())})
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
    if original.stat().st_size!=244162 or h.sha(original.read_bytes())!='efea131df773bbfec21fba9d75f38e6aea26cec55660fd7d08ce0ff5303900d0':raise RuntimeError('exact unpublished 6b67 initial complete-pair original required')
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
    inputs=list(dict.fromkeys(deps+profiles+fixtures+[rect,*extraction_files,HERE/'run_host.py',HERE/'InitialSamplingPairCases.fragment',original,
        BUNDLE/'tests/native-ax-transient-read/run_host.py',BUNDLE/'tests/native-ax-transient-read/AxTransientReadCases.fragment',
        BUNDLE/'tests/native-ax-sampling-pair/run_host.py',BUNDLE/'tests/native-ax-sampling-pair/SamplingPairCases.fragment',
        source/PKG/'BackgroundSession.java',source/PKG/'NativeCtripFlightPage.java',source/PKG/'NativeAppGoal.java']))
    tools=[java,javac,a.java_home/'lib/modules',a.java_home/'lib/ct.sym',jar]
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    report={'schema':'hepta.native-initial-ax-sampling-host.v1','all_pass':False,'stages':[],'input_before':before,'tools_before':tool_before,
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
