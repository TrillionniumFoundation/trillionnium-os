#!/usr/bin/env python3
"""Execute actual bounded diagnostic producers/consumer with explicit host IO.

The complete actual Service observation block, diagnostic factory/snapshot,
already-observed-row projection and action receipt helpers, and complete actual
Controller awaitObservationRaw are extracted without editing their bodies.
Android graph, clock, callback, authorization and disk endpoints are host fakes.
No host result claims Android execution, cleanup, business success or authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

PKG = Path('src/org/trillionnium/hepta/local')
TEST = Path('tests/observation-diagnostics')
JAVA = ['HeptaAccessibilityService.java','LocalTaskController.java','ObservationDiagnostics.java',
        'ObservationStabilityGate.java','ActionExecutionState.java','TaskCancellationQueue.java']
OWN = ['run_host.py','DiagnosticChecks.java','ObservationDiagnosticsHostTest.java',
       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template']

def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(path):
    path=Path(path).absolute();raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw),'mode':path.stat().st_mode&0o777}
def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(raw,str):raw=raw.encode()
    with path.open('xb') as stream:stream.write(raw)
    os.chmod(path,0o600)
def save(path,value):write(path,json.dumps(value,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
def section(raw,start,end):
    if raw.count(start)!=1 or raw.count(end)!=1:raise RuntimeError('nonunique source anchors: '+start)
    first=raw.index(start);return raw[first:raw.index(end,first)]
def body(raw,start):
    if raw.count(start)!=1:raise RuntimeError('nonunique body anchor: '+start)
    first=raw.index(start);i=raw.index('{',first);depth=0;mode='code';escape=False
    while i<len(raw):
        c=raw[i];pair=raw[i:i+2]
        if mode=='line':
            if c=='\n':mode='code'
        elif mode=='comment':
            if pair=='*/':mode='code';i+=1
        elif mode in ('string','char'):
            if escape:escape=False
            elif c=='\\':escape=True
            elif c==('"' if mode=='string' else "'"):mode='code'
        elif pair=='//':mode='line';i+=1
        elif pair=='/*':mode='comment';i+=1
        elif c=='"':mode='string'
        elif c=="'":mode='char'
        elif c=='{':depth+=1
        elif c=='}':
            depth-=1
            if depth==0:return raw[first:i+1]
        i+=1
    raise RuntimeError('unterminated body')
def generate(source,output):
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    controller=(source/PKG/'LocalTaskController.java').read_text()
    parts={
      'observation_callback':section(service,'    public interface ObservationCallback','    public interface Cancellation'),
      'diagnostic':section(service,'    private String diagnosticTask;','    /** Each observation owns'),
      'acquire':section(service,'    public synchronized boolean acquireTask(','    public synchronized void releaseTask('),
      'recovery_idle':section(service,'    synchronized boolean recoveryControllerIdle(','    synchronized void retireControllerAfterAcknowledgement('),
      'action_pending':section(service,'    boolean actionWorkPending()','    void retireActionWork('),
      'cancellation_pending':section(service,'    boolean nativeCancellationWorkPending()','    boolean requestNativeCancellation('),
      'observation':section(service,'    /** Each observation owns','    synchronized void bindQualificationScope(')}
    template=(source/'tests/observation-pipeline/ObserverPipelineHost.template').read_text()
    for name,value in parts.items():
        marker='{{'+name+'}}'
        if template.count(marker)!=1:raise RuntimeError('pipeline marker '+name)
        template=template.replace(marker,value,1)
    main=body(template,'    public static void main(String[] args)throws Exception{')
    template=template.replace(main,(source/TEST/'DiagnosticPipelineCases.fragment').read_text(),1)
    if '{{' in template:raise RuntimeError('unfilled pipeline fixture')
    write(output/'ObserverPipelineHost.java',template)
    methods={
        'native_stamp':body(service,'    private static ObservationDiagnostics.GraphStamp nativeDiagnosticStamp(Graph graph){'),
        'stale_record':body(service,'    private static void recordStaleDiagnostic(ActionWork work,Graph before,Graph after,String selectedId){'),
        'action_evidence':body(service,'    private static JSONObject actionDiagnosticEvidence(ActionWork work){'),
        'take_diagnostics':body(controller,'    private JSONObject takeObservationDiagnostics(String task){'),
        'await_observation':body(controller,'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline)throws Exception{')}
    for fixture,names in [('DiagnosticGraphHost',['native_stamp','stale_record','action_evidence']),('DiagnosticControllerHost',['await_observation','take_diagnostics'])]:
        text=(source/TEST/(fixture+'.template')).read_text()
        for name in names:
            marker='{{'+name+'}}'
            if text.count(marker)!=1:raise RuntimeError('method marker '+name)
            text=text.replace(marker,methods[name],1)
        if '{{' in text:raise RuntimeError('unfilled '+fixture)
        write(output/(fixture+'.java'),text)
    # Preserve the exact native guard and original default refusal call site.
    # This observer suite does not qualify the separate native action guard.
    branch='''}else if(!graph.digest.equals(now.digest)){
                    if(work!=null&&work.nativeGuard!=null){
                        try{compareNativeAction(taskId,expected,action,now,work);work.nativeActionRevalidated=true;}
                        catch(Exception mismatch){recordStaleDiagnostic(work,graph,now,action.nodeId);
                            return "stale:原生目的复核失败："+message(mismatch);}
                    }else{recordStaleDiagnostic(work,graph,now,action.nodeId);return "stale:目标窗口内容已变化";}
                }'''
    if service.count(branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')
    callback='callback.onResult(delivered.withActionExecution(actionDiagnosticEvidence(work)));'
    if service.count(callback)!=1:raise RuntimeError('actual action callback must consume diagnostic evidence')
    await_body=methods['await_observation'];finally_body=await_body[await_body.index('        }finally{\n            abandoned.set(true);'):]
    if any(token in finally_body for token in ('record(', 'System.err', 'System.out', '.wait(', '.sleep(')):raise RuntimeError('diagnostic finally must not perform IO or wait')
    finalization=section(controller,'        finally{\n            service.retireActionWork(taskId,', '    private static NotesCompletionEvidence.Frame completionFrame(')
    positions=[finalization.index(token) for token in ['backgroundCleanup=background.close();','modelCleanup=inference.endTask();','terminalDecisionSealed=true;','record(evidence,"result.json"','takeObservationDiagnostics(taskId)','if(cleanup)service.releaseTask(taskId);','running=false;','selected.onFinished(result)']]
    if positions!=sorted(positions) or finalization.count('takeObservationDiagnostics(taskId)')!=1:raise RuntimeError('original cleanup then existing terminal record order required')
    if controller.count('pendingObservationDiagnostics.add(')!=1 or controller.count('pendingObservationDiagnostics.size()<96')!=1:raise RuntimeError('bounded single memory admission required')
    extraction={'schema':'hepta.observation-diagnostics-extraction.v1','bodies_verbatim':True,
        'sources':{'service':meta(source/PKG/'HeptaAccessibilityService.java'),'controller':meta(source/PKG/'LocalTaskController.java')},
        'methods':{name:{'bytes':len(value.encode()),'sha256':sha(value.encode())} for name,value in {**parts,**methods}.items()},
        'stale_refusal_callsite':{'bytes':len(branch.encode()),'sha256':sha(branch.encode())},
        'action_callback_callsite':{'bytes':len(callback.encode()),'sha256':sha(callback.encode())},
        'legacy_pipeline_main_not_replaced_in_source':True,
        'default_whole_graph_action_refusal_retained':True,'native_action_guard_qualification_claimed':False,
        'diagnostic_finally_has_no_IO_or_wait':True,'terminal_diagnostic_uses_only_existing_result_write':True,
        'cleanup_terminal_order_source_sha256':sha(finalization.encode()),
        'boundary':'Actual Service/Controller bodies, pure tracker and stability gate. Android graph/clock, already-observed row carriers, Session carrier, callback/authorization and disk endpoints are explicit host fakes; no Android/currentness or business qualification.'}
    return extraction

def stage(name,argv,output):
    begin=time.monotonic_ns()
    with (output/(name+'.stdout')).open('xb') as stdout,(output/(name+'.stderr')).open('xb') as stderr:
        proc=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=90,check=False)
    return {'name':name,'argv':argv,'exit_code':proc.returncode,'elapsed_ns':time.monotonic_ns()-begin,
            'stdout':meta(output/(name+'.stdout')),'stderr':meta(output/(name+'.stderr'))}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True);ap.add_argument('--json-jar',type=Path,required=True);args=ap.parse_args()
    source=args.source.resolve();output=args.output.absolute();output.mkdir(parents=True,exist_ok=False)
    jdk=args.java_home.resolve();java=jdk/'bin/java';javac=jdk/'bin/javac';jar=args.json_jar.resolve()
    tools=[java,javac,jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    if not all(p.is_file() for p in tools):raise RuntimeError('complete strict JDK and JSON tool closure required')
    if jar.stat().st_size!=78332 or sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('pinned JSON jar required')
    paths=[source/PKG/x for x in JAVA]+[source/TEST/x for x in OWN]+[source/'tests/observation-pipeline/ObserverPipelineHost.template']+tools
    before=[meta(x) for x in paths];tools_before=[meta(x) for x in tools]
    report={'schema':'hepta.observation-diagnostics-host-gate.v1','all_pass':False,'stages':[],
        'input_before':before,'tools_before':tools_before,'android_execution':False,'phone_execution':False,'phone_operations':0,
        'model_executed':False,'business_completion_verified':False,'sdk_loaded':False,
        'action_guard_changed':True,'native_action_guard_qualification_claimed':False,
        'compiler_contract':'JDK17 --release 8 -Xlint:all -Werror',
        'boundary':'Production observer/consumer methods execute with explicit host IO; no device or effect authority.'}
    try:
        generated=output/'generated';generated.mkdir();extraction=generate(source,generated);save(output/'EXTRACTION.json',extraction)
        classes=output/'classes';classes.mkdir()
        sources=[source/PKG/x for x in JAVA if x not in ('HeptaAccessibilityService.java','LocalTaskController.java')]
        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))
        command=[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))
        compiled=stage('compile',command,output);report['stages'].append(compiled)
        if compiled['exit_code']!=0:raise RuntimeError('actual diagnostic wiring compilation failed')
        executed=stage('cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObservationDiagnosticsHostTest',str(output/'CASES.json')],output);report['stages'].append(executed)
        if executed['exit_code']!=0:raise RuntimeError('actual diagnostic wiring cases failed')
        cases=json.loads((output/'CASES.json').read_text())
        if cases['all_pass'] is not True or cases['cases']!=len(cases['case_names']) or len(set(cases['case_names']))!=cases['cases']:raise RuntimeError('complete unique case identity required')
        report['cases']=cases;report['cases_file']=meta(output/'CASES.json');report['extraction_file']=meta(output/'EXTRACTION.json')
        report['generated_files']={p.name:meta(p) for p in sorted(generated.glob('*.java'))}
        report['actual_Service_observation_and_callback_compiled_verbatim']=True
        report['actual_Controller_await_compiled_verbatim']=True
        report['actual_native_graph_projection_and_stale_receipt_compiled_verbatim']=True
        report['original_deadline_and_guard_calls_retained']=True;report['all_pass']=True
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['input_after']=[meta(x) for x in paths];report['tools_after']=[meta(x) for x in tools]
        report['inputs_unchanged']=report['input_after']==before;report['tools_unchanged']=report['tools_after']==tools_before
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged'];save(output/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'result':meta(output/'RESULT.json')}));return 0 if report['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())
