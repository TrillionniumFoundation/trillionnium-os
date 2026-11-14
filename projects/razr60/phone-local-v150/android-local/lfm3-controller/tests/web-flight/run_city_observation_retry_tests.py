#!/usr/bin/env python3
"""Run the new retry policy against exact current Session blocks and an actual successful query closure."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

def pin(path):
    raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def classes(root):
    return [dict(pin(p),relative=str(p.relative_to(root))) for p in sorted(root.rglob('*.class'))]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--query-output',type=Path,required=True)
    ap.add_argument('--json-jar',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--java',default='java');ap.add_argument('--compiler-contract',choices=('release8','local-source8-target8'),default='release8')
    a=ap.parse_args();here=Path(__file__).resolve().parent;root=here.parents[1]
    session=root/'src/org/trillionnium/hepta/local/WebFlightSession.java';query_runner=here/'run_query_host_tests.py';test=here/'WebCityObservationRetryHostTest.java'
    receipt=a.query_output/'RESULT.json';query=json.loads(receipt.read_bytes())
    assert query['all_pass'] is True and query['cases']['cases']==40 and query['cases']['assertions']==187
    assert query['originals_unchanged'] is True
    for row in query['source_inputs']:assert pin(Path(row['path']))==row
    assert pin(a.json_jar)['sha256']=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
    initial_classes=classes(a.query_output/'classes');inputs=list(map(pin,[session,query_runner,test,Path(__file__).resolve(),receipt,a.json_jar]))
    spec=importlib.util.spec_from_file_location('pinned_query_functions',query_runner);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    raw=session.read_bytes();text=raw.decode();signatures=['private static final class CityObservationRetry','private boolean retryLoadingDocument(','private static String loadingKey(']
    blocks=[m.java_block(raw,s) for s in signatures]
    consume='CityObservationRetry observationRetry=cityObservationRetry;cityObservationRetry=null;'
    assert text.count(consume)==1
    new_action='    void beforeModelAction(ActionDecision action,String run,long deadline)throws Exception{\n        cityObservationRetry=null;'
    assert text.count(new_action)==1
    source='''package org.trillionnium.hepta.local;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import java.util.UUID;
/** Exact production retry predicates, with synthetic clock and explicit Android IO boundaries. */
final class WebCityObservationRetryProjection {
 private WebFlightGoal goal;private WebTaskPurpose purpose;private TaskAuthorization.Gate authorization;
 private String taskId;private final Background background=new Background();private final Service service=new Service();
 private final Journal journal=new Journal();private final Cancellation cancellation=new Cancellation();private boolean retired;
 private WebFlightProgress flightProgress;private final java.util.concurrent.atomic.AtomicBoolean nativeQueryEntered=new java.util.concurrent.atomic.AtomicBoolean();
 private String loadingDocumentKey;private long loadingDocumentStarted,loadingDocumentDeadline;private int loadingDocumentReadRetries;
 private CityObservationRetry cityObservationRetry;private final java.util.List<JSONObject> records=new java.util.ArrayList<JSONObject>();
 static final class SystemClock {static long value;static long elapsedRealtime(){return value;}static void sleep(long duration){value+=duration;}}
 private static final class Background {String generation;void requireActive(){}}
 private static final class Service {void requireTaskAuthorization(String task,TaskAuthorization.Gate gate){if(!gate.taskId.equals(task))throw new AssertionError("host task mismatch");}}
 private static final class Journal {String bindingSha;}
 private static final class Cancellation {boolean cancelled;boolean isCancelled(){return cancelled;}}
 private void record(String name,JSONObject value){if(name==null||value==null)throw new AssertionError("record identity");records.add(new JSONObject(value.toString()));}
 private static void need(boolean yes,String reason){WebEvidenceJson.need(yes,reason);}
'''+'\n'.join(blocks)+'''
 WebCityObservationRetryProjection(WebFlightDomain before,WebTaskPurpose purpose){
  this.purpose=purpose;goal=purpose.flight;taskId=before.taskId;authorization=purpose.authorization.bind(taskId);
  background.generation=before.generation;journal.bindingSha=before.bindingSha;
 }
 Object token(WebFlightDomain before,ActionDecision action,String run,boolean accepted,boolean dispatched,boolean stale,long start,long end){
  return CityObservationRetry.fromOutcome(before,action,run,accepted,dispatched,stale,start,end);
 }
 void store(Object token){cityObservationRetry=(CityObservationRetry)token;}
 Object consume(){'''+consume+'''return observationRetry;}
 void newAction(){cityObservationRetry=null;}
 void now(long value){SystemClock.value=value;}
 boolean retry(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,boolean stable,WebDomStability.Result bracket,Object token,long deadline)throws Exception{
  return retryLoadingDocument(first,last,frame,stable,bracket,(CityObservationRetry)token,deadline);
 }
 int retries(){return loadingDocumentReadRetries;}int records(){return records.size();}
 void foreignTask(){taskId="99999999999999999999999999999999";}
 void foreignOwner()throws Exception{purpose=WebTaskPurpose.fromOwner("查一下2026年11月18日北京到上海的单程机票，1名成人");}
 void foreignGeneration(){background.generation="32345678-1234-1234-1234-123456789012";}
 void queryEntered(){nativeQueryEntered.set(true);}void cancel(){cancellation.cancelled=true;}void retire(){retired=true;cityObservationRetry=null;}
}
'''
    out=a.out.resolve();out.mkdir(exist_ok=False);generated=out/'WebCityObservationRetryProjection.java';generated.write_text(source)
    compiled=out/'classes';compiled.mkdir();empty=out/'empty-sourcepath';empty.mkdir();commands=[]
    cp=os.pathsep.join([str(a.query_output/'classes'),str(a.json_jar)])
    def run(name,argv):
        p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=60,check=False,env=dict(os.environ,LANG='C',LC_ALL='C'))
        stdout=out/(name+'.stdout');stderr=out/(name+'.stderr');stdout.write_bytes(p.stdout);stderr.write_bytes(p.stderr)
        commands.append({'name':name,'argv':list(map(str,argv)),'exit_code':p.returncode,'stdout':pin(stdout),'stderr':pin(stderr)});return p.returncode
    flags=['--release','8','-Xlint:all'] if a.compiler_contract=='release8' else ['-source','8','-target','8','-Xlint:all,-options']
    code=run('compile',[a.java,'-m','jdk.compiler/com.sun.tools.javac.Main',*flags,'-encoding','UTF-8','-Werror','-proc:none','-implicit:none',
        '-sourcepath',empty,'-classpath',cp,'-d',compiled,generated,test])
    cases=out/'CASES.json'
    if code==0:run('city-retry-cases',[a.java,'-Xmx384m','-cp',str(compiled)+os.pathsep+cp,'org.trillionnium.hepta.local.WebCityObservationRetryHostTest',cases])
    assert inputs==list(map(pin,[session,query_runner,test,Path(__file__).resolve(),receipt,a.json_jar]))
    assert initial_classes==classes(a.query_output/'classes')
    for row in query['source_inputs']:assert pin(Path(row['path']))==row
    passed=code==0 and len(commands)==2 and commands[1]['exit_code']==0
    result={'schema':'hepta.city-observation-retry-host-result.v1','all_pass':passed,'compiler_contract':a.compiler_contract,
        'scope':'synthetic_pages_outcomes_clock_android_io_actual_source_methods','source_inputs':inputs,
        'query_compiled_source_inputs':query['source_inputs'],'query_classes_before_after':initial_classes,
        'query_classes_unchanged':True,'source_inputs_before_after_unchanged':True,'commands':commands,
        'extracted_blocks':[{'signature':s,'bytes':len(b.encode()),'sha256':hashlib.sha256(b.encode()).hexdigest()} for s,b in zip(signatures,blocks)],
        'observe_entry_consume_statement_byte_preserved':consume,'before_model_action_clear_statement_byte_preserved':True,
        'generated_projection':pin(generated),'new_classes':classes(compiled),
        'cases':json.loads(cases.read_bytes()) if cases.exists() else None,
        'query40_rerun_here':False,'full_android_session_compiled':False,'phone_operations':0,'business_verified':False}
    target=out/'RESULT.json';target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'result':pin(target),'all_pass':passed,'cases':result['cases']}));raise SystemExit(0 if passed else 1)

if __name__=='__main__':main()
