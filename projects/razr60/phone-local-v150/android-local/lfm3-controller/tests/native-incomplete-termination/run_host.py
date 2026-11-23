#!/usr/bin/env python3
"""Actual native incomplete-terminal consumer with explicit host Android lifecycle ports."""
import argparse,hashlib,importlib.util,json,os,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
EXPECTED_CASES=[
"historical_failure_consumes_without_ui_or_post_observation",
"historical_partial_consumes_without_ui_or_success",
"ordinary_ax_failure_keeps_actual_native_journal",
"same_model_run_cannot_be_consumed_twice",
"wrong_task_is_rejected_before_terminal_journal",
"same_value_different_gate_is_rejected",
"service_replaced_gate_is_rejected",
"wrong_observation_grammar_is_rejected",
"excluded_done_status_is_rejected",
"retired_or_replaced_native_domain_is_rejected",
"success_remains_on_original_controller_path",
"non_native_failure_remains_on_original_path",
"cancelled_task_cannot_consume",
"expired_task_cannot_consume",
"receipt_collision_never_creates_accepted_outcome",
"invalid_model_run_is_rejected",
"native_retirement_and_terminal_cannot_promote_failure",
"malformed_done_raw_is_rejected_by_actual_parser"]
def sha(b):return hashlib.sha256(b).hexdigest()
def ref(p):
 p=Path(p).resolve();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=p.stat().st_mode&0o777)
def tree(p):
 out=[]
 for q in sorted(p.rglob("*")):
  if q.is_symlink():raise RuntimeError("symlink source")
  if q.is_file():out.append(dict(ref(q),relative_path=str(q.relative_to(p))))
 return out
def put(p,v):
 with p.open("x",encoding="utf8") as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write("\n")
 return ref(p)
def module(p,n):
 spec=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def prepare(source,out):
 c=module(source/"tests/native-search-planning/host_closure.py","incomplete_actual_closure")
 q=module(source/"tests/web-flight/run_query_host_tests.py","incomplete_extract")
 host=source/"tests/native-incomplete-termination/NativeIncompleteTerminationHostTest.java"
 fixture=source/"tests/native-form-history-consumers/NativeFormHistoryConsumersHostTest.java"
 paths,proof=c.prepare(source,out,(host,fixture))
 # The closure's absent Calculator type is not sufficient for actual phase checks.
 absent=out/"ports/org/trillionnium/hepta/local/CalculatorGoalContract.java"
 paths=[p for p in paths if p.resolve()!=absent.resolve()]
 local=source/"src/org/trillionnium/hepta/local"
 for name in ("ActionPolicy","NotesTaskPhaseGuard","CalculatorTaskInputGuard","CalculatorGoalContract","CalculatorCompletionEvidence"):
  paths.append(local/(name+".java"))
 ltc=local/"LocalTaskController.java";ha=local/"HeptaAccessibilityService.java"
 raw=ltc.read_bytes();text=raw.decode()
 sigs=["private boolean consumeControllerIncompleteTerminal(","private void checkActive(","private static final class Stopped ","private static String answerJson(","private static void record(File"]
 actual=[q.java_block(raw,s) for s in sigs]
 branch_start=text.index("                if(consumeControllerIncompleteTerminal(")
 branch_end=text.index('                emit("正在执行第 "+steps+',branch_start)
 branch=text[branch_start:branch_end]
 if text.count("if(consumeControllerIncompleteTerminal(")!=1 or "awaitAction(" in branch or "awaitObservation" in actual[0]:
  raise RuntimeError("incomplete terminal production extraction changed")
 call_after=text.index("long nativeDispatchStarted=",branch_end)
 if text.index("frame.nativeDomain.requireCurrent(action);",text.index("if(action==null)"))>branch_start or branch_start>=call_after:
  raise RuntimeError("new branch must follow parsed/current domains and precede ordinary attempt/perform")
 text_click=q.java_block(raw,"void requireTextOnlyClick(ActionDecision action)")
 service=out/"ports/org/trillionnium/hepta/local/HeptaAccessibilityService.java"
 a=service.read_text()
 if not a.endswith("}\n") or "private TaskAuthorization.Gate taskAuthorization;" in a:raise RuntimeError("nonunique service host port")
 service_sigs=["private synchronized boolean ownsAuthorization(","void requireTaskAuthorization(","synchronized NotesTaskPhaseGuard notesTaskPhaseFor(","synchronized CalculatorTaskInputGuard calculatorInputFor("]
 service_methods=[q.java_block(ha.read_bytes(),s) for s in service_sigs]
 ports=r'''
    private TaskAuthorization.Gate taskAuthorization;
    private String hostOwnedTask;
    private NotesTaskPhaseGuard taskNotesPhase;
    private CalculatorTaskInputGuard taskCalculatorInput;
    void fixtureBind(String task,TaskAuthorization.Gate auth,NotesTaskPhaseGuard notes,CalculatorTaskInputGuard calculator){
        hostOwnedTask=task;taskAuthorization=auth;taskNotesPhase=notes;taskCalculatorInput=calculator;
    }
    private boolean owns(String task){return hostOwnedTask!=null&&hostOwnedTask.equals(task);}
    JSONObject qualificationScopeEvidence(String task){
        TaskAuthorization.require(owns(task),"explicit host scope lease unavailable");
        return new JSONObject().put("schema","hepta.host-bound-scope-port.v1").put("task_id",task)
                .put("android_scope_proof",false);
    }
'''
 service.write_text(a[:-2]+"\n"+ports+"\n"+"\n".join(service_methods)+"\n}\n")
 # PromptFrame is a field-only host carrier. All permission/domain objects and
 # its one invoked text policy method are actual classes; no accepted authority stub.
 carrier=r'''
package org.trillionnium.hepta.local;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import android.os.SystemClock;
import org.json.*;
final class ControllerIncompleteTerminalFixture {
    final HeptaAccessibilityService service;
    NativeAppSession activeNativeTask;Object activeWebTask;
    String currentTaskId;
    final AtomicBoolean cancelled=new AtomicBoolean(false);
    PromptFrame frame;
    ControllerIncompleteTerminalFixture(HeptaAccessibilityService s,NativeAppSession nativeTask){
        service=s;activeNativeTask=nativeTask;currentTaskId=nativeTask.taskId;
    }
    private static final class PromptFrame {
        final Set<String> appPackages=Collections.emptySet(),clickNodeIds=Collections.emptySet();
        final ObservedTargetLabels targets;
        final DecisionGrammar grammar;
        final NotesTaskPhaseGuard.Domain phaseDomain;
        final CalculatorTaskInputGuard.Domain calculatorDomain;
        final NativeAppDomain nativeDomain;
        PromptFrame(DecisionGrammar g,NotesTaskPhaseGuard.Domain n,CalculatorTaskInputGuard.Domain c,NativeAppDomain d){
            grammar=g;targets=g.targets;phaseDomain=n;calculatorDomain=c;nativeDomain=d;
        }
TEXTCLICK
    }
    void configure(DecisionGrammar grammar,NotesTaskPhaseGuard.Domain notes,CalculatorTaskInputGuard.Domain calculator,NativeAppDomain domain){
        frame=new PromptFrame(grammar,notes,calculator,domain);
    }
    static final class Route {
        final String finalStatus,summary;final boolean originalPath;
        Route(String status,String text,boolean original){finalStatus=status;summary=text;originalPath=original;}
    }
    Route route(String taskId,File evidence,int steps,PhoneObservation before,ActionDecision action,
            String decisionRunId,TaskAuthorization.Gate authorization,long deadline)throws Exception{
        String finalStatus="unchanged",summary="unchanged";boolean originalPath=false;
        while(true){
BRANCH
            originalPath=true;break;
        }
        return new Route(finalStatus,summary,originalPath);
    }
ACTUAL
}
'''
 carrier=carrier.replace("TEXTCLICK",text_click).replace("BRANCH",branch).replace("ACTUAL","\n".join(actual))
 generated=out/"ports/org/trillionnium/hepta/local/ControllerIncompleteTerminalFixture.java";generated.write_text(carrier);paths.append(generated)
 paths=list(dict.fromkeys(p.resolve() for p in paths))
 production=[Path(x["path"]) for x in proof["production_inputs"]]
 production.extend([ltc,ha,source/"tests/native-incomplete-termination/run_host.py",host,fixture])
 production.extend(p for p in paths if source in p.parents)
 production=list(dict.fromkeys(p.resolve() for p in production))
 proof.update({"actual_controller_methods":[dict(signature=s,sha256=sha(v.encode())) for s,v in zip(sigs,actual)],
               "actual_service_methods":[dict(signature=s,sha256=sha(v.encode())) for s,v in zip(service_sigs,service_methods)],
               "actual_main_early_branch_sha256":sha(branch.encode()),"text_only_click_actual_sha256":sha(text_click.encode()),
               "compile_inputs":[ref(p) for p in paths],
               "inputs":[ref(p) for p in production],
               "synthetic_ports":["Android clock/socket/private-file permission operations and installed checker",
                                  "Service owned task lease and read-only qualification evidence; actual Gate identity checks are verbatim",
                                  "PromptFrame field carrier; actual parser/grammar/phase/native permission classes",
                                  "Original-path sentinel after actual early branch; original success/finally tested by retained source identity, not simulated success"],
               "no_android_no_model_no_business_success":True})
 return paths,production,proof
def main():
 p=argparse.ArgumentParser()
 for x in ("source","output","java-home","json-jar"):p.add_argument("--"+x,type=Path,required=True)
 a=p.parse_args();source,out,jdk,jar=[p.resolve() for p in (a.source,a.output,a.java_home,a.json_jar)]
 if out.exists()or source in out.parents:raise RuntimeError("fresh separate output required")
 out.mkdir(parents=True,mode=0o700)
 before=tree(source);tools=[jdk/"bin/javac",jdk/"bin/java",jdk/"lib/modules",jar,Path(sys.executable).resolve()]
 tb=[ref(p) for p in tools];inputs=[];ib=[]
 report={"schema":"hepta.native-incomplete-termination-host.v1","source":str(source),"all_pass":False,
         "phone_operations":0,"model_executed":False,"android_execution":False,"business_verified":False,
         "source_before":put(out/"SOURCE-BEFORE.json",before),"tools_before":tb,"stages":[],
         "scope":"Actual added LTC helper+main early branch, actual Session/Phone/typed receipt/grammar/phase gates; explicit host lifecycle ports. No UI effect, model inference, real APK/runtime cleanup or full controller run is simulated."}
 try:
  if sha(jar.read_bytes())!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":raise RuntimeError("JSON jar differs")
  paths,inputs,provenance=prepare(source,out/"closure");ib=[ref(p) for p in inputs];report["source_inputs_before"]=ib
  report["extraction"]=put(out/"EXTRACTION.json",provenance)
  classes=out/"classes";classes.mkdir()
  env=dict(os.environ);env["PATH"]=str(jdk/"bin")+":/usr/bin:/bin";env["PYTHONDONTWRITEBYTECODE"]="1"
  for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
  commands=[("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-cp",jar,"-d",classes,*paths]),
            ("targeted",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeIncompleteTerminationHostTest",out/"CASES.json",out/"work"])]
  for name,cmd in commands:
   cmd=list(map(str,cmd));t=time.monotonic();r=subprocess.run(cmd,cwd=out,env=env,capture_output=True,timeout=120)
   (out/(name+".stdout")).write_bytes(r.stdout);(out/(name+".stderr")).write_bytes(r.stderr)
   report["stages"].append(dict(name=name,argv=cmd,cwd=str(out),exit_code=r.returncode,elapsed_seconds=time.monotonic()-t,
                               stdout=ref(out/(name+".stdout")),stderr=ref(out/(name+".stderr"))))
   if r.returncode:raise RuntimeError("stage failed: "+name)
  cases=json.loads((out/"CASES.json").read_bytes())
  if not(cases["all_pass"]and cases["cases"]==len(EXPECTED_CASES)and cases["case_names"]==EXPECTED_CASES):raise RuntimeError("actual case contract differs")
  report["all_pass"]=True
 except Exception as e:report["error"]=type(e).__name__+": "+str(e)
 finally:
  if(out/"CASES.json").is_file():
   report["cases"]=json.loads((out/"CASES.json").read_bytes());report["cases_file"]=ref(out/"CASES.json")
  report["source_inputs_after"]=[ref(p) for p in inputs];report["source_inputs_unchanged"]=report["source_inputs_after"]==ib
  after=tree(source);report["source_after"]=put(out/"SOURCE-AFTER.json",after);report["source_unchanged"]=before==after
  report["tools_after"]=[ref(p)for p in tools];report["tools_unchanged"]=report["tools_after"]==tb
  report["all_pass"]=bool(report["all_pass"]and report["source_unchanged"]and report["tools_unchanged"]and report["source_inputs_unchanged"])
  put(out/"RESULT.json",report)
 print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"cases":report.get("cases",{}).get("cases"),
                   "assertions":report.get("cases",{}).get("assertions"),"result":str(out/"RESULT.json")}))
 return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
