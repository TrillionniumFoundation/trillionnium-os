#!/usr/bin/env python3
"""Actual flight provider/progression classes plus exact production dispatch-method projection.
Synthetic model/outcome inputs do not establish Binder, A11y delivery or business results."""
import argparse,hashlib,json,os,pathlib,signal,stat,subprocess,time
def need(yes,message):
    if not yes:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def read(path):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path,*path.parents)),"unlinked absolute input")
    a=path.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<a.st_size<=2<<20,"bounded ordinary input")
    raw=path.read_bytes();b=path.stat()
    key=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mtime_ns,q.st_ctime_ns)
    need(key(a)==key(b) and len(raw)==a.st_size,"input changed while read");return raw,key(a)
def put(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    need(path.read_bytes()==raw,"new output bytes differ")
def java_block(raw,signature):
    text=raw.decode("utf-8");need(text.count(signature)==1,"one exact production signature: "+signature)
    start=text.index(signature);opening=text.index("{",start);depth=0;state="code";i=opening
    while i<len(text):
        c=text[i];n=text[i+1] if i+1<len(text) else ""
        if state=="line":
            if c=="\n":state="code"
        elif state=="block":
            if c=="*" and n=="/":state="code";i+=1
        elif state in ('"',"'"):
            if c=="\\":i+=1
            elif c==state:state="code"
        elif c=="/" and n=="/":state="line";i+=1
        elif c=="/" and n=="*":state="block";i+=1
        elif c in ('"',"'"):state=c
        elif c=="{":depth+=1
        elif c=="}":
            depth-=1
            if depth==0:return text[start:i+1]
        i+=1
    raise RuntimeError("unfinished production Java block")
PURE_PATHS=["src/org/trillionnium/hepta/background/FixedIntentTarget.java","src/org/trillionnium/hepta/background/FixedIntentTools.java","src/org/trillionnium/hepta/local/ActionDecision.java","src/org/trillionnium/hepta/local/AppCatalogueRanker.java","src/org/trillionnium/hepta/local/CsairCityPicker.java","src/org/trillionnium/hepta/local/CsairFlightForm.java","src/org/trillionnium/hepta/local/DecisionGrammar.java","src/org/trillionnium/hepta/local/ImeVisibility.java","src/org/trillionnium/hepta/local/MiPublicProductPage.java","src/org/trillionnium/hepta/local/NotesCompletionEvidence.java","src/org/trillionnium/hepta/local/NotesCreateWorkflow.java","src/org/trillionnium/hepta/local/NotesOwnerIntent.java","src/org/trillionnium/hepta/local/ObservationState.java","src/org/trillionnium/hepta/local/ObservedAppLabels.java","src/org/trillionnium/hepta/local/ObservedChildText.java","src/org/trillionnium/hepta/local/ObservedImeEnter.java","src/org/trillionnium/hepta/local/ObservedScrollActions.java","src/org/trillionnium/hepta/local/ObservedTargetLabels.java","src/org/trillionnium/hepta/local/ObservedWindowMetadata.java","src/org/trillionnium/hepta/local/PhoneObservation.java","src/org/trillionnium/hepta/local/TaskAuthorization.java","src/org/trillionnium/hepta/local/TaskCompletionGate.java","src/org/trillionnium/hepta/local/WebEvidenceJson.java","src/org/trillionnium/hepta/local/WebEvidenceReceipt.java","src/org/trillionnium/hepta/local/WebFlightDomain.java","src/org/trillionnium/hepta/local/WebNativeGeometry.java","src/org/trillionnium/hepta/local/WebShoppingDomain.java","src/org/trillionnium/hepta/local/WebTaskDomain.java","src/org/trillionnium/hepta/local/web/WebFlightGoal.java","src/org/trillionnium/hepta/local/web/WebShoppingGoal.java","src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java","src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java","src/org/trillionnium/hepta/webprotocol/WebRecoveryPolicy.java","src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java","src/org/trillionnium/hepta/webprotocol/WebStorageEvidence.java","src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java","tests/notes-owner-intent/NotesOwnerIntentHostTest.java","tests/qualification-scope/fixtures/android/graphics/Rect.java","tests/web-flight/CsairCityPickerHostTest.java","tests/web-flight/WebFlightEvidenceHostTest.java","tests/web-flight/WebNaturalOwnerHostTest.java","tests/web-flight/WebUnstartedRetirementHostTest.java","tests/web-flight/WebTaskCompositionHostTest.java","src/org/trillionnium/hepta/local/CsairCalendar.java","tests/web-flight/CsairCalendarHostTest.java","tests/web-flight/WebCalendarNativeHostTest.java","src/org/trillionnium/hepta/local/WebFlightProgress.java","tests/web-flight/WebFlightQueryHostTest.java"]
PROJECTION="package org.trillionnium.hepta.local;\nimport org.json.JSONObject;\n/** Unit projection: the exact production Session methods are inserted below.\n * Only the Android clock/outcome carrier and file writer are host boundaries. */\nfinal class WebFlightDispatchProjection {\n    private WebTaskDomain domain,dispatchSource;\n    private String dispatchSourceRun,dispatchSourceAction,dispatchCheckedRun,dispatchCheckedAction;\n    private long dispatchCheckedAt;\n    private boolean retired,failRecord;\n    private WebFlightProgress flightProgress;\n    private final java.util.concurrent.atomic.AtomicBoolean nativeQueryEntered=new java.util.concurrent.atomic.AtomicBoolean();\n    private WebShoppingDomain.Navigation shoppingNavigation;\n    private PendingNavigation pendingNavigation;\n    private static final class SystemClock {static long elapsedRealtime(){return 1120;}}\n    private static final class HeptaAccessibilityService {\n        static final class ActionOutcome{\n            final boolean accepted,dispatched,stale;\n            ActionOutcome(boolean a,boolean d,boolean s){accepted=a;dispatched=d;stale=s;}\n        }\n    }\n    private void record(String name,JSONObject evidence)throws Exception{\n        if(failRecord)throw new java.io.IOException(\"synthetic evidence writer failure\");\n        if(name==null||evidence==null)throw new AssertionError(\"record arguments\");\n    }\n    private static void need(boolean yes,String reason){WebEvidenceJson.need(yes,reason);}\n    /* EXACT_METHODS */\n    private interface Work{void run()throws Exception;}\n    private static void rejects(Work body)throws Exception{\n        boolean refused=false;try{body.run();}catch(IllegalArgumentException|IllegalStateException|java.io.IOException expected){refused=true;}\n        if(!refused)throw new AssertionError(\"actual production dispatch method accepted a duplicate or missing source\");\n    }\n    static boolean verify(WebTaskDomain d,WebFlightProgress p,ActionDecision action,String run,int scenario)throws Exception{\n        WebFlightDispatchProjection f=new WebFlightDispatchProjection();\n        f.domain=d;f.dispatchSource=d;f.dispatchSourceRun=run;f.dispatchSourceAction=actionKey(action);\n        f.dispatchCheckedRun=run;f.dispatchCheckedAction=actionKey(action);f.dispatchCheckedAt=1111;\n        f.flightProgress=p.reserveQuery(d.flight,action,run);\n        if(scenario==0){\n            // The service deliberately rechecks authorization twice before its one platform call.\n            f.requireDispatch(action,run);f.requireDispatch(action,run);\n            f.beforeNativeClickInvocation(action,run);\n            rejects(()->f.beforeNativeClickInvocation(action,run));\n        }else if(scenario==1||scenario==2){\n            f.requireDispatch(action,run);f.beforeNativeClickInvocation(action,run);\n            f.modelActionOutcome(action,run,new HeptaAccessibilityService.ActionOutcome(scenario==1,scenario==1,false),1112,1115);\n            rejects(()->f.requireDispatch(action,run));\n            rejects(()->f.beforeNativeClickInvocation(action,run));\n            if(f.dispatchSource!=null||f.dispatchCheckedRun!=null||f.dispatchCheckedAction!=null||f.dispatchCheckedAt!=0)\n                throw new AssertionError(\"original outcome must retire the dispatch capability even when false\");\n        }else if(scenario==3){\n            f.beforeNativeClickInvocation(action,run);f.failRecord=true;\n            rejects(()->f.modelActionOutcome(action,run,new HeptaAccessibilityService.ActionOutcome(true,true,false),1112,1115));\n            rejects(()->f.requireDispatch(action,run));rejects(()->f.beforeNativeClickInvocation(action,run));\n        }else if(scenario==4){\n            f.beforeNativeClickInvocation(action,run);\n            rejects(()->f.modelActionOutcome(action,\"00000000000000000000000000000000\",\n                    new HeptaAccessibilityService.ActionOutcome(true,true,false),1112,1115));\n            rejects(()->f.requireDispatch(action,run));rejects(()->f.beforeNativeClickInvocation(action,run));\n        }else if(scenario==5){\n            f.dispatchSource=null;\n            rejects(()->f.beforeNativeClickInvocation(action,run));\n        }else if(scenario==6){\n            f.dispatchSourceAction=\"click\\nforeign\";\n            rejects(()->f.beforeNativeClickInvocation(action,run));\n            if(f.nativeQueryEntered.get())throw new AssertionError(\"wrong action consumed platform gate\");\n        }else if(scenario==7){\n            f.dispatchCheckedRun=null;f.dispatchCheckedAction=null;f.dispatchCheckedAt=0;\n            rejects(()->f.requireDispatch(action,run));\n        }else throw new AssertionError(\"unknown projection case\");\n        return true;\n    }\n}\n"
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar","calendar-dom","calendar-ax"):
        parser.add_argument("--"+name,type=pathlib.Path,required=True)
    args=parser.parse_args()
    roots=[args.source,args.output,args.java_home,args.json_jar,args.calendar_dom,args.calendar_ax]
    need(all(p.is_absolute() and not any(q.is_symlink() for q in(p,*p.parents)) for p in roots),"ordinary absolute roots")
    need(not args.output.exists(),"new host gate output")
    original={}
    def bound(p):
        raw,stamp=read(p);original[p]=(raw,stamp);return raw
    sources={name:bound(args.source/name) for name in PURE_PATHS}
    session=bound(args.source/"src/org/trillionnium/hepta/local/WebFlightSession.java")
    service=bound(args.source/"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java")
    fixture=bound(args.calendar_dom);xml=bound(args.calendar_ax);jar=bound(args.json_jar)
    need(sha(fixture)=="f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa"
         and sha(xml)=="59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec","actual manual fixture pins")
    need(len(jar)==78332 and sha(jar)=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed","actual host-only JSON")
    signatures=["void requireDispatch(ActionDecision action,String run)",
                "void beforeNativeClickInvocation(ActionDecision action,String run)",
                "private static String actionKey(ActionDecision action)",
                "void modelActionOutcome(ActionDecision action,String run,HeptaAccessibilityService.ActionOutcome outcome,",
                "private static final class PendingNavigation"]
    methods=[java_block(session,sig) for sig in signatures]
    invoke="WebFlightSession web=taskWeb;if(web!=null)web.beforeNativeClickInvocation(action,modelRunId);\n                accepted=node.performAction(AccessibilityNodeInfo.ACTION_CLICK);"
    need(service.decode().count(invoke)==1,"one actual service hook immediately before original semantic ACTION_CLICK")
    projection=PROJECTION.replace("/* EXACT_METHODS */","\n".join(methods)).encode()
    # First filesystem mutation is an exclusive output claim outside the handler.
    args.output.mkdir(mode=0o700)
    result={"schema":"hepta.v54-flight-query-compiled-gate.v1","all_pass":False,"steps":[],
            "phone_actions":0,"actual_model_or_a11y_executed":False,"business_verified":False,"started_epoch":time.time()}
    def command(name,argv,timeout):
        began=time.monotonic()
        p=subprocess.Popen([str(x) for x in argv],cwd=args.source,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"),start_new_session=True)
        forced=False
        try:out,err=p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            forced=True
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            out,err=p.communicate(timeout=10)
        put(args.output/(name+".stdout"),out);put(args.output/(name+".stderr"),err)
        result["steps"].append({"name":name,"argv":[str(x) for x in argv],"exit_code":p.returncode,"forced":forced,
                "seconds":time.monotonic()-began,"stdout_sha256":sha(out),"stderr_sha256":sha(err)})
        need(p.returncode==0 and not forced,"actual command failed: "+name)
    try:
        projection_path=args.output/"generated/org/trillionnium/hepta/local/WebFlightDispatchProjection.java"
        put(projection_path,projection)
        put(args.output/"DISPATCH-PROJECTION.json",enc({"schema":"hepta.exact-java-method-host-projection.v1",
                "session_sha256":sha(session),"service_sha256":sha(service),
                "methods":[{"signature":sig,"sha256":sha(method.encode())} for sig,method in zip(signatures,methods)],
                "generated_java_sha256":sha(projection),"android_clock_and_outcome_carrier_stubbed":True,
                "evidence_writer_stubbed":True,"actual_three_dispatch_methods_unchanged":True,"phone_executed":False}))
        classes=args.output/"classes";classes.mkdir()
        command("javac",[args.java_home/"bin/javac","--release","8","-encoding","UTF-8","-proc:none",
                "-classpath",args.json_jar,"-d",classes,*[args.source/p for p in PURE_PATHS],projection_path],90)
        command("query-chain",[args.java_home/"bin/java","-cp",str(classes)+os.pathsep+str(args.json_jar),
                "org.trillionnium.hepta.local.WebFlightQueryHostTest",args.calendar_dom,args.calendar_ax,args.output/"CASES.json"],60)
        cases=json.loads(read(args.output/"CASES.json")[0])
        need(cases["all_pass"] is True and cases["cases"]==40 and cases["form_and_city_values_synthetic"] is True
                and cases["model_and_action_outcomes_synthetic"] is True and cases["actual_query_executed"] is False
                and cases["actual_results_verified"] is False and cases["phone_actions"]==0,"exact new host cases scope")
        result["cases"]=cases;result["all_pass"]=True
    except Exception as error:
        import traceback
        result["error"]=type(error).__name__+": "+str(error);put(args.output/"ERROR.txt",traceback.format_exc().encode())
    finally:
        result["originals_unchanged"]=all(read(p)==value for p,value in original.items())
        result["all_pass"]=result["all_pass"] and result["originals_unchanged"]
        result["source_inputs"]=[{"path":str(p),"bytes":len(value[0]),"sha256":sha(value[0])} for p,value in original.items()]
        result["projection_sha256"]=sha(projection);result["finished_epoch"]=time.time()
        put(args.output/"RESULT.json",enc(result))
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"cases":result.get("cases",{}).get("cases"),
                "result":str(args.output/"RESULT.json"),"result_sha256":sha(enc(result))},ensure_ascii=False),flush=True)
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
