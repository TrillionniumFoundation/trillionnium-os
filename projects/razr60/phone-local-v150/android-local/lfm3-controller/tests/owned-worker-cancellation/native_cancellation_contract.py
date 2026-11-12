#!/usr/bin/env python3
"""Real generated worker/control-pipe tests with an explicit fake SDK only.
No model, Hexagon library, Android device, healthy DSP cancellation or business proof.
"""
import argparse, errno, hashlib, importlib.util, json, os, re, signal, subprocess, sys, time
from pathlib import Path

G,T,R="1"*32,"2"*32,"a"*32
ORIGINAL_TEST_SHA="9f2ba229165bfb3d8984c76de3c8ae2497adf328ce52ab49c28a3a14004b3491"
MODEL=b"host-only fake model bytes\n"
FAKE_GENERATE=r'''
static long long hepta_test_clock_ns(void){
    struct timespec ts;assert(clock_gettime(CLOCK_MONOTONIC,&ts)==0);
    return (long long)ts.tv_sec*1000000000LL+ts.tv_nsec;
}
static void hepta_test_sleep_ns(long long duration){
    struct timespec left={.tv_sec=(time_t)(duration/1000000000LL),.tv_nsec=(long)(duration%1000000000LL)};
    while(nanosleep(&left,&left)<0)assert(errno==EINTR);
}
int32_t geniex_llm_generate(geniex_LLM *handle,const geniex_LlmGenerateInput *in,geniex_LlmGenerateOutput *out){
    assert(handle==(geniex_LLM *)&fake_handle&&!dirty&&in->input_ids&&in->input_ids_count>0&&!in->prompt_utf8);
    assert(in->config&&in->config->sampler_config&&in->config->sampler_config->grammar_string);
    const char *entry=getenv("HEPTA_CANCEL_TEST_ENTER"),*release=getenv("HEPTA_CANCEL_TEST_RELEASE"),*delay=getenv("HEPTA_CANCEL_TEST_DELAY_MS");
    assert(entry&&release&&delay);long pause_ms=strtol(delay,NULL,10);assert(pause_ms==0||pause_ms==4300);
    struct sigaction pipe_action;assert(sigaction(SIGPIPE,NULL,&pipe_action)==0);
    fprintf(stderr,"HOST_ACTUAL_SIGPIPE_DISPOSITION %s\n",pipe_action.sa_handler==SIG_IGN?"ignore":pipe_action.sa_handler==SIG_DFL?"default":"handler");
    dirty=1;calls_generate++;
    int marker=open(entry,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);assert(marker>=0);
    static const char entered[]="generate_entered\n";
    assert(write(marker,entered,sizeof(entered)-1)==(ssize_t)(sizeof(entered)-1)&&fsync(marker)==0&&close(marker)==0);
    /* Java releases this independent file only after its real pipe-close call returned. */
    long long limit=hepta_test_clock_ns()+15000000000LL;
    while(access(release,F_OK)!=0){assert(errno==ENOENT&&hepta_test_clock_ns()<limit);hepta_test_sleep_ns(5000000LL);}
    int released=open(release,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);assert(released>=0);
    char gate[64]={0};ssize_t got=read(released,gate,sizeof(gate)-1);assert(got>0&&close(released)==0);
    assert(!strcmp(gate,"released_after_destroy\n")||!strcmp(gate,"released_after_pipe_close\n"));
    if(pause_ms)hepta_test_sleep_ns(pause_ms*1000000LL);
    bool accepted=in->on_token("x",in->user_data);
    out->full_text=strdup("x");out->profile_data.prompt_tokens=in->input_ids_count;
    out->profile_data.generated_tokens=accepted?1:0;out->profile_data.stop_reason=accepted?"eos":"callback_cancelled";
    return 0;
}
'''

def need(ok,message):
    if not ok:raise AssertionError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode()
def put(path,value):
    raw=encoded(value)
    with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
def row(path):
    raw=path.read_bytes();return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def run(logroot,name,argv,timeout):
    stdout=logroot/(name+".stdout");stderr=logroot/(name+".stderr");start=time.monotonic()
    with stdout.open("xb") as out,stderr.open("xb") as err:
        p=subprocess.Popen([str(x) for x in argv],stdout=out,stderr=err,start_new_session=True)
        try:code=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=10)
            raise AssertionError(name+" exceeded its actual process-group deadline")
    record={"name":name,"argv":[str(x) for x in argv],"exit_code":code,"elapsed_seconds":time.monotonic()-start,"stdout":row(stdout),"stderr":row(stderr)}
    need(code==0,name+" failed; original streams retained")
    return record

def native_build(base,out,cc,label):
    need(not out.exists(),"new generated native directory required");out.mkdir()
    sys.path.insert(0,str(base/"native"))
    for name in ("prompt_evidence_adapter","warm_runtime_adapter"):sys.modules.pop(name,None)
    generator=load_module("generator_"+label,base/"native/generate_adapter.py")
    generated=generator.generate(base,out)
    test_path=base/"native/tests/test_warm_runtime.py";test_bytes=test_path.read_bytes()
    need(sha(test_bytes)==ORIGINAL_TEST_SHA,"unchanged original fake-SDK harness required")
    original=load_module("warm_fixture_"+label,test_path)
    harness=original.HARNESS
    first=harness.index("int32_t geniex_llm_generate(");last=harness.index("int32_t geniex_vlm_create(",first)
    code=harness[:first]+FAKE_GENERATE+harness[last:]
    code=code.replace("TEST_MODEL_SHA",sha(MODEL)).replace("TEST_MODEL_BYTES",str(len(MODEL)))
    test=out/"cancel-fixture.c";test.write_text(code)
    binary=out/"cancel-fixture"
    record=run(out,"cc",[cc,"-std=c11","-Wall","-Wextra","-Werror","-O1","-I"+str(out),"-I"+str(base/"native"),
        "-I"+str(base/"native/vendor"),"-I"+str(base/"native/vendor/llama"),test,"-o",binary],60)
    return binary,{"generator":generated,"compile":record,"harness_original_sha256":ORIGINAL_TEST_SHA,
        "test_fixture":row(test),"binary":row(binary),"generated_worker":row(out/"worker-appuid.c"),
        "generated_diff":row(out/"worker-adapter.diff"),"fake_sdk":True}

def native_case(root,mode,binary,java,classes):
    root.mkdir(mode=0o700);(root/"runs").mkdir(mode=0o700);(root/"runs"/G).mkdir(mode=0o700);(root/"runs"/R).mkdir(mode=0o700)
    model=root/"fixture.gguf";model.write_bytes(MODEL);model.chmod(0o600)
    req=root/"runs"/R
    for name,content in (("prompt.txt","first full prompt"),("system.txt","host-test system"),("grammar.gbnf",'root ::= "x"\n')):
        p=req/name;p.write_text(content);p.chmod(0o600)
    marker=root/"entered";release=root/"release";stderr=root/"native.stderr"
    native=[binary,"--request-id",R,"--mode","llm","--runtime","llama_cpp","--compute","npu","--model",model,
        "--prompt-file",req/"prompt.txt","--system-file",req/"system.txt","--grammar-file",req/"grammar.gbnf",
        "--result-file",req/"native-result.json","--text-file",req/"raw-text.txt","--ctx-size","4096",
        "--max-tokens","32","--threads","2","--timeout-ms","30000","--log-level","debug",
        "--warm-generation",G,"--warm-task-id",T,"--warm-session-dir",root/"runs"/G]
    command=[java,"-cp",classes,"org.trillionnium.hepta.local.NativeCancellationPipeHostTest",mode,marker,release,stderr,*native]
    record=run(root,"java",command,40)
    text=(root/"java.stdout").read_text();match=re.search(r"^NATIVE_PIPE_RESULT (.+)$",text,re.M)
    need(match is not None,"actual native Java child result absent")
    raw={k:v for k,v in (x.split("=",1) for x in match.group(1).split(" "))}
    need(raw["mode"]==mode and raw["observed"]=="true" and raw["force"]=="false" and raw["force_calls"]=="0","actual process observation shape")
    exit_code=int(raw["exit"]);pid=int(raw["worker_pid"]);need(pid>0,"actual native PID required")
    terminal_path=root/"runs"/G/"native-session-result.json"
    terminal=json.loads(terminal_path.read_bytes()) if terminal_path.is_file() else None
    stderr_raw=stderr.read_bytes();stderr_text=stderr_raw.decode("utf-8")
    proof={"mode":mode,"command":record,"observed_exit_code":exit_code,"actual_worker_pid":pid,
        "process_destroy_calls":int(raw["term_calls"]),"process_destroy_forcibly_calls":int(raw["force_calls"]),
        "native_stderr":row(stderr),"native_terminal":row(terminal_path) if terminal else None,
        "native_terminal_value":terminal,"fake_sdk":True,"actual_proprietary_sdk_executed":False,"phone_tested":False}
    if mode=="baseline_destroy":
        need(exit_code in (141,74),"old actual process keeps original broken-pipe exit")
        if exit_code==141:need(terminal is None,"SIGPIPE baseline unexpectedly claimed terminal publication")
        else:need(terminal is not None and terminal["last_request_status"]==74,"original EPIPE result remains74")
        proof["original_broken_pipe_failure_preserved"]=True
        return proof
    need(terminal is not None,"actual generated native terminal missing")
    need(terminal["schema"]=="hepta.geniex-task-session.result.v1" and terminal["worker_generation"]==G
        and terminal["task_id"]==T and terminal["pid"]==pid and terminal["process_exit_observed"] is False
        and terminal["close_requested"] is False,"actual terminal is not fabricated process exit or CLOSE")
    need(terminal["last_request_status"]==exit_code,"actual native/request supervisor exit binding")
    if mode in ("idle_cancel","partial_cancel"):
        need(exit_code==143 and proof["process_destroy_calls"]==1 and terminal["signal_observed"]==15
            and terminal["requests_received"]==0 and terminal["requests_completed"]==0 and terminal["model_create_count"]==0
            and terminal["sdk_destroy_attempted"] is False and terminal["sdk_deinit_attempted"] is False
            and terminal["control_done_attempts"]==0,"idle/partial cancellation no invented SDK work")
        proof["sdk_cleanup_not_applicable_no_sdk_created"]=True
        return proof
    need(terminal["requests_received"]==1 and terminal["model_hash_count"]==1 and terminal["model_create_count"]==1
        and terminal["sdk_init_count"]==1 and terminal["model_reset_count"]==1
        and terminal["model_metadata_unchanged_before_close"] is True and terminal["sdk_destroy_attempted"] is True
        and terminal["sdk_deinit_attempted"] is True and terminal["sdk_destroy_rc"]==0 and terminal["sdk_deinit_rc"]==0,
        "actual generated terminal must record actual fake-SDK cleanup calls")
    need("init=1 create=1 reset=1 generate=1 destroy=1 deinit=1 vocab=1 vocab_free=1" in stderr_text,
        "fake-SDK independent call counters differ")
    need(terminal["control_done_attempts"]==1,"exact single actual DONE attempt")
    delivered=terminal["control_done_delivered"]==1 and terminal["control_channel_write_failed"] is False and terminal["control_channel_last_errno"]==0
    broken=terminal["control_done_delivered"]==0 and terminal["control_channel_write_failed"] is True and terminal["control_channel_last_errno"]==errno.EPIPE
    if mode=="shared_cancel":
        # A concurrent WarmProcessSession reader can consume the final DONE even
        # after destroy returns. Do not rewrite that observed delivery as EPIPE.
        need(delivered or broken,"exact observed shared control transport")
    else:
        need(broken,"no-reader raw path must actually observe EPIPE before terminal cleanup")
    proof["actual_control_transport"]="done_delivered" if delivered else "observed_epipe"
    request_path=req/"native-result.json";request=json.loads(request_path.read_bytes())
    need(request["worker_generation"]==G and request["task_id"]==T and request["request_id"]==R
        and request["process_exit_observed"] is False,"actual native request identity")
    proof["native_request"]=row(request_path);proof["native_request_value"]=request
    if mode in ("shared_cancel","raw_cancel"):
        need(exit_code==143 and proof["process_destroy_calls"]==1 and terminal["signal_observed"]==15
            and terminal["requests_completed"]==0 and terminal["last_request_return_status"]==143
            and request["generation_complete"] is False,"cancelled result remains cancelled143 with cleanup")
        proof["fake_sdk_cancelled_143_and_cleanup_observed"]=True
    else:
        need(mode=="normal_broken" and exit_code==74 and proof["process_destroy_calls"]==0 and terminal["signal_observed"]==0
            and terminal["requests_completed"]==1 and terminal["last_request_return_status"]==0
            and request["generation_complete"] is True,"normal broken control remains74, not invented cancellation")
        proof["broken_channel_without_cancel_not_promoted"]=True
    return proof

def method_block(source,name):
    start=source.index("    private static "+("boolean " if name=="cancelledSdkCleanupBound" else "long ")+name+"(")
    opening=source.index("{",start);depth=1;state="code";escape=False;i=opening+1
    while i<len(source) and depth:
        c=source[i];n=source[i+1] if i+1<len(source) else ""
        if state in ("string","char"):
            if escape:escape=False
            elif c=="\\":escape=True
            elif c==('"' if state=="string" else "'"):state="code"
        elif state=="line":
            if c=="\n":state="code"
        elif state=="block":
            if c=="*" and n=="/":state="code";i+=1
        elif c=='"':state="string"
        elif c=="'":state="char"
        elif c=="/" and n=="/":state="line";i+=1
        elif c=="/" and n=="*":state="block";i+=1
        elif c=="{":depth+=1
        elif c=="}":depth-=1
        i+=1
    need(depth==0,"actual source method closing brace missing")
    return source[start:i]

def java_value(value):
    if value is True:return "Boolean.TRUE"
    if value is False:return "Boolean.FALSE"
    if value is None:return "null"
    if isinstance(value,int):return ("Integer.valueOf(%d)" if -(1<<31)<=value<(1<<31) else "Long.valueOf(%dL)")%value
    need(isinstance(value,str),"flat actual native terminal JSON expected")
    return json.dumps(value,ensure_ascii=True)

def receipt_projection(base,out,java,javac,actual):
    out.mkdir()
    original=(base/"src/org/trillionnium/hepta/local/LocalModelEngine.java").read_text()
    a=method_block(original,"cancelledSdkCleanupBound");b=method_block(original,"exactReceiptInteger")
    terminal=actual["native_terminal_value"];pid=actual["actual_worker_pid"]
    rows="\n".join("        n.put("+json.dumps(k)+","+java_value(v)+");" for k,v in terminal.items())
    fake=r'''package org.json;
import java.util.*;
/** Minimal test-only container: no JSON parser, coercion, Android or SDK implementation. */
public final class JSONObject {
 private final Map<String,Object> values=new LinkedHashMap<String,Object>();
 public JSONObject put(String k,Object v){values.put(k,v);return this;}
 public Object opt(String k){return values.get(k);}
 public String optString(String k){Object v=values.get(k);return v instanceof String?(String)v:"";}
 public void remove(String k){values.remove(k);}
}
'''
    code='''package org.trillionnium.hepta.local;
import org.json.JSONObject;
public final class CancellationReceiptProjectionHostTest {
    static int checks;
    static final long PID='''+str(pid)+'''L;
    static void check(boolean ok,String m){checks++;if(!ok)throw new AssertionError(m);}
'''+a+"\n"+b+'''
    static JSONObject actual(){JSONObject n=new JSONObject();
'''+rows+'''
        return n;
    }
    static boolean verify(JSONObject n,boolean cancel,boolean observed,Integer exit,boolean force,int sent,int accepted,int error){
        return cancelledSdkCleanupBound(n,"'''+G+'","'+T+'''",PID,sent,accepted,cancel,observed,exit,force,error);
    }
    static boolean exact(JSONObject n){return verify(n,true,true,143,false,1,0,'''+str(errno.EPIPE)+''');}
    public static void main(String[] args){
        check(exact(actual()),"actual generated native cancelled terminal accepted by exact production method");
        String[] required={'''+",".join(json.dumps(k) for k in terminal if k not in ())+'''};
        for(String key:required){
            JSONObject n=actual();n.remove(key);
            // Every native field in this bounded receipt is consumed by the production predicate.
            check(!exact(n),"missing actual required field accepted: "+key);
        }
        String[] integers={"pid","requests_received","requests_completed","model_hash_count","model_create_count","sdk_init_count","model_reset_count","signal_observed","last_request_status","sdk_destroy_rc","sdk_deinit_rc","control_done_attempts","control_done_delivered","control_channel_last_errno","last_request_return_status"};
        for(String key:integers){
            Object value=actual().opt(key);JSONObject n=actual();n.put(key,String.valueOf(value));check(!exact(n),"string integer accepted "+key);
            n=actual();n.put(key,Double.valueOf(((Number)value).doubleValue()));check(!exact(n),"float integer accepted "+key);
        }
        String[] booleans={"model_metadata_unchanged_before_close","sdk_destroy_attempted","sdk_deinit_attempted","process_exit_observed","close_requested","control_channel_write_failed"};
        for(String key:booleans){JSONObject n=actual();n.put(key,String.valueOf(n.opt(key)));check(!exact(n),"string boolean accepted "+key);}
        for(int exit:new int[]{0,74,134,137})check(!verify(actual(),true,true,exit,false,1,0,'''+str(errno.EPIPE)+'''),"unrelated exit promoted "+exit);
        check(!verify(actual(),false,true,143,false,1,0,'''+str(errno.EPIPE)+'''),"missing actual cancellation promoted");
        check(!verify(actual(),true,false,143,false,1,0,'''+str(errno.EPIPE)+'''),"unobserved exit promoted");
        check(!verify(actual(),true,true,null,false,1,0,'''+str(errno.EPIPE)+'''),"missing exit promoted");
        check(!verify(actual(),true,true,143,true,1,0,'''+str(errno.EPIPE)+'''),"forced process promoted");
        check(!verify(actual(),true,true,143,false,0,0,'''+str(errno.EPIPE)+'''),"zero RUN promoted");
        check(!verify(actual(),true,true,143,false,1,1,'''+str(errno.EPIPE)+'''),"unaccepted final RUN promoted");
        check(!verify(actual(),true,true,143,false,1,0,0),"invalid platform EPIPE promoted");
        if(actual().opt("control_channel_write_failed")==Boolean.TRUE)
            check(!verify(actual(),true,true,143,false,1,0,'''+str(errno.EPIPE+1)+'''),"wrong platform EPIPE promoted");
        JSONObject n=actual();n.put("task_id","33333333333333333333333333333333");check(!exact(n),"foreign task");
        n=actual();n.put("worker_generation","33333333333333333333333333333333");check(!exact(n),"foreign generation");
        n=actual();n.put("pid",PID+1);check(!exact(n),"foreign actual process");
        n=actual();n.put("sdk_destroy_rc",1);check(!exact(n),"failed destroy");
        n=actual();n.put("sdk_deinit_rc",1);check(!exact(n),"failed deinit");
        n=actual();n.put("close_requested",Boolean.TRUE);check(!exact(n),"fabricated CLOSE");
        n=actual();n.put("last_request_return_status",70);check(!exact(n),"unrelated request failure masked");
        System.out.println("CancellationReceiptProjection PASS checks="+checks+" actual_generated_receipt=1 production_methods_verbatim=true proprietary_sdk_executed=false");
    }
}
'''
    # Native terminal has two identity booleans/strings plus exact counters; preserve each actual field.
    need(set(terminal)=={"schema","process_exit_observed","worker_generation","task_id","pid","requests_received","requests_completed",
        "model_hash_count","sdk_init_count","model_create_count","model_reset_count","model_metadata_unchanged_before_close",
        "close_requested","signal_observed","last_request_status","sdk_destroy_attempted","sdk_destroy_rc","sdk_deinit_attempted",
        "sdk_deinit_rc","control_done_attempts","control_done_delivered","control_channel_write_failed","control_channel_last_errno",
        "last_request_return_status"},"native terminal fixture fields changed")
    (out/"JSONObject.java").write_text(fake);(out/"CancellationReceiptProjectionHostTest.java").write_text(code)
    (out/"classes").mkdir()
    compiled=run(out,"javac",[javac,"--release","8","-d",out/"classes",out/"JSONObject.java",out/"CancellationReceiptProjectionHostTest.java"],45)
    tested=run(out,"java",[java,"-cp",out/"classes","org.trillionnium.hepta.local.CancellationReceiptProjectionHostTest"],15)
    return {"production_source":row(base/"src/org/trillionnium/hepta/local/LocalModelEngine.java"),
        "extracted_methods_sha256":sha((a+"\n"+b).encode()),"actual_native_receipt":actual["native_terminal"],
        "fixture":row(out/"CancellationReceiptProjectionHostTest.java"),"test_only_json_container":row(out/"JSONObject.java"),
        "compile":compiled,"test":tested,"not_a_full_android_compile":True}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--source",type=Path,required=True);ap.add_argument("--baseline",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True);ap.add_argument("--java",type=Path,required=True);ap.add_argument("--javac",type=Path,required=True)
    ap.add_argument("--classes",type=Path,required=True);ap.add_argument("--cc",type=Path,required=True);args=ap.parse_args()
    need(not args.out.exists(),"new contract output only");args.out.mkdir()
    result={"schema":"hepta.generated-worker-cancellation-host.v1","all_pass":False,"fake_sdk_only":True,"phone_tested":False,"actual_proprietary_sdk_executed":False}
    try:
        baseline,before=native_build(args.baseline,args.out/"baseline-generated",args.cc,"baseline")
        candidate,after=native_build(args.source,args.out/"candidate-generated",args.cc,"candidate")
        result["baseline_build"]=before;result["candidate_build"]=after;result["cases"]=[]
        for mode in ("baseline_destroy","shared_cancel","raw_cancel","normal_broken","idle_cancel","partial_cancel"):
            result["cases"].append(native_case(args.out/mode,mode,baseline if mode=="baseline_destroy" else candidate,args.java,args.classes))
        result["exact_production_receipt_predicate"]={}
        for mode in ("raw_cancel","shared_cancel"):
            actual=next(x for x in result["cases"] if x["mode"]==mode)
            result["exact_production_receipt_predicate"][mode]=receipt_projection(args.source,args.out/("receipt-predicate-"+mode),args.java,args.javac,actual)
        result.update(all_pass=True,exit_code=0)
    except Exception as error:
        result.update(exit_code=1,error=type(error).__name__+": "+str(error));raise
    finally:
        receipt=put(args.out/"RESULT.json",result)
        print(json.dumps({"result":receipt,"all_pass":result["all_pass"],"error":result.get("error")}),flush=True)
if __name__=="__main__":main()
