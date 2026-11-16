#!/usr/bin/env python3
"""Replay exact archived host fake-SDK evidence and execute production failure audit/caller blocks.
No Android private-file IO, proprietary SDK execution, phone action or business result is qualified.
"""
import argparse,gzip,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path

def need(value,message):
    if not value: raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def java_block(text,anchor):
    need(text.count(anchor)==1,"nonunique extraction anchor "+anchor)
    start=text.index(anchor);brace=text.index("{",start);depth=0;quote=None;escape=False;line=False;block=False;i=brace
    while i<len(text):
        c=text[i];n=text[i+1] if i+1<len(text) else ""
        if line:
            if c=="\n":line=False
        elif block:
            if c=="*" and n=="/":block=False;i+=1
        elif quote:
            if escape:escape=False
            elif c=="\\":escape=True
            elif c==quote:quote=None
        elif c=="/" and n=="/":line=True;i+=1
        elif c=="/" and n=="*":block=True;i+=1
        elif c in "\"'":quote=c
        elif c=="{":depth+=1
        elif c=="}":
            depth-=1
            if depth==0:return text[start:i+1]
        i+=1
    raise RuntimeError("unclosed production block")
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar","python"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();need(all(x.is_absolute() for x in vars(a).values()),"absolute paths required")
    a.output.mkdir(exist_ok=False)
    inputs={};result={"schema":"hepta.sdk-exception-failure-audit-gate.v1","all_pass":False,"steps":[],"phone_operations":0,
        "engine_full_android_class_compiled":False,"android_private_file_io_executed":False,"actual_sdk_exception_on_phone":False}
    def take(path):
        need(path.is_file() and not path.is_symlink(),"ordinary source required "+str(path))
        raw=path.read_bytes()
        if path in inputs:need(raw==inputs[path],"input changed")
        inputs[path]=raw;return raw
    def put(path,raw):
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    def run(name,argv):
        argv=list(map(str,argv));started=time.monotonic()
        p=subprocess.run(argv,capture_output=True,timeout=90)
        put(a.output/(name+".stdout"),p.stdout);put(a.output/(name+".stderr"),p.stderr)
        result["steps"].append({"name":name,"argv":argv,"exit_code":p.returncode,"elapsed_seconds":time.monotonic()-started,
                "stdout_sha256":sha(p.stdout),"stderr_sha256":sha(p.stderr)})
        need(p.returncode==0,name+" failed: "+p.stderr.decode(errors="replace"))
    try:
        take(Path(__file__))
        test=a.source/"tests/sdk-exception-failure-audit";fixtures=test/"fixtures"
        provenance=json.loads(take(fixtures/"PROVENANCE.json"))
        need(provenance["original_bytes_unchanged"] is True,"original fixtures required")
        for row in provenance["files"]:
            name=row["name"];need(Path(name).name==name,"fixture basename required")
            raw=take(fixtures/name);need(len(raw)==row["bytes"] and sha(raw)==row["sha256"],"fixture changed "+name)
        legacy=gzip.decompress(take(fixtures/"baseline-LocalModelEngine.java.gz"))
        need(sha(legacy)=="54f53d833234d0ae9d2c24c99c5857a546d1a6b9f5de3d27e69adb48af32bee3","exact c4e5 Engine preimage required")
        package=a.source/"src/org/trillionnium/hepta/local"
        engine=take(package/"LocalModelEngine.java").decode();old=legacy.decode()
        normal_start="            valid=process==null||";normal_end=";\n            cancelledSdkCleanup="
        normal=lambda s:s[s.index(normal_start):s.index(normal_end,s.index(normal_start))+1]
        normal_request_start='            boolean binding = (task==null?'
        normal_request_end='            put(receipt, "native_result_binding_valid", binding);'
        request=lambda s:s[s.index(normal_request_start):s.index(normal_request_end,s.index(normal_request_start))]
        retained={"normal_exit0_predicate":(normal(old),normal(engine)),
            "normal_request0_predicate":(request(old),request(engine)),
            "cancel143_predicate":(java_block(old,"private static boolean cancelledSdkCleanupBound("),java_block(engine,"private static boolean cancelledSdkCleanupBound(")),
            "exact_receipt_integer":(java_block(old,"private static long exactReceiptInteger("),java_block(engine,"private static long exactReceiptInteger("))}
        result["retained_predicates"]={}
        for name,(before,after) in retained.items():
            need(before==after,"retained production predicate changed "+name)
            result["retained_predicates"][name]={"byte_identical":True,"bytes":len(after.encode()),"sha256":sha(after.encode()),
                                                "identity_check_not_product_execution":True}
        handle=java_block(engine,"public static final class RunHandle {")
        first='            boolean callerCancellation=h.callerCancellationRequested();'
        last='            try{\n                ActivityManager.MemoryInfo after=memoryInfo();'
        need(engine.count(first)==1 and engine.count(last)==1,"exact classification block required")
        classification=engine[engine.index(first):engine.index(last,engine.index(first))]
        put_method=java_block(engine,"private static void put(")
        sha_method=java_block(engine,"private static String sha256(")
        raw_hash_lines=[line for line in engine.splitlines() if 'put(receipt, "raw_text_sha256_read",' in line]
        need(len(raw_hash_lines)==1,"one actual failure raw-hash line required")
        raw_hash_line=raw_hash_lines[0]+"\n"
        wrapper='''package org.trillionnium.hepta.local;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.json.JSONObject;
final class RunHandleFixture {
'''+handle+'''
    static RunHandle handle(String id,RunHandle owner){return new RunHandle(id,owner);}
    static void internalCleanup(RunHandle handle){handle.cancelForFailure();}
    static void requestOnly(RunHandle handle){handle.requestCancellationOnly();}
    static boolean caller(RunHandle handle){return handle.callerCancellationRequested();}
    static JSONObject classify(RunHandle h,SdkExceptionFailure failedSdkProof)throws Exception{
        boolean complete=false;String status="cancelled",error="original wrapper failure",raw="";JSONObject receipt=new JSONObject();
'''+classification+raw_hash_line+'''
        receipt.put("status",status).put("error",error).put("inference_completed",complete);return receipt;
    }
'''+put_method+'\n'+sha_method+'\n}\n'
        generated=a.output/"generated/org/trillionnium/hepta/local/RunHandleFixture.java";put(generated,wrapper.encode())
        result["extracted_current_blocks"]={k:{"bytes":len(v.encode()),"sha256":sha(v.encode())} for k,v in {
            "RunHandle":handle,"failure_classification":classification,"failure_raw_hash_line":raw_hash_line,"receipt_put":put_method,"sha256":sha_method}.items()}
        java_names=["SdkExceptionFailure.java","LocalRuntimeConfig.java","ModelProfile.java","ConservativeTokenBudget.java",
                    "OwnedWorkerCancellation.java","TaskCancellationQueue.java"]
        sources=[package/n for n in java_names]+[test/"SdkExceptionFailureHostTest.java"]
        for path in sources:take(path)
        jar=take(a.json_jar);need(sha(jar)=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed","JSON jar pin differs")
        java=a.java_home/"bin/java";javac=a.java_home/"bin/javac";take(java);take(javac)
        classes=a.output/"classes";classes.mkdir()
        run("compile",[javac,"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-cp",a.json_jar,"-d",classes,*sources,generated])
        run("audit-cases",[java,"-cp",str(classes)+os.pathsep+str(a.json_jar),"org.trillionnium.hepta.local.SdkExceptionFailureHostTest",
                           fixtures,a.output/"CASES.json",a.python])
        cases=json.loads((a.output/"CASES.json").read_bytes());need(cases["all_pass"] is True and cases["cases"]==43 and len(cases["case_names"])==43 and len(set(cases["case_names"]))==43,"focused cases missing")
        result["cases"]=cases;result["all_pass"]=True
    except Exception as error:result["error"]=str(error)
    finally:
        result["inputs_unchanged"]=all(p.read_bytes()==v for p,v in inputs.items())
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
        result["source_inputs"]=[{"path":str(p),"bytes":len(v),"sha256":sha(v)} for p,v in inputs.items()]
        raw=enc(result);put(a.output/"RESULT.json",raw)
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"cases":result.get("cases",{}).get("cases"),
                          "result":str(a.output/"RESULT.json"),"sha256":sha(raw)}),flush=True)
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
