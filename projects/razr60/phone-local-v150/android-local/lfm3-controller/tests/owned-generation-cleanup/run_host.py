#!/usr/bin/env python3
"""Execute real Linux fork/proc/pidfd/group queries and bind their receipts in production Java.
Android permissions, SDK execution and phone behavior still require device qualification.
"""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,sys,time
from pathlib import Path

def need(v,m):
    if not v:raise RuntimeError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def encoded(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("source","output","java-home","json-jar","python","cc"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    need(all(v.is_absolute() for v in vars(a).values()),"absolute source/output/tool paths required")
    # Tool launch aliases are resolved and their executable bytes are bound;
    # repository inputs below remain ordinary non-symlink files.
    a.python=a.python.resolve(strict=True);a.cc=a.cc.resolve(strict=True)
    a.output.mkdir(parents=True,exist_ok=False)
    result={"schema":"hepta.owned-generation-cleanup-gate.v1","all_pass":False,"steps":[],
            "phone_operations":0,"actual_sdk_executed":False,"android_platform_io_executed":False}
    inputs={}
    def take(path):
        need(path.is_file() and not path.is_symlink(),"regular source required "+str(path))
        b=path.read_bytes()
        if path in inputs:need(inputs[path]==b,"source changed")
        inputs[path]=b;return b
    def put(path,b):
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
    def run(name,argv):
        argv=list(map(str,argv));start=time.monotonic()
        c=subprocess.run(argv,capture_output=True,timeout=90)
        put(a.output/(name+".stdout"),c.stdout);put(a.output/(name+".stderr"),c.stderr)
        result["steps"].append({"name":name,"argv":argv,"exit_code":c.returncode,
            "elapsed_seconds":time.monotonic()-start,"stdout_sha256":sha(c.stdout),"stderr_sha256":sha(c.stderr)})
        need(c.returncode==0,name+" failed: "+c.stderr.decode(errors="replace"))
    try:
        # The actual adapter reads archived upstream inputs. Preserve all bytes,
        # including those closures, rather than silently omitting a dependency.
        for path in sorted(a.source.rglob("*")):
            if path.is_file():take(path)
        for path in [a.java_home/"bin/java",a.java_home/"bin/javac",a.json_jar,a.python,a.cc]:take(path)
        cxx=Path(shutil.which("c++") or "");need(cxx.is_absolute(),"C++ compiler required");take(cxx.resolve(strict=True))
        need(sha(inputs[a.json_jar])=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed","JSON pin")
        test=a.source/"tests/owned-generation-cleanup"
        native=load("owned_generation_actual_native_cases",test/"native_cases.py")
        native_out=a.output/"native";native_out.mkdir()
        started=time.monotonic()
        nr=native.run(a.source,native_out,str(a.cc))
        result["steps"].append({"name":"actual-native-fork-proc-boundary","exit_code":0,
                                "elapsed_seconds":time.monotonic()-started,"cases":nr["cases"],"checks":nr["checks"]})
        result["native_cases_file"]={"path":str(native_out/"NATIVE-CASES.json"),
                                    "bytes":(native_out/"NATIVE-CASES.json").stat().st_size,
                                    "sha256":sha((native_out/"NATIVE-CASES.json").read_bytes())}
        extraction=load("owned_generation_existing_java_extractor",a.source/"tests/sdk-exception-failure-audit/run_host.py")
        block=extraction.java_block
        package=a.source/"src/org/trillionnium/hepta/local"
        engine=inputs[package/"LocalModelEngine.java"].decode()
        scope=inputs[package/"OwnedGenerationScope.java"].decode()
        inference=inputs[package/"LocalInference.java"].decode()
        start="        boolean cleanup=persisted&&"
        end="        task.cleanup=result;return result;"
        need(engine.count(start)==1 and engine.count(end)==1,"actual release block anchors")
        release=engine[engine.index(start):engine.index(end,engine.index(start))+len(end)]
        claim=block(engine,"private static void claimProcess(")
        cleanup=block(scope,"static final class Cleanup {")
        contract=block(inference,"final class TaskCleanup {")
        force_lines=[x for x in engine.splitlines() if "force|=generationCleanup.forceKnown&&generationCleanup.forceUsed;" in x]
        need(len(force_lines)==1,"actual force aggregate")
        marker="            cancelledSdkCleanup=cancelledSdkCleanup&&generationKnown"
        at=engine.index(marker);cancel=engine[at:engine.index(";",at)+1]
        projection="""package org.trillionnium.hepta.local;
import java.io.*;
import java.util.concurrent.atomic.*;
import org.json.JSONObject;
final class EngineReleaseProjection {
    static final AtomicReference<RunHandle> PROCESS_ACTIVE=new AtomicReference<>();
    static final Object PROCESS_ADMISSION=new Object();
    // Cancellation-queue execution is covered by its existing independent gate.
    static final Queue ACTIVE_CANCELLATION=new Queue();
    static final class Queue { boolean pending(){return false;} }
    final AtomicReference<RunHandle> active=new AtomicReference<>();
    final AtomicReference<WarmTask> warmActive=new AtomicReference<>();
    final WarmTask task=new WarmTask();
    static final class RunHandle { final AtomicReference<Process> child=new AtomicReference<>(); }
    static final class WarmTask {
        final RunHandle owner=new RunHandle();LocalInference.TaskCleanup cleanup;
        final String taskId="11111111111111111111111111111111";
        String generation(){return "22222222222222222222222222222222";}
    }
    static final class DeadProcess extends Process {
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){return new ByteArrayInputStream(new byte[0]);}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public int waitFor(){return 0;}public int exitValue(){return 0;}public void destroy(){}
    }
    static final class Scope {
"""+cleanup+"""
    }
    EngineReleaseProjection(){
        task.owner.child.set(new DeadProcess());PROCESS_ACTIVE.set(task.owner);
        active.set(task.owner);warmActive.set(task);
    }
    LocalInference.TaskCleanup release(boolean persisted,boolean observed,boolean generationKnown,boolean valid,Integer exit){
        WarmTask task=this.task;Process process=task.owner.child.get();
        String receiptHash="0000000000000000000000000000000000000000000000000000000000000000";
"""+release+"""
    }
    boolean slotRetained(){return task.owner.child.get()!=null&&PROCESS_ACTIVE.get()==task.owner
        &&active.get()==task.owner&&warmActive.get()==task;}
    boolean tryNext(){try{claimProcess(new RunHandle(),new AtomicReference<RunHandle>());return true;}
        catch(IllegalStateException expected){return false;}}
"""+claim+"""
    static JSONObject cancelClassification(boolean force,boolean cancelledSdkCleanup,boolean generationKnown,Scope.Cleanup generationCleanup)throws Exception{
"""+force_lines[0]+"\n"+cancel+"""
        return new JSONObject().put("force",force).put("cooperative",cancelledSdkCleanup);
    }
}
"""
        generated=a.output/"generated/org/trillionnium/hepta/local"
        put(generated/"EngineReleaseProjection.java",projection.encode())
        put(generated/"LocalInference.java",("package org.trillionnium.hepta.local;\ninterface LocalInference {\n"+contract+"\n}\n").encode())
        result["extracted_current_blocks"]={k:{"bytes":len(v.encode()),"sha256":sha(v.encode())} for k,v in {
            "actual_release":release,"actual_claimProcess":claim,"actual_Cleanup_unforced":cleanup,
            "actual_TaskCleanup":contract,"actual_force_aggregate":force_lines[0],"actual_cancel_conjunction":cancel}.items()}
        classes=a.output/"classes";classes.mkdir()
        sources=[package/"WorkerGenerationProof.java",test/"WorkerGenerationHostTest.java",
                 generated/"EngineReleaseProjection.java",generated/"LocalInference.java"]
        run("java-compile",[a.java_home/"bin/javac","--release","8","-encoding","UTF-8","-Xlint:all","-Werror",
                            "-cp",a.json_jar,"-d",classes,*sources])
        run("java-receipts-budget-admission",[a.java_home/"bin/java","-cp",str(classes)+os.pathsep+str(a.json_jar),
              "org.trillionnium.hepta.local.WorkerGenerationHostTest",native_out/"NATIVE-CASES.json",a.output/"JAVA-CASES.json"])
        jr=json.loads((a.output/"JAVA-CASES.json").read_bytes())
        need(jr["all_pass"] is True and jr["cases"]==len(jr["case_names"]) and len(set(jr["case_names"]))==jr["cases"],"Java cases incomplete")
        names=["native:"+r["case"] for r in nr["records"]]+["java:"+n for n in jr["case_names"]]
        cases={"schema":"hepta.owned-generation-cleanup-host.v1","all_pass":True,
               "cases":nr["cases"]+jr["cases"],"checks":nr["checks"]+jr["checks"],
               "native_cases":nr["cases"],"native_checks":nr["checks"],
               "java_cases":jr["cases"],"java_checks":jr["checks"],"case_names":names,
               "unfiltered_actual_proc_enumeration":True,"real_host_fork_and_exec":True,
               "held_proc_fd_signals_and_kernel_group_queries":True,"phone_tested":False}
        need(cases["cases"]==len(names) and len(set(names))==len(names),"combined case list")
        put(a.output/"CASES.json",encoded(cases))
        result["cases"]=cases;result["all_pass"]=True
    except Exception as error:
        result["error"]=type(error).__name__+": "+str(error)
    finally:
        result["inputs_unchanged"]=all(path.read_bytes()==raw for path,raw in inputs.items())
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
        result["source_inputs"]=[{"path":str(path),"bytes":len(raw),"sha256":sha(raw)} for path,raw in inputs.items()]
        put(a.output/"RESULT.json",encoded(result))
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"cases":result.get("cases"),
                          "result":str(a.output/"RESULT.json"),"result_sha256":sha((a.output/"RESULT.json").read_bytes())}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
