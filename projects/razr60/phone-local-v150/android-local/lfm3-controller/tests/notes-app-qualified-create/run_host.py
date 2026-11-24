#!/usr/bin/env python3
"""Actual Notes contract/phase/grammar/controller admission host regression.
All Android, native model and workflow child IO is explicitly synthetic.
"""
import argparse, hashlib, importlib.util, json, os, pathlib, subprocess, sys, time
sys.dont_write_bytecode = True

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser()
    for name in ("source","java-home","output"): p.add_argument("--"+name,type=pathlib.Path,required=True)
    a=p.parse_args();s=a.source.resolve(strict=True);out=a.output.resolve()
    if out==s or s in out.parents or out.exists(): raise ValueError("new output outside source required")
    here=s/"tests/notes-app-qualified-create"
    if pathlib.Path(__file__).resolve()!=here/"run_host.py": raise ValueError("exact source runner required")
    out.mkdir(parents=True)
    helper=s/"tests/qualification-scope/prepare_fixture.py"
    before={str(x):digest(x) for x in (s/"src").rglob("*.java")}
    before.update({str(x):digest(x) for x in [pathlib.Path(__file__).resolve(),here/"NotesAppQualifiedCreateHostTest.java",here/"real-owner-50af.json",helper]})
    spec=importlib.util.spec_from_file_location("notes_app_qualified_actual_fixture",helper)
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    report=dict(schema="hepta.notes-app-qualified-create-host.v1",all_pass=False,phone_operations=0,
        android_runtime=False,native_inference=False,external_model=False,source_inputs=before,stages=[])
    env=dict(os.environ);env["PATH"]=str(a.java_home/"bin")+os.pathsep+env.get("PATH","")
    env["PYTHONDONTWRITEBYTECODE"]="1"
    for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
    def run(name,argv,timeout=90):
        start=time.monotonic();r=subprocess.run([str(x) for x in argv],capture_output=True,env=env,timeout=timeout)
        (out/(name+".stdout")).write_bytes(r.stdout);(out/(name+".stderr")).write_bytes(r.stderr)
        report["stages"].append(dict(name=name,argv=[str(x) for x in argv],exit_code=r.returncode,seconds=time.monotonic()-start,
            stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest()))
        if r.returncode:raise RuntimeError(name+" failed: "+r.stderr.decode(errors="replace")[-3000:])
        return r
    try:
        v=run("javac-version",[a.java_home/"bin/javac","-version"])
        if not v.stdout.startswith(b"javac 17."):raise ValueError("actual JDK17 required")
        files,extraction=fixture.prepare(s,out/"fixture");report["extraction"]=extraction
        uid=out/"uid-io";uid.mkdir()
        process=uid/"Process.java"
        process.write_text("package android.os;public final class Process {private Process(){}public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n")
        orig=s/"tests/qualification-scope/fixtures/android/system/Os.java";text=orig.read_text()
        marker='r.st_uid=((Number)a.get("uid")).intValue();'
        if text.count(marker)!=1:raise ValueError("actual existing filesystem UID fake anchor differs")
        fake=uid/"Os.java";fake.write_text(text.replace(marker,marker+"if(r.st_uid=="+str(os.getuid())+")r.st_uid=10481;"))
        files=[x for x in files if x not in (orig,s/"tests/qualification-scope/fixtures/android/os/Process.java")]
        files += [process,fake]
        for rel in ("tests/fixed-intent-tools/FixedIntentIntegrationHostTest.java",
                    "tests/completion/TaskCompletionGateHostTest.java",
                    "tests/notes-task-phase/NotesTaskPhaseHostTest.java",
                    "tests/notes-create-workflow/NotesCreateWorkflowHostTest.java",
                    "tests/notes-app-qualified-create/NotesAppQualifiedCreateHostTest.java"):
            files.append(s/rel)
        inputs={str(x):digest(x) for x in files}
        report["compiled_inputs"]=inputs
        report["fixture_boundary"]="Actual full LocalTaskController and Notes classes; unchanged shared IO fakes; existing held service lease prevents worker/bootstrap even for admitted requests"
        source=(s/"src/org/trillionnium/hepta/local/LocalTaskController.java").read_text()
        start=source.index("    public synchronized boolean start(final String instruction,final String expectedScopeSha256,final TaskAuthorization ownerAuthorization,\n")
        end=source.index("    public void stop(){",start)
        method=source[start:end]
        check="TaskCompletionGate.requireSupportedNotesCreate(instruction,ownerAuthorization,backgroundSelection);"
        if method.count(check)!=1 or not(method.index(check)<method.index("UUID.randomUUID()")<method.index("service.acquireTask(")<method.index("worker.execute(")):
            raise ValueError("exact admission must precede original task identity, lease and worker submission")
        report["actual_start_source_order_verified"]=True
        classes=out/"classes";classes.mkdir()
        run("compile",[a.java_home/"bin/javac","--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",classes,*files])
        run("actual-contract-producer",[a.java_home/"bin/java","-ea","-cp",classes,"org.trillionnium.hepta.local.NotesAppQualifiedCreateHostTest",here/"real-owner-50af.json",out/"cases"])
        recognizer=s/"tests/notes-task-phase/test_phase_grammar.py"
        before[str(recognizer)]=digest(recognizer)
        run("actual-emitted-grammar",[sys.executable,"-B",recognizer,out/"cases/grammar-cases.json"])
        actual=json.loads((out/"cases/CASES.json").read_text())
        if actual.get("all_pass") is not True:raise ValueError("actual producer cases did not complete")
        report["case_count"]=len(actual["cases"]);report["assertions"]=actual["checks"];report["cases"]=actual["cases"]
        report["cases_sha256"]=digest(out/"cases/CASES.json")
        report["source_inputs_unchanged"]=all(digest(pathlib.Path(k))==v for k,v in before.items())
        report["compiled_inputs_unchanged"]=all(digest(pathlib.Path(k))==v for k,v in inputs.items())
        report["all_pass"]=report["source_inputs_unchanged"] and report["compiled_inputs_unchanged"]
    except Exception as error:report["error"]=type(error).__name__+": "+str(error)
    (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps(dict(all_pass=report["all_pass"],result=str(out/"RESULT.json"),sha256=digest(out/"RESULT.json"),error=report.get("error")),ensure_ascii=False))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
