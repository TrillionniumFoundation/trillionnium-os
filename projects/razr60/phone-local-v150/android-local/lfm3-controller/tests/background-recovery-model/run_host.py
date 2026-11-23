#!/usr/bin/env python3
"""Actual Application + exact Engine shared admission/recovery/executor drain.
No phone, native model, filesystem recovery receipt or Android effect is executed.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path

def sha(b):return hashlib.sha256(b).hexdigest()
def ref(p):
    p=Path(p);b=p.read_bytes()
    return {"path":str(p),"bytes":len(b),"sha256":sha(b),"mode":stat.S_IMODE(p.stat().st_mode)}
def inventory(root):
    return {str(p.relative_to(root)):{"bytes":p.stat().st_size,"sha256":sha(p.read_bytes()),"mode":stat.S_IMODE(p.stat().st_mode)}
            for p in sorted(root.rglob("*")) if p.is_file()}
def exact(text,a,b):
    if text.count(a)!=1 or text.count(b)!=1:raise RuntimeError("nonunique actual source extraction")
    return text[text.index(a):text.index(b,text.index(a))]
def once(text,a,b):
    if text.count(a)!=1:raise RuntimeError("nonunique explicit host port")
    return text.replace(a,b,1)
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--source",type=Path,required=True);ap.add_argument("--output",type=Path,required=True)
    a=ap.parse_args();source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    before=inventory(source)
    tools={name:ref(Path(shutil.which(name)).resolve()) for name in ("java","javac")}
    tools["python"]=ref(Path(sys.executable).resolve())
    helper=source/"tests/recovery-application/prepare_engine_fixture.py"
    spec=importlib.util.spec_from_file_location("background_recovery_actual_engine_fixture",helper)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    fixture=out/"fixture";sources=module.prepare(source,fixture)
    original_extract=fixture/"EXTRACTION.json";original_extract.rename(fixture/"LEGACY-EXTRACTION.json")
    engine_source=source/"src/org/trillionnium/hepta/local/LocalModelEngine.java"
    start=exact(engine_source.read_text(),"    public RunHandle start(","    private void claimProcess(")
    engine_file=fixture/"LocalModelEngine.java";rendered=engine_file.read_text()
    if not rendered.endswith("}\n"):raise RuntimeError("fixture class ending differs")
    rendered=rendered[:-2]+"""
    // Explicit argument-only types. Actual start/claimProcess must reject before this poison IO endpoint.
    public static final class Request {}
    public interface Listener {void onFinished();}
    private void execute(RunHandle owner,Request request,Listener listener){
        throw new AssertionError("native/model IO is outside this reservation-only host test");
    }
"""+start+"}\n"
    engine_file.write_text(rendered)
    settings_file=fixture/"LocalModelSettings.java"
    settings_file.write_text(once(settings_file.read_text(),
        ' boolean isBusy(){throw new AssertionError("settings UI is outside the legacy recovery fixture");}',
        ' boolean hostBusy;\n boolean isBusy(){return hostBusy;}'))
    test=source/"tests/background-recovery-model/BackgroundRecoveryModelHostTest.java";sources.append(test)
    extraction={
        "schema":"hepta.background-recovery-model-extraction.v1",
        "legacy_generator":ref(helper),"legacy_extraction_before_explicit_focus_ports":ref(fixture/"LEGACY-EXTRACTION.json"),
        "actual_engine":ref(engine_source),
        "actual_start":{"bytes":len(start.encode()),"sha256":sha(start.encode())},
        "actual_application":ref(source/"src/org/trillionnium/hepta/local/LocalProbeApplication.java"),
        "generated_inputs":[ref(p) for p in sources if p.is_relative_to(out)],
        "java_inputs":[ref(p) for p in sources],
        "boundaries":[
            "Actual full Application; exact Engine external/start/admission/recovery/cancel/drain and actual RecoverySlotHandoff/TaskCancellationQueue.",
            "Actual ThreadPoolExecutor instance and production executorIdle are exercised with real host running/queued jobs.",
            "WarmTask and SettingsReservation are occupancy-only host type carriers, only injected for negative guards.",
            "Android/session/permission/diagnostic/settings/import IO endpoints are explicit host fixtures. No old result, native exit, cleanup proof or native worker is synthesized.",
            "Actual Engine.start is extracted verbatim; argument-only types and execute always-throw port ensure native IO cannot pass."
        ],
        "phone_tested":False,"native_execution_tested":False,"recovery_policy_tested":False
    }
    (fixture/"EXTRACTION.json").write_text(json.dumps(extraction,indent=2)+"\n")
    classes=out/"classes";classes.mkdir()
    commands=[
      ("compile",[shutil.which("javac"),"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",str(classes)]+list(map(str,sources))),
      ("background",[shutil.which("java"),"-cp",str(classes),"org.trillionnium.hepta.local.BackgroundRecoveryModelHostTest"])
    ]
    report={"schema":"hepta.background-recovery-model-host.v1","all_pass":False,"source":str(source),
      "inputs_before":before,"tools_before":tools,"extraction":ref(fixture/"EXTRACTION.json"),
      "java_inputs":[ref(p) for p in sources],"stages":[],"cases":0,"assertions":0,"phone_operations":0,
      "actual_application":True,"exact_engine_admission_and_drain":True,"actual_host_executor":True,
      "synthetic_android_session_and_diagnostic_ports":True,"native_model_or_cleanup_authority_claimed":False}
    for name,cmd in commands:
        started=time.monotonic()
        try:
            run=subprocess.run(cmd,cwd=source,capture_output=True,timeout=45)
            (out/(name+".stdout")).write_bytes(run.stdout);(out/(name+".stderr")).write_bytes(run.stderr)
            row={"name":name,"argv":cmd,"cwd":str(source),"exit_code":run.returncode,"elapsed_seconds":time.monotonic()-started,
                "stdout":ref(out/(name+".stdout")),"stderr":ref(out/(name+".stderr"))}
            report["stages"].append(row)
            if run.returncode:
                print(run.stdout.decode(errors="replace")[-5000:]);print(run.stderr.decode(errors="replace")[-5000:]);break
        except (OSError,subprocess.TimeoutExpired) as error:
            report["stages"].append({"name":name,"argv":cmd,"cwd":str(source),"exit_code":None,"error":str(error),"elapsed_seconds":time.monotonic()-started});break
    stdout=out/"background.stdout"
    if stdout.exists():
        text=stdout.read_text();m=re.search(r"^PASS background_cases=(\d+) assertions=(\d+)$",text,re.M)
        report["case_names"]=re.findall(r"^PASS case=([a-z_]+) assertions=\d+$",text,re.M)
        if m:report["cases"],report["assertions"]=map(int,m.groups())
    report["inputs_after"]=inventory(source);report["inputs_unchanged"]=report["inputs_before"]==report["inputs_after"]
    report["tools_after"]={name:ref(p["path"]) for name,p in tools.items()};report["tools_unchanged"]=report["tools_before"]==report["tools_after"]
    report["all_pass"]=len(report["stages"])==2 and all(s["exit_code"]==0 for s in report["stages"]) and report["cases"]==21 and len(report.get("case_names",[]))==21 and report["inputs_unchanged"] and report["tools_unchanged"]
    (out/"RESULT.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ("all_pass","cases","assertions","inputs_unchanged","tools_unchanged")}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":sys.exit(main())
