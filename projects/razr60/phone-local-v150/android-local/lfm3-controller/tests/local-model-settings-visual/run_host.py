#!/usr/bin/env python3
"""Ordinary GUI-Owl settings and cached-controller routing; explicit host ports, no device."""
import argparse,hashlib,json,os,re,stat,subprocess,time
from pathlib import Path

def need(value,message):
    if not value:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode()
TOKENS=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]',re.S)
def block(source,start):
    brace=source.index("{",start);depth=0
    for token in TOKENS.finditer(source,brace):
        if token.group()=="{":depth+=1
        elif token.group()=="}":
            depth-=1
            if depth==0:return source[start:token.end()]
    raise RuntimeError("unclosed exact source block")
def method(source,signature):
    need(source.count(signature)==1,"unique current production signature required: "+signature)
    return block(source,source.index(signature))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();need(all(x.is_absolute() for x in vars(a).values()),"absolute paths required")
    source=a.source.resolve(strict=True);out=a.output.absolute()
    try:out.relative_to(source)
    except ValueError:pass
    else:raise RuntimeError("output cannot be within source")
    need(os.name=="posix" and os.getuid()!=0,"non-root POSIX host required")
    out.mkdir(parents=True,exist_ok=False);inputs={}
    result={"schema":"hepta.local-model-settings-visual-host-gate.v1","all_pass":False,"stages":[],
      "phone_operations":0,"native_model_executed":False,"positive_backend_qualified":False,
      "original_settings_cases_retained":False,"actual_settings_and_runtime_router":True,
      "view_inventory_and_positive_model_loading_are_host_ports":True}
    def take(path):
        st=path.lstat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,"regular single-link input required: "+str(path))
        raw=path.read_bytes()
        if path in inputs:need(inputs[path]==raw,"source changed: "+str(path))
        inputs[path]=raw;return raw
    def put(path,raw):
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
        return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
    def run(label,args,timeout=180):
        args=list(map(str,args));row={"name":label,"argv":args};result["stages"].append(row);start=time.monotonic()
        try:
            child=subprocess.run(args,cwd=out,capture_output=True,timeout=timeout,
                env={**os.environ,"JAVA_HOME":str(a.java_home),"PATH":str(a.java_home/"bin")+os.pathsep+os.environ["PATH"]})
            row.update(exit_code=child.returncode,elapsed_seconds=time.monotonic()-start)
            row["stdout"]=put(out/(label+".stdout"),child.stdout);row["stderr"]=put(out/(label+".stderr"),child.stderr)
            need(child.returncode==0,label+" failed");return child.stdout
        except subprocess.TimeoutExpired as error:
            row.update(exit_code=None,timed_out=True,elapsed_seconds=time.monotonic()-start)
            row["stdout"]=put(out/(label+".stdout"),error.stdout or b"")
            row["stderr"]=put(out/(label+".stderr"),error.stderr or b"");raise
    try:
        test=source/"tests/local-model-settings-visual";old=source/"tests/local-model-settings"
        take(Path(__file__).resolve());take(test/"README.md")
        contract=json.loads(take(test/"CASE-CONTRACT.json"))
        need(contract["schema"]=="hepta.local-model-settings-visual-case-contract.v1"
             and contract["case_schema"]=="hepta.local-model-settings-visual-cases.v1"
             and contract["cases"]==22 and contract["assertions"]==169,"fixed complete visual contract")
        extension=json.loads(take(test/"OBSERVE-CASE-CONTRACT.json"))
        need(extension["schema"]=="hepta.local-model-settings-lfm3-observe-case-contract.v1"
             and extension["cases"]==8 and extension["assertions"]==74,"complete LFM3 observation extension")
        original_names=list(contract["names"])
        expected=original_names+extension["names"]
        need(type(expected)is list and len(expected)==30 and len(set(expected))==30
             and all(type(n)is str for n in expected),"exact unique case names")
        jar=take(a.json_jar)
        need(len(jar)==78332 and sha(jar)=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed","pinned org.json required")
        java=(a.java_home/"bin/java").resolve(strict=True);javac=(a.java_home/"bin/javac").resolve(strict=True)
        take(java);take(javac)
        version=run("javac-version",[javac,"-version"])
        need(re.match(rb"javac 17(?:\.|$)",version.strip())is not None,"actual JDK 17 required")
        take(old/"run_host.py")
        run("original-settings",["/usr/bin/python3","-B",old/"run_host.py","--source",source,
            "--output",out/"original-settings","--java-home",a.java_home,"--json-jar",a.json_jar])
        original_raw=(out/"original-settings/RESULT.json").read_bytes();original=json.loads(original_raw)
        need(original.get("all_pass")is True and original.get("inputs_unchanged")is True,"original settings gate must pass")
        for label,count,assertions in (("transaction",43,196),("generation",15,100),("context_files",8,36)):
            row=original["cases"][label]
            need(row["cases"]==count and row["assertions"]==assertions and row["passed"]is True,"original cases/assumptions retained")
        result["original_settings_cases_retained"]=True
        result["original_settings_result"]={"path":str(out/"original-settings/RESULT.json"),"bytes":len(original_raw),"sha256":sha(original_raw)}
        for row in original["source_inputs"]:take(Path(row["path"]))
        listing=json.loads(take(old/"PRODUCTION-SOURCES.json"))
        names=listing["sources"]
        need(len(names)==39 and len(set(names))==39,"complete current engine dependency list")
        pkg=source/"src/org/trillionnium/hepta/local"
        extra=["EngineInferenceAdapter.java","RuntimeInferenceAdapter.java","LocalModelSettings.java"]
        production=[source/n for n in names]+[pkg/n for n in extra]
        for path in production:take(path)
        fixture=[p for p in sorted((old/"fixtures").rglob("*.java")) if p.name!="LocalProbeApplication.java"]
        need(len(fixture)==12,"original Android fixture boundary count")
        for path in fixture:take(path)
        service=take(pkg/"HeptaAccessibilityService.java").decode()
        app=take(pkg/"LocalProbeApplication.java").decode();ui=take(pkg/"MainActivity.java").decode()
        # The actual VLM's lifecycle is covered by its unchanged canonical gate.
        take(pkg/"VlmInferenceAdapter.java");take(pkg/"VisualPromptProjection.java")
        methods={
          "app_can_change":method(app,"boolean canChangeLocalModelSettings(boolean restore)"),
          "app_require_idle":method(app,"void requireModelSettingsIdle(HeptaAccessibilityService expected)"),
          "app_main_thread":method(app,"private static void recoveryMainThread()"),
          "app_diagnostics":method(app,"private boolean otherDiagnosticsClean()"),
          "service_injected_controller":method(service,"public synchronized LocalTaskController taskController(LocalInference inference)"),
          "service_engine_controller":method(service,"public synchronized LocalTaskController taskController(LocalModelEngine engine)"),
          "service_settings_idle":method(service,"synchronized boolean modelSettingsIdle()"),
          "ui_choose":method(ui,"private void chooseLocalModelFromOwnerButton()"),
          "ui_restore":method(ui,"private void restoreLocalModelFromOwnerButton()"),
        }
        raw_template=take(test/"VisualSettingsBoundary.template").decode();generated=raw_template
        for name,body in methods.items():
            marker="{{"+name+"}}";need(generated.count(marker)==1,"exact source insertion required: "+name)
            generated=generated.replace(marker,body)
        need("{{" not in generated,"unresolved exact source insertion")
        imports=generated[:generated.index("/** Host ports:")]
        generated_paths=[]
        for match in re.finditer(r"(?m)^final class ([A-Za-z0-9_]+)\b",generated):
            body=block(generated,match.start())
            target=out/"generated/org/trillionnium/hepta/local"/(match.group(1)+".java")
            put(target,(imports+body+"\n").encode());generated_paths.append(target)
        need(len(generated_paths)==13,"complete explicit host boundary classes")
        result["production_methods"]={name:{"bytes":len(body.encode()),"sha256":sha(body.encode())} for name,body in methods.items()}
        # Only a host type modifier changes so the explicitly declared positive-asset port can
        # override verification. Every Engine field/method body stays byte-identical. The original
        # full final production Engine already passed the complete original gate above.
        engine_original=take(pkg/"LocalModelEngine.java")
        modifier=b"public final class LocalModelEngine implements AutoCloseable {"
        need(engine_original.count(modifier)==1,"unique exact Engine type modifier")
        engine_host=engine_original.replace(modifier,b"public class LocalModelEngine implements AutoCloseable {")
        need(engine_host.replace(b"public class LocalModelEngine implements AutoCloseable {",modifier)==engine_original,
             "only the declared host type modifier may change")
        engine_fixture=out/"generated/org/trillionnium/hepta/local/LocalModelEngine.java"
        put(engine_fixture,engine_host)
        production=[path for path in production if path!=pkg/"LocalModelEngine.java"]+[engine_fixture]
        result["engine_host_type_boundary"]={"only_class_final_removed":True,"all_fields_and_method_bodies_unchanged":True,
            "original_sha256":sha(engine_original),"fixture_sha256":sha(engine_host),
            "unmodified_final_engine_executed_in_original_gate":True}
        tests=[test/"VisualSettingsHostTest.java"]
        for path in tests:take(path)
        classes=out/"classes";classes.mkdir();empty=out/"empty-sourcepath";empty.mkdir()
        run("compile",[javac,"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-proc:none",
            "-sourcepath",empty,"-cp",a.json_jar,"-d",classes,*production,*fixture,*generated_paths,*tests])
        stdout=run("visual-settings",[java,"-Dhepta.fixture.host_uid="+str(os.getuid()),"-cp",
            str(classes)+os.pathsep+str(a.json_jar),"org.trillionnium.hepta.local.VisualSettingsHostTest",out/"cases"],timeout=240)
        raw=(out/"cases/RESULT.json").read_bytes();cases=json.loads(raw)
        need(cases==json.loads(stdout),"case receipt equals actual process stdout")
        result["case_result"]={"path":str(out/"cases/RESULT.json"),"bytes":len(raw),"sha256":sha(raw)}
        result["cases"]=cases
        rows=cases.get("case_results")
        need(cases.get("schema")==contract["case_schema"] and cases.get("passed")is True
          and type(cases.get("cases"))is int and cases["cases"]==30
          and type(cases.get("assertions"))is int and cases["assertions"]==243,"complete case/assertion contract")
        need(type(rows)is list and [r.get("name") for r in rows]==expected
          and all(r.get("passed")is True and type(r.get("assertions"))is int for r in rows)
          and sum(r["assertions"] for r in rows)==243,"complete ordered case names and real assertions")
        need([r["name"] for r in rows[:22]]==original_names
             and sum(r["assertions"] for r in rows[:22])==169,"all original GUI settings cases/assertions retained")
        need([r["name"] for r in rows[22:]]==extension["names"]
             and sum(r["assertions"] for r in rows[22:])==74,"all LFM3 observation cases/assertions required")
        result["original_visual_cases_retained"]={"cases":22,"assertions":169}
        result["lfm3_observation_extension"]={"cases":8,"assertions":74}
        need(cases.get("phone_operations")==0 and cases.get("native_model_executed")is False
          and cases.get("positive_backend_qualified")is False,"host scope only")
        result["case_names_sha256"]=sha(json.dumps(expected,ensure_ascii=False,separators=(",",":")).encode())
        result["all_pass"]=True
    except Exception as error:result["error"]=type(error).__name__+": "+str(error)
    finally:
        result["source_inputs"]=[{"path":str(p),"bytes":len(b),"sha256":sha(b)} for p,b in sorted(inputs.items(),key=lambda x:str(x[0]))]
        try:result["inputs_unchanged"]=all(p.read_bytes()==b for p,b in inputs.items())
        except OSError:result["inputs_unchanged"]=False
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
        ref=put(out/"RESULT.json",enc(result))
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"result":ref,
          "phone_operations":0,"native_model_executed":False}),flush=True)
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
