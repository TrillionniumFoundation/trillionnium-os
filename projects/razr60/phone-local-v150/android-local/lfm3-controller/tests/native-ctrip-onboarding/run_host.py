#!/usr/bin/env python3
"""Original five-node AX + exact provider/session/terminal projection, host only."""
import argparse,hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
ACTUAL={"before":"06ddd840988567bb2660be38ed80aac86cc843f364ff4d14e1dd2446d6d125c5",
        "after":"a6d3b9701a829f6657a5c9d2b954044b09df3f473d73c021d1eeb2328c2982f3"}
EXPECTED_RED=["actual_before_phase","actual_after_phase","actual_prompt_blocker","actual_terminal_ui"]
EXTRA=['ObservationCaptureEvidence', "PromptActionDomain","NativeAppEvidence","NativeAppDomain","NativeAppSession","NativeActionSnapshotCheck","NativeAppObservation","NativeCtripFlightPage","NativeXiaomiProductPage"]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(value,message):
    if not value:raise RuntimeError(message)
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(raw)
def record(path):
    raw=path.read_bytes();return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
def main():
    a=argparse.ArgumentParser();a.add_argument("--source",required=True,type=Path);a.add_argument("--overlay",required=True,type=Path)
    a.add_argument("--actual-before",required=True,type=Path);a.add_argument("--actual-after",required=True,type=Path)
    a.add_argument("--java-home",required=True,type=Path);a.add_argument("--json-jar",required=True,type=Path);a.add_argument("--output",required=True,type=Path)
    a.add_argument("--candidate-only",action="store_true",help="Compile/run only the actual integrated component; --source and --overlay must be identical")
    x=a.parse_args();s=x.source.resolve();ov=x.overlay.resolve();out=x.output.resolve();jdk=x.java_home.resolve();jar=x.json_jar.resolve()
    if x.candidate_only:need(s==ov,"candidate-only requires one complete integrated source")
    need(not out.exists() and s not in out.parents and ov not in out.parents,"fresh gate output outside both source trees required")
    need(sha(jar.read_bytes())==JSON_SHA and jar.stat().st_size==78332,"pinned real org.json required")
    actual=[x.actual_before.resolve(),x.actual_after.resolve()]
    for label,p in zip(("before","after"),actual):
        need(sha(p.read_bytes())==ACTUAL[label],"original actual five-node input differs: "+label)
        need(len(json.loads(p.read_text())["nodes"])==5,"actual five-node record required")
    test=Path(__file__).with_name("NativeCtripOnboardingHostTest.java").resolve()
    source_pins=[record(s/"SOURCE-MANIFEST.json")]
    prod=ov/"src/org/trillionnium/hepta/local";names=["NativeCtripFlightPage.java","NativeAppSession.java","LocalTaskController.java"]
    source_pins += [record(s/"src/org/trillionnium/hepta/local"/n) for n in names]+[record(prod/n) for n in names]+[record(test)]
    out.mkdir(parents=True,mode=0o700)
    result={"schema":"hepta.ctrip-first-launch-regression.v1","all_pass":False,"candidate_only":x.candidate_only,"phone_operations":0,"android_runtime":False,
            "model_executed":False,"business_verified":False,"inputs":source_pins,"actual_inputs":[record(p) for p in actual],"stages":[],
            "boundary":"Saved five-node AX values are original. Task/lease/installed/worker and cleanup are explicit host fixtures. Full OutcomeExplanation nested class is copied byte-exact into an otherwise empty Controller wrapper; Android Controller lifecycle is not executed."}
    env=dict(os.environ);env["PYTHONDONTWRITEBYTECODE"]="1";env["PATH"]=str(jdk/"bin")+":"+env.get("PATH","")
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
    def run(label,argv,expected=0):
        started=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=120)
        write(out/(label+".stdout"),p.stdout);write(out/(label+".stderr"),p.stderr)
        result["stages"].append({"name":label,"exit_code":p.returncode,"seconds":time.monotonic()-started,"argv":list(map(str,argv)),
                                 "stdout_sha256":sha(p.stdout),"stderr_sha256":sha(p.stderr)})
        if p.returncode!=expected:print(p.stderr.decode("utf-8","replace")[-16000:])
        need(p.returncode==expected,label+" exit differs: "+str(p.returncode))
    try:
        query=load(s/"tests/web-flight/run_query_host_tests.py","onboarding_query_compile_closure")
        bg=load(s/"tests/background-session/prepare_fixture.py","onboarding_platform_fixture")
        for mode in (("candidate",) if x.candidate_only else ("baseline","candidate")):
            root=out/mode;root.mkdir();bgfiles,bgmeta=bg.prepare(s,root/"platform-fixture")
            bgfiles=[p for p in bgfiles if not(p.parent.name=="json" and p.parent.parent.name=="org") and "terminal" not in p.parts]
            paths=[s/p for p in query.PURE_PATHS if p not in ("tests/web-flight/WebFlightQueryHostTest.java","tests/native-app/legacy-boundary/NativeAppSession.java")]+bgfiles
            paths += [s/("src/org/trillionnium/hepta/local/"+n+".java") for n in EXTRA]
            paths += [s/"tests/native-app-fixtures/NativeXmlFixture.java",s/"tests/native-app-provider/NativeAppProviderHostTest.java",
                      s/"tests/native-app-provider/NativeCtripLoginLoadingHostTest.java",test]
            if mode=="candidate":paths=[prod/p.name if p in [s/"src/org/trillionnium/hepta/local"/n for n in names[:2]] else p for p in paths]
            controller=(prod if mode=="candidate" else s/"src/org/trillionnium/hepta/local")/"LocalTaskController.java"
            block=query.java_block(controller.read_bytes(),"static final class OutcomeExplanation")
            projection=root/"projection/LocalTaskController.java"
            write(projection,("package org.trillionnium.hepta.local;\nimport org.json.JSONObject;\n"
                              "/** Exact nested presentation implementation; no lifecycle methods. */\n"
                              "public final class LocalTaskController {\n"+block+"\n}\n").encode())
            paths.append(projection);paths=list(dict.fromkeys(p.resolve() for p in paths));classes=root/"classes";classes.mkdir()
            metadata={"inputs":[record(p) for p in paths],"actual_background_fixture":bgmeta,"controller_source":record(controller),
                      "outcome_explanation_bytes":len(block.encode()),"outcome_explanation_sha256":sha(block.encode())}
            write(root/"INPUTS.json",(json.dumps(metadata,ensure_ascii=False,indent=2)+"\n").encode())
            run(mode+"-compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-classpath",jar,"-d",classes,*paths])
            cases=root/"CASES.json"
            run(mode+"-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeCtripOnboardingHostTest",
                               *actual,s/"tests/native-app-provider/fixtures",cases],3 if mode=="baseline" else 0)
            r=json.loads(cases.read_text())
            need(r["cases"]==14 and r["phone_operations"]==0 and r["business_verified"] is False,"case/boundary differs")
            if mode=="baseline":need(r["all_pass"] is False and r["regression_names"]==EXPECTED_RED,"baseline must fail exactly four actual semantic targets")
            else:need(r["all_pass"] is True and r["regression_mismatches"]==0,"candidate targets and rejection gates must pass")
            result[mode]=record(cases);result[mode+"_cases"]=r
            need(metadata["inputs"]==[record(Path(row["path"])) for row in metadata["inputs"]],"compile input changed")
        result["all_pass"]=True
    except Exception as e:result["error"]=type(e).__name__+": "+str(e)
    finally:
        result["inputs_unchanged"]=source_pins==[record(Path(r["path"])) for r in source_pins]
        result["actual_inputs_unchanged"]=result["actual_inputs"]==[record(p) for p in actual]
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"] and result["actual_inputs_unchanged"]
        raw=(json.dumps(result,ensure_ascii=False,indent=2)+"\n").encode();write(out/"RESULT.json",raw)
        print(json.dumps({"all_pass":result["all_pass"],"result":str(out/"RESULT.json"),"sha256":sha(raw),"error":result.get("error")}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
