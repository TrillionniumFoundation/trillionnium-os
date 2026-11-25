#!/usr/bin/env python3
"""Compile the unchanged production dependency closure, with four reviewed rich-parser replacements only.
Optional private originals stay outside source. No Android/ADB or model operations.
"""
import argparse, hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
NAMES = ["ProfileIdentity","ProfileTarget","WindowOwnership","BrokerProtocol","PublicPermissionControllerUi",
         "PublicOwnGroupPolicy","FixedIntentTools","BackgroundOwnedTaskPolicy","BackgroundOwnedSingleTask",
         "ProfileTaskPolicy","ProfileOwnedTask","ProfilePermissionTransient","ProfileDisplayCustody",
         "PublicOwnGroupPhysicalFence","PublicProfileRecentHistory","ProfilePrelaunchRecovery","ProfileRecoveryProcesses",
         "PublicProfileAbsenceRecovery","PublicPersonalNotesHistory","PublicPersonalNotesAbsenceRecovery"]
REPLACEMENTS = {"PublicOwnGroupPhysicalFence","PublicProfileRecentHistory","PublicPersonalNotesHistory","PublicPersonalNotesRetirement"}
ACTUAL = {
 "actual_home": (5424,"384038b19ba6411a0fae66adccf19c268139fc5978b04086e04b065d944cee9f",3,-1,-1),
 "actual_controller_1997_display_633": (7041,"3749cf826ecdb08ef70c60e973d85c8021eb7d754e6163fff0b2ece27fc59ea9",4,1997,633),
}
LEGACY = {"before-recents.txt":"bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a",
          "after-recents.txt":"5755f3c99126d9f093272b7b73cce47a74049d5398110a1c8d97465e1952c4f3"}
BASELINE = {"PublicOwnGroupPhysicalFence":"3b63a9370426984025cb9c5e5815300c992960bb0e42e40b468cd99818f6e79b",
            "PublicProfileRecentHistory":"a37f9eb8c95919e1c5084c4d8531fc74c6041e704b63acb2b99eb0e85115f94f",
            "PublicPersonalNotesHistory":"29232617cb34bcd85b768549474f895edf4a55b5c235c494ff8edef928380cf2",
            "PublicPersonalNotesRetirement":"fff04ca5f7ae56e9a894ad41688fb7d128ef0f0b01ed69f9251294f2a7f0a34d"}
def ref(path):
    path = Path(path)
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or path.is_symlink(): raise ValueError("regular input required: "+str(path))
    b = path.read_bytes()
    return dict(path=str(path),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def put(path,value):
    with path.open("x",encoding="utf-8") as f: json.dump(value,f,ensure_ascii=False,indent=2);f.write("\n")
def extract_retirement_history(original,out):
    text=original.read_text()
    marker="    private static final class History {"
    if text.count(marker)!=1 or not text.endswith("\n}\n"):raise ValueError("retirement History extraction boundary differs")
    begin=text.index(marker);end=text.rfind("\n}")
    history=text[begin:end]
    if not history.endswith("\n    }"):raise ValueError("retirement History final block differs")
    need="    private static void need(boolean ok,String code){if(!ok)throw new IllegalStateException(code);}"
    if text.count(need)!=1:raise ValueError("actual retirement need method differs")
    at=text.index("/** Bounded pre-release retirement.")
    imports=text[:at]
    generated=imports+"/* Host shell: exact private History and need bodies only. */\nfinal class PublicPersonalNotesRetirement {\n"+need+"\n"+history+"\n}\n"
    out.mkdir()
    path=out/"PublicPersonalNotesRetirement.java"
    with path.open("x",encoding="utf-8") as f:f.write(generated)
    return path,dict(source=ref(original),history_body_sha256=hashlib.sha256(history.encode()).hexdigest(),
                     need_body_sha256=hashlib.sha256(need.encode()).hexdigest(),generated=ref(path),
                     history_body_byte_exact=True,full_android_coordinator_compiled=False,phone_operations=0)
def main():
    p=argparse.ArgumentParser()
    for name in ("source","java-home","json-jar","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--baseline",type=Path)
    p.add_argument("--overlay",type=Path,help="Authoring only: exactly four reviewed parser sources replace source inputs.")
    p.add_argument("--actual-home",type=Path)
    p.add_argument("--actual-controller",type=Path)
    p.add_argument("--historical-recents",type=Path)
    p.add_argument("--business-recents",type=Path)
    a=p.parse_args()
    if bool(a.actual_home)!=bool(a.actual_controller):p.error("both actual originals must be supplied")
    source=a.source.resolve();out=a.output.resolve()
    if out.exists():raise ValueError("new output directory required")
    if ref(a.json_jar)["sha256"]!=JSON_SHA:raise ValueError("org.json pin differs")
    bg=Path("src/org/trillionnium/hepta/background")
    driver=Path(__file__).with_name("EmptyVisibleRecentsHostTest.java").resolve()
    candidate=[((a.overlay.resolve() if a.overlay and name in REPLACEMENTS else source)/bg/(name+".java")) for name in NAMES]
    shared=["tests/profile-broker/ProfileBrokerHostTest.java","tests/public-own-group-policy/PublicPhysicalAuditHostTest.java",
            "tests/personal-notes-absence/PersonalNotesAbsenceHostTest.java"]
    candidate += [source/name for name in shared]+[driver]
    baseline=[]
    if a.baseline:
        base=a.baseline.resolve()
        for name,sha in BASELINE.items():
            if ref(base/bg/(name+".java"))["sha256"]!=sha:raise ValueError("exact4c0f baseline parser required")
        baseline=[base/bg/(name+".java") for name in NAMES]+[base/name for name in shared]+[driver]
        for name,cp,bp in zip(NAMES,candidate,baseline):
            if name not in REPLACEMENTS and ref(cp)["sha256"]!=ref(bp)["sha256"]:
                raise ValueError("unchanged dependency differs: "+name)
        for name in shared:
            if ref(source/name)["sha256"]!=ref(base/name)["sha256"]:raise ValueError("old shared test changed: "+name)
    spec=dict(actual=[],legacy=[],business=[])
    if a.actual_home:
        for name,path in [("actual_home",a.actual_home),("actual_controller_1997_display_633",a.actual_controller)]:
            r=ref(path.resolve());size,sha,count,controller,display=ACTUAL[name]
            if r["bytes"]!=size or r["sha256"]!=sha:raise ValueError("actual original changed: "+name)
            spec["actual"].append(dict(name=name,rows=count,controller=controller,display=display,**r))
    if a.historical_recents:
        for name,sha in LEGACY.items():
            r=ref(a.historical_recents.resolve()/name)
            if r["sha256"]!=sha:raise ValueError("old full-visible original changed")
            spec["legacy"].append(dict(name="legacy_"+name,**r))
    if a.business_recents:
        r=ref(a.business_recents.resolve())
        if r["bytes"]!=14971 or r["sha256"]!="785b747b08cb4b7f30c48469fe6fdd5ef8d6240417c5a0f3f7ea8b239dd6b63f":raise ValueError("actual Notes business row original differs")
        spec["business"].append(dict(name="actual_notes_1909_full_visible",**r))
    retirement_candidate=(a.overlay.resolve() if a.overlay else source)/bg/"PublicPersonalNotesRetirement.java"
    retirement_baseline=a.baseline.resolve()/bg/"PublicPersonalNotesRetirement.java" if a.baseline else None
    paths=list(dict.fromkeys(candidate+baseline+[retirement_candidate]+([retirement_baseline] if retirement_baseline else [])+[Path(__file__).resolve(),a.json_jar.resolve()]))
    before={str(p):ref(p) for p in paths}
    originals={r["path"]:ref(r["path"]) for r in spec["actual"]+spec["legacy"]+spec["business"]}
    out.mkdir(parents=True,exist_ok=False,mode=0o700)
    put(out/"INPUTS.json",spec)
    result=dict(schema="hepta.empty-visible-recents-java-host-gate.v1",all_pass=False,strict_release8=True,
                source=str(source),overlay=str(a.overlay.resolve()) if a.overlay else None,
                source_inputs_before=before,actual_originals=originals,phone_operations=0,
                android_runtime=False,model_executed=False,business_verified=False,cleanup_verified=False,
                stages=[],retirement_history_extractions=[],complete_transport_is_external_prerequisite=True)
    jdk=a.java_home.resolve()/"bin"
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
    parsed={}
    try:
        for label,files,expected in ([("baseline",baseline,3)] if baseline else [])+[("candidate",candidate,0)]:
            classes=out/(label+"-classes");classes.mkdir()
            cp=str(classes)+os.pathsep+str(a.json_jar.resolve())
            original=retirement_baseline if label=="baseline" else retirement_candidate
            generated,derivation=extract_retirement_history(original,out/(label+"-retirement-history"))
            result["retirement_history_extractions"].append(derivation)
            compile_files=files+[generated]
            commands=[(label+"-compile",[str(jdk/"javac"),"--release","8","-proc:none","-Xlint:all,-options","-Werror","-encoding","UTF-8",
                                         "-cp",str(a.json_jar.resolve()),"-d",str(classes),*map(str,compile_files)],0),
                      (label+"-cases",[str(jdk/"java"),"-ea","-cp",cp,"org.trillionnium.hepta.background.EmptyVisibleRecentsHostTest",
                                       label,str(out/"INPUTS.json")],expected)]
            for name,argv,expected_code in commands:
                started=time.monotonic()
                with (out/(name+".stdout")).open("xb") as so,(out/(name+".stderr")).open("xb") as se:
                    done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=env,timeout=60)
                row=dict(name=name,argv=argv,exit_code=done.returncode,expected_exit_code=expected_code,
                         seconds=time.monotonic()-started,stdout=ref(out/(name+".stdout")),stderr=ref(out/(name+".stderr")))
                result["stages"].append(row)
                if done.returncode!=expected_code:raise RuntimeError("focused stage failed: "+name+"; original logs retained")
                if name.endswith("-cases"):
                    parsed[label]=json.loads((out/(name+".stdout")).read_text())
                    if label=="baseline" and parsed[label].get("expected_baseline_red") is not True:raise ValueError("baseline was not actual red")
                    if label=="candidate" and parsed[label].get("all_pass") is not True:raise ValueError("candidate refused positive case")
        result["baseline"]=parsed.get("baseline")
        result["candidate"]=parsed["candidate"]
        if baseline:
            first=parsed["baseline"]["projection_fixtures"];last=parsed["candidate"]["projection_fixtures"]
            if first!=last:raise ValueError("old full-visible projection/evidence changed")
            result["full_visible_projection_parity"]=dict(passed=True,fixture_count=len(first),values=first)
        else:result["full_visible_projection_parity"]=dict(passed=None,reason="baseline not supplied")
        result["source_inputs_after"]={str(p):ref(p) for p in paths}
        result["source_inputs_unchanged"]=before==result["source_inputs_after"]
        result["originals_unchanged"]=originals=={p:ref(p) for p in originals}
        if not result["source_inputs_unchanged"] or not result["originals_unchanged"]:raise ValueError("source/original drift")
        result["all_pass"]=True
    except BaseException as e:
        result["error"]=type(e).__name__+": "+str(e)
        result["source_inputs_after"]={str(p):ref(p) for p in paths}
        result["source_inputs_unchanged"]=before==result["source_inputs_after"]
        result["originals_unchanged"]=originals=={p:ref(p) for p in originals}
    put(out/"RESULT.json",result)
    print(json.dumps(dict(all_pass=result["all_pass"],result=ref(out/"RESULT.json"),
                         candidate_cases=parsed.get("candidate",{}).get("case_count"),candidate_assertions=parsed.get("candidate",{}).get("assertions"),
                         baseline_expected_red=parsed.get("baseline",{}).get("expected_baseline_red"),phone_operations=0)))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
