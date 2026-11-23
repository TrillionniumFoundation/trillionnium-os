#!/usr/bin/env python3
"""Private startup originals + unchanged pre/postlaunch recovery regression suites; host only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def identity(path):
    raw=path.read_bytes()
    return {"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar","actual-originals","postlaunch-originals","startup-originals"):
        parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args()
    source,out=a.source.resolve(),a.output.resolve()
    jdk,jar=a.java_home.resolve(),a.json_jar.resolve()
    assert not out.exists() and source not in out.parents
    out.mkdir(mode=0o700)
    before={str(p.relative_to(source)):identity(p) for p in source.rglob("*") if p.is_file()}
    original_paths=[a.startup_originals/(n+".bin") for n in ("journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output")]
    original_paths += [a.startup_originals/n for n in ("ORIGINALS.json","before-recents.stdout","after-recents.stdout")]
    originals={str(p):identity(p) for p in original_paths}
    env=dict(os.environ)
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","PYTHONPATH"):env.pop(key,None)
    env.update(PATH=str(jdk/"bin")+":/usr/bin:/bin",PYTHONDONTWRITEBYTECODE="1",PYTHONNOUSERSITE="1")
    report={"schema":"hepta.public-startup-absence-host-validation.v1","all_pass":False,"source":str(source),
            "phone_operations":0,"actual_archived_original_inputs":originals,"framework_and_current_installation_synthetic":True,"stages":[]}
    def run(name,argv,timeout=600):
        start=time.monotonic()
        with (out/(name+".stdout")).open("xb") as so,(out/(name+".stderr")).open("xb") as se:
            process=subprocess.run(list(map(str,argv)),env=env,cwd=source,stdout=so,stderr=se,timeout=timeout)
        report["stages"].append({"name":name,"argv":list(map(str,argv)),"exit_code":process.returncode,"seconds":time.monotonic()-start,
                                "stdout":identity(out/(name+".stdout")),"stderr":identity(out/(name+".stderr"))})
        assert process.returncode==0,name+" failed; original logs preserved"
    try:
        assert identity(jar)["sha256"]=="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
        run("retained-pre-postlaunch",[sys.executable,"-B",source/"tests/public-profile-absence/run_postlaunch_host.py",
              "--source",source,"--output",out/"retained","--java-home",jdk,"--json-jar",jar,
              "--actual-originals",a.actual_originals,"--postlaunch-originals",a.postlaunch_originals])
        prior=json.loads((out/"retained/RESULT.json").read_text())
        assert prior["all_pass"] is True and prior["inputs_unchanged"] is True and prior["originals_unchanged"] is True
        assert prior["complete_source_unchanged"] is True and prior["strict_release8"] is True
        report["retained_result"]=identity(out/"retained/RESULT.json")
        report["retained_case_counts"]={k:v.get("cases") for k,v in prior.items() if isinstance(v,dict) and "cases" in v}
        classes=out/"classes";classes.mkdir()
        cp=str(out/"retained/post-classes")+os.pathsep+str(jar)
        run("startup-compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror",
                              "-classpath",cp,"-d",classes,source/"tests/public-profile-absence/PublicProfileStartupAbsenceHostTest.java"])
        run("startup-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+cp,"org.trillionnium.hepta.background.PublicProfileStartupAbsenceHostTest",a.startup_originals])
        cases=json.loads((out/"startup-cases.stdout").read_text())
        assert cases["all_pass"] is True and cases["actual_archived_failure_bytes"] is True
        assert cases["cases"]==len(cases["case_names"])==len(set(cases["case_names"]))
        report["cases"]=cases
        report["all_pass"]=True
    except Exception as error:report["failure"]={"type":type(error).__name__,"message":str(error)}
    finally:
        report["source_unchanged"]=before=={str(p.relative_to(source)):identity(p) for p in source.rglob("*") if p.is_file()}
        report["originals_unchanged"]=originals=={p:identity(Path(p)) for p in originals}
        report["all_pass"]=report["all_pass"] and report["source_unchanged"] and report["originals_unchanged"]
        (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
        print(json.dumps({"all_pass":report["all_pass"],"cases":report.get("cases",{}).get("cases"),"failure":report.get("failure"),"result":str(out/"RESULT.json")}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":
    sys.dont_write_bytecode=True
    raise SystemExit(main())
