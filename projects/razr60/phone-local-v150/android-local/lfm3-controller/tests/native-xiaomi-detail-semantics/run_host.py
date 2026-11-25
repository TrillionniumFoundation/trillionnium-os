#!/usr/bin/env python3
"""Run only the public synthetic price-semantic increment; no private data or Android."""
from pathlib import Path
import argparse, hashlib, json, os, stat, subprocess, time, traceback
JAVA_FILES = ["src/org/trillionnium/hepta/local/NativeAppGoal.java","src/org/trillionnium/hepta/local/NativeAppEvidence.java","src/org/trillionnium/hepta/background/ProfileIdentity.java","src/org/trillionnium/hepta/background/ProfileTarget.java","src/org/trillionnium/hepta/background/WindowOwnership.java","src/org/trillionnium/hepta/local/ObservedChildText.java","src/org/trillionnium/hepta/local/ObservedTargetLabels.java","src/org/trillionnium/hepta/local/ObservationCaptureEvidence.java","src/org/trillionnium/hepta/local/NativeCtripFormObservation.java","src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java","src/org/trillionnium/hepta/local/ObservedScrollActions.java","src/org/trillionnium/hepta/local/ObservedImeEnter.java","src/org/trillionnium/hepta/local/NativeXiaomiSearchInputObservation.java","src/org/trillionnium/hepta/local/NativeXiaomiProductPage.java","tests/native-xiaomi-detail-mirror/DetailMirrorHostTest.java","tests/native-xiaomi-product/NativeXiaomiProductPageHostTest.java","tests/native-app-fixtures/NativeXmlFixture.java","tests/native-xiaomi-detail-semantics/DetailPriceSemanticsHostTest.java"]
FIXTURE = "tests/native-xiaomi-detail-mirror/detail-shape.json"
PARSER = "src/org/trillionnium/hepta/local/NativeXiaomiProductPage.java"
PEER_R3 = "fea7aa9179e1ec55a75ae869e594d6fe35d5a3b3faf0d3c4727e1e04da0ab829"
FIXTURE_SHA = "7a367c32c5781269598704d80c697db87f507a4305dd18e3d13f0c0c9c75bad4"
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
def check(ok,why):
    if not ok: raise ValueError(why)
def pin(p):
    s=p.lstat();check(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"regular input "+str(p))
    b=p.read_bytes();t=p.lstat()
    check((s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_ino)==(t.st_size,t.st_mtime_ns,t.st_ctime_ns,t.st_ino),"changed input")
    return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"mode":stat.S_IMODE(s.st_mode)}
def save(p,obj):
    p.write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+"\n",encoding="utf-8");p.chmod(0o644)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ("source","output","java-home","json-jar"): ap.add_argument("--"+n,required=True,type=Path)
    ap.add_argument("--mode",choices=("baseline","current"),required=True)
    a=ap.parse_args()
    check(all(p.is_absolute() for p in (a.source,a.output,a.java_home,a.json_jar)),"absolute paths")
    check(not a.output.exists() and a.source not in a.output.parents,"fresh external output")
    a.output.mkdir(parents=True)
    report={"schema":"hepta.detail-price-semantic-increment-host.v1","mode":a.mode,"all_pass":False,
            "phone_operations":0,"private_originals_read":False,"android_runtime":False,"business_completion_verified":False,
            "old_83_case_suite_rerun":False,"steps":[],"started_epoch":time.time()}
    paths=[a.source/x for x in JAVA_FILES]+[a.source/FIXTURE,Path(__file__).resolve(),a.json_jar,a.java_home/"bin/java",a.java_home/"bin/javac"]
    try:
        before=[pin(p) for p in paths];report["inputs_before"]=before
        check(pin(a.source/FIXTURE)["sha256"]==FIXTURE_SHA,"unchanged public synthetic fixture")
        check(pin(a.json_jar)["sha256"]==JSON_SHA,"fixed org.json jar")
        if a.mode=="baseline": check(pin(a.source/PARSER)["sha256"]==PEER_R3,"exact r3 baseline")
        out=a.output/"classes";out.mkdir()
        def step(name,argv):
            t=time.monotonic();r=subprocess.run([str(x) for x in argv],capture_output=True,timeout=60)
            for suffix,b in (("stdout",r.stdout),("stderr",r.stderr)):
                p=a.output/(name+"."+suffix);p.write_bytes(b);p.chmod(0o644)
            report["steps"].append({"name":name,"argv":[str(x) for x in argv],"exit_code":r.returncode,"seconds":time.monotonic()-t})
            check(r.returncode==0,name+" failed; read immutable stdout/stderr")
        step("javac",[a.java_home/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror",
                      "-cp",a.json_jar,"-d",out]+[a.source/x for x in JAVA_FILES])
        step("semantic-cases",[a.java_home/"bin/java","-cp",str(out)+os.pathsep+str(a.json_jar),
                              "org.trillionnium.hepta.local.DetailPriceSemanticsHostTest",a.source/FIXTURE,a.output/"CASES.json",a.mode])
        cases=json.loads((a.output/"CASES.json").read_text())
        check(cases["all_pass"] and cases["cases"]==14,"exact small increment")
        report["cases"]=cases;report["case_report"]=pin(a.output/"CASES.json")
        report["compiled_parser"]=pin(out/"org/trillionnium/hepta/local/NativeXiaomiProductPage.class")
        report["inputs_after"]=[pin(p) for p in paths]
        report["inputs_unchanged"]=report["inputs_after"]==before
        check(report["inputs_unchanged"],"inputs unchanged")
        report["all_pass"]=True
        report["baseline_red_demonstrated"]=a.mode=="baseline"
    except Exception as e:
        report["error"]=str(e);report["traceback"]=traceback.format_exc()
    report["finished_epoch"]=time.time()
    save(a.output/"RESULT.json",report)
    print(json.dumps({"all_pass":report["all_pass"],"mode":a.mode,"result":pin(a.output/"RESULT.json")},sort_keys=True))
    return 0 if report["all_pass"] else 1
if __name__=="__main__": raise SystemExit(main())
