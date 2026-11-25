#!/usr/bin/env python3
"""Actual private history admission and explicitly synthetic current-proof/consumer tests. No phone."""
import argparse,hashlib,json,os,stat,subprocess,traceback
from pathlib import Path
JSON_SHA="941cc2fe5b1e42c30ceeeb25578e589a137094d5eccf84d67196eca9c29e5cdb"
MAIN="org.trillionnium.hepta.local.NotesWorkflowReleasedReplyLostHostTest"
def need(v,m):
    if not v:raise RuntimeError(m)
def raw(p):
    p=Path(p);a=p.lstat();need(p.is_absolute() and p.resolve()==p and stat.S_ISREG(a.st_mode) and a.st_nlink==1,"regular unaliased input required: "+str(p))
    b=p.read_bytes();z=p.lstat();need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) and len(b)==a.st_size,"changed input")
    return b
def ref(p):
    p=Path(p);b=raw(p);return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def put(p,v):
    b=v if isinstance(v,bytes) else (json.dumps(v,ensure_ascii=False,indent=2)+"\n").encode()
    with Path(p).open("xb") as f:f.write(b)
    os.chmod(p,0o600)
def mapped(p):
    m=json.loads(raw(p));need(m["schema"]=="hepta.actual-private-original-input-map.v1" and len(m["rows"])==24,"exact 23 originals plus current control required")
    result={}
    for r in m["rows"]:
        need(r["role"] not in result,"duplicate role");v=ref(r["host_path"]);need((v["bytes"],v["sha256"])==(r["bytes"],r["sha256"]),"original changed");result[r["role"]]=v
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("source","base-source","output","java-home","android-json-jar","dependency-classes","private-input-map","legacy-input-map"):p.add_argument("--"+n,required=True)
    a=p.parse_args();source=Path(a.source);base=Path(a.base_source);out=Path(a.output);jdk=Path(a.java_home);jar=Path(a.android_json_jar);deps=Path(a.dependency_classes);mapping=Path(a.private_input_map);legacy=Path(a.legacy_input_map)
    for v in (source,base,out,jdk,jar,deps,mapping,legacy):need(v.is_absolute() and v.resolve()==v,"absolute unaliased path required")
    need(not out.exists() and source.is_dir() and base.is_dir() and deps.is_dir(),"new output/existing source required")
    need(ref(jar)["sha256"]==JSON_SHA,"actual Android16 JSON implementation required")
    before=mapped(mapping);old=mapped(legacy)
    rel="src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java"
    test=source/"tests/notes-workflow-released-reply-lost/NotesWorkflowReleasedReplyLostHostTest.java"
    oldtest=source/"tests/notes-workflow-foreign-history/NotesWorkflowForeignHistoryHostTest.java"
    sources=[ref(source/rel),ref(base/rel),ref(test),ref(oldtest)]
    consumers=["PublicPersonalNotesRecoveryClient.java","BackgroundSession.java","MobiMindPrivateFiles.java","RecoveryJournalTransaction.java","RecoveryQuiescence.java","SessionRecovery.java","LocalTaskSession.java"]
    for name in consumers:
        r="src/org/trillionnium/hepta/local/"+name
        need(raw(source/r)==raw(base/r),"unchanged consumer source required: "+r);sources.append(ref(source/r))
    for name in ("WorkerGenerationProof.java",):
        r="src/org/trillionnium/hepta/local/"+name
        need(raw(source/r)==raw(base/r),"unchanged generation source required");sources.append(ref(source/r))
    for name in ("PublicPersonalNotesAbsenceMain.java","PublicPersonalNotesHistory.java"):
        r="src/org/trillionnium/hepta/background/"+name
        need(raw(source/r)==raw(base/r),"unchanged absence producer required");sources.append(ref(source/r))
    dep_refs=[ref(x) for x in sorted(deps.rglob("*.class"))];need(dep_refs,"complete compiled dependency inventory required")
    out.mkdir(mode=0o700,parents=True);env=dict(os.environ)
    for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
    report=dict(schema="hepta.notes-workflow-released-reply-lost-runner.v1",all_pass=False,source_root=str(source),base_source_root=str(base),
      sources=sources,private_input_map=ref(mapping),private_originals=before,legacy_input_map=ref(legacy),legacy_originals=old,
      android_json_jar=ref(jar),java=ref(jdk/"bin/java"),javac=ref(jdk/"bin/javac"),
      dependency_classes=str(deps),dependency_class_refs=dep_refs,stages=[],phone_operations=0,current_absence_proven=False,
      app_recovery_completed=False,business_success_claimed=False)
    def run(label,argv):
        put(out/(label+".argv.json"),argv)
        c=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=180)
        put(out/(label+".stdout"),c.stdout);put(out/(label+".stderr"),c.stderr)
        r=dict(label=label,argv=argv,exit_code=c.returncode,stdout=ref(out/(label+".stdout")),stderr=ref(out/(label+".stderr")))
        report["stages"].append(r);need(c.returncode==0 and c.stderr==b"","stage failed: "+label);return c.stdout
    try:
        for kind,s in (("baseline",base),("candidate",source)):
            classes=out/(kind+"-classes");classes.mkdir(mode=0o700)
            files=[s/rel,test]+([oldtest] if kind=="candidate" else [])
            cp=os.pathsep.join(map(str,(jar,deps)));runtime=os.pathsep.join(map(str,(classes,jar,deps)))
            run(kind+"-compile",[str(jdk/"bin/javac"),"--release","8","-Xlint:all,-options","-Werror","-encoding","UTF-8","-proc:none","-cp",cp,"-d",str(classes)]+list(map(str,files)))
            result=json.loads(run(kind+"-test",[str(jdk/"bin/java"),"-Dhepta.android.json.path="+str(jar),"-cp",runtime,MAIN,str(mapping),str(out/(kind+"-scratch")),kind]))
            need(result["all_pass"] and result["mode"]==kind and result["phone_operations"]==0 and result["current_absence_proven"] is False,"closed report")
            report[kind+"_summary"]=result
            if kind=="candidate":
                for field in ("request_roundtrip_exact","normal_model_generation_validator_passed","client_and_background_dynamic_source_passed","actual_ack_new_idle_consumer_passed","original_byte_preservation"):need(result[field] is True,"consumer failed "+field)
                oldresult=json.loads(run("legacy-v11-test",[str(jdk/"bin/java"),"-cp",runtime,"org.trillionnium.hepta.local.NotesWorkflowForeignHistoryHostTest",str(legacy),str(out/"legacy-v11-scratch")]))
                need(oldresult["all_pass"] and oldresult["cases"]==203 and oldresult["assertions"]==339 and oldresult["phone_operations"]==0,"old v11 regression failed")
                report["legacy_v11_summary"]=oldresult
            report[kind+"_compiled_classes"]=[ref(x) for x in sorted(classes.rglob("*.class"))]
        need(before==mapped(mapping) and old==mapped(legacy),"private original changed")
        need(sources==[ref(x["path"]) for x in sources],"source changed")
        need(dep_refs==[ref(x) for x in sorted(deps.rglob("*.class"))],"compiled dependency changed")
        report["all_pass"]=True;report["all_original_bytes_unchanged"]=True
    except Exception as e:
        report["error"]=str(e);report["traceback"]=traceback.format_exc()
    put(out/"RESULT.json",report)
    print(json.dumps(dict(all_pass=report["all_pass"],result=ref(out/"RESULT.json"),baseline=report.get("baseline_summary",{}).get("cases"),
      candidate=report.get("candidate_summary",{}).get("cases"),legacy_v11=report.get("legacy_v11_summary",{}).get("cases"),phone_operations=0)))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
