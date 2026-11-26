#!/usr/bin/env python3
"""Focused v13 admission/consumer gate; no phone operations. Execute only after review."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, os, subprocess, sys, time
p=argparse.ArgumentParser(description=__doc__)
for k in ("source","base-source","output","java-home","android-json-jar","dependency-classes","actual-input-map","legacy-input-map-v12","legacy-input-map-v11","pre-eof-source"):
    p.add_argument("--"+k,type=Path,required=True)
p.add_argument("--prepare-only",action="store_true",help="Pure source generation/pin closure, no JVM")
a=p.parse_args(); source=a.source.resolve(); base=a.base_source.resolve(); out=a.output.resolve()
here=Path(__file__).resolve().parent
for k,v in vars(a).items():
    if isinstance(v,Path):setattr(a,k,v.resolve())
assert not out.exists() and source not in out.parents and base not in out.parents
out.mkdir(mode=0o700)
def ref(path):
    p=Path(path);raw=p.read_bytes();return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def tree(path):return {str(p.relative_to(path)):ref(p) for p in sorted(path.rglob("*")) if p.is_file()}
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n")
def readjson(path):return json.loads(path.read_text())
spec=importlib.util.spec_from_file_location("v13_prepare",here/"prepare.py");m=importlib.util.module_from_spec(spec);sys.dont_write_bytecode=True;spec.loader.exec_module(m)
jar=a.android_json_jar; assert ref(jar)["sha256"]=="941cc2fe5b1e42c30ceeeb25578e589a137094d5eccf84d67196eca9c29e5cdb"
java=a.java_home/"bin/java";javac=a.java_home/"bin/javac";assert java.is_file() and javac.is_file()
deps=a.dependency_classes; assert deps.is_dir()
fixed=[a.actual_input_map,a.legacy_input_map_v12,a.legacy_input_map_v11,jar,Path(__file__).resolve(),here/"prepare.py",here/"source-inverse.json"]
fixed+=sorted(here.glob("*.java"))
fixed += [here/"eof_predecessor.py",here/"source_predecessor.py",a.pre_eof_source/"src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java"]
assert ref(fixed[-1])["sha256"]=="aad22b14be14a33f0e12823f06b8ac780a023653eba7caebc4945ea281218100"
fixed += [source/"tests/profile-cleanup-evidence/session_predecessor.py"]
for row in readjson(here/"source-inverse.json")["production"]:
    fixed += [source/row["path"],base/row["path"]]
for row in readjson(here/"source-inverse.json")["unchanged"]:fixed+=[source/row["path"],base/row["path"]]
# Read every actual archive input; this never opens a live state or phone path.
input_refs={}
def pin(r):
    p=Path(r["path"]).resolve();observed=ref(p);assert observed["bytes"]==r["bytes"] and observed["sha256"]==r["sha256"]
    input_refs[str(p)]=observed
actual=readjson(a.actual_input_map)
for row in actual["rows"]:pin(row["ref"])
for row in actual["complete_task_files"]:pin(row["ref"])
pin(actual["historical_current_control"])
for path in [a.legacy_input_map_v12,a.legacy_input_map_v11]:
    mapping=readjson(path)
    for row in mapping["rows"]:pin({"path":row["host_path"],"bytes":row["bytes"],"sha256":row["sha256"]})
before=[ref(p) for p in sorted(set(fixed))]; dep_before=tree(deps)
report={"schema":"hepta.notes-workflow-aborted-after-back-runner.v1","all_pass":False,"phone_operations":0,
        "actual_phone_absence_proven":False,"app_recovery_completed":False,"business_success":False,
        "source_inputs":before,"actual_input_refs":list(input_refs.values()),"dependency_members":dep_before,
        "stages":[],"prepare_only":a.prepare_only,"executed_jvm_commands":0}
def command(name,argv,timeout=180):
    row={"name":name,"argv":[str(x) for x in argv]}; start=time.monotonic()
    result=subprocess.run(row["argv"],capture_output=True,timeout=timeout)
    row.update(exit_code=result.returncode,seconds=time.monotonic()-start)
    stdout=out/(name+".stdout");stderr=out/(name+".stderr");stdout.write_bytes(result.stdout);stderr.write_bytes(result.stderr)
    row.update(stdout=ref(stdout),stderr=ref(stderr));report["stages"].append(row);report["executed_jvm_commands"]+=1
    if result.returncode:raise RuntimeError(name+" failed; preserved actual stdout/stderr")
    return result.stdout
def runtime(name,classes,main,args):
    cp=os.pathsep.join([str(classes),str(jar),str(deps)])
    raw=command(name,[java,"-Dhepta.fixture.host_uid="+str(os.getuid()),"-Dhepta.android.json.path="+str(jar),
                      "-cp",cp,main]+list(args))
    value=json.loads(raw);save(out/(name+".json"),value)
    if name=="legacy-client-cas":
        assert value["schema"]=="hepta.personal-notes-recovery-client-host-tests.v1" and value["passed"] is True
        assert value["checks"]==27 and value["assertions"]==247 and len(value["cases"])==len(set(value["cases"]))==27
        assert value["actual_client_except_owned_process_factory"] and value["actual_background_session"] and value["phone_contacted"] is False
    else:assert value["all_pass"] is True
    return value
try:
    startup,client,prepared=m.prepare(source,base,out,a.java_home,here,a.actual_input_map)
    report["generated_source_proof"]=prepared
    save(out/"PREPARED.json",prepared)
    if a.prepare_only:
        report["status"]="SOURCE_PREPARED_NOT_EXECUTED"
    else:
        options=["--release","8","-Xlint:all,-options","-Werror","-encoding","UTF-8","-proc:none"]
        baseline=out/"baseline-classes";baseline.mkdir()
        candidate=out/"candidate-classes";candidate.mkdir()
        startup_classes=out/"startup-classes";startup_classes.mkdir()
        cp=os.pathsep.join([str(jar),str(deps)])
        newtest=here/"NotesWorkflowAbortedAfterBackHostTest.java";proc_test=here/"NotesAbortedProcessesHost.java"
        request="src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java"
        processes="src/org/trillionnium/hepta/background/ProfileRecoveryProcesses.java"
        # Baseline rejects the actual 24-input kind before any new branch. The
        # new test's new-field/constructor access is reflective and not reached.
        command("baseline-compile",[javac]+options+["-cp",cp,"-d",baseline,base/request,base/processes,newtest,proc_test])
        report["baseline"]=runtime("baseline",baseline,"org.trillionnium.hepta.local.NotesWorkflowAbortedAfterBackHostTest",
            [a.actual_input_map,out/"baseline-scratch","baseline",out/"not-used-startup.json"])
        assert report["baseline"]["cases"]==1 and report["baseline"]["exact_refusal"]=="NOTES_INPUT_SET"
        pre_eof=out/"pre-eof-classes";pre_eof.mkdir()
        command("pre-eof-compile",[javac]+options+["-cp",cp,"-d",pre_eof,a.pre_eof_source/request,base/processes,newtest,proc_test])
        report["pre_eof"]=runtime("pre-eof",pre_eof,"org.trillionnium.hepta.local.NotesWorkflowAbortedAfterBackHostTest",
            [a.actual_input_map,out/"pre-eof-scratch","pre-eof",out/"not-used-startup.json"])
        assert report["pre_eof"]["cases"]==1 and report["pre_eof"]["exact_refusal"]=="NOTES_BROKER_RECEIPT_CHANGED"
        # The existing terminal fixture has its original local JSON adapter.
        # All producer methods and private-file readers are actual source.
        command("startup-compile",[javac]+options+["-d",startup_classes]+startup)
        raw=command("startup-producer",[java,"-Dhepta.fixture.host_uid="+str(os.getuid()),"-cp",startup_classes,
             "org.trillionnium.hepta.local.NotesAbortedStartupProducerHost",a.actual_input_map,out/"startup-actual"])
        report["startup"]=json.loads(raw);assert report["startup"]["all_pass"] is True
        legacy12=source/"tests/notes-workflow-released-reply-lost/NotesWorkflowReleasedReplyLostHostTest.java"
        legacy11=source/"tests/notes-workflow-foreign-history/NotesWorkflowForeignHistoryHostTest.java"
        old_client=source/"tests/personal-notes-absence/PersonalNotesRecoveryClientHostTest.java"
        fake=source/"tests/personal-notes-absence/FakePersonalNotesRecoveryProcess.java"
        command("candidate-compile",[javac]+options+["-cp",cp,"-d",candidate,source/request,source/processes,client,fake,
                                                       source/"src/org/trillionnium/hepta/local/BackgroundSession.java",
                                                       newtest,proc_test,legacy12,legacy11,old_client])
        report["candidate_background_session_class"]=ref(candidate/"org/trillionnium/hepta/local/BackgroundSession.class")
        report["candidate"]=runtime("candidate",candidate,"org.trillionnium.hepta.local.NotesWorkflowAbortedAfterBackHostTest",
            [a.actual_input_map,out/"candidate-scratch","candidate",out/"startup-actual/RESULT.json"])
        assert report["candidate"]["cases"]==24 and report["candidate"]["actual_collect_and_cas_cases"]==8 and report["candidate"]["eof_only_cases"]==5
        report["legacy_v12"]=runtime("legacy-v12",candidate,"org.trillionnium.hepta.local.NotesWorkflowReleasedReplyLostHostTest",
            [a.legacy_input_map_v12,out/"legacy-v12-scratch","candidate"])
        assert report["legacy_v12"]["cases"]==147 and report["legacy_v12"]["assertions"]==290
        report["legacy_v11"]=runtime("legacy-v11",candidate,"org.trillionnium.hepta.local.NotesWorkflowForeignHistoryHostTest",
            [a.legacy_input_map_v11,out/"legacy-v11-scratch"])
        assert report["legacy_v11"]["cases"]==203 and report["legacy_v11"]["assertions"]==339
        # This is the original unchanged client/CAS suite, exercising the real
        # shared reconcile/receipt checks with the new compiled client.
        report["legacy_client_cas"]=runtime("legacy-client-cas",candidate,
            "org.trillionnium.hepta.local.PersonalNotesRecoveryClientHostTest",[])
        report["all_pass"]=True;report["status"]="FOCUSED_AND_ORIGINAL_CONSUMERS_PASSED"
except Exception as error:
    report["error"]=type(error).__name__+": "+str(error)
    report["status"]="FAILED_OR_INCOMPLETE_ORIGINALS_PRESERVED"
finally:
    report["source_inputs_after"]=[ref(p) for p in sorted(set(fixed))]
    report["source_inputs_unchanged"]=before==report["source_inputs_after"]
    report["dependency_members_unchanged"]=dep_before==tree(deps)
    report["actual_inputs_unchanged"]=all(ref(Path(r["path"]))==r for r in input_refs.values())
    report["all_pass"]=report["all_pass"] and report["source_inputs_unchanged"] and report["dependency_members_unchanged"] and report["actual_inputs_unchanged"]
    save(out/"RESULT.json",report)
print(json.dumps({"result":str(out/"RESULT.json"),"status":report["status"],"all_pass":report["all_pass"],
                  "executed_jvm_commands":report["executed_jvm_commands"],"phone_operations":0}))
raise SystemExit(0 if (a.prepare_only and report["status"]=="SOURCE_PREPARED_NOT_EXECUTED" and report["source_inputs_unchanged"] and report["actual_inputs_unchanged"]) or report["all_pass"] else 1)
