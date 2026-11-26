#!/usr/bin/env python3
"""Actual complete Reader/Custody active-root cases; synthetic Android IO only."""
from pathlib import Path
import argparse,ast,hashlib,importlib.util,json,os,stat,subprocess,sys,time
sys.dont_write_bytecode=True
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
LEGACY_JAVA_SHA="76dc48b6da29be78df43acbb94112bb4325e6746bcf72d4333c43362be138e47"
PORTS_SHA="884478f84b67f4c8679f60997d96ad6ea5389a657d2e39585854f078f453686d"
FIXTURE_SHA="8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201"
ACTUAL_SHA="9a42f76cfd0249bf1cfcb587bcdff9b2c533c0877df1520127cb107b299712a3"
def need(ok,message):
    if not ok:raise RuntimeError(message)
def raw(path):
    path=Path(path);need(path.is_absolute() and path.resolve(strict=True)==path,"absolute non-symlink input")
    before=path.stat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,"regular input")
    data=path.read_bytes();after=path.stat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns,before.st_mode)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode),"input changed")
    return data
def ref(path):
    path=Path(path);data=raw(path)
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mode=oct(path.stat().st_mode&0o777))
def put(path,value):
    with Path(path).open("x",encoding="utf-8") as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def load_module(path):
    spec=importlib.util.spec_from_file_location("notes_active_existing_ports",path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def original_lists(path):
    tree=ast.parse(raw(path).decode());found={}
    for node in ast.walk(tree):
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ("production","private_names"):
            name=node.targets[0].id;need(name not in found,"unique original complete class list")
            found[name]=ast.literal_eval(node.value)
    need(set(found)=={"production","private_names"} and len(found["production"])==15 and len(found["private_names"])==15,"original complete class inventories")
    return found
def main():
    parser=argparse.ArgumentParser()
    for name in ("source","output","java-home","json-jar"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--actual-failure-terminal",type=Path)
    args=parser.parse_args();source=args.source.resolve(strict=True);out=args.output.absolute();jdk=args.java_home.resolve(strict=True);jar=args.json_jar.resolve(strict=True)
    need(out!=source and source not in out.parents,"outputs outside source");out.mkdir(parents=True,exist_ok=False)
    own=Path(__file__).resolve().parent;old=source/"tests/notes-task-info-reader"
    fixture=old/"synthetic-notes-census.json";ports_source=old/"prepare_fixture.py";old_runner=old/"run_host.py";old_java=old/"NotesTaskInfoReaderHostTest.java"
    need(ref(jar)["sha256"]==JSON_SHA and ref(jar)["bytes"]==78332,"original JSON tool")
    need(ref(fixture)["sha256"]==FIXTURE_SHA and ref(fixture)["bytes"]==18714,"complete fixed synthetic TaskInfo fixture")
    need(ref(ports_source)["sha256"]==PORTS_SHA and ref(old_java)["sha256"]==LEGACY_JAVA_SHA,"original unchanged Android ports and old cases")
    expected=json.loads(raw(own/"ExpectedCases.json"));need(expected["schema"]=="hepta.notes-active-root-reader-case-inventory.v1","case inventory")
    names=expected["case_names"];need(len(names)==len(set(names))==54,"54 declared cases; no execution implied")
    declared=original_lists(old_runner)
    bg=source/"src/org/trillionnium/hepta/background"
    active_inverse=old/"active_root_predecessor.py";active_proof=load_module(active_inverse)
    for name in ("PublicPersonalNotesReader.java","PublicPersonalNotesCustody.java"):
        original=active_proof.predecessor(name,raw(bg/name))
        need(hashlib.sha256(original).hexdigest()==active_proof.PINS[name]["previous_sha256"],"complete active-root predecessor proof copy")
    files=[bg/(x+".java") for x in declared["production"]]+[source/"tests/public-own-group-policy/PublicPhysicalAuditHostTest.java",old_java,own/"NotesActiveRootReaderHostTest.java"]
    private_files=[bg/(x+".java") for x in declared["private_names"]]+[source/"tests/profile-broker/ProfileBrokerHostTest.java"]
    need(ref(private_files[-1])["sha256"]=="5880a651260aa18566364f4dbca427c5adbba8048eee7f1b8a3d55f4a6f69e04","original private47 source")
    sources=list(dict.fromkeys(files+private_files+[ports_source,old_runner,active_inverse,own/"run_host.py",own/"ExpectedCases.json",fixture]))
    actual=None
    if args.actual_failure_terminal is not None:
        path=args.actual_failure_terminal.resolve(strict=True);data=raw(path)
        need(len(data)==5903 and hashlib.sha256(data).hexdigest()==ACTUAL_SHA,"exact 569 diagnostic original")
        broker=json.loads(data);failure=broker["personal_notes_task_info_diagnostics"]["first_runtime_failure"]["actual_root_read_failure"]
        sets=[failure[k] for k in ("before_all_roots","owned_display_roots","after_all_roots")]
        need([len(v) for v in sets]==[2,2,1] and failure["stage"]=="within_sample","original observed transition, not reconstructed TaskInfo")
        actual=dict(original=ref(path),observed_set_sizes=[2,2,1],complete_taskinfo_available=False,full_rows_reconstructed=False,current_recovery_claimed=False)
        sources.append(path)
    source_before=[ref(p) for p in sources];tools=[ref(p) for p in (jdk/"bin/javac",jdk/"bin/java",jdk/"lib/ct.sym",jdk/"lib/modules",jar)]
    ports=load_module(ports_source).prepare(out/"android-host-ports")
    inputs=files+ports;before=[ref(p) for p in inputs];private_before=[ref(p) for p in private_files]
    classes=out/"classes";classes.mkdir();private_classes=out/"private-classes";private_classes.mkdir()
    flags=["--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-proc:none"]
    cp=str(classes)+os.pathsep+str(jar)
    commands=[
      ("compile-reader",[jdk/"bin/javac",*flags,"-cp",jar,"-d",classes,*inputs]),
      ("original-reader-cases",[jdk/"bin/java","-ea","-cp",cp,"org.trillionnium.hepta.background.NotesTaskInfoReaderHostTest",fixture,"synthetic_derived_fixture"]),
      ("active-root-cases",[jdk/"bin/java","-ea","-cp",cp,"org.trillionnium.hepta.background.NotesActiveRootReaderHostTest",fixture,out/"CASES.json"]),
      ("compile-original-private",[jdk/"bin/javac",*flags,"-cp",jar,"-d",private_classes,*private_files]),
      ("original-private-cases",[jdk/"bin/java","-ea","-cp",str(private_classes)+os.pathsep+str(jar),"org.trillionnium.hepta.background.ProfileBrokerHostTest"])]
    env=dict(os.environ)
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","PYTHONPATH"):env.pop(key,None)
    env.update(JAVA_HOME=str(jdk),PATH=str(jdk/"bin")+":/usr/bin:/bin",PYTHONDONTWRITEBYTECODE="1",PYTHONNOUSERSITE="1")
    report=dict(schema="hepta.notes-active-root-reader-host.v1",all_pass=False,source=str(source),stages=[],
      source_inputs_before=source_before,compile_inputs_before=before,private_compile_inputs_before=private_before,tools_before=tools,
      original_case_inventory=declared,expected_active_cases=names,original_569_shape=actual,
      phone_operations=0,android_runtime=False,framework_and_binder_fixtures_synthetic=True,current_569_recovery_claimed=False,
      complete_production_classes=True,existing_private_active_read_constructor_replaced=False)
    try:
        for name,argv in commands:
            argv=list(map(str,argv));start=time.monotonic()
            with (out/(name+".stdout")).open("xb") as stdout,(out/(name+".stderr")).open("xb") as stderr:
                p=subprocess.run(argv,cwd=source,env=env,stdout=stdout,stderr=stderr,timeout=120)
            report["stages"].append(dict(name=name,argv=argv,exit_code=p.returncode,seconds=time.monotonic()-start,stdout=ref(out/(name+".stdout")),stderr=ref(out/(name+".stderr"))))
            if name=="active-root-cases" and (out/"CASES.json").exists():report["case_report"]=ref(out/"CASES.json")
            print(json.dumps(dict(stage=name,exit_code=p.returncode)),flush=True);need(p.returncode==0,name+" failed")
            if name=="original-reader-cases":
                value=json.loads(raw(out/(name+".stdout")).decode().splitlines()[-1])
                need(value["schema"]=="hepta.notes-task-info-reader-host.v2" and value["all_pass"] is True and value["cases"]==71 and value["assertions"]==238,"original71/238")
                need(len(value["case_names"])==len(set(value["case_names"]))==71,"old case name closure")
                for key,count,assertions in (("empty_activity",14,59),("first_root_bootstrap",22,116),("taskinfo_stability",12,60)):
                    section=value[key];need(section["cases"]==count and section["assertions"]==assertions and len(set(section["case_names"]))==count,"original "+key)
                need(value["input_mode"]=="synthetic_derived_fixture" and value["input_sha256"]==FIXTURE_SHA and value["phone_operations"]==value["get_child_tasks_calls"]==value["mutation_calls"]==0,"explicit old IO scope")
                report["original_reader_cases"]=value
            elif name=="active-root-cases":
                value=json.loads(raw(out/"CASES.json"))
                need(value["schema"]=="hepta.notes-active-root-reader-cases.v1" and value["all_pass"] is True,"actual active cases")
                need(value["cases"]==len(value["case_names"])==len(set(value["case_names"]))==len(names) and set(value["case_names"])==set(names),"exact active case closure")
                need(value["maximum_frame_ms"]==1500 and value["maximum_complete_triples"]==3 and value["phone_operations"]==value["back_redispatches"]==0,"original read-only limits")
                need(value["current_569_recovery_claimed"] is False and value["cleanup_proof_produced"] is False and value["original_569_full_taskinfo_reconstructed"] is False,"authority boundary")
                report["active_cases"]=dict(cases=value["cases"],assertions=value["assertions"],all_pass=value["all_pass"],case_names=value["case_names"])
            elif name=="original-private-cases":
                value=json.loads(raw(out/(name+".stdout")).decode().splitlines()[0]);need(value["passed"] is True and value["cases"]==47 and value["assertions"]==449,"original private47/449");report["original_private_cases"]=value
        report["all_pass"]=True
    except BaseException as error:report["error"]=type(error).__name__+": "+str(error)
    finally:
        report["source_inputs_after"]=[ref(p) for p in sources];report["compile_inputs_after"]=[ref(p) for p in inputs]
        report["private_compile_inputs_after"]=[ref(p) for p in private_files];report["tools_after"]=[ref(Path(p["path"])) for p in tools]
        report["inputs_unchanged"]=all(report[a]==report[b] for a,b in (("source_inputs_before","source_inputs_after"),("compile_inputs_before","compile_inputs_after"),("private_compile_inputs_before","private_compile_inputs_after"),("tools_before","tools_after")))
        report["all_pass"] = report["all_pass"] and report["inputs_unchanged"];put(out/"RESULT.json",report)
    print(json.dumps(dict(all_pass=report["all_pass"],error=report.get("error"),result=ref(out/"RESULT.json"))),flush=True)
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
