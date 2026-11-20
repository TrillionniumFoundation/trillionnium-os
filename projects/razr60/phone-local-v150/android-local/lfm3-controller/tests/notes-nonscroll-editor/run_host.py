#!/usr/bin/env python3
"""Compile the actual Notes predicate and actual controller/Node projections.

The input JSON files are captured Hepta observations. Android Rect and the outer
observation/window containers are host DTOs, not an Android or phone execution.
The actual Node constructor/label and completionFrame method are extracted
verbatim. No synthetic label, ancestry, or body is supplied to a positive case.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

PACKAGE = "org.trillionnium.hepta.local"
PREFIX = Path("src/org/trillionnium/hepta/local")
TEST = Path("tests/notes-nonscroll-editor")
JAVA = ["NotesCompletionEvidence.java", "LocalTaskController.java", "PhoneObservation.java",
        "ObservedChildText.java", "ObservedTargetLabels.java", "ObservedScrollActions.java", "ObservedImeEnter.java"]
FIXTURES = ["v67-after.json", "v67-readiness-2.json", "v67-readiness-3.json", "v67-readiness-4.json", "v66-scrollable.json"]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def meta(path):
    path = Path(path).absolute()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha(data), "mode": path.stat().st_mode & 0o777}

def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    with path.open("xb") as stream:
        stream.write(data)

def save(path, obj):
    write(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n")

def extract(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError("extraction anchors must be unique")
    first = source.index(start)
    last = source.index(end, first)
    return source[first:last]

def lit(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        return str(value)
    return json.dumps(value, ensure_ascii=True)

def generated_fixtures(source, out):
    descriptors = json.loads((source / TEST / "fixtures/DESCRIPTORS.json").read_text())
    body = ["package " + PACKAGE + ";", "import java.util.*;", "final class CapturedNotesFixtures {"]
    body.append("static final String[] NAMES={" + ",".join(lit(x) for x in FIXTURES) + "};")
    body.append("static final String[] BODIES={" + ",".join(lit(descriptors[x]["body"]) for x in FIXTURES) + "};")
    summary = []
    for index, name in enumerate(FIXTURES):
        path = source / TEST / "fixtures" / name
        raw = path.read_bytes()
        obj = json.loads(raw)
        desc = descriptors[name]
        if desc["sha256"] != sha(raw):
            raise ValueError("actual fixture bytes changed")
        if obj["nodes_truncated"] is not False or obj["collection"]["truncation_reasons"] != []:
            raise ValueError("positive fixture is incomplete")
        if any(obj["collection"][k] != 0 for k in ["pending_nodes_at_stop", "child_slots_omitted_by_traversal_limit",
                "nodes_omitted_by_node_limit", "nodes_omitted_by_text_limit"]):
            raise ValueError("positive fixture has an omitted subtree or node")
        body.append("static PhoneObservation captured" + str(index) + "(){ List<PhoneObservation.Node> n=new ArrayList<>();")
        for node in obj["nodes"]:
            # These editor frames have no derived content. Reject such a change
            # instead of fabricating the private Result provenance constructor.
            if node.get("child_text", "") or node.get("child_text_sources", []):
                raise ValueError("fixture needs an explicit derived-text adapter")
            status = node.get("child_text_status", "not_applicable")
            if status not in ("empty", "not_applicable"):
                raise ValueError("unexpected child-text status")
            child = "new ObservedChildText.Result(\"\"," + lit(status) + "," + lit(node.get("child_text_truncated", False)) + "," + str(node.get("child_text_visited", 0)) + ",Collections.<ObservedChildText.Source>emptyList())"
            position = node.get("native_tree_position", {})
            if position.get("source") != "same_bounded_accessibility_traversal":
                raise ValueError("actual traversal provenance required")
            ime = node["ime_enter"]
            if type(ime["observed"]) is not bool or type(ime["present"]) is not bool:
                raise ValueError("fixture IME facts must be typed")
            ime_java = ("ObservedImeEnter.UNKNOWN" if not ime["observed"] else
                        "ObservedImeEnter.present(" + lit(ime["action_label"]) + ")" if ime["present"] else
                        "ObservedImeEnter.ABSENT")
            args = [lit(node["id"]),lit(node["package"]),lit(node["class_name"]),lit(node.get("view_id", "")),
                    lit(node.get("text", "")),lit(node.get("description", "")),
                    "new Rect(" + ",".join(map(str, node["bounds"])) + ")"]
            args += [lit(node.get(k, default)) for k, default in [("clickable",False),("editable",False),("scrollable",False),
                    ("enabled",True),("focused",False),("password",False)]]
            args += [child,"ObservedScrollActions.observed(Arrays.asList(" + ",".join(lit(x) for x in node["scroll_directions"]) + "))",
                     ime_java,lit(node.get("input_text_sha256")),lit(node.get("submit_available", False)),
                     lit(node.get("node_app_tree_sha256")),lit(position.get("path")),lit(position.get("parent_class"))]
            body.append("n.add(new PhoneObservation.Node(" + ",".join(args) + "));")
        win = obj["window"]
        args = [lit(obj["observation_id"]),lit(obj["package"]),str(obj["window_id"]),lit(obj["background_session"]["generation"]),
                lit(obj["nodes_truncated"]),"new PhoneObservation.Window(" + ",".join([lit(win["display_id"]),lit(win["type"]),lit(win["metadata_status"])]) + ")","n"]
        body.append("return new PhoneObservation(" + ",".join(args) + ");}")
        summary.append({"name":name,"observation_id":obj["observation_id"],"bytes":len(raw),"sha256":sha(raw),
                        "nodes":len(obj["nodes"]),"body_sha256":sha(desc["body"].encode()),"raw_capture":True})
    body.append("static PhoneObservation get(int i){switch(i){" + "".join("case " + str(i) + ":return captured" + str(i) + "();" for i in range(len(FIXTURES))) + "default:throw new IllegalArgumentException();}}}")
    write(out / "CapturedNotesFixtures.java", "\n".join(body) + "\n")
    return summary

def stage(label, argv, output):
    started = time.monotonic_ns()
    with (output / (label + ".stdout")).open("xb") as stdout, (output / (label + ".stderr")).open("xb") as stderr:
        proc = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=90, check=False)
    return {"name":label,"argv":argv,"exit_code":proc.returncode,"elapsed_ns":time.monotonic_ns()-started,
            "stdout":meta(output/(label+".stdout")),"stderr":meta(output/(label+".stderr"))}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    ap.add_argument("--java-home",required=True,type=Path)
    args=ap.parse_args()
    source=args.source.resolve(); output=args.output.absolute(); output.mkdir(parents=True,exist_ok=False)
    java=args.java_home.resolve()/"bin/java"
    # Use the compiler module so a JDK image without a javac launcher remains
    # usable. Java 8 source/bytecode is explicit; this is not an Android API build.
    tools=[java,args.java_home.resolve()/"lib/modules"]
    rels=[PREFIX/x for x in JAVA]
    rels += [TEST/"run_host.py",TEST/"NotesNonScrollEditorHostTest.java",TEST/"PreviousNotesEditorReplay.java",
             TEST/"fixtures/DESCRIPTORS.json",TEST/"fixtures/PROVENANCE.json",TEST/"fixtures/previous-v67-NotesCompletionEvidence.java.txt",
             TEST/"fixtures/previous-v67-completionFrame.java.txt"]
    rels += [TEST/"fixtures"/x for x in FIXTURES]
    paths=[source/x for x in rels]+tools
    before=[meta(x) for x in paths]; tools_before=[meta(x) for x in tools]
    result={"schema":"hepta.notes-nonscroll-editor-host-gate.v1","all_pass":False,
            "input_before":before,"tools_before":tools_before,"stages":[],
            "android_execution":False,"phone_execution":False,"business_completion_verified":False,
            "phone_operations":0,"model_executed":False,
            "qualification":"Host replay of actual captured fields, actual pure predicate and verbatim projection; platform DTO boundary only.",
            "compiler_contract":"jdk.compiler module, -source 8 -target 8; final Android source build is separate"}
    try:
        generated=output/"generated";generated.mkdir()
        phone=(source/PREFIX/"PhoneObservation.java").read_text()
        node=extract(phone,"    public static final class Node {","        JSONObject json() throws JSONException {\n            JSONObject value=new JSONObject();")
        controller=(source/PREFIX/"LocalTaskController.java").read_text()
        bridge=extract(controller,"    private static NotesCompletionEvidence.Frame completionFrame(PhoneObservation o){","    private static NotesCreateWorkflow.Observation workflowObservation")
        original_bridge=(source/TEST/"fixtures/previous-v67-completionFrame.java.txt").read_text()
        dto='''package org.trillionnium.hepta.local;
import java.util.*;
final class Rect { final int left,top,right,bottom; Rect(int l,int t,int r,int b){left=l;top=t;right=r;bottom=b;} Rect(Rect r){this(r.left,r.top,r.right,r.bottom);} }
final class PhoneObservation {
 final String id,packageName,backgroundGeneration; final int windowId; final boolean nodesTruncated;
 final Window windowMetadata; final List<Node> nodes;
 static final class Window { final Integer displayId,type;final String status;Window(Integer d,Integer t,String s){displayId=d;type=t;status=s;} }
 PhoneObservation(String i,String p,int w,String g,boolean t,Window m,List<Node> n){id=i;packageName=p;windowId=w;backgroundGeneration=g;nodesTruncated=t;windowMetadata=m;nodes=n;}
'''
        write(generated/"PhoneObservation.java",dto+node+"    }\n}\n")
        for name,method in [("CurrentCompletionBridge",bridge),("PreviousCompletionBridge",original_bridge)]:
            write(generated/(name+".java"),"package "+PACKAGE+";\nfinal class "+name+"{\n"+method+"static NotesCompletionEvidence.Frame copy(PhoneObservation o){return completionFrame(o);}\n}\n")
        fixtures=generated_fixtures(source,generated)
        result["generated_files"]={p.name:meta(p) for p in sorted(generated.glob("*.java"))}
        extraction={"schema":"hepta.notes-nonscroll-editor-extraction.v1","actual_methods_verbatim":True,
                    "node_constructor_and_label":{"source":meta(source/PREFIX/"PhoneObservation.java"),"bytes":len(node.encode()),"sha256":sha(node.encode())},
                    "completion_frame":{"source":meta(source/PREFIX/"LocalTaskController.java"),"bytes":len(bridge.encode()),"sha256":sha(bridge.encode())},
                    "previous_completion_frame":meta(source/TEST/"fixtures/previous-v67-completionFrame.java.txt"),"fixtures":fixtures,
                    "host_boundary":"Rect and outer frame/window DTOs only. Node constructors and label are verbatim. Empty child Result source-completeness metadata is not reconstructed or used by editor()."}
        save(output/"EXTRACTION.json",extraction)
        common=[source/PREFIX/x for x in JAVA if x not in ("NotesCompletionEvidence.java","LocalTaskController.java","PhoneObservation.java")]
        common += [generated/"PhoneObservation.java",generated/"CapturedNotesFixtures.java"]
        for kind,notes,bridge_name,test_name in [
                ("current",source/PREFIX/"NotesCompletionEvidence.java","CurrentCompletionBridge","NotesNonScrollEditorHostTest"),
                ("previous",source/TEST/"fixtures/previous-v67-NotesCompletionEvidence.java.txt","PreviousCompletionBridge","PreviousNotesEditorReplay")]:
            dest=output/(kind+"-sources");dest.mkdir();actual_notes=dest/"NotesCompletionEvidence.java";write(actual_notes,notes.read_bytes())
            classes=output/(kind+"-classes");classes.mkdir()
            argv=[str(java),"-m","jdk.compiler/com.sun.tools.javac.Main","-encoding","UTF-8","-source","8","-target","8","-Xlint:-options","-d",str(classes)]
            argv += list(map(str,common+[actual_notes,generated/(bridge_name+".java"),source/TEST/(test_name+".java")]))
            compiled=stage(kind+"-compile",argv,output);result["stages"].append(compiled)
            if compiled["exit_code"]!=0:raise RuntimeError(kind+" compilation failed")
            executed=stage(kind+"-cases",[str(java),"-cp",str(classes),PACKAGE+"."+test_name],output);result["stages"].append(executed)
            if executed["exit_code"]!=0:raise RuntimeError(kind+" cases failed")
            cases=json.loads((output/(kind+"-cases.stdout")).read_text())
            if cases["all_pass"] is not True or len(cases["case_names"])!=cases["cases"] or len(set(cases["case_names"]))!=cases["cases"]:
                raise ValueError("case receipt incomplete")
            filename="CASES.json" if kind=="current" else "PREVIOUS-CASES.json"
            save(output/filename,cases);result["cases" if kind=="current" else "previous"]=cases
        result["cases_file"]=meta(output/"CASES.json")
        result["previous_cases_file"]=meta(output/"PREVIOUS-CASES.json")
        result["extraction_file"]=meta(output/"EXTRACTION.json")
        result["actual_predicate_compiled"]=True
        result["actual_controller_completion_frame_compiled_verbatim"]=True
        result["actual_node_constructors_compiled_verbatim"]=True
        result["all_pass"]=True
    except Exception as error:
        result["error"]={"type":type(error).__name__,"message":str(error)}
    finally:
        result["input_after"]=[meta(x) for x in paths]
        result["tools_after"]=[meta(x) for x in tools]
        result["inputs_unchanged"]=result["input_after"]==before
        result["tools_unchanged"]=result["tools_after"]==tools_before
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"] and result["tools_unchanged"]
        save(output/"RESULT.json",result)
    print(json.dumps({"all_pass":result["all_pass"],"result":meta(output/"RESULT.json")}))
    return 0 if result["all_pass"] else 1

if __name__=="__main__":
    raise SystemExit(main())
