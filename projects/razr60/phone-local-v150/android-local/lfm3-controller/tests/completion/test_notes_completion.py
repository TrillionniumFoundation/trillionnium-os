#!/usr/bin/env python3
"""Local pure-provider regression; reads saved observations, never a device.

The positive save-list item is explicitly synthetic: this historical task never
left/reopened its editor. Actual editor bytes, input SHA, empty list and category
popup are loaded directly from the pinned historical collection.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parents[1]
PACKAGE = "org.trillionnium.hepta.local"
SOURCE = WORKSPACE / "src/org/trillionnium/hepta/local/NotesCompletionEvidence.java"
LABELS = WORKSPACE / "src/org/trillionnium/hepta/local/ObservedTargetLabels.java"
CASE = ROOT / "fixtures"
PINS = {
    "RESULT.json": "1fddf3c7cae42bf27acc36ef73e2425432deb037a25b44b5682faccac70d93a4",
    "final-current-notes.xml": "8dab056051467bf29fd37f42a0793450cd631d7ac965c49a2c83d435d34249f2",
    "evidence/task/step-01-after.json": "b8bef9319b298ac8c70dae0dd46d1e1e845712e0166e0f8cb9baf870b6e6fc9d",
    "evidence/task/step-02-after.json": "9f0d410acdee804e5611d6d68dcc948df2ba0852eb85a8ca533ba46f0d5fc013",
    "evidence/task/step-03-after.json": "9701f8e6de02f3b65e4c5e7dc68bc252532f7976b18df901961a588d183fbd0b",
    "evidence/task/step-04-after.json": "cd969e06025ae0a7d7ae5e76c22b7b3f7265808a79afb67c17f9af7d3755dba9",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def js(value):
    return "null" if value is None else json.dumps(value, ensure_ascii=False)


def boolean(value):
    return "true" if value else "false"


def node_java(node, package):
    text = node.get("text", "")
    description = node.get("description", "")
    # Mirrors the existing bridge's complete-label condition. The raw native
    # collection omits per-node package; test adapters use the observed root
    # package. For the actual editor, final XML independently confirms package,
    # EditText/editable role, text and bounds. No new device result is asserted.
    if text.strip():
        label = text
    elif description.strip():
        label = description
    elif node.get("child_text_status") == "derived" and node.get("child_text_truncated") is False:
        label = node.get("child_text", "")
    else:
        label = ""
    strings = [node["id"], package, text, label, node.get("view_id", ""), node.get("input_text_sha256")]
    bounds = "new int[]{" + ",".join(map(str, node["bounds"])) + "}"
    flags = [node.get("editable") is True, node.get("clickable") is True,
             node.get("scrollable") is True, node.get("enabled", True) is True,
             node.get("password") is True]
    return "new Node(" + ",".join([*(js(v) for v in strings), bounds, *(boolean(v) for v in flags)]) + ")"


def frame_java(name, frame):
    window = frame["window"]
    assert frame["window_id"] == window["window_id"]
    nodes = ",\n".join(node_java(n, frame["package"]) for n in frame["nodes"])
    return ("static Frame " + name + "(){return new Frame("
            + ",".join([js(frame["observation_id"]), js(frame["package"]), str(frame["window_id"]),
                          str(window["display_id"]), "null", str(window["type"]),
                          boolean(window["metadata_status"] == "observed"), boolean(frame["nodes_truncated"])])
            + ",Arrays.asList(\n" + nodes + "));}\n")


TEST = r'''
package org.trillionnium.hepta.local;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.trillionnium.hepta.local.NotesCompletionEvidence.*;

public final class NotesCompletionEvidenceHostTest {
    static final String P=NotesCompletionEvidence.NOTES;
    static final String BODY=__BODY__;
    static final String RAW=__RAW__;
    static final String GEN="97d9600f-e081-465c-9e6e-62651e09806b";
    static final int UID=__UID__;
    static int checks,groups,last;
    static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    static void group(String name){groups++;System.out.println(name+" "+(checks-last));last=checks;}
    static String repeat(String s,int n){StringBuilder b=new StringBuilder();for(int i=0;i<n;i++)b.append(s);return b.toString();}
    static String hash(String value){try{StringBuilder b=new StringBuilder();for(byte c:MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)))b.append(String.format(Locale.ROOT,"%02x",c&255));return b.toString();}catch(Exception e){throw new AssertionError(e);}}
    static Installed installed(){Map<String,String> a=new LinkedHashMap<String,String>();a.put("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256);return new Installed(P,UID,a);}
    static Frame nodes(Frame f,List<Node> n){return new Frame(f.observationId,f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,n);}
    static Frame domain(Frame f,int display,String gen,int type,boolean observed,boolean truncated){return new Frame(f.observationId,f.packageName,f.windowId,display,gen,type,observed,truncated,f.nodes);}
    static Node with(Node n,String text,String label,String sha,boolean editable,boolean clickable,boolean enabled,boolean password){return new Node(n.id,n.packageName,text,label,n.viewId,sha,n.bounds(),editable,clickable,n.scrollable,enabled,password);}
    static Node bodyNode(Frame f){for(Node n:f.nodes)if(n.editable)return n;throw new AssertionError("missing fixture field");}
    static Frame replace(Frame f,Node prior,Node replacement){List<Node> a=new ArrayList<Node>(f.nodes);a.set(a.indexOf(prior),replacement);return nodes(f,a);}
    static Frame raw(Frame f,String s){Node n=bodyNode(f);return replace(f,n,with(n,s,s,hash(s),true,true,true,false));}
    static BodyEvidence editor(Frame f){return NotesCompletionEvidence.editor(f,BODY,installed());}
    static Node item(String id,String text,String label){return new Node(id,P,text,label,P+":id/synthetic_saved_item",null,new int[]{80,800,1100,1000},false,true,false,true,false);}
    static Frame listFrame(String body){List<Node> n=new ArrayList<Node>();for(Node x:actualEmpty().nodes)if(!(P+":id/no_note_text").equals(x.viewId))n.add(x);n.add(item("n20",body,body));return nodes(actualEmpty(),n);}
    static ListEvidence list(Frame f){return NotesCompletionEvidence.list(f,BODY);}
    __FRAMES__
    public static void main(String[] ignored){
        Frame actual=actualEditor();
        BodyEvidence e=editor(actual);
        check(e.matched&&!e.rawExact&&!e.persistentBytesVerified,"actual 40LF must be matched but never raw-exact/storage-proof");
        check("body_plus_observed_40_lf".equals(e.matchRule)&&e.trailingLfCount==40,"actual exact 40LF rule");
        check("948e15865a2673e04b796abbf4ae1c0567a3a7fb93f24cb3d9cbc6bb26b4c470".equals(e.rawTextSha256),"actual complete input SHA");
        check("f5d0f260ab53f4422d6f902e5ed78563aeca3dd697c59941ef104368b146a4c7".equals(e.bodySha256),"owner body SHA");
        check(editor(actualTerminal()).matched&&!list(actualTerminal()).matched,"actual terminal still editor, not a saved/reopened list");
        check(!list(actualEmpty()).matched,"actual empty All Notes cannot prove saved item");
        check(!list(actualPopup()).matched,"actual category popup is not real list");
        check(!list(actual).matched,"actual marker-bearing editor cannot become a list");
        group("actual_saved_observation_fixtures");

        e=editor(raw(actual,BODY));check(e.matched&&e.rawExact&&e.trailingLfCount==0&&!e.persistentBytesVerified,"exact visible body still not DB bytes");
        check(editor(raw(actual,BODY+repeat("\n",40))).matched,"exact forty only");
        for(String s:new String[]{BODY+repeat("\n",39),BODY+repeat("\n",41),BODY+repeat("\r\n",40),BODY+" ",BODY+"\t",BODY+"\u00a0","\n"+BODY,BODY+"x",BODY+repeat("\n",40)+" "}){
            e=editor(raw(actual,s));check(!e.matched&&!e.rawExact&&hash(s).equals(e.rawTextSha256),"unsupported form must keep raw SHA: "+s.length());
        }
        Node n=bodyNode(actual);Frame wrongHash=replace(actual,n,with(n,n.text,n.label,hash(BODY),true,true,true,false));
        check(!editor(wrongHash).matched&&"complete_input_sha_does_not_match_observed_text".equals(editor(wrongHash).missing),"full input hash cannot be replaced by body hash");
        check(!editor(replace(actual,n,with(n,n.text,n.label,null,true,true,true,false))).matched,"missing full input SHA");
        check(!editor(raw(actual,BODY+(char)0)).matched,"NUL raw difference rejected");
        check(!NotesCompletionEvidence.editor(actual,"\ud800",installed()).matched,"invalid owner Unicode rejected without normalization");
        group("raw_forms_and_complete_input_hash");

        Map<String,String> hashes=new LinkedHashMap<String,String>();hashes.put("base",repeat("a",64));
        Installed changed=new Installed(P,UID,hashes);
        check(!NotesCompletionEvidence.editor(actual,BODY,changed).matched,"40LF rejected on changed APK");
        check(NotesCompletionEvidence.editor(raw(actual,BODY),BODY,changed).matched,"raw exact does not need historical padding pin");
        hashes.put("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256);hashes.put("split:x",repeat("b",64));
        check(!NotesCompletionEvidence.editor(actual,BODY,new Installed(P,UID,hashes)).matched,"40LF rejected with a split APK");
        check(NotesCompletionEvidence.editor(raw(actual,BODY),BODY,new Installed(P,UID,hashes)).matched,"valid split identity allows exact observed body");
        hashes.remove("base");check(!NotesCompletionEvidence.editor(raw(actual,BODY),BODY,new Installed(P,UID,hashes)).matched,"split cannot impersonate base");
        check(!NotesCompletionEvidence.editor(actual,BODY,new Installed("other.package",UID,installed().apkHashes)).matched,"wrong installed package");
        check(!NotesCompletionEvidence.editor(actual,BODY,new Installed(P,9999,installed().apkHashes)).matched,"non-app UID");
        check(!NotesCompletionEvidence.editor(actual,BODY,new Installed(P,90000,installed().apkHashes)).matched,"unsupported UID range");
        check(!NotesCompletionEvidence.editor(actual,BODY,null).matched,"missing installed facts");
        group("installed_identity_and_single_base_padding_pin");

        check(editor(domain(actual,4,GEN,1,true,false)).matched,"actual body rule supports scoped VD observations");
        for(Frame f:Arrays.asList(domain(actual,0,GEN,1,true,false),domain(actual,4,null,1,true,false),domain(actual,4,"not-a-generation",1,true,false),domain(actual,-1,null,1,true,false),domain(actual,0,null,2,true,false),domain(actual,0,null,1,false,false),domain(actual,0,null,1,true,true))){check(!editor(f).matched,"invalid metadata/domain cannot verify body");check(!list(f).matched,"invalid metadata/domain cannot verify list");}
        List<Node> two=new ArrayList<Node>(actual.nodes);two.add(new Node("n99",P,n.text,n.label,"",n.inputTextSha256,n.bounds(),true,true,false,true,false));
        check(!editor(nodes(actual,two)).matched,"second enabled editable blocks unique body");
        check(!editor(replace(actual,n,with(n,n.text,n.label,n.inputTextSha256,true,true,false,false))).matched,"disabled editor rejected");
        check(!editor(replace(actual,n,with(n,n.text,n.label,n.inputTextSha256,true,true,true,true))).matched,"password editor rejected");
        List<Node> noContext=new ArrayList<Node>();for(Node x:actual.nodes)if(!"NoteEditor".equals(x.text))noContext.add(x);
        check(!editor(nodes(actual,noContext)).matched,"matching text alone is not editor context");
        group("metadata_domains_and_editor_roles");

        Frame validList=listFrame(BODY);ListEvidence l=list(validList);
        check(l.matched&&"n20".equals(l.item.nodeId),"synthetic actual executable item has whole body");
        check(BODY.equals(l.item.fullLabel)&&ObservedTargetLabels.project(BODY).equals(l.item.label)&&!BODY.equals(l.item.label),"whole text and action label remain distinct");
        check(list(domain(validList,5,GEN,1,true,false)).matched,"list can be scoped to VD");
        Node old=validList.nodes.get(validList.nodes.size()-1);
        check(list(replace(validList,old,item("n20","",BODY))).matched,"complete original label on executable node");
        check(!list(replace(validList,old,item("n20",BODY.substring(0,12),BODY.substring(0,12)))).matched,"marker/prefix is not whole body");
        check(!list(replace(validList,old,item("n20",BODY,""))).matched,"unknown/incomplete full action label cannot identify item");
        check(!list(replace(validList,old,item("n20",BODY+"x",BODY))).matched,"different own text cannot hide behind matching label");
        for(Node bad:Arrays.asList(with(old,old.text,old.label,null,false,false,true,false),with(old,old.text,old.label,null,false,true,false,false),with(old,old.text,old.label,null,false,true,true,true),new Node(old.id,"other.package",BODY,BODY,old.viewId,null,old.bounds(),false,true,false,true,false),new Node(old.id,P,BODY,BODY,old.viewId,null,new int[]{0,3000,100,3100},false,true,false,true,false)))check(!list(replace(validList,old,bad)).matched,"wrong item authority/identity/bounds");
        List<Node> duplicate=new ArrayList<Node>(validList.nodes);duplicate.add(item("n21",BODY,BODY));check(!list(nodes(validList,duplicate)).matched,"ambiguous same-body items");
        duplicate=new ArrayList<Node>(validList.nodes);duplicate.add(bodyNode(actual));check(!list(nodes(validList,duplicate)).matched,"any editable blocks list");
        check(!NotesCompletionEvidence.list(listFrame(repeat("a",95)),repeat("a",95)).matched,"long text cannot prove complete list item");
        check(!NotesCompletionEvidence.list(listFrame("任务…"),"任务…").matched,"ellipsis does not establish unshortened text");
        String other="明天带伞并买苹果。";check(NotesCompletionEvidence.list(listFrame(other),other).matched,"no marker/name/task-ID convention in provider");
        Frame header=listFrame("所有笔记");Node hi=header.nodes.get(header.nodes.size()-1);header=replace(header,hi,new Node(hi.id,P,hi.text,hi.label,P+":id/clickable_layout",null,hi.bounds(),false,true,false,true,false));
        check(!NotesCompletionEvidence.list(header,"所有笔记").matched,"observed page header cannot impersonate a saved note");
        group("whole_body_executable_item_without_marker_or_ancestry_inference");

        List<Node> split=new ArrayList<Node>();for(Node x:validList.nodes)if(x!=old)split.add(x);
        split.add(item("n20","",""));split.add(new Node("n21",P,BODY,BODY,"",null,new int[]{100,820,900,980},false,false,false,true,false));
        check(!list(nodes(validList,split)).matched,"child geometry does not donate text to clickable parent");
        split.add(item("n21",BODY,BODY));check(!list(nodes(validList,split)).matched,"duplicate IDs fail closed");
        check(!editor(null).matched&&!list(null).matched,"null frame is missing");
        check(!NotesCompletionEvidence.list(validList,null).matched,"null body is missing");
        List<Node> tooMany=new ArrayList<Node>();for(int i=0;i<201;i++)tooMany.add(item("n"+i,"",""));check(!list(nodes(validList,tooMany)).matched,"node bound retained");
        int[] b={80,800,1100,1000};Node copied=new Node("n77",P,BODY,BODY,"",null,b,false,true,false,true,false);b[0]=9000;check(copied.left==80,"node copies mutable bounds");
        int[] returned=copied.bounds();returned[0]=7000;check(copied.left==80,"bounds accessor is defensive");
        List<Node> mutable=new ArrayList<Node>(validList.nodes);Frame frozen=nodes(validList,mutable);mutable.clear();check(list(frozen).matched,"Frame copies node list");
        boolean immutable=false;try{frozen.nodes.clear();}catch(UnsupportedOperationException expected){immutable=true;}check(immutable,"frame nodes cannot mutate");
        hashes=new LinkedHashMap<String,String>();hashes.put("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256);Installed pinned=new Installed(P,UID,hashes);hashes.clear();check(NotesCompletionEvidence.editor(actual,BODY,pinned).matched,"Installed copies hashes");
        immutable=false;try{pinned.apkHashes.clear();}catch(UnsupportedOperationException expected){immutable=true;}check(immutable,"installed map cannot mutate");
        group("malformed_inputs_and_immutable_evidence");
        System.out.println("PASS "+groups+" groups "+checks+" checks");
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java", default="java")
    parser.add_argument("--release8", action="store_true")
    parser.add_argument("--report", type=Path, default=ROOT / "VALIDATION.json")
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixtures = {}
    for name, expected in PINS.items():
        raw = (CASE / name).read_bytes()
        assert sha(raw) == expected, (name, "fixture differs")
        fixtures[name] = {"bytes": len(raw), "sha256": expected}
    result = json.loads((CASE / "RESULT.json").read_text())
    body = result["plan"]["body"]
    assert len(body) == 39 and len(body.encode()) == 69 and "\n" not in body
    actual = json.loads((CASE / "evidence/task/step-03-after.json").read_text())
    raw = next(n["text"] for n in actual["nodes"] if n.get("editable"))
    assert raw == body + "\n" * 40
    xml = ET.parse(CASE / "final-current-notes.xml").getroot()
    actual_xml = [n for n in xml.iter("node") if n.get("text") == raw]
    assert len(actual_xml) == 1
    assert actual_xml[0].get("class") == "android.widget.EditText"
    assert actual_xml[0].get("package") == "com.motorola.stylus"
    assert actual_xml[0].get("enabled") == "true" and actual_xml[0].get("password") == "false"
    installed = result["installed_identity_before"]["notes"]
    assert installed["package"] == "com.motorola.stylus" and len(installed["apks"]) == 1
    assert installed["apks"][0]["sha256"] == "0e1a52a937c04ec8df380bff3750ce4b345fa0d8d33683e5ae8aa08e70e94017"
    methods = "\n".join(frame_java(method, json.loads((CASE / name).read_text())) for method, name in (
        ("actualEmpty", "evidence/task/step-01-after.json"),
        ("actualPopup", "evidence/task/step-02-after.json"),
        ("actualEditor", "evidence/task/step-03-after.json"),
        ("actualTerminal", "evidence/task/step-04-after.json")))
    java = TEST.replace("__BODY__", js(body)).replace("__RAW__", js(raw)).replace("__UID__", str(installed["uid"])).replace("__FRAMES__", methods)
    version = subprocess.run([args.java, "-version"], text=True, capture_output=True, check=True)
    with tempfile.TemporaryDirectory(prefix="hepta-pure-notes-") as temporary:
        directory = Path(temporary)
        harness = directory / "NotesCompletionEvidenceHostTest.java"
        harness.write_text(java)
        classes = directory / "classes"
        classes.mkdir()
        compile_argv = [args.java, "-m", "jdk.compiler/com.sun.tools.javac.Main", *(["--release", "8"] if args.release8 else ["-source", "8", "-target", "8"]),
                        "-Xlint:all,-options", "-Werror", "-encoding", "UTF-8", "-d", str(classes),
                        str(SOURCE), str(LABELS), str(harness)]
        compile_result = subprocess.run(compile_argv, text=True, capture_output=True, check=True)
        run_argv = [args.java, "-cp", str(classes), PACKAGE + ".NotesCompletionEvidenceHostTest"]
        run_result = subprocess.run(run_argv, text=True, capture_output=True, check=True)
        assert run_result.stdout.splitlines()[-1].startswith("PASS 6 groups ")
        report = {"schema": "hepta.notes-completion-provider-local-check.v1", "passed": True,
                  "scope": "Pure actual provider/observation check; no Android runtime or device qualification.",
                  "java8_api_release": args.release8,
                  "java": (version.stdout + version.stderr).strip(),
                  "source": {"path": str(SOURCE), "bytes": SOURCE.stat().st_size, "sha256": sha(SOURCE.read_bytes())},
                  "test": {"path": str(Path(__file__).resolve()), "sha256": sha(Path(__file__).read_bytes())},
                  "unchanged_dependency": {"path": str(LABELS), "sha256": sha(LABELS.read_bytes())},
                  "fixture_root": str(CASE), "fixtures": fixtures,
                  "actual_fixture_assertion": "Historical raw editor matches only the pinned 40LF form; raw_exact false, storage bytes unverified, empty list/popup/editor cannot qualify a saved item.",
                  "synthetic_positive_scope": "The complete-body clickable list item is synthetic; no saved/reopened item exists in this historical task. No native or whole-task verification is simulated by this pure provider test.",
                  "package_adapter_limit": "Native observation JSON omits node package. Fixtures supply the real root package; actual editor XML independently confirms its package, role and raw text. Production bridge must read each original Node.packageName.",
                  "commands": [compile_argv, run_argv], "compile_stdout": compile_result.stdout,
                  "compile_stderr": compile_result.stderr, "stdout": run_result.stdout, "stderr": run_result.stderr,
                  "generated_fixture_harness_sha256": sha(java.encode()),
                  "compiled_class_sha256": {str(p.relative_to(classes)): sha(p.read_bytes()) for p in sorted(classes.rglob("*.class"))},
                  "no_phone_or_remote_operation": True, "no_frozen_source_or_old_result_modified": True}
    for name, expected in PINS.items():
        assert sha((CASE / name).read_bytes()) == expected, (name, "fixture changed during check")
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(run_result.stdout, end="")
    print(json.dumps({"report": str(args.report), "bytes": args.report.stat().st_size, "sha256": sha(args.report.read_bytes())}))


if __name__ == "__main__":
    main()
