#!/usr/bin/env python3
"""Actual pixel/census producer and full DTO, with explicit host SDK/clock/file IO."""
import argparse,hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path
PKG=Path("src/org/trillionnium/hepta/local")
TEST=Path("tests/pixels-native-census")
ANCHORS=[
"    private synchronized TaskAuthorization.Gate authorizationFor(",
"    private synchronized boolean ownsAuthorization(",
"    void requireTaskAuthorization(",

"    private boolean pixelNativeCensusEligible(",
"    private void persistPixelNativeCensus(",
"    private static Map<String,Object> nativeAxIdentity(",
"    private static Map<String,Object> nativeAxCensus(",
"    private static boolean completeNativeObservationGraph(",
"    private boolean nativeObservationRecheckAllowed(",
"    private static final class CaptureIdentity {",
"    private static final class ObservationPairSeal {",
"    private static final class ObservationProduct {",
"    private static final class FrozenObservationWindow {",
"    private static FrozenObservationWindow frozenObservationWindow(",
"    private static ObservationStabilityGate.FrameKey frameKey(",
"    private static void requireSameProfileOwner(",
"    private static final class ObservationEventWatermark {",
"    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,\n            String parentClass,PhoneObservation.Node retained,NodeRef reference,Graph rawOwner){",
"    private static final class NodeRef {",
"    private static String baseNodeSignature(",
"    private static ObservedScrollActions readScrollActions(",
"    private static ObservedImeEnter readImeEnter(",
"    private static String inputTextHash(",
"    private static boolean hasAction(",
"    private static String string(",
"    static String sha(",
"    static String limited(",
"    private static Map<String,Object> ctripSamplingSummary(",
]
NAMES=["PixelNativeCensusEvidence","PhoneObservation","NativeAppEvidence","NativeXiaomiSearchInputObservation","ObservedImeEnter",
"NativeActionSnapshotCheck","NativeCtripFormObservation","ObservedChildText","ObservedTargetLabels","ObservedScrollActions",
"ObservedWindowMetadata","ObservationState","ImeVisibility","ObservationCaptureEvidence","ObservationDiagnostics","ObservationStabilityGate"]
def sha(b):return hashlib.sha256(b).hexdigest()
def ref(p):
 p=Path(p);s=p.lstat()
 if not p.is_file() or p.is_symlink():raise RuntimeError("regular source required")
 b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=s.st_mode&0o777)
def put(p,data):
 if not isinstance(data,(str,bytes)):data=json.dumps(data,sort_keys=True,indent=2)+"\n"
 if isinstance(data,str):data=data.encode()
 with p.open("xb") as f:f.write(data)
 return ref(p)
def module(p,name):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def prepare(source,output):
 h=module(source/"tests/observation-diagnostics/run_host.py","pixel_exact_member_helpers")
 service=(source/PKG/"HeptaAccessibilityService.java").read_text()
 evidence=(source/PKG/"NativeAppEvidence.java").read_text()
 pixel=(source/PKG/"PixelNativeCensusEvidence.java").read_text()
 canonical_members={}
 for anchor in ["    static String fingerprint(","    private static void canonical(","    static String hash("]:
  original=h.body(evidence,anchor);copied=h.body(pixel,anchor)
  if original!=copied:raise RuntimeError("complete original canonical member required: "+anchor)
  canonical_members[anchor]=dict(bytes=len(original.encode()),sha256=sha(original.encode()),whole_body_equal=True)
 template=(source/TEST/"PixelCensusHostTest.template").read_text()
 if template.count("{{ACTUAL_MEMBERS}}")!=1:raise RuntimeError("unique complete production insertion")
 parts={a:h.body(service,a) for a in ANCHORS}
 text=template.replace("{{ACTUAL_MEMBERS}}","\n".join(parts.values()))
 if any(text.count(v)!=1 for v in parts.values()):raise RuntimeError("every complete production member occurs once")
 generated=output/"PixelCensusHostTest.java";put(generated,text)
 paths=[source/PKG/(n+".java") for n in NAMES]
 paths += [source/"src/org/trillionnium/hepta/background"/(n+".java") for n in ("ProfileIdentity","ProfileTarget","WindowOwnership")]
 paths += [source/"tests/qualification-scope/fixtures/android/graphics/Rect.java",
           source/"tests/native-observation-snapshot/SnapshotChecks.java",
           source/"tests/native-observation-snapshot/ObservationEvidenceHost.java",
           source/"tests/native-ax-observation/ActualAxPhoneChecks.java",
           source/"tests/native-ax-consumers/NativeAxConsumersHostTest.java",generated]
 extra=[source/PKG/"HeptaAccessibilityService.java",source/"tests/observation-diagnostics/run_host.py",source/TEST/"run_host.py",source/TEST/"PixelCensusHostTest.template"]
 record=dict(schema="hepta.pixels-native-census-host-extraction.v1",source=str(source),
             actual_production_members=[dict(anchor=a,bytes=len(v.encode()),sha256=sha(v.encode())) for a,v in parts.items()],
             all_complete_members_verbatim=True,canonical_members_byte_equal=canonical_members,generated=ref(generated),
             actual_object_read_authorization_abi=True,original_authorization_resolvers_verbatim=True,
             full_phone_observation_compiled=True,full_real_profile_snapshot_receipt_classes_compiled=True,
             same_traversal_retained_node_and_raw_row_builder_verbatim=True,
             host_ports=["SDK getter values and object identity","synthetic immutable selected owner/profile/generation/authorization values",
                         "elapsed clock","real host PNG encoder and file IO; host owner receipt endpoint"],
             device_read_authority_tested=False,phone_operations=0,model_executed=False,platform_action_available=False)
 return paths,extra,record
def main():
 ap=argparse.ArgumentParser()
 for n in ("source","output","java-home","json-jar"):ap.add_argument("--"+n,type=Path,required=True)
 ap.add_argument("--prepare-only",action="store_true")
 a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
 gen=out/"generated";gen.mkdir();paths,extra,extraction=prepare(source,gen)
 put(out/"EXTRACTION.json",extraction)
 tools=[a.java_home/"bin/javac",a.java_home/"bin/java",a.java_home/"lib/modules",a.java_home/"lib/ct.sym",a.json_jar]
 if ref(a.json_jar)["sha256"]!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":raise RuntimeError("pinned real JSON")
 before=[ref(p) for p in paths+extra];toolbefore=[ref(p) for p in tools]
 if a.prepare_only:
  put(out/"PREPARED.json",dict(schema="hepta.pixels-native-census-prepared.v1",compile_inputs=[ref(p) for p in paths],
        complete_inputs=before,tools=toolbefore,java_executed=False));print(json.dumps(dict(prepared=True,inputs=len(before))));return 0
 classes=out/"classes";classes.mkdir();cp=str(classes)+os.pathsep+str(a.json_jar)
 commands=[
 ("compile",[tools[0],"-J-Xmx512m","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",a.json_jar,"-d",classes,*paths]),
 ("pixel-producer-cases",[tools[1],"-Xmx512m","-Djava.awt.headless=true","-cp",cp,"org.trillionnium.hepta.local.PixelCensusHostTest","new",out/"pixel-originals",out/"PIXEL-CASES.json"]),
 ("original-ax-consumers",[tools[1],"-Xmx512m","-cp",cp,"org.trillionnium.hepta.local.NativeAxConsumersHostTest",out/"AX-CONSUMER-CASES.json"]),
 ("original-phone-branches",[tools[1],"-Xmx512m","-cp",cp,"org.trillionnium.hepta.local.PixelCensusHostTest","original",out/"old-phone-originals",out/"OLD-PHONE-CASES.json"])
 ]
 result=dict(schema="hepta.pixels-native-census-host.v1",all_pass=False,stages=[],inputs_before=before,tools_before=toolbefore,
             source=str(source),phone_operations=0,android_execution=False,model_executed=False,
             platform_action_available=False,business_success_claimed=False,fixture_boundary=extraction["host_ports"])
 env=dict(os.environ);env["PYTHONDONTWRITEBYTECODE"]="1"
 for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
 try:
  for name,cmd in commands:
   start=time.monotonic();r=subprocess.run(list(map(str,cmd)),cwd=out,env=env,capture_output=True,timeout=120)
   row=dict(name=name,argv=list(map(str,cmd)),exit_code=r.returncode,seconds=time.monotonic()-start,
            stdout=put(out/(name+".stdout"),r.stdout),stderr=put(out/(name+".stderr"),r.stderr))
   result["stages"].append(row)
   if r.returncode:raise RuntimeError("actual stage failed: "+name)
  for name in ("PIXEL-CASES","AX-CONSUMER-CASES","OLD-PHONE-CASES"):
   data=json.loads((out/(name+".json")).read_text())
   if data["all_pass"] is not True or len(set(data["case_names"]))!=data["cases"]:raise RuntimeError("complete original named cases")
   result[name]=dict(report=ref(out/(name+".json")),cases=data["cases"],assertions=data["assertions"],names=data["case_names"])
  if result["AX-CONSUMER-CASES"]["cases"]!=61 or result["OLD-PHONE-CASES"]["cases"]!=15:raise RuntimeError("original 61 and 8+7 cases preserved")
  result["all_pass"]=True
 except Exception as e:result["error"]=dict(type=type(e).__name__,message=str(e))
 finally:
  result["inputs_after"]=[ref(p) for p in paths+extra];result["tools_after"]=[ref(p) for p in tools]
  result["inputs_unchanged"]=before==result["inputs_after"];result["tools_unchanged"]=toolbefore==result["tools_after"]
  result["all_pass"]=result["all_pass"] and result["inputs_unchanged"] and result["tools_unchanged"]
  result["extraction"]=ref(out/"EXTRACTION.json");result["compile_inputs"]=[ref(p) for p in paths]
  rr=put(out/"RESULT.json",result)
 print(json.dumps(dict(all_pass=result["all_pass"],error=result.get("error"),stages=[(x["name"],x["exit_code"]) for x in result["stages"]],result=rr)))
 return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
