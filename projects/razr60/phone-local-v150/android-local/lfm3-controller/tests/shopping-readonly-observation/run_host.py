#!/usr/bin/env python3
"""Replay immutable MI DOM/retained-AX fixtures and explicit synthetic complete-native boundaries.

The actual phone records do NOT contain private complete-native snapshots. Those
records cannot grant a native action; graph boundaries are explicitly synthetic.
"""
from __future__ import annotations
import argparse,ast,gzip,hashlib,importlib.util,json,os,pathlib,signal,subprocess,time

FIXTURE_PROVENANCE_SHA="61bcbc7c7073426c2fdeb44507a523515494402262516648ed64396049e359c7"
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
OBSERVER_SHA="05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705"
MAP_SOURCE_SHA="92303867e09343ebcbb3620b9a5850bce683c1d94988d1e534dd272dcaea8647"
MAP_HELPER="""
    /** Host-only Android libcore JSONObject(Map) boundary: preserve null map entries. */
    private static JSONObject androidMap(java.util.Map<String,Object> values)throws Exception{
        JSONObject result=new JSONObject(values);
        for(java.util.Map.Entry<String,Object> e:values.entrySet())
            if(e.getValue()==null)result.put(e.getKey(),JSONObject.NULL);
        return result;
    }
"""
def need(ok,message):
    if not ok:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[2])
    for name in ("output","json-jar","java-home"):p.add_argument("--"+name,type=pathlib.Path,required=True)
    a=p.parse_args()
    for path in [a.source,a.output,a.json_jar,a.java_home]:
        need(path.is_absolute() and not any(x.is_symlink() for x in (path,*path.parents)),"absolute ordinary inputs required")
    need(not a.output.exists(),"new exclusive gate output required")
    inputs={}
    def read(path):
        raw=path.read_bytes();inputs[str(path)]={"bytes":len(raw),"sha256":sha(raw)};return raw
    query=a.source/"tests/web-flight/run_query_host_tests.py"
    tree=ast.parse(read(query).decode())
    values=[ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=="PURE_PATHS" for t in n.targets)]
    need(len(values)==1 and len(values[0])==56,"explicit 56-source query dependency closure required")
    rect="tests/qualification-scope/fixtures/android/graphics/Rect.java"
    native_boundary="tests/native-app/legacy-boundary/NativeAppSession.java"
    native_ctrip="src/org/trillionnium/hepta/local/NativeCtripFlightPage.java"
    paths=[v for v in values[0] if v.startswith("src/") or v in (rect,native_boundary)]
    need(len(paths)==55 and len(set(paths))==55 and rect in paths and native_boundary in paths
         and native_ctrip in paths and set(values[0])-set(paths)=={"tests/web-flight/WebFlightQueryHostTest.java"},
         "53 production inputs including real NativeCtripFlightPage, original Rect and throwing native-session boundary; only retained query test excluded")
    source={v:read(a.source/v) for v in paths}
    test=a.source/"tests/shopping-readonly-observation/ShoppingReadonlyObservationHost.java";read(test)
    quote_test=a.source/"tests/shopping-readonly-observation/ShoppingQuoteHost.java";read(quote_test)
    read(pathlib.Path(__file__).resolve())
    fixture=a.source/"tests/shopping-readonly-observation/fixtures/actual-shopping-v61-r1"
    raw=read(fixture/"PROVENANCE.json");need(sha(raw)==FIXTURE_PROVENANCE_SHA,"actual fixture provenance identity")
    provenance=json.loads(raw);need(provenance["full_native_snapshots_present"] is False,"no historical private native snapshot claim")
    payloads={}
    for row in provenance["files"]:
        raw=read(fixture/row["file"])
        need(len(raw)==row["gzip_bytes"] and sha(raw)==row["gzip_sha256"],"compressed actual fixture identity")
        decoded=gzip.decompress(raw)
        need(len(decoded)==row["bytes"] and sha(decoded)==row["sha256"],"full decoded original fixture identity")
        payloads[row["file"][:-3]]=decoded
    quote_fixture=a.source/"tests/shopping-readonly-observation/fixtures/quote-wire-boundary"
    qmeta=json.loads(read(quote_fixture/"PROVENANCE.json"))
    need(qmeta["sha256"]=="9fb77c909c56534c07ed8c834a475c0150aa7acfd9aaa1da698b45c45803cf4f"
         and qmeta["bytes"]==1405 and qmeta["actual_native_or_IPC_verified"] is False,"original reply template scope")
    qzip=read(quote_fixture/qmeta["file"])
    need(sha(qzip)=="447b1375487da2775a4ef6801587c5c7a4f8b45d0958c59f5a7f945951dfe5ff","exact compressed reply")
    qraw=gzip.decompress(qzip)
    need(len(qraw)==1405 and sha(qraw)==qmeta["sha256"],"exact decoded actual callback template")
    payloads["reply-first.json"]=qraw
    observer=read(fixture/"readonly_dom.js")
    need(len(observer)==14579 and sha(observer)==OBSERVER_SHA,"exact installed helper observer counting formula")
    need(sha(read(a.json_jar))==JSON_SHA,"original pinned host JSON implementation")
    for binary in ("java","javac"):read(a.java_home/"bin"/binary)
    map_path="src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java"
    need(sha(source[map_path])==MAP_SOURCE_SHA,"exact original OWNER compiler boundary source")
    original=source[map_path].decode();needle="new JSONObject(purpose.authorization.evidence())"
    need(original.count(needle)==1,"single Android Map construction boundary")
    adapted=original.replace(needle,"androidMap(purpose.authorization.evidence())")
    at=adapted.rfind("\n}");need(at>=0,"complete source class")
    adapted=adapted[:at]+MAP_HELPER+adapted[at:]
    a.output.mkdir(mode=0o700);(a.output/"fixtures").mkdir();(a.output/"classes").mkdir();(a.output/"adapted").mkdir()
    for name,raw in payloads.items():(a.output/"fixtures"/name).write_bytes(raw)
    patched=a.output/"adapted/WebTaskPurpose.java";patched.write_text(adapted)
    task_domain_path="src/org/trillionnium/hepta/local/WebTaskDomain.java"
    domain_original=source[task_domain_path].decode();domain_needle="new JSONObject(auth.authorization.evidence())"
    need(domain_original.count(domain_needle)==1,"single ordinary domain Android Map construction")
    domain_adapted=domain_original.replace(domain_needle,"androidMap(auth.authorization.evidence())")
    at=domain_adapted.rfind("\n}");need(at>=0,"complete domain class")
    domain_adapted=domain_adapted[:at]+MAP_HELPER+domain_adapted[at:]
    patched_domain=a.output/"adapted/WebTaskDomain.java";patched_domain.write_text(domain_adapted)
    extractor=a.source/"tests/action-worker/run_host_tests.py";read(extractor)
    spec=importlib.util.spec_from_file_location("original_shopping_method_extractor",extractor)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    session_path=a.source/"src/org/trillionnium/hepta/local/WebFlightSession.java"
    session=read(session_path).decode();parts=[];method_identity=[]
    for signature in ("void modelActionOutcome(ActionDecision action,String run,HeptaAccessibilityService.ActionOutcome outcome,",
                      "private static String actionKey(ActionDecision action)","private static final class PendingNavigation",
                      "private static final class CityObservationRetry",
                      "WebShoppingQuote.Completion shoppingCompletion(ActionDecision action,String run,PhoneObservation before,PhoneObservation after,long deadline)"):
        part=module.body(session,signature);parts.append(part)
        method_identity.append({"signature":signature,"bytes":len(part.encode()),"sha256":sha(part.encode())})
    template=read(a.source/"tests/shopping-readonly-observation/ShoppingSessionProjection.template").decode()
    need(template.count("/* EXACT_SHOPPING_SESSION_METHODS */")==1,"single exact source insertion")
    projection=template.replace("/* EXACT_SHOPPING_SESSION_METHODS */","\n\n".join(parts))
    # Exact completion-frame serialization must remain identical to the controller.
    controller=read(a.source/"src/org/trillionnium/hepta/local/LocalTaskController.java").decode()
    quote_source=source["src/org/trillionnium/hepta/local/WebShoppingQuote.java"].decode()
    signature="private static NotesCompletionEvidence.Frame completionFrame(PhoneObservation o)"
    need(module.body(controller,signature)==module.body(quote_source,signature),"controller and typed final-frame serialization differ")
    generated=a.output/"WebShoppingSessionProjection.java";generated.write_text(projection)
    result={"schema":"hepta.shopping-readonly-region-host.v1","all_pass":False,"started_epoch":time.time(),
            "phone_actions":0,"actual_native_snapshot_or_ipc_verified":False,"business_verified":False,
            "native_app_boundary":"Real DTO/domain compile; NativeAppSession constructor and methods all throw in this retained Web-only suite",
            "actual_fixture_provenance":provenance,"quote_wire_template":qmeta,"source_inputs":inputs,"steps":[],
            "exact_session_methods":method_identity,"session_projection_sha256":sha(projection.encode()),"controller_frame_projection_exact":True,
            "host_json_adapter":{"scope":"Android JSONObject(Map) null retention only",
                "source_sha256":MAP_SOURCE_SHA,"adapted_sha256":sha(adapted.encode()),
                "actual_authority_comparator_unchanged":True,
                "domain_source_sha256":sha(source[task_domain_path]),"domain_adapted_sha256":sha(domain_adapted.encode()),
                "reference":"https://android.googlesource.com/platform/libcore/+/refs/heads/main/json/src/main/java/org/json/JSONObject.java"}}
    def run(stage,argv,timeout=120):
        began=time.monotonic()
        proc=subprocess.Popen([str(x) for x in argv],cwd=a.source,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              start_new_session=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"))
        forced=False
        try:out,err=proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            forced=True
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            out,err=proc.communicate(timeout=10)
        (a.output/(stage+".stdout")).write_bytes(out);(a.output/(stage+".stderr")).write_bytes(err)
        row={"stage":stage,"exit_code":proc.returncode,"elapsed_seconds":time.monotonic()-began,"forced":forced,
             "stdout_sha256":sha(out),"stderr_sha256":sha(err),"stdout_bytes":len(out),"stderr_bytes":len(err)}
        result["steps"].append(row)
        need(proc.returncode==0 and not forced,"failed "+stage)
        return out
    try:
        compile_sources=[patched if name==map_path else patched_domain if name==task_domain_path else a.source/name for name in paths]
        run("compile",[a.java_home/"bin/javac","-encoding","UTF-8","-cp",a.json_jar,"-d",a.output/"classes",*compile_sources,test,quote_test,generated])
        raw=run("run",[a.java_home/"bin/java","-Xmx512m","-cp",str(a.output/"classes")+os.pathsep+str(a.json_jar),
                       "org.trillionnium.hepta.local.ShoppingReadonlyObservationHost",a.output/"fixtures"])
        summary=json.loads(raw)
        need(summary.get("all_pass") is True and summary.get("cases")==43 and summary.get("assertions")>=50
             and summary.get("phone_actions")==0 and summary.get("actual_native_snapshot_or_ipc_verified") is False
             and summary.get("business_verified") is False,"exact host scope and case count")
        result["tests"]=summary
        raw=run("quote",[a.java_home/"bin/java","-Xmx512m","-cp",str(a.output/"classes")+os.pathsep+str(a.json_jar),
                         "org.trillionnium.hepta.local.ShoppingQuoteHost",a.output/"fixtures"],timeout=240)
        quote_summary=json.loads(raw)
        need(quote_summary.get("all_pass") is True and quote_summary.get("cases")==28
             and quote_summary.get("actual_native_snapshot_or_ipc_verified") is False
             and quote_summary.get("phone_actions")==0 and quote_summary.get("business_verified") is False,
             "exact quote lifecycle scope and case count")
        result["quote_tests"]=quote_summary
        for name,record in inputs.items():
            raw=pathlib.Path(name).read_bytes();need(len(raw)==record["bytes"] and sha(raw)==record["sha256"],"input changed during gate: "+name)
        result["originals_unchanged"]=True;result["all_pass"]=True
    except BaseException as error:
        result["error"]=type(error).__name__+": "+str(error)
        raise
    finally:
        result["finished_epoch"]=time.time();target=a.output/"RESULT.json"
        target.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
        print(json.dumps({"all_pass":result["all_pass"],"result":str(target),"sha256":sha(target.read_bytes()),
                          "tests":result.get("tests"),"quote_tests":result.get("quote_tests"),"error":result.get("error")},ensure_ascii=False))
if __name__=="__main__":main()
