#!/usr/bin/env python3
"""Execute the actual pure parser against public native App XML fixtures with explicitly recorded redactions.
This is not an Android/installed-App/dispatch/completion test."""
from pathlib import Path
import argparse, hashlib, json, os, runpy, stat, subprocess, time, traceback
SCHEMA="hepta.native-xiaomi-product-compiled-gate.v1"
ORIGINAL_SHARED={
"src/org/trillionnium/hepta/local/NativeAppGoal.java":"c266f1e3e6ca3d86ad2e8f94c78a4263138822e004b5eab64dafdda5fcb653d5",
"src/org/trillionnium/hepta/local/NativeAppEvidence.java":"5ddf2055e23f96efcbc223a17b21d0a7a8e8d0fc2aae788b5d316e7f9eb006b3",
"src/org/trillionnium/hepta/background/ProfileIdentity.java":"7c170e15deb8407a80b4dbcab3564697d2192c63365bb5a062ecba6f3ebbadcd",
"src/org/trillionnium/hepta/background/ProfileTarget.java":"dc531ca250c26ed4db0605f55ed54db6039b5354ec4a6d98c8ba80cf90ade8eb",
"src/org/trillionnium/hepta/background/WindowOwnership.java":"60ccf09113a3463179dfa64cc463eeca363006a30f5518747751420cfc1fb80c",
"src/org/trillionnium/hepta/local/ObservedChildText.java":"56433b62f9c4c895edac441160fcdc4aaee7365586daa4b86863448dc4dd54d5",
"src/org/trillionnium/hepta/local/ObservedTargetLabels.java":"c4e1b1a7ae0223fc7cda90864c6a5c3759a2875bb435359464672bc79465c8ba"}
# The original parser fixtures/cases retain their bytes. The shared Frame DTO now
# has the reviewed typed capture contract; bind the actual current DTO/helper.
SHARED=dict(ORIGINAL_SHARED)
# The original parser fixture and quote-only cases still run with the current owner contract.
SHARED["src/org/trillionnium/hepta/local/NativeAppGoal.java"]="9f823e54fee2862e390df6b86d7a2fc9a02d463c073159dc6f38d6c3a31cb5c4"
SHARED["src/org/trillionnium/hepta/local/NativeAppEvidence.java"]="2f7895c8314959aaafeaa827b1d64f8ce8a8aca62c1de4b7eb82060e567c87be"
SHARED["src/org/trillionnium/hepta/local/ObservationCaptureEvidence.java"]="ba48a7788e308d987b96923aa4f15fd837b4f11a642b484ff02453af93a5035f"
# Preserve the preceding reviewed capture pins; only the complete current
# Frame/capture dependency closure changes. Parser cases/fixtures stay exact.
PRE_FORM_HISTORY_SHARED=dict(SHARED)
# Current profile equality uses the same canonical bytes without Base64 allocations.
SHARED["src/org/trillionnium/hepta/background/ProfileTarget.java"]="268dc50e7d3205cc8fb35883843fbdf8a10cc517f773867a9aae6d00fe07f2fd"
SHARED.update({
  "src/org/trillionnium/hepta/local/NativeAppEvidence.java": "b712a70ab60324fed6ae7f221ac2e4b7b414d57cc6bba50213fa4973de6dbb14",
  "src/org/trillionnium/hepta/local/ObservationCaptureEvidence.java": "b89d0adf0c1cf0b7f4e13375b570b670e78fd5ee64d6a66cdb64cb303a94e155",
  "src/org/trillionnium/hepta/local/NativeCtripFormObservation.java": "1fbedb6ffed519a402e265640fab241cfee655ea47863769cc1538cf53ddd983",
  # Bind the reviewed exact banner-coverage increment; parser cases/fixtures are unchanged.
  "src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java": "de5a0bcd74250ce051595bc9200802ad019a99a69babc18dd9ecc229a6e2afac",
  "src/org/trillionnium/hepta/local/ObservedScrollActions.java": "c31012cf776fbc4177d6c617341d006f4a45ed63df3cfc435f705e515ebbc188",
  "src/org/trillionnium/hepta/local/ObservedImeEnter.java": "e449d61e928dca5a72730b5394fa8f95a7db4dd4006440a95f839818e165acf1"
})
# Preserve the complete preceding pins. The reviewed empty-input-history kinds
# add two real helper dependencies; the parser and all 75 case/fixture bytes stay exact.
PRE_INPUT_HISTORY_SHARED=dict(SHARED)
SHARED.update({
  "src/org/trillionnium/hepta/local/ObservationCaptureEvidence.java": "e7f5ba2bf975f5a39ab47909176912ec1e825c32fb51ac778ee6a76e4abcf39d",
  "src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java": "5e3366ed3d59c94360663058004bcab06fa896f97a120717f90fd8d8f43e33bf",
  "src/org/trillionnium/hepta/local/NativeXiaomiSearchInputObservation.java": "8d1b531b7161d925b71079edffd33fd37b7f720d6fe372f82b8d22ff872e1914"
})
# Keep the complete pre-filled-query closure and verify its exact inverse below.
# Actual javac inputs remain the unchanged current files; parser fixtures stay exact.
PRE_FILLED_QUERY_SHARED=dict(SHARED)
FILLED_QUERY_SHARED={
  "src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java": "b5bbcc3e74f769c94718de560fa476431d0b726997f48b9c4ad094a997d737b2",
  "src/org/trillionnium/hepta/local/NativeXiaomiSearchInputObservation.java": "ecf6a9ccf173dc78c6c167435dc745b4080aa85a4fb77b22c3d442b7674254c3"
}
SHARED.update(FILLED_QUERY_SHARED)
PRE_CANONICAL_REUSE_SHARED=dict(SHARED)
CAPTURE_REUSE_PATH="src/org/trillionnium/hepta/local/ObservationCaptureEvidence.java"
SHARED[CAPTURE_REUSE_PATH]="b3c99f53c94b662ee35ffa26054f22f647fd2744d34edbc67d847afe9a05e651"
# Retain the exact e30 closure; the merged publication proof reverses to it.
PRE_AX_PUBLICATION_SHARED=dict(SHARED)
SHARED[CAPTURE_REUSE_PATH]="9a1677456b4f1435416649fe01d2d4690af9ffe072946f8688a54bce81fc8d86"
# Retain the complete pre-Ctrip closure; current full files keep strict pins.
PRE_CTRIP_FORM_SHARED=dict(SHARED)
SHARED.update({
  "src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java":"400db829f8b5942d9ad4a43a1bbbc18d96fe2138964482146b8cd08fd63ea593",
  "src/org/trillionnium/hepta/local/NativeCtripFormObservation.java":"ff884b8cafe28330262e8ff27423eaf34553faed3556984a3d188876ccef02ad"
})
# Keep the complete preceding closure. The getter is removed only for proof copies.
PRE_DIRECT_CARD_SHARED=dict(SHARED)
SHARED[CAPTURE_REUSE_PATH]="e7306d40d576efda5541e139abfc7e07c794f538aee7522f8f1f466947935f4c"
PATHS=[*SHARED,"src/org/trillionnium/hepta/local/NativeXiaomiProductPage.java","tests/native-xiaomi-product/NativeXiaomiProductPageHostTest.java","tests/native-app-fixtures/NativeXmlFixture.java"]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,ensure_ascii=False,indent=2)+"\n").encode()
def need(value,why):
    if not value:raise RuntimeError(why)
def bound(path):
    st=path.lstat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,"ordinary input: "+str(path))
    raw=path.read_bytes();end=path.lstat();need((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns),"changed input")
    return raw,(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();need(all(x.is_absolute() for x in (a.source,a.output,a.java_home)),"absolute paths")
    need(not a.output.exists() and a.source not in a.output.parents,"fresh external output")
    originals={}
    def read(path):v=bound(path);originals[path]=v;return v[0]
    read(Path(__file__).resolve())
    inverse_helper=a.source/"tests/native-xiaomi-query-stability/protected_filled_query.py"
    read(inverse_helper)
    read(a.source/"tests/native-ctrip-form-observation/scope_predecessor.py")
    filled_predecessor=runpy.run_path(str(inverse_helper))["predecessor"]
    capture_inverse=a.source/"tests/native-ax-canonical-reuse/protected_canonical_reuse.py"
    read(capture_inverse)
    capture_predecessor=runpy.run_path(str(capture_inverse))["predecessor"]
    publication_inverse=a.source/"tests/native-ax-observation/protected_publication.py"
    read(publication_inverse)
    publication_predecessor=runpy.run_path(str(publication_inverse))["predecessor"]
    direct_inverse=a.source/"tests/native-xiaomi-direct-card/protected_direct_card.py"
    read(direct_inverse)
    direct_capture_predecessor=runpy.run_path(str(direct_inverse))["capture_predecessor"]
    for rel in PATHS:
        raw=read(a.source/rel)
        if rel in SHARED:need(sha(raw)==SHARED[rel],"reviewed shared DTO/goal pin")
        if rel==CAPTURE_REUSE_PATH:
            before_getter=direct_capture_predecessor(raw)
            need(sha(before_getter)==PRE_DIRECT_CARD_SHARED[rel],"getter proof copy must reproduce complete preceding capture source")
            prior=publication_predecessor(before_getter)
            need(sha(prior)==PRE_AX_PUBLICATION_SHARED[rel],"AX publication proof copy must reproduce complete e30 capture source")
            need(sha(capture_predecessor(prior))==PRE_CANONICAL_REUSE_SHARED[rel],
                 "canonical reuse proof copy must reproduce the complete preceding capture source")
        if rel in FILLED_QUERY_SHARED:
            need(sha(filled_predecessor(Path(rel).name,raw))==PRE_FILLED_QUERY_SHARED[rel],
                 "filled-query proof copy must reproduce the complete prior shared source")
    provenance_path=a.source/"tests/native-xiaomi-product/fixtures/PROVENANCE.json"
    provenance=json.loads(read(provenance_path))
    need(provenance["schema"]=="hepta.native-xiaomi-public-fixtures.v2"
         and provenance["fixture_xml_values_actual"] is False
         and provenance["public_fixture_values_except_listed_redactions_match_original"] is True
         and provenance["public_fixtures_are_not_qualification_originals"] is True
         and provenance["private_originals_preserved"] is True
         and provenance["no_android_runtime_or_dispatch_verified"] is True,"explicit public fixture scope")
    redacted={x["name"] for x in provenance["files"] if x["public_redactions"]}
    need(redacted=={"detail","detail-readonly"},"exact privacy redaction scope")
    for row in provenance["files"]:
        need(row["qualification_original"] is False,"public fixture cannot be qualification original")
        if row["name"] in redacted:
            changes=row["public_redactions"]
            need(row["original_sha256"]=="19c8dc7f515e7be469e5c37bc2e3c551cc22250434a7fa640cd1d2abed39562f"
                 and row["original_bytes_unchanged"] is False and len(changes)==1
                 and changes[0]["node_index_zero_based"]==98 and changes[0]["attribute"]=="text"
                 and changes[0]["replacement"]=="REDACTED_ADDRESS"
                 and changes[0]["all_other_node_attributes_and_xml_bytes_unchanged"] is True,"exact redaction declaration")
        else:
            need(row["original_bytes_unchanged"] is True and row["sha256"]==row["original_sha256"],"unchanged nonprivate fixture")
    for row in provenance["files"]:
        raw=read(a.source/row["fixture_path"]);need(len(raw)==row["bytes"] and sha(raw)==row["sha256"],"published fixture byte pin "+row["name"])
    a.output.mkdir(mode=0o700);classes=a.output/"classes";classes.mkdir()
    result={"schema":SCHEMA,"all_pass":False,"steps":[],"original_shared_source_pins":ORIGINAL_SHARED,"pre_form_history_shared_source_pins":PRE_FORM_HISTORY_SHARED,"pre_input_history_shared_source_pins":PRE_INPUT_HISTORY_SHARED,"pre_filled_query_shared_source_pins":PRE_FILLED_QUERY_SHARED,"filled_query_inverse_verified":True,"pre_canonical_reuse_shared_source_pins":PRE_CANONICAL_REUSE_SHARED,"canonical_reuse_inverse_verified":True,"pre_ax_publication_shared_source_pins":PRE_AX_PUBLICATION_SHARED,"ax_publication_inverse_verified":True,"pre_ctrip_form_shared_source_pins":PRE_CTRIP_FORM_SHARED,"pre_direct_card_shared_source_pins":PRE_DIRECT_CARD_SHARED,"direct_card_getter_inverse_verified":True,"current_shared_source_pins":SHARED,"phone_operations":0,"model_inference":False,"android_runtime":False,"business_verified":False,"started_epoch":time.time()}
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
    def command(name,argv):
        began=time.monotonic();r=subprocess.run([str(x) for x in argv],cwd=a.source,env=env,capture_output=True,timeout=90)
        (a.output/(name+".stdout")).write_bytes(r.stdout);(a.output/(name+".stderr")).write_bytes(r.stderr)
        result["steps"].append({"name":name,"argv":[str(x) for x in argv],"exit_code":r.returncode,"seconds":time.monotonic()-began,
                "stdout_bytes":len(r.stdout),"stdout_sha256":sha(r.stdout),"stderr_bytes":len(r.stderr),"stderr_sha256":sha(r.stderr)})
        if r.returncode:
            print(r.stdout.decode(errors="replace")[-8000:]);print(r.stderr.decode(errors="replace")[-8000:])
        need(r.returncode==0,"actual host command failed: "+name)
    try:
        command("javac",[a.java_home/"bin/javac","--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",classes,*[a.source/x for x in PATHS]])
        command("cases",[a.java_home/"bin/java","-cp",classes,"org.trillionnium.hepta.local.NativeXiaomiProductPageHostTest",provenance_path.parent,a.output/"CASES.json"])
        cases=json.loads((a.output/"CASES.json").read_bytes());need(cases["all_pass"] is True and cases["cases"]==75 and len(set(cases["case_names"]))==75,"complete fixed parser cases")
        need(cases["phone_operations"]==0 and cases["android_runtime"] is False and cases["business_verified"] is False,"host-only case scope")
        result["cases"]=cases;result["all_pass"]=True
    except Exception as error:
        result["error"]=type(error).__name__+": "+str(error);(a.output/"ERROR.txt").write_text(traceback.format_exc())
    finally:
        result["inputs_unchanged"]=all(bound(path)==value for path,value in originals.items())
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"];result["finished_epoch"]=time.time()
        result["source_inputs"]=[{"path":str(path),"bytes":len(value[0]),"sha256":sha(value[0])} for path,value in originals.items()]
        raw=enc(result);(a.output/"RESULT.json").write_bytes(raw)
        print(json.dumps({"all_pass":result["all_pass"],"cases":result.get("cases",{}).get("cases"),"assertions":result.get("cases",{}).get("assertions"),
                "error":result.get("error"),"result":str(a.output/"RESULT.json"),"result_sha256":sha(raw)},ensure_ascii=False))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
