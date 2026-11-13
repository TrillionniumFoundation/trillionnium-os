#!/usr/bin/env python3
"""Execute the actual pure parser against public native App XML fixtures with explicitly recorded redactions.
This is not an Android/installed-App/dispatch/completion test."""
from pathlib import Path
import argparse, hashlib, json, os, stat, subprocess, time, traceback
SCHEMA="hepta.native-xiaomi-product-compiled-gate.v1"
SHARED={
"src/org/trillionnium/hepta/local/NativeAppGoal.java":"8f0049cda1202f1d9f2823e61479f6e031ba1f89007d7cf7f312671d78cc8474",
"src/org/trillionnium/hepta/local/NativeAppEvidence.java":"ff8b76cd14ed4d2ebfb4e6bbe20ea5dac7e391fa934726f921b195055ad37d37",
"src/org/trillionnium/hepta/local/ObservedChildText.java":"56433b62f9c4c895edac441160fcdc4aaee7365586daa4b86863448dc4dd54d5",
"src/org/trillionnium/hepta/local/ObservedTargetLabels.java":"c4e1b1a7ae0223fc7cda90864c6a5c3759a2875bb435359464672bc79465c8ba"}
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
    for rel in PATHS:
        raw=read(a.source/rel)
        if rel in SHARED:need(sha(raw)==SHARED[rel],"reviewed shared DTO/goal pin")
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
    result={"schema":SCHEMA,"all_pass":False,"steps":[],"phone_operations":0,"model_inference":False,"android_runtime":False,"business_verified":False,"started_epoch":time.time()}
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
        cases=json.loads((a.output/"CASES.json").read_bytes());need(cases["all_pass"] is True and cases["cases"]==33 and len(set(cases["case_names"]))==33,"complete fixed parser cases")
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
