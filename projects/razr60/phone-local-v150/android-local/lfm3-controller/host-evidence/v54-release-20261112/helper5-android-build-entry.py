#!/usr/bin/env python3
"""Build isolated helper5 bounded read sampling from actual code4 provenance. No phone/signing."""
import base64,gzip,hashlib,io,json,os,pathlib,re,signal,stat,struct,subprocess,sys,tarfile,time,traceback,zipfile,zlib
B=pathlib.Path("/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f")
BASE=B/"v54-web-helper-code4-build-r1"
ROOT=B/"v54-web-helper-code5-build-r1"
BASE_RESULT_SHA="021815261d930ce2e21de877a149a560908a74371dc08e169a1b2a116ef9fdec"
CANDIDATE_SHA="7e59fcd9dcc4d15cce60e35973151cf6320aec175e8f528217887fc4866a2056"
CANDIDATE_BYTES=155587
JAVA_HOME=pathlib.Path("/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home")
JSON_JAR=pathlib.Path("/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v53-web-helper-r3-dependency-closure-r2/artifacts/org.json/json/20240303/json-20240303.jar")
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
NEW_RUNTIME=("src/org/trillionnium/hepta/webhelper/CaptureReadBudget.java",
 "src/org/trillionnium/hepta/webhelper/DomInstabilityEvidence.java")
ORIGINALS={}
def need(v,m):
    if not v: raise RuntimeError(m)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+"\n").encode("utf-8")
def strict(raw):
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,"duplicate JSON key");out[k]=v
        return out
    return json.loads(raw.decode("utf-8"),object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def exact(path,expected_sha=None,expected_bytes=None,remember=True):
    path=pathlib.Path(path)
    need(path.is_absolute() and ".." not in path.parts and not path.is_symlink(),"absolute regular original required")
    with path.open("rb") as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=64*1024*1024,"bounded regular original required")
        raw=f.read(64*1024*1024+1);b=os.fstat(f.fileno())
    need(identity(a)==identity(b)==identity(path.stat()) and len(raw)==a.st_size,"file changed during exact read")
    need(expected_sha is None or sha(raw)==expected_sha,"original SHA differs: "+str(path))
    need(expected_bytes is None or len(raw)==expected_bytes,"original length differs: "+str(path))
    if remember:
        if str(path) in ORIGINALS:need(ORIGINALS[str(path)]==(sha(raw),identity(a)),"original was changed")
        else:ORIGINALS[str(path)]=(sha(raw),identity(a))
    return raw
def rel(path):
    p=pathlib.PurePosixPath(path)
    need(not p.is_absolute() and ".." not in p.parts and "." not in p.parts and str(p)==path,"canonical relative source path")
    return p
def put(path,raw):
    need(ROOT in path.parents and not path.is_symlink(),"new output must belong to own claimed root")
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    need(exact(path,sha(raw),len(raw),False)==raw,"new output readback")
    return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
def unchanged():
    for p,(digest,stamp) in ORIGINALS.items():
        raw=exact(pathlib.Path(p),digest,stamp[4],False);need(identity(pathlib.Path(p).stat())==stamp,"original identity changed")
def zipper(raw):
    out={}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(len(z.infolist())<=10000 and z.testzip() is None,"ZIP CRC/member budget")
        total=0
        for i in z.infolist():
            if i.is_dir():continue
            rel(i.filename);need(i.filename not in out and not(i.flag_bits&1),"unique nonencrypted ZIP member")
            payload=z.read(i);total+=len(payload);need(total<=64*1024*1024 and len(payload)==i.file_size,"ZIP expanded budget")
            out[i.filename]=payload
    return out
def rows(data):return [{"path":p,"bytes":len(raw),"sha256":sha(raw)} for p,raw in sorted(data.items())]
def members(data):return [{"name":p,"bytes":len(raw),"sha256":sha(raw)} for p,raw in sorted(data.items())]
def archive(data):
    target=io.BytesIO()
    with tarfile.open(fileobj=target,mode="w",format=tarfile.USTAR_FORMAT) as tar:
        for name,raw in sorted(data.items()):
            rel(name);info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o644;info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=""
            tar.addfile(info,io.BytesIO(raw))
    result=gzip.compress(target.getvalue(),compresslevel=6,mtime=0)
    with tarfile.open(fileobj=io.BytesIO(result),mode="r:gz") as tar:
        recovered={}
        for m in tar.getmembers():
            need(m.isfile() and m.name not in recovered,"regular unique tar member")
            recovered[m.name]=tar.extractfile(m).read()
    need(recovered==data,"tar exact roundtrip");return result
def fixed_gzip(raw):
    c=zlib.compressobj(6,zlib.DEFLATED,31,8,zlib.Z_FIXED);out=c.compress(raw)+c.flush()
    need(gzip.decompress(out)==raw,"fixed gzip readback");return out
def layout(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        info=z.getinfo("resources.arsc");off=info.header_offset
        need(raw[off:off+4]==b"PK\x03\x04","resource local header")
        flags,method=struct.unpack_from("<HH",raw,off+6)
        name_len,extra_len=struct.unpack_from("<HH",raw,off+26)
        data=off+30+name_len+extra_len
        need(raw[off+30:off+30+name_len]==b"resources.arsc" and method==0
             and info.compress_type==zipfile.ZIP_STORED and flags==info.flag_bits and data%4==0,"resources must be STORED and four-byte aligned")
        return {"central_method":info.compress_type,"local_method":method,"data_offset":data,"data_offset_mod4":data%4}
def main():
    need(3<=len(sys.argv)<=8 and all(len(x.encode("utf-8"))<=65536 for x in sys.argv[1:]),"fixed bounded source/payload argv")
    executing=sys.argv[1].encode("utf-8")
    compressed=base64.b64decode("".join(sys.argv[2:]),validate=True)
    need(len(compressed)<=300000,"candidate compressed bound")
    raw=gzip.decompress(compressed)
    need(len(raw)==CANDIDATE_BYTES and sha(raw)==CANDIDATE_SHA,"exact candidate payload required")
    candidate=strict(raw)
    need(candidate["schema"]=="hepta.web-helper-code5-bounded-read-candidate.v1"
         and candidate["helper_version_code"]==5 and candidate["helper_version_name"]=="0.5.0-web-evidence-v3"
         and candidate["success_wire_shape_changed"] is False and candidate["max_attempts"]==3
         and candidate["deadline_budget_ms"]==3000 and candidate["targeted_host_cases"]==33
         and candidate["host_gate_executed"] is False and candidate["android_compiled"] is False
         and candidate["phone_tested"] is False,"candidate scope differs")
    base_raw=exact(BASE/"RESULT.json",BASE_RESULT_SHA,128049);old=strict(base_raw)
    need(old["all_pass"] is True and old["version_code"]==4 and old["runtime_java_input_count"]==34
         and old["source_file_count"]==36 and old["phone_tested"] is False and old["originals_unchanged"] is True,
         "actual code4 build provenance differs")
    need(candidate["base_inputs"]==old["source_inputs"],"full 36 original source table differs")
    base_contract=old["contract_result"];exact(base_contract["path"],base_contract["sha256"],base_contract["bytes"])
    source={}
    for p in old["source_inputs"]:
        source[p["path"]]=exact(BASE/"source"/rel(p["path"]),p["sha256"],p["bytes"])
    need(len(source)==36,"exact original source count")
    originals_rows=rows(source)
    overlay={}
    for f in candidate["files"]:
        p=f["path"];rel(p);need(p not in overlay,"duplicate candidate source")
        data=f["raw_utf8"].encode("utf-8");need(len(data)==f["bytes"] and sha(data)==f["sha256"],"candidate member bytes differ")
        if p in source:need(f.get("base_sha256",sha(source[p]))==sha(source[p]),"overlay base source differs")
        overlay[p]=data
    runtime_paths=set(source)|set(NEW_RUNTIME);need(len(runtime_paths)==38,"exact helper runtime source set")
    expected_runtime_overlays=set(NEW_RUNTIME)|{
        "src/org/trillionnium/hepta/webhelper/OfficialPageCapture.java",
        "src/org/trillionnium/hepta/webhelper/EvidenceSession.java",
        "src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java"}
    need({p for p in overlay if not p.startswith("tests/capture-retry/")}==expected_runtime_overlays
         and len(overlay)==26,"only five runtime overlay members and targeted callback fixtures")
    for p in runtime_paths:
        if p in overlay:source[p]=overlay[p]
        else:need(p in source,"new runtime source missing")
    old_manifest=source["AndroidManifest.xml"]
    text=old_manifest.decode("utf-8")
    changes=candidate["manifest_change"]
    need(sha(old_manifest)==changes["base_sha256"] and len(changes["exact_replacements"])==2,"manifest derivation differs")
    for before,after in changes["exact_replacements"]:
        need(text.count(before)==1,"manifest version input not exact");text=text.replace(before,after)
    for before,after in reversed(changes["exact_replacements"]):
        need(text.count(after)==1,"manifest version output not exact")
    source["AndroidManifest.xml"]=text.encode("utf-8")
    restored=text
    for before,after in reversed(changes["exact_replacements"]):restored=restored.replace(after,before)
    need(restored.encode("utf-8")==old_manifest,"only two manifest literals may change")
    need(len(source)==38 and sum(p.endswith(".java") for p in source)==36,"new runtime inventory differs")
    source_rows=rows(source)
    for tool in old["build_tools"]:exact(tool["path"],tool["sha256"],tool["bytes"])
    java=JAVA_HOME/"bin/java";javac=JAVA_HOME/"bin/javac"
    tools={pathlib.Path(x["path"]).name:pathlib.Path(x["path"]) for x in old["build_tools"]}
    aapt=tools["aapt2"];align=tools["zipalign"];android=tools["android.jar"];r8=tools["r8-8.13.17.jar"]
    json_raw=exact(JSON_JAR,JSON_SHA,78332)
    jars=[]
    for row in old["runtime_library_jars"]:exact(row["path"],row["sha256"],row["bytes"]);jars.append(pathlib.Path(row["path"]))
    need(len(jars)==14 and JSON_JAR not in jars,"exact 14 runtime jars; host JSON cannot enter APK")
    old_apk=old["unsigned_apk"]
    old_apk_raw=exact(old_apk["path"],old_apk["sha256"],old_apk["bytes"]);old_payload=zipper(old_apk_raw)
    need(members(old_payload)==old["compiled_members"] and len(old_payload)==372,"actual old compiled member map differs")
    resource_zips=[]
    for name in ("00","05","09"):
        p=BASE/"resources"/name/"compiled-res.zip";resource_zips.append((p,exact(p)))
    need(not ROOT.exists() and all(not p.is_symlink() for p in [ROOT,*ROOT.parents]),"independent new build root required")
    unchanged()
    # FIRST MUTATION. Outside handler: a late identical invocation cannot write the winning result.
    ROOT.mkdir(mode=0o700)
    result={"schema":"hepta.web-helper-code5-android-build.v1","all_pass":False,"exit_code":1,"started_epoch":time.time(),
        "base_helper_build_sha256":BASE_RESULT_SHA,"candidate_payload_sha256":CANDIDATE_SHA,
        "version_code":5,"version_name":"0.5.0-web-evidence-v3","source_inputs":source_rows,
        "source_file_count":38,"runtime_java_input_count":36,"runtime_library_jars":old["runtime_library_jars"],
        "build_tools":old["build_tools"],"java_release":8,"compile_sdk":34,"target_sdk":35,"min_sdk":30,
        "main_app_changed":False,"original_code4_changed":False,
        "base_contract_result":base_contract,"base_contracts_rerun":False,"signed":False,"installed":False,
        "phone_tested":False,"actual_mi_dom_seen":False,"business_verified":False,
        "origin_runtime_verified":False,"storage_isolation_runtime_verified":False,"orphan_recovery_runtime_verified":False,
        "old_resource_payloads_preserved":False,"originals_unchanged":False,"steps":[],"known_limitations":candidate["known_limitations"]}
    def run(name,argv,timeout=120):
        t=time.monotonic();o=ROOT/(name+".stdout");e=ROOT/(name+".stderr");forced=False
        with o.open("xb") as stdout,e.open("xb") as stderr:
            p=subprocess.Popen([str(x) for x in argv],cwd=str(ROOT),stdout=stdout,stderr=stderr,start_new_session=True)
            try:rc=p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                forced=True;os.killpg(p.pid,signal.SIGKILL);rc=p.wait(timeout=10)
        out=exact(o,remember=False);err=exact(e,remember=False)
        need(len(out)<=4*1024*1024 and len(err)<=4*1024*1024,"bounded build log")
        item={"name":name,"argv":[str(x) for x in argv],"exit_code":rc,"forced":forced,"elapsed_seconds":time.monotonic()-t,
              "stdout":{"path":str(o),"bytes":len(out),"sha256":sha(out)},"stderr":{"path":str(e),"bytes":len(err),"sha256":sha(err)}}
        result["steps"].append(item);need(rc==0 and not forced,"actual build stage failed: "+name);return out
    try:
        put(ROOT/"BUILD.py",executing);put(ROOT/"CANDIDATE.json",raw);put(ROOT/"CANDIDATE.json.gz",compressed)
        put(ROOT/"BASE-BUILD-RESULT.json",base_raw)
        for p,data in sorted(source.items()):put(ROOT/"source"/rel(p),data)
        inventory=encoded({"schema":"hepta.web-helper-source-inventory.v1","files":source_rows})
        put(ROOT/"SOURCE-INVENTORY.json",inventory);result["source_inventory_sha256"]=sha(inventory)
        # Only the changed capture/diagnostic boundary gets a new targeted host gate.
        # The actual code4 authority/recovery tests remain immutable prior evidence.
        for p,data in sorted(overlay.items()):
            if p.startswith("tests/capture-retry/"):
                put(ROOT/"callback-fixtures"/p[len("tests/capture-retry/"):],data)
        run("capture-retry-contracts",[sys.executable,"-I","-B",ROOT/"callback-fixtures/run_host_tests.py",
            "--source-root",ROOT/"source","--fixtures",ROOT/"callback-fixtures","--out",ROOT/"capture-retry-gate",
            "--java-home",JAVA_HOME,"--json-jar",JSON_JAR,"--expected-json-jar-sha256",JSON_SHA],240)
        contract_raw=exact(ROOT/"capture-retry-gate/RESULT.json",remember=False);contract=strict(contract_raw)
        need(contract["all_pass"] is True and contract["capture_retry_checks"]==33
             and contract["phone_tested"] is False and contract["javascript_executed"] is False
             and contract["business_verified"] is False and contract["old_unrelated_contracts_rerun"] is False,
             "actual targeted callback contract gate required")
        result["contract_result"]={"path":str(ROOT/"capture-retry-gate/RESULT.json"),"bytes":len(contract_raw),"sha256":sha(contract_raw)}
        result["contract_checks"]={"capture_retry_checks":contract["capture_retry_checks"],
                                  "capture_retry_assertions":contract["capture_retry_assertions"]}
        generated=ROOT/"generated";classes=ROOT/"classes";dex=ROOT/"dex"
        generated.mkdir();classes.mkdir();dex.mkdir()
        compiled_res=[]
        for p,data in resource_zips:
            target=ROOT/"resources"/p.parent.name/"compiled-res.zip";put(target,data);compiled_res.append(target)
        run("java-version",[java,"-version"],30);run("javac-version",[javac,"-version"],30)
        version=run("d8-version",[java,"-cp",r8,"com.android.tools.r8.D8","--version"],30).decode("utf-8")
        need("D8 8.13.17" in version,"actual official compiler version differs")
        run("aapt2-link",[aapt,"link","-I",android,"--manifest",ROOT/"source/AndroidManifest.xml",
            "--java",generated,"--output-text-symbols",ROOT/"R.txt","-o",ROOT/"base.apk",
            "--extra-packages","androidx.annotation.experimental:androidx.core:androidx.lifecycle:androidx.versionedparcelable:androidx.webkit",*compiled_res])
        generated_files=sorted(p for p in generated.rglob("*.java"))
        generated_rows=[{"path":str(p.relative_to(generated)),"bytes":len(exact(p,remember=False)),"sha256":sha(exact(p,remember=False))} for p in generated_files]
        need(generated_rows==old["generated_source_inputs"],"new manifest unexpectedly changed generated permission/resource API")
        result["generated_source_inputs"]=generated_rows
        result["generated_java_count"]=len(generated_rows)
        java_inputs=sorted(ROOT/"source"/p for p in source if p.endswith(".java"))
        cp=os.pathsep.join(str(x) for x in [android,*jars])
        run("javac",[javac,"--release","8","-encoding","UTF-8","-proc:none","-classpath",cp,"-d",classes,*java_inputs,*generated_files])
        class_files=sorted(classes.rglob("*.class"));need(len(class_files)>old["application_class_count"] and len(class_files)<1000,"bounded actual new classes")
        result["application_class_count"]=len(class_files)
        run("d8",[java,"-cp",r8,"com.android.tools.r8.D8","--lib",android,"--min-api","30","--output",dex,*class_files,*jars],180)
        need(sorted(p.name for p in dex.iterdir())==["classes.dex"],"exact one dex expected")
        fresh_base=zipper(exact(ROOT/"base.apk",remember=False))
        base_names={n for n in old_payload if n=="AndroidManifest.xml" or n=="resources.arsc" or n.startswith("res/")}
        need(set(fresh_base)==base_names,"fresh resource APK membership differs")
        for n,data in fresh_base.items():
            if n!="AndroidManifest.xml":need(data==old_payload[n],"resource payload changed without a source change")
        payload=dict(old_payload);payload.update(fresh_base)
        payload["classes.dex"]=exact(dex/"classes.dex",remember=False)
        payload["assets/readonly_dom.js"]=source["assets/readonly_dom.js"]
        need(set(payload)==set(old_payload),"compiled APK member set changed")
        changed={"AndroidManifest.xml","classes.dex"}
        need(payload["assets/readonly_dom.js"]==old_payload["assets/readonly_dom.js"],"fixed DOM observer byte-for-byte unchanged")
        for n in set(payload)-changed:need(payload[n]==old_payload[n],"inherited library payload changed")
        need(not any(n.startswith("lib/") or n.endswith(".so") for n in payload),"helper cannot acquire native libraries")
        unsigned=ROOT/"helper-unsigned.apk"
        with zipfile.ZipFile(ROOT/"helper-unaligned.apk","x") as z:
            for n,data in sorted(payload.items()):
                info=zipfile.ZipInfo(n,(1980,1,1,0,0,0));info.external_attr=0o100644<<16
                info.compress_type=zipfile.ZIP_STORED if n=="resources.arsc" else zipfile.ZIP_DEFLATED
                z.writestr(info,data)
        run("zipalign",[align,"-f","4",ROOT/"helper-unaligned.apk",unsigned])
        run("zipalign-check",[align,"-c","4",unsigned])
        unsigned_raw=exact(unsigned,remember=False)
        need(len(unsigned_raw)<=2*1024*1024 and zipper(unsigned_raw)==payload,"exact bounded complete APK readback")
        result["unsigned_resource_layout"]=layout(unsigned_raw)
        badging=run("badging",[aapt,"dump","badging",unsigned]).decode("utf-8")
        permissions=run("permissions",[aapt,"dump","permissions",unsigned]).decode("utf-8")
        need("package: name='org.trillionnium.hepta.webhelper'" in badging and "versionCode='5'" in badging
             and "versionName='0.5.0-web-evidence-v3'" in badging,"actual package/version differs")
        uses=re.findall(r"uses-permission(?:-[^:]+)?: name='([^']+)'",permissions)
        need(uses==["android.permission.INTERNET"],"helper runtime permissions changed")
        need("org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE" in permissions,"signature IPC permission missing")
        need("native-code:" not in badging,"helper must have no native ABI")
        result["compiled_members"]=members(payload);result["compiled_member_count"]=len(payload)
        result["permissions"]=uses;result["unsigned_apk"]={"path":str(unsigned),"bytes":len(unsigned_raw),"sha256":sha(unsigned_raw)}
        archive_data=dict(source);archive_data["SOURCE-INVENTORY.json"]=inventory
        source_archive=archive(archive_data);result["source_archive"]=put(ROOT/"source.tar.gz",source_archive)
        result["old_resource_payloads_preserved"]=True
        result["unchanged_compiled_payload_count"]=len(payload)-len(changed)
        result["success_capture_shape_unchanged"]=True
        need(rows({p:exact(ROOT/"source"/p,remember=False) for p in source})==source_rows,"runtime source changed during compile")
        unchanged();result["originals_unchanged"]=True;result["all_pass"]=True;result["exit_code"]=0
    except Exception as error:
        result["error"]=type(error).__name__+": "+str(error)
        result["traceback"]=traceback.format_exc()
        try:unchanged();result["originals_unchanged"]=True
        except Exception as changed:result["originals_unchanged"]=False;result["original_check_error"]=str(changed)
    result["finished_epoch"]=time.time();result["elapsed_seconds"]=result["finished_epoch"]-result["started_epoch"]
    result_raw=encoded(result);result_ref=put(ROOT/"RESULT.json",result_raw)
    result_fixed=fixed_gzip(result_raw);put(ROOT/"RESULT.json.fixed.gz",result_fixed)
    put(ROOT/"RESULT.json.fixed.gz.base64",base64.b64encode(result_fixed))
    summary={k:result.get(k) for k in ("schema","all_pass","exit_code","version_code","version_name","source_file_count",
        "runtime_java_input_count","application_class_count","generated_java_count","compiled_member_count","unsigned_apk",
        "source_archive","source_inventory_sha256","unsigned_resource_layout","permissions","contract_result","contract_checks",
        "originals_unchanged","old_resource_payloads_preserved","elapsed_seconds","error","phone_tested","business_verified",
        "storage_isolation_runtime_verified","origin_runtime_verified","known_limitations")}
    summary["result"]=result_ref
    summary["result_fixed_gzip"]={"bytes":len(result_fixed),"sha256":sha(result_fixed),"base64_path":str(ROOT/"RESULT.json.fixed.gz.base64")}
    put(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,ensure_ascii=False,separators=(",",":")),flush=True)
    return result["exit_code"]
if __name__=="__main__":raise SystemExit(main())
