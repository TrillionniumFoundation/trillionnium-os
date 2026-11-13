#!/usr/bin/env python3
"""Independent Pocket4 helper6 build from actual5 and fixed inputs. Unknown Mac attempt preserved; no phone/signing."""
import base64,gzip,hashlib,io,json,os,pathlib,re,signal,stat,struct,subprocess,sys,tarfile,time,traceback,zipfile,zlib
B=pathlib.Path("/home/alex/hepta-local-007f-20261111")
BASE=B/"v54-web-helper-code5-sign-r1/inputs"
ROOT=B/"v55-web-helper-code6-p4-build-r2"
PUBLIC=B/"v55-helper6-p4-public-inputs-r1"
LARGE=B/"v55-helper6-p4-public-large-inputs-r1"
SDK_FAILED=B/"v55-helper6-p4-sdk-input-r1"
SDK_PUBLIC=B/"v55-helper6-p4-sdk-input-r2"
BASE_RESULT_SHA="cce5d75af6af48fb00b72b96475d686b61b89538c60cbd424fd99e79c58396a8"
CANDIDATE_SHA="02ad1cbe0b930708c079e66b8d7c3a88ce4b78bcba9bfbc0e58db35c0ce3a7e7"
CANDIDATE_BYTES=774612
INPUT_SHA="e171d32569902d27655e1d90b555f89d6a17156bef7f43d0bced2d5e67f258ce"
INPUT_BYTES=974898
DOWNLOAD_RESULT_SHA="5300257b246f73bc410028d8e1e61f18381e6f9b4a4406661d00b7d3d128eab6"
DOWNLOAD_RESULT_BYTES=64222
DOWNLOAD_SOURCE_SHA="981e495c209882ca907d6f417d1182e3d7f101774334bcace7b09c84e37d3291"
DOWNLOAD_SOURCE_BYTES=29435
SDK_FAILURE_SHA="e38d1133bf0c43fc5c5f575c3206a89fb215d8a33972348a09a7888c84e693a5"
SDK_FAILURE_BYTES=19882
SDK_FAILURE_SOURCE_SHA="73ba0049e625fe8a88ea21ff3ce89fd9526d8191e8dfc7da1728759dc1e42464"
LARGE_FAILURE_SHA="7b1a1a625a78fe58d80cba88136a971581b314216663ea346fdcd856bb82f097"
LARGE_FAILURE_BYTES=25490
LARGE_SOURCE_SHA="35060e2cb0e0d61b76da6df7de646dcdb4ccccf8e650640d75b80b2304c1a7ec"
PRIOR_DOWNLOAD_SHA="3ce37751fc824816475e624123a787f5e00bd011c11beb9d583835df453b18ad"
PRIOR_DOWNLOAD_BYTES=18213
RESOURCE_PACKET_SHA="a01966f37778d02ef016189218bef9a61450c66c43e16af6beb20e6833b63819"
RESOURCE_PACKET_BYTES=146213
JAVA_HOME=pathlib.Path("/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64")
JSON_JAR=PUBLIC/"host-json/json-20240303.jar"
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
P4_TOOLS=[
 {"path":str(JAVA_HOME/"bin/java"),"bytes":14544,"sha256":"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196"},
 {"path":str(JAVA_HOME/"bin/javac"),"bytes":14592,"sha256":"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4"},
 {"path":"/usr/lib/android-sdk/build-tools/debian/aapt2","bytes":54512,"sha256":"0e9ff92342040acdfd03e8708512f4e02353e3ca0a2b85ea2950da659110b009"},
 {"path":str(LARGE/"tools/r8-8.13.17.jar"),"bytes":18279079,"sha256":"d31fd0dc751d48740009cdd9a485126acb1d0d14c59b9f05579479940f4adf74"},
 {"path":str(SDK_PUBLIC/"sdk/android-34/android.jar"),"bytes":26361808,"sha256":"6cea1df3efb77103ac3e2beb9bf4718964b0e0869ab16d39d29d5cbae1c147ad"}]
JDK_RECEIPT={"path":"/home/alex/hepta-v31-nanbeige42-e59-r1/toolchains/old-jdk17-revalidation-r1/RESULT.json",
 "bytes":2954,"sha256":"349939390c8b19e8cea03e28ce6c5bc2c1d010dd06d3a435b7f1517221f0dd1c"}
NEW_RUNTIME=("src/org/trillionnium/hepta/webhelper/ObservedLinkPermit.java",
 "src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java",
 "src/org/trillionnium/hepta/webprotocol/WebDomStability.java",
 "src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java",
 "src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java")
EXPECTED_OVERLAY=("assets/readonly_dom.js",
 "src/org/trillionnium/hepta/local/web/WebShoppingGoal.java",
 "src/org/trillionnium/hepta/webhelper/DomInstabilityEvidence.java",
 "src/org/trillionnium/hepta/webhelper/EvidenceService.java",
 "src/org/trillionnium/hepta/webhelper/EvidenceSession.java",
 "src/org/trillionnium/hepta/webhelper/InstalledIdentity.java",
 "src/org/trillionnium/hepta/webhelper/ObservedLinkPermit.java",
 "src/org/trillionnium/hepta/webhelper/OfficialPageCapture.java",
 "src/org/trillionnium/hepta/webhelper/PageActivity.java",
 "src/org/trillionnium/hepta/webhelper/PageSitePolicy.java",
 "src/org/trillionnium/hepta/webhelper/ProfileIsolation.java",
 "src/org/trillionnium/hepta/webhelper/RemoteReply.java",
 "src/org/trillionnium/hepta/webhelper/TaskBinding.java",
 "src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java",
 "src/org/trillionnium/hepta/webprotocol/WebDomStability.java",
 "src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java",
 "src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java",
 "src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java",
 "src/org/trillionnium/hepta/webprotocol/WebRecoveryPolicy.java",
 "src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java")
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
    executing=globals().get("__source_raw__")
    input_raw=globals().get("__build_input_raw__")
    compressed=globals().get("__input_compressed__")
    need(isinstance(executing,bytes) and isinstance(input_raw,bytes) and isinstance(compressed,bytes),"exact short-loader inputs required")
    # Derive the one fixture-only successor from the exact already-committed r1 input.
    # All original failed outputs remain read-only and are included in unchanged().
    need(len(input_raw)==974816 and sha(input_raw)=="2edd91859e8e740ee3d8bbbc98413bab9bec3e59cef1a1ef223b0951743cde8a",
         "original committed input before fixture repair")
    need(len(compressed)==238064 and sha(compressed)=="359cc932d070ae619df1072c787c62be4bf25fb78c89f0702bba9dd878994868"
         and gzip.decompress(compressed)==input_raw,"original complete compressed input")
    prior_input_raw=input_raw;prior_packet=strict(input_raw)
    prior_candidate_raw=prior_packet["candidate"]["raw_utf8"].encode("utf-8")
    need(len(prior_candidate_raw)==774532 and sha(prior_candidate_raw)=="3cc6380f19a8ae6bd20656a10442e0ab5bad9b5e4d54e8bb0b1eb72236bed38a",
         "original failed candidate")
    repaired=strict(prior_candidate_raw)
    prior_focused_raw=(json.dumps(repaired["focused_input"],ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")
    need(len(prior_focused_raw)==409362 and sha(prior_focused_raw)=="3a577c0ca14e95b8860fb9947e270b0609d244f48adf7c722e372c3e2bfc55d2",
         "original failed focused source package")
    prior_root=B/"v55-web-helper-code6-p4-build-r1"
    prior_failure_raw=exact(prior_root/"RESULT.json","77c20162ef85dd332e503c8e69fc3fb98c87a33f4460e35c236a6b9d48b88fa0",29695)
    prior_failure=strict(prior_failure_raw)
    need(prior_failure["schema"]=="hepta.web-helper-code6-android-build.v1"
         and prior_failure["all_pass"] is False and prior_failure["exit_code"]==1
         and prior_failure["error"]=="RuntimeError: actual build stage failed: focused-javac"
         and prior_failure["originals_unchanged"] is True and len(prior_failure["steps"])==1,
         "original actual first compilation failure preserved")
    step=prior_failure["steps"][0]
    need(step["name"]=="focused-javac" and step["exit_code"]==1 and step["forced"] is False
         and step["timed_out"] is False and step["wait_exception"] is None,"original compilation failure status")
    for stream in ("stdout","stderr"):
        record=step[stream]
        need(record["path"]==str(prior_root/("focused-javac."+stream)),"fixed original compiler log")
        exact(record["path"],record["sha256"],record["bytes"])
    exact(prior_root/"focused-javac.stderr","090e1b90ac8f791eb8ad168084fc0963f36feeb90d8ffa4771d5bf5653ec7e88",451)
    exact(prior_root/"BUILD.py","58a7b378665cffc88744f4291d7a490354e267d73c796db29fc7ee6dbd6f3a12",47758)
    need(exact(prior_root/"BUILD-INPUT.json",sha(prior_input_raw),len(prior_input_raw))==prior_input_raw,"old input original")
    need(exact(prior_root/"BUILD-INPUT.json.gz",sha(compressed),len(compressed))==compressed,"old input compression original")
    need(exact(prior_root/"CANDIDATE.json",sha(prior_candidate_raw),len(prior_candidate_raw))==prior_candidate_raw,"old candidate original")
    need(exact(prior_root/"FOCUSED-INPUT.json",sha(prior_focused_raw),len(prior_focused_raw))==prior_focused_raw,"old focused original")
    prior_inventory_raw=exact(prior_root/"SOURCE-INVENTORY.json",prior_failure["source_inventory_sha256"])
    need(strict(prior_inventory_raw)["files"]==prior_failure["source_inputs"] and len(prior_failure["source_inputs"])==43,
         "original failed complete production inventory")
    for row in prior_failure["source_inputs"]:
        rel(row["path"]);exact(prior_root/"source"/row["path"],row["sha256"],row["bytes"])
    for row in repaired["focused_input"]["files"]:
        rel(row["path"]);exact(prior_root/"focused-source"/row["path"],row["sha256"],row["bytes"])
    matches=[row for row in repaired["focused_input"]["files"]
             if row["path"]=="tests/capture-retry/stubs/android/webkit/WebView.java"]
    need(len(matches)==1,"one existing WebView fixture")
    row=matches[0];before=row["raw_utf8"]
    need(len(before.encode("utf-8"))==3388 and sha(before.encode("utf-8"))=="fa566ef2639079e59386634f048b106c247f4c1bbc409f5cde973b0a07459652",
         "exact original focused WebView")
    old=" public void setWebViewClient(WebViewClient c){client=c;}\n"
    new=" public int stopLoadingCalls;\n public void stopLoading(){stopLoadingCalls++;}\n"+old
    need(before.count(old)==1 and "stopLoading" not in before,"one missing fixture API")
    row["raw_utf8"]=before.replace(old,new)
    row["bytes"]=len(row["raw_utf8"].encode("utf-8"));row["sha256"]=sha(row["raw_utf8"].encode("utf-8"))
    need(row["bytes"]==3466 and row["sha256"]=="e36d9e5e57129ddea53eee73c11c5da981dd7fe26845f71be731af7d3675d39f"
         and row["raw_utf8"].replace(new,old)==before,"only recording stopLoading fixture method")
    repaired_focused=(json.dumps(repaired["focused_input"],ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")
    need(len(repaired_focused)==409442 and sha(repaired_focused)=="c25ac58cf465200770c9ed3bd8dc9b31dbf9341fa78ba5dbac85d9e1761fcf43","exact fixture successor")
    repaired["focused_input_git"]="c636bb4d807d016e4c4bef3fe9eb0ff407e12b87"
    repaired["focused_input_bytes"]=len(repaired_focused);repaired["focused_input_sha256"]=sha(repaired_focused)
    repaired_raw=(json.dumps(repaired,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")
    need(len(repaired_raw)==CANDIDATE_BYTES and sha(repaired_raw)==CANDIDATE_SHA,"exact reviewed candidate successor")
    prior_packet["candidate"]={"git":"460d4799693c2b3e8b826b3979bd7e3e604b731a","bytes":CANDIDATE_BYTES,
                               "sha256":CANDIDATE_SHA,"raw_utf8":repaired_raw.decode("utf-8")}
    input_raw=(json.dumps(prior_packet,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")
    need(len(input_raw)==INPUT_BYTES and sha(input_raw)==INPUT_SHA,"exact reviewed build input successor")
    compressed=fixed_gzip(input_raw)
    need(gzip.decompress(compressed)==input_raw,"derived compressed input exact roundtrip")
    need(len(input_raw)==INPUT_BYTES and sha(input_raw)==INPUT_SHA,"exact independent build input")
    packet=strict(input_raw)
    need(packet["schema"]=="hepta.helper6-pocket4-independent-build-input.v1" and packet["new_phone_or_signing_authority"] is False,"P4 input scope")
    raw=packet["candidate"]["raw_utf8"].encode("utf-8")
    need(len(raw)==CANDIDATE_BYTES and sha(raw)==CANDIDATE_SHA,"exact final candidate payload")
    candidate=strict(raw)
    need(isinstance(DOWNLOAD_RESULT_SHA,str) and re.fullmatch("[0-9a-f]{64}",DOWNLOAD_RESULT_SHA)
         and isinstance(DOWNLOAD_RESULT_BYTES,int) and DOWNLOAD_RESULT_BYTES>0,"actual fixed download result must be sealed first")
    prior_download_raw=exact(PUBLIC/"RESULT.json",PRIOR_DOWNLOAD_SHA,PRIOR_DOWNLOAD_BYTES)
    prior_download=strict(prior_download_raw)
    need(prior_download["schema"]=="hepta.helper6-pocket4-fixed-public-inputs.v1"
         and prior_download["completed"] is False and prior_download["exit_code"]==1
         and prior_download["error"]=="TimeoutError: The read operation timed out"
         and prior_download["orgjson_ready"] is True and prior_download["runtime_jars_verified"] is True
         and prior_download["originals_unchanged"] is True and prior_download["sdk_dual_hash_verified"] is False
         and len(prior_download["artifacts"])==18 and "r8" not in prior_download and "sdk" not in prior_download,
         "actual first download failure and scoped successes must be preserved")
    large_raw=exact(LARGE/"RESULT.json",LARGE_FAILURE_SHA,LARGE_FAILURE_BYTES)
    large=strict(large_raw)
    need(large["schema"]=="hepta.helper6-pocket4-large-public-inputs.v1" and large["completed"] is False
         and large["exit_code"]==1 and large["error"]=="RuntimeError: TimeoutError: The read operation timed out"
         and large["r8_verified"] is True and large["sdk_dual_hash_verified"] is False
         and large["prior_verified_inputs_reused"] is True and large["prior_verified_inputs_count"]==31
         and large["orgjson_ready"] is True and large["runtime_jars_verified"] is True
         and large["originals_unchanged"] is True and len(large["sdk_attempts"])==2,
         "actual R8 completion and two incomplete SDK originals must remain a failed receipt")
    need(large["prior_result"]["path"]==str(PUBLIC/"RESULT.json")
         and large["prior_result"]["bytes"]==PRIOR_DOWNLOAD_BYTES
         and large["prior_result"]["sha256"]==PRIOR_DOWNLOAD_SHA,"large failure predecessor")
    for partial in large["sdk_attempts"]:
        need(partial["verified"] is False and partial["complete_http_body"] is False
             and partial["error"]=="TimeoutError: The read operation timed out","original SDK partial scope")
        exact(partial["path"],partial["observed_partial_sha256"],partial["bytes_written"])
    sdk_failure_raw=exact(SDK_FAILED/"RESULT.json",SDK_FAILURE_SHA,SDK_FAILURE_BYTES)
    sdk_failure=strict(sdk_failure_raw)
    need(sdk_failure["schema"]=="hepta.helper6-pocket4-sdk-public-input.v1"
         and sdk_failure["completed"] is False and sdk_failure["exit_code"]==1
         and sdk_failure["error"]=="RuntimeError: unique official SDK34 package entry"
         and sdk_failure["r8_verified"] is True and sdk_failure["sdk_dual_hash_verified"] is False
         and sdk_failure["originals_unchanged"] is True
         and sdk_failure["r8"]==large["r8"],"original official metadata path-uniqueness failure preserved")
    exact(SDK_FAILED/"source.py",SDK_FAILURE_SOURCE_SHA,26574)
    exact(SDK_FAILED/"repository/attempt-01.xml","d670de8bce15cc4ecf5d1a135f2168137ccbb8402111dfc8efcf9cb6f3b2f28f",432488)
    download_raw=exact(SDK_PUBLIC/"RESULT.json",DOWNLOAD_RESULT_SHA,DOWNLOAD_RESULT_BYTES)
    download=strict(download_raw)
    need(download["schema"]=="hepta.helper6-pocket4-sdk-public-input.v1" and download["completed"] is True
         and download["prior_verified_inputs_reused"] is True and download["prior_verified_inputs_count"]==31
         and download["orgjson_ready"] is True and download["runtime_jars_verified"] is True
         and download["r8_verified"] is True and download["r8_downloaded_here"] is False
         and download["sdk_dual_hash_verified"] is True and download["originals_unchanged"] is True
         and download["exit_code"]==0 and download["error"] is None and download["build_executed"] is False
         and download["signed"] is False and download["phone_contacted"] is False
         and download["operation_lock_accessed"] is False,"actual SDK-only completion and no-build scope")
    need(download["prior_result"]["path"]==str(PUBLIC/"RESULT.json")
         and download["prior_result"]["bytes"]==PRIOR_DOWNLOAD_BYTES
         and download["prior_result"]["sha256"]==PRIOR_DOWNLOAD_SHA
         and download["prior_large_result"]["path"]==str(LARGE/"RESULT.json")
         and download["prior_large_result"]["bytes"]==LARGE_FAILURE_BYTES
         and download["prior_large_result"]["sha256"]==LARGE_FAILURE_SHA,"two original failure receipt composition")
    need(download["prior_sdk_result"]["path"]==str(SDK_FAILED/"RESULT.json")
         and download["prior_sdk_result"]["bytes"]==SDK_FAILURE_BYTES
         and download["prior_sdk_result"]["sha256"]==SDK_FAILURE_SHA
         and download["prior_sdk_failure_flags_preserved"] is True
         and download["revision"]=="official-archive-only-r2"
         and download["repository_downloaded_here"] is False and download["gitiles_range_retried_here"] is False
         and download["gitiles_full_body_redownloaded_here"] is False,"third failure and exact archive-only successor scope")
    need(download["r8"]==large["r8"],"SDK-only receipt must preserve actual complete R8 metadata")
    for key,pin in (("r8",P4_TOOLS[3]),("sdk",P4_TOOLS[4])):
        row=download[key]
        need(row["verified"] is True and all(row[k]==pin[k] for k in ("path","bytes","sha256")),"verified artifact exact path/hash")
    need(download["sdk"]["official_git_blob"]=="923bafccf73aef996495c559e919ad8be3cabd58","SDK official Git object")
    exact(PUBLIC/"SOURCE.py","a8dbef392ef2edbe87e271513421dbc5a8b2b374ec9d4f303361f0e2b9772131",26148)
    exact(LARGE/"source.py",LARGE_SOURCE_SHA,19345)
    exact(SDK_PUBLIC/"source.py",DOWNLOAD_SOURCE_SHA,DOWNLOAD_SOURCE_BYTES)
    exact(JDK_RECEIPT["path"],JDK_RECEIPT["sha256"],JDK_RECEIPT["bytes"])
    need(candidate["schema"]=="hepta.web-helper-code6-wire4-candidate.v1"
         and candidate["helper_version_code"]==6 and candidate["helper_version_name"]=="0.6.0-web-evidence-v4"
         and candidate["wire_version"]==4 and candidate["success_wire_shape_changed"] is True
         and candidate["max_attempts"]==3 and candidate["deadline_budget_ms"]==3000
         and candidate["targeted_host_cases"]=={"scoped_navigation":23,"capture_retry":36,"typed_callback":18}
         and candidate["host_gate_executed"] is False and candidate["android_compiled"] is False
         and candidate["phone_tested"] is False,"candidate scope differs")
    base_raw=exact(BASE/"BUILD-RESULT.json",BASE_RESULT_SHA,129146);old=strict(base_raw)
    need(old["all_pass"] is True and old["version_code"]==5 and old["runtime_java_input_count"]==36
         and old["source_file_count"]==38 and old["phone_tested"] is False and old["originals_unchanged"] is True,
         "actual code5 build provenance differs")
    need(candidate["base_inputs"]==old["source_inputs"],"full 38 original source table differs")
    base_contract_original=old["base_contract_result"]
    base_contract={"path":str(BASE/"provenance/BASE-CONTRACT-RESULT.json"),"bytes":base_contract_original["bytes"],"sha256":base_contract_original["sha256"]}
    exact(base_contract["path"],base_contract["sha256"],base_contract["bytes"])
    prior_retry_original=old["contract_result"]
    prior_retry={"path":str(BASE/"provenance/CONTRACT-RESULT.json"),"bytes":prior_retry_original["bytes"],"sha256":prior_retry_original["sha256"]}
    exact(prior_retry["path"],prior_retry["sha256"],prior_retry["bytes"])
    need(old["contract_checks"]=={"capture_retry_checks":33,"capture_retry_assertions":175},"actual old callback gate")
    archived=exact(BASE/"source.tar.gz","efeda404b4f68d2d0fe4646d34e75c395b9995791fc6361d8244aa7ba2012824",92623)
    recovered={}
    with tarfile.open(fileobj=io.BytesIO(archived),mode="r:gz") as tar:
        archive_members=tar.getmembers()
        need(len(archive_members)==39,"actual 38 sources plus inventory archive")
        for item in archive_members:
            rel(item.name);need(item.isfile() and item.name not in recovered and 0<=item.size<=2*1024*1024,"bounded unique regular tar member")
            data=tar.extractfile(item).read(item.size+1)
            need(len(data)==item.size,"source archive member length");recovered[item.name]=data
    original_inventory=recovered.pop("SOURCE-INVENTORY.json")
    need(sha(original_inventory)==old["source_inventory_sha256"] and strict(original_inventory)["files"]==old["source_inputs"],"original inventory in archive")
    source={}
    for p in old["source_inputs"]:
        data=recovered.pop(p["path"])
        need(len(data)==p["bytes"] and sha(data)==p["sha256"],"archive source bytes differ")
        source[p["path"]]=data
    need(not recovered,"archive has unlisted source")
    need(len(source)==38,"exact original source count")
    originals_rows=rows(source)
    overlay={}
    for f in candidate["files"]:
        p=f["path"];rel(p);need(p not in overlay,"duplicate candidate source")
        data=f["raw_utf8"].encode("utf-8");need(len(data)==f["bytes"] and sha(data)==f["sha256"],"candidate member bytes differ")
        if p in source:need(f.get("base_sha256",sha(source[p]))==sha(source[p]),"overlay base source differs")
        overlay[p]=data
    runtime_paths=set(source)|set(NEW_RUNTIME);need(len(runtime_paths)==43,"exact helper runtime source set")
    need(set(overlay)==set(EXPECTED_OVERLAY) and len(overlay)==20,"exact twenty runtime overlays including installed identity")
    for p in runtime_paths:
        if p in overlay:source[p]=overlay[p]
        else:need(p in source,"new runtime source missing")
    focused=candidate["focused_input"]
    focused_raw=(json.dumps(focused,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")
    need(len(focused_raw)==candidate["focused_input_bytes"] and sha(focused_raw)==candidate["focused_input_sha256"]
         and focused["schema"]=="hepta.helper6-scoped-navigation-focused-input.v2"
         and focused["source_only"] is True and focused["actual_phone"] is False
         and focused["transport_doubles_not_real_binder_or_fd"] is True,
         "exact focused source bundle with explicit doubles scope")
    focused_rows={}
    for f in focused["files"]:
        p=f["path"];rel(p);need(p not in focused_rows,"unique focused source")
        data=f["raw_utf8"].encode("utf-8")
        need(len(data)==f["bytes"] and sha(data)==f["sha256"],"focused source bytes differ")
        if p.startswith("src/") or p.startswith("assets/"):
            need(p in source and source[p]==data,"focused production source must equal actual runtime byte-for-byte")
        else:need(p.startswith("tests/") and p.endswith(".java"),"only bounded Java fixtures")
        focused_rows[p]=data
    need(len(focused_rows)==56 and sum(p.endswith(".java") for p in focused_rows)==55,"actual focused closure count")
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
    need(len(source)==43 and sum(p.endswith(".java") for p in source)==41,"new runtime inventory differs")
    source_rows=rows(source)
    need(source_rows==prior_failure["source_inputs"],"all43 production files remain byte-identical to failed first build")
    for tool in P4_TOOLS:exact(tool["path"],tool["sha256"],tool["bytes"])
    java=JAVA_HOME/"bin/java";javac=JAVA_HOME/"bin/javac"
    tools={pathlib.Path(x["path"]).name:pathlib.Path(x["path"]) for x in P4_TOOLS}
    aapt=tools["aapt2"];android=tools["android.jar"];r8=tools["r8-8.13.17.jar"]
    json_raw=exact(JSON_JAR,JSON_SHA,78332)
    jars=[];runtime_local=[]
    for i,row in enumerate(old["runtime_library_jars"]):
        p=PUBLIC/"runtime"/("%02d"%i)/"classes.jar"
        exact(p,row["sha256"],row["bytes"]);jars.append(p)
        runtime_local.append({"path":str(p),"bytes":row["bytes"],"sha256":row["sha256"]})
    need(len(jars)==14 and JSON_JAR not in jars,"exact 14 runtime jars; host JSON cannot enter APK")
    old_apk=old["unsigned_apk"]
    old_apk_raw=exact(BASE/"helper-unsigned.apk",old_apk["sha256"],old_apk["bytes"]);old_payload=zipper(old_apk_raw)
    need(members(old_payload)==old["compiled_members"] and len(old_payload)==372,"actual old compiled member map differs")
    resource_raw=packet["resource_packet"]["raw_utf8"].encode("utf-8")
    need(len(resource_raw)==RESOURCE_PACKET_BYTES and sha(resource_raw)==RESOURCE_PACKET_SHA,"current actual resource packet")
    resource_packet=strict(resource_raw);need(len(resource_packet["files"])==3,"three current resource files only")
    resource_zips=[];resource_pins=[]
    resource_expected={"00":(256,"70f2f5c25be926ea951c91197e0ed782233f2f2dc3dbffcf9e555f663ba99a01"),
        "05":(107644,"ec1008aab3ff45fe62029d1ea981a95d316b3c2de82b2e3ef0d1db539c61d8c8"),
        "09":(256,"70f2f5c25be926ea951c91197e0ed782233f2f2dc3dbffcf9e555f663ba99a01")}
    for record,name in zip(resource_packet["files"],("00","05","09")):
        expected_path="/Users/qianqi/Documents/Codex/2026-11-11/hepta-local-007f/v54-web-helper-code5-build-r1/resources/"+name+"/compiled-res.zip"
        need(record["host"]=="mac" and record["path"]==expected_path,"fixed prior successful build resource path")
        data=base64.b64decode(record["data_base64"],validate=True)
        need(base64.b64encode(data).decode("ascii")==record["data_base64"]
             and (len(data),sha(data))==resource_expected[name]
             and (record["bytes"],record["sha256"])==resource_expected[name],"exact current resource archive")
        zipper(data);resource_zips.append((pathlib.Path(expected_path),data))
        resource_pins.append({k:v for k,v in record.items() if k!="data_base64"})
    identity_input=candidate["installed_identity_input"]
    identity_raw=(json.dumps(identity_input,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode("utf-8")
    need(len(identity_raw)==candidate["installed_identity_input_bytes"] and sha(identity_raw)==candidate["installed_identity_input_sha256"]
         and identity_input["schema"]=="hepta.helper6-installed-apk-identity-focused-input.v1"
         and candidate["installed_identity_host_cases"]==10,"exact helper identity gate input")
    identity_source=source["src/org/trillionnium/hepta/webhelper/InstalledIdentity.java"]
    need(len(identity_source)==7692 and sha(identity_source)=="0743b10aff01040b52235d5c57691cc1d864acd6fcef1aa626317585894cc39c","exact identity fix runtime")
    template=identity_input["template"]["raw_utf8"]
    need(len(template.encode("utf-8"))==identity_input["template"]["bytes"]
         and sha(template.encode("utf-8"))==identity_input["template"]["sha256"],"identity template bytes")
    generated_identity=template
    for method,marker,prefix in zip(identity_input["projected_methods"],("/* EXACT_FILE_SHA */","/* EXACT_STAMP */"),
            ("private static String fileSha(","private static final class Stamp")):
        method_raw=method["raw_utf8"].encode("utf-8")
        need(len(method_raw)==method["bytes"] and sha(method_raw)==method["sha256"]
             and method["raw_utf8"].startswith(prefix) and identity_source.count(method_raw)==1
             and generated_identity.count(marker)==1,"actual unique full identity method projection")
        generated_identity=generated_identity.replace(marker,method["raw_utf8"])
    identity_generated=generated_identity.encode("utf-8")
    need(identity_generated==identity_input["generated"]["raw_utf8"].encode("utf-8")
         and len(identity_generated)==identity_input["generated"]["bytes"]
         and sha(identity_generated)==identity_input["generated"]["sha256"],"identity generated source exact")
    actual_stat_raw=packet["actual_apk_stat"]["raw_utf8"].encode("utf-8")
    need(len(actual_stat_raw)==10724 and sha(actual_stat_raw)=="221fc909eb5c23f20b29f85ce0c19db971e2f12a565760e2a14550cf0705efcd","exact original APK stat receipt copy")
    actual_stat=strict(actual_stat_raw)
    before=[x for x in actual_stat["commands"] if x["label"]=="apk-lstat-before"]
    after=[x for x in actual_stat["commands"] if x["label"]=="apk-lstat-after"]
    need(len(before)==len(after)==1 and before[0]["returncode"]==after[0]["returncode"]==0
         and before[0]["stdout"]["text"]==after[0]["stdout"]["text"],"original stat before/after")
    stat_text=identity_input["actual_stat"]["raw_utf8"].encode("utf-8")
    need(stat_text==before[0]["stdout"]["text"].encode("utf-8")
         and len(stat_text)==433 and sha(stat_text)=="6c1dc85d204e0d806425069fc20ada3a0f5795ee2ffc3b0bf4218f5ed37f8c04","exact actual stat fixture values")
    need(not ROOT.exists() and all(not p.is_symlink() for p in [ROOT,*ROOT.parents]),"independent new build root required")
    unchanged()
    # FIRST MUTATION. Outside handler: a late identical invocation cannot write the winning result.
    ROOT.mkdir(mode=0o700)
    result={"schema":"hepta.web-helper-code6-android-build.v1","all_pass":False,"exit_code":1,"started_epoch":time.time(),
        "base_helper_build_sha256":BASE_RESULT_SHA,"candidate_payload_sha256":CANDIDATE_SHA,
        "version_code":6,"version_name":"0.6.0-web-evidence-v4","wire_version":4,"source_inputs":source_rows,
        "source_file_count":43,"runtime_java_input_count":41,"runtime_library_jars":runtime_local,
        "build_tools":P4_TOOLS,"java_release":8,"compile_sdk":34,"target_sdk":35,"min_sdk":30,
        "main_app_changed":False,"original_code5_changed":False,"execution_host":"pocket4",
        "original_mac_operation_status":"unknown","build_input_sha256":INPUT_SHA,"resource_archive_reads_current":resource_pins,
        "prior_failed_build":{"path":str(prior_root/"RESULT.json"),"bytes":len(prior_failure_raw),"sha256":sha(prior_failure_raw),"original_all_pass":False,"original_exit_code":1},
        "fixture_only_compile_api_repair":"WebView.stopLoading recording test double; all original assertions unchanged",
        "all43_runtime_sources_preserved_from_failed_r1":True,
        "resource_archive_historical_hashes_claimed":False,"external_zipalign_used":False,
        "jdk_prior_receipt":JDK_RECEIPT,"download_result":{"path":str(SDK_PUBLIC/"RESULT.json"),"bytes":DOWNLOAD_RESULT_BYTES,"sha256":DOWNLOAD_RESULT_SHA},
        "prior_sdk_download_failure":{"path":str(SDK_FAILED/"RESULT.json"),"bytes":SDK_FAILURE_BYTES,"sha256":SDK_FAILURE_SHA,"original_exit_code":1,"r8_verified":True,"sdk_dual_hash_verified":False},
        "prior_large_download_failure":{"path":str(LARGE/"RESULT.json"),"bytes":LARGE_FAILURE_BYTES,"sha256":LARGE_FAILURE_SHA,"original_exit_code":1,"r8_verified":True,"sdk_dual_hash_verified":False},
        "prior_download_failure":{"path":str(PUBLIC/"RESULT.json"),"bytes":PRIOR_DOWNLOAD_BYTES,"sha256":PRIOR_DOWNLOAD_SHA,"original_exit_code":1},
        "base_contract_result":base_contract,"base_contracts_rerun":False,
        "prior_capture_retry_result":prior_retry,"prior_callback_cases_preserved_and_rerun":33,"signed":False,"installed":False,
        "phone_tested":False,"actual_mi_dom_seen":False,"business_verified":False,
        "origin_runtime_verified":False,"storage_isolation_runtime_verified":False,"orphan_recovery_runtime_verified":False,
        "old_resource_payloads_preserved":False,"originals_unchanged":False,"steps":[],"known_limitations":candidate["known_limitations"]}
    def run(name,argv,timeout=120):
        t=time.monotonic();o=ROOT/(name+".stdout");e=ROOT/(name+".stderr")
        p=None;rc=None;timed_out=False;forced=False;wait_exception=None
        cleanup_attempted=False;group_absent=None;cleanup_error=None
        with o.open("xb") as stdout,e.open("xb") as stderr:
            try:
                p=subprocess.Popen([str(x) for x in argv],cwd=str(ROOT),stdin=subprocess.DEVNULL,
                    stdout=stdout,stderr=stderr,start_new_session=True)
                rc=p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                try:os.killpg(p.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:rc=p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    forced=True
                    try:os.killpg(p.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    rc=p.wait(timeout=5)
            except BaseException as error:
                wait_exception=type(error).__name__+": "+str(error)
            finally:
                # A failed leader may have exited while owned descendants remain.
                # The new session's original process group is cleaned on every
                # failure/exception; no compiler retry or new group is created.
                if p is not None and (rc!=0 or timed_out or wait_exception is not None or p.poll() is None):
                    cleanup_attempted=True
                    try:os.killpg(p.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    except OSError as error:cleanup_error=type(error).__name__+": "+str(error)
                    if p.poll() is None:
                        try:rc=p.wait(timeout=5)
                        except subprocess.TimeoutExpired:pass
                        except BaseException as error:cleanup_error=type(error).__name__+": "+str(error)
                    try:
                        os.killpg(p.pid,signal.SIGKILL);forced=True
                    except ProcessLookupError:pass
                    except OSError as error:cleanup_error=type(error).__name__+": "+str(error)
                    if p.poll() is None:
                        try:rc=p.wait(timeout=5)
                        except subprocess.TimeoutExpired:cleanup_error="owned leader exit not observed after bounded cleanup"
                        except BaseException as error:cleanup_error=type(error).__name__+": "+str(error)
                    try:os.killpg(p.pid,0);group_absent=False
                    except ProcessLookupError:group_absent=True
                    except OSError as error:
                        group_absent=None;cleanup_error=type(error).__name__+": "+str(error)
        out=exact(o,remember=False);err=exact(e,remember=False)
        need(len(out)<=4*1024*1024 and len(err)<=4*1024*1024,"bounded build log")
        exit_observed=p is not None and p.poll() is not None
        item={"name":name,"argv":[str(x) for x in argv],"pid":None if p is None else p.pid,
              "exit_code":rc,"forced":forced,"timed_out":timed_out,"wait_exception":wait_exception,
              "exit_observed":exit_observed,"elapsed_seconds":time.monotonic()-t,
              "owned_group_cleanup_attempted":cleanup_attempted,"owned_group_absent_observed_after_failure":group_absent,
              "owned_group_cleanup_error":cleanup_error,
              "stdout":{"path":str(o),"bytes":len(out),"sha256":sha(out)},"stderr":{"path":str(e),"bytes":len(err),"sha256":sha(err)}}
        result["steps"].append(item)
        need(type(rc) is int and rc==0 and exit_observed and not timed_out and not forced
             and wait_exception is None and cleanup_error is None,"actual build stage failed: "+name)
        return out
    try:
        put(ROOT/"BUILD.py",executing);put(ROOT/"CANDIDATE.json",raw)
        put(ROOT/"BUILD-INPUT.json",input_raw);put(ROOT/"BUILD-INPUT.json.gz",compressed)
        put(ROOT/"DOWNLOAD-RESULT.json",download_raw);put(ROOT/"PRIOR-DOWNLOAD-FAILURE.json",prior_download_raw)
        put(ROOT/"PRIOR-LARGE-DOWNLOAD-FAILURE.json",large_raw)
        put(ROOT/"PRIOR-SDK-DOWNLOAD-FAILURE.json",sdk_failure_raw)
        put(ROOT/"RESOURCE-ARCHIVE-READS.json",resource_raw)
        put(ROOT/"ORIGINAL-APK-STAT.json",actual_stat_raw)
        put(ROOT/"BASE-BUILD-RESULT.json",base_raw)
        for p,data in sorted(source.items()):put(ROOT/"source"/rel(p),data)
        inventory=encoded({"schema":"hepta.web-helper-source-inventory.v1","files":source_rows})
        put(ROOT/"SOURCE-INVENTORY.json",inventory);result["source_inventory_sha256"]=sha(inventory)
        # One focused host compile. Runtime rows are exact final bytes; Android,
        # parcel and record fixtures remain explicitly test doubles.
        put(ROOT/"FOCUSED-INPUT.json",focused_raw)
        focused_paths=[]
        for p,data in sorted(focused_rows.items()):
            target=ROOT/"focused-source"/rel(p);put(target,data)
            if p.endswith(".java"):focused_paths.append(target)
        focused_classes=ROOT/"focused-classes";focused_classes.mkdir()
        run("focused-javac",[javac,"--release","8","-encoding","UTF-8","-proc:none",
            "-cp",JSON_JAR,"-d",focused_classes,*focused_paths],120)
        host_cp=os.pathsep.join(str(p) for p in [focused_classes,JSON_JAR])
        scope_path=ROOT/"SCOPED-NAVIGATION-RESULT.json"
        run("scoped-navigation",[java,"-cp",host_cp,"org.trillionnium.hepta.webhelper.WebScopedNavigationHostTest",scope_path],40)
        scope_raw=exact(scope_path,remember=False);scope=strict(scope_raw)
        need(scope["all_pass"] is True and scope["cases"]==23
             and scope["synthetic_css_hit_geometry_navigation_fixtures"] is True
             and scope["phone_tested"] is False and scope["business_verified"] is False,
             "actual explicit-scope/ARM/navigation pure gate")
        callback_path=ROOT/"CAPTURE-RETRY-RESULT.json"
        run("capture-retry",[java,"-cp",host_cp,"org.trillionnium.hepta.webhelper.CaptureRetryHostTest",
            ROOT/"source/assets/readonly_dom.js",callback_path],40)
        callback_raw=exact(callback_path,remember=False);callback=strict(callback_raw)
        need(callback["all_pass"] is True and callback["cases"]==36
             and callback["phone_tested"] is False and callback["javascript_executed"] is False
             and callback["business_verified"] is False,"actual complete 36-case callback gate")
        typed_raw=run("typed-callback",[java,"-cp",host_cp,"org.trillionnium.hepta.webhelper.RemoteReplyHostTest"],40)
        typed=strict(typed_raw)
        need(typed["all_pass"] is True and typed["case_count"]==18
             and typed["production_remote_reply_executed"] is True
             and typed["binder_parcel_record_test_doubles"] is True
             and typed["android_binder_exercised"] is False and typed["real_fd_exercised"] is False
             and typed["phone_tested"] is False and typed["business_verified"] is False,"actual typed callback gate")
        typed_ref=put(ROOT/"TYPED-CALLBACK-RESULT.json",typed_raw)
        put(ROOT/"IDENTITY-INPUT.json",identity_raw)
        identity_java=ROOT/"identity-source/HelperInstalledApkIdentityHostTest.java"
        put(identity_java,identity_generated)
        stat_path=ROOT/"identity-source/actual-apk-stat.txt";put(stat_path,stat_text)
        identity_classes=ROOT/"identity-classes";identity_classes.mkdir()
        run("installed-identity-javac",[javac,"--release","8","-encoding","UTF-8","-proc:none","-d",identity_classes,identity_java],60)
        identity_path=ROOT/"INSTALLED-IDENTITY-RESULT.json"
        run("installed-identity-cases",[java,"-cp",identity_classes,"HelperInstalledApkIdentityHostTest",
             stat_path,ROOT/"identity-io",identity_path],40)
        identity_result_raw=exact(identity_path,remember=False);identity_result=strict(identity_result_raw)
        need(identity_result["schema"]=="hepta.helper-installed-apk-identity-host-checks.v1"
             and all(identity_result.get(k)==v for k,v in identity_input["expected"].items()),
             "actual helper identity gate and explicit syscall-double scope")
        result["installed_identity_contract_result"]={"path":str(identity_path),"bytes":len(identity_result_raw),"sha256":sha(identity_result_raw)}
        result["installed_identity_method_projections"]=[{k:v for k,v in m.items() if k!="raw_utf8"} for m in identity_input["projected_methods"]]
        contract={"schema":"hepta.web-helper6-focused-contracts.v1","all_pass":True,
            "installed_identity_cases":identity_result["cases"],"installed_identity_assertions":identity_result["assertions"],
            "installed_identity_android_syscalls_doubled":True,"installed_identity_actual_apk_rehashed_here":False,
            "installed_identity_result":result["installed_identity_contract_result"],
            "scoped_navigation_cases":scope["cases"],"scoped_navigation_assertions":scope["assertions"],
            "capture_retry_cases":callback["cases"],"capture_retry_assertions":callback["assertions"],
            "typed_callback_cases":typed["case_count"],"typed_callback_assertions":typed["assertion_count"],
            "actual_host_java_inputs":len(focused_paths),"prior_callback_cases_preserved_and_rerun":33,
            "old_authority_recovery_groups_rerun":False,
            "scoped_navigation_result":{"path":str(scope_path),"bytes":len(scope_raw),"sha256":sha(scope_raw)},
            "capture_retry_result":{"path":str(callback_path),"bytes":len(callback_raw),"sha256":sha(callback_raw)},
            "typed_callback_result":typed_ref,"synthetic_css_hit_geometry_navigation_fixtures":True,
            "android_binder_exercised":False,"real_fd_exercised":False,"javascript_executed":False,
            "phone_tested":False,"actual_mi_detail_seen":False,"business_verified":False}
        contract_raw=encoded(contract);result["contract_result"]=put(ROOT/"CONTRACT-RESULT.json",contract_raw)
        result["contract_checks"]={k:v for k,v in contract.items() if k.endswith("_cases") or k.endswith("_assertions")}
        result["focused_host_java_inputs"]=len(focused_paths)
        need(rows({p:exact(ROOT/"focused-source"/p,remember=False) for p in focused_rows})==rows(focused_rows),
             "focused sources changed during tests")
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
        changed={"AndroidManifest.xml","classes.dex","assets/readonly_dom.js"}
        need(payload["assets/readonly_dom.js"]==source["assets/readonly_dom.js"],"exact explicit wire4 DOM observer")
        for n in set(payload)-changed:need(payload[n]==old_payload[n],"inherited library payload changed")
        need(not any(n.startswith("lib/") or n.endswith(".so") for n in payload),"helper cannot acquire native libraries")
        unsigned=ROOT/"helper-unsigned.apk"
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,"w") as z:
            for n,data in sorted(payload.items()):
                info=zipfile.ZipInfo(n,(1980,1,1,0,0,0));info.external_attr=0o100644<<16
                info.compress_type=zipfile.ZIP_STORED if n=="resources.arsc" else zipfile.ZIP_DEFLATED
                if info.compress_type==zipfile.ZIP_STORED:
                    padding=(-(buffer.tell()+30+len(n.encode("utf-8"))+4))%4
                    info.extra=struct.pack("<HH",0xffff,padding)+b"\0"*padding
                z.writestr(info,data)
        put(unsigned,buffer.getvalue())
        result["alignment_implementation"]="python.zipfile.valid-extra-tlv.resource-stored-four-byte.v1"
        unsigned_raw=exact(unsigned,remember=False)
        need(len(unsigned_raw)<=2*1024*1024 and zipper(unsigned_raw)==payload,"exact bounded complete APK readback")
        result["unsigned_resource_layout"]=layout(unsigned_raw)
        badging=run("badging",[aapt,"dump","badging",unsigned]).decode("utf-8")
        permissions=run("permissions",[aapt,"dump","permissions",unsigned]).decode("utf-8")
        need("package: name='org.trillionnium.hepta.webhelper'" in badging and "versionCode='6'" in badging
             and "versionName='0.6.0-web-evidence-v4'" in badging,"actual package/version differs")
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
        result["success_capture_shape_unchanged"]=False
        result["capture_schema"]="hepta.owned-webview-origin-dom.v2"
        result["raw_dom_snapshots_preserved"]=True
        result["actual_top_document_javascript_executed"]=False
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
        "execution_host","original_mac_operation_status","external_zipalign_used","installed_identity_contract_result",
        "source_archive","source_inventory_sha256","unsigned_resource_layout","permissions","contract_result","contract_checks",
        "originals_unchanged","old_resource_payloads_preserved","elapsed_seconds","error","phone_tested","business_verified",
        "storage_isolation_runtime_verified","origin_runtime_verified","known_limitations")}
    summary["result"]=result_ref
    summary["result_fixed_gzip"]={"bytes":len(result_fixed),"sha256":sha(result_fixed),"base64_path":str(ROOT/"RESULT.json.fixed.gz.base64")}
    put(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,ensure_ascii=False,separators=(",",":")),flush=True)
    return result["exit_code"]
if __name__=="__main__":raise SystemExit(main())
