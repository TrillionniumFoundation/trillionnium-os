#!/usr/bin/env python3
"""Isolated exact v54 final host staging; all original 101 checks and 18 stages, no phone/signing."""
import ast,gzip,hashlib,json,os,re,signal,stat,struct,subprocess,sys,tarfile,time
from pathlib import Path,PurePosixPath
MODE="host"
BASE=Path("/home/alex/hepta-local-007f-20261111/v53-main-host-r2/source")
ROOT=Path("/home/alex/hepta-local-007f-20261111/v54-main-host-r4")
SOURCE=ROOT/"source"
PAYLOAD=Path("/home/alex/hepta-local-007f-20261111/v54-main-final-host-r3.input.json.gz")
KEY="007f-v54-main-host-r4"
BASE_COMMIT="7dee83d838b2c76b3abe3a3e61d7837316f40853"
INPUT_SHA="e195da919e53c6aa36c31f8b0f0a96f23ef67d895f2860b61fb72e73bd29cf6e"
GZIP_SHA="62fffc6c3813848236ac44044841f9ba2b586f2c87add67f795f4f18860bd398"
INVENTORY_SHA="8675c0c438cdf10f599c23a3a6305a5678fd59270f09b4f73a43f7a67bf2237d"
def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def regular(path):
    s=path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not path.is_symlink(),"independent regular file required: "+str(path))
    return s
def read(path,limit=64<<20):
    s=regular(path);need(0<=s.st_size<=limit,"bounded regular file: "+str(path));raw=path.read_bytes()
    t=regular(path);need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns) and len(raw)==s.st_size,"file changed while read: "+str(path));return raw
def row(path):
    raw=read(path);return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
def pathkey(name):
    p=PurePosixPath(name);need(isinstance(name,str) and not p.is_absolute() and ".." not in p.parts and str(p)==name and name not in ("",".") and "\\" not in name,"safe relative source path");return name
def entries(root):
    need(root.is_dir() and not root.is_symlink(),"existing real source root")
    result={}
    for p in sorted(root.rglob("*")):
        need(not p.is_symlink(),"source symlink: "+str(p))
        if p.is_dir():continue
        result[p.relative_to(root).as_posix()]=read(p)
    return result
def inventory(values):
    return [{"path":p,"bytes":len(raw),"sha256":sha(raw)} for p,raw in sorted(values.items(),key=lambda v:Path(v[0]))]
def encoded(value):return (json.dumps(value,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
def put(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return row(path)
def jput(path,value):return put(path,encoded(value))
def tool_record(path):
    s=regular(path);digest=hashlib.sha256();count=0
    with path.open("rb") as f:
        while True:
            chunk=f.read(8<<20)
            if not chunk:break
            count+=len(chunk);digest.update(chunk)
    t=regular(path)
    need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns) and count==s.st_size,"tool changed while hashing")
    return {"path":str(path),"bytes":count,"sha256":digest.hexdigest()}
def resolve_tool(path,within=None):
    real=path.resolve(strict=True)
    if within is not None:
        within=within.resolve(strict=True)
        need(real==within or within in real.parents,"tool escaped cached directory")
    return dict(tool_record(real),requested_path=str(path))
started=time.time()
need(len(sys.argv)==3,"exact stage source and canonical fixture patch; original input is immutable")
packed=read(PAYLOAD,1<<20)
need(len(packed)==322081 and sha(packed)==GZIP_SHA,"exact original r3 compressed payload")
predecessor_raw=gzip.decompress(packed)
need(len(predecessor_raw)==1129628 and sha(predecessor_raw)=="778a041fda449e483ecc2cd5aab8619c41f5bd0d3f8e8c8fca1979bd1bd72e76","exact original failed r3 candidate")
data=json.loads(predecessor_raw.decode("utf-8"))
need(data["expected_source_inventory_sha256"]=="4784f89aaf4d26f1a9a42bbdb4549a735d6d937db8adcd645e2bb95dd664a1e7","original r3 inventory")
patch_raw=sys.argv[2].encode("utf-8")
need(len(patch_raw)==37862 and sha(patch_raw)=="27b24b90fe4d288ee986750d3c14a900e0bd6a3776be852de67e1fc05402ad43"
    and blob(patch_raw)=="f5289ad219825e14e0ede26d49d286c0d6f5092f","exact reviewed three-entry patch")
patch=json.loads(patch_raw)
need(patch["schema"]=="hepta.v54-canonical-test-fixture-compiler-path-fix.v1"
    and patch["base_candidate_sha256"]==sha(predecessor_raw)
    and patch["base_candidate_git_blob"]=="2db21af5242614cd946d7906b2ea8b3169f1f51f","exact patch predecessor")
failed_root=Path("/home/alex/hepta-local-007f-20261111/v54-main-host-r3")
failed_originals=[]
def failed_original(path,size,digest):
    b=read(path);need(len(b)==size and sha(b)==digest,"original r3 failure differs: "+str(path))
    failed_originals.append((path,b));return b
failed_stage_raw=failed_original(failed_root/"STAGE-RESULT.json",7674,"895145f1b2316dea01b1fc23658d030d75cd7645848c4271af3cfe4d284e6b87")
failed_stage=json.loads(failed_stage_raw)
need(failed_stage["all_pass"] is False and failed_stage["exit_code"]==1 and failed_stage["source_unchanged"] is True
    and failed_stage["base_source_unchanged"] is True and failed_stage["source_inventory_sha256"]==data["expected_source_inventory_sha256"]
    and failed_stage["source_input_payload_sha256"]==sha(predecessor_raw) and failed_stage["host_check_count"]==1,"actual first-compile failed r3")
failed_host_raw=failed_original(failed_root/"host-checks/HOST-CHECKS.json",69330,"3f403c1e6b191f03dad6e447a1003e9e37c9aa1561d1031558631245b7869024")
failed_host=json.loads(failed_host_raw)
need(failed_host["all_pass"] is False and len(failed_host["checks"])==1 and failed_host["checks"][0]["name"]=="java-compile"
    and failed_host["checks"][0]["exit_code"]!=0 and "auxiliary class WebTaskDomain" in failed_host["error"]
    and "-Werror" in failed_host["error"],"actual auxiliary-class warning retained")
failed_original(failed_root/"original-host-checks.stdout",1402,"79faa35cd6b8d6285249faf078538e5b77edc57e00cd66958d3555dc19509285")
failed_original(failed_root/"original-host-checks.stderr",0,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
failed_original(failed_root/"SOURCE-INVENTORY.json",102673,"4784f89aaf4d26f1a9a42bbdb4549a735d6d937db8adcd645e2bb95dd664a1e7")
failed_original(failed_root/"SOURCE-BLOB-MAP.json",147796,"58ae8af05338d86365918171bdc180f51db47e8b767be43189c02ffb50627f2b")
need(failed_original(failed_root/"INPUT.json",1129628,sha(predecessor_raw))==predecessor_raw,"actual failed input")
failed_before=entries(failed_root/"source")
old_rows={r["path"]:r for r in data["base_files"]}
old_rows.update({r["path"]:r for r in data["files"]})
need(len(old_rows)==589 and set(failed_before)==set(old_rows),"all original failed589 sources")
for name,b in failed_before.items():
    r=old_rows[name]
    need(len(b)==r["bytes"] and sha(b)==r["sha256"] and blob(b)==r["git_blob_sha"],"original failed source differs: "+name)
allowed=["tools/run_host_checks.py","tests/exact-admission/prepare_fixture.py","tests/qualification-scope/prepare_fixture.py"]
need([f["path"] for f in patch["files"]]==allowed,"only three fixed Python entry points")
by_path={f["path"]:f for f in data["files"]}
for f in patch["files"]:
    name=pathkey(f["path"]);item=by_path[name];b=item["raw_utf8"].encode("utf-8")
    need(len(b)==f["base_bytes"] and sha(b)==f["base_sha256"] and blob(b)==f["base_git_blob_sha"],"exact patched predecessor")
    value=item["raw_utf8"]
    for change in f["replacements"]:
        need(type(change["count"]) is int and change["count"]==1 and value.count(change["before"])==1,"unique literal fixture change")
        value=value.replace(change["before"],change["after"])
    need(value==f["raw_utf8"],"literal patch must reproduce exact reviewed bytes")
    inverse=value
    for change in reversed(f["replacements"]):
        need(inverse.count(change["after"])==1,"unique inverse fixture change")
        inverse=inverse.replace(change["after"],change["before"])
    need(inverse==item["raw_utf8"],"fixture change must reverse exactly")
    b=value.encode("utf-8")
    need(len(b)==f["bytes"] and sha(b)==f["sha256"] and blob(b)==f["git_blob_sha"],"reviewed new fixture bytes")
    item["raw_utf8"]=value;item["bytes"]=f["bytes"];item["sha256"]=f["sha256"];item["git_blob_sha"]=f["git_blob_sha"]
    data["post_compile_host_fixture_delta"]["patches"].append({"git_blob":"f5289ad219825e14e0ede26d49d286c0d6f5092f",
        "bytes":37862,"sha256":"27b24b90fe4d288ee986750d3c14a900e0bd6a3776be852de67e1fc05402ad43","path":name,
        "base_sha256":f["base_sha256"],"new_sha256":f["sha256"],"patches":f["replacements"]})
data["post_compile_host_fixture_delta"]["only_changed_paths"]=sorted(set(data["post_compile_host_fixture_delta"]["only_changed_paths"]+allowed),key=Path)
data["scope"]["host_runner_dependency_closure_fix"]="two pure-Goal input lists and three exact legacy WebTaskDomain compiler copies; no production/Java assertions changed"
data["fixture_compile_basename_fix"]={"schema":"hepta.v54-host-fixture-basename-derivation.v1",
    "base_payload_git_blob":"2db21af5242614cd946d7906b2ea8b3169f1f51f","base_payload_bytes":1129628,
    "base_payload_sha256":sha(predecessor_raw),"patch_git_blob":"f5289ad219825e14e0ede26d49d286c0d6f5092f","patch_bytes":37862,
    "patch_sha256":sha(patch_raw),"actual_failed_host_stage":patch["actual_failed_host_stage"],"only_changed_paths":allowed,
    "production_changed":False,"java_source_or_assertions_changed":False,"android_compiler_inputs_changed":False}
data["expected_source_inventory_sha256"]=INVENTORY_SHA
raw=encoded(data)
need(len(raw)==1139016 and sha(raw)==INPUT_SHA and blob(raw)=="27cec65a7bf9326dab67431bcd9e17b4992460d8","exact derived complete r4 candidate")
derivation={"schema":"hepta.v54-r3-failure-preserving-source-derivation.v1",
    "predecessor_input_file":row(PAYLOAD),"predecessor_payload_sha256":sha(predecessor_raw),
    "patch_bytes":len(patch_raw),"patch_sha256":sha(patch_raw),"final_payload_bytes":len(raw),"final_payload_sha256":sha(raw),
    "actual_failed_stage_sha256":sha(failed_stage_raw),"old_source_count":len(failed_before),
    "old_failure_files":[{"path":str(p),"bytes":len(b),"sha256":sha(b)} for p,b in failed_originals],
    "only_changed_paths":allowed,"production_changed":False}
need(data["schema"]=="hepta.v54-main-source-candidate.v1" and data["base_commit"]==BASE_COMMIT,"actual main53 source lineage")
need(data["expected_source_file_count"]==589 and data["expected_source_inventory_sha256"]==INVENTORY_SHA,"final589 inventory")
delta=data["post_compile_host_fixture_delta"]
need(delta["base_inventory_sha256"]=="2eb66bad5e487129f69c4f18c65f87bbd5e22c2568f163a3ad9fd982da95b1e6"
    and delta["actual_android_stage_sha256"]=="a037b49f05ea48caccb2902b95bbb2314a5f767e230138dd14ae3a16851ee4b2"
    and delta["production_changed"] is False and delta["java_assertions_changed"] is False
    and delta["only_changed_paths"]==["tests/exact-admission/prepare_fixture.py","tests/notes-owner-intent/run_host_tests.py",
        "tests/owner-grammar/run_host_tests.py","tests/qualification-scope/prepare_fixture.py","tools/run_host_checks.py"],
    "only five declared post-compile Python fixture corrections")
base_rows=data["base_files"];need(len(base_rows)==570 and len(data["files"])==48,"exact base570 and48 overlays")
before=entries(BASE)
need(len(before)==570 and len({r["path"] for r in base_rows})==570 and set(before)=={r["path"] for r in base_rows},"complete actual base set")
for r in base_rows:
    name=pathkey(r["path"]);b=before[name]
    need(len(b)==r["bytes"] and sha(b)==r["sha256"] and blob(b)==r["git_blob_sha"],"actual7dee base bytes/Git differ: "+name)
need(sha(encoded(inventory(before)))==data["base_source_inventory_sha256"]=="f880e49f504d05d32eb3ba76127b14f30ee5434ca745b9929815deabc4bbf92f","actual complete main53 inventory")
target=dict(before);names=set()
for item in data["files"]:
    name=pathkey(item["path"]);b=item["raw_utf8"].encode("utf-8")
    need(name not in names and len(b)==item["bytes"] and sha(b)==item["sha256"] and blob(b)==item["git_blob_sha"],"exact unique final source overlay")
    need(item["base_sha256"]==(sha(before[name]) if name in before else None),"actual source predecessor")
    if name.endswith(".py"):ast.parse(b.decode("utf-8"),filename=name)
    names.add(name);target[name]=b
need(len(target)==589 and sha(encoded(inventory(target)))==INVENTORY_SHA,"complete final source map")
need(sha(target["build_mac.py"])=="dca1f29ff9978ff3e99e0f9c02055247140bf01f086ac3231f6b63f160da706a"
    and sha(target["assemble_pocket4.py"])=="5905861e913097b906262ae1b0deee7f97738bc25b9b7670e8e744710c35b378","existing build and permission assembler sources")
need(target["src/org/trillionnium/hepta/local/BackgroundUiPreferences.java"]==before["src/org/trillionnium/hepta/local/BackgroundUiPreferences.java"],"actual saved preferences retained")
need(sha(target["src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java"])=="1e08a7af60dbab6ce1ff53095e2039696d1de886b0fef3434b44a9f40122f02c","exact code5/v3 peer")
import xml.etree.ElementTree as ET
manifest=ET.fromstring(target["AndroidManifest.xml"]);android="{http://schemas.android.com/apk/res/android}"
need(manifest.get("package")=="org.trillionnium.hepta.local" and manifest.get(android+"versionCode")=="54"
    and manifest.get(android+"versionName")=="0.54.0-natural-official-web","exact main54 manifest")
permissions=sorted(e.get(android+"name") for e in manifest.findall("uses-permission"))
need(permissions==["org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE"],"only signature evidence permission; no INTERNET")
need(manifest.find("application").get(android+"label")=="Hepta","existing visible launcher label")
prior_stage_path=BASE.parent/"STAGE-RESULT.json"
prior_stage_raw=read(prior_stage_path)
need(len(prior_stage_raw)==4228 and sha(prior_stage_raw)=="7ebb9a3e0823573e8a8089031d6e3c25148d974e7074c7e4c0077fced8e5124b","actual prior full host stage")
prior_stage=json.loads(prior_stage_raw)
need(prior_stage["all_pass"] is True and prior_stage["source_file_count"]==570 and prior_stage["source_inventory_sha256"]==data["base_source_inventory_sha256"],"actual prior host/source linkage")
prior_host_path=Path(prior_stage["host_checks"]["path"]);need(BASE.parent in prior_host_path.parents,"prior host path")
prior_host_raw=read(prior_host_path)
need(len(prior_host_raw)==prior_stage["host_checks"]["bytes"] and sha(prior_host_raw)==prior_stage["host_checks"]["sha256"],"original host receipt")
prior_host=json.loads(prior_host_raw)
need(prior_host["all_pass"] is True and len(prior_host["checks"])==101 and all(r["exit_code"]==0 for r in prior_host["checks"]),"actual previous101 names/order")
original_check_names=[r["name"] for r in prior_host["checks"]]
tools={}
need(sys.platform.startswith("linux"),"original Pocket4 host platform")
JDK=Path("/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64")
tools["java"]=resolve_tool(JDK/"bin/java",JDK);tools["javac"]=resolve_tool(JDK/"bin/javac",JDK)
import shutil
cc=shutil.which("cc");need(cc is not None,"existing actual C compiler");tools["cc"]=resolve_tool(Path(cc))
need(tools["java"]["sha256"]=="bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196"
    and tools["javac"]["sha256"]=="2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4"
    and tools["cc"]["sha256"]=="b5f1b773a7c733738352000c92a077dc5852a1a2fc6d836b1e411be1e9ec5f88","actual previously tested host tool pins")
need(sha(before["tools/run_host_checks.py"])=="9ff87bffd0a4745a66b49d5867e8a065857e3b4b974f04bbbee18a51d7b402e3"
    and sha(target["tools/run_host_checks.py"])=="dc64aa551a0eddd6429ad3340db5445e9c00403a2110b48e1c05662f5d46ec3a","actual reviewed runner closure")
allowed_fixture_java=set(["tests/qualification-scope/fixtures/org/trillionnium/hepta/local/BackgroundSession.java","tests/qualification-scope/fixtures/org/trillionnium/hepta/local/WebFlightSession.java","tests/web-flight/WebFlightEvidenceHostTest.java","tests/web-flight/WebUnstartedRetirementHostTest.java","tests/web-flight/legacy-boundary/WebFlightDomain.java"])
for p in before:
    if p.startswith("tests/") and p.endswith(".java") and p not in allowed_fixture_java:
        need(target[p]==before[p],"undeclared existing Java assertion source changed: "+p)
need({p for p in before if p.startswith("tests/") and p.endswith(".java") and target[p]!=before[p]}==allowed_fixture_java,
    "only exact already reviewed fixture/protocol Java adaptations")
need(target["tests/completion/run_host_tests.py"]==before["tests/completion/run_host_tests.py"],"all original18 completion stage program retained")
need(set(target)==set(failed_before) and {p for p in target if target[p]!=failed_before[p]}==set(allowed),
    "exact failed589 membership and only three Python changes")
need(all(target[p]==failed_before[p] for p in target if not p.endswith(".py")),"all non-Python source bytes retained")

# This is the first mutation. A late identical launch cannot enter the winner's handler.
ROOT.mkdir(mode=0o700)
report={"schema":"hepta.v54-"+MODE+"-candidate-stage.v1","all_pass":False,"exit_code":1,"base_commit":BASE_COMMIT,
    "source_commit":None,"publication_pending":True,"source_file_count":len(target),"source_inventory_sha256":INVENTORY_SHA,
    "source_input_payload_sha256":INPUT_SHA,"input_gzip_sha256":GZIP_SHA,"post_compile_fixture_delta":delta,"mode":MODE,"started_epoch":started,
    "phone_commands_executed":0,"signed":False,"phone_tested":False,"web_query_executed":False,"web_results_verified":False,
    "tool_inputs":tools,"steps":[],"input_derivation":derivation}
def run(name,argv,timeout,cwd,env):
    begin=time.monotonic();timed=False;forced=False
    stdout=ROOT/(name+".stdout");stderr=ROOT/(name+".stderr")
    with stdout.open("xb") as out,stderr.open("xb") as err:
        proc=subprocess.Popen(list(map(str,argv)),cwd=cwd,env=env,stdout=out,stderr=err,start_new_session=True)
        try:code=proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed=True
            try:os.killpg(proc.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:code=proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forced=True
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                code=proc.wait(timeout=5)
    r={"name":name,"argv":list(map(str,argv)),"cwd":str(cwd),"exit_code":code,"timed_out":timed,"forced":forced,
       "elapsed_s":time.monotonic()-begin,"stdout":row(stdout),"stderr":row(stderr)}
    report["steps"].append(r);need(code==0 and not timed and not forced,"original "+name+" failed; exact logs preserved")
    return r
try:
    put(ROOT/"INPUT.json",raw);put(ROOT/"stage.py",sys.argv[1].encode("utf-8"))
    put(ROOT/"PRIOR-HOST-STAGE.json",prior_stage_raw)
    put(ROOT/"FIXTURE-PATCH.json",patch_raw);put(ROOT/"PRIOR-FAILED-HOST-STAGE.json",failed_stage_raw)
    jput(ROOT/"R3-FAILURE-PRESERVATION.json",derivation)
    jput(ROOT/"INPUT-DERIVATION.json",{"schema":"hepta.exact-final-source-input.v1","input_file":row(PAYLOAD),
        "input_sha256":sha(raw),"input_bytes":len(raw),"post_compile_fixture_delta":delta,"derivation":derivation})
    jput(ROOT/"START-ARGS.json",{"host":"pocket4","key":KEY,"argv":sys.argv,"cwd":os.getcwd(),"input_file":str(PAYLOAD),
        "input_gzip_sha256":GZIP_SHA,"post_compile_fixture_delta":delta,"no_published_commit_claim":True})
    SOURCE.mkdir(mode=0o700)
    for name,b in target.items():
        p=SOURCE/name;put(p,b)
        os.chmod(p,(BASE/name).stat().st_mode&0o777 if name in before else 0o644)
    need(entries(SOURCE)==target,"actual materialized source")
    report["source_inventory"]=put(ROOT/"SOURCE-INVENTORY.json",encoded(inventory(target)))
    report["source_blob_map"]=jput(ROOT/"SOURCE-BLOB-MAP.json",{"schema":"hepta.actual-source-blob-map.v1","source_root":str(SOURCE),
        "base_commit":BASE_COMMIT,"source_commit":None,"publication_pending":True,"source_inventory_sha256":INVENTORY_SHA,
        "files":[{"path":p,"bytes":len(b),"sha256":sha(b),"git_blob_sha":blob(b)} for p,b in sorted(target.items(),key=lambda v:Path(v[0]))]})
    env=dict(os.environ);env.update(PYTHONDONTWRITEBYTECODE="1",JAVA_HOME=str(JDK),PATH=str(JDK/"bin")+":"+os.environ.get("PATH","/usr/bin:/bin"))
    env.pop("SOURCE_HEAD_SHA",None)
    OUT=ROOT/"host-checks"
    (ROOT/"tmp").mkdir();env["TMPDIR"]=str(ROOT/"tmp")
    jput(ROOT/"HOST-STARTED.json",{"schema":"hepta.original-host-start.v1","command":[sys.executable,"-B",str(SOURCE/"tools/run_host_checks.py"),"--out",str(OUT)],
        "cwd":str(SOURCE),"java_home":str(JDK),"source_inventory_sha256":INVENTORY_SHA,"source_file_count":len(target),
        "source_commit":None,"publication_pending":True,"started_epoch":time.time(),"phone_commands_executed":0})
    run("original-host-checks",[sys.executable,"-B",SOURCE/"tools/run_host_checks.py","--out",OUT],900,SOURCE,env)
    host_path=OUT/"HOST-CHECKS.json";host=json.loads(read(host_path))
    checks=host.get("checks")
    need(host["schema"]=="hepta.host-checks.v3" and host["all_pass"] is True and isinstance(checks,list)
        and len(checks)==101 and all(r["exit_code"]==0 for r in checks),"all original 101 host records")
    need(host["android_compiled"] is False and host["phone_tested"] is False and host["native_grammar_model_tested"] is False
        and host["external_model_used"] is False,"host result scope retained")
    need(len({r["name"] for r in checks})==101 and [r["name"] for r in checks]==original_check_names,"all original101 names/order retained")
    for r in checks:
        for stream in ("stdout","stderr"):need(sha(read(OUT/(r["name"]+"."+stream)))==r[stream+"_sha256"],"host log differs: "+r["name"])
    nested_path=OUT/"task-completion/RESULT.json";nested=json.loads(read(nested_path))
    required=["compile","actual-completion","notes-task-phase","notes-task-phase-grammar","notes-list-provenance","notes-recovery",
        "notes-recovery-grammar","notes-task-scope","notes-task-scope-grammar","calculator-input","calculator-input-grammar",
        "failed-action-observation","notes-editor-phase","notes-editor-phase-grammar","completion-status","completion-status-grammar",
        "notes-create-workflow","notes-workflow-controller"]
    need(nested["schema"]=="hepta.task-completion-host.v1" and nested["passed"] is True
        and [r["name"] for r in nested["stages"]]==required and all(r["exit_code"]==0 for r in nested["stages"])
        and nested["compiler_contract"]=="Java 8 API release","all original 18 actual-controller stages")
    report.update(host_checks=row(host_path),host_check_count=len(checks),host_input_count=len(host["source_inputs"]),
        nested_completion=row(nested_path),nested_completion_stage_count=18,java8_api_release=True,
        original_test_assertions_retained=True,android_compiled=False,native_compiled=False,
        separate_real_web_class_gate_required=True,separate_owned_cancellation_gate_required=True)

    need(entries(SOURCE)==target and entries(BASE)==before,"candidate/base source changed")
    need(entries(failed_root/"source")==failed_before and all(read(p)==b for p,b in failed_originals),"original failed r3 source or evidence changed")
    for value in tools.values():
        now=tool_record(Path(value["path"]))
        need(now["bytes"]==value["bytes"] and now["sha256"]==value["sha256"],"cached tool changed: "+value["path"])
    need(read(PAYLOAD)==packed and read(prior_stage_path)==prior_stage_raw and read(prior_host_path)==prior_host_raw,"candidate input or prior actual host originals changed")
    report.update(all_pass=True,exit_code=0,source_unchanged=True,base_source_unchanged=True,tools_unchanged=True,
        previous_failed_source_unchanged=True,previous_failure_evidence_unchanged=True)
except BaseException as error:
    report["error"]=type(error).__name__+": "+str(error)
    report["source_unchanged"]=SOURCE.is_dir() and entries(SOURCE)==target
    report["base_source_unchanged"]=entries(BASE)==before
    report["previous_failed_source_unchanged"]=entries(failed_root/"source")==failed_before
    report["previous_failure_evidence_unchanged"]=all(read(p)==b for p,b in failed_originals)
finally:
    report["finished_epoch"]=time.time()
    if MODE=="host":
        p=ROOT/"host-checks/HOST-CHECKS.json"
        if p.is_file():
            actual=json.loads(read(p))
            report["host_checks"]=row(p);report["actual_host_all_pass"]=actual.get("all_pass")
            report["actual_host_error"]=actual.get("error");report["host_check_count"]=len(actual.get("checks",[]))
            report["host_input_count"]=len(actual.get("source_inputs",[]))
    info=jput(ROOT/"STAGE-RESULT.json",report)
    print(json.dumps({"result":info,"all_pass":report["all_pass"],"exit_code":report["exit_code"],
        "error":report.get("error"),"host_error":report.get("actual_host_error"),"source_file_count":len(target),
        "compiler_input_count":report.get("compiler_input_count"),"compiled_archive":report.get("compiled_archive"),
        "host_check_count":report.get("host_check_count"),"host_input_count":report.get("host_input_count")}),flush=True)
sys.exit(0 if report["all_pass"] else 1)
