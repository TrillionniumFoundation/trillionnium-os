#!/usr/bin/env python3
"""Stage three exact public release artifacts; no signing or repository mutation."""
import ast,hashlib,json,os,re,stat,sys,time
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
B=Path("/home/alex/hepta-local-007f-20261111")
CONFIG=json.loads("{\"schema\":\"hepta.main58-publication-staging-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v58-main-release-publication-r1\",\"core_root\":\"/home/alex/hepta-local-007f-20261111/v58-main-core101-materialized-host-r1\",\"core_result\":null,\"core_map\":{\"bytes\":141875,\"sha256\":\"807e52edb4efda808a1dc1ae490ac13f7e92ff65f3f31c6156d4b8a54e2334e1\"},\"inventory_sha256\":\"b44d3a9d9083a86d5fff36dfcc0c27958ef047a05df928923ef7c2e204cb23d6\",\"input\":null,\"publication\":null,\"git_source_map\":null,\"signer\":null,\"source_commit\":null,\"source_tree\":null,\"expected_prior_head\":null,\"base_source_commit\":\"313685edc580a750aea6301d8ff3cfd617d6fab6\",\"repository\":\"trillionniumFoundation/trillionnium-os\",\"branch\":\"codex/hepta-v45-semantic-click-20261111-007f\",\"source_prefix\":\"projects/razr60/phone-local-v150/android-local/lfm3-controller/\"}")

def need(value, why):
    if not value:
        raise RuntimeError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n").encode("utf-8")

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def no_constant(value):
        raise ValueError("non-finite JSON")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=no_constant)

def identity(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]

def read_regular(path, expected=None, limit=64<<20):
    path = Path(path)
    need(path.is_absolute(), "absolute input path")
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary input ancestors")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "bounded single-link ordinary input")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        need(identity(os.fstat(fd)) == identity(before), "input replaced before open")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit+1-size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            need(size <= limit, "input byte limit")
        raw = b"".join(chunks)
        need(identity(os.fstat(fd)) == identity(before), "input changed while open")
    finally:
        os.close(fd)
    need(identity(path.lstat()) == identity(before) and len(raw) == before.st_size, "input changed across read")
    facts = {"path": str(path), "bytes": len(raw), "sha256": sha(raw), "identity": identity(before)}
    if expected is not None:
        need(type(expected["bytes"]) is int and facts["bytes"] == expected["bytes"]
             and facts["sha256"] == expected["sha256"], "exact input bytes/SHA: "+str(path))
    return raw, facts

def unchanged(facts):
    raw, current = read_regular(facts["path"], facts)
    need(current == facts, "input identity changed: "+facts["path"])
    return raw

def checked(raw, pin, message):
    need(type(raw) is bytes and type(pin["bytes"]) is int and len(raw) == pin["bytes"]
         and sha(raw) == pin["sha256"], message)
    if "git_blob_sha" in pin:
        need(blob(raw) == pin["git_blob_sha"], message+" Git blob")
    return raw

def relative(name):
    need(type(name) is str and "\\" not in name and name not in ("", "."), "relative member")
    path = PurePosixPath(name)
    need(not path.is_absolute() and ".." not in path.parts and str(path) == name, "safe member")
    return name

def rows(values):
    return [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
            for name, raw in sorted(values.items(), key=lambda item: Path(item[0]))]

def snapshot(root):
    need(root.is_dir() and not root.is_symlink(), "existing ordinary source root")
    values, facts = {}, {}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "no source symlink")
        if path.is_dir():
            continue
        name = relative(path.relative_to(root).as_posix())
        values[name], facts[name] = read_regular(path, limit=4<<20)
    return values, facts

def validate_map(values, expected, with_git):
    need(len(expected) == len(values) and len({r["path"] for r in expected}) == len(expected),
         "exact source map membership")
    need(set(values) == {relative(r["path"]) for r in expected}, "source map path set")
    for item in expected:
        raw = values[item["path"]]
        checked(raw, item, "source map member "+item["path"])
        if with_git:
            need(blob(raw) == item["git_blob_sha"], "source map Git identity")

def write_new(path, raw, mode=0o600):
    need(ROOT in path.parents and type(raw) is bytes, "owned new output")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary output ancestors")
    fd = os.open(str(path), os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    os.chmod(path, mode)
    actual, facts = read_regular(path, {"bytes": len(raw), "sha256": sha(raw)})
    need(actual == raw, "new output readback")
    return facts

def load_bound(path, pin, original_facts):
    raw, facts = read_regular(path, pin)
    original_facts.append(facts)
    return raw



def sealed_pin(value, name):
    need(type(value) is dict and type(value.get("bytes")) is int and value["bytes"]>0
         and type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}",value["sha256"]),
         "actual sealed public pin required: "+name)

for field in ("input","publication","git_source_map","signer","core_result","core_map"):
    sealed_pin(CONFIG[field],field)
for field in ("source_commit","source_tree","expected_prior_head"):
    need(type(CONFIG[field]) is str and re.fullmatch(r"[0-9a-f]{40}",CONFIG[field]),
         "actual sealed Git identity required: "+field)
need(CONFIG["source_commit"]!=CONFIG["base_source_commit"],"new source publication")
ROOT=Path(CONFIG["root"]);CORE=Path(CONFIG["core_root"])
need(ROOT==B/"v58-main-release-publication-r1" and CORE==B/"v58-main-core101-materialized-host-r1"
     and not ROOT.exists() and not ROOT.is_symlink(),"new fixed metadata-only output")
stage_raw=globals().get("__stage_source__")
input_raw=globals().get("__metadata_raw__")
need(type(stage_raw) is bytes and len(stage_raw)>0,"same loader-verified staging source")
checked(input_raw,CONFIG["input"],"exact public metadata input")
data=strict(input_raw)
need(type(data) is dict and set(data)=={"schema","git_map_header","publication_raw","signer_raw"}
     and data["schema"]=="hepta.main58-publication-staging-input.v1",
     "exact public-only input shape")
need(type(data["publication_raw"]) is str and type(data["signer_raw"]) is str,
     "whole raw public publication and signer sources")
publication_raw=checked(data["publication_raw"].encode("utf-8"),CONFIG["publication"],"actual whole publication")
signer_raw=checked(data["signer_raw"].encode("utf-8"),CONFIG["signer"],"reviewed final signer source")
pub=strict(publication_raw)
originals=[]
core_raw=load_bound(CORE/"RESULT.json",CONFIG["core_result"],originals);core=strict(core_raw)
map_raw=load_bound(CORE/"SOURCE-BLOB-MAP.json",CONFIG["core_map"],originals);host_rows=strict(map_raw)
need(core["schema"]=="hepta.main58-original-core101-host-stage.v1"
     and core["all_pass"] is True and type(core["exit_code"]) is int and core["exit_code"]==0
     and core["source_root"]==str(CORE/"source") and core["source_file_count"]==595
     and core["source_inventory_sha256"]==CONFIG["inventory_sha256"]
     and core["host_check_count"]==101 and core["host_input_count"]==419
     and core["nested_completion_stage_count"]==18 and core["nested18_are_within_core101"] is True
     and all(core[k] is True for k in ("originals_unchanged","source_unchanged",
         "base_source_unchanged","written_files_unchanged","prior_core_evidence_unchanged",
          "historical_failed_core_evidence_unchanged","historical56_web_receipts_unchanged"))
     and core["prior_core_all_pass"] is True and type(core["prior_core_exit_code"]) is int
     and core["prior_core_exit_code"]==0 and core["prior_actual_host_check_count"]==101
     and core["historical_failed_core_all_pass"] is False
     and core["source_blob_map"]["path"]==str(CORE/"SOURCE-BLOB-MAP.json")
     and core["source_blob_map"]["bytes"]==len(map_raw)
     and core["source_blob_map"]["sha256"]==sha(map_raw),
     "actual complete same-source core receipt and exact host map")
header=data["git_map_header"]
header_keys=["schema","repository","source_prefix","source_commit","source_tree","base_source_commit",
    "source_file_count","source_inventory_sha256","host_actual_blob_map_sha256",
    "host_actual_blob_map_bytes","precommit_host_result_sha256","all_source_blobs_match_actual_tree"]
need(type(header) is dict and list(header)==header_keys,"original ordered v2 public header")
need(header["schema"]=="hepta.git-source-blob-map.v2"
     and header["repository"]==CONFIG["repository"] and header["source_prefix"]==CONFIG["source_prefix"]
     and header["source_commit"]==CONFIG["source_commit"] and header["source_tree"]==CONFIG["source_tree"]
     and header["base_source_commit"]==CONFIG["base_source_commit"]
     and type(header["source_file_count"]) is int and header["source_file_count"]==595
     and header["source_inventory_sha256"]==CONFIG["inventory_sha256"]
     and type(header["host_actual_blob_map_bytes"]) is int and header["host_actual_blob_map_bytes"]==len(map_raw)
     and header["host_actual_blob_map_sha256"]==sha(map_raw)
     and header["precommit_host_result_sha256"]==sha(core_raw)
     and header["all_source_blobs_match_actual_tree"] is True,
     "actual sealed publication header is bound to this core result")
need(type(host_rows) is list and len(host_rows)==595,"complete actual host row array")
names=[];published_rows=[]
for row in host_rows:
    need(type(row) is dict and list(row)==["path","bytes","sha256","git_blob_sha"],"original host row shape and order")
    name=relative(row["path"]);names.append(name)
    need(type(row["bytes"]) is int and row["bytes"]>=0
         and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",row["sha256"])
         and type(row["git_blob_sha"]) is str and re.fullmatch(r"[0-9a-f]{40}",row["git_blob_sha"]),
         "bounded public source row identity")
    published_rows.append({"path":name,"bytes":row["bytes"],"sha256":row["sha256"],
        "git_blob_sha":row["git_blob_sha"],"remote_blob_sha":row["git_blob_sha"],
        "repository_path":CONFIG["source_prefix"]+name,"mode":"100644"})
need(len(set(names))==595 and names==sorted(names,key=Path),"unique original actual host row ordering")
git_map=dict(header);git_map["files"]=published_rows
git_map_raw=checked(encoded(git_map),CONFIG["git_source_map"],"whole actual Git map reconstructed exactly")
need(pub["schema"]=="hepta.v58-git-publication.v1"
     and pub["repository"]==CONFIG["repository"] and pub["source_prefix"]==CONFIG["source_prefix"]
     and pub["branch"]==CONFIG["branch"] and pub["pr_number"]==139
     and pub["base_source_commit"]==CONFIG["base_source_commit"]
     and pub["expected_prior_head"]==CONFIG["expected_prior_head"]
     and pub["source_commit"]==CONFIG["source_commit"]==pub["actual_pr_head"]==pub["actual_ref_head"]
     and pub["source_tree"]==CONFIG["source_tree"] and pub["draft"] is True and pub["force"] is False
     and pub["source_file_count"]==595 and pub["source_inventory_sha256"]==CONFIG["inventory_sha256"]
     and pub["all_source_blobs_match_actual_tree"] is True and pub["all_other_repository_blobs_preserved"] is True
     and pub["host_precommit_result_sha256"]==sha(core_raw)
     and pub["host_record_count"]==101 and pub["host_input_count"]==419 and pub["nested_completion_stage_count"]==18
     and pub["actual_host_blob_map_sha256"]==sha(map_raw)
     and pub["git_source_map_sha256"]==sha(git_map_raw) and pub["git_source_map_bytes"]==len(git_map_raw)
     and pub["pr_title_body_modified"] is False and pub["phone_tested"] is False,
     "sealed actual CAS proof and full map belong together")
tree=ast.parse(signer_raw,filename=str(ROOT/"main58_signer.py"),mode="exec")
assignments=[n for n in tree.body if isinstance(n,ast.Assign)
    and any(isinstance(t,ast.Name) and t.id=="CONFIG" for t in n.targets)]
need(len(assignments)==1,"one literal signer CONFIG")
call=assignments[0].value
need(isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute)
     and isinstance(call.func.value,ast.Name) and call.func.value.id=="json" and call.func.attr=="loads"
     and len(call.args)==1 and not call.keywords and isinstance(call.args[0],ast.Constant)
     and type(call.args[0].value) is str,"read signer CONFIG without executing it")
signer_config=strict(call.args[0].value.encode("utf-8"))
for key in ("build_result","build_stage","build_input","compiled_aggregate","core_result","core_stage",
            "final_aggregate","final_inventory","core_blob_map","web_result","web_stage","web_packet",
            "git_source_map","publication"):
    sealed_pin(signer_config[key],"signer."+key)
need(signer_config["schema"]=="hepta.main58-same-host-sign-config.v1"
     and signer_config["root"]==str(B/"v58-main-sign-r1")
     and signer_config["build_root"]==str(B/"v58-main-p4-android-r1")
     and signer_config["web_root"]==str(B/"v58-main-web-regression-host-r1")
     and signer_config["core_root"]==str(CORE) and signer_config["publication_root"]==str(ROOT)
     and signer_config["source_commit"]==CONFIG["source_commit"] and signer_config["source_tree"]==CONFIG["source_tree"]
     and signer_config["expected_prior_head"]==CONFIG["expected_prior_head"]
     and signer_config["core_result"]==CONFIG["core_result"]
     and signer_config["core_blob_map"]==CONFIG["core_map"]
     and signer_config["git_source_map"]==CONFIG["git_source_map"]
     and signer_config["publication"]==CONFIG["publication"]
     and signer_config["compiled_source_inventory_sha256"]==CONFIG["inventory_sha256"]
     and signer_config["final_inventory"]["sha256"]==CONFIG["inventory_sha256"],
     "final signer consumes these same actual public bytes")
compile(signer_raw,str(ROOT/"main58_signer.py"),"exec",dont_inherit=True)
for facts in originals:unchanged(facts)
started=time.time()
ROOT.mkdir(mode=0o700)  # FIRST MUTATION, outside handler: late losers cannot write an existing root.
written=[]
result={"schema":"hepta.main58-publication-staging-result.v1","all_pass":False,"exit_code":1,
    "root":str(ROOT),"source_count":595,"source_commit":CONFIG["source_commit"],"source_tree":CONFIG["source_tree"],
    "source_inventory_sha256":CONFIG["inventory_sha256"],"core_result":CONFIG["core_result"],
    "host_map":CONFIG["core_map"],"input":CONFIG["input"],"files":written,
    "git_map_reconstructed_from_exact_host_rows":True,"git_map_matched_actual_full_bytes_sha256":True,
    "remote_git_rechecked_here":False,"signer_source_compiled_not_executed":True,
    "signer_executed":False,"signed":False,"phone_actions":0,"business_verified":False,
    "originals_unchanged":False,"written_files_unchanged":False,"started_epoch":started,"error":None}
try:
    for name,raw in (("stage.py",stage_raw),("METADATA-INPUT.json",input_raw),
                     ("GIT-SOURCE-BLOB-MAP.json",git_map_raw),("PUBLICATION.json",publication_raw),
                     ("main58_signer.py",signer_raw)):
        written.append(write_new(ROOT/name,raw))
    result["all_pass"]=True;result["exit_code"]=0
except BaseException as failure:
    result["error"]=type(failure).__name__+": "+str(failure)
finally:
    try:
        for facts in originals:unchanged(facts)
        for facts in written:unchanged(facts)
        result["originals_unchanged"]=True;result["written_files_unchanged"]=True
    except BaseException as failure:
        result["all_pass"]=False;result["exit_code"]=1
        result["integrity_error"]=type(failure).__name__+": "+str(failure)
    result["all_pass"]=bool(result["all_pass"] and result["originals_unchanged"] and result["written_files_unchanged"])
    result["exit_code"]=0 if result["all_pass"] else 1
    result["finished_epoch"]=time.time();result["elapsed_seconds"]=result["finished_epoch"]-started
    result["stage_sha256"]=sha(stage_raw)
    result_facts=write_new(ROOT/"RESULT.json",encoded(result))
    summary={"schema":"hepta.main58-publication-staging-summary.v1","all_pass":result["all_pass"],
        "exit_code":result["exit_code"],"result":result_facts,"error":result.get("error"),
        "source_count":595,"source_commit":CONFIG["source_commit"],"signed":False,"phone_actions":0}
    write_new(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,ensure_ascii=False,allow_nan=False),flush=True)
raise SystemExit(result["exit_code"])
