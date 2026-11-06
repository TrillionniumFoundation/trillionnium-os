#!/usr/bin/env python3
"""Host-only source merge of type checks and the already reviewed actual GNU prefix.
No actor, phone, installer, service, BUILD or READY is invoked. Both public slots
stay None. --out must be a fresh directory. Existing inputs are read only.
"""
import argparse, ast, copy, difflib, hashlib, json, os, shlex, stat
from pathlib import Path
DATA = json.loads("{\"type_root\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-fc33-type-checks-candidate01\",\"env_root\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01\",\"type_reader\":{\"bytes\":35028,\"sha256\":\"c42ada3af944cb6f8191d1ff8700107b01ea81414a15d25a4740925b6743d681\"},\"references\":[{\"path\":\"references/consumer.original.py\",\"bytes\":243806,\"sha256\":\"3de6208604022671d4db21e2b479e3ef4d4bba4aaa9d2faa360f1865aec428da\"},{\"path\":\"references/exact8.original.py\",\"bytes\":29027,\"sha256\":\"24db28bee38671322b11ce4c2afd5dd47425381101dd85f887141f567811b490\"},{\"path\":\"references/INPUT-CONTRACT.original.json\",\"bytes\":7175,\"sha256\":\"6acf1df1cbbb09422568c69bd838f67be7d4226f53d0f050bea27658c62a72fe\"},{\"path\":\"references/installer.original.py\",\"bytes\":34100,\"sha256\":\"714a2916680e2313bfcee5a4319d6484b3c6ea5539854818c1134ad84ea02446\"},{\"path\":\"references/PRODUCER-RETENTION-CONTRACT.original.json\",\"bytes\":4280,\"sha256\":\"e2c43784539b2deae129dcdb1d09c7f19796b5dacf88bffdde2ec2350ea368ce\"},{\"path\":\"references/readiness.original.py\",\"bytes\":16407,\"sha256\":\"2b4ff90f7078af2481feb8a2d33c39d1a0e260102cd769a4ee3b46d9bec47e11\"},{\"path\":\"references/REFERENCE-SEED.original.json\",\"bytes\":5787,\"sha256\":\"c3ca803e44708e8e3e1d7c83dea62b1f595435de6fcd2345579f1f8b4aea0c56\"},{\"path\":\"references/release_reader.original.py\",\"bytes\":28483,\"sha256\":\"e947a3b2de75a0820fcc3cb5cfe758f874cd85625cb11bac793b38256a670c43\"},{\"path\":\"references/verify_install_start_ready_UNBOUND.baseline.py\",\"bytes\":34507,\"sha256\":\"011be7502d97f5673c3df48802a3dd5dd78be2892e6a0e82873e863f619e3346\"},{\"path\":\"validation/run_controller_phone_rc_controls.py\",\"bytes\":3438,\"sha256\":\"36b67b98d0b10938ac8933488eedd58cfff480f8199e56b71a3ea40f5a1c6101\"},{\"path\":\"validation/run_install_ready_candidate_controls.py\",\"bytes\":10143,\"sha256\":\"43f66a5fa2f0350ef06f7f6cbcff4763d6cf8af867fd4dcfec26887566e8d59d\"},{\"path\":\"validation/run_install_ready_source_controls.py\",\"bytes\":14680,\"sha256\":\"92979c495d021225d6f1122e05556c62274224f760b2a88e401547274e63ce24\"}],\"environment\":[{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01/ENVIRONMENT-V2-DERIVATION.json\",\"bytes\":4259,\"sha256\":\"94c206ce7ae1b2fe7c09036ddf44a3f13c31f1d8d083084b3f4decfcd02085ce\"},{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01/source/install_ready_execution_protocol_v2.py\",\"bytes\":12782,\"sha256\":\"79f2a227e0d0c991bcc08c9edf6d5916faed798c358f27906d53a226beeda353\"},{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01/source/verify_install_start_ready_UNBOUND02.py\",\"bytes\":34510,\"sha256\":\"66fe421093482d4ce9338b1646584e94ac10600bc1edb8a711b9362d63dbddf3\"}],\"type_changes\":[[\"    need(row['offset'] == 0 and row['eof'] is True and type(row['size']) is int\\n         and row['next_offset'] == row['size'] == len(raw) and type(row['text']) is str\\n         and row['text'].encode() == raw, 'actual original output full bytes and EOF')\\n    need(status['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)}\\n         and status['log_synced'][name] is True, 'controller original durable stream counts')\\n\",\"    need(all(type(row[key]) is int for key in ('offset', 'next_offset', 'size'))\\n         and row['offset'] == 0 and row['eof'] is True\\n         and row['next_offset'] == row['size'] == len(raw) and type(row['text']) is str\\n         and row['text'].encode() == raw, 'actual original output full bytes and EOF')\\n    counts = exact(status['log_bytes'][name], ('seen', 'stored'), 'exact original durable stream counts')\\n    need(all(type(counts[key]) is int and counts[key] == len(raw) for key in ('seen', 'stored'))\\n         and status['log_synced'][name] is True, 'controller original durable stream counts')\\n\"],[\"         and status['log_truncated'] == {'stdout': False, 'stderr': False}\\n\",\"         and type(status['log_truncated']) is dict\\n         and set(status['log_truncated']) == {'stdout', 'stderr'}\\n         and all(status['log_truncated'][name] is False for name in ('stdout', 'stderr'))\\n\"],[\"    for name in ('proc_before_base64', 'proc_after_base64'):\\n\",\"    need(type(value['identity']) is list and len(value['identity']) == 5\\n         and all(type(x) is int and x > 0 for x in value['identity']),\\n         'five positive integer source-entry identity fields')\\n    for name in ('proc_before_base64', 'proc_after_base64'):\\n\"]]}")
def need(value, why):
    if not value: raise ValueError(why)
def pin(raw): return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def full9(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read_pinned(path, expected):
    p=Path(path); before=p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,"regular single-link input")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd); need(full9(before)==full9(opened),"input changed on open")
        with os.fdopen(fd,"rb",closefd=False) as f: raw=f.read(expected["bytes"]+1)
        need(full9(opened)==full9(os.fstat(fd))==full9(p.lstat()),"input changed while reading")
    finally: os.close(fd)
    need(pin(raw)=={k:expected[k]for k in ("bytes","sha256")},"pinned input bytes differ: "+str(p))
    return raw
def change(raw, edits):
    text=raw.decode("utf-8")
    for before,after in edits:
        need(text.count(before)==1,"unique exact source edit")
        text=text.replace(before,after,1)
    result=text.encode()
    reverse=result.decode()
    for before,after in reversed(edits):
        need(reverse.count(after)==1,"unique exact inverse edit")
        reverse=reverse.replace(after,before,1)
    need(reverse.encode()==raw,"full source inverse")
    return result
def dump(value): return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
def write_once(root, name, raw):
    p=root/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    need(p.read_bytes()==raw,"output readback")
def derive(type_root,env_root):
    typed=read_pinned(type_root/"source/verify_install_start_ready_UNBOUND.py",DATA["type_reader"])
    env_files={}
    for row in DATA["environment"]:
        relative=Path(row["path"]).relative_to(Path(DATA["env_root"]))
        env_files[str(relative)]=read_pinned(env_root/relative,row)
    derivation=json.loads(env_files["ENVIRONMENT-V2-DERIVATION.json"])
    original_protocol=read_pinned(env_root/"source/install_ready_execution_protocol.py",derivation["parent_protocol"])
    original_reader=read_pinned(env_root/"source/verify_install_start_ready_UNBOUND.py",derivation["parent_reader"])
    protocol=env_files["source/install_ready_execution_protocol_v2.py"]
    environment_reader=env_files["source/verify_install_start_ready_UNBOUND02.py"]
    environment_edits=[(x["before"],x["after"])for x in derivation["reader_changes"]]
    protocol_edits=[(x["before"],x["after"])for x in derivation["protocol_changes"]]
    need(change(original_protocol,protocol_edits)==protocol,"protocol full-byte derivation")
    need(change(original_reader,environment_edits)==environment_reader,"environment reader full-byte derivation")
    need(change(original_reader,DATA["type_changes"])==typed,"typed reader full-byte derivation")
    merged=change(typed,environment_edits)
    need(change(environment_reader,DATA["type_changes"])==merged,"commuting merge exact bytes")
    req=read_pinned(derivation["actual_request"]["path"],derivation["actual_request"])
    prefix=shlex.split(json.loads(req)["command"])[:-1]
    need(prefix==derivation["actual_prefix"],"actual current44 request prefix differs")
    ast.parse(merged);ast.parse(protocol)
    ns={};exec(compile(merged,"merged_install_reader","exec"),ns)
    calls=[]
    try:ns["verify_install_start_ready_originals"](b"not-json",read_pinned=lambda x:calls.append(x))
    except ValueError as e: rejection=str(e)
    else:raise ValueError("unbound public reader unexpectedly accepted")
    need(ns["FROZEN_INPUTS"]is None and ns["FROZEN_EXECUTION_PLAN"]is None and calls==[],"unbound before any I/O")
    need(ns["SOURCES"]["protocol"]==derivation["selected_protocol"],"selected protocol descriptor")
    outputs={
      "source/verify_install_start_ready_UNBOUND.py":merged,
      "source/install_ready_execution_protocol.py":protocol,
      "references/verify_install_start_ready.type-c42ada.py":typed,
      "references/verify_install_start_ready.environment-66fe.py":environment_reader,
      "references/install_ready_execution_protocol.v1.py":original_protocol,
      "references/install_ready_execution_protocol.v2.py":protocol,
      "references/ENVIRONMENT-V2-DERIVATION.original.json":env_files["ENVIRONMENT-V2-DERIVATION.json"],
      "patches/type-c42ada-to-merged.patch":"".join(difflib.unified_diff(typed.decode().splitlines(True),merged.decode().splitlines(True),fromfile="type-c42ada.py",tofile="merged.py")).encode(),
      "patches/environment-66fe-to-merged.patch":"".join(difflib.unified_diff(environment_reader.decode().splitlines(True),merged.decode().splitlines(True),fromfile="environment-66fe.py",tofile="merged.py")).encode(),
    }
    for row in DATA["references"]:
        outputs[row["path"]]=read_pinned(type_root/row["path"],row)
    facts={"schema":"razr60-install-ready-source-merge/v1","state":"HOST_SOURCE_CANDIDATE_UNBOUND",
      "parents":{"typed_reader":pin(typed),"environment_reader":pin(environment_reader),"original_reader":pin(original_reader),"protocol_v1":pin(original_protocol)},
      "selected":{"reader":pin(merged),"protocol":pin(protocol)},
      "exact_commuting_forward_and_inverse":True,
      "reader_semantic_changes":"Three type checks from c42ada plus the existing protocol descriptor change from 66fe",
      "protocol_content_changed_from_v2":False,
      "actual_prefix_read_only_reverified":derivation["actual_request"],
      "actual_prefix":prefix,"unbound_rejection":rejection,"public_callback_calls":0,
      "actual_slots_bound":False,"actual_builds":0,"phone_calls":0,"actual_installs":0,"actual_READY":0,
      "formal_role_identities_generated":0,"new_request_nonces":0,"fixed19_credit":0,
      "historical_contracts_under_references_are_not_candidate_contracts":True,
      "files":[dict(path=n,**pin(v))for n,v in sorted(outputs.items())]}
    outputs["CANDIDATE-MANIFEST.json"]=dump(facts)
    return outputs,facts
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--type-root",type=Path,default=Path(DATA["type_root"]))
    ap.add_argument("--environment-root",type=Path,default=Path(DATA["env_root"]))
    ap.add_argument("--out",type=Path)
    a=ap.parse_args();outputs,facts=derive(a.type_root,a.environment_root)
    if a.out is not None:
        a.out.mkdir(mode=0o700)
        for n,raw in outputs.items():write_once(a.out,n,raw)
        write_once(a.out,"build_candidate.py",Path(__file__).read_bytes())
    print(json.dumps(facts,sort_keys=True,ensure_ascii=False))
if __name__=="__main__":main()
