#!/usr/bin/env python3
"""Verify the exact Q4_K_M -> Q4_0 model-contract-only native delta."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require(x,msg):
 if not x:raise ValueError(msg)
base=ROOT/"provenance/ORIGINAL-APP-SOURCE-GENERATION.json"
require(sha(base)=="c84fd4e7d97f2657aaf3e16f1307ba032ca9dc6c03f0f5d5a4fa3659960a91d5","baseline generation differs")
original=json.loads(base.read_bytes());recipe=json.loads((ROOT/"SOURCE-GENERATION.json").read_bytes())
require(len(original["files"])==19,"original native member count differs")
require({str(p.relative_to(ROOT)) for p in (ROOT/"native").rglob("*") if p.is_file()}=={m["path"] for m in original["files"]},"native member set changed")
before=ROOT/"provenance/ORIGINAL-APP-venus-runtime.inc"
require(sha(before)=="c08cc9ec60a1e3abb5e5e4305cfb8340544537f49374a8c59418a02690df7000","original runtime source differs")
changes=[
("UI-Venus-2-9B-Q4_K_M.gguf","UI-Venus-2-9B-Q4_0.gguf"),
("f2a8533b4adf7dc92d0731c39bd910438d229593f2e524b8f6e0e0e83fd1ec8d","2e881d6e74899b47b1f0c9052abeeb0a7ff55913dfb18d942a3de3cadb3d1adb"),
("UINT64_C(5910782752)","UINT64_C(5482832672)"),
("ui-venus2-9b-q4_k_m-f16-mmproj","ui-venus2-9b-q4_0-f16-mmproj")]
expected=before.read_bytes()
for old,new in changes:
 require(expected.count(old.encode())==1,"model literal preimage not unique")
 expected=expected.replace(old.encode(),new.encode(),1)
require((ROOT/"native/venus-runtime.inc").read_bytes()==expected,"unexpected native runtime delta")
rows=[];unchanged=0
for m in original["files"]:
 p=ROOT/m["path"];require(not p.is_symlink() and p.is_file(),"native type differs")
 now={"path":m["path"],"bytes":p.stat().st_size,"sha256":sha(p)}
 same=now==m
 if m["path"]!="native/venus-runtime.inc":require(same,"unrelated native member changed")
 unchanged+=same;rows.append(dict(now,unchanged_from_original_app=same,original_sha256=m["sha256"]))
require(unchanged==18,"native unchanged count differs")
require(recipe["files"]==[{k:r[k] for k in ("path","bytes","sha256")} for r in rows],"recipe native members differ")
require(recipe["model"]=={"name":"UI-Venus-2-9B-Q4_0.gguf","bytes":5482832672,"sha256":"2e881d6e74899b47b1f0c9052abeeb0a7ff55913dfb18d942a3de3cadb3d1adb"},"new model pin differs")
require(recipe["mmproj"]==original["mmproj"],"projector pin changed")
require(recipe["profile"]=="ui-venus2-9b-q4_0-f16-mmproj","profile differs")
for key in ("sdk_source_commit","llama_source_commit","context_tokens","max_tokens","deadline_ms","enable_thinking","app_argv_prefix","entry_guard_sha256","worker_source_sha256","wrapper_source_sha256"):
 require(recipe[key]==original[key],"unrelated contract changed: "+key)
print(json.dumps({"schema":"hepta.ui-venus.app-q4_0-native-boundary.v1","passed":True,"baseline_source_generation_sha256":sha(base),"original_files":19,"original_files_unchanged":18,"original_files_changed":["native/venus-runtime.inc"],"only_model_identity_literals_changed":True,"changed_literal_count":4,"original_core_byte_unchanged":False,"worker_c_and_app_wrapper_bytes_unchanged":True,"same_directory_bootstrap_byte_unchanged":True,"entry_guard_bytes_unchanged":True,"files":rows,"phone_contact":False,"inference_run":False},indent=2))
