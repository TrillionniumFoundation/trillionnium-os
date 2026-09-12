#!/usr/bin/env python3
"""Prepare a fixed, unapproved source candidate. No target or release operation."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zlib

PATCH = "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"
PATCH_SHA256 = "c9072c0188bc92aae0a8f3c20335ff8f4046f3a924befa530de0fcda2628d3ef"
PARENT = "f1e35e4c28ee84cfe6b22ffc4a7f32e78f597cef"
PARENT_TREE = "363478a4fde7dfe9190b180a610da897e9b4c9c0"

def run(root, *args, **kwargs):
    return subprocess.run(args, cwd=root, check=True, timeout=180, **kwargs)

def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    root = Path(sys.argv[1]).resolve(strict=True)
    parent = run(root, "git", "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    tree = run(root, "git", "rev-parse", "HEAD^{tree}", capture_output=True, text=True).stdout.strip()
    if parent != PARENT or tree != PARENT_TREE:
        raise SystemExit("source parent/tree mismatch")
    if run(root, "git", "status", "--porcelain", capture_output=True, text=True).stdout:
        raise SystemExit("source worktree is not clean")
    patch = zlib.decompress(base64.b64decode(PATCH, validate=True))
    if hashlib.sha256(patch).hexdigest() != PATCH_SHA256:
        raise SystemExit("fixed patch digest mismatch")
    run(root, "git", "apply", "--check", "-", input=patch)
    run(root, "git", "apply", "-", input=patch)
    gen = load_module(root/"tools/contracts/generate_module_contracts.py", "contracts")
    check = load_module(root/"tools/contracts/check_module_contract_compatibility.py", "compatibility")
    source_path = root/gen.CATALOG_PATH
    source = json.loads(source_path.read_bytes())
    old_catalog_raw = (root/gen.CONTRACT_CATALOG_PATH).read_bytes()
    old_by = {item["module_id"]:item for item in json.loads(old_catalog_raw)["modules"]}
    gen.write_outputs(root, gen.static_outputs())
    shared = (root/gen.SCHEMARS_PATH).read_bytes()
    initial = gen.generated(root, shared)
    docset_path = root/"docs/machine/doc-set.v1.json"
    docset = json.loads(docset_path.read_bytes())
    for module in source["modules"]:
        mid = module["id"]
        paths = old_by[mid]["artifacts"]
        old = {kind:(root/paths[kind]).read_bytes() for kind in ("api","errors","state")}
        new = {kind:initial[paths[kind]] for kind in old}
        kinds = sorted(kind for kind in old if check.fingerprint(json.loads(old[kind])) != check.fingerprint(json.loads(new[kind])))
        families = sorted({family for kind in kinds for family in check.semantic_change_families(json.loads(old[kind]),json.loads(new[kind]),kind)})
        if kinds != ["api","errors","state"]:
            raise SystemExit("unexpected contract change scope")
        packet = {
            "schema":gen.REVIEW_PACKET_SCHEMA, "module_id":mid,
            "contracts":kinds, "families":families,
            "base_catalog_sha256":gen.sha(old_catalog_raw),
            "base_contract_sha256":{kind:gen.sha(old[kind]) for kind in kinds},
            "target_contract_sha256":{kind:gen.sha(new[kind]) for kind in kinds},
            "migration_review_sha256":gen.semantic_digest(module["migration"]),
            "rollback_review_sha256":gen.semantic_digest(module["rollback"]),
            "reviewer":"Tomasrgbsf", "review_authority":gen.REVIEW_AUTHORITY,
            "approval_asserted":False, "automatic_redispatch":False,
            "public_release":False, "claim_ceiling":gen.CLAIM_CEILING}
        raw = gen.canonical_packet(packet)
        relative = "docs/reviews/module-contracts/"+gen.sha(raw)+".json"
        path = root/relative
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        module["compatibility"]["contract_change_review"] = {
            "class":"BREAKING_MIGRATION","review_packet":relative}
        docset["required_files"].append(relative)
    source_path.write_bytes(gen.canonical_json(source))
    docset_path.write_bytes(gen.canonical_json(docset))
    run(root,sys.executable,"tools/contracts/generate_module_contracts.py","--write")
    run(root,sys.executable,"tools/docs/generate_global_docs.py")
    run(root,sys.executable,"-m","unittest","tools.tests.test_module_contracts","tools.tests.test_verify_global_docs_contracts","-q")
    run(root,sys.executable,"tools/docs/verify_global_docs.py")
    run(root,"git","add","--all")
    tree = run(root,"git","write-tree",capture_output=True,text=True).stdout.strip()
    print(json.dumps({"candidate_tree":tree,"source_parent":parent,
        "source_preparation_only":True,"approval_asserted":False,"public_release":False},sort_keys=True))

if __name__ == "__main__":
    main()
