#!/usr/bin/env python3
"""Build an exact public-only R6 source/checkpoint blob allowlist; no network or phone."""
import gzip
import hashlib
import json
from pathlib import Path
import stat
import base64

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
GROUPS = {
    "r6_runtime_and_root_changes": [
        "R6-root-final01/ASSEMBLY.json",
        "R6-root-final01/R6-SOURCE-DELTA.json",
        "R6-root-final01/RUNTIME-DELTA.json.gz",
        "R6-root-final01/runtime/MANIFEST.json",
        "R6-root-final01/root-chain/SOURCE-MANIFEST.json",
        "R6-root-final01/runtime/source/component_lifecycle.py",
        "R6-root-final01/runtime/source/prepare_component.py",
        "R6-root-final01/runtime/source/send_new_native_guard_task_r10_r4.py",
        "R6-root-final01/runtime/source/stage_component.py",
        "R6-root-final01/root-chain/source/phone_chain_bridge.py",
        "R6-root-final01/root-chain/source/run_component_root_once.py",
    ],
    "r6_assemblers": ["assemble_runtime_r6.py", "assemble_runtime_r6_final01.py"],
    "r6_freeze_complete_finalized_directory": [
        "R6-runtime-freeze01/FREEZE-REQUEST.json",
        "R6-runtime-freeze01/ROOT-ACTUAL-FREEZE-CONTROLLER.original.json",
        "R6-runtime-freeze01/ROOT-ACTUAL-FREEZE-START.original.json",
        "R6-runtime-freeze01/ROOT-ACTUAL-TRANSFER-RECEIPTS.original.json",
        "R6-runtime-freeze01/ROOT-CONTROLLER-PUBLICATION.original.json",
        "R6-runtime-freeze01/ROOT-CONTROLLER-READBACK.original.mcp.json",
        "R6-runtime-freeze01/ROOT-REVIEW-DIRECTORY-CONTROLLER.original.json",
        "R6-runtime-freeze01/SOURCE-DELTA.json",
        "R6-runtime-freeze01/TRANSFER-INPUTS.json",
        "R6-runtime-freeze01/freeze_native_bound_runtime_r6_fc33.py",
    ],
    "r6_lease_budget_review": [
        "R6-lease-budget-review/REVIEW.json",
        "R6-lease-budget-review/R6-SOURCE-INVERSE-CONTROL.json",
        "R6-lease-budget-review/R6-FINAL-REVIEW.json",
        "R6-lease-budget-review/R6-FREEZE-ACTUAL-ARGV-REVIEW.json",
    ],
    "r6_business_sender_source_and_publication": [
        "R6-business-sender-01/candidate/CLOSE-DETAILS.new.txt",
        "R6-business-sender-01/candidate/CLOSE-DETAILS.old.txt",
        "R6-business-sender-01/candidate/SOURCE-DELTA.json",
        "R6-business-sender-01/candidate/SOURCE.patch",
        "R6-business-sender-01/candidate/send_new_native_task_r5_fc33_r6.py",
        "R6-business-sender-01/derive_business_sender.py",
        "R6-business-sender-01/ACTUAL-PUBLICATION-VERIFIED.json",
        "R6-business-sender-01/ROOT-ACTUAL-PUBLICATION.original.mcp.json",
        "R6-business-sender-01/ROOT-ACTUAL-READBACK.original.mcp.json",
    ],
    "r6_ui_actual_controls_and_prior_failure": [
        "R6-sender-ui/candidate02/host-control03/RESULT.original.json",
        "R6-sender-ui/candidate02/host-control03/ROOT-ACTUAL-HOST-CONTROLS.original.json",
        "R6-sender-ui/candidate02/host-control03/ROOT-ACTUAL-RESULT-READ.original.mcp.json",
        "R6-sender-ui/candidate02/ROOT-ACTUAL-HOST-CONTROLS.original.json",
    ],
    "r6_component_preparer_plan_and_execution_start_only": [
        "R6-component-preparer01/CREATE-PLAN-REQUEST.json",
        "R6-component-preparer01/NEG01-EXECUTION-REQUEST.json",
        "R6-component-preparer01/ROOT-NEG01-EXECUTION-START.original.json",
        "R6-component-preparer01/ROOT-NEG01-PLAN-CONTROLLER.original.json",
        "R6-component-preparer01/ROOT-NEG01-PLAN-READBACK.original.mcp.json",
        "R6-component-preparer01/ROOT-NEG01-PLAN-START.original.json",
        "R6-component-preparer01/ROOT-SOURCE-PUBLICATION.original.mcp.json",
        "R6-component-preparer01/SOURCE-DELTA.json",
        "R6-component-preparer01/prepare_native_bound_components_r6_fc33.py",
    ],
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(rel):
    path = ROOT / rel
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.resolve() != path:
        raise ValueError("not an exact regular local file: " + rel)
    raw = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, x) != getattr(after, x) for x in fields) or len(raw) != before.st_size:
        raise ValueError("source changed while reading: " + rel)
    return raw


def descriptor(rel, group):
    raw = read(rel)
    if not rel.endswith(".gz"):
        raw.decode("utf-8", "strict")
    return {
        "path": rel, "local_path": str(ROOT / rel), "bytes": len(raw),
        "sha256": sha(raw), "git_blob_sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
        "mode": "100644", "type": "blob", "category": group,
        "encoding": "base64" if rel.endswith(".gz") else "utf-8",
    }


def mcp_json(value):
    return json.loads(value["content"][0]["text"])


def main():
    paths = [rel for values in GROUPS.values() for rel in values]
    if len(paths) != 49 or len(set(paths)) != len(paths):
        raise ValueError("fixed requested original count changed")
    freeze_expected = set(GROUPS["r6_freeze_complete_finalized_directory"])
    freeze_actual = {str(p.relative_to(ROOT)) for p in (ROOT / "R6-runtime-freeze01").rglob("*") if p.is_file()}
    if freeze_actual != freeze_expected:
        raise ValueError("finalized freeze directory changed")

    bundle_raw = read("R6-root-final01/RUNTIME-DELTA.json.gz")
    if (len(bundle_raw), sha(bundle_raw)) != (354879, "9e55afe114fb1a87280f6cebeb515f33ff9b3b02ddfb81ffba7decb345246852"):
        raise ValueError("reviewed binary bundle differs")
    bundle = json.loads(gzip.decompress(bundle_raw))
    if bundle["schema"] != "hepta.fc33.reviewed-runtime-delta-bundle.v1" or len(bundle["files"]) != 17:
        raise ValueError("bundle shape differs")
    bundle_rows = []
    for row in bundle["files"]:
        body = base64.b64decode(row["base64"], validate=True)
        if len(body) != row["bytes"] or sha(body) != row["sha256"] or body != read("R6-root-final01/" + row["path"]):
            raise ValueError("bundle member differs: " + row["path"])
        if not (row["path"].endswith(".py") or row["path"].endswith("MANIFEST.json") or row["path"] == "runtime/reference/REVIEWED-PRODUCTION-PINS.json"):
            raise ValueError("non-source member in source bundle")
        bundle_rows.append({k: row[k] for k in ("path", "bytes", "sha256")})

    ui = json.loads(read("R6-sender-ui/candidate02/host-control03/RESULT.original.json"))
    if ui["private_UI_text_exported"] is not False or ui["phone_calls"] != 0 or ui["native_sends"] != 0 or ui["passed"] is not True or ui["control_count"] != 8:
        raise ValueError("public UI control result differs")
    failed = json.loads(read("R6-sender-ui/candidate02/ROOT-ACTUAL-HOST-CONTROLS.original.json"))
    failed_status = mcp_json(failed["status"])
    failed_read = mcp_json(failed["read"])
    if failed_status["exit_code"] != 1 or failed_status["state"] != "failed":
        raise ValueError("prior failed control not preserved as failed")
    stderr = failed_read["stderr"]
    if stderr["eof"] is not True or bytes.fromhex(stderr["bytes_hex"]).decode("utf-8") != stderr["text"] or stderr["size"] != 290:
        raise ValueError("prior error original incomplete")

    plan_readback = mcp_json(json.loads(read("R6-component-preparer01/ROOT-NEG01-PLAN-READBACK.original.mcp.json")))
    docs = {Path(row["path"]).name: json.loads(row["text"]) for row in plan_readback["files"]}
    for field in ("preserved_draft", "request"):
        if set(docs["ROOT-PLAN.json"][field]) != {"path", "bytes", "sha256"}:
            raise ValueError("plan embeds an unapproved body: " + field)
    if docs["RESULT.json"]["phone_calls"] != 0 or docs["RESULT.json"]["state"] != "ONE_NEW_COMPONENT_PLAN_PREPARED_NO_PHONE_EXECUTION":
        raise ValueError("plan receipt is not the original host-only result")

    rows = [descriptor(rel, group) for group, values in GROUPS.items() for rel in values]
    rows.append(descriptor(str(Path(__file__).resolve().relative_to(ROOT)), "public_allowlist_builder"))
    report = {
        "schema": "hepta.fc33.r6.exact-public-git-allowlist.v1",
        "state": "LOCAL_COMPLETE_BYTES_REVIEWED_GIT_UPLOAD_NOT_YET_ASSERTED",
        "repository_full_name": "TrillionniumFoundation/trillionnium-os",
        "original_count": 49,
        "file_count_excluding_this_allowlist": len(rows),
        "files": rows,
        "groups": {name: len(values) for name, values in GROUPS.items()},
        "public_content_review": {
            "source_bundle_members_full_bytes_checked": bundle_rows,
            "source_bundle_binary_bytes_preserved": True,
            "runtime_members": 38,
            "root_chain_members": 3,
            "ui_controls03": {"passed": True, "control_count": 8, "phone_calls": 0, "native_sends": 0, "private_UI_text_exported": False},
            "ui_controls02": {"state": "failed", "exit_code": 1, "stderr_bytes": 290, "stderr_sha256": sha(stderr["text"].encode())},
            "plan_private_fields_are_three_field_descriptors_only": True,
            "root_execution_evidence_in_this_source_package": "START_ONLY; subsequent failure is a separate evidence package",
        },
        "exclusions": [
            "private packet, XML, draft, sender archive and actual private body files",
            "R6 component execution status/read/terminal/failure generated after the fixed start-only selection",
            "unchanged runtime originals except source-only delta bundle members",
            "unrequested broad-directory contents outside the finalized freeze directory",
        ],
        "phone_calls": 0, "tree_created": False, "commit_created": False, "ref_updated": False,
        "private_packet_XML_draft_bodies_uploaded": False,
    }
    raw = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    target = OUT / "PUBLIC-WHITELIST.json"
    if target.exists():
        if target.read_bytes() != raw:
            raise ValueError("immutable allowlist already differs")
    else:
        with target.open("xb") as f:
            f.write(raw)
    print(json.dumps({"path": str(target), "bytes": len(raw), "sha256": sha(raw), "originals": 49, "with_builder_and_allowlist": len(rows) + 1, "source_bundle_members": len(bundle_rows)}))


if __name__ == "__main__":
    main()
