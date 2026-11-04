#!/usr/bin/env python3
"""Prepare an entirely new acceptance request; no phone, model or task dispatch.

Root runs this helper to generate fresh bytes. It creates a new directory once;
it never registers, sends, retries, restores or replays any task.
Python 3.12+, standard library only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

SEAL = "700e5fb07e5ad250f4df5bd0452660b03dd0138b89718343e10e895c4db50d35"
PACKAGE = "org.trillionnium.hepta.controlprobe"
VISUAL = [
    {"id": "visual_receipt", "kind": "visual_receipt_matches_challenge",
     "package": PACKAGE,
     "challenge_view_id": PACKAGE + ":id/visual_challenge_code",
     "receipt_view_id": PACKAGE + ":id/visual_receipt",
     "challenge_prefix": "挑战码：", "receipt_prefix": "HEPTA_VISUAL_OK "},
    {"id": "return", "kind": "foreground_hepta"},
]

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def snapshot(path, maximum=4096):
    path = path.absolute()
    require(path.parent.resolve() == path.parent, "input parent is not canonical")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= maximum, "input is not a bounded regular file")
        data = os.read(fd, maximum + 1)
        after, named = os.fstat(fd), path.lstat()
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
            require(getattr(before, field) == getattr(after, field)
                    == getattr(named, field), "input changed while read")
        require(len(data) == before.st_size, "input length changed")
    finally:
        os.close(fd)
    return data

def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()

def materialize(kind, nonce, text=None):
    require(re.fullmatch("[0-9a-f]{32}", nonce), "nonce must be 32 lowercase hex characters")
    metadata = {
        "schema": "hepta.fresh-acceptance-material.v150.1",
        "case": {"health": "HEALTH", "visual": "E2E-01", "unicode": "E2E-02"}[kind],
        "kind": kind, "nonce": nonce, "candidate_source_seal_sha256": SEAL,
        "phone_operations": 0, "model_operations": 0,
        "registered": False, "dispatched": False, "automatic_replay": False,
    }
    extras = {}
    if kind == "health":
        request = ("Fresh bounded local health request. Do not use any phone tool or operate the device. "
                   "Return final JSON with kind=turn.complete, tool=none, empty call_id/command/argv, "
                   "task_status=completed, and summary exactly this nonce: " + nonce)
        conditions = None
        metadata["business_qualification_eligible"] = False
    elif kind == "visual":
        request = ("本次 nonce=" + nonce
                   + "。打开“视觉挑战”，只根据本轮真实截图选择题目要求的选项一次。"
                   "点击前不得读取层级、挑战码或旧截图，不得二次尝试。"
                   "点击后用公开原文读取同一快照中的 visual_challenge_code 与 visual_receipt，"
                   "确认回执与挑战码匹配，最后返回 HEPTA。"
                   "任一条件不满足就如实报告部分完成或失败，不重复动作。")
        conditions = VISUAL
        metadata.update({
            "business_qualification_eligible": True,
            "requires_fresh_challenge_setup_by_root": True,
            "maximum_visual_taps": 1,
            "component": PACKAGE + "/.VisualChallengeActivity",
            "pre_tap_hierarchy_or_code_read_forbidden": True,
        })
    else:
        require(isinstance(text, str), "Unicode mode requires exact text")
        encoded = text.encode("utf-8", errors="strict")
        require(0 < len(encoded) <= 4096 and "\0" not in text,
                "Unicode text must have 1..4096 UTF-8 bytes and no NUL")
        require(nonce not in text, "task nonce must not also occur in Unicode text")
        delimiter = "HEPTA_TEXT_" + secrets.token_hex(12)
        require(delimiter not in text, "text delimiter collision")
        request = ("本次 nonce=" + nonce
                   + "。打开“Unicode验证”，读取当前输入框原文后，只输入一次下列精确文本。"
                   "分隔行不属于文本；保留所有换行、引号、空格和符号。"
                   "随后点击 unicode_submit 一次，公开读回 unicode_input、unicode_readback 和 "
                   "unicode_receipt 全文并核对，最后返回 HEPTA。"
                   "任一条件不满足就如实报告部分完成或失败，不重复输入或确认。\n"
                   + delimiter + "_BEGIN\n" + text + "\n" + delimiter + "_END")
        text_sha = sha(encoded)
        receipt = ("HEPTA_UNICODE_READBACK\nsha256=" + text_sha
                   + "\ncodepoints=" + str(len(text)) + "\nutf8_bytes=" + str(len(encoded)))
        receipt_bytes = receipt.encode()
        conditions = [
            {"id": "editor", "kind": "text_readback_exact", "package": PACKAGE,
             "view_id": PACKAGE + ":id/unicode_input", "utf8_sha256": text_sha},
            {"id": "public_readback", "kind": "public_text_exact", "package": PACKAGE,
             "view_id": PACKAGE + ":id/unicode_readback", "utf8_sha256": text_sha},
            {"id": "public_receipt", "kind": "public_text_exact", "package": PACKAGE,
             "view_id": PACKAGE + ":id/unicode_receipt", "utf8_sha256": sha(receipt_bytes)},
            {"id": "return", "kind": "foreground_hepta"},
        ]
        extras = {"expected-text.txt": encoded, "expected-public-receipt.txt": receipt_bytes}
        metadata.update({
            "business_qualification_eligible": True,
            "component": PACKAGE + "/.TextEntryActivity",
            "submit_view_id": PACKAGE + ":id/unicode_submit",
            "text_utf8_sha256": text_sha, "text_utf8_bytes": len(encoded),
            "text_codepoints": len(text), "public_receipt_sha256": sha(receipt_bytes),
            "maximum_input_attempts": 1, "maximum_submit_attempts_in_request": 1,
        })
    raw = request.encode("utf-8")
    require(request.count(nonce) == 1, "nonce occurrence count differs")
    metadata.update({"request_sha256": sha(raw), "request_utf8_bytes": len(raw),
                     "request_has_trailing_newline": request.endswith("\n"),
                     "contract_required": True,
                     "business_contract_required": conditions is not None,
                     "health_contract_required": kind == "health",
                     "registration_helper": "register_health_contract.py" if kind == "health" else "register_task_contract.py",
                     "coverage": "entire_request" if conditions is not None else None})
    return raw, conditions, extras, metadata

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["health", "visual", "unicode"])
    parser.add_argument("--out", type=Path, required=True, help="New, nonexistent owned directory")
    parser.add_argument("--nonce", help="Root-supplied fresh 32-lowercase-hex nonce; otherwise generated now")
    parser.add_argument("--text-file", type=Path, help="Exact fresh Unicode bytes; never trimmed")
    args = parser.parse_args()
    nonce = args.nonce or secrets.token_hex(16)
    require(args.kind == "unicode" or args.text_file is None, "--text-file is only for Unicode")
    text = None
    if args.kind == "unicode":
        if args.text_file:
            text = snapshot(args.text_file).decode("utf-8", errors="strict")
        else:
            marker = secrets.token_hex(12)
            text = ("本机验收·" + marker + " 🦉📱\n"
                    "第二行：原样保留 \"双引号\" '单引号' 与 $HOME $(echo literal) ; & | < > "
                    + chr(96) + "反引号" + chr(96) + " \\")
    raw, conditions, extras, metadata = materialize(args.kind, nonce, text)
    output = args.out.absolute()
    require(output.parent.resolve() == output.parent, "output parent must be canonical")
    require(output.parent.is_dir(), "output parent must already exist")
    output.mkdir(mode=0o700)  # EEXIST is deliberate: never overwrite or recycle a task.
    files = [write_new(output / "request.txt", raw)]
    if conditions is not None:
        files.append(write_new(output / "postconditions.json", json_bytes(conditions)))
    for name, value in extras.items():
        files.append(write_new(output / name, value))
    metadata["files"] = list(files)
    files.append(write_new(output / "material.json", json_bytes(metadata)))
    parent_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    print(json.dumps({"status": "fresh_material_only_not_registered_or_dispatched",
                      "case": metadata["case"], "nonce": nonce,
                      "request_sha256": metadata["request_sha256"], "files": files,
                      "phone_operations": 0, "model_operations": 0},
                     ensure_ascii=False, separators=(",", ":")))

if __name__ == "__main__":
    main()
