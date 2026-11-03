"""One-use exact-request health contracts. No device/model access in this module.

A health contract grants no phone tools. Summary remains an unconstrained
string in the model schema; exact nonce equality is independently validated.
"""
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
from task_postconditions import (private_directory, private_json, write_exclusive,
                                  request_hash, require, IDENTITY)
from phone_local_http_worker import strict_json

TEMPLATE_SCHEMA = "hepta.health-template.v150.3"
MODE = "final_only_zero_phone_tools"
FIELDS = {"schema", "expected_scope", "request_sha256", "nonce", "mode"}

def validate_template(value):
    require(isinstance(value, dict) and set(value) == FIELDS
            and value["schema"] == TEMPLATE_SCHEMA and value["mode"] == MODE,
            "health template fields/mode differ")
    require(isinstance(value["expected_scope"], dict)
            and set(value["expected_scope"]) == {"session_id", "profile_id"}
            and all(isinstance(item, str) and 0 < len(item.encode()) <= 256 and "\0" not in item
                    for item in value["expected_scope"].values()), "health known scope differs")
    require(isinstance(value["request_sha256"], str)
            and re.fullmatch("[0-9a-f]{64}", value["request_sha256"])
            and isinstance(value["nonce"], str)
            and re.fullmatch("[A-Za-z0-9_-]{16,64}", value["nonce"]),
            "health request hash/nonce differs")

def register(state, request, session_id, profile_id, nonce):
    state = Path(state).absolute()
    private_directory(state)
    require(isinstance(request, str) and 0 < len(request.encode()) <= 512*1024
            and "\0" not in request and request.count(nonce) == 1,
            "health exact request or single fresh nonce differs")
    template = {"schema": TEMPLATE_SCHEMA, "expected_scope": {
        "session_id": session_id, "profile_id": profile_id},
        "request_sha256": request_hash(request), "nonce": nonce, "mode": MODE}
    validate_template(template)
    directory = state/"health-contracts"
    for path in (directory, directory/"templates", directory/"bindings"):
        path.mkdir(mode=0o700, exist_ok=True)
        private_directory(path)
    target = directory/"templates"/(template["request_sha256"]+".json")
    require(not (directory/"bindings"/target.name).exists(),
            "health request has already been consumed")
    digest = write_exclusive(target, template)
    return {"path": str(target), "template_sha256": digest,
            "request_sha256": template["request_sha256"], "mode": MODE,
            "phone_operations": 0, "model_requests": 0, "dispatched": False}

def load(directory, identity, request):
    directory = Path(directory)
    if not directory.exists():
        return None
    private_directory(directory)
    templates, bindings = directory/"templates", directory/"bindings"
    private_directory(templates); private_directory(bindings)
    selected = private_json(templates/(request_hash(request)+".json"))
    if selected is None:
        return None
    value, digest = selected
    validate_template(value)
    require(value["request_sha256"] == request_hash(request)
            and request.count(value["nonce"]) == 1
            and value["expected_scope"] == {key:identity[key] for key in ("session_id","profile_id")},
            "health original request/nonce/known scope differs")
    bound = {"schema": "hepta.health-template-binding.v150.3",
             "identity": {key:identity[key] for key in IDENTITY},
             "request_sha256": value["request_sha256"], "template_sha256": digest,
             "nonce": value["nonce"], "mode": MODE, "state": "consumed_no_reuse"}
    try:
        binding_sha = write_exclusive(bindings/(value["request_sha256"]+".json"), bound)
    except FileExistsError as error:
        raise ValueError("one-time health request consumed; no request or tool replay") from error
    return {**bound, "schema": "hepta.bound-health-contract.v150.3",
            "template_sha256": digest, "binding_sha256": binding_sha}

def final_only_schema(base):
    schema = copy.deepcopy(base)
    properties = schema["properties"]
    for name, value in {"kind":"turn.complete", "tool":"none", "call_id":"",
                        "command":"", "task_status":"completed"}.items():
        properties[name] = {"type":"string", "const":value}
    properties["argv"] = {"type":"array", "items":{"type":"string"}, "minItems":0, "maxItems":0}
    # Intentionally no const, enum, pattern or nonce literal in summary grammar.
    properties["summary"] = {"type":"string", "maxLength":1024}
    return schema

def validate_decision(contract, value):
    if contract is None:
        return
    require(isinstance(value, dict)
            and value.get("kind") == "turn.complete" and value.get("tool") == "none"
            and value.get("call_id") == "" and value.get("command") == ""
            and value.get("argv") == [] and value.get("task_status") == "completed"
            and value.get("summary") == contract["nonce"],
            "health contract forbids all tools and requires the exact new nonce summary")

def raw_private(path, maximum):
    require(path.parent.resolve() == path.parent, "health evidence path not canonical")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= maximum, "health evidence identity/size differs")
        with os.fdopen(fd,"rb",closefd=False) as stream:
            raw = stream.read(maximum+1)
        after, named = os.fstat(fd), path.lstat()
        require(len(raw) == before.st_size and all(
            getattr(before,key) == getattr(after,key) == getattr(named,key)
            for key in ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_nlink")),
            "health evidence changed during read")
    finally:
        os.close(fd)
    return raw

def terminal_evidence(contract, kind, summary, run_dir, round_number, request_id,
                      tool_count, dispatched_calls, mapped_calls):
    evidence = {"schema":"hepta.health-outcome.v150.3", "mode":MODE,
        "request_sha256":contract["request_sha256"], "nonce":contract["nonce"],
        "template_sha256":contract["template_sha256"],
        "binding_sha256":contract["binding_sha256"], "identity":contract["identity"],
        "provider_requested_terminal":kind, "provider_checks_passed":False,
        "native_completed_required_independently":True, "business_verified":False,
        "automatic_retry":False, "old_request_or_effect_replayed":False,
        "tool_count":tool_count, "native_tool_dispatch_count":len(dispatched_calls),
        "mapped_phone_tool_count":len(mapped_calls)}
    if kind != "turn.complete":
        return evidence
    require(round_number == 1 and tool_count == 0 and not dispatched_calls and not mapped_calls,
            "health must use one model round and zero phone tools")
    require(summary == contract["nonce"], "health completion summary differs from exact nonce")
    prefix = Path(run_dir)/("local-%02d" % round_number)
    def record(suffix):
        path = prefix.with_suffix(suffix)
        raw = raw_private(path, 65536)
        value = strict_json(raw)
        require(isinstance(value,dict), "health evidence must be an object")
        evidence[suffix.removeprefix(".").replace(".","_")+"_sha256"] = hashlib.sha256(raw).hexdigest()
        return value
    receipt = record(".http-receipt.json")
    worker = record(".worker-result.json")
    joined = record(".joined.json")
    after = record(".slot-after.json")
    before = record(".slot-before.json")
    decision = record(".decision.json")
    validate_decision(contract, decision)
    require(receipt.get("request_id") == request_id and receipt.get("attempt_count") == 1
            and receipt.get("http_status") == 200 and receipt.get("transport_terminal") == "complete_http_response"
            and receipt.get("inference_terminal") == "stop" and receipt.get("error_category") is None
            and receipt.get("automatic_retry") is False and receipt.get("fallback_model") is False
            and receipt.get("redirect_followed") is False, "health HTTP request lacks an original real terminal")
    request_raw = raw_private(prefix.with_suffix(".request.json"), 2*1024*1024)
    require(hashlib.sha256(request_raw).hexdigest() == receipt.get("request_sha256"),
            "health HTTP body hash differs")
    body = strict_json(request_raw)
    summary_schema = body["response_format"]["json_schema"]["schema"]["properties"]["summary"]
    require(summary_schema == {"type":"string", "maxLength":1024},
            "health nonce must not be forced by schema grammar")
    owner = body["messages"][-1]
    require(owner.get("role") == "user" and owner["content"][0].get("type") == "text"
            and request_hash(owner["content"][0]["text"]) == contract["request_sha256"],
            "health model did not receive the exact original owner input")
    response = raw_private(prefix.with_suffix(".http-response.json"), 1024*1024)
    require(hashlib.sha256(response).hexdigest() == receipt.get("response_sha256")
            and len(response) == receipt.get("response_bytes"), "health raw HTTP response differs")
    decoded = strict_json(response)
    require(decoded.get("model") == body.get("model") == receipt.get("response_model"),
            "health original model identity differs")
    choices = decoded.get("choices")
    require(isinstance(choices,list) and len(choices)==1
            and choices[0].get("finish_reason") == "stop"
            and strict_json(choices[0]["message"]["content"]) == decision,
            "health decision does not match original stopped model response")
    require(worker.get("request_id") == request_id and worker.get("returncode") == 0
            and worker.get("cancelled") is False
            and joined.get("child_wait_returned") is True
            and joined.get("dedicated_process_group_absent") is True,
            "health HTTP worker has not joined")
    require(before.get("observed") is True and before.get("idle") is True
            and after.get("observed") is True and after.get("idle") is True
            and after.get("slot",{}).get("is_processing") is False,
            "health phone inference slot cleanup is unconfirmed")
    evidence.update(provider_checks_passed=True, request_id=request_id,
        response_sha256=receipt["response_sha256"], model_finish_reason="stop",
        summary_utf8_sha256=hashlib.sha256(summary.encode()).hexdigest(),
        usage=receipt.get("usage"), elapsed_monotonic_seconds=receipt.get("elapsed_monotonic_seconds"),
        nonce_was_not_schema_const_or_enum=True)
    return evidence
