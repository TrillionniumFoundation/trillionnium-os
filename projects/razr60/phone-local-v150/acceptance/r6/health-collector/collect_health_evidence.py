#!/usr/bin/env python3
"""Read-only evidence collection for one explicitly selected fresh phone turn.

No sockets, ADB, shell, subprocess, model calls or sidecar inspect/execute.
Only named evidence is read; a new private output directory preserves exact
input bytes by SHA256. Run on the phone, or against an explicitly copied snapshot.
Missing/unknown/cancelled evidence never becomes business success.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from native_journal_audit import SCOPE_FIELDS, strict_loads, verify_records

SEAL = "26eb35e366cbc577408fe2662dc6c34d8a80f786bd46c584c43b5c9e2f7382a3"
CONFIG = "0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755"
SERVICE = "ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2"
MODEL = "gui-owl-1.5-2b-phone-q4km"
MUTATIONS = {"phone.open_app", "phone.tap", "phone.input_text", "phone.return_hepta"}
SAFE_STATES = {"completed", "failed", "timed_out", "cancelled", "output_limit_exceeded"}
TERMINALS = {"turn.complete", "turn.fail", "turn.cancelled"}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def compact(value, sort=False, ascii=False):
    return json.dumps(value, sort_keys=sort, ensure_ascii=ascii,
                      separators=(",", ":"), allow_nan=False).encode()

def identity(info):
    return tuple(getattr(info,k) for k in
                 ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_nlink"))

class Snapshot:
    def __init__(self, out, max_total):
        self.out, self.max_total, self.total = out, max_total, 0
        self.rows, self.cache, self.stats = [], {}, {}
        (out/"raw").mkdir(mode=0o700)

    def read(self, path, required=True, maximum=64*1024*1024):
        path = Path(path).absolute()
        key = str(path)
        if key in self.cache:
            return self.cache[key]
        require(path.parent.resolve() == path.parent, "noncanonical evidence parent: " + key)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            if not required:
                return None
            raise
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and 0 <= before.st_size <= maximum, "evidence file type/size differs: " + key)
            require(self.total + before.st_size <= self.max_total, "total evidence byte bound reached")
            pieces, length = [], 0
            while True:
                part = os.read(fd, min(1024*1024, maximum+1-length))
                if not part:
                    break
                pieces.append(part)
                length += len(part)
                require(length <= maximum, "evidence grew beyond its bound")
            raw = b"".join(pieces)
            after, named = os.fstat(fd), path.lstat()
            require(identity(before) == identity(after) == identity(named)
                    and len(raw) == before.st_size, "evidence changed during snapshot: " + key)
        finally:
            os.close(fd)
        digest = sha(raw)
        destination = self.out/"raw"/digest
        if not destination.exists():
            write_new(destination,raw)
        self.rows.append({"source":key,"bytes":len(raw),"sha256":digest,
                          "copy":"raw/"+digest,"independent_file_snapshot":True})
        self.cache[key], self.stats[key] = raw, identity(before)
        self.total += len(raw)
        return raw

    def json(self, path, required=True, maximum=64*1024*1024):
        raw = self.read(path,required,maximum)
        return None if raw is None else strict_loads(raw)

    def lines(self,path,required=True):
        raw = self.read(path,required)
        if raw is None:
            return []
        require(not raw or raw.endswith(b"\n"), "incomplete final JSONL line: " + str(path))
        return [strict_loads(line) for line in raw.splitlines() if line]

    def final_changes(self):
        result = []
        for path, expected in self.stats.items():
            try:
                if identity(Path(path).lstat()) != expected:
                    result.append(path)
            except OSError:
                result.append(path)
        return result

def write_new(path,raw):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)

def decode64(value):
    require(isinstance(value,str),"base64 data must be text")
    raw = base64.b64decode(value,validate=True)
    require(base64.b64encode(raw).decode()==value,"noncanonical base64")
    return raw

def streams(result,call):
    require(result.get("call_id")==call["call_id"] and result.get("status")=="terminal",
            "provider tool result lacks exact terminal identity")
    events, term = result.get("events"), result.get("terminal")
    require(isinstance(events,list) and isinstance(term,dict),"provider event/terminal missing")
    data = {"stdout":bytearray(),"stderr":bytearray()}
    kinds = []
    for index,row in enumerate(events):
        require(row.get("call_id")==call["call_id"] and row.get("tool")==call["tool"]
                and type(row.get("seq")) is int and row["seq"]==index,"provider event identity/sequence differs")
        event = row["event"]
        kind = event["kind"]
        kinds.append(kind)
        if kind=="output":
            require(event.get("encoding")=="base64" and event.get("stream") in data,
                    "provider output encoding/stream differs")
            raw = decode64(event["data"])
            require(type(event.get("byte_count")) is int and event["byte_count"]==len(raw),
                    "provider output byte count differs")
            data[event["stream"]].extend(raw)
    require(kinds and kinds[0]=="accepted" and kinds[-1]=="terminal"
            and all(kinds.count(k)==1 for k in ("accepted","started","terminal"))
            and events[-1]["event"].get("terminal")==term,
            "provider result lacks unique ordered accepted/started/terminal")
    for name,raw in data.items():
        require(type(term.get(name+"_bytes")) is int and term[name+"_bytes"]==len(raw),
                "provider terminal byte count differs")
    return {key:bytes(value) for key,value in data.items()}

def native_tool_streams(frames,call,result):
    selected = [f for f in frames if f.get("call_id")==call["call_id"]]
    for kind in ("tool.accepted","tool.started","tool.result"):
        require(sum(f.get("kind")==kind for f in selected)==1,
                "native tool lacks unique "+kind)
    ending = next(f["payload"] for f in selected if f["kind"]=="tool.result")
    for key in ("exit_code","error","output_truncated","stdout_bytes","stderr_bytes"):
        require(ending.get(key)==result["terminal"].get(key),
                "native/provider tool terminal differs: "+key)
    output = {}
    for stream in ("stdout","stderr"):
        chunks = [decode64(f["payload"]["data"]) for f in selected if f["kind"]=="tool."+stream]
        output[stream] = b"".join(chunks)
    return output, ending

def inspect_tool(snapshot,run,state,sidecar,client,scope,call,result,frames):
    key = sha(call["call_id"].encode())
    semantic = snapshot.json(run/("semantic-"+key+".json"))
    require(semantic.get("call_id")==call["call_id"] and semantic.get("turn")==scope,
            "semantic record scope differs")
    require(semantic.get("wire_call")==call and semantic.get("wire_tool")==call["tool"],
            "semantic wire call differs from dispatched native call")
    require(call["tool"]=="shell.exec","selected phone-local proof requires actual shell.exec")
    argv = call["argv"]
    require(len(argv)==9 and argv[:3]==[
        "/usr/bin/python3","/var/lib/trillionnium/owner-open/phone-local-v150/tool_client.py","execute"]
        and argv[3]=="--action-id" and argv[5]=="--command-b64"
        and argv[7]=="--timeout-ms","phone executor argv differs")
    token, command = argv[4], decode64(argv[6])
    require(re.fullmatch("[0-9a-f]{32}",token) and semantic["capture_id"]==token,
            "action ID differs from semantic capture")
    require(str(int(argv[8]))==argv[8] and 1<=int(argv[8])<=60000,"tool timeout bound differs")
    command_sha = sha(command)
    row = {"call_id":call["call_id"],"semantic_tool":semantic["semantic_tool"],
           "wire_tool":call["tool"],"action_id":token,"command_sha256":command_sha,
           "call_sha256":sha(compact(call,sort=True,ascii=True)),
           "provider_result_present":result is not None,
           "native_raw_streams_equal":False,"safe_original_execution_terminal":False,
           "successful_original_execution":False,"issues":[]}
    saved = snapshot.json(run/("result-"+key+".json"),required=False)
    require(saved==result,"saved provider tool result differs from provider-in transcript")
    native_data = None
    if result is not None:
        provider_data = streams(result,call)
        native_data, ending = native_tool_streams(frames,call,result)
        require(provider_data==native_data,"original native raw stream differs from provider input")
        row["native_raw_streams_equal"] = True
        row["native_terminal"] = ending
        row["raw_output"] = {key:{"bytes":len(value),"sha256":sha(value)}
                             for key,value in native_data.items()}
        if semantic["semantic_tool"]=="phone.screenshot" and result["terminal"].get("exit_code")==0:
            envelope = strict_loads(native_data["stdout"])
            require(envelope.get("capture_id")==token,"screenshot envelope capture ID differs")
            image = envelope["screenshot"]
            encoded = decode64(image["data_base64"])
            require(sha(encoded)==image["image_sha256"] and len(encoded)==image["encoded_bytes"],
                    "native screenshot bytes/hash differs")
            capture = snapshot.json(run/("capture-"+token+".json"),required=False)
            if capture:
                require(capture["image_sha256"]==sha(encoded) and capture["turn"]==scope
                        and capture["original_result_sha256"]==sha(snapshot.read(run/("result-"+key+".json"))),
                        "derived capture binding differs")
                actual = snapshot.read(run/Path(capture["path"]).name)
                require(actual==encoded,"saved model image differs from native screenshot")
                row["native_screenshot_image_sha256"]=sha(encoded)
            else:
                row["issues"].append("Screenshot returned but not validated/attached by a later model round.")
    else:
        row["issues"].append("Provider did not durably consume the original tool result.")
    action = sidecar/"actions"/token
    intent = snapshot.json(action/"intent.json",required=False)
    receipt = snapshot.json(action/"receipt.json",required=False)
    pending = snapshot.read(action/"receipt.pending",required=False)
    if pending is not None:
        row["issues"].append("receipt.pending exists; do not infer a safe committed terminal from it.")
    for label,obj in (("sidecar intent",intent),("sidecar receipt",receipt)):
        if obj is not None:
            require(obj.get("action_id")==token and obj.get("command_sha256")==command_sha,
                    label+" action/command binding differs")
        else:
            row["issues"].append(label+" is absent.")
    claim = snapshot.json(client/(token+".claim.json"),required=False)
    client_result = snapshot.json(client/(token+".result.json"),required=False)
    if claim:
        require(claim.get("action_id")==token and claim.get("command_sha256")==command_sha,
                "client claim action/command binding differs")
    else:
        row["issues"].append("client claim is absent.")
    if receipt:
        row["sidecar_terminal"] = receipt
        row["executor_credential_evidence"] = {key:value for key,value in receipt.items()
            if "uid" in key or "gid" in key or "credential" in key}
        row["shell_uid_qualification_note"] = "Unicode/screenshot helper qualification requires actual UID2000; r4 root-only fixture is insufficient."
        safe = (receipt.get("state") in SAFE_STATES and receipt.get("terminal") is True
                and all(receipt.get(key) is True for key in
                        ("effect_started","process_group_established","waitpid_joined","process_group_absent")))
        row["safe_original_execution_terminal"] = safe
        require(receipt.get("dispatch_count") in (0,1),"sidecar dispatch count is not at-most-once")
        row["dispatch_count"] = receipt.get("dispatch_count")
        sidecar_data = {}
        for name in ("stdout","stderr"):
            raw = snapshot.read(action/(name+".bin"),required=False)
            if raw is not None:
                sidecar_data[name]=raw
                if receipt.get("terminal") is True:
                    require(len(raw)==receipt.get(name+"_bytes") and sha(raw)==receipt.get(name+"_sha256"),
                            "sidecar terminal output hash/length differs")
        row["client_received_same_terminal_receipt"] = bool(
            client_result and client_result.get("receipt")==receipt)
        if safe and receipt.get("state")=="completed" and native_data is not None:
            require(set(sidecar_data)=={"stdout","stderr"},"completed execution raw outputs are missing")
            require(native_data==sidecar_data,"completed sidecar raw output differs from native shell.exec")
            require(result["terminal"].get("exit_code")==receipt.get("exit_code"),
                    "completed sidecar/native exit codes differ")
            row["successful_original_execution"] = bool(
                receipt.get("exit_code")==0 and result["terminal"].get("kind")=="exited"
                and result["terminal"].get("error") is None
                and result["terminal"].get("output_truncated") is False
                and row["client_received_same_terminal_receipt"])
        elif native_data is not None and sidecar_data:
            row["cancel_or_failure_forwarding"] = {
                key:{"sidecar_sha256":sha(value),"native_sha256":sha(native_data[key]),
                     "equal":value==native_data[key]}
                for key,value in sidecar_data.items()}
            row["issues"].append("Failure/cancel can append client diagnostics or omit late output; no full-success inference.")
    ledger = state/"evidence"/"action-ledger"
    if semantic["semantic_tool"] in MUTATIONS:
        ledger_intent = snapshot.json(ledger/(token+".intent.json"),required=False)
        resolution = snapshot.json(ledger/(token+".resolution.json"),required=False)
        require(ledger_intent is not None,"mutating dispatch has no durable action ledger intent")
        require(ledger_intent.get("action_id")==token and ledger_intent.get("command_sha256")==command_sha
                and ledger_intent.get("call_id")==call["call_id"]
                and ledger_intent.get("semantic_identity")=={k:scope[k] for k in SCOPE_FIELDS[:-1]},
                "action ledger binding differs")
        row["effect_fingerprint"]=ledger_intent.get("effect_fingerprint")
        row["ledger_resolution"] = resolution
        row["unresolved_effect"] = resolution is None
        if resolution:
            require(resolution.get("action_id")==token and resolution.get("intent_sha256")==sha(
                snapshot.read(ledger/(token+".intent.json")))
                and resolution.get("automatic_replay") is False
                and resolution.get("business_verified") is False,
                "action ledger resolution lost original intent/no-replay binding")
            if resolution.get("native_result_sha256"):
                require(saved is not None and resolution["native_result_sha256"]==sha(
                    snapshot.read(run/("result-"+key+".json"))),"ledger native result hash differs")
            if resolution.get("inspection_sha256"):
                inspected = snapshot.read(ledger/(token+".inspection.json"))
                require(sha(inspected)==resolution["inspection_sha256"],"ledger original inspection hash differs")
                observed = strict_loads(inspected).get("receipt",{})
                require(observed.get("action_id")==token and observed.get("command_sha256")==command_sha,
                        "ledger original inspection action binding differs")
    else:
        row["unresolved_effect"]=False
    return row

R6_HEALTH_SOURCE_SEAL = "26eb35e366cbc577408fe2662dc6c34d8a80f786bd46c584c43b5c9e2f7382a3"
R6_HEALTH_POLICY = 'Perform this one-use no-action health check. Return one JSON object:\nkind="turn.complete", call_id="", tool="none", command="", argv=[], task_status="completed".\nSet summary to exactly the nonce requested in the owner\'s message. Copy it without any prefix, suffix, explanation, Markdown, or changed character. No tools, app actions, text edits, or additional rounds are allowed.'

def prompt_layout(body,exact_request,health_case=False):
    """Read exact messages; never reinterpret a normal request as a health check."""
    if isinstance(body.get("messages"),list) and len(body["messages"]) == 2:
        require(health_case and SEAL == R6_HEALTH_SOURCE_SEAL,
                "two-message layout requires selected frozen r6 HEALTH case")
        require(body["messages"] == [
                    {"role":"system","content":R6_HEALTH_POLICY},
                    {"role":"user","content":exact_request.decode("utf-8",errors="strict")}],
                "r6 minimal health policy or exact owner bytes differ")
        return "r6_health_exact_owner_only"
    if isinstance(body["messages"][1]["content"],str):
        projected = strict_loads(body["messages"][1]["content"])
        owner = body["messages"][-1]
        require(len(body["messages"])==3 and owner.get("role")=="user"
                and owner["content"][0].get("type")=="text"
                and owner["content"][0]["text"].encode("utf-8")==exact_request
                and projected.get("owner_request_utf8_sha256")==sha(exact_request)
                and not any(row.get("role")=="user" for row in projected["transcript"]),
                "r2 exact owner text/hash/layout binding differs")
        layout = "r2_explicit_owner_last"
    else:
        projected = strict_loads(body["messages"][1]["content"][0]["text"])
        user_rows = [row for row in projected["transcript"] if row.get("role")=="user"]
        require(len(user_rows)==1 and isinstance(user_rows[0].get("content"),str)
                and user_rows[0]["content"].encode("utf-8")==exact_request,
                "local model did not receive the exact original user input")
        layout = "r1_owner_in_context_transcript"
    return layout

def inspect_rounds(snapshot,run,original_run,exact_request,health_case=False):
    output = []
    for path in sorted(run.glob("local-*.request.json")):
        match = re.fullmatch(r"local-([0-9]{2})\.request\.json",path.name)
        require(match is not None,"unexpected model round filename")
        number, prefix = int(match[1]),path.name.removesuffix(".request.json")
        body = snapshot.json(path)
        layout = prompt_layout(body,exact_request,health_case)
        images = snapshot.json(run/(prefix+".images.json"))
        receipt = snapshot.json(run/(prefix+".http-receipt.json"),required=False)
        response = snapshot.read(run/(prefix+".http-response.json"),required=False)
        joined = snapshot.json(run/(prefix+".joined.json"),required=False)
        spawned = snapshot.json(run/(prefix+".spawned.json"),required=False)
        worker = snapshot.json(run/(prefix+".worker-result.json"),required=False)
        before = snapshot.json(run/(prefix+".slot-before.json"),required=False)
        after = snapshot.json(run/(prefix+".slot-after.json"),required=False)
        decision = snapshot.json(run/(prefix+".decision.json"),required=False)
        require(body.get("model")==MODEL and body.get("stream") is False
                and body.get("temperature")==0 and body.get("max_tokens")==256,
                "selected model/bounds differ")
        require(images.get("old_images_attached") is False
                and images.get("service_manifest_sha256")==SERVICE,
                "image metadata service pin or old-image policy differs")
        rows = images.get("images",[])
        urls = [part["image_url"]["url"] for message in body["messages"]
                if isinstance(message.get("content"),list) for part in message["content"]
                if part.get("type")=="image_url"]
        require(len(urls)==len(rows)<=1,"model image cardinality differs")
        image_hashes = []
        for url,meta in zip(urls,rows):
            require(url.startswith("data:image/jpeg;base64,"),"model image URL is not embedded JPEG")
            raw = decode64(url.split(",",1)[1])
            source = Path(meta["source"])
            require(source.parent==Path(original_run) and meta["attached_round"]==number
                    and meta["sha256"]==sha(raw) and meta["bytes"]==len(raw),
                    "model image source/round/hash binding differs")
            require(snapshot.read(run/source.name)==raw,"model request image differs from saved capture")
            image_hashes.append(sha(raw))
        properties=body["response_format"]["json_schema"]["schema"].get("properties", {})
        health_schema=(properties.get("summary")=={"type":"string","maxLength":1024}
            and all(properties.get(key,{}).get("const")==value for key,value in
                    {"kind":"turn.complete","tool":"none","call_id":"","command":"","task_status":"completed"}.items())
            and properties.get("argv",{}).get("maxItems")==0)
        row = {"round":number,"request_id":images["request_id"],"model":body["model"],
               "final_only_health_schema_with_unforced_summary":health_schema,
               "model_image_sha256":image_hashes,"max_tokens":body["max_tokens"],
               "exact_user_input_sha256":sha(exact_request),"exact_user_input_retained":True,
               "prompt_layout":layout,
               "http_receipt_present":receipt is not None,"http_response_complete":False,
               "worker_joined":bool(joined and joined.get("child_wait_returned") is True
                                    and joined.get("dedicated_process_group_absent") is True),
               "server_slot_observed_idle_after":bool(after and after.get("observed") is True
                                                     and after.get("idle") is True),
               "usage":None,"elapsed_monotonic_seconds":None,"timings":None,
               "raw_finish_reason":None,"provider_decision_present":decision is not None,
               "decision_summary_sha256":sha(decision["summary"].encode()) if isinstance(decision,dict) and isinstance(decision.get("summary"),str) else None,
               "decision_fields":{key:decision.get(key) for key in ("kind","tool","task_status","call_id","command","argv")} if isinstance(decision,dict) else None,
               "automatic_retry":False,"fallback_model":False,
               "client_exit_is_server_cancel_proof":False}
        if receipt:
            require(receipt.get("request_id")==images["request_id"]
                    and receipt.get("request_sha256")==sha(snapshot.read(path))
                    and receipt.get("attempt_count")==1
                    and receipt.get("automatic_retry") is False
                    and receipt.get("fallback_model") is False
                    and receipt.get("redirect_followed") is False
                    and receipt.get("service_manifest_sha256")==SERVICE,
                    "HTTP request/attempt/service identity differs")
            row.update(usage=receipt.get("usage"),timings=receipt.get("timings"),
                       elapsed_monotonic_seconds=receipt.get("elapsed_monotonic_seconds"),
                       raw_finish_reason=receipt.get("inference_terminal"),
                       error_category=receipt.get("error_category"),
                       transport_terminal=receipt.get("transport_terminal"))
            if response is not None:
                require(receipt.get("response_bytes")==len(response)
                        and receipt.get("response_sha256")==sha(response),"HTTP response hash differs")
                if receipt.get("http_status")==200:
                    decoded = strict_loads(response)
                    require(decoded.get("model")==MODEL,"HTTP response model differs")
                    require(decoded.get("usage")==receipt.get("usage"),"HTTP usage differs from raw response")
                    choices = decoded.get("choices",[])
                    require(len(choices)==1,"HTTP response choices differ")
                    row["raw_finish_reason"]=choices[0].get("finish_reason")
                    if decision is not None:
                        require(strict_loads(choices[0]["message"]["content"])==decision,
                                "saved model decision differs from raw response")
                    row["http_response_complete"] = bool(
                        receipt.get("transport_terminal")=="complete_http_response"
                        and choices[0].get("finish_reason")=="stop"
                        and receipt.get("error_category") is None)
        row["real_terminal_and_cleanup"] = bool(row["http_response_complete"]
            and row["worker_joined"] and row["server_slot_observed_idle_after"]
            and worker and worker.get("returncode")==0
            and before and before.get("observed") is True and before.get("idle") is True
            and spawned and spawned.get("actual_spawn") is True)
        output.append(row)
    require([row["round"] for row in output]==list(range(1,len(output)+1)),
            "model round sequence is incomplete")
    return output

def main():
    global SEAL,CONFIG,SERVICE,MODEL
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-state",type=Path,required=True)
    parser.add_argument("--run-dir",type=Path,help="Explicit copied run; basename must match original claim")
    parser.add_argument("--request-file",type=Path,required=True)
    parser.add_argument("--selected-scope-file",type=Path,required=True)
    parser.add_argument("--native-journal",type=Path,action="append",required=True,
                        help="Raw JSONL file or segment directory; may repeat, no wrapper JSON")
    parser.add_argument("--sidecar-journal",type=Path,required=True,
                        help="Directory containing actions/, not the actions directory itself")
    parser.add_argument("--client-receipts",type=Path,required=True)
    parser.add_argument("--source-seal",type=Path)
    parser.add_argument("--provider-source",type=Path,
                        help="Selected byte-pinned source directory for pure original-receipt reparse")
    parser.add_argument("--source-seal-sha256",default=SEAL,
                        help="Root-selected full production source seal; r1 default, explicit pin for later revisions")
    parser.add_argument("--config-file",type=Path,help="Config only; its api_key_file is never read")
    parser.add_argument("--service-manifest",type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--expected-summary-file",type=Path,
                        help="Exact fresh health model summary bytes; required to qualify a HEALTH pass")
    parser.add_argument("--case-id",required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--max-total-mib",type=int,default=512)
    args=parser.parse_args()
    require(args.case_id=="HEALTH","this r6 layout revision is qualified for HEALTH evidence only")
    require(1<=args.max_total_mib<=2048,"evidence budget out of range")
    output=args.out.absolute()
    require(output.parent.resolve()==output.parent,"output parent must be canonical")
    output.mkdir(mode=0o700)
    snapshot=Snapshot(output,args.max_total_mib*1024*1024)
    report={"schema":"hepta.readonly-turn-evidence.v150.1","case_id":args.case_id,
            "collection_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "collector_operations":{"phone_actions":0,"model_requests":0,"socket_requests":0,
                                    "sidecar_execute_or_inspect":0,"existing_evidence_writes":0},
            "candidate_source_seal_sha256":SEAL,"issues":[],"checks":{},
            "proof_complete":False,"complete_business_success":False,
            "task_classification":"unconfirmed","raw_evidence_private":True,
            "inference_phone_residency":"Requires independent actual process/service evidence; loopback alone is insufficient.",
            "timing_note":"HTTP durations are local monotonic durations. No cross-host clock subtraction.",
            "monetary_cost":None,"hardware_energy_joules":None,"native_end_to_end_latency_seconds":None}
    try:
        require(re.fullmatch("[0-9a-f]{64}",args.source_seal_sha256),"source seal pin must be SHA256")
        SEAL=args.source_seal_sha256
        selected_seal=None
        if args.source_seal:
            raw_seal=snapshot.read(args.source_seal)
            require(sha(raw_seal)==SEAL,"Root-selected source seal bytes differ")
            selected_seal=strict_loads(raw_seal)
            CONFIG=selected_seal["configuration"]["sha256"]
            SERVICE=selected_seal["phone_service_inputs_sha256"]
            MODEL=selected_seal["model"]
        report["candidate_source_seal_sha256"]=SEAL
        selected=snapshot.json(args.selected_scope_file)
        scope=selected.get("scope",selected)
        require(set(scope)==set(SCOPE_FIELDS) and all(isinstance(scope[k],str) and scope[k]
                                                    for k in SCOPE_FIELDS),"exact selected five-field scope required")
        report["scope"]=scope
        request=snapshot.read(args.request_file)
        text=request.decode("utf-8",errors="strict")
        require(request and b"\0" not in request,"exact request is empty or contains NUL")
        if args.nonce:
            require(re.fullmatch("[A-Za-z0-9_-]{16,64}",args.nonce) and text.count(args.nonce)==1,
                    "fresh nonce must occur exactly once")
        report["request_utf8_sha256"]=sha(request)
        report["fresh_nonce_supplied_and_exact"]=bool(args.nonce)
        state=args.provider_state.absolute()
        claim_key=sha(compact([scope[k] for k in SCOPE_FIELDS[:-1]],ascii=True))
        claim=snapshot.json(state/"evidence"/"claims"/claim_key)
        require(claim.get("identity")==scope and claim.get("request_sha256")==sha(request)
                and claim.get("state")=="accepted_no_redispatch","durable accepted claim differs")
        original_run=Path(claim["run_dir"])
        require(re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{32}",original_run.name),
                "claim run basename differs")
        run=args.run_dir.absolute() if args.run_dir else state/"evidence"/original_run.name
        require(run.name==original_run.name,"copied run basename must preserve original claim binding")
        report.update(original_run_dir=str(original_run),snapshot_run_dir=str(run))
        incoming=snapshot.lines(run/"provider-in.jsonl")
        outgoing=snapshot.lines(run/"provider-out.jsonl")
        require(incoming and incoming[0].get("kind")=="turn.start","provider turn.start missing")
        require(all(incoming[0]["turn"].get(k)==scope[k] for k in SCOPE_FIELDS)
                and incoming[0]["turn"].get("user_input","").encode()==request,
                "provider request/scope differs from selected request")
        for label,frames in (("in",incoming),("out",outgoing)):
            require([row.get("seq") for row in frames]==list(range(len(frames))),
                    "provider "+label+" sequence incomplete")
        terminal=snapshot.json(run/"terminal.json",required=False)
        ends=[row for row in outgoing if row.get("kind") in TERMINALS]
        require(len(ends)<=1,"multiple provider terminals")
        provider_kind=ends[0]["kind"] if ends else None
        report["provider_terminal"]=terminal
        report["checks"]["provider_terminal_persisted_and_last"]=bool(
            terminal and ends and outgoing[-1]==ends[0] and terminal.get("kind")==provider_kind
            and all(terminal.get(k)==v for k,v in ends[0].items() if k not in {"protocol","seq","kind"}))
        native=[]
        for entry in args.native_journal:
            paths=sorted(entry.glob("*.jsonl")) if entry.is_dir() else [entry]
            require(paths,"native journal input has no JSONL files")
            for path in paths:
                native.extend(snapshot.lines(path))
        native_audit=verify_records(native,scope)
        selected_records=native_audit.pop("selected_records")
        frames=native_audit.pop("frames")
        report["native_hash_verification"]=native_audit
        report["checks"]["native_record_and_turn_integrity"]=native_audit["status"]=="PASS"
        if selected_records:
            write_new(output/"selected-native-records.json",json_bytes(selected_records))
            report["native_turn_request_sha256"]=selected_records[0]["payload"].get("request_sha256")
        native_end=frames[-1].get("payload",{}) if frames and frames[-1].get("kind")=="turn.end" else {}
        report["native_terminal"]=native_end
        status_map={"turn.complete":"completed","turn.fail":"provider_failed","turn.cancelled":"cancelled"}
        report["checks"]["provider_native_terminal_agree"]=bool(
            provider_kind and native_end.get("status")==status_map[provider_kind])
        terminal_field="error" if provider_kind=="turn.fail" else "summary"
        report["checks"]["provider_native_terminal_text_agree"]=bool(terminal
            and terminal_field in native_end and native_end.get(terminal_field)==terminal.get(terminal_field))
        calls=[row["call"] for row in outgoing if row.get("kind")=="tool.call"]
        require(len({row["call_id"] for row in calls})==len(calls),"repeated provider call identity")
        results=[row for row in incoming if row.get("kind")=="tool.result"]
        require(len({row["call_id"] for row in results})==len(results),"repeated provider result identity")
        result_by_id={row["call_id"]:row for row in results}
        require(set(result_by_id)<=set(call["call_id"] for call in calls),"result without original dispatch")
        dispatches=[snapshot.json(path) for path in sorted(run.glob("dispatch-*.json"))]
        require([row["call"] for row in dispatches]==calls,"durable dispatch intent order differs")
        for row in dispatches:
            require(row["call_sha256"]==sha(compact(row["call"],sort=True,ascii=True)),
                    "dispatch call hash differs")
        report["tools"]=[]
        for call in calls:
            try:
                report["tools"].append(inspect_tool(snapshot,run,state,args.sidecar_journal.absolute(),
                    args.client_receipts.absolute(),scope,call,result_by_id.get(call["call_id"]),frames))
            except (OSError,ValueError,TypeError,KeyError,IndexError,AttributeError) as error:
                report["tools"].append({"call_id":call.get("call_id"),"evidence_error":str(error),
                    "successful_original_execution":False,"safe_original_execution_terminal":False})
        tool_rows=report["tools"]
        report["checks"]["all_original_tool_evidence_aligned"]=all(
            not row.get("evidence_error") and row.get("native_raw_streams_equal")
            and row.get("safe_original_execution_terminal") for row in tool_rows)
        report["checks"]["all_original_tool_executions_successful"]=all(
            row.get("successful_original_execution") for row in tool_rows)
        report["checks"]["no_unresolved_mutating_effects"]=all(
            not row.get("unresolved_effect",True) for row in tool_rows)
        fingerprints=[row["effect_fingerprint"] for row in tool_rows if row.get("effect_fingerprint")]
        require(len(fingerprints)==len(set(fingerprints)),"same bound effect dispatched twice in one turn")
        report["model_rounds"]=inspect_rounds(snapshot,run,original_run,request,args.case_id=="HEALTH")
        report["checks"]["all_model_rounds_real_terminal_and_cleanup"]=bool(report["model_rounds"]) and all(
            row["real_terminal_and_cleanup"] for row in report["model_rounds"])
        model_images={value for row in report["model_rounds"] for value in row["model_image_sha256"]}
        native_images={row["native_screenshot_image_sha256"] for row in tool_rows
                       if row.get("native_screenshot_image_sha256")}
        require(model_images<=native_images,"model received image without matching original native screenshot")
        contract=snapshot.json(run/"task-contract.json",required=False)
        outcome=snapshot.json(run/"business-outcome.json",required=False)
        report["business_outcome"]=outcome
        if args.provider_source and selected_seal:
            from business_fact_recheck import recheck
            independent=recheck(snapshot,args.provider_source,selected_seal,contract,outcome,scope,
                                request,calls,result_by_id,run)
        else:
            independent={"status":"PINNED_PARSER_SOURCE_NOT_PROVIDED",
                         "source_pins_verified":False,"business_verified":False}
        report["independent_business_reparse"]=independent
        report["checks"]["pinned_runtime_source_bytes_verified"]=independent.get("source_pins_verified") is True
        report["checks"]["business_contract_verified"]=bool(
            independent.get("business_verified") is True and
            outcome and outcome.get("business_verified") is True
            and outcome.get("postconditions_verified") is True
            and outcome.get("coverage")=="entire_request"
            and outcome.get("emitted_protocol_terminal")=="turn.complete"
            and outcome.get("identity")==scope
            and contract and contract.get("contract",{}).get("request_sha256")==sha(request)
            and outcome.get("contract_sha256")==contract.get("source_sha256"))
        if contract and contract.get("binding_kind")=="one_time_request_template":
            template=snapshot.read(state/"task-contracts"/"templates"/(sha(request)+".json"))
            binding=snapshot.read(state/"task-contracts"/"bindings"/(sha(request)+".json"))
            bound=strict_loads(binding)
            require(sha(template)==contract["template_sha256"] and sha(binding)==contract["binding_sha256"]
                    and bound["identity"]=={k:scope[k] for k in SCOPE_FIELDS[:-1]}
                    and bound["state"]=="consumed_no_reuse","one-time template/binding differs")
            conditions=contract["contract"]["postconditions"]
            if any(row["kind"]=="visual_receipt_matches_challenge" for row in conditions):
                require(sum(row.get("semantic_tool")=="phone.tap" for row in tool_rows)<=1,
                        "visual contract dispatched more than one tap")
            if any(row["kind"]=="text_readback_exact" for row in conditions):
                require(sum(row.get("semantic_tool")=="phone.input_text" for row in tool_rows)<=1,
                        "Unicode contract dispatched more than one input")
        for label,path,pin in (("source_seal",args.source_seal,SEAL),
                               ("production_config",args.config_file,CONFIG),
                               ("service_inputs",args.service_manifest,SERVICE)):
            report["checks"][label+"_pin_matches"]=bool(path and sha(snapshot.read(path))==pin)
        http=report["model_rounds"]
        for field in ("prompt_tokens","completion_tokens","total_tokens"):
            values=[row["usage"].get(field) if isinstance(row["usage"],dict) else None for row in http]
            report[field+"_sum"]=sum(values) if values and all(type(v) is int and v>=0 for v in values) else None
        durations=[row["elapsed_monotonic_seconds"] for row in http]
        report["http_elapsed_seconds_sum"]=sum(durations) if durations and all(
            type(v) in (int,float) and v>=0 for v in durations) else None
        report["observed_model_request_count"]=len(http)
        report["observed_tool_dispatch_count"]=len(calls)
        report["checks"]["whole_task_requires_fresh_nonce"]=bool(args.nonce)
        if args.case_id=="HEALTH":
            health_contract=snapshot.json(run/"health-contract.json",required=False)
            health_outcome=snapshot.json(run/"health-outcome.json",required=False)
            report["bound_health_contract"]=health_contract
            report["health_outcome"]=health_outcome
            health_bound=False
            if health_contract and health_contract.get("schema")=="hepta.bound-health-contract.v150.3":
                health_template=snapshot.read(state/"health-contracts"/"templates"/(sha(request)+".json"))
                health_binding=snapshot.read(state/"health-contracts"/"bindings"/(sha(request)+".json"))
                template_value,binding_value=strict_loads(health_template),strict_loads(health_binding)
                health_bound=bool(health_contract.get("request_sha256")==sha(request)
                    and health_contract.get("nonce")==args.nonce
                    and health_contract.get("identity")=={key:scope[key] for key in SCOPE_FIELDS[:-1]}
                    and health_contract.get("template_sha256")==sha(health_template)
                    and health_contract.get("binding_sha256")==sha(health_binding)
                    and template_value.get("expected_scope")=={key:scope[key] for key in ("session_id","profile_id")}
                    and template_value.get("request_sha256")==sha(request)
                    and template_value.get("nonce")==args.nonce
                    and binding_value.get("identity")==health_contract["identity"]
                    and binding_value.get("state")=="consumed_no_reuse"
                    and binding_value.get("template_sha256")==sha(health_template))
            report["checks"]["health_one_use_binding_verified"]=health_bound
            report["checks"]["health_provider_checks_passed"]=bool(health_bound and health_outcome
                and health_outcome.get("provider_checks_passed") is True
                and health_outcome.get("identity")==health_contract["identity"]
                and health_outcome.get("request_sha256")==sha(request)
                and health_outcome.get("nonce")==args.nonce
                and health_outcome.get("native_tool_dispatch_count")==0
                and health_outcome.get("mapped_phone_tool_count")==0)
            expected_summary=(snapshot.read(args.expected_summary_file) if args.expected_summary_file
                              else args.nonce.encode() if health_bound else None)
            final_round=http[-1] if http else {}
            report["checks"]["health_nonce_not_forced_by_schema"]=final_round.get("final_only_health_schema_with_unforced_summary") is True
            expected_display="[无动作；业务未独立验证] "+str(args.nonce)
            report["checks"]["health_native_display_keeps_known_prefix"]=bool(terminal
                and terminal.get("summary")==expected_display and native_end.get("summary")==expected_display)
            fields=final_round.get("decision_fields") or {}
            report["checks"]["health_has_one_model_round_and_no_tools"]=len(http)==1 and not calls
            report["checks"]["health_exact_new_nonce_summary"]=bool(
                expected_summary is not None and args.nonce
                and expected_summary.decode("utf-8").count(args.nonce)==1
                and final_round.get("decision_summary_sha256")==sha(expected_summary)
                and fields=={"kind":"turn.complete","tool":"none","task_status":"completed",
                             "call_id":"","command":"","argv":[]})
        proof_keys=[key for key in report["checks"] if key!="business_contract_verified"]
        report["proof_complete"]=all(report["checks"][key] for key in proof_keys)
        report["complete_business_success"]=bool(
            report["proof_complete"] and report["checks"]["business_contract_verified"])
        report["health_qualification_pass"]=bool(args.case_id=="HEALTH" and report["proof_complete"])
        if report["complete_business_success"]:
            report["task_classification"]="complete_success"
        elif provider_kind=="turn.cancelled" or native_end.get("status")=="cancelled":
            report["task_classification"]="cancelled"
        elif outcome and outcome.get("status")=="partial":
            report["task_classification"]="partial"
        elif provider_kind=="turn.fail":
            report["task_classification"]="failed"
        elif args.case_id=="HEALTH" and provider_kind=="turn.complete" and not calls:
            report["task_classification"]="health_pass" if report["health_qualification_pass"] else "health_protocol_only_complete"
        elif provider_kind=="turn.complete":
            report["task_classification"]="unverified_completion"
    except (OSError,ValueError,UnicodeError,TypeError,KeyError,IndexError,AttributeError) as error:
        report["issues"].append({"error_class":type(error).__name__,"error":str(error)})
        report["proof_complete"]=False
        report["complete_business_success"]=False
        report["health_qualification_pass"]=False
    changes=snapshot.final_changes()
    report["changed_after_snapshot"]=changes
    if changes:
        report["issues"].append({"error":"Sources changed after their independent snapshots; recollect after terminal."})
        report["proof_complete"]=False
        report["complete_business_success"]=False
        report["health_qualification_pass"]=False
        if report["task_classification"] in {"complete_success","health_pass"}:
            report["task_classification"]="unconfirmed"
    report["inputs"]=snapshot.rows
    report["input_bytes"]=snapshot.total
    report["source_snapshot_scope"]="Per-file stable reads plus final metadata recheck; not a filesystem-wide atomic snapshot."
    raw=json_bytes(report)
    write_new(output/"REPORT.json",raw)
    print(json.dumps({"report":str(output/"REPORT.json"),"report_sha256":sha(raw),
                      "case_id":args.case_id,"task_classification":report["task_classification"],
                      "proof_complete":report["proof_complete"],
                      "complete_business_success":report["complete_business_success"],
                      "issues":report["issues"],"phone_actions":0,"model_requests":0},
                     ensure_ascii=False,separators=(",",":")))
    return 0 if not report["issues"] else 2

if __name__=="__main__":
    sys.exit(main())
