"""Independently reparse original typed receipts with byte-pinned frozen code.

Only pure parsers are used. No mapper, tool executor, socket, subprocess or
model client is invoked. Parser-created image/JSON artifacts go into the new
collector output directory. Existing evidence is never modified.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok,message):
    if not ok: raise ValueError(message)

def exclusive(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())

def recheck(snapshot,provider_source,seal,contract,outcome,scope,request,calls,result_by_id,run):
    source_root=Path(provider_source).absolute()
    trusted=snapshot.out/"typed-parser-source"
    trusted.mkdir(mode=0o700)
    pins=[]
    for item in seal["production_files"]:
        relative=Path(item["path"])
        require(relative.parts[0]=="source" and len(relative.parts)==2
                and relative.suffix==".py","unexpected source path in selected seal")
        raw=snapshot.read(source_root/relative.name)
        require(len(raw)==item["bytes"] and sha(raw)==item["sha256"],"typed parser source pin differs")
        exclusive(trusted/relative.name,raw)
        pins.append(item)
    if not contract or "contract" not in contract:
        return {"status":"NO_TRUSTED_BUSINESS_CONTRACT","source_pins_verified":True,
                "business_verified":False,"raw_native_facts_reparsed":False}
    required_modules={"provider_openai_compatible","phone_observation_tools","phone_task_guards",
                      "task_postconditions"}
    require(not required_modules.intersection(sys.modules),
            "typed parser module names already loaded; use a fresh collector process")
    before=list(sys.path)
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(trusted))
    try:
        phone=importlib.import_module("phone_observation_tools")
        tasks=importlib.import_module("task_postconditions")
        tasks.validate_conditions(contract["contract"]["postconditions"])
        derived=snapshot.out/"typed-derived"
        derived.mkdir(mode=0o700)
        def record(path,value):
            require(path.parent==derived,"derived parser path left new collection output")
            exclusive(path,json.dumps(value,ensure_ascii=False,separators=(",",":")).encode())
        parser=phone.PhoneTools(derived,record)
        parser.bind(scope)
        parser.visual_read_constraints=[item for item in contract["contract"]["postconditions"]
            if item["kind"]=="visual_receipt_matches_challenge"]
        messages=[{"role":"user","content":request.decode("utf-8",errors="strict")}]
        issues=[]
        for index,call in enumerate(calls):
            key=sha(call["call_id"].encode())
            semantic=snapshot.json(run/("semantic-"+key+".json"))
            require(semantic["wire_call"]==call and semantic["turn"]==scope,"parser semantic binding differs")
            parser.calls[call["call_id"]]=semantic
            result=result_by_id.get(call["call_id"])
            if result is None:
                issues.append({"call_id":call["call_id"],"reason":"original native result missing"})
                break
            messages.append({"role":"tool","tool_call_id":call["call_id"],
                             "content":json.dumps(result,ensure_ascii=False,separators=(",",":"))})
            try:
                # The frozen function parses the original result and records fresh
                # derivations only. No command mapper or device executor is called.
                parser.prepare(messages,messages,index+1)
            except Exception as error:
                issues.append({"call_id":call["call_id"],"error_class":type(error).__name__,
                               "reason":str(error)})
                break
        facts=list(parser.verified_facts.values())
        expected=tasks.evaluate(contract,facts,parser.last_result_call_id,
            (outcome or {}).get("model_reported_status"),
            (outcome or {}).get("requested_protocol_terminal"))
        agrees=bool(outcome and all(expected.get(key)==outcome.get(key) for key in
            ("business_verified","postconditions_verified","postconditions",
             "missing_postconditions","verified_facts","coverage","contract_sha256")))
        return {"status":"PASS" if agrees and not issues else "INCOMPLETE_OR_MISMATCH",
                "source_pins_verified":True,"raw_native_facts_reparsed":True,
                "business_verified":bool(expected["business_verified"] and agrees and not issues),
                "recorded_business_outcome_agrees":agrees,
                "independent_postconditions":expected["postconditions"],
                "independent_verified_facts":facts,"issues":issues,
                "phone_operations":0,"model_requests":0,"tool_calls_replayed":0}
    finally:
        sys.path[:]=before
