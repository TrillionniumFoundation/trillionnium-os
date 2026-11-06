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
from native_journal_audit import strict_loads

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok,message):
    if not ok: raise ValueError(message)

def exclusive(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())

def validate_contract(tasks, contract, scope, request, approved_apps=None):
    value=contract.get("contract")
    scoped=isinstance(value,dict) and value.get('schema')=='hepta.task-contract.v150.3'
    require(isinstance(value,dict) and set(value)=={
        "schema","identity","request_sha256","postconditions","coverage"}|({'app_scope'} if scoped else set()),
        "business contract shape differs")
    require(value["schema"] in {"hepta.task-contract.v149.1","hepta.task-contract.v150.2","hepta.task-contract.v150.3"},
            "business contract schema is not reviewed")
    require(value["identity"]=={key:scope[key] for key in tasks.IDENTITY}
            and value["request_sha256"]==sha(request)
            and value["coverage"] in {"entire_request","declared_postconditions_only"},
            "business contract request, identity or coverage differs")
    tasks.validate_conditions(value["postconditions"],
        allow_anchor=value["schema"]!="hepta.task-contract.v149.1")
    if scoped:
        require(isinstance(approved_apps,dict) and approved_apps,
                'new scoped contract requires the actual approved registry')
        tasks.validate_app_scope(value['app_scope'],sha(request),approved_apps)
    return value["schema"]

def verify_template_binding(snapshot,state,contract,scope,request,nonce):
    request_hash=sha(request)
    template=snapshot.read(state/"task-contracts"/"templates"/(request_hash+".json"))
    binding=snapshot.read(state/"task-contracts"/"bindings"/(request_hash+".json"))
    bound,original_template=strict_loads(binding),strict_loads(template)
    version={"hepta.task-contract.v149.1":"v149.1",
             "hepta.task-contract.v150.2":"v150.2",
             "hepta.task-contract.v150.3":"v150.3"}.get(contract["contract"]["schema"])
    require(version is not None,"unreviewed template-bound contract schema")
    expected_identity={k:scope[k] for k in ("session_id","profile_id","task_id","turn_id")}
    require(sha(template)==contract["template_sha256"] and sha(binding)==contract["binding_sha256"]
            and bound["identity"]==expected_identity==contract["contract"]["identity"]
            and bound["schema"]=="hepta.task-template-binding."+version
            and original_template["schema"]=="hepta.task-template."+version
            and original_template["expected_scope"]=={k:scope[k] for k in ("session_id","profile_id")}
            and original_template["request_sha256"]==bound["request_sha256"]==request_hash
            and original_template["nonce"]==bound["nonce"]==nonce
            and original_template["postconditions"]==contract["contract"]["postconditions"]
            and original_template["coverage"]==contract["contract"]["coverage"]
            and bound["template_sha256"]==sha(template)
            and bound["state"]=="consumed_no_reuse","one-time template/binding schema or identity differs")
    template_fields={'schema','expected_scope','request_sha256','nonce','postconditions','coverage'}
    binding_fields={'schema','identity','request_sha256','template_sha256','nonce','state'}
    scoped=version=='v150.3'
    require(set(original_template)==template_fields|({'app_scope'} if scoped else set())
            and set(bound)==binding_fields|({'app_scope','app_scope_sha256'} if scoped else set()),
            'one-time template/binding fields contain an unreviewed scope or directive')
    if scoped:
        scope_value=contract['contract']['app_scope']
        scope_sha=sha(json.dumps(scope_value,ensure_ascii=False,sort_keys=True,
                                separators=(',',':'),allow_nan=False).encode())
        require(original_template['app_scope']==bound['app_scope']==scope_value
                and bound['app_scope_sha256']==scope_sha
                and scope_value.get('owner_request_sha256')==request_hash,
                'one-time request app scope changed across template/binding/contract')
    canonical=json.dumps(contract["contract"],sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()
    require(sha(canonical)==contract["source_sha256"],"template-derived contract byte hash differs")
    verified={"schema_version":version,"one_time_binding_verified":True}
    if scoped:
        verified.update(app_scope_binding_verified=True,app_scope_sha256=scope_sha)
    return verified

def recheck(snapshot,provider_source,seal,contract,outcome,scope,request,calls,result_by_id,run,*,approved_apps=None):
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
        contract_schema=validate_contract(tasks,contract,scope,request,approved_apps)
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
        compared=("schema","business_verified","postconditions_verified","postconditions",
                  "missing_postconditions","verified_facts","coverage","contract_sha256")
        if contract_schema=='hepta.task-contract.v150.3':
            compared+=('app_scope','app_scope_sha256')
        agrees=bool(outcome and all(expected.get(key)==outcome.get(key) for key in compared))
        if contract_schema!='hepta.task-contract.v150.3':
            agrees=agrees and not any(k in (outcome or {}) for k in ('app_scope','app_scope_sha256'))
        return {"status":"PASS" if agrees and not issues else "INCOMPLETE_OR_MISMATCH",
                "source_pins_verified":True,"raw_native_facts_reparsed":True,
                "business_verified":bool(expected["business_verified"] and agrees and not issues),
                "recorded_business_outcome_agrees":agrees,
                "contract_schema":contract_schema,"outcome_schema":expected["schema"],
                "app_scope_sha256":expected.get('app_scope_sha256'),
                "independent_postconditions":expected["postconditions"],
                "independent_verified_facts":facts,"issues":issues,
                "phone_operations":0,"model_requests":0,"tool_calls_replayed":0}
    finally:
        sys.path[:]=before
        for item in pins:
            name=Path(item["path"]).stem
            module=sys.modules.get(name)
            if module is not None and Path(getattr(module,"__file__"," ")).parent==trusted:
                sys.modules.pop(name,None)
