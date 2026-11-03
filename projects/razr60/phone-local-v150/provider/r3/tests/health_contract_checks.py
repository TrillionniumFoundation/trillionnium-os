#!/usr/bin/env python3
"""Narrow offline r3 health-contract checks; never contacts model or phone."""
import argparse,ast,concurrent.futures,copy,hashlib,json,os,secrets,sys,threading,types
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/"source"))
import health_contracts as h
import provider_phone_local as p
def sha(raw): return hashlib.sha256(raw).hexdigest()
def raw(value): return json.dumps(value,ensure_ascii=False,separators=(",",":")).encode()
def put(path,value):
    data=value if isinstance(value,bytes) else raw(value)
    with path.open("xb") as out: out.write(data)
    path.chmod(0o600)
def rejected(callback):
    try: callback()
    except (ValueError,p.ProviderError,FileNotFoundError,FileExistsError): return
    raise AssertionError("expected closed rejection")
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();args.out.parent.mkdir(parents=True,exist_ok=True,mode=0o700);args.out.mkdir(mode=0o700)
    checks=[]
    def check(name,ok=True):
        assert ok,name
        checks.append(name)
    state=args.out/"state";state.mkdir(mode=0o700)
    nonce="OFFLINE_HEALTH_"+secrets.token_hex(16)
    request="Offline fixture, no device calls. Return exactly "+nonce
    identity={key:key+"-"+secrets.token_hex(8) for key in
              ("session_id","profile_id","task_id","turn_id","turn_stream_id")}
    reg=h.register(state,request,identity["session_id"],identity["profile_id"],nonce)
    check("registration_only_exact_request",reg["request_sha256"]==sha(request.encode()) and reg["dispatched"] is False)
    contract=h.load(state/"health-contracts",identity,request)
    check("exact_known_scope_and_consumed_identity",contract["identity"]=={key:identity[key] for key in h.IDENTITY})
    check("health_schema_is_bound",contract["schema"]=="hepta.bound-health-contract.v150.3")
    rejected(lambda:h.load(state/"health-contracts",identity,request));check("same_request_not_reconsumed")
    replacement=dict(identity,task_id="task-"+secrets.token_hex(8))
    rejected(lambda:h.load(state/"health-contracts",replacement,request));check("new_task_id_does_not_reuse_template")
    rejected(lambda:h.register(state,request,identity["session_id"],identity["profile_id"],nonce));check("registration_never_overwrites")
    schema=h.final_only_schema(p.SCHEMA)
    check("final_only_kind",schema["properties"]["kind"]["const"]=="turn.complete")
    check("tool_none_and_empty_action_fields",schema["properties"]["tool"]["const"]=="none"
          and schema["properties"]["argv"]["maxItems"]==0
          and schema["properties"]["call_id"]["const"]==schema["properties"]["command"]["const"]=="")
    check("summary_not_grammar_forced",schema["properties"]["summary"]=={"type":"string","maxLength":1024}
          and nonce not in json.dumps(schema))
    check("normal_business_schema_unchanged","tool.call" in p.SCHEMA["properties"]["kind"]["enum"])
    valid={"kind":"turn.complete","tool":"none","call_id":"","command":"","argv":[],
           "summary":nonce,"task_status":"completed"}
    h.validate_decision(contract,valid);check("exact_nonce_decision_accepted")
    bad=dict(valid,summary=nonce+"x")
    rejected(lambda:h.validate_decision(contract,bad));check("wrong_nonce_rejected_independently")
    bad=dict(valid,kind="tool.call",tool="phone.open_app",argv=["视觉挑战"],call_id="r01_fixture",task_status="in_progress")
    rejected(lambda:h.validate_decision(contract,bad));check("well_formed_phone_action_forbidden")
    adapter=p.PhoneLocalAdapter.__new__(p.PhoneLocalAdapter)
    adapter.health_contract=contract;adapter.round=1;adapter.phone_tools=types.SimpleNamespace(calls={})
    adapter.receive=lambda *a,**k: (_ for _ in ()).throw(AssertionError("dispatch fence must run before receive"))
    rejected(lambda:adapter._decision(bad,"r01_fixture"));check("decision_guard_prevents_mapping")
    rejected(lambda:adapter.emit("tool.call",call={"call_id":"different","tool":"shell.exec","argv":["never"]}))
    check("native_emit_guard_prevents_dispatch")
    check("no_mapped_phone_call",adapter.phone_tools.calls=={})
    adapter._decision(valid,"unused");check("valid_completion_sets_completed_status",adapter.model_task_status=="completed")
    run=args.out/"run";run.mkdir(mode=0o700)
    rid=secrets.token_hex(16)
    body={"model":"fixture-phone-model","response_format":{"type":"json_schema","json_schema":{"schema":schema}},
          "messages":[{"role":"user","content":[{"type":"text","text":request}]}]}
    response={"model":"fixture-phone-model","choices":[{"finish_reason":"stop","message":{"content":json.dumps(valid)}}]}
    receipt={"request_id":rid,"attempt_count":1,"http_status":200,"transport_terminal":"complete_http_response",
        "inference_terminal":"stop","error_category":None,"automatic_retry":False,"fallback_model":False,
        "redirect_followed":False,"request_sha256":sha(raw(body)),"response_sha256":sha(raw(response)),
        "response_bytes":len(raw(response)),"response_model":"fixture-phone-model",
        "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"elapsed_monotonic_seconds":.01}
    originals={".request.json":body,".http-response.json":response,".http-receipt.json":receipt,
        ".worker-result.json":{"request_id":rid,"returncode":0,"cancelled":False},
        ".joined.json":{"child_wait_returned":True,"dedicated_process_group_absent":True},
        ".slot-before.json":{"observed":True,"idle":True,"slot":{"is_processing":False}},
        ".slot-after.json":{"observed":True,"idle":True,"slot":{"is_processing":False}},
        ".decision.json":valid}
    for suffix,value in originals.items(): put(run/("local-01"+suffix),value)
    verified=h.terminal_evidence(contract,"turn.complete",nonce,run,1,rid,0,set(),{})
    check("complete_http_join_slot_evidence",verified["provider_checks_passed"] is True)
    check("native_completion_still_independently_required",verified["native_completed_required_independently"] is True
          and verified["business_verified"] is False)
    rejected(lambda:h.terminal_evidence(contract,"turn.complete",nonce,run,1,rid,1,{"attempt"},{}))
    check("any_recorded_tool_prevents_health_success")
    rejected(lambda:h.terminal_evidence(contract,"turn.complete",nonce,run,2,rid,0,set(),{}))
    check("health_not_multiple_model_rounds")
    for suffix,key,value,name in [
        (".http-receipt.json","inference_terminal","length","budget_exhaustion_never_success"),
        (".http-receipt.json","attempt_count",2,"retry_count_never_success"),
        (".joined.json","dedicated_process_group_absent",False,"unjoined_worker_never_success"),
        (".slot-after.json","idle",False,"busy_phone_slot_never_success")]:
        path=run/("local-01"+suffix);changed=copy.deepcopy(originals[suffix]);changed[key]=value
        path.write_bytes(raw(changed))
        rejected(lambda:h.terminal_evidence(contract,"turn.complete",nonce,run,1,rid,0,set(),{}))
        path.write_bytes(raw(originals[suffix]));check(name)
    forced=copy.deepcopy(body);forced["response_format"]["json_schema"]["schema"]["properties"]["summary"]={"type":"string","const":nonce}
    (run/"local-01.request.json").write_bytes(raw(forced))
    changed=copy.deepcopy(receipt);changed["request_sha256"]=sha(raw(forced))
    (run/"local-01.http-receipt.json").write_bytes(raw(changed))
    rejected(lambda:h.terminal_evidence(contract,"turn.complete",nonce,run,1,rid,0,set(),{}))
    check("schema_forced_nonce_is_not_health_proof")
    (run/"local-01.request.json").write_bytes(raw(body));(run/"local-01.http-receipt.json").write_bytes(raw(receipt))
    cancelled=h.terminal_evidence(contract,"turn.cancelled",None,run,1,rid,0,set(),{})
    check("cancelled_terminal_not_health_success",cancelled["provider_checks_passed"] is False)
    bad_scope=dict(identity,profile_id="other-profile")
    nonce2="OFFLINE_HEALTH_"+secrets.token_hex(16);request2="Return "+nonce2
    h.register(state,request2,identity["session_id"],identity["profile_id"],nonce2)
    rejected(lambda:h.load(state/"health-contracts",bad_scope,request2));check("profile_mismatch_closed")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(h.load,state/"health-contracts",identity,request2) for _ in range(2)]
        successes=0
        for future in futures:
            try: future.result();successes+=1
            except (ValueError,FileExistsError): pass
    check("concurrent_consume_exactly_once",successes==1)
    for path in (ROOT/"source").glob("*.py"): ast.parse(path.read_bytes(),feature_version=(3,12))
    check("all_runtime_sources_python3_12_syntax")
    result={"schema":"hepta.health-contract-offline-validation.v150.3","status":"PASS",
        "assertions":len(checks),"checks":checks,"actual_phone_actions":0,"actual_model_requests":0,
        "synthetic_receipts_are_not_live_qualification":True,
        "health_module_sha256":sha((ROOT/"source/health_contracts.py").read_bytes()),
        "provider_sha256":sha((ROOT/"source/provider_phone_local.py").read_bytes())}
    put(args.out/"RESULT.json",result)
    print(json.dumps(result,separators=(",",":")))
if __name__=="__main__": main()
