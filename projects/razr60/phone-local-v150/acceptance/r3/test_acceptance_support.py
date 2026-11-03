#!/usr/bin/env python3
"""Offline collector checks; synthetic evidence is not phone/task qualification."""
import argparse
import ast
import base64
import copy
import json
import os
from pathlib import Path
import secrets
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import collect_turn_evidence as collect
from native_journal_audit import verify_records, record_hashes

def b64(raw): return base64.b64encode(raw).decode()
def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    collect.write_new(path,value if isinstance(value,bytes) else collect.json_bytes(value))

def fixture(root,state_name="completed",missing_provider=False):
    token=secrets.token_hex(16)
    scope={key:key+"-"+secrets.token_hex(8) for key in collect.SCOPE_FIELDS}
    call_id="r01_"+secrets.token_hex(8)
    command=b"printf fixture_only_never_executed"
    argv=["/usr/bin/python3","/var/lib/trillionnium/owner-open/phone-local-v150/tool_client.py",
          "execute","--action-id",token,"--command-b64",b64(command),"--timeout-ms","60000"]
    call={"call_id":call_id,"tool":"shell.exec","argv":argv}
    case=root/token
    run,state,sidecar,client=case/"run",case/"state",case/"sidecar",case/"client"
    for path in (run,state,sidecar,client): path.mkdir(parents=True,mode=0o700)
    semantic={"call_id":call_id,"capture_id":token,"turn":scope,"wire_call":call,
              "wire_tool":"shell.exec","semantic_tool":"phone.tap"}
    key=collect.sha(call_id.encode())
    put(run/("semantic-"+key+".json"),semantic)
    rawout="新输出 🦉\n".encode()
    side_err=b""
    native_err=b"" if state_name=="completed" else b"HEPTA_PHONE_LOCAL fixture cancellation diagnostic\n"
    terminal={"kind":"exited","exit_code":0 if state_name=="completed" else 73,
              "error":None,"output_truncated":False,"stdout_bytes":len(rawout),"stderr_bytes":len(native_err)}
    plain=[{"kind":"accepted"},{"kind":"started"},
           {"kind":"output","stream":"stdout","encoding":"base64","byte_count":2,"data":b64(rawout[:2])},
           {"kind":"output","stream":"stdout","encoding":"base64","byte_count":len(rawout)-2,"data":b64(rawout[2:])}]
    if native_err:
        plain.append({"kind":"output","stream":"stderr","encoding":"base64","byte_count":len(native_err),"data":b64(native_err)})
    plain.append({"kind":"terminal","terminal":terminal})
    result={"call_id":call_id,"status":"terminal","terminal":terminal,"events":[
        {"call_id":call_id,"tool":"shell.exec","seq":i,"event":value} for i,value in enumerate(plain)]}
    frames=[{"kind":"tool.accepted","call_id":call_id,"payload":{}},
            {"kind":"tool.started","call_id":call_id,"payload":{}},
            {"kind":"tool.stdout","call_id":call_id,"payload":{"data":b64(rawout)}}]
    if native_err: frames.append({"kind":"tool.stderr","call_id":call_id,"payload":{"data":b64(native_err)}})
    frames.append({"kind":"tool.result","call_id":call_id,"payload":terminal})
    if not missing_provider: put(run/("result-"+key+".json"),result)
    intent={"action_id":token,"command_sha256":collect.sha(command),"state":"intent","terminal":False}
    receipt={**intent,"state":state_name,"terminal":True,"effect_started":True,
        "process_group_established":True,"waitpid_joined":True,"process_group_absent":True,
        "dispatch_count":1,"exit_code":0 if state_name=="completed" else 143,
        "stdout_bytes":len(rawout),"stderr_bytes":len(side_err),
        "stdout_sha256":collect.sha(rawout),"stderr_sha256":collect.sha(side_err),
        "can_redispatch":False}
    action=sidecar/"actions"/token
    put(action/"intent.json",intent);put(action/"receipt.json",receipt)
    put(action/"stdout.bin",rawout);put(action/"stderr.bin",side_err)
    put(client/(token+".claim.json"),{"action_id":token,"command_sha256":collect.sha(command)})
    put(client/(token+".result.json"),{"receipt":receipt})
    ledger=state/"evidence"/"action-ledger"
    ledger_intent={"action_id":token,"command_sha256":collect.sha(command),"call_id":call_id,
                   "semantic_identity":{key:scope[key] for key in collect.SCOPE_FIELDS[:-1]},
                   "effect_fingerprint":collect.sha(b"fixture-only-"+token.encode())}
    put(ledger/(token+".intent.json"),ledger_intent)
    if not missing_provider:
        resolution={"action_id":token,"intent_sha256":collect.sha((ledger/(token+".intent.json")).read_bytes()),
                    "automatic_replay":False,"business_verified":False,
                    "native_result_sha256":collect.sha((run/("result-"+key+".json")).read_bytes())}
        put(ledger/(token+".resolution.json"),resolution)
    out=case/"collected"
    out.mkdir(mode=0o700)
    snap=collect.Snapshot(out,8*1024*1024)
    row=collect.inspect_tool(snap,run,state,sidecar,client,scope,call,
                             None if missing_provider else result,frames)
    return row,snap,frames,call,result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--historical-native-json",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    args.out.mkdir(mode=0o700)
    checks=[]
    def check(name,value):
        if not value: raise AssertionError(name)
        checks.append(name)
    for filename in ("materialize_case.py","native_journal_audit.py","collect_turn_evidence.py"):
        ast.parse((ROOT/filename).read_bytes(),feature_version=(3,12))
    check("python3_12_syntax",True)
    old_raw=args.historical_native_json.read_bytes()
    old=json.loads(old_raw)
    audited=verify_records(old["original_records"],old["identity"])
    check("actual_original_native_two_level_hashes",audited["status"]=="PASS"
          and audited["record_hashes_verified"]==2)
    check("filtered_turn_not_whole_global_chain",audited["global_chain_complete"] is False)
    changed=copy.deepcopy(old["original_records"])
    changed[0]["payload"]["request_sha256"]="0"*64
    check("native_payload_corruption_rejected",verify_records(changed,old["identity"])["status"]=="FAIL")
    changed=copy.deepcopy(old["original_records"])
    changed[1]["previous_record_sha256"]="0"*64
    changed[1]["payload_sha256"],changed[1]["record_sha256"]=record_hashes(changed[1])
    check("rehashed_wrong_predecessor_rejected",verify_records(changed,old["identity"])["status"]=="FAIL")
    row,snap,frames,call,result=fixture(args.out)
    check("complete_original_tool_streams_aligned",row["native_raw_streams_equal"] is True)
    check("split_unicode_bytes_preserved",row["raw_output"]["stdout"]["sha256"]==collect.sha("新输出 🦉\n".encode()))
    check("completed_effect_candidates_require_join_and_original_receipt",row["successful_original_execution"] is True)
    check("raw_input_copies_retained",all((snap.out/item["copy"]).read_bytes()==snap.cache[item["source"]] for item in snap.rows))
    bad=copy.deepcopy(frames)
    next(frame for frame in bad if frame["kind"]=="tool.stdout")["payload"]["data"]=b64(b"corruption")
    native,_=collect.native_tool_streams(bad,call,result)
    check("different_native_bytes_are_detectable",native!=collect.streams(result,call))
    row,_,_,_,_=fixture(args.out,"cancelled")
    check("cancel_execution_terminal_is_not_success",row["safe_original_execution_terminal"] is True
          and row["successful_original_execution"] is False)
    check("cancel_diagnostic_difference_is_explicit",row["cancel_or_failure_forwarding"]["stderr"]["equal"] is False)
    row,_,_,_,_=fixture(args.out,missing_provider=True)
    check("missing_native_result_never_success",row["successful_original_execution"] is False
          and row["provider_result_present"] is False and row["unresolved_effect"] is True)
    report={"status":"PASS","assertions":len(checks),"checks":checks,
        "historical_native_input_sha256":collect.sha(old_raw),
        "source_files":[{"name":name,"sha256":collect.sha((ROOT/name).read_bytes())}
                        for name in ("native_journal_audit.py","collect_turn_evidence.py")],
        "actual_phone_actions":0,"actual_model_requests":0,
        "synthetic_effect_executions":0,"scope":"collector integrity only; not native or model qualification"}
    put(args.out/"RESULT.json",report)
    print(json.dumps(report,separators=(",",":")))

if __name__=="__main__":
    main()
