#!/usr/bin/env python3
"""Reproduce unchecked native metadata using the unchanged committed candidate.
All requests/receipts are host-generated fixtures. No source is patched.
"""
import argparse,copy,hashlib,importlib,importlib.util,json,os,sys,time
from pathlib import Path
HELPER_SHA="3269dbc7da98ab00ee60f1a458c71244ff312b17e541314b54e20c0ebec92bc7"
PINS_SHA="ccdb924f7b8e1556008a443f8412b4d35604e884dc171c9e7d855299f40b1fb4"
DENIED=[]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-package",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args();package=args.source_package.resolve();out=args.out
    assert out.is_absolute() and out.parent.resolve()==out.parent
    os.umask(0o077);out.mkdir(mode=0o700)
    helper=package/"test_shared_business_admission.py"
    assert sha(helper.read_bytes())==HELPER_SHA and sha((package/"CANDIDATE-PINS.json").read_bytes())==PINS_SHA
    def audit(event,arguments):
        denied=event in {"socket.__new__","socket.connect","socket.bind","socket.getaddrinfo",
                        "subprocess.Popen","os.system","os.fork","os.forkpty","os.posix_spawn","os.exec","pty.spawn"}
        paths=[]
        if event=="open" and len(arguments)>2 and isinstance(arguments[0],(str,bytes,os.PathLike)):
            flags=arguments[2]
            if isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):paths=[arguments[0]]
        elif event in {"os.mkdir","os.remove","os.rmdir","os.chmod","os.rename"}:paths=arguments[:2] if event=="os.rename" else arguments[:1]
        for path in paths:
            if isinstance(path,(str,bytes,os.PathLike)):
                resolved=os.path.abspath(os.fsdecode(path))
                denied=denied or not(resolved==str(out) or resolved.startswith(str(out)+os.sep))
        if denied:
            DENIED.append({"event":event});raise PermissionError("native metadata host audit denied "+event)
    sys.dont_write_bytecode=True;sys.addaudithook(audit)
    spec=importlib.util.spec_from_file_location("shared_regression_helper",helper)
    H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
    pins,original=H.verify_sources(package)
    sys.path.insert(0,str(package/"candidate/source"))
    importlib.import_module("daily_phone_local")
    H.OBS=importlib.import_module("phone_observation_tools")
    H.GUARDS=importlib.import_module("phone_task_guards")
    H.CONTRACT=importlib.import_module("task_postconditions")
    H.CODEX=importlib.import_module("provider_codex_host")
    H.OPENAI=importlib.import_module("provider_openai_compatible")
    original_native=H.native
    variants=[
      ("valid_full_fields","control"),
      ("event_wrong_target","target differs from omitted/None mapped target and the other events"),
      ("event_target_object","target_id object cannot encode Option<String>"),
      ("started_pid_bool","bool cannot encode u32 pid"),
      ("started_pid_float","float cannot encode u32 pid"),
      ("event_elapsed_float","float cannot encode u64 event elapsed_ms"),
      ("terminal_elapsed_float","float cannot encode u64 terminal elapsed_ms"),
      ("exited_zero_with_signal","runtime producer chooses Signaled for a signal; exited/0/signal9 contradicts it"),
      ("historical_minimal_terminal","documented retained compatibility; not a new defect claim"),
    ]
    before=H.resources();findings=[];started=time.monotonic()
    for label,reason in variants:
        directory=out/label;directory.mkdir(mode=0o700);H.OUT=directory
        samples=[]
        def fixture_native(call_id,raw,tool,label=label):
            reply=original_native(call_id,raw,tool)
            for index,record in enumerate(reply["events"]):
                record["target_id"]=None;record["elapsed_ms"]=index
            if label=="event_wrong_target":reply["events"][2]["target_id"]="synthetic-foreign-target"
            elif label=="event_target_object":reply["events"][2]["target_id"]={"synthetic_wrong_type":True}
            elif label=="started_pid_bool":reply["events"][1]["event"]["pid"]=False
            elif label=="started_pid_float":reply["events"][1]["event"]["pid"]=12345.0
            elif label=="event_elapsed_float":reply["events"][2]["elapsed_ms"]=0.5
            elif label=="terminal_elapsed_float":
                reply["terminal"]["elapsed_ms"]=7.5;reply["events"][-1]["event"]["terminal"]["elapsed_ms"]=7.5
            elif label=="exited_zero_with_signal":
                reply["terminal"]["signal"]=9;reply["events"][-1]["event"]["terminal"]["signal"]=9
            elif label=="historical_minimal_terminal":
                for terminal in (reply["terminal"],reply["events"][-1]["event"]["terminal"]):
                    del terminal["signal"];del terminal["elapsed_ms"]
            envelope=dict(reply,protocol=H.OPENAI.PROTOCOL,kind="tool.result",seq=1)
            decoded=H.OPENAI.decode(H.canonical(envelope)+b"\n")
            known=H.OPENAI.known_tool_result(decoded)
            parsed=H.OBS.native_streams(reply,call_id,tool)
            assert known is True and parsed==raw
            samples.append({"call_id":call_id,"tool":tool,"outer_decode_and_known_tool_result_accepted":known,
                            "native_streams_accepted":True,"raw_stdout_sha256":sha(raw)})
            return reply
        H.native=fixture_native
        results=[]
        H.business_case("complete_control",results,{})
        assert len(results)==1 and results[0]["business_outcome"]["business_verified"]is True
        assert results[0]["actual_terminal"]["kind"]=="turn.complete"
        findings.append({"variant":label,"source_contract_reason":reason,"fixtures":samples,
                         "actual_shared_gate_terminal":"turn.complete","actual_shared_business_verified":True,
                         "synthetic_fixture_only":True,
                         "malformed_metadata_promoted":label not in {"valid_full_fields","historical_minimal_terminal"},
                         "native_dispatches":0,"phone_calls":0,"model_requests":0})
    H.native=original_native
    _,after_sources=H.verify_sources(package)
    assert original==after_sources
    after=H.resources()
    assert before["fds"]==after["fds"] and before["threads"]==after["threads"] and not DENIED
    result={"schema":"razr60-current-native-metadata-coverage-reproduction/v1",
            "state":"SEVEN_UNCHECKED_METADATA_REPRODUCTIONS",
            "production_candidate_modified":False,"candidate_observation_sha256":"22580b8aa22d5c0ab4040888872e642a5176042023dd7bcf50e67efe51248409",
            "candidate_daily_sha256":"689db3908014940a1e39689b966d30ab16ac6f9c0d7892becf1718b9840c824f",
            "source_pins_sha256":PINS_SHA,"harness_dependency_sha256":HELPER_SHA,
            "script_sha256":sha(Path(__file__).read_bytes()),"variants":findings,
            "finding_count":sum(row["malformed_metadata_promoted"]for row in findings),
            "controls":2,"all_inputs_synthetic":True,
            "outer_scope":"Production decode and known_tool_result invoked. CodexAdapter tool.result receive not executed; its source calls these and checks frame/call identity, without these metadata fields.",
            "semantic_scope":"Real PhoneTools.prepare created facts; real task contract and CodexAdapter.emit persisted turn.complete for each explicitly synthetic fixture.",
            "target_basis":"Mapped wire_call omits target. Checked Rust decoder clones call.target_id into request, and every runtime event clones that request target; expected current target is None.",
            "limits":["No installed runtime or transport corruption was performed.","This proves consumer acceptance and fixture semantic promotion, not an independently demonstrated attack ingress.",
                      "A full PhoneLocalAdapter was not instantiated and its executor gate was not bypassed.","Historical minimal terminal acceptance is an existing declared compatibility choice.",
                      "No v2 parser edit, production adoption, or whole NEG11 qualification is made."],
            "phone_calls":0,"model_requests":0,"native_dispatches":0,"audit_denied_events":DENIED,
            "fd_thread_baseline_restored":True,"elapsed_seconds":time.monotonic()-started}
    descriptor=H.write_new(out/"RESULT.json",result)
    print(json.dumps({"state":result["state"],"findings":result["finding_count"],"controls":2,
                      "result":descriptor,"script_sha256":result["script_sha256"],
                      "phone_calls":0,"native_dispatches":0,"production_candidate_modified":False},sort_keys=True))
if __name__=="__main__":main()
