#!/usr/bin/env python3
"""Synthetic host-only controls for R5 trace rebinding and independent closure.

Real PhoneTools.map, native_bound_call, NativeGuardSession._call and the closer's
verify_mapped_phase execute. The r6 transport is an explicitly synthetic fixture
using the closer's r6_wire constructor. No PhoneLocalTools or PhoneLocalAdapter
instance is constructed; validate_executor is never replaced or bypassed.
"""
import argparse,base64,copy,hashlib,importlib,importlib.util,json,os,sys,time,types
from pathlib import Path
sys.dont_write_bytecode=True
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def reject(kind,fn):
    try:fn()
    except kind as e:return{"type":type(e).__name__,"message":str(e)}
    raise AssertionError("expected controlled rejection")
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--source-package",type=Path,required=True)
    ap.add_argument("--runtime",type=Path,required=True);ap.add_argument("--out",type=Path,required=True);a=ap.parse_args()
    out=a.out.resolve();assert not out.exists();os.umask(0o077);out.mkdir(mode=0o700)
    H=load("r5_trace_host_fixture",a.source_package/"test_shared_business_admission_v3.py")
    H.verify_sources(a.source_package);H.OUT=out;sys.addaudithook(H.audit)
    sys.path.insert(0,str((a.source_package/"candidate/source").resolve()))
    OBS=importlib.import_module("phone_observation_tools");H.OBS=OBS
    K=load("r5_review_kernel",a.runtime/"source/native_guard_session_r2.py")
    CLOSE=load("r5_review_closer",a.runtime/"source/close_component.py")
    watched=[a.runtime/"source/native_guard_session_r2.py",a.runtime/"source/close_component.py"]
    originals={str(p):p.read_bytes()for p in watched}
    cfg={"executor":{"mode":"phone_local_sidecar","python":"/usr/bin/python3","client_path":str(CLOSE.C.CLIENT),
                     "client_sha256":CLOSE.C.CLIENT_SHA,"timeout_ms":60000}}
    who=H.identity();nonce=H.secrets.token_hex(16)
    claims={"config_generation","request_sha256","binding_fingerprint"}
    def latest():
        return{"call_id":"SYNTHETIC_image","attached_round":2,"received_monotonic":time.monotonic(),
               "encoded_size":[120,280],"viewport":H.viewport(),"page_state":H.page(),
               "source_png_sha256":"a"*64,"image_sha256":"b"*64,"page_state_sha256":sha(H.page().encode()),
               "observed_page":{"component":H.APP}}
    class SyntheticR6Transport(OBS.PhoneTools):
        def _wire_call(self,call_id,shell):
            return OBS.native_bound_call(CLOSE.r6_wire(call_id,self._token(call_id),shell.encode(),cfg),self.binding)
    def record(path,value):
        path=Path(path);raw=CLOSE.C.encoded(value)
        with path.open("xb")as f:f.write(raw)
    before=H.resources();rows=[];fixtures={}
    for phase in ("capture","guard"):
        directory=H.mkdir(out/phase);mapper=SyntheticR6Transport(directory,record);mapper.bind(who);mapper.round=2
        if phase=="guard":mapper.latest=latest()
        kernel=object.__new__(K.NativeGuardSession)
        kernel.run=directory;kernel.contract={"nonce":nonce};kernel.contract_sha="c"*64;kernel.scope=who
        kernel.mapper=mapper;kernel.phone=OBS;kernel.pending=None;kernel.out_seq=0;kernel.outbound=[]
        tool="phone.screenshot"if phase=="capture"else"phone.tap";argv=["0"]if phase=="capture"else["SYNTHETIC_image","10","10"]
        raw=kernel._call(tool,phase,argv,trace=phase=="guard");call=json.loads(raw)["call"]
        original=mapper.calls[call["call_id"]]["wire_call"];plain=base64.b64decode(original["argv"][6],validate=True)
        actual=base64.b64decode(call["argv"][6],validate=True)
        assert actual==(b"set -x; "if phase=="guard"else b"")+plain
        assert call==OBS.native_bound_call(call,who)
        assert {k:call[k]for k in("request_sha256","binding_fingerprint")}==H.reference_claims(call,who)
        assert call["binding_fingerprint"]==original["binding_fingerprint"] and call["config_generation"] is None
        assert (call["request_sha256"]!=original["request_sha256"]) is(phase=="guard")
        dispatch=json.loads((directory/(phase+".dispatch-intent.json")).read_bytes())
        assert dispatch["original_mapper_call"]==original and dispatch["actual_native_call"]==call
        assert dispatch["actual_command_sha256"]==sha(actual)
        assert json.loads((directory/("semantic-"+sha(call["call_id"].encode())+".json")).read_bytes())["wire_call"]==original
        decision={"kind":"tool.call","tool":tool,"call_id":call["call_id"],"argv":argv,"command":"",
                  "summary":"explicit native component phase","task_status":"in_progress"}
        files={"run/"+p.name:p.read_bytes()for p in directory.iterdir()if p.is_file()}
        def closure_parser(label):
            d=H.mkdir(out/(phase+"-closure-"+label));p=OBS.PhoneTools(d,record);p.bind(who);p.round=2
            if phase=="guard":p.latest=latest()
            return p
        p=closure_parser("positive")
        checked=CLOSE.verify_mapped_phase(p,files,phase,decision,call,cfg,who)
        assert checked["wire_call"]==original and p.calls[call["call_id"]]==checked
        rows.append({"name":phase+"_real_mapper_trace_and_closer","passed":True,"synthetic_r6_transport":True,
                     "claims_equal_independent_reference":True,"original_record_preserved":True,
                     "request_digest_changes_only_for_trace":phase=="guard","command_sha256":sha(actual)})
        fixtures[phase]=(call,original,files,decision,closure_parser)
    call,original,files,decision,closure_parser=fixtures["guard"]
    stale=copy.deepcopy(call)
    for key in claims:stale[key]=original[key]
    rejection=reject(OBS.ProviderError,lambda:OBS.native_bound_call(stale,who))
    modified=copy.deepcopy(files);intent=json.loads(modified["run/guard.dispatch-intent.json"]);intent["actual_native_call"]=stale
    modified["run/guard.dispatch-intent.json"]=CLOSE.C.encoded(intent)
    close_rejection=reject(ValueError,lambda:CLOSE.verify_mapped_phase(closure_parser("stale"),modified,"guard",decision,stale,cfg,who))
    rows.append({"name":"stale_trace_claims_rejected_even_when_intent_matches","passed":True,
                 "helper_rejection":rejection,"closer_rejection":close_rejection})
    wrong=copy.deepcopy(call);wrong["request_sha256"]="0"*64
    modified=copy.deepcopy(files);intent=json.loads(modified["run/guard.dispatch-intent.json"]);intent["actual_native_call"]=wrong
    modified["run/guard.dispatch-intent.json"]=CLOSE.C.encoded(intent)
    rows.append({"name":"wrong_digest_self_consistent_intent_rejected","passed":True,
                 "rejection":reject(ValueError,lambda:CLOSE.verify_mapped_phase(closure_parser("wrong"),modified,"guard",decision,wrong,cfg,who))})
    for code in (70,71):
        output=("+ exit "+str(code)+"\n").encode();reply=H.native(call["call_id"],output,"shell.exec",wire_call=call,scope=who)
        reply["seq"]=2;reply["events"][2]["event"]["stream"]="stderr"
        for terminal in (reply["terminal"],reply["events"][-1]["event"]["terminal"]):
            terminal.update(exit_code=code,stdout_bytes=0,stderr_bytes=len(output))
        H.seal_native_fixture(reply,call,who)
        value,streams=K.native_streams(CLOSE.C.encoded(reply),2,call)
        assert value==reply and streams=={"stdout":b"","stderr":output}
        error=reject(OBS.ProviderError,lambda:OBS.native_streams(reply,call["call_id"],"shell.exec",expected_call=call,expected_scope=who))
        rows.append({"name":"expected_nonzero_"+str(code)+"_component_only","passed":True,
                     "component_envelope_parser_accepts_expected_nonzero":True,"production_success_parser_rejects":error})
    after=H.resources();assert before["fds"]==after["fds"]and before["threads"]==after["threads"]
    assert before["child_user_seconds"]==after["child_user_seconds"]and before["child_system_seconds"]==after["child_system_seconds"]
    assert all(p.read_bytes()==originals[str(p)]for p in watched)and not H.DENIED
    result={"schema":"razr60-r5-trace-closure-host-review/v1","state":"PASSED_SELECTED_SYNTHETIC_CONTROLS",
            "source_pins":{str(p):{"bytes":len(originals[str(p)]),"sha256":sha(originals[str(p)])}for p in watched},
            "production_pins_sha256":sha((a.source_package/"CANDIDATE-PINS.json").read_bytes()),
            "case_count":len(rows),"cases":rows,"resources_restored":True,"audit_denied_events":H.DENIED,
            "PhoneLocalTools_or_Adapter_constructed":False,"validate_executor_bypassed":False,
            "phone_calls":0,"native_dispatches":0,"model_requests":0,"component_qualified":False,
            "limits":["Real inherited PhoneTools.map and current r6_wire construct text; the transport fixture is explicitly synthetic.",
                      "NativeGuardSession._call and verify_mapped_phase run, but no real accepted component session or sidecar is created.",
                      "Component nonzero envelope acceptance is not production semantic success; expected 70/71 remain rejected by the production success parser.",
                      "No complete guard_result/verify_r6, journal provenance, public witness, or lifecycle closure is simulated as a real pass."]}
    pin=H.write_new(out/"RESULT.json",result);print(json.dumps({"state":result["state"],"case_count":len(rows),"result":pin}))
if __name__=="__main__":main()

