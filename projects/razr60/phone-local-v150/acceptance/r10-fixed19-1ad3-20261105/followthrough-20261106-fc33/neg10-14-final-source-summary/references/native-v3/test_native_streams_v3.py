#!/usr/bin/env python3
"""Host-only native v3 parser and real outer-receive/semantic/business tests.

Public test inputs are synthetic. Optional archived NEG01 originals are only read.
Local tool.call frames terminate in an owned regular file: no executor, phone,
model, socket, subprocess, or transport is invoked.
"""
import argparse,base64,copy,hashlib,importlib,importlib.util,json,os,signal,sys,time,traceback,types
from pathlib import Path
PINS_SHA="168cbbb9c49e86613622dfe6ce682516847cc856086b3369909e923ae8007d68"
HELPER_SHA="dbbfece5877955b68a98770af41a9010365990b3fdbe29a8c9c37e648ec6756a"
ACTUAL_SCHEMA_SHA="76ec7ca00770c6ec66db6fb9919bfb15145de670d690b5f61b30a3b047df695c"
U64=18446744073709551615
OUT=None
DENIED=[]
H=OBS=CODEX=OPENAI=CONTRACT=None
def sha(b):return hashlib.sha256(b).hexdigest()
def audit(event,args):
    denied=event in {"socket.__new__","socket.connect","socket.bind","socket.getaddrinfo",
                    "subprocess.Popen","os.system","os.fork","os.forkpty","os.posix_spawn","os.exec","pty.spawn"}
    paths=[]
    if event=="open" and len(args)>2 and isinstance(args[0],(str,bytes,os.PathLike)):
        if isinstance(args[2],int) and args[2]&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):paths=[args[0]]
    elif event in {"os.mkdir","os.remove","os.rmdir","os.chmod","os.rename"}:
        paths=args[:2] if event=="os.rename" else args[:1]
    for path in paths:
        if isinstance(path,(str,bytes,os.PathLike)):
            p=os.path.abspath(os.fsdecode(path))
            denied=denied or not(p==str(OUT)or p.startswith(str(OUT)+os.sep))
    if denied:
        DENIED.append({"event":event});raise PermissionError("host-only native v3 audit denied "+event)
def reject(fn):
    try:fn()
    except OPENAI.ProviderError as e:return {"type":type(e).__name__,"message":str(e)}
    raise AssertionError("expected controlled ProviderError rejection")
def terminal_set(r,key,value):
    r["terminal"][key]=value;r["events"][-1]["event"]["terminal"][key]=copy.deepcopy(value)
def terminal_del(r,key):
    del r["terminal"][key];del r["events"][-1]["event"]["terminal"][key]
def target_set(r,value):
    r["registry"]["target_id"]=copy.deepcopy(value)
    for e in r["events"]:e["target_id"]=copy.deepcopy(value)
def reseq(r):
    for i,e in enumerate(r["events"]):e["seq"]=i
def variants():
    rows=[]
    def add(name,fn):rows.append((name,fn))
    add("all_wrong_target",lambda r,c:target_set(r,"synthetic-foreign-target"))
    add("event_wrong_target",lambda r,c:r["events"][2].__setitem__("target_id","synthetic-foreign-target"))
    add("event_target_object",lambda r,c:r["events"][2].__setitem__("target_id",{"synthetic":True}))
    add("event_target_missing",lambda r,c:r["events"][2].pop("target_id"))
    add("registry_wrong_target",lambda r,c:r["registry"].__setitem__("target_id","synthetic-foreign-target"))
    add("registry_missing",lambda r,c:r.pop("registry"))
    add("registry_target_missing",lambda r,c:r["registry"].pop("target_id"))
    add("registry_wrong_call",lambda r,c:r["registry"].__setitem__("call_id","synthetic-other-call"))
    add("registry_wrong_tool",lambda r,c:r["registry"].__setitem__("tool","adb.exec"))
    for name,value in [("bool",False),("float",12345.0),("zero",0),("negative",-1),("overflow",4294967296)]:
        add("started_pid_"+name,lambda r,c,v=value:r["events"][1]["event"].__setitem__("pid",v))
    add("started_pid_missing",lambda r,c:r["events"][1]["event"].pop("pid"))
    for name,value in [("float",0.5),("bool",False),("negative",-1),("overflow",U64+1)]:
        add("event_elapsed_"+name,lambda r,c,v=value:r["events"][2].__setitem__("elapsed_ms",v))
        add("terminal_elapsed_"+name,lambda r,c,v=value:terminal_set(r,"elapsed_ms",v))
    add("event_elapsed_missing",lambda r,c:r["events"][2].pop("elapsed_ms"))
    add("terminal_elapsed_missing",lambda r,c:terminal_del(r,"elapsed_ms"))
    add("exited_zero_with_signal",lambda r,c:terminal_set(r,"signal",9))
    add("signal_false",lambda r,c:terminal_set(r,"signal",False))
    add("signal_missing",lambda r,c:terminal_del(r,"signal"))
    add("legacy_minimal_terminal",lambda r,c:(terminal_del(r,"signal"),terminal_del(r,"elapsed_ms")))
    add("terminal_unknown_field",lambda r,c:terminal_set(r,"future_field","unqualified"))
    add("terminal_nonzero_exit",lambda r,c:terminal_set(r,"exit_code",70))
    add("terminal_truncated",lambda r,c:terminal_set(r,"output_truncated",True))
    add("terminal_error",lambda r,c:terminal_set(r,"error","synthetic error"))
    for name,value in [("bool",False),("float",0.0)]:
        add("terminal_exit_"+name,lambda r,c,v=value:terminal_set(r,"exit_code",v))
        add("event_terminal_exit_"+name,lambda r,c,v=value:r["events"][-1]["event"]["terminal"].__setitem__("exit_code",v))
    add("event_terminal_stdout_float",lambda r,c:r["events"][-1]["event"]["terminal"].__setitem__("stdout_bytes",float(r["terminal"]["stdout_bytes"])))
    add("event_terminal_stderr_false",lambda r,c:r["events"][-1]["event"]["terminal"].__setitem__("stderr_bytes",False))
    add("event_terminal_truncated_zero",lambda r,c:r["events"][-1]["event"]["terminal"].__setitem__("output_truncated",0))
    add("event_terminal_elapsed_float",lambda r,c:r["events"][-1]["event"]["terminal"].__setitem__("elapsed_ms",7.0))
    for name,value in [("progress","progress"),("queued","queued"),("list",[]),("object",{}),("none",None)]:
        add("unknown_event_kind_"+name,lambda r,c,v=value:r["events"][2]["event"].__setitem__("kind",v))
    add("event_record_unknown_field",lambda r,c:r["events"][2].__setitem__("future_field",0))
    add("accepted_unknown_field",lambda r,c:r["events"][0]["event"].__setitem__("future_field",0))
    add("output_stream_list",lambda r,c:r["events"][2]["event"].__setitem__("stream",[]))
    add("output_wrong_encoding",lambda r,c:r["events"][2]["event"].__setitem__("encoding","utf-8"))
    add("output_invalid_base64",lambda r,c:r["events"][2]["event"].__setitem__("data","!!!"))
    add("output_wrong_count",lambda r,c:r["events"][2]["event"].__setitem__("byte_count",1))
    add("output_float_count",lambda r,c:r["events"][2]["event"].__setitem__("byte_count",float(r["events"][2]["event"]["byte_count"])))
    add("wrong_call",lambda r,c:r.__setitem__("call_id","synthetic-other-call"))
    add("wrong_event_call",lambda r,c:r["events"][2].__setitem__("call_id","synthetic-other-call"))
    add("wrong_event_tool",lambda r,c:r["events"][2].__setitem__("tool","adb.exec"))
    add("wrong_event_sequence",lambda r,c:r["events"][2].__setitem__("seq",3))
    add("boolean_event_sequence",lambda r,c:r["events"][0].__setitem__("seq",False))
    add("mapped_call_identity_mismatch",lambda r,c:c.__setitem__("call_id","synthetic-other-call"))
    add("mapped_target_alias_conflict",lambda r,c:c.update(target="first",target_id="second"))
    add("mapped_target_wrong_type",lambda r,c:c.__setitem__("target_id",False))
    def out_before_start(r,c):
        r["events"][1],r["events"][2]=r["events"][2],r["events"][1];reseq(r)
    def duplicate_start(r,c):
        r["events"].insert(2,copy.deepcopy(r["events"][1]));reseq(r)
    def missing_start(r,c):
        del r["events"][1];reseq(r)
    add("output_before_started",out_before_start);add("duplicate_started",duplicate_start);add("missing_started",missing_start)
    return rows
def parser_checks():
    rows=[];scope=H.identity();call={"call_id":"synthetic_v3_parser","tool":"shell.exec","argv":["SYNTHETIC_NONEXECUTABLE"]}
    def accept(label,raw,edit=None):
        reply=H.native(call["call_id"],raw,call["tool"],wire_call=call,scope=scope);expected=copy.deepcopy(call)
        if edit:edit(reply,expected)
        H.seal_native_fixture(reply,expected,scope)
        assert OBS.native_streams(reply,call["call_id"],call["tool"],expected_call=expected,expected_scope=scope)==raw
        rows.append({"name":label,"expected":"accept","passed":True,"synthetic":True,"stdout_bytes":len(raw),"stdout_sha256":sha(raw)})
    accept("full_current_empty",b"")
    accept("full_current_unicode_newline","中文😀\nHEPTA".encode())
    def multi(r,c):
        raw="中文😀\nHEPTA".encode();chunks=[raw[:2],raw[2:6],raw[6:]]
        event=r["events"][2];outputs=[]
        for part in chunks:
            e=copy.deepcopy(event);e["event"]["data"]=base64.b64encode(part).decode();e["event"]["byte_count"]=len(part);outputs.append(e)
        r["events"]=r["events"][:2]+outputs+[r["events"][-1]];reseq(r)
    accept("full_current_multichunk","中文😀\nHEPTA".encode(),multi)
    for label,fields in [("explicit_target_id",{"target_id":"synthetic-target"}),
                         ("target_alias",{"target":"synthetic-target"}),
                         ("matching_aliases",{"target":"synthetic-target","target_id":"synthetic-target"}),
                         ("null_canonical_alias",{"target":"synthetic-target","target_id":None})]:
        def bind(r,c,fields=fields):c.update(fields);target_set(r,"synthetic-target")
        accept(label,b"target",bind)
    def edges(r,c):
        r["events"][1]["event"]["pid"]=4294967295
        for e in r["events"]:e["elapsed_ms"]=U64
        terminal_set(r,"elapsed_ms",U64)
    accept("integer_upper_bounds",b"bounds",edges)
    raw=b"synthetic parser output"
    for name,mutation in variants():
        reply=H.native(call["call_id"],raw,call["tool"],wire_call=call,scope=scope);expected=copy.deepcopy(call);mutation(reply,expected)
        error=reject(lambda:OBS.native_streams(reply,call["call_id"],call["tool"],expected_call=expected,expected_scope=scope))
        rows.append({"name":name,"expected":"reject","passed":True,"synthetic":True,"rejection":error})
    reply=H.native(call["call_id"],b"a",call["tool"],wire_call=call,scope=scope);reply["events"][2]["event"]["data"]="YR=="
    rows.append({"name":"noncanonical_base64_pad_bits","expected":"reject","passed":True,"synthetic":True,
                 "rejection":reject(lambda:OBS.native_streams(reply,call["call_id"],call["tool"],expected_call=call,expected_scope=scope))})
    return rows
def chain_case(label,mutation):
    directory=H.mkdir(OUT/("CHAIN-"+label));state=H.mkdir(directory/"state")
    evidence=H.mkdir(state/"evidence");H.mkdir(evidence/"claims")
    contracts=H.contracts_tree(state/"task-contracts");run=H.mkdir(evidence/"run")
    who=H.identity();nonce=H.secrets.token_hex(16)
    public="SYNTHETIC 中文😀\nHEPTA "+nonce
    owner="SYNTHETIC host-only public receipt request "+nonce
    condition={"id":"public","kind":"public_text_exact","package":H.PACKAGE,"view_id":H.PUBLIC,"utf8_sha256":sha(public.encode())}
    template=H.template(who,owner,nonce,[condition]);CONTRACT.write_exclusive(contracts/"templates"/(CONTRACT.request_hash(owner)+".json"),template)
    frame={"protocol":OPENAI.PROTOCOL,"kind":"turn.start","seq":0,"turn":dict(who,user_input=owner)}
    rfd,wfd=os.pipe();source=os.fdopen(rfd,"rb",buffering=0);sink=open(directory/"LOCAL-ONLY-WIRE.jsonl","x",encoding="utf-8")
    adapter=None
    try:
        b=H.canonical(frame)+b"\n";assert len(b)<8192 and os.write(wfd,b)==len(b)
        adapter=CODEX.CodexAdapter(types.SimpleNamespace(evidence=evidence,contracts=contracts),source,sink,run)
        assert adapter.receive("turn.start",timeout=1)==frame and adapter.claimed and adapter.accepted_identity==who
        decision={"call_id":"synthetic_public_"+H.secrets.token_hex(10),"tool":"phone.read_text","command":"","argv":[H.PACKAGE,H.PUBLIC]}
        adapter.phone_tools.map(decision);call=adapter.phone_tools.calls[decision["call_id"]]
        assert call["turn"]==who and call["wire_call"]["call_id"]==decision["call_id"]
        # Production emit writes only to this owned regular file. There is no
        # Host executor/transport attached to the sink.
        adapter.emit("tool.call",call=copy.deepcopy(call["wire_call"]))
        assert adapter.pending_call_id==call["call_id"] and adapter.dispatched_calls=={call["call_id"]}
        payload=H.public_payload(call["capture_id"],public);reply=H.native(call["call_id"],H.canonical(payload),call["wire_tool"],wire_call=call["wire_call"],scope=who)
        expected=copy.deepcopy(call["wire_call"])
        if mutation:mutation(reply,expected)
        assert expected==call["wire_call"],"consumer-chain mutations may only alter received data"
        reply.update(protocol=OPENAI.PROTOCOL,kind="tool.result",seq=1)
        fixture={"all_fixture_data_synthetic":True,"owner_frame":frame,"task_template":template,"mapped_call":call,
                 "received_native_fixture":reply,"sink_is_local_regular_file":True,"actual_native_dispatches":0}
        H.write_new(directory/"SYNTHETIC-INPUTS.json",fixture)
        b=H.canonical(reply)+b"\n";assert len(b)<8192 and os.write(wfd,b)==len(b)
        received=adapter.receive("tool.result",timeout=1)
        assert received==reply and adapter.pending_call_id is None
        result_path=run/("result-"+sha(call["call_id"].encode())+".json")
        assert json.loads(result_path.read_bytes())==reply
        error=None
        if mutation:
            error=reject(lambda:H.prepare_one(adapter.phone_tools,call,received,1))
            assert call["call_id"] not in adapter.phone_tools.verified_facts
        else:
            H.prepare_one(adapter.phone_tools,call,received,1)
            assert adapter.phone_tools.verified_facts[call["call_id"]]["kind"]=="public_text_observation"
        adapter.model_task_status="completed"
        adapter.emit("turn.complete",summary="SYNTHETIC fixture only; no model or phone")
        outcome=json.loads((run/"business-outcome.json").read_bytes())
        terminal=json.loads((run/"terminal.json").read_bytes())
        expected_terminal="turn.fail" if mutation else "turn.complete"
        assert terminal["kind"]==outcome["emitted_protocol_terminal"]==expected_terminal
        assert outcome["business_verified"] is (mutation is None)
        assert outcome["missing_postconditions"]==(["public"]if mutation else [])
        wire=(directory/"LOCAL-ONLY-WIRE.jsonl").read_bytes();frames=[json.loads(line)for line in wire.splitlines()]
        assert [f["kind"]for f in frames]==["tool.call",expected_terminal]
        replay=reject(lambda:adapter.phone_tools.map(decision))
        late=reject(lambda:adapter.emit("turn.complete",summary="late synthetic completion"))
        assert (directory/"LOCAL-ONLY-WIRE.jsonl").read_bytes()==wire
        return {"name":label,"passed":True,"all_inputs_synthetic":True,"outer_CodexAdapter_receive_executed":True,
                "trusted_mapping_and_persisted_dispatch_call_equal":json.loads((run/"dispatch-000.json").read_bytes())["call"]==call["wire_call"],
                "semantic_parser_rejection":error,"actual_shared_terminal":terminal["kind"],
                "fixture_business_verified":outcome["business_verified"],"missing_postconditions":outcome["missing_postconditions"],
                "same_call_remap_rejected":replay,"late_terminal_rejected":late,"local_only_tool_call_frames":1,
                "native_dispatches":0,"phone_calls":0,"model_requests":0}
    finally:H.close_adapter(adapter,source,sink,wfd)
def trust_variants(scope):
    rows=[]
    def add(name,fn):rows.append((name,fn))
    for key in ("request_sha256","binding_fingerprint"):
        add("wrong_"+key,lambda r,c,k=key:r["registry"].__setitem__(k,"0"*64))
        add("missing_"+key,lambda r,c,k=key:r["registry"].pop(k))
    add("wrong_observation_sha256",lambda r,c:r.__setitem__("observation_sha256","0"*64))
    add("missing_observation_sha256",lambda r,c:r.pop("observation_sha256"))
    add("generation_changed_without_rehash",lambda r,c:r.__setitem__("generation",r["generation"]+1))
    for label,value in (("bool",True),("float",1.0),("zero",0),("negative",-1),("allocator_exhausted",U64),("overflow",U64+1)):
        add("generation_"+label,lambda r,c,v=value:r.__setitem__("generation",v))
    add("generation_missing",lambda r,c:r.pop("generation"))
    add("registry_terminal_receipt_changed",lambda r,c:r["registry"].__setitem__("state",r["registry"]["state"]+" "))
    add("registry_terminal_receipt_missing",lambda r,c:r["registry"].pop("state"))
    add("registry_terminal_receipt_wrong_generation",lambda r,c:r["registry"].__setitem__("state",r["registry"]["state"].replace("generation: 1,","generation: 2,")))
    add("started_pid_changed_without_rehash",lambda r,c:r["events"][1]["event"].__setitem__("pid",12346))
    add("terminal_elapsed_changed_without_rehash",lambda r,c:terminal_set(r,"elapsed_ms",8))
    def bytes_changed(r,c):
        event=r["events"][2]["event"];raw=bytearray(base64.b64decode(event["data"],validate=True));assert raw
        raw[0]^=1;event["data"]=base64.b64encode(raw).decode()
    add("same_length_output_bytes_changed",bytes_changed)
    old_scope=dict(scope,turn_id=scope["turn_id"]+"-old")
    add("old_turn_request_digest",lambda r,c:r["registry"].__setitem__("request_sha256",H.reference_claims(c,old_scope)["request_sha256"]))
    add("registry_cancel_flag_integer",lambda r,c:r["registry"].__setitem__("cancellation_requested",0))
    add("registry_connection_flag_integer",lambda r,c:r["registry"].__setitem__("connection_lost",0))
    add("registry_history_bool",lambda r,c:r["registry"].__setitem__("earliest_history_seq",False))
    add("registry_history_float",lambda r,c:r["registry"].__setitem__("next_event_seq",4.0))
    add("registry_history_negative",lambda r,c:r["registry"].__setitem__("earliest_history_seq",-1))
    add("registry_history_reversed",lambda r,c:r["registry"].__setitem__("earliest_history_seq",5))
    add("registry_history_overflow",lambda r,c:r["registry"].__setitem__("next_event_seq",U64+1))
    add("registry_unknown_field",lambda r,c:r["registry"].__setitem__("future",True))
    add("outer_unknown_field",lambda r,c:r.__setitem__("future",True))
    add("outer_protocol_changed",lambda r,c:r.__setitem__("protocol","synthetic-unknown-protocol"))
    add("outer_kind_changed",lambda r,c:r.__setitem__("kind","synthetic-unknown-kind"))
    add("outer_sequence_float",lambda r,c:r.__setitem__("seq",1.0))
    return rows


def trust_parser_checks():
    scope=H.identity();call={"call_id":"synthetic_trust_parser","tool":"shell.exec","argv":["SYNTHETIC_NONEXECUTABLE","中文😀\nHEPTA"]}
    raw=b"SYNTHETIC immutable output";rows=[]
    for name,mutate in trust_variants(scope):
        reply=H.native(call["call_id"],raw,call["tool"],wire_call=call,scope=scope);expected=copy.deepcopy(call)
        mutate(reply,expected)
        error=reject(lambda:OBS.native_streams(reply,call["call_id"],call["tool"],expected_call=expected,expected_scope=scope))
        rows.append({"name":name,"expected":"reject","passed":True,"synthetic":True,"rejection":error})
    for label,generation in (("allocator_minimum",1),("allocator_maximum_allocatable",U64-1)):
        reply=H.native(call["call_id"],raw,call["tool"],wire_call=call,scope=scope);reply["generation"]=generation
        H.seal_native_fixture(reply,call,scope)
        assert OBS.native_streams(reply,call["call_id"],call["tool"],expected_call=call,expected_scope=scope)==raw
        rows.append({"name":label,"expected":"accept","passed":True,"synthetic":True})
    reply=H.native(call["call_id"],raw,call["tool"],wire_call=call,scope=scope)
    wrong_scope=dict(scope,session_id=scope["session_id"]+"-other")
    error=reject(lambda:OBS.native_streams(reply,call["call_id"],call["tool"],expected_call=call,expected_scope=wrong_scope))
    rows.append({"name":"trusted_scope_changed_original_digest_rejected","expected":"reject","passed":True,"synthetic":True,"rejection":error})
    for label,bad_scope in (("missing_scope",None),("scope_extra",dict(scope,extra="x")),
                            ("scope_missing_stream",{k:v for k,v in scope.items()if k!="turn_stream_id"}),
                            ("scope_float",dict(scope,turn_id=1.0))):
        error=reject(lambda s=bad_scope:OBS.native_streams(reply,call["call_id"],call["tool"],expected_call=call,expected_scope=s))
        rows.append({"name":label,"expected":"reject","passed":True,"synthetic":True,"rejection":error})
    boundary=copy.deepcopy(reply);boundary["generation"]=2;H.seal_native_fixture(boundary,call,scope)
    assert OBS.native_streams(boundary,call["call_id"],call["tool"],expected_call=call,expected_scope=scope)==raw
    elapsed=copy.deepcopy(reply);elapsed["events"][2]["elapsed_ms"]+=1
    assert OBS.native_streams(elapsed,call["call_id"],call["tool"],expected_call=call,expected_scope=scope)==raw
    limits={"unsigned_generation_rewrite_with_recomputed_full_receipt_and_digest_is_indistinguishable":True,
            "event_record_elapsed_ms_is_type_checked_but_excluded_by_actual_producer_ObservationDigest":True,
            "terminal_elapsed_ms_is_in_the_digest_and_mutation_rejected":True,
            "no_independent_admission_counter_or_MAC_claimed":True}
    return rows,limits


def dispatch_checks():
    rows=[]
    for label in ("mapped_base","mapped_full","wrong_request_claim","wrong_binding_claim","wrong_config_generation",
                  "partial_claims","changed_argv","unknown_field","changed_target"):
        directory=H.mkdir(OUT/("DISPATCH-"+label));evidence=H.mkdir(directory/"evidence");H.mkdir(evidence/"claims")
        run=H.mkdir(evidence/"run");who=H.identity()
        frame={"protocol":OPENAI.PROTOCOL,"kind":"turn.start","seq":0,"turn":dict(who,user_input="SYNTHETIC dispatch binding only")}
        rfd,wfd=os.pipe();source=os.fdopen(rfd,"rb",buffering=0);sink=open(directory/"LOCAL-ONLY-WIRE.jsonl","x",encoding="utf-8")
        adapter=None
        try:
            encoded=H.canonical(frame)+b"\n";assert os.write(wfd,encoded)==len(encoded)
            adapter=CODEX.CodexAdapter(types.SimpleNamespace(evidence=evidence,contracts=None),source,sink,run)
            assert adapter.receive("turn.start",timeout=1)==frame and adapter.claimed
            decision={"call_id":"synthetic_dispatch_"+H.secrets.token_hex(8),"tool":"phone.read_text",
                      "command":"","argv":[H.PACKAGE,H.PUBLIC]}
            adapter.phone_tools.map(decision);record=adapter.phone_tools.calls[decision["call_id"]]
            full=copy.deepcopy(record["wire_call"]);base={k:v for k,v in full.items()if k not in{"config_generation","request_sha256","binding_fingerprint"}}
            assert {k:full[k]for k in ("request_sha256","binding_fingerprint")}==H.reference_claims(base,who)
            assert full["config_generation"] is None
            call=copy.deepcopy(base if label=="mapped_base"else full)
            if label=="wrong_request_claim":call["request_sha256"]="0"*64
            elif label=="wrong_binding_claim":call["binding_fingerprint"]="0"*64
            elif label=="wrong_config_generation":call["config_generation"]=0
            elif label=="partial_claims":call.pop("request_sha256")
            elif label=="changed_argv":call["argv"][-1]+=" SYNTHETIC_CHANGED"
            elif label=="unknown_field":call["unexpected"]=True
            elif label=="changed_target":call["target_id"]="synthetic-other-target"
            accepted=label in{"mapped_base","mapped_full"}
            if accepted:
                adapter.emit("tool.call",call=call)
                wire=(directory/"LOCAL-ONLY-WIRE.jsonl").read_bytes();frames=[json.loads(line)for line in wire.splitlines()]
                persisted=json.loads((run/"dispatch-000.json").read_bytes())
                assert len(frames)==1 and frames[0]["call"]==persisted["call"]==full
                assert persisted["call_sha256"]==sha(json.dumps(full,sort_keys=True,separators=(",",":")).encode())
                assert adapter.dispatched_calls=={record["call_id"]}and adapter.pending_call_id==record["call_id"]
                duplicate=reject(lambda:adapter.emit("tool.call",call=call))
                assert (directory/"LOCAL-ONLY-WIRE.jsonl").read_bytes()==wire
                outcome={"complete_mapped_call_equals_dispatch_and_frame":True,"duplicate_rejected":duplicate}
            else:
                error=reject(lambda:adapter.emit("tool.call",call=call))
                assert not adapter.dispatched_calls and adapter.pending_call_id is None
                assert not list(run.glob("dispatch-*.json"))and(directory/"LOCAL-ONLY-WIRE.jsonl").read_bytes()==b""
                outcome={"rejection":error,"zero_local_tool_call_frames":True}
            rows.append({"name":label,"passed":True,"synthetic":True,"expected":"accept"if accepted else"reject",**outcome})
        finally:H.close_adapter(adapter,source,sink,wfd)
    return rows


def ledger_binding_check():
    # Real reservation components, explicit synthetic sidecar record only.
    # No PhoneLocalTools/PhoneLocalAdapter instance or executor qualification is bypassed.
    ACTION=importlib.import_module("action_ledger");LEDGER=importlib.import_module("ledger_round_evidence")
    directory=H.mkdir(OUT/"LEDGER-FULL-CALL");evidence=H.mkdir(directory/"evidence");run=H.mkdir(evidence/"run")
    who=H.identity();owner="SYNTHETIC full-call ledger reservation";rid=H.secrets.token_hex(16);call_id="r01_"+rid[:16]
    action_id=H.secrets.token_hex(16);command=b"SYNTHETIC_NONEXECUTABLE_COMMAND"
    base={"call_id":call_id,"tool":"shell.exec","argv":["/usr/bin/python3",ACTION.EXECUTOR_BINDING["client_path"],"execute",
          "--action-id",action_id,"--command-b64",base64.b64encode(command).decode(),"--timeout-ms","1000"]}
    full=OBS.native_bound_call(base,who)
    record={"semantic_tool":"phone.return_hepta","call_id":call_id,"capture_id":action_id,"turn":who,
            "state":"SYNTHETIC_HOST_ONLY_NOT_PHYSICAL","wire_tool":"shell.exec","wire_call":full}
    semantic=run/("semantic-"+sha(call_id.encode())+".json");H.write_new(semantic,record)
    action=ACTION.ActionLedger(evidence,run);ledger=LEDGER.LedgerPrefix(action,run,who,owner)
    ledger.before_request(1,rid,call_id)
    for suffix in (".request.json",".open-replay-exclusions.json",".schema-clock.json"):
        H.write_new(run/("local-01"+suffix),{"synthetic":True,"purpose":"host-only ledger input","suffix":suffix})
    ledger.bind_request(run/"local-01");ledger.reserve_before_frame(record)
    assert len(ledger.events)==1
    event=json.loads((ledger.directory/ledger.events[0]["name"]).read_bytes())
    assert event["wire_call_canonical_sha256"]==sha(LEDGER.canonical(full))
    assert event["semantic_sha256"]==sha(semantic.read_bytes())and event["native_dispatch_asserted"] is False
    assert event["wire_call_canonical_sha256"]!=sha(LEDGER.canonical(base))
    original=list(action.intents());assert len(original)==1 and original[0][2] is None
    duplicate=reject(lambda:ledger.reserve_before_frame(record));assert list(action.intents())==original
    return {"passed":True,"synthetic_record":True,"real_ActionLedger_and_LedgerPrefix":True,
            "stored_wire_call_hash_covers_all_three_dispatch_claims":True,"stored_semantic_file_full_record_equal":True,
            "duplicate_reservation_rejected":duplicate,"native_dispatches":0,
            "PhoneLocalTools_or_PhoneLocalAdapter_constructed":False,"validate_executor_bypassed":False}


def actual_checks(package,required):
    path=package/"private/NEG01-NATIVE-SCHEMA.json"
    if not path.exists():
        assert not required,"--require-actual requested but private actual originals are missing"
        return {"status":"NOT_AVAILABLE_NOT_RUN","limits":"Archived private NEG01 originals are optional for public fixture reproduction."}
    raw=H.pinned(path,16924,ACTUAL_SCHEMA_SHA);manifest=json.loads(raw)
    files={r["member"]:H.pinned(package/"private/NEG01-native-originals"/r["member"],r["bytes"],r["sha256"])for r in manifest["files"]}
    start=json.loads(files["run/provider-in-00.jsonl"]);accepted=json.loads(files["run/accepted.json"])
    names=("session_id","profile_id","task_id","turn_id","turn_stream_id")
    assert accepted["identity"]=={k:start["turn"][k]for k in names}
    assert accepted["owner_request_sha256"]==sha(start["turn"]["user_input"].encode())
    calls=[json.loads(files["run/provider-out-00.jsonl"])["call"],json.loads(files["run/provider-out-01.jsonl"])["call"]]
    replies=[json.loads(files["run/provider-in-01.jsonl"]),json.loads(files["run/provider-in-02.jsonl"])]
    assert all(set(c)=={"call_id","tool","argv"}and c["tool"]=="shell.exec"for c in calls)
    golden_checks=[]
    for original_call,original_reply in zip(calls,replies):
        claims=H.reference_claims(original_call,accepted["identity"])
        assert all(original_reply["registry"][key]==value for key,value in claims.items())
        bound=OBS.native_bound_call(original_call,accepted["identity"])
        assert all(bound[key]==value for key,value in claims.items()) and bound["config_generation"] is None
        computed=H.reference_observation(original_call,original_reply)
        assert computed==original_reply["observation_sha256"]
        copied=copy.deepcopy(original_reply);H.seal_native_fixture(copied,original_call,accepted["identity"])
        assert copied==original_reply
        golden_checks.append({"call_id":original_call["call_id"],"request_sha256":claims["request_sha256"],
            "binding_fingerprint":claims["binding_fingerprint"],"observation_sha256":computed,
            "generation":original_reply["generation"],"all_three_formulas_and_full_terminal_receipt_match":True})
    decoded=OBS.native_streams(replies[0],calls[0]["call_id"],calls[0]["tool"],expected_call=calls[0],expected_scope=accepted["identity"])
    assert len(decoded)==71365
    error=reject(lambda:OBS.native_streams(replies[1],calls[1]["call_id"],calls[1]["tool"],expected_call=calls[1],expected_scope=accepted["identity"]))
    corrupted=copy.deepcopy(replies[0]);target_set(corrupted,"synthetic-foreign-target")
    target_error=reject(lambda:OBS.native_streams(corrupted,calls[0]["call_id"],calls[0]["tool"],expected_call=calls[0],expected_scope=accepted["identity"]))
    return {"status":"READ_ONLY_ACTUAL_ORIGINALS_VERIFIED","original_file_count":len(files),"schema_manifest_sha256":sha(raw),
            "source_archive_sha256":manifest["source_archive"]["sha256"],"accepted_scope_matches_original_turn_start":True,
            "all_actual_three_preimages_and_full_receipts_match":golden_checks,
            "original_dispatch_call_has_no_target":True,"original_capture_stdout_bytes":len(decoded),"original_capture_stdout_sha256":sha(decoded),
            "original_capture_exited_zero_accepted":True,"original_guard_exit_code":replies[1]["terminal"]["exit_code"],
            "original_guard_rejected":error,"actual_copy_with_all_wrong_target_rejected":target_error,
            "phone_calls":0,"native_dispatches":0,"originals_modified":False}
def main():
    global OUT,H,OBS,CODEX,OPENAI,CONTRACT
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--package-root",type=Path,default=Path(__file__).resolve().parent)
    ap.add_argument("--out",type=Path,required=True);ap.add_argument("--require-actual",action="store_true")
    args=ap.parse_args();package=args.package_root.resolve();OUT=args.out
    assert OUT.is_absolute() and OUT.parent.resolve()==OUT.parent
    os.umask(0o077);OUT.mkdir(mode=0o700);sys.dont_write_bytecode=True;sys.addaudithook(audit)
    helper=package/"test_shared_business_admission_v3.py";assert sha(helper.read_bytes())==HELPER_SHA
    spec=importlib.util.spec_from_file_location("native_v3_fixture_helper",helper);H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
    pins,before_sources=H.verify_sources(package);assert sha((package/"CANDIDATE-PINS.json").read_bytes())==PINS_SHA
    sys.path.insert(0,str(package/"candidate/source"));importlib.import_module("daily_phone_local")
    OBS=H.OBS=importlib.import_module("phone_observation_tools")
    CODEX=H.CODEX=importlib.import_module("provider_codex_host")
    OPENAI=H.OPENAI=importlib.import_module("provider_openai_compatible")
    CONTRACT=H.CONTRACT=importlib.import_module("task_postconditions")
    H.GUARDS=importlib.import_module("phone_task_guards");H.OUT=OUT
    before=H.resources();started=time.monotonic();fatal=None;parser=[];chains=[];actual={};trust_parser=[];trust_limits={};trust_chains=[];dispatch=[];ledger={}
    previous=signal.getsignal(signal.SIGALRM);assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0)
    def expired(_sig,_frame):raise TimeoutError("native v3 host regression 50-second deadline")
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,50)
    try:
        parser=parser_checks()
        selected=("all_wrong_target","event_wrong_target","event_target_object","event_target_missing","started_pid_bool",
                  "started_pid_float","started_pid_missing","event_elapsed_float","terminal_elapsed_float","exited_zero_with_signal","legacy_minimal_terminal")
        mutations=dict(variants());chains.append(chain_case("valid_current_schema",None))
        for name in selected:chains.append(chain_case(name,mutations[name]))
        trust_parser,trust_limits=trust_parser_checks()
        trust_selected=("wrong_request_sha256","missing_request_sha256","wrong_binding_fingerprint","missing_binding_fingerprint",
                        "wrong_observation_sha256","missing_observation_sha256","generation_changed_without_rehash","generation_bool",
                        "generation_float","registry_terminal_receipt_changed","same_length_output_bytes_changed")
        trust_mutations=dict(trust_variants(H.identity()))
        for name in trust_selected:trust_chains.append(chain_case("trust_"+name,trust_mutations[name]))
        dispatch=dispatch_checks()
        ledger=ledger_binding_check()
        actual=actual_checks(package,args.require_actual)
        _,after_sources=H.verify_sources(package);assert before_sources==after_sources
    except BaseException as e:
        fatal={"type":type(e).__name__,"message":str(e),"traceback":traceback.format_exc()}
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
    after=H.resources()
    restored=(before["fds"]==after["fds"]and before["threads"]==after["threads"]
              and before["child_user_seconds"]==after["child_user_seconds"]and before["child_system_seconds"]==after["child_system_seconds"])
    passed=fatal is None and len(parser)==73 and len(chains)==12 and len(trust_chains)==11 and len(dispatch)==9 and ledger.get("passed") is True and restored and not DENIED
    result={"schema":"razr60-native-streams-v3-host-consumer-regression/v1","state":"PASSED_CURRENT_SCHEMA_SCOPE"if passed else"FAILED",
            "pins_sha256":PINS_SHA,"script_sha256":sha(Path(__file__).read_bytes()),"helper_sha256":HELPER_SHA,
            "parser_case_count":len(parser),"parser_cases":parser,"consumer_chain_case_count":len(chains),"consumer_chains":chains,
            "trust_parser_case_count":len(trust_parser),"trust_parser_cases":trust_parser,"trust_consumer_chains":trust_chains,
            "dispatch_binding_cases":dispatch,"ledger_binding":ledger,"trust_boundaries":trust_limits,
            "original_actual_checks":actual,"original_14_shared_scenarios_not_added_to_these_counts":True,
            "resources":{"before":before,"after":after,"fd_thread_child_cpu_baseline_restored":restored},
            "audit_denied_events":DENIED,"fatal_error":fatal,"elapsed_seconds":time.monotonic()-started,
            "phone_calls":0,"model_requests":0,"native_dispatches":0,"local_only_tool_call_frame_count":len(chains)+len(trust_chains)+2,
            "PhoneLocalAdapter_constructed":False,"validate_executor_bypassed_or_modified":False,
            "candidate_adopted":False,"whole_NEG11_qualified":False,"whole_NEG12_qualified":False,"whole_NEG13_qualified":False,
            "limits":["All newly generated requests and receipts are synthetic; local tool.call frames end in an owned regular file with no executor attached.",
                      "Real CodexAdapter turn/tool.result receive and emit, PhoneTools.map/prepare and business gate run without production monkeypatches.",
                      "PhoneLocalAdapter fixed executor gate is not bypassed; no full instance or installed daemon is exercised.",
                      "Actual NEG01 positives use pinned archived bytes only; new target mutation is a host copy and no current UI observation is claimed.",
                      "Request digest and configuration fingerprint are recomputed from the accepted scope and mapped call. The complete observed bytes and full terminal receipt are checked against the current producer digest.",
                      "Generation is type/range/receipt/digest checked; no independent generation anchor or MAC exists in the current post-result-only protocol.",
                      "This validates the observed current schema. Historical v1 and v2 are preserved; no installed adoption or complete NEG11 qualification is claimed."]}
    pin=H.write_new(OUT/"RESULT.json",result)
    print(json.dumps({"state":result["state"],"result":pin,"script_sha256":result["script_sha256"],
                      "parser_cases":len(parser),"consumer_chain_cases":len(chains),"trust_parser_cases":len(trust_parser),"trust_consumer_chain_cases":len(trust_chains),
                      "dispatch_cases":len(dispatch),"ledger_binding_passed":ledger.get("passed"),"actual_original_status":actual.get("status"),
                      "resources_restored":restored,"fatal_error":fatal,"phone_calls":0,"native_dispatches":0},sort_keys=True))
    return 0 if passed else 1
if __name__=="__main__":sys.exit(main())
