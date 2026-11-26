#!/usr/bin/env python3
"""Pure source generation only. This module never starts Java or a device tool."""
from pathlib import Path
import ast, hashlib, json, os, sys

def sha(raw): return hashlib.sha256(raw).hexdigest()
def ref(path):
    p=Path(path); b=p.read_bytes()
    return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def one(text,old,new):
    if text.count(old)!=1: raise AssertionError("unique fixture replacement missing: "+old[:100])
    return text.replace(old,new)
def body(text,anchor):
    if text.count(anchor)!=1: raise AssertionError("unique actual member: "+anchor)
    start=text.index(anchor); opening=text.index("{",start); depth=0; state="code"; i=opening
    while i<len(text):
        c=text[i]; n=text[i:i+2]
        if state=="line":
            if c=="\n":state="code"
        elif state=="block":
            if n=="*/":state="code";i+=1
        elif state in ("string","char"):
            if c=="\\":i+=1
            elif state=="string" and c=='"' or state=="char" and c=="'":state="code"
        elif n=="//":state="line";i+=1
        elif n=="/*":state="block";i+=1
        elif c=='"':state="string"
        elif c=="'":state="char"
        elif c=="{":depth+=1
        elif c=="}":
            depth-=1
            if depth==0:return text[start:i+1]
        i+=1
    raise AssertionError("unterminated actual member")

def v12_runner_predecessor(raw):
    """Proof-only inverse of the reviewed v12 source bridge; never executes an old runner."""
    assert type(raw) is bytes, "v12 fixture bytes required"
    if len(raw)==7449 and sha(raw)=="ad05c9ef9b7a9e59a57629411269dc11e6dabd78008138d501a081adef53c1a0": return raw
    assert len(raw)==8993 and sha(raw)=="b72ff09ea52e88fdf983a05aa4cd5531adfb5578cdb7f8f0930162a84839649d", "unreviewed v12 fixture"
    text=raw.decode("utf-8")
    text=one(text,'import argparse,hashlib,json,os,stat,subprocess,traceback,types\n','import argparse,hashlib,json,os,stat,subprocess,traceback\n')
    text=one(text,'    consumer_inverse_proofs=[]\n','')
    text=one(text,'        current,historical=raw(source/r),raw(base/r)\n        if name=="PublicPersonalNotesRecoveryClient.java" and current!=historical:\n            helper=source/"tests/notes-workflow-aborted-after-back/source_predecessor.py"\n            inverse=source/"tests/notes-workflow-aborted-after-back/source-inverse.json"\n            helper_ref=ref(helper);inverse_ref=ref(inverse);base_ref=ref(base/r)\n            need(helper_ref["sha256"]=="b6644c18529182e234957ba52572c035254a20785f8614be859b889bf137e936","reviewed v13 client predecessor helper changed")\n            helper_raw=raw(helper)\n            need(hashlib.sha256(helper_raw).hexdigest()==helper_ref["sha256"],"v13 predecessor helper changed before load")\n            predecessor=types.ModuleType("v13_client_source_predecessor");predecessor.__file__=str(helper)\n            exec(compile(helper_raw,str(helper),"exec"),predecessor.__dict__)\n            current=predecessor.client_predecessor(current,historical,raw(inverse))\n            sources.extend((helper_ref,inverse_ref,base_ref))\n            consumer_inverse_proofs.append(dict(source=ref(source/r),historical=base_ref,helper=helper_ref,inverse=inverse_ref,\n                full_inverse_byte_exact=True,proof_only=True,old_java_compiled_by_this_bridge=False,\n                candidate_client_compiled_here=False,candidate_client_origin="dependency_classes",\n                current_client_dependency_provenance_must_be_verified_by_producer=True))\n        need(current==historical,"unchanged consumer source required: "+r);sources.append(ref(source/r))\n','        need(raw(source/r)==raw(base/r),"unchanged consumer source required: "+r);sources.append(ref(source/r))\n')
    text=one(text,'      sources=sources,consumer_source_inverse_proofs=consumer_inverse_proofs,private_input_map=ref(mapping),private_originals=before,legacy_input_map=ref(legacy),legacy_originals=old,\n','      sources=sources,private_input_map=ref(mapping),private_originals=before,legacy_input_map=ref(legacy),legacy_originals=old,\n')
    restored=text.encode("utf-8")
    assert len(restored)==7449 and sha(restored)=="ad05c9ef9b7a9e59a57629411269dc11e6dabd78008138d501a081adef53c1a0", "v12 full predecessor mismatch"
    return restored

def source_proof(source,base,here):
    proof=json.loads((here/"source-inverse.json").read_text())
    rows=[];eof_predecessors=[]
    for row in proof["production"]:
        current=(source/row["path"]).read_bytes(); old=(base/row["path"]).read_bytes()
        if row["path"]=="src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java" and sha(current)!=row["candidate_sha256"]:
            helper=here/"eof_predecessor.py";helper_raw=helper.read_bytes()
            assert sha(helper_raw)=='809ff16fb568511796cb0322b650af5a7a3b0b11fca2ccb6a5f4bc9da73011a5',"reviewed EOF source inverse changed"
            module={};exec(compile(helper_raw,str(helper),"exec"),module)
            current=module["request_predecessor"](current)
            eof_predecessors.append({"actual_source":ref(source/row["path"]),"helper":ref(helper),
                "complete_pre_eof_sha256":sha(current),"full_inverse_byte_exact":True,"proof_only":True,
                "actual_current_request_still_compiled":True})
        assert sha(current)==row["candidate_sha256"] and sha(old)==row["base_sha256"],row["path"]
        a=old.decode().splitlines(keepends=True); b=current.decode().splitlines(keepends=True); restored=list(b)
        for e in reversed(row["edits"]):
            x="".join(a[e["a0"]:e["a1"]]); y="".join(b[e["b0"]:e["b1"]])
            assert sha(x.encode())==e["old_sha256"] and sha(y.encode())==e["new_sha256"]
            restored[e["b0"]:e["b1"]]=a[e["a0"]:e["a1"]]
        assert "".join(restored).encode()==old
        rows.append({"candidate":ref(source/row["path"]),"baseline":ref(base/row["path"]),
                     "exact_full_inverse":True,"known_edit_count":len(row["edits"])})
    unchanged=[];fixture_predecessors=[];normal_cleanup_predecessors=[]
    for row in proof["unchanged"]:
        a=source/row["path"]; b=base/row["path"]
        current=a.read_bytes();historical=b.read_bytes()
        if row["path"]=="tests/notes-workflow-released-reply-lost/run_host.py" and current!=historical:
            restored=v12_runner_predecessor(current)
            assert restored==historical and sha(restored)==row["sha256"],row["path"]
            fixture_predecessors.append({"candidate":ref(a),"baseline":ref(b),
                "full_inverse_byte_exact":True,"proof_only":True,"historical_runner_executed":False})
        elif row["path"]=="src/org/trillionnium/hepta/local/BackgroundSession.java" and current!=historical:
            helper=source/"tests/background-broker/normal_session_history.py"
            helper_ref=ref(helper);helper_raw=helper.read_bytes()
            assert helper_ref["sha256"]=="e6b00313ec35d3c324a08ca0406910a5fc9ab26497fea524d30c6a295e8a8dea" and sha(helper_raw)==helper_ref["sha256"],"reviewed normal cleanup Session inverse helper changed"
            namespace={};exec(compile(helper_raw,str(helper),"exec"),namespace)
            restored,detail=namespace["predecessor"]("BackgroundSession.java",current.decode("utf-8"))
            assert restored.encode("utf-8")==historical and sha(historical)==row["sha256"],row["path"]
            normal_cleanup_predecessors.append({"candidate":ref(a),"baseline":ref(b),"helper":helper_ref,
                "full_inverse_byte_exact":True,"proof_only":True,"actual_current_session_still_used":True,"detail":detail})
        else:
            assert current==historical and sha(current)==row["sha256"],row["path"]
            unchanged.append(row)
    return {"production":rows,"request_eof_predecessors":eof_predecessors,"unchanged":unchanged,"reviewed_fixture_predecessors":fixture_predecessors,"normal_cleanup_predecessors":normal_cleanup_predecessors,
            "original_unchanged_contract_members":len(proof["unchanged"]),
            "actual_compiled_request_is_unmodified":True,
            "actual_compiled_client_has_only_original_owned_process_factory_port":True}

def prepare_startup(source,out,java_home,here,owner_uid):
    # Execute only the existing session-terminal source generator prefix.
    # The compiler/runtime loops occur after def identity and are never imported.
    runner=source/"tests/session-terminal/run_host.py"; text=runner.read_text()
    marker="\ndef identity(path):"; assert text.count(marker)==1
    prefix=text[:text.index(marker)]
    assert "subprocess.run(" not in prefix
    ns={"__file__":str(runner),"__name__":"__startup_fixture_generation__"}
    previous=list(sys.argv)
    try:
        sys.argv=[str(runner),"--output",str(out),"--java-home",str(java_home)]
        exec(compile(prefix,str(runner),"exec"),ns)
    finally:sys.argv=previous
    generated=out/"src"; harness=generated/"org/trillionnium/hepta/local/SessionTerminalHost.java"
    before=harness.read_text(); current=before
    local=source/"src/org/trillionnium/hepta/local"
    session=(local/"LocalTaskSession.java").read_text()
    background=(local/"BackgroundSession.java").read_text()
    web=(local/"WebFlightSession.java").read_text()
    journal=(local/"WebEvidenceJournal.java").read_text()
    original_background="static final class BackgroundSession {static final class Selection {JSONObject json(){return new JSONObject();}}}"
    actual_background=original_background[:-1]+'\nstatic final String JOURNAL="background-session.active.json";\n'+body(background,"static boolean hasUnreleased(")+"\n}"
    actual_web="static final class WebFlightSession {\n"+body(web,"static boolean hasUnreleased(")+"\n}\n"
    actual_web+="static final class WebEvidenceJournal {static final String ACTIVE=\"web-helper.active.json\";\n"+body(journal,"static boolean hasUnreleased(")+"\n}"
    current=one(current,original_background,actual_background+"\n"+actual_web)
    current=one(current,"static final class LeaseState {final boolean background=false,web=false;}",body(session,"private static final class LeaseState"))
    current=one(current,"LeaseState readLeaseState(){return new LeaseState();}",body(session,"private LeaseState readLeaseState()"))
    current=one(current,"volatile boolean pending,blocked,recovering;","volatile boolean pending,blocked,recovering;boolean cachedLeaseUnreleased;")
    harness.write_text(current)
    # New lease presence uses the actual existing private-file readers. No
    # synthetic true-return path replaces them. UID numbering remains the
    # old session-terminal adapter, mapped to this exact historical owner.
    process=generated/"android/os/Process.java"
    process.write_text(one(process.read_text(),"return 10000;","return "+str(owner_uid)+";"))
    os_source=generated/"android/system/Os.java"; os_text=os_source.read_text()
    os_source.write_text(one(os_text,'?10000:realUid;','?'+str(owner_uid)+':realUid;'))
    (generated/"org/trillionnium/hepta/local/MobiMindPrivateFiles.java").write_bytes((local/"MobiMindPrivateFiles.java").read_bytes())
    (generated/"org/trillionnium/hepta/local/NotesAbortedStartupProducerHost.java").write_bytes((here/"NotesAbortedStartupProducerHost.java").read_bytes())
    # All original producer members remain exact, including archivePriorRecords.
    exact=[]
    for anchor in ns["signatures"]:
        member=body(session,anchor); assert current.count(member)==1,anchor
        exact.append({"signature":anchor,"bytes":len(member.encode()),"sha256":sha(member.encode())})
    for text,anchor in [(background,"static boolean hasUnreleased("),(web,"static boolean hasUnreleased("),
                        (journal,"static boolean hasUnreleased("),(session,"private static final class LeaseState"),
                        (session,"private LeaseState readLeaseState()")]:
        member=body(text,anchor); assert current.count(member)==1
        exact.append({"signature":anchor,"sha256":sha(member.encode())})
    originals=[runner,local/"LocalTaskSession.java",local/"SessionTerminalEvidence.java",local/"SessionJournalQueue.java",
               local/"SessionRecovery.java",local/"BackgroundSession.java",local/"WebFlightSession.java",
               local/"WebEvidenceJournal.java",local/"MobiMindPrivateFiles.java"]
    sources=sorted(generated.rglob("*.java"))+[local/"SessionJournalQueue.java",local/"SessionRecovery.java",local/"SessionTerminalEvidence.java"]
    return sources,{"original_source_refs":[ref(p) for p in originals],"actual_extracted_members":exact,
        "old_generator_prefix_sha256":sha(prefix.encode()),"generated":[ref(p) for p in sorted(generated.rglob("*.java"))],
        "startup_producer_member_bodies_exact":True,"existing_session_terminal_io_ports":True,
        "existing_refusing_ack_stub_retained":True,"lease_presence_uses_actual_private_file_readers":True,
        "host_uid_number_mapping":owner_uid,"startup_uses_original_session_terminal_json_fixture":True,
        "request_and_client_tests_use_pinned_android_json_jar":True,
        "path_projection_is_after_producer_and_both_raw_records_retained":True,
        "phone_startup_proven":False}

def prepare_client(source,out,here):
    local=source/"src/org/trillionnium/hepta/local"; out.mkdir()
    original=(local/"PublicPersonalNotesRecoveryClient.java").read_text()
    old='new ProcessBuilder("su","-c",command).redirectErrorStream(true).start()'
    new='FakePersonalNotesRecoveryProcess.start(command)'
    compiled=one(original,old,new)
    assert one(compiled,new,old)==original
    p=out/"PublicPersonalNotesRecoveryClient.java";p.write_text(compiled)
    return p,{"source":ref(local/"PublicPersonalNotesRecoveryClient.java"),"generated":ref(p),
              "unique_old_expression":old,"unique_host_io_expression":new,"whole_source_inverse_equal":True,
              "port_source":ref(source/"tests/personal-notes-absence/FakePersonalNotesRecoveryProcess.java"),
              "no_su_or_phone_process_can_be_dispatched":True}

def prepare(source,base,out,java_home,here,mapping):
    proof=source_proof(source,base,here)
    manifest=json.loads(mapping.read_text()); row=next(r for r in manifest["rows"] if r["role"]=="journal")
    raw=Path(row["ref"]["path"]).read_bytes(); assert len(raw)==row["ref"]["bytes"] and sha(raw)==row["ref"]["sha256"]
    uid=json.loads(raw)["app_uid"]
    startup,startup_proof=prepare_startup(source,out/"startup-fixture",java_home,here,uid)
    client,client_proof=prepare_client(source,out/"candidate-client",here)
    # The inherited Proc port bodies are exact. Its current values are fixtures;
    # the actual production capture and rejection code is compiled unchanged.
    old=(source/"tests/profile-recovery/ProfileRecoveryHostTest.java").read_text()
    new=(here/"NotesAbortedProcessesHost.java").read_text()
    for anchor in ["static byte[] bytes(","static byte[] stat(","static byte[] status(","static final class Proc implements"]:
        assert new.count(body(old,anchor))==1,anchor
    return startup,client,{"source_inverse":proof,"startup":startup_proof,"client_process_port":client_proof,
                          "proc_port_exact":True,"jvm_invocations":0,"phone_operations":0}
