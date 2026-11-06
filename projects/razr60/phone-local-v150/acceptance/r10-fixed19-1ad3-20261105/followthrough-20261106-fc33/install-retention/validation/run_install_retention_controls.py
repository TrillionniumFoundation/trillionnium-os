"""Offline adversarial/real-host-byte tests. No actor, device, BUILD or install runs."""
import base64,copy,errno,hashlib,json,os,signal,stat,subprocess,sys,tempfile,time,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=Path(sys.argv[1]);OUT.mkdir(mode=0o700)
def load(name,path):
    m=types.ModuleType(name);m.__file__=str(path);exec(compile(path.read_bytes(),str(path),"exec"),m.__dict__);return m
C=load("capture",ROOT/"source/install_retention_protocol_UNBOUND.py")
B=load("binding",ROOT/"source/verify_install_retention_UNBOUND.py")
R=load("install_reader",ROOT/"references/verify_install_start_ready.d1de.py")
P=load("execution_protocol",ROOT/"references/install_ready_execution_protocol.v2.py")
cases=[]
def check(v):
    if not v:raise AssertionError("offline source control failed")
def test(name,fn):
    fn();cases.append(dict(name=name,passed=True))
def rejects(name,fn,message=None,kind=ValueError):
    try:fn()
    except kind as e:
        if message is not None:check(message in str(e))
        cases.append(dict(name=name,passed=True,rejection=str(e),exception=type(e).__name__))
    else:raise AssertionError("accepted negative "+name)
def mutate(raw,fn):
    value=json.loads(raw);fn(value);return C.canonical(value)
def row(path,raw):return dict(path=path,**C.pin(raw))
def meta(size,inode=11):
    return [1,inode,stat.S_IFREG|0o600,0,0,1,size,100,100]
calls=[]
def trap(x):calls.append(x);raise AssertionError("unbound called source I/O")
rejects("producer_unbound_before_parse_and_io",lambda:C.run_bound(b"bad",b"bad"),"UNBOUND_")
rejects("phase_authority_unbound_before_callback",lambda:B.derive_scope_from_actual_phase(b"bad",read_pinned=trap),"UNBOUND_")
rejects("retention_reader_unbound_before_callback",lambda:B.verify_retention_inputs(b"bad",read_pinned=trap),"UNBOUND_")
rejects("retention_writer_unbound_before_directory",lambda:B.retain_installation_originals(b"bad",OUT/"never",read_pinned=trap),"UNBOUND_")
test("no_unbound_callbacks_or_output_directory",lambda:check(calls==[]and not(OUT/"never").exists()))
rejects("duplicate_scope_json",lambda:C.strict(b'{"x":1,"x":2}',100),"duplicate")
rejects("nonfinite_scope_json",lambda:C.strict(b'{"x":NaN}',100),"nonfinite")

large=b'{"fixture":"HOST_SOURCE_CONTROL","payload":"'+("汉🙂\\n".encode()*1100000)+b'"}\n'
check(len(large)>8*1024*1024 and len(large)<=C.MAX_FILE)
boundary=dict(retirement_sha256="1"*64,component_input_sha256="2"*64,policy_adoption_sha256="3"*64)
release_manifest=dict(_boundary=boundary,_archive_sha256="4"*64,_manifest_sha256="5"*64,writes=[{"fixture":1}])
stage=dict(state="STAGED_DISABLED_NOT_STARTED",release_id="v150-r10-r1",archive_sha256="4"*64,
           manifest_sha256="5"*64,writes_verified=1,disable_identity=[1,101,0,1,1],retirement_sha256="1"*64,
           closed_component_originals_preserved=True,old_retirement_current_equality_claimed=False,
           stage_preservation=C.pin(large),policy_adoption_inputs_sha256="3"*64,
           component_boundary_inputs_sha256="2"*64,model_requests=0,task_submissions=0,service_starts=0)
started=dict(state="SERVICE_SPAWNED_READINESS_NOT_YET_ESTABLISHED",pid=51,process_identity=[51,51,51,999],
             boot_id=C.BOOT,release_id="v150-r10-r1",one_start_attempt=True,model_requests=0,task_submissions=0)
phases={"stage":{"phone_stdout":R.original_entry_stdout(stage)},"start":{"phone_stdout":R.original_entry_stdout(started)}}
files,generation=B.phase_files(R,C,release_manifest,"stage",phases)
small_intent=R.original_file_json(dict(release_id="v150-r10-r1",retirement_sha256="1"*64,write_count=1,automatic_replay=False))
contents={"install_intent":small_intent,"staged":R.original_file_json(stage),"preservation":large}
scope=dict(schema=C.SCHEMA,boot_id=C.BOOT,release_id="v150-r10-r1",phase="stage",
    authority_inputs={"path":"/HOST_SOURCE_CONTROL/phase-authority.json","bytes":17,"sha256":"a"*64},
    release_inputs={"path":"/HOST_SOURCE_CONTROL/release.json","bytes":17,"sha256":"b"*64},
    execution_plan={"path":"/HOST_SOURCE_CONTROL/plan.json","bytes":17,"sha256":"c"*64},
    actual_build_result_sha256="d"*64,archive_sha256="4"*64,release_manifest_sha256="5"*64,
    retirement_sha256="1"*64,component_boundary_inputs_sha256="2"*64,policy_adoption_inputs_sha256="3"*64,
    phase_result_sha256="e"*64,phase_stdout_sha256=C.pin(phases["stage"]["phone_stdout"])["sha256"],
    phase_source_identity=[41,39,41,41,123],installation_generation=None,files=files)
scope_raw=C.canonical(scope);C.decode_scope(scope_raw)
test("stage_file_pins_derived_from_original_serializations_and_preservation_pin",
     lambda:check(all(C.pin(contents[x["role"]])=={k:x[k]for k in("bytes","sha256")}for x in files)))
test("stdout_and_saved_file_encodings_stay_distinct",lambda:check(phases["stage"]["phone_stdout"]!=contents["staged"]))
start_files,start_generation=B.phase_files(R,C,release_manifest,"start",phases)
start_scope=copy.deepcopy(scope);start_scope.update(phase="start",files=start_files,installation_generation=start_generation)
test("start_binds_full_supervisor_generation",lambda:C.validate_scope(start_scope))
for name,fn,message in [
 ("arbitrary_path",lambda x:x["files"][0].update(path="/etc/passwd"),"role/path"),
 ("wrong_role",lambda x:x["files"][0].update(role="model"),"role/path"),
 ("wrong_boot",lambda x:x.update(boot_id="another"),"scope"),
 ("stage_claims_new_generation",lambda x:x.update(installation_generation=[1,1,1,1]),"no new supervisor"),
 ("bool_file_size",lambda x:x["files"][0].update(bytes=True),"typed bounded"),
 ("float_file_size",lambda x:x["files"][0].update(bytes=float(x["files"][0]["bytes"])),"typed bounded"),
 ("oversize_preservation",lambda x:x["files"][-1].update(bytes=C.MAX_FILE+1),"typed bounded"),
 ("extra_file",lambda x:x["files"].append(copy.deepcopy(x["files"][0])),"file count"),
 ("old_phase_identity_boolean",lambda x:x["phase_source_identity"].__setitem__(0,True),"exact identity"),
]:
    rejects("scope_"+name,lambda fn=fn:C.decode_scope(mutate(scope_raw,fn)),message)
rejects("scope_missing_final_LF",lambda:C.decode_scope(scope_raw[:-1]),"canonical")
bad_phases=copy.deepcopy(phases);bad_started=copy.deepcopy(started);bad_started["process_identity"][-1]=True
bad_phases["start"]["phone_stdout"]=R.original_entry_stdout(bad_started)
rejects("start_tuple_boolean_not_int",lambda:B.phase_files(R,C,release_manifest,"start",bad_phases),"identity")
bad_phases=copy.deepcopy(phases);bad_stage=copy.deepcopy(stage);bad_stage["writes_verified"]=True
bad_phases["stage"]["phone_stdout"]=R.original_entry_stdout(bad_stage)
rejects("stage_writes_boolean_not_int",lambda:B.phase_files(R,C,release_manifest,"stage",bad_phases),"actual stage")
bound=C.bind_source(scope_raw,(ROOT/"source/install_retention_protocol_UNBOUND.py").read_bytes())
test("in_memory_bound_source_exact_inverse",lambda:check(bound.replace(
 ("FROZEN_SCOPE = "+repr(C.pin(scope_raw))+"\n").encode(),b"FROZEN_SCOPE = None\n",1)==
 (ROOT/"source/install_retention_protocol_UNBOUND.py").read_bytes()))

class FixtureObserver:
    def __init__(self,generation=None):self.generation=generation
    def start(self):pass
    def finish(self):
        raw=b"41 (HOST SOURCE CONTROL) S 39 41 41 "+b"0 "*15+b"123\n"
        return dict(boot_id=C.BOOT,before_identity=[41,39,41,41,123],after_identity=[41,39,41,41,123],
                    before_proc_base64=base64.b64encode(raw).decode(),after_proc_base64=base64.b64encode(raw).decode(),
                    started_monotonic_ns=100,ended_monotonic_ns=200,installation_generation=self.generation)
class RootOwnershipFixture:
    """Only uid/gid are normalized for a synthetic phone fixture on a nonroot Mac."""
    def __init__(self,real):self.real=real
    def normalize(self,m):
        m=list(m);m[3:5]=[0,0];return m
    def actual(self,m):
        if m is None:return None
        m=list(m);m[3:5]=[os.getuid(),os.getgid()];return m
    def check_root(self,expected=None):return self.normalize(self.real.check_root(self.actual(expected)))
    def scan(self,row,expected_metadata=None,index=None):
        m,b=self.real.scan(row,self.actual(expected_metadata),index);return self.normalize(m),b

def fdcount():return len(os.listdir("/dev/fd"))
with tempfile.TemporaryDirectory(prefix="fc33-install-retention-")as temporary:
    root=Path(temporary).resolve()/"originals";root.mkdir(mode=0o700)
    for role,body in contents.items():
        p=root/C.FILES[role]
        with p.open("xb")as f:f.write(body)
        p.chmod(0o600)
    baseline_fds=fdcount()
    with C.LocalOriginals(str(root),os.getuid(),os.getgid())as real:
        fs=RootOwnershipFixture(real)
        first=C.capture(scope_raw,C.manifest_operation(),fs,FixtureObserver())
        operations=C.chunk_operations(scope_raw,first)
        chunks=[C.capture(scope_raw,op,fs,FixtureObserver())for op in operations]
        last=C.capture(scope_raw,C.manifest_operation(),fs,FixtureObserver())
    restored=C.reassemble(scope_raw,first,chunks,last)
    test("real_host_large_original_complete_roundtrip",lambda:check(restored==contents))
    test("large_original_exceeds_shell_cap_each_chunk_is_bounded",
         lambda:check(len(large)>8*1024*1024 and all(len(x)<C.MAX_RECORD<8*1024*1024 for x in chunks)))
    test("full9_scan_and_chunk_fds_return_to_baseline",lambda:check(fdcount()==baseline_fds))
    test("UTF8_emoji_backslash_newline_and_final_LF_preserved",lambda:check(restored["preservation"]==large and large.endswith(b"\n")))
    for name,fn,message in [
     ("byte_count_boolean",lambda x:x["files"][0].update(bytes=True),"typed bounded"),
     ("byte_count_float",lambda x:x["files"][0].update(bytes=float(x["files"][0]["bytes"])),"typed bounded"),
     ("file_hardlink",lambda x:x["files"][0]["metadata"].__setitem__(5,2),"single-link"),
     ("root_metadata_float",lambda x:x["root_metadata"].__setitem__(1,float(x["root_metadata"][1])),"typed full9"),
     ("other_scope",lambda x:x["scope"].update(sha256="f"*64),"belongs to scope"),
     ("swapped_roles",lambda x:x["files"].reverse(),"order"),
     ("capture_pid_boolean",lambda x:x["observer"]["before_identity"].__setitem__(0,True),"identity"),
     ("unearned_generation",lambda x:x["observer"].update(installation_generation=[1,1,1,1]),"stage generation"),
    ]:
        rejects("manifest_"+name,lambda fn=fn:C.validate_manifest(scope_raw,mutate(first,fn)),message)
    for name,fn,message in [
     ("index_boolean",lambda x:x.update(index=False),"typed exact"),
     ("offset_float",lambda x:x.update(offset=0.0),"typed exact"),
     ("length_boolean",lambda x:x["chunk"].update(bytes=True),"typed bounded"),
     ("file_size_float",lambda x:x["file"].update(bytes=float(x["file"]["bytes"])),"typed bounded"),
     ("wrong_data_hash",lambda x:x["chunk"].update(sha256="0"*64),"complete canonical"),
     ("wrong_manifest",lambda x:x["manifest"].update(sha256="0"*64),"linkage"),
     ("wrong_scope",lambda x:x["scope"].update(sha256="0"*64),"linkage"),
     ("wrong_file_inode",lambda x:x["file"]["metadata"].__setitem__(1,x["file"]["metadata"][1]+1),"original file identity"),
     ("eof_int",lambda x:x.update(eof=1),"final slice"),
     ("eof_false",lambda x:x.update(eof=False),"final slice"),
     ("extra_field",lambda x:x.update(qualified=True),"exact retained"),
    ]:
        rejects("chunk_"+name,lambda fn=fn:C.validate_chunk(scope_raw,first,operations[0],mutate(chunks[0],fn)),message)
    rejects("truncated_chunk_JSON",lambda:C.validate_chunk(scope_raw,first,operations[0],chunks[0][:-10]),kind=(ValueError,UnicodeError))
    rejects("missing_chunk",lambda:C.reassemble(scope_raw,first,chunks[:-1],last),"all and only")
    duplicate=list(chunks);duplicate[1]=duplicate[0]
    rejects("duplicate_or_reordered_chunk",lambda:C.reassemble(scope_raw,first,duplicate,last))
    changed_last=mutate(last,lambda x:x["files"][0]["metadata"].__setitem__(1,x["files"][0]["metadata"][1]+1))
    rejects("final_original_identity_changed",lambda:C.reassemble(scope_raw,first,chunks,changed_last),"bookends")
    opbad=mutate(operations[0],lambda x:x.update(index=False))
    rejects("operation_boolean_index",lambda:C.operation(scope_raw,opbad),"bounded chunk index")
    opbad=mutate(operations[0],lambda x:x.update(role="provider"))
    rejects("operation_out_of_scope_role",lambda:C.operation(scope_raw,opbad),"bounded chunk index")
    opbad=mutate(operations[0],lambda x:x.update(index=999999))
    rejects("operation_past_EOF",lambda:C.operation(scope_raw,opbad),"bounded chunk index")

    selected=files[0];path=root/C.FILES[selected["role"]]
    original=path.read_bytes();saved=path.with_suffix(".saved");path.rename(saved);path.symlink_to(saved.name)
    with C.LocalOriginals(str(root),os.getuid(),os.getgid())as real:
        rejects("actual_file_symlink_refused",lambda:real.scan(selected),"single-link")
    path.unlink();saved.rename(path)
    os.link(path,root/"hardlink")
    with C.LocalOriginals(str(root),os.getuid(),os.getgid())as real:
        rejects("actual_multiple_link_file_refused",lambda:real.scan(selected),"single-link")
    (root/"hardlink").unlink()
    with C.LocalOriginals(str(root),os.getuid(),os.getgid())as real:
        oldroot=real.root_metadata[:];m,_=real.scan(selected)
        path.write_bytes(b"x"+original[1:])
        rejects("actual_same_length_content_change_refused",lambda:real.scan(selected),"complete original")
        path.write_bytes(original);path.chmod(0o600)
        rejects("actual_stale_full9_refused",lambda:real.scan(selected,m),"full9 differs")
    with C.LocalOriginals(str(root),os.getuid(),os.getgid())as real:
        oldread=C.os.read
        def truncated(fd,size):return b""
        C.os.read=truncated
        try:rejects("actual_short_read_refused",lambda:real.scan(selected),"complete original")
        finally:C.os.read=oldread
        def io_error(fd,size):raise OSError(errno.EIO,"HOST_SOURCE_CONTROL")
        C.os.read=io_error
        try:rejects("unknown_read_io_error_not_hidden",lambda:real.scan(selected),kind=OSError)
        finally:C.os.read=oldread
    with C.LocalOriginals(str(root),os.getuid(),os.getgid())as real:
        renamed=root.with_name("renamed");root.rename(renamed)
        try:rejects("original_directory_rename_refused",lambda:real.scan(selected),kind=FileNotFoundError)
        finally:renamed.rename(root)
    test("error_paths_close_original_descriptors",lambda:check(fdcount()==baseline_fds))
    value=dict(scope=scope,scope_pin=C.pin(scope_raw),files=json.loads(first)["files"],bodies=restored,original_operation_count=len(operations)+2)
    result=B._save_verified(value,Path(temporary).resolve()/"retained")
    def read_retained(row):
        p=Path(row["path"]);before=C.full9(p.lstat());raw=p.read_bytes()
        check(before==row["metadata"]==C.full9(p.lstat())and C.pin(raw)=={k:row[k]for k in("bytes","sha256")});return raw
    pool=R.Originals(result["original_map"],read_retained)
    for original in json.loads(first)["files"]:
        raw=pool.phone({k:original[k]for k in("path","bytes","sha256","metadata")},original["path"],C.MAX_FILE)
        check(raw==contents[original["role"]])
    pool.recheck()
    test("retained_host_full9_map_accepted_by_unchanged_install_reader",lambda:check(result["actual_install_or_READY_qualified"]is False))
    rejects("retained_directory_cannot_be_overwritten",lambda:B._save_verified(value,Path(temporary).resolve()/"retained"),kind=FileExistsError)
    before=fdcount();oldsync=B.os.fsync
    def fail_sync(fd):raise OSError(errno.EIO,"HOST_SOURCE_CONTROL")
    B.os.fsync=fail_sync
    try:rejects("unknown_publish_io_leaves_no_terminal_result",lambda:B._save_verified(value,Path(temporary).resolve()/"failed"),kind=OSError)
    finally:B.os.fsync=oldsync
    test("failed_publish_no_result_and_fd_baseline",lambda:check(not(Path(temporary)/"failed/RETENTION-RESULT.json").exists()and fdcount()==before))
    pre=load("pre_dirfd_binding",ROOT/"references/verify_install_retention.pre_dirfd.py")
    def swap_publication(module,folder,escape):
        old_open=module.os.open;changed=[False]
        def racing_open(path,flags,*args,**kwargs):
            if not changed[0]and flags&os.O_CREAT:
                changed[0]=True;folder.rename(folder.with_name(folder.name+"_original"))
                folder.symlink_to(escape,target_is_directory=True)
            return old_open(path,flags,*args,**kwargs)
        module.os.open=racing_open
        try:return module._save_verified(value,folder)
        finally:module.os.open=old_open
    escaped=Path(temporary).resolve()/"escaped_baseline";escaped.mkdir(mode=0o700)
    baseline_result=swap_publication(pre,Path(temporary).resolve()/"baseline_race",escaped)
    test("pre_fix_directory_swap_reproduced",lambda:check((escaped/"RETENTION-RESULT.json").exists()))
    blocked=Path(temporary).resolve()/"escaped_fixed";blocked.mkdir(mode=0o700);before=fdcount()
    rejects("directory_swap_rejected_on_held_fd_publication",
            lambda:swap_publication(B,Path(temporary).resolve()/"fixed_race",blocked),"directory identity")
    test("directory_swap_writes_nothing_to_replacement_and_closes_fds",
         lambda:check(list(blocked.iterdir())==[]and fdcount()==before))


template=(ROOT/"source/install_retention_protocol_UNBOUND.py").read_bytes()
actor_plan=dict(actor=dict(path=P.P4+"/ops/HOST_SOURCE_CONTROL.py",bytes=3,sha256=hashlib.sha256(b"abc").hexdigest()),
                actor_python="/usr/bin/python3",actor_cwd=P.P4)
selected_lease=dict(label="HOST_SOURCE_CONTROL_capture",request_path=P.P4+"/requests/HOST_SOURCE_CONTROL_capture.json",
                    idempotency_key="HOST_SOURCE_CONTROL_capture")
expected=B.expected_operation(C,P,template,scope_raw,C.manifest_operation(),selected_lease,actor_plan)
largest=B.expected_operation(C,P,template,scope_raw,operations[2],selected_lease,actor_plan)
test("manifest_and_chunk_wire_requests_below_unchanged_ceiling",
     lambda:check(max(expected["wire_bytes"],largest["wire_bytes"])<65536))
test("exact_v2_environment_and_timeout",
     lambda:check(__import__("shlex").split(expected["request"]["command"])[:-1]==P.GNU_EXEC_PREFIX
                  and expected["request"]["timeout_seconds"]==120 and C.CAPTURE_SECONDS==30))
test("request_serializer_final_LF",lambda:check(expected["request_raw"].endswith(b"\n")and expected["request_raw"]==P.request_bytes(expected["request"])))

def actor_fixture(phone_code=0,result_change=None,status_change=None,request_change=None,retained_stdout=None):
    source=b"abc";source_row=dict(actor_plan["actor"],metadata=meta(len(source),55))
    req=expected["request_raw"]if request_change is None else request_change(expected["request_raw"])
    intent=dict(schema="hepta.phone-local.operator-intent.v150.1",label=selected_lease["label"],
                utc="1970-01-01T00:00:01.500000+00:00",request_sha256=C.pin(req)["sha256"],
                request=json.loads(req),automatic_replay=False)
    baseline=dict(rc=0,stderr="",stdout="\n".join([R.BOOT,R.FINGERPRINT,"adb","Enforcing","3021"])+"\n",route="adb")
    result=dict(schema="hepta.phone-local.operator-result.v150.1",label=selected_lease["label"],status="command_exited",
                model_decision=False,native_task_result=False,elapsed_seconds=0.1,
                phone=dict(rc=phone_code,command=expected["wrapped_command"],route="adb",stdout=first.decode(),stderr=""))
    if result_change:result_change(result)
    raw_result=R.original_actor_json(result)
    summary=dict(run=expected["actor_operation_dir"],status="command_exited",sha256=C.pin(raw_result)["sha256"],
                 elapsed_seconds=0.1,http_status=None,phone_rc=phone_code,error=None)
    summary_raw=(json.dumps(summary,ensure_ascii=False)+"\n").encode()
    dispatch=expected["dispatch"]
    status=dict(job_id="HOST_SOURCE_CONTROL_job",state="succeeded",exit_code=0,at_unix_ms=2000,
                output_complete=True,output_durable=True,terminal_publication_confirmed=True,timed_out=False,cancelled=False,
                log_errors=dict(stdout=None,stderr=None),log_truncated=dict(stdout=False,stderr=False),
                log_synced=dict(stdout=True,stderr=True),
                log_bytes=dict(stdout=dict(seen=len(summary_raw),stored=len(summary_raw)),stderr=dict(seen=0,stored=0)))
    if status_change:status_change(status)
    def stream(raw):return dict(bytes_hex=raw.hex(),eof=True,next_offset=len(raw),offset=0,size=len(raw),text=raw.decode())
    def tool(value):return C.canonical(dict(content=[dict(type="text",text=json.dumps(value))],structuredContent=None,isError=False))
    values=dict(dispatch=C.canonical(dispatch),
      start=tool(dict(job=dict(dispatch,id="HOST_SOURCE_CONTROL_job",created_unix_ms=1000,launch_state="launched",launch_error=None,env_keys=[]),reused=False)),
      status=tool(status),read=tool(dict(job_id="HOST_SOURCE_CONTROL_job",stdout=stream(summary_raw),stderr=stream(b""))))
    pool_values={}
    def add(path,raw,private=False):
        pool_values[path]=raw
        return dict(path=path,**C.pin(raw),**({"metadata":meta(len(raw),len(pool_values)+100)}if private else{}))
    process={key:add("/HOST_SOURCE_CONTROL/"+key,raw)for key,raw in values.items()}
    root=expected["actor_operation_dir"]
    records=dict(process=process,actor_source_before=source_row,actor_source_after=source_row,
                 request=add(selected_lease["request_path"],req,True),
                 intent=add(root+"/intent.json",R.original_actor_json(intent),True),
                 baseline=add(root+"/baseline.json",R.original_actor_json(baseline),True),
                 result=add(root+"/result.json",raw_result,True),
                 phone_stdout=add("/HOST_SOURCE_CONTROL/phone_stdout",result["phone"]["stdout"].encode()if retained_stdout is None else retained_stdout),
                 phone_stderr=add("/HOST_SOURCE_CONTROL/phone_stderr",result["phone"]["stderr"].encode()))
    pool_values[source_row["path"]]=source
    class FixturePool:
        def read(self,row,maximum):
            raw=pool_values[row["path"]];check(len(raw)<=maximum and C.pin(raw)=={k:row[k]for k in("bytes","sha256")});return raw
        def p4(self,row,path,maximum,request=False):check(row["path"]==path);return self.read(row,maximum)
    return B.verify_capture_actor(R,C,records,expected,selected_lease,actor_plan,FixturePool())
test("synthetic_original_capture_actor_roundtrip",lambda:check(actor_fixture()[0]==first))
rejects("controller_zero_phone_nonzero_rejected_with_consistent_hashes",lambda:actor_fixture(phone_code=7),"phone must also exit zero")
rejects("phone_false_is_not_integer_exit_zero",lambda:actor_fixture(phone_code=False),"phone must also exit zero")
rejects("unknown_timeout_never_retains_success",lambda:actor_fixture(status_change=lambda x:x.update(timed_out=True)),"complete success")
rejects("controller_log_count_boolean_rejected",lambda:actor_fixture(status_change=lambda x:x["log_bytes"]["stderr"].update(seen=False)),"stream counts")
rejects("capture_actor_wrong_label_consistent_result_hash",lambda:actor_fixture(result_change=lambda x:x.update(label="OLD_LABEL")),"complete original binding")
rejects("wrong_inline_source_request",lambda:actor_fixture(request_change=lambda x:mutate(x,lambda v:v.update(command=v["command"]+"\n# changed"))),"inline producer request")
rejects("capture_separate_stdout_mismatch",lambda:actor_fixture(retained_stdout=b"{}\n"),"retained capture phone streams")
rejects("capture_success_with_nonempty_stderr_rejected",lambda:actor_fixture(result_change=lambda x:x["phone"].update(stderr="hidden failure")),"empty stderr")
child="""import importlib.util,json,os,sys,time
p=sys.argv[1];s=importlib.util.spec_from_file_location('retention',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r,w=os.pipe();os.set_blocking(w,False)
try:
 while True:os.write(w,b'x'*65536)
except BlockingIOError:pass
os.set_blocking(w,True);saved=os.dup(1);os.dup2(w,1);start=time.monotonic();before=[os.getpid(),os.getpgrp(),os.getsid(0)]
try:
 try:m.write_response(b'z',time.monotonic()+0.15)
 except ValueError as e:error=str(e)
 else:raise AssertionError('full pipe accepted')
 blocking=os.get_blocking(1)
finally:os.dup2(saved,1);os.close(saved);os.close(w);os.close(r)
print(json.dumps(dict(error=error,elapsed=time.monotonic()-start,same_process=before==[os.getpid(),os.getpgrp(),os.getsid(0)],blocking_restored=blocking)))
"""
child_path=OUT/"blocked_stdout_child.py";child_path.write_text(child)
p=subprocess.Popen([sys.executable,"-I","-B",str(child_path),str(ROOT/"source/install_retention_protocol_UNBOUND.py")],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
try:stdout,stderr=p.communicate(timeout=5)
except BaseException:
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    p.communicate();raise
check(p.returncode==0 and not stderr);pipe_result=json.loads(stdout)
test("blocked_output_bounded_and_original_process_unchanged",
     lambda:check(pipe_result["same_process"]and pipe_result["blocking_restored"]and 0.1<=pipe_result["elapsed"]<2))
try:os.killpg(p.pid,0)
except ProcessLookupError:pass
else:raise AssertionError("host test process group remained")
test("host_deadline_test_process_group_cleaned",lambda:check(True))
result=dict(schema="hepta.install-original-retention.source-controls.v1",state="PASS_SOURCE_ONLY",
            passed=len(cases),tests=cases,large_original_bytes=len(large),large_original_sha256=C.pin(large)["sha256"],
            chunk_count=len(chunks),maximum_chunk_response_bytes=max(map(len,chunks)),
            manifest_wire_bytes=expected["wire_bytes"],chunk_wire_bytes=largest["wire_bytes"],
            source_pins={p.name:C.pin(p.read_bytes())for p in sorted((ROOT/"source").glob("*.py"))},
            actual_authority_positive_executed=False,actual_phone_observer_executed=False,
            real_host_file_bytes_and_full9_exercised=True,uid_gid_only_normalized_in_synthetic_phone_fixture=True,
            synthetic_capture_actor_fixtures=True,blocked_pipe_result=pipe_result,
            actual_scopes_bound=0,actor_executions=0,phone_calls=0,actual_BUILD=0,actual_install=0,actual_READY=0,
            new_nonces=0,fixed19_credit=0,whole_qualification=False)
raw=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
with(OUT/"RESULT.json").open("xb")as f:f.write(raw)
print(json.dumps({k:result[k]for k in("state","passed","large_original_bytes","chunk_count","maximum_chunk_response_bytes",
    "manifest_wire_bytes","chunk_wire_bytes","source_pins","actual_authority_positive_executed","phone_calls","fixed19_credit")},sort_keys=True))
