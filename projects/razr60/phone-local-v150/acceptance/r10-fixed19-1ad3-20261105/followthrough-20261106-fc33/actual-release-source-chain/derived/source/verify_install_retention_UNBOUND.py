"""Host-only original authority and bounded capture binding; no dispatch.
Actual slots remain None. Pure constructors and fixture helpers cannot qualify
BUILD, installation, READY or a business case.
"""
import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path,PurePosixPath
import re
import shlex
import stat
import types

FROZEN_PHASE_AUTHORITY = None
FROZEN_RETENTION_INPUTS = None
INSTALL_READER = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/verify_install_start_ready_UNBOUND.py', 'bytes': 35272, 'sha256': '11dc1a130bbec45fd65767707fea354532f7ba18b53b3b227d1eaea4babedd2b'}
PRODUCER = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/install_retention_protocol_UNBOUND.py', 'bytes': 20851, 'sha256': '280df226c4bde2294bfaefec93da40fcbc0c685e7c20a2359444e856fbd0bb7a'}
AUTH_SCHEMA = "hepta.install-original-retention.phase-authority-inputs.v1"
INPUT_SCHEMA = "hepta.install-original-retention.original-inputs.v1"

def need(ok,message):
    if not ok:raise ValueError(message)

def pin(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def canonical(value):
    return(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()

def load_source(row,read_pinned,name):
    raw=read_pinned(dict(row))
    need(type(raw)is bytes and pin(raw)=={k:row[k]for k in ("bytes","sha256")},"exact reviewed host source")
    module=types.ModuleType(name);module.__file__=row["path"]
    exec(compile(raw,row["path"],"exec"),module.__dict__)
    return module,raw

def source_context(read_pinned):
    R,rraw=load_source(INSTALL_READER,read_pinned,"reviewed_install_reader")
    C,craw=load_source(PRODUCER,read_pinned,"reviewed_install_retention")
    return R,C,rraw,craw

def phase_files(R,C,manifest,phase,phases):
    stage_raw=phases["stage"]["phone_stdout"];stage=R.strict(stage_raw,65536)
    R.exact(stage,("state","release_id","archive_sha256","manifest_sha256","writes_verified",
                  "disable_identity","retirement_sha256","closed_component_originals_preserved",
                  "old_retirement_current_equality_claimed","stage_preservation",
                  "policy_adoption_inputs_sha256","component_boundary_inputs_sha256",
                  "model_requests","task_submissions","service_starts"),"exact actual stage stdout")
    boundary=manifest["_boundary"]
    need(stage_raw==R.original_entry_stdout(stage)and stage["state"]=="STAGED_DISABLED_NOT_STARTED"
         and stage["release_id"]=="v150-r10-r1"and stage["archive_sha256"]==manifest["_archive_sha256"]
         and stage["manifest_sha256"]==manifest["_manifest_sha256"]
         and type(stage["writes_verified"])is int and stage["writes_verified"]==len(manifest["writes"])
         and stage["retirement_sha256"]==boundary["retirement_sha256"]
         and stage["component_boundary_inputs_sha256"]==boundary["component_input_sha256"]
         and stage["policy_adoption_inputs_sha256"]==boundary["policy_adoption_sha256"]
         and stage["closed_component_originals_preserved"]is True
         and stage["old_retirement_current_equality_claimed"]is False
         and all(type(stage[k])is int and stage[k]==0 for k in("model_requests","task_submissions","service_starts")),
         "actual stage source stdout and exact BUILD boundary")
    disable=stage["disable_identity"]
    need(type(disable)is list and len(disable)==5 and all(type(n)is int and n>=0 for n in disable)
         and disable[1]>0 and disable[2]==0,"actual disable original identity")
    C.pinned(stage["stage_preservation"],C.MAX_FILE)
    if phase=="stage":
        intent={"release_id":"v150-r10-r1","retirement_sha256":boundary["retirement_sha256"],
                "write_count":len(manifest["writes"]),"automatic_replay":False}
        specs=[("install_intent",pin(R.original_file_json(intent))),
               ("staged",pin(R.original_file_json(stage))),("preservation",stage["stage_preservation"])]
        generation=None
    else:
        raw=phases["start"]["phone_stdout"];started=R.strict(raw,65536)
        R.exact(started,("state","pid","process_identity","boot_id","release_id","one_start_attempt",
                         "model_requests","task_submissions"),"exact actual STARTED stdout")
        generation=C.identity(started["process_identity"],4)
        need(raw==R.original_entry_stdout(started)and started["state"]=="SERVICE_SPAWNED_READINESS_NOT_YET_ESTABLISHED"
             and type(started["pid"])is int and generation[:3]==[started["pid"]]*3
             and started["boot_id"]==C.BOOT and started["release_id"]=="v150-r10-r1"
             and started["one_start_attempt"]is True and all(type(started[k])is int and started[k]==0
                  for k in("model_requests","task_submissions")),"actual started supervisor generation")
        intent={"release_id":"v150-r10-r1","maximum_start_attempts":1,"old_release_remains_disabled":True}
        specs=[("start_intent",pin(R.original_file_json(intent))),("started",pin(R.original_file_json(started)))]
    return [dict(role=role,path=C.ROOT+"/"+C.FILES[role],**value)for role,value in specs],generation

def _derive_authority(inputs_raw,read_pinned):
    R,C,rraw,craw=source_context(read_pinned)
    R.descriptor(FROZEN_PHASE_AUTHORITY,4*1024*1024,metadata=False)
    need(type(inputs_raw)is bytes and pin(inputs_raw)=={k:FROZEN_PHASE_AUTHORITY[k]for k in("bytes","sha256")},
         "exact frozen actual phase authority")
    value=R.exact(R.strict(inputs_raw),("schema","phase","release_inputs","execution_plan","phases","original_map"),
                  "exact phase authority input")
    need(value["schema"]==AUTH_SCHEMA and value["phase"]in C.ROLES,"installation stage/start authority only")
    R.descriptor(value["release_inputs"],1024*1024,metadata=False)
    R.descriptor(value["execution_plan"],65536,metadata=False)
    pool=R.Originals(value["original_map"],read_pinned)
    need(pool.read(INSTALL_READER,262144)==rraw and pool.read(PRODUCER,65536)==craw,"source original map bookends")
    P=R.reviewed(pool.read(R.SOURCES["protocol"],262144),R.SOURCES["protocol"],"original_install_protocol")
    A=R.reviewed(pool.read(R.SOURCES["release"],262144),R.SOURCES["release"],"original_BUILD_reader")
    release_raw=pool.read(value["release_inputs"],1024*1024);release_inputs=R.strict(release_raw,1024*1024)
    release=A.verify_final_release_inputs(release_raw,read_pinned=pool.read)
    need(release["state"]=="ACTUAL_HOST_RELEASE_ORIGINALS_VERIFIED_PHONE_READINESS_SEPARATE"
         and release["all_17_shared_bytes_equal"]is True and release["all_originals_bookended"]is True
         and release["phone_ready"]is False and release["whole_case_pass"]is False,"actual BUILD originals, never caller qualification")
    plan_raw=pool.read(value["execution_plan"],65536);plan=R.strict(plan_raw,65536)
    P.validate_plan(plan,release,release_inputs)
    need(plan["release_inputs_sha256"]==pin(release_raw)["sha256"],"phase plan actual BUILD binding")
    archive=pool.read(release_inputs["release_archive"],64*1024*1024)
    installer=pool.read(release_inputs["installer_source"],262144)
    projection=A.project_installer(installer,release_inputs["release_archive"],archive)
    manifest,unused=projection["load_release"](PurePosixPath(release_inputs["release_archive"]["path"]),
       release_inputs["release_archive"]["sha256"],release["release_pins"]["component_boundary_inputs_sha256"],
       release["release_pins"]["policy_adoption_inputs_sha256"])
    order=("stage",)if value["phase"]=="stage"else("stage","start")
    R.exact(value["phases"],order,"actual required phase originals only")
    phases={name:R.verify_phase(name,value["phases"][name],plan,release,release_inputs,
                  manifest["_boundary"]["retirement_sha256"],P,pool)for name in order}
    if len(order)==2:
        need(phases["stage"]["authority"]["terminal_unix_ms"]<=phases["start"]["authority"]["created_unix_ms"],
             "stage original completion precedes start")
    files,generation=phase_files(R,C,manifest,value["phase"],phases)
    selected=phases[value["phase"]]
    scope=dict(schema=C.SCHEMA,boot_id=C.BOOT,release_id="v150-r10-r1",phase=value["phase"],
       authority_inputs=FROZEN_PHASE_AUTHORITY,release_inputs=value["release_inputs"],execution_plan=value["execution_plan"],
       actual_build_result_sha256=release["actual_build_result_sha256"],archive_sha256=manifest["_archive_sha256"],
       release_manifest_sha256=manifest["_manifest_sha256"],retirement_sha256=manifest["_boundary"]["retirement_sha256"],
       component_boundary_inputs_sha256=manifest["_boundary"]["component_input_sha256"],
       policy_adoption_inputs_sha256=manifest["_boundary"]["policy_adoption_sha256"],
       phase_result_sha256=selected["actual_actor_result_sha256"],
       phase_stdout_sha256=pin(selected["phone_stdout"])["sha256"],
       phase_source_identity=selected["source_receipt"]["identity"],installation_generation=generation,files=files)
    C.validate_scope(scope);scope_raw=C.canonical(scope);pool.recheck()
    return scope_raw,dict(R=R,C=C,P=P,template=craw,plan=plan,release=release,release_inputs=release_inputs,
                         retirement_sha256=manifest["_boundary"]["retirement_sha256"],
                         last_phase=selected,authority_value=value)

def derive_scope_from_actual_phase(inputs_raw,*,read_pinned):
    need(FROZEN_PHASE_AUTHORITY is not None,"UNBOUND_INSTALL_RETENTION_PHASE_AUTHORITY_NO_IO")
    scope,context=_derive_authority(inputs_raw,read_pinned)
    return scope

def lease(C,P,value):
    C.exact(value,("label","request_path","idempotency_key"),"exact original capture operation identity")
    need(type(value["label"])is str and re.fullmatch("[A-Za-z0-9_-]{1,100}",value["label"]),"original actor label syntax")
    need(type(value["request_path"])is str and PurePosixPath(P.P4)in P.path(value["request_path"]).parents,
         "established P4 request namespace")
    need(type(value["idempotency_key"])is str and 1<=len(value["idempotency_key"].encode())<=128,"original controller identity")
    return value

def expected_operation(C,P,template,scope_raw,op_raw,identity_row,actor_plan):
    C.decode_scope(scope_raw);C.operation(scope_raw,op_raw);lease(C,P,identity_row)
    bound=C.bind_source(scope_raw,template)
    bootstrap=("import base64\n_SCOPE=base64.b64decode("+repr(base64.b64encode(scope_raw).decode())+",validate=True)\n"
               "_OP=base64.b64decode("+repr(base64.b64encode(op_raw).decode())+",validate=True)\n").encode()+bound+b"\nrun_bound(_SCOPE,_OP)\n"
    compile(bootstrap,"<exact-install-retention-inline>","exec")
    command=shlex.join(P.GNU_EXEC_PREFIX+[bootstrap.decode()])
    wrapped="/debug_ramdisk/su -c "+shlex.quote(command);wire=("shell,v2,raw:"+wrapped).encode()
    need(len(wire)<65536,"unchanged ADB service byte ceiling")
    request=dict(kind="shell",root=True,timeout_seconds=120,command=command)
    dispatch=dict(host="pocket4",executable=actor_plan["actor_python"],
       args=["-I","-B",actor_plan["actor"]["path"],identity_row["label"],identity_row["request_path"]],
       cwd=actor_plan["actor_cwd"],idempotency_key=identity_row["idempotency_key"])
    return dict(request=request,request_raw=P.request_bytes(request),wrapped_command=wrapped,dispatch=dispatch,
                actor_operation_dir=P.P4+"/operations/"+identity_row["label"],wire_bytes=len(wire),
                template=pin(template),bound_source=pin(bound),bootstrap=pin(bootstrap))

def verify_capture_actor(R,C,records,expected,identity_row,actor_plan,pool):
    R.exact(records,("process","actor_source_before","actor_source_after","request","intent","baseline","result",
                     "phone_stdout","phone_stderr"),"complete actual capture actor originals")
    for key in("actor_source_before","actor_source_after"):
        row=records[key]
        need({k:row[k]for k in("path","bytes","sha256")}==actor_plan["actor"],"original capture actor source")
        pool.p4(row,actor_plan["actor"]["path"],65536)
    need(records["actor_source_before"]==records["actor_source_after"],"actual capture actor full9 bookends")
    request_raw=pool.p4(records["request"],identity_row["request_path"],65536,request=True)
    need(request_raw==expected["request_raw"],"exact complete inline producer request")
    authority,cli=R.verify_process(records["process"],expected,pool)
    root=expected["actor_operation_dir"]
    intent_raw=pool.p4(records["intent"],root+"/intent.json",131072,request=True)
    baseline_raw=pool.p4(records["baseline"],root+"/baseline.json",131072,request=True)
    result_raw=pool.p4(records["result"],root+"/result.json",R.MAX_RESULT,request=True)
    intent,baseline,result=R.strict(intent_raw,131072),R.strict(baseline_raw,131072),R.strict(result_raw,R.MAX_RESULT)
    need(intent_raw==R.original_actor_json(intent)and baseline_raw==R.original_actor_json(baseline)
         and result_raw==R.original_actor_json(result),"actual saved actor JSON encodings")
    R.exact(intent,("schema","label","utc","request_sha256","request","automatic_replay"),"exact capture intent")
    need(intent["schema"]=="hepta.phone-local.operator-intent.v150.1"and intent["label"]==identity_row["label"]
         and intent["request_sha256"]==pin(request_raw)["sha256"]and intent["request"]==expected["request"]
         and intent["automatic_replay"]is False,"one original capture request, no replay")
    stamp=datetime.datetime.fromisoformat(intent["utc"])
    need(stamp.tzinfo is not None,"original actor timezone")
    need(authority["created_unix_ms"]<=int(stamp.timestamp()*1000)<=authority["terminal_unix_ms"],"capture intent process lifetime")
    need(type(baseline.get("rc"))is int and baseline["rc"]==0 and baseline.get("stderr")==""
         and baseline["stdout"].splitlines()==[R.BOOT,R.FINGERPRINT,"adb","Enforcing","3021"],
         "original capture baseline")
    need(result.get("schema")=="hepta.phone-local.operator-result.v150.1"
         and result.get("label")==intent["label"]and result.get("status")=="command_exited"
         and result.get("model_decision")is False and result.get("native_task_result")is False
         and pin(result_raw)["sha256"]==cli["sha256"],"capture result complete original binding")
    elapsed=result.get("elapsed_seconds")
    need(type(elapsed)in(int,float)and math.isfinite(elapsed)and elapsed>=0 and cli["elapsed_seconds"]==elapsed,
         "finite original capture elapsed")
    phone=result.get("phone")
    need(type(phone)is dict and type(phone.get("rc"))is int and phone["rc"]==0
         and phone.get("command")==expected["wrapped_command"]and phone.get("route")==baseline.get("route"),
         "actual original capture phone zero and exact command")
    need(type(phone.get("stdout"))is str and type(phone.get("stderr"))is str,"complete original capture streams")
    stdout,stderr=phone["stdout"].encode(),phone["stderr"].encode()
    need(len(stdout)<=C.MAX_RECORD and len(stdout)+len(stderr)<=8*1024*1024 and stderr==b"",
         "bounded capture response, unchanged shell limit and empty stderr")
    need(pool.read(records["phone_stdout"],C.MAX_RECORD)==stdout
         and pool.read(records["phone_stderr"],8192)==stderr,"complete retained capture phone streams")
    return stdout,authority

def verify_retention_inputs(inputs_raw,*,read_pinned):
    need(FROZEN_PHASE_AUTHORITY is not None and FROZEN_RETENTION_INPUTS is not None,
         "UNBOUND_INSTALL_RETENTION_ORIGINALS_NO_IO")
    R,C,rraw,craw=source_context(read_pinned)
    R.descriptor(FROZEN_RETENTION_INPUTS,4*1024*1024,metadata=False)
    need(type(inputs_raw)is bytes and pin(inputs_raw)=={k:FROZEN_RETENTION_INPUTS[k]for k in("bytes","sha256")},
         "exact frozen retention originals")
    value=R.exact(R.strict(inputs_raw),("schema","phase_authority","scope","operations","original_map"),
                  "exact retention originals input")
    need(value["schema"]==INPUT_SCHEMA and value["phase_authority"]==FROZEN_PHASE_AUTHORITY,"same actual phase authority")
    pool=R.Originals(value["original_map"],read_pinned)
    need(pool.read(INSTALL_READER,262144)==rraw and pool.read(PRODUCER,65536)==craw,"capture reader and source originals")
    authority_raw=pool.read(value["phase_authority"],4*1024*1024)
    scope_raw,context=_derive_authority(authority_raw,read_pinned)
    need(pool.read(value["scope"],C.MAX_SCOPE)==scope_raw,"scope derived from complete actual BUILD/phase originals")
    operations=value["operations"]
    need(type(operations)is list and 4<=len(operations)<=36,"bounded complete phase capture operations")
    plan=context["plan"];P=context["P"]
    consumed={key:{v[key]for v in plan["phases"].values()}for key in("label","request_path","idempotency_key")}
    prior_terminal=context["last_phase"]["authority"]["terminal_unix_ms"];job_ids=set();raws=[]
    def check_one(number,op_raw):
        nonlocal prior_terminal
        row=R.exact(operations[number],("identity","originals"),"capture identity and original records")
        selected=lease(C,P,row["identity"])
        for key in consumed:
            need(selected[key]not in consumed[key],"capture identity not reused or shared with install phase")
            consumed[key].add(selected[key])
        expected=expected_operation(C,P,craw,scope_raw,op_raw,selected,plan)
        raw,observed=verify_capture_actor(R,C,row["originals"],expected,selected,plan,pool)
        need(prior_terminal<=observed["created_unix_ms"]and observed["job_id"]not in job_ids,
             "original capture complete before next, distinct jobs")
        prior_terminal=observed["terminal_unix_ms"];job_ids.add(observed["job_id"])
        return raw
    first=check_one(0,C.manifest_operation());manifest=C.validate_manifest(scope_raw,first)
    expected_chunks=C.chunk_operations(scope_raw,first)
    need(len(operations)==len(expected_chunks)+2,"all chunk operations and final manifest")
    for number,op_raw in enumerate(expected_chunks,1):raws.append(check_one(number,op_raw))
    last=check_one(len(operations)-1,C.manifest_operation())
    bodies=C.reassemble(scope_raw,first,raws,last);pool.recheck()
    return dict(scope=C.decode_scope(scope_raw),scope_pin=pin(scope_raw),files=manifest["files"],bodies=bodies,
                original_operation_count=len(operations),all_originals_bookended=True,
                actual_install_or_READY_qualified=False)

def _save_verified(value,output):
    """Publish only into the same newly created host directory, through its held FD."""
    need(isinstance(output,Path) and output.is_absolute(),"absolute new retained host directory")
    output.mkdir(mode=0o700)
    created=output.lstat()
    directory=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    rows=[];published=set()
    fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
    def meta(info):return [getattr(info,k)for k in fields]
    def check_directory():
        observed=os.fstat(directory);path_info=output.lstat()
        need(stat.S_ISDIR(path_info.st_mode)and stat.S_IMODE(path_info.st_mode)==0o700
             and meta(observed)[:5]==meta(path_info)[:5]==meta(created)[:5],
             "same newly created retained directory identity")
        need(set(os.listdir(directory))==published,"only selected retained files in owned directory")
    try:
        check_directory()
        for original in value["files"]:
            name=PurePosixPath(original["path"]).name;path=output/name;raw=value["bodies"][original["role"]]
            need(pin(raw)=={k:original[k]for k in("bytes","sha256")},"full original before publication")
            check_directory()
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,"wb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
            published.add(name);check_directory()
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            try:
                before=os.fstat(fd);observed=meta(before)
                need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600,
                     "private retained host file")
                with os.fdopen(fd,"rb",closefd=False)as f:again=f.read(len(raw)+1)
                need(again==raw and observed==meta(os.fstat(fd))
                     and observed==meta(os.stat(name,dir_fd=directory,follow_symlinks=False)),
                     "retained original complete bytes/full9 bookends")
            finally:os.close(fd)
            check_directory()
            rows.append(dict(namespace="phone_gnu",original={k:original[k]for k in("path","bytes","sha256","metadata")},
                             retained=dict(path=str(path),**pin(raw),metadata=observed)))
        result=dict(schema="hepta.install-original-retention.retained.v1",state="COMPLETE_INSTALLATION_ORIGINAL_BYTES_RETAINED",
                    scope=value["scope_pin"],installation_generation=value["scope"]["installation_generation"],original_map=rows,
                    original_operation_count=value["original_operation_count"],actual_install_or_READY_qualified=False)
        check_directory()
        fd=os.open("RETENTION-RESULT.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(fd,"wb")as f:f.write(canonical(result));f.flush();os.fsync(f.fileno())
        published.add("RETENTION-RESULT.json");os.fsync(directory);check_directory()
        return result
    finally:os.close(directory)

def retain_installation_originals(inputs_raw,output,*,read_pinned):
    value=verify_retention_inputs(inputs_raw,read_pinned=read_pinned)
    return _save_verified(value,output)
