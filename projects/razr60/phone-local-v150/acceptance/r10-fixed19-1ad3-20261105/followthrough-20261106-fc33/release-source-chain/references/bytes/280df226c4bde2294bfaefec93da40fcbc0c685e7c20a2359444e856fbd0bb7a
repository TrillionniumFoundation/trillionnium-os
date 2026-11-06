"""Installation-only bounded original-byte capture. No installer or service runs here.
The public entry refuses before parsing or I/O until one actual scope is pinned.
Host fixture helpers do not confer phase, BUILD, installation or READY authority.
"""
import base64
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import select
import signal
import stat
import sys
import time

FROZEN_SCOPE = None
BOOT = "f8019f83-20a7-4f18-bea1-51c980621e4d"
ROOT = "/var/lib/trillionnium/owner-open/phone-local-v150/root-install-v150-r10-r1"
SCHEMA = "hepta.install-original-retention.scope.v1"
OP_SCHEMA = "hepta.install-original-retention.operation.v1"
MANIFEST_SCHEMA = "hepta.install-original-retention.manifest.v1"
CHUNK_SCHEMA = "hepta.install-original-retention.chunk.v1"
CHUNK_BYTES = 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_RECORD = 2 * 1024 * 1024
MAX_SCOPE = 32768
MAX_OPERATION = 32768
CAPTURE_SECONDS = 30
FILES = {"install_intent":"INSTALL-INTENT.json","staged":"STAGED.json",
         "preservation":"STAGED-PRESERVATION.original.json",
         "start_intent":"START-INTENT.json","started":"STARTED.json"}
ROLES = {"stage":("install_intent","staged","preservation"),
         "start":("start_intent","started")}
META = ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
HASH = re.compile("[0-9a-f]{64}")

def need(ok, message):
    if not ok: raise ValueError(message)

def exact(value, fields, message):
    need(type(value) is dict and set(value)==set(fields),message)
    return value

def pin(raw):
    need(type(raw) is bytes,"original bytes required")
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()

def strict(raw, maximum):
    need(type(raw)is bytes and 0<len(raw)<=maximum,"bounded complete JSON")
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,"duplicate JSON key");result[key]=value
        return result
    return json.loads(raw.decode("utf-8"),object_pairs_hook=pairs,
                      parse_constant=lambda _:(_ for _ in ()).throw(ValueError("nonfinite JSON")))

def pinned(value, maximum, positive=True):
    exact(value,("bytes","sha256"),"exact byte/hash pin")
    need(type(value["bytes"])is int and (0 if not positive else 1)<=value["bytes"]<=maximum
         and type(value["sha256"])is str and HASH.fullmatch(value["sha256"]),"typed bounded byte/hash pin")
    return value

def descriptor(value, maximum):
    exact(value,("path","bytes","sha256"),"exact original descriptor")
    p=PurePosixPath(value["path"])
    need(type(value["path"])is str and p.is_absolute() and str(p)==value["path"]
         and ".."not in p.parts and not any(c in value["path"]for c in "\0\r\n\t"),"canonical original path")
    pinned({k:value[k]for k in ("bytes","sha256")},maximum)
    return value

def identity(value, count):
    need(type(value)is list and len(value)==count and all(type(n)is int and n>0 for n in value),
         "positive exact identity tuple")
    return value

def metadata(value, size=None, directory=False, uid=0, gid=0):
    need(type(value)is list and len(value)==9 and all(type(n)is int and n>=0 for n in value),
         "typed full9 original")
    need(value[0]>0 and value[1]>0 and value[3:5]==[uid,gid] and value[5]>=1,"owned full9 identity")
    if directory:
        need(stat.S_ISDIR(value[2])and stat.S_IMODE(value[2])==0o700,"private original directory")
    else:
        need(stat.S_ISREG(value[2])and stat.S_IMODE(value[2])==0o600 and value[5]==1,
             "private single-link original file")
        need(size is None or value[6]==size,"full9 file size")
    return value

def validate_scope(value):
    exact(value,("schema","boot_id","release_id","phase","authority_inputs","release_inputs",
                 "execution_plan","actual_build_result_sha256","archive_sha256","release_manifest_sha256",
                 "retirement_sha256","component_boundary_inputs_sha256","policy_adoption_inputs_sha256",
                 "phase_result_sha256","phase_stdout_sha256","phase_source_identity",
                 "installation_generation","files"),"exact installation scope")
    need(value["schema"]==SCHEMA and value["boot_id"]==BOOT and value["release_id"]=="v150-r10-r1"
         and value["phase"]in ROLES,"installation-only scope")
    for key in ("authority_inputs","release_inputs","execution_plan"):
        descriptor(value[key],4*1024*1024 if key!="execution_plan"else 65536)
    for key in ("actual_build_result_sha256","archive_sha256","release_manifest_sha256","retirement_sha256",
                "component_boundary_inputs_sha256","policy_adoption_inputs_sha256",
                "phase_result_sha256","phase_stdout_sha256"):
        need(type(value[key])is str and HASH.fullmatch(value[key]),"actual phase/build digest")
    identity(value["phase_source_identity"],5)
    if value["phase"]=="stage":need(value["installation_generation"]is None,"stage has no new supervisor generation")
    else:
        generation=identity(value["installation_generation"],4)
        need(generation[:3]==[generation[0]]*3,"exact started supervisor group/session")
    rows=value["files"]
    need(type(rows)is list and len(rows)==len(ROLES[value["phase"]]),"exact phase file count")
    for role,row in zip(ROLES[value["phase"]],rows):
        exact(row,("role","path","bytes","sha256"),"exact installation file role")
        need(row["role"]==role and row["path"]==ROOT+"/"+FILES[role],"installation role/path allowlist")
        pinned({k:row[k]for k in ("bytes","sha256")},MAX_FILE if role=="preservation"else 65536)
    return value

def decode_scope(raw):
    value=validate_scope(strict(raw,MAX_SCOPE))
    need(canonical(value)==raw,"canonical scope and final LF")
    return value

def proc_identity(raw):
    need(type(raw)is bytes and 0<len(raw)<=4096,"bounded raw proc identity")
    left,sep,right=raw.rpartition(b") ");fields=right.split()
    need(sep and b" ("in left and len(fields)>=20,"complete original proc identity")
    return identity([int(left.split(b" ",1)[0]),int(fields[1]),int(fields[2]),int(fields[3]),int(fields[19])],5)

def validate_observer(value, scope):
    exact(value,("boot_id","before_identity","after_identity","before_proc_base64","after_proc_base64",
                 "started_monotonic_ns","ended_monotonic_ns","installation_generation"),"exact capture observer")
    if scope["phase"]=="stage":need(value["installation_generation"]is None,"manifest stage generation must be null")
    else:identity(value["installation_generation"],4)
    need(value["boot_id"]==BOOT and value["installation_generation"]==scope["installation_generation"],
         "same actual boot and installation generation")
    for key in ("before_identity","after_identity"):
        identity(value[key],5)
    need(value["before_identity"]==value["after_identity"],"same capture process generation")
    for side in ("before","after"):
        encoded=value[side+"_proc_base64"]
        need(type(encoded)is str and len(encoded)<=5500,"bounded proc encoding")
        raw=base64.b64decode(encoded,validate=True)
        need(base64.b64encode(raw).decode()==encoded and proc_identity(raw)==value[side+"_identity"],
             "original proc bytes and typed identity agree")
    a,b=value["started_monotonic_ns"],value["ended_monotonic_ns"]
    need(type(a)is int and type(b)is int and 0<=a<=b and b-a<=CAPTURE_SECONDS*1000000000,
         "bounded capture lifetime")
    return value

def validate_manifest(scope_raw, raw):
    scope=decode_scope(scope_raw);value=strict(raw,MAX_OPERATION)
    exact(value,("schema","scope","root_metadata","files","observer"),"exact installation capture manifest")
    need(value["schema"]==MANIFEST_SCHEMA and value["scope"]==pin(scope_raw)
         and canonical(value)==raw,"canonical manifest belongs to scope")
    pinned(value["scope"],MAX_SCOPE);metadata(value["root_metadata"],directory=True)
    need(type(value["files"])is list and len(value["files"])==len(scope["files"]),"manifest file count")
    for expected,row in zip(scope["files"],value["files"]):
        exact(row,("role","path","bytes","sha256","metadata"),"exact captured file descriptor")
        pinned({k:row[k]for k in ("bytes","sha256")},MAX_FILE if row["role"]=="preservation"else 65536)
        need({k:row[k]for k in expected}==expected,"manifest file order and exact bytes")
        metadata(row["metadata"],row["bytes"])
    validate_observer(value["observer"],scope)
    return value

def manifest_operation():
    return canonical({"schema":OP_SCHEMA,"mode":"manifest"})

def chunk_operations(scope_raw, manifest_raw):
    value=validate_manifest(scope_raw,manifest_raw)
    return [canonical({"schema":OP_SCHEMA,"mode":"chunk","manifest_base64":base64.b64encode(manifest_raw).decode(),
                       "role":row["role"],"index":index})
            for row in value["files"]for index in range((row["bytes"]+CHUNK_BYTES-1)//CHUNK_BYTES)]

def operation(scope_raw, raw):
    value=strict(raw,MAX_OPERATION)
    need(canonical(value)==raw,"canonical operation and final LF")
    need(type(value)is dict and value.get("schema")==OP_SCHEMA,"capture operation schema")
    if value.get("mode")=="manifest":
        exact(value,("schema","mode"),"manifest has no arbitrary targets")
        return value,None,None
    exact(value,("schema","mode","manifest_base64","role","index"),"exact chunk operation")
    need(value["mode"]=="chunk"and type(value["manifest_base64"])is str
         and len(value["manifest_base64"])<=24000,"bounded original manifest encoding")
    raw_manifest=base64.b64decode(value["manifest_base64"],validate=True)
    need(base64.b64encode(raw_manifest).decode()==value["manifest_base64"],"canonical manifest base64")
    manifest=validate_manifest(scope_raw,raw_manifest)
    selected=[row for row in manifest["files"]if row["role"]==value["role"]]
    need(len(selected)==1 and type(value["index"])is int
         and 0<=value["index"]<(selected[0]["bytes"]+CHUNK_BYTES-1)//CHUNK_BYTES,"exact role and bounded chunk index")
    return value,manifest,selected[0]

def full9(info):return [getattr(info,key)for key in META]

class LocalOriginals:
    """Read-only opened-directory interface. Only private tests may override root/uid/gid."""
    def __init__(self, root=ROOT, uid=0, gid=0):
        self.root=root;self.uid=uid;self.gid=gid;self.fd=None;self.root_metadata=None
    def open_root(self):
        parts=PurePosixPath(self.root).parts
        need(parts and parts[0]=="/"and ".."not in parts,"absolute original directory")
        fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            for part in parts[1:]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                os.close(fd);fd=child
            return fd
        except BaseException:
            os.close(fd);raise
    def __enter__(self):
        self.fd=self.open_root()
        try:
            self.root_metadata=metadata(full9(os.fstat(self.fd)),directory=True,uid=self.uid,gid=self.gid)
            return self
        except BaseException:
            os.close(self.fd);self.fd=None;raise
    def check_root(self, expected=None):
        current=full9(os.fstat(self.fd));again=self.open_root()
        try:need(full9(os.fstat(again))==current==self.root_metadata,"same original directory full9")
        finally:os.close(again)
        need(expected is None or current==expected,"manifest original directory changed")
        return current
    def scan(self,row,expected_metadata=None,index=None):
        role=row["role"];name=FILES[role]
        need(row["path"]==ROOT+"/"+name,"closed file role/path")
        self.check_root()
        first=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        metadata(full9(first),row["bytes"],uid=self.uid,gid=self.gid)
        need(expected_metadata is None or full9(first)==expected_metadata,"original full9 differs from manifest")
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
        try:
            need(full9(os.fstat(fd))==full9(first),"same original file descriptor")
            digest=hashlib.sha256();size=0;selected=bytearray()
            offset=None if index is None else index*CHUNK_BYTES
            while True:
                piece=os.read(fd,min(65536,row["bytes"]+1-size))
                if not piece:break
                previous=size;size+=len(piece)
                need(size<=row["bytes"],"original grew past bound")
                digest.update(piece)
                if offset is not None:
                    left=max(previous,offset);right=min(size,offset+CHUNK_BYTES)
                    if right>left:selected.extend(piece[left-previous:right-previous])
            need(size==row["bytes"]and digest.hexdigest()==row["sha256"],"complete original bytes and SHA256")
            after=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            need(full9(first)==full9(os.fstat(fd))==full9(after),"original full9 FD/path bookends")
            self.check_root()
            if index is not None:need(len(selected)==min(CHUNK_BYTES,row["bytes"]-offset),"complete selected slice")
            return full9(first),bytes(selected)
        finally:os.close(fd)
    def __exit__(self,*unused):
        if self.fd is not None:os.close(self.fd);self.fd=None

class ProcessObserver:
    def __init__(self,scope):self.scope=scope
    def observe(self):
        with open("/proc/sys/kernel/random/boot_id","rb")as f:boot=f.read(128)
        need(boot==BOOT.encode()+b"\n","exact current boot")
        with open("/proc/self/stat","rb")as f:raw=f.read(4097)
        ident=proc_identity(raw)
        need(ident[:4]==[os.getpid(),os.getppid(),os.getpgrp(),os.getsid(0)],"same original capture process")
        return ident,raw
    def start(self):
        self.started=time.monotonic_ns();self.before,self.raw_before=self.observe()
    def finish(self):
        after,raw_after=self.observe()
        value=dict(boot_id=BOOT,before_identity=self.before,after_identity=after,
                   before_proc_base64=base64.b64encode(self.raw_before).decode(),
                   after_proc_base64=base64.b64encode(raw_after).decode(),
                   started_monotonic_ns=self.started,ended_monotonic_ns=time.monotonic_ns(),
                   installation_generation=self.scope["installation_generation"])
        return validate_observer(value,self.scope)

def capture(scope_raw,op_raw,files,observer):
    """Internal read-only engine. Public authority is run_bound or the host binding reader."""
    scope=decode_scope(scope_raw);op,manifest,row=operation(scope_raw,op_raw)
    observer.start()
    if manifest is None:
        rows=[]
        for selected in scope["files"]:
            meta,unused=files.scan(selected)
            rows.append(dict(selected,metadata=meta))
        result=dict(schema=MANIFEST_SCHEMA,scope=pin(scope_raw),root_metadata=files.check_root(),files=rows)
    else:
        root=files.check_root(manifest["root_metadata"])
        meta,body=files.scan(row,row["metadata"],op["index"])
        files.check_root(manifest["root_metadata"])
        offset=op["index"]*CHUNK_BYTES
        result=dict(schema=CHUNK_SCHEMA,scope=pin(scope_raw),manifest=pin(base64.b64decode(op["manifest_base64"])),
                    root_metadata=root,file=row,index=op["index"],offset=offset,
                    chunk=pin(body),data_base64=base64.b64encode(body).decode(),
                    eof=offset+len(body)==row["bytes"])
    result["observer"]=observer.finish();raw=canonical(result)
    need(len(raw)<=MAX_RECORD,"bounded per-operation output")
    return raw

def validate_chunk(scope_raw,manifest_raw,op_raw,raw):
    scope=decode_scope(scope_raw);op,manifest,row=operation(scope_raw,op_raw)
    need(op["mode"]=="chunk"and pin(manifest_raw)==pin(base64.b64decode(op["manifest_base64"])),"selected chunk manifest")
    result=strict(raw,MAX_RECORD)
    exact(result,("schema","scope","manifest","root_metadata","file","index","offset","chunk",
                  "data_base64","eof","observer"),"exact retained chunk")
    need(canonical(result)==raw and result["schema"]==CHUNK_SCHEMA,"canonical chunk and final LF")
    pinned(result["scope"],MAX_SCOPE);pinned(result["manifest"],MAX_OPERATION)
    need(result["scope"]==pin(scope_raw)and result["manifest"]==pin(manifest_raw),"scope/manifest chunk linkage")
    need(result["root_metadata"]==manifest["root_metadata"]and result["file"]==row,"chunk original file identity")
    metadata(result["root_metadata"],directory=True);metadata(result["file"]["metadata"],row["bytes"])
    pinned({k:result["file"][k]for k in ("bytes","sha256")},MAX_FILE if row["role"]=="preservation"else 65536)
    need(type(result["index"])is int and result["index"]==op["index"]
         and type(result["offset"])is int and result["offset"]==op["index"]*CHUNK_BYTES,"typed exact sequence/offset")
    need(type(result["data_base64"])is str and len(result["data_base64"])<=4*((CHUNK_BYTES+2)//3),"bounded original chunk encoding")
    body=base64.b64decode(result["data_base64"],validate=True)
    pinned(result["chunk"],CHUNK_BYTES)
    need(base64.b64encode(body).decode()==result["data_base64"]and pin(body)==result["chunk"]
         and len(body)==min(CHUNK_BYTES,row["bytes"]-result["offset"]),"complete canonical chunk bytes")
    need(type(result["eof"])is bool and result["eof"]is(result["offset"]+len(body)==row["bytes"]),"exact final slice marker")
    validate_observer(result["observer"],scope)
    return row["role"],body

def reassemble(scope_raw,first_raw,chunks,last_raw):
    first=validate_manifest(scope_raw,first_raw);last=validate_manifest(scope_raw,last_raw)
    need(first["files"]==last["files"]and first["root_metadata"]==last["root_metadata"],
         "all original byte/full9 manifest bookends")
    operations=chunk_operations(scope_raw,first_raw)
    need(type(chunks)is list and len(chunks)==len(operations),"all and only complete chunk operations")
    output={row["role"]:bytearray()for row in first["files"]}
    for op,raw in zip(operations,chunks):
        role,body=validate_chunk(scope_raw,first_raw,op,raw);output[role].extend(body)
    for row in first["files"]:
        need(pin(bytes(output[row["role"]]))=={k:row[k]for k in ("bytes","sha256")},"reconstructed full original pin")
    return {key:bytes(raw)for key,raw in output.items()}

def bind_source(scope_raw,template_raw):
    decode_scope(scope_raw)
    need(type(template_raw)is bytes and 0<len(template_raw)<=65536,"bounded complete producer source")
    needle=b"FROZEN_SCOPE = None"+bytes([10])
    need(template_raw.count(needle)==1,"one source binding slot")
    replacement=("FROZEN_SCOPE = "+repr(pin(scope_raw))+"\n").encode()
    bound=template_raw.replace(needle,replacement,1)
    need(bound.replace(replacement,needle,1)==template_raw,"exact source binding inverse")
    compile(bound,"<bound-install-retention-producer>","exec")
    return bound

def write_response(raw,deadline):
    need(type(raw)is bytes and len(raw)<=MAX_RECORD,"bounded exact response")
    prior=os.get_blocking(1);os.set_blocking(1,False)
    try:
        offset=0
        while offset<len(raw):
            remain=deadline-time.monotonic();need(remain>0,"capture output deadline")
            unused,writable,exception=select.select([],[1],[1],remain)
            need(writable and not exception,"capture output ready")
            try:count=os.write(1,raw[offset:])
            except(InterruptedError,BlockingIOError):continue
            need(count>0,"capture output write");offset+=count
    finally:os.set_blocking(1,prior)

def run_bound(scope_raw,op_raw):
    need(FROZEN_SCOPE is not None,"UNBOUND_INSTALL_RETENTION_SCOPE_NO_IO")
    pinned(FROZEN_SCOPE,MAX_SCOPE)
    need(pin(scope_raw)==FROZEN_SCOPE,"exact frozen scope bytes")
    scope=decode_scope(scope_raw);operation(scope_raw,op_raw)
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,"root read-only producer")
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),"preserve original timer")
    prior=signal.getsignal(signal.SIGALRM)
    def expired(*unused):raise TimeoutError("bounded installation original capture")
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,CAPTURE_SECONDS)
    deadline=time.monotonic()+CAPTURE_SECONDS
    try:
        with LocalOriginals()as files:
            raw=capture(scope_raw,op_raw,files,ProcessObserver(scope))
        write_response(raw,deadline)
    finally:
        try:signal.setitimer(signal.ITIMER_REAL,0)
        finally:signal.signal(signal.SIGALRM,prior)
