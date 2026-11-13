import base64,gzip,hashlib,json,os,secrets,stat,sys
TASK_BASE="/home/alex/hepta-local-007f-20261111"
BASE=TASK_BASE+"/background-web-adapters-v58-r1"
PINS=[{"path":"/home/alex/hepta-local-007f-20261111/background-web-adapters-v58-r1/web_entry_support.py","bytes":70091,"sha256":"ffc943520d277e4235f9e07eb6469881e7f0554878e675834318a6d3c86560e1"},{"path":"/home/alex/hepta-local-007f-20261111/background-web-adapters-v58-r1/prepare_background_web_v58_r1.py","bytes":27543,"sha256":"cee95e2e0601ae14c42776398bd648aa88176bc42679e3546447e71529827d12"},{"path":"/home/alex/hepta-local-007f-20261111/background-web-adapters-v58-r1/run_background_web_v58_r1.py","bytes":34153,"sha256":"c8017b1971ab28e22df151bd9c4c4f829958416d78c10348b458d0aec82795da"}]
PAYLOAD_BYTES=131787
PAYLOAD_SHA="3823db773a29f7433b22caf7748e67201278d0b4b15e0c0be3d34523e58ff202"
ARGV_BYTES=52588
ARGV_SHA="4fd86807c6dde87cc88f4347435815c036a141614898a2430a6ac33e68f63a6c"
GZIP_BYTES=39439
GZIP_SHA="13154507bd0f5ca759933cf991a58f5cf04fc1998f53feba3edcb7a21a3a9152"
TRANSPORT_KEY="007f-web58-runtime-three-source-publish-r1"
def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def file_id(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def dir_id(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
def pairs(items):
    result={}
    for key,value in items:
        need(key not in result,"duplicate stdin key");result[key]=value
    return result
def no_constant(value):raise ValueError("nonfinite stdin number")
need(len(PINS)==3 and [p["path"] for p in PINS]==[BASE+"/"+name for name in
     ("web_entry_support.py","prepare_background_web_v58_r1.py","run_background_web_v58_r1.py")]
     and all(type(p["bytes"]) is int and 0<p["bytes"]<=131072 for p in PINS)
     and type(PAYLOAD_BYTES) is int and PAYLOAD_BYTES==sum(p["bytes"] for p in PINS)<=393216,
     "three fixed actual runtime sources must be sealed")
need(type(ARGV_BYTES) is int and 0<ARGV_BYTES<=1<<20
     and type(GZIP_BYTES) is int and 0<GZIP_BYTES<=1<<20,
     "actual runtime transport lengths must be sealed")
for digest in [p["sha256"] for p in PINS]+[PAYLOAD_SHA,ARGV_SHA,GZIP_SHA]:
    need(type(digest) is str and len(digest)==64 and all(c in "0123456789abcdef" for c in digest),
         "actual runtime transport digests must be sealed")
need(len(sys.argv)==2,"one complete compressed source argument")
argument=sys.argv[1].encode("ascii","strict")
need(len(argument)==ARGV_BYTES and sha(argument)==ARGV_SHA and ARGV_BYTES<=1<<20,
     "exact bounded source argument")
packed=base64.b64decode(argument,validate=True)
need(base64.b64encode(packed)==argument and len(packed)==GZIP_BYTES and sha(packed)==GZIP_SHA,
     "canonical full compressed source identity")
data=gzip.decompress(packed)
need(len(data)==PAYLOAD_BYTES and sha(data)==PAYLOAD_SHA,
     "full gzip CRC and complete concatenated source identity before any mutation")
payloads=[];at=0
for pin in PINS:
    need(os.path.dirname(pin["path"])==BASE and os.path.basename(pin["path"]) not in ("",".",".."),
         "fixed direct runtime child")
    part=data[at:at+pin["bytes"]];at+=pin["bytes"]
    need(len(part)==pin["bytes"] and sha(part)==pin["sha256"],"individual complete runtime source identity")
    # Compile the same verified bytes for syntax only; do not import or execute them.
    compile(part,pin["path"],"exec",dont_inherit=True)
    payloads.append(part)
need(at==len(data) and len(payloads)==3,"exact three-source framing")
need(os.getcwd()==TASK_BASE,"fixed working directory")
fds=[];chain=[];temps={};published=[];directory_created_here=False
def directories():
    for parent,name,fd,before in chain:
        current=os.fstat(fd)
        need(stat.S_ISDIR(current.st_mode) and dir_id(current)==before,"opened directory identity")
        if parent is not None:
            named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            need(stat.S_ISDIR(named.st_mode) and dir_id(named)==before,"ordinary named directory identity")
def read_exact(name,pin):
    before=os.stat(name,dir_fd=bfd,follow_symlinks=False)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==pin["bytes"],"regular single-link exact-sized file")
    fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=bfd)
    try:
        need(file_id(os.fstat(fd))==file_id(before),"file replaced before open")
        chunks=[];total=0
        while total<=pin["bytes"]:
            chunk=os.read(fd,min(65536,pin["bytes"]+1-total))
            if not chunk:break
            chunks.append(chunk);total+=len(chunk)
        data=b"".join(chunks)
        need(len(data)==pin["bytes"] and sha(data)==pin["sha256"],"full readback bytes and digest")
        need(file_id(os.fstat(fd))==file_id(before)==file_id(os.stat(name,dir_fd=bfd,follow_symlinks=False)),"file stable across read")
        return data,{"path":pin["path"],"bytes":len(data),"sha256":sha(data),"identity":file_id(before)}
    finally:os.close(fd)
def remove_own_temp(name):
    identity=temps[name]
    try:current=os.stat(name,dir_fd=bfd,follow_symlinks=False)
    except FileNotFoundError:
        del temps[name];return
    need(stat.S_ISREG(current.st_mode) and (current.st_dev,current.st_ino)==identity,"only this process temporary inode may be removed")
    os.unlink(name,dir_fd=bfd);del temps[name]
try:
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    fds.append(fd);chain.append((None,None,fd,dir_id(os.fstat(fd))))
    components=BASE.strip("/").split("/")
    for index,component in enumerate(components):
        parent=fd
        try:
            fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
        except FileNotFoundError:
            need(index==len(components)-1 and component=="background-web-adapters-v58-r1",
                 "only the fixed final runtime directory may be created")
            directories()
            try:
                os.mkdir(component,0o700,dir_fd=parent);directory_created_here=True;os.fsync(parent)
            except FileExistsError:pass
            fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
        fds.append(fd);chain.append((parent,component,fd,dir_id(os.fstat(fd))))
    bfd=fd;directories()
    # Check the fixed destination before creating any temporary or final file.
    for pin,data in zip(PINS,payloads):
        name=os.path.basename(pin["path"])
        try:existing,_=read_exact(name,pin)
        except FileNotFoundError:continue
        need(existing==data,"existing destination must be identical")
    for i,(pin,data) in enumerate(zip(PINS,payloads)):
        directories();name=os.path.basename(pin["path"]);created=False
        try:existing,facts=read_exact(name,pin)
        except FileNotFoundError:
            tmp=".hepta-fixed-source-gzip-"+str(os.getpid())+"-"+secrets.token_hex(8)+"-"+str(i)+".tmp"
            tfd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=bfd)
            st=os.fstat(tfd);temps[tmp]=(st.st_dev,st.st_ino)
            try:
                need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,"new owned regular temporary")
                at=0
                while at<len(data):
                    count=os.write(tfd,data[at:]);need(count>0,"temporary write progress");at+=count
                os.fsync(tfd)
            finally:os.close(tfd)
            check,_=read_exact(tmp,pin);need(check==data,"full temporary readback")
            directories()
            try:
                os.link(tmp,name,src_dir_fd=bfd,dst_dir_fd=bfd,follow_symlinks=False)
                created=True
            except FileExistsError:
                existing,_=read_exact(name,pin);need(existing==data,"concurrent exact destination only")
            finally:remove_own_temp(tmp)
            os.fsync(bfd)
            existing,facts=read_exact(name,pin)
        need(existing==data,"published original bytes")
        published.append(dict(facts,created_here=created,reused_identical=not created))
    directories()
    for pin,data in zip(PINS,payloads):
        actual,_=read_exact(os.path.basename(pin["path"]),pin);need(actual==data,"fixed runtime sources exact at publication end")
except BaseException as failure:
    print(json.dumps({"schema":"hepta.fixed-source-gzip-argv-transport-receipt.v1","transport_completed":False,"transport_key":TRANSPORT_KEY,"published":published,"error":type(failure).__name__+": "+str(failure),"runtime_imported":False,"runtime_executed":False,"phone_contacted":False},sort_keys=True),flush=True)
    raise
finally:
    try:
        for name in list(temps):remove_own_temp(name)
    finally:
        for fd in reversed(fds):os.close(fd)
print(json.dumps({"schema":"hepta.fixed-source-gzip-argv-transport-receipt.v1","transport_completed":True,"transport_key":TRANSPORT_KEY,"argv_bytes":ARGV_BYTES,"argv_sha256":ARGV_SHA,"gzip_bytes":GZIP_BYTES,"gzip_sha256":GZIP_SHA,"payload_bytes":PAYLOAD_BYTES,"payload_sha256":PAYLOAD_SHA,"published":published,"source_count":3,"source_syntax_compiled":True,"directory_created_here":directory_created_here,"runtime_imported":False,"runtime_executed":False,"release_manifest_published":False,"prepare_wrapper_published":False,"host_tests_executed":False,"phone_contacted":False,"next_action":"await_actual_installations_and_root_sealed_release_and_prepare"},sort_keys=True),flush=True)
# Publication ends here. No runtime module, host test or phone action is executed.
