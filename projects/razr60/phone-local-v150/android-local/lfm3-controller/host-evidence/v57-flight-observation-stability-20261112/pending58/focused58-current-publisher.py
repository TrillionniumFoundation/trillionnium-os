import base64,gzip,hashlib,json,os,secrets,stat,sys
BASE="/home/alex/hepta-local-007f-20261111"
PINS=[{"path":"/home/alex/hepta-local-007f-20261111/v58-main-wire4-host-p4-r1.py","bytes":79802,"sha256":"a7b9a549983ff21f6c62b47ebb60d6c172c22d42d2d092ede5d726996546b2a7"}]
ARGV_BYTES=34068
ARGV_SHA="1b0b903f2beea63fec733c0263d45156d1897579cfaa5e95aa7dd189fdd04f5e"
GZIP_BYTES=25551
GZIP_SHA="ce320bf68dd68804cbdf6e44465a3ec306fbf6068aae7377cb872b329407a3dc"
LOADER="import hashlib,os,pathlib,stat,sys\np=pathlib.Path(\"/home/alex/hepta-local-007f-20261111/v58-main-wire4-host-p4-r1.py\")\nassert all(not q.is_symlink() for q in (p,*p.parents))\nfd=os.open(str(p),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)\ndef identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)\ntry:\n a=os.fstat(fd)\n assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==79802\n with os.fdopen(os.dup(fd),\"rb\") as f:raw=f.read(79802+1)\n assert len(raw)==79802 and hashlib.sha256(raw).hexdigest()==\"a7b9a549983ff21f6c62b47ebb60d6c172c22d42d2d092ede5d726996546b2a7\"\n assert identity(a)==identity(os.fstat(fd))==identity(os.lstat(p))\nfinally:os.close(fd)\nsys.argv=[str(p)]\nexec(compile(raw,str(p),\"exec\",dont_inherit=True),{\"__name__\":\"__main__\",\"__file__\":str(p),\"__stage_source__\":raw})\n"
LOADER_SHA="66271c66c21afdf69165db024f54e5d88df3d195adfc073a3be73040e1b35858"
SUPERVISOR="import hashlib,json,os,signal,subprocess,sys,time\nloader=sys.argv[1]\nassert len(loader.encode(\"utf-8\"))==866 and hashlib.sha256(loader.encode(\"utf-8\")).hexdigest()==\"66271c66c21afdf69165db024f54e5d88df3d195adfc073a3be73040e1b35858\"\nassert os.getcwd()==\"/home/alex/hepta-local-007f-20261111\"\nstarted=time.monotonic()\np=subprocess.Popen([\"/usr/bin/python3\",\"-I\",\"-B\",\"-c\",loader],stdin=subprocess.DEVNULL,start_new_session=True)\nprint(json.dumps({\"schema\":\"hepta.main58-focused39-pty-bounded-launch.v1\",\"event\":\"started\",\"child_pid\":p.pid,\"timeout_seconds\":1200,\"loader_sha256\":hashlib.sha256(loader.encode()).hexdigest()}),flush=True)\ncode=None;timed_out=False;forced=False;error=None\ntry:\n    code=p.wait(timeout=1200)\nexcept BaseException as failure:\n    timed_out=isinstance(failure,subprocess.TimeoutExpired)\n    error=type(failure).__name__+\": \"+str(failure)\n    if p.poll() is None:\n        try:os.killpg(p.pid,signal.SIGTERM)\n        except ProcessLookupError:pass\n        try:code=p.wait(timeout=10)\n        except subprocess.TimeoutExpired:\n            forced=True\n            try:os.killpg(p.pid,signal.SIGKILL)\n            except ProcessLookupError:pass\n            try:code=p.wait(timeout=10)\n            except subprocess.TimeoutExpired:error+=\"; owned child exit not observed\"\nexit_observed=p.poll() is not None\nprint(json.dumps({\"schema\":\"hepta.main58-focused39-pty-bounded-launch.v1\",\"event\":\"finished\",\"child_pid\":p.pid,\"child_returncode\":code,\"exit_observed\":exit_observed,\"timed_out\":timed_out,\"forced_kill\":forced,\"error\":error,\"elapsed_seconds\":time.monotonic()-started}),flush=True)\nif error is not None or timed_out or forced or not exit_observed or type(code) is not int:raise SystemExit(124 if timed_out else 125)\nraise SystemExit(code if code>=0 else 128-code)\n"
SUPERVISOR_SHA="07f6c922a93c877c470aeb544afa998879bd768c8c9189057e116052a961ed22"
TRANSPORT_KEY="007f-v58-main-wire4-host-p4-r1"
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
need(len(sys.argv)==2,"one complete compressed source argument")
argument=sys.argv[1].encode("ascii","strict")
need(len(argument)==ARGV_BYTES and sha(argument)==ARGV_SHA and ARGV_BYTES<=1<<20,
     "exact bounded source argument")
packed=base64.b64decode(argument,validate=True)
need(base64.b64encode(packed)==argument and len(packed)==GZIP_BYTES and sha(packed)==GZIP_SHA,
     "canonical full compressed source identity")
need(len(PINS)==1 and 0<PINS[0]["bytes"]<=1<<20,"one fixed bounded source destination")
data=gzip.decompress(packed)
need(len(data)==PINS[0]["bytes"] and sha(data)==PINS[0]["sha256"],
     "full gzip CRC and complete source identity before any mutation")
need(os.path.dirname(PINS[0]["path"])==BASE
     and os.path.basename(PINS[0]["path"]) not in ("",".",".."),"fixed direct source child")
payloads=[data]
need(len(LOADER.encode("utf-8"))==866 and sha(LOADER.encode("utf-8"))==LOADER_SHA,
     "original loader bytes")
need(len(SUPERVISOR.encode("utf-8"))==1786
     and sha(SUPERVISOR.encode("utf-8"))==SUPERVISOR_SHA,"reviewed bounded supervisor bytes")
compile(data,PINS[0]["path"],"exec",dont_inherit=True)
compile(LOADER,"<original-core101-loader>","exec",dont_inherit=True)
compile(SUPERVISOR,"<reviewed-bounded-supervisor>","exec",dont_inherit=True)
need(os.getcwd()==BASE,"fixed working directory")
fds=[];chain=[];temps={};published=[]
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
    for component in BASE.strip("/").split("/"):
        parent=fd
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
        actual,_=read_exact(os.path.basename(pin["path"]),pin);need(actual==data,"fixed source exact before execution")
except BaseException as failure:
    print(json.dumps({"schema":"hepta.fixed-source-gzip-argv-transport-receipt.v1","transport_completed":False,"transport_key":TRANSPORT_KEY,"published":published,"error":type(failure).__name__+": "+str(failure),"coordinator_started":False},sort_keys=True),flush=True)
    raise
finally:
    try:
        for name in list(temps):remove_own_temp(name)
    finally:
        for fd in reversed(fds):os.close(fd)
print(json.dumps({"schema":"hepta.fixed-source-gzip-argv-transport-receipt.v1","transport_completed":True,"transport_key":TRANSPORT_KEY,"argv_bytes":ARGV_BYTES,"argv_sha256":ARGV_SHA,"gzip_bytes":GZIP_BYTES,"gzip_sha256":GZIP_SHA,"published":published,"original_loader_sha256":LOADER_SHA,"bounded_supervisor_sha256":SUPERVISOR_SHA,"coordinator_started":False,"next_action":"exec_reviewed_supervisor_then_original_loader"},sort_keys=True),flush=True)
os.execv("/usr/bin/python3",["/usr/bin/python3","-I","-B","-c",SUPERVISOR,LOADER])
