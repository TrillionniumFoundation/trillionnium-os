#!/usr/bin/env python3
"""Linux-only real fork boundary for the production owned-generation helper."""
from pathlib import Path
import ctypes, hashlib, importlib.util, json, os, shutil, signal, subprocess, sys, threading, time, uuid

ENV=("HEPTA_WORKER_SCOPE_REQUIRED","HEPTA_WORKER_SCOPE_TASK","HEPTA_WORKER_SCOPE_GENERATION",
     "HEPTA_WORKER_SCOPE_TOKEN","HEPTA_WORKER_SCOPE_PARENT_START","HEPTA_WORKER_SCOPE_BOOT")
BUDGET=4_000_000_000
def digest(b): return hashlib.sha256(b).hexdigest()
def meta(p):
    b=p.read_bytes()
    return {"path":str(p),"bytes":len(b),"sha256":digest(b)}
def check(c,m):
    if not c: raise AssertionError(m)
def proc(pid):
    raw=Path(f"/proc/{pid}/stat").read_text(); at=raw.rfind(")")
    f=raw[at+2:].split()
    check(raw.split(" ",1)[0]==str(pid) and len(f)>=20,"proc identity")
    return {"pid":pid,"state":f[0],"ppid":int(f[1]),"pgid":int(f[2]),"start":int(f[19])}
def held(pid):
    fd=os.open(f"/proc/{pid}",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    b=os.open("stat",os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
    try: raw=os.read(b,8192).decode()
    finally: os.close(b)
    check(raw.split(" ",1)[0]==str(pid),"held proc pid")
    return fd
def exact_signal(pid,sig):
    fd=held(pid)
    try: signal.pidfd_send_signal(fd,sig,None,0)
    finally: os.close(fd)
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s)
    sys.modules[name]=m;s.loader.exec_module(m);return m

def compile_fixture(source,out,cc):
    native=source/"native"
    sys.path.insert(0,str(native))
    base=load("owned_generation_original_fixture",native/"tests/test_warm_runtime.py")
    gen=load("owned_generation_actual_generator",native/"generate_adapter.py")
    generated=out/"generated";generated.mkdir();gen.generate(source,generated)
    text=base.HARNESS.replace("TEST_MODEL_SHA",digest(base.WEIGHT)).replace("TEST_MODEL_BYTES",str(len(base.WEIGHT)))
    include='#include "warm-protocol.inc"'
    check(text.count(include)==1,"original include")
    text=text.replace(include,include+'\n#include "parent-death-guard.h"\n#include "owned-generation.inc"')
    main='int main(int argc,char **argv){'
    check(text.count(main)==1,"original main")
    text=text.replace(main,'int hepta_previous_fixture_main(int argc,char **argv){')
    text+=(source/"tests/owned-generation-cleanup/fixture-main.c").read_text()
    inc=["-I"+str(generated),"-I"+str(native),"-I"+str(native/"vendor"),"-I"+str(native/"vendor/llama")]
    cxx=shutil.which("c++");check(cxx is not None,"C++ compiler")
    rows=[]
    def command(argv,stem):
        p=subprocess.run(argv,capture_output=True,timeout=60)
        (out/(stem+".stdout")).write_bytes(p.stdout);(out/(stem+".stderr")).write_bytes(p.stderr)
        rows.append({"argv":argv,"exit_code":p.returncode,"stdout":meta(out/(stem+".stdout")),"stderr":meta(out/(stem+".stderr"))})
        check(p.returncode==0,p.stderr.decode())
    boundary=out/"boundary.o"
    command([cxx,"-std=c++11","-Wall","-Wextra","-Werror","-O1","-fexceptions",
             "-DHEPTA_SDK_EXCEPTION_BOUNDARY=1",*inc,"-c",str(native/"sdk-exception-boundary.cpp"),"-o",str(boundary)],"boundary")
    binaries={}
    for variant in ("normal","unsupported"):
        h=out/(variant+".c")
        code=text
        if variant=="unsupported":
            code=code.replace('#include "owned-generation.inc"','#undef SYS_pidfd_send_signal\n#include "owned-generation.inc"')
        h.write_text(code)
        obj=out/(variant+".o");binary=out/variant
        command([cc,"-std=c11","-Wall","-Wextra","-Werror","-O1","-fexceptions",
                 "-DHEPTA_SDK_EXCEPTION_BOUNDARY=1","-DHEPTA_OWNED_GENERATION_HOST_TRACE=1",*inc,"-c",str(h),"-o",str(obj)],variant+"-c")
        command([cxx,str(obj),str(boundary),"-o",str(binary)],variant+"-link")
        binaries[variant]=binary
    (out/"COMPILE.json").write_text(json.dumps(rows,indent=2)+"\n")
    return binaries

class Scope:
    def __init__(self,root,binary,mode):
        self.files=root/"files";self.files.mkdir(mode=0o700,parents=True)
        (self.files/"runs").mkdir(mode=0o700)
        self.gen=uuid.uuid4().hex;self.task=uuid.uuid4().hex;self.token=uuid.uuid4().hex
        self.directory=self.files/"runs"/self.gen;self.directory.mkdir(mode=0o700)
        self.expected={"task":self.task,"generation":self.gen,"token":self.token,"boot":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                       "uid":os.getuid(),"appPid":os.getpid(),"appStart":proc(os.getpid())["start"]}
        env=dict(os.environ)
        vals=("v1",self.task,self.gen,self.token,str(self.expected["appStart"]),self.expected["boot"])
        env.update(zip(ENV,vals))
        self.stdout=open(root/"worker.stdout","wb");self.stderr=open(root/"worker.stderr","wb")
        self.process=subprocess.Popen([str(binary),"--fixture-scope",str(self.files),self.gen,self.task,mode],
                                      env=env,stdin=subprocess.PIPE,stdout=self.stdout,stderr=self.stderr)
        self.child=None;self.reaper=None;self.child_wait=None
        self.mode=mode;self.root=root;self.binary=binary;self.direct=None
    def wait_identity(self):
        p=self.directory/"worker-generation.identity"
        end=time.monotonic()+3
        while not p.is_file() and self.process.poll() is None and time.monotonic()<end: time.sleep(.01)
        check(p.is_file(),"early identity missing")
        self.identity=p.read_bytes()
        return self.identity
    def wait_child(self):
        p=self.directory/"fixture-child.pid";end=time.monotonic()+3
        while not p.is_file() and self.process.poll() is None and time.monotonic()<end:time.sleep(.01)
        check(p.is_file(),"fixture fork missing")
        self.child=int(p.read_text());self.child_before=proc(self.child)
        return self.child
    def parent_exit(self,term=False):
        if term: exact_signal(self.process.pid,signal.SIGTERM)
        self.direct=self.process.wait(timeout=5)
        if self.child:
            def reap():
                try:self.child_wait=os.waitpid(self.child,0)
                except ChildProcessError as e:self.child_wait=str(e)
            self.reaper=threading.Thread(target=reap,daemon=True);self.reaper.start()
        return self.direct
    def cleanup(self,binary=None,override=None,budget=BUDGET):
        nonce=uuid.uuid4().hex;submitted=time.monotonic_ns();deadline=submitted+budget
        identity=(self.directory/"worker-generation.identity").read_bytes() if (self.directory/"worker-generation.identity").exists() else b""
        argv=[str(binary or self.binary),"--hepta-owned-generation-cleanup-v1",str(self.files),self.gen,self.task,
              self.token,str(self.expected["appPid"]),str(self.expected["appStart"]),self.expected["boot"],
              digest(identity),nonce,str(deadline)]
        if override:
            for i,value in override.items():argv[i]=str(value)
        env={k:v for k,v in os.environ.items() if k not in ENV}
        p=subprocess.Popen(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdout,stderr=p.communicate(timeout=6)
        self.root.joinpath("helper.stdout").write_bytes(stdout);self.root.joinpath("helper.stderr").write_bytes(stderr)
        path=self.directory/("generation-cleanup-"+nonce+".json")
        receipt=json.loads(path.read_bytes()) if path.is_file() else None
        result={"expected":self.expected,"identity":identity.decode(),"nonce":nonce,"submitted":submitted,"deadline":deadline,
                "helper_exit":p.returncode,"helper_pid":p.pid,"native":receipt,"direct_exit":self.direct,
                "child_pid":self.child,"receipt":meta(path) if path.is_file() else None,"argv":argv,
                "helper_stdout":meta(self.root/"helper.stdout"),"helper_stderr":meta(self.root/"helper.stderr")}
        self.root.joinpath("RESULT.json").write_text(json.dumps(result,indent=2)+"\n")
        return result
    def alive_child(self):
        if not self.child:return False
        try:return proc(self.child)["state"] not in ("Z","X")
        except FileNotFoundError:return False
    def close(self):
        if self.process.poll() is None:
            try:exact_signal(self.process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                exact_signal(self.process.pid,signal.SIGKILL);self.process.wait(timeout=3)
        if self.child and self.alive_child():
            try:exact_signal(self.child,signal.SIGTERM)
            except ProcessLookupError:pass
            end=time.monotonic()+.3
            while self.alive_child() and time.monotonic()<end:time.sleep(.01)
            if self.alive_child():
                try:exact_signal(self.child,signal.SIGKILL)
                except ProcessLookupError:pass
        if self.reaper:self.reaper.join(timeout=3)
        elif self.child:
            try:os.waitpid(self.child,0)
            except ChildProcessError:pass
        for f in (self.process.stdin,self.stdout,self.stderr):
            if f is not None and not f.closed:f.close()

def run(source,out,cc):
    check(sys.platform.startswith("linux"),"Linux /proc boundary required")
    check(os.getuid()>0,"run as ordinary host account, not root")
    check(hasattr(signal,"pidfd_send_signal"),"host pidfd_send_signal API unavailable")
    libc=ctypes.CDLL(None,use_errno=True)
    check(libc.prctl(36,1,0,0,0)==0,"fixture subreaper setup")
    binaries=compile_fixture(source,out,cc)
    results=[];checks=0
    def verify(c,m):
        nonlocal checks;checks+=1;check(c,m)
    def one(name,mode,expected_clean=True,term=False,variant="normal",override=None,expect_force=False,kind=None):
        d=out/name;d.mkdir();s=Scope(d,binaries["normal"],mode)
        try:
            if mode!="missing-identity":s.wait_identity()
            if mode.startswith("fork-"):
                s.wait_child()
                if mode in ("fork-exec","fork-wrong-token"):
                    end=time.monotonic()+2
                    while time.monotonic()<end:
                        try:
                            if Path(f"/proc/{s.child}/cmdline").read_bytes().startswith(b"sleep\0"):break
                        except FileNotFoundError:pass
                        time.sleep(.01)
                    verify(Path(f"/proc/{s.child}/cmdline").read_bytes().startswith(b"sleep\0"),"actual exec argv")
            direct=s.parent_exit(term)
            verify(direct==(-signal.SIGTERM if term else 70 if mode=="exit70" else 0),"real parent wait")
            if s.child:
                verify(s.alive_child(),"child remains after parent wait")
                probe=subprocess.run([str(binaries["normal"]),"--fixture-group-presence",
                    str(s.directory/"worker-generation.identity")],capture_output=True,timeout=3)
                verify(probe.returncode==0,"actual bound group existence query")
                group=json.loads(probe.stdout)
                (d/"group-present.json").write_bytes(probe.stdout)
                if mode in ("fork-escape","fork-escape-unreadable"):
                    verify(group["result"]==-1 and group["errno"]==3,"original group absent after explicit escape")
                else:
                    verify(group["result"]==0 and group["errno"]==0,"kernel sees live child group")
            call=override(s) if override else None
            r=s.cleanup(binary=binaries[variant],override=call,budget=BUDGET if expected_clean or variant=="unsupported" else 600_000_000)
            n=r["native"]
            if expected_clean:
                verify(r["helper_exit"]==0 and n is not None and n["cleanup_known"] is True,"actual generation cleanup")
                verify(n["remaining_owned_count"]==n["unknown_count"]==n["escaped_generation_count"]==0,"no unresolved member")
                verify(n["scan_complete"] and n["empty_readbacks"]>=2 and n["scans"]>=2,"two complete observations")
                probes=n["group_presence_observations"][-n["empty_readbacks"]:]
                verify(n["group_presence_probe_used"] and n["group_presence_probe_signal"]==0,"kernel query used")
                verify(len(probes)>=2 and all(p["result"]==-1 and p["errno"]==3 and p["pgid"]==n["pgid"] for p in probes),"kernel group ESRCH")
                verify(probes[-1]["monotonic_ns"]-probes[0]["monotonic_ns"]>=100_000_000,"two kernel absences separated")
                verify(n["numeric_pid_signal_used"] is False and n["group_signal_used"] is False,"no numeric/group fallback")
                verify(n["sdk_called"] is False and n["worker_started"] is False,"cleanup starts no SDK")
                verify(n["helper_pid"]!=n["leader_pid"] and n["helper_pgid"]!=n["pgid"],"helper outside worker group")
                verify(n["kill_attempts"]>0 if expect_force else n["kill_attempts"]==0,"force audit")
                if s.child:
                    s.reaper.join(timeout=2)
                    verify(not s.alive_child() and isinstance(s.child_wait,tuple),"actual descendant reaped")
                    verify(n["term_attempts"]==1 and len(n["targets"])==1,"single bound target")
            else:
                verify(r["helper_exit"]==78 and (n is None or n["cleanup_known"] is False),"refused cleanup proof")
                if n:verify(n["term_attempts"]==n["kill_attempts"]==0,"unknown sends no real signal")
                if s.child:verify(s.alive_child(),"rejected scope leaves child untouched")
            if kind=="unsupported":verify(n["pidfd_supported"] is False,"unsupported is explicit")
            r["case"]=name;r["expected_clean"]=expected_clean;r["checks_at_end"]=checks
            results.append(r)
        finally:s.close()
    one("empty_normal0","exit0")
    one("empty_status70","exit70")
    one("parent143_requires_absence","pause",term=True)
    one("fork_before_READY_parent0","fork-term")
    one("fork_before_READY_parent143","fork-live-parent",term=True)
    one("changed_argv_inherits_scope","fork-exec")
    one("descendant_KILL_is_force","fork-ignore",expect_force=True)
    one("unsupported_pidfd_zero_signal","fork-term",False,variant="unsupported",kind="unsupported")
    one("wrong_task_zero_signal","fork-term",False,override=lambda s:{4:"0"*32})
    one("wrong_hash_zero_signal","fork-term",False,override=lambda s:{9:"0"*64})
    one("wrong_token_zero_signal","fork-term",False,override=lambda s:{5:"0"*32})
    one("missing_early_identity","missing-identity",False)
    one("same_group_wrong_environment","fork-wrong-token",False)
    one("escaped_generation_refused","fork-escape",False)
    one("same_group_unreadable_refused","fork-unreadable",False)
    one("other_group_unreadable_refused","fork-escape-unreadable",False)
    # An unrelated same-UID worker has its own immutable token/group and survives.
    d=out/"unrelated_sibling_untouched";d.mkdir();sibling=Scope(d/"sibling",binaries["normal"],"pause")
    try:
        sibling.wait_identity();before=proc(sibling.process.pid)
        one("owned_child_with_unrelated_sibling","fork-term")
        verify(sibling.process.poll() is None and proc(sibling.process.pid)["start"]==before["start"],"unrelated sibling untouched")
        results[-1]["unrelated_sibling_identity"]=before
    finally:sibling.close()
    # A held proc FD never targets a later numeric-PID occupant. This executes
    # the ESRCH path after the exact original exits; forced kernel PID reuse is
    # not claimed by this host fixture.
    d=out/"stale_held_proc_fd";d.mkdir();s=Scope(d,binaries["normal"],"hold-exit")
    fd=None
    try:
        s.wait_identity();fd=held(s.process.pid);original=proc(s.process.pid)
        s.process.stdin.close();s.parent_exit()
        try:signal.pidfd_send_signal(fd,signal.SIGTERM,None,0);rejected=False
        except ProcessLookupError:rejected=True
        verify(rejected,"stale held FD must report ESRCH")
        results.append({"case":"stale_held_proc_fd_rejects","original_identity":original,
                        "actual_ESRCH":rejected,"forced_kernel_pid_reuse":False,"checks_at_end":checks})
    finally:
        if fd is not None:os.close(fd)
        s.close()
    summary={"schema":"hepta.owned-generation-native-host.v1","cases":len(results),"checks":checks,
             "records":results,"real_host_fork":True,"real_sdk_executed":False,"phone_tested":False,
             "containment_scope":"fixed UID and inherited group/environment; escaped sessions are refused, not proven absent"}
    (out/"NATIVE-CASES.json").write_text(json.dumps(summary,indent=2)+"\n")
    return summary
