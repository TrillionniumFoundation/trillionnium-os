import hashlib,json,os,signal,subprocess,sys,time
loader=sys.argv[1]
assert len(loader.encode("utf-8"))==866 and hashlib.sha256(loader.encode("utf-8")).hexdigest()=="66271c66c21afdf69165db024f54e5d88df3d195adfc073a3be73040e1b35858"
assert os.getcwd()=="/home/alex/hepta-local-007f-20261111"
started=time.monotonic()
p=subprocess.Popen(["/usr/bin/python3","-I","-B","-c",loader],stdin=subprocess.DEVNULL,start_new_session=True)
print(json.dumps({"schema":"hepta.main58-focused39-pty-bounded-launch.v1","event":"started","child_pid":p.pid,"timeout_seconds":1200,"loader_sha256":hashlib.sha256(loader.encode()).hexdigest()}),flush=True)
code=None;timed_out=False;forced=False;error=None
try:
    code=p.wait(timeout=1200)
except BaseException as failure:
    timed_out=isinstance(failure,subprocess.TimeoutExpired)
    error=type(failure).__name__+": "+str(failure)
    if p.poll() is None:
        try:os.killpg(p.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:code=p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            forced=True
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:code=p.wait(timeout=10)
            except subprocess.TimeoutExpired:error+="; owned child exit not observed"
exit_observed=p.poll() is not None
print(json.dumps({"schema":"hepta.main58-focused39-pty-bounded-launch.v1","event":"finished","child_pid":p.pid,"child_returncode":code,"exit_observed":exit_observed,"timed_out":timed_out,"forced_kill":forced,"error":error,"elapsed_seconds":time.monotonic()-started}),flush=True)
if error is not None or timed_out or forced or not exit_observed or type(code) is not int:raise SystemExit(124 if timed_out else 125)
raise SystemExit(code if code>=0 else 128-code)
