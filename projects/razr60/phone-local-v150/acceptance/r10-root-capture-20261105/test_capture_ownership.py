#!/usr/bin/env python3
"""Material real-child fault probes. No main/SSH/phone/network/signal calls."""
import errno,hashlib,json,os,subprocess,sys,threading,time,types
from pathlib import Path
ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'source/run_component_root_once.py'
BIND=json.loads((ROOT/'CANDIDATE-BINDING.json').read_text())
OUT=Path(os.environ.get('RAZR_CAPTURE_FAULT_OUTPUT',str(ROOT/'evidence'/('ownership-'+str(time.time_ns()))))).resolve()
OUT.mkdir(parents=True,exist_ok=False)

def fds():
    directory=next(p for p in ('/proc/self/fd','/dev/fd') if Path(p).is_dir())
    result=set()
    for item in os.listdir(directory):
        if not item.isdecimal():continue
        try:os.fstat(int(item))
        except OSError as e:
            if e.errno!=errno.EBADF:raise
        else:result.add(int(item))
    return result

def workers():return sorted(t.name for t in threading.enumerate() if t.name.startswith('hepta-host-capture-'))
def module():
    raw=SOURCE.read_bytes();assert hashlib.sha256(raw).hexdigest()==BIND['candidate_sha256']
    m=types.ModuleType('capture_ownership_source');m.__file__=str(SOURCE)
    exec(compile(raw,str(SOURCE),'exec'),m.__dict__);return m

results=[]
for fault in ('capture-construction','thread-start-failed','interrupt-before-thread-start','interrupt-after-thread-start','interrupt-child-wait','output-limit-plus-one'):
    m=module();folder=OUT/fault;folder.mkdir(mode=0o700);c=m.Chain.__new__(m.Chain);c.out=folder;c.steps=[]
    children=[];real_popen=subprocess.Popen
    def popen(argv,**kw):
        assert argv[:4]==[sys.executable,'-I','-B','-c'],'only bounded local test Python allowed'
        p=real_popen(argv,**kw);children.append(p);p.harness_wait=p.wait
        if fault=='interrupt-child-wait':
            def interrupted(*a,**kw):raise KeyboardInterrupt('controlled wait interruption')
            p.wait=interrupted
        return p
    m.subprocess=types.SimpleNamespace(Popen=popen,PIPE=subprocess.PIPE,DEVNULL=subprocess.DEVNULL,TimeoutExpired=subprocess.TimeoutExpired)
    class ControlledThread:
        def __init__(self,*a,**kw):self.actual=threading.Thread(*a,**kw)
        @property
        def ident(self):return self.actual.ident
        def is_alive(self):return self.actual.is_alive()
        def join(self,*a,**kw):return self.actual.join(*a,**kw)
        def start(self):
            if fault=='thread-start-failed':raise RuntimeError('injected OS thread creation failure')
            if fault=='interrupt-before-thread-start':raise KeyboardInterrupt('before OS thread start')
            self.actual.start()
            if fault=='interrupt-after-thread-start':raise KeyboardInterrupt('after OS thread start')
    def event():
        if fault=='capture-construction':raise OSError(errno.ENOMEM,'injected capture state allocation')
        return threading.Event()
    m.threading=types.SimpleNamespace(Event=event,Lock=threading.Lock,Thread=ControlledThread)
    before=fds();before_workers=workers();start=time.monotonic();error=None
    code='import time; time.sleep(.15)'
    if fault=='output-limit-plus-one':
        code="import os\nleft=64*1024*1024+1\nwhile left:\n b=b'x'*min(65536,left)\n n=os.write(1,b)\n left-=n"
    try:c.execute_process('phase',[sys.executable,'-I','-B','-c',code],5.0 if fault=='output-limit-plus-one' else 1.0)
    except BaseException as exc:error=exc
    elapsed=time.monotonic()-start
    assert error is not None and len(children)==1
    p=children[0]
    assert p.stdout.closed and p.stderr.closed,(fault,'pipe readers leaked')
    assert workers()==before_workers,(fault,'worker leaked',workers())
    assert fds()==before,(fault,'fd leaked',sorted(before),sorted(fds()))
    assert not (folder/'phase/RESULT.json').exists()
    unknown=json.loads((folder/'phase/UNKNOWN.json').read_text());assert unknown['pid']==p.pid and unknown['automatic_retry'] is False
    assert c._owned_host_children['phase'] is p
    cap=unknown['output_capture']
    if fault=='capture-construction':assert cap is None
    elif fault=='interrupt-before-thread-start':
        assert cap['pipe_reader_owner']=='closed_by_caller' and cap['worker_joined'] is False
    else:assert cap['worker_joined'] is True
    if fault=='output-limit-plus-one':
        assert cap['error']['code']=='OUTPUT_LIMIT_EXCEEDED' and cap['captured']['stdout']['bytes']==64*1024*1024
        assert (folder/'phase/stdout.original').stat().st_size==64*1024*1024
        assert cap['prefix_only_or_unknown'] is True
    rc=p.harness_wait(timeout=2)
    item={'case':fault,'pass':True,'elapsed_seconds':elapsed,'error_type':type(error).__name__,
        'pipe_readers_closed_at_return':True,'worker_inventory_equal_at_return':True,'fd_inventory_equal_at_return':True,
        'no_success_result':True,'retained_actual_child_handle':True,'unknown':unknown,
        'test_holder_natural_child_join_rc':rc,'signals_sent':0,'automatic_replay':False}
    results.append(item);(folder/'TEST-RESULT.json').write_text(json.dumps(item,indent=2)+'\n')
summary={'schema':'hepta.capture-ownership-real-process-tests.v1','source_sha256':BIND['candidate_sha256'],
    'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'passed':len(results),'failed':0,'cases':results,
    'phone_calls':0,'network_calls':0,'signals_sent':0,'all_local_test_children_naturally_joined':True}
(OUT/'TEST-RESULT.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({'passed':len(results),'failed':0,'result':str(OUT/'TEST-RESULT.json'),'source_sha256':BIND['candidate_sha256']},indent=2))
