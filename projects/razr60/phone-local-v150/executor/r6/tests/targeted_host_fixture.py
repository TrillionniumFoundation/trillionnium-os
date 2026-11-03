from pathlib import Path
import base64,hashlib,json,os,selectors,socket,struct,subprocess,sys,tarfile,time,uuid,shutil
BASE=Path('/operator-workspace/razr60/runtime/executor-v150-r6-candidate-hosttest03')
BASE.mkdir(parents=True,exist_ok=False)
A=Path('/operator-workspace/pocket4/razr60-phone-local-executor-v150-r6-candidate-hosttest.tar.gz')
assert hashlib.sha256(A.read_bytes()).hexdigest()=='78f3e1785646d4018aabb50182f3f6514d9256ffc64394f42ae7f9392c601084'
with tarfile.open(A,'r:gz') as tar:tar.extractall(BASE,filter='data')
for name in ('phone_tool_sidecar.cpp','phone_tool_worker.cpp'):
 shutil.copy2(Path('/operator-workspace/pocket4/executor-r6-candidate-source03')/name,BASE/name)
O=BASE/'host-checks-03';O.mkdir()
rows=[]
def stage(argv,label,timeout=120):
 t=time.monotonic();r=subprocess.run(argv,capture_output=True,timeout=timeout)
 (O/(label+'.stdout')).write_bytes(r.stdout);(O/(label+'.stderr')).write_bytes(r.stderr)
 rows.append({'name':label,'argv':argv,'rc':r.returncode,'seconds':round(time.monotonic()-t,6)})
 if r.returncode:raise RuntimeError(label+': '+r.stderr.decode('utf8','replace')[:2000])
stage(['/usr/bin/cc','-O1','-c',str(BASE/'vendor/hash/sha256/sha256.c'),'-I'+str(BASE/'vendor/hash'),'-o',str(O/'sha256.o')],'compile-sha')
stage(['/usr/bin/c++','-std=c++17','-O1','-pthread','-DHEPTA_TESTING','-I'+str(BASE/'vendor'),str(BASE/'phone_tool_sidecar.cpp'),str(BASE/'vendor/hash/hash.cpp'),str(O/'sha256.o'),'-o',str(O/'sidecar-fixture')],'compile-sidecar')
stage(['/usr/bin/c++','-std=c++17','-O1','-DHEPTA_TESTING',str(BASE/'phone_tool_worker.cpp'),'-o',str(O/'worker-fixture')],'compile-worker')
checks=[];servers=[]
BOOT='u:r:trillionnium_owner_open_bootstrap:s0';MAGISK='u:r:magisk:s0'
def check(name,condition,details=None):
 checks.append({'name':name,'passed':bool(condition),'details':details})
 if not condition:raise AssertionError(name+': '+repr(details))
def start(name,context=BOOT,state=None):
 state=state or O/('state-'+name)
 endpoint='hepta_r6_fixture_'+uuid.uuid4().hex[:20]
 log=(O/(name+'.server.stderr')).open('wb')
 argv=[str(O/'sidecar-fixture'),'--state-dir',str(state),'--socket-name',endpoint,'--fixture-uid',str(os.getuid()),'--fixture-worker',str(O/'worker-fixture'),'--fixture-peer-context',context]
 proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=log)
 sel=selectors.DefaultSelector();sel.register(proc.stdout,selectors.EVENT_READ)
 if not sel.select(5):raise RuntimeError('server readiness timeout')
 line=proc.stdout.readline();sel.close()
 if not line:raise RuntimeError('server failed before ready: '+str(proc.poll()))
 ready=json.loads(line);(O/(name+'.ready.json')).write_bytes(line)
 servers.append((proc,log));return proc,endpoint,state,ready
def stop(proc):
 if proc.poll() is None:
  proc.terminate()
  try:proc.wait(timeout=8)
  except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2);raise
def receive(sock,n):
 b=b''
 while len(b)<n:
  x=sock.recv(n-len(b))
  if not x:raise RuntimeError('truncated response')
  b+=x
 return b
def request(endpoint,q):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
  sock.settimeout(5);sock.connect(chr(0)+endpoint);raw=json.dumps(dict(version=1,**q),separators=(',',':')).encode()
  try:sock.sendall(struct.pack('!I',len(raw))+raw)
  except BrokenPipeError:pass
  n=struct.unpack('!I',receive(sock,4))[0];assert n<=12*1024*1024
  return json.loads(receive(sock,n))
def execute(endpoint,command,timeout=2000,action=None,extra=None):
 a=action or uuid.uuid4().hex;q={'op':'execute','action_id':a,'command_sha256':hashlib.sha256(command.encode()).hexdigest(),'command':command,'timeout_ms':timeout}
 q.update(extra or {});return a,q,request(endpoint,q)
R={'schema':'hepta.executor-r6-targeted-host-checks.v1','scope':'Host fixture only; current UID, synthetic contexts, host /bin/sh. No Android, real SELinux transition, phone, model, provider or native-r5 qualification.', 'phone_operations':0,'policy_writes':0}
try:
 proc,endpoint,state,ready=start('bootstrap')
 h=request(endpoint,{'op':'health'})
 check('bootstrap-authorized-health',h['execute_authorized'] is True and h['executor_revision']==6,h)
 marker='R6_'+uuid.uuid4().hex
 aid,q,res=execute(endpoint,"printf '"+marker+"'")
 r=res['receipt'];(O/'completed-original.json').write_text(json.dumps(res,indent=2))
 check('worker-after-exec-handshake-and-output',r['state']=='completed' and r['worker_domain_verified'] is True and r['execution_context']=='host_fixture_worker_not_android_selinux' and r['execution_uid']==os.getuid() and r['waitpid_joined'] is True and r['process_group_absent'] is True and base64.b64decode(res['stdout_b64']).decode()==marker,r)
 orig=(state/'actions'/aid/'receipt.json').read_bytes()
 dup=request(endpoint,q)
 check('duplicate-read-only-receipt',dup['duplicate'] is True and dup['receipt']==r and (state/'actions'/aid/'receipt.json').read_bytes()==orig,dup)
 badid=uuid.uuid4().hex
 (state/'actions'/badid).symlink_to(state/'actions'/aid,target_is_directory=True)
 bad=request(endpoint,{'op':'inspect','action_id':badid})
 check('non-enoent-inspect-fails-not-not-found',bad.get('error')=='action_directory_inspection_failed' and bad.get('state')=='rejected',bad)
 (state/'actions'/badid).unlink() # remove only this test-owned symlink, never an action journal
 timeout_marker='TIME_'+uuid.uuid4().hex;late='LATE_'+uuid.uuid4().hex
 ta,tq,tr=execute(endpoint,"printf '"+timeout_marker+"'; sleep 2; printf '"+late+"'",timeout=250)
 check('worker-group-timeout-joined-no-late',tr['receipt']['state']=='timed_out' and tr['receipt']['worker_domain_verified'] and tr['receipt']['waitpid_joined'] and tr['receipt']['process_group_absent'] and base64.b64decode(tr['stdout_b64']).decode()==timeout_marker,tr['receipt'])
 stop(proc)
 # Same existing journal: readonly Magisk peer must not force an execution or poison recovery.
 mp,me,ms,mh=start('magisk',MAGISK,state)
 deny=request(me,q)
 check('magisk-existing-action-execute-denied',deny.get('error')=='execute_peer_context_denied' and deny.get('effect_started') is False and (state/'actions'/aid/'receipt.json').read_bytes()==orig,deny)
 mh=request(me,{'op':'health'})
 check('denied-execute-does-not-poison-recovery',mh['state']=='ready' and mh['execute_authorized'] is False,mh)
 mi=request(me,{'op':'inspect','action_id':aid,'command_sha256':q['command_sha256']})
 check('magisk-inspect-readonly-original',mi['receipt']==r,mi['receipt'])
 stop(mp)
 up,ue,us,uh=start('wrong-domain','u:r:shell:s0')
 denied=request(ue,{'op':'health'})
 check('unapproved-domain-rejected-before-operation',denied.get('error')=='peer_identity_denied' and list((us/'actions').iterdir())==[],denied)
 stop(up)
 wp,we,ws,wh=start('worker-denied')
 wa,wq,wr=execute(we,"printf NEVER_EXECUTED",extra={'_fixture_worker_domain_fail':True})
 rr=wr['receipt'];(O/'worker-domain-denied.json').write_text(json.dumps(wr,indent=2))
 check('worker-domain-failure-no-effect',rr['state']=='indeterminate' and rr['worker_domain_verified'] is False and rr['effect_started'] is None and rr['waitpid_joined'] is True and rr['process_group_absent'] is True and base64.b64decode(wr['stdout_b64'])==b'',rr)
 receipt_before=(ws/'actions'/wa/'receipt.json').read_bytes()
 stop(wp)
 rp,re,rs,rh=start('worker-denied-restart',state=ws)
 blocked=request(re,{'op':'health'})
 _,_,blockedexec=execute(re,'printf NO_REPLAY')
 check('worker-unknown-survives-restart',blocked['state']=='recovery_required' and blockedexec['receipt']['state']=='recovery_required' and (ws/'actions'/wa/'receipt.json').read_bytes()==receipt_before,blocked)
 stop(rp)
 R['status']='PASS'
except Exception as e:
 R['status']='FAILED';R['error']=repr(e)
finally:
 for proc,log in servers:
  try:stop(proc)
  except Exception as e:checks.append({'name':'owned-server-stop','passed':False,'error':repr(e)});R['status']='FAILED'
  log.close()
 R['build_steps']=rows;R['checks']=checks;R['passed']=sum(x['passed'] for x in checks);R['total']=len(checks)
 R['sources']=[{'path':n,'bytes':(BASE/n).stat().st_size,'sha256':hashlib.sha256((BASE/n).read_bytes()).hexdigest()} for n in ('phone_tool_sidecar.cpp','phone_tool_worker.cpp','phone_security.h')]
 (O/'RESULT.json').write_text(json.dumps(R,indent=2)+'\n')
 print(json.dumps({'status':R['status'],'passed':R['passed'],'total':R['total'],'error':R.get('error'),'result':str(O/'RESULT.json'),'sha256':hashlib.sha256((O/'RESULT.json').read_bytes()).hexdigest()},indent=2))
if R['status']!='PASS':raise SystemExit(1)
