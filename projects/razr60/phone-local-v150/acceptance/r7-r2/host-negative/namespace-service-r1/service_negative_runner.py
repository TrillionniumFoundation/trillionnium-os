#!/usr/bin/env python3
"""NEG06/14 against frozen provider entry/functions inside an isolated host FS/net."""
import argparse,errno,fcntl,hashlib,importlib,json,os,re,resource,secrets,signal,socket,stat,subprocess,sys,threading,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
SUITE=Path('/suite');SOURCE=SUITE/'provider/source';WORK=Path('/work');HARNESS=Path('/harness')
SEAL_SHA='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
COMBO_SHA='ee2bba801325525f9fa910c2c613352b54c32cb71921f2e7a16d2f25205e94d4'
COMBO_CANONICAL='1f4763e8bf56cf25392a944298d08e4284495b0b7f44b3edb77060a250b598c5'
PROTOCOL_SHA='a9f314c4f2b6a7f05cbe7cc129ffcecef709f1f00b01b2dc5d08b0b6360b64e4'
CLIENT=Path('/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py')
CLIENT_SHA='500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
OWNED=[];DAILY=OPENAI=None;SERVER_SHA=None
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def mkdir(p):p.mkdir(mode=0o700);return p
def write(p,v):
 b=json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False).encode()+b'\n'
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def read(p):return json.loads(p.read_bytes())
def pinned(p,digest):
 b=p.read_bytes();assert sha(b)==digest,(str(p),'pin differs');return b
def proc(pid):
 try:raw=Path('/proc')/str(pid)/'stat';b=raw.read_bytes()
 except (FileNotFoundError,ProcessLookupError):return None
 pos=b.rfind(b')');assert pos>0
 tail=b[pos+2:].split();assert len(tail)>19
 return {'pid':int(b.split(b' ',1)[0]),'ppid':int(tail[1]),'pgid':int(tail[2]),'sid':int(tail[3]),'start_ticks':int(tail[19])}
def census(group):
 members=[]
 for p in Path('/proc').iterdir():
  if p.name.isdigit():
   row=proc(int(p.name))
   if row and (row['pgid']==group or row['sid']==group):members.append(row)
 try:os.killpg(group,0);kernel='exists'
 except ProcessLookupError:kernel='ESRCH'
 return {'group':group,'members':members,'kernel':kernel}
def resources():
 r=resource.getrusage(resource.RUSAGE_SELF);c=resource.getrusage(resource.RUSAGE_CHILDREN)
 return {'monotonic':time.monotonic(),'fd_count':len(list(Path('/proc/self/fd').iterdir())),'thread_count':threading.active_count(),'cpu_user':r.ru_utime,'cpu_system':r.ru_stime,'children_cpu_user':c.ru_utime,'children_cpu_system':c.ru_stime,'maxrss_lifetime_KiB':r.ru_maxrss,'maxrss_is_case_peak':False,'available_bytes':os.statvfs(WORK).f_bavail*os.statvfs(WORK).f_frsize}
def wait_file(p,deadline,process=None):
 while time.monotonic()<deadline:
  if p.is_file():
   try:return read(p)
   except json.JSONDecodeError:pass
  if process is not None and process.p.poll() is not None:raise RuntimeError('original process exited before '+str(p))
  time.sleep(.01)
 raise TimeoutError('original file deadline '+str(p))
class Owned:
 def __init__(self,label,argv,root):
  self.label=label;self.root=root;self.signals=[];self.joined=False;self.result=None
  self.stdout=open(root/(label+'.stdout'),'xb');self.stderr=open(root/(label+'.stderr'),'xb')
  self.p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=self.stdout,stderr=self.stderr,start_new_session=True)
  self.identity=proc(self.p.pid)
  if self.identity is not None:assert self.identity['pid']==self.identity['pgid']==self.identity['sid']
  self.argv=argv;OWNED.append(self)
  write(root/(label+'-SPAWN.json'),{'argv':argv,'pid':self.p.pid,'observed_identity':self.identity,'monotonic':time.monotonic(),'synthetic_host_namespace':True})
 def signal(self,n):
  if self.p.poll() is not None:return
  current=proc(self.p.pid)
  if self.identity is None or current!=self.identity:raise RuntimeError('owned identity no longer exact; no signal')
  self.signals.append({'signal':n,'identity':current,'monotonic':time.monotonic()})
  os.killpg(self.p.pid,n)
 def join(self,timeout=5,stop=False):
  if self.joined:return self.result
  if stop:self.signal(signal.SIGTERM)
  try:rc=self.p.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   self.signal(signal.SIGKILL);rc=self.p.wait(timeout=2)
  self.stdout.close();self.stderr.close();self.joined=True
  observed=census(self.p.pid)
  self.result={'pid':self.p.pid,'original_identity':self.identity,'returncode':rc,'actual_direct_child_wait_returned':True,'signals':self.signals,'group_after':observed,'monotonic':time.monotonic()}
  write(self.root/(self.label+'-JOIN.json'),self.result)
  return self.result
def config_tree(root,label):
 d=mkdir(root/label);state=mkdir(d/'state')
 cfg=read(SUITE/'production-config.json')
 key=d/'synthetic-only-api.key';fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(24)+'\n')
 cfg.update(endpoint='http://127.0.0.1:18099/v1/chat/completions',api_key_file=str(key),model='synthetic-fixture-no-real-inference')
 write(d/'config.json',cfg)
 ident={'session_id':'seed-'+secrets.token_hex(16),'profile_id':'host-synthetic','task_id':'seed-'+secrets.token_hex(16),'turn_id':'seed-'+secrets.token_hex(16)}
 seed=[{'identity':ident,'origin_receipt_sha256':sha(canonical({'synthetic_only':True,'identity':ident}))}]
 seed_rec=write(d/'retained.json',seed)
 write(d/'FIXTURE-DECLARATION.json',{'scope':'host_isolated','synthetic':True,'config_sha256':sha((d/'config.json').read_bytes()),'source_requires_inference_location_phone_literal':True,'actual_inference_location':'host fixture only; literal is schema compatibility, never a phone attestation','production_config_unchanged':True,'changed_fixture_fields':['endpoint','api_key_file','model'],'fixture_deadline_seconds':1,'real_model_requests':0,'key_contents_not_reported':True})
 return d,state,seed_rec
def daemon_argv(d,state,seed,port):
 return ['/usr/bin/python3','-I','-B',str(SOURCE/'daily_phone_local.py'),'--state',str(state),'--config',str(d/'config.json'),'--port',str(port),'--workers','1','--timeout','1','--retained-claims',str(d/'retained.json'),'--retained-claims-sha256',seed['sha256']]
class Evidence:
 def __init__(self,cid):self.path=mkdir(WORK/cid);self.checks=[];self.observations=[]
 def check(self,n,c):
  self.checks.append({'name':n,'passed':c is True})
  if c is not True:raise AssertionError(n)
 def exception(self,n,fn,kind):
  try:value=fn()
  except kind as ex:
   row={'label':n,'type':type(ex).__name__,'error':str(ex),'errno':getattr(ex,'errno',None)}
   self.observations.append(row);self.check(n,True);return row
  raise AssertionError(n+' unexpectedly returned '+repr(value))
def no_members(e,label,result):
 e.check(label+' actual wait and group absence',result['actual_direct_child_wait_returned'] is True and result['group_after']['members']==[] and result['group_after']['kernel']=='ESRCH')
def neg06(e):
 fixture=Owned('fixture-server',['/usr/bin/python3','-I','-B',str(HARNESS/'fixture_server.py'),'--out',str(e.path/'fixture')],e.path)
 wait_file(e.path/'fixture/READY.json',time.monotonic()+5,fixture)
 d,state,seed=config_tree(e.path,'timeout-turn')
 daemon=Owned('daily-timeout',daemon_argv(d,state,seed,18101),e.path)
 ready=wait_file(state/'ready.json',time.monotonic()+5,daemon)
 e.check('current frozen daily source actually ready',ready['source_sha256']=='92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3' and ready['accepting'] is True)
 nonce=secrets.token_hex(16);identity={'session_id':'host-'+secrets.token_hex(16),'profile_id':'host-synthetic','task_id':'host-'+secrets.token_hex(16),'turn_id':'host-'+secrets.token_hex(16),'turn_stream_id':'host-'+secrets.token_hex(16)}
 frame={'protocol':OPENAI.PROTOCOL,'kind':'turn.start','seq':0,'turn':dict(identity,user_input='New isolated deterministic timeout '+nonce)}
 write(e.path/'ORIGINAL-TURN.json',{'synthetic':True,'frame':frame})
 connection=socket.create_connection(('127.0.0.1',18101),timeout=3);connection.settimeout(8);reader=connection.makefile('rb')
 started=time.monotonic();wire=[]
 try:
  connection.sendall(canonical(frame)+b'\n')
  while True:
   raw=reader.readline(OPENAI.MAX_LINE+1)
   if not raw:break
   assert len(raw)<=OPENAI.MAX_LINE
   value=json.loads(raw);wire.append(value)
   if value['kind'] in ('turn.complete','turn.cancelled','turn.fail'):break
 finally:reader.close();connection.close()
 write(e.path/'ORIGINAL-WIRE.json',{'frames':wire,'elapsed_seconds':time.monotonic()-started})
 e.check('one real failure wire contains model_timeout',len([x for x in wire if x['kind']=='turn.fail'])==1 and 'model_timeout' in wire[-1].get('error',''))
 e.check('zero tool dispatch in actual wire',not any(x['kind']=='tool.call' for x in wire))
 runs=[p for p in (state/'evidence').iterdir() if p.is_dir() and re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',p.name)]
 e.check('one original accepted run',len(runs)==1);run=runs[0]
 wait_file(run/'connection-ended.json',time.monotonic()+5,daemon)
 terminal=read(run/'terminal.json');business=read(run/'business-outcome.json');spawn=read(run/'local-01.spawned.json');joined=read(run/'local-01.joined.json');slot=read(run/'local-01.slot-after.json');failure=read(run/'local-01.model-failure.json')
 health=read(state/'model-health-phone-local.json');worker_result=read(run/'local-01.worker-result.json')
 e.check('actual health classifies original timeout without fallback',failure['category']=='model_timeout' and failure['automatic_retry'] is False and failure['account_or_model_changed'] is False and health['availability']=='observed_unavailable' and health['reason']=='model_timeout' and health['issued']==health['failure_fence']==1)
 e.check('original worker result has a real bounded exit and no retry',type(worker_result['returncode']) is int and worker_result['automatic_retry'] is False)
 request=wait_file(e.path/'fixture/REQUEST.json',time.monotonic()+2,fixture);original_end=wait_file(e.path/'fixture/REQUEST-TERMINAL.json',time.monotonic()+2,fixture)
 e.check('provider persisted original failed terminal and unverified business',terminal['kind']=='turn.fail' and 'model_timeout' in terminal.get('error','') and business['business_verified'] is False)
 e.check('HTTP client original wait/group receipt',joined['pid']==spawn['pid'] and joined['child_wait_returned'] is True and joined['dedicated_process_group_absent'] is True)
 worker_group=census(spawn['process_group']);write(e.path/'ORIGINAL-WORKER-CENSUS.json',worker_group)
 e.check('kernel independently confirms original HTTP group absent',worker_group['members']==[] and worker_group['kernel']=='ESRCH')
 e.check('fixture actual server slot idle',slot['observed'] is True and slot['idle'] is True and original_end['response_sent'] is False and original_end['terminal']!='fixture_deadline_or_stop')
 claims=list((state/'evidence/claims').iterdir())
 e.check('retained seed and new consumed claim remain',len(claims)==2 and any(read(p).get('identity')==identity for p in claims))
 e.check('no typed effects mapped or reserved',not list(state.rglob('semantic-*.json')) and not list(state.rglob('dispatch-*.json')) and not list(state.rglob('*.intent.json')))
 e.check('exactly one actual HTTP worker spawn',len(list(state.rglob('local-*.spawned.json')))==1 and not list(state.rglob('codex-*.spawned.json')))
 body=read(run/'local-01.request.json')
 e.check('fixture received original current prompt bytes',request['request_sha256']==sha(json.dumps(body,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()) and request['request_id']==original_end['request_id'])
 claim_hashes={str(p):sha(p.read_bytes()) for p in claims}
 result=daemon.join(stop=True);no_members(e,'daily timeout daemon',result)
 e.check('all original accepted claims survive daemon exit',claim_hashes=={str(p):sha(p.read_bytes()) for p in (state/'evidence/claims').iterdir()})
 fixture_result=fixture.join(stop=True);no_members(e,'synthetic fixture server',fixture_result)
 exit_record=read(e.path/'fixture/EXIT.json')
 e.check('fixture exactly one request no retry and idle before exit',exit_record['post_count']==1 and exit_record['active'] is False)
 e.check('provider stopped accepting after owned cleanup',read(state/'ready.json')['accepting'] is False)
 write(e.path/'TERMINAL-EVIDENCE.json',{'run':str(run),'terminal':terminal,'business':business,'model_failure':failure,'model_health':health,'worker_result':worker_result,'spawned':spawn,'joined':joined,'slot_after':slot,'http_worker_receipt_present':(run/'local-01.http-receipt.json').exists(),'fixture_terminal':original_end,'server_exit':exit_record,'claims':[{'path':str(p),'sha256':sha(p.read_bytes())} for p in claims],'real_model_requests':0,'fixture_http_requests':1})
def neg14(e):
 evidence=mkdir(e.path/'evidence-race');run=mkdir(evidence/('20261104-000000-'+secrets.token_hex(16)))
 known=['local-01.request.json.new','health-outcome.json.new']
 for index,name in enumerate(known):
  temporary=run/name;canonical_path=run/name[:-4]
  write(temporary,{'synthetic':True,'index':index})
  enumerated=list(run.iterdir());original=temporary.read_bytes();e.check(name+' actual pathname enumerated',temporary in enumerated)
  os.replace(temporary,canonical_path)
  value=DAILY.evidence_item_size(temporary,evidence)
  write(e.path/('RENAME-'+str(index)+'.json'),{'enumerated':[str(p) for p in enumerated],'missing_original_path':str(temporary),'renamed_to':str(canonical_path),'source_return':value,'original_sha256':sha(original),'surviving_sha256':sha(canonical_path.read_bytes())})
  e.check(name+' only recognized disappeared temporary tolerated',value is None and canonical_path.read_bytes()==original)
 e.exception('unknown canonical missing is rejected',lambda:DAILY.evidence_item_size(run/'unknown.json',evidence),FileNotFoundError)
 e.exception('recognized name without real parent rejected',lambda:DAILY.evidence_item_size(evidence/('20261104-000000-'+secrets.token_hex(16))/'terminal.json.new',evidence),FileNotFoundError)
 link=run/'terminal.json.new';link.symlink_to(run/'local-01.request.json')
 e.exception('symlink evidence is rejected',lambda:DAILY.evidence_item_size(link,evidence),RuntimeError)
 blocked=mkdir(run/'unreadable');write(blocked/'evidence.json',{'synthetic':True});os.chmod(blocked,0)
 try:
  err=e.exception('real unreadable path EACCES propagates',lambda:DAILY.evidence_item_size(blocked/'evidence.json',evidence),PermissionError)
  e.check('real kernel EACCES observed',err['errno']==errno.EACCES)
  def scan():
   return list(os.walk(blocked,onerror=DAILY.raise_evidence_scan_error))
  e.exception('actual scandir error propagates through original callback',scan,PermissionError)
 finally:os.chmod(blocked,0o700)
 for label,port in [('orphan',18102),('capacity',18103)]:
  d,state,seed=config_tree(e.path,label);ev=mkdir(state/'evidence');rundir=mkdir(ev/('20261104-000001-'+secrets.token_hex(16)))
  if label=='orphan':
   original=rundir/'local-01.spawn-intent.json';write(original,{'synthetic_only':True,'state':'reserved_without_joined'})
   before=sha(original.read_bytes());expected='unjoined prior inference-client round'
  else:
   original=rundir/'sparse-capacity.bin'
   fd=os.open(original,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
   try:os.ftruncate(fd,1024*OPENAI.MAX_LINE);os.fsync(fd)
   finally:os.close(fd)
   before=(original.stat().st_size,original.stat().st_ino);expected='evidence capacity reached'
   write(e.path/'SPARSE-CAPACITY.json',{'path':str(original),'apparent_bytes':original.stat().st_size,'allocated_bytes':original.stat().st_blocks*512,'production_space_consumed':False,'full_content_hash_not_computed':'Sparse fixture size is the input; do not read 1GiB zeros for metadata evidence.'})
  argv=daemon_argv(d,state,seed,port)+['--max-evidence-bytes',str(1024*OPENAI.MAX_LINE)]
  child=Owned('daily-'+label,argv,e.path);result=child.join(timeout=8)
  stderr=(e.path/('daily-'+label+'.stderr')).read_text()
  e.check(label+' exact entry rejects at intended gate',result['returncode']!=0 and expected in stderr)
  no_members(e,label+' daemon',result)
  claims=list((ev/'claims').iterdir())
  e.check(label+' retained consumed seed not deleted',len(claims)==1)
  e.check(label+' no model worker or typed action spawned',not list(state.rglob('local-*.spawned.json')) and not list(state.rglob('semantic-*.json')) and not list(state.rglob('dispatch-*.json')))
  if label=='orphan':e.check('orphan original intent preserved',sha(original.read_bytes())==before and not (rundir/'local-01.joined.json').exists())
  else:e.check('capacity original sparse input preserved and service nonaccepting',(original.stat().st_size,original.stat().st_ino)==before and read(state/'ready.json')['accepting'] is False)
  lock_fd=os.open(state/'daemon.lock',os.O_RDWR|os.O_NOFOLLOW)
  try:fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(lock_fd,fcntl.LOCK_UN)
  finally:os.close(lock_fd)
  e.check(label+' daemon ownership lock released',True)
  write(e.path/(label+'-ORIGINAL-REJECTION.json'),{'original_returncode':result['returncode'],'original_stderr':stderr,'source_sha256':sha((SOURCE/'daily_phone_local.py').read_bytes()),'claims':[{'path':str(p),'sha256':sha(p.read_bytes())} for p in claims],'original_fixture_preserved':True,'real_model_requests':0,'fixture_http_requests':0})
def verify():
 seal=json.loads(pinned(SUITE/'provider/SOURCE-SEAL.json',SEAL_SHA))
 combo=json.loads(pinned(SUITE/'combination.json',COMBO_SHA));assert sha(canonical(combo))==COMBO_CANONICAL
 p=json.loads(pinned(SUITE/'protocol.json',PROTOCOL_SHA));old=json.loads(pinned(SUITE/'original-protocol.json','c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0'))
 assert p['cases']==old['cases'] and p['limits']==old['limits'] and p['qualified_geometry']==old['qualified_geometry']
 for x in seal['production_files']:assert len(pinned(SUITE/'provider'/x['path'],x['sha256']))==x['bytes']
 assert sha(CLIENT.read_bytes())==CLIENT_SHA and CLIENT.resolve()==CLIENT
 pinned(HARNESS/'fixture_server.py',SERVER_SHA)
 return p
def main():
 global DAILY,OPENAI,SERVER_SHA
 a=argparse.ArgumentParser();a.add_argument('--execute-once',action='store_true');a.add_argument('--server-sha256',required=True);args=a.parse_args()
 if not args.execute_once:print('review-only');return 0
 SERVER_SHA=args.server_sha256;os.umask(0o077)
 assert WORK.is_dir() and not (WORK/'SUITE-INTENT.json').exists()
 outer=read(WORK/'OUTER-ENV.json')
 current={'uid':os.getuid(),'gid':os.getgid(),'netns':os.readlink('/proc/self/ns/net'),'mntns':os.readlink('/proc/self/ns/mnt'),'pidns':os.readlink('/proc/self/ns/pid'),'capabilities':[x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith(('CapEff:','CapPrm:','NoNewPrivs:'))]}
 assert current['uid']==0 and current['netns']!=outer['host_netns'] and current['mntns']!=outer['host_mntns']
 caps=int(next(x.split()[1] for x in current['capabilities'] if x.startswith('CapEff:')),16)
 assert caps & ((1<<1)|(1<<2))==0,'DAC overrides must be dropped for real unreadable evidence test'
 assert os.statvfs(SUITE).f_flag & 1 and os.statvfs(CLIENT).f_flag & 1
 write(WORK/'SUITE-INTENT.json',{'schema':'hepta.isolated-service-negatives.v1','cases':['NEG-06','NEG-14'],'current_namespace':current,'source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'real_model_requests':0,'production_changes':0})
 p=verify();sys.path.insert(0,str(SOURCE));DAILY=importlib.import_module('daily_phone_local');OPENAI=importlib.import_module('provider_openai_compatible')
 write(WORK/'SOURCE-ENTRY-PREFLIGHT.json',{'daily_source':str(DAILY.__file__),'daily_sha256':sha(Path(DAILY.__file__).read_bytes()),'client_path':str(CLIENT),'client_sha256':sha(CLIENT.read_bytes()),'all_13_source_pins_verified':True,'case_objects':[x for x in p['cases'] if x['id'] in ('NEG-06','NEG-14')],'limits':p['limits'],'geometry':p['qualified_geometry']})
 def timeout(n,f):raise TimeoutError('absolute isolated-suite 45s bound')
 signal.signal(signal.SIGALRM,timeout);signal.alarm(45)
 started=time.monotonic();rows=[]
 try:
  for cid,fn in [('NEG-06',neg06),('NEG-14',neg14)]:
   e=Evidence(cid);before=resources();error=None;first=len(OWNED)
   try:fn(e)
   except BaseException as ex:error={'type':type(ex).__name__,'error':str(ex),'traceback':traceback.format_exc()}
   finally:
    for child in reversed(OWNED[first:]):
     if not child.joined:
      try:child.join(timeout=3,stop=True)
      except BaseException as ex:error=error or {'type':type(ex).__name__,'error':'owned cleanup unknown: '+str(ex)}
   after=resources()
   for name,ok in [('runner FD baseline restored',after['fd_count']==before['fd_count']),('runner thread baseline restored',after['thread_count']==before['thread_count']),('all owned children actually waited and groups absent',all(x.joined and x.result['group_after']['members']==[] and x.result['group_after']['kernel']=='ESRCH' for x in OWNED[first:]))]:
    e.checks.append({'name':name,'passed':bool(ok)})
   passed=error is None and all(x['passed'] for x in e.checks)
   row={'schema':'hepta.isolated-service-negative-result.v150.r7-r2.1','case_id':cid,'layer':'host_isolated','status':'PASS' if passed else 'FAIL','source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'error':error,'assertions':e.checks,'observations':e.observations,'resources':{'before':before,'after':after,'elapsed_seconds':after['monotonic']-before['monotonic']},'owned_processes':[x.result for x in OWNED[first:]],'real_model_requests':0,'phone_calls':0,'native_dispatches':0,'synthetic_only':True,'fixture_http_requests_observed':(1 if (e.path/'fixture/REQUEST.json').is_file() else 0)}
   rec=write(e.path/'RESULT.json',row);rows.append({'case_id':cid,'protocol_result':row['status'],'result':rec,'assertions':len(e.checks)})
  verify();signal.alarm(0)
  result={'schema':'hepta.isolated-service-negative-suite.v150.r7-r2.1','status':'PASS' if all(x['protocol_result']=='PASS' for x in rows) else 'FAIL','source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'cases':rows,'elapsed_seconds':time.monotonic()-started,'actual_namespace':current,'phone_calls':0,'real_model_requests':0,'native_dispatches':0,'fixture_http_requests_observed':sum(1 for x in rows if (WORK/x['case_id']/'fixture/REQUEST.json').is_file()),'frozen_production_sources_unchanged':True,'scope':'Original NEG06/14 host_isolated requirements only; fixture uses phone literal solely to satisfy unchanged source schema.'}
  rec=write(WORK/'RESULT.json',result);print(json.dumps({'result':rec,'status':result['status'],'cases':rows,'phone_calls':0,'real_model_requests':0}))
  return 0 if result['status']=='PASS' else 1
 finally:
  signal.alarm(0)
  for child in reversed(OWNED):
   if not child.joined:
    try:child.join(timeout=2,stop=True)
    except BaseException:pass
if __name__=='__main__':raise SystemExit(main())
