"""Root-owned bounded actor using the existing pinned phone transport.
No ADB lifecycle changes or automatic request/effect retries.
"""
from pathlib import Path
import argparse,datetime,hashlib,http.client,json,os,re,shlex,socket,stat,sys,time,types
BASE=Path('/home/alex/razr60-local-model-v150')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
FINGERPRINT='motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys'
PHONE='/data/local/tmp/hepta-phone-local-v150-r1'
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as s:
  for b in iter(lambda:s.read(1048576),b''):h.update(b)
 return h.hexdigest()
def save(p,value):
 raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as s:s.write(raw);s.flush();os.fsync(s.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
ap=argparse.ArgumentParser();ap.add_argument('label');ap.add_argument('request',type=Path);args=ap.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]{1,100}',args.label)
raw=args.request.read_bytes(); req=json.loads(raw)
(BASE/'operations').mkdir(mode=0o700,exist_ok=True);run=BASE/'operations'/args.label;run.mkdir(mode=0o700)
start=time.monotonic()
save(run/'intent.json',{'schema':'hepta.phone-local.operator-intent.v150.1','label':args.label,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'request_sha256':hashlib.sha256(raw).hexdigest(),'request':req,'automatic_replay':False})
result={'schema':'hepta.phone-local.operator-result.v150.1','label':args.label,'model_decision':False,'native_task_result':False}
try:
 p=Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved_ui_package_phase_r7.py')
 b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
 f=types.ModuleType('v150_root_phone_actor');f.__file__=str(p);exec(compile(b,str(p),'exec'),f.__dict__)
 c=json.loads((p.parent/'preserved-ui-package-config.json').read_text());t=f.route(c)
 baseline=f.shell('cat /proc/sys/kernel/random/boot_id; getprop ro.build.fingerprint; getprop sys.usb.config; getenforce; pidof adbd',c,t,timeout=15)
 assert baseline['rc']==0 and baseline['stdout'].splitlines()==[BOOT,FINGERPRINT,'adb','Enforcing','3021'], 'Phone baseline changed'
 save(run/'baseline.json',baseline)
 kind=req['kind']
 if kind=='shell':
  command=req['command']
  if req.get('root'):command='/debug_ramdisk/su -c '+shlex.quote(command)
  result['phone']=f.shell(command,c,t,timeout=min(300,int(req.get('timeout_seconds',30))))
  result['status']='command_exited'
 elif kind=='push':
  p=Path(req['source']); info=p.lstat()
  assert stat.S_ISREG(info.st_mode) and not p.is_symlink() and sha_file(p)==req['sha256']
  dest=req['destination'];assert dest.startswith(PHONE+'/') and '..' not in Path(dest).parts
  check=f.shell('test ! -e '+shlex.quote(dest),c,t,timeout=10);assert check['rc']==0,'Destination exists; do not overwrite'
  save(run/'push-reserved.json',{'source':str(p),'destination':dest,'bytes':info.st_size,'sha256':req['sha256']})
  f.push(str(p),dest,c,t)
  observed=f.shell('sha256sum '+shlex.quote(dest)+'; stat -c %s '+shlex.quote(dest),c,t,timeout=90)
  result['readback']=observed
  assert observed['rc']==0 and observed['stdout'].splitlines()[0].split()[0]==req['sha256'] and int(observed['stdout'].splitlines()[1])==info.st_size
  result.update(status='pushed_and_hash_verified',bytes=info.st_size,sha256=req['sha256'])
 elif kind=='http':
  assert req.get('port',18087)==18087
  method=req.get('method','GET');path=req['path'];assert method in ('GET','POST') and path.startswith('/') and '\r' not in path and '\n' not in path
  body=json.dumps(req['body'],ensure_ascii=False,separators=(',',':')).encode() if 'body' in req else b''
  assert len(body)<=4*1024*1024
  headers={'Host':'127.0.0.1:18087','Connection':'close','Content-Type':'application/json','Content-Length':str(len(body))}
  if req.get('auth',False):
   key=(BASE/'private/llama-api.key').read_text().strip();assert re.fullmatch(r'[A-Za-z0-9_-]{32,128}',key);headers['Authorization']='Bearer '+key
  timeout=min(300,int(req.get('timeout_seconds',120)))
  with socket.create_connection(('127.0.0.1',t[0]),timeout=timeout) as sock:
   f.request(sock,'host:transport-id:'+t[1]);f.request(sock,'tcp:18087')
   packet=(method+' '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode()+body
   save(run/'http-dispatch-reserved.json',{'method':method,'path':path,'body_sha256':hashlib.sha256(body).hexdigest(),'auth':req.get('auth',False),'phone_tcp':18087,'through_existing_adb_transport':True})
   sock.sendall(packet);response=http.client.HTTPResponse(sock);response.begin();out=response.read(8*1024*1024+1);assert len(out)<=8*1024*1024
  result.update(status='http_response_received',http_status=response.status,response=out.decode('utf-8'),response_sha256=hashlib.sha256(out).hexdigest(),elapsed_seconds=time.monotonic()-start)
 else:raise RuntimeError('Unknown operation')
except BaseException as e:
 result.update(status='failed_or_unknown_no_retry',error=type(e).__name__,detail=str(e),automatic_replay=False)
result['elapsed_seconds']=time.monotonic()-start
save(run/'result.json',result)
print(json.dumps({'run':str(run),'status':result['status'],'sha256':sha_file(run/'result.json'),'elapsed_seconds':result['elapsed_seconds'],'http_status':result.get('http_status'),'phone_rc':result.get('phone',{}).get('rc'),'error':result.get('detail')},ensure_ascii=False))
sys.exit(1 if result['status']=='failed_or_unknown_no_retry' else 0)
