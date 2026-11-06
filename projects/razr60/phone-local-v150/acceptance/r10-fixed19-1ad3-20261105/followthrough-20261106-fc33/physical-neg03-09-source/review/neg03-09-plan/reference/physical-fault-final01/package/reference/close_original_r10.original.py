#!/usr/bin/env python3
"""Host-only closure of one pinned r10 original task and its existing draft receipts.

No phone call, UI action, model/slot query, registration, Send or Cancel.
Only two named, already-produced Pocket4 draft restoration receipts are read.
Every closure output is new; an unknown closure is never replayed in place.
"""
from pathlib import Path
import argparse,ast,base64,hashlib,io,json,os,re,shlex,signal,stat,subprocess,sys,tarfile,time,types
import root_acceptance_r10 as core
B=None
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
SSH=['/usr/bin/ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22',
 '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast']
class ClosureError(Exception):pass
def need(v,label):
 if not v:raise ClosureError(label)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def strict(raw):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ClosureError('nonfinite JSON')))
def metadata(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
class Originals:
 def __init__(self,out,allowed_files=()):self.out=out;self.observed={};self.absent=set();self.total=0;self.allowed_files=set(map(str,allowed_files));self.directories={}
 def read(self,path,required=True,maximum=64*1024*1024):
  p=Path(path);need(p.is_absolute() and p.parent.resolve(strict=False)==p.parent,'noncanonical local evidence')
  need(B in p.parents or str(p) in self.allowed_files,'local evidence outside owned project and explicit private original')
  need(p.name not in ('api.key','llama-api.key','synthetic-only-api.key'),'credential read forbidden')
  try:fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  except FileNotFoundError:
   need(not required,'required original missing');self.absent.add(str(p));return None
  try:
   a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,'original type/size')
   parts=[];total=0
   while True:
    block=os.read(fd,min(65536,maximum+1-total))
    if not block:break
    total+=len(block);need(total<=maximum,'original read budget');parts.append(block)
   raw=b''.join(parts)
   need(metadata(a)==metadata(os.fstat(fd))==metadata(p.lstat()) and len(raw)==a.st_size,'original changed while read')
   old=self.observed.get(str(p));current={'metadata':metadata(a),'bytes':len(raw),'sha256':sha(raw)}
   need(old is None or old==current,'original differs from earlier read')
   if old is None:self.total+=len(raw);need(self.total<=256*1024*1024,'closure total evidence bound')
   self.observed[str(p)]=current;return raw
  finally:os.close(fd)
 def json(self,path,required=True,maximum=64*1024*1024):
  b=self.read(path,required,maximum);return strict(b) if b is not None else None
 def lines(self,path):
  raw=self.read(path);need(raw.endswith(b'\n'),'original JSONL lacks final newline')
  return [strict(line) for line in raw.splitlines() if line]
 def pinned(self,path,pin,maximum=64*1024*1024):
  b=self.read(path,maximum=maximum);need(sha(b)==pin,'original SHA differs');return b
 def directory(self,path):
  p=Path(path);need(p.resolve(strict=True)==p and p.is_dir(),'original directory is noncanonical')
  before=p.stat();names=sorted(x.name for x in p.iterdir());after=p.stat()
  need(metadata(before)==metadata(after),'directory changed during enumeration')
  value={'metadata':metadata(before),'names':names}
  need(str(p) not in self.directories or self.directories[str(p)]==value,'directory inventory changed')
  self.directories[str(p)]=value;return names
 def unchanged(self):
  for path,value in list(self.directories.items()):
   self.directory(path);need(self.directories[path]==value,'directory inventory changed after audit')
  before=dict(self.observed)
  for path,row in before.items():
   self.pinned(Path(path),row['sha256']);need(self.observed[path]==row,'original metadata changed')
  for path in self.absent:
   try:Path(path).lstat()
   except FileNotFoundError:continue
   raise ClosureError('original absence changed')
def relative(value):
 p=Path(value);need(not p.is_absolute() and p.parts and all(x not in ('','.','..') for x in p.parts),'unsafe snapshot member')
 return p
def put(path,raw):
 need(path.parent.resolve(strict=True)==path.parent,'output parent changed')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def writej(path,value):return put(path,(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode())
def zero(v):return type(v) is int and v==0
def original_phone_zero(snapshot,path,stdout_raw):
 v=snapshot.json(path,maximum=32*1024*1024);phone=v.get('wrapper',{}).get('phone',{})
 need(zero(v.get('actor_rc')) and zero(phone.get('rc')),'original capture actor/phone terminal is not zero')
 need(isinstance(phone.get('stdout'),str) and phone['stdout'].encode()==stdout_raw,'original capture stdout differs')
 return v
def read_draft_receipts(snapshot,out,label,preserved):
 original=snapshot.json(preserved,maximum=131072)
 need(isinstance(original,dict) and isinstance(original.get('exact_utf8_b64'),str),'private original draft shape')
 draft=base64.b64decode(original['exact_utf8_b64'],validate=True);draft.decode('utf-8',errors='strict')
 need(draft and sha(draft)==original['utf8_sha256'],'private original draft integrity')
 remote_dir='/home/alex/codex-hepta-natural-'+label+'-root-v150'
 remote="""from pathlib import Path
import base64,hashlib,json,os,stat
d=Path(%r);assert d.parent.resolve(strict=True)==d.parent and d.resolve(strict=True)==d
rows=[]
for name in ('DRAFT-RESTORE-RESULT.json','PRESERVED-DRAFT-RESTORE.original.json'):
 p=d/name;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=262144
  chunks=[]
  while True:
   b=os.read(fd,65536)
   if not b:break
   chunks.append(b)
  raw=b''.join(chunks);c=os.fstat(fd);n=p.lstat()
  fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  assert len(raw)==a.st_size and all(getattr(a,k)==getattr(c,k)==getattr(n,k) for k in fields)
 finally:os.close(fd)
 rows.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'raw_b64':base64.b64encode(raw).decode()})
print(json.dumps({'files':rows,'phone_calls':0,'model_calls':0},separators=(',',':')))
"""%remote_dir
 started=time.monotonic()
 child=subprocess.run(SSH+['/usr/bin/python3 -B -c '+shlex.quote(remote)],stdin=subprocess.DEVNULL,
                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
 put(out/'DRAFT-READ-PACKET.private.json',child.stdout);put(out/'DRAFT-READ.stderr.private',child.stderr)
 writej(out/'DRAFT-READ-PROCESS.private.json',{'returncode':child.returncode,'elapsed_seconds':time.monotonic()-started,
  'original_only_two_named_files':True,'automatic_retry':False,'phone_calls':0,'model_calls':0})
 need(zero(child.returncode) and child.stderr==b'','original draft read did not complete zero')
 packet=strict(child.stdout);need(packet.get('phone_calls')==0 and packet.get('model_calls')==0,'draft read scope')
 originals={}
 for row in packet['files']:
  need(row['name'] in ('DRAFT-RESTORE-RESULT.json','PRESERVED-DRAFT-RESTORE.original.json') and row['name'] not in originals,'draft original names')
  body=base64.b64decode(row['raw_b64'],validate=True);need(len(body)==row['bytes'] and sha(body)==row['sha256'],'draft original integrity')
  put(out/row['name'],body);originals[row['name']]=strict(body)
 need(len(originals)==2,'two original draft receipts required')
 result=originals['DRAFT-RESTORE-RESULT.json'];wire=originals['PRESERVED-DRAFT-RESTORE.original.json']
 need(result.get('state')=='ORIGINAL_DRAFT_RESTORED' and result.get('original_draft_submitted') is False
      and result.get('model_business_credit') is False and result.get('restore_attempts')==1
      and result.get('utf8_sha256')==sha(draft),'original cleanup disposition')
 need(zero(wire.get('rc')) and wire.get('stderr')=='','original draft restore wire not terminal zero')
 value=strict(wire['stdout'])
 need(value.get('schema')=='hepta.focused-unicode-input.v1' and value.get('status') in ('set_verified','already_exact')
      and value.get('operation_id')=='root-restore-'+label and value.get('display_id')==0
      and value.get('package')=='org.trillionnium.owneropen'
      and value.get('view_id')=='org.trillionnium.owneropen:id/ui_prompt'
      and value.get('own_automation_disconnected') is True,'original cleanup action binding')
 readback=base64.b64decode(value['readback_text_b64'],validate=True)
 need(readback==draft and value.get('requested_utf8_sha256')==sha(draft)
      and value.get('after_utf8_sha256')==sha(draft),'private exact draft readback differs')
 return {'exact_original_draft_restored':True,'original_draft_submitted':False,
         'restore_attempts':1,'business_return_credit':False,'private_text_or_digest_in_public_output':False}
def load_pinned(snapshot,path,pin,name):
 raw=snapshot.pinned(Path(path),pin,1048576)
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(raw,str(path),'exec'),module.__dict__);return module

def load_collectors(snapshot,ctx):
 names=('native_journal_audit','ledger_prefix_audit','mobile_use_evidence',
        'business_fact_recheck','history_context_audit','health_context_audit','collect_business_evidence')
 need(set(ctx['collector_files'])=={name+'.py' for name in names},'exact seven collector sources required')
 loaded={}
 for name in names:
  loaded[name]=load_pinned(snapshot,Path(ctx['collector_dir'])/(name+'.py'),ctx['collector_files'][name+'.py'],name)
 return loaded

def cleanup_assessment_api(snapshot,path,pin):
 raw=snapshot.pinned(path,pin,1048576);tree=ast.parse(raw,filename=str(path))
 names={'require','validate_original_records','assess_original'}
 selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
 need({n.name for n in selected}==names and len(selected)==len(names),'pure cleanup assessment inventory differs')
 namespace={'hashlib':hashlib,'re':re,'strict_json':strict}
 exec(compile(ast.Module(body=selected,type_ignores=[]),str(path)+'#offline-original-assessment','exec'),namespace)
 return types.SimpleNamespace(assess_original=namespace['assess_original'])

def verify_runtime_binding(snapshot,ctx,root,config,seal):
 runtime=ctx['runtime'];identity=runtime['server_identity']
 service=snapshot.json(root/'sources/PHONE-SERVICE-INPUTS-v150-r10.json')
 claim=snapshot.read(root/'runtime/model.identity',maximum=128)
 need(claim==(':'.join(str(identity[k]) for k in ('pid','pgid','sid','start_ticks'))+'\n').encode(),
      'captured original model claim differs')
 ready=snapshot.json(root/'runtime/READY-BOUND.json')
 need(ready.get('schema')=='hepta.model-startup-bound.v1' and ready.get('state')=='READY_BOUND_IMAGE_CANCEL_REQUIRED'
      and ready.get('server_identity')==identity and ready.get('binding')==ctx['ready']['actual_binding'],
      'captured startup binding differs from selected ready original')
 binding_path=Path(runtime['binding_path'])
 binding=strict(snapshot.pinned(root/'runtime/bindings'/binding_path.name,runtime['binding_sha256']))
 need(set(binding)=={'schema','server_identity','model_claim','model_claim_sha256','server_binary_sha256','server_domain','endpoint'}
      and binding['schema']=='hepta.model-cleanup-binding.v1' and binding['server_identity']==identity
      and binding['model_claim']==str(binding_path.parent.parent/'model.identity')
      and binding['model_claim_sha256']==sha(claim) and binding['server_domain']=='u:r:magisk:s0'
      and binding['endpoint']==config['endpoint']
      and binding['server_binary_sha256']==service['runtime']['server']['sha256']
      and ctx['ready']['roles']['model']['exe']==service['runtime']['server']['path'],
      'captured model binding path/source/config identity differs')

def verify_capture(snapshot,ctx,release,exporter,request):
 e=Path(ctx['export_dir']);root=e/'snapshot'
 manifest=snapshot.json(e/'UNPACK-MANIFEST.json',maximum=4*1024*1024)
 result_raw=snapshot.read(e/'CAPTURE-RESULT.json',maximum=131072);result=strict(result_raw)
 bound=snapshot.json(e/'CAPTURE-BINDING.json',maximum=65536)
 need(bound['nonce']==ctx['nonce'] and bound['owner_request_sha256']==sha(request)
      and bound['combination_sha256']==sha(release['binding_raw'])
      and bound['sender_label']==ctx['sender_label'] and bound['release_pins']==ctx['release_pins']
      and bound['runtime']==ctx['runtime'],'r10 capture binding differs')
 need(result.get('schema')=='hepta.original-capture-result.v150.r10.1','r10 capture result schema')
 snapshot.read(e/'CAPTURE-TERMINAL.json',maximum=65536)
 need(exporter.capture_terminal_zero(e,bound) is True,'original capture process not terminal zero')
 original_phone_zero(snapshot,e/('accept-r10-'+ctx['nonce']+'-capture.original-operation.json'),result_raw)
 cap_raw=snapshot.pinned(root/'CAPTURE.json',result['capture_sha256'],4*1024*1024);cap=strict(cap_raw)
 need(cap.get('schema')=='hepta.original-capture.v150.r10.1'
      and cap.get('nonce')==ctx['nonce'] and cap.get('owner_request_sha256')==sha(request)
      and cap.get('combination_sha256')==sha(release['binding_raw'])
      and cap.get('selected_scope')==bound['sender_scope'],'archived capture identity differs')
 need(exporter.capture_complete(result,cap) is True,'r10 original capture incomplete')
 need(manifest.get('capture_process_completed_zero') is True and manifest.get('complete_original_capture') is True
      and manifest['capture_sha256']==sha(cap_raw) and manifest['archive_sha256']==result['archive']['sha256'],
      'unpack completion differs')
 archive=snapshot.pinned(e/'originals.tar.gz',result['archive']['sha256'])
 need(len(archive)==result['archive']['bytes'],'original archive size')
 seen={};total=0
 with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
  for member in tar:
   rel=exporter.safe_member(member.name)
   need(member.isfile() and not member.issym() and not member.islnk() and str(rel) not in seen,'archive member kind/duplicate')
   need(0<=member.size<=(64*1024*1024 if str(rel)=='selected-native-raw.jsonl' else 16*1024*1024)
        and len(seen)<2056,'archive member bound')
   total+=member.size;need(total<=66*1024*1024,'archive expansion bound')
   stream=tar.extractfile(member);need(stream is not None,'archive body absent');body=stream.read(member.size+1)
   need(len(body)==member.size and snapshot.read(root/rel)==body,'archive original/copy differ')
   seen[str(rel)]=(len(body),sha(body))
 listed={r['path']:(r['bytes'],r['sha256']) for r in manifest['files']}
 need(len(listed)==len(manifest['files']) and seen==listed,'unpack manifest differs')
 originals={}
 for row in cap['files']:
  rel=str(exporter.safe_member(row['export_relative_path']))
  if row.get('state')=='captured':
   need(rel not in originals,'duplicate captured original');originals[rel]=(row['bytes'],row['sha256'])
  elif row.get('state')=='absent':need(snapshot.read(root/rel,required=False) is None,'captured original absence differs')
 need(all(seen.get(k)==v for k,v in originals.items()),'captured original pins differ')
 need(set(seen)==set(originals)|{'CAPTURE.json','host-bound-request.txt','selected-scope.json','selected-native-raw.jsonl'},
      'unlisted archive member')
 need(snapshot.read(root/'host-bound-request.txt')==request,'copied owner differs')
 native=snapshot.read(root/'selected-native-raw.jsonl').splitlines(keepends=True)
 need(len(native)==len(cap['native_raw_records']),'native row count differs')
 for body,row in zip(native,cap['native_raw_records']):
  need(body.endswith(b'\n') and len(body)==row['bytes'] and sha(body)==row['sha256'],'native raw byte integrity')
 selected=snapshot.json(root/'selected-scope.json')
 need(cap['selected_scope']==selected.get('scope',selected),'selected scope differs')
 return root,cap

def original_http(row,path):
 need(row.get('method')=='GET' and row.get('path')==path and row.get('automatic_retry') is False
      and row.get('redirect_followed') is False and row.get('complete') is True
      and type(row.get('http_status')) is int and row['http_status']==200 and row.get('error') is None,
      'original read-only HTTP observation incomplete')
 raw=base64.b64decode(row['raw_http_response_b64'],validate=True)
 need(len(raw)<=65536+8192 and sha(raw)==row['raw_http_response_sha256'],'original HTTP byte pin')
 head,body=raw.split(b'\r\n\r\n',1);lines=head.decode('iso-8859-1').split('\r\n')
 need(len(head)+4<=8192 and len(body)<=65536 and re.fullmatch(r'HTTP/1\.[01] 200(?: .*)?',lines[0]),'original HTTP status')
 headers={}
 for line in lines[1:]:
  need(':' in line and not line.startswith((' ','\t')),'original header framing')
  name,value=line.split(':',1);name=name.lower();need(name not in headers,'duplicate original header')
  headers[name]=value.strip()
 need('transfer-encoding' not in headers and re.fullmatch('[0-9]+',headers.get('content-length',''))
      and int(headers['content-length'])==len(body)==row['body_bytes'] and sha(body)==row['body_sha256'],
      'original HTTP body framing/hash')
 return strict(body)

def verify_cleanup(snapshot,ctx,root,run,number,cleanup_api,request,request_id):
 stem=run/('local-%02d'%number)
 def get(name):return snapshot.json(str(stem)+'.'+name+'.json')
 after=get('slot-after');ctl=after.get('cleanup_controller',{})
 need(ctl.get('schema')=='hepta.cleanup-observer-controller.v1'
      and ctl.get('state')=='ORIGINAL_CLEANUP_VERIFIED_AND_OBSERVER_JOINED' and ctl.get('admitted') is True
      and ctl.get('request_id')==request_id and ctl.get('request_sha256')==sha(request)
      and ctl.get('pidfd_opened') is True and ctl.get('waitpid_join_returned') is True
      and zero(ctl.get('observer_returncode')) and ctl.get('observer_may_still_exist') is False
      and ctl.get('signals')==[] and ctl.get('deadline_exceeded') is False
      and type(ctl.get('elapsed_seconds')) in (int,float) and 0<=ctl['elapsed_seconds']<=6,
      'original owned cleanup observer did not close within its bound')
 for name in ('post_count','new_model_requests','decision_count','tool_count'):
  need(zero(ctl.get(name)),'observer produced a model/effect action')
 stdout=base64.b64decode(ctl['stdout_b64'],validate=True);stderr=base64.b64decode(ctl['stderr_b64'],validate=True)
 need(sha(stdout)==ctl['stdout_sha256'] and stderr==b'' and sha(stderr)==ctl['stderr_sha256'],
      'observer original pipe bytes differ')
 frames=[strict(x) for x in stdout.splitlines()]
 need(len(frames)==2,'observer original terminal framing')
 started=get('cleanup-observer-started');summary=get('cleanup-observer-result')
 need(frames[0]==started==ctl['observer_identity'] and frames[1]['kind']=='observer_result'
      and frames[1]['result']==summary==ctl['observer_result'],'observer original result differs')
 provider=ctx['ready']['roles']['provider']['identity']
 need(started.get('kind')=='observer_started' and type(started.get('pid')) is int and started['pid']>1
      and started['pid']==ctl['observer_pid'] and started.get('parent_pid')==provider[0]
      and started.get('pgid')==provider[1] and started.get('sid')==provider[2]
      and type(started.get('start_ticks')) is int and started['start_ticks']>0
      and started.get('read_only_network') is True and zero(started.get('post_count')),
      'original observer process ownership differs')
 ref=ctl['observer_result_ref'];raw=snapshot.read(str(stem)+'.cleanup-observer-result.json')
 need(frames[1]['result_ref']==ref and ref.get('bytes')==len(raw) and ref.get('sha256')==sha(raw)
      and Path(ref['path']).name==stem.name+'.cleanup-observer-result.json'
      and Path(ref['path']).parent.name==run.name,'observer durable result reference differs')
 expected=ctx['runtime']['server_identity']
 need(summary.get('schema')=='hepta.model-passive-cleanup.v1' and summary.get('admitted') is True
      and summary.get('server_identity')==expected and summary.get('request_id')==request_id
      and summary.get('request_sha256')==sha(request) and summary.get('request_bytes')==len(request)
      and summary.get('automatic_retry') is False and summary.get('deadline_exceeded') is False
      and summary.get('client_exit_is_server_cancel_proof') is False,
      'original server cleanup summary differs')
 for name in ('post_count','new_model_requests','decision_count','tool_count'):
  need(zero(summary.get(name)),'original cleanup performed a model/effect action')
 need(type(summary.get('get_count')) is int and 2<=summary['get_count']<=12 and summary['get_count']%2==0,
      'original observation count differs')
 pins=summary.get('original_local_receipts',{})
 need(set(pins)=={'images','worker-result','spawned','joined','request-identity'},'original local receipt inventory')
 for name,row in pins.items():
  value=snapshot.read(str(stem)+'.'+name+'.json')
  need(len(value)==row['bytes'] and sha(value)==row['sha256'],'original cleanup local receipt pin')
 identity=get('request-identity');worker=get('worker-result');spawned=get('spawned');joined=get('joined')
 need(identity.get('request_id')==worker.get('request_id')==request_id
      and identity.get('request_sha256')==worker.get('request_sha256')==sha(request)
      and identity.get('request_bytes')==worker.get('request_bytes')==len(request)
      and spawned.get('actual_spawn') is True and spawned.get('pid')==spawned.get('process_group')==joined.get('pid')
      and joined.get('child_wait_returned') is True and joined.get('dedicated_process_group_absent') is True,
      'original request/body/HTTP-worker ownership differs')
 cycles=summary['get_count']//2;need(len(summary['observations'])==cycles,'original cycle count')
 final=None;last=None
 for cycle in range(1,cycles+1):
  rq=get('cleanup-observe-%02d'%(2*cycle-1));sl=get('cleanup-observe-%02d'%(2*cycle))
  need(rq.get('cycle')==sl.get('cycle')==cycle,'original observation cycle differs')
  receipt=original_http(rq,'/hepta/requests/'+request_id);slots=original_http(sl,'/slots')
  assessment=cleanup_api.assess_original(request_id,expected,receipt,slots,sha(request),len(request))
  recorded=summary['observations'][cycle-1]
  need(recorded.get('cycle')==cycle and recorded.get('assessment')==assessment,'offline original cleanup assessment differs')
  if cycle<cycles:need(assessment.get('admitted') is False,'observer continued after admission')
  final=assessment;last={'observed':type(slots[0].get('is_processing')) is bool,
      'idle':slots[0].get('is_processing') is False,'slot':slots[0],
      'response_sha256':sl['body_sha256'],'automatic_retry':False}
 need(final and final.get('admitted') is True and all(summary.get(k)==v for k,v in final.items()),
      'original server task has no qualified terminal and release')
 need(summary['last_slot_observation']==ctl['last_slot_observation']==last
      and after=={**last,'cleanup_controller':ctl},'slot-after lost original server task ownership')
 # Raw on-device producer files are separate from the GET representation.
 for pin in receipt['records']:
  body=snapshot.pinned(root/'runtime/receipts'/request_id/pin['name'],pin['sha256'],2*1024*1024)
  need(len(body)==pin['bytes'],'native producer original byte count differs')
 need(snapshot.read(root/'runtime/receipts'/request_id/'accepted-body.bin')==request,
      'native accepted body differs from the single original HTTP request')
 return {'round':number,'request_id':request_id,'server_original_terminal':final['original_model_terminal'],
         'original_server_identity':expected,'offline_original_assessment_verified':True,
         'observer_join_verified':True,'raw_producer_originals_verified':True,'network_calls':0}

def verify_models(snapshot,ctx,root,report,run,kind,material,cleanup_api):
 rows=report['model_rounds'];need(rows and len(rows)<=ctx['max_model_rounds']==8
     and report['observed_model_request_count']==len(rows),'model round count')
 need([r['round'] for r in rows]==list(range(1,len(rows)+1)),'model rounds not consecutive')
 cleanups=[]
 for row in rows:
  need(row.get('real_terminal_and_cleanup') is True and row.get('worker_joined') is True
       and row.get('server_slot_observed_idle_after') is True,'original model terminal/cleanup unresolved')
  stem=run/('local-%02d'%row['round']);request=snapshot.read(str(stem)+'.request.json')
  response=snapshot.read(str(stem)+'.http-response.json');receipt=snapshot.json(str(stem)+'.http-receipt.json')
  images=snapshot.json(str(stem)+'.images.json');worker=snapshot.json(str(stem)+'.worker-result.json')
  need(type(receipt.get('attempt_count')) is int and receipt['attempt_count']==1
       and receipt.get('automatic_retry') is False and receipt.get('fallback_model') is False
       and receipt.get('redirect_followed') is False and receipt.get('service_manifest_sha256')==ctx['release_pins']['service_inputs_sha256']
       and receipt.get('request_sha256')==sha(request) and receipt.get('response_bytes')==len(response)
       and receipt.get('response_sha256')==sha(response) and receipt.get('request_id')==images['request_id']
       and receipt.get('http_status')==200 and zero(worker.get('returncode')),'original HTTP terminal/body/attempt differs')
  need(row.get('http_response_complete') is True and row.get('transport_terminal')=='complete_http_response'
       and row.get('automatic_retry') is False and row.get('fallback_model') is False,'original HTTP incomplete')
  cleanups.append(verify_cleanup(snapshot,ctx,root,run,row['round'],cleanup_api,request,images['request_id']))
  if kind=='health':
   obj=strict(response);decision=strict(obj['choices'][0]['message']['content'])
   need(obj['choices'][0]['finish_reason']=='stop' and decision.get('kind')=='turn.complete'
        and decision.get('summary')==material['nonce'],'raw health nonce differs')
 if kind=='health':need(len(rows)==1,'health must have one model round')
 return cleanups

def close(a):
 global B
 os.umask(0o077);ctx,release=core.load_context(a.context,a.context_sha256)
 B=Path(ctx['project_dir']);need(B.resolve(strict=True)==B,'project root changed')
 out=Path(ctx['closure_dir']);need(out==Path(ctx['workflow_dir'])/'closure' and B in out.parents
     and out.parent.resolve(strict=True)==out.parent,'canonical new closure output required')
 allowed=[a.context.absolute(),Path(ctx['materializer'])]
 allowed += [Path(row['path']) for row in ctx['inputs'].values()]
 allowed += [Path(ctx['collector_dir'])/name for name in ctx['collector_files']]
 allowed += [Path(ctx['operator_directory'])/name for name in ctx['operator_files']]
 out.mkdir(mode=0o700)
 writej(out/'CLOSURE-INTENT.private.json',{'schema':'hepta.r10.original-closure-intent.v1',
  'context_sha256':a.context_sha256,'report_sha256':a.report_sha256,'case':ctx['case'],
  'combination_manifest_sha256':ctx['combination_manifest_sha256'],
  'original_draft_read_scope':'two already produced Pocket4 cleanup receipts only',
  'phone_calls':0,'model_calls':0,'task_submissions':0,'automatic_retry':False})
 snapshot=Originals(out,allowed)
 snapshot.pinned(a.context.absolute(),a.context_sha256)
 for row in ctx['inputs'].values():snapshot.pinned(Path(row['path']),row['sha256'])
 for name,pin in ctx['operator_files'].items():snapshot.pinned(Path(ctx['operator_directory'])/name,pin)
 modules=load_collectors(snapshot,ctx);auditor=modules['native_journal_audit'];business=modules['collect_business_evidence']
 exporter=load_pinned(snapshot,Path(ctx['operator_directory'])/'export_originals_r10.py',
                      ctx['operator_files']['export_originals_r10.py'],'closed_original_export_r10')
 kind=ctx['kind'];h=Path(ctx['material_dir']);e=Path(ctx['export_dir']);material=ctx['material']
 request=snapshot.read(h/'request.txt',maximum=24576)
 need(kind in core.KINDS and ctx['case']==core.KINDS[kind] and material['case']==ctx['case']
      and snapshot.read(h/'combination.json')==release['binding_raw']
      and material['combination_manifest_sha256']==ctx['combination_manifest_sha256']
      and sha(request)==material['request_sha256']==ctx['request_sha256']
      and re.fullmatch('[0-9a-f]{32}',ctx['nonce']) and request.decode().count(ctx['nonce'])==1,
      'original material/owner/combination differs')
 report_path=e/'audit-01/REPORT.json';report_raw=snapshot.pinned(report_path,a.report_sha256);report=strict(report_raw)
 need(report['case_id']==ctx['case'] and report['candidate_source_seal_sha256']==ctx['release_pins']['source_seal_sha256']
      and report['request_utf8_sha256']==sha(request) and report.get('changed_after_snapshot')==[]
      and report.get('issues')==[],'original collector report identity/issues')
 result=snapshot.json(e/'COLLECTOR-RESULT.json',maximum=131072)
 need(zero(result.get('process_exit_code')) and result.get('report_sha256')==sha(report_raw)
      and result.get('report_path')==str(report_path) and result.get('original_capture_complete') is True
      and result.get('collector_source_sha256')==ctx['collector_files']['collect_business_evidence.py'],
      'collector terminal/integrity differs')
 snapshot.read(e/'collector.stdout');need(snapshot.read(e/'collector.stderr')==b'','collector stderr is not empty')
 for row in report['inputs']:
  source=Path(row['source']);copy=report_path.parent/relative(row['copy'])
  body=snapshot.pinned(source,row['sha256']);need(len(body)==row['bytes'] and snapshot.read(copy)==body,'collector raw copy differs')
 root,capture=verify_capture(snapshot,ctx,release,exporter,request)
 scope=report['scope'];need(set(scope)==set(KEYS) and all(isinstance(scope[k],str) and scope[k] for k in KEYS),'exact scope shape')
 need(capture['selected_scope']==scope,'capture/report scope differs')
 native_raw=snapshot.read(root/'selected-native-raw.jsonl');need(native_raw.endswith(b'\n'),'native raw boundary')
 records=[auditor.strict_loads(line) for line in native_raw.splitlines() if line]
 audit=auditor.verify_records(records,scope)
 need(audit['status']=='PASS' and audit['errors']==[] and audit['unsupported']==[]
      and audit['record_count']==audit['selected_scope_record_count']==audit['record_hashes_verified'],
      'independent native record integrity')
 frames=audit['frames'];need(sum(f['kind']=='turn.accepted' for f in frames)==1
      and sum(f['kind']=='turn.end' for f in frames)==1 and frames[-1]['payload']==report['native_terminal'],'native terminal differs')
 digest=report['native_turn_request_sha256']
 need(re.fullmatch('[0-9a-f]{64}',digest) and all(f['payload'].get('turn_request_sha256')==digest for f in frames),
      'native envelope request hash differs')
 state=root/'provider-state';run=Path(report['snapshot_run_dir'])
 need(run.parent==state/'evidence' and re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',run.name),'original run path differs')
 snapshot.directory(run)
 claim_key=sha(json.dumps([scope[k] for k in KEYS[:-1]],ensure_ascii=True,separators=(',',':')).encode())
 claim=snapshot.json(state/'evidence/claims'/claim_key)
 need(claim.get('identity')==scope and claim.get('request_sha256')==sha(request) and claim.get('state')=='accepted_no_redispatch'
      and Path(claim['run_dir']).name==run.name,'original one-use claim differs')
 incoming=snapshot.lines(run/'provider-in.jsonl');outgoing=snapshot.lines(run/'provider-out.jsonl')
 for rows in (incoming,outgoing):need([v.get('seq') for v in rows]==list(range(len(rows))),'provider sequence incomplete')
 need(incoming[0]['kind']=='turn.start' and all(incoming[0]['turn'][k]==scope[k] for k in KEYS)
      and incoming[0]['turn']['user_input'].encode()==request,'provider owner/scope differs')
 terminal=snapshot.json(run/'terminal.json');need(terminal==report['provider_terminal'],'provider terminal differs')
 endings=[x for x in outgoing if x['kind'] in ('turn.complete','turn.fail','turn.cancelled')]
 need(len(endings)==1 and outgoing[-1]==endings[0] and terminal['kind']==endings[0]['kind'],'provider terminal not unique/last')
 status={'turn.complete':'completed','turn.fail':'provider_failed','turn.cancelled':'cancelled'}[terminal['kind']]
 need(report['native_terminal']['status']==status,'native/provider terminal class differs')
 calls=[r['call'] for r in outgoing if r['kind']=='tool.call'];results=[r for r in incoming if r['kind']=='tool.result']
 result_by_id={r['call_id']:r for r in results}
 need(len(result_by_id)==len(results) and set(result_by_id)<={c['call_id'] for c in calls},'duplicate/foreign original result')
 need(len(calls)==len({c['call_id'] for c in calls})==report['observed_tool_dispatch_count']
      and len(calls)<=ctx['max_tool_calls']==7 and len(report['tools'])==len(calls),'original tool count/identity')
 dispatched=[snapshot.json(p)['call'] for p in sorted(run.glob('dispatch-*.json'))]
 need(dispatched==calls,'durable dispatch order differs')
 for call,previous in zip(calls,report['tools']):
  row=business.inspect_tool(snapshot,run,state,root/'executor-r6',root/'client-receipts',scope,call,result_by_id.get(call['call_id']),frames)
  need(row==previous and row.get('safe_original_execution_terminal') is True and row.get('unresolved_effect') is False
       and row.get('r6_terminal_identity_and_cleanup_verified') is True and row.get('native_raw_streams_equal') is True,
       'original effect terminal unresolved')
 for stage in ('tool.accepted','tool.started','tool.result'):
  matched=[f for f in frames if f['kind']==stage]
  need(len(matched)==len(calls) and {f['call_id'] for f in matched}=={c['call_id'] for c in calls},'native tool lifecycle count')
 checks=report['checks']
 for name in ('source_seal_pin_matches','production_config_pin_matches','service_inputs_pin_matches',
              'pinned_runtime_source_bytes_verified','provider_terminal_persisted_and_last',
              'provider_native_terminal_agree','native_record_and_turn_integrity',
              'all_original_tool_evidence_aligned','no_unresolved_mutating_effects'):
  need(checks.get(name) is True,'original closure check not confirmed: '+name)
 seal=snapshot.json(root/'sources/provider-r10/SOURCE-SEAL-v150-r10.json')
 for path,pin in ((root/'sources/provider-r10/SOURCE-SEAL-v150-r10.json',ctx['release_pins']['source_seal_sha256']),
                  (root/'sources/local-config-r10.json',ctx['release_pins']['configuration_sha256']),
                  (root/'sources/PHONE-SERVICE-INPUTS-v150-r10.json',ctx['release_pins']['service_inputs_sha256'])):
  snapshot.pinned(path,pin)
 config=snapshot.json(root/'sources/local-config-r10.json');source=root/'sources/provider-r10/source'
 business.SEAL=ctx['release_pins']['source_seal_sha256'];business.CONFIG=ctx['release_pins']['configuration_sha256']
 business.SERVICE=ctx['release_pins']['service_inputs_sha256'];business.MODEL=seal['model']
 projection=business.load_projection_api(snapshot,source,seal)
 if kind=='health':
  need(calls==[],'health contains a tool')
  projection['round_contexts']=business.rebuild_original_health(snapshot,source,seal,config,request,run,calls)
 else:
  prefix=business.audit_ledger_prefix(snapshot,run,state,scope,request,seal,root/'CAPTURE.json',calls,source)
  need(prefix.get('complete_prefix_reconstruction') is True and checks.get('complete_original_ledger_prefix_verified') is True,
       'complete original ledger prefix unconfirmed')
  projection['round_contexts']=business.rebuild_original_history(snapshot,source,seal,config,scope,request,run,calls,result_by_id,prefix)
 reparse=modules['business_fact_recheck'].recheck(snapshot,source,seal,
     snapshot.json(run/'task-contract.json',required=False),
     snapshot.json(run/'business-outcome.json',required=False),scope,request,calls,result_by_id,run,
     approved_apps=config['approved_apps'])
 need(reparse==report['independent_business_reparse'],
      'source-derived app scope/contract/business reparse differs from original report')
 original_rounds=business.inspect_rounds(snapshot,run,Path(report['original_run_dir']),request,projection,calls)
 need(original_rounds==report['model_rounds'],'source-derived original model/ledger/history differs')
 cleanup_pin=next(row['sha256'] for row in seal['production_files'] if row['path']=='source/model_slot_cleanup.py')
 verify_runtime_binding(snapshot,ctx,root,config,seal)
 cleanup_api=cleanup_assessment_api(snapshot,source/'model_slot_cleanup.py',cleanup_pin)
 cleanups=verify_models(snapshot,ctx,root,report,run,kind,material,cleanup_api)
 draft=read_draft_receipts(snapshot,out,ctx['sender_label'],Path(ctx['inputs']['preserved_draft']['path']))
 snapshot.unchanged()
 audit_copy={k:v for k,v in audit.items() if k not in ('selected_records','frames')}
 writej(out/'NATIVE-INDEPENDENT-AUDIT.private.json',audit_copy);put(out/'NATIVE-SELECTED-RAW.jsonl',native_raw)
 healthy=kind=='health' and report.get('health_qualification_pass') is True and result.get('health_qualification_pass') is True and report.get('proof_complete') is True and result.get('proof_complete') is True and status=='completed'
 success=kind!='health' and report.get('complete_business_success') is True and result.get('complete_business_success') is True and report.get('proof_complete') is True and result.get('proof_complete') is True and status=='completed'
 previous={'identity':scope,'request_sha256':digest,'terminal':report['native_terminal'],
  'known_no_phone_tool_execution':len(calls)==0,'known_all_dispatched_tools_confirmed_terminal':len(calls)>0,
  'scope':'Original task lifecycle only. Next sender independently rechecks current selection and global action gate.',
  'complete_business_success':success,'health_qualification_pass':healthy,'original_failed_status_unchanged':status!='completed',
  'model_business_return_credit_from_draft_restore':False}
 prev=writej(out/'ACTUAL-PREVIOUS-INPUT.json',previous)
 closure={'schema':'hepta.root-host-original-closure.v150.r10.1','state':'ORIGINAL_TASK_LIFECYCLE_CLOSED',
  'kind':kind,'case':ctx['case'],'native_status':status,'context_sha256':a.context_sha256,'report_sha256':sha(report_raw),
  'combination_manifest_sha256':ctx['combination_manifest_sha256'],'release_pins':ctx['release_pins'],
  'native_request_sha256':digest,'scope':scope,'capture_actor_and_phone_actual_zero':True,'collector_actual_exit_zero':True,
  'independent_native_audit':audit_copy,'model_round_count':len(report['model_rounds']),'tool_dispatch_count':len(calls),
  'all_original_effect_terminals_verified':True,'model_workers_joined_and_original_server_releases_verified':True,
  'independent_model_cleanup':cleanups,'report_proof_complete_preserved':report['proof_complete'],
  'provider_native_text_agreement_preserved':checks.get('provider_native_terminal_text_agree'),
  'health_qualification_pass':healthy,'complete_business_success':success,'draft_cleanup':draft,
  'input_files_independently_rechecked':len(snapshot.observed),'input_bytes':snapshot.total,'previous':prev,
  'phone_calls':0,'model_calls':0,'new_send':0,'new_cancel':0,'old_effect_replayed':False,
  'service_changes':0,'permission_to_dispatch_not_inferred':True}
 writej(out/'CLOSURE-CHECK.private.json',closure)
 public={'state':closure['state'],'kind':kind,'case':ctx['case'],'native_status':status,'health_qualification_pass':healthy,
  'complete_business_success':success,'original_tool_terminals_verified':len(calls),
  'original_model_releases_verified':len(cleanups),'exact_original_draft_restored':True,'original_draft_submitted':False,
  'phone_calls':0,'model_calls':0,'new_send':0,'new_cancel':0,'next_sender_still_requires_current_gates':True}
 writej(out/'SUMMARY.json',public);print(json.dumps(public,sort_keys=True));return 0

def expired(signum,frame):raise ClosureError('absolute host closure deadline')
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--context',type=Path,required=True);p.add_argument('--context-sha256',required=True)
 p.add_argument('--report-sha256',required=True);p.add_argument('--execute-close-once',action='store_true')
 a=p.parse_args()
 for pin in (a.context_sha256,a.report_sha256):need(re.fullmatch('[0-9a-f]{64}',pin),'explicit SHA256 required')
 if not a.execute_close_once:
  print(json.dumps({'state':'PREPARED_SOURCE_ONLY','original_reads':0,'phone_calls':0,'closure_writes':0}));return 0
 signal.signal(signal.SIGALRM,expired);signal.alarm(120)
 try:return close(a)
 except BaseException as error:
  print(json.dumps({'state':'CLOSURE_NOT_CONFIRMED','error_class':type(error).__name__,
   'phone_calls':0,'model_calls':0,'new_send':0,'automatic_retry':False},sort_keys=True));raise
 finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
