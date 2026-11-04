#!/usr/bin/env python3
"""Root-only host closure of one already captured r7-r2 task.
Reads named Main originals and two original P4 draft cleanup receipts.
No phone command, UI action, model/slot query, task registration or task Send.
"""
from pathlib import Path
import argparse,base64,collections,hashlib,io,json,os,re,shlex,signal,stat,subprocess,sys,tarfile,time,types
B=Path('/operator-workspace/phone-local-v150')
D=B/'closure-r7-r2-helper-r1'
COMBO=B/'module-r7-r2-finalization-r1/COMBINATION-FROZEN-v150-r7-module-r2.json'
COMBO_SHA='ee2bba801325525f9fa910c2c613352b54c32cb71921f2e7a16d2f25205e94d4'
CANON='1f4763e8bf56cf25392a944298d08e4284495b0b7f44b3edb77060a250b598c5'
SOURCE='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
CONFIG='<INSTANCE_CONFIGURATION_SHA256_REQUIRED>'
SERVICE='ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2'
AUDIT='da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
SSH=['ssh','-J','operator-jump-host','-o','HostName=192.0.2.4','-p','22','-o','BatchMode=yes',
 '-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','operator-secondary-host']
PINS={
 'health-r7-r2-original-export-r1/export_health_r7_once.py':'54289c1f441bdaa394b88e4f0f1749b2f7f058e3f5126f33ee0139a213a00209',
 'business-r7-r2-original-export-r1/export_business_once.py':'64cabfd0d1196dec37be44183224d9fb4309b229c2702305da4614e39251d4d3',
 'acceptance-r7-r2/collector-r7/collect_health_evidence.py':'887d28ae2cc09fe857ab01fac19bbb32d14e35c5d78b230bb82950a6d956dbf2',
 'acceptance-r7-r2/business-collector-r7-r1/collect_business_evidence.py':'e5fc961d5cec94ab2e075c84dd5672b0d616863a616d59270d92cfd527dfddc7',
 'acceptance-r7-r2/business-collector-r7-r1/mobile_use_evidence.py':'24d79c3d802661e73dc697e68891f7d4c158180ecc85c0ad20567562813bd228',
 'acceptance-r7-r2/collector-r7/native_journal_audit.py':AUDIT,
 'send_new_native_task_r5.py':'5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}
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
 def __init__(self,allowed_files=()):self.observed={};self.absent=set();self.total=0;self.allowed_files=set(map(str,allowed_files))
 def read(self,path,required=True,maximum=64*1024*1024):
  p=Path(path);need(p.is_absolute() and p.parent.resolve(strict=True)==p.parent,'noncanonical local evidence')
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
 def unchanged(self):
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
def load_module(snapshot,name,rel,pin):
 raw=snapshot.pinned(B/rel,pin);m=types.ModuleType(name);m.__file__=str(B/rel)
 sys.modules[name]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m
def put(path,raw):
 need(path.parent.resolve(strict=True)==path.parent,'output parent changed')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def writej(path,value):return put(path,(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode())
def zero(v):return type(v) is int and v==0
def original_phone_zero(snapshot,path,stdout_raw):
 v=snapshot.json(path,maximum=32*1024*1024);phone=v.get('wrapper',{}).get('phone',{})
 need(zero(v.get('actor_rc')) and zero(phone.get('rc')),'original capture actor/phone terminal is not zero')
 need(isinstance(phone.get('stdout'),str) and phone['stdout'].encode()==stdout_raw,'original capture stdout differs')
 return v
def verify_capture(snapshot,kind,e,h,material,request,combo_raw,health_export,business_export):
 manifest=snapshot.json(e/'UNPACK-MANIFEST.json',maximum=4*1024*1024)
 if kind=='health':
  raw=snapshot.read(e/'ACTUAL-CAPTURE-01.json',maximum=4*1024*1024);cap=strict(raw);root=e
  need(health_export.capture_terminal_zero() is True,'health capture terminal original gate')
  original_phone_zero(snapshot,e/'capture-original-native-r7-r2-health-01.original-operation.json',raw)
  expected={'staged_request_and_registration','actual_source_config_service','unique_provider_owner_and_sender_scope','provider_start_exact_owner','durable_claim_scope_owner_run'}
  need(cap.get('state')=='CAPTURED_BOUND_ORIGINALS' and cap.get('export_complete') is True and cap.get('issues')==[]
       and set(cap.get('bindings',{}))==expected and all(v is True for v in cap['bindings'].values()),'health original capture incomplete')
  need(cap.get('owner_request_sha256')==sha(request) and cap.get('nonce')==material['nonce'],'health capture owner differs')
  listed={}
  for row in cap['files']:
   if row.get('state')!='captured':continue
   rel=relative(row['export_relative_path']);need(rel.parts[0] in ('registration','sources','provider-state'),'health snapshot root')
   body=base64.b64decode(row['raw_b64'],validate=True)
   need(len(body)==row['bytes'] and sha(body)==row['sha256'] and snapshot.read(root/rel)==body,'health original bytes differ')
   need(str(rel) not in listed,'duplicate captured file');listed[str(rel)]=(row['bytes'],row['sha256'])
  need({r['path']:(r['bytes'],r['sha256']) for r in manifest['files']}==listed,'health unpack manifest differs')
  native=[base64.b64decode(r['raw_b64'],validate=True) for r in cap['native_raw_records']]
  for b,r in zip(native,cap['native_raw_records']):need(len(b)==r['bytes'] and sha(b)==r['sha256'] and b.endswith(b'\n'),'health native original row differs')
  need(snapshot.read(root/'selected-native-raw.jsonl')==b''.join(native),'health native copy differs')
 else:
  root=e/'snapshot';result_raw=snapshot.read(e/'CAPTURE-RESULT.json',maximum=131072);result=strict(result_raw)
  bound=snapshot.json(e/'CAPTURE-BINDING.json',maximum=65536)
  need(bound['nonce']==material['nonce'] and bound['owner_request_sha256']==sha(request) and bound['combination_sha256']==sha(combo_raw),'business capture binding')
  need(business_export.capture_terminal_zero(e,bound) is True,'business original phone terminal')
  original_phone_zero(snapshot,e/('business-r7-r2-'+material['nonce']+'-capture.original-operation.json'),result_raw)
  cap_raw=snapshot.pinned(root/'CAPTURE.json',result['capture_sha256'],4*1024*1024);cap=strict(cap_raw)
  need(business_export.capture_complete(result,cap) is True,'business original capture incomplete')
  need(manifest.get('capture_process_completed_zero') is True and manifest.get('complete_original_capture') is True
       and manifest['capture_sha256']==sha(cap_raw) and manifest['archive_sha256']==result['archive']['sha256'],'business unpack completion')
  archive=snapshot.pinned(e/'originals.tar.gz',result['archive']['sha256'])
  need(len(archive)==result['archive']['bytes'],'business archive size')
  seen={};total=0
  with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
   for member in tar:
    rel=relative(member.name);need(member.isfile() and not member.issym() and not member.islnk() and str(rel) not in seen,'archive member kind/duplicate')
    need(member.size<=64*1024*1024 and len(seen)<776,'archive member bound')
    total+=member.size;need(total<=66*1024*1024,'archive expansion bound')
    stream=tar.extractfile(member);need(stream is not None,'archive body absent');body=stream.read(member.size+1)
    need(len(body)==member.size and snapshot.read(root/rel)==body,'archive original/copy differ')
    seen[str(rel)]=(len(body),sha(body))
  need(seen=={r['path']:(r['bytes'],r['sha256']) for r in manifest['files']},'archive manifest file set differs')
  originals={}
  for r in cap['files']:
   if r.get('state')=='captured':
    rel=str(relative(r['export_relative_path']));need(rel not in originals,'duplicate capture file');originals[rel]=(r['bytes'],r['sha256'])
  need(all(seen.get(k)==v for k,v in originals.items()),'original captured file pin differs')
  need(set(seen)==set(originals)|{'CAPTURE.json','host-bound-request.txt','selected-scope.json','selected-native-raw.jsonl'},'unlisted archive member')
  need(snapshot.read(root/'host-bound-request.txt')==request,'copied owner differs')
  native=snapshot.read(root/'selected-native-raw.jsonl').splitlines(keepends=True)
  need(len(native)==len(cap['native_raw_records']),'native captured row count')
  for body,row in zip(native,cap['native_raw_records']):need(body.endswith(b'\n') and len(body)==row['bytes'] and sha(body)==row['sha256'],'native captured row integrity')
 need(cap['selected_scope']==snapshot.json(root/'selected-scope.json').get('scope',snapshot.json(root/'selected-scope.json')),'selected original scope differs')
 return root,cap
def verify_models(snapshot,report,run,kind,material):
 rows=report['model_rounds'];need(rows and report['observed_model_request_count']==len(rows),'model round count')
 need([r['round'] for r in rows]==list(range(1,len(rows)+1)),'model rounds not consecutive')
 for row in rows:
  need(row.get('real_terminal_and_cleanup') is True and row.get('worker_joined') is True
       and row.get('server_slot_observed_idle_after') is True,'original model cleanup/idle unconfirmed')
  stem=run/('local-%02d'%row['round'])
  joined=snapshot.json(str(stem)+'.joined.json');spawn=snapshot.json(str(stem)+'.spawned.json')
  slot=snapshot.json(str(stem)+'.slot-after.json');worker=snapshot.json(str(stem)+'.worker-result.json')
  need(joined.get('child_wait_returned') is True and joined.get('dedicated_process_group_absent') is True
       and type(joined.get('pid')) is int and joined['pid']>1 and joined['pid']==spawn['pid']==spawn['process_group'],'original HTTP worker join/group binding')
  need(slot.get('observed') is True and slot.get('idle') is True and zero(worker.get('returncode')),'original slot/worker terminal')
  request=snapshot.read(str(stem)+'.request.json');response=snapshot.read(str(stem)+'.http-response.json')
  receipt=snapshot.json(str(stem)+'.http-receipt.json')
  need(type(receipt.get('attempt_count')) is int and receipt['attempt_count']==1 and receipt.get('automatic_retry') is False
       and receipt.get('fallback_model') is False and receipt.get('redirect_followed') is False
       and receipt.get('service_manifest_sha256')==SERVICE and receipt.get('request_sha256')==sha(request)
       and receipt.get('response_bytes')==len(response) and receipt.get('response_sha256')==sha(response)
       and receipt.get('request_id')==snapshot.json(str(stem)+'.images.json')['request_id']
       and receipt.get('http_status')==200,'HTTP request/response/attempt/service differs')
  # Exact request/response integrity and transport result were parsed by the byte-pinned original collector.
  need(row.get('http_response_complete') is True and row.get('transport_terminal')=='complete_http_response'
       and row.get('automatic_retry') is False and row.get('fallback_model') is False,'original HTTP transport not complete')
  if kind=='health':
   obj=strict(response);content=obj['choices'][0]['message']['content'];decision=strict(content)
   need(obj['choices'][0]['finish_reason']=='stop' and decision.get('kind')=='turn.complete'
        and decision.get('summary')==material['nonce'],'raw model health nonce differs')
 if kind=='health':need(len(rows)==1,'health must have exactly one model round')
def read_draft_receipts(snapshot,out,label,preserved):
 original=snapshot.json(preserved,maximum=131072)
 need(isinstance(original,dict) and isinstance(original.get('exact_utf8_b64'),str),'private original draft shape')
 draft=base64.b64decode(original['exact_utf8_b64'],validate=True);draft.decode('utf-8',errors='strict')
 need(draft and sha(draft)==original['utf8_sha256'],'private original draft integrity')
 remote_dir='/operator-home/codex-hepta-natural-'+label+'-root-v150'
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
def close(a):
 os.umask(0o077);snapshot=Originals((a.preserved_draft.absolute(),))
 for rel,pin in PINS.items():snapshot.pinned(B/rel,pin)
 combo_raw=snapshot.pinned(COMBO,COMBO_SHA);combo=strict(combo_raw)
 need(sha(canonical(combo))==CANON and combo['state']=='frozen' and combo['provider_source_seal_sha256']==SOURCE
      and combo['provider_config_sha256']==CONFIG and combo['service_inputs_sha256']==SERVICE,'full combination differs')
 auditor=load_module(snapshot,'native_journal_audit','acceptance-r7-r2/collector-r7/native_journal_audit.py',AUDIT)
 load_module(snapshot,'mobile_use_evidence','acceptance-r7-r2/business-collector-r7-r1/mobile_use_evidence.py',
             PINS['acceptance-r7-r2/business-collector-r7-r1/mobile_use_evidence.py'])
 business=load_module(snapshot,'closed_original_business','acceptance-r7-r2/business-collector-r7-r1/collect_business_evidence.py',
                      PINS['acceptance-r7-r2/business-collector-r7-r1/collect_business_evidence.py'])
 health_export=load_module(snapshot,'closed_health_export','health-r7-r2-original-export-r1/export_health_r7_once.py',
                          PINS['health-r7-r2-original-export-r1/export_health_r7_once.py'])
 business_export=load_module(snapshot,'closed_business_export','business-r7-r2-original-export-r1/export_business_once.py',
                            PINS['business-r7-r2-original-export-r1/export_business_once.py'])
 kind=a.kind;h=B/(kind+'-r7-r2-01');e=B/(kind+'-r7-r2-originals-01');label='phone-local-r7-r2-'+kind+'-01'
 material=snapshot.json(h/'material.json',maximum=131072);request=snapshot.read(h/'request.txt',maximum=24576)
 need(snapshot.read(h/'combination.json')==combo_raw and material['combination_manifest_sha256']==COMBO_SHA
      and material['request_sha256']==sha(request),'original material/full combination differs')
 need(re.fullmatch('[0-9a-f]{32}',material['nonce']) and request.decode().count(material['nonce'])==1,'original task nonce binding')
 case={'health':'HEALTH','visual':'E2E-01','unicode':'E2E-02'}[kind];need(material['case']==case,'material case differs')
 report_path=e/('health-audit-01' if kind=='health' else 'business-audit-01')/'REPORT.json'
 report_raw=snapshot.pinned(report_path,a.report_sha256);report=strict(report_raw)
 need(report['case_id']==case and report['candidate_source_seal_sha256']==SOURCE
      and report['request_utf8_sha256']==sha(request) and report.get('changed_after_snapshot')==[]
      and report.get('issues')==[],'original collector report identity/issues')
 result=snapshot.json(e/'COLLECTOR-RESULT.json',maximum=131072)
 need(zero(result.get('process_exit_code')) and result.get('report_sha256')==sha(report_raw)
      and result.get('report_path')==str(report_path) and result.get('original_capture_complete') is True,'collector actual terminal/integrity')
 snapshot.read(e/'collector.stdout');need(snapshot.read(e/'collector.stderr')==b'','collector stderr is not empty')
 for row in report['inputs']:
  source=Path(row['source']);copy=report_path.parent/relative(row['copy'])
  body=snapshot.pinned(source,row['sha256']);need(len(body)==row['bytes'] and snapshot.read(copy)==body,'collector input/raw copy differs')
 root,capture=verify_capture(snapshot,kind,e,h,material,request,combo_raw,health_export,business_export)
 scope=report['scope'];need(set(scope)==set(KEYS) and all(isinstance(scope[k],str) and scope[k] for k in KEYS),'exact scope shape')
 need(capture['selected_scope']==scope,'original capture/report scope differs')
 native_raw=snapshot.read(root/'selected-native-raw.jsonl');need(native_raw.endswith(b'\n'),'native raw boundary')
 records=[auditor.strict_loads(line) for line in native_raw.splitlines() if line]
 audit=auditor.verify_records(records,scope)
 need(audit['status']=='PASS' and audit['errors']==[] and audit['unsupported']==[]
      and audit['record_count']==audit['selected_scope_record_count']==audit['record_hashes_verified'],'independent native record/selected integrity')
 frames=audit['frames'];need(sum(f['kind']=='turn.accepted' for f in frames)==1
     and sum(f['kind']=='turn.end' for f in frames)==1 and frames[-1]['payload']==report['native_terminal'],'native terminal differs')
 digest=report['native_turn_request_sha256']
 need(re.fullmatch('[0-9a-f]{64}',digest) and all(f['payload'].get('turn_request_sha256')==digest for f in frames),'native envelope request hash differs')
 state=root/'provider-state';run=Path(report['snapshot_run_dir'])
 need(run.parent==state/'evidence' and re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',run.name),'original run path differs')
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
 calls=[r['call'] for r in outgoing if r['kind']=='tool.call'];results={r['call_id']:r for r in incoming if r['kind']=='tool.result'}
 need(len(calls)==len({c['call_id'] for c in calls})==report['observed_tool_dispatch_count']
      and len(report['tools'])==len(calls),'original tool dispatch count/identity')
 dispatched=[snapshot.json(p)['call'] for p in sorted(run.glob('dispatch-*.json'))]
 need(dispatched==calls,'original durable dispatch order')
 independently_checked=[]
 for call,previous in zip(calls,report['tools']):
  row=business.inspect_tool(snapshot,run,state,root/'executor-r6',root/'client-receipts',scope,call,results.get(call['call_id']),frames)
  need(row==previous and row.get('safe_original_execution_terminal') is True and row.get('unresolved_effect') is False
       and row.get('r6_terminal_identity_and_cleanup_verified') is True and row.get('native_raw_streams_equal') is True,'original effect terminal unresolved')
  independently_checked.append(row)
 for stage in ('tool.accepted','tool.started','tool.result'):
  matched=[f for f in frames if f['kind']==stage]
  need(len(matched)==len(calls) and {f['call_id'] for f in matched}=={c['call_id'] for c in calls},'native original tool lifecycle count')
 checks=report['checks']
 for name in ('source_seal_pin_matches','production_config_pin_matches','service_inputs_pin_matches',
              'pinned_runtime_source_bytes_verified','provider_terminal_persisted_and_last',
              'provider_native_terminal_agree','native_record_and_turn_integrity',
              'all_original_tool_evidence_aligned','no_unresolved_mutating_effects'):
  need(checks.get(name) is True,'original collector closure check not confirmed')
 verify_models(snapshot,report,run,kind,material)
 if kind=='health':need(calls==[],'health contains a tool')
 else:
  seal=snapshot.json(root/'sources/provider-r7/SOURCE-SEAL-v150-r7.json')
  projection=business.load_projection_api(snapshot,root/'sources/provider-r7/source',seal)
  original_rounds=business.inspect_rounds(snapshot,run,Path(report['original_run_dir']),request,projection,calls)
  need(original_rounds==report['model_rounds'],'original named action/model projection differs')
 out=B/(kind+'-r7-r2-closure-r1');out.mkdir(mode=0o700)
 writej(out/'CLOSURE-INTENT.private.json',{'kind':kind,'report_sha256':sha(report_raw),'combination_manifest_sha256':COMBO_SHA,
 'scope':scope,'native_request_sha256':digest,'original_draft_read_scope':'only two already produced P4 cleanup receipts',
 'phone_calls':0,'model_calls':0,'task_submissions':0,'automatic_retry':False})
 draft=read_draft_receipts(snapshot,out,label,a.preserved_draft)
 snapshot.unchanged()
 audit_copy={k:v for k,v in audit.items() if k not in ('selected_records','frames')}
 writej(out/'NATIVE-INDEPENDENT-AUDIT.private.json',audit_copy)
 put(out/'NATIVE-SELECTED-RAW.jsonl',native_raw)
 healthy=kind=='health' and report.get('health_qualification_pass') is True and result.get('health_qualification_pass') is True and report.get('proof_complete') is True and result.get('proof_complete') is True and status=='completed'
 business_success=kind!='health' and report.get('complete_business_success') is True and result.get('complete_business_success') is True and report.get('proof_complete') is True and result.get('proof_complete') is True and status=='completed'
 previous={'identity':scope,'request_sha256':digest,'terminal':report['native_terminal'],
  'known_no_phone_tool_execution':len(calls)==0,'known_all_dispatched_tools_confirmed_terminal':len(calls)>0,
  'scope':'Original task lifecycle closure only. Next sender must independently recheck current selection and global action gate.',
  'complete_business_success':business_success,'health_qualification_pass':healthy,
  'original_failed_status_unchanged':status!='completed','model_business_return_credit_from_draft_restore':False}
 prev=writej(out/'ACTUAL-PREVIOUS-INPUT.json',previous)
 closure={'schema':'hepta.root-host-original-closure.v150.r7.r2.1','state':'ORIGINAL_TASK_LIFECYCLE_CLOSED',
  'kind':kind,'native_status':status,'report_sha256':sha(report_raw),'combination_manifest_sha256':COMBO_SHA,
  'source_seal_sha256':SOURCE,'native_request_sha256':digest,'scope':scope,
  'capture_actor_and_phone_actual_zero':True,'collector_actual_exit_zero':True,
  'independent_native_audit':audit_copy,'model_round_count':len(report['model_rounds']),'tool_dispatch_count':len(calls),
  'all_original_effect_terminals_verified':True,'model_workers_joined_and_slots_observed_idle':True,
  'report_proof_complete_preserved':report['proof_complete'],'provider_native_text_agreement_preserved':checks.get('provider_native_terminal_text_agree'),
  'health_qualification_pass':healthy,'complete_business_success':business_success,'draft_cleanup':draft,
  'input_files_independently_rechecked':len(snapshot.observed),'input_bytes':snapshot.total,
  'previous':prev,'phone_calls':0,'model_calls':0,'new_send':0,'new_cancel':0,
  'old_effect_replayed':False,'service_changes':0,'permission_to_dispatch_not_inferred':True}
 rec=writej(out/'CLOSURE-CHECK.private.json',closure)
 public={'state':closure['state'],'kind':kind,'native_status':status,'health_qualification_pass':healthy,
  'complete_business_success':business_success,'original_tool_terminals_verified':len(calls),
  'exact_original_draft_restored':True,'original_draft_submitted':False,'phone_calls':0,'model_calls':0,
  'new_send':0,'new_cancel':0,'next_sender_still_requires_current_gates':True}
 writej(out/'SUMMARY.json',public);print(json.dumps(public,sort_keys=True));return 0
def expired(signum,frame):raise ClosureError('absolute host closure deadline')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('kind',choices=('health','visual','unicode'))
 p.add_argument('--report-sha256',required=True);p.add_argument('--preserved-draft',type=Path,required=True)
 p.add_argument('--execute-close-once',action='store_true');a=p.parse_args()
 need(re.fullmatch('[0-9a-f]{64}',a.report_sha256),'report pin shape')
 if not a.execute_close_once:print('prepared source only; no original reads or closure writes');return 0
 signal.signal(signal.SIGALRM,expired);signal.alarm(120)
 try:return close(a)
 except BaseException as error:
  print(json.dumps({'state':'CLOSURE_NOT_CONFIRMED','kind':a.kind,'error_class':type(error).__name__,
    'phone_calls':0,'model_calls':0,'new_send':0,'automatic_retry':False},sort_keys=True))
  raise
 finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
