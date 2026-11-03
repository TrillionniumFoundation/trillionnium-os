#!/usr/bin/env python3
"""Root-only r6 business original capture/export and frozen host collector.
No new nonce, registration, Send, UI, model/slot request, sidecar IPC or replay.
preview is local-only. capture/export require --execute-read-once.
"""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,os,re,shlex,signal,stat,subprocess,sys,tarfile,time
B=Path('/operator-workspace/razr60/phone-local-v150')
D=B/'business-r6-r2-original-export-r1'
S=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
SEAL_SHA='a8bd87b3d50c993b3e4ac7799ca66dd8e84cbd7925deb7e641e5cc66c1bdb7c1'
CONFIG_SHA='0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755'
SERVICE_SHA='ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2'
CAPTURE_SHA='d9f4e037ca45ac6d236137639fdb4c9525c8693c4dc4e68f404f79726efeff36'
CHUNK_SHA='a5f5659a3c8f44baf0277f2c44a0b06c73d042854aac88b47807002186103e44'
COLLECTOR_SHA='5719479507cd6f2366bb8848cb28a6f4a8d175a2ebc91332c77da2239b4fe899'
AUDITOR_SHA='da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'
RECHECK_SHA='0f9ccb8a9a29981af7eaca69624d00793d9e88bcfd5e1fbff71296a1c40bdfa6'
HARNESS_SHA='630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6'
MAX_ARCHIVE=64*1024*1024
CHUNK=1024*1024
SSH=['ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22',
 '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast']
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def strict(raw):
 def pairs(xs):
  value={}
  for k,v in xs:need(k not in value,'duplicate JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def meta(s):
 return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,limit=4*1024*1024,pin=None):
 p=Path(path);need(p.is_absolute() and p.parent.resolve(strict=True)==p.parent,'noncanonical local original')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=limit,'local file type/bound')
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
  need(meta(a)==meta(os.fstat(fd))==meta(p.lstat()) and len(raw)==a.st_size and len(raw)<=limit,'original changed/short')
  need(pin is None or sha(raw)==pin,'local source pin differs: '+p.name)
  return raw
 finally:os.close(fd)
def put(path,raw):
 p=Path(path);need(p.parent.resolve(strict=True)==p.parent,'output parent not canonical')
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def json_bytes(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
def writej(path,value):
 raw=json_bytes(value);put(path,raw);return raw
def mkdir(path):
 need(path.parent.resolve(strict=True)==path.parent,'new directory parent differs')
 path.mkdir(mode=0o700)
def child_path(path):
 p=Path(path).absolute()
 need(B in p.parents and p.parent.resolve(strict=True)==p.parent,'operator paths must stay in owned Main project')
 return p
def material_inputs(a):
 h=child_path(a.material);need(h.resolve(strict=True)==h and h.is_dir(),'material directory')
 e=child_path(a.out);need(e!=h and not (e in h.parents or h in e.parents),'material/output overlap')
 need(re.fullmatch('[a-z0-9][a-z0-9-]{5,80}',a.sender_label),'sender label format')
 material_raw=read(h/'material.json',131072);m=strict(material_raw)
 request=read(h/'request.txt',24576);combo_raw=read(h/'combination.json',65536);combo=strict(combo_raw)
 need(m.get('case') in ('E2E-01','E2E-02'),'only actual visual/Unicode material')
 need(m['candidate_source_seal_sha256']==SEAL_SHA and combo['provider_source_seal_sha256']==SEAL_SHA,'r6 source binding')
 need(m['request_sha256']==sha(request),'owner bytes differ from material')
 need(m['combination_manifest_sha256']==sha(combo_raw),'combination raw pin differs')
 need(combo['provider_config_sha256']==CONFIG_SHA and combo['service_inputs_sha256']==SERVICE_SHA
  and combo['state']=='frozen' and combo['cloud_fallback'] is False,'frozen r6 combination binding')
 nonce=m['nonce'];need(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce)
  and request.decode().count(nonce)==1,'exact existing material nonce')
 return h,e,m,material_raw,request,combo_raw
def sender_originals(e,label,owner_sha):
 p4='/operator-workspace/pocket4/codex-hepta-natural-'+label+'-root-v150'
 code=r"""from pathlib import Path
import base64,hashlib,json,os,stat
P=Path(P4PATH)
assert P.resolve(strict=True)==P and P.is_dir()
rows=[]
for name in ('SEND-NATIVE-LATENCY.json','SEND.MONOTONIC-WINDOW.json'):
 p=P/name;row={'source_path':str(p),'name':name};rows.append(row)
 try:fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError:row.update(state='absent',lookup_errno=2);continue
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=262144
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(262145)
  met=lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert met(a)==met(os.fstat(fd))==met(p.lstat()) and len(raw)==a.st_size
  row.update(state='captured',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),raw_b64=base64.b64encode(raw).decode(),stat=list(met(a)))
 finally:os.close(fd)
print(json.dumps({'schema':'hepta.business-sender-originals.readonly.v1','files':rows,'phone_calls':0,'draft_files_read':0},sort_keys=True,separators=(',',':')))
""".replace('P4PATH',repr(p4))
 r=subprocess.run(SSH+['python3','-I','-'],input=code.encode(),capture_output=True,timeout=20)
 put(e/'sender-fetch.stdout',r.stdout);put(e/'sender-fetch.stderr',r.stderr)
 need(r.returncode==0 and len(r.stdout)<=1024*1024,'P4 original sender read failed; no phone capture issued')
 envelope=strict(r.stdout);rows=envelope['files'];need(len(rows)==2,'sender original count')
 found={}
 for row in rows:
  name=row['name'];need(name in ('SEND-NATIVE-LATENCY.json','SEND.MONOTONIC-WINDOW.json') and name not in found,'sender name')
  if row['state']!='captured':continue
  raw=base64.b64decode(row['raw_b64'],validate=True)
  need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original sender bytes')
  put(e/'sender'/name,raw);found[name]=strict(raw)
 latency=found.get('SEND-NATIVE-LATENCY.json');need(isinstance(latency,dict),'original sender latency absent')
 need(latency.get('owner_request_utf8_sha256')==owner_sha and latency.get('send_attempt_count')==1
  and latency.get('automatic_send_retry') is False,'one original Send and exact owner required')
 scope=latency.get('scope');need(isinstance(scope,dict) and set(scope)==set(KEYS),'actual accepted scope required')
 obs=latency.get('original_observation');need(isinstance(obs,dict) and obs.get('provider_match_count')==1,'unique original observation')
 match=obs.get('match');need(isinstance(match,dict) and match.get('evidence_root_mode')=='production'
  and match.get('scope')==scope and match.get('owner_utf8_sha256')==owner_sha,'original production observation binding')
 run=Path(match['run_dir'])
 need(run.parent==S/'provider-state/evidence'
  and re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',run.name),'original run path')
 line=base64.b64decode(match['provider_start_original_b64'],validate=True)
 need(len(line)==match['provider_start_original_bytes'] and sha(line)==match['provider_start_original_sha256'],'sender raw start integrity')
 frame=strict(line);need(frame.get('kind')=='turn.start'
  and {k:frame['turn'][k] for k in KEYS}==scope
  and sha(frame['turn']['user_input'].encode())==owner_sha,'sender raw start binding')
 return scope,run.name
def harness(e):
 p=B/'root-operators-r6-cycle03/run_cycle03.py';read(p,16384,HARNESS_SHA)
 spec=importlib.util.spec_from_file_location('root_business_original_transport',p)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.D=e
 return m
def phone_request(source,bound,timeout):
 arg=base64.b64encode(json.dumps(bound,sort_keys=True,separators=(',',':')).encode()).decode()
 command='/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -B -c '+shlex.quote(source)+' '+shlex.quote(arg)
 return {'kind':'shell','root':True,'timeout_seconds':timeout,'command':command}
def original_operation(m,e,label,req,limit):
 # Persistent exclusive intent prevents re-dispatch after an unknown transport result.
 writej(e/(label+'.request.json'),req)
 try:ph=m.call_phone(label,req)
 except AssertionError:
  wrapper=strict(read(e/(label+'.original-operation.json'),limit+2*1024*1024))
  ph=wrapper['wrapper'].get('phone',{})
 need(isinstance(ph.get('stdout'),str),'no original output; inspect the same operation, never recapture')
 raw=ph['stdout'].encode();need(len(raw)<=limit,'original operation stdout bound')
 return ph,raw
def capture_once(a):
 h,e,m,material_raw,request,combo_raw=material_inputs(a)
 read(B/'send_new_native_task_r5.py',65536,'5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281')
 intent_raw=read(B/(a.sender_label+'.local-once.json'),131072);intent=strict(intent_raw)
 need(intent['task']==a.sender_label and intent['prompt'].encode()==request
  and intent['prompt_sha256']==sha(request) and intent['evidence_root_mode']=='production'
  and intent['automatic_replay'] is False,'actual sender exclusive intent binding')
 sender_raw=read(B/(a.sender_label+'.send-result.json'),2*1024*1024)
 source=read(D/'capture_business_originals.py',65536,CAPTURE_SHA).decode()
 mkdir(e);mkdir(e/'sender');mkdir(e/'host-inputs');mkdir(e/'chunks')
 for name,raw in (('material.json',material_raw),('request.txt',request),('combination.json',combo_raw),
  ('sender-local-once.json',intent_raw),('sender-send-result.json',sender_raw)):
  put(e/'host-inputs'/name,raw)
 for name in ('postconditions.json','expected-text.txt','expected-public-receipt.txt'):
  p=h/name
  if p.exists():put(e/'host-inputs'/name,read(p,131072))
 scope,run=sender_originals(e,a.sender_label,sha(request))
 bound={'nonce':m['nonce'],'case_id':m['case'],'owner_request_sha256':sha(request),
  'request_b64':base64.b64encode(request).decode(),'combination_sha256':sha(combo_raw),
  'sender_scope':scope,'sender_run':run,'sender_label':a.sender_label}
 writej(e/'CAPTURE-BINDING.json',bound)
 label='business-r6-r2-'+m['nonce']+'-capture'
 ph,raw=original_operation(harness(e),e,label,phone_request(source,bound,75),131072)
 put(e/'CAPTURE-RESULT.json',raw);result=strict(raw)
 original_raw=read(e/(label+'.original-operation.json'),2*1024*1024)
 original=strict(original_raw);original_phone=original['wrapper'].get('phone',{})
 need(original_phone.get('rc')==ph.get('rc') and original_phone.get('stdout')==ph.get('stdout'),
  'capture process terminal differs from retained original')
 writej(e/'CAPTURE-TERMINAL.json',{'schema':'hepta.business-capture-process-terminal.v150.r6.2',
  'nonce':m['nonce'],'owner_request_sha256':sha(request),'operation_label':label,
  'original_operation_sha256':sha(original_raw),'capture_result_sha256':sha(raw),
  'phone_process_rc':original_phone.get('rc'),'actor_rc':original.get('actor_rc'),
  'capture_process_completed_zero':type(original_phone.get('rc')) is int and original_phone['rc']==0})
 need(result.get('schema')=='hepta.business-original-capture-result.v150.r6.1'
  and result.get('nonce')==m['nonce'] and result.get('owner_request_sha256')==sha(request)
  and result.get('combination_sha256')==sha(combo_raw) and result.get('selected_scope')==scope,'capture result binding')
 need(result.get('archive') is not None,'capture produced no archive; original result retained; do not recapture')
 return export_originals(a)
def safe_member(name):
 p=Path(name)
 need(not p.is_absolute() and p.parts and all(re.fullmatch('[A-Za-z0-9._-]+',v)
  and v not in ('.','..') for v in p.parts),'unsafe archive member')
 need(p.parts[0] in ('provider-state','sources','client-receipts','executor-r6',
  'CAPTURE.json','host-bound-request.txt','selected-scope.json','selected-native-raw.jsonl'),'archive root not allowed')
 return p
def capture_terminal_zero(e,bound):
 label='business-r6-r2-'+bound['nonce']+'-capture'
 terminal=strict(read(e/'CAPTURE-TERMINAL.json',65536))
 original_raw=read(e/(label+'.original-operation.json'),2*1024*1024)
 original=strict(original_raw);phone=original['wrapper'].get('phone',{})
 result_raw=read(e/'CAPTURE-RESULT.json',131072)
 need(terminal.get('schema')=='hepta.business-capture-process-terminal.v150.r6.2'
  and terminal.get('nonce')==bound['nonce'] and terminal.get('owner_request_sha256')==bound['owner_request_sha256']
  and terminal.get('operation_label')==label and terminal.get('original_operation_sha256')==sha(original_raw)
  and terminal.get('capture_result_sha256')==sha(result_raw)
  and terminal.get('phone_process_rc')==phone.get('rc')
  and terminal.get('actor_rc')==original.get('actor_rc')
  and isinstance(phone.get('stdout'),str) and phone['stdout'].encode()==result_raw,
  'capture process terminal original binding differs')
 actual_zero=type(phone.get('rc')) is int and phone['rc']==0
 need(terminal.get('capture_process_completed_zero') is actual_zero,'capture zero-exit marker differs')
 return actual_zero
def final_qualification(capture_is_complete,process_rc,report):
 process_zero=type(process_rc) is int and process_rc==0
 return {'proof_complete':capture_is_complete is True and process_zero and report.get('proof_complete') is True,
  'complete_business_success':capture_is_complete is True and process_zero and report.get('complete_business_success') is True,
  'task_classification':(report.get('task_classification') if process_zero else 'unconfirmed_collector_process')
   if capture_is_complete is True else 'unconfirmed_original_capture'}
def capture_complete(result,capture):
 expected={'actual_source_config_service_client','unique_provider_owner_and_sender_scope',
  'provider_start_exact_owner','durable_claim_scope_owner_run','original_task_contract_files_retained',
  'dispatched_tool_originals_enumerated','original_native_scope_retained'}
 return (result.get('export_complete') is True and result.get('issues')==[]
  and capture.get('state')=='CAPTURED_BOUND_ORIGINALS' and capture.get('export_complete') is True
  and capture.get('issues')==[] and isinstance(capture.get('bindings'),dict)
  and set(capture['bindings'])==expected and all(v is True for v in capture['bindings'].values()))
def unpack(e,result,bound,capture_process_completed_zero):
 root=e/'snapshot';mkdir(root);archive=e/'originals.tar.gz';seen={};total=0
 with tarfile.open(archive,'r:gz') as t:
  for member in t:
   need(member.isfile() and not member.issym() and not member.islnk(),'nonregular archive member')
   rel=safe_member(member.name);need(str(rel) not in seen and len(seen)<776,'archive duplicate/count')
   need(0<=member.size<=(MAX_ARCHIVE if str(rel)=='selected-native-raw.jsonl' else 16*1024*1024),'archive member size')
   total+=member.size;need(total<=MAX_ARCHIVE+2*1024*1024,'archive expansion budget')
   stream=t.extractfile(member);need(stream is not None,'archive file body absent')
   raw=stream.read(member.size+1);need(len(raw)==member.size,'archive short body')
   p=root/rel;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);put(p,raw)
   seen[str(rel)]={'bytes':len(raw),'sha256':sha(raw)}
 capture_raw=read(root/'CAPTURE.json',2*1024*1024,result['capture_sha256']);capture=strict(capture_raw)
 need(capture.get('schema')=='hepta.business-original-capture.v150.r6.1'
  and capture.get('owner_request_sha256')==bound['owner_request_sha256']
  and capture.get('nonce')==bound['nonce'] and capture.get('selected_scope')==bound['sender_scope']
  and capture.get('combination_sha256')==bound['combination_sha256'],'archived capture binding')
 rows=capture.get('files',[]);need(len(rows)<=768,'capture original file count')
 expected=set()
 for row in rows:
  if row.get('state')!='captured':continue
  rel=str(safe_member(row['export_relative_path']));need(rel not in expected,'capture duplicate original path')
  expected.add(rel);need(seen.get(rel)=={'bytes':row['bytes'],'sha256':row['sha256']},'original snapshot file differs')
 generated={'CAPTURE.json','host-bound-request.txt','selected-scope.json','selected-native-raw.jsonl'}
 need(set(seen)==expected|(set(seen)&generated),'unlisted archive file')
 need(read(root/'host-bound-request.txt',24576)==base64.b64decode(bound['request_b64'],validate=True),'copied owner bytes differ')
 native=[]
 if (root/'selected-native-raw.jsonl').exists():
  native=read(root/'selected-native-raw.jsonl',MAX_ARCHIVE).splitlines(keepends=True)
 need(len(native)==len(capture['native_raw_records']),'original raw native record count')
 for line,row in zip(native,capture['native_raw_records']):
  need(line.endswith(b'\n') and len(line)==row['bytes'] and sha(line)==row['sha256'],'original native raw bytes differ')
  need(strict(line).get('scope')==bound['sender_scope'],'original native selected scope differs')
 complete=(capture_process_completed_zero is True and capture_complete(result,capture) and generated<=set(seen))
 manifest={'schema':'hepta.business-original-unpack.v150.r6.1','complete_original_capture':complete,
  'capture_sha256':sha(capture_raw),'archive_sha256':result['archive']['sha256'],
  'capture_process_completed_zero':capture_process_completed_zero is True,
  'files':[{'path':k,**v} for k,v in sorted(seen.items())],'native_raw_record_count':len(native),
  'qualified_business_success':False,'phone_ui_actions':0,'model_requests':0,'original_file_writes':0,
  'transport_phases_preserved_only':'Existing collector validates claim/result/receipt; this wrapper does not add a 15-phase audit claim.',
  'no_empty_directory_absence_inference':True}
 # Real absence is recorded in CAPTURE.json; local empty dirs are only collector paths.
 for p in (root/'executor-r6/actions',root/'client-receipts',root/'provider-state/evidence/action-ledger'):
  p.mkdir(mode=0o700,parents=True,exist_ok=True)
 writej(e/'UNPACK-MANIFEST.json',manifest)
 return manifest
def export_originals(a):
 h,e,m,mraw,request,combo_raw=material_inputs(a)
 bound=strict(read(e/'CAPTURE-BINDING.json',65536));result=strict(read(e/'CAPTURE-RESULT.json',131072))
 need(bound['nonce']==m['nonce'] and bound['owner_request_sha256']==sha(request)
  and bound['combination_sha256']==sha(combo_raw) and bound['sender_label']==a.sender_label,'stored export identity differs')
 archive=result.get('archive');need(isinstance(archive,dict),'no original archive metadata')
 size=archive.get('bytes');need(type(size) is int and 0<size<=MAX_ARCHIVE,'original archive size')
 need(archive['path']==str(S/'business-original-captures-r6-r2'/m['nonce']/'originals.tar.gz'),'original archive path')
 source=read(D/'read_archive_chunk.py',8192,CHUNK_SHA).decode();transport=harness(e)
 start=time.monotonic();rows=[]
 for offset in range(0,size,CHUNK):
  need(time.monotonic()-start<300,'export read budget expired; preserve existing chunks, no capture replay')
  index=offset//CHUNK;p=e/'chunks'/('%03d.bin'%index)
  wanted=min(CHUNK,size-offset)
  if p.exists():
   raw=read(p,CHUNK);saved=strict(read(e/'chunks'/('%03d.json'%index),65536))
   need(saved['offset']==offset and len(raw)==wanted and sha(raw)==saved['sha256']
    and saved['archive_sha256']==archive['sha256'],'existing original chunk differs')
   rows.append(saved);continue
  b={'nonce':m['nonce'],'archive_sha256':archive['sha256'],'archive_bytes':size,
     'archive_stat':archive['stat'],'offset':offset}
  label='business-r6-r2-'+m['nonce']+'-chunk-%03d'%index
  ph,raw=original_operation(transport,e,label,phone_request(source,b,10),2*1024*1024)
  need(ph.get('rc')==0,'original archive chunk read failed; inspect retained original')
  v=strict(raw);need(v.get('schema')=='hepta.business-archive-chunk.v150.r6.1'
   and v.get('nonce')==m['nonce'] and v.get('archive_sha256')==archive['sha256']
   and v.get('archive_stat')==archive['stat'] and v.get('archive_bytes')==size and v.get('offset')==offset,
   'original chunk binding differs')
  data=base64.b64decode(v['raw_b64'],validate=True)
  need(len(data)==wanted==v['bytes'] and sha(data)==v['sha256']
   and v.get('eof') is (offset+wanted==size),'original chunk length/hash/eof')
  put(p,data);saved={k:v[k] for k in ('offset','bytes','sha256','archive_sha256','eof')}
  writej(e/'chunks'/('%03d.json'%index),saved);rows.append(saved)
 destination=e/'originals.tar.gz';fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 digest=hashlib.sha256();written=0
 with os.fdopen(fd,'wb') as f:
  for index,row in enumerate(rows):
   raw=read(e/'chunks'/('%03d.bin'%index),CHUNK,row['sha256']);f.write(raw);digest.update(raw);written+=len(raw)
  f.flush();os.fsync(f.fileno())
 need(written==size and digest.hexdigest()==archive['sha256'],'whole archive hash differs')
 manifest=unpack(e,result,bound,capture_terminal_zero(e,bound))
 outcome={'state':'ORIGINALS_EXPORTED' if manifest['complete_original_capture'] else 'PARTIAL_ORIGINALS_RETAINED',
  'original_capture_complete':manifest['complete_original_capture'],'archive_sha256':digest.hexdigest(),
  'archive_bytes':written,'captured_file_count':len(manifest['files']),
  'native_raw_record_count':manifest['native_raw_record_count'],'chunks':len(rows),
  'elapsed_export_seconds':time.monotonic()-start,'task_submissions':0,'phone_ui_actions':0,
  'model_requests':0,'automatic_capture_retry':False,'qualification':False}
 writej(e/'EXPORT-RESULT.json',outcome);print(json.dumps(outcome,sort_keys=True))
 return 0 if outcome['original_capture_complete'] else 2
def collect(a):
 h,e,m,mraw,request,combo_raw=material_inputs(a)
 manifest=strict(read(e/'UNPACK-MANIFEST.json',2*1024*1024));root=e/'snapshot'
 bound=strict(read(e/'CAPTURE-BINDING.json',65536))
 need(read(root/'host-bound-request.txt',24576)==request and bound['owner_request_sha256']==sha(request)
  and bound['combination_sha256']==sha(combo_raw),'host/phone original identity differs')
 # Recheck every exported snapshot file before using a collection result.
 for row in manifest['files']:
  read(root/safe_member(row['path']),MAX_ARCHIVE,row['sha256'])
 collector=B/'acceptance-r5/business-collector-r5-r1'
 for name,pin in (('collect_business_evidence.py',COLLECTOR_SHA),
  ('native_journal_audit.py',AUDITOR_SHA),('business_fact_recheck.py',RECHECK_SHA)):
  read(collector/name,65536,pin)
 args=[sys.executable,'-B',str(collector/'collect_business_evidence.py'),
  '--provider-state',str(root/'provider-state'),
  '--run-dir',str(root/'provider-state/evidence'/bound['sender_run']),
  '--request-file',str(root/'host-bound-request.txt'),'--selected-scope-file',str(root/'selected-scope.json'),
  '--native-journal',str(root/'selected-native-raw.jsonl'),'--sidecar-journal',str(root/'executor-r6'),
  '--client-receipts',str(root/'client-receipts'),
  '--source-seal',str(root/'sources/provider-r6-r2/SOURCE-SEAL-v150-r6-r2.json'),
  '--source-seal-sha256',SEAL_SHA,'--provider-source',str(root/'sources/provider-r6-r2/source'),
  '--config-file',str(root/'sources/local-config-r6-r2.json'),
  '--service-manifest',str(root/'sources/PHONE-SERVICE-INPUTS-v150-r3.json'),
  '--nonce',m['nonce'],'--case-id',m['case'],'--out',str(e/'business-audit-01'),'--max-total-mib','128']
 writej(e/'COLLECTOR-INTENT.json',{'argv':args,'source_sha256':COLLECTOR_SHA,'phone_calls':0,'model_requests':0})
 process=subprocess.run(args,capture_output=True,timeout=90)
 put(e/'collector.stdout',process.stdout);put(e/'collector.stderr',process.stderr)
 report_path=e/'business-audit-01/REPORT.json'
 report_raw=read(report_path,8*1024*1024) if report_path.exists() else None
 report=strict(report_raw) if report_raw is not None else {}
 capture_result=strict(read(e/'CAPTURE-RESULT.json',131072))
 capture_raw=read(root/'CAPTURE.json',2*1024*1024,capture_result['capture_sha256'])
 original_capture=strict(capture_raw)
 complete=(capture_terminal_zero(e,bound) is True
  and manifest.get('capture_process_completed_zero') is True
  and manifest.get('complete_original_capture') is True
  and manifest['capture_sha256']==sha(capture_raw)
  and manifest['archive_sha256']==capture_result['archive']['sha256']
  and original_capture.get('selected_scope')==bound['sender_scope']
  and original_capture.get('owner_request_sha256')==sha(request)
  and original_capture.get('combination_sha256')==sha(combo_raw)
  and capture_complete(capture_result,original_capture))
 flags=final_qualification(complete,process.returncode,report)
 result={'state':'HOST_BUSINESS_COLLECTOR_TERMINAL','process_exit_code':process.returncode,
  'report_path':str(report_path),'report_sha256':sha(report_raw) if report_raw is not None else None,
  'source_seal_sha256':SEAL_SHA,'collector_source_sha256':COLLECTOR_SHA,
  'original_capture_complete':complete,'raw_collector_proof_complete':report.get('proof_complete') is True,
  'raw_collector_complete_business_success':report.get('complete_business_success') is True,
  'proof_complete':flags['proof_complete'],
  'complete_business_success':flags['complete_business_success'],
  'raw_collector_task_classification':report.get('task_classification'),
  'task_classification':flags['task_classification'],
  'case_id':m['case'],'phone_calls':0,'model_requests':0,'automatic_retry':False,
  'new_previous_input_generated':False,'fixed19_attempt_automatically_written':False}
 writej(e/'COLLECTOR-RESULT.json',result);print(json.dumps(result,sort_keys=True))
 return 0 if process.returncode==0 and result['complete_business_success'] and result['proof_complete'] else 2
def phase_expired(signum,frame):
 raise TimeoutError('Root operator phase bound expired; inspect retained original operation, never resubmit')
def main():
 os.umask(0o077)
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('phase',choices=('preview','capture','export','collect'))
 p.add_argument('--material',type=Path,required=True)
 p.add_argument('--sender-label',required=True)
 p.add_argument('--out',type=Path,required=True)
 p.add_argument('--execute-read-once',action='store_true')
 a=p.parse_args()
 if a.phase=='preview':
  need(not a.execute_read_once,'preview performs no phone call')
  h,e,m,mraw,request,combo=material_inputs(a)
  print(json.dumps({'state':'HOST_ONLY_PREVIEW','case_id':m['case'],'material':str(h),'output':str(e),
   'source_seal_sha256':SEAL_SHA,'collector_sha256':COLLECTOR_SHA,'phone_calls':0,
   'nonce_generated':False,'originals_only_after_actual_sender':True,
   'capture_root':str(S/'business-original-captures-r6-r2'),
   'capture_seconds':50,'finalize_seconds':15,'export_phase_seconds':300,'collector_seconds':90,
   'automatic_capture_retry':False,'qualification':False},sort_keys=True));return 0
 if a.phase in ('capture','export'):
  need(a.execute_read_once,'Root must explicitly select --execute-read-once')
  signal.signal(signal.SIGALRM,phase_expired)
  signal.setitimer(signal.ITIMER_REAL,480 if a.phase=='capture' else 360)
  try:return capture_once(a) if a.phase=='capture' else export_originals(a)
  finally:signal.setitimer(signal.ITIMER_REAL,0)
 need(not a.execute_read_once,'collect is host-only')
 signal.signal(signal.SIGALRM,phase_expired);signal.setitimer(signal.ITIMER_REAL,120)
 try:return collect(a)
 finally:signal.setitimer(signal.ITIMER_REAL,0)
if __name__=='__main__':sys.exit(main())
