#!/usr/bin/env python3
"""Root-only fixed health-r7-r3-01 export and host collection. No nonce generation.
capture invokes one reviewed read-only phone operation; collect is host-only.
No Send, tool execute, model/slot query, service action, key or draft read exists.
"""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,os,re,shlex,stat,subprocess,sys
B=Path('/operator-workspace/phone-local-v150')
D=B/'health-r7-r3-original-export-r1'
H=B/'health-r7-r3-01'
E=B/'health-r7-r3-originals-01'
LABEL='phone-local-r7-r3-health-01'
OP='capture-original-native-r7-r3-health-01'
P4=Path('/operator-home/codex-hepta-natural-'+LABEL+'-root-v150')
PHONE_SOURCE_SHA='4c9cc49a3c89d6fd70c74e1ef67e8428424963a82a35405a981f1113fa9a802f'
PREVIOUS_SHA='<ROOT_REVIEWED_CURRENT_PREVIOUS_SHA256_REQUIRED>'
COLLECTOR_SHA='887d28ae2cc09fe857ab01fac19bbb32d14e35c5d78b230bb82950a6d956dbf2'
SEAL_SHA='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
SSH=['ssh','-J','operator-jump-host','-o','HostName=192.0.2.4','-p','22','-o','BatchMode=yes',
     '-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','operator-secondary-host']
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def strict(raw):
 def pairs(xs):
  value={}
  for k,v in xs:need(k not in value,'duplicate JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda v:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def local_read(path,limit=4*1024*1024,pin=None):
 path=Path(path);need(path.parent.resolve(strict=True)==path.parent,'noncanonical local parent')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=limit,'local file bound/type')
  data=[]
  with os.fdopen(fd,'rb',closefd=False) as f:
   raw=f.read(limit+1)
  b=os.fstat(fd);c=path.lstat()
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(identity(a)==identity(b)==identity(c) and len(raw)==a.st_size and len(raw)<=limit,'local original changed')
  need(pin is None or sha(raw)==pin,'local pin differs: '+path.name)
  return raw
 finally:os.close(fd)
def put(path,raw):
 path=Path(path);need(path.parent.resolve(strict=True)==path.parent,'output parent changed')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def writej(path,value):
 raw=(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 put(path,raw);return raw
def mkdir(path):
 path=Path(path);need(path.parent.resolve(strict=True)==path.parent,'new directory parent not canonical')
 path.mkdir(mode=0o700)
def inputs():
 material_raw=local_read(H/'material.json',65536);material=strict(material_raw)
 request=local_read(H/'request.txt',16000);combo=local_read(H/'combination.json',65536)
 need(material['request_sha256']==sha(request),'material owner SHA differs')
 nonce=material['nonce'];need(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'nonce format')
 need(request.decode('utf-8').count(nonce)==1,'one exact material nonce required')
 previous_raw=local_read(B/'private/current-closed-task/previous.json',65536,PREVIOUS_SHA)
 previous=strict(previous_raw)
 need(previous['terminal']['status']=='provider_failed' and previous['known_no_phone_tool_execution'] is False and previous['known_all_dispatched_tools_confirmed_terminal'] is True,'current previous disposition')
 return material,request,combo,previous,material_raw
def p4_sender_originals():
 # This remote program reads exactly two existing actor receipts. No phone import/call.
 code="""from pathlib import Path
import base64,hashlib,json,os,stat
P=Path("""+repr(str(P4))+""")
assert P.resolve(strict=True)==P and P.is_dir()
rows=[]
for name in ('SEND-NATIVE-LATENCY.json','SEND.MONOTONIC-WINDOW.json'):
 p=P/name;row={'source_path':str(p),'name':name};rows.append(row)
 try:
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError:row.update(state='absent',lookup_errno=2);continue
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=262144
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(262145)
  b=os.fstat(fd);c=p.lstat()
  met=lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert met(a)==met(b)==met(c) and len(raw)==a.st_size and len(raw)<=262144
  row.update(state='captured',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),raw_b64=base64.b64encode(raw).decode(),stat=list(met(a)),eof=True)
 finally:os.close(fd)
print(json.dumps({'schema':'hepta.health-sender-originals.readonly.v1','files':rows,'phone_calls':0,'draft_files_read':0},sort_keys=True,separators=(',',':')))
"""
 r=subprocess.run(SSH+['python3','-I','-'],input=code.encode(),capture_output=True,timeout=20)
 put(E/'sender-fetch.stdout',r.stdout);put(E/'sender-fetch.stderr',r.stderr)
 need(r.returncode==0,'P4 sender original read failed; retained, no phone export dispatched')
 need(len(r.stdout)<=1024*1024,'sender envelope size')
 envelope=strict(r.stdout);rows=envelope['files'];need(len(rows)==2,'sender original count')
 found={}
 for row in rows:
  need(row['name'] in ('SEND-NATIVE-LATENCY.json','SEND.MONOTONIC-WINDOW.json'),'unexpected sender path')
  if row['state']!='captured':continue
  raw=base64.b64decode(row['raw_b64'],validate=True)
  need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'sender original bytes differ')
  put(E/'sender'/row['name'],raw);found[row['name']]=strict(raw)
 return found
def unpack(capture):
 rows=capture.get('files',[]);need(len(rows)<=160,'export file count')
 preserved=[];seen=set()
 for row in rows:
  if row.get('state')!='captured':continue
  rel=Path(row['export_relative_path'])
  need(not rel.is_absolute() and '..' not in rel.parts and len(rel.parts)>1,'unsafe captured relative path')
  need(rel.parts[0] in ('registration','sources','provider-state'),'unapproved captured export root')
  need(rel.name not in ('api.key','llama-api.key') and 'DRAFT' not in rel.name,'private key/draft must not be exported')
  need(str(rel) not in seen,'duplicate captured path');seen.add(str(rel))
  raw=base64.b64decode(row['raw_b64'],validate=True)
  need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'captured original integrity')
  out=E/rel;out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  need(out.parent.resolve()==out.parent,'unsafe output parent')
  put(out,raw);preserved.append({'path':str(rel),'bytes':len(raw),'sha256':sha(raw),'source_path':row['source_path']})
 scope=capture.get('selected_scope')
 raw_native=[]
 for row in capture.get('native_raw_records',[]):
  raw=base64.b64decode(row['raw_b64'],validate=True)
  need(raw.endswith(b'\n') and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'native raw row integrity')
  need(scope is not None and strict(raw).get('scope')==scope,'native exact scope')
  raw_native.append(raw)
 if scope is not None:
  need(set(scope)==set(KEYS),'actual scope fields')
  writej(E/'selected-scope.json',{'scope':scope,'source':'actual provider-in and original sender observation; no inferred task identity'})
 if raw_native:put(E/'selected-native-raw.jsonl',b''.join(raw_native))
 # These paths make zero-tool collector inputs explicit. Empty local directories
 # are not evidence that the phone had no actions; original census is in capture.
 for p in (E/'executor-r6',E/'client-receipts'):p.mkdir(mode=0o700,exist_ok=False)
 manifest={'schema':'hepta.health-original-export-unpack.v150.r6.1','files':preserved,
  'native_raw_record_count':len(raw_native),'native_raw_bytes':sum(map(len,raw_native)),
  'original_capture_state':capture.get('state'),'export_complete':capture.get('export_complete') is True,
  'phone_actions':0,'model_calls':0,'qualification':False,
  'no_action_absence_inferred_from_local_directories':True,'original_user_draft_not_read':True,'key_files_not_read':True}
 writej(E/'UNPACK-MANIFEST.json',manifest)
 return manifest

def capture_terminal_zero():
 raw=local_read(E/'ACTUAL-CAPTURE-01.json',4*1024*1024)
 original_raw=local_read(E/(OP+'.original-operation.json'),8*1024*1024)
 original=strict(original_raw);phone=original.get('wrapper',{}).get('phone',{})
 terminal=strict(local_read(E/'CAPTURE-TERMINAL.json',65536))
 need(terminal.get('schema')=='hepta.health-capture-process-terminal.v150.r7.1'
  and terminal.get('operation_label')==OP
  and terminal.get('original_operation_sha256')==sha(original_raw)
  and terminal.get('capture_sha256')==sha(raw)
  and terminal.get('phone_process_rc')==phone.get('rc')
  and terminal.get('actor_rc')==original.get('actor_rc')
  and isinstance(phone.get('stdout'),str) and phone['stdout'].encode('utf-8')==raw,
  'capture process terminal differs from its original wrapper')
 actual_zero=(type(phone.get('rc')) is int and phone['rc']==0
  and type(original.get('actor_rc')) is int and original['actor_rc']==0)
 need(terminal.get('capture_process_completed_zero') is actual_zero,'capture zero marker differs')
 return actual_zero

def final_health_qualification(capture_complete,process_rc,report):
 process_zero=type(process_rc) is int and process_rc==0
 return {'health_qualification_pass':capture_complete is True and process_zero
          and report.get('health_qualification_pass') is True,
  'proof_complete':capture_complete is True and process_zero and report.get('proof_complete') is True,
  'task_classification':(report.get('task_classification') if process_zero else 'unconfirmed_collector_process')
     if capture_complete is True else 'unconfirmed_original_capture'}

def capture_once():
 os.umask(0o077)
 material,request,combo,previous,material_raw=inputs()
 local_read(B/'send_new_native_task_r5.py',65536,'5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281')
 intent_raw=local_read(B/(LABEL+'.local-once.json'),65536);intent=strict(intent_raw)
 need(intent['task']==LABEL and intent['prompt'].encode('utf-8')==request and intent['prompt_sha256']==sha(request),'actual sender intent differs')
 need(intent['previous_identity']==previous['identity'] and intent['previous_digest']==previous['request_sha256'],'sender must use current Root-closed failed previous with all original tools confirmed terminal')
 need(intent['evidence_root_mode']=='production' and intent['automatic_replay'] is False,'sender production/no replay binding')
 sender_raw=local_read(B/(LABEL+'.send-result.json'),1024*1024);sender=strict(sender_raw)
 summary=None
 if isinstance(sender.get('stdout'),str):
  try:summary=strict(sender['stdout'])
  except (ValueError,TypeError):pass
 if isinstance(summary,dict):
  need(summary.get('prompt_sha256')==sha(request) and summary.get('out')==str(P4),'sender actual summary identity')
  need(summary.get('send_attempt_count')==1,'sender reports zero or multiple Send; no phone capture issued')
 mkdir(E);mkdir(E/'sender');mkdir(E/'host-inputs')
 for name,raw in [('material.json',material_raw),('request.txt',request),('combination.json',combo),
                  ('sender-local-once.json',intent_raw),('sender-send-result.json',sender_raw)]:
  put(E/'host-inputs'/name,raw)
 found=p4_sender_originals();latency=found.get('SEND-NATIVE-LATENCY.json')
 need(isinstance(latency,dict),'no original sender latency receipt; no phone export dispatched')
 need(latency.get('owner_request_utf8_sha256')==sha(request) and latency.get('send_attempt_count')==1 and latency.get('automatic_send_retry') is False,'sender receipt owner/one Send differs')
 scope=latency.get('scope')
 need(scope is None or set(scope)==set(KEYS) and scope!=previous['identity'],'sender original fresh scope required')
 observation=latency.get('original_observation')
 if isinstance(observation,dict) and isinstance(observation.get('match'),dict):
  need(observation['match']['evidence_root_mode']=='production' and observation['match']['scope']==scope,'sender production actual scope')
 bound={'nonce':material['nonce'],'owner_request_sha256':sha(request),'combination_sha256':sha(combo),
        'sender_scope':scope,'previous_input_sha256':PREVIOUS_SHA}
 writej(E/'CAPTURE-BINDING.json',bound)
 source=local_read(D/'capture_health_originals.py',65536,PHONE_SOURCE_SHA).decode('utf-8')
 arg=base64.b64encode(json.dumps(bound,sort_keys=True,separators=(',',':')).encode()).decode()
 command='/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -B -c '+shlex.quote(source)+' '+shlex.quote(arg)
 req={'kind':'shell','root':True,'timeout_seconds':50,'command':command}
 writej(E/'CAPTURE-REQUEST.json',req)
 harness=B/'root-operators-r6-cycle03/run_cycle03.py'
 local_read(harness,16384,'630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6')
 spec=importlib.util.spec_from_file_location('root_health_original_read_once',harness)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.D=E
 try:ph=m.call_phone(OP,req)
 except AssertionError:
  # A partial phone capture intentionally exits2. Retain and unpack its originals
  # from the already-written wrapper; never submit a second operation.
  operation=strict(local_read(E/(OP+'.original-operation.json'),8*1024*1024))
  ph=operation['wrapper'].get('phone',{})
 need(isinstance(ph.get('stdout'),str),'original phone stdout missing; inspect same operation, do not rerun')
 raw=ph['stdout'].encode('utf-8')
 need(len(raw)<=4*1024*1024,'phone capture output exceeds bound')
 put(E/'ACTUAL-CAPTURE-01.json',raw)
 original_raw=local_read(E/(OP+'.original-operation.json'),8*1024*1024)
 original=strict(original_raw);original_phone=original.get('wrapper',{}).get('phone',{})
 need(original_phone.get('rc')==ph.get('rc') and original_phone.get('stdout')==ph.get('stdout'),
  'capture original process binding differs')
 capture_zero=(type(original_phone.get('rc')) is int and original_phone['rc']==0
  and type(original.get('actor_rc')) is int and original['actor_rc']==0)
 writej(E/'CAPTURE-TERMINAL.json',{'schema':'hepta.health-capture-process-terminal.v150.r7.1',
  'operation_label':OP,'original_operation_sha256':sha(original_raw),
  'capture_sha256':sha(raw),'phone_process_rc':original_phone.get('rc'),
  'actor_rc':original.get('actor_rc'),'capture_process_completed_zero':capture_zero})

 capture=strict(raw)
 need(capture.get('schema')=='hepta.production-health-original-capture.v150.r7.1','capture schema differs')
 need(capture.get('owner_request_sha256')==sha(request) and capture.get('nonce')==material['nonce'],'capture identity differs')
 need(capture.get('combination_sha256')==sha(combo),'capture combination differs')
 manifest=unpack(capture)
 complete_export=manifest['export_complete'] is True and capture_zero
 result={'state':'ORIGINALS_EXPORTED' if complete_export else 'PARTIAL_ORIGINALS_RETAINED',
         'original_export':str(E),'capture_sha256':sha(raw),'files':len(manifest['files']),
         'native_records':manifest['native_raw_record_count'],'export_complete':complete_export,'raw_capture_export_complete':manifest['export_complete'],
         'capture_process_completed_zero':capture_zero,'phone_process_rc':original_phone.get('rc'),
         'actor_rc':original.get('actor_rc'),'health_qualified':False,'task_submissions':0,'model_requests':0,'phone_ui_actions':0,
         'phone_read_operations':1,'automatic_retry':False,'draft_files_read':0,'key_files_read':0}
 writej(E/'EXPORT-RESULT.json',result);print(json.dumps(result,sort_keys=True))
 return 0 if complete_export else 2
def collect():
 material,request,combo,previous,material_raw=inputs()
 capture=strict(local_read(E/'ACTUAL-CAPTURE-01.json',4*1024*1024))
 capture_complete=(capture.get('state')=='CAPTURED_BOUND_ORIGINALS'
   and capture.get('export_complete') is True and capture.get('issues')==[]
   and isinstance(capture.get('bindings'),dict)
   and set(capture['bindings'])=={'staged_request_and_registration','actual_source_config_service',
       'unique_provider_owner_and_sender_scope','provider_start_exact_owner','durable_claim_scope_owner_run'}
   and all(value is True for value in capture['bindings'].values())
   and capture_terminal_zero())
 need(capture.get('owner_request_sha256')==sha(request) and capture.get('nonce')==material['nonce'],'export differs from original health')
 collector=B/'acceptance-r7-r3/collector-r7/collect_health_evidence.py'
 local_read(collector,65536,COLLECTOR_SHA)
 args=[sys.executable,'-B',str(collector),'--provider-state',str(E/'provider-state'),
 '--request-file',str(H/'request.txt'),'--selected-scope-file',str(E/'selected-scope.json'),
 '--native-journal',str(E/'selected-native-raw.jsonl'),'--sidecar-journal',str(E/'executor-r6'),
 '--client-receipts',str(E/'client-receipts'),'--source-seal',str(B/'provider-r7/SOURCE-SEAL-v150-r7.json'),
 '--source-seal-sha256',SEAL_SHA,'--provider-source',str(B/'provider-r7/source'),
 '--config-file',str(B/'provider-r7/local-config.phone.production.json'),
 '--service-manifest',str(B/'PHONE-SERVICE-INPUTS-v150-r3.json'),
 '--nonce',material['nonce'],'--case-id','HEALTH','--out',str(E/'health-audit-01')]
 writej(E/'COLLECTOR-INTENT.json',{'argv':args,'phone_calls':0,'model_requests':0})
 r=subprocess.run(args,capture_output=True,timeout=40)
 put(E/'collector.stdout',r.stdout);put(E/'collector.stderr',r.stderr)
 report_path=E/'health-audit-01/REPORT.json'
 report_raw=local_read(report_path,4*1024*1024) if report_path.exists() else None
 report=strict(report_raw) if report_raw is not None else {}
 result={'state':'HOST_COLLECTOR_TERMINAL','process_exit_code':r.returncode,
 'report_path':str(report_path),'report_sha256':sha(report_raw) if report_raw is not None else None,
 'original_capture_complete':capture_complete,
 'raw_collector_health_qualification_pass':report.get('health_qualification_pass') is True,
 'raw_collector_proof_complete':report.get('proof_complete') is True,
 **final_health_qualification(capture_complete,r.returncode,report),
 'complete_business_success':False,'phone_calls':0,'model_requests':0,'automatic_retry':False}
 writej(E/'COLLECTOR-RESULT.json',result);print(json.dumps(result,sort_keys=True))
 return 0 if result['health_qualification_pass'] and result['proof_complete'] else 2
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('capture','collect'))
 p.add_argument('--execute-read-once',action='store_true',help='Root explicit one read-only phone export; never Send')
 a=p.parse_args()
 if a.phase=='capture':
  need(a.execute_read_once,'capture requires Root explicit --execute-read-once')
  return capture_once()
 need(not a.execute_read_once,'collect is host-only')
 return collect()
if __name__=='__main__':sys.exit(main())
