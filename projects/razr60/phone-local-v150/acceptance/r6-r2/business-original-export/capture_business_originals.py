#!/usr/bin/env python3
"""Root-only bounded business original snapshot. No model, IPC, UI or tool request.
Reads the already accepted r6 turn and writes only a new private capture directory.
One bound original identity is supplied as base64 JSON. Never generates a nonce.
"""
import base64,hashlib,io,json,os,re,signal,stat,sys,tarfile,time
from pathlib import Path
BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
STATE=BASE/'provider-state'
EVIDENCE=STATE/'evidence'
NATIVE=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
SEAL_SHA='a8bd87b3d50c993b3e4ac7799ca66dd8e84cbd7925deb7e641e5cc66c1bdb7c1'
CONFIG_SHA='0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755'
SERVICE_SHA='ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2'
CLIENT_SHA='500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
MAX_BYTES=64*1024*1024
MAX_SCAN=128*1024*1024
MAX_FILE=16*1024*1024
MAX_FILES=768
MAX_LINE=4*1024*1024
R={'schema':'hepta.business-original-capture.v150.r6.1','state':'PARTIAL_ORIGINAL_CAPTURE',
   'phone_ui_actions':0,'model_requests':0,'socket_calls':0,'tool_calls':0,
   'original_file_writes':0,'task_submissions':0,'qualification':False,
   'files':[],'directories':[],'native_sources':[],'native_raw_records':[],
   'bindings':{},'issues':[],'limits':{'retained_bytes':MAX_BYTES,
   'native_scan_bytes':MAX_SCAN,'files':MAX_FILES,'capture_seconds':50,
   'finalize_seconds':15,'archive_bytes':MAX_BYTES}}
READS=[]; DIRS=[]; RAW={}; RETAINED=0; SCANNED=0; SNAP=None; OUT=None

def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,message):
 if not ok:raise ValueError(message)
def strict(raw):
 def pairs(items):
  value={}
  for k,v in items:need(k not in value,'duplicate_json_key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,
  parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite_json')))
def encoded(obj):
 return (json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def meta(s):
 return {k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
def issue(where,e):
 R['issues'].append({'where':str(where),'type':type(e).__name__,'message':str(e)[:512]})
def safe_relative(value):
 p=Path(value)
 need(isinstance(value,str) and not p.is_absolute() and p.parts
      and all(re.fullmatch('[A-Za-z0-9._-]+',n) and n not in ('.','..') for n in p.parts),
      'invalid_snapshot_relative_path')
 return p
def mkdir_new(path):
 need(path.parent.resolve(strict=True)==path.parent,'noncanonical_new_directory_parent')
 path.mkdir(mode=0o700)
def put(path,raw):
 need(path.parent.resolve(strict=True)==path.parent,'noncanonical_output_parent')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def save(relative,raw):
 p=SNAP/safe_relative(relative)
 p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 need(p.parent.resolve(strict=True)==p.parent,'snapshot_parent_changed')
 put(p,raw)
def directory(path,cap=256,required=True):
 path=Path(path)
 try:
  need(path.resolve(strict=True)==path,'noncanonical_directory')
  a=path.lstat();need(stat.S_ISDIR(a.st_mode),'not_directory')
  names=sorted(os.listdir(path));need(len(names)<=cap,'directory_entry_budget')
  need(meta(a)==meta(path.lstat()),'directory_changed_during_listing')
  R['directories'].append({'source_path':str(path),'state':'observed','names':names,'stat':meta(a)})
  DIRS.append((path,meta(a),names))
  return names
 except FileNotFoundError:
  R['directories'].append({'source_path':str(path),'state':'absent','lookup_errno':2,'required':required})
  if required:issue(path,ValueError('required_directory_absent'))
 except Exception as e:issue(path,e)
 return []
def capture(path,relative,required=True,limit=MAX_FILE):
 global RETAINED
 relative=str(safe_relative(relative))
 need(relative not in RAW,'duplicate_capture_destination')
 p=Path(path);row={'source_path':str(p),'export_relative_path':relative,'required':required}
 R['files'].append(row);need(len(R['files'])<=MAX_FILES,'capture_file_count')
 fd=None
 try:
  need(p.name not in ('api.key','llama-api.key') and 'DRAFT' not in p.name.upper()
       and p.suffix not in ('.key','.pem'),'key_or_draft_not_permitted')
  need(p.parent.resolve(strict=True)==p.parent,'noncanonical_source_parent')
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);a=os.fstat(fd)
  need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=limit,'source_file_type_or_bound')
  need(RETAINED+a.st_size<=MAX_BYTES,'retained_byte_budget')
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
  b=os.fstat(fd);c=p.lstat()
  need(meta(a)==meta(b)==meta(c) and len(raw)==a.st_size and len(raw)<=limit,'source_changed_or_short_read')
  save(relative,raw);RAW[relative]=raw;RETAINED+=len(raw);READS.append((p,meta(a)))
  row.update(state='captured',bytes=len(raw),sha256=sha(raw),stat_before=meta(a),
             stat_after=meta(b),eof=True)
  return raw
 except FileNotFoundError:
  row.update(state='absent',lookup_errno=2)
  if required:issue(relative,ValueError('required_original_absent'))
 except Exception as e:
  row.update(state='read_error',error=type(e).__name__+':'+str(e)[:512]);issue(relative,e)
 finally:
  if fd is not None:os.close(fd)
 return None
def tree(path,relative,depth=0):
 need(depth<=3,'original_tree_depth_bound')
 for name in directory(path,256):
  p=path/name
  try:
   safe_relative(name);s=p.lstat()
   if stat.S_ISDIR(s.st_mode):tree(p,relative+'/'+name,depth+1)
   else:capture(p,relative+'/'+name)
  except Exception as e:issue(p,e)
def find_run(wanted,scope):
 matches=[]
 names=directory(EVIDENCE,2048)
 for name in names:
  if not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',name):continue
  p=EVIDENCE/name/'provider-in.jsonl';fd=None
  try:
   need(p.parent.resolve(strict=True)==p.parent,'provider_run_not_canonical')
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);a=os.fstat(fd)
   need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,'provider_start_file_type')
   with os.fdopen(fd,'rb',closefd=False) as f:line=f.readline(131073)
   need(meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'provider_start_changed')
   need(len(line)<=131072 and line.endswith(b'\n'),'provider_start_bound')
   frame=strict(line);turn=frame.get('turn',{})
   if frame.get('kind')!='turn.start' or not isinstance(turn.get('user_input'),str):continue
   if sha(turn['user_input'].encode())!=wanted:continue
   matches.append({'run':name,'scope':{k:turn.get(k) for k in KEYS},
    'provider_start_sha256':sha(line),'provider_start_bytes':len(line)})
  except FileNotFoundError:continue
  finally:
   if fd is not None:os.close(fd)
 R['provider_matches']=matches
 need(len(matches)==1 and matches[0]['scope']==scope,'unique_original_owner_and_exact_sender_scope_required')
 return matches[0]['run']
def native_capture(scope):
 global RETAINED,SCANNED
 names=[n for n in directory(NATIVE,512) if n.endswith('.jsonl')]
 need(names,'native_segments_absent')
 selected=[]
 for name in names:
  p=NATIVE/name;row={'source_path':str(p)};R['native_sources'].append(row);fd=None
  try:
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);a=os.fstat(fd)
   need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,'native_file_type')
   need(SCANNED+a.st_size<=MAX_SCAN,'native_scan_budget')
   h=hashlib.sha256();offset=0;line_no=0
   with os.fdopen(fd,'rb',closefd=False) as f:
    while True:
     line=f.readline(MAX_LINE+1)
     if not line:break
     line_no+=1;begin=offset;offset+=len(line);SCANNED+=len(line)
     need(len(line)<=MAX_LINE and line.endswith(b'\n') and SCANNED<=MAX_SCAN,'native_line_or_scan_bound')
     h.update(line);v=strict(line)
     if v.get('scope')==scope:
      need(len(selected)<2048 and RETAINED+len(line)<=MAX_BYTES,'selected_native_budget')
      r={'source_path':str(p),'line_1based':line_no,'offset':begin,'bytes':len(line),
       'sha256':sha(line),'store_seq':v.get('store_seq'),'turn_seq':v.get('turn_seq'),'kind':v.get('kind')}
      selected.append((r,line));RETAINED+=len(line)
   need(meta(a)==meta(os.fstat(fd))==meta(p.lstat()) and offset==a.st_size,'native_changed_or_short')
   row.update(state='scanned_to_eof',bytes_scanned=offset,whole_file_sha256=h.hexdigest(),stat=meta(a))
   READS.append((p,meta(a)))
  except Exception as e:row.update(state='scan_error',error=str(e)[:512]);issue(p,e)
  finally:
   if fd is not None:os.close(fd)
 need(selected,'selected_native_records_absent')
 need(all(type(r['store_seq']) is int for r,_ in selected),'native_store_sequence_type')
 selected.sort(key=lambda item:item[0]['store_seq'])
 R['native_raw_records']=[r for r,_ in selected]
 save('selected-native-raw.jsonl',b''.join(raw for _,raw in selected))
 R['native_selection_note']='Original raw lines for all five scope fields; filtered scope is not a complete global-WAL chain.'
def capture_actions(run,scope):
 raw=RAW['provider-state/evidence/'+run+'/provider-out.jsonl']
 need(raw.endswith(b'\n'),'provider_output_incomplete_line')
 frames=[strict(line) for line in raw.splitlines() if line]
 calls=[v['call'] for v in frames if v.get('kind')=='tool.call']
 need(len(calls)<=7,'original_dispatch_count_exceeds_frozen_budget')
 ids=[]
 for call in calls:
  try:
   a=call['argv']
   need(call['tool']=='shell.exec' and len(a)==9
    and a[:3]==['/usr/bin/python3',str(BASE/'tool_client_r6.py'),'execute']
    and a[3]=='--action-id' and a[5]=='--command-b64' and a[7]=='--timeout-ms',
    'original_tool_argv_not_pinned_r6')
   action=a[4];need(re.fullmatch('[0-9a-f]{32}',action) and action not in ids,'original_action_id_not_unique')
   ids.append(action)
   ad=BASE/'executor-r6/actions'/action
   names=directory(ad,32,False)
   (SNAP/'executor-r6/actions'/action).mkdir(mode=0o700,parents=True,exist_ok=True)
   if names:tree(ad,'executor-r6/actions/'+action)
   else:
    for name in ('intent.json','receipt.json','stdout.bin','stderr.bin'):
     capture(ad/name,'executor-r6/actions/'+action+'/'+name,False)
   for suffix in ('.claim.json','.result.json'):
    capture(BASE/'client-receipts'/(action+suffix),'client-receipts/'+action+suffix,False)
   td=BASE/'client-receipts'/(action+'.transport-r6')
   if directory(td,64,False):tree(td,'client-receipts/'+action+'.transport-r6')
   for suffix in ('.intent.json','.resolution.json','.inspection.json','.retirement-proof.json'):
    capture(EVIDENCE/'action-ledger'/(action+suffix),'provider-state/evidence/action-ledger/'+action+suffix,False)
  except Exception as e:issue('tool_originals/'+str(call.get('call_id')),e)
 R['original_dispatched_action_ids']=ids
 R['original_provider_tool_call_count']=len(calls)
 R['bindings']['dispatched_tool_originals_enumerated']=len(ids)==len(calls)
def final_stability():
 for path,m in READS:
  try:need(meta(path.lstat())==m,'original_changed_after_read')
  except Exception as e:issue(path,e)
 for path,m,names in DIRS:
  try:need(meta(path.lstat())==m and sorted(os.listdir(path))==names,'original_directory_changed_after_listing')
  except Exception as e:issue(path,e)
def timeout(signum,frame):raise TimeoutError('bounded_original_capture_expired')
def capture_bound(bound):
 global OUT,SNAP
 need(set(bound)=={'nonce','case_id','owner_request_sha256','request_b64',
  'combination_sha256','sender_scope','sender_run','sender_label'},'bound_fields')
 need(bound['case_id'] in ('E2E-01','E2E-02'),'only_visual_or_unicode_business_case')
 nonce=bound['nonce'];wanted=bound['owner_request_sha256'];scope=bound['sender_scope']
 need(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'nonce_format')
 need(isinstance(scope,dict) and set(scope)==set(KEYS)
  and all(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v for v in scope.values()),'exact_original_scope')
 need(re.fullmatch('[0-9a-f]{64}',wanted) and re.fullmatch('[0-9a-f]{64}',bound['combination_sha256']),'hash_format')
 need(re.fullmatch('[a-z0-9][a-z0-9-]{5,80}',bound['sender_label']),'sender_label_format')
 owner=base64.b64decode(bound['request_b64'],validate=True)
 need(0<len(owner)<=24576 and sha(owner)==wanted and owner.decode().count(nonce)==1,'exact_owner_bytes')
 root=BASE/'business-original-captures-r6-r2'
 if not root.exists():mkdir_new(root)
 need(root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700
  and root.stat().st_uid==0,'private_capture_parent')
 OUT=root/nonce;mkdir_new(OUT);SNAP=OUT/'snapshot';mkdir_new(SNAP)
 for rel in ('provider-state','client-receipts','executor-r6/actions','sources/provider-r6-r2/source'):
  (SNAP/rel).mkdir(mode=0o700,parents=True,exist_ok=True)
 R.update(nonce=nonce,case_id=bound['case_id'],owner_request_sha256=wanted,
  combination_sha256=bound['combination_sha256'],selected_scope=scope,
  sender_label=bound['sender_label'],sender_run=bound['sender_run'],
  snapshot_scope='Stable individual files and final metadata/name checks; not an atomic filesystem snapshot.')
 save('host-bound-request.txt',owner)
 save('selected-scope.json',encoded({'scope':scope,'source':'actual original sender and provider acceptance'}))
 seal_raw=capture(BASE/'provider-r6-r2/SOURCE-SEAL-v150-r6-r2.json','sources/provider-r6-r2/SOURCE-SEAL-v150-r6-r2.json',True,65536)
 need(seal_raw is not None and sha(seal_raw)==SEAL_SHA,'actual_source_seal_pin')
 seal=strict(seal_raw);rows=seal['production_files']
 need(len(rows)==13,'sealed_production_source_count')
 for row in rows:
  rel=safe_relative(row['path'])
  need(len(rel.parts)==2 and rel.parts[0]=='source' and rel.suffix=='.py','sealed_source_relative_path')
  raw=capture(BASE/'provider-r6-r2'/rel,'sources/provider-r6-r2/'+str(rel),True,65536)
  need(raw is not None and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'actual_production_source_pin')
 for rel,p,pin in (
  ('sources/local-config-r6-r2.json',BASE/'local-config-r6-r2.json',CONFIG_SHA),
  ('sources/PHONE-SERVICE-INPUTS-v150-r3.json',BASE/'PHONE-SERVICE-INPUTS-v150-r3.json',SERVICE_SHA),
  ('sources/tool_client_r6.py',BASE/'tool_client_r6.py',CLIENT_SHA)):
  raw=capture(p,rel,True,65536);need(raw is not None and sha(raw)==pin,'actual_fixed_input_pin')
 R['bindings']['actual_source_config_service_client']=True
 run=find_run(wanted,scope);need(run==bound['sender_run'],'actual_sender_run_differs')
 R.update(actual_run=run,actual_run_dir=str(EVIDENCE/run))
 R['bindings']['unique_provider_owner_and_sender_scope']=True
 prefix='provider-state/evidence/'+run;tree(EVIDENCE/run,prefix)
 incoming=RAW[prefix+'/provider-in.jsonl']
 need(incoming.endswith(b'\n'),'provider_input_incomplete_line')
 start=strict(incoming.splitlines()[0]);turn=start['turn']
 need(start['kind']=='turn.start' and {k:turn[k] for k in KEYS}==scope
  and turn['user_input'].encode()==owner,'original_provider_owner_bytes')
 need(prefix+'/provider-out.jsonl' in RAW,'original_provider_output_absent')
 R['bindings']['provider_start_exact_owner']=True
 claim_key=sha(json.dumps([scope[k] for k in KEYS[:-1]],ensure_ascii=True,separators=(',',':')).encode())
 raw=capture(EVIDENCE/'claims'/claim_key,'provider-state/evidence/claims/'+claim_key,True,65536);claim=strict(raw)
 need(claim.get('identity')==scope and claim.get('request_sha256')==wanted
  and claim.get('state')=='accepted_no_redispatch' and claim.get('run_dir')==str(EVIDENCE/run),'actual_durable_claim')
 R['claim_key']=claim_key;R['bindings']['durable_claim_scope_owner_run']=True
 for kind in ('templates','bindings'):
  capture(STATE/'task-contracts'/kind/(wanted+'.json'),'provider-state/task-contracts/'+kind+'/'+wanted+'.json',True,131072)
 R['bindings']['original_task_contract_files_retained']=all(
  'provider-state/task-contracts/'+k+'/'+wanted+'.json' in RAW for k in ('templates','bindings'))
 capture_actions(run,scope)
 native_capture(scope)
 R['bindings']['original_native_scope_retained']=bool(R['native_raw_records'])
def archive_snapshot():
 paths=[]
 for root,dirs,files in os.walk(SNAP,followlinks=False):
  dirs.sort();files.sort()
  for d in dirs:need(not (Path(root)/d).is_symlink(),'snapshot_link_directory')
  for name in files:
   p=Path(root)/name;need(p.is_file() and not p.is_symlink(),'snapshot_file_type')
   paths.append(p)
 need(len(paths)<=MAX_FILES+8,'archive_member_count')
 path=OUT/'originals.tar.gz'
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:
  with tarfile.open(fileobj=f,mode='w:gz',compresslevel=1) as t:
   for p in paths:
    m=p.lstat();raw=p.read_bytes();need(stat.S_ISREG(m.st_mode) and m.st_nlink==1
      and len(raw)==m.st_size and meta(p.lstat())==meta(m),'snapshot_changed_before_archive')
    name=str(p.relative_to(SNAP));safe_relative(name)
    info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;info.uid=info.gid=0;info.mtime=0
    t.addfile(info,io.BytesIO(raw))
  f.flush();os.fsync(f.fileno())
 need(path.stat().st_size<=MAX_BYTES,'archive_byte_bound')
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return {'path':str(path),'bytes':path.stat().st_size,'sha256':h.hexdigest(),'stat':meta(path.stat()),
         'member_count':len(paths)}
def main():
 started=time.monotonic_ns();signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,50)
 try:
  need(len(sys.argv)==2 and len(sys.argv[1])<=50000,'one_bounded_identity_argument')
  capture_bound(strict(base64.b64decode(sys.argv[1],validate=True)))
 except Exception as e:issue('capture',e)
 finally:signal.setitimer(signal.ITIMER_REAL,0)
 archive=None;capture_sha=None
 signal.setitimer(signal.ITIMER_REAL,15)
 try:
  final_stability()
  R['retained_original_bytes']=RETAINED;R['native_scan_bytes']=SCANNED
  R['elapsed_capture_monotonic_ns']=time.monotonic_ns()-started
  expected={'actual_source_config_service_client','unique_provider_owner_and_sender_scope',
   'provider_start_exact_owner','durable_claim_scope_owner_run',
   'original_task_contract_files_retained','dispatched_tool_originals_enumerated','original_native_scope_retained'}
  R['export_complete']=not R['issues'] and set(R['bindings'])==expected and all(v is True for v in R['bindings'].values())
  R['state']='CAPTURED_BOUND_ORIGINALS' if R['export_complete'] else 'PARTIAL_ORIGINAL_CAPTURE'
  if SNAP is not None:
   raw=encoded(R);save('CAPTURE.json',raw);capture_sha=sha(raw)
   archive=archive_snapshot()
 except Exception as e:issue('finalize',e)
 finally:signal.setitimer(signal.ITIMER_REAL,0)
 result={'schema':'hepta.business-original-capture-result.v150.r6.1',
  'state':R['state'],'export_complete':R.get('export_complete') is True and archive is not None and not R['issues'],
  'capture_sha256':capture_sha,'archive':archive,'case_id':R.get('case_id'),
  'nonce':R.get('nonce'),'owner_request_sha256':R.get('owner_request_sha256'),
  'combination_sha256':R.get('combination_sha256'),'selected_scope':R.get('selected_scope'),
  'original_file_count':sum(x.get('state')=='captured' for x in R['files']),
  'native_record_count':len(R['native_raw_records']),'issues':R['issues'],
  'elapsed_monotonic_ns':time.monotonic_ns()-started,
  'task_submissions':0,'phone_ui_actions':0,'model_requests':0,'socket_calls':0,
  'original_file_writes':0,'new_private_snapshot_only':True,'qualification':False}
 sys.stdout.buffer.write(encoded(result));sys.stdout.buffer.flush()
 return 0 if result['export_complete'] else 2
if __name__=='__main__':sys.exit(main())
