#!/usr/bin/env python3
"""Root-only bounded business original snapshot. No model, IPC, UI or tool request.
Reads the already accepted r10 turn and writes only a new private capture directory.
One bound original identity is supplied as base64 JSON. Never generates a nonce.
"""
import base64,hashlib,io,json,os,re,signal,stat,sys,tarfile,time
from pathlib import Path
BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
STATE=BASE/'provider-state'
EVIDENCE=STATE/'evidence'
NATIVE=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
CLIENT_SHA='500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
MAX_BYTES=64*1024*1024
MAX_SCAN=128*1024*1024
MAX_FILE=16*1024*1024
MAX_FILES=2048
MAX_LINE=4*1024*1024
R={'schema':'hepta.original-capture.v150.r10.1','state':'PARTIAL_ORIGINAL_CAPTURE',
   'phone_ui_actions':0,'model_requests':0,'socket_calls':0,'tool_calls':0,
   'original_file_writes':0,'task_submissions':0,'qualification':False,
   'files':[],'directories':[],'native_sources':[],'native_raw_records':[],
   'bindings':{},'issues':[],'limits':{'retained_bytes':MAX_BYTES,
   'native_scan_bytes':MAX_SCAN,'files':MAX_FILES,'capture_seconds':50,
   'finalize_seconds':15,'archive_bytes':MAX_BYTES}}
READS=[]; DIRS=[]; ABSENT=[]; RAW={}; RETAINED=0; SCANNED=0; SNAP=None; OUT=None

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
  R['directories'].append({'source_path':str(path),'state':'absent','lookup_errno':2,'required':required});ABSENT.append(path)
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
  row.update(state='absent',lookup_errno=2);ABSENT.append(p)
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
 dispatched=[]
 for call in calls:
  a=call['argv']
  need(call['tool']=='shell.exec' and len(a)==9
   and a[:3]==['/usr/bin/python3',str(BASE/'tool_client_r6.py'),'execute']
   and a[3]=='--action-id' and a[5]=='--command-b64' and a[7]=='--timeout-ms',
   'original_tool_argv_not_pinned_r6')
  token=a[4];need(re.fullmatch('[0-9a-f]{32}',token) and token not in dispatched,'action_id_not_unique')
  dispatched.append(token)
 ledger=EVIDENCE/'action-ledger'
 names=directory(ledger,1024)
 intents=[n for n in names if n.endswith('.intent.json')]
 need(len(intents)<=256 and all(re.fullmatch(r'[0-9a-f]{32}\.intent\.json',n) for n in intents),'full_ledger_inventory_bound')
 R['ledger_intent_inventory']=[];R['ledger_auxiliary_inventory']=[]
 reserved=[]
 for name in intents:
  raw=capture(ledger/name,'provider-state/evidence/action-ledger/'+name,True,16384)
  need(raw is not None,'original_global_intent_absent');v=strict(raw)
  token=name[:-len('.intent.json')]
  need(v.get('action_id')==token,'global_intent_identity_differs')
  R['ledger_intent_inventory'].append({'name':name,'bytes':len(raw),'sha256':sha(raw)})
  if v.get('semantic_identity')=={k:scope[k] for k in KEYS[:-1]}:reserved.append(token)
 auxiliary=sorted(n[:-len('.intent.json')]+suffix for n in intents
  for suffix in ('.resolution.json','.inspection.json','.retirement-proof.json'))
 need(sorted(n for n in names if re.fullmatch(r'[0-9a-f]{32}\.(resolution|inspection|retirement-proof)\.json',n))
  ==sorted(n for n in auxiliary if n in names),'orphan_ledger_auxiliary_original')
 for name in auxiliary:
  raw=capture(ledger/name,'provider-state/evidence/action-ledger/'+name,False,262144)
  r=R['files'][-1]
  if raw is not None:R['ledger_auxiliary_inventory'].append({'name':name,'state':'captured','bytes':len(raw),'sha256':sha(raw)})
  else:
   need(r.get('state')=='absent' and r.get('lookup_errno')==2,'auxiliary_read_failure_is_not_absence')
   R['ledger_auxiliary_inventory'].append({'name':name,'state':'absent','lookup_errno':2})
 R['bindings']['complete_action_ledger_intent_inventory']=True
 R['bindings']['complete_action_ledger_auxiliary_originals']=True
 action_ids=sorted(set(dispatched)|set(reserved))
 client_names=directory(BASE/'client-receipts',8192)
 for token in action_ids:
  ad=BASE/'executor-r6/actions'/token;names=directory(ad,64,False)
  (SNAP/'executor-r6/actions'/token).mkdir(mode=0o700,parents=True,exist_ok=True)
  for name in names:
   p=ad/name
   if stat.S_ISDIR(p.lstat().st_mode):tree(p,'executor-r6/actions/'+token+'/'+name)
   else:capture(p,'executor-r6/actions/'+token+'/'+name)
  for name in ('intent.json','receipt.json','receipt.pending','stdout.bin','stderr.bin'):
   if name not in names:capture(ad/name,'executor-r6/actions/'+token+'/'+name,False)
  selected=[n for n in client_names if n.startswith(token+'.')]
  for name in selected:
   p=BASE/'client-receipts'/name
   if stat.S_ISDIR(p.lstat().st_mode):tree(p,'client-receipts/'+name)
   else:capture(p,'client-receipts/'+name)
  for suffix in ('.claim.json','.result.json','.inspect.json'):
   if token+suffix not in selected:capture(BASE/'client-receipts'/(token+suffix),'client-receipts/'+token+suffix,False)
 R['original_dispatched_action_ids']=dispatched
 R['original_reserved_action_ids']=reserved
 R['original_provider_tool_call_count']=len(calls)
 R['bindings']['dispatched_tool_originals_enumerated']=True
 R['bindings']['reservation_originals_enumerated']=True
def final_stability():
 for path in ABSENT:
  try:path.lstat()
  except FileNotFoundError:continue
  except Exception as e:issue(path,e)
  else:issue(path,ValueError('original_absence_changed_after_read'))
 for path,m in READS:
  try:need(meta(path.lstat())==m,'original_changed_after_read')
  except Exception as e:issue(path,e)
 for path,m,names in DIRS:
  try:need(meta(path.lstat())==m and sorted(os.listdir(path))==names,'original_directory_changed_after_listing')
  except Exception as e:issue(path,e)
def timeout(signum,frame):raise TimeoutError('bounded_original_capture_expired')
def validate_release_pins(pins):
 need(isinstance(pins,dict) and set(pins)=={
  'source_seal_sha256','configuration_sha256','service_inputs_sha256','module_manifest_sha256',
  'component_boundary_inputs_sha256','policy_adoption_inputs_sha256'},'release_pin_fields')
 need(all(isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) for x in pins.values()),'release_pin_shape')
 return True
def validate_registered_ready(pins,registered_ready):
 validate_release_pins(pins)
 need(isinstance(registered_ready,dict)
  and registered_ready.get('schema')=='hepta.r10.actual-readiness.v1'
  and registered_ready.get('state')=='EXACT_COMBINATION_READY_TRANSPORT_ONLY'
  and all(registered_ready.get(k)==v for k,v in pins.items()),'staged_original_ready_release_pin_differs')
 return True
def capture_bound(bound):
 global OUT,SNAP
 need(set(bound)=={'nonce','case_id','owner_request_sha256','request_b64',
  'combination_sha256','sender_scope','sender_run','sender_label','release_pins','runtime'},'bound_fields')
 need(bound['case_id'] in ('HEALTH','E2E-01','E2E-02','E2E-03','E2E-04'),'reviewed_case_required')
 nonce=bound['nonce'];wanted=bound['owner_request_sha256'];scope=bound['sender_scope']
 need(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'nonce_format')
 need(isinstance(scope,dict) and set(scope)==set(KEYS)
  and all(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v for v in scope.values()),'exact_original_scope')
 need(re.fullmatch('[0-9a-f]{64}',wanted) and re.fullmatch('[0-9a-f]{64}',bound['combination_sha256']),'hash_format')
 need(re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',bound['sender_label']),'sender_label_format')
 owner=base64.b64decode(bound['request_b64'],validate=True)
 need(0<len(owner)<=16000 and sha(owner)==wanted and owner.decode().count(nonce)==1,'exact_owner_bytes')
 pins=bound['release_pins']
 validate_release_pins(pins)
 root=BASE/'original-captures-r10-r1'
 if not root.exists():mkdir_new(root)
 need(root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700
  and root.stat().st_uid==0,'private_capture_parent')
 OUT=root/nonce;mkdir_new(OUT);SNAP=OUT/'snapshot';mkdir_new(SNAP)
 for rel in ('provider-state','client-receipts','executor-r6/actions','sources/provider-r10/source','runtime'):
  (SNAP/rel).mkdir(mode=0o700,parents=True,exist_ok=True)
 R.update(nonce=nonce,case_id=bound['case_id'],owner_request_sha256=wanted,
  combination_sha256=bound['combination_sha256'],selected_scope=scope,
  sender_label=bound['sender_label'],sender_run=bound['sender_run'],release_pins=pins,
  snapshot_scope='Stable individual files and final metadata/name checks; not an atomic filesystem snapshot.')
 save('host-bound-request.txt',owner)
 save('selected-scope.json',encoded({'scope':scope,'source':'actual original sender and provider acceptance'}))
 stage=BASE/'cases-r10-r1'/nonce
 staged=['request.txt','material.json','combination.json','REGISTRATION-RESULT.json','register.stdout','register.stderr','READINESS-RECHECK.original.json']
 if bound['case_id']!='HEALTH':staged.extend(['postconditions.json','app-scope.json'])
 for name in staged:capture(stage/name,'registration/'+name,True,262144)
 need(RAW['registration/request.txt']==owner and sha(RAW['registration/combination.json'])==bound['combination_sha256'],
  'staged_actual_request_combination_differs')
 registered_ready=strict(RAW['registration/READINESS-RECHECK.original.json'])
 validate_registered_ready(pins,registered_ready)
 R['bindings']['registered_request_originals_retained']=True
 seal_raw=capture(BASE/'provider-r10-r1/SOURCE-SEAL-v150-r10.json','sources/provider-r10/SOURCE-SEAL-v150-r10.json',True,262144)
 need(seal_raw is not None and sha(seal_raw)==pins['source_seal_sha256'],'actual_source_seal_pin')
 seal=strict(seal_raw);rows=seal['production_files']
 need(len(rows)==15 and len({x['path'] for x in rows})==15,'sealed_production_source_count')
 for row in rows:
  rel=safe_relative(row['path'])
  need(len(rel.parts)==2 and rel.parts[0]=='source' and rel.suffix=='.py','sealed_source_relative_path')
  raw=capture(BASE/'provider-r10-r1'/rel,'sources/provider-r10/'+str(rel),True,1048576)
  need(raw is not None and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'actual_production_source_pin')
 for rel,p,pin in (
  ('sources/local-config-r10.json',BASE/'local-config-r10-r1.json',pins['configuration_sha256']),
  ('sources/PHONE-SERVICE-INPUTS-v150-r10.json',BASE/'PHONE-SERVICE-INPUTS-v150-r10-r1.json',pins['service_inputs_sha256']),
  ('sources/tool_client_r6.py',BASE/'tool_client_r6.py',CLIENT_SHA)):
  raw=capture(p,rel,True,262144);need(raw is not None and sha(raw)==pin,'actual_fixed_input_pin')
 need(seal['configuration']['sha256']==pins['configuration_sha256']
  and seal['phone_service_inputs_sha256']==pins['service_inputs_sha256']
  and strict(RAW['sources/local-config-r10.json'])['service_manifest_sha256']==pins['service_inputs_sha256'],
  'actual_release_source_config_service_chain')
 R['bindings']['actual_source_config_service_client']=True
 runtime=bound['runtime'];boot=runtime['boot_id']
 need(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot)
  and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot,'runtime_boot_changed')
 model_root=BASE/'model-runtime-r10-r1'/boot
 for name in ('model.identity','READY-BOUND.json','STARTUP-INTENT.json','BIND-INTENT.json'):
  capture(model_root/name,'runtime/'+name,True,262144)
 tree(model_root/'bindings','runtime/bindings')
 tree(model_root/'receipts','runtime/receipts')
 rb=strict(RAW['runtime/READY-BOUND.json'])
 need(rb.get('state')=='READY_BOUND_IMAGE_CANCEL_REQUIRED'
  and rb.get('server_identity')==runtime['server_identity']
  and rb['binding']['sha256']==runtime['binding_sha256'],'actual_startup_binding_identity')
 R['bindings']['runtime_binding_and_original_receipts_retained']=True
 run=find_run(wanted,scope);need(run==bound['sender_run'],'actual_sender_run_differs')
 R.update(actual_run=run,actual_run_dir=str(EVIDENCE/run))
 R['bindings']['unique_provider_owner_and_sender_scope']=True
 prefix='provider-state/evidence/'+run;tree(EVIDENCE/run,prefix)
 need(prefix+'/task-app-scope.json' in RAW,'original_resolved_task_app_scope_absent')
 resolved_scope=strict(RAW[prefix+'/task-app-scope.json'])
 need(resolved_scope.get('schema')=='hepta.resolved-task-app-scope.v1'
      and resolved_scope.get('owner_request_sha256')==wanted,'original_task_app_scope_owner_binding')
 if bound['case_id']!='HEALTH':
  declared_scope=strict(RAW['registration/app-scope.json'])
  need(resolved_scope.get('mode')=='request_bound_explicit_subset'
       and resolved_scope.get('app_scope')==declared_scope,'original_registered_and_runtime_app_scope_differ')
 else:
  need(resolved_scope.get('mode')=='legacy_global_registry_no_contract'
       and resolved_scope.get('app_scope') is None,'HEALTH_has_business_app_authority')
 R['bindings']['original_task_app_scope_retained']=True
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
 contract='health-contracts' if bound['case_id']=='HEALTH' else 'task-contracts'
 for kind in ('templates','bindings'):
  capture(STATE/contract/kind/(wanted+'.json'),'provider-state/'+contract+'/'+kind+'/'+wanted+'.json',True,131072)
 R['bindings']['original_task_contract_files_retained']=all(
  'provider-state/'+contract+'/'+k+'/'+wanted+'.json' in RAW for k in ('templates','bindings'))
 capture_actions(run,scope)
 if bound['case_id']=='HEALTH':need(R['original_provider_tool_call_count']==0,'health_dispatched_phone_tools')
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
  need(len(sys.argv)==2 and len(sys.argv[1])<=80000,'one_bounded_identity_argument')
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
   'original_task_contract_files_retained','original_task_app_scope_retained','dispatched_tool_originals_enumerated','original_native_scope_retained',
   'complete_action_ledger_intent_inventory','complete_action_ledger_auxiliary_originals',
   'reservation_originals_enumerated','runtime_binding_and_original_receipts_retained','registered_request_originals_retained'}
  R['export_complete']=not R['issues'] and set(R['bindings'])==expected and all(v is True for v in R['bindings'].values())
  R['state']='CAPTURED_BOUND_ORIGINALS' if R['export_complete'] else 'PARTIAL_ORIGINAL_CAPTURE'
  if SNAP is not None:
   raw=encoded(R);save('CAPTURE.json',raw);capture_sha=sha(raw)
   archive=archive_snapshot()
 except Exception as e:issue('finalize',e)
 finally:signal.setitimer(signal.ITIMER_REAL,0)
 result={'schema':'hepta.original-capture-result.v150.r10.1',
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
