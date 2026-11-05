#!/usr/bin/env python3
"""Bounded Root read-only capture of an existing NEG04/05/07 original turn.
This separate entry does not broaden the positive or CPU cancellation collector.
Only a new private evidence directory is written; no model, IPC, UI, task or signal.
Default is source/plan preview; unfrozen future dependencies reject execution.
"""
import argparse,base64,errno,hashlib,io,json,os,re,signal,stat,sys,tarfile,time
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
R={'schema':'hepta.physical-fault.phone-original-capture.v1','state':'PARTIAL_NEGATIVE_ORIGINAL_CAPTURE',
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
 selected_raw=b''.join(raw for _,raw in selected)
 save('selected-native-raw.jsonl',selected_raw)
 GENERATED['selected-native-raw.jsonl']={'bytes':len(selected_raw),'sha256':sha(selected_raw),'kind':'complete_selected_original_raw_lines'}
 R['native_selection_note']='Selected original lines plus every scanned original segment are retained; no global-WAL chain claim is inferred.'
 for row in R['native_sources']:
  need(row.get('state')=='scanned_to_eof','incomplete_native_scan')
  p=Path(row['source_path']);raw=capture(p,'native-originals/'+p.name,True,MAX_BYTES)
  need(raw is not None and len(raw)==row['bytes_scanned'] and sha(raw)==row['whole_file_sha256'],
       'complete_native_source_copy_differs')
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
def parent_fd(path):
    """Walk directory FDs without links; only /proc/1/root is an explicit anchor.

    The GNU chroot cannot resolve that Android magic link lexically. Runtime
    startup separately binds the init PID namespace and the anchor inode.
    """
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2 <= len(path.parts) <= 64,
         'bounded absolute path required')
    if path.parts[:4] == ('/', 'proc', '1', 'root'):
        fd = os.open(ANDROID, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[4:]
    else:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[1:]
    need(parts, 'file path required')
    try:
        for name in parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd); raise


def open_live_policy(path):
    """Retry only a failed policy open reporting EBUSY, never an acquired fd.

    The retry window is one monotonic second, at most 21 open attempts, with
    each pause capped at 50ms. Existing caller deadlines remain unchanged.
    """
    deadline = time.monotonic() + 1.0
    last_busy = None
    for attempt in range(21):
        if attempt and time.monotonic() >= deadline:
            raise last_busy
        try:
            return os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        except OSError as error:
            if error.errno != errno.EBUSY:
                raise
            last_busy = error
            remaining = deadline - time.monotonic()
            if attempt == 20 or remaining <= 0:
                raise
            time.sleep(min(0.05, remaining))
    raise AssertionError('bounded policy-open loop exhausted unexpectedly')



# Source-only trust slots. Root finalizes these from an actual reviewed release.
# A caller cannot authorize execution by filling its own plan.
FINAL_DEPENDENCIES = None
ANDROID = Path('/proc/1/root')
MODULE = ANDROID / 'data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
CAPTURE_ROOT = BASE / 'fault-original-captures-r10-r1'
POLICY_OPEN_PARENT_SHA = '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'
NEGATIVE_SCHEMA = 'hepta.physical-fault.phone-capture-plan.v1'
NEGATIVE_FIELDS = {'schema','state','nonce','case_id','owner_request_sha256','request_b64',
 'combination_sha256','sender_scope','native_request_sha256','sender_run','sender_label',
 'operator_label','operator_plan_sha256','operator_package_sha256','release_pins',
 'runtime_binding','runtime','task_template_sha256','app_scope_sha256',
 'watch_plan_sha256','watch_source_sha256'}
DEPENDENCY_FIELDS = {'runtime_package_sha256','consumer_sha256','readiness_sha256',
 'fault_package_sha256','active_source_sha256','fault_verifier_sha256',
 'configuration_sha256','service_inputs_sha256','policy_adoption_sha256','live_policy'}
GENERATED = {}
ANDROID_ABSENT = []
REVIEWED_CAPTURE_RAW = None
REVIEWED_PLAN_RAW = None
MAX_PLAN = 65536

def exact_hash(value):
 need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value),'exact_sha256_required')
 return value

def validate_negative_plan(bound, *, require_final=True):
 need(isinstance(bound,dict) and set(bound)==NEGATIVE_FIELDS and
      bound['schema']==NEGATIVE_SCHEMA and
      bound['state']=='ROOT_REVIEWED_EXISTING_NEGATIVE_ORIGINAL_CAPTURE',
      'negative_capture_plan_fields_or_state')
 need(bound['case_id'] in ('NEG-04','NEG-05','NEG-07'),'only_NEG04_NEG05_NEG07_originals')
 nonce=bound['nonce'];scope=bound['sender_scope']
 need(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'existing_nonce_shape')
 need(isinstance(scope,dict) and set(scope)==set(KEYS) and
      all(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v for v in scope.values()),
      'actual_original_five_scope_required')
 for key in ('owner_request_sha256','combination_sha256','native_request_sha256',
             'operator_plan_sha256','operator_package_sha256','task_template_sha256','app_scope_sha256',
             'watch_plan_sha256','watch_source_sha256'):
  exact_hash(bound[key])
 for key in ('sender_label','operator_label'):
  need(isinstance(bound[key],str) and re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',bound[key]),'existing_label_shape')
 need(re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',bound['sender_run']),'actual_run_basename')
 owner=base64.b64decode(bound['request_b64'],validate=True)
 need(0<len(owner)<=16000 and sha(owner)==bound['owner_request_sha256'] and
      owner.decode('utf-8').count(nonce)==1,'exact_existing_owner_bytes')
 validate_release_pins(bound['release_pins'])
 binding=bound['runtime_binding']
 need(isinstance(binding,dict) and set(binding)=={'schema','release_pins','readiness'} and
      binding['schema']=='hepta.r10.active-runtime-binding.v1' and
      binding['release_pins']==bound['release_pins'],'original_runtime_binding_fields')
 rr=binding['readiness']
 need(isinstance(rr,dict) and set(rr)=={'bytes','sha256','raw_b64'} and
      type(rr['bytes']) is int and 0<rr['bytes']<=32768,'bounded_original_READY_required')
 ready_raw=base64.b64decode(rr['raw_b64'],validate=True)
 need(len(ready_raw)==rr['bytes'] and sha(ready_raw)==rr['sha256'],'READY_raw_pin')
 ready=strict(ready_raw);validate_registered_ready(bound['release_pins'],ready)
 runtime=bound['runtime']
 need(isinstance(runtime,dict) and set(runtime)=={'boot_id','server_identity','binding_sha256'},
      'runtime_original_identity_fields')
 need(isinstance(runtime['boot_id'],str) and
      re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',runtime['boot_id']) and
      ready['boot_id']==runtime['boot_id'],'READY_boot_differs')
 ident=runtime['server_identity']
 need(isinstance(ident,dict) and set(ident)=={'schema','boot_id','pid','pgid','sid','start_ticks'} and
      ident['schema']=='hepta.llama-server-identity.v1' and ident['boot_id']==runtime['boot_id'] and
      all(type(ident[k]) is int and ident[k]>0 for k in ('pid','pgid','sid','start_ticks')),
      'actual_server_generation_required')
 exact_hash(runtime['binding_sha256'])
 need(ready['roles']['model']['identity']==[ident[k] for k in ('pid','pgid','sid','start_ticks')] and
      ready['actual_binding']['sha256']==runtime['binding_sha256'],'READY_model_generation_or_binding_differs')
 if require_final:
  final=FINAL_DEPENDENCIES
  need(isinstance(final,dict) and set(final)==DEPENDENCY_FIELDS,
       'future_reviewed_release_dependencies_are_unfrozen')
  for key in DEPENDENCY_FIELDS-{'live_policy'}:exact_hash(final[key])
  policy=final['live_policy']
  need(isinstance(policy,dict) and set(policy)=={'bytes','sha256'} and
       type(policy['bytes']) is int and 0<policy['bytes']<=16*1024*1024,'reviewed_live_policy_pin_required')
  exact_hash(policy['sha256'])
  need(bound['operator_package_sha256']==final['fault_package_sha256'] and
       bound['release_pins']['configuration_sha256']==final['configuration_sha256'] and
       bound['release_pins']['service_inputs_sha256']==final['service_inputs_sha256'] and
       bound['release_pins']['policy_adoption_inputs_sha256']==final['policy_adoption_sha256'] and
       ready['policy_sha256']==policy['sha256'],'actual_plan_and_reviewed_release_differ')
 return owner,ready

def save_generated(relative,raw,kind):
 global RETAINED
 need(isinstance(raw,bytes) and relative not in GENERATED and relative not in RAW and
      RETAINED+len(raw)<=MAX_BYTES,'generated_original_byte_budget_or_duplicate')
 save(relative,raw);RETAINED+=len(raw)
 GENERATED[relative]={'bytes':len(raw),'sha256':sha(raw),'kind':kind}

def capture_android_regular(path,relative,required=True,limit=MAX_FILE):
 global RETAINED
 path=Path(path)
 need(path in {MODULE/'MODULE-MANIFEST-v150-r10-r1.json',
      ANDROID/'data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.bin'},
      'only_explicit_Android_original_paths_allowed')
 relative=str(safe_relative(relative));need(relative not in RAW,'duplicate_Android_original')
 row={'source_path':str(path),'export_relative_path':relative,'required':required,
      'source_resolution':'explicit_proc1_root_anchor'}
 R['files'].append(row);need(len(R['files'])<=MAX_FILES,'capture_file_count')
 parent=None;fd=None
 try:
  parent,name=parent_fd(path);fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and
       0<=a.st_size<=limit and RETAINED+a.st_size<=MAX_BYTES,'Android_original_type_or_budget')
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
  b=os.fstat(fd);c=os.stat(name,dir_fd=parent,follow_symlinks=False)
  need(meta(a)==meta(b)==meta(c) and len(raw)==a.st_size,'Android_original_changed')
  save(relative,raw);RAW[relative]=raw;RETAINED+=len(raw);READS.append((path,meta(a)))
  row.update(state='captured',bytes=len(raw),sha256=sha(raw),stat_before=meta(a),stat_after=meta(b),eof=True)
  return raw
 except FileNotFoundError:
  row.update(state='absent',lookup_errno=2);ANDROID_ABSENT.append(path)
  if required:issue(relative,ValueError('required_Android_original_absent'))
 except Exception as error:
  row.update(state='read_error',error=type(error).__name__+':'+str(error)[:512]);issue(relative,error)
 finally:
  if fd is not None:os.close(fd)
  if parent is not None:os.close(parent)
 return None

def pending_absent():
 path=ANDROID/'data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.pending'
 parent,name=parent_fd(path)
 try:
  before=meta(os.fstat(parent))
  try:os.stat(name,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError:pass
  else:raise ValueError('selected_pending_exists')
  after=meta(os.fstat(parent));need(before==after,'selected_parent_changed')
  if path not in ANDROID_ABSENT:ANDROID_ABSENT.append(path)
  return {'source':str(path),'lookup_errno':2,'parent_metadata':before}
 finally:os.close(parent)

def kernel_observation(expected_boot):
 need(os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0),'Root_readonly_capture_required')
 with open('/proc/sys/kernel/random/boot_id','rb') as f:boot=f.read(129)
 need(len(boot)<=128 and boot.decode('ascii').strip()==expected_boot,'capture_boot_changed')
 with open('/proc/self/attr/current','rb') as f:domain=f.read(257)
 need(len(domain)<=256 and domain.rstrip(b'\0\n')==b'u:r:magisk:s0','Root_capture_domain_differs')
 anchor=os.stat(ANDROID)
 need(stat.S_ISDIR(anchor.st_mode) and (anchor.st_dev,anchor.st_ino)!=(os.stat('/').st_dev,os.stat('/').st_ino),
      'Android_init_anchor_differs')
 with open(ANDROID/'sys/fs/selinux/enforce','rb') as f:enforce=f.read(9)
 need(enforce in (b'1',b'1\n'),'SELinux_not_Enforcing')
 fd=open_live_policy(ANDROID/'sys/fs/selinux/policy')
 try:
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(FINAL_DEPENDENCIES['live_policy']['bytes']+1)
 finally:os.close(fd)
 need({'bytes':len(raw),'sha256':sha(raw)}==FINAL_DEPENDENCIES['live_policy'],'actual_policy_differs')
 return {'boot_id':expected_boot,'boot_original_b64':base64.b64encode(boot).decode(),
         'enforce_original_b64':base64.b64encode(enforce).decode(),
         'policy':{'bytes':len(raw),'sha256':sha(raw)},'android_anchor':[anchor.st_dev,anchor.st_ino],
         'observer_uid':0,'observer_gid':0,'domain_original_b64':base64.b64encode(domain).decode(),
         'policy_open_function_parent_sha256':POLICY_OPEN_PARENT_SHA,
         'policy_adoption_inferred':False}

def capture_release(bound,ready):
 pins=bound['release_pins']
 raw=capture(BASE/'provider-r10-r1/SOURCE-SEAL-v150-r10.json',
             'sources/provider-r10/SOURCE-SEAL-v150-r10.json',True,262144)
 need(raw is not None and sha(raw)==pins['source_seal_sha256'],'actual_source_seal_pin')
 seal=strict(raw);rows=seal['production_files']
 need(len(rows)==15 and len({row['path'] for row in rows})==15,'sealed_fifteen_sources')
 for row in rows:
  relative=safe_relative(row['path'])
  need(len(relative.parts)==2 and relative.parts[0]=='source' and relative.suffix=='.py',
       'sealed_production_relative_path')
  data=capture(BASE/'provider-r10-r1'/relative,'sources/provider-r10/'+str(relative),True,1048576)
  need(data is not None and len(data)==row['bytes'] and sha(data)==row['sha256'],'sealed_production_pin')
 for relative,path,pin in (
  ('sources/local-config-r10.json',BASE/'local-config-r10-r1.json',pins['configuration_sha256']),
  ('sources/PHONE-SERVICE-INPUTS-v150-r10.json',BASE/'PHONE-SERVICE-INPUTS-v150-r10-r1.json',pins['service_inputs_sha256']),
  ('sources/tool_client_r6.py',BASE/'tool_client_r6.py',CLIENT_SHA)):
  data=capture(path,relative,True,262144);need(data is not None and sha(data)==pin,'actual_fixed_input_pin')
 need(seal['configuration']['sha256']==pins['configuration_sha256'] and
      seal['phone_service_inputs_sha256']==pins['service_inputs_sha256'] and
      strict(RAW['sources/local-config-r10.json'])['service_manifest_sha256']==pins['service_inputs_sha256'],
      'sealed_source_configuration_service_chain')
 for name,pin in (('release_boundaries.py',FINAL_DEPENDENCIES['consumer_sha256']),
                  ('collect_r10_readiness.py',FINAL_DEPENDENCIES['readiness_sha256'])):
  matches=[row for row in seal['operator_helpers'] if Path(row['path']).name==name]
  need(len(matches)==1,'sealed_operator_helper_unique_row')
  row=matches[0];relative=safe_relative(row['path'])
  need(len(relative.parts)==1 and str(relative)==name,'sealed_operator_helper_exact_relative_path')
  data=capture(BASE/'provider-r10-r1'/relative,'sources/provider-r10/'+str(relative),True,1048576)
  need(data is not None and len(data)==row['bytes'] and sha(data)==row['sha256']==pin,'sealed_operator_helper_pin')
 data=capture_android_regular(MODULE/'MODULE-MANIFEST-v150-r10-r1.json',
     'sources/MODULE-MANIFEST-v150-r10-r1.json',True,1048576)
 need(data is not None and sha(data)==pins['module_manifest_sha256'],'actual_module_manifest_pin')
 R['bindings']['actual_sealed_sources_and_module']=True

def capture_model_originals(bound):
 boot=bound['runtime']['boot_id'];root=BASE/'model-runtime-r10-r1'/boot
 for name in ('model.identity','READY-BOUND.json','STARTUP-INTENT.json','BIND-INTENT.json'):
  capture(root/name,'runtime/'+name,True,262144)
 tree(root/'bindings','runtime/bindings')
 ready=strict(RAW['runtime/READY-BOUND.json'])
 need(ready.get('state')=='READY_BOUND_IMAGE_CANCEL_REQUIRED' and
      ready['server_identity']==bound['runtime']['server_identity'] and
      ready['binding']['sha256']==bound['runtime']['binding_sha256'],'actual_model_startup_generation')
 prefix='provider-state/evidence/'+bound['sender_run']
 names=sorted(name for name in RAW if Path(name).parent==Path(prefix) and
              re.fullmatch(r'local-[0-9]{2}\.request-identity\.json',Path(name).name))
 need(len(names)<=8 and [Path(name).name for name in names]==
      ['local-%02d.request-identity.json'%i for i in range(1,len(names)+1)],'actual_model_round_inventory')
 requests=[];seen=set()
 for name in names:
  identity=strict(RAW[name]);rid=identity['request_id']
  need(identity.get('schema')=='hepta.original-wire-request.v1' and identity.get('automatic_retry') is False and
       isinstance(rid,str) and re.fullmatch('[0-9a-f]{32}',rid) and rid not in seen,
       'unique_original_model_request_identity')
  seen.add(rid)
  request_name=name[:-len('.request-identity.json')]+'.request.json'
  need(request_name in RAW and sha(RAW[request_name])==identity['request_sha256'] and
       len(RAW[request_name])==identity['request_bytes'],'actual_model_body_pin')
  tree(root/'receipts'/rid,'runtime/receipts/'+rid)
  need('runtime/receipts/'+rid+'/accepted-body.bin' in RAW and
       RAW['runtime/receipts/'+rid+'/accepted-body.bin']==RAW[request_name],
       'actual_producer_accepted_body_differs')
  requests.append({'request_id':rid,'request_identity':name,'request_sha256':identity['request_sha256'],
                   'request_bytes':identity['request_bytes']})
 R['model_requests_captured']=requests
 R['bindings']['original_model_rounds_and_producer_trees']=True

def capture_remaining_ledger():
 root=EVIDENCE/'action-ledger'
 for name in directory(root,1024):
  safe_relative(name);rel='provider-state/evidence/action-ledger/'+name
  if rel in RAW:continue
  path=root/name
  need(stat.S_ISREG(path.lstat().st_mode),'unexpected_global_ledger_subdirectory')
  need(capture(path,rel,True,262144) is not None,'global_ledger_original_not_retained')
 R['bindings']['complete_global_ledger_file_bytes']=True

def capture_fault_originals(bound):
 capture(BASE/'fault-source-bundles-r10-r1'/bound['nonce']/'OPERATOR-BUNDLE.original.json',
      'fault-bundle/OPERATOR-BUNDLE.original.json',limit=262144)
 root=BASE/'fault-watch-r10-r1'/bound['owner_request_sha256']
 actor=BASE/'fault-injections-r10-r1'/bound['owner_request_sha256']
 tree(root,'fault-watch');tree(actor,'fault-actor')
 required={'fault-watch/PLAN.original.json','fault-watch/SOURCE.original.py',
   'fault-watch/ARMED.json','fault-watch/ACTOR-PLAN.original.json','fault-watch/RESULT.json',
   'fault-actor/INTENT.json','fault-actor/PRE-SIGNAL.json','fault-actor/RESULT.json'}
 need(required<=set(RAW),'complete_fault_actor_and_watch_originals_required')
 need(sha(RAW['fault-watch/PLAN.original.json'])==bound['watch_plan_sha256'] and
      sha(RAW['fault-watch/SOURCE.original.py'])==bound['watch_source_sha256'] and
      sha(RAW['fault-watch/ACTOR-PLAN.original.json'])==bound['operator_plan_sha256'],
      'actual_fault_watch_and_actor_source_plan_pins')
 ap=strict(RAW['fault-watch/ACTOR-PLAN.original.json'])
 result=strict(RAW['fault-watch/RESULT.json']);act=strict(RAW['fault-actor/RESULT.json'])
 need(ap['case_id']==bound['case_id'] and ap['nonce']==bound['nonce'] and
      ap['scope']==bound['sender_scope'] and ap['run']==bound['sender_run'] and
      ap['owner_request_sha256']==bound['owner_request_sha256'] and
      ap['operation_id']==bound['operator_label'],'actual_fault_actor_plan_binding')
 need(result['state']=='ONE_FAULT_AND_FINAL_ORIGINAL_OBSERVATION_RETAINED' and
      result['actor_plan_sha256']==bound['operator_plan_sha256'] and
      result['watch_plan_sha256']==bound['watch_plan_sha256'] and
      result['watch_source_sha256']==bound['watch_source_sha256'] and
      result['case_id']==bound['case_id'] and result['scope']==bound['sender_scope'] and
      result['automatic_retry'] is False and result['physical_case_pass'] is False and
      act['state']=='ONE_PIDFD_ACTION_RETURNED','actual_fault_actor_not_successfully_joined')
 need('FAILURE.json' not in {Path(k).name for k in RAW if k.startswith(('fault-watch/','fault-actor/'))},
      'failed_fault_attempt_cannot_close')
 if bound['case_id']=='NEG-07':
  need('fault-watch/PRE-LATE-FENCE.json' in RAW and 'fault-watch/PRE-LATE-DURABILITY.json' in RAW and 'fault-watch/POST-LATE-FENCE.json' in RAW and
       'fault-watch/LATE-RECEIPT.original.json' in RAW,'actual_NEG07_live_before_late_fence_missing')
 R['fault_watch_plan_sha256']=bound['watch_plan_sha256']
 R['fault_watch_source_sha256']=bound['watch_source_sha256']
 R['bindings']['complete_original_fault_actor_and_watch']=True

def capture_bound(bound):
 global OUT,SNAP
 need(type(REVIEWED_PLAN_RAW) is bytes and 0<len(REVIEWED_PLAN_RAW)<=MAX_PLAN
      and strict(REVIEWED_PLAN_RAW)==bound,'exact_reviewed_plan_original_required')
 owner,ready=validate_negative_plan(bound,require_final=True)
 nonce=bound['nonce'];scope=bound['sender_scope'];wanted=bound['owner_request_sha256']
 before=kernel_observation(bound['runtime']['boot_id'])
 if not CAPTURE_ROOT.exists():mkdir_new(CAPTURE_ROOT)
 need(CAPTURE_ROOT.resolve(strict=True)==CAPTURE_ROOT and
      stat.S_IMODE(CAPTURE_ROOT.stat().st_mode)==0o700 and CAPTURE_ROOT.stat().st_uid==0,
      'private_negative_capture_parent')
 OUT=CAPTURE_ROOT/nonce;mkdir_new(OUT);SNAP=OUT/'snapshot';mkdir_new(SNAP)
 for rel in ('provider-state','client-receipts','executor-r6/actions','sources/provider-r10/source',
             'runtime','observations','client-selected','native-originals'):
  (SNAP/rel).mkdir(mode=0o700,parents=True,exist_ok=True)
 R.update(nonce=nonce,case_id=bound['case_id'],owner_request_sha256=wanted,
   combination_sha256=bound['combination_sha256'],selected_scope=scope,
   native_request_sha256=bound['native_request_sha256'],
   sender_label=bound['sender_label'],sender_run=bound['sender_run'],
   operator_label=bound['operator_label'],operator_plan_sha256=bound['operator_plan_sha256'],
   operator_package_sha256=bound['operator_package_sha256'],release_pins=bound['release_pins'],
   reviewed_dependencies=FINAL_DEPENDENCIES,
   snapshot_scope='Individual stable original files with final metadata/name checks; not an atomic filesystem snapshot.',
   fault_eligibility_assessed=False,physical_case_pass=False,native_closure_issued=False)
 save_generated('SOURCE.original.py',REVIEWED_CAPTURE_RAW,'exact_reviewed_compiled_source')
 save_generated('CAPTURE-PLAN.original.json',REVIEWED_PLAN_RAW,'exact_explicit_Root_input_bytes')
 save_generated('host-bound-request.txt',owner,'exact_owner_UTF8_copy')
 save_generated('selected-scope.json',encoded({'scope':scope,'source':'Root pinned original sender acceptance'}),
                'derived_original_selection')
 save_generated('observations/KERNEL-BEFORE.json',encoded(before),'derived_read_observation')
 ready_raw=base64.b64decode(bound['runtime_binding']['readiness']['raw_b64'],validate=True)
 save_generated('readiness/ACTUAL-READY.original.json',ready_raw,'explicit_original_READY_bytes')
 capture_release(bound,ready)
 run=find_run(wanted,scope);need(run==bound['sender_run'],'actual_sender_run_differs')
 R.update(actual_run=run,actual_run_dir=str(EVIDENCE/run))
 R['bindings']['unique_original_provider_owner_scope_run']=True
 prefix='provider-state/evidence/'+run;tree(EVIDENCE/run,prefix)
 incoming=RAW[prefix+'/provider-in.jsonl']
 need(incoming.endswith(b'\n'),'provider_input_incomplete')
 first=strict(incoming.splitlines()[0]);turn=first['turn']
 need(first['kind']=='turn.start' and {k:turn[k] for k in KEYS}==scope and
      turn['user_input'].encode()==owner,'original_provider_owner_scope')
 R['bindings']['provider_start_exact_owner']=True
 claim_key=sha(json.dumps([scope[k] for k in KEYS[:-1]],ensure_ascii=True,separators=(',',':')).encode())
 raw=capture(EVIDENCE/'claims'/claim_key,'provider-state/evidence/claims/'+claim_key,True,65536)
 need(raw is not None,'original_claim_missing');claim=strict(raw)
 need(claim.get('identity')==scope and claim.get('request_sha256')==wanted and
      claim.get('state')=='accepted_no_redispatch' and claim.get('run_dir')==str(EVIDENCE/run),
      'actual_durable_claim_binding')
 R['claim_key']=claim_key;R['bindings']['durable_claim_scope_owner_run']=True
 for kind in ('templates','bindings'):
  need(capture(STATE/'task-contracts'/kind/(wanted+'.json'),
       'provider-state/task-contracts/'+kind+'/'+wanted+'.json',True,131072) is not None,
       'original_registered_task_contract_missing')
 need(sha(RAW['provider-state/task-contracts/templates/'+wanted+'.json'])==bound['task_template_sha256'],
      'original_task_template_pin')
 resolved=strict(RAW[prefix+'/task-app-scope.json'])
 need(resolved.get('schema')=='hepta.resolved-task-app-scope.v1' and
      resolved.get('mode')=='request_bound_explicit_subset' and
      resolved.get('owner_request_sha256')==wanted and
      resolved.get('app_scope_sha256')==bound['app_scope_sha256'],
      'actual_resolved_task_app_scope_binding')
 R['bindings']['original_task_contract_and_app_scope']=True
 capture_fault_originals(bound)
 capture_model_originals(bound)
 capture_actions(run,scope);capture_remaining_ledger()
 native_capture(scope)
 records=[strict(line) for line in (SNAP/'selected-native-raw.jsonl').read_bytes().splitlines()]
 need(all(row['payload']['request_sha256']==bound['native_request_sha256'] for row in records),
      'original_native_envelope_digest_differs')
 R['bindings']['complete_native_source_bytes_and_scope_selection']=True
 before_pending=pending_absent()
 selected=capture_android_regular(ANDROID/'data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.bin',
                                  'client-selected/owner-client-session-v1.bin',True,262144)
 need(selected is not None,'actual_selected_state_missing')
 after_pending=pending_absent();need(before_pending==after_pending,'selected_pending_bookends_differ')
 save_generated('observations/SELECTED-PENDING-ABSENCE.json',
                encoded({'before':before_pending,'after':after_pending}),'derived_read_observation')
 R['bindings']['original_selected_state_and_pending_absence']=True
 after=kernel_observation(bound['runtime']['boot_id'])
 need(after==before,'boot_Enforcing_policy_or_anchor_changed')
 save_generated('observations/KERNEL-AFTER.json',encoded(after),'derived_read_observation')
 R['bindings']['boot_Enforcing_policy_bookends_equal']=True
 R['generated_originals']=GENERATED

def archive_snapshot():
 paths=[]
 for root,dirs,files in os.walk(SNAP,followlinks=False):
  dirs.sort();files.sort()
  for d in dirs:need(not (Path(root)/d).is_symlink(),'snapshot_link_directory')
  for name in files:
   p=Path(root)/name;need(p.is_file() and not p.is_symlink(),'snapshot_file_type')
   paths.append(p)
 need(len(paths)<=MAX_FILES+16,'archive_member_count')
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
 global REVIEWED_CAPTURE_RAW,REVIEWED_PLAN_RAW
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--plan-b64')
 parser.add_argument('--plan-sha256')
 parser.add_argument('--reviewed-source-sha256')
 parser.add_argument('--execute-read-once',action='store_true')
 args=parser.parse_args()
 if not args.execute_read_once:
  if args.plan_b64 is not None:
   data=base64.b64decode(args.plan_b64,validate=True)
   need(0<len(data)<=MAX_PLAN and sha(data)==args.plan_sha256,'preview_plan_byte_pin')
   validate_negative_plan(strict(data),require_final=False)
  print(encoded({'schema':'hepta.physical-fault.phone-capture-preview.v1',
   'state':'SOURCE_ONLY_PREVIEW_NO_PHONE_READ','future_dependencies_frozen':FINAL_DEPENDENCIES is not None,
   'phone_reads':0,'phone_writes':0,'new_nonces':0,'case_executions':0,
   'capture_seconds':50,'finalize_seconds':15,'maximum_retained_bytes':MAX_BYTES,
   'maximum_native_scan_bytes':MAX_SCAN,'maximum_files':MAX_FILES}).decode(),end='')
  return 0
 need(args.plan_b64 is not None and args.plan_sha256 is not None and args.reviewed_source_sha256 is not None,
      'explicit_plan_and_source_pins_required')
 data=base64.b64decode(args.plan_b64,validate=True)
 need(0<len(data)<=MAX_PLAN and sha(data)==args.plan_sha256,'actual_plan_byte_pin')
 bound=strict(data);validate_negative_plan(bound,require_final=True)
 source=globals().get('_REVIEWED_SOURCE_BYTES')
 need(type(source) is bytes and 0<len(source)<=65536 and sha(source)==args.reviewed_source_sha256,
      'exact_reviewed_compiled_source_required')
 REVIEWED_CAPTURE_RAW=source
 REVIEWED_PLAN_RAW=data
 need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'preexisting_capture_alarm')
 previous=signal.getsignal(signal.SIGALRM);signal.signal(signal.SIGALRM,timeout)
 started=time.monotonic_ns();archive=None;capture_sha=None
 try:
  signal.setitimer(signal.ITIMER_REAL,50)
  try:capture_bound(bound)
  except Exception as error:issue('capture',error)
  finally:signal.setitimer(signal.ITIMER_REAL,0)
  signal.setitimer(signal.ITIMER_REAL,15)
  try:
   final_stability()
   for path in ANDROID_ABSENT:
    parent,name=parent_fd(path)
    try:
     try:os.stat(name,dir_fd=parent,follow_symlinks=False)
     except FileNotFoundError:continue
     raise ValueError('Android_original_absence_changed')
    finally:os.close(parent)
   expected={'actual_sealed_sources_and_module','unique_original_provider_owner_scope_run',
    'provider_start_exact_owner','durable_claim_scope_owner_run','original_task_contract_and_app_scope',
    'original_model_rounds_and_producer_trees','complete_action_ledger_intent_inventory',
    'complete_action_ledger_auxiliary_originals','dispatched_tool_originals_enumerated',
    'reservation_originals_enumerated','complete_global_ledger_file_bytes',
    'complete_native_source_bytes_and_scope_selection','original_selected_state_and_pending_absence',
    'boot_Enforcing_policy_bookends_equal','complete_original_fault_actor_and_watch'}
   R.update(source_sha256=sha(source),plan_sha256=sha(data),generated_originals=GENERATED,
      retained_original_bytes=RETAINED,native_scan_bytes=SCANNED,
      elapsed_capture_monotonic_ns=time.monotonic_ns()-started)
   R['export_complete']=not R['issues'] and set(R['bindings'])==expected and all(v is True for v in R['bindings'].values())
   R['state']='CAPTURED_NEGATIVE_ORIGINALS_UNQUALIFIED' if R['export_complete'] else 'PARTIAL_NEGATIVE_ORIGINAL_CAPTURE'
   if SNAP is not None:
    report=encoded(R);need(len(report)<=2*1024*1024,'capture_manifest_size_bound')
    save('CAPTURE.json',report);capture_sha=sha(report);archive=archive_snapshot()
  except Exception as error:issue('finalize',error)
  finally:signal.setitimer(signal.ITIMER_REAL,0)
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
 result={'schema':'hepta.physical-fault.phone-capture-result.v1','state':R['state'],
  'export_complete':R.get('export_complete') is True and archive is not None and not R['issues'],
  'capture_sha256':capture_sha,'archive':archive,'case_id':bound['case_id'],'nonce':bound['nonce'],
  'owner_request_sha256':bound['owner_request_sha256'],'combination_sha256':bound['combination_sha256'],
  'selected_scope':bound['sender_scope'],'native_request_sha256':bound['native_request_sha256'],
  'source_sha256':sha(source),'plan_sha256':sha(data),
  'original_file_count':sum(x.get('state')=='captured' for x in R['files']),
  'native_record_count':len(R['native_raw_records']),'issues':R['issues'],
  'elapsed_monotonic_ns':time.monotonic_ns()-started,
  'task_submissions':0,'phone_ui_actions':0,'model_requests':0,'socket_calls':0,'tool_calls':0,
  'signals_sent':0,'new_native_nonces':0,'original_file_writes':0,'new_private_snapshot_only':True,
  'fault_eligibility_assessed':False,'native_closure_issued':False,'physical_case_pass':False,
  'automatic_retry':False}
 sys.stdout.buffer.write(encoded(result));sys.stdout.buffer.flush()
 return 0 if result['export_complete'] else 2

if __name__=='__main__':sys.exit(main())
