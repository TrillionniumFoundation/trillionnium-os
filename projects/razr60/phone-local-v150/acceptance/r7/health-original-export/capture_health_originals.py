#!/usr/bin/env python3
"""Fixed r7 health original capture for Root. Read-only: no sockets/processes/UI.
The sole runtime argument is a bound identity object supplied by the host exporter.
No API key or preserved user draft path is read or hashed.
"""
import base64,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
STATE=BASE/'provider-state'
EVIDENCE=STATE/'evidence'
STAGED=BASE/'root-health-r7-01'
JOURNAL=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
MAX_OUTPUT=4*1024*1024
MAX_RETAIN=2*1024*1024
MAX_SCAN=64*1024*1024
MAX_FILES=160
MAX_LINE=1024*1024
PINNED_SOURCES={
 'sources/SOURCE-SEAL-v150-r7.json':(BASE/'provider-r7/SOURCE-SEAL-v150-r7.json','7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'),
 'sources/local-config-r7.json':(BASE/'local-config-r7.json','0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755'),
 'sources/PHONE-SERVICE-INPUTS-v150-r3.json':(BASE/'PHONE-SERVICE-INPUTS-v150-r3.json','ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2'),
 'sources/provider_phone_local.py':(BASE/'provider-r7/source/provider_phone_local.py','8f57e86ec66e4588e2e6f43ea761f17e9ae02361791995ff2f5831a16e46dbe6')}
R={'schema':'hepta.production-health-original-capture.v150.r7.1','state':'PARTIAL_ORIGINAL_CAPTURE',
 'phone_actions':0,'model_calls':0,'socket_calls':0,'service_changes':0,'task_submissions':0,
 'qualification':False,'read_only':True,'files':[],'directories':[],'native_sources':[],
 'native_raw_records':[],'issues':[],'bindings':{},
 'limits':{'stdout_bytes':MAX_OUTPUT,'retained_original_bytes':MAX_RETAIN,'native_scan_bytes':MAX_SCAN,'regular_file_count':MAX_FILES,'seconds':40}}
RAW={};READS=[];retained=0;scan_bytes=0;SCOPE=None
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,message):
 if not ok:raise ValueError(message)
def meta(s):
 return {k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
def strict(raw):
 def pairs(items):
  out={}
  for k,v in items:
   need(k not in out,'duplicate_json_key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite_json')))
def issue(label,error):
 R['issues'].append({'where':label,'type':type(error).__name__,'message':str(error)[:512]})
def directory(path,cap,required=True):
 path=Path(path)
 try:
  need(path.resolve(strict=True)==path,'directory_noncanonical_or_symlink')
  before=path.lstat();need(stat.S_ISDIR(before.st_mode),'not_directory')
  names=sorted(os.listdir(path));need(len(names)<=cap,'directory_entry_budget')
  after=path.lstat();need(meta(before)==meta(after),'directory_changed_during_listing')
  R['directories'].append({'path':str(path),'state':'observed','stat':meta(before),'names':names})
  return names
 except FileNotFoundError:
  R['directories'].append({'path':str(path),'state':'absent','lookup_errno':2,'required':required})
  if required:issue(str(path),ValueError('required_directory_absent'))
 except Exception as e:issue(str(path),e)
 return []
def capture(path,relative,required=True,limit=524288):
 global retained
 path=Path(path);row={'source_path':str(path),'export_relative_path':relative,'required':required}
 R['files'].append(row)
 if len(R['files'])>MAX_FILES:raise ValueError('file_count_budget')
 fd=None
 try:
  need(path.name not in ('api.key','llama-api.key'),'key_file_never_read')
  need(path.parent.resolve(strict=True)==path.parent,'file_parent_noncanonical_or_symlink')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'not_single_link_regular_file')
  need(0<=before.st_size<=limit and retained+before.st_size<=MAX_RETAIN,'original_file_byte_budget')
  chunks=[];size=0
  while True:
   part=os.read(fd,min(65536,limit+1-size))
   if not part:break
   chunks.append(part);size+=len(part);need(size<=limit,'file_grew_past_bound')
  raw=b''.join(chunks);after=os.fstat(fd);named=path.lstat()
  need(meta(before)==meta(after)==meta(named) and len(raw)==before.st_size,'file_changed_or_incomplete_read')
  row.update(state='captured',stat_before=meta(before),stat_after=meta(after),eof=True,
    bytes=len(raw),sha256=sha(raw),raw_b64=base64.b64encode(raw).decode())
  retained+=len(raw);RAW[relative]=raw;READS.append((path,meta(before)))
  return raw
 except FileNotFoundError:
  row.update(state='absent',lookup_errno=2)
  if required:issue(relative,ValueError('required_original_absent'))
 except Exception as e:
  row.update(state='read_error',error=type(e).__name__+':'+str(e)[:512]);issue(relative,e)
 finally:
  if fd is not None:os.close(fd)
 return None
def search_actual_run(wanted,hint):
 matches=[]
 names=directory(EVIDENCE,1024)
 candidates=[n for n in names if re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',n)]
 need(len(candidates)<=512,'provider_run_count_bound')
 for name in candidates:
  d=EVIDENCE/name;need(d.resolve(strict=True)==d and d.is_dir(),'run_directory_noncanonical')
  p=d/'provider-in.jsonl';fd=None
  try:
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'provider_start_file_type')
   with os.fdopen(fd,'rb',closefd=False) as f:raw=f.readline(131073)
   after=os.fstat(fd);named=p.lstat()
   need(len(raw)<=131072 and raw.endswith(b'\n'),'provider_start_line_bound')
   need(meta(before)==meta(after)==meta(named),'provider_start_changed')
   frame=strict(raw)
   if frame.get('kind')!='turn.start':continue
   turn=frame.get('turn',{})
   if not isinstance(turn.get('user_input'),str) or sha(turn['user_input'].encode('utf-8'))!=wanted:continue
   scope={k:turn.get(k) for k in KEYS}
   need(all(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v for v in scope.values()),'actual_scope_invalid')
   matches.append({'run_dir':str(d),'run':name,'scope':scope,'provider_start_original_sha256':sha(raw),'provider_start_original_bytes':len(raw)})
  except FileNotFoundError:continue
  finally:
   if fd is not None:os.close(fd)
 R['provider_matches']=matches
 need(len(matches)==1,'exact_owner_provider_match_must_be_unique')
 match=matches[0]
 need(hint is None or match['scope']==hint,'sender_observed_scope_does_not_match_original_provider')
 return match
def capture_tree(path,relative,depth=0):
 need(depth<=3,'run_tree_depth_bound')
 for name in directory(path,128):
  need(name not in ('.','..') and '/' not in name,'invalid_run_entry')
  p=path/name
  try:
   s=p.lstat()
   if stat.S_ISDIR(s.st_mode):capture_tree(p,relative+'/'+name,depth+1)
   else:capture(p,relative+'/'+name,True)
  except Exception as e:issue(relative+'/'+name,e)
def native_capture():
 global scan_bytes,retained
 names=[n for n in directory(JOURNAL,256) if n.endswith('.jsonl')]
 need(names,'no_native_segments')
 for name in names:
  path=JOURNAL/name;row={'source_path':str(path)};R['native_sources'].append(row);fd=None
  try:
   fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'native_not_single_link_regular')
   need(before.st_size+scan_bytes<=MAX_SCAN,'native_scan_budget')
   whole=hashlib.sha256();offset=0;line_no=0
   with os.fdopen(fd,'rb',closefd=False) as f:
    while True:
     raw=f.readline(MAX_LINE+1)
     if not raw:break
     line_no+=1;scan_bytes+=len(raw);need(len(raw)<=MAX_LINE and scan_bytes<=MAX_SCAN,'native_line_or_scan_bound')
     whole.update(raw);begin=offset;offset+=len(raw)
     need(raw.endswith(b'\n'),'native_incomplete_line')
     value=strict(raw)
     if value.get('scope')==SCOPE:
      need(len(R['native_raw_records'])<128,'native_selected_count_bound')
      need(retained+len(raw)<=MAX_RETAIN,'selected_native_retention_budget')
      R['native_raw_records'].append({'source_path':str(path),'line_1based':line_no,'offset':begin,
       'bytes':len(raw),'sha256':sha(raw),'raw_b64':base64.b64encode(raw).decode(),
       'store_seq':value.get('store_seq'),'turn_seq':value.get('turn_seq'),'kind':value.get('kind')})
      retained+=len(raw)
   after=os.fstat(fd);named=path.lstat()
   need(meta(before)==meta(after)==meta(named) and offset==before.st_size,'native_segment_changed_or_short')
   row.update(state='captured_full_scan',stat_before=meta(before),stat_after=meta(after),eof=True,bytes_scanned=offset,whole_file_sha256=whole.hexdigest())
   READS.append((path,meta(before)))
  except Exception as e:row.update(state='scan_error',error=type(e).__name__+':'+str(e)[:512]);issue(str(path),e)
  finally:
   if fd is not None:os.close(fd)
 need(R['native_raw_records'],'no_selected_native_records')
 R['native_raw_records'].sort(key=lambda r:r['store_seq'] if type(r.get('store_seq')) is int else -1)
 R['native_selection_scope']='all five fields; original raw lines retained; not a full global-WAL chain claim'
def expired(signum,frame):raise TimeoutError('capture_40_second_bound')
def main():
 global SCOPE
 started=time.monotonic_ns();signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,40)
 try:
  bound=strict(base64.b64decode(sys.argv[1],validate=True))
  need(set(bound)=={'nonce','owner_request_sha256','combination_sha256','sender_scope','previous_input_sha256'},'bound_fields')
  nonce=bound['nonce'];wanted=bound['owner_request_sha256'];hint=bound['sender_scope']
  need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[0-9a-f]{64}',wanted),'new_identity_format')
  need(re.fullmatch('[0-9a-f]{64}',bound['combination_sha256']),'combination_pin_format')
  need(bound['previous_input_sha256']=='<ROOT_REVIEWED_CURRENT_PREVIOUS_SHA256_REQUIRED>','current_previous_binding')
  need(hint is None or isinstance(hint,dict) and set(hint)==set(KEYS),'sender_scope_shape')
  R.update(nonce=nonce,owner_request_sha256=wanted,combination_sha256=bound['combination_sha256'],sender_scope_hint=hint)
  for name in ('request.txt','combination.json','register.stdout','register.stderr','REGISTRATION-RESULT.json'):
   capture(STAGED/name,'registration/'+name,True)
  owner=RAW['registration/request.txt'];need(sha(owner)==wanted and owner.decode('utf-8').count(nonce)==1,'staged_exact_owner_and_nonce')
  need(sha(RAW['registration/combination.json'])==bound['combination_sha256'],'staged_combination_bytes')
  reg=strict(RAW['registration/REGISTRATION-RESULT.json'])
  need(reg.get('rc')==0 and reg.get('request_sha256')==wanted and reg.get('nonce')==nonce and reg.get('send_attempts')==0,'original_registration_binding')
  R['bindings']['staged_request_and_registration']=True
  for rel,(path,expected) in PINNED_SOURCES.items():
   raw=capture(path,rel,True,65536);need(raw is not None and sha(raw)==expected,'actual_source_pin_'+rel)
  R['bindings']['actual_source_config_service']=True
  match=search_actual_run(wanted,hint);SCOPE=match['scope'];R.update(selected_scope=SCOPE,actual_run=match['run'],actual_run_dir=match['run_dir'])
  R['bindings']['unique_provider_owner_and_sender_scope']=True
  run=EVIDENCE/match['run'];prefix='provider-state/evidence/'+match['run']
  capture_tree(run,prefix)
  incoming=RAW[prefix+'/provider-in.jsonl'];need(incoming.endswith(b'\n'),'selected_provider_input_complete_lines')
  start=strict(incoming.splitlines()[0]);turn=start['turn']
  need(start['kind']=='turn.start' and {k:turn[k] for k in KEYS}==SCOPE and turn['user_input'].encode('utf-8')==owner,'selected_original_start')
  R['bindings']['provider_start_exact_owner']=True
  claim_key=sha(json.dumps([SCOPE[k] for k in KEYS[:-1]],ensure_ascii=True,separators=(',',':')).encode())
  claim_raw=capture(EVIDENCE/'claims'/claim_key,'provider-state/evidence/claims/'+claim_key,True)
  claim=strict(claim_raw)
  need(claim.get('identity')==SCOPE and claim.get('request_sha256')==wanted and claim.get('state')=='accepted_no_redispatch' and claim.get('run_dir')==str(run),'durable_actual_claim')
  R['claim_key']=claim_key;R['bindings']['durable_claim_scope_owner_run']=True
  for part in ('templates','bindings'):
   capture(STATE/'health-contracts'/part/(wanted+'.json'),'provider-state/health-contracts/'+part+'/'+wanted+'.json',True)
  for name in ('provider-out.jsonl','terminal.json'):
   need(prefix+'/'+name in RAW,'selected_required_terminal_original_missing_'+name)
  directory(BASE/'executor-r6/actions',512,False)
  directory(BASE/'client-receipts',1024,False)
  R['zero_tool_journal_note']='Directory observations only; no action absence or success inferred. Collector verifies actual dispatch count from provider and native originals.'
  native_capture()
 except Exception as e:issue('capture',e)
 finally:signal.setitimer(signal.ITIMER_REAL,0)
 for path,original in READS:
  try:need(meta(path.lstat())==original,'changed_after_original_read')
  except Exception as e:issue(str(path),e)
 R['elapsed_monotonic_ns']=time.monotonic_ns()-started
 R['retained_original_bytes']=retained;R['native_scan_bytes']=scan_bytes
 R['snapshot_scope']='stable individual regular files, complete EOF reads and final named identity check; no atomic whole-tree claim'
 R['export_complete']=not R['issues'] and len(R['bindings'])==5 and bool(R['native_raw_records'])
 R['state']='CAPTURED_BOUND_ORIGINALS' if R['export_complete'] else 'PARTIAL_ORIGINAL_CAPTURE'
 raw=(json.dumps(R,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
 if len(raw)>MAX_OUTPUT:
  R['export_complete']=False
  raw=(json.dumps({'schema':R['schema'],'state':'PARTIAL_OUTPUT_BUDGET_EXCEEDED','export_complete':False,
    'would_be_bytes':len(raw),'limit_bytes':MAX_OUTPUT,'qualification':False,
    'phone_actions':0,'socket_calls':0,'model_calls':0,
    'message':'No complete export emitted; preserve operation and do not treat this summary as original proof.'},sort_keys=True)+'\n').encode()
 sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
 return 0 if R['export_complete'] else 2
if __name__=='__main__':sys.exit(main())
