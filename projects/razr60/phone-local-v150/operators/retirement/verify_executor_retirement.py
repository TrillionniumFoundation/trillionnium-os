#!/usr/bin/env python3
"""Independent, offline retirement verifier. Writes a new report only.
Never opens a phone connection, executes a command, or changes any old receipt.
A complete automatic pass is separate from explicit Root review of external
service/operation history; a capture's boolean success is never sufficient.
"""
import argparse, base64, hashlib, json, os, re, stat, sys
from pathlib import Path
AUDIT_SHA='da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'
HERE=Path(__file__).resolve().parent
assert hashlib.sha256((HERE/'native_journal_audit.py').read_bytes()).hexdigest()==AUDIT_SHA
sys.path.insert(0,str(HERE))
from native_journal_audit import strict_loads, verify_records
CAPTURE_SHA='36cbcd29621281206fcf273308e551164274daa62b26c67094cc90d489d95dee'
LEGACY_SOURCE_SEAL='700e5fb07e5ad250f4df5bd0452660b03dd0138b89718343e10e895c4db50d35'
INTENT_SHA='37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417'
ACTION='fc7bd6d939fb740a6403a04521fbb057'
COMMAND_SHA='7976b489740b138a22fb8d724f953af92b7a1e3a1c15b5b60941482ab497487f'
INSTANCE='ec17ea0567048b7094ac702fa4321d7d'
SERVER_PID=31206
SERVER_START=6437072
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
BINARY_SHA='30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa'
SOURCE_SHA='beedc3a1a178d4b75887773e8ea1feae508cef89a692b35a03da3134893cafb4'
CMDLINE_SHA='6dd75240d6802d1bc275fcc47cdc0e080bcf64b340e0596eec605f3c9920b976'
ROLES={'supervisor':(31065,31065,31065,6436889),'model':(31121,31121,31121,6437048),
       'sidecar':(31206,31206,31206,6437072),'provider':(31274,31274,31274,6437094)}
SAFE={'completed','failed','timed_out','cancelled','output_limit_exceeded'}
ROOT_REVIEW_FINDINGS={'old_mac_services_disabled_and_unloaded',
 'no_external_journal_erasure_or_state_rebinding','original_claims_and_failed_task_retained',
 'no_new_unresolved_actions','future_new_tasks_only_on_new_executor_endpoint'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,reason):
 if not ok:raise ValueError(reason)
def load_original(path,maxbytes=32*1024*1024,parse_json=True):
 path=Path(path).absolute()
 require(path.parent.resolve()==path.parent,'noncanonical original parent')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maxbytes,'original file bound/type')
  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maxbytes+1)
  after=os.fstat(fd);named=path.lstat()
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
  require(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in fields),'original file changed')
 finally:os.close(fd)
 return raw,strict_loads(raw) if parse_json else None
def decode_item(item):
 require(isinstance(item,dict) and isinstance(item.get('raw_b64'),str),'original raw bytes absent')
 raw=base64.b64decode(item['raw_b64'],validate=True)
 require(base64.b64encode(raw).decode()==item['raw_b64'],'noncanonical base64')
 count=item.get('bytes',item.get('metadata',{}).get('bytes'))
 require(type(count) is int and count==len(raw) and item.get('sha256')==sha(raw),'original byte/hash binding differs')
 return raw
def original_json(item):return strict_loads(decode_item(item))
def parse_unix(item):
 raw=decode_item(item['raw'])
 require(item.get('complete') is True and item.get('EOF_observed') is True,'Unix table lacks observed EOF')
 rows=raw.splitlines()
 require(raw.endswith(b'\n') and rows and rows[0].split()==[b'Num',b'RefCount',b'Protocol',b'Flags',b'Type',b'St',b'Inode',b'Path'],'Unix table header/end incomplete')
 matches=[];count=0
 for line in rows[1:]:
  if not line.strip():continue
  parts=line.split(None,7)
  require(len(parts) in (7,8) and parts[0].endswith(b':'),'Unix row incomplete')
  require(all(re.fullmatch(b'[0-9A-Fa-f]+',v) for v in parts[1:6]) and parts[6].isdigit(),'Unix fields malformed')
  count+=1
  if len(parts)==8 and parts[7]==b'@hepta_phone_local_v150':
   matches.append({'inode':int(parts[6]),'listener':bool(int(parts[3],16)&0x10000) and int(parts[4],16)==1})
 require(count>0 and item.get('parsed_row_count')==count,'empty/incomplete Unix table')
 return matches
def file_tree(snapshot):
 require(snapshot.get('complete') is True,'journal snapshot incomplete')
 rows=snapshot['entries']
 require(type(rows) is list and snapshot['entry_count']==len(rows),'journal count mismatch')
 require(snapshot['entries_metadata_sha256']==sha(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()),'journal metadata digest mismatch')
 entries={};size=0
 for row in rows:
  name=row['relative_path'];parts=name.split('/')
  require(name not in entries and all(p and p not in ('.','..') for p in parts),'journal path duplicate/escape')
  meta=row['metadata']
  require(meta.get('uid')==0 and meta.get('gid')==0,'journal ownership differs')
  if meta['kind']=='regular':
   require(meta['mode']==0o600 and meta['nlink']==1 and type(meta['bytes']) is int,'journal file permissions/type differ')
   require(re.fullmatch('[0-9a-f]{64}',row.get('sha256','')) and row.get('complete') is True,'file hash/completeness missing')
   size+=meta['bytes']
   if 'raw_b64' in row:decode_item(row)
  else:require(meta['kind']=='directory' and meta['mode']==0o700,'journal directory/special type differs')
  entries[name]=row
 require(size==snapshot['hashed_file_bytes'],'journal total size differs')
 require(set(entries)>= {'server.lock','actions'},'journal root missing')
 for key in ('base_metadata','actions_metadata'):
  m=snapshot[key];require(m['kind']=='directory' and m['uid']==m['gid']==0 and m['mode']==0o700,'journal root identity/owner differs')
 absence=snapshot['target_absence']
 require(absence.get('action_id')==ACTION and absence.get('exists') is False
         and absence.get('absence_confirmed') is True and absence.get('direct_errno')==2
         and absence.get('method')=='fstatat_same_anchored_actions_fd_AT_SYMLINK_NOFOLLOW','target is not directly ENOENT')
 require(not any(name=='actions/'+ACTION or name.startswith('actions/'+ACTION+'/') for name in entries),'target action exists')
 ids={name.split('/')[1] for name in entries if name.startswith('actions/')}
 receipts=[]
 for token in ids:
  require(re.fullmatch('[0-9a-f]{32}',token),'unexpected action directory')
  expected={'actions/'+token,'actions/'+token+'/intent.json','actions/'+token+'/receipt.json',
            'actions/'+token+'/stdout.bin','actions/'+token+'/stderr.bin'}
  require({name for name in entries if name=='actions/'+token or name.startswith('actions/'+token+'/')}==expected,'unsafe/pending/unknown action files')
  intent=original_json(entries['actions/'+token+'/intent.json'])
  receipt=original_json(entries['actions/'+token+'/receipt.json'])
  require(intent.get('action_id')==token and receipt.get('action_id')==token
    and receipt.get('command_sha256')==intent.get('command_sha256'),'original action identity differs')
  require(receipt.get('terminal') is True and receipt.get('state') in SAFE
    and all(receipt.get(k) is True for k in ('effect_started','process_group_established','waitpid_joined','process_group_absent')),
    'journal contains unsafe original terminal')
  require(type(receipt.get('pgid')) is int and receipt['pgid']>1
    and receipt.get('pid')==receipt['pgid'] and re.fullmatch('[0-9a-f]{32}',receipt.get('server_instance','')),'receipt process/server binding missing')
  for stream in ('stdout','stderr'):
   item=entries['actions/'+token+'/'+stream+'.bin']
   require(receipt[stream+'_sha256']==item['sha256'] and receipt[stream+'_bytes']==item['metadata']['bytes'],'sidecar output metadata mismatch')
  receipts.append(receipt)
 return entries,receipts
def process_is_original(info,identity):
 return info.get('exists') is True and info.get('pid')==identity[0] and info.get('start_ticks')==identity[3]
def verify(before,after,native_records,native_report,*,before_sha,after_sha,native_sha,report_sha):
 checks=[];details={}
 def check(name,ok):
  require(ok,name);checks.append(name)
 for phase,capture in [('before',before),('after',after)]:
  check(phase+'_capture_schema_and_errors',capture.get('schema')=='hepta.executor-retirement-capture.v150.2'
    and capture.get('phase')==phase and capture.get('read_errors')==[]
    and capture.get('boot_id')==BOOT and capture.get('recovery_qualified') is False)
  expected=capture.get('expected',{})
  check(phase+'_original_binding',expected.get('action_id')==ACTION and expected.get('command_sha256')==COMMAND_SHA
    and expected.get('server_pid')==SERVER_PID and expected.get('server_start_ticks')==SERVER_START
    and expected.get('server_instance')==INSTANCE and expected.get('server_binary_sha256')==BINARY_SHA
    and expected.get('server_source_sha256')==SOURCE_SHA and expected.get('cmdline_sha256')==CMDLINE_SHA
    and expected.get('original_provider_ledger_intent_sha256')==INTENT_SHA)
  check(phase+'_read_only_operations',all(capture.get(k)==0 for k in ('sidecar_execute_requests','model_requests','filesystem_writes','process_stop_requests')))
 check('chronological_same_phone_capture',type(before.get('monotonic_end_ns')) is int
    and type(after.get('monotonic_start_ns')) is int and after['monotonic_start_ns']>before['monotonic_end_ns'])
 check('after_includes_exact_before',sha(decode_item(after['before_capture_original']))==before_sha)
 for key in ('server_before','server_after'):
  server=before[key]
  check(key+'_same_original_live_identity',server.get('exists') is True and server.get('pid')==SERVER_PID
     and server.get('start_ticks')==SERVER_START and server.get('pgid')==SERVER_PID and server.get('sid')==SERVER_PID
     and server.get('identity_stable') is True and server.get('selinux_context')=='u:r:magisk:s0')
  check(key+'_exe_cmdline_pin',server.get('executable',{}).get('sha256')==BINARY_SHA
     and sha(decode_item(server['cmdline']))==CMDLINE_SHA)
 for key,op in [('executor_health','health'),('original_action_inspect','inspect')]:
  record=before[key];request=original_json(record['request']);response=original_json(record['response'])
  check(key+'_real_peer_and_raw_protocol',record.get('operation')==op and record.get('peer_pid')==SERVER_PID
     and record.get('peer_uid')==0 and record.get('peer_context')=='u:r:magisk:s0'
     and request.get('op')==op and request.get('version')==1 and response==record['value']
     and response.get('version')==1 and response.get('protocol')=='hepta_phone_local_v150')
  if op=='health':
   check('live_health_instance',response.get('server_instance')==INSTANCE and response.get('state')=='ready')
  else:
   check('original_inspect_is_not_success',request.get('action_id')==ACTION and request.get('command_sha256')==COMMAND_SHA
     and response.get('receipt',{}).get('action_id')==ACTION
     and response['receipt'].get('state')=='not_found' and response['receipt'].get('terminal') is False)
 before_unix=parse_unix(before['unix_sockets']);server_unix=parse_unix(before['server_unix_sockets'])
 after_unix=parse_unix(after['unix_sockets'])
 netns=before['unix_sockets'].get('netns_link')
 check('same_live_and_retired_network_namespace',isinstance(netns,str) and netns.startswith('net:[')
     and before['server_unix_sockets'].get('netns_link')==netns and after['unix_sockets'].get('netns_link')==netns)
 listener={r['inode'] for r in before_unix if r['listener']}
 server_listener={r['inode'] for r in server_unix if r['listener']}
 fd_sockets={}
 for row in before['server_fds']:
  match=re.fullmatch(r'socket:\[([0-9]+)\]',row.get('link',''))
  if match:fd_sockets[int(match.group(1))]=row['fd']
 check('original_listener_bound_to_same_server_fd',bool(listener & server_listener & set(fd_sockets)))
 check('old_endpoint_absent_after_complete_EOF',not after_unix)
 tree_before,receipts=file_tree(before['journal']);tree_after,after_receipts=file_tree(after['journal'])
 check('whole_original_journal_unchanged',tree_before==tree_after and receipts==after_receipts)
 for key in ('base_metadata','actions_metadata'):
  check(key+'_same_original_inode',before['journal'][key]==after['journal'][key])
 actionmeta=before['journal']['actions_metadata']
 actionfds=[r for r in before['server_fds'] if r.get('metadata',{}).get('kind')=='directory'
     and r['metadata'].get('dev')==actionmeta['dev'] and r['metadata'].get('ino')==actionmeta['ino']]
 check('journal_was_actual_original_actions_fd',bool(actionfds))
 for key in ('original_client_claim','original_client_result','original_provider_ledger_intent'):
  raw_before=decode_item(before[key]);raw_after=decode_item(after[key])
  check(key+'_unchanged',raw_before==raw_after)
 ledger=original_json(before['original_provider_ledger_intent'])
 check('original_ledger_exact_bytes',sha(decode_item(before['original_provider_ledger_intent']))==INTENT_SHA
      and len(decode_item(before['original_provider_ledger_intent']))==832
      and ledger.get('action_id')==ACTION and ledger.get('command_sha256')==COMMAND_SHA)
 claim=original_json(before['original_client_claim']);client=original_json(before['original_client_result'])
 check('original_client_claim_and_failure_retained',claim.get('action_id')==client.get('action_id')==ACTION
    and claim.get('command_sha256')==client.get('command_sha256')==COMMAND_SHA
    and client.get('state')=='indeterminate' and client.get('can_redispatch') is False)
 for name,pin in [('service.sh','77100454bbb4a9cf614f8292cbbab21d9988504f92c03f005fcf13ef66247ce6'),
                  ('role_guard.sh','c0197647dbfcf7b481dbcd6fef53ff09df1ec3d6d973340690e7a058791299d7')]:
  check(name+'_same_reviewed_source',before['services']['module_files'][name]['sha256']==pin
      and after['services']['module_files'][name]['sha256']==pin)
 marker=after['services']['module_files']
 check('original_module_disabled_or_removed',any(marker[name].get('exists') is True
     and marker[name].get('metadata',{}).get('kind')=='regular' for name in ('disable','remove')))
 for key in ('dev','ino','uid','gid','mode'):
  check('per_boot_claim_retained_'+key,before['services']['per_boot_claim_directory_metadata'][key]
      ==after['services']['per_boot_claim_directory_metadata'][key])
 for name,item in before['services']['claim_files'].items():
  if name.endswith(('.stdout','.stderr')) or item.get('exists') is not True:continue
  check('retained_original_boot_record_'+name,item['sha256']==after['services']['claim_files'][name].get('sha256'))
 census=after['process_census']
 check('complete_retired_process_census',census.get('complete') is True and census.get('unreadable')==[])
 groupmap={r['pgid']:r for r in after['owned_process_groups']}
 required_groups={v[1] for v in ROLES.values()}
 historical=[]
 for receipt in receipts:
  if receipt['server_instance']==INSTANCE:required_groups.add(receipt['pgid'])
  else:historical.append({'action_id':receipt['action_id'],'server_instance':receipt['server_instance'],
      'old_pgid':receipt['pgid'],'original_safe_terminal':True,
      'current_numeric_group_observation':groupmap.get(receipt['pgid']),
      'signal_to_current_occupants_authorized':False})
 details['historical_groups']=historical
 for role,identity in ROLES.items():
  actual=tuple(map(int,decode_item(after['services']['claim_files'][role+'.identity']).decode().strip().split(':')))
  check(role+'_original_identity_retained',actual==identity)
  observed=after['role_process_identities'][role]
  check(role+'_original_process_retired',not process_is_original(observed,identity)
       and (observed.get('exists') is False and observed.get('direct_errno')==2
            or observed.get('exists') is True and observed.get('start_ticks')!=identity[3]))
 for pgid in sorted(required_groups):
  observed=groupmap.get(pgid,{})
  check('current_epoch_group_absent_'+str(pgid),observed.get('absence_confirmed') is True
       and observed.get('census_members')==[] and observed.get('signal_zero',{}).get('absent') is True
       and observed['signal_zero'].get('errno')==3
       and not any(row['pgid']==pgid for row in census['processes']))
 require(type(native_records) is list and native_records,'native records absent')
 scope=native_records[0]['scope'];audit=verify_records(native_records,scope)
 check('native_original_record_hashes_and_full_turn',audit['status']=='PASS' and len(native_records)==7)
 check('native_scope_matches_original_intent',all(scope[k]==v for k,v in ledger['semantic_identity'].items()))
 frames=audit['frames'];call=ledger['call_id']
 selected=[f for f in frames if str(f.get('kind','')).startswith('tool.')]
 check('native_has_only_original_call',selected and {f.get('call_id') for f in selected}=={call})
 for kind in ('tool.accepted','tool.started','tool.result'):
  check('native_exact_once_'+kind,sum(f.get('kind')==kind for f in selected)==1)
 result=next(f['payload'] for f in selected if f['kind']=='tool.result')
 data={stream:b''.join(base64.b64decode(f['payload']['data'],validate=True)
       for f in selected if f['kind']=='tool.'+stream) for stream in ('stdout','stderr')}
 check('original_failed_client_terminal',result.get('exit_code')==71 and result.get('output_truncated') is False
       and result.get('stdout_bytes')==len(data['stdout'])==0 and result.get('stderr_bytes')==len(data['stderr'])==426)
 prefix=b'\nHEPTA_PHONE_LOCAL '
 check('original_client_diagnostic_exact_binding',data['stderr'].startswith(prefix) and data['stderr'].endswith(b'\n'))
 diagnostic=strict_loads(data['stderr'][len(prefix):-1])
 check('diagnostic_preserves_unknown_transport',diagnostic.get('client_error')=='transport_indeterminate_no_retry'
       and diagnostic.get('action_id')==ACTION and diagnostic.get('receipt')==client)
 check('original_native_failed_not_rewritten',frames[-1]['kind']=='turn.end' and frames[-1]['payload']['status']=='provider_failed')
 check('original_report_scope_source_failure_retained',native_report.get('scope')==scope
    and native_report.get('candidate_source_seal_sha256')==LEGACY_SOURCE_SEAL
    and native_report.get('complete_business_success') is False
    and native_report.get('native_terminal',{}).get('status')=='provider_failed')
 toolrows=native_report.get('tools',[])
 check('original_report_raw_stream_alignment',len(toolrows)==1 and toolrows[0].get('action_id')==ACTION
     and toolrows[0].get('command_sha256')==COMMAND_SHA and toolrows[0].get('call_id')==call
     and toolrows[0].get('native_raw_streams_equal') is True
     and all(toolrows[0].get('raw_output',{}).get(stream)=={'bytes':len(raw),'sha256':sha(raw)} for stream,raw in data.items()))
 audit.pop('selected_records');audit.pop('frames');details['native_hash_verification']=audit
 details['native_terminal']=result
 details['original_request_scope']=scope
 details['actions_directory_identity']={'dev':actionmeta['dev'],'ino':actionmeta['ino']}
 details['original_server_listener_fds']=[{'fd':fd_sockets[x],'inode':x} for x in sorted(listener & server_listener & set(fd_sockets))]
 return {'checks':checks,'details':details,'artifact_sha256':{'before':before_sha,'after':after_sha,'native_records':native_sha,'native_report':report_sha}}
def validate_external_review(review,proof,review_dir):
 require(review.get('schema')=='hepta.retirement-root-review.v150.1','Root review schema')
 require(review.get('action_id')==ACTION and review.get('intent_sha256')==INTENT_SHA,'Root review original identity')
 require(review.get('artifact_sha256')==proof['artifact_sha256'],'Root review evidence bindings')
 findings=review.get('findings')
 require(type(findings) is dict and set(findings)==ROOT_REVIEW_FINDINGS,'Root review findings missing')
 references=[]
 for name in sorted(ROOT_REVIEW_FINDINGS):
  finding=findings[name]
  require(finding.get('reviewed_conclusion') is True and isinstance(finding.get('reason'),str) and finding['reason'].strip(),'unreviewed external condition')
  refs=finding.get('evidence')
  require(type(refs) is list and refs,'Root review needs actual original artifacts')
  for item in refs:
   p=Path(item['path'])
   if not p.is_absolute():p=review_dir/p
   raw,_unused=load_original(p,parse_json=False)
   require(sha(raw)==item.get('sha256'),'Root review artifact pin differs')
   references.append({'finding':name,'path':str(p),'sha256':sha(raw),'bytes':len(raw)})
 return references
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('before','after','native-records','native-report','capture-source'):
  p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--native-report-sha256',required=True)
 p.add_argument('--root-review',type=Path)
 p.add_argument('--root-review-sha256')
 p.add_argument('--output',type=Path,required=True)
 args=p.parse_args()
 report={'schema':'hepta.executor-retirement-proof.v150.1','action_id':ACTION,'command_sha256':COMMAND_SHA,
     'intent_sha256':INTENT_SHA,'verifier_sha256':sha(Path(__file__).read_bytes()),
     'retired_executor':{'server_instance':INSTANCE,'pid':SERVER_PID,'start_ticks':SERVER_START,'boot_id':BOOT,
     'binary_sha256':BINARY_SHA,'source_sha256':SOURCE_SHA,'endpoint':'hepta_phone_local_v150'},
     'automatic_checks_pass':False,'external_review_verified':False,'eligible_for_new_version_resolution':False,
     'resolution_written':False,'business_verified':False,'automatic_replay':False,
     'original_task_terminal_unchanged':True,'old_claims_edited':False,
     'trust_boundary':'Trusted sole Root operating history; no privileged external journal erasure/rebinding. Not a cryptographic proof against privileged tampering.'}
 try:
  require(sha(args.capture_source.read_bytes())==CAPTURE_SHA,'capture source pin differs')
  br,before=load_original(args.before);ar,after=load_original(args.after)
  nr,native=load_original(args.native_records);rr,native_report=load_original(args.native_report)
  require(sha(rr)==args.native_report_sha256,'original report pin differs')
  proof=verify(before,after,native,native_report,before_sha=sha(br),after_sha=sha(ar),native_sha=sha(nr),report_sha=sha(rr))
  report.update(proof,automatic_checks_pass=True)
  report['retired_executor'].update(actions_dev=proof['details']['actions_directory_identity']['dev'],
                                   actions_ino=proof['details']['actions_directory_identity']['ino'])
  if args.root_review:
   review_raw,review=load_original(args.root_review)
   require(args.root_review_sha256==sha(review_raw),'Root review byte pin required')
   report['external_review_original_sha256']=sha(review_raw)
   report['external_evidence']=validate_external_review(review,proof,args.root_review.parent)
   report.update(external_review_verified=True,eligible_for_new_version_resolution=True,
                 state='VERIFIED_EVIDENCE_FOR_EXPLICIT_NEW_VERSION_RESOLUTION')
  else:report['state']='AUTOMATIC_CHECKS_PASS_EXTERNAL_ROOT_REVIEW_STILL_REQUIRED'
 except Exception as exc:report.update(state='BLOCKED_RETAIN_UNKNOWN',error_type=type(exc).__name__,error=str(exc))
 raw=(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
 directory=os.open(args.output.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(directory);os.close(directory)
 print(json.dumps({'state':report['state'],'automatic_checks_pass':report['automatic_checks_pass'],
      'eligible_for_new_version_resolution':report['eligible_for_new_version_resolution'],
      'output':str(args.output),'sha256':sha(raw),'bytes':len(raw)},indent=2))
 return 0 if report['eligible_for_new_version_resolution'] else 2
if __name__=='__main__':
 raise SystemExit(main())
