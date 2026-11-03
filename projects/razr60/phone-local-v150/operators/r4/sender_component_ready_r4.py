"""Fixed, read-only component-r2 readiness gate for the Root-owned one-Send actor.

This module never launches a service or connects to a socket. Production uses
only the frozen component paths below. Host fixtures replace paths in an isolated
copy of the generated probe, never by a production CLI switch.
"""
import hashlib,json,os,re,stat
from pathlib import Path
STATE=Path('/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6')
SOURCE=STATE/'source-r2/component_probe_provider.py'
SOURCE_SHA='ff65efc41c30027d0066ddd6fdf3120278c83ccdbe56d7e24922ed96782d2118'
PROOF_SHA='2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e'
RESOLUTION_SHA='7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433'
SCOPE='native executor component only; zero model requests and zero business UI effects; HEPTA task-entry UI counted separately'
CONTRACT_KEYS={'schema','nonce','owner_request_sha256','selected_session_id','selected_profile_id',
 'executor_server_instance','executor_journal','endpoint','client_sha256','parent_sha256','worker_sha256',
 'policy_rule_sha256','patched_policy_sha256','retirement_proof_sha256','retirement_resolution_sha256',
 'provider_source_sha256','expires_unix_ms','scope'}
PINS={'schema':'hepta.native-component-probe.contract.v150.r6.1',
 'executor_journal':'/data/trillionnium/owner-open/state/phone-local-v150/executor-r6-component-01',
 'endpoint':'hepta_phone_executor_v150_r6',
 'client_sha256':'500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f',
 'parent_sha256':'8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976',
 'worker_sha256':'49fb74f8798194c63d5e510c0ed81604d64a55e1df84822d9457ae4110cab6da',
 'policy_rule_sha256':'7011fc8b0e4629a05bdd9739d168cdcba9b43044e54e0cdadb6da5f5bb876381',
 'patched_policy_sha256':'67ee1d75606e42e8b95c91faa57f7a22a5070e177cd6cc82552308f3de2b25d0',
 'retirement_proof_sha256':PROOF_SHA,'retirement_resolution_sha256':RESOLUTION_SHA,
 'provider_source_sha256':SOURCE_SHA,'scope':SCOPE}
def require(ok,label):
 if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def strict(raw):
 def pairs(items):
  out={}
  for k,v in items:
   require(k not in out,'duplicate_json_key');out[k]=v
  return out
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))
 require(isinstance(value,dict),'object_required')
 return value
def private_read(path,limit,owner):
 require(path.is_absolute() and path.parent.resolve()==path.parent,'canonical_parent')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==owner and not before.st_mode&0o077 and before.st_size<=limit,'private_file_identity')
  data=bytearray();eof=False
  while len(data)<=limit:
   chunk=os.read(fd,min(65536,limit+1-len(data)))
   if not chunk:eof=True;break
   data.extend(chunk)
  after=os.fstat(fd)
 finally:os.close(fd)
 fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
 require(eof and len(data)==before.st_size and len(data)<=limit and all(getattr(before,k)==getattr(after,k) for k in fields),'file_changed_or_incomplete')
 return bytes(data)
def validate_contract(c):
 require(set(c)==CONTRACT_KEYS and all(c.get(k)==v for k,v in PINS.items()),'component_contract_frozen_binding')
 require(re.fullmatch('[0-9a-f]{32}',c['nonce']) is not None and re.fullmatch('[0-9a-f]{32}',c['executor_server_instance']) is not None,'component_nonce_instance')
 for k in ('selected_session_id','selected_profile_id'):
  require(isinstance(c[k],str) and 0<len(c[k].encode())<=256 and '\0' not in c[k],'component_selection')
 require(type(c['expires_unix_ms']) is int and c['expires_unix_ms']>0,'component_expiry')
 request=('执行一次手机本地执行器组件资格探针，标记 '+c['nonce']+'。只通过原生工具通道输出该新标记一次；不调用模型，不操作任何 App，不重放旧动作。').encode()
 require(c['owner_request_sha256']==sha(request),'component_exact_owner')
 return request
def binding(contract_path,owner_bytes,identity):
 raw=private_read(contract_path.absolute(),16384,os.getuid());c=strict(raw)
 require(validate_contract(c)==owner_bytes,'component_owner_request_bytes')
 require(c['selected_session_id']==identity['session_id'] and c['selected_profile_id']==identity['profile_id'],'component_selected_session_profile')
 return {'schema':'hepta.sender-component-binding.v150.r4','contract':c,
         'contract_sha256':sha(raw),'contract_bytes':len(raw),'source_sha256':SOURCE_SHA,
         'phone_contract_path':str(STATE/'contracts'/(c['nonce']+'.json')),
         'phone_ready_path':str(STATE/('ready-'+c['nonce']+'.json')),
         'phone_source_path':str(SOURCE)}
VALIDATOR_SOURCE = r'''
def validate_ready_observation(value,binding,previous=None,minimum_remaining_ns=15000000000):
 def need(ok,label):
  if not ok:raise ValueError(label)
 c=binding['contract'];r=value.get('ready',{})
 need(value.get('state')=='ready_observed','component_ready_not_observed')
 need(value.get('contract_sha256')==binding['contract_sha256'] and value.get('provider_source_sha256')==binding['source_sha256'],'component_raw_input_pin')
 need(value.get('claim_absent') is True and value.get('ended_absent') is True,'component_already_consumed_or_ended')
 need(value.get('attempt_bound') is True and value.get('process_identity_bound') is True,'component_attempt_or_process_identity')
 expected={'nonce':c['nonce'],'owner_request_sha256':c['owner_request_sha256'],
  'provider_source_sha256':binding['source_sha256'],'contract_sha256':binding['contract_sha256'],
  'executor_server_instance':c['executor_server_instance'],'port':18080,'scope':c['scope'],
  'readiness_scope':'transport_and_readonly_parent_identity_only','clock':'phone CLOCK_MONOTONIC'}
 need(all(r.get(k)==v for k,v in expected.items()) and r.get('accepting_one_session') is True,'component_ready_binding')
 need(type(r.get('pid')) is int and r['pid']>1 and type(r.get('pid_start_ticks')) is int and r['pid_start_ticks']>0,'component_pid_start_shape')
 need(isinstance(r.get('instance'),str) and re.fullmatch('[0-9a-f]{32}',r['instance']) is not None,'component_instance_shape')
 times=[r.get(k) for k in ('ready_monotonic_ns','accept_deadline_monotonic_ns','service_deadline_monotonic_ns')]
 now=value.get('phone_monotonic_ns');wall=value.get('phone_unix_ms')
 need(all(type(x) is int and x>0 for x in times+[now,wall]),'component_clock_shape')
 ready,accept,service=times
 need(ready<=now<accept<service and 0<accept-ready<=40000001000,'component_ready_window')
 need(abs(service-accept-30000000000)<=1000,'component_window_not_extended')
 need(accept-now>=minimum_remaining_ns,'component_accept_window_too_short')
 need(c['expires_unix_ms']-wall>=minimum_remaining_ns//1000000,'component_contract_expiring')
 need(value.get('remaining_accept_ns')==accept-now,'component_remaining_clock_binding')
 need(isinstance(value.get('ready_sha256'),str) and re.fullmatch('[0-9a-f]{64}',value['ready_sha256']) is not None,'component_ready_raw_hash')
 if previous is not None:
  need(value['ready_sha256']==previous['ready_sha256'] and
       all(r[k]==previous['ready'][k] for k in ('pid','pid_start_ticks','instance')),'component_ready_identity_changed')
 return value
'''
exec(compile(VALIDATOR_SOURCE,'sender_component_ready_validator','exec'))
PHONE_SOURCE = r'''
import base64,hashlib,json,os,re,stat,time
from pathlib import Path
BOUND=__BOUND__
STATE=Path('/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6')
PROC=Path('/proc')
def need(ok,label):
 if not ok:raise ValueError(label)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def strict(raw):
 def pairs(items):
  result={}
  for k,v in items:
   need(k not in result,'duplicate_json_key');result[k]=v
  return result
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))
 need(isinstance(value,dict),'object_required');return value
def regular(path,limit):
 need(path.parent.resolve()==path.parent,'canonical_private_parent')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o077 and before.st_size<=limit,'private_file_identity')
  data=bytearray();eof=False
  while len(data)<=limit:
   chunk=os.read(fd,min(65536,limit+1-len(data)))
   if not chunk:eof=True;break
   data.extend(chunk)
  after=os.fstat(fd)
 finally:os.close(fd)
 keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
 need(eof and len(data)==before.st_size and len(data)<=limit and all(getattr(before,k)==getattr(after,k) for k in keys),'private_read_incomplete_or_changed')
 return bytes(data)
def absent(path):
 try:path.lstat()
 except FileNotFoundError:return True
 return False
def proc_bytes(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  data=bytearray();eof=False
  while len(data)<=limit:
   chunk=os.read(fd,min(4096,limit+1-len(data)))
   if not chunk:eof=True;break
   data.extend(chunk)
 finally:os.close(fd)
 need(eof and len(data)<=limit,'proc_read_incomplete')
 return bytes(data)
def process_start(pid):
 raw=proc_bytes(PROC/str(pid)/'stat',4096)
 fields=raw.decode().rsplit(')',1)[1].split()
 need(len(fields)>19 and fields[0] not in ('Z','X','x'),'component_process_not_live')
 return int(fields[19])
c=BOUND['contract'];nonce=c['nonce']
for directory in (STATE,STATE/'contracts',STATE/'claims'):
 info=directory.lstat()
 need(directory.resolve()==directory and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,'component_private_directory')
contract=STATE/'contracts'/(nonce+'.json')
raw=regular(contract,16384)
need(digest(raw)==BOUND['contract_sha256'] and strict(raw)==c,'component_contract_raw_mismatch')
need(absent(STATE/'claims'/(nonce+'.json')),'component_claim_already_exists')
need(absent(STATE/('service-ended-'+nonce+'.json')),'component_service_already_ended')
ready_path=STATE/('ready-'+nonce+'.json')
try:ready_raw=regular(ready_path,16384)
except FileNotFoundError:
 print(json.dumps({'state':'waiting_for_ready','contract_sha256':BOUND['contract_sha256'],
  'owner_request_sha256':c['owner_request_sha256'],'nonce':nonce,
  'phone_monotonic_ns':time.monotonic_ns(),'phone_unix_ms':time.time_ns()//1000000,
  'claim_absent':True,'ended_absent':True,'phone_writes':False,'socket_connections':0}))
 raise SystemExit(0)
ready=strict(ready_raw)
need(type(ready.get('pid')) is int and ready['pid']>1,'component_ready_pid')
pid=ready['pid']
start=process_start(pid)
attempt_raw=regular(STATE/('service-attempt-'+nonce+'.json'),16384)
attempt=strict(attempt_raw)
need(attempt=={'contract_sha256':BOUND['contract_sha256'],'automatic_restart':False,'pid':pid},'component_attempt_binding')
source=STATE/'source-r2/component_probe_provider.py'
source_raw=regular(source,65536)
need(digest(source_raw)==BOUND['source_sha256'],'component_installed_source_pin')
cmdline=proc_bytes(PROC/str(pid)/'cmdline',8192)
wanted=[b'/usr/bin/python3',b'-B',str(source).encode(),b'--contract',str(contract).encode(),b'--contract-sha256',BOUND['contract_sha256'].encode()]
need(cmdline==b'\0'.join(wanted)+b'\0','component_process_cmdline')
need(start==ready.get('pid_start_ticks')==process_start(pid),'component_process_start_changed')
need(absent(STATE/'claims'/(nonce+'.json')) and absent(STATE/('service-ended-'+nonce+'.json')),'component_consumed_during_read')
need(regular(ready_path,16384)==ready_raw,'component_ready_changed_during_read')
now=time.monotonic_ns()
value={'state':'ready_observed','ready':ready,'ready_sha256':digest(ready_raw),
 'contract_sha256':digest(raw),'provider_source_sha256':digest(source_raw),
 'attempt_sha256':digest(attempt_raw),'attempt_bound':True,'process_identity_bound':True,
 'process_cmdline_sha256':digest(cmdline),'process_start_ticks':start,
 'claim_absent':True,'ended_absent':True,'phone_monotonic_ns':now,'phone_unix_ms':time.time_ns()//1000000,
 'remaining_accept_ns':ready['accept_deadline_monotonic_ns']-now,
 'phone_writes':False,'socket_connections':0,'readiness_scope':'transport_and_readonly_parent_identity_only'}
__VALIDATOR__
validate_ready_observation(value,BOUND)
print(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False))
'''
def phone_probe(bound):
 require(bound['source_sha256']==SOURCE_SHA and bound['contract']['provider_source_sha256']==SOURCE_SHA,'r2_source_required')
 return PHONE_SOURCE.replace('__BOUND__',repr(bound)).replace('__VALIDATOR__',VALIDATOR_SOURCE)
