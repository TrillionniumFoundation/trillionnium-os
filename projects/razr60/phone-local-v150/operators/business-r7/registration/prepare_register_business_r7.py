#!/usr/bin/env python3
"""Root only: fresh r7 visual/Unicode material + one registration; never Send."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,re,shlex,subprocess,sys,types
B=Path('/operator-workspace/phone-local-v150')
D=B/'business-r7-root-operator-r1'
GNU='/var/lib/trillionnium/owner-open/phone-local-v150'
SOURCE_SHA='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
CONFIG_SHA='0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755'
MATERIALIZER_SHA='23d3993c989783a89d48a1955109ae7cec163171e68801e9f19a74adc5d81efc'
AGGREGATE_SHA='c3b91281a1076ac6fd782fe722eeedae7384817dcbd89060e94b095be48ce083'
REGISTRAR_SHA='3518d52418547eaa797159d8e76aa3df38e1e1b6a61282612388e0d857d5d230'
SENDER_SHA='5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'
HARNESS_SHA='630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6'
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,label):
 if not ok:raise ValueError(label)
def put(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def jbytes(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
def pin(path,expected):
 raw=path.read_bytes();require(sha(raw)==expected,'source_pin:'+path.name);return raw
def binding_module():
 path=B/'acceptance-r7/aggregate_protocol_r7.py';raw=pin(path,AGGREGATE_SHA)
 module=types.ModuleType('fixed_r7_binding');module.__file__=str(path)
 exec(compile(raw,str(path),'exec'),module.__dict__)
 return module

PHONE_SOURCE=r"""
from pathlib import Path
import hashlib,json,os,stat,subprocess
B=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
kind=PAYLOAD['kind'];assert kind in ('visual','unicode')
D=B/('root-'+kind+'-r7-01')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(p,raw):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def read_new(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=16384
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(16385)
  z=os.fstat(fd);n=p.lstat()
  assert len(raw)==s.st_size and all(getattr(s,k)==getattr(z,k)==getattr(n,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))
  return raw
 finally:os.close(fd)
os.umask(0o077)
s=B.lstat();assert stat.S_ISDIR(s.st_mode) and not B.is_symlink() and B.resolve()==B
assert s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
assert not D.exists() and not D.is_symlink()
reg=B/'provider-r7/register_task_contract.py'
assert sha(reg.read_bytes())=='3518d52418547eaa797159d8e76aa3df38e1e1b6a61282612388e0d857d5d230'
assert sha((B/'provider-r7/SOURCE-SEAL-v150-r7.json').read_bytes())=='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
assert sha((B/'local-config-r7.json').read_bytes())=='0eb740aea8591a0377bc9ceecafb4b848a9dcdd7dc2cb75ffc3f0892abe5c755'
expected={'request.txt','postconditions.json','material.json','combination.json'}
if kind=='unicode':expected|={'expected-text.txt','expected-public-receipt.txt'}
assert set(PAYLOAD['files'])==expected
D.mkdir(mode=0o700)
records=[]
for name,raw in PAYLOAD['files'].items():
 assert isinstance(raw,bytes) and 0<len(raw)<=32768 and name in expected
 put(D/name,raw)
 s=(D/name).lstat()
 assert s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 assert (D/name).read_bytes()==raw
 records.append({'name':name,'bytes':len(raw),'sha256':sha(raw)})
fd=os.open(D,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
raw=PAYLOAD['files']['request.txt'];nonce=PAYLOAD['nonce'];scope=PAYLOAD['scope']
assert raw.decode('utf-8',errors='strict').count(nonce)==1
assert sha(raw)==PAYLOAD['request_sha256']
assert sha(PAYLOAD['files']['combination.json'])==PAYLOAD['combination_manifest_sha256']
args=['/usr/bin/python3','-B',str(reg),'--state',str(B/'provider-state'),
 '--request-file',str(D/'request.txt'),'--postconditions-file',str(D/'postconditions.json'),
 '--session-id',scope['session_id'],'--profile-id',scope['profile_id'],
 '--nonce',nonce,'--coverage','entire_request']
r=subprocess.run(args,capture_output=True,timeout=15)
put(D/'register.stdout',r.stdout);put(D/'register.stderr',r.stderr)
result={'schema':'hepta.root-business-registration-once.v150.r7.1','kind':kind,
 'case':PAYLOAD['case'],'rc':r.returncode,'nonce':nonce,'request_sha256':sha(raw),
 'combination_manifest_sha256':PAYLOAD['combination_manifest_sha256'],
 'combination_sha256':PAYLOAD['combination_sha256'],
 'previous_input_sha256':PAYLOAD['previous_input_sha256'],
 'expected_scope':scope,'coverage':'entire_request','files':records,
 'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr),
 'stdout_bytes':len(r.stdout),'stderr_bytes':len(r.stderr),
 'send_attempts':0,'model_requests':0,'automatic_retry':False,
 'live_selected_identity_checked_here':False,'frozen_sender_checks_required':True}
if r.returncode==0:
 assert r.stderr==b''
 value=json.loads(r.stdout);target=B/'provider-state/task-contracts/templates'/(sha(raw)+'.json')
 assert value['status']=='registered_one_time_request_contract' and value['path']==str(target)
 assert value['request_sha256']==sha(raw) and value['phone_operations']==value['model_operations']==0
 original=read_new(target)
 assert sha(original)==value['template_sha256']
 template=json.loads(original)
 assert template=={'schema':'hepta.task-template.v149.1','expected_scope':scope,
  'request_sha256':sha(raw),'nonce':nonce,'postconditions':json.loads(PAYLOAD['files']['postconditions.json']),
  'coverage':'entire_request'}
 consumed=B/'provider-state/task-contracts/bindings'/(sha(raw)+'.json')
 assert not consumed.exists() and not consumed.is_symlink()
 result['registration']=value
 result['template_original_sha256']=sha(original)
 result['unconsumed_template_read_back']=True
put(D/'REGISTRATION-RESULT.json',(json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps(result,sort_keys=True))
raise SystemExit(r.returncode)
"""
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('kind',choices=('visual','unicode'))
 p.add_argument('--combination',type=Path,required=True)
 p.add_argument('--combination-sha256',required=True)
 p.add_argument('--previous-input',type=Path,required=True)
 p.add_argument('--previous-sha256',required=True)
 p.add_argument('--execute-register-once',action='store_true')
 a=p.parse_args()
 require(a.execute_register_once,'Root explicit one-time registration required; no files or nonce generated')
 os.umask(0o077)
 bind=binding_module();bind.validate_protocol()
 selected=bind.load_combination(a.combination,a.combination_sha256)
 require(selected['frozen'],'full frozen production combination required')
 previous_raw=bind.read(a.previous_input,2*1024*1024)
 require(sha(previous_raw)==a.previous_sha256,'Root supplied previous input pin')
 previous=bind.strict(previous_raw)
 identity=previous.get('identity')
 require(isinstance(identity,dict) and set(identity)==set(KEYS),'previous requires actual five-field sender identity, not a raw collector report')
 require(all(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v for v in identity.values()),'previous scope shape')
 digest=previous.get('request_sha256')
 require(isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'previous native request digest')
 status=previous.get('terminal',{}).get('status')
 known_failed=previous.get('known_no_phone_tool_execution') is True or previous.get('known_all_dispatched_tools_confirmed_terminal') is True
 require(status in ('completed','provider_failed','cancelled') and (status=='completed' or known_failed),'previous actual terminal/receipts must already be closed')
 H=B/(a.kind+'-r7-01');run=D/(a.kind+'-01')
 require(not H.exists() and not H.is_symlink() and not run.exists() and not run.is_symlink(),'one-time output already exists; inspect original attempt')
 pin(B/'provider-r7/SOURCE-SEAL-v150-r7.json',SOURCE_SHA)
 pin(B/'acceptance-r7/materialize_case_r7.py',MATERIALIZER_SHA)
 pin(B/'provider-r7/register_task_contract.py',REGISTRAR_SHA)
 pin(B/'send_new_native_task_r5.py',SENDER_SHA)
 helper=B/'root-operators-r6-cycle03/run_cycle03.py';pin(helper,HARNESS_SHA)
 run.mkdir(mode=0o700)
 put(run/'PREVIOUS-INPUT.original.json',previous_raw)
 put(run/'PREPARE-INTENT.json',jbytes({'kind':a.kind,'previous_input_sha256':sha(previous_raw),
  'previous_identity':identity,'previous_request_sha256':digest,'previous_status':status,
  'combination_manifest_sha256':a.combination_sha256,'registration_only':True,
  'automatic_retry':False,'send_attempts':0,'nonce_generated_before_this_invocation':False}))
 argv=[sys.executable,'-B',str(B/'acceptance-r7/materialize_case_r7.py'),a.kind,
  '--combination',str(a.combination),'--combination-sha256',a.combination_sha256,'--out',str(H)]
 r=subprocess.run(argv,capture_output=True,timeout=15)
 put(run/'materialize.stdout',r.stdout);put(run/'materialize.stderr',r.stderr)
 put(run/'MATERIALIZE-TERMINAL.json',jbytes({'returncode':r.returncode,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)}))
 require(r.returncode==0 and r.stderr==b'','materialization failed; inspect original files, do not rerun')
 meta_raw=bind.read(H/'material.json',32768);meta=bind.strict(meta_raw)
 require(meta['schema']=='hepta.fresh-acceptance-material.v150.r7.1' and meta['kind']==a.kind,'material kind/schema')
 require(meta['case']=={'visual':'E2E-01','unicode':'E2E-02'}[a.kind] and meta['coverage']=='entire_request','entire-request contract required')
 require(meta['candidate_source_seal_sha256']==SOURCE_SHA and meta['combination_manifest_sha256']==a.combination_sha256,'material source/combination pin')
 require(meta['combination_sha256']==selected['combination_sha256'],'material full combination')
 nonce=meta['nonce'];require(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'fresh nonce shape')
 names=['request.txt','postconditions.json','combination.json']
 if a.kind=='unicode':names+=['expected-text.txt','expected-public-receipt.txt']
 require({row['path'] for row in meta['files']}=={str(H/name) for name in names},'exact material files')
 files={}
 for name in names:
  raw=bind.read(H/name,32768);row=next(row for row in meta['files'] if row['path']==str(H/name))
  require(row['bytes']==len(raw) and row['sha256']==sha(raw),'material exact file bytes:'+name)
  files[name]=raw
 files['material.json']=meta_raw
 request=files['request.txt']
 require(sha(request)==meta['request_sha256'] and len(request)==meta['request_utf8_bytes'],'owner exact bytes')
 require(request.decode('utf-8',errors='strict').count(nonce)==1,'nonce occurrence')
 require(sha(files['combination.json'])==a.combination_sha256,'combination exact bytes')
 payload={'kind':a.kind,'case':meta['case'],'files':files,'nonce':nonce,'request_sha256':sha(request),
  'combination_manifest_sha256':a.combination_sha256,'combination_sha256':selected['combination_sha256'],
  'scope':{key:identity[key] for key in ('session_id','profile_id')},
  'previous_input_sha256':sha(previous_raw)}
 code='PAYLOAD='+repr(payload)+'\n'+PHONE_SOURCE
 compile(code,'phone-business-registration','exec')
 put(run/'phone-registration.source.py',code.encode())
 spec=importlib.util.spec_from_file_location('root_phone_once',helper)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.D=run
 req={'kind':'shell','root':True,'timeout_seconds':45,
  'command':'/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -B -c '+shlex.quote(code)}
 put(run/'register-business.request.json',jbytes(req))
 try:ph=m.call_phone('register-fresh-native-r7-'+a.kind+'-01',req)
 except BaseException:
  print(json.dumps({'state':'ORIGINAL_REGISTRATION_UNCONFIRMED_NO_SEND','kind':a.kind,'originals_retained':True,'automatic_retry':False}))
  raise
 require(ph['rc']==0,'actual phone registration process failed')
 result=bind.strict(ph['stdout'])
 require(result['rc']==0 and result['send_attempts']==0 and result['model_requests']==0,'registration terminal')
 require(result['request_sha256']==sha(request) and result['coverage']=='entire_request','registered exact owner/coverage')
 require(result['combination_manifest_sha256']==a.combination_sha256 and result['previous_input_sha256']==sha(previous_raw),'registered provenance')
 require(result['unconsumed_template_read_back'] is True,'original template readback')
 put(run/'REGISTRATION-RESULT.json',jbytes(result))
 print(json.dumps({'state':'FRESH_BUSINESS_REGISTERED_NO_SEND','kind':a.kind,'case':meta['case'],
  'nonce':nonce,'request_sha256':sha(request),'template_sha256':result['template_original_sha256'],
  'combination_manifest_sha256':a.combination_sha256,'combination_sha256':selected['combination_sha256'],
  'phone_directory':GNU+'/root-'+a.kind+'-r7-01','send_attempts':0,'model_requests':0,
  'live_selected_identity_checked_here':False,'frozen_sender_checks_required':True,
  'automatic_replay':False},sort_keys=True))
if __name__=='__main__':main()
