#!/usr/bin/env python3
"""Generate readonly startup capture; keep original 256 KiB/member and 2 MiB raw export bounds."""
from pathlib import Path
import difflib,hashlib,json,os,shlex,subprocess
D=Path(__file__).resolve().parent;B=D.parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(path,raw):
 if isinstance(raw,str):raw=raw.encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
old=(B/'module-r7-r1-finalization-r1/read_module_r7_r1_readiness_once.sh').read_bytes()
assert sha(old)=='<PRIVATE_BOUND_SHA256_001_REQUIRED>'
bundle=json.loads((D/'sealed-module-v150-r7-r2/BUNDLE.json').read_bytes())
module=D/'sealed-module-v150-r7-r2/module'
manifest=module/'MODULE-MANIFEST-v150-r7-r2.json'
mr=manifest.read_bytes();assert sha(mr)==bundle['module_manifest']['sha256']
sums=(module/'module-inputs.sha256').read_bytes();assert sha(sums)==bundle['module_input_sums']['sha256']
sealed=(module/'SEALED').read_bytes()
args=shlex.split(old.decode().split('exec ',1)[1]);assert args[-2]=='-c'
code=args[-1].replace('v150-r7-r1','v150-r7-r2').replace('module-start-r7-r1','module-start-r7-r2')
marker='files=[];total=0;groups=set();expected={}\n';assert code.count(marker)==1
extra=r'''
# Module evidence is hashed only; its large host-original copies are never base64-exported.
M=Path('/proc/1/root/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r2')
module_verification={'schema':'hepta.module-all-files-readonly-hashes.v1','complete':False,'issues':[],'files':[],'raw_evidence_exported':False}
EXPECTED_MANIFEST_SHA='__MANIFEST_SHA__'
EXPECTED_SUMS_SHA='__SUMS_SHA__'
EXPECTED_SEALED_SHA='__SEALED_SHA__'
def bounded_file_hash(path):
 st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==st.st_gid==0 and st.st_size<=4194304
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  opened=os.fstat(fd);assert (st.st_dev,st.st_ino)==(opened.st_dev,opened.st_ino)
  h=hashlib.sha256();size=0
  while True:
   raw=os.read(fd,65536)
   if not raw:break
   size+=len(raw);assert size<=4194304;h.update(raw)
  after=os.fstat(fd)
  assert (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
 finally:os.close(fd)
 assert size==opened.st_size
 return {'bytes':size,'sha256':h.hexdigest(),'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode))}
if M.is_dir() and not M.is_symlink():
 observed={};hashed_bytes=0;entries=0
 for p in sorted(M.rglob('*')):
  entries+=1;assert entries<=512
  st=p.lstat()
  assert not stat.S_ISLNK(st.st_mode)
  if stat.S_ISDIR(st.st_mode):continue
  item=bounded_file_hash(p);hashed_bytes+=item['bytes'];assert hashed_bytes<=16777216
  name=str(p.relative_to(M));observed[name]=item
  module_verification['files'].append(dict(relative=name,**item))
 def exact(name,pin):
  return name in observed and observed[name]['sha256']==pin
 checks={'manifest_exact':exact('MODULE-MANIFEST-v150-r7-r2.json',EXPECTED_MANIFEST_SHA),
  'sums_exact':exact('module-inputs.sha256',EXPECTED_SUMS_SHA),'sealed_exact':exact('SEALED',EXPECTED_SEALED_SHA)}
 expected_files={}
 if checks['sums_exact']:
  raw=(M/'module-inputs.sha256').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED_SUMS_SHA
  for line in raw.decode('ascii').splitlines():
   pin,name=line.split('  ',1)
   assert len(pin)==64 and all(c in '0123456789abcdef' for c in pin) and name not in expected_files and not name.startswith('/') and '..' not in Path(name).parts
   expected_files[name]=pin
  expected_files.update({'module-inputs.sha256':EXPECTED_SUMS_SHA,'SEALED':EXPECTED_SEALED_SHA})
  checks['expected_file_set_exact']=set(expected_files)==set(observed)
  checks['all_frozen_file_hashes_exact']=all(exact(name,pin) for name,pin in expected_files.items())
  checks['all_owned_modes_exact']=all(x['uid']==x['gid']==0 and x['mode']==('0o700' if name=='service.sh' else '0o600') for name,x in observed.items())
 else:
  checks.update(expected_file_set_exact=False,all_frozen_file_hashes_exact=False,all_owned_modes_exact=False)
 module_verification.update(checks=checks,complete=all(checks.values()),hashed_file_count=len(observed),hashed_bytes=hashed_bytes)
 module_verification['issues']=[name for name,value in checks.items() if value is not True]
else:module_verification['issues'].append('new_module_directory_absent_or_symlink')
'''
for k,v in {'__MANIFEST_SHA__':sha(mr),'__SUMS_SHA__':sha(sums),'__SEALED_SHA__':sha(sealed)}.items():
 assert extra.count(k)==1;extra=extra.replace(k,v)
code=code.replace(marker,marker+extra,1)
assert code.count("'files':files")==1
code=code.replace("'files':files","'module_verification':module_verification,'files':files",1)
compile(code,'r7-r2-readiness-capture','exec')
args[-1]=code
script='#!/system/bin/sh\n# Root-only existing startup capture plus all-module hashes; no evidence recursion/export, model request or UI.\nset -eu\nexec '+shlex.join(args)+'\n'
pin=put(D/'read_module_r7_r2_readiness_once.sh',script)
subprocess.run(['/bin/sh','-n',pin['path']],check=True)
diff=''.join(difflib.unified_diff(old.decode().splitlines(True),script.splitlines(True),fromfile='r7-r1/readonly-startup-capture',tofile='r7-r2/readonly-startup-capture'))
dp=put(D/'READINESS-R7-R2-BOUNDED.diff',diff)
report={'schema':'hepta.r7-r2.readonly-startup-capture-source.v1','source':pin,'diff':dp,
 'raw_scope':['new installer top-level regular startup receipts','new module per-boot claim top-level regular startup receipts'],
 'raw_member_bound_bytes':262144,'raw_total_bound_bytes':2097152,'per_module_hash_member_bound_bytes':4194304,'module_hash_total_bound_bytes':16777216,
 'all_module_file_hashes_required_for_complete':True,'module_evidence_raw_exported':False,
 'startup_transport_is_not_model_health_or_business_qualification':True,'shell_and_embedded_python_syntax_checked':True,
 'phone_execution':False,'new_nonce':False,'model_requests':0}
put(D/'READINESS-SOURCE-SEAL.json',json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
