#!/usr/bin/env python3
"""Host-only immutable r7 module source preparation. No phone, model or nonce."""
from pathlib import Path
import ast,difflib,hashlib,json,os,subprocess
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r6-r2-finalization-r1'
MANIFEST_SHA='9e5a8c3f9a5a7f4426d109beba1073edcfa2dfe4712760e446054b04906afb4a'
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p,pin,size=None):
 p=Path(p);assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1
 b=p.read_bytes();assert sha(b)==pin
 if size is not None:assert len(b)==size
 return b
def write(p,b):
 if isinstance(b,str):b=b.encode()
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {'path':str(p.relative_to(D)),'bytes':len(b),'sha256':sha(b)}
manifest_raw=read(OLD/'sealed-module-v150-r6-r2/module/MODULE-MANIFEST-v150-r6-r2.json',MANIFEST_SHA,27396)
manifest=json.loads(manifest_raw);pins={x['path']:x for x in manifest['files']}
changes=[];rows=[];unchanged=[]
renames=[('v150-r6-r2','v150-r7-r1'),('v150_r6_r2','v150_r7_r1'),('V150_R6_R2','V150_R7_R1'),('module-r6-activation-r2','module-r7-activation-r1'),('module-history-r6-r2','module-history-r7-r1')]
for p in sorted((OLD/'module-root').iterdir()):
 assert p.is_file() and not p.is_symlink()
 raw=read(p,pins[p.name]['sha256'],pins[p.name]['bytes']);s=raw.decode()
 for before,after in renames:s=s.replace(before,after)
 if p.name in ('service.sh','role_guard.sh'):
  before='PRIOR_R6_R1=/data/adb/modules/trillionnium_hepta_phone_local_v150_r6_r1\n'
  assert s.count(before)==1
  s=s.replace(before,before+'PRIOR_R6_R2=/data/adb/modules/trillionnium_hepta_phone_local_v150_r6_r2\n')
  before='previous_release_disabled() {\n';assert s.count(before)==1
  s=s.replace(before,before+'    [ -d "$PRIOR_R6_R2" ] && [ ! -L "$PRIOR_R6_R2" ] || return 1\n    [ -f "$PRIOR_R6_R2/disable" ] && [ ! -L "$PRIOR_R6_R2/disable" ] || return 1\n')
 if p.name=='service.sh':s=s.replace('# Candidate v150-r6 phone-only startup.','# Frozen v150-r7 phone-only startup.')
 if p.name=='launch-provider.sh':s=s.replace('/provider-r6-r2/source/','/provider-r7/source/').replace('/local-config-r6-r2.json','/local-config-r7.json')
 if p.name=='activation_gate.sh':s=s.replace('same eighteen-group census','same twenty-two-group census')
 if p.name=='retired-groups.tsv':
  assert s.endswith('\n');s+='0\n32604\n406\n629\n'
 if p.name=='module.prop':
  s=s.replace('r6 attempt 2','r7 attempt 1').replace('version=v150-r6-attempt2','version=v150-r7-attempt1').replace('versionCode=150062','versionCode=150071')
  s=s.replace('Embedded health dependency pin closure and preserved cleanup signal shielding;','Frozen GUI-Owl named JSON action mapping and preserved cleanup signal shielding;')
 rows.append(write(D/'module-root'/p.name,s))
 if p.name.endswith('.sh'):subprocess.run(['/bin/sh','-n',str(D/'module-root'/p.name)],check=True)
 if raw!=s.encode():changes.extend(difflib.unified_diff(raw.decode().splitlines(True),s.splitlines(True),fromfile='r6-r2/'+p.name,tofile='r7-r1/'+p.name))
 else:unchanged.append(p.name)
for name in ('launch-model.sh','launch-sidecar.sh','role-expectations.tsv'):
 assert name in unchanged,'protected model/executor/role inputs changed'
p=OLD/'activation-payload/proc_and_original_gate.py'
raw=read(p,'713ff1089d9136062353e659e6f54193422f6c336f0c598dff5d12859cfac1c8',4861)
s=raw.decode()
assert s.count('0,0))')==1
s=s.replace('0,0))','0,0,0,0,0,0))').replace('module-r6-r2','module-r7-r1')
ast.parse(s);compile(s,str(p),'exec')
rows.append(write(D/'activation-payload/proc_and_original_gate.py',s))
changes.extend(difflib.unified_diff(raw.decode().splitlines(True),s.splitlines(True),fromfile='r6-r2/proc_and_original_gate.py',tofile='r7-r1/proc_and_original_gate.py'))
diff=write(D/'MODULE-R7-R1-MINIMAL.diff',''.join(changes))
report={'schema':'hepta.module-r7-r1.source-preparation.v1','files':rows,'diff':diff,'old_module_manifest_sha256':MANIFEST_SHA,'unchanged_source_files':unchanged,'unsealed':True,'pending':['actual original r6-r2 service quiescence with wrapper and authoritative successful tool exit','original cancel task/HTTP-worker/native receipt/draft closure by Root and integration','r7 source/payload binding and new full combination'],'phone_calls':0,'model_requests':0,'nonce_generation':0,'existing_executor_model_policy_native_rootfs_changed':False}
write(D/'SOURCE-PREPARATION.json',json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'SOURCE_PREPARED_HOST_ONLY_UNSEALED','files':rows,'diff':diff,'unchanged_source_files':unchanged,'phone_calls':0,'model_requests':0}))
