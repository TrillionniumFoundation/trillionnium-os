#!/usr/bin/env python3
"""Host-only r7-r2 module source fork; never installs, loads policy or starts services."""
from pathlib import Path
import ast,difflib,hashlib,json,os,subprocess
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r7-r1-finalization-r1'
MANIFEST_SHA='c0e31ecac9168218e7b6a622e4a3df138859743bd83911add42c32906d173a06'
RULE_SHA='e9ffb955ba3872d7b3c453729ef8b6e52b8679f86f05496d25a1b735f9bed7a2'
DELTA_SHA='607aba933beb89ca763815bb212fb3d129c3dfda9d7337e0b40fc9e7198cc0d6'
NEW_GROUPS=('<NEW_RETIRED_GROUP_IDS_REQUIRED>',)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p,pin,size=None):
 p=Path(p);assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1
 b=p.read_bytes();assert sha(b)==pin,(str(p),'hash')
 if size is not None:assert len(b)==size
 return b
def write(p,b):
 if isinstance(b,str):b=b.encode()
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 if p.exists():
  assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and p.read_bytes()==b,'existing candidate differs: '+str(p)
  return {'path':str(p.relative_to(D)),'bytes':len(b),'sha256':sha(b)}
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {'path':str(p.relative_to(D)),'bytes':len(b),'sha256':sha(b)}
mr=read(OLD/'sealed-module-v150-r7-r1/module/MODULE-MANIFEST-v150-r7-r1.json',MANIFEST_SHA,29431)
pins={x['path']:x for x in json.loads(mr)['files']}
policy=B/'policy-servicemanager-r7-diagnosis-r1'
newrule=read(policy/'sepolicy-r7-r2.proposed.rule',RULE_SHA,12595)
delta=read(policy/'servicemanager-prop-read-only.proposed.rule',DELTA_SHA,330)
oldrule=read(OLD/'module-root/sepolicy.rule','116a96094dfec4c222e7a0a90598b3674ec2858b409be0dcecd72ea02ef993bb')
assert newrule==oldrule+b'\n'+delta
active=[x.strip() for x in delta.decode().splitlines() if x.strip() and not x.startswith('#')]
assert active==['allow trillionnium_owner_open_phone_worker servicemanager_prop file { getattr open read map }']
rows=[];changes=[];unchanged=[]
renames=[('v150-r7-r1','v150-r7-r2'),('v150_r7_r1','v150_r7_r2'),('V150_R7_R1','V150_R7_R2'),('module-r7-activation-r1','module-r7-activation-r2'),('module-history-r7-r1','module-history-r7-r2')]
for p in sorted((OLD/'module-root').iterdir()):
 assert p.is_file() and not p.is_symlink()
 raw=read(p,pins[p.name]['sha256'],pins[p.name]['bytes']);s=raw.decode()
 for before,after in renames:s=s.replace(before,after)
 if p.name in ('service.sh','role_guard.sh'):
  before='PRIOR_R6_R2=/data/adb/modules/trillionnium_hepta_phone_local_v150_r6_r2\n'
  assert s.count(before)==1
  s=s.replace(before,before+'PRIOR_R7_R1=/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r1\n')
  before='previous_release_disabled() {\n';assert s.count(before)==1
  s=s.replace(before,before+'    [ -d "$PRIOR_R7_R1" ] && [ ! -L "$PRIOR_R7_R1" ] || return 1\n    [ -f "$PRIOR_R7_R1/disable" ] && [ ! -L "$PRIOR_R7_R1/disable" ] || return 1\n')
 if p.name=='activation_gate.sh':s=s.replace('twenty-two-group census','twenty-six-group census')
 if p.name=='retired-groups.tsv':
  assert s.endswith('\n') and len(s.splitlines())==22
  s+=''.join(str(x)+'\n' for x in NEW_GROUPS)
 if p.name=='sepolicy.rule':s=newrule.decode()
 if p.name=='module.prop':
  s=s.replace('r7 attempt 1','r7 attempt 2').replace('version=v150-r7-attempt1','version=v150-r7-attempt2').replace('versionCode=150071','versionCode=150072')
  s=s.replace('Frozen GUI-Owl named JSON action mapping and preserved cleanup signal shielding;','Four read-only servicemanager property permissions; same frozen GUI-Owl action mapping and cleanup shielding;')
 rows.append(write(D/'module-root'/p.name,s))
 if p.name.endswith('.sh'):subprocess.run(['/bin/sh','-n',str(D/'module-root'/p.name)],check=True)
 if raw!=s.encode():changes.extend(difflib.unified_diff(raw.decode().splitlines(True),s.splitlines(True),fromfile='r7-r1/'+p.name,tofile='r7-r2/'+p.name))
 else:unchanged.append(p.name)
for name in ('launch-model.sh','launch-sidecar.sh','launch-provider.sh','role-expectations.tsv'):
 assert name in unchanged,'protected production role source changed: '+name
p=OLD/'activation-payload/proc_and_original_gate.py'
raw=read(p,'0adb90db6fc4eab253ab9f96641d1ea5f689372dfdde31c9d39760d3d6c35897',4881)
s=raw.decode()
before='<PRIVATE_OLD_GROUP_EDIT_TARGET_REQUIRED>';assert s.count(before)==1
s=s.replace(before,'<PRIVATE_NEW_GROUP_EDIT_TARGET_REQUIRED>').replace('module-r7-r1','module-r7-r2')
ast.parse(s);compile(s,str(p),'exec')
rows.append(write(D/'activation-payload/proc_and_original_gate.py',s))
changes.extend(difflib.unified_diff(raw.decode().splitlines(True),s.splitlines(True),fromfile='r7-r1/proc_and_original_gate.py',tofile='r7-r2/proc_and_original_gate.py'))
diff=write(D/'MODULE-R7-R2-MINIMAL.diff',''.join(changes))
report={'schema':'hepta.module-r7-r2.source-preparation.v1','files':rows,'diff':diff,'old_module_manifest_sha256':MANIFEST_SHA,
 'full_policy_source_sha256':RULE_SHA,'policy_delta_sha256':DELTA_SHA,'added_permissions':active,
 'unchanged_source_files':unchanged,'unsealed':True,
 'pending':['actual Magisk offline parser and exact four-permission semantic delta','Root live policy application and readback semantic equivalence','all original r7-r1 effects safely terminal and global ledger clear, followed by exact service retirement','new activation-inputs, module/source seal, full combination and Root-only installer review'],
 'existing_provider_action_journal':'Preserve every original directory, intent, receipt and stream; never require or fabricate empty actions. Preserve original dev/inode and verify safe terminal lifecycle, not successful business.',
 'existing_provider_files':'Verify original 22 installed files and config; do not overwrite or require their paths absent.',
 'historical_source_prepare_failure':{'job_id':'<HOST_JOB_IDENTIFIER_OMITTED>','exit_code':1,'reason':'test treated role identity history path rename as forbidden byte change; candidate files retained and exact checked'},
 'phone_calls':0,'model_requests':0,'nonce_generation':0,'policy_applied':False,'provider_model_executor_native_rootfs_budgets_changed':False}
write(D/'SOURCE-PREPARATION.json',json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'SOURCE_PREPARED_HOST_ONLY_UNSEALED','files':rows,'diff':diff,'unchanged_source_files':unchanged,'phone_calls':0,'model_requests':0}))
