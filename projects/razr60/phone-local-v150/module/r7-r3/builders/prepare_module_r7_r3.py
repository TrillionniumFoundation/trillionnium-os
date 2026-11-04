#!/usr/bin/env python3
"""Host-only r7-r3 module source fork; no install, policy load, service or model request."""
from pathlib import Path
import ast,difflib,hashlib,json,os,subprocess
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r7-r2-finalization-r1'
MANIFEST_SHA='1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd'
RULE_SHA='30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8'
DELTA_SHA='a844e622896f84e3fb535ccb1315e21b48a5bcbf2d78a8ae05be9c4b3f174662'
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
mr=read(OLD/'sealed-module-v150-r7-r2/module/MODULE-MANIFEST-v150-r7-r2.json',MANIFEST_SHA,32052)
pins={x['path']:x for x in json.loads(mr)['files']}
policy=B/'policy-display-r7-r3-candidate-r1'
newrule=read(policy/'sepolicy-r7-r3.proposed.rule',RULE_SHA,13094)
delta=read(policy/'display-ipc-three-atoms.proposed.rule',DELTA_SHA,498)
oldrule=read(OLD/'module-root/sepolicy.rule','e9ffb955ba3872d7b3c453729ef8b6e52b8679f86f05496d25a1b735f9bed7a2',12595)
assert newrule==oldrule+b'\n'+delta
active=[x.strip() for x in delta.decode().splitlines() if x.strip() and not x.startswith('#')]
assert active==[
 'allow servicemanager trillionnium_owner_open_phone_worker binder transfer',
 'allow system_server trillionnium_owner_open_phone_worker fd use',
 'allow system_server trillionnium_owner_open_phone_worker fifo_file write']
rows=[];changes=[];unchanged=[];reverse_equal=[]
renames=[('v150-r7-r2','v150-r7-r3'),('v150_r7_r2','v150_r7_r3'),('V150_R7_R2','V150_R7_R3'),('module-r7-activation-r2','module-r7-activation-r3'),('module-history-r7-r2','module-history-r7-r3')]
prior_line='PRIOR_R7_R2=/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r2\n'
prior_gate='    [ -d "$PRIOR_R7_R2" ] && [ ! -L "$PRIOR_R7_R2" ] || return 1\n    [ -f "$PRIOR_R7_R2/disable" ] && [ ! -L "$PRIOR_R7_R2/disable" ] || return 1\n'
for p in sorted((OLD/'module-root').iterdir()):
 assert p.is_file() and not p.is_symlink()
 raw=read(p,pins[p.name]['sha256'],pins[p.name]['bytes']);s=raw.decode()
 for before,after in renames:s=s.replace(before,after)
 if p.name in ('service.sh','role_guard.sh'):
  before='PRIOR_R7_R1=/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r1\n'
  assert s.count(before)==1;s=s.replace(before,before+prior_line)
  before='previous_release_disabled() {\n';assert s.count(before)==1
  s=s.replace(before,before+prior_gate)
 if p.name=='activation_gate.sh':s=s.replace('twenty-six-group census','thirty-group census')
 if p.name=='retired-groups.tsv':
  assert s.endswith('\n') and len(s.splitlines())==26
  s+=''.join(str(x)+'\n' for x in NEW_GROUPS)
 if p.name=='sepolicy.rule':s=newrule.decode()
 if p.name=='module.prop':
  s=s.replace('r7 attempt 2','r7 attempt 3').replace('version=v150-r7-attempt2','version=v150-r7-attempt3').replace('versionCode=150072','versionCode=150073')
  s=s.replace('Four read-only servicemanager property permissions; same frozen GUI-Owl action mapping and cleanup shielding;','Three explicit Binder and dump-pipe permissions; same frozen GUI-Owl action mapping and cleanup shielding;')
 if p.name not in ('sepolicy.rule','module.prop','retired-groups.tsv'):
  back=s
  if p.name in ('service.sh','role_guard.sh'):back=back.replace(prior_gate,'').replace(prior_line,'')
  if p.name=='activation_gate.sh':back=back.replace('thirty-group census','twenty-six-group census')
  for before,after in reversed(renames):back=back.replace(after,before)
  assert back.encode()==raw,'unexpected lifecycle source difference: '+p.name
  reverse_equal.append(p.name)
 rows.append(write(D/'module-root'/p.name,s))
 if p.name.endswith('.sh'):subprocess.run(['/bin/sh','-n',str(D/'module-root'/p.name)],check=True)
 if raw!=s.encode():changes.extend(difflib.unified_diff(raw.decode().splitlines(True),s.splitlines(True),fromfile='r7-r2/'+p.name,tofile='r7-r3/'+p.name))
 else:unchanged.append(p.name)
for name in ('launch-model.sh','launch-sidecar.sh','launch-provider.sh','role-expectations.tsv'):
 assert name in unchanged,'protected production role source changed: '+name
p=OLD/'activation-payload/proc_and_original_gate.py'
raw=read(p,'12a74aa99d56d780f6e3a6e420d5480db35ab7399b58f9b3b840839741be46e8',4905)
s=raw.decode()
before='0,0,0,0))';after='0,0,0,0,0,0,0,0))'
assert s.count(before)==1
s=s.replace(before,after).replace('module-r7-r2','module-r7-r3')
assert s.replace(after,before).replace('module-r7-r3','module-r7-r2').encode()==raw
ast.parse(s);compile(s,str(p),'exec')
rows.append(write(D/'activation-payload/proc_and_original_gate.py',s))
changes.extend(difflib.unified_diff(raw.decode().splitlines(True),s.splitlines(True),fromfile='r7-r2/proc_and_original_gate.py',tofile='r7-r3/proc_and_original_gate.py'))
diff=write(D/'MODULE-R7-R3-MINIMAL.diff',''.join(changes))
report={'schema':'hepta.module-r7-r3.source-preparation.v1','files':rows,'diff':diff,'old_module_manifest_sha256':MANIFEST_SHA,
 'full_policy_source_sha256':RULE_SHA,'policy_delta_sha256':DELTA_SHA,'added_permissions':active,
 'unchanged_source_files':unchanged,'namespace_and_prior_gate_reverse_byte_equal':reverse_equal,
 'unsealed':True,'retired_group_count_required':30,'new_groups_absence_required_not_observed_by_builder':list(NEW_GROUPS),
 'pending':['Root original r7-r2 retirement with all four original effects preserved and exact host/actor/phone terminal evidence',
 'Root live three-permission application and actual policy semantic audit/readback',
 'new activation-inputs, module seal, full combination and Root-only installer review'],
 'existing_provider_action_journal':'Preserve all four original action directories, intents, receipts and streams. Two timed_out and two completed with exit 68 remain failed business. Never require or fabricate empty actions.',
 'original_global_ledger_gate_sha256':'23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e',
 'existing_provider_files':'Verify original 22 installed files and config; do not overwrite or require their paths absent.',
 'gnu_installer_selinux_view_required':'/proc/1/root/sys/fs/selinux/{enforce,policy}; no mount or permission change',
 'phone_calls':0,'model_requests':0,'nonce_generation':0,'policy_applied':False,'provider_model_executor_native_rootfs_budgets_changed':False}
write(D/'SOURCE-PREPARATION.json',json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'SOURCE_PREPARED_HOST_ONLY_UNSEALED','files':rows,'diff':diff,'unchanged_source_files':unchanged,'phone_calls':0,'model_requests':0}))
