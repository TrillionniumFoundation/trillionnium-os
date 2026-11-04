#!/usr/bin/env python3
"""Host-only second installer: bind failed pre-unpack original; correct only GNU view paths and OUT."""
from pathlib import Path
import base64,difflib,hashlib,json,os,re,shlex,subprocess
D=Path(__file__).resolve().parent;B=D.parent
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p,pin):
 b=Path(p).read_bytes();assert sha(b)==pin;return b
def put(p,b):
 if isinstance(b,str):b=b.encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
capture_raw=read(B/'module-r7-r2-root-deploy-r1-01/ACTUAL-READINESS-CAPTURE-01.json','<PRIVATE_BOUND_SHA256_001_REQUIRED>')
capture=json.loads(capture_raw)
assert capture['current_members']==[] and capture['original_identities']=={} and len(capture['files'])==20
assert capture['module_verification']['complete'] is False and capture['module_verification']['files']==[]
assert capture['module_verification']['issues']==['new_module_directory_absent_or_symlink']
rows={}
for row in capture['files']:
 assert row['relative'].startswith('operator/') and row['uid']==row['gid']==0 and row['mode']=='0o600'
 name=row['relative'].split('/',1)[1];assert re.fullmatch('[A-Za-z0-9._-]+',name) and name not in rows
 b=base64.b64decode(row['raw_b64'],validate=True);assert len(b)==row['bytes'] and sha(b)==row['sha256'];rows[name]=(row,b)
assert rows['OPERATOR-EXIT'][1]==b'1\n' and rows['preserved-state-preflight.json'][1]==b''
assert rows['preserved-state-preflight.stderr'][0]['sha256']=='<PRIVATE_BOUND_SHA256_002_REQUIRED>'
assert b"FileNotFoundError" in rows['preserved-state-preflight.stderr'][1] and b"/sys/fs/selinux/enforce" in rows['preserved-state-preflight.stderr'][1]
old=read(D/'install_start_module_r7_r2_once.sh','a6fad152446a80cd5cb4929337ee77021af9938b6848d8e85f44269d00dd6f62').decode()
s=old
assert s.count('module-install-start-v150-r7-r2-01')==1
s=s.replace('module-install-start-v150-r7-r2-01','module-install-start-v150-r7-r2-02')
for leaf in ('enforce','policy'):
 a="Path('/sys/fs/selinux/"+leaf+"')";b="Path('/proc/1/root/sys/fs/selinux/"+leaf+"')"
 assert s.count(a)==2
 s=s.replace(a,b)
proof=r'''# Attempt 01 stopped in its readonly preflight before unpack/install/start.
# Verify its exact immutable 20-file output; no previous mutation or task is repeated.
FAILED_OUT=$BASE/module-install-start-v150-r7-r2-01
[ -d "$FAILED_OUT" ] && [ ! -L "$FAILED_OUT" ]
[ "$("$SYS/readlink" -f "$FAILED_OUT")" = "$FAILED_OUT" ]
[ "$("$SYS/stat" -c '%u:%g:%a' "$FAILED_OUT")" = 0:0:700 ]
[ "$("$SYS/ls" -A "$FAILED_OUT" | "$BB" wc -l)" -eq 20 ]
[ ! -e "$FAILED_OUT/unpacked" ] && [ ! -L "$FAILED_OUT/unpacked" ]
while IFS=' ' read -r expected_sha expected_bytes original_name; do
    [ -f "$FAILED_OUT/$original_name" ] && [ ! -L "$FAILED_OUT/$original_name" ]
    [ "$("$SYS/stat" -c '%u:%g:%a:%h:%s' "$FAILED_OUT/$original_name")" = "0:0:600:1:$expected_bytes" ]
    actual_sha=$("$SYS/sha256sum" "$FAILED_OUT/$original_name")
    [ "${actual_sha%% *}" = "$expected_sha" ]
done <<'R7R2_ATTEMPT01_EXACT_FILES'
__ROWS__
R7R2_ATTEMPT01_EXACT_FILES
[ "$("$SYS/cat" "$FAILED_OUT/OPERATOR-EXIT")" = 1 ]
# Existing script gates below still require new module, activation, claim and OUT -02 absent.
'''
table='\n'.join(row['sha256']+' '+str(row['bytes'])+' '+name for name,(row,b) in sorted(rows.items()))
proof=proof.replace('__ROWS__',table)
marker='[ ! -e "$OUT" ] && [ ! -L "$OUT" ]\n';assert s.count(marker)==1
s=s.replace(marker,marker+proof,1)
reverse=s.replace(proof,'',1).replace('module-install-start-v150-r7-r2-02','module-install-start-v150-r7-r2-01')
for leaf in ('enforce','policy'):reverse=reverse.replace("Path('/proc/1/root/sys/fs/selinux/"+leaf+"')","Path('/sys/fs/selinux/"+leaf+"')")
assert reverse==old
assert '[ ! -e "$MOD" ] && [ ! -L "$MOD" ]' in s and '[ ! -e "$NEW_GATE" ] && [ ! -L "$NEW_GATE" ]' in s and '[ ! -e "$CLAIM" ] && [ ! -L "$CLAIM" ]' in s
assert s.count('"$BB" setsid "$BB" sh "$MOD/service.sh"')==1
installer=put(D/'install_start_module_r7_r2_attempt2_once.sh',s)
subprocess.run(['/bin/sh','-n',installer['path']],check=True)
start=s.index("<<'R7R2_READONLY_PY'\n")+len("<<'R7R2_READONLY_PY'\n")
end=s.index('\nR7R2_READONLY_PY',start)
compile(s[start:end],'attempt2-readonly-guard','exec')
rold=read(D/'read_module_r7_r2_readiness_once.sh','<PRIVATE_BOUND_SHA256_003_REQUIRED>').decode()
assert rold.count('module-install-start-v150-r7-r2-01')==1
rnew=rold.replace('module-install-start-v150-r7-r2-01','module-install-start-v150-r7-r2-02')
rp=put(D/'read_module_r7_r2_readiness_attempt2_once.sh',rnew)
subprocess.run(['/bin/sh','-n',rp['path']],check=True)
compile(shlex.split(rnew.split('exec ',1)[1])[-1],'attempt2-readiness','exec')
diff=''.join(difflib.unified_diff(old.splitlines(True),s.splitlines(True),fromfile='preserved/attempt1-installer',tofile='new/attempt2-installer'))
diff+=''.join(difflib.unified_diff(rold.splitlines(True),rnew.splitlines(True),fromfile='preserved/attempt1-readiness',tofile='new/attempt2-readiness'))
dp=put(D/'INSTALLER-ATTEMPT2-GNU-VIEW.diff',diff)
report={'schema':'hepta.r7-r2.installer-attempt2-source.v1','installer':installer,'readiness':rp,'diff':dp,
 'original_installer_sha256':sha(old.encode()),'original_failed_capture_sha256':sha(capture_raw),
 'original_preflight_error_sha256':rows['preserved-state-preflight.stderr'][0]['sha256'],
 'original_stage':'readonly_guard_before_unpack_no_module_or_role_started',
 'changes':['four GNU policy/enforce reads use existing host /proc/1/root view','new OUT -02 with exact immutable prior output gate','readiness selects OUT -02 only'],
 'exact_prior_file_count':20,'reverse_transformation_exact':True,'shell_and_embedded_python_syntax':True,
 'existing_module_manifest_and_combination_unchanged':True,'policy_loads':0,'phone_calls':0,'model_requests':0,'new_nonce':False,
 'previous_failed_attempt_preserved':True,'automatic_retry':False}
put(D/'INSTALLER-ATTEMPT2-SOURCE-SEAL.json',json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
