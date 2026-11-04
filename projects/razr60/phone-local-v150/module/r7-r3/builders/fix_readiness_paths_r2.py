#!/usr/bin/env python3
"""Correct only two statically rejected readiness paths; no phone execution."""
from pathlib import Path
import ast,difflib,hashlib,json,os,re,shlex,subprocess
D=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def put(path,b):
 if isinstance(b,str):b=b.encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {'path':str(path),'bytes':len(b),'sha256':sha(b)}
old=(D/'read_module_r7_r3_readiness_once.sh').read_bytes()
assert len(old)==6791 and sha(old)=='<PRIVATE_BOUND_SHA256_001_REQUIRED>'
pairs=[('module-install-start-v150-r7-r3-02','module-install-start-v150-r7-r3-01'),('trillionnium_hepta_phone_local_v150_r7_r2','trillionnium_hepta_phone_local_v150_r7_r3')]
s=old.decode()
for before,after in pairs:
 assert s.count(before)==1,(before,s.count(before));s=s.replace(before,after,1)
back=s
for before,after in reversed(pairs):back=back.replace(after,before,1)
assert back.encode()==old
args=shlex.split(s.split('exec ',1)[1]);assert args[-2]=='-c'
py=args[-1];ast.parse(py);compile(py,'corrected-r7-r3-readiness','exec')
prior=shlex.split(old.decode().split('exec ',1)[1])[-1]
installer=(D/'install_start_module_r7_r3_once.sh').read_bytes()
assert sha(installer)=='<PRIVATE_BOUND_SHA256_002_REQUIRED>'
install=installer.decode()
assert "O=B/'module-install-start-v150-r7-r3-01'" in py
assert "M=Path('/proc/1/root/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r3')" in py
assert 'OUT=$BASE/module-install-start-v150-r7-r3-01' in install
assert 'MOD=/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r3' in install
pin=put(D/'read_module_r7_r3_readiness_r2_once.sh',s)
subprocess.run(['/bin/sh','-n',pin['path']],check=True)
diff=''.join(difflib.unified_diff(prior.splitlines(True),py.splitlines(True),fromfile='unexecuted-readiness-r1',tofile='corrected-readiness-r2'))
dp=put(D/'READINESS-PATHS-r2.diff',diff)
v={'schema':'hepta.r7-r3.readiness-path-revision.v1','state':'SOURCE_CORRECTED_NOT_EXECUTED_ON_PHONE','source':pin,'diff':dp,
 'parent_sha256':sha(old),'change_count':2,'reverse_bytes_equal':True,'installer_out_and_module_paths_match':True,
 'installer_sha256':sha(installer),'raw_member_bound_bytes':262144,'raw_total_bound_bytes':2097152,
 'per_module_hash_member_bound_bytes':4194304,'module_hash_total_bound_bytes':16777216,
 'module_evidence_raw_exported':False,'module_and_combination_unchanged':True,
 'root_static_finding_not_phone_failure':True,'original_reader_executed_on_phone':False,'phone_calls':0,'model_requests':0}
rp=put(D/'READINESS-SOURCE-SEAL-r2.json',json.dumps(v,indent=2)+'\n')
print(json.dumps({'source':pin,'diff':dp,'revision':rp,'phone_calls':0}))
