#!/usr/bin/env python3
"""Host-only r7-r3 readiness adaptation; preserve hash-only module evidence bounds."""
from pathlib import Path
import difflib,hashlib,json,os,shlex,subprocess
D=Path(__file__).resolve().parent;B=D.parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(path,raw):
 if isinstance(raw,str):raw=raw.encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
old=(B/'module-r7-r2-finalization-r1/read_module_r7_r2_readiness_attempt2_once.sh').read_bytes()
assert sha(old)=='1ad5fb1895e033da7bca77a7a4146837dd91deab4b356232bb7f239d4c7840de'
bundle=json.loads((D/'sealed-module-v150-r7-r3/BUNDLE.json').read_bytes())
module=D/'sealed-module-v150-r7-r3/module'
mr=(module/'MODULE-MANIFEST-v150-r7-r3.json').read_bytes();assert sha(mr)==bundle['module_manifest']['sha256']
sums=(module/'module-inputs.sha256').read_bytes();assert sha(sums)==bundle['module_input_sums']['sha256']
sealed=(module/'SEALED').read_bytes()
args=shlex.split(old.decode().split('exec ',1)[1]);assert args[-2]=='-c';original_code=args[-1]
code=original_code.replace('v150-r7-r2','v150-r7-r3').replace('module-start-r7-r2-02','module-start-r7-r3-01').replace('module-start-r7-r2','module-start-r7-r3')
for key,value in [('EXPECTED_MANIFEST_SHA',sha(mr)),('EXPECTED_SUMS_SHA',sha(sums)),('EXPECTED_SEALED_SHA',sha(sealed))]:
 lines=[x for x in code.splitlines() if x.startswith(key+'=')];assert len(lines)==1
 code=code.replace(lines[0],key+'='+repr(value),1)
compile(code,'r7-r3-readiness-capture','exec')
assert "st.st_size<=4194304" in code and "hashed_bytes<=16777216" in code
assert "'raw_evidence_exported':False" in code
args[-1]=code
script='#!/system/bin/sh\n# Root-only current startup originals and all-module hashes; no model request, UI or mutation.\nset -eu\nexec '+shlex.join(args)+'\n'
pin=put(D/'read_module_r7_r3_readiness_once.sh',script)
subprocess.run(['/bin/sh','-n',pin['path']],check=True)
diff=''.join(difflib.unified_diff(original_code.splitlines(True),code.splitlines(True),fromfile='r7-r2/original-readiness-python',tofile='r7-r3/readonly-startup-python'))
dp=put(D/'READINESS-R7-R3-MINIMAL.diff',diff)
report={'schema':'hepta.r7-r3.readonly-startup-capture-source.v1','source':pin,'diff':dp,
 'parent_readiness_sha256':sha(old),'raw_member_bound_bytes':262144,'raw_total_bound_bytes':2097152,
 'per_module_hash_member_bound_bytes':4194304,'module_hash_total_bound_bytes':16777216,
 'all_module_file_hashes_required_for_complete':True,'module_evidence_raw_exported':False,
 'startup_transport_is_not_model_health_or_business_qualification':True,
 'shell_and_embedded_python_syntax_checked':True,'phone_execution':False,'new_nonce':False,'model_requests':0}
put(D/'READINESS-SOURCE-SEAL.json',json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
