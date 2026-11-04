#!/usr/bin/env python3
"""Mirror the immutable host-sealed r7-r2 package to configured Pocket4; never access phone."""
from pathlib import Path
import base64,hashlib,json,os,subprocess,sys
D=Path(__file__).resolve().parent
DEST='/operator-home/razr60-local-model-v150/module-r7-deploy-r2-01'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
files=[
('sealed-module-v150-r7-r2.tar.gz','archive.tar.gz','f0c7abb46bc0b119e9296390ad845f6ff53992e669f747fb9a558206eb2003cf'),
('install_start_module_r7_r2_once.sh','install_start_module_r7_r2_once.sh','a6fad152446a80cd5cb4929337ee77021af9938b6848d8e85f44269d00dd6f62'),
('read_module_r7_r2_readiness_once.sh','read_module_r7_r2_readiness_once.sh','<PRIVATE_BOUND_SHA256_001_REQUIRED>'),
('COMBINATION-FROZEN-v150-r7-module-r2.json','COMBINATION-FROZEN-v150-r7-module-r2.json','ee2bba801325525f9fa910c2c613352b54c32cb71921f2e7a16d2f25205e94d4'),
('COMBINATION-VALIDATION-r7-r2.json','COMBINATION-VALIDATION-r7-r2.json','<PRIVATE_BOUND_SHA256_002_REQUIRED>'),
('sealed-module-v150-r7-r2/module/MODULE-MANIFEST-v150-r7-r2.json','MODULE-MANIFEST-v150-r7-r2.json','1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd'),
('sealed-module-v150-r7-r2/BUNDLE.json','BUNDLE.json','<PRIVATE_BOUND_SHA256_003_REQUIRED>'),
('INSTALLER-SOURCE-SEAL.json','INSTALLER-SOURCE-SEAL.json',None),
('READINESS-SOURCE-SEAL.json','READINESS-SOURCE-SEAL.json',None)]
rows=[]
for src,name,pin in files:
 p=D/src;assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1
 raw=p.read_bytes();h=sha(raw)
 if pin:assert h==pin
 rows.append({'name':name,'bytes':len(raw),'sha256':h,'data_base64':base64.b64encode(raw).decode('ascii')})
payload=json.dumps({'destination':DEST,'files':rows},sort_keys=True).encode()
remote=r"""import base64,hashlib,json,os,stat,sys
from pathlib import Path
raw=sys.stdin.buffer.read(8388609);assert len(raw)<=8388608
v=json.loads(raw);D=Path(v['destination']);assert str(D)=='/operator-home/razr60-local-model-v150/module-r7-deploy-r2-01'
D.mkdir(mode=0o700)
rows=[]
for row in v['files']:
 name=row['name'];assert '/' not in name and name not in ('','.','..')
 b=base64.b64decode(row['data_base64'],validate=True);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
 p=D/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 st=p.lstat();rb=p.read_bytes()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and rb==b
 rows.append({'path':str(p),'bytes':len(rb),'sha256':hashlib.sha256(rb).hexdigest(),'mode':stat.S_IMODE(st.st_mode)})
fd=os.open(D,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'state':'POCKET4_EXACT_MIRROR_VERIFIED','files':rows,'count':len(rows),'total_bytes':sum(x['bytes'] for x in rows),'phone_calls':0},sort_keys=True))
"""
import shlex
p=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','operator-secondary-host','python3 -c '+shlex.quote(remote)],input=payload,capture_output=True,timeout=80)
put(D/'POCKET4-MIRROR.stdout',p.stdout);put(D/'POCKET4-MIRROR.stderr',p.stderr)
assert p.returncode==0 and p.stderr==b'',(p.returncode,p.stderr[:1000].decode(errors='replace'))
r=json.loads(p.stdout);assert r['count']==len(rows) and r['state']=='POCKET4_EXACT_MIRROR_VERIFIED'
assert {(x['path'].split('/')[-1],x['bytes'],x['sha256']) for x in r['files']}=={(x['name'],x['bytes'],x['sha256']) for x in rows}
put(D/'POCKET4-MIRROR-READBACK.json',(json.dumps(r,indent=2,sort_keys=True)+'\n').encode())
print(json.dumps(r))
