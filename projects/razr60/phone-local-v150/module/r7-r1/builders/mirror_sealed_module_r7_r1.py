#!/usr/bin/env python3
"""Host-only byte-exact mirror of the already-sealed r7 package; no phone calls."""
import base64,hashlib,json,os,shlex,subprocess
from pathlib import Path
D=Path(__file__).resolve().parent
DEST='/operator-home/razr60-local-model-v150/module-r7-deploy-r1-01'
items={
 'ROOT-LIFECYCLE-RUNBOOK.md':D/'ROOT-LIFECYCLE-RUNBOOK.md',
 'READINESS-CAPTURE-SOURCE-SEAL-r7-r1.json':D/'READINESS-CAPTURE-SOURCE-SEAL-r7-r1.json',
 'capture_module_r7_r1_readiness.py':D/'capture_module_r7_r1_readiness.py',
 'read_module_r7_r1_readiness_once.sh':D/'read_module_r7_r1_readiness_once.sh',
 'INSTALLER-SOURCE-SEAL.json':D/'INSTALLER-SOURCE-SEAL.json',
 'archive.tar.gz':D/'sealed-module-v150-r7-r1.tar.gz',
 'install_start_module_r7_r1_once.sh':D/'install_start_module_r7_r1_once.sh',
 'COMBINATION-FROZEN-v150-r7-module-r1.json':D/'COMBINATION-FROZEN-v150-r7-module-r1.json',
 'COMBINATION-VALIDATION-r7-r1.json':D/'COMBINATION-VALIDATION-r7-r1.json',
 'BUNDLE.json':D/'sealed-module-v150-r7-r1/BUNDLE.json',
 'MODULE-MANIFEST-v150-r7-r1.json':D/'sealed-module-v150-r7-r1/module/MODULE-MANIFEST-v150-r7-r1.json',
 'seal-binding.json':D/'sealed-module-v150-r7-r1/module/seal-binding.json',
 'module-inputs.sha256':D/'sealed-module-v150-r7-r1/module/module-inputs.sha256',
 'payload-inputs.sha256':D/'sealed-module-v150-r7-r1/module/payload-inputs.sha256',
}
rows=[]
for name,path in items.items():
 assert path.is_file() and not path.is_symlink() and path.stat().st_nlink==1
 raw=path.read_bytes()
 rows.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'data_b64':base64.b64encode(raw).decode()})
remote=r"""
import base64,hashlib,json,os,stat,sys
from pathlib import Path
packet=json.load(sys.stdin);root=Path(packet['destination'])
assert str(root)=='/operator-home/razr60-local-model-v150/module-r7-deploy-r1-01'
assert root.parent.resolve(strict=True)==root.parent and not root.is_symlink()
root.mkdir(mode=0o700,exist_ok=True)
info=root.stat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700
out=[]
for row in packet['files']:
 name=row['name'];assert name and all(c.isascii() and (c.isalnum() or c in '._-') for c in name)
 raw=base64.b64decode(row['data_b64'],validate=True)
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 path=root/name
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 info=path.stat();actual=path.read_bytes()
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600
 assert actual==raw
 out.append({'path':str(path),'bytes':len(actual),'sha256':hashlib.sha256(actual).hexdigest()})
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'state':'COPIED_AND_BYTE_READBACK_VERIFIED','files':out,'phone_calls':0,'model_requests':0}))
"""
ssh=['/usr/bin/ssh','-T','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22',
 '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5',
 '-o','ClearAllForwardings=yes','-o','ControlMaster=no','-o','ControlPath=none',
 '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','pocket4-usb4-fast',
 'python3 -c '+shlex.quote(remote)]
proc=subprocess.run(ssh,input=json.dumps({'destination':DEST,'files':rows}).encode(),
 stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=55)
for name,data in [('MIRROR-STDOUT.original',proc.stdout),('MIRROR-STDERR.original',proc.stderr)]:
 with (D/name).open('xb') as f:f.write(data)
assert proc.returncode==0 and not proc.stderr,(proc.returncode,proc.stderr.decode(errors='replace'))
result=json.loads(proc.stdout)
assert result['state']=='COPIED_AND_BYTE_READBACK_VERIFIED'
assert len(result['files'])==len(rows)
for row,actual in zip(rows,result['files']):
 assert actual['path']==DEST+'/'+row['name'] and actual['bytes']==row['bytes'] and actual['sha256']==row['sha256']
with (D/'POCKET4-MIRROR-READBACK.json').open('xb') as f:f.write(proc.stdout)
print(proc.stdout.decode(),end='')
