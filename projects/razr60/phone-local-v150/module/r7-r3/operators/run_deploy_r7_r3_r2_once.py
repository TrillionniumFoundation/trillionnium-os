#!/usr/bin/env python3
"""Root-only push/install/readiness driver. No automatic replay; each phase is a unique operation."""
from pathlib import Path
import base64,gzip,hashlib,importlib.util,json,os,shlex,stat,sys
B=Path('/operator-workspace/phone-local-v150')
D=B/'module-r7-r3-root-deploy-r1-01'
S=B/'module-r7-r3-finalization-r1'
H='/data/trillionnium/owner-open/state/phone-local-v150'
GNU='/var/lib/trillionnium/owner-open/phone-local-v150'
ROOT='/data/trillionnium/owner-open/root'
BB='/data/adb/magisk/busybox'
ARCHIVE_SHA='5ad09c1cc21610457776a2e83f3b50c9ad2abc50fa7303b3a090df070c123852'
COMBO_SHA='e42e6cb00112be91ac9414b04786ad2693b86a9af413b8f90a0e0e42543c81d1'
INSTALL_SHA='<PRIVATE_BOUND_SHA256_001_REQUIRED>'
READY_SHA='56b776c709c6a1e0770a46a3be6b1bcf922df10991d800a77960bebfdd1a7d68'
def sha(b):return hashlib.sha256(b).hexdigest()
def read(path,pin,size):
 path=Path(path);st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and path.parent.resolve(strict=True)==path.parent
 raw=path.read_bytes();assert len(raw)==size and sha(raw)==pin
 return raw
def zero(v):return type(v) is int and v==0
def main():
 assert len(sys.argv)==2 and sys.argv[1] in ('push','install','readiness')
 phase=sys.argv[1];os.umask(0o077)
 # Must precede any remote operation so local receipt persistence cannot fail for a missing directory.
 D.mkdir(mode=0o700,parents=True,exist_ok=True)
 st=D.lstat();assert stat.S_ISDIR(st.st_mode) and not D.is_symlink() and D.resolve(strict=True)==D
 assert st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700
 review=json.loads(read(B/'module-r7-r3-root-retirement-r1/ROOT-RETIREMENT-REVIEW.json','<PRIVATE_BOUND_SHA256_002_REQUIRED>',1242))
 assert review['four_groups_two_independent_censuses_and_ESRCH'] is True
 assert review['all_four_original_receipts_and_terminal_states_preserved'] is True
 assert review['supervisor_original_exit']==143
 assert all(zero(review[k]) for k in ('actual_stop_host_exit','actual_stop_actor_exit','actual_stop_phone_exit'))
 read(S/'COMBINATION-FROZEN-v150-r7-module-r3.json',COMBO_SHA,971)
 hp=B/'root-operators-r6-cycle03/run_cycle03.py'
 assert sha(hp.read_bytes())=='630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6'
 spec=importlib.util.spec_from_file_location('root_phone_original_helper',hp)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.D=D
 if phase=='push':
  req={'kind':'push','source':'/operator-home/razr60-local-model-v150/module-r7-deploy-r3-01/archive.tar.gz',
   'destination':'/data/local/tmp/hepta-phone-local-v150-r1/sealed-module-v150-r7-r3.tar.gz',
   'sha256':ARCHIVE_SHA,'timeout_seconds':120}
  label='r7r3-push-frozen-module-archive-01'
  remote="from pathlib import Path\nimport os,hashlib,json,subprocess,sys\nB=Path('/operator-home/razr60-local-model-v150');a=B/'ops/phone_once.py';assert hashlib.sha256(a.read_bytes()).hexdigest()=='<PRIVATE_BOUND_SHA256_003_REQUIRED>'\nreq="+repr(req)+"\nlabel="+repr(label)+"\np=B/'requests'/(label+'.json');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(fd,'w') as f:json.dump(req,f);f.write('\\n');f.flush();os.fsync(f.fileno())\nr=subprocess.run([sys.executable,'-I',str(a),label,str(p)],capture_output=True,timeout=140)\nb=(B/'operations'/label/'result.json').read_bytes();print(json.dumps({'actor_rc':r.returncode,'wrapper_sha256':hashlib.sha256(b).hexdigest(),'wrapper':json.loads(b)},sort_keys=True))"
  raw=m.ssh(remote,160);v=json.loads(raw);m.put(D/(label+'.original-operation.json'),raw)
  assert zero(v['actor_rc']) and v['wrapper']['status']=='pushed_and_hash_verified'
  assert zero(v['wrapper']['readback']['rc']) and v['wrapper']['sha256']==ARCHIVE_SHA and v['wrapper']['bytes']==4025281
  print(json.dumps({'state':v['wrapper']['status'],'actor_rc':v['actor_rc'],'bytes':v['wrapper']['bytes'],'sha256':v['wrapper']['sha256'],'wrapper_sha256':v['wrapper_sha256']},sort_keys=True))
 elif phase=='install':
  raw=read(S/'install_start_module_r7_r3_once.sh',INSTALL_SHA,94777)
  compressed=gzip.compress(raw,mtime=0);encoded=base64.b64encode(compressed).decode()
  stage=r'''
from pathlib import Path
import base64,gzip,hashlib,os,stat
os.umask(0o077)
parent=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
st=parent.lstat()
assert os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0
assert stat.S_ISDIR(st.st_mode) and not parent.is_symlink() and parent.resolve(strict=True)==parent
assert st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700
raw=gzip.decompress(base64.b64decode('__COMPRESSED__',validate=True))
assert len(raw)==94777 and hashlib.sha256(raw).hexdigest()=='__INSTALL_SHA__'
path=parent/'root-install-r7-r3-01.sh'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:
 f.write(raw);f.flush();os.fsync(f.fileno())
 st=os.fstat(f.fileno())
 assert stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size==len(raw)
fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
assert hashlib.sha256(path.read_bytes()).hexdigest()=='__INSTALL_SHA__'
'''
  assert stage.count('__COMPRESSED__')==1 and stage.count('__INSTALL_SHA__')==2
  stage=stage.replace('__COMPRESSED__',encoded).replace('__INSTALL_SHA__',INSTALL_SHA)
  compile(stage,'exclusive-root-installer-stage','exec')
  command='set -eu\n'+BB+' timeout -s TERM -k 3 25 '+BB+' chroot '+ROOT+' /usr/bin/python3 -I -c '+shlex.quote(stage)+'\n'+BB+' sh '+shlex.quote(H+'/root-install-r7-r3-01.sh')+' --execute-once'
  assert len(command.encode())<65536
  ph=m.call_phone('r7r3-install-start-frozen-module-01',{'kind':'shell','root':True,'timeout_seconds':240,'command':command})
  assert zero(ph['rc'])
  print(json.dumps({'state':'INSTALLER_RETURNED_ZERO_NEW_READINESS_REQUIRED','phone_rc':ph['rc'],'installer_sha256':INSTALL_SHA,'model_requests_generated_by_driver':0},sort_keys=True))
 elif phase=='readiness':
  raw=read(S/'read_module_r7_r3_readiness_r2_once.sh',READY_SHA,6791)
  ph=m.call_phone('r7r3-read-original-startup-readiness-01',{'kind':'shell','root':True,'timeout_seconds':40,'command':BB+' sh -c '+shlex.quote(raw.decode())})
  assert zero(ph['rc'])
  capture=json.loads(ph['stdout']);m.writej(D/'ACTUAL-READINESS-CAPTURE-01.json',capture)
  print(json.dumps({'state':'ORIGINAL_STARTUP_CAPTURED_NOT_MODEL_HEALTH','files':len(capture['files']),
   'current_members':capture['current_members'],'model_requests':capture['model_requests']},sort_keys=True))
 return 0
if __name__=='__main__':raise SystemExit(main())
