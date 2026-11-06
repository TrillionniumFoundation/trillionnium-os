from pathlib import Path
import hashlib,os,stat
a=Path('/home/alex/razr60-local-model-v150/ops/phone_once.py')
r=Path('/home/alex/razr60-local-model-v150/requests/ng-fc33-final05-owned-xml-readonly01.json')
keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
for p,h in [(a,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'),(r,'485e888fae619849d2d74e34c2cd630c1045509726eb8242e5d5382807109b7c')]:
 assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=1048576
  body=f.read(1048577);after=os.fstat(f.fileno())
 assert hashlib.sha256(body).hexdigest()==h and len(body)==before.st_size and [getattr(before,k)for k in keys]==[getattr(after,k)for k in keys]==[getattr(p.lstat(),k)for k in keys]
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(a),'ng-fc33-final05-owned-xml-readonly01',str(r)])
