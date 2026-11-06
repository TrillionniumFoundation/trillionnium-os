from pathlib import Path
import hashlib,os,stat
a=Path('/home/alex/razr60-local-model-v150/ops/phone_once.py')
r=Path('/home/alex/razr60-local-model-v150/requests/ng-fc33-r5-shared-parents-observe01.json')
keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
for p,h in [(a,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'),(r,'e5a385a782af2ca09acf63413f0ca6c11b4b50f371639dc7eadbadf82de4fef9')]:
 assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=1048576
  body=f.read(1048577);after=os.fstat(f.fileno())
 assert hashlib.sha256(body).hexdigest()==h and len(body)==before.st_size and [getattr(before,k)for k in keys]==[getattr(after,k)for k in keys]==[getattr(p.lstat(),k)for k in keys]
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(a),'ng-fc33-r5-shared-parents-observe01',str(r)])
