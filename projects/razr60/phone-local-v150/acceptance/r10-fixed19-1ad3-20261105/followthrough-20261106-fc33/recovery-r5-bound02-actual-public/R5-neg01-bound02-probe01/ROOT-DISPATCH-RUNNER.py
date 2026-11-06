from pathlib import Path
import hashlib,os,stat
actor=Path('/home/alex/razr60-local-model-v150/ops/phone_once.py')
request=Path('/home/alex/razr60-local-model-v150/requests/ng-fc33-neg01-bound02-unstarted-readonly01.json')
fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
for p,size,digest in [(actor,5652,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'),(request,25892,'2a2035002f678589890259339be8f3242c3f14bbe58fdd58f2bb997b9789ae77')]:
 assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  before=os.fstat(stream.fileno())
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size
  body=stream.read(size+1);after=os.fstat(stream.fileno())
 assert len(body)==size and hashlib.sha256(body).hexdigest()==digest
 assert [getattr(before,k) for k in fields]==[getattr(after,k) for k in fields]==[getattr(p.lstat(),k) for k in fields]
 if p==request:assert stat.S_IMODE(before.st_mode)==0o600 and before.st_uid==before.st_gid==1000
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(actor),'ng-fc33-neg01-bound02-unstarted-readonly01',str(request)])
