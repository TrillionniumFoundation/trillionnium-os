import os,sys,stat,hashlib
from pathlib import Path
p=Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-bind-e2e-sources-r5-01.py")
assert p.resolve(strict=True)==p
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
with os.fdopen(fd,'rb') as f:
 a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==18012
 raw=f.read(18013);b=os.fstat(f.fileno())
assert len(raw)==18012 and hashlib.sha256(raw).hexdigest()=="a39fbab2020e357bbd5a146e15af96b76f847fcd83b54a2fd60dfc6430e5e3a1"
assert [getattr(a,k)for k in keys]==[getattr(b,k)for k in keys]==[getattr(p.lstat(),k)for k in keys]
sys.argv=[str(p),'--bind-source-once']
exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})
