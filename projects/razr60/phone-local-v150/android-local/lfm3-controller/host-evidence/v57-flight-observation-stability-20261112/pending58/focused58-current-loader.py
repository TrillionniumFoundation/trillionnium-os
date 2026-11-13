import hashlib,os,pathlib,stat,sys
p=pathlib.Path("/home/alex/hepta-local-007f-20261111/v58-main-wire4-host-p4-r1.py")
assert all(not q.is_symlink() for q in (p,*p.parents))
fd=os.open(str(p),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
try:
 a=os.fstat(fd)
 assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==79802
 with os.fdopen(os.dup(fd),"rb") as f:raw=f.read(79802+1)
 assert len(raw)==79802 and hashlib.sha256(raw).hexdigest()=="a7b9a549983ff21f6c62b47ebb60d6c172c22d42d2d092ede5d726996546b2a7"
 assert identity(a)==identity(os.fstat(fd))==identity(os.lstat(p))
finally:os.close(fd)
sys.argv=[str(p)]
exec(compile(raw,str(p),"exec",dont_inherit=True),{"__name__":"__main__","__file__":str(p),"__stage_source__":raw})
