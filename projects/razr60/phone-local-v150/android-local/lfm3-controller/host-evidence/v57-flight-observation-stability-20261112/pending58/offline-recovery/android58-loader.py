import hashlib,os,pathlib,stat,sys
p=pathlib.Path("/home/alex/hepta-local-007f-20261111/v58-main-p4-android-r1.py")
assert all(not q.is_symlink() for q in (p,*p.parents))
fd=os.open(str(p),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
try:
 a=os.fstat(fd)
 assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==90099
 with os.fdopen(os.dup(fd),"rb") as f:raw=f.read(90099+1)
 assert len(raw)==90099 and hashlib.sha256(raw).hexdigest()=="a933105576d7012b74386c934a7f1c9184fa9c01e87ebf9c13fc728ce54dfa51"
 assert identity(a)==identity(os.fstat(fd))==identity(os.lstat(p))
finally:os.close(fd)
sys.argv=[str(p)]
exec(compile(raw,str(p),"exec",dont_inherit=True),{"__name__":"__main__","__file__":str(p),"__stage_source__":raw})
