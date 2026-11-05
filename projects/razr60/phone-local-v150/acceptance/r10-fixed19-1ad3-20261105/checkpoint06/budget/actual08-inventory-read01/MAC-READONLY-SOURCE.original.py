import pathlib,os,stat,hashlib,json,lzma
B=pathlib.Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
p=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/INVENTORY.json'
assert p.resolve(strict=True)==p
fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
meta=lambda s:[getattr(s,k) for k in fields]
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==849854
 with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(849855)
 assert meta(a)==meta(os.fstat(fd))==meta(p.lstat())
finally:os.close(fd)
assert len(raw)==849854 and hashlib.sha256(raw).hexdigest()=='80b8a56ee78055c19caf3b342af5bc5e479180843b0f3bc223751649188b7fc4'
packed=lzma.compress(raw,preset=6);assert lzma.decompress(packed)==raw
out=B/'root-fixed19-1ad3-20261105-r1/readonly-inventory08-timing01'
assert out.parent.resolve(strict=True)==out.parent
os.mkdir(out,0o700)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
put(out/'INVENTORY.original.json.xz',packed)
r={'original':{'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'metadata':meta(a)},'lossless_original_xz':{'path':str(out/'INVENTORY.original.json.xz'),'bytes':len(packed),'sha256':hashlib.sha256(packed).hexdigest()},'full9_bookends_equal':True,'phone_calls':0,'original_writes':0,'case_pass':False}
b=(json.dumps(r,sort_keys=True,indent=2)+'\n').encode();put(out/'RESULT.json',b)
print(json.dumps({'result':{'path':str(out/'RESULT.json'),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()},**r},sort_keys=True))
