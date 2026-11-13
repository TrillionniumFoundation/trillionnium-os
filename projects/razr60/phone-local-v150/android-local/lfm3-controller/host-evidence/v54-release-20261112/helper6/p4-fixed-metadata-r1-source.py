import hashlib,io,json,os,stat,sys,tarfile
B="/home/alex/hepta-local-007f-20261111/v54-web-helper-code5-sign-r1/inputs/"
PINS=[
 ("provenance/DEPENDENCY-RESULT.json",486209,"08c8c0dbc5677643da0aeb202314a4c26fda76ee2904696cd18aea102715cdc0"),
 ("provenance/R8-RESULT.json",8620,"d4aa66ea4105c13ba8b6e1c2540a3aeb74d3a3f70ddcf128818d4aad08ac5eeb"),
 ("source.tar.gz",92623,"efeda404b4f68d2d0fe4646d34e75c395b9995791fc6361d8244aa7ba2012824")]
def ident(s):
 return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
seen={}
def read(name,size,sha):
 from pathlib import Path
 p=Path(B+name)
 assert p.is_absolute() and all(not q.is_symlink() for q in (p,*p.parents))
 fd=os.open(str(p),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd)
  assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==size
  with os.fdopen(os.dup(fd),"rb") as stream: raw=stream.read(size+1)
  assert ident(a)==ident(os.fstat(fd))==ident(p.stat())
  assert len(raw)==size and hashlib.sha256(raw).hexdigest()==sha
  seen[str(p)]=ident(a)
  return raw
 finally: os.close(fd)
raws=[read(*pin) for pin in PINS]
dep=json.loads(raws[0]);r8=json.loads(raws[1])
assert isinstance(dep.get("artifacts"),list) and len(dep["artifacts"])==17
target="src/org/trillionnium/hepta/webhelper/InstalledIdentity.java"
with tarfile.open(fileobj=io.BytesIO(raws[2]),mode="r:gz") as archive:
 rows=archive.getmembers()
 assert len(rows)==39 and len({r.name for r in rows})==39
 hits=[r for r in rows if r.name==target]
 assert len(hits)==1 and hits[0].isfile() and hits[0].size==7567
 raw=archive.extractfile(hits[0]).read(7568)
 assert len(raw)==7567 and hashlib.sha256(raw).hexdigest()=="15c9d44cde2d93f823372ab6e0baf6214d4cb80835907694df1212be4d3edf73"
for path,before in seen.items(): assert ident(os.stat(path,follow_symlinks=False))==before
report={"schema":"hepta.helper6-pocket4-fixed-input-metadata.v1","originals":[{"path":B+n,"bytes":s,"sha256":h} for n,s,h in PINS],
 "originals_final_identity_unchanged":True,"dependency_artifact_rows":dep["artifacts"],"r8_original_receipt":r8,
 "installed_identity":{"path_in_archive":target,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"raw_utf8":raw.decode("utf-8","strict")},
 "compiled":False,"downloaded":False,"signed":False,"phone_contacted":False,"operation_lock_accessed":False,
 "original_mac_operation_status":"unknown","claim":"Fixed pinned original metadata and one source member only; no toolchain or build pass."}
out=(json.dumps(report,ensure_ascii=False,sort_keys=True)+"\n").encode("utf-8")
assert len(out)<=65536
sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
