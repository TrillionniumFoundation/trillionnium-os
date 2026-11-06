import base64,gzip,hashlib,io,json,os,stat,tarfile
from pathlib import Path
ROOT=Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/followthrough-20261106-fc33-source-audit01/native-streams-v3")
RESULTS=json.loads("{\"actual-shared-run01\":{\"bytes\":79208,\"sha256\":\"0250099e4209e1f13d5def2b38298826b3e574e3adf95048986f45f3362a75f2\"},\"actual-native-run01\":{\"bytes\":61293,\"sha256\":\"6c62408d6d19460757d0160ac49aaf3b2fa3b1e1673a5220bbf4ba1a1e945968\"},\"actual-selected-guards-run01\":{\"bytes\":11071,\"sha256\":\"1a0e24bb1d9caa9e7b95669bdedea9470ff769f4ac3335b0aef1e898cc0d4d90\"}}")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def meta(st):return[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns]
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=4*1024*1024
  with os.fdopen(os.dup(fd),"rb")as f:raw=f.read(before.st_size+1)
  assert len(raw)==before.st_size and meta(before)==meta(os.fstat(fd))==meta(os.lstat(path))
 finally:os.close(fd)
 return raw,meta(before)
def write(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 checked,_=read(path);assert checked==raw
 return{"bytes":len(raw),"sha256":sha(raw),"git_blob_sha1":git(raw)}
os.umask(0o077)
for folder,pin in RESULTS.items():
 raw,_=read(ROOT/folder/"RESULT.json");assert len(raw)==pin["bytes"]and sha(raw)==pin["sha256"]
evidence=ROOT/"evidence";evidence.mkdir(mode=0o700)
blobs={};rows=[];directory_inventory={}
for folder in RESULTS:
 base=ROOT/folder
 for directory,subdirs,names in os.walk(base,topdown=True,followlinks=False):
  d=Path(directory);ds=os.lstat(d);assert stat.S_ISDIR(ds.st_mode)and not stat.S_ISLNK(ds.st_mode)
  assert all(not (d/name).is_symlink() for name in subdirs)
  directory_inventory[str(d.relative_to(ROOT))]=sorted(subdirs+names)
  for name in sorted(names):
   path=d/name;raw,metadata=read(path);relative=str(path.relative_to(ROOT));blobs[relative]=raw
   rows.append({"path":relative,"bytes":len(raw),"sha256":sha(raw),"source_metadata":metadata})
assert len(blobs)<=1024 and sum(map(len,blobs.values()))<=16*1024*1024
manifest={"schema":"razr60-native-v3-actual-host-output-inventory/v1","source_root":str(ROOT),
 "files":sorted(rows,key=lambda r:r["path"]),"file_count":len(rows),"total_original_bytes":sum(map(len,blobs.values())),
 "directory_names":directory_inventory,"results":RESULTS,"all_fixture_scopes_synthetic":True,
 "private_NEG01_originals_included":False,"phone_calls":0,"native_dispatches":0,"model_requests":0}
manifest_raw=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
manifest_pin=write(evidence/"HOST-OUTPUTS-MANIFEST.json",manifest_raw)
buffer=io.BytesIO()
with gzip.GzipFile(fileobj=buffer,mode="wb",mtime=0,filename="")as gz:
 with tarfile.open(fileobj=gz,mode="w")as tar:
  allblobs=dict(blobs,**{"HOST-OUTPUTS-MANIFEST.json":manifest_raw})
  for name,raw in sorted(allblobs.items()):
   info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;info.uid=info.gid=0;info.mtime=0
   tar.addfile(info,io.BytesIO(raw))
archive=buffer.getvalue();archive_pin=write(evidence/"HOST-OUTPUTS.tar.gz",archive)
with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz")as tar:
 assert len(tar.getmembers())==len(blobs)+1 and all(m.isfile()for m in tar.getmembers())
 assert all(tar.extractfile(name).read()==raw for name,raw in allblobs.items())
for row in rows:
 raw,metadata=read(ROOT/row["path"])
 assert len(raw)==row["bytes"]and sha(raw)==row["sha256"]and metadata==row["source_metadata"]
for directory,names in directory_inventory.items():assert sorted(os.listdir(ROOT/directory))==names
print(json.dumps({"state":"HOST_ORIGINAL_OUTPUTS_ARCHIVED","files":len(rows),"original_bytes":sum(map(len,blobs.values())),
 "archive":archive_pin,"manifest":manifest_pin,"source_files_unchanged":True,"phone_calls":0,"native_dispatches":0},sort_keys=True))
