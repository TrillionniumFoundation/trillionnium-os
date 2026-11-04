#!/system/bin/sh
# Root-only existing startup capture plus all-module hashes; no evidence recursion/export, model request or UI.
set -eu
exec /data/adb/magisk/busybox timeout -s TERM -k 2 20 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -B -c 'from pathlib import Path
import base64,hashlib,json,os,stat
B=Path('"'"'/var/lib/trillionnium/owner-open/phone-local-v150'"'"')
O=B/'"'"'module-install-start-v150-r7-r2-02'"'"'
C=Path('"'"'/proc/1/root/data/adb/trillionnium-hepta-phone-local-v150-r7-r2/<INSTANCE_UUID_REQUIRED>'"'"')
files=[];total=0;groups=set();expected={}

# Module evidence is hashed only; its large host-original copies are never base64-exported.
M=Path('"'"'/proc/1/root/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r2'"'"')
module_verification={'"'"'schema'"'"':'"'"'hepta.module-all-files-readonly-hashes.v1'"'"','"'"'complete'"'"':False,'"'"'issues'"'"':[],'"'"'files'"'"':[],'"'"'raw_evidence_exported'"'"':False}
EXPECTED_MANIFEST_SHA='"'"'1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd'"'"'
EXPECTED_SUMS_SHA='"'"'<PRIVATE_BOUND_SHA256_001_REQUIRED>'"'"'
EXPECTED_SEALED_SHA='"'"'<PRIVATE_BOUND_SHA256_002_REQUIRED>'"'"'
def bounded_file_hash(path):
 st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==st.st_gid==0 and st.st_size<=4194304
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  opened=os.fstat(fd);assert (st.st_dev,st.st_ino)==(opened.st_dev,opened.st_ino)
  h=hashlib.sha256();size=0
  while True:
   raw=os.read(fd,65536)
   if not raw:break
   size+=len(raw);assert size<=4194304;h.update(raw)
  after=os.fstat(fd)
  assert (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
 finally:os.close(fd)
 assert size==opened.st_size
 return {'"'"'bytes'"'"':size,'"'"'sha256'"'"':h.hexdigest(),'"'"'uid'"'"':st.st_uid,'"'"'gid'"'"':st.st_gid,'"'"'mode'"'"':oct(stat.S_IMODE(st.st_mode))}
if M.is_dir() and not M.is_symlink():
 observed={};hashed_bytes=0;entries=0
 for p in sorted(M.rglob('"'"'*'"'"')):
  entries+=1;assert entries<=512
  st=p.lstat()
  assert not stat.S_ISLNK(st.st_mode)
  if stat.S_ISDIR(st.st_mode):continue
  item=bounded_file_hash(p);hashed_bytes+=item['"'"'bytes'"'"'];assert hashed_bytes<=16777216
  name=str(p.relative_to(M));observed[name]=item
  module_verification['"'"'files'"'"'].append(dict(relative=name,**item))
 def exact(name,pin):
  return name in observed and observed[name]['"'"'sha256'"'"']==pin
 checks={'"'"'manifest_exact'"'"':exact('"'"'MODULE-MANIFEST-v150-r7-r2.json'"'"',EXPECTED_MANIFEST_SHA),
  '"'"'sums_exact'"'"':exact('"'"'module-inputs.sha256'"'"',EXPECTED_SUMS_SHA),'"'"'sealed_exact'"'"':exact('"'"'SEALED'"'"',EXPECTED_SEALED_SHA)}
 expected_files={}
 if checks['"'"'sums_exact'"'"']:
  raw=(M/'"'"'module-inputs.sha256'"'"').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED_SUMS_SHA
  for line in raw.decode('"'"'ascii'"'"').splitlines():
   pin,name=line.split('"'"'  '"'"',1)
   assert len(pin)==64 and all(c in '"'"'0123456789abcdef'"'"' for c in pin) and name not in expected_files and not name.startswith('"'"'/'"'"') and '"'"'..'"'"' not in Path(name).parts
   expected_files[name]=pin
  expected_files.update({'"'"'module-inputs.sha256'"'"':EXPECTED_SUMS_SHA,'"'"'SEALED'"'"':EXPECTED_SEALED_SHA})
  checks['"'"'expected_file_set_exact'"'"']=set(expected_files)==set(observed)
  checks['"'"'all_frozen_file_hashes_exact'"'"']=all(exact(name,pin) for name,pin in expected_files.items())
  checks['"'"'all_owned_modes_exact'"'"']=all(x['"'"'uid'"'"']==x['"'"'gid'"'"']==0 and x['"'"'mode'"'"']==('"'"'0o700'"'"' if name=='"'"'service.sh'"'"' else '"'"'0o600'"'"') for name,x in observed.items())
 else:
  checks.update(expected_file_set_exact=False,all_frozen_file_hashes_exact=False,all_owned_modes_exact=False)
 module_verification.update(checks=checks,complete=all(checks.values()),hashed_file_count=len(observed),hashed_bytes=hashed_bytes)
 module_verification['"'"'issues'"'"']=[name for name,value in checks.items() if value is not True]
else:module_verification['"'"'issues'"'"'].append('"'"'new_module_directory_absent_or_symlink'"'"')
for name,base in [('"'"'operator'"'"',O),('"'"'claim'"'"',C)]:
 if not base.exists():continue
 for p in sorted(base.iterdir()):
  s=p.lstat()
  if not stat.S_ISREG(s.st_mode):continue
  assert s.st_nlink==1 and s.st_size<=262144
  raw=p.read_bytes();total+=len(raw);assert total<=2097152
  files.append({'"'"'relative'"'"':name+'"'"'/'"'"'+p.name,'"'"'bytes'"'"':len(raw),'"'"'sha256'"'"':hashlib.sha256(raw).hexdigest(),'"'"'raw_b64'"'"':base64.b64encode(raw).decode(),'"'"'uid'"'"':s.st_uid,'"'"'gid'"'"':s.st_gid,'"'"'mode'"'"':oct(stat.S_IMODE(s.st_mode))})
  if p.name.endswith('"'"'.identity'"'"') or p.name in ('"'"'supervisor-identity'"'"',):
   text=raw.decode().strip()
   if len(text.split('"'"':'"'"'))==4 and all(x.isdigit() for x in text.split('"'"':'"'"')):
    parts=list(map(int,text.split('"'"':'"'"')));expected[name+'"'"'/'"'"'+p.name]=parts;groups.update(parts[:3])
  if p.name=='"'"'service-spawn-pid'"'"':
   value=int(raw.strip());groups.add(value);expected[name+'"'"'/'"'"'+p.name]=[value]
members=[]
for p in Path('"'"'/proc'"'"').iterdir():
 if not p.name.isdigit():continue
 try:
  raw=(p/'"'"'stat'"'"').read_bytes();pid=int(p.name)
  assert 0<len(raw)<=65536 and raw.startswith(str(pid).encode()+b'"'"' ('"'"') and b'"'"') '"'"' in raw
  tail=raw.rsplit(b'"'"') '"'"',1)[1].split();assert len(tail)>=20 and len(tail[0])==1
  assert all(tail[i].isdigit() for i in (2,3,19))
  pg=int(tail[2]);sid=int(tail[3]);start=int(tail[19])
  if pid in groups or pg in groups or sid in groups:
   item={'"'"'pid'"'"':pid,'"'"'pgid'"'"':pg,'"'"'sid'"'"':sid,'"'"'start_ticks'"'"':start,'"'"'state'"'"':tail[0].decode('"'"'ascii'"'"')}
   try:item['"'"'context'"'"']=(p/'"'"'attr/current'"'"').read_text().strip();item['"'"'exe'"'"']=os.readlink(p/'"'"'exe'"'"')
   except (FileNotFoundError,PermissionError):pass
   members.append(item)
 except (FileNotFoundError,ProcessLookupError):continue
print(json.dumps({'"'"'schema'"'"':'"'"'hepta.module-start-r7-r2.original-readiness-capture'"'"','"'"'module_verification'"'"':module_verification,'"'"'files'"'"':files,'"'"'raw_bytes'"'"':total,'"'"'original_identities'"'"':expected,'"'"'current_members'"'"':members,'"'"'model_requests'"'"':0,'"'"'send'"'"':0,'"'"'automatic_retry'"'"':False,'"'"'capture_scope'"'"':'"'"'original startup receipts and current matching processes; no complete-quiescence or health-success claim'"'"','"'"'files_are_independent_observations'"'"':True},sort_keys=True))
'
