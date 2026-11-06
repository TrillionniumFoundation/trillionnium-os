#!/usr/bin/env python3
"""Read complete originals from this already-ended owned host test only."""
import base64, hashlib, json, os, stat, zlib
from pathlib import Path
ROOT = Path('/home/alex/razr60-local-model-v150/fc33-neg14-capacity-native-v3-01')
def sha(b): return hashlib.sha256(b).hexdigest()
def nine(s): return [getattr(s,n) for n in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')]
def need(v,m):
    if not v: raise ValueError(m)
def scan():
    return [ROOT/'PUBLICATION.json'] + sorted(p for p in (ROOT/'RUN01').rglob('*') if not p.is_dir())
need(not (ROOT/'RUN01/owned-tests').exists(), 'owned test tree cleanup required')
before = scan()
need(1 < len(before) < 128, 'bounded complete original set')
files=[];total=0
for p in before:
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=4*1024*1024,'bounded regular original')
        chunks=[]
        while True:
            b=os.read(fd,65536)
            if not b: break
            chunks.append(b)
        b=b''.join(chunks);need(nine(a)==nine(os.fstat(fd))==nine(p.lstat()) and len(b)==a.st_size,'complete full9 bookend')
        total+=len(b);need(total<=8*1024*1024,'total original bound')
        files.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':sha(b),'full9':nine(a),'base64':base64.b64encode(b).decode()})
    finally:os.close(fd)
need(scan()==before,'closed original pathname set unchanged')
packet=(json.dumps({'schema':'fc33.neg14.complete-owned-host-originals.v1','root':str(ROOT),'files':files,'file_count':len(files),'bytes':total,'no_phone_or_model_calls':True},sort_keys=True,separators=(',',':'))+'\n').encode()
packed=zlib.compress(packet,9)
print(json.dumps({'packet_bytes':len(packet),'packet_sha256':sha(packet),'compressed_bytes':len(packed),'compressed_sha256':sha(packed),'archive_base64':base64.b64encode(packed).decode()},sort_keys=True))
