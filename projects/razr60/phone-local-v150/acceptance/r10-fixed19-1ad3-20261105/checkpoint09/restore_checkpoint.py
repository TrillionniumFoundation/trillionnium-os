#!/usr/bin/env python3
"""Verify this checkpoint losslessly. Optional destination must be a new directory.
No archived program is imported, compiled or executed.
"""
import argparse,hashlib,io,json,lzma,os,stat,tarfile
from pathlib import Path,PurePosixPath

def require(ok,why):
 if not ok:raise ValueError(why)
def strict(raw):
 def pairs(rows):
  d={}
  for k,v in rows:require(k not in d,'Duplicate JSON key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def safe(n):
 p=PurePosixPath(n);require(type(n) is str and n and not p.is_absolute() and str(p)==n and '..' not in p.parts and '\\' not in n and '\0' not in n,'Unsafe member path');return p

def read(p,limit):
 require(p.resolve(strict=True)==p,'Symlink in input path')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=limit,'Unsafe or oversized input')
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(a.st_size+1)
  fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  meta=lambda s:tuple(getattr(s,k) for k in fields)
  require(len(b)==a.st_size and meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'Input identity changed');return b
 finally:os.close(fd)
def assemble(base,rows,descriptor):
 require(type(rows) is list and 1<=len(rows)<=1024,'Bad part count');total=0;parts=[];names=set()
 for r in rows:
  require(set(r)=={'path','offset','bytes','sha256'} and type(r['offset']) is int and r['offset']==total,'Noncontiguous part')
  safe(r['path']);require(r['path'] not in names,'Duplicate part');names.add(r['path'])
  b=read(base/r['path'],524288);require(pin(b)=={k:r[k] for k in ('bytes','sha256')},'Part hash mismatch');parts.append(b);total+=len(b)
  require(total<=512*1024*1024,'Archive storage bound')
 b=b''.join(parts);require(pin(b)==descriptor,'Whole concatenation differs');return b

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--destination',type=Path);args=ap.parse_args()
 base=Path(__file__).resolve().parent;mf=strict(read(base/'archive/ARCHIVE-MANIFEST.json',1024*1024))
 packed=assemble(base,mf['parts'],mf['archive']);index_raw=assemble(base,mf['source_index_parts'],mf['source_index'])
 decoder=lzma.LZMADecompressor();plain=decoder.decompress(packed,max_length=mf['tar']['bytes']+1)
 require(decoder.eof and not decoder.unused_data and pin(plain)==mf['tar'],'Incomplete or extra XZ stream')
 index=strict(index_raw);rows=index['files'];require(len(rows)==index['members']==mf['source_members'],'Source count differs')
 originals={r['path']:r for r in rows};require(len(originals)==len(rows),'Duplicate source index path')
 for name in originals:safe(name)
 expected={'SOURCE-INDEX.json':mf['source_index']};expected.update({'originals/'+n:{k:r[k] for k in ('bytes','sha256')} for n,r in originals.items()})
 bodies={}
 with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as t:
  members=t.getmembers();require(len(members)==len(expected)==mf['archive_members'],'Archive member count differs')
  for m in members:
   safe(m.name);require(m.isfile() and m.name in expected and m.name not in bodies,'Unexpected/nonregular member');require(m.size==expected[m.name]['bytes'],'Member size differs')
   b=t.extractfile(m).read();require(pin(b)==expected[m.name],'Member hash differs');bodies[m.name]=b
 require(bodies['SOURCE-INDEX.json']==index_raw,'Embedded source index differs')
 if args.destination is not None:
  out=args.destination.absolute();require(not out.exists() and out.parent.resolve(strict=True)==out.parent,'Destination must be new with canonical parent');out.mkdir(mode=0o700)
  for n,b in sorted(bodies.items()):
   p=out/n;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 print(json.dumps({'verified_original_files':len(rows),'verified_original_bytes':sum(r['bytes'] for r in rows),'archive':mf['archive'],'extracted':args.destination is not None,'archived_source_executed':False,'whole_cases_qualified':0},sort_keys=True))
if __name__=='__main__':main()
