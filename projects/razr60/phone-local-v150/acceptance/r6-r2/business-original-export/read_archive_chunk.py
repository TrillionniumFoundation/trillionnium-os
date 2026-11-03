#!/usr/bin/env python3
"""Root-only bounded read of one already-created business archive chunk."""
import base64,hashlib,json,os,re,signal,stat,sys
from pathlib import Path
ROOT=Path('/var/lib/trillionnium/owner-open/phone-local-v150/business-original-captures-r6-r2')
CHUNK=1024*1024
MAX_ARCHIVE=64*1024*1024
def need(ok,why):
 if not ok:raise ValueError(why)
def meta(s):
 return {k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
def expire(sig,frame):raise TimeoutError('archive_chunk_8s_limit')
def main():
 signal.signal(signal.SIGALRM,expire);signal.setitimer(signal.ITIMER_REAL,8)
 bound=json.loads(base64.b64decode(sys.argv[1],validate=True))
 need(set(bound)=={'nonce','archive_sha256','archive_bytes','archive_stat','offset'},'chunk_bound_fields')
 nonce=bound['nonce'];size=bound['archive_bytes'];offset=bound['offset']
 need(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'nonce_format')
 need(isinstance(bound['archive_sha256'],str) and re.fullmatch('[0-9a-f]{64}',bound['archive_sha256']),'archive_pin_format')
 need(type(size) is int and 0<size<=MAX_ARCHIVE,'archive_size')
 need(type(offset) is int and 0<=offset<size and offset%CHUNK==0,'chunk_offset')
 p=ROOT/nonce/'originals.tar.gz'
 need(p.parent.resolve(strict=True)==p.parent and p.parent.parent==ROOT,'archive_parent')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  need(stat.S_ISREG(a.st_mode) and stat.S_IMODE(a.st_mode)==0o600
       and a.st_uid==a.st_gid==0 and a.st_nlink==1 and a.st_size==size,'archive_type_owner_mode')
  need(meta(a)==bound['archive_stat'],'archive_identity_changed')
  os.lseek(fd,offset,os.SEEK_SET);wanted=min(CHUNK,size-offset);parts=[];n=0
  while n<wanted:
   part=os.read(fd,wanted-n)
   need(part,'archive_short_chunk');parts.append(part);n+=len(part)
  raw=b''.join(parts)
  need(meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'archive_changed_during_chunk')
 finally:os.close(fd)
 result={'schema':'hepta.business-archive-chunk.v150.r6.1','nonce':nonce,
  'archive_sha256':bound['archive_sha256'],'archive_bytes':size,'archive_stat':bound['archive_stat'],
  'offset':offset,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
  'raw_b64':base64.b64encode(raw).decode(),'eof':offset+len(raw)==size,
  'phone_ui_actions':0,'model_requests':0,'socket_calls':0,'file_writes':0}
 sys.stdout.write(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n')
 signal.setitimer(signal.ITIMER_REAL,0)
 return 0
if __name__=='__main__':sys.exit(main())
