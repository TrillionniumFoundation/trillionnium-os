#!/usr/bin/env python3
"""Disposable local counter. Original phone shell bytes are recorded, never executed."""
from pathlib import Path
import argparse,hashlib,json,os,re,time
def write(path,v):
 raw=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 return hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--intent',type=Path,required=True);p.add_argument('--delay-ms',type=int,required=True);a=p.parse_args()
 os.umask(0o077);assert 0<=a.delay_ms<=2000
 raw=a.intent.read_bytes();v=json.loads(raw);out=a.intent.parent
 assert str(out).startswith('/work/NEG-') and out.resolve()==out
 assert v['schema']=='hepta.synthetic-host-counter-intent.v1' and v['phone_command_executed'] is False
 assert re.fullmatch('[0-9a-f]{32}',v['action_id']) and re.fullmatch('[0-9a-f]{64}',v['command_sha256'])
 started=time.monotonic()
 identity={'pid':os.getpid(),'pgid':os.getpgrp(),'sid':os.getsid(0),'uid':os.getuid(),'gid':os.getgid()}
 assert identity['pid']==identity['pgid']==identity['sid']
 binding={'action_id':v['action_id'],'command_sha256':v['command_sha256'],'call_id':v['original_call']['call_id'],'intent_sha256':hashlib.sha256(raw).hexdigest()}
 write(out/'COUNTER-CLAIM.json',{'schema':'hepta.synthetic-host-counter-claim.v1',**binding,**identity,'can_redispatch':False})
 counter_sha=write(out/'COUNTER.json',{'schema':'hepta.synthetic-host-counter.v1','value':1,**binding,'committed_monotonic':time.monotonic(),'synthetic_only':True,'phone_effects':0})
 if a.delay_ms:time.sleep(a.delay_ms/1000)
 stdout=b'HOST-ONLY-COUNTER=1\n'
 write(out/'COUNTER-RECEIPT.json',{'schema':'hepta.synthetic-host-counter-receipt.v1',**binding,**identity,
  'counter_sha256':counter_sha,'value':1,'state':'counter_committed_before_exit','elapsed_seconds':time.monotonic()-started,
  'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stdout_bytes':len(stdout),'stderr_bytes':0,
  'phone_command_executed':False,'actual_process_wait_is_external':True})
 os.write(1,stdout)
 return 0
if __name__=='__main__':raise SystemExit(main())
