#!/usr/bin/env python3
"""One bounded bwrap host fixture. No production or phone mounts, no real model."""
import argparse,hashlib,json,os,re,signal,stat,subprocess,sys,time
from pathlib import Path
BASE=Path('/operator-home/razr60-local-model-v150/acceptance-r7-host-negative-r1')
HARNESS=BASE/'namespace-component-r1'
INPUTS=BASE/'inputs-r1'
MANIFEST_SHA='f42f62e3d778c551eaf8ceb9d2a73bd367b0c8ed9e09d9f4c2d025bcb403bb58'
CLIENT='/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py'
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,v):
 raw=(json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
def check_inputs():
 raw=(INPUTS/'MANIFEST.json').read_bytes();assert sha(raw)==MANIFEST_SHA
 rows=json.loads(raw)['files'];out=[]
 for x in rows:
  p=INPUTS/x['name'];st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1
  b=p.read_bytes();assert len(b)==x['bytes'] and sha(b)==x['sha256']
  out.append({'path':x['name'],'bytes':len(b),'sha256':sha(b)})
 return out
def identity(pid):
 try:b=(Path('/proc')/str(pid)/'stat').read_bytes()
 except FileNotFoundError:return None
 t=b[b.rfind(b')')+2:].split()
 return {'pid':pid,'ppid':int(t[1]),'pgid':int(t[2]),'sid':int(t[3]),'start_ticks':int(t[19])}
def group_absent(pgid):
 rows=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:q=identity(int(p.name))
  except (FileNotFoundError,ProcessLookupError):continue
  if q and (q['pgid']==pgid or q['sid']==pgid):rows.append(q)
 try:os.killpg(pgid,0);kernel='exists'
 except ProcessLookupError:kernel='ESRCH'
 return {'members':rows,'kernel':kernel}
def originals(root):
 rows=[];excluded=[]
 for p in sorted(root.rglob('*')):
  st=p.lstat();r=str(p.relative_to(root))
  if p.name=='synthetic-only-api.key':
   excluded.append({'path':r,'reason':'synthetic credential; no content or digest retained'});continue
  if stat.S_ISLNK(st.st_mode):
   excluded.append({'path':r,'reason':'intentional hostile evidence symlink fixture','link_target':os.readlink(p)});continue
  if stat.S_ISDIR(st.st_mode):continue
  if not stat.S_ISREG(st.st_mode):raise RuntimeError('unexpected non-regular fixture evidence')
  if p.name=='sparse-capacity.bin':
   excluded.append({'path':r,'reason':'sparse capacity boundary, metadata only','apparent_bytes':st.st_size,'allocated_bytes':st.st_blocks*512});continue
  assert st.st_size<=4*1024*1024
  raw=p.read_bytes();rows.append({'path':r,'bytes':len(raw),'sha256':sha(raw)})
 return rows,excluded
def main():
 a=argparse.ArgumentParser();a.add_argument('--execute-once',action='store_true');a.add_argument('--attempt',required=True);a.add_argument('--expected-runner-sha256',required=True);args=a.parse_args()
 assert re.fullmatch('component-attempt-[0-9]{2}',args.attempt)
 if not args.execute_once:print('review-only; no fixture execution');return 0
 os.umask(0o077)
 assert sha((HARNESS/'host_negative_runner.py').read_bytes())==args.expected_runner_sha256
 before=check_inputs();out=BASE/args.attempt;out.mkdir(mode=0o700)
 env={'host_uid':os.getuid(),'host_gid':os.getgid(),'host_pid':os.getpid(),'host_netns':os.readlink('/proc/self/ns/net'),'host_mntns':os.readlink('/proc/self/ns/mnt'),'host_pidns':os.readlink('/proc/self/ns/pid'),'phone_calls':0,'real_model_requests':0,'host_system_paths_modified':False}
 write(out/'OUTER-ENV.json',env);write(out/'INPUT-PINS-BEFORE.json',before)
 argv=['/usr/bin/bwrap','--unshare-user','--uid','0','--gid','0','--unshare-pid','--unshare-net','--unshare-ipc','--unshare-uts','--die-with-parent','--new-session',
 '--ro-bind','/usr','/usr','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--symlink','usr/bin','/bin','--symlink','usr/sbin','/sbin',
 '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/var/lib/trillionnium/owner-open/phone-local-v150',
 '--ro-bind',str(INPUTS),'/suite','--ro-bind',str(HARNESS),'/harness','--bind',str(out),'/work','--ro-bind',str(INPUTS/'client/tool_client_r6.py'),CLIENT,
 '--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--setenv','PYTHONDONTWRITEBYTECODE','1','--chdir','/work','--cap-drop','ALL','--',
 '/usr/bin/python3','-I','-B','/harness/host_negative_runner.py','--execute-once']
 write(out/'EXECUTION-INTENT.json',{'argv':argv,'runner_sha256':args.expected_runner_sha256,'phone_calls':0,'real_model_requests':0,'production_changes':0})
 started=time.monotonic();timed_out=False;signals=[];stdout=open(out/'namespace.stdout','xb');stderr=open(out/'namespace.stderr','xb')
 child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
 ident=identity(child.pid);write(out/'BWRAP-SPAWN.json',{'pid':child.pid,'identity':ident,'monotonic':time.monotonic()})
 try:
  try:rc=child.wait(timeout=55)
  except subprocess.TimeoutExpired:
   timed_out=True
   for sig,bound in [(signal.SIGTERM,3),(signal.SIGKILL,2)]:
    if child.poll() is not None:break
    assert identity(child.pid)==ident,'owned bwrap identity changed; no signal'
    os.killpg(child.pid,sig);signals.append({'signal':sig,'monotonic':time.monotonic()})
    try:child.wait(timeout=bound)
    except subprocess.TimeoutExpired:continue
   rc=child.poll()
   assert rc is not None,'bwrap cleanup remains unknown'
 finally:stdout.close();stderr.close()
 after=check_inputs();assert after==before
 write(out/'INPUT-PINS-AFTER.json',after)
 census=group_absent(child.pid)
 inner=json.loads((out/'RESULT.json').read_bytes()) if (out/'RESULT.json').is_file() else None
 result={'schema':'hepta.component-fixture-outer.v150.r7-r1.1','original_argv':argv,'original_pid':child.pid,'original_identity':ident,'returncode':rc,'actual_direct_child_wait_returned':True,'timed_out':timed_out,'signals':signals,'group_after':census,'elapsed_seconds':time.monotonic()-started,'source_input_pins_preserved':before==after,'inner_status':inner.get('status') if inner else None,'phone_calls':0,'real_model_requests':0,'host_system_paths_modified':False,'production_changes':0,'scope':'host_isolated; synthetic guard and contract receipts, no physical-device evidence'}
 rec=write(out/'OUTER-RESULT.json',result);rows,excluded=originals(out)
 manifest=write(out/'ORIGINAL-FILES.json',{'files':rows,'excluded':excluded,'scope':'original host isolated evidence, no phone task','files_count':len(rows),'bytes':sum(x['bytes'] for x in rows)})
 print(json.dumps({'result':rec,'manifest':manifest,'returncode':rc,'inner_status':result['inner_status'],'timed_out':timed_out,'files':len(rows),'phone_calls':0,'real_model_requests':0}))
 return 0 if rc==0 and inner and inner['status']=='PASS' and not timed_out and census['members']==[] and census['kernel']=='ESRCH' else 1
if __name__=='__main__':raise SystemExit(main())
