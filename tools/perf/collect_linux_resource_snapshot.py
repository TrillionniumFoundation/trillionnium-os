#!/usr/bin/env python3
"""Read a finite, descriptor-bound cgroup-v2 snapshot; never qualify a workload.

Kernel semantics: https://docs.kernel.org/admin-guide/cgroup-v2.html
The observer must remain outside a dedicated workload cgroup. Keep the workload
at an explicit work-end barrier until this observer has returned. systemd can
remove an exited unit's cgroup before collection, including RemainAfterExit.
A snapshot is sequential, not atomic across files. It does not prove that the
caller selected the installed subject or that nobody reset/migrated its state.
Deadline admission includes result construction and owned descriptor closure;
it cannot preempt a blocked synchronous kernel operation. A late publication
failure can retain a visible report, which still requires observer zero exit.
Run as a standalone observer and bind its actual whole-process termination.
Raw directory close exceptions are unknown and are never retried by number;
after interruption, terminate the observer instead of reusing this library.
Python asynchronous exceptions around raw descriptor acquisition cannot supply
a guarantee that every descriptor closed before that process terminated.
"""
from __future__ import annotations
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Any

SCHEMA = 'org.trillionnium.linux-resource-snapshot.v1'
CGROUP_ROOT = Path('/sys/fs/cgroup')
CGROUP2_MAGIC = 0x63677270
MAX_FILE_BYTES = 65536
MAX_REPORT_BYTES = 1024 * 1024
MAX_SECONDS = 5.0
UINT64_MAX = (1 << 64) - 1
FILES = ('cpu.stat', 'memory.current', 'memory.peak', 'io.stat', 'pids.current', 'pids.peak')
RESOURCE_UNITS = {
 'cpu_user_ns':'ns','cpu_system_ns':'ns','rss_current_bytes':'bytes','rss_peak_bytes':'bytes',
 'fd_peak':'count','thread_peak':'count','process_peak':'count',
 'context_switches_voluntary':'count','context_switches_involuntary':'count',
 'cgroup_cpu_usage_usec':'usec','cgroup_memory_current_bytes':'bytes','cgroup_memory_peak_bytes':'bytes',
 'cgroup_io_read_bytes':'bytes','cgroup_io_write_bytes':'bytes','cgroup_pids_current':'count','cgroup_pids_peak':'count',
 'read_bytes':'bytes','write_bytes':'bytes','fsync_count':'count','queue_depth_peak':'count',
 'queue_wait_ns':'ns','lock_wait_ns':'ns','lock_hold_ns':'ns','unknown_rate':'ratio','redispatch_count':'count','fairness':'ratio',
}
MAPPING = {
 'cgroup_cpu_usage_usec':('cpu.stat','usage_usec'),
 'cgroup_memory_current_bytes':('memory.current','value'),
 'cgroup_memory_peak_bytes':('memory.peak','value'),
 'cgroup_io_read_bytes':('io.stat','rbytes'),
 'cgroup_io_write_bytes':('io.stat','wbytes'),
 'cgroup_pids_current':('pids.current','value'),
 'cgroup_pids_peak':('pids.peak','value'),
}
UNAVAILABLE_REASON = {
 'cpu_user_ns':'Per-operation process CPU custody is absent; cgroup user_usec remains raw and is not silently given another scope.',
 'cpu_system_ns':'Per-operation process CPU custody is absent; cgroup system_usec remains raw and is not silently given another scope.',
 'rss_current_bytes':'cgroup memory includes other charged memory and is not process RSS.',
 'rss_peak_bytes':'cgroup memory.peak is not a process RSS peak.',
 'fd_peak':'No continuous descriptor lifecycle instrumentation.',
 'thread_peak':'pids.peak counts tasks in the cgroup hierarchy, not an individually bound process thread peak.',
 'process_peak':'pids.peak includes threads and cannot supply a distinct process peak.',
 'context_switches_voluntary':'No complete per-thread lifetime rusage collection.',
 'context_switches_involuntary':'No complete per-thread lifetime rusage collection.',
 'read_bytes':'Cgroup block accounting is not per-process read_bytes accounting.',
 'write_bytes':'Cgroup block accounting is not per-process write_bytes accounting.',
 'fsync_count':'I/O bytes and requests do not count fsync/fdatasync calls.',
 'queue_depth_peak':'No mechanical queue lifecycle observations.',
 'queue_wait_ns':'No runtime queue admission spans.',
 'lock_wait_ns':'No runtime lock acquisition spans.',
 'lock_hold_ns':'No runtime lock ownership spans.',
 'unknown_rate':'No raw workload outcomes were supplied or executed.',
 'redispatch_count':'No actual effect lifecycle trace was supplied or executed.',
 'fairness':'No mixed-client work and completion observations.',
}

class SnapshotError(RuntimeError): pass

class DirectoryHandle:
 """One close attempt for a raw Linux directory descriptor.

 A close error may have already released and reused the number. Never retry
 it. An asynchronous exception before delegation leaves closure unknown;
 this standalone observer must terminate, allowing the kernel to retire its
 descriptor table. Do not reuse an interrupted observer as a library worker.
 """
 def __init__(self, fd: int):self._fd=fd
 def __index__(self) -> int:
  if self._fd is None:raise SnapshotError('directory close already attempted')
  return self._fd
 def fileno(self) -> int:return self.__index__()
 def close(self) -> None:
  if self._fd is None:return
  closing=self._fd;self._fd=None
  os.close(closing)

def close_directory(handle: DirectoryHandle) -> None:handle.close()

def close_file(owner: io.FileIO) -> None:
 # FileIO retires its descriptor inside C. Retrying the same object is safe:
 # after a consuming close, its closed state cannot target a reused number.
 # An exception before entering close leaves this object as the owner.
 owner.close()

def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def check_deadline(deadline: float) -> None:
 if time.monotonic() >= deadline: raise SnapshotError('observer deadline exceeded')

def canonical_absolute(path: Path | str) -> Path:
 text = os.fspath(path)
 p = Path(text)
 if not p.is_absolute() or str(p) != text or '..' in p.parts or any(ord(c)<32 for c in text):
  raise SnapshotError('path must be canonical absolute with no control characters')
 return p

def open_directory(path: Path, deadline: float) -> DirectoryHandle:
 fd=DirectoryHandle(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC));owned=[fd]
 try:
  for part in path.parts[1:]:
   check_deadline(deadline)
   child=DirectoryHandle(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd))
   # Both handles remain recorded across the parent's close attempt.
   owned.append(child);close_directory(fd);fd=child
  check_deadline(deadline);return fd
 except BaseException as failure:
  for handle in owned:
   try:close_directory(handle)
   except BaseException as cleanup:failure.add_note('Directory close attempt failed: '+repr(cleanup))
  raise

def identity(metadata: os.stat_result) -> dict[str,int]:
 return {'device':metadata.st_dev,'inode':metadata.st_ino,'uid':metadata.st_uid,'gid':metadata.st_gid,
         'mode':stat.S_IMODE(metadata.st_mode),'links':metadata.st_nlink}

def filesystem_type(fd: int) -> int:
 # f_type is the first native long on Linux. The generously sized aligned
 # buffer avoids assuming the layout of the rest of struct statfs.
 if not sys.platform.startswith('linux'): raise SnapshotError('Linux is required')
 buf=(ctypes.c_long*64)();libc=ctypes.CDLL(None,use_errno=True)
 number=fd.fileno() if isinstance(fd,DirectoryHandle) else fd
 if libc.fstatfs(number,ctypes.byref(buf)) != 0: raise SnapshotError('cannot identify cgroup filesystem')
 return int(buf[0])

def stable_directory(path: Path, held_fd: int, deadline: float) -> None:
 again=open_directory(path,deadline)
 try:
  if identity(os.fstat(again)) != identity(os.fstat(held_fd)):
   raise SnapshotError('cgroup directory path no longer names observed object')
 finally:close_directory(again)

def read_kernel_file(dir_fd: int, name: str, deadline: float) -> dict[str,Any]:
 check_deadline(deadline)
 try:
  owner=io.FileIO(name,'rb',opener=lambda selected,flags:os.open(selected,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dir_fd))
 except FileNotFoundError:return {'status':'unavailable','reason':'Kernel counter file is absent on this selected cgroup.'}
 except PermissionError:return {'status':'unavailable','reason':'Observer cannot read this selected kernel counter.'}
 try:
  fd=owner.fileno()
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:
   raise SnapshotError('kernel counter is not single-link regular')
  chunks=[];size=0;start=time.monotonic_ns()
  while True:
   check_deadline(deadline)
   raw=os.read(fd,min(4096,MAX_FILE_BYTES+1-size))
   check_deadline(deadline)
   if not raw:break
   size+=len(raw)
   if size>MAX_FILE_BYTES:raise SnapshotError('kernel counter exceeds read bound')
   chunks.append(raw)
  finish=time.monotonic_ns();after=os.fstat(fd)
  if identity(before)!=identity(after):raise SnapshotError('kernel counter descriptor identity changed')
  current=os.stat(name,dir_fd=dir_fd,follow_symlinks=False)
  if identity(before)!=identity(current):raise SnapshotError('kernel counter directory entry changed')
  data=b''.join(chunks)
  try:text=data.decode('ascii')
  except UnicodeDecodeError as error:raise SnapshotError('kernel counter is not ASCII') from error
  return {'status':'observed','raw':text,'bytes':size,'sha256':sha256(data),'identity':identity(before),
          'read_start_monotonic_ns':start,'read_end_monotonic_ns':finish}
 finally:close_file(owner)

def count(text: str) -> int:
 if re.fullmatch(r'(?:0|[1-9][0-9]*)\n?',text) is None:raise SnapshotError('kernel integer is noncanonical')
 if len(text.rstrip('\n'))>20:raise SnapshotError('kernel integer exceeds uint64 width')
 value=int(text)
 if value>UINT64_MAX:raise SnapshotError('kernel integer exceeds uint64')
 return value

def parse_counter(name: str, text: str) -> dict[str,int]:
 if name != 'cpu.stat' and name != 'io.stat':return {'value':count(text)}
 if name=='cpu.stat':
  result={}
  for line in text.splitlines():
   pair=line.split()
   if len(pair)!=2 or re.fullmatch('[a-z][a-z0-9_.]*',pair[0]) is None or pair[0] in result:
    raise SnapshotError('cpu.stat has invalid or duplicate fields')
   result[pair[0]]=count(pair[1])
  if 'usage_usec' not in result:raise SnapshotError('cpu.stat has no usage_usec')
  return result
 totals={'rbytes':0,'wbytes':0};seen=set()
 for line in text.splitlines():
  fields=line.split()
  if not fields or re.fullmatch(r'[0-9]+:[0-9]+',fields[0]) is None or fields[0] in seen:
   raise SnapshotError('io.stat has invalid or duplicate device')
  seen.add(fields[0]);values={}
  for field in fields[1:]:
   pair=field.split('=')
   if len(pair)!=2 or re.fullmatch('[a-z][a-z0-9_.]*',pair[0]) is None or pair[0] in values:
    raise SnapshotError('io.stat has invalid or duplicate field')
   values[pair[0]]=count(pair[1])
  if not {'rbytes','wbytes'} <= values.keys():raise SnapshotError('io.stat lacks byte counters')
  for key in totals:
   totals[key]+=values[key]
   if totals[key]>UINT64_MAX:raise SnapshotError('io.stat aggregate exceeds uint64')
 return totals

def collect(cgroup: Path, *, seconds: float = 2.0) -> dict[str,Any]:
 if type(seconds) not in (int,float) or not 0<seconds<=MAX_SECONDS:raise SnapshotError('observer duration is outside 0..5 seconds')
 path=canonical_absolute(cgroup)
 if path==CGROUP_ROOT or not path.is_relative_to(CGROUP_ROOT):raise SnapshotError('select a non-root cgroup beneath /sys/fs/cgroup')
 started=time.monotonic_ns();deadline=time.monotonic()+seconds;fd=open_directory(path,deadline)
 try:
  before=identity(os.fstat(fd))
  if filesystem_type(fd)!=CGROUP2_MAGIC:raise SnapshotError('selected filesystem is not cgroup v2')
  raws={name:read_kernel_file(fd,name,deadline) for name in FILES};parsed={}
  for name,raw in raws.items():
   if raw['status']=='observed':parsed[name]=parse_counter(name,raw['raw'])
  stable_directory(path,fd,deadline);check_deadline(deadline)
  if identity(os.fstat(fd))!=before:raise SnapshotError('cgroup metadata changed during observation')
  result={}
  for name,unit in RESOURCE_UNITS.items():
   if name in MAPPING:
    source,key=MAPPING[name]
    if source in parsed:result[name]={'status':'observed','value':parsed[source][key],'unit':unit,'reason':None}
    else:result[name]={'status':'unavailable','value':None,'unit':unit,'reason':raws[source]['reason']}
   else:result[name]={'status':'unavailable','value':None,'unit':unit,'reason':UNAVAILABLE_REASON[name]}
  all_kernel=all(result[name]['status']=='observed' for name in MAPPING)
  proc_fd=open_directory(Path('/proc')/str(os.getpid()),deadline)
  try:membership=read_kernel_file(proc_fd,'cgroup',deadline)
  finally:close_directory(proc_fd)
  check_deadline(deadline)
  if membership['status']!='observed':raise SnapshotError('observer cgroup membership unavailable')
  membership_raw=membership['raw'].encode('ascii')
  if len(membership_raw)>4096:raise SnapshotError('observer membership exceeds byte bound')
  memberships=[line[3:] for line in membership_raw.decode('ascii').splitlines() if line.startswith('0::')]
  observer_in_scope=None
  if len(memberships)==1:
   current=Path(memberships[0]);selected=Path('/')/path.relative_to(CGROUP_ROOT)
   observer_in_scope=current==selected or current.is_relative_to(selected)
  document={'schema':SCHEMA,'decision':'SOURCE_KERNEL_SNAPSHOT_COMPLETE' if all_kernel else 'SOURCE_KERNEL_SNAPSHOT_PARTIAL',
   'observed_at_utc':datetime.now(timezone.utc).isoformat(),'window_start_monotonic_ns':started,'window_end_monotonic_ns':time.monotonic_ns(),
   'cgroup':{'path':str(path),'identity':before,'filesystem_type':CGROUP2_MAGIC,'scope':'This kernel cgroup and its descendants; subject identity is unqualified.'},
   'raw_kernel_observations':raws,'resources':result,'observer_membership':{'cgroup_sha256':sha256(membership_raw),'included_in_selected_scope':observer_in_scope,'membership_trust':'Same-namespace procfs observation; caller must independently establish installed placement.'},'all_seven_cgroup_counters_observed':all_kernel,
   'resource_contract_complete':False,'runtime_stages_observed':False,'installed_subject_verified':False,'barrier_proven_by_this_tool':False,
   'workload_executed':False,'production_ready':False,'public_release':False,'automatic_redispatch':False,
   'observer_process_zero_exit_required':True,
   'semantics':{'cpu_and_io':'Cumulative kernel cgroup accounting; not a per-operation delta. Device byte counters are summed, with no physical topology or amplification proof.',
    'memory':'Charged cgroup memory, not RSS. Peak is since cgroup creation for this new read-only descriptor; observer never resets it.',
    'pids':'Kernel tasks/TIDs, including threads and descendant cgroups; never substituted for distinct-process or per-process thread peak.',
    'snapshot':'Observer inclusion is explicitly reported; an included observer is not an admissible isolated workload measurement. Sequential file reads with true observer timestamps, not an atomic multi-controller or continuous measurement.',
    'trust':'Byte hashes and kernel descriptor bindings prove only observed input identity, never external operator approval or installed qualification.'}}
  document['content_sha256']=sha256(json.dumps(document,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
  check_deadline(deadline)
 finally:close_directory(fd)
 check_deadline(deadline)
 return document

def publish(path: Path, document: dict[str,Any]) -> None:
 path=canonical_absolute(path);deadline=time.monotonic()+MAX_SECONDS
 temp='.resource-snapshot-'+secrets.token_hex(16);parent=None;report=None;linked=False;owned=None
 raw=(json.dumps(document,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 if len(raw)>MAX_REPORT_BYTES:raise SnapshotError('report exceeds byte bound')
 check_deadline(deadline)
 try:
  parent=open_directory(path.parent,deadline)
  meta=os.fstat(parent)
  if meta.st_uid!=os.geteuid() or stat.S_IMODE(meta.st_mode)&0o022:raise SnapshotError('output parent must be observer-owned and not group/world writable')
  report=io.FileIO(temp,'wb',opener=lambda selected,flags:os.open(selected,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent));fd=report.fileno()
  owned=identity(os.fstat(fd));offset=0
  while offset<len(raw):
   check_deadline(deadline);n=os.write(fd,raw[offset:])
   if not n:raise SnapshotError('report write made no progress')
   offset+=n
  os.fsync(fd);check_deadline(deadline)
  if identity(os.fstat(parent))!=identity(meta):raise SnapshotError('output parent metadata changed')
  # Finish the report descriptor before exposing its name. A failed or
  # interrupted observer process remains inadmissible even if a file survives.
  close_file(report);report=None
  os.link(temp,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False);linked=True
  os.unlink(temp,dir_fd=parent);os.fsync(parent)
  stable_directory(path.parent,parent,deadline)
  if identity(os.fstat(parent))!=identity(meta):raise SnapshotError('output parent metadata changed')
  final=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  if (final.st_dev,final.st_ino)!=(owned['device'],owned['inode']) or final.st_nlink!=1 or stat.S_IMODE(final.st_mode)!=0o600:raise SnapshotError('published report identity differs')
  check_deadline(deadline)
 except BaseException:
  if parent is not None:
   for name in ([path.name] if linked else [])+[temp]:
    try:
     now=os.stat(name,dir_fd=parent,follow_symlinks=False)
     if owned and (now.st_dev,now.st_ino)==(owned['device'],owned['inode']):os.unlink(name,dir_fd=parent)
    except FileNotFoundError:pass
  raise
 finally:
  try:
   if report is not None:close_file(report)
  finally:
   if parent is not None:close_directory(parent)
 check_deadline(deadline)

def main(argv: list[str]|None=None) -> int:
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--cgroup',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--seconds',type=float,default=2.0);parser.add_argument('--require-all-cgroup-counters',action='store_true');args=parser.parse_args(argv)
 try:
  document=collect(args.cgroup,seconds=args.seconds)
  if args.require_all_cgroup_counters and not document['all_seven_cgroup_counters_observed']:raise SnapshotError('selected cgroup lacks requested kernel counters')
  publish(args.output,document)
 except (SnapshotError,OSError,ValueError) as error:print('Resource snapshot failed: '+str(error),file=sys.stderr);return 2
 print(json.dumps({'schema':SCHEMA,'decision':document['decision'],'resource_contract_complete':False,'output':str(args.output)},sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
