#!/usr/bin/env python3
"""Hostile identity/grammar/publication tests, plus actual Linux self-snapshot."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

SOURCE=Path(__file__).resolve().parents[1]/'perf/collect_linux_resource_snapshot.py'
SPEC=importlib.util.spec_from_file_location('linux_resource_snapshot_tested',SOURCE)
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class LinuxResourceSnapshotTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
 def tearDown(self):self.temp.cleanup()
 def fixture(self):
  files={'cpu.stat':'usage_usec 19\nuser_usec 11\nsystem_usec 8\ncore_sched.force_idle_usec 0\n',
   'memory.current':'4096\n','memory.peak':'8192\n','io.stat':'8:0 rbytes=3 wbytes=4 rios=1 wios=1\n8:16 rbytes=5 wbytes=6 rios=1 wios=1\n',
   'pids.current':'3\n','pids.peak':'7\n'}
  for name,text in files.items():(self.root/name).write_text(text)
  return files
 def collect_fixture(self):
  self.fixture()
  with mock.patch.object(M,'CGROUP_ROOT',self.root.parent),mock.patch.object(M,'filesystem_type',return_value=M.CGROUP2_MAGIC):return M.collect(self.root)
 def test_cpu_extension_field_preserved(self):
  self.assertEqual(M.parse_counter('cpu.stat','usage_usec 19\ncore_sched.force_idle_usec 2\n')['core_sched.force_idle_usec'],2)
 def test_duplicate_cpu_field_rejected(self):
  with self.assertRaises(M.SnapshotError):M.parse_counter('cpu.stat','usage_usec 1\nusage_usec 2\n')
 def test_io_sums_bound_kernel_device_counters(self):
  self.assertEqual(M.parse_counter('io.stat','8:0 rbytes=3 wbytes=4\n8:16 rbytes=5 wbytes=6\n'),{'rbytes':8,'wbytes':10})
 def test_io_empty_reports_actual_zero_counters(self):self.assertEqual(M.parse_counter('io.stat',''),{'rbytes':0,'wbytes':0})
 def test_io_duplicate_device_rejected(self):
  with self.assertRaises(M.SnapshotError):M.parse_counter('io.stat','8:0 rbytes=3 wbytes=4\n8:0 rbytes=5 wbytes=6\n')
 def test_io_duplicate_field_rejected(self):
  with self.assertRaises(M.SnapshotError):M.parse_counter('io.stat','8:0 rbytes=3 wbytes=4 rbytes=5\n')
 def test_io_incomplete_byte_fields_rejected(self):
  with self.assertRaises(M.SnapshotError):M.parse_counter('io.stat','8:0 rbytes=3\n')
 def test_io_aggregate_overflow_rejected(self):
  with self.assertRaises(M.SnapshotError):M.parse_counter('io.stat',f'8:0 rbytes={M.UINT64_MAX} wbytes=0\n8:16 rbytes=1 wbytes=0\n')
 def test_integer_grammar_and_overflow_rejected(self):
  for value in ['-1','+1','01','1.0','1e9','1\n\n',str(1<<65),'max']:
   with self.subTest(value=value),self.assertRaises(M.SnapshotError):M.count(value)
 def test_symlink_counter_refused(self):
  (self.root/'target').write_text('3\n');(self.root/'memory.current').symlink_to('target');fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  try:
   with self.assertRaises(OSError):M.read_kernel_file(fd,'memory.current',M.time.monotonic()+1)
  finally:os.close(fd)
 def test_hardlinked_counter_refused(self):
  (self.root/'memory.current').write_text('3\n');os.link(self.root/'memory.current',self.root/'another');fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  try:
   with self.assertRaises(M.SnapshotError):M.read_kernel_file(fd,'memory.current',M.time.monotonic()+1)
  finally:os.close(fd)
 def test_fifo_counter_never_blocks(self):
  os.mkfifo(self.root/'cpu.stat');fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  try:
   with self.assertRaises(M.SnapshotError):M.read_kernel_file(fd,'cpu.stat',M.time.monotonic()+1)
  finally:os.close(fd)
 def test_counter_byte_bound(self):
  (self.root/'cpu.stat').write_bytes(b'x'*(M.MAX_FILE_BYTES+1));fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  try:
   with self.assertRaises(M.SnapshotError):M.read_kernel_file(fd,'cpu.stat',M.time.monotonic()+1)
  finally:os.close(fd)
 def test_counter_path_replacement_rejected(self):
  p=self.root/'memory.current';p.write_text('3\n');fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);real=M.os.read;changed=False
  def read(selected,n):
   nonlocal changed
   data=real(selected,n)
   if not changed:
    changed=True;p.rename(self.root/'old');p.write_text('4\n')
   return data
  try:
   with mock.patch.object(M.os,'read',read),self.assertRaises(M.SnapshotError):M.read_kernel_file(fd,'memory.current',M.time.monotonic()+1)
  finally:os.close(fd)
 def test_counter_permission_change_rejected(self):
  p=self.root/'memory.current';p.write_text('3\n');fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);real=M.os.read
  def read(selected,n):data=real(selected,n);p.chmod(0o600);return data
  try:
   with mock.patch.object(M.os,'read',read),self.assertRaises(M.SnapshotError):M.read_kernel_file(fd,'memory.current',M.time.monotonic()+1)
  finally:os.close(fd)
 def test_missing_controller_unavailable_not_zero(self):
  fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  try:r=M.read_kernel_file(fd,'memory.current',M.time.monotonic()+1)
  finally:os.close(fd)
  self.assertEqual(r['status'],'unavailable');self.assertNotIn('value',r)
 def test_cgroup_metadata_path_replacement_rejected(self):
  p=self.root/'group';p.mkdir();fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);p.rename(self.root/'oldgroup');p.mkdir()
  try:
   with self.assertRaises(M.SnapshotError):M.stable_directory(p,fd,M.time.monotonic()+1)
  finally:os.close(fd)
 def test_ordinary_filesystem_not_kernel_observation(self):
  with mock.patch.object(M,'CGROUP_ROOT',self.root.parent),self.assertRaises(M.SnapshotError):M.collect(self.root)
 def test_slow_last_read_cannot_complete(self):
  p=self.root/'memory.current';p.write_text('3\n');fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);real=M.os.read
  def read(selected,n):data=real(selected,n);M.time.sleep(0.04);return data
  try:
   with mock.patch.object(M.os,'read',read),self.assertRaises(M.SnapshotError):M.read_kernel_file(fd,'memory.current',M.time.monotonic()+0.02)
  finally:os.close(fd)
 def test_known_kernel_values_do_not_manufacture_rss_process_peaks(self):
  x=self.collect_fixture();self.assertEqual(len(x['resources']),26)
  self.assertEqual(x['resources']['cgroup_memory_peak_bytes']['value'],8192)
  self.assertEqual(x['resources']['cgroup_pids_peak']['value'],7)
  for key in ['rss_peak_bytes','process_peak','thread_peak','fsync_count','unknown_rate','fairness']:
   self.assertEqual(x['resources'][key]['status'],'unavailable');self.assertIsNone(x['resources'][key]['value'])
  self.assertFalse(x['resource_contract_complete']);self.assertFalse(x['installed_subject_verified']);self.assertFalse(x['production_ready'])
  self.assertEqual(x['decision'],'SOURCE_KERNEL_SNAPSHOT_COMPLETE')
 def test_publication_private_single_link_and_no_overwrite(self):
  p=self.root/'report.json';M.publish(p,{'value':3});self.assertEqual(json.loads(p.read_text()),{'value':3});s=p.stat();self.assertEqual(s.st_nlink,1);self.assertEqual(stat.S_IMODE(s.st_mode),0o600)
  with self.assertRaises(FileExistsError):M.publish(p,{'value':4})
  self.assertEqual(json.loads(p.read_text()),{'value':3})
 def test_publication_serialization_failure_never_opens_owned_parent(self):
  def descriptors():
   result={}
   for name in os.listdir('/proc/self/fd'):
    try:result[name]=os.readlink('/proc/self/fd/'+name)
    except FileNotFoundError:pass
   return result
  for value,error in [(float('nan'),ValueError),(object(),TypeError)]:
   with self.subTest(error=error.__name__):
    before=descriptors()
    with self.assertRaises(error):M.publish(self.root/'report.json',{'value':value})
    after=descriptors()
    self.assertEqual(after,before)
    self.assertEqual(list(self.root.iterdir()),[])
 def test_publication_symlink_parent_refused(self):
  p=self.root/'real';p.mkdir();link=self.root/'link';link.symlink_to(p,target_is_directory=True)
  with self.assertRaises(OSError):M.publish(link/'report.json',{'value':3})
  self.assertFalse((p/'report.json').exists())
 def test_publication_writable_parent_refused(self):
  self.root.chmod(0o770)
  with self.assertRaises(M.SnapshotError):M.publish(self.root/'report.json',{'value':3})
  self.assertFalse((self.root/'report.json').exists())
 def test_publication_parent_permission_change_refused(self):
  real=M.os.fsync;changed=False
  def fsync(fd):
   nonlocal changed
   real(fd)
   if not changed:changed=True;self.root.chmod(0o770)
  with mock.patch.object(M.os,'fsync',fsync),self.assertRaises(M.SnapshotError):M.publish(self.root/'report.json',{'value':3})
  self.assertEqual(list(self.root.iterdir()),[])
 def test_publication_report_close_failure_cannot_expose_name(self):
  real=M.close_file;failed=False
  def close(owner):
   nonlocal failed
   real(owner)
   if not failed:failed=True;raise OSError('report close interrupted after consuming fd')
  with mock.patch.object(M,'close_file',close),self.assertRaises(OSError):M.publish(self.root/'report.json',{'value':3})
  self.assertTrue(failed);self.assertEqual(list(self.root.iterdir()),[])
 def test_report_interruption_before_owned_close_retires_same_object(self):
  real=M.close_file;calls=[];before=set(os.listdir('/proc/self/fd'))
  def close(owner):
   calls.append(owner)
   if len(calls)==1:raise KeyboardInterrupt('before owned FileIO close')
   real(owner)
  with mock.patch.object(M,'close_file',close),self.assertRaises(KeyboardInterrupt):M.publish(self.root/'report.json',{'value':3})
  self.assertEqual(len(calls),2);self.assertIs(calls[0],calls[1]);self.assertTrue(calls[0].closed)
  self.assertEqual(set(os.listdir('/proc/self/fd')),before);self.assertEqual(list(self.root.iterdir()),[])
 def test_report_interruption_after_close_never_closes_reused_number(self):
  real=M.close_file;calls=[];replacement=[];saved=self.root/'other'
  def close(owner):
   calls.append(owner)
   if len(calls)==1:
    old=owner.fileno();real(owner)
    fresh=os.open(saved,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);replacement.append(fresh)
    self.assertEqual(fresh,old)
    raise KeyboardInterrupt('after real consuming FileIO close and FD reuse')
   real(owner)
  try:
   with mock.patch.object(M,'close_file',close),self.assertRaises(KeyboardInterrupt):M.publish(self.root/'report.json',{'value':3})
   self.assertEqual(len(calls),2);self.assertIs(calls[0],calls[1]);self.assertTrue(calls[0].closed)
   os.write(replacement[0],b'not closed by stale cleanup')
   self.assertEqual(saved.read_bytes(),b'not closed by stale cleanup')
   self.assertFalse((self.root/'report.json').exists())
  finally:
   for fd in replacement:os.close(fd)
 def test_directory_parent_close_interruption_preserves_child_cleanup(self):
  real_open=M.os.open;real_close=M.os.close;opened=[];attempts=[]
  def open_owned(*args,**kwargs):
   fd=real_open(*args,**kwargs);opened.append(fd);return fd
  def close(fd):
   attempts.append(fd)
   if len(attempts)==1:raise KeyboardInterrupt('before raw directory close; ownership unknown')
   real_close(fd)
  try:
   with mock.patch.object(M.os,'open',open_owned),mock.patch.object(M.os,'close',close),self.assertRaises(KeyboardInterrupt):M.open_directory(Path('/tmp'),M.time.monotonic()+1)
   self.assertEqual(len(opened),2);self.assertEqual(attempts,opened)
   # The new child was never lost; the parent's interrupted raw close is
   # deliberately not retried. A standalone observer must terminate then.
   with self.assertRaises(OSError):os.fstat(opened[1])
   os.fstat(opened[0])
  finally:
   # Fixture teardown owns the untouched parent in this single-thread probe;
   # it grants no production permission to retry an unknown numeric FD.
   if opened:real_close(opened[0])
 def test_directory_consuming_close_interruption_preserves_reused_number(self):
  real_close=M.os.close;attempts=[];replacement=[];saved=self.root/'other'
  def close(fd):
   attempts.append(fd);real_close(fd)
   if len(attempts)==1:
    fresh=os.open(saved,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);replacement.append(fresh)
    self.assertEqual(fresh,fd)
    raise KeyboardInterrupt('after consuming directory close and FD reuse')
  try:
   with mock.patch.object(M.os,'close',close),self.assertRaises(KeyboardInterrupt):M.open_directory(Path('/tmp'),M.time.monotonic()+1)
   self.assertEqual(len(attempts),2)
   os.write(replacement[0],b'reused descriptor preserved')
   self.assertEqual(saved.read_bytes(),b'reused descriptor preserved')
  finally:
   for fd in replacement:real_close(fd)
 def test_late_observer_membership_close_cannot_complete(self):
  self.fixture();proc=Path('/proc')/str(os.getpid());proc_inode=proc.stat().st_ino;real=M.os.close;delayed=False
  def close(fd):
   nonlocal delayed
   matching=os.fstat(fd).st_ino==proc_inode;real(fd)
   if matching and not delayed:delayed=True;M.time.sleep(0.04)
  with mock.patch.object(M,'CGROUP_ROOT',self.root.parent),mock.patch.object(M,'filesystem_type',return_value=M.CGROUP2_MAGIC),mock.patch.object(M.os,'close',close),self.assertRaises(M.SnapshotError):M.collect(self.root,seconds=0.02)
  self.assertTrue(delayed)
 def test_late_retained_cgroup_close_cannot_complete(self):
  self.fixture();real_open=M.open_directory;real_close=M.os.close;retained=[];delayed=[]
  def open_directory(path,deadline):
   fd=real_open(path,deadline)
   if path==self.root and not retained:retained.append(fd.fileno())
   return fd
  def close(fd):
   real_close(fd)
   if retained and fd==retained[0] and not delayed:delayed.append(True);M.time.sleep(0.15)
  with mock.patch.object(M,'CGROUP_ROOT',self.root.parent),mock.patch.object(M,'filesystem_type',return_value=M.CGROUP2_MAGIC),mock.patch.object(M,'open_directory',side_effect=open_directory),mock.patch.object(M.os,'close',side_effect=close),self.assertRaises(M.SnapshotError):M.collect(self.root,seconds=0.1)
  self.assertEqual(delayed,[True])
 def test_late_published_parent_close_cannot_report_success(self):
  real_open=M.open_directory;real_close=M.os.close;retained=[];delayed=[];p=self.root/'report.json'
  def open_directory(path,deadline):
   fd=real_open(path,deadline)
   if path==self.root and not retained:retained.append(fd.fileno())
   return fd
  def close(fd):
   real_close(fd)
   if retained and fd==retained[0] and not delayed:delayed.append(True);M.time.sleep(0.15)
  with mock.patch.object(M,'MAX_SECONDS',0.1),mock.patch.object(M,'open_directory',side_effect=open_directory),mock.patch.object(M.os,'close',side_effect=close),self.assertRaises(M.SnapshotError):M.publish(p,{'value':3})
  self.assertEqual(delayed,[True])
  # The visible commit is retained, but this failed observer never grants
  # success from file existence; consumers require an actual zero exit.
  self.assertEqual(json.loads(p.read_text()),{'value':3})
 def test_failed_observer_never_publishes_or_reports_success(self):
  p=self.root/'report.json'
  with mock.patch.object(M,'collect',side_effect=OSError('kernel observation failed')):
   self.assertEqual(M.main(['--cgroup','/sys/fs/cgroup/private','--output',str(p)]),2)
  self.assertFalse(p.exists())
 def test_clock_not_accepted_as_input(self):
  with self.assertRaises(SystemExit):M.main(['--cgroup','/sys/fs/cgroup/private','--output',str(self.root/'report.json'),'--monotonic-ns','3'])
 @unittest.skipUnless(Path('/sys/fs/cgroup/cgroup.controllers').exists(),'Linux cgroup v2 required')
 def test_actual_self_cgroup_returns_source_only_observations(self):
  lines=Path('/proc/self/cgroup').read_text().splitlines();entry=next((x for x in lines if x.startswith('0::')),None)
  if not entry or entry=='0::/':self.skipTest('no non-root current cgroup')
  path=Path('/sys/fs/cgroup')/entry[3:].lstrip('/')
  if not path.exists():self.skipTest('current namespace does not expose the process cgroup')
  x=M.collect(path);self.assertFalse(x['resource_contract_complete']);self.assertFalse(x['installed_subject_verified']);self.assertGreater(x['window_end_monotonic_ns'],x['window_start_monotonic_ns'])
  self.assertTrue(any(v['status']=='observed' for v in x['raw_kernel_observations'].values()))

if __name__=='__main__':unittest.main()
