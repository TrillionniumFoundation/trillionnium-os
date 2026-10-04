from __future__ import annotations
import importlib.util, io, os, stat, tempfile, unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('common_base_boundary_test',ROOT/'tools/generate-owner-open-common-base.py')
assert SPEC and SPEC.loader
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
REAL_FILEIO=io.FileIO;REAL_STAT=os.stat;REAL_REPLACE=os.replace;REAL_CLOSE=os.close

def open_fds():
 return {int(p.name) for p in Path('/proc/self/fd').iterdir() if p.name.isdecimal() and p.exists()}

class CommonBaseBoundaryTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='common-base-owned-fixture-');self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.input=self.root/'input.mk';self.output=self.root/'output.mk'
  self.input.write_bytes(b'original\n');self.output.write_bytes(b'old complete output\n')
  before=open_fds();self.addCleanup(lambda:self.assertEqual(open_fds(),before))
 def test_exact_bounded_read_and_byte_preserving_render(self):
  self.input.write_bytes(b'X'*M.MAX_BYTES);reads=[]
  class Measured(REAL_FILEIO):
   def read(self,size=-1):
    value=super().read(size);reads.append(len(value));return value
  with mock.patch.object(M.io,'FileIO',Measured):self.assertEqual(M.bounded_text(self.input),'X'*M.MAX_BYTES)
  self.assertEqual(sum(reads),M.MAX_BYTES);self.assertTrue(all(size<=4096 for size in reads))
  common=(ROOT/M.COMMON).read_bytes();self.assertEqual(M.render(common.decode()).encode(),(ROOT/M.OUTPUT).read_bytes())
 def test_preexisting_input_symlink_rejected(self):
  target=self.root/'target';target.write_bytes(b'changed!\n');self.input.unlink();self.input.symlink_to(target)
  with self.assertRaises(M.GenerationError):M.bounded_text(self.input)
  self.assertEqual(target.read_bytes(),b'changed!\n')
 def test_real_post_stat_same_size_symlink_replacement_rejected(self):
  target=self.root/'alternate';target.write_bytes(b'changed!\n')
  def switched(path,*args,**kwargs):
   metadata=REAL_STAT(path,*args,**kwargs)
   if path==self.input.name and kwargs.get('dir_fd') is not None:self.input.unlink();self.input.symlink_to(target)
   return metadata
  with mock.patch.object(M.os,'stat',switched):
   with self.assertRaises(OSError):M.bounded_text(self.input)
  self.assertEqual(target.read_bytes(),b'changed!\n')
 def test_real_post_stat_larger_replacement_rejected_before_read(self):
  alternate=self.root/'alternate';alternate.write_bytes(b'X'*(M.MAX_BYTES+64));reads=[]
  class Measured(REAL_FILEIO):
   def read(self,size=-1):reads.append(size);return super().read(size)
  def switched(path,*args,**kwargs):
   metadata=REAL_STAT(path,*args,**kwargs)
   if path==self.input.name and kwargs.get('dir_fd') is not None:REAL_REPLACE(alternate,self.input)
   return metadata
  with mock.patch.object(M.os,'stat',switched),mock.patch.object(M.io,'FileIO',Measured):
   with self.assertRaises(M.GenerationError):M.bounded_text(self.input)
  self.assertEqual(reads,[])
 def test_growth_after_real_pre_read_stat_never_reads_extra_byte(self):
  self.input.write_bytes(b'X'*M.MAX_BYTES);reads=[];case=self
  class Growing(REAL_FILEIO):
   def read(self,size=-1):
    if not reads:
     with case.input.open('ab') as writer:writer.write(b'Z')
    value=super().read(size);reads.append(len(value));return value
  with mock.patch.object(M.io,'FileIO',Growing):
   with self.assertRaises(M.GenerationError):M.bounded_text(self.input)
  self.assertLessEqual(sum(reads),M.MAX_BYTES);self.assertEqual(self.input.stat().st_size,M.MAX_BYTES+1)
 def test_directory_entry_replacement_after_actual_read_rejected(self):
  alternate=self.root/'alternate';alternate.write_bytes(b'original\n');case=self
  class Replacing(REAL_FILEIO):
   def read(self,size=-1):
    value=super().read(size);REAL_REPLACE(alternate,case.input);return value
  with mock.patch.object(M.io,'FileIO',Replacing):
   with self.assertRaises(M.GenerationError):M.bounded_text(self.input)
 def test_fifo_and_nonordinary_parent_rejected(self):
  self.input.unlink();os.mkfifo(self.input)
  with self.assertRaises(M.GenerationError):M.bounded_text(self.input)
  actual=self.root/'actual';actual.mkdir();(actual/'input').write_text('valid\n');linked=self.root/'linked';linked.symlink_to(actual,target_is_directory=True)
  with self.assertRaises(M.GenerationError):M.bounded_text(linked/'input')
 def test_preexisting_output_symlink_refused_without_target_write(self):
  outside=self.root/'outside';outside.write_text('sentinel\n');self.output.unlink();self.output.symlink_to(outside)
  with self.assertRaises(M.GenerationError):M.publish_generated(self.output,'new complete output\n')
  self.assertEqual(outside.read_text(),'sentinel\n');self.assertTrue(self.output.is_symlink());self.assertEqual(list(self.root.glob('.owner-open-common-base-*')),[])
 def test_publish_complete_inode_replace_and_temporary_starts_private(self):
  old_inode=self.output.stat().st_ino;before_after=[];modes=[]
  class Measured(REAL_FILEIO):
   def write(self,data):modes.append(stat.S_IMODE(os.fstat(self.fileno()).st_mode));return super().write(data)
  def observed(*args,**kwargs):
   before_after.append(self.output.read_bytes());REAL_REPLACE(*args,**kwargs);before_after.append(self.output.read_bytes())
  new=b'new complete output\n'*1000
  with mock.patch.object(M.os,'replace',observed),mock.patch.object(M.io,'FileIO',Measured):M.publish_generated(self.output,new.decode())
  self.assertEqual(before_after,[b'old complete output\n',new]);self.assertNotEqual(self.output.stat().st_ino,old_inode)
  self.assertEqual(set(modes),{0o600});self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o644);self.assertEqual(list(self.root.glob('.owner-open-common-base-*')),[])
 def test_output_mutation_during_write_refused_other_writer_preserved(self):
  case=self
  class Changed(REAL_FILEIO):
   def write(self,data):value=super().write(data);case.output.write_bytes(b'other writer\n');return value
  with mock.patch.object(M.io,'FileIO',Changed):
   with self.assertRaises(M.GenerationError):M.publish_generated(self.output,'new complete output\n')
  self.assertEqual(self.output.read_bytes(),b'other writer\n');self.assertEqual(list(self.root.glob('.owner-open-common-base-*')),[])
 def test_last_moment_output_symlink_replaced_without_following_target(self):
  outside=self.root/'outside';outside.write_text('sentinel\n')
  def switched(*args,**kwargs):self.output.unlink();self.output.symlink_to(outside);return REAL_REPLACE(*args,**kwargs)
  with mock.patch.object(M.os,'replace',switched):M.publish_generated(self.output,'new complete output\n')
  self.assertEqual(outside.read_text(),'sentinel\n');self.assertFalse(self.output.is_symlink());self.assertEqual(self.output.read_text(),'new complete output\n')
  # Entry rename never follows the target; it is not compare-and-swap against a hostile writer.
 def test_late_parent_swap_cannot_publish_into_replacement_directory(self):
  parent=self.root/'selected';parent.mkdir();output=parent/'generated.mk';output.write_text('old selected\n');moved=self.root/'moved'
  def switched(*args,**kwargs):
   parent.rename(moved);parent.mkdir();(parent/'generated.mk').write_text('other directory\n');return REAL_REPLACE(*args,**kwargs)
  with mock.patch.object(M.os,'replace',switched):
   with self.assertRaises(M.GenerationError):M.publish_generated(output,'complete late output\n')
  self.assertEqual((parent/'generated.mk').read_text(),'other directory\n');self.assertEqual((moved/'generated.mk').read_text(),'complete late output\n')
  # A failed late observer may leave complete output in its originally opened parent; no successful generation.
 def test_one_shot_owned_close_before_delegation_closes_and_rethrows(self):
  owned=[]
  class Interrupted(REAL_FILEIO):
   def close(self):
    if self not in owned:owned.append(self);raise KeyboardInterrupt('before real object close')
    return super().close()
  with mock.patch.object(M.io,'FileIO',Interrupted):
   with self.assertRaises(KeyboardInterrupt):M.bounded_text(self.input)
  self.assertTrue(all(stream.closed for stream in owned))
 def test_owned_close_after_real_release_never_closes_reused_fd(self):
  replacement=self.root/'replacement';replacement.write_text('replacement\n');reused=[];case=self
  class Interrupted(REAL_FILEIO):
   def close(self):
    if not self.closed:
     old=self.fileno();super().close();fd=os.open(replacement,os.O_WRONLY);case.assertEqual(fd,old);reused.append(fd)
     raise KeyboardInterrupt('after actual close and actual fd reuse')
    return super().close()
  try:
   with mock.patch.object(M.io,'FileIO',Interrupted):
    with self.assertRaises(KeyboardInterrupt):M.bounded_text(self.input)
   self.assertEqual(os.write(reused[0],b'alive'),5)
  finally:
   for fd in reused:REAL_CLOSE(fd)
 def test_directory_close_after_real_release_never_retries_reused_fd(self):
  handle=M.DirectoryHandle(self.root);old=handle.fd;replacement=self.root/'replacement';replacement.write_text('replacement\n');reused=[]
  def closed(fd):
   REAL_CLOSE(fd)
   if fd==old:
    new=os.open(replacement,os.O_WRONLY);self.assertEqual(new,old);reused.append(new);raise KeyboardInterrupt('after actual directory close and actual fd reuse')
  try:
   with mock.patch.object(M.os,'close',closed):
    with self.assertRaises(KeyboardInterrupt):handle.close()
    handle.close()
   self.assertEqual(os.write(reused[0],b'alive'),5)
  finally:
   for fd in reused:REAL_CLOSE(fd)

if __name__=='__main__':unittest.main()
