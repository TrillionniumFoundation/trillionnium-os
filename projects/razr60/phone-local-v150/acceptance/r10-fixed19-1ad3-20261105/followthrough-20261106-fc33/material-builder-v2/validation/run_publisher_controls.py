"""Host publication tests only: no R4 read, source derivation, runtime freeze or phone."""
import errno,hashlib,json,os,stat,sys,tempfile,types
from pathlib import Path
source=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(mode=0o700)
M=types.ModuleType("material_v2");M.__file__=str(source);exec(compile(source.read_bytes(),str(source),"exec"),M.__dict__)
cases=[]
def check(v):
 if not v:raise AssertionError("material publication control")
def test(name,fn):fn();cases.append(dict(name=name,passed=True))
def rejects(name,fn,kind=ValueError):
 try:fn()
 except kind as e:cases.append(dict(name=name,passed=True,exception=type(e).__name__,rejection=str(e)))
 else:raise AssertionError("accepted "+name)
files={"COMBINATION.json":b"{}\n","shared/provider/source/x.py":b"HOST_SOURCE_CONTROL\n",
 "shared/config.json":b"{}\n","reference/source.json":b"{}\n","DERIVATION.json":b'{"state":"HOST_SOURCE_CONTROL"}\n'}
def fds():return len(os.listdir("/dev/fd"))
with tempfile.TemporaryDirectory(prefix="fc33-material-publisher-")as temporary:
 base=Path(temporary).resolve();before=fds();record=[];oldopen=M.os.open
 def record_open(path,flags,*args,**kwargs):
  if flags&os.O_CREAT:record.append(str(path))
  return oldopen(path,flags,*args,**kwargs)
 M.os.open=record_open
 try:M.publish_material(base/"valid",files)
 finally:M.os.open=oldopen
 test("all_complete_nested_material_bytes_read_back",lambda:check(all((base/"valid"/n).read_bytes()==raw for n,raw in files.items())))
 test("terminal_DERIVATION_written_last",lambda:check(record[-1]=="DERIVATION.json"))
 test("success_all_directory_and_file_fds_closed",lambda:check(fds()==before))
 rejects("existing_output_not_reused",lambda:M.publish_material(base/"valid",files),FileExistsError)
 for index,name in enumerate(("/absolute","../escape","shared/../escape","unknown_parent/x")):
  altered=dict(files);altered[name]=b"x"
  rejects("unqualified_member_"+str(index),lambda a=altered,i=index:M.publish_material(base/("invalid"+str(i)),a))
  check(not(base/("invalid"+str(index))).exists())
 def replace_on_first_create(output,escape,nested=False):
  escape.mkdir(mode=0o700);previous=M.os.open;done=[False]
  def race(path,flags,*args,**kwargs):
   if not done[0]and flags&os.O_CREAT and(not nested or str(path)=="x.py"):
    done[0]=True;target=output/"shared/provider/source"if nested else output
    target.rename(target.with_name(target.name+"_original"));target.symlink_to(escape,target_is_directory=True)
   return previous(path,flags,*args,**kwargs)
  M.os.open=race
  try:M.publish_material(output,files)
  finally:M.os.open=previous
 for nested in (False,True):
  tag="nested"if nested else"root";escape=base/("escaped_"+tag);before=fds()
  rejects(tag+"_directory_symlink_replacement_rejected",lambda n=nested,e=escape,t=tag:replace_on_first_create(base/("race_"+t),e,n))
  test(tag+"_replacement_gets_zero_files_and_no_fd_leak",lambda e=escape,b=before:check(list(e.iterdir())==[]and fds()==b))
 output=base/"io_failure";oldsync=M.os.fsync;before=fds()
 def fail(fd):raise OSError(errno.EIO,"HOST_SOURCE_CONTROL")
 M.os.fsync=fail
 try:rejects("unknown_payload_io_not_accepted",lambda:M.publish_material(output,files),OSError)
 finally:M.os.fsync=oldsync
 test("payload_failure_has_no_terminal_and_all_fds_closed",lambda:check(not(output/"DERIVATION.json").exists()and fds()==before))
 output=base/"corruption";corrupted=[False]
 def corrupt(fd):
  oldsync(fd)
  if not corrupted[0]and(output/"COMBINATION.json").exists():
   corrupted[0]=True;(output/"COMBINATION.json").write_bytes(b"wrong")
 M.os.fsync=corrupt
 try:rejects("created_payload_readback_corruption_rejected",lambda:M.publish_material(output,files))
 finally:M.os.fsync=oldsync
 test("corrupt_payload_never_publishes_terminal",lambda:check(not(output/"DERIVATION.json").exists()))
 output=base/"late_sync_failure";before=fds()
 def late(fd):
  if(output/"DERIVATION.json").exists()and stat.S_ISDIR(os.fstat(fd).st_mode):
   raise OSError(errno.EIO,"HOST_SOURCE_CONTROL_LATE_DURABILITY_UNKNOWN")
  return oldsync(fd)
 M.os.fsync=late
 try:rejects("late_directory_sync_error_not_inferred_success",lambda:M.publish_material(output,files),OSError)
 finally:M.os.fsync=oldsync
 test("late_unknown_closes_fds_and_result_presence_is_not_success",lambda:check(fds()==before and(output/"DERIVATION.json").exists()))
report=dict(schema="hepta.material-source.host-publisher-controls.v1",state="PASS_SOURCE_ONLY",passed=len(cases),tests=cases,
 source=dict(bytes=source.stat().st_size,sha256=hashlib.sha256(source.read_bytes()).hexdigest()),
 R4_originals_read=False,actual_material_derivation=False,runtime_freeze=False,actual_BUILD=False,phone_calls=0,
 actual_install=False,actual_READY=False,new_acceptance_nonces=0,fixed19_credit=0,
 qualified_success_requires_original_host_process_success_and_complete_outputs=True)
with(out/"RESULT.json").open("xb")as f:f.write((json.dumps(report,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(report,sort_keys=True))
