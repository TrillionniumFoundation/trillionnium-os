#!/usr/bin/env python3
"""Read-only exact shared-parent aliases after one failed pre-stage admission."""
import base64,errno,json,os,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
KEYS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
G=Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1')
A=Path('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1')
LABEL='root-r10-neg01-fc33-bound01'
NONCE='e2fdaccd43cec9da1df4d77783db8fdb'
def need(v,s):
    if not v:raise ValueError(s)
def metadata(st):return [getattr(st,k)for k in KEYS]
def audit(event,args):
    if event.startswith(('subprocess.','socket.'))or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg','os.putenv','os.unsetenv','ctypes.dlopen','ctypes.dlsym','os.mkdir','os.remove','os.unlink','os.rmdir','os.rename','os.replace','os.symlink','os.link','os.chmod','os.chown','os.truncate','os.utime','os.chflags','os.setxattr','os.removexattr'}:
        raise PermissionError('diagnostic is read-only: '+event)
    if event=='open':
        path,mode,flags=args
        need(not ((type(mode)is str and any(c in mode for c in 'wax+'))or(type(flags)is int and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))),'no file writes')
def alias(path):
    first=path.lstat();names=sorted(os.listdir(path));label=os.getxattr(path,'security.selinux',follow_symlinks=False)
    need(stat.S_ISDIR(first.st_mode)and len(names)<=20000,'bounded actual directory')
    need(metadata(first)==metadata(path.lstat())and names==sorted(os.listdir(path))and label==os.getxattr(path,'security.selinux',follow_symlinks=False),'complete alias full9/name/label bookends')
    return {'path':str(path),'metadata':metadata(first),'names':names,'selinux_raw_b64':base64.b64encode(label).decode()}
def presence(path):
    try:s=path.lstat()
    except FileNotFoundError as e:
        need(e.errno==errno.ENOENT,'actual ENOENT required');return {'path':str(path),'exists':False,'errno':e.errno}
    return {'path':str(path),'exists':True,'metadata':metadata(s),'is_directory':stat.S_ISDIR(s.st_mode),'is_symlink':stat.S_ISLNK(s.st_mode)}
need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'existing owned root transport required')
sys.addaudithook(audit)
started=time.monotonic_ns();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
need(boot=='f8019f83-20a7-4f18-bea1-51c980621e4d','same actual boot')
before={'gnu':alias(G),'android':alias(A)}
observations=[presence(p)for p in (G/LABEL,A/LABEL/'executor',Path('/proc/1/root/data/local/tmp')/('hepta-native-guard-'+NONCE))]
after={'gnu':alias(G),'android':alias(A)}
need(before==after,'two actual shared-parent observations changed')
value={'schema':'hepta.fc33.shared-parent-readonly-observation.v1','state':'ACTUAL_DIRECTORY_NAMES_OBSERVED_NO_ADMISSION','label':LABEL,'nonce':NONCE,'boot_id':boot,'before':before,'after':after,'current_owned_paths':observations,'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),'phone_file_writes':0,'ui_inputs':0,'native_dispatches':0,'model_requests':0,'automatic_retry':False,'qualification':False}
raw=json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False)+'\n';need(len(raw.encode())<=65536,'bounded complete observation');print(raw,end='')
