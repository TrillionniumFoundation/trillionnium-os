#!/usr/bin/env python3
"""Read-only current-boot census with explicit errno handling, then the unchanged original ledger gate."""
import errno,hashlib,json,os,stat,sys
EXPECTED_BOOT='<INSTANCE_BOOT_ID_REQUIRED>'
RETIRED_GROUPS=frozenset(('<RETIRED_GROUP_IDS_REQUIRED>',))
ANCHORS={'<ANCHOR_PID_REQUIRED>':'<ANCHOR_START_REQUIRED>'}
ORIGINAL='/var/lib/trillionnium/owner-open/phone-local-v150/module-r5-activation/activation_original_gate.py'
ORIGINAL_SHA='23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e'
GONE_ERRNOS=frozenset((errno.ENOENT,errno.ESRCH))
def parse_stat(raw,pid):
    if not isinstance(raw,bytes) or not raw or len(raw)>65536:
        raise ValueError('invalid_proc_stat_size')
    if not raw.startswith(str(pid).encode()+b' (') or b') ' not in raw:
        raise ValueError('proc_stat_pid_or_shape')
    tail=raw.rsplit(b') ',1)[1].split()
    if len(tail)<20 or len(tail[0])!=1:
        raise ValueError('proc_stat_fields')
    fields=[]
    for index in (2,3,19):
        text=tail[index]
        if not text or not text.isdigit():
            raise ValueError('proc_stat_numeric_field')
        fields.append(int(text))
    return {'pid':pid,'pgrp':fields[0],'session':fields[1],'start_ticks':fields[2]}
def read_stat(pid):
    fd=None
    try:
        fd=os.open('/proc/'+str(pid)+'/stat',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        chunks=[];size=0
        while True:
            block=os.read(fd,4096)
            if not block:break
            size+=len(block)
            if size>65536:raise ValueError('proc_stat_oversize')
            chunks.append(block)
        return parse_stat(b''.join(chunks),pid)
    except OSError as error:
        # These exact kernel errno values mean this process disappeared.
        # EACCES/EPERM/EIO and every parse error remain failures.
        if error.errno in GONE_ERRNOS:return None
        raise
    finally:
        if fd is not None:os.close(fd)
def census():
    if os.getuid()!=0 or os.geteuid()!=0:
        raise PermissionError('root_required')
    with open('/proc/sys/kernel/random/boot_id','rt',encoding='ascii') as stream:
        if stream.read(128).strip()!=EXPECTED_BOOT:raise ValueError('wrong_boot')
    own=read_stat(os.getpid())
    if own is None:raise ValueError('own_proc_view_missing')
    for pid,start in ANCHORS.items():
        row=read_stat(pid)
        if row is None or row['start_ticks']!=start:
            raise ValueError('known_native_proc_view_identity_changed')
    with os.scandir('/proc') as entries:
        pids=sorted(int(e.name) for e in entries if e.name.isascii() and e.name.isdigit())
    if not pids or len(pids)>100000:
        raise ValueError('proc_inventory_bound')
    present=[];gone=0;inspected=0
    for pid in pids:
        row=read_stat(pid)
        if row is None:
            gone+=1
            continue
        inspected+=1
        if row['pid'] in RETIRED_GROUPS or row['pgrp'] in RETIRED_GROUPS or row['session'] in RETIRED_GROUPS:
            present.append(row)
    if present:
        raise ValueError('retired_process_group_or_session_present')
    return {'schema':'hepta.module-r7-r1.read-only-census.v1','state':'RETIRED_GROUPS_ABSENT',
            'retired_group_count':len(RETIRED_GROUPS),'native_view_anchors':len(ANCHORS),
            'inspected_processes':inspected,'confirmed_enoent_or_esrch':gone,'members':[],
            'signals_sent':0,'model_requests':0,'task_submissions':0}
def original_source():
    fd=os.open(ORIGINAL,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and before.st_size==15700):
            raise ValueError('original_gate_private_file_identity')
        raw=b''
        while len(raw)<=15700:
            block=os.read(fd,15701-len(raw))
            if not block:break
            raw+=block
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise ValueError('original_gate_changed')
    finally:os.close(fd)
    if len(raw)!=15700 or hashlib.sha256(raw).hexdigest()!=ORIGINAL_SHA:
        raise ValueError('original_gate_pin')
    return raw
def main():
    if sys.argv[1:]!=['--check-and-chain']:
        raise SystemExit('REVIEW_ONLY: explicit --check-and-chain required')
    report=census()
    raw=original_source()
    print(json.dumps(report,separators=(',',':')),flush=True)
    # This is the already reviewed exact original gate, not a new resolver.
    exec(compile(raw,ORIGINAL,'exec'),{'__name__':'__main__','__file__':ORIGINAL})
if __name__=='__main__':
    main()
