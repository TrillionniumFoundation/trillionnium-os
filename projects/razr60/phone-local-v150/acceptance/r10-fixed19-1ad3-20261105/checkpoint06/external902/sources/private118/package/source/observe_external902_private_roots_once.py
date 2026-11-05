#!/usr/bin/env python3
"""One fixed later private-root observation; no runtime, diagnostic command, or cleanup execution."""
import sys
sys.dont_write_bytecode=True
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

ANDROID=Path('/proc/1/root')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
LABEL='root-r10-neg01-7c907661-01'
NONCE='902e851c3ca1f90deab3d880ab993774'
ACTION_ID='5a952602788122f47ff1370cfa38dffe'
HOME=Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1')/LABEL
ANDROID_HOME=Path('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1')/LABEL
JOURNAL=ANDROID_HOME/'executor'
FIXTURE=Path('/proc/1/root/data/local/tmp')/('hepta-native-guard-'+NONCE)
ROOTS=(str(HOME),str(JOURNAL),str(FIXTURE))
ANCHOR_PATHS=(str(HOME.parent),str(ANDROID_HOME.parent),str(ANDROID_HOME),str(FIXTURE.parent))
LEASE_PIN=(2496,'31688136fbcb7ae520c096decc11c9c36a67a304172401c3aab6c14e7848c736')
LEASE_EXPIRES_UNIX_MS=1793879507570
RUNTIME_PIN=(16808,'31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb')
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_ENTRIES=1024
MAX_DIRECTORY_NAMES=512
MAX_RELATIVE_DEPTH=16
MAX_FILE_BYTES=8*1024*1024
MAX_TOTAL_BYTES=16*1024*1024
OUTPUT_LIMIT=8*1024*1024
ENTRIES={}
RAW_FILES={}
READ_BYTES=0
PRIOR_ADDITIONS_OBSERVATION={'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/added-originals-read01/originals/PHONE-STDOUT.original', 'bytes': 290642, 'sha256': 'd7be9355122929210e7c736e5e68a57ac56f84095005e3e201e0c549f0e33f6b'}
EXTERNAL_ROOT_PLAN_REFERENCE={'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/ROOT-PLAN.original.json', 'bytes': 4783, 'sha256': '9a94108ffc737133ba879bd9cccd70c7ec3ae2f3da17eb689e5b1d5610789d58'}
EXTERNAL_PREPARED_REFERENCE={'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/material/PREPARED.json', 'bytes': 2873, 'sha256': 'a8b8b355a9bde5db21123cf503be5f62a24d55226e154ce5ed95a428347d1898'}
ORIGIN_PINS=[{'path': '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/intent.json', 'bytes': 936, 'sha256': '6b03da94090459e47dedc5bb8f27d86429f62e08cd479354266b21855e9d9f2a', 'metadata': [65086, 154878, 33152, 0, 0, 1, 936, 1793879035983915586, 1793879035983915586]}, {'path': '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/receipt.json', 'bytes': 1512, 'sha256': '997f41e4992c2d604e2be2a8c3aaaac9a4f4b94dd0c9304aa4664ae44c79a01a', 'metadata': [65086, 147691, 33152, 0, 0, 1, 1512, 1793879037451915585, 1793879037455915585]}, {'path': '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/stdout.bin', 'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'metadata': [65086, 154328, 33152, 0, 0, 1, 0, 1793879035987915586, 1793879035987915586]}, {'path': '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/stderr.bin', 'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'metadata': [65086, 154570, 33152, 0, 0, 1, 0, 1793879035987915586, 1793879035987915586]}]

def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:
            need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def metadata(s):
    return [getattr(s,k) for k in META]


def parent_fd(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2<=len(path.parts)<=64,'bounded absolute path')
    if path.parts[:4]==('/','proc','1','root'):
        fd=os.open(ANDROID,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[4:]
    else:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[1:]
    need(parts,'original leaf required')
    try:
        for name in parts[:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child
        return fd,parts[-1]
    except BaseException:
        os.close(fd);raise


def boot():
    with open('/proc/sys/kernel/random/boot_id','rb') as stream:raw=stream.read(128)
    need(raw.strip().decode()==BOOT,'actual boot changed');return raw


def own_fds():
    names=os.listdir('/proc/self/fd');need(len(names)<=256,'own FD census bound')
    value={}
    for name in names:
        need(name.isdigit(),'own FD name shape');fd=int(name)
        try:s=os.fstat(fd)
        except OSError as error:
            need(error.errno in (errno.EBADF,errno.ENOENT),'own FD observation unknown');continue
        value[fd]=(s.st_dev,s.st_ino,s.st_mode)
    return value


def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8')

def label_bytes(fd):
    raw=os.getxattr(fd,'security.selinux')
    need(0<len(raw)<=4096,'bounded existing SELinux label required')
    return raw.hex()

def node_scope(path):
    path=Path(path);text=str(path)
    need(path.is_absolute() and '..' not in path.parts and str(Path(text))==text,'canonical fixed-tree path required')
    roots=[Path(root) for root in ROOTS if text==root or text.startswith(root+'/')]
    need(len(roots)==1 and len(path.parts)-len(roots[0].parts)<=MAX_RELATIVE_DEPTH,'within one fixed bounded root required')
    return roots[0],roots[0]==FIXTURE

def observe_node(path):
    """One whole regular file or complete directory row; never follows a link."""
    global READ_BYTES
    path=Path(path);root,fixture=node_scope(path);text=str(path)
    parent,leaf=parent_fd(path);fd=None
    try:
        before_name=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        is_dir=stat.S_ISDIR(before_name.st_mode)
        need(is_dir or stat.S_ISREG(before_name.st_mode),'symlink or special private-tree object refused')
        # NONBLOCK prevents a rename-to-FIFO race from blocking before fstat.
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK|
                   (os.O_DIRECTORY if is_dir else 0),dir_fd=parent)
        before=os.fstat(fd)
        need(metadata(before)==metadata(before_name),'named original changed before open')
        need((stat.S_ISDIR(before.st_mode) if is_dir else stat.S_ISREG(before.st_mode)),
             'opened original type differs')
        owner=2000 if fixture else 0
        modes=(0o700,) if is_dir else ((0o600,0o400) if fixture else (0o600,))
        need(before.st_uid==before.st_gid==owner and stat.S_IMODE(before.st_mode) in modes
             and (is_dir or before.st_nlink==1),'fixed private/fixture ownership or mode differs')
        selinux=label_bytes(fd)
        row={'path':text,'metadata':metadata(before),'selinux_raw_hex':selinux}
        if is_dir:
            names=sorted(os.listdir(fd))
            need(len(names)<=MAX_DIRECTORY_NAMES and len(names)==len(set(names))
                 and all(type(name) is str and name not in ('.','..') and '/' not in name and '\x00' not in name
                         and len(name.encode('utf-8'))<=255 for name in names),'bounded UTF-8 directory names required')
            row.update(kind='directory',names=names);raw=None
        else:
            size=before.st_size
            need(0<=size<=MAX_FILE_BYTES,'bounded whole regular original required')
            if text not in ENTRIES:need(READ_BYTES+size<=MAX_TOTAL_BYTES,'aggregate raw original byte budget')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(size+1)
            need(len(raw)==size,'whole original byte count changed')
            row.update(kind='file',bytes=len(raw),sha256=sha(raw))
        need(metadata(before)==metadata(os.fstat(fd))==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False))
             and label_bytes(fd)==selinux,'full9 or SELinux label changed during read')
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
    fresh_parent,fresh_leaf=parent_fd(path)
    try:
        need(fresh_leaf==leaf and metadata(os.stat(leaf,dir_fd=fresh_parent,follow_symlinks=False))==row['metadata'],
             'canonical named original was replaced')
    finally:os.close(fresh_parent)
    if text in ENTRIES:
        need(ENTRIES[text]==row,'fixed-root original changed across bookends')
        if raw is not None:need(RAW_FILES[text]==raw,'whole original bytes changed across bookends')
    else:
        need(len(ENTRIES)<MAX_ENTRIES,'complete fixed-root entry bound')
        ENTRIES[text]=row
        if raw is not None:READ_BYTES+=len(raw);RAW_FILES[text]=raw
    return row

def observe_anchor(path):
    """Fixed ancestor metadata only: never lists sibling case names."""
    need(path in ANCHOR_PATHS,'only fixed ancestors may be observed')
    parent,leaf=parent_fd(path);fd=None
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        s=os.fstat(fd);context=label_bytes(fd)
        need(stat.S_ISDIR(s.st_mode),'fixed ancestor directory required')
        if path!=str(FIXTURE.parent):
            need(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'private ancestor ownership/mode')
        need(metadata(s)==metadata(os.fstat(fd))==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False))
             and context==label_bytes(fd),'ancestor full9/label changed')
        row={'path':path,'metadata':metadata(s),'selinux_raw_hex':context,'children_listed':False}
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
    fresh_parent,fresh_leaf=parent_fd(path)
    try:
        need(fresh_leaf==leaf and metadata(os.stat(leaf,dir_fd=fresh_parent,follow_symlinks=False))==row['metadata'],
             'fixed canonical ancestor replaced')
    finally:os.close(fresh_parent)
    return row

def fixture_absence():
    parent,leaf=parent_fd(FIXTURE)
    try:
        before=os.fstat(parent);context=label_bytes(parent)
        for _ in range(2):
            try:os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'exact fixture ENOENT required')
            else:raise ValueError('fixed fixture appeared during absence observation')
        need(metadata(before)==metadata(os.fstat(parent)) and context==label_bytes(parent),
             'fixture absence ancestor changed')
        row={'path':str(FIXTURE),'kind':'absent','absence':'ENOENT','parent_metadata':metadata(before),
             'parent_selinux_raw_hex':context}
    finally:os.close(parent)
    fresh_parent,fresh_leaf=parent_fd(FIXTURE)
    try:
        need(fresh_leaf==leaf and metadata(os.fstat(fresh_parent))==row['parent_metadata']
             and label_bytes(fresh_parent)==row['parent_selinux_raw_hex'],'fixture canonical ancestor replaced')
        try:os.stat(fresh_leaf,dir_fd=fresh_parent,follow_symlinks=False)
        except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'canonical fixture absence unknown')
        else:raise ValueError('fixed fixture canonical leaf appeared')
    finally:os.close(fresh_parent)
    if str(FIXTURE) in ENTRIES:need(ENTRIES[str(FIXTURE)]==row,'fixture absence changed across bookends')
    else:
        need(len(ENTRIES)<MAX_ENTRIES,'fixture entry bound');ENTRIES[str(FIXTURE)]=row
    return row

def walk_fixed_root(root):
    need(root in ROOTS,'only three fixed observation roots')
    if root==str(FIXTURE):
        parent,leaf=parent_fd(root)
        try:
            try:os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError as exc:
                need(exc.errno==errno.ENOENT,'fixture existence unknown');missing=True
            else:missing=False
        finally:os.close(parent)
        if missing:return fixture_absence()
    first=observe_node(root)
    need(first['kind']=='directory','existing fixed root must be a directory')
    stack=[str(Path(root)/name) for name in reversed(first['names'])]
    while stack:
        path=stack.pop();row=observe_node(path)
        if row['kind']=='directory':stack.extend(str(Path(path)/name) for name in reversed(row['names']))
    return first

def validate_retained_bindings():
    """Only byte/link checks on already retained originals; never imports runtime code."""
    lease_raw=RAW_FILES[str(HOME/'LEASE.json')]
    need((len(lease_raw),sha(lease_raw))==LEASE_PIN,'fixed actual lease bytes differ')
    lease=strict(lease_raw.decode('utf-8'))
    need(lease['schema']=='hepta.native-guard.lease.v1' and lease['label']==LABEL and lease['nonce']==NONCE
         and lease['boot_id']==BOOT and lease['case_id']=='NEG-01'
         and lease['android_journal']==str(Path(str(JOURNAL)[len('/proc/1/root'):]))
         and lease['package_sha256']==RUNTIME_PIN[1] and lease['expires_unix_ms']==LEASE_EXPIRES_UNIX_MS,
         'fixed existing lease identities differ; no lease extension')
    mf_raw=RAW_FILES[str(HOME/'package/MANIFEST.json')]
    need((len(mf_raw),sha(mf_raw))==RUNTIME_PIN,'exact staged actual31da runtime manifest differs')
    manifest=strict(mf_raw.decode('utf-8'));rows=manifest['files']
    need(manifest['schema']=='hepta.native-guard.adapter-package.v1'
         and manifest['state']=='HOST_REVIEWED_NOT_PHONE_QUALIFIED'
         and type(rows) is list and len(rows)==32,'fixed current runtime32 manifest shape')
    files=set();dirs={'.'}
    for row in rows:
        need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact runtime member descriptor')
        name=row['path'];rel=Path(name)
        need(type(name) is str and str(rel)==name and not rel.is_absolute() and '..' not in rel.parts
             and name not in files and type(row['bytes']) is int and 0<row['bytes']<=MAX_FILE_BYTES,
             'bounded unique runtime member')
        raw=RAW_FILES[str(HOME/'package'/rel)]
        need((len(raw),sha(raw))==(row['bytes'],row['sha256']),'staged runtime source differs')
        files.add(name);dirs.update(str(p) for p in rel.parents)
    package_root=str(HOME/'package')
    observed_files={str(Path(path).relative_to(package_root)) for path,row in ENTRIES.items()
                    if path.startswith(package_root+'/') and row['kind']=='file'}
    observed_dirs={str(Path(path).relative_to(package_root)) for path,row in ENTRIES.items()
                   if (path==package_root or path.startswith(package_root+'/')) and row['kind']=='directory'}
    need(observed_files==files|{'MANIFEST.json'} and observed_dirs==dirs,'complete runtime package member set differs')
    owner=RAW_FILES[str(HOME/'owner-request.txt')]
    need(sha(owner)==lease['owner_request_sha256'] and owner.decode('utf-8').count(NONCE)==1,
         'fixed lease owner request original differs')
    for pin in ORIGIN_PINS:
        row=ENTRIES[pin['path']]
        need(row['kind']=='file' and (row['bytes'],row['sha256'],row['metadata'])
             ==(pin['bytes'],pin['sha256'],pin['metadata']),'actual capture-origin executor original changed')
    return {'fixed_lease_bytes_and_identity_verified':True,'runtime_manifest_and_all_32_source_bytes_verified':True,
            'capture_origin_four_executor_full9_pins_verified':True,
            'expired_lease_observation_only':int(time.time()*1000)>lease['expires_unix_ms'],
            'lease_not_required_to_be_live':True,'runtime_executed':False}

def verify_aliases(anchors):
    anchor={row['path']:row for row in anchors}
    for left,right in ((str(HOME.parent),str(ANDROID_HOME.parent)),(str(HOME),str(ANDROID_HOME))):
        a=ENTRIES[left] if left in ENTRIES else anchor[left]
        b=ENTRIES[right] if right in ENTRIES else anchor[right]
        need((a['metadata'],a['selinux_raw_hex'])==(b['metadata'],b['selinux_raw_hex']),
             'GNU/Android fixed home or parent alias differs')
    gnu=str(HOME/'executor');android=str(JOURNAL)
    left={path[len(gnu):]:{k:v for k,v in row.items() if k!='path'}
          for path,row in ENTRIES.items() if path==gnu or path.startswith(gnu+'/')}
    right={path[len(android):]:{k:v for k,v in row.items() if k!='path'}
           for path,row in ENTRIES.items() if path==android or path.startswith(android+'/')}
    need(left and left==right,'complete GNU/Android executor alias rows differ')
    for relative,row in left.items():
        if row['kind']=='file':need(RAW_FILES[gnu+relative]==RAW_FILES[android+relative],'executor alias bytes differ')
    return {'home_and_parent_full9_selinux_equal':True,'executor_alias_rows':len(left),
            'executor_all_relative_names_full9_selinux_bytes_equal':True,'aliases_are_not_independent_physical_trees':True}

def main():
    started=time.monotonic();started_ns=time.time_ns();phase='bootstrap';failure=None;complete=False
    anchors=[];bindings=None;aliases=None;before=None;fd_observation=None;bookends=False;boot_bookends=False
    try:
        need(len(sys.argv)==1,'fixed one-case observation accepts no alternate inputs')
        need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root credentials required')
        before=own_fds();boot_raw=boot()
        need((os.stat(ANDROID).st_dev,os.stat(ANDROID).st_ino)!=(os.stat('/').st_dev,os.stat('/').st_ino),
             'GNU and explicit Android root anchor must differ')
        phase='fixed_ancestor_metadata_only'
        anchors=[observe_anchor(path) for path in ANCHOR_PATHS]
        phase='three_fixed_root_views'
        for root in ROOTS:walk_fixed_root(root)
        phase='exact_existing_lease_runtime_and_origin_bindings'
        bindings=validate_retained_bindings();aliases=verify_aliases(anchors)
        phase='whole_tree_full9_label_content_bookends'
        for path,row in list(ENTRIES.items()):
            if row['kind']=='absent':fixture_absence()
            else:observe_node(path)
        for row in anchors:need(observe_anchor(row['path'])==row,'fixed ancestor changed at end')
        bookends=True
        need(boot()==boot_raw,'boot changed across fixed private observation');boot_bookends=True
        complete=True;phase='complete'
    except BaseException as exc:
        failure={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':phase}
    finally:
        if before is not None:
            try:
                after=own_fds();remaining=[{'fd':fd,'identity':list(identity)} for fd,identity in after.items()
                                          if fd>=3 and before.get(fd)!=identity]
                fd_observation={'complete':not remaining,'new_read_FDs_remaining':remaining,
                                'closed_unknown_or_foreign_FDs':False}
                if remaining:
                    complete=False
                    if failure is None:failure={'type':'ValueError','detail':'new read FD remains','phase':'FD_bookend'}
            except BaseException as exc:
                complete=False;fd_observation={'complete':False,'type':type(exc).__name__,'detail':str(exc)[:1024]}
                if failure is None:failure={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':'FD_bookend'}
    originals=[{**ENTRIES[path],'encoding':'base64','data_base64':base64.b64encode(raw).decode('ascii')}
               for path,raw in RAW_FILES.items()]
    result={'schema':'hepta.native-guard.fixed-external-private-roots-observation.v1',
        'state':'FIXED_PRIVATE_ROOTS_ORIGINALS_RETAINED' if complete else 'FIXED_PRIVATE_ROOTS_FAILED_OR_PARTIAL_RETAIN_ORIGINALS',
        'observation_complete':complete,'failure':failure,'label':LABEL,'nonce':NONCE,'boot_id':BOOT,
        'roots':list(ROOTS),'fixed_ancestor_metadata_only':anchors,'entries':list(ENTRIES.values()),
        'file_originals':originals,'file_count':len(RAW_FILES),'raw_file_bytes':READ_BYTES,
        'existing_original_bindings':bindings,'alias_checks':aliases,'read_bookends_complete':bookends,
        'boot_bookends_complete':boot_bookends,'owned_read_fd_observation':fd_observation,
        'prior_additions_observation_reference':PRIOR_ADDITIONS_OBSERVATION,
        'root_plan_reference':EXTERNAL_ROOT_PLAN_REFERENCE,'prepared_reference':EXTERNAL_PREPARED_REFERENCE,
        'observation_started_unix_ns':started_ns,'observation_ended_unix_ns':time.time_ns(),
        'total_wall_seconds':time.monotonic()-started,
        'budgets':{'entries':MAX_ENTRIES,'directory_names':MAX_DIRECTORY_NAMES,'relative_depth':MAX_RELATIVE_DEPTH,
                   'file_bytes':MAX_FILE_BYTES,'total_raw_bytes':MAX_TOTAL_BYTES,'output_bytes':OUTPUT_LIMIT},
        'fresh_later_observation_not_original_failure_snapshot':True,'process_absence_proof':False,
        'fixture_absence_is_observation_only':True,'native_boundary_qualified_or_adopted':False,
        'global_clearance_proof':False,'admission_granted':False,'component_qualified':False,
        'runtime_modules_loaded':0,'runtime_function_calls':0,'new_model_or_native_diagnostic_commands':0,
        'process_launches':0,'signals':0,'locks_acquired':0,'runtime_close_calls':0,'runtime_cleanup_calls':0,
        'phone_case_or_source_writes':0,'lease_changes':0,'new_nonces':0,'automatic_retry':False}
    try:
        raw=encoded(result);need(len(raw)<=OUTPUT_LIMIT,'complete private original collection exceeds eight-MiB output bound')
    except BaseException as exc:
        complete=False
        raw=encoded({'schema':result['schema'],'state':'COMPLETE_PRIVATE_ORIGINAL_SERIALIZATION_REFUSED',
            'observation_complete':False,'full_originals_retained':False,'type':type(exc).__name__,'detail':str(exc)[:1024],
            'label':LABEL,'nonce':NONCE,'global_clearance_proof':False,'admission_granted':False,
            'component_qualified':False,'native_boundary_qualified_or_adopted':False,'automatic_retry':False,
            'phone_case_or_source_writes':0})
    sys.stdout.write(raw.decode('utf-8'))
    return 0 if complete else 1

if __name__=='__main__':raise SystemExit(main())
