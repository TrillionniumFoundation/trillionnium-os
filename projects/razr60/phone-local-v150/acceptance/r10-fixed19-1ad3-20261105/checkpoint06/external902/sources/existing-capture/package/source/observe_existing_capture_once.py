#!/usr/bin/env python3
"""Only observe existing capture01 fixed leaves and the two fixed902 boundary leaves."""
import sys
sys.dont_write_bytecode=True
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import time

ANDROID=Path('/proc/1/root')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
EXTERNAL_LABEL='root-r10-neg01-7c907661-01'
EXTERNAL_NONCE='902e851c3ca1f90deab3d880ab993774'
CAPTURE_ROOT=BASE/'native-guard-snapshots-r10-r1'/(EXTERNAL_LABEL+'-capture-01')
BOUNDARY_PARENT=BASE/'native-guard-boundaries-r10-r1'
BOUNDARY_PATHS=(str(BOUNDARY_PARENT/(EXTERNAL_NONCE+'.json')),str(BOUNDARY_PARENT/EXTERNAL_NONCE))
BOUNDARY_FILE_LIMIT=1024*1024
OUTPUT_LIMIT=8*1024*1024
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
READSET={}
DIRECTORIES={}
READ_BYTES=0
# Ordered: the small native RESULT is retained before other leaves are touched.
LEAF_RULES=(('RESULT.json',65536,65536,True),
            ('CAPTURE.json',16*1024*1024,1024*1024,False),
            ('PARTIAL-CAPTURE.json',2*1024*1024,2*1024*1024,True),
            ('ORIGINALS.tar.gz',64*1024*1024,0,False))
FAILED_SNAPSHOT_ORIGINAL_REFERENCE={'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/snapshot01/originals/phone-result.json.original', 'bytes': 2481, 'sha256': 'ec47f2a86488391201c86b3880bd8c0d7c24cdbed94eb95e658474d25c5935e8'}

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


def read_original(path,maximum=16*1024*1024,expected=None,expected_metadata=None):
    global READ_BYTES
    path=Path(path);parent,leaf=parent_fd(path)
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=maximum,
                 'bounded private original shape')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
            named=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            need(len(raw)==before.st_size and metadata(before)==metadata(os.fstat(fd))==metadata(named),
                 'original full9 read changed')
        finally:os.close(fd)
    finally:os.close(parent)
    row={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'metadata':metadata(before)}
    if expected is not None:need((len(raw),row['sha256'])==expected,'exact original pin differs')
    if expected_metadata is not None:need(row['metadata']==expected_metadata,'fixed original metadata differs')
    if str(path) in READSET:need(row==READSET[str(path)],'bootstrap original changed across verification')
    else:
        READ_BYTES+=len(raw);need(READ_BYTES<=16*1024*1024,'bootstrap original readset bound')
        READSET[str(path)]=row
    return raw


def read_directory(path):
    path=Path(path);parent,leaf=parent_fd(path)
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd);names=sorted(os.listdir(fd))
            need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o700 and len(names)<=128,'private bounded source directory')
            need(metadata(before)==metadata(os.fstat(fd))==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                 'source directory changed')
        finally:os.close(fd)
    finally:os.close(parent)
    row={'path':str(path),'metadata':metadata(before),'names':names}
    if str(path) in DIRECTORIES:need(row==DIRECTORIES[str(path)],'source directory changed across verification')
    else:DIRECTORIES[str(path)]=row
    return row


def boot():
    with open('/proc/sys/kernel/random/boot_id','rb') as stream:raw=stream.read(128)
    need(raw.strip().decode()==BOOT,'actual boot changed');return raw


def recheck_bootstrap():
    for row in list(READSET.values()):
        read_original(row['path'],max(1,row['bytes']),(row['bytes'],row['sha256']),row['metadata'])
    for row in list(DIRECTORIES.values()):read_directory(row['path'])


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


def fixed_boundary_observation(path,expected_kind):
    need((path,expected_kind) in ((BOUNDARY_PATHS[0],'file'),(BOUNDARY_PATHS[1],'directory')),
         'only two fixed native boundary leaves may be observed')
    parent,leaf=parent_fd(path)
    parent_before=None;leaf_before=None;absent=False
    try:
        parent_before=os.fstat(parent)
        need(stat.S_ISDIR(parent_before.st_mode) and parent_before.st_uid==parent_before.st_gid==0
             and stat.S_IMODE(parent_before.st_mode)==0o700,'private existing fixed boundary parent required')
        try:leaf_before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError as exc:
            need(exc.errno==errno.ENOENT,'exact boundary leaf ENOENT required');absent=True
        if absent:
            result={'path':path,'state':'ENOENT','leaf_errno':errno.ENOENT,'parent_metadata':metadata(parent_before)}
        elif expected_kind=='file':
            need(stat.S_ISREG(leaf_before.st_mode),'fixed boundary JSON is not a regular file')
            raw=read_original(path,BOUNDARY_FILE_LIMIT,expected_metadata=metadata(leaf_before))
            result={'path':path,'state':'REGULAR_ORIGINAL_RETAINED','kind':'file',**READSET[path],
                    'encoding':'base64','data_base64':base64.b64encode(raw).decode('ascii'),
                    'parent_metadata':metadata(parent_before)}
        else:
            need(stat.S_ISDIR(leaf_before.st_mode),'fixed boundary original directory is not a directory')
            row=read_directory(path)
            need(row['metadata']==metadata(leaf_before),'fixed boundary directory identity changed')
            result={'state':'DIRECTORY_NAMES_OBSERVED_NO_CHILD_READS','kind':'directory',**row,
                    'parent_metadata':metadata(parent_before)}
        need(metadata(parent_before)==metadata(os.fstat(parent)),'fixed boundary parent changed during read')
        if absent:
            try:os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'boundary leaf absence unknown')
            else:raise ValueError('fixed boundary leaf appeared during observation')
        else:
            need(metadata(leaf_before)==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                 'fixed boundary leaf changed during observation')
    finally:os.close(parent)
    fresh_parent,fresh_leaf=parent_fd(path)
    try:
        need(fresh_leaf==leaf and metadata(os.fstat(fresh_parent))==metadata(parent_before),
             'fixed boundary canonical parent changed')
        if absent:
            try:os.stat(fresh_leaf,dir_fd=fresh_parent,follow_symlinks=False)
            except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'canonical boundary leaf absence unknown')
            else:raise ValueError('fixed boundary canonical leaf appeared')
        else:
            need(metadata(os.stat(fresh_leaf,dir_fd=fresh_parent,follow_symlinks=False))==metadata(leaf_before),
                 'fixed boundary canonical leaf changed')
    finally:os.close(fresh_parent)
    return result


def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8')

def observe_capture_leaf(rule):
    need(rule in LEAF_RULES and len(rule)==4,'only four fixed native capture leaves')
    name,maximum,retain_limit,body_required=rule
    path=CAPTURE_ROOT/name
    parent,leaf=parent_fd(path);fd=None
    before=None;parent_before=None;absent=False
    try:
        parent_before=os.fstat(parent)
        need(metadata(parent_before)==DIRECTORIES[str(CAPTURE_ROOT)]['metadata'],
             'fixed capture parent differs from initial directory')
        try:before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError as exc:
            need(exc.errno==errno.ENOENT,'exact capture leaf absence required');absent=True
        if absent:
            result={'path':str(path),'state':'ENOENT','leaf_errno':errno.ENOENT,
                    'parent_metadata':metadata(parent_before),'whole_bytes_retained':False,
                    'whole_file_hash_computed':False}
        else:
            need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
                 and 0<=before.st_size<=maximum,'bounded private regular native capture original required')
            retain=retain_limit>0 and before.st_size<=retain_limit
            need(not body_required or retain,'this native JSON leaf requires its complete bounded body')
            fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
            need(metadata(os.fstat(fd))==metadata(before),'capture leaf changed before open')
            digest=hashlib.sha256();count=0;pieces=[]
            with os.fdopen(fd,'rb',closefd=False) as stream:
                while count<before.st_size:
                    chunk=stream.read(min(1024*1024,before.st_size-count))
                    need(chunk,'capture original shortened during whole-file hash')
                    digest.update(chunk);count+=len(chunk)
                    if retain:pieces.append(chunk)
                need(stream.read(1)==b'','capture original grew during whole-file hash')
            need(count==before.st_size and metadata(before)==metadata(os.fstat(fd))
                 ==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                 'native capture original full9 changed during whole read')
            result={'path':str(path),'state':'REGULAR_ORIGINAL_OBSERVED','kind':'file',
                    'bytes':count,'sha256':digest.hexdigest(),'metadata':metadata(before),
                    'parent_metadata':metadata(parent_before),'whole_file_hash_computed':True,
                    'whole_bytes_retained':retain,'body_retention_limit_bytes':retain_limit}
            if retain:
                raw=b''.join(pieces);need(len(raw)==count and sha(raw)==result['sha256'],'retained body differs from whole-file hash')
                result.update(encoding='base64',data_base64=base64.b64encode(raw).decode('ascii'))
            else:
                result['body_omission_reason']='fixed_archive_descriptor_only' if name=='ORIGINALS.tar.gz' else 'CAPTURE_json_exceeds_fixed_one_MiB_body_limit'
        need(metadata(parent_before)==metadata(os.fstat(parent)),'capture parent changed during fixed leaf read')
        if absent:
            try:os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'capture leaf absence unknown')
            else:raise ValueError('native capture leaf appeared during observation')
        else:
            need(metadata(before)==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                 'native capture leaf changed after read')
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
    canonical_parent,canonical_leaf=parent_fd(path)
    try:
        need(canonical_leaf==leaf and metadata(os.fstat(canonical_parent))==metadata(parent_before),
             'fixed capture canonical parent replaced')
        if absent:
            try:os.stat(leaf,dir_fd=canonical_parent,follow_symlinks=False)
            except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'canonical capture absence unknown')
            else:raise ValueError('fixed capture canonical leaf appeared')
        else:
            need(metadata(os.stat(leaf,dir_fd=canonical_parent,follow_symlinks=False))==metadata(before),
                 'fixed capture canonical leaf replaced')
    finally:os.close(canonical_parent)
    need((name in DIRECTORIES[str(CAPTURE_ROOT)]['names'])==(not absent),
         'fixed capture leaf existence differs from complete initial names')
    return result

def main():
    started=time.monotonic();started_ns=time.time_ns();phase='bootstrap';error=None;complete=False
    directory=None;leaves=[];boundaries=[];before=None;fd_observation=None;bookends=False;boot_bookends=False
    try:
        need(len(sys.argv)==1,'fixed existing-output observer accepts no alternate inputs')
        need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root credentials required')
        before=own_fds();boot_raw=boot()
        phase='existing_capture_directory_names_full9'
        directory=read_directory(CAPTURE_ROOT)
        phase='four_exact_capture_leaves_RESULT_first'
        for rule in LEAF_RULES:leaves.append(observe_capture_leaf(rule))
        phase='two_exact902_boundary_leaves'
        for path,kind in zip(BOUNDARY_PATHS,('file','directory')):
            boundaries.append(fixed_boundary_observation(path,kind))
        phase='whole_file_and_directory_bookends'
        for rule,observed in zip(LEAF_RULES,leaves):
            need(observe_capture_leaf(rule)==observed,'existing capture original changed at final whole-file bookend')
        recheck_bootstrap()
        for row,kind in zip(boundaries,('file','directory')):
            need(fixed_boundary_observation(row['path'],kind)==row,'fixed boundary changed at final bookend')
        bookends=True
        need(boot()==boot_raw,'boot changed across fixed existing-output observation');boot_bookends=True
        complete=True;phase='complete'
    except BaseException as exc:
        error={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':phase}
    finally:
        if before is not None:
            try:
                after=own_fds();remaining=[{'fd':fd,'identity':list(identity)} for fd,identity in after.items()
                                          if fd>=3 and before.get(fd)!=identity]
                fd_observation={'complete':not remaining,'new_read_FDs_remaining':remaining,
                                'closed_unknown_or_foreign_FDs':False}
                if remaining:
                    complete=False
                    if error is None:error={'type':'ValueError','detail':'new read FDs remain','phase':'FD_bookend'}
            except BaseException as exc:
                complete=False;fd_observation={'complete':False,'type':type(exc).__name__,'detail':str(exc)[:1024]}
                if error is None:error={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':'FD_bookend'}
    result={'schema':'hepta.native-guard.existing-capture-and-boundary-observation.v1',
        'state':'EXISTING_FIXED_OUTPUTS_OBSERVED' if complete else 'EXISTING_FIXED_OUTPUT_OBSERVATION_FAILED_OR_PARTIAL',
        'observation_complete':complete,'failure':error,'boot_id':BOOT,'label':EXTERNAL_LABEL,'nonce':EXTERNAL_NONCE,
        'capture_directory':directory,'capture_leaves':leaves,'boundary_observations':boundaries,
        'all_directory_rows':list(DIRECTORIES.values()),'boundary_original_descriptors':list(READSET.values()),
        'whole_hash_and_directory_bookends_complete':bookends,'boot_bookends_complete':boot_bookends,
        'owned_read_fd_observation':fd_observation,'failed_snapshot_original_reference':FAILED_SNAPSHOT_ORIGINAL_REFERENCE,
        'observation_started_unix_ns':started_ns,'observation_ended_unix_ns':time.time_ns(),
        'total_wall_seconds':time.monotonic()-started,'output_limit_bytes':OUTPUT_LIMIT,
        'result_read_first':True,'capture_snapshot_subtree_traversed':False,'archive_body_retained':False,
        'existing_capture_contents_validated_or_adopted':False,'boundary_validated_or_adopted':False,
        'fresh_later_observation_not_existing_snapshot_creation_time':True,
        'snapshot_entry_rerun':False,'capture_suffix_changed':False,'new_case_or_nonce':False,
        'phone_case_or_source_writes':0,'phone_evidence_writes':0,'runtime_modules_loaded':0,
        'runtime_function_calls':0,'process_launches':0,'signals':0,'kernel_signal_zero_queries':0,
        'model_requests':0,'native_dispatches':0,'socket_connections':0,'runtime_cleanup_calls':0,
        'boundary_publications':0,'global_clearance_proof':False,'component_qualified':False,'automatic_retry':False}
    try:
        raw=encoded(result);need(len(raw)<=OUTPUT_LIMIT,'complete existing-output observation exceeds eight-MiB stdout bound')
    except BaseException as exc:
        complete=False
        raw=encoded({'schema':result['schema'],'state':'COMPLETE_OBSERVATION_SERIALIZATION_REFUSED',
            'observation_complete':False,'complete_originals_retained':False,'type':type(exc).__name__,'detail':str(exc)[:1024],
            'label':EXTERNAL_LABEL,'nonce':EXTERNAL_NONCE,'existing_capture_contents_validated_or_adopted':False,
            'boundary_validated_or_adopted':False,'component_qualified':False,'automatic_retry':False,'phone_evidence_writes':0})
    sys.stdout.write(raw.decode('utf-8'))
    return 0 if complete else 1

if __name__=='__main__':raise SystemExit(main())
