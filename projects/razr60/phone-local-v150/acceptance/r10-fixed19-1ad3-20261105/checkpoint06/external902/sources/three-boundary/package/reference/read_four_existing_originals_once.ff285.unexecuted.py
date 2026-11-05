#!/usr/bin/env python3
"""Retain four fixed existing originals; no snapshot/closure/publication is executed."""
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
LABEL='root-r10-neg01-7c907661-01'
NONCE='902e851c3ca1f90deab3d880ab993774'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
DIRECTORIES={}
OUTPUT_LIMIT=8*1024*1024
FIXED_DIRECTORIES=[{'metadata': [65086, 154599, 16832, 0, 0, 3, 3452, 1793882440195914287, 1793882440195914287], 'names': ['CAPTURE.json', 'ORIGINALS.tar.gz', 'RESULT.json', 'snapshot'], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-snapshots-r10-r1/root-r10-neg01-7c907661-01-capture-01'}, {'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774', 'metadata': [65086, 157440, 16832, 0, 0, 2, 3452, 1793882485267914270, 1793882485267914270], 'names': ['AFTER-INVENTORY.original.json', 'CLOSURE.original.json', 'PUBLISH-INTENT.json']}]
FIXED_FILES=[{'name': 'CLOSURE.original.json', 'bytes': 55124, 'metadata': [65086, 156890, 33152, 0, 0, 1, 55124, 1793882485259914270, 1793882485259914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774/CLOSURE.original.json', 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719', 'prior_metadata_bound': True, 'pin_origin': 'actual_6e1d_boundary_descriptor'}, {'name': 'AFTER-INVENTORY.original.json', 'bytes': 923078, 'metadata': [65086, 156601, 33152, 0, 0, 1, 923078, 1793882485267914270, 1793882485267914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774/AFTER-INVENTORY.original.json', 'sha256': 'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d', 'prior_metadata_bound': True, 'pin_origin': 'actual_6e1d_boundary_descriptor'}, {'name': 'PUBLISH-INTENT.json', 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774/PUBLISH-INTENT.json', 'bytes': 742, 'sha256': '3d56ef41cf7d2adf1858466d8d96ec877fb4553fdb97afe5609cc8475bac04a9', 'metadata': None, 'prior_metadata_bound': False, 'pin_origin': 'source_396d_publish_fields_and_1e2d_compact_encoding_of_actual_boundary_and_lease'}, {'name': 'ORIGINALS.tar.gz', 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-snapshots-r10-r1/root-r10-neg01-7c907661-01-capture-01/ORIGINALS.tar.gz', 'bytes': 2204770, 'sha256': '462da4db9b36028cfec2b933f94bd52c185a103e12d1a771d2b67a47a21d9e03', 'metadata': [65086, 153268, 33152, 0, 0, 1, 2204770, 1793882440179914287, 1793882440179914287], 'prior_metadata_bound': True, 'pin_origin': 'actual_45aff_whole_file_hash_and_full9'}]
PUBLISH_EXPECTED=b'{"automatic_retry":false,"closure":{"bytes":55124,"sha256":"ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719"},"inventory":{"bytes":923078,"sha256":"b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d"},"lease_sha256":"31688136fbcb7ae520c096decc11c9c36a67a304172401c3aab6c14e7848c736","maximum_publish_attempts":1,"nonce":"902e851c3ca1f90deab3d880ab993774","schema":"hepta.native-guard.boundary-publish-intent.v1","scope":{"profile_id":"owner-open","session_id":"session-ee897738-8fc2-4d3e-a916-5fe368b340ef","task_id":"task-d3f61033-5b61-40e4-b8c6-7ea00d6b2d56","turn_id":"turn-c2247546-2cb4-4c98-b20f-b4ee06c2f14c","turn_stream_id":"r5-stream-6d465a4b53634e510a9b448f5d53be3ce4115ea2303e9ceeefaccd99bcc04475"}}\n'
ACTUAL_INPUT_REFERENCES={'observation': {'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/existing-capture-read01/originals/PHONE-STDOUT.original', 'bytes': 211933, 'sha256': '6be3fbb0726b450ff98aac38defd38f89fff093bf644da56568688e7d99fc647'}, 'capture': {'path': '/workspace/scratch/1ad3d6f55439/property_diagnostic/external902_existing_capture_parser_candidate01/actual-run01/retained-bodies/capture/CAPTURE.json', 'bytes': 144079, 'sha256': 'b6dffc54291f7a35486cab4b677c5ff5ea3fe4fb4fa2bad4a28d3094ddbca04d'}, 'snapshot_result': {'path': '/workspace/scratch/1ad3d6f55439/property_diagnostic/external902_existing_capture_parser_candidate01/actual-run01/retained-bodies/capture/RESULT.json', 'bytes': 714, 'sha256': 'f67f2365baeaf24ee224caf9d0f53661bbb0faba69d6d219ce94da3877c62f08'}, 'boundary': {'path': '/workspace/scratch/1ad3d6f55439/property_diagnostic/external902_existing_capture_parser_candidate01/actual-run01/retained-bodies/boundary/902e851c3ca1f90deab3d880ab993774.json', 'bytes': 9686, 'sha256': '6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'}, 'publisher_source': {'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/source-binary-read01/late_boundary.original.py', 'bytes': 74287, 'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}, 'common_source': {'path': '/workspace/scratch/1ad3d6f55439/runtime_prefix_successor_candidate01/delivery-final01/package/runtime/source/component_common.py', 'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}}

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


def fixed_original(row):
    need(row in FIXED_FILES and set(row)=={'name','path','bytes','sha256','metadata','prior_metadata_bound','pin_origin'},
         'only four literal existing-file descriptors permitted')
    path=Path(row['path']);parent,leaf=parent_fd(path);fd=None;before=None;parent_before=None
    try:
        parent_before=os.fstat(parent)
        need(metadata(parent_before)==DIRECTORIES[str(path.parent)]['metadata'],
             'original parent differs from fixed observed directory')
        before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==row['bytes'],
             'fixed private regular original length differs')
        if row['prior_metadata_bound']:
            need(row['metadata'] is not None and metadata(before)==row['metadata'],'previous actual full9 differs')
        else:
            need(row['name']=='PUBLISH-INTENT.json' and row['metadata'] is None,
                 'only publish intent may establish its first full9 observation')
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
        need(metadata(os.fstat(fd))==metadata(before),'fixed original changed before open')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(row['bytes']+1)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'fixed original complete bytes/SHA differ')
        if row['name']=='PUBLISH-INTENT.json':need(raw==PUBLISH_EXPECTED,'publisher-defined canonical bytes differ')
        need(metadata(before)==metadata(os.fstat(fd))==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False))
             and metadata(parent_before)==metadata(os.fstat(parent)),'fixed original full9/parent changed during read')
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
    canonical_parent,canonical_leaf=parent_fd(path)
    try:
        need(canonical_leaf==leaf and metadata(os.fstat(canonical_parent))==metadata(parent_before)
             and metadata(os.stat(canonical_leaf,dir_fd=canonical_parent,follow_symlinks=False))==metadata(before),
             'fixed canonical parent or original changed')
    finally:os.close(canonical_parent)
    need(leaf in DIRECTORIES[str(path.parent)]['names'],'fixed original missing from complete directory names')
    return {'name':row['name'],'path':row['path'],'bytes':len(raw),'sha256':sha(raw),'metadata':metadata(before),
        'parent_metadata':metadata(parent_before),'expected_prior_metadata':row['metadata'],
        'prior_metadata_bound':row['prior_metadata_bound'],'pin_origin':row['pin_origin'],
        'whole_file_bytes_retained':True,'encoding':'base64','data_base64':base64.b64encode(raw).decode('ascii')}

def main():
    started=time.monotonic();started_ns=time.time_ns();phase='bootstrap';failure=None;complete=False
    before=None;rows=[];bookends=False;boot_bookend=False;fd_observation=None
    try:
        need(len(sys.argv)==1,'fixed reader accepts no alternate path, nonce, or options')
        need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root required')
        need(len(FIXED_FILES)==4 and len({r['path'] for r in FIXED_FILES})==4
             and sum(r['bytes'] for r in FIXED_FILES)<4*1024*1024,'four originals exact raw budget')
        before=own_fds();boot_raw=boot()
        phase='two_fixed_parent_directories'
        for expected in FIXED_DIRECTORIES:need(read_directory(expected['path'])==expected,'fixed directory full9/names changed')
        phase='closure_inventory_publish_intent_then_archive'
        for expected in FIXED_FILES:rows.append(fixed_original(expected))
        phase='four_whole_file_full9_and_parent_bookends'
        for expected,observed in zip(FIXED_FILES,rows):need(fixed_original(expected)==observed,'whole original changed at final bookend')
        for expected in FIXED_DIRECTORIES:need(read_directory(expected['path'])==expected,'fixed directory changed at final bookend')
        bookends=True;need(boot()==boot_raw,'boot changed');boot_bookend=True;complete=True;phase='complete'
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
                    if failure is None:failure={'type':'ValueError','detail':'owned read descriptors remain','phase':'FD_bookend'}
            except BaseException as exc:
                complete=False;fd_observation={'complete':False,'type':type(exc).__name__,'detail':str(exc)[:1024]}
                if failure is None:failure={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':'FD_bookend'}
    result={'schema':'hepta.native-guard.four-fixed-existing-originals.v1',
        'state':'FOUR_FIXED_EXISTING_ORIGINALS_RETAINED' if complete else 'FIXED_EXISTING_ORIGINALS_FAILED_OR_PARTIAL',
        'observation_complete':complete,'failure':failure,'boot_id':BOOT,'label':LABEL,'nonce':NONCE,
        'files':rows,'directories':list(DIRECTORIES.values()),'all_whole_file_bookends_complete':bookends,
        'boot_bookends_complete':boot_bookend,'owned_read_fd_observation':fd_observation,
        'actual_input_references':ACTUAL_INPUT_REFERENCES,
        'publish_intent_expected_bytes_are_source_derived_not_previously_observed':True,
        'publish_intent_full9_first_observed_here':any(r['name']=='PUBLISH-INTENT.json' for r in rows),
        'observation_started_unix_ns':started_ns,'observation_ended_unix_ns':time.time_ns(),
        'total_wall_seconds':time.monotonic()-started,'output_limit_bytes':OUTPUT_LIMIT,
        'prior_source_or_case_outputs_rewritten':False,'runtime_modules_loaded':0,'runtime_function_calls':0,
        'phone_source_writes':0,'phone_evidence_writes':0,'process_launches':0,'signals':0,
        'kernel_signal_zero_queries':0,'model_requests':0,'native_dispatches':0,'socket_connections':0,
        'snapshot_entry_calls':0,'closure_entry_calls':0,'publication_entry_calls':0,'runtime_cleanup_calls':0,
        'new_case_or_nonce':False,'snapshot_archive_decoded_or_validated':False,'existing_boundary_validated_or_adopted':False,
        'native_boundary_published':False,'component_qualified':False,'case_pass':False,'automatic_retry':False,
        'fresh_later_read_not_original_snapshot_or_publication_time':True}
    try:
        raw=encoded(result);need(len(raw)<=OUTPUT_LIMIT,'full four-original output exceeds eight-MiB bound')
    except BaseException as exc:
        complete=False;raw=encoded({'schema':result['schema'],'state':'COMPLETE_ORIGINAL_SERIALIZATION_REFUSED',
            'observation_complete':False,'complete_originals_retained':False,'type':type(exc).__name__,'detail':str(exc)[:1024],
            'label':LABEL,'nonce':NONCE,'case_pass':False,'automatic_retry':False,'phone_evidence_writes':0})
    sys.stdout.write(raw.decode('utf-8'));return 0 if complete else 1

if __name__=='__main__':raise SystemExit(main())
