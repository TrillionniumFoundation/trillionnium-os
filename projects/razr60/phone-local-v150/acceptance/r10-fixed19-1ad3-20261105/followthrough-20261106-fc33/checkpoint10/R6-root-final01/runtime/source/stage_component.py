#!/usr/bin/env python3
"""Root-only, create-only staging of reviewed component inputs; no role launch.

The archive and this program are transported separately by the existing Root
transport. All archive members are preflighted in memory before the first
destination is created. A failed stage is preserved and never retried in place.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import types
import zlib


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        out={}
        for key,value in items:
            need(key not in out,'duplicate JSON key');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))


def archive_members(raw):
    need(0<len(raw)<=8*1024*1024,'compressed archive size bound')
    decoder=zlib.decompressobj(31);plain=decoder.decompress(raw,16*1024*1024+1)
    need(len(plain)<=16*1024*1024 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
         'gzip archive is oversized, incomplete or concatenated')
    files={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for row in archive:
            p=Path(row.name)
            need(len(files)<80 and str(p)==row.name and not p.is_absolute() and '..' not in p.parts
                 and '\0' not in row.name and '\\' not in row.name and row.name not in files
                 and row.isreg() and not row.pax_headers and row.uid==row.gid==0 and row.mode==0o600
                 and row.mtime==0 and 0<=row.size<=8*1024*1024,'archive member type/path/metadata/size bound')
            source=archive.extractfile(row);need(source is not None,'archive original absent')
            data=source.read(row.size+1);need(len(data)==row.size,'archive member incomplete')
            files[row.name]=data
    need(sum(map(len,files.values()))<=8*1024*1024,'archive content byte bound')
    canonical=io.BytesIO()
    with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,data in sorted(files.items()):
            row=tarfile.TarInfo(name);row.mode=0o600;row.uid=row.gid=0;row.mtime=0;row.size=len(data)
            archive.addfile(row,io.BytesIO(data))
    need(plain==canonical.getvalue(),'noncanonical tar metadata/order/trailing content')
    return files


def validate_archive(files, lease_sha, package_sha):
    for key in ('LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json',
                'package/source/component_common.py','package/source/component_lifecycle.py'):
        need(key in files,'required archive member absent')
    lease_raw=files['LEASE.json'];need(sha(lease_raw)==lease_sha,'Root lease byte pin differs')
    lease=strict(lease_raw)
    need(lease.get('schema')=='hepta.native-guard.lease.v1' and lease.get('package_sha256')==package_sha,
         'explicit component lease required')
    label=lease.get('label','');need(re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',label),'new component label required')
    manifest_raw=files['package/MANIFEST.json'];need(sha(manifest_raw)==package_sha,'Root adapter package pin differs')
    manifest=strict(manifest_raw)
    need(manifest.get('schema')=='hepta.native-guard.adapter-package.v1'
         and manifest.get('state')=='HOST_REVIEWED_NOT_PHONE_QUALIFIED','reviewed adapter package required')
    rows=manifest['files'];need(len(rows)==38 and len({r['path'] for r in rows})==len(rows),'package inventory bound')
    expected={'package/MANIFEST.json','LEASE.json','owner-request.txt','sender-contract.json',
        'inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json',
        'inputs/service-inputs.original.json'}
    need('prior_boundary' in lease,'explicit first/later component boundary selection required')
    if lease['prior_boundary'] is not None:
        expected.add('inputs/PRIOR-BOUNDARY.original.json')
        data=files['inputs/PRIOR-BOUNDARY.original.json'];prior=lease['prior_boundary']
        need(len(data)==prior['bytes'] and sha(data)==prior['sha256'],'prior-boundary archived original differs')
    for row in rows:
        name='package/'+row['path'];need(name in files and Path(row['path']).parts[0] in ('source','reference','tests','validation'),
                                      'approved package-relative namespace required')
        need(len(files[name])==row['bytes'] and sha(files[name])==row['sha256'],'package archive byte pin differs')
        expected.add(name)
    reviewed=strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(reviewed)==15,'exact reviewed production set required')
    for name,h in reviewed.items():
        need(re.fullmatch(r'[a-z_]+\.py',name),'production filename bound')
        path='inputs/production/'+name;expected.add(path)
        need(path in files and sha(files[path])==h,'production source archive differs')
    need(set(files)==expected,'unreviewed or missing archive members')
    need(len(files['inputs/COMBINATION.json'])==lease['combination']['bytes']
         and sha(files['inputs/COMBINATION.json'])==lease['combination']['sha256'], 'combination input pin differs')
    owner=files['owner-request.txt']
    need(20<=len(owner)<=16000 and sha(owner)==lease['owner_request_sha256'] and b'\0' not in owner
         and owner.decode().count(lease['nonce'])==1,'exact Root owner request differs')
    return lease,manifest


def modules_from_reviewed(files, home):
    C=types.ModuleType('component_common');C.__file__=str(home/'package/source/component_common.py')
    sys.modules['component_common']=C
    exec(compile(files['package/source/component_common.py'],C.__file__,'exec'),C.__dict__)
    source='package/source/native_proc_profile.py'
    need(source in files,'reviewed platform proc profile absent')
    P=types.ModuleType('native_proc_profile');P.__file__=str(home/source)
    sys.modules['native_proc_profile']=P
    exec(compile(files[source],P.__file__,'exec'),P.__dict__)
    source='package/source/late_boundary.py'
    need(source in files,'reviewed later-boundary verifier absent')
    V=types.ModuleType('late_boundary');V.__file__=str(home/source)
    V.__reviewed_source_sha256__=sha(files[source]);sys.modules['late_boundary']=V
    V.__reviewed_package_sources__={name[len('package/'):]:raw for name,raw in files.items()
                                    if name.startswith('package/') and name!='package/MANIFEST.json'}
    exec(compile(files[source],V.__file__,'exec'),V.__dict__)
    L=types.ModuleType('component_lifecycle');L.__file__=str(home/'package/source/component_lifecycle.py')
    sys.modules['component_lifecycle']=L
    exec(compile(files['package/source/component_lifecycle.py'],L.__file__,'exec'),L.__dict__)
    if strict(files['LEASE.json'])['prior_boundary'] is not None:
        source='package/source/component_snapshot.py'
        need(source in files,'reviewed original snapshot/proc observer absent')
        S=types.ModuleType('component_snapshot');S.__file__=str(home/source)
        sys.modules['component_snapshot']=S
        exec(compile(files[source],S.__file__,'exec'),S.__dict__)
        original=L.verify_retired
        L.verify_retired=lambda lease:original(lease,late_boundary_module=V)
    return C,L


def ensure_new_or_exact_directory(C, path, *, selinux=None, created=None):
    path=Path(path);parent,name=C.parent_fd(path)
    new=False
    try:
        try:os.mkdir(name,mode=0o700,dir_fd=parent);new=True;os.fsync(parent)
        except FileExistsError:pass
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            s=os.fstat(fd)
            need(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'private directory ownership/mode differs')
            if selinux is not None:
                if new:os.setxattr(fd,'security.selinux',selinux.encode()+b'\0')
                need(os.getxattr(fd,'security.selinux').rstrip(b'\0').decode()==selinux,'new journal directory label differs')
            if new and created is not None:created.append({'path':str(path),'metadata':C.metadata(os.fstat(fd)),
                                                        'selinux':selinux})
        finally:os.close(fd)
    finally:os.close(parent)
    return new


SHARED_STATE_LABEL = 'u:object_r:trillionnium_owner_open_state_file:s0'


def create_isolated_journal(C, home, lease, created):
    """Only the new executor leaf is relabeled; both shared views stay pinned."""
    home=Path(home);label=lease['label']
    need(isinstance(label,str) and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',label),
         'bounded component label required before journal creation')
    need(home==C.BASE/'native-guard-r10-r1'/label
         and lease['android_journal']==str(C.ANDROID_BASE/'native-guard-r10-r1'/label/'executor'),
         'exact isolated executor journal path required')
    journal=C.ANDROID/lease['android_journal'].lstrip('/')
    views=((home.parent,journal.parent.parent),(home,journal.parent))
    handles=[];pairs=[];leaf_fd=None
    wanted=SHARED_STATE_LABEL.encode()
    try:
        for gnu_path,android_path in views:
            pair=[]
            for path in (gnu_path,android_path):
                parent,name=C.parent_fd(path)
                try:fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                except BaseException:os.close(parent);raise
                row={'path':str(path),'parent':parent,'name':name,'fd':fd}
                handles.append(row);pair.append(row)
                before=os.fstat(fd);raw_label=os.getxattr(fd,'security.selinux')
                names=sorted(os.listdir(fd))
                need(len(names)<=4096,'shared ancestor entry bound')
                need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
                     and stat.S_IMODE(before.st_mode)==0o700,'shared ancestor ownership/mode differs')
                need(raw_label in (wanted,wanted+b'\0'),'shared ancestor state label differs')
                need(C.metadata(before)==C.metadata(os.fstat(fd))
                     ==C.metadata(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                     'shared ancestor identity changed during observation')
                row.update(before_metadata=C.metadata(before),label_raw=raw_label,names_before=names)
            need(pair[0]['before_metadata']==pair[1]['before_metadata']
                 and pair[0]['label_raw']==pair[1]['label_raw']
                 and pair[0]['names_before']==pair[1]['names_before'],
                 'GNU/Android shared ancestor aliases differ')
            pairs.append(pair)
        # Creation is relative to the already-held and verified Android home FD.
        # An existing name (including a symlink) is a refusal, never an update.
        parent_fd=pairs[1][1]['fd']
        os.mkdir('executor',mode=0o700,dir_fd=parent_fd);os.fsync(parent_fd)
        leaf_fd=os.open('executor',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
        before=os.fstat(leaf_fd)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
             and stat.S_IMODE(before.st_mode)==0o700 and os.listdir(leaf_fd)==[],
             'new isolated journal ownership/mode/content differs')
        os.setxattr(leaf_fd,'security.selinux',C.EXECUTOR_LABEL.encode()+b'\0')
        leaf_label=os.getxattr(leaf_fd,'security.selinux')
        need(leaf_label in (C.EXECUTOR_LABEL.encode(),C.EXECUTOR_LABEL.encode()+b'\0'),
             'new isolated journal label differs')
        # Persist the new directory's xattr before claiming durable creation.
        os.fsync(leaf_fd);os.fsync(parent_fd)
        leaf_metadata=C.metadata(os.fstat(leaf_fd))
        need(leaf_metadata==C.metadata(os.stat('executor',dir_fd=parent_fd,follow_symlinks=False)),
             'new isolated journal named identity differs')
        created.append({'path':str(journal),'metadata':leaf_metadata,'selinux':C.EXECUTOR_LABEL})
        records=[]
        for index,pair in enumerate(pairs):
            for row in pair:
                current=C.metadata(os.fstat(row['fd']))
                need(current[:5]==row['before_metadata'][:5]
                     and current==C.metadata(os.stat(row['name'],dir_fd=row['parent'],follow_symlinks=False))
                     and os.getxattr(row['fd'],'security.selinux')==row['label_raw'],
                     'shared ancestor identity or original label changed')
                expected=sorted(row['names_before']+(['executor'] if index==1 else []))
                need(sorted(os.listdir(row['fd']))==expected,'unexpected shared ancestor entry delta')
                row['after_metadata']=current
            need(pair[0]['after_metadata']==pair[1]['after_metadata'],'shared alias bookends disagree')
            records.append({'gnu_path':pair[0]['path'],'android_path':pair[1]['path'],
                'before_metadata':pair[0]['before_metadata'],'after_metadata':pair[0]['after_metadata'],
                'selinux':SHARED_STATE_LABEL,'selinux_raw_hex':pair[0]['label_raw'].hex(),
                'labels_unchanged':True})
        return {'schema':'hepta.native-guard.journal-layout.v1',
            'state':'NEW_EXECUTOR_LEAF_SHARED_ANCESTORS_PRESERVED',
            'shared_ancestors':records,'journal':{'path':str(journal),'metadata':leaf_metadata,
                'selinux':C.EXECUTOR_LABEL,'selinux_raw_hex':leaf_label.hex(),'created_exclusive':True,
                'label_fsynced_before_created_record':True},
            'existing_directory_label_writes':0,'new_journal_label_writes':1,'policy_changes':0}
    finally:
        if leaf_fd is not None:os.close(leaf_fd)
        for row in reversed(handles):os.close(row['fd']);os.close(row['parent'])


def stage(a):
    need(a.execute_private_stage_once,'explicit Root create-only stage required')
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'Root stage only')
    os.umask(0o077)
    path=Path(a.archive).absolute()
    need(path.parent.resolve()==path.parent and path.parent==Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1'),
         'explicit GNU staging archive directory required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0
             and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=8*1024*1024,'private original transport archive required')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(8*1024*1024+1)
        after=os.fstat(fd);named=path.lstat()
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in keys),
             'original transport archive changed')
    finally:os.close(fd)
    need(sha(raw)==a.archive_sha256,'Root archive byte pin differs')
    files=archive_members(raw);lease,manifest=validate_archive(files,a.lease_sha256,a.package_sha256)
    need(path.name==lease['label']+'.tar.gz','staging archive label differs')
    home=Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1')/lease['label']
    C,L=modules_from_reviewed(files,home);L.native_root(lease['boot_id'])
    need(0<lease['expires_unix_ms']-__import__('time').time_ns()//1000000<=900000,'Root lease expired; no automatic extension')
    old_lock,retired=L.verify_retired(lease)
    created=[];started=False
    try:
        # Existing parent namespace may be shared by separately closed leases;
        # this exact label and journal must not exist in any form.
        for target in (home,C.ANDROID/lease['android_journal'].lstrip('/')):
            try:target.lstat()
            except FileNotFoundError:pass
            else:need(False,'one-use component destination already exists')
        ensure_new_or_exact_directory(C,home.parent,created=created)
        need(ensure_new_or_exact_directory(C,home,created=created),'one-use home already exists');started=True
        for name,data in sorted(files.items()):
            target=home/name
            parents=[];p=target.parent
            while p!=home:parents.append(p);p=p.parent
            for p in reversed(parents):ensure_new_or_exact_directory(C,p,created=created)
            parent,leaf=C.parent_fd(target)
            try:
                f=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
                with os.fdopen(f,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
                os.fsync(parent)
            finally:os.close(parent)
            need(C.read(target)==data,'new staged file readback differs')
        for name in ('claims','operator'):ensure_new_or_exact_directory(C,home/name,created=created)
        journal_layout=create_isolated_journal(C,home,lease,created)
        L.verify_package(home/'package/MANIFEST.json',a.package_sha256)
        q,_=L.load_lease(home,a.lease_sha256);need(q==lease,'staged lease changed')
        combo,_=C.load_combination(home/'inputs',files['inputs/COMBINATION.json'],
            C.strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json']))
        actual_artifacts=C.verify_external(combo)
        result={'schema':'hepta.native-guard.private-stage.v1','state':'PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES',
            'lease_sha256':a.lease_sha256,'package_sha256':a.package_sha256,'archive_sha256':a.archive_sha256,
            'archive_source':str(path),'archive_metadata':C.metadata(before),'members':len(files),'created_directories':created,
            'journal_layout':journal_layout,
            'retirement_verified_before_writes':retired,'existing_artifacts_read_only':actual_artifacts,
            'existing_files_overwritten':0,'service_launches':0,'model_requests':0,'native_tasks':0,
            'existing_helper_or_policy_changes':0,'automatic_retry':False,'component_qualified':False}
        C.put(home/'STAGE-COMPLETE.json',result);print(C.encoded(result).decode(),end='')
        return 0
    except BaseException as error:
        if started:
            C.put(home/'STAGE-FAILURE.json',{'error_type':type(error).__name__,'detail':str(error)[:1024],
                'created_directories':created,'automatic_retry':False,'automatic_cleanup':False})
        raise
    finally:os.close(old_lock)


def main():
    p=argparse.ArgumentParser()
    for name in ('archive','archive-sha256','lease-sha256','package-sha256'):p.add_argument('--'+name,required=True)
    p.add_argument('--execute-private-stage-once',action='store_true')
    return stage(p.parse_args())


if __name__=='__main__':raise SystemExit(main())
