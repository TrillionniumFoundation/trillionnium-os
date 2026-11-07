#!/usr/bin/env python3
"""One explicit phone release stage/start; preserve prior journals and modules.

Run inside the existing GNU phone root as the existing Magisk operator. Inputs
are a separately reviewed archive hash and immutable release manifest. Unknown
outcomes are inspected through their existing output directory, never replayed.
"""
from pathlib import Path, PurePosixPath
from contextlib import contextmanager
import argparse
import errno
import fcntl
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time

ANDROID = Path('/proc/1/root')
BASE = Path('/var/lib/trillionnium/owner-open/phone-local-v150')
ANDROID_BASE = '/data/trillionnium/owner-open/state/phone-local-v150'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
FINGERPRINT = 'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys'
POLICY = 'bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38'
FAILED_PREDECESSOR_SHA = '1bd4a67b7368466396612d2177d81831cc9fe6a9442a2e831159a4a263fdd89a'
OLD_MODULE = '/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r3'
OLD_ROLES = {'supervisor':[571,571,571,10690877], 'model':[707,707,707,10691094],
             'sidecar':[987,987,987,10691164], 'provider':[1286,1286,1286,10691228]}
MODULE = '/data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2'
HELPER = '/data/local/tmp/hepta-phone-executor-v150-r9-r1'
MODEL_RUNTIME = ANDROID_BASE+'/model-runtime-r9-r2'
HISTORY = '/data/adb/trillionnium-hepta-phone-local-v150-r9-r2'
EXECUTOR_HISTORY = ANDROID_BASE+'/executor-r6/module-history-r9-r2'
ROOTS = [MODULE, '/data/local/tmp/hepta-phone-local-v150-r9-r2',
         ANDROID_BASE+'/provider-r9-r2', ANDROID_BASE+'/module-r9-activation-r2', HELPER]
HELPER_LABEL = 'u:object_r:trillionnium_owner_open_phone_helper_file:s0'
EXECUTOR_LABEL = 'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0'
LABELS = {'u:object_r:shell_data_file:s0', HELPER_LABEL, EXECUTOR_LABEL}
ANCHORS = {'/data/adb/modules':0, '/data/adb':0, '/data/local/tmp':2000,
           ANDROID_BASE:0, ANDROID_BASE+'/executor-r6':0}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _v: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def android(name):
    p = PurePosixPath(name)
    need(p.is_absolute() and '..' not in p.parts and str(p) == name, 'noncanonical Android target')
    return ANDROID / name.lstrip('/')


def beneath(name, root):
    return name == root or name.startswith(root+'/')


def directory_profile(name):
    allowed = any(beneath(name, root) for root in ROOTS+[HISTORY, EXECUTOR_HISTORY, MODEL_RUNTIME])
    mode = 0o755 if beneath(name, HELPER) else 0o700
    label = HELPER_LABEL if beneath(name, HELPER) else EXECUTOR_LABEL if beneath(name, EXECUTOR_HISTORY) else None
    return allowed, mode, label


@contextmanager
def directory_fd(path, create=False):
    """Open every Android component without symlinks; only init's root is magic."""
    path = Path(path)
    if not path.is_relative_to(ANDROID):
        need(not create and path.is_absolute() and path.resolve(strict=True)==path,
             'canonical GNU directory required')
        fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            yield fd
        finally:
            os.close(fd)
        return
    parts = path.relative_to(ANDROID).parts
    fd = os.open(ANDROID, os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    prefix = ''
    try:
        for name in parts:
            need(name not in ('','.', '..'), 'unsafe directory component')
            prefix += '/'+name
            allowed, mode, label = directory_profile(prefix)
            created = False
            try:
                child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            except FileNotFoundError:
                need(create and allowed, 'unapproved directory creation: '+prefix)
                os.mkdir(name,mode,dir_fd=fd)
                os.fsync(fd)
                child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                created = True
            info = os.fstat(child)
            if created:
                os.fchown(child,0,0)
                os.fchmod(child,mode)
                if label:
                    os.setxattr(child,'security.selinux',label.encode()+b'\0')
                os.fsync(child)
                info = os.fstat(child)
            try:
                named = os.stat(name,dir_fd=fd,follow_symlinks=False)
                need(stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(named.st_dev,named.st_ino),
                     'directory identity changed: '+prefix)
                if prefix in ANCHORS:
                    need(info.st_uid==ANCHORS[prefix], 'trusted parent ownership differs: '+prefix)
                if allowed:
                    need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==mode,
                         'release directory ownership/mode differs: '+prefix)
                    if label:
                        need(os.getxattr(child,'security.selinux').rstrip(b'\0').decode()==label,
                             'release directory label differs: '+prefix)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def stable(path, limit=32*1024*1024, permissions=None):
    path = Path(path)
    with directory_fd(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and 0 <= a.st_size <= limit, 'regular bounded file required: '+str(path))
        if permissions is not None:
            need((a.st_uid, a.st_gid, stat.S_IMODE(a.st_mode)) == permissions, 'file ownership/mode differs: '+str(path))
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(limit+1)
        z, n = os.fstat(fd), Path(path).lstat()
        keys = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw) == a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(n,k) for k in keys), 'file changed during read')
        return raw
    finally:
        os.close(fd)


def hash_file(path, size, expected):
    path = Path(path)
    with directory_fd(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_size == size, 'pinned file size/type differs: '+str(path))
        h = hashlib.sha256()
        total = 0
        with os.fdopen(fd, 'rb', closefd=False) as f:
            while True:
                block=f.read(min(1048576,size+1-total))
                if not block:
                    break
                total+=len(block)
                need(total<=size,'pinned file grew beyond declared size: '+str(path))
                h.update(block)
        z, n = os.fstat(fd), Path(path).lstat()
        keys = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink','st_mode','st_uid','st_gid')
        need(total==size and all(getattr(a,k)==getattr(z,k)==getattr(n,k) for k in keys) and h.hexdigest()==expected, 'pinned file changed or hash differs: '+str(path))
    finally:
        os.close(fd)


def sync_directory(path):
    with directory_fd(path) as fd:
        os.fsync(fd)


def put(path, raw, mode=0o600):
    with directory_fd(path.parent) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,dir_fd=parent)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as f:
            f.write(raw)
            f.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(path.parent)
    need(stable(path, max(len(raw),1), (0,0,mode)) == raw, 'write readback differs')


def put_json(path, value):
    put(path, (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())


def proc(pid):
    try:
        raw = (Path('/proc')/str(pid)/'stat').read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    tail = raw.rsplit(') ',1)[1].split()
    return {'identity':[pid,int(tail[2]),int(tail[3]),int(tail[19])], 'state':tail[0]}


def census_old_groups():
    groups = {v[0] for v in OLD_ROLES.values()}
    members = []
    for path in Path('/proc').iterdir():
        if path.name.isascii() and path.name.isdigit():
            row = proc(int(path.name))
            if row and groups.intersection(row['identity'][:3]):
                members.append(row)
    need(not members, 'previous groups still present')
    for group in groups:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            continue
        raise RuntimeError('previous process group absence unconfirmed')


def base_identity():
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0, 'root operator required')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT, 'migration boot changed')
    need(Path('/proc/self/attr/current').read_text().strip('\x00\n')=='u:r:magisk:s0', 'operator domain differs')
    need(os.readlink('/proc/1/exe')=='/system/bin/init' and
         Path('/proc/1/attr/current').read_text().strip('\x00\n')=='u:r:init:s0' and
         proc(1)['identity'][3]==0, 'Android init root anchor differs')
    fingerprint=subprocess.run([str(ANDROID/'data/adb/magisk/busybox'),'chroot',str(ANDROID),
                                '/system/bin/getprop','ro.build.fingerprint'],
                               check=True,capture_output=True,timeout=5,text=True)
    need(fingerprint.stdout.strip()==FINGERPRINT and fingerprint.stderr=='','phone fingerprint differs')
    need((ANDROID/'sys/fs/selinux/enforce').read_text().strip()=='1', 'SELinux must remain enforcing')
    need(digest((ANDROID/'sys/fs/selinux/policy').read_bytes())==POLICY, 'live policy differs')
    need(BASE.resolve(strict=True)==BASE and BASE.stat().st_uid==BASE.stat().st_gid==0 and
         stat.S_IMODE(BASE.stat().st_mode)==0o700, 'state root differs')
    need(stable(android(OLD_MODULE+'/disable'),1,(0,0,0o600))==b'', 'previous release not disabled')


def load_release(archive, expected):
    raw = stable(archive,64*1024*1024)
    need(digest(raw)==expected, 'archive hash differs')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as t:
        members = t.getmembers()
        need(0 < len(members) <= 256 and len({m.name for m in members})==len(members), 'archive inventory differs')
        for m in members:
            p = PurePosixPath(m.name)
            need(m.isfile() and not p.is_absolute() and '..' not in p.parts and str(p)==m.name and 0 <= m.size <= 32*1024*1024, 'unsafe archive member')
        need(sum(m.size for m in members)<=64*1024*1024, 'archive expanded size exceeds bound')
        blobs = {m.name:t.extractfile(m).read() for m in members}
    manifest = strict(blobs['release.json'])
    need(manifest['schema']=='hepta.phone-release.v1' and manifest['release_id']=='v150-r9-r2', 'release identity differs')
    need(manifest['migration_boot']==BOOT and manifest['policy_sha256']==POLICY, 'release boot/policy differs')
    writes = manifest['writes']
    need(len(writes)==len({x['target'] for x in writes})==len({x['member'] for x in writes}) and 0 < len(writes)<=240, 'duplicate/empty write targets')
    need(set(blobs)=={'release.json'} | {x['member'] for x in writes}, 'archive allowlist differs')
    roots = [manifest['module_dir'], manifest['runtime_dir'], manifest['provider_dir'], manifest['activation_dir'], manifest['helper_dir']]
    need(roots==ROOTS, 'release root allowlist differs')
    extras = {ANDROID_BASE+'/local-config-r9-r2.json',ANDROID_BASE+'/PHONE-SERVICE-INPUTS-v150-r9-r2.json'}
    for row in writes:
        android(row['target'])
        need(any(row['target'].startswith(root+'/') for root in roots) or row['target'] in extras, 'write target outside release')
        need(type(row['mode']) is int and (row['mode'] in (0o600,0o700,0o755) or
             row['mode']==0o644 and row['target'].startswith(HELPER+'/helpers/') and
             row['target'].endswith('.jar') and row.get('selinux')==HELPER_LABEL), 'unreviewed file mode')
        need(not row.get('selinux') or row['selinux'] in LABELS, 'unreviewed file label')
        need(row['target'] not in (MODULE+'/disable',MODULE+'/remove'), 'installer owns disable marker')
        need(len(blobs[row['member']])==row['bytes'] and digest(blobs[row['member']])==row['sha256'], 'member size/hash differs')
    targets={row['target'] for row in writes}
    need(all(not any(parent in targets for parent in map(str,PurePosixPath(name).parents)) for name in targets),
         'write targets overlap directories')
    directories=manifest['runtime_directories']
    need(len(directories)==len({x['path'] for x in directories})<=32,'runtime directory inventory differs')
    for row in directories:
        android(row['path'])
        need(any(beneath(row['path'],root) for root in (HISTORY,EXECUTOR_HISTORY,MODEL_RUNTIME)),
             'runtime directory outside release')
        need(row.get('selinux')==directory_profile(row['path'])[2],'runtime directory label differs')
        need(row['path'] not in targets and not any(beneath(row['path'],target) for target in targets),
             'runtime directory overlaps file')
    existing=manifest['verify_existing']
    need(len(existing)==len({x['target'] for x in existing})<=256,'existing input inventory differs')
    for row in existing:
        android(row['target'])
        need(row['target'] not in targets and type(row['bytes']) is int and 0<=row['bytes']<=8*1024**3 and
             re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'existing input descriptor differs')
    need(re.fullmatch('[0-9a-f]{64}',manifest['retirement_probe_sha256']) is not None,'retirement probe pin required')
    manifest['_archive_sha256']=expected
    manifest['_manifest_sha256']=digest(blobs['release.json'])
    return manifest, blobs


def retirement(manifest, expected_hash):
    directory = BASE/'module-retire-r7-r3-for-r8-r1-01'
    raw = stable(directory/'RETIREMENT.json',8*1024*1024,(0,0,0o600))
    need(digest(raw)==expected_hash, 'retirement identity differs')
    r = strict(raw)
    o = strict(stable(directory/'OPERATOR-RESULT.json',65536,(0,0,0o600)))
    need(r['schema']=='hepta.r7-r3-retirement-observation.v1' and r['state']=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED', 'retirement incomplete')
    need(r['boot_id']==BOOT and r['original_role_identities']==OLD_ROLES and r['global_pending_clear'] is True and r['server_lock_now_unheld'] is True, 'retirement provenance differs')
    need(o['state']=='R7_R3_RETIRED_ORIGINALS_PRESERVED' and o['retirement_sha256']==expected_hash and o['live_policy_unchanged'] is True, 'retirement operator incomplete')
    need(r['old_claims_deleted'] is False and r['old_task_terminal_rewritten'] is False and r['automatic_replay'] is False, 'historical state was changed')
    census_old_groups()
    probe = BASE/'module-r8-r1-retirement-code-r1/retirement_probe.py'
    probe_raw = stable(probe,262144,(0,0,0o600))
    need(digest(probe_raw)==manifest['retirement_probe_sha256'], 'preservation verifier source differs')
    namespace={'__name__':'release_preservation_readonly','__file__':str(probe)}
    exec(compile(probe_raw,str(probe),'exec',optimize=0),namespace)
    need(namespace['retained_state']()==r['preserved_state'], 'retained claims/ledger/actions changed')
    need(manifest['failed_predecessor_sha256']==FAILED_PREDECESSOR_SHA,
         'actual failed predecessor closure pin required')
    failed_raw=stable(BASE/'module-r9-r1-failed-start-closure-01/FAILED-START-CLOSURE.json',65536,(0,0,0o600))
    need(digest(failed_raw)==FAILED_PREDECESSOR_SHA,'failed predecessor closure changed')
    failed=strict(failed_raw)
    need(failed['schema']=='hepta.r9-r1.preclaim-failure-closure.v1'
         and failed['state']=='ORIGINAL_PRECLAIM_FAILURE_CLOSED_MODULE_DISABLED'
         and failed['boot_id']==BOOT and failed['original_release']=='v150-r9-r1'
         and failed['retirement_sha256']==expected_hash
         and failed['prior_business_state_unchanged'] is True
         and failed['old_failures_preserved'] is True and failed['automatic_retry'] is False,
         'failed predecessor closure identity differs')
    disabled=android('/data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r1/disable')
    info=disabled.lstat()
    need(stable(disabled,1,(0,0,0o600))==b'' and
         [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns]==failed['disable_identity'],
         'failed predecessor disable marker changed')
    original_root=BASE/'root-install-v150-r9-r1'
    need({Path(row['path']).name for row in failed['startup_originals']}==
         {'STARTED.json','service.stdout','service.stderr'},'failed original inventory differs')
    for row in failed['startup_originals']:
        original=Path(row['path']);need(original.parent==original_root,'failed original path differs')
        raw=stable(original,row['bytes'],(0,0,0o600))
        need(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'failed original startup evidence changed')
    return r, namespace


def make_private_directory(path):
    with directory_fd(path,create=True):
        pass


def verify_writes(manifest):
    for row in manifest['writes']:
        path=android(row['target'])
        hash_file(path,row['bytes'],row['sha256'])
        info=path.lstat()
        need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==row['mode'],
             'written file metadata differs: '+row['target'])
        if row.get('selinux'):
            need(os.getxattr(path,'security.selinux',follow_symlinks=False).rstrip(b'\0').decode()==row['selinux'],
                 'written file label differs: '+row['target'])
    for row in manifest['verify_existing']:
        hash_file(android(row['target']),row['bytes'],row['sha256'])
    for row in manifest['runtime_directories']:
        with directory_fd(android(row['path'])):
            pass


def stage(manifest, blobs, out, retirement_hash):
    base_identity()
    previous, verifier = retirement(manifest,retirement_hash)
    for row in manifest['verify_existing']:
        hash_file(android(row['target']),row['bytes'],row['sha256'])
    for row in manifest['writes']:
        path=android(row['target'])
        need(not path.exists() and not path.is_symlink(), 'new target already exists; inspect original outcome: '+row['target'])
    need(not out.exists(), 'stage already consumed; inspect original output')
    out.mkdir(mode=0o700)
    sync_directory(out.parent)
    put_json(out/'INSTALL-INTENT.json',{'release_id':manifest['release_id'],'retirement_sha256':retirement_hash,'write_count':len(manifest['writes']),'automatic_replay':False})
    written=[]
    try:
        # Inhibit this new module before publishing any discoverable service code.
        make_private_directory(android(manifest['module_dir']))
        disable=android(manifest['module_dir']+'/disable')
        put(disable,b'')
        for row in manifest['writes']:
            path=android(row['target'])
            make_private_directory(path.parent)
            put(path,blobs[row['member']],row['mode'])
            if row.get('selinux'):
                with directory_fd(path.parent) as parent:
                    fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
                    try:
                        os.setxattr(fd,'security.selinux',row['selinux'].encode()+b'\0')
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            written.append(row['target'])
        for directory in manifest['runtime_directories']:
            path=android(directory['path'])
            make_private_directory(path)
        verify_writes(manifest)
        need(verifier['retained_state']()==previous['preserved_state'], 'retained state changed during install')
        census_old_groups()
        st=disable.lstat()
        result={'state':'STAGED_DISABLED_NOT_STARTED','release_id':manifest['release_id'],'archive_sha256':manifest['_archive_sha256'],'manifest_sha256':manifest['_manifest_sha256'],'writes_verified':len(written),'disable_identity':[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns], 'retirement_sha256':retirement_hash,'preserved_state_unchanged':True,'model_requests':0,'task_submissions':0,'service_starts':0}
        put_json(out/'STAGED.json',result)
        return result
    except BaseException as error:
        put_json(out/'STAGE-FAILURE.json',{'state':'INCOMPLETE_INSPECT_ORIGINAL_NO_RETRY','error_type':type(error).__name__,'error':str(error),'written':written,'automatic_retry':False})
        raise


def start(manifest, out, retirement_hash):
    base_identity()
    retirement(manifest,retirement_hash)
    staged=strict(stable(out/'STAGED.json',65536,(0,0,0o600)))
    need(staged['state']=='STAGED_DISABLED_NOT_STARTED' and staged['release_id']==manifest['release_id'] and
         staged['retirement_sha256']==retirement_hash and
         staged['archive_sha256']==manifest['_archive_sha256'] and staged['manifest_sha256']==manifest['_manifest_sha256'],
         'stage not confirmed for this exact archive')
    verify_writes(manifest)
    disable=android(manifest['module_dir']+'/disable');st=disable.lstat()
    need([st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]==staged['disable_identity'] and stable(disable,1,(0,0,0o600))==b'', 'new disable marker changed')
    put_json(out/'START-INTENT.json',{'release_id':manifest['release_id'],'maximum_start_attempts':1,'old_release_remains_disabled':True})
    child=None
    removed=False
    try:
        with directory_fd(disable.parent) as parent:
            os.unlink(disable.name,dir_fd=parent)
            removed=True
            os.fsync(parent)
        argv=[str(ANDROID/'data/adb/magisk/busybox'),'chroot','/proc/1/root','/data/adb/magisk/busybox','sh',manifest['module_dir']+'/service.sh']
        with (out/'service.stdout').open('xb') as stdout,(out/'service.stderr').open('xb') as stderr:
            child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        spawned=proc(child.pid)
        need(spawned is not None and spawned['state']!='Z' and spawned['identity'][:3]==[child.pid]*3,
             'new startup process identity was not observed; inspect the original process only')
        again=proc(child.pid)
        need(again is not None and again['state']!='Z' and again['identity']==spawned['identity'],
             'new startup process changed before publication')
        result={'state':'SERVICE_SPAWNED_READINESS_NOT_YET_ESTABLISHED','pid':child.pid,
                'process_identity':spawned['identity'],'boot_id':BOOT,'release_id':manifest['release_id'],
                'one_start_attempt':True,'model_requests':0,'task_submissions':0}
        put_json(out/'STARTED.json',result)
        return result
    except BaseException as error:
        put_json(out/'START-FAILURE.json',{'state':'START_OUTCOME_REQUIRES_ORIGINAL_INSPECTION_NO_RETRY',
                 'disable_removed':removed,'spawn_returned_pid':None if child is None else child.pid,
                 'original_child_returncode_observed':None if child is None else child.poll(),
                 'error_type':type(error).__name__,'error':str(error),'automatic_retry':False,
                 'automatic_rollback':False})
        raise


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--archive-sha256',required=True)
    p.add_argument('--retirement-sha256',required=True)
    p.add_argument('--phase',choices=('stage','start'),required=True)
    p.add_argument('--execute-reviewed-operation-once',action='store_true',required=True)
    a=p.parse_args();os.umask(0o077)
    for value in (a.archive_sha256,a.retirement_sha256):
        need(re.fullmatch('[0-9a-f]{64}',value) is not None,'SHA256 required')
    manifest,blobs=load_release(a.archive,a.archive_sha256)
    out=BASE/'root-install-v150-r9-r2'
    result=stage(manifest,blobs,out,a.retirement_sha256) if a.phase=='stage' else start(manifest,out,a.retirement_sha256)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    main()
