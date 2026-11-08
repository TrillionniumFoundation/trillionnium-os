#!/usr/bin/env python3
"""Root operator for one separately selected r9 transfer/stage/start/read phase.

No old lifecycle action is repeated. Every remote operation has one exclusive
identity, and incomplete outcomes are inspected through their original records.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import sys

B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
OUTPUT=B/'root-r9-r2-deploy-20261104-r1'
P4='/home/alex/razr60-local-model-v150'
P4_RELEASE=P4+'/releases/v150-r9-r2'
P4_ARCHIVE=P4_RELEASE+'/phone-release-v150-r9-r2.tar.gz'
PHONE_ARCHIVE='/data/local/tmp/hepta-phone-local-v150-r1/phone-release-v150-r9-r2.tar.gz'
G='/var/lib/trillionnium/owner-open/phone-local-v150'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
ACTOR_SHA='179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'
HELPER_SHA='630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6'
INSTALLER_SHA='53bfabae55516bd7043d7b55c9ff379f2b2d21a6866665af6e55510cc8c35d00'
COLLECTOR_SHA='b7ca21b829034691019f8a2ba93446e19198ec1f0fc00456b345ea07bd9af53e'
SSH=['/usr/bin/ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22',
     '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast']
GNU_PREFIX='/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -B '


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,limit=64*1024*1024):
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=limit,'bounded regular input required')
    raw=path.read_bytes();after=path.lstat()
    need(len(raw)==info.st_size and (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'host input changed')
    return raw


def put(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def record(path,value):put(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())


def helper():
    path=B/'root-operators-r6-cycle03/run_cycle03.py'
    need(sha(read(path,65536))==HELPER_SHA,'existing transport helper changed')
    spec=importlib.util.spec_from_file_location('existing_root_phone_transport',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.D=OUTPUT
    return module


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('phase',choices=('copy','push','stage','start','snapshot'))
    parser.add_argument('--release-dir',type=Path,required=True)
    parser.add_argument('--build-result-sha256',required=True)
    parser.add_argument('--execute-reviewed-phase-once',action='store_true',required=True)
    args=parser.parse_args();os.umask(0o077)
    release=args.release_dir.absolute()
    need(release.resolve(strict=True)==release and release.is_relative_to(B/'root-r9-r2-integration-20261104-r1'),
         'new reviewed host release directory required')
    build_raw=read(release/'BUILD-RESULT.json',65536)
    need(sha(build_raw)==args.build_result_sha256,'build result pin differs')
    build=json.loads(build_raw)
    need(build['state']=='SEALED_ACTUAL_RETIREMENT_BOUND' and build['production_source_count']==15,
         'actual retirement-bound release required')
    need(build['failed_predecessor_sha256']=='1bd4a67b7368466396612d2177d81831cc9fe6a9442a2e831159a4a263fdd89a',
         'actual failed predecessor closure required')
    archive=release/'phone-release-v150-r9-r2.tar.gz';archive_row=build['archive']
    need(str(archive)==archive_row['path'],'archive path differs from actual build')
    archive_raw=read(archive)
    need(len(archive_raw)==archive_row['bytes'] and sha(archive_raw)==archive_row['sha256'],'archive pin differs')
    for value in (build['retirement_sha256'],build['source_seal_sha256'],build['configuration_sha256'],
                  build['module_manifest_sha256'],build['service_inputs_sha256']):
        need(re.fullmatch('[0-9a-f]{64}',value) is not None,'actual SHA required')
    need(sha(read(release/'provider/SOURCE-SEAL-v150-r9.json'))==build['source_seal_sha256'],'source seal changed')
    need(sha(read(release/'local-config-r9-r2.json'))==build['configuration_sha256'],'configuration changed')
    need(sha(read(release/'PHONE-SERVICE-INPUTS-v150-r9-r2.json'))==build['service_inputs_sha256'],'service inputs changed')
    need(sha(read(release/'module/MODULE-MANIFEST-v150-r9-r2.json'))==build['module_manifest_sha256'],'module manifest changed')
    need(read(release/'module/SEALED')==b'HEPTA_PHONE_LOCAL_V150_R9_R2_REVIEWED_INPUTS_BOUND\n','module is not sealed')
    need(B.resolve(strict=True)==B,'host workspace changed')
    OUTPUT.mkdir(mode=0o700,exist_ok=True)
    info=OUTPUT.lstat()
    need(OUTPUT.resolve(strict=True)==OUTPUT and stat.S_ISDIR(info.st_mode) and
         info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'private operator output differs')
    binding=dict(release_dir=str(release),build_result_sha256=args.build_result_sha256,
                 archive_sha256=archive_row['sha256'],retirement_sha256=build['retirement_sha256'],
                 failed_predecessor_sha256=build['failed_predecessor_sha256'],
                 migration_boot=BOOT,automatic_retry=False)
    root_binding=OUTPUT/'DEPLOY-BINDING.json'
    if root_binding.exists():need(json.loads(read(root_binding))==binding,'operator namespace already bound to another release')
    else:record(root_binding,binding)
    record(OUTPUT/(args.phase+'.INTENT.json'),dict(phase=args.phase,**binding))
    try:
        transport=helper()
        if args.phase=='copy':
            code='''from pathlib import Path
import os,sys,json,hashlib,stat
B=Path('''+repr(P4)+''');D=Path('''+repr(P4_RELEASE)+''')
assert B.resolve(strict=True)==B and B.is_dir()
assert hashlib.sha256((B/'ops/phone_once.py').read_bytes()).hexdigest()=='''+repr(ACTOR_SHA)+'''
raw=sys.stdin.buffer.read(64*1024*1024+1)
assert len(raw)=='''+str(len(archive_raw))+''' and hashlib.sha256(raw).hexdigest()=='''+repr(sha(archive_raw))+'''
os.umask(0o077)
parent=D.parent
if not parent.exists():parent.mkdir(mode=0o700)
assert parent.resolve(strict=True)==parent and parent.stat().st_uid==os.getuid() and stat.S_IMODE(parent.stat().st_mode)==0o700
D.mkdir(mode=0o700)
p=D/'phone-release-v150-r9-r2.tar.gz'
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
assert p.read_bytes()==raw
fd=os.open(D,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'state':'P4_ARCHIVE_COPIED_AND_VERIFIED','path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
'''
            result=subprocess.run(SSH+['python3 -I -c '+shlex.quote(code)],input=archive_raw,capture_output=True,timeout=120)
            put(OUTPUT/'copy.stdout',result.stdout);put(OUTPUT/'copy.stderr',result.stderr)
            need(result.returncode==0,'copy failed; inspect original durable process and output')
            value=json.loads(result.stdout)
            need(value['sha256']==archive_row['sha256'] and value['bytes']==archive_row['bytes'],'remote copy identity differs')
        elif args.phase=='push':
            copied=json.loads(read(OUTPUT/'copy.RESULT.json'))
            need(copied['state']=='P4_ARCHIVE_COPIED_AND_VERIFIED' and copied['sha256']==archive_row['sha256'],'copy not confirmed')
            request=dict(kind='push',source=P4_ARCHIVE,destination=PHONE_ARCHIVE,
                         sha256=archive_row['sha256'],timeout_seconds=120)
            label='root-r9r2-push-release-20261104-01'
            code='''from pathlib import Path
import os,sys,json,hashlib,subprocess
B=Path('''+repr(P4)+''');actor=B/'ops/phone_once.py'
assert hashlib.sha256(actor.read_bytes()).hexdigest()=='''+repr(ACTOR_SHA)+'''
request='''+repr(request)+''';label='''+repr(label)+'''
p=B/'requests'/(label+'.json')
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump(request,f);f.write('\\n');f.flush();os.fsync(f.fileno())
r=subprocess.run([sys.executable,'-I',str(actor),label,str(p)],capture_output=True,timeout=150)
raw=(B/'operations'/label/'result.json').read_bytes()
print(json.dumps({'actor_rc':r.returncode,'wrapper_sha256':hashlib.sha256(raw).hexdigest(),'wrapper':json.loads(raw)},sort_keys=True))
'''
            raw=transport.ssh(code,170);put(OUTPUT/(label+'.original-operation.json'),raw)
            result=json.loads(raw);wrapped=result['wrapper']
            need(result['actor_rc']==0 and wrapped['status']=='pushed_and_hash_verified' and
                 wrapped['readback']['rc']==0 and wrapped['sha256']==archive_row['sha256'] and
                 wrapped['bytes']==archive_row['bytes'],'phone archive push not confirmed')
            value=dict(state=wrapped['status'],bytes=wrapped['bytes'],sha256=wrapped['sha256'],
                       actor_rc=result['actor_rc'],wrapper_sha256=result['wrapper_sha256'])
        elif args.phase in ('stage','start'):
            if args.phase=='stage':
                pushed=json.loads(read(OUTPUT/'push.RESULT.json'))
                need(pushed['state']=='pushed_and_hash_verified' and pushed['sha256']==archive_row['sha256'],'push not confirmed')
            else:
                staged=json.loads(read(OUTPUT/'stage.RESULT.json'))
                need(staged['state']=='STAGED_DISABLED_NOT_STARTED' and staged['archive_sha256']==archive_row['sha256'],
                     'exact stage not confirmed')
            path=B/'root-r9-r2-integration-20261104-r1/operators/install_phone_release.py'
            source=read(path,65536);need(sha(source)==INSTALLER_SHA,'reviewed installer changed')
            argv=['pinned-r9-installer','--archive','/proc/1/root'+PHONE_ARCHIVE,
                  '--archive-sha256',archive_row['sha256'],'--retirement-sha256',build['retirement_sha256'],
                  '--phase',args.phase,'--execute-reviewed-operation-once']
            code='import base64,hashlib,sys\nraw=base64.b64decode('+repr(base64.b64encode(source).decode())+',validate=True)\nassert hashlib.sha256(raw).hexdigest()=='+repr(INSTALLER_SHA)+'\nsys.argv='+repr(argv)+'\nexec(compile(raw,"pinned-r9-installer","exec"),{"__name__":"__main__","__file__":"pinned-r9-installer"})\n'
            result=transport.call_phone('root-r9r2-'+args.phase+'-release-20261104-01',
                dict(kind='shell',root=True,timeout_seconds=150,command=GNU_PREFIX+'-c '+shlex.quote(code)))
            value=json.loads(result['stdout'])
            need(value['state']==('STAGED_DISABLED_NOT_STARTED' if args.phase=='stage' else
                 'SERVICE_SPAWNED_READINESS_NOT_YET_ESTABLISHED'),'original phase outcome differs')
        else:
            started=json.loads(read(OUTPUT/'start.RESULT.json'))
            need(started['state']=='SERVICE_SPAWNED_READINESS_NOT_YET_ESTABLISHED','start not confirmed')
            startup_identity=started['process_identity']
            need(isinstance(startup_identity,list) and len(startup_identity)==4 and
                 startup_identity[:3]==[started['pid']]*3,'actual startup identity missing')
            source=read(release/'provider/collect_r9_readiness.py',65536)
            need(sha(source)==COLLECTOR_SHA,'reviewed readiness collector changed')
            entry=G+'/provider-r9-r2/collect_r9_readiness.py'
            argv=[entry,'--expected-boot',BOOT,'--source-seal-sha256',build['source_seal_sha256'],
                  '--configuration-sha256',build['configuration_sha256'],
                  '--module-manifest-sha256',build['module_manifest_sha256']]
            expected_daily=next(row['sha256'] for row in json.loads(read(release/'provider/SOURCE-SEAL-v150-r9.json'))['production_files']
                                if row['path']=='source/daily_phone_local.py')
            code='''from pathlib import Path
import hashlib,json,sys,time,os
B=Path('''+repr(G)+''');boot='''+repr(BOOT)+'''
claim=Path('/proc/1/root/data/adb/trillionnium-hepta-phone-local-v150-r9-r2')/boot
expected='''+repr(startup_identity)+'''
deadline=time.monotonic()+180
while time.monotonic()<deadline:
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot
    try:
        stat_raw=(Path('/proc')/str(expected[0])/'stat').read_text()
    except (FileNotFoundError,ProcessLookupError):
        raise RuntimeError('original startup process ended; inspect preserved logs, no restart')
    tail=stat_raw.rsplit(') ',1)[1].split()
    if [expected[0],int(tail[2]),int(tail[3]),int(tail[19])]!=expected or tail[0]=='Z':
        raise RuntimeError('original startup process no longer live; inspect preserved logs, no restart')
    if (claim/'exit-code').exists():raise RuntimeError('original new supervisor ended; inspect original claim, no restart')
    ready=B/'provider-state/ready.json'
    try:r=json.loads(ready.read_bytes())
    except FileNotFoundError:r={}
    if r.get('accepting') is True and r.get('source_sha256')=='''+repr(expected_daily)+''' and (claim/'services-started').is_file():break
    time.sleep(.5)
else:raise TimeoutError('original readiness observation deadline; inspect existing startup, no restart')
p=Path('''+repr(entry)+''');raw=p.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='''+repr(COLLECTOR_SHA)+'''
sys.argv='''+repr(argv)+'''
exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})
'''
            result=transport.call_phone('root-r9r2-readiness-original-20261104-01',
                dict(kind='shell',root=True,timeout_seconds=210,command=GNU_PREFIX+'-c '+shlex.quote(code)))
            value=json.loads(result['stdout'])
            need(value['state']=='EXACT_COMBINATION_READY_TRANSPORT_ONLY','actual readiness not established')
        record(OUTPUT/(args.phase+'.RESULT.json'),value)
        print(json.dumps(value,sort_keys=True))
    except BaseException as error:
        record(OUTPUT/(args.phase+'.FAILURE.json'),dict(state='INSPECT_ORIGINAL_OUTCOME_NO_RETRY',
            phase=args.phase,error_type=type(error).__name__,error=str(error),automatic_retry=False))
        raise


if __name__=='__main__':main()
