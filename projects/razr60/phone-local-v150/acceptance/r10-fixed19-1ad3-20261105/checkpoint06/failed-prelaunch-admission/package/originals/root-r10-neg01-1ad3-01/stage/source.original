#!/usr/bin/env python3
"""Fixed NEG01 stage-only observation. No source/case writes or process actions."""
import sys
sys.dont_write_bytecode = True
import errno, hashlib, io, json, os, re, stat, tarfile, time, zlib
from pathlib import Path

LABEL='root-r10-neg01-1ad3-01'
NONCE='7c74b84aefb177d15f746fa7eae29d54'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
HOME=Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1')/LABEL
ANDROID=Path('/proc/1/root')
ARCHIVE=Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1')/(LABEL+'.tar.gz')
LEASE_PIN=(2488,'2f47f823ef1484852c5dc1b91f27020d6f56685b3024dc320d5925a3dac92d59')
PACKAGE_PIN=(16808,'67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c')
ARCHIVE_PIN=(469829,'9aacc5789a65dd875ab9fe7456e2258e0bf4e54575d3be71a50d5542a489b288')
STAGE_PIN=(15628,'a9855aba9e1112a5d98ef038225275c5359dab94ca6a157b6f1f03f8a7cd3309')
LEASE_EXPIRES_UNIX_MS=1793872564534
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ABSENT=(
 'STAGE-FAILURE.json','DETACHED-LAUNCH-INTENT.json','DETACHED-LAUNCH-RESULT.json',
 'supervisor.stdout','supervisor.stderr','LIFECYCLE-ATTEMPT.json','SUPERVISOR.json',
 'RETIRED-BASELINE-VERIFIED.json','BASELINE-INVENTORY.json','PORT-RESERVED.json',
 'sidecar.SPAWNED.json','provider.SPAWNED.json','SIDECAR-HEALTH.original.json',
 'PROVIDER-HEALTH.original.json','BOUND-CONTRACT.json','READY.json',
 'CONNECTION-ACCEPTED.json','ACCEPTED.json','PROVIDER-ENDED.json',
 'LIFECYCLE-FAILURE.json','LIFECYCLE-ENDED.json','sidecar.JOINED.json','provider.JOINED.json',
 'sidecar.TERM-INTENT.json','provider.TERM-INTENT.json','ROOT-SETUP-PLAN.json',
 'ROOT-BEFORE-GUARD-PLAN.json','ROOT-AFTER-GUARD-PLAN.json','claims/'+NONCE+'.json')

# The following six pure functions are copied byte-for-byte from the exact
# runtime stage4d4692/common1e2d sources. No source module or main is executed.
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
    rows=manifest['files'];need(5<=len(rows)<=32 and len({r['path'] for r in rows})==len(rows),'package inventory bound')
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

def parent_fd(path):
    """Walk directory FDs without links; only /proc/1/root is an explicit anchor.

    The GNU chroot cannot resolve that Android magic link lexically. Runtime
    startup separately binds the init PID namespace and the anchor inode.
    """
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2 <= len(path.parts) <= 64,
         'bounded absolute path required')
    if path.parts[:4] == ('/', 'proc', '1', 'root'):
        fd = os.open(ANDROID, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[4:]
    else:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[1:]
    need(parts, 'file path required')
    try:
        for name in parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd); raise

START=time.monotonic()
DEADLINE=START+25
FILES={}
DIRECTORIES={}
HELD=[]
READ_TOTAL=0

def tick():
    need(time.monotonic()<=DEADLINE,'bounded local observation budget elapsed')

def metadata(s):
    return [getattr(s,k) for k in META]

def pin(raw):
    return {'bytes':len(raw),'sha256':sha(raw)}

def named(row):
    return os.stat(row['leaf'],dir_fd=row['parent'],follow_symlinks=False)

def hold(path, directory=False):
    tick();path=Path(path)
    parent,leaf=parent_fd(path)
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|
                   (os.O_DIRECTORY if directory else 0),dir_fd=parent)
    except BaseException:
        os.close(parent);raise
    row={'path':str(path),'parent':parent,'leaf':leaf,'fd':fd}
    HELD.append(row)
    s=os.fstat(fd)
    need((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
         and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==(0o700 if directory else 0o600)
         and (directory or s.st_nlink==1),'private regular/directory observation shape')
    row['metadata']=metadata(s)
    need(row['metadata']==metadata(named(row)),'named object differs from held FD')
    return row

def directory(path):
    tick();key=str(path)
    if key in DIRECTORIES:return DIRECTORIES[key]
    row=hold(path,True)
    row['names']=sorted(os.listdir(row['fd']))
    need(len(row['names'])<=128 and all('/' not in n and n not in ('.','..') for n in row['names']),
         'directory entry bound/shape')
    row['selinux_raw_hex']=os.getxattr(row['fd'],'security.selinux').hex()
    need(metadata(os.fstat(row['fd']))==row['metadata']==metadata(named(row)),
         'directory changed during observation')
    DIRECTORIES[key]=row
    return row

def read_file(path,maximum=8*1024*1024,expected=None):
    global READ_TOTAL
    tick();key=str(path)
    if key in FILES:
        row=FILES[key]
        need(metadata(os.fstat(row['fd']))==row['metadata']==metadata(named(row)),'prior file changed')
        raw=row['raw']
    else:
        row=hold(path)
        need(0<=row['metadata'][6]<=maximum,'regular original size bound')
        with os.fdopen(row['fd'],'rb',closefd=False) as stream:raw=stream.read(row['metadata'][6]+1)
        need(len(raw)==row['metadata'][6] and metadata(os.fstat(row['fd']))==row['metadata']==metadata(named(row)),
             'original bytes or full9 identity raced')
        READ_TOTAL+=len(raw);need(READ_TOTAL<=16*1024*1024,'fixed observation total read bound')
        row['raw']=raw;row.update(pin(raw));FILES[key]=row
    need(len(raw)<=maximum,'cached original size bound')
    if expected is not None:need((len(raw),sha(raw))==expected,'exact original byte pin differs')
    tick();return raw

def missing(relative):
    path=Path(relative);row=directory(HOME/path.parent)
    try:os.stat(path.name,dir_fd=row['fd'],follow_symlinks=False)
    except OSError as error:need(error.errno==errno.ENOENT,'absence is unknown')
    else:need(False,'launch/acceptance original exists: '+relative)
    need(metadata(os.fstat(row['fd']))==row['metadata']==metadata(named(row)),
         'absence parent changed')

def recheck():
    for row in HELD:
        tick()
        need(metadata(os.fstat(row['fd']))==row['metadata']==metadata(named(row)),
             'held original full9 identity changed')
        parent,leaf=parent_fd(row['path'])
        try:
            need(leaf==row['leaf'] and metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False))==row['metadata'],
                 'canonical original path was replaced')
        finally:os.close(parent)
        if 'names' in row:
            need(sorted(os.listdir(row['fd']))==row['names']
                 and os.getxattr(row['fd'],'security.selinux').hex()==row['selinux_raw_hex'],
                 'directory entries or label changed')

def boot():
    with open('/proc/sys/kernel/random/boot_id','rb') as stream:raw=stream.read(128)
    need(raw.strip().decode()==BOOT,'actual boot differs')
    return raw

def observe():
    need(len(sys.argv)==1,'fixed one-case probe takes no alternate inputs')
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root credentials required')
    boot_raw=boot()
    need((os.stat(ANDROID).st_dev,os.stat(ANDROID).st_ino)!=(os.stat('/').st_dev,os.stat('/').st_ino),
         'GNU and explicit Android root anchors must differ')
    wall_start=time.time_ns()//1000000
    directory(HOME)
    lease_raw=read_file(HOME/'LEASE.json',262144,LEASE_PIN)
    stage_raw=read_file(HOME/'STAGE-COMPLETE.json',65536,STAGE_PIN)
    manifest_raw=read_file(HOME/'package/MANIFEST.json',262144,PACKAGE_PIN)
    archive=read_file(ARCHIVE,8*1024*1024,ARCHIVE_PIN)
    files=archive_members(archive)
    need(len(files)==56,'exact actual archive member count')
    lease,manifest=validate_archive(files,LEASE_PIN[1],PACKAGE_PIN[1])
    need(files['LEASE.json']==lease_raw and files['package/MANIFEST.json']==manifest_raw,
         'phone originals differ from exact original transport archive')
    need(lease['label']==LABEL and lease['nonce']==NONCE and lease['boot_id']==BOOT
         and lease['case_id']=='NEG-01' and lease['expires_unix_ms']==LEASE_EXPIRES_UNIX_MS,
         'fixed failed lease binding differs')
    need(wall_start>=LEASE_EXPIRES_UNIX_MS,'observation is only for this already expired lease')
    need(len(manifest['files'])==32 and len({r['path'] for r in manifest['files']})==32,'exact runtime32 set')
    stage=strict(stage_raw)
    need(stage['schema']=='hepta.native-guard.private-stage.v1'
         and stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES'
         and stage['lease_sha256']==LEASE_PIN[1] and stage['package_sha256']==PACKAGE_PIN[1]
         and stage['archive_sha256']==ARCHIVE_PIN[1] and stage['archive_source']==str(ARCHIVE)
         and stage['members']==56 and stage['service_launches']==stage['model_requests']==stage['native_tasks']==0
         and stage['existing_files_overwritten']==stage['existing_helper_or_policy_changes']==0,
         'actual stage completion fields differ')
    need(FILES[str(ARCHIVE)]['metadata']==stage['archive_metadata'],'retained transport archive full9 changed')
    wanted_files=set(files)|{'STAGE-COMPLETE.json'}
    wanted_dirs={'.','claims','operator','executor'}
    for name in files:
        wanted_dirs.update(str(p) for p in Path(name).parents)
    need(len(wanted_dirs)<=64,'fixed tree directory bound')
    observed_files=set();observed_dirs=set();stack=[Path('.')]
    while stack:
        tick();relative=stack.pop();row=directory(HOME/relative);observed_dirs.add(str(relative))
        need(str(relative) in wanted_dirs,'unexpected directory in retained case')
        for name in row['names']:
            rel=relative/name;key=str(rel);s=os.stat(name,dir_fd=row['fd'],follow_symlinks=False)
            if stat.S_ISDIR(s.st_mode):stack.append(rel)
            else:
                need(key in wanted_files,'unexpected non-directory in retained case')
                raw=read_file(HOME/rel)
                need(raw==(stage_raw if key=='STAGE-COMPLETE.json' else files[key]),
                     'staged original tree byte changed')
                observed_files.add(key)
    need(observed_files==wanted_files and observed_dirs==wanted_dirs,'exact staged tree closed set differs')
    for name in ('claims','operator','executor'):
        need(directory(HOME/name)['names']==[],'one-use directory is no longer empty: '+name)
    for name in ABSENT:missing(name)
    layout=stage['journal_layout'];journal=layout['journal']
    need(layout['state']=='NEW_EXECUTOR_LEAF_SHARED_ANCESTORS_PRESERVED'
         and layout['existing_directory_label_writes']==0 and layout['new_journal_label_writes']==1
         and layout['policy_changes']==0 and journal['created_exclusive'] is True
         and journal['label_fsynced_before_created_record'] is True,
         'actual original journal layout differs')
    need(journal['path']==str(ANDROID/lease['android_journal'].lstrip('/'))
         and Path(journal['path']).name=='executor','exact original Android journal alias')
    g=directory(HOME/'executor');a=directory(Path(journal['path']))
    need(g['metadata']==a['metadata']==journal['metadata'] and g['names']==a['names']==[]
         and g['selinux_raw_hex']==a['selinux_raw_hex']==journal['selinux_raw_hex'],
         'empty isolated journal seed changed or aliases differ')
    need(len(layout['shared_ancestors'])==2,'original shared ancestor count')
    for index,original in enumerate(layout['shared_ancestors']):
        expected=HOME.parent if index==0 else HOME
        need(original['gnu_path']==str(expected),'exact shared ancestor path')
        left=directory(expected);right=directory(Path(original['android_path']))
        need(left['metadata']==right['metadata'] and left['names']==right['names']
             and left['metadata'][:5]==original['after_metadata'][:5]
             and left['selinux_raw_hex']==right['selinux_raw_hex']==original['selinux_raw_hex'],
             'shared ancestor identity, alias or original label changed')
    recheck()
    for name in ABSENT:missing(name)
    need(boot()==boot_raw and time.time_ns()//1000000>=wall_start,'boot/wall time changed')
    recheck();tick()
    result={'schema':'hepta.native-guard.stage-only-read-observation.v1',
        'state':'EXACT_STAGED_TREE_RETAINED_NO_LAUNCH_ARTIFACTS_OBSERVED',
        'label':LABEL,'nonce':NONCE,'case_id':'NEG-01','boot_id':BOOT,
        'home':str(HOME),'lease':pin(lease_raw),'lease_expires_unix_ms':LEASE_EXPIRES_UNIX_MS,
        'lease_expired':True,'package':pin(manifest_raw),'stage_complete':pin(stage_raw),
        'archive':dict(path=str(ARCHIVE),**pin(archive)),'archive_member_count':56,
        'exact_current_file_count':len(observed_files),'exact_current_directory_count':len(observed_dirs),
        'files':{str(Path(k).relative_to(HOME)):dict(bytes=v['bytes'],sha256=v['sha256'],metadata=v['metadata'])
            for k,v in sorted(FILES.items()) if Path(k)==HOME or HOME in Path(k).parents},
        'directories':{str(Path(k).relative_to(HOME)):dict(metadata=v['metadata'],names=v['names'],
            selinux_raw_hex=v['selinux_raw_hex']) for k,v in sorted(DIRECTORIES.items())
            if Path(k)==HOME or HOME in Path(k).parents},
        'explicit_absence':{name:'ENOENT_AT_HELD_PARENT_BEFORE_AND_AFTER_READSET' for name in ABSENT},
        'journal':{'gnu_path':str(HOME/'executor'),'android_path':journal['path'],
            'metadata':g['metadata'],'selinux_raw_hex':g['selinux_raw_hex'],
            'empty':True,'exact_original_seed_metadata':True,'both_views_equal':True},
        'full9_named_fd_and_canonical_path_bookends':True,
        'read_total_bytes':READ_TOTAL,'elapsed_seconds':time.monotonic()-START,
        'phone_source_or_case_writes':0,'process_starts':0,'signals_sent':0,
        'socket_connections':0,'fixture_attempts':0,'lease_extensions':0,
        'native_boundary_created':False,'component_qualified':False,'business_qualified':False,
        'sender_termination_verified_here':False,'process_absence_verified_here':False,
        'global_publication_absence_verified_here':False,
        'failed_predecessor_closed_here':False,'automatic_retry':False}
    return result

def main():
    try:
        result=observe();code=0
    except BaseException as error:
        result={'schema':'hepta.native-guard.stage-only-read-observation.v1',
            'state':'READ_REJECTED_OR_UNKNOWN_RETAIN_ORIGINALS','label':LABEL,'nonce':NONCE,
            'error_type':type(error).__name__,'detail':str(error)[:1024],
            'phone_source_or_case_writes':0,'process_starts':0,'signals_sent':0,
            'failed_predecessor_closed_here':False,'component_qualified':False,'automatic_retry':False}
        code=1
    finally:
        for row in reversed(HELD):
            os.close(row['fd']);os.close(row['parent'])
    raw=(json.dumps(result,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
    need(len(raw)<=65536,'bounded observation output')
    sys.stdout.write(raw.decode());return code

if __name__=='__main__':raise SystemExit(main())
