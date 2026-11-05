#!/usr/bin/env python3
"""Explicit readonly observation of published902 using exact original constituents.

This independently identified adapter never calls or patches verify_current or
verify_retired and never turns the historical lease into new-case permission.
Actual completed host audit prerequisites must be bound before any phone read.
"""
import sys
sys.dont_write_bytecode = True
import base64
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import types
import zlib

LABEL = 'root-r10-neg01-7c907661-01'
NONCE = '902e851c3ca1f90deab3d880ab993774'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
LEASE_PIN = (2496, '31688136fbcb7ae520c096decc11c9c36a67a304172401c3aab6c14e7848c736')
PACKAGE_PIN = (16808, '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb')
COMBINATION_PIN = (4702, '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e')
LEASE_EXPIRES_UNIX_MS = 1793879507570
RETIREMENT_PROBE_PIN = (766658, 'd1fe1478ee9699b5a1199aa4c2b96a2a405f7cafd0b5707071cfd2238dbe5df4')
INVENTORY_SHA256 = 'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d'
OBSERVED_CALL_SECONDS = 180
OUTPUT_LIMIT = 1048576
MAX_PACKET_RAW = 16777216
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
READSET = {}
DIRECTORIES = {}
READ_BYTES = 0
CALLS = []
GROUP_CALLS = []
OBSERVATION_PARTS = {}
HOST_SOURCE_DIR = '/home/alex/codex-hepta-external902-independent-closure-audit-source-1ad3-01'
HOST_AUDIT_DIR = '/home/alex/codex-hepta-external902-independent-closure-audit-1ad3-01'
HOST_DRIVER = {'path': '/home/alex/codex-hepta-external902-independent-closure-audit-source-1ad3-01/audit_existing_closure.py', 'bytes': 26038, 'sha256': '8e6bab425940cae081f0684e61b20b6dbf5f9568c20ddecc3e1ee8f907536d29'}
HOST_CALLER = {'path': '/home/alex/codex-hepta-external902-independent-closure-audit-source-1ad3-01/CALLER.original.py', 'bytes': 49502, 'sha256': 'e2455108f95f54868703c523119835ac1288ea232d180968b174b0263b2ad256'}
HOST_SOURCE_PACKAGE = {'bytes': 4937, 'sha256': '39b3fe622eeda1beffdaba392e602275979421daa05d1ec732b3c7c8bb99a2da'}
HOST_ORIGINAL_CLOSURE = {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/closure/CLOSURE.original.json', 'bytes': 55124, 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'}
HOST_ORIGINAL_PLAN = {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/CLOSURE-PLAN.json', 'bytes': 2601, 'sha256': '77e77c83002b355692a1ca184992668409dc27136e58936520ccf55f419dc2a4'}
FINAL_HOST_AUDIT_BINDING = {'schema': 'hepta.existing902.host-audit-prerequisite.v1', 'state': 'ACTUAL_HOST_AUDIT_COMPLETE_AND_INDEPENDENTLY_VERIFIED', 'driver': {'bytes': 26038, 'path': '/home/alex/codex-hepta-external902-independent-closure-audit-source-1ad3-01/audit_existing_closure.py', 'sha256': '8e6bab425940cae081f0684e61b20b6dbf5f9568c20ddecc3e1ee8f907536d29'}, 'caller': {'path': '/home/alex/codex-hepta-external902-independent-closure-audit-source-1ad3-01/CALLER.original.py', 'bytes': 49502, 'sha256': 'e2455108f95f54868703c523119835ac1288ea232d180968b174b0263b2ad256'}, 'source_package': {'bytes': 4937, 'sha256': '39b3fe622eeda1beffdaba392e602275979421daa05d1ec732b3c7c8bb99a2da'}, 'original_closure': {'bytes': 55124, 'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/closure/CLOSURE.original.json', 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'}, 'original_plan': {'bytes': 2601, 'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/CLOSURE-PLAN.json', 'sha256': '77e77c83002b355692a1ca184992668409dc27136e58936520ccf55f419dc2a4'}, 'caller_result': {'path': '/home/alex/codex-hepta-external902-independent-closure-audit-source-1ad3-01/CALLER-RESULT.json', 'bytes': 2125, 'sha256': '0aba002433726ab64629cbdb78b9ffd2b9295af86c2a34865c90dbffae51fb1d'}, 'byte_equality': {'path': '/home/alex/codex-hepta-external902-independent-closure-audit-1ad3-01/BYTE-EQUALITY.json', 'bytes': 52142, 'sha256': '6bb0cb5179850cce2adc53982796bde4dd6bb2f0269968df33e91ff4b4dc8461'}, 'recomputed_closure': {'bytes': 55124, 'path': '/home/alex/codex-hepta-external902-independent-closure-audit-1ad3-01/RECOMPUTED-EXPECTED-CLOSURE.json', 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'}, 'controller': {'job_id': '1a1ac11fdf1-fc05-5216', 'retained_receipts': [{'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/independent-host-audit01/CONTROLLER-START.tool.json', 'bytes': 1528, 'sha256': '05e6c7acc2e8435327c5a44897f15a799d52f63233be4c010d84e58411608b37'}, {'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/independent-host-audit01/CONTROLLER-STATUS.tool.json', 'bytes': 954, 'sha256': '3e4b1685ef84efeba90ebc17994b5161eb688618c93fc246c1a443324bb3c8ee'}, {'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/independent-host-audit01/CONTROLLER-READ.tool.json', 'bytes': 3850, 'sha256': '8100cb0abe3817baaa1ec786d44af1a5baf947aaf57c0e339f3cb4aae847e114'}, {'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/independent-host-audit01/CONTROLLER-STDOUT.original', 'bytes': 1053, 'sha256': '24e997f7479a0107c9f4b89b8a3b1b1cd1d2515a55647a66341385e8ec1e050e'}, {'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/independent-host-audit01/CONTROLLER-STDERR.original', 'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}], 'complete': True, 'durable': True, 'exit_code': 0, 'stdout_complete': True, 'stderr_complete': True}, 'independent_actual_verification': {'path': '/workspace/scratch/1ad3d6f55439/existing902_current_head_observer_candidate01/package/validation/ACTUAL-HOST-AUDIT-PREREQUISITE-VERIFICATION.json', 'bytes': 3354, 'sha256': '90e8317116b70f1b3bc7d0732a1fc8cd0e1909e8546583d87c23d62bbea0e643'}}
FIXED_PACKET = {'codec': 'zlib+base64', 'packed': {'bytes': 3659, 'sha256': 'd4c663d20abc17a7dae318692cf059fd6e91660520cc62c900233f9fc7a3ae6e'}, 'raw': {'bytes': 13832, 'sha256': '3f50f6f782d9f0d8e1ee7d475a3c082b29e0867230309eec0c0c5ed677a628ee'}, 'data': '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'}
CASE_HOME = Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1') / LABEL
ANDROID = Path('/proc/1/root')

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

def source_package():
    root=CASE_HOME/'package'
    manifest_raw=read_original(root/'MANIFEST.json',262144,PACKAGE_PIN);manifest=strict(manifest_raw)
    need(manifest['schema']=='hepta.native-guard.adapter-package.v1'
         and manifest['state']=='HOST_REVIEWED_NOT_PHONE_QUALIFIED','exact actual runtime manifest shape')
    rows=manifest['files'];need(type(rows) is list and len(rows)==32,'exact runtime32')
    files={};dirs={'.'}
    for row in rows:
        need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact runtime member descriptor')
        name=row['path'];p=Path(name)
        need(type(name) is str and str(p)==name and not p.is_absolute() and '..' not in p.parts
             and name not in files and type(row['bytes']) is int and 0<row['bytes']<=16*1024*1024,
             'canonical unique bounded runtime member')
        files[name]=read_original(root/p,16*1024*1024,(row['bytes'],row['sha256']))
        dirs.update(str(d) for d in p.parents)
    expected=set(files)|{'MANIFEST.json'};observed=set();observed_dirs=set();stack=[Path('.')]
    while stack:
        rel=stack.pop();directory=read_directory(root/rel);observed_dirs.add(str(rel))
        need(str(rel) in dirs,'extra source directory')
        for name in directory['names']:
            relative=rel/name;full=root/relative;s=full.lstat()
            if stat.S_ISDIR(s.st_mode):stack.append(relative)
            else:
                need(stat.S_ISREG(s.st_mode) and str(relative) in expected,'extra or non-regular source member')
                observed.add(str(relative))
    need(observed==expected and observed_dirs==dirs,'actual source closed set changed')
    return root,files

def load_module(name,root,files):
    need(name not in sys.modules,'fresh exact runtime module required: '+name)
    relative='source/'+name+'.py';raw=files[relative];module=types.ModuleType(name)
    module.__file__=str(root/relative);sys.modules[name]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module

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

def release_owned_verifier_lock(before,lock_identity,returned_fd):
    after=own_fds();closed=[];errors=[];targets=set()
    for fd,identity in after.items():
        if fd>=3 and identity==lock_identity and fd not in before:targets.add(fd)
    if returned_fd is not None:
        if type(returned_fd) is not int or returned_fd<3 or returned_fd in before:
            errors.append('returned FD is not an observed new owned FD')
        elif returned_fd not in after:
            errors.append('returned owned FD is already absent; release is not established')
        else:
            # A returned FD is our original verifier's new resource.  Even an
            # inode/flag mismatch must close it before reporting a rejection.
            targets.add(returned_fd)
    for fd in sorted(targets):
        identity=after[fd];row={'fd':fd,'identity':list(identity),
            'returned_by_verifier':fd==returned_fd,'matches_bootstrap_lock':identity==lock_identity}
        if identity!=lock_identity:errors.append('returned lock differs from bootstrap inode')
        try:
            row['readonly']=(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE)==os.O_RDONLY
            if not row['readonly']:errors.append('original verifier lock FD is not read-only')
        except BaseException as exc:
            errors.append('owned FD flags unknown: '+type(exc).__name__)
        finally:
            try:os.close(fd);row['close_returned']=True
            except BaseException as exc:
                row['close_returned']=False;errors.append('owned FD close failed: '+type(exc).__name__)
        try:os.fstat(fd)
        except OSError as exc:
            row['observed_EBADF']=exc.errno==errno.EBADF
            if exc.errno!=errno.EBADF:errors.append('owned FD close observation unknown')
        else:row['observed_EBADF']=False;errors.append('owned FD remains after close')
        closed.append(row)
    final=own_fds()
    remaining=[{'fd':fd,'identity':list(identity)} for fd,identity in final.items()
               if fd>=3 and before.get(fd)!=identity]
    if remaining:errors.append('unexpected new own FDs remain; no complete cleanup claim')
    if returned_fd is not None and not any(row['fd']==returned_fd for row in closed):
        errors.append('returned verifier lock was not closed by this diagnostic')
    return {'only_returned_own_or_new_exact_existing_lock_FDs_closed':True,'closed':closed,
        'new_FDs_remaining':remaining,'errors':errors,'complete':not errors}

def read_original(path,maximum=16*1024*1024,expected=None,expected_metadata=None):
    global READ_BYTES
    path=Path(path);parent,leaf=parent_fd(path)
    fd=None
    try:
        parent_before=metadata(os.fstat(parent))
        before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0
             and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=maximum,
             'bounded private original shape')
        if expected_metadata is not None:
            need(metadata(before)==expected_metadata,'fixed original metadata differs before open')
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        need(metadata(os.fstat(fd))==metadata(before),'original full9 changed before open')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
        named=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        need(len(raw)==before.st_size and metadata(before)==metadata(os.fstat(fd))==metadata(named),
             'original full9 read changed')
        need(metadata(os.fstat(parent))==parent_before,'original parent changed during read')
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
    canonical,canonical_leaf=parent_fd(path)
    try:
        need(canonical_leaf==leaf and metadata(os.fstat(canonical))==parent_before
             and metadata(os.stat(canonical_leaf,dir_fd=canonical,follow_symlinks=False))==metadata(before),
             'canonical original path changed')
    finally:os.close(canonical)
    row={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'metadata':metadata(before)}
    if expected is not None:need((len(raw),row['sha256'])==expected,'exact original pin differs')
    if expected_metadata is not None:need(row['metadata']==expected_metadata,'fixed original metadata differs')
    if str(path) in READSET:need(row==READSET[str(path)],'bootstrap original changed across verification')
    else:
        READ_BYTES+=len(raw);need(READ_BYTES<=16*1024*1024,'bootstrap original readset bound')
        READSET[str(path)]=row
    return raw


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def descriptor(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def strict_unpack(packet, maximum):
    need(type(packet) is dict and set(packet) == {'codec', 'packed', 'raw', 'data'},
        'exact lossless packet required')
    need(packet['codec'] == 'zlib+base64' and type(packet['data']) is str,
        'fixed packet codec required')
    for key in ('packed', 'raw'):
        row = packet[key]
        need(type(row) is dict and set(row) == {'bytes', 'sha256'}
            and type(row['bytes']) is int and 0 < row['bytes'] <= maximum
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
            'bounded exact packet descriptor required')
    need(len(packet['data']) <= 4 * ((maximum + 2) // 3), 'bounded base64 packet required')
    packed = base64.b64decode(packet['data'], validate=True)
    need(descriptor(packed) == packet['packed'], 'lossless packed bytes differ')
    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(packed, packet['raw']['bytes'] + 1)
    need(decompressor.eof and not decompressor.unused_data and not decompressor.unconsumed_tail
        and decompressor.flush() == b'' and descriptor(raw) == packet['raw'],
        'lossless complete bounded packet required')
    return raw


def pack_original(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PACKET_RAW, 'bounded whole observation required')
    packed = zlib.compress(raw, 9)
    packet = {'codec': 'zlib+base64', 'packed': descriptor(packed), 'raw': descriptor(raw),
        'data': base64.b64encode(packed).decode('ascii')}
    need(strict_unpack(packet, MAX_PACKET_RAW) == raw, 'whole observation lossless roundtrip differs')
    return packet


def fixed_data():
    raw = strict_unpack(FIXED_PACKET, 131072)
    value = strict(raw)
    need(type(value) is dict and set(value) == {'package_readset', 'head', 'lease', 'owner',
        'retirement', 'head_order', 'source_map', 'source_map_review', 'combination'},
        'fixed source map fields differ')
    rows = value['package_readset']
    need(type(rows) is list and len(rows) == 33 and len({row['path'] for row in rows}) == 33,
        'exact source33 descriptor set required')
    for row in rows:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'metadata'}
            and type(row['path']) is str and Path(row['path']).is_absolute()
            and type(row['bytes']) is int and 0 < row['bytes'] <= 16 * 1024 * 1024
            and type(row['metadata']) is list and len(row['metadata']) == 9
            and all(type(item) is int for item in row['metadata']), 'fixed source descriptor differs')
    return value


def host_prerequisite():
    # This is a literal in a separately reviewed source, never a runtime input.
    # The phone cannot reread P4 controller artifacts. Their actual verification
    # must precede the final source binding and remains separately attributable.
    value = FINAL_HOST_AUDIT_BINDING
    need(type(value) is dict, 'actual successful independent host audit is not bound')
    need(set(value) == {'schema', 'state', 'driver', 'caller', 'source_package',
        'original_closure', 'original_plan', 'caller_result', 'byte_equality',
        'recomputed_closure', 'controller', 'independent_actual_verification'},
        'exact host audit prerequisite fields required')
    need(value['schema'] == 'hepta.existing902.host-audit-prerequisite.v1'
        and value['state'] == 'ACTUAL_HOST_AUDIT_COMPLETE_AND_INDEPENDENTLY_VERIFIED',
        'actual host audit completion required')
    need(value['driver'] == HOST_DRIVER and value['caller'] == HOST_CALLER
        and value['source_package'] == HOST_SOURCE_PACKAGE
        and value['original_closure'] == HOST_ORIGINAL_CLOSURE
        and value['original_plan'] == HOST_ORIGINAL_PLAN,
        'fixed actual host audit source/original bindings differ')
    paths = {'caller_result': HOST_SOURCE_DIR + '/CALLER-RESULT.json',
        'byte_equality': HOST_AUDIT_DIR + '/BYTE-EQUALITY.json',
        'recomputed_closure': HOST_AUDIT_DIR + '/RECOMPUTED-EXPECTED-CLOSURE.json'}
    for name, path in paths.items():
        row = value[name]
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
            and row['path'] == path and type(row['bytes']) is int and 0 < row['bytes'] <= 1048576
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
            'actual host audit output descriptor differs: ' + name)
    need({key: value['recomputed_closure'][key] for key in ('bytes', 'sha256')}
        == {key: HOST_ORIGINAL_CLOSURE[key] for key in ('bytes', 'sha256')},
        'actual full closure byte equality prerequisite differs')
    controller = value['controller']
    need(type(controller) is dict and set(controller) == {'job_id', 'retained_receipts',
        'complete', 'durable', 'exit_code', 'stdout_complete', 'stderr_complete'}
        and type(controller['job_id']) is str and 1 <= len(controller['job_id']) <= 128
        and controller['complete'] is controller['durable'] is True
        and type(controller['exit_code']) is int and controller['exit_code'] == 0
        and controller['stdout_complete'] is controller['stderr_complete'] is True,
        'independently checked completed controller required')
    receipts = controller['retained_receipts']
    need(type(receipts) is list and 1 <= len(receipts) <= 32, 'bounded retained controller origins required')
    for row in receipts + [value['independent_actual_verification']]:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
            and type(row['path']) is str and Path(row['path']).is_absolute()
            and type(row['bytes']) is int and 0 <= row['bytes'] <= 16 * 1024 * 1024
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
            'retained host verification origin descriptor differs')
    return value


def phase_call(name, function, *args, **kwargs):
    row = {'name': name, 'entered_monotonic_ns': time.monotonic_ns(), 'entered': True,
        'returned': False}
    CALLS.append(row)
    result = function(*args, **kwargs)
    row['returned'] = True
    row['returned_monotonic_ns'] = time.monotonic_ns()
    return result


def group_observation(C, name, identities):
    row = {'name': name, 'entered': True, 'returned': False,
        'identity_count': len(identities), 'unique_numeric_pgids': len({item[0] for item in identities}),
        'signal_zero_completed_count': None, 'count_is_exact': False,
        'started_monotonic_ns': time.monotonic_ns()}
    GROUP_CALLS.append(row)
    observation = C.absent_groups(identities)
    row.update({'returned': True, 'signal_zero_completed_count': row['unique_numeric_pgids'],
        'count_is_exact': True, 'finished_monotonic_ns': time.monotonic_ns(),
        'original_observation': observation})
    return observation


def descriptor_read(row, maximum=16 * 1024 * 1024):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'metadata'},
        'original exact4 descriptor required')
    return read_original(row['path'], maximum, (row['bytes'], row['sha256']), row['metadata'])


def historical_binding(C, L, fixed):
    lease_raw = descriptor_read(fixed['lease'], 262144)
    lease, second = phase_call('L.load_lease_historical_only', L.load_lease,
        CASE_HOME, LEASE_PIN[1], require_live=False)
    need(second == lease_raw and lease['label'] == LABEL and lease['nonce'] == NONCE
        and lease['boot_id'] == BOOT and lease['case_id'] == 'NEG-01'
        and lease['expires_unix_ms'] == LEASE_EXPIRES_UNIX_MS
        and time.time_ns() // 1000000 >= LEASE_EXPIRES_UNIX_MS,
        'fixed expired historical owner identity differs')
    need(lease['package_sha256'] == PACKAGE_PIN[1]
        and lease['combination'] == fixed['combination']
        and lease['retirement'] == fixed['retirement'], 'historical source/retirement identity differs')
    owner = descriptor_read(fixed['owner'], 16000)
    need(sha(owner) == lease['owner_request_sha256'] and owner.decode().count(NONCE) == 1,
        'fixed historical owner request differs')
    head_raw = descriptor_read(fixed['head'])
    head = C.strict(head_raw)
    need(head['nonce'] == NONCE and head['case_id'] == lease['case_id']
        and head['boot_id'] == BOOT and head['package_sha256'] == PACKAGE_PIN[1]
        and head['combination_sha256'] == COMBINATION_PIN[1]
        and head['prior_boundary'] == lease['prior_boundary']
        and head['retirement'] == lease['retirement']
        and head['owner_request_sha256'] == lease['owner_request_sha256']
        and head['scope']['session_id'] == lease['selected_session_id']
        and head['scope']['profile_id'] == lease['selected_profile_id']
        and head['component_qualified'] is False and head['business_qualified'] is False,
        'published head does not bind the exact historical lease/owner')
    read_original(CASE_HOME / 'inputs/COMBINATION.json', 16384, COMBINATION_PIN)
    return lease, head


def lifecycle_retirement_binding(late, lease, fixed):
    # Explicit adapter version of the extra L.verify_retired source-binding gate.
    # Original retired_originals already enforces proof/preflight/preservation.
    raw = {key: phase_call('late.original_retirement_' + key, late.original, row)
        for key, row in fixed['retirement'].items()}
    for row in fixed['retirement'].values():
        descriptor_read(row)
    proof, preflight, bound = (strict(raw[key]) for key in ('proof', 'preflight', 'bound_inputs'))
    need(raw['disabled_flag'] == b'' and preflight['groups'] == proof['original_role_identities']
        and preflight['preserved_state'] == proof['preserved_state']
        and bound.get('complete_current_accepted_case_union_verified') is True,
        'original lifecycle retirement source inputs differ')
    row = fixed['retirement']['probe']
    need((len(raw['probe']), sha(raw['probe'])) == RETIREMENT_PROBE_PIN,
        'original retirement source pin differs')
    module = types.ModuleType('existing_head902_original_retirement_source')
    module.__file__ = row['path']
    exec(compile(raw['probe'], module.__file__, 'exec'), module.__dict__)
    need(module.BOUND == bound and {key: list(value) for key, value in module.GROUPS.items()}
        == preflight['groups'], 'original d1fe source does not bind original BOUND/GROUPS')
    return {'source': row, 'bound_inputs': fixed['retirement']['bound_inputs'],
        'original_generated_BOUND_and_GROUPS_verified': True,
        'retained_state_preflight_retire_stop_calls': 0}, list(preflight['groups'].values())


def fixed_source_bootstrap(fixed):
    for row in fixed['package_readset']:
        descriptor_read(row)
    root, files = source_package()
    need(set(READSET[path]['sha256'] for path in READSET if path.startswith(str(root) + '/'))
        == set(row['sha256'] for row in fixed['package_readset']), 'actual source33 pin set differs')
    C = load_module('component_common', root, files)
    load_module('native_proc_profile', root, files)
    L = load_module('component_lifecycle', root, files)
    late = load_module('late_boundary', root, files)
    snapshot = load_module('component_snapshot', root, files)
    package = phase_call('C.verify_package', C.verify_package, root / 'MANIFEST.json', PACKAGE_PIN[1])
    need(len(package['files']) == 32, 'actual original32 source package differs')
    return C, L, late, snapshot


def observe_current_head(C, L, late, snapshot, lease, head, fixed):
    chain, originals = phase_call('late.chain_originals', late.chain_originals, fixed['head'],
        combination_sha256=COMBINATION_PIN[1], package_sha256=PACKAGE_PIN[1],
        boot_id=BOOT, retirement=lease['retirement'])
    need(chain[0][0] == head and [row[0]['nonce'] for row in chain] == fixed['head_order']
        and len(chain) == 6 and len(originals) == 18, 'fixed published902 complete original chain differs')
    OBSERVATION_PARTS['original_chain_descriptors'] = originals
    side = phase_call('late.non_native_sidebranch', late.non_native_sidebranch, phone_originals=True)
    OBSERVATION_PARTS['fixed_non_native_sidebranch'] = side['binding']
    retirement, roles = phase_call('late.retired_originals', late.retired_originals,
        lease['retirement'], BOOT)
    generated, retired_roles = lifecycle_retirement_binding(late, lease, fixed)
    OBSERVATION_PARTS['retirement_generated_source_binding'] = generated
    need(roles == retired_roles and len(retired_roles) == 4, 'original four retired roles differ')
    roles = list(roles)
    for old_head, _old_inventory, _old_closure in chain:
        roles.extend(old_head['component_role_identities'].values())
    roles.extend(side['binding']['component_role_identities'].values())
    need(len(roles) == 25 and len({tuple(item) for item in roles}) == len(roles),
        'closed role identities repeat or fixed full role census differs')
    selected = phase_call('late.effective_prior_inventory', late.effective_prior_inventory,
        chain[0][0], chain[0][1], side)
    need(selected == chain[0][1] and len(selected['roots']) == 27,
        'existing current native head must select its own exact27-root inventory')
    need(head['inventory']['sha256'] == INVENTORY_SHA256, 'published902 inventory pin differs')
    observed = phase_call('late.current_inventory', late.current_inventory, selected)
    OBSERVATION_PARTS['full_observed_inventory'] = observed
    phase_call('late.preserve_non_native_private', late.preserve_non_native_private, observed, side)
    all_absence = [group_observation(C, 'all25-first', roles),
        group_observation(C, 'all25-second', roles)]
    tables, endpoints = phase_call('snapshot.endpoint_absence', snapshot.endpoint_absence)
    OBSERVATION_PARTS['endpoint_original_tables'] = {
        key: {'raw_b64': base64.b64encode(raw).decode('ascii'), **descriptor(raw)}
        for key, raw in tables.items()}
    OBSERVATION_PARTS['endpoint_original_summary'] = endpoints
    recheck_rows = originals + list(lease['retirement'].values()) + side['originals']
    need(len(recheck_rows) == 26, 'exact18+5+3 original bookend set differs')
    phase_call('late.recheck_originals_after_dynamic', late.recheck_originals, recheck_rows)
    retired_absence = [group_observation(C, 'retired4-first', retired_roles),
        group_observation(C, 'retired4-second', retired_roles)]
    return {'chain': chain, 'chain_originals': originals, 'side': side,
        'retirement': retirement, 'generated_retirement': generated, 'observed': observed,
        'selected': selected, 'roles': roles, 'all_absence': all_absence,
        'retired_absence': retired_absence, 'tables': tables, 'endpoints': endpoints,
        'recheck_rows': recheck_rows}


def main():
    started = time.monotonic()
    phase = 'host_prerequisite'
    failure = cleanup = result = None
    before_fds = lock_identity = lock_fd = None
    verified = False
    fixed = host = native_context = observation = None
    lock_observation = None
    try:
        need(len(sys.argv) == 1, 'fixed existing-head observer has no alternate inputs')
        host = host_prerequisite()
        fixed = fixed_data()
        need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
            'actual native Root credentials required')
        before_fds = own_fds()
        boot_raw = boot()
        phase = 'exact_source33_bootstrap'
        C, L, late, snapshot = fixed_source_bootstrap(fixed)
        native_context = phase_call('L.native_root', L.native_root, BOOT)
        lease, head = historical_binding(C, L, fixed)
        need(time.monotonic() - started <= 25, 'exact source bootstrap exceeded25seconds')
        phase = 'original_constituent_observation'
        observation = observe_current_head(C, L, late, snapshot, lease, head, fixed)
        phase = 'existing_readonly_journal_lock'
        lock_path = C.BASE / 'executor-r6/server.lock'
        lock_row = observation['selected']['entries'].get(str(lock_path))
        need(type(lock_row) is dict and lock_row.get('kind') == 'file',
            'existing lock missing from exact cumulative inventory')
        read_original(lock_path, 65536, (lock_row['bytes'], lock_row['sha256']), lock_row['metadata'])
        lock_identity = tuple(lock_row['metadata'][key] for key in (0, 1, 2))
        need(lock_identity not in before_fds.values(), 'no inherited original journal lock FD')
        lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(lock_fd >= 3 and lock_fd not in before_fds
            and metadata(os.fstat(lock_fd)) == lock_row['metadata'], 'original readonly lock inode differs')
        need((fcntl.fcntl(lock_fd, fcntl.F_GETFL) & os.O_ACCMODE) == os.O_RDONLY,
            'actual existing lock is not readonly')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_observation = {'path': str(lock_path), 'fd': lock_fd,
            'metadata': lock_row['metadata'], 'readonly': True,
            'nonblocking_exclusive_acquired': True, 'acquired_monotonic_ns': time.monotonic_ns(),
            'lock_creates_or_truncates_file': False, 'global_writer_lock_claimed': False}
        phase = 'held_lock_full_originals_bookend'
        phase_call('late.recheck_originals_while_lock_held', late.recheck_originals,
            observation['recheck_rows'])
        for row in observation['recheck_rows']:
            descriptor_read(row)
        recheck_bootstrap()
        need(boot() == boot_raw, 'boot changed across current head observation')
        read_original(lock_path, 65536, (lock_row['bytes'], lock_row['sha256']), lock_row['metadata'])
        need(metadata(os.fstat(lock_fd)) == lock_row['metadata'], 'held lock identity changed')
        lock_observation['final_originals_bookend_monotonic_ns'] = time.monotonic_ns()
        need(time.monotonic() - started < OBSERVED_CALL_SECONDS,
            'original constituent observation returned after180seconds')
        verified = True
    except BaseException as error:
        failure = {'phase': phase, 'type': type(error).__name__, 'detail': str(error)[:2000]}
    finally:
        if before_fds is not None:
            try:
                cleanup = release_owned_verifier_lock(before_fds, lock_identity, lock_fd)
                if not cleanup['complete']:
                    verified = False
            except BaseException as error:
                verified = False
                cleanup = {'complete': False, 'error_type': type(error).__name__, 'detail': str(error)[:1000]}
        else:
            cleanup = {'complete': True, 'owned_resource_stage_entered': False, 'closed': [],
                'new_FDs_remaining': [], 'errors': []}
    observations = dict(OBSERVATION_PARTS) if OBSERVATION_PARTS else None
    if observations is not None:
        observations['returned_group_absence_originals'] = [row['original_observation']
            for row in GROUP_CALLS if row['returned']]
        observations['partial_unless_complete_observation_is_true'] = True
    signal_counts_known = all(row['returned'] and row['count_is_exact'] for row in GROUP_CALLS)
    completed_signal_zero = sum(row['signal_zero_completed_count'] or 0 for row in GROUP_CALLS)
    result = {'schema': 'hepta.native-guard.existing-head902-readonly-observation.v1',
        'state': 'EXISTING_PUBLISHED_HEAD_ORIGINALS_AND_FRESH_DYNAMIC_GATES_OBSERVED'
            if verified else 'EXISTING_HEAD_READONLY_OBSERVATION_FAILED_OR_PARTIAL',
        'label': LABEL, 'nonce': NONCE, 'boot_id': BOOT,
        'package': {'bytes': PACKAGE_PIN[0], 'sha256': PACKAGE_PIN[1]},
        'head': fixed['head'] if fixed else None,
        'host_audit_prerequisite': host,
        'host_prerequisite_scope': 'Externally verified actual host artifacts bound into reviewed source; not reread from phone',
        'adapter_source_provenance': 'Exact observer and caller bytes must be retained by the controller; original runtime is separately pinned',
        'original_runtime_entry_verify_current_calls': 0,
        'original_runtime_entry_verify_retired_calls': 0,
        'independently_identified_constituent_adapter': True,
        'original_constituent_callsites': CALLS, 'original_group_observation_calls': GROUP_CALLS,
        'completed_signal_zero_queries_in_returned_calls': completed_signal_zero,
        'all_entered_signal_zero_counts_exact': signal_counts_known,
        'failed_call_query_count_unknown': not signal_counts_known,
        'signal_zero_queries_successful_path_maximum': 58,
        'delivered_signals_requested': 0, 'explicit_nonzero_signal_calls': 0,
        'self_deadline_installed': False, 'trace_or_profile_installed': False,
        'post_return_observation_limit_seconds': OBSERVED_CALL_SECONDS,
        'hard_preemptive_deadline_claimed': False,
        'historical_lease_expiry_unchanged': LEASE_EXPIRES_UNIX_MS,
        'historical_lease_used_for_new_admission': False,
        'actual_native_context': native_context, 'original_readset': list(READSET.values()),
        'original_source_directories': list(DIRECTORIES.values()),
        'original_journal_lock': lock_observation, 'owned_fd_cleanup': cleanup,
        'failure': failure, 'complete_observation': verified,
        'observations': None, 'output_truncated': False,
        'atomic_global_snapshot_claimed': False, 'future_input_authorization': False,
        'observer_rebound_original_runtime_functions': False,
        'phone_content_writes': 0, 'runtime_main_calls': 0, 'process_launches': 0,
        'endpoint_connections': 0, 'model_requests': 0, 'native_sends': 0,
        'snapshot_calls': 0, 'boundary_publications': 0, 'new_nonce_or_lease': False,
        'old_mac_sender_capture_unknown_preserved': True,
        'component_qualified': False, 'business_qualified': False, 'case_pass': False,
        'automatic_retry': False}
    try:
        if observations is not None:
            result['observations'] = pack_original(encoded(observations))
        need(not verified or (len(GROUP_CALLS) == 4 and signal_counts_known
            and completed_signal_zero <= 58 and cleanup['complete']), 'complete dynamic observation accounting differs')
        need(not verified or time.monotonic() - started < OBSERVED_CALL_SECONDS,
            'complete report prepared after180seconds')
        result['total_wall_seconds'] = time.monotonic() - started
        raw = encoded(result)
        need(len(raw) <= OUTPUT_LIMIT, 'whole lossless observation exceeds one-MiB output budget')
    except BaseException as error:
        verified = False
        raw = encoded({'schema': result['schema'], 'state': 'OBSERVATION_SERIALIZATION_REJECTED',
            'label': LABEL, 'nonce': NONCE, 'complete_observation': False,
            'error_type': type(error).__name__, 'detail': str(error)[:1000],
            'original_constituent_callsites': CALLS, 'original_group_observation_calls': GROUP_CALLS,
            'owned_fd_cleanup': cleanup, 'complete_raw_observation_retained': False,
            'phone_content_writes': 0, 'native_sends': 0, 'boundary_publications': 0,
            'component_qualified': False, 'case_pass': False, 'automatic_retry': False})
        need(len(raw) <= OUTPUT_LIMIT, 'failure report exceeded fixed output budget')
    sys.stdout.write(raw.decode('ascii'))
    return 0 if verified else 1


if __name__ == '__main__':
    raise SystemExit(main())
