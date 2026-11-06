"""Pure command derivation for the reviewed installer and readiness entries.

No operation is dispatched here. Publication, BUILD, labels, requests, and original
process records must be bound separately before the public reader can qualify.
"""
import base64
import hashlib
import json
from pathlib import PurePosixPath
import re
import shlex

BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
GNU = '/var/lib/trillionnium/owner-open/phone-local-v150'
P4 = '/home/alex/razr60-local-model-v150'
READY = GNU + '/provider-r10-r1/collect_r10_readiness.py'
ACTOR_PIN = {'bytes': 5652, 'sha256': '179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'}
INSTALLER_PIN = {'bytes': 34100, 'sha256': '22a04f452d86a1d02e66b227acfc12e3e119fe4fdc9b0d39b5656a415bc9d40b'}
READY_PIN = {'bytes': 16407, 'sha256': '8fcf151ebeeeeaa38f0d8e057b4340f7c681f402d6a5a9670ca95f79737935e5'}
RECEIPT_PREFIX = b'HEPTA_INSTALL_READY_SOURCE_EXECUTION_V1 '
PHASES = ('stage', 'start', 'ready')
PLAN_SCHEMA = 'hepta.production.install-start-ready.execution-plan.v1'
HASH = re.compile('[0-9a-f]{64}')
MAX_WIRE_EXCLUSIVE = 65536
# Exact full environment prefix from original current44 REQUEST d8bcef88.
GNU_EXEC_PREFIX = ["/data/adb/magisk/busybox","env","-i","PATH=/usr/bin:/bin:/usr/libexec/trillionnium","PYTHONHOME=/usr","PYTHONDONTWRITEBYTECODE=1","LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu","LANG=C.UTF-8","LC_ALL=C.UTF-8","TMPDIR=/var/lib/trillionnium/owner-open/tmp","NO_COLOR=1","TERM=dumb","/data/adb/magisk/busybox","chroot","/data/trillionnium/owner-open/root","/usr/bin/python3","-I","-B","-c"]

def need(ok, message):
    if not ok:
        raise ValueError(message)

def exact(value, fields, message):
    need(type(value) is dict and set(value) == set(fields), message)
    return value

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()

def request_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode()

def path(value):
    need(type(value) is str and value and not any(c in value for c in '\0\r\n\t'), 'plain absolute path')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts, 'canonical absolute path')
    return p

def pin(row, maximum):
    exact(row, ('path', 'bytes', 'sha256'), 'exact source/artifact descriptor')
    path(row['path'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= maximum
         and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'bounded complete pin')
    return {key: row[key] for key in ('bytes', 'sha256')}

def validate_plan(plan, release, release_inputs):
    exact(plan, ('schema', 'boot_id', 'release_id', 'release_inputs_sha256', 'actor',
                 'actor_python', 'actor_cwd', 'archive', 'installer', 'phases'), 'exact one-use execution plan')
    need(plan['schema'] == PLAN_SCHEMA and plan['boot_id'] == BOOT
         and plan['release_id'] == 'v150-r10-r1', 'selected boot and release')
    need(type(plan['release_inputs_sha256']) is str and HASH.fullmatch(plan['release_inputs_sha256']),
         'actual release input pin')
    need(pin(plan['actor'], 65536) == ACTOR_PIN
         and PurePosixPath(P4) in path(plan['actor']['path']).parents,
         'exact retained original actor under the established P4 project')
    need(plan['actor_python'] == '/usr/bin/python3' and plan['actor_cwd'] == P4,
         'explicit established P4 interpreter and project')
    need(pin(plan['installer'], 262144) == INSTALLER_PIN
         and PurePosixPath(GNU) in path(plan['installer']['path']).parents,
         'exact original installer in an explicitly published GNU path')
    need(pin(plan['archive'], 64 * 1024 * 1024) ==
         {k: release_inputs['release_archive'][k] for k in ('bytes', 'sha256')},
         'phone archive must contain the actual independently verified BUILD bytes')
    need(path(plan['archive']['path']).parent == path(plan['installer']['path']).parent
         and plan['archive']['path'] != plan['installer']['path'],
         'explicit common private delivery directory')
    exact(plan['phases'], PHASES, 'exact ordered stage, start and READY phases')
    labels, requests, keys = set(), set(), set()
    for name in PHASES:
        row = exact(plan['phases'][name], ('label', 'request_path', 'idempotency_key', 'timeout_seconds'),
                    'exact phase identity')
        need(type(row['label']) is str and re.fullmatch('[A-Za-z0-9_-]{1,100}', row['label']),
             'original actor label syntax')
        need(PurePosixPath(P4) in path(row['request_path']).parents, 'private retained request namespace')
        need(type(row['idempotency_key']) is str and 1 <= len(row['idempotency_key'].encode()) <= 128,
             'finite original controller identity')
        need(type(row['timeout_seconds']) is int and 1 <= row['timeout_seconds'] <= 300,
             'unchanged original actor shell timeout ceiling')
        labels.add(row['label']); requests.add(row['request_path']); keys.add(row['idempotency_key'])
    need(len(labels) == len(requests) == len(keys) == 3, 'three distinct one-use identities')
    need(release['phone_ready'] is False and release['whole_case_pass'] is False,
         'host BUILD must not claim installation or READY')
    return plan

# The guard changes no reviewed entry body. It emits one separate stderr receipt,
# installs only a finite pre-exec timer, and then executes the exact original source.
# Its time is part of the original actor operation timeout, never an added lease.
GUARD = r'''import base64,hashlib,json,os,select,signal,stat,sys,time
def need(ok,message):
 if not ok:raise ValueError(message)
def pairs(rows):
 v={}
 for k,x in rows:
  need(k not in v,'duplicate guard key');v[k]=x
 return v
def sha(b):return hashlib.sha256(b).hexdigest()
def preserve_cleanup(action):
 primary=sys.exc_info()[1]
 try:action()
 except BaseException as cleanup:
  if primary is not None:raise primary from cleanup
  raise
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def meta(s):return[getattr(s,k)for k in META]
def read_regular(name,maximum):
 a=os.lstat(name)
 need(stat.S_ISREG(a.st_mode)and a.st_uid==a.st_gid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=maximum,'private complete entry source')
 fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  need(meta(os.fstat(fd))==meta(a),'entry original FD')
  raw=bytearray()
  while True:
   b=os.read(fd,min(65536,maximum+1-len(raw)))
   if not b:break
   raw.extend(b);need(len(raw)<=maximum,'entry source byte limit')
  need(len(raw)==a.st_size and meta(os.fstat(fd))==meta(os.lstat(name))==meta(a),'entry source full9 bookends')
  return bytes(raw),meta(a)
 finally:preserve_cleanup(lambda:os.close(fd))
def identity():
 with open('/proc/self/stat','rb')as f:raw=f.read(4097)
 need(0<len(raw)<=4096,'bounded original proc stat')
 left,sep,right=raw.rpartition(b') ');fields=right.split()
 need(sep and b' ('in left and len(fields)>=20,'complete original proc fields')
 result=[int(left.split(b' ',1)[0]),int(fields[1]),int(fields[2]),int(fields[3]),int(fields[19])]
 need(result[:4]==[os.getpid(),os.getppid(),os.getpgrp(),os.getsid(0)]and min(result)>0,'same process identity view')
 return result,raw
need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'root entry guard')
need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'preserve existing timer')
started=time.monotonic_ns();deadline=time.monotonic()+10
def expired(*unused):raise TimeoutError('original source guard pre-exec deadline')
old=signal.getsignal(signal.SIGALRM);signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,10)
try:
 spec=json.loads(base64.b64decode(SPEC,validate=True),object_pairs_hook=pairs)
 need(set(spec)=={'schema','boot_id','phase','source','argv'}and spec['schema']=='hepta.production.install-ready.entry-spec.v1','exact entry spec')
 with open('/proc/sys/kernel/random/boot_id','rb')as f:boot_raw=f.read(128)
 need(0<len(boot_raw)<128,'bounded original boot identity')
 boot=boot_raw.decode().strip()
 need(boot==spec['boot_id'],'same actual boot')
 body,metadata=read_regular(spec['source']['path'],262144)
 need(len(body)==spec['source']['bytes']and sha(body)==spec['source']['sha256'],'complete selected entry bytes')
 before,raw_before=identity();after,raw_after=identity();need(before==after,'self identity bookends')
 receipt={'schema':'hepta.production.install-ready.entry-original.v1','boot_id':boot,'phase':spec['phase'],'source':dict(spec['source'],metadata=metadata),'argv':spec['argv'],'identity':before,'proc_before_base64':base64.b64encode(raw_before).decode(),'proc_after_base64':base64.b64encode(raw_after).decode(),'started_monotonic_ns':started,'observed_monotonic_ns':time.monotonic_ns(),'source_bytes_verified':True,'exec_started_here':False,'independent_parent_wait_claimed':False}
 out=b'HEPTA_INSTALL_READY_SOURCE_EXECUTION_V1 '+(json.dumps(receipt,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
 need(len(out)<=8192,'bounded source receipt')
 blocking=os.get_blocking(2);os.set_blocking(2,False)
 try:
  offset=0
  while offset<len(out):
   remain=deadline-time.monotonic();need(remain>0,'source receipt deadline')
   unused,writable,exceptional=select.select([],[2],[2],remain)
   need(writable and not exceptional,'source receipt FD ready')
   try:n=os.write(2,out[offset:])
   except(InterruptedError,BlockingIOError):continue
   need(n>0,'source receipt write');offset+=n
 finally:preserve_cleanup(lambda:os.set_blocking(2,blocking))
 need(time.monotonic()<deadline,'guard complete before deadline')
finally:
 def restore_timer():
  try:signal.setitimer(signal.ITIMER_REAL,0)
  finally:preserve_cleanup(lambda:signal.signal(signal.SIGALRM,old))
 preserve_cleanup(restore_timer)
sys.argv=spec['argv']
exec(compile(body,spec['source']['path'],'exec'),{'__name__':'__main__','__file__':spec['source']['path']})
'''

def expected_phase(plan, phase, release, release_inputs, retirement_sha256):
    need(phase in PHASES and HASH.fullmatch(retirement_sha256), 'known phase and actual retirement')
    selected = plan['phases'][phase]
    pins = release['release_pins']
    if phase in ('stage', 'start'):
        source = dict(plan['installer'])
        argv = [source['path'], '--archive', plan['archive']['path'], '--archive-sha256',
                plan['archive']['sha256'], '--retirement-sha256', retirement_sha256,
                '--component-boundary-inputs-sha256', pins['component_boundary_inputs_sha256'],
                '--policy-adoption-inputs-sha256', pins['policy_adoption_inputs_sha256'],
                '--phase', phase, '--execute-reviewed-operation-once']
    else:
        source = dict(path=READY, **READY_PIN)
        argv = [READY, '--expected-boot', BOOT,
                '--source-seal-sha256', pins['source_seal_sha256'],
                '--configuration-sha256', pins['configuration_sha256'],
                '--module-manifest-sha256', pins['module_manifest_sha256'],
                '--component-boundary-inputs-sha256', pins['component_boundary_inputs_sha256'],
                '--policy-adoption-inputs-sha256', pins['policy_adoption_inputs_sha256']]
    spec = dict(schema='hepta.production.install-ready.entry-spec.v1', boot_id=BOOT,
                phase=phase, source=source, argv=argv)
    bootstrap = 'SPEC=' + repr(base64.b64encode(canonical(spec)).decode()) + '\n' + GUARD
    compile(bootstrap, '<reviewed-install-ready-original-entry-guard>', 'exec')
    # Keep the complete actual GNU environment, without extra shell actions.
    command = shlex.join(GNU_EXEC_PREFIX + [bootstrap])
    wrapped = '/debug_ramdisk/su -c ' + shlex.quote(command)
    wire = ('shell,v2,raw:' + wrapped).encode()
    need(len(wire) < MAX_WIRE_EXCLUSIVE, 'unchanged ADB service byte ceiling')
    request = dict(kind='shell', root=True, timeout_seconds=selected['timeout_seconds'], command=command)
    dispatch = dict(host='pocket4', executable=plan['actor_python'],
                    args=['-I', '-B', plan['actor']['path'], selected['label'], selected['request_path']],
                    cwd=plan['actor_cwd'], idempotency_key=selected['idempotency_key'])
    return dict(spec=spec, request=request, request_raw=request_bytes(request), dispatch=dispatch,
                wrapped_command=wrapped, wire_bytes=len(wire),
                actor_operation_dir=P4 + '/operations/' + selected['label'])
