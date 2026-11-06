#!/usr/bin/env python3
"""P4-only explicit Root fixture phase through the unchanged reviewed Actor.

Default is a host preview. The execute flag runs only the actual provider's
hash-bound phase plan. NEG02 has an explicit setup prelude: open TextEntry,
observe its unique public editor, focus at the observed editor's center if
needed, then append a fresh ASCII marker. Every command/wire original remains
in a new directory; no model/tool success or native-worker qualification is
claimed for these UID2000 fixture actions.
"""
import argparse
import base64
import importlib.util
import os
from pathlib import Path
import re
import shlex
import sys
import time
import types

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import component_common as C
import component_listener as LISTENER
import native_guard_session_r2 as K
import witness_bundle as W
from prepare_component import host_read,write_new

ACTOR_SHA='1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'
CORE_SHA='705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'
TRANSPORT_SHA='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'


def pin(path,wanted,maximum=16*1024*1024):
    raw=host_read(path,maximum);C.need(C.sha(raw)==wanted,'explicit original pin differs: '+str(path));return raw


def module(path,raw,name):
    old=sys.modules.get(name)
    if old is not None:
        C.need(Path(old.__file__)==Path(path),'foreign module already imported: '+name)
        return old
    value=types.ModuleType(name);value.__file__=str(path);sys.modules[name]=value
    exec(compile(raw,str(path),'exec'),value.__dict__);return value


def inputs(a):
    tree=Path(a.material).absolute();lease_raw=pin(tree/'LEASE.json',a.lease_sha256)
    lease=C.strict(lease_raw);C.need(lease['schema']=='hepta.native-guard.lease.v1'
        and lease['package_sha256']==a.package_sha256,'one reviewed actual lease required')
    manifest_raw=pin(tree/'package/MANIFEST.json',a.package_sha256);manifest=C.strict(manifest_raw)
    C.need(manifest['schema']=='hepta.native-guard.adapter-package.v1'
        and manifest['state']=='HOST_REVIEWED_NOT_PHONE_QUALIFIED','reviewed adapter package required')
    rows=manifest['files'];C.need(5<=len(rows)<=32 and len({x['path'] for x in rows})==len(rows),'exact package set required')
    for row in rows:C.need(len(pin(tree/'package'/C.relative(row['path']),row['sha256']))==row['bytes'],'package original length differs')
    selected={x['path']:x for x in rows}
    C.need(selected['source/root_fixture_once.py']['sha256']==C.sha(host_read(Path(__file__))),
           'Root fixture entry is not the reviewed package source')
    reviewed=C.strict(host_read(tree/'package/reference/REVIEWED-PRODUCTION-PINS.json'))
    combo_raw=pin(tree/'inputs/COMBINATION.json',lease['combination']['sha256'])
    C.need(len(combo_raw)==lease['combination']['bytes'],'component combination byte size differs')
    combo,cfg=C.load_combination(tree/'inputs',combo_raw,reviewed,private_inputs=False)
    bound_raw=pin(a.bound_contract,a.bound_contract_sha256);bound=C.strict(bound_raw)
    accepted_raw=pin(a.accepted,a.accepted_sha256);accepted=C.strict(accepted_raw)
    plan_raw=pin(a.plan,a.plan_sha256,65536);plan,commands=W.validate_plan(plan_raw)
    C.need(bound['schema']=='hepta.native-guard.bound-contract.v1'
        and bound['lease_sha256']==a.lease_sha256
        and C.sha(C.encoded(bound['contract']))==plan['contract_sha256']==accepted['contract_sha256']
        and bound['contract']['source_seal_sha256']==combo['source_seal']['sha256']
        and bound['contract']['configuration_sha256']==combo['configuration']['sha256']
        and bound['contract']['case_id']==lease['case_id'] and bound['contract']['nonce']==lease['nonce']
        and bound['contract']['owner_request_sha256']==lease['owner_request_sha256']
        and accepted['scope']==plan['scope'],'actual accepted scope/contract/combination differs')
    C.need(all(plan['scope'][k]==lease['selected_'+k] for k in ('session_id','profile_id'))
        and plan['operation_id']==C.root_operation_id(plan['scope'],plan['contract_sha256'],plan['phase']),
        'actual phase identity differs')
    expected_dir=C.COMPONENT_EVIDENCE/bound['run_basename']
    C.need(accepted['run_dir']==str(expected_dir)
        and re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+lease['nonce'],bound['run_basename']),'actual accepted run differs')
    return tree,lease,combo,cfg,plan,commands


def frozen_actor(tree,lease,out,phone,guards):
    core_path=tree/'package/reference/component_core.py'
    module(core_path,pin(core_path,CORE_SHA),'component_core')
    actor_path=tree/'package/reference/component_once_r9.py'
    old=module(actor_path,pin(actor_path,ACTOR_SHA),'original_component_actor')
    # Deliberately do not call the historical constructor: it generates an
    # unrelated nonce and binds old r9 acceptance inputs. The reused methods
    # below remain the unchanged frozen original implementation.
    actor=old.Actor.__new__(old.Actor)
    actor.args=types.SimpleNamespace(expected_boot=lease['boot_id'])
    actor.out=out;actor.counter=actor.setup_counter=actor.host_counter=0
    actor.phone_stage='/data/local/tmp/hepta-native-guard-'+lease['nonce']
    actor.created=time.monotonic()
    actor.deadline=min(actor.created+180,actor.created+(lease['expires_unix_ms']/1000-time.time()))
    C.need(actor.deadline>actor.created,'actual fixture lease expired; no execution')
    raw=pin(old.F_SOURCE,TRANSPORT_SHA)
    actor.f=module(old.F_SOURCE,raw,'original_native_guard_adb_transport')
    actor.config=C.strict(host_read(old.F_SOURCE.parent/'preserved-ui-package-config.json'))
    actor.route=actor.f.route(actor.config)
    actor.phone=phone;actor.guards=guards
    return actor


def execution_files(actor,command,name,phase,lease):
    C.need(time.time()*1000<lease['expires_unix_ms'],'fixture lease expired before original command')
    actor.native_guard_fence()
    tag=phase+'-'+name;path=actor.out/(tag+'.command.sh');write_new(path,command)
    result_path,result=actor.execute_command(path,C.sha(command),tag,trace=False)
    uid=Path(result['execution_uid_original']['path'])
    paths={name:Path(result['stdout']['path']),name+'_stderr':Path(result['stderr']['path']),
        name+'_execution':result_path,name+'_wire':Path(result['raw_shell_v2_original']),
        name+'_command':path,name+'_uid':uid,name+'_uid_wire':uid.with_suffix('').with_suffix('.wire.json'),
        name+'_intent':actor.out/(tag+'.DISPATCH-INTENT.json')}
    raw={key:host_read(p,8*1024*1024) for key,p in paths.items()}
    LISTENER.verify_operator_execution(raw,name,raw[name],command,phase=phase,nonce=lease['nonce'],boot=lease['boot_id'])
    return paths,raw


def fixture_input_point(state):
    value=state[K.INPUT]
    C.need(value['class']=='android.widget.EditText' and value['focusable']=='true'
           and value['enabled']=='true' and value['visible-to-user']=='true' and value['password']=='false',
           'unique public editor is not eligible for Root setup focus')
    m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',value['bounds'])
    C.need(m is not None,'actual editor bounds absent');x1,y1,x2,y2=map(int,m.groups())
    x=(x1+x2)//2;y=(y1+y2)//2
    C.need(0<=x1<x<x2<=1224 and 0<=y1<y<y2<=2992,'no interior point in original editor bounds')
    return x,y


def fixture_mapping_context(modules,cfg):
    """Host-only command ingredients; phone execution retains its own checks.

    The configured executor tuple is checked without treating this P4 host as
    the phone filesystem. This object has no dispatch or semantic map method.
    The actual phone's unchanged readiness/lifecycle and native mapper still
    verify the eight external artifacts and the real executor client bytes.
    """
    local=modules['phone_local_tools'];phone=modules['phone_observation_tools']
    local.validate_executor(cfg['executor'],verify_files=False)
    return types.SimpleNamespace(apps=local.validate_apps(cfg['approved_apps']),
        _serial_guard=lambda:phone.PhoneTools._serial_guard(None),
        _focus_input_precondition=local.current_viewport_guard)


def text_prelude(actor,lease,plan,mapper,phone,guards):
    """Explicit setup only; never called during a capture/guard action."""
    C.need(plan['phase']=='setup' and lease['case_id']=='NEG-02','text prelude only before NEG02 capture')
    base=plan['operation_id'];serial=mapper._serial_guard();record=[]
    def token(name):return C.sha((base+':fixture:'+name).encode())[:32]
    def execute(name,command):
        paths,raw=execution_files(actor,command,'prelude-'+name,'setup',lease)
        record.append({'name':name,'command_sha256':C.sha(command),'files':{k:str(v) for k,v in paths.items()}})
        return raw['prelude-'+name]
    target=mapper.apps['Unicode验证']['component'];C.need(guards.component(target)==K.TEXT,'exact TextEntry probe component differs')
    opened=execute('open',guards.app_open_command(serial,target,token('open'),mapper._focus_input_precondition()).encode())
    guards.verify_app_open(C.strict(opened),token('open'),target)
    def observe(name):
        command=guards.public_text_command(serial,token(name),K.PACKAGE,actor.phone_stage+'/prelude-'+name+'.xml').encode()
        raw=execute(name,command);return K.public_state(raw,token(name),phone,guards)
    initial,page,viewport=observe('initial');old_text=initial[K.INPUT]['text']
    C.need(initial[K.RECEIPT]['text']=='等待输入','Root fixture must retain the original unsubmitted public receipt')
    focused=initial
    if initial[K.INPUT]['focused']!='true':
        x,y=fixture_input_point(initial)
        command=(serial+guards.page_equality_guard(page)
            +'[ "$(dumpsys display | grep \'mViewports=\')" = '+shlex.quote(viewport)+' ] || exit 68; '
            +'exec /system/bin/input tap '+str(x)+' '+str(y)).encode()
        execute('focus',command);focused,page,viewport=observe('focused')
    C.need(focused[K.INPUT]['focused']=='true' and focused[K.INPUT]['text']==old_text
        and focused[K.RECEIPT]==initial[K.RECEIPT] and focused[K.READBACK]==initial[K.READBACK],
        'actual Root setup focus changed content or did not focus the unique editor')
    marker='-fixture-'+lease['nonce'][:12]
    C.need(len((old_text+marker).encode())<=4096,'explicit fixture text exceeds public witness bound')
    command=(serial+guards.page_equality_guard(page)
        +'[ "$(dumpsys display | grep \'mViewports=\')" = '+shlex.quote(viewport)+' ] || exit 68; '
        +'/system/bin/input keyevent KEYCODE_MOVE_END || exit 78; '
        +'exec /system/bin/input text '+shlex.quote(marker)).encode()
    execute('append',command)
    return {'schema':'hepta.native-guard.root-text-fixture-prelude.v1','scope':plan['scope'],
        'contract_sha256':plan['contract_sha256'],'operation_id':base,'records':record,
        'initial_public_state':initial,'expected_final_input_text':old_text+marker,
        'focus_point_source':'center of the single visible original public EditText bounds',
        'maximum_focus_taps':1,'maximum_append_commands':1,'native_worker_qualification':False,
        'model_requests':0,'business_qualified':False,'automatic_retry':False}


def retain_actor_originals(actor,plan,a,paths,prelude,apk_before,apk_after):
    planned={str(p.absolute()):name for name,p in paths.items()};files={};total=0
    for p in sorted(actor.out.iterdir()):
        C.need(p.is_file() and not p.is_symlink(),'unexpected nested/aliased original Actor output')
        raw=host_read(p,8*1024*1024);total+=len(raw)
        C.need(total<=16*1024*1024 and len(files)<256,'full original Actor output byte/count bound')
        row={'source_path':str(p.absolute()),'source_metadata':C.metadata(p.lstat()),**C.descriptor(raw)}
        if str(p.absolute()) in planned:row['planned_file_key']=planned[str(p.absolute())]
        else:row['raw_b64']=base64.b64encode(raw).decode()
        files[p.name]=row
    value={'schema':'hepta.native-guard.root-actor-originals.v1','phase_plan_sha256':a.plan_sha256,
        'scope':plan['scope'],'contract_sha256':plan['contract_sha256'],'phase':plan['phase'],
        'frozen_actor_source_sha256':ACTOR_SHA,'frozen_core_source_sha256':CORE_SHA,
        'frozen_transport_source_sha256':TRANSPORT_SHA,'files':files,'fixture_prelude':prelude,
        'installed_probe_before':apk_before,'installed_probe_after':apk_after,
        'source_equals_apk_not_asserted':True,'uid2000_fixture_only_not_native_worker_qualification':True,
        'model_requests':0,'native_task_submissions':0,'automatic_retry':False}
    raw=C.encoded(value);C.need(len(raw)<=16*1024*1024,'actor-originals envelope byte bound')
    path=actor.out/'ACTOR-ORIGINALS.json';write_new(path,raw);return path


def run(a):
    os.umask(0o077);tree,lease,combo,cfg,plan,commands=inputs(a)
    if not a.execute_root_fixture_phase_once:
        print(C.encoded({'state':'HOST_ONLY_ROOT_FIXTURE_PREVIEW','phase_plan_sha256':a.plan_sha256,
            'phase':plan['phase'],'operation_id':plan['operation_id'],'execution_order':plan['execution_order'],
            'explicit_text_setup_prelude':plan['phase']=='setup' and lease['case_id']=='NEG-02',
            'phone_calls':0,'native_tasks':0,'model_requests':0,'nonces_generated':0}).decode(),end='');return 0
    out=Path(a.out).absolute();out.mkdir(mode=0o700)
    write_new(out/'ACTOR-ATTEMPT.json',C.encoded({'phase_plan_sha256':a.plan_sha256,'lease_sha256':a.lease_sha256,
        'scope':plan['scope'],'phase':plan['phase'],'state':'RESERVED_NO_AUTOMATIC_RETRY',
        'automatic_retry':False,'native_task_claim':False,'model_requests':0}))
    modules=C.import_production(tree/'inputs/production');phone=modules['phone_observation_tools'];guards=modules['phone_task_guards']
    mapper=fixture_mapping_context(modules,cfg)
    actor=frozen_actor(tree,lease,out,phone,guards);prelude=None;files={};apk_before=None
    fence_count=[0]
    def live_fence():
        fence_count[0]+=1
        home=C.BASE/'native-guard-r10-r1'/lease['label']
        argv=['/usr/bin/python3','-I','-B',str(home/'package/source/witness_bundle.py'),'fence',
            '--lease',str(home),'--lease-sha256',a.lease_sha256,'--phase',plan['phase'],
            '--phase-plan-sha256',a.plan_sha256,'--execute-read-only-fence']
        command='/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root '+shlex.join(argv)
        raw,wire=actor.read(actor.basic_guard()+'/debug_ramdisk/su -c '+shlex.quote(command),
                           'live-scope-fence-'+str(fence_count[0]),15)
        value=C.strict(raw)
        C.need(value.get('schema')=='hepta.native-guard.root-fixture-live-fence.v1'
            and value.get('state')=='ACTUAL_ACCEPTED_PHASE_STILL_LIVE'
            and value.get('phase_plan_sha256')==a.plan_sha256 and value.get('phase')==plan['phase']
            and value.get('scope')==plan['scope'] and value.get('contract_sha256')==plan['contract_sha256']
            and value.get('lease_sha256')==a.lease_sha256 and value.get('package_sha256')==a.package_sha256
            and value.get('boot_id')==lease['boot_id'] and value.get('ui_actions')==0,
            'actual current component phase not confirmed; no Root fixture execution')
        return value
    actor.native_guard_fence=live_fence
    try:
        live_fence()
        if plan['phase']=='setup':
            actor.read(actor.basic_guard()+'umask 077; mkdir '+shlex.quote(actor.phone_stage)
                +' && [ "$(stat -c %u:%a '+shlex.quote(actor.phone_stage)+')" = 2000:700 ]','reserve-fixture-stage')
        else:
            actor.read(actor.basic_guard()+'test -d '+shlex.quote(actor.phone_stage)+' && test ! -L '
                +shlex.quote(actor.phone_stage)+' && [ "$(stat -c %u:%a '+shlex.quote(actor.phone_stage)
                +')" = 2000:700 ]','verify-fixture-stage')
        apk_before=actor.probe_apk_identity('probe-before')
        if plan['phase']=='setup' and lease['case_id']=='NEG-02':prelude=text_prelude(actor,lease,plan,mapper,phone,guards)
        originals={}
        for name in plan['execution_order']:
            paths,raw=execution_files(actor,commands[name],name,plan['phase'],lease)
            files.update(paths);originals.update(raw)
        W.validate_files(plan,commands,originals,lease['nonce'],lease['boot_id'])
        if prelude is not None:
            final,page,viewport=K.public_state(originals['public'],plan['operation_id'],phone,guards)
            C.need(final[K.INPUT]['focused']=='true' and final[K.INPUT]['text']==prelude['expected_final_input_text']
                and final[K.RECEIPT]['text']=='等待输入' and final[K.READBACK]==prelude['initial_public_state'][K.READBACK],
                'Root setup final public readback differs; do not publish or retry')
        apk_after=actor.probe_apk_identity('probe-after');C.need(apk_after==apk_before,'installed public probe changed during fixture')
        evidence=retain_actor_originals(actor,plan,a,files,prelude,apk_before,apk_after)
        index={'schema':'hepta.native-guard.root-original-index.v1','phase_plan_sha256':a.plan_sha256,
            'files':{k:str(v.absolute()) for k,v in files.items()},'actor_originals_file':str(evidence),
            'frozen_actor_source_sha256':ACTOR_SHA,'frozen_transport_source_sha256':TRANSPORT_SHA}
        raw=C.encoded(index);write_new(out/'ORIGINAL-INDEX.json',raw)
        result={'state':'ROOT_FIXTURE_ORIGINALS_RETAINED_NOT_PUBLISHED','phase':plan['phase'],
            'original_index':{'path':str(out/'ORIGINAL-INDEX.json'),**C.descriptor(raw)},
            'component_qualified':False,'native_worker_qualification':False,'model_requests':0,
            'automatic_retry':False,'phone_stage_retained':actor.phone_stage}
        write_new(out/'RESULT.json',C.encoded(result));print(C.encoded(result).decode(),end='');return 0
    except BaseException as error:
        write_new(out/'FAILURE.json',C.encoded({'state':'ROOT_FIXTURE_FAILED_OR_UNKNOWN_ORIGINALS_RETAINED',
            'error_type':type(error).__name__,'detail':str(error)[:1024],'automatic_retry':False,
            'native_worker_qualification':False,'component_qualified':False,'model_requests':0}))
        raise


# Independent epoch fixture output domain. Historical Actor/core are not modified.
import hashlib
import json
import socket
import stat
import struct

EPOCH_FIXTURE_WRITER_SCHEMA = 'hepta.epoch.root-fixture-writer.v1'
EPOCH_FIXTURE_PNG_LIMIT = 1048576
EPOCH_FIXTURE_PUBLIC_LIMIT = 32768
EPOCH_FIXTURE_GENERIC_LIMIT = 16384
EPOCH_FIXTURE_PHASE_LIMITS = {'setup': {'stream': 163840, 'command': 65536, 'metadata': 65536, 'envelope': 262144, 'final': 65536, 'total': 622592}, 'before-guard': {'stream': 1146880, 'command': 65536, 'metadata': 65536, 'envelope': 131072, 'final': 65536, 'total': 1474560}, 'after-guard': {'stream': 65536, 'command': 32768, 'metadata': 65536, 'envelope': 131072, 'final': 65536, 'total': 360448}}
EPOCH_FIXTURE_DOMAIN_LIMITS = {'setup': {'generic': 65536, 'public': 98304, 'png': 0}, 'before-guard': {'generic': 65536, 'public': 32768, 'png': 1048576}, 'after-guard': {'generic': 32768, 'public': 32768, 'png': 0}}
EPOCH_FIXTURE_MAX_FILES = 256
EPOCH_FIXTURE_MAX_FRAMES = 4096
EPOCH_FIXTURE_MAX_WIRES = 96
EPOCH_FIXTURE_METADATA_FILE_LIMIT = 65536
EPOCH_FIXTURE_COMMAND_LIMIT = 32768
EPOCH_FIXTURE_WIRE_CONTROL_LIMIT = 262144
EPOCH_FIXTURE_CONTROL_PHASE_LIMIT = 1048576


def epoch_fixture_parent_fd(path):
    supplied = os.fspath(path)
    path = Path(path)
    C.need(path.is_absolute() and str(path) == supplied
           and '..' not in path.parts, 'canonical P4 fixture path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def epoch_fixture_read(path, maximum=8*1024*1024):
    C.need(type(maximum) is int and 0 <= maximum <= 16*1024*1024,
           'finite fixture original bound required')
    path = Path(path)
    parent, leaf = epoch_fixture_parent_fd(path)
    fd = None
    try:
        pm = C.metadata(os.fstat(parent))
        named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        C.need(stat.S_ISREG(named.st_mode) and named.st_nlink == 1
               and 0 <= named.st_size <= maximum, 'bounded regular fixture original required')
        fd = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        before = C.metadata(os.fstat(fd))
        C.need(before == C.metadata(named), 'fixture original changed before open')
        pieces = []
        total = 0
        while total <= named.st_size:
            part = os.read(fd, min(65536, named.st_size+1-total))
            if not part:
                break
            pieces.append(part)
            total += len(part)
        raw = b''.join(pieces)
        C.need(len(raw) == named.st_size and before == C.metadata(os.fstat(fd))
               == C.metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
               and C.metadata(os.fstat(parent)) == pm, 'fixture original full9 bookend differs')
        fresh, name = epoch_fixture_parent_fd(path)
        try:
            C.need(C.metadata(os.fstat(fresh)) == pm
                   and C.metadata(os.stat(name, dir_fd=fresh, follow_symlinks=False)) == before,
                   'fixture original canonical path changed')
        finally:
            os.close(fresh)
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def epoch_fixture_pin(path, wanted, maximum=16*1024*1024):
    raw = epoch_fixture_read(path, maximum)
    C.need(C.sha(raw) == wanted, 'epoch fixture pinned original differs: '+str(path))
    return raw


class EpochFixtureWriter:
    """One phase's shared, monotonic write admission; no per-wire pool reset."""
    def __init__(self, out, phase, binding):
        C.need(phase in EPOCH_FIXTURE_PHASE_LIMITS and type(binding) is dict,
               'explicit bound epoch phase required')
        self.out = Path(out)
        self.phase = phase
        self.binding = binding
        self.limits = dict(EPOCH_FIXTURE_PHASE_LIMITS[phase])
        self.charged = {name: 0 for name in self.limits}
        self.domain_limits = dict(EPOCH_FIXTURE_DOMAIN_LIMITS[phase])
        self.domain_charged = {name: 0 for name in self.domain_limits}
        self.files = {}
        self.frames = 0
        self.wires = []
        self.control_bytes = 0
        self.sealed = False
        self.root = None
        self.root_creation_attempted = False
        parent, leaf = epoch_fixture_parent_fd(self.out)
        try:
            self.root_creation_attempted = True
            os.mkdir(leaf, 0o700, dir_fd=parent)
            self.root = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
            st = os.fstat(self.root)
            C.need(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
                   and st.st_uid == os.getuid() and st.st_gid == os.getgid(),
                   'owned fixture output root differs')
            self.root_identity = C.metadata(st)[:6]
            os.fsync(self.root)
            os.fsync(parent)
        except BaseException:
            if self.root is not None:
                os.close(self.root)
                self.root = None
            raise
        finally:
            os.close(parent)

    def root_check(self):
        C.need(self.root is not None, 'fixture writer root closed')
        fresh, leaf = epoch_fixture_parent_fd(self.out)
        try:
            C.need(C.metadata(os.fstat(self.root))[:6] == self.root_identity
                   == C.metadata(os.stat(leaf, dir_fd=fresh, follow_symlinks=False))[:6],
                   'fixture writer directory identity changed')
        finally:
            os.close(fresh)

    def remaining(self, kind):
        C.need(kind in self.limits and kind != 'total', 'unknown writer charge domain')
        return min(self.limits[kind]-self.charged[kind], self.limits['total']-self.charged['total'])

    def charge(self, kind, count):
        C.need(not self.sealed and type(count) is int and count >= 0
               and count <= self.remaining(kind), 'epoch phase writer byte pool exhausted')
        self.charged[kind] += count
        self.charged['total'] += count

    def open(self, name, kind):
        self.root_check()
        C.need(not self.sealed and type(name) is str and 0 < len(name.encode()) <= 160
               and re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None and name not in ('.', '..')
               and name not in self.files and len(self.files) < EPOCH_FIXTURE_MAX_FILES,
               'fixture original name/count or one-use identity differs')
        C.need(kind in self.limits and kind != 'total', 'fixture file domain differs')
        row = {'name': name, 'kind': kind, 'fd': None, 'creation_attempted': True,
               'identity_registered': False, 'identity': None, 'written': 0, 'reserved': 0,
               'digest': hashlib.sha256(), 'closed': False, 'complete': False,
               'descriptor': None, 'close_error': None}
        self.files[name] = row
        try:
            row['fd'] = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=self.root)
            st = os.fstat(row['fd'])
            C.need(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
                   and st.st_nlink == 1 and st.st_uid == os.getuid() and st.st_gid == os.getgid()
                   and st.st_size == 0, 'new fixture file is not empty private regular inode')
            row['identity'] = C.metadata(st)
            C.need(row['identity'] == C.metadata(os.stat(name, dir_fd=self.root, follow_symlinks=False)),
                   'new fixture file path differs')
            row['identity_registered'] = True
            os.fsync(self.root)
            return row
        except BaseException:
            self.close_file(row, complete=False)
            raise

    def write_reserved(self, row, raw):
        C.need(self.files.get(row['name']) is row and type(raw) is bytes
               and row['written']+len(raw) <= row['reserved']
               and row['fd'] is not None and row['identity_registered']
               and not row['closed'], 'owned fixture file is not writable')
        self.root_check()
        held = C.metadata(os.fstat(row['fd']))
        C.need(held[:6] == row['identity'][:6] and held[6] == row['written']
               and held == C.metadata(os.stat(row['name'], dir_fd=self.root, follow_symlinks=False)),
               'fixture output inode/content changed before write')
        pending = memoryview(raw)
        while pending:
            wrote = os.write(row['fd'], pending)
            C.need(wrote > 0, 'fixture output write made no progress')
            row['written'] += wrote
            row['digest'].update(pending[:wrote])
            pending = pending[wrote:]

    def reserve_stream(self, row, count, domain):
        C.need(self.files.get(row['name']) is row and row['kind'] == 'stream'
               and domain in self.domain_limits and type(count) is int and count >= 0
               and self.domain_charged[domain]+count <= self.domain_limits[domain],
               'shared phase output-domain pool exhausted before payload read')
        self.charge('stream', count)
        self.domain_charged[domain] += count
        row['reserved'] += count

    def close_file(self, row, complete=False):
        if row['closed']:
            return row['descriptor']
        fd = row['fd']
        try:
            if fd is not None:
                os.fsync(fd)
                held = C.metadata(os.fstat(fd))
                C.need(row['identity_registered'] and held[:6] == row['identity'][:6]
                       and held[6] == row['written']
                       and held == C.metadata(os.stat(row['name'], dir_fd=self.root, follow_symlinks=False)),
                       'fixture output identity or actual length differs on close')
                os.lseek(fd, 0, os.SEEK_SET)
                digest = hashlib.sha256()
                total = 0
                while total <= row['written']:
                    raw = os.read(fd, min(65536, row['written']+1-total))
                    if not raw:
                        break
                    total += len(raw)
                    digest.update(raw)
                C.need(total == row['written'] and digest.hexdigest() == row['digest'].hexdigest()
                       and held == C.metadata(os.fstat(fd))
                       == C.metadata(os.stat(row['name'], dir_fd=self.root, follow_symlinks=False)),
                       'fixture owned output full-byte readback differs')
                self.root_check()
                row['descriptor'] = {'path': str(self.out/row['name']), 'bytes': total,
                                     'sha256': digest.hexdigest(), 'metadata': held}
                row['complete'] = bool(complete)
        except BaseException as error:
            row['close_error'] = {'type': type(error).__name__, 'detail': str(error)[:256]}
            raise
        finally:
            if fd is not None:
                os.close(fd)
                row['fd'] = None
            row['closed'] = True
        return row['descriptor']

    def put(self, path, value, kind='metadata', maximum=None):
        path = Path(path)
        C.need(path.parent == self.out, 'fixture writer cannot leave owned flat output')
        raw = value if type(value) is bytes else C.encoded(value)
        if maximum is None:
            maximum = EPOCH_FIXTURE_METADATA_FILE_LIMIT if kind in ('metadata', 'final') else self.limits[kind]
        C.need(type(maximum) is int and len(raw) <= maximum, 'serialized fixture file exceeds writer cap')
        self.charge(kind, len(raw))
        row = self.open(path.name, kind)
        row['reserved'] = len(raw)
        try:
            self.write_reserved(row, raw)
            return self.close_file(row, complete=True)
        except BaseException:
            if not row['closed']:
                self.close_file(row, complete=False)
            raise

    def read(self, path, maximum=8*1024*1024):
        return epoch_fixture_read(path, maximum)

    def control_charge(self, count):
        C.need(type(count) is int and count >= 0
               and self.control_bytes + count <= EPOCH_FIXTURE_CONTROL_PHASE_LIMIT,
               'shared epoch wire-control byte bound exceeded')
        self.control_bytes += count

    def seal(self):
        C.need(not self.sealed and all(row['closed'] and row['complete']
               and row['descriptor'] is not None for row in self.files.values()),
               'all actual fixture files must be complete before writer seal')
        self.root_check()
        C.need(sorted(os.listdir(self.root)) == sorted(self.files),
               'untracked fixture output file appeared')
        originals = {}
        for name, row in sorted(self.files.items()):
            raw = self.read(self.out/name)
            observed = row['descriptor']
            C.need(C.descriptor(raw) == {k: observed[k] for k in ('bytes', 'sha256')}
                   and C.metadata(os.stat(name, dir_fd=self.root, follow_symlinks=False)) == observed['metadata'],
                   'complete fixture prefix changed before writer seal')
            originals[name] = {'kind': row['kind'], 'reserved_bytes': row['reserved'],
                               'actual_written_bytes': row['written'], **observed}
        value = {'schema': EPOCH_FIXTURE_WRITER_SCHEMA,
            'state': 'ACTUAL_PHASE_OUTPUT_FILES_RETAINED_NOT_COMPONENT_QUALIFICATION',
            'binding': self.binding, 'phase': self.phase, 'limits': self.limits,
            'domain_limits': self.domain_limits,
            'charged_before_self': dict(self.charged),
            'domain_charged': dict(self.domain_charged),
            'phase_frames_charged': self.frames, 'wire_count': len(self.wires),
            'control_bytes_charged': self.control_bytes,
            'all_wire_receipts_terminal': all(row['error'] is None and row['exit_code'] is not None
                                             and row['socket_eof'] and row['socket_closed']
                                             for row in self.wires),
            'prefix_files': originals, 'self_file': 'OUTPUT-WRITER.original.json',
            'self_file_excluded_from_prefix': True,
            'self_raw_bytes_charged_separately_by_consumer': True,
            'charges_are_monotonic_reservations_not_refunded_actual_bytes': True,
            'automatic_retry': False, 'component_qualified': False,
            'native_worker_qualification': False, 'old_core_wire_function_executed': False}
        C.need(value['all_wire_receipts_terminal'], 'nonterminal fixture wire cannot be sealed')
        proof = self.put(self.out/'OUTPUT-WRITER.original.json', value, kind='final', maximum=131072)
        self.sealed = True
        self.root_check()
        C.need(sorted(os.listdir(self.root)) == sorted(self.files), 'writer final file set changed')
        return proof

    def close(self):
        errors = []
        for row in self.files.values():
            if not row['closed']:
                try:
                    self.close_file(row, complete=False)
                except BaseException as error:
                    errors.append({'name': row['name'], 'type': type(error).__name__})
        ambiguous = [row['name'] for row in self.files.values()
                     if row['creation_attempted'] and not row['identity_registered']]
        if self.root is not None:
            try:
                os.fsync(self.root)
            except BaseException as error:
                errors.append({'name': '.', 'type': type(error).__name__})
            finally:
                os.close(self.root)
                self.root = None
        return {'known_owned_fds_closed': all(r['fd'] is None for r in self.files.values()),
                'creation_registration_unknown': ambiguous, 'errors': errors,
                'owned_fd_cleanup_complete': not errors and not ambiguous}


def epoch_fixture_wire_exchange(actor, command, tag, prefix, seconds, domain):
    """Bounded successor: frame/control admission precedes payload reads and file writes."""
    writer = actor.epoch_writer
    C.need(type(command) is str and '\0' not in command
           and 0 < len(('shell,v2,raw:'+command).encode()) < 65536,
           'short epoch shell request required')
    C.need(type(seconds) is int and 1 <= seconds <= 60 and domain in ('generic', 'public', 'png'),
           'bounded explicit epoch wire domain required')
    C.need(len(writer.wires) < EPOCH_FIXTURE_MAX_WIRES, 'shared epoch wire count exhausted')
    limit = {'generic': EPOCH_FIXTURE_GENERIC_LIMIT, 'public': EPOCH_FIXTURE_PUBLIC_LIMIT,
             'png': EPOCH_FIXTURE_PNG_LIMIT}[domain]
    state = {'tag': tag, 'domain': domain, 'limit': limit, 'frames': [],
             'counts': {1: 0, 2: 0}, 'exit_code': None, 'socket_eof': False,
             'closed_stdin': False, 'error': None, 'last_header_b64': None,
             'control_bytes': 0, 'send_bytes_offered': 0, 'send_completion_unknown': False,
             'socket_creation_attempted': False, 'socket_identity_registered': False,
             'socket_closed': False, 'partial_frame': None,
             'partial_control': None, 'control_received_bytes': 0,
             'started_ns': time.monotonic_ns(), 'finished_ns': None}
    writer.wires.append(state)
    deadline = min(actor.deadline, time.monotonic()+seconds)
    stdout = stderr = sock = None
    completed = False
    receipt = None

    def bounded_socket():
        left = deadline-time.monotonic()
        C.need(left > 0, 'epoch shell absolute deadline exhausted')
        sock.settimeout(left)

    def receive_exact(count, control=False, capture=None):
        C.need(type(count) is int and 0 <= count <= max(EPOCH_FIXTURE_PNG_LIMIT, 65536),
               'bounded receive size required')
        if control:
            C.need(state['control_bytes']+count <= EPOCH_FIXTURE_WIRE_CONTROL_LIMIT,
                   'one epoch wire-control byte limit exceeded')
            writer.control_charge(count)
            state['control_bytes'] += count
            state['partial_control'] = {'expected_bytes': count, 'raw': b''}
        pieces = []
        done = 0
        while done < count:
            bounded_socket()
            raw = sock.recv(min(65536, count-done))
            if not raw:
                state['socket_eof'] = True
                raise ValueError('epoch shell EOF inside a required record')
            done += len(raw)
            if control:
                state['control_received_bytes'] += len(raw)
                state['partial_control']['raw'] += raw
            if capture is None:
                pieces.append(raw)
            else:
                writer.write_reserved(capture, raw)
            if state['partial_frame'] is not None:
                state['partial_frame']['received_bytes'] = done
                state['partial_frame']['digest'].update(raw)
        result = b''.join(pieces)
        if control:
            state['partial_control'] = None
        return result

    def smart_request(value):
        raw = value.encode()
        C.need(0 < len(raw) < 65536, 'bounded exact smart-socket request')
        request = ('%04x' % len(raw)).encode()+raw
        C.need(state['control_bytes']+len(request) <= EPOCH_FIXTURE_WIRE_CONTROL_LIMIT,
               'wire request control budget exhausted')
        writer.control_charge(len(request))
        state['control_bytes'] += len(request)
        state['send_bytes_offered'] += len(request)
        state['send_completion_unknown'] = True
        bounded_socket()
        sock.sendall(request)
        state['send_completion_unknown'] = False
        reply = receive_exact(4, control=True)
        if reply == b'OKAY':
            return
        if reply == b'FAIL':
            size_raw = receive_exact(4, control=True)
            C.need(re.fullmatch(b'[0-9a-fA-F]{4}', size_raw) is not None,
                   'invalid smart FAIL length')
            body = receive_exact(int(size_raw, 16), control=True)
            state['smart_failure'] = {'length_header_b64': base64.b64encode(size_raw).decode(),
                                      'raw_b64': base64.b64encode(body).decode(), **C.descriptor(body)}
            raise ValueError('actual smart-socket FAIL retained')
        state['smart_reply_b64'] = base64.b64encode(reply).decode()
        raise ValueError('unexpected smart-socket reply retained')

    try:
        stdout = writer.open(prefix.name+'.stdout.bin', 'stream')
        stderr = writer.open(prefix.name+'.stderr.bin', 'stream')
        state['socket_creation_attempted'] = True
        sock = socket.create_connection(('127.0.0.1', actor.route[0]), timeout=min(seconds, 5))
        state['socket_identity_registered'] = True
        smart_request('host:transport-id:'+str(actor.route[1]))
        smart_request('shell,v2,raw:'+command)
        while state['exit_code'] is None:
            C.need(writer.frames < EPOCH_FIXTURE_MAX_FRAMES,
                   'shared epoch shell frame count exhausted before header read')
            header = receive_exact(5, control=True)
            writer.frames += 1
            stream, length = struct.unpack('<BI', header)
            state['last_header_b64'] = base64.b64encode(header).decode()
            C.need(stream in (1, 2, 3, 4), 'unexpected epoch shell stream type')
            if stream in (1, 2):
                C.need(sum(state['counts'].values())+length <= limit,
                       'epoch wire domain limit exceeded before payload read')
                writer.reserve_stream(stdout if stream == 1 else stderr, length, domain)
            elif stream == 3:
                C.need(length in (1, 4), 'epoch EXIT length differs')
            else:
                C.need(length == 0 and not state['closed_stdin'], 'epoch CLOSE_STDIN differs')
            state['partial_frame'] = {'stream': stream, 'declared_bytes': length,
                                      'received_bytes': 0, 'digest': hashlib.sha256()}
            if stream in (1, 2):
                receive_exact(length, capture=stdout if stream == 1 else stderr)
                state['counts'][stream] += length
                payload = None
            else:
                payload = receive_exact(length, control=True)
            digest = state['partial_frame']['digest'].hexdigest()
            state['frames'].append({'stream': stream, 'bytes': length, 'sha256': digest})
            state['partial_frame'] = None
            if stream == 3:
                code = int.from_bytes(payload, 'little')
                C.need(0 <= code <= 255, 'actual epoch EXIT code differs')
                state['exit_code'] = code
            elif stream == 4:
                state['closed_stdin'] = True
        # EXIT is necessary but not sufficient: retain actual EOF at the same deadline.
        bounded_socket()
        writer.control_charge(1)
        state['control_bytes'] += 1
        trailing = sock.recv(1)
        state['control_received_bytes'] += len(trailing)
        if trailing:
            state['partial_control'] = {'expected_bytes': 0, 'raw': trailing}
        C.need(trailing == b'', 'epoch data appeared after terminal EXIT')
        state['socket_eof'] = True
        C.need(time.monotonic() <= deadline, 'epoch output terminal exceeded phase deadline')
        completed = True
    except BaseException as error:
        state['error'] = {'type': type(error).__name__, 'detail': str(error)[:1024]}
        raise
    finally:
        cleanup_errors = []
        if sock is not None:
            try:
                sock.close()
                state['socket_closed'] = True
            except BaseException as error:
                cleanup_errors.append({'operation': 'socket_close', 'type': type(error).__name__})
        streams = {}
        for label, row in (('stdout', stdout), ('stderr', stderr)):
            if row is not None:
                try:
                    streams[label] = writer.close_file(row, complete=completed)
                except BaseException as error:
                    cleanup_errors.append({'operation': label+'_close', 'type': type(error).__name__})
                    streams[label] = row['descriptor']
            else:
                streams[label] = None
        partial = state['partial_frame']
        if partial is not None:
            partial = {k: v for k, v in partial.items() if k != 'digest'} | {
                'received_sha256': state['partial_frame']['digest'].hexdigest()}
        state['finished_ns'] = time.monotonic_ns()
        partial_control = state['partial_control']
        if partial_control is not None:
            partial_control = {'expected_bytes': partial_control['expected_bytes'],
                               'raw_b64': base64.b64encode(partial_control['raw']).decode(),
                               **C.descriptor(partial_control['raw'])}
        receipt = {'schema': 'hepta.epoch.operator-raw-shell-v2.v1', 'command': command,
            'command_utf8_sha256': C.sha(command.encode()),
            'wire_request_bytes': len(('shell,v2,raw:'+command).encode()),
            'address': ['127.0.0.1', actor.route[0]], 'transport_id': str(actor.route[1]),
            'p4_monotonic_started_ns': state['started_ns'], 'p4_monotonic_finished_ns': state['finished_ns'],
            'exit_code': state['exit_code'], 'original_exit_frame_received': state['exit_code'] is not None,
            'output_complete': completed and not cleanup_errors,
            'socket_eof_observed': state['socket_eof'], 'socket_closed': state['socket_closed'],
            'socket_creation_attempted': state['socket_creation_attempted'],
            'socket_identity_registered': state['socket_identity_registered'],
            'frames': state['frames'], 'frame_count': len(state['frames']),
            'domain': domain, 'domain_output_limit': limit,
            'control_bytes_charged': state['control_bytes'],
            'phase_control_bytes_charged': writer.control_bytes,
            'phase_frames_charged': writer.frames,
            'phase_writer_charges': dict(writer.charged),
            'phase_domain_charges': dict(writer.domain_charged),
            'last_header_b64': state['last_header_b64'], 'partial_frame': partial,
            'partial_control': partial_control,
            'control_received_bytes': state['control_received_bytes'],
            'smart_failure': state.get('smart_failure'), 'smart_reply_b64': state.get('smart_reply_b64'),
            'send_bytes_offered': state['send_bytes_offered'],
            'send_completion_unknown': state['send_completion_unknown'],
            'error': state['error'], 'cleanup_errors': cleanup_errors,
            'automatic_retry': False, 'explicit_signal_calls': 0,
            'socket_close_may_affect_remote_process': True,
            'phone_process_join_or_cleanup_proven': False,
            'old_core_wire_function_executed': False,
            'epoch_writer_binding': writer.binding, **streams}
        try:
            writer.put(prefix.with_suffix('.wire.json'), receipt, maximum=EPOCH_FIXTURE_METADATA_FILE_LIMIT)
        except BaseException as record_error:
            # The original error is retained even if the complete frame JSON cannot
            # fit its remaining serialization pool. This is never a complete wire.
            serialized = C.encoded(receipt)
            compact = {'schema': 'hepta.epoch.fixture-wire-record-refusal.v1',
                'state': 'WIRE_ORIGINALS_PARTIAL_METADATA_NOT_COMPLETELY_RETAINED',
                'original_wire_error': state['error'],
                'record_error': {'type': type(record_error).__name__, 'detail': str(record_error)[:512]},
                'serialized_receipt_body_retained': False,
                'serialized_receipt': C.descriptor(serialized), 'frame_count': len(state['frames']),
                'exit_code': state['exit_code'], 'socket_eof_observed': state['socket_eof'],
                'socket_closed': state['socket_closed'], 'streams': streams,
                'writer_charges': dict(writer.charged), 'domain_charges': dict(writer.domain_charged),
                'automatic_retry': False, 'phone_process_join_or_cleanup_proven': False}
            writer.put(prefix.with_suffix('.WIRE-RECORD-REFUSAL.json'), compact, kind='final', maximum=16384)
            raise
    C.need(receipt['output_complete'], 'epoch wire cleanup is not complete')
    return receipt


def epoch_inputs(a):
    tree=Path(a.material).absolute();epoch_fixture_bootstrap(tree)
    lease_raw=epoch_fixture_pin(tree/'LEASE.json',a.lease_sha256)
    lease=C.strict(lease_raw);C.need(lease['schema']=='hepta.native-guard.epoch-lease.v1'
        and lease['package_sha256']==a.package_sha256,'one reviewed actual epoch lease required')
    C.epoch_lease_protocol_value(lease)
    manifest_raw=epoch_fixture_pin(tree/'package/MANIFEST.json',a.package_sha256);manifest=C.strict(manifest_raw)
    C.need(manifest['schema']=='hepta.native-guard.adapter-package.v1'
        and manifest['state']=='HOST_REVIEWED_NOT_PHONE_QUALIFIED','reviewed adapter package required')
    rows=manifest['files'];C.need(len(rows)==32 and len({x['path'] for x in rows})==len(rows),'exact package set required')
    for row in rows:C.need(len(epoch_fixture_pin(tree/'package'/C.relative(row['path']),row['sha256']))==row['bytes'],'package original length differs')
    selected={x['path']:x for x in rows}
    C.need(selected['source/root_fixture_once.py']['sha256']==C.sha(epoch_fixture_read(Path(__file__))),
           'Root fixture entry is not the reviewed package source')
    reviewed=C.strict(epoch_fixture_read(tree/'package/reference/REVIEWED-PRODUCTION-PINS.json'))
    combo_raw=epoch_fixture_pin(tree/'inputs/COMBINATION.json',lease['combination']['sha256'])
    C.need(len(combo_raw)==lease['combination']['bytes'],'component combination byte size differs')
    combo,cfg=C.load_combination(tree/'inputs',combo_raw,reviewed,private_inputs=False,actual_context='p4')
    bound_raw=epoch_fixture_pin(a.bound_contract,a.bound_contract_sha256);bound=C.strict(bound_raw)
    accepted_raw=epoch_fixture_pin(a.accepted,a.accepted_sha256);accepted=C.strict(accepted_raw)
    plan_raw=epoch_fixture_pin(a.plan,a.plan_sha256,32768);plan,commands=W.validate_plan(plan_raw)
    C.need(bound['schema']=='hepta.native-guard.bound-contract.v1'
        and bound['lease_sha256']==a.lease_sha256
        and C.sha(C.encoded(bound['contract']))==plan['contract_sha256']==accepted['contract_sha256']
        and bound['contract']['source_seal_sha256']==combo['source_seal']['sha256']
        and bound['contract']['configuration_sha256']==combo['configuration']['sha256']
        and bound['contract']['case_id']==lease['case_id'] and bound['contract']['nonce']==lease['nonce']
        and bound['contract']['owner_request_sha256']==lease['owner_request_sha256']
        and accepted['scope']==plan['scope'],'actual accepted scope/contract/combination differs')
    C.need(all(plan['scope'][k]==lease['selected_'+k] for k in ('session_id','profile_id'))
        and plan['operation_id']==C.root_operation_id(plan['scope'],plan['contract_sha256'],plan['phase']),
        'actual phase identity differs')
    expected_dir=C.COMPONENT_EVIDENCE/bound['run_basename']
    C.need(accepted['run_dir']==str(expected_dir)
        and re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+lease['nonce'],bound['run_basename']),'actual accepted run differs')
    a._epoch_writer_admission=epoch_fixture_admission(lease,plan)
    return tree,lease,combo,cfg,plan,commands

def epoch_frozen_actor(tree,lease,out,phone,guards,writer):
    core_path=tree/'package/reference/component_core.py'
    module(core_path,epoch_fixture_pin(core_path,CORE_SHA),'component_core')
    actor_path=tree/'package/reference/component_once_r9.py'
    old=module(actor_path,epoch_fixture_pin(actor_path,ACTOR_SHA),'original_component_actor')
    # Deliberately do not call the historical constructor: it generates an
    # unrelated nonce and binds old r9 acceptance inputs. The reused methods
    # below remain the unchanged frozen original implementation.
    epoch_type=epoch_actor_type(old);actor=epoch_type.__new__(epoch_type)
    actor.args=types.SimpleNamespace(expected_boot=lease['boot_id'])
    actor.out=out;actor.counter=actor.setup_counter=actor.host_counter=0
    actor.phone_stage='/data/local/tmp/hepta-native-guard-'+lease['nonce']
    actor.created=time.monotonic()
    actor.deadline=min(actor.created+180,actor.created+(lease['expires_unix_ms']/1000-time.time()))
    C.need(actor.deadline>actor.created,'actual fixture lease expired; no execution')
    raw=epoch_fixture_pin(old.F_SOURCE,TRANSPORT_SHA)
    actor.f=module(old.F_SOURCE,raw,'original_native_guard_adb_transport')
    actor.config=C.strict(epoch_fixture_read(old.F_SOURCE.parent/'preserved-ui-package-config.json'))
    actor.route=actor.f.route(actor.config)
    actor.phone=phone;actor.guards=guards
    actor.epoch_writer=writer;actor.epoch_wire_domains={}
    return actor

def epoch_execution_files(actor,command,name,phase,lease):
    C.need(time.time()*1000<lease['expires_unix_ms'],'fixture lease expired before original command')
    actor.native_guard_fence()
    tag=phase+'-'+name;path=actor.out/(tag+'.command.sh');actor.epoch_writer.put(path,command,kind='command',maximum=EPOCH_FIXTURE_COMMAND_LIMIT)
    actor.epoch_wire_domains[tag+'-execute']=('png' if name=='png' else 'public' if name in ('public','prelude-initial','prelude-focused') else 'generic')
    result_path,result=actor.execute_command(path,C.sha(command),tag,trace=False)
    uid=Path(result['execution_uid_original']['path'])
    paths={name:Path(result['stdout']['path']),name+'_stderr':Path(result['stderr']['path']),
        name+'_execution':result_path,name+'_wire':Path(result['raw_shell_v2_original']),
        name+'_command':path,name+'_uid':uid,name+'_uid_wire':uid.with_suffix('').with_suffix('.wire.json'),
        name+'_intent':actor.out/(tag+'.DISPATCH-INTENT.json')}
    raw={key:epoch_fixture_read(p,8*1024*1024) for key,p in paths.items()}
    LISTENER.verify_epoch_operator_execution(raw,name,raw[name],command,phase=phase,nonce=lease['nonce'],boot=lease['boot_id'])
    return paths,raw

def epoch_text_prelude(actor,lease,plan,mapper,phone,guards):
    """Explicit setup only; never called during a capture/guard action."""
    C.need(plan['phase']=='setup' and lease['case_id']=='NEG-02','text prelude only before NEG02 capture')
    base=plan['operation_id'];serial=mapper._serial_guard();record=[]
    def token(name):return C.sha((base+':fixture:'+name).encode())[:32]
    def execute(name,command):
        paths,raw=epoch_execution_files(actor,command,'prelude-'+name,'setup',lease)
        record.append({'name':name,'command_sha256':C.sha(command),'files':{k:str(v) for k,v in paths.items()}})
        return raw['prelude-'+name]
    target=mapper.apps['Unicode验证']['component'];C.need(guards.component(target)==K.TEXT,'exact TextEntry probe component differs')
    opened=execute('open',guards.app_open_command(serial,target,token('open'),mapper._focus_input_precondition()).encode())
    guards.verify_app_open(C.strict(opened),token('open'),target)
    def observe(name):
        command=guards.public_text_command(serial,token(name),K.PACKAGE,actor.phone_stage+'/prelude-'+name+'.xml').encode()
        raw=execute(name,command);return K.public_state(raw,token(name),phone,guards)
    initial,page,viewport=observe('initial');old_text=initial[K.INPUT]['text']
    C.need(initial[K.RECEIPT]['text']=='等待输入','Root fixture must retain the original unsubmitted public receipt')
    focused=initial
    if initial[K.INPUT]['focused']!='true':
        x,y=fixture_input_point(initial)
        command=(serial+guards.page_equality_guard(page)
            +'[ "$(dumpsys display | grep \'mViewports=\')" = '+shlex.quote(viewport)+' ] || exit 68; '
            +'exec /system/bin/input tap '+str(x)+' '+str(y)).encode()
        execute('focus',command);focused,page,viewport=observe('focused')
    C.need(focused[K.INPUT]['focused']=='true' and focused[K.INPUT]['text']==old_text
        and focused[K.RECEIPT]==initial[K.RECEIPT] and focused[K.READBACK]==initial[K.READBACK],
        'actual Root setup focus changed content or did not focus the unique editor')
    marker='-fixture-'+lease['nonce'][:12]
    C.need(len((old_text+marker).encode())<=4096,'explicit fixture text exceeds public witness bound')
    command=(serial+guards.page_equality_guard(page)
        +'[ "$(dumpsys display | grep \'mViewports=\')" = '+shlex.quote(viewport)+' ] || exit 68; '
        +'/system/bin/input keyevent KEYCODE_MOVE_END || exit 78; '
        +'exec /system/bin/input text '+shlex.quote(marker)).encode()
    execute('append',command)
    return {'schema':'hepta.native-guard.root-text-fixture-prelude.v1','scope':plan['scope'],
        'contract_sha256':plan['contract_sha256'],'operation_id':base,'records':record,
        'initial_public_state':initial,'expected_final_input_text':old_text+marker,
        'focus_point_source':'center of the single visible original public EditText bounds',
        'maximum_focus_taps':1,'maximum_append_commands':1,'native_worker_qualification':False,
        'model_requests':0,'business_qualified':False,'automatic_retry':False}

def epoch_fixture_profile(phase):
    C.need(phase in EPOCH_FIXTURE_PHASE_LIMITS, 'exact epoch phase profile required')
    return {'schema': 'hepta.epoch.fixture-output-profile.v2',
        'phase': phase, 'writer_schema': EPOCH_FIXTURE_WRITER_SCHEMA,
        'phase_limits': dict(EPOCH_FIXTURE_PHASE_LIMITS[phase]),
        'phase_domain_limits': dict(EPOCH_FIXTURE_DOMAIN_LIMITS[phase]),
        'wire_domain_limits': {'generic': EPOCH_FIXTURE_GENERIC_LIMIT,
                               'public': EPOCH_FIXTURE_PUBLIC_LIMIT, 'png': EPOCH_FIXTURE_PNG_LIMIT},
        'phase_files': EPOCH_FIXTURE_MAX_FILES, 'phase_frames': EPOCH_FIXTURE_MAX_FRAMES,
        'phase_wires': EPOCH_FIXTURE_MAX_WIRES,
        'metadata_file_bytes': EPOCH_FIXTURE_METADATA_FILE_LIMIT,
        'command_file_bytes': EPOCH_FIXTURE_COMMAND_LIMIT,
        'wire_control_bytes': EPOCH_FIXTURE_WIRE_CONTROL_LIMIT,
        'phase_control_bytes': EPOCH_FIXTURE_CONTROL_PHASE_LIMIT,
        'actor_envelope_bytes': EPOCH_FIXTURE_PHASE_LIMITS[phase]['envelope'],
        'writer_proof_bytes': 131072, 'index_bytes': 65536,
        'result_bytes': 8192, 'failure_bytes': 8192,
        'parent_stdout_bytes': 65536, 'parent_stderr_bytes': 65536,
        'parent_terminal_bytes': 262144, 'parent_summary_bytes': 4096,
        'parent_metadata_pool_bytes': 262144, 'parent_complete_output_pool_bytes': 524288,
        'parent_raw_stream_pool_bytes': 262144, 'parent_raw_stream_files': 4,
        'parent_raw_pool_includes_two_failure_prefix_fallback_files': True,
        'parent_capture_runs': 1, 'parent_metadata_files': 16,
        'shared_phase_pool_not_reset_per_wire': True,
        'witness_plan_bytes': 32768, 'witness_provenance_bytes': 65536,
        'witness_mailbox_bytes': 16384,
        'source_profile_is_not_case_capacity_admission': True}


def epoch_fixture_bootstrap(tree):
    bootstrap = getattr(C, 'epoch_fixture_bootstrap', None)
    C.need(callable(bootstrap), 'full actual P4 package bootstrap unavailable; no epoch output')
    bootstrap(tree, 'p4')
    C.need(globals().get('__actual_context__') == 'p4'
           and C.epoch_actual_context(globals()) == 'p4',
           'actual P4 context and reviewed package injection required')
    source_files = globals().get('__reviewed_package_sources__')
    manifest_raw = globals().get('__reviewed_package_manifest_raw__')
    C.need(type(source_files) is dict and len(source_files) == 32 and type(manifest_raw) is bytes,
           'complete actual manifest and all 32 original sources required')
    C.need(source_files.get('source/root_fixture_once.py') == epoch_fixture_read(Path(__file__)),
           'actual fixture source is not the complete reviewed package original')
    return manifest_raw, source_files


def epoch_fixture_admission(lease, plan):
    admission = getattr(C, 'epoch_fixture_writer_admission', None)
    C.need(callable(admission), 'actual case resource reservation admission unavailable')
    profile = epoch_fixture_profile(plan['phase'])
    result = admission(lease, plan, profile)
    C.need(type(result) is dict and 0 < len(C.encoded(result)) <= 65536,
           'complete bound writer admission original required')
    # The common owner checks its exact evolving reservation protocol. This
    # caller records the entire actual return, never substitutes a boolean.
    return result


def epoch_actor_type(original):
    class EpochActor(original.Actor):
        def raw(self, command, tag, seconds=30):
            C.need(re.fullmatch('[a-z0-9-]{1,64}', tag) is not None, 'epoch wire tag differs')
            remaining = int(self.deadline-time.monotonic())
            C.need(remaining >= 1, 'actual fixture lease or total 180-second bound exhausted')
            seconds = min(seconds, remaining)
            self.counter += 1
            prefix = self.out/('wire-%03d-%s' % (self.counter, tag))
            domain = self.epoch_wire_domains.get(tag, 'generic')
            self.epoch_writer.put(prefix.with_suffix('.INTENT.json'), {
                'schema': 'hepta.epoch.fixture-wire-intent.v1', 'command': command,
                'wire_request_bytes': len(('shell,v2,raw:'+command).encode()),
                'p4_monotonic_ns': time.monotonic_ns(), 'automatic_retry': False,
                'domain': domain, 'writer_binding': self.epoch_writer.binding})
            C.need(self.f.route(self.config) == self.route, 'existing ADB route changed; no redispatch')
            return epoch_fixture_wire_exchange(self, command, tag, prefix, seconds, domain)

        def read(self, command, tag, seconds=30):
            result = self.raw(command, tag, seconds)
            C.need(result['exit_code'] == 0 and result['output_complete'] is True
                   and result['socket_eof_observed'] is True and result['stderr']['bytes'] == 0,
                   'actual epoch read has no complete clean terminal: '+tag)
            return self.epoch_writer.read(Path(result['stdout']['path'])), result

        def execute_command(self, command_file, command_sha, tag, trace=False, page=None, viewport=None,
                            effect_deadline=None):
            command = self.epoch_writer.read(command_file, 128 * 1024)
            C.need(C.sha(command) == command_sha and b'\0' not in command, 'reserved command bytes differ')
            destination = self.phone_stage + '/' + tag + '.sh'
            uid_file = self.phone_stage + '/' + tag + '.uid'
            intent = self.out / (tag + '.DISPATCH-INTENT.json')
            self.epoch_writer.put(intent, {'command': str(command_file), 'command_sha256': command_sha,
                'phone_command_path': destination, 'uid_original_path': uid_file,
                'trace': trace, 'state': 'RESERVED_MAY_BE_UNKNOWN', 'automatic_retry': False,
                'model_requests': 0, 'native_task_claim': False})
            absent = self.basic_guard() + 'test ! -e ' + shlex.quote(destination) + ' && test ! -L ' + shlex.quote(destination)
            self.read(absent, tag + '-stage-absent')
            if effect_deadline is not None:
                C.need(time.monotonic() < effect_deadline, 'captured image expired before original sync')
            # Original AOSP sync transport sends data frames, never an oversized shell command.
            self.f.push(command_file, destination, self.config, self.route)
            self.epoch_writer.put(self.out / (tag + '.SYNC.json'), {'state': 'ORIGINAL_SYNC_SEND_OKAY', 'path': destination,
                'source_sha256': command_sha, 'bytes': len(command), 'automatic_retry': False})
            if effect_deadline is not None:
                C.need(time.monotonic() < effect_deadline, 'captured image expired before original shell dispatch')
            wire = self.basic_guard() + 'umask 077; set -C; '
            wire += 'test -f ' + shlex.quote(destination) + ' && test ! -L ' + shlex.quote(destination) + ' || exit 78; '
            wire += '[ "$(stat -c %u ' + shlex.quote(destination) + ')" = 2000 ] || exit 78; '
            wire += '[ "$(sha256sum ' + shlex.quote(destination) + " | cut -d ' ' -f 1)\" = " + shlex.quote(command_sha) + ' ] || exit 78; '
            wire += 'chmod 0400 ' + shlex.quote(destination) + ' || exit 78; '
            wire += 'id -u >' + shlex.quote(uid_file) + ' || exit 78; '
            wire += '[ "$(cat ' + shlex.quote(uid_file) + ')" = 2000 ] || exit 78; '
            if page is not None:
                wire += self.guards.page_equality_guard(page)
            if viewport is not None:
                wire += '[ "$(dumpsys display | grep \'mViewports=\')" = ' + shlex.quote(viewport) + ' ] || exit 78; '
            wire += 'exec /system/bin/sh ' + ('-x ' if trace else '') + shlex.quote(destination)
            seconds = 45
            if effect_deadline is not None:
                seconds = min(seconds, int(effect_deadline - time.monotonic()))
                C.need(seconds >= 1, 'captured image expired before original shell dispatch')
            original = self.raw(wire, tag + '-execute', seconds)
            if effect_deadline is not None:
                C.need(original['p4_monotonic_finished_ns'] <= int(effect_deadline * 1_000_000_000),
                     'original guarded command did not terminate within capture age')
            uid_raw, uid_receipt = self.read(self.basic_guard() + 'cat ' + shlex.quote(uid_file), tag + '-actual-uid')
            C.need(uid_raw == b'2000\n', 'actual component shell execution UID differs')
            value = {'schema': 'hepta.epoch.operator-command-execution.v1', 'command_sha256': command_sha,
                'execution_uid': 2000, 'execution_uid_original': uid_receipt['stdout'],
                'exit_code': original['exit_code'], 'output_complete': original['output_complete'],
                'stdout': original['stdout'], 'stderr': original['stderr'], 'dispatch_count': 1,
                'automatic_retry': False, 'native_task_claim': False, 'model_requests': 0,
                'operator_shell_trace': trace, 'raw_shell_v2_original': str(Path(original['stdout']['path']).with_suffix('').with_suffix('.wire.json'))}
            path = self.out / (tag + '.EXECUTION.json')
            self.epoch_writer.put(path, value)
            return path, value

        def probe_apk_identity(self, tag):
            raw, _ = self.read(self.basic_guard() + 'pm path ' + shlex.quote(K.PACKAGE), tag + '-paths')
            lines = raw.decode('utf-8', 'strict').splitlines()
            C.need(1 <= len(lines) <= 16 and all(x.startswith('package:/data/app/') and x.endswith('.apk') for x in lines),
                 'actual public probe package paths differ')
            paths = sorted(x[len('package:'):] for x in lines)
            C.need(len(set(paths)) == len(paths), 'duplicate probe APK path')
            identities = []
            for index, path in enumerate(paths):
                command = self.basic_guard() + 'stat -c %s ' + shlex.quote(path) + ' && sha256sum ' + shlex.quote(path)
                raw, _ = self.read(command, tag + '-apk-' + str(index))
                rows = raw.decode('utf-8', 'strict').splitlines()
                C.need(len(rows) == 2 and rows[0].isdigit() and 0 < int(rows[0]) <= 100 * 1024 * 1024 and
                     re.fullmatch('[0-9a-f]{64}  ' + re.escape(path), rows[1]) is not None,
                     'actual public probe APK original hash differs')
                identities.append({'path': path, 'bytes': int(rows[0]), 'sha256': rows[1][:64]})
            self.epoch_writer.put(self.out / (tag + '.json'), {'installed_public_package': K.PACKAGE, 'apks': identities,
                'source_equals_apk_not_asserted': True})
            return identities

    return EpochActor


def epoch_retain_actor_originals(actor, plan, a, paths, prelude, apk_before, apk_after):
    writer = actor.epoch_writer
    writer.root_check()
    C.need(sorted(os.listdir(writer.root)) == sorted(writer.files),
           'actual actor contains an untracked output')
    planned = {str(p.absolute()): name for name, p in paths.items()}
    files = {}
    total = 0
    for name, row in sorted(writer.files.items()):
        C.need(row['closed'] and row['complete'] and row['descriptor'] is not None,
               'actor prefix file not completely retained')
        path = writer.out/name
        raw = writer.read(path)
        total += len(raw)
        observed = row['descriptor']
        C.need(C.descriptor(raw) == {k: observed[k] for k in ('bytes', 'sha256')}
               and C.metadata(path.lstat()) == observed['metadata'], 'actual actor prefix changed')
        value = {'source_path': str(path), 'source_metadata': observed['metadata'], **C.descriptor(raw)}
        if str(path) in planned:
            value['planned_file_key'] = planned[str(path)]
        else:
            value['raw_b64'] = base64.b64encode(raw).decode()
        files[name] = value
    C.need(total <= writer.limits['total'], 'actual actor prefix exceeds phase total')
    value = {'schema': 'hepta.epoch.root-actor-originals.v1',
        'phase_plan_sha256': a.plan_sha256, 'scope': plan['scope'],
        'contract_sha256': plan['contract_sha256'], 'phase': plan['phase'],
        'actor_reference_source_sha256': ACTOR_SHA, 'core_reference_source_sha256': CORE_SHA,
        'route_transport_reference_source_sha256': TRANSPORT_SHA,
        'epoch_adapter_source': C.descriptor(globals()['__reviewed_package_sources__']['source/root_fixture_once.py']),
        'old_core_wire_function_executed': False, 'original_actor_methods_modified_in_place': False,
        'writer_binding': writer.binding, 'writer_profile': epoch_fixture_profile(plan['phase']),
        'files': files, 'fixture_prelude': prelude,
        'installed_probe_before': apk_before, 'installed_probe_after': apk_after,
        'source_equals_apk_not_asserted': True,
        'uid2000_fixture_only_not_native_worker_qualification': True,
        'model_requests': 0, 'native_task_submissions': 0, 'automatic_retry': False}
    raw = C.encoded(value)
    path = actor.out/'ACTOR-ORIGINALS.json'
    writer.put(path, raw, kind='envelope', maximum=writer.limits['envelope'])
    return path


def epoch_fixture_live_fence(actor, lease, plan, a, fence_count):
    fence_count[0] += 1
    home = C.BASE/'native-guard-r10-r1'/lease['label']
    argv = ['/usr/bin/python3', '-I', '-B', str(home/'package/source/witness_bundle.py'), 'fence',
        '--lease', str(home), '--lease-sha256', a.lease_sha256, '--phase', plan['phase'],
        '--phase-plan-sha256', a.plan_sha256, '--execute-read-only-fence']
    command = '/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root '+shlex.join(argv)
    raw, _wire = actor.read(actor.basic_guard()+'/debug_ramdisk/su -c '+shlex.quote(command),
                            'live-scope-fence-'+str(fence_count[0]), 15)
    value = C.strict(raw)
    C.need(value.get('schema') == 'hepta.native-guard.root-fixture-live-fence.v1'
        and value.get('state') == 'ACTUAL_ACCEPTED_PHASE_STILL_LIVE'
        and value.get('phase_plan_sha256') == a.plan_sha256 and value.get('phase') == plan['phase']
        and value.get('scope') == plan['scope'] and value.get('contract_sha256') == plan['contract_sha256']
        and value.get('lease_sha256') == a.lease_sha256 and value.get('package_sha256') == a.package_sha256
        and value.get('boot_id') == lease['boot_id'] and value.get('ui_actions') == 0,
        'actual current component phase not confirmed; no Root fixture execution')
    return value


def run_epoch(a):
    os.umask(0o077)
    tree, lease, combo, cfg, plan, commands = epoch_inputs(a)
    if not a.execute_root_fixture_phase_once:
        value = {'schema': 'hepta.epoch.root-fixture-preview.v1',
            'state': 'HOST_ONLY_EPOCH_FIXTURE_PREVIEW', 'phase_plan_sha256': a.plan_sha256,
            'phase': plan['phase'], 'writer_profile': epoch_fixture_profile(plan['phase']),
            'writer_admission': C.descriptor(C.encoded(a._epoch_writer_admission)),
            'phone_calls': 0, 'native_tasks': 0, 'model_requests': 0, 'nonces_generated': 0}
        raw = C.encoded(value)
        C.need(len(raw) <= 4096, 'bounded epoch preview')
        print(raw.decode(), end='')
        return 0
    out = Path(a.out).absolute()
    binding = {'schema': 'hepta.epoch.fixture-writer-binding.v1',
        'lease_sha256': a.lease_sha256, 'package_sha256': a.package_sha256,
        'phase_plan_sha256': a.plan_sha256,
        'adapter_source': C.descriptor(globals()['__reviewed_package_sources__']['source/root_fixture_once.py']),
        'admission': C.descriptor(C.encoded(a._epoch_writer_admission)),
        'profile': C.descriptor(C.encoded(epoch_fixture_profile(plan['phase'])))}
    writer = EpochFixtureWriter(out, plan['phase'], binding)
    actor = None
    try:
        writer.put(out/'WRITER-ADMISSION.original.json', a._epoch_writer_admission, maximum=65536)
        writer.put(out/'ACTOR-ATTEMPT.json', {
            'phase_plan_sha256': a.plan_sha256, 'lease_sha256': a.lease_sha256,
            'scope': plan['scope'], 'phase': plan['phase'], 'state': 'RESERVED_NO_AUTOMATIC_RETRY',
            'automatic_retry': False, 'native_task_claim': False, 'model_requests': 0,
            'writer_binding': binding, 'writer_profile': epoch_fixture_profile(plan['phase'])})
        modules = C.import_production(tree/'inputs/production', actual_context='p4')
        phone = modules['phone_observation_tools']
        guards = modules['phone_task_guards']
        mapper = fixture_mapping_context(modules, cfg)
        actor = epoch_frozen_actor(tree, lease, out, phone, guards, writer)
        prelude = None
        files = {}
        fence_count = [0]
        actor.native_guard_fence = lambda: epoch_fixture_live_fence(actor, lease, plan, a, fence_count)
        actor.native_guard_fence()
        if plan['phase'] == 'setup':
            actor.read(actor.basic_guard()+'umask 077; mkdir '+shlex.quote(actor.phone_stage)
                +' && [ "$(stat -c %u:%a '+shlex.quote(actor.phone_stage)+')" = 2000:700 ]', 'reserve-fixture-stage')
        else:
            actor.read(actor.basic_guard()+'test -d '+shlex.quote(actor.phone_stage)+' && test ! -L '
                +shlex.quote(actor.phone_stage)+' && [ "$(stat -c %u:%a '+shlex.quote(actor.phone_stage)
                +')" = 2000:700 ]', 'verify-fixture-stage')
        apk_before = actor.probe_apk_identity('probe-before')
        if plan['phase'] == 'setup' and lease['case_id'] == 'NEG-02':
            prelude = epoch_text_prelude(actor, lease, plan, mapper, phone, guards)
        originals = {}
        for name in plan['execution_order']:
            paths, raw = epoch_execution_files(actor, commands[name], name, plan['phase'], lease)
            files.update(paths)
            originals.update(raw)
        W.validate_epoch_files(plan, commands, originals, lease['nonce'], lease['boot_id'])
        if prelude is not None:
            final, _page, _viewport = K.public_state(originals['public'], plan['operation_id'], phone, guards)
            C.need(final[K.INPUT]['focused'] == 'true' and final[K.INPUT]['text'] == prelude['expected_final_input_text']
                and final[K.RECEIPT]['text'] == '等待输入'
                and final[K.READBACK] == prelude['initial_public_state'][K.READBACK],
                'Root setup final public readback differs; do not publish or retry')
        apk_after = actor.probe_apk_identity('probe-after')
        C.need(apk_after == apk_before, 'installed public probe changed during fixture')
        evidence = epoch_retain_actor_originals(actor, plan, a, files, prelude, apk_before, apk_after)
        index = {'schema': 'hepta.epoch.root-original-index.v1', 'phase_plan_sha256': a.plan_sha256,
            'files': {key: str(path.absolute()) for key, path in files.items()},
            'actor_originals_file': str(evidence), 'writer_proof_file': str(out/'OUTPUT-WRITER.original.json'),
            'result_file': str(out/'RESULT.json'), 'writer_binding': binding,
            'epoch_adapter_source': binding['adapter_source']}
        raw = C.encoded(index)
        index_desc = writer.put(out/'ORIGINAL-INDEX.json', raw, kind='final', maximum=65536)
        result = {'schema': 'hepta.epoch.root-fixture-result.v1',
            'state': 'EPOCH_ROOT_FIXTURE_ORIGINALS_RETAINED_NOT_PUBLISHED', 'phase': plan['phase'],
            'original_index': {k: index_desc[k] for k in ('path', 'bytes', 'sha256')},
            'writer_proof_file': str(out/'OUTPUT-WRITER.original.json'),
            'writer_binding': binding, 'component_qualified': False, 'native_worker_qualification': False,
            'model_requests': 0, 'automatic_retry': False, 'phone_stage_retained': actor.phone_stage}
        result_desc = writer.put(out/'RESULT.json', result, kind='final', maximum=8192)
        proof = writer.seal()
        summary = {'schema': 'hepta.epoch.root-fixture-summary.v1', 'state': result['state'],
            'result': {k: result_desc[k] for k in ('path', 'bytes', 'sha256')},
            'writer_proof': {k: proof[k] for k in ('path', 'bytes', 'sha256')},
            'component_qualified': False, 'automatic_retry': False}
        raw = C.encoded(summary)
        C.need(len(raw) <= 4096, 'bounded epoch child summary required')
        print(raw.decode(), end='')
        return 0
    except BaseException as error:
        if not writer.sealed:
            failure = {'schema': 'hepta.epoch.root-fixture-failure.v1',
                'state': 'EPOCH_ROOT_FIXTURE_FAILED_OR_UNKNOWN_ORIGINALS_RETAINED',
                'error_type': type(error).__name__, 'detail': str(error)[:1024],
                'writer_binding': binding, 'writer_charges': dict(writer.charged),
                'domain_charges': dict(writer.domain_charged),
                'automatic_retry': False, 'native_worker_qualification': False,
                'component_qualified': False, 'model_requests': 0,
                'phone_process_terminal_or_cleanup_claimed': False}
            try:
                writer.put(out/'FAILURE.json', failure, kind='final', maximum=8192)
            except BaseException as retention_error:
                print(C.encoded({'state': 'EPOCH_FAILURE_RETENTION_INCOMPLETE',
                    'original_error': type(error).__name__, 'retention_error': type(retention_error).__name__}).decode(),
                    file=sys.stderr, end='')
        raise
    finally:
        closed = writer.close()
        C.need(closed['owned_fd_cleanup_complete'] is True,
               'fixture writer FD cleanup incomplete: '+repr(closed))


def main():
    p=argparse.ArgumentParser()
    for name in ('material','lease-sha256','package-sha256','plan','plan-sha256','bound-contract',
                 'bound-contract-sha256','accepted','accepted-sha256','out'):p.add_argument('--'+name,required=True)
    p.add_argument('--execute-root-fixture-phase-once',action='store_true')
    a=p.parse_args()
    observed=C.strict(epoch_fixture_pin(Path(a.material).absolute()/'LEASE.json',a.lease_sha256))
    if observed.get('schema')=='hepta.native-guard.epoch-lease.v1':return run_epoch(a)
    return run(a)


if __name__=='__main__':raise SystemExit(main())
