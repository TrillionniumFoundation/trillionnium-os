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
import hashlib
import stat
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
TRANSPORT_SHA='06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0'


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
    rows=manifest['files'];C.need(len(rows)==38 and len({x['path'] for x in rows})==len(rows),'exact package set required')
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


def _transport_config_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def _read_pinned_transport_config(path, expected_size, expected_sha256):
    # One descriptor, bounded bytes, same verified bytes consumed by json.loads.
    # A failed read admits no route, helper execution or device effect.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_size != expected_size):
            raise RuntimeError('transport_config_file_identity_or_size_mismatch_before_route')
        chunks = []
        received = 0
        while received < expected_size + 1:
            chunk = os.read(descriptor, expected_size + 1 - received)
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if (_transport_config_identity(before) != _transport_config_identity(after)
                or _transport_config_identity(after) != _transport_config_identity(named)):
            raise RuntimeError('transport_config_changed_during_read_before_route')
        if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise RuntimeError('transport_config_byte_pin_mismatch_before_route')
        return raw
    finally:
        os.close(descriptor)


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
    transport_path=Path('/home/alex/codex-razr60-r6-followthrough-20261107/deadline/candidate/preserved_ui_package_phase_r7.py')
    raw=pin(transport_path,TRANSPORT_SHA)
    config_raw=_read_pinned_transport_config(Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved-ui-package-config.json'), 2416, '310dd82101f2ab309cd790d03f0c01e40cbdfef7064510ea4120327aaac72fef')
    actor.f=module(transport_path,raw,'original_native_guard_adb_transport')
    actor.config=C.strict(config_raw)
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


def main():
    p=argparse.ArgumentParser()
    for name in ('material','lease-sha256','package-sha256','plan','plan-sha256','bound-contract',
                 'bound-contract-sha256','accepted','accepted-sha256','out'):p.add_argument('--'+name,required=True)
    p.add_argument('--execute-root-fixture-phase-once',action='store_true')
    return run(p.parse_args())


if __name__=='__main__':raise SystemExit(main())
