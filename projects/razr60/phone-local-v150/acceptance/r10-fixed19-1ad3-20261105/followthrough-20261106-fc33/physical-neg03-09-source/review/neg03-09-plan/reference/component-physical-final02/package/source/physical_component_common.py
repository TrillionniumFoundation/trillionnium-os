#!/usr/bin/env python3
"""Pure source admission, fixed physical request recipes, and receipt parsing."""
import ast
import base64
import copy
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import sys
import time
import types
import zlib

B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
DIRECT_SHA='915f57d98934f216179806beefc213986df83e255e402c6d8a8f34fea6d123f0'
CONTEXT_SHA='2f5e6169f66017bee29b32a4f05d9cb8a0936e01c36b7b1f59aa015ba1ffb02d'
ACTIVE_SHA='f1a68fcc420799a7221019afdcda046a8d297b23d674e1e2642e888df26635dd'
FIXTURE_SHA='3cbc0d9d77629c2183f706fc897075a16952e4cb586f16fef29a65e521c81487'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_ORIGINAL=64*1024*1024
MAX_PNG=16*1024*1024
PIN_KEYS={'source_seal_sha256','configuration_sha256','service_inputs_sha256',
    'module_manifest_sha256','component_boundary_inputs_sha256','policy_adoption_inputs_sha256'}


def need(value,message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def desc(path,raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def b64(raw):
    return base64.b64encode(raw).decode()


def decode(value,maximum):
    need(isinstance(value,str) and len(value)<=4*((maximum+2)//3),'bounded base64 string required')
    raw=base64.b64decode(value,validate=True)
    need(len(raw)<=maximum and b64(raw)==value,'canonical bounded base64 required')
    return raw


class Originals:
    def __init__(self):
        self.seen={}
    def read(self,row,maximum=MAX_ORIGINAL):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
            and 0<=row['bytes']<=maximum and isinstance(row['sha256'],str)
            and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact bounded descriptor required')
        p=Path(row['path'])
        need(p.is_absolute() and '..' not in p.parts and p.resolve(strict=True)==p,'canonical original required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],
                'single-link regular original differs')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw=stream.read(row['bytes']+1)
            metadata=tuple(getattr(before,k) for k in META)
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and
                metadata==tuple(getattr(os.fstat(fd),k) for k in META)
                ==tuple(getattr(p.lstat(),k) for k in META),'original bytes or identity changed')
        finally:
            os.close(fd)
        record={'descriptor':copy.deepcopy(row),'metadata':metadata}
        need(str(p) not in self.seen or self.seen[str(p)]==record,'original changed across reads')
        self.seen[str(p)]=record
        return raw
    def known(self,path,maximum=MAX_ORIGINAL):
        p=Path(path)
        need(p.is_absolute() and p.resolve(strict=True)==p,'canonical discovered original required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,
                'bounded discovered regular original required')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw=stream.read(before.st_size+1)
            metadata=tuple(getattr(before,k) for k in META)
            need(len(raw)==before.st_size and metadata==tuple(getattr(os.fstat(fd),k) for k in META)
                ==tuple(getattr(p.lstat(),k) for k in META),'discovered original changed')
        finally:
            os.close(fd)
        row=desc(p,raw)
        record={'descriptor':row,'metadata':metadata}
        need(str(p) not in self.seen or self.seen[str(p)]==record,'discovered original changed across reads')
        self.seen[str(p)]=record
        return row,raw
    def recheck(self):
        for record in list(self.seen.values()):
            self.read(record['descriptor'])


def relative(name):
    p=Path(name)
    need(isinstance(name,str) and str(p)==name and not p.is_absolute()
        and '..' not in p.parts and name not in ('','.'),'canonical relative member required')
    return p


def module(raw,path,name):
    m=types.ModuleType(name)
    m.__file__=str(path)
    m.__reviewed_source_sha256__=sha(raw)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    return m


def load_members(originals,row,field='files'):
    raw=originals.read(row,262144)
    mf=strict(raw)
    rows=mf[field]
    need(type(rows) is list and 1<=len(rows)<=128 and len({r['path'] for r in rows})==len(rows),
        'bounded unique complete manifest required')
    root=Path(row['path']).parent
    bodies={}
    for member in rows:
        need(type(member) is dict and set(member)=={'path','bytes','sha256'},'exact manifest row required')
        name=member['path']
        bodies[name]=originals.read({'path':str(root/relative(name)),
            'bytes':member['bytes'],'sha256':member['sha256']})
    return mf,bodies


def verify_literal_increment(new,old,allowed,path_names=()):
    a,b=ast.parse(old),ast.parse(new)
    found=[]
    for tree,is_new in ((a,False),(b,True)):
        names=[]
        for node in tree.body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                name=node.targets[0].id
                if name not in allowed:
                    continue
                if is_new:
                    if name in path_names:
                        value=node.value
                        ok=isinstance(value,ast.BinOp) and isinstance(value.op,ast.Div) \
                            and isinstance(value.left,ast.Name) and value.left.id=='B' \
                            and isinstance(value.right,ast.Constant) and isinstance(value.right.value,str)
                        ok=ok or (isinstance(value,ast.Call) and isinstance(value.func,ast.Name)
                            and value.func.id=='Path' and not value.keywords and len(value.args)==1
                            and isinstance(value.args[0],ast.Constant) and isinstance(value.args[0].value,str))
                        need(ok,'frozen dependency path must remain a static Path expression')
                    else:
                        value=ast.literal_eval(node.value)
                        need(isinstance(value,(str,tuple)),'frozen dependency must remain a literal')
                node.value=ast.Constant(value=None)
                names.append(name)
        need(set(names)==set(allowed) and len(names)==len(allowed),'exact selected dependency assignments required')
        found.append(names)
    need(ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False),
        'dependency increment changed other reviewed executable logic')


def admit(plan,originals,own_root):
    need(type(plan) is dict and set(plan)=={'schema','case_id','label','nonce','request','component_package',
        'release','ready','active_package','fixture_result','out','rotation_authorized'}
        and plan['schema']=='hepta.physical-component.root-plan.v1'
        and plan['case_id'] in ('COMP-01','NEG-03')
        and re.fullmatch('[a-z0-9][a-z0-9-]{5,39}',plan['label'])
        and re.fullmatch('[0-9a-f]{32}',plan['nonce']),'explicit actual component identity required')
    need(type(plan['rotation_authorized']) is bool and plan['rotation_authorized'] is (plan['case_id']=='NEG-03'),
        'physical rotation must be explicitly scoped to this NEG03 case')
    owner=originals.read(plan['request'],4096)
    need(owner and b'\0' not in owner and owner.decode('utf8').count(plan['nonce'])==1,
        'exact component owner request must contain its supplied nonce once')
    mf,files=load_members(originals,plan['component_package'])
    need(mf['schema']=='hepta.fixed19.comp01-neg03.source-package.v1'
        and sha(files['source/prepare_direct_return_component.py'])==DIRECT_SHA
        and sha(files['source/verify_unqualified_geometry_fixture.py'])==FIXTURE_SHA,
        'unchanged reviewed direct component entries required')
    _,oldcontext=originals.known(own_root/'reference/component_source_context.original.py',65536)
    _,oldactive=originals.known(own_root/'reference/active_runtime_r10.original.py',65536)
    need(sha(oldcontext)==CONTEXT_SHA and sha(oldactive)==ACTIVE_SHA,'reviewed source references differ')
    verify_literal_increment(files['source/component_source_context.py'],oldcontext,
        {'MATERIALIZER','CONSUMER','CONSUMER_PIN','READINESS_PIN','RUNTIME_SHA','POLICY_SHA','ADOPTION_SHA'},
        {'MATERIALIZER','CONSUMER'})
    direct_path=Path(plan['component_package']['path']).parent/'source/prepare_direct_return_component.py'
    D=module(files['source/prepare_direct_return_component.py'],direct_path,'original_direct_return_entry')
    C,co,package=D.context(plan['component_package']['sha256'])
    release,pins=C.sealed_sources(co,plan['release'])
    need(pins['boot_id']==BOOT and pins['policy_sha256']!=
        '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7',
        'actual newly adopted and sealed R8 generation required')
    amf,afiles=load_members(originals,plan['active_package'])
    active_raw=afiles['source/active_runtime_r10.py']
    verify_literal_increment(active_raw,oldactive,{'CONSUMER_SHA','READINESS_SHA','POLICY_SHA','ADOPTION_SHA'})
    active=module(active_raw,Path(plan['active_package']['path']).parent/'source/active_runtime_r10.py',
        'physical_case_active_runtime')
    need(active.CONSUMER_SHA==pins['boundary_consumer_sha256']
        and active.READINESS_SHA==pins['readiness_source_sha256']
        and active.POLICY_SHA==pins['policy_sha256'] and active.ADOPTION_SHA==pins['policy_adoption_inputs_sha256'],
        'component and active runtime dependency generations differ')
    pp=strict(afiles['source/production-pins.json'])
    need(pp=={name:sha(raw) for name,raw in release['source'].items()},'active complete production15 differs')
    active._REVIEWED_PRODUCTION_PINS=pp
    ready_raw=originals.read(plan['ready'],32768)
    binding={'schema':'hepta.r10.active-runtime-binding.v1',
        'release_pins':{key:pins[key] for key in PIN_KEYS},
        'readiness':{'bytes':len(ready_raw),'sha256':sha(ready_raw),'raw_b64':b64(ready_raw)}}
    ready=active.validate_runtime_binding(binding,BOOT)
    if plan['case_id']=='COMP-01':
        need(plan['fixture_result'] is None,'COMP01 must not inherit a NEG03 fixture result')
    else:
        fixture=strict(originals.read(plan['fixture_result'],1048576))
        need(fixture['schema']=='hepta.fixed19.neg03.geometry-fixture-result.v1'
            and fixture['state']=='NEG03_COMPONENT_FIXTURE_PASSED'
            and fixture['case_id']=='NEG-03' and fixture['fixture_id']=='neg03-'+plan['nonce']
            and fixture['source_package']['sha256']==plan['component_package']['sha256']
            and fixture['release_pins']==pins and fixture['fixed19_component_case_passed'] is True
            and fixture['physical_qualified'] is False and fixture['all_receipts_synthetic'] is True
            and fixture['actual_phone_observations']==0 and fixture['automatic_retry'] is False
            and len(fixture['negative_observations'])==6
            and {row['name'] for row in fixture['negative_observations']}==
                {semantic+'-'+axis for semantic in ('screenshot','return') for axis in ('display','rotation','geometry')}
            and all(row['input_dispatches']==0 and row['physical_qualified'] is False
                and row['new_tap_mapping'] is False and row['current_valid_latest'] is False
                for row in fixture['negative_observations'])
            and fixture['checks'] and all(row['passed'] is True for row in fixture['checks']),
            'separate fresh same-release six-axis host fixture must already be verified')
    C.recheck_source_package(co,package)
    originals.recheck()
    return {'D':D,'C':C,'co':co,'package':package,'release':release,'release_path':plan['release']['path'],'pins':pins,'ready':ready,
        'binding':binding,'active_raw':active_raw,'production_pins_raw':afiles['source/production-pins.json'],
        'owner':owner}


@contextmanager
def actual_modules(admitted):
    source=admitted['release']['source']
    root=Path(admitted['release_path'])
    names=('provider_openai_compatible','task_postconditions','phone_task_guards','phone_observation_tools',
        'phone_local_http_worker','retirement_recovery','phone_local_tools')
    old={name:sys.modules.get(name) for name in names}
    loaded={}
    try:
        for name in names:
            m=module(source[name+'.py'],root/'provider/source'/(name+'.py'),'physical_actual_'+name)
            loaded[name]=m
            sys.modules[name]=m
        yield loaded
    finally:
        for name in names:
            if old[name] is None:
                sys.modules.pop(name,None)
            else:
                sys.modules[name]=old[name]


def live_request(admitted):
    payload={'active':admitted['active_raw'].decode(),'production_pins':
        admitted['production_pins_raw'].decode(),'binding':admitted['binding'],'boot_id':BOOT}
    raw=enc(payload)
    need(len(raw)<=262144,'original active observer decompressed budget')
    packed=gzip.compress(raw,mtime=0)
    script=("import base64,zlib,json,sys,types,time,importlib\n"
        "sys.dont_write_bytecode=True\n"
        "p=base64.b64decode(sys.argv[1],validate=True);d=zlib.decompressobj(31);b=d.decompress(p,262145)\n"
        "assert len(b)<=262144 and d.eof and not d.unused_data and not d.unconsumed_tail\n"
        "import hashlib;assert len(b)=="+str(len(raw))+" and hashlib.sha256(b).hexdigest()=="+repr(sha(raw))+"\n"
        "v=json.loads(b);a=types.ModuleType('active_runtime_r10');a.__file__='<exact-carried-active-runtime>'\n"
        "a._REVIEWED_PRODUCTION_PINS=json.loads(v['production_pins']);sys.modules['active_runtime_r10']=a\n"
        "exec(compile(v['active'],a.__file__,'exec'),a.__dict__)\n"
        "with a.verified_runtime(v['binding'],v['boot_id']) as state:\n"
        " m=importlib.import_module('model_slot_cleanup');slots,http=m.get_json(state['config'],'/slots',time.monotonic()+.75)\n"
        " assert http['complete'] is True and http['http_status']==200 and http['error'] is None\n"
        " assert isinstance(slots,list) and len(slots)==1 and slots[0]['is_processing'] is False\n"
        " assert slots[0]['hepta_server']['identity']==state['ready']['actual_binding']['server_identity']\n"
        " observation=a.verify_current(state,hash_images=False)\n"
        " print(json.dumps({'schema':'hepta.physical-component.live-admission.v1','state':'ACTUAL_SAME_GENERATION_IDLE',"
        "'runtime':observation,'slots':slots,'slot_get_receipt':http,'phone_ui_actions':0,'model_requests':0,'native_submissions':0},sort_keys=True))\n")
    command=('/data/adb/magisk/busybox timeout -s TERM -k 1 8 /data/adb/magisk/busybox chroot '
        '/data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '+shlex.quote(script)+' '+shlex.quote(b64(packed)))
    return request(command,12)


def request(command,timeout):
    need(isinstance(command,str) and '\0' not in command and type(timeout) is int and 1<=timeout<=20,
        'bounded fixed shell recipe required')
    wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(command)).encode()
    need(len(wire)<65536,'original exclusive ADB request budget exceeded')
    return {'kind':'shell','root':True,'timeout_seconds':timeout,'command':command}


def validate_live(value,admitted):
    need(type(value) is dict and set(value)=={'schema','state','runtime','slots','slot_get_receipt',
        'phone_ui_actions','model_requests','native_submissions'}
        and value['schema']=='hepta.physical-component.live-admission.v1'
        and value['state']=='ACTUAL_SAME_GENERATION_IDLE'
        and value['phone_ui_actions']==value['model_requests']==value['native_submissions']==0,
        'actual idle live admission required')
    slots=value['slots'];http=value['slot_get_receipt']
    need(type(slots) is list and len(slots)==1 and slots[0]['is_processing'] is False
        and slots[0]['hepta_server']['identity']==admitted['ready']['actual_binding']['server_identity']
        and http['method']=='GET' and http['path']=='/slots' and http['automatic_retry'] is False
        and http['redirect_followed'] is False and http['complete'] is True
        and http['http_status']==200 and http['error'] is None,'original actual idle GET differs')
    v=value['runtime']
    need(v['schema']=='hepta.r10.active-runtime-observation.v1' and v['boot_id']==BOOT
        and v['release_pins']==admitted['binding']['release_pins']
        and v['readiness_original']==admitted['binding']['readiness']
        and v['policy_sha256']==admitted['pins']['policy_sha256']
        and {k:r['identity'] for k,r in v['roles'].items()}==
            {k:r['identity'] for k,r in admitted['ready']['roles'].items()}
        and v['model_requests']==v['task_submissions']==v['ui_actions']==v['signals_sent']==0,
        'actual live generation differs from exact READY')
    return v


def png_info(raw):
    need(0<len(raw)<=MAX_PNG and raw.startswith(b'\x89PNG\r\n\x1a\n'),'bounded actual PNG required')
    pos=8;chunks=[];size=None
    while pos<len(raw):
        need(pos+12<=len(raw),'truncated PNG chunk')
        length=struct.unpack('>I',raw[pos:pos+4])[0]
        kind=raw[pos+4:pos+8]
        need(length<=MAX_PNG and pos+12+length<=len(raw),'bounded PNG chunk required')
        data=raw[pos+8:pos+8+length]
        crc=struct.unpack('>I',raw[pos+8+length:pos+12+length])[0]
        need((zlib.crc32(kind+data)&0xffffffff)==crc,'actual PNG CRC differs')
        if not chunks:
            need(kind==b'IHDR' and length==13,'PNG IHDR must be first')
            size=struct.unpack('>II',data[:8])
            need(all(0<x<=8192 for x in size) and size[0]*size[1]<=1224*2992,'actual screenshot pixel bound')
        chunks.append(kind);pos+=12+length
        if kind==b'IEND':
            need(length==0 and pos==len(raw),'PNG must end at its IEND')
            break
    need(chunks[-1]==b'IEND' and b'IDAT' in chunks,'complete actual PNG required')
    return {'width':size[0],'height':size[1],'bytes':len(raw),'sha256':sha(raw)}


def physical_request(modules,nonce,phase,baseline=None):
    """Only rotation settings change; the original input guard ends in a no-effect marker."""
    need(phase in ('portrait-baseline','rotate-negative','restore-positive'),'fixed physical phase required')
    obs,guards,local=(modules[n] for n in ('phone_observation_tools','phone_task_guards','phone_local_tools'))
    need(obs.ORIGINAL_SIZE==(1224,2992) and obs.PHYSICAL_DISPLAY=='4630947043778501779',
        'reviewed geometry differs')
    guard=local.current_viewport_guard()
    need('input ' not in guard and 'am start' not in guard and 'settings put' not in guard,
        'reviewed qualification guard must remain read-only')
    marker='hepta_guard_admitted_'+nonce+'_'+phase
    temp='/data/local/tmp/hepta-physical-'+nonce+'-'+phase
    q=shlex.quote
    body=obs.PhoneTools('/not-used',lambda *_:None)._serial_guard()
    body+='[ "$(cat /proc/sys/kernel/random/boot_id)" = '+q(BOOT)+' ] || exit 64; '
    body+='umask 077; mkdir -m 700 '+q(temp)+' || exit 66; '
    cleanup='hepta_rc=$?; trap - 0; rm -f -- '+q(temp+'/screen.png')+' '+q(temp+'/guard.out')+' '+q(temp+'/guard.err')+'; rmdir '+q(temp)+' || exit 69; exit "$hepta_rc"'
    body+='trap '+q(cleanup)+' 0; '
    body+='hepta_set_acc_rc=-1; hepta_set_rot_rc=-1; '
    if phase!='portrait-baseline':
        need(type(baseline) is dict,'actual observed baseline required before setting mutation')
        old=baseline['value']
        need(re.fullmatch('[01]',old['accelerometer_rotation']) and re.fullmatch('[0-3]',old['user_rotation'])
            and re.fullmatch('[0-7]',old['stay_on']),'actual settings baseline shape')
        body+='[ "$(getprop ro.build.fingerprint)" = '+q(baseline['fingerprint'])+' ] || exit 64; '
        body+='[ "$(settings get global stay_on_while_plugged_in)" = '+q(old['stay_on'])+' ] || exit 70; '
        if phase=='rotate-negative':
            body+='[ "$(settings get system accelerometer_rotation)" = '+q(old['accelerometer_rotation'])+' ] || exit 70; '
            body+='[ "$(settings get system user_rotation)" = '+q(old['user_rotation'])+' ] || exit 70; '
            body+=guards.page_equality_guard(baseline['page'])
            body+=guard
            acc,rot='0','1'
        else:
            # This is the one explicitly authorized inverse of this run's settings change.
            # Unknown original actor completion is reconciled before Root admits this phase.
            acc,rot=old['accelerometer_rotation'],old['user_rotation']
        body+='settings put system accelerometer_rotation '+q(acc)+'; hepta_set_acc_rc=$?; '
        body+='if [ "$hepta_set_acc_rc" = 0 ]; then settings put system user_rotation '+q(rot)+'; hepta_set_rot_rc=$?; fi; '
        # Bounded settling only; success is decided from actual later observations.
        body+='sleep 1; '
    body+=guards.page_capture('hepta_before_page')
    body+="hepta_before_vp=$(dumpsys display | grep 'mViewports='); "
    body+='screencap -d '+obs.PHYSICAL_DISPLAY+' -p '+q(temp+'/screen.png')+' || exit 67; '
    body+="hepta_after_vp=$(dumpsys display | grep 'mViewports='); "
    body+=guards.page_capture('hepta_after_page')
    body+='('+guard+'printf \'%s\\n\' '+q(marker)+') >'+q(temp+'/guard.out')+' 2>'+q(temp+'/guard.err')+'; hepta_guard_rc=$?; '
    body+="hepta_guard_after_vp=$(dumpsys display | grep 'mViewports='); "
    body+=guards.page_capture('hepta_guard_after_page')
    body+='hepta_png_bytes=$(wc -c < '+q(temp+'/screen.png')+' | tr -d "[:space:]"); '
    body+='[ "$hepta_png_bytes" -gt 0 ] && [ "$hepta_png_bytes" -le '+str(MAX_PNG)+' ] || exit 73; '
    body+='hepta_png_sha=$(sha256sum '+q(temp+'/screen.png')+" | cut -d ' ' -f 1); "
    body+='hepta_guard_out_bytes=$(wc -c < '+q(temp+'/guard.out')+' | tr -d "[:space:]"); '
    body+='hepta_guard_err_bytes=$(wc -c < '+q(temp+'/guard.err')+' | tr -d "[:space:]"); '
    body+='[ "$hepta_guard_out_bytes" -le 4096 ] && [ "$hepta_guard_err_bytes" -le 16384 ] || exit 73; '
    body+='hepta_stay=$(settings get global stay_on_while_plugged_in); '
    body+='hepta_acc=$(settings get system accelerometer_rotation); hepta_rot=$(settings get system user_rotation); '
    body+='hepta_fingerprint=$(getprop ro.build.fingerprint); '
    for source,target in (('hepta_before_page','page_before_b64'),('hepta_after_page','page_after_b64'),
        ('hepta_before_vp','viewport_before_b64'),('hepta_after_vp','viewport_after_b64'),
        ('hepta_guard_after_page','page_guard_after_b64'),('hepta_guard_after_vp','viewport_guard_after_b64'),
        ('hepta_fingerprint','fingerprint_b64')):
        body+=guards.b64_variable(source,target)
    for name,path in (('png_b64','screen.png'),('guard_stdout_b64','guard.out'),('guard_stderr_b64','guard.err')):
        body+=name+'=$(base64 '+q(temp+'/'+path)+" | tr -d '\r\n'); "
    fmt='{"schema":"hepta.physical-component.rotation-observation.v1","nonce":"'+nonce+'","phase":"'+phase+'","boot_id":"'+BOOT+'","stay_on":"%s","accelerometer_rotation":"%s","user_rotation":"%s","set_accelerometer_rc":%s,"set_user_rotation_rc":%s,"guard_rc":%s,"guard_stdout_b64":"%s","guard_stderr_b64":"%s","page_before_b64":"%s","page_after_b64":"%s","viewport_before_b64":"%s","viewport_after_b64":"%s","page_guard_after_b64":"%s","viewport_guard_after_b64":"%s","fingerprint_b64":"%s","png_bytes":%s,"png_sha256":"%s","png_base64":"%s"}\n'
    args=['hepta_stay','hepta_acc','hepta_rot','hepta_set_acc_rc','hepta_set_rot_rc','hepta_guard_rc',
        'guard_stdout_b64','guard_stderr_b64','page_before_b64','page_after_b64','viewport_before_b64',
        'viewport_after_b64','page_guard_after_b64','viewport_guard_after_b64',
        'fingerprint_b64','hepta_png_bytes','hepta_png_sha','png_b64']
    body+='printf '+q(fmt)+' '+' '.join('"$'+name+'"' for name in args)
    return request(body,20),{'guard_sha256':sha(guard.encode()),'admission_marker':marker,
        'geometry_or_screenshot_rewritten':False,'input_commands':0,'fixed_phone_temporary_directory':temp}


def parse_physical(modules,raw,nonce,phase):
    obs,guards,provider=(modules[n] for n in ('phone_observation_tools','phone_task_guards','provider_openai_compatible'))
    v=strict(raw)
    expected={'schema','nonce','phase','boot_id','stay_on','accelerometer_rotation','user_rotation',
        'set_accelerometer_rc','set_user_rotation_rc','guard_rc','guard_stdout_b64','guard_stderr_b64',
        'page_before_b64','page_after_b64','viewport_before_b64','viewport_after_b64',
        'page_guard_after_b64','viewport_guard_after_b64',
        'fingerprint_b64','png_bytes','png_sha256','png_base64'}
    need(type(v) is dict and set(v)==expected and v['schema']=='hepta.physical-component.rotation-observation.v1'
        and v['nonce']==nonce and v['phase']==phase and v['boot_id']==BOOT,'actual physical observation identity differs')
    for key,pattern in (('stay_on','[0-7]'),('accelerometer_rotation','[01]'),('user_rotation','[0-3]')):
        need(isinstance(v[key],str) and re.fullmatch(pattern,v[key]),'actual setting observation differs')
    page=decode(v['page_before_b64'],16384).decode('utf8')
    viewport=decode(v['viewport_before_b64'],16384).decode('utf8')
    need(decode(v['page_after_b64'],16384).decode()==page
        and decode(v['viewport_after_b64'],16384).decode()==viewport
        and decode(v['page_guard_after_b64'],16384).decode()==page
        and decode(v['viewport_guard_after_b64'],16384).decode()==viewport,
        'page/viewport changed across actual screenshot and production guard')
    observed=guards.page_state(page)
    fingerprint=decode(v['fingerprint_b64'],1024).decode()
    need(fingerprint and '\0' not in fingerprint and '\n' not in fingerprint,'actual fingerprint required')
    png=decode(v['png_base64'],MAX_PNG)
    info=png_info(png)
    need((info['width'],info['height']) in ((1224,2992),(2992,1224)),
        'actual physical inner display screenshot dimensions differ')
    need(type(v['png_bytes']) is int and v['png_bytes']==len(png) and v['png_sha256']==sha(png),
        'actual screenshot length/hash differs')
    gout,gerr=decode(v['guard_stdout_b64'],4096),decode(v['guard_stderr_b64'],16384)
    need(not gerr,'qualification guard produced unexpected stderr')
    if phase=='rotate-negative':
        need(v['set_accelerometer_rc']==v['set_user_rotation_rc']==0
            and v['accelerometer_rotation']=='0' and v['user_rotation']=='1',
            'authorized rotation setting mutation was not observed')
        active=[entry for entry in re.findall(r'DisplayViewport\{([^{}]+)\}',viewport)
            if re.search(r'\bisActive=true(?:,|$)',entry)]
        need(len(active)==1 and re.search(r'\bdisplayId=0(?:,|$)',active[0])
            and re.search(r'\borientation=1(?:,|$)',active[0]),'actual rotated inner viewport must be observed, not inferred')
        try:
            obs.validate_viewport(viewport)
        except provider.ProviderError as error:
            reason=str(error)
            need('display or rotation is not qualified' in reason,'unexpected production parser rejection')
        else:
            raise ValueError('production parser accepted the actual rotated viewport')
        need(type(v['guard_rc']) is int and v['guard_rc']==68 and gout==b'',
            'actual production input qualification guard did not reject before its marker')
    else:
        obs.validate_viewport(viewport)
        need(type(v['guard_rc']) is int and v['guard_rc']==0
            and gout==('hepta_guard_admitted_'+nonce+'_'+phase+'\n').encode(),
            'actual qualified positive guard control failed')
        if phase=='restore-positive':
            need(v['set_accelerometer_rc']==v['set_user_rotation_rc']==0,'actual settings restoration was not successful')
        else:
            need(v['set_accelerometer_rc']==v['set_user_rotation_rc']==-1,'baseline must not mutate settings')
        reason=None
    return {'value':v,'page':page,'viewport':viewport,'fingerprint':fingerprint,'observed':observed,
        'png':png,'png_info':info,'production_rejection':reason}
