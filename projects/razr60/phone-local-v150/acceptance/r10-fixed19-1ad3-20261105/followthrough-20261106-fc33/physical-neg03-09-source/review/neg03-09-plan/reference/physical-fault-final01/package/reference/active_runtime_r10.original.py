#!/usr/bin/env python3
"""Read-only r10 active-task binding. No idle gate, action, signal or POST.

Future actual READY bytes and six release pins are supplied explicitly by Root.
The same four live role generations, sealed 17 production bytes, eight external
dependencies and explicitly adopted policy are rechecked while tasks are active.
Production modules are compiled from exact reviewed bytes, never from pyc.
"""
import base64
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
A=Path('/proc/1/root')
PROVIDER=BASE/'provider-r10-r1'
MODULE=A/'data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
RUNTIME_ROOT=BASE/'model-runtime-r10-r1'
CLAIM_ROOT=A/'data/adb/trillionnium-hepta-phone-local-v150-r10-r1'
# Final dependency pins are filled only after the reviewed R4 consumer cascade.
CONSUMER_SHA='a791a7493fe8544aa44b910dd627f405f71678a048f9df94df91529a54fdf703'
READINESS_SHA='345723406df0c523ab55b167bb52f5ceb9432d387ffe3b4aa5b1e5442465e392'
CONFIG_SHA='780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'
SERVICE_SHA='2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'
POLICY_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PARENT_POLICY_SHA='bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38'
ADOPTION_SHA='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
MODEL_SHA='dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c'
MODEL_EXE='/data/local/tmp/hepta-phone-local-v150-r10-r1/bin/llama-server'
PYTHON_SHA='f7ad87c414fc6a5126571b2ecca19351119ac10e54d0539de6a0a9300d81087f'
SIDECAR_EXE='/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6'
SIDECAR_SHA='8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976'
PIN_KEYS={'source_seal_sha256','configuration_sha256','service_inputs_sha256',
    'module_manifest_sha256','component_boundary_inputs_sha256','policy_adoption_inputs_sha256'}
ROLE_KEYS={'supervisor','model','sidecar','provider'}
READY_FIELDS={'schema','state','boot_id','roles','provider_ready','loopback_listeners',
    'sidecar_socket_inode','source_seal_sha256','configuration_sha256','module_manifest_sha256',
    'service_inputs_sha256','shared_material_binding','component_external_artifacts',
    'policy_sha256','parent_policy_sha256','policy_adoption_inputs_sha256',
    'component_boundary_inputs_sha256','component_boundary_sha256','release_boundary_bundle_sha256',
    'actual_binding','slot_observation','slot_get_receipt','model_requests','task_submissions',
    'ui_actions','signals_sent','health_qualified','business19_qualified','cold_boot_qualified'}
ORDER=('provider_openai_compatible','task_postconditions','phone_task_guards',
    'phone_observation_tools','phone_local_http_worker','model_slot_cleanup',
    'retirement_recovery','action_ledger','model_health','phone_local_tools',
    'ledger_round_evidence','provider_codex_host','health_contracts','provider_phone_local',
    'daily_phone_local')
SHA_RE=re.compile(r'[0-9a-f]{64}\Z')
_CURRENT=None


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        out={}
        for key,value in rows:
            need(key not in out,'duplicate JSON key')
            out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()


def equal(a,b):return encoded(a)==encoded(b)


def raw_record(raw):
    return dict(bytes=len(raw),sha256=sha(raw),raw_b64=base64.b64encode(raw).decode())


def decode_record(row,limit):
    need(isinstance(row,dict) and set(row)=={'bytes','sha256','raw_b64'},'raw original fields differ')
    need(type(row['bytes']) is int and 0<row['bytes']<=limit and
         isinstance(row['sha256'],str) and SHA_RE.fullmatch(row['sha256']) and
         isinstance(row['raw_b64'],str) and len(row['raw_b64'])<=4*((limit+2)//3),'raw original bounds')
    raw=base64.b64decode(row['raw_b64'],validate=True)
    need(equal(raw_record(raw),row),'raw original length/hash/canonical bytes differ')
    raw.decode('utf-8')
    return raw


def role_rows(ready):
    roles=ready['roles']
    need(isinstance(roles,dict) and set(roles)==ROLE_KEYS,'four actual readiness roles required')
    expected={'supervisor':('u:r:magisk:s0',None),
        'model':('u:r:magisk:s0',MODEL_EXE),
        'sidecar':('u:r:trillionnium_owner_open_phone_executor:s0',SIDECAR_EXE),
        'provider':('u:r:magisk:s0','/usr/bin/python3')}
    for name,row in roles.items():
        need(isinstance(row,dict) and set(row)=={'identity','state','domain','uid','gid','no_new_privs','exe'},
             'actual role observation fields differ')
        identity=row['identity']
        need(isinstance(identity,list) and len(identity)==4 and all(type(n) is int and n>1 for n in identity)
             and identity[0]==identity[1]==identity[2],'actual live owned role generation required')
        need(row['state'] in ('R','S','D','I') and row['domain']==expected[name][0]
             and equal(row['uid'],[0]*4) and equal(row['gid'],[0]*4)
             and type(row['no_new_privs']) is int and row['no_new_privs']==0
             and isinstance(row['exe'],str) and row['exe'].startswith('/')
             and (expected[name][1] is None or row['exe']==expected[name][1]),'actual role credentials/image differ')
    need(len({r['identity'][0] for r in roles.values()})==4,'readiness role PID collision')
    return {name:row['identity'] for name,row in roles.items()}


def validate_runtime_binding(binding,expected_boot):
    need(isinstance(binding,dict) and set(binding)=={'schema','release_pins','readiness'}
         and binding['schema']=='hepta.r10.active-runtime-binding.v1','active runtime binding fields/schema')
    pins=binding['release_pins']
    need(isinstance(pins,dict) and set(pins)==PIN_KEYS and
         all(isinstance(v,str) and SHA_RE.fullmatch(v) for v in pins.values()),'six explicit release pins required')
    need(pins['configuration_sha256']==CONFIG_SHA and pins['service_inputs_sha256']==SERVICE_SHA
         and pins['policy_adoption_inputs_sha256']==ADOPTION_SHA,'reviewed r10 material/adoption pins differ')
    raw=decode_record(binding['readiness'],32768);ready=strict(raw)
    need(isinstance(ready,dict) and set(ready)==READY_FIELDS
         and ready['schema']=='hepta.r10.actual-readiness.v1'
         and ready['state']=='EXACT_COMBINATION_READY_TRANSPORT_ONLY'
         and ready['boot_id']==expected_boot,'actual selected r10 READY original required')
    need(all(ready[k]==v for k,v in pins.items()),'READY and six selected pins differ')
    need(ready['policy_sha256']==POLICY_SHA and ready['parent_policy_sha256']==PARENT_POLICY_SHA,
         'explicitly adopted live export differs')
    for key in ('component_boundary_sha256','release_boundary_bundle_sha256'):
        need(isinstance(ready[key],str) and SHA_RE.fullmatch(ready[key]),'READY boundary hash differs')
    for key in ('model_requests','task_submissions','ui_actions','signals_sent'):
        need(type(ready[key]) is int and ready[key]==0,'READY is not the original transport-only observation')
    for key in ('health_qualified','business19_qualified','cold_boot_qualified'):
        need(ready[key] is False,'transport readiness is not an acceptance credit')
    role_rows(ready)
    need(ready['slot_observation'].get('is_processing') is False
         and ready['slot_get_receipt'].get('complete') is True
         and ready['slot_get_receipt'].get('http_status')==200
         and ready['slot_get_receipt'].get('error') is None,'original startup idle observation required')
    need(isinstance(ready['component_external_artifacts'],dict) and
         set(ready['component_external_artifacts'])==
         {'client','sidecar','worker','screen_helper','focus_helper','unicode_helper','busybox','python'},
         'READY eight external artifacts required')
    return ready


def validate_task_expectations(plan,owner):
    ready=validate_runtime_binding(plan['runtime_binding'],plan['expected_boot'])
    pins=plan['runtime_binding']['release_pins']
    if 'release_pins' in plan:
        need(equal(plan['release_pins'],pins),'signal plan six release pins differ')
        need(equal(plan['roles'],role_rows(ready)),'signal roles differ from original READY')
    else:
        need(all(plan[k]==pins[k] for k in ('source_seal_sha256','configuration_sha256','service_inputs_sha256')),
             'cancellation source/config/service pins differ from original READY')
    scope=plan['app_scope']
    need(isinstance(scope,dict) and set(scope)=={'schema','owner_request_sha256','apps'}
         and scope['schema']=='hepta.task-app-scope.v1'
         and scope['owner_request_sha256']==sha(owner)==plan['owner_request_sha256'],
         'explicit scope must bind the unchanged owner bytes')
    need(isinstance(plan['task_template_sha256'],str) and SHA_RE.fullmatch(plan['task_template_sha256']),
         'actual v150.3 template pin required')
    apps=scope['apps']
    need(isinstance(apps,list) and 1<=len(apps)<=64,'nonempty explicit app subset required')
    aliases=set()
    for row in apps:
        need(isinstance(row,dict) and set(row)=={'alias','component'},'app scope tuple fields differ')
        alias,component=row['alias'],row['component']
        need(isinstance(alias,str) and 0<len(alias.encode())<=128 and '\0' not in alias and alias not in aliases,
             'app scope alias invalid or duplicated')
        aliases.add(alias)
        need(isinstance(component,str) and 0<len(component.encode())<=512
             and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.$]*/(?:\.)?[A-Za-z][A-Za-z0-9_.$]*',component)
             and component.split('/')[0]!='org.trillionnium.owneropen','app scope component invalid')
    return ready


def stable(path,limit=1048576):
    path=Path(path)
    need(path.parent.resolve(strict=True)==path.parent,'noncanonical original parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==0
             and stat.S_IMODE(a.st_mode)==0o600 and 0<=a.st_size<=limit,'private original metadata differs')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(limit+1)
        b,n=os.fstat(fd),path.lstat()
        fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink','st_uid','st_gid')
        need(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(n,k) for k in fields),
             'private original changed during read')
        return raw
    finally:os.close(fd)


@contextmanager
def reviewed_modules(sources):
    expected=_REVIEWED_PRODUCTION_PINS
    need(set(sources)==set(expected)=={n+'.py' for n in ORDER},'exact reviewed 15-source set required')
    need(all(isinstance(raw,bytes) and sha(raw)==expected[name] for name,raw in sources.items()),
         'unreviewed production source bytes')
    old={name:sys.modules.get(name) for name in ORDER};oldpath=sys.path[:]
    try:
        for name in ORDER:sys.modules.pop(name,None)
        for name in ORDER:
            module=types.ModuleType(name);module.__file__=str(PROVIDER/'source'/(name+'.py'))
            module.__reviewed_source_sha256__=sha(sources[name+'.py']);sys.modules[name]=module
            exec(compile(sources[name+'.py'],module.__file__,'exec',optimize=0),module.__dict__)
        yield {name:sys.modules[name] for name in ORDER}
    finally:
        sys.path[:]=oldpath
        for name,module in old.items():
            if module is None:sys.modules.pop(name,None)
            else:sys.modules[name]=module


def require_final_dependencies():
    need(all(isinstance(value,str) and SHA_RE.fullmatch(value)
             for value in (CONSUMER_SHA,READINESS_SHA)),
         'final active-task consumer/readiness sources are not frozen')


def module_original(row):
    name=Path(row['path'])
    need(not name.is_absolute() and '..' not in name.parts and str(name)==row['path']
         and '\n' not in row['path'] and '\r' not in row['path'],'unsafe module original path')
    maximum=32*1024*1024 if row['path']=='evidence/RELEASE-BOUNDARIES.json' else 16*1024*1024
    need(type(row['bytes']) is int and 0<=row['bytes']<=maximum
         and isinstance(row['sha256'],str) and SHA_RE.fullmatch(row['sha256']),
         'bounded exact module original required')
    raw=android_private(MODULE/name,limit=row['bytes'])
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'module original length/hash differs')
    return raw


def installed(binding,expected_boot):
    require_final_dependencies()
    ready=validate_runtime_binding(binding,expected_boot);pins=binding['release_pins']
    need(os.getuid()==os.geteuid()==0 and os.readlink('/proc/1/exe')=='/system/bin/init'
         and domain('/proc/1/attr/current')=='u:r:init:s0'
         and domain('/proc/self/attr/current')=='u:r:magisk:s0','native Android Magisk root view required')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==expected_boot,'actual boot differs')
    need((A/'sys/fs/selinux/enforce').read_bytes() in (b'1',b'1\n'),'Enforcing required')
    paths={'seal':PROVIDER/'SOURCE-SEAL-v150-r10.json','config':BASE/'local-config-r10-r1.json',
        'service':BASE/'PHONE-SERVICE-INPUTS-v150-r10-r1.json','consumer':PROVIDER/'release_boundaries.py',
        'readiness':PROVIDER/'collect_r10_readiness.py'}
    raw={name:stable(path,262144) for name,path in paths.items()}
    need(sha(raw['seal'])==pins['source_seal_sha256'] and sha(raw['config'])==CONFIG_SHA
         and sha(raw['service'])==SERVICE_SHA and sha(raw['consumer'])==CONSUMER_SHA
         and sha(raw['readiness'])==READINESS_SHA,'installed r10 source/config/service/helper pins differ')
    seal,config,service=strict(raw['seal']),strict(raw['config']),strict(raw['service'])
    need(seal['schema']=='hepta.provider-r10.actual-integration-seal.v1'
         and seal['module_release']=='v150-r10-r1'
         and seal['configuration']['sha256']==CONFIG_SHA
         and seal['phone_service_inputs_sha256']==SERVICE_SHA
         and config['service_manifest_sha256']==SERVICE_SHA
         and service['schema']=='hepta.phone-local.service-inputs.v150.r10.1'
         and service['runtime']['server']['sha256']==MODEL_SHA,'actual integration seal/config/service differs')
    rows=seal['production_files'];expected=_REVIEWED_PRODUCTION_PINS
    need(isinstance(rows,list) and len(rows)==15 and len({r['path'] for r in rows})==15,'source row inventory differs')
    sources={}
    for row in rows:
        rel=Path(row['path'])
        need(str(rel)==row['path'] and len(rel.parts)==2 and rel.parts[0]=='source'
             and rel.name in expected,'unreviewed production path')
        data=stable(PROVIDER/rel,262144)
        need(len(data)==row['bytes'] and sha(data)==row['sha256']==expected[rel.name],'production source pin differs')
        sources[rel.name]=data
    need(set(sources)==set(expected),'incomplete reviewed source set')
    module_raw=android_private(MODULE/'MODULE-MANIFEST-v150-r10-r1.json')
    need(sha(module_raw)==pins['module_manifest_sha256'],'actual module manifest differs')
    manifest=strict(module_raw)
    need(manifest['schema']=='hepta.module-r10-r1.file-manifest.v1','actual r10 module schema differs')
    module_rows={r['path']:r for r in manifest['files']}
    need(len(module_rows)==len(manifest['files']),'duplicate module path')
    module_originals={}
    for name in ('evidence/RELEASE-BOUNDARIES.json','seal-binding.json'):
        data=module_original(module_rows[name])
        module_originals[name]=data
    need(android_private(MODULE/'SEALED')==b'HEPTA_PHONE_LOCAL_V150_R10_R1_REVIEWED_INPUTS_BOUND\n',
         'reviewed r10 SEALED marker differs')
    for flag in ('disable','remove'):
        try:(MODULE/flag).lstat()
        except FileNotFoundError:pass
        else:raise ValueError('active r10 module inhibited')
    consumer=types.ModuleType('reviewed_active_release_boundaries');consumer.__file__=str(paths['consumer'])
    exec(compile(raw['consumer'],consumer.__file__,'exec',optimize=0),consumer.__dict__)
    boundary_raw=module_originals['evidence/RELEASE-BOUNDARIES.json']
    boundary=consumer.validate_bundle(boundary_raw,ready['release_boundary_bundle_sha256'])
    need(boundary['component_input_sha256']==pins['component_boundary_inputs_sha256']
         and boundary['policy_adoption_sha256']==pins['policy_adoption_inputs_sha256']
         and boundary['component_boundary_sha256']==ready['component_boundary_sha256']
         and boundary['runtime_policy']['sha256']==POLICY_SHA,'installed explicit boundary/adoption differs')
    integration=strict(module_originals['seal-binding.json'])
    need(integration['schema']=='hepta.module-r10-r1.exact-integration.v1'
         and integration['release_id']=='v150-r10-r1','new exact integration namespace required')
    for key in ('policy_sha256','parent_policy_sha256','policy_adoption_inputs_sha256',
                'component_boundary_inputs_sha256','component_boundary_sha256','release_boundary_bundle_sha256'):
        need(integration[key]==ready[key],'sealed runtime binding differs: '+key)
    material=consumer.validate_shared_materials(boundary,sources,raw['config'],raw['service'])
    artifacts=consumer.external_artifact_bindings(boundary,sources,raw['service'])
    consumer.validate_external_inventory(artifacts,manifest['payload_files'],path_key='path')
    need(equal(material,ready['shared_material_binding']) and equal(artifacts,integration['component_external_artifacts']),
         'actual shared17 or eight sealed dependencies differ')
    external=consumer.current_external_artifacts(boundary)
    need(equal(external,ready['component_external_artifacts']),'current eight dependencies differ from original READY')
    return dict(binding=binding,binding_sha256=sha(encoded(binding)),ready=ready,pins=pins,
        paths=paths,raw=raw,sources=sources,config=config,service=service,consumer=consumer,
        boundary=boundary,module_raw=module_raw,module_originals=module_originals,
        external=external,material=material)


def verify_current(state,*,hash_images=False):
    ready,pins=state['ready'],state['pins'];boot=ready['boot_id']
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot
         and (A/'sys/fs/selinux/enforce').read_bytes() in (b'1',b'1\n'),'boot or Enforcing changed')
    claim=CLAIM_ROOT/boot;roles={};claims={}
    for name,wanted in ready['roles'].items():
        claim_raw=android_private(claim/(name+'.identity'),limit=4096)
        identity=list(map(int,claim_raw.decode('ascii').strip().split(':')))
        need(equal(identity,wanted['identity']),'actual role claim generation differs: '+name)
        current=process(identity[0])
        need(current['state'] not in ('Z','X','x') and all(equal(current[k],wanted[k])
             for k in ('identity','domain','uid','gid','no_new_privs','exe')),'actual active role differs: '+name)
        if hash_images and name in ('model','sidecar','provider'):
            pin={'model':MODEL_SHA,'sidecar':SIDECAR_SHA,'provider':PYTHON_SHA}[name]
            need(digest_file(Path('/proc')/str(identity[0])/'exe')==pin,'role runtime image differs: '+name)
        roles[name]=current;claims[name]=raw_record(claim_raw)
    need(android_private(claim/'services-started',limit=65536),'actual four-role startup not admitted')
    provider_raw=stable(BASE/'provider-state/ready.json',65536);provider=strict(provider_raw)
    need(provider.get('accepting') is True and provider.get('workers')==1
         and provider['pid']==roles['provider']['identity'][0] and provider['port']==18080
         and provider['source_sha256']==_REVIEWED_PRODUCTION_PINS['daily_phone_local.py']
         and provider['config_sha256']==CONFIG_SHA and provider['service_manifest_sha256']==SERVICE_SHA,
         'current original provider readiness differs')
    model=importlib.import_module('model_slot_cleanup')
    runtime=RUNTIME_ROOT/boot;bound_raw=stable(runtime/'READY-BOUND.json')
    bound=strict(bound_raw)
    need(bound['state']=='READY_BOUND_IMAGE_CANCEL_REQUIRED'
         and equal(bound['binding'],ready['actual_binding']),'actual model startup binding differs')
    bp=Path(bound['binding']['path']);identity=roles['model']['identity']
    need(bp==runtime/'bindings'/('slot-cleanup-%s-%d-%d.json'%(boot,identity[0],identity[3])),
         'model binding path/generation differs')
    binding_raw=stable(bp,65536)
    need(sha(binding_raw)==bound['binding']['sha256'],'model binding raw pin differs')
    server_binding=model.load_binding(bp)
    need(server_binding['server_binary_sha256']==MODEL_SHA
         and server_binding['server_domain']=='u:r:magisk:s0'
         and server_binding['model_claim']==str(runtime/'model.identity')
         and server_binding['endpoint']==state['config']['endpoint'],'r10 model binding fields differ')
    actual_model=model.verify_identity(server_binding,hash_binary=hash_images)
    need([actual_model[k] for k in ('pid','pgid','sid','start_ticks')]==identity
         and actual_model['boot_id']==boot,'actual READY-BOUND model role differs')
    listeners=[listen(18087,roles['model']['identity'][0]),listen(18080,roles['provider']['identity'][0])]
    need(equal(listeners,ready['loopback_listeners']),'actual listener owners/inodes differ')
    unix=[line.split() for line in Path('/proc/net/unix').read_text().splitlines()[1:]]
    side=[r for r in unix if len(r)>=8 and r[-1]=='@hepta_phone_executor_v150_r6']
    need(len(side)==1 and side[0][6]==ready['sidecar_socket_inode']
         and side[0][6] in sockets(roles['sidecar']['identity'][0]),'actual sidecar listener ownership differs')
    for name,row in roles.items():
        after=process(row['identity'][0])
        need(after['state'] not in ('Z','X','x') and all(equal(after[k],row[k]) for k in
             ('identity','domain','uid','gid','no_new_privs','exe')),'role generation changed during active check')
    external=state['consumer'].current_external_artifacts(state['boundary'])
    need(equal(external,state['external']),'external dependency bytes/metadata changed during task')
    for name,path in state['paths'].items():
        need(stable(path,262144)==state['raw'][name],'installed original changed during active check: '+name)
    need(android_private(MODULE/'MODULE-MANIFEST-v150-r10-r1.json')==state['module_raw'],
         'module manifest changed during active task')
    rows={row['path']:row for row in strict(state['module_raw'])['files']}
    for name,raw in state['module_originals'].items():
        need(module_original(rows[name])==raw,'sealed boundary original changed during active task')
    result=dict(schema='hepta.r10.active-runtime-observation.v1',boot_id=boot,
        runtime_binding_sha256=state['binding_sha256'],readiness_original=state['binding']['readiness'],
        release_pins=pins,policy_sha256=POLICY_SHA,roles=roles,role_claim_originals=claims,
        provider_ready_original=raw_record(provider_raw),model_ready_bound_original=raw_record(bound_raw),
        model_binding_original=raw_record(binding_raw),component_external_artifacts=external,
        idle_gate_called=False,retired_absence_gate_called=False,model_requests=0,
        task_submissions=0,ui_actions=0,signals_sent=0,physical_case_pass=False)
    state['last_observation']=result
    return result


@contextmanager
def verified_runtime(binding,expected_boot):
    global _CURRENT
    if _CURRENT is not None:
        need(_CURRENT['binding_sha256']==sha(encoded(binding)) and _CURRENT['ready']['boot_id']==expected_boot,
             'nested active runtime binding differs')
        yield _CURRENT
        return
    state=installed(binding,expected_boot)
    with reviewed_modules(state['sources']):
        verify_current(state,hash_images=True)
        _CURRENT=state
        try:yield state
        finally:_CURRENT=None


def current(binding,expected_boot):
    need(_CURRENT is not None and _CURRENT['binding_sha256']==sha(encoded(binding))
         and _CURRENT['ready']['boot_id']==expected_boot,'reviewed active runtime context is absent or changed')
    return _CURRENT


def contract_originals(run,actual,owner,plan,config,read=stable):
    """Rebuild v150.3 from immutable original template/binding; never consumes it."""
    post=importlib.import_module('task_postconditions')
    owner_hash=sha(owner);identity={k:actual[k] for k in post.IDENTITY}
    need(owner_hash==plan['owner_request_sha256'],'app-scope owner bytes changed')
    paths={'template':BASE/'provider-state/task-contracts/templates'/(owner_hash+'.json'),
        'binding':BASE/'provider-state/task-contracts/bindings'/(owner_hash+'.json'),
        'contract':Path(run)/'task-contract.json','resolved_scope':Path(run)/'task-app-scope.json'}
    raws={name:read(path,65536) for name,path in paths.items()}
    template,binding,wrapper,resolved=[strict(raws[name]) for name in ('template','binding','contract','resolved_scope')]
    post.validate_template(template)
    need(template['schema']=='hepta.task-template.v150.3'
         and sha(raws['template'])==plan['task_template_sha256']
         and template['request_sha256']==owner_hash and template['nonce']==plan['nonce']
         and owner.decode().count(template['nonce'])==1
         and equal(template['expected_scope'],{k:actual[k] for k in ('session_id','profile_id')})
         and equal(template['app_scope'],plan['app_scope']),'original v150.3 template/owner/app tuple differs')
    post.validate_app_scope(template['app_scope'],owner_hash,config['approved_apps'])
    expected_binding=dict(schema='hepta.task-template-binding.v150.3',identity=identity,
        request_sha256=owner_hash,template_sha256=sha(raws['template']),nonce=plan['nonce'],
        state='consumed_no_reuse',app_scope=template['app_scope'],
        app_scope_sha256=post.app_scope_hash(template['app_scope']))
    need(equal(binding,expected_binding),'original consumed app-scope binding differs')
    contract=dict(schema='hepta.task-contract.v150.3',identity=identity,request_sha256=owner_hash,
        postconditions=template['postconditions'],coverage=template['coverage'],app_scope=template['app_scope'])
    expected_wrapper=dict(contract=contract,
        source_sha256=sha(json.dumps(contract,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()),
        binding_kind='one_time_request_template',template_sha256=sha(raws['template']),
        binding_sha256=sha(raws['binding']))
    need(equal(wrapper,expected_wrapper),'original trusted contract wrapper differs')
    selected,expected_scope=post.resolve_task_apps(wrapper,owner_hash,config['approved_apps'])
    need(equal(resolved,expected_scope) and resolved['mode']=='request_bound_explicit_subset',
         'actual resolved task app scope differs from production resolver')
    expected_component=plan.get('expected_probe_component') or plan.get('probe_component')
    if expected_component is not None:
        guards=importlib.import_module('phone_task_guards')
        need(expected_component in {guards.component(row['component']) for row in selected.values()},
             'operator expected probe lies outside explicit owner app subset')
    for name,path in paths.items():
        need(read(path,65536)==raws[name],'app-scope original changed during observation: '+name)
    return dict(schema='hepta.r10.original-task-scope-observation.v1',
        owner_request_sha256=owner_hash,accepted_identity=identity,
        app_scope_sha256=post.app_scope_hash(template['app_scope']),resolved=resolved,
        originals={name:dict(source=str(paths[name]),**raw_record(raw)) for name,raw in raws.items()},
        contract_registration_calls=0,physical_case_pass=False)



# Exact read-only primitives from the final reviewed readiness source.

def android_private(path,mode=0o600,limit=16*1024*1024):
    """Read below verified init root; no subsequent symbolic links are followed."""
    path=Path(path)
    need(path.is_relative_to(A),'Android read outside init root')
    parts=path.relative_to(A).parts
    need(parts and all(x not in ('','.', '..') for x in parts),'unsafe Android components')
    directory=os.open(A,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    descriptor=None
    try:
        for component in parts[:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            os.close(directory);directory=child
        descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
        before=os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
             before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==mode and
             0<=before.st_size<=limit,'private Android file metadata differs: '+str(path))
        raw=bytearray()
        while len(raw)<=limit:
            block=os.read(descriptor,min(65536,limit+1-len(raw)))
            if not block:break
            raw.extend(block)
        after=os.fstat(descriptor)
        named=os.stat(parts[-1],dir_fd=directory,follow_symlinks=False)
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_size','st_nlink','st_mtime_ns','st_ctime_ns')
        need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in fields),
             'private Android file changed during read')
        return bytes(raw)
    finally:
        if descriptor is not None:os.close(descriptor)
        os.close(directory)

def domain(path):
    raw=Path(path).read_bytes()
    if raw.endswith(b'\x00') or raw.endswith(b'\n'):raw=raw[:-1]
    need(b'\x00' not in raw and b'\n' not in raw and b'\r' not in raw,'malformed process domain')
    return raw.decode('ascii')

def process(pid):
    p=Path('/proc')/str(pid);raw=(p/'stat').read_text();tail=raw.rsplit(') ',1)[1].split()
    status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (p/'status').read_text().splitlines() if ':' in line}
    return dict(identity=[pid,int(tail[2]),int(tail[3]),int(tail[19])],state=tail[0],
                domain=domain(p/'attr/current'),uid=list(map(int,status['Uid'].split())),
                gid=list(map(int,status['Gid'].split())),no_new_privs=int(status['NoNewPrivs']),
                exe=os.readlink(p/'exe'))

def digest_file(path):
    h=hashlib.sha256();count=0
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):
            count+=len(block);need(count<32*1024*1024,'readiness source size bound');h.update(block)
    return h.hexdigest()

def sockets(pid):
    result=set()
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:target=os.readlink(fd)
        except FileNotFoundError:continue
        match=re.fullmatch(r'socket:\[([0-9]+)\]',target)
        if match:result.add(match.group(1))
    return result

def listen(port,pid):
    rows=[line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
    matches=[row for row in rows if row[1]=='0100007F:'+format(port,'04X') and row[3]=='0A']
    need(len(matches)==1 and matches[0][9] in sockets(pid),'owned loopback listener absent')
    return dict(address='127.0.0.1',port=port,inode=matches[0][9],owner_pid=pid)
