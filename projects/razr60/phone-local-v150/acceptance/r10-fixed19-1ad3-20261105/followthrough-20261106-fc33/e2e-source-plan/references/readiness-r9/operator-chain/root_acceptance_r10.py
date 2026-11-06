#!/usr/bin/env python3
"""Root-only r10 operator preparation, one registration and the unchanged sender.

prepare and sender-preview are host-only. register and sender-execute require
their explicit phase flags. No automatic retry, nonce generation or replacement
of any existing material, original claim, actor, sender or evidence is allowed.
"""
import argparse,base64,gzip,hashlib,importlib.util,io,json,os,re,shlex,stat,subprocess,sys,types
from pathlib import Path

HERE=Path(__file__).resolve().parent
GNU='/var/lib/trillionnium/owner-open/phone-local-v150'
SENDER_SHA='5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'
HARNESS_SHA='630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6'
MATERIALIZER_SHA='b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290'
READINESS_SHA='b0a3f3b4fbda835506c3d0f9099abbe3b47a10b6a131ee2069c9ef7350c6ba63'
TRANSPORT_SOURCE_SHA='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
BOUNDED_TRANSPORT_SCHEMA='hepta.root-bounded-inline.v150.r10.1'
MAX_TRANSPORT_JSON=2*1024*1024
MAX_TRANSPORT_PART=1024*1024
ADB_REQUEST_EXCLUSIVE_LIMIT=65536
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
KINDS={'health':'HEALTH','visual':'E2E-01','unicode':'E2E-02','calculator':'E2E-03','settings':'E2E-04'}
COLLECTOR_NAMES={'business_fact_recheck.py','collect_business_evidence.py','health_context_audit.py',
    'history_context_audit.py','ledger_prefix_audit.py','mobile_use_evidence.py','native_journal_audit.py'}

def need(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        v={}
        for k,x in rows:need(k not in v,'duplicate JSON field');v[k]=x
        return v
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def read(path,maximum=8*1024*1024,pin=None):
    p=Path(path).absolute();need(p.parent.resolve()==p.parent,'noncanonical source parent')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=maximum,'bounded regular input required')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
        z,n=os.fstat(fd),p.lstat()
        need(len(raw)==s.st_size and all(getattr(s,k)==getattr(z,k)==getattr(n,k)
             for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')),'input changed')
        need(pin is None or sha(raw)==pin,'input SHA differs: '+str(p));return raw
    finally:os.close(fd)
def put(p,raw):
    need(p.parent.resolve()==p.parent,'noncanonical output parent')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
def writej(p,v):return put(p,encoded(v))
def file_descriptor(path,pin=None,maximum=8*1024*1024):
    raw=read(path,maximum,pin);return {'path':str(Path(path).absolute()),'bytes':len(raw),'sha256':sha(raw)},raw
def module(path,pin,name):
    raw=read(path,1048576,pin);m=types.ModuleType(name);m.__file__=str(path)
    sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def relative(name):
    p=Path(name);need(not p.is_absolute() and p.parts and all(re.fullmatch('[A-Za-z0-9._-]+',x)
         and x not in ('.','..') for x in p.parts),'unsafe relative source path');return p
def manifest_sources(path,pin,prefix=None):
    desc,raw=file_descriptor(path,pin);value=strict(raw);rows=value['files'];found={}
    for row in rows:
        rel=relative(row['path'])
        if prefix is not None and (len(rel.parts)!=2 or rel.parts[0]!=prefix):continue
        body=read(Path(path).parent/rel,1048576,row['sha256']);need(len(body)==row['bytes'],'manifest size differs')
        key=rel.name if prefix else str(rel);need(key not in found,'duplicate manifest source');found[key]=row['sha256']
    return desc,value,found
def verify_ready(ready,release):
    need(ready.get('schema')=='hepta.r10.actual-readiness.v1'
         and ready.get('state')=='EXACT_COMBINATION_READY_TRANSPORT_ONLY','actual r10 ready observation required')
    for key in ('source_seal_sha256','configuration_sha256','module_manifest_sha256','service_inputs_sha256'):
        need(ready.get(key)==release['report'][key],'ready/release binding differs: '+key)
    for key in ('component_boundary_inputs_sha256','policy_adoption_inputs_sha256'):
        need(isinstance(ready.get(key),str) and re.fullmatch('[0-9a-f]{64}',ready[key])
             and ready[key]==release['report'].get(key)==release['binding'].get(key),
             'ready/explicit release boundary differs: '+key)
    need(ready.get('boot_id')==release['binding']['migration_boot'],'ready boot differs')
    need(set(ready.get('roles',{}))=={'supervisor','model','sidecar','provider'},'four original roles required')
    for name,v in ready['roles'].items():
        a=v.get('identity');need(isinstance(a,list) and len(a)==4 and all(type(x) is int and x>0 for x in a)
            and a[0]==a[1]==a[2] and v.get('state')!='Z' and v.get('uid')==v.get('gid')==[0]*4
            and v.get('no_new_privs')==0,'actual owned role differs: '+name)
    need(len({x['identity'][0] for x in ready['roles'].values()})==4,'role PID collision')
    p=ready['provider_ready'];need(p['accepting'] is True and p['pid']==ready['roles']['provider']['identity'][0]
        and p['port']==18080 and p['config_sha256']==release['report']['configuration_sha256']
        and p['service_manifest_sha256']==release['report']['service_inputs_sha256'],'provider accepting binding differs')
    actual=ready['actual_binding'];ident=actual['server_identity']
    need(actual['state']=='BOUND' and ident['boot_id']==ready['boot_id']
        and [ident[k] for k in ('pid','pgid','sid','start_ticks')]==ready['roles']['model']['identity'],'model binding identity differs')
    expected=GNU+'/model-runtime-r10-r1/'+ready['boot_id']+'/bindings/slot-cleanup-'+ready['boot_id']+'-'+str(ident['pid'])+'-'+str(ident['start_ticks'])+'.json'
    need(actual['path']==expected and re.fullmatch('[0-9a-f]{64}',actual['sha256']),'model binding path/hash differs')
    slot=ready['slot_observation'];need(slot['is_processing'] is False and slot['hepta_server']['identity']==ident,'ready slot identity differs')
    return {'boot_id':ready['boot_id'],'server_identity':ident,'binding_path':actual['path'],'binding_sha256':actual['sha256']}
def check_previous(previous):
    identity=previous.get('identity');need(isinstance(identity,dict) and set(identity)==set(KEYS),'previous five-scope original required')
    need(all(isinstance(x,str) and 0<len(x.encode())<=256 and '\0' not in x for x in identity.values()),'previous scope shape')
    need(re.fullmatch('[0-9a-f]{64}',previous.get('request_sha256','')),'previous native envelope digest')
    status=previous.get('terminal',{}).get('status')
    need(status in ('completed','provider_failed','cancelled') and (status=='completed'
        or previous.get('known_no_phone_tool_execution') is True
        or previous.get('known_all_dispatched_tools_confirmed_terminal') is True),'previous original lifecycle not closed')
def materializer(path):return module(path,MATERIALIZER_SHA,'pinned_root_materializer_r10')

def prepare(a):
    os.umask(0o077)
    b=a.project_dir.absolute();need(b.resolve()==b and b.is_dir(),'canonical project directory')
    out=a.out.absolute();need(b in out.parents and out.parent.resolve()==out.parent,'new owned workflow directory')
    need(re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',a.sender_label),'fresh explicit sender label')
    om,_,operators=manifest_sources(HERE/'SOURCE-MANIFEST.json',a.operator_manifest_sha256)
    expected={'root_acceptance_r10.py','registration_phone_r10.py','capture_originals_r10.py','read_archive_chunk_r10.py',
              'export_originals_r10.py','close_original_r10.py'}
    need(set(operators)==expected,'exact reviewed operator source set')
    mat=materializer(a.materializer)
    release=mat.validate_release(a.release_dir,a.build_result_sha256)
    build,_=file_descriptor(a.release_dir/'BUILD-RESULT.json',a.build_result_sha256)
    prev_desc,prev_raw=file_descriptor(a.previous_input,a.previous_sha256,262144);previous=strict(prev_raw);check_previous(previous)
    ready_desc,ready_raw=file_descriptor(a.ready_input,a.ready_sha256,262144);ready=strict(ready_raw)
    runtime=verify_ready(ready,release)
    draft_desc,draft_raw=file_descriptor(a.preserved_draft,a.preserved_draft_sha256,131072);draft=strict(draft_raw)
    exact=base64.b64decode(draft['exact_utf8_b64'],validate=True);exact.decode()
    need(exact and sha(exact)==draft['utf8_sha256'],'nonempty private original draft required')
    retirement_desc,_=file_descriptor(a.retirement_resolution,a.retirement_resolution_sha256,262144)
    collector_desc,collector_manifest,collectors=manifest_sources(a.collector_package/'MANIFEST.json',a.collector_package_sha256,'collector')
    need(set(collectors)==COLLECTOR_NAMES and collector_manifest['schema']=='hepta.r10.acceptance-tools.v1','full reviewed r10 collector set')
    selected={Path(r['path']).name:r['sha256'] for r in strict(release['source_seal_raw'])['production_files']}
    need(collector_manifest['reviewed_production_source_pins']==selected,'collector reviewed source set differs from actual release')
    seal=strict(release['source_seal_raw']);helpers={x['path']:x['sha256'] for x in seal['operator_helpers']}
    need(helpers.get('collect_r10_readiness.py')==READINESS_SHA,'readiness helper not sealed in release')
    h=a.material.absolute();need(b in h.parents and h.resolve()==h,'owned material directory')
    mdesc,mraw=file_descriptor(h/'material.json');m=strict(mraw)
    need(m['schema']=='hepta.fresh-acceptance-material.v150.r10.1' and m['kind'] in KINDS
         and m.get('release_id')=='v150-r10-r1' and m['case']==KINDS[m['kind']] and m['release_build_result_sha256']==a.build_result_sha256
         and m['combination_manifest_sha256']==sha(release['binding_raw'])
         and m['combination_sha256']==release['combination_sha256'],'actual material/full release differs')
    need(read(h/'combination.json')==release['binding_raw'],'material raw combination differs')
    files={}
    for row in m['files']:
        p=Path(row['path']);need(p.parent==h and re.fullmatch('[A-Za-z0-9._-]+',p.name),'material file location')
        raw=read(p,262144,row['sha256']);need(len(raw)==row['bytes'],'material file size')
        files[p.name]={'bytes':len(raw),'sha256':sha(raw)}
    files['material.json']={'bytes':len(mraw),'sha256':sha(mraw)}
    request=read(h/'request.txt',16000,m['request_sha256'])
    need(len(request)>=20 and request!=exact and re.fullmatch('[0-9a-f]{32}',m['nonce'])
        and request.decode().count(m['nonce'])==1,'exact owner request/nonce differs')
    scope_raw=read(h/'app-scope.json',16384,files['app-scope.json']['sha256']) if 'app-scope.json' in files else None
    mat.validate_material_app_scope(m,request,scope_raw,strict(release['config_raw']))
    plan=strict(read(h/'REGISTRATION-ARGV.json'))
    for key in ('session_id','profile_id'):
        flag='--'+key.replace('_','-');need(plan['argv'][plan['argv'].index(flag)+1]==previous['identity'][key],'material registration scope differs')
    expected_remote,expected_argv=mat.registration_argv(m,previous['identity']['session_id'],previous['identity']['profile_id'])
    need(plan.get('schema')=='hepta.r10.registration-plan.v1' and plan['argv']==expected_argv
         and plan.get('phone_case_directory')==expected_remote,'exact scoped registration plan differs')
    read(b/'send_new_native_task_r5.py',65536,SENDER_SHA)
    read(b/'root-operators-r6-cycle03/run_cycle03.py',16384,HARNESS_SHA)
    for suffix in ('.preview.actor.py','.actor.py','.local-once.json','.send-result.json'):
        need(not (b/(a.sender_label+suffix)).exists(),'sender label already has an original attempt')
    need(not out.exists(),'workflow already exists; inspect original intent')
    ctx={'schema':'hepta.root-acceptance-context.v150.r10.1','release_id':'v150-r10-r1','project_dir':str(b),'workflow_dir':str(out),
        'operator_directory':str(HERE),'materializer':str(a.materializer.absolute()),'release_dir':str(a.release_dir.absolute()),
        'material_dir':str(h),'export_dir':str(out/'export'),'closure_dir':str(out/'closure'),
        'sender_label':a.sender_label,'kind':m['kind'],'case':m['case'],'nonce':m['nonce'],
        'request_sha256':sha(request),'material':m,'material_files':files,
        'previous':previous,'ready':ready,'runtime':runtime,
        'release_pins':{k:release['report'][k] for k in ('source_seal_sha256','configuration_sha256','module_manifest_sha256','service_inputs_sha256','component_boundary_inputs_sha256','policy_adoption_inputs_sha256')},
        'combination_manifest_sha256':sha(release['binding_raw']),'combination_sha256':release['combination_sha256'],
        'collector_dir':str(a.collector_package.absolute()/'collector'),'collector_files':collectors,'operator_files':operators,
        'readiness_helper_sha256':READINESS_SHA,'registrar_sha256':helpers[m['registration_helper']],
        'inputs':{'previous':prev_desc,'ready':ready_desc,'preserved_draft':draft_desc,'retirement_resolution':retirement_desc,
                  'build_result':build,'operator_manifest':om,'collector_manifest':collector_desc,'material':mdesc},
        'max_tool_calls':7,'max_model_rounds':8,'phone_calls':0,'model_requests':0,'nonce_generated_here':False,
        'automatic_retry':False,'registered':False,'dispatched':False}
    out.mkdir(mode=0o700)
    result=writej(out/'ROOT-CONTEXT.json',ctx)
    print(json.dumps({'state':'HOST_ONLY_OPERATOR_CONTEXT_PREPARED','context':result,'case':ctx['case'],
        'phase_order':['register','sender-preview','sender-execute','capture','export','collect','close'],
        'phone_calls':0,'model_requests':0,'new_nonce_generated':False},sort_keys=True));return 0

def load_context(path,pin):
    raw=read(path,1048576,pin);ctx=strict(raw)
    need(ctx.get('schema')=='hepta.root-acceptance-context.v150.r10.1' and ctx.get('release_id')=='v150-r10-r1','operator context/release schema')
    need(Path(ctx['operator_directory'])==HERE,'operator directory differs')
    for name,digest in ctx['operator_files'].items():read(HERE/relative(name),1048576,digest)
    for row in ctx['inputs'].values():need(len(read(row['path'],1048576,row['sha256']))==row['bytes'],'selected input length changed')
    for name,pin in ctx['collector_files'].items():read(Path(ctx['collector_dir'])/name,1048576,pin)
    h=Path(ctx['material_dir'])
    for name,row in ctx['material_files'].items():need(len(read(h/name,262144,row['sha256']))==row['bytes'],'material changed')
    mat=materializer(Path(ctx['materializer']))
    release=mat.validate_release(ctx['release_dir'],ctx['inputs']['build_result']['sha256'])
    scope_raw=read(h/'app-scope.json',16384,ctx['material_files']['app-scope.json']['sha256']) if 'app-scope.json' in ctx['material_files'] else None
    mat.validate_material_app_scope(ctx['material'],read(h/'request.txt',16000,ctx['request_sha256']),
                                   scope_raw,strict(release['config_raw']))
    need(ctx['release_pins']=={k:release['report'][k] for k in ('source_seal_sha256','configuration_sha256','module_manifest_sha256','service_inputs_sha256','component_boundary_inputs_sha256','policy_adoption_inputs_sha256')},'context selected release pins differ')
    verify_ready(ctx['ready'],release);check_previous(ctx['previous'])
    need(strict(read(ctx['inputs']['ready']['path']))==ctx['ready']
         and strict(read(ctx['inputs']['previous']['path']))==ctx['previous'],'context copied original differs')
    return ctx,release
def harness(ctx,out):
    path=Path(ctx['project_dir'])/'root-operators-r6-cycle03/run_cycle03.py'
    h=module(path,HARNESS_SHA,'root_once_exact_transport');h.D=out;return h
def bounded_phone_request(source_name,source,argument,timeout):
    """Versioned transport only: exact source/argv, bounded decode, same ADB limit."""
    need(source_name in {'registration_phone_r10.py','capture_originals_r10.py','read_archive_chunk_r10.py'},'reviewed transport program required')
    if isinstance(source,str):source=source.encode('utf-8')
    need(type(source) is bytes and 0<len(source)<=MAX_TRANSPORT_PART,'transport source bound')
    source.decode('utf-8',errors='strict')
    need(isinstance(argument,str) and 0<len(argument.encode('ascii'))<=MAX_TRANSPORT_PART,'transport argument bound')
    base64.b64decode(argument,validate=True)
    need(type(timeout) is int and 1<=timeout<=300,'original operation timeout bound')
    envelope=encoded({'schema':BOUNDED_TRANSPORT_SCHEMA,'source_name':source_name,
        'source_b64':base64.b64encode(source).decode(),'source_bytes':len(source),'source_sha256':sha(source),
        'argument':argument,'argument_bytes':len(argument),'argument_sha256':sha(argument.encode('ascii'))})
    need(0<len(envelope)<=MAX_TRANSPORT_JSON,'transport envelope bound')
    stream=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0,compresslevel=9) as gz:gz.write(envelope)
    packed=stream.getvalue();packed_b64=base64.b64encode(packed).decode()
    bootstrap='''import base64,hashlib,json,sys,zlib
def require(ok,why):
 if not ok:raise ValueError(why)
def digest(raw):return hashlib.sha256(raw).hexdigest()
packed=base64.b64decode(%r,validate=True)
require(len(packed)==%d and digest(packed)==%r,'compressed transport bytes differ')
expected=%d
require(0<expected<=2097152,'transport decompression output bound')
decoder=zlib.decompressobj(31)
raw=decoder.decompress(packed,expected+1)
require(len(raw)==expected and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,'bounded transport stream differs')
require(digest(raw)==%r,'transport envelope digest differs')
def pairs(rows):
 value={}
 for key,item in rows:
  require(key not in value,'duplicate transport key');value[key]=item
 return value
v=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite transport JSON')))
require(set(v)=={'schema','source_name','source_b64','source_bytes','source_sha256','argument','argument_bytes','argument_sha256'} and v['schema']==%r,'transport envelope schema')
require(v['source_name'] in {'registration_phone_r10.py','capture_originals_r10.py','read_archive_chunk_r10.py'},'transport source name')
source=base64.b64decode(v['source_b64'],validate=True)
require(0<len(source)<=1048576 and len(source)==v['source_bytes'] and digest(source)==v['source_sha256'],'original source bytes differ')
argument=v['argument'];require(isinstance(argument,str),'original argument type')
arg=argument.encode('ascii');require(0<len(arg)<=1048576 and len(arg)==v['argument_bytes'] and digest(arg)==v['argument_sha256'],'original argument bytes differ')
base64.b64decode(argument,validate=True)
sys.argv=['-c',argument]
exec(compile(source,v['source_name'],'exec'),{'__name__':'__main__','__file__':v['source_name']})
'''%(packed_b64,len(packed),sha(packed),len(envelope),sha(envelope),BOUNDED_TRANSPORT_SCHEMA)
    command='/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -B -c '+shlex.quote(bootstrap)
    # This is the exact immutable actor's su quoting and immutable shell service prefix.
    wire=('shell,v2,raw:'+'/debug_ramdisk/su -c '+shlex.quote(command)).encode('utf-8')
    need(len(wire)<ADB_REQUEST_EXCLUSIVE_LIMIT,'bounded wrapper still exceeds original ADB request limit; no dispatch')
    request={'kind':'shell','root':True,'timeout_seconds':timeout,'command':command}
    binding={'schema':BOUNDED_TRANSPORT_SCHEMA,'source_name':source_name,'source_bytes':len(source),
        'source_sha256':sha(source),'argument_bytes':len(argument),'argument_sha256':sha(argument.encode('ascii')),
        'envelope_bytes':len(envelope),'envelope_sha256':sha(envelope),'gzip_bytes':len(packed),'gzip_sha256':sha(packed),
        'adb_service_bytes':len(wire),'adb_exclusive_limit':ADB_REQUEST_EXCLUSIVE_LIMIT,
        'frozen_transport_source_sha256':TRANSPORT_SOURCE_SHA,'decompressed_source_and_argv_are_exact':True,
        'source_and_argv_execution_semantics_preserved':True,'automatic_retry':False}
    return request,binding
def phone_once(ctx,out,label,source_name,payload,timeout=65):
    source=read(HERE/source_name,1048576,ctx['operator_files'][source_name])
    arg=base64.b64encode(encoded(payload)).decode()
    req,binding=bounded_phone_request(source_name,source,arg,timeout)
    writej(out/(label+'.transport.json'),binding)
    writej(out/(label+'.request.json'),req)
    h=harness(ctx,out)
    try:ph=h.call_phone(label,req)
    except AssertionError:
        original=strict(read(out/(label+'.original-operation.json'),8*1024*1024));ph=original.get('wrapper',{}).get('phone',{})
    original=strict(read(out/(label+'.original-operation.json'),8*1024*1024))
    need(type(original.get('actor_rc')) is int and original['actor_rc']==0
         and original.get('wrapper',{}).get('phone')==ph
         and type(ph.get('rc')) is int and ph['rc']==0 and isinstance(ph.get('stdout'),str),
         'original actor/phone operation unconfirmed; inspect retained original, never re-dispatch')
    return ph,strict(ph['stdout'])
def registration_payload(ctx,operation):
    payload={'operation':operation,'ready':ctx['ready'],'release_pins':ctx['release_pins'],
        'readiness_helper_sha256':ctx['readiness_helper_sha256']}
    if operation=='register':
        files={}
        for name,row in ctx['material_files'].items():
            raw=read(Path(ctx['material_dir'])/name,262144,row['sha256'])
            files[name]={**row,'raw_b64':base64.b64encode(raw).decode()}
        payload.update(kind=ctx['kind'],nonce=ctx['nonce'],request_sha256=ctx['request_sha256'],
            files=files,previous=ctx['previous'],previous_input_sha256=ctx['inputs']['previous']['sha256'],
            registrar_sha256=ctx['registrar_sha256'])
    return payload
def register(ctx):
    out=Path(ctx['workflow_dir'])/'register';out.mkdir(mode=0o700)
    _,result=phone_once(ctx,out,ctx['sender_label']+'-register-gzip-r2','registration_phone_r10.py',registration_payload(ctx,'register'))
    need(result['rc']==0 and result['unconsumed_template_read_back'] is True
        and result['request_sha256']==ctx['request_sha256'] and result['nonce']==ctx['nonce']
        and result['previous_input_sha256']==ctx['inputs']['previous']['sha256'],'registered original binding differs')
    record=writej(out/'REGISTRATION-RESULT.json',result)
    print(json.dumps({'state':'REGISTERED_ONCE_NO_SEND','result':record,'send_attempts':0,'model_requests':0},sort_keys=True));return 0
def sender(ctx,execute):
    b=Path(ctx['project_dir']);registration=strict(read(Path(ctx['workflow_dir'])/'register/REGISTRATION-RESULT.json'))
    need(registration['rc']==0 and registration['unconsumed_template_read_back'] is True
         and registration['request_sha256']==ctx['request_sha256'],'unconfirmed registration')
    path=b/'send_new_native_task_r5.py';read(path,65536,SENDER_SHA)
    args=[sys.executable,'-B',str(path),ctx['sender_label'],str(Path(ctx['material_dir'])/'request.txt'),
        ctx['inputs']['previous']['path'],'--preserved-draft',ctx['inputs']['preserved_draft']['path'],
        '--retirement-resolution',ctx['inputs']['retirement_resolution']['path'],'--evidence-root','production']
    if ctx['kind'] in ('visual','unicode'):args+=['--reset-probe']
    phase='sender-execute' if execute else 'sender-preview';out=Path(ctx['workflow_dir'])/phase;out.mkdir(mode=0o700)
    if execute:
        preview=strict(read(Path(ctx['workflow_dir'])/'sender-preview/PREVIEW-RESULT.json'))
        actual_preview=read(b/(ctx['sender_label']+'.preview.actor.py'),262144,preview['actor_sha256'])
        need(preview['state']=='BUILT_ONLY_NO_PHONE' and preview['phone_calls']==0,'preview did not complete')
        _,gate=phone_once(ctx,out,ctx['sender_label']+'-send-gate-gzip-r2','registration_phone_r10.py',registration_payload(ctx,'check'))
        need(gate['state']=='EXACT_ORIGINAL_READY_RECHECKED','selected ready gate changed')
        writej(out/'READINESS-GATE.json',gate);args+=['--execute-once']
    writej(out/'INTENT.json',{'argv':args,'sender_sha256':SENDER_SHA,'previous_input_sha256':ctx['inputs']['previous']['sha256'],
        'request_sha256':ctx['request_sha256'],'execute_once':execute,'automatic_retry':False})
    r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=620 if execute else 20)
    put(out/'stdout',r.stdout);put(out/'stderr',r.stderr)
    writej(out/'HOST-TERMINAL.json',{'returncode':r.returncode,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr),
        'automatic_retry':False,'new_send_attempt_permitted':False})
    need(r.returncode==0 and r.stderr==b'','sender original process unconfirmed; inspect same original')
    result=strict(r.stdout)
    if execute:
        actual=read(b/(ctx['sender_label']+'.actor.py'),262144)
        need(actual==actual_preview,'executed actor differs from exact preview')
        writej(out/'SENDER-RESULT.json',result)
        print(json.dumps({'state':'ORIGINAL_SENDER_RETURNED_REQUIRES_CAPTURE','business_success_asserted':False,
            'sender_label':ctx['sender_label'],'automatic_retry':False},sort_keys=True))
    else:
        need(result['state']=='BUILT_ONLY_NO_PHONE' and result['phone_calls']==result['send_attempts']==0,'sender preview state')
        writej(out/'PREVIEW-RESULT.json',result);print(json.dumps(result,sort_keys=True))
    return 0

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='phase',required=True)
    q=sub.add_parser('prepare')
    for name in ('project-dir','materializer','release-dir','material','previous-input','ready-input','preserved-draft',
                 'retirement-resolution','collector-package','out'):q.add_argument('--'+name,type=Path,required=True)
    for name in ('build-result-sha256','previous-sha256','ready-sha256','preserved-draft-sha256',
                 'retirement-resolution-sha256','operator-manifest-sha256','collector-package-sha256','sender-label'):
        q.add_argument('--'+name,required=True)
    for phase in ('register','sender-preview','sender-execute'):
        q=sub.add_parser(phase);q.add_argument('--context',type=Path,required=True);q.add_argument('--context-sha256',required=True)
        if phase!='sender-preview':q.add_argument('--execute-'+('register-once' if phase=='register' else 'send-once'),action='store_true')
    a=p.parse_args()
    if a.phase=='prepare':return prepare(a)
    if a.phase=='register':need(a.execute_register_once,'explicit Root one-time registration phase required')
    if a.phase=='sender-execute':need(a.execute_send_once,'explicit Root one-time Send phase required')
    ctx,_=load_context(a.context,a.context_sha256)
    return register(ctx) if a.phase=='register' else sender(ctx,a.phase=='sender-execute')
if __name__=='__main__':raise SystemExit(main())
