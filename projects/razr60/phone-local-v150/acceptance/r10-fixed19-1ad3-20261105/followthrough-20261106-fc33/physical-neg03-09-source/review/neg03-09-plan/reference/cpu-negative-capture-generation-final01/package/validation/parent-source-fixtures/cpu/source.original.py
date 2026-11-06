"""Pure verification of existing NEG-08/09 CPU cancellation originals.

No transport, model, signal, UI, subprocess, filesystem read or write is present.
read_pinned is supplied by a host caller that retains original source metadata
and rechecks its read set. A successful CPU result does not close a native case.
"""
import ast
import base64
import gzip
import hashlib
import hmac
import json
import re
import shlex
import stat
import struct
import types
import zlib
from pathlib import PurePosixPath as Path

SCHEMA = 'hepta.r10.cpu-cancel-original-inputs.v1'
RESULT_SCHEMA = 'hepta.r10.cpu-cancel-original-verification.v1'
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
P4 = '/home/alex/razr60-local-model-v150'
KEYS = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
UI_PACKAGE_SHA = '65720e417594205b45172fe509f3419d607d3dbf1e579b2a17faa8b40315ca10'
CONFIG_SHA = '780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'
SERVICE_SHA = '2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'
MODEL_SHA = 'dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c'
POLICY_SHA = '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
ADOPTION_SHA = 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
OPERATOR_SOURCES = {
 'active_runtime_r10.py':'f1a68fcc420799a7221019afdcda046a8d297b23d674e1e2642e888df26635dd',
 'cancel_native_once_r10.py':'d973891aa125ce2deb2237064fbc101d5d9d915d9e4bd75e25e4da298eecd5f1',
 'cancel_phase.py':'36890bfb9dbbf324963a92c93e45d211a574fcb8e360c8e413669ce2ce607ed2',
 'decode_client_state.py':'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073',
 'native_journal_audit.py':'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf',
 'observe_cancel_phase_r10.py':'0418a96677d6561ef44f03a59f62997fb616ca0f091285c9ab9bf7cfb4885cb9',
 'production-pins.json':'73963fdcea527cdbc3628bdeff5918f7106afbaf095fb183e4b199391e46a7a5',
 'reviewed_page_projection.py':'96a1af463b205adf5baa544a9a27122fc7424e72fcc38e2fd4bcf26533ea7c93'}
PURE_SOURCES = {
 'model_slot_cleanup.py':'9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183',
 'close_original_r10.py':'19af371cb5271ea6b3f8c2929ab969357aee07d14d498dcf50f57e9b3bbc9e75',
 'task_postconditions.py':'d4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3',
 'configuration':CONFIG_SHA, 'service':SERVICE_SHA}
MAX_TOTAL = 64*1024*1024
MAX_FILE = 16*1024*1024
PROTOCOL = 'trillionnium.owner-open.provider-jsonl.v1'
ROOT = Path('/retained-originals')
SELECTED_READ = ('test ! -e /data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.pending && '
 'base64 /data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.bin && '
 'test ! -e /data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.pending')

class Unverified(ValueError):
    pass

def need(value, message):
    if not value:
        raise Unverified(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(rows):
        out = {}
        for key,value in rows:
            need(key not in out, 'duplicate original JSON key')
            out[key] = value
        return out
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Unverified('nonfinite JSON')))

def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()

def equal(a,b):
    return encoded(a)==encoded(b)

def number(value, minimum=0, maximum=2**63-1):
    return type(value) is int and minimum<=value<=maximum

def descriptor(value, maximum=MAX_FILE):
    need(isinstance(value,dict) and set(value)=={'path','bytes','sha256'}, 'exact retained descriptor required')
    p=value['path']
    need(isinstance(p,str) and p.startswith('/') and '\0' not in p and
         str(Path(p))==p and '..' not in Path(p).parts, 'retained path differs')
    need(number(value['bytes'],0,maximum) and isinstance(value['sha256'],str) and
         re.fullmatch('[0-9a-f]{64}',value['sha256']), 'retained byte pin differs')
    return value

def embedded(row, maximum=MAX_FILE):
    need(isinstance(row,dict) and number(row.get('bytes'),0,maximum) and
         isinstance(row.get('raw_b64'),str) and len(row['raw_b64'])<=4*((maximum+2)//3),
         'embedded original bound')
    raw=base64.b64decode(row['raw_b64'],validate=True)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'], 'embedded original byte pin')
    return raw

class Originals:
    def __init__(self, callback):
        self.callback=callback
        self.seen={}
        self.total=0
    def read(self,row,maximum=MAX_FILE):
        descriptor(row,maximum)
        raw=self.callback(row)
        need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256'],
             'retained original bytes differ: '+row['path'])
        key=(row['path'],row['bytes'],row['sha256'])
        previous=self.seen.get(row['path'])
        if previous is None:
            self.total+=len(raw)
            need(self.total<=MAX_TOTAL,'original verification byte budget')
            self.seen[row['path']]=(key,raw,dict(row))
        else:
            need(previous[0]==key and previous[1]==raw,'retained original changed between reads')
        return raw
    def recheck(self):
        for key,raw,row in self.seen.values():
            need(self.callback(row)==raw,'retained original changed after verification')
    def descriptors(self):
        return [self.seen[p][2] for p in sorted(self.seen)]

def retained(row, source, originals, maximum=MAX_FILE):
    need(isinstance(row,dict) and set(row)=={'source','bytes','sha256','metadata','retained'},
         'original source/retained mapping fields differ')
    need(row['source']==source,'original source path differs')
    metadata=row['metadata']
    need(isinstance(metadata,dict) and set(metadata)==set(META) and
         all(type(x) is int for x in metadata.values()) and
         stat.S_ISREG(metadata['st_mode']) and metadata['st_nlink']==1 and
         metadata['st_size']==row['bytes'], 'original full metadata/type differs')
    raw=originals.read(row['retained'],maximum)
    need(row['bytes']==len(raw) and row['sha256']==sha(raw),'source and retained original differ')
    return raw

def projection(raw, functions, constants=(), namespace=None):
    """Execute only exact reviewed pure function/constant AST nodes, no imports."""
    tree=ast.parse(raw)
    out=dict(namespace or {})
    nodes=[]
    seen=set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in functions:
            nodes.append(node);seen.add(node.name)
        elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in constants:
                nodes.append(node);seen.add(name)
    need(seen==set(functions)|set(constants),'reviewed pure projection member set differs')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<reviewed-pure-projection>','exec',optimize=0),out)
    return types.SimpleNamespace(**out)

def load_apis(value, originals):
    need(set(value['operator_sources'])==set(OPERATOR_SOURCES),'eight reviewed operator sources required')
    loaded={}
    for name,pin in OPERATOR_SOURCES.items():
        raw=originals.read(value['operator_sources'][name],1048576)
        need(sha(raw)==pin,'operator source is not the frozen R6 dependency revision: '+name)
        loaded['source/'+name]=raw
    raw=originals.read(value['operator_package'],65536)
    need(sha(raw)==UI_PACKAGE_SHA,'actual final UI package differs')
    manifest=strict(raw)
    need(manifest['schema']=='hepta.r10.native-cancel-operator-package.v1' and
         len(manifest['files'])==8 and
         {r['path']:r['sha256'] for r in manifest['files']}==
         {'source/'+k:v for k,v in OPERATOR_SOURCES.items()}, 'operator source inventory differs')
    for row in manifest['files']:
        need(len(loaded[row['path']])==row['bytes'],'operator source original size differs')
    need(set(value['reviewed_sources'])==set(PURE_SOURCES),'pure source/config/service fields differ')
    pure={}
    for name,pin in PURE_SOURCES.items():
        pure[name]=originals.read(value['reviewed_sources'][name],1048576)
        need(sha(pure[name])==pin,'reviewed receipt/source/config pin differs: '+name)
    ns=dict(base64=base64,hashlib=hashlib,json=json,re=re,Path=Path)
    active=projection(loaded['source/active_runtime_r10.py'],
        {'need','sha','strict','encoded','equal','raw_record','decode_record','role_rows',
         'validate_runtime_binding','validate_task_expectations'},
        {'CONFIG_SHA','SERVICE_SHA','POLICY_SHA','PARENT_POLICY_SHA','ADOPTION_SHA','MODEL_EXE',
         'SIDECAR_EXE','SHA_RE','PIN_KEYS','ROLE_KEYS','READY_FIELDS'},ns)
    phase=projection(loaded['source/cancel_phase.py'],
        {'need','sha','strict','encoded','scope','native_request_digest','validate_plan','phase_ready',
         'selected_matches','unique_ui_node'}, {'KEYS','HEPTA','MUTATIONS'},
        dict(ns,active=active,ET=__import__('xml.etree.ElementTree',fromlist=['ElementTree'])))
    build=projection(loaded['source/cancel_native_once_r10.py'],{'build_observer_request'},(),
        dict(ns,need=need,encoded=encoded,sha=sha,gzip=gzip,shlex=shlex))
    audit_ns={}
    exec(compile(loaded['source/native_journal_audit.py'],'<reviewed-native-audit>','exec'),audit_ns)
    page_ns={}
    exec(compile(loaded['source/reviewed_page_projection.py'],'<reviewed-page-projection>','exec'),page_ns)
    decoder=projection(loaded['source/decode_client_state.py'],{'decode_client_state'},
        {'UUID','HEX64','DOMAINS'},dict(ns,hmac=hmac,struct=struct))
    cleanup=projection(pure['model_slot_cleanup.py'],
        {'require','validate_original_records','assess_original'},(),
        dict(ns,strict_json=strict))
    # These original functions only read the supplied snapshot object; the
    # original positive-case CLI/case admission is neither loaded nor invoked.
    closure=projection(pure['close_original_r10.py'],{'original_http','verify_cleanup'},(),
        dict(ns,need=need,sha=sha,strict=strict,zero=lambda v:type(v) is int and v==0))
    post=projection(pure['task_postconditions.py'],
        {'require','app_scope_hash','validate_app_scope','resolve_task_apps','validate_conditions','validate_template'},
        {'SHA','ID','PACKAGE','VIEW','APP_COMPONENT','TASK_VERSIONS','APP_SCOPE_SCHEMA'},
        dict(ns,ProviderError=Unverified))
    return types.SimpleNamespace(active=active,phase=phase,build=build,post=post,
        audit=types.SimpleNamespace(**audit_ns),page=types.SimpleNamespace(**page_ns),
        decoder=decoder,cleanup=cleanup,closure=closure,loaded=loaded,pure=pure,manifest=manifest)

def parse_observer_command(command):
    need(isinstance(command,str) and len(('shell,v2,raw:'+command).encode())<65536,
         'actual single-su ADB wire bound')
    top=shlex.split(command)
    need(len(top)==3 and top[:2]==['/debug_ramdisk/su','-c'] and
         command=='/debug_ramdisk/su -c '+shlex.quote(top[2]),'single su observer envelope differs')
    inner=shlex.split(top[2])
    prefix=['/data/adb/magisk/busybox','timeout','-s','TERM','-k','1','8',
            '/data/adb/magisk/busybox','chroot','/data/trillionnium/owner-open/root',
            '/usr/bin/python3','-I','-B','-c']
    need(len(inner)==len(prefix)+2 and inner[:len(prefix)]==prefix and
         len(top[2].encode())<62000,'original bounded observer argv differs')
    bootstrap,wire=inner[-2:]
    need(top[2]==' '.join(prefix)+' '+shlex.quote(bootstrap)+' '+shlex.quote(wire),
         'observer shell has unreviewed syntax')
    packed=base64.b64decode(wire,validate=True)
    d=zlib.decompressobj(31)
    payload=d.decompress(packed,262145)
    need(len(payload)<=262144 and d.eof and not d.unused_data and not d.unconsumed_tail,
         'original observer decompression bound or trailing data')
    return bootstrap,payload

def wire_value(row):
    need(isinstance(row,dict) and row.get('automatic_retry') is False and row.get('error') is None,
         'original operator call failed or retried')
    need(number(row.get('p4_monotonic_started_ns')) and
         number(row.get('p4_monotonic_finished_ns')) and
         row['p4_monotonic_started_ns']<=row['p4_monotonic_finished_ns'],'operator monotonic window differs')
    wire=row.get('original_wire_receipt')
    need(isinstance(wire,dict) and type(wire.get('rc')) is int and wire['rc']==0 and
         isinstance(wire.get('stdout'),str) and isinstance(wire.get('stderr'),str),
         'actual original wire result is not a complete zero terminal')
    return wire

def scope_native(observation,plan,api,terminal):
    actual=api.phase.scope(observation['scope'])
    need(actual!=plan['previous_scope'],'old native task cannot qualify')
    rows=observation['native_originals']
    need(isinstance(rows,list) and 1<=len(rows)<=2048,'native original record count')
    records=[]
    for row in rows:
        need(isinstance(row.get('source'),str) and row['source'].startswith(BASE.rsplit('/',1)[0]+'/turn-events.jsonl.segments/')
             and row['source'].endswith('.jsonl') and number(row.get('offset')), 'native original source mapping')
        raw=embedded(row,4*1024*1024)
        need(raw.endswith(b'\n') and len(raw.splitlines())==1,'native original line framing')
        record=strict(raw)
        payload_hash,record_hash=api.audit.record_hashes(record)
        need(payload_hash==record['payload_sha256'] and record_hash==record['record_sha256'] and
             record['scope']==actual,'native original record integrity')
        records.append(record)
    need([r['turn_seq'] for r in records]==list(range(len(records))) and
         len({r['store_seq'] for r in records})==len(records),'complete original turn sequence required')
    frames=[r['payload']['frame'] for r in records]
    digest=api.phase.native_request_digest(actual,base64.b64decode(plan['request_b64'],validate=True))
    need(observation['native_request_sha256']==digest and
         [f['host_seq'] for f in frames]==list(range(len(frames))) and
         frames[0]['kind']=='turn.accepted','native owner digest/admission differs')
    for record,frame in zip(records,frames):
        need({k:frame.get(k) for k in KEYS}==actual and frame['kind']==record['kind'] and
             frame['event_id']==record['event_id'] and record['payload']['request_sha256']==digest and
             frame['payload']['turn_request_sha256']==digest,'native five-scope/request link differs')
    ends=[f for f in frames if f['kind']=='turn.end']
    cancels=[f for f in frames if f['kind']=='turn.cancel.accepted']
    need(len(ends)<=1 and (not ends or frames[-1]==ends[0]),'native terminal order differs')
    need(observation['native_accepted'] is True and
         equal(observation['native_terminal'],ends[0] if ends else None) and
         observation['cancel_acceptances']==len(cancels) and
         equal(observation['cancel_acceptance_frames'],cancels),'native summary differs from original bytes')
    if terminal:
        result=api.audit.verify_records(records,actual)
        need(result['status']=='PASS' and result['errors']==[] and result['unsupported']==[],
             'terminal native raw audit incomplete')
    return frames

def runtime_observation(observation,plan,ready):
    row=observation['runtime_observation']
    need(row.get('schema')=='hepta.r10.active-runtime-observation.v1' and
         row['boot_id']==plan['expected_boot'] and
         row['runtime_binding_sha256']==sha(encoded(plan['runtime_binding'])) and
         equal(row['readiness_original'],plan['runtime_binding']['readiness']) and
         equal(row['release_pins'],plan['runtime_binding']['release_pins']) and
         row['policy_sha256']==POLICY_SHA,'actual active READY/release binding differs')
    for flag in ('idle_gate_called','retired_absence_gate_called','physical_case_pass'):
        need(row.get(flag) is False,'active observation is not the frozen contract')
    for flag in ('model_requests','task_submissions','ui_actions','signals_sent'):
        need(type(row.get(flag)) is int and row[flag]==0,'active verifier produced an action')
    need(set(row['roles'])==set(row['role_claim_originals'])==set(ready['roles']),
         'four actual active roles required')
    for name,wanted in ready['roles'].items():
        current=row['roles'][name]
        need(current['state'] in ('R','S','D','I') and
             all(equal(current[k],wanted[k]) for k in ('identity','domain','uid','gid','no_new_privs','exe')),
             'actual live role generation/credentials changed')
        claim=embedded(row['role_claim_originals'][name],4096)
        need(list(map(int,claim.decode('ascii').strip().split(':')))==wanted['identity'],
             'actual role claim original differs')
    provider=strict(embedded(row['provider_ready_original'],65536))
    need(provider.get('accepting') is True and provider.get('workers')==1 and
         provider['pid']==ready['roles']['provider']['identity'][0] and provider['port']==18080 and
         provider['config_sha256']==CONFIG_SHA and provider['service_manifest_sha256']==SERVICE_SHA and
         provider['source_sha256']=='f42fa1f3268d2a2c00e49610d356b440d1e32722fbe2af877580fb6eb180f712',
         'provider actual source/config readiness differs')
    bound_raw=embedded(row['model_ready_bound_original'],1048576)
    binding_raw=embedded(row['model_binding_original'],65536)
    bound,binding=strict(bound_raw),strict(binding_raw)
    model_identity=ready['roles']['model']['identity']
    server={'schema':'hepta.llama-server-identity.v1','boot_id':plan['expected_boot'],
            **dict(zip(('pid','pgid','sid','start_ticks'),model_identity))}
    need(bound['state']=='READY_BOUND_IMAGE_CANCEL_REQUIRED' and
         equal(bound['binding'],ready['actual_binding']) and
         bound['binding']['sha256']==sha(binding_raw) and
         binding['server_identity']==server and binding['server_binary_sha256']==MODEL_SHA and
         binding['server_domain']=='u:r:magisk:s0' and
         binding['endpoint']=='http://127.0.0.1:18087/v1/chat/completions' and
         binding['model_claim']==BASE+'/model-runtime-r10-r1/'+plan['expected_boot']+'/model.identity',
         'original CPU server generation/binding differs')
    return server,bound_raw,binding_raw

def source_record(row,expected_source,maximum=MAX_FILE):
    need(row.get('source')==expected_source,'embedded phone source path differs')
    return embedded(row,maximum)

class PhoneOriginals:
    def __init__(self,rows,originals,run,boot):
        need(isinstance(rows,dict) and 1<=len(rows)<=2048,'finite phone original mapping required')
        self.rows=rows;self.originals=originals;self.used=set();self.run=run;self.boot=boot
    def key(self,path):
        p=Path(str(path))
        need(p.is_relative_to(ROOT),'original projection path outside retained root')
        rel=str(p.relative_to(ROOT))
        need('..' not in p.parts and rel in self.rows,'required phone original missing: '+rel)
        return rel
    def source(self,rel):
        if rel.startswith('runtime/'):
            return BASE+'/model-runtime-r10-r1/'+self.boot+'/'+rel[8:]
        return BASE+'/'+rel
    def read(self,path,maximum=MAX_FILE):
        rel=self.key(path);self.used.add(rel)
        return retained(self.rows[rel],self.source(rel),self.originals,maximum)
    def json(self,path,maximum=MAX_FILE):
        return strict(self.read(path,maximum))
    def pinned(self,path,pin,maximum=MAX_FILE):
        raw=self.read(path,maximum);need(sha(raw)==pin,'phone original raw pin differs');return raw


def directory_original(row,source,names):
    need(isinstance(row,dict) and set(row)=={'source','metadata_before','metadata_after','names_before','names_after'}
         and row['source']==source,'original directory record fields/path differ')
    before,after=row['metadata_before'],row['metadata_after']
    need(isinstance(before,dict) and set(before)==set(META) and
         all(type(x) is int for x in before.values()) and stat.S_ISDIR(before['st_mode']) and
         equal(before,after),'original directory bookends differ')
    need(row['names_before']==row['names_after']==sorted(names) and len(set(names))==len(names),
         'original directory names are incomplete/changed')
    need(all(isinstance(x,str) and re.fullmatch('[A-Za-z0-9._-]{1,192}',x) and x not in ('.','..')
             for x in names),'original directory contains an unreviewed name')

def task_scope(observation,plan,api,phone):
    run=observation['run'];actual=observation['scope'];owner=plan['owner_request_sha256']
    paths={'template':BASE+'/provider-state/task-contracts/templates/'+owner+'.json',
           'binding':BASE+'/provider-state/task-contracts/bindings/'+owner+'.json',
           'contract':BASE+'/provider-state/evidence/'+run+'/task-contract.json',
           'resolved_scope':BASE+'/provider-state/evidence/'+run+'/task-app-scope.json'}
    observed=observation['task_scope_originals']
    need(observed['schema']=='hepta.r10.original-task-scope-observation.v1' and
         observed['owner_request_sha256']==owner and
         observed['accepted_identity']=={k:actual[k] for k in KEYS[:-1]} and
         observed['contract_registration_calls']==0 and observed['physical_case_pass'] is False and
         set(observed['originals'])==set(paths),'original task scope receipt differs')
    raws={}
    for name,path in paths.items():
        raws[name]=source_record(observed['originals'][name],path,65536)
        need(phone.read(ROOT/Path(path).relative_to(BASE))==raws[name],
             'retained post-cancel task scope changed')
    template,binding,wrapper,resolved=[strict(raws[n]) for n in paths]
    api.post.validate_template(template)
    need(template['schema']=='hepta.task-template.v150.3' and
         sha(raws['template'])==plan['task_template_sha256'] and template['request_sha256']==owner and
         template['nonce']==plan['nonce'] and template['expected_scope']=={k:actual[k] for k in KEYS[:2]} and
         equal(template['app_scope'],plan['app_scope']),'request-bound v150.3 template differs')
    config=strict(api.pure['configuration'])
    api.post.validate_app_scope(template['app_scope'],owner,config['approved_apps'])
    identity={k:actual[k] for k in KEYS[:-1]}
    expected={'schema':'hepta.task-template-binding.v150.3','identity':identity,'request_sha256':owner,
        'template_sha256':sha(raws['template']),'nonce':plan['nonce'],'state':'consumed_no_reuse',
        'app_scope':template['app_scope'],'app_scope_sha256':api.post.app_scope_hash(template['app_scope'])}
    need(equal(binding,expected),'one-use task app-scope binding differs')
    contract={'schema':'hepta.task-contract.v150.3','identity':identity,'request_sha256':owner,
        'postconditions':template['postconditions'],'coverage':template['coverage'],'app_scope':template['app_scope']}
    expected={'contract':contract,'source_sha256':sha(encoded(contract)[:-1]),
        'binding_kind':'one_time_request_template','template_sha256':sha(raws['template']),
        'binding_sha256':sha(raws['binding'])}
    need(equal(wrapper,expected),'original task contract wrapper differs')
    selected,wanted=api.post.resolve_task_apps(wrapper,owner,config['approved_apps'])
    need(equal(resolved,wanted) and equal(observed['resolved'],wanted) and
         observed['app_scope_sha256']==api.post.app_scope_hash(template['app_scope']) and
         plan['probe_component'] in {api.page.component(r['component']) for r in selected.values()},
         'resolved task app scope differs')
    health=source_record(observation['health_contract_original'],BASE+'/provider-state/evidence/'+run+'/health-contract.json',65536)
    need(strict(health)=={'status':'no_health_contract'},'CPU cancellation cannot borrow HEALTH scope')

def provider_originals(observation,plan):
    scope=observation['scope'];run=observation['run']
    need(re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',run),'original run name malformed')
    incoming_raw=embedded(observation['provider_input_original'],4*1024*1024)
    outgoing_raw=embedded(observation['provider_output_original'],4*1024*1024)
    def lines(raw):
        need(not raw or raw.endswith(b'\n'),'incomplete original provider line')
        rows=[strict(line) for line in raw.splitlines()]
        need(all(r.get('protocol')==PROTOCOL and type(r.get('seq')) is int and r['seq']==i
             for i,r in enumerate(rows)),'original provider protocol/sequence differs')
        return rows
    incoming,outgoing=lines(incoming_raw),lines(outgoing_raw)
    owner=base64.b64decode(plan['request_b64'],validate=True)
    need(incoming and incoming[0]['kind']=='turn.start' and
         {k:incoming[0]['turn'][k] for k in KEYS}==scope and
         incoming[0]['turn']['user_input'].encode()==owner,'original provider owner/five-scope differs')
    claim_key=sha(json.dumps([scope[k] for k in KEYS[:-1]],separators=(',',':')).encode())
    claim_raw=source_record(observation['claim_original'],BASE+'/provider-state/evidence/claims/'+claim_key,1048576)
    claim=strict(claim_raw)
    need(claim['identity']==scope and claim['request_sha256']==sha(owner) and
         claim['state']=='accepted_no_redispatch' and claim['run_dir']==BASE+'/provider-state/evidence/'+run and
         observation['claim_consumed'] is True,'original one-use claim differs')
    wires=[r['call'] for r in outgoing if r['kind']=='tool.call']
    calls=observation['calls']
    need(len(calls)==len(wires)<=7 and len({r['call_id'] for r in wires})==len(wires),
         'original dispatch count/identity differs')
    originals={}
    for row in observation['action_originals']:
        need(row['source'] not in originals,'duplicate original action source')
        originals[row['source']]=embedded(row,1048576)
    for wire,call in zip(wires,calls):
        argv=wire['argv'];cid=wire['call_id']
        need(wire['tool']=='shell.exec' and len(argv)==9 and
             argv[:3]==['/usr/bin/python3',BASE+'/tool_client_r6.py','execute'] and
             argv[3]=='--action-id' and argv[5]=='--command-b64' and argv[7]=='--timeout-ms',
             'dispatch is not the original frozen client')
        command=base64.b64decode(argv[6],validate=True);action=argv[4]
        path=BASE+'/provider-state/evidence/'+run+'/semantic-'+sha(cid.encode())+'.json'
        semantic=strict(originals[path])
        need(semantic['turn']==scope and semantic['call_id']==cid and semantic['capture_id']==action and
             semantic['wire_call']==wire and call['call_id']==cid and call['action_id']==action and
             call['command_sha256']==sha(command) and call['semantic_tool']==semantic['semantic_tool'],
             'original semantic/wire/dispatch link differs')
        component=api_component(semantic.get('component'))
        need(call['component']==component,'original component normalization differs')
        if call['semantic_tool']=='phone.open_app':
            need(call['verified_app_open'] is True and component==plan['probe_component'],
                 'original Actor never observed the required open receipt')
            intent=strict(originals[BASE+'/provider-state/evidence/action-ledger/'+action+'.intent.json'])
            receipt=strict(originals[BASE+'/executor-r6/actions/'+action+'/receipt.json'])
            need(intent['action_id']==action and intent['command_sha256']==sha(command) and
                 intent['semantic_identity']=={k:scope[k] for k in KEYS[:-1]} and intent['automatic_replay'] is False and
                 receipt['action_id']==action and receipt['command_sha256']==sha(command) and
                 receipt['state']=='completed' and receipt['can_redispatch'] is False,
                 'original open intent/terminal link differs')
    return incoming,outgoing,incoming_raw,outgoing_raw

def api_component(value):
    if value is None:return None
    need(isinstance(value,str) and value.count('/')==1,'semantic component malformed')
    package,activity=value.split('/')
    if activity.startswith('.'):activity=package+activity
    return package+'/'+activity

def model_originals(observation,plan,ready,api,phone):
    m=observation['model'];run=observation['run']
    need(isinstance(m,dict) and number(m.get('round'),1,8) and
         isinstance(m.get('request_id'),str) and re.fullmatch('[0-9a-f]{32}',m['request_id']),
         'original model round/request id missing')
    server,bound_raw,binding_raw=runtime_observation(observation,plan,ready)
    need(m['server_identity']==server and m['ready_sha256']==sha(bound_raw) and
         m['binding_sha256']==sha(binding_raw),'original model READY generation differs')
    prefix=BASE+'/provider-state/evidence/'+run+'/local-%02d'%m['round']
    request_identity_raw=source_record(m['request_identity_original'],prefix+'.request-identity.json')
    images_raw=source_record(m['images_original'],prefix+'.images.json')
    identity,images=strict(request_identity_raw),strict(images_raw)
    body=phone.read(ROOT/Path(prefix+'.request.json').relative_to(BASE),2*1024*1024)
    need(identity['schema']=='hepta.original-wire-request.v1' and identity['automatic_retry'] is False and
         identity['request_id']==m['request_id']==images['request_id'] and
         identity['request_sha256']==m['request_sha256']==m['body_original_sha256']==sha(body) and
         type(identity['request_bytes']) is int and identity['request_bytes']==m['request_bytes']==len(body),
         'actual model identity/body/round differs')
    for suffix,raw in (('.request-identity.json',request_identity_raw),('.images.json',images_raw)):
        need(phone.read(ROOT/Path(prefix+suffix).relative_to(BASE))==raw,'retained model original differs')
    body_value=strict(body);grammar=body_value.get('response_format',{})
    config=strict(api.pure['configuration'])
    need(grammar.get('type')=='json_schema' and grammar.get('json_schema',{}).get('name')=='hepta_mobile_use_action'
         and grammar['json_schema'].get('strict') is True,'model request is not original business grammar')
    need(body_value.get('model')==config['model'] and type(body_value.get('max_tokens')) is int and
         body_value['max_tokens']==config['max_tokens']==256 and body_value.get('stream') is False,
         'model identity/stream/token budget changed')
    parts=[item for message in body_value['messages'] if isinstance(message.get('content'),list)
           for item in message['content'] if item.get('type')=='image_url']
    need(images['old_images_attached'] is False and len(parts)==len(images['images'])==m['image_count'] and
         len(parts)<=1,'original image attachment count/history differs')
    for part,image in zip(parts,images['images']):
        url=part['image_url']['url']
        need(url.startswith('data:image/jpeg;base64,'),'original image MIME differs')
        raw=base64.b64decode(url.split(',',1)[1],validate=True)
        need(len(raw)==image['bytes'] and sha(raw)==image['sha256'] and image['attached_round']==m['round'],
             'original attached image bytes/round differ')
    need(isinstance(m['original_http'],list) and len(m['original_http'])==2,'original GET pair absent')
    receipt=api.closure.original_http(m['original_http'][0],'/hepta/requests/'+m['request_id'])
    slots=api.closure.original_http(m['original_http'][1],'/slots')
    assessment=api.cleanup.assess_original(m['request_id'],server,receipt,slots,sha(body),len(body))
    decoded=api.cleanup.validate_original_records(m['request_id'],server,receipt,sha(body),len(body))
    point=decoded.get('cancel-processed.json',{}).get('details',{}).get('safe_point')
    active=(slots[0]['is_processing'] is True and receipt['state'] not in ('completed','cancelled','failed') and
            receipt.get('terminal_durable') is False and receipt.get('slot_release_observed') is False)
    need(equal(m['assessment'],assessment) and equal(m['original_cancel_safe_point'],point) and
         m['original_active'] is active and m['task_id']==receipt['task_id'] and m['slot_id']==receipt['slot_id'],
         'model observation summary differs from raw server originals')
    return {'model':m,'body':body,'receipt':receipt,'slots':slots,'assessment':assessment,
            'decoded':decoded,'server':server,'bound_raw':bound_raw,'binding_raw':binding_raw}

def safe_point_verdict(case_id,model,receipt,assessment,decoded):
    """Only actual original event fields can qualify CPU interruption."""
    event=decoded.get('cancel-processed.json')
    point=event.get('details',{}).get('safe_point') if isinstance(event,dict) else None
    expected='cpu_decode' if case_id=='NEG-08' else 'cpu_image_encode'
    reasons=[]
    def check(ok,name):
        if not ok:reasons.append(name)
    check(assessment.get('admitted') is True,'original_release_and_idle_unverified')
    check(assessment.get('original_model_terminal')=='cancelled' and receipt.get('state')=='cancelled',
          'original_model_terminal_not_cancelled')
    check(assessment.get('server_cancel_acknowledged') is True,'server_cancel_not_acknowledged')
    check(model.get('image_count')==(0 if case_id=='NEG-08' else 1),'original_image_count_differs')
    if not isinstance(event,dict) or not isinstance(point,dict):
        reasons.append('original_cancel_safe_point_absent')
    else:
        details=event.get('details',{})
        check(event.get('event')=='actual_cancel_task_processed','original_cancel_event_differs')
        check(details.get('matched_slot') is True and details.get('prior_terminal_preserved') is False and
              details.get('server_cancel_applied') is True and details.get('cancelled_before_start') is False,
              'cancel_was_not_applied_to_original_running_slot')
        check(event.get('task_id')==model.get('task_id') and event.get('slot_id')==model.get('slot_id') and
              event.get('request_id')==model.get('request_id') and
              event.get('request_sha256')==model.get('request_sha256') and
              event.get('server_identity')==model.get('server_identity'),'safe_point_original_owner_link_differs')
        check(point.get('phase')==expected,'actual_cpu_phase_missed')
        check(number(point.get('original_cancel_queue_id'),0,2**31-1),'original_cancel_queue_id_unverified')
        for key in ('abort_callback_observed','compute_synchronized','queue_handoff_completed','partial_result_not_dispatched'):
            check(point.get(key) is True,key+'_not_true')
        check(type(point.get('model_retry_count')) is int and point['model_retry_count']==0,'model_retry_count_not_zero')
        code=point.get('compute_return_code')
        check(type(code) is int,'actual_compute_return_code_absent')
        check(point.get('persistent_queue_thread_exit_claim') is False,'persistent_queue_thread_exit_not_permitted')
        check(point.get('http_delivery_observed') is False,'partial_HTTP_delivery_not_permitted')
        check(number(point.get('discarded_partial_text_bytes')) and number(point.get('discarded_partial_token_count')),
              'discarded_partial_counters_absent')
        check(point.get('image_encode_abort_supported') is True,'reviewed_CPU_vision_callback_not_enabled')
        if expected=='cpu_decode':
            check(type(point.get('decode_return_code')) is int and point['decode_return_code']==code and
                  code in (0,2) and point.get('image_encode_return_code') is None,'CPU_decode_return_inconsistent')
        else:
            check(type(point.get('image_encode_return_code')) is int and point['image_encode_return_code']==code and
                  point.get('decode_return_code') is None,'CPU_image_return_inconsistent')
    return {'qualified':not reasons,'expected_phase':expected,
            'observed_phase':point.get('phase') if isinstance(point,dict) else None,
            'original_cancel_queue_id':point.get('original_cancel_queue_id') if isinstance(point,dict) else None,
            'reasons':reasons}


def tap_command(api,plan,node,page,selected_raw):
    # Project only the original command-building prefix, before the first
    # self.save/intent operation. Never execute Actor, shell, save, or time calls.
    tree=ast.parse(api.loaded['source/cancel_native_once_r10.py'])
    actor=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Actor')
    fn=next(n for n in actor.body if isinstance(n,ast.FunctionDef) and n.name=='guarded_tap')
    body=[]
    for n in fn.body:
        if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='save':
            break
        body.append(n)
    need(len(body)==10 and isinstance(body[0],ast.Expr),'reviewed command prefix shape differs')
    out=dict(base64=base64,shlex=shlex,need=need,HEPTA=api.phase.HEPTA,
             SELECTED_READ=SELECTED_READ,PAGE_STATE_COMMAND=api.page.PAGE_STATE_COMMAND,
             self=types.SimpleNamespace(plan=plan),node=node,page=page,selected_raw=selected_raw)
    exec(compile(ast.Module(body=body,type_ignores=[]),'<reviewed-tap-command-prefix>','exec'),out)
    return out['command']

def page_command(api):
    tree=ast.parse(api.loaded['source/cancel_native_once_r10.py'])
    actor=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Actor')
    fn=next(n for n in actor.body if isinstance(n,ast.FunctionDef) and n.name=='page')
    need(isinstance(fn.body[0],ast.Assign),'original page command AST differs')
    out={'PAGE_STATE_COMMAND':api.page.PAGE_STATE_COMMAND}
    exec(compile(ast.Module(body=[fn.body[0]],type_ignores=[]),'<reviewed-page-command>','exec'),out)
    return out['command']

def actor_originals(value,originals,api):
    rows=value['actor_originals']
    need(isinstance(rows,dict) and 15<=len(rows)<=1024,'complete bounded Actor original set required')
    plan_row=rows.get('PLAN.original.json')
    need(isinstance(plan_row,dict),'actual Actor plan absent')
    plan=strict(originals.read(plan_row['retained'],65536));owner=api.phase.validate_plan(plan)
    need(plan['case_id']==value['case_id'],'CPU case and original plan differ')
    need((plan['case_id']=='NEG-08' and plan['require_image_cancel'] is False) or
         (plan['case_id']=='NEG-09' and plan['require_image_cancel'] is True),
         'Root selected NEG08 text / NEG09 required-image contract')
    out=P4+'/cancel-native-r10/'+plan['label']
    directory_original(value['actor_directory'],out,rows)
    raw={name:retained(row,out+'/'+name,originals) for name,row in rows.items()}
    need(raw['PLAN.original.json']==originals.read(plan_row['retained'],65536),'original plan changed')
    begin,armed,window,intent,result=[strict(raw[n]) for n in
        ('BEGIN.json','PHASE-ARMED.json','CANCEL-PHASE-WINDOW.json','CANCEL-ONCE.intent.json','RESULT.json')]
    need(begin['schema']=='hepta.r10.native-cancel-operator-begin.v1' and
         begin['plan_sha256']==sha(raw['PLAN.original.json']) and begin['case_id']==plan['case_id'] and
         begin['task_submissions']==begin['provider_connections']==0 and begin['automatic_retry'] is False,
         'actual original Actor BEGIN differs')
    need(result['schema']=='hepta.r10.native-cancel-once-result.v1' and result['case_id']==plan['case_id'] and
         result['scope']==window['final']['scope'] and result['owner_request_sha256']==plan['owner_request_sha256'],
         'Actor result identity differs')
    before,final,last=window['before'],window['final'],result['last_original_observation']
    need(isinstance(last,dict),'actual final post-cancel original absent')
    actual=final['scope']
    need(equal(armed['original_observation'],before) and
         window['physical_case_pass'] is False and window['model_return_postcondition'] is False and
         window['operator_navigation_separate'] is (plan['case_id']=='NEG-09'),
         'original phase window/provenance differs')
    need(api.phase.phase_ready(plan,before) is True and api.phase.phase_ready(plan,final,before) is True,
         'original active pre-Cancel phase not qualified')
    need(equal(result['scope'],actual) and intent['schema']=='hepta.r10.native-cancel-ui-intent.v1' and
         intent['plan_sha256']==sha(raw['PLAN.original.json']) and intent['scope']==actual and
         intent['native_request_sha256']==final['native_request_sha256'] and
         intent['cancel_attempt'] is True and intent['automatic_retry'] is False and
         intent['transport']=='original_HEPTA_UI' and intent['provider_frame_injection'] is False,
         'single original Cancel intent differs')
    once=retained(value['once_reservation'],P4+'/native-cancel-intents-r10/'+plan['owner_request_sha256']+'.json',originals,65536)
    reservation=strict(once)
    need(reservation['plan_sha256']==sha(raw['PLAN.original.json']) and reservation['scope']==actual and
         reservation['out']==out and reservation['one_operator_sequence_reserved'] is True and
         reservation['automatic_retry'] is False,'actual owner-once reservation differs')
    wire_rows={}
    for name,body in raw.items():
        match=re.fullmatch(r'([0-9]{3})-(.+)\.original\.json',name)
        if match:
            counter=int(match[1]);need(counter not in wire_rows,'duplicate operator counter')
            wire_rows[counter]=(match[2],strict(body))
    need(sorted(wire_rows)==list(range(1,len(wire_rows)+1)),'original operator sequence/census incomplete')
    observations={};by_tag={};previous_end=begin['p4_monotonic_ns']
    for counter,(tag,row) in sorted(wire_rows.items()):
        need(row['automatic_retry'] is False and number(row['p4_monotonic_started_ns']) and
             number(row['p4_monotonic_finished_ns']) and previous_end<=row['p4_monotonic_started_ns']<=row['p4_monotonic_finished_ns'],
             'original serial operator windows differ')
        previous_end=row['p4_monotonic_finished_ns']
        need(tag not in by_tag,'operator phase repeated')
        by_tag[tag]=(counter,row)
        observer=(re.fullmatch(r'WAIT-[0-9]{3}|AFTER-CANCEL-[0-9]{3}',tag) is not None or tag=='FINAL-PRE-CANCEL')
        if observer:
            boot,payload=parse_observer_command(row['command'])
            expanded=strict(payload)
            need(set(expanded)=={'plan','scope_hint','source'} and equal(expanded['plan'],plan) and
                 (expanded['scope_hint'] is None or expanded['scope_hint']==actual),'original observer payload target differs')
            expected=api.build.build_observer_request(plan,expanded['scope_hint'],api.loaded)
            wanted_boot,wanted_payload=parse_observer_command(expected['command'])
            need(boot==wanted_boot and payload==wanted_payload,'observer actual pinned source/bootstrap/payload differs')
            name='%03d-%s.observation.json'%(counter,tag)
            if row['error'] is None:
                value=strict(wire_value(row)['stdout'])
                need(name in raw and strict(raw[name])==value,'original observation copy differs from actual wire')
                observations[tag]=(counter,row,value)
            else:
                need(tag!='FINAL-PRE-CANCEL' and name not in raw,'failed read cannot supply a phase observation')
        else:
            wire_value(row)
            if tag in ('PHASE-SELECTED','TASK-CONTROL-SELECTED','FINAL-PRE-CANCEL-SELECTED'):
                need(row['command']=='/debug_ramdisk/su -c '+shlex.quote(SELECTED_READ),'original selected read command differs')
            elif tag in ('PHASE-PUBLIC-FOREGROUND','OPERATOR-HEPTA-FOREGROUND','TASK-CONTROL-FOREGROUND','FINAL-PRE-CANCEL-FOREGROUND'):
                need(row['command']==page_command(api),'original public page read command differs')
            elif tag in ('TASK-CONTROL-UI','CANCEL-UI'):
                xmlpath='/data/local/tmp/hepta-native-cancel-r10-'+plan['nonce']+'-'+str(counter)+'.xml'
                need(row['command']=='test ! -e '+xmlpath+' && test ! -L '+xmlpath+' && uiautomator dump '+xmlpath+' && cat '+xmlpath,
                     'original bounded UI dump command differs')
            elif tag=='OPERATOR-HEPTA-NAVIGATION':
                need(plan['case_id']=='NEG-09' and row['command']=='am start -W -n org.trillionnium.owneropen/.OwnerOpenShellActivity',
                     'unexpected operator navigation')
            else:
                need(tag in ('OPEN-CURRENT-TASK','CANCEL-ONCE'),'unreviewed operator command in actual trace')
    for name in raw:
        if re.fullmatch(r'[0-9]{3}-.+\.observation\.json',name):
            prefix=name[:-len('.observation.json')]
            need(prefix+'.original.json' in raw,'unpaired original observation')
    need('FINAL-PRE-CANCEL' in observations and equal(observations['FINAL-PRE-CANCEL'][2],final),
         'actual final phase observation missing')
    waits=[x for tag,x in observations.items() if tag.startswith('WAIT-') and equal(x[2],before)]
    posts=[x for tag,x in observations.items() if tag.startswith('AFTER-CANCEL-')]
    need(len(waits)==1 and posts and equal(max(posts,key=lambda x:x[0])[2],last),
         'armed/last observation is not an actual original call')
    def selected(tag):
        wire=wire_value(by_tag[tag][1])
        body=base64.b64decode(''.join(wire['stdout'].split()),validate=True)
        identity=api.decoder.decode_client_state(body);api.phase.selected_matches(identity,final)
        return identity,body
    def page(tag):
        value=strict(wire_value(by_tag[tag][1])['stdout'])
        text=base64.b64decode(value['page_b64'],validate=True).decode()
        viewport=base64.b64decode(value['viewport_b64'],validate=True).decode()
        actual_page=api.page.page_state(text);api.page.validate_viewport(viewport)
        return {'raw':text,'viewport':viewport,'page':actual_page}
    initial_selected,_=selected('PHASE-SELECTED');initial_page=page('PHASE-PUBLIC-FOREGROUND')
    need(equal(armed['selected_identity'],initial_selected) and equal(armed['independent_page'],initial_page) and
         initial_page['page']['component']==(api.phase.HEPTA if plan['case_id']=='NEG-08' else plan['probe_component']),
         'original independent selected/foreground precondition differs')
    for tag,sel,pg,xml,resource in (
       ('OPEN-CURRENT-TASK','TASK-CONTROL-SELECTED','TASK-CONTROL-FOREGROUND','TASK-CONTROL-UI','ui_task_summary'),
       ('CANCEL-ONCE','FINAL-PRE-CANCEL-SELECTED','FINAL-PRE-CANCEL-FOREGROUND','CANCEL-UI','ui_cancel')):
        _,selected_raw=selected(sel);public=page(pg)
        node=api.phase.unique_ui_node(wire_value(by_tag[xml][1])['stdout'],'org.trillionnium.owneropen:id/'+resource)
        call=by_tag[tag][1];mark=strict(raw[tag+'.intent.json'])
        command=tap_command(api,plan,node,public,selected_raw)
        need(call['command']==command and mark['command_sha256']==sha(command.encode()) and
             mark['selected_record_sha256']==sha(selected_raw) and mark['ui_node']==node and
             mark['scope']==actual and mark['plan_sha256']==sha(raw['PLAN.original.json']) and
             mark['cancel_attempt'] is (tag=='CANCEL-ONCE') and mark['automatic_retry'] is False and
             mark['provider_frame_injection'] is False and
             by_tag[pg][1]['p4_monotonic_finished_ns']<=mark['p4_monotonic_ns']<=call['p4_monotonic_started_ns'],
             'actual UI CAS/once command differs')
    cancel_index,cancel_row=by_tag['CANCEL-ONCE']
    need(by_tag['FINAL-PRE-CANCEL'][0]<by_tag['FINAL-PRE-CANCEL-SELECTED'][0]<
         by_tag['FINAL-PRE-CANCEL-FOREGROUND'][0]<cancel_index and
         all(x[0]>cancel_index for x in posts) and
         window['p4_monotonic_ns']<=intent['p4_monotonic_ns'],
         'original phase/Cancel/post-read ordering differs')
    need(('OPERATOR-HEPTA-NAVIGATION' in by_tag)==(plan['case_id']=='NEG-09'),
         'operator navigation contract differs')
    sender=strict(raw['SENDER-ORIGINALS.json'])
    need(set(sender)=={'SEND.once.json','SEND.MONOTONIC-INTENT.json','SEND.MONOTONIC-WINDOW.json','FINAL-PRE-SEND-UI.json'},
         'original one-Send subset missing')
    src='/home/alex/codex-hepta-natural-'+plan['sender_label']+'-root-v150/'
    send={name:strict(source_record(dict(row,source=row['path']),src+name,262144)) for name,row in sender.items()}
    need(send['SEND.once.json']['prompt'].encode()==owner and
         send['SEND.once.json']['prompt_sha256']==sha(owner) and send['SEND.once.json']['automatic_replay'] is False and
         type(send['SEND.MONOTONIC-INTENT.json']['send_attempt_count']) is int and
         send['SEND.MONOTONIC-INTENT.json']['send_attempt_count']==1,'original one Send owner differs')
    period=send['SEND.MONOTONIC-WINDOW.json']
    need(send['SEND.MONOTONIC-INTENT.json']['p4_pre_send_monotonic_ns']<=period['send_started_monotonic_ns']<=
         period['send_returned_monotonic_ns']<=armed['p4_monotonic_ns'] and period['send_status'] in ('tap_returned','unknown'),
         'original sender/armed monotonic order differs')
    api.phase.unique_ui_node(send['FINAL-PRE-SEND-UI.json']['stdout'],'org.trillionnium.owneropen:id/ui_send')
    return plan,ready_from_plan(plan,api),before,final,last,result,raw,by_tag

def ready_from_plan(plan,api):
    return api.active.validate_runtime_binding(plan['runtime_binding'],plan['expected_boot'])

def verify_cpu_cancel(inputs_raw,*,read_pinned):
    """Validate one existing actual case. Missing originals raise Unverified."""
    need(type(inputs_raw) is bytes and 0<len(inputs_raw)<=2*1024*1024,'explicit bounded original-input JSON required')
    value=strict(inputs_raw)
    need(isinstance(value,dict) and set(value)=={'schema','case_id','operator_package','operator_sources',
         'actor_directory','actor_originals','once_reservation','phone_directories','phone_originals','reviewed_sources'}
         and value['schema']==SCHEMA and value['case_id'] in ('NEG-08','NEG-09'),'CPU original-input interface differs')
    originals=Originals(read_pinned);api=load_apis(value,originals)
    plan,ready,before,final,last,result,actor_raw,by_tag=actor_originals(value,originals,api)
    need(before['scope']==final['scope']==last['scope'] and before['run']==final['run']==last['run'] and
         before['native_request_sha256']==final['native_request_sha256']==last['native_request_sha256'] and
         before['calls']==final['calls']==last['calls'],'original scope/run/request/dispatch advanced')
    run=last['run'];phone=PhoneOriginals(value['phone_originals'],originals,run,plan['expected_boot'])
    model_results=[]
    for observation in (before,final,last):
        need(observation['schema']=='hepta.r10.cancel-phase-observation.v1' and
             observation['state']=='BOUND_ORIGINAL_PHASE_OBSERVED' and observation['boot_id']==plan['expected_boot'] and
             observation['owner_request_sha256']==plan['owner_request_sha256'],'actual original observation identity differs')
        for k in ('model_requests','task_submissions','tool_calls','ui_actions','signals','original_file_writes'):
            need(type(observation[k]) is int and observation[k]==0,'read-only observer action count differs')
        scope_native(observation,plan,api,observation is last)
        provider_originals(observation,plan)
        task_scope(observation,plan,api,phone)
        model_results.append(model_originals(observation,plan,ready,api,phone))
    first,pre,post=model_results
    ownership=('request_id','request_sha256','request_bytes','round','image_count','server_identity','task_id','slot_id')
    need(all(equal(first['model'][k],pre['model'][k]) and equal(pre['model'][k],post['model'][k]) for k in ownership)
         and first['body']==pre['body']==post['body'],'original model owner/round/generation changed')
    for key in ('bound_raw','binding_raw'):
        need(first[key]==pre[key]==post[key],'model startup binding changed during Cancel')
    model=post['model'];rid=model['request_id'];number_=model['round']
    run_root=ROOT/'provider-state/evidence'/run
    directories=value['phone_directories']
    need(isinstance(directories,dict) and set(directories)=={'run','producer','ledger_prefix'},
         'actual run/producer/ledger-prefix directory bookends required')
    for key,relative,source in (
        ('run','provider-state/evidence/'+run,BASE+'/provider-state/evidence/'+run),
        ('producer','runtime/receipts/'+rid,BASE+'/model-runtime-r10-r1/'+plan['expected_boot']+'/receipts/'+rid),
        ('ledger_prefix','provider-state/evidence/'+run+'/ledger-prefix',
         BASE+'/provider-state/evidence/'+run+'/ledger-prefix')):
        descendants=[Path(p).relative_to(relative).parts for p in phone.rows
                     if Path(p).is_relative_to(relative)]
        need(descendants and all(parts for parts in descendants),
             'original directory has no complete file census')
        if key=='run':
            need(all(len(parts)==1 or len(parts)==2 and parts[0]=='ledger-prefix'
                     for parts in descendants)
                 and ('ledger-prefix','baseline.json') in descendants,
                 'run descendants exceed the exact ledger-prefix source contract')
            names=sorted({parts[0] for parts in descendants})
        else:
            need(all(len(parts)==1 for parts in descendants)
                 and (key!='ledger_prefix' or ('baseline.json',) in descendants),
                 'producer/ledger-prefix originals are not a complete flat census')
            names=[parts[0] for parts in descendants]
        directory_original(directories[key],source,names)
    # Consume every indexed original, including any result/decision file, and
    # require the run census to contain no later model request reservation.
    for rel in sorted(phone.rows):phone.read(ROOT/rel)
    identity_names=[p.name for p in map(Path,phone.rows) if p.parent==Path('provider-state/evidence/'+run)
                    and re.fullmatch(r'local-[0-9]{2}\.request-identity\.json',p.name)]
    need(sorted(identity_names)==['local-%02d.request-identity.json'%n for n in range(1,number_+1)],
         'later/unindexed/nonconsecutive model request detected')
    incoming,outgoing,inraw,outraw=provider_originals(last,plan)
    need(phone.read(run_root/'provider-in.jsonl')==inraw and phone.read(run_root/'provider-out.jsonl')==outraw,
         'late provider prefix changed after original cancel observation')
    endings=[f for f in outgoing if f['kind'] in ('turn.complete','turn.fail','turn.cancelled')]
    terminal=phone.json(run_root/'terminal.json')
    need(len(endings)==1 and outgoing[-1]==endings[0] and endings[0]['kind']==terminal['kind']=='turn.cancelled',
         'actual provider cancellation terminal missing/conflicting')
    dispatched=[r for r in outgoing if r['kind']=='tool.call']
    dispatch_names=sorted(p for p in phone.rows if Path(p).parent==Path('provider-state/evidence/'+run)
                          and re.fullmatch(r'dispatch-.*\.json',Path(p).name))
    need([phone.json(ROOT/p)['call'] for p in dispatch_names]==[r['call'] for r in dispatched],
         'late durable dispatch originals differ')
    frames=scope_native(last,plan,api,True)
    accepted=[f for f in frames if f['kind']=='turn.cancel.accepted']
    cancelled=frames[-1]['kind']=='turn.end' and frames[-1]['payload'].get('status')=='cancelled'
    need(len(accepted)==1 and accepted[0]['payload'].get('status')=='requested' and
         accepted[0]['payload'].get('automatic_redispatch') is False and cancelled,
         'native original cancellation not uniquely accepted/terminal')
    need(post['assessment'].get('admitted') is True,'actual original model release/idle unresolved')
    cleanup=api.closure.verify_cleanup(phone,{'ready':ready,'runtime':{'server_identity':post['server']}},
        ROOT,run_root,number_,api.cleanup,post['body'],rid)
    need(cleanup['server_original_terminal']==post['assessment']['original_model_terminal'],
         'provider passive cleanup and Actor GET terminal differ')
    producer_names={Path(p).name for p in phone.rows if Path(p).parent==Path('runtime/receipts/'+rid)}
    need(producer_names=={p['name'] for p in post['receipt']['records']},
         'actual producer file census differs from final GET originals')
    for row in post['receipt']['records']:
        raw=phone.pinned(ROOT/'runtime/receipts'/rid/row['name'],row['sha256'],2*1024*1024)
        need(len(raw)==row['bytes'],'producer original byte count differs')
        if row['name'].endswith('.json'):
            original=next(x for x in post['receipt']['original_records'] if x['name']==row['name'])
            need(raw==original['raw_utf8'].encode(),'on-disk producer original differs from actual GET')
    need(phone.read(ROOT/'runtime/receipts'/rid/'accepted-body.bin')==post['body'],'original accepted body differs')
    original_model=before['model'];last_model=last['model']
    drained=(last_model['request_id']==original_model['request_id'] and
             last_model['request_sha256']==original_model['request_sha256'] and
             last_model['server_identity']==original_model['server_identity'] and
             last_model['assessment'].get('admitted') is True)
    point=last_model.get('original_cancel_safe_point') or {}
    actor_image=(drained and last_model['image_count']==1 and
        last_model['assessment'].get('server_cancel_acknowledged') is True and
        point.get('phase')=='cpu_image_encode' and point.get('abort_callback_observed') is True and
        point.get('compute_synchronized') is True and point.get('queue_handoff_completed') is True and
        point.get('model_retry_count')==0 and point.get('partial_result_not_dispatched') is True)
    ordinary=bool(accepted and cancelled and drained and last['calls']==before['calls'])
    expected={'state':'ORIGINAL_CANCEL_AND_DRAIN_OBSERVED' if ordinary else 'UNKNOWN_OR_PHASE_MISSED_RETAIN_ORIGINALS',
        'cancel_tap_attempts':1,'cancel_acceptance_observed':bool(accepted),'native_cancelled_observed':cancelled,
        'original_model_terminal_release_idle_observed':drained,'dispatch_prefix_unchanged':last['calls']==before['calls'],
        'operator_navigation_separate':plan['case_id']=='NEG-09','model_return_postcondition':False,
        'actual_image_request':original_model['image_count']==1,'image_encoder_interruption_phase_proven':actor_image,
        'automatic_retry':False,'task_submissions':0,'model_requests':0,'provider_frame_injections':0,
        'physical_case_pass':False,'independent_original_capture_and_late_closure_required':True}
    need(all(equal(result.get(k),v) for k,v in expected.items()),'Actor summary differs from actual originals')
    cpu=safe_point_verdict(plan['case_id'],model,post['receipt'],post['assessment'],post['decoded'])
    originals.recheck()
    return {'schema':RESULT_SCHEMA,'state':'ORIGINAL_CPU_CANCEL_SAFE_POINT_VERIFIED' if ordinary and cpu['qualified']
            else 'ORIGINAL_CANCEL_VERIFIED_CPU_PHASE_UNQUALIFIED',
        'case_id':plan['case_id'],'scope':last['scope'],'owner_request_sha256':plan['owner_request_sha256'],
        'native_request_sha256':last['native_request_sha256'],'run':run,
        'release_pins':plan['runtime_binding']['release_pins'],'server_identity':post['server'],
        'request_id':rid,'request_sha256':sha(post['body']),'request_bytes':len(post['body']),
        'round':number_,'task_id':model['task_id'],'slot_id':model['slot_id'],'image_count':model['image_count'],
        'ordinary_cancel_verified':ordinary,'cpu_cancellation_qualified':ordinary and cpu['qualified'],
        'cpu_safe_point':cpu,'model_terminal':post['assessment']['original_model_terminal'],
        'server_cancel_acknowledged':post['assessment']['server_cancel_acknowledged'],
        'original_server_release_and_idle_verified':True,'original_http_worker_and_observer_join_verified':True,
        'actual_operator_cancel_count':1,'model_retry_count':point.get('model_retry_count'),
        'late_dispatch_prefix_unchanged':True,'physical_case_pass':False,
        'independent_native_late_closure_still_required':True,
        'qualification_scope':'CPU safe-point evidence for this single original model request; no full native case PASS.',
        'original_input_count':len(originals.seen),'original_input_bytes':originals.total,
        'input_originals':originals.descriptors(),'phone_calls':0,'new_model_requests':0,
        'new_ui_actions':0,'signals_sent':0,'new_nonces':0,'automatic_retry':False}
