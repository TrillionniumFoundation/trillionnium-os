#!/usr/bin/env python3
"""Pure assembly of actual NEG-08/09 originals. No filesystem or transport I/O.
The only external read is the caller's pinned-original callback. Future source
pins are source literals, not authority supplied by a case plan.
"""
import ast
import base64
import copy
import fnmatch
import gzip
import hashlib
import io
import json
from pathlib import PurePosixPath as Path
import re
import shlex
import stat
import types
import zlib

FINAL_DEPENDENCIES = None
SCHEMA = 'hepta.r10.cpu-negative-closure-plan.v1'
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
P4 = '/home/alex/razr60-local-model-v150'
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SCOPE = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
MAX_FILE = 16*1024*1024
MAX_ARCHIVE = 64*1024*1024
MAX_EXPANDED_TAR = 72*1024*1024  # Container headers + <=64MiB originals + <=4MiB CAPTURE.
MAX_INPUT = 192*1024*1024
EMPTY_SHA = hashlib.sha256(b'').hexdigest()
PARENT_PINS = {
 'root_transport': (45952,'53b5f9a3cd95a92b4aaa7382fcd890fc197c20a8a0106b7f49332e2ba3a67cc8'),
 'ledger_parent': (29100,'022b9321d19563d2405051f796dfebe517045333627babe34aeeb810754647f4'),
 'business': (56572,'b2774a4669a60d576fe3f19ea00fdec7119b5e5d36a6b591853bc686dbb5de3f'),
 'positive_closer': (41173,'19af371cb5271ea6b3f8c2929ab969357aee07d14d498dcf50f57e9b3bbc9e75'),
 'protocol': (37318,'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0'),
 'cleanup': (37375,'9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183'),
 'postconditions': (23211,'d4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3'),
 'configuration': (None,'780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'),
 'service': (10635,'2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a')}
# Configuration length is required to match its actual sealed descriptor.
# Its immutable SHA is the fixed authority here; no inferred length is supplied.
FIXED_SHA = {k:v[1] for k,v in PARENT_PINS.items()}
OPERATOR_NAMES = {'active_runtime_r10.py','cancel_native_once_r10.py','cancel_phase.py',
 'decode_client_state.py','native_journal_audit.py','observe_cancel_phase_r10.py',
 'production-pins.json','reviewed_page_projection.py'}
DEP_SOURCE_NAMES = {'cpu','phone','p4','sender','root_transport'}
DEP_HASH_NAMES = {'ui_package_sha256','active_sha256','runtime_package_sha256',
 'consumer_sha256','readiness_sha256','policy_adoption_sha256','configuration_sha256',
 'service_inputs_sha256','combination_sha256'}
SOURCE_NAMES = DEP_SOURCE_NAMES | {'ledger_parent','ledger_negative','business',
 'positive_closer','protocol','cleanup','postconditions','configuration','service','root_transport_parent'}

class Unverified(ValueError):
    pass

def need(value, code):
    if not value:
        raise Unverified(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(rows):
        value = {}
        for key,item in rows:
            need(key not in value, 'duplicate_json_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Unverified('nonfinite_json')))

def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),
                       allow_nan=False)+'\n').encode()

def pretty(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,
                       allow_nan=False)+'\n').encode()

def same(left,right):
    return encoded(left) == encoded(right)

def number(value, minimum=0, maximum=2**63-1):
    return type(value) is int and minimum <= value <= maximum

def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value), 'sha256_shape')
    return value

def canonical(path):
    need(type(path) is str and path.startswith('/') and '\0' not in path and
         str(Path(path)) == path and '..' not in Path(path).parts, 'canonical_absolute_path')
    return path

def relative(path):
    need(type(path) is str and not path.startswith('/') and
         re.fullmatch(r'[A-Za-z0-9._/-]{1,1024}',path) and
         all(p not in ('','.','..') for p in path.split('/')), 'archive_relative_path')
    return path

def exact3(row, maximum=MAX_FILE):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}, 'exact_descriptor')
    canonical(row['path'])
    need(number(row['bytes'],0,maximum), 'original_byte_bound')
    digest(row['sha256'])
    return row

def bytes_pin(row, maximum=MAX_FILE):
    need(type(row) is dict and set(row)=={'bytes','sha256'} and
         number(row['bytes'],0,maximum), 'byte_descriptor')
    digest(row['sha256'])
    return row

def metadata(row, directory=False):
    need(type(row) is dict and set(row)==set(META) and
         all(type(v) is int for v in row.values()), 'full9_dictionary')
    need((stat.S_ISDIR if directory else stat.S_ISREG)(row['st_mode']) and
         row['st_dev']>=0 and row['st_ino']>0 and row['st_uid']>=0 and row['st_gid']>=0,
         'original_metadata_type')
    if not directory:
        need(row['st_nlink']==1 and row['st_size']>=0, 'original_single_link')
    return row

def final_dependencies():
    value = FINAL_DEPENDENCIES
    need(type(value) is dict and set(value)=={'schema','sources','live_policy'} | DEP_HASH_NAMES,
         'future_dependencies_unfrozen')
    need(value['schema']=='hepta.r10.cpu-negative-final-dependencies.v1',
         'dependency_schema')
    need(type(value['sources']) is dict and set(value['sources'])==DEP_SOURCE_NAMES,
         'dependency_source_set')
    for row in value['sources'].values():
        bytes_pin(row, 131072)
        need(row['bytes']>0, 'dependency_source_empty')
    for name in DEP_HASH_NAMES:
        digest(value[name])
    bytes_pin(value['live_policy'])
    need(value['live_policy']['bytes']>0, 'dependency_policy_empty')
    need(value['configuration_sha256']==FIXED_SHA['configuration'] and
         value['service_inputs_sha256']==FIXED_SHA['service'], 'shared17_identity')
    return value

class Originals:
    def __init__(self, callback):
        self.callback=callback
        self.seen={}
        self.total=0
    def read(self,row,maximum=MAX_FILE):
        exact3(row,maximum)
        raw=self.callback(row)
        need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256'],
             'original_pin_or_readback')
        old=self.seen.get(row['path'])
        need(old is None or old==(dict(row),raw), 'original_changed_between_reads')
        if old is None:
            self.total+=len(raw)
            need(self.total<=MAX_INPUT, 'host_original_pool_bound')
            self.seen[row['path']]=(dict(row),raw)
        return raw
    def recheck(self):
        for row,raw in tuple(self.seen.values()):
            need(self.callback(row)==raw, 'original_changed_at_final_bookend')
    def index(self):
        return [row for row,_ in sorted(self.seen.values(),key=lambda x:x[0]['path'])]

def literal(raw,name):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign) and
           len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(nodes)==1, 'unique_source_literal')
    return ast.literal_eval(nodes[0].value)

def source_segment(raw,name,classname=None):
    tree=ast.parse(raw)
    nodes=tree.body
    if classname:
        rows=[n for n in nodes if isinstance(n,ast.ClassDef) and n.name==classname]
        need(len(rows)==1,'unique_reviewed_class')
        nodes=rows[0].body
    rows=[n for n in nodes if isinstance(n,ast.FunctionDef) and n.name==name]
    need(len(rows)==1,'unique_reviewed_function')
    return ast.get_source_segment(raw.decode(),rows[0])

def root_source(raw,parent):
    need((len(parent),sha(parent))==PARENT_PINS['root_transport'],'root_transport_parent_pin')
    for key in ('REMOTE_IO','SSH','ACTOR'):
        need(same(literal(raw,key),literal(parent,key)), 'original_root_transport_constant_changed')
    for name in ('execute_process','remote','remote_program','phone'):
        need(source_segment(raw,name,'Chain')==source_segment(parent,name,'Chain'),
             'original_root_transport_function_changed')
    return raw

def remote_code(root_raw, operation, *, phase, remote_root, argv=None, timeout=None,
                request=None, nonce=None):
    """Evaluate only reviewed source-string assembly before self.remote."""
    tree=ast.parse(root_raw)
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Chain')
    fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==operation)
    prefix=[]
    for node in fn.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and
                t.id in ('value','result') for t in node.targets):
            break
        prefix.append(copy.deepcopy(node))
    need(prefix and not any(isinstance(n,(ast.Import,ast.ImportFrom,ast.With,ast.Try))
                            for n in prefix),'reviewed_transport_prefix_shape')
    namespace={'REMOTE_IO':literal(root_raw,'REMOTE_IO'),'ACTOR':literal(root_raw,'ACTOR'),
        'need':need,'sha':sha,'shlex':shlex,'re':re,'Path':Path,
        'self':types.SimpleNamespace(remote_root=remote_root,p={'nonce':nonce}),
        'name':phase,'argv':argv,'timeout':timeout,'tag':phase.removeprefix('phone-'),'req':request}
    exec(compile(ast.Module(body=prefix,type_ignores=[]),'<pinned-transport-string-prefix>','exec'),namespace)
    return namespace['code'].encode()

def host_phase(originals, records, phase, argv, timeout, stdin):
    need(type(records) is dict and set(records)=={'intent','child','result','stdout','stderr','stdin'},
         'original_host_phase_fields')
    raws={k:originals.read(v,MAX_ARCHIVE if k=='stdout' else MAX_FILE)
          for k,v in records.items() if v is not None}
    need(set(raws)==({'intent','child','result','stdout','stderr'} | ({'stdin'} if stdin is not None else set())),
         'original_host_phase_complete')
    intent,child,result=[strict(raws[k]) for k in ('intent','child','result')]
    wanted={'schema':'hepta.native-guard.root-host-command.v1','phase':phase,
        'argv':argv,'stdin_sha256':None if stdin is None else sha(stdin),
        'maximum_starts':1,'maximum_wait_seconds':timeout,'automatic_retry':False,'signals_on_timeout':False}
    need(intent==wanted and raws['intent']==pretty(intent),'original_host_intent_exact')
    if stdin is not None:
        need(raws['stdin']==stdin,'original_host_stdin_exact')
    need(number(child.get('pid'),2) and child.get('source_intent_sha256')==sha(raws['intent']) and
         child.get('maximum_starts')==1,'original_host_child_identity')
    missing=child.get('identity_missing_only_if_actual_child_already_joined')
    need((missing is False and child.get('pgid')==child['pid']==child.get('sid')) or
         (missing is True and child.get('pgid') is None and child.get('sid') is None),
         'original_host_child_group')
    need(result.get('state')=='ORIGINAL_HOST_CHILD_JOINED' and result.get('phase')==phase and
         result.get('pid')==child['pid'] and type(result.get('returncode')) is int and
         result['returncode']==0 and result.get('automatic_retry') is False and
         result.get('stdout')==records['stdout'] and result.get('stderr')==records['stderr'] and
         raws['stderr']==b'', 'original_host_terminal_not_joined_zero')
    return raws['stdout']

def remote_phase(originals, value, root_raw, phase, argv, timeout, remote_root):
    need(type(value) is dict and set(value)=={'host','p4_terminal','p4_argv','p4_stdout','p4_stderr'},
         'actual_remote_phase_fields')
    code=remote_code(root_raw,'remote_program',phase=phase,remote_root=remote_root,argv=argv,timeout=timeout)
    out=host_phase(originals,value['host'],phase,literal(root_raw,'SSH'),timeout+30,code)
    original=originals.read(value['p4_terminal'])
    result=strict(original)
    need(same(strict(out),result) and result.get('automatic_retry') is False and
         type(result.get('returncode')) is int and result['returncode']==0 and
         type(result.get('stdout')) is str and result.get('stderr')=='',
         'actual_remote_terminal_zero')
    need(strict(originals.read(value['p4_argv']))==argv and
         originals.read(value['p4_stdout'])==result['stdout'].encode() and
         originals.read(value['p4_stderr'])==b'', 'remote_original_stream_binding')
    return result['stdout'].encode()

def unpack_archive(raw):
    """Bounded one-gzip, regular-only complete tar; no filesystem extraction."""
    import tarfile
    need(type(raw) is bytes and 0<len(raw)<=MAX_ARCHIVE,'compressed_archive_bound')
    dec=zlib.decompressobj(31)
    plain=dec.decompress(raw,MAX_EXPANDED_TAR+1)
    need(len(plain)<=MAX_EXPANDED_TAR and dec.eof and not dec.unused_data and
         not dec.unconsumed_tail,'single_bounded_gzip_archive')
    members={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for item in archive:
            name=relative(item.name)
            need(name not in members and len(members)<2065 and item.isfile() and
                 item.type==tarfile.REGTYPE and item.linkname=='' and item.mode==0o600 and
                 item.uid==0 and item.gid==0 and item.mtime==0 and
                 set(item.pax_headers)<= {'path'} and
                 item.pax_headers.get('path',name)==name and
                 0<=item.size<=MAX_ARCHIVE, 'archive_member_type_or_duplicate')
            stream=archive.extractfile(item)
            need(stream is not None,'archive_regular_body')
            body=stream.read(item.size+1)
            need(len(body)==item.size,'archive_member_short')
            members[name]=body
    need(members and sum(map(len,members.values()))<=MAX_ARCHIVE+4*1024*1024,
         'complete_archive_raw_bound')
    return members

def file_row(row, members):
    need(type(row) is dict and set(row)=={'source','bytes','sha256','metadata','retained'},
         'source_retained_row_fields')
    canonical(row['source']);metadata(row['metadata'])
    rel=row['retained'];need(type(rel) is dict and set(rel)=={'path','bytes','sha256'},'archive_retained_descriptor')
    name=relative(rel['path'])
    need(name in members and len(members[name])==row['bytes']==rel['bytes']==row['metadata']['st_size'] and
         sha(members[name])==row['sha256']==rel['sha256'],'archive_source_row_integrity')
    return members[name]

def directory_row(row, source, names):
    need(type(row) is dict and set(row)=={'source','metadata_before','metadata_after','names_before','names_after'} and
         row['source']==source,'directory_record_fields')
    metadata(row['metadata_before'],True)
    need(same(row['metadata_before'],row['metadata_after']) and
         row['names_before']==row['names_after']==sorted(names) and len(set(names))==len(names),
         'complete_original_directory_bookends')
    for name in names:
        need(type(name) is str and re.fullmatch('[A-Za-z0-9._-]{1,192}',name) and name not in ('.','..'),
             'original_flat_directory_name')

def source_rows(value):
    rows=[]
    def walk(item):
        if type(item) is dict:
            if set(item)=={'source','bytes','sha256','metadata','retained'}:
                rows.append(item)
            else:
                for child in item.values():walk(child)
        elif type(item) is list:
            for child in item:walk(child)
    walk(value)
    return rows

def load_sources(plan, originals, final):
    need(type(plan['sources']) is dict and set(plan['sources'])==SOURCE_NAMES,'reviewed_source_set')
    raw={}
    for name,row in plan['sources'].items():
        raw[name]=originals.read(row,131072)
        if name in DEP_SOURCE_NAMES:
            need({'bytes':len(raw[name]),'sha256':sha(raw[name])}==final['sources'][name],
                 'future_reviewed_source_pin')
        elif name=='root_transport_parent':
            need((len(raw[name]),sha(raw[name]))==PARENT_PINS['root_transport'],'transport_reference_pin')
        elif name!='ledger_negative':
            need(sha(raw[name])==FIXED_SHA[name],'fixed_pure_reference_pin')
    root_source(raw['root_transport'],raw['root_transport_parent'])
    for name in ('UI_PACKAGE_SHA','POLICY_SHA','ADOPTION_SHA'):
        expected={'UI_PACKAGE_SHA':final['ui_package_sha256'],'POLICY_SHA':final['live_policy']['sha256'],
                  'ADOPTION_SHA':final['policy_adoption_sha256']}[name]
        need(literal(raw['cpu'],name)==expected,'CPU_generation_binding')
    need(literal(raw['cpu'],'OPERATOR_SOURCES')['active_runtime_r10.py']==final['active_sha256'],
         'CPU_active_generation')
    need(literal(raw['phone'],'FINAL_DEPENDENCIES')=={
        'runtime_package_sha256':final['runtime_package_sha256'],'consumer_sha256':final['consumer_sha256'],
        'readiness_sha256':final['readiness_sha256'],'ui_package_sha256':final['ui_package_sha256'],
        'active_source_sha256':final['active_sha256'],'cpu_verifier_sha256':final['sources']['cpu']['sha256'],
        'configuration_sha256':final['configuration_sha256'],'service_inputs_sha256':final['service_inputs_sha256'],
        'policy_adoption_sha256':final['policy_adoption_sha256'],'live_policy':final['live_policy']},
        'phone_collector_final_dependencies')
    for name,expected in (
        ('REVIEWED_OPERATOR_PACKAGE_SHA256',final['ui_package_sha256']),
        ('REVIEWED_ACTIVE_SOURCE_SHA256',final['active_sha256']),
        ('REVIEWED_CPU_VERIFIER_SOURCE_SHA256',final['sources']['cpu']['sha256'])):
        need(literal(raw['p4'],name)==expected,'P4_collector_final_dependencies')
    return raw

def validate_plan(value):
    keys={'schema','state','case_id','nonce','scope','owner_request_sha256','native_request_sha256',
          'combination_sha256','sources','phone','p4','actor_execution','sender','out'}
    need(type(value) is dict and set(value)==keys and value['schema']==SCHEMA and
         value['state']=='ROOT_REVIEWED_EXISTING_NEGATIVE_ORIGINALS_ONLY','closure_plan_fields')
    need(value['case_id'] in ('NEG-08','NEG-09') and re.fullmatch('[0-9a-f]{32}',value['nonce']),
         'fixed_negative_case_existing_nonce')
    need(type(value['scope']) is dict and set(value['scope'])==set(SCOPE) and
         all(type(x) is str and 0<len(x.encode())<=256 and '\0' not in x
             for x in value['scope'].values()),'actual_original_scope')
    for key in ('owner_request_sha256','native_request_sha256','combination_sha256'):
        digest(value[key])
    need(value['out']==B+'/cpu-cancel-negative-closures-r1/'+value['nonce'],
         'new_host_output_exact_existing_nonce')
    for key,fields in (
        ('phone',{'plan','request','operation','wrapper','execution','archive'}),
        ('p4',{'plan','execution','result','archive'}),
        ('sender',{'execution','request','previous','preserved_draft','retirement_resolution',
                   'generated_actor','local_once','send_result'})):
        need(type(value[key]) is dict and set(value[key])==fields,'original_input_group_fields')
    return value

def _phone_artifacts(plan, originals, raw_sources, final):
    value=plan['phone'];plan_raw=originals.read(value['plan'],65536);bound=strict(plan_raw)
    need(bound.get('schema')=='hepta.cpu-cancel.phone-capture-plan.v1' and
         bound.get('nonce')==plan['nonce'] and bound.get('case_id')==plan['case_id'] and
         bound.get('sender_scope')==plan['scope'] and bound.get('owner_request_sha256')==plan['owner_request_sha256'] and
         bound.get('native_request_sha256')==plan['native_request_sha256'] and
         bound.get('combination_sha256')==final['combination_sha256']==plan['combination_sha256'],
         'phone_original_plan_scope')
    request=strict(originals.read(value['request'],65536))
    need(request==phone_request(raw_sources['phone'],plan_raw),'exact_bounded_phone_capture_request')
    control=P4+'/cpu-negative-controls-r1/'+plan['nonce']
    code=remote_code(raw_sources['root_transport'],'phone',phase='phone-negative-capture',
                    remote_root=control,request=request,nonce=plan['nonce'])
    stdout=host_phase(originals,value['execution'],'phone-negative-capture',
        literal(raw_sources['root_transport'],'SSH'),request['timeout_seconds']+55,code)
    operation_raw=originals.read(value['operation'],MAX_ARCHIVE)
    need(stdout==operation_raw,'phone_original_host_stdout')
    op=strict(operation_raw);wrapper_raw=originals.read(value['wrapper'],MAX_ARCHIVE)
    wrapper=strict(wrapper_raw);wire=wrapper.get('phone',{})
    need(type(op.get('actor_rc')) is int and op['actor_rc']==0 and
         op.get('wrapper_sha256')==sha(wrapper_raw) and same(op.get('wrapper'),wrapper) and
         type(wire.get('rc')) is int and wire['rc']==0 and wire.get('stderr')=='' and
         type(wire.get('stdout')) is str,'original_phone_actor_and_wire_terminal')
    result_raw=wire['stdout'].encode();result=strict(result_raw)
    need(result.get('schema')=='hepta.cpu-cancel.phone-capture-result.v1' and
         result.get('state')=='CAPTURED_NEGATIVE_ORIGINALS_UNQUALIFIED' and
         result.get('export_complete') is True and result.get('issues')==[] and
         result.get('source_sha256')==sha(raw_sources['phone']) and
         result.get('plan_sha256')==sha(plan_raw),'final_phone_capture_not_complete')
    archive_raw=originals.read(value['archive'],MAX_ARCHIVE)
    remote=result['archive']
    need(remote['path']==BASE+'/negative-original-captures-r10-r1/'+plan['nonce']+'/originals.tar.gz' and
         remote['bytes']==len(archive_raw) and remote['sha256']==sha(archive_raw),'phone_archive_original_pin')
    members=unpack_archive(archive_raw)
    need('CAPTURE.json' in members and sha(members['CAPTURE.json'])==result['capture_sha256'] and
         remote['member_count']==len(members),'phone_archive_capture_and_count')
    capture=strict(members['CAPTURE.json'])
    need(capture.get('schema')=='hepta.cpu-cancel.phone-original-capture.v1' and
         capture.get('state')==result['state'] and capture.get('export_complete') is True and
         capture.get('issues')==[] and capture.get('reviewed_dependencies')==
         literal(raw_sources['phone'],'FINAL_DEPENDENCIES'),'phone_capture_schema_and_final_state')
    for key in ('case_id','nonce','owner_request_sha256','combination_sha256','native_request_sha256'):
        need(result.get(key)==capture.get(key)==plan[key],'phone_case_binding')
    need(result.get('selected_scope')==capture.get('selected_scope')==plan['scope'],'phone_scope_binding')
    for key in ('task_submissions','phone_ui_actions','model_requests','socket_calls','tool_calls',
                'signals_sent','new_native_nonces','original_file_writes'):
        need(type(result.get(key)) is int and result[key]==0,'capture_process_action_count')
    need(result.get('automatic_retry') is False and result.get('new_private_snapshot_only') is True and
         result.get('physical_case_pass') is False and result.get('native_closure_issued') is False,
         'capture_is_not_qualification')
    expected={'CAPTURE.json'}
    source_map={};absences=set()
    for row in capture['files']:
        canonical(row['source_path']);name=relative(row['export_relative_path'])
        if row.get('state')=='captured':
            metadata(row['stat_before'])
            need(row.get('eof') is True and row['stat_before']==row['stat_after'] and
                 name in members and row['bytes']==len(members[name])==row['stat_before']['st_size'] and
                 row['sha256']==sha(members[name]),'captured_phone_original_metadata_and_bytes')
            need(name not in expected and row['source_path'] not in source_map,'duplicate_phone_original')
            expected.add(name);source_map[row['source_path']]=(name,row)
        else:
            need(row.get('state')=='absent' and row.get('lookup_errno')==2 and
                 row.get('required') is False and name not in members,'phone_absence_is_not_missing_archive')
            absences.add(row['source_path'])
    for name,row in capture['generated_originals'].items():
        relative(name)
        need(name not in expected and name in members and
             row['bytes']==len(members[name]) and row['sha256']==sha(members[name]),'generated_original_pin')
        expected.add(name)
    need(set(members)==expected and members['SOURCE.original.py']==raw_sources['phone'] and
         members['CAPTURE-PLAN.original.json']==plan_raw,'phone_archive_exact_closed_member_set')
    need(result['original_file_count']==sum(r.get('state')=='captured' for r in capture['files']),
         'phone_file_count')
    for row in capture['directories']:
        canonical(row['source_path'])
        if row.get('state')=='observed':
            metadata(row['stat'],True)
            need(row['names']==sorted(set(row['names'])),'phone_directory_names')
        else:
            need(row.get('state')=='absent' and row.get('lookup_errno')==2 and
                 row.get('required') is False,'phone_directory_absence')
    return {'plan':bound,'plan_raw':plan_raw,'capture':capture,'capture_raw':members['CAPTURE.json'],
            'result':result,'result_raw':result_raw,'members':members,'sources':source_map,'absences':absences}

def phone_request(source, plan_raw):
    """Pure request recipe; emits no call and makes no new identity."""
    need(type(source) is bytes and 0<len(source)<=65536 and
         type(plan_raw) is bytes and 0<len(plan_raw)<=65536,'phone_recipe_bounds')
    packet=encoded({'source_b64':base64.b64encode(source).decode(),
                    'plan_b64':base64.b64encode(plan_raw).decode(),
                    'source_sha256':sha(source),'plan_sha256':sha(plan_raw)})
    need(len(packet)<=262144,'phone_packet_bound')
    packed=gzip.compress(packet,compresslevel=9,mtime=0)
    boot="import base64,hashlib,json,sys,zlib\np=base64.b64decode("+repr(base64.b64encode(packed).decode())+",validate=True)\n"
    boot+="d=zlib.decompressobj(31);b=d.decompress(p,262145)\nassert len(b)<=262144 and d.eof and not d.unused_data and not d.unconsumed_tail\n"
    boot+="assert hashlib.sha256(b).hexdigest()=="+repr(sha(packet))+"\nv=json.loads(b)\ns=base64.b64decode(v['source_b64'],validate=True)\n"
    boot+="assert hashlib.sha256(s).hexdigest()==v['source_sha256']\nsys.argv=['capture_negative_originals.py','--plan-b64',v['plan_b64'],'--plan-sha256',v['plan_sha256'],'--reviewed-source-sha256',v['source_sha256'],'--execute-read-once']\n"
    boot+="exec(compile(s,'capture_negative_originals.py','exec'),{'__name__':'__main__','__file__':'capture_negative_originals.py','_REVIEWED_SOURCE_BYTES':s})\n"
    command='/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '+shlex.quote(boot)
    need(len(('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(command)).encode())<65536,
         'actual_single_su_ADB_bound')
    return {'kind':'shell','root':True,'timeout_seconds':120,'command':command}

def _p4_artifacts(plan, originals, raw_sources, final):
    value=plan['p4'];plan_raw=originals.read(value['plan'],2*1024*1024);bound=strict(plan_raw)
    need(bound.get('schema')=='hepta.cpu-cancel.p4-original-capture-plan.v1' and
         bound.get('case_id')==plan['case_id'] and bound.get('expected_scope')==plan['scope'] and
         bound.get('owner_request_sha256')==plan['owner_request_sha256'],'P4_capture_plan_binding')
    label=bound['capture_label']
    need(re.fullmatch('[a-z0-9-]{1,70}',label),'P4_capture_existing_label')
    inp=P4+'/cpu-cancel-p4-capture-inputs-r1/'+label
    source_path=inp+'/capture_p4_cancel_originals.py'
    argv=['/usr/bin/python3','-I','-B',source_path,'--plan',inp+'/PLAN.json','--plan-sha256',sha(plan_raw),
          '--reviewed-source-sha256',sha(raw_sources['p4']),'--execute-host-only']
    stdout=remote_phase(originals,value['execution'],raw_sources['root_transport'],'negative-p4-capture',
                        argv,90,P4+'/cpu-negative-controls-r1/'+plan['nonce'])
    summary=strict(stdout);result_raw=originals.read(value['result'],4*1024*1024);result=strict(result_raw)
    need(summary.get('state')==result.get('state')=='ORIGINAL_FILES_CAPTURED_CPU_ELIGIBILITY_NOT_ASSESSED' and
         summary.get('result',{}).get('bytes')==len(result_raw) and
         summary.get('result',{}).get('sha256')==sha(result_raw) and
         result.get('schema')=='hepta.cpu-cancel.p4-capture-result.v1' and
         result.get('originals_rechecked_after_archive') is True,'P4_final_result_binding')
    archive_raw=originals.read(value['archive'],MAX_ARCHIVE)
    remote=result['archive']
    need(remote==summary['archive'] and remote['bytes']==len(archive_raw) and
         remote['sha256']==sha(archive_raw) and
         remote['path']==P4+'/cpu-cancel-p4-original-captures-r1/'+label+'/ORIGINALS.tar.gz',
         'P4_archive_actual_pin')
    members=unpack_archive(archive_raw)
    capraw=members.get('CAPTURE.original.json');need(type(capraw) is bytes,'P4_capture_raw_present')
    need(result['capture']==summary['capture'] and result['capture']['bytes']==len(capraw) and
         result['capture']['sha256']==sha(capraw) and result['archive_member_count']==len(members),
         'P4_capture_result_and_archive_equal')
    capture=strict(capraw)
    need(capture.get('schema')=='hepta.cpu-cancel.p4-original-capture.v1' and
         capture.get('state')==result['state'] and capture.get('case_id')==plan['case_id'] and
         capture.get('expected_scope')==plan['scope'] and capture.get('owner_request_sha256')==plan['owner_request_sha256'] and
         capture.get('all_original_full9_and_bytes_rechecked') is True and
         capture.get('complete_directory_census_bookends_equal') is True,
         'P4_complete_capture_binding')
    expected={'CAPTURE.original.json'}
    for row in source_rows(capture):
        file_row(row,members);expected.add(row['retained']['path'])
    need(set(members)==expected and capture['retained_member_count']+1==len(members),
         'P4_archive_closed_member_set')
    need(file_row(capture['source'],members)==raw_sources['p4'] and
         file_row(capture['plan'],members)==plan_raw and
         file_row(capture['reviewed_inputs']['cpu_verifier_source'],members)==raw_sources['cpu'],
         'P4_actual_compiled_sources_and_plan')
    need(capture.get('actor_required_cpu_records_missing')==[] and
         capture.get('actor_failure_original_present') is False and
         capture.get('sender_failure_original_present') is False and
         capture.get('actor_directory') is not None and capture.get('sender_directory') is not None and
         capture.get('once_reservation') is not None,'missing_or_failed_actual_case_originals')
    return {'plan':bound,'plan_raw':plan_raw,'capture':capture,'capture_raw':capraw,
            'result':result,'members':members}

def _materialize_view(plan,phone,p4,raw_sources,originals):
    retained={}
    root=plan['out']+'/originals'
    def put(relative_name,raw):
        path=root+'/'+relative(relative_name)
        need(path not in retained,'host_retained_name_duplicate')
        retained[path]=raw
        return {'path':path,'bytes':len(raw),'sha256':sha(raw)}
    mappings={}
    for group,data in (('phone',phone),('p4',p4)):
        for name,raw in data['members'].items():
            mappings[(group,name)]=put(group+'/'+name,raw)
    def mapped(row):
        result=copy.deepcopy(row)
        result['retained']=mappings[('p4',row['retained']['path'])]
        return result
    cap=p4['capture'];pc=phone['capture']
    actor_rows={k:mapped(v) for k,v in cap['actor_originals'].items()}
    actor_plan_raw=retained[actor_rows['PLAN.original.json']['retained']['path']]
    actor_plan=strict(actor_plan_raw)
    need(actor_plan_raw==file_row(cap['reviewed_inputs']['actor_plan'],p4['members']) and
         actor_plan['nonce']==plan['nonce'] and actor_plan['case_id']==plan['case_id'] and
         actor_plan['owner_request_sha256']==plan['owner_request_sha256'] and
         actor_plan['label']==pc['operator_label']==cap['actor_label'] and
         actor_plan['sender_label']==pc['sender_label']==cap['sender_label'] and
         sha(actor_plan_raw)==pc['operator_plan_sha256'],'cross_host_original_actor_plan')
    rows={}
    for source,(name,row) in phone['sources'].items():
        if source.startswith(BASE+'/model-runtime-r10-r1/'+actor_plan['expected_boot']+'/'):
            rel='runtime/'+source.split('/model-runtime-r10-r1/'+actor_plan['expected_boot']+'/',1)[1]
        elif source.startswith(BASE+'/'):
            rel=source[len(BASE)+1:]
        else:
            continue
        need(rel not in rows,'CPU_phone_source_alias')
        rows[rel]={'source':source,'bytes':row['bytes'],'sha256':row['sha256'],
                   'metadata':row['stat_before'],'retained':mappings[('phone',name)]}
    actor_result=strict(retained[actor_rows['RESULT.json']['retained']['path']])
    last=actor_result['last_original_observation']
    rid=last['model']['request_id'];run=last['run']
    need(pc['actual_run']==run==phone['plan']['sender_run'],'captured_exact_last_run')
    def directory(source):
        ds=[r for r in pc['directories'] if r.get('source_path')==source]
        need(ds and all(r==ds[0] for r in ds) and ds[0].get('state')=='observed',
             'complete_original_directory_source')
        d=ds[0]
        return {'source':source,'metadata_before':d['stat'],'metadata_after':d['stat'],
                'names_before':d['names'],'names_after':list(d['names'])}
    pure={}
    for key,name in (('model_slot_cleanup.py','cleanup'),('close_original_r10.py','positive_closer'),
                     ('task_postconditions.py','postconditions'),('configuration','configuration'),('service','service')):
        pure[key]=plan['sources'][name]
    operators={name:mapped(row)['retained'] for name,row in cap['reviewed_inputs']['operator_sources'].items()}
    need(set(operators)==OPERATOR_NAMES,'actual_eight_source_map')
    value={'schema':'hepta.r10.cpu-cancel-original-inputs.v1','case_id':plan['case_id'],
        'operator_package':mapped(cap['reviewed_inputs']['operator_package'])['retained'],
        'operator_sources':operators,'actor_directory':cap['actor_directory'],'actor_originals':actor_rows,
        'once_reservation':mapped(cap['once_reservation']),
        'phone_directories':{'run':directory(BASE+'/provider-state/evidence/'+run),
           'ledger_prefix':directory(BASE+'/provider-state/evidence/'+run+'/ledger-prefix'),
           'producer':directory(BASE+'/model-runtime-r10-r1/'+actor_plan['expected_boot']+'/receipts/'+rid)},
        'phone_originals':rows,'reviewed_sources':pure}
    directory_row(value['actor_directory'],P4+'/cancel-native-r10/'+actor_plan['label'],actor_rows)
    directory_row(cap['sender_directory'],'/home/alex/codex-hepta-natural-'+actor_plan['sender_label']+'-root-v150',
                  cap['sender_originals'])
    need(len(phone['members'])+len(p4['members'])==len(retained),'complete_host_copy_inventory')
    return value,retained,actor_plan,actor_result

def assemble(plan_raw, *, read_pinned):
    final=final_dependencies()  # Must precede any case read or callback.
    plan=validate_plan(strict(plan_raw))
    need(plan['combination_sha256']==final['combination_sha256'],'current_combination_pin')
    originals=Originals(read_pinned)
    raw_sources=load_sources(plan,originals,final)
    phone=_phone_artifacts(plan,originals,raw_sources,final)
    p4=_p4_artifacts(plan,originals,raw_sources,final)
    value,retained,actor_plan,actor_result=_materialize_view(plan,phone,p4,raw_sources,originals)
    def read_combined(row):
        if row['path'] in retained:
            body=retained[row['path']]
            need(len(body)==row['bytes'] and sha(body)==row['sha256'],'retained_projection_read')
            return body
        return originals.read(row)
    originals.recheck()
    return {'plan':plan,'plan_raw':plan_raw,'final':final,'originals':originals,
            'raw_sources':raw_sources,'phone':phone,'p4':p4,'cpu_inputs':value,
            'cpu_inputs_raw':encoded(value),'retained':retained,'read_pinned':read_combined,
            'actor_plan':actor_plan,'actor_result':actor_result,
            'assembly_summary':{'schema':'hepta.r10.cpu-negative-assembled.v1',
                'state':'ORIGINAL_NEGATIVE_INPUTS_ASSEMBLED','case_id':plan['case_id'],
                'nonce':plan['nonce'],'scope':plan['scope'],'input_plan_sha256':sha(plan_raw),
                'original_phone_archive_sha256':plan['phone']['archive']['sha256'],
                'original_p4_archive_sha256':plan['p4']['archive']['sha256'],
                'normalization':'Source full9 preserved; directory equality follows original collector final stability, not two invented reads.',
                'case_qualification_assessed':False,'physical_case_pass':False,
                'phone_calls':0,'model_requests':0,'new_native_nonces':0,'automatic_retry':False}}
