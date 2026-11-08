"""Pure semantic reader for the one fully retained actual R9 scope.
No file, process, device, network, signal or replay operations are performed.
Inputs are complete original bytes; predecessor and host values come from
their separately pinned original readers, composed by the public reader.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat
import types
import zlib

RAW_PINS = {'controller_reader': {'bytes': 16570, 'sha256': 'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'}, 'library_attempt05': {'bytes': 19740, 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}, 'library_common': {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'library_diag02': {'bytes': 29504, 'sha256': '296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6'}, 'library_late': {'bytes': 218894, 'sha256': '9adcd6a865875f209bf56cfadc952b40cf4984889cb3450837446b6b95dcbd54'}, 'library_lifecycle': {'bytes': 48643, 'sha256': 'eb43d1f5df1b0e4295770c82328fd17e09b9eaa766861f3803928a0b1f9f4e18'}, 'library_manifest': {'bytes': 65655, 'sha256': '654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}, 'library_native_profile': {'bytes': 4633, 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, 'observer_actor': {'bytes': 7578, 'sha256': 'c74aec49cd4fa84238194242653d5d3798b7f5cdc4659f90bcb50ec0c424902f'}, 'observer_config': {'bytes': 2416, 'sha256': '18600d15ae02724db5e630a39a310b2449c5d7fb162a73239bd7f8045164e1a6'}, 'observer_profile': {'bytes': 4383, 'sha256': '325e36d77472700fc9aab5d3149d7e56e267185d56a4ee11a6362ce6d85c1806'}, 'scope_host_request': {'bytes': 34843, 'sha256': '3abf8649800b30d9cd5012b554f27eb60720521119b1907c862723d60dc8745f'}, 'scope_outer': {'bytes': 2420400, 'sha256': 'e6ec9a6d3812c6801cb2f0b2aa44c9fb51db0ea1b68c7f83762f1cbda660f795'}, 'scope_phone_request': {'bytes': 22529, 'sha256': 'de19b265e7bf8f0a963a8863331847da9d9c9ae9f01fe4f23b030323b9b21d84'}, 'scope_read': {'bytes': 1239, 'sha256': '12f5ba79434e858e2425d019737392a6f12cbcf1d51442351ce4035da4971322'}, 'scope_source': {'bytes': 56762, 'sha256': 'ed02a304a97815991d2a5366ca2df45e3f28a2c18652eac6662404de53ff75a2'}, 'scope_start': {'bytes': 35960, 'sha256': 'fda4af684b32892286431096f5b60ee2a21c3cee23de674002e24a97dfa83c00'}, 'scope_status': {'bytes': 952, 'sha256': '73717463e2118e48061e07149807b714ffc070d1473f4643e89268ac0561d23a'}, 'source_helper': {'bytes': 25791, 'sha256': '06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0'}}
LABEL='root-r10-neg01-fc33-r9-bound01'
NONCE='299483481a678cbd589aeba54ed8b68f'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
SOURCE_HOME=BASE+'/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01'
JOB='1a1b72f0689-12894-985'
ORIGINAL_JOB='1a1b6f11ffd-12894-818'
RAW_SCOPE_PIN={'bytes':11658275,'sha256':'7323e266eed8e2e0413f4a04e4368b703953103c214a569a0fe175bcc76b2ddd'}
LIMITS={'compressed_bytes':8388608,'inventory_entries':30000,'inventory_file_bytes':67108864,
        'inventory_unique_file_bytes':536870912,'original_fixture_cap':14,
        'per_proc_census_seconds':2,'proc_pids':4096,'proc_stat_bytes':8192,'result_bytes':67108864,
        'scope_entries':512,'scope_raw_bytes':16777216,'shared_actual_read_bytes':201326592,'shared_seconds':30}

def need(value,why):
    if not value:raise ValueError(why)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def enc(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def exactpin(value):return {k:value[k]for k in ('bytes','sha256')}
def literal(raw,name):
    matches=[n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign)
             and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name]
    need(len(matches)==1,'one source constant '+name);return ast.literal_eval(matches[0])
def function(raw,name):
    text=raw.decode('utf-8','strict')
    matches=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name]
    need(len(matches)==1,'one source function '+name)
    return ast.get_source_segment(text,matches[0])+'\n'
def full9(value,*,directory=False):
    need(type(value)is list and len(value)==9 and all(type(v)is int and v>=0 for v in value),
         'exact nonnegative integer full9 metadata')
    need((stat.S_ISDIR(value[2])if directory else stat.S_ISREG(value[2])and value[5]==1),
         'ordinary directory or single-link regular original')
    return value
def named(value):
    need(type(value)is list and value==sorted(set(value))and len(value)<=20000
         and all(type(x)is str and x not in ('','.','..')and'/'not in x and'\0'not in x for x in value),
         'complete bounded sorted canonical names')
def descriptor(row,raw=None):
    need(type(row)is dict and type(row['path'])is str and Path(row['path']).is_absolute()
         and str(Path(row['path']))==row['path']and'..'not in Path(row['path']).parts,
         'canonical original path')
    need(type(row['bytes'])is int and 0<=row['bytes']<=64*1024*1024
         and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'typed bounded exact original pin')
    if 'metadata'in row:need(full9(row['metadata'])[6]==row['bytes'],'original size/full9')
    if raw is not None:need(type(raw)is bytes and pin(raw)==exactpin(row),'complete original bytes')
def blob(row,*,limit=1048576):
    need(type(row['bytes'])is int and 0<=row['bytes']<=limit,'raw original byte bound')
    raw=base64.b64decode(row['raw_base64'],validate=True)
    need(base64.b64encode(raw).decode()==row['raw_base64']and pin(raw)==exactpin(row),'canonical complete raw original')
    return raw
def stamp(value):
    need(type(value)is dict and set(value)=={'unix_ns','monotonic_ns'}
         and all(type(v)is int and v>0 for v in value.values()),'two exact original clocks')
    return value['monotonic_ns']
def ordered_stamps(*values):
    rows=[stamp(v)for v in values];need(rows==sorted(rows),'original monotonic order');return rows

def current_absence(value,expected_paths):
    need(type(value)is list and len(value)==len(expected_paths),'all ten fixed current paths')
    for row,path in zip(value,expected_paths):
        need(set(row)=={'path','parent_path','parent_metadata','parent_names','state','errno',
             'missing_path','missing_component_index','untraversed_components','leaf_itself_observed_absent',
             'historical_execution_inferred'}and row['path']==path,'exact current absence row')
        p=Path(path)
        if p.parts[:4]==('/','proc','1','root'):start=Path('/proc/1/root');parts=p.parts[4:]
        else:start=Path('/');parts=p.parts[1:]
        i=row['missing_component_index']
        need(type(i)is int and 0<=i<len(parts),'actual first missing component index')
        parent=start.joinpath(*parts[:i]);missing=parent/parts[i]
        need(row['state']=='CURRENT_FIRST_MISSING_COMPONENT_ENOENT'and type(row['errno'])is int
             and row['errno']==2 and row['historical_execution_inferred']is False,
             'current exact ENOENT not historical execution claim')
        need(row['parent_path']==str(parent)and row['missing_path']==str(missing)
             and row['untraversed_components']==list(parts[i+1:])
             and row['leaf_itself_observed_absent']is(i==len(parts)-1),'preserve missing ancestor versus exact leaf')
        full9(row['parent_metadata'],directory=True);named(row['parent_names'])
        need(parts[i]not in row['parent_names'],'missing component conflicts with complete parent names')
    return True

def verify_failed_r9_scope(raw,*,retained,host):
    need(type(RAW_PINS)is dict and type(raw)is dict and set(raw)==set(RAW_PINS),'exact bound original input closure')
    for key,data in raw.items():need(type(data)is bytes and pin(data)==RAW_PINS[key],'full fixed original: '+key)
    # The unchanged controller validates actual launch, exit, durable counters and both EOFs.
    c=types.ModuleType('original_scope_controller');c.__file__='/fixed-original/verify_host_controller_originals.py'
    exec(compile(raw['controller_reader'],c.__file__,'exec'),c.__dict__)
    job,status,streams=c.controller({name:strict(raw['scope_'+name])for name in ('start','status','read')},code=0,complete=True)
    request=strict(raw['scope_host_request']);dispatch=request['args'][3].encode()
    need(job['id']==JOB and all(job[k]==request[k]for k in ('host','executable','args','idempotency_key'))
         and request['timeout_seconds']==150 and request['args'][:3]==['-I','-B','-c'],
         'same unique original observer host request and unchanged budget')
    need(streams['stderr']==b''and len(streams['stdout'])==228,'full observer terminal streams')
    output=strict(streams['stdout']);outer=strict(raw['scope_outer'])
    need(output['actor_rc']==0 and output['automatic_retry']is False
         and exactpin(output['result'])==pin(raw['scope_outer'])
         and output['result']['path']=='/home/alex/codex-ro-r9-failed01-full-scope-20261107-01/RESULT.json',
         'complete observed output original')
    q=strict(raw['scope_phone_request']);qs=pin(raw['scope_phone_request'])
    need(outer['schema']=='hepta.r9.failed-first-push-scope-dispatch-result.v1'
         and outer['label']=='ro-r9-failed01-full-scope-20261107-01'and type(outer['actor_rc'])is int
         and outer['actor_rc']==0 and outer['automatic_retry']is False
         and outer['past_failure_offender_identified']is False,'successful read-only observer outer result')
    for key in ('signals_sent_by_dispatch','native_submissions','new_nonces'):
        need(type(outer[key])is int and outer[key]==0,'observer dispatch no native effect')
    need(outer['request']=={'path':'/home/alex/razr60-local-model-v150/requests/ro-r9-failed01-full-scope-20261107-01.json',**qs}
         and q['kind']=='shell'and q['root']is True and q['timeout_seconds']==90,'one actual fixed read-only phone request')
    dt=ast.parse(dispatch)
    qnode=next(n.value for n in dt.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='REQUEST'for t in n.targets))
    need(isinstance(qnode,ast.Call)and isinstance(qnode.func,ast.Attribute)and qnode.func.attr=='b64decode'
         and base64.b64decode(ast.literal_eval(qnode.args[0]),validate=True)==raw['scope_phone_request']
         and literal(dispatch,'REQUEST_SHA')==qs['sha256'],'exact embedded actor request')
    original_pins=literal(dispatch,'PINS')
    deps={row['path']:row for row in original_pins}
    need(len(deps)==len(original_pins)==4,'four fixed actual observation profile originals')
    for key in ('source_helper','observer_actor','observer_config','observer_profile'):
        matches=[r for r in original_pins if exactpin(r)==pin(raw[key])]
        need(len(matches)==1,'one actual selected transport dependency '+key);descriptor(matches[0],raw[key])
    actor_path=literal(dispatch,'ACTOR')
    need(actor_path==next(r['path']for r in original_pins if exactpin(r)==pin(raw['observer_actor'])),
         'only the adopted read-only observation actor')
    profile=strict(raw['observer_profile']);cfg=strict(raw['observer_config'])
    # The exact dispatcher bookends these pinned full9 sources around its single waited actor.
    pops=[n for n in ast.walk(dt)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='Popen']
    need(len(pops)==1,'exact one observer actor process')
    waits=[n for n in ast.walk(dt)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='wait']
    need(len(waits)==1 and any(k.arg=='timeout'and ast.literal_eval(k.value)==110 for k in waits[0].keywords),
         'unchanged joined actor wait budget')
    w=outer['wrapper'];ph=w['phone']
    need(w['label']==outer['label']and w['status']=='command_exited'and w['model_decision']is False
         and w['native_task_result']is False and type(ph['rc'])is int and ph['rc']==0 and ph['stderr']==''
         and ph['command']=='/debug_ramdisk/su -c '+shlex.quote(q['command']),'successful exact read-only phone wire')
    argv=shlex.split(q['command'])
    need(argv[:7]==['/data/adb/magisk/busybox','chroot','/data/trillionnium/owner-open/root','/usr/bin/python3','-I','-B','-c']
         and len(argv)==8,'exact held source chroot wire')
    embedded=[n for n in ast.walk(ast.parse(argv[-1]))if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)
              and n.func.attr=='b64decode']
    need(len(embedded)==1,'one complete source payload')
    z=zlib.decompressobj();code=z.decompress(base64.b64decode(ast.literal_eval(embedded[0].args[0]),validate=True),131073)
    need(z.eof and not z.unused_data and not z.unconsumed_tail and code==raw['scope_source'],'complete executed fixed observer source')
    at=ast.parse(raw['observer_actor'])
    initial=next(n.value for n in at.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='result'for t in n.targets))
    keys=[ast.literal_eval(k)for k in initial.keys]
    need(keys==['schema','label','model_decision','native_task_result'],'original actor result order')
    shell=next(n for n in ast.parse(raw['source_helper']).body if isinstance(n,ast.FunctionDef)and n.name=='shell')
    returns=[n for n in ast.walk(shell)if isinstance(n,ast.Return)]
    need(len(returns)==1 and isinstance(returns[0].value,ast.Dict),'original helper return order')
    phonekeys=[ast.literal_eval(k)for k in returns[0].value.keys]
    need(phonekeys==['command','rc','route','stdout','stderr'],'original phone dictionary order')
    restored={k:w[k]for k in keys};restored['phone']={k:ph[k]for k in phonekeys}
    restored['status']=w['status'];restored['elapsed_seconds']=w['elapsed_seconds']
    need(set(restored)==set(w)and set(restored['phone'])==set(ph),'no omitted wrapper fields')
    wrapper_raw=(json.dumps(restored,ensure_ascii=False,indent=2)+'\n').encode()
    descriptor(outer['wrapper_original'],wrapper_raw)
    need(outer['wrapper_original']['metadata'][2:5]==[stat.S_IFREG|0o600,1000,1000]
         and outer['wrapper_original']['path']=='/home/alex/razr60-local-model-v150/operations/'+outer['label']+'/result.json',
         'same actual wrapper original identity')
    envelope=strict(ph['stdout'])
    need(set(envelope)=={'schema','encoding','payload','raw_bytes','raw_sha256','compressed_bytes','compressed_sha256','returncode'}
         and envelope['schema']=='hepta.r9.failed-first-push-scope.compressed-originals.v1'
         and envelope['encoding']=='zlib-base64'and type(envelope['returncode'])is int and envelope['returncode']==0,
         'one complete original successful phone envelope')
    compressed=base64.b64decode(envelope['payload'],validate=True)
    need(pin(compressed)=={'bytes':envelope['compressed_bytes'],'sha256':envelope['compressed_sha256']}
         and len(compressed)<=LIMITS['compressed_bytes'],'full bounded compressed original')
    z=zlib.decompressobj();scope_raw=z.decompress(compressed,LIMITS['result_bytes']+1)
    need(z.eof and not z.unused_data and not z.unconsumed_tail
         and pin(scope_raw)=={'bytes':envelope['raw_bytes'],'sha256':envelope['raw_sha256']}==RAW_SCOPE_PIN,
         'entire fixed phone original with no trailing compressed member')
    v=strict(scope_raw)
    need(v['schema']=='hepta.r9.failed-first-push.scope-observation.v1'
         and v['state']=='COMPLETE_READ_ONLY_SCOPE_ORIGINALS_CAPTURED_NO_DISPOSITION'
         and v['label']==LABEL and v['nonce']==NONCE and v['boot_id']==BOOT
         and v['original_root_job']==ORIGINAL_JOB and v['capture_source_sha256']==pin(code)['sha256'],
         'one actual same-boot failed R9 scope')
    source=raw['scope_source']
    constants={n:literal(source,n)for n in ('KNOWN_PHONE_ORIGINALS','RETAINED_R8_FILES','RETAINED_R8_BINDING',
               'ROLE_FUNCTIONS','TARGET_PATHS','FAILED_LEASE','FAILED_PACKAGE','PACKAGE','LEASE','COMMON','LIFECYCLE','LATE_SOURCE')}
    need(host['label']==LABEL and host['nonce']==NONCE and host['boot_id']==BOOT
         and host['schema']=='hepta.r9.retained-first-push-host-verification.v1'
         and host['original_root_job']==ORIGINAL_JOB and host['original_nonce_consumed']is True
         and host['source_order']['root_first_material_push_failure_before_copy_stage_sender_and_native_launch']is True,
         'separate complete failed host reader is required')
    need(v['failed_host_lease']==constants['FAILED_LEASE']
         and exactpin(v['failed_host_lease']['descriptor'])==host['lease']
         and v['failed_host_lease']['value']['nonce']==NONCE
         and v['failed_runtime_package']==constants['FAILED_PACKAGE']==host['package'],
         'actual failed host lease/package preserved')
    need(v['source_package_on_phone']=={'home':SOURCE_HOME,**constants['PACKAGE']},'exact old R8 read-only library')
    for k in ('phone_file_writes','signals_including_signal_zero','locks_acquired','sockets_opened','subprocesses_spawned',
              'ui_actions','model_requests','native_submissions','new_nonces','native_case_credit'):
        need(type(v[k])is int and v[k]==0,'zero observer effects and qualification')
    for k in ('automatic_retry','runtime_admission','retirement_accepted','past_failure_offender_identified','original_failure_rewritten'):
        need(v[k]is False,'no premature qualification or historical replacement')
    for k in ('native_terminal','global_unknown_effect_count','current_new_R9_private_roots','current_new_R9_component_role_identities'):
        need(v[k]is None,'original capture unknown fields remain unchanged')
    for k in ('first_launch_receipt_gap','original_start_reused','current_absence_is_not_historical_zero_effect',
              'complete_old49_preserved','full_inventory_entries_equal','all_target_paths_observed_twice','current_targets_all_unreachable_ENOENT'):
        need(v[k]is True,'required exact capture flags')
    need(v['original_wrapper_status']=='failed_or_unknown_no_retry'and v['limits']==LIMITS,'failure family and unchanged all budgets')
    ordered_stamps(v['began'],v['ended'])
    need(type(v['elapsed_seconds'])is float and 0<v['elapsed_seconds']<30
         and 0<stamp(v['ended'])-stamp(v['began'])<30*10**9,'actual complete scope deadline')
    need(v['original_files']=={}and v['present_target_tree_before']==v['present_target_tree_after']=={}
         and type(v['retained_scope_raw_bytes'])is int and v['retained_scope_raw_bytes']==0,'no present new R9 scope originals omitted')
    # Load only original pure inventory/stat validators from exact observed source bytes.
    cn={'need':need}
    exec(compile(function(raw['library_common'],'stat_identity'),'<original-common-stat>','exec'),cn)
    common=types.SimpleNamespace(need=need,HASH=re.compile('[0-9a-f]{64}'))
    invns={'C':common,'Path':Path,'stat':stat,'re':re}
    exec(compile(function(raw['library_late'],'inventory_value'),'<original-inventory-value>','exec'),invns)
    inventory_value=invns['inventory_value']
    manifest=strict(raw['library_manifest']);members={r['path']:r for r in manifest['files']}
    need(len(members)==len(manifest['files'])==38 and pin(raw['library_manifest'])==constants['PACKAGE'],'complete original library package38')
    libnames={'library_common':'source/component_common.py','library_lifecycle':'source/component_lifecycle.py',
              'library_late':'source/late_boundary.py','library_native_profile':'source/native_proc_profile.py',
              'library_attempt05':'reference/non_native_attempt05.py','library_diag02':'reference/non_native_diag02.py'}
    for key,name in libnames.items():need(pin(raw[key])==exactpin(members[name]),'original library member '+name)
    for key,n in [('library_common','COMMON'),('library_lifecycle','LIFECYCLE'),('library_late','LATE_SOURCE')]:
        need(pin(raw[key])==constants[n],'exact selected library source constant')
    old=retained['inventory_value'];before=v['full_inventory_before'];after=v['full_inventory_after']
    need(retained['retained_failed_staged_binding']==constants['RETAINED_R8_BINDING']==v['prior_retained_failed_staged_binding']
         ==host['retained_failed_staged_binding'],'actually consumed prior R8 proof')
    need(retained['retained_preaccept_binding']==v['prior_retained_preaccept_binding']==host['retained_preaccept_binding']
         ==manifest['retained_preaccept_binding'],'all original retained R7 bindings')
    need(inventory_value(old)==inventory_value(before)==inventory_value(after),'all old49 originals and full topology exactly preserved')
    need(len(old['roots'])==49 and v['prior_roots']==old['roots']
         and pin(enc(old))==retained['inventory']==v['prior_inventory'],'complete actually consumed old49 predecessor')
    need(len(before['entries'])==3991 and before['file_bytes_hashed']==53016728,'entire actual inventory cardinality and byte total')
    fixtures=[p for p in old['roots']if re.fullmatch('/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',p)]
    need(len(fixtures)==v['actual_fixture_root_count']==13<=14,'unchanged original fixture cap')
    life_pins={n:pin(function(raw['library_lifecycle'],n).encode())for n in ('fixture_absence','inventory')}
    need(v['unchanged_original_inventory_functions']==life_pins,'original complete scanner function bytes')
    # Every observed read descriptor is accounted for by one explicit actual source/read family.
    readset=v['readset'];expected={}
    def add(row):
        descriptor(row)
        need('metadata'in row,'every original read has actual full9')
        bare={k:row[k]for k in ('path','bytes','sha256','metadata')}
        if row['path']in expected:need(expected[row['path']]==bare,'overlapping exact read families agree')
        expected[row['path']]=bare
    for path,row in before['entries'].items():
        if row['kind']=='file':add({'path':path,**{k:row[k]for k in ('bytes','sha256','metadata')}})
    for path,row in readset.items():
        need(set(row)=={'path','bytes','sha256','metadata'}and row['path']==path,'exact readset row')
        descriptor(row)
    for name,row in members.items():
        path=SOURCE_HOME+'/package/'+name
        need(path in readset and exactpin(readset[path])==exactpin(row),'all38 source originals actually read')
        add(readset[path])
    manifest_path=SOURCE_HOME+'/package/MANIFEST.json'
    need(exactpin(readset[manifest_path])==constants['PACKAGE'],'original library manifest read');add(readset[manifest_path])
    for row in constants['KNOWN_PHONE_ORIGINALS']:add(row)
    need(len(constants['KNOWN_PHONE_ORIGINALS'])==20,'all20 fixed known original sources')
    for row in constants['RETAINED_R8_FILES'].values():add(row)
    r7archive=literal(raw['library_late'],'RETAINED_PREACCEPT_ARCHIVE')
    need(exactpin(readset[r7archive['path']])==exactpin(r7archive),'same exact old R7 archive read')
    add(readset[r7archive['path']])
    # Execute five original pure role functions, with only fully pinned in-memory reads.
    role_orig=v['role_source_originals'];rolesources=constants['ROLE_FUNCTIONS']
    need(set(rolesources)=={'literals','role_rows','roles_from_pinned_originals','parse_stat','matching_roles'}
         and v['unchanged_role_source_functions']=={n:pin(s.encode())for n,s in rolesources.items()},
         'all five original role functions exact')
    lib_by_path={SOURCE_HOME+'/package/'+name:raw[key]for key,name in libnames.items()}
    role_reads=[];role_bytes={}
    def original(path,expected_row=None,*,limit=1048576,include_raw=True):
        path=str(path);need(path in role_orig,'role reader exact original closure')
        row=role_orig[path];descriptor(row)
        b=blob(row,limit=limit)if'raw_base64'in row else lib_by_path.get(path)
        need(type(b)is bytes and len(b)<=limit and pin(b)==exactpin(row),'complete role source raw')
        need(('raw_base64'in row)is include_raw,'source raw retention matches original caller')
        if expected_row is not None:
            need(expected_row.get('path',path)==path and expected_row['sha256']==row['sha256']
                 and ('bytes'not in expected_row or expected_row['bytes']==row['bytes'])
                 and ('metadata'not in expected_row or expected_row['metadata']==row['metadata']),
                 'original role descriptor full9 and pin')
        role_reads.append(path);role_bytes[path]=b;return b
    ns={'ast':ast,'Path':Path,'re':re,'need':need,'strict':strict,'original':original,'BASE':Path(BASE),
        'HOME':Path(SOURCE_HOME),'PACKAGE':Path(SOURCE_HOME)/'package','LABEL':'root-r10-neg01-fc33-r8-bound01',
        'NONCE':'aa06c3b8d035dcd0c0047105f620b3bf','BOOT':BOOT,'LEASE_SHA256':constants['LEASE']['sha256'],
        'MANIFEST_PIN':constants['PACKAGE'],'LATE_PIN':constants['LATE_SOURCE'],'COMMON_PIN':constants['COMMON']}
    for name,body in rolesources.items():exec(compile(body,'<original-role-'+name+'>','exec'),ns)
    roles,chain=ns['roles_from_pinned_originals']()
    need(roles==v['historical_roles']and chain==v['native_boundary_descriptors']
         and len(roles)==42 and len(chain)==10 and len(role_reads)==len(set(role_reads))==20
         and set(role_reads)==set(role_orig),'entire original42 roles and20 source closure')
    family_counts={'retired':sum(r['family']=='original-retired-r9-r2'for r in roles),
                   'native':sum(r['family'].startswith('native:')for r in roles),
                   'nonnative':sum(r['family'].startswith('nonnative:')for r in roles),
                   'retained_R7':sum(r['family'].startswith('retained-r7:')for r in roles)}
    need(family_counts=={'retired':4,'native':30,'nonnative':6,'retained_R7':2},'actual roles, not the component cap')
    for row in role_orig.values():add(row)
    need(readset==expected and len(readset)==3661,'complete closed readset with no omitted or added original')
    # Preserve the leaf/ancestor distinction and complete parent inventories.
    targets=constants['TARGET_PATHS']
    need(len(targets)==10 and len(set(targets))==10,'ten unique exact failed operation paths')
    need(v['targets_before']==v['targets_after'],'all exact fixed paths stable across the whole observation')
    current_absence(v['targets_before'],targets)
    parents=v['parents_before']
    need(parents==v['parents_after']and len(parents)==3,'all complete parent bookends')
    expected_parents=[BASE+'/native-guard-r10-r1',
        '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1',
        '/proc/1/root/data/local/tmp']
    for row,path in zip(parents,expected_parents):
        need(set(row)=={'path','metadata','names','selinux_raw_base64'}and row['path']==path,'exact parent inventory')
        full9(row['metadata'],directory=True);named(row['names'])
        label=base64.b64decode(row['selinux_raw_base64'],validate=True)
        need(0<len(label)<=512 and label.endswith(b'\0'),'complete SELinux parent label')
    need(all(parents[0][k]==parents[1][k]for k in ('metadata','names','selinux_raw_base64'))
         and len(parents[0]['names'])==18 and len(parents[2]['names'])==898,'same GNU/Android parent and full fixture parent')
    for row in v['targets_before']:
        found=[p for p in parents if p['path']==row['parent_path']]
        if found:need(found[0]['metadata']==row['parent_metadata']and found[0]['names']==row['parent_names'],'absence parent joins complete parent inventory')
    # Replay every retained raw proc read in source order. There is no kill(0).
    procs=v['proc_originals'];need(type(procs)is list and len(procs)==1944,'all original proc reads')
    previous=stamp(v['began']);proc_bytes=0
    for row in procs:
        need(set(row)=={'path','bytes','sha256','raw_base64','observed'},'exact proc raw descriptor')
        b=blob(row,limit=1048576);proc_bytes+=len(b)
        now=stamp(row['observed']);need(previous<=now<=stamp(v['ended']),'proc original time range and order');previous=now
    at=0
    def proc(path,expected_row=None,*,limit=1048576):
        nonlocal at
        need(at<len(procs),'complete retained proc source-order sequence');row=procs[at];at+=1
        need(row['path']==path,'exact original proc read path/order')
        b=blob(row,limit=limit)
        if expected_row is not None:
            need({k:row[k]for k in ('path','bytes','sha256','raw_base64')}==expected_row,
                 'census or endpoint raw joins ordered proc originals')
        return b,row
    boot1,_=proc('/proc/sys/kernel/random/boot_id',limit=128);need(boot1==(BOOT+'\n').encode(),'original same boot')
    mount,_=proc('/proc/self/mountinfo')
    lines=[line.split()for line in mount.decode('ascii').splitlines()if len(line.split())>6 and line.split()[4]=='/proc']
    need(len(lines)==1 and ' - proc 'in' '.join(lines[0]),'original native proc mountinfo')
    domain,_=proc('/proc/1/attr/current',limit=256);need(domain.rstrip(b'\0\n')==b'u:r:init:s0','original init domain')
    native_ns={'require':need}
    exec(compile(function(raw['library_native_profile'],'parse_stat'),'<original-native-stat>','exec'),native_ns)
    initraw,_=proc('/proc/1/stat',limit=65536);init=native_ns['parse_stat'](initraw,1)
    need(init['start_ticks']==0 and init['state']!='Z','exact native init stat')
    observer=v['observer'];need(observer['pid']==v['native_proc_profile']['pid'],'original observer identity')
    ownraw,_=proc('/proc/%d/stat'%observer['pid'],limit=65536);own=native_ns['parse_stat'](ownraw,observer['pid'])
    need(own==v['native_proc_profile']and own['state']!='Z','full original observer stat')
    domain,_=proc('/proc/self/attr/current',limit=256)
    need(domain.rstrip(b'\0\n')==b'u:r:magisk:s0'and observer['domain']=='u:r:magisk:s0','ordinary observer Magisk domain')
    statusraw,_=proc('/proc/self/status',limit=65536);fields=dict(line.split(':',1)for line in statusraw.decode().splitlines()if':'in line)
    need(pin(statusraw)==observer['status']and list(map(int,fields['Uid'].split()))==[0]*4
         and list(map(int,fields['Gid'].split()))==[0]*4 and int(fields['NoNewPrivs'])==0,'original root observer status')
    need(full9(observer['gnu_anchor'],directory=True)[:2]!=full9(observer['android_anchor'],directory=True)[:2]
         and observer['exe']=='/usr/bin/python3','separate GNU/Android anchors and exact observer executable')
    censuses=v['role_censuses'];need(type(censuses)is list and len(censuses)==2,'two complete current role scans')
    stats=0;seen_current=[]
    for i,census in enumerate(censuses,1):
        need(census['index']==i and census['scan_complete']is True
             and census['read_errors']==[] and census['snapshot_atomic']is False
             and census['kernel_ESRCH_asserted']is False and census['historical_failed_offender_identified']is False,
             'current census preserves its observed limits and no kernel absence claim')
        times=ordered_stamps(v['began'],census['began'],census['scan_ended'],census['ended'],v['ended'])
        need(times[3]-times[1]<2*10**9,'original two second proc census bound')
        pids=census['pid_names_begin']
        need(type(pids)is list and pids==sorted(set(pids))and len(pids)<=4096
             and all(type(pid)is int and pid>0 for pid in pids)and pids==census['pid_names_end']
             and [row['pid']for row in census['rows']]==pids and len(pids)==965,
             'both complete original proc directory snapshots and all965 stat originals')
        predicate=[];ids={r['identity'][0]for r in roles};expectedids={r['identity'][0]:r['identity']for r in roles}
        last=stamp(census['began'])
        for row in census['rows']:
            need(set(row)=={'pid','observed','original','parsed','common_parsed','matches'},'exact census stat row')
            pid=row['pid'];b,procrow=proc('/proc/%d/stat'%pid,row['original'],limit=8192)
            independent=ns['parse_stat'](b,pid);current=cn['stat_identity'](b,pid,census=True)
            need(independent==row['parsed']and current==row['common_parsed']
                 and all(independent[k]==current[k]for k in ('pid','ppid','pgid','sid','start_ticks','state')),
                 'both original stat parsers over complete actual raw')
            need(row['matches']==ns['matching_roles'](independent,roles)==[],'exact original role-membership predicates')
            ordered_stamps(procrow['observed'],row['observed'],census['scan_ended'])
            now=stamp(row['observed']);need(last<=now,'source-order stat observation times');last=now
            if ((pid in expectedids and independent['identity']==expectedids[pid])or independent['pgid']in ids or independent['sid']in ids):predicate.append(pid)
            stats+=1
        need(census['original_predicate_matching_pids']==predicate==[] and census['matching_details']==[],
             'no omitted matching role details, including numeric group/session membership')
        endpoints=v['endpoints_before'if i==1 else'endpoints_after']
        need(set(endpoints)=={'tcp','tcp6','unix'},'all three endpoint originals')
        for name in ('tcp','tcp6','unix'):
            b,_=proc('/proc/net/'+name,endpoints[name],limit=1048576)
        seen_current.append({'index':i,'processes':len(pids),'read_errors':0,'matching_pids':[],
            'kernel_ESRCH_asserted':False,'duration_ns':times[3]-times[1]})
    boot2,_=proc('/proc/sys/kernel/random/boot_id',limit=128)
    need(boot2==boot1 and at==len(procs)and stats==1930,'entire ordered proc read closure and same boot end')
    # Independently reconstruct actual read accounting from the unchanged source's calls.
    totals={
      'library_manifest':pin(raw['library_manifest'])['bytes'],
      'library38_sources':sum(row['bytes']for row in members.values()),
      'known20_two_bookends':2*sum(row['bytes']for row in constants['KNOWN_PHONE_ORIGINALS']),
      'retained_R8_four_two_bookends':2*sum(row['bytes']for row in constants['RETAINED_R8_FILES'].values()),
      'retained_R8_reader_load':constants['RETAINED_R8_FILES']['verify_retained_staged_r8.py']['bytes'],
      'retained_proof_reads':constants['RETAINED_R8_FILES']['RETENTION-INPUTS.json']['bytes']
          +constants['RETAINED_R8_FILES']['ORIGINALS.zlib']['bytes']+r7archive['bytes'],
      'roles20_two_bookends':2*sum(row['bytes']for row in role_orig.values()),
      'two_complete_old49_inventories':before['file_bytes_hashed']+after['file_bytes_hashed'],
      'all_proc_original_reads':proc_bytes,
    }
    need(sum(totals.values())==v['budgeted_actual_read_bytes']==128345494<=LIMITS['shared_actual_read_bytes'],
         'all actual counted reads equal independently reconstructed bounded total')
    need(host['scoped_inference_under_retained_single_actor_source']['push_branch_not_reached']is True
         and host['scoped_inference_under_retained_single_actor_source']['root_copy_stage_sender_native_launch_not_reached']is True
         and host['baseline_device_shell_wire_dispatched']is None,'retain bounded host source inference without historical wire claim')
    summary={'schema':'hepta.r9.retained-first-push-scope-verification.v1',
      'state':'ACTUAL_SAME_BOOT_OLD49_AND_FAILED_R9_ABSENCE_VERIFIED_NO_GLOBAL_ZERO_EFFECT_CLAIM',
      'label':LABEL,'nonce':NONCE,'boot_id':BOOT,'actual_scope_job':JOB,'original_root_job':ORIGINAL_JOB,
      'outer_original':pin(raw['scope_outer']),'complete_phone_original':pin(scope_raw),
      'wrapper_original':outer['wrapper_original'],'source':pin(code),
      'previous_inventory':retained['inventory'],'inventory':pin(enc(after)),'inventory_root_count':49,
      'inventory_entries':3991,'inventory_files':sum(r['kind']=='file'for r in after['entries'].values()),
      'inventory_unique_file_bytes':after['file_bytes_hashed'],'complete_old49_preserved':True,
      'readset_count':len(readset),'readset':pin(enc(readset)),
      'role_source_count':20,'historical_roles':42,'actual_role_families':family_counts,
      'native_chain_originals':10,'proc_raw_originals':1944,'proc_stat_originals':1930,
      'proc_censuses':seen_current,'shared_elapsed_seconds':v['elapsed_seconds'],
      'actual_read_accounting':totals,'actual_read_bytes':sum(totals.values()),
      'current_absence_observations':{'boot_id':BOOT,'targets':v['targets_after']},
      'current_R9_private_roots':[],'current_R9_component_role_identities':{},
      'private_roots_and_roles_scope':'This one retained failed first-push actor/source and same-boot exact targets only.',
      'historical_failed_listener_identity':None,'historical_failed_route_callsite':None,
      'baseline_device_shell_wire_dispatched':None,'global_unknown_effect_count':None,'native_terminal':None,
      'kernel_ESRCH_asserted':False,'first_launch_receipt_gap':True,'original_start_reused':True,
      'native_case_credit':0,'component_qualified':False,'business_qualified':False,
      'replay_authorized':False,'new_nonce_authorized':False,'remote_cleanup_proven':False,'retirement_accepted':False}
    return {'summary':summary,'inventory_value':after,'inventory_roots':after['roots'],
      'current_absence_observations':summary['current_absence_observations'],
      'retained_preaccept_binding':retained['retained_preaccept_binding'],
      'retained_failed_staged_binding':retained['retained_failed_staged_binding'],
      'raw_originals':{'scope':scope_raw,'wrapper':wrapper_raw}}
