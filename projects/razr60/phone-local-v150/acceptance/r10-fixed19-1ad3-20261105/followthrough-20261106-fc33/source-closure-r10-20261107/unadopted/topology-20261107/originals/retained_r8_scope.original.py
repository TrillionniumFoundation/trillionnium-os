#!/usr/bin/env python3
"""Independent pure semantic checks of the exact complete failed R8 scope.

No observation or disposition is produced here. Every conclusion is bounded by
the actual captured bytes and the unchanged readers whose source pins match
the staged runtime. The earlier failure and global unknowns stay unchanged.
"""
import ast
import base64
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import stat
import types

LABEL='root-r10-neg01-fc33-r8-bound01'
NONCE='aa06c3b8d035dcd0c0047105f620b3bf'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
HOME=BASE+'/native-guard-r10-r1/'+LABEL
JOURNAL='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL+'/executor'
FIXTURE='/proc/1/root/data/local/tmp/hepta-native-guard-'+NONCE
CAPTURE={'bytes':13060990,'sha256':'634f27497d2e953c2d2b3dd7826e83d7ae9bd5236c23840f55abcf9ebbe2ff49'}
SOURCE={'bytes':29814,'sha256':'08634f66e5b0a1438de61bd499172991a9971466ecf2f5a8d66860cfbf8523b5'}
PACKAGE={'bytes':65655,'sha256':'654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}
LEASE={'bytes':2506,'sha256':'f05ee53a7609972c18f6bab2263008a4c3de3b49b12b8654df94790b25c30a44'}
OWNER='71a2d0f06fa7da2fa473a9caf30219744c169d0cd4fa204c2563925770d6e67a'
OLD={'bytes':1378036,'sha256':'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}
BEFORE={'bytes':1403290,'sha256':'d4229c821fb8de087e2636b48c6958658a92b5a15b92e256c04a255d9cf55c26'}
AFTER={'bytes':1403291,'sha256':'2008db913728ff0c3836cb6edb361e37f427d7663f2832163fe93b2adb18f432'}
STATE_LABEL=b'u:object_r:trillionnium_owner_open_state_file:s0\0'
JOURNAL_LABEL=b'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0\0'

def need(value,message):
    if not value:raise ValueError(message)

def pin(raw):
    need(type(raw)is bytes,'whole original bytes required')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def enc(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()

def strict(raw):
    need(type(raw)is bytes and len(raw)<=64*1024*1024,'bounded complete original JSON')
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate actual original field');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite original JSON'))

def literal(source,name):
    rows=[n for n in ast.parse(source).body if isinstance(n,ast.Assign)and len(n.targets)==1
         and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name]
    need(len(rows)==1,'one exact source literal: '+name)
    return ast.literal_eval(rows[0].value)

def source_function(source,name):
    rows=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name==name]
    need(len(rows)==1,'one exact original function: '+name)
    return rows[0]

def raw_value(row,maximum=1048576):
    need(type(row)is dict and type(row['path'])is str,'actual raw original descriptor')
    data=base64.b64decode(row['raw_base64'],validate=True)
    need(0<len(data)<=maximum and pin(data)=={k:row[k]for k in ('bytes','sha256')},'exact actual raw original pin')
    return data

def complete_private_files(value,stage_files,stage_complete_raw):
    before=value['full_inventory_before'];after=value['full_inventory_after']
    expected=dict(stage_files);expected[HOME+'/STAGE-COMPLETE.json']=stage_complete_raw
    rows=value['original_files'];need(set(rows)==set(expected)and len(rows)==63,'all63 actual new scope raw files required')
    for path,data in expected.items():
        row=rows[path]
        need(row['path']==path and raw_value(row,16*1024*1024)==data,'same actual stage raw member and full capture raw')
        desc={k:row[k]for k in ('path','bytes','sha256','metadata')}
        need(desc==value['readset'][path] and before['entries'][path]==after['entries'][path]
             =={'kind':'file','metadata':row['metadata'],**pin(data)},'both full inventories match each complete private raw file')
    need(sum(map(len,expected.values()))==3929058==value['retained_scope_raw_bytes'],'all private captured bytes accounted')
    return expected

def current_markers_and_parents(value,source,after,stage):
    markers=literal(source,'MARKERS')
    need(type(markers)is tuple and len(markers)==44 and len(set(markers))==44
         and {'READY.json','ACCEPTED.json','BOUND-CONTRACT.json'}<=set(markers),'complete true fixed lifecycle marker family')
    home=after['entries'][HOME]
    for side in ('before','after'):
        rows=value['markers_'+side]
        need([row['path']for row in rows]==[HOME+'/'+name for name in markers],'all44 actually named marker paths')
        for row in rows:
            need(set(row)=={'path','parent_metadata','state','errno','historical_execution_inferred'}
                 and row['state']=='CURRENT_EXPLICIT_ENOENT'and row['errno']==2
                 and row['historical_execution_inferred']is False
                 and row['parent_metadata']==home['metadata'] and row['path']not in after['entries']
                 and PurePosixPath(row['path']).name not in home['names'],'marker ENOENT binds held actual home parent')
    need(value['markers_before']==value['markers_after'],'all44 actual marker results and parent generations persist')
    parents=value['parents_before']
    expected_parents=[str(PurePosixPath(HOME).parent),str(PurePosixPath(JOURNAL).parent.parent),str(PurePosixPath(FIXTURE).parent)]
    need(parents==value['parents_after']and [row['path']for row in parents]==expected_parents,'all three canonical shared parent originals persist')
    for row in parents:
        need(set(row)=={'path','metadata','names','selinux_raw_base64'}and row['names']==sorted(set(row['names']))
             and type(row['metadata'])is list and len(row['metadata'])==9 and all(type(n)is int for n in row['metadata'])
             and stat.S_ISDIR(row['metadata'][2]),'complete shared directory full9/names/label')
    need(all(parents[0][k]==parents[1][k]for k in ('metadata','names','selinux_raw_base64'))
         and base64.b64decode(parents[0]['selinux_raw_base64'],validate=True)==STATE_LABEL
         and parents[0]['metadata'][3:5]==[0,0] and stat.S_IMODE(parents[0]['metadata'][2])==0o700,
         'GNU/Android shared-parent aliases preserve actual private directory and label')
    need(LABEL in parents[0]['names'] and PurePosixPath(FIXTURE).name not in parents[2]['names'],'actual home exists and exact fixture leaf is absent')
    scopes=value['scope_roots_before']
    need(scopes==value['scope_roots_after']and [row['path']for row in scopes]==[HOME,JOURNAL,FIXTURE],
         'both actual fixed scope existence observations agree')
    for path,row,parent in ((HOME,scopes[0],parents[0]['metadata']),(JOURNAL,scopes[1],home['metadata'])):
        need(row=={'path':path,'parent_metadata':parent,'state':'PRESENT','metadata':after['entries'][path]['metadata']},
             'existing scope root binds its complete retained full9 and canonical parent')
    need(scopes[2]=={'path':FIXTURE,'parent_metadata':parents[2]['metadata'],'state':'CURRENT_EXPLICIT_ENOENT',
         'errno':2,'historical_execution_inferred':False} and FIXTURE not in after['roots']
         and FIXTURE not in after['entries'],'R8 fixture is an explicit separate absent leaf, not an invented inventory root')
    labels=value['scope_labels_before']
    new_paths={path for path in after['entries']if path==HOME or path.startswith(HOME+'/')or path==JOURNAL}
    need(labels==value['scope_labels_after']and set(labels)==new_paths and len(labels)==73,'all73 actual private object labels persist')
    for path,row in labels.items():
        label=base64.b64decode(row['selinux_raw_base64'],validate=True)
        need(row['metadata']==after['entries'][path]['metadata']
             and label==(JOURNAL_LABEL if path in (HOME+'/executor',JOURNAL)else STATE_LABEL),
             'same-generation private state/executor label')
    layout=stage['journal_layout'];journal=layout['journal']
    need(journal['path']==JOURNAL and journal['metadata']==after['entries'][JOURNAL]['metadata']
         and bytes.fromhex(journal['selinux_raw_hex'])==JOURNAL_LABEL
         and journal['created_exclusive']is True and journal['label_fsynced_before_created_record']is True
         and layout['new_journal_label_writes']==1 and layout['existing_directory_label_writes']==layout['policy_changes']==0,
         'actual exclusive stage journal remains the same empty original object')
    shared=layout['shared_ancestors'][0]
    need(shared['before_metadata']==shared['after_metadata']==parents[0]['metadata']
         and bytes.fromhex(shared['selinux_raw_hex'])==STATE_LABEL and shared['labels_unchanged']is True,
         'shared canonical parent has not been replaced since actual stage')
    return {'named_current_absences':44,'private_labeled_objects':73,'retained_scope_roots':[HOME,JOURNAL],
        'separate_current_absent_fixture':scopes[2],'source_stage_journal_generation_preserved':True}

def endpoints(value,common,source_snapshot):
    function=source_function(source_snapshot,'endpoint_absence');receipts=[]
    for side in ('before','after'):
        rows=value['endpoints_'+side]
        need(set(rows)=={'tcp','tcp6','unix'},'complete three endpoint tables')
        data={}
        for name,path in (('tcp','/proc/net/tcp'),('tcp6','/proc/net/tcp6'),('unix','/proc/net/unix')):
            need(rows[name]['path']==path,'exact original kernel endpoint table name')
            data[name]=raw_value(rows[name])
        def bounded_proc(path):
            need(path in ('/proc/net/tcp','/proc/net/tcp6','/proc/net/unix'),'unchanged parser stays in actual table inputs')
            return data[path.rsplit('/',1)[1]]
        # This reader performs no clock observation. The parser's timestamp is
        # discarded; actual per-read clocks remain in proc_originals.
        ns={'C':common,'bounded_proc':bounded_proc,'time':types.SimpleNamespace(monotonic_ns=lambda:0)}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<unchanged actual endpoint parser>','exec'),ns)
        observed,verdict=ns['endpoint_absence']()
        need(observed==data and verdict=={'port_18080_listener_absent':True,'r6_abstract_endpoint_absent':True,
             'socket_connections':0,'observed_monotonic_ns':0},'same exact unchanged endpoint parser verdict')
        receipts.append({'position':side,'tables':{name:pin(data[name])for name in data},
            'port_18080_listener_absent':True,'r6_abstract_endpoint_absent':True,
            'derived_from_actual_raw_tables':True,'socket_connections_by_reader':0})
    return receipts

def native_profile_originals(value,files):
    rows=value['proc_originals'];need(type(rows)is list and 1<=len(rows)<=64,'bounded complete original pseudo-file reads')
    collected={}
    total=0
    for row in rows:
        raw=raw_value(row,1048576);total+=len(raw);collected.setdefault(row['path'],[]).append(raw)
        stamp=row['observed']
        need(type(stamp)is dict and set(stamp)=={'monotonic_ns','unix_ns'}
             and all(type(n)is int for n in stamp.values())
             and all(value['began'][k]<=stamp[k]<=value['ended'][k]for k in stamp),
             'actual pseudo-file read lies within whole-capture clocks')
    need(collected['/proc/sys/kernel/random/boot_id']==[(BOOT+'\n').encode()]*2,'same original boot on both capture sides')
    source=files[HOME+'/package/source/native_proc_profile.py']
    parser=source_function(source,'parse_stat')
    ns={'require':need};exec(compile(ast.Module(body=[parser],type_ignores=[]),'<unchanged native proc parser>','exec'),ns)
    init_rows=collected['/proc/1/stat'];need(len(init_rows)==1,'one original native-init stat')
    init=ns['parse_stat'](init_rows[0],1)
    need(init['start_ticks']==0 and init['state']!='Z' and collected['/proc/1/attr/current'][0].rstrip(b'\0\n')==b'u:r:init:s0',
         'actual native init stat/domain originals')
    observer=value['observer'];ownrows=collected['/proc/'+str(observer['pid'])+'/stat']
    need(len(ownrows)==1 and ns['parse_stat'](ownrows[0],observer['pid'])==value['native_proc_profile']
         and value['native_proc_profile']['state']!='Z','actual unchanged native observer stat profile')
    mounts=collected['/proc/self/mountinfo'];need(len(mounts)==1,'one native mountinfo original')
    lines=mounts[0].decode('ascii').splitlines()
    selected=[line.split()for line in lines if len(line.split())>6 and line.split()[4]=='/proc']
    need(len(selected)==1 and ' - proc 'in ' '.join(selected[0]),'one actual native procfs mount')
    status=collected['/proc/self/status'];domain=collected['/proc/self/attr/current']
    need(len(status)==len(domain)==1 and pin(status[0])==observer['status']
         and domain[0].rstrip(b'\0\n')==b'u:r:magisk:s0'and observer['domain']=='u:r:magisk:s0',
         'actual Root observer status/domain originals')
    fields=dict(line.split(':',1)for line in status[0].decode().splitlines()if ':'in line)
    need(list(map(int,fields['Uid'].split()))==list(map(int,fields['Gid'].split()))==[0]*4
         and int(fields['NoNewPrivs'])==0,'actual Root identity and no-new-privileges zero')
    need(observer['gnu_anchor'][:2]!=observer['android_anchor'][:2],'actual GNU and Android anchors remain distinct')
    for side in ('before','after'):
        for row in value['endpoints_'+side].values():
            raw=raw_value(row)
            need(raw in collected[row['path']],'each endpoint table is one of the actual retained pseudo-file reads')
    return total

def verify_complete_scope(capture_raw,source,stage_files,stage_complete_raw,prior,common,inventory_reader):
    need(pin(capture_raw)==CAPTURE and pin(source)==SOURCE,'complete actual capture and exact observer source')
    value=strict(capture_raw);need(enc(value)==capture_raw,'whole canonical original capture')
    need(value['schema']=='hepta.r8.staged-before-fork.scope-observation.v1'
         and value['state']=='COMPLETE_READ_ONLY_SCOPE_ORIGINALS_CAPTURED_NO_DISPOSITION'
         and value['label']==LABEL and value['nonce']==NONCE and value['boot_id']==BOOT
         and value['original_root_job']=='1a1b60cdf9b-12894-20e'
         and value['capture_source_sha256']==SOURCE['sha256']and 'error'not in value,'one complete error-free original scope capture')
    need(value['native_terminal']is None and value['global_unknown_effect_count']is None
         and all(value[k]is False for k in ('retirement_accepted','runtime_admission','original_failure_rewritten',
             'past_failure_offender_identified','automatic_retry'))
         and value['fixture_absence_is_not_zero_effect']is True,'observed absence cannot rewrite original unknowns or grant admission')
    need(all(type(value[k])is int and value[k]==0 for k in ('phone_file_writes','signals_including_signal_zero',
         'locks_acquired','sockets_opened','subprocesses_spawned','ui_actions','model_requests','native_submissions',
         'new_nonces','native_case_credit')),'original complete scope observation stayed read-only')
    need(value['limits']=={'shared_seconds':30,'shared_actual_read_bytes':201326592,'inventory_entries':30000,
         'inventory_unique_file_bytes':536870912,'inventory_file_bytes':67108864,'original_fixture_cap':14,
         'scope_entries':512,'scope_raw_bytes':16777216,'result_bytes':67108864,'compressed_bytes':8388608},
         'same original stricter shared observation budget')
    need(0<=value['elapsed_seconds']<30 and math.isfinite(value['elapsed_seconds'])
         and 0<value['ended']['monotonic_ns']-value['began']['monotonic_ns']<30_000_000_000
         and value['ended']['unix_ns']>=value['began']['unix_ns'],'complete actual capture stayed within original30 seconds')
    files=complete_private_files(value,stage_files,stage_complete_raw)
    manifest=strict(files[HOME+'/package/MANIFEST.json'])
    need(pin(files[HOME+'/package/MANIFEST.json'])==PACKAGE and len(manifest['files'])==38
         and len({row['path']for row in manifest['files']})==38,'same full actual package38')
    for row in manifest['files']:
        path=HOME+'/package/'+row['path']
        need(pin(files[path])=={k:row[k]for k in ('bytes','sha256')},'every actual frozen runtime member preserved')
    lease_raw=files[HOME+'/LEASE.json'];lease=strict(lease_raw)
    need(pin(lease_raw)==LEASE and value['lease']['descriptor']==LEASE and value['lease']['value']==lease
         and value['lease']['expired_at_observation']is True
         and value['began']['unix_ns']//1000000>lease['expires_unix_ms'],
         'same original lease remains expired, without extension')
    need((lease['label'],lease['nonce'],lease['boot_id'],lease['case_id'])==(LABEL,NONCE,BOOT,'NEG-01')
         and lease['package_sha256']==PACKAGE['sha256']and lease['owner_request_sha256']==OWNER
         and pin(files[HOME+'/owner-request.txt'])['sha256']==OWNER
         and files[HOME+'/owner-request.txt'].count(NONCE.encode())==1,'same exact consumed original identity')
    old=prior['inventory_value'];before=value['full_inventory_before'];after=value['full_inventory_after']
    need(pin(enc(old))==OLD==prior['inventory']==value['prior_inventory']
         and value['prior_retained_binding']==prior['retained_preaccept_binding']==manifest['retained_preaccept_binding'],
         'same independently verified accepted R7 old47 predecessor')
    need(inventory_reader(before)==inventory_reader(after)and pin(enc(before))==BEFORE and pin(enc(after))==AFTER,
         'both complete49 original inventories agree except original elapsed')
    need(value['prior_roots']==old['roots']and after['roots']==old['roots']+[HOME,JOURNAL]
         and value['actual_scope_roots']==[HOME,JOURNAL]and value['actual_root_count']==49
         and len(after['entries'])==3991 and after['file_bytes_hashed']==53016728,
         'actual49 roots and complete3991-entry inventory')
    need(all(after['entries'].get(path)==row for path,row in old['entries'].items()),'all3918 old47 original entries remain exact')
    for path in after['entries']:
        if any(Path(path)==Path(root)or Path(root)in Path(path).parents for root in old['roots']):
            need(path in old['entries'],'no new child added below any old retained root')
    fixtures=[root for root in after['roots']if re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',root)]
    need(len(fixtures)==value['actual_fixture_root_count']==13 and FIXTURE not in fixtures,'actual fixture root count remains13')
    need(all(value[k]is True for k in ('complete_old47_preserved','full_inventory_entries_equal',
        'all_scope_raw_files_match_both_complete_inventories')),'actual full-read bookends all completed')
    stage=strict(stage_complete_raw)
    need(stage['lease_sha256']==LEASE['sha256']and stage['package_sha256']==PACKAGE['sha256']
         and stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES','actual complete staging belongs to this failed runtime and lease')
    private=current_markers_and_parents(value,source,after,stage)
    for path in (HOME+'/claims',HOME+'/operator',HOME+'/executor',JOURNAL):
        need(after['entries'][path]['kind']=='directory'and after['entries'][path]['names']==[],'all current claims/operator/executor namespaces are empty')
    need(after['entries'][HOME+'/executor']==after['entries'][JOURNAL],'both executor aliases identify one unchanged empty directory')
    need(all(PurePosixPath(path).name!='lock'and not PurePosixPath(path).name.endswith('.lock')
         for path in value['original_files']),'no new scope lock inode appears')
    function_pins={}
    life=files[HOME+'/package/source/component_lifecycle.py'].decode()
    for name in ('fixture_absence','inventory'):
        function_pins[name]=pin((ast.get_source_segment(life,source_function(life,name))+'\n').encode())
    need(value['unchanged_original_inventory_functions']==function_pins,'complete inventory source functions remain the exact originals')
    endpoint_receipts=endpoints(value,common,files[HOME+'/package/source/component_snapshot.py'])
    proc_bytes=native_profile_originals(value,files)
    known=literal(source,'KNOWN_PHONE_ORIGINALS')
    need(len(known)==20 and all(value['readset'][row['path']]=={k:row[k]for k in ('path','bytes','sha256','metadata')}for row in known),
         'all20 earlier role-source originals persist with complete full9')
    # The source's two complete inventories hash aliases exactly as originally
    # counted; every other successful source read is accounted in this formula.
    read_bytes=PACKAGE['bytes']+sum(row['bytes']for row in manifest['files'])+2*sum(row['bytes']for row in known)
    read_bytes+=LEASE['bytes']+len(files[HOME+'/owner-request.txt'])+2*(3000200+413)
    read_bytes+=before['file_bytes_hashed']+after['file_bytes_hashed']+proc_bytes
    need(read_bytes==value['budgeted_actual_read_bytes']==119134962<=201326592,'shared actual read budget independently accounted')
    return value,lease,files,{'schema':'hepta.r8.complete-scope.pure-replay.v1','capture':CAPTURE,'observer_source':SOURCE,
        'inventory':AFTER,'root_count':49,'entry_count':3991,'file_bytes_hashed':53016728,'old47_entries_preserved':3918,
        'new_private_file_count':63,'new_private_bytes':3929058,'actual_fixture_root_count':13,
        'unchanged_inventory_functions':function_pins,'current_endpoints':endpoint_receipts,**private,
        'budgeted_actual_read_bytes':read_bytes,'retirement_accepted':False,'runtime_admission':False,
        'native_case_credit':0,'past_failure_offender_identified':False,'global_unknown_effect_count':None}
