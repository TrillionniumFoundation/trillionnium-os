#!/usr/bin/env python3
"""P4 host-only complete private receiver; no phone, signal, or subprocess."""
from pathlib import Path
import argparse,ast,base64,hashlib,io,json,os,re,shlex,stat,tarfile,zlib
SOURCE_BYTES = 69722
SOURCE_SHA = 'a539c674dc1bb9041e7381b807baabcab38f7705fe24277b052ecc78ee5d2759'
REQUEST_BYTES = 25892
REQUEST_SHA = '2a2035002f678589890259339be8f3242c3f14bbe58fdd58f2bb997b9789ae77'
INPUTS_BYTES = 36390
INPUTS_SHA = '9f208e160b9f11de65e758b8f060991a2ea64427d50e851ea1a7b1522e13d11d'
ACTOR_LABEL = 'ng-fc33-neg01-bound02-unstarted-readonly01'

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def enc(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(rows):
        d={}
        for k,v in rows:
            need(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def full9(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

def read_exact(path,size,digest):
    need(path.resolve(strict=True)==path,'canonical host original path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==size,'host original regular file size')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(size+1)
        need(len(raw)==size and sha(raw)==digest and full9(a)==full9(os.fstat(fd))==full9(path.lstat()),'host original bytes/full9 changed')
        return raw,{'path':str(path),'bytes':size,'sha256':digest,'metadata':full9(a)}
    finally:os.close(fd)

def decode_zlib(encoded_raw,expected_size,expected_sha,limit):
    need(len(encoded_raw)<=limit,'compressed input bound')
    z=zlib.decompressobj();raw=z.decompress(encoded_raw,expected_size+1)
    need(z.eof and not z.unused_data and not z.unconsumed_tail and len(raw)==expected_size and sha(raw)==expected_sha,'complete exact zlib stream')
    return raw

def write_new(root,name,raw):
    p=root/name
    need(p.parent==root or root in p.parents,'host output namespace')
    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as s:s.write(raw);s.flush();os.fsync(s.fileno())
    return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}

def check_metadata_row(row):
    m=row.get('metadata')
    need(type(m) is list and len(m)==9 and all(type(v) is int and v>=0 for v in m),'actual full9 shape')

def tree_complete(observed,blobs):
    roots=observed['roots'];rows=observed['entries'];total=0
    need(len(roots)==len(set(roots)) and type(rows) is dict,'tree roots/rows')
    for path,row in rows.items():
        need(row['path']==path and sum(path==r or path.startswith(r+'/') for r in roots)==1,'tree exact lexical root')
        if row['kind']=='absent':
            need(path in roots and row['absence']=='ENOENT' and row['no_effect_inferred'] is False,'exact root absence only')
            continue
        check_metadata_row(row)
        if row['kind']=='directory':
            names=sorted(p.rsplit('/',1)[-1] for p in rows if p.rsplit('/',1)[0]==path)
            need(row['names']==names and len(names)==len(set(names)),'complete directory children')
        else:
            need(row['kind']=='file' and row['metadata'][6]==row['bytes'],'regular file size row')
            total+=row['bytes']
            if blobs is not None:
                need(row['sha256'] in blobs and len(blobs[row['sha256']])==row['bytes'],'every private byte preserved')
    need(total==observed['file_bytes_hashed'],'tree byte accounting')

"""Independent host receiver for the frozen bound02 read-only packet."""

def projection(observed):
    return {'roots':observed['roots'],'entries':{p:({k:v for k,v in r.items() if k!='observed_monotonic_ns'} if r['kind']=='absent' else r) for p,r in observed['entries'].items()},'file_bytes_hashed':observed['file_bytes_hashed']}

def legacy_rows(observed):
    answer={}
    for path,row in observed['entries'].items():
        if row['kind']=='absent':answer[path]={'kind':'absent','absence':'ENOENT'}
        elif row['kind']=='directory':answer[path]={k:row[k] for k in ('kind','metadata','names')}
        else:answer[path]={k:row[k] for k in ('kind','metadata','bytes','sha256')}
    return answer

def regular_row(row,blobs=None,expected=None,owner=None):
    check_metadata_row(row);m=row['metadata']
    need(row['kind']=='file' and stat.S_ISREG(m[2]) and m[5]==1 and type(row['bytes']) is int and row['bytes']==m[6] and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact regular file descriptor')
    need(type(row['path']) is str and Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts and base64.b64decode(row['selinux_raw_b64'],validate=True),'absolute full file/label descriptor')
    if owner is not None:need(m[3:5]==owner[:2] and stat.S_IMODE(m[2]) in owner[2],'actual file owner/mode')
    if expected is not None:
        for k in ('path','bytes','sha256','metadata','selinux_raw_b64'):
            if k in expected:need(row[k]==expected[k],'actual file exact pin '+k)
    if blobs is not None:need(row['sha256'] in blobs and len(blobs[row['sha256']])==row['bytes'],'complete preserved file body')

def directory_row(row):
    check_metadata_row(row);m=row['metadata']
    need(stat.S_ISDIR(m[2]) and type(row['names']) is list and row['names']==sorted(set(row['names'])) and all(type(n) is str and n not in ('','.','..') and '/' not in n and '\0' not in n for n in row['names']),'complete directory type/member grammar')
    need(base64.b64decode(row['selinux_raw_b64'],validate=True),'complete directory label original')

def independent_archive(raw,inputs):
    decoder=zlib.decompressobj(31);plain=decoder.decompress(raw,16*1024*1024+1)
    need(len(plain)<=16*1024*1024 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'exact bounded original gzip tar')
    files={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for row in archive:
            p=Path(row.name);need(str(p)==row.name and not p.is_absolute() and '..' not in p.parts and '\\' not in row.name and '\0' not in row.name and row.name not in files and row.isreg() and not row.pax_headers and row.uid==row.gid==row.mtime==0 and row.mode==0o600 and 0<=row.size<=8*1024*1024,'canonical original tar member')
            stream=archive.extractfile(row);need(stream is not None,'complete archive original');b=stream.read(row.size+1);need(len(b)==row.size,'complete archive member');files[row.name]=b
    need(len(files)==62 and sum(map(len,files.values()))<=8*1024*1024,'exact62 archive bounds')
    canonical=io.BytesIO()
    with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,b in sorted(files.items()):
            row=tarfile.TarInfo(name);row.mode=0o600;row.uid=row.gid=row.mtime=0;row.size=len(b);archive.addfile(row,io.BytesIO(b))
    need(plain==canonical.getvalue(),'original tar entire canonical byte identity')
    need([{'relative_path':n,'bytes':len(b),'sha256':sha(b)} for n,b in sorted(files.items())]==inputs['archive_members'],'all62 actual source member pins')
    manifest=strict(files['package/MANIFEST.json']);lease=strict(files['LEASE.json']);reviewed=strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json'])
    need(sha(files['package/MANIFEST.json'])==inputs['package_sha256'] and manifest['files']==inputs['runtime_files'] and len(manifest['files'])==38 and sha(files['LEASE.json'])==inputs['lease_sha256'] and lease==inputs['lease'],'exact actual38 package and lease')
    expected={'LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json','inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json','inputs/service-inputs.original.json','inputs/PRIOR-BOUNDARY.original.json'}
    expected.update('package/'+r['path'] for r in manifest['files']);need(len(reviewed)==15,'exact production15');expected.update('inputs/production/'+n for n in reviewed);need(set(files)==expected,'exact staged source namespace')
    for row in manifest['files']:need(len(files['package/'+row['path']])==row['bytes'] and sha(files['package/'+row['path']])==row['sha256'],'runtime member full bytes')
    for name,h in reviewed.items():need(re.fullmatch(r'[a-z_]+\.py',name) and sha(files['inputs/production/'+name])==h,'production member full bytes')
    return files

def validate_bound02(value,inputs,blobs):
    scope={'label':inputs['label'],'nonce':inputs['nonce'],'lease_sha256':inputs['lease_sha256'],'runtime_sha256':inputs['package_sha256'],'boot_id':inputs['lease']['boot_id']}
    need(value['scope']==scope and value['inputs_sha256']==INPUTS_SHA,'exact actual unstarted scope and inputs')
    for key in ('file_writes','file_deletes','signals_to_other_processes','ui_calls','model_requests','native_dispatches','endpoint_connections','target_programs_imported_or_executed'):
        need(type(value[key]) is int and value[key]==0,'readonly exact effect counter '+key)
    for key in ('process_liveness_measured','role_generation_invented','scope_closure','deletion_authorized','component_qualified','business_qualified','automatic_retry'):need(value[key] is False,'no inferred authority '+key)
    need(value['historical_native_effect_count_inferred'] is None and value['private_request_and_XML_original_bodies_do_not_publish'] is True,'unknown historical effects retained')
    baseline_raw=blobs[inputs['baseline']['sha256']];baseline=strict(baseline_raw)
    need(len(baseline_raw)==inputs['baseline']['bytes'] and baseline['schema']=='hepta.native-guard.complete-inventory.v1' and baseline['roots']==inputs['baseline_roots'] and len(baseline['roots'])==44 and len(baseline['entries'])==3823 and baseline['file_bytes_hashed']==44353573,'actual unchanged44 source inventory')
    regular_row(value['baseline_original'],blobs,inputs['baseline'],[0,0,[0o600]]);regular_row(value['boundary_original'],blobs,inputs['boundary'],[0,0,[0o600]])
    boundary=strict(blobs[inputs['boundary']['sha256']]);need(len(blobs[inputs['boundary']['sha256']])==inputs['boundary']['bytes'] and inputs['lease']['prior_boundary']==inputs['boundary'],'actual prior-boundary bytes')
    identity=value['collector_identity'];need(identity['boot_id']==scope['boot_id'] and base64.b64decode(identity['domain_raw_b64'],validate=True).rstrip(b'\0\n')==b'u:r:magisk:s0','actual collector root domain/boot')
    original=identity['init_stat_original'];raw=base64.b64decode(original['base64'],validate=True);need(len(raw)==original['bytes'] and sha(raw)==original['sha256'],'actual complete init stat')
    head,tail=raw.rsplit(b') ',1);parts=tail.split();parsed={'pid':1,'state':parts[0].decode(),'ppid':int(parts[1]),'pgid':int(parts[2]),'sid':int(parts[3]),'start_ticks':int(parts[19])}
    need(head.startswith(b'1 (') and parsed==identity['init'] and parsed['start_ticks']==0 and identity['gnu_root_metadata'][:2]!=identity['android_root_metadata'][:2],'native init identity and distinct anchor')
    expected_locks={p:r for p,r in baseline['entries'].items() if r['kind']=='file' and (p.rsplit('/',1)[-1]=='lock' or p.endswith('.lock'))};locks=value['locks']
    need(len(expected_locks)==26 and len({tuple(r['metadata'][:2]) for r in expected_locks.values()})==14 and locks['alias_count']==26 and locks['inode_group_count']==14 and len(locks['aliases'])==26 and len({r['path'] for r in locks['aliases']})==26 and {r['path'] for r in locks['aliases']}==set(expected_locks),'exact original26 lock aliases/14 inode groups')
    for row in locks['aliases']:regular_row(row,expected=expected_locks[row['path']],owner=[0,0,[0o600]])
    need(locks['lock_files_created']==0 and locks['held_through_both_windows'] is True and locks['lock_mode']=='LOCK_EX|LOCK_NB on existing O_RDONLY descriptors','actual readonly held-lock contract')
    windows=value['windows'];need(len(windows)==2 and [w['index'] for w in windows]==[0,1],'two complete current windows')
    home=inputs['phone_home'];android=inputs['android_home'];journal=android+'/executor';fixture=inputs['fixture']
    def canonical(p):return home+p[len(android):] if p==android or p.startswith(android+'/') else p
    all_digests={inputs['baseline']['sha256'],inputs['boundary']['sha256']};targets=None;directories=None;complete_stage=None
    for window in windows:
        need(type(window['started_monotonic_ns']) is int and window['finished_monotonic_ns']>=window['started_monotonic_ns'],'actual window measurement order')
        for field in ('parents_before','parents_after'):
            rows=window[field];need(len(rows)==5 and [r['path'] for r in rows]==inputs['parent_paths'],'same exact five parent aliases')
            for row in rows:directory_row(row)
            need({k:rows[0][k] for k in ('metadata','names','selinux_raw_b64')}=={k:rows[1][k] for k in ('metadata','names','selinux_raw_b64')} and inputs['label'] in rows[0]['names'],'actual shared parent alias equality')
        need(window['parents_before']==window['parents_after'],'complete five-parent within-window bookend')
        aliases=window['home_aliases_before'];need([r['path'] for r in aliases]==[home,android] and aliases==window['home_aliases_after'],'two complete home aliases/bookend')
        for row in aliases:directory_row(row)
        need({k:aliases[0][k] for k in ('metadata','names','selinux_raw_b64')}=={k:aliases[1][k] for k in ('metadata','names','selinux_raw_b64')},'same inode/full9/label/home members')
        need(len(window['transport'])==4 and len(window['xml'])==11,'exact4transport11XML observation count')
        for row,pin in zip(window['transport'],inputs['transport']):regular_row(row,blobs,pin,pin['owner']);all_digests.add(row['sha256'])
        for row,pin in zip(window['xml'],inputs['sender_xml']):regular_row(row,blobs,pin,[2000,2000,[0o666]]);all_digests.add(row['sha256'])
        archive=next(r for r in window['transport'] if r['path']==inputs['archive_path']);files=independent_archive(blobs[archive['sha256']],inputs)
        observed=window['baseline'];tree_complete(observed,None)
        need(observed['roots']==baseline['roots'] and legacy_rows(observed)==baseline['entries'] and observed['file_bytes_hashed']==baseline['file_bytes_hashed'],'all44 actual file/full9/names rows independently equal original')
        private=window['private'];tree_complete(private,blobs);need(private['roots']==[home,journal,fixture],'exact private three-root readset')
        canonical_rows={};aliasmap={}
        for path,row in private['entries'].items():
            if path==fixture:continue
            p=canonical(path);need(p==home or p.startswith(home+'/'),'private scope canonical boundary')
            body={k:v for k,v in row.items() if k!='path'}
            if p in canonical_rows:need(canonical_rows[p]==body,'current canonical aliases preserve all fields')
            canonical_rows[p]=body;aliasmap.setdefault(p,[]).append(path)
            if row['kind']=='file':regular_row(row,blobs,owner=[0,0,[0o600]]);all_digests.add(row['sha256'])
            else:directory_row(row);need(row['metadata'][3:5]==[0,0] and stat.S_IMODE(row['metadata'][2])==0o700,'private directory owner/mode')
        file_rows={p:dict(path=p,**r) for p,r in canonical_rows.items() if r['kind']=='file'};dir_rows={p:dict(path=p,**r) for p,r in canonical_rows.items() if r['kind']=='directory'}
        need(set(file_rows)=={home+'/'+name for name in files}|{home+'/STAGE-COMPLETE.json'} and len(file_rows)==63 and set(dir_rows)==set(inputs['expected_directories']) and len(dir_rows)==9,'exact63 files/9 unique directories no undeclared lifecycle/native records')
        members=[]
        for name,raw in sorted(files.items()):
            row=file_rows[home+'/'+name];need(blobs[row['sha256']]==raw and row['bytes']==len(raw),'all62 current originals equal whole archive')
            members.append({'relative_path':name,'path':row['path'],'bytes':len(raw),'sha256':sha(raw),'metadata':row['metadata']})
        stage_row=file_rows[home+'/STAGE-COMPLETE.json'];regular_row(stage_row,blobs,inputs['stage_complete'],[0,0,[0o600]]);stage=strict(blobs[stage_row['sha256']]);complete_stage=stage
        need(stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES' and stage['members']==62 and stage['lease_sha256']==inputs['lease_sha256'] and stage['package_sha256']==inputs['package_sha256'] and stage['archive_sha256']==archive['sha256'] and stage['created_directories']==inputs['stage_directory_identity'] and stage['service_launches']==stage['model_requests']==stage['native_tasks']==0,'actual original stage record exact identities')
        for created in stage['created_directories']:
            row=dir_rows[canonical(created['path'])];need(row['metadata'][:5]==created['metadata'][:5],'originally created private directory first5 identity')
            if created['selinux'] is not None:need(base64.b64decode(row['selinux_raw_b64'],validate=True).rstrip(b'\0').decode()==created['selinux'],'original explicit private label')
        for name in ('claims','operator','executor'):need(dir_rows[home+'/'+name]['names']==[],'no entries in '+name)
        absence=private['entries'][fixture];tmp=window['parents_after'][-1];need(absence['kind']=='absent' and absence['absence']=='ENOENT' and absence['no_effect_inferred'] is False and absence['parent_metadata']==tmp['metadata'] and absence['parent_selinux_raw_b64']==tmp['selinux_raw_b64'],'exact fixture ENOENT under same complete XML parent profile')
        # Canonical JSON sorts object keys; the producer accumulated aliases
        # in its declared root order, so derive that list order independently.
        for names in aliasmap.values():names.sort(key=lambda p:next(i for i,r in enumerate(private['roots']) if p==r or p.startswith(r+'/')))
        expected_summary={'archive_member_count':62,'runtime_file_count':38,'current_home_file_count':63,'unique_private_directory_count':9,'all_current_archive_bytes_exact':True,'all_runtime_bytes_exact':True,'members':members,'canonical_aliases':aliasmap,'claims_operator_executor_empty':True,'original_lease_expired':True,'process_liveness_measured':False,'role_generation_invented':False}
        need(window['stage_members']==expected_summary,'independent exact current-scope summary')
        need(window['pinned_input_bookends']==[value['baseline_original'],value['boundary_original']],'full actual baseline/boundary reread identities')
        current_targets=file_rows|{r['path']:r for r in window['transport']+window['xml']};need(len(current_targets)==78,'exact78 unique file targets observed, no deletion authority')
        if targets is not None:need(targets==current_targets and directories==dir_rows,'same current file/directory identities in both windows')
        targets=current_targets;directories=dir_rows
    first,second=windows;need(first['finished_monotonic_ns']<=second['started_monotonic_ns'],'ordered separate observation windows')
    for field in ('parents_before','parents_after','home_aliases_before','home_aliases_after','transport','xml','stage_members','pinned_input_bookends'):need(first[field]==second[field],'exact two-window identity '+field)
    need(projection(first['baseline'])==projection(second['baseline']) and projection(first['private'])==projection(second['private']),'all private and original44 bookends exact')
    need(set(blobs)==all_digests and value['preserved_unique_original_bytes']==sum(map(len,blobs.values()))<=16*1024*1024,'all and only bounded required private original blobs')
    resources=value['resources'];need(resources['closed_lock_descriptors']==14 and resources['close_errors']==[] and resources['initial_fd_names']==resources['final_fd_names'],'all14 locks closed/actual FD baseline restored')
    minimum=2*(44353573+first['private']['file_bytes_hashed']+sum(r['bytes'] for r in first['transport']+first['xml']))+3*(inputs['baseline']['bytes']+inputs['boundary']['bytes'])+sum(r['bytes'] for r in locks['aliases'])
    need(type(value['read_bytes']) is int and minimum<=value['read_bytes']<=160*1024*1024,'complete two-window read byte accounting')
    return {'original44_full_inventory_equal':True,'original44_roots':44,'original44_entries':3823,'baseline_file_bytes_per_window':44353573,'runtime_files':38,'archive_members':62,'private_home_files':63,'unique_private_directories':9,'transport_files':4,'sender_xml_files':11,'exact_owned_file_count':78,'exact_file_bytes':sum(r['bytes'] for r in targets.values()),'lock_aliases':26,'lock_inode_groups':14,'window_count':2,'claims_operator_executor_empty':True,'fixture_absent_same_complete_parent':True,'actual_FD_baseline_restored':True,'original_lease_unchanged':True,'lease_expiry_observed_by_pinned_producer_not_extended':True,'role_generation_invented':False,'current_role_liveness_measured':False,'scope_closure':False,'case_credit':False}, {'files':[targets[p] for p in sorted(targets)],'directories':[directories[p] for p in sorted(directories,key=lambda p:(-p.count('/'),p))],'surviving_parents':first['parents_after'],'home_aliases':first['home_aliases_after'],'fixture_absence':first['private']['entries'][fixture],'original44_baseline':inputs['baseline'],'source_lease_sha256':inputs['lease_sha256'],'source_package_sha256':inputs['package_sha256'],'phone_label':inputs['label'],'nonce':inputs['nonce'],'scope_closure':False,'deletion_authorized':False}

def read_unpinned(path,maximum):
    need(path.resolve(strict=True)==path,'canonical operation original path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==1000 and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=maximum,'actual private operation original bounds')
        with os.fdopen(fd,'rb',closefd=False) as stream:body=stream.read(maximum+1)
        need(len(body)==before.st_size and full9(before)==full9(os.fstat(fd))==full9(path.lstat()),'actual operation full read bookend')
    finally:os.close(fd)
    return read_exact(path,len(body),sha(body))

def receiver_main():
    parser=argparse.ArgumentParser();parser.add_argument('--result',required=True);parser.add_argument('--bytes',type=int,required=True);parser.add_argument('--sha256',required=True);parser.add_argument('--version',required=True);parser.add_argument('--out',required=True);args=parser.parse_args()
    path=Path(args.result);need(path==Path('/home/alex/razr60-local-model-v150/operations')/ACTOR_LABEL/'result.json' and 0<args.bytes<=12*1024*1024 and re.fullmatch('[0-9a-f]{64}',args.sha256),'one existing bounded actual operation result')
    raw,result_descriptor=read_exact(path,args.bytes,args.sha256);m=result_descriptor['metadata']
    need(':'.join(str(m[i]) for i in (0,1,6,7,8))==args.version and m[3:6]==[1000,1000,1] and stat.S_IMODE(m[2])==0o600,'actual root observed result version/ownership')
    operation=strict(raw)
    actor_raw,actor_descriptor=read_exact(Path('/home/alex/razr60-local-model-v150/ops/phone_once.py'),5652,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22')
    request_raw,request_descriptor=read_exact(Path('/home/alex/razr60-local-model-v150/requests')/(ACTOR_LABEL+'.json'),REQUEST_BYTES,REQUEST_SHA);request=strict(request_raw)
    need(set(request)=={'kind','root','command','timeout_seconds'} and request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==70,'frozen exact actual shell request')
    need(operation['schema']=='hepta.phone-local.operator-result.v150.1' and operation['label']==ACTOR_LABEL and operation['status']=='command_exited' and operation['model_decision'] is False and operation['native_task_result'] is False,'actual actor terminal schema')
    need(operation['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),'exact original actor root=true transformation')
    inner=shlex.split(request['command']);need(inner[-5:-1]==['/usr/bin/python3','-I','-B','-c'] and inner[0]=='/data/adb/magisk/busybox' and '/debug_ramdisk/su' not in inner,'one root wrapper and reviewed GNU route')
    loader=ast.parse(inner[-1]);assign=next(n for n in loader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='c' for t in n.targets));compressed=base64.b64decode(ast.literal_eval(assign.value.args[0]),validate=True)
    source=decode_zlib(compressed,SOURCE_BYTES,SOURCE_SHA,65535);source_tree=ast.parse(source)
    assignment=next(n for n in source_tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='INPUTS_RAW' for t in n.targets));inputs_raw=ast.literal_eval(assignment.value)
    need(len(inputs_raw)==INPUTS_BYTES and sha(inputs_raw)==INPUTS_SHA,'frozen exact actual source/input bytes');inputs=strict(inputs_raw)
    host_inputs_raw,host_inputs_descriptor=read_exact(Path('/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/INPUTS.json'),INPUTS_BYTES,INPUTS_SHA);need(host_inputs_raw==inputs_raw,'published host/source input full bytes')
    originals={n:read_unpinned(path.parent/n,1048576) for n in ('intent.json','baseline.json')}
    intent=strict(originals['intent.json'][0]);baseline=strict(originals['baseline.json'][0])
    need(intent['schema']=='hepta.phone-local.operator-intent.v150.1' and intent['label']==ACTOR_LABEL and intent['request']==request and intent['request_sha256']==sha(request_raw) and intent['automatic_replay'] is False,'same actual request and intent')
    need(baseline['rc']==0 and baseline['stdout'].splitlines()==[inputs['lease']['boot_id'],'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'] and baseline['route']==operation['phone']['route']==[5037,'23'],'actual actor baseline original and same configured transport')
    stdout=operation['phone']['stdout'].encode();need(len(stdout)<=8*1024*1024,'unchanged8MiB stdout cap');envelope=strict(stdout)
    need(envelope['schema']=='hepta.fc33.bound02.unstarted-readonly.packet.v1' and envelope['private_originals'] is True and envelope['qualification_granted'] is False,'complete readonly packet envelope')
    frame=envelope['packet'];need(type(frame['bytes']) is int and 0<frame['bytes']<=32*1024*1024 and frame['encoding']=='zlib-base64','bounded original packet length');compressed=base64.b64decode(frame['base64'],validate=True)
    need(len(compressed)==frame['compressed_bytes'] and sha(compressed)==frame['compressed_sha256'],'full compressed packet descriptor');packet_raw=decode_zlib(compressed,frame['bytes'],frame['sha256'],8*1024*1024);value=strict(packet_raw);need(enc(value)==packet_raw and value['schema']=='hepta.fc33.bound02.unstarted-readonly.v1','canonical complete packet original')
    blobs={}
    for h,r in value['original_blobs'].items():
        b=base64.b64decode(r['base64'],validate=True);need(re.fullmatch('[0-9a-f]{64}',h) and len(b)==r['bytes'] and sha(b)==h,'every original blob full bytes and hash');blobs[h]=b
    need(sum(map(len,blobs.values()))<=16*1024*1024,'complete private blob budget')
    out=Path(args.out);need(out.parent.resolve(strict=True)==out.parent and not out.exists(),'new private receiver output namespace only');out.mkdir(mode=0o700)
    outputs={}
    for name,b in [('result.original.json',raw),('packet.original.json',packet_raw),('source.original.py',source),('inputs.original.json',inputs_raw),('actor.original.py',actor_raw),('request.original.json',request_raw)]+[(n+'.original',r[0]) for n,r in originals.items()]:outputs[name]=write_new(out,name,b)
    for h,b in blobs.items():outputs['originals/'+h+'.bin']=write_new(out,'originals/'+h+'.bin',b)
    checks=None;target_pin=None;error=None
    try:
        need(operation['phone']['rc']==0 and operation['phone']['stderr']=='' and value['state']=='COMPLETE_FRESH_UNSTARTED_SCOPE_CAPTURE_NO_CLOSURE' and value['terminal_error'] is None and value['errors']==[],'complete successful actual readonly capture')
        checks,targets=validate_bound02(value,inputs,blobs)
        targets.update(schema='hepta.fc33.bound02.readonly-exact-target-observation.v1',source_packet=outputs['packet.original.json'],source_result=result_descriptor,source_inputs=host_inputs_descriptor,preserved_unique_originals={h:outputs['originals/'+h+'.bin'] for h in blobs},sender_terminal_proof=inputs['sender_terminal_proof'],historical_failed_case_credit=False)
        target_pin=write_new(out,'EXACT-TARGETS.PUBLIC.json',enc(targets))
    except BaseException as exc:error={'type':type(exc).__name__,'detail':str(exc)[:2048]}
    report={'schema':'hepta.fc33.bound02.unstarted-readonly-host-verification.v1','state':'COMPLETE_UNSTARTED_SCOPE_PRIVATELY_PRESERVED_AND_INDEPENDENTLY_VERIFIED' if error is None else 'ORIGINALS_PRESERVED_WITH_UNKNOWN_REMAINING','actual_result':result_descriptor,'actual_actor':actor_descriptor,'actual_request':request_descriptor,'actual_inputs':host_inputs_descriptor,'operation_originals':{n:r[1] for n,r in originals.items()},'phone_rc':operation['phone']['rc'],'probe_state':value['state'],'probe_error':value['terminal_error'],'host_validation_error':error,'checks':checks,'target_observation':target_pin,'preserved_unique_originals':len(blobs),'preserved_unique_original_bytes':sum(map(len,blobs.values())),'output_descriptors':outputs,'read_bytes':value['read_bytes'],'resources':value['resources'],'sender_terminal_proof':inputs['sender_terminal_proof'],'phone_calls_by_host_receiver':0,'scope_closure':False,'deletion_authorized':False,'component_qualified':False,'business_qualified':False,'historical_unknowns_upgraded':False,'private_request_and_XML_bodies_published':False}
    report_pin=write_new(out,'HOST-VERIFICATION.PUBLIC.json',enc(report));print(json.dumps({'state':report['state'],'report':report_pin,'target_observation':target_pin,'phone_rc':report['phone_rc'],'probe_error':report['probe_error'],'host_validation_error':error,'scope_closure':False},sort_keys=True));return 0 if error is None else 1

if __name__=="__main__":raise SystemExit(receiver_main())
