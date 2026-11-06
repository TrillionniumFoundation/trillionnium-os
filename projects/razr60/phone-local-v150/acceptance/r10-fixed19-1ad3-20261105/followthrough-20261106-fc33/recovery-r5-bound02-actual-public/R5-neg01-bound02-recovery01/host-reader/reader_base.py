#!/usr/bin/env python3
"""Independent host verification of one already completed bound02 cleanup.

No phone, signals, subprocess, producer import, or execution of target source.
Only fixed literals are parsed from the exact request source. The independent
prior readonly validator has an explicit held-preflight resource branch; it
never pretends those descriptors were closed before the mutation phase.
"""
from pathlib import Path
import argparse,ast,base64,copy,hashlib,io,json,lzma,os,re,shlex,stat,tarfile,zlib

FROZEN = None
BASE = Path('/home/alex/razr60-local-model-v150')
ACTOR = BASE/'ops/phone_once.py'
ACTOR_PIN = (5652, '179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22')
PROBE_PIN = (69722, 'a539c674dc1bb9041e7381b807baabcab38f7705fe24277b052ecc78ee5d2759')
INPUTS_SHA = '9f208e160b9f11de65e758b8f060991a2ea64427d50e851ea1a7b1522e13d11d'
EXPECTED_COMMAND_PREFIX = ['/data/adb/magisk/busybox','env','-i',
    'PATH=/usr/bin:/bin:/usr/libexec/trillionnium','PYTHONHOME=/usr','PYTHONDONTWRITEBYTECODE=1',
    'LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu',
    'LANG=C.UTF-8','LC_ALL=C.UTF-8','TMPDIR=/var/lib/trillionnium/owner-open/tmp','NO_COLOR=1','TERM=dumb',
    '/data/adb/magisk/busybox','chroot','/data/trillionnium/owner-open/root','/usr/bin/python3','-I','-B','-c']

def need(ok, why):
    if not ok: raise ValueError(why)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(rows):
        out={}
        for k,v in rows:
            need(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def full9(s):
    return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

def metadata(m):
    need(type(m)is list and len(m)==9 and all(type(v)is int and 0<=v<(1<<63) for v in m),'exact bounded full9')

def read_exact(path, size, digest, expected_metadata=None):
    path=Path(path)
    need(path.is_absolute() and str(path)==str(path.resolve(strict=True)) and type(size)is int and 0<=size<=32*1024*1024,'canonical bounded host original')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==size,'regular single-link original length')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(size+1)
        m=full9(a)
        need(len(raw)==size and sha(raw)==digest and m==full9(os.fstat(fd))==full9(path.lstat()) and path.resolve(strict=True)==path,'original bytes/full9/canonical bookends')
        if expected_metadata is not None: need(m==expected_metadata,'original preserved host identity changed')
        return raw,{'path':str(path),'bytes':size,'sha256':digest,'metadata':m}
    finally:os.close(fd)

def read_row(row):
    return read_exact(row['path'],row['bytes'],row['sha256'],row.get('metadata'))

def observe_input(path):
    path=Path(path);need(path.resolve(strict=True)==path,'canonical operation input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=1048576,'operation input size/type')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(before.st_size+1)
        need(len(raw)==before.st_size and full9(before)==full9(os.fstat(fd))==full9(path.lstat()),'operation input first full read')
    finally:os.close(fd)
    return read_exact(path,len(raw),sha(raw),full9(before))

def write_new(root, name, raw):
    need('/' not in name and name not in ('.','..'),'finite output basename')
    path=root/name
    need(root.resolve(strict=True)==root,'canonical private output directory')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    _,row=read_exact(path,len(raw),sha(raw));return row

def decompress_frame(frame, limit):
    need(frame['encoding']=='zlib-base64' and type(frame['bytes'])is int and 0<frame['bytes']<=limit,'bounded preflight frame')
    compressed=base64.b64decode(frame['base64'],validate=True)
    need(len(compressed)==frame['compressed_bytes'] and sha(compressed)==frame['compressed_sha256'] and len(compressed)<=8*1024*1024,'complete compressed frame')
    d=zlib.decompressobj();raw=d.decompress(compressed,frame['bytes']+1)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==frame['bytes'] and sha(raw)==frame['sha256'],'exact whole preflight stream')
    return raw

def extract_source(request):
    words=shlex.split(request['command'])
    need(words[:-1]==EXPECTED_COMMAND_PREFIX and len(request['command'].encode())<=65535,'exact reviewed GNU command prefix and wire bound')
    tree=ast.parse(words[-1]);nodes=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='c']
    need(len(nodes)==1 and isinstance(nodes[0].value,ast.Call),'one explicit compressed source literal')
    call=nodes[0].value
    need(ast.unparse(call.func)=='base64.b64decode' and len(call.args)==1,'reviewed single base64 source expression')
    compressed=base64.b64decode(ast.literal_eval(call.args[0]),validate=True)
    need(len(compressed)<=65535,'bounded compressed source')
    d=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=128*1024*1024)
    source=d.decompress(compressed,max_length=FROZEN['source']['bytes']+1)
    need(d.eof and not d.unused_data and len(source)==FROZEN['source']['bytes'] and sha(source)==FROZEN['source']['sha256'],'whole reviewed recovery source from actual request')
    return source

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

def validate_bound02_held_preflight(value,inputs,blobs):
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
    resources=value['resources'];need(enc(resources)==enc({'held_lock_descriptors':14,'closed_lock_descriptors':0,'held_file_descriptors':78,'held_directory_descriptors':13}),'actual held-preflight descriptor counts, no fabricated release')
    minimum=2*(44353573+first['private']['file_bytes_hashed']+sum(r['bytes'] for r in first['transport']+first['xml']))+3*(inputs['baseline']['bytes']+inputs['boundary']['bytes'])+sum(r['bytes'] for r in locks['aliases'])
    need(type(value['read_bytes']) is int and minimum<=value['read_bytes']<=160*1024*1024,'complete two-window read byte accounting')
    return {'original44_full_inventory_equal':True,'original44_roots':44,'original44_entries':3823,'baseline_file_bytes_per_window':44353573,'runtime_files':38,'archive_members':62,'private_home_files':63,'unique_private_directories':9,'transport_files':4,'sender_xml_files':11,'exact_owned_file_count':78,'exact_file_bytes':sum(r['bytes'] for r in targets.values()),'lock_aliases':26,'lock_inode_groups':14,'window_count':2,'claims_operator_executor_empty':True,'fixture_absent_same_complete_parent':True,'actual_FD_baseline_restored':False,'held_preflight_resources_verified':True,'original_lease_unchanged':True,'lease_expiry_observed_by_pinned_producer_not_extended':True,'role_generation_invented':False,'current_role_liveness_measured':False,'scope_closure':False,'case_credit':False}, {'files':[targets[p] for p in sorted(targets)],'directories':[directories[p] for p in sorted(directories,key=lambda p:(-p.count('/'),p))],'surviving_parents':first['parents_after'],'home_aliases':first['home_aliases_after'],'fixture_absence':first['private']['entries'][fixture],'original44_baseline':inputs['baseline'],'source_lease_sha256':inputs['lease_sha256'],'source_package_sha256':inputs['package_sha256'],'phone_label':inputs['label'],'nonce':inputs['nonce'],'scope_closure':False,'deletion_authorized':False}

