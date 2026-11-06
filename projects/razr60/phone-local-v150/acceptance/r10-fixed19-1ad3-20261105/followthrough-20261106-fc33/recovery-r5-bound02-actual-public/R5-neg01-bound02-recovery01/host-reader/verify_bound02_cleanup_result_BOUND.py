#!/usr/bin/env python3
"""Independent host verification of one already completed bound02 cleanup.

No phone, signals, subprocess, producer import, or execution of target source.
Only fixed literals are parsed from the exact request source. The independent
prior readonly validator has an explicit held-preflight resource branch; it
never pretends those descriptors were closed before the mutation phase.
"""
from pathlib import Path
import argparse,ast,base64,copy,hashlib,io,json,lzma,os,re,shlex,stat,tarfile,zlib

FROZEN = {'operation_label': 'ng-fc33-neg01-bound02-owned-recovery01', 'source': {'bytes': 219894, 'sha256': 'c9a87756b951e504e74165975aa5aa2cad8e904bd6b64ce99efb6a25888949dc'}, 'request': {'bytes': 40150, 'path': '/home/alex/razr60-local-model-v150/requests/ng-fc33-neg01-bound02-owned-recovery01.json', 'sha256': '4a8acc78add217e6218adb10dc4714f6c700bd35931f6e045a93c201b0677fac'}, 'targets': {'bytes': 119542, 'metadata': [66306, 39846937, 33152, 1000, 1000, 1, 119542, 1793996987640007964, 1793996987640007964], 'path': '/home/alex/razr60-local-model-v150/fc33-neg01-bound02-unstarted-readonly01-import01/EXACT-TARGETS.PUBLIC.json', 'sha256': '719efadefa46d3280c0222050150ff670fde95ba4e628667349159a902bb2181'}, 'authority': {'bytes': 4800, 'sha256': '566bf7a6c6a2784363731bb2e595a3a842f2b262bd451f501172fb62c5b49469'}}
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

def literal(source, name):
    tree=ast.parse(source)
    nodes=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1
           and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(nodes)==1,'exactly one reviewed source literal: '+name)
    return ast.literal_eval(nodes[0].value)


def source_context(source, targets_raw):
    """Inspect fixed bytes only; never import or execute the phone producer."""
    cap=literal(source,'CAP_RAW')
    need(type(cap)is bytes and (len(cap),sha(cap))==PROBE_PIN
         and literal(source,'CAP_SHA')==PROBE_PIN[1],'exact immutable readonly producer bytes')
    inputs_raw=literal(cap,'INPUTS_RAW')
    need(type(inputs_raw)is bytes and len(inputs_raw)==36390 and sha(inputs_raw)==INPUTS_SHA,
         'exact original source inputs literal')
    need(literal(source,'TARGETS_RAW')==targets_raw
         and literal(source,'TARGETS_SHA')==FROZEN['targets']['sha256'],
         'complete exact target literal equals preserved original')
    authority_raw=literal(source,'AUTHORITY_RAW')
    need(type(authority_raw)is bytes and len(authority_raw)==FROZEN['authority']['bytes']
         and sha(authority_raw)==FROZEN['authority']['sha256']
         and literal(source,'AUTHORITY_SHA')==sha(authority_raw)
         and literal(source,'OPERATION_LABEL')==FROZEN['operation_label']
         and literal(source,'RECOVERY_SECONDS')==55,'exact authority, operation and deadline literals')
    return strict(inputs_raw),strict(targets_raw),strict(authority_raw),inputs_raw,authority_raw,cap


def independent_targets(targets, inputs, authority):
    need(targets['schema']=='hepta.fc33.bound02.readonly-exact-target-observation.v1'
         and targets['phone_label']==inputs['label'] and targets['nonce']==inputs['nonce']
         and targets['source_lease_sha256']==inputs['lease_sha256']
         and targets['source_package_sha256']==inputs['package_sha256'],
         'same preserved exact unstarted scope')
    files={r['path']:r for r in targets['files']}
    dirs={r['path']:r for r in targets['directories']}
    parents={r['path']:r for r in targets['surviving_parents']}
    need(len(files)==len(targets['files'])==78 and len(dirs)==len(targets['directories'])==9
         and len(parents)==5 and list(parents)==inputs['parent_paths'],
         'exact finite78 files9 directories5 parents')
    home=inputs['phone_home']
    expected={home+'/'+r['relative_path'] for r in inputs['archive_members']}|{home+'/STAGE-COMPLETE.json'}
    expected|={r['path'] for r in inputs['transport']+inputs['sender_xml']}
    need(set(files)==expected and set(dirs)==set(inputs['expected_directories']),
         'exact complete declared file and directory namespace')
    for path,row in files.items():
        regular_row(row)
        need(str(Path(path))==path and str(Path(path).parent) in dirs|parents,
             'canonical target below held declared parent')
    for path,row in (dirs|parents).items():
        directory_row(row);metadata(row['metadata'])
        if path in dirs:
            need(row['metadata'][3:5]==[0,0] and stat.S_IMODE(row['metadata'][2])==0o700
                 and row['names']==sorted(Path(p).name for p in files|dirs if str(Path(p).parent)==path),
                 'private original directory exact owner/membership')
    fixture=targets['fixture_absence'];parent=parents[str(Path(inputs['fixture']).parent)]
    need(fixture['path']==inputs['fixture'] and fixture['kind']=='absent'
         and fixture['absence']=='ENOENT' and fixture['parent_metadata']==parent['metadata']
         and fixture['parent_selinux_raw_b64']==parent['selinux_raw_b64'],
         'single coherent complete parent profile, no mixed snapshots')
    need(authority['schema']=='hepta.fc33.bound02.unstarted-recovery-authority.v1'
         and authority['sender_terminal_proof']==inputs['sender_terminal_proof']
         and authority['source_targets']==FROZEN['targets']
         and authority['historical_scope_never_launched_by_original_coordinator'] is True
         and authority['host_preservation_recheck_required'] is True
         and authority['current_proc_liveness_measured'] is False
         and authority['role_generation_invented'] is False,
         'fixed actual unstarted authority; no invented process identity')
    return files,dirs,parents


def output_reservation(frame,files,dirs,parents):
    paths=list(files)+list(dirs)
    operations=sum(len(enc({'path':p}))+4*9*21+1024 for p in paths)
    parent_bytes=sum(len(enc(r))+9*21+512 for r in parents.values())
    absences=18*(max(len(p.encode()) for p in paths)+9*21+256*2+512)
    other=64*1024;future=operations+parent_bytes+absences+other;fixed=len(enc(frame))
    need(fixed+future<=8*1024*1024,'complete output reserved within unchanged8MiB cap')
    return {'fixed_preflight_json_bytes':fixed,'operations_max_bytes':operations,
        'parents_max_bytes':parent_bytes,'absences_max_bytes':absences,'other_max_bytes':other,
        'future_max_bytes':future,'wire_max_bytes':fixed+future,'stdout_cap':8*1024*1024}


def compare_preserved_observation(observed,targets):
    keys=('files','directories','surviving_parents','home_aliases','original44_baseline',
          'source_lease_sha256','source_package_sha256','phone_label','nonce','scope_closure','deletion_authorized')
    for key in keys:
        need(enc(observed[key])==enc(targets[key]),'complete current preflight equals preserved target: '+key)
    # Each window has its own actual monotonic observation time; every identity,
    # parent field, absence result and flag is still compared without relaxation.
    a={k:v for k,v in observed['fixture_absence'].items() if k!='observed_monotonic_ns'}
    b={k:v for k,v in targets['fixture_absence'].items() if k!='observed_monotonic_ns'}
    need(enc(a)==enc(b),'exact fixture absence and same complete current parent')


def validate_recovery(value,pre,inputs,targets,authority,blobs):
    files,dirs,parents=independent_targets(targets,inputs,authority)
    need(value['schema']=='hepta.fc33.bound02.exact-unstarted-recovery.v1'
         and value['operation_label']==FROZEN['operation_label']
         and value['scope_label']==inputs['label'] and value['nonce']==inputs['nonce']
         and value['boot_id']==inputs['lease']['boot_id']
         and value['targets_sha256']==FROZEN['targets']['sha256']
         and enc(value['authority'])==enc(authority),'exact actual recovery identity and authority')
    need(value['state']=='EXACT_UNSTARTED_SCOPE_REMOVED_ORIGINAL44_UNCHANGED_NO_CASE_CREDIT'
         and value['phase']=='complete' and value['preflight_complete'] is True
         and value['terminal_error'] is None,'complete successful recovery terminal')
    for key in ('scope_closure','component_qualified','business_qualified','qualified_source_parent',
                'automatic_retry','role_generation_invented','historical_wait_invented'):
        need(value[key] is False,'unrelated authority remains false: '+key)
    for key in ('ui_calls','model_requests','native_dispatches','signals_to_other_processes'):
        need(type(value[key])is int and value[key]==0,'no unrelated effects: '+key)
    need(value['host_private_originals_untouched'] is True,'private original archive retained')
    need(pre['schema']=='hepta.fc33.bound02.unstarted-recovery-preflight.v1'
         and pre['targets_sha256']==FROZEN['targets']['sha256']
         and enc(pre['authority'])==enc(authority),'exact actual held-preflight identity')
    expected_blobs=[{'sha256':h,'bytes':len(b)} for h,b in sorted(blobs.items())]
    need(len(expected_blobs)==74 and enc(pre['actual_complete_originals'])==enc(expected_blobs)
         and pre['all_original_bytes_preserved_by_host_authority'] is True
         and pre['private_body_blobs_omitted_because_already_exactly_preserved'] is True,
         'all74 whole private originals reread and hash checked')
    prechecks,observed=validate_bound02_held_preflight(pre,inputs,blobs)
    compare_preserved_observation(observed,targets)
    expected_role_authority={'original_sender_terminal_proof':authority['sender_terminal_proof'],
        'original_root_failed_before_prepared_and_launch':True,'expired_original_lease':True,
        'current_complete_scope_has_only_stage_material':True,'current_proc_liveness_measured':False,
        'role_generation_invented':False,'no_signal_sent':True}
    need(enc(value['unstarted_role_authority'])==enc(expected_role_authority),
         'precise original never-launched authority without current process claim')
    additional=44353573+sum(r['bytes'] for r in files.values())+sum(inputs[k]['bytes'] for k in ('baseline','boundary'))+128*1024
    need(type(value['additional_read_allowance'])is int and value['additional_read_allowance']==additional==51703579,
         'finite read allowance including full final baseline and boundary rereads')
    need(enc(value['output_reservation'])==enc(output_reservation(value['preflight'],files,dirs,parents)),
         'independent full pre-mutation output reservation')
    groups={};directory_map={}
    for path,row in (dirs|parents).items():
        metadata(row['metadata']);key=tuple(row['metadata'][:2])
        fields={k:copy.deepcopy(row[k]) for k in ('metadata','names','selinux_raw_b64')}
        if key in groups:need(enc(groups[key]['fields'])==enc(fields),'initial directory aliases identical')
        else:groups[key]={'fields':fields,'removed':False}
        directory_map[path]=groups[key]
    need(len(groups)==13,'exact13 held directory inode groups')
    order=[('file',p) for p in sorted(files)]
    order += [('directory',p) for p in sorted(dirs,key=lambda p:(-p.count('/'),p))]
    operations=value['operations'];need(len(operations)==len(order)==87,'exact finite87 removal events')
    for i,(row,(kind,path)) in enumerate(zip(operations,order)):
        need(set(row)=={'index','kind','path','before_metadata','parent_before_metadata','effect_attempted',
                       'syscall_returned','verified_absent','after_metadata','parent_after_metadata','parent_fsynced'},
             'exact complete removal event shape')
        need(type(row['index'])is int and row['index']==i and (row['kind'],row['path'])==(kind,path),
             'one deterministic event for each owned target')
        need(all(row[k] is True for k in ('effect_attempted','syscall_returned','verified_absent','parent_fsynced')),
             'every actual effect returned and was checked/fsynced')
        before=row['before_metadata'];after=row['after_metadata'];pm=row['parent_after_metadata']
        for m in (before,after,row['parent_before_metadata'],pm):metadata(m)
        parent=directory_map[str(Path(path).parent)]
        need(not parent['removed'] and row['parent_before_metadata']==parent['fields']['metadata'],
             'held parent exact chained full9')
        if kind=='file':
            need(before==files[path]['metadata'] and after[:5]==before[:5] and after[5]==0
                 and after[6:8]==before[6:8],'exact original file inode lost its only link')
        else:
            current=directory_map[path]
            need(not current['removed'] and current['fields']['names']==[]
                 and before==current['fields']['metadata'] and before[5]==2,
                 'only emptied original directory removed')
            need(after[:5]==before[:5] and after[5]==0,'exact directory inode lost links')
            current['removed']=True
        old=parent['fields']['metadata'];name=Path(path).name
        need(name in parent['fields']['names'] and pm[:5]==old[:5]
             and pm[5]==old[5]-(1 if kind=='directory' else 0),'only declared parent entry/link delta')
        parent['fields']['names'].remove(name);parent['fields']['metadata']=pm
    need(all(directory_map[p]['removed'] for p in dirs),'all9 original directory identities removed')
    after=value['after'];need(set(after)=={'parents','absences','original44'},'exact final postcondition fields')
    expected_parents=[{'path':r['path'],**directory_map[r['path']]['fields']} for r in targets['surviving_parents']]
    need(enc(after['parents'])==enc(expected_parents),'complete actual after parents match all87 chained changes')
    need(inputs['label'] not in expected_parents[0]['names'] and len(expected_parents[0]['names'])==16
         and expected_parents[0]['metadata'][5]==18,'shared parent original membership restored')
    home=inputs['phone_home']
    expected_absences=[home,inputs['android_home'],inputs['fixture']]+[p for p in sorted(files) if not p.startswith(home+'/')]
    need(len(expected_absences)==18 and [r['path'] for r in after['absences']]==expected_absences,
         'complete18 exact final absence paths')
    for row in after['absences']:
        need(set(row)=={'kind','path','absence','parent_metadata','parent_selinux_raw_b64',
                       'observed_monotonic_ns','no_effect_inferred'},'exact final absence fields')
        metadata(row['parent_metadata']);parent=directory_map[str(Path(row['path']).parent)]['fields']
        need(row['kind']=='absent' and row['absence']=='ENOENT' and row['no_effect_inferred'] is False
             and type(row['observed_monotonic_ns'])is int and row['observed_monotonic_ns']>0
             and row['parent_metadata']==parent['metadata']
             and row['parent_selinux_raw_b64']==parent['selinux_raw_b64'],
             'exact held/reopened final absence and surviving parent identity')
    before=pre['windows'][1]['baseline']
    projected={'roots':before['roots'],'entries':legacy_rows(before),'file_bytes_hashed':before['file_bytes_hashed']}
    projected_raw=enc(projected)
    expected_projection={'complete_roots':44,'complete_entries':3823,'complete_file_bytes_hashed':44353573,
        'canonical_projection_bytes':len(projected_raw),'canonical_projection_sha256':sha(projected_raw),
        'equal_to_complete_preflight_projection':True,'all_present_labels_exact':True,
        'absent_fixture_parents_match_actual_surviving_parent':True}
    need(enc(after['original44'])==enc(expected_projection),
         'actual complete post-read projection exactly matches original44')
    resource=value['resources']
    need(set(resource)=={'close_errors','initial_fd_names','final_fd_names','closed_file_descriptors',
                        'closed_directory_descriptors','closed_lock_descriptors'},'complete final resource fields')
    need(resource['close_errors']==[] and resource['initial_fd_names']==resource['final_fd_names']
         and type(resource['closed_file_descriptors'])is int and resource['closed_file_descriptors']==78
         and type(resource['closed_directory_descriptors'])is int and resource['closed_directory_descriptors']==13
         and type(resource['closed_lock_descriptors'])is int and resource['closed_lock_descriptors']==14,
         'all owned descriptors closed to actual measured FD baseline')
    need(all(type(n)is str and n.isdigit() for n in resource['initial_fd_names'])
         and len(resource['initial_fd_names'])==len(set(resource['initial_fd_names'])),'exact actual FD names')
    for key,number in (('files_removed_verified',78),('directories_removed_verified',9),('effect_attempt_count',87)):
        need(type(value[key])is int and value[key]==number,'independent exact removal count '+key)
    need(type(value['read_bytes'])is int and pre['read_bytes']<=value['read_bytes']<=160*1024*1024+additional,
         'bounded actual complete read accounting')
    need(type(value['elapsed_seconds'])in (int,float) and 0<=value['elapsed_seconds']<=80,
         'bounded actual elapsed result')
    return {'exact_files_removed':78,'exact_directories_removed':9,'ordered_operations_checked':87,
        'exact_final_absences':18,'original44_roots':44,'original44_entries':3823,
        'original44_bytes_read_per_complete_window':44353573,'after_projection':expected_projection,
        'after_inventory_representation':'Complete post-read projection hash matches the independently checked complete preflight graph; no separate raw after-inventory was emitted.',
        'preflight_checks':prechecks,'preflight_adapter_is_original':False,
        'preflight_adapter_changes_only_resource_phase_validation':True,
        'whole_operation_was_readonly':False,'all14_original_locks_held_during_effects':True,
        'actual_final_resource_observation':resource,'measured_fd_baseline_restored':True,
        'current_process_liveness_measured':False,'role_generation_invented':False,
        'historical_supervisor_wait_proven':False,'producer_source_executed_by_reader':False,
        'producer_scope_closure_flag':False,'business_or_component_credit':False,
        'owned_recovery_closed':True,'fresh_component_admission_required':True}


def main():
    need(type(FROZEN)is dict,'UNBOUND_NO_IO')
    parser=argparse.ArgumentParser()
    for name in ('result','sha256','version','out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--bytes',required=True,type=int);a=parser.parse_args()
    label=FROZEN['operation_label'];path=Path(a.result)
    need(path==BASE/'operations'/label/'result.json' and 0<a.bytes<=16*1024*1024
         and re.fullmatch('[0-9a-f]{64}',a.sha256),'one bounded actual recovery result only')
    result_raw,result_pin=read_exact(path,a.bytes,a.sha256)
    m=result_pin['metadata']
    need(':'.join(str(m[i]) for i in (0,1,6,7,8))==a.version
         and m[3:6]==[1000,1000,1] and stat.S_IMODE(m[2])==0o600,
         'actual Root-observed immutable result version and owner')
    actor_raw,actor_pin=read_exact(ACTOR,*ACTOR_PIN)
    request_raw,request_pin=read_row(FROZEN['request'])
    out=Path(a.out)
    need(out.parent==BASE and out.name==label.removeprefix('ng-')+'-import01'
         and out.parent.resolve(strict=True)==out.parent and not os.path.lexists(out),
         'fresh exact private import namespace')
    out.mkdir(mode=0o700)
    outputs=[write_new(out,'result.original.json',result_raw),write_new(out,'actor.original.py',actor_raw),
             write_new(out,'request.original.json',request_raw)]
    checks=None;error=None;operation_inputs={};preserved=[];authority_originals=[];phone_rc=None
    try:
        operation=strict(result_raw);request=strict(request_raw)
        need(operation['schema']=='hepta.phone-local.operator-result.v150.1'
             and operation['label']==label and operation['status']=='command_exited'
             and operation['model_decision'] is False and operation['native_task_result'] is False,
             'actual original recovery actor terminal')
        need(set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell'
             and request['root'] is True and type(request['timeout_seconds'])is int
             and request['timeout_seconds']==80,'exact reviewed recovery request')
        need(operation['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),
             'exact pinned actor single root wrapper')
        for filename in ('intent.json','baseline.json'):
            body,row=observe_input(path.parent/filename);operation_inputs[filename]=(body,row)
            outputs.append(write_new(out,filename+'.original',body))
        intent=strict(operation_inputs['intent.json'][0]);baseline=strict(operation_inputs['baseline.json'][0])
        need(intent['schema']=='hepta.phone-local.operator-intent.v150.1' and intent['label']==label
             and enc(intent['request'])==enc(request) and intent['request_sha256']==sha(request_raw)
             and intent['automatic_replay'] is False,'original one-use actor intent')
        need(type(baseline['rc'])is int and baseline['rc']==0
             and baseline['stdout'].splitlines()==['f8019f83-20a7-4f18-bea1-51c980621e4d',
                'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021']
             and baseline['route']==operation['phone']['route']==[5037,'23'],
             'exact actual boot/build/route baseline')
        source=extract_source(request);outputs.append(write_new(out,'recovery-source.original.py',source))
        targets_raw,targets_pin=read_row(FROZEN['targets'])
        inputs,targets,authority,inputs_raw,authority_raw,cap=source_context(source,targets_raw)
        independent_targets(targets,inputs,authority)
        host_inputs,input_pin=read_row(authority['input_original'])
        need(host_inputs==inputs_raw,'actual preserved host/source input bytes equal')
        outputs.extend([write_new(out,'targets.original.json',targets_raw),
            write_new(out,'authority.original.json',authority_raw),write_new(out,'inputs.original.json',inputs_raw),
            write_new(out,'readonly-source.reference.py',cap)])
        for name,row in sorted(authority['host_original_preservation'].items()):
            _,pin=read_row(row);authority_originals.append({'name':name,'original':pin})
        for name in ('scope_report','sender_terminal_proof','source_sender_public','source_packet','source_result'):
            raw,pin=read_row(authority[name]);authority_originals.append({'name':name,'original':pin})
            if name=='scope_report':
                scope_report=strict(raw)
                need(scope_report['state']=='COMPLETE_UNSTARTED_SCOPE_PRIVATELY_PRESERVED_AND_INDEPENDENTLY_VERIFIED'
                     and scope_report['phone_rc']==0 and scope_report['host_validation_error'] is None
                     and scope_report['target_observation']['sha256']==sha(targets_raw),
                     'prior complete independent preservation proof')
        blobs={}
        for h,row in sorted(targets['preserved_unique_originals'].items()):
            need(set(row)=={'path','bytes','sha256'} and row['sha256']==h
                 and row['path']==str(Path(authority['source_targets']['path']).parent/'originals'/(h+'.bin')),
                 'only exact74 previously preserved private blob paths')
            raw,pin=read_row(row);need(h not in blobs,'unique preserved original digest')
            blobs[h]=raw;preserved.append(pin)
        phone_rc=operation['phone']['rc'];wire=operation['phone']['stdout'].encode()
        need(len(wire)<=8*1024*1024,'unchanged original8MiB phone stdout cap')
        outputs.append(write_new(out,'recovery-packet.original.json',wire))
        value=strict(wire);need(enc(value)==wire,'canonical unchanged recovery stdout')
        pre_raw=decompress_frame(value['preflight'],32*1024*1024);pre=strict(pre_raw)
        need(enc(pre)==pre_raw,'canonical complete held-preflight bytes')
        outputs.append(write_new(out,'preflight.original.json',pre_raw))
        need(type(phone_rc)is int and phone_rc==0 and operation['phone']['stderr']=='',
             'actual complete successful phone recovery')
        checks=validate_recovery(value,pre,inputs,targets,authority,blobs)
        # Re-read every exact authoritative host original after the full parser,
        # including private preserved blobs; no post-delete phone reads occur.
        for row in [result_pin,actor_pin,request_pin,targets_pin,input_pin]+preserved+[r['original'] for r in authority_originals]+[r[1] for r in operation_inputs.values()]:
            read_row(row)
    except BaseException as exc:
        error={'type':type(exc).__name__,'detail':str(exc)[:2048]}
    report={'schema':'hepta.fc33.bound02.exact-unstarted-recovery-host-verification.v1',
        'state':'EXACT_UNSTARTED_RECOVERY_INDEPENDENTLY_VERIFIED_NO_CASE_CREDIT' if error is None else 'ORIGINALS_PRESERVED_RECOVERY_INCOMPLETE_OR_UNKNOWN',
        'actual_result':result_pin,'actual_actor':actor_pin,'actual_request':request_pin,
        'actual_operation_inputs':{name:row for name,(_,row) in operation_inputs.items()},
        'phone_rc':phone_rc,'host_validation_error':error,'checks':checks,
        'rechecked_preserved_originals':preserved,'rechecked_authority_originals':authority_originals,
        'output_descriptors':outputs,'phone_calls_by_host_verifier':0,
        'producer_source_imported_or_executed':False,'owned_recovery_closed':error is None,
        'scope_closure':False,'current_proc_liveness_measured':False,
        'original_failed_case_qualification':False,'historical_unknowns_upgraded':False,
        'private_bodies_in_public_report':False}
    report_pin=write_new(out,'HOST-VERIFICATION.PUBLIC.json',enc(report))
    print(json.dumps({'state':report['state'],'report':report_pin,'phone_rc':phone_rc,
        'host_validation_error':error,'owned_recovery_closed':error is None},sort_keys=True))
    return 0 if error is None else 1


if __name__=='__main__':raise SystemExit(main())
