#!/usr/bin/env python3
"""Import one already completed read-only P4 operation. No device invocation.

Every XML and foreign audit body stays in the private P4 preservation directory.
This proves the finite observation only, not cleanup, role liveness or all97.
"""
from pathlib import Path
import ast,base64,hashlib,json,lzma,os,shlex,stat,zlib

BASE=Path('/home/alex/razr60-local-model-v150')
LABEL='ng-fc33-final05-surviving-parents-readonly02'
OUT=BASE/'fc33-final05-surviving-parents-readonly02-import01'
RESULT_PIN=(195248,'d0d2726adb89a6e29c6ed054972c4ef9131402a521cdfdfdf1196284dcd0c0e4')
REQUEST_PIN=(28145,'e7afd47d4f41b18fe5745de2c2c32eabb8d771b54f7354fd64e89ed54fa45fbf')
SOURCE_PIN=(91164,'0af051db4502e1655c5e3eb1580ff6cd981fae794dc6cb41a56e1704bd490acc')
INPUTS_PIN=(16641,'f057b3fd8d42db1ade3d0c24b23ae90982bfe3bedf469d535a92d42ad4072c8e')
CAP_PIN=(63646,'70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44')
TARGETS_PIN=(183176,'0aad40b0feac77b963547d90b27ed49eb260d3a2c14fd9a9dbfe4a61550597d1')
REFERENCE_PIN=(12129,'5dd20c0bb2fbc049dea1b168cb83a730a3abc9916677be5e47ac81bbd7518427')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'

def need(v,s):
    if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def strict(b):
    def pairs(rows):
        d={}
        for k,v in rows:need(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def full9(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def read(p,pin=None,maximum=16*1024*1024):
    need(p.resolve(strict=True)==p,'canonical host original')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,'bounded regular single-link host original')
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(maximum+1)
        need(len(b)==before.st_size and full9(before)==full9(os.fstat(fd))==full9(p.lstat()),'host original full9 bookend')
        if pin is not None:need((len(b),sha(b))==pin,'pinned host original '+str(p))
        return b,{'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':full9(before)}
    finally:os.close(fd)
def put(name,b):
    p=OUT/name;need(p.parent==OUT or OUT in p.parents,'private output namespace')
    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def assignments(raw):
    return {n.targets[0].id:n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
def decode_zlib(b,n,h):
    need(type(n) is int and 0<n<=33554432,'bounded packet raw length')
    d=zlib.decompressobj();raw=d.decompress(b,n+1)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==n and sha(raw)==h,'full exact packet decompression')
    return raw
def meta(m):need(type(m) is list and len(m)==9 and all(type(x) is int and 0<=x<(1<<63) for x in m),'bounded complete integer full9')
def label(row):
    b=base64.b64decode(row['selinux_raw_b64'],validate=True);need(0<len(b)<=256,'complete SELinux label')
def pin_equal(row,pin):
    need(row['path']==pin['path'],'exact ordered path')
    for k in ('bytes','sha256','metadata','selinux_raw_b64'):need(row[k]==pin[k],'exact original '+k)
def directory(row,path):
    need(set(row)=={'path','metadata','names','selinux_raw_b64'} and row['path']==path,'exact parent row schema/path')
    meta(row['metadata']);label(row)
    need(stat.S_ISDIR(row['metadata'][2]) and row['names']==sorted(set(row['names'])) and len(row['names'])<=20000,'complete bounded directory membership')
    need(all(type(n) is str and n not in ('.','..') and '/' not in n and '\0' not in n and 0<len(n.encode())<=255 for n in row['names']),'bounded leaf grammar')
def file_row(row):
    need(row['kind']=='file','regular original row kind');meta(row['metadata']);label(row)
    need(stat.S_ISREG(row['metadata'][2]) and row['metadata'][5]==1 and row['bytes']==row['metadata'][6] and type(row['bytes']) is int,'regular single-link full original')
def parent_diff(old,new,old_has_names=True):
    need(old['path']==new['path'],'comparison path')
    return {'path':new['path'],'metadata_changes':[{'index':i,'old':a,'new':b} for i,(a,b) in enumerate(zip(old['metadata'],new['metadata'])) if a!=b],
            'label_changed':old['selinux_raw_b64']!=new['selinux_raw_b64'],
            'old_names_were_observed':old_has_names,
            'names_added':sorted(set(new['names'])-set(old['names'])) if old_has_names else None,
            'names_removed':sorted(set(old['names'])-set(new['names'])) if old_has_names else None}

def validate(value,inputs,cap_inputs,baseline,blobs,targets,reference):
    need(value['schema']=='hepta.fc33.final05.parent-reconciliation-observation.v1' and value['state']=='COMPLETE_FRESH_PARENT_XML_AND_FOREIGN_AUDIT_OBSERVATIONS_NO_CLOSURE' and value['terminal_error'] is None and value['errors']==[],'complete error-free finite readonly observation')
    need(value['scope_label']=='root-r10-neg02-a1055-final05' and value['nonce']=='9b37081161d7bcbc3adf76d2e6ec7841' and value['boot_id']==BOOT and value['inputs_sha256']==INPUTS_PIN[1],'exact observed failed scope/source')
    need(value['reference_failure']==inputs['reference_failure'] and value['reference_failure_preflight']==inputs['reference_failure_preflight'],'explicit prior failure source relation')
    for k in ('file_writes','file_deletes','ui_calls','model_requests','native_dispatches','signals_to_other_processes'):
        need(type(value[k]) is int and value[k]==0,'no effects '+k)
    for k in ('foreign_cleanup_success_inferred','all44_files_refreshed','private82_or_transport4_refreshed','known_process_liveness_refreshed','all97_current_originals_proven','scope_closure','deletion_authorized','business_qualified','component_qualified','automatic_retry'):
        need(value[k] is False,'no extra inferred authority '+k)
    need(value['foreign_originals_read_only'] is True and value['private_xml_and_foreign_original_bodies_do_not_publish'] is True,'private original role')
    identity=value['collector_identity'];init=identity['init_stat_original'];init_raw=base64.b64decode(init['base64'],validate=True)
    need(len(init_raw)==init['bytes']<=8192 and sha(init_raw)==init['sha256'],'complete native init stat original')
    head,tail=init_raw.rsplit(b') ',1);fields=tail.split()
    parsed={'pid':1,'state':fields[0].decode(),'ppid':int(fields[1]),'pgid':int(fields[2]),'sid':int(fields[3]),'start_ticks':int(fields[19])}
    need(head.startswith(b'1 (') and parsed==identity['init'] and parsed['start_ticks']==0,'independently decoded native init')
    need(identity['boot_id']==BOOT and base64.b64decode(identity['domain_raw_b64'],validate=True).rstrip(b'\0\n')==b'u:r:magisk:s0','same boot and actual Root domain')
    meta(identity['gnu_root_metadata']);meta(identity['android_root_metadata'])
    need(identity['gnu_root_metadata'][:2]!=identity['android_root_metadata'][:2] and type(identity['collector_pid']) is int and identity['collector_pid']>1,'distinct GNU/Android roots')
    need(baseline['schema']=='hepta.native-guard.complete-inventory.v1' and baseline['roots']==cap_inputs['baseline_roots'] and len(baseline['roots'])==44 and len(baseline['entries'])==3823,'exact44 lock source, not a new44 census')
    pin_equal(value['lock_inventory_original'],cap_inputs['baseline'])
    aliases={p:r for p,r in baseline['entries'].items() if r['kind']=='file' and (p.rsplit('/',1)[-1]=='lock' or p.endswith('.lock'))}
    need(len(aliases)==26 and len({tuple(r['metadata'][:2]) for r in aliases.values()})==14,'actual old14 lock groups')
    gnu='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/executor/server.lock'
    android='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/executor/server.lock'
    for p in (gnu,android):
        need(p not in aliases,'new lock aliases distinct');aliases[p]=dict(cap_inputs['foreign_server_lock'],path=p)
    locks=value['locks'];ordered=sorted(aliases,key=lambda p:(aliases[p]['metadata'][0],aliases[p]['metadata'][1],p))
    need(locks['alias_count']==28 and locks['inode_group_count']==15 and locks['old_inode_group_count']==14 and locks['lock_mode']=='LOCK_EX|LOCK_NB on existing O_RDONLY descriptors' and locks['lock_files_created']==0 and locks['held_through_both_windows'] is True,'all existing lock groups held')
    need(len(locks['aliases'])==28 and [r['path'] for r in locks['aliases']]==ordered,'all complete ordered lock observations')
    for row in locks['aliases']:file_row(row);pin_equal(row,aliases[row['path']])
    need(len({tuple(r['metadata'][:2]) for r in locks['aliases']})==15,'exact actual inode grouping')
    windows=value['windows'];need(len(windows)==2 and [w['index'] for w in windows]==[0,1],'exact two windows')
    refs=inputs['parent_identity_references'];paths=[r['path'] for r in refs]
    used_blobs=set();all_parents=[]
    for w in windows:
        need(w['parents_before']==w['parents_after'] and len(w['parents_before'])==5,'within-window complete parents stable')
        for row,old in zip(w['parents_before'],refs):
            directory(row,old['path']);need(row['metadata'][:5]==old['metadata'][:5] and row['selinux_raw_b64']==old['selinux_raw_b64'],'same parent identity/mode/owner/label')
        parent=w['parents_before'];need({k:v for k,v in parent[0].items() if k!='path'}=={k:v for k,v in parent[1].items() if k!='path'},'complete shared parent aliases')
        all_parents.append(parent)
        need(len(w['xml'])==11 and len(w['foreign_audit_originals'])==2,'all fixed13 originals')
        for row,pin in zip(w['xml'],inputs['xml_files']):
            file_row(row);pin_equal(row,pin);need(row['metadata'][3:6]==[2000,2000,1] and Path(row['path']).name in parent[-1]['names'],'source-owned XML membership')
        need([r['path'] for r in w['foreign_audit_originals']]==inputs['foreign_audit_paths'],'exact two finite foreign audit paths')
        for row in w['foreign_audit_originals']:
            file_row(row);need(0<=row['bytes']<=4194304 and Path(row['path']).name in parent[2]['names'],'bounded foreign originals in exact stage parent')
        for row in w['xml']+w['foreign_audit_originals']:
            need(row['sha256'] in blobs and len(blobs[row['sha256']])==row['bytes'],'full raw original retained privately');used_blobs.add(row['sha256'])
        absence=w['fixture_absence']
        need(absence['kind']=='absent' and absence['path']==inputs['fixture_path'] and absence['absence']=='ENOENT' and absence['no_effect_inferred'] is False and type(absence['observed_monotonic_ns']) is int,'exact current leaf-only fixture absence')
        need(absence['parent_metadata']==parent[-1]['metadata'] and absence['parent_selinux_raw_b64']==parent[-1]['selinux_raw_b64'] and Path(inputs['fixture_path']).name not in parent[-1]['names'],'fixture absence shares one exact full current parent profile')
    need(all_parents[0]==all_parents[1] and windows[0]['xml']==windows[1]['xml'] and windows[0]['foreign_audit_originals']==windows[1]['foreign_audit_originals'],'complete two-window originals stable')
    need({k:v for k,v in windows[0]['fixture_absence'].items() if k!='observed_monotonic_ns'}=={k:v for k,v in windows[1]['fixture_absence'].items() if k!='observed_monotonic_ns'},'fixture two-window same full identity')
    need(used_blobs==set(blobs),'no extra or missing private blobs')
    resources=value['resources'];need(resources['closed_lock_descriptors']==15 and resources['close_errors']==[] and resources['initial_fd_names']==resources['final_fd_names'],'all15 locks closed and exact FD baseline')
    need(type(value['read_bytes']) is int and value['read_bytes']<=160*1024*1024 and type(value['elapsed_seconds']) in (int,float) and 0<=value['elapsed_seconds']<30,'bounded finite observation')
    minimum=2*cap_inputs['baseline']['bytes']+sum(r['bytes'] for r in locks['aliases'])+2*sum(r['bytes'] for r in windows[0]['xml']+windows[0]['foreign_audit_originals'])+init['bytes']+len(base64.b64decode(identity['domain_raw_b64'],validate=True))
    need(minimum<value['read_bytes']<=minimum+256,'all original reads plus exactly bounded two boot reads')
    fresh=all_parents[0]
    old_diffs=[parent_diff(a,b) for a,b in zip(targets['surviving_parents'],fresh)]
    failure_diffs=[parent_diff(a,b,a.get('names_observed_in_reference',True)) for a,b in zip(refs,fresh)]
    audit=[]
    for row in windows[0]['foreign_audit_originals']:
        raw=blobs[row['sha256']];item={'original':row,'body_retained_privately':True,'claims_not_accepted_as_cleanup_proof':True}
        try:
            obj=strict(raw);item['json_type']=type(obj).__name__
            if type(obj) is dict:
                item['top_level_keys']=sorted(obj)
                item['selected_unverified_foreign_claims']={k:obj[k] for k in ('schema','state','phase','scope_label','nonce','file_count','directory_count','removed_file_count','removed_directory_count','effect_attempt_count','automatic_retry') if k in obj and type(obj[k]) in (str,int,bool,type(None))}
        except (ValueError,TypeError,UnicodeError):item['json_type']='non_JSON_original'
        audit.append(item)
    return {'five_complete_current_parent_profiles':fresh,'fixture_absence':windows[0]['fixture_absence'],
            'eleven_xml_originals':windows[0]['xml'],'eleven_xml_total_bytes':sum(r['bytes'] for r in windows[0]['xml']),
            'two_foreign_audit_originals':audit,'old_targets_parent_differences':old_diffs,'failed_preflight_reference_differences':failure_diffs,
            'all15_existing_lock_groups_held_through_two_windows':True,'exact_resource_baseline_restored':True,
            'current_parent_and_fixture_profile_coherent':True,'old44_full_files_refreshed':False,'all97_current_originals_proven':False,'known_role_liveness_refreshed':False,
            'unknown_foreign_cleanup_not_admitted':True,'scope_closure':False,'cleanup_authorized':False}

def main():
    for n,h in (RESULT_PIN,REQUEST_PIN,SOURCE_PIN,INPUTS_PIN,CAP_PIN,TARGETS_PIN,REFERENCE_PIN):
        need(type(n) is int and n>0 and len(h)==64 and all(c in '0123456789abcdef' for c in h),'complete fixed host pin grammar')
    result_raw,result_pin=read(BASE/'operations'/LABEL/'result.json',RESULT_PIN)
    op=strict(result_raw);need(op['label']==LABEL and op['status']=='command_exited' and op['model_decision'] is False and op['native_task_result'] is False,'actual one observed operator operation')
    actor_raw,actor_pin=read(BASE/'ops/phone_once.py',(5652,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'))
    request_raw,request_pin=read(BASE/'requests'/(LABEL+'.json'),REQUEST_PIN);request=strict(request_raw)
    need(set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==50,'exact actual request')
    need(op['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),'exact pinned actor root transformation')
    args=shlex.split(request['command']);need(args[-5:-1]==['/usr/bin/python3','-I','-B','-c'] and not any('/su' in v for v in args[:-1]),'single actor wrapper and exact Python route')
    loader=assignments(args[-1]);zipped=base64.b64decode(ast.literal_eval(loader['c'].args[0]),validate=True)
    d=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024);source=d.decompress(zipped,max_length=SOURCE_PIN[0]+1)
    need(d.eof and not d.unused_data and (len(source),sha(source))==SOURCE_PIN,'complete exact bounded source XZ')
    src=assignments(source);inputs_raw=ast.literal_eval(src['INPUTS_RAW']);inputs=strict(inputs_raw)
    need((len(inputs_raw),sha(inputs_raw))==INPUTS_PIN and ast.literal_eval(src['INPUTS_SHA'])==INPUTS_PIN[1],'exact source embedded inputs')
    cap_raw=ast.literal_eval(src['CAP_SOURCE_RAW']);need((len(cap_raw),sha(cap_raw))==CAP_PIN,'unchanged original read-only helpers')
    cap_inputs=strict(ast.literal_eval(assignments(cap_raw)['INPUTS_RAW']))
    target_raw,target_pin=read(BASE/'fc33-final05-recovery-inputs01/TARGETS.json',TARGETS_PIN);targets=strict(target_raw)
    ref_raw,ref_pin=read(Path(inputs['actual_failure_profile_reference']['path']),REFERENCE_PIN);reference=strict(ref_raw)
    refs=reference['complete_parent_profiles']+[{'path':'/proc/1/root/data/local/tmp','metadata':reference['fixture_absence']['parent_metadata'],'selinux_raw_b64':reference['fixture_absence']['parent_selinux_raw_b64'],'names_observed_in_reference':False}]
    need(inputs['parent_identity_references']==refs and inputs['reference_failure_preflight']=={k:reference['source'][k] for k in ('path','bytes','sha256')},'exact actual failed observation reference')
    xml={r['path']:r for r in targets['files'] if r['path'].startswith('/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-')}
    need(len(xml)==11 and {r['path']:r for r in inputs['xml_files']}==xml and [r['path'] for r in refs]==[r['path'] for r in targets['surviving_parents']],'original ownership and fixed parent paths unchanged')
    baseline_desc=next(r for r in targets['preserved_blob_descriptors'] if r['sha256']==cap_inputs['baseline']['sha256'])
    baseline_raw,baseline_pin=read(Path(baseline_desc['preserved_path']),(baseline_desc['bytes'],baseline_desc['sha256']));baseline=strict(baseline_raw)
    operation_inputs={name:read(BASE/'operations'/LABEL/name,maximum=1048576) for name in ('intent.json','baseline.json')}
    intent=strict(operation_inputs['intent.json'][0]);actor_baseline=strict(operation_inputs['baseline.json'][0])
    need(intent['label']==LABEL and intent['request']==request and intent['request_sha256']==sha(request_raw) and intent['automatic_replay'] is False,'actual unique actor intent')
    need(actor_baseline['rc']==0 and actor_baseline['stdout'].splitlines()==[BOOT,'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'],'actual original baseline')
    need(not OUT.exists() and OUT.parent.resolve(strict=True)==OUT.parent,'create-only private host preservation')
    OUT.mkdir(mode=0o700)
    outputs=[put('result.original.json',result_raw),put('phone-actor.original.py',actor_raw),put('phone-request.original.json',request_raw),put('observer-source.original.py',source),put('observer-inputs.original.json',inputs_raw),put('targets.original.json',target_raw),put('failure-reference.original.json',ref_raw),put('original44-lock-source.original.json',baseline_raw)]
    for name,(raw,_) in operation_inputs.items():outputs.append(put(name+'.original',raw))
    error=None;checks=None;value=None;blobs={}
    try:
        need(op['phone']['rc']==0 and op['phone']['stderr']=='','actual observer complete zero exit')
        envelope=strict(op['phone']['stdout'].encode());need(envelope['schema']=='hepta.fc33.final05.parent-reconciliation.packet.v1' and envelope['private_originals'] is True and envelope['qualification_granted'] is False,'complete private observation envelope')
        frame=envelope['packet'];compressed=base64.b64decode(frame['base64'],validate=True)
        need(frame['encoding']=='zlib-base64' and len(compressed)==frame['compressed_bytes'] and sha(compressed)==frame['compressed_sha256'],'complete compressed frame')
        packet_raw=decode_zlib(compressed,frame['bytes'],frame['sha256']);value=strict(packet_raw);need(enc(value)==packet_raw,'canonical complete packet')
        outputs.append(put('packet.original.PRIVATE.json',packet_raw))
        for digest,row in value['original_blobs'].items():
            b=base64.b64decode(row['base64'],validate=True);need(len(b)==row['bytes'] and sha(b)==digest,'complete private blob')
            blobs[digest]=b;outputs.append(put('private-originals/'+digest+'.bin',b))
        checks=validate(value,inputs,cap_inputs,baseline,blobs,targets,reference)
    except BaseException as exc:error={'type':type(exc).__name__,'detail':str(exc)[:2048]}
    report={'schema':'hepta.fc33.final05.parent-observation-host-verification.v1',
            'state':'COMPLETE_FINITE_OBSERVATION_PRIVATELY_PRESERVED_NO_CLOSURE' if error is None else 'ORIGINALS_PRESERVED_VALIDATION_INCOMPLETE',
            'actual_result':result_pin,'actual_actor':actor_pin,'actual_request':request_pin,'actual_original_targets':target_pin,'actual_failure_reference':ref_pin,'actual_lock_source':baseline_pin,
            'actual_operation_inputs':{k:pin for k,(_,pin) in operation_inputs.items()},'output_descriptors':outputs,
            'phone_rc':op['phone']['rc'],'probe_state':None if value is None else value['state'],'host_validation_error':error,'checks':checks,
            'unique_private_blobs':len(blobs),'unique_private_blob_bytes':sum(map(len,blobs.values())),
            'private_bodies_in_public_report':False,'phone_calls_by_host_importer':0,'scope_closure':False,'cleanup_authorized':False,'component_qualified':False,'business_qualified':False}
    pin=put('HOST-VERIFICATION.PUBLIC.json',enc(report))
    print(json.dumps({'state':report['state'],'report':pin,'error':error,'phone_calls':0,'scope_closure':False},sort_keys=True))
    return 0 if error is None else 1

if __name__=='__main__':raise SystemExit(main())
