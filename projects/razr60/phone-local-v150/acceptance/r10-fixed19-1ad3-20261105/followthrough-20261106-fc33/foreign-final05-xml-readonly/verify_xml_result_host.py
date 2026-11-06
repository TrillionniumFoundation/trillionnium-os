#!/usr/bin/env python3
"""P4 host-only exact XML result import. All body originals stay private on P4."""
from pathlib import Path
import ast,base64,hashlib,json,os,shlex,stat,zlib
BASE=Path('/home/alex/razr60-local-model-v150')
LABEL='ng-fc33-final05-owned-xml-readonly01'
SOURCE_PIN=(16908,'0da3844a26c87a994f3c69e926d312f0e3fe944c8515e8824c960963fa2beed4')
REQUEST_PIN=(8361,'485e888fae619849d2d74e34c2cd630c1045509726eb8242e5d5382807109b7c')
RESULT_PIN=(138954,'00c8c8b2f78d8eef7b02ebaf5d71d049550a3200f3b6406bc6631e3fcf7c23d9')
PUBLIC=BASE/'fc33-final05-failed-scope-readonly01-import02/recovery-scope-derivation01/SENDER-XML-EXPECTED-PUBLIC.json'
OUT=BASE/'fc33-final05-owned-xml-readonly01-import01'
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
def read(p,pin=None,maximum=1048576):
    need(p.resolve(strict=True)==p,'canonical host source path')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,'host original type/link/size')
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(maximum+1)
        need(len(b)==a.st_size and full9(a)==full9(os.fstat(fd))==full9(p.lstat()),'host original full read bookend')
        if pin is not None:need((len(b),sha(b))==pin,'host original pinned bytes')
        return b,{'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':full9(a)}
    finally:os.close(fd)
def put(name,b):
    p=OUT/name;need(p.parent==OUT or OUT in p.parents,'private import namespace')
    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def unzip(z,size,digest,maximum):
    need(type(size) is int and 0<size<=maximum,'bounded decompression length')
    d=zlib.decompressobj();b=d.decompress(z,size+1)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(b)==size and sha(b)==digest,'complete pinned zlib original')
    return b
def metadata(m):need(type(m) is list and len(m)==9 and all(type(n) is int and n>=0 for n in m),'exact full9 integer shape')

result_raw,result_pin=read(BASE/'operations'/LABEL/'result.json',RESULT_PIN)
operation=strict(result_raw)
need(operation['label']==LABEL and operation['status']=='command_exited' and operation['model_decision'] is False and operation['native_task_result'] is False,'actual readonly actor result')
actor_raw,actor_pin=read(BASE/'ops/phone_once.py',(5652,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'))
request_raw,request_pin=read(BASE/'requests'/(LABEL+'.json'),REQUEST_PIN)
request=strict(request_raw)
need(set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==30,'exact original request shape')
need(operation['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),'exact reviewed actor root transformation')
args=shlex.split(request['command']);need(args[-5:-1]==['/usr/bin/python3','-I','-B','-c'] and not any('/su' in v for v in args[:-1]),'exact inner Python/no nested su')
loader=ast.parse(args[-1]);node=next(n for n in loader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='c' for t in n.targets))
zipped=base64.b64decode(ast.literal_eval(node.value.args[0]),validate=True)
source=unzip(zipped,*SOURCE_PIN,65535)
assignments={n.targets[0].id:n.value for n in ast.parse(source).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
inputs_raw=ast.literal_eval(assignments['INPUTS_RAW']);inputs=strict(inputs_raw)
need(len(inputs_raw)==6979 and sha(inputs_raw)=='e60399fc51486e454aad6d751e728ec1f8b001ce0e72be73d5eda52f4409e855'==ast.literal_eval(assignments['INPUTS_SHA']),'actual source embedded inputs exact')
public_raw,public_pin=read(PUBLIC,(11024,'1fbd5617faca1b85a47318a87b30578fe18111bb9db4129d85740aa3848de0cf'))
public=strict(public_raw)
need(inputs['rows']==[{k:r[k] for k in ('root_path','sequence','expected_bytes','expected_sha256','pin_basis','command_source')} for r in public['rows']],'exact full public provenance projection')
operation_inputs={}
for name in ('intent.json','baseline.json'):operation_inputs[name]=read(BASE/'operations'/LABEL/name)
intent=strict(operation_inputs['intent.json'][0]);baseline=strict(operation_inputs['baseline.json'][0])
need(intent['label']==LABEL and intent['request']==request and intent['request_sha256']==sha(request_raw) and intent['automatic_replay'] is False,'actual immutable intent')
need(baseline['rc']==0 and baseline['stdout'].splitlines()==['f8019f83-20a7-4f18-bea1-51c980621e4d','motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'],'actual phone baseline')
envelope=strict(operation['phone']['stdout'].encode())
need(envelope['schema']=='hepta.fc33.final05.xml-readonly.packet.v1' and envelope['private_originals'] is True and envelope['qualification_granted'] is False,'complete private XML packet envelope')
frame=envelope['packet'];compressed=base64.b64decode(frame['base64'],validate=True)
need(frame['encoding']=='zlib-base64' and len(compressed)==frame['compressed_bytes'] and sha(compressed)==frame['compressed_sha256'],'compressed packet exact descriptor')
packet_raw=unzip(compressed,frame['bytes'],frame['sha256'],8*1024*1024);value=strict(packet_raw)
need(enc(value)==packet_raw and value['schema']=='hepta.fc33.final05.xml-readonly.v1','canonical full packet')
blobs={}
for digest,row in value['original_blobs'].items():
    b=base64.b64decode(row['base64'],validate=True);need(len(b)==row['bytes'] and sha(b)==digest,'complete private original blob');blobs[digest]=b
need(OUT.parent.resolve(strict=True)==OUT.parent and not OUT.exists(),'create-only private preservation output')
OUT.mkdir(mode=0o700)
outputs=[put('result.original.json',result_raw),put('packet.original.PRIVATE.json',packet_raw),put('probe-source.original.py',source),put('probe-inputs.original.json',inputs_raw),put('phone-actor.original.py',actor_raw),put('phone-request.original.json',request_raw),put('sender-xml-public-manifest.original.json',public_raw)]
for name,(b,_) in operation_inputs.items():outputs.append(put(name+'.original',b))
for digest,b in blobs.items():outputs.append(put('private-originals/'+digest+'.xml',b))
error=None;checks=None
try:
    need(operation['phone']['rc']==0 and operation['phone']['stderr']=='' and value['state']=='COMPLETE_FRESH_XML_OBSERVATIONS_NO_CLOSURE' and value['terminal_error'] is None and value['errors']==[],'actual probe complete success')
    need(value['scope_label']=='root-r10-neg02-a1055-final05' and value['nonce']=='9b37081161d7bcbc3adf76d2e6ec7841' and value['public_inputs_sha256']==sha(inputs_raw),'exact failed scope identity')
    for key in ('xml_created','file_writes','file_deletes','ui_calls','model_requests','native_dispatches','signals_to_other_processes'):
        need(type(value[key]) is int and value[key]==0,'actual readonly '+key)
    for key in ('deletion_authorized','scope_closure','existing_scope_liveness_reproven_by_this_xml_probe','historical_absence_inferred','automatic_retry'):
        need(value[key] is False,'no inferred authority '+key)
    need(value['stdout_contains_private_xml_originals_do_not_publish'] is True,'private body marker')
    windows=value['windows'];parents=value['parent_profiles']
    need(len(windows)==2 and [w['index'] for w in windows]==[0,1] and windows[0]['rows']==windows[1]['rows'],'two complete exact XML windows')
    need(len(parents)==3 and parents[0]==parents[1]==parents[2],'complete common parent bookends')
    parent=parents[0];metadata(parent['metadata'])
    need(parent['path']=='/proc/1/root/data/local/tmp' and parent['names']==sorted(set(parent['names'])) and stat.S_ISDIR(parent['metadata'][2]),'actual bounded parent names/type')
    rows=windows[0]['rows'];expected=inputs['rows'];need(len(rows)==len(expected)==11,'all eleven exact source paths')
    matched=[];absent=[];blob_paths=set();read_bytes=0
    for row,original in zip(rows,expected):
        need(row['path']==original['root_path'],'fixed ordered XML path')
        leaf=Path(row['path']).name
        if row['state']=='COMPLETE_ORIGINAL_READ':
            m=row['metadata'];metadata(m)
            need(stat.S_ISREG(m[2]) and m[3:6]==[2000,2000,1] and (stat.S_IMODE(m[2]) & 0o7111)==0,'ordinary original-shell single-link XML')
            need(row['bytes']==m[6]==original['expected_bytes'] and row['sha256']==original['expected_sha256'],'actual complete original XML hash/size')
            need(row['matches_recorded_original_xml'] is True and row['ordinary_shell_owned_non_executable_file'] is True and row['raw_preserved_privately'] is True,'exact probe byte/owner predicates')
            need(row['sha256'] in blobs and len(blobs[row['sha256']])==row['bytes'] and leaf in parent['names'],'preserved XML and parent membership')
            base64.b64decode(row['selinux_raw_b64'],validate=True);blob_paths.add(row['sha256']);read_bytes+=row['bytes'];matched.append(row)
        else:
            need(row['state']=='OBSERVED_ENOENT' and row['errno']==2 and row['no_effect_inferred'] is False and row['parent_metadata']==parent['metadata'] and row['parent_selinux_raw_b64']==parent['selinux_raw_b64'] and leaf not in parent['names'],'leaf-only ENOENT with exact current parent')
            absent.append(row)
    need(blob_paths==set(blobs) and value['read_bytes']==2*read_bytes,'all complete bytes accounted without extra blobs')
    identity=value['collector_identity'];need(identity['boot_id']=='f8019f83-20a7-4f18-bea1-51c980621e4d' and base64.b64decode(identity['domain_raw_b64'],validate=True).rstrip(b'\0\n')==b'u:r:magisk:s0','same boot/Root domain')
    init=identity['init_stat_original'];raw=base64.b64decode(init['base64'],validate=True);head,tail=raw.rsplit(b') ',1)
    need(len(raw)==init['bytes'] and sha(raw)==init['sha256'] and head.startswith(b'1 (') and int(tail.split()[19])==0,'complete original native init stat')
    need(identity['gnu_root_metadata'][:2]!=identity['android_root_metadata'][:2],'distinct GNU Android root anchors')
    checks={'matched_existing_xml_count':len(matched),'exact_observed_enoent_count':len(absent),'matched_existing_xml_bytes':read_bytes,'read_bytes_two_windows':2*read_bytes,'matched_existing_files':matched,'absent_files':absent,'parent_profile':parent,'scope_liveness_reproved':False,'source_owned_xml_bytes_proven':True,'scope_closure':False,'cleanup_authorized':False}
except BaseException as exc:error={'type':type(exc).__name__,'detail':str(exc)[:2048]}
report={'schema':'hepta.fc33.final05.xml-readonly-host-verification.v1','state':'COMPLETE_XML_ORIGINALS_PRIVATELY_PRESERVED_NO_CLOSURE' if error is None else 'PRIVATE_ORIGINALS_PRESERVED_VALIDATION_INCOMPLETE',
        'actual_result':result_pin,'actual_actor':actor_pin,'actual_request':request_pin,'actual_operation_inputs':{name:pin for name,(_,pin) in operation_inputs.items()},'actual_public_manifest':public_pin,
        'phone_rc':operation['phone']['rc'],'probe_state':value['state'],'host_validation_error':error,'checks':checks,'output_descriptors':outputs,'preserved_unique_xml_blobs':len(blobs),'preserved_unique_xml_bytes':sum(map(len,blobs.values())),
        'private_bodies_in_public_report':False,'phone_calls_by_host_importer':0,'scope_closure':False,'cleanup_authorized':False}
pin=put('HOST-VERIFICATION.PUBLIC.json',enc(report))
print(json.dumps({'state':report['state'],'report':pin,'matched_xml_count':None if checks is None else checks['matched_existing_xml_count'],'absent_xml_count':None if checks is None else checks['exact_observed_enoent_count'],'matched_bytes':None if checks is None else checks['matched_existing_xml_bytes'],'error':error,'phone_calls':0,'scope_closure':False},sort_keys=True))
raise SystemExit(0 if error is None else 1)
