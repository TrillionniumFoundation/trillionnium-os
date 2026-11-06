#!/usr/bin/env python3
"""Root-only admission: complete private host preservation, then exact actor once.

--verify-only reads and verifies only. --execute-once additionally publishes one
host admission and execs the already pinned phone actor. No retries or fallback.
"""
from pathlib import Path
import ast,base64,hashlib,json,lzma,os,shlex,stat,sys,time,zlib
BASE=Path('/home/alex/razr60-local-model-v150')
LABEL='ng-fc33-final05-owned-scope-recovery01'
REQUEST=BASE/'requests'/(LABEL+'.json')
REQUEST_PIN=(43834,'243f961660aab37fa2c8e7b23e6936379fabddc42d5304704b05907f30f8898a')
SOURCE_PIN=(275947,'30172f90d4cd2cb3042a6c998a3e501d0eaba1ba3bf83bf1198a6fa19821a622')
ACTOR=BASE/'ops/phone_once.py'
ACTOR_PIN=(5652,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22')
ADMISSION=BASE/'fc33-final05-owned-scope-recovery01-HOST-ADMISSION.json'
HOST_INPUTS=BASE/'fc33-final05-recovery-inputs01'
TARGET_PIN=(183176,'0aad40b0feac77b963547d90b27ed49eb260d3a2c14fd9a9dbfe4a61550597d1')
TARGET_METADATA=[66306,39846600,33152,1000,1000,1,183176,1793990364709986368,1793990364709986368]
PRESERVE_PIN=(39397,'c9b92b2ff119466d95ba5b32ef99e009616e319385b064cb63433c83b863afcf')
MAX_HOST_FILE=32*1024*1024
MAX_HOST_READ=64*1024*1024
READ_BYTES=0
CHECKED={}

def need(v,s):
    if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def strict(b):
    def pairs(rows):
        d={}
        for k,v in rows:need(k not in d,'duplicate JSON');d[k]=v
        return d
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def full9(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def read_original(path,size,digest,metadata=None,mode=0o600):
    global READ_BYTES
    p=Path(path);need(p.is_absolute() and p.resolve(strict=True)==p and str(p).startswith(str(BASE)+'/'),'canonical declared P4 host original')
    need(type(size) is int and 0<=size<=MAX_HOST_FILE and len(digest)==64,'bounded pinned host original')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==1000 and stat.S_IMODE(a.st_mode)==mode and a.st_size==size,'host original owner/mode/link/size')
        if metadata is not None:need(full9(a)==metadata,'exact original full9 differs')
        chunks=[];count=0
        while True:
            b=os.read(fd,min(1048576,size+1-count))
            if not b:break
            count+=len(b);READ_BYTES+=len(b);need(count<=size and READ_BYTES<=MAX_HOST_READ,'whole host preservation read budget');chunks.append(b)
        raw=b''.join(chunks)
        need(len(raw)==size and sha(raw)==digest and full9(a)==full9(os.fstat(fd))==full9(p.lstat()) and p.resolve(strict=True)==p,'complete exact host original bookend')
        row={'path':str(p),'bytes':size,'sha256':digest,'metadata':full9(a)}
        if str(p) in CHECKED:need(CHECKED[str(p)]==row,'repeated host input changed')
        CHECKED[str(p)]=row;return raw,row
    finally:os.close(fd)
def descriptor(d):return read_original(d['path'],d['bytes'],d['sha256'],d.get('metadata'))
def absent(path):
    need(path.parent.resolve(strict=True)==path.parent,'canonical absence parent')
    try:path.lstat()
    except OSError as exc:need(exc.errno==2,'unknown host absence')
    else:need(False,'already existing namespace, reconcile only: '+str(path))
def bounded_unzip(raw,size=None,maximum=16*1024*1024):
    d=zlib.decompressobj(31);out=d.decompress(raw,maximum+1)
    need(len(out)<=maximum and d.eof and not d.unused_data and not d.unconsumed_tail,'complete bounded original gzip')
    if size is not None:need(len(out)==size,'gzip original length')
    return out

def verify():
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000,'configured P4 operator identity')
    absent(BASE/'operations'/LABEL);absent(ADMISSION)
    actor_raw,actor_pin=read_original(ACTOR,*ACTOR_PIN,
        [66306,39753173,33200,1000,1000,1,5652,1793710413391340155,1793710413391359586],mode=0o660)
    request_raw,request_pin=read_original(REQUEST,*REQUEST_PIN);request=strict(request_raw)
    need(set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==80,'one reviewed shell/root request')
    argv=shlex.split(request['command'])
    expected_prefix=['/data/adb/magisk/busybox','env','-i','PATH=/usr/bin:/bin:/usr/libexec/trillionnium','PYTHONHOME=/usr','PYTHONDONTWRITEBYTECODE=1','LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu','LANG=C.UTF-8','LC_ALL=C.UTF-8','TMPDIR=/var/lib/trillionnium/owner-open/tmp','NO_COLOR=1','TERM=dumb','/data/adb/magisk/busybox','chroot','/data/trillionnium/owner-open/root','/usr/bin/python3','-I','-B','-c']
    need(argv[:-1]==expected_prefix,'exact reviewed GNU route and one actor-owned Root wrapper')
    loader=ast.parse(argv[-1]);node=next(n for n in loader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='c' for t in n.targets))
    compressed=base64.b64decode(ast.literal_eval(node.value.args[0]),validate=True)
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024)
    source=decoder.decompress(compressed,max_length=SOURCE_PIN[0]+1)
    need(decoder.eof and not decoder.unused_data and (len(source),sha(source))==SOURCE_PIN,'complete actual phone source inverse, no execution')
    assignments={n.targets[0].id:n.value for n in ast.parse(source).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    cap=ast.literal_eval(assignments['CAP_SOURCE_RAW']);target_embedded=ast.literal_eval(assignments['TARGETS_RAW']);authority=strict(ast.literal_eval(assignments['AUTHORITY_RAW']))
    need((len(cap),sha(cap))==(63646,'70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44') and ast.literal_eval(assignments['OPERATION_LABEL'])==LABEL,'exact original readonly module and recovery namespace')
    targets_raw,target_pin=read_original(HOST_INPUTS/'TARGETS.json',*TARGET_PIN,TARGET_METADATA);targets=strict(targets_raw)
    need(targets_raw==target_embedded and authority['targets']==target_pin,'source embedded target equals exact actual full9 public original')
    preservation_raw,preservation_pin=read_original(HOST_INPUTS/'PRESERVATION.json',*PRESERVE_PIN);preservation=strict(preservation_raw)
    need(authority['preservation']=={k:preservation_pin[k] for k in ('path','bytes','sha256')}
        and preservation['target']=={k:target_pin[k] for k in ('path','bytes','sha256')},'exact source authority and preservation target pin')
    need(len(preservation['all_read_p4_originals'])==106 and len(preservation['host_originals'])==9,'all complete captured and sender host originals')
    bodies={};retained={}
    for row in preservation['all_read_p4_originals']+preservation['host_originals']:
        b,pin=descriptor(row)
        if '/originals/' in row['path'] or '/private-originals/' in row['path']:
            retained[row['sha256']]={'bytes':row['bytes'],'path':row['path']}
        if row['path'].startswith(str(HOST_INPUTS/'sender')+'/'):bodies[Path(row['path']).name]=b
    need(len(retained)==88,'all88 private scope/XML originals read exactly')
    need(len(targets['files'])==97 and len({r['path'] for r in targets['files']})==97 and len(targets['directories'])==10,'actual97/10 target namespace')
    for row in targets['files']:
        need(row['sha256'] in retained and retained[row['sha256']]['bytes']==row['bytes'],'every97 target pair matches verified private bytes')
    need({r['sha256']:r['bytes'] for r in targets['preserved_blob_descriptors']}=={h:r['bytes'] for h,r in retained.items()},'exact descriptor set of all88 retained blobs')
    raw_sender,sender_pin=descriptor(authority['sender_private_preservation'])
    sender=strict(bounded_unzip(raw_sender));need(len(sender['files'])==144 and len(sender['xml_expected_private'])==11,'complete144 private sender original set')
    sender_bodies={}
    for name,row in sender['files'].items():
        b=base64.b64decode(row['base64'],validate=True);pin=row['descriptor']
        need(len(b)==pin['bytes'] and sha(b)==pin['sha256'] and Path(pin['path']).name==name,'complete sender original body descriptor')
        sender_bodies[name]=b
    forbidden={'SEND.once.json','SEND.MONOTONIC-INTENT.json','SEND.result.json','SEND.unknown.json','SEND.MONOTONIC-WINDOW.json','SEND-NATIVE-LATENCY.json'}
    need(not set(sender_bodies)&forbidden,'original sender has no Send intent/result records')
    prepared=strict(sender_bodies['COMPONENT-PREPARED-NO-SEND.json']);failure=strict(sender_bodies['ACTOR-FAILURE.json']);restore=strict(sender_bodies['DRAFT-RESTORE-RESULT.json'])
    need(prepared['nonce']=='9b37081161d7bcbc3adf76d2e6ec7841' and prepared['owner_request_sha256']=='99dc5822937e8d50b604e39bd9da678d4ae80d2fab8cf3d32d61fd27ebe5ac8f'
        and prepared['send_attempt_count']==0 and prepared['provider_started_by_sender'] is False,'actual original sender zero-Send scope')
    need(failure=={'error_type':'AssertionError','error':'Fixed component ready observation failed; no Send','automatic_send_retry':False},'actual original sender failure')
    need(restore['state']=='ORIGINAL_DRAFT_RESTORED' and restore['restore_attempts']==1 and restore['original_draft_submitted'] is False,'actual private original draft restoration')
    need(sha(bodies['SENDER-TERMINAL-PROOF.json'])=='9f33402d6d3bf1b7911f0cf1d53cb47f0900c9cff1f39e4590dbc3b57bc5d5fe','reviewed independent sender termination proof')
    terminal=strict(bodies['SENDER-TERMINAL-PROOF.json']);host_plan=strict(bodies['ROOT-PLAN.original.json']);host_manifest=strict(bodies['SENDER-SOURCE-MANIFEST.original.json'])
    source_row=next(r for r in host_manifest['files'] if r['path']=='source/send_component_host_navigation_once.py')
    need(host_plan['source_package']['sha256']==sha(bodies['SENDER-SOURCE-MANIFEST.original.json']) and source_row['sha256']==sha(bodies['send_component_host_navigation_once.original.py']),'actual original host source chain')
    receipt=strict(bodies['SENDER-ACTUAL-RESULT.original.json']);summary=strict(receipt['stdout'])
    need(bodies['SENDER-ACTUAL-RESULT.original.json']==bodies['sender-stdout.original'] and receipt['rc']==2 and receipt['stderr']=='' and summary['state']=='PRE_SEND_OR_ACTOR_FAILURE' and summary['send_attempt_count']==0,'original synchronous remote sender terminal')
    need(terminal['host_identity']['wait_returned'] is True and terminal['host_identity']['both_eof'] is True and terminal['host_identity']['worker_joined'] is True and terminal['synchronous_remote_sender']['rc']==2 and terminal['generic_original_remote_terminal_or_cleanup_proven_preserved'] is False,'original host join proof, no rewrite of historical generic flag')
    for key in ('scope_report','xml_report','scope_packet','sender_terminal_proof'):
        raw,_=descriptor(authority[key])
        if key=='scope_report':
            v=strict(raw);need(v['host_validation_error'] is None and v['checks']['original44_full_inventory_equal'] is True and v['checks']['bounded_no_claim_or_action_records'] is True and v['checks']['fresh_known_groups_absent_two_windows'] is True,'actual complete readonly scope report')
        elif key=='xml_report':
            v=strict(raw);need(v['host_validation_error'] is None and v['checks']['matched_existing_xml_count']==11 and v['checks']['exact_observed_enoent_count']==0,'actual complete original XML report')
    # Reopen canonical path identities after the entire read set: no replaced
    # source, request, TARGETS, private bundle or original may pass this bookend.
    for path,row in CHECKED.items():
        p=Path(path);need(p.resolve(strict=True)==p and full9(p.lstat())==row['metadata'],'whole host original set final full9/canonical bookend')
    absent(BASE/'operations'/LABEL);absent(ADMISSION)
    checked=sorted(CHECKED.values(),key=lambda r:r['path'])
    return {'schema':'hepta.fc33.final05.recovery-host-admission.v1','state':'COMPLETE_PRIVATE_PRESERVATION_VERIFIED_ACTOR_NOT_YET_EXECUTED',
        'operation_label':LABEL,'request':request_pin,'actor':actor_pin,'phone_source':{'bytes':SOURCE_PIN[0],'sha256':SOURCE_PIN[1]},'targets':target_pin,'preservation':preservation_pin,
        'authority':authority,'checked_host_originals':checked,'checked_host_original_count':len(checked),'host_read_bytes':READ_BYTES,
        'source_sender_original_count':144,'private_blob_count':88,'file_target_count':97,'directory_target_count':10,'all_target_pairs_privately_retained':True,
        'source_sender_closed_and_send0':True,'original_draft_restored':True,'historical_supervisor_wait_invented':False,
        'actor_execution_result_not_known_from_admission':True,'component_qualified':False,'business_qualified':False,'automatic_retry':False,'private_bodies_in_admission':False}

def publish_admission(value):
    need(ADMISSION.parent.resolve(strict=True)==ADMISSION.parent,'canonical admission parent')
    raw=enc(value);need(len(raw)<=262144,'bounded public admission record')
    fd=os.open(ADMISSION,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    parent=os.open(ADMISSION.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)
    saved,_=read_original(ADMISSION,len(raw),sha(raw));need(saved==raw,'exact create-only host admission readback')

def main():
    need(sys.argv[1:] in (['--verify-only'],['--execute-once']),'explicit verify-only or Root execute-once mode required')
    value=verify()
    if sys.argv[1]=='--verify-only':
        print(json.dumps({'state':value['state'],'checked_host_original_count':value['checked_host_original_count'],'host_read_bytes':value['host_read_bytes'],'files':97,'directories':10,'private_blobs':88,'sender_originals':144,'phone_calls':0,'admission_written':False,'automatic_retry':False},sort_keys=True));return 0
    publish_admission(value)
    # Root dispatches this single reviewed executable branch. execv preserves
    # the original actor's one-JSON stdout, exit status and create-only intent.
    os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(ACTOR),LABEL,str(REQUEST)])
    raise RuntimeError('execv returned unexpectedly; never retry')
if __name__=='__main__':raise SystemExit(main())
