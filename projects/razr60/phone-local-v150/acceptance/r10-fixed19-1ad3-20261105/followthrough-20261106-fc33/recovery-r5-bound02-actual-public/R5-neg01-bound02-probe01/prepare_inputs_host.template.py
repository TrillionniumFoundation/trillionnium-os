#!/usr/bin/env python3
"""Derive one unstarted bound02 read-only input set from complete host originals.

This program only reads P4 host files and creates a new private host archive.
It does not open a device connection, execute target sources, or signal tasks.
"""
from pathlib import Path
import ast,base64,gzip,hashlib,io,json,os,re,stat,tarfile,zlib
import xml.etree.ElementTree as ET
FROZEN = None
HOST_ORIGINALS_RAW = None

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
def read(pin,limit):
    p=Path(pin['path']);need(p.resolve(strict=True)==p,'canonical pinned host path')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==1000 and 0<=a.st_size<=limit,'private bounded regular host original')
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(limit+1)
        need(len(b)==a.st_size and full9(a)==full9(os.fstat(fd))==full9(p.lstat()),'host original full9/read bookend')
        row={'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':full9(a)}
        for k in ('bytes','sha256','metadata'):
            if k in pin:need(row[k]==pin[k],'host original pin differs '+k)
        return b,row
    finally:os.close(fd)
def decompress(raw,cap):
    d=zlib.decompressobj(31);b=d.decompress(raw,cap+1)
    need(len(b)<=cap and d.eof and not d.unconsumed_tail and not d.unused_data,'complete single bounded gzip')
    return b
def archive_members(raw):
    plain=decompress(raw,16*1024*1024);files={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for row in archive:
            p=Path(row.name)
            need(len(files)<80 and str(p)==row.name and not p.is_absolute() and '..' not in p.parts and '\0' not in row.name and '\\' not in row.name and row.name not in files and row.isreg() and not row.pax_headers and row.uid==row.gid==0 and row.mode==0o600 and row.mtime==0 and 0<=row.size<=8*1024*1024,'canonical archive member')
            stream=archive.extractfile(row);need(stream is not None,'archive member original');b=stream.read(row.size+1);need(len(b)==row.size,'complete archive original');files[row.name]=b
    need(len(files)==62 and sum(map(len,files.values()))<=8*1024*1024,'exact62 bounded archive')
    canonical=io.BytesIO()
    with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,b in sorted(files.items()):
            row=tarfile.TarInfo(name);row.mode=0o600;row.uid=row.gid=0;row.mtime=0;row.size=len(b);archive.addfile(row,io.BytesIO(b))
    need(plain==canonical.getvalue(),'exact canonical tar original')
    return files
def original(name):
    row=HOST[name];b=base64.b64decode(row['base64'],validate=True);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'embedded actual host original '+name);return b
def terminal_proof():
    plan=strict(original('ROOT-PLAN.original.json'));manifest_raw=original('RUNTIME-MANIFEST.original.json');manifest=strict(manifest_raw)
    need(plan['package']['sha256']==sha(manifest_raw) and plan['package']['bytes']==len(manifest_raw),'plan exact runtime manifest')
    sender=original('send_new_native_guard_task_r10_r4.py');r=next(r for r in manifest['files'] if r['path']=='source/send_new_native_guard_task_r10_r4.py')
    need(r['bytes']==len(sender) and r['sha256']==sha(sender),'sender runtime source pin')
    source=sender.decode();tree=ast.parse(source)
    calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess']
    need(len(calls)==1 and ast.unparse(calls[0])=='subprocess.run(ssh, input=source.encode(), capture_output=True, timeout=600)','actual synchronous sender subprocess contract')
    need("receipt = {'rc': result.returncode, 'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')}" in source and "receipt = {'UNKNOWN': str(error), 'automatic_replay': False}" in source,'completed result versus exception paths')
    intent=strict(original('sender-execute.INTENT.json'));child=strict(original('sender-execute.CHILD.json'));capture=strict(original('sender-execute.OUTPUT-CAPTURE.json'))
    need(intent['phase']=='sender-execute' and intent['argv'][:3]==['/usr/bin/python3','-I','-B'] and intent['argv'][3]==str(Path(plan['package']['path']).parent/'source/send_new_native_guard_task_r10_r4.py') and intent['argv'][4]==FROZEN['label'] and intent['argv'][-1]=='--execute-once' and intent['maximum_starts']==1 and intent['automatic_retry'] is False and intent['signals_on_timeout'] is False,'exact one-use sender host invocation')
    need(child['pid']==child['pgid']==child['sid']==58537 and child['source_intent_sha256']==sha(original('sender-execute.INTENT.json')),'actual sender host identity')
    need(capture['pid']==58537 and capture['phase']=='sender-execute' and capture['source_intent_sha256']==child['source_intent_sha256'] and capture['child_wait_returned'] is True and capture['child_returncode']==0 and capture['stdout_eof'] is True and capture['stderr_eof'] is True and capture['worker_joined'] is True and capture['prefix_only_or_unknown'] is False and capture['error'] is None and capture['persist_errors']==capture['pipe_close_errors']==[] and capture['signals_sent']==0,'actual complete wait/dualEOF/join')
    receipt_raw=original('SENDER-RESULT.original.json');receipt=strict(receipt_raw)
    need(capture['captured']=={'stdout':{'bytes':len(receipt_raw),'sha256':sha(receipt_raw)},'stderr':{'bytes':0,'sha256':sha(b'')}},'original complete output identity')
    need(set(receipt)=={'rc','stdout','stderr'} and receipt['rc']==2 and receipt['stderr']=='','normal synchronous remote rc2 result')
    terminal=strict(receipt['stdout']);need(terminal['state']=='PRE_SEND_OR_ACTOR_FAILURE' and terminal['out']==FROZEN['sender_root'] and terminal['prompt_sha256']==plan['request']['sha256'] and terminal['send_attempt_count']==0 and terminal['automatic_replay'] is False and terminal['business_success_verified'] is False and terminal['retirement_resolution_sha256']==plan['sender_retirement_resolution']['sha256'],'same precise failed sender terminal')
    need(terminal['draft_restore']=={'state':'ORIGINAL_DRAFT_RESTORED','restore_attempts':1,'original_draft_submitted':False},'actual exact restoration terminal')
    failure=strict(original('ROOT-FAILURE.original.json'));host=next(r for r in failure['host_cleanup']['host_children'] if r['phase']=='sender-execute')
    need(host['output_capture']==capture and host['child_wait_returned'] is True and host['returncode']==0 and host['cleanup_errors']==[] and host['signals_sent']==0 and capture['remote_terminal_or_cleanup_proven'] is False and host['remote_terminal_or_cleanup_proven'] is False,'same joined host child, preserve generic original flag')
    phases=[r['phase'] for r in failure['steps']]
    need(phases==['prepare-material','host-stage-material','phone-push-material','phone-copy-material','phone-push-stage-source','phone-copy-stage-source','phone-stage','sender-preview','sender-prepared'] and failure['root_fixture_attempts']==[] and failure['detail']=='original phase failed; no replay: sender-prepared','actual failure stopped before launch and fixtures')
    need(all(r['returncode']==0 for r in failure['steps'][:-1]) and failure['steps'][-1]['returncode']!=0,'all prior phases joined and prepared gate failed')
    wrapper=strict(original('phone-stage.stdout.original.json'));need(wrapper['actor_rc']==0 and wrapper['wrapper']['phone']['rc']==0 and wrapper['wrapper']['phone']['stderr']=='','actual successful phone stage wrapper')
    stage_raw=wrapper['wrapper']['phone']['stdout'].encode();need(stage_raw==original('STAGE-COMPLETE.original.json'),'same actual stage stdout original')
    stage=strict(stage_raw);need(stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES' and stage['members']==62 and stage['lease_sha256']==FROZEN['lease_sha256'] and stage['package_sha256']==FROZEN['package_sha256'] and stage['service_launches']==stage['model_requests']==stage['native_tasks']==0,'actual stage no-role result')
    return {'schema':'hepta.fc33.bound02.sender-terminal-proof.v1','state':'ACTUAL_SYNCHRONOUS_SENDER_TERMINAL_BEFORE_PREPARED_NO_CASE_CREDIT','host_pid':58537,'host_wait_returncode':0,'synchronous_remote_rc':2,'send_attempt_count':0,'draft_restore_attempts':1,'host_both_eof':True,'host_worker_joined':True,'root_phase_sequence':phases,'root_fixture_attempts':[], 'launch_phase_reached':False,'historical_remote_pid_or_wait_invented':False,'generic_original_remote_terminal_or_cleanup_proven_preserved':False,'scope_closure':False,'component_qualified':False,'business_qualified':False}
def put(name,b):
    p=DEST/name;need(p.parent==DEST,'one new private host namespace')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    return {'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':full9(p.lstat())}

need(FROZEN is not None and HOST_ORIGINALS_RAW is not None,'actual host source bindings required')
HOST=strict(HOST_ORIGINALS_RAW);need(sha(HOST_ORIGINALS_RAW)==FROZEN['host_originals_sha256'],'full embedded host original package')
terminal=terminal_proof()
archive,archive_pin=read(FROZEN['archive'],8*1024*1024);files=archive_members(archive)
stage_source,stage_source_pin=read(FROZEN['stage_source'],65536)
need(stage_source==files['package/source/stage_component.py']==original('stage_component.py'),'complete actual stage source equal runtime original')
lease_raw=files['LEASE.json'];lease=strict(lease_raw);manifest_raw=files['package/MANIFEST.json'];manifest=strict(manifest_raw)
need(lease_raw==original('LEASE.original.json') and manifest_raw==original('RUNTIME-MANIFEST.original.json') and len(manifest['files'])==38,'exact lease and runtime38 originals')
expected={'LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json','inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json','inputs/service-inputs.original.json','inputs/PRIOR-BOUNDARY.original.json'}
expected.update('package/'+r['path'] for r in manifest['files']);reviewed=strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json']);need(len(reviewed)==15,'exact reviewed15 production source count');expected.update('inputs/production/'+n for n in reviewed)
need(set(files)==expected,'archive exact owned member namespace')
for r in manifest['files']:need(len(files['package/'+r['path']])==r['bytes'] and sha(files['package/'+r['path']])==r['sha256'],'each runtime original pin')
for name,h in reviewed.items():need(re.fullmatch('[a-z_]+\\.py',name) and sha(files['inputs/production/'+name])==h,'each production source original')
sender_zip,sender_zip_pin=read(FROZEN['sender_archive'],4*1024*1024);sender=strict(decompress(sender_zip,8*1024*1024))
sender_public_raw,sender_public_pin=read(FROZEN['sender_public'],65536);sender_public=strict(sender_public_raw)
need(sender['source_path']==FROZEN['sender_root'] and len(sender['files'])==23 and sender_public['original_file_count']==23 and sender_public['original_private_archive']['sha256']==sha(sender_zip),'actual complete sender preservation chain')
sender_root=Path(sender['source_path']);need(sender_root.resolve(strict=True)==sender_root and full9(sender_root.lstat())==sender['source_metadata'] and sorted(os.listdir(sender_root))==sender['names'],'same complete ended sender namespace')
xml=[];pattern=re.compile(r'test ! -e (/data/local/tmp/hepta-natural-'+re.escape(FROZEN['label'])+r'-v150-([1-9][0-9]*).xml) && uiautomator dump \1 && cat \1\Z')
for name,r in sorted(sender['files'].items()):
    b=base64.b64decode(r['base64'],validate=True);need(len(b)==r['descriptor']['bytes'] and sha(b)==r['descriptor']['sha256'],'private sender original exact bytes');live,pin=read(r['descriptor'],8*1024*1024);need(live==b,'ended sender original changed')
    value=strict(b);command=value.get('command') if isinstance(value,dict) else None
    if type(command) is not str:continue
    match=pattern.fullmatch(command)
    if match:
        need(value['rc']==0 and value['stderr']=='','actual successful exact XML dump');stdout=value['stdout'].encode();at=stdout.find(b'<?xml ');need(at>=0 and stdout.find(b'<?xml ',at+1)<0,'one complete XML stdout suffix');raw=stdout[at:];need(ET.fromstring(raw).tag=='hierarchy' and 0<len(raw)<=262144,'bounded complete XML original')
        xml.append({'path':'/proc/1/root'+match.group(1),'bytes':len(raw),'sha256':sha(raw),'sequence':int(match.group(2)),'command_source':pin,'pin_basis':'exact UTF-8 recorded stdout suffix after one XML declaration'})
    elif 'hepta-natural-'+FROZEN['label']+'-v150-' in command and '.xml' in command:need(False,'unrecognized current-scope XML command')
need(full9(sender_root.lstat())==sender['source_metadata'] and sorted(os.listdir(sender_root))==sender['names'],'ended sender namespace final bookend')
xml.sort(key=lambda r:r['sequence']);need([r['sequence'] for r in xml]==list(range(1,12)),'exact11 sender XML paths')
need(not any(sender_public['specific_sender_records_present'].values()),'no prepared or Send record in complete sender namespace')
baseline_raw,baseline_host=read(FROZEN['baseline_host'],2*1024*1024);baseline=strict(baseline_raw)
need(len(baseline['roots'])==44 and len(baseline['entries'])==3823 and baseline['file_bytes_hashed']==44353573,'actual original44 baseline')
DEST=Path(FROZEN['destination']);need(DEST.parent.resolve(strict=True)==DEST.parent and not DEST.exists(),'create-only private host preservation destination');DEST.mkdir(mode=0o700)
retained={}
for name,raw in [('component-inputs.tar.gz',archive),('stage_component.original.py',stage_source),('STAGE-COMPLETE.original.json',original('STAGE-COMPLETE.original.json')),('HOST-ORIGINALS.PRIVATE.json',HOST_ORIGINALS_RAW),('SENDER-ORIGINALS.PRIVATE.json.gz',sender_zip),('BASELINE44.original.json',baseline_raw)]:retained[name]=put(name,raw)
proof_pin=put('SENDER-TERMINAL-PROOF.json',enc(terminal))
home=FROZEN['phone_home'];android_home=FROZEN['android_home'];gnu_stage=FROZEN['gnu_stage'];android_stage=FROZEN['android_stage'];label=FROZEN['label']
transport=[{'path':gnu_stage+'/'+label+'.tar.gz','bytes':len(archive),'sha256':sha(archive),'owner':[0,0,[384]]},{'path':android_stage+'/hepta-native-guard-'+label+'.tar.gz','bytes':len(archive),'sha256':sha(archive),'owner':[2000,2000,[438]]},{'path':gnu_stage+'/'+label+'.stage.py','bytes':len(stage_source),'sha256':sha(stage_source),'owner':[0,0,[384]]},{'path':android_stage+'/hepta-native-guard-'+label+'.stage.py','bytes':len(stage_source),'sha256':sha(stage_source),'owner':[2000,2000,[438]]}]
stage=strict(original('STAGE-COMPLETE.original.json'));need(stage['archive_source']==transport[0]['path'],'same transport archive path');transport[0]['metadata']=stage['archive_metadata']
expected_dirs=sorted({home,home+'/claims',home+'/operator',home+'/executor'}|{home+'/'+str(Path(n).parent) for n in files if str(Path(n).parent)!='.'})
need(len(expected_dirs)==9,'exact9 unique private directories')
inputs={'schema':'hepta.fc33.bound02.unstarted-readonly-inputs.v1','label':label,'nonce':FROZEN['nonce'],'lease':lease,'lease_sha256':sha(lease_raw),'package_sha256':sha(manifest_raw),'runtime_files':manifest['files'],'archive_members':[{'relative_path':n,'bytes':len(b),'sha256':sha(b)} for n,b in sorted(files.items())],'archive_path':transport[0]['path'],'transport':transport,'stage_complete':{'bytes':len(original('STAGE-COMPLETE.original.json')),'sha256':sha(original('STAGE-COMPLETE.original.json'))},'expected_directories':expected_dirs,'phone_home':home,'android_home':android_home,'fixture':'/proc/1/root/data/local/tmp/hepta-native-guard-'+FROZEN['nonce'],'baseline':FROZEN['baseline'],'boundary':FROZEN['boundary'],'baseline_roots':baseline['roots'],'parent_paths':[str(Path(home).parent),str(Path(android_home).parent),gnu_stage,android_stage,'/proc/1/root/data/local/tmp'],'sender_xml':xml,'stage_directory_identity':stage['created_directories'],'sender_terminal_proof':proof_pin,'preservation':retained,'sender_public_original':sender_public_pin,'historical_remote_PID_not_invented':True,'phone_scope_current_state_not_yet_observed':True,'deletion_authorized':False}
inputs_pin=put('INPUTS.json',enc(inputs));report={'schema':'hepta.fc33.bound02.host-input-derivation.v1','state':'EXACT_SOURCE_ONLY_READONLY_INPUTS_NOT_PHONE_OBSERVED','inputs':inputs_pin,'archive_members':62,'runtime_files':38,'expected_home_files':63,'expected_directories':9,'transport_files':4,'sender_xml_files':11,'expected_current_owned_file_count':78,'terminal_proof':proof_pin,'preservation':retained,'baseline_host_original':baseline_host,'source_archive':archive_pin,'source_stage':stage_source_pin,'source_sender_archive':sender_zip_pin,'phone_calls':0,'scope_closure':False,'component_qualified':False,'business_qualified':False,'deletion_authorized':False}
report_pin=put('HOST-DERIVATION.json',enc(report));print(json.dumps({'report':report_pin,'inputs':inputs_pin,'sender_terminal_proof':proof_pin,'phone_calls':0,'scope_closure':False},sort_keys=True))
