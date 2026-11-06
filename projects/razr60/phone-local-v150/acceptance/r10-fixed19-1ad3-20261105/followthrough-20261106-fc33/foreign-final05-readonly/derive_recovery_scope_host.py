#!/usr/bin/env python3
"""P4 host-only scope derivation and private sender preservation; no phone call."""
from pathlib import Path
import base64,gzip,hashlib,json,os,re,stat,xml.etree.ElementTree as ET

ROOT=Path('/home/alex/razr60-local-model-v150/fc33-final05-failed-scope-readonly01-import02')
SENDER=Path('/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150')
LABEL='root-r10-neg02-a1055-final05'
GNU='/var/lib/trillionnium/owner-open/phone-local-v150'
ANDROID='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150'
HOME=GNU+'/native-guard-r10-r1/'+LABEL
def need(ok,why):
    if not ok:raise ValueError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def full9(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def strict(b):
    def pairs(rows):
        d={}
        for k,v in rows:need(k not in d,'duplicate JSON');d[k]=v
        return d
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(p,maximum):
    need(p.resolve(strict=True)==p,'canonical host path')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,'host original type/size')
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(maximum+1)
        need(len(b)==a.st_size and full9(a)==full9(os.fstat(fd))==full9(p.lstat()),'host original changed')
        return b,{'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':full9(a)}
    finally:os.close(fd)
def put(out,name,b):
    p=out/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def canonical_phone(path):
    return GNU+path[len(ANDROID):] if path==ANDROID or path.startswith(ANDROID+'/') else path

report_raw,report_pin=read(ROOT/'HOST-VERIFICATION.json',65536)
need(len(report_raw)==25011 and sha(report_raw)=='0e84d8aa6f2d49c479f6d1bf5fabd5bafc57ed505b342d7bfeec51bc7b232ddf','actual complete host reader proof')
report=strict(report_raw);need(report['state']=='FULL_FRESH_CAPTURE_VERIFIED_NO_CLOSURE' and report['host_validation_error'] is None,'fresh reader success required')
packet_raw,packet_pin=read(ROOT/'packet.original.json',32*1024*1024)
need(len(packet_raw)==14514847 and sha(packet_raw)=='7944f356067f54060dbbac1a5b152370606ed55c8e8474cc6b94b6aedf66240b','actual fresh packet original')
packet=strict(packet_raw);e=packet['evidence'];rows=e['private_before']['entries']
canonical={};aliases={};absent=[]
for path,row in rows.items():
    if row['kind']=='absent':absent.append(row);continue
    p=canonical_phone(path);need(p==HOME or p.startswith(HOME+'/'),'one actual owned home only')
    item={k:v for k,v in row.items() if k!='path'}
    if p in canonical:need(canonical[p]==item,'GNU/Android alias content/full9/label differs')
    canonical[p]=item;aliases.setdefault(p,[]).append(path)
files={p:r for p,r in canonical.items() if r['kind']=='file'}
dirs={p:r for p,r in canonical.items() if r['kind']=='directory'}
stage_paths={r['path'] for r in e['stage_members']['members']}
runtime_names={'STAGE-COMPLETE.json','RETIRED-BASELINE-VERIFIED.json','BASELINE-INVENTORY.json',
 'DETACHED-LAUNCH-INTENT.json','DETACHED-LAUNCH-RESULT.json','LIFECYCLE-ATTEMPT.json','LIFECYCLE-ENDED.json',
 'LIFECYCLE-FAILURE.json','PORT-RESERVED.json','SUPERVISOR.json','sidecar.SPAWN-INTENT.json','sidecar.SPAWNED.json',
 'sidecar.barrier.json','sidecar.ADMIT.json','sidecar.TERM-INTENT.json','sidecar.JOINED.json','supervisor.stdout','supervisor.stderr',
 'executor/server.lock','executor/sidecar.stdout','executor/sidecar.stderr'}
expected_files=stage_paths|{HOME+'/'+n for n in runtime_names}
expected_dirs={HOME+'/'+n if n else HOME for n in ('','inputs','inputs/production','package','package/reference','package/source','claims','operator','executor','executor/actions')}
need(set(files)==expected_files and len(files)==82 and set(dirs)==expected_dirs and len(dirs)==10,'actual minimal scope is not exact61 plus21 lifecycle files/10dirs')
need(len(absent)==1 and absent[0]['path']=='/proc/1/root/data/local/tmp/hepta-native-guard-9b37081161d7bcbc3adf76d2e6ec7841','exact absent fixture')
source_names=sorted(p.name for p in SENDER.iterdir());before=full9(SENDER.lstat())
need(len(source_names)==144 and stat.S_ISDIR(SENDER.lstat().st_mode),'complete known sender directory member count')
originals={};summaries=[];xml=[];total=0
pattern=re.compile(r'test ! -e (/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-([1-9][0-9]*).xml) && uiautomator dump \1 && cat \1\Z')
for name in source_names:
    body,pin=read(SENDER/name,512*1024);total+=len(body);need(total<=8*1024*1024,'sender total byte budget')
    originals[name]={'descriptor':pin,'base64':base64.b64encode(body).decode()}
    value=strict(body)
    command=value.get('command') if isinstance(value,dict) else None
    if command is None:continue
    match=pattern.fullmatch(command)
    if match:
        need(value['rc']==0 and value['stderr']=='','one actual successful scope XML dump/read')
        stdout=value['stdout'].encode('utf-8');at=stdout.find(b'<?xml ')
        need(at>=0 and stdout.find(b'<?xml ',at+1)<0,'one complete recorded XML suffix')
        xmlraw=stdout[at:];tree=ET.fromstring(xmlraw);need(tree.tag=='hierarchy','actual UI hierarchy original')
        need(0<len(xmlraw)<=262144,'bounded original XML')
        xml.append({'android_path':match.group(1),'root_path':'/proc/1/root'+match.group(1),'sequence':int(match.group(2)),
            'expected_bytes':len(xmlraw),'expected_sha256':sha(xmlraw),'pin_basis':'exact UTF-8 recorded stdout suffix after one XML declaration',
            'command_source':pin,'command':command,'recorded_phone_rc':value['rc'],
            'recorded_xml_base64_private':base64.b64encode(xmlraw).decode()})
    elif 'hepta-natural-'+LABEL+'-v150-' in command and '.xml' in command:
        need(False,'unrecognized scope XML command shape')
need(full9(SENDER.lstat())==before and sorted(p.name for p in SENDER.iterdir())==source_names,'sender directory changed during complete read')
for name,row in originals.items():
    need(full9((SENDER/name).lstat())==row['descriptor']['metadata'],'sender original changed after read')
need(len(xml)==len({r['root_path'] for r in xml}),'one creation command per exact XML path')
xml.sort(key=lambda r:r['sequence'])
prepared=strict(base64.b64decode(originals['COMPONENT-PREPARED-NO-SEND.json']['base64'],validate=True))
failure=strict(base64.b64decode(originals['ACTOR-FAILURE.json']['base64'],validate=True))
restore=strict(base64.b64decode(originals['DRAFT-RESTORE-RESULT.json']['base64'],validate=True))
need(prepared['nonce']=='9b37081161d7bcbc3adf76d2e6ec7841' and prepared['owner_request_sha256']=='99dc5822937e8d50b604e39bd9da678d4ae80d2fab8cf3d32d61fd27ebe5ac8f'
     and prepared['send_attempt_count']==0 and prepared['provider_started_by_sender'] is False,'actual sender prepared scope')
need(failure=={'error_type':'AssertionError','error':'Fixed component ready observation failed; no Send','automatic_send_retry':False},'actual no Send failure')
need(restore['state']=='ORIGINAL_DRAFT_RESTORED' and restore['restore_attempts']==1 and restore['original_draft_submitted'] is False,'actual draft restore original')
out=ROOT/'recovery-scope-derivation01';out.mkdir(mode=0o700)
private={'schema':'hepta.fc33.final05.sender-private-preservation.v1','sender_root':str(SENDER),'directory_metadata':before,
         'files':originals,'xml_expected_private':xml,'phone_calls':0}
private_pin=put(out,'SENDER-ORIGINALS.PRIVATE.json.gz',gzip.compress(enc(private),mtime=0))
public_xml=[{k:v for k,v in row.items() if k!='recorded_xml_base64_private'} for row in xml]
xmlpin=put(out,'SENDER-XML-EXPECTED-PUBLIC.json',enc({'schema':'hepta.fc33.final05.sender-xml-exact-paths.v1',
    'rows':public_xml,'private_preservation':private_pin,'current_phone_file_existence_proven':False,
    'current_phone_full9_proven':False,'deletion_authorized':False}))
scope={'schema':'hepta.fc33.final05.recovery-scope-candidate.v1','state':'EXACT_SCOPE_DERIVED_NO_DELETE_AUTHORIZATION',
    'fresh_packet':packet_pin,'host_verification':report_pin,'private_home':HOME,
    'private_files':[dict(path=p,aliases=aliases[p],**r) for p,r in sorted(files.items())],
    'private_directories':[dict(path=p,aliases=aliases[p],**r) for p,r in sorted(dirs.items(),key=lambda x:(-x[0].count('/'),x[0]))],
    'transport_files':e['transport'],'fixture_absent_original':absent[0],
    'private_file_count':82,'private_directory_count':10,'transport_file_count':4,
    'core_recovery_exact_file_count':86,'sender_xml_separate_pending_count':len(xml),
    'sender_private_preservation':private_pin,'sender_xml_public_manifest':xmlpin,
    'sender_historical_scope':{'prepared_original':originals['COMPONENT-PREPARED-NO-SEND.json']['descriptor'],
      'failure_original':originals['ACTOR-FAILURE.json']['descriptor'],'restore_original':originals['DRAFT-RESTORE-RESULT.json']['descriptor'],
      'send_attempt_count':0,'restore_attempt_count':1,'original_draft_submitted':False,
      'current_host_sender_process_termination_independently_proven_by_this_program':False},
    'expected_shared_parent_effect_after_exact_home_removal':{'remove_one_name':LABEL,'expected_remaining_name_count':16,'expected_nlink':18},
    'required_pre_mutation_rechecks':['exact full tree and all full9/hash/label identities','all15 declared lock groups held',
      'original44 entire inventory unchanged','same boot and known two identities absent by complete proc and signal0',
      'complete private originals retained outside phone with verified reader','no foreign/new entries','explicit Root authorization'],
    'out_of_scope':['all historical44 roots','all host sender originals','all public native boundaries and case terminal records','absent fixture'],
    'scope_closure':False,'component_qualified':False,'business_qualified':False,'deletion_authorized':False,
    'historical_supervisor_wait_not_fabricated':True,'phone_calls':0}
scope_pin=put(out,'RECOVERY-SCOPE-CANDIDATE.json',enc(scope))
print(json.dumps({'scope':scope_pin,'xml_manifest':xmlpin,'private_sender_preservation':private_pin,
    'private_files':82,'private_directories':10,'transport_files':4,'sender_files_preserved':len(originals),'sender_bytes':total,
    'xml_sequences':[r['sequence'] for r in xml],'xml_current_state':'NOT_YET_OBSERVED','phone_calls':0,'deletion_authorized':False},sort_keys=True))
