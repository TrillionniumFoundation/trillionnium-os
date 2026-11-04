#!/usr/bin/env python3
"""Generate the concrete r7 once-only operator for Root review. Never execute it."""
from pathlib import Path
import difflib,hashlib,json,os,re,subprocess
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r6-r2-finalization-r1/install_start_module_r6_r2_once.sh'
def sha(x):return hashlib.sha256(x).hexdigest()
def read(p,pin=None):
 p=Path(p);assert p.is_file() and not p.is_symlink() and p.stat().st_nlink==1
 raw=p.read_bytes()
 if pin is not None:assert sha(raw)==pin
 return raw
def put(p,b):
 if isinstance(b,str):b=b.encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
bundle=json.loads(read(D/'sealed-module-v150-r7-r1/BUNDLE.json'))
binding=json.loads(read(D/'sealed-module-v150-r7-r1/module/seal-binding.json'))
assert binding['module_id']=='trillionnium_hepta_phone_local_v150_r7_r1'
assert binding['host_source_and_input_review_complete'] is True and binding['phone_installation_authorized_by_host_seal'] is False
assert binding['original_task_and_draft_closure_required_before_install'] is True
qraw=read(D/'sealed-module-v150-r7-r1/module/evidence/R6-R2-ACTUAL-SERVICE-QUIESCENCE.json',binding['current_boot_r6_r2_service_quiescence']['result_sha256'])
quiet=json.loads(qraw)
assert quiet['state']=='FOUR_ORIGINAL_GROUPS_ABSENT_ORIGINAL_STATE_PRESERVED'
archive=bundle['archive'];manifest=bundle['module_manifest']
daily=[x for x in binding['payloads'] if x['path'].endswith('/provider-r7/source/daily_phone_local.py')]
assert len(daily)==1 and daily[0]['sha256']=='92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3'
original=read(OLD,'c261d2018c137940bdb42ec819987b3a1884b91e50f07f1ebb3c0f7ba5ea9714').decode()
s=original.replace('v150-r6-r2','v150-r7-r1').replace('v150_r6_r2','v150_r7_r1')
s=s.replace('module-r6-activation-r2','module-r7-activation-r1').replace('module-history-r6-r2','module-history-r7-r1')
s=s.replace('provider-r6-r2','provider-r7').replace('local-config-r6-r2.json','local-config-r7.json')
s=s.replace('New r6-r2 attempt','New r7-r1 attempt').replace('Install exact r6-r2 module','Install exact r7-r1 module')
s=s.replace('234698',str(archive['bytes'])).replace('9142783ef569c136d6fee89dd3b4f8fe5cfca0c0353cbe4bdbf4d69aaa79bb17',archive['sha256'])
s=s.replace('9e5a8c3f9a5a7f4426d109beba1073edcfa2dfe4712760e446054b04906afb4a',manifest['sha256'])
s=s.replace('713ff1089d9136062353e659e6f54193422f6c336f0c598dff5d12859cfac1c8',bundle['activation_payload']['sha256'])
s=s.replace('a8bd87b3d50c993b3e4ac7799ca66dd8e84cbd7925deb7e641e5cc66c1bdb7c1',binding['provider_source_seal_sha256'])
s=s.replace('0999a3609a89520ed8e1f550fa28c86959137d1edb98994f7ad78fe35db42a57',daily[0]['sha256'])
s=s.replace("'hepta.module-r6.transport-readiness.v1'","'hepta.module-r7.transport-readiness.v1'")
marker='[ ! -e "$BASE/provider-r7" ] && [ ! -L "$BASE/provider-r7" ]\n'
assert s.count(marker)==2
check=['# Root must separately close original task/HTTP worker/native receipt/draft before invocation.',
 '# Old r6-r2 groups already absent: do not send TERM or fabricate a supervisor exit.',
 'STOPPED_R6_R2=/data/adb/modules/trillionnium_hepta_phone_local_v150_r6_r2',
 'STOPPED_CLAIM=/data/adb/trillionnium-hepta-phone-local-v150-r6-r2/$BOOT',
 '[ -d "$STOPPED_R6_R2" ] && [ ! -L "$STOPPED_R6_R2" ]',
 '[ -d "$STOPPED_CLAIM" ] && [ ! -L "$STOPPED_CLAIM" ]',
 '[ -f "$STOPPED_R6_R2/disable" ] && [ ! -L "$STOPPED_R6_R2/disable" ]',
 '[ "$("$SYS/stat" -c \'%u:%g:%a:%h:%s\' "$STOPPED_R6_R2/disable")" = 0:0:600:1:0 ]',
 'stopped_manifest_sha=$("$SYS/sha256sum" "$STOPPED_R6_R2/MODULE-MANIFEST-v150-r6-r2.json")',
 '[ "${stopped_manifest_sha%% *}" = 9e5a8c3f9a5a7f4426d109beba1073edcfa2dfe4712760e446054b04906afb4a ]']
for role,identity in sorted(quiet['original_role_identities'].items()):
 assert role in ('supervisor','model','sidecar','provider')
 check.append('[ "$("$SYS/cat" "$STOPPED_CLAIM/'+role+'.identity")" = '+':'.join(map(str,identity))+' ]')
for name,row in sorted(quiet['original_service']['history_files'].items()):
 assert re.fullmatch(r'[A-Za-z0-9._-]+',name) and row['present'] is True and re.fullmatch('[0-9a-f]{64}',row['sha256'])
 assert row['uid']==row['gid']==0 and row['mode']==0o600
 check+=['[ -f "$STOPPED_CLAIM/'+name+'" ] && [ ! -L "$STOPPED_CLAIM/'+name+'" ]',
  '[ "$("$SYS/stat" -c \'%u:%g:%a:%h:%s\' "$STOPPED_CLAIM/'+name+'")" = 0:0:600:1:'+str(row['bytes'])+' ]',
  'stopped_record_sha=$("$SYS/sha256sum" "$STOPPED_CLAIM/'+name+'")',
  '[ "${stopped_record_sha%% *}" = '+row['sha256']+' ]']
for name in ('exit-code','terminal-scope','model.stop','sidecar.stop','provider.stop'):
 if name not in quiet['original_service']['history_files']:
  check.append('[ ! -e "$STOPPED_CLAIM/'+name+'" ] && [ ! -L "$STOPPED_CLAIM/'+name+'" ]')
s=s.replace(marker,'\n'.join(check)+'\n'+marker,1)
marker='write_once r6-r1-original-start-status \'failed_protocol_source_pin; original_exit74; no task or model request; independent quiescence verified.\'\n'
assert s.count(marker)==1
s=s.replace(marker,marker+"write_once r6-r2-original-service-quiescence-sha256 "+sha(qraw)+"\nwrite_once r6-r2-original-supervisor-exit-record-status '"+quiet['original_supervisor_exit_status']+"'\nwrite_once r6-r2-original-task-closure-scope 'Separate Root precondition; service census does not establish native/HTTP-worker/draft closure.'\n")
s=s.replace('22 pinned payload files verified;',str(bundle['new_provider_file_count'])+' pinned payload files verified;')
s=s.replace('All new module inputs,44 payloads,','All new module inputs,'+str(bundle['total_existing_and_new_payloads'])+' payloads,')
assert '/provider-r6-r2/source/' not in s and '/local-config-r6-r2.json' not in s
assert s.count(daily[0]['sha256'])==1 and 'kill -TERM' not in s and 'kill -KILL' not in s
p=D/'install_start_module_r7_r1_once.sh';pin=put(p,s)
subprocess.run(['/bin/sh','-n',str(p)],check=True)
diff=''.join(difflib.unified_diff(original.splitlines(True),s.splitlines(True),fromfile='r6-r2/installer',tofile='r7-r1/installer'))
dp=put(D/'INSTALLER-R7-R1-MINIMAL.diff',diff)
report={'schema':'hepta.module-r7-r1.install-operator-source.v1','installer':pin,'diff':dp,'module_manifest_sha256':manifest['sha256'],'archive':archive,'old_service_quiescence_sha256':sha(qraw),'phone_execution':False,'original_task_and_draft_closure_separate_root_gate':True,'model_requests':0}
put(D/'INSTALLER-SOURCE-SEAL.json',json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
