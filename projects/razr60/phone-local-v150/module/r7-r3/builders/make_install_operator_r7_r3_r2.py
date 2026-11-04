#!/usr/bin/env python3
"""Host-only new r7-r3 installer generation; never executes the generated phone code."""
from pathlib import Path
import base64,difflib,hashlib,json,os,re,subprocess
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r7-r2-finalization-r1/install_start_module_r7_r2_once.sh'
OLD_SHA='a6fad152446a80cd5cb4929337ee77021af9938b6848d8e85f44269d00dd6f62'
def sha(raw):return hashlib.sha256(raw).hexdigest()
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
def once(s,old,new):
 assert s.count(old)==1,(old,s.count(old))
 return s.replace(old,new,1)
bundle=json.loads(read(D/'sealed-module-v150-r7-r3/BUNDLE.json'))
M=D/'sealed-module-v150-r7-r3/module'
binding=json.loads(read(M/'seal-binding.json'))
manifest=json.loads(read(M/'MODULE-MANIFEST-v150-r7-r3.json',bundle['module_manifest']['sha256']))
assert binding['module_id']=='trillionnium_hepta_phone_local_v150_r7_r3'
assert binding['host_source_and_input_review_complete'] is True and binding['phone_installation_authorized_by_host_seal'] is False
assert binding['existing_provider_source_config_not_overwritten'] is True and manifest['provider_payload_mode']=='verify_existing_only_no_overwrite'
retirement=binding['current_boot_r7_r2_retirement']
qraw=read(M/'evidence/R7-R2-RETIREMENT.json',retirement['result_sha256']);q=json.loads(qraw)
oraw=read(M/'evidence/R7-R2-RETIREMENT-OPERATOR.json',retirement['operator_sha256']);op=json.loads(oraw)
capture=json.loads(read(M/'evidence/R7-R2-RETIREMENT-CAPTURE.json',retirement['capture_sha256']))
captured={}
for row in capture['files']:
 raw=base64.b64decode(row['data_base64'],validate=True);assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
 assert row['path'] not in captured;captured[row['path']]=raw
assert captured['RETIREMENT.json']==qraw and captured['OPERATOR-RESULT.json']==oraw
before=json.loads(captured['PREFLIGHT.json']);assert before['preserved_state']==q['preserved_state']
assert op['supervisor_original_exit_code']==143 and q['original_effect_count']==4
assert len(q['preserved_state']['executor_original_actions'])==4
live=binding['live_policy_sha256'];assert re.fullmatch('[0-9a-f]{64}',live)
archive=bundle['archive'];mp=bundle['module_manifest']
guard=read(D/'installer_preserved_state_check.py.template').decode()
for name,value in {'__RETIREMENT_SHA256__':sha(qraw),'__OPERATOR_SHA256__':sha(oraw),'__PREFLIGHT_SHA256__':sha(captured['PREFLIGHT.json']),'__LIVE_POLICY_SHA256__':live}.items():guard=once(guard,name,value)
compile(guard,'installer-preserved-state-check','exec')
assert "Path('/sys/fs/selinux/" not in guard
assert guard.count("'/proc/1/root/sys/fs/selinux/enforce'")==2 and guard.count("'/proc/1/root/sys/fs/selinux/policy'")==2
original=read(OLD,OLD_SHA).decode()
s=original
for old,new in [('v150-r7-r2','v150-r7-r3'),('v150_r7_r2','v150_r7_r3'),('V150_R7_R2','V150_R7_R3'),
 ('module-r7-activation-r2','module-r7-activation-r3'),('module-history-r7-r2','module-history-r7-r3'),
 ('module-start-r7-r2','module-start-r7-r3'),('module-r7-r2.transport-readiness','module-r7-r3.transport-readiness')]:
 s=s.replace(old,new)
s=s.replace('New r7-r2 attempt','New r7-r3 attempt').replace('Install exact r7-r2 module','Install exact r7-r3 module')
s=once(s,'[ "$("$SYS/stat" -c \'%s\' "$ARCHIVE")" = 2138009 ]','[ "$("$SYS/stat" -c \'%s\' "$ARCHIVE")" = '+str(archive['bytes'])+' ]')
assert s.count('f0c7abb46bc0b119e9296390ad845f6ff53992e669f747fb9a558206eb2003cf')==2
s=s.replace('f0c7abb46bc0b119e9296390ad845f6ff53992e669f747fb9a558206eb2003cf',archive['sha256'])
s=once(s,'1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd',mp['sha256'])
s=s.replace('439ebd30f0e003cc4b0f5c08cade8c59b922eedcd3a3302169323a7f0397f089',live)
s=once(s,'12a74aa99d56d780f6e3a6e420d5480db35ab7399b58f9b3b840839741be46e8',binding['census_fix']['sha256'])
start="<<'R7R2_READONLY_PY'\n";end='\nR7R2_READONLY_PY\n'
assert s.count(start)==s.count(end)==1
a=s.index(start);b=s.index(end,a)
s=s[:a]+"<<'R7R3_READONLY_PY'\n"+guard.rstrip('\n')+'\nR7R3_READONLY_PY\n'+s[b+len(end):]
checks=['# Exact current r7-r2 retirement originals; no signal, restart or deletion here.',
 'STOPPED_R7_R2=/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r2',
 'STOPPED_R7_R2_CLAIM=/data/adb/trillionnium-hepta-phone-local-v150-r7-r2/$BOOT',
 '[ -d "$STOPPED_R7_R2" ] && [ ! -L "$STOPPED_R7_R2" ]',
 '[ -d "$STOPPED_R7_R2_CLAIM" ] && [ ! -L "$STOPPED_R7_R2_CLAIM" ]',
 '[ -f "$STOPPED_R7_R2/disable" ] && [ ! -L "$STOPPED_R7_R2/disable" ]',
 '[ "$("$SYS/stat" -c \'%u:%g:%a:%h:%s\' "$STOPPED_R7_R2/disable")" = 0:0:600:1:0 ]',
 'stopped_current_manifest_sha=$("$SYS/sha256sum" "$STOPPED_R7_R2/MODULE-MANIFEST-v150-r7-r2.json")',
 '[ "${stopped_current_manifest_sha%% *}" = 1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd ]']
for name,raw in sorted(captured.items()):
 if not name.startswith('original-service/'):continue
 base=name.split('/',1)[1];assert re.fullmatch('[A-Za-z0-9._-]+',base)
 checks+=['[ -f "$STOPPED_R7_R2_CLAIM/'+base+'" ] && [ ! -L "$STOPPED_R7_R2_CLAIM/'+base+'" ]',
 '[ "$("$SYS/stat" -c \'%u:%g:%a:%h:%s\' "$STOPPED_R7_R2_CLAIM/'+base+'")" = 0:0:600:1:'+str(len(raw))+' ]',
 'stopped_current_record_sha=$("$SYS/sha256sum" "$STOPPED_R7_R2_CLAIM/'+base+'")',
 '[ "${stopped_current_record_sha%% *}" = '+sha(raw)+' ]']
marker='[ -d "$BASE/provider-r7" ] && [ ! -L "$BASE/provider-r7" ]\n'
s=once(s,marker,'\n'.join(checks)+'\n'+marker)
s=once(s,'write_once started-utc "$("$SYS/date" -u +%Y-%m-%dT%H:%M:%SZ)"\n',
 'write_once started-utc "$("$SYS/date" -u +%Y-%m-%dT%H:%M:%SZ)"\nwrite_once r7-r2-actual-retirement-sha256 '+sha(qraw)+'\nwrite_once r7-r2-original-supervisor-exit 143\n')
s=s.replace('write_once four-permission-live-policy-sha256','write_once three-atom-live-policy-sha256')
s=once(s,'# Exactly two original safe-terminal actions were verified by the pinned readonly guard; do not delete them.\n[ "$("$SYS/ls" -A "$DATA/actions" | "$BB" wc -l)" -eq 2 ]',
 '# Exactly four original safe-terminal actions were verified by the pinned readonly guard; do not delete them.\n[ "$("$SYS/ls" -A "$DATA/actions" | "$BB" wc -l)" -eq 4 ]')
assert s.count('"$BB" setsid "$BB" sh "$MOD/service.sh"')==1
assert 'cp" -R "$UNPACK/provider-payload' not in s and '> "$BASE/local-config-r7.json"' not in s
assert '[ -z "$("$SYS/ls" -A "$DATA/actions")" ]' not in s
assert '--live' not in s and 'kill -TERM' not in s and 'kill -KILL' not in s
assert "Path('/sys/fs/selinux/" not in s
pin=put(D/'install_start_module_r7_r3_once.sh',s)
subprocess.run(['/bin/sh','-n',pin['path']],check=True)
diff=''.join(difflib.unified_diff(original.splitlines(True),s.splitlines(True),fromfile='r7-r2/frozen-first-installer',tofile='r7-r3/new-installer'))
dp=put(D/'INSTALLER-R7-R3-MINIMAL.diff',diff);guardpin=put(D/'installer_preserved_state_check.py',guard)
checks={'single_service_start':True,'no_provider_or_config_write':True,'no_policy_load':True,'nonempty_four_actions_verified':True,
 'old_original_action_and_run_bytes_read_before_start':True,'fresh_two_censuses_esrch_and_locks':True,
 'gnu_selinux_reads_use_existing_proc1_root_view':True,'no_prior_failed_attempt_replay':True,
 'tar_metadata_normalized_by_sealer':bundle['tar_all_members_root_owned_prescribed_modes'],
 'inherited_startup_identity_and_cleanup_control_flow':True,'shell_syntax':True}
report={'schema':'hepta.module-r7-r3.install-operator-source.v1','installer':pin,'diff':dp,'readonly_guard':guardpin,
 'parent_installer_sha256':OLD_SHA,'module_manifest_sha256':mp['sha256'],'archive':archive,'retirement_sha256':sha(qraw),'policy_sha256':live,
 'source_checks':checks,'phone_execution':False,'model_requests':0,'new_nonce':False,
 'qualification':'Host source only. Root must perform the single install/start and independently capture original readiness; fresh health and business remain unqualified.'}
put(D/'INSTALLER-SOURCE-SEAL.json',json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
