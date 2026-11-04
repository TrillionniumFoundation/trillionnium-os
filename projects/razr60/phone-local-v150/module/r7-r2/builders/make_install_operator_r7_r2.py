#!/usr/bin/env python3
"""Generate only a new Root-reviewed installer from the frozen r7-r1 operator; never execute phone code."""
from pathlib import Path
import base64,difflib,hashlib,json,os,re,subprocess
D=Path(__file__).resolve().parent;B=D.parent
OLD=B/'module-r7-r1-finalization-r1/install_start_module_r7_r1_once.sh'
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
bundle=json.loads(read(D/'sealed-module-v150-r7-r2/BUNDLE.json'))
M=D/'sealed-module-v150-r7-r2/module'
binding=json.loads(read(M/'seal-binding.json'))
manifest=json.loads(read(M/'MODULE-MANIFEST-v150-r7-r2.json',bundle['module_manifest']['sha256']))
assert binding['module_id']=='trillionnium_hepta_phone_local_v150_r7_r2'
assert binding['host_source_and_input_review_complete'] is True and binding['phone_installation_authorized_by_host_seal'] is False
assert binding['existing_provider_source_config_not_overwritten'] is True and manifest['provider_payload_mode']=='verify_existing_only_no_overwrite'
retirement=binding['current_boot_r7_r1_retirement']
qraw=read(M/'evidence/R7-R1-RETIREMENT.json',retirement['result_sha256']);q=json.loads(qraw)
oraw=read(M/'evidence/R7-R1-RETIREMENT-OPERATOR.json',retirement['operator_sha256']);op=json.loads(oraw)
capture=json.loads(read(M/'evidence/R7-R1-RETIREMENT-CAPTURE.json',retirement['capture_sha256']))
captured={}
for row in capture['files']:
 raw=base64.b64decode(row['data_base64'],validate=True);assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
 assert row['path'] not in captured;captured[row['path']]=raw
assert captured['RETIREMENT.json']==qraw and captured['OPERATOR-RESULT.json']==oraw
before=json.loads(captured['PREFLIGHT.json'])
assert before['preserved_state']==q['preserved_state']
assert op['supervisor_original_exit_code']==143
live=binding['live_policy_sha256'];assert re.fullmatch('[0-9a-f]{64}',live)
archive=bundle['archive'];mp=bundle['module_manifest']
guard=read(D/'installer_preserved_state_check.py.template').decode()
for name,value in {'__RETIREMENT_SHA256__':sha(qraw),'__OPERATOR_SHA256__':sha(oraw),'__PREFLIGHT_SHA256__':sha(captured['PREFLIGHT.json']),'__LIVE_POLICY_SHA256__':live}.items():
 guard=once(guard,name,value)
compile(guard,'installer-preserved-state-check','exec')
original=read(OLD,'<PRIVATE_BOUND_SHA256_001_REQUIRED>').decode()
s=original.replace('v150-r7-r1','v150-r7-r2').replace('v150_r7_r1','v150_r7_r2')
s=s.replace('module-r7-activation-r1','module-r7-activation-r2').replace('module-history-r7-r1','module-history-r7-r2')
s=s.replace('New r7-r1 attempt','New r7-r2 attempt').replace('Install exact r7-r1 module and new provider payload','Install exact r7-r2 module; verify unchanged existing provider payload')
s=once(s,'[ "$("$SYS/stat" -c \'%s\' "$ARCHIVE")" = 276950 ]','[ "$("$SYS/stat" -c \'%s\' "$ARCHIVE")" = '+str(archive['bytes'])+' ]')
s=s.replace('91a4a30c9b32eba545542ec3a1baa1701447ef8796f092f8f90afdcda4fae220',archive['sha256'])
s=once(s,'c0e31ecac9168218e7b6a622e4a3df138859743bd83911add42c32906d173a06',mp['sha256'])
s=once(s,'05756784090a574be850a068576fbded2842f3fa8c1af0aa5b430f875c78a31f',live)
s=once(s,'0adb90db6fc4eab253ab9f96641d1ea5f689372dfdde31c9d39760d3d6c35897',binding['census_fix']['sha256'])
marker='[ ! -e "$BASE/provider-r7" ] && [ ! -L "$BASE/provider-r7" ]\n'
assert s.count(marker)==2
checks=['# r7-r1 retirement is exact observed history; never stop/restart it here.',
 'STOPPED_R7_R1=/data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r1',
 'STOPPED_R7_CLAIM=/data/adb/trillionnium-hepta-phone-local-v150-r7-r1/$BOOT',
 '[ -d "$STOPPED_R7_R1" ] && [ ! -L "$STOPPED_R7_R1" ]',
 '[ -d "$STOPPED_R7_CLAIM" ] && [ ! -L "$STOPPED_R7_CLAIM" ]',
 '[ -f "$STOPPED_R7_R1/disable" ] && [ ! -L "$STOPPED_R7_R1/disable" ]',
 '[ "$("$SYS/stat" -c \'%u:%g:%a:%h:%s\' "$STOPPED_R7_R1/disable")" = 0:0:600:1:0 ]',
 'stopped_manifest_sha=$("$SYS/sha256sum" "$STOPPED_R7_R1/MODULE-MANIFEST-v150-r7-r1.json")',
 '[ "${stopped_manifest_sha%% *}" = c0e31ecac9168218e7b6a622e4a3df138859743bd83911add42c32906d173a06 ]']
for name,raw in sorted(captured.items()):
 if not name.startswith('original-service/'):continue
 base=name.split('/',1)[1]
 assert re.fullmatch('[A-Za-z0-9._-]+',base)
 checks+=['[ -f "$STOPPED_R7_CLAIM/'+base+'" ] && [ ! -L "$STOPPED_R7_CLAIM/'+base+'" ]',
  '[ "$("$SYS/stat" -c \'%u:%g:%a:%h:%s\' "$STOPPED_R7_CLAIM/'+base+'")" = 0:0:600:1:'+str(len(raw))+' ]',
  'stopped_record_sha=$("$SYS/sha256sum" "$STOPPED_R7_CLAIM/'+base+'")',
  '[ "${stopped_record_sha%% *}" = '+sha(raw)+' ]']
checks+=['[ -d "$BASE/provider-r7" ] && [ ! -L "$BASE/provider-r7" ]',
 '[ "$("$SYS/readlink" -f "$BASE/provider-r7")" = "$BASE/provider-r7" ]',
 '[ "$("$SYS/stat" -c \'%u:%g:%a\' "$BASE/provider-r7")" = 0:0:700 ]',
 '[ -f "$BASE/local-config-r7.json" ] && [ ! -L "$BASE/local-config-r7.json" ]']
s=s.replace(marker,'\n'.join(checks)+'\n',1)
s=once(s,'[ ! -e "$BASE/local-config-r7.json" ] && [ ! -L "$BASE/local-config-r7.json" ]\n','')
m='write_once started-utc "$("$SYS/date" -u +%Y-%m-%dT%H:%M:%SZ)"\n'
s=once(s,m,m+"write_once r7-r1-actual-retirement-sha256 "+sha(qraw)+"\nwrite_once r7-r1-original-supervisor-exit 143\nwrite_once four-permission-live-policy-sha256 "+live+"\n")
preflight=r'''# Recheck exact retained terminal actions and original state without opening any IPC connection.
"$BB" timeout -s TERM -k 3 25 "$BB" env -i \
 PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONPATH=/usr/libexec/trillionnium/owner-open PYTHONHOME=/usr \
 PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu \
 LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb \
 "$BB" chroot "$ROOT" /usr/bin/python3 -B - > "$OUT/preserved-state-preflight.json" 2> "$OUT/preserved-state-preflight.stderr" <<'R7R2_READONLY_PY'
__GUARD__
R7R2_READONLY_PY
[ ! -s "$OUT/preserved-state-preflight.stderr" ]
'''
preflight=once(preflight,'__GUARD__',guard.rstrip('\n'))
s=once(s,'UNPACK=$OUT/unpacked\n',preflight+'UNPACK=$OUT/unpacked\n')
s=once(s,'[ -z "$("$SYS/ls" -A "$DATA/actions")" ]',
 '# Exactly two original safe-terminal actions were verified by the pinned readonly guard; do not delete them.\n[ "$("$SYS/ls" -A "$DATA/actions" | "$BB" wc -l)" -eq 2 ]')
start=s.index('# Only the new provider-r7 tree/config are installed. Service inputs are reused.')
end=s.index('# New module only. No existing module or history directory is overwritten.',start)
verification=['# Every r7 provider/config/service file already exists. Verify bytes and metadata only.']
for row in manifest['included_provider_files']:
 target=row['android_target'];rel=row['archive_path']
 assert re.fullmatch('/data/trillionnium/owner-open/state/phone-local-v150/[A-Za-z0-9._/-]+',target)
 assert '..' not in Path(rel).parts and not rel.startswith('/')
 verification+=['[ -f "'+target+'" ] && [ ! -L "'+target+'" ]',
  '[ "$("$SYS/readlink" -f "'+target+'")" = "'+target+'" ]',
  '[ "$("$SYS/stat" -c \'%u:%g:%a:%h:%s\' "'+target+'")" = 0:0:600:1:'+str(row['bytes'])+' ]',
  'existing_payload_sha=$("$SYS/sha256sum" "'+target+'")',
  '[ "${existing_payload_sha%% *}" = '+row['sha256']+' ]',
  '"$SYS/cmp" "$UNPACK/provider-payload/'+rel+'" "'+target+'" >/dev/null 2>&1',
  'exact_label "'+target+'" u:object_r:trillionnium_owner_open_state_file:s0']
verification+=['(cd "$BASE" && "$SYS/sha256sum" -c "$UNPACK/provider-payload/provider-payload.sha256") > "$OUT/existing-provider-hash.stdout" 2> "$OUT/existing-provider-hash.stderr"','']
s=s[:start]+'\n'.join(verification)+s[end:]
s=once(s,"write_once provider-installed '22 pinned payload files verified; new provider tree/config installed, existing service inputs verified unchanged.'",
 "write_once provider-verified-existing '22 existing pinned provider/config/service files verified; no existing payload write, relabel, chmod or chown.'")
s=once(s,"write_once original-retirement-status partial_then_independent_remaining_roles_recovery",
 "write_once historical-r5-retirement-status partial_then_independent_remaining_roles_recovery\nwrite_once current-r7-retirement-status original_four_groups_absent_state_preserved")
s=s.replace("'hepta.module-r7.transport-readiness.v1'","'hepta.module-r7-r2.transport-readiness.v1'")
assert s.count('"$BB" setsid "$BB" sh "$MOD/service.sh"')==1
assert 'cp" -R "$UNPACK/provider-payload' not in s and '> "$BASE/local-config-r7.json"' not in s
assert '[ -z "$("$SYS/ls" -A "$DATA/actions")" ]' not in s
assert '--live' not in s and 'kill -TERM' not in s and 'kill -KILL' not in s
pin=put(D/'install_start_module_r7_r2_once.sh',s)
subprocess.run(['/bin/sh','-n',pin['path']],check=True)
diff=''.join(difflib.unified_diff(original.splitlines(True),s.splitlines(True),fromfile='r7-r1/frozen-installer',tofile='r7-r2/new-installer'))
dp=put(D/'INSTALLER-R7-R2-MINIMAL.diff',diff)
guardpin=put(D/'installer_preserved_state_check.py',guard)
checks={'single_service_start':True,'no_provider_or_config_write':True,'no_policy_load':True,'nonempty_two_actions_verified':True,
 'old_original_action_and_run_bytes_read_before_start':True,'fresh_two_censuses_esrch_and_locks':True,
 'tar_metadata_normalized_by_sealer':bundle['tar_all_members_root_owned_prescribed_modes'],
 'inherited_startup_identity_and_cleanup_control_flow':True,'shell_syntax':True}
report={'schema':'hepta.module-r7-r2.install-operator-source.v1','installer':pin,'diff':dp,'readonly_guard':guardpin,
 'module_manifest_sha256':mp['sha256'],'archive':archive,'retirement_sha256':sha(qraw),'policy_sha256':live,
 'source_checks':checks,'phone_execution':False,'model_requests':0,'new_nonce':False,
 'qualification':'Host source only. Root must perform the single install/start and independently capture original readiness; fresh health and business remain unqualified.'}
put(D/'INSTALLER-SOURCE-SEAL.json',json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
