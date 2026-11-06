#!/usr/bin/env python3
"""Derive the one new host admission guard without publishing or executing it."""
from pathlib import Path
import ast,difflib,hashlib,json
D=Path(__file__).resolve().parent;O=D/'candidate01'
OLD=D.parent/'R5-final05-recovery01/candidate02'
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def put(name,b):
    p=O/name
    if p.exists():assert p.read_bytes()==b
    else:p.write_bytes(b)
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
old=(OLD/'HOST-PRE-DISPATCH.py').read_bytes()
assert (len(old),sha(old))==(14670,'52f29b97c655b96106a2220b8f6a6f689fda53a0cfff992e439186d2e9468bca')
verifier=(D.parent/'R5-final05-parent-reconcile-probe02/import_parent_observer_host_v4.py').read_bytes()
assert (len(verifier),sha(verifier))==(22485,'cebb4cbe8244826208c17011e1838a31c24349dc3dd3ce37cc3f2cae5c8c9d0d')
extension=(D/'host_guard_reconciliation_extension.py').read_bytes();ast.parse(extension)
s=old.decode();replacements={
 "LABEL='ng-fc33-final05-owned-scope-recovery01'":"LABEL='ng-fc33-final05-owned-scope-recovery02'",
 "ADMISSION=BASE/'fc33-final05-owned-scope-recovery01-HOST-ADMISSION.json'":"ADMISSION=BASE/'fc33-final05-owned-scope-recovery02-HOST-ADMISSION.json'",
 "REQUEST_PIN=(43834,'243f961660aab37fa2c8e7b23e6936379fabddc42d5304704b05907f30f8898a')":"REQUEST_PIN=(49592,'16e3ad935ad485e94146c5b35521b297694d3431ac3955014aa4b08e2c2db425')",
 "SOURCE_PIN=(275947,'30172f90d4cd2cb3042a6c998a3e501d0eaba1ba3bf83bf1198a6fa19821a622')":"SOURCE_PIN=(358086,'94ab728a7fd4adb0ba4d4d7d5dc3c84cdad8923e73b4bd0cd87d5159bf6f0dc1')",
 "    # Reopen canonical path identities after the entire read set: no replaced":"    reconciliation_check=verify_parent_reconciliation(source,assignments,authority,targets)\n    # Reopen canonical path identities after the entire read set: no replaced",
 "        'authority':authority,'checked_host_originals':checked,":"        'authority':authority,'parent_reconciliation':reconciliation_check,'checked_host_originals':checked,",
 "'private_blobs':88,'sender_originals':144,'phone_calls':0,":"'private_blobs':88,'sender_originals':144,'reconciliation_verified':value['parent_reconciliation']['complete_current_parent_profiles_revalidated_from_private_packet'],'derived_targets_sha256':value['parent_reconciliation']['derived_targets_sha256'],'phone_calls':0,",
}
for oldvalue,newvalue in replacements.items():assert s.count(oldvalue)==1;s=s.replace(oldvalue,newvalue)
insertion='RECONCILIATION_VALIDATOR_RAW='+repr(verifier)+'\n\n'+extension.decode()+'\n\n'
assert s.count('def verify():\n')==1;s=s.replace('def verify():\n',insertion+'def verify():\n')
raw=s.encode();ast.parse(raw);g={'__name__':'guard_source_definitions_only'};exec(compile(raw,'<host-guard02-definitions>','exec'),g)
assert g['READ_BYTES']==0 and g['CHECKED']=={} and g['LABEL']=='ng-fc33-final05-owned-scope-recovery02'
assert len(g['REQUEST_PIN'][1])==len(g['SOURCE_PIN'][1])==64
pin=put('HOST-PRE-DISPATCH.py',raw)
put('HOST-GUARD-EXTENSION.py',extension)
patch=''.join(difflib.unified_diff(old.decode().splitlines(True),s.splitlines(True),fromfile='recovery01/HOST-PRE-DISPATCH.py',tofile='recovery02/HOST-PRE-DISPATCH.py'))
put('HOST-GUARD.patch',patch.encode())
report={'schema':'hepta.fc33.final05.recovery02-host-guard-derivation.v1','parent':{'bytes':len(old),'sha256':sha(old)},'candidate':pin,
 'new_extension':{'bytes':len(extension),'sha256':sha(extension)},'retained_validator':{'bytes':len(verifier),'sha256':sha(verifier)},
 'whole_parent_inverse':False,
 'phone_calls':0,'actual_execution':None,'original_preservation_verification_kept':True,'whole_original_set_final_bookend_kept':True,
 'new_actual_packet_and_21_private_outputs_reverified':True,'prior_known0_recovery_reverified':True,'host_read_cap_unchanged':67108864}
reverse=s.replace(insertion,'')
for oldvalue,newvalue in reversed(list(replacements.items())):assert reverse.count(newvalue)==1;reverse=reverse.replace(newvalue,oldvalue)
assert reverse.encode()==old;report['whole_parent_inverse']=True
put('HOST-GUARD-DERIVATION.json',enc(report))
print(json.dumps({'guard':pin,'extension':report['new_extension'],'whole_parent_inverse':True},sort_keys=True))
