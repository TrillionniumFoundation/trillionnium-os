#!/usr/bin/env python3
"""Only new source/projection/guard controls; original26 effect controls not rerun."""
from pathlib import Path
import ast,base64,copy,hashlib,json,lzma,shlex,zlib
D=Path(__file__).resolve().parent;O=D/'candidate01'
checks=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def check(name,v):
    if not v:raise AssertionError(name)
    checks.append(name)
def refused(name,fn,phrase):
    try:fn()
    except ValueError as exc:check(name,phrase in str(exc))
    else:raise AssertionError(name+' accepted')
source=(O/'SOURCE.py').read_bytes();request_raw=(O/'PHONE-REQUEST.json').read_bytes();manifest=json.loads((O/'MANIFEST.json').read_bytes())
check('final_source_request_pins_exact',all((len(b),sha(b))==(manifest[k]['bytes'],manifest[k]['sha256']) for k,b in [('source',source),('request',request_raw)]))
n={'__name__':'host_recovery02_definition_controls'};exec(compile(source,'<known-source-definitions-only>','exec'),n)
C=n['C'];original=json.loads(n['TARGETS_RAW']);target=n['TARGETS'];fixture=str(C.FIXTURE)
check('definitions_only_load_has_no_capture_or_recovery_state',C.STATE is None and n['RECOVERY'] is None)
check('original_targets_and_cap_raw_unchanged',len(n['TARGETS_RAW'])==183176 and sha(n['TARGETS_RAW'])=='0aad40b0feac77b963547d90b27ed49eb260d3a2c14fd9a9dbfe4a61550597d1' and sha(n['CAP_SOURCE_RAW'])=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44')
check('exact_actual_parent_projection_matches_declared_sha',sha(enc(target))==n['DERIVED_TARGETS_SHA']=='58b253b325daacf7417e7c2c53bd636c8840064b61965e4c37ffbf99e01263e0')
reverse=copy.deepcopy(target);reverse['surviving_parents']=original['surviving_parents'];reverse['prior_fixture_absence']=original['prior_fixture_absence'];reverse['prior_private_tree']['entries'][fixture]=original['prior_private_tree']['entries'][fixture]
check('full_inverse_only_five_parents_two_absent_parent_fields',enc(reverse)==n['TARGETS_RAW'] and target['files']==original['files'] and target['directories']==original['directories'])
check('historical_monotonic_values_retained_not_recast_as_fresh',all(target[k]['observed_monotonic_ns']==original[k]['observed_monotonic_ns'] for k in ['prior_fixture_absence']) and target['prior_private_tree']['entries'][fixture]['observed_monotonic_ns']==original['prior_private_tree']['entries'][fixture]['observed_monotonic_ns'])
files,dirs,parents=n['finite_plan']();check('same_original_finite97_files10_dirs5_parents',len(files)==97 and len(dirs)==10 and len(parents)==5)
check('both_absent_expectations_use_one_current_parent_full9_label',all(row['parent_metadata']==target['surviving_parents'][-1]['metadata'] and row['parent_selinux_raw_b64']==target['surviving_parents'][-1]['selinux_raw_b64'] for row in (target['prior_fixture_absence'],target['prior_private_tree']['entries'][fixture])))
old_ext=(D.parent/'R5-final05-recovery01/candidate02/recovery_extension.py').read_bytes();ext=(O/'recovery_extension.py').read_bytes()
added=b"'targets_sha256':TARGETS_SHA,'reconciliation_sha256':RECONCILIATION_SHA,'derived_targets_sha256':DERIVED_TARGETS_SHA,'authority':AUTHORITY,"
check('whole_mutation_preflight_and_resource_core_unchanged',ext.count(added)==2 and ext.replace(added,b"'targets_sha256':TARGETS_SHA,'authority':AUTHORITY,")==old_ext)
req=json.loads(request_raw);argv=shlex.split(req['command']);loader=ast.parse(argv[-1]);assign={x.targets[0].id:x.value for x in loader.body if isinstance(x,ast.Assign) and isinstance(x.targets[0],ast.Name)}
xz=base64.b64decode(ast.literal_eval(assign['c'].args[0]),validate=True);dec=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=33554432);raw=dec.decompress(xz,max_length=len(source)+1)
check('one_complete_xz_inverse_same_bound_source',raw==source and dec.eof and not dec.unused_data and len(xz)==36368 and len(request_raw)==49592 and len(request_raw)<=65535)
C.STATE={'evidence':{},'blobs':{},'read_bytes':0};frame=n['compressed_preflight']();pre=json.loads(zlib.decompress(base64.b64decode(frame['base64'],validate=True)))
check('preflight_explicit_original_and_reconciliation_and_derived_hashes',pre['targets_sha256']==n['TARGETS_SHA'] and pre['reconciliation_sha256']==n['RECONCILIATION_SHA'] and pre['derived_targets_sha256']==n['DERIVED_TARGETS_SHA'])
func=next(x for x in ast.parse(ext).body if isinstance(x,ast.FunctionDef) and x.name=='cleanup_main')
constructor=next(x.value for x in func.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='RECOVERY' for t in x.targets))
initial=eval(compile(ast.Expression(constructor),'<pure-audit-constructor>','eval'),n)
check('final_audit_constructor_emits_same_three_hashes_without_credit',all(initial[k]==pre[k] for k in ('targets_sha256','reconciliation_sha256','derived_targets_sha256')) and initial['component_qualified'] is False and initial['business_qualified'] is False)
reservation=n['reserve_output'](frame,files,dirs,parents)
check('runtime_output_gate_still_bounded_before_effects',reservation['wire_max_bytes']<=8388608 and reservation['other_max_bytes']==65536)

# Exercise only the unchanged preflight comparator with synthetic observations.
# All actual file/lock/process/device readers and mutation functions stay unused.
saved_dir=C.directory
def evidence():
    return {'private_before':copy.deepcopy(target['prior_private_tree']),'private_after':copy.deepcopy(target['prior_private_tree']),
       'home_aliases_before':copy.deepcopy(target['prior_home_aliases']),'home_aliases_after':copy.deepcopy(target['prior_home_aliases']),
       'parents_before':copy.deepcopy([parents[p] for p in C.INPUTS['parent_paths']]),'parents_after':copy.deepcopy([parents[p] for p in C.INPUTS['parent_paths']]),
       'bounded_current_presence':{'home_records':{},'claims_directory':{'names':[]},'actions_directory':{'names':[]},'fixture_root':{'kind':'absent'}},
       'locks':{'alias_count':28,'inode_group_count':15}}
actual_parent=copy.deepcopy(target['surviving_parents'][-1])
C.directory=lambda p:{'state':'COMPLETE_DIRECTORY_LISTING',**copy.deepcopy(actual_parent)}
try:
    C.STATE={'errors':[],'evidence':evidence(),'lock_fds':[None]*15};n['check_capture'](files,dirs,parents)
    check('synthetic_consistent_current_projection_accepted',True)
    C.STATE['evidence']['private_before']=copy.deepcopy(original['prior_private_tree'])
    refused('synthetic_original_mixed_parent_snapshot_rejected',lambda:n['check_capture'](files,dirs,parents),'private byte/full9/label/tree changed')
    C.STATE={'errors':[],'evidence':evidence(),'lock_fds':[None]*15};actual_parent['metadata'][7]-=1
    refused('synthetic_future_tmp_parent_change_rejected',lambda:n['check_capture'](files,dirs,parents),'exact current XML parent')
    actual_parent=copy.deepcopy(target['surviving_parents'][-1]);C.STATE={'errors':[],'evidence':evidence(),'lock_fds':[None]*15}
    C.STATE['evidence']['parents_before'][2]['names'].append('SYNTHETIC-UNADMITTED-FOREIGN')
    refused('synthetic_future_foreign_parent_member_rejected',lambda:n['check_capture'](files,dirs,parents),'exact prior parent metadata/labels/names')
finally:C.directory=saved_dir;C.STATE=None
guard=(O/'HOST-PRE-DISPATCH.py').read_bytes();g={'__name__':'guard_definitions_only'};exec(compile(guard,'<host-guard-definitions-only>','exec'),g)
check('host_guard_definition_load_reads_no_file_or_phone',g['READ_BYTES']==0 and g['CHECKED']=={} and g['LABEL']=='ng-fc33-final05-owned-scope-recovery02')
check('host_guard_pins_same_request_source_and_original_actor',g['SOURCE_PIN']==(len(source),sha(source)) and g['REQUEST_PIN']==(len(request_raw),sha(request_raw)) and g['ACTOR_PIN']==(5652,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'))
gd=json.loads((O/'HOST-GUARD-DERIVATION.json').read_bytes());check('complete_old_guard_inverse_record_matches_exact_final_guard',gd['whole_parent_inverse'] is True and gd['candidate']['sha256']==sha(guard) and gd['candidate']['bytes']==len(guard))
check('original_effect_controls_retained_without_reexecution',sha(old_ext)=='4e1d4053c73af74543a15beb03b536e45eb5f857e673bc2babc55502c8078f30' and C.STATE is None)
out={'schema':'hepta.fc33.final05.recovery02-host-controls.v1','state':'NEW_PROJECTION_AND_BINDING_HOST_CONTROLS_PASSED','source':manifest['source'],'request':manifest['request'],
 'guard':{'bytes':len(guard),'sha256':sha(guard)},'checks':checks,'check_count':len(checks),'synthetic_comparator_controls_not_phone_evidence':True,
 'original26_effect_controls_not_repeated':True,'phone_calls':0,'file_deletes':0,'scope_closure':False,'cleanup_executed':False,'component_qualified':False,'business_qualified':False}
b=enc(out);p=O/'HOST-CONTROLS.json'
if p.exists():assert p.read_bytes()==b
else:p.write_bytes(b)
print(json.dumps({'path':str(p),'bytes':len(b),'sha256':sha(b),'count':len(checks)},sort_keys=True))
