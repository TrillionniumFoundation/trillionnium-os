#!/usr/bin/env python3
"""Host-only material preparation from explicit Root identities and byte pins.

No nonce is generated, no phone command is run, and no provider/model is
started. The source seal is an independent component seal, never a final
integration seal or four-role readiness claim.
"""
import argparse
import ast
import base64
import gzip
import io
import os
from pathlib import Path
import re
import shlex
import sys
import tarfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from component_common import need,sha,strict,encoded,descriptor,relative,BASE,ANDROID,ANDROID_BASE


def host_read(path, maximum=16*1024*1024):
    import stat
    path = Path(path).absolute()
    need(path.parent.resolve() == path.parent, 'canonical host parent required')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=maximum, 'host original type/link/size')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
        b=os.fstat(fd);c=path.lstat()
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(c,k) for k in keys), 'host original changed')
        return raw
    finally:os.close(fd)


def pin(path, expected, maximum=16*1024*1024):
    raw=host_read(path,maximum);need(sha(raw)==expected,'explicit Root hash differs: '+str(path));return raw


def write_new(path, raw):
    with open(path,'xb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno())


def validate_retirement(raw, original_dir, boot):
    value=strict(raw)
    need(set(value)=={'schema','boot_id','files'}
         and value['schema']=='hepta.native-guard.retirement-original-input.v1' and value['boot_id']==boot,
         'explicit actual retirement descriptor required')
    rows=value['files'];need(set(rows)=={'proof','preflight','probe','bound_inputs','disabled_flag'},'actual retirement input set')
    code=BASE/'module-r10-r1-retirement-code-r1';out=BASE/'module-retire-r9-r2-for-r10-r1-01'
    paths={'proof':out/'RETIREMENT.json','preflight':out/'PREFLIGHT.json','probe':code/'retirement_probe.py',
        'bound_inputs':code/'BOUND-INPUTS.json','disabled_flag':ANDROID/'data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable'}
    originals={}
    for key,expected in paths.items():
        row=rows[key]
        need(set(row)=={'path','bytes','sha256','metadata'} and row['path']==str(expected)
             and isinstance(row['metadata'],list) and len(row['metadata'])==9, 'actual retirement path/metadata required')
        data=pin(Path(original_dir)/(key+'.original'),row['sha256'])
        need(len(data)==row['bytes'],'actual retirement original size differs');originals[key]=data
    proof,before,bound=(strict(originals[k]) for k in ('proof','preflight','bound_inputs'))
    need(proof.get('schema')=='hepta.r9-r2-retirement-observation.v1'
         and proof.get('state')=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED' and proof.get('boot_id')==boot
         and proof.get('server_lock_now_unheld') is True and proof.get('global_pending_clear') is True
         and proof.get('old_claims_deleted') is False and proof.get('old_task_terminal_rewritten') is False
         and proof.get('automatic_restart') is False and proof.get('automatic_replay') is False,
         'current actual four-role retirement not established')
    need(before.get('state')=='READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
         and before['groups']==proof['original_role_identities']
         and set(before['groups'])=={'supervisor','provider','model','sidecar'}
         and before['preserved_state']==proof['preserved_state']
         and bound.get('complete_current_accepted_case_union_verified') is True
         and originals['disabled_flag']==b'', 'actual complete original retirement binding differs')
    tree=ast.parse(originals['probe'])
    constants={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body
        if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('BOUND','GROUPS')}
    need(constants.get('BOUND')==bound and {k:list(v) for k,v in constants['GROUPS'].items()}==before['groups'],
         'generated retirement probe does not bind original inputs')
    return rows


def make_archive(files):
    need(len(files)<=80 and sum(map(len,files.values()))<=8*1024*1024,'component staging inventory bound')
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,raw in sorted(files.items()):
            relative(name)
            entry=tarfile.TarInfo(name);entry.mode=0o600;entry.uid=entry.gid=0;entry.mtime=0;entry.size=len(raw)
            archive.addfile(entry,io.BytesIO(raw))
    return gzip.compress(stream.getvalue(),compresslevel=9,mtime=0)


def prepare(a):
    os.umask(0o077)
    need(re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',a.label) and a.case_id in ('NEG-01','NEG-02'), 'component label/case')
    need(re.fullmatch('[0-9a-f]{32}',a.nonce) and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',a.boot_id),
         'Root must explicitly provide a fresh identity and actual boot')
    need(type(a.expires_unix_ms) is int and 0<a.expires_unix_ms-time.time_ns()//1000000<=600000,
         'Root lease expiry must be explicit, current and at most 600 seconds')
    for s in (a.session_id,a.profile_id):
        need(0<len(s.encode())<=256 and '\0' not in s,'native session/profile shape')
    manifest_raw=pin(a.package,a.package_sha256,262144);manifest=strict(manifest_raw)
    need(manifest.get('schema')=='hepta.native-guard.adapter-package.v1'
         and manifest.get('state')=='HOST_REVIEWED_NOT_PHONE_QUALIFIED','reviewed component adapter package required')
    rows=manifest['files'];need(5<=len(rows)<=32 and len({r['path'] for r in rows})==len(rows),'package inventory bound')
    files={'package/MANIFEST.json':manifest_raw}
    package_dir=Path(a.package).absolute().parent
    for row in rows:
        raw=pin(package_dir/relative(row['path']),row['sha256'])
        need(len(raw)==row['bytes'],'package original size');files['package/'+row['path']]=raw
    reviewed=strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(reviewed)==15,'reviewed production inventory required')
    prod=[]
    for name,h in sorted(reviewed.items()):
        need(re.fullmatch(r'[a-z_]+\.py',name),'production filename')
        data=pin(Path(a.production_source)/name,h);files['inputs/production/'+name]=data
        prod.append({'path':'production/'+name,**descriptor(data)})
    cfg_raw=pin(a.config_file,a.config_sha256);cfg=strict(cfg_raw)
    svc_raw=pin(a.service_file,a.service_sha256);svc=strict(svc_raw)
    need(cfg.get('service_manifest_sha256')==sha(svc_raw),'new config/service original binding differs')
    need(cfg.get('schema')=='hepta.phone-local-provider.v150.1'
         and isinstance(cfg.get('approved_apps'),dict) and cfg.get('inference_location')=='phone'
         and cfg.get('expected_parallel_slots')==1,'original production registry/config schema differs')
    # Seven/eight are enforced by the exact reviewed production source bytes,
    # not invented configuration keys. This component performs zero model rounds.
    source={'schema':'hepta.native-guard.component-source-seal.v150.r10.1',
        'state':'REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE','intended_module_release':'v150-r10-r1',
        'configuration':descriptor(cfg_raw),'phone_service_inputs_sha256':sha(svc_raw),
        'production_files':[dict(path='source/'+Path(r['path']).name,bytes=r['bytes'],sha256=r['sha256']) for r in prod]}
    source_raw=encoded(source);artifacts=strict(pin(a.artifacts_file,a.artifacts_sha256))
    need(set(artifacts)=={'client','sidecar','worker','screen_helper','focus_helper','unicode_helper','busybox','python'},
         'explicit reviewed external artifact set required')
    for row in artifacts.values():
        need(set(row)=={'path','bytes','sha256','uid','gid','mode','selinux'}
             and row['uid']==row['gid']==0 and type(row['mode']) is int
             and re.fullmatch('[0-9a-f]{64}',row['sha256']) and type(row['bytes']) is int and row['bytes']>0,
             'exact existing artifact bytes/metadata required')
    need(re.fullmatch('[0-9a-f]{64}',a.live_policy_sha256),'explicit reviewed live policy byte pin required')
    combo={'schema':'hepta.native-guard.component-combination.v150.r10.1',
        'state':'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY','source_seal':descriptor(source_raw),
        'configuration':descriptor(cfg_raw),'service_inputs':descriptor(svc_raw),'production_files':prod,
        'artifacts':artifacts,'live_policy_sha256':a.live_policy_sha256}
    combo_raw=encoded(combo)
    files.update({'inputs/COMBINATION.json':combo_raw,'inputs/SOURCE-SEAL.original.json':source_raw,
        'inputs/configuration.original.json':cfg_raw,'inputs/service-inputs.original.json':svc_raw})
    retirement_raw=pin(a.retirement_descriptor,a.retirement_descriptor_sha256)
    retirement=validate_retirement(retirement_raw,a.retirement_originals,a.boot_id)
    prior=None
    prior_args=(a.prior_boundary_descriptor,a.prior_boundary_descriptor_sha256,a.prior_boundary_original)
    need(all(prior_args),'r4 requires all three actual published prior-boundary inputs')
    if all(prior_args):
        prior=strict(pin(a.prior_boundary_descriptor,a.prior_boundary_descriptor_sha256,262144))
        need(set(prior)=={'path','bytes','sha256','metadata'} and re.fullmatch(
            r'/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/[0-9a-f]{32}\.json',prior['path'])
            and isinstance(prior['metadata'],list) and len(prior['metadata'])==9,
            'explicit original phone late-boundary descriptor differs')
        prior_raw=pin(a.prior_boundary_original,prior['sha256'])
        need(len(prior_raw)==prior['bytes'],'prior-boundary original size differs')
        files['inputs/PRIOR-BOUNDARY.original.json']=prior_raw
    owner=pin(a.owner_request_file,a.owner_request_sha256,16000)
    need(20<=len(owner)<=16000 and b'\0' not in owner and owner.decode().count(a.nonce)==1,'exact Root owner request differs')
    lease={'schema':'hepta.native-guard.lease.v1','label':a.label,'boot_id':a.boot_id,'case_id':a.case_id,
        'nonce':a.nonce,'owner_request_sha256':sha(owner),'selected_session_id':a.session_id,
        'selected_profile_id':a.profile_id,'expires_unix_ms':a.expires_unix_ms,'combination':descriptor(combo_raw),
        'retirement':retirement,'prior_boundary':prior,
        'android_journal':str(ANDROID_BASE/'native-guard-r10-r1'/a.label/'executor'),
        'package_sha256':a.package_sha256}
    lease_raw=encoded(lease)
    contract={'schema':'hepta.native-guard.sender-contract.v1',**{k:lease[k] for k in ('label','nonce','case_id','boot_id',
        'owner_request_sha256','selected_session_id','selected_profile_id','expires_unix_ms','package_sha256')},
        'lease_sha256':sha(lease_raw),'combination_sha256':sha(combo_raw)}
    files.update({'LEASE.json':lease_raw,'owner-request.txt':owner,'sender-contract.json':encoded(contract)})
    out=Path(a.out).absolute();out.mkdir(mode=0o700)
    # Validate the actual staged source/config/service layout with the same
    # production-pin routine; this is a private host fixture, not a phone stage.
    for name,raw in files.items():
        path=out/'tree'/relative(name);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);write_new(path,raw)
    from component_common import load_combination
    load_combination(out/'tree/inputs',combo_raw,reviewed,private_inputs=False)
    archive=make_archive(files);write_new(out/'component-inputs.tar.gz',archive)
    home=BASE/'native-guard-r10-r1'/a.label
    launch=[artifacts['python']['path'],'-I','-B',str(home/'package/source/component_lifecycle.py'),
        '--lease',str(home),'--lease-sha256',sha(lease_raw),'--package',str(home/'package/MANIFEST.json'),
        '--package-sha256',a.package_sha256,'--execute-detached-launch-once']
    result={'schema':'hepta.native-guard.host-preparation.v1','state':'HOST_MATERIAL_ONLY_NOT_DEPLOYED',
        'label':a.label,'case_id':a.case_id,'nonce':a.nonce,'owner_request_sha256':sha(owner),
        'package_sha256':a.package_sha256,'lease':descriptor(lease_raw),'combination':descriptor(combo_raw),
        'archive':descriptor(archive),'archive_members':len(files),'phone_home':str(home),
        'root_detached_launcher_argv':launch,'root_shell_launch_fragment':shlex.join(launch),
        'launcher_fork_is_not_readiness':True,'supervisor_native_init_parent_required':True,
        'sender_contract_path':str(out/'tree/sender-contract.json'),'sender_contract_sha256':sha(files['sender-contract.json']),
        'retirement_descriptor_sha256':sha(retirement_raw),'original_sender_sha256':'5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281',
        'phone_calls':0,'model_requests':0,'native_submissions':0,'nonces_generated':0,'component_qualified':False,
        'business_qualified':False,'final_r10_builder_must_compare_all_component_bytes_and_consume_late_inventory':True}
    write_new(out/'PREPARED.json',encoded(result));print(encoded(result).decode(),end='')
    return 0


def main():
    p=argparse.ArgumentParser()
    for name in ('label','case-id','nonce','boot-id','session-id','profile-id','package','package-sha256',
        'production-source','config-file','config-sha256','service-file','service-sha256','artifacts-file',
        'artifacts-sha256','live-policy-sha256','retirement-descriptor','retirement-descriptor-sha256',
        'retirement-originals','owner-request-file','owner-request-sha256','out'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--expires-unix-ms',required=True,type=int)
    for name in ('prior-boundary-descriptor','prior-boundary-descriptor-sha256','prior-boundary-original'):
        p.add_argument('--'+name)
    return prepare(p.parse_args())




# Explicit current common dependencies; no wildcard imports or target reads.
from component_common import (COMPONENT_EVIDENCE, EPOCH_ID, EPOCH_MAX_SLOTS,
    EPOCH_SCOPE_KEYS, EPOCH_REGISTRY_ROOT, EPOCH_TRANSPORT_FILES,
    _ep_bare, _ep_encoded, _ep_exact, _ep_json_original, _ep_manifest_raw,
    _ep_need, _ep_pin, _ep_re, _ep_same, _ep_sha, _ep_strict,
    epoch_anchor_value, epoch_binding_value, epoch_directory_claim_value,
    epoch_generation_value, epoch_identity_value, epoch_initialization_value,
    epoch_lease_protocol_value, epoch_manifest_value, epoch_reservation_value,
    epoch_scope_binding_value, epoch_stage_binding_value, epoch_terminal_value)

# Pure protocol replay. All file bodies arrive with their original phone
# descriptors. Source authority, actual live observations, and native closure
# semantics are separate mandatory callers; this parser does not grant a slot.

def _ep_required_record(index, originals, path):
    pin=index['files'].get(path)
    _ep_need(pin is not None,'required immutable protocol original is absent: '+path)
    return {'original':pin,'value':_ep_json_original(pin,index,originals)}


def _ep_optional_record(index, originals, path):
    return _ep_required_record(index,originals,path) if path in index['files'] else None


def _ep_complete_directory(index, path, names):
    row=index['directories'].get(path)
    _ep_need(row is not None and row['names']==sorted(names),
             'protocol directory is omitted, incomplete or contains an unknown member: '+path)
    return row


def _ep_slot_paths(identity):
    label=identity['label'];nonce=identity['nonce']
    return ['/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+label,
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/'+label,
            '/proc/1/root/data/local/tmp/hepta-native-guard-'+nonce]


def _ep_generation_records(index, originals, binding, lease):
    count=len(binding['prior_generations'])+1
    _ep_complete_directory(index,EPOCH_REGISTRY_ROOT+'/generations',
                           ['%02d.json'%n for n in range(1,count+1)])
    records=[]
    for ordinal in range(1,count+1):
        record=_ep_required_record(index,originals,
                                   EPOCH_REGISTRY_ROOT+'/generations/%02d.json'%ordinal)
        value=epoch_generation_value(record['value'])
        _ep_need(value['ordinal']==ordinal,'source catalog has a gap or reordered ordinal')
        if ordinal<count:
            _ep_need(_ep_same(record,binding['prior_generations'][ordinal-1]),
                     'a previous source catalog is not the exact finite reviewed original')
        elif lease is not None:
            _ep_need(_ep_same(record['original'],lease['epoch']['generation'])
                     and value['runtime']['sha256']==lease['package_sha256']
                     and {k:value['combination'][k] for k in ('bytes','sha256')}==lease['combination'],
                     'actual lease changed the one current catalog runtime or combination')
        if ordinal>1:
            _ep_need(value['predecessor_generation']=={
                k:records[-1]['original'][k] for k in ('path','bytes','sha256')},
                'source revision does not retain its exact prior catalog')
        records.append(record)
    return records


def _ep_scope_originals(record, identity, identity_pin, index, originals):
    value=record['value']; accepted_pin=value['accepted']
    accepted=_ep_strict(_ep_manifest_raw(accepted_pin,index,originals))
    epoch_scope_binding_value(value,identity,identity_pin,accepted,accepted_pin)
    home=_ep_slot_paths(identity)[1]
    _ep_need(accepted_pin['path']==home+'/ACCEPTED.json',
             'native scope must come from the original accepted file in this actual home')
    _ep_exact(accepted,{'scope','run_dir','contract_sha256','native_tools_dispatched'},
              'actual accepted original fields differ')
    _ep_need(type(accepted['native_tools_dispatched']) is int
             and accepted['native_tools_dispatched']==0,
             'scope binding cannot fabricate a prior dispatch')
    bound_record=_ep_required_record(index,originals,home+'/BOUND-CONTRACT.json')
    claim_record=_ep_required_record(index,originals,home+'/claims/'+identity['nonce']+'.json')
    bound=bound_record['value'];claim=claim_record['value']
    _ep_need(bound.get('schema')=='hepta.native-guard.bound-contract.v1'
             and type(bound.get('contract')) is dict,
             'scope lacks its actual original bound component contract')
    contract=bound['contract'];scope=value['scope']
    run=str(COMPONENT_EVIDENCE)+'/'+bound['run_basename']
    _ep_need(accepted['run_dir']==run
             and _ep_re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+identity['nonce'],bound['run_basename'])
             and accepted['contract_sha256']==_ep_sha(_ep_encoded(contract))
             and contract.get('nonce')==identity['nonce']
             and contract.get('case_id')==identity['case_id']
             and contract.get('owner_request_sha256')==identity['owner_request']['sha256']
             and all(contract.get('selected_'+k)==scope[k]==identity['selected_'+k]
                     for k in ('session_id','profile_id')),
             'actual accepted native scope changed its one-use identity or owner contract')
    _ep_need(_ep_same(claim,{'schema':'hepta.native-guard-component.claim.v1',
        'scope':scope,'contract_sha256':accepted['contract_sha256'],
        'state':'accepted_never_reuse','run_dir':run,'model_requests':0}),
        'actual native claim is not the original once-only zero-model claim')
    local=_ep_required_record(index,originals,run+'/accepted.json')['value']
    _ep_need(local.get('state')=='accepted_never_replay'
             and _ep_same(local.get('identity'),scope)
             and local.get('owner_request_sha256')==identity['owner_request']['sha256']
             and local.get('contract_sha256')==accepted['contract_sha256'],
             'original native run acceptance differs from the home scope binding')
    return value


def _ep_launch_originals(record, identity, identity_pin, scope_record, generation,
                         index, originals):
    value=record['value']
    _ep_exact(value,{'schema','epoch_id','ordinal','identity','scope_binding',
        'root_fixture_plan','bound_contract','accepted','root_source_authorization',
        'fixture_namespace','fixture_may_exist','state'},
        'explicit original accepted-scope fixture authorization required')
    _ep_need(value['schema']=='hepta.native-guard.epoch-fixture-phase-binding.v1'
             and value['epoch_id']==EPOCH_ID and type(value['ordinal']) is int
             and value['ordinal']==identity['ordinal']
             and _ep_same(value['identity'],identity_pin)
             and _ep_same(value['scope_binding'],scope_record['original'])
             and value['state']=='EXACT_ACCEPTED_SCOPE_FIXTURE_PHASE_AUTHORIZED'
             and value['fixture_may_exist'] is True
             and value['fixture_namespace']==_ep_slot_paths(identity)[2],
             'fixture phase permission changed its actual scope, ordinal or fixed namespace')
    for key in ('root_fixture_plan','bound_contract','accepted','root_source_authorization'):
        _ep_pin(value[key],original=True);_ep_manifest_raw(value[key],index,originals)
    home=_ep_slot_paths(identity)[1]
    _ep_need(value['root_fixture_plan']['path']==home+'/ROOT-SETUP-PLAN.json'
             and value['bound_contract']['path']==home+'/BOUND-CONTRACT.json'
             and _ep_same(value['accepted'],scope_record['value']['accepted']),
             'fixture permission is not the actual native setup original')
    plan=_ep_strict(originals[value['root_fixture_plan']['path']])
    # The full reviewed fixture-plan parser remains a mandatory native closer
    # gate. These crosslinks only authorize observing this exact named root.
    accepted=_ep_strict(originals[value['accepted']['path']])
    bound=_ep_strict(originals[value['bound_contract']['path']])
    _ep_need(plan.get('schema')=='hepta.native-guard.root-phase-plan.v1'
             and plan.get('phase')=='setup'
             and _ep_same(plan.get('scope'),scope_record['value']['scope'])
             and plan.get('contract_sha256')==accepted['contract_sha256']
             and plan.get('automatic_retry') is False
             and bound.get('contract',{}).get('nonce')==identity['nonce']
             and bound.get('contract',{}).get('case_id')==identity['case_id'],
             'fixture original belongs to another native scope or bound contract')
    return value


def _ep_retired_admission(record, identity, index, originals, observation_verifier):
    value=record['value']
    _ep_exact(value,{'schema','epoch_id','ordinal','retired_original'},
              'complete immutable lifecycle admission binding required')
    home=_ep_slot_paths(identity)[1]
    pin=value['retired_original'];_ep_pin(pin,original=True)
    _ep_need(value['schema']=='hepta.native-guard.epoch-lifecycle-admission-binding.v1'
             and value['epoch_id']==EPOCH_ID and type(value['ordinal']) is int
             and value['ordinal']==identity['ordinal']
             and pin['path']==home+'/RETIRED-BASELINE-VERIFIED.json',
             'lifecycle admission is not this actual original home observation')
    retired=_ep_strict(_ep_manifest_raw(pin,index,originals))
    proof=retired.get('explicit_late_boundary_verification')
    _ep_need(type(proof) is dict
             and proof.get('schema')=='hepta.native-guard.epoch-current-verification.v1'
             and proof.get('state')=='COMPLETE_CURRENT_EPOCH_PREDECESSOR_VERIFIED'
             and proof.get('epoch_id')==EPOCH_ID
             and proof.get('ordinal')==identity['ordinal']
             and proof.get('boot_id')==identity['boot_id']
             and proof.get('nonce')==identity['nonce'],
             'actual lifecycle did not record a complete new-domain current verification')
    for key in ('inventory_spec','inventory','control_inventory','inventory_observation',
                'predecessor_context','legacy_semantic','active_semantic',
                'role_absence','endpoint_observations','initial_manifest','final_manifest'):
        _ep_need(key in proof,'current admission omitted its actual proof field: '+key)
    observation_verifier(proof['inventory_spec'],proof['inventory'],
                         proof['control_inventory'],proof['inventory_observation'])
    _ep_need(proof.get('native_boundary_created') is False
             and proof.get('model_requests')==0 and type(proof['model_requests']) is int,
             'current admission invented a native result or model request')
    return {'retired_original':pin,'retired':retired,'proof':proof}


def epoch_registry_replay(lease, manifest, originals, *, mode,
                          inventory_validator, observation_verifier):
    _ep_need(mode in ('preclose','published') and callable(inventory_validator)
             and callable(observation_verifier),'explicit protocol mode and complete inventory gates required')
    binding=epoch_binding_value();index=epoch_manifest_value(manifest,originals,binding=binding)
    if mode=='preclose':epoch_lease_protocol_value(lease)
    else:_ep_need(lease is None,'postpublication replay cannot substitute a current preclose lease')
    anchor_pin=index['files'].get(binding['anchor']['path'])
    _ep_need(anchor_pin is not None,'actual immutable epoch anchor is missing')
    anchor=epoch_anchor_value(originals[anchor_pin['path']],anchor_pin,binding=binding)
    initial_record=_ep_required_record(index,originals,EPOCH_REGISTRY_ROOT+'/INITIALIZATION.json')
    initialization=epoch_initialization_value(initial_record['value'],
        original=initial_record['original'],anchor=anchor,binding=binding,index=index,originals=originals,
        inventory_validator=inventory_validator,observation_verifier=observation_verifier)
    generations=_ep_generation_records(index,originals,binding,lease)
    generation_by_pin={_ep_encoded(r['original']):r for r in generations}
    _ep_need(_ep_encoded(initial_record['value']['generation']) in generation_by_pin,
             'initialization has an unreviewed source catalog')
    root_names={'ANCHOR.json','INITIALIZATION.json','REGISTRY.lock','ROOT-AUTHORIZATION.json',
                'generations','initialization','slots'}
    seal=_ep_optional_record(index,originals,EPOCH_REGISTRY_ROOT+'/SEALED.json')
    if seal is not None:root_names.add('SEALED.json')
    _ep_complete_directory(index,EPOCH_REGISTRY_ROOT,root_names)
    _ep_need(initial_record['value']['root_authorization']['path']==EPOCH_REGISTRY_ROOT+'/ROOT-AUTHORIZATION.json',
             'source authority must retain its one actual create-only namespace')
    _ep_complete_directory(index,EPOCH_REGISTRY_ROOT+'/initialization',
        {'BASELINE-BUSINESS.json','BASELINE-CONTROL.json','INVENTORY-SPEC.json',
         'INVENTORY-OBSERVATION.json','carriers'})
    carrier_names=[r['role']+'.original' for r in initial_record['value']['carriers']]
    _ep_complete_directory(index,EPOCH_REGISTRY_ROOT+'/initialization/carriers',carrier_names)
    slot_root=EPOCH_REGISTRY_ROOT+'/slots'
    parent=index['directories'].get(slot_root)
    _ep_need(parent is not None,'complete actual slot namespace is missing')
    claims=[name for name in parent['names'] if _ep_re.fullmatch(r'0[1-8]\.CLAIM\.json',name)]
    count=len(claims)
    _ep_need(0<=count<=EPOCH_MAX_SLOTS and claims==['%02d.CLAIM.json'%n for n in range(1,count+1)]
             and set(parent['names'])==set(claims+['%02d'%n for n in range(1,count+1)]),
             'partial, unknown, duplicate or noncontiguous slot allocation blocks replay')
    if mode=='preclose':
        _ep_need(seal is None and count==lease['epoch']['ordinal'] and count>0,
                 'capture is not the sole highest unsealed ordinal')
        for key,wanted in (('anchor',anchor_pin),('initialization',initial_record['original'])):
            _ep_need(_ep_same(lease['epoch'][key],wanted),'lease changed its immutable '+key)
    slots=[];closed=[];nonce_set=set(binding['legacy_nonces']+binding['failed_nonces'])
    labels=set();scope_set=set();prior_terminal=None;prior_boundary=anchor['legacy']['native_chain'][0]['boundary']
    for n in range(1,count+1):
        prefix=slot_root+'/%02d/'%n
        claim=_ep_required_record(index,originals,slot_root+'/%02d.CLAIM.json'%n)
        reservation=epoch_reservation_value(claim['value'],binding=binding,
                                            ordinal=n,previous_terminal=prior_terminal)
        generation=generation_by_pin.get(_ep_encoded(reservation['generation']))
        _ep_need(generation is not None,'slot selected a catalog outside the finite reviewed generation set')
        for key in ('authorization_request','resource_reservation'):
            _ep_manifest_raw(reservation[key],index,originals)
        directory=_ep_required_record(index,originals,prefix+'DIRECTORY-BINDING.json')
        directory_row=index['directories'].get(prefix[:-1])
        _ep_need(directory_row is not None,'actual exclusively claimed slot directory is missing')
        epoch_directory_claim_value(directory['value'],ordinal=n,claim=claim['original'],directory=directory_row)
        records={key:_ep_optional_record(index,originals,prefix+filename) for key,filename in (
            ('identity','IDENTITY.json'),('admission','ADMISSION.json'),('stage','STAGE.json'),
            ('scope_binding','SCOPE-BINDING.json'),('launch','LAUNCH.json'),('terminal','COMMIT.json'))}
        names={'DIRECTORY-BINDING.json'}|{filename for key,filename in (
            ('identity','IDENTITY.json'),('admission','ADMISSION.json'),('stage','STAGE.json'),
            ('scope_binding','SCOPE-BINDING.json'),('launch','LAUNCH.json'),('terminal','COMMIT.json'))
            if records[key] is not None}
        identity_record=records['identity'];identity=None;inventory_roots=[];required_absence=[]
        if identity_record is None:
            _ep_need(all(records[k] is None for k in records),
                     'a later phase cannot exist before the actual durable identity')
            _ep_need(n==count and mode=='preclose',
                     'unknown preidentity claim cannot become a terminal or authorize a next ordinal')
        else:
            identity=epoch_identity_value(identity_record['value'],reservation,claim['original'],
                                           forbidden_nonces=nonce_set)
            _ep_need(identity['label'] not in labels and _ep_same(identity['prior_boundary'],prior_boundary),
                     'slot repeats a label or skips the actual previous native boundary')
            nonce_set.add(identity['nonce']);labels.add(identity['label'])
            _ep_manifest_raw(identity['owner_request'],index,originals)
            _ep_need(identity['owner_request']['path']==prefix+'owner-request.original.txt',
                     'owner request must already be an actual create-only slot original')
            names.add('owner-request.original.txt')
            roots=_ep_slot_paths(identity);required_absence=list(roots)
            stage=records['stage']
            if stage is not None:
                epoch_stage_binding_value(stage['value'],identity=identity,identity_pin=identity_record['original'],
                    generation_value=generation['value'],index=index,originals=originals)
                inventory_roots=roots[:2];required_absence=roots[2:]
            else:
                _ep_need(all(records[k] is None for k in ('admission','scope_binding','launch','terminal')),
                         'later actual phases cannot be inferred before private stage completion')
            if records['admission'] is not None:
                _ep_retired_admission(records['admission'],identity,index,originals,observation_verifier)
            if records['scope_binding'] is not None:
                _ep_need(records['admission'] is not None,'native accepted scope omitted actual lifecycle admission')
                scope_value=_ep_scope_originals(records['scope_binding'],identity,identity_record['original'],index,originals)
                scope_key=tuple(scope_value['scope'][k] for k in EPOCH_SCOPE_KEYS)
                _ep_need(scope_key not in scope_set,'active slots repeat a native scope')
                scope_set.add(scope_key)
            if records['launch'] is not None:
                _ep_need(records['scope_binding'] is not None,'fixture phase precedes actual accepted scope')
                _ep_launch_originals(records['launch'],identity,identity_record['original'],
                    records['scope_binding'],generation['value'],index,originals)
                inventory_roots=roots;required_absence=[]
            if records['terminal'] is not None:
                _ep_need(records['launch'] is not None,'native terminal lacks its actual fixture phase')
                terminal=epoch_terminal_value(records['terminal']['value'],original=records['terminal']['original'],
                    identity=identity,identity_pin=identity_record['original'],
                    scope_binding=records['scope_binding']['value'],scope_pin=records['scope_binding']['original'],
                    generation=generation['original'],predecessor_terminal=prior_terminal,
                    index=index,originals=originals)
                names.update(('BOUNDARY.json','CLOSURE.json','AFTER-INVENTORY.json'))
                closed.append({'ordinal':n,'generation':generation['original'],
                    'identity':identity_record['original'],'scope_binding':records['scope_binding']['original'],
                    'boundary':terminal['boundary'],'inventory':terminal['inventory'],
                    'closure':terminal['closure'],'terminal':records['terminal']['original']})
                prior_terminal=records['terminal']['original'];prior_boundary=terminal['boundary']
            else:
                _ep_need(mode=='preclose' and n==count,'a consumed unknown slot forbids further allocation/publication')
            if n==count and mode=='preclose':
                _ep_need(records['terminal'] is None
                         and _ep_same(lease['epoch']['identity'],identity_record['original'])
                         and _ep_same(lease['epoch']['reservation'],claim['original'])
                         and lease['nonce']==identity['nonce'] and lease['label']==identity['label'],
                         'capture lease does not belong to this current uncommitted identity')
        if prefix+'transport' in index['directories']:
            names.add('transport')
            actual=index['directories'][prefix+'transport']['names']
            _ep_need(set(actual)<=set(EPOCH_TRANSPORT_FILES),
                     'new transport contains an unreviewed phase filename')
        _ep_complete_directory(index,prefix[:-1],names)
        slots.append({'ordinal':n,'claim':claim,'directory_binding':directory,**records,
                      'inventory_roots':inventory_roots,'required_absence_roots':required_absence})
    if seal is not None:
        _ep_need(mode=='published' and count>0,
                 'an empty or active epoch cannot claim a sealed production boundary')
        _ep_exact(seal['value'],{'schema','epoch_id','boot_id','last_terminal',
            'qualified_boundaries','source_authorization','native_epoch_closed'},'complete explicit epoch seal required')
        value=seal['value']
        _ep_need(value['schema']=='hepta.native-guard.epoch-seal.v1'
                 and value['epoch_id']==EPOCH_ID and value['boot_id']==binding['boot_id']
                 and value['native_epoch_closed'] is True and _ep_same(value['last_terminal'],prior_terminal),
                 'epoch seal changed its actual terminal frontier')
    current=slots[-1] if slots and mode=='preclose' else None
    active={'schema':'hepta.native-guard.epoch-active-domain.v1','epoch_id':EPOCH_ID,
        'current_ordinal':count,'consumed_reservations':[r['claim']['original'] for r in slots],
        'closed_native_records':closed,
        'current_identity':current['identity']['original'] if current and current['identity'] else None,
        'current_scope_binding':current['scope_binding']['original'] if current and current['scope_binding'] else None,
        'predecessor_terminal':prior_terminal}
    registry={'schema':'hepta.native-guard.epoch-replayed-registry.v1','epoch_id':EPOCH_ID,
        'boot_id':binding['boot_id'],'mode':mode,'manifest':_ep_bare(_ep_encoded(manifest)),
        'initialization':initialization,'generations':generations,'slots':slots,'sealed':seal}
    failures={'footprint':initialization['footprint'],'host_origins':anchor['host_origins'],
        'carriers':initialization['carriers'],
        'retained_failed_fixture_absences':binding['retained_failed_fixture_absences'],
        'unresolved_namespace_members':initialization['footprint']['unknown_namespace_members']}
    return {'legacy':anchor['legacy'],'active':active,'registry':registry,'anchor':anchor,
        'failure_inputs':failures,'retained_roots':initialization['footprint']['retained_roots'],
        'control_roots':[{'path':p,'presence':'present'} for p in binding['control_roots']]}


def epoch_inventory_spec_from_replay(anchor, registry, failures, *, legacy_alias_pairs):
    binding=epoch_binding_value()
    _ep_need(registry['schema']=='hepta.native-guard.epoch-replayed-registry.v1'
             and registry['epoch_id']==EPOCH_ID and registry['boot_id']==binding['boot_id'],
             'inventory specification must come from the exact protocol replay')
    _ep_need(failures['unresolved_namespace_members']==[]
             and failures['footprint']['namespace_coverage_complete'] is True,
             'an unknown retained namespace cannot be omitted from the inventory budget')
    active=[]
    for slot in registry['slots']:
        identity=slot['identity']['value'] if slot['identity'] is not None else None
        active.append({'ordinal':slot['ordinal'],'identity':None if identity is None else
            {k:identity[k] for k in ('label','nonce')},
            'inventory_roots':slot['inventory_roots'],
            'required_absence_roots':slot['required_absence_roots']})
    # Actual complete active-home aliases are filled from both freshly read
    # trees by the existing snapshot and then the v4 pure core validates every
    # relative row. Fixed legacy/failed aliases are never synthesized anew.
    return {'schema':'hepta.native-guard.two-epoch-inventory-spec.v4',
        'legacy_anchor':anchor['legacy']['native_chain'][0]['boundary'],
        'active_reservations':active,'retained_roots':failures['footprint']['retained_roots'],
        'control_roots':[{'path':p,'presence':'present'} for p in binding['control_roots']],
        'control_leaves':[{'path':r['path'],'presence':'present'} for r in binding['control_leaves']],
        'alias_pairs':sorted([list(pair) for pair in legacy_alias_pairs]+binding['alias_pairs']),
        'retained_failed_fixture_absences':binding['retained_failed_fixture_absences']}


# Current epoch structural API for the existing prepare_component member.
# These functions are pure over exact captured byte maps. They do not run a
# historical reader, inventory scan, subprocess, publisher or target command.

def _epoch_inventory_module():
    import component_common as common
    import component_lifecycle as lifecycle
    context = common.epoch_actual_context(globals())
    common._ep_need(common.epoch_actual_context(common.__dict__) == context
        and common.epoch_actual_context(lifecycle.__dict__) == context,
        'current protocol modules require the same explicitly injected actual context')
    return common, lifecycle


def epoch_verify_capture_protocol(lease, manifest, originals_by_path, *, inventory_validator):
    common, lifecycle = _epoch_inventory_module()
    common.epoch_binding_value()
    return epoch_registry_replay(lease, manifest, originals_by_path, mode='preclose',
        inventory_validator=inventory_validator,
        observation_verifier=lifecycle.verify_epoch_inventory_observation)


def epoch_verify_publication_protocol(manifest, originals_by_path, *, inventory_validator):
    common, lifecycle = _epoch_inventory_module()
    common.epoch_binding_value()
    return epoch_registry_replay(None, manifest, originals_by_path, mode='published',
        inventory_validator=inventory_validator,
        observation_verifier=lifecycle.verify_epoch_inventory_observation)


def epoch_planned_inventory_from_protocol(anchor, registry, failure_inputs):
    common, lifecycle = _epoch_inventory_module()
    common.epoch_binding_value()
    value = epoch_inventory_spec_from_replay(anchor, registry, failure_inputs,
        legacy_alias_pairs=lifecycle.EPOCH_INVENTORY_LEGACY_ALIAS_PAIRS)
    # This first validation authenticates the fixed source-bound domain and
    # phase partition. Present active homes still require the complete actual
    # pair list reconstructed from both captured views before final inventory
    # observation verification; no future aliases are synthesized here.
    lifecycle.inventory_epoch_spec_value(value)
    return value


def epoch_preservation_context_from_protocol(lease, verified, *, manifest,
        originals_by_path, inventory_validator):
    common, lifecycle = _epoch_inventory_module()
    replayed = epoch_verify_capture_protocol(lease, manifest, originals_by_path,
        inventory_validator=inventory_validator)
    common._ep_need(common._ep_same(verified, replayed),
        'preservation must use the same complete actual preclose protocol replay')
    registry = replayed['registry']; slots = registry['slots']
    common._ep_need(registry['mode'] == 'preclose' and slots,
        'an actual current preclose slot is required for preservation')
    current = slots[-1]
    common._ep_need(current['identity'] is not None and current['admission'] is not None
        and current['stage'] is not None and current['terminal'] is None,
        'preservation cannot infer an admission, stage or terminal that was never recorded')
    index = common.epoch_manifest_value(manifest, originals_by_path,
                                        binding=common.epoch_binding_value())
    identity = current['identity']['value']
    observed = _ep_retired_admission(current['admission'], identity, index,
        originals_by_path, lifecycle.verify_epoch_inventory_observation)
    retired = observed['retired']; proof = observed['proof']
    common._ep_exact(retired, {'retirement_sha256','retirement_originals',
        'old_group_absence','old_journal_lock_held_without_writing',
        'old_preserved_state_equal_before_new_actions','explicit_late_boundary_verification',
        'equality_is_not_claimed_after_component_actions'},
        'actual retired admission envelope omitted an original predicate')
    common._ep_need(retired['retirement_sha256'] == lease['retirement']['proof']['sha256']
        and retired['old_journal_lock_held_without_writing'] is True
        and retired['old_preserved_state_equal_before_new_actions'] is False
        and retired['equality_is_not_claimed_after_component_actions'] is True,
        'the epoch cannot relabel original retirement equality or its held lock')
    expected_retirement = {name:{k:pin[k] for k in ('bytes','sha256')}
                           for name,pin in lease['retirement'].items()}
    common._ep_need(common._ep_same(retired['retirement_originals'], expected_retirement)
        and type(retired['old_group_absence']) is list and len(retired['old_group_absence']) == 2,
        'actual retired originals or the two original group observations differ')
    prior_records = replayed['active']['closed_native_records']
    common._ep_need(len(prior_records) == current['ordinal']-1
        and current['ordinal'] == lease['epoch']['ordinal'],
        'unknown or unclosed consumed slots cannot be skipped by preservation')
    if prior_records:
        prior = prior_records[-1]
        original = prior['inventory']
        inventory = common._ep_strict(common._ep_manifest_raw(original,index,originals_by_path))
        inventory_validator(inventory)
        boundary = prior['boundary']
        predecessor = prior['terminal']
    else:
        initialization = registry['initialization']
        original = initialization['preservation_inventory_original']
        inventory = initialization['preservation_inventory']
        common._ep_need(common._ep_same(inventory,
            common._ep_strict(common._ep_manifest_raw(original,index,originals_by_path))),
            'first-slot preservation changed its actual bootstrap business inventory')
        boundary = None
        predecessor = None
    lease_boundary = (replayed['legacy']['native_chain'][0]['boundary']
                      if boundary is None else boundary)
    common._ep_need(common._ep_same(lease['prior_boundary'], lease_boundary)
        and common._ep_same(identity['prior_boundary'], lease_boundary)
        and common._ep_same(identity['predecessor_terminal'], predecessor)
        and common._ep_same(replayed['active']['predecessor_terminal'], predecessor),
        'actual predecessor frontier changed between durable identity and capture')
    expected = {'schema':'hepta.native-guard.epoch-predecessor-context.v1',
        'epoch_id':common.EPOCH_ID,'ordinal':current['ordinal'],
        'legacy_head':replayed['legacy']['native_chain'][0]['boundary'],
        'previous_active_boundary':boundary,'previous_active_closed_components':len(prior_records),
        'consumed_slots_before_current':current['ordinal']-1,
        'predecessor_terminal':predecessor,'source_generation':identity['source_generation'],
        'preservation_inventory_original':original}
    common._ep_need(common._ep_same(proof['predecessor_context'], expected),
        'actual initial admission used another predecessor, source or preservation original')
    # Do not create new elapsed times, censuses or endpoint observations here.
    # This is the exact observed envelope. Mandatory semantic verification and
    # the source/action original validators separately authenticate its content.
    return {'preservation_inventory':inventory,
        'preservation_inventory_original':original,'prior_boundary':boundary,
        'lease_prior_boundary':lease_boundary,'closed_components':len(prior_records),
        'consumed_slots_before_current':current['ordinal']-1,
        'predecessor_terminal':predecessor,'lifecycle_admission_expected':proof}




# Pure active-domain replay for the existing prepare_component member.
# No old boundary is rewritten into the new schema, no live I/O is performed,
# and no public closed API is called recursively. A source-bound host closure
# action is mandatory for every previous native record. That separate gate
# authenticates the real host deep audit; this phone/consumer replay never
# claims that it read a P4 archive, host inode, or reexecuted the host parser.

_EPS_BOUNDARY_FIELDS = (
    'schema','state','boot_id','nonce','case_id','scope','owner_request_sha256',
    'package_sha256','combination_sha256','retirement','roots','inventory','closure',
    'prior_boundary','component_role_identities','publisher_source_sha256',
    'component_qualified','native_status','actual_native_calls',
    'original_retirement_rewritten','business_qualified','model_requests',
    'automatic_replay','non_native_sidebranch','epoch')
_EPS_BOUNDARY_EPOCH_FIELDS = (
    'schema','epoch_id','anchor','initialization','ordinal','reservation','identity',
    'scope_binding','generation','predecessor_terminal','previous_active_boundary',
    'capture_manifest','legacy_semantic','capture_epoch_observation',
    'preservation_inventory','lease','capture','active_semantic')
_EPS_CLOSURE_FIELDS = (
    'schema','state','closed','component_qualified','business_qualified',
    'four_role_qualification','model_requests','automatic_replay','boot_id','nonce',
    'case_id','scope','owner_request_sha256','lease_sha256','lease_source_path',
    'package_sha256','combination_sha256','retirement','prior_boundary','inventory',
    'non_native_sidebranch','epoch_preservation','component_role_identities',
    'native_status','actual_native_calls','unknown_effects',
    'native_hash_chain_and_terminal_verified','two_original_r6_calls_verified',
    'all_actual_r6_calls_verified','global_ledger_delta_verified',
    'original_sender_and_draft_restoration_verified',
    'independent_role_and_endpoint_absence_verified','all_prior_originals_preserved',
    'original_retirement_rewritten','old_retirement_current_equality_claimed',
    'capture','archive','independent_native_audit','typed_reparse','ledger','sender',
    'root_fixture','root_fixture_attempts','root_fixture_directory_originals',
    'root_fixture_absence_originals','original_host_inputs','closure_source_sha256',
    'phone_calls','commands_executed','boundary_published_here')
_EPS_SAVED = (
    ('inputs_manifest','epoch-inputs/MANIFEST.json'),
    ('legacy_semantic','epoch-inputs/LEGACY-SEMANTIC.json'),
    ('active_semantic','epoch-inputs/ACTIVE-SEMANTIC.json'),
    ('inventory_spec','after/EPOCH-INVENTORY-SPEC.json'),
    ('inventory_observation','after/EPOCH-INVENTORY-OBSERVATION.json'),
    ('control_inventory','after/CONTROL-INVENTORY.json'))


def _eps_modules(late_module):
    common, lifecycle = _epoch_inventory_module()
    context = common.epoch_actual_context(globals())
    common._ep_need(common.epoch_actual_context(late_module.__dict__) == context,
                    'active replay lost its explicit actual late context')
    raw = globals().get('__reviewed_package_manifest_raw__')
    sources = globals().get('__reviewed_package_sources__')
    common._ep_need(type(raw) is bytes and type(sources) is dict and len(sources) == 32
        and getattr(common,'__reviewed_package_manifest_raw__',None) == raw
        and getattr(lifecycle,'__reviewed_package_manifest_raw__',None) == raw
        and getattr(late_module,'__reviewed_package_manifest_raw__',None) == raw,
        'all active modules must retain the same complete source-authorized manifest')
    manifest = common._ep_strict(raw)
    common._ep_need(type(manifest) is dict and type(manifest.get('files')) is list
        and len(manifest['files']) == 32, 'the exact complete runtime manifest is absent')
    seen = set()
    for row in manifest['files']:
        common._ep_exact(row, {'path','bytes','sha256'}, 'runtime row fields differ')
        path = row['path']
        common._ep_need(type(path) is str and path not in seen and path in sources
            and path.startswith(('source/','reference/'))
            and not path.startswith('/') and '..' not in path.split('/')
            and '' not in path.split('/') and '\0' not in path
            and (path.endswith('.py') or path.endswith('.json'))
            and type(row['bytes']) is int
            and 0 < row['bytes'] <= (131072 if path.endswith('.py') else 16*1024*1024)
            and type(sources[path]) is bytes
            and common._ep_bare(sources[path]) == {k:row[k] for k in ('bytes','sha256')},
            'active replay complete runtime bytes differ')
        seen.add(path)
    common._ep_need(seen == set(sources), 'active source map has omitted or extra bytes')
    for module, name in ((common,'component_common'), (lifecycle,'component_lifecycle'),
                         (late_module,'late_boundary')):
        common._ep_need(getattr(module,'__reviewed_source_sha256__',None)
            == common._ep_sha(sources['source/'+name+'.py']), 'loaded active module source differs')
    common._ep_need(globals().get('__reviewed_source_sha256__')
        == common._ep_sha(sources['source/prepare_component.py']), 'active prepare source differs')
    return common, lifecycle, context, raw, sources


def _eps_read(pin, index, originals, budget_check):
    budget_check()
    common, _life = _epoch_inventory_module()
    raw = common._ep_manifest_raw(pin, index, originals)
    budget_check()
    return raw


def _eps_snapshot_api():
    """Use the already loaded reviewed member; never import a target path."""
    common,_life=_epoch_inventory_module()
    module=sys.modules.get('component_snapshot')
    sources=globals().get('__reviewed_package_sources__')
    raw=globals().get('__reviewed_package_manifest_raw__')
    common._ep_need(module is not None and type(sources) is dict and type(raw) is bytes
        and common.epoch_actual_context(module.__dict__)==common.epoch_actual_context(globals())
        and getattr(module,'__reviewed_package_manifest_raw__',None)==raw
        and getattr(module,'__reviewed_source_sha256__',None)
            ==common._ep_sha(sources['source/component_snapshot.py']),
        'the exact current snapshot member must already be loaded in the same actual context')
    observed=getattr(module,'__reviewed_package_sources__',None)
    common._ep_need(type(observed) is dict and set(observed)==set(sources)
        and all(type(observed[name]) is bytes and observed[name]==body for name,body in sources.items()),
        'snapshot authority lost the complete original current32 source map')
    return module


def epoch_verify_closure_action_authority(record, slot, registry, index, originals,
        *,boundary_raw,inventory_raw,closure_raw,capture,budget_check):
    common,_life=_epoch_inventory_module()
    common._ep_need(callable(budget_check),'same enclosing closure authority budget required')
    budget_check();snapshot=_eps_snapshot_api()
    gate=getattr(snapshot,'verify_epoch_closure_authority',None)
    common._ep_need(callable(gate),'the source-bound two-layer closure action gate is not installed')
    ordinal=record['ordinal']
    common._ep_need(type(ordinal) is int and 1<=ordinal<=8
        and slot['ordinal']==ordinal and slot['identity'] is not None
        and common._ep_same(slot['identity']['original'],record['identity']),
        'closure action is not the exact actual allocated ordinal')
    matching=[row for row in registry['generations'] if common._ep_same(row['original'],record['generation'])]
    common._ep_need(len(matching)==1,'closure action source generation is not independently catalogued')
    path=common.EPOCH_REGISTRY_ROOT+'/slots/%02d/closure-authority/AUTHORITY.json'%ordinal
    pin=index['files'].get(path)
    common._ep_need(pin is not None,'actual closure source/action authority original is absent')
    expected={'epoch_id':common.EPOCH_ID,'ordinal':ordinal,
        'nonce':slot['identity']['value']['nonce'],'identity':record['identity'],
        'generation':record['generation'],'registry_root':common.EPOCH_REGISTRY_ROOT,
        'identity_value':slot['identity']['value'],'epoch_binding':capture['lease']['epoch']}
    def original_from(value):
        return _eps_read(value,index,originals,budget_check)
    def directory_from(value):
        budget_check()
        common._ep_need(value in index['directories'],'actual complete authority directory is absent')
        return index['directories'][value]
    value=gate(pin,expected=expected,original_from=original_from,directory_from=directory_from,
        runtime_raw=globals()['__reviewed_package_manifest_raw__'],
        runtime_sources=globals()['__reviewed_package_sources__'],generation=matching[0]['value'],
        closure_raw=closure_raw,inventory_raw=inventory_raw,capture_raw=capture['capture_raw'],
        budget_check=budget_check)
    budget_check()
    return value


def _eps_saved_leaf(index, originals, path, bare, budget_check):
    common, _life = _epoch_inventory_module()
    row = index['files'].get(path)
    common._ep_need(row is not None and common._ep_same(
        {k:row[k] for k in ('bytes','sha256')}, bare),
        'an exact saved capture body and its real phone metadata are missing')
    return row, _eps_read(row, index, originals, budget_check)


def _eps_roles(value):
    common, _life = _epoch_inventory_module()
    common._ep_exact(value, {'supervisor','provider','sidecar'}, 'three native role originals required')
    roles = [value[name] for name in ('supervisor','provider','sidecar')]
    common._ep_need(all(type(row) is list and len(row) == 4
        and all(type(n) is int and n > 1 for n in row) and row[:3] == [row[0]]*3
        for row in roles) and len({tuple(row) for row in roles}) == 3
        and len({row[0] for row in roles}) == 3, 'native role generations repeat or are malformed')
    return roles


def _eps_semantic_value(lease, verified, checked, preservation):
    common, _life = _epoch_inventory_module()
    active = verified['active']; registry = verified['registry']
    ordinal = lease['epoch']['ordinal']
    common._ep_need(type(ordinal) is int and 1 <= ordinal <= 8
        and len(checked) == ordinal - 1 and len(active['closed_native_records']) == len(checked),
        'active semantics must cover every previous consumed native ordinal exactly once')
    boundaries = [row['boundary'] for row in checked]
    common._ep_need([row['record']['ordinal'] for row in checked] == list(range(1,ordinal))
        and common._ep_same([row['record'] for row in checked],active['closed_native_records']),
        'checked active records are not the complete original prefix')
    previous = None if not checked else checked[-1]['record']['boundary']
    terminal = None if not checked else checked[-1]['record']['terminal']
    common._ep_need(common._ep_same(preservation['prior_boundary'],previous)
        and common._ep_same(preservation['predecessor_terminal'],terminal)
        and preservation['closed_components'] == ordinal-1
        and preservation['consumed_slots_before_current'] == ordinal-1,
        'active semantics changed its actual preservation predecessor')
    result = {'schema':'hepta.native-guard.epoch-active-semantics.v1',
        'epoch_id':common.EPOCH_ID,'boot_id':lease['boot_id'],
        'epoch_anchor':lease['epoch']['anchor'],'current_ordinal':ordinal,
        'current_identity':active['current_identity'],
        'current_scope_binding':active['current_scope_binding'],
        'current_generation':lease['epoch']['generation'],
        'closed_records':[row['record'] for row in checked],
        'previous_native_components':len(checked),'consumed_slots_before_current':ordinal-1,
        'native_nonces':[row['nonce'] for row in boundaries],
        'native_scopes':[row['scope'] for row in boundaries],
        'native_call_counts':[row['actual_native_calls'] for row in boundaries],
        'retired_active_role_identities':[role for row in boundaries for role in _eps_roles(row['component_role_identities'])],
        'qualified_case_ids':[row['case_id'] for row in boundaries if row['component_qualified']],
        'preservation_inventory_original':preservation['preservation_inventory_original'],
        'previous_active_boundary':previous,'predecessor_terminal':terminal,
        'source_generations':registry['generations'],
        'all_previous_native_records_verified':True,'legacy_domains_flattened':False,
        'legacy_semantics_verified_here':False,'live_inventory_verified_here':False,
        'role_absence_verified_here':False,'endpoints_verified_here':False,
        'component_qualified':False,'business_qualified':False,'native_boundary_created':False}
    common._ep_exact(result, common.EPOCH_ACTIVE_SEMANTIC_FIELDS, 'active29 result contract differs')
    return result


def _eps_capture_view(boundary, inventory, outer_index, outer_originals,
                      prior_checked, *, late_module, budget_check):
    common, lifecycle, context, runtime_raw, sources = _eps_modules(late_module)
    epoch = boundary['epoch']
    lease_raw = _eps_read(epoch['lease'],outer_index,outer_originals,budget_check)
    lease = common._ep_strict(lease_raw)
    common.epoch_lease_protocol_value(lease)
    cap_raw = _eps_read(epoch['capture'],outer_index,outer_originals,budget_check)
    cap = common._ep_strict(cap_raw)
    manifest_raw = _eps_read(epoch['capture_manifest'],outer_index,outer_originals,budget_check)
    manifest = common._ep_strict(manifest_raw)
    common._ep_need(common._ep_encoded(manifest) == manifest_raw,
                    'the saved original preclose manifest is not canonical')
    for key in ('anchor','initialization','ordinal','reservation','identity','generation'):
        common._ep_need(common._ep_same(epoch[key],lease['epoch'][key]),
                        'saved lease changed the boundary epoch link: '+key)
    common._ep_need(type(cap) is dict
        and cap.get('schema') == 'hepta.native-guard.epoch-original-capture.v1'
        and cap.get('state') == 'ORIGINAL_BYTES_CAPTURED_FOR_INDEPENDENT_AUDIT'
        and cap['lease_sha256'] == common._ep_sha(lease_raw)
        and all(common._ep_same(cap[key],boundary[key]) for key in
            ('boot_id','nonce','case_id','scope','owner_request_sha256','package_sha256','combination_sha256'))
        and lease['nonce'] == boundary['nonce'] and lease['case_id'] == boundary['case_id']
        and lease['boot_id'] == boundary['boot_id']
        and lease['package_sha256'] == boundary['package_sha256']
        and lease['combination']['sha256'] == boundary['combination_sha256'],
        'the original lease/capture/boundary identity differs')
    snapshot = str(common.BASE/'native-guard-snapshots-r10-r1'/(lease['label']+'-capture-01'))
    common._ep_need(epoch['capture']['path'] == snapshot+'/CAPTURE.json'
        and epoch['lease']['path'] == str(common.BASE/'native-guard-r10-r1'/lease['label']/'LEASE.json')
        and epoch['capture_manifest']['path'] == snapshot+'/snapshot/epoch-inputs/MANIFEST.json',
        'saved preclose originals left their actual single-use namespace')
    raw_by_path = {}; expected_names = {name for _key,name in _EPS_SAVED if name.startswith('epoch-inputs/')}
    for row in manifest['files']:
        raw = _eps_read(row,outer_index,outer_originals,budget_check)
        name = 'epoch-inputs/files/'+common._ep_sha(row['path'].encode('utf-8'))+'.original'
        common._ep_need(row['path'] not in raw_by_path and name not in expected_names
            and name in cap['files'], 'saved protocol original is missing or repeats')
        retained = cap['files'][name]
        common._ep_need(retained['kind'] == 'original_file_bytes'
            and retained['source_path'] == row['path']
            and common._ep_same(retained['source_metadata'],row['metadata'])
            and common._ep_bare(raw) == {k:retained[k] for k in ('bytes','sha256')},
            'saved protocol bytes borrowed a different original phone identity')
        raw_by_path[row['path']] = raw; expected_names.add(name)
    common._ep_need({name for name in cap['files'] if name.startswith('epoch-inputs/')} == expected_names,
                    'saved epoch capture namespace is not complete and closed')
    saved = {}; saved_pins = {}; binding = {'schema':'hepta.native-guard.epoch-capture-binding.v1',
        'native_chain_domains_flattened':False,'case_or_lease_authorized':False}
    for key, name in _EPS_SAVED:
        row = cap['files'].get(name)
        common._ep_need(type(row) is dict and row['kind'] == 'derived_read_observation'
            and row['source_path'] is None and row['source_metadata'] is None,
            'saved derived observation was relabeled as an earlier physical input')
        bare = {k:row[k] for k in ('bytes','sha256')}
        pin, raw = _eps_saved_leaf(outer_index,outer_originals,snapshot+'/snapshot/'+name,bare,budget_check)
        binding[key] = common._ep_bare(raw); saved[key] = common._ep_strict(raw); saved_pins[key] = pin
        if key in ('legacy_semantic','active_semantic'):
            common._ep_need(common._ep_same(epoch[key],pin), 'published semantic original differs')
        if key == 'inventory_observation':
            common._ep_need(common._ep_same(epoch['capture_epoch_observation'],pin),
                            'published inventory observation differs')
    common._ep_need(common._ep_same(cap['epoch'],binding)
        and common._ep_same(saved['inputs_manifest'],manifest), 'six complete captured observation bindings differ')
    replayed = epoch_verify_capture_protocol(lease,manifest,raw_by_path,
                                            inventory_validator=late_module.inventory_value)
    common._ep_need(common._ep_same(replayed['active']['closed_native_records'],
                                    [row['record'] for row in prior_checked])
        and replayed['active']['current_ordinal'] == epoch['ordinal']
        and common._ep_same(replayed['active']['current_identity'],epoch['identity'])
        and common._ep_same(replayed['active']['current_scope_binding'],epoch['scope_binding']),
        'the saved preclose registry is not the original exact prior prefix and current ordinal')
    preservation = epoch_preservation_context_from_protocol(lease,replayed,manifest=manifest,
        originals_by_path=raw_by_path,inventory_validator=late_module.inventory_value)
    common._ep_need(common._ep_same(preservation['preservation_inventory_original'],epoch['preservation_inventory'])
        and common._ep_same(preservation['lease_prior_boundary'],boundary['prior_boundary']),
        'preservation cannot skip a retained terminal or substitute its actual inventory')
    expected_spec = epoch_planned_inventory_from_protocol(replayed['anchor'],replayed['registry'],replayed['failure_inputs'])
    expected_spec = common._ep_strict(common._ep_encoded(expected_spec))
    snapshot = _eps_snapshot_api()
    alias_gate = getattr(snapshot,'_eps_alias_pairs_from_capture',None)
    common._ep_need(callable(alias_gate), 'the exact complete-home alias reader is not installed')
    expected_spec['alias_pairs'] = alias_gate(expected_spec,cap['files'],cap['directories'])
    common._ep_need(common._ep_same(saved['inventory_spec'],expected_spec),
                    'saved one-pool inventory specification does not derive from actual stage originals')
    summary = lifecycle.verify_epoch_inventory_observation(expected_spec,inventory,
        saved['control_inventory'],saved['inventory_observation'])
    manifest_gate = getattr(snapshot,'_eps_manifest_inventory_rows',None)
    common._ep_need(callable(manifest_gate),'the exact manifest/inventory raw-row gate is not installed')
    manifest_gate(manifest,inventory,saved['control_inventory'],saved['inventory_observation'])
    budget_check()
    phone_active = saved['active_semantic']
    common._ep_exact(phone_active,common.EPOCH_ACTIVE_PROOF_FIELDS,'saved active proof outer fields differ')
    common._ep_need(phone_active['schema'] == 'hepta.native-guard.epoch-active-semantic-proof.v1'
        and phone_active['actual_context'] == 'phone','saved active proof is not the original phone result')
    epoch_verify_phone_active_source_observation(phone_active['source_observation'],manifest,raw_by_path,replayed)
    expected_semantic = _eps_semantic_value(lease,replayed,prior_checked,preservation)
    common._ep_need(common._ep_same(phone_active['semantic'],expected_semantic),
        'saved active semantics do not equal the independently verified ordinal prefix')
    phone_legacy = saved['legacy_semantic']
    common._ep_exact(phone_legacy,{'schema','semantic','actual_context','source_observation'},
                      'saved legacy proof fields differ')
    common._ep_need(phone_legacy['schema'] == 'hepta.native-guard.epoch-legacy-semantic-proof.v1'
        and phone_legacy['actual_context'] == 'phone','saved legacy proof context differs')
    late_module.verify_epoch_phone_legacy_source_observation(phone_legacy['source_observation'],
        manifest,raw_by_path,replayed)
    retired, retired_roles = late_module._epoch_retired_from_capture(lease['retirement'],
        lease['boot_id'],common.epoch_manifest_value(manifest,raw_by_path,binding=common.epoch_binding_value()),raw_by_path)
    common._ep_need(common._ep_same(lease['retirement'],replayed['legacy']['retirement']),
                    'record changed the immutable five original retirement inputs')
    budget_check()
    return {'lease':lease,'lease_raw':lease_raw,'capture':cap,'capture_raw':cap_raw,
        'manifest':manifest,'originals_by_path':raw_by_path,'verified':replayed,
        'preservation':preservation,'saved':saved,'saved_pins':saved_pins,
        'binding':binding,'inventory_summary':summary,'expected_semantic':expected_semantic,
        'retired':retired,'retired_roles':retired_roles}


def _eps_closure_details(boundary, inventory_raw, closed, capture, *, sources, budget_check):
    common, _life = _epoch_inventory_module()
    common._ep_exact(closed,_EPS_CLOSURE_FIELDS,'complete original epoch closer output differs')
    common._ep_need(closed['schema'] == 'hepta.native-guard.epoch-original-closure.v1'
        and closed['state'] in ('ORIGINAL_NATIVE_COMPONENT_CLOSED','ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED')
        and closed['closed'] is True and type(closed['component_qualified']) is bool,
        'a current epoch native closure is absent')
    passed = closed['state'] == 'ORIGINAL_NATIVE_COMPONENT_CLOSED'
    count = closed['actual_native_calls']
    common._ep_need(type(count) is int and 0 <= count <= 2
        and closed['component_qualified'] is passed
        and ((passed and closed['native_status'] == 'completed' and count == 2)
             or (not passed and closed['native_status'] in ('provider_failed','cancelled'))),
        'failed or incomplete native execution cannot become qualified')
    for key in ('business_qualified','four_role_qualification','automatic_replay',
                'original_retirement_rewritten','old_retirement_current_equality_claimed','boundary_published_here'):
        common._ep_need(closed[key] is False,'closure grants an unsupported authority: '+key)
    for key in ('model_requests','unknown_effects','phone_calls','commands_executed'):
        common._ep_need(type(closed[key]) is int and closed[key] == 0,'closure count must be exact zero: '+key)
    for key in ('native_hash_chain_and_terminal_verified','all_actual_r6_calls_verified',
                'global_ledger_delta_verified','original_sender_and_draft_restoration_verified',
                'independent_role_and_endpoint_absence_verified','all_prior_originals_preserved'):
        common._ep_need(closed[key] is True,'original host closure omitted a mandatory gate: '+key)
    common._ep_need(closed['two_original_r6_calls_verified'] is (count == 2),
                    'r6 call count was promoted or omitted')
    for key in ('boot_id','nonce','case_id','scope','owner_request_sha256','package_sha256',
                'combination_sha256','retirement','prior_boundary','non_native_sidebranch',
                'component_role_identities','component_qualified','native_status','actual_native_calls'):
        common._ep_need(common._ep_same(closed[key],boundary[key]),'closure boundary differs: '+key)
    common._ep_need(closed['lease_sha256'] == common._ep_sha(capture['lease_raw'])
        and closed['lease_source_path'] == boundary['epoch']['lease']['path']
        and closed['closure_source_sha256'] == common._ep_sha(sources['source/close_component.py'])
        and common._ep_same(closed['capture'],common._ep_bare(capture['capture_raw']))
        and common._ep_same(closed['inventory'],common._ep_bare(inventory_raw)),
        'closure changed the actual source, lease, capture or complete inventory bytes')
    # These are cross-checks of the real output. They are deliberately not
    # described as a second execution of the host native/ledger/r6 audit.
    typed = closed['typed_reparse']
    common._ep_exact(typed,{'component_qualified','actual_calls','all_original_r6_terminals_verified',
        'unknown_effects','age','receipt_states','typed_rejections','phone_calls','commands_executed'},
        'original typed native reparse fields differ')
    common._ep_need(typed['component_qualified'] is passed and type(typed['actual_calls']) is int
        and typed['actual_calls'] == count and typed['all_original_r6_terminals_verified'] is True
        and all(type(typed[k]) is int and typed[k] == 0 for k in ('unknown_effects','phone_calls','commands_executed'))
        and type(typed['receipt_states']) is list and len(typed['receipt_states']) == count
        and type(typed['typed_rejections']) is list and (not passed or typed['typed_rejections'] == []),
        'typed reparse contradicts actual native terminals or qualification')
    audit = closed['independent_native_audit']
    common._ep_need(type(audit) is dict and audit.get('status') == 'PASS'
        and audit.get('errors') == [] and audit.get('unsupported') == []
        and type(audit.get('record_hashes_verified')) is int and audit['record_hashes_verified'] > 0
        and audit['record_hashes_verified'] == audit.get('selected_scope_record_count'),
        'real host native audit output is incomplete or rejects the original chain')
    ledger = closed['ledger']; ordinal = boundary['epoch']['ordinal']
    common._ep_exact(ledger,{'actual_actions','new_inventory_entries',
        'previous_active_closed_components','legacy_closed_components'},'complete epoch ledger output differs')
    common._ep_need(type(ledger['actual_actions']) is list and len(ledger['actual_actions']) == count
        and len(set(ledger['actual_actions'])) == count
        and all(type(v) is str and v for v in ledger['actual_actions'])
        and type(ledger['new_inventory_entries']) is int and ledger['new_inventory_entries'] >= 0
        and type(ledger['previous_active_closed_components']) is int
        and ledger['previous_active_closed_components'] == ordinal-1
        and type(ledger['legacy_closed_components']) is int and ledger['legacy_closed_components'] == 6,
        'ledger confuses active records with the separate historical domain')
    common._ep_need(type(closed['original_host_inputs']) is dict and closed['original_host_inputs']
        and type(closed['root_fixture_attempts']) is list,
        'real host original inputs and actual fixture attempts are missing')
    for path, row in closed['original_host_inputs'].items():
        common._ep_path(path)
        common._ep_exact(row,{'bytes','sha256','metadata'},'actual host original row fields differ')
        common._ep_full9(row['metadata'],kind='file')
        common._ep_need(type(row['bytes']) is int and row['bytes'] == row['metadata'][6]
            and type(row['sha256']) is str and common.HASH.fullmatch(row['sha256']),
            'actual host original size/hash differs from its independently retained identity')
    preservation = closed['epoch_preservation']; ctx = capture['preservation']
    expected = {'schema':'hepta.native-guard.epoch-closure-preservation.v1',
        'legacy_anchor':capture['saved']['inventory_spec']['legacy_anchor'],
        'legacy_native_components':6,'legacy_fixture_roots':7,
        'active_closed_components_before_current':ordinal-1,'consumed_slots_before_current':ordinal-1,
        'current_ordinal':ordinal,'prior_active_boundary':ctx['prior_boundary'],
        'lease_prior_boundary':ctx['lease_prior_boundary'],'predecessor_terminal':ctx['predecessor_terminal'],
        'preservation_inventory_original':ctx['preservation_inventory_original'],
        'lifecycle_admission_sha256':common._ep_sha(common._ep_encoded(ctx['lifecycle_admission_expected'])),
        'capture_binding':capture['binding'],'whole_union_verification':capture['inventory_summary'],
        'legacy_and_active_domains_are_separate':True,'historical_originals_rewritten':False,
        'boundary_published_here':False,'new_native_epoch_created_here':False}
    common._ep_exact(preservation,set(expected)|{'legacy_semantic','active_semantic'},
                      'complete closure preservation fields differ')
    for key,value in expected.items():
        common._ep_need(common._ep_same(preservation[key],value),'closure preservation differs: '+key)
    for key in ('legacy_semantic','active_semantic'):
        pair = preservation[key]; active = key == 'active_semantic'
        flags = {'context_source_bindings_kept_separate','physical_full9_source_observation_claimed'} if active else {'context_source_observations_kept_separate'}
        common._ep_exact(pair,{'phone','host','phone_serialized_observation','host_serialized_observation','semantic_sha256'}|flags,
                          'phone and host semantic provenance must remain separate')
        common._ep_need(common._ep_same(pair['phone'],capture['saved'][key])
            and type(pair['host']) is dict and pair['host']['actual_context'] in ('mac','p4')
            and pair['host']['schema'] == pair['phone']['schema']
            and common._ep_same(pair['host']['semantic'],pair['phone']['semantic'])
            and common._ep_same(pair['phone_serialized_observation'],
                common._ep_bare(common._ep_encoded(pair['phone'])))
            and common._ep_same(pair['host_serialized_observation'],
                common._ep_bare(common._ep_encoded(pair['host'])))
            and pair['semantic_sha256'] == common._ep_sha(common._ep_encoded(pair['host']['semantic'])),
            'closure semantic proof bytes or cross-context meaning differ')
        common._ep_need(pair['context_source_bindings_kept_separate' if active else 'context_source_observations_kept_separate'] is True,
                        'closure merged incompatible physical source observations')
        if active:
            common._ep_need(pair['physical_full9_source_observation_claimed'] is False,
                            'active module identity was relabeled as a physical source observation')
    budget_check()


def _eps_record(record, registry, index, originals, prior_checked, *, late_module, budget_check):
    common, lifecycle, context, runtime_raw, sources = _eps_modules(late_module)
    budget_check()
    ordinal = len(prior_checked)+1
    common._ep_exact(record,{'ordinal','generation','identity','scope_binding','boundary','inventory','closure','terminal'},
                      'complete original active record required')
    common._ep_need(type(record['ordinal']) is int and record['ordinal'] == ordinal
        and 1 <= ordinal <= 8 and ordinal <= len(registry['slots']),
        'one-record gate cannot skip an active ordinal')
    slot = registry['slots'][ordinal-1]
    common._ep_need(slot['terminal'] is not None and slot['identity'] is not None
        and slot['scope_binding'] is not None, 'native record is not durably terminal and scoped')
    boundary_raw = _eps_read(record['boundary'],index,originals,budget_check)
    inventory_raw = _eps_read(record['inventory'],index,originals,budget_check)
    closure_raw = _eps_read(record['closure'],index,originals,budget_check)
    boundary, inventory, closed = map(common._ep_strict,(boundary_raw,inventory_raw,closure_raw))
    common._ep_exact(boundary,_EPS_BOUNDARY_FIELDS,'explicit epoch boundary fields differ')
    common._ep_exact(boundary['epoch'],_EPS_BOUNDARY_EPOCH_FIELDS,'explicit epoch boundary binding differs')
    epoch = boundary['epoch']; identity = slot['identity']['value']; terminal = slot['terminal']['value']
    common._ep_need(boundary['schema'] == 'hepta.native-guard.epoch-boundary.v1'
        and boundary['state'] == 'CLOSED_COMPONENT_AND_CUMULATIVE_ORIGINALS_PRESERVED'
        and epoch['schema'] == 'hepta.native-guard.epoch-boundary-binding.v1'
        and epoch['epoch_id'] == common.EPOCH_ID and type(epoch['ordinal']) is int and epoch['ordinal'] == ordinal,
        'old flat boundary or foreign ordinal cannot enter the active domain')
    for key in ('nonce','label'):
        common._ep_need(type(identity[key]) is str,'actual allocated identity fields differ')
    common._ep_need(boundary['nonce'] == identity['nonce']
        and boundary['boot_id'] == registry['boot_id']
        and boundary['case_id'] == identity['case_id']
        and common._ep_same(boundary['scope'],slot['scope_binding']['value']['scope'])
        and boundary['owner_request_sha256'] == identity['owner_request']['sha256'],
        'native boundary changed its actual allocated identity or accepted scope')
    common.scope(boundary['scope'])
    source_record = [row for row in registry['generations'] if common._ep_same(row['original'],record['generation'])]
    common._ep_need(len(source_record) == 1 and source_record[0]['value']['ordinal'] == 1,
                    'later or unknown source generations require a separate reviewed reader')
    generation = source_record[0]['value']
    common._ep_need(boundary['package_sha256'] == common._ep_sha(runtime_raw) == generation['runtime']['sha256']
        and boundary['combination_sha256'] == generation['combination']['sha256']
        and boundary['publisher_source_sha256'] == common._ep_sha(sources['source/late_boundary.py']),
        'native record changed the actual reviewed source generation')
    for key in ('identity','scope_binding','generation'):
        common._ep_need(common._ep_same(epoch[key],record[key]),'boundary source/identity link differs: '+key)
    for key in ('boundary','closure','inventory'):
        common._ep_need(common._ep_same(terminal[key],record[key]),'terminal changed its immutable '+key)
    common._ep_need(common._ep_same(epoch['reservation'],slot['claim']['original'])
        and common._ep_same(record['terminal'],slot['terminal']['original'])
        and common._ep_same(record['identity'],slot['identity']['original'])
        and common._ep_same(record['scope_binding'],slot['scope_binding']['original'])
        and common._ep_same(boundary['inventory'],record['inventory'])
        and common._ep_same(boundary['closure'],record['closure']),
        'actual claim, scope or closed original crosslinks differ')
    # The actual predecessor is read from the durable current IDENTITY, never
    # synthesized by removing a later COMMIT or flattening the legacy chain.
    prior_boundary = identity['prior_boundary']
    previous = None if not prior_checked else prior_checked[-1]['record']['boundary']
    terminal_before = None if not prior_checked else prior_checked[-1]['record']['terminal']
    common._ep_need(common._ep_same(boundary['prior_boundary'],prior_boundary)
        and common._ep_same(epoch['previous_active_boundary'],previous)
        and common._ep_same(epoch['predecessor_terminal'],terminal_before)
        and common._ep_same(identity['predecessor_terminal'],terminal_before),
        'active native predecessor is discontinuous')
    roles = _eps_roles(boundary['component_role_identities'])
    common._ep_need(boundary['original_retirement_rewritten'] is False
        and boundary['business_qualified'] is False and boundary['automatic_replay'] is False
        and type(boundary['model_requests']) is int and boundary['model_requests'] == 0
        and common._ep_same(terminal['source_verifier'],generation['pure_verifier']),
        'native boundary or terminal changed its source authority or replay policy')
    late_module.inventory_value(inventory)
    common._ep_need(common._ep_same(boundary['roots'],inventory['roots']),
                    'boundary omitted a complete business inventory root')
    capture = _eps_capture_view(boundary,inventory,index,originals,prior_checked,
        late_module=late_module,budget_check=budget_check)
    common._ep_need(common._ep_same(epoch['lease'],slot['stage']['value']['lease'])
        and common._ep_same(capture['lease']['retirement'],boundary['retirement']),
        'closed lease did not come from the actual stage or retained original retirement')
    _eps_closure_details(boundary,inventory_raw,closed,capture,sources=sources,budget_check=budget_check)
    authority_gate = globals().get('epoch_verify_closure_action_authority')
    common._ep_need(callable(authority_gate), 'the actual source-bound host closure action gate is not installed')
    authority = authority_gate(record,slot,registry,index,originals,
        boundary_raw=boundary_raw,inventory_raw=inventory_raw,closure_raw=closure_raw,
        capture=capture,budget_check=budget_check)
    common._ep_need(type(authority) is dict
        and authority.get('schema') == 'hepta.native-guard.epoch-closure-action-verification.v1'
        and authority.get('state') == 'SOURCE_BOUND_ORIGINAL_HOST_CLOSURE_AND_OUTPUTS_VERIFIED'
        and common._ep_same(authority.get('closure'),common._ep_bare(closure_raw))
        and authority.get('host_deep_closure_execution_verified') is True
        and authority.get('host_archive_read_by_phone_or_consumer') is False,
        'structural closure summaries cannot grant actual host action authority')
    common._ep_need(type(boundary['component_qualified']) is bool
        and boundary['component_qualified'] is terminal['component_qualified'],
        'final native terminal changed independent component qualification')
    budget_check()
    return {'record':record,'boundary':boundary,'inventory':inventory,'closure':closed,
        'capture':capture,'roles':roles,'authority':authority}


def _eps_verify_prefix(verified, manifest, originals, *, late_module, budget_check):
    common, _life, _context, _runtime, _sources = _eps_modules(late_module)
    common._ep_need(callable(budget_check),'one enclosing original budget callback is required')
    budget_check()
    index = common.epoch_manifest_value(manifest,originals,binding=common.epoch_binding_value())
    records = verified['active']['closed_native_records']
    common._ep_need(type(records) is list and len(records) <= 8,
                    'bounded active native prefix required')
    forbidden = set(common.epoch_binding_value()['legacy_nonces']+common.epoch_binding_value()['failed_nonces'])
    scopes = set(); role_ids = set(); checked = []
    _retired,retired_roles = late_module._epoch_retired_from_capture(verified['legacy']['retirement'],
        verified['legacy']['boot_id'],index,originals)
    role_ids.update(map(tuple,retired_roles))
    legacy_head = None
    for old in verified['legacy']['native_chain']:
        raw = _eps_read(old['boundary'],index,originals,budget_check); value = common._ep_strict(raw)
        if legacy_head is None:legacy_head = value
        scopes.add(tuple(value['scope'][name] for name in common.EPOCH_SCOPE_KEYS))
        role_ids.update(tuple(row) for row in _eps_roles(value['component_role_identities']))
    side = verified['legacy']['non_native_sidebranch']
    side_value = common._ep_strict(_eps_read(side['closure'],index,originals,budget_check))
    common._ep_need(side_value['schema'] == 'hepta.native-guard.non-native-attempt-closure.v1'
        and side_value['state'] == 'ORIGINAL_PRE_NATIVE_ATTEMPT_FAILED_CLOSED'
        and side_value['facts']['component_qualified'] is False
        and side_value['facts']['native_scope_assigned'] is False
        and side_value['facts']['native_case_created'] is False
        and type(side_value['facts']['native_case_count']) is int
        and side_value['facts']['native_case_count'] == 0,
        'the separate original pre-native failure cannot become a native scope')
    role_ids.update(map(tuple,_eps_roles(side_value['component_role_identities'])))
    for record in records:
        item = _eps_record(record,verified['registry'],index,originals,checked,
                           late_module=late_module,budget_check=budget_check)
        value = item['boundary']; scope = tuple(value['scope'][name] for name in common.EPOCH_SCOPE_KEYS)
        common._ep_need(value['nonce'] not in forbidden and scope not in scopes
            and not (set(map(tuple,item['roles'])) & role_ids)
            and common._ep_same(value['non_native_sidebranch'],legacy_head['non_native_sidebranch']),
            'active native nonce, scope or role generation reuses an earlier domain')
        forbidden.add(value['nonce']);scopes.add(scope);role_ids.update(map(tuple,item['roles']));checked.append(item)
    budget_check()
    return checked, index


def epoch_verify_active_semantics(lease, manifest, originals_by_path, verified,
                                  *, late_module, budget_check):
    """Verify only previous active native records, in order, with no recursion."""
    common, _life, context, _runtime, _sources = _eps_modules(late_module)
    common._ep_need(callable(budget_check),'the original enclosing budget must be provided')
    budget_check()
    replayed = epoch_verify_capture_protocol(lease,manifest,originals_by_path,
                                            inventory_validator=late_module.inventory_value)
    common._ep_need(common._ep_same(replayed,verified)
        and replayed['registry']['mode'] == 'preclose'
        and len(replayed['active']['closed_native_records']) == lease['epoch']['ordinal']-1,
        'active semantics require the complete actual highest preclose protocol replay')
    source_observation = epoch_active_source_binding(replayed,actual_context=context)
    checked, _index = _eps_verify_prefix(replayed,manifest,originals_by_path,
        late_module=late_module,budget_check=budget_check)
    current = replayed['registry']['slots'][-1]
    common._ep_need(current['identity'] is not None and current['terminal'] is None
        and current['identity']['value']['nonce'] == lease['nonce'],
        'active semantics have no actual current uncommitted identity')
    current_scope = None if current['scope_binding'] is None else current['scope_binding']['value']['scope']
    forbidden = set(common.epoch_binding_value()['legacy_nonces']+common.epoch_binding_value()['failed_nonces'])
    forbidden.update(item['boundary']['nonce'] for item in checked)
    common._ep_need(lease['nonce'] not in forbidden,'current identity repeats an old or consumed nonce')
    if current_scope is not None:
        older = [item['boundary']['scope'] for item in checked]
        for row in replayed['legacy']['native_chain']:
            older.append(common._ep_strict(_eps_read(row['boundary'],_index,originals_by_path,budget_check))['scope'])
        # The fixed non-native05 original has no assigned native scope; its
        # nonce and real role generations are checked in the separate domain.
        common._ep_need(not any(common._ep_same(current_scope,row) for row in older),
                        'current accepted scope reuses an active or historical identity')
    preservation = epoch_preservation_context_from_protocol(lease,replayed,manifest=manifest,
        originals_by_path=originals_by_path,inventory_validator=late_module.inventory_value)
    semantic = _eps_semantic_value(lease,replayed,checked,preservation)
    value = {'schema':'hepta.native-guard.epoch-active-semantic-proof.v1','actual_context':context,
        'source_observation':source_observation,'semantic':semantic}
    budget_check()
    return common.epoch_active_proof_contract(value,expected_semantic=semantic,
        expected_source_observation=source_observation,actual_context=context)


def epoch_closed_boundary_from_originals(raw, inventory_raw, closure_raw, *, original_descriptor,
        registry_originals, combination_sha256, package_sha256, late_module, budget_check):
    common, _life, _context, runtime_raw, _sources = _eps_modules(late_module)
    common._ep_need(callable(budget_check),'one enclosing closed-record budget is required')
    common._ep_exact(registry_originals,{'manifest','originals_by_path'},
                      'actual postpublication registry originals are required')
    budget_check()
    manifest = registry_originals['manifest']; originals = registry_originals['originals_by_path']
    verified = epoch_verify_publication_protocol(manifest,originals,
                                                inventory_validator=late_module.inventory_value)
    checked, index = _eps_verify_prefix(verified,manifest,originals,
                                        late_module=late_module,budget_check=budget_check)
    matches = [item for item in checked if common._ep_same(item['record']['boundary'],original_descriptor)]
    common._ep_need(len(matches) == 1,'requested boundary is not one actually committed native ordinal')
    item = matches[0]; record = item['record']
    for given,key in ((raw,'boundary'),(inventory_raw,'inventory'),(closure_raw,'closure')):
        common._ep_need(type(given) is bytes
            and given == _eps_read(record[key],index,originals,budget_check),
            'public record API received different complete original bytes')
    common._ep_need(item['boundary']['package_sha256'] == package_sha256 == common._ep_sha(runtime_raw)
        and item['boundary']['combination_sha256'] == combination_sha256,
        'public closed record source/combination identity differs')
    budget_check()
    return item['boundary'], item['inventory'], item['closure']


def epoch_publish_result_from_originals(raw, *, registry_originals, late_module, budget_check):
    common, _life, _context, _runtime, _sources = _eps_modules(late_module)
    common._ep_need(callable(budget_check),'one enclosing publication result budget is required')
    common._ep_exact(registry_originals,{'manifest','originals_by_path'},'postpublication originals required')
    budget_check()
    verified = epoch_verify_publication_protocol(registry_originals['manifest'],registry_originals['originals_by_path'],
                                                inventory_validator=late_module.inventory_value)
    checked, _index = _eps_verify_prefix(verified,registry_originals['manifest'],registry_originals['originals_by_path'],
                                        late_module=late_module,budget_check=budget_check)
    common._ep_need(checked,'an empty active epoch cannot claim a native publication')
    item = checked[-1]; boundary=item['boundary'];record=item['record'];epoch=boundary['epoch']
    expected={'schema':'hepta.native-guard.epoch-boundary-publish-result.v1',
        'state':'ORIGINAL_EPOCH_NATIVE_BOUNDARY_AND_TERMINAL_PUBLISHED',
        'epoch_id':common.EPOCH_ID,'ordinal':record['ordinal'],'nonce':boundary['nonce'],
        'case_id':boundary['case_id'],'boundary':record['boundary'],'inventory':record['inventory'],
        'closure':record['closure'],'terminal':record['terminal'],'initialization':epoch['initialization'],
        'generation':record['generation'],'scope_binding':record['scope_binding'],
        'predecessor_terminal':epoch['predecessor_terminal'],
        'component_qualified':boundary['component_qualified'],'business_qualified':False,
        'native_boundary_created':True,'automatic_replay':False}
    budget_check()
    return common.epoch_publish_result_contract(common._ep_strict(raw),expected=expected)




def epoch_render_verified_close_program(coordinator_raw, plan_raw, closure_plan_raw, *,
                                        binding, base, bootstrap, budget_check):
    """Pure fixed recipe from an admitted snapshot action; no target source executes."""
    snapshot = _eps_snapshot_api()
    _eca_need = snapshot._eca_need
    _eca_strict = snapshot._eca_strict
    _eca_sha = snapshot._eca_sha
    from pathlib import PurePosixPath
    import stat
    _eca_need(callable(budget_check), 'the same complete action budget is required')
    budget_check()
    def _eca_owned_source_sections(coordinator_raw):
     tree=ast.parse(coordinator_raw);lines=coordinator_raw.splitlines(keepends=True)
     functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
     chain=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Chain')
     methods={n.name:n for n in chain.body if isinstance(n,ast.FunctionDef)}
     chosen=('need','sha','enc','strict','desc','read','put','syncdir','newdir','original_stream',
      'close_streams_owned','filedesc','capture_stat','close_unclaimed_capture_readers','capture_output_worker',
      'write_captured_output','capture_observation')
     operations=('stop_host_capture','persist_host_capture','verify_host_capture_outputs',
      'join_host_capture','execute_process','close_owned_host_outputs')
     def source(node):return b''.join(lines[node.lineno-1:node.end_lineno]).decode()
     raw='import hashlib,json,os,re,selectors,stat,subprocess,threading,time\nfrom pathlib import Path\n'
     raw+='HOST_OUTPUT_LIMIT=65536\nHOST_CAPTURE_POLL=0.025\nHOST_CAPTURE_STOP_WAIT=1.0\n'
     raw+='\n\n'.join(source(functions[name]) for name in chosen)+'\n\n'
     raw+='class EpochOwnedHostPhase:\n    def __init__(self,out):\n        self.out=Path(out);self.steps=[]\n'
     raw+='\n'.join(source(methods[name]) for name in operations)+'\n'
     return raw

    def _eca_entry_argv(package,manifest,entry,arguments,*,actual_context,seconds,binding,bootstrap):
     _eca_need({k:manifest[k] for k in ('bytes','sha256')}
    =={k:binding['runtime'][k] for k in ('bytes','sha256')}
      and entry in ('close_component','component_snapshot','stage_component','component_lifecycle',
       'run_root_fixture_phase','root_fixture_once','witness_bundle','late_boundary'),
      'one reviewed actual current entry and full runtime pin required')
     limits={'close_component':150,'component_snapshot':75,'stage_component':90,'component_lifecycle':60,
      'run_root_fixture_phase':250,'root_fixture_once':180,'witness_bundle':35,'late_boundary':100}
     _eca_need(actual_context in ('phone','p4') and type(seconds) is int and 0<seconds<=limits[entry]
      and type(arguments) is list and all(type(v) is str and '\0' not in v for v in arguments),
      'actual entry context, single operation bound or argv differs')
     return ['/usr/bin/python3','-I','-B','-c',bootstrap,
      str(package),str(manifest['bytes']),manifest['sha256'],entry,actual_context,str(seconds),*arguments]

    def _eca_render_close_program(coordinator_raw,plan_raw,closure_plan_raw,*,binding,base,bootstrap,budget_check):
     budget_check();plan=_eca_strict(plan_raw);closure=_eca_strict(closure_plan_raw)
     _eca_need(type(plan) is dict and plan.get('schema')==binding['root_plan_schema']
      and plan.get('package')==binding['runtime'] and plan.get('combination')==binding['combination']
      and plan.get('shared_materials')==binding['shared_materials']
      and type(plan.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}',plan['nonce'])
      and type(plan.get('label')) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',plan['label']),
      'actual epoch plan changed its complete current source generation or identity')
     epoch=plan.get('epoch')
     _eca_need(type(epoch) is dict and set(epoch)=={'schema','epoch_id','anchor','initialization',
      'ordinal','reservation','identity','generation'}
      and epoch['schema']=='hepta.native-guard.epoch-lease-binding.v1'
      and type(epoch['ordinal']) is int and 1<=epoch['ordinal']<=8
      and epoch['epoch_id']=='legacy902-active01',
      'actual complete bounded epoch identity links are required')
     for name in ('anchor','initialization','reservation','identity','generation'):
      original=epoch[name]
      _eca_need(type(original) is dict and set(original)=={'path','bytes','sha256','metadata'}
       and type(original['path']) is str and PurePosixPath(original['path']).is_absolute()
       and str(PurePosixPath(original['path']))==original['path'] and '..' not in PurePosixPath(original['path']).parts
       and type(original['bytes']) is int and 0<original['bytes']<=16777216
       and type(original['sha256']) is str and re.fullmatch('[0-9a-f]{64}',original['sha256'])
       and type(original['metadata']) is list and len(original['metadata'])==9
       and all(type(n) is int for n in original['metadata'])
       and stat.S_ISREG(original['metadata'][2]) and original['metadata'][5]==1
       and original['metadata'][6]==original['bytes'],
       'actual phone original must retain its own complete full9: '+name)
     _eca_need({k:epoch['generation'][k] for k in ('path','bytes','sha256')}==binding['generation'],
       'actual bounded claimed generation is required')
     root='/home/alex/codex-native-guard-chain-r10-r1/'+plan['nonce']
     _eca_need(PurePosixPath(plan['out'])==base/'native-guard-root-chains-r10-r1'/plan['label']
      and type(closure) is dict and set(closure)=={'schema','label','archive','capture_sha256','package',
      'sender_dir','sender_host_result','sender_local_once','sender_actor','request','previous',
      'preserved_draft','root_fixture_attempts'}
      and closure['schema']=='hepta.native-guard.closure-plan.v1' and closure['label']==plan['label'],
      'original finite closure plan fields or fixed Root namespace differ')
     manifest=dict(binding['runtime'],path=root+'/material/tree/package/MANIFEST.json')
     _eca_need(closure['package']==manifest and closure['archive']['path']==root+'/closure-inputs/ORIGINALS.tar.gz'
      and closure['sender_dir']=='/home/alex/codex-hepta-natural-'+plan['label']+'-root-v150',
      'closer input escaped the actual single case material/sender namespaces')
     for name in ('request','previous','preserved_draft'):
      _eca_need(closure[name]==dict(plan[name],path=root+'/inputs/'+name+'.original'),
        'closer actual original input differs from its Root plan: '+name)
     plan_path=root+'/CLOSURE-PLAN.json';out=root+'/closure'
     argv=_eca_entry_argv(root+'/material/tree/package',manifest,'close_component',
      ['--plan',plan_path,'--plan-sha256',_eca_sha(closure_plan_raw),'--out',out,
       '--execute-host-closure-once'],actual_context='p4',seconds=150,binding=binding,bootstrap=bootstrap)
     code=_eca_owned_source_sections(coordinator_raw)
     code+='\nROOT_PLAN='+repr(plan)+'\nCLOSURE_PLAN_RAW='+repr(closure_plan_raw)+'\n'
     code+='ROOT='+repr(root)+'\nPLAN_PATH='+repr(plan_path)+'\nARGV='+repr(argv)+'\n'
     code+='''need(read(PLAN_PATH,len(CLOSURE_PLAN_RAW))==CLOSURE_PLAN_RAW,'actual closure plan changed')
need(Path(ROOT).resolve(strict=True)==Path(ROOT),'exact existing P4 case namespace required')
runner=EpochOwnedHostPhase(ROOT)
try:
    runner.execute_process('epoch-close',ARGV,150,input_raw=None,async_start=False)
except BaseException:
    runner.close_owned_host_outputs()
    raise
phase=Path(ROOT)/'epoch-close';out=Path(ROOT)/'closure'
rows={}
for role,path in [('p4_intent',phase/'INTENT.json'),('p4_child',phase/'CHILD.json'),
    ('p4_result',phase/'RESULT.json'),('p4_output_capture',phase/'OUTPUT-CAPTURE.json'),
    ('p4_stdout',phase/'stdout.original'),('p4_stderr',phase/'stderr.original'),
    ('closure_plan',Path(PLAN_PATH)),('closure_result',out/'RESULT.json'),
    ('closed_original',out/'CLOSURE.original.json'),('inventory_original',out/'AFTER-INVENTORY.original.json')]:
    body=read(path,16777216)
    rows[role]={'origin':desc(path,body)}
rows['p4_joined']=dict(rows['p4_result'])
value={'schema':'hepta.native-guard.epoch-owned-host-closure-output.v2',
    'state':'ORIGINAL_INNER_CLOSER_JOINED_AND_OUTPUTS_RETAINED',
    'root_plan_sha256':sha(enc(ROOT_PLAN)),'inner_stdin':None,'originals':rows,
    'phone_calls':0,'signals_sent':0,'automatic_retry':False}
encoded=enc(value);need(len(encoded)<=65536,'complete descriptor-only closure envelope exceeds fixed output pool')
print(encoded.decode(),end='')
'''
     compile(code,'reviewed_epoch_inner_closer_producer','exec')
     budget_check()
     return {'code':code,'phase':'epoch-close','p4_root':root,'p4_directory':root+'/epoch-close',
      'p4_argv':argv,'p4_wait_seconds':150,'p4_output_limit_bytes_per_stream':65536,
      'closure_plan_path':plan_path,'closure_out':out,'mac_wait_seconds':180,
      'mac_directory':str(PurePosixPath(plan['out'])/'epoch-close')}
    return _eca_render_close_program(coordinator_raw, plan_raw, closure_plan_raw,
        binding=binding, base=base, bootstrap=bootstrap, budget_check=budget_check)

if __name__=='__main__':
    raise SystemExit(main())


# New explicitly scoped original collector for the existing prepare_component
# member. No target invocation is performed by importing this fragment. The
# enclosing phone operation supplies its existing clock through budget_check.

class _EpochOriginalCollector:
    def __init__(self, common, binding, budget_check):
        common._ep_need(callable(budget_check), 'one enclosing budget callback required')
        self.c=common; self.binding=binding; self.check=budget_check
        self.files={}; self.raw={}; self.directories={}; self.total=0
        self.public={r['path']:r for r in binding['control_leaves']}
        self.fixed={r['path']:r for r in binding['fixed_inputs']}
        self.fixed.update(self.public)
        self.approved_saved=set()

    def directory(self, path, *, private=False):
        c=self.c; self.check(); path=str(c._ep_path(path))
        row=c.epoch_read_directory(path); self.check()
        if private:
            c._ep_need(row['metadata'][3:5]==[0,0]
                       and c._ep_stat.S_IMODE(row['metadata'][2])==0o700,
                       'complete control directory must remain root-owned private')
        if path in self.directories:
            c._ep_need(c._ep_same(self.directories[path],row),
                       'directory changed within the complete original collection')
        else:
            c._ep_need(path not in self.files and len(self.directories)<30000,
                       'directory type conflict or metadata set exceeded')
            self.directories[path]=row
        return row

    def allowed_file(self,path):
        c=self.c; c._ep_path(path)
        return (path in self.fixed or path in self.approved_saved
            or any(path.startswith(root+'/') for root in self.binding['control_roots']))

    def file(self,path,*,expected=None):
        c=self.c; self.check(); path=str(c._ep_path(path))
        c._ep_need(self.allowed_file(path),'original is outside fixed historical/control/saved scopes')
        if expected is not None:
            c._ep_pin(expected,original=True)
            c._ep_need(expected['path']==path,'expected original path differs')
        if path in self.files:
            if expected is not None:
                c._ep_need(c._ep_same(self.files[path],expected),
                           'one original path has two byte/full9 identities')
            return self.files[path],self.raw[path]
        c._ep_need(len(self.files)<c.EPOCH_MAX_INPUT_FILES,
                   'complete original file count exceeds the one capture input pool')
        self.directory(str(c._EpPath(path).parent))
        chain,name=c._ep_parent_chain(path); fd=None
        try:
            self.check()
            fd=c._ep_os.open(name,c._ep_os.O_RDONLY|c._ep_os.O_NONBLOCK
                |c._ep_os.O_NOFOLLOW|c._ep_os.O_CLOEXEC,dir_fd=chain[-1][0])
            before=c._ep_metadata(c._ep_os.fstat(fd))
            c._ep_need(c._ep_stat.S_ISREG(before[2]) and before[5]==1
                       and type(before[6]) is int and 0<=before[6]
                       and before[6]<=c.EPOCH_MAX_INPUT_FILE
                       and before[6]<=c.EPOCH_MAX_INPUT_BYTES-self.total,
                       'original type/size exceeds the single precharged retained-body pool')
            public=self.public.get(path)
            if public is None:
                c._ep_need(before[3:6]==[0,0,1]
                           and c._ep_stat.S_IMODE(before[2])==0o600,
                           'original is not an exact root-owned private regular file')
            else:
                c._ep_need(before==public['metadata'] and before[6]==public['bytes'],
                           'old shell-owned incoming file changed its individually fixed full9')
            if expected is not None:
                c._ep_need(before==expected['metadata'] and before[6]==expected['bytes'],
                           'saved/fixed original differs before reading any content')
            parts=[];left=before[6]+1
            while left:
                self.check()
                part=c._ep_os.read(fd,min(65536,left))
                if not part:break
                parts.append(part);left-=len(part)
            body=b''.join(parts)
            c._ep_need(len(body)==before[6]
                       and before==c._ep_metadata(c._ep_os.fstat(fd))
                       ==c._ep_metadata(c._ep_os.stat(name,dir_fd=chain[-1][0],follow_symlinks=False))
                       ==c._ep_metadata(c._EpPath(path).lstat()),
                       'complete original changed its held/named/canonical file identity')
            row={'path':path,**c._ep_bare(body),'metadata':before}
            if public is not None:c._ep_need(c._ep_same(row,public),'old incoming body changed')
            if expected is not None:c._ep_need(c._ep_same(row,expected),'saved/fixed bytes changed')
            c._ep_chain_check(chain);self.check()
            self.total+=len(body);self.files[path]=row;self.raw[path]=body
        finally:
            if fd is not None:c._ep_os.close(fd)
            for item in reversed(chain):c._ep_os.close(item[0])
        self.directory(str(c._EpPath(path).parent))
        return row,body

    def tree(self,root):
        c=self.c
        c._ep_need(root in self.binding['control_roots'],'only the two complete private control roots may be scanned')
        pending=[(root,0)]
        while pending:
            path,depth=pending.pop();self.check()
            c._ep_need(depth<=16,'control directory depth exceeds the fixed protocol')
            row=self.directory(path,private=True)
            for name in row['names']:
                self.check();child=path+'/'+name
                before=c._EpPath(child).lstat()
                if c._ep_stat.S_ISDIR(before.st_mode):pending.append((child,depth+1))
                else:
                    c._ep_need(c._ep_stat.S_ISREG(before.st_mode),
                               'control namespace contains a link, special file or unknown type')
                    self.file(child)
            self.directory(path,private=True)

    def manifest(self):
        return {'schema':'hepta.native-guard.epoch-capture-inputs.v1',
            'files':[self.files[p] for p in sorted(self.files)],
            'directories':[self.directories[p] for p in sorted(self.directories)]}


def _epoch_saved_input_paths(common,label):
    common._ep_need(type(label) is str and common.EPOCH_LABEL.fullmatch(label),
                   'one actual registry identity label required')
    home=str(common.BASE/'native-guard-r10-r1'/label)
    snapshot=str(common.BASE/'native-guard-snapshots-r10-r1'/(label+'-capture-01'))
    return {'lease':home+'/LEASE.json','capture':snapshot+'/CAPTURE.json',
        'capture_manifest':snapshot+'/snapshot/epoch-inputs/MANIFEST.json',
        'legacy_semantic':snapshot+'/snapshot/epoch-inputs/LEGACY-SEMANTIC.json',
        'active_semantic':snapshot+'/snapshot/epoch-inputs/ACTIVE-SEMANTIC.json',
        'capture_epoch_observation':snapshot+'/snapshot/after/EPOCH-INVENTORY-OBSERVATION.json'}


def epoch_recheck_input_originals(manifest,*,budget_check):
    common,_lifecycle=_epoch_inventory_module()
    common._ep_need(common.epoch_actual_context(common.__dict__)=='phone'
                   and callable(budget_check),'actual phone and enclosing budget required')
    fixed=common.epoch_binding_value()
    common._ep_exact(manifest,{'schema','files','directories'},'complete recheck manifest required')
    common._ep_need(manifest['schema']=='hepta.native-guard.epoch-capture-inputs.v1'
                   and type(manifest['files']) is list
                   and 1<=len(manifest['files'])<=common.EPOCH_MAX_INPUT_FILES
                   and type(manifest['directories']) is list
                   and 1<=len(manifest['directories'])<=30000,
                   'bounded complete recheck sets required')
    public={r['path']:r for r in fixed['control_leaves']};total=0;seen=set()
    for row in manifest['files']:
        budget_check();common._ep_pin(row,original=True)
        common._ep_need(row['path'] not in seen,'recheck repeats an original path')
        seen.add(row['path']);total+=row['bytes']
        common._ep_need(total<=common.EPOCH_MAX_INPUT_BYTES,'recheck exceeds the retained input pool')
        common.epoch_read_original(row,public_exact=public.get(row['path']));budget_check()
    for row in manifest['directories']:
        budget_check()
        common._ep_exact(row,{'path','metadata','names'},'directory original fields differ')
        common._ep_need(row['path'] not in seen,'recheck file/directory identity conflict')
        seen.add(row['path'])
        common._ep_need(common._ep_same(common.epoch_read_directory(row['path']),row),
                       'directory names or full9 changed at the final collection bookend')
        budget_check()
    return common._ep_strict(common._ep_encoded(manifest))


def epoch_collect_original_inputs(lease,*,mode,budget_check,inventory_validator):
    common,_lifecycle=_epoch_inventory_module()
    common._ep_need(common.epoch_actual_context(common.__dict__)=='phone'
                   and mode in ('preclose','published') and callable(budget_check)
                   and callable(inventory_validator),'explicit phone collection mode and budgets required')
    budget_check();binding=common.epoch_binding_value();common.epoch_lease_protocol_value(lease)
    collector=_EpochOriginalCollector(common,binding,budget_check)
    for root in binding['control_roots']:collector.tree(root)
    for row in binding['fixed_inputs']+binding['control_leaves']:
        collector.file(row['path'],expected=row)
    slotroot=common.EPOCH_REGISTRY_ROOT+'/slots';directory=collector.directories[slotroot]
    names=directory['names']
    claims=[n for n in names if common._ep_re.fullmatch(r'0[1-8]\.CLAIM\.json',n)]
    count=len(claims)
    common._ep_need(1<=count<=common.EPOCH_MAX_SLOTS
                   and claims==['%02d.CLAIM.json'%i for i in range(1,count+1)]
                   and set(names)==set(claims+['%02d'%i for i in range(1,count+1)]),
                   'partial or unclaimed slot namespace cannot be collected as complete')
    labels=[];identities={}
    for ordinal in range(1,count+1):
        path=slotroot+'/%02d/IDENTITY.json'%ordinal
        common._ep_need(path in collector.raw,'preidentity or unknown slot blocks this capture/publication reader')
        identity=common._ep_strict(collector.raw[path]);label=identity.get('label')
        common._ep_need(type(label) is str and common.EPOCH_LABEL.fullmatch(label)
                       and label not in labels and type(identity.get('ordinal')) is int
                       and identity['ordinal']==ordinal,'actual slot identity/label order differs')
        labels.append(label);identities[ordinal]=identity
        collector.approved_saved.update(_epoch_saved_input_paths(common,label).values())
        collector.approved_saved.update(_epoch_saved_inventory_paths(common,label).values())
    common._ep_need(lease['label']==labels[-1]
                   and lease['nonce']==identities[count]['nonce']
                   and lease['epoch']['ordinal']==count,
                   'reader lease is not the actual highest consumed identity')
    leasepath=_epoch_saved_input_paths(common,lease['label'])['lease']
    _leasepin,lease_raw=collector.file(leasepath)
    common._ep_need(common._ep_same(common._ep_strict(lease_raw),lease),
                   'reader lease differs from the actual immutable phone original')
    for ordinal in range(1,count+1):
        prefix=slotroot+'/%02d/'%ordinal;terminal=prefix+'COMMIT.json'
        if terminal not in collector.raw:
            common._ep_need(mode=='preclose' and ordinal==count,
                           'publication cannot omit any consumed slot terminal')
            continue
        boundary_path=prefix+'BOUNDARY.json'
        common._ep_need(boundary_path in collector.raw,'terminal is missing its actual native boundary')
        boundary=common._ep_strict(collector.raw[boundary_path]);epoch=boundary.get('epoch')
        common._ep_need(type(epoch) is dict,'epoch native boundary lacks explicit domain binding')
        expected_paths=_epoch_saved_input_paths(common,labels[ordinal-1])
        for key,path in expected_paths.items():
            pin=epoch.get(key);common._ep_pin(pin,original=True)
            common._ep_need(pin['path']==path,'saved preclose dependency escaped its exact actual case path')
            collector.file(path,expected=pin)
        _epoch_collect_saved_inventory_inputs(common,collector,labels[ordinal-1],expected_paths)
        manifest_raw=collector.raw[expected_paths['capture_manifest']]
        saved=common._ep_strict(manifest_raw)
        common._ep_exact(saved,{'schema','files','directories'},'saved preclose manifest fields differ')
        common._ep_need(saved['schema']=='hepta.native-guard.epoch-capture-inputs.v1'
                       and common._ep_encoded(saved)==manifest_raw
                       and type(saved['files']) is list
                       and 1<=len(saved['files'])<=common.EPOCH_MAX_INPUT_FILES,
                       'saved preclose manifest is not canonical bounded original data')
        subset={}
        for row in saved['files']:
            common._ep_pin(row,original=True)
            common._ep_need(collector.allowed_file(row['path']),
                           'saved manifest cannot expand historical/control/case read authority')
            _pin,body=collector.file(row['path'],expected=row);subset[row['path']]=body
        # Preserve the old directory rows as historical observations. Never
        # refresh them with the post-COMMIT directory metadata just collected.
        common.epoch_manifest_value(saved,subset,binding=binding)
    manifest=collector.manifest();originals=dict(collector.raw)
    common.epoch_manifest_value(manifest,originals,binding=binding)
    if mode=='preclose':
        verified=epoch_verify_capture_protocol(lease,manifest,originals,
            inventory_validator=inventory_validator)
    else:
        verified=epoch_verify_publication_protocol(manifest,originals,
            inventory_validator=inventory_validator)
    epoch_recheck_input_originals(manifest,budget_check=budget_check);budget_check()
    return {'manifest':manifest,'originals_by_path':originals,'verified':verified}


def _epoch_saved_inventory_paths(common,label):
    saved=_epoch_saved_input_paths(common,label)
    directory=str(common._EpPath(saved['capture_epoch_observation']).parent)
    return {'inventory_spec':directory+'/EPOCH-INVENTORY-SPEC.json',
            'control_inventory':directory+'/CONTROL-INVENTORY.json'}


def _epoch_collect_saved_inventory_inputs(common,collector,label,saved_paths):
    """Retain both derived actual bodies, pinned by their saved CAPTURE rows.

    They have their own current phone full9 descriptors. A derived CAPTURE row
    has no origin metadata and is never passed off as that physical identity.
    """
    capture=common._ep_strict(collector.raw[saved_paths['capture']])
    common._ep_need(capture.get('schema')=='hepta.native-guard.epoch-original-capture.v1'
                   and type(capture.get('files')) is dict,
                   'only the actual epoch capture can authorize its fixed saved derived inputs')
    binding=capture.get('epoch')
    common._ep_exact(binding,{'schema','inputs_manifest','legacy_semantic','active_semantic',
        'inventory_spec','inventory_observation','control_inventory',
        'native_chain_domains_flattened','case_or_lease_authorized'},
        'saved CAPTURE epoch binding is not the exact six-descriptor contract')
    common._ep_need(binding['schema']=='hepta.native-guard.epoch-capture-binding.v1'
                   and binding['native_chain_domains_flattened'] is False
                   and binding['case_or_lease_authorized'] is False,
                   'saved CAPTURE cannot flatten domains or authorize a new case')
    paths={'inputs_manifest':saved_paths['capture_manifest'],
           'legacy_semantic':saved_paths['legacy_semantic'],
           'active_semantic':saved_paths['active_semantic'],
           'inventory_observation':saved_paths['capture_epoch_observation'],
           **_epoch_saved_inventory_paths(common,label)}
    relative={'inputs_manifest':'epoch-inputs/MANIFEST.json',
              'legacy_semantic':'epoch-inputs/LEGACY-SEMANTIC.json',
              'active_semantic':'epoch-inputs/ACTIVE-SEMANTIC.json',
              'inventory_spec':'after/EPOCH-INVENTORY-SPEC.json',
              'inventory_observation':'after/EPOCH-INVENTORY-OBSERVATION.json',
              'control_inventory':'after/CONTROL-INVENTORY.json'}
    for key,path in paths.items():
        collector.check()
        expected=binding[key]
        common._ep_exact(expected,{'bytes','sha256'},'saved derived binding must be an exact byte descriptor')
        common._ep_need(type(expected['bytes']) is int and 0<=expected['bytes']<=common.EPOCH_MAX_INPUT_FILE
                       and type(expected['sha256']) is str and common.EPOCH_HASH.fullmatch(expected['sha256']),
                       'saved derived input descriptor exceeds the unchanged per-original bound')
        row=capture['files'].get(relative[key])
        common._ep_exact(row,{'path','bytes','sha256','source_path','source_metadata','kind'},
                         'saved derived CAPTURE original row differs')
        common._ep_need(row['path']==relative[key] and row['source_path'] is None
                       and row['source_metadata'] is None and row['kind']=='derived_read_observation'
                       and common._ep_same({k:row[k] for k in ('bytes','sha256')},expected),
                       'saved derived CAPTURE identity was relabelled or changed')
        _actual,body=collector.file(path)
        common._ep_need(common._ep_bare(body)==expected,
                       'actual saved derived raw differs from both CAPTURE bindings')
        collector.check()


# Pure current-generation source identities, added to prepare_component.
# The owning loader must inject the exact reviewed runtime manifest bytes and
# complete source map before module evaluation. No virtual path is stat'ed.

def epoch_active_source_binding(verified, *, actual_context):
    common,lifecycle=_epoch_inventory_module()
    common._ep_need(actual_context in ('phone','mac','p4'), 'explicit proof context required')
    registry=verified['registry']
    common._ep_need(registry['mode']=='preclose'
                   and type(registry['slots']) is list and registry['slots'],
                   'active proof requires the actual highest preclose reservation')
    current=registry['slots'][-1]['claim']['value']['generation']
    common._ep_pin(current,original=True)
    records=registry['generations']
    common._ep_need(type(records) is list and len(records)==1,
                   'a later source generation requires its separately reviewed finite reader increment')
    record=records[0]
    common._ep_exact(record,{'original','value'},'complete actual generation record required')
    common._ep_need(common._ep_same(record['original'],current),
                   'current reservation selected a different source generation')
    common.epoch_generation_value(record['value'])
    common._ep_need(record['value']['ordinal']==1,
                   'first implementation cannot claim an unimplemented later generation')
    raw=getattr(common,'__reviewed_package_manifest_raw__',None)
    sources=getattr(common,'__reviewed_package_sources__',None)
    common._ep_need(type(raw) is bytes and type(sources) is dict
                   and common._ep_bare(raw)=={k:record['value']['runtime'][k] for k in ('bytes','sha256')},
                   'actual full runtime manifest bytes must match the source-authorized catalog')
    for module in (lifecycle,):
        common._ep_need(getattr(module,'__reviewed_package_manifest_raw__',None)==raw
                       and common._ep_same(
                           {p:common._ep_bare(b) for p,b in getattr(module,'__reviewed_package_sources__',{}).items()},
                           {p:common._ep_bare(b) for p,b in sources.items()}),
                       'secondary module loader changed or omitted the original reviewed source set')
    local_raw=globals().get('__reviewed_package_manifest_raw__')
    local_sources=globals().get('__reviewed_package_sources__')
    common._ep_need(type(local_raw) is bytes and local_raw==raw
                   and type(local_sources) is dict and set(local_sources)==set(sources)
                   and all(type(local_sources[p]) is bytes and local_sources[p]==b
                           for p,b in sources.items()),
                   'prepare loader lost the exact original manifest/source map')
    manifest=common._ep_strict(raw);rows=manifest.get('files')
    common._ep_need(type(rows) is list and len(rows)==32 and len(sources)==32,
                   'complete exactly32 runtime source members required')
    checked=[];seen=set()
    for row in rows:
        common._ep_exact(row,{'path','bytes','sha256'},'runtime source descriptor fields differ')
        path=row['path']
        common._ep_need(type(path) is str and '\0' not in path
                       and not path.startswith('/') and '..' not in path.split('/')
                       and '' not in path.split('/') and path not in seen and path in sources
                       and type(row['bytes']) is int and 0<row['bytes']
                       and ((path.endswith('.py') and row['bytes']<=131072)
                            or (path.endswith('.json') and row['bytes']<=16*1024*1024)),
                       'runtime member name, count or per-source bound differs')
        body=sources[path]
        common._ep_need(type(body) is bytes
                       and common._ep_bare(body)=={k:row[k] for k in ('bytes','sha256')},
                       'complete current runtime member bytes differ from the exact manifest')
        seen.add(path);checked.append(row)
    common._ep_need(seen==set(sources)
                   and getattr(common,'__reviewed_source_sha256__',None)
                       ==common._ep_sha(sources['source/component_common.py'])
                   and globals().get('__reviewed_source_sha256__')
                       ==common._ep_sha(sources['source/prepare_component.py']),
                   'loaded current code identities differ from the complete reviewed map')
    return {'schema':'hepta.native-guard.epoch-active-source-binding.v1',
        'context':actual_context,'current_generation':current,
        'generation_records':records,
        'reviewed_source_bindings':sorted(checked,key=lambda r:r['path']),
        'physical_full9_observation_claimed':False}


def epoch_verify_phone_active_source_observation(value,manifest,originals_by_path,verified):
    """Pure binding of captured phone proof to the same complete32 actual map.

    This does not recompute active semantics; the independent mandatory active
    semantic gate must still compare the complete semantic value separately.
    """
    common,_lifecycle=_epoch_inventory_module()
    common._ep_exact(value,common.EPOCH_ACTIVE_SOURCE_OBSERVATION_FIELDS,
                     'captured active source-binding fields differ')
    common._ep_need(value['schema']=='hepta.native-guard.epoch-active-source-binding.v1'
                   and value['context']=='phone'
                   and value['physical_full9_observation_claimed'] is False,
                   'captured source binding is not explicitly phone and nonphysical')
    index=common.epoch_manifest_value(manifest,originals_by_path,
                                     binding=common.epoch_binding_value())
    expected=epoch_active_source_binding(verified,actual_context='phone')
    for record in expected['generation_records']:
        pin=record['original'];common._ep_pin(pin,original=True)
        common._ep_need(pin['path'] in index['files']
                       and common._ep_same(index['files'][pin['path']],pin)
                       and common._ep_same(common._ep_strict(originals_by_path[pin['path']]),record['value']),
                       'captured source catalog is not the actual complete phone original')
    common._ep_need(common._ep_same(value,expected),
                   'phone source binding changes the catalog or any complete runtime member')
    return value
