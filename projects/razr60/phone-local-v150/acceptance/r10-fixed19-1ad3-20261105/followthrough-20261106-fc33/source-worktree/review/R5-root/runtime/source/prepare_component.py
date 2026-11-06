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
    rows=manifest['files'];need(len(rows)==38 and len({r['path'] for r in rows})==len(rows),'package inventory bound')
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


if __name__=='__main__':
    raise SystemExit(main())
