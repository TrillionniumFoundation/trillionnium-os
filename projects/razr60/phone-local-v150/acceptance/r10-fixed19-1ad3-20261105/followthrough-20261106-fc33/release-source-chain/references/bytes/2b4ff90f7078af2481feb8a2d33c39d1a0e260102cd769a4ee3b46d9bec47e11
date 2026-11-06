#!/usr/bin/env python3
"""One read-only r9 phone snapshot: process, exact source, sockets and slot.

No health prompt, native task, App action, service signal or recovery is issued.
The output is evidence of this observation, never a business acceptance result.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'source'))
from model_slot_cleanup import load_binding,private_bytes,verify_identity,admission_identity,get_json
from phone_local_http_worker import strict_json

BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
A=Path('/proc/1/root')
MODULE=A/'data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
MODEL_HASH='dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c'
PARENT_POLICY='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
BOUNDARY_CONSUMER_SHA256 = '3de6208604022671d4db21e2b479e3ef4d4bba4aaa9d2faa360f1865aec428da'


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def android_private(path,mode=0o600,limit=16*1024*1024):
    """Read below verified init root; no subsequent symbolic links are followed."""
    path=Path(path)
    need(path.is_relative_to(A),'Android read outside init root')
    parts=path.relative_to(A).parts
    need(parts and all(x not in ('','.', '..') for x in parts),'unsafe Android components')
    directory=os.open(A,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    descriptor=None
    try:
        for component in parts[:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            os.close(directory);directory=child
        descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
        before=os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
             before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==mode and
             0<=before.st_size<=limit,'private Android file metadata differs: '+str(path))
        raw=bytearray()
        while len(raw)<=limit:
            block=os.read(descriptor,min(65536,limit+1-len(raw)))
            if not block:break
            raw.extend(block)
        after=os.fstat(descriptor)
        named=os.stat(parts[-1],dir_fd=directory,follow_symlinks=False)
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_size','st_nlink','st_mtime_ns','st_ctime_ns')
        need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in fields),
             'private Android file changed during read')
        return bytes(raw)
    finally:
        if descriptor is not None:os.close(descriptor)
        os.close(directory)


def module_original(row):
    name=Path(row['path'])
    need(not name.is_absolute() and '..' not in name.parts and str(name)==row['path'] and
         '\n' not in row['path'] and '\r' not in row['path'],'unsafe module manifest path')
    maximum=32*1024*1024 if row['path']=='evidence/RELEASE-BOUNDARIES.json' else 16*1024*1024
    need(type(row['bytes']) is int and 0<=row['bytes']<=maximum,
         'bounded exact module input size required')
    raw=android_private(MODULE/name,0o700 if row['path']=='service.sh' else 0o600,limit=row['bytes'])
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'module source/evidence differs')
    return raw


def domain(path):
    raw=Path(path).read_bytes()
    if raw.endswith(b'\x00') or raw.endswith(b'\n'):raw=raw[:-1]
    need(b'\x00' not in raw and b'\n' not in raw and b'\r' not in raw,'malformed process domain')
    return raw.decode('ascii')


def process(pid):
    p=Path('/proc')/str(pid);raw=(p/'stat').read_text();tail=raw.rsplit(') ',1)[1].split()
    status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (p/'status').read_text().splitlines() if ':' in line}
    return dict(identity=[pid,int(tail[2]),int(tail[3]),int(tail[19])],state=tail[0],
                domain=domain(p/'attr/current'),uid=list(map(int,status['Uid'].split())),
                gid=list(map(int,status['Gid'].split())),no_new_privs=int(status['NoNewPrivs']),
                exe=os.readlink(p/'exe'))


def digest_file(path):
    h=hashlib.sha256();count=0
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):
            count+=len(block);need(count<32*1024*1024,'readiness source size bound');h.update(block)
    return h.hexdigest()


def sockets(pid):
    result=set()
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:target=os.readlink(fd)
        except FileNotFoundError:continue
        match=re.fullmatch(r'socket:\[([0-9]+)\]',target)
        if match:result.add(match.group(1))
    return result


def listen(port,pid):
    rows=[line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
    matches=[row for row in rows if row[1]=='0100007F:'+format(port,'04X') and row[3]=='0A']
    need(len(matches)==1 and matches[0][9] in sockets(pid),'owned loopback listener absent')
    return dict(address='127.0.0.1',port=port,inode=matches[0][9],owner_pid=pid)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--expected-boot',required=True)
    parser.add_argument('--source-seal-sha256',required=True)
    parser.add_argument('--configuration-sha256',required=True)
    parser.add_argument('--module-manifest-sha256',required=True)
    parser.add_argument('--component-boundary-inputs-sha256',required=True)
    parser.add_argument('--policy-adoption-inputs-sha256',required=True)
    args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0,'root required')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(boot==args.expected_boot and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot),'unexpected boot')
    need(os.readlink('/proc/1/exe')=='/system/bin/init' and domain('/proc/1/attr/current')=='u:r:init:s0','native proc view differs')
    need((A/'sys/fs/selinux/enforce').read_text().strip()=='1','SELinux no longer enforcing')
    boundary_source=private_bytes(HERE/'release_boundaries.py',262144)
    need(sha(boundary_source)==BOUNDARY_CONSUMER_SHA256,'reviewed boundary consumer source differs')
    consumer={'__name__':'reviewed_release_boundaries','__file__':str(HERE/'release_boundaries.py')}
    exec(compile(boundary_source,consumer['__file__'],'exec',optimize=0),consumer)
    early_manifest_raw=android_private(MODULE/'MODULE-MANIFEST-v150-r10-r1.json')
    need(sha(early_manifest_raw)==args.module_manifest_sha256,'module manifest differs before policy check')
    early_manifest=strict_json(early_manifest_raw)
    rows=[r for r in early_manifest['files'] if r['path']=='evidence/RELEASE-BOUNDARIES.json']
    need(len(rows)==1,'one explicit release-boundary bundle required')
    boundary_raw=module_original(rows[0])
    boundary=consumer['validate_bundle'](boundary_raw,rows[0]['sha256'])
    need(boundary['component_input_sha256']==args.component_boundary_inputs_sha256
         and boundary['policy_adoption_sha256']==args.policy_adoption_inputs_sha256,
         'independently expected release-boundary inputs differ')
    need(sha((A/'sys/fs/selinux/policy').read_bytes())==boundary['runtime_policy']['sha256'],
         'live policy differs from Root explicit adopted export')
    for flag in ('disable','remove'):
        need(not (MODULE/flag).exists() and not (MODULE/flag).is_symlink(),'new module inhibited')
    seal_raw=private_bytes(HERE/'SOURCE-SEAL-v150-r10.json')
    need(sha(seal_raw)==args.source_seal_sha256,'source seal differs')
    seal=strict_json(seal_raw)
    pins={Path(row['path']).name:row for row in seal['production_files']}
    need(len(pins)==15,'production source inventory differs')
    production_raw={}
    for row in seal['production_files']:
        raw=private_bytes(HERE/row['path'],262144)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'production source differs')
        production_raw[Path(row['path']).name]=raw
    manifest_raw=android_private(MODULE/'MODULE-MANIFEST-v150-r10-r1.json')
    need(sha(manifest_raw)==args.module_manifest_sha256,'module manifest differs')
    manifest=strict_json(manifest_raw)
    need(manifest_raw==early_manifest_raw,'module manifest changed across policy verification')
    need(len(manifest['files'])==len({r['path'] for r in manifest['files']}),'duplicate module input')
    module_sums={}
    for row in manifest['files']:
        module_original(row)
        module_sums[row['path']]=row['sha256']
    module_sums['MODULE-MANIFEST-v150-r10-r1.json']=args.module_manifest_sha256
    expected_sums=''.join(pin+'  '+name+'\n' for name,pin in sorted(module_sums.items())).encode()
    need(android_private(MODULE/'module-inputs.sha256')==expected_sums,'module input checksum list differs')
    need(android_private(MODULE/'SEALED')==b'HEPTA_PHONE_LOCAL_V150_R10_R1_REVIEWED_INPUTS_BOUND\n',
         'module reviewed seal differs')
    integration=strict_json(android_private(MODULE/'seal-binding.json'))
    need(integration['policy_sha256']==boundary['runtime_policy']['sha256']
         and integration['parent_policy_sha256']==PARENT_POLICY
         and integration['policy_adoption_inputs_sha256']==args.policy_adoption_inputs_sha256
         and integration['component_boundary_inputs_sha256']==args.component_boundary_inputs_sha256
         and integration['component_boundary_sha256']==boundary['component_boundary_sha256']
         and integration['release_boundary_bundle_sha256']==sha(boundary_raw),
         'module seal does not bind the exact explicit runtime policy and component originals')
    config_raw=private_bytes(BASE/'local-config-r10-r1.json')
    need(sha(config_raw)==args.configuration_sha256,'configuration differs')
    config=strict_json(config_raw)
    service_raw=private_bytes(BASE/'PHONE-SERVICE-INPUTS-v150-r10-r1.json')
    need(sha(service_raw)==config['service_manifest_sha256']==seal['phone_service_inputs_sha256'],
         'current service input manifest differs')
    service=strict_json(service_raw)
    need(service['runtime']['server']['sha256']==MODEL_HASH and
         service['schema']=='hepta.phone-local.service-inputs.v150.r10.1','current runtime manifest is not r9')
    material_binding=consumer['validate_shared_materials'](boundary,production_raw,config_raw,service_raw)
    external_bindings=consumer['external_artifact_bindings'](boundary,production_raw,service_raw)
    need(integration['component_external_artifacts']==external_bindings,
         'module did not bind all eight exact component dependencies')
    consumer['validate_external_inventory'](external_bindings,manifest['payload_files'],path_key='path')
    external_before=consumer['current_external_artifacts'](boundary)
    claim=A/'data/adb/trillionnium-hepta-phone-local-v150-r10-r1'/boot
    roles={}
    expect={
        'supervisor':('u:r:magisk:s0',None,None),
        'model':('u:r:magisk:s0','/data/local/tmp/hepta-phone-local-v150-r10-r1/bin/llama-server',MODEL_HASH),
        'sidecar':('u:r:trillionnium_owner_open_phone_executor:s0','/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6','8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976'),
        'provider':('u:r:magisk:s0','/usr/bin/python3','f7ad87c414fc6a5126571b2ecca19351119ac10e54d0539de6a0a9300d81087f')}
    for name,(context,executable,pin) in expect.items():
        raw=android_private(claim/(name+'.identity'));identity=list(map(int,raw.decode().strip().split(':')))
        need(len(identity)==4 and identity[0]==identity[1]==identity[2],'owned role claim differs')
        row=process(identity[0]);need(row['identity']==identity and row['state']!='Z','role no longer original live process')
        need(row['domain']==context and row['uid']==row['gid']==[0]*4 and row['no_new_privs']==0,'role credentials differ')
        if executable:need(row['exe']==executable,'role executable path differs: '+name)
        if pin:need(digest_file(Path('/proc')/str(identity[0])/'exe')==pin,'role binary pin differs')
        roles[name]=row
    need(len({row['identity'][0] for row in roles.values()})==4,'role PID collision')
    need(android_private(claim/'services-started'),'supervisor has not admitted all services')
    ready=strict_json(private_bytes(BASE/'provider-state/ready.json'))
    need(ready['accepting'] is True and ready['pid']==roles['provider']['identity'][0] and
         ready['port']==18080 and ready['source_sha256']==pins['daily_phone_local.py']['sha256'] and
         ready['config_sha256']==args.configuration_sha256 and
         ready['service_manifest_sha256']==config['service_manifest_sha256'],'provider readiness identity differs')
    run=BASE/'model-runtime-r10-r1'/boot
    bound=strict_json(private_bytes(run/'READY-BOUND.json',16*1024*1024))
    need(bound['state']=='READY_BOUND_IMAGE_CANCEL_REQUIRED','startup binding absent')
    binding_path=Path(bound['binding']['path'])
    need(binding_path.parent==run/'bindings','binding path differs')
    need(sha(private_bytes(binding_path))==bound['binding']['sha256'],'binding file changed')
    binding=load_binding(binding_path);model=verify_identity(binding,hash_binary=True)
    need([model[k] for k in ('pid','pgid','sid','start_ticks')]==roles['model']['identity'],'binding model role mismatch')
    slot,receipt=get_json(config,'/slots',time.monotonic()+2.0)
    need(receipt['complete'] is True and receipt['http_status']==200 and receipt['error'] is None and
         isinstance(slot,list) and len(slot)==1 and slot[0].get('is_processing') is False,'model slot not ready/idle')
    admission_identity(binding,config,{'observed':True,'idle':True,'slot':slot[0]})
    capability=slot[0]['hepta_server']['cancel_safe_point']
    for key in ('cpu_decode_abort_callback_installed','image_encode_abort_callback_installed',
                'compute_and_queue_handoff_required_before_release'):
        need(capability.get(key) is True,'cancellation capability absent: '+key)
    listeners=[listen(18087,roles['model']['identity'][0]),listen(18080,roles['provider']['identity'][0])]
    unix=[line.split() for line in Path('/proc/net/unix').read_text().splitlines()[1:]]
    side=[row for row in unix if len(row)>=8 and row[-1]=='@hepta_phone_executor_v150_r6']
    need(len(side)==1 and side[0][6] in sockets(roles['sidecar']['identity'][0]),'sidecar original owned socket absent')
    for role,row in roles.items():
        after=process(row['identity'][0])
        need(after['state']!='Z' and all(after[key]==row[key] for key in
             ('identity','domain','uid','gid','no_new_privs','exe')),
             'role identity changed during snapshot: '+role)
    external_after=consumer['current_external_artifacts'](boundary)
    need(external_after==external_before,'component external dependency metadata changed during readiness')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot,'boot changed during snapshot')
    report=dict(schema='hepta.r10.actual-readiness.v1',state='EXACT_COMBINATION_READY_TRANSPORT_ONLY',
        boot_id=boot,roles=roles,provider_ready=ready,loopback_listeners=listeners,
        sidecar_socket_inode=side[0][6],source_seal_sha256=args.source_seal_sha256,
        configuration_sha256=args.configuration_sha256,module_manifest_sha256=args.module_manifest_sha256,
        service_inputs_sha256=sha(service_raw),
        shared_material_binding=material_binding,component_external_artifacts=external_after,
        policy_sha256=boundary['runtime_policy']['sha256'],parent_policy_sha256=PARENT_POLICY,
        policy_adoption_inputs_sha256=args.policy_adoption_inputs_sha256,
        component_boundary_inputs_sha256=args.component_boundary_inputs_sha256,
        component_boundary_sha256=boundary['component_boundary_sha256'],
        release_boundary_bundle_sha256=sha(boundary_raw),
        actual_binding=bound['binding'],slot_observation=slot[0],slot_get_receipt=receipt,
        model_requests=0,task_submissions=0,ui_actions=0,signals_sent=0,
        health_qualified=False,business19_qualified=False,cold_boot_qualified=False)
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
