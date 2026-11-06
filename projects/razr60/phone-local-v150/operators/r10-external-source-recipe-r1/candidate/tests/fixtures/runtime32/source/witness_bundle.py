#!/usr/bin/env python3
"""Pack actual Root fixture originals; publish bytes once without running UI.

The fixture commands are supplied by the live pinned component provider.
Root executes those commands through the preserved Actor.execute_command path,
whose actual wire and separate UID original are checked here and by the
listener. This program contains no ADB, execute IPC or model request.
"""
import argparse
import base64
import io
import os
from pathlib import Path
import re
import sys
import tarfile
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parent))
import component_common as C
import component_lifecycle as LIFE
import component_listener as LISTENER
from prepare_component import host_read,write_new

SUFFIXES=('','_execution','_wire','_command','_stderr','_uid','_uid_wire','_intent')


def validate_plan(raw):
    v=C.strict(raw)
    C.need(set(v)=={'schema','scope','contract_sha256','phase','operation_id','commands','execution_order',
                   'operator_fixture_not_model_or_worker_qualification','automatic_retry',
                   'caller_must_retain_original_command_execution_and_wire'}
           and v['schema']=='hepta.native-guard.root-phase-plan.v1'
           and v['phase'] in ('setup','before-guard','after-guard')
           and v['operator_fixture_not_model_or_worker_qualification'] is True
           and v['automatic_retry'] is False
           and v['caller_must_retain_original_command_execution_and_wire'] is True,'actual Root phase plan required')
    C.scope(v['scope']);C.need(C.HASH.fullmatch(v['contract_sha256']),'kernel contract pin required')
    order=v['execution_order']
    C.need(isinstance(order,list) and set(order)==set(v['commands']) and len(order)==len(set(order))
           and 1<=len(order)<=3 and set(order)<={'open','disturbance','public','png'},'bounded ordered Root fixture commands')
    if v['phase']=='before-guard':C.need(order==['disturbance','public','png'],'disturbance must precede independent witness reads')
    commands={}
    for name,row in v['commands'].items():
        C.need(set(row)=={'base64','bytes','sha256'},'exact command original descriptor')
        raw=base64.b64decode(row['base64'],validate=True);raw.decode()
        C.need(0<len(raw)<=131072 and b'\0' not in raw and C.descriptor(raw)=={k:row[k] for k in ('bytes','sha256')},
               'original Root command bytes differ')
        commands[name]=raw
    return v,commands


def validate_files(plan,commands,files,nonce,boot):
    required={n+s for n in commands for s in SUFFIXES}
    C.need(set(files)==required,'full original fixture file set differs')
    C.need(plan['operation_id']==C.root_operation_id(plan['scope'],plan['contract_sha256'],plan['phase']),
           'fixture operation id differs')
    for name in plan['execution_order']:
        LISTENER.verify_operator_execution(files,name,files[name],commands[name],phase=plan['phase'],nonce=nonce,boot=boot)
    # Actual phase ordering comes from wire clocks, not mapping/list iteration.
    last=0
    for name in plan['execution_order']:
        wire=C.strict(files[name+'_wire']);uid=C.strict(files[name+'_uid_wire'])
        C.need(wire['p4_monotonic_started_ns']>=last,'actual Root phase execution order differs')
        last=uid['p4_monotonic_finished_ns']


def archive(files):
    import gzip
    C.need(len(files)<=32 and sum(map(len,files.values()))<=16*1024*1024
        and all(len(raw)<=8*1024*1024 for raw in files.values()),'witness original count/byte bound')
    result=io.BytesIO()
    with tarfile.open(fileobj=result,mode='w',format=tarfile.USTAR_FORMAT) as out:
        for name,raw in sorted(files.items()):
            C.relative(name);row=tarfile.TarInfo(name);row.size=len(raw);row.mode=0o600;row.uid=row.gid=0;row.mtime=0
            out.addfile(row,io.BytesIO(raw))
    return gzip.compress(result.getvalue(),compresslevel=9,mtime=0)


def unpack(raw):
    C.need(0<len(raw)<=16*1024*1024,'bounded witness archive required')
    decoder=zlib.decompressobj(31);plain=decoder.decompress(raw,20*1024*1024+1)
    C.need(len(plain)<=20*1024*1024 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
           'witness archive oversized, truncated or concatenated')
    files={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as source:
        for row in source:
            C.relative(row.name)
            C.need(row.name not in files and len(files)<32 and row.isreg() and not row.pax_headers
                   and row.uid==row.gid==0 and row.mode==0o600 and row.mtime==0 and 0<=row.size<=8*1024*1024,
                   'witness archive path/type/metadata/size differs')
            f=source.extractfile(row);C.need(f is not None,'witness file absent')
            data=f.read(row.size+1);C.need(len(data)==row.size,'witness file incomplete');files[row.name]=data
    # Exact canonical re-encoding also rejects hidden trailing tar content.
    encoded=archive(files)
    C.need(zlib.decompress(encoded,31)==plain,'witness tar contains noncanonical or trailing data')
    return files


def pack(a):
    os.umask(0o077)
    raw=host_read(a.plan,65536);C.need(C.sha(raw)==a.plan_sha256,'actual exported plan pin differs')
    plan,commands=validate_plan(raw)
    C.need(re.fullmatch('[0-9a-f]{32}',a.nonce) and re.fullmatch('[0-9a-f-]{36}',a.boot_id),'explicit actual fixture identity')
    index_raw=host_read(a.original_index,262144);C.need(C.sha(index_raw)==a.original_index_sha256,'Root original index pin differs')
    index=C.strict(index_raw)
    C.need(set(index)=={'schema','phase_plan_sha256','files','actor_originals_file','frozen_actor_source_sha256','frozen_transport_source_sha256'}
           and index['schema']=='hepta.native-guard.root-original-index.v1' and index['phase_plan_sha256']==C.sha(raw)
           and index['frozen_actor_source_sha256']=='1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'
           and index['frozen_transport_source_sha256']=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b',
           'actual frozen Root actor/transport attribution differs')
    originals={};origins={}
    for key,path in index['files'].items():
        C.need(re.fullmatch('[a-z_]+',key),'original file key')
        p=Path(path);data=host_read(p,8*1024*1024);originals[key]=data
        origins[key]={'source_path':str(p.absolute()),'source_metadata':C.metadata(p.lstat()),**C.descriptor(data)}
    validate_files(plan,commands,originals,a.nonce,a.boot_id)
    phase=plan['phase'];members={phase+'/'+key+'.original':data for key,data in originals.items()}
    actor_path=Path(index['actor_originals_file']);actor_raw=host_read(actor_path,16*1024*1024)
    LISTENER.verify_root_actor_originals(actor_raw,raw,originals)
    actor_name=phase+'/ACTOR-ORIGINALS.original.json';members[actor_name]=actor_raw
    provenance={'schema':'hepta.native-guard.root-original-provenance.v1','phase_plan_sha256':C.sha(raw),
        'original_index_sha256':C.sha(index_raw),'source_files':origins,
        'frozen_actor_source_sha256':index['frozen_actor_source_sha256'],
        'frozen_transport_source_sha256':index['frozen_transport_source_sha256'],
        'uid2000_fixture_only_not_native_worker_qualification':True,'model_requests':0,
        'actor_originals':{'path':actor_name,**C.descriptor(actor_raw)},
        'actor_originals_source':{'source_path':str(actor_path.absolute()),
            'source_metadata':C.metadata(actor_path.lstat()),**C.descriptor(actor_raw)}}
    prov_raw=C.encoded(provenance);members[phase+'/PROVENANCE.json']=prov_raw
    mailbox={'schema':'hepta.native-guard.root-witness.v1','phase':phase,'scope':plan['scope'],
        'contract_sha256':plan['contract_sha256'],'operation_id':plan['operation_id'],
        'files':{key:{'path':phase+'/'+key+'.original',**C.descriptor(data)} for key,data in originals.items()},
        'provenance':{'path':phase+'/PROVENANCE.json',**C.descriptor(prov_raw)}}
    members['mailbox.json']=C.encoded(mailbox);members['plan.original.json']=raw
    out=Path(a.out).absolute();out.mkdir(mode=0o700)
    for name,data in members.items():
        p=out/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);write_new(p,data)
    body=archive(members);write_new(out/'witness.tar.gz',body)
    result={'schema':'hepta.native-guard.host-witness-bundle.v1','state':'ORIGINAL_BYTES_PACKED_NOT_PUBLISHED',
        'phase':phase,'scope':plan['scope'],'contract_sha256':plan['contract_sha256'],'phase_plan_sha256':C.sha(raw),
        'archive':C.descriptor(body),'mailbox':C.descriptor(members['mailbox.json']),'members':len(members),
        'phone_calls':0,'native_calls':0,'model_requests':0,'component_qualified':False,'business_qualified':False}
    write_new(out/'PACKED.json',C.encoded(result));print(C.encoded(result).decode(),end='')


def publish(a):
    C.need(a.execute_publish_original_bytes_once,'explicit one-use Root original publication required')
    os.umask(0o077)
    home=C.private_dir(Path(a.lease));lease,_=LIFE.load_lease(home,a.lease_sha256);LIFE.native_root(lease['boot_id'])
    C.verify_package(home/'package/MANIFEST.json',lease['package_sha256'])
    path=Path(a.archive).absolute();raw=C.read(path,16*1024*1024)
    C.need(C.sha(raw)==a.archive_sha256,'actual Root witness transport archive pin differs')
    files=unpack(raw);plan,commands=validate_plan(files['plan.original.json']);phase=plan['phase']
    C.need(path==C.BASE/'native-guard-staging-r10-r1'/(lease['label']+'-'+phase+'.witness.tar.gz'),
           'explicit one-phase GNU witness transport path required')
    C.need(C.read(home/('ROOT-'+phase.upper()+'-PLAN.json'),65536)==files['plan.original.json'],
           'live one-use phase plan differs from packed original')
    accepted=C.strict(C.read(home/'ACCEPTED.json',65536));bound=C.strict(C.read(home/'BOUND-CONTRACT.json',65536))
    C.need(accepted['scope']==plan['scope'] and accepted['contract_sha256']==plan['contract_sha256']
           and C.sha(C.encoded(bound['contract']))==plan['contract_sha256'],'actual accepted native scope/contract differs')
    for name in ('PROVIDER-ENDED.json','LIFECYCLE-ENDED.json','LIFECYCLE-FAILURE.json'):
        try:(home/name).lstat()
        except FileNotFoundError:pass
        else:C.need(False,'component ended; no late witness publication')
    mailbox=C.strict(files['mailbox.json'])
    C.need(set(mailbox)=={'schema','phase','scope','contract_sha256','operation_id','files','provenance'}
           and mailbox['schema']=='hepta.native-guard.root-witness.v1'
           and all(mailbox[k]==plan[k] for k in ('phase','scope','contract_sha256','operation_id')),'packed mailbox identity differs')
    expected={'mailbox.json','plan.original.json'};originals={}
    for key,row in mailbox['files'].items():
        C.need(row['path']==phase+'/'+key+'.original','one phase-only witness path required')
        data=files[row['path']];C.need(C.descriptor(data)=={k:row[k] for k in ('bytes','sha256')},'packed original pin differs')
        originals[key]=data;expected.add(row['path'])
    prov=mailbox['provenance'];C.need(prov['path']==phase+'/PROVENANCE.json','phase provenance path')
    C.need(C.descriptor(files[prov['path']])=={k:prov[k] for k in ('bytes','sha256')},'Root provenance pin differs')
    provenance=C.strict(files[prov['path']])
    C.need(set(provenance)=={'schema','phase_plan_sha256','original_index_sha256','source_files',
        'frozen_actor_source_sha256','frozen_transport_source_sha256',
        'uid2000_fixture_only_not_native_worker_qualification','model_requests','actor_originals','actor_originals_source'}
        and provenance['schema']=='hepta.native-guard.root-original-provenance.v1'
        and provenance['phase_plan_sha256']==C.sha(files['plan.original.json'])
        and provenance['frozen_actor_source_sha256']=='1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'
        and provenance['frozen_transport_source_sha256']=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
        and provenance['uid2000_fixture_only_not_native_worker_qualification'] is True
        and provenance['model_requests']==0 and set(provenance['source_files'])==set(originals)
        and all(all(provenance['source_files'][name][k]==C.descriptor(raw)[k] for k in ('bytes','sha256'))
                for name,raw in originals.items()),'original Root actor provenance differs')
    actor=provenance['actor_originals']
    C.need(actor['path']==phase+'/ACTOR-ORIGINALS.original.json'
        and C.descriptor(files[actor['path']])=={k:actor[k] for k in ('bytes','sha256')}
        and all(provenance['actor_originals_source'][k]==actor[k] for k in ('bytes','sha256')),
        'complete Actor original envelope pin differs')
    LISTENER.verify_root_actor_originals(files[actor['path']],files['plan.original.json'],originals)
    expected.add(actor['path'])
    expected.add(prov['path']);C.need(set(files)==expected,'extra/missing witness archive member')
    validate_files(plan,commands,originals,lease['nonce'],lease['boot_id'])
    directory=C.private_dir(home/'operator'/phase,create=True)
    for name,data in sorted(files.items()):
        if name.startswith(phase+'/'):C.put(directory/Path(name).name,data)
    C.put(directory/'PLAN.original.json',files['plan.original.json'])
    C.put(directory/'PUBLICATION.json',{'archive_path':str(path),'archive_sha256':a.archive_sha256,
        'scope':plan['scope'],'phase':phase,'model_requests':0,'native_dispatches':0,'automatic_retry':False})
    # The mailbox is the sole publication barrier and is created last.
    C.put(home/'operator'/(phase+'.json'),files['mailbox.json'])
    print(C.encoded({'state':'ORIGINAL_ROOT_WITNESS_BYTES_PUBLISHED_ONCE','phase':phase,
        'mailbox_sha256':C.sha(files['mailbox.json']),'component_qualified':False,'native_dispatches_by_publisher':0}).decode(),end='')


def fence(a):
    """Read-only current-scope fence for the separately attributed UI actor."""
    C.need(a.execute_read_only_fence,'explicit original scope observation required')
    home=C.private_dir(Path(a.lease));lease,lease_raw=LIFE.load_lease(home,a.lease_sha256)
    LIFE.native_root(lease['boot_id']);C.verify_package(home/'package/MANIFEST.json',lease['package_sha256'])
    C.need(Path(__file__)==home/'package/source/witness_bundle.py','fence must use staged pinned source')
    plan_raw=C.read(home/('ROOT-'+a.phase.upper()+'-PLAN.json'),65536)
    C.need(C.sha(plan_raw)==a.phase_plan_sha256,'actual current Root phase changed')
    plan,_=validate_plan(plan_raw);C.need(plan['phase']==a.phase,'actual current phase differs')
    bound_raw=C.read(home/'BOUND-CONTRACT.json',65536);accepted_raw=C.read(home/'ACCEPTED.json',65536)
    bound=C.strict(bound_raw);accepted=C.strict(accepted_raw)
    C.need(bound['lease_sha256']==a.lease_sha256 and accepted['scope']==plan['scope']
        and accepted['contract_sha256']==plan['contract_sha256']==C.sha(C.encoded(bound['contract'])),
        'actual accepted owner/scope differs before Root fixture')
    prohibited=['PROVIDER-ENDED.json','LIFECYCLE-ENDED.json','LIFECYCLE-FAILURE.json','operator/'+a.phase+'.json']
    if a.phase=='setup':prohibited+=['CAPTURE-RESULT.json','GUARD-RESULT.json']
    elif a.phase=='before-guard':prohibited+=['GUARD-RESULT.json']
    for name in prohibited:
        try:(home/name).lstat()
        except OSError as error:C.need(error.errno==2,'current phase absence unknown')
        else:C.need(False,'phase ended/advanced/already published; no Root UI execution')
    if a.phase!='setup':
        prior=C.strict(C.read(home/('CAPTURE-RESULT.json' if a.phase=='before-guard' else 'GUARD-RESULT.json')))
        C.need(prior['scope']==plan['scope'] and prior['contract_sha256']==plan['contract_sha256'],
            'required earlier actual native phase differs')
    ready_raw=C.read(home/'READY.json',65536);ready=C.strict(ready_raw)
    supervisor_raw=C.read(home/'SUPERVISOR.json',16384);supervisor=C.strict(supervisor_raw)
    roles={'provider':ready['identity'],'sidecar':bound['sidecar_identity'],'supervisor':supervisor}
    for role,original in roles.items():
        C.need(C.target_identity(original['identity'][0],original['identity'])==original,
               'component role generation changed before fixture: '+role)
    C.need(C.read(home/'READY.json',65536)==ready_raw and C.read(home/'BOUND-CONTRACT.json',65536)==bound_raw
        and C.read(home/'ACCEPTED.json',65536)==accepted_raw and C.read(home/'SUPERVISOR.json',16384)==supervisor_raw,
        'original current scope changed during Root fixture fence')
    result={'schema':'hepta.native-guard.root-fixture-live-fence.v1','state':'ACTUAL_ACCEPTED_PHASE_STILL_LIVE',
        'phase':a.phase,'phase_plan_sha256':a.phase_plan_sha256,'scope':plan['scope'],
        'contract_sha256':plan['contract_sha256'],'lease_sha256':C.sha(lease_raw),'package_sha256':lease['package_sha256'],
        'boot_id':lease['boot_id'],'roles':roles,'phone_unix_ms':__import__('time').time_ns()//1000000,
        'phone_writes':0,'ui_actions':0,'socket_connections':0,'signals_sent':0,'model_requests':0}
    print(C.encoded(result).decode(),end='');return 0


def validate_epoch_files(plan,commands,files,nonce,boot):
    required={n+s for n in commands for s in SUFFIXES}
    C.need(set(files)==required,'full original fixture file set differs')
    C.need(plan['operation_id']==C.root_operation_id(plan['scope'],plan['contract_sha256'],plan['phase']),
           'fixture operation id differs')
    for name in plan['execution_order']:
        LISTENER.verify_epoch_operator_execution(files,name,files[name],commands[name],phase=plan['phase'],nonce=nonce,boot=boot)
    # Actual phase ordering comes from wire clocks, not mapping/list iteration.
    last=0
    for name in plan['execution_order']:
        wire=C.strict(files[name+'_wire']);uid=C.strict(files[name+'_uid_wire'])
        C.need(wire['p4_monotonic_started_ns']>=last,'actual Root phase execution order differs')
        last=uid['p4_monotonic_finished_ns']

def epoch_witness_lease(lease_raw):
    C.need(type(lease_raw) is bytes and 0 < len(lease_raw) <= 131072,
           'complete bound epoch lease original required')
    lease = C.strict(lease_raw)
    C.need(type(lease) is dict and lease.get('schema') == 'hepta.native-guard.epoch-lease.v1',
           'explicit epoch lease required, no v1 compatibility widening')
    gate = getattr(C, 'epoch_lease_protocol_value', None)
    C.need(callable(gate), 'epoch lease protocol implementation unavailable')
    gate(lease)
    return lease


def epoch_witness_origin(value, raw, path):
    C.need(type(value) is dict and set(value) == {'source_path', 'source_metadata', 'bytes', 'sha256'}
           and value['source_path'] == path, 'actual epoch witness origin path/fields differ')
    return LISTENER.epoch_fixture_original_row(value, raw, Path(path).name, Path(path).parent)


def build_epoch_witness_members(plan_raw, index_raw, originals, actor_raw, writer_raw,
                                result_raw, source_origins, envelope_origins, lease_raw):
    """Pure v2 construction. It neither authorizes a copy nor publishes bytes."""
    C.need(type(plan_raw) is bytes and 0 < len(plan_raw) <= 32768,
           'source-fixed serialized epoch plan bound required before construction')
    lease = epoch_witness_lease(lease_raw)
    plan, commands = validate_plan(plan_raw)
    C.need(type(originals) is dict and type(source_origins) is dict
           and set(source_origins) == set(originals), 'complete actual phase source origins required')
    validate_epoch_files(plan, commands, originals, lease['nonce'], lease['boot_id'])
    verified = LISTENER.verify_epoch_root_actor_originals(actor_raw, plan_raw, originals,
        writer_raw=writer_raw, index_raw=index_raw, result_raw=result_raw)
    actor, index = C.strict(actor_raw), C.strict(index_raw)
    C.need(C.strict(result_raw)['phone_stage_retained'] == '/data/local/tmp/hepta-native-guard-'+lease['nonce'],
           'actual fixture result namespace differs from epoch lease')
    binding = actor['writer_binding']
    C.need(binding['lease_sha256'] == C.sha(lease_raw)
           and binding['package_sha256'] == lease['package_sha256'],
           'actual epoch writer belongs to another lease or package')
    copy_gate = getattr(C, 'epoch_fixture_copy_admission', None)
    C.need(callable(copy_gate), 'approved same-phase copy reservation verifier unavailable')
    admission_raw = base64.b64decode(actor['files']['WRITER-ADMISSION.original.json']['raw_b64'], validate=True)
    copy_admission = copy_gate(lease, plan, LISTENER.epoch_fixture_consumer_profile(plan['phase']),
                               C.strict(admission_raw))
    C.need(type(copy_admission) is dict and 0 < len(C.encoded(copy_admission)) <= 65536,
           'complete canonical same-claim copy admission required')
    parent = Path(index['actor_originals_file']).parent
    identities = set()
    for key, data in originals.items():
        inode = epoch_witness_origin(source_origins[key], data, index['files'][key])
        C.need(inode not in identities, 'planned epoch witness source aliases another file')
        identities.add(inode)
    extras = {'actor_originals': ('ACTOR-ORIGINALS.original.json', actor_raw, index['actor_originals_file']),
        'writer_proof': ('OUTPUT-WRITER.original.json', writer_raw, index['writer_proof_file']),
        'original_index': ('ORIGINAL-INDEX.original.json', index_raw, str(parent/'ORIGINAL-INDEX.json')),
        'actor_result': ('RESULT.original.json', result_raw, index['result_file'])}
    C.need(type(envelope_origins) is dict and set(envelope_origins) == set(extras),
           'all four actual epoch envelope origins required')
    phase = plan['phase']
    members = {phase+'/'+key+'.original': data for key, data in originals.items()}
    provenance = {'schema': 'hepta.epoch.root-original-provenance.v1',
        'phase_plan_sha256': C.sha(plan_raw), 'original_index_sha256': C.sha(index_raw),
        'source_files': source_origins, 'epoch_adapter_source': actor['epoch_adapter_source'],
        'writer_binding': binding, 'writer_verification': verified,
        'copy_admission': copy_admission,
        'uid2000_fixture_only_not_native_worker_qualification': True,
        'model_requests': 0, 'case_capacity_authorized_by_this_constructor': False}
    for key, (name, body, source_path) in extras.items():
        inode = epoch_witness_origin(envelope_origins[key], body, source_path)
        C.need(inode not in identities, 'epoch envelope aliases another retained original')
        identities.add(inode)
        if key != 'writer_proof':
            source_row = C.strict(writer_raw)['prefix_files'][Path(source_path).name]
            C.need(C.encoded(envelope_origins[key]['source_metadata']) == C.encoded(source_row['metadata']),
                   'epoch envelope/writer original full9 differs')
        members[phase+'/'+name] = body
        provenance[key] = {'path': phase+'/'+name, **C.descriptor(body)}
        provenance[key+'_source'] = envelope_origins[key]
    provenance_raw = C.encoded(provenance)
    C.need(len(provenance_raw) <= 65536, 'bounded serialized epoch provenance required')
    members[phase+'/PROVENANCE.json'] = provenance_raw
    mailbox = {'schema': 'hepta.epoch.root-witness.v1', 'phase': phase, 'scope': plan['scope'],
        'contract_sha256': plan['contract_sha256'], 'operation_id': plan['operation_id'],
        'files': {key: {'path': phase+'/'+key+'.original', **C.descriptor(data)}
                  for key, data in originals.items()},
        'provenance': {'path': phase+'/PROVENANCE.json', **C.descriptor(provenance_raw)}}
    members['mailbox.json'] = C.encoded(mailbox)
    members['plan.original.json'] = plan_raw
    C.need(len(members) <= 32 and sum(len(b) for b in members.values()) <= 16*1024*1024
           and all(type(b) is bytes and len(b) <= 8*1024*1024 for b in members.values())
           and len(members['mailbox.json']) <= 16384,
           'complete epoch witness member count/byte pool exceeded')
    return members


def validate_epoch_witness_members(members, lease_raw):
    """Pure exact reconstruction; no old mailbox/provenance fallback."""
    C.need(type(members) is dict and 1 <= len(members) <= 32
           and all(type(k) is str and type(v) is bytes and len(v) <= 8*1024*1024
                   for k, v in members.items())
           and sum(len(b) for b in members.values()) <= 16*1024*1024,
           'bounded full epoch witness members required')
    lease = epoch_witness_lease(lease_raw)
    plan_raw = members['plan.original.json']
    plan, commands = validate_plan(plan_raw)
    mailbox = C.strict(members['mailbox.json'])
    phase = plan['phase']
    C.need(type(mailbox) is dict and set(mailbox) == {'schema', 'phase', 'scope', 'contract_sha256',
           'operation_id', 'files', 'provenance'}
           and mailbox['schema'] == 'hepta.epoch.root-witness.v1'
           and all(C.encoded(mailbox[k]) == C.encoded(plan[k])
                   for k in ('phase', 'scope', 'contract_sha256', 'operation_id')),
           'explicit epoch mailbox identity differs')
    originals = {}
    for key, row in mailbox['files'].items():
        C.need(type(key) is str and re.fullmatch('[a-z_]+', key)
               and type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
               and row['path'] == phase+'/'+key+'.original', 'epoch planned member descriptor differs')
        body = members[row['path']]
        C.need(C.encoded({k: row[k] for k in ('bytes', 'sha256')}) == C.encoded(C.descriptor(body)),
               'epoch planned member byte pin differs')
        originals[key] = body
    prov_desc = mailbox['provenance']
    C.need(type(prov_desc) is dict and set(prov_desc) == {'path', 'bytes', 'sha256'}
           and prov_desc['path'] == phase+'/PROVENANCE.json', 'epoch provenance path differs')
    prov_raw = members[prov_desc['path']]
    C.need(C.encoded({k: prov_desc[k] for k in ('bytes', 'sha256')}) == C.encoded(C.descriptor(prov_raw)),
           'epoch full provenance byte pin differs')
    provenance = C.strict(prov_raw)
    extras = {'actor_originals': 'ACTOR-ORIGINALS.original.json',
              'writer_proof': 'OUTPUT-WRITER.original.json',
              'original_index': 'ORIGINAL-INDEX.original.json', 'actor_result': 'RESULT.original.json'}
    bodies = {}
    for key, name in extras.items():
        row = provenance[key]
        C.need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
               and row['path'] == phase+'/'+name, 'epoch envelope member path differs')
        bodies[key] = members[row['path']]
        C.need(C.encoded({k: row[k] for k in ('bytes', 'sha256')}) == C.encoded(C.descriptor(bodies[key])),
               'epoch envelope original byte pin differs')
    reconstructed = build_epoch_witness_members(plan_raw, bodies['original_index'], originals,
        bodies['actor_originals'], bodies['writer_proof'], bodies['actor_result'],
        provenance['source_files'], {key: provenance[key+'_source'] for key in extras}, lease_raw)
    C.need(set(reconstructed) == set(members)
           and all(reconstructed[k] == members[k] for k in members),
           'complete epoch witness cannot be exactly reconstructed')
    validate_epoch_files(plan, commands, originals, lease['nonce'], lease['boot_id'])
    return plan, commands, originals, provenance['writer_verification']


def epoch_witness_body_cost(members, lease_raw):
    """Exact per-path body charges, never an inode/sha dedup or capacity grant."""
    plan, _commands, originals, verification = validate_epoch_witness_members(members, lease_raw)
    phase = plan['phase']
    groups = {'planned_originals': {phase+'/'+key+'.original' for key in originals},
        'actor_envelope': {phase+'/ACTOR-ORIGINALS.original.json'},
        'writer_proof': {phase+'/OUTPUT-WRITER.original.json'},
        'original_index': {phase+'/ORIGINAL-INDEX.original.json'},
        'actor_result': {phase+'/RESULT.original.json'},
        'provenance': {phase+'/PROVENANCE.json'}, 'mailbox': {'mailbox.json'},
        'plan': {'plan.original.json'}}
    C.need(sum(len(v) for v in groups.values()) == len(members)
           and set().union(*groups.values()) == set(members), 'exact witness body charge partition differs')
    rows = {key: {'members': len(names), 'bytes': sum(len(members[name]) for name in names),
                  'files': {name: C.descriptor(members[name]) for name in sorted(names)}}
            for key, names in groups.items()}
    total = sum(len(body) for body in members.values())
    return {'schema': 'hepta.epoch.fixture-witness-body-cost.v1', 'phase': phase,
        'groups': rows, 'member_count': len(members), 'member_body_bytes': total,
        'p4_actor_all_original_body_bytes': verification['all_actual_output_bytes'],
        'phone_operator_member_body_bytes_before_publication_record': total,
        'phone_listener_saved_member_count': len(members)-1,
        'phone_listener_saved_body_bytes': total-len(members['plan.original.json']),
        'same_content_or_inode_not_deduplicated': True,
        'archive_transport_receiver_receipts_and_material_copies_included': False,
        'new_copy_authorization_or_balance_issued': False}


def main():
    p=argparse.ArgumentParser();subs=p.add_subparsers(dest='operation',required=True)
    x=subs.add_parser('pack')
    for name in ('plan','plan-sha256','original-index','original-index-sha256','nonce','boot-id','out'):x.add_argument('--'+name,required=True)
    x=subs.add_parser('publish')
    for name in ('lease','lease-sha256','archive','archive-sha256'):x.add_argument('--'+name,required=True)
    x.add_argument('--execute-publish-original-bytes-once',action='store_true')
    x=subs.add_parser('fence')
    for name in ('lease','lease-sha256','phase-plan-sha256'):x.add_argument('--'+name,required=True)
    x.add_argument('--phase',required=True,choices=('setup','before-guard','after-guard'))
    x.add_argument('--execute-read-only-fence',action='store_true')
    a=p.parse_args();return {'pack':pack,'publish':publish,'fence':fence}[a.operation](a)


if __name__=='__main__':main()
