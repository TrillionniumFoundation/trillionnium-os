#!/usr/bin/env python3
"""Pure original-byte verification of the single exact-owned final03 cleanup.

Every external byte arrives through read_pinned. This module never opens a
phone/host path, starts a process, sends a signal or removes a file. A successful
phone result is verified against the actual original command, preserved targets,
every removal transition, inventory, process/endpoint observations and two audit
originals. The prior final02 sender wait remains unknown.
"""
import ast,base64,errno,hashlib,io,json,re,shlex,stat,tarfile,types,zlib
from pathlib import Path,PurePosixPath
DRIVER={'bytes':34572,'sha256':'c3a738614731abe034b83b929a031e59aff0b18f979cd0354e49e3b62dd45e87'}
CAPTURE={'bytes':41406,'sha256':'8c297f1e53be4f55e2bb2f41dc59d76e39d1b65e8d0baf890c9ff13b9b9a862e'}
CORE={'bytes':30672,'sha256':'4ec2c347c94e7998095825c16fd12cd0b3663e84aaf0b5c44e109577de8531c0'}
PRESERVATION={'bytes':514658,'sha256':'cd171a907fa50dbf186833ffc7af5f50d6236f57441571523c1a06fd6f4ddc4e'}
PRIOR_HOST={'bytes':2683,'sha256':'8aef0e5b30eee87907584a3998d64d5bc6549f3997878db03da21a64740fbb01'}
RETAINED_CLOSURE={'bytes':65567,'sha256':'38a93ca265e0bb1b35ae80ab8309f389991e8c9a300700508e09841df3313e76'}
ACTOR={'bytes':5652,'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'}
ACTOR_LABEL='ng-a1055-final03-owned-cleanup01'
ACTOR_PATH='/home/alex/razr60-local-model-v150/ops/phone_once.py'
ACTOR_REQUEST_PATH='/home/alex/razr60-local-model-v150/requests/'+ACTOR_LABEL+'.json'
OPERATION_PREFIX='/home/alex/razr60-local-model-v150/operations/'+ACTOR_LABEL
KEY='a1055-final03-owned-cleanup01'
MAX_FILE=16*1024*1024
MAX_TOTAL=32*1024*1024
STATE_LABEL=b'u:object_r:trillionnium_owner_open_state_file:s0\0'
MEMBERS={'SOURCE.original.py','BOUND-REQUEST.original.json','CAPTURE-SOURCE.original.py',
 'CAPTURE-REQUEST.original.json','CLEANUP-INTENT.original.json','CLEANUP-RESULT.original.json',
 'PRE-INVENTORY.json','PRE-OBSERVATIONS.json','AFTER-INVENTORY.json','POST-OBSERVATIONS.json',
 'PRESERVED-ORIGINAL-MAP.json','AUDIT-ORIGINALS.json'}
def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):
    need(type(raw)is bytes,'original bytes required')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def pin2(row):return {k:row[k]for k in ('bytes','sha256')}
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    need(type(raw)is bytes and len(raw)<=MAX_TOTAL,'bounded original JSON')
    def pairs(items):
        d={}
        for k,v in items:need(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite'))
def unbox(raw):
    value=strict(raw)
    if type(value)is dict and 'content'in value:
        need(len(value['content'])==1 and value['content'][0]['type']=='text','one original MCP text')
        value=strict(value['content'][0]['text'].encode())
    return value
def load(raw,name):
    m=types.ModuleType(name);m.__file__='<reviewed-pure-'+name+'>'
    exec(compile(raw,m.__file__,'exec'),m.__dict__);return m
def full9(value):
    need(type(value)is list and len(value)==9 and all(type(n)is int for n in value),'full9 exact integers')
    return value
def decoded(s,maximum):
    need(type(s)is str,'base64 original string')
    b=base64.b64decode(s,validate=True);need(len(b)<=maximum,'raw byte bound');return b
def exact3(row):
    need(type(row)is dict and set(row)=={'path','bytes','sha256'}and type(row['path'])is str
      and type(row['bytes'])is int and 0<=row['bytes']<=MAX_TOTAL
      and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact pinned original descriptor')
    p=PurePosixPath(row['path']);need(p.is_absolute()and str(p)==row['path']and'..'not in p.parts,'canonical original path')
    return row
def bounded_archive(packet):
    compressed=decoded(packet['archive_base64'],MAX_FILE)
    need(pin(compressed)==packet['archive'],'original compressed archive pin')
    decoder=zlib.decompressobj(31);plain=decoder.decompress(compressed,MAX_TOTAL+1)
    need(len(plain)<=MAX_TOTAL and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
      and pin(plain)==packet['archive_plain'],'single complete bounded gzip')
    files={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:')as tar:
        for member in tar:
            need(member.name in MEMBERS and member.name not in files and member.isreg()
              and not member.pax_headers and member.uid==member.gid==0 and member.mode==0o600
              and member.mtime==0 and 0<=member.size<=MAX_FILE,'exact regular canonical archive member')
            stream=tar.extractfile(member);need(stream is not None,'original member exists')
            raw=stream.read(member.size+1);need(len(raw)==member.size,'complete original member')
            files[member.name]=raw
    need(set(files)==MEMBERS and packet['archive_member_count']==12 and sum(map(len,files.values()))<=MAX_TOTAL,
         'complete exact twelve-member packet')
    sink=io.BytesIO()
    with tarfile.open(fileobj=sink,mode='w',format=tarfile.USTAR_FORMAT)as tar:
        for name,raw in sorted(files.items()):
            info=tarfile.TarInfo(name);info.mode=0o600;info.uid=info.gid=0;info.mtime=0;info.size=len(raw)
            tar.addfile(info,io.BytesIO(raw))
    need(sink.getvalue()==plain,'exact canonical tar bytes')
    return compressed,files
def wire(source,bound,capture):
    payload=enc({'binding':bound.decode(),'source':source.decode(),'capture_source':capture.decode()})
    compressed=zlib.compress(payload,9)
    inline="import base64,json,types,zlib;v=json.loads(zlib.decompress(base64.b85decode("+repr(base64.b85encode(compressed).decode())+")));s=v['source'].encode();r=v['binding'].encode();c=v['capture_source'].encode();m=types.ModuleType('owned_stage_cleanup');exec(compile(s,'<owned_stage_cleanup>','exec'),m.__dict__);raise SystemExit(m.main(r,s,c))"
    env='/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '
    command=env+shlex.quote(inline)
    full='/debug_ramdisk/su -c '+shlex.quote(command)
    need(len(('shell,v2,raw:'+full+'\0').encode())<=65535,'complete ADB service wire including NUL limit')
    return enc({'kind':'shell','root':True,'command':command,'timeout_seconds':70}),full
def terminal_originals(values,operation_raw,phone_request_raw):
    start=unbox(values['root_start']);status=unbox(values['root_status']);read=unbox(values['root_read'])
    dispatch=strict(values['dispatch']);request=dispatch['tool_request'];job=start['job']
    need(request=={'host':'pocket4','executable':'/usr/bin/python3',
      'args':['-I','-B',ACTOR_PATH,ACTOR_LABEL,ACTOR_REQUEST_PATH],'idempotency_key':KEY},
      'exact original Root actor request and one-use key')
    need(job['host']==request['host']and job['executable']==request['executable']and job['args']==request['args']
      and job['idempotency_key']==KEY and job['launch_state']=='launched'and job['launch_error']is None,
      'actual original actor launch')
    need(start['reused']is False,'original actor was a fresh one-use launch')
    job_id=job['id'];need(re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+',job_id),'actual opaque original job id')
    need(status['job_id']==read['job_id']==job_id and status['state']=='succeeded'and status['exit_code']==0
      and status['output_complete']is True and status['output_durable']is True
      and status['terminal_publication_confirmed']is True and status['timed_out']is False and status['cancelled']is False,
      'successful actual original parent terminal; unknown cannot qualify')
    need(status['automatic_retry']is False,'original parent automatic retry forbidden')
    for key in ('stdout','stderr'):
        expected=values['root_'+key];row=read[key]
        need(row['offset']==0 and row['eof']is True and row['size']==row['next_offset']==len(expected)
          and bytes.fromhex(row['bytes_hex'])==expected and row['text'].encode()==expected,
          'complete original stdout/stderr and dual EOF')
        need(status['log_bytes'][key]=={'seen':len(expected),'stored':len(expected)}
          and status['log_errors'][key]is None and status['log_truncated'][key]is False
          and status['log_synced'][key]is True,'durable untruncated original streams')
    need(values['root_stderr']==b'','original actor stderr empty')
    summary=strict(values['root_stdout'])
    need(summary['run']==OPERATION_PREFIX and summary['status']=='command_exited'
      and summary['phone_rc']==0 and summary['error']is None
      and summary['sha256']==pin(operation_raw)['sha256'],'actual returned operation pin')
    publish=unbox(values['request_publish'])
    need(publish['written']==publish['size']==len(phone_request_raw)
      and publish['sha256']==pin(phone_request_raw)['sha256']and publish['mode']==0o600,'actual phone request publication')
    return job_id
def original_absence(rows,paths):
    need(type(rows)is list and [row['path']for row in rows]==paths,'exact original absence path list')
    for row in rows:
        need(set(row)=={'path','errno','parent_metadata','parent_selinux_raw_b64','observed_monotonic_ns'}
          and row['errno']==errno.ENOENT and type(row['observed_monotonic_ns'])is int and row['observed_monotonic_ns']>0,
          'actual ENOENT observation required')
        need(stat.S_ISDIR(full9(row['parent_metadata'])[2]),'absence actual parent directory')
        decoded(row['parent_selinux_raw_b64'],512)
def observations(core,obs,roles,observer,*,pre=False):
    need(len(roles)==len(set(map(tuple,roles)))==37,'all exact37 generations')
    need(observer['domain']=='u:r:magisk:s0'and observer['uid']==observer['gid']==[0]*4
      and observer['nnp']==0 and observer['exe']=='/usr/bin/python3','actual ordinary Root observer')
    for key in ('identity',):
        need(type(observer[key])is list and all(type(n)is int for n in observer[key]),'original observer generation')
    argv=decoded(observer['argv_b64'],65536)
    need(hashlib.sha256(argv).hexdigest()==observer['argv_sha256'],'observer original argv hash')
    need(len(obs['all37_role_absence'])==len(obs['scope_process_census'])==2,'two complete37/scope observations')
    for old,current in zip(obs['all37_role_absence'],obs['scope_process_census']):
        need(old['kernel_group_absence']is True and old['members']==[]and 1<=old['numeric_pids']<=4096,
             'all original kernel groups absent')
        need(current['matches']==current['errors']==[]and current['original_parent_wait_inferred']is False
          and current['collector_pid_excluded']==observer['identity'][0]and 1<=current['enumerated_pids']<=4096
          and len(current['disappeared_pids'])==len(set(current['disappeared_pids']))
          and current['inspected_pids']+len(current['disappeared_pids'])+1==current['enumerated_pids']
          and 0<=current['finished_monotonic_ns']-current['started_monotonic_ns']<2000000000,'complete bounded process census')
    need(len(obs['endpoint_observations'])==2,'two endpoint observations')
    for tables,row in zip((obs['endpoint_tables_before'],obs['endpoint_tables_after']),obs['endpoint_observations']):
        core._endpoint_originals(tables)
        need(set(row)=={'port_18080_listener_absent','r6_abstract_endpoint_absent','socket_connections','observed_monotonic_ns'}
          and row['port_18080_listener_absent']is True and row['r6_abstract_endpoint_absent']is True
          and row['socket_connections']==0 and type(row['observed_monotonic_ns'])is int,'actual endpoint parse')
def verify_removals(core,driver,targets,events):
    need(type(events)is list and len(events)==75,'all75 actual exact removal events')
    own_rows={row['path']:row for row in targets['files']}
    states={row['path']:dict(row)for row in targets['directories'].values()}
    shared=targets['aliases'][2]['gnu'];states[shared['path']]=dict(shared)
    for row in targets['transport_parents']:states[row['path']]=dict(row)
    staging=states[str(driver.STAGING)]
    staging['names']=sorted(staging['names']+[driver.INTENT.name])
    own_files=sorted(path for path in own_rows if driver.under(path,driver.HOME))
    dirs=sorted(targets['directories'],key=lambda n:(len(Path(n).parts),n),reverse=True)
    directory_paths=[str(driver.HOME if name=='.'else driver.HOME/name)for name in dirs]
    transfer_paths=[row['path']for row in targets['files']if row['path']not in own_files]
    ordered_transfers=[str(driver.STAGING/(driver.LABEL+'.tar.gz')),str(driver.STAGING/(driver.LABEL+'.stage.py')),
      '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-'+driver.LABEL+'.tar.gz',
      '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-'+driver.LABEL+'.stage.py']
    need(set(transfer_paths)==set(ordered_transfers),'exact four transport originals')
    expected_order=own_files+directory_paths+ordered_transfers
    need([r['path']for r in events]==expected_order and len(set(expected_order))==75,'exact removal order and scope, no alias double delete')
    last=0
    for event in events:
        path=event['path'];parent=states[str(Path(path).parent)]
        core._directory(event['parent_after'])
        before=full9(event['before_metadata']);after=full9(event['after_unlinked_inode_metadata'])
        need(after[:5]==before[:5]and after[5]==0 and event['named_errno']==errno.ENOENT,
             'actual held exact inode removed and original named ENOENT')
        need(type(event['completed_monotonic_ns'])is int and event['completed_monotonic_ns']>last,'ordered removal observations')
        last=event['completed_monotonic_ns']
        if path in own_rows:
            row=own_rows[path]
            need(set(event)=={'kind','path','before_metadata','after_unlinked_inode_metadata','bytes','sha256',
              'selinux_raw_b64','named_errno','parent_after','completed_monotonic_ns'}
              and event['kind']=='file'and before==row['metadata']and after[6]==row['bytes']
              and pin2(event)==pin2(row)and event['selinux_raw_b64']==row['selinux_raw_b64'],
              'exact original complete file metadata/bytes/label before unlink')
            delta=0
        else:
            row=states[path]
            need(set(event)=={'kind','path','before_metadata','after_unlinked_inode_metadata','selinux_raw_b64',
              'named_errno','parent_after','completed_monotonic_ns'}and event['kind']=='directory'
              and row['names']==[]and before==row['metadata']and event['selinux_raw_b64']==row['selinux_raw_b64'],
              'only exact emptied own directory')
            delta=-1;del states[path]
        old=parent['metadata'];new=event['parent_after']
        need(Path(path).name in parent['names']and new['path']==parent['path']
          and new['names']==sorted(n for n in parent['names']if n!=Path(path).name)
          and new['metadata'][:5]==old[:5]and new['metadata'][5]==old[5]+delta
          and new['selinux_raw_b64']==parent['selinux_raw_b64'],'exact permitted parent transition')
        states[parent['path']]=dict(new)
    need(len(states)==3 and sum(row['kind']=='file'for row in events)==66,'only three surviving tracked parents')
    return states
def verify_cleanup_execution(inputs_raw,*,read_pinned):
    inputs=strict(inputs_raw)
    required={'schema','cleanup_source','bound_request','phone_request','dispatch','preservation_core_source',
      'preservation_inputs','preservation_manifest','preservation_host_verification','retained_stage_closure',
      'actor_source','actor_intent','actor_baseline','actor_result','root_start','root_status','root_read',
      'root_stdout','root_stderr','request_publish','packet_archive','packet_originals','root_authority'}
    need(type(inputs)is dict and set(inputs)==required
      and inputs['schema']=='hepta.owned-unstarted-stage.cleanup-execution-inputs.v1','exact cleanup execution input contract')
    book={}
    def read(row):
        exact3(row);raw=read_pinned(row);need(pin(raw)==pin2(row),'exact original callback bytes')
        if row['path']in book:need(book[row['path']]==row,'same original descriptor on reread')
        book[row['path']]=row;return raw
    values={key:read(inputs[key])for key in required-{'schema','packet_originals'}}
    need(pin(values['cleanup_source'])==DRIVER and pin(values['preservation_core_source'])==CORE
      and pin(values['preservation_manifest'])==PRESERVATION and pin(values['preservation_host_verification'])==PRIOR_HOST
      and pin(values['retained_stage_closure'])==RETAINED_CLOSURE and pin(values['actor_source'])==ACTOR,
      'all reviewed original source and prior closure pins')
    core=load(values['preservation_core_source'],'prior_preservation')
    priorproof=core.verify_capture_preservation(values['preservation_inputs'],read_pinned=read)
    preserved=strict(values['preservation_manifest'])
    need(preserved['core_source']==inputs['preservation_core_source']
      and preserved['scope']==priorproof['scope']and preserved['owned_file_originals']==priorproof['owned_file_originals'],
      'exact independently reviewed preservation receipt rejoined to actual original bytes')
    # The immutable cd17 receipt records the previously independently reviewed
    # 692c eight-child closure. Re-read its complete original pool; never upgrade
    # the unrelated old final02 UNKNOWN wait.
    for field in ('host_source_input_full9','host_failure_input_full9'):
        rows=preserved[field]
        rows=list(rows.values())if type(rows)is dict else rows
        need(type(rows)is list and rows,'complete preserved host original book')
        for row in rows:read({k:row[k]for k in ('path','bytes','sha256')})
    need(pin(values['root_authority'])=={'bytes':14038,'sha256':'abece2fc864f7bafaeae96b092cc7e9901ec5b12b57fc46c3f00d60bd659171b'},
         'actual independently preserved Root execution authority')
    authority=strict(values['root_authority'])
    need(authority['schema']=='hepta.root.owned-stage-cleanup-original-execution-authority.v1'
      and authority['job_id']=='1a1afd118bc-fc05-6bdf','exact original cleanup process family')
    authority_files={}
    for row in authority['files']:
        name=Path(row['path']).name;need(name not in authority_files,'unique Root authority original')
        authority_files[name]=read(row)
    for key,name in {'phone_request':'PHONE-REQUEST.original.json','root_start':'ROOT-PROCESS-START.original.json',
        'root_status':'ROOT-PROCESS-STATUS.original.json','root_read':'ROOT-PROCESS-READ.original.json',
        'root_stdout':'ROOT-STDOUT.original','root_stderr':'ROOT-STDERR.original',
        'request_publish':'ROOT-PUBLISH.original.json'}.items():
        need(values[key]==authority_files[name],'actual Root authority original '+name)
    need(strict(authority_files['ROOT-DISPATCH.original.json'])==strict(values['dispatch'])['tool_request'],
         'actual dispatched request equals frozen complete plan')
    publication=strict(authority_files['ROOT-PUBLISH-REQUEST.original.json'])
    need(set(publication)=={'host','path','expected_version','data_base64'}and publication['host']=='pocket4'
      and publication['path']==ACTOR_REQUEST_PATH and publication['expected_version']=='absent'
      and decoded(publication['data_base64'],1048576)==values['phone_request'],
      'actual create-only publication original bytes and absent condition')
    actor_raw=values['actor_result'];operation=strict(actor_raw)
    need(pin(actor_raw)['sha256']=='991d4ae5f4555c365d66b0e3468b21432517aa339db190b02869230c35b888b2',
         'exact actual cleanup operation original')
    need(operation['schema']=='hepta.phone-local.operator-result.v150.1'and operation['label']==ACTOR_LABEL
      and operation['status']=='command_exited'and operation['phone']['rc']==0
      and operation['phone']['stderr']==''and operation['model_decision']is False
      and operation['native_task_result']is False,'successful original actor result, no unknown cleanup')
    job_id=terminal_originals(values,actor_raw,values['phone_request'])
    packet_raw=operation['phone']['stdout'].encode()
    need(len(packet_raw)<=8*1024*1024-65536,'original stdout limit')
    packet=strict(packet_raw)
    need(packet['schema']=='hepta.owned-unstarted-stage.cleanup-result-packet.v1'
      and packet['state']=='EXACT_OWNED_STAGE_REMOVED_AWAITING_INDEPENDENT_HOST_CLOSURE'
      and packet['original_final02_sender_wait']=='UNKNOWN_UNCHANGED'and packet['automatic_retry']is False,
      'actual cleanup packet, never a native task qualification')
    compressed,members=bounded_archive(packet)
    need(read(inputs['packet_archive'])==compressed,'complete retained archive original')
    original_members={}
    for row in inputs['packet_originals']:
        name=Path(row['path']).name;need(name in members and name not in original_members,'exact unique retained packet originals')
        need(read(row)==members[name],'retained packet original byte equality');original_members[name]=row
    need(set(original_members)==MEMBERS,'all12 host original copies')
    source=members['SOURCE.original.py'];bound=members['BOUND-REQUEST.original.json'];capture=members['CAPTURE-SOURCE.original.py']
    need(source==values['cleanup_source']and bound==values['bound_request']and pin(capture)==CAPTURE,
         'actual packet executed source/binding original bytes')
    driver=load(source,'cleanup_driver');b,q,qraw,targets,omap,mraw=driver.validate_request(bound,source,capture)
    need(members['CAPTURE-REQUEST.original.json']==qraw and members['PRESERVED-ORIGINAL-MAP.json']==mraw
      and b['scope']==priorproof['scope']==packet['scope'],'same original scope and preserved request/map')
    need(targets['files']==priorproof['owned_file_originals']and targets['directories']==priorproof['owned_directory_originals'],
         'all exact original66/9 targets')
    expected_actor,full_command=wire(source,bound,capture)
    need(values['phone_request']==expected_actor and operation['phone']['command']==full_command,'actual command executes exact reviewed bytes')
    ai=strict(values['actor_intent']);baseline=strict(values['actor_baseline'])
    need(ai['request']==strict(expected_actor)and ai['request_sha256']==pin(expected_actor)['sha256']
      and ai['label']==ACTOR_LABEL and ai['automatic_replay']is False,'actual original actor intent')
    need(baseline['rc']==0 and baseline['stderr']==''and baseline['stdout'].splitlines()==[
      driver.BOOT,'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'],
      'actual sameboot fixed-route baseline')
    cap=load(capture,'original_capture')
    raw_by_path={path:read(item['copy'])for path,item in priorproof['original_copies'].items()}
    rows={path:item['original']for path,item in priorproof['original_copies'].items()}
    def original(path,expected=None,**_kwargs):
        path=str(path);need(path in raw_by_path,'original callback exact175 scope')
        if expected is not None:
            need(all(expected[k]==rows[path][k]for k in ('bytes','sha256')if k in expected),'actual original byte pins')
            if 'metadata'in expected:need(expected['metadata']==rows[path]['metadata'],'actual original full9')
        return raw_by_path[path]
    cap.read_original=original;cap.DATA=dict(raw_by_path)
    cap.C=load(raw_by_path[str(cap.HOME/'package/source/component_common.py')],'original_common')
    files,life,late,retained,summary,snapshot=driver.api_from_preflight(cap,q)
    prior=summary['inventory']
    preinv=strict(members['PRE-INVENTORY.json']);pre=strict(members['PRE-OBSERVATIONS.json'])
    afterinv=strict(members['AFTER-INVENTORY.json']);post=strict(members['POST-OBSERVATIONS.json'])
    before_original=strict(priorproof['observations_raw'])
    need(late.inventory_value(preinv)==late.inventory_value(priorproof['inventory'])
      and preinv['roots']==prior['roots']+[str(cap.HOME),str(cap.JOURNAL)]and len(preinv['roots'])==43,
      'fresh complete43 equals fully preserved original topology and metadata')
    for key in ('stage_before','stage_after','transport_before','transport_after','historical_role_generations',
                'retired_production_role_generations','native_historical_inventory','historical_inventory',
                'retained_stage_binding','retained_stage_closure','retained_stage_parent_profiles'):
        need(pre[key]==before_original[key],'fresh preserved preflight field '+key)
    need(pre['schema']=='hepta.owned-unstarted-stage.phone-observations.v1'
      and pre['state']=='EXPIRED_OWNED_UNSTARTED_STAGE_PRESERVED_NO_CLEANUP'
      and pre['current_inventory_root_count']==43 and pre['phone_file_writes']==0
      and pre['lease_expired_observed']is True and pre['original_lease_expires_unix_ms']==q['scope']['lease_expires_unix_ms'],
      'complete unmodified original collector preflight')
    roles=pre['historical_role_generations']+pre['retired_production_role_generations']
    observations(core,pre,roles,pre['native_identity'],pre=True)
    expected_argv=shlex.split(strict(expected_actor)['command'])[-5:]
    need(decoded(pre['native_identity']['argv_b64'],65536).rstrip(b'\0').split(b'\0')==[x.encode()for x in expected_argv],
         'actual observer argv executes exact bound cleanup source')
    original_absence(pre['absent_before'],[str(cap.HOME/n)for n in cap.ABSENT_NAMES]+[str(cap.FIXTURE),retained.FIXTURE])
    original_absence(pre['absent_after'],[str(cap.HOME/n)for n in cap.ABSENT_NAMES]+[str(cap.FIXTURE),retained.FIXTURE])
    need(len(pre['locks_before'])==len(pre['locks_after'])==13,'complete original continuous lock set')
    for a,c,old in zip(pre['locks_before'],pre['locks_after'],before_original['locks_before']):
        need(a==old and c['canonical_path']==a['canonical_path']and c['metadata']==a['metadata']
          and c['same_open_fd_held']is True,'all13 existing original locked generations')
    intent_raw=members['CLEANUP-INTENT.original.json'];result_raw=members['CLEANUP-RESULT.original.json']
    intent=strict(intent_raw);result=strict(result_raw)
    need(intent['schema']=='hepta.owned-unstarted-stage.cleanup-intent.v1'
      and intent['state']=='ONE_EXACT_OWNED_CLEANUP_RESERVED'and intent['scope']==b['scope']
      and intent['source']==DRIVER and intent['binding']==pin(bound)and intent['capture_source']==CAPTURE
      and intent['capture_request']==pin(qraw)and intent['owned_files']==targets['files']
      and intent['owned_directories']==targets['directories']and intent['owned_targets']==driver.TARGETS
      and intent['preserved_original_map']==pin(mraw)and intent['fresh_preflight_original_count']==175
      and intent['fresh_preflight_inventory']==pin(members['PRE-INVENTORY.json'])
      and intent['automatic_retry']is False and intent['native_task_replay']is False
      and intent['original_lease_modified']is False and intent['nonce_reused']is False,'durable exact intent before removals')
    audits=strict(members['AUDIT-ORIGINALS.json'])
    need(audits['schema']=='hepta.owned-unstarted-stage.actual-audit-originals.v1'
      and len(audits['files'])==2 and audits['files']==packet['audit_originals']
      and audits['outside_complete41_inventory']is True and audits['old_inventory_not_claimed_to_cover_all_phone_files']is True,
      'two actual audit originals explicitly outside41')
    for row,raw,path in zip(audits['files'],(intent_raw,result_raw),(driver.INTENT,driver.RESULT)):
        need(set(row)=={'path','bytes','sha256','metadata','selinux_raw_b64'}and row['path']==str(path)
          and pin2(row)==pin(raw),'exact full audit original bytes')
        m=full9(row['metadata']);need(stat.S_ISREG(m[2])and stat.S_IMODE(m[2])==0o600
          and m[3:6]==[0,0,1]and m[6]==len(raw)and decoded(row['selinux_raw_b64'],512)==STATE_LABEL,
          'actual root600 singlelink state_file audit')
    need(result['schema']=='hepta.owned-unstarted-stage.cleanup-phone-result.v1'
      and result['state']=='EXACT_OWNED_UNSTARTED_STAGE_REMOVED'and result['scope']==b['scope']
      and result['source']==DRIVER and result['binding']==pin(bound)and result['intent']==audits['files'][0]
      and result['preservation_manifest']==b['preservation_manifest']==inputs['preservation_manifest']
      and result['host_verification']==b['host_verification']==inputs['preservation_host_verification']
      and result['removed_files']==66 and result['removed_directories']==9
      and result['pre_inventory']==preinv and result['pre_observations']==pre
      and result['after_inventory']==afterinv and result['post_observations']==post,'actual complete original cleanup result')
    states=verify_removals(core,driver,targets,result['removed'])
    need(post['schema']=='hepta.owned-unstarted-stage.post-cleanup-observations.v1'and post['scope']==b['scope']
      and post['all37_role_generations']==roles and post['native_identity']['identity']==pre['native_identity']['identity']
      and post['native_identity']['argv_sha256']==pre['native_identity']['argv_sha256'],'same actual observer and complete post scope')
    observations(core,post,roles,post['native_identity'])
    paths=targets['fresh_required_absence_after_cleanup']
    need(paths==post['fresh_required_absence_paths']==packet['fresh_required_absence_paths'],'same exact seven top-level absence paths')
    original_absence(post['absent_before'],paths);original_absence(post['absent_after'],paths)
    for row in post['retained_final02_fixture_absence']:original_absence([row],[retained.FIXTURE])
    need(len(post['retained_final02_fixture_absence'])==2,'two retained fixture observations')
    need(late.inventory_value(afterinv)==late.inventory_value(prior)and len(afterinv['roots'])==41
      and retained.validate_private_preservation(summary,afterinv,validate_inventory=late.inventory_value)is True,
      'actual complete41 comparison view and all old retained private entries unchanged')
    need(post['inventory']==pin(members['AFTER-INVENTORY.json'])==packet['after_inventory']
      and post['retained_inventory']==pin(summary['inventory_raw'])
      and packet['post_observations']==pin(members['POST-OBSERVATIONS.json']),'raw inventory and observation pins')
    profiles=post['retained_stage_parent_profiles']
    need(profiles==late.retained_stage_parent_profiles(summary,prior,profiles['before'],profiles['after'])
      and profiles['allowed_new_homes']==[],'actual shared parents exact old names with current full9')
    shared=states[str(driver.HOME.parent)]
    need(profiles['after']['gnu']==shared,'last physical home removal agrees with final shared parent')
    for alias in ('gnu','android'):
        need(profiles['before'][alias]==profiles['after'][alias],'two actual shared parent bookends')
    need(post['same13_lock_open_descriptions']==pre['locks_after'],'same13 locked original inodes through after phase')
    need(post['live_policy']==pre['live_policy']=={'bytes':2667752,'sha256':cap.POLICY_SHA}
      and post['old63_originals_preserved']is True and post['complete_inventory_value_equal']is True,
      'actual unchanged policy and original63 preserve gates')
    ap=result['audit_scope_parent_profiles']
    need(set(ap)=={'schema','before','after','removed_transport_names','added_audit_names'}
      and ap['schema']=='hepta.native-guard.cleanup-audit-parent-profiles.v1'
      and ap['before']==targets['transport_parents'][0]
      and ap['removed_transport_names']==sorted([driver.LABEL+'.tar.gz',driver.LABEL+'.stage.py'])
      and ap['added_audit_names']==sorted([driver.INTENT.name,driver.RESULT.name]),'exact independent audit parent family')
    core._directory(ap['before'],private=True,label=STATE_LABEL);core._directory(ap['after'],private=True,label=STATE_LABEL)
    before=ap['before'];after=ap['after'];last_parent=states[str(driver.STAGING)]
    need(after['path']==before['path']==str(driver.STAGING)
      and after['metadata'][:6]==before['metadata'][:6]
      and after['names']==sorted((set(before['names'])-set(ap['removed_transport_names']))|set(ap['added_audit_names']))
      and after['names']==sorted(last_parent['names']+[driver.RESULT.name])
      and after['selinux_raw_b64']==before['selinux_raw_b64']
      and audits['parent_after_result']==after,'actual final staging parent full9/names/label after result entry publication')
    need(result['android_upload_parent_before']==targets['transport_parents'][1]
      and result['android_upload_parent_after']==states[targets['transport_parents'][1]['path']],
      'Android upload parent exact only two removals')
    for k in ('new_native_case_count','new_component_role_generation_count','new_fixture_count','fixed19_credit'):
        need(result[k]==post[k]==packet[k]==0,'cleanup gives no new native/role/fixture/case credit')
    need(result['old_final02_untouched']is True and result['prior_final02_original_sender_wait']==post['prior_final02_original_sender_wait']=='UNKNOWN_UNCHANGED'
      and post['no_original_wait_reconstructed']is True and result['whole_deadline_seconds']==45
      and 0<=result['elapsed_before_result_seconds']<45 and result['automatic_retry']is False,
      'original deadlines, old unknown wait and one-use scope preserved')
    for key in ('policy_changes','native_submissions','model_requests','ui_actions'):need(post[key]==0,'no business or policy action')
    for row in list(book.values()):read(row)
    closed={'schema':'hepta.native-guard.owned-unstarted-stage-cleanup.v1',
      'state':'VERIFIED_OWNED_UNSTARTED_STAGE_CLEANUP','consumed_nonce':driver.NONCE,'boot_id':driver.BOOT,
      'original_scope':b['scope'],'cleanup_source':inputs['cleanup_source'],'cleanup_bound_request':inputs['bound_request'],
      'actual_root_job_id':job_id,'actual_operation':inputs['actor_result'],'actual_archive':inputs['packet_archive'],
      'preservation_manifest':inputs['preservation_manifest'],'host_verification':inputs['preservation_host_verification'],
      'retained_stage_closure':inputs['retained_stage_closure'],
      'after_inventory':original_members['AFTER-INVENTORY.json'],'retained_inventory':pin(summary['inventory_raw']),
      'post_observations':original_members['POST-OBSERVATIONS.json'],
      'cleanup_intent':original_members['CLEANUP-INTENT.original.json'],'cleanup_result':original_members['CLEANUP-RESULT.original.json'],
      'retained_stage_parent_profiles':profiles,'fresh_required_absence_paths':paths,
      'audit_originals':audits['files'],'audit_scope_parent_profiles':ap,
      'audit_scope_explicitly_additional_to41':True,'removed_files':66,'removed_directories':9,
      'new_native_case_count':0,'new_component_role_generation_count':0,'new_fixture_count':0,'fixed19_credit':0,
      'old_final02_original_sender_wait':'UNKNOWN_UNCHANGED','no_original_wait_reconstructed':True,
      'post_cleanup_fresh_current41_admission_required':True}
    return {'closure_value':closed,'closure_raw':enc(closed),'after_inventory_raw':members['AFTER-INVENTORY.json'],
      'after_inventory_value':late.inventory_value(afterinv),'audit_result_raw':result_raw,'audit_intent_raw':intent_raw,
      'originals':list(book.values()),'retained_inventory_raw':summary['inventory_raw']}
def verify_owned_unstarted_stage_cleanup(inputs_raw,*,read_pinned):
    inputs=strict(inputs_raw)
    need(set(inputs)=={'schema','execution_inputs','closure'}
      and inputs['schema']=='hepta.owned-unstarted-stage.cleanup-verification-inputs.v1','exact immutable cleanup consumer inputs')
    execution=exact3(inputs['execution_inputs']);closure=exact3(inputs['closure'])
    eraw=read_pinned(execution);craw=read_pinned(closure)
    need(pin(eraw)==pin2(execution)and pin(craw)==pin2(closure),'complete exact cleanup input and closure originals')
    value=verify_cleanup_execution(eraw,read_pinned=read_pinned)
    need(craw==value['closure_raw'],'closure is exactly independently reconstructed original evidence, not supplied PASS flags')
    need(read_pinned(execution)==eraw and read_pinned(closure)==craw,'consumer original bookends')
    c=value['closure_value']
    return {'schema':'hepta.native-guard.owned-unstarted-stage-cleanup-verification.v1',
      'state':'VERIFIED_OWNED_UNSTARTED_STAGE_CLEANUP','consumed_nonce':c['consumed_nonce'],'boot_id':c['boot_id'],
      'closure':closure,'after_inventory':c['after_inventory'],'retained_inventory':c['retained_inventory'],
      'after_inventory_raw':value['after_inventory_raw'],'after_inventory_value':value['after_inventory_value'],
      'original_scope':c['original_scope'],'retained_stage_parent_profiles':c['retained_stage_parent_profiles'],
      'fresh_required_absence_paths':c['fresh_required_absence_paths'],'audit_originals':c['audit_originals'],
      'audit_scope_parent_profiles':c['audit_scope_parent_profiles'],'preservation_manifest':c['preservation_manifest'],
      'host_verification':c['host_verification'],'retained_stage_closure':c['retained_stage_closure'],
      'new_native_case_count':0,'new_component_role_generation_count':0,'new_fixture_count':0,
      'fixed19_credit':0,'old_final02_original_sender_wait':'UNKNOWN_UNCHANGED',
      'post_cleanup_fresh_current41_admission_required':True}
if __name__=='__main__':
    raise SystemExit('Pure verification API only; exact actual execution originals are required.')
