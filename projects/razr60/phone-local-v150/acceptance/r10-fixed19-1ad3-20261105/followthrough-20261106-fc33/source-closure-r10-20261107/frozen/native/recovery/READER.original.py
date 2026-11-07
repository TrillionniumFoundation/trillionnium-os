#!/usr/bin/env python3
"""Pure original-byte verification of the single exact-owned failed NEG02 final04 current44 cleanup.

Every external byte arrives through read_pinned. This module never opens a
phone/host path, starts a process, sends a signal or removes a file. A successful
phone result is verified against the actual original command, preserved targets,
every removal transition, inventory, process/endpoint observations and two audit
originals. The prior final02 sender wait remains unknown.
"""
import ast,base64,errno,hashlib,io,json,lzma,re,shlex,stat,tarfile,types,zlib
from pathlib import Path,PurePosixPath
DRIVER={'bytes': 58095, 'sha256': '9fc8106bac74648ca0e6fe6fb94c3485af683a6957ece68887a13ec21438220d'}
CAPTURE={'bytes': 89241, 'sha256': 'e6f1562d9e887137958eaeecb8aec647c4601ac4796c33656a7aaf58985daa34'}
CORE={'bytes': 41792, 'sha256': 'a6eccadaa8a6e62614be3e036a177d6cfea8c28dd8e77e51d1be25f3b40c8278'}
PRESERVATION={'bytes': 3450056, 'sha256': '94ed8217264ba8a60d7d7f3b3edc1a63caf22d36c1187ef40bda516e308b5955'}
PRIOR_HOST={'bytes': 4904, 'sha256': '792222d932a478f26f01465975528d132099e5dd5e98f6beaf6a32838631c5b3'}
RETAINED_CLOSURE={'bytes':65567,'sha256':'38a93ca265e0bb1b35ae80ab8309f389991e8c9a300700508e09841df3313e76'}
ACTOR={'bytes':5652,'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'}
ACTOR_LABEL='ng-a1055-neg02-final04-owned-cleanup02'
ACTOR_PATH='/home/alex/razr60-local-model-v150/ops/phone_once.py'
ACTOR_REQUEST_PATH='/home/alex/razr60-local-model-v150/requests/'+ACTOR_LABEL+'.json'
OPERATION_PREFIX='/home/alex/razr60-local-model-v150/operations/'+ACTOR_LABEL
KEY='a1055-neg02-final04-owned-cleanup02'
ROOT_CLEANUP_AUTHORITY={'bytes': 4063, 'sha256': 'ca6574a4aa50893bab4007e4fb32f98bd70fa30ff2c27d2e38deee5794be604e'}
ACTUAL_CLEANUP_JOB='1a1b15889a7-fc05-77e7'
ACTUAL_OPERATION={'bytes': 6151995, 'sha256': '9bae925fe62ad40039b1b915d309c14c1d58a5f36067ad4d1b77fae719fe6fd0'}
GUARDED_XZ_CONSTRUCTION={'bytes': 4517, 'sha256': 'dd2ad3a8b00f4d71dc852ade86f71b979e31a232dc4524314cc1f1a4432c59d9'}
XML_PARENT_TRANSITION_VERIFIER={'bytes': 36573, 'sha256': 'e22887c26a9d9758c7e9be8e780eccadf638060b469c74db35cc2d56c82b372d'}
XML_PARENT_TRANSITION_INPUTS={'bytes': 6142, 'sha256': 'b06c8af1f40cc5114df3261e1a26d9c83e7f98d0980e0dd5e19cb5373ec22e41'}
XML_PARENT_TRANSITION_PIN={'bytes':1224,'sha256':'dd2250f11292f8781478921043a92a09822ed598bb3bf1e511ec4253cf061f92'}
PREVIOUS_CLEANUP={'bytes':17625,'sha256':'d85b8b7d22bbfc67ceb2a098b60cfb4b5edcc4249296121ed5d9a014b7d07cca'}
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
def wire(source,bound,capture,construction_raw,*,read):
    need(pin(construction_raw)==GUARDED_XZ_CONSTRUCTION,'exact reviewed guarded-XZ construction original')
    c=strict(construction_raw)
    need(type(c)is dict and set(c)=={'schema','state','source','bound_request','capture_source','parent_builder',
      'builder','probe_inputs','wrapper','compressed_payload','launcher','phone_request','wrapper_identifier',
      'compile_marker','codec','decode_memory_limit_bytes','whole_seconds','actor_seconds','actor_kind',
      'complete_service_including_nul','maximum_service_including_nul_bytes','guard','output_bounds'},
      'exact single guarded-XZ cleanup construction')
    need(c['schema']=='hepta.owned-unstarted-stage.guarded-xz-construction.v1'
      and c['state']=='ROOT_REVIEW_REQUIRED_EXACT_CLEANUP_CANDIDATE'
      and c['source']==pin(source)and c['bound_request']==pin(bound)and c['capture_source']==pin(capture)
      and c['output_bounds']==strict(bound)['output_bounds'],'construction binds complete executed cleanup originals')
    need(c['whole_seconds']==45 and c['actor_seconds']==70 and c['actor_kind']=='shell'
      and c['codec']=='XZ preset6 standard container'and c['decode_memory_limit_bytes']==16777216
      and c['maximum_service_including_nul_bytes']==65535 and c['wrapper_identifier']=='owned_stage_cleanup'
      and c['compile_marker']=='<reviewed-exact-owned-current44-cleanup>',
      'one exact cleanup kind and original45/70/65535/16MiB limits')
    parent=read(exact3(c['parent_builder']));selected=read(exact3(c['builder']))
    need(pin(parent)=={'bytes':14548,'sha256':'c6b7088a3512dc493292a91a936fa815c708a1c18b4bb14205c200f07f1f53ea'},
      'complete reviewed parent guard with all probe gates')
    old=b'<reviewed-readonly-current41-rollback>';new=b'<reviewed-exact-owned-current44-cleanup>'
    need(parent.count(old)==1 and new not in parent and selected==parent.replace(old,new,1)
      and selected.replace(new,old,1)==parent,'whole guard single compile-marker forward/inverse')
    builder=load(selected,'guarded_xz_cleanup')
    probe_inputs=read(exact3(c['probe_inputs']))
    need(pin(probe_inputs)=={'bytes':4366,'sha256':'c20c2e38aa4ce94c6ee0b4a0cdf4f1d023e1b5cc7b83c7aa60ae0f4475096292'},
      'exact original actual XZ probe input set')
    def probe_read(row):
        need(type(row)is dict and set(row)=={'path','bytes','sha256','metadata'},'all10 probe originals retain exact4 descriptors')
        full9(row['metadata'])
        return read(row)
    probe=builder.verify_actual_xz_probe(probe_inputs,read_pinned=probe_read)
    need(probe['all10_originals_recomputed']is True and probe['original_wait_exit']==0
      and probe['original_dual_EOF']is True,'complete original successful probe and all4 library identities')
    wrapper=read(exact3(c['wrapper']))
    expected_wrapper=b"import json,types\nv=json.loads(BINDING_RAW);s=v['source'].encode();r=v['binding'].encode();c=v['capture_source'].encode()\nm=types.ModuleType('owned_stage_cleanup');exec(compile(s,'<owned_stage_cleanup>','exec'),m.__dict__)\nraise SystemExit(m.main(r,s,c))\n"
    need(wrapper==expected_wrapper,'complete fixed one-call cleanup wrapper bytes')
    payload=enc({'binding':bound.decode(),'source':source.decode(),'capture_source':capture.decode()})
    raw=wrapper+b'\0'+payload
    compressed=read(exact3(c['compressed_payload']))
    need(len(compressed)<=MAX_FILE,'single original compressed payload bound')
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=16777216)
    need(decoder.decompress(compressed,max_length=len(raw)+1)==raw and decoder.eof and not decoder.unused_data,
      'single complete XZ payload exact bytes and original memory bound')
    # Use the actual sealed compressed original, never assume a host encoder
    # reproduces another runtime's legal compressed bitstream.
    launcher,guard=builder.build_checked_xz_launcher(wrapper,payload,compressed,probe['probe_source_raw'],probe['identity_raw'])
    need(launcher==read(exact3(c['launcher']))and guard==c['guard'],
      'whole launcher equals the complete reviewed identity guard and actual payload')
    env='/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '
    command=env+shlex.quote(launcher.decode());full='/debug_ramdisk/su -c '+shlex.quote(command)
    service=('shell,v2,raw:'+full+'\0').encode()
    need(pin(service)==c['complete_service_including_nul']and len(service)<=65535,
      'exact complete ADB service including original prefix and final NUL')
    actor=enc({'kind':'shell','root':True,'command':command,'timeout_seconds':70})
    need(actor==read(exact3(c['phone_request'])),'complete frozen cleanup request, never readonly stdin kind')
    return actor,full
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
def require_actual_binding():
    need(all(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int
      and row['bytes']>0 and re.fullmatch('[0-9a-f]{64}',row['sha256'])
      for row in (DRIVER,CORE,PRESERVATION,PRIOR_HOST,ROOT_CLEANUP_AUTHORITY,ACTUAL_OPERATION,GUARDED_XZ_CONSTRUCTION,XML_PARENT_TRANSITION_VERIFIER,XML_PARENT_TRANSITION_INPUTS))
      and type(ACTUAL_CLEANUP_JOB)is str and ACTUAL_CLEANUP_JOB,
      'UNBOUND: complete actual capture, cleanup and original authority required')
def previous_cleanup_observations(core,cap,samples):
    need(type(samples)is list and len(samples)==2,'two original previous-cleanup observations')
    for sample in samples:
        need(set(sample)=={'closure','audit_originals','absence','prior_audits_not_replaced'}
          and sample['closure']==PREVIOUS_CLEANUP==cap.PRIOR_CLEANUP['closure']
          and sample['audit_originals']==cap.PRIOR_CLEANUP['audit_originals']
          and sample['prior_audits_not_replaced']is True,
          'old d85b and both original audit full9 remain distinct and unchanged')
        core._absence_rows(sample['absence'],cap.PRIOR_CLEANUP['absence_paths'])

def observations(core,obs,roles,observer,*,pre=False):
    need(len(roles)==len(set(map(tuple,roles)))==40,'all exact40 generations')
    need(observer['domain']=='u:r:magisk:s0'and observer['uid']==observer['gid']==[0]*4
      and observer['nnp']==0 and observer['exe']=='/usr/bin/python3','actual ordinary Root observer')
    for key in ('identity',):
        need(type(observer[key])is list and all(type(n)is int for n in observer[key]),'original observer generation')
    argv=decoded(observer['argv_b64'],65536)
    need(hashlib.sha256(argv).hexdigest()==observer['argv_sha256'],'observer original argv hash')
    need(len(obs['all40_role_absence'])==len(obs['scope_process_census'])==2,'two complete40/scope observations')
    for old,current in zip(obs['all40_role_absence'],obs['scope_process_census']):
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
def verify_selected_xml_parent_transition(source_raw,inputs_raw,*,read_pinned,targets):
    need(pin(source_raw)==XML_PARENT_TRANSITION_VERIFIER and pin(inputs_raw)==XML_PARENT_TRANSITION_INPUTS,
      'exact independently reviewed timestamp-transition verifier and full original inputs')
    need(XML_PARENT_TRANSITION_VERIFIER=={'bytes':36573,'sha256':'e22887c26a9d9758c7e9be8e780eccadf638060b469c74db35cc2d56c82b372d'},
      'one reviewed actual18 helper source identity')
    selected_inputs=strict(inputs_raw)
    need(type(selected_inputs)is dict and set(selected_inputs)=={'schema','originals'}
      and selected_inputs['schema']=='hepta.owned-unstarted-stage.xml-parent-timestamp-transition-verification-inputs.v2'
      and type(selected_inputs['originals'])is dict and len(selected_inputs['originals'])==18
      and 'failed_root_transport'in selected_inputs['originals'],
      'mandatory v2 all18 originals including original failed756b Root wait/streams')
    verifier=load(source_raw,'xml_parent_timestamp_transition')
    proof=verifier.verify_xml_parent_timestamp_transition(inputs_raw,read_pinned=read_pinned)
    need(proof['state']=='VERIFIED_EXACT_OBSERVED_TIMESTAMP_TRANSITION_NO_CLEANUP_CREDIT'
      and proof['cleanup_qualified']is False and proof['fixed19_credit']==0
      and proof['diagnostic_holds_component_locks']is False
      and proof['diagnostic_reverified192_originals']is False
      and proof['failed756b_directory_rows_were_not_retained']is True,
      'finite prior observations are not the new locked cleanup preflight')
    need(proof['schema']=='hepta.owned-unstarted-stage.xml-parent-timestamp-transition-verification.v2'
      and proof['originals']==selected_inputs['originals']
      and proof['historical_failed_root_transport_original']==selected_inputs['originals']['failed_root_transport']
      and type(proof['historical_failed_root_provenance'])is dict,
      'complete v2 typed Root provenance retained, not inferred from actor result')
    historical=proof['historical_failed_root_provenance']
    need(historical['schema']=='hepta.xml-parent-transition.historical-failed756b-root-provenance.v1'
      and historical['original_job_id']=='1a1b10ebd5e-fc05-756b'
      and historical['original_start_reused']is True and historical['original_start_retried_launch']is False
      and historical['original_controller_wait_exit_code']==0 and historical['actual_phone_exit_code']==1
      and historical['original_publication_status']=='UNKNOWN_ORIGINAL_MCP_TIMEOUT_NOT_INFERRED_WRITTEN'
      and historical['original_wait_inferred_from_P4_result']is False
      and historical['historical_failed756b_effects_inferred_zero']is False
      and historical['root_original_streams']['stdout']['eof']is True
      and historical['root_original_streams']['stderr']['eof']is True,
      'historical failed756b original reused/wait/dualEOF/phone1 and publication UNKNOWN unchanged')
    transition=proof['transition'];old=proof['old_parent_row'];current=proof['new_parent_row']
    need(pin(enc(transition))==XML_PARENT_TRANSITION_PIN
      and old==targets['sender_xml_parent']and pin(enc(old))==transition['original_parent']
      and pin(enc(current))==transition['observed_parent'],
      'whole observed transition and both full canonical parent rows are independently reconstructed')
    need(current=={**old,'metadata':transition['observed_metadata']}
      and full9(current['metadata'])[:7]==full9(old['metadata'])[:7]
      and old['metadata']==transition['original_metadata']
      and old['path']==current['path']=='/proc/1/root/data/local/tmp',
      'only the two explicitly observed timestamps may differ; all names and raw labels remain exact')
    return proof

def verify_removals(core,driver,targets,events,*,xml_parent):
    need(type(events)is list and len(events)==86,'all86 actual exact removal events')
    own_rows={row['path']:row for row in targets['files']}
    states={row['path']:dict(row)for row in targets['directories'].values()}
    shared=targets['aliases'][2]['gnu'];states[shared['path']]=dict(shared)
    for row in targets['transport_parents']:states[row['path']]=dict(row)
    states[xml_parent['path']]=dict(xml_parent)
    staging=states[str(driver.STAGING)]
    staging['names']=sorted(staging['names']+[driver.INTENT.name])
    own_files=sorted(path for path in own_rows if driver.under(path,driver.HOME))
    dirs=sorted(targets['directories'],key=lambda n:(len(Path(n).parts),n),reverse=True)
    directory_paths=[str(driver.HOME if name=='.'else driver.HOME/name)for name in dirs]
    xml_paths=['/proc/1/root/data/local/tmp/hepta-natural-'+driver.LABEL+'-v150-'+str(i)+'.xml'for i in range(1,12)]
    transfer_paths=[row['path']for row in targets['files']if row['path']not in own_files and row['path']not in xml_paths]
    ordered_transfers=[str(driver.STAGING/(driver.LABEL+'.tar.gz')),str(driver.STAGING/(driver.LABEL+'.stage.py')),
      '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-'+driver.LABEL+'.tar.gz',
      '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-'+driver.LABEL+'.stage.py']
    need(set(transfer_paths)==set(ordered_transfers),'exact four transport originals')
    expected_order=own_files+directory_paths+ordered_transfers+xml_paths
    need([r['path']for r in events]==expected_order and len(set(expected_order))==86,'exact removal order and scope, no alias double delete')
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
    need(len(states)==4 and sum(row['kind']=='file'for row in events)==77,'only four surviving tracked parents')
    return states
def foreign_window_original(core,window,scope,phase,parents,absence_parents,minimum=0):
    fields={'phase','files','parents_before','parents_after','root_absence_before',
      'root_absence_after','journal_absence_basis','started_monotonic_ns','finished_monotonic_ns'}
    need(type(window)is dict and set(window)==fields and window['phase']==phase
      and window['files']==scope['files']and len(window['files'])==4,
      'four complete separately retained foreign originals in the exact observation window')
    need(window['parents_before']==window['parents_after']==parents,
      'complete two-parent full9/names/raw-label bookends in this actual window')
    for row in parents:core._directory(row)
    start=window['started_monotonic_ns'];end=window['finished_monotonic_ns']
    need(type(start)is int and type(end)is int and 0<start<=end and minimum<=start,
      'ordered actual foreign observation window')
    need(window['journal_absence_basis']==scope['journal_absence_basis'],
      'journal has only the independently observed absent ancestor, no invented stat or wait')
    for sample in (window['root_absence_before'],window['root_absence_after']):
        core._absence_rows(sample,scope['root_absence_paths'])
        for row in sample:
            parent=absence_parents[row['path']]
            need(start<=row['observed_monotonic_ns']<=end
              and row['parent_metadata']==parent['metadata']
              and row['parent_selinux_raw_b64']==parent['selinux_raw_b64'],
              'every exact foreign ENOENT belongs to this window and its actual complete parent')
    return end

def foreign_accounting(inline,reads,scope):
    need(type(inline)is int and inline>=0 and reads in (8,12),'finite actual foreign read domain')
    complete=sum(row['bytes']for row in scope['files'])
    need(complete==1561740,'fixed four exact complete foreign byte lengths')
    external=(reads//4)*complete
    need(inline+external<=MAX_TOTAL,'one shared32MiB charge, not a separate allowance per family')
    return {'inline_retained_path_bytes':inline,'foreign_complete_file_reads':reads,
      'foreign_cumulative_read_bytes':external,'charged_bytes':inline+external,
      'maximum_total_bytes':MAX_TOTAL,'per_file_maximum_bytes':MAX_FILE,
      'domain':'inline_retained_path_bytes_plus_foreign_cumulative_reads',
      'whole_program_physical_io_capped':False}

def verify_foreign_cleanup_originals(core,cap,q,priorproof,raw_by_path,pre,post,intent,result,packet,members,states):
    # priorproof is the complete, source-pinned preservation API result. That API
    # really re-runs the independent foreign original verifier and its two
    # historical readers, including7173's initial timeout and same-key authority.
    scope=cap.foreign_binding(q)
    need(priorproof['foreign_retained_scope']==scope==pre['foreign_retained_scope']
      ==intent['foreign_retained_scope']==result['foreign_retained_scope'],
      'same independently reconstructed foreign original family through actual cleanup')
    foreign_paths={row['path']for row in scope['files']}
    need(len(foreign_paths)==4 and not foreign_paths.intersection(raw_by_path)
      and len(raw_by_path)==192 and packet['external_complete_foreign_original_count']==4
      and packet['foreign_originals_deleted']is False,
      '192 inline originals plus4 complete foreign references, never extra owned targets')
    need(not foreign_paths.intersection(row['path']for row in result['removed']),
      'no foreign original appears in any actual removal event')
    prebook=pre['foreign_retained_bookends']
    need(type(prebook)is dict and set(prebook)=={'before','after','read_accounting'},
      'complete original capture foreign windows')
    roots=scope['root_absence_paths'];aliases=pre['stage_before']['aliases'][2]
    before_absence={roots[0]:aliases['gnu'],roots[1]:aliases['android'],roots[2]:pre['sender_xml_before']['parent']}
    initial=scope['initial_parent_profiles']['after']
    end=foreign_window_original(core,prebook['before'],scope,'capture_before',initial,before_absence)
    end=foreign_window_original(core,prebook['after'],scope,'capture_after',initial,before_absence,end)
    inline=sum(map(len,raw_by_path.values()));before_account=foreign_accounting(inline,8,scope)
    need(prebook['read_accounting']==before_account==intent['foreign_read_accounting_before_audit']
      and intent['foreign_reference_family_not_owned_or_deleted']is True,
      'all eight actual pre-audit foreign reads included in the original shared charge')
    book=result['foreign_retained_bookends']
    need(type(book)is dict and set(book)=={'before','after','read_accounting'}
      and book['before']==prebook['before'],'full RESULT preserves the actual first foreign window')
    parents=[result['android_upload_parent_after'],result['audit_scope_parent_profiles']['after']]
    need(parents[0]==states[initial[0]['path']]
      and result['android_upload_parent_before']==initial[0]
      and result['audit_scope_parent_profiles']['before']==initial[1],
      'foreign current parent transitions start from the preserved initial window')
    for index,(old,current)in enumerate(zip(initial,parents)):
        removed={cap.UPLOAD_ARCHIVE.name,cap.UPLOAD_SOURCE.name}if index==0 else {cap.ARCHIVE.name,cap.STAGE_SOURCE.name}
        added=set()if index==0 else {Path(row['path']).name for row in packet['audit_originals']}
        need(removed<=set(old['names'])and not added.intersection(old['names'])
          and current['path']==old['path']and current['metadata'][:6]==old['metadata'][:6]
          and current['selinux_raw_b64']==old['selinux_raw_b64']
          and current['names']==sorted((set(old['names'])-removed)|added),
          'only owned transport removals and the declared GNU audits change foreign parent membership')
    after_absence={roots[0]:post['retained_stage_parent_profiles']['after']['gnu'],
      roots[1]:post['retained_stage_parent_profiles']['after']['android'],
      roots[2]:result['sender_xml_parent_after']}
    last=max([end]+[row['completed_monotonic_ns']for row in result['removed']]
      +[row['finished_monotonic_ns']for row in post['scope_process_census']]
      +[row['observed_monotonic_ns']for row in post['endpoint_observations']])
    foreign_window_original(core,book['after'],scope,'cleanup_after',parents,after_absence,last)
    during_account=foreign_accounting(inline+len(members['CLEANUP-INTENT.original.json']),12,scope)
    final_account=foreign_accounting(inline+len(members['CLEANUP-INTENT.original.json'])
      +len(members['CLEANUP-RESULT.original.json']),12,scope)
    need(book['read_accounting']==during_account and packet['final_read_accounting']==final_account,
      'RESULT-before-write and final-complete-readback are separate exact accounting instants')
    return {'scope':scope,'bookends':book,'before_accounting':before_account,'final_accounting':final_account}

def verified_phone_known_deflate_segments(driver,known,prior,members,compressed,reported):
    """Recover actual phone DEFLATE pieces without assuming host encoder identity.

    Declared lengths only select bounded candidate slices. Each slice must
    independently decode to the exact complete known original and accept one
    final empty stored block at a valid byte-aligned nonfinal boundary. All
    literal segments, headers, padding, final block and trailer are checked
    byte-for-byte. The complete outer gzip was already bounded and decoded.
    """
    inventory=dict(prior);inventory['elapsed_seconds']=0.0
    ib,_im,ia=driver._inventory_parts(inventory,prior)
    sequence=[raw for _name,raw in sorted(known.items())]+[ib,ia,ib,ia[:-1]]
    sizes=reported['known_nonfinal_deflate_segment_bytes']
    need(type(sizes)is list and len(sizes)==len(sequence)==12
      and all(type(n)is int and 0<=n<=MAX_FILE for n in sizes)
      and sum(sizes)<=MAX_FILE,'twelve bounded original known-segment candidate lengths')
    expected={}
    for raw,size in zip(sequence,sizes):
        need((size==0)==(len(raw)==0),'empty known original has exactly an empty DEFLATE segment')
        need(raw not in expected or expected[raw]==size,'duplicate known raw has the same original length')
        expected[raw]=size
    need(compressed[:10]==b'\x1f\x8b\x08\0\0\0\0\0\0\x03','exact source-generated gzip header')
    offset=10;plain_size=0;crc=0;actual={}
    final_block=b'\x01\0\0\xff\xff'
    def account(raw):
        nonlocal plain_size,crc
        plain_size+=len(raw);need(plain_size<=MAX_TOTAL,'complete uncompressed tar bound')
        crc=zlib.crc32(raw,crc)
    def literal(raw):
        nonlocal offset
        if not raw:return
        exact=driver._stored_deflate(raw)
        need(offset+len(exact)<=len(compressed)-13 and compressed[offset:offset+len(exact)]==exact,
          'actual unknown literal block/header/padding exactly reconstructed from complete raw')
        offset+=len(exact);account(raw)
    def original(raw):
        nonlocal offset
        if not raw:return
        need(raw in expected,'known segment must have a complete reviewed original')
        size=expected[raw]
        need(size>=5 and offset+size<=len(compressed)-13,'bounded original known segment slice')
        segment=compressed[offset:offset+size]
        need(segment.endswith(b'\0\0\xff\xff'),'original full-flush nonfinal boundary')
        decoder=zlib.decompressobj(-15)
        restored=decoder.decompress(segment,len(raw)+1)
        need(restored==raw and not decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
          'actual known segment independently decodes to every exact original byte')
        tail=decoder.decompress(final_block,1)
        need(tail==b''and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
          'appended final empty block proves a valid byte-aligned nonfinal boundary')
        need(raw not in actual or actual[raw]==segment,'repeated complete known original has identical actual DEFLATE bytes')
        actual[raw]=segment;offset+=size;account(raw)
    actual_inventory=driver.strict(members['AFTER-INVENTORY.json'])
    parts=driver._inventory_parts(actual_inventory,prior)
    need((parts[0],parts[2])==(ib,ia),'complete current44 inventory original segmentation')
    actual_result=driver.CAP.strict(members['CLEANUP-RESULT.original.json']) if driver.CAP is not None else strict(members['CLEANUP-RESULT.original.json'])
    rb,ra=driver._result_parts(actual_result)
    need(actual_result['after_inventory']==actual_inventory,'same complete RESULT inventory object')
    for name,raw in sorted(members.items()):
        literal(driver._tar_header(name,len(raw)))
        if name in known:original(raw)
        elif name=='AFTER-INVENTORY.json':
            original(parts[0]);literal(parts[1]);original(parts[2])
        elif name=='CLEANUP-RESULT.original.json':
            literal(rb);original(parts[0]);literal(parts[1]);original(parts[2][:-1]);literal(ra)
        else:literal(raw)
        literal(b'\0'*((-len(raw))%512))
    final_zeros=1024+(-(plain_size+1024))%10240
    need(final_zeros<=10752,'unchanged complete USTAR EOF bound');literal(b'\0'*final_zeros)
    need(compressed[offset:offset+5]==final_block and offset+13==len(compressed),
      'one exact final block and trailer without omitted or appended compressed bytes')
    need(compressed[offset+5:offset+9]==(crc&0xffffffff).to_bytes(4,'little')
      and compressed[offset+9:offset+13]==(plain_size&0xffffffff).to_bytes(4,'little'),
      'whole canonical tar CRC32 and exact original ISIZE')
    if b''in expected:actual[b'']=b''
    need(set(actual)==set(expected),'every complete pre-audit known segment consumed')
    return actual


def original_segment_budget_plan(driver,facade,known,prior,intent_raw,original_segments):
    """Use the unchanged planning function body in an isolated host namespace.
    The sole replaced codec function returns fully verified phone-original
    bytes. It cannot encode a new value, read a path or alter the driver module.
    """
    def original_nonfinal(raw):
        need(raw in original_segments,'planning may only request verified complete original segments')
        return original_segments[raw]
    namespace=dict(driver.plan_cleanup_output.__globals__)
    namespace['_known_deflate']=original_nonfinal
    original_function=types.FunctionType(driver.plan_cleanup_output.__code__,namespace,
      'reviewed_plan_with_verified_phone_segments',driver.plan_cleanup_output.__defaults__,
      driver.plan_cleanup_output.__closure__)
    return original_function(facade,known,prior,intent_raw)


def verify_complete_output_budget(driver,cap,b,prior,intent,result,packet,packet_raw,members,compressed,foreign):
    known={name:members[name]for name in ('SOURCE.original.py','BOUND-REQUEST.original.json',
      'CAPTURE-SOURCE.original.py','CAPTURE-REQUEST.original.json','CLEANUP-INTENT.original.json',
      'PRE-INVENTORY.json','PRE-OBSERVATIONS.json','PRESERVED-ORIGINAL-MAP.json')}
    need('pre_inventory'not in result and 'pre_observations'not in result
      and result['pre_inventory_original']==pin(members['PRE-INVENTORY.json'])
      and result['pre_observations_original']==pin(members['PRE-OBSERVATIONS.json']),
      'lossless PRE member references resolve to the full original bytes in this exact archive')
    need(intent['reviewed_output_bounds']==b['output_bounds']==driver.OUTPUT_BOUNDS
      and intent['pre_mutation_output_plan_required']is True,
      'one exact reviewed finite reservation in source, request and pre-delete durable intent')
    facade=types.SimpleNamespace(foreign_read_accounting=lambda:foreign['before_accounting'])
    segments=verified_phone_known_deflate_segments(driver,known,prior,members,compressed,packet['pre_mutation_output_budget'])
    plan=original_segment_budget_plan(driver,facade,known,prior,members['CLEANUP-INTENT.original.json'],segments)
    need(plan['report']==result['pre_mutation_output_budget']==packet['pre_mutation_output_budget'],
      'entire pre-audit budget independently reconstructed from complete retained original bytes')
    need(foreign['final_accounting']['charged_bytes']<=plan['report']['maximum_final_inline_plus_foreign_charge']<=MAX_TOTAL,
      'actual final DATA plus12foreign reads plus2audits respects its one reserved maximum')
    driver.CAP=cap;driver.PRE_MUTATION_PLAN=plan
    plain,rebuilt=driver.encode_cleanup_archive(members,plan)
    need(rebuilt==compressed and pin(plain)==packet['archive_plain']
      and packet['output_encoding']=='one_gzip_known_full_flush_unknown_stored_v1',
      'single-gzip representation exactly rebuilds every canonical tar byte and block')
    metadata_raw=enc({**packet,'archive_base64':''})
    need(len(metadata_raw)<=b['output_bounds']['packet_metadata_maximum_bytes']
      and enc(packet)==packet_raw and len(packet_raw)<=plan['report']['maximum_complete_stdout_bytes']<=8*1024*1024-65536,
      'all original stdout bytes and complete metadata satisfy the pre-delete output bound')
    return plan['report']


def verify_cleanup_execution(inputs_raw,*,read_pinned):
    require_actual_binding()
    inputs=strict(inputs_raw)
    required={'schema','cleanup_source','bound_request','phone_request','dispatch','preservation_core_source',
      'preservation_inputs','preservation_manifest','preservation_host_verification','retained_stage_closure',
      'actor_source','actor_intent','actor_baseline','actor_result','root_start','root_status','root_read',
      'root_stdout','root_stderr','request_publish','packet_archive','packet_originals','root_authority',
      'previous_cleanup_closure','guarded_xz_construction','xml_parent_transition_verifier_source','xml_parent_transition_inputs'}
    need(type(inputs)is dict and set(inputs)==required
      and inputs['schema']=='hepta.owned-unstarted-stage.cleanup-current44-execution-inputs.v2','exact cleanup execution input contract')
    book={}
    def read(row):
        need(type(row)is dict and set(row)in({'path','bytes','sha256'}, {'path','bytes','sha256','metadata'}),
          'exact3 original or exact4 original probe descriptor only')
        exact3({k:row[k]for k in ('path','bytes','sha256')})
        if 'metadata'in row:full9(row['metadata'])
        # The caller must verify all9 actual FD/named metadata integers whenever
        # present; preserving the field without checking it is not this contract.
        raw=read_pinned(row);need(pin(raw)==pin2(row),'exact original callback bytes')
        old=book.get(row['path'])
        if old is not None:
            need({k:old[k]for k in ('path','bytes','sha256')}=={k:row[k]for k in ('path','bytes','sha256')},
              'same original descriptor on reread')
            if 'metadata'in old and 'metadata'in row:need(old['metadata']==row['metadata'],'same full9 probe descriptor')
        if old is None or 'metadata'in row:book[row['path']]=row
        return raw
    values={key:read(inputs[key])for key in required-{'schema','packet_originals'}}
    need(pin(values['cleanup_source'])==DRIVER and pin(values['preservation_core_source'])==CORE
      and pin(values['preservation_manifest'])==PRESERVATION and pin(values['preservation_host_verification'])==PRIOR_HOST
      and pin(values['retained_stage_closure'])==RETAINED_CLOSURE and pin(values['actor_source'])==ACTOR
      and pin(values['previous_cleanup_closure'])==PREVIOUS_CLEANUP,
      'all reviewed original source and prior closure pins')
    core=load(values['preservation_core_source'],'prior_preservation')
    priorproof=core.verify_capture_preservation(values['preservation_inputs'],read_pinned=read)
    preserved=strict(values['preservation_manifest'])
    need(preserved['core_source']==inputs['preservation_core_source']
      and preserved['scope']==priorproof['scope']and preserved['owned_file_originals']==priorproof['owned_file_originals'],
      'exact independently reviewed preservation receipt rejoined to actual original bytes')
    # The new core independently replays the23 sender originals and explicit
    # P4-to-Mac mapping; b62a retains the prior Root78/ten-child proof. It never
    # upgrades unrelated final02 UNKNOWN or claims to repeat the earlier Root run.
    for field in ('host_source_input_full9',):
        rows=preserved[field]
        rows=list(rows.values())if type(rows)is dict else rows
        need(type(rows)is list and rows,'complete preserved host original book')
        for row in rows:read({k:row[k]for k in ('path','bytes','sha256')})
    need(pin(values['root_authority'])==ROOT_CLEANUP_AUTHORITY,
         'actual independently preserved Root execution authority')
    authority=strict(values['root_authority'])
    need(authority['schema']=='hepta.root.owned-stage-cleanup-original-execution-authority.v1'
      and authority['job_id']==ACTUAL_CLEANUP_JOB,'exact original cleanup process family')
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
    need(pin(actor_raw)==ACTUAL_OPERATION,
         'exact actual cleanup operation original')
    need(operation['schema']=='hepta.phone-local.operator-result.v150.1'and operation['label']==ACTOR_LABEL
      and operation['status']=='command_exited'and operation['phone']['rc']==0
      and operation['phone']['stderr']==''and operation['model_decision']is False
      and operation['native_task_result']is False,'successful original actor result, no unknown cleanup')
    job_id=terminal_originals(values,actor_raw,values['phone_request'])
    packet_raw=operation['phone']['stdout'].encode()
    need(len(packet_raw)<=8*1024*1024-65536,'original stdout limit')
    packet=strict(packet_raw)
    need(packet['schema']=='hepta.owned-unstarted-stage.cleanup-current44-result-packet.v2'
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
    need(targets['files']==priorproof['owned_file_originals']and targets['directories']==priorproof['owned_directory_originals']
      and targets['aliases']==priorproof['owned_stage_aliases']
      and targets['transport_parents']==priorproof['transport_parent_originals']
      and targets['sender_xml_parent']==priorproof['sender_xml_parent_original'],
      'all exact original77/9 targets and complete four parent scopes')
    xml_proof=verify_selected_xml_parent_transition(values['xml_parent_transition_verifier_source'],
      values['xml_parent_transition_inputs'],read_pinned=read,targets=targets)
    selected_xml_parent=xml_proof['new_parent_row']
    need(driver.XML_PARENT_TIMESTAMP_TRANSITION==xml_proof['transition']
      and driver.selected_xml_parent(targets)==selected_xml_parent,
      'phone source applies only the independently reconstructed finite timestamp transition')
    expected_actor,full_command=wire(source,bound,capture,values['guarded_xz_construction'],read=read)
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
        path=str(path);need(path in raw_by_path,'original callback exact192 scope')
        if expected is not None:
            need(all(expected[k]==rows[path][k]for k in ('bytes','sha256')if k in expected),'actual original byte pins')
            if 'metadata'in expected:need(expected['metadata']==rows[path]['metadata'],'actual original full9')
        return raw_by_path[path]
    cap.read_original=original;cap.DATA=dict(raw_by_path)
    cap.ROWS={path:{k:row[k]for k in ('path','bytes','sha256','metadata','selinux_raw_b64')}for path,row in rows.items()}
    cap.C=load(raw_by_path[str(cap.HOME/'package/source/component_common.py')],'original_common')
    files,life,late,retained,summary,snapshot=driver.api_from_preflight(cap,q)
    prior_raw=raw_by_path[q['prior_inventory']['path']]
    need(pin(prior_raw)==cap.CURRENT_INVENTORY,'exact current44 qualified NEG01 original inventory')
    prior=strict(prior_raw)
    expected_files,_names=cap.expected_tree(files)
    driver.validate_owned_target_families(cap,q,targets,expected_files)
    old_cleanup=strict(values['previous_cleanup_closure'])
    need(old_cleanup['audit_originals']==cap.PRIOR_CLEANUP['audit_originals'],
      'previous d85b audit originals match the separately reread family')
    preinv=strict(members['PRE-INVENTORY.json']);pre=strict(members['PRE-OBSERVATIONS.json'])
    afterinv=strict(members['AFTER-INVENTORY.json']);post=strict(members['POST-OBSERVATIONS.json'])
    before_original=strict(priorproof['observations_raw'])
    need(late.inventory_value(preinv)==late.inventory_value(priorproof['inventory'])
      and preinv['roots']==prior['roots']+[str(cap.HOME),str(cap.JOURNAL)]and len(preinv['roots'])==46 and len(prior['roots'])==44,
      'fresh complete46 equals fully preserved current44 plus exact owned stage')
    for key in ('stage_before','stage_after','transport_before','transport_after','historical_role_generations',
                'retired_production_role_generations','native_historical_inventory','historical_inventory',
                'retained_stage_binding','retained_stage_closure','retained_stage_parent_profiles',
                'current44_original_proof'):
        need(pre[key]==before_original[key],'fresh preserved preflight field '+key)
    for key in ('sender_xml_before','sender_xml_after'):
        need(pre[key]=={**before_original[key],'parent':selected_xml_parent},
          'complete fresh eleven-file XML observation permits only the exact prior observed parent transition')
    need(pre['schema']=='hepta.owned-unstarted-stage.phone-observations.v3'
      and pre['state']=='EXPIRED_OWNED_UNSTARTED_STAGE_PRESERVED_NO_CLEANUP'
      and pre['current_inventory_root_count']==46 and pre['phone_file_writes']==0
      and pre['lease_expired_observed']is True and pre['original_lease_expires_unix_ms']==q['scope']['lease_expires_unix_ms'],
      'complete unmodified original collector preflight')
    roles=pre['historical_role_generations']+pre['retired_production_role_generations']
    observations(core,pre,roles,pre['native_identity'],pre=True)
    previous_cleanup_observations(core,cap,[pre['prior_cleanup_before'],pre['prior_cleanup_after']])
    expected_argv=shlex.split(strict(expected_actor)['command'])[-5:]
    need(decoded(pre['native_identity']['argv_b64'],65536).rstrip(b'\0').split(b'\0')==[x.encode()for x in expected_argv],
         'actual observer argv executes exact bound cleanup source')
    original_absence(pre['absent_before'],[str(cap.HOME/n)for n in cap.ABSENT_NAMES]+[str(cap.FIXTURE),retained.FIXTURE])
    original_absence(pre['absent_after'],[str(cap.HOME/n)for n in cap.ABSENT_NAMES]+[str(cap.FIXTURE),retained.FIXTURE])
    need(len(pre['locks_before'])==len(pre['locks_after'])==14,'complete original continuous lock set')
    for a,c,old in zip(pre['locks_before'],pre['locks_after'],before_original['locks_before']):
        need(a==old and c['canonical_path']==a['canonical_path']and c['metadata']==a['metadata']
          and c['same_open_fd_held']is True,'all14 existing original locked generations')
    intent_raw=members['CLEANUP-INTENT.original.json'];result_raw=members['CLEANUP-RESULT.original.json']
    intent=strict(intent_raw);result=strict(result_raw)
    need(intent['schema']=='hepta.owned-unstarted-stage.cleanup-current44-intent.v2'
      and intent['state']=='ONE_EXACT_OWNED_CLEANUP_RESERVED'and intent['scope']==b['scope']
      and intent['source']==DRIVER and intent['binding']==pin(bound)and intent['capture_source']==CAPTURE
      and intent['capture_request']==pin(qraw)and intent['owned_files']==targets['files']
      and intent['owned_directories']==targets['directories']and intent['owned_targets']==driver.TARGETS
      and intent['preserved_original_map']==pin(mraw)and intent['fresh_preflight_original_count']==192
      and intent['fresh_preflight_inventory']==pin(members['PRE-INVENTORY.json'])
      and intent['automatic_retry']is False and intent['native_task_replay']is False
      and intent['original_lease_modified']is False and intent['nonce_reused']is False,'durable exact intent before removals')
    need(intent['owned_file_families']=={'private_stage':62,'gnu_transport':2,'android_upload':2,'sender_xml':11}
      and intent['sender_xml_command_originals']==cap.SENDER_XML_ORIGINALS
      and intent['sender_xml_parent_before']==selected_xml_parent
      and intent['xml_parent_timestamp_transition']==xml_proof['transition']
      and intent['previous_cleanup']==cap.PRIOR_CLEANUP
      and intent['selected_component_head']==q['native_boundaries'][0]
      and intent['retained_inventory']==cap.CURRENT_INVENTORY,
      'durable typed77 ownership and separate historical44/two old audits')
    audits=strict(members['AUDIT-ORIGINALS.json'])
    need(audits['schema']=='hepta.owned-unstarted-stage.actual-audit-originals.v1'
      and len(audits['files'])==2 and audits['files']==packet['audit_originals']
      and audits['outside_complete44_inventory']is True and audits['old_inventory_not_claimed_to_cover_all_phone_files']is True,
      'two actual new audit originals explicitly outside44, prior two untouched')
    for row,raw,path in zip(audits['files'],(intent_raw,result_raw),(driver.INTENT,driver.RESULT)):
        need(set(row)=={'path','bytes','sha256','metadata','selinux_raw_b64'}and row['path']==str(path)
          and pin2(row)==pin(raw),'exact full audit original bytes')
        m=full9(row['metadata']);need(stat.S_ISREG(m[2])and stat.S_IMODE(m[2])==0o600
          and m[3:6]==[0,0,1]and m[6]==len(raw)and decoded(row['selinux_raw_b64'],512)==STATE_LABEL,
          'actual root600 singlelink state_file audit')
    need(result['schema']=='hepta.owned-unstarted-stage.cleanup-current44-phone-result.v2'
      and result['state']=='EXACT_OWNED_UNSTARTED_STAGE_REMOVED'and result['scope']==b['scope']
      and result['source']==DRIVER and result['binding']==pin(bound)and result['intent']==audits['files'][0]
      and result['preservation_manifest']==b['preservation_manifest']==inputs['preservation_manifest']
      and result['host_verification']==b['host_verification']==inputs['preservation_host_verification']
      and result['removed_files']==77 and result['removed_directories']==9
      and result['pre_inventory_original']==pin(members['PRE-INVENTORY.json'])
      and result['pre_observations_original']==pin(members['PRE-OBSERVATIONS.json'])
      and result['after_inventory']==afterinv and result['post_observations']==post
      and result['xml_parent_timestamp_transition']==xml_proof['transition'],'actual complete original cleanup result')
    states=verify_removals(core,driver,targets,result['removed'],xml_parent=selected_xml_parent)
    need(post['schema']=='hepta.owned-unstarted-stage.post-cleanup-current44-observations.v1'and post['scope']==b['scope']
      and post['all40_role_generations']==roles and post['native_identity']['identity']==pre['native_identity']['identity']
      and post['native_identity']['argv_sha256']==pre['native_identity']['argv_sha256'],'same actual observer and complete post scope')
    observations(core,post,roles,post['native_identity'])
    previous_cleanup_observations(core,cap,post['previous_cleanup_observations'])
    paths=targets['fresh_required_absence_after_cleanup']
    need(paths==post['fresh_required_absence_paths']==packet['fresh_required_absence_paths']
      ==driver.exact_absence_paths(cap)and len(paths)==18,'same exact seven scope plus eleven XML absence paths')
    original_absence(post['absent_before'],paths);original_absence(post['absent_after'],paths)
    for row in post['retained_final02_fixture_absence']:original_absence([row],[retained.FIXTURE])
    need(len(post['retained_final02_fixture_absence'])==2,'two retained fixture observations')
    need(late.inventory_value(afterinv)==late.inventory_value(prior)and len(afterinv['roots'])==44
      and retained.validate_private_preservation(summary,afterinv,validate_inventory=late.inventory_value)is True,
      'actual complete44 comparison view and all old retained private entries unchanged')
    need(post['inventory']==pin(members['AFTER-INVENTORY.json'])==packet['after_inventory']
      and post['retained_inventory']==pin(prior_raw)
      and post['historical_retained41_inventory']==pin(summary['inventory_raw'])
      and post['selected_component_head']==q['native_boundaries'][0]
      and packet['post_observations']==pin(members['POST-OBSERVATIONS.json']),'raw inventory and observation pins')
    profiles=post['retained_stage_parent_profiles']
    need(profiles==late.retained_stage_parent_profiles(summary,prior,profiles['before'],profiles['after'])
      and profiles['allowed_new_homes']==[str(driver.HOME.parent/'root-r10-neg01-a1055-final04')],
      'actual shared parents preserve only the complete qualified NEG01 prefix with fresh full9')
    shared=states[str(driver.HOME.parent)]
    need(profiles['after']['gnu']==shared,'last physical home removal agrees with final shared parent')
    for alias in ('gnu','android'):
        need(profiles['before'][alias]==profiles['after'][alias],'two actual shared parent bookends')
    need(post['same14_lock_open_descriptions']==pre['locks_after'],'same14 locked original inodes through after phase')
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
    xp=selected_xml_parent;xa=states[xp['path']]
    need(result['sender_xml_parent_before']==xp and result['sender_xml_parent_after']==xa
      and result['sender_xml_original_count']==11 and result['sender_xml_scope_not_claimed_by_inventory_count']is True
      and xa['metadata'][:6]==xp['metadata'][:6]and xa['selinux_raw_b64']==xp['selinux_raw_b64']
      and xa['names']==sorted(set(xp['names'])-{Path(r['path']).name for r in cap.SENDER_XML_ORIGINALS}),
      'complete original XML parent only loses these eleven owned names')
    for sample in (post['absent_before'],post['absent_after']):
        for row in sample:
            if row['path']in {r['path']for r in cap.SENDER_XML_ORIGINALS}:
                need(row['parent_metadata']==xa['metadata']and row['parent_selinux_raw_b64']==xa['selinux_raw_b64'],
                  'each XML actual ENOENT observes final unchanged exact parent full9/label')
    need(result['selected_component_head']==q['native_boundaries'][0]
      and result['retained_inventory']==cap.CURRENT_INVENTORY and result['previous_cleanup']==cap.PRIOR_CLEANUP,
      'result preserves selected native head and old audit family explicitly')
    foreign=verify_foreign_cleanup_originals(core,cap,q,priorproof,raw_by_path,pre,post,intent,result,packet,members,states)
    budget=verify_complete_output_budget(driver,cap,b,prior,intent,result,packet,packet_raw,members,compressed,foreign)
    for k in ('new_native_case_count','new_component_role_generation_count','new_fixture_count','fixed19_credit'):
        need(result[k]==post[k]==packet[k]==0,'cleanup gives no new native/role/fixture/case credit')
    need(result['old_final02_untouched']is True and result['prior_final02_original_sender_wait']==post['prior_final02_original_sender_wait']=='UNKNOWN_UNCHANGED'
      and post['no_original_wait_reconstructed']is True and result['whole_deadline_seconds']==45
      and 0<=result['elapsed_before_result_seconds']<45 and result['automatic_retry']is False,
      'original deadlines, old unknown wait and one-use scope preserved')
    for key in ('policy_changes','native_submissions','model_requests','ui_actions'):need(post[key]==0,'no business or policy action')
    for row in list(book.values()):read(row)
    closed={'schema':'hepta.native-guard.owned-unstarted-stage-cleanup-current44.v2',
      'state':'VERIFIED_OWNED_UNSTARTED_STAGE_CLEANUP','consumed_nonce':driver.NONCE,'boot_id':driver.BOOT,
      'original_scope':b['scope'],'cleanup_source':inputs['cleanup_source'],'cleanup_bound_request':inputs['bound_request'],
      'actual_root_job_id':job_id,'actual_operation':inputs['actor_result'],'actual_archive':inputs['packet_archive'],
      'preservation_manifest':inputs['preservation_manifest'],'host_verification':inputs['preservation_host_verification'],
      'retained_stage_closure':inputs['retained_stage_closure'],
      'after_inventory':original_members['AFTER-INVENTORY.json'],'retained_inventory':pin(prior_raw),
      'selected_component_head':q['native_boundaries'][0],
      'previous_cleanup_closure':inputs['previous_cleanup_closure'],
      'previous_audit_originals':cap.PRIOR_CLEANUP['audit_originals'],
      'sender_original_wait':priorproof['sender_original_wait'],
      'post_observations':original_members['POST-OBSERVATIONS.json'],
      'cleanup_intent':original_members['CLEANUP-INTENT.original.json'],'cleanup_result':original_members['CLEANUP-RESULT.original.json'],
      'retained_stage_parent_profiles':profiles,'fresh_required_absence_paths':paths,
      'audit_originals':audits['files'],'audit_scope_parent_profiles':ap,
      'foreign_retained_scope':foreign['scope'],'foreign_retained_bookends':foreign['bookends'],
      'pre_mutation_output_budget':budget,'final_read_accounting':foreign['final_accounting'],
      'audit_scope_explicitly_additional_to44':True,'removed_files':77,'removed_directories':9,
      'removed_sender_xml_files':11,'sender_xml_parent_before':xp,'sender_xml_parent_after':xa,
      'xml_parent_timestamp_transition':xml_proof['transition'],
      'xml_parent_transition_verifier_source':inputs['xml_parent_transition_verifier_source'],
      'xml_parent_transition_inputs':inputs['xml_parent_transition_inputs'],
      'new_native_case_count':0,'new_component_role_generation_count':0,'new_fixture_count':0,'fixed19_credit':0,
      'old_final02_original_sender_wait':'UNKNOWN_UNCHANGED','no_original_wait_reconstructed':True,
      'post_cleanup_fresh_current44_admission_required':True}
    return {'closure_value':closed,'closure_raw':enc(closed),'after_inventory_raw':members['AFTER-INVENTORY.json'],
      'after_inventory_value':late.inventory_value(afterinv),'audit_result_raw':result_raw,'audit_intent_raw':intent_raw,
      'originals':list(book.values()),'retained_inventory_raw':prior_raw}
def verify_owned_unstarted_stage_cleanup(inputs_raw,*,read_pinned):
    require_actual_binding()
    inputs=strict(inputs_raw)
    need(set(inputs)=={'schema','execution_inputs','closure'}
      and inputs['schema']=='hepta.owned-unstarted-stage.cleanup-current44-verification-inputs.v2','exact immutable cleanup consumer inputs')
    execution=exact3(inputs['execution_inputs']);closure=exact3(inputs['closure'])
    eraw=read_pinned(execution);craw=read_pinned(closure)
    need(pin(eraw)==pin2(execution)and pin(craw)==pin2(closure),'complete exact cleanup input and closure originals')
    value=verify_cleanup_execution(eraw,read_pinned=read_pinned)
    need(craw==value['closure_raw'],'closure is exactly independently reconstructed original evidence, not supplied PASS flags')
    need(read_pinned(execution)==eraw and read_pinned(closure)==craw,'consumer original bookends')
    c=value['closure_value']
    return {'schema':'hepta.native-guard.owned-unstarted-stage-cleanup-current44-verification.v2',
      'state':'VERIFIED_OWNED_UNSTARTED_STAGE_CLEANUP','consumed_nonce':c['consumed_nonce'],'boot_id':c['boot_id'],
      'closure':closure,'after_inventory':c['after_inventory'],'retained_inventory':c['retained_inventory'],
      'selected_component_head':c['selected_component_head'],
      'previous_cleanup_closure':c['previous_cleanup_closure'],'previous_audit_originals':c['previous_audit_originals'],
      'sender_original_wait':c['sender_original_wait'],
      'xml_parent_timestamp_transition':c['xml_parent_timestamp_transition'],
      'xml_parent_transition_verifier_source':c['xml_parent_transition_verifier_source'],
      'xml_parent_transition_inputs':c['xml_parent_transition_inputs'],
      'after_inventory_raw':value['after_inventory_raw'],'after_inventory_value':value['after_inventory_value'],
      'original_scope':c['original_scope'],'retained_stage_parent_profiles':c['retained_stage_parent_profiles'],
      'fresh_required_absence_paths':c['fresh_required_absence_paths'],'audit_originals':c['audit_originals'],
      'audit_scope_parent_profiles':c['audit_scope_parent_profiles'],'preservation_manifest':c['preservation_manifest'],
      'foreign_retained_scope':c['foreign_retained_scope'],'foreign_retained_bookends':c['foreign_retained_bookends'],
      'pre_mutation_output_budget':c['pre_mutation_output_budget'],'final_read_accounting':c['final_read_accounting'],
      'host_verification':c['host_verification'],'retained_stage_closure':c['retained_stage_closure'],
      'new_native_case_count':0,'new_component_role_generation_count':0,'new_fixture_count':0,
      'fixed19_credit':0,'old_final02_original_sender_wait':'UNKNOWN_UNCHANGED',
      'post_cleanup_fresh_current44_admission_required':True}
if __name__=='__main__':
    raise SystemExit('Pure verification API only; exact actual execution originals are required.')
