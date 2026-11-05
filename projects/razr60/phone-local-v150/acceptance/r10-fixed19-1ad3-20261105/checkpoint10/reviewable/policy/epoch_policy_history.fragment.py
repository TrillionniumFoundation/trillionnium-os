# New, explicit pure history authority. The original ProcView is unchanged.
import hashlib as _ehp_hashlib
import json as _ehp_json
import math as _ehp_math
from pathlib import PurePosixPath as _EhpPath
import re as _ehp_re
import stat as _ehp_stat

EPOCH_POLICY_HISTORY_AUTHORITY_BINDING = None
EPOCH_POLICY_HISTORY_INPUT_FIELDS = ('schema','epoch_id','original_adoption','actual_export',
    'full_rule','root_scope_decision','reconciliation','authority','originals')
EPOCH_POLICY_HISTORY_RESULT_FIELDS = ('schema','state','input','original_adoption',
    'policy_transition','authority','used_originals')
EPOCH_POLICY_HISTORY_AUTHORITY_FIELDS = ('schema','state','packet','reconciliation','sources','readset')
EPOCH_POLICY_HISTORY_ROLES = ('auditor_source','caller_source','source_manifest','original_verifier_source',
    'controller_request','controller_start','controller_status','controller_read','controller_stdout','controller_stderr',
    'caller_sources','caller_result','child_intent','child_identity','child_result','child_capture','child_stdout','child_stderr',
    'audit_intent','audit_readset','policy_summary','audit_result','parent_names_before','parent_names_after')
_EHP_BASE = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
_EHP_SOURCE = _EHP_BASE+'/epoch-policy-history-audit-source-1ad3-02'
_EHP_CALLER_OUT = _EHP_BASE+'/epoch-policy-history-audit-owned-1ad3-02'
_EHP_AUDIT_OUT = _EHP_BASE+'/epoch-policy-history-audit-1ad3-02'
_EHP_PHASE = 'policy-history-audit'
_EHP_BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
_EHP_ADOPTION = {'path':_EHP_BASE+'/policy-runtime-properties-r10-live-02/POLICY-ADOPTION.json',
    'bytes':208226,'sha256':'527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'}
_EHP_SOURCE_PINS = {
 'auditor_source':{'path':_EHP_SOURCE+'/audit_policy_history_once.py','bytes':30469,
   'sha256':'d36554cbcaff99458a6333e2282d78e10e53b0ba5723b98ee731df55e0677225'},
 'caller_source':{'path':_EHP_SOURCE+'/run_policy_history_owned_once.py','bytes':54438,
   'sha256':'334a036241b1fc313a9a16b0930a616bebc2ffcc7f8a7708f45ee5494ac7803d'},
 'source_manifest':{'path':_EHP_SOURCE+'/SOURCE-MANIFEST.json','bytes':582,
   'sha256':'688af2c7bf1bb177f3cf6305116d4f8a1a5eff53c461db4238ad9be192f28d9d'},
 'original_verifier_source':{'path':_EHP_BASE+'/policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/source/policy_runtime_properties_verifier.py',
   'bytes':126796,'sha256':'74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}}
_EHP_LIMITS = {'seconds':90,'original_paths':555,'original_unique_bytes':33554432,
    'physical_read_bytes':67108864,'file_bytes':16777216,'source_bytes':131072,
    'parent_depth':48,'directory_observations':2048,'owned_fds':64,'output_total_bytes':1572864,
    'readset_bytes':1048576,'policy_summary_bytes':65536,'intent_bytes':32768,
    'result_bytes':32768,'failure_bytes':32768,'stdout_bytes':65536}
_EHP_EXPECTED_SUMMARY = {'current_adoption_sha256':_EHP_ADOPTION['sha256'],
    'runtime_policy':{'bytes':2667740,'sha256':'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'},
    'retirement_sha256':'b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90',
    'prior_boundary_sha256':'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
    'root_scope_decision_sha256':'5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132',
    'parent_adoption_sha256':'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
    'verification_original_count':554,'verification_original_bytes':31518321,
    'service_start_admitted':False,'component_qualified':False,'phone_calls':0,'policy_writes':0}
_EHP_CONTROLLER_REQUEST = {'host':'mac','executable':'/usr/bin/python3',
    'args':['-I','-B',_EHP_SOURCE+'/run_policy_history_owned_once.py','--source-manifest-sha256',
            _EHP_SOURCE_PINS['source_manifest']['sha256'],'--execute-fixed-owned-history-once'],
    'cwd':_EHP_BASE,'timeout_seconds':150,'idempotency_key':'root-1ad3-policy-history-audit-owned02-20261105'}
_EHP_ARGV = ['/usr/bin/python3','-I','-B',_EHP_SOURCE+'/audit_policy_history_once.py','--execute-fixed-history-audit-once']
_EHP_META_KEYS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def _ehp_need(condition, reason):
    if not condition:
        raise ValueError('epoch policy history: '+reason)


def _ehp_encode(value):
    return (_ehp_json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')


def _ehp_equal(left,right):
    return _ehp_encode(left)==_ehp_encode(right)


def _ehp_strict(raw,maximum=16777216):
    _ehp_need(type(raw) is bytes and 0<len(raw)<=maximum,'bounded complete JSON original required')
    def pairs(items):
        result={}
        for key,value in items:
            _ehp_need(type(key) is str and key not in result,'duplicate JSON field')
            result[key]=value
        return result
    return _ehp_json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pairs,
        parse_constant=lambda _: _ehp_need(False,'nonfinite JSON value'))


def _ehp_bare(raw):
    _ehp_need(type(raw) is bytes,'whole original body required')
    return {'bytes':len(raw),'sha256':_ehp_hashlib.sha256(raw).hexdigest()}


def _ehp_keys(value,keys,reason):
    _ehp_need(type(value) is dict and set(value)==set(keys),reason)
    return value


def _ehp_descriptor(value):
    _ehp_keys(value,('path','bytes','sha256'),'exact3 original descriptor required')
    path=value['path']
    _ehp_need(type(path) is str and path.startswith('/') and '\x00' not in path
        and str(_EhpPath(path))==path and '..' not in _EhpPath(path).parts
        and len(path.encode())<=4096,'canonical original path required')
    _ehp_need(type(value['bytes']) is int and 0<=value['bytes']<=16777216
        and type(value['sha256']) is str and _ehp_re.fullmatch('[0-9a-f]{64}',value['sha256']),
        'bounded typed original size/SHA required')
    return value


def _ehp_original(value):
    return _ehp_descriptor({key:value[key] for key in ('path','bytes','sha256')})


def _ehp_metadata(value,*,size=None,directory=False):
    _ehp_need(type(value) is list and len(value)==9 and all(type(x) is int and x>=0 for x in value),
        'complete actual host full9 required')
    _ehp_need((_ehp_stat.S_ISDIR(value[2]) if directory else _ehp_stat.S_ISREG(value[2]))
        and value[0]>0 and value[1]>0,'actual original metadata type differs')
    if not directory:
        _ehp_need(value[5]==1 and value[3]==501 and not _ehp_stat.S_IMODE(value[2])&0o022,
            'actual Mac original private identity differs')
    if size is not None:_ehp_need(value[6]==size,'full9 size differs from complete body')
    return value


def _ehp_full4(value,original):
    _ehp_keys(value,('path','bytes','sha256','metadata'),'exact4 original observation required')
    _ehp_need(_ehp_equal(_ehp_original(value),original),'actual original path/bytes/SHA differs')
    _ehp_metadata(value['metadata'],size=original['bytes'])
    return value


def _ehp_flags(value,*,true=(),false=(),zero=()):
    for key in true:_ehp_need(value[key] is True,'true actual field required: '+key)
    for key in false:_ehp_need(value[key] is False,'false boundary field required: '+key)
    for key in zero:_ehp_need(type(value[key]) is int and value[key]==0,'strict zero required: '+key)


def _ehp_native(raw):
    outer=_ehp_strict(raw,1048576)
    _ehp_need(type(outer) is dict and outer.get('isError') is False
        and type(outer.get('content')) is list and len(outer['content'])==1,
        'complete successful native tool envelope required')
    item=outer['content'][0]
    _ehp_need(type(item) is dict and item.get('type')=='text' and type(item.get('text')) is str,
        'one native JSON body required')
    value=_ehp_strict(item['text'].encode(),524288)
    _ehp_need(type(value) is dict,'native result object required')
    return value


def _ehp_sources(roles,raws):
    for name,pin in _EHP_SOURCE_PINS.items():
        _ehp_need(_ehp_equal(roles[name],pin),'independent fixed source identity differs: '+name)
    manifest=_ehp_strict(raws['source_manifest'],65536)
    _ehp_keys(manifest,('schema','target_root','files'),'actual source manifest shape differs')
    expected=[]
    for role in ('auditor_source','caller_source'):
        row=_EHP_SOURCE_PINS[role]
        expected.append({'path':_EhpPath(row['path']).name,'bytes':row['bytes'],'sha256':row['sha256']})
    _ehp_need(manifest['schema']=='hepta.native-guard.policy-history-owned-source.v1'
        and manifest['target_root']==_EHP_SOURCE and _ehp_equal(manifest['files'],expected),
        'actual whole two-source manifest differs')
    return sorted((_EHP_SOURCE_PINS[name] for name in _EHP_SOURCE_PINS),key=lambda row:row['path'])


def _ehp_controller(binding,roles,raws):
    request=_ehp_strict(raws['controller_request'],65536)
    _ehp_need(_ehp_equal(request,_EHP_CONTROLLER_REQUEST),'actual fixed controller request differs')
    start=_ehp_native(raws['controller_start']);status=_ehp_native(raws['controller_status'])
    read=_ehp_native(raws['controller_read']);job=start['job'];job_id=binding['controller_job_id']
    _ehp_need(type(job_id) is str and _ehp_re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+',job_id),
        'fixed actual native controller job ID required')
    _ehp_flags(start,true=('audit_recorded',),false=('local_record_pending','reused'))
    _ehp_need(start['launch']['ok'] is True and job['id']==job_id
        and job['launch_state']=='launched' and job['launch_error'] is None and job['env_keys']==[],
        'controller actual launch identity differs')
    for key in ('host','executable','args','cwd','idempotency_key'):
        _ehp_need(_ehp_equal(job[key],request[key]),'actual controller source/action differs: '+key)
    _ehp_need(status['job_id']==job_id and status['state']=='succeeded'
        and type(status['exit_code']) is int and status['exit_code']==0
        and read['job_id']==job_id,'same actual controller successful terminal required')
    _ehp_flags(status,true=('audit_recorded','output_complete','output_durable','terminal_publication_confirmed'),
        false=('automatic_retry','cancelled','timed_out'))
    _ehp_need(type(status['terminal_publication_protocol']) is int
        and status['terminal_publication_protocol']==1,'actual terminal protocol differs')
    _ehp_flags(read,true=('audit_recorded',))
    for stream in ('stdout','stderr'):
        row=read[stream];raw=raws['controller_'+stream]
        _ehp_need(type(row) is dict and type(row['bytes_hex']) is str
            and row['bytes_hex']==raw.hex() and row['eof'] is True,'complete controller stream differs')
        for key,want in (('offset',0),('next_offset',len(raw)),('size',len(raw))):
            _ehp_need(type(row[key]) is int and row[key]==want,'controller stream offset/EOF differs')
        _ehp_need(_ehp_equal(status['log_bytes'][stream],{'seen':len(raw),'stored':len(raw)})
            and status['log_errors'][stream] is None and status['log_synced'][stream] is True
            and status['log_truncated'][stream] is False,'controller complete/durable stream differs')
    _ehp_need(raws['controller_stderr']==b'' and len(raws['controller_stdout'])<=65536,
        'successful fixed caller bounded stdout and empty stderr required')
    final=_ehp_strict(raws['controller_stdout'],65536)
    _ehp_need(final['schema']=='hepta.native-guard.policy-history-owned-caller-summary.v1'
        and final['state']=='OWNED_AUDITOR_JOINED_ALL_ORIGINALS_RETAINED_AND_CALLER_FDS_CLOSED'
        and _ehp_equal(final['caller_result'],roles['caller_result']),
        'actual caller final output does not bind its complete result')
    _ehp_flags(final,true=('external_controller_originals_still_required',),
        false=('automatic_retry','case_pass'),zero=('signals_sent','phone_calls'))
    _ehp_need(type(final['actual_child_starts']) is int and final['actual_child_starts']==1,
        'exactly one actual owned child required')
    return final


def _ehp_child(roles,raws):
    intent=_ehp_strict(raws['child_intent'],65536);child=_ehp_strict(raws['child_identity'],65536)
    capture=_ehp_strict(raws['child_capture'],65536);result=_ehp_strict(raws['child_result'],65536)
    expected={'schema':'hepta.native-guard.root-host-command.v1','phase':_EHP_PHASE,'argv':_EHP_ARGV,
        'stdin_sha256':None,'maximum_starts':1,'maximum_wait_seconds':100,'automatic_retry':False,
        'signals_on_timeout':False,'deadline_scope':'popen_start_through_child_join_pipe_eof_and_output_verification',
        'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
        'output_transport':'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
        'output_limit_bytes_per_stream':65536,'hard_bound_on_filesystem_spawn_or_cleanup':False}
    _ehp_need(_ehp_equal(intent,expected),'actual 0374 fixed intent differs')
    intent_sha=_ehp_bare(raws['child_intent'])['sha256']
    _ehp_need(type(child['pid']) is int and child['pid']>1
        and all(type(child[k]) is int and child[k]==child['pid'] for k in ('pgid','sid'))
        and child['source_intent_sha256']==intent_sha and child['maximum_starts']==1
        and type(child['maximum_starts']) is int
        and child['identity_missing_only_if_actual_child_already_joined'] is False,
        'actual owned child process generation differs')
    _ehp_need(capture['schema']=='hepta.native-guard.host-output-capture.v1'
        and capture['phase']==_EHP_PHASE and type(capture['pid']) is int and capture['pid']==child['pid']
        and capture['source_intent_sha256']==intent_sha
        and capture['pipe_reader_owner']=='closed_by_worker'
        and type(capture['output_limit_bytes_per_stream']) is int and capture['output_limit_bytes_per_stream']==65536,
        'actual bounded owned output capture identity differs')
    _ehp_flags(capture,true=('worker_started','worker_joined','child_wait_returned','stdout_eof','stderr_eof'),
        false=('prefix_only_or_unknown','automatic_retry','remote_terminal_or_cleanup_proven'),
        zero=('child_returncode','signals_sent'))
    _ehp_need(capture['error'] is None and capture['persist_errors']==[] and capture['pipe_close_errors']==[],
        'capture has unresolved output/cleanup errors')
    deadline=capture['execution_deadline_monotonic']
    _ehp_need(type(deadline) in (int,float) and _ehp_math.isfinite(deadline) and deadline>0
        and _ehp_equal(deadline,child['execution_deadline_monotonic'])
        and capture['deadline_validity']=='this_running_coordinator_only'
        and child['deadline_validity']=='this_running_coordinator_only','owned deadline binding differs')
    for value in (capture['child_join_observed_monotonic'],*capture['eof_observed_monotonic'].values()):
        _ehp_need(type(value) in (int,float) and _ehp_math.isfinite(value) and 0<value<=deadline,
            'actual join and EOF must complete within their original deadline')
    for stream in ('stdout','stderr'):
        raw=raws['child_'+stream];file=capture['files'][stream]
        _ehp_need(len(raw)<=65536 and _ehp_equal(capture['captured'][stream],_ehp_bare(raw))
            and _ehp_equal(_ehp_original(file),roles['child_'+stream])
            and file['original_created_inode_bound'] is True,'complete held-inode child stream differs')
        _ehp_keys(file['metadata'],_EHP_META_KEYS,'captured stream full9 shape differs')
        meta=[file['metadata'][k] for k in _EHP_META_KEYS];_ehp_metadata(meta,size=len(raw))
        initial=child['original_output_identities'][stream]
        _ehp_keys(initial,_EHP_META_KEYS,'original created stream metadata differs')
        before=[initial[k] for k in _EHP_META_KEYS];_ehp_metadata(before,size=0)
        _ehp_need(before[:6]==meta[:6] and _ehp_stat.S_IMODE(meta[2])==0o600,
            'created output inode/owner/mode changed')
    _ehp_need(raws['child_stderr']==b'' and result['state']=='ORIGINAL_HOST_CHILD_JOINED'
        and result['phase']==_EHP_PHASE and type(result['pid']) is int and result['pid']==child['pid']
        and type(result['returncode']) is int and result['returncode']==0
        and result['automatic_retry'] is False
        and _ehp_equal(result['stdout'],roles['child_stdout'])
        and _ehp_equal(result['stderr'],roles['child_stderr']),'actual original child result differs')
    return _ehp_strict(raws['child_stdout'],65536)


def _ehp_parent_rows(rows,path):
    _ehp_need(type(rows) is list and 1<=len(rows)<=24,'bounded complete parent sequence required')
    expected=list(reversed([str(p) for p in _EhpPath(path).parents]))
    _ehp_need([r['path'] for r in rows]==expected,'parent sequence differs from actual source path')
    for row in rows:
        _ehp_keys(row,('path','metadata'),'parent observation shape differs')
        _ehp_metadata(row['metadata'],directory=True)


def _ehp_caller(roles,raws,controller_final):
    caller=_ehp_strict(raws['caller_result'],65536)
    sources=_ehp_strict(raws['caller_sources'],262144)
    _ehp_need(caller['schema']=='hepta.native-guard.policy-history-owned-caller.v1'
        and caller['state']=='FIXED_AUDITOR_CHILD_JOINED_AND_COMPLETE_OUTPUTS_RECHECKED'
        and _ehp_equal(caller['source_manifest'],roles['source_manifest'])
        and _ehp_equal(caller['sources'],{'audit_policy_history_once.py':roles['auditor_source'],
            'run_policy_history_owned_once.py':roles['caller_source']})
        and _ehp_equal(caller['argv'],_EHP_ARGV) and caller['phase']==_EHP_PHASE,
        'actual caller source/action fields differ')
    for key,role in (('child','child_identity'),('result','child_result'),('joined','child_result'),
                     ('output_capture','child_capture'),('stdout','child_stdout'),('stderr','child_stderr'),
                     ('source_observations','caller_sources')):
        _ehp_need(_ehp_equal(caller[key],roles[role]),'caller source/action original differs: '+key)
    _ehp_flags(caller,true=('no_parent_all_time_full9_stability_claim','controller_authority_still_required'),
        false=('new_nonce_or_lease','component_qualified','business_qualified','automatic_retry'),
        zero=('phone_calls','signals_sent'))
    _ehp_need(_ehp_equal(caller['cleanup'],{'stream_cleanup_errors':[],'host_children':[]})
        and _ehp_equal(controller_final['owned_host_cleanup'],caller['cleanup']),
        'actual owned caller cleanup differs')
    for key,want in (('physical_read_limit',16777216),('metadata_limit',524288),('stream_pool_limit',262144)):
        _ehp_need(type(caller[key]) is int and caller[key]==want,'caller fixed bound differs')
    for key in ('read_bytes','capture_read_bytes_reserved','physical_read_total_upper','metadata_bytes','stream_write_bytes_reserved',
                'parent_names_decoded_bytes','metadata_total_charged_bytes'):
        _ehp_need(type(controller_final[key]) is int and controller_final[key]>=0,'caller resource counter type differs')
    _ehp_need(controller_final['read_bytes']+controller_final['capture_read_bytes_reserved']+controller_final['parent_names_decoded_bytes']==
        controller_final['physical_read_total_upper']<=16777216
        and controller_final['capture_read_bytes_reserved']<=262148
        and controller_final['metadata_bytes']+controller_final['parent_names_decoded_bytes']==
        controller_final['metadata_total_charged_bytes']<=524288
        and controller_final['stream_write_bytes_reserved']<=262144,
        'caller actual read/write bounds exceeded')
    _ehp_keys(sources,('schema','source_manifest','sources','parent_transition','audit_outputs',
        'self_report_is_not_source_authority'),'complete caller source observations differ')
    _ehp_need(sources['schema']=='hepta.native-guard.policy-history-caller-sources.v1'
        and sources['self_report_is_not_source_authority'] is True,'source observation scope differs')
    _ehp_keys(sources['sources'],('audit_policy_history_once.py','run_policy_history_owned_once.py'),
        'caller did not retain both source observations')
    for record,role in ((sources['source_manifest'],'source_manifest'),
        (sources['sources']['audit_policy_history_once.py'],'auditor_source'),
        (sources['sources']['run_policy_history_owned_once.py'],'caller_source')):
        _ehp_keys(record,('path','bytes','sha256','metadata','parents'),'actual source read shape differs')
        _ehp_full4({k:record[k] for k in ('path','bytes','sha256','metadata')},roles[role])
        _ehp_parent_rows(record['parents'],record['path'])
    transition=sources['parent_transition']
    _ehp_keys(transition,('schema','before','after','allowed_created_directory',
        'ordinary_ancestors_full9_equal','base_first5_equal','base_all_time_full9_stable_claim',
        'only_declared_name_added'),'caller parent transition shape differs')
    _ehp_need(transition['schema']=='hepta.native-guard.policy-history-caller-parent-transition.v1'
        and transition['allowed_created_directory']==_EHP_AUDIT_OUT,'caller owned directory addition differs')
    _ehp_flags(transition,true=('ordinary_ancestors_full9_equal','base_first5_equal','only_declared_name_added'),
        false=('base_all_time_full9_stable_claim',))
    before=transition['before'];after=transition['after']
    decoded_names=[]
    for row,role in ((before,'parent_names_before'),(after,'parent_names_after')):
        _ehp_keys(row,('parents','base_names'),'BASE observation shape differs')
        _ehp_parent_rows(row['parents'],roles['caller_source']['path'])
        names=_ehp_names_decode(row['base_names'])
        _ehp_need(raws[role]==_ehp_names_wire(names),
            'explicit derived carrier differs from the complete actual parent names')
        decoded_names.append(names)
    for left,right in zip(before['parents'],after['parents']):
        _ehp_need(left['path']==right['path'],'parent path changed')
        _ehp_need(_ehp_equal(left['metadata'][:5],right['metadata'][:5]) if left['path']==_EHP_BASE
            else _ehp_equal(left,right),'unapproved source ancestor changed')
    name=_EhpPath(_EHP_AUDIT_OUT).name
    _ehp_need(name not in decoded_names[0] and decoded_names[1]==sorted(decoded_names[0]+[name]),
        'undeclared BASE additions or removals occurred')
    decoded_charge=len(raws['parent_names_before'])+len(raws['parent_names_after'])
    _ehp_need(type(caller['parent_names_decoded_bytes']) is int
        and caller['parent_names_decoded_bytes']==controller_final['parent_names_decoded_bytes']==decoded_charge
        and caller['parent_names_byte_charge_is_canonical_expanded_data_not_kernel_dirent_bytes'] is True
        and controller_final['parent_names_byte_charge_is_canonical_expanded_data_not_kernel_dirent_bytes'] is True,
        'actual complete expanded parent names were not charged to the same caller pools')
    names={'INTENT.json':'audit_intent','READSET.json':'audit_readset',
        'POLICY-SUMMARY.json':'policy_summary','RESULT.json':'audit_result'}
    _ehp_keys(sources['audit_outputs'],names,'actual four audit originals missing')
    for filename,role in names.items():
        observed=sources['audit_outputs'][filename]
        _ehp_keys(observed,('path','bytes','sha256','metadata','parents'),'caller audit output observation differs')
        _ehp_full4({k:observed[k] for k in ('path','bytes','sha256','metadata')},roles[role])
        _ehp_parent_rows(observed['parents'],observed['path'])
        _ehp_need(_ehp_equal(caller['audit_outputs'][filename],roles[role])
            and _ehp_equal(controller_final['auditor_originals'][filename],roles[role]),
            'caller final and actual audit output disagree')
    expected_members=sorted((roles[r] for r in ('caller_sources','caller_result','child_intent','child_identity',
        'child_result','child_capture','child_stdout','child_stderr')),key=lambda row:row['path'])
    _ehp_need(_ehp_equal(controller_final['originals'],expected_members),'caller exact eight-file closure differs')
    return sources


def _ehp_readset(roles,raws,adoption,sources,budget_check):
    value=_ehp_strict(raws['audit_readset'],1048576)
    _ehp_keys(value,('schema','adoption','verification_originals','directories','physical_read_bytes_through_input_rechecks',
        'unique_original_bytes','unique_original_objects','descriptor_path_bytes','original_paths','peak_owned_read_fds',
        'all_actual_reads_complete_and_bookended','all_input_fds_held_through_entire_audit','actual_source',
        'actual_context','phone_metadata_substituted','originals_modified','phone_calls','policy_writes'),
        'complete actual policy readset shape differs')
    _ehp_need(value['schema']=='hepta.native-guard.policy-history-complete-readset.v1'
        and value['actual_context']=='mac','actual complete Mac readset required')
    _ehp_flags(value,true=('all_actual_reads_complete_and_bookended',),
        false=('all_input_fds_held_through_entire_audit','phone_metadata_substituted','originals_modified'),
        zero=('phone_calls','policy_writes'))
    for key,want in (('unique_original_bytes',23893406),('unique_original_objects',332),
                     ('descriptor_path_bytes',31518321),('original_paths',555)):
        _ehp_need(type(value[key]) is int and value[key]==want,'complete original input accounting differs')
    _ehp_need(type(value['peak_owned_read_fds']) is int and 1<=value['peak_owned_read_fds']<=64,
        'actual bounded reader FD evidence differs')
    expected=adoption['verification_originals']
    _ehp_need(type(expected) is list and len(expected)==554,'original adoption complete554 input list differs')
    expected_by={};digests={}
    for row in expected:
        budget_check();_ehp_descriptor(row)
        _ehp_need(row['path'] not in expected_by and row['path'].startswith(_EHP_BASE+'/'),
            'original554 identity duplicate or outside fixed namespace')
        expected_by[row['path']]=row
        _ehp_need(row['sha256'] not in digests or digests[row['sha256']]==row['bytes'],
            'same original SHA has conflicting byte sizes')
        digests[row['sha256']]=row['bytes']
    _ehp_need(sum(row['bytes'] for row in expected)==31518321 and len(digests)==332
        and sum(digests.values())==23893406
        and _ehp_equal(expected_by[_EHP_SOURCE_PINS['original_verifier_source']['path']],
                       _EHP_SOURCE_PINS['original_verifier_source']),'full original554 domain differs')
    rows=value['verification_originals']
    _ehp_need(type(rows) is list and len(rows)==554 and
        [r['original']['path'] for r in rows]==sorted(expected_by),'readset does not enumerate the whole554 original paths')
    for row in rows:
        budget_check();_ehp_keys(row,('original','metadata_before','metadata_after',
            'physical_complete_reads','verifier_callback_reads'),'actual readset row shape differs')
        expected_row=expected_by[row['original']['path']]
        _ehp_need(_ehp_equal(row['original'],expected_row),'readset original is not the actual adoption row')
        _ehp_metadata(row['metadata_before'],size=expected_row['bytes'])
        _ehp_need(_ehp_equal(row['metadata_before'],row['metadata_after'])
            and type(row['physical_complete_reads']) is int and row['physical_complete_reads']==2
            and type(row['verifier_callback_reads']) is int and 0<row['verifier_callback_reads']<=1000000,
            'original complete read/bookend or callback consumption differs')
    old=value['adoption'];_ehp_keys(old,('original','metadata_before','metadata_after','physical_complete_reads'),
        'complete original adoption readset differs')
    _ehp_need(_ehp_equal(old['original'],_EHP_ADOPTION)
        and type(old['physical_complete_reads']) is int and old['physical_complete_reads']==2
        and _ehp_equal(old['metadata_before'],old['metadata_after']),'adoption complete bookend differs')
    _ehp_metadata(old['metadata_before'],size=208226)
    _ehp_full4(value['actual_source'],roles['auditor_source'])
    source_observed=sources['sources']['audit_policy_history_once.py']
    _ehp_need(_ehp_equal(value['actual_source']['metadata'],source_observed['metadata']),
        'auditor actual source and owned caller source identity differ')
    directories=value['directories']
    _ehp_need(type(directories) is list and len(directories)<=2048,'bounded actual directory observations required')
    expected_dirs=sorted({str(parent) for row in [*expected,_EHP_ADOPTION,roles['auditor_source']]
        for parent in _EhpPath(row['path']).parents})
    _ehp_need([d['path'] for d in directories]==expected_dirs,'readset omits or invents canonical parent observations')
    for row in directories:
        _ehp_keys(row,('path','metadata'),'readset directory shape differs');_ehp_metadata(row['metadata'],directory=True)
    expected_read=2*31518321+2*208226+3*_EHP_SOURCE_PINS['auditor_source']['bytes']+len(raws['audit_intent'])
    _ehp_need(type(value['physical_read_bytes_through_input_rechecks']) is int
        and value['physical_read_bytes_through_input_rechecks']==expected_read,
        'actual readset read counter differs from complete input/source/output copies')
    return value


def _ehp_audit(roles,raws,adoption,sources,child_summary,budget_check):
    intent=_ehp_strict(raws['audit_intent'],32768);result=_ehp_strict(raws['audit_result'],32768)
    summary=_ehp_strict(raws['policy_summary'],65536)
    readset=_ehp_readset(roles,raws,adoption,sources,budget_check)
    expected_intent={'schema':'hepta.native-guard.policy-history-host-audit-intent.v1',
        'source':readset['actual_source'],'adoption':_EHP_ADOPTION,
        'original_verifier':_EHP_SOURCE_PINS['original_verifier_source'],'out':_EHP_AUDIT_OUT,
        'argv':[_EHP_SOURCE+'/audit_policy_history_once.py','--execute-fixed-history-audit-once'],
        'limits':_EHP_LIMITS,'original_verifier_function':'verify_adoption','original_main_calls':0,
        'phone_calls':0,'policy_writes':0,'new_nonce_or_lease':False,'automatic_retry':False}
    _ehp_need(_ehp_equal(intent,expected_intent),'actual original-function invocation differs')
    _ehp_keys(result,('schema','state','source','intent','original_adoption','original_verifier','readset','policy_summary',
        'original_function_calls','original_main_calls','input_paths','verification_originals',
        'owned_input_fds_closed_after_each_bookend','external_owned_process_completion_still_required',
        'physical_read_bytes_before_result_and_final_output_rechecks','limits','elapsed_seconds',
        'phone_calls','policy_writes','case_credit','new_nonce_or_lease','fresh_phone_clearance',
        'component_qualified','business_qualified','automatic_retry'),'complete audit result shape differs')
    _ehp_need(result['schema']=='hepta.native-guard.policy-history-host-reconciliation.v1'
        and result['state']=='ORIGINAL_POLICY_ADOPTION_FUNCTION_RETURNED_AND_ALL_INPUTS_RECHECKED'
        and _ehp_equal(result['source'],readset['actual_source'])
        and _ehp_equal(result['limits'],_EHP_LIMITS),'actual original audit result identity differs')
    _ehp_flags(result,true=('owned_input_fds_closed_after_each_bookend','external_owned_process_completion_still_required'),
        false=('new_nonce_or_lease','fresh_phone_clearance','component_qualified','business_qualified','automatic_retry'),
        zero=('original_main_calls','phone_calls','policy_writes','case_credit'))
    for key,want in (('original_function_calls',1),('input_paths',555),('verification_originals',554)):
        _ehp_need(type(result[key]) is int and result[key]==want,'actual function/input count differs')
    _ehp_need(type(result['elapsed_seconds']) in (int,float) and _ehp_math.isfinite(result['elapsed_seconds'])
        and 0<=result['elapsed_seconds']<=90,'original single audit time limit differs')
    for key,role in (('intent','audit_intent'),('readset','audit_readset'),('policy_summary','policy_summary')):
        _ehp_full4(result[key],roles[role])
        filename={'intent':'INTENT.json','readset':'READSET.json','policy_summary':'POLICY-SUMMARY.json'}[key]
        _ehp_need(_ehp_equal(result[key]['metadata'],sources['audit_outputs'][filename]['metadata']),
            'actual auditor output full9 differs across caller')
    _ehp_full4(result['original_adoption'],_EHP_ADOPTION)
    _ehp_need(_ehp_equal(result['original_adoption']['metadata'],readset['adoption']['metadata_before']),
        'original adoption full9 result/readset mismatch')
    _ehp_full4(result['original_verifier'],_EHP_SOURCE_PINS['original_verifier_source'])
    verifier_row=next(r for r in readset['verification_originals'] if r['original']['path']==result['original_verifier']['path'])
    _ehp_need(_ehp_equal(result['original_verifier']['metadata'],verifier_row['metadata_before']),
        'actual old74f4 original differs from complete consumed readset')
    _ehp_need(type(summary) is dict and all(k in summary and _ehp_equal(summary[k],v)
        for k,v in _EHP_EXPECTED_SUMMARY.items()) and _ehp_equal(summary['full_rule'],adoption['full_rule'])
        and summary['current_policy_adoption']['bytes']==208226
        and summary['current_policy_adoption']['sha256']==_EHP_ADOPTION['sha256'],
        'complete original policy verifier return differs')
    before_result=readset['physical_read_bytes_through_input_rechecks']+len(raws['audit_readset'])+len(raws['policy_summary'])
    _ehp_need(type(result['physical_read_bytes_before_result_and_final_output_rechecks']) is int
        and result['physical_read_bytes_before_result_and_final_output_rechecks']==before_result,
        'actual read counter before result differs')
    _ehp_keys(child_summary,('schema','state','result','readset','policy_summary',
        'external_owned_process_completion_still_required','complete_physical_read_bytes','owned_output_bytes',
        'phone_calls','policy_writes','case_credit','new_nonce_or_lease','component_qualified'),
        'actual auditor final stdout shape differs')
    _ehp_need(child_summary['schema']=='hepta.native-guard.policy-history-host-audit-summary.v1'
        and child_summary['state']=='ORIGINAL_POLICY_HISTORY_RETAINED_AND_OWNED_HOST_FDS_CLOSED',
        'actual auditor final post-FD-close state differs')
    for key,role in (('result','audit_result'),('readset','audit_readset'),('policy_summary','policy_summary')):
        _ehp_full4(child_summary[key],roles[role])
    output_bytes=sum(len(raws[r]) for r in ('audit_intent','audit_readset','policy_summary','audit_result'))
    expected_total=2*31518321+2*208226+3*_EHP_SOURCE_PINS['auditor_source']['bytes']+2*output_bytes
    _ehp_need(type(child_summary['owned_output_bytes']) is int and child_summary['owned_output_bytes']==output_bytes<=1572864
        and type(child_summary['complete_physical_read_bytes']) is int
        and child_summary['complete_physical_read_bytes']==expected_total<=67108864,
        'actual whole audit physical read/output pool differs')
    _ehp_flags(child_summary,true=('external_owned_process_completion_still_required',),
        false=('new_nonce_or_lease','component_qualified'),zero=('phone_calls','policy_writes','case_credit'))
    return summary


def verify_epoch_policy_history(input_raw, *, read_pinned, budget_check):
    """Verify only fixed, already completed original history; perform no I/O."""
    binding=EPOCH_POLICY_HISTORY_AUTHORITY_BINDING
    _ehp_need(type(binding) is dict,'actual reviewed source/action binding is not installed')
    _ehp_keys(binding,('schema','input','authority','roles','controller_job_id'),'fixed history binding shape differs')
    _ehp_need(binding['schema']=='hepta.native-guard.policy-history-authority-source-binding.v1'
        and globals().get('__actual_context__') in ('phone','mac','p4')
        and callable(read_pinned) and callable(budget_check),'explicit reviewed context and original callbacks required')
    budget_check();_ehp_descriptor(binding['input']);_ehp_descriptor(binding['authority'])
    _ehp_need(_ehp_equal(_ehp_bare(input_raw),{k:binding['input'][k] for k in ('bytes','sha256')}),
        'actual source-bound policy history input differs')
    value=_ehp_strict(input_raw,65536);_ehp_keys(value,EPOCH_POLICY_HISTORY_INPUT_FIELDS,'history input exact9 differs')
    _ehp_need(value['schema']=='hepta.native-guard.epoch-policy-history-input.v1'
        and value['epoch_id']=='legacy902-active01','fixed policy history epoch differs')
    roles=_ehp_keys(binding['roles'],EPOCH_POLICY_HISTORY_ROLES,'complete fixed24 role map required')
    by_path={}
    for name,row in roles.items():
        _ehp_descriptor(row);_ehp_need(row['path'] not in by_path,'source/action role originals must use distinct actual paths')
        by_path[row['path']]=row
    expected_rows=sorted(by_path.values(),key=lambda row:row['path'])
    _ehp_need(_ehp_equal(value['originals'],expected_rows)
        and _ehp_equal(value['original_adoption'],_EHP_ADOPTION)
        and _ehp_equal(value['authority'],binding['authority'])
        and _ehp_equal(value['reconciliation'],roles['audit_result']),
        'history input is not the fixed actual complete source/action set')
    declared=dict(by_path)
    for key in ('original_adoption','actual_export','full_rule','root_scope_decision','reconciliation','authority'):
        row=_ehp_descriptor(value[key])
        _ehp_need(row['path'] not in declared or _ehp_equal(declared[row['path']],row),
            'conflicting duplicate original identity')
        declared[row['path']]=row
    used={};body_cache={};digest_bodies={}
    def get(row):
        budget_check();_ehp_descriptor(row);path=row['path']
        _ehp_need(path in declared and _ehp_equal(declared[path],row),'unlisted source/action original requested')
        if path not in body_cache:
            raw=read_pinned(row);budget_check()
            _ehp_need(type(raw) is bytes and _ehp_equal(_ehp_bare(raw),{k:row[k] for k in ('bytes','sha256')}),
                'complete actual source/action original bytes differ')
            if row['sha256'] in digest_bodies:
                _ehp_need(digest_bodies[row['sha256']]==raw,'same SHA reuse requires identical complete body')
            else:digest_bodies[row['sha256']]=raw
            body_cache[path]=raw;used[path]=row
        return body_cache[path]
    packet=_ehp_strict(get(value['authority']),65536)
    _ehp_keys(packet,('schema','epoch_id','roles','controller_job_id','original_adoption',
        'reconciliation','policy_summary','readset'),'fixed authority packet shape differs')
    _ehp_need(packet['schema']=='hepta.native-guard.policy-history-authority.v1'
        and packet['epoch_id']=='legacy902-active01' and _ehp_equal(packet['roles'],roles)
        and packet['controller_job_id']==binding['controller_job_id']
        and _ehp_equal(packet['original_adoption'],_EHP_ADOPTION)
        and _ehp_equal(packet['reconciliation'],roles['audit_result'])
        and _ehp_equal(packet['policy_summary'],roles['policy_summary'])
        and _ehp_equal(packet['readset'],roles['audit_readset']),'packet cannot choose source or action authority')
    raw_roles={name:get(row) for name,row in roles.items()}
    sources=_ehp_sources(roles,raw_roles)
    fixed_paths={'caller_sources':_EHP_CALLER_OUT+'/SOURCE-OBSERVATIONS.json',
        'caller_result':_EHP_CALLER_OUT+'/CALLER-RESULT.json',
        'child_intent':_EHP_CALLER_OUT+'/'+_EHP_PHASE+'/INTENT.json',
        'child_identity':_EHP_CALLER_OUT+'/'+_EHP_PHASE+'/CHILD.json',
        'child_result':_EHP_CALLER_OUT+'/'+_EHP_PHASE+'/RESULT.json',
        'child_capture':_EHP_CALLER_OUT+'/'+_EHP_PHASE+'/OUTPUT-CAPTURE.json',
        'child_stdout':_EHP_CALLER_OUT+'/'+_EHP_PHASE+'/stdout.original',
        'child_stderr':_EHP_CALLER_OUT+'/'+_EHP_PHASE+'/stderr.original',
        'audit_intent':_EHP_AUDIT_OUT+'/INTENT.json','audit_readset':_EHP_AUDIT_OUT+'/READSET.json',
        'policy_summary':_EHP_AUDIT_OUT+'/POLICY-SUMMARY.json','audit_result':_EHP_AUDIT_OUT+'/RESULT.json',
        'parent_names_before':_EHP_BASE+'/epoch-policy-history-input-1ad3-01/PARENT-NAMES-BEFORE.decoded.json',
        'parent_names_after':_EHP_BASE+'/epoch-policy-history-input-1ad3-01/PARENT-NAMES-AFTER.decoded.json'}
    _ehp_need(all(roles[k]['path']==p for k,p in fixed_paths.items()),'fixed source/action output namespace differs')
    controller_final=_ehp_controller(binding,roles,raw_roles)
    child_summary=_ehp_child(roles,raw_roles)
    source_observations=_ehp_caller(roles,raw_roles,controller_final)
    adoption=_ehp_strict(get(value['original_adoption']),208226)
    _ehp_need(adoption['schema']=='hepta.runtime-properties-r10.policy-adoption.v1'
        and adoption['boot_id']==_EHP_BOOT,'original adoption scope differs')
    for key in ('actual_export','full_rule','root_scope_decision'):
        _ehp_need(_ehp_equal(value[key],adoption[key]),'current policy input differs from original adoption: '+key)
        get(value[key])
    summary=_ehp_audit(roles,raw_roles,adoption,source_observations,child_summary,budget_check)
    budget_check();_ehp_need(set(used)==set(declared),'declared source/action original set was not completely consumed')
    authority={'schema':'hepta.native-guard.epoch-policy-history-source-action-verification.v1',
        'state':'FIXED_SOURCE_INPUTS_OWNED_EXECUTION_AND_RESULT_VERIFIED','packet':value['authority'],
        'reconciliation':value['reconciliation'],'sources':sources,'readset':roles['audit_readset']}
    return {'schema':'hepta.native-guard.epoch-policy-history-verification.v1',
        'state':'ORIGINAL_POLICY_ADOPTION_REVERIFIED_BY_OWNED_HOST_AUDIT','input':_ehp_bare(input_raw),
        'original_adoption':value['original_adoption'],'policy_transition':summary,'authority':authority,
        'used_originals':sorted(used.values(),key=lambda row:row['path'])}


def _ehp_digest(raw):
    return _ehp_bare(raw)['sha256']

# Lossless directory-name data only. It neither authorizes nor reads a path.
def _ehp_names_wire(value):
    return (_ehp_json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8','strict')


def _ehp_names_decode(value):
    _ehp_need(type(value) is dict and set(value)=={'schema','encoding','count','decoded','rows'}
        and value['schema']=='hepta.directory-name-prefix-table.v1'
        and value['encoding']=='unicode-prefix-length-and-suffix',
        'fixed parent name data encoding required')
    _ehp_need(type(value['count']) is int and 0<=value['count']<=4096
        and type(value['rows']) is list and len(value['rows'])==value['count'],
        'original name count bound exceeded')
    pin=value['decoded']
    _ehp_need(type(pin) is dict and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int
        and 3<=pin['bytes']<=524288 and type(pin['sha256']) is str
        and _ehp_re.fullmatch('[0-9a-f]{64}',pin['sha256']),
        'bounded full decoded name descriptor required')
    _ehp_need(len(_ehp_names_wire(value))<=65536,'prefix data exceeds original serialized field bound')
    names=[];previous='';decoded_charge=3
    for row in value['rows']:
        _ehp_need(type(row) is list and len(row)==2 and type(row[0]) is int
            and 0<=row[0]<=len(previous) and type(row[1]) is str,
            'typed bounded prefix/suffix row required')
        name=previous[:row[0]]+row[1]
        _ehp_need(name and '/' not in name and '\x00' not in name and name not in ('.','..')
            and (not names or previous<name),'complete names must be strict sorted unique basenames')
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        _ehp_need(row[0]==common,'prefix length must be canonical maximal common prefix')
        decoded_charge+=len(_ehp_names_wire(name))-1+(1 if names else 0)
        _ehp_need(decoded_charge<=pin['bytes']<=524288,'decoded names exceed bounded original bytes')
        names.append(name);previous=name
    raw=_ehp_names_wire(names)
    _ehp_need(len(raw)==pin['bytes'] and _ehp_digest(raw)==pin['sha256'],'complete decoded names bytes/SHA differ')
    return names


def _ehp_names_encode(names):
    _ehp_need(type(names) is list and len(names)<=4096 and all(type(x) is str for x in names)
        and names==sorted(set(names)),'original complete name count/order differs')
    raw=_ehp_names_wire(names)
    _ehp_need(len(raw)<=524288,'complete decoded parent names exceed the shared metadata pool')
    rows=[];previous=''
    for name in names:
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        rows.append([common,name[common:]]);previous=name
    value={'schema':'hepta.directory-name-prefix-table.v1','encoding':'unicode-prefix-length-and-suffix',
        'count':len(names),'decoded':{'bytes':len(raw),'sha256':_ehp_digest(raw)},'rows':rows}
    _ehp_need(len(_ehp_names_wire(value))<=65536 and _ehp_names_decode(value)==names,
        'lossless complete prefix data exceeds original serialized field bound')
    return value
