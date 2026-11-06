#!/usr/bin/env python3
"""Pure late closure for one existing NEG-08/09. No phone, model or filesystem I/O.
Only pinned callback reads and reviewed pure projections are used. Ordinary
cancellation, CPU safe-point qualification and physical-case qualification
remain distinct conclusions.
"""
import ast
import base64
import copy
import datetime
import fnmatch
import hashlib
import json
from pathlib import PurePosixPath
import re
import shlex
import types
import negative_originals as O

SCHEMA='hepta.r10.cpu-negative-closure.v1'
NATIVE='/var/lib/trillionnium/owner-open/turn-events.jsonl.segments'
ROOT='/negative-retained-view'
need=O.need
sha=O.sha
strict=O.strict
same=O.same
def zero(v):return type(v) is int and v==0

def projected(raw, names, constants=(), namespace=None):
    """Exact pinned raw function/constant projection; no source imports."""
    tree=ast.parse(raw);body=[];seen=set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names:
            body.append(copy.deepcopy(node));seen.add(node.name)
        elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in constants:
                body.append(copy.deepcopy(node));seen.add(key)
    need(seen==set(names)|set(constants),'pure_source_projection_closed_set')
    ns=dict(namespace or {})
    exec(compile(ast.Module(body=body,type_ignores=[]),'<exact-pinned-pure-projection>','exec'),ns)
    return types.SimpleNamespace(**ns)

def load_cpu(context):
    raw=context['raw_sources']['cpu']
    tree=ast.parse(raw)
    need(all(isinstance(node,(ast.Import,ast.ImportFrom,ast.Assign,ast.FunctionDef,ast.ClassDef,ast.Expr))
             for node in tree.body),'CPU_pure_module_top_level')
    module=types.ModuleType('reviewed_cpu_cancel_originals')
    exec(compile(raw,'<reviewed-cpu-originals>','exec'),module.__dict__)
    return module

class FrozenSnapshot:
    """Closed archive view. A missing member is never silently treated as ENOENT."""
    def __init__(self,context):
        self.context=context;phone=context['phone']
        self.files={ROOT+'/'+name:raw for name,raw in phone['members'].items()}
        self.absences={ROOT+'/'+row['export_relative_path'] for row in phone['capture']['files']
                       if row.get('state')=='absent' and row.get('lookup_errno')==2}
        self.directories={}
        for row in phone['capture']['directories']:
            source=row['source_path']
            if source.startswith(O.BASE+'/') and row.get('state')=='observed':
                path=ROOT+'/'+source[len(O.BASE)+1:]
                old=self.directories.get(path)
                need(old is None or same(old,row),'source_directory_views_changed')
                self.directories[path]=row
        owner=self
        class ArchivePath(PurePosixPath):
            def glob(self,pattern):
                need('/' not in pattern and '**' not in pattern,'closed_nonrecursive_glob')
                return iter(ArchivePath(k) for k in sorted(owner.files)
                            if PurePosixPath(k).parent==self and fnmatch.fnmatchcase(PurePosixPath(k).name,pattern))
        self.Path=ArchivePath
    def read(self,path,required=True,maximum=O.MAX_FILE):
        text=str(path);need(text.startswith(ROOT+'/') and '..' not in PurePosixPath(text).parts,
                           'closed_snapshot_path')
        if text in self.files:
            raw=self.files[text];need(len(raw)<=maximum,'snapshot_read_bound');return raw
        if not required:
            parent=self.directories.get(str(PurePosixPath(text).parent))
            absent=text in self.absences or parent is not None and PurePosixPath(text).name not in parent['names']
            need(absent,'missing_archive_is_not_original_absence')
            return None
        raise O.Unverified('required_original_missing')
    def json(self,path,required=True,maximum=O.MAX_FILE):
        raw=self.read(path,required=required,maximum=maximum)
        return None if raw is None else strict(raw)
    def pinned(self,path,pin,maximum=O.MAX_FILE):
        raw=self.read(path,maximum=maximum);need(sha(raw)==pin,'snapshot_original_pin');return raw

def ledger_api(context,snapshot):
    raw=context['raw_sources']['ledger_negative']
    parent=context['raw_sources']['ledger_parent']
    old="    require(capture.get('state')=='CAPTURED_BOUND_ORIGINALS'\n"
    new=("    require(capture.get('schema')=='hepta.cpu-cancel.phone-original-capture.v1'\n"
         "            and capture.get('state')=='CAPTURED_NEGATIVE_ORIGINALS_UNQUALIFIED'\n")
    old2=("    require(len(directories)==1 and directories[0].get('state')=='observed',\n"
          "            'original complete ledger directory listing differs')\n")
    new2=("    require(1<=len(directories)<=2 and all(exact(row,directories[0]) for row in directories)\n"
          "            and directories[0].get('state')=='observed',\n"
          "            'negative collector ledger directory observations differ')\n"
          "    # This exact collector visits the same ledger in capture_actions and\n"
          "    # capture_remaining_ledger. Preserve both raw rows; only equal views coalesce.\n"
          "    directories=directories[:1]\n")
    wanted=parent
    for a,b in ((old,new),(old2,new2)):
        need(wanted.count(a.encode())==1,'unique_ledger_derivation_anchor')
        wanted=wanted.replace(a.encode(),b.encode())
    need(raw==wanted,'explicit_two_point_ledger_adapter')
    names={n.name for n in ast.parse(parent).body if isinstance(n,ast.FunctionDef)}
    return projected(raw,names,{'SCOPE','MUTATIONS'},dict(ast=ast,base64=base64,datetime=datetime,
        hashlib=hashlib,json=json,re=re,Path=snapshot.Path,strict_loads=strict))

def business_api(context,snapshot):
    return projected(context['raw_sources']['business'],
        {'sha','require','compact','decode64','streams','native_tool_streams',
         'r6_journal_binding','r6_terminal_identity_and_cleanup','inspect_tool'},
        {'MUTATIONS','SAFE_STATES','R6_CLIENT_SOURCE_SHA256','R6_ENDPOINT','R6_PARENT','R6_BOOTSTRAP'},
        dict(base64=base64,hashlib=hashlib,json=json,re=re,Path=snapshot.Path,
             strict_loads=strict,SCOPE_FIELDS=O.SCOPE))

def complete_native(context,api,before,final,last):
    phone=context['phone'];cap=phone['capture'];scope=context['plan']['scope']
    dirs=[r for r in cap['directories'] if r.get('source_path')==NATIVE]
    need(len(dirs)==1 and dirs[0].get('state')=='observed','complete_native_directory_original')
    expected=[NATIVE+'/'+n for n in dirs[0]['names'] if n.endswith('.jsonl')]
    sources=cap['native_sources']
    need([r['source_path'] for r in sources]==expected and expected,'complete_native_segment_set')
    records=[];by_location={};selected=[]
    for row in sources:
        source=row['source_path']
        need(source in phone['sources'] and row.get('state')=='scanned_to_eof','native_source_not_complete')
        rel,original=phone['sources'][source];raw=phone['members'][rel]
        need(len(raw)==row['bytes_scanned'] and sha(raw)==row['whole_file_sha256'] and
             same(original['stat_before'],row['stat']),'native_scan_copy_full9_and_bytes')
        offset=0
        for number,line in enumerate(raw.splitlines(keepends=True),1):
            need(line.endswith(b'\n') and len(line)<=4*1024*1024,'native_complete_line')
            record=strict(line);api.audit.record_hashes(record);records.append(record)
            need(len(records)<=131072,'bounded_native_record_count')
            by_location[(source,offset)]=(line,record,number)
            if record.get('scope')==scope:selected.append((record,line,source,offset,number))
            offset+=len(line)
        need(offset==len(raw),'native_complete_segment_bytes')
    audit=api.audit.verify_records(records,scope)
    need(audit['status']=='PASS' and not audit['errors'] and not audit['unsupported'] and
         not audit['unobserved_global_sequence_gaps'],'full_captured_native_prefix_not_verified')
    selected.sort(key=lambda x:x[0]['store_seq'])
    raw_selected=b''.join(x[1] for x in selected)
    need(raw_selected==phone['members']['selected-native-raw.jsonl'] and
         len(selected)==len(cap['native_raw_records']),'selected_native_raw_subset_exact')
    for item,row in zip(selected,cap['native_raw_records']):
        record,line,source,offset,number=item
        need(row=={'source_path':source,'line_1based':number,'offset':offset,'bytes':len(line),
             'sha256':sha(line),'store_seq':record['store_seq'],'turn_seq':record['turn_seq'],'kind':record['kind']},
             'native_original_location_record')
        need(record['payload']['request_sha256']==context['plan']['native_request_sha256'],
             'native_actual_request_digest')
    for observation in (before,final,last):
        pieces=[]
        for row in observation['native_originals']:
            key=(row['source'],row['offset']);need(key in by_location,'observer_native_location_missing')
            line,record,_=by_location[key]
            observed=base64.b64decode(row['raw_b64'],validate=True)
            need(observed==line and len(line)==row['bytes'] and sha(line)==row['sha256'] and record['scope']==scope,
                 'observer_native_raw_not_original_prefix')
            pieces.append(line)
        joined=b''.join(pieces)
        need(raw_selected.startswith(joined),'observer_native_not_selected_prefix')
        if observation is last:need(joined==raw_selected,'native_turn_advanced_after_last_observation')
    frames=audit['frames']
    need(frames[-1]['kind']=='turn.end' and frames[-1]['payload'].get('status')=='cancelled',
         'native_cancel_end_not_original')
    summary={k:v for k,v in audit.items() if k not in ('selected_records','frames')}
    summary.update(schema='hepta.cpu-negative.complete-captured-native-prefix.v1',
       state='COMPLETE_CAPTURED_SEGMENT_PREFIX_VERIFIED',
       segment_count=len(sources),all_captured_segments_scanned=True,
       unseen_predecessor_or_genesis_attested=False,
       original_observer_hash_claims_left_unchanged=True)
    return frames,summary,selected

def verify_effect_prefix(context,snapshot,api,frames,last):
    owner=base64.b64decode(context['actor_plan']['request_b64'],validate=True)
    incoming,outgoing,_iraw,_oraw=api_cpu_provider(context,last)
    calls=[v['call'] for v in outgoing if v['kind']=='tool.call']
    ids={call['call_id'] for call in calls}
    tool_frames=[f for f in frames if f['kind'].startswith('tool.')]
    need(all(f['kind'] in ('tool.accepted','tool.started','tool.stdout','tool.stderr','tool.result')
             and f.get('call_id') in ids for f in tool_frames),'native_provider_dispatch_prefix')
    p=snapshot.Path;run=p(ROOT)/'provider-state/evidence'/last['run'];state=p(ROOT)/'provider-state'
    seal=snapshot.json(p(ROOT)/'sources/provider-r10/SOURCE-SEAL-v150-r10.json')
    ledger=ledger_api(context,snapshot).audit(snapshot,run,state,context['plan']['scope'],owner,
        seal,p(ROOT)/'CAPTURE.json',calls,p(ROOT)/'sources/provider-r10/source')
    need(ledger.get('status')=='PASS' and ledger.get('complete_prefix_reconstruction') is True and
         ledger.get('unaccounted_original_intents')==[],'complete_global_ledger_originals_unverified')
    baseline=snapshot.json(run/'ledger-prefix/baseline.json')
    ledger_dir=state/'evidence/action-ledger'
    original_dir=context['phone']['capture']['actual_run_dir'].rsplit('/',1)[0]+'/action-ledger'
    directory=snapshot.directories[str(ledger_dir)]
    need(directory['source_path']==original_dir and
         all(name=='ledger.lock' or re.fullmatch(
             r'[0-9a-f]{32}\.(intent|resolution|inspection|retirement-proof)\.json',name)
             for name in directory['names']),'unindexed_global_ledger_name')
    # Only this task's new reservations may change. A baseline ENOENT stays
    # historical evidence and is not silently promoted to a later resolution.
    for prior in baseline['initial_auxiliary_originals']:
        observed=snapshot.read(ledger_dir/prior['name'],required=False)
        if prior['state']=='absent':
            need(observed is None,'unrelated_prior_auxiliary_was_created')
        else:
            need(observed==base64.b64decode(prior['raw_base64'],validate=True),
                 'unrelated_prior_auxiliary_changed')
    business=business_api(context,snapshot)
    results=[r for r in incoming if r.get('kind')=='tool.result']
    need(len(results)==len(calls) and len({r.get('call_id') for r in results})==len(results)
         and {r.get('call_id') for r in results}==ids,'complete_unique_original_tool_result_set')
    rows=[]
    for call in calls:
        matching=[r for r in results if r.get('call_id')==call['call_id']]
        need(len(matching)==1,'exact_original_tool_result')
        row=business.inspect_tool(snapshot,run,state,p(ROOT)/'executor-r6',p(ROOT)/'client-receipts',
                                  context['plan']['scope'],call,matching[0],frames)
        need(row['successful_original_execution'] is True and row['safe_original_execution_terminal'] is True and
             row['native_raw_streams_equal'] is True and row.get('unresolved_effect') is False and
             row['dispatch_count']==1 and not row['issues'],'dispatched_effect_not_known_complete')
        rows.append(row)
    mutations=[r for r in rows if r['semantic_tool'] in business.MUTATIONS]
    if context['plan']['case_id']=='NEG-08':
        need(not calls and not mutations,'predispatch_cancel_has_task_effect')
    else:
        need(len(mutations)==1 and mutations[0]['semantic_tool']=='phone.open_app' and
             all(r['semantic_tool'] in ('phone.open_app','phone.screenshot') for r in rows),
             'post_effect_cancel_has_extra_task_effect')
        need(len([r for r in last['calls'] if r['semantic_tool']=='phone.open_app' and r['verified_app_open'] is True])==1,
             'one_original_open_not_confirmed')
    need(context['phone']['capture']['original_dispatched_action_ids']==[r['action_id'] for r in rows],
         'complete_original_dispatched_action_inventory')
    return {'global_ledger':ledger,'original_tool_receipts':rows,
            'confirmed_task_effect_count':len(mutations),'original_dispatch_count':len(calls),
            'complete_global_ledger_names_verified':True,
            'baseline_intents_and_auxiliary_originals_preserved':True,
            'followup_model_input_or_forced_return':False,'automatic_replay':False,
            'unknown_effect_count':0,'identity_release':False}

def api_cpu_provider(context,last):
    return context['_cpu'].provider_originals(last,context['actor_plan'])

def protocol(context):
    value=strict(context['raw_sources']['protocol'])
    need(value.get('schema')=='hepta.fixed-acceptance-set.v150.1' and
         value.get('set_id')=='stock16-phone-local-fixed-set-r4','original_protocol_identity')
    rows=[r for r in value['cases'] if r['id']==context['plan']['case_id']]
    need(len(rows)==1 and rows[0]['negative_case'] is True and rows[0]['expected_business_verified'] is False and
         rows[0]['required_qualification_layers']==['host_isolated','physical_native_task'] and
         rows[0]['required_metrics']==['latency','usage','cost','resources','evidence','restoration'],
         'original_NEG08_09_contract_layers')
    need(value['limits']['maximum_sequential_tool_calls_before_final_summary']==7 and
         value['limits']['model_rounds']==8 and value['limits']['turn_deadline_seconds']==300 and
         value['limits']['default_model_round_deadline_seconds']==120,'original_protocol_caps')
    return rows[0]


def original_transport_copies(context,role,host):
    rows=context['p4']['capture']['transport_originals'][role]
    expected={'launch_request':host['intent'],'terminal_operation':host['result'],
              'stdout':host['stdout'],'stderr':host['stderr']}
    need(set(rows)==set(expected),'complete_original_transport_mapping')
    for name,descriptor in expected.items():
        row=rows[name]
        need(type(row) is dict and set(row)=={'original_descriptor','captured_copy','original_metadata_not_claimed_from_copy'}
             and row['original_descriptor']==descriptor and row['original_metadata_not_claimed_from_copy'] is True,
             'transport_original_is_not_copy_metadata')
        need(O.file_row(row['captured_copy'],context['p4']['members'])==
             context['originals'].read(descriptor),'transport_original_and_P4_retained_copy')

def actor_terminal(context):
    plan=context['actor_plan'];nonce=context['plan']['nonce']
    package=O.P4+'/cpu-negative-case-inputs-r1/'+nonce+'/operator'
    argv=['/usr/bin/python3','-I','-B',package+'/source/cancel_native_once_r10.py',
          '--plan',O.P4+'/cpu-negative-case-inputs-r1/'+nonce+'/ACTOR-PLAN.json',
          '--package',package+'/MANIFEST.json','--package-sha256',context['final']['ui_package_sha256'],
          '--out',O.P4+'/cancel-native-r10/'+plan['label'],'--execute-once']
    need(O.number(plan['wait_seconds'],1,300),'bounded_original_actor_wait')
    timeout=plan['wait_seconds']+240
    original=context['plan']['actor_execution']
    stdout=O.remote_phase(context['originals'],original,context['raw_sources']['root_transport'],
        'negative-cancel-actor',argv,timeout,O.P4+'/cpu-negative-controls-r1/'+nonce)
    expected={k:v for k,v in context['actor_result'].items() if k!='last_original_observation'}
    need(strict(stdout)==expected,'actual_Actor_stdout_and_retained_result')
    preview=strict(O.file_row(context['p4']['capture']['actor_originals']['PACKAGE-PREVIEW.json'],
                             context['p4']['members']))
    need(preview['package_sha256']==context['final']['ui_package_sha256'] and
         preview['plan_sha256']==sha(O.file_row(context['p4']['capture']['actor_originals']['PLAN.original.json'],
                                                context['p4']['members'])) and
         preview['out']==argv[-2] and preview['case_id']==plan['case_id'],'actual_Actor_package_preview')
    original_transport_copies(context,'actor',original['host'])
    return {'original_host_child_joined':True,'original_P4_Actor_returncode':0,
            'original_phase':'negative-cancel-actor','automatic_retry':False}

def literal_from_actor(raw,name):
    return O.literal(raw,name)

def sender_terminal(context,api,selected):
    plan=context['plan'];data=plan['sender'];originals=context['originals'];actor_plan=context['actor_plan']
    owner=originals.read(data['request'],65536);label=actor_plan['sender_label']
    need(owner==base64.b64decode(actor_plan['request_b64'],validate=True) and
         sha(owner)==plan['owner_request_sha256'] and owner.decode().count(plan['nonce'])==1,
         'actual_sender_exact_owner_nonce')
    previous_raw=originals.read(data['previous'],65536);previous=strict(previous_raw)
    need(previous['identity']==actor_plan['previous_scope'] and previous['identity']!=plan['scope'] and
         previous.get('terminal',{}).get('status') in ('completed','provider_failed','cancelled'),
         'actual_sender_closed_previous')
    private_raw=originals.read(data['preserved_draft'],131072);private=strict(private_raw)
    draft=base64.b64decode(private['exact_utf8_b64'],validate=True);draft.decode('utf-8',errors='strict')
    need(draft and sha(draft)==private['utf8_sha256'] and draft!=owner,'private_original_draft_integrity')
    retirement_raw=originals.read(data['retirement_resolution'],4*1024*1024)
    retirement=strict(retirement_raw)
    generated=originals.read(data['generated_actor'],262144)
    values={k:literal_from_actor(generated,k) for k in
        ('label','reset_probe','preserved_draft','expected','previous_identity','previous_digest',
         'evidence_mode','component_binding','retirement_binding','READ_ONLY_PROBE_SOURCE')}
    need(values['label']==label and values['reset_probe'] is False and
         values['preserved_draft'].encode()==draft and values['expected'].encode()==owner and
         values['previous_identity']==previous['identity'] and values['previous_digest']==previous['request_sha256'] and
         values['evidence_mode']=='production' and values['component_binding'] is None,
         'actual_sender_generated_actor_inputs')
    need(values['retirement_binding']['resolution_sha256']==sha(retirement_raw),
         'actual_sender_retirement_original')
    sender_raw=context['raw_sources']['sender']
    need(values['READ_ONLY_PROBE_SOURCE']==O.literal(sender_raw,'READ_ONLY_PROBE'),
         'actual_sender_probe_source')
    latency=O.literal(sender_raw,'LATENCY_OBSERVER').encode()
    for name in ('latency_read_original','observe_original_terminal'):
        need(O.source_segment(generated,name)==O.source_segment(latency,name),
             'actual_sender_original_terminal_observer')
    tree=ast.parse(generated)
    sends=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and
           n.func.id=='tap' and len(n.args)==1 and isinstance(n.args[0],ast.Name) and n.args[0].id=='send']
    intents=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and
             n.func.id=='save' and n.args and isinstance(n.args[0],ast.Constant) and
             n.args[0].value=='SEND.MONOTONIC-INTENT.json']
    need(len(sends)==len(intents)==1 and intents[0].lineno<sends[0].lineno,
         'single_source_Send_after_durable_intent')
    argv=['/usr/bin/python3','-I','-B',plan['sources']['sender']['path'],label,
          data['request']['path'],data['previous']['path'],'--preserved-draft',data['preserved_draft']['path'],
          '--retirement-resolution',data['retirement_resolution']['path'],
          '--evidence-root','production','--execute-once']
    stdout=O.host_phase(originals,data['execution'],'negative-sender',argv,660,None)
    outer_raw=originals.read(data['send_result'],16*1024*1024)
    need(stdout==outer_raw,'sender_outer_stdout_is_original_send_result')
    outer=strict(outer_raw)
    need(set(outer)=={'rc','stdout','stderr'} and type(outer['rc']) is int and outer['rc']==0 and outer['stderr']=='',
         'actual_sender_SSH_terminal_not_zero')
    terminal=strict(outer['stdout'])
    need(terminal.get('state')=='ORIGINAL_NATIVE_TERMINAL_OBSERVED' and terminal.get('native_status')=='cancelled' and
         terminal.get('out')=='/home/alex/codex-hepta-natural-'+label+'-root-v150' and
         terminal.get('prompt_sha256')==plan['owner_request_sha256'] and type(terminal.get('send_attempt_count')) is int and
         terminal['send_attempt_count']==1 and terminal.get('automatic_replay') is False and
         terminal.get('business_success_verified') is False and terminal.get('independent_collector_required') is True and
         terminal.get('retirement_resolution_sha256')==sha(retirement_raw) and
         terminal.get('draft_restore')=={'state':'ORIGINAL_DRAFT_RESTORED','restore_attempts':1,
                                        'original_draft_submitted':False},
         'sender_actual_terminal_or_cleanup_missing')
    once=strict(originals.read(data['local_once'],65536))
    need(once['task']==label and once['prompt'].encode()==owner and once['prompt_sha256']==sha(owner) and
         once['previous_identity']==previous['identity'] and once['previous_digest']==previous['request_sha256'] and
         once['retirement_resolution_sha256']==sha(retirement_raw) and once['evidence_root_mode']=='production' and
         once['automatic_replay'] is False and once['supplied_app_commands'] is False and
         once['supplied_app_coordinates'] is False,'original_sender_once')
    cap=context['p4']['capture'];members=context['p4']['members']
    raw={k:O.file_row(v,members) for k,v in cap['sender_originals'].items()}
    need(not any(n in raw for n in ('ACTOR-FAILURE.json','DRAFT-RESTORE-UNCONFIRMED.json',
                                    'DRAFT-RESTORE-PENDING.json')),
         'sender_original_failure_or_unknown_retained')
    embedded=strict(O.file_row(cap['actor_originals']['SENDER-ORIGINALS.json'],members))
    need(set(embedded)=={'SEND.once.json','SEND.MONOTONIC-INTENT.json','SEND.MONOTONIC-WINDOW.json','FINAL-PRE-SEND-UI.json'},
         'exact_original_Send_subset')
    for name,row in embedded.items():
        need(name in raw and base64.b64decode(row['raw_b64'],validate=True)==raw[name] and
             row['bytes']==len(raw[name]) and row['sha256']==sha(raw[name]),
             'Actor_original_Send_subset_not_actual_sender_bytes')
    preserved=strict(raw['PRESERVED-USER-DRAFT.json'])
    need(preserved['exact_text'].encode()==draft and preserved['utf8_sha256']==sha(draft) and
         preserved.get('restore_required') is True and preserved.get('submitted_original_draft') is False,
         'actual_pre_Send_preserved_draft')
    timing=strict(raw['SEND-NATIVE-LATENCY.json'])
    need(timing.get('schema')=='hepta.p4-send-native-terminal-latency.v150.r3' and
         timing.get('state')=='ORIGINAL_NATIVE_TERMINAL_OBSERVED' and timing.get('native_status')=='cancelled' and
         timing.get('scope')==plan['scope'] and timing.get('owner_request_utf8_sha256')==sha(owner) and
         timing.get('send_attempt_count')==1 and timing.get('automatic_send_retry') is False and
         timing.get('native_hash_chain_verified') is False,'sender_original_terminal_observation')
    window=strict(raw['SEND.MONOTONIC-WINDOW.json'])
    need(set(window)=={'send_started_monotonic_ns','send_returned_monotonic_ns','clock',
         'send_status','automatic_replay'} and window['automatic_replay'] is False and
         window['clock']=='Pocket4 time.monotonic_ns' and
         O.number(window['send_started_monotonic_ns'],1) and
         O.number(window['send_returned_monotonic_ns'],window['send_started_monotonic_ns']) and
         timing['send_call_started_monotonic_ns']==window['send_started_monotonic_ns'] and
         timing['send_call_returned_monotonic_ns']==window['send_returned_monotonic_ns'] and
         timing['send_wire_state']==window['send_status'],'original_Send_wire_window')
    known='SEND.result.json' in raw
    unknown='SEND.unknown.json' in raw
    need(known is not unknown and window['send_status']==('tap_returned' if known else 'unknown'),
         'single_Send_wire_disposition')
    if known:
        strict(raw['SEND.result.json'])
    else:
        failure=strict(raw['SEND.unknown.json'])
        need(set(failure)=={'error','automatic_replay','next'} and type(failure['error']) is str and
             failure['automatic_replay'] is False and failure['next']=='Only read original request/scope',
             'original_unknown_Send_record_lost')
    need(O.number(timing.get('terminal_observation_end_monotonic_ns'),
                  window['send_returned_monotonic_ns']) and
         timing['send_to_terminal_observed_seconds']==(
             timing['terminal_observation_end_monotonic_ns']-window['send_started_monotonic_ns'])/1e9,
         'original_same_process_latency')
    observation=timing['original_observation'];end=observation['native_terminal']
    need(observation['state']=='native_terminal_observed' and observation['match']['scope']==plan['scope'] and
         observation['native_request_sha256']==plan['native_request_sha256'] and
         base64.b64decode(end['raw_line_b64'],validate=True)==selected[-1][1] and
         end['source']==selected[-1][2] and end['raw_line_sha256']==sha(selected[-1][1]) and
         end['raw_line_bytes']==len(selected[-1][1]),'sender_native_terminal_same_original')
    final_selected=context['phone']['members']['client-selected/owner-client-session-v1.bin']
    for name,expected_identity,expected_digest in (
       ('FINAL-PRE-SEND-SELECTED.original-read.json',previous['identity'],previous['request_sha256']),
       ('RESTORE-SELECTED.original-read.json',plan['scope'],plan['native_request_sha256']),
       ('RESTORE-SELECTED-FINAL.original-read.json',plan['scope'],plan['native_request_sha256'])):
        wire=strict(raw[name])
        need(type(wire.get('rc')) is int and wire['rc']==0 and wire.get('stderr')=='',
             'sender_selected_original_read_terminal')
        selected_raw=base64.b64decode(''.join(wire['stdout'].split()),validate=True)
        value=api.decoder.decode_client_state(selected_raw)
        need(all(value[k]==expected_identity[k] for k in ('session_id','task_id','turn_id')) and
             value['turn_request_sha256']==expected_digest,'sender_selected_checksum_CAS')
        if name.startswith('RESTORE-'):need(selected_raw==final_selected,'late_selected_task_identity_changed')
    for name in ('PRE-MUTATION-RETIREMENT.original-read.json','FINAL-PRE-SEND-RETIREMENT.original-read.json',
                 'RESTORE-GLOBAL-GATE.original-read.json'):
        receipt=strict(raw[name]);wire=receipt['original_wire_receipt'];value=strict(wire['stdout'])
        need(type(wire.get('rc')) is int and wire['rc']==0 and wire.get('stderr')=='' and
             receipt.get('read_only') is True and receipt.get('no_retry') is True and
             value.get('state')=='original_retirement_verified' and value.get('global_action_gate_clear') is True and
             value.get('resolution_sha256')==sha(retirement_raw) and
             value.get('proof_sha256')==values['retirement_binding']['proof_sha256'],
             'actual_global_action_retirement_gate_original')
    restore=private_restoration({name:strict(raw[name]) for name in
          ('DRAFT-RESTORE-RESULT.json','PRESERVED-DRAFT-RESTORE.original.json')},label,private_raw)
    original_transport_copies(context,'sender',data['execution'])
    return {'original_host_parent_wait_receipt_available':True,'original_host_child_joined':True,
        'original_sender_SSH_returncode':0,'actual_send_attempt_count':1,
        'original_sender_native_terminal':'cancelled','draft_restoration':restore,
        'original_Send_wire_state':window['send_status'],
        'original_unknown_Send_wire_preserved':unknown,
        'wire_unknown_is_not_relabelled_success':True,
        'native_terminal_independently_verified_after_original_wire':True,
        'selected_state_checksum_and_compare_and_set_verified':True,
        'actual_UI_actions_occurred':True,'operator_restoration_is_not_model_business':True,
        'send_to_terminal_observed_seconds':timing['send_to_terminal_observed_seconds'],
        'original_sender_source_sha256':sha(sender_raw),'generated_actor_source_sha256':sha(generated),
        'private_text_or_inner_digest_in_public_output':False,'automatic_replay':False}

def private_restoration(originals,label,preserved_raw):
 original=strict(preserved_raw)
 need(isinstance(original,dict) and isinstance(original.get('exact_utf8_b64'),str),'private original draft shape')
 draft=base64.b64decode(original['exact_utf8_b64'],validate=True);draft.decode('utf-8',errors='strict')
 need(draft and sha(draft)==original['utf8_sha256'],'private original draft integrity')
 result=originals['DRAFT-RESTORE-RESULT.json'];wire=originals['PRESERVED-DRAFT-RESTORE.original.json']
 need(result.get('state')=='ORIGINAL_DRAFT_RESTORED' and result.get('original_draft_submitted') is False
      and result.get('model_business_credit') is False and result.get('restore_attempts')==1
      and result.get('utf8_sha256')==sha(draft),'original cleanup disposition')
 need(zero(wire.get('rc')) and wire.get('stderr')=='','original draft restore wire not terminal zero')
 value=strict(wire['stdout'])
 need(value.get('schema')=='hepta.focused-unicode-input.v1' and value.get('status') in ('set_verified','already_exact')
      and value.get('operation_id')=='root-restore-'+label and value.get('display_id')==0
      and value.get('package')=='org.trillionnium.owneropen'
      and value.get('view_id')=='org.trillionnium.owneropen:id/ui_prompt'
      and value.get('own_automation_disconnected') is True,'original cleanup action binding')
 readback=base64.b64decode(value['readback_text_b64'],validate=True)
 need(readback==draft and value.get('requested_utf8_sha256')==sha(draft)
      and value.get('after_utf8_sha256')==sha(draft),'private exact draft readback differs')
 return {'exact_original_draft_restored':True,'original_draft_submitted':False,
         'restore_attempts':1,'business_return_credit':False,'private_text_or_digest_in_public_output':False}

def protection_and_metrics(context,api,cpu,last,sender,effects):
    plan=context['plan'];phone=context['phone'];members=phone['members'];cap=phone['capture']
    before_raw=members['observations/KERNEL-BEFORE.json'];after_raw=members['observations/KERNEL-AFTER.json']
    need(before_raw==after_raw,'kernel_policy_boot_original_bookends')
    kernel=strict(before_raw)
    need(kernel['boot_id']==context['actor_plan']['expected_boot'] and
         kernel['policy']==context['final']['live_policy'] and kernel['observer_uid']==kernel['observer_gid']==0 and
         base64.b64decode(kernel['enforce_original_b64'],validate=True) in (b'1',b'1\n') and
         base64.b64decode(kernel['domain_original_b64'],validate=True).rstrip(b'\0\n')==b'u:r:magisk:s0',
         'actual_kernel_policy_Enforcing_readonly_capture_identity')
    pending=strict(members['observations/SELECTED-PENDING-ABSENCE.json'])
    need(set(pending)=={'before','after'} and pending['before']==pending['after'] and
         pending['before']['lookup_errno']==2 and
         pending['before']['source']=='/proc/1/root/data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.pending',
         'actual_selected_pending_canonical_absence')
    O.metadata(pending['before']['parent_metadata'],True)
    selected=api.decoder.decode_client_state(members['client-selected/owner-client-session-v1.bin'])
    need(all(selected[k]==plan['scope'][k] for k in ('session_id','task_id','turn_id')) and
         selected['turn_request_sha256']==plan['native_request_sha256'],'late_selected_original_task')
    claim_path=O.BASE+'/provider-state/evidence/claims/'+cap['claim_key']
    need(claim_path in phone['sources'],'late_durable_claim_original')
    name,row=phone['sources'][claim_path];claim_raw=members[name]
    embedded=base64.b64decode(last['claim_original']['raw_b64'],validate=True)
    need(claim_raw==embedded,'one_use_claim_changed_after_original_cancel')
    claim=strict(claim_raw)
    need(claim['state']=='accepted_no_redispatch' and claim['identity']==plan['scope'] and
         claim['request_sha256']==plan['owner_request_sha256'],'late_claim_not_consumed')
    seal_raw=members['sources/provider-r10/SOURCE-SEAL-v150-r10.json']
    need(sha(seal_raw)==phone['plan']['release_pins']['source_seal_sha256'],
         'actual_source_seal_release_pin')
    need(members['sources/local-config-r10.json']==context['raw_sources']['configuration'] and
         members['sources/PHONE-SERVICE-INPUTS-v150-r10.json']==context['raw_sources']['service'],
         'actual_shared_configuration_service_raw')
    seal=strict(seal_raw)
    names=set()
    for source in seal['production_files']:
        rel=source['path'];need(rel not in names,'sealed_production_duplicate');names.add(rel)
        raw=members['sources/provider-r10/'+rel]
        need(len(raw)==source['bytes'] and sha(raw)==source['sha256'],'actual_sealed_production_source')
    need(len(names)==15,'actual_fifteen_production_sources')
    ready_raw=members['readiness/ACTUAL-READY.original.json']
    need(ready_raw==base64.b64decode(context['actor_plan']['runtime_binding']['readiness']['raw_b64'],validate=True),
         'original_registered_READY_not_same')
    prefix='provider-state/evidence/'+last['run']+'/local-%02d'%cpu['round']
    http_name=prefix+'.http-receipt.json'
    http=strict(members[http_name]) if http_name in members else None
    resources={'original_server_identity':cpu['server_identity'],'original_task_id':cpu['task_id'],
        'original_slot_id':cpu['slot_id'],'request_id':cpu['request_id'],
        'original_model_terminal':cpu['model_terminal'],
        'server_release_idle_and_original_HTTP_workers_joined':True,
        'original_records_source':'Captured request producer records and actual same-request GET pairs; no guessed resource counters.'}
    metrics={'latency':{'send_to_native_terminal_observed_seconds':sender['send_to_terminal_observed_seconds'],
            'source':'Original sender same-process monotonic observation, not a guessed device clock.'},
        'usage':{'value':None if http is None else http.get('usage'),
            'source':http_name if http is not None else None,
            'absent_value_is_not_zero':True},
        'cost':{'value':None,'claim':'No billing or cost figure inferred from a cancelled local request.'},
        'resources':resources,
        'evidence':{'phone_archive':plan['phone']['archive'],'P4_archive':plan['p4']['archive'],
                    'source_seal_sha256':sha(seal_raw),'actual_READY_sha256':sha(ready_raw)},
        'restoration':sender['draft_restoration']}
    return {'selected_state_retained':True,'pending_file_actual_ENOENT':True,
        'one_use_claim_still_consumed':True,'native_identity_not_released':True,
        'baseline_intents_and_auxiliary_preserved_with_complete_task_prefix':True,
        'policy_boot_Enforcing_original_bookends':True,'actual_shared_source_seal_verified':True,
        'operator_UI_and_restoration_recorded_separately':True,'task_effects':effects['confirmed_task_effect_count'],
        'metrics':metrics}

def close_originals(plan_raw,*,read_pinned):
    context=O.assemble(plan_raw,read_pinned=read_pinned)
    contract=protocol(context)
    cpu=load_cpu(context);context['_cpu']=cpu
    cpu_result=cpu.verify_cpu_cancel(context['cpu_inputs_raw'],read_pinned=context['read_pinned'])
    originals=cpu.Originals(context['read_pinned'])
    api=cpu.load_apis(context['cpu_inputs'],originals)
    actor_plan,ready,before,final,last,result,_actorraw,_tags=cpu.actor_originals(context['cpu_inputs'],originals,api)
    need(same(actor_plan,context['actor_plan']) and cpu_result['scope']==context['plan']['scope'] and
         cpu_result['native_request_sha256']==context['plan']['native_request_sha256'],
         'actual_CPU_scope_binding')
    actor_end=actor_terminal(context)
    frames,native,selected=complete_native(context,api,before,final,last)
    snapshot=FrozenSnapshot(context)
    effects=verify_effect_prefix(context,snapshot,api,frames,last)
    sender=sender_terminal(context,api,selected)
    protection=protection_and_metrics(context,api,cpu_result,last,sender,effects)
    originals.recheck();context['originals'].recheck()
    ordinary=cpu_result['ordinary_cancel_verified'] is True
    need(ordinary and effects['unknown_effect_count']==0,'ordinary_cancel_not_closed')
    eligible=cpu_result['cpu_cancellation_qualified'] is True
    closure={'schema':SCHEMA,
      'state':'ORIGINAL_NEGATIVE_CLOSED_CPU_ELIGIBLE' if eligible else 'ORIGINAL_ORDINARY_CANCEL_CLOSED_CPU_UNQUALIFIED',
      'closed':True,'case_id':context['plan']['case_id'],'nonce':context['plan']['nonce'],
      'scope':context['plan']['scope'],'owner_request_sha256':context['plan']['owner_request_sha256'],
      'native_request_sha256':context['plan']['native_request_sha256'],
      'combination_sha256':context['plan']['combination_sha256'],
      'release_pins':cpu_result['release_pins'],'input_plan_sha256':sha(plan_raw),
      'sources':context['plan']['sources'],'original_archives':{
        'phone':context['plan']['phone']['archive'],'P4':context['plan']['p4']['archive']},
      'actual_original_inputs':context['originals'].index(),
      'CPU_result':cpu_result,'actor_terminal':actor_end,'sender_terminal':sender,
      'native_captured_prefix':native,'global_ledger_and_effects':effects,'protection':protection,
      'ordinary_cancellation_verified':ordinary,'CPU_case_eligible':eligible,
      'actual_model_request_observed':True,'actual_CPU_safe_point_observed':eligible,
      'actual_original_Send_count':1,'actual_original_Cancel_count':1,
      'unknown_effect_count':0,'native_status':'cancelled',
      'private_originals_retained':True,'private_text_or_inner_digest_in_public_output':False,
      'business_verified':False,'model_business_qualification':False,
      'host_isolated_qualification':None,'physical_case_pass':False,
      'final_qualification_entry':'root_cpu_negative.py --qualify-original-case-once',
      'protocol_sha256':sha(context['raw_sources']['protocol']),
      'protocol_required_qualification_layers':contract['required_qualification_layers'],
      'case_replay_permitted':False,'identity_release_permitted':False,
      'this_host_entry':{'phone_calls':0,'UI_actions':0,'model_requests':0,'signals':0,
                         'new_native_nonces':0,'automatic_retry':False}}
    context.pop('_cpu')
    return closure,context

def qualification_receipt(closure,closure_descriptor):
    """Actual evidence only. The CLI invokes this after durable raw closure write."""
    O.exact3(closure_descriptor,32*1024*1024)
    need(closure.get('schema')==SCHEMA and closure.get('closed') is True and
         closure.get('state')=='ORIGINAL_NEGATIVE_CLOSED_CPU_ELIGIBLE' and
         closure.get('ordinary_cancellation_verified') is True and closure.get('CPU_case_eligible') is True and
         closure.get('actual_model_request_observed') is True and closure.get('actual_CPU_safe_point_observed') is True and
         closure.get('unknown_effect_count')==0 and closure.get('native_status')=='cancelled' and
         closure['CPU_result']['cpu_cancellation_qualified'] is True,
         'actual_physical_negative_not_qualified')
    need(closure.get('case_id') in ('NEG-08','NEG-09') and
         closure.get('protocol_sha256')==O.FIXED_SHA['protocol'] and
         closure.get('actual_original_Send_count')==closure.get('actual_original_Cancel_count')==1 and
         closure.get('physical_case_pass') is False and closure.get('model_business_qualification') is False,
         'qualification_exact_negative_layer')
    for key in ('Root_closer_source_sha256','Root_assembler_source_sha256','Root_entry_source_sha256',
                'input_plan_sha256'):
        O.digest(closure.get(key))
    O.exact3(closure.get('Root_original_input_index'))
    need(closure_descriptor['bytes']==len(O.encoded(closure)) and closure_descriptor['sha256']==sha(O.encoded(closure)),
         'qualification_exact_durable_closure')
    return {'schema':'hepta.fixed19.physical-negative-receipt.v1',
      'state':'ORIGINAL_PHYSICAL_CPU_NEGATIVE_QUALIFIED','case_id':closure['case_id'],
      'nonce':closure['nonce'],'scope':closure['scope'],'owner_request_sha256':closure['owner_request_sha256'],
      'native_request_sha256':closure['native_request_sha256'],'combination_sha256':closure['combination_sha256'],
      'release_pins':closure['release_pins'],'protocol_sha256':closure['protocol_sha256'],
      'qualification_layer':'physical_native_task','physical_case_pass':True,
      'CPU_cancellation_qualified':True,'ordinary_cancellation_verified':True,
      'closure_original':closure_descriptor,'metrics':closure['protection']['metrics'],
      'original_input_index':closure['Root_original_input_index'],
      'input_plan_sha256':closure['input_plan_sha256'],
      'sources':closure['sources'],
      'Root_sources':{key:closure[key] for key in ('Root_closer_source_sha256',
                      'Root_assembler_source_sha256','Root_entry_source_sha256')},
      'host_isolated_qualification':None,'model_business_qualification':False,'business_verified':False,
      'complete_fixed19_or_other_case_credit':False,'case_replay_permitted':False,
      'identity_release_permitted':False,'actual_original_Send_count':1,'actual_original_Cancel_count':1,
      'new_phone_calls':0,'new_model_requests':0,'new_nonces':0,'automatic_retry':False}
