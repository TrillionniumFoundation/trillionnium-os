#!/usr/bin/env python3
"""Independent host-only closure of actual physical NEG04/05/07 originals.

No phone, socket, signal, model or task entry is called. Complete retained
archives, actual host child/capture receipts and pinned pure projections are
the evidence. This file never expands the CPU NEG08/09 closer's case list.
"""
import argparse
import ast
import base64
import copy
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import signal
import stat
import struct
import sys
import time
import types
import zlib

import physical_fault_common as S
import fault_originals as O
import fault_projections as P

SSH=['/usr/bin/ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22',
    '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast']
P4_ROOT='/home/alex/codex-physical-faults-r10-r1'
ROOT=P.ROOT
NATIVE='/var/lib/trillionnium/owner-open/turn-events.jsonl.segments'
need=O.need
sha=O.sha
strict=O.strict


def phase_rows(out,name,read):
    base=Path(out)/'transport'/name
    names={'intent':'INTENT.json','child':'CHILD.json','result':'RESULT.json',
        'stdout':'stdout.original','stderr':'stderr.original','output_capture':'OUTPUT-CAPTURE.json'}
    result={key:read.known(base/value)[0] for key,value in names.items()}
    intent=strict(read.read(result['intent']))
    result['stdin']=None if intent['stdin_sha256'] is None else read.known(base/'stdin.original')[0]
    return result


def verify_root_phase(context,name,argv,timeout,stdin=None):
    rows=context['execution']['phases'][name]
    expected_base=Path(context['plan']['out'])/'transport'/name
    need(Path(rows['intent']['path']).parent==expected_base,'phase_outside_actual_root_attempt')
    return O.host_phase(context['originals'],rows,name,argv,timeout,stdin)


def unpack_p4_export(raw,expected_root):
    wrapper=strict(raw)
    need(wrapper.get('schema')=='hepta.physical-fault.p4-original-export.v1' and
         O.number(wrapper.get('plain_bytes'),1,64*1024*1024),'bounded_P4_original_export')
    packed=S.decode(wrapper['gzip_base64'],16*1024*1024)
    need(len(packed)==wrapper['gzip_bytes'] and sha(packed)==wrapper['gzip_sha256'],'P4_original_compressed_pin')
    d=zlib.decompressobj(31);body=d.decompress(packed,64*1024*1024+1)
    need(len(body)==wrapper['plain_bytes'] and sha(body)==wrapper['plain_sha256'] and
         d.eof and not d.unused_data and not d.unconsumed_tail,'P4_original_unpacked_pin')
    value=strict(body)
    need(value.get('schema')=='hepta.physical-fault.p4-originals.v1' and value.get('root')==expected_root and
         type(value.get('files')) is list and 1<=len(value['files'])<=128,'P4_exact_original_root')
    files={}
    for row in value['files']:
        name=O.relative(row['relative']);original=row['original']
        need(name not in files and original['path']==expected_root+'/'+name,'P4_unique_original_origin')
        data=S.decode(row['base64'],64*1024*1024)
        need(original==S.desc(expected_root+'/'+name,data),'P4_exact_original_bytes')
        files[name]=data
    return files


def phone_phase(context,name,request):
    plan=context['plan'];remote=P4_ROOT+'/'+plan['nonce']
    p4_case=context['execution']['p4_case']
    expected_case={'schema':'hepta.physical-fault.p4-case.v1','nonce':plan['nonce'],'case_id':plan['case_id'],
        'label':plan['label'],'root_plan_sha256':sha(context['plan_raw']),
        'root_source_manifest':context['execution']['source_package'],'automatic_retry':False,
        'phone_actor_starts_per_phase':1}
    need(p4_case==expected_case,'original_P4_case_binding')
    case_raw=S.enc(p4_case)
    packet={'schema':'hepta.physical-fault.p4-phase.v1','case_sha256':sha(case_raw),
        'nonce':plan['nonce'],'case_id':plan['case_id'],'phase':name,'request':request}
    argv=['/usr/bin/python3','-I','-B',remote+'/source/p4_fault_dispatch_once.py',
        '--case-root',remote,'--self-sha256',sha(context['files']['source/p4_fault_dispatch_once.py']),
        '--execute-one-phone-actor']
    output=verify_root_phase(context,'phone-'+name,SSH+[shlex.join(argv)],request['timeout_seconds']+55,S.enc(packet))
    phase_root=remote+'/phases/'+name
    files=unpack_p4_export(output,phase_root)
    expected={'DISPATCH-RESULT.json','DISPATCH-INTENT.json','PHASE.original.json','REQUEST.original.json',
        'WRAPPER.original.json','OPERATION.original.json','ACTOR-INTENT.original.json','ACTOR-BASELINE.original.json'} | {
        'capture/phone-actor/'+n for n in ('INTENT.json','CHILD.json','RESULT.json','stdout.original',
                                       'stderr.original','OUTPUT-CAPTURE.json')}
    need(set(files)==expected,'complete_P4_phase_export_closed_set')
    need(files['PHASE.original.json']==S.enc(packet) and files['REQUEST.original.json']==S.enc(request),
         'P4_executed_exact_original_request')
    result=strict(files['DISPATCH-RESULT.json']);intent=strict(files['DISPATCH-INTENT.json'])
    label='pf-'+plan['nonce']+'-'+name
    actor_argv=['/usr/bin/python3','-I','-B',O.P4+'/ops/phone_once.py',label,O.P4+'/requests/'+label+'.json']
    need(intent['argv']==actor_argv and intent['actor_source']=={'path':O.P4+'/ops/phone_once.py','bytes':5652,
         'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'} and
         intent['case_sha256']==sha(case_raw) and intent['phase']==name and intent['nonce']==plan['nonce'] and
         intent['maximum_actor_starts']==1 and intent['automatic_retry'] is False and intent['signals_sent']==0,
         'actual_P4_actor_owned_once_intent')
    def read_virtual(row):
        path=row['path'];need(path.startswith(phase_root+'/'),'P4_capture_original_origin')
        data=files[path[len(phase_root)+1:]]
        need(S.desc(path,data)==row,'P4_original_descriptor');return data
    originals=O.Originals(read_virtual)
    base=phase_root+'/capture/phone-actor/'
    records={k:S.desc(base+n,files['capture/phone-actor/'+n]) for k,n in (
        ('intent','INTENT.json'),('child','CHILD.json'),('result','RESULT.json'),('stdout','stdout.original'),
        ('stderr','stderr.original'),('output_capture','OUTPUT-CAPTURE.json'))}
    records['stdin']=None
    actor_stdout=O.host_phase(originals,records,'phone-actor',actor_argv,request['timeout_seconds']+20,None)
    child=strict(files['capture/phone-actor/RESULT.json'])
    wrapper_raw=files['WRAPPER.original.json'];wrapper=strict(wrapper_raw)
    operation=strict(files['OPERATION.original.json']);phone=wrapper.get('phone')
    actual_intent=strict(files['ACTOR-INTENT.original.json']);baseline=strict(files['ACTOR-BASELINE.original.json'])
    actor_summary=strict(actor_stdout)
    need(actual_intent['schema']=='hepta.phone-local.operator-intent.v150.1' and actual_intent['label']==label and
         actual_intent['request_sha256']==sha(S.enc(request)) and actual_intent['request']==request and
         actual_intent['automatic_replay'] is False and wrapper['schema']=='hepta.phone-local.operator-result.v150.1' and
         wrapper['label']==label and wrapper['model_decision'] is False and wrapper['native_task_result'] is False and
         wrapper['status']=='command_exited' and actor_summary=={'run':O.P4+'/operations/'+label,
             'status':'command_exited','sha256':sha(wrapper_raw),'elapsed_seconds':wrapper['elapsed_seconds'],
             'http_status':None,'phone_rc':0,'error':None},'original_phone_actor_intent_summary_wrapper_binding')
    need(baseline['command']=='cat /proc/sys/kernel/random/boot_id; getprop ro.build.fingerprint; getprop sys.usb.config; getenforce; pidof adbd' and
         type(baseline['rc']) is int and baseline['rc']==0 and baseline['stderr']=='' and
         baseline['stdout'].splitlines()==[S.BOOT,'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'] and
         phone['route']==baseline['route'] and phone['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),
         'actual_original_phone_baseline_and_exact_command')
    need(operation=={'actor_rc':0,'wrapper_sha256':sha(wrapper_raw),'wrapper':wrapper} and
         type(phone) is dict and type(phone.get('rc')) is int and phone['rc']==0 and
         phone.get('stderr')=='' and type(phone.get('stdout')) is str,'actual_phone_original_return_not_zero')
    need(result['state']=='ONE_ORIGINAL_PHONE_ACTOR_JOINED_WITH_COMPLETE_HOST_CAPTURE' and
         result['phase']==name and result['nonce']==plan['nonce'] and result['case_sha256']==sha(case_raw) and
         result['actor_child']==child and result['actor_starts']==1 and result['automatic_retry'] is False and
         result['phone_rc']==0 and result['request_sha256']==sha(S.enc(request)) and
         result['phone_stdout_bytes']==len(phone['stdout'].encode()) and
         result['phone_stdout_sha256']==sha(phone['stdout'].encode()) and
         result['phone_stderr_bytes']==0 and result['phone_stderr_sha256']==sha(b''),
         'original_P4_phone_operation_and_capture_disagree')
    need(result['wrapper_original']==S.desc(O.P4+'/operations/'+label+'/result.json',wrapper_raw) and
         result['case_id']==plan['case_id'] and result['label']==label and result['signals_sent']==0 and
         result['phone_effect_qualified'] is False,'P4_operator_never_awards_physical_case')
    return phone['stdout'].encode(),files


def phone_archive(context,result,capture_plan_raw):
    plan=context['plan'];body=context['originals'].read(context['execution']['phone_archive'],O.MAX_ARCHIVE)
    cp=strict(capture_plan_raw);watch=context['admitted']['watch'];final=context['admitted']['final']
    collector=S.module(context['files']['source/capture_fault_phone.py'],'capture_fault_phone.py','pure_fault_capture_plan')
    owner,ready=collector.validate_negative_plan(cp,require_final=True)
    need(owner==context['admitted']['owner'] and cp['sender_scope']==context['execution']['scope'] and
         cp['sender_run']==context['execution']['provider_run'] and cp['native_request_sha256']==context['execution']['native_request_sha256'] and
         cp['sender_label']==plan['label'] and cp['operator_label']==watch['operation_id'] and
         cp['combination_sha256']==final['combination_sha256'] and cp['watch_plan_sha256']==sha(context['admitted']['watch_raw']) and
         cp['watch_source_sha256']==sha(context['files']['source/watch_physical_fault_once.py']) and
         cp['task_template_sha256']==watch['task_template_sha256'] and cp['release_pins']==watch['release_pins'] and
         cp['runtime_binding']==watch['runtime_binding'],'actual_phone_capture_plan_generation_scope')
    expected_final={k:v for k,v in final.items() if k not in ('combination_sha256',)}
    expected_final.update(fault_verifier_sha256=sha(context['files']['source/verify_physical_fault.py']),
        configuration_sha256=plan['configuration']['sha256'],service_inputs_sha256=plan['service']['sha256'])
    need(collector.FINAL_DEPENDENCIES==expected_final,'phone_capture_current_final_dependencies')
    remote=result['archive']
    need(remote['path']==O.BASE+'/fault-original-captures-r10-r1/'+plan['nonce']+'/originals.tar.gz' and
         remote['bytes']==len(body) and remote['sha256']==sha(body),'actual_phone_full_archive_binding')
    need(result.get('schema')=='hepta.physical-fault.phone-capture-result.v1' and
         result.get('state')=='CAPTURED_NEGATIVE_ORIGINALS_UNQUALIFIED' and result.get('export_complete') is True
         and result.get('issues')==[] and result['source_sha256']==sha(context['files']['source/capture_fault_phone.py'])
         and result['plan_sha256']==sha(capture_plan_raw),'actual_final_phone_capture_complete')
    members=O.unpack_archive(body);cap=strict(members['CAPTURE.json'])
    need(sha(members['CAPTURE.json'])==result['capture_sha256'] and remote['member_count']==len(members) and
         cap.get('schema')=='hepta.physical-fault.phone-original-capture.v1' and
         cap.get('state')=='CAPTURED_NEGATIVE_ORIGINALS_UNQUALIFIED' and cap.get('export_complete') is True
         and cap.get('issues')==[] and cap['reviewed_dependencies']==O.literal(
             context['files']['source/capture_fault_phone.py'],'FINAL_DEPENDENCIES'),'phone_capture_source_and_state')
    expected={'CAPTURE.json'};sources={};absences=set()
    for row in cap['files']:
        source=O.canonical(row['source_path']);name=O.relative(row['export_relative_path'])
        if row['state']=='captured':
            O.metadata(row['stat_before'])
            need(row['eof'] is True and row['stat_before']==row['stat_after'] and name not in expected and
                 source not in sources and row['bytes']==len(members[name])==row['stat_before']['st_size'] and
                 row['sha256']==sha(members[name]),'captured_original_full9_and_bytes')
            expected.add(name);sources[source]=(name,row)
        else:
            need(row['state']=='absent' and row['lookup_errno']==2 and row['required'] is False and
                 name not in members,'true_optional_original_absence')
            absences.add(source)
    for name,row in cap['generated_originals'].items():
        O.relative(name);need(name not in expected and name in members and row['bytes']==len(members[name])
            and row['sha256']==sha(members[name]),'generated_original_pin')
        expected.add(name)
    need(set(members)==expected and members['SOURCE.original.py']==context['files']['source/capture_fault_phone.py']
        and members['CAPTURE-PLAN.original.json']==capture_plan_raw,'complete_phone_archive_closed_set')
    need(members['fault-bundle/OPERATOR-BUNDLE.original.json']==S.operator_bundle_bytes(context['admitted']['operator_bundle']) and
         members['fault-watch/OPERATOR-MANIFEST.original.json']==S.decode(context['admitted']['operator_bundle']['manifest_b64'],262144),
         'staged_and_executed_operator_bundle_exact_originals')
    for source_key,plan_key in (('owner_request_sha256','owner_request_sha256'),('selected_scope','sender_scope'),
        ('actual_run','sender_run'),('sender_label','sender_label'),('operator_label','operator_label'),
        ('operator_plan_sha256','operator_plan_sha256'),('operator_package_sha256','operator_package_sha256'),
        ('combination_sha256','combination_sha256'),('native_request_sha256','native_request_sha256'),('release_pins','release_pins')):
        need(cap[source_key]==cp[plan_key],'phone_capture_and_exact_input_'+source_key)
    need(cap['source_sha256']==sha(context['files']['source/capture_fault_phone.py']) and
         cap['plan_sha256']==sha(capture_plan_raw) and cap['fault_eligibility_assessed'] is False and
         cap['physical_case_pass'] is False and cap['native_closure_issued'] is False and
         all(v is True for v in cap['bindings'].values()),'collector_never_self_qualifies_case')
    for row in cap['directories']:
        if row['state']=='observed':
            O.metadata(row['stat'],True)
            need(row['names']==sorted(set(row['names'])),'complete_phone_directory_census')
        else:need(row['state']=='absent' and row['lookup_errno']==2 and row['required'] is False,
                  'phone_directory_absence_not_unknown')
    for k in ('case_id','nonce'):
        need(result[k]==cap[k]==plan[k],'phone_capture_case_binding')
    return {'members':members,'capture':cap,'sources':sources,'absences':absences,'result':result,
            'plan':cp}


def p4_archive(context):
    plan=context['plan'];run=context['execution'];body=context['originals'].read(run['p4_archive'],O.MAX_ARCHIVE)
    members=O.unpack_archive(body);cap=strict(members['CAPTURE.original.json'])
    need(cap['schema']=='hepta.physical-fault.p4-sender-original-capture.v1' and
         cap['state']=='COMPLETE_P4_SENDER_ORIGINALS_CAPTURED_UNQUALIFIED' and cap['case_id']==plan['case_id'] and
         cap['nonce']==plan['nonce'] and cap['sender_label']==plan['label'] and cap['scope']==run['scope'] and
         cap['owner_request_sha256']==sha(context['admitted']['owner']) and
         cap['all_original_full9_and_bytes_rechecked'] is True and cap['complete_directory_census_bookends_equal'] is True,
         'P4_sender_original_archive_complete')
    expected={'CAPTURE.original.json'}
    for row in O.source_rows(cap):O.file_row(row,members);expected.add(row['retained']['path'])
    need(set(members)==expected and O.file_row(cap['source'],members)==context['files']['source/capture_fault_p4.py'],
         'P4_sender_capture_exact_source_and_closed_set')
    plan_raw=context['originals'].read(run['p4_capture_plan'],65536)
    wanted={'schema':'hepta.physical-fault.p4-sender-capture-plan.v1','case_id':plan['case_id'],
        'nonce':plan['nonce'],'sender_label':plan['label'],'owner_request_sha256':sha(context['admitted']['owner']),
        'scope':run['scope'],'out':O.P4+'/fault-p4-original-captures-r1/'+plan['nonce']}
    need(strict(plan_raw)==wanted and O.file_row(cap['plan'],members)==plan_raw and
         cap['plan']['source']==O.P4+'/fault-p4-capture-inputs-r1/'+plan['nonce']+'/PLAN.json' and
         cap['source']['source']==P4_ROOT+'/'+plan['nonce']+'/source/capture_fault_p4.py',
         'actual_P4_capture_source_and_plan_paths')
    O.directory_row(cap['sender_directory'],'/home/alex/codex-hepta-natural-'+plan['label']+'-root-v150',
        cap['sender_originals'])
    return {'members':members,'capture':cap,'sender':{k:O.file_row(v,members) for k,v in cap['sender_originals'].items()}}


def p4_operations(context):
    plan=context['plan'];run=context['execution'];files=context['files'];read=context['originals']
    root=P4_ROOT+'/'+plan['nonce'];case_raw=S.enc(run['p4_case'])
    selected={name:files['source/'+name] for name in
        ('owned_capture.py','p4_fault_dispatch_once.py','capture_fault_p4.py')}
    packet={'root':root,'case':S.b64(case_raw),'source':{name:{'bytes':len(raw),'sha256':sha(raw),
        'base64':S.b64(raw)} for name,raw in selected.items()}}
    nodes=[n for n in ast.parse(files['source/run_physical_fault_once.py']).body
        if isinstance(n,ast.FunctionDef) and n.name=='stage_program']
    need(len(nodes)==1,'one_reviewed_fixed_P4_stage_recipe')
    pure={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<fixed-stage-recipe>','exec'),pure)
    value=verify_root_phase(context,'p4-stage',SSH+[shlex.join(['/usr/bin/python3','-I','-B','-c',pure['stage_program']()])],
        45,S.enc(packet))
    need(strict(value)=={'state':'EXACT_SOURCE_AND_CASE_STAGED_NO_PHONE','case_sha256':sha(case_raw),'phone_calls':0},
         'actual_P4_create_only_case_stage')
    raw=read.read(run['p4_capture_plan'],65536);inp=O.P4+'/fault-p4-capture-inputs-r1/'+plan['nonce']
    value=verify_root_phase(context,'p4-capture-plan',SSH+[shlex.join(['/usr/bin/python3','-I','-B','-c',
        S.p4_plan_stage_program(inp,sha(raw))])],30,raw)
    need(value==b'STAGED_EXACT_PLAN_NO_PHONE\n','actual_P4_capture_plan_stage')
    argv=['/usr/bin/python3','-I','-B',root+'/source/capture_fault_p4.py','--plan',inp+'/PLAN.json',
        '--plan-sha256',sha(raw),'--self-sha256',sha(files['source/capture_fault_p4.py']),'--execute-read-once']
    output=verify_root_phase(context,'p4-sender-capture',SSH+[shlex.join(argv)],90,None)
    result=strict(output);cap=context['p4']['capture'];members=context['p4']['members']
    out=O.P4+'/fault-p4-original-captures-r1/'+plan['nonce'];archive=result['archive']
    body=read.read(run['p4_archive'],O.MAX_ARCHIVE)
    need(result['schema']=='hepta.physical-fault.p4-capture-result.v1' and
         result['state']==cap['state'] and result['phone_calls']==0 and result['physical_case_pass'] is False and
         result['automatic_retry'] is False and result['originals_rechecked_after_archive'] is True and
         result['archive_member_count']==len(members) and result['capture']==S.desc(out+'/CAPTURE.original.json',members['CAPTURE.original.json']) and
         archive==S.desc(out+'/ORIGINALS.tar.gz',body),'actual_owned_P4_capture_result_and_archive')
    expected_result=dict(result);expected_result.pop('result')
    need(result['result']==S.desc(out+'/RESULT.json',O.encoded(expected_result)),
         'original_P4_capture_result_file_pin')
    chunks=[];count=(archive['bytes']+524287)//524288
    for index in range(count):
        value=verify_root_phase(context,'p4-archive-chunk-%03d'%index,
            SSH+[shlex.join(['/usr/bin/python3','-I','-B','-c',S.p4_archive_chunk_program(archive,index)])],30,None)
        row=strict(value);chunk=S.decode(row['base64'],524288)
        need(row['offset']==index*524288 and row['bytes']==len(chunk) and row['sha256']==sha(chunk),
             'actual_P4_sender_archive_chunk')
        chunks.append(chunk)
    need(b''.join(chunks)==body,'actual_P4_full_original_archive_readback')
    return {'p4-stage','p4-capture-plan','p4-sender-capture'}|{'p4-archive-chunk-%03d'%i for i in range(count)}


def native_prefix(context,api):
    phone=context['phone'];cap=phone['capture'];scope=context['execution']['scope']
    ds=[r for r in cap['directories'] if r['source_path']==NATIVE]
    need(len(ds)==1 and ds[0]['state']=='observed','complete_native_source_directory')
    expected=[NATIVE+'/'+n for n in ds[0]['names'] if n.endswith('.jsonl')]
    need([r['source_path'] for r in cap['native_sources']]==expected and expected,'complete_native_segments')
    records=[];selected=[]
    for row in cap['native_sources']:
        source=row['source_path'];name,original=phone['sources'][source];raw=phone['members'][name]
        need(row['state']=='scanned_to_eof' and row['bytes_scanned']==len(raw) and
             row['whole_file_sha256']==sha(raw) and row['stat']==original['stat_before'],'whole_native_segment_bytes')
        offset=0
        for number,line in enumerate(raw.splitlines(keepends=True),1):
            need(line.endswith(b'\n') and len(line)<=4*1024*1024,'complete_native_line')
            value=strict(line);api.record_hashes(value);records.append(value)
            need(len(records)<=131072,'native_record_bound')
            if value.get('scope')==scope:selected.append((value,line,source,offset,number))
            offset+=len(line)
    audit=api.verify_records(records,scope)
    need(audit['status']=='PASS' and not audit['errors'] and not audit['unsupported'] and
         not audit['unobserved_global_sequence_gaps'],'native_full_hash_chain_not_verified')
    selected.sort(key=lambda x:x[0]['store_seq'])
    need(b''.join(v[1] for v in selected)==phone['members']['selected-native-raw.jsonl'] and
         len(selected)==len(cap['native_raw_records']),'native_selected_raw_original_subset')
    for item,row in zip(selected,cap['native_raw_records']):
        value,line,source,offset,number=item
        need(row=={'source_path':source,'line_1based':number,'offset':offset,'bytes':len(line),
            'sha256':sha(line),'store_seq':value['store_seq'],'turn_seq':value['turn_seq'],'kind':value['kind']}
            and value['payload']['request_sha256']==context['execution']['native_request_sha256'],
            'native_original_record_location_and_request')
    frames=audit['frames']
    need(frames[-1]['kind']=='turn.end' and frames[-1]['payload'].get('status')=='provider_failed' and
         not any(f['kind']=='turn.cancel.accepted' for f in frames),'fault_native_failure_without_cancel')
    return frames,{k:v for k,v in audit.items() if k not in ('selected_records','frames')},selected


def load_apis(context,snapshot):
    bodies=context['admitted']['operator_sources'];ns={'base64':base64,'hashlib':hashlib,'json':json,'re':re,'Path':snapshot.Path}
    audit=S.module(bodies['source/native_journal_audit.py'],'native_journal_audit.py','fault_native_audit')
    page=S.module(bodies['source/reviewed_page_projection.py'],'reviewed_page_projection.py','fault_public_page')
    decoder_raw=context['files']['reference/decode_client_state.py']
    decoder=P.projected(decoder_raw,{'decode_client_state'},{'UUID','HEX64','DOMAINS'},
        dict(ns,hmac=hmac,struct=struct))
    cleanup=P.projected(context['files']['reference/model_slot_cleanup.py'],
        {'require','validate_original_records','assess_original'},(),dict(ns,strict_json=strict))
    model=P.projected(context['files']['reference/close_original_r10.original.py'],
        {'original_http','verify_cleanup'},(),dict(ns,need=need,sha=sha,strict=strict,zero=lambda v:type(v) is int and v==0))
    ledger_raw=context['files']['source/ledger_prefix_fault.py'];parent=context['files']['reference/ledger_prefix_audit.original.py']
    old="    require(capture.get('state')=='CAPTURED_BOUND_ORIGINALS'\n"
    new="    require(capture.get('schema')=='hepta.physical-fault.phone-original-capture.v1'\n            and capture.get('state')=='CAPTURED_NEGATIVE_ORIGINALS_UNQUALIFIED'\n"
    old2="    require(len(directories)==1 and directories[0].get('state')=='observed',\n            'original complete ledger directory listing differs')\n"
    new2="    require(1<=len(directories)<=2 and all(exact(row,directories[0]) for row in directories)\n            and directories[0].get('state')=='observed',\n            'negative collector ledger directory observations differ')\n    # This exact collector visits the same ledger in capture_actions and\n    # capture_remaining_ledger. Preserve both raw rows; only equal views coalesce.\n    directories=directories[:1]\n"
    wanted=parent
    for a,b in ((old,new),(old2,new2)):
        need(wanted.count(a.encode())==1,'exact_ledger_increment_anchor');wanted=wanted.replace(a.encode(),b.encode())
    need(ledger_raw==wanted,'only_reviewed_ledger_collector_adapter')
    names={n.name for n in ast.parse(parent).body if isinstance(n,ast.FunctionDef)}
    ledger=P.projected(ledger_raw,names,{'SCOPE','MUTATIONS'},
        dict(ns,ast=ast,datetime=datetime,strict_loads=strict))
    return types.SimpleNamespace(audit=audit,page=page,decoder=decoder,cleanup=cleanup,model=model,ledger=ledger)


def provider(context,snapshot):
    scope=context['execution']['scope'];run=context['phone']['capture']['actual_run'];p=snapshot.Path
    rd=p(ROOT)/'provider-state/evidence'/run
    iraw=snapshot.read(rd/'provider-in.jsonl');oraw=snapshot.read(rd/'provider-out.jsonl')
    need(iraw.endswith(b'\n') and oraw.endswith(b'\n'),'complete_original_provider_lines')
    incoming=[strict(x) for x in iraw.splitlines()];outgoing=[strict(x) for x in oraw.splitlines()]
    for rows in (incoming,outgoing):
        need(all(v.get('protocol')=='trillionnium.owner-open.provider-jsonl.v1' and
            type(v.get('seq')) is int and v['seq']==i for i,v in enumerate(rows)),
            'actual_provider_protocol_and_sequences')
    need(incoming[0]['kind']=='turn.start' and {k:incoming[0]['turn'][k] for k in O.SCOPE}==scope and
         incoming[0]['turn']['user_input'].encode()==context['admitted']['owner'],'exact_admitted_original_owner_scope')
    terminal=snapshot.json(rd/'terminal.json')
    need(terminal['kind']=='turn.fail' and not any(v['kind'] in ('turn.complete','turn.cancelled','turn.cancel')
        for v in incoming+outgoing),'negative_failure_never_relabelled_success')
    endings=[v for v in outgoing if v['kind'] in ('turn.complete','turn.fail','turn.cancelled')]
    need(len(endings)==1 and outgoing[-1]==endings[0] and endings[0]==terminal,'one_unchanged_provider_failure')
    business=snapshot.json(rd/'business-outcome.json')
    need(business.get('business_verified') is False,'negative_business_must_remain_false')
    return rd,incoming,outgoing,terminal,business


def actor_and_fences(context,api,frames,incoming,outgoing,terminal):
    members=context['phone']['members'];watch=context['admitted']['watch'];scope=context['execution']['scope']
    apraw=members['fault-watch/ACTOR-PLAN.original.json'];ap=strict(apraw)
    W=S.module(context['files']['source/watch_physical_fault_once.py'],'watch_physical_fault_once.py','fault_pure_watch')
    expected=W.actor_plan(watch,(context['phone']['capture']['actual_run'],scope))
    need(ap==expected and apraw==O.encoded(ap),'exact_original_signal_plan')
    need(members['fault-watch/PLAN.original.json']==context['admitted']['watch_raw'] and
         members['fault-watch/SOURCE.original.py']==context['files']['source/watch_physical_fault_once.py'],
         'actual_watch_compiled_source_plan')
    intent=strict(members['fault-actor/INTENT.json']);pre=strict(members['fault-actor/PRE-SIGNAL.json'])
    result=strict(members['fault-actor/RESULT.json']);summary=strict(members['fault-watch/RESULT.json'])
    need(intent['plan']==ap and intent['operator_manifest_sha256']==watch['fault_package_sha256'] and
         intent['automatic_retry'] is False and pre['plan_sha256']==sha(apraw),'exact_original_actor_intent')
    need(result['state']=='ONE_PIDFD_ACTION_RETURNED' and result['case_id']==context['plan']['case_id'] and
         result['scope']==scope and result['operator_manifest_sha256']==watch['fault_package_sha256'] and
         result['automatic_retry'] is False and result['physical_case_pass'] is False and
         result['pre_signal']=={'path':O.BASE+'/fault-injections-r10-r1/'+watch['owner_request_sha256']+'/PRE-SIGNAL.json',
                               'bytes':len(members['fault-actor/PRE-SIGNAL.json']),'sha256':sha(members['fault-actor/PRE-SIGNAL.json'])},
         'original_actor_single_signal_result')
    action=result['action'];case=context['plan']['case_id']
    target=pre['worker']['worker'] if case=='NEG-07' else pre['chain']['carrier']
    need(action['target_pid']==target['pid'] and action['signal']==(19 if case=='NEG-07' else 15) and
         action['syscall_returned_zero'] is True and
         0<intent['created_monotonic_ns']<=action['syscall_started_monotonic_ns']<=action['syscall_returned_monotonic_ns'] and
         action['final_revalidation']['target_identity']==[target[k] for k in ('pid','pgrp','sid','start_ticks')],
         'exact_held_pidfd_action_identity')
    phase_identity={k:pre['phase'][k] for k in ('input','output','health_contract','task_scope_originals','native','calls','action_originals')}
    need(action['final_revalidation']['final_phase_sha256']==sha(O.encoded(phase_identity)) and
         intent['created_monotonic_ns']<=action['final_revalidation']['finished_monotonic_ns']<=action['syscall_started_monotonic_ns'] and
         action['syscall_returned_monotonic_ns']-intent['created_monotonic_ns']<=30_000_000_000 and
         target['state'] not in ('T','t') and target['pid'] not in
         {1,pre['chain']['native_parent']['pid'],*[r[0] for r in watch['roles'].values()]},
         'immediate_same_phase_revalidation_and_original_30s_actor_budget')
    need(pre['phase']['native']['native_terminal'] is None and pre['phase']['native']['cancel_acceptances']==0 and
         pre['phase']['native']['native_request_sha256']==context['execution']['native_request_sha256'],
         'actual_fault_before_native_terminal')
    prefix=pre['phase']['native']['native_originals']
    need(0<len(prefix)<len(frames),'actual_pre_signal_native_prefix_without_end')
    for index,row in enumerate(prefix):
        raw=S.decode(row['raw_b64'],4*1024*1024);name,unused=context['phone']['sources'][row['source']]
        full=members[name]
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and
             full[row['offset']:row['offset']+len(raw)]==raw and strict(raw)['payload']['frame']==frames[index],
             'actual_pre_signal_native_raw_prefix_location')
    claim_source=str(W.claim_path(scope));name,unused=context['phone']['sources'][claim_source]
    need(sha(members[name])==pre['chain']['claim_sha256'],'original_consumed_claim_unchanged_after_signal')
    for name,actual in (('input',incoming),('output',outgoing)):
        raw=base64.b64decode(pre['phase'][name]['raw_b64'],validate=True)
        selected=[strict(x) for x in raw.splitlines()]
        need(pre['phase'][name]['bytes']==len(raw) and pre['phase'][name]['sha256']==sha(raw) and
             actual[:len(selected)]==selected,'fault_pre_phase_is_original_prefix')
    need(summary['state']=='ONE_FAULT_AND_FINAL_ORIGINAL_OBSERVATION_RETAINED' and
         summary['actor_plan_sha256']==sha(apraw) and summary['watch_plan_sha256']==sha(context['admitted']['watch_raw']) and
         summary['watch_source_sha256']==sha(context['files']['source/watch_physical_fault_once.py']) and
         summary['physical_case_pass'] is False and summary['signal_actor_invocations']==1 and summary['followup_signals']==0 and
         0<summary['finished_monotonic_ns']-summary['started_monotonic_ns']<=240_000_000_000,
         'original_watch_complete_bounded_once')
    observed_calls=pre['phase']['calls']
    need(len(observed_calls)==(0 if case=='NEG-04' else 1),'original_fault_dispatch_phase_count')
    if case=='NEG-05':
        page=pre['public_effect'];need(type(page) is dict,'actual_public_effect_required_before_detach')
        need(0<=action['syscall_started_monotonic_ns']-page['finished_monotonic_ns']<=1_000_000_000,
             'physical_effect_observation_not_fresh_at_signal')
        qi=strict(members['fault-actor/PAGE-QUERY-INTENT.json']);qr=strict(members['fault-actor/PAGE-QUERY-RESULT.json'])
        stdout=S.decode(qr['stdout_b64'],32768);stderr=S.decode(qr['stderr_b64'],32768)
        marker='HEPTA_R9_FAULT_VIEWPORT_BOUNDARY'
        code=('set -e; [ "$(getprop ro.serialno)" = ZY22LS7WZT ]; '
              '[ "$(cat /proc/sys/kernel/random/boot_id)" = '+shlex.quote(ap['expected_boot'])+' ]; '+
              api.page.PAGE_STATE_COMMAND+'; printf "\\n'+marker+'\\n"; dumpsys display | grep "mViewports="')
        need(qi['argv']==['/proc/1/root/data/adb/magisk/busybox','chroot','/proc/1/root','/system/bin/sh','-c',code]
             and qi['command_sha256']==page['command_sha256']==sha(code.encode()) and
             qi['stock_original_sha256']=='5a7bed5c097b1ee4e560c8bd311e8e0f4d66141e4fff3fb76ae5d14e5fb9c841' and
             qi['phone_ui_actions']==qr['phone_ui_actions']==page['phone_ui_actions']==0 and
             qi['automatic_retry'] is qr['automatic_retry'] is False and
             type(qr['original_pid']) is int and qr['original_pid']>1 and qr['original_pid']!=target['pid'] and
             qr['returncode']==page['helper_exit_code']==0 and stderr==b'' and
             qr['cleanup_signals_to_owned_query_group']==page['helper_cleanup_signals']==[] and
             page['stdout_b64']==qr['stdout_b64'] and page['bytes']==len(stdout) and page['stdout_sha256']==sha(stdout) and
             page['started_monotonic_ns']==qr['started_monotonic_ns']<qr['finished_monotonic_ns']<=page['finished_monotonic_ns'] and
             0<qr['finished_monotonic_ns']-qr['started_monotonic_ns']<=4_000_000_000,
             'actual_independent_readonly_page_owned_helper')
        parts=stdout.decode('utf-8').split('\n'+marker+'\n')
        need(len(parts)==2 and api.page.page_state(parts[0])==page['page'] and
             api.page.validate_viewport(parts[1])==page['viewport_sha256'] and
             page['page']['component']==ap['expected_probe_component'] and page['numeric_effect_count_claimed'] is False,
             'original_public_probe_page_and_viewport_readback')
    if case=='NEG-07':
        before=strict(members['fault-watch/PRE-LATE-FENCE.json'])
        after=strict(members['fault-watch/POST-LATE-FENCE.json'])
        durable=strict(members['fault-watch/PRE-LATE-DURABILITY.json'])
        late=strict(members['fault-watch/LATE-RECEIPT-OBSERVATION.json'])
        pending=base64.b64decode(before['pending_receipt']['raw_b64'],validate=True)
        for value,name in ((before,'PRE-LATE'),(after,'POST-LATE')):
            need(value['schema']=='hepta.physical-fault.four-original-visibility-fence.v1' and
                 value['case_id']==case and value['owner_request_sha256']==watch['owner_request_sha256'] and
                 value['scope']==scope and value['run']==ap['run'] and value['name']==name and
                 set(value['originals'])=={'terminal','provider_input','provider_output','claim'} and
                 value['clock']=='phone time.monotonic_ns same watch process' and
                 value['all_four_raw_files_bookended_equal'] is True and value['original_production_files_written']==0 and
                 value['automatic_redispatch'] is False,'original_before_after_fence_case_identity')
        pendingv=strict(pending);late_raw=members['fault-watch/LATE-RECEIPT.original.json'];latev=strict(late_raw)
        need(pendingv['terminal'] is False and pendingv['state']=='running' and latev['terminal'] is True and
             pendingv['action_id']==latev['action_id']==observed_calls[0]['action_id'] and
             pendingv['command_sha256']==latev['command_sha256']==observed_calls[0]['command_sha256'],
             'real_before_late_and_later_receipt_identity')
        pending_row=before['pending_receipt']['original'];late_row=late['original']
        O.metadata(pending_row['stat_before']);O.metadata(late_row['stat_before'])
        need(pending_row['bytes']==len(pending) and pending_row['sha256']==sha(pending) and
             pending_row['stat_before']==pending_row['stat_after'] and pending_row['eof'] is True and
             late_row['bytes']==len(late_raw) and late_row['sha256']==sha(late_raw) and
             late_row['stat_before']==late_row['stat_after'] and late_row['eof'] is True and
             pending_row['path']==late_row['path']==O.BASE+'/executor-r6/actions/'+observed_calls[0]['action_id']+'/receipt.json' and
             late['original_dispatch_identity']=={'action_id':observed_calls[0]['action_id'],'call_id':observed_calls[0]['call_id']} and
             latev['waitpid_joined'] is True and latev['process_group_absent'] is True and latev['waitpid_identity_lost'] is False,
             'same_actual_before_and_late_receipt_full_metadata_and_cleanup')
        late_name,late_final=context['phone']['sources'][late_row['path']]
        need(members[late_name]==late_raw and late_final['stat_before']==late_row['stat_before'],
             'actual_late_receipt_is_final_original_sidecar_receipt')
        need(action['syscall_returned_monotonic_ns']<=before['started_monotonic_ns']<=before['finished_monotonic_ns']
             <=durable['observed_after_all_four_copies_and_fence_fsync_monotonic_ns']<late['observed_monotonic_ns']
             <=after['started_monotonic_ns']<=after['finished_monotonic_ns'] and
             before['pending_receipt_unchanged_across_reads'] is True,'real_same_process_visibility_order')
        need(durable['schema']=='hepta.physical-fault.before-late-durable-bookend.v1' and
             durable['receipt_still_running_after_fence_persistence'] is True and
             durable['same_original_pending_receipt']==before['pending_receipt']['original'] and
             durable['fence']=={'path':O.BASE+'/fault-watch-r10-r1/'+watch['owner_request_sha256']+'/PRE-LATE-FENCE.json',
                'bytes':len(members['fault-watch/PRE-LATE-FENCE.json']),
                'sha256':sha(members['fault-watch/PRE-LATE-FENCE.json'])},
             'actual_before_late_fence_durable_bookend')
        for key in ('terminal','provider_input','provider_output','claim'):
            b=before['originals'][key];a=after['originals'][key]
            O.metadata(b['original']['stat_before'])
            need(b['original']==a['original'] and b['original']['stat_before']==b['original']['stat_after'] and
                 b['original']['eof'] is True,'late_result_rewrote_prior_original_fence')
            braw=members['fault-watch/PRE-LATE-'+key+'.original'];araw=members['fault-watch/POST-LATE-'+key+'.original']
            need(braw==araw and len(braw)==b['original']['bytes'] and sha(braw)==b['original']['sha256'],
                 'actual_four_fence_original_bytes')
            prefix=O.BASE+'/fault-watch-r10-r1/'+watch['owner_request_sha256']+'/'
            need(b['retained']==S.desc(prefix+'PRE-LATE-'+key+'.original',braw) and
                 a['retained']==S.desc(prefix+'POST-LATE-'+key+'.original',araw),'actual_four_fence_retained_file_pins')
            source=b['original']['path'];name,orig=context['phone']['sources'][source]
            need(context['phone']['members'][name]==braw and orig['stat_before']==b['original']['stat_before'],
                 'final_archive_cannot_replace_before_late_original')
        before_input=[strict(x) for x in members['fault-watch/PRE-LATE-provider_input.original'].splitlines()]
        deadline=W.terminal_deadline(before_input,observed_calls[0]['call_id'])
        need(deadline==strict(members['fault-watch/ORIGINAL-DEADLINE-RESULT.json']),
             'actual_native_result_deadline_before_late')
    return {'single_original_pidfd_action':True,'pre_signal_dispatch_count':len(observed_calls),
        'unknown_wire_outcome_not_upgraded_by_later_receipt':True,'late_fence_verified':case=='NEG-07',
        'automatic_redispatch':False,'original_actor_signal':action['signal']},ap,summary


def effects_and_models(context,snapshot,api,frames,rd,incoming,outgoing,ap):
    scope=context['execution']['scope'];case=context['plan']['case_id'];p=snapshot.Path
    state=p(ROOT)/'provider-state';source=p(ROOT)/'sources/provider-r10/source'
    seal=snapshot.json(p(ROOT)/'sources/provider-r10/SOURCE-SEAL-v150-r10.json')
    calls=[v['call'] for v in outgoing if v['kind']=='tool.call']
    results=[v for v in incoming if v['kind']=='tool.result']
    need(len(calls)==(0 if case=='NEG-04' else 1) and len({v['call_id'] for v in calls})==len(calls),
         'exact_fault_dispatch_count_no_second_effect')
    need(len(results)==(1 if case=='NEG-07' else 0),'fault_expected_original_result_visibility')
    native_calls=[f for f in frames if f['kind']=='tool.accepted']
    need(len(native_calls)==len(calls) and {f['call_id'] for f in native_calls}=={v['call_id'] for v in calls},
         'native_and_provider_dispatch_count_agree')
    need(all(not f['kind'].startswith('tool.') or f.get('call_id') in {v['call_id'] for v in calls}
         for f in frames),'no_unaccounted_native_tool')
    ledger=api.ledger.audit(snapshot,rd,state,scope,context['admitted']['owner'],seal,
        p(ROOT)/'CAPTURE.json',calls,source)
    need(ledger.get('status')=='PASS' and ledger.get('complete_prefix_reconstruction') is True and
         ledger.get('unaccounted_original_intents')==[],'complete_global_ledger_prefix_not_verified')
    baseline=snapshot.json(rd/'ledger-prefix/baseline.json')
    ld=state/'evidence/action-ledger'
    for old in baseline['initial_auxiliary_originals']:
        raw=snapshot.read(ld/old['name'],required=False)
        need(raw is None if old['state']=='absent' else raw==base64.b64decode(old['raw_base64'],validate=True),
             'unrelated_baseline_ledger_auxiliary_changed')
    business=P.business_api(context,snapshot);rows=[]
    for call in calls:
        result=next((r for r in results if r.get('call_id')==call['call_id']),None)
        proof=business.inspect_tool(snapshot,rd,state,p(ROOT)/'executor-r6',p(ROOT)/'client-receipts',scope,call,result,frames)
        need(proof['semantic_tool']=='phone.open_app' and proof.get('dispatch_count')==1 and
             proof.get('safe_original_execution_terminal') is True and
             proof.get('r6_terminal_identity_and_cleanup_verified') is True,
             'original_disposable_effect_and_r6_cleanup_not_verified')
        semantic=snapshot.json(rd/('semantic-'+sha(call['call_id'].encode())+'.json'))
        need(api.page.component(semantic['component'])==ap['expected_probe_component'] and semantic['turn']==scope,
             'only_original_approved_probe_action')
        # A later sidecar terminal is a cleanup fact. It does not repair the
        # failed native wire or change the provider's unconfirmed outcome.
        if case=='NEG-05':need(result is None and proof['provider_result_present'] is False,
                              'disconnected_original_result_was_not_consumed')
        if case=='NEG-07':
            need(result['terminal']['kind']=='timed_out' and proof['successful_original_execution'] is False,
                 'timed_out_original_cannot_be_full_success')
        rows.append(proof)
    need(context['phone']['capture']['original_dispatched_action_ids']==[r['action_id'] for r in rows],
         'complete_original_dispatched_action_inventory')
    model_rows=[];captured=context['phone']['capture']['model_requests_captured']
    need((0 if case=='NEG-04' else 1)<=len(captured)<=8,'bounded_actual_model_request_inventory')
    run_prefix='provider-state/evidence/'+context['execution']['provider_run']+'/'
    request_names=sorted(name for name in context['phone']['members'] if name.startswith(run_prefix) and
        Path(name).parent==Path(run_prefix) and re.fullmatch(r'local-[0-9]{2}\.request\.json',Path(name).name))
    need(len(request_names)==len(captured),'no_unbound_partial_model_request_can_be_omitted')
    if not captured:
        need(not any(name.startswith(run_prefix) and Path(name).parent==Path(run_prefix) and
             re.match(r'local-[0-9]{2}[.]',Path(name).name) for name in context['phone']['members']),
             'zero_POST_requires_complete_original_no_model_attempt_files')
    ready=strict(context['phone']['members']['readiness/ACTUAL-READY.original.json'])
    runtime=context['phone']['plan']['runtime']
    for number,row in enumerate(captured,1):
        stem=rd/('local-%02d'%number);body=snapshot.read(str(stem)+'.request.json')
        identity=snapshot.json(str(stem)+'.request-identity.json')
        need(identity['request_id']==row['request_id'] and identity['request_sha256']==sha(body),
             'actual_single_model_request_identity')
        model_rows.append(api.model.verify_cleanup(snapshot,{'ready':ready,'runtime':runtime},p(ROOT),rd,
            number,api.cleanup,body,row['request_id']))
    return {'global_ledger':ledger,'original_tool_receipts':rows,'original_dispatch_count':len(calls),
        'confirmed_later_r6_cleanup_count':len(rows),'semantic_second_effect_count':0,
        'earlier_wire_unknown_preserved':case in ('NEG-04','NEG-05'),
        'late_receipt_is_not_business_success':True,'model_original_cleanups':model_rows,
        'automatic_redispatch':False}


def generation_and_scope(context,snapshot,ap):
    phone=context['phone'];members=phone['members'];p=snapshot.Path
    ready_raw=members['readiness/ACTUAL-READY.original.json'];ready=strict(ready_raw)
    need(ready_raw==base64.b64decode(context['admitted']['watch']['runtime_binding']['readiness']['raw_b64'],validate=True),
         'captured_actual_READY_is_exact_admitted_original')
    need(members['observations/KERNEL-BEFORE.json']==members['observations/KERNEL-AFTER.json'],
         'actual_kernel_policy_boot_bookends')
    kernel=strict(members['observations/KERNEL-BEFORE.json']);final=context['admitted']['final']
    need(kernel['boot_id']==ap['expected_boot'] and kernel['policy']==final['live_policy'] and
         kernel['observer_uid']==kernel['observer_gid']==0 and
         base64.b64decode(kernel['enforce_original_b64'],validate=True) in (b'1',b'1\n') and
         base64.b64decode(kernel['domain_original_b64'],validate=True).rstrip(b'\0\n')==b'u:r:magisk:s0',
         'actual_Enforcing_policy_original_generation')
    pending=strict(members['observations/SELECTED-PENDING-ABSENCE.json'])
    need(set(pending)=={'before','after'} and pending['before']==pending['after'] and
         pending['before']['source']=='/proc/1/root/data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.pending' and
         type(pending['before']['lookup_errno']) is int and pending['before']['lookup_errno']==2,
         'actual_selected_pending_absence_bookends')
    O.metadata(pending['before']['parent_metadata'],True)
    sealraw=members['sources/provider-r10/SOURCE-SEAL-v150-r10.json'];seal=strict(sealraw)
    need(sha(sealraw)==ap['release_pins']['source_seal_sha256'],'actual_frozen_source_seal')
    fixed=strict(context['admitted']['operator_sources']['source/production-pins.json'])
    need(len(seal['production_files'])==15 and len({r['path'] for r in seal['production_files']})==15,
         'actual_fifteen_sealed_production_members')
    expected={r['path'].split('/')[-1]:{'bytes':r['bytes'],'sha256':r['sha256']} for r in seal['production_files']}
    # The reviewed package's production-pins file is itself part of the exact
    # immutable operator inventory. Normalize only its documented container.
    pins=fixed.get('files',fixed.get('production_sources',fixed))
    if isinstance(pins,list):pins={Path(r['path']).name:{'bytes':r['bytes'],'sha256':r['sha256']} for r in pins}
    if all(isinstance(v,str) for v in pins.values()):
        need({k:v['sha256'] for k,v in expected.items()}==pins,'operator_current_production_SHA_set')
    else:need(expected==pins,'operator_current_production_byte_set')
    for row in seal['production_files']:
        raw=members['sources/provider-r10/'+row['path']]
        need((len(raw),sha(raw))==(row['bytes'],row['sha256']),'actual_captured_production_source')
    need(members['sources/local-config-r10.json']==context['originals'].read(context['plan']['configuration']) and
         members['sources/PHONE-SERVICE-INPUTS-v150-r10.json']==context['originals'].read(context['plan']['service']),
         'actual_shared_config_service_originals')
    owner=context['admitted']['owner'];wanted=sha(owner);scope=context['execution']['scope']
    rd=p(ROOT)/'provider-state/evidence'/phone['capture']['actual_run']
    template_raw=snapshot.read(p(ROOT)/'provider-state/task-contracts/templates'/(wanted+'.json'))
    template=strict(template_raw);binding_raw=snapshot.read(p(ROOT)/'provider-state/task-contracts/bindings'/(wanted+'.json'))
    binding=strict(binding_raw);wrapper=snapshot.json(rd/'task-contract.json');resolved=snapshot.json(rd/'task-app-scope.json')
    identity={k:scope[k] for k in O.SCOPE[:-1]}
    post_raw=members['sources/provider-r10/source/task_postconditions.py']
    post=P.projected(post_raw,{'require','app_scope_hash','validate_app_scope','resolve_task_apps','validate_conditions','validate_template'},
        {'SHA','ID','PACKAGE','VIEW','APP_COMPONENT','TASK_VERSIONS','APP_SCOPE_SCHEMA'},
        dict(hashlib=hashlib,json=json,re=re,ProviderError=O.Unverified))
    post.validate_template(template);config=strict(members['sources/local-config-r10.json'])
    post.validate_app_scope(template['app_scope'],wanted,config['approved_apps'])
    need(context['phone']['plan']['app_scope_sha256']==post.app_scope_hash(template['app_scope']),
         'phone_capture_registered_app_scope_hash')
    need(template['schema']=='hepta.task-template.v150.3' and sha(template_raw)==ap['task_template_sha256'] and
         template['request_sha256']==wanted and template['nonce']==ap['nonce'] and
         template['expected_scope']=={k:scope[k] for k in ('session_id','profile_id')} and
         template['app_scope']==ap['app_scope'],'actual_original_v150_3_owner_contract')
    need(binding==dict(schema='hepta.task-template-binding.v150.3',identity=identity,request_sha256=wanted,
        template_sha256=sha(template_raw),nonce=ap['nonce'],state='consumed_no_reuse',app_scope=template['app_scope'],
        app_scope_sha256=post.app_scope_hash(template['app_scope'])),'original_consumed_template_binding')
    contract=dict(schema='hepta.task-contract.v150.3',identity=identity,request_sha256=wanted,
        postconditions=template['postconditions'],coverage=template['coverage'],app_scope=template['app_scope'])
    need(wrapper==dict(contract=contract,source_sha256=sha(json.dumps(contract,sort_keys=True,ensure_ascii=False,
        separators=(',',':')).encode()),binding_kind='one_time_request_template',template_sha256=sha(template_raw),
        binding_sha256=sha(binding_raw)),'actual_original_contract_wrapper')
    selected,expected_scope=post.resolve_task_apps(wrapper,wanted,config['approved_apps'])
    need(resolved==expected_scope,'actual_resolved_owner_app_scope')
    claim_key=phone['capture']['claim_key'];claim=snapshot.json(p(ROOT)/'provider-state/evidence/claims'/claim_key)
    need(claim['state']=='accepted_no_redispatch' and claim['identity']==scope and claim['request_sha256']==wanted,
         'original_semantic_identity_remains_consumed')
    return {'source_seal_sha256':sha(sealraw),'actual_READY_sha256':sha(ready_raw),
        'actual_policy_sha256':final['live_policy']['sha256'],'same_boot_Enforcing':True,
        'one_use_claim_still_consumed':True,'actual_request_bound_app_scope_verified':True}


def fault_contract(context):
    raw=context['files']['reference/original-protocol.json']
    need((len(raw),sha(raw))==S.PROTOCOL_PIN,'unchanged_fixed19_protocol')
    value=strict(raw);rows=[r for r in value['cases'] if r['id']==context['plan']['case_id']]
    need(len(rows)==1 and rows[0]['required_qualification_layers']==['host_isolated','physical_native_task'] and
         rows[0]['required_metrics']==['latency','usage','cost','resources','evidence','restoration'] and
         rows[0]['expected_business_verified'] is False and value['limits']['turn_deadline_seconds']==300,
         'separate_fixed_fault_contract')
    return rows[0]


def verify(context):
    plan=context['plan'];run=context['execution'];files=context['files'];ad=context['admitted']
    need(run['schema']=='hepta.physical-fault.execution-originals.v1' and run['root_plan_sha256']==sha(context['plan_raw'])
        and run['case_id']==plan['case_id'] and run['nonce']==plan['nonce'] and run['automatic_retry'] is False,
        'actual_execution_binding')
    contract=fault_contract(context)
    stage_request,bundle_ref=S.operator_stage_request(ad['operator_bundle'],plan['nonce'])
    stage_raw,_=phone_phase(context,'operator-stage',stage_request)
    need(strict(stage_raw)=={'state':'EXACT_STATIC_OPERATOR_BUNDLE_STAGED_NO_TASK','original':bundle_ref,
        'new_send':0,'new_signal':0},'actual_exact_static_operator_bundle_stage')
    request=S.source_request(files['source/watch_physical_fault_once.py'],ad['watch_raw'],'watch',bundle_ref)
    watcher,_=phone_phase(context,'watch',request);watch_result=strict(watcher)
    need(watch_result['scope']==run['scope'] and watch_result['run']==run['provider_run'],
         'original_live_watch_scope')
    armed_raw,_=phone_phase(context,'armed-read',S.armed_request(ad['watch'],files['source/watch_physical_fault_once.py'],ad['watch_raw']))
    armed=strict(armed_raw)
    need(armed['watch_plan_sha256']==sha(ad['watch_raw']) and armed['watch_source_sha256']==sha(files['source/watch_physical_fault_once.py']),
         'actual_watch_armed_before_Send')
    cp_raw=context['originals'].read(run['phone_capture_plan'],65536)
    capture_request=S.source_request(files['source/capture_fault_phone.py'],cp_raw,'capture')
    captured,_=phone_phase(context,'capture',capture_request);capture_result=strict(captured)
    context['phone']=phone_archive(context,capture_result,cp_raw)
    need(context['phone']['members']['fault-watch/RESULT.json']==O.encoded(watch_result),
         'captured_watch_result_is_actual_original_stdout')
    context['p4']=p4_archive(context)
    expected_p4=p4_operations(context)
    context['raw_sources']={'business':files['reference/collect_business_evidence.original.py']}
    snapshot=P.FrozenSnapshot(context);api=load_apis(context,snapshot)
    frames,native,selected=native_prefix(context,api.audit)
    rd,incoming,outgoing,terminal,business=provider(context,snapshot)
    actor,ap,watch=actor_and_fences(context,api,frames,incoming,outgoing,terminal)
    generation=generation_and_scope(context,snapshot,ap)
    effects=effects_and_models(context,snapshot,api,frames,rd,incoming,outgoing,ap)
    sender=verify_sender(context,api,selected)
    need(sender['send_to_terminal_observed_seconds']<=300,'actual_native_turn_exceeded_original_300s_bound')
    # The exact source-generated archive request is rechecked for every
    # complete chunk; an imported archive alone cannot attest transport.
    chunk_count=(capture_result['archive']['bytes']+524287)//524288
    joined=[]
    for index in range(chunk_count):
        chunk_raw,_=phone_phase(context,'archive-chunk-%03d'%index,S.archive_chunk_request(capture_result['archive'],index))
        chunk=strict(chunk_raw);body=S.decode(chunk['base64'],524288)
        need(chunk['offset']==index*524288 and chunk['bytes']==len(body) and chunk['sha256']==sha(body),'actual_archive_chunk')
        joined.append(body)
    need(b''.join(joined)==context['originals'].read(run['phone_archive'],O.MAX_ARCHIVE),'actual_full_archive_readback')
    expected_phone={'phone-operator-stage','phone-watch','phone-armed-read','phone-capture'}|{'phone-archive-chunk-%03d'%i for i in range(chunk_count)}
    need({n for n in run['phases'] if n.startswith('phone-')}==expected_phone,'no_unaccounted_phone_phase')
    need(set(run['phases'])==expected_phone|expected_p4|{'sender-preview','negative-sender'},
         'complete_root_effect_and_collection_phase_closed_set')
    usage=[]
    for row in effects['model_original_cleanups']:
        name='provider-state/evidence/'+run['provider_run']+'/local-%02d.http-receipt.json'%row['round']
        value=strict(context['phone']['members'][name]) if name in context['phone']['members'] else None
        usage.append({'round':row['round'],'original':name,'value':None if value is None else value.get('usage')})
    metrics={'latency':{'send_to_native_terminal_observed_seconds':sender['send_to_terminal_observed_seconds'],
        'phone_watch_elapsed_seconds':(watch['finished_monotonic_ns']-watch['started_monotonic_ns'])/1e9},
        'usage':{'original_rows':usage,'absent_value_is_not_zero':True},
        'cost':{'value':None,'billing_not_observed':True},
        'resources':{'model_original_cleanups':effects['model_original_cleanups'],
                     'sidecar_original_terminal_cleanup_count':effects['confirmed_later_r6_cleanup_count']},
        'evidence':{'phone_archive':run['phone_archive'],'P4_archive':run['p4_archive'],**generation},
        'restoration':sender['draft_restoration']}
    return {'schema':'hepta.physical-fault.original-closure.v1',
        'state':'PHYSICAL_FAULT_ORIGINALS_VERIFIED_PENDING_ROOT_VERIFIER_JOIN',
        'case_id':plan['case_id'],'nonce':plan['nonce'],'scope':run['scope'],
        'native_request_sha256':run['native_request_sha256'],'owner_request_sha256':sha(ad['owner']),
        'source_package':run['source_package'],'root_plan_sha256':sha(context['plan_raw']),
        'native_status':'provider_failed','business_verified':False,'physical_originals_verified':True,
        'physical_case_pass':False,'host_isolated_not_inferred':True,'whole_case_pass':False,
        'actual_model_not_fixture':True,'native_full_captured_prefix':native,'actor':actor,'effects':effects,
        'sender':sender,'generation':generation,'metrics':metrics,'automatic_retry':False,
        'new_send':0,'new_signal':0,'new_phone_call':0,'pending_root_owned_verifier_join':True}


def verify_sender(context,api,selected):
    plan=context['plan'];data={**plan['sender_inputs'],**context['execution']['sender']};originals=context['originals'];actor_plan=dict(context['admitted']['watch']);actor_plan['request_b64']=actor_plan['owner_request_b64'];plan={**plan,'scope':context['execution']['scope'],'native_request_sha256':context['execution']['native_request_sha256'],'owner_request_sha256':sha(context['admitted']['owner'])}
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
    values={k:O.literal(generated,k) for k in
        ('label','reset_probe','preserved_draft','expected','previous_identity','previous_digest',
         'evidence_mode','component_binding','retirement_binding','READ_ONLY_PROBE_SOURCE')}
    need(values['label']==label and values['reset_probe'] is False and
         values['preserved_draft'].encode()==draft and values['expected'].encode()==owner and
         values['previous_identity']==previous['identity'] and values['previous_digest']==previous['request_sha256'] and
         values['evidence_mode']=='production' and values['component_binding'] is None,
         'actual_sender_generated_actor_inputs')
    need(values['retirement_binding']['resolution_sha256']==sha(retirement_raw),
         'actual_sender_retirement_original')
    sender_raw=originals.read(plan['sender_source'],65536)
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
    argv=['/usr/bin/python3','-I','-B',plan['sender_source']['path'],label,
          data['request']['path'],data['previous']['path'],'--preserved-draft',data['preserved_draft']['path'],
          '--retirement-resolution',data['retirement_resolution']['path'],
          '--evidence-root','production','--execute-once']
    preview_raw=verify_root_phase(context,'sender-preview',argv[:-1],30,None)
    preview=strict(preview_raw)
    need(preview['state']=='BUILT_ONLY_NO_PHONE' and preview['phone_calls']==preview['send_attempts']==0 and
         preview['actor_sha256']==sha(generated) and
         originals.known(Path(context['plan']['out'])/'SENDER-PREVIEW.original.json',65536)[1]==preview_raw and
         originals.known(Path(context['plan']['out'])/'SENDER-PREVIEW-ACTOR.original.py',262144)[1]==generated,
         'original_preview_exactly_matches_one_executed_sender_actor')
    stdout=verify_root_phase(context,'negative-sender',argv,660,None)
    outer_raw=originals.read(data['send_result'],16*1024*1024)
    need(stdout==outer_raw,'sender_outer_stdout_is_original_send_result')
    outer=strict(outer_raw)
    need(set(outer)=={'rc','stdout','stderr'} and type(outer['rc']) is int and outer['rc']==0 and outer['stderr']=='',
         'actual_sender_SSH_terminal_not_zero')
    terminal=strict(outer['stdout'])
    need(terminal.get('state')=='ORIGINAL_NATIVE_TERMINAL_OBSERVED' and terminal.get('native_status')=='provider_failed' and
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
    preserved=strict(raw['PRESERVED-USER-DRAFT.json'])
    need(preserved['exact_text'].encode()==draft and preserved['utf8_sha256']==sha(draft) and
         preserved.get('restore_required') is True and preserved.get('submitted_original_draft') is False,
         'actual_pre_Send_preserved_draft')
    timing=strict(raw['SEND-NATIVE-LATENCY.json'])
    need(timing.get('schema')=='hepta.p4-send-native-terminal-latency.v150.r3' and
         timing.get('state')=='ORIGINAL_NATIVE_TERMINAL_OBSERVED' and timing.get('native_status')=='provider_failed' and
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
    restore=P.private_restoration({name:strict(raw[name]) for name in
          ('DRAFT-RESTORE-RESULT.json','PRESERVED-DRAFT-RESTORE.original.json')},label,private_raw)
    return {'original_host_parent_wait_receipt_available':True,'original_host_child_joined':True,
        'original_sender_SSH_returncode':0,'actual_send_attempt_count':1,
        'original_sender_native_terminal':'provider_failed','draft_restoration':restore,
        'original_Send_wire_state':window['send_status'],
        'original_unknown_Send_wire_preserved':unknown,
        'wire_unknown_is_not_relabelled_success':True,
        'native_terminal_independently_verified_after_original_wire':True,
        'selected_state_checksum_and_compare_and_set_verified':True,
        'actual_UI_actions_occurred':True,'operator_restoration_is_not_model_business':True,
        'send_to_terminal_observed_seconds':timing['send_to_terminal_observed_seconds'],
        'original_sender_source_sha256':sha(sender_raw),'generated_actor_source_sha256':sha(generated),
        'private_text_or_inner_digest_in_public_output':False,'automatic_replay':False}
