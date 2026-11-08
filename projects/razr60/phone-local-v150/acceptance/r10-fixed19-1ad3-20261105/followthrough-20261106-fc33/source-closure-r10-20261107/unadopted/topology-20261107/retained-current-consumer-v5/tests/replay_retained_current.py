#!/usr/bin/env python3
"""Bounded host-only replay of complete actual current retained consumers.

All mutable-system observations, phone operations and production entrypoints
are excluded. Original Mac bytes are preloaded through bounded no-follow reads
and compared again afterward. This is not phone I/O or a 90-second stage test.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
import types
import zlib

READSET=[]


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()


def full9(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read_original(path, expected, metadata=None):
    path=Path(path);need(path.is_absolute() and path.resolve(strict=True)==path,'fixed canonical Mac original path')
    before=full9(path.lstat())
    need(stat.S_ISREG(before[2]) and before[5]==1 and before[6]<=16*1024*1024,
         'bounded single-link ordinary Mac original')
    need(metadata is None or before==metadata,'retained original actual generation differs')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(full9(os.fstat(fd))==before,'Mac original open generation')
        chunks=[];size=0
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            size+=len(chunk);need(size<=16*1024*1024,'bounded complete Mac original read');chunks.append(chunk)
        raw=b''.join(chunks)
        need(full9(os.fstat(fd))==before==full9(path.lstat()),'Mac original read full9 bookend')
    finally:os.close(fd)
    need(pin(raw)==expected,'exact complete Mac original bytes')
    READSET.append({'path':str(path),'metadata':before,**pin(raw)})
    return raw


def module(raw,name):
    value=types.ModuleType(name);value.__file__='<offline-'+name+':'+pin(raw)['sha256']+'>'
    exec(compile(raw,value.__file__,'exec'),value.__dict__)
    return value


def literal_values(raw):
    result={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name):
                    try:result[target.id]=ast.literal_eval(node.value)
                    except (ValueError,TypeError):pass
    return result


class OriginalProvider:
    def __init__(self, files, proof_rows, proof_bytes):
        self.files=files;self.rows=proof_rows;self.proof=proof_bytes;self.calls=[];self.corrupt=set()
    def reset(self, corrupt=()):
        self.calls=[];self.corrupt=set(corrupt)
    def stage(self,row):
        need(type(row)is dict and set(row)=={'path','bytes','sha256','metadata'},'exact full9 retained-stage descriptor')
        key='original/'+row['path'].lstrip('/')
        need(key in self.files,'explicit retained-stage original path only')
        raw=self.files[key];need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'retained-stage complete source bytes')
        if row['path'] in self.corrupt:raw=raw[:-1]
        self.calls.append({'provider':'stage','descriptor':copy.deepcopy(row),'returned':pin(raw)})
        return raw
    def retained(self,row):
        need(type(row)is dict and set(row)=={'path','bytes','sha256'} and row.get('path') in self.rows
             and row==self.rows[row['path']],'only the fixed complete retained original descriptors')
        raw=self.proof[row['path']]
        need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'retained complete original/source bytes before explicit fault')
        if row['path'] in self.corrupt:raw=raw[:-1]
        self.calls.append({'provider':'retained','descriptor':copy.deepcopy(row),'returned':pin(raw)})
        return raw


def old_current(anchor,sources,provider):
    saved_path=sys.path[:];saved_dwb=sys.dont_write_bytecode
    present='component_common' in sys.modules;saved=sys.modules.get('component_common')
    try:
        sys.dont_write_bytecode=True
        common=module(sources['source/component_common.py'],'frozen_current_common')
        common.__reviewed_source_sha256__=pin(sources['source/component_common.py'])['sha256']
        sys.modules['component_common']=common
        current=types.ModuleType('exact_frozen_current_retained_reference')
        current.__file__='<exact-current-reference:'+pin(anchor)['sha256']+'>'
        current.__reviewed_source_sha256__=pin(anchor)['sha256']
        current.__reviewed_package_sources__=dict(sources,**{'source/late_boundary.py':anchor})
        current.__retained_stage_read_pinned__=provider.stage
        current.__retained_preaccept_read_pinned__=provider.retained
        current.__retained_failed_staged_read_pinned__=provider.retained
        current.__retained_failed_transport_read_pinned__=provider.retained
        current.__retained_failed_transport_adapter_read_pinned__=provider.retained
        exec(compile(anchor,current.__file__,'exec'),current.__dict__)
        return current
    finally:
        sys.path[:]=saved_path;sys.dont_write_bytecode=saved_dwb
        if present:sys.modules['component_common']=saved
        else:sys.modules.pop('component_common',None)


def run_case(target,method,args,kwargs,provider,*,derived,corrupt=()):
    provider.reset(corrupt);inputs=copy.deepcopy((args,kwargs));unchanged=copy.deepcopy(inputs)
    start=time.perf_counter();cpu=time.process_time()
    try:
        if method=='effective_current_prior_inventory':
            scope=(target._methods[method].__globals__ if derived else target.__dict__)
            branches=scope['non_native_sidebranches']()
            result=getattr(target,method)(*inputs[0],branches,**inputs[1])
        elif method=='reviewed_historical_source_parent_inventory' and not derived:
            boundary,inventory,closure=target.source_parent_closed_boundary_originals(*inputs[0],**inputs[1])
            result=target.effective_current_prior_inventory(boundary,inventory,target.non_native_sidebranches())
        else:
            result=getattr(target,method)(*inputs[0],**inputs[1])
        if derived:
            need(type(result)is dict and result['schema']=='hepta.UNADOPTED.retained-current-result.v1'
                 and result['producer_kind']=='current-retained-consumer' and result['method']==method
                 and result['execution_provenance']==target.provenance()
                 and result['historical_result_is_old_execution_attestation'] is False
                 and result['production_adopted'] is False and result['runtime_admission'] is False
                 and type(result['current_native_case_credit'])is int and result['current_native_case_credit']==0
                 and result['whole_stage_budget_verified'] is False,'actual new complete current result envelope')
            result=result['historical_result']
        answer={'accepted':True,'result':result}
    except Exception as error:
        answer={'accepted':False,'exception_type':type(error).__name__,'message':str(error)}
    timing={'wall_seconds':time.perf_counter()-start,'cpu_seconds':time.process_time()-cpu}
    need(inputs==unchanged,'actual current consumer changed supplied original arguments')
    return answer,copy.deepcopy(provider.calls),timing


def compare(old,new,method,args,kwargs,provider,*,label,accepted,corrupt=()):
    a,reads_a,time_a=run_case(old,method,args,kwargs,provider,derived=False,corrupt=corrupt)
    b,reads_b,time_b=run_case(new,method,args,kwargs,provider,derived=True,corrupt=corrupt)
    need(a==b,'complete current retained return/error differs: '+label+' '+
         (str(a)[:300]+' / '+str(b)[:300] if not a['accepted'] or not b['accepted'] else ''))
    need(reads_a==reads_b,'complete current original read sequence differs: '+label)
    need(a['accepted'] is accepted,'expected current retained result differs: '+label+' '+str(a)[:300])
    row={'case':label,'method':method,'accepted':accepted,'complete_return_or_exception_equal':True,
         'complete_original_read_sequence_equal':True,'original_read_count':len(reads_a),
         'original_read_sequence':pin(encoded(reads_a)),'single_case_old':time_a,'single_case_new':time_b}
    if accepted:row['complete_historical_result']=pin(encoded(a['result']))
    else:row.update({key:a[key] for key in ('exception_type','message')})
    print(json.dumps({'kind':'case-complete','case':label,'accepted':accepted,'reads':len(reads_a)},sort_keys=True),flush=True)
    return row,a


def main():
    def timeout(_sig,_frame):
        raise TimeoutError('bounded offline complete current differential 300 seconds')
    signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,300)
    packed=sys.stdin.buffer.read(1024*1024+1);need(0<len(packed)<=1024*1024,'bounded exact source payload')
    carrier=json.loads(packed);code={key:base64.b64decode(value,validate=True) for key,value in carrier['source_bytes'].items()}
    manifest_raw=base64.b64decode(carrier['mac_readset_base64'],validate=True);manifest=json.loads(manifest_raw)
    need(manifest['schema']=='hepta.offline.source-parent-mac-readset.v1' and len(manifest['files'])==29,'existing exact 29-original readset')
    files={key:read_original(row['path'],{k:row[k] for k in ('bytes','sha256')},row['metadata'])
           for key,row in manifest['files'].items()}
    anchor=files['anchor/current_late.py'];constants=literal_values(anchor)
    loader=module(code['loader'],'v5_bound_loader');candidate=loader.load_bound(code['constructor'],code['constructor'])
    adapter_constants=literal_values(code['historical_adapter']);proof=adapter_constants['FROZEN_PROOF_INPUTS']['proof']
    sources={key[len('dependency/'):]:value for key,value in files.items() if key.startswith('dependency/')}
    rows={};proof_bytes={};projections=[]
    def actual(phone,host):
        need({k:phone[k] for k in ('bytes','sha256')}=={k:host[k] for k in ('bytes','sha256')},'same pinned host/phone bytes')
        raw=read_original(host['path'],{k:host[k] for k in ('bytes','sha256')})
        rows[phone['path']]=phone;proof_bytes[phone['path']]=raw
    def manifest_pair(phone,host,phone_base64,archive,host_archive):
        raw=read_original(host['path'],{k:host[k] for k in ('bytes','sha256')})
        canonical=base64.b64decode(phone_base64,validate=True)
        need(pin(canonical)=={k:phone[k] for k in ('bytes','sha256')},'exact frozen phone-manifest representation')
        a=json.loads(raw);b=json.loads(canonical)
        need(a['archive']==host_archive and b['archive']==archive,'explicit exact original archive-path mapping')
        a['archive']=b['archive'];need(a==b,'only documented archive-path representation differs')
        rows[phone['path']]=phone;proof_bytes[phone['path']]=canonical
        projections.append({'actual_host_manifest':pin(raw),'frozen_phone_representation':pin(canonical),
                            'changed_field':'archive.path','is_fresh_phone_observation':False})
    actual(constants['RETAINED_PREACCEPT_ARCHIVE'],constants['RETAINED_PREACCEPT_HOST_ARCHIVE'])
    manifest_pair(constants['RETAINED_PREACCEPT_PHONE'],constants['RETAINED_PREACCEPT_HOST'],
        constants['RETAINED_PREACCEPT_PHONE_MANIFEST_BASE64'],constants['RETAINED_PREACCEPT_ARCHIVE'],constants['RETAINED_PREACCEPT_HOST_ARCHIVE'])
    actual(constants['RETAINED_FAILED_STAGED_ARCHIVE'],constants['RETAINED_FAILED_STAGED_HOST_ARCHIVE'])
    actual(constants['RETAINED_FAILED_STAGED_READER'],constants['RETAINED_FAILED_STAGED_HOST_READER'])
    manifest_pair(constants['RETAINED_FAILED_STAGED_PHONE'],constants['RETAINED_FAILED_STAGED_HOST'],
        constants['RETAINED_FAILED_STAGED_PHONE_MANIFEST_BASE64'],constants['RETAINED_FAILED_STAGED_ARCHIVE'],constants['RETAINED_FAILED_STAGED_HOST_ARCHIVE'])
    actual(proof['archive'],proof['host_archive']);actual(proof['reader'],proof['host_reader'])
    manifest_pair(proof['phone'],proof['host'],proof['phone_manifest_base64'],proof['archive'],proof['host_archive'])
    actual(constants['RETAINED_FAILED_TRANSPORT_ADAPTER'],constants['RETAINED_FAILED_TRANSPORT_HOST_ADAPTER'])
    need(proof_bytes[constants['RETAINED_FAILED_TRANSPORT_ADAPTER']['path']]==code['historical_adapter'],
         'payload and actual retained original adapter source agree')
    provider=OriginalProvider(files,rows,proof_bytes)
    old=old_current(anchor,sources,provider)
    params=dict(current_source=anchor,historical_sources=sources,historical_adapter_source=code['historical_adapter'],
        v4_constructor_source=code['v4_constructor'],v4_loader_source=code['v4_loader'],
        v3_constructor_source=code['v3_constructor'],v3_loader_source=code['v3_loader'],
        v2_selector_source=code['v2_selector'],v2_loader_source=code['v2_loader'],
        inventory_function=code['inventory_function'],scope_function=code['scope_function'],
        read_stage_original=provider.stage,read_retained_original=provider.retained,implementation_source=code['constructor'])
    provider.reset();new=candidate.construct(**params);need(provider.calls==[],'pure source construction does not read proof originals')
    record=old.reviewed_source_parent_records()[0]
    raw=files['original/'+record['boundary']['path'].lstrip('/')]
    inv=files['original/'+record['inventory']['path'].lstrip('/')]
    closure=files['original/'+record['closure']['path'].lstrip('/')]
    values=(json.loads(raw),json.loads(inv));kw={'original_descriptor':record['boundary']}
    print(json.dumps({'kind':'originals-and-construction-ready','original_files':len(READSET),
        'current_source':new.provenance()['actual_current_execution_source'],
        'adapter_source':new.provenance()['actual_adapter_execution_source']}),flush=True)
    positives=[];results={}
    for name in ('retained_preaccept','retained_failed_staged','retained_failed_transport'):
        row,result=compare(old,new,name,(),{},provider,label='complete-'+name,accepted=True)
        positives.append(row);results[name]=result['result']
    row,result=compare(old,new,'effective_current_prior_inventory',values,{},provider,
        label='actual-current-effective-source-parent44-to-retained49',accepted=True)
    positives.append(row);effective=result['result']
    for label in ('complete-closure-through-current-retained49','repeat-complete-closure-through-current-retained49'):
        row,result=compare(old,new,'reviewed_historical_source_parent_inventory',(raw,inv,closure),kw,provider,label=label,accepted=True)
        positives.append(row);need(result['result']==effective,'same actual complete current effective inventory')
    need(positives[-1]['original_read_count']>0
         and positives[-1]['original_read_sequence']==positives[-2]['original_read_sequence'],
         'repeat full combined entry rereads complete original sequence')
    negatives=[]
    mutations=[('r7-archive', 'retained_preaccept',constants['RETAINED_PREACCEPT_ARCHIVE']),
        ('r7-manifest','retained_preaccept',constants['RETAINED_PREACCEPT_PHONE']),
        ('r8-reader','retained_failed_staged',constants['RETAINED_FAILED_STAGED_READER']),
        ('r8-manifest','retained_failed_staged',constants['RETAINED_FAILED_STAGED_PHONE']),
        ('r8-archive','retained_failed_staged',constants['RETAINED_FAILED_STAGED_ARCHIVE']),
        ('r9-adapter','retained_failed_transport',constants['RETAINED_FAILED_TRANSPORT_ADAPTER']),
        ('r9-reader','retained_failed_transport',proof['reader']),
        ('r9-manifest','retained_failed_transport',proof['phone']),
        ('r9-archive','retained_failed_transport',proof['archive']),
        ('r9-prior-r8-archive','retained_failed_transport',constants['RETAINED_FAILED_STAGED_ARCHIVE']),
        ('r9-prior-r7-archive','retained_failed_transport',constants['RETAINED_PREACCEPT_ARCHIVE'])]
    for label,name,row in mutations:
        summary,_=compare(old,new,name,(),{},provider,label=label+'-byte-corruption',accepted=False,corrupt=(row['path'],))
        negatives.append(summary)
    row,_=compare(old,new,'retained_failed_transport',(),{},provider,label='r9-archive-before-r8-reader',accepted=False,
        corrupt=(proof['archive']['path'],constants['RETAINED_FAILED_STAGED_READER']['path']))
    negatives.append(row)
    bad=copy.deepcopy(record['boundary']);bad['metadata'][1]+=1
    row,_=compare(old,new,'reviewed_historical_source_parent_inventory',(raw,inv[:-1],closure[:-1]),
        {'original_descriptor':bad},provider,label='full9-before-inventory-before-retained-proof',accepted=False,
        corrupt=(proof['archive']['path'],));negatives.append(row)
    bad_inv=json.loads(inv);bad_inv['file_bytes_hashed']+=1
    row,_=compare(old,new,'effective_current_prior_inventory',(values[0],bad_inv),{},provider,
        label='current-inventory-accounting-before-retained-family',accepted=False);negatives.append(row)
    # Concrete result identity faults; no externally supplied receipt replaces execution.
    scope=new._methods['retained_failed_transport'].__globals__
    actual_adapter=scope['retained_failed_transport_adapter']()
    provider.reset();actual_envelope=actual_adapter.verify()
    expected=actual_adapter.provenance();envelope_rejections=[]
    faults=[]
    for key,value in [('schema','old'),('producer_kind','r7-reader'),('method','source_parent_inventory'),
        ('historical_result_is_old_execution_attestation',True),('production_adopted',True),('runtime_admission',True),
        ('current_native_case_credit',False),('current_native_case_credit',1),('whole_stage_budget_verified',True),
        ('historical_result',[])]:
        changed=copy.deepcopy(actual_envelope);changed[key]=value;faults.append((key+'='+repr(value),changed))
    changed=copy.deepcopy(actual_envelope);changed['execution_provenance']['actual_derived_adapter_source']['sha256']='0'*64
    faults.append(('wrong-actual-adapter-code',changed))
    changed=copy.deepcopy(actual_envelope);changed['execution_provenance']['historical_adapter_data_source']['sha256']='0'*64
    faults.append(('wrong-historical-adapter-data-anchor',changed))
    for label,changed in faults:
        try:candidate.decode_result(changed,kind='r9-runtime-adapter',method='verify',expected_provenance=expected)
        except ValueError as error:envelope_rejections.append({'case':label,'exception_type':'ValueError','message':str(error)})
        else:raise ValueError('required retained result envelope rejection: '+label)
    # The exact selected R9 producer proves all nested v2 paths actually ran.
    reader=actual_adapter.reader();provider.reset()
    receipt=reader.verify_retained_transport_archive(proof['archive'],read_pinned=actual_adapter.read_pinned)
    execution=receipt['execution_provenance'];constructions=execution['construction_receipt']['constructions']
    kinds={row['kind'] for row in constructions};contexts={row['context'] for row in constructions if row['kind']=='inventory-function'}
    need(kinds=={'r9-reader','r9-scope','r8-reader','r8-scope','r7-reader','inventory-function'}
         and contexts=={'r7-readers','r8-payload','r9-scope'},'actual nested v2 code selection evidence')
    standalone={}
    for kind,factory,entry,descriptor,read in [
        ('r7-reader',scope['retained_preaccept_reader'],'verify_retained_preaccept_archive',constants['RETAINED_PREACCEPT_PHONE'],scope['retained_preaccept_read_pinned']),
        ('r8-reader',scope['retained_failed_staged_reader'],'verify_retained_staged_archive',constants['RETAINED_FAILED_STAGED_PHONE'],scope['retained_failed_staged_read_pinned'])]:
        provider.reset();reader=factory();result=getattr(reader,entry)(descriptor,read_pinned=read)
        standalone[kind]=result['execution_provenance']
    r9=results['retained_failed_transport'];r8=results['retained_failed_staged'];r7=results['retained_preaccept']
    need(len(r7['inventory_roots'])==47 and len(r8['inventory_roots'])==len(r9['inventory_roots'])==49
         and effective[0]==r9['inventory_value'] and effective[1]==r9['inventory']
         and r9['global_unknown_effect_count'] is None and r9['native_terminal'] is None
         and r9['remote_cleanup_proven'] is False and r9['retirement_accepted'] is False
         and r9['native_case_credit']==0 and r9['new_nonce_authorized'] is False,
         'actual retained failure, UNKNOWN, inventory and non-admission meanings remain intact')
    before=list(READSET)
    for row in before:read_original(row['path'],{k:row[k] for k in ('bytes','sha256')},row['metadata'])
    need(READSET[len(before):]==before,'all original Mac source/archive byte/full9 bookends')
    result={'kind':'complete-current-retained-differential-report','schema':'hepta.UNADOPTED.current-retained-replay.v5',
        'state':'PASS','constructor_source':pin(code['constructor']),'bound_loader_source':pin(code['loader']),
        'complete_current_provenance':new.provenance(),'positive_cases':positives,'negative_cases':negatives,
        'new_envelope_rejections':envelope_rejections,'actual_nested_r9_reader_execution':execution,
        'actual_standalone_retained_execution':standalone,'current_effective_inventory':{'roots':len(effective[0]['roots']),
             'entries':len(effective[0]['entries']),'descriptor':effective[1],'classification':effective[2]},
        'exact_full_returns_errors_and_original_callbacks_equal':True,'repeated_full_combined_validation':True,
        'original_failure_semantics':{k:r9[k] for k in ('global_unknown_effect_count','native_terminal','remote_cleanup_proven',
            'retirement_accepted','native_case_credit','new_nonce_authorized','first_launch_receipt_gap')},
        'readset':before,'readset_after':READSET[len(before):],'all_original_byte_full9_bookends_unchanged':True,
        'host_to_frozen_phone_manifest_projections':projections,'immutable_preload_outside_validations':True,
        'phone_calls':0,'native_requests':0,'current_native_case_credit':0,'runtime_admission':False,'production_adopted':False,
        'validation_result_cache':False,'live_observation_cache':False,'complete_production_IO_metering_verified':False,
        'whole_stage_budget_verified':False,'single_case_timings_are_not_90_second_phone_stage_evidence':True,
        'python':sys.version,'source_payload_pin':pin(packed),'existing_v3_readset_pin':pin(manifest_raw)}
    signal.setitimer(signal.ITIMER_REAL,0)
    sys.stdout.buffer.write(encoded(result));sys.stdout.buffer.flush()


if __name__=='__main__':main()
