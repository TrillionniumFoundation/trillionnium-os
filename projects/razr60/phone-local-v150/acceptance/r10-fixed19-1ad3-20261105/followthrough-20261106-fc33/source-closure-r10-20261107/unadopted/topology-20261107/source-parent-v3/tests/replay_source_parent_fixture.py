#!/usr/bin/env python3
"""Complete, bounded offline comparison of the three source-parent entries.

Only explicitly pinned local/Mac retained files are read. No phone, ADB,
native request, stage, service, network, or original-file write is performed.
The immutable input-byte preload is outside timings; every validation and
nested source construction is repeated. This is not production I/O metering.
"""
from __future__ import annotations
import argparse
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import statistics
import sys
import time
import types

ANCHOR_PIN={'bytes':259866,'sha256':'f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7'}
CURRENT_NONCE='ac03e3864c1798742c472957b06ca843'
REMOTE='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/'
READSET=[]


def need(ok, why):
    if not ok:raise ValueError(why)


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()


def full9(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read_local(path, expected=None, expected_metadata=None):
    path=Path(path);before=full9(path.lstat())
    need(stat.S_ISREG(before[2]) and before[5]==1 and before[6]<=16*1024*1024,
         'bounded ordinary local original')
    need(expected_metadata is None or before==expected_metadata,'retained Mac full9 differs before read')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        need(full9(os.fstat(fd))==before,'local original open identity')
        chunks=[];size=0
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            size+=len(chunk);need(size<=16*1024*1024,'bounded original bytes')
            chunks.append(chunk)
        raw=b''.join(chunks)
        need(full9(os.fstat(fd))==before==full9(path.lstat()),'local original full9 bookend')
    finally:os.close(fd)
    need(expected is None or pin(raw)==expected,'exact retained local original bytes')
    READSET.append({'path':str(path),'metadata':before,**pin(raw)})
    return raw


def literal_values(raw):
    out={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign):
            for name in node.targets:
                if isinstance(name,ast.Name):
                    try:out[name.id]=ast.literal_eval(node.value)
                    except (ValueError,TypeError):pass
    return out


def module(raw, name):
    result=types.ModuleType(name);result.__file__='<offline-'+name+':'+pin(raw)['sha256']+'>'
    exec(compile(raw,result.__file__,'exec'),result.__dict__)
    return result


class SuppliedOriginals:
    def __init__(self, files):
        self.files=files;self.calls=[];self.corrupt_at=None

    def reset(self, corrupt_at=None):
        self.calls=[];self.corrupt_at=corrupt_at

    def __call__(self, row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256','metadata'},
             'exact inherited retained-stage original descriptor')
        key='original/'+row['path'].lstrip('/')
        need(key in self.files,'only supplied exact historical original paths')
        raw=self.files[key]
        need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'full original bytes at callback boundary')
        if self.corrupt_at==len(self.calls):raw=raw[:-1]
        self.calls.append({'descriptor':copy.deepcopy(row),'returned_bytes':pin(raw)})
        return raw


def old_factory(anchor, sources, callback):
    """Execute the exact frozen current factory without source substitution."""
    need(pin(anchor)==ANCHOR_PIN,'exact frozen current source-parent constructor')
    saved_path=sys.path[:];saved_dwb=sys.dont_write_bytecode
    present='component_common' in sys.modules;saved=sys.modules.get('component_common')
    try:
        sys.dont_write_bytecode=True
        common=module(sources['source/component_common.py'],'exact-source-parent-common')
        common.__reviewed_source_sha256__=pin(sources['source/component_common.py'])['sha256']
        sys.modules['component_common']=common
        parent=types.ModuleType('exact_frozen_current_factory')
        parent.__file__='<exact-current-source-parent-factory:'+ANCHOR_PIN['sha256']+'>'
        parent.__reviewed_source_sha256__=ANCHOR_PIN['sha256']
        parent.__reviewed_package_sources__=dict(sources)
        parent.__retained_stage_read_pinned__=callback
        exec(compile(anchor,parent.__file__,'exec'),parent.__dict__)
        reader=parent.source_parent_reader()
        need(reader.provenance()['historical_reader_functions_changed'] is False,
             'reference is the original exact-reader contract')
        return reader,parent
    finally:
        sys.path[:]=saved_path;sys.dont_write_bytecode=saved_dwb
        if present:sys.modules['component_common']=saved
        else:sys.modules.pop('component_common',None)


def outcome(reader, name, args, kwargs, callback, *, derived, corrupt_at=None):
    callback.reset(corrupt_at)
    inputs=copy.deepcopy((args,kwargs));before=copy.deepcopy(inputs)
    try:
        result=getattr(reader,name)(*inputs[0],**inputs[1])
        if derived:
            need(result['schema']=='hepta.UNADOPTED.derived-source-parent-result.v1'
                 and result['method']==name
                 and result['historical_result_is_old_execution_attestation'] is False
                 and result['production_adopted'] is False
                 and result['runtime_admission'] is False
                 and result['current_native_case_credit']==0
                 and result['whole_stage_budget_verified'] is False,
                 'derived result cannot attest old execution or grant current credit')
            result=result['historical_result']
        answer={'accepted':True,'historical_result':result}
    except Exception as error:
        answer={'accepted':False,'exception_type':type(error).__name__,'message':str(error)}
    need(inputs==before,'source-parent entry must not mutate supplied inputs')
    return answer,copy.deepcopy(callback.calls)


def compare(old,new,name,args,kwargs,callback,*,label,accepted=None,corrupt_at=None):
    left,reads_left=outcome(old,name,args,kwargs,callback,derived=False,corrupt_at=corrupt_at)
    right,reads_right=outcome(new,name,args,kwargs,callback,derived=True,corrupt_at=corrupt_at)
    need(left==right,'complete historical return/error differs: '+label)
    need(reads_left==reads_right,'exact callback sequence or bytes differ: '+label)
    if accepted is not None:need(left['accepted'] is accepted,'expected accept/reject differs: '+label)
    summary={'case':label,'entry':name,'accepted':left['accepted'],
        'complete_return_or_exception_equal':True,'callback_order_and_bytes_equal':True,
        'callback_reads':len(reads_left),'callback_sequence':pin(encoded(reads_left))}
    if left['accepted']:summary['historical_result_bytes']=pin(encoded(left['historical_result']))
    else:summary.update({k:left[k] for k in ('exception_type','message')})
    return summary,left


def run(files, constructor_raw, loader_raw, inventory_raw, rounds):
    loader=module(loader_raw,'bound-loader')
    candidate=loader.load_bound(constructor_raw,constructor_raw)
    need(candidate.pin(constructor_raw)==loader.CONSTRUCTOR_PIN,'constructor/actual binding')
    anchor=files['anchor/current_late.py'];constants=literal_values(anchor)
    sources={name:files['dependency/'+name] for name in candidate.DEPENDENCIES}
    callback=SuppliedOriginals(files)
    old,parent=old_factory(anchor,sources,callback)
    old_path=sys.path[:];old_dwb=sys.dont_write_bytecode;old_common=sys.modules.get('component_common')
    new=candidate.construct(sources=sources,inventory_function=inventory_raw,
        read_pinned=callback,implementation_source=constructor_raw)
    need(sys.path==old_path and sys.dont_write_bytecode==old_dwb
         and sys.modules.get('component_common') is old_common,'construction restores ambient import state')
    provenance=new.provenance()
    need(provenance['historical_reader_functions_changed'] is True
         and provenance['historical_publisher_data_identity_changed'] is False
         and provenance['source_slot_contains_actual_derived_bytes'] is True
         and provenance['validation_result_cache'] is False
         and provenance['complete_production_IO_metering_verified'] is False,
         'explicit new execution provenance and unchanged historical data anchor')
    context={'combination_sha256':candidate.COMBINATION,'package_sha256':candidate.PACKAGE}
    current=constants['SOURCE_PARENT_RECORDS'][0]
    need(current['nonce']==CURRENT_NONCE,'fixed final04 historical source-parent')
    boundary=files['original/'+current['boundary']['path'].lstrip('/')]
    inventory=files['original/'+current['inventory']['path'].lstrip('/')]
    closure=files['original/'+current['closure']['path'].lstrip('/')]
    for raw,row in ((boundary,current['boundary']),(inventory,current['inventory']),(closure,current['closure'])):
        need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'fixed current historical original pins')
    descriptors=[];values=[];raws=[];row=current['boundary']
    while row is not None:
        need(len(values)<11,'finite full ancestor chain')
        raw=files['original/'+row['path'].lstrip('/')]
        need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'every complete ancestor boundary byte pin')
        value=json.loads(raw)
        need(encoded(value)==raw,'canonical exact historical boundary bytes')
        descriptors.append(row);values.append(value);raws.append(raw);row=value['prior_boundary']
    need(len(values)==10 and len({v['nonce'] for v in values})==10,'one final04 prefix plus nine exact ancestors')
    positives=[]
    for index,(raw,row) in enumerate(zip(raws,descriptors)):
        summary,result=compare(old,new,'boundary_from_original',(raw,),
            {'original_descriptor':row,**context},callback,label='boundary-%02d'%index,accepted=True)
        need(result['historical_result']==values[index],'exact boundary value retained')
        positives.append(summary)
    kw={'original_descriptor':current['boundary'],**context}
    closed_case=(boundary,inventory,closure)
    summary,closed=compare(old,new,'closed_boundary_originals',closed_case,kw,callback,
                           label='complete-final04-closure',accepted=True)
    positives.append(summary)
    summary,tail=compare(old,new,'require_failed_ancestor_tail',(values,),{},callback,
                         label='complete-ten-boundary-tail',accepted=True)
    positives.append(summary)
    need(tail['historical_result'] is None,'original full-tail return is None')
    result_boundary,result_inventory,result_closure=closed['historical_result']
    need(result_boundary==values[0] and result_boundary['component_qualified'] is True
         and result_boundary['actual_native_calls']==2
         and result_boundary['business_qualified'] is False
         and result_boundary['retained_unstarted_stage']['original_sender_wait']=='UNKNOWN_UNCHANGED',
         'historical final04 credit and retained UNKNOWN must stay historical')
    negatives=[]
    cases=[
      ('boundary-truncated','boundary_from_original',(boundary[:-1],),kw),
      ('boundary-wrong-type','boundary_from_original',(boundary.decode(),),kw),
      ('wrong-original-path','boundary_from_original',(boundary,),{**kw,'original_descriptor':{**current['boundary'],'path':REMOTE+'0'*32+'.json'}}),
      ('wrong-combination','boundary_from_original',(boundary,),{**kw,'combination_sha256':'0'*64}),
      ('wrong-package','boundary_from_original',(boundary,),{**kw,'package_sha256':'0'*64}),
      ('inventory-truncated','closed_boundary_originals',(boundary,inventory[:-1],closure),kw),
      ('closure-truncated','closed_boundary_originals',(boundary,inventory,closure[:-1]),kw),
      ('boundary-before-bad-inventory','closed_boundary_originals',(boundary[:-1],inventory[:-1],closure),kw),
      ('tail-too-short','require_failed_ancestor_tail',(values[-8:],),{}),
      ('tail-too-long','require_failed_ancestor_tail',([values[0]]*3+values,),{}),
      ('tail-reordered','require_failed_ancestor_tail',(values[:-2]+[values[-1],values[-2]],),{}),
      ('tail-duplicate','require_failed_ancestor_tail',(values[:-1]+[values[-2]],),{}),
    ]
    metadata_bad=copy.deepcopy(kw);metadata_bad['original_descriptor']['metadata'][1]+=1
    # The exact old inner reader accepts a shape-valid self descriptor for
    # its current prefix. The frozen OUTER source-parent selector owns the
    # fixed actual record/full9 comparison. Preserve and disclose both roles.
    compatibility,_=compare(old,new,'boundary_from_original',(boundary,),metadata_bad,
        callback,label='original-inner-current-descriptor-shape-only',accepted=True)
    try:parent._source_parent_original(boundary,metadata_bad['original_descriptor'])
    except ValueError as error:
        outer_binding={'altered_current_full9_rejected':True,'exception_type':'ValueError',
                       'message':str(error),'frozen_call_site':'_source_parent_original',
                       'derived_candidate_does_not_replace_outer_binding':True}
    else:raise ValueError('frozen outer exact source-parent identity must reject changed full9')
    legacy_metadata=copy.deepcopy(descriptors[-1]);legacy_metadata['metadata'][1]+=1
    cases.append(('wrong-fixed-ancestor-full9','boundary_from_original',(raws[-1],),
                  {'original_descriptor':legacy_metadata,**context}))
    changed=copy.deepcopy(values);changed[-1]['actual_native_calls']+=1
    cases.append(('tail-changed-historical-count','require_failed_ancestor_tail',(changed,),{}))
    changed=copy.deepcopy(values);changed[0]['prior_boundary']['metadata'][1]+=1
    cases.append(('prefix-full-identity-changed','require_failed_ancestor_tail',(changed,),{}))
    for label,name,args,kwargs in cases:
        summary,_=compare(old,new,name,args,kwargs,callback,label=label,accepted=False)
        negatives.append(summary)
    for index,label in ((0,'retained-read-before-invalid'),(1,'retained-bookend-changed')):
        summary,_=compare(old,new,'closed_boundary_originals',closed_case,kw,callback,
            label=label,accepted=False,corrupt_at=index)
        negatives.append(summary)
    constructor_rejections=[]
    for label,changed in [('implementation-declaration-mismatch',{'implementation_source':constructor_raw+b'\n'}),
                          ('noncallable-original-provider',{'read_pinned':None})]:
        params=dict(sources=sources,inventory_function=inventory_raw,read_pinned=callback,
                    implementation_source=constructor_raw);params.update(changed)
        try:candidate.construct(**params)
        except ValueError as error:constructor_rejections.append({'case':label,'exception_type':'ValueError','message':str(error)})
        else:raise ValueError('mandatory constructor binding did not reject: '+label)
    # A separate profiled validation observes C readers and metadata helpers.
    # It is excluded from all timing samples and does not claim syscall-level
    # or production I/O budget coverage.
    callback.reset();profile_counts={}
    def observed(frame,event,arg):
        if event=='call' and frame.f_code.co_name in ('read','pinned','original','describe'):
            key=frame.f_globals.get('__name__','?')+':'+frame.f_code.co_name
            profile_counts[key]=profile_counts.get(key,0)+1
        elif event=='c_call' and getattr(arg,'__module__',None) in ('posix','os') and getattr(arg,'__name__',None) in ('stat','lstat','open','read','scandir','listdir','readlink'):
            key='stdlib:'+arg.__name__;profile_counts[key]=profile_counts.get(key,0)+1
    sys.setprofile(observed)
    try:new.closed_boundary_originals(*closed_case,**kw);new.require_failed_ancestor_tail(values)
    finally:sys.setprofile(None)
    need(not [key for key in profile_counts if not key.startswith('stdlib:')],
         'offline supplied-original path unexpectedly called an ambient historical file reader')
    callback.reset()
    timings={name:{'original':[],'derived':[]} for name in candidate.METHODS}
    entries={'boundary_from_original':((boundary,),kw),
             'closed_boundary_originals':(closed_case,kw),
             'require_failed_ancestor_tail':((values,),{})}
    need(sys.getprofile() is None and sys.gettrace() is None,'unprofiled timing boundary')
    for index in range(rounds):
        for name,(args,kwargs) in entries.items():
            for key,reader in ([('original',old),('derived',new)] if index%2==0 else [('derived',new),('original',old)]):
                callback.reset();start=time.perf_counter_ns();cpu=time.process_time_ns()
                getattr(reader,name)(*args,**kwargs)
                timings[name][key].append({'wall_seconds':(time.perf_counter_ns()-start)/1e9,
                    'cpu_seconds':(time.process_time_ns()-cpu)/1e9,'callback_reads':len(callback.calls)})
    medians={name:{key:{metric:statistics.median(row[metric] for row in samples)
        for metric in ('wall_seconds','cpu_seconds','callback_reads')} for key,samples in by_kind.items()}
        for name,by_kind in timings.items()}
    return {'schema':'hepta.UNADOPTED.complete-source-parent-differential.v1','state':'PASS',
      'constructor_source':pin(constructor_raw),'bound_loader_source':pin(loader_raw),
      'inventory_function':pin(inventory_raw),'frozen_factory_source':pin(anchor),
      'construction_provenance':provenance,'original_exact_reader_provenance':old.provenance(),
      'positive_cases':positives,'negative_cases':negatives,'constructor_rejections':constructor_rejections,
      'unchanged_inner_interface_compatibility_cases':[compatibility],
      'frozen_outer_source_parent_binding':outer_binding,
      'historical_boundary_count':10,'full_current_original_inventory':{'roots':len(result_inventory['roots']),
          'entries':len(result_inventory['entries']),'bytes':pin(inventory)},
      'original_unknown_retained':result_boundary['retained_unstarted_stage']['original_sender_wait'],
      'historical_final04_component_qualified':True,'current_native_case_credit':0,
      'all_historical_results_equal':True,'all_callback_reads_equal':True,
      'profile_only_IO_observation':{'counts':profile_counts,'historical_C_file_reader_calls':0,
          'scope':'one derived closure plus complete-tail pass; constructor/preload outside profile',
          'syscall_level_or_production_IO_metering':False},
      'rounds':rounds,'timings':timings,'medians':medians,
      'timing_boundary':'complete entry plus derived envelope, immutable original preload and top construction excluded',
      'production_adopted':False,'runtime_admission':False,'whole_stage_budget_verified':False,
      'validation_result_cache':False,'live_observation_cache':False,'phone_calls':0,'native_requests':0,
      'python':sys.version,'platform':platform.platform()}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--fixture',type=Path)
    p.add_argument('--legacy-export',type=Path)
    p.add_argument('--manifest-base64')
    p.add_argument('--constructor-base64',required=True)
    p.add_argument('--loader-base64',required=True)
    p.add_argument('--inventory-base64',required=True)
    p.add_argument('--rounds',type=int,default=3)
    p.add_argument('--output',type=Path)
    a=p.parse_args()
    need(1<=a.rounds<=3 and bool(a.fixture)!=bool(a.manifest_base64),'one bounded explicit fixture source')
    def expired(_sig,_frame):raise TimeoutError('offline replay diagnostic deadline 240 seconds')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,240)
    if a.fixture:
        raw=read_local(a.fixture);bundle=json.loads(raw)
        need(bundle['schema']=='hepta.private.source-parent-fixture.v1'
             and bundle['readset']==bundle['readset_after'],'retained collection full9/hash bookends')
        files={key:base64.b64decode(value,validate=True) for key,value in bundle['files'].items()}
        if bundle.get('missing_originals'):
            need(a.legacy_export is not None and len(bundle['missing_originals'])==1,'explicit supplemental legacy original')
            legacy=json.loads(read_local(a.legacy_export));need(len(legacy['found'])==1,'one exact legacy original')
            found=legacy['found'][0];b=base64.b64decode(found['raw_base64'],validate=True)
            row=bundle['missing_originals'][0]
            need(pin(b)=={k:row[k] for k in ('bytes','sha256')}
                 and found['metadata_before']==found['metadata_after'],'legacy full original double read')
            files['original/'+row['path'].lstrip('/')]=b
        fixture_identity={'kind':'immutable retained private bundle plus explicit supplemental original',
                          'bundle':pin(raw),'original_collection_was_partial':not bundle['all_originals_complete']}
    else:
        manifest_raw=base64.b64decode(a.manifest_base64,validate=True);manifest=json.loads(manifest_raw)
        need(manifest['schema']=='hepta.offline.source-parent-mac-readset.v1'
             and type(manifest['files']) is dict and len(manifest['files'])==29,'complete fixed Mac fixture manifest')
        files={key:read_local(row['path'],{k:row[k] for k in ('bytes','sha256')},row['metadata'])
               for key,row in manifest['files'].items()}
        fixture_identity={'kind':'explicit same-host retained-original byte/full9 readset','manifest':pin(manifest_raw)}
    constructor=base64.b64decode(a.constructor_base64,validate=True)
    loader=base64.b64decode(a.loader_base64,validate=True)
    inventory=base64.b64decode(a.inventory_base64,validate=True)
    result=run(files,constructor,loader,inventory,a.rounds)
    before=list(READSET)
    for row in before:read_local(row['path'],{k:row[k] for k in ('bytes','sha256')},row['metadata'])
    need(READSET[len(before):]==before,'all original source/fixture post-validation byte/full9 bookends')
    result.update(fixture=fixture_identity,readset=before,readset_after=READSET[len(before):],
                  source_and_original_bytes_and_full9_unchanged=True)
    signal.setitimer(signal.ITIMER_REAL,0)
    text=json.dumps(result,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n'
    if a.output:
        with a.output.open('x',encoding='utf-8') as out:out.write(text)
    print(text,end='')

if __name__=='__main__':main()
