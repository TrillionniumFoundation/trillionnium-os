#!/usr/bin/env python3
"""Pure actual-history controls for the exact R4 -> R5 LATE source transition.

Reads immutable Mac originals only. Never invokes a phone, actor, task, model,
signal, cleanup or runtime publisher. New writes are confined to CONTROL-RESULT01.
"""
from pathlib import Path
import ast
import copy
import hashlib
import json
import os
import stat
import sys
import time
import types

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
HERE = B/'followthrough-fc33-source-parent-late01'
OLD = B/'native-guard-r10-r1-operator-final-v3-getattr-a1055-r4/runtime'
CAP = B/'owned-unstarted-stage-cleanup-neg02-final04-a1055-candidate01/foreign-retained-reference01/capture02-import01/packet'
CHAIN = B/'native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final04'
OUT = HERE/'CONTROL-RESULT01'
SOURCE_PIN = {'bytes': 181669, 'sha256': '0a9f52cf8fb71177d0816f561cce279811a7182e986c12912d9431bde5997cda'}
OLD_PIN = {'bytes': 153138, 'sha256': '27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4'}
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BOOK = {}; PHONE_MAP = {}; CHECKS = []


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def meta(st):
    return [getattr(st,key) for key in META]


def read(path, expected=None):
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve(strict=True)==path.parent,
         'explicit canonical actual host original path required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd); before=meta(st)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<=st.st_size<=16*1024*1024,
             'bounded actual single-link host original')
        parts=[];count=0
        while True:
            part=os.read(fd,65536)
            if not part:break
            count+=len(part);need(count<=16*1024*1024,'complete bounded host read');parts.append(part)
        raw=b''.join(parts)
        need(len(raw)==st.st_size and before==meta(os.fstat(fd))==meta(path.lstat()),
             'complete actual host FD and named full9 bookends')
        if expected is not None:
            need(pin(raw)=={k:expected[k] for k in ('bytes','sha256')},'exact whole original pin: '+str(path))
            if 'metadata' in expected:
                need(expected['metadata']==before,'all nine actual host metadata integers: '+str(path))
    finally:
        os.close(fd)
    row={'path':str(path),**pin(raw),'metadata':before}
    need(str(path) not in BOOK or BOOK[str(path)]==row,'original changed during history controls')
    BOOK[str(path)]=row
    return raw


def phone_original(row, host_path=None):
    need(type(row)is dict and set(row)=={'path','bytes','sha256','metadata'},
         'complete phone original descriptor required')
    path=CAP/'originals'/(row['sha256']+'.bin') if host_path is None else Path(host_path)
    raw=read(path,{k:row[k] for k in ('bytes','sha256')})
    mapped={'phone_original':copy.deepcopy(row),'host_original':copy.deepcopy(BOOK[str(path)])}
    need(row['path'] not in PHONE_MAP or PHONE_MAP[row['path']]==mapped,
         'one explicit phone-to-host namespace mapping per actual original')
    PHONE_MAP[row['path']]=mapped
    return raw


def reject(name, function):
    try:
        function()
    except (ValueError,KeyError,TypeError,AttributeError) as error:
        CHECKS.append({'name':name,'state':'REJECTED','error_type':type(error).__name__,'reason':str(error)})
    else:
        raise AssertionError('negative control unexpectedly accepted: '+name)


def module_from_bytes(raw,path,source_map,common,callback=None):
    m=types.ModuleType('actual_source_parent_control_'+hashlib.sha256(raw).hexdigest()[:12])
    m.__file__=str(path);m.__reviewed_source_sha256__=pin(raw)['sha256'];m.__reviewed_package_sources__=source_map
    if callback is not None:m.__retained_stage_read_pinned__=callback
    sys.modules['component_common']=common
    exec(compile(raw,str(path),'exec'),m.__dict__)
    return m


def write(path,raw):
    path=Path(path);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False)as f:f.write(raw);f.flush();os.fsync(fd)
    finally:os.close(fd)
    need(read(path)==raw,'exact control result readback')
    return {'path':str(path),**pin(raw)}


def main():
    started=time.monotonic();need(not OUT.exists(),'create-only control result namespace')
    self_raw=read(Path(__file__))
    source=read(HERE/'runtime/source/late_boundary.py',SOURCE_PIN)
    old=read(HERE/'runtime/reference/source_parent_late_boundary_r4.py',OLD_PIN)
    need(read(OLD/'source/late_boundary.py',OLD_PIN)==old,'independent full-byte retained source equality')
    manifest_raw=read(OLD/'MANIFEST.json',{'bytes':46685,'sha256':'72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'})
    manifest=json.loads(manifest_raw);sources={row['path']:read(OLD/row['path'],row)for row in manifest['files']}
    need(len(sources)==37,'all thirty-seven actual R4 sources read in full')
    sources['reference/source_parent_late_boundary_r4.py']=old;sources['source/late_boundary.py']=source
    qraw=read(CAP/'REQUEST.original.json',{'bytes':42253,'sha256':'3d716252466d6afe1d582047b221816394bf5740399ade9da0b9678da6002056'})
    q=json.loads(qraw);descriptors=q['native_boundaries'];need(len(descriptors)==10,'actual qualified head and original nine failures')
    native_raw=[phone_original(row)for row in descriptors];native=[json.loads(raw)for raw in native_raw]
    head=native[0]
    inventory_raw=phone_original(head['inventory']);closure_raw=phone_original(head['closure'],CHAIN/'CLOSURE.json')
    previous_raw=read(CHAIN/'ACTUAL-PREVIOUS-INPUT.json',{'bytes':1426,'sha256':'fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0'})
    previous=json.loads(previous_raw)
    need(previous['late_boundary']==descriptors[0] and previous['identity']==head['scope']
         and previous['closed_component']=={'path':str(CHAIN/'CLOSURE.json'),**pin(closure_raw)}
         and previous['component_qualified']is True,'actual host previous-publication linkage')
    retained_descriptor=q['retained_baseline_inventory'];retained_raw=phone_original(retained_descriptor)
    def retained_read(row):
        need(row==retained_descriptor,'only the exact original old39 inventory can feed the retained reader')
        return phone_original(row)
    common_raw=sources['source/component_common.py'];common=types.ModuleType('component_common');common.__file__=str(OLD/'source/component_common.py')
    common.__reviewed_source_sha256__=pin(common_raw)['sha256'];exec(compile(common_raw,common.__file__,'exec'),common.__dict__)
    late=module_from_bytes(source,HERE/'runtime/source/late_boundary.py',sources,common,retained_read)
    old_reader=late.source_parent_reader();provenance=old_reader.provenance()
    need(sys.modules['component_common']is common,'source-parent loader restored the calling common module')
    need(not hasattr(old_reader,'publish')and not hasattr(old_reader,'main')and not hasattr(old_reader,'verify_current'),
         'pure reader facade has no phone/current admission/publisher entry')
    original_values=[old_reader.boundary_from_original(raw,original_descriptor=row,
        combination_sha256=late.SOURCE_PARENT_COMBINATION_SHA256,package_sha256=late.SOURCE_PARENT_PACKAGE_SHA256)
        for row,raw in zip(descriptors,native_raw)]
    need(original_values==native,'original R4 boundary reader preserves all ten actual values')
    old_reader.require_failed_ancestor_tail(original_values)
    late.require_failed_ancestor_tail(original_values)
    old_closed=old_reader.closed_boundary_originals(native_raw[0],inventory_raw,closure_raw,
        original_descriptor=descriptors[0],combination_sha256=late.SOURCE_PARENT_COMBINATION_SHA256,
        package_sha256=late.SOURCE_PARENT_PACKAGE_SHA256)
    new_closed=late.source_parent_closed_boundary_originals(native_raw[0],inventory_raw,closure_raw,
        original_descriptor=descriptors[0])
    need(new_closed==old_closed and enc(new_closed)==enc(old_closed),
         'complete original and new classified closed public returns must be byte-identical')
    need(new_closed[0]['component_qualified']is True and new_closed[2]['component_qualified']is True
         and new_closed[0]['actual_native_calls']==2
         and new_closed[2]['closure_source_sha256']==late.SOURCE_PARENT_CLOSURE_SHA256,
         'actual historical qualified NEG01 remains qualified only for its original tuple')
    retained=late.retained_unstarted_stage(read_pinned=retained_read)
    need(len(retained['inventory']['roots'])==41
         and head['roots']==retained['inventory']['roots']+late.source_parent_private_roots(),
         'actual whole inventories prove exact retained41 plus three known roots equals current44')
    branches=late.non_native_sidebranches()
    selected,selected_pin,selection=late.effective_current_prior_inventory(head,new_closed[1],branches,retained=retained)
    need(selected==new_closed[1]and selected_pin==head['inventory']
         and selection=='exact_previous_source_component_head_with_retained_unstarted_stage',
         'actual source-parent whole inventory selection')
    late.validate_retained_stage_parent_profiles(retained,head['retained_stage_parent_profiles'],new_closed[1])
    # The following package digest is an isolated reader-interface control input.
    # It is neither an install manifest nor a qualification for the new tuple.
    control_package=hashlib.sha256(b'fc33-pure-reader-context-control\0'+source).hexdigest()
    checked=late.boundary_from_original(native_raw[0],original_descriptor=descriptors[0],
        combination_sha256=late.REVIEWED_CURRENT_COMBINATION_SHA256,package_sha256=control_package)
    classified=late.closed_boundary_originals(native_raw[0],inventory_raw,closure_raw,
        original_descriptor=descriptors[0],combination_sha256=late.REVIEWED_CURRENT_COMBINATION_SHA256,
        package_sha256=control_package)
    need(checked==head and classified==old_closed,'new dispatch classification preserves exact old values without promotion')
    CHECKS.extend({'name':name,'state':'PASSED'}for name in(
        'all_37_complete_actual_R4_sources','exact_153138_byte_parent_reference','original_module_globals_and_old_source_overlay',
        'actual_ten_original_boundaries','unchanged_original_nine_failed_tail','actual_NEG01_complete_original_closure',
        'old_and_new_full_public_returns_identical','actual_retained41_plus_exact_three_roots_equals44',
        'exact_source_parent_inventory_selection','actual_retained_parent_alias_profile','new_reader_exact_source_parent_classification'))
    reject('old_package_cannot_be_new',lambda:late.current_context(late.REVIEWED_CURRENT_COMBINATION_SHA256,late.SOURCE_PARENT_PACKAGE_SHA256))
    reject('old_combination_cannot_be_new',lambda:late.current_context(late.SOURCE_PARENT_COMBINATION_SHA256,control_package))
    reject('historical_qualified_head_cannot_supply_new_current_case',lambda:late.boundary_value(head,
        combination_sha256=late.REVIEWED_CURRENT_COMBINATION_SHA256,package_sha256=control_package))
    changed=copy.deepcopy(descriptors[0]);changed['metadata'][7]+=1
    reject('source_parent_full9_nanosecond_change',lambda:late.source_parent_boundary_from_original(native_raw[0],original_descriptor=changed))
    changed_path=copy.deepcopy(descriptors[0]);changed_path['path']=changed_path['path'].replace(head['nonce'],'0'*32)
    reject('source_parent_original_path_change',lambda:late.source_parent_boundary_from_original(native_raw[0],original_descriptor=changed_path))
    changed_head=copy.deepcopy(head);changed_head['component_qualified']=False
    reject('source_parent_original_qualification_rewrite',lambda:late.source_parent_boundary_from_original(enc(changed_head),original_descriptor=descriptors[0]))
    reject('source_parent_inventory_byte_change',lambda:late.source_parent_closed_boundary_originals(native_raw[0],inventory_raw+b' ',closure_raw,original_descriptor=descriptors[0]))
    reject('source_parent_closure_byte_change',lambda:late.source_parent_closed_boundary_originals(native_raw[0],inventory_raw,closure_raw+b' ',original_descriptor=descriptors[0]))
    reject('actual_source_parent_cannot_be_omitted',lambda:late.require_failed_ancestor_tail(native[1:]))
    reordered=copy.deepcopy(native);reordered[-1],reordered[-2]=reordered[-2],reordered[-1]
    reject('historical_tail_reordering',lambda:late.require_failed_ancestor_tail(reordered))
    rewritten=copy.deepcopy(native);rewritten[-1]['actual_native_calls']=1
    reject('historical_tail_bytes_cannot_change',lambda:late.require_failed_ancestor_tail(rewritten))
    duplicate=copy.deepcopy(native);duplicate[1]=duplicate[2]
    reject('historical_tail_duplicate',lambda:late.require_failed_ancestor_tail(duplicate))
    reject('source_parent_cannot_be_reused_as_current_prefix',lambda:late.require_failed_ancestor_tail([head]+native))
    reject('third_new_prefix_exceeds_exact_capacity',lambda:late.require_failed_ancestor_tail([head,head,head]+native))
    altered=dict(sources);altered['reference/source_parent_late_boundary_r4.py']=source
    poisoned=module_from_bytes(source,HERE/'runtime/source/late_boundary.py',altered,common,retained_read)
    reject('new_source_cannot_impersonate_old_reader',poisoned.source_parent_reader)
    fields=late.manifest_source_parent_binding()
    need(fields['runtime_file_count']==38 and fields['source_parent_native_boundary_count']==1
         and fields['historical_failed_native_boundary_count']==9 and fields['historical_native_boundary_count']==10
         and fields['native_chain_cap']==12 and fields['component_role_cap']==42 and fields['fixture_root_cap']==14
         and fields['current_complete_inventory_root_count']==44
         and fields['maximum_complete_inventory_roots_after_two_final_NEG_cases']==50
         and fields['source_parent_qualification_is_current_tuple_credit']is False,'all actual derived finite resource bounds')
    all_inputs=list(BOOK.values())
    for row in all_inputs:read(row['path'],row)
    OUT.mkdir(mode=0o700)
    public=write(OUT/'IDENTICAL-CLOSED-PUBLIC-RETURN.json',enc(old_closed))
    originals=write(OUT/'ALL-ACTUAL-HOST-ORIGINALS.json',enc(all_inputs))
    mapping=write(OUT/'ACTUAL-PHONE-TO-HOST-ORIGINALS.json',enc(list(PHONE_MAP.values())))
    fields_pin=write(OUT/'MANIFEST-SOURCE-PARENT-FIELDS.json',enc(fields))
    self_pin=write(OUT/'VERIFIER.original.py',self_raw)
    result={'schema':'hepta.fc33.actual-source-parent-history-controls.v1','state':'ACTUAL_HISTORY_AND_NEGATIVE_CONTROLS_PASSED',
        'source':{'path':str(HERE/'runtime/source/late_boundary.py'),**SOURCE_PIN},
        'source_parent':{'path':str(HERE/'runtime/reference/source_parent_late_boundary_r4.py'),**OLD_PIN},
        'verifier':self_pin,'actual_host_originals':originals,'phone_to_host_originals':mapping,'public_return':public,
        'manifest_fields':fields_pin,'source_parent_provenance':provenance,'actual_native_boundary_count':10,
        'actual_historical_failed_count':9,'actual_source_parent_count':1,'original_qualified_NEG01_preserved':True,
        'historical_qualification_grants_new_tuple_credit':False,'old_original_sources_changed':False,
        'current_tuple_qualified':False,'current_package_fixture_only':True,'control_package_context_sha256':control_package,
        'new_task_or_publish_or_model_or_phone_calls':0,'current_device_state_claimed':False,
        'checks':CHECKS,'elapsed_seconds':time.monotonic()-started}
    result_pin=write(OUT/'RESULT.json',enc(result))
    print(json.dumps({'result':result_pin,'state':result['state'],'checks':len(CHECKS),'actual_host_originals':len(all_inputs),
        'mapped_phone_originals':len(PHONE_MAP),'phone_calls':0},sort_keys=True))


if __name__=='__main__':
    main()
