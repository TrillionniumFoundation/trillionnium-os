#!/usr/bin/env python3
"""Derive a source-only capture-aware closure. No case read, task or dispatch."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'cpu_cancel_closure_cache'
R8=ROOT.parent/'transport_fix/native-guard-property-root-r8-transport-candidate03-1ad3'

def sha(raw):return hashlib.sha256(raw).hexdigest()

def replace_function(raw,name,replacement):
    tree=ast.parse(raw)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
    assert len(nodes)==1
    node=nodes[0];lines=raw.splitlines(keepends=True)
    old=b''.join(lines[node.lineno-1:node.end_lineno])
    assert raw.count(old)==1
    return raw.replace(old,replacement.encode()+b'\n',1)

ROOT_FUNCTIONS='''def normalized_capture_root(raw):
    """Undo only the actual R8 freezer's seven RHS writes, at UTF-8 byte offsets."""
    need(type(raw) is bytes and 0<len(raw)<=131072,'bounded_actual_capture_root')
    tree=ast.parse(raw);lines=raw.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    edits=[];values={}
    for name in ROOT_CAPTURE_SLOTS:
        rows=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and
              isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
        need(len(rows)==1,'one_actual_R8_slot')
        node=rows[0].value;value=ast.literal_eval(node)
        if name=='VERIFIER_BYTES':need(number(value,1,131072),'actual_R8_verifier_byte_bound')
        else:digest(value)
        start=offsets[node.lineno-1]+node.col_offset
        end=offsets[node.end_lineno-1]+node.end_col_offset
        need(0<=start<end<=len(raw),'actual_R8_slot_span')
        edits.append((start,end));values[name]=value
    normalized=raw
    for start,end in sorted(edits,reverse=True):normalized=normalized[:start]+b'None'+normalized[end:]
    need((len(normalized),sha(normalized))==ROOT_CAPTURE_TEMPLATE,
         'actual_R8_root_not_exact_reviewed_capture_template_with_seven_slots')
    return normalized,values

def root_source(raw,parent):
    need((len(parent),sha(parent))==PARENT_PINS['root_transport'],'root_transport_parent_pin')
    normalized_capture_root(raw)
    for key in ('REMOTE_IO','SSH','ACTOR'):
        need(same(literal(raw,key),literal(parent,key)), 'original_root_transport_constant_changed')
    for name in ('remote','remote_program','phone'):
        need(source_segment(raw,name,'Chain')==source_segment(parent,name,'Chain'),
             'original_root_remote_or_phone_function_changed')
    # execute_process, helpers and the actual async join are bound by the full
    # 71820-byte 50a5 template inverse, including the exact reviewed 0374 capture.
    return raw
'''

HOST_FUNCTIONS='''def host_capture(raw,records,child,result,intent_raw,stdout,stderr):
    value=strict(raw)
    fields={'schema','phase','pid','source_intent_sha256','output_limit_bytes_per_stream',
        'worker_started','worker_joined','pipe_reader_owner','child_wait_returned','child_returncode',
        'child_join_observed_monotonic','execution_deadline_monotonic','deadline_validity',
        'stdout_eof','stderr_eof','eof_observed_monotonic','prefix_only_or_unknown','captured','files',
        'error','persist_errors','pipe_close_errors','automatic_retry','signals_sent',
        'remote_terminal_or_cleanup_proven'}
    need(type(value) is dict and set(value)==fields and raw==pretty(value),
         'exact_original_capture_sidecar')
    need(value['schema']=='hepta.native-guard.host-output-capture.v1' and
         value['phase']==result['phase'] and value['pid']==child['pid']==result['pid'] and
         value['source_intent_sha256']==sha(intent_raw) and
         value['output_limit_bytes_per_stream']==64*1024*1024,
         'capture_phase_child_intent_bound')
    need(value['worker_started'] is True and value['worker_joined'] is True and
         value['pipe_reader_owner']=='closed_by_worker' and value['child_wait_returned'] is True and
         type(value['child_returncode']) is int and value['child_returncode']==0 and
         value['stdout_eof'] is True and value['stderr_eof'] is True and
         value['prefix_only_or_unknown'] is False and value['error'] is None and
         value['persist_errors']==value['pipe_close_errors']==[] and value['automatic_retry'] is False and
         value['signals_sent']==0 and value['remote_terminal_or_cleanup_proven'] is False,
         'capture_not_complete_or_unknown')
    deadline=value['execution_deadline_monotonic']
    need(type(deadline) in (int,float) and 0<deadline<float('inf') and
         child.get('execution_deadline_monotonic')==deadline and
         value['deadline_validity']==child.get('deadline_validity')=='this_running_coordinator_only',
         'same_original_capture_deadline')
    eof=value['eof_observed_monotonic'];joined=value['child_join_observed_monotonic']
    need(type(eof) is dict and set(eof)=={'stdout','stderr'} and
         all(type(t) in (int,float) and 0<t<=deadline for t in [joined,*eof.values()]),
         'child_join_or_EOF_after_original_deadline')
    need(set(value['captured'])==set(value['files'])=={'stdout','stderr'} and
         type(child.get('original_output_identities')) is dict and
         set(child['original_output_identities'])=={'stdout','stderr'},
         'both_original_capture_streams_required')
    same_inode=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')
    for label,body in (('stdout',stdout),('stderr',stderr)):
        wanted={'bytes':len(body),'sha256':sha(body)}
        need(value['captured'][label]==wanted,'actual_output_differs_from_captured_pipe')
        file=value['files'][label]
        need(type(file) is dict and set(file)=={'path','bytes','sha256','metadata','original_created_inode_bound'}
             and {k:file[k] for k in ('path','bytes','sha256')}==records[label] and
             file['original_created_inode_bound'] is True,'captured_output_original_path_or_inode')
        initial=metadata(child['original_output_identities'][label]);final=metadata(file['metadata'])
        need(initial['st_size']==0 and final['st_size']==len(body) and
             stat.S_IMODE(initial['st_mode'])==stat.S_IMODE(final['st_mode'])==0o600 and
             all(initial[k]==final[k] for k in same_inode),
             'created_output_inode_not_retained_through_complete_capture')
    return value

def host_phase(originals, records, phase, argv, timeout, stdin):
    need(type(records) is dict and set(records)=={'intent','child','result','stdout','stderr','stdin','output_capture'},
         'original_host_phase_fields_with_capture')
    raws={k:originals.read(v,MAX_ARCHIVE if k=='stdout' else MAX_FILE)
          for k,v in records.items() if v is not None}
    need(set(raws)==({'intent','child','result','stdout','stderr','output_capture'} |
                    ({'stdin'} if stdin is not None else set())),
         'original_host_phase_complete')
    directory=Path(records['intent']['path']).parent
    need(directory.name==phase,'original_phase_directory_name')
    for key,leaf in (('intent','INTENT.json'),('child','CHILD.json'),('result','RESULT.json'),
                     ('stdout','stdout.original'),('stderr','stderr.original'),
                     ('output_capture','OUTPUT-CAPTURE.json')):
        need(records[key]['path']==str(directory/leaf),'original_phase_member_exact_path')
    if stdin is not None:
        need(records['stdin']['path']==str(directory/'stdin.original'),'original_stdin_member_path')
    intent,child,result=[strict(raws[k]) for k in ('intent','child','result')]
    wanted={'schema':'hepta.native-guard.root-host-command.v1','phase':phase,
        'argv':argv,'stdin_sha256':None if stdin is None else sha(stdin),
        'maximum_starts':1,'maximum_wait_seconds':timeout,'automatic_retry':False,'signals_on_timeout':False,
        'deadline_scope':'popen_start_through_child_join_pipe_eof_and_output_verification',
        'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
        'output_transport':'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
        'output_limit_bytes_per_stream':64*1024*1024,'hard_bound_on_filesystem_spawn_or_cleanup':False}
    need(intent==wanted and raws['intent']==pretty(intent),'original_host_capture_intent_exact')
    if stdin is not None:
        need(raws['stdin']==stdin,'original_host_stdin_exact')
    need(number(child.get('pid'),2) and child.get('source_intent_sha256')==sha(raws['intent']) and
         child.get('maximum_starts')==1,'original_host_child_identity')
    missing=child.get('identity_missing_only_if_actual_child_already_joined')
    need((missing is False and child.get('pgid')==child['pid']==child.get('sid')) or
         (missing is True and child.get('pgid') is None and child.get('sid') is None),
         'original_host_child_group')
    need(set(result)=={'state','phase','pid','returncode','stdout','stderr','automatic_retry'} and
         result.get('state')=='ORIGINAL_HOST_CHILD_JOINED' and result.get('phase')==phase and
         result.get('pid')==child['pid'] and type(result.get('returncode')) is int and
         result['returncode']==0 and result.get('automatic_retry') is False and
         result.get('stdout')==records['stdout'] and result.get('stderr')==records['stderr'] and
         raws['stderr']==b'', 'original_host_terminal_not_joined_zero')
    host_capture(raws['output_capture'],records,child,result,raws['intent'],raws['stdout'],raws['stderr'])
    return raws['stdout']
'''

def main():
    source=ROOT/'source';reference=ROOT/'reference';validation=ROOT/'validation'
    for p in (source,reference,validation):p.mkdir(parents=True,exist_ok=True)
    pins={'negative_originals.py':(37253,'939674588f6229e27b71581a45bbf5b92e53c7b71edf2dab836e1f83158ec8b2'),
        'close_cpu_negative.py':(43958,'5c4314195c84c30352c21e381957a922676ea16eadd8a86450da59012f949ce5'),
        'ledger_prefix_negative.py':(29465,'7ed57c6579eb16abc78993793be09956cc758c4c017228b65247260a6d8affa6'),
        'root_cpu_negative.py':(15256,'29531f8f54716b6aa83f76a3007473b9b5a38f4fbd6b8f74d895bfa2a1d3a748')}
    originals={}
    for name,wanted in pins.items():
        raw=(BASE/name).read_bytes();assert (len(raw),sha(raw))==wanted
        originals[name]=raw;(reference/name).write_bytes(raw)
    template=(R8/'source/run_component_root_once.py').read_bytes()
    assert (len(template),sha(template))==(71820,'50a500e0c1cc014d3d4043f8c86172bf0b6068719473eb5646aca818416ed649')
    parent=(R8/'reference/Q2-run_component_root_once.py').read_bytes()
    assert (len(parent),sha(parent))==(45952,'53b5f9a3cd95a92b4aaa7382fcd890fc197c20a8a0106b7f49332e2ba3a67cc8')
    (reference/'root-capture-r8-50a5.original.py').write_bytes(template)
    (reference/'root-Q2-53b5.original.py').write_bytes(parent)
    raw=originals['negative_originals.py']
    marker=b'FINAL_DEPENDENCIES = None\n'
    assert raw.count(marker)==1
    raw=raw.replace(marker,marker+b"ROOT_CAPTURE_TEMPLATE = (71820, '50a500e0c1cc014d3d4043f8c86172bf0b6068719473eb5646aca818416ed649')\nROOT_CAPTURE_SLOTS = ('PKG','COMBINATION','VERIFIER_SHA','VERIFIER_BYTES','POLICY_SHA','ADOPTION_SHA','ROOT_SCOPE_SHA')\n",1)
    raw=replace_function(raw,'root_source',ROOT_FUNCTIONS)
    raw=replace_function(raw,'host_phase',HOST_FUNCTIONS)
    needle=b"    root_source(raw['root_transport'],raw['root_transport_parent'])\n"
    extra=b"    for slot,key in (('PKG','runtime_package_sha256'),('COMBINATION','combination_sha256'),('ADOPTION_SHA','policy_adoption_sha256')):\n        need(literal(raw['root_transport'],slot)==final[key],'actual_R8_root_final_generation_slot')\n    need(literal(raw['root_transport'],'POLICY_SHA')==final['live_policy']['sha256'],'actual_R8_root_actual_policy_slot')\n"
    assert raw.count(needle)==1;raw=raw.replace(needle,needle+extra,1)
    (source/'negative_originals.py').write_bytes(raw)
    for name in ('close_cpu_negative.py','ledger_prefix_negative.py'):(source/name).write_bytes(originals[name])
    root=originals['root_cpu_negative.py']
    old=b"'negative_originals': {'bytes': 37253, 'sha256': '939674588f6229e27b71581a45bbf5b92e53c7b71edf2dab836e1f83158ec8b2'}"
    new=("'negative_originals': {'bytes': %d, 'sha256': '%s'}"%(len(raw),sha(raw))).encode()
    assert root.count(old)==1;root=root.replace(old,new,1)
    (source/'root_cpu_negative.py').write_bytes(root)
    changes={}
    for name,original in originals.items():
        current=(source/name).read_bytes();compile(current,str(source/name),'exec')
        ast.parse(current,feature_version=(3,9))
        changes[name]={'before':{'bytes':len(original),'sha256':sha(original)},
            'after':{'bytes':len(current),'sha256':sha(current)},'byte_identical':current==original}
        (validation/(name+'.patch')).write_text(''.join(difflib.unified_diff(
            original.decode().splitlines(True),current.decode().splitlines(True),fromfile='original/'+name,tofile='candidate/'+name)))
    report={'schema':'hepta.cpu-negative.capture-transport-source-derivation.v1','state':'SOURCE_ONLY_FUTURE_DEPENDENCIES_NONE',
        'files':changes,'root_template':{'bytes':len(template),'sha256':sha(template)},
        'parent_root':{'bytes':len(parent),'sha256':sha(parent)},
        'allowed_actual_root_RHS_slots':['PKG','COMBINATION','VERIFIER_SHA','VERIFIER_BYTES','POLICY_SHA','ADOPTION_SHA','ROOT_SCOPE_SHA'],
        'unchanged_root_remote_constants':['REMOTE_IO','SSH','ACTOR'],
        'unchanged_root_remote_methods':['remote','remote_program','phone'],
        'host_phase_new_required_original':'output_capture => same phase OUTPUT-CAPTURE.json exact3',
        'success_RESULT_schema_unchanged_exact7':True,'FINAL_DEPENDENCIES_remains_None':True,
        'new_phone_calls':0,'new_case_executions':0,'physical_case_pass':False}
    (validation/'DERIVATION.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
