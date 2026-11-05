#!/usr/bin/env python3
"""Pure compatibility tests over retained real 0374 process originals.

No new child, namespace, signal, phone call or case execution occurs. Negative
controls mutate in-memory copies only, and never become acceptance evidence.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import types

ROOT=Path(__file__).resolve().parent
SAMPLE=ROOT.parent/'transport_fix/capture0374-review01/evidence/utf8-binary-input/phase'

def sha(raw):return hashlib.sha256(raw).hexdigest()

def load(path,name):
    raw=path.read_bytes();m=types.ModuleType(name);m.__file__=str(path)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    return m,raw

def fill(raw,values):
    lines=raw.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    edits=[]
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in values:
            v=node.value;edits.append((offsets[v.lineno-1]+v.col_offset,
                offsets[v.end_lineno-1]+v.end_col_offset,repr(values[node.targets[0].id]).encode()))
    assert len(edits)==len(values)
    for a,b,v in sorted(edits,reverse=True):raw=raw[:a]+v+raw[b:]
    return raw

def main():
    module,source=load(ROOT/'source/negative_originals.py','candidate_capture_assembler')
    old,_=load(ROOT/'reference/negative_originals.py','original_capture_assembler')
    root=(ROOT/'reference/root-capture-r8-50a5.original.py').read_bytes()
    parent=(ROOT/'reference/root-Q2-53b5.original.py').read_bytes()
    checks=[]
    def record(name,fn):
        fn();checks.append({'name':name,'passed':True})
    def rejected(fn,token=None):
        try:fn()
        except (ValueError,AssertionError) as ex:
            if token is not None:assert token in str(ex),(token,str(ex))
            return str(ex)
        raise AssertionError('expected source or original rejection')
    synthetic_slots={name:('%064x'%(i+1)) for i,name in enumerate(module.ROOT_CAPTURE_SLOTS)}
    synthetic_slots['VERIFIER_BYTES']=125010
    synthetic_root=fill(root,synthetic_slots)
    def inverse():
        normalized,values=module.normalized_capture_root(synthetic_root)
        assert normalized==root and values==synthetic_slots
        assert module.root_source(synthetic_root,parent)==synthetic_root
    record('only seven reviewed actual R8 RHS slots invert exactly to full 50a5 template',inverse)
    record('unfilled Root template is not an actual frozen source',
        lambda:rejected(lambda:module.root_source(root,parent)))
    record('old 53b compatibility gate rejects the new reviewed execute_process',
        lambda:rejected(lambda:old.root_source(synthetic_root,parent),'original_root_transport_function_changed'))
    changed=synthetic_root.replace(b"output_limit_bytes_per_stream':HOST_OUTPUT_LIMIT",b"output_limit_bytes_per_stream':1",1)
    assert changed!=synthetic_root
    record('new Root body change outside seven slots is rejected',
        lambda:rejected(lambda:module.root_source(changed,parent),'exact_reviewed_capture_template'))
    record('an eighth appended source mutation is rejected',
        lambda:rejected(lambda:module.root_source(synthetic_root+b'\n# unreviewed\n',parent),'exact_reviewed_capture_template'))
    record('invalid actual verifier byte type is rejected',
        lambda:rejected(lambda:module.root_source(fill(root,dict(synthetic_slots,VERIFIER_BYTES=True)),parent),
            'actual_R8_verifier_byte_bound'))
    def none_gate():
        touched=[]
        def forbidden(_):touched.append(True);raise AssertionError('read reached')
        assert module.FINAL_DEPENDENCIES is None
        rejected(lambda:module.assemble(b'not even JSON',read_pinned=forbidden),'future_dependencies_unfrozen')
        assert touched==[]
    record('unfrozen closure rejects before case parsing or private original read',none_gate)

    leaves={'intent':'INTENT.json','child':'CHILD.json','result':'RESULT.json','stdout':'stdout.original',
        'stderr':'stderr.original','stdin':'stdin.original','output_capture':'OUTPUT-CAPTURE.json'}
    bodies={str(SAMPLE/name):(SAMPLE/name).read_bytes() for name in leaves.values()}
    intent=json.loads(bodies[str(SAMPLE/'INTENT.json')])
    original_stdout=bodies[str(SAMPLE/'stdout.original')]
    original_stdin=bodies[str(SAMPLE/'stdin.original')]
    def run(overrides=None,remove=(),old_version=False):
        values=dict(bodies)
        if overrides:values.update(overrides)
        rows={key:{'path':str(SAMPLE/name),'bytes':len(values[str(SAMPLE/name)]),
                   'sha256':sha(values[str(SAMPLE/name)])} for key,name in leaves.items() if key not in remove}
        target=old if old_version else module
        originals=target.Originals(lambda row:values[row['path']])
        result=target.host_phase(originals,rows,intent['phase'],intent['argv'],intent['maximum_wait_seconds'],original_stdin)
        assert result==original_stdout
        originals.recheck()
        if not old_version:
            assert {r['path'] for r in originals.index()}==set(values)
        return result
    record('real final0374 complete phase accepted with exact7 RESULT plus separate sidecar',lambda:run())
    record('sidecar appears in the complete consumed original read set',lambda:run())
    record('old intent schema rejects the actual new intent even without new record key',
        lambda:rejected(lambda:run(remove=('output_capture',),old_version=True),'original_host_intent_exact'))
    record('missing sidecar never yields a joined phase',
        lambda:rejected(lambda:run(remove=('output_capture',)),'original_host_phase_fields_with_capture'))
    cap=json.loads(bodies[str(SAMPLE/'OUTPUT-CAPTURE.json')])
    def cap_mutate(fn):
        value=copy.deepcopy(cap);fn(value)
        return {str(SAMPLE/'OUTPUT-CAPTURE.json'):module.pretty(value)}
    controls=[
        ('unknown prefix is rejected',lambda v:v.update(prefix_only_or_unknown=True),'capture_not_complete_or_unknown'),
        ('stdout without EOF is rejected',lambda v:v.update(stdout_eof=False),'capture_not_complete_or_unknown'),
        ('reader not joined is rejected',lambda v:v.update(worker_joined=False),'capture_not_complete_or_unknown'),
        ('capture from another child is rejected',lambda v:v.update(pid=v['pid']+1),'capture_phase_child_intent_bound'),
        ('renamed replacement capture is rejected',lambda v:v['files']['stdout'].update(original_created_inode_bound=False),'captured_output_original_path_or_inode'),
        ('late descendant EOF is rejected',lambda v:v['eof_observed_monotonic'].update(stdout=v['execution_deadline_monotonic']+1),'child_join_or_EOF_after_original_deadline'),
        ('same-size wrong captured output digest is rejected',lambda v:v['captured']['stdout'].update(sha256='0'*64),'actual_output_differs_from_captured_pipe'),
        ('original-created inode mismatch is rejected',lambda v:v['files']['stdout']['metadata'].update(st_ino=v['files']['stdout']['metadata']['st_ino']+1),'created_output_inode_not_retained'),
        ('capture cannot claim remote cleanup',lambda v:v.update(remote_terminal_or_cleanup_proven=True),'capture_not_complete_or_unknown')]
    for name,fn,token in controls:
        record(name,lambda fn=fn,token=token:rejected(lambda:run(cap_mutate(fn)),token))
    result=json.loads(bodies[str(SAMPLE/'RESULT.json')]);result['output_capture']={'path':'invented'}
    record('success RESULT remains exact7; no invented capture pointer',lambda:rejected(
        lambda:run({str(SAMPLE/'RESULT.json'):module.pretty(result)}),'original_host_terminal_not_joined_zero'))
    root_module,_=load(ROOT/'source/root_cpu_negative.py','candidate_root_closer')
    assert root_module.PURE_MODULES['negative_originals']=={'bytes':len(source),'sha256':sha(source)}
    for name in ('close_cpu_negative.py','ledger_prefix_negative.py'):
        assert (ROOT/'source'/name).read_bytes()==(ROOT/'reference'/name).read_bytes()
    record('Root pure-source pin updated; actual CPU/ledger closure logic unchanged',lambda:None)
    evidence={'schema':'hepta.cpu-negative.capture-compatibility-source-checks.v1',
        'state':'NARROW_COMPATIBILITY_CHECKS_PASSED','passed':len(checks),'failed':0,'checks':checks,
        'candidate_source':{'bytes':len(source),'sha256':sha(source)},
        'real_retained_process_originals':[{ 'path':key,'bytes':len(raw),'sha256':sha(raw)} for key,raw in sorted(bodies.items())],
        'synthetic_Root_slot_values_are_unit_controls_only':True,'mutated_originals_are_in_memory_negative_controls_only':True,
        'phone_calls':0,'new_processes':0,'new_signals':0,'new_case_executions':0,'physical_case_pass':False,
        'FINAL_DEPENDENCIES_remains_None':True}
    output=ROOT/'validation/COMPATIBILITY-TESTS.json'
    with output.open('x') as stream:json.dump(evidence,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps({'passed':len(checks),'failed':0,'evidence':str(output),'phone_calls':0,'new_processes':0}))

if __name__=='__main__':main()
