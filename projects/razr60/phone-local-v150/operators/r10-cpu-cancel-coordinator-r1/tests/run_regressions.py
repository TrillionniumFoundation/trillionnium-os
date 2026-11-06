#!/usr/bin/env python3
"""Local source/transport regressions. Fixtures never grant a physical case pass."""
import argparse
import ast
import base64
import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def load(path, name):
    raw = path.read_bytes(); module = types.ModuleType(name); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, raw


def fill(raw, values):
    lines = raw.splitlines(keepends=True); offsets = [0]
    for line in lines: offsets.append(offsets[-1] + len(line))
    edits = []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in values:
            v = node.value; edits.append((offsets[v.lineno-1] + v.col_offset,
                offsets[v.end_lineno-1] + v.end_col_offset, repr(values[node.targets[0].id]).encode()))
    assert len(edits) == len(values)
    for start, end, text in sorted(edits, reverse=True): raw = raw[:start] + text + raw[end:]
    return raw


def rejected(fn, token=None):
    try:
        fn()
    except (ValueError, AssertionError, FileExistsError, FileNotFoundError) as error:
        if token is not None: assert token in str(error), (token, str(error))
        return {'rejection':str(error)}
    raise AssertionError('expected rejection')


def fixture(M):
    raw = (ROOT/'reference/active-current-template.py').read_bytes()
    active = M.module_from_raw('active_runtime_r10', fill(raw,
        {'CONSUMER_SHA':'1'*64, 'READINESS_SHA':'2'*64, 'POLICY_SHA':'3'*64, 'ADOPTION_SHA':'4'*64}), '<synthetic-bound-active>')
    active._REVIEWED_PRODUCTION_PINS = json.loads((ROOT/'reference/production-pins-current.json').read_bytes())
    old = sys.modules.get('active_runtime_r10'); sys.modules['active_runtime_r10'] = active
    try:
        guards, _ = load(ROOT/'reference/cancel-base/cancel_phase.py', 'actual_cancel_phase')
    finally:
        if old is None: sys.modules.pop('active_runtime_r10', None)
        else: sys.modules['active_runtime_r10'] = old
    boot = 'f8019f83-20a7-4f18-bea1-51c980621e4d'; nonce = 'e'*32
    scope = {'session_id':'fixture-session', 'profile_id':'owner-open', 'task_id':'previous-task',
        'turn_id':'previous-turn', 'turn_stream_id':'previous-stream'}
    pins = {'source_seal_sha256':'5'*64, 'configuration_sha256':active.CONFIG_SHA,
        'service_inputs_sha256':active.SERVICE_SHA, 'module_manifest_sha256':'6'*64,
        'component_boundary_inputs_sha256':'7'*64, 'policy_adoption_inputs_sha256':active.ADOPTION_SHA}
    ready = {key:None for key in active.READY_FIELDS}
    ready.update(schema='hepta.r10.actual-readiness.v1', state='EXACT_COMBINATION_READY_TRANSPORT_ONLY',
        boot_id=boot, policy_sha256=active.POLICY_SHA, parent_policy_sha256=active.PARENT_POLICY_SHA, **pins)
    ready.update(component_boundary_sha256='8'*64, release_boundary_bundle_sha256='9'*64,
        model_requests=0, task_submissions=0, ui_actions=0, signals_sent=0,
        health_qualified=False, business19_qualified=False, cold_boot_qualified=False,
        slot_observation={'is_processing':False}, slot_get_receipt={'complete':True,'http_status':200,'error':None},
        component_external_artifacts={n:None for n in ('client','sidecar','worker','screen_helper','focus_helper','unicode_helper','busybox','python')},
        actual_binding={'sha256':'a'*64}, roles={})
    for index, role in enumerate(('supervisor','model','sidecar','provider'), 1):
        pid = 40000 + index
        ready['roles'][role] = {'identity':[pid,pid,pid,90000+index], 'state':'S',
            'domain':'u:r:trillionnium_owner_open_phone_executor:s0' if role=='sidecar' else 'u:r:magisk:s0',
            'uid':[0]*4, 'gid':[0]*4, 'no_new_privs':0,
            'exe':{'model':active.MODEL_EXE,'sidecar':active.SIDECAR_EXE,'provider':'/usr/bin/python3','supervisor':'/usr/bin/python3'}[role]}
    ready_raw = active.encoded(ready)
    runtime = {'schema':'hepta.r10.active-runtime-binding.v1','release_pins':pins,
        'readiness':{'bytes':len(ready_raw),'sha256':M.sha(ready_raw),'raw_b64':base64.b64encode(ready_raw).decode()}}
    owner = ('本次 nonce='+nonce+'。打开测试应用后等待取消；这只是主机测试数据。').encode()
    request_hash = M.sha(owner)
    app_scope = {'schema':'hepta.task-app-scope.v1','owner_request_sha256':request_hash,
        'apps':[{'alias':'fixture','component':'org.example.fixture/org.example.fixture.MainActivity'}]}
    template = {'schema':'hepta.task-template.v150.3','expected_scope':{k:scope[k] for k in ('session_id','profile_id')},
        'request_sha256':request_hash,'nonce':nonce,'coverage':'entire_request','postconditions':[], 'app_scope':app_scope}
    draft = '原始中文草稿🙂\n第二行'.encode()
    raw_inputs = {'request':owner, 'previous':M.encode({'identity':scope,'request_sha256':'b'*64,'terminal':{'status':'cancelled'}}),
        'preserved_draft':M.encode({'exact_utf8_b64':base64.b64encode(draft).decode(),'utf8_sha256':M.sha(draft)}),
        'retirement_resolution':M.encode({'fixture_only':True}), 'registration_template':M.encode(template)}
    plan = {'schema':'hepta.cpu-cancel.coordinator-plan.v1','state':'ROOT_REVIEWED_REGISTERED_UNCONSUMED_CASE_ONCE',
        'case_id':'NEG-08','nonce':nonce,'out':str(M.B/'cpu-cancel-negative-coordinators-r1'/nonce),
        'actor_label':'fixture-cancel-08','sender_label':'fixture-sender-08','capture_label':'fixture-capture-08',
        'expected_boot':boot,'wait_seconds':60,'require_image_cancel':False,
        'probe_component':'org.example.fixture/org.example.fixture.MainActivity','runtime_binding':runtime,
        'sender_inputs':{k:M.descriptor(str(M.B/('fixture-'+k+'.original')),v) for k,v in raw_inputs.items() if k!='registration_template'},
        'registration_template':M.descriptor(str(M.B/'fixture-template.original'),raw_inputs['registration_template']),
        'qualify_physical_case':True}
    final = {'configuration_sha256':active.CONFIG_SHA,'service_inputs_sha256':active.SERVICE_SHA,
        'policy_adoption_sha256':active.ADOPTION_SHA,'ui_package_sha256':'c'*64,'combination_sha256':'d'*64}
    return plan, raw_inputs, {'cancel_phase':guards,'active_runtime_r10':active}, final


def actual_phase_fixture(O):
    directory = ROOT/'reference/actual-capture0374'
    raws = {name:(directory/name).read_bytes() for name in
        ('INTENT.json','CHILD.json','RESULT.json','stdout.original','stderr.original','stdin.original','OUTPUT-CAPTURE.json')}
    result = O.strict(raws['RESULT.json']); original_dir = str(Path(result['stdout']['path']).parent)
    names = {'intent':'INTENT.json','child':'CHILD.json','result':'RESULT.json','stdout':'stdout.original',
        'stderr':'stderr.original','stdin':'stdin.original','output_capture':'OUTPUT-CAPTURE.json'}
    def verify(changes=None, remove=()):
        bodies = dict(raws); bodies.update(changes or {})
        by_path = {original_dir+'/'+name:raw for name,raw in bodies.items()}
        records = {key:{'path':original_dir+'/'+name,'bytes':len(bodies[name]),'sha256':O.sha(bodies[name])}
            for key,name in names.items() if key not in remove}
        intent = O.strict(bodies['INTENT.json'])
        originals = O.Originals(lambda row:by_path[row['path']])
        answer = O.host_phase(originals, records, intent['phase'], intent['argv'], intent['maximum_wait_seconds'], bodies['stdin.original'])
        assert answer == bodies['stdout.original']; originals.recheck()
        return {'original_paths':len(originals.index()),'stdout_bytes':len(answer),'fixture_is_historical_host_capture':True}
    return raws, verify


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--output', required=True); args = ap.parse_args()
    M, source = load(ROOT/'source/coordinate_cpu_cancel_once.py', 'reviewed_coordinator_unit')
    O, _ = load(ROOT/'reference/negative_originals.original.py', 'actual_closer_assembly')
    R, root_raw = load(ROOT/'reference/root-capture-r8.original.py', 'actual_root_capture_module')
    rows = []
    def test(name, call):
        try:
            detail = call(); rows.append({'name':name,'passed':True,'detail':detail})
        except BaseException as error:
            rows.append({'name':name,'passed':False,'error_type':type(error).__name__,'detail':str(error)[:4096]})

    def authority_first():
        calls=[]; old=M.read_regular; M.read_regular=lambda *a,**k:calls.append(a)
        try:rejected(lambda:M.main(['--execute-once','--plan','/must-not-read']), 'unfrozen')
        finally:M.read_regular=old
        assert not calls and M.FINAL_AUTHORITY is None
        return {'private_reads':0,'remote_calls':0}
    test('unfrozen authority rejects before private input or remote action',authority_first)
    test('preview contains no case credit or native allocation',lambda: {'preview':M.preview()})

    def reference_pins():
        index=json.loads((ROOT/'REFERENCE-INDEX.json').read_bytes())
        for row in index['files']:
            raw=(ROOT/row['path']).read_bytes();assert M.byte_pin(raw)=={k:row[k] for k in ('bytes','sha256')}
        return {'complete_reference_files':len(index['files'])}
    test('all retained upstream reference bytes stay exact',reference_pins)
    slots={name:format(i+1,'064x') for i,name in enumerate(O.ROOT_CAPTURE_SLOTS)};slots['VERIFIER_BYTES']=125010
    bound_root=fill(root_raw,slots); parent=(ROOT/'reference/root-Q2.original.py').read_bytes()
    test('whole actual Root source inverses through only seven original RHS slots',lambda: {'bytes':len(O.root_source(bound_root,parent))})
    test('extra Root source byte is rejected before transport use',lambda:rejected(lambda:O.root_source(bound_root+b'\n# extra\n',parent),'exact_reviewed_capture_template'))

    plan,raw_inputs,modules,final=fixture(M)
    authority={'final_dependencies':final,'sources':{'sender':{'path':'/reviewed/sender.py'}}}
    actor_holder={}
    def plans():
        for case in ('NEG-08','NEG-09'):
            p=copy.deepcopy(plan);p['case_id']=case;p['require_image_cancel']=case=='NEG-09'
            M.validate_case_plan(p,authority); actor=M.make_actor_plan(p,raw_inputs,modules)
            assert modules['cancel_phase'].validate_plan(actor)==raw_inputs['request'];actor_holder[case]=actor
        return {'actual_validator':'cancel_phase.validate_plan','cases':['NEG-08','NEG-09'],'synthetic_data_only':True}
    test('both generated plans use actual unchanged Actor validator',plans)
    def drift():
        p=copy.deepcopy(plan);p['runtime_binding']['release_pins']['configuration_sha256']='0'*64
        return rejected(lambda:M.validate_case_plan(p,authority),'same actual source/policy')
    test('mixed source generation rejects before staging',drift)
    test('original Actor stricter wait bound is not silently widened',lambda:rejected(lambda:M.make_actor_plan(dict(plan,wait_seconds=300),raw_inputs,modules),'finite wait'))
    test('boolean wait cannot impersonate an integer',lambda:rejected(lambda:M.validate_case_plan(dict(plan,wait_seconds=True),authority),'wait contract'))
    def different_registration():
        inp=dict(raw_inputs);v=M.strict(inp['registration_template']);v['nonce']='f'*32;inp['registration_template']=M.encode(v)
        return rejected(lambda:M.make_actor_plan(plan,inp,modules),'registered template')
    test('wrong registered nonce never produces an Actor plan',different_registration)

    actor=M.make_actor_plan(plan,raw_inputs,modules)
    actual_scope={**actor['previous_scope'],'task_id':'new-original-task','turn_id':'new-original-turn','turn_stream_id':'new-original-stream'}
    observation={'state':'BOUND_ORIGINAL_PHASE_OBSERVED','scope':actual_scope,'owner_request_sha256':actor['owner_request_sha256'],
        'boot_id':plan['expected_boot'],'native_terminal':{'payload':{'status':'cancelled'}},
        'native_request_sha256':'a'*64,'run':'20261106-010203-'+plan['nonce']}
    result={'schema':'hepta.r10.native-cancel-once-result.v1','state':'ORIGINAL_CANCEL_AND_DRAIN_OBSERVED',
        'case_id':plan['case_id'],'owner_request_sha256':actor['owner_request_sha256'],'cancel_tap_attempts':1,
        'cancel_acceptance_observed':True,'native_cancelled_observed':True,
        'original_model_terminal_release_idle_observed':True,'dispatch_prefix_unchanged':True,
        'automatic_retry':False,'scope':actual_scope,'last_original_observation':observation}
    def phone_plan():
        value=M.make_phone_plan(plan,actor,M.encode(actor),result,final)
        assert value['sender_scope']==actual_scope and value['sender_run']==observation['run']
        assert value['operator_plan_sha256']==M.sha(M.encode(actor))
        assert set(value)==O.literal((ROOT/'reference/phone_capture.original.py').read_bytes(),'NEGATIVE_FIELDS')
        return {'fields':sorted(value),'scope_not_generated':True}
    test('phone capture plan derives scope and run only from actual-result fields',phone_plan)
    bad=copy.deepcopy(result);bad['last_original_observation']['scope']={**actual_scope,'task_id':'another'}
    test('Actor and final observation scope disagreement rejects',lambda:rejected(lambda:M.make_phone_plan(plan,actor,M.encode(actor),bad,final),'scope comes only'))
    test('boolean cancellation count cannot produce capture plan',lambda:rejected(lambda:M.make_phone_plan(plan,actor,M.encode(actor),dict(result,cancel_tap_attempts=True),final),'single original'))

    raws,verify_phase=actual_phase_fixture(O)
    test('actual historical complete Root phase is accepted by unchanged CPU closer',verify_phase)
    for label,mutator in (
        ('missing stdout EOF',lambda v:v.update(stdout_eof=False)),
        ('unjoined reader',lambda v:v.update(worker_joined=False)),
        ('created inode substitution',lambda v:v['files']['stdout']['metadata'].update(st_ino=v['files']['stdout']['metadata']['st_ino']+1)),
        ('late EOF beyond original deadline',lambda v:v['eof_observed_monotonic'].update(stdout=v['execution_deadline_monotonic']+1))):
        def run(mutator=mutator):
            cap=O.strict(raws['OUTPUT-CAPTURE.json']);mutator(cap)
            return rejected(lambda:verify_phase({'OUTPUT-CAPTURE.json':O.pretty(cap)}))
        test('actual closer rejects '+label,run)
    def extra_result_field():
        v=O.strict(raws['RESULT.json']);v['output_capture']={}
        return rejected(lambda:verify_phase({'RESULT.json':O.pretty(v)}),'original_host_terminal')
    test('successful RESULT remains exact7 and excludes sidecar fields',extra_result_field)

    def original_argv_contract():
        sender=M.sender_argv(plan,authority);assert sender[-3:]==['--evidence-root','production','--execute-once']
        argv=M.actor_argv(plan,final);timeout=actor['wait_seconds']+240
        code=O.remote_code(bound_root,'remote_program',phase='negative-cancel-actor',
            remote_root=M.P4+'/cpu-negative-controls-r1/'+plan['nonce'],argv=argv,timeout=timeout)
        assert b'negative-cancel-actor' in code and ('timeout='+repr(timeout)).encode() in code
        return {'sender_host_timeout':660,'sender_stdin':None,'actor_inner_timeout':timeout,
            'actor_host_timeout':timeout+30,'generated_original_remote_code_bytes':len(code)}
    test('original sender and Actor argv plus per-phase deadlines remain exact',original_argv_contract)

    def preflight_packet():
        operator={'source/'+p.name:p.read_bytes() for p in (ROOT/'reference/cancel-base').iterdir()}
        operator['source/active_runtime_r10.py']=(ROOT/'reference/active-current-template.py').read_bytes()
        operator['source/production-pins.json']=(ROOT/'reference/production-pins-current.json').read_bytes()
        req=M.preflight_request(actor,M.strict(raw_inputs['previous']),operator)
        argv=shlex.split(req['command']);code=argv[-1];tree=ast.parse(code)
        packed=next(n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='b64decode')
        packet=json.loads(gzip.decompress(base64.b64decode(ast.literal_eval(packed.args[0]),validate=True)))
        assert packet['plan']==actor and len(packet['sources'])==6
        assert req['timeout_seconds']==12 and 'NO_MATCHING_ACCEPTED_TASK' in code
        return {'complete_sources':6,'request_bytes':len(req['command'].encode()),'phone_calls':0}
    test('preflight request retains exact six-source payload and no dispatch action',preflight_packet)

    def chunk_check():
        raw=('中文🙂\n'.encode()+bytes(range(256)))*(M.CHUNK//260+7)
        row=M.descriptor('/fixed/ORIGINALS.tar.gz',raw);parts=[];meta=[1,2,33152,0,0,1,len(raw),3,4]
        for offset in range(0,len(raw),M.CHUNK):
            piece=raw[offset:offset+M.CHUNK];v={**row,'path':row['path'],'total_bytes':len(raw),'offset':offset,
                **M.byte_pin(piece),'metadata':meta,'base64':base64.b64encode(piece).decode(),'eof':offset+len(piece)==len(raw)}
            body,_=M.check_chunk(v,row,offset,meta);parts.append(body)
        assert b''.join(parts)==raw
        v['metadata']=list(meta);v['metadata'][1]+=1
        rejected(lambda:M.check_chunk(v,row,offset,meta),'generation')
        return {'bytes':len(raw),'chunks':len(parts),'binary_and_utf8_exact':True}
    test('full binary archive transport rejects changed inode and preserves complete bytes',chunk_check)

    def one_attempt():
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700);c=M.Coordinator.__new__(M.Coordinator);c.out=Path(tmp);c.tickets=[]
            attempts=[]
            def fail():attempts.append(1);raise ValueError('simulated unknown after dispatch')
            rejected(lambda:c.once('negative-sender',fail),'simulated unknown')
            rejected(lambda:c.once('negative-sender',lambda:attempts.append(2)),'already attempted')
            assert len(attempts)==1 and c.tickets[0]['call_entered'] and not c.tickets[0]['call_returned']
            return {'calls':len(attempts),'unknown_ticket_retained':True}
    test('failed dispatch ticket prevents same-identity replay',one_attempt)

    def stage_create_only():
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);os.chmod(base,0o700);target=base/'new-case'
            raw=b'Chinese \xe4\xb8\xad\xe6\x96\x87\n\x00'
            packet={'operator/source/test.py':{**M.byte_pin(raw),'base64':base64.b64encode(raw).decode()}}
            namespace={'root':target,'forbidden':[],'files':packet}
            with contextlib.redirect_stdout(io.StringIO()):exec(compile(M.STAGE_SOURCE,'exact-stage-source','exec'),namespace)
            assert (target/'operator/source/test.py').read_bytes()==raw
            with contextlib.redirect_stdout(io.StringIO()):rejected(lambda:exec(compile(M.STAGE_SOURCE,'exact-stage-source','exec'),namespace))
            assert (target/'operator/source/test.py').read_bytes()==raw
            return {'actual_stage_function_executed_on_private_local_fixture':True,'replay_overwrites':0}
    test('actual create-only stager retains bytes and refuses existing namespace',stage_create_only)

    def actual_async_join():
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);os.chmod(root,0o700)
            c=R.Chain.__new__(R.Chain);c.out=root;c.steps=[]
            argv=['/usr/bin/python3','-I','-B','-c','import sys;sys.stdout.buffer.write("中文🙂\\n".encode())']
            handle=None
            try:
                handle=c.execute_process('negative-sender',argv,20,None,async_start=True)
                result=M.finish_async_phase(c,R,'negative-sender',handle)
                records=M.phase_records(R,root/'negative-sender',stdin=False)
                body={row['path']:R.read(row['path']) for row in records.values() if row is not None}
                original=O.Originals(lambda row:body[row['path']])
                stdout=O.host_phase(original,records,'negative-sender',argv,20,None)
                assert stdout=='中文🙂\n'.encode() and len(result)==7 and set(records)==M.PHASE_KEYS
                assert not c._owned_host_children and not c._owned_host_captures and not c._owned_host_streams
                return {'actual_original_Root_methods':['execute_process','join_host_capture','persist_host_capture','verify_host_capture_outputs'],
                    'new_async_finalizer':True,'actual_closer_host_phase_accepted':True,
                    'all_seven_originals':{k:None if row is None else {'descriptor':row,'raw_base64':base64.b64encode(body[row['path']]).decode()} for k,row in records.items()},
                    'phone_calls':0,'test_child_exit':0}
            finally:
                if getattr(c,'_owned_host_captures',{}):c.close_owned_host_outputs()
                # Cleanup authority is solely this test's retained local child,
                # never a remote/policy/native process or a numeric pid alone.
                if handle is not None and handle[0].returncode is None:
                    try:handle[0].wait(timeout=3)
                    except BaseException:handle[0].kill();handle[0].wait(timeout=3)
    test('actual local asynchronous Root capture joins and satisfies exact CPU phase verifier',actual_async_join)

    report={'schema':'hepta.cpu-cancel.coordinator-local-regressions.v1',
        'state':'PASS' if all(r['passed'] for r in rows) else 'FAIL','source':M.byte_pin(source),
        'passed':sum(r['passed'] for r in rows),'total':len(rows),'tests':rows,
        'authority_frozen':False,'phone_calls':0,'native_cases_run':0,'physical_case_pass':False,
        'host_isolated_acceptance_case_credit':0,
        'scope':'Implementation source and local transport regressions. Synthetic READY and case data are not actual runtime authority.'}
    path=Path(args.output).resolve();path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(M.encode(report))
    print(json.dumps({'state':report['state'],'passed':report['passed'],'total':report['total'],'report':str(path),**M.byte_pin(path.read_bytes())},sort_keys=True))
    return 0 if report['state']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
