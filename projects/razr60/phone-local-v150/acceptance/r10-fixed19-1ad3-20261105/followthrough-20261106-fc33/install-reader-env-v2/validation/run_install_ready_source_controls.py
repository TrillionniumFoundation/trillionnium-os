"""Finite pure/parser controls; no actor, installer, service, or phone is executed."""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1])
need_result = OUT.parent.resolve(strict=True)
OUT.mkdir(mode=0o700)
def load(name):
    path = ROOT / 'source' / name
    module = types.ModuleType(name.removesuffix('.py'))
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module
P = load('install_ready_execution_protocol.py')
R = load('verify_install_start_ready_UNBOUND.py')
cases = []
def test(name, function):
    result = function()
    cases.append({'name': name, 'passed': True})
    return result
def rejects(name, function):
    try:
        function()
    except Exception as error:
        cases.append({'name': name, 'passed': True, 'rejection_class': type(error).__name__})
        return
    raise AssertionError('accepted negative: ' + name)
def check(value):
    if not value:
        raise AssertionError('control assertion')
def canon(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
def row(path, raw, inode=1, root=False, mode=0o600):
    return dict(path=path, **R.pin(raw), metadata=[1,inode,stat.S_IFREG|mode,0 if root else 1000,
                 0 if root else 1000,1,len(raw),1000,1000])
def tool(value):
    return canon({'content':[{'type':'text','text':json.dumps(value)}],
                  'structuredContent':None,'isError':False})

calls = []
rejects('unbound_public_rejects_before_parse_or_callback',
        lambda: R.verify_install_start_ready_originals(b'not-json', read_pinned=lambda x:calls.append(x)))
test('unbound_public_did_no_io', lambda:check(calls == []))
rejects('duplicate_json', lambda:R.strict(b'{"x":1,"x":2}'))
rejects('nonfinite_json', lambda:R.strict(b'{"x":NaN}'))
rejects('bool_original_size', lambda:R.descriptor({'path':'/original','bytes':True,'sha256':'0'*64}))
rejects('incomplete_full9', lambda:R.check_metadata([1]*8))
rejects('hardlink_original', lambda:R.check_metadata([1,1,stat.S_IFREG|0o600,0,0,2,0,1,1]))
rejects('phone_not_root', lambda:R.check_metadata([1,1,stat.S_IFREG|0o600,1000,0,1,0,1,1],root=True))
rejects('ambiguous_relative_namespace', lambda:R.canonical_path('/a/../b'))

pins = {name: chr(ord('a')+number)*64 for number,name in enumerate((
    'source_seal_sha256','configuration_sha256','module_manifest_sha256',
    'service_inputs_sha256','component_boundary_inputs_sha256','policy_adoption_inputs_sha256'))}
release = {'release_pins':pins,'phone_ready':False,'whole_case_pass':False}
release_inputs = {'release_archive':{'path':'/host/actual-unbound/phone-release-v150-r10-r1.tar.gz',
                                    'bytes':16,'sha256':'1'*64}}
plan = {'schema':P.PLAN_SCHEMA,'boot_id':P.BOOT,'release_id':'v150-r10-r1','release_inputs_sha256':'2'*64,
        'actor':dict(path=P.P4+'/ops/phone_once.py',**P.ACTOR_PIN),
        'actor_python':'/usr/bin/python3','actor_cwd':P.P4,
        'archive':dict(path=P.GNU+'/HOST_SOURCE_CONTROL/phone-release-v150-r10-r1.tar.gz',
                       bytes=16,sha256='1'*64),
        'installer':dict(path=P.GNU+'/HOST_SOURCE_CONTROL/install_phone_release_r10.py',**P.INSTALLER_PIN),
        'phases':{name:{'label':'HOST_SOURCE_CONTROL_'+name,
                        'request_path':P.P4+'/requests/HOST_SOURCE_CONTROL_'+name+'.json',
                        'idempotency_key':'HOST_SOURCE_CONTROL_'+name,'timeout_seconds':120}
                  for name in P.PHASES}}
test('finite_plan_source_contract', lambda:P.validate_plan(plan,release,release_inputs))
bad = copy.deepcopy(plan);bad['phases']['stage']['timeout_seconds']=True
rejects('bool_shell_timeout', lambda:P.validate_plan(bad,release,release_inputs))
bad = copy.deepcopy(plan);bad['phases']['ready']['timeout_seconds']=301
rejects('expanded_original_actor_timeout', lambda:P.validate_plan(bad,release,release_inputs))
bad = copy.deepcopy(plan);bad['actor']['sha256']='0'*64
rejects('arbitrary_actor_source', lambda:P.validate_plan(bad,release,release_inputs))
bad = copy.deepcopy(plan);bad['phases']['start']['label']=bad['phases']['stage']['label']
rejects('reused_operation_label', lambda:P.validate_plan(bad,release,release_inputs))
expect = {name:P.expected_phase(plan,name,release,release_inputs,'3'*64) for name in P.PHASES}
test('three_original_cli_phase_vectors', lambda:check(
    expect['stage']['spec']['argv'][-3:] == ['--phase','stage','--execute-reviewed-operation-once']
    and expect['start']['spec']['argv'][-3:] == ['--phase','start','--execute-reviewed-operation-once']
    and expect['ready']['spec']['argv'][:3] == [P.READY,'--expected-boot',P.BOOT]
    and all(x['wire_bytes']<65536 for x in expect.values())
    and all(x['dispatch']['args'][:2]==['-I','-B']for x in expect.values())))
test('entry_guard_compiles_without_execution', lambda:compile(P.GUARD,'<unexecuted-source-guard>','exec'))

# The exact guard AST preserves a primary failure if a local cleanup also fails.
guard_tree = ast.parse(P.GUARD)
cleanup_fn = next(n for n in guard_tree.body if isinstance(n,ast.FunctionDef)and n.name=='preserve_cleanup')
guard_ns = {'sys':sys}
exec(compile(ast.Module(body=[cleanup_fn],type_ignores=[]),'<pure-cleanup-projection>','exec'),guard_ns)
class PrimaryFailure(Exception):pass
def cleanup_primary():
    original = PrimaryFailure('source-control-original')
    try:
        try:raise original
        finally:guard_ns['preserve_cleanup'](lambda:(_ for _ in()).throw(OSError('source-control-cleanup')))
    except PrimaryFailure as error:
        check(error is original and isinstance(error.__cause__,OSError))
test('guard_cleanup_preserves_original_exception_object',cleanup_primary)
rejects('guard_cleanup_failure_cannot_be_success',
        lambda:guard_ns['preserve_cleanup'](lambda:(_ for _ in()).throw(OSError('source-control'))))

raw = b'complete original bytes\n'
origin = row('/phone/example',raw,root=True)
host = row('/host/copy',raw,inode=2)
mapping = [{'namespace':'phone_gnu','original':origin,'retained':host}]
pool = R.Originals(mapping,lambda selected:raw)
test('explicit_namespace_full_bytes_roundtrip',lambda:check(pool.phone(origin,'/phone/example')==raw))
test('original_map_full_bookend',pool.recheck)
rejects('no_implicit_host_path_translation',lambda:pool.read(dict(origin,path='/proc/1/root/phone/example')))
wrongpool=R.Originals(mapping,lambda selected:b'tail only\n')
rejects('truncated_retained_copy',lambda:wrongpool.read(origin))
mutable=[raw]
unstable=R.Originals(mapping,lambda selected:mutable[0]);unstable.read(origin);mutable[0]=b'changed'
rejects('changed_retained_bookend',unstable.recheck)
rejects('duplicate_original_map_row',lambda:R.Originals(mapping+mapping,lambda selected:raw))

# Original-controller fixtures below are explicitly synthetic. They test parsing
# and command linkage only, and are never represented as actual controller receipts.
summary={'run':expect['stage']['actor_operation_dir'],'status':'command_exited',
         'sha256':'4'*64,'elapsed_seconds':0.1,'http_status':None,'phone_rc':0,'error':None}
summary_raw=(json.dumps(summary,ensure_ascii=False)+'\n').encode()
job=dict(expect['stage']['dispatch'],id='HOST_SOURCE_CONTROL_JOB',created_unix_ms=1000,
         launch_state='launched',launch_error=None,env_keys=[])
start={'job':job,'reused':False}
status={'job_id':job['id'],'state':'succeeded','exit_code':0,'at_unix_ms':2000,
        'output_complete':True,'output_durable':True,'terminal_publication_confirmed':True,
        'timed_out':False,'cancelled':False,'log_errors':{'stdout':None,'stderr':None},
        'log_truncated':{'stdout':False,'stderr':False},'log_synced':{'stdout':True,'stderr':True},
        'log_bytes':{'stdout':{'seen':len(summary_raw),'stored':len(summary_raw)},'stderr':{'seen':0,'stored':0}}}
def stream(b):return dict(bytes_hex=b.hex(),eof=True,next_offset=len(b),offset=0,size=len(b),text=b.decode())
read={'job_id':job['id'],'stdout':stream(summary_raw),'stderr':stream(b'')}
def process_fixture(changes=None):
    values={'dispatch':canon(expect['stage']['dispatch']),'start':tool(copy.deepcopy(start)),
            'status':tool(copy.deepcopy(status)),'read':tool(copy.deepcopy(read))}
    if changes:changes(values)
    refs={k:dict(path='/synthetic/'+k,**R.pin(v))for k,v in values.items()}
    class FixturePool:
        def read(self,record,maximum):return values[PurePosixPath(record['path']).name]
    return R.verify_process(refs,expect['stage'],FixturePool())
test('synthetic_controller_complete_original_shape',process_fixture)
def modify_tool(key,modifier):
    def alter(values):
        x=R.tool_value(values[key]);modifier(x);values[key]=tool(x)
    return alter
rejects('actual_argv_cannot_be_self_reported_elsewhere',
        lambda:process_fixture(modify_tool('start',lambda x:x['job']['args'].append('--unreviewed'))))
rejects('reuse_refused',lambda:process_fixture(modify_tool('start',lambda x:x.update(reused=True))))
rejects('nonzero_actor_wait_preserved',
        lambda:process_fixture(modify_tool('status',lambda x:x.update(state='failed',exit_code=7))))
rejects('unknown_actor_exit_refused',lambda:process_fixture(modify_tool('status',lambda x:x.update(exit_code=None))))
rejects('missing_original_eof',lambda:process_fixture(modify_tool('read',lambda x:x['stdout'].update(eof=False))))
rejects('truncated_original_stream',lambda:process_fixture(modify_tool('status',lambda x:x['log_truncated'].update(stdout=True))))
rejects('controller_zero_does_not_imply_phone_zero',
        lambda:process_fixture(modify_tool('read',lambda x:x['stdout'].update(text='{}'))))

actual_installer=(ROOT/'references/installer.original.py').read_bytes()
source_row=row(plan['installer']['path'],actual_installer,inode=25,root=True)
proc=b'123 (synthetic control) R 122 123 123 '+b'0 '*15+b'999 0\n'
check(R.proc_identity(proc)==[123,122,123,123,999])
receipt={'schema':'hepta.production.install-ready.entry-original.v1','boot_id':R.BOOT,'phase':'stage',
         'source':source_row,'argv':expect['stage']['spec']['argv'],'identity':[123,122,123,123,999],
         'proc_before_base64':base64.b64encode(proc).decode(),'proc_after_base64':base64.b64encode(proc).decode(),
         'started_monotonic_ns':1000,'observed_monotonic_ns':2000,'source_bytes_verified':True,
         'exec_started_here':False,'independent_parent_wait_claimed':False}
source_map=[{'namespace':'phone_gnu','original':source_row,'retained':row('/host/installer-copy',actual_installer,inode=26)}]
source_pool=R.Originals(source_map,lambda selected:actual_installer)
def guard_bytes(value):return P.RECEIPT_PREFIX+canon(value)
test('synthetic_guard_actual_source_bytes_and_raw_proc_join',
     lambda:R.verify_guard(guard_bytes(receipt),expect['stage'],P,source_pool))
bad=copy.deepcopy(receipt);bad['identity'][-1]+=1
rejects('source_receipt_mismatched_proc_start_ticks',lambda:R.verify_guard(guard_bytes(bad),expect['stage'],P,source_pool))
bad=copy.deepcopy(receipt);bad['source']['metadata'][3]=1000
rejects('source_receipt_nonroot_original',lambda:R.verify_guard(guard_bytes(bad),expect['stage'],P,source_pool))
bad=copy.deepcopy(receipt);bad['argv'][-2]='ready'
rejects('source_receipt_wrong_exact_entry_argv',lambda:R.verify_guard(guard_bytes(bad),expect['stage'],P,source_pool))
rejects('entry_stderr_after_receipt_not_dropped',lambda:R.verify_guard(guard_bytes(receipt)+b'entry error\n',expect['stage'],P,source_pool))
rejects('incomplete_guard_receipt',lambda:R.verify_guard(guard_bytes(receipt)[:-1],expect['stage'],P,source_pool))

# Exact original pure validate_install_delta AST: no synthetic relaxation.
consumer_raw=(ROOT/'references/consumer.original.py').read_bytes()
check(R.pin(consumer_raw)=={'bytes':243806,'sha256':'3de6208604022671d4db21e2b479e3ef4d4bba4aaa9d2faa360f1865aec428da'})
tree=ast.parse(consumer_raw);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate_install_delta')
ns={'Path':PurePosixPath,'stat':stat,'need':R.need,'INSTALL_DIRECTORY':R.GNU+'/executor-r6/module-history-r10-r1'}
exec(compile(ast.Module(body=[fn],type_ignores=[]),'<unchanged-original-install-delta-projection>','exec'),ns)
parent=R.GNU+'/executor-r6';child=ns['INSTALL_DIRECTORY'];old=parent+'/keep'
before={'schema':'hepta.native-guard.complete-inventory.v1','roots':[parent],'file_bytes_hashed':4,
        'inventory_is_closure_or_retirement':False,'elapsed_seconds':0.1,
        'entries':{parent:{'kind':'directory','metadata':[1,5,stat.S_IFDIR|0o700,0,0,2,64,10,10],'names':['keep']},
                   old:{'kind':'file','metadata':[1,6,stat.S_IFREG|0o600,0,0,1,4,10,10],'sha256':'0'*64}}}
after=copy.deepcopy(before);after['entries'][parent]['metadata'][5:]=[3,128,11,11];after['entries'][parent]['names']=['keep','module-history-r10-r1']
after['entries'][child]={'kind':'directory','metadata':[1,7,stat.S_IFDIR|0o700,0,0,2,64,11,11],'names':[]}
test('unchanged_parent_pure_empty_directory_delta',lambda:ns['validate_install_delta'](before,after))
bad=copy.deepcopy(after);bad['entries'][old]['sha256']='1'*64
rejects('stage_cannot_change_old_original',lambda:ns['validate_install_delta'](before,bad))
bad=copy.deepcopy(after);bad['entries'][child]['names']=['unexpected']
rejects('stage_directory_must_be_empty',lambda:ns['validate_install_delta'](before,bad))
test('source_file_and_stdout_json_formats_remain_distinct',
     lambda:check(R.original_file_json({'state':'STAGED_DISABLED_NOT_STARTED'})!=
                  R.original_entry_stdout({'state':'STAGED_DISABLED_NOT_STARTED'})))
test('all_actual_public_slots_still_none',
     lambda:check(R.FROZEN_INPUTS is None and R.FROZEN_EXECUTION_PLAN is None))

source_rows=[]
for path in sorted((ROOT/'source').glob('*.py')):
    body=path.read_bytes();source_rows.append(dict(path=str(path),**R.pin(body)))
result={'schema':'hepta.production.install-ready.host-source-controls.v1','state':'PASS_SOURCE_ONLY',
        'passed':len(cases),'tests':cases,'sources':source_rows,
        'public_api_actual_positive_executed':False,'synthetic_phase_fixture_used':True,
        'actual_builds':0,'actual_phone_operations':0,'actual_installs':0,'actual_READY':0,
        'new_nonces':0,'whole_qualification':False,'fixed19_credit':0,
        'test_scope':'pure original-byte/namespace/CLI/phase/guard parsers and unchanged parent delta only'}
result_raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
with (OUT/'RESULT.json').open('xb')as f:f.write(result_raw)
sys.stdout.buffer.write(result_raw)
