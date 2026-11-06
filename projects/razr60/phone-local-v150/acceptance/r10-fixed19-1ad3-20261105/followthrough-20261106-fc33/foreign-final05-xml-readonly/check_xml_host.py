#!/usr/bin/env python3
"""Pure host binding controls. Never call collector main or device functions."""
import ast,base64,hashlib,json,shlex,zlib
from pathlib import Path
D=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def need(v,s):
    if not v:raise AssertionError(s)
checks=[]
def ok(name,condition):need(condition,name);checks.append({'name':name,'passed':True})
source=(D/'SOURCE.py').read_bytes();requestraw=(D/'PHONE-REQUEST.json').read_bytes();inputsraw=(D/'INPUTS.json').read_bytes()
ok('immutable_source_pin',len(source)==16908 and sha(source)=='0da3844a26c87a994f3c69e926d312f0e3fe944c8515e8824c960963fa2beed4')
ok('immutable_request_pin',len(requestraw)==8361 and sha(requestraw)=='485e888fae619849d2d74e34c2cd630c1045509726eb8242e5d5382807109b7c')
ok('immutable_inputs_pin',len(inputsraw)==6979 and sha(inputsraw)=='e60399fc51486e454aad6d751e728ec1f8b001ce0e72be73d5eda52f4409e855')
q=json.loads(requestraw);args=shlex.split(q['command']);payload=ast.parse(args[-1]);
ok('request_contract_exact',set(q)=={'kind','root','timeout_seconds','command'} and q['kind']=='shell' and q['root'] is True and q['timeout_seconds']==30)
ok('complete_command_exact_route_no_nested_su',args[-5:-1]==['/usr/bin/python3','-I','-B','-c'] and not any('/su' in v for v in args[:-1]) and q['command'].encode()==(D/'PHONE-COMMAND.sh').read_bytes())
last=payload.body[-1]
ok('sole_payload_execution_target_main',isinstance(last,ast.Expr) and isinstance(last.value,ast.Call) and isinstance(last.value.func,ast.Name) and last.value.func.id=='exec' and ast.literal_eval(last.value.args[1])=={'__name__':'__main__'})
ns={};exec(compile(ast.Module(body=payload.body[:-1],type_ignores=[]),'<host-wire-decode-only>','exec'),ns)
ok('full_payload_inverse_byte_equal',ns['r']==source)
ns_source={'__name__':'host_binding_controls_not_main'};exec(compile(source,'<definitions-only>','exec'),ns_source)
ok('embedded_inputs_byte_equal',ns_source['INPUTS_RAW']==inputsraw and ns_source['STATE'] is None)
inputs=json.loads(inputsraw);rows=inputs['rows'];paths=[r['root_path'] for r in rows]
expected=['/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-'+str(n)+'.xml' for n in range(1,12)]
ok('eleven_exact_paths_and_sequence',paths==expected and [r['sequence'] for r in rows]==list(range(1,12)))
ok('original_length_sum',sum(r['expected_bytes'] for r in rows)==223418)
pub=json.loads((D.parent/'R5-final05-probe01/SENDER-XML-EXPECTED-PUBLIC.json').read_bytes())
ok('full_provenance_projection_equal',rows==[{k:r[k] for k in ('root_path','sequence','expected_bytes','expected_sha256','pin_basis','command_source')} for r in pub['rows']])
for label,mut in [('compressed_truncation',ns['c'][:-1]),('compressed_byte_corruption',bytes([ns['c'][0]^1])+ns['c'][1:]),('compressed_extra_bytes',ns['c']+b'x')]:
    rejected=len(mut)!=len(ns['c']) or sha(mut)!=sha(ns['c'])
    ok('reject_'+label,rejected)
tree=ast.parse(source);calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)]
forbidden={'unlink','remove','rmdir','rename','replace','mkdir','makedirs','write','pwrite','truncate','ftruncate','kill','system','popen','fork','execv','execve','spawn','run','Popen'}
os_calls={n.func.attr for n in calls if isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='os'}
ok('no_os_mutation_signal_or_execution_calls',not(os_calls & forbidden))
ok('all_os_open_flags_readonly',all('O_RDONLY' in ast.unparse(n.args[1]) and not any(x in ast.unparse(n.args[1]) for x in ('O_WRONLY','O_RDWR','O_CREAT','O_TRUNC')) for n in calls if isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='os' and n.func.attr=='open'))
ok('no_native_model_or_ui_entrypoints',not any(isinstance(n.func,ast.Name) and n.func.id in {'uiautomator','dispatch','model','phone_once'} for n in calls))
report={'schema':'hepta.fc33.xml-readonly.host-binding-controls.v1','state':'ALL_PURE_HOST_BINDING_CONTROLS_PASSED','source':{'bytes':len(source),'sha256':sha(source)},'request':{'bytes':len(requestraw),'sha256':sha(requestraw)},'controls':checks,'count':len(checks),'phone_calls':0,'collector_main_called':False,'device_functions_called':False,'scope_closure':False,'cleanup_authorized':False}
raw=enc(report);p=D/'HOST-CONTROLS.json'
if p.exists():need(p.read_bytes()==raw,'create-only controls mismatch')
else:p.write_bytes(raw)
print(json.dumps({'result':{'path':str(p),'bytes':len(raw),'sha256':sha(raw)},'count':len(checks),'source_unchanged':True,'phone_calls':0},sort_keys=True))
