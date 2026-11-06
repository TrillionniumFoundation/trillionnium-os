#!/usr/bin/env python3
"""Bind original host wait, synchronous SSH result, scope failure, and source pins."""
from pathlib import Path
import ast,hashlib,json
D=Path(__file__).resolve().parent
F=D.parent/'R5-stage-parent-diagnosis01/foreign-final05'
def need(v,s):
    if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def raw(p,n,h):
    b=p.read_bytes();need((len(b),sha(b))==(n,h),'original pin '+str(p));return b
def pin(p):
    b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
planraw=raw(F/'ROOT-PLAN.original.json',4856,'b7c0181cd3bedf16766e6bf6fab483e0f4118859c14c30356a8ec172eb29a100');plan=json.loads(planraw)
source_raw=raw(D/'send_component_host_navigation_once.original.py',41633,'0f4b8d992009102b4f91d6fbd11ce2306a74a9287b5266c64d48207966ca1759')
manifest_raw=raw(D/'SENDER-SOURCE-MANIFEST.original.json',40520,'7fae0095783e0d89f3aee15322d45266057f8275d6a01b882d1b178805d391d6');manifest=json.loads(manifest_raw)
need(plan['source_package']['sha256']==sha(manifest_raw) and plan['source_package']['bytes']==len(manifest_raw),'root plan exact source package')
entry=next(r for r in manifest['files'] if r['path']=='source/send_component_host_navigation_once.py')
need(entry['sha256']==sha(source_raw) and entry['bytes']==len(source_raw),'actual historical source package member')
carrier=json.loads((D/'SENDER-HOST-CONTROLLER.original.mcp.json').read_bytes());originals={Path(r['path']).name:r for r in carrier['files']}
def controller(name,n,h):
    r=originals[name];b=r['text'].encode();need((len(b),sha(b))==(n,h) and r['size']==n and r['sha256']==h,'original controller raw pin');return json.loads(b)
intent=controller('INTENT.json',2291,'8eff08398f2d99cd1bb05563da7684b922ecdceecdedc0855ede6bbe7e535266')
child=controller('CHILD.json',907,'c92d7245598091ecd17e321a61a2474ccda9f0b3c1ddf934e474ef7a639df596')
capture=controller('OUTPUT-CAPTURE.json',2512,'e1e60174e468a8c49ddcc85efa8eec6a99a44cf87ef004f743e4003ab6bfbb0a')
need(intent['phase']=='sender-execute' and intent['argv'][:3]==['/usr/bin/python3','-I','-B'] and intent['argv'][3]==str(Path(plan['source_package']['path']).parent/'source/send_component_host_navigation_once.py') and intent['argv'][4]==plan['label'] and intent['argv'][-1]=='--execute-once','original exact sender executable')
need(intent['maximum_starts']==1 and intent['automatic_retry'] is False and intent['signals_on_timeout'] is False,'original one-start contract')
need(child['pid']==child['pgid']==child['sid']==62500 and child['source_intent_sha256']==originals['INTENT.json']['sha256'],'original owned host identity')
need(capture['phase']=='sender-execute' and capture['pid']==62500 and capture['source_intent_sha256']==child['source_intent_sha256'] and capture['child_wait_returned'] is True and capture['child_returncode']==0,'original actual owned host wait returned')
need(capture['stdout_eof'] is True and capture['stderr_eof'] is True and capture['worker_joined'] is True and capture['prefix_only_or_unknown'] is False and capture['error'] is None and capture['persist_errors']==capture['pipe_close_errors']==[] and capture['signals_sent']==0,'complete dual EOF/persistence/join without signals')
stdout=raw(F/'sender-execute/stdout.original',678,'20f7ba2dd1b701fdaba15bd15e228653cad2feed61a691aba748923d54d74816')
receipt_raw=raw(D/'SENDER-ACTUAL-RESULT.original.json',678,'20f7ba2dd1b701fdaba15bd15e228653cad2feed61a691aba748923d54d74816')
need(stdout==receipt_raw and capture['captured']['stdout']=={'bytes':678,'sha256':sha(stdout)} and capture['captured']['stderr']=={'bytes':0,'sha256':sha(b'')},'original actual receipt and exact captured stdout')
receipt=json.loads(receipt_raw);terminal=json.loads(receipt['stdout'])
need(set(receipt)=={'rc','stdout','stderr'} and receipt['rc']==2 and receipt['stderr']=='','actual synchronous SSH nonzero result not UNKNOWN')
need(terminal['state']=='PRE_SEND_OR_ACTOR_FAILURE' and terminal['out']=='/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150' and terminal['prompt_sha256']==plan['request']['sha256'] and terminal['send_attempt_count']==0 and terminal['automatic_replay'] is False and terminal['business_success_verified'] is False,'exact original no-Send actor terminal')
need(terminal['draft_restore']=={'state':'ORIGINAL_DRAFT_RESTORED','restore_attempts':1,'original_draft_submitted':False} and terminal['retirement_resolution_sha256']==plan['sender_retirement_resolution']['sha256'],'original draft restoration terminal')
tree=ast.parse(source_raw);calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess']
need(len(calls)==1 and calls[0].func.attr=='run' and ast.unparse(calls[0])=='subprocess.run(ssh, input=source.encode(), capture_output=True, timeout=600)','reviewed source exact synchronous subprocess, no detached sender')
source_text=source_raw.decode()
need("receipt = {'rc': result.returncode, 'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')}" in source_text and "receipt = {'UNKNOWN': str(error), 'automatic_replay': False}" in source_text,'actual status source versus exception branch')
need("if exit_code:raise SystemExit(exit_code)" in source_text and "'PRE_SEND_OR_ACTOR_FAILURE'" in source_text and "exit_code=2" in source_text,'original remote terminal and exit path')
failure_raw=raw(F/'ROOT-FAILURE.json',13831,'1e8e43e90551df4638cb2853754557243bb902547b4923ca2991083cdb9f0cbf');failure=json.loads(failure_raw)
host=next(r for r in failure['host_cleanup']['host_children'] if r['phase']=='sender-execute')
need(host['output_capture']==capture and host['child_wait_returned'] is True and host['returncode']==0 and host['cleanup_errors']==[] and host['signals_sent']==0,'original ROOT failure retains same actual joined host child')
need(capture['remote_terminal_or_cleanup_proven'] is False and host['remote_terminal_or_cleanup_proven'] is False,'generic original unknown is preserved')
report={'schema':'hepta.fc33.final05.sender-terminal-derived-proof.v1','state':'EXACT_HOST_JOIN_AND_SYNCHRONOUS_SENDER_TERMINAL_BOUND_NO_CASE_CREDIT',
 'source_original':pin(D/'send_component_host_navigation_once.original.py'),'source_manifest_original':pin(D/'SENDER-SOURCE-MANIFEST.original.json'),'root_plan_original':pin(F/'ROOT-PLAN.original.json'),'root_failure_original':pin(F/'ROOT-FAILURE.json'),
 'controller_originals':[{k:r[k] for k in ('path','size','sha256','version')} for r in originals.values()],
 'actual_send_result_original':pin(D/'SENDER-ACTUAL-RESULT.original.json'),'actual_host_stdout_original':pin(F/'sender-execute/stdout.original'),
 'host_identity':{'pid':62500,'pgid':62500,'sid':62500,'wait_returned':True,'returncode':0,'stdout_bytes':678,'stderr_bytes':0,'both_eof':True,'worker_joined':True,'signals_sent':0},
 'synchronous_remote_sender':{'rc':2,'terminal_state':terminal['state'],'terminal_stdout_utf8_sha256':sha(receipt['stdout'].encode()),'source_subprocess':'subprocess.run exact source above; completed result branch, not exception/timeout','terminal_and_exit_path_bound':True,'new_signal_sent':False,'historical_remote_pid_or_wait_status_invented':False},
 'scope':{'label':plan['label'],'nonce':plan['nonce'],'owner_request_sha256':plan['request']['sha256'],'package_sha256':plan['package']['sha256']},
 'send_attempt_count':0,'draft_restore_attempt_count':1,'original_draft_submitted':False,
 'generic_original_remote_terminal_or_cleanup_proven_preserved':False,'scope_closure':False,'component_qualified':False,'business_qualified':False,'deletion_authorized':False,
 'separate_scope_liveness_proof_required':'Exact supervisor/sidecar generations, complete proc and kernel signal-zero absence under recovery locks; this host result does not replace it.',
 'phone_calls':0,'new_host_or_device_signals':0}
b=enc(report);p=D/'SENDER-TERMINAL-PROOF.json'
if p.exists():need(p.read_bytes()==b,'create-only proof mismatch')
else:p.write_bytes(b)
print(json.dumps({'proof':{'path':str(p),'bytes':len(b),'sha256':sha(b)},'host_child_joined':True,'synchronous_sender_rc':2,'send_attempt_count':0,'draft_restore_attempts':1,'scope_closure':False},sort_keys=True))
