"""Submit one ordinary natural-language task through the real HEPTA UI.

R3 adds a bounded read-only original-native terminal latency observation.
Only Root operates the phone. No control commands or coordinates are supplied
to the model; app actions must come from its own observed UI and tool decisions.
"""
from pathlib import Path
import argparse, hashlib, json, os, subprocess

READ_ONLY_PROBE = "import base64,hashlib,json,os,re,stat,sys\nfrom pathlib import Path\nWANTED=sys.argv[1]\nHINT=json.loads(base64.b64decode(sys.argv[2])) if len(sys.argv)>2 and sys.argv[2]!='-' else None\nassert re.fullmatch('[0-9a-f]{64}',WANTED)\nE=Path('/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence')\nJ=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')\nKEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')\ndef sha(b): return hashlib.sha256(b).hexdigest()\ndef strict(b):\n def pairs(xs):\n  result={}\n  for k,v in xs:\n   if k in result: raise ValueError('duplicate_json_key')\n   result[k]=v\n  return result\n return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite_json')))\ndef canonical_directory(p):\n assert p.is_dir() and not p.is_symlink() and p.resolve()==p,'noncanonical_evidence_directory'\ncanonical_directory(E);canonical_directory(J)\ndirs=sorted([p for p in E.iterdir() if re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',p.name)])\nassert len(dirs)<=512,'provider_directory_bound'\nmatches=[]\nfor d in dirs:\n canonical_directory(d)\n p=d/'provider-in.jsonl'\n try: fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n except FileNotFoundError: continue\n try:\n  before=os.fstat(fd)\n  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1,'provider_file_type'\n  raw=os.read(fd,131072)\n  after=os.fstat(fd)\n  assert (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino) and after.st_size>=before.st_size,'provider_file_identity'\n finally: os.close(fd)\n for line in raw.splitlines(keepends=True):\n  if not line.endswith(b'\\n'): continue\n  frame=strict(line)\n  if frame.get('kind')!='turn.start': continue\n  turn=frame.get('turn',{})\n  if not isinstance(turn.get('user_input'),str) or sha(turn['user_input'].encode('utf-8'))!=WANTED: continue\n  scope={k:turn.get(k) for k in KEYS}\n  assert all(isinstance(v,str) and 0<len(v.encode())<=256 and '\\0' not in v for v in scope.values()),'provider_scope'\n  matches.append({'run_dir':str(d),'provider_input_file':str(p),'scope':scope,'owner_utf8_sha256':WANTED,\n                  'provider_start_original_b64':base64.b64encode(line).decode(),\n                  'provider_start_original_sha256':sha(line),'provider_start_original_bytes':len(line)})\nanswer={'schema':'hepta.read-only-new-turn-observation.v150.r3','owner_utf8_sha256':WANTED,\n        'provider_match_count':len(matches),'phone_writes':False,'model_requests':0,'tool_dispatches':0,\n        'native_hash_chain_verified':False,'business_qualified':False}\nif not matches:\n answer['state']='no_matching_provider_start'\nelif len(matches)!=1:\n answer.update(state='ambiguous_matching_provider_starts',matches=matches)\nelse:\n match=matches[0];scope=match['scope'];answer['match']=match\n if HINT is not None and HINT!=scope:\n  answer['state']='scope_changed'\n else:\n  files=sorted(J.glob('*.jsonl'));assert len(files)<=1024,'native_segment_count_bound'\n  total=0;selected=[];terminal=[]\n  needle=scope['turn_id'].encode('utf-8')\n  for p in files:\n   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n   try:\n    info=os.fstat(fd)\n    assert stat.S_ISREG(info.st_mode) and info.st_nlink==1,'native_file_type'\n    total+=info.st_size;assert total<=64*1024*1024,'native_scan_bytes_bound'\n    with os.fdopen(fd,'rb',closefd=False) as stream:\n     while True:\n      raw=stream.readline(4*1024*1024+1)\n      if not raw: break\n      assert len(raw)<=4*1024*1024,'native_record_bytes_bound'\n      if not raw.endswith(b'\\n'): continue\n      if needle not in raw: continue\n      row=strict(raw)\n      if row.get('scope')!=scope: continue\n      payload=row.get('payload',{});frame=payload.get('frame',{})\n      assert isinstance(frame,dict),'native_frame_type'\n      selected.append({'file':str(p),'store_seq':row.get('store_seq'),'turn_seq':row.get('turn_seq'),\n                       'kind':frame.get('kind'),'row_kind':row.get('kind'),'request_sha256':payload.get('request_sha256'),\n                       'record_sha256':row.get('record_sha256'),'raw_line_sha256':sha(raw),'raw_line_bytes':len(raw)})\n      if frame.get('kind')=='turn.end':\n       terminal.append({'frame':frame,'record':row,'raw_line_b64':base64.b64encode(raw).decode(),\n                        'raw_line_sha256':sha(raw),'raw_line_bytes':len(raw),'source':str(p)})\n   finally: os.close(fd)\n  selected.sort(key=lambda r:r['turn_seq'] if type(r['turn_seq']) is int else -1)\n  assert [r['turn_seq'] for r in selected]==list(range(len(selected))),'native_turn_sequence_gap_or_duplicate'\n  hashes={r['request_sha256'] for r in selected}\n  assert len(hashes)<=1 and all(isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) for x in hashes),'native_request_hash_binding'\n  answer.update(native_records=selected,native_record_count=len(selected),native_scanned_bytes=total,\n                native_request_sha256=next(iter(hashes)) if hashes else None)\n  assert len(terminal)<=1,'duplicate_native_terminal'\n  if terminal:\n   assert selected and selected[-1]['kind']=='turn.end' and terminal[0]['record']['turn_seq']==selected[-1]['turn_seq'],'native_terminal_order'\n   assert terminal[0]['frame'].get('payload',{}).get('status') in ('completed','provider_failed','cancelled'),'native_terminal_status'\n   answer.update(state='native_terminal_observed',native_terminal=terminal[0])\n  else: answer['state']='native_pending'\nprint(json.dumps(answer,ensure_ascii=False,separators=(',',':'),allow_nan=False))\n"
LATENCY_OBSERVER = "import signal\nclass OriginalReadDeadline(RuntimeError): pass\ndef latency_read_original(scope=None):\n # Entire host route discovery plus wire read has an 8-second alarm.\n # Remote process is read-only and separately bounded by BusyBox 6s + 1s kill.\n def alarm(_signum,_frame): raise OriginalReadDeadline('read_only_probe_total_deadline')\n previous_handler=signal.getsignal(signal.SIGALRM)\n previous_timer=signal.getitimer(signal.ITIMER_REAL)\n assert previous_timer==(0.0,0.0),'preexisting observer alarm; no read'\n signal.signal(signal.SIGALRM,alarm)\n start=time.monotonic_ns()\n result=None\n try:\n  signal.setitimer(signal.ITIMER_REAL,8.0)\n  hint=base64.b64encode(json.dumps(scope,separators=(',',':')).encode()).decode() if scope else '-'\n  command='/data/adb/magisk/busybox timeout -s TERM -k 1 6 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -c '+shlex.quote(READ_ONLY_PROBE_SOURCE)+' '+shlex.quote(hashlib.sha256(expected.encode()).hexdigest())+' '+shlex.quote(hint)\n  result=f.shell('/debug_ramdisk/su -c '+shlex.quote(command),c,t,timeout=6)\n  assert result['rc']==0,'read-only probe nonzero exit'\n  value=json.loads(result['stdout'])\n  assert value['owner_utf8_sha256']==hashlib.sha256(expected.encode()).hexdigest(),'probe request binding'\n  return {'read_start_monotonic_ns':start,'read_end_monotonic_ns':time.monotonic_ns(),\n          'read_deadline_seconds':8,'original_wire_receipt':result,'observation':value}\n except Exception as error:\n  return {'read_start_monotonic_ns':start,'read_end_monotonic_ns':time.monotonic_ns(),\n          'read_deadline_seconds':8,'original_wire_receipt':result,\n          'read_error_type':type(error).__name__,'read_error':str(error),'automatic_send_retry':False}\n finally:\n  signal.setitimer(signal.ITIMER_REAL,0)\n  signal.signal(signal.SIGALRM,previous_handler)\ndef observe_original_terminal(send_started_monotonic_ns,send_returned_monotonic_ns,send_status):\n deadline=send_started_monotonic_ns+335_000_000_000\n scope=None;count=0;reads=[];last_negative_start=None;result=None\n while time.monotonic_ns()+8_000_000_000<=deadline:\n  count+=1\n  reading=latency_read_original(scope)\n  save('LATENCY-%04d.original-read.json'%count,reading)\n  observation=reading.get('observation')\n  reads.append({'start':reading['read_start_monotonic_ns'],'end':reading['read_end_monotonic_ns'],\n                'state':observation.get('state') if observation else 'read_unknown'})\n  if observation:\n   state=observation['state']\n   if state in ('ambiguous_matching_provider_starts','scope_changed'):\n    result={'state':'UNKNOWN_SCOPE_BINDING','original_observation':observation};break\n   if 'match' in observation:\n    observed_scope=observation['match']['scope']\n    assert observed_scope!=previous_identity,'old scope cannot be the fresh task'\n    if scope is None: scope=observed_scope\n    assert scope==observed_scope,'observation changed scope'\n   if state=='native_terminal_observed':\n    end=reading['read_end_monotonic_ns']\n    lower=max(send_started_monotonic_ns,last_negative_start or send_started_monotonic_ns)\n    result={'state':'ORIGINAL_NATIVE_TERMINAL_OBSERVED','native_status':observation['native_terminal']['frame']['payload']['status'],\n            'terminal_observation_end_monotonic_ns':end,\n            'send_to_terminal_observed_seconds':(end-send_started_monotonic_ns)/1e9,\n            'terminal_persistence_latency_interval_seconds':[(lower-send_started_monotonic_ns)/1e9,(end-send_started_monotonic_ns)/1e9],\n            'observation_uncertainty_interval_seconds':(end-lower)/1e9,\n            'original_observation':observation}\n    break\n   if state=='native_pending':\n    last_negative_start=reading['read_start_monotonic_ns']\n  pause=min(0.75,max(0,(deadline-time.monotonic_ns())/1e9-8))\n  if pause: time.sleep(pause)\n if result is None: result={'state':'UNKNOWN_MONITOR_BOUND_REACHED','next':'Read the same original request/scope only; never Send again'}\n ends=[r['end']-r['start'] for r in reads]\n gaps=[reads[i]['start']-reads[i-1]['start'] for i in range(1,len(reads))]\n result.update(schema='hepta.p4-send-native-terminal-latency.v150.r3',\n   owner_request_utf8_sha256=hashlib.sha256(expected.encode()).hexdigest(),scope=scope,\n   send_call_started_monotonic_ns=send_started_monotonic_ns,\n   send_call_returned_monotonic_ns=send_returned_monotonic_ns,send_wire_state=send_status,\n   clock='Pocket4 time.monotonic_ns, one actor process',monitor_budget_seconds=335,\n   read_deadline_seconds=8,poll_pause_seconds=0.75,\n   nominal_poll_start_interval_upper_seconds=8.75,\n   maximum_observed_poll_start_interval_seconds=max(gaps,default=0)/1e9,\n   maximum_observed_read_seconds=max(ends,default=0)/1e9,\n   observer_elapsed_seconds=(time.monotonic_ns()-send_started_monotonic_ns)/1e9,\n   read_count=count,automatic_send_retry=False,send_attempt_count=1,\n   native_hash_chain_verified=False,business_success_verified=False,\n   qualification='Observed native terminal latency upper bound; independent collector still required',\n   original_receipts_preserved=True)\n save('SEND-NATIVE-LATENCY.json',result)\n return result\n"

BASE = Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument('label')
p.add_argument('request_file', type=Path)
p.add_argument('previous_report', type=Path)
p.add_argument('--preserved-draft', type=Path, required=True)
p.add_argument('--reset-probe', action='store_true')
args = p.parse_args()
import base64, re
assert re.fullmatch(r'[a-z0-9-]{1,70}',args.label)
prompt = args.request_file.read_text(encoding='utf-8')
assert 20 <= len(prompt.encode()) <= 16000
preserved = json.loads(args.preserved_draft.read_bytes())
preserved_draft = base64.b64decode(preserved['exact_utf8_b64'],validate=True).decode('utf-8')
assert hashlib.sha256(preserved_draft.encode()).hexdigest()==preserved['utf8_sha256']
previous = json.loads(args.previous_report.read_bytes())
identity = previous['identity']
digest = previous['request_sha256']
assert len(digest) == 64
known_failed = previous.get('known_no_phone_tool_execution') is True or previous.get('known_all_dispatched_tools_confirmed_terminal') is True
previous_status = previous.get('terminal', {}).get('status', 'provider_failed' if known_failed else 'completed')
assert previous_status in ('completed', 'provider_failed', 'cancelled'), 'Prior terminal requires explicit review'
assert previous_status == 'completed' or known_failed, 'Prior effects require confirmed terminal outcomes'
label = args.label
old = (BASE.parent / 'stock16-hepta-control-check-Root-v146-r1/control_send_once.py').read_text()
assert hashlib.sha256(old.encode()).hexdigest()=='ca200ab35d39ec42232e853c785ab298958858cb4f03e2092231d1ccc638fc70'
source = old[:old.index('expected=')]
source += 'label=' + repr(label) + '\nreset_probe=' + repr(args.reset_probe) + '\n'
source += 'preserved_draft=' + repr(preserved_draft) + '\n'
source += 'expected=' + repr(prompt) + '\nprevious_identity=' + repr(identity) + '\nprevious_digest=' + repr(digest) + '\nprevious_status=' + repr(previous_status) + '\n'
source += 'known_all_prior_tools_confirmed=' + repr(previous.get('known_all_dispatched_tools_confirmed_terminal') is True) + '\n'
decoder = (BASE.parent / 'stock16-hepta-app-task-selection-source-B-v147-r1/decode_client_state.py').read_text()
assert hashlib.sha256(decoder.encode()).hexdigest()=='a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'
source += decoder[:decoder.index("if __name__ == '__main__':")] + '\n'
source += "out=Path('/operator-workspace/pocket4/codex-hepta-natural-" + label + "-root-v150');os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)\n"
helpers = old[old.index('def save('):old.index("sh('svc power stayon")]
helpers = helpers.replace('hepta-control-v146-', 'hepta-natural-' + label + '-v150-')
helpers = helpers.replace("'uiautomator dump '+path+'; cat '+path", "'test ! -e '+path+' && uiautomator dump '+path+' && cat '+path")
source += helpers
source += 'READ_ONLY_PROBE_SOURCE=' + repr(READ_ONLY_PROBE) + '\n'
source += LATENCY_OBSERVER
source += r'''
if reset_probe:sh('am force-stop org.trillionnium.hepta.controlprobe')
sh('input keyevent 224; wm dismiss-keyguard; cmd statusbar collapse; am start -W -n org.trillionnium.owneropen/.OwnerOpenShellActivity')
nodes=dump('INITIAL')
for index in range(4):
 if any(n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_prompt' for n in nodes):break
 dismiss=[n for n in nodes if n.attrib.get('package')=='org.trillionnium.owneropen' and n.attrib.get('resource-id')=='android:id/button2' and n.attrib.get('text') in ('关闭','返回','完成') and n.attrib.get('clickable')=='true']
 assert len(dismiss)==1,'Unknown modal retained; no task sent'
 tap(dismiss[0]);nodes=dump('DISMISS-INFO-'+str(index))
assert any(n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_prompt' for n in nodes)
status=node(nodes,'org.trillionnium.owneropen:id/ui_control_status').attrib.get('text','')
assert '暂停' not in status,'Task arming is paused; no task sent'
editor=node(nodes,'org.trillionnium.owneropen:id/ui_prompt');existing=editor.attrib.get('text','')
# A preserved-empty draft is independently confirmed with the frozen helper.
# Its CAS still compares effectiveText==empty before the only new input action.
if preserved_draft=='' and editor.attrib.get('hint') and existing==editor.attrib.get('hint'):
 existing=''
assert existing == preserved_draft, 'Draft changed since immutable preservation; no task sent'
save('PRESERVED-USER-DRAFT.json',{'exact_text':existing,'utf8_sha256':hashlib.sha256(existing.encode()).hexdigest(),'restore_required':True,'submitted_original_draft':False})
if existing!=expected:
 tap(editor)
 helper='CLASSPATH=/data/local/tmp/hepta-unicode-v148-r2/input.jar app_process /system/bin org.trillionnium.hepta.input.UnicodeInput set-text --operation-id root-prompt-' + label + ' --display 0 --package org.trillionnium.owneropen --view-id org.trillionnium.owneropen:id/ui_prompt --expected-text-b64 '+shlex.quote(base64.b64encode(existing.encode()).decode() or '-')+' --text-b64 '+shlex.quote(base64.b64encode(expected.encode()).decode())
 result=sh(helper);save('OPERATOR-CHINESE-PROMPT-INPUT.json',result);answer=json.loads(result['stdout']);assert answer['status'] in ('set_verified','already_exact') and answer['own_automation_disconnected'] is True and base64.b64decode(answer['readback_text_b64']).decode()==expected

nodes=dump('DRAFT');assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected
tap(node(nodes,'org.trillionnium.owneropen:id/ui_tools'));nodes=dump('CONNECT-MENU');tap(node(nodes,'org.trillionnium.owneropen:id/ui_reconnect'));time.sleep(.5)
nodes=dump('CURRENT-CONNECTION');tap(node(nodes,'org.trillionnium.owneropen:id/ui_task_summary'));nodes=dump('TASK-CONTROLS');tap(node(nodes,'org.trillionnium.owneropen:id/ui_inspect'));time.sleep(.5)
nodes=dump('READBACK');tap(node(nodes,'org.trillionnium.owneropen:id/ui_tools'));nodes=dump('DETAILS-MENU');tap(node(nodes,'org.trillionnium.owneropen:id/ui_details'));nodes=dump('RAW-DETAILS')
records=[]
for line in node(nodes,'org.trillionnium.owneropen:id/ui_log').attrib['text'].splitlines():
 try:records.append(json.loads(line))
 except (ValueError,TypeError):pass
save('PREVIOUS-ORIGINAL-READBACK.json',records)
hellos=[i for i,r in enumerate(records) if r.get('kind')=='broker.hello.ack']
inspections=[r['frame'] for r in records[(hellos[-1]+1 if hellos else 0):] if r.get('frame',{}).get('kind')=='turn.inspect.result' and all(r['frame'].get(k)==v for k,v in previous_identity.items())]
if inspections and hellos:
 hello=records[hellos[-1]];assert hello['host_hello_ack']['payload']['runtime_ready'] is True
 proof=inspections[-1]['payload'];assert proof['request_sha256']==previous_digest and proof['complete'] is True and proof['has_more'] is False
 assert proof['frames'][-1]['kind']=='turn.end' and proof['frames'][-1]['payload']['status']==previous_status
 qualified={'method':'same_connection_real_app_original_inspect','hello':hello,'previous_original_readback':inspections[-1]}
else:
 # Accessibility exposes only the first100000 characters of this diagnostic
 # TextView. Its prefix is not authority for selecting or completing a task.
 # The app still processes its full native response and owns its Send fence.
 # The app's view cache also drops a prefix at131072 characters, so even a
 # shorter exposed suffix can lack a complete JSON response. Observe the
 # committed selection and full native records instead of treating the view
 # cache as the execution record. The app's original Inspect/Send fence stays.
 diagnostic_chars=len(node(nodes,'org.trillionnium.owneropen:id/ui_log').attrib['text'])
 directory='/data/user/0/org.trillionnium.owneropen/files/'
 state_read=root('test ! -e '+directory+'owner-client-session-v1.pending && base64 '+directory+'owner-client-session-v1.bin && test ! -e '+directory+'owner-client-session-v1.pending');assert state_read['rc']==0
 raw=base64.b64decode(''.join(state_read['stdout'].split()),validate=True);selected=decode_client_state(raw)
 assert all(selected[k]==previous_identity[k] for k in ('session_id','task_id','turn_id')) and selected['turn_request_sha256']==previous_digest,'Selected app identity differs; no Send'
 journal=root('grep -h -F '+shlex.quote(previous_identity['turn_id'])+' /data/trillionnium/owner-open/state/turn-events.jsonl.segments/*.jsonl');assert journal['rc']==0
 original=[json.loads(line) for line in journal['stdout'].splitlines()];assert original and all(row['scope']==previous_identity for row in original)
 assert [row['turn_seq'] for row in original]==list(range(len(original)))
 assert all(row['payload']['request_sha256']==previous_digest for row in original)
 last=original[-1]['payload']['frame'];assert last['kind']=='turn.end' and last['payload']['status']==previous_status
 if previous_status!='completed' and not known_all_prior_tools_confirmed:assert not any(row['kind'].startswith('tool.') for row in original),'Failed task has effects without confirmed outcomes; no fresh test'
 qualified={'method':'real_app_inspect_then_read_only_selected_identity_and_original_journal','app_diagnostic_not_complete_record':True,'diagnostic_chars':diagnostic_chars,'selected_identity':selected,'original_records':original,'app_state_writes':False,'app_guard_bypassed':False}
qualified['prompt_sha256']=hashlib.sha256(expected.encode()).hexdigest();save('PRE-SEND-QUALIFIED.json',qualified)
for index in range(2):
 done=node(nodes,'android:id/button2');assert done.attrib['text'] in ('关闭','完成');tap(done);nodes=dump('CLOSE-DETAILS-'+str(index))
assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected
assert f.read('cat /proc/sys/kernel/random/boot_id',c,t)=='f8019f83-20a7-4f18-bea1-51c980621e4d'
send=node(nodes,'org.trillionnium.owneropen:id/ui_send');save('SEND.once.json',{'prompt':expected,'prompt_sha256':hashlib.sha256(expected.encode()).hexdigest(),'bounds':send.attrib['bounds'],'supplied_app_commands':False,'supplied_app_coordinates':False,'automatic_replay':False})
# Additional read-only freshness guard: identical old text cannot bind this timing.
pre=latency_read_original()
save('LATENCY-PRE-SEND.original-read.json',pre)
assert pre.get('observation',{}).get('state')=='no_matching_provider_start','New exact request already present or read unknown; no Send'
save('SEND.MONOTONIC-INTENT.json',{'p4_pre_send_monotonic_ns':time.monotonic_ns(),'send_attempt_count':1,'automatic_replay':False})
send_started_monotonic_ns=time.monotonic_ns()
send_status='unknown'
try:
 result=tap(send);send_status='tap_returned';save('SEND.result.json',result)
except Exception as error:
 save('SEND.unknown.json',{'error':str(error),'automatic_replay':False,'next':'Only read original request/scope'})
send_returned_monotonic_ns=time.monotonic_ns()
save('SEND.MONOTONIC-WINDOW.json',{'send_started_monotonic_ns':send_started_monotonic_ns,'send_returned_monotonic_ns':send_returned_monotonic_ns,'clock':'Pocket4 time.monotonic_ns','send_status':send_status,'automatic_replay':False})
timing=observe_original_terminal(send_started_monotonic_ns,send_returned_monotonic_ns,send_status)
print(json.dumps({'state':timing['state'],'native_status':timing.get('native_status'),'out':str(out),'route':t,'prompt_sha256':hashlib.sha256(expected.encode()).hexdigest(),'send_to_terminal_observed_seconds':timing.get('send_to_terminal_observed_seconds'),'latency_receipt':str(out/'SEND-NATIVE-LATENCY.json'),'automatic_replay':False}))
if timing['state']!='ORIGINAL_NATIVE_TERMINAL_OBSERVED': raise SystemExit(2)
'''
compile(source, label + '.actor.py', 'exec')
(BASE / (label + '.actor.py')).write_text(source)
intent = {'task': args.label, 'prompt': prompt, 'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
          'previous_identity': identity, 'previous_digest': digest,
          'supplied_app_commands': False, 'supplied_app_coordinates': False, 'automatic_replay': False}
with (BASE / (label + '.local-once.json')).open('x') as stream:
    json.dump(intent, stream, ensure_ascii=False, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
ssh = ['ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22','-o','BatchMode=yes',
       '-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast','python3','-I','-']
try:
    result = subprocess.run(ssh, input=source.encode(), capture_output=True, timeout=600)
    receipt = {'rc': result.returncode, 'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')}
except Exception as error:
    receipt = {'UNKNOWN': str(error), 'automatic_replay': False}
(BASE / (label + '.send-result.json')).write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n')
print(json.dumps(receipt, ensure_ascii=False, indent=2))
