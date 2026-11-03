#!/usr/bin/env python3
"""No-replay and real shell.exec mapping fixtures; never execute phone effects."""
from pathlib import Path
import base64, datetime, hashlib, json, secrets, sys, traceback
from types import SimpleNamespace
from unittest.mock import patch
BASE=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE/'source'))
from action_ledger import ActionLedger
from provider_phone_local import PhoneLocalAdapter
from phone_local_tools import PhoneLocalTools, validate_executor
from provider_openai_compatible import ProviderError,tool_call
RUN=BASE/'validation'/('action-fences-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(8))
RUN.mkdir(mode=0o700)
report={'schema':'hepta.local-action-fences.v150.1','layer':'host_isolated_fixture','checks':{},
        'real_model_requests':0,'physical_phone_actions':0}
def check(name,value=True):
    assert value,name
    report['checks'][name]=True
def rejects(name,fn):
    try:fn()
    except Exception:check(name);return
    raise AssertionError(name)
def identity():
    nonce=secrets.token_hex(16)
    return {'session_id':'s'+nonce,'profile_id':'fixture','task_id':'t'+nonce,'turn_id':'u'+nonce}
def record(kind='phone.input_text',text='新fixture'):
    token=secrets.token_hex(16)
    return {'semantic_tool':kind,'capture_id':token,'call_id':'call_'+token,
            'package':'fixture.app','view_id':'fixture.app:id/editor','expected_text':'',
            'requested_utf8_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'wire_call':{'call_id':'call_'+token,'tool':'adb.exec','argv':['-s','fixture','shell','fixture-command']},
            'component':'fixture.app/.Activity','source_png_sha256':'b'*64,
            'page_state_sha256':'c'*64,'original_xy':[100,100]}
def inspected(rec,**updates):
    receipt={'action_id':rec['capture_id'],'command_sha256':hashlib.sha256(b'fixture-command').hexdigest(),
             'terminal':True,'state':'completed','exit_code':0,'effect_started':True,'process_group_established':True,'waitpid_joined':True,'process_group_absent':True}
    receipt.update(updates)
    return {'version':1,'protocol':'hepta_phone_local_v150','receipt':receipt}
try:
    evidence=RUN/'evidence';evidence.mkdir(mode=0o700)
    run=evidence/'one';run.mkdir(mode=0o700)
    ledger=ActionLedger(evidence,run);original=record();ident=identity()
    ledger.reserve(original,ident)
    old_intent=(ledger.directory/(original['capture_id']+'.intent.json')).read_bytes()
    rejects('unknown original effect blocks a different new call ID',lambda:ledger.reserve(record(text='完全新的不同输入'),ident))
    rejects('unknown original effect also blocks a new semantic task',lambda:ledger.reserve(record(text='另一个新输入'),identity()))
    rejects('wrong command SHA cannot release recovery gate',lambda:ledger.resolve_inspected(original['capture_id'],inspected(original,command_sha256='d'*64)))
    rejects('unstarted effect cannot release inspected gate',lambda:ledger.resolve_inspected(original['capture_id'],inspected(original,effect_started=False)))
    rejects('unestablished process group cannot release gate',lambda:ledger.resolve_inspected(original['capture_id'],inspected(original,process_group_established=False)))
    rejects('unjoined effect cannot release recovery gate',lambda:ledger.resolve_inspected(original['capture_id'],inspected(original,waitpid_joined=False)))
    rejects('nonterminal result cannot release recovery gate',lambda:ledger.resolve_inspected(original['capture_id'],inspected(original,terminal=False,state='running')))
    check('failed inspections do not create resolution',not (ledger.directory/(original['capture_id']+'.resolution.json')).exists())
    ledger.resolve_inspected(original['capture_id'],inspected(original))
    resolution=json.loads((ledger.directory/(original['capture_id']+'.resolution.json')).read_text())
    check('original sidecar inspection retained', (ledger.directory/(original['capture_id']+'.inspection.json')).exists())
    check('inspection never grants business success',resolution['business_verified'] is False and resolution['automatic_replay'] is False)
    check('original task terminal unchanged marker',resolution['original_task_terminal_unchanged'] is True)
    rejects('same input cannot replay under fresh call ID',lambda:ledger.reserve(record(),ident))
    rejects('same bound input cannot replay under fresh task',lambda:ledger.reserve(record(),identity()))
    check('original intent bytes immutable',(ledger.directory/(original['capture_id']+'.intent.json')).read_bytes()==old_intent)
    different=record(text='新的nonce文本 '+secrets.token_hex(16));ledger.reserve(different,identity())
    check('new distinct work admitted only after inspection', (ledger.directory/(different['capture_id']+'.intent.json')).exists())

    half=RUN/'half-written';half.mkdir(mode=0o700)
    half_run=half/'run';half_run.mkdir(mode=0o700)
    half_ledger=ActionLedger(half,half_run);half_record=record(text='half-write '+secrets.token_hex(16))
    half_ledger.reserve(half_record,identity())
    from task_postconditions import write_exclusive
    retained_path=half_ledger.directory/(half_record['capture_id']+'.inspection.json')
    write_exclusive(retained_path,inspected(half_record))
    retained_bytes=retained_path.read_bytes()
    half_ledger.resolve_inspected(half_record['capture_id'],inspected(half_record))
    check('interrupted inspection-to-resolution phase recovers', (half_ledger.directory/(half_record['capture_id']+'.resolution.json')).exists())
    check('recovery reuses original inspection bytes',retained_path.read_bytes()==retained_bytes)

    race=RUN/'ledger-race';race.mkdir(mode=0o700)
    race_run=race/'run';race_run.mkdir(mode=0o700)
    import os,threading
    entrants=[ActionLedger(race,race_run),ActionLedger(race,race_run)]
    barrier=threading.Barrier(2);results=[]
    before_fds=len(os.listdir('/dev/fd'))
    def compete(index):
        barrier.wait()
        try:entrants[index].reserve(record(text='race '+secrets.token_hex(16)),identity());results.append('reserved')
        except ProviderError:results.append('blocked')
    threads=[threading.Thread(target=compete,args=(i,)) for i in range(2)]
    for thread in threads:thread.start()
    for thread in threads:thread.join(3)
    check('ledger cross-instance lock threads join',all(not thread.is_alive() for thread in threads))
    check('only one concurrent mutation reserves',sorted(results)==['blocked','reserved'])
    check('ledger lock FD baseline restored',len(os.listdir('/dev/fd'))==before_fds)

    fake=object.__new__(PhoneLocalAdapter)
    fake.round=3;fake.model_task_status='unknown'
    fake.phone_tools=SimpleNamespace(visual_read_constraints=[{'kind':'visual_receipt_matches_challenge'}],
                                     calls={'old':{'semantic_tool':'phone.tap'}},latest=None)
    fake.task_contract=None
    decision={'kind':'tool.call','call_id':'newcall','tool':'phone.tap','command':'',
              'argv':['new-image','500','500'],'summary':'second selection','task_status':'in_progress'}
    rejects('visual contract rejects second tap before any mapper/effect',lambda:fake._decision(decision,'newcall'))
    fake.phone_tools=SimpleNamespace(visual_read_constraints=[],calls={
        'old':{'semantic_tool':'phone.input_text','package':'fixture.app','view_id':'fixture.app:id/editor'}})
    fake.task_contract={'contract':{'postconditions':[{'kind':'text_readback_exact','package':'fixture.app','view_id':'fixture.app:id/editor'}]}}
    decision.update(tool='phone.input_text',command='new',argv=['fixture.app','fixture.app:id/editor',''])
    rejects('Unicode contract rejects a second editor input before mapping',lambda:fake._decision(decision,'newcall'))
    fake.round=8
    rejects('last round cannot dispatch one more effect',lambda:fake._decision(decision,'newcall'))

    maps=RUN/'mapper';maps.mkdir(mode=0o700)
    config={'mode':'phone_local_sidecar','python':'/usr/bin/python3',
            'client_path':'/var/lib/trillionnium/owner-open/phone-local-v150/tool_client.py',
            'client_sha256':'b298ac86fdf57dd0c7dc5159febf114ed176398d32ea672c9abda4a6eb621539','timeout_ms':60000}
    validate_executor(config,verify_files=False)
    real_validator=validate_executor
    with patch('phone_local_tools.validate_executor',side_effect=lambda cfg,**kw:real_validator(cfg,verify_files=False)):
        mapper=PhoneLocalTools(maps,lambda p,v:p.write_text(json.dumps(v)),
                              {'probe':{'component':'org.trillionnium.hepta.controlprobe/.VisualChallengeActivity','label':'fixture'}},config)
        mapper.bind({**identity(),'turn_stream_id':'stream-'+secrets.token_hex(16)})
        argv=mapper.map({'call_id':'localreturn','tool':'phone.return_hepta','command':'','argv':[]})
    record_map=mapper.calls['localreturn']
    check('phone-local mapper emits real shell.exec',record_map['wire_call']['tool']=='shell.exec' and record_map['wire_tool']=='shell.exec')
    check('exact reviewed client argv',argv[:3]==['/usr/bin/python3',config['client_path'],'execute'])
    check('client action ID equals semantic capture identity',argv[4]==record_map['capture_id'])
    command=base64.b64decode(argv[6]).decode()
    check('generated guarded Android shell has no su wrapper','su -c' not in command and 'getprop ro.serialno' in command)
    check('client timeout bounded',argv[-2:]==['--timeout-ms','60000'])
    wire=tool_call({'type':'function','id':'localreturn','function':{'name':'shell_exec','arguments':json.dumps({'argv':argv})}},set())
    check('native protocol wire equals reviewed mapping',wire==record_map['wire_call'])
    from provider_codex_host import CodexAdapter
    import threading
    for phase in [1,2]:
        cancel_root=RUN/('cancel-fence-'+str(phase));cancel_root.mkdir(mode=0o700)
        cancel_run=cancel_root/'run';cancel_run.mkdir(mode=0o700)
        cancel_record=record(text='fence-'+str(phase)+'-'+secrets.token_hex(16))
        fake_cancel=object.__new__(PhoneLocalAdapter)
        fake_cancel.cancelled=threading.Event()
        fake_cancel.accepted_identity=identity()
        fake_cancel.action_ledger=ActionLedger(cancel_root,cancel_run)
        fake_cancel.phone_tools=SimpleNamespace(calls={cancel_record['call_id']:cancel_record})
        polls=[0];writes=[]
        def receive(expected=None,timeout=0):
            polls[0]+=1
            if polls[0]==phase:fake_cancel.cancelled.set()
        fake_cancel.receive=receive
        with patch.object(CodexAdapter,'emit',side_effect=lambda kind,**kw:writes.append(kind)):
            fake_cancel.emit('tool.call',call=cancel_record['wire_call'])
        check('queued cancel at fence%d writes no tool frame'%phase,writes==[])
        rows=fake_cancel.action_ledger.intents()
        if phase==1:
            check('cancel before reservation leaves no fake unknown intent',rows==[])
        else:
            check('cancel after reservation records known not-dispatched',len(rows)==1 and rows[0][2]['state']=='known_not_dispatched')
            check('predispatch cancel never claims business success',rows[0][2]['business_verified'] is False)

    from provider_phone_local import compact_transcript
    projected=compact_transcript([{'role':'assistant','content':'fixture return','tool_calls':[{'id':'localreturn','function':{'arguments':json.dumps({'argv':argv})}}]}],mapper)
    serialized=json.dumps(projected)
    check('model history omits executable shell/base64','--command-b64' not in serialized and 'getprop ro.serialno' not in serialized)
    check('model history retains semantic attempted action',projected[0]['actions'][0]['tool']=='phone.return_hepta' and projected[0]['actions'][0]['attempted_once_do_not_replay'])
    report['status']='PASS'
except Exception as e:
    report.update(status='FAIL',error_type=type(e).__name__,error=str(e),traceback=traceback.format_exc())
raw=json.dumps(report,ensure_ascii=False,indent=2).encode();(RUN/'RESULT.json').write_bytes(raw)
print(json.dumps({'status':report['status'],'checks':len(report['checks']),'result':str(RUN/'RESULT.json'),'sha256':hashlib.sha256(raw).hexdigest()}))
sys.exit(0 if report['status']=='PASS' else 1)
