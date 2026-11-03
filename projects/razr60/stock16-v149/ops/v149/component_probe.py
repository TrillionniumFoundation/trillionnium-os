"""Fresh operator component checks; not model decisions or native task receipts.

Uses the frozen mapper and existing phone transport. Each label reserves one
command once. Any timeout or uncertain result remains consumed without retry.
"""
from pathlib import Path
import argparse, base64, datetime, hashlib, json, os, subprocess, sys, time

BASE = Path(__file__).resolve().parent
CANDIDATE = BASE.parent/'stock16-hepta-task-provider-C-v149-r1'
sha = lambda raw:hashlib.sha256(raw).hexdigest()

def save(path, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

parser = argparse.ArgumentParser()
parser.add_argument('label')
parser.add_argument('decision', type=Path)
parser.add_argument('--latest', type=Path)
parser.add_argument('--expected-exit', type=int, default=0)
args = parser.parse_args()
assert args.label and all(ch.isalnum() or ch in '-_' for ch in args.label)
plan = json.loads((CANDIDATE/'INSTALL-PLAN.json').read_bytes())
for relative, pin in plan['source_pins'].items():
    assert sha((CANDIDATE/relative).read_bytes()) == pin['sha256']
sys.path.insert(0,str(CANDIDATE/'source'))
from phone_observation_tools import PhoneTools, strict_json, validate_viewport, jpeg_size, SERIAL, SCREEN_FIELDS, PHYSICAL_DISPLAY
from phone_task_guards import verify_return, verify_public_text, decode_text, page_state

run = BASE/('component-'+args.label)
run.mkdir(mode=0o700,exist_ok=False)
decision = json.loads(args.decision.read_bytes())
assert decision['call_id'] == args.label
mapper = PhoneTools(run, save)
mapper.bind({'session_id':'operator-v149-component-check','profile_id':'operator-component',
             'task_id':args.label,'turn_id':args.label})
if args.latest:
    latest = json.loads(args.latest.read_bytes())
    assert latest['qualification'] == 'actual_phone_component_screenshot_not_native_task'
    assert 0 <= time.time()-latest['received_unix'] <= 120
    mapper.latest = {**latest,'received_monotonic':time.monotonic()-(time.time()-latest['received_unix']),
                     'attached_round':0}
argv = mapper.map(decision)
assert argv[:3] == ['-s', SERIAL, 'shell'] and len(argv)==4
started = time.monotonic()
save(run/'COMMAND-INTENT.json',{'kind':'operator_component_check','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
     'semantic_tool':decision['tool'],'command_sha256':sha(argv[-1].encode()),'native_task_or_model_call':False,
     'automatic_replay':False,'expected_exit':args.expected_exit})
cmd = [sys.executable,'-B',str(BASE/'stock_phone.py'),'component-'+args.label,argv[-1],'--timeout','45']
if decision['tool'] in {'phone.tap','phone.return_hepta','phone.input_text'}:cmd.append('--effect')
outer = subprocess.run(cmd,capture_output=True,timeout=70)
save(run/'TRANSPORT-PROCESS.json',{'rc':outer.returncode,'stdout_sha256':sha(outer.stdout),
                                 'stderr':outer.stderr.decode(errors='replace'),'elapsed_seconds':time.monotonic()-started})
original = json.loads((BASE/('component-'+args.label+'.result.json')).read_bytes())
assert original.get('ssh_rc') == 0 and not original.get('stderr'), 'Transport unknown/failed; no retry'
receipt = json.loads(original['stdout'])
assert receipt['rc'] == args.expected_exit, {'unexpected_rc':receipt['rc'],'stderr':receipt.get('stderr'),'stdout':receipt.get('stdout','')[:1000]}
assert not receipt.get('stderr'), 'Unexpected phone stderr retained; no retry'
result = {'schema':'hepta.operator-component-check.v149.1','label':args.label,'kind':'operator_component_check',
          'semantic_tool':decision['tool'],'actual_exit_code':receipt['rc'], 'model_requests':0,
          'native_task_result':False,'full_model_task_qualification':False,
          'raw_receipt_sha256':sha(original['stdout'].encode()),'elapsed_seconds':time.monotonic()-started}
call = mapper.calls[args.label]
if receipt['rc']:
    result.update(status='EXPECTED_GUARD_REJECTION',guard_exit_matches_pre_input_branch=True,independent_input_audit=False)
elif decision['tool']=='phone.return_hepta':
    observed, viewport = verify_return(strict_json(receipt['stdout']),call['capture_id']);validate_viewport(viewport)
    result.update(status='ACTUAL_RETURN_COMPONENT_VERIFIED',observed=observed)
elif decision['tool']=='phone.read_text':
    observed, viewport = verify_public_text(strict_json(receipt['stdout']),call['capture_id'],call['package'],call['view_ids']);validate_viewport(viewport)
    result.update(status='ACTUAL_PUBLIC_TEXT_COMPONENT_VERIFIED',observed=observed)
elif decision['tool']=='phone.screenshot':
    envelope = strict_json(receipt['stdout'])
    assert set(envelope)=={'schema','capture_id','page_before_b64','page_after_b64','screenshot'}
    assert envelope['schema']=='hepta.capture-page-envelope.v149.1' and envelope['capture_id']==call['capture_id']
    before=decode_text(envelope['page_before_b64'],'page before'); after=decode_text(envelope['page_after_b64'],'page after')
    assert before==after; observed=page_state(before)
    value=envelope['screenshot'];assert set(value)==SCREEN_FIELDS
    assert value['capture_id']==call['capture_id'] and value['serial']==SERIAL and value['rotation']==0 and value['logical_display_id']==0
    assert value['physical_display_id'] in {PHYSICAL_DISPLAY,'local:'+PHYSICAL_DISPLAY}
    assert value['status']=='encoded' and value['media_type']=='image/jpeg' and value['encoding']=='base64'
    assert (value['original_width'],value['original_height'])==(1224,2992)
    assert value['viewport_before']==value['viewport_after'];validate_viewport(value['viewport_before'])
    image=base64.b64decode(value['data_base64'],validate=True)
    assert sha(image)==value['image_sha256'] and len(image)==value['encoded_bytes'] and len(image)<=call['max_image_bytes']
    size=jpeg_size(image);assert size==(value['encoded_width'],value['encoded_height'])
    (run/'actual-screenshot.jpg').write_bytes(image)
    latest={'qualification':'actual_phone_component_screenshot_not_native_task','call_id':args.label,'received_unix':time.time(),
            'encoded_size':list(size),'viewport':value['viewport_before'],'page_state':before,'page_state_sha256':sha(before.encode()),
            'source_png_sha256':value['source_png_sha256'],'image_sha256':value['image_sha256'],'observed_page':observed}
    save(run/'LATEST.json',latest)
    result.update(status='ACTUAL_SCREENSHOT_COMPONENT_VERIFIED',observed=observed,encoded_size=list(size),image_sha256=sha(image))
elif decision['tool']=='phone.input_text':
    value=strict_json(receipt['stdout']);raw=base64.b64decode(value['readback_text_b64'],validate=True)
    assert value.get('schema')=='hepta.focused-unicode-input.v1'
    assert value['status'] in {'set_verified','already_exact'} and raw==decision['command'].encode()
    assert value.get('operation_id')==args.label and value.get('display_id')==0
    assert value.get('package')==call['package'] and value.get('view_id')==call['view_id']
    assert value.get('requested_utf8_sha256')==sha(raw) and value.get('after_utf8_sha256')==sha(raw)
    assert value.get('before_utf8_sha256')==sha(call['expected_text'].encode())
    assert base64.b64encode(raw).decode()==value['readback_text_b64']
    assert value['own_automation_disconnected'] is True
    if value['status']=='set_verified':
        assert value.get('action_attempted') is True and value.get('effect_state')=='observed_exact_requested_text'
    else:
        assert value.get('action_attempted') is False and value.get('effect_state')=='not_started'
    result.update(status='ACTUAL_UNICODE_COMPONENT_EXACT_READBACK',input_status=value['status'],utf8_sha256=sha(raw),utf8_bytes=len(raw))
else:
    result.update(status='MAPPED_PHONE_COMMAND_EXITED')
save(run/'RESULT.json',result)
print(json.dumps(result,ensure_ascii=False))
