"""Deterministic failure/postcondition tests with no phone or model calls.

Local disposable CLI and Android command fixtures exercise actual stream,
shell mapping, cleanup and wire paths. They never invoke adb or real Codex.
"""
import base64
import concurrent.futures
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE/'source'))
from fixtures import PAGE, WINDOW, ACTIVITY, VIEWPORT, BINDING, PACKAGE, b64, native_result
from model_health import ModelFailure, ModelHealth, cli_failure
from phone_task_guards import page_state, verify_return, verify_public_text, HEPTA_FULL_COMPONENT
from phone_observation_tools import PhoneTools, ProviderError, SERIAL, sha
from provider_codex_host import CodexAdapter, advance_cli_error_diagnostic, model_transcript, selected_tool_disable_notice
from provider_openai_compatible import PROTOCOL
from daily_provider import DailyAdapter, replace_json, file_identity
from task_postconditions import (load_contract, evaluate, terminal_fields, identity_key, request_hash,
                                 validate_conditions, write_exclusive)

CHECKS = {}


def check(name, condition=True):
    assert condition, name
    CHECKS[name] = True


def rejected(name, function, errors=(ProviderError, OSError, ValueError, TypeError)):
    try:
        function()
    except errors:
        check(name)
        return
    raise AssertionError(name + ' accepted an invalid fixture')


def tools_at(root, name):
    directory = root/name
    directory.mkdir(mode=0o700)
    def record(path, value):
        with path.open('x') as stream:
            json.dump(value, stream, ensure_ascii=False)
    tools = PhoneTools(directory, record)
    tools.bind(BINDING)
    return tools


def returned(token, *, launch=None, page=PAGE, viewport=VIEWPORT):
    return {'schema': 'hepta.return-receipt.v149.1', 'operation_id': token, 'launch_exit_code': 0,
            'launch_b64': b64(launch or 'Starting: Intent fixture\nStatus: ok\nActivity: org.trillionnium.owneropen/.OwnerOpenShellActivity\nComplete\n'),
            'page_b64': b64(page), 'viewport_b64': b64(viewport)}


def xml_for(values, package=PACKAGE):
    root = ET.Element('hierarchy', rotation='0')
    for index, (view_id, text) in enumerate(values):
        ET.SubElement(root, 'node', {'resource-id': view_id, 'package': package,
            'class': 'android.widget.TextView', 'password': 'false', 'enabled': 'true',
            'bounds': f'[10,{100+index*60}][1100,{150+index*60}]', 'text': text})
    return ET.tostring(root, encoding='unicode')


def public_receipt(token, values, package=PACKAGE):
    return {'schema': 'hepta.public-text-receipt.v149.1', 'operation_id': token, 'package': package,
            'page_before_b64': b64(PAGE), 'page_after_b64': b64(PAGE),
            'viewport_before_b64': b64(VIEWPORT), 'viewport_after_b64': b64(VIEWPORT),
            'xml_b64': b64(xml_for(values, package))}


def test_errors(root):
    actual_message = 'You’ve hit your usage limit. Visit https://chatgpt.com/settings/usage to purchase more credits or try again at Nov 9th, 2026 9:53 AM.'
    actual = {'type': 'turn.failed', 'error': {'message': actual_message}}
    failure = cli_failure(actual)
    check('fresh_observed_quota_message_classifies_usage_limit', failure.category == 'usage_limit_exceeded')
    check('quota_phone_error_explicit_and_no_raw_credentials', '模型额度已用尽' in str(failure) and 'http' not in str(failure))
    for code, expected in [('invalid_api_key', 'authentication_failed'), ('rate_limit_exceeded', 'rate_limit_exceeded'),
                           ('invalid_request_error', 'request_rejected'), ('connection_error', 'transport_unavailable'),
                           ('deadline_exceeded', 'model_timeout'), ('unqualified-code', 'unknown_model_failure')]:
        check('structured_failure_' + code, cli_failure({'type': 'turn.failed', 'error': {'code': code}}).category == expected)
    for kind in ['tool.result', 'item.completed', 'turn.completed']:
        rejected('untrusted_or_success_' + kind + '_not_model_failure',
                 lambda kind=kind: cli_failure({'type': kind, 'message': actual_message}))
    notice = {'type': 'error', 'message': 'Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`.'}
    check('known_disabled_code_mode_item_notice_remains_allowed', selected_tool_disable_notice(notice))
    check('nearby_code_mode_notice_not_whitelisted', not selected_tool_disable_notice({**notice, 'message': notice['message']+'x'}))
    attempt = 0
    for number in range(1, 6):
        attempt = advance_cli_error_diagnostic({'type':'error','message':f'Reconnecting... {number}/5 (request timed out)'}, attempt)
    check('existing_same_process_reconnect_monotonic_1_to_5', attempt == 5)
    rejected('reconnect_repeated_attempt_fails', lambda: advance_cli_error_diagnostic({'type':'error','message':'Reconnecting... 5/5 (request timed out)'}, 5))
    rejected('quota_diagnostic_not_swallowed', lambda: advance_cli_error_diagnostic(actual, 0), (ModelFailure,))
    health = ModelHealth(root/'model-health.json', 'gpt-6.1-sol', replace_json)
    first, already_inflight = health.begin(), health.begin()
    health.failure(first, failure)
    health.success(already_inflight)
    check('inflight_success_cannot_clear_later_observed_quota', health.value['availability'] == 'observed_unavailable' and health.value['reason'] == 'usage_limit_exceeded')
    health.failure(already_inflight, ModelFailure('transport_unavailable'))
    check('older_transport_failure_does_not_hide_quota', health.value['reason'] == 'usage_limit_exceeded')
    recovered = health.begin(); health.success(recovered)
    check('later_started_actual_success_can_clear_failure', health.value['availability'] == 'observed_available')
    restored = ModelHealth(root/'model-health.json', 'gpt-6.1-sol', replace_json)
    check('observed_health_survives_restart', restored.value == health.value)
    rejected('phone_error_cannot_change_model_health', lambda: health.failure(recovered, ProviderError('phone failure')))
    check('health_file_private', (root/'model-health.json').stat().st_mode & 0o777 == 0o600)


def test_page_return_and_reads(root):
    check('two_display_external_null_does_not_mask_internal_focus', page_state(PAGE)['component'] == HEPTA_FULL_COMPONENT)
    mutations = {
        'top_display': PAGE.replace('mTopFocusedDisplayId=0', 'mTopFocusedDisplayId=1'),
        'internal_null': PAGE.replace('mCurrentFocus=Window{3b4490 u0 '+HEPTA_FULL_COMPONENT+'}', 'mCurrentFocus=null'),
        'keyguard': PAGE.replace('isKeyguardShowing=false', 'isKeyguardShowing=true'),
        'focused_app_changed': PAGE.replace('mFocusedApp=ActivityRecord{171231292 u0 org.trillionnium.owneropen/.OwnerOpenShellActivity t205}', 'mFocusedApp=ActivityRecord{171231292 u0 com.example.other/.Elsewhere t205}'),
        'duplicate_top': PAGE+'\nmTopFocusedDisplayId=0',
        'missing_display_sections': '\n'.join(line for line in PAGE.splitlines() if 'Display: mDisplayId=' not in line),
    }
    for name, value in mutations.items():
        rejected('page_' + name + '_rejected', lambda value=value: page_state(value))
    tool = tools_at(root, 'return')
    argv = tool.map({'call_id':'return01','tool':'phone.return_hepta','command':'','argv':[]})
    token = tool.calls['return01']['capture_id']
    check('return_uses_only_verified_component_and_captures_am_status', 'org.trillionnium.owneropen/.OwnerOpenShellActivity' in argv[-1] and 'hepta_launch_rc=$?' in argv[-1] and argv[-1].endswith('exit "$hepta_launch_rc"'))
    reply = returned(token)
    message = native_result('return01', reply)
    rendered, paths = tool.prepare([message], model_transcript([message]), 1)
    check('return_requires_real_native_receipt_and_focus', tool.verified_facts['return01']['kind'] == 'foreground_hepta' and not paths)
    check('return_only_explicit_mapping_no_automatic_action', len(tool.calls) == 1)
    for name, value in {
        'wrong_token': {**reply, 'operation_id': 'foreign'},
        'failed_launch_rc': {**reply, 'launch_exit_code': 1},
        'zero_rc_error_text': returned(token, launch='Error type 3\nError: Activity class does not exist.'),
        'wrong_actual_focus': returned(token, page=PAGE.replace('org.trillionnium.owneropen', 'com.example.other')),
        'missing_status': returned(token, launch='Activity: org.trillionnium.owneropen/.OwnerOpenShellActivity\nComplete'),
    }.items():
        rejected('return_' + name + '_not_success', lambda value=value: verify_return(value, token))
    bad_native = native_result('return01', reply, exit_code=1)
    rejected('native_failed_return_even_valid_payload_rejected', lambda: tool.prepare([bad_native],model_transcript([bad_native]),2))
    reader = tools_at(root, 'reader')
    view = PACKAGE+':id/unicode_readback'
    text = '中文🙂\nexact second line'
    read_argv = reader.map({'call_id':'read01','tool':'phone.read_text','command':'','argv':[PACKAGE,view]})
    read_token = reader.calls['read01']['capture_id']
    payload = public_receipt(read_token, [(view,text)])
    read_message = native_result('read01',payload)
    original = copy.deepcopy(read_message)
    projected,_ = reader.prepare([read_message],model_transcript([read_message]),1)
    fact = reader.verified_facts['read01']
    check('public_UI_unicode_newline_exact_readback', fact['values'][0]['text'] == text and fact['values'][0]['utf8_sha256'] == sha(text.encode()))
    check('public_read_preserves_original_wire', read_message == original)
    check('public_read_bounded_unique_owned_XML_and_no_app_private_data', 'uiautomator dump' in read_argv[-1] and '/data/data/' not in read_argv[-1] and '-le 196608' in read_argv[-1])
    for name, value in {
        'duplicate_view': {**payload,'xml_b64':b64(xml_for([(view,text),(view,text)]))},
        'password': {**payload,'xml_b64':b64(xml_for([(view,text)]).replace('password="false"','password="true"'))},
        'wrong_package': {**payload,'xml_b64':b64(xml_for([(view,text)],'com.example.other'))},
        'outside_bounds': {**payload,'xml_b64':b64(xml_for([(view,text)]).replace('[10,100][1100,150]','[10,100][1225,150]'))},
        'missing_view': {**payload,'xml_b64':b64(xml_for([(PACKAGE+':id/other',text)]))},
        'changed_focus': {**payload,'page_after_b64':b64(PAGE.replace('t205','t206'))},
        'changed_display': {**payload,'viewport_after_b64':b64(VIEWPORT.replace('orientation=0','orientation=1'))},
        'xml_entity': {**payload,'xml_b64':b64('<!DOCTYPE hierarchy [<!ENTITY x "unsafe">]>'+xml_for([(view,text)]))},
    }.items():
        rejected('public_read_' + name + '_rejected', lambda value=value: verify_public_text(value, read_token, PACKAGE, [view]))
    return fact


def test_contracts_and_terminals(root, public_fact):
    directory=root/'contracts';directory.mkdir(mode=0o700)
    for name in ['templates','bindings']:(directory/name).mkdir(mode=0o700)
    request='输入、确认、公开读回并返回HEPTA nonce_v149_test_0000001'
    condition={'id':'public_receipt','kind':'public_text_exact','package':PACKAGE,
               'view_id':public_fact['values'][0]['view_id'],'utf8_sha256':public_fact['values'][0]['utf8_sha256']}
    conditions=[condition,{'id':'return','kind':'foreground_hepta'}]
    template={'schema':'hepta.task-template.v149.1','expected_scope':{key:BINDING[key] for key in ('session_id','profile_id')},
              'request_sha256':request_hash(request),'nonce':'nonce_v149_test_0000001','postconditions':conditions,'coverage':'entire_request'}
    template_path=directory/'templates'/(request_hash(request)+'.json');write_exclusive(template_path,template)
    check('unregistered_prompt_does_not_gain_contract',load_contract(directory,BINDING,'different') is None)
    rejected('wrong_known_session_cannot_consume_template',lambda:load_contract(directory,{**BINDING,'session_id':'foreign'},request))
    check('scope_rejection_does_not_consume_template',not (directory/'bindings'/template_path.name).exists())
    contract=load_contract(directory,BINDING,request)
    check('UI_generated_task_turn_bound_at_admission',contract['contract']['identity']=={key:BINDING[key] for key in ('session_id','profile_id','task_id','turn_id')})
    rejected('one_time_nonce_cannot_rebind_new_turn',lambda:load_contract(directory,{**BINDING,'turn_id':'new-turn'},request))
    check('template_retained_with_durable_consumption_binding',template_path.exists() and (directory/'bindings'/template_path.name).exists())
    returned_fact={'kind':'foreground_hepta','call_id':'return01','original_result_sha256':'a'*64}
    facts=[public_fact,returned_fact]
    full=evaluate(contract,facts,'return01','completed','turn.complete')
    check('full_explicit_public_receipt_and_return_contract_verifies',full['business_verified'])
    check('fully_verified_contract_keeps_existing_complete_wire',terminal_fields('turn.complete',{'summary':'done'},full,True)[0]=='turn.complete')
    missing=evaluate(contract,[public_fact],'read01','completed','turn.complete')
    kind,fields=terminal_fields('turn.complete',{'summary':'done'},missing,True)
    check('missing_return_is_turn_fail_not_completed',kind=='turn.fail' and set(fields)=={'error'} and 'return' in fields['error'])
    stale=evaluate(contract,facts,'generic-later','completed','turn.complete')
    check('later_tool_invalidates_old_foreground_postcondition',not stale['business_verified'])
    helper_only={'kind':'text_readback_exact','call_id':'input','package':PACKAGE,'view_id':condition['view_id'],'utf8_sha256':condition['utf8_sha256']}
    check('input_helper_does_not_prove_public_app_receipt',not evaluate(contract,[helper_only,returned_fact],'return01','completed','turn.complete')['business_verified'])
    for status in ['partial','failed','unknown']:
        result=evaluate(contract,facts,'return01',status,'turn.complete')
        check('model_' + status + '_cannot_be_business_success',not result['business_verified'] and terminal_fields('turn.complete',{'summary':'x'},result,True)[0]=='turn.fail')
    partial_scope=copy.deepcopy(contract);partial_scope['contract']['coverage']='declared_postconditions_only'
    scoped=evaluate(partial_scope,facts,'return01','completed','turn.complete')
    check('passing_limited_conditions_does_not_claim_entire_task',scoped['postconditions_verified'] and not scoped['business_verified'] and terminal_fields('turn.complete',{'summary':'x'},scoped,True)[0]=='turn.fail')
    uncontracted=evaluate(None,facts,'return01','completed','turn.complete')
    kind,fields=terminal_fields('turn.complete',{'summary':'model claims done'},uncontracted,True)
    check('no_contract_has_explicit_unverified_summary',not uncontracted['business_verified'] and '业务未独立验证' in fields['summary'])
    visual={'id':'visual_receipt','kind':'visual_receipt_matches_challenge','package':PACKAGE,
            'challenge_view_id':PACKAGE+':id/visual_challenge_code','receipt_view_id':PACKAGE+':id/visual_receipt',
            'receipt_prefix':'HEPTA_VISUAL_OK ', 'challenge_prefix':'挑战码：'}
    vc=copy.deepcopy(contract);vc['contract']['postconditions']=[visual,{'id':'return','kind':'foreground_hepta'}]
    def vf(code, receipt):
        return {'kind':'public_text_observation','call_id':'read_visual','package':PACKAGE,'xml_sha256':'b'*64,
                'values':[{'view_id':visual['challenge_view_id'],'text':code,'utf8_sha256':sha(code.encode())},
                          {'view_id':visual['receipt_view_id'],'text':receipt,'utf8_sha256':sha(receipt.encode())}]}
    tap={'kind':'visual_tap_executed','call_id':'tap','package':PACKAGE,'source_image_call_id':'shot','source_image_sha256':'a'*64}
    vp=vf('挑战码：ABCDEF12','HEPTA_VISUAL_OK ABCDEF12')
    check('visual_receipt_matches_same_public_snapshot_after_tap',evaluate(vc,[tap,vp,returned_fact],'return01','completed','turn.complete')['business_verified'])
    check('visual_return_only_is_not_business_success',not evaluate(vc,[returned_fact],'return01','completed','turn.complete')['business_verified'])
    check('visual_receipt_without_actual_screenshot_bound_tap_rejected',not evaluate(vc,[vp,returned_fact],'return01','completed','turn.complete')['business_verified'])
    check('visual_wrong_receipt_code_rejected',not evaluate(vc,[tap,vf('挑战码：ABCDEF12','HEPTA_VISUAL_OK 00000000'),returned_fact],'return01','completed','turn.complete')['business_verified'])
    check('newer_bad_visual_receipt_overrides_old_good',not evaluate(vc,[tap,vp,vf('挑战码：ABCDEF13','HEPTA_VISUAL_OK ABCDEF12'),returned_fact],'return01','completed','turn.complete')['business_verified'])
    for label, challenge in [('wrong_prefix','Code: ABCDEF12'),('multiple_codes','挑战码：ABCDEF12 ABCDEF13'),
                             ('lowercase','挑战码：abcdef12'),('extra_newline','挑战码：ABCDEF12\n')]:
        check('visual_' + label + '_rejected',not evaluate(vc,[tap,vf(challenge,'HEPTA_VISUAL_OK ABCDEF12'),returned_fact],'return01','completed','turn.complete')['business_verified'])
    constrained=tools_at(root,'constrained');constrained.visual_read_constraints=[visual]
    rejected('challenge_read_before_visual_tap_not_dispatched',lambda:constrained.map({'call_id':'peek','tool':'phone.read_text','command':'','argv':[PACKAGE,visual['challenge_view_id']]}))
    # Actual two-admission race on the one-time template, not a mocked lock.
    race_request='race request nonce_v149_race_0000001';race_template=copy.deepcopy(template)
    race_template.update(request_sha256=request_hash(race_request),nonce='nonce_v149_race_0000001')
    write_exclusive(directory/'templates'/(request_hash(race_request)+'.json'),race_template)
    barrier=threading.Barrier(2)
    def bind_race(index):
        barrier.wait()
        try:load_contract(directory,{**BINDING,'turn_id':'race-'+str(index)},race_request);return True
        except ProviderError:return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=list(pool.map(bind_race,[0,1]))
    check('concurrent_admission_exactly_one_template_binding',sum(outcomes)==1)
    # Existing native terminal schema receives fail, not extra business fields.
    run=root/'wire-partial';run.mkdir(mode=0o700);sink=io.StringIO()
    adapter=CodexAdapter(SimpleNamespace(),io.BytesIO(),sink,run)
    adapter.task_contract=contract;adapter.accepted_identity=BINDING;adapter.model_task_status='completed'
    adapter.phone_tools.verified_facts={'read01':public_fact};adapter.phone_tools.last_result_call_id='read01'
    adapter.emit('turn.complete',summary='model claimed success')
    wire=json.loads(sink.getvalue())
    check('actual_emit_converts_partial_to_legacy_fail_frame',wire['kind']=='turn.fail' and set(wire)=={'protocol','kind','seq','error'})
    check('actual_persisted_terminal_matches_wire_failure',json.loads((run/'terminal.json').read_text())['kind']=='turn.fail')
    check('business_sidecar_false_for_partial',json.loads((run/'business-outcome.json').read_text())['business_verified'] is False)
    adapter.frames.close();adapter.inputs.close()


def test_local_shell_guards(root):
    # These executable shims replace Android commands only in this local test.
    # The resulting production shell text is executed unchanged except that
    # its one owned temporary pathname is relocated into this temporary root.
    mock=root/'mock-bin';mock.mkdir()
    fixture='''#!{python}
import os,sys,pathlib,shutil
name=pathlib.Path(sys.argv[0]).name
base=pathlib.Path(os.environ['HEPTA_TEST_FIXTURES'])
if name=='getprop': print('{serial}')
elif name=='dumpsys':
    print((base/('window' if sys.argv[1]=='window' else 'activity' if sys.argv[1]=='activity' else 'viewport')).read_text(),end='')
elif name=='screencap': shutil.copyfile(base/'png',sys.argv[-1])
elif name=='input':
    with (base/'input-calls').open('a') as out:out.write(' '.join(sys.argv[1:])+'\\n')
elif name=='am':
    print((base/'launch').read_text(),end='');sys.exit(int((base/'launch-rc').read_text()))
elif name=='uiautomator': shutil.copyfile(base/'ui.xml',sys.argv[-1]);print('UI hierarchy dumped')
else: raise SystemExit(90)
'''.format(python=sys.executable,serial=SERIAL)
    for name in ['getprop','dumpsys','screencap','input','am','uiautomator']:
        path=mock/name;path.write_text(fixture);path.chmod(0o700)
    fixtures=root/'shell-fixtures';fixtures.mkdir()
    def set_fixture(name,value): (fixtures/name).write_text(value)
    set_fixture('window',WINDOW+'\n');set_fixture('activity',ACTIVITY+'\n');set_fixture('viewport',VIEWPORT+'\n')
    set_fixture('launch','Status: ok\nActivity: org.trillionnium.owneropen/.OwnerOpenShellActivity\nComplete\n');set_fixture('launch-rc','0')
    png=b'fixture-pixel-content';(fixtures/'png').write_bytes(png)
    env={**os.environ,'PATH':str(mock)+os.pathsep+os.environ['PATH'],'HEPTA_TEST_FIXTURES':str(fixtures)}
    def tap_command(name):
        tool=tools_at(root,name);tool.round=2
        tool.latest={'call_id':'shot','attached_round':2,'received_monotonic':__import__('time').monotonic(),
            'encoded_size':[612,1496],'viewport':VIEWPORT,'page_state':PAGE,
            'page_state_sha256':sha(PAGE.encode()),'source_png_sha256':sha(png),
            'image_sha256':'a'*64,'observed_page':{'component':HEPTA_FULL_COMPONENT}}
        argv=tool.map({'call_id':'tap','tool':'phone.tap','command':'','argv':['shot','100','100']})
        return argv[-1].replace(tool.calls['tap']['guard_png_path'],str(fixtures/'owned-guard.png'))
    command=tap_command('tap-stable')
    check('tap_shell_syntax_valid',subprocess.run(['/bin/sh','-n'],input=command.encode(),capture_output=True).returncode==0)
    result=subprocess.run(['/bin/sh'],input=command.encode(),env=env,capture_output=True,timeout=10)
    check('stable_exact_pixels_and_focus_execute_one_mock_input',result.returncode==0 and (fixtures/'input-calls').read_text().splitlines()==['-d 0 tap 200 200'])
    check('tap_guard_owned_file_cleaned',not (fixtures/'owned-guard.png').exists())
    (fixtures/'input-calls').unlink();(fixtures/'png').write_bytes(b'different pixels same viewport')
    result=subprocess.run(['/bin/sh'],input=tap_command('tap-changed-pixels').encode(),env=env,capture_output=True,timeout=10)
    check('same_viewport_changed_pixels_rejected_before_input',result.returncode==71 and not (fixtures/'input-calls').exists())
    (fixtures/'png').write_bytes(png);set_fixture('window',WINDOW.replace('t205','t206')+'\n')
    result=subprocess.run(['/bin/sh'],input=tap_command('tap-changed-focus').encode(),env=env,capture_output=True,timeout=10)
    check('same_viewport_changed_page_focus_rejected_before_input',result.returncode==70 and not (fixtures/'input-calls').exists())
    set_fixture('window',WINDOW+'\n');set_fixture('viewport',VIEWPORT.replace('orientation=0','orientation=1')+'\n')
    result=subprocess.run(['/bin/sh'],input=tap_command('tap-changed-viewport').encode(),env=env,capture_output=True,timeout=10)
    check('changed_viewport_rejected_before_input',result.returncode==68 and not (fixtures/'input-calls').exists())
    set_fixture('viewport',VIEWPORT+'\n')
    ret=tools_at(root,'return-shell');argv=ret.map({'call_id':'ret','tool':'phone.return_hepta','command':'','argv':[]})
    result=subprocess.run(['/bin/sh'],input=argv[-1].encode(),env=env,capture_output=True,timeout=10)
    check('actual_return_shell_receipt_parses',result.returncode==0 and verify_return(json.loads(result.stdout),ret.calls['ret']['capture_id'])[0]['component']==HEPTA_FULL_COMPONENT)
    set_fixture('launch-rc','1')
    result=subprocess.run(['/bin/sh'],input=argv[-1].encode(),env=env,capture_output=True,timeout=10)
    check('am_failure_not_masked_by_tail_observation_or_printf',result.returncode==1 and json.loads(result.stdout)['launch_exit_code']==1)
    read=tools_at(root,'read-shell');view=PACKAGE+':id/result';set_fixture('ui.xml',xml_for([(view,'公开回执🙂')]))
    argv=read.map({'call_id':'read','tool':'phone.read_text','command':'','argv':[PACKAGE,view]})
    command=argv[-1].replace(read.calls['read']['source_xml_path'],str(fixtures/'owned-read.xml'))
    result=subprocess.run(['/bin/sh'],input=command.encode(),env=env,capture_output=True,timeout=10)
    check('actual_read_shell_preserves_UTF8_public_receipt',result.returncode==0 and verify_public_text(json.loads(result.stdout),read.calls['read']['capture_id'],PACKAGE,[view])[0]['values'][0]['text']=='公开回执🙂')
    check('public_read_owned_XML_cleaned',not (fixtures/'owned-read.xml').exists())


def test_fake_cli_quota_stream(root):
    # A local test executable emits recorded event shapes; it is not Codex.
    fake=root/'fake-cli';fake.write_text('#!'+sys.executable+'\nimport sys,json\nsys.stdin.read()\nprint(json.dumps({"type":"item.completed","item":{"type":"error","message":"Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`."}}),flush=True)\nprint(json.dumps({"type":"error","message":"You’ve hit your usage limit."}),flush=True)\nprint(json.dumps({"type":"turn.failed","error":{"message":"You’ve hit your usage limit."}}),flush=True)\nsys.exit(1)\n');fake.chmod(0o700)
    state=root/'fake-state';state.mkdir(mode=0o700);evidence=state/'evidence';evidence.mkdir(mode=0o700)
    (evidence/'claims').mkdir(mode=0o700);cwd=state/'empty';cwd.mkdir(mode=0o700);run=evidence/'run';run.mkdir(mode=0o700)
    args=SimpleNamespace(codex=str(fake),cli_stat=file_identity(fake),model='gpt-6.1-sol',cwd=cwd,
                         evidence=evidence,timeout=5,contracts=None)
    args.model_health=ModelHealth(state/'model-health.json',args.model,replace_json)
    read_fd,write_fd=os.pipe();source=os.fdopen(read_fd,'rb',buffering=0);sink=io.StringIO()
    frame={'protocol':PROTOCOL,'kind':'turn.start','seq':0,'turn':{**BINDING,'user_input':'fixture request'}}
    os.write(write_fd,(json.dumps(frame)+'\n').encode())
    adapter=DailyAdapter(args,source,sink,run,threading.Event())
    try:
        try:adapter.run()
        except ModelFailure as error:adapter.emit('turn.fail',error=str(error))
        frames=[json.loads(line) for line in sink.getvalue().splitlines()]
        check('actual_streamed_fake_cli_quota_becomes_phone_fail',frames[-1]['kind']=='turn.fail' and '[usage_limit_exceeded]' in frames[-1]['error'])
        check('quota_before_decision_dispatches_zero_phone_tools',not any(frame['kind']=='tool.call' for frame in frames))
        check('failed_turn_identity_claim_remains_consumed',len(list((evidence/'claims').iterdir()))==1)
        check('quota_failure_persists_classified_health',json.loads((state/'model-health.json').read_text())['reason']=='usage_limit_exceeded')
        check('actual_original_failure_events_preserved',b'usage limit' in (run/'codex-01.events.jsonl').read_bytes())
        check('fake_CLI_child_group_joined_and_no_relaunch',json.loads((run/'codex-01.joined.json').read_text())['dedicated_process_group_absent'] is True and len(list(run.glob('*.spawn-intent.json')))==1)
        check('quota_business_outcome_not_verified',json.loads((run/'business-outcome.json').read_text())['business_verified'] is False)
    finally:
        adapter.join_child();adapter.frames.close();adapter.inputs.close();source.close();os.close(write_fd)


def main():
    with tempfile.TemporaryDirectory(prefix='hepta-v149-offline-') as directory:
        root=Path(directory).resolve()
        test_errors(root)
        fact=test_page_return_and_reads(root)
        test_contracts_and_terminals(root,fact)
        test_local_shell_guards(root)
        test_fake_cli_quota_stream(root)
    return {'schema':'hepta.v149.offline-checks.v1','checks':CHECKS,'checks_passed':len(CHECKS),
            'real_model_calls':0,'phone_calls':0,'live_services_modified':False,
            'fixtures':'Synthetic UI/native events and disposable local CLI/Android command shims',
            'live_acceptance':False}


if __name__=='__main__':
    print(json.dumps(main(),ensure_ascii=False,indent=2))
