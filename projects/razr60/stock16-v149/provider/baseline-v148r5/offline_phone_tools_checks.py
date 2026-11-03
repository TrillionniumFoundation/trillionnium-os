"""Offline semantic/image boundary checks; never execute phone or model tools."""
from pathlib import Path
import base64, copy, hashlib, json, os, re, shlex, struct, subprocess, sys, tempfile, zlib

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / 'source'))
import phone_observation_tools as module
from phone_observation_tools import PhoneTools, ProviderError
from provider_codex_host import model_transcript

def rejected(function):
    try: function()
    except (ProviderError, OSError, UnicodeError, ValueError, TypeError): return True
    raise AssertionError('invalid input was accepted')

def png(width, height):
    def chunk(kind, value):
        return struct.pack('>I', len(value)) + kind + value + struct.pack('>I', zlib.crc32(kind + value))
    body = (b'\0' + bytes([41, 98, 180]) * width) * height
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(body)) + chunk(b'IEND', b'')

def native_result(call_id, payload):
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    terminal = {'kind': 'exited', 'exit_code': 0, 'error': None, 'output_truncated': False,
                'stdout_bytes': len(raw), 'stderr_bytes': 0}
    inner = [{'kind': 'accepted'}, {'kind': 'started', 'pid': 999}]
    for start in range(0, len(raw), 4096):
        chunk = raw[start:start+4096]
        inner.append({'kind': 'output', 'stream': 'stdout', 'encoding': 'base64',
                      'byte_count': len(chunk), 'data': base64.b64encode(chunk).decode()})
    inner.append({'kind': 'terminal', 'terminal': terminal})
    result = {'call_id': call_id, 'status': 'terminal', 'terminal': terminal,
              'events': [{'call_id': call_id, 'tool':'adb.exec', 'seq': i, 'event': e} for i, e in enumerate(inner)]}
    return {'role': 'tool', 'tool_call_id': call_id,
            'content': json.dumps(result, ensure_ascii=False, separators=(',', ':'))}

def main():
    checks = {}
    viewport = json.loads((BASE.parent / 'stock16-hepta-image-unicode-Root-v148-r1/PHONE-SOURCE-SCREEN.json').read_text())['viewport']
    checks['real_retained_viewport_qualified'] = bool(module.validate_viewport(viewport))
    for name, value in [('rotation', viewport.replace('orientation=0', 'orientation=2', 1)),
                        ('display', viewport.replace('displayId=0', 'displayId=4', 1)),
                        ('multiple_active', viewport.replace('isActive=false', 'isActive=true'))]:
        checks['wrong_' + name + '_rejected'] = rejected(lambda value=value: module.validate_viewport(value))
    binding = dict(session_id='session-fixture', profile_id='owner-open', task_id='task-fixture',
                   turn_id='turn-fixture', turn_stream_id='stream-fixture')
    with tempfile.TemporaryDirectory(prefix='hepta-vision-offline-') as directory:
        root = Path(directory)
        source_png = png(1224, 2992); (root / 'synthetic-source.png').write_bytes(source_png)
        # sips is only a local fixture encoder. It is not a production dependency
        # or a claimed phone/model image source.
        result = subprocess.run(['/usr/bin/sips', '-s', 'format', 'jpeg', '--resampleHeight', '1600',
                                 str(root / 'synthetic-source.png'), '--out', str(root / 'fixture.jpg')],
                                capture_output=True, timeout=20)
        assert result.returncode == 0
        image = (root / 'fixture.jpg').read_bytes(); width, height = module.jpeg_size(image)
        assert height == 1600 and abs(width * 2992 - height * 1224) <= 2992
        checks['real_local_fixture_JPEG_structural_SOF_EOI_valid'] = True
        for name, raw in [('truncated', image[:-1]), ('trailing', image + b'x'), ('signature', b'x' + image[1:])]:
            checks['JPEG_' + name + '_rejected'] = rejected(lambda raw=raw: module.jpeg_size(raw))
        module.SCREEN_JAR_SHA256 = '0' * 64
        def make_tools(name):
            folder = root / name; folder.mkdir(mode=0o700)
            def record(path, value):
                with path.open('x') as stream: json.dump(value, stream, ensure_ascii=False)
            tools = PhoneTools(folder, record); tools.bind(binding); return tools
        tools = make_tools('valid')
        decision = dict(call_id='shot01', tool='phone.screenshot', argv=['0'], command='')
        wire = tools.map(decision)
        command = wire[-1]
        assert command.count('screencap ') == 1 and command.count(' app_process ') == 1
        assert wire[:3] == ['-s', module.SERIAL, 'shell']
        assert '--max-bytes 196608' in command and 'screencap -d 4630947043778501779 -p' in command
        assert subprocess.run(['/bin/sh', '-n'], input=command.encode(), capture_output=True).returncode == 0
        checks['single_explicit_capture_canonical_mapping_no_effect_executed'] = True
        assert 'test ! -L '+tools.calls['shot01']['source_png_path'] in command
        assert command.count('rm -f -- ')==1 and '*' not in command
        trap=re.search(r"trap '([^']+)' 0;",command).group(1)
        owned=root/'owned-source.png';owned.write_bytes(b'fixture')
        local_trap=trap.replace(tools.calls['shot01']['source_png_path'],str(owned))
        result=subprocess.run(['/bin/sh'],input=('trap '+shlex.quote(local_trap)+' 0; exit 7').encode(),capture_output=True)
        assert result.returncode==7 and not owned.exists()
        checks['exact_owned_PNG_cleanup_preserves_original_failure_status']=True
        owned.mkdir()
        result=subprocess.run(['/bin/sh'],input=('trap '+shlex.quote(local_trap)+' 0; exit 0').encode(),capture_output=True)
        assert result.returncode==69 and owned.is_dir()
        checks['PNG_cleanup_failure_nonzero_without_recursive_deletion']=True
        token = tools.calls['shot01']['capture_id']
        payload = {'schema': 'hepta.phone-screenshot.v1', 'status': 'encoded', 'capture_id': token,
            'serial': module.SERIAL, 'logical_display_id': 0, 'physical_display_id': 'local:' + module.PHYSICAL_DISPLAY,
            'rotation': 0, 'viewport_before': viewport, 'viewport_after': viewport,
            'original_width': 1224, 'original_height': 2992, 'encoded_width': width, 'encoded_height': height,
            'media_type': 'image/jpeg', 'encoding': 'base64', 'quality': 80,
            'data_base64': base64.b64encode(image).decode(), 'image_sha256': module.sha(image),
            'source_png_sha256': module.sha(source_png), 'source_png_bytes': len(source_png), 'encoded_bytes': len(image)}
        message = native_result('shot01', payload); original = copy.deepcopy(message)
        rendered, paths = tools.prepare([message], model_transcript([message]), 2)
        assert message == original and len(paths) == 1 and Path(paths[0]).read_bytes() == image
        assert Path(paths[0]).stat().st_mode & 0o777 == 0o600
        assert 'output_reference' in rendered[0]['content'] and payload['data_base64'] not in rendered[0]['content']
        checks['original_wire_unchanged_JPEG0600_attached_compact_model_view'] = True
        latest = tools.latest.copy()
        tap = tools.map(dict(call_id='tap01', tool='phone.tap', command='', argv=['shot01', str(width // 2), str(height // 2)]))
        expected_x = (2 * (width // 2) * 1224 + width) // (2 * width)
        assert tap[-1].endswith('input -d 0 tap ' + str(expected_x) + ' 1496') and tools.latest is None
        checks['encoded_coordinate_half_up_mapping_and_image_consumed'] = True
        checks['second_tap_without_new_image_rejected'] = rejected(lambda: tools.map(dict(call_id='tap02', tool='phone.tap', command='', argv=['shot01','0','0'])))
        tools.latest = latest
        checks['point_outside_image_rejected'] = rejected(lambda: tools.map(dict(call_id='tap03', tool='phone.tap', command='', argv=['shot01',str(width),'0'])))
        checks['foreign_screenshot_id_rejected'] = rejected(lambda: tools.map(dict(call_id='tap04', tool='phone.tap', command='', argv=['foreign','1','1'])))
        tools.latest = dict(latest, attached_round=1)
        checks['previous_completion_image_rejected'] = rejected(lambda: tools.map(dict(call_id='tap05', tool='phone.tap', command='', argv=['shot01','1','1'])))
        other = {'role': 'user', 'content': 'another observation happened'}
        _, old_paths = tools.prepare([message, other], model_transcript([message, other]), 3)
        assert not old_paths and tools.latest is None
        checks['historical_image_not_attached_for_actions'] = True
        for name, mutate in {
            'capture_id': lambda value: value.update(capture_id='foreign'),
            'sha': lambda value: value.update(image_sha256='0'*64),
            'serial': lambda value: value.update(serial='other'),
            'viewport_change': lambda value: value.update(viewport_after=viewport + ' changed'),
            'dimensions': lambda value: value.update(encoded_width=width+1),
            'bytes': lambda value: value.update(encoded_bytes=len(image)+1),
            'codec_status': lambda value: value.update(status='rejected'),
        }.items():
            instance = make_tools(name); instance.map(decision); changed = copy.deepcopy(payload)
            changed['capture_id'] = instance.calls['shot01']['capture_id']; mutate(changed)
            invalid = native_result('shot01', changed)
            checks['screenshot_' + name + '_mismatch_rejected'] = rejected(lambda: instance.prepare([invalid], model_transcript([invalid]), 1))
        budget = make_tools('budget'); budget.encoded_bytes_used = module.MAX_TURN_IMAGE_BYTES - 65535
        checks['exhausted_budget_rejected_before_capture_mapping'] = rejected(lambda: budget.map(decision))
        wrong_tool = copy.deepcopy(message); wrong = json.loads(wrong_tool['content'])
        wrong['events'][0]['tool']='shell.exec';wrong_tool['content']=json.dumps(wrong)
        instance=make_tools('wrong_tool');instance.map(decision)
        checks['same_call_wrong_native_tool_type_rejected']=rejected(lambda:instance.prepare([wrong_tool],model_transcript([wrong_tool]),1))
        text = '蓝牙中文🙂 $HOME `id` $(id)'
        typing = make_tools('typing')
        argv = typing.map(dict(call_id='input01', tool='phone.input_text', command=text,
                               argv=['com.android.settings','android:id/search_src_text','']))
        assert text not in argv[-1] and base64.b64encode(text.encode()).decode() in argv[-1]
        assert '--expected-text-b64 -' in argv[-1]
        assert subprocess.run(['/bin/sh','-n'],input=argv[-1].encode(),capture_output=True).returncode == 0
        checks['Unicode_and_shell_metacharacters_encoded_not_executed'] = True
        reply = {'schema': 'hepta.focused-unicode-input.v1', 'status': 'set_verified',
            'effect_state': 'observed_exact_requested_text', 'operation_id': 'input01', 'display_id':0,
            'package':'com.android.settings','view_id':'android:id/search_src_text',
            'requested_utf8_sha256':module.sha(text.encode()),'after_utf8_sha256':module.sha(text.encode()),
            'before_utf8_sha256':module.sha(b''),
            'readback_text_b64':base64.b64encode(text.encode()).decode(), 'action_attempted':True,
            'own_automation_disconnected':True}
        text_message=native_result('input01',reply); rendered,_=typing.prepare([text_message],model_transcript([text_message]),1)
        assert json.loads(rendered[0]['content'])['_hepta_verified_text_input']['actual_readback_utf8']==text
        checks['Unicode_exact_readback_decoded_for_model'] = True
        for name, value in [('NUL','x\0y'),('too_large','x'*4097)]:
            checks['Unicode_'+name+'_rejected'] = rejected(lambda value=value: module.b64_text(value))
        checks['empty_text_canonical_dash'] = module.b64_text('')=='-'
        bad=copy.deepcopy(reply);bad['own_automation_disconnected']=False;bad_message=native_result('input01',bad)
        checks['incomplete_automation_cleanup_rejected'] = rejected(lambda: typing.prepare([bad_message],model_transcript([bad_message]),2))
        missing=copy.deepcopy(reply);missing.pop('readback_text_b64');missing_message=native_result('input01',missing)
        checks['missing_Unicode_readback_not_inferred_empty']=rejected(lambda:typing.prepare([missing_message],model_transcript([missing_message]),2))
        wrong_before=copy.deepcopy(reply);wrong_before['before_utf8_sha256']='0'*64;wrong_message=native_result('input01',wrong_before)
        checks['input_expected_old_text_hash_mismatch_rejected']=rejected(lambda:typing.prepare([wrong_message],model_transcript([wrong_message]),2))
        actual_path=BASE.parent/'stock16-hepta-image-unicode-Root-v148-r1/CODEC-ACTUAL-OUTPUT.json'
        if actual_path.exists():
            actual=json.loads(actual_path.read_text());actual_image=base64.b64decode(actual['data_base64'],validate=True)
            assert len(actual_image)==actual['encoded_bytes'] and module.sha(actual_image)==actual['image_sha256']
            assert module.jpeg_size(actual_image)==(actual['encoded_width'],actual['encoded_height'])
            assert module.validate_viewport(actual['viewport_before']) and actual['viewport_before']==actual['viewport_after']
            real_tools=make_tools('Root-codec-fixture-only')
            record={'call_id':'root-codec-fixture','capture_id':actual['capture_id'],'max_image_bytes':196608}
            wrapped=native_result(record['call_id'],actual);value=real_tools._image(json.loads(wrapped['content']),wrapped['content'],record)
            assert Path(value['path']).read_bytes()==actual_image
            checks['real_Root_phone_codec_sample_passes_full_image_parser_not_model_evidence']=True
    assert all(checks.values())
    return {'checks':checks,'checks_passed':len(checks),'fixture_image_source':'Synthetic local PNG encoded by sips for offline boundaries only; not phone/model evidence',
        'model_execution':False,'phone_execution':False,'service_mutations':False,'live_image_attachment_tested':False}

if __name__=='__main__':print(json.dumps(main(),ensure_ascii=False,indent=2))
