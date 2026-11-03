"""Synthetic protocol/UI fixtures; never evidence of a live phone/model run."""
import base64
import json

PACKAGE = 'org.trillionnium.owneropen'
COMPONENT = PACKAGE + '/.OwnerOpenShellActivity'
FULL_COMPONENT = PACKAGE + '/' + PACKAGE + '.OwnerOpenShellActivity'
WINDOW = '''  Display: mDisplayId=1 (organized)
    mCurrentFocus=null
    mFocusedApp=null
    isKeyguardShowing=false
  Display: mDisplayId=0 (organized)
    mCurrentFocus=Window{3b4490 u0 org.trillionnium.owneropen/org.trillionnium.owneropen.OwnerOpenShellActivity}
    mFocusedApp=ActivityRecord{171231292 u0 org.trillionnium.owneropen/.OwnerOpenShellActivity t205}
    isKeyguardShowing=false
  mTopFocusedDisplayId=0'''
ACTIVITY = '    topResumedActivity=ActivityRecord{171231292 u0 org.trillionnium.owneropen/.OwnerOpenShellActivity t205}'
PAGE = WINDOW + '\n' + ACTIVITY
VIEWPORT = "mViewports=[DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, uniqueId='local:4630947043778501779', orientation=0, logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}, DisplayViewport{type=INTERNAL, valid=true, isActive=false, displayId=1, uniqueId='local:cover-fixture', orientation=2, logicalFrame=Rect(0, 0 - 1080, 1272), physicalFrame=Rect(0, 0 - 1080, 1272)}]"
BINDING = dict(session_id='session-fixture', profile_id='owner-open', task_id='task-fixture',
               turn_id='turn-fixture', turn_stream_id='stream-fixture')


def b64(value):
    return base64.b64encode(value.encode() if isinstance(value, str) else value).decode()


def screenshot_envelope(value, page=PAGE):
    return {'schema': 'hepta.capture-page-envelope.v149.1', 'capture_id': value['capture_id'],
            'page_before_b64': b64(page), 'page_after_b64': b64(page), 'screenshot': value}


def native_result(call_id, value, *, raw=None, exit_code=0):
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode() if raw is None else raw
    terminal = {'kind': 'exited', 'exit_code': exit_code, 'error': None, 'output_truncated': False,
                'stdout_bytes': len(raw), 'stderr_bytes': 0}
    events = [{'kind': 'accepted'}, {'kind': 'started', 'pid': 999}]
    for start in range(0, len(raw), 4096):
        chunk = raw[start:start+4096]
        events.append({'kind': 'output', 'stream': 'stdout', 'encoding': 'base64',
                       'byte_count': len(chunk), 'data': b64(chunk)})
    events.append({'kind': 'terminal', 'terminal': terminal})
    reply = {'call_id': call_id, 'status': 'terminal', 'terminal': terminal,
             'events': [{'call_id': call_id, 'tool': 'adb.exec', 'seq': i, 'event': event}
                        for i, event in enumerate(events)]}
    return {'role': 'tool', 'tool_call_id': call_id,
            'content': json.dumps(reply, ensure_ascii=False, separators=(',', ':'))}
