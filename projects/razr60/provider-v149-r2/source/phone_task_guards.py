"""Pure mappings and parsers for qualified inner-display page/return receipts.

This module executes no phone command. Guard failures precede input; a launch
return code alone cannot establish the HEPTA foreground postcondition.
"""
import base64
import hashlib
import re
import shlex
import xml.etree.ElementTree as ET

from provider_openai_compatible import ProviderError

HEPTA_COMPONENT = 'org.trillionnium.owneropen/.OwnerOpenShellActivity'
HEPTA_FULL_COMPONENT = 'org.trillionnium.owneropen/org.trillionnium.owneropen.OwnerOpenShellActivity'
PAGE_STATE_COMMAND = (
    "dumpsys window | grep -E '^[[:space:]]*(Display: mDisplayId=|mTopFocusedDisplayId=|mCurrentFocus=|mFocusedApp=|isKeyguardShowing=)'; "
    "dumpsys activity activities | grep -E '^[[:space:]]*topResumedActivity='"
)


def require(ok, reason):
    if not ok:
        raise ProviderError('[phone_postcondition] ' + reason)


def decode_text(value, label, maximum=16384):
    require(isinstance(value, str) and 0 < len(value) <= maximum * 2, label + ' encoding missing or oversized')
    try:
        raw = base64.b64decode(value, validate=True)
        text = raw.decode('utf-8', errors='strict')
    except (ValueError, UnicodeError) as error:
        raise ProviderError('[phone_postcondition] ' + label + ' is not canonical UTF8/base64') from error
    require(base64.b64encode(raw).decode() == value and 0 < len(raw) <= maximum and '\0' not in text,
            label + ' bound or canonical encoding differs')
    return text


def component(text):
    values = re.findall(r'(?<![A-Za-z0-9_.$/])([A-Za-z][A-Za-z0-9_.$]*/[A-Za-z0-9_.$]+)(?![A-Za-z0-9_.$/])', text)
    require(len(values) == 1, 'foreground component is missing or ambiguous')
    package, activity = values[0].split('/')
    if activity.startswith('.'):
        activity = package + activity
    return package + '/' + activity


def page_state(text):
    require(isinstance(text, str) and 0 < len(text.encode()) <= 16384 and '\0' not in text,
            'page state is missing or oversized')
    sections, top_ids, resumed = {}, [], []
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.fullmatch(r'Display: mDisplayId=([0-9]+)(?:\s+.*)?', line)
        if match:
            current = int(match.group(1))
            require(current not in sections, 'duplicate display section')
            sections[current] = {}
            continue
        match = re.fullmatch(r'mTopFocusedDisplayId=([0-9]+)', line)
        if match:
            top_ids.append(int(match.group(1)))
            continue
        if line.startswith('topResumedActivity='):
            resumed.append(line.split('=', 1)[1])
            continue
        match = re.fullmatch(r'(mCurrentFocus|mFocusedApp|isKeyguardShowing)=(.*)', line)
        require(match is not None and current in sections, 'page state line is outside a qualified display section')
        key, value = match.groups()
        require(key not in sections[current], 'duplicate display focus field')
        sections[current][key] = value
    require(top_ids == [0] and 0 in sections, 'top focused display is not the qualified inner display')
    active = sections[0]
    require(set(active) == {'mCurrentFocus', 'mFocusedApp', 'isKeyguardShowing'}
            and active['isKeyguardShowing'] == 'false', 'inner display focus or unlocked state is unconfirmed')
    require(active['mCurrentFocus'].startswith('Window{') and active['mFocusedApp'].startswith('ActivityRecord{'),
            'inner display focus is null or not an app window')
    require(len(resumed) == 1 and resumed[0].startswith('ActivityRecord{'), 'resumed activity is missing or ambiguous')
    actual = component(active['mCurrentFocus'])
    require(component(active['mFocusedApp']) == actual and component(resumed[0]) == actual,
            'focused window, focused app and resumed activity disagree')
    return {'display_id': 0, 'component': actual, 'keyguard_showing': False}


def page_capture(variable):
    return variable + '=$(' + PAGE_STATE_COMMAND + '); '


def b64_variable(source, target):
    return target + "=$(printf '%s' \"$" + source + "\" | base64 | tr -d '\\r\\n'); "


def page_equality_guard(expected):
    return page_capture('hepta_page_now') + '[ "$hepta_page_now" = ' + shlex.quote(expected) + ' ] || exit 70; '


def return_command(serial_guard, token):
    # Capture am's exit code immediately. All observations are read-only and
    # cannot replace a failed launch status with the last printf/grep status.
    shell = serial_guard + 'hepta_launch=$(am start -W -n ' + shlex.quote(HEPTA_COMPONENT) + ' 2>&1); hepta_launch_rc=$?; '
    shell += page_capture('hepta_return_page')
    shell += "hepta_return_viewport=$(dumpsys display | grep 'mViewports='); "
    for source, target in [('hepta_launch', 'hepta_launch_b64'), ('hepta_return_page', 'hepta_page_b64'),
                           ('hepta_return_viewport', 'hepta_viewport_b64')]:
        shell += b64_variable(source, target)
    template = '{"schema":"hepta.return-receipt.v149.1","operation_id":"' + token + '","launch_exit_code":%s,"launch_b64":"%s","page_b64":"%s","viewport_b64":"%s"}\n'
    shell += 'printf ' + shlex.quote(template) + ' "$hepta_launch_rc" "$hepta_launch_b64" "$hepta_page_b64" "$hepta_viewport_b64"; exit "$hepta_launch_rc"'
    return shell


def verify_return(value, token):
    require(isinstance(value, dict) and set(value) == {'schema', 'operation_id', 'launch_exit_code', 'launch_b64', 'page_b64', 'viewport_b64'}
            and value['schema'] == 'hepta.return-receipt.v149.1' and value['operation_id'] == token
            and type(value['launch_exit_code']) is int and value['launch_exit_code'] == 0,
            'return receipt identity or launch exit status differs')
    launch = decode_text(value['launch_b64'], 'launch receipt', 8192)
    require(re.findall(r'^Status:\s*(\S+)\s*$', launch, re.MULTILINE) == ['ok']
            and not re.search(r'^\s*(?:Error|Exception|SecurityException)\b', launch, re.MULTILINE),
            'activity launch did not report one successful status')
    activities = re.findall(r'^Activity:\s*(\S+)\s*$', launch, re.MULTILINE)
    require(len(activities) == 1 and component(activities[0]) == HEPTA_FULL_COMPONENT,
            'activity launch reported a different target')
    page = decode_text(value['page_b64'], 'return page')
    observed = page_state(page)
    require(observed['component'] == HEPTA_FULL_COMPONENT, 'HEPTA is not the actual focused and resumed activity')
    return observed, decode_text(value['viewport_b64'], 'return viewport')


def public_text_command(serial_guard, token, package, path):
    shell = serial_guard + 'umask 077; test ! -e ' + shlex.quote(path) + ' && test ! -L ' + shlex.quote(path) + ' || exit 66; '
    cleanup = 'hepta_read_rc=$?; trap - 0; rm -f -- ' + shlex.quote(path) + ' || exit 69; exit "$hepta_read_rc"'
    shell += 'trap ' + shlex.quote(cleanup) + ' 0; '
    shell += page_capture('hepta_page_before')
    shell += "hepta_vp_before=$(dumpsys display | grep 'mViewports='); "
    shell += 'hepta_dump=$(uiautomator dump ' + shlex.quote(path) + ' 2>&1) || { printf \'%s\\n\' "$hepta_dump" >&2; exit 73; }; '
    shell += '[ "$(wc -c < ' + shlex.quote(path) + ')" -le 196608 ] || exit 74; '
    shell += "hepta_vp_after=$(dumpsys display | grep 'mViewports='); "
    shell += page_capture('hepta_page_after')
    for source, target in [('hepta_page_before', 'hepta_page_before_b64'), ('hepta_page_after', 'hepta_page_after_b64'),
                           ('hepta_vp_before', 'hepta_vp_before_b64'), ('hepta_vp_after', 'hepta_vp_after_b64')]:
        shell += b64_variable(source, target)
    shell += 'hepta_xml_b64=$(base64 < ' + shlex.quote(path) + " | tr -d '\\r\\n'); "
    template = ('{"schema":"hepta.public-text-receipt.v149.1","operation_id":"' + token + '","package":"' + package
                + '","page_before_b64":"%s","page_after_b64":"%s","viewport_before_b64":"%s","viewport_after_b64":"%s","xml_b64":"%s"}\n')
    shell += 'printf ' + shlex.quote(template) + ' "$hepta_page_before_b64" "$hepta_page_after_b64" "$hepta_vp_before_b64" "$hepta_vp_after_b64" "$hepta_xml_b64"'
    return shell


def verify_public_text(value, token, package, view_ids):
    require(isinstance(value, dict) and set(value) == {'schema', 'operation_id', 'package', 'page_before_b64',
            'page_after_b64', 'viewport_before_b64', 'viewport_after_b64', 'xml_b64'}
            and value['schema'] == 'hepta.public-text-receipt.v149.1'
            and value['operation_id'] == token and value['package'] == package,
            'public text receipt identity differs')
    before = decode_text(value['page_before_b64'], 'public text page before')
    after = decode_text(value['page_after_b64'], 'public text page after')
    require(before == after, 'public text page focus changed during observation')
    observed = page_state(before)
    require(observed['component'].split('/')[0] == package, 'public text target is not the focused package')
    viewport_before = decode_text(value['viewport_before_b64'], 'public text viewport before')
    viewport_after = decode_text(value['viewport_after_b64'], 'public text viewport after')
    require(viewport_before == viewport_after, 'public text display changed during observation')
    xml = decode_text(value['xml_b64'], 'public UI hierarchy', 196608)
    require('<!DOCTYPE' not in xml and '<!ENTITY' not in xml, 'public UI XML declarations are forbidden')
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise ProviderError('[phone_postcondition] public UI XML is malformed') from error
    require(root.tag == 'hierarchy' and root.get('rotation') == '0', 'public UI root or rotation differs')
    nodes = list(root.iter())
    require(len(nodes) <= 4096 and all(node.tag in {'hierarchy', 'node'} for node in nodes), 'public UI node bound or type differs')
    values = []
    for view_id in view_ids:
        matches = [node for node in nodes if node.get('resource-id') == view_id]
        require(len(matches) == 1, 'public view is missing or ambiguous: ' + view_id)
        node = matches[0]
        require(node.get('package') == package and node.get('password') == 'false'
                and node.get('enabled') == 'true' and node.get('visible-to-user', 'true') == 'true',
                'public view package, password, visibility or enabled state differs')
        bounds = re.fullmatch(r'\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]', node.get('bounds', ''))
        require(bounds is not None, 'public view bounds are missing')
        x1, y1, x2, y2 = map(int, bounds.groups())
        require(0 <= x1 < x2 <= 1224 and 0 <= y1 < y2 <= 2992, 'public view bounds leave the qualified screen')
        text = node.get('text')
        require(isinstance(text, str) and '\0' not in text and len(text.encode()) <= 4096, 'public view text is absent or oversized')
        values.append({'view_id': view_id, 'text': text, 'utf8_sha256': hashlib.sha256(text.encode()).hexdigest(),
                       'bounds': [x1, y1, x2, y2]})
    return {'package': package, 'component': observed['component'], 'display_id': 0,
            'xml_sha256': hashlib.sha256(xml.encode()).hexdigest(), 'values': values}, viewport_before
