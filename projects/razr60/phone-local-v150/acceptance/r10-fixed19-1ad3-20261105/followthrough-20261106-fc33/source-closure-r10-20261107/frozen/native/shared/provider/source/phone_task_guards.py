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


# v150-r9: opening an app means bringing its approved component to the top.
# One activity start is followed only by bounded observations. No retrying effect.
APP_OPEN_FLAGS = "NEW_TASK|CLEAR_TOP"
APP_OPEN_MAX_OBSERVATIONS = 20

def stable_activity_observation(target):
    full = component(target)
    package, activity = full.split("/")
    short = package + "/." + activity[len(package) + 1:] if activity.startswith(package + ".") else full
    variants = "(" + "|".join(re.escape(x) for x in sorted({full, short})) + ")"
    suffix = variants + r"([[:space:]}]|$)"
    shell = "hepta_open_attempts=0; hepta_open_stable=false; hepta_open_previous=''; hepta_open_previous_vp=''; "
    shell += "hepta_open_page=''; hepta_open_viewport=''; "
    shell += 'if [ "$hepta_launch_rc" -eq 0 ]; then '
    shell += 'while [ "$hepta_open_attempts" -lt ' + str(APP_OPEN_MAX_OBSERVATIONS) + ' ]; do '
    shell += 'hepta_open_attempts=$((hepta_open_attempts + 1)); '
    shell += page_capture("hepta_open_page")
    shell += "hepta_open_viewport=$(dumpsys display | grep 'mViewports='); "
    checks = [
        r"^[[:space:]]*mCurrentFocus=Window\{.*[[:space:]]" + suffix,
        r"^[[:space:]]*mFocusedApp=ActivityRecord\{.*[[:space:]]" + suffix,
        r"^[[:space:]]*topResumedActivity=ActivityRecord\{.*[[:space:]]" + suffix,
        r"^[[:space:]]*mTopFocusedDisplayId=0$",
    ]
    predicate = " && ".join(
        '[ "$(printf \'%s\\n\' "$hepta_open_page" | grep -E -c -- '
        + shlex.quote(pattern) + ')" = 1 ]' for pattern in checks)
    shell += "if " + predicate + '; then '
    shell += 'if [ "$hepta_open_page" = "$hepta_open_previous" ] && [ "$hepta_open_viewport" = "$hepta_open_previous_vp" ]; then '
    shell += 'hepta_open_stable=true; break; fi; '
    shell += 'hepta_open_previous=$hepta_open_page; hepta_open_previous_vp=$hepta_open_viewport; '
    shell += "else hepta_open_previous=''; hepta_open_previous_vp=''; fi; "
    shell += 'if [ "$hepta_open_attempts" -lt ' + str(APP_OPEN_MAX_OBSERVATIONS) + ' ]; then sleep 0.1; fi; '
    shell += "done; fi; "
    return shell

def app_open_command(serial_guard, target, token, precondition=""):
    require(re.fullmatch(r"[0-9a-f]{32}", token), "open operation token differs")
    component(target)
    shell = serial_guard + precondition
    shell += 'hepta_launch=$(am start --display 0 -f 0x14000000 -W -n ' + shlex.quote(target) + ' 2>&1); hepta_launch_rc=$?; '
    shell += stable_activity_observation(target)
    for source, dest in [("hepta_launch", "hepta_launch_b64"),
                         ("hepta_open_page", "hepta_page_b64"),
                         ("hepta_open_viewport", "hepta_viewport_b64")]:
        shell += b64_variable(source, dest)
    template = ('{"schema":"hepta.local-app-open.v150.2","operation_id":"' + token
                + '","launch_exit_code":%s,"launch_flags":"NEW_TASK|CLEAR_TOP",'
                  '"observation_attempts":%s,"observation_stable":%s,'
                  '"launch_b64":"%s","page_b64":"%s","viewport_b64":"%s"}\n')
    shell += 'printf ' + shlex.quote(template) + ' "$hepta_launch_rc" "$hepta_open_attempts" "$hepta_open_stable" "$hepta_launch_b64" "$hepta_page_b64" "$hepta_viewport_b64"; '
    shell += '[ "$hepta_launch_rc" -eq 0 ] || exit "$hepta_launch_rc"; '
    shell += '[ "$hepta_open_stable" = true ] || exit 77'
    return shell

def verify_app_open(value, token, target):
    names = {"schema", "operation_id", "launch_exit_code", "launch_flags",
             "observation_attempts", "observation_stable", "launch_b64",
             "page_b64", "viewport_b64"}
    require(isinstance(value, dict) and set(value) == names
            and value["schema"] == "hepta.local-app-open.v150.2"
            and value["operation_id"] == token
            and type(value["launch_exit_code"]) is int and value["launch_exit_code"] == 0
            and value["launch_flags"] == APP_OPEN_FLAGS
            and type(value["observation_attempts"]) is int
            and 2 <= value["observation_attempts"] <= APP_OPEN_MAX_OBSERVATIONS
            and value["observation_stable"] is True, "app open observation identity or stability differs")
    launch = decode_text(value["launch_b64"], "app launch receipt", 8192)
    require(re.findall(r"^Status:\s*(\S+)\s*$", launch, re.MULTILINE) == ["ok"]
            and not re.search(r"^\s*(?:Error|Exception|SecurityException)\b", launch, re.MULTILINE),
            "app launch failed")
    activities = re.findall(r"^Activity:\s*(\S+)\s*$", launch, re.MULTILINE)
    require(len(activities) == 1 and component(activities[0]) == component(target),
            "launch reported another component")
    observed = page_state(decode_text(value["page_b64"], "app foreground"))
    require(observed["component"] == component(target), "launched app is not actual foreground")
    return observed, decode_text(value["viewport_b64"], "app viewport")


def verify_focus_input(value, operation_id, package, view_id, old_text, requested_text):
    """v2 atomically intends one focus then one replacement; no v1 reinterpretation."""
    expected = requested_text.encode()
    require(isinstance(value, dict) and value.get('schema') == 'hepta.focused-unicode-input.v2'
            and value.get('operation_id') == operation_id and value.get('display_id') == 0
            and value.get('package') == package and value.get('view_id') == view_id
            and value.get('requested_utf8_sha256') == hashlib.sha256(expected).hexdigest()
            and value.get('before_utf8_sha256') == hashlib.sha256(old_text.encode()).hexdigest()
            and value.get('after_utf8_sha256') == hashlib.sha256(expected).hexdigest()
            and value.get('focus_verified') is True and value.get('text_verified') is True
            and value.get('own_automation_disconnected') is True,
            'focus input identity, exact text, focus or cleanup differs')
    focus = value.get('focus_action_attempted')
    require(type(focus) is bool and value.get('focus_action_accepted') is focus,
            'focus action receipt is inconsistent')
    capabilities = value.get('observed_target_capabilities')
    require(type(value.get('target_match_count')) is int and value['target_match_count'] == 1
            and isinstance(capabilities, list) and len(capabilities) == 1
            and isinstance(capabilities[0], dict)
            and all(capabilities[0].get(key) is True for key in
                    ('visible', 'enabled', 'editable', 'focusable', 'focused'))
            and capabilities[0].get('password') is False
            and isinstance(capabilities[0].get('action_ids'), list)
            and all(type(x) is int for x in capabilities[0]['action_ids'])
            and 2097152 in capabilities[0]['action_ids'],
            'focus input actual unique editor capability differs')
    if value.get('status') == 'set_verified':
        require(value.get('action_attempted') is True and value.get('action_accepted') is True
                and value.get('effect_state') == 'observed_exact_requested_text',
                'focus input changed-text receipt is inconsistent')
    else:
        require(value.get('status') == 'already_exact' and old_text == requested_text
                and value.get('action_attempted') is False and value.get('action_accepted') is False
                and value.get('effect_state') == ('focus_verified_text_already_exact' if focus else 'not_started'),
                'focus input already-exact receipt is inconsistent')
    encoded = value.get('readback_text_b64')
    require(isinstance(encoded, str), 'focus input exact readback absent')
    try:
        readback = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise ProviderError('focus input readback is not canonical base64') from error
    require(readback == expected and base64.b64encode(readback).decode() == encoded,
            'focus input original readback bytes differ')
    return readback


def verify_public_text_anchor(value, token, package, title_view_id, anchor_text, value_view_id):
    """Explicit v150.1 selector: unique title and value in one direct Preference text container.

    Android Preference keys are never view IDs. No ancestor search, first-match,
    text normalization or fallback to a different row is performed.
    """
    observed, viewport = verify_public_text(value, token, package, [])
    xml = decode_text(value['xml_b64'], 'public UI hierarchy', 196608)
    root = ET.fromstring(xml)
    require(isinstance(anchor_text, str) and 0 < len(anchor_text.encode()) <= 256
            and '\0' not in anchor_text and title_view_id != value_view_id,
            'public anchor selector is invalid')
    parents = {child: parent for parent in root.iter() for child in parent}
    matches = [node for node in root.iter('node')
               if node.get('resource-id') == title_view_id and node.get('text') == anchor_text]
    require(len(matches) == 1, 'public title anchor is missing or ambiguous')
    title = matches[0]
    row = parents.get(title)
    require(row is not None and row.tag == 'node'
            and row.get('class') == 'android.widget.RelativeLayout',
            'public title is not in a qualified direct Preference text container')
    titles = [node for node in row if node.get('resource-id') == title_view_id]
    values = [node for node in row if node.get('resource-id') == value_view_id]
    require(titles == [title] and len(values) == 1,
            'Preference row title or summary is missing or ambiguous')
    target = values[0]
    def checked_bounds(node):
        require(node.get('package') == package and node.get('password') == 'false'
                and node.get('enabled') == 'true' and node.get('visible-to-user', 'true') == 'true',
                'public anchor node package, privacy, visibility or enabled state differs')
        match = re.fullmatch(r'\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]', node.get('bounds', ''))
        require(match is not None, 'public anchor bounds absent')
        x1, y1, x2, y2 = map(int, match.groups())
        require(0 <= x1 < x2 <= 1224 and 0 <= y1 < y2 <= 2992,
                'public anchor node leaves the qualified screen')
        return [x1, y1, x2, y2]
    row_bounds, title_bounds, bounds = map(checked_bounds, (row, title, target))
    require(title.get('class') == target.get('class') == 'android.widget.TextView',
            'public anchor title/summary class differs')
    for box in (title_bounds, bounds):
        require(row_bounds[0] <= box[0] < box[2] <= row_bounds[2]
                and row_bounds[1] <= box[1] < box[3] <= row_bounds[3],
                'public anchor title/summary leaves its actual row')
    text = target.get('text')
    require(isinstance(text, str) and '\0' not in text and len(text.encode()) <= 4096,
            'public anchored text absent or oversized')
    typed_value = {'selector_schema': 'hepta.public-text-anchor.v150.1',
                   'title_view_id': title_view_id, 'anchor_text': anchor_text,
                   'value_view_id': value_view_id, 'text': text,
                   'utf8_sha256': hashlib.sha256(text.encode()).hexdigest(),
                   'row_bounds': row_bounds, 'anchor_bounds': title_bounds, 'bounds': bounds,
                   'relation': 'same_direct_preference_text_container'}
    observed.pop('values')
    return {**observed, 'anchor_value': typed_value}, viewport
