"""Exact pure fragments from reviewed r9 page/viewport modules; no phone calls."""
import re
import hashlib
class ProviderError(ValueError):
    pass

PAGE_STATE_COMMAND = (
    "dumpsys window | grep -E '^[[:space:]]*(Display: mDisplayId=|mTopFocusedDisplayId=|mCurrentFocus=|mFocusedApp=|isKeyguardShowing=)'; "
    "dumpsys activity activities | grep -E '^[[:space:]]*topResumedActivity='"
)

def require(ok, reason):
    if not ok:
        raise ProviderError('[phone_postcondition] ' + reason)

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

PHYSICAL_DISPLAY = '4630947043778501779'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def validate_viewport(text):
    require(isinstance(text, str) and 0 < len(text.encode()) <= 16384 and '\0' not in text,
            'screenshot viewport is missing or oversized')
    entries = re.findall(r'DisplayViewport\{([^{}]+)\}', text)
    active = [entry for entry in entries if re.search(r'\bisActive=true(?:,|$)', entry)]
    require(len(active) == 1, 'screenshot requires one observed active display')
    entry = active[0]
    for field in ['type=INTERNAL', 'valid=true', 'displayId=0',
                  "uniqueId='local:" + PHYSICAL_DISPLAY + "'", 'orientation=0',
                  'logicalFrame=Rect(0, 0 - 1224, 2992)',
                  'physicalFrame=Rect(0, 0 - 1224, 2992)']:
        require(re.search(re.escape(field) + r'(?:,|$)', entry),
                'screenshot display or rotation is not qualified')
    return sha(text.encode())
