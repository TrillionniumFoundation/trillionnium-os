"""Explicit phone tools, verified image inputs, and deterministic coordinates.

No command is executed here. A selected semantic tool maps to one ordinary
Host adb.exec request. Only the matching, completed native result can supply an
image. Original provider/Host records are never changed by the model projection.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import time

from provider_openai_compatible import ProviderError
from phone_task_guards import (page_state, page_capture, b64_variable, page_equality_guard,
    return_command, verify_return, public_text_command, verify_public_text, decode_text, HEPTA_FULL_COMPONENT)

SERIAL = 'ZY22LS7WZT'
PHYSICAL_DISPLAY = '4630947043778501779'
ORIGINAL_SIZE = (1224, 2992)
MAX_IMAGE_BYTES = 196608
MAX_TURN_IMAGE_BYTES = 393216
MIN_IMAGE_BUDGET = 65536
INPUT_JAR = '/data/local/tmp/hepta-phone-executor-v150-r6/helpers/unicode-input-v148r2.jar'
INPUT_JAR_SHA256 = '0dedcab0d1a0edcd87e0023bf6809366afb4b6f02f3354db8828ed1b3ecbadc2'
SCREEN_JAR = '/data/local/tmp/hepta-phone-executor-v150-r6/helpers/screen-codec-v148r1.jar'
# Compiled codec byte pin; Root qualifies/deploys the artifact independently.
SCREEN_JAR_SHA256 = 'bb1176b7707d1a2a67bcfd2bc9bd1b5db16036c3929f8eb1d8820b927ef62639'
SAFE_CALL = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z')
VIEW_ID = re.compile(r'[A-Za-z][A-Za-z0-9_.]*:id/[A-Za-z0-9_]+\Z')
SCREEN_FIELDS = {'schema', 'status', 'capture_id', 'serial', 'logical_display_id',
    'physical_display_id', 'rotation', 'viewport_before', 'viewport_after',
    'original_width', 'original_height', 'encoded_width', 'encoded_height',
    'media_type', 'encoding', 'quality', 'data_base64', 'image_sha256',
    'source_png_sha256', 'source_png_bytes', 'encoded_bytes'}
SCREEN_INPUTS = {'phone.tap', 'phone.swipe', 'phone.long_press', 'phone.back', 'phone.home'}


def require(ok, reason):
    if not ok:
        raise ProviderError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'phone observation has duplicate JSON fields')
            value[key] = item
        return value
    def invalid(_value):
        raise ProviderError('phone observation contains a non-finite value')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    require(isinstance(value, dict), 'phone observation must be a JSON object')
    return value


def b64_text(value):
    require(isinstance(value, str) and '\0' not in value, 'phone text is malformed')
    raw = value.encode('utf-8', errors='strict')
    require(len(raw) <= 4096, 'phone text exceeds the qualified4096-byte input limit')
    return base64.b64encode(raw).decode() if raw else '-'


def native_streams(reply, call_id, expected_tool='adb.exec'):
    require(expected_tool in {'adb.exec', 'shell.exec'}, 'unqualified phone result wire tool')
    require(reply.get('call_id') == call_id and reply.get('status') == 'terminal',
            'phone result lacks matching terminal identity')
    terminal = reply.get('terminal')
    require(isinstance(terminal, dict) and terminal.get('kind') == 'exited'
            and terminal.get('exit_code') == 0 and terminal.get('error') is None
            and terminal.get('output_truncated') is False,
            'phone semantic tool is not confirmed successful and complete')
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    events = reply.get('events')
    require(isinstance(events, list), 'phone result events are missing')
    for index, record in enumerate(events):
        require(isinstance(record, dict) and record.get('call_id') == call_id and record.get('tool') == expected_tool
                and type(record.get('seq')) is int and record['seq'] == index,
                'phone result event scope or sequence differs')
        event = record.get('event')
        require(isinstance(event, dict), 'phone result event is malformed')
        if event.get('kind') != 'output':
            continue
        name = event.get('stream')
        require(name in streams and event.get('encoding') == 'base64'
                and isinstance(event.get('data'), str), 'phone output stream differs')
        try:
            raw = base64.b64decode(event['data'], validate=True)
        except (ValueError, TypeError) as error:
            raise ProviderError('phone output base64 is invalid') from error
        require(type(event.get('byte_count')) is int and event['byte_count'] == len(raw),
                'phone output byte count differs')
        streams[name].extend(raw)
    kinds = [record['event']['kind'] for record in events]
    require(kinds and kinds[0] == 'accepted' and kinds[-1] == 'terminal'
            and all(kinds.count(kind) == 1 for kind in ('accepted', 'started', 'terminal'))
            and events[-1]['event'].get('terminal') == terminal,
            'phone result does not contain its original accepted/start/terminal events')
    for name, raw in streams.items():
        require(type(terminal.get(name + '_bytes')) is int
                and terminal[name + '_bytes'] == len(raw), 'phone terminal count differs')
    require(not streams['stderr'], 'phone semantic tool reported stderr')
    return bytes(streams['stdout'])


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


def jpeg_size(raw):
    """Bounded structural JPEG check; Android codec owns pixel encoding.

    Require one baseline8-bit frame and scan, bounded marker lengths, valid
    entropy escapes/restart markers and a final EOI with no trailing payload.
    This is not a claim of an independent full JPEG pixel decoder.
    """
    require(isinstance(raw, bytes) and 32 <= len(raw) <= MAX_IMAGE_BYTES
            and raw[:2] == b'\xff\xd8' and raw[-2:] == b'\xff\xd9',
            'screenshot JPEG signature or size differs')
    position, dimensions, seen_tables, seen_scan = 2, None, set(), False
    while position < len(raw):
        require(raw[position] == 255, 'JPEG marker boundary is invalid')
        while position < len(raw) and raw[position] == 255:
            position += 1
        require(position < len(raw), 'JPEG marker is truncated')
        marker = raw[position]; position += 1
        if marker == 217:
            require(seen_scan and position == len(raw), 'JPEG EOI has trailing or absent scan')
            return dimensions
        require(marker not in {0, 216} and not 208 <= marker <= 215,
                'JPEG marker appears outside an encoded scan')
        require(position + 2 <= len(raw), 'JPEG segment length is absent')
        length = struct.unpack('>H', raw[position:position+2])[0]
        require(length >= 2 and position + length <= len(raw), 'JPEG segment is out of bounds')
        data = raw[position+2:position+length]; position += length
        if marker == 192:
            require(dimensions is None and len(data) >= 9 and data[0] == 8,
                    'JPEG frame type or precision differs')
            height, width, channels = struct.unpack('>HHB', data[1:6])
            require(channels in {1, 3} and len(data) == 6 + channels * 3
                    and 1 <= width <= 1600 and 1 <= height <= 1600,
                    'JPEG frame dimensions or components differ')
            dimensions = (width, height)
        elif marker in {219, 196}:
            require(data, 'JPEG coding table is empty'); seen_tables.add(marker)
        elif marker == 218:
            require(dimensions is not None and seen_tables == {219, 196}
                    and not seen_scan and len(data) >= 6, 'JPEG scan prerequisites are absent')
            seen_scan = True
            start = position
            while position < len(raw):
                if raw[position] != 255:
                    position += 1; continue
                require(position + 1 < len(raw), 'JPEG entropy escape is truncated')
                after = raw[position+1]
                if after == 0 or 208 <= after <= 215:
                    position += 2; continue
                if after == 255:
                    position += 1; continue
                require(after == 217 and position > start,
                        'JPEG contains an unsupported extra scan or marker')
                break
        else:
            require(marker == 221 or marker == 254 or 224 <= marker <= 239,
                    'JPEG contains an unqualified marker')
    raise ProviderError('JPEG has no final encoded scan')


class PhoneTools:
    def __init__(self, run_dir, atomic_record):
        self.run_dir, self.atomic_record = Path(run_dir), atomic_record
        self.binding = None
        self.calls, self.images = {}, {}
        self.encoded_bytes_used = 0
        self.max_turn_image_bytes = MAX_TURN_IMAGE_BYTES
        self.action_deadline = None
        self.latest = None
        self.round = 0
        self.verified_facts = {}
        self.foreground_observations = {}
        self.last_result_call_id = None
        self.visual_read_constraints = []

    def bind(self, identity):
        require(self.binding is None, 'phone tool turn binding already exists')
        self.binding = dict(identity)

    def invalidate(self):
        self.latest = None

    def _token(self, call_id):
        require(self.binding and isinstance(call_id, str) and SAFE_CALL.fullmatch(call_id),
                'phone semantic tool requires a safe unique call ID and accepted turn')
        require(call_id not in self.calls, 'phone semantic call is already mapped; no redispatch')
        return sha(json.dumps([self.binding, call_id], sort_keys=True,
                              separators=(',', ':')).encode())[:32]

    def _serial_guard(self):
        return '[ "$(getprop ro.serialno)" = ' + shlex.quote(SERIAL) + ' ] || exit 64; '

    def _wire_call(self, call_id, shell):
        return {'call_id': call_id, 'tool': 'adb.exec', 'argv': ['-s', SERIAL, 'shell', shell]}

    def remember_foreground(self, call_id, page, viewport, result_sha256):
        """Retain an original foreground observation; replaying history cannot refresh it."""
        observed = page_state(page)
        viewport_sha = validate_viewport(viewport)
        value = {'call_id':call_id, 'turn':dict(self.binding), **observed,
                 'page_state':page, 'page_state_sha256':sha(page.encode()),
                 'viewport':viewport, 'viewport_sha256':viewport_sha,
                 'original_result_sha256':result_sha256}
        previous = self.foreground_observations.get(call_id)
        if previous is not None:
            require({k:v for k,v in previous.items() if k != 'received_monotonic'} == value,
                    'retained foreground observation changed')
            return previous
        value['received_monotonic'] = time.monotonic()
        self.foreground_observations[call_id] = value
        return value

    def current_foreground(self):
        value = self.foreground_observations.get(self.last_result_call_id)
        if (value is None or value['turn'] != self.binding
                or not 0 <= time.monotonic() - value['received_monotonic'] <= 120):
            return None
        return value

    def _current_screenshot(self, screenshot_id):
        latest = self.latest
        require(latest and latest['call_id'] == screenshot_id
                and latest['attached_round'] == self.round
                and latest['turn'] == self.binding,
                'screen input requires this turn and round\'s current attached screenshot')
        require(0 <= time.monotonic() - latest['received_monotonic'] <= 120,
                'screen input screenshot expired; no input dispatched')
        validate_viewport(latest['viewport'])
        observed = page_state(latest['page_state'])
        require(observed == latest['observed_page']
                and sha(latest['page_state'].encode()) == latest['page_state_sha256']
                and SHA256.fullmatch(latest['source_png_sha256'])
                and SHA256.fullmatch(latest['image_sha256']),
                'screen input screenshot page/provenance binding differs')
        return latest

    def _screen_input(self, tool, args, command, token):
        """Map one closed input shape; the model never supplies executable text.

        Every operation shares the same exact-image, focus, unlocked-page and
        viewport checks as tap. Back/Home are fixed keycodes, not a generic key
        capability. The receipt proves dispatch completed, not its UI outcome.
        """
        counts = {'phone.tap':3, 'phone.swipe':6, 'phone.long_press':4,
                  'phone.back':1, 'phone.home':1}
        require(tool in counts and command == '' and len(args) == counts[tool],
                'screen input has unsupported command or argument shape')
        require(tool == 'phone.tap' or not self.visual_read_constraints,
                'one-shot visual contract does not admit alternate input actions')
        latest = self._current_screenshot(args[0])
        points, duration = [], None
        if tool in {'phone.tap', 'phone.swipe', 'phone.long_press'}:
            count = 4 if tool == 'phone.swipe' else 2
            encoded = args[1:1+count]
            require(all(isinstance(v, str) and re.fullmatch(r'0|[1-9][0-9]{0,4}', v)
                        for v in encoded), 'screen input coordinates must be canonical integers')
            width, height = latest['encoded_size']
            require(type(width) is int and type(height) is int and 1 <= width <= 1600
                    and 1 <= height <= 1600, 'screen input encoded size differs')
            for index in range(0, count, 2):
                x, y = map(int, encoded[index:index+2])
                require(0 <= x < width and 0 <= y < height,
                        'screen input point is outside the attached image')
                original_x = (2 * x * ORIGINAL_SIZE[0] + width) // (2 * width)
                original_y = (2 * y * ORIGINAL_SIZE[1] + height) // (2 * height)
                require(0 <= original_x < ORIGINAL_SIZE[0] and 0 <= original_y < ORIGINAL_SIZE[1],
                        'screen input mapped coordinate is outside the original display')
                points.append(([x, y], [original_x, original_y]))
        if tool in {'phone.swipe', 'phone.long_press'}:
            require(isinstance(args[-1], str) and re.fullmatch(r'[1-9][0-9]{2,3}', args[-1]),
                    'gesture duration must be a canonical integer')
            duration = int(args[-1])
            require((500 if tool == 'phone.long_press' else 100) <= duration <= 1500,
                    'gesture duration is outside the bounded input interval')
        if tool == 'phone.tap':
            input_argv = ['tap'] + list(map(str, points[0][1]))
        elif tool == 'phone.long_press':
            input_argv = ['swipe'] + list(map(str, points[0][1] * 2)) + [str(duration)]
        elif tool == 'phone.swipe':
            require(points[0][1] != points[1][1], 'swipe endpoints coincide; use typed long_press')
            input_argv = ['swipe'] + list(map(str, points[0][1] + points[1][1])) + [str(duration)]
        else:
            input_argv = ['keyevent', '4' if tool == 'phone.back' else '3']
        shell = self._serial_guard() + '[ "$(dumpsys display | grep \'mViewports=\')" = ' + shlex.quote(latest['viewport']) + ' ] || exit 68; '
        shell += page_equality_guard(latest['page_state'])
        guard_path = '/data/local/tmp/hepta-input-guard-' + token + '.png'
        shell += 'umask 077; test ! -e ' + shlex.quote(guard_path) + ' && test ! -L ' + shlex.quote(guard_path) + ' || exit 66; '
        cleanup = 'hepta_guard_rc=$?; trap - 0; rm -f -- ' + shlex.quote(guard_path) + ' || exit 69; exit "$hepta_guard_rc"'
        shell += 'trap ' + shlex.quote(cleanup) + ' 0; '
        shell += 'screencap -d ' + PHYSICAL_DISPLAY + ' -p ' + shlex.quote(guard_path) + ' || exit 67; '
        shell += '[ "$(sha256sum ' + shlex.quote(guard_path) + " | cut -d ' ' -f 1)\" = " + shlex.quote(latest['source_png_sha256']) + ' ] || exit 71; '
        shell += page_equality_guard(latest['page_state'])
        shell += '[ "$(dumpsys display | grep \'mViewports=\')" = ' + shlex.quote(latest['viewport']) + ' ] || exit 68; '
        shell += 'input -d 0 ' + ' '.join(input_argv)
        record = {'source_image_call_id':args[0], 'source_image_sha256':latest['image_sha256'],
                  'page_state_sha256':latest['page_state_sha256'],
                  'source_png_sha256':latest['source_png_sha256'],
                  'exact_pixel_and_focus_guard':True, 'guard_png_path':guard_path,
                  'package':latest['observed_page']['component'].split('/')[0]}
        if tool in {'phone.tap', 'phone.long_press'}:
            record.update(encoded_xy=points[0][0], original_xy=points[0][1])
        elif tool == 'phone.swipe':
            record.update(encoded_start_xy=points[0][0], original_start_xy=points[0][1],
                          encoded_end_xy=points[1][0], original_end_xy=points[1][1])
        if duration is not None:
            record['duration_ms'] = duration
        return shell, record

    def map(self, decision):
        call_id, tool = decision['call_id'], decision['tool']
        token = self._token(call_id)
        args, command = decision['argv'], decision['command']
        record = {'semantic_tool': tool, 'call_id': call_id, 'capture_id': token,
                  'turn': self.binding, 'state': 'model_decision_mapped_not_dispatch_confirmation'}
        if tool == 'phone.screenshot':
            require(command == '' and args == ['0'], 'screenshot requires empty command and argv[0]')
            require(SHA256.fullmatch(SCREEN_JAR_SHA256), 'screenshot codec artifact not qualified')
            budget = min(MAX_IMAGE_BYTES, self.max_turn_image_bytes - self.encoded_bytes_used)
            require(budget >= MIN_IMAGE_BUDGET, 'turn screenshot byte budget exhausted; no capture dispatched')
            path = '/data/local/tmp/hepta-shot-' + token + '.png'
            shell = self._serial_guard() + 'umask 077; '
            shell += '[ "$(sha256sum ' + shlex.quote(SCREEN_JAR) + " | cut -d ' ' -f 1)\" = " + shlex.quote(SCREEN_JAR_SHA256) + ' ] || exit 65; '
            shell += 'test ! -e ' + shlex.quote(path) + ' && test ! -L ' + shlex.quote(path) + ' || exit 66; '
            cleanup = 'hepta_capture_rc=$?; trap - 0; rm -f -- ' + shlex.quote(path) + ' || exit 69; exit "$hepta_capture_rc"'
            shell += 'trap ' + shlex.quote(cleanup) + ' 0; '
            shell += page_capture('hepta_page_before')
            shell += "hepta_vp_before=$(dumpsys display | grep 'mViewports='); "
            shell += 'screencap -d ' + PHYSICAL_DISPLAY + ' -p ' + shlex.quote(path) + ' || exit 67; '
            shell += "hepta_vp_after=$(dumpsys display | grep 'mViewports='); "
            shell += page_capture('hepta_page_after')
            shell += b64_variable('hepta_page_before', 'hepta_page_before_b64')
            shell += b64_variable('hepta_page_after', 'hepta_page_after_b64')
            shell += "hepta_before_b64=$(printf '%s' \"$hepta_vp_before\" | base64 | tr -d '\\r\\n'); "
            shell += "hepta_after_b64=$(printf '%s' \"$hepta_vp_after\" | base64 | tr -d '\\r\\n'); "
            argv = ['encode', '--capture-id', token, '--input', path, '--serial', SERIAL,
                    '--viewport-before-b64', '$hepta_before_b64', '--viewport-after-b64', '$hepta_after_b64',
                    '--max-bytes', str(budget)]
            quoted = [('\"' + value + '\"') if value.startswith('$hepta_') else shlex.quote(value) for value in argv]
            shell += 'hepta_codec=$(CLASSPATH=' + shlex.quote(SCREEN_JAR) + ' app_process /system/bin org.trillionnium.hepta.screen.ScreenshotCodec ' + ' '.join(quoted) + ') || exit 72; '
            template = '{"schema":"hepta.capture-page-envelope.v149.1","capture_id":"' + token + '","page_before_b64":"%s","page_after_b64":"%s","screenshot":%s}\n'
            shell += 'printf ' + shlex.quote(template) + ' "$hepta_page_before_b64" "$hepta_page_after_b64" "$hepta_codec"'
            record.update(max_image_bytes=budget, source_png_path=path)
            self.invalidate()
        elif tool == 'phone.input_text':
            require(len(args) == 3 and PACKAGE.fullmatch(args[0]) and VIEW_ID.fullmatch(args[1]),
                    'input_text requires package, exact view-id and observed current text')
            require(SHA256.fullmatch(INPUT_JAR_SHA256), 'Unicode helper artifact not qualified')
            expected, replacement = b64_text(args[2]), b64_text(command)
            helper = ['set-text', '--operation-id', call_id, '--display', '0', '--package', args[0],
                      '--view-id', args[1], '--expected-text-b64', expected, '--text-b64', replacement]
            shell = self._serial_guard() + '[ "$(sha256sum ' + shlex.quote(INPUT_JAR) + " | cut -d ' ' -f 1)\" = " + shlex.quote(INPUT_JAR_SHA256) + ' ] || exit 65; '
            shell += 'CLASSPATH=' + shlex.quote(INPUT_JAR) + ' app_process /system/bin org.trillionnium.hepta.input.UnicodeInput ' + ' '.join(shlex.quote(value) for value in helper)
            record.update(package=args[0], view_id=args[1], expected_text=args[2], requested_text=command,
                          requested_utf8_sha256=sha(command.encode()))
            self.invalidate()
        elif tool in SCREEN_INPUTS:
            shell, input_record = self._screen_input(tool, args, command, token)
            record.update(input_record)
            self.invalidate()
        elif tool == 'phone.read_text':
            require(command == '' and 2 <= len(args) <= 6 and PACKAGE.fullmatch(args[0])
                    and len(set(args[1:])) == len(args[1:]) and all(VIEW_ID.fullmatch(v) for v in args[1:]),
                    'read_text requires package and one to five unique exact public view IDs')
            for condition in self.visual_read_constraints:
                if args[0] == condition['package'] and condition['challenge_view_id'] in args[1:]:
                    require(any(fact['kind'] == 'visual_tap_executed' and fact['package'] == args[0]
                                for fact in self.verified_facts.values()),
                            'visual challenge readback requires a completed screenshot-bound visual tap first')
            xml_path = '/data/local/tmp/hepta-public-read-' + token + '.xml'
            shell = public_text_command(self._serial_guard(), token, args[0], xml_path)
            record.update(package=args[0], view_ids=args[1:], source_xml_path=xml_path)
            self.invalidate()
        elif tool == 'phone.return_hepta':
            require(command == '' and args == [], 'return_hepta requires empty command and argv')
            shell = return_command(self._serial_guard(), token)
            record.update(postcondition='actual_inner_display_focused_resumed_HEPTA')
            self.invalidate()
        else:
            raise ProviderError('unrecognized phone semantic tool')
        wire = self._wire_call(call_id, shell)
        record['wire_tool'] = wire['tool']
        record['wire_call'] = wire
        self.atomic_record(self.run_dir / ('semantic-' + sha(call_id.encode()) + '.json'), record)
        self.calls[call_id] = record
        return wire['argv']

    def _image(self, reply, source_content, call):
        call_id = call['call_id']; source_hash = sha(source_content.encode())
        if call_id in self.images:
            old = self.images[call_id]
            require(old['original_result_sha256'] == source_hash
                    and sha(self._read_image(Path(old['path']))) == old['image_sha256'],
                    'retained screenshot observation changed')
            return old
        raw = native_streams(reply, call_id, call.get('wire_tool', 'adb.exec'))
        require(len(raw) <= 600000, 'screenshot JSON exceeds its transport bound')
        envelope = strict_json(raw)
        require(set(envelope) == {'schema', 'capture_id', 'page_before_b64', 'page_after_b64', 'screenshot'}
                and envelope['schema'] == 'hepta.capture-page-envelope.v149.1'
                and envelope['capture_id'] == call['capture_id'], 'screenshot page envelope differs')
        page_before = decode_text(envelope['page_before_b64'], 'page before capture')
        page_after = decode_text(envelope['page_after_b64'], 'page after capture')
        require(page_before == page_after, 'page focus changed during screenshot capture')
        observed_page = page_state(page_before)
        value = envelope['screenshot']
        require(isinstance(value, dict) and set(value) == SCREEN_FIELDS
                and value.get('schema') == 'hepta.phone-screenshot.v1' and value.get('status') == 'encoded'
                and value.get('capture_id') == call['capture_id'] and value.get('serial') == SERIAL
                and type(value.get('logical_display_id')) is int and value['logical_display_id'] == 0
                and type(value.get('rotation')) is int and value['rotation'] == 0
                and isinstance(value.get('physical_display_id'), str)
                and value.get('physical_display_id') in {PHYSICAL_DISPLAY, 'local:' + PHYSICAL_DISPLAY},
                'screenshot metadata does not match the selected phone call')
        before, after = value.get('viewport_before'), value.get('viewport_after')
        require(before == after, 'screenshot display changed during capture')
        viewport_sha = validate_viewport(before)
        require((value.get('original_width'), value.get('original_height')) == ORIGINAL_SIZE
                and value.get('media_type') == 'image/jpeg' and value.get('encoding') == 'base64'
                and type(value.get('quality')) is int and 1 <= value['quality'] <= 100
                and isinstance(value.get('data_base64'), str), 'screenshot codec fields differ')
        try: image = base64.b64decode(value['data_base64'], validate=True)
        except (ValueError, TypeError) as error: raise ProviderError('screenshot JPEG base64 is invalid') from error
        require(base64.b64encode(image).decode() == value['data_base64']
                and type(value.get('encoded_bytes')) is int and value['encoded_bytes'] == len(image)
                and len(image) <= call['max_image_bytes'] and value.get('image_sha256') == sha(image)
                and isinstance(value.get('source_png_sha256'), str) and SHA256.fullmatch(value['source_png_sha256'])
                and type(value.get('source_png_bytes')) is int and 0 < value['source_png_bytes'] <= 16*1024*1024,
                'screenshot bytes or provenance hash differs')
        size = jpeg_size(image)
        require(size == (value.get('encoded_width'), value.get('encoded_height')),
                'screenshot JPEG SOF dimensions differ from codec metadata')
        require(abs(size[0] * ORIGINAL_SIZE[1] - size[1] * ORIGINAL_SIZE[0]) <= max(ORIGINAL_SIZE),
                'screenshot encoding changed the display aspect ratio')
        require(self.encoded_bytes_used + len(image) <= self.max_turn_image_bytes,
                'turn screenshot budget exceeded')
        path = self.run_dir / ('image-' + call['capture_id'] + '.jpg')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(image); stream.flush(); os.fsync(stream.fileno())
        self.encoded_bytes_used += len(image)
        result = {k: v for k, v in value.items() if k != 'data_base64'}
        result.update(path=str(path), call_id=call_id, turn=self.binding,
                      original_result_sha256=source_hash, viewport_sha256=viewport_sha,
                      encoded_size=list(size), viewport=before, received_monotonic=time.monotonic(),
                      page_state=page_before, page_state_sha256=sha(page_before.encode()),
                      observed_page=observed_page,
                      observation_kind='lossy_scaled_actual_phone_screenshot_not_UI_XML',
                      pixel_mapping='round_half_up(encoded_coordinate*original_dimension/encoded_dimension)',
                      turn_image_bytes_used=self.encoded_bytes_used)
        self.atomic_record(self.run_dir / ('capture-' + call['capture_id'] + '.json'), result)
        self.images[call_id] = result
        self.remember_foreground(call_id, page_before, before, source_hash)
        if observed_page['component'] == HEPTA_FULL_COMPONENT:
            self.verified_facts[call_id] = {'kind': 'foreground_hepta', 'call_id': call_id,
                'original_result_sha256': source_hash, 'component': observed_page['component'],
                'display_id': 0, 'evidence_type': 'screenshot_page_focus'}
        return result

    def _read_image(self, path):
        require(path.parent == self.run_dir, 'image path left the current run directory')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and 0 < info.st_size <= MAX_IMAGE_BYTES, 'retained image ownership or size changed')
            raw = bytearray()
            while len(raw) <= MAX_IMAGE_BYTES:
                chunk = os.read(fd, min(65536, MAX_IMAGE_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            require(len(raw) == info.st_size, 'retained image changed while read')
            return bytes(raw)
        finally:
            os.close(fd)

    def prepare(self, messages, rendered, round_number):
        require(len(messages) == len(rendered), 'model transcript projection count differs')
        self.round = round_number
        self.latest = None
        self.last_result_call_id = next((m.get('tool_call_id') for m in reversed(messages)
                                        if m.get('role') == 'tool'), None)
        output, attached = [], []
        for index, (original, projected) in enumerate(zip(messages, rendered)):
            if original.get('role') != 'tool' or original.get('tool_call_id') not in self.calls:
                output.append(projected); continue
            call_id = original['tool_call_id']; call = self.calls[call_id]
            reply = strict_json(projected['content'])
            if call['semantic_tool'] == 'phone.screenshot':
                actual = strict_json(original['content']); image = self._image(actual, original['content'], call)
                fresh = index == len(messages) - 1
                public = {key: value for key, value in image.items()
                          if key not in {'path', 'received_monotonic', 'viewport', 'page_state'}}
                public.update(image_attached_in_this_completion=fresh, stale_for_actions=not fresh)
                reply['_hepta_image_observation'] = public
                # This is a derived model view, not a changed wire/native record.
                for record in reply.get('events', []):
                    event = record.get('event', {})
                    if event.get('kind') == 'output':
                        raw = base64.b64decode(event['data'], validate=True)
                        record['event'] = {'kind': 'output_reference', 'stream': event['stream'],
                                           'original_encoding': 'base64', 'byte_count': len(raw),
                                           'sha256': sha(raw), 'original_data_retained_in_wire_evidence': True}
                decoded = reply.get('_hepta_decoded_output', {})
                for stream in decoded.get('streams', []):
                    if stream.get('stream') == 'stdout':
                        stream.pop('text', None)
                        stream['render_status'] = 'image_codec_JSON_referenced_actual_JPEG_attached_when_fresh'
                if fresh:
                    self.latest = dict(image, attached_round=round_number)
                    attached.append(image)
            elif call['semantic_tool'] == 'phone.input_text':
                actual = strict_json(original['content']); raw = native_streams(actual, call_id, call.get('wire_tool', 'adb.exec')); value = strict_json(raw)
                expected = call['requested_text'].encode()
                require(value.get('schema') == 'hepta.focused-unicode-input.v1'
                        and value.get('status') in {'set_verified', 'already_exact'}
                        and value.get('operation_id') == call_id and value.get('display_id') == 0
                        and value.get('package') == call['package'] and value.get('view_id') == call['view_id']
                        and value.get('requested_utf8_sha256') == sha(expected)
                        and value.get('before_utf8_sha256') == sha(call['expected_text'].encode())
                        and value.get('after_utf8_sha256') == sha(expected)
                        and value.get('own_automation_disconnected') is True,
                        'Unicode helper did not verify the exact requested field text and cleanup')
                if value['status'] == 'set_verified':
                    require(value.get('action_attempted') is True
                            and value.get('effect_state') == 'observed_exact_requested_text',
                            'Unicode changed-text status is inconsistent')
                else:
                    require(value.get('action_attempted') is False and value.get('effect_state') == 'not_started',
                            'Unicode already-exact status is inconsistent')
                require(isinstance(value.get('readback_text_b64'), str), 'Unicode readback field is absent')
                try: readback = base64.b64decode(value['readback_text_b64'], validate=True)
                except (ValueError, TypeError) as error: raise ProviderError('Unicode readback encoding differs') from error
                require(readback == expected and base64.b64encode(readback).decode() == value['readback_text_b64'],
                        'Unicode helper readback differs from requested text or is noncanonical')
                reply['_hepta_verified_text_input'] = {'call_id': call_id, 'package': call['package'],
                    'view_id': call['view_id'], 'actual_readback_utf8': readback.decode(),
                    'actual_utf8_sha256': sha(readback), 'status': value['status'],
                    'own_automation_disconnected': True, 'original_wire_evidence_unchanged': True}
                self.verified_facts[call_id] = {'kind': 'text_readback_exact', 'call_id': call_id,
                    'package': call['package'], 'view_id': call['view_id'], 'utf8_sha256': sha(readback),
                    'original_result_sha256': sha(original['content'].encode()),
                    'evidence_type': 'focused_unicode_helper_exact_readback'}
            elif call['semantic_tool'] in SCREEN_INPUTS:
                actual = strict_json(original['content'])
                raw = native_streams(actual, call_id, call.get('wire_tool', 'adb.exec'))
                require(raw == b'', 'qualified screen input produced unexpected output')
                kind = 'visual_tap_executed' if call['semantic_tool'] == 'phone.tap' else 'screen_action_executed'
                self.verified_facts[call_id] = {'kind': kind, 'call_id': call_id,
                    'semantic_tool':call['semantic_tool'],
                    'package': call['package'], 'source_image_call_id': call['source_image_call_id'],
                    'source_image_sha256': call['source_image_sha256'],
                    'original_result_sha256': sha(original['content'].encode()),
                    'exact_pixel_and_focus_guard': True}
            elif call['semantic_tool'] == 'phone.read_text':
                actual = strict_json(original['content'])
                raw = native_streams(actual, call_id, call.get('wire_tool', 'adb.exec'))
                require(len(raw) <= 400000, 'public text receipt exceeds transport bound')
                value = strict_json(raw)
                observation, viewport = verify_public_text(value, call['capture_id'],
                                                            call['package'], call['view_ids'])
                validate_viewport(viewport)
                self.remember_foreground(call_id, decode_text(value['page_before_b64'], 'public text page'),
                                         viewport, sha(original['content'].encode()))
                fact = {'kind': 'public_text_observation', 'call_id': call_id,
                        'original_result_sha256': sha(original['content'].encode()),
                        **observation, 'evidence_type': 'focused_public_UI_XML_unique_view_readback'}
                self.verified_facts[call_id] = fact
                reply['_hepta_verified_public_text'] = fact
            elif call['semantic_tool'] == 'phone.return_hepta':
                actual = strict_json(original['content'])
                value = strict_json(native_streams(actual, call_id, call.get('wire_tool', 'adb.exec')))
                observed, viewport = verify_return(value, call['capture_id'])
                validate_viewport(viewport)
                self.remember_foreground(call_id, decode_text(value['page_b64'], 'return page'),
                                         viewport, sha(original['content'].encode()))
                fact = {'kind': 'foreground_hepta', 'call_id': call_id,
                        'original_result_sha256': sha(original['content'].encode()),
                        'component': observed['component'], 'display_id': 0,
                        'evidence_type': 'explicit_return_launch_and_actual_focus'}
                self.verified_facts[call_id] = fact
                reply['_hepta_verified_return'] = fact
            output.append({**projected, 'content': json.dumps(reply, ensure_ascii=False, separators=(',', ':'))})
        self.atomic_record(self.run_dir / f'codex-{round_number:02d}.images.json',
                           {'turn': self.binding, 'images': [{k: v for k, v in image.items() if k != 'received_monotonic'} for image in attached],
                            'direct_host_tools_enabled': False, 'old_images_attached': False})
        return output, [image['path'] for image in attached]

