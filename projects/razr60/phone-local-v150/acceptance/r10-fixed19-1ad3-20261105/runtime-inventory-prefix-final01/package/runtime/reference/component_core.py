"""Byte-preserving operator transport and public probe evidence; no phone CLI."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
import xml.etree.ElementTree as ET

PACKAGE = 'org.trillionnium.hepta.controlprobe'
TEXT_COMPONENT = PACKAGE + '/' + PACKAGE + '.TextEntryActivity'
VISUAL_COMPONENT = PACKAGE + '/' + PACKAGE + '.VisualChallengeActivity'
INPUT_ID = PACKAGE + ':id/unicode_input'
SUBMIT_ID = PACKAGE + ':id/unicode_submit'
READBACK_ID = PACKAGE + ':id/unicode_readback'
RECEIPT_ID = PACKAGE + ':id/unicode_receipt'
SERIAL = 'ZY22LS7WZT'
PHYSICAL_DISPLAY = '4630947043778501779'
SIZE = (1224, 2992)
CONFIG_SHA = '635c58193598f2e2d3479246b5b93ddd348fe2555ff0b502e19b0e634580191b'
SEAL_SHA = '3ec84e70ace3a2736cc5233482dc96304d0af350cb1cb0318f2b6c010b062a96'
SERVICE_SHA = 'db89827f8068de55e35f577147de764cec66abee32bec63c424355d05204d2ff'
INPUTS_SHA = 'f81222a661c51f3efb732089ff3120202622d45d42f69dbf0bfe1bcc82d86514'
CLIENT_SHA = '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
COMPONENT_SHA = '776e740f91d9f71418e313a91f32677c0cafed50c4c84fc1df4e25a1b760a5f3'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(items):
        out = {}
        for name, value in items:
            need(name not in out, 'duplicate JSON member')
            out[name] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def raw_file(path, maximum=4 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
         'canonical absolute file path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= maximum, 'file type/link/size differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after, named = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) ==
             getattr(named, k) for k in fields), 'file changed while read')
        return raw
    finally:
        os.close(fd)


def put(path, value):
    path = Path(path)
    raw = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def load_inputs(inputs, production_pins):
    inputs = Path(inputs)
    need(inputs.resolve(strict=True) == inputs, 'noncanonical host input root')
    need(sha(raw_file(inputs / 'MANIFEST.json')) == INPUTS_SHA, 'actual reviewed host input manifest differs')
    selected = {'provider/SOURCE-SEAL.json': SEAL_SHA, 'production-config.json': CONFIG_SHA,
                'production-service-inputs.json': SERVICE_SHA, 'client/tool_client_r6.py': CLIENT_SHA}
    selected.update({'provider/source/' + name: pin for name, pin in production_pins.items()})
    need(len(production_pins) == 15, 'complete actual production inventory required')
    inventory = strict(raw_file(inputs / 'MANIFEST.json'))['files']
    indexed = {row['name']: row for row in inventory}
    need(len(indexed) == len(inventory), 'duplicate input inventory entry')
    for relative, expected in selected.items():
        raw = raw_file(inputs / relative)
        row = indexed[relative]
        need(sha(raw) == expected == row['sha256'] and len(raw) == row['bytes'],
             'actual input bytes differ: ' + relative)
    seal = strict(raw_file(inputs / 'provider/SOURCE-SEAL.json'))
    need(seal['configuration']['sha256'] == CONFIG_SHA and
         seal['phone_service_inputs_sha256'] == SERVICE_SHA, 'actual source/config/service seal differs')
    need({Path(row['path']).name: row['sha256'] for row in seal['production_files']} == production_pins,
         'source seal production pins differ')
    return strict(raw_file(inputs / 'production-config.json'))


def wire_exchange(frozen_transport, address, transport_id, command, output, *, seconds=30,
                  maximum=8 * 1024 * 1024):
    """One shell-v2 wire exchange, exact bytes, no route discovery or retry here.

    The actor calls the pinned route verifier immediately before entry. Host
    tests use the same frozen request/receive functions with a local fixture.
    Partial streams and the original failure remain saved if no EXIT arrives.
    """
    wire_command = 'shell,v2,raw:' + command
    need(isinstance(command, str) and '\0' not in command and
         0 < len(wire_command.encode()) < 65536, 'short ADB wire command required')
    need(type(seconds) is int and 1 <= seconds <= 60, 'bounded shell deadline required')
    output = Path(output)
    stdout_path, stderr_path = output.with_suffix('.stdout.bin'), output.with_suffix('.stderr.bin')
    stdout = stdout_path.open('xb')
    try:
        stderr = stderr_path.open('xb')
    except BaseException:
        stdout.close()
        raise
    code = None
    error = None
    frames = []
    counts = {1: 0, 2: 0}
    started = time.monotonic_ns()
    deadline = time.monotonic() + seconds
    try:
        with socket.create_connection(address, timeout=min(seconds, 5)) as sock:
            class DeadlineIO:
                # The unchanged receive() may perform many recv() calls. Bound
                # each one by the same absolute deadline, including a slow drip.
                def _bound(self):
                    remaining = deadline - time.monotonic()
                    need(remaining > 0, 'original shell total deadline exceeded')
                    sock.settimeout(remaining)
                def recv(self, count):
                    self._bound()
                    return sock.recv(count)
                def sendall(self, data):
                    self._bound()
                    return sock.sendall(data)
            wire = DeadlineIO()
            frozen_transport.request(wire, 'host:transport-id:' + str(transport_id))
            frozen_transport.request(wire, wire_command)
            closed_stdin = False
            while code is None:
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'original shell total deadline exceeded')
                sock.settimeout(remaining)
                stream, length = struct.unpack('<BI', frozen_transport.receive(wire, 5))
                need(length <= maximum, 'shell frame exceeds byte bound')
                payload = frozen_transport.receive(wire, length)
                need(time.monotonic() <= deadline, 'original shell total deadline exceeded')
                frames.append({'stream': stream, 'bytes': length, 'sha256': sha(payload)})
                if stream in (1, 2):
                    need(sum(counts.values()) + length <= maximum, 'shell output exceeds byte bound')
                    target = stdout if stream == 1 else stderr
                    target.write(payload)
                    target.flush()
                    os.fsync(target.fileno())
                    counts[stream] += length
                elif stream == 3:
                    need(length in (1, 4), 'shell EXIT frame length differs')
                    code = int.from_bytes(payload, 'little')
                    need(0 <= code <= 255, 'shell EXIT value differs')
                elif stream == 4:
                    need(length == 0 and not closed_stdin, 'shell CLOSE_STDIN differs')
                    closed_stdin = True
                else:
                    raise ValueError('unexpected shell stream')
    except BaseException as exc:
        error = {'type': type(exc).__name__, 'message': str(exc)[:2048]}
        raise
    finally:
        for stream in (stdout, stderr):
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        streams = {}
        for name, path in [('stdout', stdout_path), ('stderr', stderr_path)]:
            raw = raw_file(path, maximum)
            streams[name] = {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}
        receipt = {'schema': 'hepta.r9.operator-raw-shell-v2.v1', 'command': command,
            'command_utf8_sha256': sha(command.encode()), 'wire_request_bytes': len(wire_command.encode()),
            'address': list(address), 'transport_id': str(transport_id),
            'p4_monotonic_started_ns': started, 'p4_monotonic_finished_ns': time.monotonic_ns(),
            'exit_code': code, 'original_exit_frame_received': code is not None,
            'output_complete': code is not None and error is None, 'frames': frames,
            'automatic_retry': False, 'error': error, **streams}
        put(output.with_suffix('.wire.json'), receipt)
    return receipt


def public_probe_state(value, operation_id, guards, phone):
    """Canonical public state from the original XML, never an invented counter."""
    observed, viewport = guards.verify_public_text(value, operation_id, PACKAGE,
                                                   [INPUT_ID, SUBMIT_ID, RECEIPT_ID])
    phone.validate_viewport(viewport)
    need(observed['component'] == TEXT_COMPONENT, 'public witness is not actual TextEntry Activity')
    xml = guards.decode_text(value['xml_b64'], 'actual public XML', 196608)
    root = ET.fromstring(xml)
    nodes = list(root.iter('node'))
    state = {'schema': 'hepta.r9.public-submit-effect-witness.v1', 'component': TEXT_COMPONENT,
             'numeric_counter_available': False, 'values': {}}
    selected = {}
    for view_id in (INPUT_ID, SUBMIT_ID, RECEIPT_ID, READBACK_ID):
        matches = [n for n in nodes if n.get('resource-id') == view_id]
        if view_id == READBACK_ID and not matches:
            state['values'][view_id] = {'observed_match_count': 0, 'state': 'absent_in_original_public_xml'}
            continue
        need(len(matches) == 1, 'public witness field missing or ambiguous: ' + view_id)
        node = matches[0]
        need(node.get('package') == PACKAGE and node.get('password') == 'false' and
             node.get('enabled') == 'true' and node.get('visible-to-user', 'true') == 'true',
             'public witness field is not uniquely visible and enabled')
        bounds = re.fullmatch(r'\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]', node.get('bounds', ''))
        need(bounds is not None, 'public field bounds missing')
        x1, y1, x2, y2 = map(int, bounds.groups())
        need(0 <= x1 < x2 <= SIZE[0] and 0 <= y1 < y2 <= SIZE[1], 'public field leaves viewport')
        text = node.get('text')
        need(isinstance(text, str) and '\0' not in text and len(text.encode()) <= 4096,
             'public witness text missing or oversized')
        selected[view_id] = node
        state['values'][view_id] = {'observed_match_count': 1,
            **{k: node.get(k, '') for k in ('resource-id', 'class', 'text', 'content-desc',
               'package', 'password', 'enabled', 'focusable', 'focused', 'clickable',
               'checkable', 'checked', 'selected', 'scrollable', 'bounds')},
            'visible-to-user': node.get('visible-to-user', 'true')}
    need(selected[INPUT_ID].get('class') == 'android.widget.EditText' and
         selected[INPUT_ID].get('focusable') == 'true', 'public input is not the expected editor')
    need(selected[SUBMIT_ID].get('class') == 'android.widget.Button' and
         selected[SUBMIT_ID].get('clickable') == 'true' and
         selected[SUBMIT_ID].get('text') == '确认并读回', 'complete visible Submit control differs')
    need(selected[RECEIPT_ID].get('class') == 'android.widget.TextView', 'public receipt class differs')
    page = guards.decode_text(value['page_after_b64'], 'original public page')
    return state, page, viewport, nodes


def encoded_submit_point(state, encoded_size):
    raw = state['values'][SUBMIT_ID]['bounds']
    x1, y1, x2, y2 = map(int, re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', raw).groups())
    width, height = encoded_size
    x, y = round(((x1 + x2) / 2) * width / SIZE[0]), round(((y1 + y2) / 2) * height / SIZE[1])
    need(0 <= x < width and 0 <= y < height, 'Submit projection leaves original captured image')
    mapped_x, mapped_y = round(x * SIZE[0] / width), round(y * SIZE[1] / height)
    need(x1 < mapped_x < x2 and y1 < mapped_y < y2, 'rounded tap is not inside actual Submit bounds')
    return x, y
