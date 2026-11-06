"""Pure, offline decoder of HEPTA49's non-secret committed identity record.

No phone operations, app-state writes, locks, transport or effect authority.
The caller supplies bytes captured read-only after the real app's Inspect.
"""
import base64
import hashlib
import hmac
import json
import re
import struct
import sys

UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
DOMAINS = ('transport_event', 'job_runtime_event', 'job_journal_record')


def decode_client_state(encoded: bytes) -> dict:
    if not isinstance(encoded, bytes) or not 52 < len(encoded) <= 512:
        raise ValueError('invalid record length')
    payload, checksum = encoded[:-32], encoded[-32:]
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), checksum):
        raise ValueError('record checksum mismatch')
    offset = 0

    def take(count):
        nonlocal offset
        if offset + count > len(payload):
            raise ValueError('truncated state field')
        value = payload[offset:offset + count]
        offset += count
        return value

    def byte():
        return take(1)[0]

    def ascii_string():
        count = byte()
        if not 1 <= count <= 64:
            raise ValueError('invalid state string length')
        raw = take(count)
        if any(not 0x21 <= value <= 0x7e for value in raw):
            raise ValueError('noncanonical state string bytes')
        return raw.decode('ascii')

    def identity(prefix):
        value = ascii_string()
        if not re.fullmatch(re.escape(prefix) + UUID, value):
            raise ValueError('invalid local client identity')
        return value

    def optional(reader):
        present = byte()
        if present not in (0, 1):
            raise ValueError('invalid state presence flag')
        return reader() if present else None

    if take(8) != b'OOCLST01' or struct.unpack('>i', take(4))[0] != 2:
        raise ValueError('unsupported state schema')
    revision = struct.unpack('>q', take(8))[0]
    if revision < 1:
        raise ValueError('invalid snapshot revision')
    session = identity('session-')
    task = identity('task-')
    turn = optional(lambda: identity('turn-'))
    request_digest = optional(ascii_string)
    if request_digest is not None and (turn is None or not HEX64.fullmatch(request_digest)):
        raise ValueError('invalid turn request digest')
    count = byte()
    if count > len(DOMAINS) or (turn is None and count):
        raise ValueError('invalid cursor count/selected turn')
    cursors = {}
    previous = -1
    for _ in range(count):
        ordinal = byte()
        if ordinal >= len(DOMAINS) or ordinal <= previous:
            raise ValueError('duplicate/unknown/noncanonical cursor domain')
        previous = ordinal
        epoch = ascii_string()
        cursor = struct.unpack('>q', take(8))[0]
        if not HEX64.fullmatch(epoch) or cursor < 0:
            raise ValueError('invalid cursor producer/cursor')
        cursors[DOMAINS[ordinal]] = {'producer_epoch_sha256': epoch, 'inclusive_cursor': cursor}
    if offset != len(payload):
        raise ValueError('unknown/trailing state fields')
    return {'schema': 'org.trillionnium.owneropen.client-session.v2',
            'revision': revision, 'session_id': session, 'task_id': task,
            'turn_id': turn, 'turn_request_sha256': request_digest, 'cursors': cursors,
            'record_bytes': len(encoded), 'record_sha256': hashlib.sha256(encoded).hexdigest(),
            'payload_sha256': checksum.hex(), 'checksum_valid': True,
            'scope': 'Non-secret identity observation only; no effect/replay authority. Profile and stream are not stored.'}


if __name__ == '__main__':
    # Input is only base64 of the <=512-byte identity record, not app data trees.
    text = sys.stdin.buffer.read(4097)
    if len(text) > 4096:
        raise SystemExit('input exceeds bounded base64 identity capture')
    encoded = base64.b64decode(b''.join(text.split()), validate=True)
    print(json.dumps(decode_client_state(encoded), ensure_ascii=False, indent=2))
