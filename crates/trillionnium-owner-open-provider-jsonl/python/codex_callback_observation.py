"""Bounded native callback observations; never change execution terminal facts.

Large Host frames are scanned as borrowed bytes. Only bounded control metadata
is decoded into a DOM; event payloads are discarded with an explicit event-domain
bridge gap. The caller must retain at most one bounded raw frame, without copying
its byte buffer, and validate Host sequence/call/turn binding before delivery.
"""
from __future__ import annotations

import codecs
import json
import math
import re
from typing import Any

from jsonl_provider_runtime import ProviderRuntimeError, decode_strict_event

MAX_HOST_FRAME_BYTES = 32 * 1024 * 1024
MAX_NATIVE_REPLY_BYTES = 256 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_DEPTH = 64
MAX_OBJECT_KEYS = 4096
MAX_KEY_BYTES = 16 * 1024
MAX_KEY_WORKING_BYTES = 4 * 1024 * 1024
MAX_VALUE_NODES = 32768
MAX_NUMBER_BYTES = 128
MAX_STRING_ESCAPES = 32768
U64_MAX = (1 << 64) - 1
_SPECIAL = re.compile(rb'["\\\x00-\x1f]')
_NUMBER = re.compile(rb'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
_WS = frozenset(b' \t\r\n')


class ObservationBudgetError(ProviderRuntimeError):
    pass


class HostObservation(dict):
    """A normal observation mapping with a separate bridge-owned gap.

    Keeping the gap outside incoming metadata avoids overwriting an unknown
    producer field named bridge_observation_gap. Native encoding adds a separate
    content item in that collision case.
    """
    def __init__(self, value: dict[str, Any], gap: dict[str, Any] | None = None):
        super().__init__(value)
        self.bridge_gap = gap


def _bounded_json(value: Any, maximum: int) -> bytes | None:
    result = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, sort_keys=True,
                               separators=(',', ':'))
    try:
        for fragment in encoder.iterencode(value):
            encoded = fragment.encode('utf-8')
            if len(result) + len(encoded) > maximum:
                return None
            result.extend(encoded)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise ObservationBudgetError('callback observation is not bounded valid JSON') from error
    return bytes(result)


def _gap(call_id: Any, count: int, first: int | None, last: int | None,
         output_bytes: int) -> dict[str, Any]:
    if not isinstance(call_id, str) or not call_id or len(call_id.encode('utf-8')) > 256:
        raise ObservationBudgetError('callback gap call identity is invalid')
    return {'domain': 'tool_execution_event', 'call_id': call_id,
            'event_count': count, 'first_seq': first, 'last_seq': last,
            'output_bytes': output_bytes, 'reason': 'native_callback_observation_budget'}


class _Scanner:
    def __init__(self, raw: bytes | bytearray | memoryview):
        self.raw = memoryview(raw)
        if not self.raw.contiguous or self.raw.ndim != 1 or self.raw.itemsize != 1:
            raise ObservationBudgetError('Host frame must be one contiguous byte buffer')
        self.pos = 0
        self.size = len(self.raw)
        self.count = 0
        self.first: int | None = None
        self.last: int | None = None
        self.output_bytes = 0
        self.call_ids: set[str] = set()
        self.summary_error: str | None = None
        self.has_events = False
        # Conservative cumulative budgets include discarded objects. Keys may
        # remain alive in nested duplicate-detection sets; UCS-4 is the worst
        # decoded string representation. No lifetime reclamation is assumed.
        self.key_working_bytes = 0
        self.value_nodes = 0
        self.string_escapes = 0

    def node(self):
        self.value_nodes += 1
        if self.value_nodes > MAX_VALUE_NODES:
            self.fail('Host callback global value node budget exhausted')

    def fail(self, message: str):
        raise ObservationBudgetError(message)

    def ws(self):
        while self.pos < self.size and self.raw[self.pos] in _WS:
            self.pos += 1

    def expect(self, byte: int):
        self.ws()
        if self.pos >= self.size or self.raw[self.pos] != byte:
            self.fail('malformed Host callback JSON')
        self.pos += 1

    def string(self, *, key: bool = False) -> tuple[int, int]:
        self.ws()
        start = self.pos
        if self.pos >= self.size or self.raw[self.pos] != 34:
            self.fail('malformed Host callback JSON string')
        self.pos += 1
        while True:
            special = _SPECIAL.search(self.raw, self.pos)
            if special is None:
                self.fail('unterminated Host callback JSON string')
            # Validate skipped UTF-8 in small pieces, without decoding/copying a
            # potentially 32 MiB output string into another owned value.
            decoder = codecs.getincrementaldecoder('utf-8')('strict')
            for offset in range(self.pos, special.start(), 8192):
                decoder.decode(self.raw[offset:min(special.start(), offset + 8192)], final=False)
            decoder.decode(b'', final=True)
            self.pos = special.start()
            byte = self.raw[self.pos]
            if byte == 34:
                self.pos += 1
                if key and self.pos - start > MAX_KEY_BYTES:
                    self.fail('Host callback JSON key exceeds its byte budget')
                return start, self.pos
            if byte != 92:
                self.fail('unescaped control byte in Host callback JSON string')
            self.string_escapes += 1
            if self.string_escapes > MAX_STRING_ESCAPES:
                self.fail('Host callback cumulative string escape budget exhausted')
            self.pos += 1
            if self.pos >= self.size:
                self.fail('unterminated Host callback JSON escape')
            escape = self.raw[self.pos]
            self.pos += 1
            if escape == 117:
                if self.pos + 4 > self.size or any(v not in b'0123456789abcdefABCDEF'
                                                  for v in self.raw[self.pos:self.pos + 4]):
                    self.fail('malformed Host callback JSON unicode escape')
                scalar = int(bytes(self.raw[self.pos:self.pos + 4]), 16)
                self.pos += 4
                if 0xD800 <= scalar <= 0xDBFF:
                    if (self.pos + 6 > self.size
                            or self.raw[self.pos:self.pos + 2] != b'\\u'
                            or any(v not in b'0123456789abcdefABCDEF'
                                   for v in self.raw[self.pos + 2:self.pos + 6])):
                        self.fail('unpaired Host callback JSON unicode surrogate')
                    low = int(bytes(self.raw[self.pos + 2:self.pos + 6]), 16)
                    if not 0xDC00 <= low <= 0xDFFF:
                        self.fail('unpaired Host callback JSON unicode surrogate')
                    self.pos += 6
                elif 0xDC00 <= scalar <= 0xDFFF:
                    self.fail('unpaired Host callback JSON unicode surrogate')
            elif escape not in b'"\\/bfnrt':
                self.fail('malformed Host callback JSON escape')

    def key(self, seen: set[str]) -> tuple[str, int, int]:
        start, end = self.string(key=True)
        self.key_working_bytes += (end - start) * 4 + 128
        if self.key_working_bytes > MAX_KEY_WORKING_BYTES:
            self.fail('Host callback cumulative key working budget exhausted')
        try:
            key = json.loads(bytes(self.raw[start:end]))
        except (UnicodeError, ValueError) as error:
            raise ObservationBudgetError('invalid Host callback JSON key') from error
        if key in seen:
            self.fail('duplicate Host callback JSON key')
        if len(seen) >= MAX_OBJECT_KEYS:
            self.fail('Host callback object key budget exhausted')
        seen.add(key)
        self.expect(58)
        return key, start, end

    def done_member(self, close: int) -> bool:
        self.ws()
        if self.pos < self.size and self.raw[self.pos] == close:
            self.pos += 1
            return True
        self.expect(44)
        return False

    def skip(self, depth: int = 0):
        if depth > MAX_DEPTH:
            self.fail('Host callback JSON nesting budget exhausted')
        self.ws()
        self.node()
        if self.pos >= self.size:
            self.fail('truncated Host callback JSON')
        byte = self.raw[self.pos]
        if byte == 34:
            self.string()
        elif byte in (91, 123):
            close = 93 if byte == 91 else 125
            self.pos += 1
            self.ws()
            if self.pos < self.size and self.raw[self.pos] == close:
                self.pos += 1
                return
            seen: set[str] = set()
            while True:
                if byte == 123:
                    self.key(seen)
                self.skip(depth + 1)
                if self.done_member(close):
                    return
        elif byte in (45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57):
            number = _NUMBER.match(self.raw, self.pos)
            if number is None:
                self.fail('malformed Host callback JSON number')
            if number.end() - self.pos > MAX_NUMBER_BYTES:
                self.fail('Host callback JSON number exceeds its byte budget')
            token = bytes(self.raw[self.pos:number.end()])
            if any(value in token for value in b'.eE') and not math.isfinite(float(token)):
                self.fail('Host callback JSON number is non-finite')
            self.pos = number.end()
        else:
            for literal in (b'true', b'false', b'null'):
                if self.raw[self.pos:self.pos + len(literal)] == literal:
                    self.pos += len(literal)
                    return
            self.fail('malformed Host callback JSON scalar')

    def small_value(self, start: int, end: int):
        if end - start > MAX_KEY_BYTES:
            self.summary_error = 'event identity/sequence metadata is oversized'
            return None
        try:
            return json.loads(bytes(self.raw[start:end]))
        except (ValueError, UnicodeError) as error:
            raise ObservationBudgetError('invalid Host callback event metadata') from error

    def event_body(self) -> tuple[Any, Any]:
        self.node()
        self.expect(123)
        self.ws()
        seen: set[str] = set()
        values: dict[str, Any] = {}
        if self.pos < self.size and self.raw[self.pos] == 125:
            self.pos += 1
            return None, None
        while True:
            key, _, _ = self.key(seen)
            self.ws()
            start = self.pos
            self.skip(4)
            if key in {'kind', 'byte_count'}:
                values[key] = self.small_value(start, self.pos)
            if self.done_member(125):
                return values.get('kind'), values.get('byte_count')

    def event(self):
        self.node()
        self.expect(123)
        self.ws()
        seen: set[str] = set()
        seq = call_id = kind = count = None
        if self.pos < self.size and self.raw[self.pos] == 125:
            self.pos += 1
        else:
            while True:
                key, _, _ = self.key(seen)
                self.ws()
                start = self.pos
                if key == 'event' and self.pos < self.size and self.raw[self.pos] == 123:
                    kind, count = self.event_body()
                else:
                    self.skip(3)
                    if key == 'seq':
                        seq = self.small_value(start, self.pos)
                    elif key == 'call_id':
                        call_id = self.small_value(start, self.pos)
                if self.done_member(125):
                    break
        self.count += 1
        if (type(seq) is not int or not 0 <= seq <= U64_MAX
                or self.last is not None and seq <= self.last):
            self.summary_error = 'event sequences are missing, invalid or unordered'
        else:
            self.first = seq if self.first is None else self.first
            self.last = seq
        if not isinstance(call_id, str) or not call_id or len(call_id.encode('utf-8')) > 256:
            self.summary_error = 'event call identity is invalid'
        else:
            self.call_ids.add(call_id)
            if len(self.call_ids) > 1:
                self.summary_error = 'event call identity conflict'
                # Keep no attacker-sized identity collection.
                self.call_ids = {call_id}
        if kind == 'output':
            if type(count) is not int or not 0 <= count <= U64_MAX:
                self.summary_error = 'event output byte count is invalid'
            elif self.output_bytes + count > U64_MAX:
                self.summary_error = 'event output byte count overflows u64'
            else:
                self.output_bytes += count

    def events(self):
        self.node()
        self.expect(91)
        self.ws()
        if self.pos < self.size and self.raw[self.pos] == 93:
            self.pos += 1
            return
        while True:
            self.event()
            if self.done_member(93):
                return

    def scan(self) -> bytes:
        self.node()
        self.expect(123)
        fields: list[tuple[int, int, int, int]] = []
        total = 2
        seen: set[str] = set()
        self.ws()
        if self.pos < self.size and self.raw[self.pos] == 125:
            self.pos += 1
        else:
            while True:
                key, ks, ke = self.key(seen)
                self.ws()
                start = self.pos
                if key == 'events':
                    self.has_events = True
                    self.events()
                else:
                    self.skip(1)
                    total += ke - ks + self.pos - start + 2
                    if total > MAX_METADATA_BYTES:
                        self.fail('Host callback control metadata exceeds its byte budget')
                    fields.append((ks, ke, start, self.pos))
                if self.done_member(125):
                    break
        self.ws()
        if self.pos != self.size:
            self.fail('trailing data after Host callback JSON')
        parts = [bytes(self.raw[ks:ke]) + b':' + bytes(self.raw[vs:ve])
                 for ks, ke, vs, ve in fields]
        return b'{' + b','.join(parts) + b'}'


def decode_host_observation(raw: bytes | bytearray | memoryview, *,
                            maximum_raw_bytes: int = MAX_HOST_FRAME_BYTES) -> dict[str, Any]:
    """Decode one borrowed Host frame without creating a large event DOM.

    Raw frames no larger than the native limit use the generic allocation-gated
    decoder unchanged. Larger frames strictly scan/skip events, then decode only
    the <=256 KiB metadata through that same generic allocation gate. No raw
    input slice or whole UTF-8 string is created for the large frame.
    """
    if len(raw) > maximum_raw_bytes:
        raise ObservationBudgetError('Host callback frame exceeds its raw byte budget')
    scanner = _Scanner(raw)
    try:
        if len(raw) <= MAX_NATIVE_REPLY_BYTES:
            # Lexical scalar validation is identical across the projection
            # boundary; the generic decoder still owns small-frame allocation.
            scanner.skip()
            scanner.ws()
            if scanner.pos != scanner.size:
                raise ObservationBudgetError('trailing data after Host callback JSON')
            return decode_strict_event(bytes(raw) if isinstance(raw, memoryview) else raw)
        metadata = scanner.scan()
    except (UnicodeError, RecursionError) as error:
        raise ObservationBudgetError('Host callback JSON validation failed') from error
    value = decode_strict_event(metadata)
    if value.get('kind') != 'tool.result':
        raise ObservationBudgetError('only tool.result may use the larger Host frame budget')
    call_id = value.get('call_id')
    if scanner.count:
        if scanner.summary_error or scanner.call_ids != {call_id}:
            raise ObservationBudgetError(scanner.summary_error or 'event scope conflicts with callback')
        gap = _gap(call_id, scanner.count, scanner.first, scanner.last, scanner.output_bytes)
        value['events'] = []
        value['events_truncated'] = True
        return HostObservation(value, gap)
    # Whitespace or empty observations need no invented truncation or gap.
    if scanner.has_events:
        value['events'] = []
    return HostObservation(value)


def _summary(events: list[Any], call_id: Any) -> dict[str, Any]:
    first = last = None
    output_bytes = 0
    for event in events:
        if not isinstance(event, dict) or event.get('call_id') != call_id:
            raise ObservationBudgetError('event scope conflicts with callback')
        seq = event.get('seq')
        if type(seq) is not int or not 0 <= seq <= U64_MAX or last is not None and seq <= last:
            raise ObservationBudgetError('event sequences are missing, invalid or unordered')
        first = seq if first is None else first
        last = seq
        body = event.get('event')
        if isinstance(body, dict) and body.get('kind') == 'output':
            count = body.get('byte_count')
            if type(count) is not int or not 0 <= count <= U64_MAX or output_bytes + count > U64_MAX:
                raise ObservationBudgetError('event output byte count is invalid or overflowing')
            output_bytes += count
    return _gap(call_id, len(events), first, last, output_bytes)


def native_tool_result_reply(rpc_id: int | str, outcome: dict[str, Any], *,
                             maximum_reply_bytes: int = MAX_NATIVE_REPLY_BYTES) -> bytes:
    """Encode the exact native envelope, projecting only observation events.

    Small results remain unchanged. Large observations retain all non-event
    metadata and exact terminal/registry facts. The original outcome DOM is never
    deep-copied or mutated. Metadata that cannot fit raises an explicit error.
    """
    gap = getattr(outcome, 'bridge_gap', None)
    value: dict[str, Any] = outcome

    def reply(candidate: dict[str, Any], bridge_gap: dict[str, Any] | None) -> bytes | None:
        projected = candidate
        separate_gap = None
        if bridge_gap is not None:
            if 'bridge_observation_gap' in candidate:
                separate_gap = bridge_gap
            else:
                projected = {**candidate, 'bridge_observation_gap': bridge_gap}
        text = _bounded_json(projected, maximum_reply_bytes)
        if text is None:
            return None
        contents = [{'type': 'inputText', 'text': text.decode('utf-8')}]
        if separate_gap is not None:
            extra = _bounded_json({'bridge_observation_gap': separate_gap}, maximum_reply_bytes)
            if extra is None:
                return None
            contents.append({'type': 'inputText', 'text': extra.decode('utf-8')})
        envelope = {'id': rpc_id, 'result': {'contentItems': contents,
                    'success': outcome.get('status') in {'terminal', 'existing', 'inhibited'}}}
        encoded = _bounded_json(envelope, maximum_reply_bytes - 1)
        return None if encoded is None else encoded + b'\n'

    encoded = reply(value, gap)
    if encoded is not None:
        return encoded
    events = outcome.get('events')
    if not isinstance(events, list) or not events:
        raise ObservationBudgetError('native callback control metadata exceeds its envelope budget')
    gap = _summary(events, outcome.get('call_id'))
    value = {**outcome, 'events': [], 'events_truncated': True}
    encoded = reply(value, gap)
    if encoded is None:
        raise ObservationBudgetError('native callback control metadata exceeds its envelope budget')
    return encoded
