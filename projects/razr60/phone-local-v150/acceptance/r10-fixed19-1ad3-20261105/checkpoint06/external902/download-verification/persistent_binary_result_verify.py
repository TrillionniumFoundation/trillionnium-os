#!/usr/bin/env python3
"""Local-only verification of retained operation_result pages; no remote API or retained-code execution."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import re

MAC = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-fixed19-1ad3-20261105-r1/external902-7c907661-mac-originals01/'
P4 = '/home/alex/codex-hepta-external902-7c907661-originals-1ad3-01/'
FIXED = {
    ('pocket4', P4 + 'EXTERNAL902-P4-ORIGINALS.tar.xz'): (
        820660, 'ab778aa6c6f45b33f8b1d4af11be68f7d33306af0a40492c1738556af2100a8d',
        '66306:33991650:820660:1793883317563311695:1793883317563311695'),
    ('mac', MAC + 'EXTERNAL902-ORIGINALS.tar.xz'): (
        1796220, '55934b9f1fefecd4f1f30c677920935fc527a08e0a218138024b5d0230d88ffc',
        '16777233:588533027:1796220:1793881880637206994:1793881880637206994'),
    ('mac', MAC + 'ORIGINALS-MANIFEST.json'): (
        263330, '06b153ea42ec72dfbc9c9d51a9b2b9e0c99815678484190c95bdeab76abd9966',
        '16777233:588533028:263330:1793881880643453078:1793881880643453078'),
}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def descriptor(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def strict(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def payload(value):
    need(type(value) is dict and value.get('isError') is False, 'MCP response is not successful')
    if type(value.get('structuredContent')) is dict:
        return value['structuredContent']
    content = value.get('content')
    need(type(content) is list and len(content) == 1 and content[0].get('type') == 'text',
         'one original MCP text result required')
    return strict(content[0]['text'])


def verify(segment, write_outputs=False):
    segment = Path(segment).resolve(strict=True)
    request_path = segment / 'REQUEST.json'
    request = strict(request_path.read_bytes())
    need(set(request) == {'idempotency_key', 'operation'} and
         type(request['idempotency_key']) is str and 1 <= len(request['idempotency_key'].encode()) <= 128,
         'fixed read operation request required')
    operation = request['operation']
    need(set(operation) == {'tool', 'arguments'} and operation['tool'] == 'binary_read',
         'only retained binary_read results are in scope')
    args = operation['arguments']
    need(set(args) == {'host', 'path', 'offset', 'limit', 'expected_version'},
         'fixed full binary request arguments required')
    need((args['host'], args['path']) in FIXED, 'native read outside exact authorized archive scope')
    size, file_sha, version = FIXED[(args['host'], args['path'])]
    need(args['expected_version'] == version and type(args['offset']) is int and
         0 <= args['offset'] < size and type(args['limit']) is int and 1 <= args['limit'] <= 65536,
         'native file version or range differs')
    starts, statuses, errors, pages = [], [], [], []
    operation_id = None
    for path in sorted(segment.glob('START-*.MCP.original.json')):
        raw = strict(path.read_bytes())
        if raw.get('isError') is not False:
            errors.append(descriptor(path)); continue
        row = payload(raw)
        need(row.get('tool_name') == 'binary_read' and row.get('idempotency_binding_retained') is True,
             'start is not retained binary-read admission')
        opid = row.get('operation_id')
        need(type(opid) is str and re.fullmatch('[0-9a-f]{64}', opid), 'invalid operation ID')
        need(operation_id in (None, opid), 'idempotent admission returned a different operation ID')
        operation_id = opid; starts.append(descriptor(path))
    need(starts and operation_id, 'no original successful operation admission')
    for path in sorted(segment.glob('STATUS-*.MCP.original.json')):
        raw = strict(path.read_bytes())
        if raw.get('isError') is not False:
            errors.append(descriptor(path)); continue
        row = payload(raw)
        need(row.get('operation_id') == operation_id and row.get('tool_name') == 'binary_read',
             'status ID/tool mismatch')
        if row.get('async_state') == 'completed':
            need(row.get('result_state') == 'stored_observed' and row.get('payload_available') is True and
                 row.get('owned_future_active') is False, 'operation has no stored completed payload')
            statuses.append(descriptor(path))
    need(statuses, 'no original completed stored-result status')
    total, result_sha = None, None
    for path in sorted(segment.glob('PAGE-*-attempt*.MCP.original.json')):
        name = re.fullmatch(r'PAGE-([0-9]{8})-attempt([0-9]{2})\.MCP\.original\.json', path.name)
        need(name, 'unrecognized page receipt filename')
        raw = strict(path.read_bytes())
        if raw.get('isError') is not False:
            errors.append(descriptor(path)); continue
        row = payload(raw)
        need(row.get('operation_id') == operation_id and row.get('immutable_snapshot') is True and
             row.get('payload_kind') == 'native_result' and
             row.get('format') == 'serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization',
             'page does not retain the same immutable native SDK result')
        need(type(row.get('total_bytes')) is int and 0 < row['total_bytes'] <= 1048576 and
             type(row.get('result_sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['result_sha256']),
             'invalid immutable SDK payload identity')
        need(total in (None, row['total_bytes']) and result_sha in (None, row['result_sha256']),
             'page whole-payload descriptor changed')
        total, result_sha = row['total_bytes'], row['result_sha256']
        body = base64.b64decode(row['data_base64'], validate=True)
        need(type(row.get('offset')) is int and row['offset'] == int(name[1]) and
             type(row.get('next_offset')) is int and row['next_offset'] == row['offset'] + len(body) and
             0 < len(body) <= 16384 and row['next_offset'] <= total and
             row.get('eof') is (row['next_offset'] == total), 'page byte range or EOF differs')
        pages.append((row['offset'], body, descriptor(path)))
    need(pages, 'no retained payload pages')
    pages.sort(key=lambda row: row[0])
    end = 0
    for offset, body, _ in pages:
        need(offset == end, 'successful pages have a gap, overlap, or duplicate')
        end += len(body)
    need(end == total, 'immutable SDK payload incomplete: %d of %d bytes' % (end, total))
    sdk_raw = b''.join(row[1] for row in pages)
    need(sha(sdk_raw) == result_sha, 'immutable SDK payload SHA differs')
    sdk = strict(sdk_raw)
    need(sdk.get('resultType') == 'complete' and sdk.get('isError') is False,
         'stored native SDK result is not a complete success')
    native = payload(sdk)
    need(set(native) == {'chunk_sha256', 'data_base64', 'eof', 'next_offset', 'offset', 'path', 'size', 'version'},
         'unexpected original native binary response shape')
    need(native['path'] == args['path'] and native['version'] == version and
         type(native['size']) is int and native['size'] == size,
         'original native file identity differs')
    chunk = base64.b64decode(native['data_base64'], validate=True)
    length = min(args['limit'], size - args['offset'])
    need(type(native['offset']) is int and native['offset'] == args['offset'] and len(chunk) == length and
         type(native['next_offset']) is int and native['next_offset'] == args['offset'] + length and
         native['eof'] is (native['next_offset'] == size) and native['chunk_sha256'] == sha(chunk),
         'original native chunk length, range, hash, or EOF differs')
    need(type(sdk.get('content')) is list and len(sdk['content']) == 1 and sdk['content'][0].get('type') == 'text',
         'one original native JSON text required')
    native_raw = sdk['content'][0]['text'].encode('utf-8')
    proof = {'schema': 'hepta.retained-native-binary-result-verification.v1',
             'state': 'IMMUTABLE_SDK_PAYLOAD_AND_ORIGINAL_VERSION_PINNED_CHUNK_VERIFIED',
             'operation_id': operation_id, 'request': descriptor(request_path), 'admissions': starts,
             'completed_stored_status': statuses, 'pages': [row[2] for row in pages], 'error_receipts_preserved': errors,
             'sdk_payload': {'bytes': len(sdk_raw), 'sha256': sha(sdk_raw)},
             'original_native_json_text': {'bytes': len(native_raw), 'sha256': sha(native_raw)},
             'native_file': {'path': args['path'], 'bytes': size, 'expected_sha256': file_sha, 'version': version},
             'native_chunk': {'offset': args['offset'], 'bytes': len(chunk), 'sha256': sha(chunk),
                              'next_offset': native['next_offset'], 'eof': native['eof']},
             'whole_native_file_verified_here': False, 'archive_members_verified_here': False,
             'qualification': False, 'remote_operations_by_verifier': 0,
             'retained_source_imported_or_executed': False, 'verifier': descriptor(Path(__file__).resolve())}
    if write_outputs:
        outputs = {'SDK-PAYLOAD.original.json': sdk_raw, 'NATIVE-BINARY-READ.original.json': native_raw,
                   'NATIVE-CHUNK.bin': chunk, 'SEGMENT-VERIFICATION.json': encoded(proof)}
        need(all(not (segment / name).exists() for name in outputs), 'refuse to replace retained segment outputs')
        for name, raw in outputs.items():
            with (segment / name).open('xb') as stream:
                stream.write(raw)
            need((segment / name).read_bytes() == raw, 'local output readback differs')
    return chunk, proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('segment')
    parser.add_argument('--commit-local-outputs', action='store_true')
    args = parser.parse_args()
    body, proof = verify(args.segment, args.commit_local_outputs)
    print(json.dumps({'state': proof['state'], 'native_chunk': proof['native_chunk'],
                      'operation_id': proof['operation_id'], 'qualification': False}, sort_keys=True))
