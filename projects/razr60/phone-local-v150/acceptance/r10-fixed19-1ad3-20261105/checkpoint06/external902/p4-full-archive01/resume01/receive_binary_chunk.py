#!/usr/bin/env python3
"""Validate one native binary_read MCP receipt; write only new local evidence files."""
from pathlib import Path
import base64
import hashlib
import json
import sys

R = Path(__file__).resolve().parent
REMOTE = '/home/alex/codex-hepta-external902-7c907661-originals-1ad3-01'
FILES = {'RESULT.json': (5213, '3b1244bc603f33599fd739e141df5c546deacc4eeadf7be837f9a553c0edf857'), 'COLLECTOR.original.py': (40752, 'c1e5867be5cb2f03efb9b41d01c26097309adb7f9b7fd4a95f48a36b7fefe34d'), 'ORIGINALS-MANIFEST.json': (147912, '99b413337849ebe3c2b89dece5c65dacd396d05d2d39abee5cde84d71c1e6e6e'), 'EXTERNAL902-P4-ORIGINALS.tar.xz': (820660, 'ab778aa6c6f45b33f8b1d4af11be68f7d33306af0a40492c1738556af2100a8d')}


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def descriptor(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


name, offset_text, expected_version = sys.argv[1:]
assert name in FILES
offset = int(offset_text)
size, file_sha = FILES[name]
assert offset >= 0 and offset < size and offset % 32768 == 0
receipt = R / 'receipts' / (name + '.offset-' + str(offset).zfill(8) + '.MCP.original.json')
mcp = json.loads(receipt.read_bytes())
assert mcp.get('isError') is False
value = mcp.get('structuredContent')
if not value:
    value = json.loads('\n'.join(row['text'] for row in mcp['content'] if row['type'] == 'text'))
assert value['path'] == REMOTE + '/' + name and value['size'] == size
assert value['offset'] == offset and type(value['version']) is str and value['version']
if expected_version:
    assert value['version'] == expected_version
raw = base64.b64decode(value['data_base64'], validate=True)
assert len(raw) == min(32768, size - offset)
assert sha(raw) == value['chunk_sha256']
assert value['next_offset'] == offset + len(raw)
assert value['eof'] is (value['next_offset'] == size)
version_path = R / 'versions' / (name + '.json')
version = {'path': REMOTE + '/' + name, 'version': value['version'], 'size': size, 'expected_sha256': file_sha}
if offset == 0:
    put(version_path, enc(version))
else:
    assert json.loads(version_path.read_bytes()) == version
chunk = R / 'chunks' / name / (str(offset).zfill(8) + '.bin')
put(chunk, raw)
result = {'state': 'NATIVE_VERSION_PINNED_BINARY_CHUNK_VERIFIED', 'name': name, 'offset': offset,
    'next_offset': value['next_offset'], 'eof': value['eof'], 'version': value['version'],
    'remote_path': value['path'], 'file_size': size, 'expected_file_sha256': file_sha,
    'raw_MCP_receipt': descriptor(receipt), 'chunk': descriptor(chunk),
    'native_chunk_sha256_matched': True, 'exact_expected_chunk_length': True,
    'native_get_only': True, 'remote_process_start': False, 'phone_or_P4_calls': False}
verification_path = R / 'receipts' / (name + '.offset-' + str(offset).zfill(8) + '.VERIFIED.json')
put(verification_path, enc(result))
print(json.dumps({'name': name, 'offset': offset, 'next_offset': value['next_offset'],
    'eof': value['eof'], 'version': value['version'], 'chunk_bytes': len(raw),
    'verification': descriptor(verification_path)}, sort_keys=True))
