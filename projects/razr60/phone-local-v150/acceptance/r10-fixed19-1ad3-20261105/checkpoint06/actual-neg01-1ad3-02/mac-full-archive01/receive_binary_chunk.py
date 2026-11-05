#!/usr/bin/env python3
"""Validate one native binary_read MCP receipt; write only new local evidence files."""
from pathlib import Path
import base64
import hashlib
import json
import sys

R = Path(__file__).resolve().parent
REMOTE = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-fixed19-1ad3-20261105-r1/neg01-1ad3-02-root-evidence01'
FILES = {
    'ROOT-ORIGINALS.tar.xz': (1726952, 'c1af0a770a53ea43a75ca27268147a9ed1059ffd2952006dd76753a997af7a4c'),
    'ORIGINALS-MANIFEST.json': (83642, 'f816acf43134b5cd9b6ae8c62f1e740fac90a3ff7a3c191cb77bfd4e037f8550'),
    'RESULT.json': (3314, '8e791adcd831ecdb28c27740198155054a0e0d7de501470e38d68a123a13d750'),
    'COLLECTOR.original.py': (20496, '181889ed6477819622909d0bdd016ad5d51d3352e17925c0359fc941d87a7d66'),
}


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
assert offset >= 0 and offset < size and offset % 65536 == 0
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
assert len(raw) == min(65536, size - offset)
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
