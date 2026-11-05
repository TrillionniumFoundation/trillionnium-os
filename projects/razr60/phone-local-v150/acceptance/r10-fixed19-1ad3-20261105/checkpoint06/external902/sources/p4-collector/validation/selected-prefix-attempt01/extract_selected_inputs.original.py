#!/usr/bin/env python3
"""Recover only independently pinned complete members from retained verified XZ-prefix chunks."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import io
import json
import lzma
import tarfile

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
D = BASE / 'actual_external_902e_7c907661_01/mac-full-archive01'
OUT = HERE / 'selected-inputs'
VERSION = '16777233:588533027:1796220:1793881880637206994:1793881880637206994'
REMOTE = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-fixed19-1ad3-20261105-r1/external902-7c907661-mac-originals01/EXTERNAL902-ORIGINALS.tar.xz'
PINS = {
    'root-originals/material/component-inputs.tar.gz': (471979, '989a78d8c9a844ea0f06859a9e9e2b66bafeacd4702a9b8388d6a031b7775afb'),
    'root-originals/phone-plan-setup/stdout.original': (31127, '256181bd37dd1a3b9e4f3c76e901f75de85d4125015356bc1698010d424d2b19'),
    'root-originals/sender-preview/stdout.original': (454, '0778817d222b4abbc77ae2aea8ad151ddc835ca6e6c3345cf517e605134ff691'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def desc(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


failure_path = BASE / 'actual_external_902e_7c907661_01/ROOT-FAILURE.json'
failure_raw = failure_path.read_bytes()
assert (len(failure_raw), sha(failure_raw)) == (20867, '25f7bca3dfd2f10308e2d430704db54e393c12bd0add116065ff8666be85320b')
failure = json.loads(failure_raw)
for phase, name in [('phone-plan-setup', 'root-originals/phone-plan-setup/stdout.original'),
                    ('sender-preview', 'root-originals/sender-preview/stdout.original')]:
    matches = [row['stdout'] for row in failure['steps'] if row['phase'] == phase]
    assert len(matches) == 1 and (matches[0]['bytes'], matches[0]['sha256']) == PINS[name]
prepared_path = BASE / 'actual_external_902e_7c907661_01/material/PREPARED.json'
prepared_raw = prepared_path.read_bytes()
assert (len(prepared_raw), sha(prepared_raw)) == (2873, 'a8b8b355a9bde5db21123cf503be5f62a24d55226e154ce5ed95a428347d1898')
prepared = json.loads(prepared_raw)
assert (prepared['archive']['bytes'], prepared['archive']['sha256']) == PINS['root-originals/material/component-inputs.tar.gz']
parts, receipts = [], []
for offset in range(0, 1703936, 65536):
    stem = 'EXTERNAL902-ORIGINALS.tar.xz.offset-' + str(offset).zfill(8)
    path = D / 'receipts' / (stem + '.MCP.original.json')
    tool = json.loads(path.read_bytes())
    assert tool.get('isError') is False
    value = tool.get('structuredContent') or json.loads('\n'.join(row['text'] for row in tool['content'] if row['type'] == 'text'))
    raw = base64.b64decode(value['data_base64'], validate=True)
    assert value['version'] == VERSION and value['path'] == REMOTE and value['size'] == 1796220
    assert value['offset'] == offset and value['next_offset'] == offset + 65536 and value['eof'] is False
    assert len(raw) == 65536 and sha(raw) == value['chunk_sha256']
    chunk_path = D / 'chunks/EXTERNAL902-ORIGINALS.tar.xz' / (str(offset).zfill(8) + '.bin')
    assert chunk_path.read_bytes() == raw
    parts.append(raw)
    receipts.append({'raw_MCP_receipt': desc(path), 'chunk': desc(chunk_path), 'offset': offset})
prefix = b''.join(parts)
decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
plain = decoder.decompress(prefix, max_length=16 * 1024 * 1024 + 1)
assert len(plain) <= 16 * 1024 * 1024 and decoder.eof is False
selected = {}
with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
    for member in archive:
        assert member.isfile() and not member.issym() and not member.islnk()
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and str(path) == member.name and '\0' not in member.name
        assert all(part not in ('', '.', '..') for part in path.parts)
        if member.name in PINS:
            assert member.name not in selected
            raw = archive.extractfile(member).read()
            assert (len(raw), sha(raw)) == PINS[member.name] and member.size == len(raw)
            selected[member.name] = raw
        if set(selected) == set(PINS):
            break
assert set(selected) == set(PINS)
for name, raw in selected.items():
    put(OUT / name, raw)
report = {'schema': 'hepta.external902.independently-pinned-selected-prefix-members.v1',
    'state': 'THREE_COMPLETE_MEMBERS_MATCH_SEPARATE_EXACT_PINS_FULL_ARCHIVE_STILL_INCOMPLETE',
    'original_xz_complete': False, 'original_xz_crc_or_whole_sha_verified': False,
    'full_239_member_set_verified': False, 'prefix_bytes': len(prefix),
    'prefix_sha256': sha(prefix), 'decompressed_prefix_bytes': len(plain),
    'decompressed_prefix_sha256': sha(plain), 'first_version': VERSION,
    'independent_fixed_pin_sources': [desc(failure_path), desc(prepared_path)],
    'selected_members': [{'archive_member': name, **desc(OUT / name)} for name in sorted(selected)],
    'all_selected_complete_member_bytes_match_independent_pins': True,
    'retained_download_result': desc(D / 'DOWNLOAD-RESULT.json'),
    'chunk_receipts': receipts, 'source': desc(Path(__file__).resolve()),
    'archive_source_executed': False, 'remote_calls': 0, 'phone_calls': 0, 'case_pass': False}
put(OUT / 'SELECTED-INPUTS-VERIFICATION.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps({'state': report['state'], 'report': desc(OUT / 'SELECTED-INPUTS-VERIFICATION.json'),
    'members': report['selected_members'], 'full_archive_complete': False}, sort_keys=True))
