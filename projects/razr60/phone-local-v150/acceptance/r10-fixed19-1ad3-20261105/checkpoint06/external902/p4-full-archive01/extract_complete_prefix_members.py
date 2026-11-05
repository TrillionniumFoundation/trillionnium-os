#!/usr/bin/env python3
"""Extract only complete prefix members independently pinned by the already complete original manifest."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import io
import json
import lzma
import stat
import tarfile

R = Path(__file__).resolve().parent
OUT = R / 'prefix-members01'
REMOTE = '/home/alex/codex-hepta-external902-7c907661-originals-1ad3-01'
VERSION = '66306:33991650:820660:1793883317563311695:1793883317563311695'
ARCHIVE_NAME = 'EXTERNAL902-P4-ORIGINALS.tar.xz'
JOB = '1a1abc71a1f-fc05-5077'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def desc(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def unwrap(path):
    value = json.loads(path.read_bytes())
    assert value.get('isError') is False
    return value.get('structuredContent') or json.loads('\n'.join(row['text'] for row in value['content'] if row['type'] == 'text'))


manifest_path = R / 'complete-small-originals/ORIGINALS-MANIFEST.json'
manifest_raw = manifest_path.read_bytes()
assert (len(manifest_raw), sha(manifest_raw)) == (147912, '99b413337849ebe3c2b89dece5c65dacd396d05d2d39abee5cde84d71c1e6e6e')
manifest = json.loads(manifest_raw)
assert manifest['archive']['path'] == REMOTE + '/' + ARCHIVE_NAME
assert (manifest['archive']['bytes'], manifest['archive']['sha256']) == (820660, 'ab778aa6c6f45b33f8b1d4af11be68f7d33306af0a40492c1738556af2100a8d')
assert manifest['total_original_files'] == 235 and manifest['total_original_file_bytes'] == 5925299
rows = {row['archive_member']: row for row in manifest['files']}
assert len(rows) == 235
status = unwrap(R / 'CONTROLLER-STATUS.json')
readback = unwrap(R / 'CONTROLLER-READ.json')
assert status['job_id'] == readback['job_id'] == JOB and status['exit_code'] == 0
assert status['output_complete'] is True and status['output_durable'] is True
assert status['terminal_publication_confirmed'] is True and status['log_truncated'] == {'stdout': False, 'stderr': False}
stream = readback['stdout']
stdout = bytes.fromhex(stream['bytes_hex'])
assert len(stdout) == stream['size'] == stream['next_offset'] == 1920 and stream['offset'] == 0 and stream['eof'] is True
assert stdout.decode() == stream['text']
final = json.loads(stdout)
assert final['manifest']['path'] == REMOTE + '/ORIGINALS-MANIFEST.json'
assert (final['manifest']['bytes'], final['manifest']['sha256']) == (len(manifest_raw), sha(manifest_raw))
assert final['last_full_recheck']['checked_file_count'] == 235 and final['case_pass'] is False

parts, receipts = [], []
for offset in range(0, 491520, 32768):
    stem = ARCHIVE_NAME + '.offset-' + str(offset).zfill(8)
    path = R / 'receipts' / (stem + '.MCP.original.json')
    value = unwrap(path)
    raw = base64.b64decode(value['data_base64'], validate=True)
    assert value['path'] == REMOTE + '/' + ARCHIVE_NAME and value['version'] == VERSION and value['size'] == 820660
    assert value['offset'] == offset and value['next_offset'] == offset + 32768 and value['eof'] is False
    assert len(raw) == 32768 and sha(raw) == value['chunk_sha256']
    chunk = R / 'chunks' / ARCHIVE_NAME / (str(offset).zfill(8) + '.bin')
    assert chunk.read_bytes() == raw
    parts.append(raw)
    receipts.append({'offset': offset, 'raw_MCP_receipt': desc(path), 'decoded_chunk': desc(chunk)})
prefix = b''.join(parts)
decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
plain = decoder.decompress(prefix, max_length=manifest['tar_plaintext']['bytes'] + 1)
assert len(plain) <= manifest['tar_plaintext']['bytes'] and decoder.eof is False
members = {}
truncated_boundary = None
try:
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            assert member.isfile() and not member.issym() and not member.islnk()
            assert not path.is_absolute() and str(path) == member.name and '\0' not in member.name
            assert all(part not in ('', '.', '..') for part in path.parts)
            assert member.name in rows and member.name not in members
            expected = rows[member.name]
            assert member.size == expected['bytes']
            if member.offset_data + member.size > len(plain):
                truncated_boundary = {'archive_member': member.name, 'data_offset': member.offset_data,
                    'declared_bytes': member.size, 'available_body_bytes': max(0, len(plain) - member.offset_data)}
                break
            raw = archive.extractfile(member).read()
            assert (len(raw), sha(raw)) == (expected['bytes'], expected['sha256'])
            meta = expected['metadata']
            assert len(meta) == 9 and all(type(x) is int for x in meta)
            assert stat.S_ISREG(meta[2]) and meta[5] == 1 and meta[6] == len(raw)
            members[member.name] = raw
except tarfile.ReadError as error:
    assert str(error) in ('unexpected end of data', 'truncated header')
    truncated_boundary = {'type': type(error).__name__, 'detail': str(error)}
assert 0 < len(members) < 235 and truncated_boundary is not None
for name, raw in members.items():
    put(OUT / 'extracted' / name, raw)
counts = {prefix: sum(name.startswith(prefix + '/') for name in members)
          for prefix in manifest['complete_source_roots']}
complete_roots = {}
for prefix, root in manifest['complete_source_roots'].items():
    expected = {name for name in rows if name.startswith(prefix + '/')}
    observed = {name for name in members if name.startswith(prefix + '/')}
    complete_roots[prefix] = {'path': root, 'expected_files': len(expected), 'extracted_files': len(observed),
        'all_files_declared_by_complete_original_manifest_present_and_byte_verified': observed == expected}
report = {'schema': 'hepta.external902-p4.complete-prefix-members.v1',
    'state': 'COMPLETE_MEMBER_SUBSET_INDEPENDENTLY_MATCHES_FULL_ORIGINAL_MANIFEST_ARCHIVE_STILL_INCOMPLETE',
    'collector_job': JOB, 'full_original_manifest': desc(manifest_path),
    'original_controller_terminal_and_manifest_binding_verified': True,
    'original_expected_archive': manifest['archive'], 'archive_first_version': VERSION,
    'prefix_bytes': len(prefix), 'prefix_sha256': sha(prefix),
    'decoded_prefix_bytes': len(plain), 'decoded_prefix_sha256': sha(plain),
    'outer_xz_complete': False, 'outer_xz_crc_and_whole_sha_verified': False,
    'all_235_members_verified': False, 'complete_extracted_members': len(members),
    'complete_extracted_bytes': sum(map(len, members.values())),
    'complete_tree_counts': counts, 'complete_root_member_coverage': complete_roots,
    'truncated_next_member_or_header': truncated_boundary,
    'missing_archive_members': sorted(set(rows) - set(members)),
    'members': [{'archive_member': name, 'original_manifest_row': rows[name],
        'local_copy': desc(OUT / 'extracted' / name)} for name in sorted(members)],
    'native_chunk_receipts': receipts,
    'controller_originals': [desc(R / name) for name in ('CONTROLLER-REQUEST.json', 'CONTROLLER-START.json', 'CONTROLLER-STATUS.json', 'CONTROLLER-READ.json')],
    'source': desc(Path(__file__).resolve()), 'source_imported_or_executed_from_archive': False,
    'remote_calls': 0, 'phone_calls': 0, 'process_start_calls': 0,
    'original_mac_sender_join_or_EOF_retrofitted': False, 'native_cleanup_or_boundary_publication_proven': False,
    'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
    'local_files_do_not_reproduce_original_metadata': True, 'case_pass': False}
put(OUT / 'PREFIX-MEMBER-VERIFICATION.json', enc(report))
print(json.dumps({'state': report['state'], 'verification': desc(OUT / 'PREFIX-MEMBER-VERIFICATION.json'),
    'members': len(members), 'bytes': report['complete_extracted_bytes'], 'complete_roots': complete_roots,
    'missing': report['missing_archive_members'], 'full_archive_complete': False, 'case_pass': False}, sort_keys=True))
