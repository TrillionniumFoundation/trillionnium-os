#!/usr/bin/env python3
"""Assemble fixed native downloads and verify the 109 original files without executing them."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import io
import json
import stat
import tarfile
import lzma

R = Path(__file__).resolve().parent
BASE = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
REMOTE = BASE + '/root-fixed19-1ad3-20261105-r1/neg01-1ad3-02-root-evidence01'
SOURCE = BASE + '/native-guard-root-chains-r10-r1/root-r10-neg01-1ad3-02'
LABEL = 'root-r10-neg01-1ad3-02'
NONCE = 'bc0573ad459cecae9884d6a46568621b'
JOB = '1a1aba11802-fc05-4f2d'
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
FILES = {
    'ROOT-ORIGINALS.tar.xz': (1726952, 'c1af0a770a53ea43a75ca27268147a9ed1059ffd2952006dd76753a997af7a4c'),
    'ORIGINALS-MANIFEST.json': (83642, 'f816acf43134b5cd9b6ae8c62f1e740fac90a3ff7a3c191cb77bfd4e037f8550'),
    'RESULT.json': (3314, '8e791adcd831ecdb28c27740198155054a0e0d7de501470e38d68a123a13d750'),
    'COLLECTOR.original.py': (20496, '181889ed6477819622909d0bdd016ad5d51d3352e17925c0359fc941d87a7d66'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def desc(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def unwrap(raw):
    value = json.loads(raw)
    assert value.get('isError') is False
    return value.get('structuredContent') or json.loads('\n'.join(row['text'] for row in value['content'] if row['type'] == 'text'))


def safe(name):
    path = PurePosixPath(name)
    assert name and not path.is_absolute() and str(path) == name and '\0' not in name
    assert all(part not in ('', '.', '..') for part in path.parts)
    return path


download = json.loads((R / 'DOWNLOAD-RESULT.json').read_bytes())
assert download['state'] == 'ALL_NATIVE_BINARY_CHUNKS_VERSION_PINNED_AND_VERIFIED'
assert download['verified_chunks'] == download['expected_chunks'] == 31 and download['failures'] == []
assembled, receipt_index = {}, []
for name, (size, expected_sha) in FILES.items():
    version = json.loads((R / 'versions' / (name + '.json')).read_bytes())
    assert version['size'] == size and version['expected_sha256'] == expected_sha
    parts = []
    for offset in range(0, size, 65536):
        stem = name + '.offset-' + str(offset).zfill(8)
        receipt_path = R / 'receipts' / (stem + '.MCP.original.json')
        verification_path = R / 'receipts' / (stem + '.VERIFIED.json')
        value = unwrap(receipt_path.read_bytes())
        raw = base64.b64decode(value['data_base64'], validate=True)
        expected_length = min(65536, size - offset)
        assert value['path'] == REMOTE + '/' + name and value['version'] == version['version']
        assert value['size'] == size and value['offset'] == offset and len(raw) == expected_length
        assert value['next_offset'] == offset + expected_length and value['eof'] is (offset + expected_length == size)
        assert value['chunk_sha256'] == sha(raw)
        chunk = R / 'chunks' / name / (str(offset).zfill(8) + '.bin')
        assert chunk.read_bytes() == raw
        verified = json.loads(verification_path.read_bytes())
        assert verified['raw_MCP_receipt'] == desc(receipt_path) and verified['chunk'] == desc(chunk)
        parts.append(raw)
        receipt_index.append({'name': name, 'offset': offset, 'version': version['version'],
            'raw_MCP_receipt': desc(receipt_path), 'verification': desc(verification_path), 'chunk': desc(chunk)})
    raw = b''.join(parts)
    assert len(raw) == size and sha(raw) == expected_sha
    assembled[name] = raw
assert len(receipt_index) == 31

manifest = json.loads(assembled['ORIGINALS-MANIFEST.json'])
result = json.loads(assembled['RESULT.json'])
assert manifest['state'] == 'EXACT_ENDED_FAILED_PREFIX_READ_ONLY_BYTE_COPY'
assert result['state'] == 'FAILED_CASE_ORIGINALS_ARCHIVED_WITH_FULL9_BOOKENDS'
for value in (manifest, result):
    assert value['source_root'] == SOURCE and value['label'] == LABEL and value['nonce'] == NONCE
    assert value['source_files'] == 109 and value['source_directories'] == 15 and value['source_file_bytes'] == 6126794
    assert value['same_instant_as_failure'] is False and value['atomic_filesystem_snapshot'] is False
    assert value['originals_modified'] is False and value['case_pass'] is False
    assert value['phone_calls'] == value['p4_calls'] == value['subprocesses'] == value['signals_sent'] == 0
for key, name in [('archive', 'ROOT-ORIGINALS.tar.xz'), ('collector_source', 'COLLECTOR.original.py')]:
    for value in (manifest, result):
        row = value[key]
        assert row['path'] == REMOTE + '/' + name and (row['bytes'], row['sha256']) == FILES[name]
assert result['manifest']['path'] == REMOTE + '/ORIGINALS-MANIFEST.json'
assert (result['manifest']['bytes'], result['manifest']['sha256']) == FILES['ORIGINALS-MANIFEST.json']

plain = lzma.decompress(assembled['ROOT-ORIGINALS.tar.xz'])
assert len(plain) == manifest['tar_plaintext']['bytes'] and sha(plain) == manifest['tar_plaintext']['sha256']
members = {}
with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
    for member in archive.getmembers():
        assert member.isfile() and not member.issym() and not member.islnk()
        path = safe(member.name)
        assert path.parts[0] == 'root-originals' and len(path.parts) > 1
        relative = '/'.join(path.parts[1:])
        assert relative not in members
        raw = archive.extractfile(member).read()
        assert len(raw) == member.size
        members[relative] = raw
assert len(members) == manifest['archive_regular_members'] == 109
assert sum(len(raw) for raw in members.values()) == 6126794
file_rows = {}
for row in manifest['files']:
    relative = str(safe(row['relative_path']))
    assert relative not in file_rows and row['path'] == SOURCE + '/' + relative
    raw = members[relative]
    assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
    assert len(row['metadata']) == 9 and all(type(x) is int for x in row['metadata'])
    assert stat.S_ISREG(row['metadata'][2]) and row['metadata'][5] == 1 and row['metadata'][6] == len(raw)
    file_rows[relative] = row
assert set(file_rows) == set(members)
directories = {}
for row in manifest['directories']:
    relative = row['relative_path']
    if relative:
        safe(relative)
    assert relative not in directories
    assert row['path'] == SOURCE + ('/' + relative if relative else '')
    assert len(row['metadata']) == 9 and all(type(x) is int for x in row['metadata'])
    assert stat.S_ISDIR(row['metadata'][2])
    assert row['names'] == sorted(set(row['names']))
    directories[relative] = row
assert len(directories) == 15 and '' in directories
all_paths = set(file_rows) | (set(directories) - {''})
for relative, row in directories.items():
    children = sorted(PurePosixPath(path).name for path in all_paths if str(PurePosixPath(path).parent) == (relative or '.'))
    assert children == row['names']

failure = json.loads(members['ROOT-FAILURE.json'])
assert (len(members['ROOT-FAILURE.json']), sha(members['ROOT-FAILURE.json'])) == (6664, 'e057408165ccca775f8fcc196dc7fdc69fe0aaba72b18f1da0cf5e0f4c8ae471')
assert failure['state'] == 'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
assert failure['host_cleanup'] == {'host_children': [], 'stream_cleanup_errors': []}
assert failure['root_fixture_attempts'] == [] and len(failure['steps']) == 7
phase_proofs = []
for step in failure['steps']:
    name = step['phase']
    original_result = json.loads(members[name + '/RESULT.json'])
    capture = json.loads(members[name + '/OUTPUT-CAPTURE.json'])
    child = json.loads(members[name + '/CHILD.json'])
    intent_raw = members[name + '/INTENT.json']
    assert original_result == step and step['state'] == 'ORIGINAL_HOST_CHILD_JOINED' and step['returncode'] == 0
    assert capture['pid'] == child['pid'] == step['pid']
    assert capture['source_intent_sha256'] == child['source_intent_sha256'] == sha(intent_raw)
    assert capture['worker_joined'] is True and capture['child_wait_returned'] is True and capture['child_returncode'] == 0
    assert capture['stdout_eof'] is True and capture['stderr_eof'] is True and capture['prefix_only_or_unknown'] is False
    for stream in ('stdout', 'stderr'):
        relative = name + '/' + stream + '.original'
        raw, row = members[relative], file_rows[relative]
        exact = {key: row[key] for key in ('path', 'bytes', 'sha256')}
        assert step[stream] == exact
        held = capture['files'][stream]
        assert {key: held[key] for key in exact} == exact and held['original_created_inode_bound'] is True
        assert [held['metadata'][key] for key in META] == row['metadata']
        assert capture['captured'][stream] == {'bytes': len(raw), 'sha256': sha(raw)}
    phase_proofs.append({'phase': name, 'pid': step['pid'], 'original_joined_rc': 0, 'both_original_EOFs': True, 'held_inode_full9_matches_manifest': True})
assert len(manifest['original_host_phase_receipts']) == len(phase_proofs) == result['joined_host_phase_count'] == 7

status = unwrap((R / 'CONTROLLER-STATUS.tool.json').read_bytes())
readback = unwrap((R / 'CONTROLLER-READ.tool.json').read_bytes())
assert status['job_id'] == readback['job_id'] == JOB and status['exit_code'] == 0
assert status['state'] == 'succeeded' and status['output_complete'] is True and status['output_durable'] is True
assert status['terminal_publication_confirmed'] is True and status['timed_out'] is False
streams = {}
for stream, expected_size in [('stdout', 1897), ('stderr', 0)]:
    row = readback[stream]
    raw = bytes.fromhex(row['bytes_hex'])
    assert row['text'].encode() == raw and len(raw) == row['size'] == row['next_offset'] == expected_size
    assert row['offset'] == 0 and row['eof'] is True
    assert status['log_bytes'][stream] == {'seen': expected_size, 'stored': expected_size}
    assert status['log_synced'][stream] is True and status['log_truncated'][stream] is False and status['log_errors'][stream] is None
    streams[stream] = raw
final = json.loads(streams['stdout'])
assert final['state'] == result['state'] and final['case_pass'] is False
assert final['last_full_recheck']['checked_file_count'] == 109 and final['last_full_recheck']['checked_directory_count'] == 15
assert final['last_full_recheck']['completed_unix_ns'] >= result['after_copy_full_recheck']['completed_unix_ns']
for key, name in [('archive', 'ROOT-ORIGINALS.tar.xz'), ('manifest', 'ORIGINALS-MANIFEST.json'), ('result', 'RESULT.json')]:
    row = final[key]
    assert row['path'] == REMOTE + '/' + name and (row['bytes'], row['sha256']) == FILES[name]

for name, raw in assembled.items():
    put(R / name, raw)
for name, raw in members.items():
    put(R / 'root-originals' / name, raw)
for stream, raw in streams.items():
    put(R / ('CONTROLLER-' + stream.upper() + '.original'), raw)
verification = {
    'schema': 'hepta.fixed19.root02-complete-original-download-verification.v1',
    'state': 'EXACT_FOUR_ARTIFACTS_109_MEMBERS_AND_ACTUAL_FINAL_CONTROLLER_VERIFIED',
    'collector_job': JOB, 'collector_exit_code': 0, 'collector_output_complete': True, 'collector_output_durable': True,
    'collector_final_stdout_after_final_full_recheck_verified': True,
    'source_root': SOURCE, 'label': LABEL, 'nonce': NONCE,
    'archive_regular_members': 109, 'source_directories': 15, 'original_file_bytes': 6126794,
    'all_manifest_paths_bytes_sha256_and_full9_shapes_verified': True,
    'complete_directory_child_sets_match_manifest': True, 'all_109_members_extracted_without_execution': True,
    'local_extraction_does_not_reproduce_original_filesystem_metadata': True,
    'original_failed_state_preserved': failure['state'], 'original_host_phases': phase_proofs,
    'case_pass': False, 'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
    'download_native_binary_read_calls': 31, 'download_maximum_concurrency': 4,
    'all_chunks_pinned_to_first_version_per_file': True, 'no_tool_output_truncation': True,
    'downloader_remote_process_start_calls': 0, 'downloader_remote_view_calls': 0,
    'downloader_phone_calls': 0, 'downloader_P4_calls': 0, 'download_failures': [],
    'files': {name: desc(R / name) for name in FILES},
    'controller_originals': [desc(R / name) for name in ('CONTROLLER-REQUEST.json', 'CONTROLLER-START.tool.json', 'CONTROLLER-STATUS.tool.json', 'CONTROLLER-READ.tool.json', 'CONTROLLER-STDOUT.original', 'CONTROLLER-STDERR.original')],
    'download_result': desc(R / 'DOWNLOAD-RESULT.json'), 'binary_receipts': receipt_index,
    'verifier_source': desc(Path(__file__).resolve()),
}
put(R / 'LOCAL-COMPLETE-VERIFICATION.json', enc(verification))
put(R / 'BINARY-READ-RECEIPT-INDEX.json', enc({'schema': 'hepta.fixed19.root02-binary-read-receipt-index.v1',
    'raw_MCP_receipts': 31, 'verified_chunks': 31, 'files': {name: desc(R / name) for name in FILES},
    'versions': [desc(R / 'versions' / (name + '.json')) for name in FILES], 'receipts': receipt_index}))
print(json.dumps({'state': verification['state'], 'verification': desc(R / 'LOCAL-COMPLETE-VERIFICATION.json'),
    'receipt_index': desc(R / 'BINARY-READ-RECEIPT-INDEX.json'), 'archive': desc(R / 'ROOT-ORIGINALS.tar.xz'),
    'files': 109, 'directories': 15, 'bytes': 6126794, 'case_pass': False}, sort_keys=True))
