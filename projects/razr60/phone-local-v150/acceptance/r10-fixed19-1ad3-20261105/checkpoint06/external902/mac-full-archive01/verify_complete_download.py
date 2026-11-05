#!/usr/bin/env python3
"""Verify fixed external902 native downloads and original records; execute no archived code."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import io
import json
import lzma
import stat
import tarfile

R = Path(__file__).resolve().parent
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
REMOTE = B + '/root-fixed19-1ad3-20261105-r1/external902-7c907661-mac-originals01'
SOURCE = B + '/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01'
JOB = '1a1abb10570-fc05-4fca'
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
FILES = {
    'EXTERNAL902-ORIGINALS.tar.xz': (1796220, '55934b9f1fefecd4f1f30c677920935fc527a08e0a218138024b5d0230d88ffc'),
    'ORIGINALS-MANIFEST.json': (263330, '06b153ea42ec72dfbc9c9d51a9b2b9e0c99815678484190c95bdeab76abd9966'),
    'RESULT.json': (4968, 'f59a539c21bf4c76d937f916b3ac777f1cf55aab121599a70c85ed535e7f61f2'),
    'COLLECTOR.original.py': (36689, '4ab7739134578d6ab641eeac07e9676721ca3c2967b29a2f5a2bb320c2041ebc'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def desc(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


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
assert download['verified_chunks'] == download['expected_chunks'] == 35 and download['failures'] == []
assembled, receipts = {}, []
for name, (size, digest) in FILES.items():
    version = json.loads((R / 'versions' / (name + '.json')).read_bytes())
    assert version['path'] == REMOTE + '/' + name and version['size'] == size and version['expected_sha256'] == digest
    parts = []
    for offset in range(0, size, 65536):
        stem = name + '.offset-' + str(offset).zfill(8)
        receipt_path = R / 'receipts' / (stem + '.MCP.original.json')
        verification_path = R / 'receipts' / (stem + '.VERIFIED.json')
        value = unwrap(receipt_path.read_bytes())
        raw = base64.b64decode(value['data_base64'], validate=True)
        length = min(65536, size - offset)
        assert value['path'] == version['path'] and value['version'] == version['version'] and value['size'] == size
        assert value['offset'] == offset and len(raw) == length and value['next_offset'] == offset + length
        assert value['eof'] is (offset + length == size) and value['chunk_sha256'] == sha(raw)
        chunk = R / 'chunks' / name / (str(offset).zfill(8) + '.bin')
        assert chunk.read_bytes() == raw
        verified = json.loads(verification_path.read_bytes())
        assert verified['raw_MCP_receipt'] == desc(receipt_path) and verified['chunk'] == desc(chunk)
        receipts.append({'name': name, 'offset': offset, 'version': version['version'],
            'raw_MCP_receipt': desc(receipt_path), 'verification': desc(verification_path), 'chunk': desc(chunk)})
        parts.append(raw)
    raw = b''.join(parts)
    assert (len(raw), sha(raw)) == (size, digest)
    assembled[name] = raw
assert len(receipts) == 35

manifest = json.loads(assembled['ORIGINALS-MANIFEST.json'])
result = json.loads(assembled['RESULT.json'])
assert manifest['state'] == 'EXACT_FAILED_CASE_AND_FIXED_SOURCE_ORIGINALS_READ_ONLY_BYTE_COPY'
assert result['state'] == 'FAILED_EXTERNAL_CASE_AND_PINNED_SOURCE_ORIGINALS_ARCHIVED'
for value in (manifest, result):
    assert value['case_source_root'] == SOURCE and value['label'] == 'root-r10-neg01-7c907661-01'
    assert value['nonce'] == '902e851c3ca1f90deab3d880ab993774'
    assert value['case_original_files'] == 199 and value['total_original_files'] == 239
    assert value['observed_directories'] == 36 and value['total_original_file_bytes'] == 8368292
    assert value['case_pass'] is False and value['component_qualified'] is False and value['business_qualified'] is False
    assert value['same_instant_as_failure'] is False and value['atomic_filesystem_snapshot'] is False
    assert value['originals_modified'] is False and value['phone_calls'] == value['p4_calls'] == value['subprocesses'] == value['signals_sent'] == 0
    for key, name in [('archive', 'EXTERNAL902-ORIGINALS.tar.xz'), ('collector_source', 'COLLECTOR.original.py')]:
        assert value[key]['path'] == REMOTE + '/' + name
        assert (value[key]['bytes'], value[key]['sha256']) == FILES[name]
assert (result['manifest']['bytes'], result['manifest']['sha256']) == FILES['ORIGINALS-MANIFEST.json']
plain = lzma.decompress(assembled['EXTERNAL902-ORIGINALS.tar.xz'])
assert len(plain) == manifest['tar_plaintext']['bytes'] and sha(plain) == manifest['tar_plaintext']['sha256']
members = {}
with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
    for member in archive.getmembers():
        assert member.isfile() and not member.issym() and not member.islnk()
        name = str(safe(member.name))
        assert name not in members
        raw = archive.extractfile(member).read()
        assert len(raw) == member.size
        members[name] = raw
assert len(members) == manifest['archive_regular_members'] == 239
assert sum(map(len, members.values())) == 8368292
file_rows = {}
for row in manifest['files']:
    name = str(safe(row['archive_member']))
    assert name not in file_rows
    raw = members[name]
    assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
    assert len(row['metadata']) == 9 and all(type(x) is int for x in row['metadata'])
    assert stat.S_ISREG(row['metadata'][2]) and row['metadata'][5] == 1 and row['metadata'][6] == len(raw)
    file_rows[name] = row
assert set(file_rows) == set(members)
roots = manifest['complete_source_roots']
assert roots['root-originals'] == SOURCE and set(roots) == {'root-originals', 'runtime-originals', 'root-source-originals'}
for name, row in file_rows.items():
    prefix, _, relative = name.partition('/')
    if prefix in roots:
        assert row['path'] == roots[prefix] + '/' + relative
    else:
        assert {key: row[key] for key in ('path', 'bytes', 'sha256')} == manifest['additional_fixed_files'][name]
complete_dirs, aux_dirs = {}, []
for row in manifest['directories']:
    assert len(row['metadata']) == 9 and all(type(x) is int for x in row['metadata'])
    assert stat.S_ISDIR(row['metadata'][2]) and row['names'] == sorted(set(row['names']))
    if row['scope'] == 'complete_tree':
        name = str(safe(row['archive_prefix']))
        assert name not in complete_dirs
        prefix, _, relative = name.partition('/')
        assert row['path'] == roots[prefix] + ('/' + relative if relative else '')
        complete_dirs[name] = row
    else:
        assert row['scope'] == 'parent_identity_and_child_names_only_not_all_child_contents' and row['archive_prefix'] is None
        aux_dirs.append(row)
assert len(complete_dirs) + len(aux_dirs) == 36
paths = set(file_rows) | set(complete_dirs)
for name, row in complete_dirs.items():
    children = sorted(PurePosixPath(path).name for path in paths if str(PurePosixPath(path).parent) == name)
    assert children == row['names']

source_proofs = []
for prefix, filename, expected_count, expected_pin in [
        ('runtime-originals', 'MANIFEST.json', 32, (16808, '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb')),
        ('root-source-originals', 'SOURCE-MANIFEST.json', 3, (11894, 'f865ae8b2edaf8c8f3076fc299796b953f66af7f848042b68932d76aaaab67c6'))]:
    raw = members[prefix + '/' + filename]
    assert (len(raw), sha(raw)) == expected_pin
    value = json.loads(raw)
    assert len(value['files']) == expected_count
    expected = {prefix + '/' + filename}
    for pin in value['files']:
        name = prefix + '/' + str(safe(pin['path']))
        assert name not in expected
        expected.add(name)
        assert (len(members[name]), sha(members[name])) == (pin['bytes'], pin['sha256'])
    assert {name for name in members if name.startswith(prefix + '/')} == expected
    source_proofs.append({'prefix': prefix, 'declared_members': expected_count, 'manifest_sha256': expected_pin[1], 'all_member_hashes_match': True})

failure_raw = members['root-originals/ROOT-FAILURE.json']
assert (len(failure_raw), sha(failure_raw)) == (20867, '25f7bca3dfd2f10308e2d430704db54e393c12bd0add116065ff8666be85320b')
failure = json.loads(failure_raw)
assert failure['state'] == 'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
assert len(failure['steps']) == 19 and len(failure['host_cleanup']['host_children']) == 1
phase_proofs = []
for step in failure['steps']:
    prefix = 'root-originals/' + step['phase'] + '/'
    capture = json.loads(members[prefix + 'OUTPUT-CAPTURE.json'])
    child = json.loads(members[prefix + 'CHILD.json'])
    assert json.loads(members[prefix + 'RESULT.json']) == step
    assert step['state'] == 'ORIGINAL_HOST_CHILD_JOINED' and step['returncode'] == 0
    assert capture['pid'] == child['pid'] == step['pid']
    assert capture['source_intent_sha256'] == child['source_intent_sha256'] == sha(members[prefix + 'INTENT.json'])
    assert capture['worker_joined'] is True and capture['child_wait_returned'] is True and capture['child_returncode'] == 0
    assert capture['stdout_eof'] is True and capture['stderr_eof'] is True and capture['prefix_only_or_unknown'] is False
    for stream in ('stdout', 'stderr'):
        key = prefix + stream + '.original'
        row, raw = file_rows[key], members[key]
        exact = {name: row[name] for name in ('path', 'bytes', 'sha256')}
        held = capture['files'][stream]
        assert step[stream] == exact and {name: held[name] for name in exact} == exact
        assert held['original_created_inode_bound'] is True and [held['metadata'][name] for name in META] == row['metadata']
        assert capture['captured'][stream] == {'bytes': len(raw), 'sha256': sha(raw)}
    phase_proofs.append({'phase': step['phase'], 'pid': step['pid'], 'original_joined_rc': 0, 'original_both_EOFs': True})
unknown = failure['host_cleanup']['host_children'][0]
assert unknown['phase'] == 'sender-execute' and unknown['pid'] == 54589
assert unknown['state'] == 'OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY' and unknown['returncode'] is None
capture = json.loads(members['root-originals/sender-execute/OUTPUT-CAPTURE.json'])
assert enc(capture) == enc(unknown['output_capture'])
assert capture['child_wait_returned'] is False and capture['child_returncode'] is None
assert capture['stdout_eof'] is False and capture['stderr_eof'] is False and capture['prefix_only_or_unknown'] is True
assert capture['remote_terminal_or_cleanup_proven'] is False
for stream in ('stdout', 'stderr'):
    key = 'root-originals/sender-execute/' + stream + '.original'
    assert members[key] == b''
    held = capture['files'][stream]
    assert [held['metadata'][name] for name in META] == file_rows[key]['metadata']
    assert {name: held[name] for name in ('path', 'bytes', 'sha256')} == {name: file_rows[key][name] for name in ('path', 'bytes', 'sha256')}

status = unwrap((R / 'CONTROLLER-STATUS.tool.json').read_bytes())
readback = unwrap((R / 'CONTROLLER-READ.tool.json').read_bytes())
assert status['job_id'] == readback['job_id'] == JOB and status['exit_code'] == 0
assert status['state'] == 'succeeded' and status['output_complete'] is True and status['output_durable'] is True
assert status['terminal_publication_confirmed'] is True and status['timed_out'] is False
streams = {}
for stream, size in [('stdout', 2073), ('stderr', 0)]:
    row = readback[stream]
    raw = bytes.fromhex(row['bytes_hex'])
    assert row['text'].encode() == raw and len(raw) == row['size'] == row['next_offset'] == size
    assert row['offset'] == 0 and row['eof'] is True
    assert status['log_bytes'][stream] == {'seen': size, 'stored': size}
    assert status['log_synced'][stream] is True and status['log_truncated'][stream] is False and status['log_errors'][stream] is None
    streams[stream] = raw
final = json.loads(streams['stdout'])
assert final['state'] == result['state'] and final['case_pass'] is False
assert final['last_full_recheck']['checked_file_count'] == 239 and final['last_full_recheck']['checked_directory_count'] == 36
assert final['last_full_recheck']['completed_unix_ns'] >= result['after_copy_full_recheck']['completed_unix_ns']
for key, name in [('archive', 'EXTERNAL902-ORIGINALS.tar.xz'), ('manifest', 'ORIGINALS-MANIFEST.json'), ('result', 'RESULT.json')]:
    assert final[key]['path'] == REMOTE + '/' + name
    assert (final[key]['bytes'], final[key]['sha256']) == FILES[name]

for name, raw in assembled.items():
    put(R / name, raw)
for name, raw in members.items():
    put(R / 'extracted' / name, raw)
for stream, raw in streams.items():
    put(R / ('CONTROLLER-' + stream.upper() + '.original'), raw)
proof = {'schema': 'hepta.external902.complete-mac-original-download-verification.v1',
    'state': 'FOUR_EXACT_ARTIFACTS_239_MEMBERS_AND_ACTUAL_FINAL_CONTROLLER_VERIFIED',
    'collector_job': JOB, 'collector_exit_code': 0, 'collector_complete_durable_final_stdout_verified': True,
    'regular_archive_members': 239, 'case_original_members': 199, 'source_file_bytes': 8368292,
    'observed_directories': 36, 'complete_tree_directories': len(complete_dirs), 'fixed_parent_name_only_directories': len(aux_dirs),
    'all_member_hashes_and_full9_shapes_verified': True, 'complete_tree_child_sets_match': True,
    'fixed_source_packages': source_proofs, 'original_joined_host_phases': phase_proofs,
    'sender54589_original_parent_joined': False, 'sender54589_original_stdout_eof': False,
    'sender54589_original_stderr_eof': False, 'sender54589_original_remote_cleanup_proven': False,
    'later_sender_top_result_does_not_retrofit_parent_observation': True,
    'actor_py_not_in_this_fixed_collection_scope': True, 'full_native_closure_or_boundary_publication_proven': False,
    'case_pass': False, 'original_failed_state_preserved': failure['state'],
    'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
    'local_extraction_does_not_reproduce_original_metadata': True,
    'native_binary_read_calls': 35, 'maximum_parallel_reads': 4, 'all_chunks_first_version_pinned': True,
    'download_failures': [], 'tool_output_truncation': False, 'downloader_process_start_calls': 0,
    'downloader_view_calls': 0, 'downloader_P4_calls': 0, 'downloader_phone_calls': 0,
    'files': {name: desc(R / name) for name in FILES}, 'binary_receipts': receipts,
    'controller_originals': [desc(R / name) for name in ('CONTROLLER-REQUEST.json', 'CONTROLLER-START.tool.json', 'CONTROLLER-STATUS.tool.json', 'CONTROLLER-READ.tool.json', 'CONTROLLER-STDOUT.original', 'CONTROLLER-STDERR.original')],
    'download_result': desc(R / 'DOWNLOAD-RESULT.json'), 'verifier_source': desc(Path(__file__).resolve())}
put(R / 'LOCAL-COMPLETE-VERIFICATION.json', enc(proof))
put(R / 'BINARY-READ-RECEIPT-INDEX.json', enc({'schema': 'hepta.external902.binary-read-receipt-index.v1',
    'raw_MCP_receipts': 35, 'verified_chunks': 35, 'files': {name: desc(R / name) for name in FILES},
    'versions': [desc(R / 'versions' / (name + '.json')) for name in FILES], 'receipts': receipts}))
print(json.dumps({'state': proof['state'], 'verification': desc(R / 'LOCAL-COMPLETE-VERIFICATION.json'),
    'receipt_index': desc(R / 'BINARY-READ-RECEIPT-INDEX.json'), 'archive': desc(R / 'EXTERNAL902-ORIGINALS.tar.xz'),
    'files': 239, 'case_files': 199, 'source_bytes': 8368292, 'case_pass': False}, sort_keys=True))
