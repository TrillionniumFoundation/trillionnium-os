#!/usr/bin/env python3
"""Verify downloaded fixed P4 originals and controller completion; execute no retained source."""
from pathlib import Path, PurePosixPath
import ast
import base64
import gzip
import hashlib
import io
import json
import lzma
import stat
import tarfile

R = Path(__file__).resolve().parent
REMOTE = '/home/alex/codex-hepta-external902-7c907661-originals-1ad3-01'
JOB = '1a1abc71a1f-fc05-5077'
LABEL = 'root-r10-neg01-7c907661-01'
NONCE = '902e851c3ca1f90deab3d880ab993774'
FILES = {
    'RESULT.json': (5213, '3b1244bc603f33599fd739e141df5c546deacc4eeadf7be837f9a553c0edf857'),
    'COLLECTOR.original.py': (40752, 'c1e5867be5cb2f03efb9b41d01c26097309adb7f9b7fd4a95f48a36b7fefe34d'),
    'ORIGINALS-MANIFEST.json': (147912, '99b413337849ebe3c2b89dece5c65dacd396d05d2d39abee5cde84d71c1e6e6e'),
    'EXTERNAL902-P4-ORIGINALS.tar.xz': (820660, 'ab778aa6c6f45b33f8b1d4af11be68f7d33306af0a40492c1738556af2100a8d'),
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
    assert type(name) is str and name and not path.is_absolute() and str(path) == name and '\0' not in name
    assert all(part not in ('', '.', '..') for part in path.parts)
    return path


def tar_members(raw, maximum):
    assert len(raw) <= maximum
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            assert member.isfile() and not member.issym() and not member.islnk()
            name = str(safe(member.name))
            assert name not in members and 0 <= member.size <= maximum
            body = archive.extractfile(member).read()
            assert len(body) == member.size
            members[name] = body
    return members


# Preserve the failed synchronous attempt; complete it only from fixed-version
# direct prefix chunks and independently verified immutable operation payloads.
import importlib.util
import sys
sys.dont_write_bytecode = True
segment_verifier_path = R.parent / 'persistent_binary_result_verify.py'
segment_verifier_raw = segment_verifier_path.read_bytes()
assert (len(segment_verifier_raw), sha(segment_verifier_raw)) == (
    10729, '90cc878b6ab605bf64501a595166ecd6b6bd211933a371a798a9d33fabb20859')
spec = importlib.util.spec_from_file_location('local_retained_binary_result_verifier', segment_verifier_path)
segment_verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(segment_verifier)
download = json.loads((R / 'DOWNLOAD-RESULT.json').read_bytes())
assert download['state'] == 'DOWNLOAD_INCOMPLETE_ERRORS_PRESERVED'
assert download['maximum_parallel_reads'] == 1 and download['limit'] == 32768
assembled, receipts, versions, persistent_proofs = {}, [], {}, []
for name, (size, digest) in FILES.items():
    version = json.loads((R / 'versions' / (name + '.json')).read_bytes())
    assert version['path'] == REMOTE + '/' + name and version['size'] == size and version['expected_sha256'] == digest
    versions[name] = version['version']
    parts = []
    direct_end = 491520 if name == 'EXTERNAL902-P4-ORIGINALS.tar.xz' else size
    for offset in range(0, direct_end, 32768):
        stem = name + '.offset-' + str(offset).zfill(8)
        receipt_path = R / 'receipts' / (stem + '.MCP.original.json')
        verification_path = R / 'receipts' / (stem + '.VERIFIED.json')
        value = unwrap(receipt_path.read_bytes())
        body = base64.b64decode(value['data_base64'], validate=True)
        length = min(32768, size - offset)
        assert value['path'] == version['path'] and value['version'] == version['version'] and value['size'] == size
        assert value['offset'] == offset and len(body) == length and value['next_offset'] == offset + length
        assert value['eof'] is (offset + length == size) and value['chunk_sha256'] == sha(body)
        chunk = R / 'chunks' / name / (str(offset).zfill(8) + '.bin')
        assert chunk.read_bytes() == body
        checked = json.loads(verification_path.read_bytes())
        assert checked['raw_MCP_receipt'] == desc(receipt_path) and checked['chunk'] == desc(chunk)
        receipts.append({'kind': 'direct_native_binary_result', 'file': name, 'offset': offset,
            'version': version['version'], 'raw_MCP_receipt': desc(receipt_path),
            'verification': desc(verification_path), 'chunk': desc(chunk)})
        parts.append(body)
    if name == 'EXTERNAL902-P4-ORIGINALS.tar.xz':
        for offset in (491520, 557056, 622592, 688128, 753664, 819200):
            segment = R / 'persistent-read01' / ('segment-' + str(offset).zfill(8))
            body, proof = segment_verifier.verify(segment, write_outputs=False)
            assert proof['native_file'] == {'path': version['path'], 'bytes': size,
                'expected_sha256': digest, 'version': version['version']}
            assert proof['native_chunk'] == {'offset': offset, 'bytes': min(65536, size-offset),
                'sha256': sha(body), 'next_offset': min(offset+65536, size),
                'eof': min(offset+65536, size) == size}
            request = json.loads((segment / 'REQUEST.json').read_bytes())
            assert request['operation']['arguments']['limit'] == min(65536, size-offset)
            assert (segment / 'NATIVE-CHUNK.bin').read_bytes() == body
            assert json.loads((segment / 'SEGMENT-VERIFICATION.json').read_bytes()) == proof
            receipts.append({'kind': 'persistent_operation_original_native_sdk_payload', 'file': name,
                'offset': offset, 'version': version['version'],
                'verification': desc(segment / 'SEGMENT-VERIFICATION.json'),
                'chunk': desc(segment / 'NATIVE-CHUNK.bin'),
                'sdk_payload': desc(segment / 'SDK-PAYLOAD.original.json'),
                'native_binary_original': desc(segment / 'NATIVE-BINARY-READ.original.json')})
            persistent_proofs.append(proof)
            parts.append(body)
    raw = b''.join(parts)
    assert (len(raw), sha(raw)) == (size, digest)
    assembled[name] = raw
assert len(receipts) == 29 and len(persistent_proofs) == 6
failed_original = R / 'receipts' / 'EXTERNAL902-P4-ORIGINALS.tar.xz.offset-00491520.MCP.original.json'
assert json.loads(failed_original.read_bytes()).get('isError') is True
error_receipts = [desc(failed_original)] + [row for proof in persistent_proofs for row in proof['error_receipts_preserved']]
persistent_originals = [desc(path) for path in sorted((R / 'persistent-read01').glob('segment-*/*.MCP.original.json'))]

source = assembled['COLLECTOR.original.py'].decode()
source_tree = ast.parse(source)
wanted = {'LABEL', 'NONCE', 'FIXED_TREES', 'MATERIAL_FILES', 'ADDITIONAL_FIXED_FILES', 'SETUP_TERMINAL', 'RUNTIME_MANIFEST_SHA'}
constants = {node.targets[0].id: ast.literal_eval(node.value) for node in source_tree.body
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted}
assert set(constants) == wanted and constants['LABEL'] == LABEL and constants['NONCE'] == NONCE
manifest = json.loads(assembled['ORIGINALS-MANIFEST.json'])
result = json.loads(assembled['RESULT.json'])
counts = {'sender-originals': 116, 'setup-fixture-originals': 55, 'material-originals': 56}
assert manifest['state'] == 'EXACT_THREE_P4_TREES_AND_PINNED_SIBLING_ORIGINALS_READ_ONLY_BYTE_COPY'
assert result['state'] == 'EXTERNAL902_THREE_P4_TREES_AND_PINNED_SIBLING_ORIGINALS_ARCHIVED'
for value in (manifest, result):
    assert value['label'] == LABEL and value['nonce'] == NONCE
    assert value['complete_source_roots'] == constants['FIXED_TREES']
    assert value['additional_fixed_files'] == constants['ADDITIONAL_FIXED_FILES']
    assert value['complete_tree_file_counts'] == counts and value['fixed_sibling_file_count'] == 8
    assert value['total_original_files'] == 235 and value['observed_directories'] == 12
    assert value['total_original_file_bytes'] == 5925299
    assert value['case_pass'] is False and value['component_qualified'] is False and value['business_qualified'] is False
    assert value['same_instant_as_failure'] is False and value['atomic_filesystem_snapshot'] is False
    assert value['originals_modified'] is False and value['process_census_performed'] is False
    assert value['phone_calls'] == value['subprocesses'] == value['network_calls'] == value['signals_sent'] == 0
    assert value['mac_actor_py_in_this_archive'] is False
    for key, name in [('archive', 'EXTERNAL902-P4-ORIGINALS.tar.xz'), ('collector_source', 'COLLECTOR.original.py')]:
        row = value[key]
        assert row['path'] == REMOTE + '/' + name and (row['bytes'], row['sha256']) == FILES[name]
assert result['original_mac_sender_pid'] == 54589 and result['original_sender_join_or_EOF_retrofitted'] is False
assert result['native_cleanup_or_boundary_publication_verified_here'] is False
assert (result['manifest']['bytes'], result['manifest']['sha256']) == FILES['ORIGINALS-MANIFEST.json']
plain = lzma.decompress(assembled['EXTERNAL902-P4-ORIGINALS.tar.xz'])
assert len(plain) == manifest['tar_plaintext']['bytes'] and sha(plain) == manifest['tar_plaintext']['sha256']
members = tar_members(plain, 68 * 1024 * 1024)
assert len(members) == manifest['archive_regular_members'] == 235 and sum(map(len, members.values())) == 5925299
file_rows = {}
for row in manifest['files']:
    name = str(safe(row['archive_member']))
    assert name not in file_rows
    raw = members[name]
    assert (len(raw), sha(raw)) == (row['bytes'], row['sha256'])
    meta = row['metadata']
    assert len(meta) == 9 and all(type(x) is int for x in meta)
    assert stat.S_ISREG(meta[2]) and meta[5] == 1 and meta[6] == len(raw)
    file_rows[name] = row
assert set(file_rows) == set(members)
roots = constants['FIXED_TREES']
assert {prefix: sum(name.startswith(prefix + '/') for name in members) for prefix in roots} == counts
for name, row in file_rows.items():
    prefix, _, relative = name.partition('/')
    if prefix in roots:
        assert row['path'] == roots[prefix] + '/' + relative
    else:
        assert {key: row[key] for key in ('path', 'bytes', 'sha256')} == constants['ADDITIONAL_FIXED_FILES'][name]
assert len(set(file_rows) - {name for name in file_rows if name.partition('/')[0] in roots}) == 8
complete_dirs, aux_dirs = {}, []
for row in manifest['directories']:
    meta = row['metadata']
    assert len(meta) == 9 and all(type(x) is int for x in meta) and stat.S_ISDIR(meta[2])
    assert row['names'] == sorted(set(row['names']))
    if row['scope'] == 'complete_tree':
        name = str(safe(row['archive_prefix']))
        assert name not in complete_dirs
        prefix, _, relative = name.partition('/')
        assert row['path'] == roots[prefix] + ('/' + relative if relative else '')
        complete_dirs[name] = row
    else:
        assert row['scope'] == 'parent_identity_and_child_names_only_not_all_child_contents' and row['archive_prefix'] is None
        aux_dirs.append(row)
assert len(complete_dirs) + len(aux_dirs) == 12
paths = set(file_rows) | set(complete_dirs)
for name, row in complete_dirs.items():
    assert sorted(PurePosixPath(path).name for path in paths if str(PurePosixPath(path).parent) == name) == row['names']
for name, pin in constants['ADDITIONAL_FIXED_FILES'].items():
    parents = [row for row in aux_dirs if row['path'] == str(PurePosixPath(pin['path']).parent)]
    assert len(parents) == 1 and PurePosixPath(pin['path']).name in parents[0]['names']

assert len(constants['MATERIAL_FILES']) == 56
for name, pin in constants['MATERIAL_FILES'].items():
    row = file_rows['material-originals/' + name]
    assert {key: row[key] for key in ('path', 'bytes', 'sha256')} == pin
component_gzip = members['sibling-input-originals/component-inputs.tar.gz']
assert (len(component_gzip), sha(component_gzip)) == (471979, '989a78d8c9a844ea0f06859a9e9e2b66bafeacd4702a9b8388d6a031b7775afb')
component_members = tar_members(gzip.decompress(component_gzip), 16 * 1024 * 1024)
assert len(component_members) == 56
assert {'material-originals/tree/' + name: raw for name, raw in component_members.items()} == {
    name: raw for name, raw in members.items() if name.startswith('material-originals/')}
runtime_raw = component_members['package/MANIFEST.json']
assert (len(runtime_raw), sha(runtime_raw)) == (16808, constants['RUNTIME_MANIFEST_SHA'])
runtime = json.loads(runtime_raw)
assert len(runtime['files']) == 32
expected_package = {'package/MANIFEST.json'}
for pin in runtime['files']:
    name = 'package/' + str(safe(pin['path']))
    assert name not in expected_package
    expected_package.add(name)
    assert (len(component_members[name]), sha(component_members[name])) == (pin['bytes'], pin['sha256'])
assert {name for name in component_members if name.startswith('package/')} == expected_package
lease = json.loads(component_members['LEASE.json'])
contract = json.loads(component_members['sender-contract.json'])
assert lease['label'] == contract['label'] == LABEL and lease['nonce'] == contract['nonce'] == NONCE
assert lease['package_sha256'] == contract['package_sha256'] == constants['RUNTIME_MANIFEST_SHA']
terminal_raw = members['setup-fixture-originals/HOST-TERMINAL.json']
assert (len(terminal_raw), sha(terminal_raw)) == (24411, '82b4faebc69bae4d2e917af81300d82483f0183b7d3f357aa594c57cd6926ff6')
sender_names = {name[len('sender-originals/'):] for name in members if name.startswith('sender-originals/')}
assert {'SEND.once.json', 'SEND.MONOTONIC-INTENT.json', 'SEND.MONOTONIC-WINDOW.json', 'SEND-NATIVE-LATENCY.json'} <= sender_names
sender_branch = sender_names & {'SEND.result.json', 'SEND.unknown.json'}
assert len(sender_branch) == 1

request = json.loads((R / 'CONTROLLER-REQUEST.json').read_bytes())
start = unwrap((R / 'CONTROLLER-START.json').read_bytes())
status = unwrap((R / 'CONTROLLER-STATUS.json').read_bytes())
readback = unwrap((R / 'CONTROLLER-READ.json').read_bytes())
assert request['stdin'].encode() == assembled['COLLECTOR.original.py']
assert request['host'] == start['job']['host'] == 'pocket4' and request['executable'] == start['job']['executable'] == '/usr/bin/python3'
assert request['args'] == start['job']['args'] and request['cwd'] == start['job']['cwd'] == '/home/alex'
assert request['idempotency_key'] == start['job']['idempotency_key'] == 'root-1ad3-external902-p4-originals01-20261105'
assert start['job']['id'] == status['job_id'] == readback['job_id'] == JOB
assert status['state'] == 'succeeded' and status['exit_code'] == 0 and status['timed_out'] is False and status['cancelled'] is False
assert status['output_complete'] is True and status['output_durable'] is True and status['terminal_publication_confirmed'] is True
streams = {}
for stream, size in [('stdout', 1920), ('stderr', 0)]:
    row = readback[stream]
    raw = bytes.fromhex(row['bytes_hex'])
    assert row['text'].encode() == raw and len(raw) == row['size'] == row['next_offset'] == size
    assert row['offset'] == 0 and row['eof'] is True
    assert status['log_bytes'][stream] == {'seen': size, 'stored': size}
    assert status['log_synced'][stream] is True and status['log_truncated'][stream] is False and status['log_errors'][stream] is None
    streams[stream] = raw
final = json.loads(streams['stdout'])
assert final['state'] == result['state'] and final['case_pass'] is False
assert final['complete_tree_file_counts'] == counts and final['fixed_sibling_file_count'] == 8
assert final['total_original_files'] == 235 and final['total_original_file_bytes'] == 5925299
last = final['last_full_recheck']
for observed in (manifest['first_full_recheck'], result['after_copy_full_recheck'], last):
    assert observed['checked_file_count'] == 235 and observed['checked_directory_count'] == 12
assert manifest['started_unix_ns'] <= manifest['first_full_recheck']['completed_unix_ns'] <= result['after_copy_full_recheck']['completed_unix_ns'] <= last['completed_unix_ns']
assert manifest['first_full_recheck']['completed_monotonic_ns'] <= result['after_copy_full_recheck']['completed_monotonic_ns'] <= last['completed_monotonic_ns']
artifact_rows = {'COLLECTOR.original.py': result['collector_source']}
for key, name in [('archive', 'EXTERNAL902-P4-ORIGINALS.tar.xz'), ('manifest', 'ORIGINALS-MANIFEST.json'), ('result', 'RESULT.json')]:
    row = final[key]
    assert row['path'] == REMOTE + '/' + name and (row['bytes'], row['sha256']) == FILES[name]
    artifact_rows[name] = row
for name, row in artifact_rows.items():
    meta = row['metadata']
    assert [int(x) for x in versions[name].split(':')] == [meta[0], meta[1], meta[6], meta[7], meta[8]]

for name, raw in assembled.items():
    put(R / name, raw)
for name, raw in members.items():
    put(R / 'extracted' / name, raw)
for stream, raw in streams.items():
    put(R / ('CONTROLLER-' + stream.upper() + '.original'), raw)
proof = {'schema': 'hepta.external902.complete-p4-original-download-verification.v1',
    'state': 'FOUR_EXACT_ARTIFACTS_235_MEMBERS_AND_ACTUAL_FINAL_CONTROLLER_VERIFIED',
    'collector_job': JOB, 'collector_exit_code': 0, 'collector_complete_durable_final_stdout_verified': True,
    'regular_archive_members': 235, 'total_original_file_bytes': 5925299,
    'complete_tree_file_counts': counts, 'fixed_sibling_file_count': 8,
    'observed_directories': 12, 'complete_tree_directories': len(complete_dirs), 'fixed_parent_name_only_directories': len(aux_dirs),
    'all_member_hashes_and_full9_shapes_verified': True, 'complete_tree_child_sets_match': True,
    'all_three_bookends_match_counts_and_order': True, 'artifact_versions_match_created_output_full9': True,
    'component_gzip_whole_sha_and_all56_bytes_match_material': True,
    'runtime_32_sources_exactly_match_original_manifest': constants['RUNTIME_MANIFEST_SHA'],
    'sender_result_branch_retained': sorted(sender_branch)[0], 'setup_original_terminal_sha256': sha(terminal_raw),
    'sender54589_original_parent_joined': False, 'sender54589_original_stdout_eof': False,
    'sender54589_original_stderr_eof': False, 'later_P4_records_do_not_retrofit_original_parent_observation': True,
    'mac_actor_py_not_in_this_fixed_P4_scope': True, 'native_cleanup_or_boundary_publication_verified': False,
    'case_pass': False, 'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
    'local_extraction_does_not_reproduce_original_metadata': True,
    'direct_successful_native_chunks': 23, 'completed_retained_native_operations': 6,
    'verified_payload_chunks': 29, 'maximum_parallel_native_operations': 1,
    'direct_chunk_limit': 32768, 'persistent_native_chunk_limit': 65536,
    'result_page_maximum_authorized_bytes': 16384, 'result_page_maximum_authorized_parallel': 4,
    'all_chunks_first_version_pinned': True, 'download_failures_preserved': error_receipts,
    'prior_timeouts_do_not_prove_native_nonexecution': True, 'tool_output_truncation': False,
    'downloader_process_start_calls': 0, 'downloader_view_calls': 0, 'downloader_phone_calls': 0,
    'retained_source_imported_or_executed': False,
    'files': {name: desc(R / name) for name in FILES}, 'binary_receipts': receipts,
    'controller_originals': [desc(R / name) for name in ('CONTROLLER-REQUEST.json', 'CONTROLLER-START.json', 'CONTROLLER-STATUS.json', 'CONTROLLER-READ.json', 'CONTROLLER-STDOUT.original', 'CONTROLLER-STDERR.original')],
    'download_result': desc(R / 'DOWNLOAD-RESULT.json'),
    'persistent_operation_originals': persistent_originals,
    'persistent_segment_verifier': desc(segment_verifier_path),
    'original_full_verifier': desc(R / 'verify_complete_download.py'),
    'verifier_source': desc(Path(__file__).resolve())}
put(R / 'LOCAL-COMPLETE-VERIFICATION.json', enc(proof))
put(R / 'BINARY-READ-RECEIPT-INDEX.json', enc({'schema': 'hepta.external902-p4.binary-read-receipt-index.v1',
    'direct_successful_native_receipts': 23, 'completed_retained_native_operations': 6,
    'verified_payload_chunks': 29, 'error_receipts_preserved': error_receipts,
    'persistent_operation_originals': persistent_originals,
    'files': {name: desc(R / name) for name in FILES},
    'versions': [desc(R / 'versions' / (name + '.json')) for name in FILES], 'receipts': receipts}))
print(json.dumps({'state': proof['state'], 'verification': desc(R / 'LOCAL-COMPLETE-VERIFICATION.json'),
    'receipt_index': desc(R / 'BINARY-READ-RECEIPT-INDEX.json'),
    'archive': desc(R / 'EXTERNAL902-P4-ORIGINALS.tar.xz'), 'files': 235, 'source_bytes': 5925299,
    'case_pass': False}, sort_keys=True))
