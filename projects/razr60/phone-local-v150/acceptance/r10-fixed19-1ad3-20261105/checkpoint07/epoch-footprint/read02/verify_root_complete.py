"""Independent local consumption of actual read02 receipts, bytes and references."""
import base64
import copy
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zlib

ROOT = Path('/workspace/scratch/1ad3d6f55439')
HERE = Path(__file__).parent
REMOTE = '/home/alex/razr60-local-model-v150/fixed19-root-1ad3-epoch-retained-footprint-read02'
VERSION = '66306:44336387:4531388:1793897324452756243:1793897324452756243'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            assert key not in value
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def inner(raw):
    value = strict(raw)
    assert not value.get('isError')
    assert len(value['content']) == 1 and value['content'][0]['type'] == 'text'
    return strict(value['content'][0]['text'])


download = strict((HERE / 'LOCAL-ARCHIVE-COMPLETE-VERIFICATION.json').read_bytes())
assert download['chunk_count'] == len(download['chunks']) == 70
parts = []; position = 0
for item in download['chunks']:
    receipt_raw = Path(item['tool_receipt']['path']).read_bytes()
    assert pin(receipt_raw) == {k: item['tool_receipt'][k] for k in ('bytes', 'sha256')}
    receipt = inner(receipt_raw)
    raw = base64.b64decode(receipt['data_base64'], validate=True)
    assert base64.b64encode(raw).decode() == receipt['data_base64']
    assert receipt['version'] == VERSION and receipt['size'] == 4531388
    assert receipt['path'] == REMOTE + '/FULL-ORIGINALS.tar.xz'
    assert receipt['offset'] == item['offset'] == position
    assert 0 < len(raw) <= 65536 and pin(raw)['sha256'] == receipt['chunk_sha256']
    position += len(raw)
    assert receipt['next_offset'] == item['next_offset'] == position
    assert receipt['eof'] is (position == 4531388)
    if item.get('request'):
        request_raw = Path(item['request']['path']).read_bytes()
        assert pin(request_raw) == {k: item['request'][k] for k in ('bytes', 'sha256')}
        request = strict(request_raw)
        assert request['host'] == 'pocket4' and request['path'] == receipt['path']
        assert request['expected_version'] == VERSION and request['offset'] == receipt['offset']
        assert 0 < request['limit'] <= 65536
    parts.append(raw)
archive = b''.join(parts)
assert pin(archive) == dict(bytes=4531388, sha256='d5982a434a6317ddf7b2503127d1581b0aa55d828096ed42e1a7b276af8f21ed')
assert archive == (HERE / 'FULL-ORIGINALS.tar.xz').read_bytes()
mfraw = (HERE / 'ARCHIVE-MANIFEST.json').read_bytes(); mf = strict(mfraw)
assert pin(mfraw) == dict(bytes=2436, sha256='f72805b724317aa4a8a60389e217cfc1c4f9aa6c54900bc8603c25d481da7251')
unpacker = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
tarraw = unpacker.decompress(archive, max_length=12083201)
assert unpacker.eof and not unpacker.unused_data and pin(tarraw) == mf['tar']
members = {}
with tarfile.open(fileobj=io.BytesIO(tarraw), mode='r:') as handle:
    for member in handle.getmembers():
        name = PurePosixPath(member.name)
        assert member.isfile() and not member.issym() and not member.islnk()
        assert not name.is_absolute() and '..' not in name.parts and str(name) == member.name
        assert member.name not in members
        members[member.name] = handle.extractfile(member).read()
assert len(members) == len(mf['files']) == 12
assert set(members) == {row['path'] for row in mf['files']}
for row in mf['files']:
    assert pin(members[row['path']]) == {k: row[k] for k in ('bytes', 'sha256')}
    assert members[row['path']] == (HERE / 'extracted' / row['path']).read_bytes()
stdout = members['PHONE-STDOUT.original']; report = strict(stdout)
assert pin(stdout) == dict(bytes=5908972, sha256='24c53a4c345d27cbbb2ba18852633eadc5c6a640b170c037d01b9e8e1f1c3e8c')
assert report['schema'] == 'hepta.native-guard.fixed-epoch-retained-footprint-observation.v2'
assert report['state'] == 'EXACT_FIXED_RETAINED_ORIGINALS_AND_CURRENT_ABSENCES_OBSERVED'
assert report['observation_complete'] is report['complete_raw_observation_retained'] is True
assert report['failure'] is None
assert report['owned_read_fd_observation'] == dict(complete=True, locks_acquired=0,
                                                  new_read_FDs_remaining=[], unknown_or_foreign_FDs_closed=False)
for key in ('case_pass', 'global_clearance_proof', 'future_input_authorization', 'epoch_initialized',
            'new_nonce_or_lease', 'native_case_qualified', 'atomic_global_snapshot_claimed'):
    assert report[key] is False
for key in ('phone_content_writes', 'runtime_modules_loaded', 'runtime_function_calls',
            'process_launches', 'endpoint_connections', 'signals', 'model_requests', 'native_sends'):
    assert type(report[key]) is int and report[key] == 0
packet = report['observations']
assert set(packet) == {'codec', 'packed', 'raw', 'data'} and packet['codec'] == 'zlib+base64'
packed = base64.b64decode(packet['data'], validate=True)
assert base64.b64encode(packed).decode() == packet['data'] and pin(packed) == packet['packed']
decoder = zlib.decompressobj()
raw = decoder.decompress(packed, 16*1024*1024+1)
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
assert pin(raw) == packet['raw'] == dict(bytes=9787061, sha256='7fa31c24fb0a00ccd26bd255dedfe11e4dd212a9cc2a11eeca30fcdf6dadf534')
assert raw == (HERE / 'OBSERVATIONS.decoded-original.json').read_bytes()
obs = strict(raw)
assert encoded(obs) == raw
footprint_raw = (ROOT / 'epoch_native_candidate01/footprint01/FOOTPRINT.json').read_bytes()
footprint = strict(footprint_raw)
assert pin(footprint_raw) == report['footprint_original']
expected = {row['path']: row for row in footprint['retained_directory_member_originals']}
leaves = {row['path']: row for row in footprint['fixed_control_leaves']}
entries = {row['path']: row for row in obs['entries']}
assert len(entries) == len(obs['entries']) == 146 and set(entries) == set(expected) | set(leaves)
for path, row in entries.items():
    m = row['metadata']
    assert type(m) is list and len(m) == 9 and all(type(n) is int for n in m)
    prior = expected.get(path, leaves.get(path))
    if path in expected:
        assert row['kind'] == prior['kind'] and m == prior['metadata']
        if 'selinux_raw_hex' in prior:
            assert row['selinux_raw_hex'] == prior['selinux_raw_hex']
        if row['kind'] == 'directory':
            assert row['names'] == prior['names']
    elif prior.get('historical_metadata') is not None:
        assert m == prior['historical_metadata']
    if row['kind'] == 'file':
        assert stat.S_ISREG(m[2]) and m[5] == 1 and m[6] == row['bytes']
        assert row['bytes'] == prior.get('bytes', prior.get('expected_bytes'))
        assert row['sha256'] == prior.get('sha256', prior.get('expected_sha256'))
    else:
        assert stat.S_ISDIR(m[2]) and row['names'] == sorted(set(row['names']))
bodies = {}
for item in obs['file_originals']:
    body = base64.b64decode(item['data_base64'], validate=True)
    assert base64.b64encode(body).decode() == item['data_base64']
    assert pin(body) == {k: item[k] for k in ('bytes', 'sha256')}
    assert pin(body) == {k: entries[item['path']][k] for k in ('bytes', 'sha256')}
    assert item['path'] not in bodies
    bodies[item['path']] = body
assert len(bodies) == 126 and sum(map(len, bodies.values())) == 7114062
assert set(bodies) == {path for path, row in entries.items() if row['kind'] == 'file'}
parents = obs['immediate_parent_observations']
assert len(parents) == len({row['path'] for row in parents}) == 22
absences = obs['positive_absence_observations']
wanted_absences = {row['path'] for row in footprint['absence_checks'] + footprint['new_control_roots']}
assert len(absences) == len(wanted_absences) == 65
assert {row['path'] for row in absences} == wanted_absences
reference_count = 0
for item in absences:
    assert item['state'] == 'POSITIVELY_OBSERVED_ENOENT' and item['absence_is_new_permission'] is False
    for which in ('first', 'final'):
        observed = item[which]; ref = observed['canonical_parent_observation']
        assert set(ref) == {'table', 'index', 'serialized_observation'}
        assert ref['table'] == 'immediate_parent_observations' and type(ref['index']) is int
        assert 0 <= ref['index'] < len(parents)
        parent = parents[ref['index']]
        assert pin(encoded(parent)) == ref['serialized_observation']
        assert parent['path'] == str(Path(item['path']).parent)
        assert Path(item['path']).name not in parent['names']
        assert observed['held_parent_enoent_observations'] == 2
        assert observed['reopened_parent_enoent_observations'] == 1
        assert observed['started_monotonic_ns'] <= observed['finished_monotonic_ns']
        reference_count += 1
    assert encoded(item['first']['canonical_parent_observation']) == encoded(item['final']['canonical_parent_observation'])
    assert item['first']['finished_monotonic_ns'] <= item['final']['started_monotonic_ns']
assert reference_count == 130
assert set(obs['read_bookends']) == set(entries)
for path, row in obs['read_bookends'].items():
    assert row['first']['started_monotonic_ns'] <= row['first']['finished_monotonic_ns']
    assert row['first']['finished_monotonic_ns'] <= row['final']['started_monotonic_ns'] <= row['final']['finished_monotonic_ns']
    assert row['both_reads_are_whole_bodies'] is (entries[path]['kind'] == 'file')
assert report['whole_file_reads'] == 252 and report['physical_read_bytes_charged'] == 14322260 < 16*1024*1024
assert report['object_operations'] == 1780 < 4096 and 0 < report['total_wall_seconds'] < 30
assert len(obs['canonical_ancestor_observations']) == 34
assert len(obs['actual_alias_checks']) == len(footprint['extra_alias_pairs']) == 2
for item, pair in zip(obs['actual_alias_checks'], footprint['extra_alias_pairs']):
    assert item['paths'] == pair and item['both_views_observed_and_charged'] is True
    assert all(entries[p]['metadata'] == item['metadata'] and entries[p]['names'] == item['names']
               and entries[p]['selinux_raw_hex'] == item['selinux_raw_hex'] for p in pair)
bridge = obs['fixed_proc_root_bridge']
assert encoded(bridge['first']['identity']) == encoded(bridge['final']['identity'])
assert bridge['first']['identity']['pid1_generation'] == [1, 0, 0, 0]
for which in ('first', 'final'):
    item = bridge[which]['pid1_stat_original']
    body = base64.b64decode(item['data_base64'], validate=True)
    assert pin(body) == {k: item[k] for k in ('bytes', 'sha256')}
    end = body.rfind(b')'); fields = body[end+2:].split()
    assert body[:end+1] == b'1 (init)' and int(fields[1]) == 0
    assert [1, int(fields[2]), int(fields[3]), int(fields[19])] == [1, 0, 0, 0]
    item = obs['boot_originals'][which]; body = base64.b64decode(item['data_base64'], validate=True)
    assert pin(body) == {k: item[k] for k in ('bytes', 'sha256')}
    assert body.decode().strip() == report['boot_id'] == 'f8019f83-20a7-4f18-bea1-51c980621e4d'
meta_obs = copy.deepcopy(obs)
for row in meta_obs['file_originals']:
    row['data_base64'] = ''
metadata_bytes = len(encoded(meta_obs))
assert metadata_bytes == 301485 < 524288

# This is an explicitly derived metadata projection. It has no pretend empty
# file bodies and is not relabeled as the original phone observation envelope.
projection = dict(schema='hepta.fixed19.retained-footprint-metadata-projection.v1',
                  state='DERIVED_FROM_COMPLETE_ACTUAL_READ02_ORIGINALS',
                  source_phone_stdout=dict(path=REMOTE + '/PHONE-STDOUT.original', **pin(stdout)),
                  source_decoded_observations=pin(raw), footprint_original=pin(footprint_raw),
                  observation_started_unix_ns=report['observation_started_unix_ns'],
                  observation_ended_unix_ns=report['observation_ended_unix_ns'],
                  entries=obs['entries'], immediate_parent_observations=parents,
                  positive_absence_observations=absences, read_bookends=obs['read_bookends'],
                  canonical_ancestor_observations=obs['canonical_ancestor_observations'],
                  actual_alias_checks=obs['actual_alias_checks'], fixed_proc_root_bridge=bridge,
                  boot_originals=obs['boot_originals'],
                  file_original_pins=[{k: row[k] for k in ('path', 'bytes', 'sha256')} for row in obs['file_originals']],
                  complete_original_file_bodies_retained_in_source=True,
                  body_bytes_omitted_from_this_metadata_projection=True,
                  source_binding_itself_is_not_current_admission=True,
                  atomic_global_snapshot_claimed=False, phone_calls_by_projection=0,
                  new_nonce_or_lease=False, case_credit=False)
projection_raw = encoded(projection)
with (HERE / 'SOURCE-BINDING-OBSERVATIONS.json').open('xb') as handle:
    handle.write(projection_raw)
verification = dict(schema='hepta.fixed19.root-read02-complete-original-consumption.v1',
                    state='ROOT_INDEPENDENTLY_VERIFIED_COMPLETE_READ02_ARCHIVE_AND_METADATA_PROJECTION',
                    original_archive=pin(archive), original_manifest=pin(mfraw), original_tar=pin(tarraw),
                    original_phone_stdout=pin(stdout), original_decoded=pin(raw),
                    fixed_version=VERSION, independently_recomputed_chunks=70,
                    independently_recomputed_tar_members=12, present_rows=146, complete_file_bodies=126,
                    complete_raw_file_bytes=7114062, positive_absences=65, full_parent_table_rows=22,
                    actual_parent_references_expanded=130, metadata_bytes=metadata_bytes,
                    physical_read_bytes=14322260, whole_file_reads=252,
                    projection=dict(path=str(HERE / 'SOURCE-BINDING-OBSERVATIONS.json'), **pin(projection_raw)),
                    full9_integer_precision_retained=True, owned_fd_cleanup_complete=True,
                    original_read01_failure_unchanged=True, old_sender_unknown_unchanged=True,
                    target_source_executed_by_this_verifier=False, phone_calls=0, remote_calls=0,
                    epoch_admitted=False, new_case_nonce_or_lease=False, fixed19_case_credit=0)
verification_raw = (json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
with (HERE / 'ROOT-COMPLETE-VERIFICATION.json').open('xb') as handle:
    handle.write(verification_raw)
print(json.dumps(dict(report=pin(verification_raw), projection=pin(projection_raw))))
