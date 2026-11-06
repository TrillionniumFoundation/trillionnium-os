#!/usr/bin/env python3
"""Preserve complete source originals from one bounded, read-only controller job."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import types
import zlib

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent.parent

def need(value, message):
    if not value:
        raise ValueError(message)

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()

def put(relative, raw):
    path = HERE / relative
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
    return {'path': str(path), **pin(raw)}

def checked_body(row):
    need(set(row) == {'path', 'bytes', 'sha256', 'metadata', 'eof', 'full9_bookended', 'text'}, 'complete original record')
    need(type(row['text']) is str and type(row['bytes']) is int, 'exact text and byte length types')
    body = row['text'].encode('utf-8')
    need(pin(body) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact UTF8 original bytes')
    metadata = row['metadata']
    need(type(metadata) is list and len(metadata) == 9 and all(type(v) is int and v >= 0 for v in metadata), 'complete integer full9 metadata')
    need(stat.S_ISREG(metadata[2]) and metadata[5] == 1 and metadata[6] == len(body), 'regular single-link complete original')
    need(row['eof'] is True and row['full9_bookended'] is True, 'original EOF and full9 bookends')
    return body

def main():
    source = (REVIEW / 'install-build-controller/verify_host_controller_originals.py').read_bytes()
    need(pin(source) == {'bytes': 16570, 'sha256': 'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'}, 'pinned original controller reader')
    C = types.ModuleType('fc33_source_graph_original_controller_reader')
    C.__file__ = 'verify_host_controller_originals.py'
    exec(compile(source, C.__file__, 'exec'), C.__dict__)
    carrier = json.loads((HERE / 'evidence/OBSERVATION-CONTROLLER.original.json').read_bytes())
    job, status, streams = C.controller(carrier, code=0, complete=True)
    need(streams['stderr'] == b'', 'read-only observation has no stderr')
    need(carrier['request']['stdin'].encode() == (HERE / 'observe_actual_graph.py').read_bytes(), 'actual observer source exactly reviewed')
    envelope = json.loads(streams['stdout'])
    need(envelope['schema'] == 'hepta.fc33.complete-original-zlib-transfer.v1' and envelope['compression'] == 'zlib', 'one complete zlib transfer')
    need(type(envelope['original']['bytes']) is int and 0 < envelope['original']['bytes'] <= 64 * 1024 * 1024, 'bounded exact original size')
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(envelope['raw_zlib_base64'], validate=True), envelope['original']['bytes'] + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(raw) == envelope['original'], 'complete single zlib stream and original pin')
    observation = json.loads(raw)
    inputs = json.loads((HERE / 'INPUTS.json').read_bytes())
    need(observation['schema'] == 'hepta.fc33.r6.complete-actual-source-graph-readback.v1'
         and observation['state'] == 'SOURCE_GRAPH_ORIGINALS_READ_BACK_NO_TASK_EXECUTION', 'actual source readback only')
    need(observation['complete_directory_bookends'] is observation['all_files_full9_bookended'] is True, 'all directory and file bookends')
    need(all(type(observation[k]) is int and observation[k] == 0 for k in ('phone_calls', 'source_modules_executed', 'filesystem_writes', 'native_dispatches')), 'no source or phone execution')
    need(all(observation[k] is None for k in ('actual_BUILD', 'actual_READY', 'actual_current_cases')), 'no inferred actual task outputs')
    need(set(observation['roots']) == set(inputs['roots']) and set(observation['extra_originals']) == set(inputs['extra_originals']), 'all exact selected source roots')
    counts = {}; originals = []; pending = {}; total = 0
    for label, group in observation['roots'].items():
        terminal = inputs['roots'][label]
        root = str(PurePosixPath(terminal['path']).parent)
        need(group['root'] == root and group['terminal'] == terminal, 'exact actual root and terminal')
        files = group['files']; directories = group['directory_originals']
        need(type(group['file_count']) is int and group['file_count'] == len(files), 'actual source member count')
        local = {}
        for name, row in files.items():
            relative = PurePosixPath(name)
            need(not relative.is_absolute() and '..' not in relative.parts and str(relative) == name, 'canonical relative source member')
            need(row['path'] == root + '/' + name, 'exact source member namespace')
            body = checked_body(row); local[name] = body; total += len(body)
            target = 'actual/' + label + '/' + name
            pending[target] = body
            originals.append({'group': label, 'relative': name, 'local_path': str(HERE / target), **{k: row[k] for k in ('path', 'bytes', 'sha256', 'metadata')}})
        terminal_name = PurePosixPath(terminal['path']).name
        need(pin(local[terminal_name]) == {k: terminal[k] for k in ('bytes', 'sha256')}, 'exact actual terminal original')
        document = json.loads(local[terminal_name]); rows = document['files']
        need(type(rows) is list and len(rows) == len({r['path'] for r in rows}), 'unique actual manifest rows')
        manifest_names = set()
        for row in rows:
            name = str(PurePosixPath(row['path']).relative_to(root))
            need(name not in manifest_names and set(row) == {'path', 'bytes', 'sha256'} and type(row['bytes']) is int, 'exact full source descriptor')
            manifest_names.add(name)
            need(pin(local[name]) == {k: row[k] for k in ('bytes', 'sha256')}, 'actual manifest-to-member bytes')
        need(manifest_names | {terminal_name} == set(files) and terminal_name not in manifest_names, 'manifest enumerates complete directory including terminal')
        need(type(group['file_bytes']) is int and group['file_bytes'] == sum(map(len, local.values())), 'complete root byte count')
        for name, row in directories.items():
            rel = PurePosixPath(name)
            expected_path = root if name == '.' else root + '/' + name
            metadata = row['metadata']
            need(row['path'] == expected_path and type(metadata) is list and len(metadata) == 9 and all(type(v) is int and v >= 0 for v in metadata), 'complete directory full9')
            need(stat.S_ISDIR(metadata[2]) and stat.S_IMODE(metadata[2]) == 0o700, 'private actual source directory')
            direct = {PurePosixPath(n).name for n in files if PurePosixPath(n).parent == rel}
            direct.update(PurePosixPath(n).name for n in directories if n != '.' and PurePosixPath(n).parent == rel)
            need(row['names'] == sorted(direct), 'exact actual directory names and no omitted children')
        need('.' in directories, 'root directory observation')
        counts[label] = len(files)
    for label, row in observation['extra_originals'].items():
        need({k: row[k] for k in ('path', 'bytes', 'sha256')} == inputs['extra_originals'][label], 'exact extra original descriptor')
        body = checked_body(row); total += len(body)
        target = 'actual/extra_originals/' + label + '.original.py'
        pending[target] = body
        originals.append({'group': 'extra_originals', 'relative': label, 'local_path': str(HERE / target), **{k: row[k] for k in ('path', 'bytes', 'sha256', 'metadata')}})
    need(type(observation['complete_file_bytes']) is int and observation['complete_file_bytes'] == total, 'complete combined original byte count')
    for relative, body in pending.items():
        put(relative, body)
    put('evidence/OBSERVATION-STDOUT.original.json', streams['stdout'])
    put('evidence/OBSERVATION.original.json', raw)
    manifest = {'schema': 'hepta.fc33.r6.actual-source-graph-archive.v1', 'files': originals,
                'file_count': len(originals), 'file_bytes': total, 'root_counts': counts,
                'observation_job_id': job['id'], 'whole_directory_originals_retained': True}
    manifest_raw = enc(manifest); put('ORIGINALS-MANIFEST.json', manifest_raw)
    result = {'schema': 'hepta.fc33.r6.actual-source-graph-archive-verification.v1',
              'state': 'COMPLETE_ACTUAL_SOURCE_BYTES_PRESERVED_NO_TASK_EXECUTION',
              'observation_job_id': job['id'], 'pages': len(carrier['reads']),
              'transport_reader': pin(source), 'observation_stdout': pin(streams['stdout']),
              'observation': pin(raw), 'originals_manifest': pin(manifest_raw),
              'actual_root_counts': counts, 'extra_originals_count': len(inputs['extra_originals']),
              'complete_actual_original_count': len(originals), 'complete_file_bytes': total,
              'all_file_full9_and_directory_names_verified': True, 'both_streams_eof': True,
              'automatic_retry': False, 'source_controls_rerun': False,
              'phone_calls': 0, 'native_dispatches': 0, 'new_nonces': 0,
              'actual_BUILD': None, 'actual_READY': None, 'actual_current_cases': None, 'fixed19_credit': 0}
    put('VERIFICATION.json', enc(result))
    print(json.dumps({'counts': counts, 'original_count': len(originals), 'bytes': total,
                      'manifest': pin(manifest_raw), 'verification': pin(enc(result))}, sort_keys=True))

if __name__ == '__main__':
    main()
