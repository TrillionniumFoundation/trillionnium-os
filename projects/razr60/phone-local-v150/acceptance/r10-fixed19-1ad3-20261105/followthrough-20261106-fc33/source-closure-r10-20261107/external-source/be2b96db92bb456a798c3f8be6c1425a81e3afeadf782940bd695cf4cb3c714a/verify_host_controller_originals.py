"""Verify this attempt's retained actual evidence only; no fixtures or effects."""
import base64
import hashlib
import json
import re
import stat
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
E = HERE / 'evidence'
LABEL = 'root-r10-neg01-fc33-bound01'
NONCE = 'e2fdaccd43cec9da1df4d77783db8fdb'
META = {'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'}
PHASES = ['prepare-material', 'host-stage-material', 'phone-push-material',
          'phone-copy-material', 'phone-push-stage-source', 'phone-copy-stage-source', 'phone-stage']

def need(value, why):
    if not value:
        raise ValueError(why)

def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def body(name):
    return (E / name).read_bytes()

def tool(value):
    need(value.get('isError') is False, 'original MCP operation must not be error')
    blocks = [item['text'] for item in value['content'] if item['type'] == 'text']
    need(len(blocks) == 1 and value.get('structuredContent') is None, 'one exact original controller JSON text')
    return strict(blocks[0])

def controller(record, *, code=0, complete=True):
    started, status = tool(record['start']), tool(record['status'])
    job = started['job']
    need(started['reused'] is False and job['launch_state'] == 'launched' and job['launch_error'] is None,
         'one actual launched original job')
    need(status['job_id'] == job['id'] and type(status['exit_code']) is int and status['exit_code'] == code,
         'same actual original terminal exit')
    need(status['state'] == ('succeeded' if code == 0 else 'failed'), 'exact terminal state')
    for name in ('output_complete', 'output_durable', 'terminal_publication_confirmed'):
        need(status[name] is True, 'complete durable terminal')
    for name in ('timed_out', 'cancelled', 'automatic_retry'):
        need(status[name] is False, 'no timeout/cancel/retry flag')
    reads = record.get('reads', [record.get('read')])
    result = {}
    for stream in ('stdout', 'stderr'):
        need(status['log_synced'][stream] is True and status['log_truncated'][stream] is False
             and status['log_errors'][stream] is None, 'actual durable untruncated stream')
        counts = status['log_bytes'][stream]
        need(set(counts) == {'seen', 'stored'} and all(type(v) is int and v >= 0 for v in counts.values())
             and counts['seen'] == counts['stored'], 'exact typed original stream counters')
        chunks, end = [], 0
        for wrapped in reads:
            value = tool(wrapped)
            need(value['job_id'] == job['id'], 'same original read job')
            row = value[stream]
            raw = bytes.fromhex(row['bytes_hex'])
            need(type(row['offset']) is int and type(row['next_offset']) is int
                 and type(row['size']) is int and row['size'] == counts['stored']
                 and row['next_offset'] == row['offset'] + len(raw)
                 and type(row['text']) is str and row['text'].encode() == raw,
                 'original stream bytes, text, offsets and typed size agree')
            if complete:
                need(row['offset'] == end, 'lossless contiguous original process reads')
            end = row['next_offset']
            chunks.append(raw)
        need(row['eof'] is True and end == counts['stored'], 'actual stream terminal EOF')
        result[stream] = b''.join(chunks)
        if complete:
            need(len(result[stream]) == counts['stored'], 'all original stream bytes retained')
    return job, status, result

def descriptor(row, raw=None):
    need(type(row['bytes']) is int and row['bytes'] >= 0 and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'typed complete original bytes and hash')
    metadata = row['metadata']
    need(set(metadata) == META and all(type(v) is int and v >= 0 for v in metadata.values()),
         'original full9 metadata retains all integers')
    need(metadata['st_size'] == row['bytes'] and metadata['st_nlink'] == 1
         and stat.S_ISREG(metadata['st_mode']), 'exact original regular single-link file')
    need(row['eof'] is True and row['full9_bookended'] is True, 'full read and metadata bookend recorded')
    if raw is not None:
        need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'complete raw body matches original descriptor')

def main():
    mac_record = strict(body('mac-observation-controller.original.json'))
    mac_job, mac_status, prefix = controller(mac_record, complete=False)
    tx_record = strict(body('mac-log-transfer-controller.original.json'))
    tx_job, tx_status, tx_streams = controller(tx_record)
    need(tx_streams['stdout'] == body('mac-log-transfer.stdout.original.json') and tx_streams['stderr'] == b'',
         'exact whole compressed-transfer original output')
    tx = strict(tx_streams['stdout'])
    need(tx['controller_job_id'] == mac_job['id'] and tx['compression'] == 'zlib', 'same audit original transport')
    compressed = base64.b64decode(tx['raw_zlib_base64'], validate=True)
    decoder = zlib.decompressobj()
    mac_raw = decoder.decompress(compressed, tx['original_stdout']['bytes'] + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, 'complete single bounded zlib member')
    descriptor(tx['original_stdout'], mac_raw)
    need(tx['original_stdout']['path'].startswith(mac_job['remote_job_dir'] + '/')
         and len(mac_raw) == mac_status['log_bytes']['stdout']['stored'] == 232288
         and mac_raw.startswith(prefix['stdout']) and len(prefix['stdout']) == 16384
         and prefix['stderr'] == b'' and mac_raw == body('mac-observation.stdout.original.json'),
         'whole original audit log matches controller count, retained prefix, EOF probe and local bytes')
    mac = strict(mac_raw)
    p4_job, p4_status, p4_streams = controller(strict(body('pocket4-observation-controller.original.json')))
    need(p4_streams['stdout'] == body('pocket4-observation.stdout.original.json') and p4_streams['stderr'] == b'',
         'exact full P4 host observation output')
    p4 = strict(p4_streams['stdout'])
    for value, host in ((mac, 'mac'), (p4, 'pocket4')):
        need(value['schema'] == 'hepta.fc33.failed-neg01-host-original-observation.v1'
             and value['state'] == 'COMPLETE_HOST_READ_ONLY_OBSERVATION'
             and value['host'] == host and value['label'] == LABEL and value['nonce'] == NONCE,
             'same exact failed attempt host scope')
        for key in ('phone_calls', 'project_modules_executed', 'cleanup_actions', 'sender_executions'):
            need(type(value[key]) is int and value[key] == 0, 'read-only host observation')
        need(value['private_bodies_exported'] is False and value['new_qualification'] is False,
             'observation cannot grant qualification or export private bodies')
    tree = mac['tree']
    files = {r['relative_path']: r for r in tree['files']}
    need(len(files) == len(tree['files']) == tree['file_count'] == 115
         and sum(r['bytes'] for r in files.values()) == tree['file_bytes'] == 10998073,
         'complete observed failed attempt file accounting')
    for row in files.values():
        descriptor(row)
        need(row['path'] == str(Path(tree['root']) / row['relative_path']), 'exact retained host namespace')
    directories = {r['relative_path']: r for r in tree['directories']}
    need(len(directories) == len(tree['directories']) == 15 and tree['complete_tree_bookended'] is True,
         'complete actual directory inventory')
    for name, row in directories.items():
        need(row['full9_bookended'] is True and set(row['metadata']) == META
             and all(type(v) is int for v in row['metadata'].values()), 'directory full9 exact integers')
        members = set()
        base = Path(name)
        for other in list(files) + [p for p in directories if p != '.']:
            rel = Path(other)
            if rel.parent == base:
                members.add(rel.name)
        need(sorted(members) == row['names'], 'complete listed directory member set')
    public = {r['relative_path']: r for r in tree['public_originals']}
    need(len(public) == len(tree['public_originals']) == 30, 'exact public phase original count')
    for name, row in public.items():
        p = Path(name)
        need('stdin.original' not in p.parts and not any('preserved_draft' in part for part in p.parts),
             'private raw bodies never in public originals')
        need((len(p.parts) == 1 and name in {'ROOT-FAILURE.json', 'CHAIN-INTENT.json'})
             or (len(p.parts) == 2 and p.parts[0] in PHASES
                 and p.name in {'INTENT.json', 'RESULT.json', 'JOINED.json', 'stdout.original', 'stderr.original'}),
             'closed public original member allowlist')
        descriptor(row, row['text'].encode())
        need({k: row[k] for k in files[name]} == files[name], 'same original descriptor in complete tree')
    failure = strict(public['ROOT-FAILURE.json']['text'])
    need([r['phase'] for r in failure['steps']] == PHASES and failure['host_cleanup'] == {'host_children': [], 'stream_cleanup_errors': []},
         'actual root stopped after exact seven joined phases')
    for phase in PHASES:
        result = strict(public[phase + '/RESULT.json']['text'])
        need(result == next(row for row in failure['steps'] if row['phase'] == phase)
             and result['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
             and type(result['returncode']) is int and result['returncode'] == 0,
             'same actual synchronous phase join record')
        for stream in ('stdout', 'stderr'):
            need(result[stream] == {k: files[phase + '/' + stream + '.original'][k]
                                    for k in ('path', 'bytes', 'sha256')}, 'phase join exact stream pins')
    stage = strict(public['phone-stage/stdout.original']['text'])
    need(type(stage['actor_rc']) is int and stage['actor_rc'] == 0
         and type(stage['wrapper']['phone']['rc']) is int and stage['wrapper']['phone']['rc'] == 1
         and stage['wrapper']['phone']['stdout'] == '', 'outer actor success does not erase inner stage rejection')
    error = stage['wrapper']['phone']['stderr']
    need('retained_stage_parent_profiles' in error
         and 'shared parent identity/label/names differ from exact admitted additions' in error,
         'actual selected stage failure')
    for row in mac['presence'][:6]:
        need(row['state'] == 'ENOENT' and type(row['errno']) is int and row['errno'] == 2,
             'exact Mac sender phase and local markers absent at observation')
    need([row['state'] for row in p4['presence'][:2]] == ['DIRECTORY_PRESENT', 'DIRECTORY_PRESENT'],
         'actual failed P4 chain and phone-stage evidence remain present')
    for row in p4['presence'][2:]:
        need(row['state'] == 'ENOENT' and type(row['errno']) is int and row['errno'] == 2,
             'exact P4 sender directory and seven send markers absent')
    root_original = strict(body('root-stage-failure.original.json'))
    root_job, root_status, root_streams = controller(root_original, code=1)
    root_files = tool(root_original['failure_file'])['files']
    need(len(root_files) == 1 and root_files[0]['text'].encode() == public['ROOT-FAILURE.json']['text'].encode(),
         'same complete root failure original independently reread')
    for key in ('root', 'sender'):
        descriptor(mac['source_originals'][key])
    need(mac['source_originals']['root']['sha256'] == '2af78597f211b8b7de32d5f40591e46c4ea5ff7caa3c4a2547ac4325666c2032'
         and mac['source_originals']['sender']['sha256'] == '53a6e9149cf768211c3c8ba74d3c422f95d78f14efdb8751af1ac55d1a9225d5',
         'exact source control flow for stop-before-sender inference')
    observed_operation = strict(body('root-parent-observation-operation.original.json'))
    observation_controller = strict(body('root-parent-observation-controller.original.json'))
    observation_job, observation_status, observation_streams = controller(observation_controller)
    retained = tool(observation_controller['actual_file'])['files']
    need(len(retained) == 1 and retained[0]['text'].encode() == body('root-parent-observation-operation.original.json'),
         'root supplied fresh phone observation exact original bytes')
    current = strict(observed_operation['phone']['stdout'])
    need(observed_operation['phone']['rc'] == 0 and current['label'] == LABEL and current['nonce'] == NONCE
         and len(current['current_owned_paths']) == 3
         and all(row['exists'] is False and type(row['errno']) is int and row['errno'] == 2
                 for row in current['current_owned_paths']), 'separate actual phone observation reports three exact owned paths absent')
    report = {
        'schema': 'hepta.fc33.failed-neg01-host-evidence-verification.v1',
        'state': 'ACTUAL_FAILED_ATTEMPT_STOPPED_BEFORE_SENDER_HOST_EVIDENCE_VERIFIED',
        'label': LABEL, 'nonce': NONCE,
        'root_job': root_job['id'], 'root_exit_code': root_status['exit_code'],
        'root_stdout_bytes': len(root_streams['stdout']), 'root_stderr_bytes': len(root_streams['stderr']),
        'mac_observation_job': mac_job['id'], 'mac_log_transfer_job': tx_job['id'],
        'pocket4_observation_job': p4_job['id'], 'root_phone_observation_job': observation_job['id'],
        'host_tree_file_count': len(files), 'host_tree_directory_count': len(directories),
        'host_tree_file_bytes': tree['file_bytes'], 'public_original_count': len(public),
        'public_original_bytes': mac['public_original_bytes'],
        'phase_order': PHASES, 'last_phase_host_exit_code': 0, 'last_phase_actor_exit_code': 0,
        'last_phase_phone_exit_code': 1, 'sender_stage_reached_by_this_root_chain': False,
        'sender_conclusion_basis': 'Exact executed root source requires successful phone-stage return before sender-preview/execute; retained root failure and complete phase inventory stop at inner phone rc=1; Mac/P4 exact sender paths are absent at the recorded observations.',
        'mac_absent_sender_paths': [row['path'] for row in mac['presence'][:6]],
        'pocket4_absent_sender_paths': [row['path'] for row in p4['presence'][2:]],
        'separate_root_phone_observation_owned_paths': current['current_owned_paths'],
        'original_audit_transport': 'Complete closed stdout file read with EOF/full9 and zlib transfer; controller terminal stored count, first 16384 bytes and terminal EOF probe agree. This is not represented as contiguous process_read pagination.',
        'private_body_exported': False,
        'outer_only_sensitive_descriptors': [row for row in files.values()
            if Path(row['relative_path']).name == 'stdin.original' or 'preserved_draft' in row['relative_path']],
        'scope_limits': [
            'No claim that phone had zero effects: material/source push and stage attempt already occurred.',
            'No claim of global sender inactivity, foreign-attempt cleanup, current tuple qualification, or component closure.',
            'Path absence is at the recorded observations; the stop-before-sender conclusion also relies on the exact executed source and complete original phase history.',
            'The fresh phone observation was executed earlier by root; this agent only performed host reads.',
        ],
        'new_control_scenarios': 0, 'phone_calls_by_this_agent': 0, 'cleanup_actions_by_this_agent': 0,
        'component_qualified': False, 'business_qualified': False,
        'actual_BUILD': None, 'actual_install': None, 'actual_READY': None,
        'original_files': [{'path': str(p.relative_to(HERE)), **pin(p.read_bytes())}
                           for p in sorted(E.iterdir()) if p.is_file()],
    }
    raw = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with (HERE / 'VERIFICATION.json').open('xb') as f:
        f.write(raw)
    print(json.dumps({'state': report['state'], 'result': pin(raw),
                      'root_job': root_job['id'], 'phone_calls_by_this_agent': 0}, sort_keys=True))

if __name__ == '__main__':
    main()
