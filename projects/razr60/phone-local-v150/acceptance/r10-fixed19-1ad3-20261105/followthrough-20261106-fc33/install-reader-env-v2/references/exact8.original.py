#!/usr/bin/env python3
"""Pure eight-stream origin reader. No phone, process or filesystem operations.

The caller supplies original pinned bytes, not context assertions. A reviewed
future final-release reader is a required immutable source slot. This function
rechecks that actual host BUILD, then connects selected installed module bytes,
READY, four identity files and three original guarded binds. It returns origin
selectors only. It never grants BUILD, output closure, readiness or rollback
qualification. Nonregular supervisor streams remain explicit UNKNOWN.

read_pinned accepts exact3 retained-host rows and exact4 original-phone rows.
For exact4 it must verify the original capture's full9 provenance as well as
returning the exact bytes; host-copy metadata is not phone metadata.
"""
import base64
import hashlib
import json
import re
import stat
import types
from pathlib import PurePosixPath

RELEASE_READER = {"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/source/verify_final_release_inputs_v3.py","bytes":28483,"sha256":"e947a3b2de75a0820fcc3cb5cfe758f874cd85625cb11bac793b38256a670c43"}
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
POLICY = '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
PARENT_POLICY = 'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
RUNTIME = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'
COMBINATION = '02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'
HELPER_PIN = {'bytes': 32701, 'sha256': '958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a'}
READY_PIN = {'bytes': 16407, 'sha256': '2b4ff90f7078af2481feb8a2d33c39d1a0e260102cd769a4ee3b46d9bec47e11'}
OBSERVER_PIN = {'bytes': 28570, 'sha256': 'e48a4e1cd905643a7de060b49536d508aa31ba4535ea0a71708e6ccb71abd9bf'}
MODULE = '/proc/1/root/data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
CLAIM = '/proc/1/root/data/adb/trillionnium-hepta-phone-local-v150-r10-r1/' + BOOT
EXECUTOR_LOGS = '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/executor-r6/module-history-r10-r1/' + BOOT
GNU = '/var/lib/trillionnium/owner-open/phone-local-v150'
SUPERVISOR_LOGS = GNU + '/root-install-v150-r10-r1'
READY_PATH = GNU + '/provider-r10-r1/collect_r10_readiness.py'
ROLES = ('model', 'sidecar', 'provider')
FOUR = ('supervisor',) + ROLES
STREAMS = ('stdout', 'stderr')
SCHEMA = 'hepta.resident-owner.eight-stream-original-inputs.v1'
FIELDS = {'schema', 'release_inputs', 'ready', 'module_originals',
          'role_identity_originals', 'child_bindings'}
MAX_ONE = 16 * 1024 * 1024
MAX_BIND = 262144
MAX_POOL = 8 * 1024 * 1024
MAX_POOL_FILES = 64
EMPTY_SHA = hashlib.sha256(b'').hexdigest()

def need(value, reason):
    if not value:
        raise ValueError(reason)

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def strict(raw, maximum=MAX_ONE):
    need(type(raw) is bytes and len(raw) <= maximum, 'complete bounded original JSON bytes')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate original JSON field')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite original JSON'))

def exact(value, keys, message):
    need(type(value) is dict and set(value) == set(keys), message)
    return value

def path(value):
    need(type(value) is str and value.startswith('/') and not value.startswith('//')
         and all(c not in value for c in ('\0', '\n', '\r', '\t'))
         and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts,
         'canonical absolute original path')
    return value

def metadata(value, *, regular=False, mode=None):
    need(type(value) is list and len(value) == 9
         and all(type(n) is int and 0 <= n < 2**64 for n in value)
         and value[1] > 0, 'exact unsigned original full9')
    if regular:
        need(stat.S_ISREG(value[2]) and value[3:6] == [0, 0, 1]
             and value[6] <= MAX_ONE, 'Root single-link regular original')
    if mode is not None:
        need(stat.S_IMODE(value[2]) == mode, 'exact original mode')
    return value

def descriptor(row, *, phone=False, maximum=MAX_ONE, expected_path=None, mode=0o600):
    exact(row, {'path', 'bytes', 'sha256', 'metadata'} if phone else {'path', 'bytes', 'sha256'},
          'exact phone4 or retained-host3 descriptor')
    path(row['path'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= maximum
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'finite complete original byte pin')
    if expected_path is not None:
        need(row['path'] == expected_path, 'original path differs from the fixed producer namespace')
    if phone:
        metadata(row['metadata'], regular=True, mode=mode)
        need(row['metadata'][6] == row['bytes'], 'original full9 size differs')
    return row

def exact3(row):
    return {key: row[key] for key in ('path', 'bytes', 'sha256')}

class Originals:
    def __init__(self, read_pinned):
        need(callable(read_pinned), 'original byte reader required')
        self.callback = read_pinned
        self.rows = {}
        self.total = 0
    def read(self, row, *, phone=False, maximum=MAX_ONE, expected_path=None, mode=0o600):
        descriptor(row, phone=phone, maximum=maximum, expected_path=expected_path, mode=mode)
        raw = self.callback(row)
        need(type(raw) is bytes and pin(raw) == {key: row[key] for key in ('bytes', 'sha256')},
             'complete original bytes differ from descriptor')
        prior = self.rows.get(row['path'])
        if prior is None:
            need(len(self.rows) < MAX_POOL_FILES and self.total + len(raw) <= MAX_POOL,
                 'finite eight-stream original pool exhausted')
            self.rows[row['path']] = (dict(row), raw)
            self.total += len(raw)
        else:
            need(prior == (row, raw), 'one original path changed during verification')
        return raw
    def recheck(self):
        for row, raw in self.rows.values():
            need(self.callback(row) == raw, 'final original byte bookend differs')

def load_reviewed(raw, row, name):
    need(pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'reviewed source byte identity')
    result = types.ModuleType(name)
    result.__file__ = row['path']
    exec(compile(raw, row['path'], 'exec'), result.__dict__)
    return result

def identity(value):
    need(type(value) is list and len(value) == 4
         and all(type(n) is int and 0 < n < 2**64 for n in value)
         and value[0] > 1 and value[0] == value[1] == value[2],
         'one dedicated resident PID/group/session/start generation')
    return value

def interval(value):
    need(type(value) is list and len(value) == 2
         and all(type(n) is int and 0 < n < 2**64 for n in value)
         and 0 <= value[1] - value[0] <= 2_000_000_000,
         'original bounded two-second BOOTTIME bind interval')
    return value

def proc_original(helper, value, expected=None, parent=None):
    exact(value, {'path', 'errno', 'raw_b64', 'value'}, 'complete original proc observation')
    need(value['errno'] is None and type(value['raw_b64']) is str
         and type(value['value']) is dict, 'bind requires observed live original proc bytes')
    raw = base64.b64decode(value['raw_b64'], validate=True)
    pid = value['value'].get('pid')
    need(type(pid) is int and pid > 1 and value['path'] == '/proc/' + str(pid) + '/stat',
         'exact proc PID path')
    parsed = helper.parse_stat(raw, pid)
    need(parsed == value['value'] and parsed['state'] not in ('Z', 'X', 'x'),
         'reparsed live proc original differs')
    if expected is not None:
        need(parsed['identity'] == expected, 'original process generation differs')
    if parent is not None:
        need(parsed['parent_pid'] == parent[0], 'original direct parent relation differs')
    return parsed

def kind(mode):
    if stat.S_ISREG(mode):
        return 'regular_file'
    if stat.S_ISFIFO(mode):
        return 'pipe'
    if stat.S_ISCHR(mode):
        return 'character_device'
    if stat.S_ISSOCK(mode):
        return 'socket'
    return 'other_nonregular'

def parent_outputs(helper, value, supervisor, bind_interval):
    exact(value, {'schema', 'scope', 'parent_identity', 'observed_start_boottime_ns',
                  'observed_end_boottime_ns', 'outputs', 'installer_start_fd_identity_proven',
                  'supervisor_original_parent_wait',
                  'nonregular_outputs_remain_explicit_not_regular_log_credit',
                  'complete_output_closure_qualified'}, 'exact parent FD observation fields')
    need(value['schema'] == 'hepta.resident-owner.parent-output-bind-observation.v1'
         and value['scope'] == 'DIRECT_PARENT_FD_AT_CHILD_BIND_ONLY'
         and value['parent_identity'] == supervisor
         and value['installer_start_fd_identity_proven'] is False
         and value['supervisor_original_parent_wait'] == 'NOT_RETAINED'
         and value['nonregular_outputs_remain_explicit_not_regular_log_credit'] is True
         and value['complete_output_closure_qualified'] is False,
         'parent bind observation cannot claim startup FD, wait or output closure')
    frame = interval([value['observed_start_boottime_ns'], value['observed_end_boottime_ns']])
    need(bind_interval[0] <= frame[0] <= frame[1] <= bind_interval[1], 'parent observation outside bind bracket')
    exact(value['outputs'], STREAMS, 'both parent output FD originals required')
    result = {}
    last = frame[0]
    fields = {'fd', 'kind', 'proc_fd_path', 'before_full9', 'after_full9',
              'fdinfo_before_b64', 'fdinfo_after_b64', 'flags', 'specified_regular_path',
              'path_before_full9', 'path_after_full9', 'observed_start_boottime_ns',
              'observed_end_boottime_ns', 'pipe_eof_observed', 'regular_contents_read'}
    for number, stream in ((1, 'stdout'), (2, 'stderr')):
        row = exact(value['outputs'][stream], fields, 'complete parent FD original')
        before = metadata(row['before_full9'])
        after = metadata(row['after_full9'])
        observed_kind = kind(before[2])
        step = interval([row['observed_start_boottime_ns'], row['observed_end_boottime_ns']])
        need(last <= step[0] <= step[1] <= frame[1], 'ordered original parent FD observation times')
        last = step[1]
        need(type(row['fd']) is int and row['fd'] == number and row['proc_fd_path'] == '/proc/' + str(supervisor[0]) + '/fd/' + str(number)
             and before == after and row['kind'] == observed_kind
             and row['pipe_eof_observed'] is None and row['regular_contents_read'] is False,
             'parent FD type/full9 must be actual and unchanged within its bracket')
        first_info = base64.b64decode(row['fdinfo_before_b64'], validate=True)
        after_info = base64.b64decode(row['fdinfo_after_b64'], validate=True)
        flags = helper.parent_fdinfo(first_info)
        need(type(row['flags']) is int and row['flags'] == flags
             and first_info == after_info and helper.parent_fdinfo(after_info) == flags,
             'complete original parent FD flags/bytes changed')
        if observed_kind == 'regular_file':
            named = SUPERVISOR_LOGS + '/service.' + stream
            metadata(before, regular=True, mode=0o600)
            need(row['specified_regular_path'] == named
                 and row['path_before_full9'] == row['path_after_full9'] == before,
                 'parent regular FD must equal fixed private service log')
        else:
            need(row['specified_regular_path'] is None
                 and row['path_before_full9'] is None and row['path_after_full9'] is None,
                 'nonregular output cannot acquire a regular-file path or credit')
        result[stream] = row
    return result

def verify_module_and_ready(value, pool, release, release_inputs):
    module = exact(value['module_originals'], {'manifest', 'binding', 'service', 'helper'},
                   'exact selected installed module originals')
    host_manifest = pool.read(release_inputs['module_manifest'], maximum=1024*1024)
    host_binding = pool.read(release_inputs['module_binding'], maximum=1024*1024)
    manifest_raw = pool.read(module['manifest'], phone=True, maximum=1024*1024,
                             expected_path=MODULE + '/MODULE-MANIFEST-v150-r10-r1.json')
    binding_raw = pool.read(module['binding'], phone=True, maximum=1024*1024,
                            expected_path=MODULE + '/seal-binding.json')
    need(manifest_raw == host_manifest and binding_raw == host_binding,
         'installed module manifest/binding bytes differ from independently verified actual BUILD')
    manifest, bound = strict(manifest_raw), strict(binding_raw)
    need(manifest['schema'] == 'hepta.module-r10-r1.file-manifest.v1'
         and manifest['module_id'] == 'trillionnium_hepta_phone_local_v150_r10_r1'
         and manifest['release_id'] == 'v150-r10-r1'
         and manifest['binding_sha256'] == pin(binding_raw)['sha256']
         and manifest['phone_qualification'] is False
         and bound['schema'] == 'hepta.module-r10-r1.exact-integration.v1'
         and bound['release_id'] == 'v150-r10-r1' and bound['migration_boot'] == BOOT,
         'actual module original family differs')
    need(type(manifest['files']) is list and 1 <= len(manifest['files']) <= 512,
         'finite complete module member manifest')
    members = {}
    for item in manifest['files']:
        exact(item, {'path', 'bytes', 'sha256'}, 'module relative member pin')
        name = item['path']
        need(type(name) is str and name and not PurePosixPath(name).is_absolute()
             and '..' not in PurePosixPath(name).parts and str(PurePosixPath(name)) == name
             and all(c not in name for c in ('\0', '\r', '\n', '\t')) and name not in members,
             'unique exact module member name')
        need(type(item['bytes']) is int and 0 <= item['bytes'] <= 32*1024*1024
             and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']),
             'complete bounded module member identity')
        members[name] = item
    source_rows = {}
    source_raw = {}
    for key, name, mode in (('service', 'service.sh', 0o700),
                            ('helper', 'resident_owner_terminal.py', 0o600)):
        need(name in members, 'reviewed owner source missing from actual module')
        raw = pool.read(module[key], phone=True, maximum=262144,
                        expected_path=MODULE + '/' + name, mode=mode)
        need(pin(raw) == {k: members[name][k] for k in ('bytes', 'sha256')},
             'installed owner source differs from actual BUILD module member')
        source_rows[key] = exact3(module[key])
        source_raw[key] = raw
    need(pin(source_raw['helper']) == HELPER_PIN, 'exact reviewed H05 helper required')
    ready_input = exact(value['ready'], {'source', 'original'}, 'actual READY source and raw report required')
    ready_source = pool.read(ready_input['source'], phone=True, maximum=262144,
                             expected_path=READY_PATH)
    need(pin(ready_source) == READY_PIN, 'exact unchanged actual-readiness producer source')
    ready_raw = pool.read(ready_input['original'], maximum=1024*1024)
    ready = strict(ready_raw)
    need(ready['schema'] == 'hepta.r10.actual-readiness.v1'
         and ready['state'] == 'EXACT_COMBINATION_READY_TRANSPORT_ONLY'
         and ready['boot_id'] == BOOT and ready['policy_sha256'] == POLICY
         and ready['parent_policy_sha256'] == PARENT_POLICY
         and ready['health_qualified'] is False and ready['business19_qualified'] is False
         and ready['cold_boot_qualified'] is False
         and ready['model_requests'] == ready['task_submissions'] == ready['ui_actions'] == ready['signals_sent'] == 0,
         'raw READY must remain transport-only actual producer family')
    for key, digest in release['release_pins'].items():
        need(ready[key] == digest, 'READY pin differs from verified actual release: ' + key)
    need(ready['module_manifest_sha256'] == pin(manifest_raw)['sha256']
         and release['production_combination_manifest_sha256'] == pin(binding_raw)['sha256']
         and ready['source_seal_sha256'] == bound['provider_source_seal_sha256']
         and ready['configuration_sha256'] == bound['configuration_sha256']
         and ready['service_inputs_sha256'] == bound['service_inputs_sha256']
         and ready['component_boundary_inputs_sha256'] == bound['component_boundary_inputs_sha256']
         and ready['policy_adoption_inputs_sha256'] == bound['policy_adoption_inputs_sha256']
         and ready['component_boundary_sha256'] == bound['component_boundary_sha256']
         and ready['release_boundary_bundle_sha256'] == bound['release_boundary_bundle_sha256']
         and bound['policy_sha256'] == POLICY and bound['parent_policy_sha256'] == PARENT_POLICY,
         'actual installed module, READY and host BUILD tuple differ')
    exact(ready['roles'], FOUR, 'exact four actual readiness roles')
    exact(value['role_identity_originals'], FOUR, 'four original identity files required')
    identities = {}
    credentials = {'supervisor': ('u:r:magisk:s0', None),
                   'model': ('u:r:magisk:s0', '/data/local/tmp/hepta-phone-local-v150-r10-r1/bin/llama-server'),
                   'sidecar': ('u:r:trillionnium_owner_open_phone_executor:s0', '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6'),
                   'provider': ('u:r:magisk:s0', '/usr/bin/python3')}
    for role in FOUR:
        row = exact(ready['roles'][role], {'identity', 'state', 'domain', 'uid', 'gid', 'no_new_privs', 'exe'},
                    'complete actual READY role row')
        current = identity(row['identity'])
        raw = pool.read(value['role_identity_originals'][role], phone=True, maximum=128,
                        expected_path=CLAIM + '/' + role + '.identity')
        need(raw == (':'.join(map(str, current)) + '\n').encode(),
             'actual claim generation differs from raw READY')
        domain, executable = credentials[role]
        need(row['state'] in ('R', 'S', 'D', 'T', 't', 'K', 'W', 'P', 'I')
             and row['domain'] == domain and row['uid'] == row['gid'] == [0, 0, 0, 0]
             and row['no_new_privs'] == 0 and type(row['exe']) is str
             and (executable is None or row['exe'] == executable),
             'actual READY role credentials or selected executable differ')
        identities[role] = current
    need(len({row[0] for row in identities.values()}) == 4, 'resident generations collide')
    helper = load_reviewed(source_raw['helper'], source_rows['helper'], 'exact_reviewed_resident_helper')
    return helper, identities, source_rows, ready_input, module

def verify_bind_set(value, pool, helper, identities, source_rows):
    exact(value['child_bindings'], ROLES, 'exact three original guarded child bindings')
    supervisor = identities['supervisor']
    outputs = {}
    parent_samples = []
    last_end = 0
    helper_generations = set()
    bind_keys = {'schema', 'role', 'boot_id', 'pid', 'child_identity', 'parent_identity',
                 'helper_observation', 'parent_output_bind_observation', 'bind_observation_interval_boottime_ns',
                 'spawn_original', 'identity_original', 'child_before', 'child_after',
                 'parent_before', 'parent_after', 'regular_logs_initial', 'sources',
                 'qualification', 'task_qualification', 'signals_sent', 'wait_called_by_helper'}
    for role in ROLES:
        bind_row = value['child_bindings'][role]
        raw = pool.read(bind_row, phone=True, maximum=MAX_BIND,
                        expected_path=CLAIM + '/owner-' + role + '.bind.json')
        bind = exact(strict(raw, MAX_BIND), bind_keys, 'exact reviewed H05 child bind receipt')
        original = identities[role]
        need(bind['schema'] == 'hepta.resident-owner.child-binding.v1'
             and bind['role'] == role and bind['boot_id'] == BOOT and bind['pid'] == original[0]
             and bind['child_identity'] == original and bind['parent_identity'] == supervisor
             and bind['sources'] == source_rows
             and bind['qualification'] == 'PHONE_SOURCE_UNQUALIFIED'
             and bind['task_qualification'] is False and bind['signals_sent'] == 0
             and bind['wait_called_by_helper'] is False,
             'actual bind cannot replace a role, source, original wait or task qualification')
        frame = interval(bind['bind_observation_interval_boottime_ns'])
        need(last_end <= frame[0], 'original service model/sidecar/provider bind order differs')
        last_end = frame[1]
        proc_original(helper, bind['parent_before'], supervisor)
        proc_original(helper, bind['parent_after'], supervisor)
        proc_original(helper, bind['child_before'], original, supervisor)
        proc_original(helper, bind['child_after'], original, supervisor)
        bounded_helper = proc_original(helper, bind['helper_observation'], parent=supervisor)
        need(bounded_helper['pid'] not in {v[0] for v in identities.values()},
             'finite observer helper cannot be a resident role')
        generation = tuple(bounded_helper['identity'])
        need(generation not in helper_generations, 'three binds require distinct finite helper generations')
        helper_generations.add(generation)
        spawn = pool.read(bind['spawn_original'], phone=True, maximum=128,
                           expected_path=CLAIM + '/' + role + '.spawn-pid')
        need(spawn == (str(original[0]) + '\n').encode(), 'original service $! differs')
        need(bind['identity_original'] == value['role_identity_originals'][role],
             'bind must use the same exact original claim identity/full9')
        pool.read(bind['identity_original'], phone=True, maximum=128,
                  expected_path=CLAIM + '/' + role + '.identity')
        parent_samples.append((role, parent_outputs(helper, bind['parent_output_bind_observation'],
                                                    supervisor, frame)))
        exact(bind['regular_logs_initial'], STREAMS, 'both guarded child outputs required')
        for number, stream in ((1, 'stdout'), (2, 'stderr')):
            log = bind['regular_logs_initial'][stream]
            expected = (EXECUTOR_LOGS if role == 'sidecar' else CLAIM) + '/' + role + '.' + stream
            descriptor(log, phone=True, maximum=0, expected_path=expected)
            need(log['bytes'] == log['metadata'][6] == 0 and log['sha256'] == EMPTY_SHA,
                 'guarded original child log must be empty before service admission')
            outputs[role + '.' + stream] = {
                'role': role, 'stream': stream, 'fd': number, 'kind': 'regular_file',
                'path': expected, 'initial_metadata': log['metadata'],
                'origin': 'SOURCE_BOUND_GUARDED_CHILD_BIND',
                'origin_bindings': [exact3(bind_row)],
                'initial_empty_bytes_sha256': EMPTY_SHA,
                'independent_child_fd_target_stat_raw_retained': False,
                'child_fd_match_basis': 'REVIEWED_H05_PRODUCER_ASSERTION_AND_INITIAL_LOG_ORIGINAL',
                'pipe_eof_claimed': False}
    for number, stream in ((1, 'stdout'), (2, 'stderr')):
        first = parent_samples[0][1][stream]
        for _, sample in parent_samples[1:]:
            row = sample[stream]
            need(row['kind'] == first['kind'] and row['before_full9'][:6] == first['before_full9'][:6]
                 and row['specified_regular_path'] == first['specified_regular_path']
                 and row['flags'] == first['flags'],
                 'same supervisor output inode/type/access required across all three original binds')
        outputs['supervisor.' + stream] = {
            'role': 'supervisor', 'stream': stream, 'fd': number, 'kind': first['kind'],
            'path': first['specified_regular_path'],
            'initial_metadata': first['before_full9'],
            'origin': 'DIRECT_PARENT_FD_AT_CHILD_BIND_ONLY',
            'origin_bindings': [exact3(value['child_bindings'][role]) for role in ROLES],
            'installer_start_fd_identity_proven': False,
            'initial_regular_contents_read': False, 'pipe_eof_claimed': False}
    names = [role + '.' + stream for role in FOUR for stream in STREAMS]
    need(set(outputs) == set(names) and len(outputs) == 8, 'complete typed four-role eight-stream set')
    streams = [outputs[name] for name in names]
    regular = [{'name': name, 'path': outputs[name]['path'],
                'initial_metadata': outputs[name]['initial_metadata']}
               for name in names if outputs[name]['kind'] == 'regular_file']
    nonregular = [outputs[name] for name in names if outputs[name]['kind'] != 'regular_file']
    inode_keys = [tuple(row['initial_metadata'][:2]) for row in regular]
    need(len(inode_keys) == len(set(inode_keys))
         and len({row['path'] for row in regular}) == len(regular),
         'fixed eight stream roles cannot alias a selected regular output inode/path')
    return streams, regular, nonregular

def verify_resident_output_bindings(binding_raw, *, read_pinned):
    need(RELEASE_READER is not None, 'UNBOUND_REVIEWED_ACTUAL_RELEASE_READER_NO_IO')
    value = exact(strict(binding_raw, 1024*1024), FIELDS, 'exact eight-stream input contract')
    need(value['schema'] == SCHEMA, 'eight-stream input family differs')
    pool = Originals(read_pinned)
    reader_raw = pool.read(RELEASE_READER, maximum=262144)
    release_reader = load_reviewed(reader_raw, RELEASE_READER, 'reviewed_actual_resident_release_reader')
    release_raw = pool.read(value['release_inputs'], maximum=1024*1024)
    release_inputs = strict(release_raw, 1024*1024)
    release = release_reader.verify_final_release_inputs(release_raw, read_pinned=read_pinned)
    need(release['schema'] == 'hepta.r10.actual-final-release-original-verdict.v1'
         and release['state'] == 'ACTUAL_HOST_RELEASE_ORIGINALS_VERIFIED_PHONE_READINESS_SEPARATE'
         and release['all_17_shared_bytes_equal'] is True and release['all_originals_bookended'] is True
         and release['component_package_sha256'] == RUNTIME
         and release['runtime_combination_sha256'] == COMBINATION
         and release['policy_sha256'] == POLICY
         and release['phone_ready'] is False and release['business_qualified'] is False
         and release['whole_case_pass'] is False and release['fixed19_credit'] == 0
         and release['phone_calls'] == release['model_calls'] == release['native_submissions'] == 0,
         'actual reviewed host BUILD originals required, never caller qualification booleans')
    helper, identities, sources, ready, module = verify_module_and_ready(value, pool, release, release_inputs)
    streams, selector, nonregular = verify_bind_set(value, pool, helper, identities, sources)
    pool.recheck()
    return {
        'schema': 'hepta.resident-owner.eight-stream-original-verdict.v1',
        'state': ('VERIFIED_EIGHT_STREAM_ORIGINAL_BINDINGS' if not nonregular else
                  'EIGHT_STREAM_ORIGINAL_BINDINGS_VERIFIED_NONREGULAR_OUTPUT_UNKNOWN'),
        'boot_id': BOOT, 'role_identities': identities,
        'selected_module_sources': sources,
        'module_originals': module, 'ready_originals': ready,
        'actual_release_reader': RELEASE_READER, 'actual_release_inputs': value['release_inputs'],
        'actual_build_result_sha256': release['actual_build_result_sha256'],
        'actual_build_originals_reverified': True,
        'release_pins': release['release_pins'],
        'eight_streams': streams, 'regular_selector': selector, 'nonregular_streams': nonregular,
        'complete_stream_origin_count': 8,
        'required_observer_source_pin': OBSERVER_PIN,
        'two_complete_original_O08_censuses_still_required': True,
        'READY_execution_authority_and_task_lifecycle_are_separate_gates': True,
        'nonregular_output_closure_state': 'UNKNOWN' if nonregular else 'NO_NONREGULAR_STREAMS',
        'all_selected_originals_bookended': True,
        'originals': [dict(row) for row, _raw in pool.rows.values()],
        'original_count': len(pool.rows), 'original_bytes_read': pool.total,
        'actual_release_binding_qualified': False, 'whole_resident_output_qualified': False,
        'whole_rollback_qualified': False, 'installer_start_fd_identity_proven': False,
        'supervisor_original_parent_wait': 'NOT_RETAINED', 'pipe_eof_claimed': False,
        'phone_calls': 0, 'processes_started': 0, 'native_case_credit': 0}
