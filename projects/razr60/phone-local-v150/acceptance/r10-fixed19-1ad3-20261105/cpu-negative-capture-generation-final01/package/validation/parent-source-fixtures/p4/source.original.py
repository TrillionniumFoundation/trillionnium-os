#!/usr/bin/env python3
"""Capture one existing P4 cancellation Actor, its sender and owner-once originals.

This source performs file reads and writes only to its new private evidence
directory. It never executes an Actor, transport, model, phone command or signal.
Default preview reads no plan, case directory or private input. Final dependency
pins and an explicit reviewed plan are required before any capture.
"""
import argparse
import base64
import errno
import gzip
import hashlib
import io
import json
import os
from pathlib import PurePosixPath as Path
import re
import stat
import sys
import tarfile
import time

SCHEMA = 'hepta.cpu-cancel.p4-original-capture.v1'
PLAN_SCHEMA = 'hepta.cpu-cancel.p4-original-capture-plan.v1'
P4 = '/home/alex/razr60-local-model-v150'
INPUT_BASE = P4 + '/cpu-cancel-p4-capture-inputs-r1'
OUTPUT_BASE = P4 + '/cpu-cancel-p4-original-captures-r1'
REVIEWED_OPERATOR_PACKAGE_SHA256 = '65720e417594205b45172fe509f3419d607d3dbf1e579b2a17faa8b40315ca10'
REVIEWED_ACTIVE_SOURCE_SHA256 = 'f1a68fcc420799a7221019afdcda046a8d297b23d674e1e2642e888df26635dd'
REVIEWED_CPU_VERIFIER_SOURCE_SHA256 = '7c30e54630d6b18fd69ccc50821ddefd9abcd25c6681fbfea35fa1e484782143'
ACTOR_SHA256 = 'd973891aa125ce2deb2237064fbc101d5d9d915d9e4bd75e25e4da298eecd5f1'
OPERATOR_NAMES = ('active_runtime_r10.py','cancel_native_once_r10.py','cancel_phase.py',
    'decode_client_state.py','native_journal_audit.py','observe_cancel_phase_r10.py',
    'production-pins.json','reviewed_page_projection.py')
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SCOPE = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
TRANSPORT_KEYS = ('launch_request','terminal_operation','stdout','stderr')
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 2048
MAX_DIRECTORY_FILES = 1024
MAX_SECONDS = 60.0
O_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def need(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def metadata(value):
    return {key: getattr(value, key) for key in META}

def canonical(path):
    need(type(path) is str and path.startswith('/') and '\x00' not in path,
         'explicit absolute path required')
    parts = path[1:].split('/')
    need(parts and all(part not in ('', '.', '..') for part in parts),
         'noncanonical path')
    need(str(Path(path)) == path, 'canonical path spelling differs')
    return path

def under(path, root):
    canonical(path)
    need(path.startswith(root + '/'), 'path outside the one explicit input namespace')
    return path

def parent_fd(path):
    canonical(path)
    parts = path[1:].split('/')
    fd = os.open('/', O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

def exact3(value, cap=MAX_FILE):
    need(type(value) is dict and set(value) == {'path','bytes','sha256'},
         'exact three-field descriptor required')
    canonical(value['path'])
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= cap
         and type(value['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None,
         'descriptor byte pin differs')
    return value

def fixed_dependencies():
    for value in (REVIEWED_OPERATOR_PACKAGE_SHA256, REVIEWED_ACTIVE_SOURCE_SHA256,
                  REVIEWED_CPU_VERIFIER_SOURCE_SHA256):
        need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
             'future final dependency pins are absent; capture is disabled')

def read_regular(path, cap, check_time):
    parent, leaf = parent_fd(path)
    fd = -1
    try:
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= cap, 'bounded regular single-link file required')
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        need(metadata(os.fstat(fd)) == metadata(before), 'original changed at open')
        chunks = []
        count = 0
        while True:
            check_time()
            chunk = os.read(fd, min(65536, cap + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            need(count <= cap, 'original exceeds byte limit')
        raw = b''.join(chunks)
        need(len(raw) == before.st_size
             and metadata(os.fstat(fd)) == metadata(before)
             == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False)),
             'original file bookends differ')
        return raw, metadata(before)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)

def observe_absence(path):
    """Only real ENOENT from a canonical held ancestor proves absence."""
    canonical(path)
    parts = path[1:].split('/')
    fd = os.open('/', O_DIRECTORY)
    walked = '/'
    try:
        for index, part in enumerate(parts):
            before = metadata(os.fstat(fd))
            try:
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'absence is unknown, not ENOENT')
                need(metadata(os.fstat(fd)) == before, 'absence ancestor changed')
                return {'ancestor': walked, 'metadata': before,
                    'missing_component': part, 'unresolved_suffix': parts[index:],
                    'errno': errno.ENOENT}
            if index == len(parts) - 1:
                raise ValueError('expected absent path exists')
            need(stat.S_ISDIR(st.st_mode), 'absence walk encountered non-directory or link')
            nxt = os.open(part, O_DIRECTORY, dir_fd=fd)
            need(metadata(os.fstat(nxt)) == metadata(st), 'absence ancestor changed at open')
            os.close(fd)
            fd = nxt
            walked = (walked.rstrip('/') + '/' + part)
        raise ValueError('absence path has no missing component')
    finally:
        os.close(fd)

def new_directory(path):
    parent, leaf = parent_fd(path)
    try:
        parent_stat = os.fstat(parent)
        need(parent_stat.st_uid == os.geteuid() and stat.S_IMODE(parent_stat.st_mode) == 0o700,
             'existing output parent must already be private and owned')
        os.mkdir(leaf, 0o700, dir_fd=parent)
        fd = os.open(leaf, O_DIRECTORY, dir_fd=parent)
        try:
            st = os.fstat(fd)
            need(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
                 'new private output directory differs')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)

def put(path, raw):
    parent, leaf = parent_fd(path)
    fd = -1
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'output write stopped')
            view = view[count:]
        os.fsync(fd)
        os.fsync(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)
    actual, _ = read_regular(path, max(len(raw), 1), lambda: None)
    need(actual == raw, 'new output readback differs')
    return {'path': path, 'bytes': len(raw), 'sha256': sha(raw)}

class Capture:
    def __init__(self):
        self.started = time.monotonic()
        self.originals = {}
        self.retained = {}
        self.directories = []
        self.absences = []
        self.total = 0
        self.retained_total = 0

    def clock(self):
        need(time.monotonic() - self.started <= MAX_SECONDS, 'capture time bound exceeded')

    def file(self, path, relative, pin=None, cap=MAX_FILE):
        self.clock()
        need(type(relative) is str and not relative.startswith('/')
             and all(x not in ('', '.', '..') for x in relative.split('/')),
             'retained relative name differs')
        raw, info = read_regular(path, cap, self.clock)
        if pin is not None:
            exact3(pin, cap)
            need(path == pin['path'] and (len(raw), sha(raw)) == (pin['bytes'], pin['sha256']),
                 'explicit original byte pin differs')
        original = {'source': path, 'bytes': len(raw), 'sha256': sha(raw), 'metadata': info}
        if path in self.originals:
            old, old_raw = self.originals[path]
            need(old == original and old_raw == raw, 'repeated original differs')
        else:
            self.total += len(raw)
            need(self.total <= MAX_TOTAL and len(self.originals) < MAX_FILES,
                 'complete original pool exceeds bound')
            self.originals[path] = (original, raw)
        need(relative not in self.retained, 'retained archive name reused')
        self.retained_total += len(raw)
        need(self.retained_total <= MAX_TOTAL, 'all retained copies exceed complete byte bound')
        self.retained[relative] = raw
        return {**original, 'retained': {'path': relative, 'bytes': len(raw), 'sha256': sha(raw)}}

    def absence(self, path):
        first, second = observe_absence(path), observe_absence(path)
        need(first == second, 'double absence observations differ')
        result = {'schema': 'hepta.canonical-path-absence.v1', 'source': path,
            'canonical_ancestor': {'source': first['ancestor'],
                'metadata_before': first['metadata'], 'metadata_after': second['metadata']},
            'missing_component': first['missing_component'],
            'unresolved_suffix': first['unresolved_suffix'],
            'observations': [{'errno': errno.ENOENT}, {'errno': errno.ENOENT}],
            'final_observations': []}
        self.absences.append((result, first))
        return result

    def directory(self, path, prefix):
        try:
            parent, leaf = parent_fd(path)
        except OSError as error:
            need(error.errno == errno.ENOENT, 'directory ancestor read is unknown, not absent')
            return None, {}, self.absence(path)
        fd = -1
        try:
            try:
                fd = os.open(leaf, O_DIRECTORY, dir_fd=parent)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'directory is neither real nor proven absent')
                return None, {}, self.absence(path)
            before = metadata(os.fstat(fd))
            need(stat.S_ISDIR(before['st_mode']) and before['st_uid'] == os.geteuid()
                 and not (before['st_mode'] & 0o022), 'original directory identity or writer permissions differ')
            names = sorted(os.listdir(fd))
            need(len(names) <= MAX_DIRECTORY_FILES and len(names) == len(set(names))
                 and all(re.fullmatch('[A-Za-z0-9._-]{1,192}', n) is not None
                         and n not in ('.','..') for n in names), 'directory name/count bound differs')
            rows = {}
            for name in names:
                self.clock()
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                     'unreviewed nested directory, link or special file in complete census')
                rows[name] = self.file(path + '/' + name, prefix + '/' + name)
            after = metadata(os.fstat(fd))
            need(before == after == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
                 and names == sorted(os.listdir(fd)), 'complete directory bookends differ')
            row = {'source': path, 'metadata_before': before, 'metadata_after': after,
                   'names_before': names, 'names_after': list(names)}
            self.directories.append(row)
            return row, rows, None
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent)

    def optional_file(self, path, relative, cap=MAX_FILE):
        try:
            return self.file(path, relative, cap=cap), None
        except OSError as error:
            need(error.errno == errno.ENOENT, 'optional file read is unknown, not absent')
            return None, self.absence(path)

    def recheck(self):
        for original, raw in self.originals.values():
            self.clock()
            current, info = read_regular(original['source'], MAX_FILE, self.clock)
            need(current == raw and info == original['metadata'],
                 'original bytes or full9 changed at final bookend')
        for row in self.directories:
            parent, leaf = parent_fd(row['source'])
            fd = -1
            try:
                fd = os.open(leaf, O_DIRECTORY, dir_fd=parent)
                need(metadata(os.fstat(fd)) == row['metadata_before']
                     == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
                     and sorted(os.listdir(fd)) == row['names_before'],
                     'complete directory final census differs')
                row['metadata_after'] = metadata(os.fstat(fd))
                row['names_after'] = sorted(os.listdir(fd))
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent)
        for row, first in self.absences:
            a, b = observe_absence(row['source']), observe_absence(row['source'])
            need(first == a == b, 'canonical final double absence differs')
            row['canonical_ancestor']['metadata_after'] = b['metadata']
            row['final_observations'] = [{'errno': errno.ENOENT}, {'errno': errno.ENOENT}]

def validate_plan(value, plan_path):
    keys = {'schema','case_id','capture_label','actor_label','sender_label',
        'owner_request_sha256','expected_scope','actor_plan','operator_package',
        'operator_sources','cpu_verifier_source','transport_originals','out'}
    need(type(value) is dict and set(value) == keys and value['schema'] == PLAN_SCHEMA,
         'exact capture plan fields required')
    need(value['case_id'] in ('NEG-08','NEG-09'), 'only the two existing cancellation contracts')
    for key in ('capture_label','actor_label','sender_label'):
        need(type(value[key]) is str and re.fullmatch('[a-z0-9-]{1,70}', value[key]) is not None,
             'explicit existing-case label required')
    need(type(value['owner_request_sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', value['owner_request_sha256']) is not None,
         'actual owner request hash required')
    scope = value['expected_scope']
    need(scope is None or (type(scope) is dict and set(scope) == set(SCOPE)
         and scope['profile_id'] == 'owner-open'
         and all(type(scope[k]) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,256}', scope[k])
                 for k in SCOPE)), 'explicit expected scope or unknown null required')
    root = INPUT_BASE + '/' + value['capture_label']
    need(plan_path == root + '/PLAN.json', 'capture plan must be the exact new retained input')
    need(value['out'] == OUTPUT_BASE + '/' + value['capture_label'], 'new output namespace differs')
    for key, cap in (('actor_plan',65536),('operator_package',65536),('cpu_verifier_source',1048576)):
        under(exact3(value[key], cap)['path'], root)
    need(type(value['operator_sources']) is dict and set(value['operator_sources']) == set(OPERATOR_NAMES),
         'exact eight original operator sources required')
    for row in value['operator_sources'].values():
        under(exact3(row,1048576)['path'], root)
    need(value['operator_package']['sha256'] == REVIEWED_OPERATOR_PACKAGE_SHA256
         and value['operator_sources']['active_runtime_r10.py']['sha256'] == REVIEWED_ACTIVE_SOURCE_SHA256
         and value['operator_sources']['cancel_native_once_r10.py']['sha256'] == ACTOR_SHA256
         and value['cpu_verifier_source']['sha256'] == REVIEWED_CPU_VERIFIER_SOURCE_SHA256,
         'final frozen dependencies differ')
    transport = value['transport_originals']
    need(type(transport) is dict and set(transport) == {'actor','sender'},
         'actor and sender transport records must be separate')
    for role, records in transport.items():
        need(type(records) is dict and set(records) == set(TRANSPORT_KEYS),
             'explicit four transport fields required, null means unavailable')
        for row in records.values():
            if row is None:
                continue
            need(type(row) is dict and set(row) == {'original','retained_on_p4'},
                 'explicit original-to-retained transport mapping required')
            exact3(row['original'])
            under(exact3(row['retained_on_p4'])['path'], root)
            need({k:row['original'][k] for k in ('bytes','sha256')} ==
                 {k:row['retained_on_p4'][k] for k in ('bytes','sha256')},
                 'transport retained copy bytes differ')
    return root

def reviewed_inputs(capture, plan):
    result = {}
    for key, cap in (('actor_plan',65536),('operator_package',65536),('cpu_verifier_source',1048576)):
        result[key] = capture.file(plan[key]['path'], 'inputs/' + key + '.original', plan[key], cap)
    result['operator_sources'] = {}
    for name in OPERATOR_NAMES:
        row = plan['operator_sources'][name]
        result['operator_sources'][name] = capture.file(row['path'], 'sources/' + name, row,1048576)
    manifest = strict(capture.retained[result['operator_package']['retained']['path']])
    need(manifest.get('schema') == 'hepta.r10.native-cancel-operator-package.v1'
         and type(manifest.get('files')) is list and len(manifest['files']) == 8,
         'frozen operator manifest schema or exact source count differs')
    expected = {'source/'+name: {'path':'source/'+name,
        'bytes':plan['operator_sources'][name]['bytes'],
        'sha256':plan['operator_sources'][name]['sha256']} for name in OPERATOR_NAMES}
    need(len({row['path'] for row in manifest['files']}) == 8
         and {row['path']:row for row in manifest['files']} == expected,
         'all eight raw operator sources must match their actual manifest')
    actor_plan = strict(capture.retained[result['actor_plan']['retained']['path']])
    for key, expected_value in (('schema','hepta.r10.native-cancel-once-plan.v1'),
        ('label',plan['actor_label']),('sender_label',plan['sender_label']),
        ('case_id',plan['case_id']),('owner_request_sha256',plan['owner_request_sha256'])):
        need(actor_plan.get(key) == expected_value, 'actual Actor plan binding differs')
    owner = base64.b64decode(actor_plan['request_b64'], validate=True)
    need(20 <= len(owner) <= 16000 and sha(owner) == plan['owner_request_sha256'],
         'actual Actor owner bytes differ')
    return result, actor_plan, owner

def transport_inputs(capture, plan):
    result = {}
    for role in ('actor','sender'):
        result[role] = {}
        for key in TRANSPORT_KEYS:
            mapping = plan['transport_originals'][role][key]
            if mapping is None:
                result[role][key] = None
                continue
            row = mapping['retained_on_p4']
            copy = capture.file(row['path'], 'transport/'+role+'-'+key+'.original', row)
            result[role][key] = {'original_descriptor': mapping['original'],
                'captured_copy': copy, 'original_metadata_not_claimed_from_copy': True}
    return result

def capture_existing(capture, plan, actor_plan, owner):
    actor_path = P4 + '/cancel-native-r10/' + plan['actor_label']
    sender_path = '/home/alex/codex-hepta-natural-' + plan['sender_label'] + '-root-v150'
    once_path = P4 + '/native-cancel-intents-r10/' + plan['owner_request_sha256'] + '.json'
    actor, actor_rows, actor_absent = capture.directory(actor_path, 'actor')
    sender, sender_rows, sender_absent = capture.directory(sender_path, 'sender')
    once, once_absent = capture.optional_file(once_path, 'owner-once/reservation.original.json',65536)
    plan_raw = capture.retained['inputs/actor_plan.original']
    if 'PLAN.original.json' in actor_rows:
        need(capture.retained['actor/PLAN.original.json'] == plan_raw,
             'captured Actor trace belongs to a different original plan')
    if 'SEND.once.json' in sender_rows:
        row = strict(capture.retained['sender/SEND.once.json'])
        need(row.get('prompt_sha256') == plan['owner_request_sha256']
             and type(row.get('prompt')) is str and row['prompt'].encode('utf-8') == owner,
             'captured sender belongs to a different owner request')
    if once is not None:
        value = strict(capture.retained['owner-once/reservation.original.json'])
        need(value.get('plan_sha256') == sha(plan_raw) and value.get('out') == actor_path
             and value.get('one_operator_sequence_reserved') is True
             and value.get('automatic_retry') is False, 'owner-once original binding differs')
        if plan['expected_scope'] is not None:
            need(value.get('scope') == plan['expected_scope'], 'owner-once actual scope differs')
    return {'actor_directory':actor,'actor_originals':actor_rows,'actor_absence':actor_absent,
        'sender_directory':sender,'sender_originals':sender_rows,'sender_absence':sender_absent,
        'once_reservation':once,'once_absence':once_absent,
        'actor_required_cpu_records_missing': sorted(set(('PLAN.original.json','BEGIN.json',
            'PHASE-ARMED.json','CANCEL-PHASE-WINDOW.json','CANCEL-ONCE.intent.json','RESULT.json'))-set(actor_rows)),
        'actor_failure_original_present':'FAILURE.json' in actor_rows,
        'sender_failure_original_present':'ACTOR-FAILURE.json' in sender_rows}

def write_retained(out, values):
    directories = set()
    for relative, raw in sorted(values.items()):
        parts = relative.split('/')
        current = out + '/retained'
        if current not in directories:
            new_directory(current)
            directories.add(current)
        for part in parts[:-1]:
            current += '/' + part
            if current not in directories:
                new_directory(current)
                directories.add(current)
        put(current + '/' + parts[-1], raw)

def archive(out, values, report_raw, check_time):
    path = out + '/ORIGINALS.tar.gz'
    parent, leaf = parent_fd(path)
    fd = -1
    try:
        fd = os.open(leaf, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as zipped:
                with tarfile.open(fileobj=zipped,mode='w',format=tarfile.GNU_FORMAT) as tf:
                    members = dict(values)
                    members['CAPTURE.original.json'] = report_raw
                    for name, raw in sorted(members.items()):
                        check_time()
                        item = tarfile.TarInfo(name)
                        item.size = len(raw); item.mode = 0o600
                        item.uid = item.gid = 0; item.mtime = 0
                        tf.addfile(item,io.BytesIO(raw))
            stream.flush()
            os.fsync(fd)
        need(os.fstat(fd).st_size <= MAX_TOTAL, 'archive byte bound exceeded')
        os.fsync(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)
    raw, _ = read_regular(path,MAX_TOTAL,check_time)
    return {'path':path,'bytes':len(raw),'sha256':sha(raw)}

def preview():
    return {'schema':SCHEMA,'state':'SOURCE_PREVIEW_NO_CASE_OR_PLAN_READ',
        'final_dependency_pins_available':all(type(v) is str for v in
            (REVIEWED_OPERATOR_PACKAGE_SHA256,REVIEWED_ACTIVE_SOURCE_SHA256,REVIEWED_CPU_VERIFIER_SOURCE_SHA256)),
        'required_plan_schema':PLAN_SCHEMA,'maximum_original_file_bytes':MAX_FILE,
        'maximum_total_original_bytes':MAX_TOTAL,'maximum_original_files':MAX_FILES,
        'per_directory_file_count_maximum':MAX_DIRECTORY_FILES,'maximum_capture_seconds':MAX_SECONDS,
        'input_namespace':INPUT_BASE,'output_namespace':OUTPUT_BASE,
        'complete_actor_sender_census_required':True,'nullable_owner_once_requires_double_canonical_ENOENT':True,
        'transport_originals_are_raw_evidence_not_summary':True,
        'private_original_bodies_printed':False,'action_counter_scope':'this_capture_process_only',
        'existing_actor_ui_actions_not_summarized':True,'phone_calls':0,'actor_executions':0,
        'new_native_nonces':0,'cpu_qualification_assessed':False,'native_case_closure_claimed':False,
        'automatic_retry':False}

def execute(args):
    fixed_dependencies()  # Before reading any plan, case, owner or output path.
    need(args.plan is not None and args.plan_sha256 is not None
         and args.reviewed_source_sha256 is not None,'explicit reviewed source and plan required')
    canonical(args.plan)
    under(args.plan,INPUT_BASE)
    need(re.fullmatch('[0-9a-f]{64}',args.plan_sha256) is not None
         and re.fullmatch('[0-9a-f]{64}',args.reviewed_source_sha256) is not None,
         'reviewed byte hashes required')
    capture = Capture()
    source_path = os.path.abspath(__file__)
    source_row = capture.file(source_path,'inputs/CAPTURE-SOURCE.original.py',cap=1048576)
    need(source_row['sha256'] == args.reviewed_source_sha256,'capture source pin differs')
    plan_row = capture.file(args.plan,'inputs/CAPTURE-PLAN.original.json',cap=2*1024*1024)
    need(plan_row['sha256'] == args.plan_sha256,'capture plan pin differs')
    plan = strict(capture.retained['inputs/CAPTURE-PLAN.original.json'])
    validate_plan(plan,args.plan)
    inputs, actor_plan, owner = reviewed_inputs(capture,plan)
    transport = transport_inputs(capture,plan)
    out = plan['out']
    new_directory(out)
    intent = put(out+'/INTENT.json',encoded({
        'schema':'hepta.cpu-cancel.p4-capture-intent.v1','source':source_row,'plan':plan_row,
        'case_id':plan['case_id'],'maximum_capture_attempts':1,'automatic_retry':False,
        'new_actor_executions':0,'phone_calls':0,'new_native_nonces':0}))
    copies_started = False
    try:
        case = capture_existing(capture,plan,actor_plan,owner)
        capture.recheck()
        report = {'schema':SCHEMA,'state':'ORIGINAL_FILES_CAPTURED_CPU_ELIGIBILITY_NOT_ASSESSED',
            'source':source_row,'plan':plan_row,'intent':intent,'case_id':plan['case_id'],
            'capture_label':plan['capture_label'],'actor_label':plan['actor_label'],
            'sender_label':plan['sender_label'],'owner_request_sha256':plan['owner_request_sha256'],
            'expected_scope':plan['expected_scope'],'reviewed_inputs':inputs,
            'transport_originals':transport,**case,
            'original_file_count':len(capture.originals),'original_raw_bytes':capture.total,
            'retained_member_count':len(capture.retained),'retained_raw_bytes':capture.retained_total,
            'all_original_full9_and_bytes_rechecked':True,
            'complete_directory_census_bookends_equal':True,
            'transport_completion_or_parent_wait_claimed':False,'cpu_qualification_assessed':False,
            'physical_case_pass':False,'native_case_closure_claimed':False,'private_original_bodies_printed':False,
            'action_counter_scope':'this_capture_process_only','existing_actor_ui_actions_not_summarized':True,
            'phone_calls':0,'actor_executions':0,'model_requests':0,'signals':0,
            'new_native_nonces':0,'automatic_retry':False}
        raw = encoded(report)
        need(len(raw)<=4*1024*1024,'capture metadata report bound exceeded')
        copies_started = True
        write_retained(out,capture.retained)
        capture.recheck()
        need(encoded(report)==raw,'capture metadata changed during retained copy')
        report_row = put(out+'/CAPTURE.original.json',raw)
        archive_row = archive(out,capture.retained,raw,capture.clock)
        capture.recheck()
        need(encoded(report)==raw,'final archive read bookends changed capture report')
        result = {'schema':'hepta.cpu-cancel.p4-capture-result.v1','state':report['state'],
            'capture':report_row,'archive':archive_row,'original_file_count':len(capture.originals),
            'original_raw_bytes':capture.total,'archive_member_count':len(capture.retained)+1,
            'originals_rechecked_after_archive':True,'phone_calls':0,'new_actor_executions':0,
            'new_native_nonces':0,'cpu_qualification_assessed':False,'native_case_closure_claimed':False,
            'automatic_retry':False}
        result_row = put(out+'/RESULT.json',encoded(result))
        print(encoded({'state':result['state'],'result':result_row,'capture':report_row,
                       'archive':archive_row,'phone_calls':0,'cpu_qualification_assessed':False}).decode(),end='')
        return 0
    except BaseException as error:
        partial_copy_error = None
        if not copies_started:
            copies_started = True
            try:
                write_retained(out,capture.retained)
            except BaseException as copy_error:
                partial_copy_error = type(copy_error).__name__
        failure = {'schema':'hepta.cpu-cancel.p4-capture-failure.v1','state':'INCOMPLETE_CAPTURE_RETAINED_NO_RETRY',
            'source':source_row,'plan':plan_row,'intent':intent,'error_type':type(error).__name__,
            'error':str(error)[:512],'captured_original_count':len(capture.originals),
            'partial_originals':[value[0] for value in capture.originals.values()],
            'retained_relative_members':sorted(capture.retained),'partial_copy_error_type':partial_copy_error,
            'originals_claimed_complete':False,'cpu_qualification_assessed':False,
            'native_case_closure_claimed':False,'phone_calls':0,'actor_executions':0,
            'new_native_nonces':0,'automatic_retry':False}
        row = put(out+'/FAILURE.json',encoded(failure))
        print(encoded({'state':failure['state'],'failure':row,'phone_calls':0}).decode(),end='')
        return 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan')
    parser.add_argument('--plan-sha256')
    parser.add_argument('--reviewed-source-sha256')
    parser.add_argument('--execute-host-only',action='store_true')
    args = parser.parse_args()
    if not args.execute_host_only:
        print(encoded(preview()).decode(),end='')
        return 0
    os.umask(0o077)
    return execute(args)

if __name__ == '__main__':
    raise SystemExit(main())
