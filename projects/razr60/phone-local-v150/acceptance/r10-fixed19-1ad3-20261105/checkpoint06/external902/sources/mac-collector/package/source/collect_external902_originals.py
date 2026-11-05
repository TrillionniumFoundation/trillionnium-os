#!/usr/bin/env python3
"""Read fixed external902 originals; preserve unjoined sender history and create a separate byte copy."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
R = B / 'root-fixed19-1ad3-20261105-r1'
SOURCE = B / 'native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01'
OUT = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-fixed19-1ad3-20261105-r1/external902-7c907661-mac-originals01')
LABEL = 'root-r10-neg01-7c907661-01'
NONCE = '902e851c3ca1f90deab3d880ab993774'
FIXED_CASE_PINS = {'ROOT-PLAN.original.json': (4783, '9a94108ffc737133ba879bd9cccd70c7ec3ae2f3da17eb689e5b1d5610789d58'), 'ROOT-FAILURE.json': (20867, '25f7bca3dfd2f10308e2d430704db54e393c12bd0add116065ff8666be85320b'), 'CHAIN-INTENT.json': (363, '13cc6b10faee047287e5c0e599de51425e4b8d043cf36dfb96b5517e825aa3ff'), 'material/PREPARED.json': (2873, 'a8b8b355a9bde5db21123cf503be5f62a24d55226e154ce5ed95a428347d1898')}
PHASES = ('prepare-material', 'host-stage-material', 'phone-push-material', 'phone-copy-material', 'phone-push-stage-source', 'phone-copy-stage-source', 'phone-stage', 'sender-preview', 'sender-prepared', 'phone-launch', 'phone-plan-setup', 'store-plan-setup', 'fixture-setup', 'fixture-originals-setup', 'pack-setup', 'phone-push-witness-setup', 'phone-copy-witness-setup', 'phone-publish-setup', 'phone-plan-before-guard')
SOURCE_PACKAGES = {'runtime-originals': {'root': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime', 'manifest_name': 'MANIFEST.json', 'manifest': {'bytes': 16808, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/MANIFEST.json', 'sha256': '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'}, 'files': [{'bytes': 1438, 'path': 'reference/REVIEWED-PRODUCTION-PINS.json', 'sha256': '73963fdcea527cdbc3628bdeff5918f7106afbaf095fb183e4b199391e46a7a5'}, {'bytes': 664638, 'path': 'reference/attempt05-AFTER-INVENTORY.original.json', 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}, {'bytes': 164095, 'path': 'reference/attempt05-CLOSURE.original.json', 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, {'bytes': 4650, 'path': 'reference/attempt05-SIDE-PROOF.original.json', 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, {'bytes': 18133, 'path': 'reference/component_common_r5.py', 'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'}, {'bytes': 13238, 'path': 'reference/component_core.py', 'sha256': '705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'}, {'bytes': 30647, 'path': 'reference/component_once_r9.py', 'sha256': '1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'}, {'bytes': 4116, 'path': 'reference/decode_client_state.py', 'sha256': 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'}, {'bytes': 53502, 'path': 'reference/environment_parent_late_boundary_r6.py', 'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'}, {'bytes': 28109, 'path': 'reference/native_guard_session.py', 'sha256': '77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b'}, {'bytes': 6701, 'path': 'reference/native_journal_audit.py', 'sha256': 'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'}, {'bytes': 19740, 'path': 'reference/non_native_attempt05.py', 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}, {'bytes': 35730, 'path': 'reference/policy_parent_late_boundary_r4.py', 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'}, {'bytes': 62434, 'path': 'reference/property_parent_late_boundary_r7.py', 'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'}, {'bytes': 40788, 'path': 'reference/send_new_native_task_r5.py', 'sha256': '5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}, {'bytes': 17390, 'path': 'reference/tool_client_r6.py', 'sha256': '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'}, {'bytes': 99120, 'path': 'source/close_component.py', 'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'}, {'bytes': 19138, 'path': 'source/component_common.py', 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, {'bytes': 40261, 'path': 'source/component_lifecycle.py', 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, {'bytes': 38823, 'path': 'source/component_listener.py', 'sha256': 'ad345c0080cbfd89f1378bb6e8583f43e1fa4af0a5928d7ecbf4ccc8d4f04c52'}, {'bytes': 24187, 'path': 'source/component_snapshot.py', 'sha256': '2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa'}, {'bytes': 74287, 'path': 'source/late_boundary.py', 'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}, {'bytes': 28878, 'path': 'source/native_guard_session_r2.py', 'sha256': '5fe50be4dccbe655a39124876d1f9c2199de20d80ec0a84f08a63d88e7f1a931'}, {'bytes': 4633, 'path': 'source/native_proc_profile.py', 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, {'bytes': 14259, 'path': 'source/prepare_component.py', 'sha256': '46a28fd77dc64d94ccdd4c1f3e12912e22ebb39defc29b69991df831d75afc7d'}, {'bytes': 18728, 'path': 'source/root_fixture_once.py', 'sha256': 'bb70017c4f184efc0c9372ab072fa2d11a1cf7cbd3276257fa7b3605a426e0d1'}, {'bytes': 39149, 'path': 'source/root_fixture_originals.py', 'sha256': 'c1cd1402888de5bc4176255269014995e9d39dc658912d3c28a117ec51010f9e'}, {'bytes': 10498, 'path': 'source/run_root_fixture_phase.py', 'sha256': 'bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2'}, {'bytes': 40952, 'path': 'source/send_new_native_guard_task_r10_r4.py', 'sha256': 'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad'}, {'bytes': 18666, 'path': 'source/sender_native_guard_ready_r10_r4.py', 'sha256': 'f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99'}, {'bytes': 19116, 'path': 'source/stage_component.py', 'sha256': '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340'}, {'bytes': 18137, 'path': 'source/witness_bundle.py', 'sha256': 'f949ae3d6cec26bf98448fd0ac20b1f46472190be022d6532b1973177e0edfca'}]}, 'root-source-originals': {'root': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/root-chain', 'manifest_name': 'SOURCE-MANIFEST.json', 'manifest': {'bytes': 11894, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/root-chain/SOURCE-MANIFEST.json', 'sha256': 'f865ae8b2edaf8c8f3076fc299796b953f66af7f848042b68932d76aaaab67c6'}, 'files': [{'bytes': 126796, 'path': 'reference/policy_native5_verifier.py', 'sha256': '74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}, {'bytes': 8098, 'path': 'source/phone_chain_bridge.py', 'sha256': '72564868d7162281e34172d6163c0fb39a20c55ab24d3e8534347912e2680d27'}, {'bytes': 72194, 'path': 'source/run_component_root_once.py', 'sha256': 'f98ca61da43f0d62604701a1e4dc1d58df03cbb6e0cd7566bf293e298f0b15e0'}]}}
ADDITIONAL_FIXED_FILES = {'sender-top-originals/root-r10-neg01-7c907661-01.send-result.json': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-01.send-result.json', 'bytes': 699, 'sha256': '97f1d13685636c03681120916abc20b357d0e47dfa594f1edfc22d40f68c24f5'}, 'sender-top-originals/root-r10-neg01-7c907661-01.local-once.json': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-01.local-once.json', 'bytes': 1178, 'sha256': '2a1bd1c330837c3dec9e1a880ca628e7e700ed7c1ac3a09d8c5896ddf3f076e9'}, 'source-provenance/membership-overlay-SOURCE-MANIFEST.json': {'bytes': 1959, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r8-membership-source-396d-candidate02/freezer/overlay/SOURCE-MANIFEST.json', 'sha256': '9ba3fc63742139d40ae25ca72e79179e5405f40b75651096f4d594a56a7c60db'}}
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
MAX_FILES = 2048
MAX_DIRECTORIES = 512
MAX_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 100


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('utf-8')


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def metadata(value):
    return [getattr(value, key) for key in META]


def descriptor(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def relative(value):
    need(type(value) is str and '\0' not in value, 'plain relative path required')
    path = PurePosixPath(value)
    need(value and not path.is_absolute() and str(path) == value
         and all(p not in ('', '.', '..') for p in path.parts), 'canonical relative path required')
    return path


def check_time(started):
    # Cooperative only: filesystem/compression syscalls are not preempted.
    need(time.monotonic() - started < MAX_SECONDS, 'collector observation budget exhausted')


def open_directory(path, parent=None, leaf=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical directory required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path if parent is None else leaf, flags, dir_fd=parent)
    try:
        value = os.fstat(fd)
        need(stat.S_ISDIR(value.st_mode) and metadata(value) == metadata(path.lstat()),
             'directory path/held identity differs')
        return fd, metadata(value)
    except BaseException:
        os.close(fd)
        raise


def check_directory(path, fd, expected, full=True):
    need(path.resolve(strict=True) == path, 'held directory path became noncanonical')
    held, named = metadata(os.fstat(fd)), metadata(path.lstat())
    need(held == named, 'held directory path identity differs')
    need(held == expected if full else held[:5] == expected[:5], 'directory changed across observation')


def read_file(path, parent_fd, leaf, expected=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(leaf, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= MAX_BYTES, 'bounded single-link original file required')
        if expected is not None:
            need(metadata(before) == expected, 'original file identity changed before re-read')
        chunks = []
        total = 0
        while total <= before.st_size:
            part = os.read(fd, min(65536, before.st_size + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        raw = b''.join(chunks)
        need(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
             == metadata(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False))
             == metadata(path.lstat()), 'original file bytes/identity raced')
        return raw, metadata(before)
    finally:
        os.close(fd)


def collect_tree(started, handles):
    files, directories = {}, {}
    total = 0

    def retain(path, name, parent_key, parent_fd, leaf, expected=None):
        nonlocal total
        relative(name)
        need(name not in files and len(files) < MAX_FILES, 'unique bounded original file required')
        info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode), 'only regular original files are collected')
        raw, original_metadata = read_file(path, parent_fd, leaf, metadata(info))
        if expected is not None:
            need(descriptor(path, raw) == expected, 'fixed additional original differs')
        total += len(raw)
        need(total <= MAX_BYTES, 'combined case/source/original byte budget exceeded')
        files[name] = {'raw': raw, 'metadata': original_metadata, 'parent': parent_key,
                       'leaf': leaf, 'descriptor': descriptor(path, raw)}
        check_time(started)

    def visit(path, name, parent_fd=None, leaf=None):
        check_time(started)
        relative(name)
        need(name not in handles and len(handles) < MAX_DIRECTORIES, 'unique bounded directory required')
        fd, first = open_directory(path, parent_fd, leaf)
        handles[name] = (path, fd, first)
        names = sorted(os.listdir(fd))
        need(len(names) <= MAX_FILES + MAX_DIRECTORIES, 'directory child count exceeded')
        directories[name] = {'path': str(path), 'archive_prefix': name, 'scope': 'complete_tree',
                             'metadata': first, 'names': names}
        for child in names:
            need(child not in ('', '.', '..') and '/' not in child and '\0' not in child,
                 'single direct child name required')
            child_name = name + '/' + child
            relative(child_name)
            info = os.stat(child, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                visit(path / child, child_name, fd, child)
            else:
                retain(path / child, child_name, name, fd, child)
            check_time(started)
        need(sorted(os.listdir(fd)) == names, 'directory child set changed during scan')
        check_directory(path, fd, first)

    visit(SOURCE, 'root-originals')
    for prefix, package in SOURCE_PACKAGES.items():
        visit(Path(package['root']), prefix)
    parent_keys = {}
    for archive_name, pin in ADDITIONAL_FIXED_FILES.items():
        path = Path(pin['path'])
        need(path.is_absolute() and path.resolve(strict=True) == path and B in path.parents,
             'fixed additional source path must stay inside B')
        parent = path.parent
        if parent not in parent_keys:
            key = 'pinned-parent-' + str(len(parent_keys))
            need(key not in handles and len(handles) < MAX_DIRECTORIES, 'pinned parent handle budget exceeded')
            fd, first = open_directory(parent)
            handles[key] = (parent, fd, first)
            names = sorted(os.listdir(fd))
            need(len(names) <= MAX_FILES + MAX_DIRECTORIES, 'pinned parent child-name budget exceeded')
            directories[key] = {'path': str(parent), 'archive_prefix': None,
                'scope': 'parent_identity_and_child_names_only_not_all_child_contents',
                'metadata': first, 'names': names}
            parent_keys[parent] = key
        key = parent_keys[parent]
        _, fd, first = handles[key]
        retain(path, archive_name, key, fd, path.name, pin)
        check_directory(parent, fd, first)
        need(sorted(os.listdir(fd)) == directories[key]['names'], 'pinned parent child set changed')
    return files, directories


def recheck_tree(files, directories, handles, started):
    check_time(started)
    for name, row in sorted(files.items()):
        relative(name)
        path = Path(row['descriptor']['path'])
        parent_path, parent_fd, parent_metadata = handles[row['parent']]
        need(path.parent == parent_path and path.name == row['leaf'], 'held original parent binding differs')
        check_directory(parent_path, parent_fd, parent_metadata)
        raw, current_metadata = read_file(path, parent_fd, row['leaf'], row['metadata'])
        need(raw == row['raw'] and current_metadata == row['metadata'],
             'original file changed across full observation bookend')
        check_time(started)
    for name, row in directories.items():
        path, fd, first = handles[name]
        check_directory(path, fd, first)
        need(sorted(os.listdir(fd)) == row['names'], 'observed directory child set changed')
    return {'checked_file_count': len(files), 'checked_directory_count': len(directories),
            'completed_unix_ns': time.time_ns(), 'completed_monotonic_ns': time.monotonic_ns()}


def verify_ended_failure(files):
    def raw(name):
        key = 'root-originals/' + str(relative(name))
        need(key in files, 'required case original absent: ' + name)
        return files[key]['raw']
    def value(name):
        return strict(raw(name))
    fixed = {}
    for name, pin in FIXED_CASE_PINS.items():
        body = raw(name)
        need((len(body), sha(body)) == pin, 'fixed external case original differs: ' + name)
        fixed[name] = strict(body)
    failure = fixed['ROOT-FAILURE.json']
    plan = fixed['ROOT-PLAN.original.json']
    chain = fixed['CHAIN-INTENT.json']
    prepared = fixed['material/PREPARED.json']
    need(plan['label'] == chain['label'] == prepared['label'] == LABEL
         and plan['nonce'] == chain['nonce'] == prepared['nonce'] == NONCE
         and plan['case_id'] == chain['case_id'] == prepared['case_id'] == 'NEG-01'
         and plan['out'] == str(SOURCE), 'fixed case identity differs')
    need(plan['package'] == SOURCE_PACKAGES['runtime-originals']['manifest']
         and plan['source_package'] == SOURCE_PACKAGES['root-source-originals']['manifest']
         and prepared['package_sha256'] == plan['package']['sha256'], 'fixed actual source package links differ')
    need(failure['state'] == 'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failure['signals_sent_by_coordinator'] == 0 and failure['send_again'] is False
         and failure['automatic_retry'] is False and failure['component_qualified'] is False
         and failure['business_qualified'] is False, 'retained failure ownership state differs')
    need([r['phase'] for r in failure['steps']] == list(PHASES) and len(PHASES) == 19,
         'exact nineteen original joined phases required')
    phase_proofs = []
    for step in failure['steps']:
        name = step['phase']
        result = value(name + '/RESULT.json')
        intent_raw = raw(name + '/INTENT.json')
        intent = strict(intent_raw)
        child = value(name + '/CHILD.json')
        capture = value(name + '/OUTPUT-CAPTURE.json')
        need(enc(result) == enc(step) and set(result) == {'state', 'phase', 'pid', 'returncode',
             'stdout', 'stderr', 'automatic_retry'} and result['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
             and result['returncode'] == 0 and type(result['pid']) is int and result['pid'] > 0
             and result['automatic_retry'] is False, 'actual joined host result differs')
        digest = sha(intent_raw)
        need(intent['phase'] == name and intent['maximum_starts'] == 1
             and intent['automatic_retry'] is False and intent['signals_on_timeout'] is False
             and child['source_intent_sha256'] == capture['source_intent_sha256'] == digest
             and child['pid'] == capture['pid'] == result['pid'], 'host intent/child/capture binding differs')
        need(capture['schema'] == 'hepta.native-guard.host-output-capture.v1'
             and capture['phase'] == name and capture['worker_started'] is True
             and capture['worker_joined'] is True and capture['child_wait_returned'] is True
             and capture['child_returncode'] == 0 and capture['stdout_eof'] is True
             and capture['stderr_eof'] is True and capture['prefix_only_or_unknown'] is False
             and capture['pipe_reader_owner'] == 'closed_by_worker' and capture['error'] is None
             and capture['persist_errors'] == [] and capture['pipe_close_errors'] == [],
             'complete original joined capture required')
        for stream in ('stdout', 'stderr'):
            key = name + '/' + stream + '.original'
            body = raw(key)
            exact = descriptor(SOURCE / key, body)
            held = capture['files'][stream]
            need(result[stream] == exact and {k: held[k] for k in exact} == exact
                 and held['original_created_inode_bound'] is True
                 and [held['metadata'][k] for k in META] == files['root-originals/' + key]['metadata']
                 and capture['captured'][stream] == {'bytes': len(body), 'sha256': sha(body)},
                 'joined output bytes/full9 identity differs')
        if intent['stdin_sha256'] is not None:
            need(sha(raw(name + '/stdin.original')) == intent['stdin_sha256'], 'retained stdin differs')
        phase_proofs.append({'phase': name, 'pid': result['pid'], 'returncode': 0,
            'result': files['root-originals/' + name + '/RESULT.json']['descriptor'],
            'capture': files['root-originals/' + name + '/OUTPUT-CAPTURE.json']['descriptor'],
            'original_host_child_joined': True, 'both_original_output_eofs': True})
    cleanup = failure['host_cleanup']
    need(cleanup['stream_cleanup_errors'] == [] and len(cleanup['host_children']) == 1,
         'exact original one-child unknown cleanup record required')
    unknown = cleanup['host_children'][0]
    need(unknown['phase'] == 'sender-execute' and unknown['pid'] == 54589
         and unknown['state'] == 'OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY'
         and unknown['returncode'] is None and unknown['signals_sent'] == 0
         and unknown['automatic_retry'] is False, 'original unjoined sender must remain unknown')
    capture = value('sender-execute/OUTPUT-CAPTURE.json')
    need(enc(capture) == enc(unknown['output_capture']), 'original unknown capture differs from fixed ROOT-FAILURE')
    intent_raw = raw('sender-execute/INTENT.json')
    intent = strict(intent_raw)
    child = value('sender-execute/CHILD.json')
    need(capture['pid'] == child['pid'] == 54589 and capture['phase'] == intent['phase'] == 'sender-execute'
         and capture['source_intent_sha256'] == child['source_intent_sha256'] == sha(intent_raw),
         'unknown sender original identity differs')
    need(capture['child_wait_returned'] is False and capture['child_returncode'] is None
         and capture['stdout_eof'] is False and capture['stderr_eof'] is False
         and capture['prefix_only_or_unknown'] is True and capture['remote_terminal_or_cleanup_proven'] is False
         and capture['worker_joined'] is True and capture['signals_sent'] == 0,
         'unknown sender cannot be upgraded to original join, EOF or cleanup')
    for stream in ('stdout', 'stderr'):
        key = 'sender-execute/' + stream + '.original'
        body = raw(key)
        exact = descriptor(SOURCE / key, body)
        held = capture['files'][stream]
        need(len(body) == 0 and {k: held[k] for k in exact} == exact
             and held['original_created_inode_bound'] is True
             and [held['metadata'][k] for k in META] == files['root-originals/' + key]['metadata']
             and capture['captured'][stream] == {'bytes': 0, 'sha256': sha(b'')},
             'original unknown sender prefix changed')
    if intent['stdin_sha256'] is not None:
        need(sha(raw('sender-execute/stdin.original')) == intent['stdin_sha256'], 'unknown sender retained stdin differs')
    return {'joined_original_host_phases': phase_proofs,
        'unjoined_sender_original': {'phase': 'sender-execute', 'pid': 54589,
            'state': unknown['state'], 'returncode': None, 'original_child_joined': False,
            'original_stdout_eof': False, 'original_stderr_eof': False,
            'original_remote_terminal_or_cleanup_proven': False,
            'capture': files['root-originals/sender-execute/OUTPUT-CAPTURE.json']['descriptor']},
        'retained_root_fixture_attempts': failure['root_fixture_attempts'],
        'later_root_result_file_observed': 'root-originals/ROOT-RESULT.json' in files,
        'no_new_case_qualification_from_collection': True}


def verify_source_packages(files):
    proofs = []
    for prefix, package in SOURCE_PACKAGES.items():
        manifest_name = prefix + '/' + package['manifest_name']
        body = files[manifest_name]['raw']
        need(files[manifest_name]['descriptor'] == package['manifest'], 'fixed manifest descriptor differs')
        manifest = strict(body)
        need(enc(manifest['files']) == enc(package['files']), 'fixed manifest exact member rows differ')
        expected = {manifest_name}
        for pin in package['files']:
            key = prefix + '/' + str(relative(pin['path']))
            need(key not in expected, 'duplicate fixed source member')
            expected.add(key)
            row = files[key]
            need(row['descriptor'] == {'path': str(Path(package['root']) / pin['path']),
                 'bytes': pin['bytes'], 'sha256': pin['sha256']}, 'fixed source body differs')
        need({name for name in files if name.startswith(prefix + '/')} == expected,
             'source package complete member set differs')
        proofs.append({'archive_prefix': prefix, 'manifest': package['manifest'],
            'exact_declared_members': len(package['files']), 'all_declared_source_bodies_read': True,
            'sources_imported_or_executed': False, 'runtime_eligibility_or_policy_adoption_revalidated': False})
    return proofs


def verify_sender_top_originals(files):
    for name, pin in ADDITIONAL_FIXED_FILES.items():
        need(files[name]['descriptor'] == pin, 'additional fixed original differs')
    result_pin = ADDITIONAL_FIXED_FILES['sender-top-originals/' + LABEL + '.send-result.json']
    local_pin = ADDITIONAL_FIXED_FILES['sender-top-originals/' + LABEL + '.local-once.json']
    result = strict(files['sender-top-originals/' + LABEL + '.send-result.json']['raw'])
    local = strict(files['sender-top-originals/' + LABEL + '.local-once.json']['raw'])
    terminal = strict(result['stdout'])
    need(result['rc'] == 0 and terminal['state'] == 'ORIGINAL_NATIVE_TERMINAL_OBSERVED'
         and terminal['native_status'] == 'provider_failed' and terminal['send_attempt_count'] == 1
         and terminal['automatic_replay'] is False and terminal['business_success_verified'] is False,
         'fixed later sender top record differs')
    need(local['task'] == LABEL and local['prompt_sha256'] == terminal['prompt_sha256']
         and NONCE in local['prompt'] and local['automatic_replay'] is False,
         'fixed sender local-once identity differs')
    return {'send_result': result_pin, 'local_once': local_pin,
        'recorded_native_status': terminal['native_status'], 'recorded_send_attempt_count': 1,
        'top_record_is_not_original_parent_join_or_output_EOF': True,
        'full_native_cleanup_or_boundary_publication_verified_by_collector': False}


def put_new(directory_fd, path, raw):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES + 4 * 1024 * 1024, 'bounded new evidence output required')
    fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory_fd)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == 0
             and first.st_uid == os.geteuid() and stat.S_IMODE(first.st_mode) == 0o600,
             'new private regular evidence inode required')
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:offset + 65536])
            need(count > 0, 'new evidence short write')
            offset += count
        os.fsync(fd)
        final = metadata(os.fstat(fd))
        need(final[:5] == metadata(first)[:5] and final == metadata(path.lstat()),
             'created evidence inode replaced')
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        count = 0
        while count <= len(raw):
            block = os.read(fd, min(65536, len(raw) + 1 - count))
            if not block:
                break
            digest.update(block)
            count += len(block)
        need(count == len(raw) and digest.hexdigest() == sha(raw)
             and final == metadata(os.fstat(fd)) == metadata(path.lstat()),
             'new evidence readback differs')
        os.fsync(directory_fd)
        return {**descriptor(path, raw), 'metadata': final}
    finally:
        os.close(fd)


def main():
    started = time.monotonic()
    start_unix_ns = time.time_ns()
    handles = {}
    parent_fd = out_fd = None
    out_identity = None
    try:
        need(type(COLLECTOR_SOURCE) is bytes and len(COLLECTOR_SOURCE) <= 65536,
             'exact controller-retained collector source required')
        files, directories = collect_tree(started, handles)
        case_proof = verify_ended_failure(files)
        source_proofs = verify_source_packages(files)
        sender_top_proof = verify_sender_top_originals(files)
        before_write = recheck_tree(files, directories, handles, started)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, row in sorted(files.items()):
                member = tarfile.TarInfo(str(relative(name)))
                member.size = len(row['raw'])
                member.mode = 0o600
                member.uid = member.gid = 0
                member.mtime = 0
                archive.addfile(member, io.BytesIO(row['raw']))
        tar_raw = buffer.getvalue()
        need(len(tar_raw) <= MAX_BYTES + 4 * 1024 * 1024, 'archive framing budget exceeded')
        packed = lzma.compress(tar_raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6)
        need(lzma.decompress(packed) == tar_raw, 'lossless original archive differs')
        check_time(started)
        parent_fd, parent_identity = open_directory(R)
        need(not os.path.lexists(OUT), 'new independent evidence directory required; no retry or overwrite')
        os.mkdir(OUT.name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        out_fd, out_identity = open_directory(OUT, parent_fd, OUT.name)
        need(out_identity[3] == os.geteuid() and stat.S_IMODE(out_identity[2]) == 0o700,
             'new private evidence directory required')
        collector_row = put_new(out_fd, OUT / 'COLLECTOR.original.py', COLLECTOR_SOURCE)
        archive_row = put_new(out_fd, OUT / 'EXTERNAL902-ORIGINALS.tar.xz', packed)
        manifest = {'schema': 'hepta.root.external902-case-and-pinned-originals-manifest.v1',
            'state': 'EXACT_FAILED_CASE_AND_FIXED_SOURCE_ORIGINALS_READ_ONLY_BYTE_COPY',
            'case_source_root': str(SOURCE), 'label': LABEL, 'nonce': NONCE,
            'complete_source_roots': {'root-originals': str(SOURCE),
                **{prefix: row['root'] for prefix, row in SOURCE_PACKAGES.items()}},
            'additional_fixed_files': ADDITIONAL_FIXED_FILES,
            'started_unix_ns': start_unix_ns, 'first_full_recheck': before_write,
            'files': [{**row['descriptor'], 'archive_member': name, 'metadata': row['metadata']}
                      for name, row in sorted(files.items())],
            'directories': [row for _, row in sorted(directories.items())],
            'case_original_files': sum(name.startswith('root-originals/') for name in files),
            'total_original_files': len(files), 'observed_directories': len(directories),
            'total_original_file_bytes': sum(len(row['raw']) for row in files.values()),
            'archive': archive_row, 'tar_plaintext': {'bytes': len(tar_raw), 'sha256': sha(tar_raw)},
            'archive_regular_members': len(files), 'collector_source': collector_row,
            'case_original_receipts': case_proof, 'fixed_source_packages': source_proofs,
            'separate_sender_top_records': sender_top_proof,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'observation_scope': 'Later complete case/source trees plus individually fixed files, with full9/bytes/child-name bookends',
            'originals_modified': False, 'phone_calls': 0, 'p4_calls': 0, 'subprocesses': 0,
            'signals_sent': 0, 'case_pass': False, 'component_qualified': False, 'business_qualified': False}
        manifest_row = put_new(out_fd, OUT / 'ORIGINALS-MANIFEST.json', enc(manifest))
        after_copy = recheck_tree(files, directories, handles, started)
        check_directory(R, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        result = {'schema': 'hepta.root.external902-originals-collection.v1',
            'state': 'FAILED_EXTERNAL_CASE_AND_PINNED_SOURCE_ORIGINALS_ARCHIVED',
            'label': LABEL, 'nonce': NONCE, 'case_source_root': str(SOURCE), 'out': str(OUT),
            'fixed_case_pins': {name: {'path': str(SOURCE / name), 'bytes': pin[0], 'sha256': pin[1]}
                                for name, pin in FIXED_CASE_PINS.items()},
            'archive': archive_row, 'manifest': manifest_row, 'collector_source': collector_row,
            'case_original_files': manifest['case_original_files'], 'total_original_files': len(files),
            'observed_directories': len(directories), 'total_original_file_bytes': manifest['total_original_file_bytes'],
            'after_copy_full_recheck': after_copy,
            'joined_original_host_phase_count': len(case_proof['joined_original_host_phases']),
            'unjoined_sender_original_preserved': case_proof['unjoined_sender_original'],
            'later_sender_top_records_do_not_retrofit_join_EOF_or_native_cleanup': True,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'originals_modified': False, 'phone_calls': 0, 'p4_calls': 0, 'subprocesses': 0,
            'signals_sent': 0, 'case_pass': False, 'component_qualified': False, 'business_qualified': False,
            'automatic_retry': False, 'filesystem_or_compression_hard_deadline': False}
        result_row = put_new(out_fd, OUT / 'RESULT.json', enc(result))
        final_check = recheck_tree(files, directories, handles, started)
        check_directory(R, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        need(sorted(os.listdir(out_fd)) == ['COLLECTOR.original.py', 'EXTERNAL902-ORIGINALS.tar.xz',
            'ORIGINALS-MANIFEST.json', 'RESULT.json'], 'new evidence output inventory differs')
        print(enc({'state': result['state'], 'result': result_row, 'archive': archive_row,
            'manifest': manifest_row, 'case_original_files': manifest['case_original_files'],
            'total_original_files': len(files), 'total_original_file_bytes': manifest['total_original_file_bytes'],
            'last_full_recheck': final_check, 'original_unjoined_sender_pid': 54589,
            'original_sender_join_or_EOF_retrofitted': False, 'case_pass': False,
            'phone_calls': 0, 'p4_calls': 0, 'same_instant_as_failure': False,
            'atomic_filesystem_snapshot': False}).decode(), end='')
        return 0
    except BaseException as error:
        if out_fd is not None:
            try:
                put_new(out_fd, OUT / 'FAILED-OR-UNKNOWN.json', enc({
                    'state': 'EVIDENCE_COLLECTION_FAILED_OR_UNKNOWN_RETAIN_EXISTING_OUTPUTS',
                    'error_type': type(error).__name__, 'detail': str(error)[:2000],
                    'case_source_root': str(SOURCE), 'out': str(OUT), 'case_pass': False,
                    'automatic_retry': False, 'originals_modified': False,
                    'phone_calls': 0, 'p4_calls': 0, 'signals_sent': 0}))
            except BaseException:
                pass
        raise
    finally:
        if out_fd is not None:
            os.close(out_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        for _, fd, _ in handles.values():
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
