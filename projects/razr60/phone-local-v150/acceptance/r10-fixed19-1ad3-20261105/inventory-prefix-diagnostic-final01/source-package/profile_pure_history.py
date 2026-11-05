#!/usr/bin/env python3
"""Profile exact archived pure readers locally, never a live admission.

No phone, process, network, filesystem-original reader, or verifier entrypoint
is allowed inside the measured calls. The exact stage loader supplies a bounded
in-memory package map, as it did before the actual create-only phone stage.
"""
import argparse
import base64
import builtins
import contextlib
import cProfile
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import types

ARCHIVE = (469829, '9aacc5789a65dd875ab9fe7456e2258e0bf4e54575d3be71a50d5542a489b288')
STAGE = (19116, '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340')
LEASE = '2f47f823ef1484852c5dc1b91f27020d6f56685b3024dc320d5925a3dac92d59'
PACKAGE = '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'
CANDIDATE = (67005, '147cf49e91fb4bcbddeba6591d48c8782efe20452db2b2d6179e7addd68c27e4')
OLD_EXPRESSION = b'sum(p == q or q in p.parents for q in paths) == 1'
NEW_EXPRESSION = b'sum(p.parts[:len(q.parts)] == q.parts for q in paths) == 1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def read_exact(path, expected):
    raw = Path(path).read_bytes()
    require((len(raw), sha(raw)) == expected, 'exact input pin differs: ' + str(path))
    return raw


def save(path, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return {'path': str(Path(path).resolve()), 'bytes': len(raw), 'sha256': sha(raw)}


@contextlib.contextmanager
def no_external_effects():
    """A test fence, not a substitute for the production admission gates."""
    denied = []
    patches = []
    def replace(owner, name):
        if not hasattr(owner, name):
            return
        previous = getattr(owner, name)
        def forbidden(*args, **kwargs):
            denied.append(name)
            raise AssertionError('PURE_PROFILE_EXTERNAL_OPERATION_FORBIDDEN:' + name)
        patches.append((owner, name, previous))
        setattr(owner, name, forbidden)
    for owner, names in [(builtins, ('open',)), (os, ('open', 'fork', 'kill', 'killpg', 'system', 'execve', 'execv', 'posix_spawn', 'posix_spawnp')),
                         (socket, ('socket', 'create_connection')), (subprocess, ('Popen', 'run', 'call', 'check_call', 'check_output'))]:
        for name in names:
            replace(owner, name)
    try:
        yield denied
    finally:
        for owner, name, previous in reversed(patches):
            setattr(owner, name, previous)
        require(not denied, 'pure reader attempted an external operation: ' + repr(denied))


def canonical(value):
    """Retain exact bytes in comparisons; module objects are separate code pins."""
    if type(value) is bytes:
        return {'__exact_bytes_base64__': base64.b64encode(value).decode()}
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in sorted(value.items()) if not isinstance(v, types.ModuleType)}
    if isinstance(value, (tuple, list)):
        return [canonical(v) for v in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise TypeError('non-data pure output: ' + type(value).__name__)


def fingerprint(value):
    raw = json.dumps(canonical(value), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return {'bytes': len(raw), 'sha256': sha(raw)}


def summarize(profile):
    # Recompiled identical source has distinct code objects. Keep every entry,
    # then add counters explicitly instead of losing a duplicate three-part key.
    raw_rows = []
    grouped = {}
    for entry in profile.getstats():
        code = entry.code
        filename, line, name = ('~', 0, code) if type(code) is str else (code.co_filename, code.co_firstlineno, code.co_name)
        row = {'file': filename, 'line': line, 'function': name,
               'primitive_calls': entry.callcount-entry.reccallcount,
               'calls': entry.callcount, 'self_seconds': entry.inlinetime,
               'cumulative_seconds': entry.totaltime}
        raw_rows.append(row)
        key = (filename, line, name)
        if key not in grouped:
            grouped[key] = dict(row, code_objects=1)
        else:
            for field in ('primitive_calls', 'calls', 'self_seconds', 'cumulative_seconds'):
                grouped[key][field] += row[field]
            grouped[key]['code_objects'] += 1
    rows = list(grouped.values())
    rows.sort(key=lambda r: r['cumulative_seconds'], reverse=True)
    selected = [r for r in rows if r['function'] in {
        'non_native_sidebranch', 'property_parent_reader', 'environment_parent_reader',
        'policy_parent_reader', 'boundary_from_original', 'closed_boundary_originals',
        'inventory_value', 'verify_sidebranch', 'require_failed_ancestor_tail',
        'validate_private_preservation', '<built-in method builtins.compile>'}]
    return {'top_cumulative': rows[:30], 'selected': selected,
            'raw_code_objects': raw_rows, 'aggregation': 'all getstats code objects retained; matching location counters summed'}


def load(args):
    stage_raw = read_exact(args.stage_source, STAGE)
    archive_raw = read_exact(args.archive, ARCHIVE)
    module = types.ModuleType('exact_stage_loader_for_pure_profile')
    module.__file__ = str(Path(args.stage_source).resolve())
    exec(compile(stage_raw, module.__file__, 'exec'), module.__dict__)
    files = module.archive_members(archive_raw)
    lease, manifest = module.validate_archive(files, LEASE, PACKAGE)
    loaded_files = files
    if args.candidate_source is not None:
        candidate = read_exact(args.candidate_source, CANDIDATE)
        parent = files['package/source/late_boundary.py']
        require(parent.count(OLD_EXPRESSION) == candidate.count(NEW_EXPRESSION) == 1
                and candidate.replace(NEW_EXPRESSION, OLD_EXPRESSION) == parent,
                'candidate must be the exact single-expression derivation')
        loaded_files = dict(files)
        loaded_files['package/source/late_boundary.py'] = candidate
    # This is an inert path for __file__ identity. It is never created or read.
    home = Path('/PURE-LOCAL-NO-PHONE-NO-CURRENT-ADMISSION') / lease['label']
    old_path = sys.path[:]
    old_modules = {k: sys.modules.get(k) for k in ('component_common', 'native_proc_profile', 'component_lifecycle', 'component_snapshot', 'late_boundary')}
    try:
        common, life = module.modules_from_reviewed(loaded_files, home)
        late = sys.modules['late_boundary']
    except BaseException:
        sys.path[:] = old_path
        for k, v in old_modules.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        raise
    return files, lease, manifest, late, old_path, old_modules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--stage-source', type=Path, required=True)
    parser.add_argument('--candidate-source', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700)
    try:
        files, lease, manifest, late, old_path, old_modules = load(args)
    except BaseException as error:
        row = save(args.out / 'PROFILE-LOAD-FAILURE.json', {
            'state': 'EXACT_INPUT_OR_LOADER_FAILED_NO_QUALIFICATION',
            'error_type': type(error).__name__, 'detail': str(error),
            'phone_calls': 0, 'p4_calls': 0, 'process_starts': 0})
        print(json.dumps(row, sort_keys=True))
        raise
    result = {'schema': 'hepta.pure-historical-reader-host-profile.v1',
              'scope': 'immutable_retained_bytes_only_not_verify_current_or_live_phone',
              'archive': {'bytes': ARCHIVE[0], 'sha256': ARCHIVE[1]},
              'package_sha256': PACKAGE, 'lease_sha256': LEASE, 'archive_members': len(files),
              'runtime_members': len(manifest['files']), 'phone_calls': 0, 'p4_calls': 0,
              'process_starts': 0, 'live_current_inventory_reads': 0,
              'candidate_source_override': None if args.candidate_source is None else {
                  'bytes': CANDIDATE[0], 'sha256': CANDIDATE[1],
                  'single_expression_inverse_verified': True,
                  'is_actual_runtime_or_valid_under_original_manifest': False},
              'claimed_phone_speedup': False, 'cases': []}
    try:
        targets = [('fixed_non_native_sidebranch', lambda: late.non_native_sidebranch()),
                   ('actual08_boundary_original', lambda: late.boundary_from_original(
                       files['inputs/PRIOR-BOUNDARY.original.json'], original_descriptor=lease['prior_boundary'],
                       combination_sha256=lease['combination']['sha256'], package_sha256=lease['package_sha256']))]
        for label, operation in targets:
            profiler = cProfile.Profile()
            with no_external_effects() as denied:
                plain_cpu_start = time.process_time()
                plain_start = time.monotonic()
                plain_value = operation()
                plain_elapsed = time.monotonic()-plain_start
                plain_cpu_elapsed = time.process_time()-plain_cpu_start
                plain_projection = fingerprint(plain_value)
                cpu_start = time.process_time()
                start = time.monotonic()
                profiler.enable()
                try:
                    value = operation()
                finally:
                    profiler.disable()
                elapsed = time.monotonic() - start
                cpu_elapsed = time.process_time() - cpu_start
                projected = fingerprint(value)
                require(projected == plain_projection, 'pure repeat result changed')
            result['cases'].append({'name': label, 'wall_seconds': elapsed, 'process_cpu_seconds': cpu_elapsed,
                                    'uninstrumented_wall_seconds': plain_elapsed,
                                    'uninstrumented_process_cpu_seconds': plain_cpu_elapsed,
                                    'output': projected, 'denied_external_operations': denied,
                                    'profile': summarize(profiler)})
        result['state'] = 'EXACT_PURE_SUBSET_PROFILED_NOT_FULL_ADMISSION'
    except BaseException as error:
        result['state'] = 'PROFILE_FAILED_NO_QUALIFICATION'
        result['error'] = {'type': type(error).__name__, 'detail': str(error)}
        raise
    finally:
        sys.path[:] = old_path
        for key, value in old_modules.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
        row = save(args.out / 'PROFILE.json', result)
        print(json.dumps({'state': result['state'], 'report': row}, sort_keys=True))


if __name__ == '__main__':
    main()
