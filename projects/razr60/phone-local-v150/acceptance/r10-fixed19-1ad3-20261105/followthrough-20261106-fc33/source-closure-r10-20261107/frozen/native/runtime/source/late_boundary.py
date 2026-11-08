#!/usr/bin/env python3
"""Cumulative component verification, explicit publish, and failure-only diagnostics.

The default CLI is a zero-effect preview.  The one publish entry can only copy
already independently closed evidence into a new private boundary namespace.
It cannot run a tool, contact a service, load a policy, signal a role, send a
task or rewrite the original r9-r2 retirement proof.
"""
import argparse
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import component_common as C

ROOT = C.BASE / 'native-guard-boundaries-r10-r1'
SCHEMA = 'hepta.native-guard.late-boundary.v1'
STATE = 'CLOSED_COMPONENT_AND_CUMULATIVE_ORIGINALS_PRESERVED'
# Exactly one previously closed source tuple, not current qualification.
SOURCE_PARENT_REFERENCE = 'reference/source_parent_late_boundary_r4.py'
SOURCE_PARENT_READER_BYTES = 153138
SOURCE_PARENT_READER_SHA256 = '27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4'
SOURCE_PARENT_COMMON_SHA256 = '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'
SOURCE_PARENT_COMBINATION_SHA256 = '02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'
SOURCE_PARENT_PACKAGE_SHA256 = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'
SOURCE_PARENT_POLICY_SHA256 = '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
SOURCE_PARENT_POLICY_ADOPTION_SHA256 = '98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'
SOURCE_PARENT_CLOSURE_SHA256 = '5b145819502951fe37e56ceb1bd2e04a6be19deef2f210590c1711e5fe401655'
SOURCE_PARENT_RECORDS = ({'actual_native_calls': 2,
  'boundary': {'bytes': 29342,
               'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895],
               'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json',
               'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'},
  'case_id': 'NEG-01',
  'closed_previous': {'bytes': 1426,
                      'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final04/ACTUAL-PREVIOUS-INPUT.json',
                      'sha256': 'fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0'},
  'closure': {'bytes': 135871,
              'metadata': [65086, 161041, 33152, 0, 0, 1, 135871, 1793954243803886896, 1793954243803886896],
              'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843/CLOSURE.original.json',
              'sha256': 'cdd271173ae84ea9d52a844eed86b08fac0def4bb6e175da3edcb6777728d288'},
  'closure_source_sha256': '5b145819502951fe37e56ceb1bd2e04a6be19deef2f210590c1711e5fe401655',
  'component_qualified': True,
  'home': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04',
  'inventory': {'bytes': 1345535,
                'metadata': [65086,
                             159230,
                             33152,
                             0,
                             0,
                             1,
                             1345535,
                             1793954243803886896,
                             1793954243803886896],
                'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843/AFTER-INVENTORY.original.json',
                'sha256': '4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4'},
  'label': 'root-r10-neg01-a1055-final04',
  'native_status': 'completed',
  'nonce': 'ac03e3864c1798742c472957b06ca843',
  'owner_request_sha256': '1a358e904a40bf65da409d0efb044fa0133c65aa81ac632af02542ded4c7f8c5',
  'prior_boundary': {'bytes': 21325,
                     'metadata': [65086,
                                  158182,
                                  33152,
                                  0,
                                  0,
                                  1,
                                  21325,
                                  1793928633271896666,
                                  1793928633271896666],
                     'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50.json',
                     'sha256': 'fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66'},
  'private_roots': ['/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04/executor',
                    '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04',
                    '/proc/1/root/data/local/tmp/hepta-native-guard-ac03e3864c1798742c472957b06ca843'],
  'roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence',
            '/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence',
            '/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts',
            '/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6',
            '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings',
            '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03',
            '/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04',
            '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05',
            '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06',
            '/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07',
            '/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08',
            '/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01',
            '/proc/1/root/data/local/tmp/hepta-native-guard-902e851c3ca1f90deab3d880ab993774',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01',
            '/proc/1/root/data/local/tmp/hepta-native-guard-6077fc8f045572edc4acfb13ed7e09a8',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02',
            '/proc/1/root/data/local/tmp/hepta-native-guard-8daaaad6a322963e87973613c1fac762',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-sides01/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-sides01',
            '/proc/1/root/data/local/tmp/hepta-native-guard-82012c7447c5f35d97c832d1d9481860',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-v3stack01/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-v3stack01',
            '/proc/1/root/data/local/tmp/hepta-native-guard-a493b853566d68099f7dbc0a124aff50',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02/executor',
            '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04/executor',
            '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04',
            '/proc/1/root/data/local/tmp/hepta-native-guard-ac03e3864c1798742c472957b06ca843'],
  'scope': {'profile_id': 'owner-open',
            'session_id': 'session-ee897738-8fc2-4d3e-a916-5fe368b340ef',
            'task_id': 'task-d3f61033-5b61-40e4-b8c6-7ea00d6b2d56',
            'turn_id': 'turn-ee9559cb-2540-46b3-91ba-4b4ce427e4bc',
            'turn_stream_id': 'r5-stream-b885cb9bcf82355ed1f0e85e91f4afa2af3ac5a70acd9e0ab95f5221a83d241b'}},)
SOURCE_PARENT_READER_DEPENDENCIES = {'reference/attempt05-AFTER-INVENTORY.original.json': {'bytes': 664638,
                                                       'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'},
 'reference/attempt05-CLOSURE.original.json': {'bytes': 164095,
                                               'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'},
 'reference/attempt05-SIDE-PROOF.original.json': {'bytes': 4650,
                                                  'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'},
 'reference/component_common_r5.py': {'bytes': 18133,
                                      'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'},
 'reference/diag02-AFTER-INVENTORY.original.json': {'bytes': 1031582,
                                                    'sha256': '10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d'},
 'reference/diag02-CLOSURE.original.json': {'bytes': 253127,
                                            'sha256': 'e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035'},
 'reference/diag02-SIDE-PROOF.original.json': {'bytes': 8439,
                                               'sha256': 'a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd'},
 'reference/environment_parent_late_boundary_r6.py': {'bytes': 53502,
                                                      'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'},
 'reference/non_native_attempt05.py': {'bytes': 19740,
                                       'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'},
 'reference/non_native_diag02.py': {'bytes': 29504,
                                    'sha256': '296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6'},
 'reference/policy_parent_late_boundary_r4.py': {'bytes': 35730,
                                                 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'},
 'reference/property_parent_late_boundary_r7.py': {'bytes': 62434,
                                                   'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'},
 'reference/retained_unstarted_stage_final02.py': {'bytes': 62662,
                                                   'sha256': 'bc6faf1c7ae2b7e3d44be3d4fe19e4272073073f8df283397ef37c177ca25850'},
 'reference/source_parent_late_boundary_r4.py': {'bytes': 153138,
                                                 'sha256': '27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4'},
 'source/component_common.py': {'bytes': 19138,
                                'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}}
HISTORICAL_FAILED_BOUNDARY_COUNT = 9
MAX_NEW_CURRENT_CASE_PREFIX = 2
RETAINED_BASE_ROOT_COUNT = 41
SOURCE_PARENT_COUNT = len(SOURCE_PARENT_RECORDS)
SOURCE_PARENT_HOME_COUNT = len({row['home'] for row in SOURCE_PARENT_RECORDS})
SOURCE_PARENT_INVENTORY_ROOT_COUNT = len(SOURCE_PARENT_RECORDS[0]['roots'])
MAX_CHAIN = HISTORICAL_FAILED_BOUNDARY_COUNT + SOURCE_PARENT_COUNT + MAX_NEW_CURRENT_CASE_PREFIX
COMPONENT_ROLE_CAP = 3*(MAX_CHAIN+2)
MAX_FIXTURE_ROOTS = MAX_CHAIN+2
MAX_CURRENT_INVENTORY_ROOTS = SOURCE_PARENT_INVENTORY_ROOT_COUNT+3*MAX_NEW_CURRENT_CASE_PREFIX
FIELDS = {'schema', 'state', 'boot_id', 'nonce', 'case_id', 'scope',
          'owner_request_sha256', 'package_sha256', 'combination_sha256',
          'retirement', 'roots', 'inventory', 'closure', 'prior_boundary',
          'component_role_identities', 'publisher_source_sha256',
          'component_qualified', 'native_status', 'actual_native_calls',
          'original_retirement_rewritten', 'business_qualified',
          'model_requests', 'automatic_replay', 'non_native_sidebranch'}


def reviewed_source_sha256():
    # The create-only stage evaluates already byte-pinned archive modules before
    # any target directory exists. Its loader provides the same source digest.
    injected = globals().get('__reviewed_source_sha256__')
    if injected is not None:
        C.need(isinstance(injected, str) and C.HASH.fullmatch(injected),
               'pinned in-memory module source digest differs')
        return injected
    return C.sha(C.read(Path(__file__), 1048576, private=False))


def exact_descriptor(row, *, expected_path=None):
    C.need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256', 'metadata'},
           'exact original file identity required')
    p = Path(row['path'])
    C.need(p.is_absolute() and str(p) == row['path'] and '..' not in p.parts
           and (expected_path is None or p == Path(expected_path)), 'original path differs')
    C.need(type(row['bytes']) is int and 0 <= row['bytes'] <= 16*1024*1024
           and isinstance(row['sha256'], str) and C.HASH.fullmatch(row['sha256']),
           'original byte descriptor differs')
    m = row['metadata']
    C.need(isinstance(m, list) and len(m) == 9 and all(type(n) is int for n in m)
           and stat.S_ISREG(m[2]) and stat.S_IMODE(m[2]) == 0o600
           and m[3:6] == [0, 0, 1] and m[6] == row['bytes'],
           'original private file metadata differs')
    return p


def original(row, *, expected_path=None):
    p = exact_descriptor(row, expected_path=expected_path)
    before = C.metadata(p.lstat())
    raw = C.pinned(p, {k: row[k] for k in ('bytes', 'sha256')}, 16*1024*1024)
    C.need(before == row['metadata'] == C.metadata(p.lstat()),
           'closed boundary original file identity changed')
    return raw


def describe(path, raw):
    return {'path': str(path), **C.descriptor(raw), 'metadata': C.metadata(Path(path).lstat())}


def inventory_value(value):
    """Validate complete topology; only elapsed wall-clock measurement is excluded."""
    C.need(isinstance(value, dict) and set(value) == {'schema', 'roots', 'entries',
        'file_bytes_hashed', 'elapsed_seconds', 'inventory_is_closure_or_retirement'}
        and value['schema'] == 'hepta.native-guard.complete-inventory.v1'
        and value['inventory_is_closure_or_retirement'] is False,
        'complete original inventory schema differs')
    roots, entries = value['roots'], value['entries']
    C.need(isinstance(roots, list) and 1 <= len(roots) <= 64
        and len(roots) == len(set(roots)) and isinstance(entries, dict)
        and 1 <= len(entries) <= 30000, 'bounded complete inventory required')
    paths = [Path(p) for p in roots]
    C.need(all(p.is_absolute() and str(p) == s and '..' not in p.parts
               for p, s in zip(paths, roots)), 'inventory root path differs')
    C.need(all(a == b or not (a in b.parents or b in a.parents) for a in paths for b in paths),
           'inventory roots overlap')
    C.need(all(p in entries and entries[p].get('kind') in ('directory', 'absent') for p in roots),
           'inventory root is absent or not a directory')
    root_parts = frozenset(p.parts for p in paths)
    root_depths = frozenset(len(parts) for parts in root_parts)
    children = {}
    for name in entries:
        p = Path(name)
        children.setdefault(str(p.parent), []).append(p.name)
    total = 0
    for name, row in entries.items():
        p = Path(name)
        C.need(p.is_absolute() and str(p) == name and '..' not in p.parts
               and sum(p.parts[:depth] in root_parts for depth in root_depths
                       if depth <= len(p.parts)) == 1,
               'inventory entry left its unique complete root')
        if row.get('kind') == 'absent':
            C.need(row == {'kind': 'absent', 'absence': 'ENOENT'} and name in roots
                   and re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}', name)
                   and not children.get(name), 'only an explicit fixture-root ENOENT may be retained')
            continue
        m = row.get('metadata')
        C.need(isinstance(m, list) and len(m) == 9 and all(type(n) is int for n in m),
               'inventory original metadata differs')
        if row.get('kind') == 'directory':
            C.need(set(row) == {'kind', 'metadata', 'names'} and stat.S_ISDIR(m[2])
                   and isinstance(row['names'], list) and row['names'] == sorted(set(row['names']))
                   and all(isinstance(n, str) and n not in ('', '.', '..') and '/' not in n
                           and '\0' not in n for n in row['names']), 'inventory directory differs')
            actual = sorted(children.get(name, []))
            C.need(actual == row['names'], 'inventory omitted or fabricated a directory child')
        else:
            C.need(set(row) == {'kind', 'metadata', 'bytes', 'sha256'}
                   and row['kind'] == 'file' and stat.S_ISREG(m[2]) and m[5] == 1
                   and type(row['bytes']) is int and 0 <= row['bytes'] <= 64*1024*1024
                   and m[6] == row['bytes'] and isinstance(row['sha256'], str)
                   and C.HASH.fullmatch(row['sha256']), 'inventory original file differs')
            total += row['bytes']
        if str(p) not in roots:
            C.need(str(p.parent) in entries and entries[str(p.parent)]['kind'] == 'directory',
                   'inventory entry has no retained parent')
    C.need(type(value['file_bytes_hashed']) is int and total == value['file_bytes_hashed']
           and total <= 512*1024*1024, 'inventory byte accounting differs')
    return {k: v for k, v in value.items() if k != 'elapsed_seconds'}


def boundary_value(value, *, combination_sha256, package_sha256):
    current_context(combination_sha256, package_sha256)
    C.need(isinstance(value, dict) and set(value) == CURRENT_RETAINED_FIELDS
           and value['schema'] == SCHEMA and value['state'] == STATE,
           'explicit independently closed late boundary required')
    C.need(value['combination_sha256'] == combination_sha256
           and value['package_sha256'] == package_sha256
           and all(isinstance(value[k], str) and C.HASH.fullmatch(value[k]) for k in
                   ('owner_request_sha256', 'package_sha256', 'combination_sha256', 'publisher_source_sha256')),
           'closed boundary source/combination binding differs')
    C.need(value['publisher_source_sha256'] == reviewed_source_sha256(),
           'closed boundary publisher is not this reviewed package source')
    C.need(re.fullmatch('[0-9a-f]{32}', value['nonce'])
           and re.fullmatch('[0-9a-f-]{36}', value['boot_id'])
           and value['case_id'] in ('NEG-01', 'NEG-02'), 'closed component identity differs')
    C.scope(value['scope'])
    C.need(value['original_retirement_rewritten'] is False and value['business_qualified'] is False
           and type(value['model_requests']) is int and value['model_requests'] == 0
           and value['automatic_replay'] is False, 'boundary overstates qualification or permits replay')
    C.need(type(value['component_qualified']) is bool
           and value['native_status'] in ('completed', 'provider_failed', 'cancelled')
           and type(value['actual_native_calls']) is int and 0 <= value['actual_native_calls'] <= 2,
           'closed native outcome/count differs')
    home = ROOT / value['nonce']
    exact_descriptor(value['inventory'], expected_path=home / 'AFTER-INVENTORY.original.json')
    exact_descriptor(value['closure'], expected_path=home / 'CLOSURE.original.json')
    if value['prior_boundary'] is not None:
        p = exact_descriptor(value['prior_boundary'])
        C.need(p.parent == ROOT and re.fullmatch(r'[0-9a-f]{32}\.json', p.name),
               'prior boundary left the dedicated original namespace')
    roles = value['component_role_identities']
    C.need(isinstance(roles, dict) and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(isinstance(v, list) and len(v) == 4 and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3, 'closed component role identities differ')
    sidebranch = non_native_sidebranch()
    C.need(value.get('non_native_sidebranch') == sidebranch['binding']
           and value['nonce'] != sidebranch['binding']['nonce'],
           'current native boundary omitted or reinterpreted the fixed non-native sidebranch')
    current_sidebranch_bindings(value)
    current_retained_stage_binding(value)
    current_retained_preaccept_binding(value)
    current_retained_failed_staged_binding(value)
    current_retained_failed_transport_binding(value)
    return value


def closure_matches(closure, boundary, inventory_raw):
    C.need(isinstance(closure, dict)
           and closure.get('schema') == 'hepta.native-guard.original-closure.v1'
           and closure.get('state') in ('ORIGINAL_NATIVE_COMPONENT_CLOSED',
                                       'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED')
           and closure.get('closed') is True and type(closure.get('component_qualified')) is bool
           and closure.get('business_qualified') is False
           and type(closure.get('model_requests')) is int and closure['model_requests'] == 0
           and closure.get('automatic_replay') is False
           and type(closure.get('actual_native_calls')) is int and 0 <= closure['actual_native_calls'] <= 2
           and closure.get('four_role_qualification') is False
           and closure.get('original_retirement_rewritten') is False,
           'independent original component closure is absent')
    sidebranch = non_native_sidebranch()
    C.need(boundary.get('non_native_sidebranch') == sidebranch['binding']
           and closure.get('non_native_sidebranch') == sidebranch['binding']
           and boundary['nonce'] != sidebranch['binding']['nonce'],
           'current closure does not retain the exact separate non-native sidebranch')
    preserve_non_native_private(C.strict(inventory_raw), sidebranch)
    passed = closure['state'] == 'ORIGINAL_NATIVE_COMPONENT_CLOSED'
    C.need(closure['component_qualified'] is passed
           and ((passed and closure.get('native_status') == 'completed'
                 and closure.get('actual_native_calls') == 2
                 and closure.get('two_original_r6_calls_verified') is True)
                or (not passed and closure.get('native_status') in ('provider_failed', 'cancelled'))),
           'failed lifecycle cannot be converted to component qualification')
    for key in ('boot_id', 'nonce', 'case_id', 'scope', 'owner_request_sha256',
                'package_sha256', 'combination_sha256', 'retirement', 'component_role_identities',
                'component_qualified', 'native_status', 'actual_native_calls'):
        C.need(closure.get(key) == boundary[key], 'closed component binding differs: ' + key)
    C.need(closure.get('inventory') == C.descriptor(inventory_raw)
           and closure.get('prior_boundary') == boundary['prior_boundary'],
           'closure does not bind these cumulative original inventory bytes')
    C.need(type(closure.get('unknown_effects')) is int and closure['unknown_effects'] == 0,
           'unknown native effect cannot be closed')
    for key in ('native_hash_chain_and_terminal_verified', 'all_actual_r6_calls_verified',
                'global_ledger_delta_verified', 'original_sender_and_draft_restoration_verified',
                'independent_role_and_endpoint_absence_verified', 'all_prior_originals_preserved'):
        C.need(closure.get(key) is True, 'independent closure gate absent: ' + key)


# This source candidate is deliberately inadmissible until Root independently
# closes and publishes the one actual legacy attempt, then reviews these pins.
# A caller cannot supply or replace this record through a lease or CLI argument.
REVIEWED_FAILED_ANCESTOR = {'boundary': {'bytes': 5003, 'metadata': [65086, 151071, 33152, 0, 0, 1, 5003, 1793826667027935563, 1793826667027935563], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/88d68d88130d3c74e6c950a6346357c1.json', 'sha256': 'ee008c3b2adec701be4c0bdfd38ca7ac0d650da9b7783f51d3fe4638bfdc5b58'}, 'inventory': {'bytes': 563365, 'metadata': [65086, 150632, 33152, 0, 0, 1, 563365, 1793826665711935563, 1793826665711935563], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/88d68d88130d3c74e6c950a6346357c1/AFTER-INVENTORY.original.json', 'sha256': '145d5937cd328ed568b1af9c73f7d331211d1c44cfad8ecf960b47d91f308eee'}, 'closure': {'bytes': 119753, 'metadata': [65086, 152047, 33152, 0, 0, 1, 119753, 1793826665711935563, 1793826665711935563], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/88d68d88130d3c74e6c950a6346357c1/CLOSURE.original.json', 'sha256': 'b8a27617eaff8dda0f1c61b5aa14a89d7014a157e0b33280b14162c7591bcaa3'}, 'publisher_source_sha256': '234e248d4db6aff6125071a62f92e48360df1bab839250b26699c8af63067b07', 'external_closure_source_sha256': '112a1676a09b9990f13ef3d0fef1f396e9018c47d2ee89b23063be9d36b097f8', 'external_capture_verifier_source_sha256': '3ce59c2f9bf1719af6715e41a92cc53482892c98517322ab669b76e09fca2d98', 'external_reconciliation_sha256': 'fee3b04713d83a2d371b17eb523f67eafcf66a04d416895cc00cd3bc0dc77f93'}
LEGACY_NONCE = '88d68d88130d3c74e6c950a6346357c1'
LEGACY_PACKAGE_SHA256 = 'd09489d965b3bc8adca12a7403b87baf5ec2e333e983fbc2b911992e9f25e65f'
LEGACY_COMBINATION_SHA256 = '7f5929ae709239f8a5d92314146d2b63151bb06746d160da7961a3de29c486af'
LEGACY_BOOT_ID = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
LEGACY_SCHEMA = 'hepta.native-guard.external-late-boundary.v1'
LEGACY_STATE = 'EXTERNALLY_CLOSED_LEGACY_COMPONENT_AND_CUMULATIVE_ORIGINALS_PRESERVED'
LEGACY_PARENT_CLOSURE_SHA256 = '94ea482ed93f8394d0f7a52f3855ce3ae23a9a0b790cb18b9a796fdffbf60339'
LEGACY_FIXTURE_RECONCILER_SHA256 = '8ca927e88397246ac83e4553c8b5dac59f5bebc2c507095d059f6e6478f546ef'
LEGACY_SCOPE = {'profile_id': 'owner-open', 'session_id': 'session-ee897738-8fc2-4d3e-a916-5fe368b340ef', 'task_id': 'task-d3f61033-5b61-40e4-b8c6-7ea00d6b2d56', 'turn_id': 'turn-8a01d008-58ca-405c-809e-73dcebda9185', 'turn_stream_id': 'r5-stream-58a156c741ca241915d588db22713d1d3fc5d0d420e7181e1a7da87020afb3c2'}
LEGACY_RETIREMENT = {'bound_inputs': {'bytes': 848888, 'metadata': [65086, 148812, 33152, 0, 0, 1, 848888, 0, 1793807681115942806], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/module-r10-r1-retirement-code-r1/BOUND-INPUTS.json', 'sha256': '607f832e4f1b0904a67e1102c3653543961aa71e55aa7a309cd6911c6234ec61'}, 'disabled_flag': {'bytes': 0, 'metadata': [65086, 154139, 33152, 0, 0, 1, 0, 1793807685267942804, 1793807685267942804], 'path': '/proc/1/root/data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'preflight': {'bytes': 703888, 'metadata': [65086, 154138, 33152, 0, 0, 1, 703888, 1793807685235942804, 1793807685235942804], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/module-retire-r9-r2-for-r10-r1-01/PREFLIGHT.json', 'sha256': '5205cd79b2f117d775c5574c63110b33e9b55f7cb69f5e212e034b8c4e9c9254'}, 'probe': {'bytes': 766658, 'metadata': [65086, 154037, 33152, 0, 0, 1, 766658, 0, 1793807681127942806], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/module-r10-r1-retirement-code-r1/retirement_probe.py', 'sha256': 'd1fe1478ee9699b5a1199aa4c2b96a2a405f7cafd0b5707071cfd2238dbe5df4'}, 'proof': {'bytes': 37869, 'metadata': [65086, 151157, 33152, 0, 0, 1, 37869, 1793807690051942802, 1793807690051942802], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/module-retire-r9-r2-for-r10-r1-01/RETIREMENT.json', 'sha256': 'b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'}}


def reviewed_failed_ancestor():
    p = REVIEWED_FAILED_ANCESTOR
    C.need(isinstance(p, dict) and set(p) == {'boundary', 'inventory', 'closure',
        'publisher_source_sha256', 'external_closure_source_sha256',
        'external_capture_verifier_source_sha256', 'external_reconciliation_sha256'},
        'the one actual failed ancestor has not been published and reviewed')
    exact_descriptor(p['boundary'], expected_path=ROOT/(LEGACY_NONCE+'.json'))
    for key, name in [('inventory', 'AFTER-INVENTORY.original.json'),
                      ('closure', 'CLOSURE.original.json')]:
        exact_descriptor(p[key], expected_path=ROOT/LEGACY_NONCE/name)
    C.need(all(isinstance(p[k], str) and C.HASH.fullmatch(p[k]) for k in
        ('publisher_source_sha256', 'external_closure_source_sha256',
         'external_capture_verifier_source_sha256', 'external_reconciliation_sha256')),
        'fixed external source proof pins are incomplete')
    return p



# The current combination is not known until the new actual policy export and
# explicit Root adoption have been reviewed. No lease or caller can fill this.
REVIEWED_CURRENT_COMBINATION_SHA256 = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'
POLICY_PARENT_PACKAGE_SHA256 = '1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996'
POLICY_PARENT_READER_SHA256 = 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'
POLICY_PARENT_COMMON_SHA256 = '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'
POLICY_PARENT_CLOSURE_SHA256 = '0261ed0e13ea35987765a99d6cefb394fb6825d49ac1870e49e805ec01029d69'
POLICY_PARENT_NONCE = 'c705647dd4ebb5d421be1041a9c41ca6'
POLICY_PARENT_BOUNDARY_SHA256 = '3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'
POLICY_PARENT_REFERENCE = 'reference/policy_parent_late_boundary_r4.py'
REVIEWED_PRE_POLICY_ANCESTOR = {'boundary': {'bytes': 4748, 'metadata': [65086, 149437, 33152, 0, 0, 1, 4748, 1793828404835934900, 1793828404835934900], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6.json', 'sha256': '3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'}, 'inventory': {'bytes': 633600, 'metadata': [65086, 153196, 33152, 0, 0, 1, 633600, 1793828403499934901, 1793828403499934901], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6/AFTER-INVENTORY.original.json', 'sha256': 'e48c39003bd26f65dde74958f0081a89c23027da19a11afd4fc2a81414c5c349'}, 'closure': {'bytes': 49087, 'metadata': [65086, 152153, 33152, 0, 0, 1, 49087, 1793828403499934901, 1793828403499934901], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6/CLOSURE.original.json', 'sha256': '559f2440fdd1c9f43c64399351f3fda0be95890d21cbde4aea211751e5f9aa81'}}


# This is the one already closed R6 native failure.  Its original descriptor
# record is populated only from the pinned Root06 raw files by the host source
# derivation entry.  It cannot be supplied through a lease or a runtime option.
REVIEWED_ENVIRONMENT_PARENT_ANCESTOR = {'boundary': {'bytes': 8774, 'metadata': [65086, 156811, 33152, 0, 0, 1, 8774, 1793845849603928245, 1793845849603928245], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/154588e3a15591a21ec18950d18e3ecd.json', 'sha256': 'eca628a18327146b7710a478fc2c2f716f79d55907b2821666828a0795e2060f'}, 'inventory': {'bytes': 737114, 'metadata': [65086, 156758, 33152, 0, 0, 1, 737114, 1793845847051928246, 1793845847051928246], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/154588e3a15591a21ec18950d18e3ecd/AFTER-INVENTORY.original.json', 'sha256': 'fcd752b17eed7d36718f81e61a0f81d22554aa1a478180371619de1c10d98759'}, 'closure': {'bytes': 54878, 'metadata': [65086, 156683, 33152, 0, 0, 1, 54878, 1793845847051928246, 1793845847051928246], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/154588e3a15591a21ec18950d18e3ecd/CLOSURE.original.json', 'sha256': '8fc9d05e877d91f6706558968276848e252784414983ea026b5c9ef00a8deb2a'}}
ENVIRONMENT_PARENT_PACKAGE_SHA256 = '4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e'
ENVIRONMENT_PARENT_READER_SHA256 = '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'
ENVIRONMENT_PARENT_COMMON_SHA256 = '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'
ENVIRONMENT_PARENT_CLOSURE_SHA256 = '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'
ENVIRONMENT_PARENT_NONCE = '154588e3a15591a21ec18950d18e3ecd'
ENVIRONMENT_PARENT_BOUNDARY_SHA256 = 'eca628a18327146b7710a478fc2c2f716f79d55907b2821666828a0795e2060f'
ENVIRONMENT_PARENT_REFERENCE = 'reference/environment_parent_late_boundary_r6.py'


def reviewed_environment_parent_ancestor():
    p = REVIEWED_ENVIRONMENT_PARENT_ANCESTOR
    C.need(isinstance(p, dict) and set(p) == {'boundary', 'inventory', 'closure'},
           'the fixed actual06 original record is absent')
    exact_descriptor(p['boundary'], expected_path=ROOT/(ENVIRONMENT_PARENT_NONCE+'.json'))
    C.need(p['boundary']['bytes'] == 8774
           and p['boundary']['sha256'] == ENVIRONMENT_PARENT_BOUNDARY_SHA256,
           'fixed actual06 boundary byte pin differs')
    for key, name in [('inventory', 'AFTER-INVENTORY.original.json'),
                      ('closure', 'CLOSURE.original.json')]:
        exact_descriptor(p[key], expected_path=ROOT/ENVIRONMENT_PARENT_NONCE/name)
    C.need(p['inventory']['bytes'] == 737114
           and p['inventory']['sha256'] == 'fcd752b17eed7d36718f81e61a0f81d22554aa1a478180371619de1c10d98759'
           and p['closure']['bytes'] == 54878
           and p['closure']['sha256'] == '8fc9d05e877d91f6706558968276848e252784414983ea026b5c9ef00a8deb2a',
           'fixed actual06 closed original pins differ')
    return p


def is_environment_parent_ancestor(value):
    """Classify the fixed whole original06, without reclassifying any other R6 case."""
    return (isinstance(value, dict)
            and C.descriptor(C.encoded(value)) == {
                'bytes': 8774, 'sha256': ENVIRONMENT_PARENT_BOUNDARY_SHA256})



# This revision is inadmissible until a new explicit property-policy adoption
# has supplied all three current pins. Historical pins are actual old originals.
PROPERTY_PARENT_REFERENCE = 'reference/property_parent_late_boundary_r7.py'
PROPERTY_PARENT_READER_SHA256 = '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'
PROPERTY_PARENT_COMMON_SHA256 = '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'
PROPERTY_PARENT_PACKAGE_SHA256 = '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
PROPERTY_PARENT_COMBINATION_SHA256 = 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
PROPERTY_PARENT_POLICY_SHA256 = '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PROPERTY_PARENT_ADOPTION_SHA256 = 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
PROPERTY_PARENT_CLOSURE_SHA256 = '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'
PROPERTY_PARENT_NONCES = ('2b0b103ee6de7a422064b9571266bf5d','16805e43f9787c44c262d5b6c6d8ed95')
PROPERTY_PARENT_CALL_COUNTS = (1,0)
PROPERTY_PARENT_ORIGINAL_PINS = {'attempt08': {'boundary': {'bytes': 9373, 'sha256': 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'}, 'inventory': {'bytes': 849854, 'sha256': '80b8a56ee78055c19caf3b342af5bc5e479180843b0f3bc223751649188b7fc4'}, 'closure': {'bytes': 54785, 'sha256': '7e42ed77926bdf3bc728e4aef5009ffb23d50adfe1f6ce6b9e236fc621aa17cb'}}, 'attempt07': {'boundary': {'bytes': 9078, 'sha256': '46b03cd66426395198b4a3093117659d5cfb128cc981815934fc1ea695c97be0'}, 'inventory': {'bytes': 776988, 'sha256': '32726cebc8d85dc7086073ba9d6494248a3ec625826a5ed635cffa6715811432'}, 'closure': {'bytes': 25716, 'sha256': 'd5a6433d473ced291328536664497d9fa9861b42f126ecf9ad189df497520a57'}}}
REVIEWED_PROPERTY_PARENT_ANCESTORS = {'attempt08': {'boundary': {'bytes': 9373, 'metadata': [65086, 153711, 33152, 0, 0, 1, 9373, 1793853757339925229, 1793853757339925229], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d.json', 'sha256': 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'}, 'inventory': {'bytes': 849854, 'metadata': [65086, 156653, 33152, 0, 0, 1, 849854, 1793853752103925231, 1793853752103925231], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d/AFTER-INVENTORY.original.json', 'sha256': '80b8a56ee78055c19caf3b342af5bc5e479180843b0f3bc223751649188b7fc4'}, 'closure': {'bytes': 54785, 'metadata': [65086, 157036, 33152, 0, 0, 1, 54785, 1793853752099925231, 1793853752099925231], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d/CLOSURE.original.json', 'sha256': '7e42ed77926bdf3bc728e4aef5009ffb23d50adfe1f6ce6b9e236fc621aa17cb'}}, 'attempt07': {'boundary': {'bytes': 9078, 'metadata': [65086, 155387, 33152, 0, 0, 1, 9078, 1793851076499926252, 1793851076499926252], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/16805e43f9787c44c262d5b6c6d8ed95.json', 'sha256': '46b03cd66426395198b4a3093117659d5cfb128cc981815934fc1ea695c97be0'}, 'inventory': {'bytes': 776988, 'metadata': [65086, 155685, 33152, 0, 0, 1, 776988, 1793851073491926253, 1793851073491926253], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/16805e43f9787c44c262d5b6c6d8ed95/AFTER-INVENTORY.original.json', 'sha256': '32726cebc8d85dc7086073ba9d6494248a3ec625826a5ed635cffa6715811432'}, 'closure': {'bytes': 25716, 'metadata': [65086, 155749, 33152, 0, 0, 1, 25716, 1793851073491926253, 1793851073491926253], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/16805e43f9787c44c262d5b6c6d8ed95/CLOSURE.original.json', 'sha256': 'd5a6433d473ced291328536664497d9fa9861b42f126ecf9ad189df497520a57'}}}
REVIEWED_CURRENT_POLICY_SHA256 = '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
REVIEWED_CURRENT_POLICY_ADOPTION_SHA256 = '98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'


def require_current_revision():
    for name, value, previous in (
            ('combination', REVIEWED_CURRENT_COMBINATION_SHA256, PROPERTY_PARENT_COMBINATION_SHA256),
            ('policy', REVIEWED_CURRENT_POLICY_SHA256, PROPERTY_PARENT_POLICY_SHA256),
            ('adoption', REVIEWED_CURRENT_POLICY_ADOPTION_SHA256, PROPERTY_PARENT_ADOPTION_SHA256)):
        C.need(isinstance(value, str) and C.HASH.fullmatch(value) and value != previous,
               'new current '+name+' has not been explicitly frozen and adopted')
    C.need(REVIEWED_CURRENT_COMBINATION_SHA256 != SOURCE_PARENT_COMBINATION_SHA256
           and REVIEWED_CURRENT_COMBINATION_SHA256 != LEGACY_COMBINATION_SHA256,
           'a retained historical combination cannot become the current revision')
    C.need(REVIEWED_CURRENT_COMBINATION_SHA256 != V3_RUNTIME_DIAGNOSTIC_COMBINATION_SHA256
           and REVIEWED_CURRENT_POLICY_SHA256 != V3_RUNTIME_DIAGNOSTIC_POLICY_SHA256
           and REVIEWED_CURRENT_POLICY_ADOPTION_SHA256 != V3_RUNTIME_DIAGNOSTIC_ADOPTION_SHA256,
           'final generation cannot relabel the unchanged pre-policy v3 diagnostic')
    reviewed_property_parent_ancestors()


def reviewed_property_parent_ancestors():
    records = REVIEWED_PROPERTY_PARENT_ANCESTORS
    C.need(isinstance(records, dict) and set(records) == {'attempt08','attempt07'},
           'the two fixed actual R7 property-parent records are absent')
    result = []
    for name, nonce in zip(('attempt08','attempt07'), PROPERTY_PARENT_NONCES):
        record = records[name]
        C.need(isinstance(record, dict) and set(record) == {'boundary','inventory','closure'},
               'fixed actual R7 record fields differ')
        exact_descriptor(record['boundary'], expected_path=ROOT/(nonce+'.json'))
        for key, filename in (('inventory','AFTER-INVENTORY.original.json'),
                              ('closure','CLOSURE.original.json')):
            exact_descriptor(record[key], expected_path=ROOT/nonce/filename)
        for key, pin in PROPERTY_PARENT_ORIGINAL_PINS[name].items():
            C.need({k:record[key][k] for k in ('bytes','sha256')} == pin,
                   'fixed actual R7 original byte pin differs: '+name+'/'+key)
        result.append(record)
    return result


# Exact failed-closed predecessor of the diagnostic mapper generation.
# The new implementation composes a pure historical reader; it never marks
# this module as the old publisher or replays the old mapper with new sources.
DIAGNOSTIC_PARENT_NONCE = '902e851c3ca1f90deab3d880ab993774'
DIAGNOSTIC_PARENT_PACKAGE_SHA256 = '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'
DIAGNOSTIC_PARENT_COMBINATION_SHA256 = '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'
DIAGNOSTIC_PARENT_PUBLISHER_SHA256 = '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'
DIAGNOSTIC_PARENT_COMMON_SHA256 = '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'
DIAGNOSTIC_PARENT_CLOSURE_SHA256 = '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'
DIAGNOSTIC_PARENT_MAPPER_SHA256 = 'f16c77c1b4509babcea5fc2e8d0a7ae8ab43b3cd58e6640441b44ecd4bccb6df'
DIAGNOSTIC_PARENT_BOUNDARY_FUNCTION_SHA256 = 'b72dbb687a5b465ed4b1318afbf47ad37f31bed2e73916cc2bebb45f5456f8fd'
REVIEWED_DIAGNOSTIC_PARENT_ANCESTOR = {'boundary': {'bytes': 9686, 'metadata': [65086, 156280, 33152, 0, 0, 1, 9686, 1793882486435914270, 1793882486435914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774.json', 'sha256': '6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'}, 'inventory': {'bytes': 923078, 'metadata': [65086, 156601, 33152, 0, 0, 1, 923078, 1793882485267914270, 1793882485267914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774/AFTER-INVENTORY.original.json', 'sha256': 'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d'}, 'closure': {'bytes': 55124, 'metadata': [65086, 156890, 33152, 0, 0, 1, 55124, 1793882485259914270, 1793882485259914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774/CLOSURE.original.json', 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'}}


def reviewed_diagnostic_parent_ancestor():
    record = REVIEWED_DIAGNOSTIC_PARENT_ANCESTOR
    C.need(type(record) is dict and set(record) == {'boundary','inventory','closure'},
           'fixed failed-closed diagnostic predecessor is absent')
    exact_descriptor(record['boundary'], expected_path=ROOT/(DIAGNOSTIC_PARENT_NONCE+'.json'))
    exact_descriptor(record['inventory'], expected_path=ROOT/DIAGNOSTIC_PARENT_NONCE/'AFTER-INVENTORY.original.json')
    exact_descriptor(record['closure'], expected_path=ROOT/DIAGNOSTIC_PARENT_NONCE/'CLOSURE.original.json')
    C.need({k:record['boundary'][k] for k in ('bytes','sha256')} ==
           {'bytes':9686,'sha256':'6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'}
           and {k:record['inventory'][k] for k in ('bytes','sha256')} ==
           {'bytes':923078,'sha256':'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d'}
           and {k:record['closure'][k] for k in ('bytes','sha256')} ==
           {'bytes':55124,'sha256':'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'},
           'fixed diagnostic predecessor original pins differ')
    return record


def diagnostic_parent_context(combination_sha256, package_sha256):
    C.need(combination_sha256 == DIAGNOSTIC_PARENT_COMBINATION_SHA256
           and package_sha256 == DIAGNOSTIC_PARENT_PACKAGE_SHA256,
           'historical diagnostic predecessor must use its own exact generation')


def is_diagnostic_parent_ancestor(value):
    if type(value) is not dict:
        return False
    record = reviewed_diagnostic_parent_ancestor()
    return C.descriptor(C.encoded(value)) == {k:record['boundary'][k] for k in ('bytes','sha256')}


def diagnostic_parent_boundary_value(value, *, combination_sha256, package_sha256):
    diagnostic_parent_context(combination_sha256, package_sha256)
    C.need(isinstance(value, dict) and set(value) == FIELDS
           and value['schema'] == SCHEMA and value['state'] == STATE,
           'explicit independently closed late boundary required')
    C.need(value['combination_sha256'] == combination_sha256
           and value['package_sha256'] == package_sha256
           and all(isinstance(value[k], str) and C.HASH.fullmatch(value[k]) for k in
                   ('owner_request_sha256', 'package_sha256', 'combination_sha256', 'publisher_source_sha256')),
           'closed boundary source/combination binding differs')
    C.need(value['publisher_source_sha256'] == DIAGNOSTIC_PARENT_PUBLISHER_SHA256,
           'closed boundary publisher is not this reviewed package source')
    C.need(re.fullmatch('[0-9a-f]{32}', value['nonce'])
           and re.fullmatch('[0-9a-f-]{36}', value['boot_id'])
           and value['case_id'] in ('NEG-01', 'NEG-02'), 'closed component identity differs')
    C.scope(value['scope'])
    C.need(value['original_retirement_rewritten'] is False and value['business_qualified'] is False
           and type(value['model_requests']) is int and value['model_requests'] == 0
           and value['automatic_replay'] is False, 'boundary overstates qualification or permits replay')
    C.need(type(value['component_qualified']) is bool
           and value['native_status'] in ('completed', 'provider_failed', 'cancelled')
           and type(value['actual_native_calls']) is int and 0 <= value['actual_native_calls'] <= 2,
           'closed native outcome/count differs')
    home = ROOT / value['nonce']
    exact_descriptor(value['inventory'], expected_path=home / 'AFTER-INVENTORY.original.json')
    exact_descriptor(value['closure'], expected_path=home / 'CLOSURE.original.json')
    if value['prior_boundary'] is not None:
        p = exact_descriptor(value['prior_boundary'])
        C.need(p.parent == ROOT and re.fullmatch(r'[0-9a-f]{32}\.json', p.name),
               'prior boundary left the dedicated original namespace')
    roles = value['component_role_identities']
    C.need(isinstance(roles, dict) and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(isinstance(v, list) and len(v) == 4 and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3, 'closed component role identities differ')
    sidebranch = non_native_sidebranch()
    C.need(value.get('non_native_sidebranch') == sidebranch['binding']
           and value['nonce'] != sidebranch['binding']['nonce'],
           'current native boundary omitted or reinterpreted the fixed non-native sidebranch')
    return value



def diagnostic_parent_from_original(raw, original_descriptor):
    record = reviewed_diagnostic_parent_ancestor()
    C.need(type(raw) is bytes and original_descriptor == record['boundary']
           and C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')},
           'diagnostic predecessor bytes or original full identity differ')
    value = diagnostic_parent_boundary_value(C.strict(raw),
        combination_sha256=DIAGNOSTIC_PARENT_COMBINATION_SHA256,
        package_sha256=DIAGNOSTIC_PARENT_PACKAGE_SHA256)
    C.need(value['nonce'] == DIAGNOSTIC_PARENT_NONCE
           and value['inventory'] == record['inventory'] and value['closure'] == record['closure']
           and value['prior_boundary'] == reviewed_property_parent_ancestors()[0]['boundary']
           and value['component_qualified'] is False and value['native_status'] == 'provider_failed'
           and type(value['actual_native_calls']) is int and value['actual_native_calls'] == 1,
           'fixed diagnostic predecessor was omitted, promoted or reinterpreted')
    return value


def diagnostic_parent_reader_provenance():
    return {'schema':'hepta.native-guard.diagnostic-parent-reader-provenance.v1',
        'implementation_source_sha256':reviewed_source_sha256(),
        'historical_publisher_source_sha256':DIAGNOSTIC_PARENT_PUBLISHER_SHA256,
        'historical_boundary_function_sha256':DIAGNOSTIC_PARENT_BOUNDARY_FUNCTION_SHA256,
        'historical_package_sha256':DIAGNOSTIC_PARENT_PACKAGE_SHA256,
        'historical_combination_sha256':DIAGNOSTIC_PARENT_COMBINATION_SHA256,
        'historical_mapper_sha256':DIAGNOSTIC_PARENT_MAPPER_SHA256,
        'execution':'new reviewed pure reader composition',
        'historical_publisher_executed_unchanged':False,
        'historical_mapper_recomputed_with_current_source':False}


# Exact failed6077 used the original 8b9a/b4d4/f220/8ee generation.
# This is a new pure reader composition, not an execution of the old publisher.
CODEC_DIAGNOSTIC_PARENT_NONCE = '6077fc8f045572edc4acfb13ed7e09a8'
CODEC_DIAGNOSTIC_PARENT_PACKAGE_SHA256 = '8b9a3b24f2449022120f7f1ef15905ee9a07edac8062fcf46cf7bb0b0c8e7302'
CODEC_DIAGNOSTIC_PARENT_COMBINATION_SHA256 = 'b4d4a221a4a516177cecf8e182a7ee9a494fc65feb85277cfdf10d28396d5709'
CODEC_DIAGNOSTIC_PARENT_PUBLISHER_SHA256 = 'f220f25fe355e5c6591d6fe6f420fb474e166404fcdb4828799e446ae3d46646'
CODEC_DIAGNOSTIC_PARENT_COMMON_SHA256 = '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'
CODEC_DIAGNOSTIC_PARENT_CLOSURE_SHA256 = '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'
CODEC_DIAGNOSTIC_PARENT_MAPPER_SHA256 = '8ee1782227472737ebb5854bef959f899f3c873714d85eff4f9360f995b18040'
CODEC_DIAGNOSTIC_PARENT_BOUNDARY_FUNCTION_SHA256 = 'b72dbb687a5b465ed4b1318afbf47ad37f31bed2e73916cc2bebb45f5456f8fd'
REVIEWED_CODEC_DIAGNOSTIC_PARENT_ANCESTOR = {'boundary': {'bytes': 9998, 'metadata': [65086, 149888, 33152, 0, 0, 1, 9998, 1793894221355909793, 1793894221355909793], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/6077fc8f045572edc4acfb13ed7e09a8.json', 'sha256': '621f82a3c071c755f4460f591ac1faa92ec6940b2a19c7a4d76948668abf669e'}, 'inventory': {'bytes': 996847, 'metadata': [65086, 157104, 33152, 0, 0, 1, 996847, 1793894219967909794, 1793894219967909794], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/AFTER-INVENTORY.original.json', 'sha256': '4d64153c7cecf0782bb804791cf272e01ca83ae0b36d9927096762cc3fafc228'}, 'closure': {'bytes': 55184, 'metadata': [65086, 156366, 33152, 0, 0, 1, 55184, 1793894219963909794, 1793894219963909794], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/CLOSURE.original.json', 'sha256': '35af6a58a84413770bb14ede44eca83ac2774cd4591c7df1501b501cb1643335'}}


def reviewed_codec_diagnostic_parent_ancestor():
    record = REVIEWED_CODEC_DIAGNOSTIC_PARENT_ANCESTOR
    C.need(type(record) is dict and set(record) == {'boundary','inventory','closure'},
           'fixed failed6077 predecessor is absent')
    exact_descriptor(record['boundary'], expected_path=ROOT/(CODEC_DIAGNOSTIC_PARENT_NONCE+'.json'))
    exact_descriptor(record['inventory'], expected_path=ROOT/CODEC_DIAGNOSTIC_PARENT_NONCE/'AFTER-INVENTORY.original.json')
    exact_descriptor(record['closure'], expected_path=ROOT/CODEC_DIAGNOSTIC_PARENT_NONCE/'CLOSURE.original.json')
    C.need({k:record['boundary'][k] for k in ('bytes','sha256')} == {'bytes': 9998, 'sha256': '621f82a3c071c755f4460f591ac1faa92ec6940b2a19c7a4d76948668abf669e'}
           and {k:record['inventory'][k] for k in ('bytes','sha256')} == {'bytes': 996847, 'sha256': '4d64153c7cecf0782bb804791cf272e01ca83ae0b36d9927096762cc3fafc228'}
           and {k:record['closure'][k] for k in ('bytes','sha256')} == {'bytes': 55184, 'sha256': '35af6a58a84413770bb14ede44eca83ac2774cd4591c7df1501b501cb1643335'},
           'fixed failed6077 original pins differ')
    return record


def codec_diagnostic_parent_context(combination_sha256, package_sha256):
    C.need(combination_sha256 == CODEC_DIAGNOSTIC_PARENT_COMBINATION_SHA256
           and package_sha256 == CODEC_DIAGNOSTIC_PARENT_PACKAGE_SHA256,
           'historical failed6077 must use its own exact executed generation')


def is_codec_diagnostic_parent_ancestor(value):
    if type(value) is not dict:
        return False
    record = reviewed_codec_diagnostic_parent_ancestor()
    return C.descriptor(C.encoded(value)) == {k:record['boundary'][k] for k in ('bytes','sha256')}


def codec_diagnostic_parent_boundary_value(value, *, combination_sha256, package_sha256):
    codec_diagnostic_parent_context(combination_sha256, package_sha256)
    C.need(isinstance(value, dict) and set(value) == FIELDS
           and value['schema'] == SCHEMA and value['state'] == STATE,
           'explicit independently closed late boundary required')
    C.need(value['combination_sha256'] == combination_sha256
           and value['package_sha256'] == package_sha256
           and all(isinstance(value[k], str) and C.HASH.fullmatch(value[k]) for k in
                   ('owner_request_sha256', 'package_sha256', 'combination_sha256', 'publisher_source_sha256')),
           'closed boundary source/combination binding differs')
    C.need(value['publisher_source_sha256'] == CODEC_DIAGNOSTIC_PARENT_PUBLISHER_SHA256,
           'closed boundary publisher is not this reviewed package source')
    C.need(re.fullmatch('[0-9a-f]{32}', value['nonce'])
           and re.fullmatch('[0-9a-f-]{36}', value['boot_id'])
           and value['case_id'] in ('NEG-01', 'NEG-02'), 'closed component identity differs')
    C.scope(value['scope'])
    C.need(value['original_retirement_rewritten'] is False and value['business_qualified'] is False
           and type(value['model_requests']) is int and value['model_requests'] == 0
           and value['automatic_replay'] is False, 'boundary overstates qualification or permits replay')
    C.need(type(value['component_qualified']) is bool
           and value['native_status'] in ('completed', 'provider_failed', 'cancelled')
           and type(value['actual_native_calls']) is int and 0 <= value['actual_native_calls'] <= 2,
           'closed native outcome/count differs')
    home = ROOT / value['nonce']
    exact_descriptor(value['inventory'], expected_path=home / 'AFTER-INVENTORY.original.json')
    exact_descriptor(value['closure'], expected_path=home / 'CLOSURE.original.json')
    if value['prior_boundary'] is not None:
        p = exact_descriptor(value['prior_boundary'])
        C.need(p.parent == ROOT and re.fullmatch(r'[0-9a-f]{32}\.json', p.name),
               'prior boundary left the dedicated original namespace')
    roles = value['component_role_identities']
    C.need(isinstance(roles, dict) and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(isinstance(v, list) and len(v) == 4 and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3, 'closed component role identities differ')
    sidebranch = non_native_sidebranch()
    C.need(value.get('non_native_sidebranch') == sidebranch['binding']
           and value['nonce'] != sidebranch['binding']['nonce'],
           'current native boundary omitted or reinterpreted the fixed non-native sidebranch')
    return value



def codec_diagnostic_parent_from_original(raw, original_descriptor):
    record = reviewed_codec_diagnostic_parent_ancestor()
    C.need(type(raw) is bytes and original_descriptor == record['boundary']
           and C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')},
           'failed6077 bytes or original full identity differ')
    value = codec_diagnostic_parent_boundary_value(C.strict(raw),
        combination_sha256=CODEC_DIAGNOSTIC_PARENT_COMBINATION_SHA256,
        package_sha256=CODEC_DIAGNOSTIC_PARENT_PACKAGE_SHA256)
    C.need(value['nonce'] == CODEC_DIAGNOSTIC_PARENT_NONCE
           and value['inventory'] == record['inventory'] and value['closure'] == record['closure']
           and value['prior_boundary'] == reviewed_diagnostic_parent_ancestor()['boundary']
           and value['component_qualified'] is False and value['native_status'] == 'provider_failed'
           and type(value['actual_native_calls']) is int and value['actual_native_calls'] == 1,
           'fixed failed6077 was omitted, promoted or reinterpreted')
    return value


def codec_diagnostic_parent_reader_provenance():
    return {'schema':'hepta.native-guard.codec-diagnostic-parent-reader-provenance.v1',
        'implementation_source_sha256':reviewed_source_sha256(),
        'historical_publisher_source_sha256':CODEC_DIAGNOSTIC_PARENT_PUBLISHER_SHA256,
        'historical_boundary_function_sha256':CODEC_DIAGNOSTIC_PARENT_BOUNDARY_FUNCTION_SHA256,
        'historical_package_sha256':CODEC_DIAGNOSTIC_PARENT_PACKAGE_SHA256,
        'historical_combination_sha256':CODEC_DIAGNOSTIC_PARENT_COMBINATION_SHA256,
        'historical_mapper_sha256':CODEC_DIAGNOSTIC_PARENT_MAPPER_SHA256,
        'execution':'new reviewed pure reader composition',
        'historical_publisher_executed_unchanged':False,
        'historical_mapper_recomputed_with_current_source':False}


# Exact failed820 historical family. These pins name executed v1, not v3.
STACK_DIAGNOSTIC_PARENT_NONCE = '82012c7447c5f35d97c832d1d9481860'
STACK_DIAGNOSTIC_PARENT_PACKAGE_SHA256 = '5efc7e38d40cb74111001a961e9060eac72050fd5aca9d5bf6fcc08c5d017f47'
STACK_DIAGNOSTIC_PARENT_COMBINATION_SHA256 = '765e66acedee58e41de0ef45b6ea8061709e5b63a7aef43437876349289e86ec'
STACK_DIAGNOSTIC_PARENT_PUBLISHER_SHA256 = '7b085c88e5e4bfd78ddfaa41f9db47b8476644127e798fcd918599ca32652980'
STACK_DIAGNOSTIC_PARENT_COMMON_SHA256 = '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'
STACK_DIAGNOSTIC_PARENT_CLOSURE_SHA256 = '5cf82a59264f87ea565581a8d29790dacdad9a17ec67b3b17e15cd4762494f87'
STACK_DIAGNOSTIC_PARENT_MAPPER_SHA256 = '5f65cc1ac383eca37f1081fae775be8d4243eae91169ba958a72c85b24476eb7'
STACK_DIAGNOSTIC_PARENT_BOUNDARY_FUNCTION_SHA256 = 'aa6c21ebc5af88d8a0d285f716dd734ac88e6c0686b203fdf91e229bc1bf2b1d'
REVIEWED_STACK_DIAGNOSTIC_PARENT_ANCESTOR = {'boundary': {'bytes': 21002, 'metadata': [65086, 159031, 33152, 0, 0, 1, 21002, 1793920477083899777, 1793920477083899777], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/82012c7447c5f35d97c832d1d9481860.json', 'sha256': '2433dd817e470e9536ec314b6a8e9d395a47053f7c1aba1cd7adee35635843fc'}, 'inventory': {'bytes': 1107000, 'metadata': [65086, 158938, 33152, 0, 0, 1, 1107000, 1793920473643899779, 1793920473643899779], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/82012c7447c5f35d97c832d1d9481860/AFTER-INVENTORY.original.json', 'sha256': '115893679cea5f3606f4adef61c4b01ecdc65870b6aa0c8c862df4e0313f90aa'}, 'closure': {'bytes': 66879, 'metadata': [65086, 158937, 33152, 0, 0, 1, 66879, 1793920473643899779, 1793920473643899779], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/82012c7447c5f35d97c832d1d9481860/CLOSURE.original.json', 'sha256': 'd2671a0f936f3c1c7e4846117050880bb3140e13fe4fb7723be7786d83d66ccf'}}


def reviewed_stack_diagnostic_parent_ancestor():
    record = REVIEWED_STACK_DIAGNOSTIC_PARENT_ANCESTOR
    C.need(type(record) is dict and set(record) == {'boundary','inventory','closure'},
           'fixed failed820 predecessor is absent')
    exact_descriptor(record['boundary'], expected_path=ROOT/(STACK_DIAGNOSTIC_PARENT_NONCE+'.json'))
    exact_descriptor(record['inventory'], expected_path=ROOT/STACK_DIAGNOSTIC_PARENT_NONCE/'AFTER-INVENTORY.original.json')
    exact_descriptor(record['closure'], expected_path=ROOT/STACK_DIAGNOSTIC_PARENT_NONCE/'CLOSURE.original.json')
    C.need({k:record['boundary'][k] for k in ('bytes','sha256')} == {'bytes': 21002, 'sha256': '2433dd817e470e9536ec314b6a8e9d395a47053f7c1aba1cd7adee35635843fc'}
           and {k:record['inventory'][k] for k in ('bytes','sha256')} == {'bytes': 1107000, 'sha256': '115893679cea5f3606f4adef61c4b01ecdc65870b6aa0c8c862df4e0313f90aa'}
           and {k:record['closure'][k] for k in ('bytes','sha256')} == {'bytes': 66879, 'sha256': 'd2671a0f936f3c1c7e4846117050880bb3140e13fe4fb7723be7786d83d66ccf'},
           'fixed failed820 full original byte pins differ')
    return record


def stack_diagnostic_parent_context(combination_sha256, package_sha256):
    C.need(combination_sha256 == STACK_DIAGNOSTIC_PARENT_COMBINATION_SHA256
           and package_sha256 == STACK_DIAGNOSTIC_PARENT_PACKAGE_SHA256,
           'historical failed820 must use exact executed 5efc/765e/f821 generation')


def is_stack_diagnostic_parent_ancestor(value):
    if type(value) is not dict:
        return False
    record = reviewed_stack_diagnostic_parent_ancestor()
    return C.descriptor(C.encoded(value)) == {k:record['boundary'][k] for k in ('bytes','sha256')}


def stack_diagnostic_parent_boundary_value(value, *, combination_sha256, package_sha256):
    stack_diagnostic_parent_context(combination_sha256, package_sha256)
    C.need(isinstance(value, dict) and set(value) == CURRENT_FIELDS
           and value['schema'] == SCHEMA and value['state'] == STATE,
           'explicit independently closed late boundary required')
    C.need(value['combination_sha256'] == combination_sha256
           and value['package_sha256'] == package_sha256
           and all(isinstance(value[k], str) and C.HASH.fullmatch(value[k]) for k in
                   ('owner_request_sha256', 'package_sha256', 'combination_sha256', 'publisher_source_sha256')),
           'closed boundary source/combination binding differs')
    C.need(value['publisher_source_sha256'] == STACK_DIAGNOSTIC_PARENT_PUBLISHER_SHA256,
           'closed boundary publisher is not this reviewed package source')
    C.need(re.fullmatch('[0-9a-f]{32}', value['nonce'])
           and re.fullmatch('[0-9a-f-]{36}', value['boot_id'])
           and value['case_id'] in ('NEG-01', 'NEG-02'), 'closed component identity differs')
    C.scope(value['scope'])
    C.need(value['original_retirement_rewritten'] is False and value['business_qualified'] is False
           and type(value['model_requests']) is int and value['model_requests'] == 0
           and value['automatic_replay'] is False, 'boundary overstates qualification or permits replay')
    C.need(type(value['component_qualified']) is bool
           and value['native_status'] in ('completed', 'provider_failed', 'cancelled')
           and type(value['actual_native_calls']) is int and 0 <= value['actual_native_calls'] <= 2,
           'closed native outcome/count differs')
    home = ROOT / value['nonce']
    exact_descriptor(value['inventory'], expected_path=home / 'AFTER-INVENTORY.original.json')
    exact_descriptor(value['closure'], expected_path=home / 'CLOSURE.original.json')
    if value['prior_boundary'] is not None:
        p = exact_descriptor(value['prior_boundary'])
        C.need(p.parent == ROOT and re.fullmatch(r'[0-9a-f]{32}\.json', p.name),
               'prior boundary left the dedicated original namespace')
    roles = value['component_role_identities']
    C.need(isinstance(roles, dict) and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(isinstance(v, list) and len(v) == 4 and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3, 'closed component role identities differ')
    sidebranch = non_native_sidebranch()
    C.need(value.get('non_native_sidebranch') == sidebranch['binding']
           and value['nonce'] != sidebranch['binding']['nonce'],
           'current native boundary omitted or reinterpreted the fixed non-native sidebranch')
    current_sidebranch_bindings(value)
    return value


def stack_diagnostic_parent_from_original(raw, original_descriptor):
    record = reviewed_stack_diagnostic_parent_ancestor()
    C.need(type(raw) is bytes and original_descriptor == record['boundary']
           and C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')},
           'failed820 bytes or full original identity differ')
    value = stack_diagnostic_parent_boundary_value(C.strict(raw),
        combination_sha256=STACK_DIAGNOSTIC_PARENT_COMBINATION_SHA256,
        package_sha256=STACK_DIAGNOSTIC_PARENT_PACKAGE_SHA256)
    C.need(value['nonce'] == STACK_DIAGNOSTIC_PARENT_NONCE
           and value['inventory'] == record['inventory'] and value['closure'] == record['closure']
           and value['prior_boundary'] == reviewed_codec_diagnostic_parent_ancestor()['boundary']
           and value['component_qualified'] is False and value['native_status'] == 'provider_failed'
           and type(value['actual_native_calls']) is int and value['actual_native_calls'] == 1,
           'fixed failed820 was omitted, promoted or reinterpreted')
    return value


def stack_diagnostic_parent_reader_provenance():
    return {'schema':'hepta.native-guard.stack-diagnostic-parent-reader-provenance.v1',
        'implementation_source_sha256':reviewed_source_sha256(),
        'historical_publisher_source_sha256':STACK_DIAGNOSTIC_PARENT_PUBLISHER_SHA256,
        'historical_boundary_function_sha256':STACK_DIAGNOSTIC_PARENT_BOUNDARY_FUNCTION_SHA256,
        'historical_package_sha256':STACK_DIAGNOSTIC_PARENT_PACKAGE_SHA256,
        'historical_combination_sha256':STACK_DIAGNOSTIC_PARENT_COMBINATION_SHA256,
        'historical_mapper_sha256':STACK_DIAGNOSTIC_PARENT_MAPPER_SHA256,
        'execution':'new reviewed pure reader composition',
        'historical_publisher_executed_unchanged':False,
        'historical_mapper_recomputed_with_current_source':False}


# Executed v3/f821 diagnostic family: actual original identity is REQUIRED.
V3_RUNTIME_DIAGNOSTIC_NONCE = 'a493b853566d68099f7dbc0a124aff50'
V3_RUNTIME_DIAGNOSTIC_RECORD = {'boundary': {'bytes': 21325, 'metadata': [65086, 158182, 33152, 0, 0, 1, 21325, 1793928633271896666, 1793928633271896666], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50.json', 'sha256': 'fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66'}, 'inventory': {'bytes': 1182289, 'metadata': [65086, 158128, 33152, 0, 0, 1, 1182289, 1793928630371896667, 1793928630371896667], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50/AFTER-INVENTORY.original.json', 'sha256': 'bd880b6dbfe1a870eab9d0dc6e3916e8bc539d115975c5b983c65742fbab6242'}, 'closure': {'bytes': 70349, 'metadata': [65086, 156987, 33152, 0, 0, 1, 70349, 1793928630371896667, 1793928630371896667], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50/CLOSURE.original.json', 'sha256': 'ed3163d67036a437bc3855bad22543bc5bb9d8ecf71e1952b704f1dfa3eac7f2'}}
V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256 = 'd30e58c42205fa99cdb9367d7f1186532d27a1d20a2bfe20a1c41c387ddffc70'
V3_RUNTIME_DIAGNOSTIC_COMBINATION_SHA256 = 'f265d39c001aa09a813a03b92b0a96689ab1bcc431c8e408c8ce4da80693a945'
V3_RUNTIME_DIAGNOSTIC_PUBLISHER_SHA256 = '311cfa163ba7ae603ef3483846abb52a958342ac1149cc59c842c63a79f3ab15'
V3_RUNTIME_DIAGNOSTIC_CLOSURE_SHA256 = 'f88efe8b7fb73151ec1598ba556379c53c0aadd1073ad6da03a9ff0cbd04a2c4'
V3_RUNTIME_DIAGNOSTIC_POLICY_SHA256 = 'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
V3_RUNTIME_DIAGNOSTIC_ADOPTION_SHA256 = '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
V3_RUNTIME_DIAGNOSTIC_BOUNDARY_FUNCTION_SHA256 = '265b23e473fcabf9bc00d7ab6819c82c79eedbe8b162817c4ba48924a631ffc5'


def reviewed_v3_runtime_diagnostic_ancestor():
    record = V3_RUNTIME_DIAGNOSTIC_RECORD
    C.need(type(record) is dict and set(record) == {'boundary','inventory','closure'}
           and isinstance(V3_RUNTIME_DIAGNOSTIC_NONCE, str)
           and re.fullmatch('[0-9a-f]{32}', V3_RUNTIME_DIAGNOSTIC_NONCE),
           'actual closed v3 diagnostic original identity is not bound')
    exact_descriptor(record['boundary'], expected_path=ROOT/(V3_RUNTIME_DIAGNOSTIC_NONCE+'.json'))
    exact_descriptor(record['inventory'], expected_path=ROOT/V3_RUNTIME_DIAGNOSTIC_NONCE/'AFTER-INVENTORY.original.json')
    exact_descriptor(record['closure'], expected_path=ROOT/V3_RUNTIME_DIAGNOSTIC_NONCE/'CLOSURE.original.json')
    return record


def v3_runtime_diagnostic_context(combination_sha256, package_sha256):
    C.need(combination_sha256 == V3_RUNTIME_DIAGNOSTIC_COMBINATION_SHA256
           and package_sha256 == V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256,
           'v3 diagnostic must retain its executed f821 combination and source generation')


def is_v3_runtime_diagnostic_ancestor(value):
    if type(value) is not dict:
        return False
    record = reviewed_v3_runtime_diagnostic_ancestor()
    return C.descriptor(C.encoded(value)) == {k:record['boundary'][k] for k in ('bytes','sha256')}


def v3_runtime_diagnostic_boundary_value(value, *, combination_sha256, package_sha256):
    v3_runtime_diagnostic_context(combination_sha256, package_sha256)
    C.need(isinstance(value, dict) and set(value) == CURRENT_FIELDS
           and value['schema'] == SCHEMA and value['state'] == STATE,
           'explicit independently closed late boundary required')
    C.need(value['combination_sha256'] == combination_sha256
           and value['package_sha256'] == package_sha256
           and all(isinstance(value[k], str) and C.HASH.fullmatch(value[k]) for k in
                   ('owner_request_sha256', 'package_sha256', 'combination_sha256', 'publisher_source_sha256')),
           'closed boundary source/combination binding differs')
    C.need(value['publisher_source_sha256'] == V3_RUNTIME_DIAGNOSTIC_PUBLISHER_SHA256,
           'closed boundary publisher is not this reviewed package source')
    C.need(re.fullmatch('[0-9a-f]{32}', value['nonce'])
           and re.fullmatch('[0-9a-f-]{36}', value['boot_id'])
           and value['case_id'] in ('NEG-01', 'NEG-02'), 'closed component identity differs')
    C.scope(value['scope'])
    C.need(value['original_retirement_rewritten'] is False and value['business_qualified'] is False
           and type(value['model_requests']) is int and value['model_requests'] == 0
           and value['automatic_replay'] is False, 'boundary overstates qualification or permits replay')
    C.need(type(value['component_qualified']) is bool
           and value['native_status'] in ('completed', 'provider_failed', 'cancelled')
           and type(value['actual_native_calls']) is int and 0 <= value['actual_native_calls'] <= 2,
           'closed native outcome/count differs')
    home = ROOT / value['nonce']
    exact_descriptor(value['inventory'], expected_path=home / 'AFTER-INVENTORY.original.json')
    exact_descriptor(value['closure'], expected_path=home / 'CLOSURE.original.json')
    if value['prior_boundary'] is not None:
        p = exact_descriptor(value['prior_boundary'])
        C.need(p.parent == ROOT and re.fullmatch(r'[0-9a-f]{32}\.json', p.name),
               'prior boundary left the dedicated original namespace')
    roles = value['component_role_identities']
    C.need(isinstance(roles, dict) and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(isinstance(v, list) and len(v) == 4 and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3, 'closed component role identities differ')
    sidebranch = non_native_sidebranch()
    C.need(value.get('non_native_sidebranch') == sidebranch['binding']
           and value['nonce'] != sidebranch['binding']['nonce'],
           'current native boundary omitted or reinterpreted the fixed non-native sidebranch')
    current_sidebranch_bindings(value)
    C.need(value['component_qualified'] is False and value['case_id'] == 'NEG-01'
           and value['native_status'] in ('provider_failed', 'cancelled')
           and value['actual_native_calls'] <= 1, 'DIAGNOSTIC_ONLY never grants NEG credit or second call')
    return value


def v3_runtime_diagnostic_from_original(raw, original_descriptor):
    record = reviewed_v3_runtime_diagnostic_ancestor()
    C.need(type(raw) is bytes and original_descriptor == record['boundary']
           and C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')},
           'v3 diagnostic full original identity differs')
    value = v3_runtime_diagnostic_boundary_value(C.strict(raw),
        combination_sha256=V3_RUNTIME_DIAGNOSTIC_COMBINATION_SHA256,
        package_sha256=V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256)
    C.need(value['nonce'] == V3_RUNTIME_DIAGNOSTIC_NONCE
           and value['inventory'] == record['inventory'] and value['closure'] == record['closure']
           and value['prior_boundary'] == reviewed_stack_diagnostic_parent_ancestor()['boundary']
           and value['component_qualified'] is False and value['native_status'] == 'provider_failed'
           and type(value['actual_native_calls']) is int and value['actual_native_calls'] == 1,
           'v3 diagnostic was skipped, promoted or reinterpreted')
    return value


def v3_runtime_diagnostic_reader_provenance():
    return {'schema':'hepta.native-guard.v3-runtime-diagnostic-reader-provenance.v1',
        'implementation_source_sha256':reviewed_source_sha256(),
        'historical_publisher_source_sha256':V3_RUNTIME_DIAGNOSTIC_PUBLISHER_SHA256,
        'historical_boundary_function_sha256':V3_RUNTIME_DIAGNOSTIC_BOUNDARY_FUNCTION_SHA256,
        'historical_package_sha256':V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256,
        'historical_combination_sha256':V3_RUNTIME_DIAGNOSTIC_COMBINATION_SHA256,
        'historical_policy_sha256':V3_RUNTIME_DIAGNOSTIC_POLICY_SHA256,
        'historical_adoption_sha256':V3_RUNTIME_DIAGNOSTIC_ADOPTION_SHA256,
        'execution':'new reviewed pure reader composition',
        'historical_publisher_executed_unchanged':False,
        'historical_mapper_recomputed_with_current_source':False}


def property_parent_records():
    return [*reviewed_property_parent_ancestors(), reviewed_environment_parent_ancestor(),
            reviewed_pre_policy_ancestor(), reviewed_failed_ancestor()]


def is_property_parent_ancestor(value):
    if not isinstance(value, dict):
        return False
    descriptor = C.descriptor(C.encoded(value))
    return any(descriptor == {k:row['boundary'][k] for k in ('bytes','sha256')}
               for row in reviewed_property_parent_ancestors())


def _retained_property_parent_original(raw, original_descriptor):
    for index, record in enumerate(property_parent_records()):
        if C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')}:
            C.need(original_descriptor == record['boundary'],
                   'fixed retained boundary full original identity differs')
            return index, record
    return None


# This is a current reader composition, never a replacement historical publisher.
_PROPERTY_CURRENT_INVENTORY_PIN = {'bytes': 3788, 'sha256': '086dedcdc7ac8d1627e1c2592ed7a9f130a4395dd4b27e9bc86a512c91af06f1'}
_PROPERTY_ORIGINAL_INVENTORY_PIN = {'bytes': 3610, 'sha256': '089e36ccc22a7ce83905623c5e1247a689a719a5e8094c681d007f5fe50aa0b4'}
_PROPERTY_INVENTORY_BUILTINS = ('all', 'dict', 'frozenset', 'int', 'isinstance', 'len', 'list', 'set', 'sorted', 'str', 'sum', 'type', 'zip')
_PROPERTY_READER_METHODS = ('boundary_from_original', 'closed_boundary_originals',
                          'require_failed_ancestor_tail', 'environment_parent_reader')


class CurrentPropertyParentReader:
    """Only the four reader methods used by this exact current R8 source."""
    __slots__ = ('_methods', '_provenance')

    def __init__(self, methods, provenance):
        from types import MappingProxyType
        C.need(set(methods) == set(_PROPERTY_READER_METHODS)
               and all(callable(f) for f in methods.values()),
               'exact current property-parent reader methods required')
        object.__setattr__(self, '_methods', MappingProxyType(dict(methods)))
        object.__setattr__(self, '_provenance', C.encoded(provenance))

    def __getattr__(self, name):
        try:
            return self._methods[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name, value):
        raise AttributeError('current property-parent reader is immutable')

    def provenance(self):
        return C.strict(self._provenance)


def _current_property_parent_reader(old, original_raw):
    """Rebind only pure membership in a freshly loaded, exact historical R7.

    Every historical method still uses its original module globals. Its
    inventory_value slot selects this current source's exact helper code.
    The historical file path remains a location anchor for unchanged nested
    readers; it is not the execution identity of the composed current reader.
    """
    import ast
    import types
    C.need(type(original_raw) is bytes and len(original_raw) == 62434
           and C.sha(original_raw) == PROPERTY_PARENT_READER_SHA256
           and old.__dict__.get('__reviewed_source_sha256__') == PROPERTY_PARENT_READER_SHA256,
           'exact freshly loaded R7 original required for current membership')
    text = original_raw.decode('utf-8', 'strict')
    nodes = [n for n in ast.parse(text).body
             if isinstance(n, ast.FunctionDef) and n.name == 'inventory_value']
    C.need(len(nodes) == 1, 'one exact historical inventory function required')
    node = nodes[0]
    original = ''.join(text.splitlines(keepends=True)[node.lineno-1:node.end_lineno]).encode('utf-8')
    C.need(C.descriptor(original) == _PROPERTY_ORIGINAL_INVENTORY_PIN,
           'historical inventory function provenance differs')
    current_source = reviewed_source_sha256()
    supplied = globals().get('__reviewed_package_sources__')
    if supplied is None:
        current_raw = C.read(Path(__file__), 1048576, private=False)
    else:
        C.need(isinstance(supplied, dict) and 'source/late_boundary.py' in supplied,
               'current membership source is absent from reviewed package')
        current_raw = supplied['source/late_boundary.py']
    C.need(type(current_raw) is bytes and 0 < len(current_raw) <= 1048576
           and C.sha(current_raw) == current_source,
           'current membership source bytes differ')
    current_text = current_raw.decode('utf-8', 'strict')
    current_nodes = [n for n in ast.parse(current_text).body
                     if isinstance(n, ast.FunctionDef) and n.name == 'inventory_value']
    C.need(len(current_nodes) == 1, 'one exact current inventory function required')
    node = current_nodes[0]
    helper = ''.join(current_text.splitlines(keepends=True)[node.lineno-1:node.end_lineno]).encode('utf-8')
    C.need(C.descriptor(helper) == _PROPERTY_CURRENT_INVENTORY_PIN
           and old.C.__dict__.get('__reviewed_source_sha256__') == PROPERTY_PARENT_COMMON_SHA256,
           'current inventory helper or exact historical common provenance differs')
    admitted_builtins = old.inventory_value.__globals__.get('__builtins__')
    C.need(type(admitted_builtins) is dict
           and all(name in admitted_builtins for name in _PROPERTY_INVENTORY_BUILTINS),
           'the original R7 namespace omitted a required pure builtin')
    namespace = {'__name__': 'current_r8_property_parent_inventory',
        '__file__': '<current-late-boundary:'+current_source+':property-parent-inventory>',
        'C': old.C, 'Path': old.Path, 're': old.re, 'stat': old.stat,
        '__builtins__': {name: admitted_builtins[name] for name in _PROPERTY_INVENTORY_BUILTINS}}
    current = types.FunctionType(inventory_value.__code__, namespace, 'inventory_value')
    old.inventory_value = current

    def historical_publisher_source_sha256():
        return PROPERTY_PARENT_READER_SHA256

    old.reviewed_source_sha256 = historical_publisher_source_sha256
    old.__dict__.pop('__reviewed_source_sha256__', None)
    old.__dict__.pop('main', None)
    old.__dict__.pop('publish', None)
    for name in ('closed_boundary_originals', 'chain_originals', 'current_inventory',
                 'non_native_sidebranch', 'preserve_non_native_private'):
        C.need(getattr(old, name).__globals__ is old.__dict__
               and getattr(old, name).__globals__['inventory_value'] is current,
               'historical method globals did not select current membership')
    C.need(old.reviewed_source_sha256() == PROPERTY_PARENT_READER_SHA256,
           'historical publisher identity changed')
    provenance = {'schema': 'hepta.native-guard.current-property-parent-reader.v1',
        'mode': 'CURRENT_R8_MEMBERSHIP_WITH_BYTE_EXACT_R7_ORIGINAL',
        'current_late_boundary_source_sha256': current_source,
        'historical_publisher_source': {'bytes': 62434, 'sha256': PROPERTY_PARENT_READER_SHA256},
        'historical_common_source': {'bytes': 19138, 'sha256': PROPERTY_PARENT_COMMON_SHA256},
        'inventory_helper_source': dict(_PROPERTY_CURRENT_INVENTORY_PIN),
        'original_inventory_function': dict(_PROPERTY_ORIGINAL_INVENTORY_PIN),
        'helper_binding': 'same_current_inventory_value_code_with_original_R7_common_globals',
        'pure_builtin_dependencies': list(_PROPERTY_INVENTORY_BUILTINS),
        'builtin_resolution': 'explicit13_from_admitted_original_R7_namespace',
        'ambient_builtin_fallback': False,
        'historical_reader_executed_unmodified': False,
        'original_source_bytes_changed': False, 'nested_readers_optimized': False,
        'verification_result_cache': False, 'disabled_entries': ['main', 'publish'],
        'methods': list(_PROPERTY_READER_METHODS)}
    return CurrentPropertyParentReader({name: getattr(old, name) for name in _PROPERTY_READER_METHODS},
                                       provenance)


def property_parent_reader():
    """Raw-load exact R7 originals, then select explicit current pure membership."""
    import types
    package = Path(__file__).parent.parent
    supplied = globals().get('__reviewed_package_sources__')
    C.need(supplied is None or isinstance(supplied, dict), 'reviewed package source map differs')
    expected = {'source/component_common.py': (19138, PROPERTY_PARENT_COMMON_SHA256),
                PROPERTY_PARENT_REFERENCE: (62434, PROPERTY_PARENT_READER_SHA256)}
    sources = {}
    for name, (size, digest) in expected.items():
        if supplied is None:
            raw = C.read(package/name, 1048576, private=False)
        else:
            C.need(name in supplied, 'reviewed R7 property-parent source is absent')
            raw = supplied[name]
        C.need(type(raw) is bytes and len(raw) == size and C.sha(raw) == digest,
               'reviewed R7 property-parent bytes differ: '+name)
        sources[name] = raw
    present = 'component_common' in sys.modules
    saved = sys.modules.get('component_common')
    previous_path = sys.path[:]
    previous_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        old_common = types.ModuleType('component_common')
        old_common.__file__ = str(package/'source/component_common.py')
        old_common.__reviewed_source_sha256__ = PROPERTY_PARENT_COMMON_SHA256
        sys.modules['component_common'] = old_common
        exec(compile(sources['source/component_common.py'], old_common.__file__, 'exec'),
             old_common.__dict__)
        old = types.ModuleType('reviewed_property_parent_late_boundary_r7')
        old.__file__ = str(package/PROPERTY_PARENT_REFERENCE)
        old.__reviewed_source_sha256__ = PROPERTY_PARENT_READER_SHA256
        if supplied is not None:
            old.__reviewed_package_sources__ = supplied
        exec(compile(sources[PROPERTY_PARENT_REFERENCE], old.__file__, 'exec'), old.__dict__)
        C.need(old.REVIEWED_CURRENT_COMBINATION_SHA256 == PROPERTY_PARENT_COMBINATION_SHA256
               and old.reviewed_environment_parent_ancestor() == reviewed_environment_parent_ancestor()
               and old.reviewed_pre_policy_ancestor() == reviewed_pre_policy_ancestor()
               and old.reviewed_failed_ancestor() == reviewed_failed_ancestor()
               and old.REVIEWED_NON_NATIVE_ATTEMPT05 == REVIEWED_NON_NATIVE_ATTEMPT05,
               'R7 reader changed a fixed historical or separate non-native record')
        return _current_property_parent_reader(old, sources[PROPERTY_PARENT_REFERENCE])
    finally:
        sys.path[:] = previous_path
        sys.dont_write_bytecode = previous_dwb
        if not present:
            sys.modules.pop('component_common', None)
        else:
            sys.modules['component_common'] = saved


def environment_parent_reader():
    """The fixed R6 reader remains owned by the exact retained R7 reader."""
    return property_parent_reader().environment_parent_reader()


def _environment_parent_original(raw, original_descriptor):
    p = reviewed_environment_parent_ancestor()
    if C.descriptor(raw) == {k:p['boundary'][k] for k in ('bytes', 'sha256')}:
        C.need(original_descriptor == p['boundary'], 'actual06 full original identity differs')
        return True
    return False


def current_context(combination_sha256, package_sha256):
    require_current_revision()
    reviewed_diag02_non_native_record()
    C.need(type(REVIEWED_CURRENT_COMBINATION_SHA256) is str
           and C.HASH.fullmatch(REVIEWED_CURRENT_COMBINATION_SHA256)
           and combination_sha256 == REVIEWED_CURRENT_COMBINATION_SHA256
           and isinstance(package_sha256, str) and C.HASH.fullmatch(package_sha256)
           and package_sha256 not in (SOURCE_PARENT_PACKAGE_SHA256, V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256, STACK_DIAGNOSTIC_PARENT_PACKAGE_SHA256, DIAG02_PACKAGE_SHA256, CODEC_DIAGNOSTIC_PARENT_PACKAGE_SHA256, DIAGNOSTIC_PARENT_PACKAGE_SHA256, PROPERTY_PARENT_PACKAGE_SHA256,
               POLICY_PARENT_PACKAGE_SHA256, LEGACY_PACKAGE_SHA256,
               ENVIRONMENT_PARENT_PACKAGE_SHA256),
           'current package/combination cannot reinterpret a historical component')


def policy_parent_reader():
    """Compile the exact old reader and common bytes; never import old bytecode.

    Before staging, reviewed loaders inject their complete byte-pinned package
    map. Runtime/on-disk readers use the same two exact package files. The
    parent reader runs in a separate module with its original source identity.
    No parent main, live observation or publication entry is called here.
    """
    import types
    package = Path(__file__).parent.parent
    supplied = globals().get('__reviewed_package_sources__')
    C.need(supplied is None or isinstance(supplied, dict), 'reviewed package source map differs')
    expected = {'reference/component_common_r5.py': (18133, POLICY_PARENT_COMMON_SHA256),
                POLICY_PARENT_REFERENCE: (35730, POLICY_PARENT_READER_SHA256)}
    sources = {}
    for name, (size, digest) in expected.items():
        if supplied is None:
            raw = C.read(package/name, 1048576, private=False)
        else:
            C.need(name in supplied, 'reviewed historical source is absent from the package map')
            raw = supplied[name]
        C.need(type(raw) is bytes and len(raw) == size and C.sha(raw) == digest,
               'reviewed historical source bytes differ: '+name)
        sources[name] = raw
    saved = sys.modules.get('component_common')
    previous_path = sys.path[:]
    previous_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        old_common = types.ModuleType('component_common')
        old_common.__file__ = str(package/'reference/component_common_r5.py')
        old_common.__reviewed_source_sha256__ = POLICY_PARENT_COMMON_SHA256
        sys.modules['component_common'] = old_common
        exec(compile(sources['reference/component_common_r5.py'], old_common.__file__, 'exec'),
             old_common.__dict__)
        old = types.ModuleType('reviewed_policy_parent_late_boundary_r4')
        old.__file__ = str(package/POLICY_PARENT_REFERENCE)
        old.__reviewed_source_sha256__ = POLICY_PARENT_READER_SHA256
        exec(compile(sources[POLICY_PARENT_REFERENCE], old.__file__, 'exec'), old.__dict__)
        C.need(old.LEGACY_COMBINATION_SHA256 == LEGACY_COMBINATION_SHA256
               and old.LEGACY_PACKAGE_SHA256 == LEGACY_PACKAGE_SHA256
               and old.reviewed_failed_ancestor() == reviewed_failed_ancestor(),
               'old reader reference does not preserve the exact external03 record')
        return old
    finally:
        sys.path[:] = previous_path
        sys.dont_write_bytecode = previous_dwb
        if saved is None:
            sys.modules.pop('component_common', None)
        else:
            sys.modules['component_common'] = saved


def reviewed_pre_policy_ancestor():
    p = REVIEWED_PRE_POLICY_ANCESTOR
    C.need(isinstance(p, dict) and set(p) == {'boundary', 'inventory', 'closure'},
           'the fixed actual04 original record is absent')
    exact_descriptor(p['boundary'], expected_path=ROOT/(POLICY_PARENT_NONCE+'.json'))
    C.need(p['boundary']['bytes'] == 4748
           and p['boundary']['sha256'] == POLICY_PARENT_BOUNDARY_SHA256,
           'fixed actual04 boundary byte pin differs')
    for key, name in [('inventory', 'AFTER-INVENTORY.original.json'),
                      ('closure', 'CLOSURE.original.json')]:
        exact_descriptor(p[key], expected_path=ROOT/POLICY_PARENT_NONCE/name)
    C.need(p['inventory']['bytes'] == 633600
           and p['inventory']['sha256'] == 'e48c39003bd26f65dde74958f0081a89c23027da19a11afd4fc2a81414c5c349'
           and p['closure']['bytes'] == 49087
           and p['closure']['sha256'] == '559f2440fdd1c9f43c64399351f3fda0be95890d21cbde4aea211751e5f9aa81',
           'fixed actual04 closed original pins differ')
    return p


def is_pre_policy_ancestor(value):
    """Exact canonical original04 classification, never a schema-only test."""
    return (isinstance(value, dict)
            and C.descriptor(C.encoded(value)) == {
                'bytes': 4748, 'sha256': POLICY_PARENT_BOUNDARY_SHA256})


def _old_original_kind(raw, original_descriptor):
    p = reviewed_pre_policy_ancestor()
    q = reviewed_failed_ancestor()
    if C.descriptor(raw) == {k:p['boundary'][k] for k in ('bytes', 'sha256')}:
        C.need(original_descriptor == p['boundary'], 'actual04 full original identity differs')
        return 'pre_policy_ancestor'
    if C.descriptor(raw) == {k:q['boundary'][k] for k in ('bytes', 'sha256')}:
        C.need(original_descriptor == q['boundary'], 'external03 full original identity differs')
        return 'external_ancestor'
    return None



def boundary_from_original(raw, *, original_descriptor, combination_sha256, package_sha256):
    """Read a new component, the exact prior source prefix, or nine fixed failed originals."""
    current_context(combination_sha256, package_sha256)
    C.need(type(raw) is bytes and 0 < len(raw) <= 16*1024*1024,
           'bounded original boundary bytes required')
    exact_descriptor(original_descriptor)
    C.need(C.descriptor(raw) == {k:original_descriptor[k] for k in ('bytes','sha256')},
           'boundary bytes differ from their actual original descriptor')
    if _source_parent_original(raw, original_descriptor) is not None:
        return source_parent_boundary_from_original(raw, original_descriptor=original_descriptor)
    if C.descriptor(raw) == {k:reviewed_v3_runtime_diagnostic_ancestor()['boundary'][k]
                             for k in ('bytes','sha256')}:
        return v3_runtime_diagnostic_from_original(raw, original_descriptor)
    if C.descriptor(raw) == {k:reviewed_stack_diagnostic_parent_ancestor()['boundary'][k]
                             for k in ('bytes','sha256')}:
        return stack_diagnostic_parent_from_original(raw, original_descriptor)
    if C.descriptor(raw) == {k:reviewed_codec_diagnostic_parent_ancestor()['boundary'][k]
                             for k in ('bytes','sha256')}:
        return codec_diagnostic_parent_from_original(raw, original_descriptor)
    if C.descriptor(raw) == {k:reviewed_diagnostic_parent_ancestor()['boundary'][k]
                             for k in ('bytes','sha256')}:
        return diagnostic_parent_from_original(raw, original_descriptor)
    retained = _retained_property_parent_original(raw, original_descriptor)
    if retained is not None:
        index, record = retained
        old = property_parent_reader()
        value = old.boundary_from_original(raw, original_descriptor=original_descriptor,
            combination_sha256=PROPERTY_PARENT_COMBINATION_SHA256,
            package_sha256=PROPERTY_PARENT_PACKAGE_SHA256)
        if index < 2:
            C.need(is_property_parent_ancestor(value)
                   and value['nonce'] == PROPERTY_PARENT_NONCES[index]
                   and value['package_sha256'] == PROPERTY_PARENT_PACKAGE_SHA256
                   and value['combination_sha256'] == PROPERTY_PARENT_COMBINATION_SHA256
                   and value['publisher_source_sha256'] == PROPERTY_PARENT_READER_SHA256
                   and value['closure'] == record['closure'] and value['inventory'] == record['inventory']
                   and value['prior_boundary'] == property_parent_records()[index+1]['boundary']
                   and value['component_qualified'] is False and value['native_status'] == 'provider_failed'
                   and type(value['actual_native_calls']) is int
                   and value['actual_native_calls'] == PROPERTY_PARENT_CALL_COUNTS[index]
                   and value['non_native_sidebranch'] == non_native_sidebranch()['binding'],
                   'a fixed actual08/07 failure was reinterpreted')
        return value
    value = C.strict(raw)
    checked = boundary_value(value, combination_sha256=combination_sha256,
                             package_sha256=package_sha256)
    C.need(original_descriptor['path'] == str(ROOT/(checked['nonce']+'.json')),
           'ordinary boundary filename does not bind its nonce')
    C.need(checked['nonce'] not in (*(r['nonce'] for r in reviewed_source_parent_records()), V3_RUNTIME_DIAGNOSTIC_NONCE, STACK_DIAGNOSTIC_PARENT_NONCE, DIAG02_NONCE, CODEC_DIAGNOSTIC_PARENT_NONCE, DIAGNOSTIC_PARENT_NONCE, *PROPERTY_PARENT_NONCES, POLICY_PARENT_NONCE,
                                  LEGACY_NONCE, ENVIRONMENT_PARENT_NONCE),
           'a historical nonce cannot be relabeled as current')
    return checked



def closed_boundary_originals(raw, inventory_raw, closure_raw, *, original_descriptor,
                             combination_sha256, package_sha256):
    value = boundary_from_original(raw, original_descriptor=original_descriptor,
        combination_sha256=combination_sha256, package_sha256=package_sha256)
    if _source_parent_original(raw, original_descriptor) is not None:
        return source_parent_closed_boundary_originals(raw, inventory_raw, closure_raw,
            original_descriptor=original_descriptor)
    retained = _retained_property_parent_original(raw, original_descriptor)
    if retained is not None:
        index, _record = retained
        old = property_parent_reader()
        checked, inv, closed = old.closed_boundary_originals(raw, inventory_raw, closure_raw,
            original_descriptor=original_descriptor,
            combination_sha256=PROPERTY_PARENT_COMBINATION_SHA256,
            package_sha256=PROPERTY_PARENT_PACKAGE_SHA256)
        C.need(checked == value, 'retained R7 reader changed its original result')
        if index < 2:
            C.need(closed.get('closure_source_sha256') == PROPERTY_PARENT_CLOSURE_SHA256
                   and closed.get('state') == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
                   and closed.get('component_qualified') is False
                   and closed.get('native_status') == 'provider_failed'
                   and type(closed.get('actual_native_calls')) is int
                   and closed['actual_native_calls'] == PROPERTY_PARENT_CALL_COUNTS[index]
                   and type(closed.get('unknown_effects')) is int and closed['unknown_effects'] == 0,
                   'fixed actual08/07 closure origin or failure semantics differ')
        return checked, inv, closed
    C.need(type(inventory_raw) is bytes and type(closure_raw) is bytes
           and C.descriptor(inventory_raw) == {k:value['inventory'][k] for k in ('bytes','sha256')}
           and C.descriptor(closure_raw) == {k:value['closure'][k] for k in ('bytes','sha256')},
           'closed boundary inventory/closure original bytes differ')
    inv, closed = C.strict(inventory_raw), C.strict(closure_raw)
    inventory_value(inv)
    C.need(inv['roots'] == value['roots'], 'closed boundary omitted cumulative original roots')
    closure_matches(closed, value, inventory_raw)
    if is_v3_runtime_diagnostic_ancestor(value):
        cause = closed.get('diagnostic_cause_evidence')
        C.need(closed.get('closure_source_sha256') == V3_RUNTIME_DIAGNOSTIC_CLOSURE_SHA256
               and closed.get('state') == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
               and closed.get('diagnostic_only') is True and closed.get('component_qualified') is False
               and closed.get('native_status') == 'provider_failed'
               and type(closed.get('actual_native_calls')) is int and closed['actual_native_calls'] == 1
               and type(closed.get('unknown_effects')) is int and closed['unknown_effects'] == 0
               and type(cause) is dict
               and cause.get('schema') == 'hepta.diagnostic-only.actual-stack-cause-evidence.v1'
               and cause.get('actual_stack_and_receipt_linkage_observed') is True
               and cause.get('proposed_policy_cause_confirmed') is True
               and cause.get('causal_evidence_observed') is True
               and cause.get('policy_sha256') == V3_RUNTIME_DIAGNOSTIC_POLICY_SHA256
               and cause.get('source_sha256') == '2dd3808f19d34c241b5d2e4fef133a4950df19984803c82fd9aad992a8228cde'
               and cause.get('jar_sha256') == '54adf8e1434380b9b8414fac7ce1632a35ce8ebe97b5f1dc8b68af64fb6de60f'
               and cause.get('independent_jvm_identity') is False
               and cause.get('kernel_trace_observed') is False,
               'actual closed v3 data_local errno13 diagnostic cause and failed accounting required')
    if is_stack_diagnostic_parent_ancestor(value):
        C.need(closed.get('closure_source_sha256') == STACK_DIAGNOSTIC_PARENT_CLOSURE_SHA256
               and closed.get('state') == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
               and closed.get('component_qualified') is False
               and closed.get('native_status') == 'provider_failed'
               and type(closed.get('actual_native_calls')) is int and closed['actual_native_calls'] == 1
               and type(closed.get('unknown_effects')) is int and closed['unknown_effects'] == 0,
               'failed820 closure origin or failed accounting differs')
    if is_codec_diagnostic_parent_ancestor(value):
        C.need(closed.get('closure_source_sha256') == CODEC_DIAGNOSTIC_PARENT_CLOSURE_SHA256
               and closed.get('state') == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
               and closed.get('component_qualified') is False
               and closed.get('native_status') == 'provider_failed'
               and type(closed.get('actual_native_calls')) is int and closed['actual_native_calls'] == 1
               and type(closed.get('unknown_effects')) is int and closed['unknown_effects'] == 0,
               'failed6077 closure origin or failed accounting differs')
    if is_diagnostic_parent_ancestor(value):
        C.need(closed.get('closure_source_sha256') == DIAGNOSTIC_PARENT_CLOSURE_SHA256
               and closed.get('state') == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
               and closed.get('component_qualified') is False
               and closed.get('native_status') == 'provider_failed'
               and type(closed.get('actual_native_calls')) is int and closed['actual_native_calls'] == 1
               and type(closed.get('unknown_effects')) is int and closed['unknown_effects'] == 0,
               'diagnostic predecessor closure origin or failed accounting differs')
    if not (is_codec_diagnostic_parent_ancestor(value) or is_diagnostic_parent_ancestor(value)):
        current_closure_sidebranches(closed, value, inventory_raw)
    return value, inv, closed



def require_failed_ancestor_tail(values):
    """New prefix, exact old source prefix, then all nine original failed bytes."""
    records = reviewed_source_parent_records()
    retained_count = HISTORICAL_FAILED_BOUNDARY_COUNT+len(records)
    C.need(type(values) is list and retained_count <= len(values) <= MAX_CHAIN,
           'all exact source-parent originals and the original nine failures are required')
    current_count = len(values)-retained_count
    C.need(0 <= current_count <= MAX_NEW_CURRENT_CASE_PREFIX,
           'only two newly closed cases belong to the new source tuple')
    history = values[current_count:]
    old = source_parent_reader()
    for value, record in zip(history[:len(records)], records):
        raw = C.encoded(value)
        C.need(C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')},
               'source-parent prefix was omitted, reordered, altered or duplicated')
        checked = old.boundary_from_original(raw, original_descriptor=record['boundary'],
            combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)
        C.need(checked == value, 'source-parent original reader changed its result')
    # The unchanged old function checks the old current prefix and all nine
    # exact historical canonical boundary bytes, full predecessor IDs and counts.
    old.require_failed_ancestor_tail(history)
    seen_nonce = set(); seen_scope = set(); current_package = None
    for index, value in enumerate(values):
        key = tuple(value['scope'][name] for name in C.SCOPE)
        C.need(value['nonce'] not in seen_nonce and key not in seen_scope,
               'closed boundary repeats a nonce or native scope across source tuples')
        seen_nonce.add(value['nonce']); seen_scope.add(key)
        if index < current_count:
            if current_package is None:
                current_package = value['package_sha256']
            C.need(value['package_sha256'] == current_package,
                   'new component prefix changes its source-package generation')
            boundary_value(value, combination_sha256=REVIEWED_CURRENT_COMBINATION_SHA256,
                           package_sha256=current_package)
            following = values[index+1]; prior = value['prior_boundary']
            C.need(prior is not None
                   and prior['path'] == str(ROOT/(following['nonce']+'.json'))
                   and {k:prior[k] for k in ('bytes','sha256')} == C.descriptor(C.encoded(following)),
                   'new source component prefix is not a complete continuous original chain')
            if index == current_count-1:
                C.need(prior == records[0]['boundary'],
                       'new source prefix must point to the exact actual source-parent head')


def chain_originals(first, *, combination_sha256, package_sha256, boot_id, retirement):
    rows = []; observed = []; seen_nonce = set(); seen_scope = set(); current = first
    while current is not None:
        C.need(len(rows) < MAX_CHAIN, 'closed boundary chain exceeds its fixed bound')
        raw = original(current)
        value = boundary_from_original(raw, original_descriptor=current,
            combination_sha256=combination_sha256, package_sha256=package_sha256)
        key = tuple(value['scope'][k] for k in C.SCOPE)
        C.need(value['nonce'] not in seen_nonce and key not in seen_scope,
               'closed boundary repeats a nonce or native scope')
        seen_nonce.add(value['nonce']); seen_scope.add(key)
        C.need(value['boot_id'] == boot_id and value['retirement'] == retirement,
               'closed boundary changes the original retirement or boot')
        inv_raw, closed_raw = original(value['inventory']), original(value['closure'])
        value, inv, closed = closed_boundary_originals(raw, inv_raw, closed_raw,
            original_descriptor=current, combination_sha256=combination_sha256,
            package_sha256=package_sha256)
        rows.append((value, inv, closed))
        observed.extend((current, value['inventory'], value['closure']))
        current = value['prior_boundary']
    require_failed_ancestor_tail([r[0] for r in rows])
    for later, earlier in zip(rows, rows[1:]):
        C.need(set(earlier[0]['roots']) <= set(later[0]['roots']),
               'later boundary omitted an earlier private original root')
    return rows, observed


def retired_originals(retirement, boot_id):
    C.need(isinstance(retirement, dict) and set(retirement) == {
        'proof', 'preflight', 'probe', 'bound_inputs', 'disabled_flag'}, 'retirement original set differs')
    out = C.BASE / 'module-retire-r9-r2-for-r10-r1-01'
    code = C.BASE / 'module-r10-r1-retirement-code-r1'
    paths = {'proof': out/'RETIREMENT.json', 'preflight': out/'PREFLIGHT.json',
             'probe': code/'retirement_probe.py', 'bound_inputs': code/'BOUND-INPUTS.json',
             'disabled_flag': C.ANDROID/'data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable'}
    raw = {k: original(retirement[k], expected_path=p) for k, p in paths.items()}
    proof, before, bound = (C.strict(raw[k]) for k in ('proof', 'preflight', 'bound_inputs'))
    C.need(proof.get('schema') == 'hepta.r9-r2-retirement-observation.v1'
           and proof.get('state') == 'ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED'
           and proof.get('boot_id') == boot_id and proof.get('server_lock_now_unheld') is True
           and proof.get('global_pending_clear') is True and proof.get('old_claims_deleted') is False
           and proof.get('old_task_terminal_rewritten') is False and proof.get('automatic_restart') is False
           and proof.get('automatic_replay') is False and raw['disabled_flag'] == b'',
           'original whole r9-r2 retirement differs')
    C.need(before.get('schema') == 'hepta.r9-r2-retirement-preflight.v1'
           and before.get('state') == 'READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
           and before.get('groups') == proof.get('original_role_identities')
           and set(before['groups']) == {'supervisor', 'provider', 'model', 'sidecar'}
           and before.get('preserved_state') == proof.get('preserved_state')
           and bound.get('complete_current_accepted_case_union_verified') is True,
           'original retirement complete-case preservation differs')
    # Do not call the old retained_state equality after new component actions.
    return proof, list(before['groups'].values())


def current_inventory(expected, *, current_lease=None, prior_boundary=None):
    import component_lifecycle as LIFE
    fixtures = [p for p in expected['roots'] if re.fullmatch(
        r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}', p)]
    observed = retained_failed_staged_inventory(expected['roots'], fixture_roots=fixtures,current_lease=current_lease,prior_boundary=prior_boundary)
    C.need(inventory_value(observed) == inventory_value(expected),
           'current complete cumulative originals differ; no new component admission')
    return observed


def recheck_originals(rows):
    for row in rows:
        original(row)


# Fixed non-native attempt05 sidebranch. These pins remain unset until the
# independently closed actual originals and verifier source are reviewed.
NON_NATIVE_ATTEMPT05_NONCE = 'e4c3ccb0b2d706be3b7bf105ae772405'
NON_NATIVE_SIDEBRANCH_REFERENCE = 'reference/non_native_attempt05.py'
NON_NATIVE_SIDEBRANCH_SOURCE_BYTES = 19740
NON_NATIVE_SIDEBRANCH_SOURCE_SHA256 = 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'
REVIEWED_NON_NATIVE_ATTEMPT05 = {'closure': {'bytes': 164095, 'metadata': [65086, 153455, 33152, 0, 0, 1, 164095, 1793843548839929123, 1793843548839929123], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/CLOSURE.original.json', 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, 'inventory': {'bytes': 664638, 'metadata': [65086, 143754, 33152, 0, 0, 1, 664638, 1793843548843929123, 1793843548843929123], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/AFTER-INVENTORY.original.json', 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}, 'nonce': 'e4c3ccb0b2d706be3b7bf105ae772405', 'proof': {'bytes': 4650, 'metadata': [65086, 147519, 33152, 0, 0, 1, 4650, 1793843550651929122, 1793843550651929122], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/SIDE-PROOF.original.json', 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, 'schema': 'hepta.native-guard.reviewed-non-native-attempt.v1', 'sources': {'capture': '3e72353d8bd0dec122f10f5f3f5a6fe50e6dfb5251a41e51fc89974d4d4867bb', 'capture_driver': '17fe5e803ff55f6f752ebadfab11163c619e5de42a4ee09d5c1e549df7635d80', 'closer': '508fb5d474ff4fcc2e32586a186c5cb3d9b511ed98dc284c202a216ceb59e3f6', 'publisher': '2185e2fbdad9b5a2c8f2f54891fcd29ae1d90651ac68ded8c72c4914d490bb97', 'sender_verifier': '3117035c31ab46e865a93a4ff797388c18d4e9e6c669bc5d4b48ae9711f1842e', 'verifier': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}}
NON_NATIVE_REFERENCE_FILES = {
    'proof': 'reference/attempt05-SIDE-PROOF.original.json',
    'closure': 'reference/attempt05-CLOSURE.original.json',
    'inventory': 'reference/attempt05-AFTER-INVENTORY.original.json'}
NON_NATIVE_CAPTURE_FILES = {
    'proof': 'SIDE-PROOF.original.json',
    'closure': 'CLOSURE.original.json',
    'inventory': 'AFTER-INVENTORY.original.json'}
NON_NATIVE_BINDING_FIELDS = {
    'schema', 'nonce', 'proof', 'closure', 'inventory',
    'component_role_identities', 'preserved_roots', 'private_roots',
    'native_predecessor', 'native_case_count', 'component_qualified'}


def compose_current_sidebranch_inventory(verifier, verifier_raw):
    """Select one explicitly composed pure function; never cache observations."""
    import ast
    raw_sha = C.sha(verifier_raw)
    C.need((len(verifier_raw), raw_sha) in (
        (NON_NATIVE_SIDEBRANCH_SOURCE_BYTES, NON_NATIVE_SIDEBRANCH_SOURCE_SHA256),
        (DIAG02_VERIFIER_BYTES, DIAG02_VERIFIER_SHA256))
        and verifier.__dict__.get('__reviewed_source_sha256__') == raw_sha,
        'current composition requires an exact retained verifier source')
    text = verifier_raw.decode('utf-8')
    functions = [node for node in ast.parse(text).body
                 if isinstance(node, ast.FunctionDef) and node.name == 'inventory_value']
    C.need(len(functions) == 1, 'one retained inventory function required')
    original = ast.get_source_segment(text, functions[0]).encode('utf-8')
    C.need(C.sha(original) == '1ade2e15372674def544c1f0fac358b957c527cc6ff898c67672f31ac3944f88',
           'retained inventory function body differs')
    old_setup = b'    total=0\n'
    new_setup = (b'    root_parts=frozenset(p.parts for p in paths)\n'
                 b'    root_depths=frozenset(len(parts) for parts in root_parts)\n'
                 b'    total=0\n')
    old_predicate = b'any(p==r or r in p.parents for r in paths)'
    new_predicate = (b'any(p.parts[:depth] in root_parts for depth in root_depths '
                     b'if depth<=len(p.parts))')
    C.need(original.count(old_setup) == original.count(old_predicate) == 1,
           'exact inventory topology replacement sites required')
    current = original.replace(old_setup, new_setup).replace(old_predicate, new_predicate)
    C.need(C.sha(current) == 'c487c93fe46660524bdc40981e1b5432f61dcd31a9888809b697d7b4e895bde3'
           and current.replace(new_predicate, old_predicate).replace(new_setup, old_setup) == original,
           'current inventory composition or whole-byte inverse differs')
    selected = {}
    exec(compile(current, verifier.__file__+'::current_inventory_parts_v1', 'exec'),
         verifier.__dict__, selected)
    fn = selected['inventory_value']
    C.need(fn.__globals__ is verifier.__dict__
           and fn.__defaults__ == verifier.inventory_value.__defaults__
           and fn.__kwdefaults__ == verifier.inventory_value.__kwdefaults__,
           'current inventory must retain original verifier globals and signature')
    verifier.inventory_value = fn
    provenance = {'schema': 'hepta.native-guard.current-inventory-composition.v1',
        'reference_verifier_source': {'bytes': len(verifier_raw), 'sha256': raw_sha},
        'reference_inventory_function': {'bytes': len(original), 'sha256': C.sha(original)},
        'current_inventory_function': {'bytes': len(current), 'sha256': C.sha(current)},
        'current_composing_source_sha256': reviewed_source_sha256(),
        'strategy': 'fresh_per_call_root_component_membership',
        'reference_source_bytes_unchanged': True, 'original_module_globals_used': True,
        'historical_binding_rewritten': False, 'validation_result_cache': False,
        'live_observation_cache': False}
    verifier.__current_inventory_composition__ = provenance
    return provenance


def non_native_sidebranch(*, phone_originals=False):
    """Verify one fixed sidebranch from original package bytes, with no scope.

    The pure verifier never performs I/O. Package raw maps and package files
    provide the same three retained originals. Only explicit phone callers
    additionally read their fixed original phone paths and full identities.
    """
    import types
    record = REVIEWED_NON_NATIVE_ATTEMPT05
    C.need(isinstance(record, dict) and record.get('nonce') == NON_NATIVE_ATTEMPT05_NONCE
           and record.get('schema') == 'hepta.native-guard.reviewed-non-native-attempt.v1',
           'the actual non-native attempt05 closure is not reviewed')
    C.need(type(NON_NATIVE_SIDEBRANCH_SOURCE_BYTES) is int
           and 0 < NON_NATIVE_SIDEBRANCH_SOURCE_BYTES <= 1048576
           and isinstance(NON_NATIVE_SIDEBRANCH_SOURCE_SHA256, str)
           and C.HASH.fullmatch(NON_NATIVE_SIDEBRANCH_SOURCE_SHA256),
           'the pure non-native verifier source is not reviewed')
    package = Path(__file__).parent.parent
    supplied = globals().get('__reviewed_package_sources__')
    C.need(supplied is None or isinstance(supplied, dict), 'reviewed package source map differs')
    def package_raw(name, size, digest):
        C.need(type(size) is int and 0 < size <= 16*1024*1024
               and isinstance(digest, str) and C.HASH.fullmatch(digest),
               'bounded sidebranch package original required')
        if supplied is None:
            raw = C.read(package/name, 16*1024*1024, private=False)
        else:
            C.need(name in supplied, 'sidebranch package original is missing: '+name)
            raw = supplied[name]
        C.need(type(raw) is bytes and len(raw) == size and C.sha(raw) == digest,
               'sidebranch package original bytes differ: '+name)
        return raw
    verifier_raw = package_raw(NON_NATIVE_SIDEBRANCH_REFERENCE,
        NON_NATIVE_SIDEBRANCH_SOURCE_BYTES, NON_NATIVE_SIDEBRANCH_SOURCE_SHA256)
    raw = {}
    for key, name in NON_NATIVE_REFERENCE_FILES.items():
        exact_descriptor(record[key])
        raw[key] = package_raw(name, record[key]['bytes'], record[key]['sha256'])
    verifier = types.ModuleType('reviewed_non_native_attempt05')
    verifier.__file__ = str(package/NON_NATIVE_SIDEBRANCH_REFERENCE)
    verifier.__reviewed_source_sha256__ = NON_NATIVE_SIDEBRANCH_SOURCE_SHA256
    saved_path = sys.path[:]; saved_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        exec(compile(verifier_raw, verifier.__file__, 'exec'), verifier.__dict__)
        inventory_composition = compose_current_sidebranch_inventory(verifier, verifier_raw)
        verified = verifier.verify_sidebranch(raw['proof'], raw['closure'], raw['inventory'],
                                               expected_record=record)
    finally:
        sys.path[:] = saved_path
        sys.dont_write_bytecode = saved_dwb
    binding = verified['binding']
    C.need(isinstance(binding, dict) and set(binding) == NON_NATIVE_BINDING_FIELDS
           and binding['schema'] == 'hepta.native-guard.non-native-sidebranch-binding.v1'
           and binding['nonce'] == NON_NATIVE_ATTEMPT05_NONCE
           and type(binding['native_case_count']) is int and binding['native_case_count'] == 0
           and binding['component_qualified'] is False
           and all(binding[key] == record[key] for key in NON_NATIVE_REFERENCE_FILES)
           and binding['native_predecessor'] == reviewed_pre_policy_ancestor()['boundary'],
           'pure verifier did not preserve the exact separate non-native binding')
    inv = C.strict(raw['inventory']); inventory_value(inv)
    C.need(binding['preserved_roots'] == inv['roots']
           and isinstance(binding['private_roots'], list) and len(binding['private_roots']) == 3
           and len(set(binding['private_roots'])) == 3
           and set(binding['private_roots']) <= set(inv['roots']),
           'non-native preserved/private root set differs')
    roles = binding['component_role_identities']
    C.need(isinstance(roles, dict) and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(isinstance(v, list) and len(v) == 4 and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3,
           'non-native ended role identities differ')
    rows = [record[k] for k in NON_NATIVE_REFERENCE_FILES]
    if phone_originals:
        for key in NON_NATIVE_REFERENCE_FILES:
            C.need(original(record[key]) == raw[key], 'phone sidebranch original differs from reviewed copy')
    return {'binding': binding, 'inventory': inv, 'originals': rows, 'raw': raw,
            'verified': verified, 'verifier': verifier, 'current_inventory_composition': inventory_composition}


def preserve_non_native_private(inventory, sidebranch):
    """Keep old roots and exact ended05 private subtrees through the shared pure verifier."""
    inventory_value(inventory)
    C.need(sidebranch['verifier'].validate_private_preservation(
               sidebranch['verified'], inventory) is True,
           'the fixed non-native private preservation gate did not pass')


def effective_prior_inventory(boundary, inventory, sidebranch):
    """Head04 uses the real ended05 inventory; a current head uses its own inventory."""
    if is_pre_policy_ancestor(boundary):
        C.need(C.descriptor(C.encoded(boundary)) ==
               {k:sidebranch['binding']['native_predecessor'][k] for k in ('bytes', 'sha256')},
               'non-native sidebranch does not follow this exact native predecessor')
        selected = sidebranch['inventory']
    else:
        C.need(boundary.get('non_native_sidebranch') == sidebranch['binding'],
               'current native head omitted or changed the fixed non-native sidebranch')
        selected = inventory
    preserve_non_native_private(selected, sidebranch)
    return selected


def verify_current(lease, *, combination_sha256, package_sha256):
    """Read-only admission with a separate, fixed zero-native-case sidebranch."""
    require_r10_retained_transport()
    C.need(lease.get('prior_boundary') is not None
           and lease.get('combination', {}).get('sha256') == combination_sha256
           and lease.get('package_sha256') == package_sha256, 'next lease late-boundary binding differs')
    C.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == lease['boot_id'],
           'boot changed since the closed component')
    chain, originals = chain_originals(lease['prior_boundary'], combination_sha256=combination_sha256,
        package_sha256=package_sha256, boot_id=lease['boot_id'], retirement=lease['retirement'])
    branches = non_native_sidebranches(phone_originals=True)
    sidebranch = branches[0]
    C.need(all(lease['nonce'] != row[0]['nonce'] for row in chain)
           and all(lease['nonce'] != s['binding']['nonce'] for s in branches), 'closed native/non-native nonce cannot be reused')
    _proof, roles = retired_originals(lease['retirement'], lease['boot_id'])
    component_roles = []
    for boundary, _inventory, _closure in chain:
        component_roles.extend(boundary['component_role_identities'].values())
    for branch in branches:
        component_roles.extend(branch['binding']['component_role_identities'].values())
    require_component_role_budget(component_roles)
    C.need(len(chain) < MAX_CHAIN and len(component_roles)+3 <= COMPONENT_ROLE_CAP,
           'no capacity for another native generation; fixed history cannot be discarded')
    roles.extend(component_roles)
    roles.extend(retained_preaccept_roles())
    C.need(len({tuple(x) for x in roles}) == len(roles), 'closed role identities repeat')
    retained=retained_unstarted_stage()
    C.need(lease['nonce']!=retained['binding']['nonce'],'expired unstarted nonce is permanently consumed')
    retained_r7=retained_preaccept()
    C.need(lease['nonce']!=retained_r7['nonce'],'original failed preaccept nonce remains consumed')
    retained_r8=retained_failed_staged()
    C.need(lease['nonce']!=retained_r8['nonce'],'original failed staged R8 nonce remains consumed')
    retained_r9=retained_failed_transport()
    C.need(lease['nonce']!=retained_r9['nonce'],'original failed transport R9 nonce remains consumed')
    selected, selected_pin, selection = effective_current_prior_inventory(chain[0][0], chain[0][1], branches,retained=retained)
    retained_transport=retained_stage_external_originals(retained)+retained_failed_staged_external_originals()+retained_failed_transport_external_originals()
    parent_before=retained_stage_parent_aliases();fixture_before=fresh_retained_fixture_absence()
    r8_fixture_before=fresh_retained_failed_staged_fixture_absence(retained_failed_staged_value=retained_r8)
    observed = current_inventory(selected,current_lease=lease,prior_boundary=chain[0][0])
    r8_fixtures=[r8_fixture_before,fresh_retained_failed_staged_fixture_absence(retained_failed_staged_value=retained_r8)]
    validate_retained_failed_staged_fixture_observations(r8_fixtures,retained_failed_staged_value=retained_r8)
    preserve_non_native_sidebranches(observed, branches)
    preserve_retained_unstarted_stage(observed,retained=retained)
    fixture_after=fresh_retained_fixture_absence();validate_retained_fixture_observations([fixture_before,fixture_after])
    current_home=retained_stage_current_home(lease,parent_before,lstat=os.lstat,read_private=C.read)
    parent_profiles=retained_stage_parent_profiles(retained,observed,parent_before,retained_stage_parent_aliases(),
        additional_home=current_home)
    absence = [r10_current_admission_absence(lease,roles,'current-admission-01'),
               r10_current_admission_absence(lease,roles,'current-admission-02')]
    from component_snapshot import endpoint_absence
    _tables, endpoints = endpoint_absence()
    recheck_originals(originals + list(lease['retirement'].values()) +
                      [row for branch in branches for row in branch['originals']] + retained_transport)
    return {'schema': 'hepta.native-guard.late-boundary-verification.v1',
        'state': 'EXACT_CLOSED_CUMULATIVE_ORIGINALS_UNCHANGED',
        'previous_boundary': lease['prior_boundary'], 'closed_components': len(chain),
        'inventory_sha256': selected_pin['sha256'], 'roots': observed['roots'],
        'inventory_selection': selection,'retained_preaccept_binding':retained_r7['retained_preaccept_binding'],
        'retained_failed_staged_binding':retained_r8['retained_failed_staged_binding'],
        'retained_failed_transport_binding':retained_r9['retained_failed_transport_binding'],
        'retained_failed_staged_fixture_absence':r8_fixtures,
        'retained_unstarted_stage':retained['binding'],'retained_stage_parent_profiles':parent_profiles,
        'retained_stage_fixture_absence':[fixture_before,fixture_after],
        'non_native_sidebranch': sidebranch['binding'],
        'non_native_sidebranches': [s['binding'] for s in branches],
        'entries': len(observed['entries']), 'file_bytes_hashed': observed['file_bytes_hashed'],
        'original_retirement_sha256': lease['retirement']['proof']['sha256'],
        'absence_observations': absence, 'endpoints': endpoints,
        'old_retirement_current_equality_claimed': False, 'original_retirement_rewritten': False,
        'phone_tool_calls': 0, 'model_requests': 0, 'signals': 0, 'writes': 0}


def publish(a):
    require_r10_retained_transport()
    require_current_revision()
    import component_lifecycle as LIFE
    os.umask(0o077)
    home = C.private_dir(Path(a.lease)); lease, lease_raw = LIFE.load_lease(home, a.lease_sha256, require_live=False)
    current_context(lease['combination']['sha256'], lease['package_sha256'])
    C.need(lease['prior_boundary'] is not None, 'policy transition cannot restart the original chain')
    LIFE.native_root(lease['boot_id'])
    C.need(Path(__file__) == home/'package/source/late_boundary.py', 'publish must use staged pinned source')
    verify_current_package(home/'package/MANIFEST.json', lease['package_sha256'])
    raw = {}
    for key in ('closure', 'inventory'):
        p = Path(getattr(a, key)); body = C.read(p, 16*1024*1024)
        C.need(C.sha(body) == getattr(a, key+'_sha256'), 'approved host original pin differs: '+key)
        raw[key] = body
    closed, inv = C.strict(raw['closure']), C.strict(raw['inventory'])
    inventory_value(inv)
    retained_r7=current_retained_preaccept_binding(closed)
    preserve_retained_preaccept(inv,retained_preaccept_value=retained_r7)
    retained_r8=current_retained_failed_staged_binding(closed)
    preserve_retained_failed_staged(inv,retained_failed_staged_value=retained_r8)
    retained_r9=current_retained_failed_transport_binding(closed)
    preserve_retained_failed_transport(inv,retained_failed_transport_value=retained_r9)
    branches = non_native_sidebranches(phone_originals=True)
    sidebranch = branches[0]
    preserve_non_native_sidebranches(inv, branches)
    retained=retained_unstarted_stage();preserve_retained_unstarted_stage(inv,retained=retained)
    retained_transport=retained_stage_external_originals(retained)+retained_failed_staged_external_originals()+retained_failed_transport_external_originals()
    current_retained_stage_binding(closed)
    validate_retained_stage_parent_profiles(retained,closed['retained_stage_parent_profiles'],inv)
    C.need(retained_stage_parent_aliases()==closed['retained_stage_parent_profiles']['after'],
           'shared parent changed since the exact closed snapshot')
    fresh_retained_fixture_absence()
    C.need(closed.get('lease_sha256') == C.sha(lease_raw)
           and closed.get('lease_source_path') == str(home/'LEASE.json')
           and closed.get('closure_source_sha256') == C.sha(C.read(home/'package/source/close_component.py',1048576,private=False)),
           'closed lease or independently reviewed closure source differs')
    base = {k: lease[k] for k in ('boot_id', 'nonce', 'case_id', 'owner_request_sha256',
                                  'package_sha256', 'retirement', 'prior_boundary')}
    base.update(schema=SCHEMA, state=STATE, scope=closed['scope'],
        combination_sha256=lease['combination']['sha256'], roots=inv['roots'],
        component_role_identities=closed['component_role_identities'],
        component_qualified=closed['component_qualified'], native_status=closed['native_status'],
        actual_native_calls=closed['actual_native_calls'],
        publisher_source_sha256=reviewed_source_sha256(),
        retained_preaccept_binding=retained_r7['retained_preaccept_binding'],
        retained_failed_staged_binding=retained_r8['retained_failed_staged_binding'],
        retained_failed_transport_binding=retained_r9['retained_failed_transport_binding'],
        non_native_sidebranch=sidebranch['binding'],
        non_native_sidebranches=[s['binding'] for s in branches],
        retained_unstarted_stage=retained['binding'],retained_stage_parent_profiles=closed['retained_stage_parent_profiles'],
        original_retirement_rewritten=False, business_qualified=False, model_requests=0,
        automatic_replay=False)
    # closure_matches checks the actual fields, independently of staged filenames.
    closure_matches(closed, base, raw['inventory'])
    current_closure_sidebranches(closed, base, raw['inventory'])
    _proof, roles = retired_originals(lease['retirement'], lease['boot_id'])
    prior_originals = []
    component_roles = []
    if lease['prior_boundary'] is not None:
        previous, prior_originals = chain_originals(lease['prior_boundary'],
            combination_sha256=base['combination_sha256'], package_sha256=base['package_sha256'],
            boot_id=base['boot_id'], retirement=base['retirement'])
        C.need(len(previous) < MAX_CHAIN, 'native generation cap exhausted')
        C.need(set(previous[0][0]['roots']) <= set(inv['roots']), 'new boundary omitted prior original roots')
        C.need(all(row[0]['nonce'] != base['nonce'] and row[0]['scope'] != base['scope'] for row in previous),
               'new boundary reuses a closed scope/nonce')
        for boundary, _i, _c in previous:
            component_roles.extend(boundary['component_role_identities'].values())
    component_roles.extend(base['component_role_identities'].values())
    for branch in branches:
        component_roles.extend(branch['binding']['component_role_identities'].values())
    require_component_role_budget(component_roles)
    roles.extend(component_roles)
    roles.extend(retained_preaccept_roles())
    C.need(len({tuple(x) for x in roles}) == len(roles), 'closed role identities repeat')
    current_inventory(inv,current_lease=lease)
    fresh_retained_fixture_absence()
    C.absent_groups(roles); C.absent_groups(roles)
    from component_snapshot import endpoint_absence
    endpoint_absence()
    recheck_originals(prior_originals + list(lease['retirement'].values()) +
                      [row for branch in branches for row in branch['originals']] + retained_transport)
    try:
        C.private_dir(ROOT)
    except FileNotFoundError:
        C.private_dir(ROOT, create=True)
    target = C.private_dir(ROOT/lease['nonce'], create=True)
    C.put(target/'PUBLISH-INTENT.json', {'schema': 'hepta.native-guard.boundary-publish-intent.v1',
        'nonce': base['nonce'], 'scope': base['scope'], 'lease_sha256': C.sha(lease_raw),
        'closure': C.descriptor(raw['closure']), 'inventory': C.descriptor(raw['inventory']),
        'maximum_publish_attempts': 1, 'automatic_retry': False})
    for key, filename in [('closure', 'CLOSURE.original.json'), ('inventory', 'AFTER-INVENTORY.original.json')]:
        path = target/filename; C.put(path, raw[key]); base[key] = describe(path, raw[key])
    current_inventory(inv,current_lease=lease)
    recheck_originals(prior_originals + list(lease['retirement'].values()) +
                      [row for branch in branches for row in branch['originals']] + retained_transport)
    boundary_value(base, combination_sha256=base['combination_sha256'], package_sha256=base['package_sha256'])
    path = ROOT/(lease['nonce']+'.json'); body = C.encoded(base); C.put(path, body)
    row = describe(path, body); original(row)
    return {'schema': 'hepta.native-guard.boundary-publish-result.v1',
        'state': 'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED', 'boundary': row,
        'old_retirement_current_equality_claimed': False, 'original_retirement_rewritten': False,
        'phone_tool_calls': 0, 'model_requests': 0, 'signals': 0, 'automatic_retry': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('lease', 'lease-sha256', 'closure', 'closure-sha256', 'inventory', 'inventory-sha256'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--execute-publish-once', action='store_true')
    a = p.parse_args()
    if not a.execute_publish_once:
        print(C.encoded({'state': 'HOST_PREVIEW_NO_BOUNDARY_PUBLISH', 'phone_calls': 0,
            'model_requests': 0, 'writes': 0, 'requires': 'Explicit Root publish after independent original closure.'}).decode(), end='')
        return 0
    print(C.encoded(publish(a)).decode(), end='')
    return 0



# Explicit unchanged Common bindings for the two-literal package reader derivation.
from component_common import read, need, sha, strict, pinned, relative, KERNEL_SHA

# Separately typed zero-role retained stage; never a native/old-sidebranch generation.
RETAINED_STAGE_REFERENCE = 'reference/retained_unstarted_stage_final02.py'
RETAINED_STAGE_BYTES = 62662
RETAINED_STAGE_SHA256 = 'bc6faf1c7ae2b7e3d44be3d4fe19e4272073073f8df283397ef37c177ca25850'
REVIEWED_RETAINED_STAGE_BINDING = {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'closure': {'bytes': 65567, 'sha256': '38a93ca265e0bb1b35ae80ab8309f389991e8c9a300700508e09841df3313e76'}, 'closure_projection': {'bytes': 9310, 'sha256': '850be3b4a55215105f17aabe6336610593dcdd9a3788c8fdc2d9f8f8d040dda5'}, 'component_qualified': False, 'component_role_identities': {}, 'fixture_root_count': 0, 'host_core_source': {'bytes': 29059, 'sha256': '8042130efbe14998089b96aab6a9665859ceed62599232ade33b3c57cdcc9afb'}, 'inventory': {'bytes': 1206630, 'sha256': 'fe8f37a3e4fb5ce46514e14c80b4e5ef8986d4653a8ad4a991bc463caaf78aa6'}, 'label': 'root-r10-neg01-a1055-final02', 'native_case_count': 0, 'native_predecessor': {'bytes': 21325, 'metadata': [65086, 158182, 33152, 0, 0, 1, 21325, 1793928633271896666, 1793928633271896666], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50.json', 'sha256': 'fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66'}, 'nonce': 'd11e31c9ac94920d47998ca88a97e98f', 'observation_projection': {'bytes': 18262, 'sha256': 'aa3efe0f8edf3b119e21ae45afa8efe9163886156ae6d91860ad4233e5be5046'}, 'observations': {'bytes': 1200485, 'sha256': 'da74addf5ae9c0bf3d78ad5639ac7b6101b44988af1e03c9632ad99f0d7d64ba'}, 'original_map': {'bytes': 46513, 'sha256': '906c16661ba90a2bc4887b256f04fc2451f0cf8018aba071dc82b6a8811a89bc'}, 'original_map_projection': {'bytes': 28683, 'sha256': 'c85679f94659026587e24e91ae922ba94c1d3d7070cd83fca6a265754d238423'}, 'original_sender_wait': 'UNKNOWN_UNCHANGED', 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02/executor'], 'projection_source': {'bytes': 3256, 'sha256': 'af9791a4e31022fd892cb2cd8be5b1070210613ed899b3f35c4db45315e624dd'}, 'reader_source_sha256': 'bc6faf1c7ae2b7e3d44be3d4fe19e4272073073f8df283397ef37c177ca25850', 'schema': 'hepta.native-guard.retained-unstarted-stage-binding.v1', 'scope_profile': 'expired_private_stage_no_roles_no_Send'}

def retained_stage_verifier():
    import types
    package=Path(__file__).parent.parent
    supplied=globals().get('__reviewed_package_sources__')
    C.need(supplied is None or type(supplied)is dict,'reviewed retained-stage package map')
    raw=C.read(package/RETAINED_STAGE_REFERENCE,262144,private=False) if supplied is None else supplied[RETAINED_STAGE_REFERENCE]
    C.need(type(raw)is bytes and len(raw)==RETAINED_STAGE_BYTES and C.sha(raw)==RETAINED_STAGE_SHA256,
           'exact independently reviewed retained-stage reader')
    verifier=types.ModuleType('reviewed_retained_unstarted_stage')
    verifier.__file__=str(package/RETAINED_STAGE_REFERENCE)
    verifier.__reviewed_source_sha256__=RETAINED_STAGE_SHA256
    exec(compile(raw,verifier.__file__,'exec'),verifier.__dict__)
    return verifier

def retained_unstarted_stage(*, read_pinned=None):
    """Historical-only pure proof. Host callers inject their exact retained-old39 reader."""
    reader=read_pinned
    if reader is None:reader=globals().get('__retained_stage_read_pinned__')
    if reader is None:reader=original
    C.need(callable(reader),'explicit original reader required')
    verifier=retained_stage_verifier()
    summary=verifier.verify_retained_unstarted_stage(read_pinned=reader,validate_inventory=inventory_value)
    C.need(summary['binding']==REVIEWED_RETAINED_STAGE_BINDING
           and summary['binding']['native_case_count']==0
           and summary['binding']['component_role_identities']=={}
           and summary['binding']['fixture_root_count']==0
           and summary['original_sender_wait']=='UNKNOWN_UNCHANGED',
           'zero-role retained stage cannot grant native/role/fixture credit')
    return summary

def retained_stage_external_originals(summary):
    """Fresh phone-only bookends for the two GNU transport files outside the private roots."""
    import base64
    rows=[]
    for row in summary['required_originals']:
        if row['path'].startswith(summary['private_roots'][0]+'/'):continue
        descriptor={k:row[k]for k in('path','bytes','sha256','metadata')}
        path=Path(row['path']);label=os.getxattr(path,'security.selinux',follow_symlinks=False)
        original(descriptor)
        C.need(base64.b64encode(label).decode()==row['selinux_raw_b64']
               and label==os.getxattr(path,'security.selinux',follow_symlinks=False),
               'retained external transport source label differs')
        rows.append(descriptor)
    C.need(len(rows)==2,'exact retained GNU source/archive pair')
    return rows

def current_retained_stage_binding(value):
    C.need(value.get('retained_unstarted_stage')==REVIEWED_RETAINED_STAGE_BINDING
           and value.get('nonce')!=REVIEWED_RETAINED_STAGE_BINDING['nonce'],
           'current native original omitted or reused retained unstarted scope')
    return REVIEWED_RETAINED_STAGE_BINDING

def preserve_retained_unstarted_stage(current, *, retained=None, read_pinned=None):
    retained=retained_unstarted_stage(read_pinned=read_pinned) if retained is None else retained
    C.need(retained['binding']==REVIEWED_RETAINED_STAGE_BINDING,'fixed retained-stage identity')
    C.need(retained_stage_verifier().validate_private_preservation(retained,current,
                validate_inventory=inventory_value)is True,'retained private roots changed')
    return True

def fresh_retained_fixture_absence():
    # Called only by phone admission/snapshot/publish, never pure host history.
    return retained_stage_verifier().require_fresh_fixture_absence(lstat=os.lstat)

def retained_stage_current_home(lease, parent_profile, *, lstat, read_private):
    """Distinguish actual pre-create ENOENT from the exact completed current stage."""
    home=C.BASE/'native-guard-r10-r1'/lease['label']
    C.need(parent_profile['gnu']['path']==str(home.parent),'current home parent profile differs')
    try:
        before=lstat(home)
    except FileNotFoundError as error:
        C.need(error.errno==2 and home.name not in parent_profile['gnu']['names'],
               'pre-create home absence must be actual ENOENT and absent from complete parent names')
        return None
    C.need(stat.S_ISDIR(before.st_mode)and stat.S_IMODE(before.st_mode)==0o700
           and before.st_uid==before.st_gid==0 and home.name in parent_profile['gnu']['names'],
           'existing current home is not the exact private staged directory')
    lease_raw=read_private(home/'LEASE.json',1048576)
    complete_raw=read_private(home/'STAGE-COMPLETE.json',1048576)
    stage=C.strict(complete_raw)
    C.need(lease_raw==C.encoded(lease)
           and stage.get('schema')=='hepta.native-guard.private-stage.v1'
           and stage.get('state')=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES'
           and stage.get('lease_sha256')==C.sha(lease_raw)
           and stage.get('package_sha256')==lease['package_sha256']
           and stage.get('existing_files_overwritten')==0
           and stage.get('service_launches')==0 and stage.get('model_requests')==0
           and stage.get('native_tasks')==0
           and stage.get('existing_helper_or_policy_changes')==0
           and stage.get('automatic_retry')is False and stage.get('component_qualified')is False,
           'existing home requires exact original LEASE and completed no-role stage')
    C.need(C.metadata(before)==C.metadata(lstat(home)),'current staged home changed while binding phase')
    return home


def retained_stage_parent_aliases():
    """One bounded exact GNU/native shared-parent observation, without process actions."""
    import base64
    paths=(C.BASE/'native-guard-r10-r1',
           C.ANDROID/'data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1')
    rows=[]
    for path in paths:
        before=path.lstat();meta=C.metadata(before)
        C.need(stat.S_ISDIR(before.st_mode)and stat.S_IMODE(before.st_mode)==0o700
               and before.st_uid==before.st_gid==0,'retained stage parent ownership/type')
        names=sorted(p.name for p in path.iterdir())
        C.need(len(names)<=20000 and len(names)==len(set(names)),'bounded complete shared-parent names')
        label=os.getxattr(path,'security.selinux',follow_symlinks=False)
        C.need(C.metadata(path.lstat())==meta and sorted(p.name for p in path.iterdir())==names,
               'shared parent changed during observation')
        rows.append({'path':str(path),'metadata':meta,'names':names,
                     'selinux_raw_b64':base64.b64encode(label).decode()})
    C.need(all(rows[0][k]==rows[1][k]for k in('metadata','names','selinux_raw_b64')),
           'shared parent GNU/native aliases differ')
    return {'gnu':rows[0],'android':rows[1],'same_inode_and_full9':True}

def validate_retained_stage_parent_profiles(summary, profiles, inventory, *, additional_home=None):
    """Pure validation of exact source-parent homes plus at most two new homes."""
    import base64
    current=inventory_value(inventory)
    obs=C.strict(summary['observation_projection_raw'])['selected_actual_fields']
    old=obs['stage_before']['aliases'][2];gnu=Path(old['gnu']['path']);android=Path(old['android']['path'])
    C.need(type(profiles)is dict and set(profiles)=={'schema','binding','before','after','allowed_new_homes'}
           and profiles['schema']=='hepta.native-guard.retained-stage-parent-profiles.v1'
           and profiles['binding']==summary['binding']==REVIEWED_RETAINED_STAGE_BINDING,
           'exact retained shared-parent proof family')
    homes=sorted(p for p in current['roots'] if Path(p).parent==gnu and Path(p).name not in old['gnu']['names'])
    counted=len(homes)
    if additional_home is not None:
        p=Path(additional_home)
        C.need(p.parent==gnu and p.name not in old['gnu']['names'],'only explicit current lease home may be added')
        homes=sorted(set(homes)|{str(p)})
    retained_r7=retained_preaccept();retained_home=retained_r7['private_roots'][0]
    C.need(retained_home in homes,'exact retained failed R7 home omitted from shared parents')
    retained_r8=retained_failed_staged();r8_home=retained_r8['private_roots'][0]
    C.need(r8_home in homes and r8_home!=retained_home and len(retained_r8['private_roots'])==2,
           'exact separately retained staged R8 home and two roots')
    native_homes=[p for p in homes if p not in (retained_home,r8_home)]
    preserve_retained_preaccept(inventory,retained_preaccept_value=retained_r7)
    preserve_retained_failed_staged(inventory,retained_failed_staged_value=retained_r8)
    C.need(set(source_parent_homes()) <= set(native_homes)
           and SOURCE_PARENT_HOME_COUNT<=len(native_homes)<=SOURCE_PARENT_HOME_COUNT+MAX_NEW_CURRENT_CASE_PREFIX
           and len(summary['inventory']['roots'])==RETAINED_BASE_ROOT_COUNT
           and len(current['roots'])==len(summary['inventory']['roots'])+3*(counted-1)+len(retained_r8['private_roots'])
           and profiles['allowed_new_homes']==homes,'only reviewed current native prefix may add shared-parent members')
    names=sorted(set(old['gnu']['names'])|{Path(p).name for p in homes})
    before,after=profiles['before'],profiles['after']
    C.need(before==after and type(before)is dict
           and set(before)=={'gnu','android','same_inode_and_full9'}
           and before['same_inode_and_full9']is True,'shared-parent two-observation full9 bookends')
    for key,path in (('gnu',gnu),('android',android)):
        row=before[key];original_row=old[key]
        C.need(type(row)is dict and set(row)=={'path','metadata','names','selinux_raw_b64'}
               and row['path']==str(path)and row['names']==names
               and type(row['metadata'])is list and len(row['metadata'])==9
               and all(type(n)is int for n in row['metadata'])
               and row['metadata'][:5]==original_row['metadata'][:5]
               and row['metadata'][5]==original_row['metadata'][5]+len(homes)
               and row['selinux_raw_b64']==original_row['selinux_raw_b64']
               and base64.b64decode(row['selinux_raw_b64'],validate=True)==b'u:object_r:trillionnium_owner_open_state_file:s0\0',
               'shared parent identity/label/names differ from exact admitted additions')
    C.need(all(before['gnu'][k]==before['android'][k]for k in('metadata','names','selinux_raw_b64')),
           'both shared parent aliases must be one exact generation')
    return True

def retained_stage_parent_profiles(summary, inventory, before, after, *, additional_home=None):
    obs=C.strict(summary['observation_projection_raw'])['selected_actual_fields']
    old=obs['stage_before']['aliases'][2]['gnu'];parent=Path(old['path'])
    homes=sorted(p for p in inventory['roots'] if Path(p).parent==parent and Path(p).name not in old['names'])
    if additional_home is not None:homes=sorted(set(homes)|{str(additional_home)})
    value={'schema':'hepta.native-guard.retained-stage-parent-profiles.v1','binding':summary['binding'],
           'before':before,'after':after,'allowed_new_homes':homes}
    validate_retained_stage_parent_profiles(summary,value,inventory,additional_home=additional_home)
    return value

def validate_retained_fixture_observations(rows):
    expected='/proc/1/root/data/local/tmp/hepta-native-guard-'+REVIEWED_RETAINED_STAGE_BINDING['nonce']
    C.need(type(rows)is list and len(rows)==2,'two explicit fresh retained-fixture observations')
    for row in rows:
        C.need(type(row)is dict and set(row)=={'path','errno','parent_metadata','started_monotonic_ns',
                   'finished_monotonic_ns','original_wait_inferred'}
               and row['path']==expected and row['errno']==2
               and type(row['parent_metadata'])is list and len(row['parent_metadata'])==9
               and all(type(n)is int for n in row['parent_metadata'])
               and stat.S_ISDIR(row['parent_metadata'][2])
               and type(row['started_monotonic_ns'])is int and type(row['finished_monotonic_ns'])is int
               and 0<row['started_monotonic_ns']<=row['finished_monotonic_ns']
               and row['original_wait_inferred']is False,'actual fixture ENOENT observation required')
    C.need(rows[0]['finished_monotonic_ns']<=rows[1]['started_monotonic_ns'],'fresh fixture observations out of order')
    return True


CURRENT_RUNTIME_PATHS = frozenset(['reference/REVIEWED-PRODUCTION-PINS.json', 'reference/attempt05-AFTER-INVENTORY.original.json', 'reference/attempt05-CLOSURE.original.json', 'reference/attempt05-SIDE-PROOF.original.json', 'reference/component_common_r5.py', 'reference/component_core.py', 'reference/component_once_r9.py', 'reference/decode_client_state.py', 'reference/diag02-AFTER-INVENTORY.original.json', 'reference/diag02-CLOSURE.original.json', 'reference/diag02-SIDE-PROOF.original.json', 'reference/environment_parent_late_boundary_r6.py', 'reference/native_guard_session.py', 'reference/native_journal_audit.py', 'reference/non_native_attempt05.py', 'reference/non_native_diag02.py', 'reference/policy_parent_late_boundary_r4.py', 'reference/property_parent_late_boundary_r7.py', 'reference/send_new_native_task_r5.py', 'reference/tool_client_r6.py', 'source/close_component.py', 'source/component_common.py', 'source/component_lifecycle.py', 'source/component_listener.py', 'source/component_snapshot.py', 'source/late_boundary.py', 'source/native_guard_session_r2.py', 'source/native_proc_profile.py', 'source/prepare_component.py', 'source/root_fixture_once.py', 'source/root_fixture_originals.py', 'source/run_root_fixture_phase.py', 'source/send_new_native_guard_task_r10_r4.py', 'source/sender_native_guard_ready_r10_r4.py', 'source/stage_component.py', 'source/witness_bundle.py', 'reference/retained_unstarted_stage_final02.py', SOURCE_PARENT_REFERENCE])

def _verify_current_package38_original(package, pin):
    package = Path(package)
    raw = read(package, 262144); need(sha(raw) == pin, 'adapter package pin differs')
    m = strict(raw)
    need(m.get('schema') == 'hepta.native-guard.adapter-package.v1'
         and m.get('state') == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED', 'explicit adapter package required')
    files = m['files']; names = [x['path'] for x in files]
    need(len(names) == len(set(names)) and len(names) == 38, 'exact current 38-member package inventory required')
    for row in files:
        data = pinned(package.parent / relative(row['path']),
                      {k: row[k] for k in ('bytes', 'sha256')}, private=False)
        if row['path'] == 'reference/native_guard_session.py':
            need(sha(data) == KERNEL_SHA, 'frozen two-call kernel differs')
    need({'reference/native_guard_session.py', 'reference/REVIEWED-PRODUCTION-PINS.json',
          'source/native_guard_session_r2.py', 'source/component_common.py', 'source/component_listener.py',
          'source/component_lifecycle.py'} <= set(names), 'adapter package incomplete')
    return m

def validate_current_package_manifest(manifest):
    """Pure shape/pin check, called after the caller pins every member byte."""
    reviewed_diag02_non_native_record()
    retained_failed_transport_adapter().validate_manifest(manifest)
    rows = manifest['files']; index = {row['path']: row for row in rows}
    C.need(len(rows) == 38 and set(index) == CURRENT_RUNTIME_PATHS
           and manifest.get('runtime_file_count') == 38
           and manifest.get('retained_unstarted_stage') == REVIEWED_RETAINED_STAGE_BINDING
           and manifest.get('retained_unstarted_stage_count') == 1
           and manifest.get('current_complete_inventory_root_count') == EFFECTIVE_INITIAL_INVENTORY_ROOT_COUNT
           and manifest.get('maximum_complete_inventory_roots_after_two_final_NEG_cases') == MAX_COMPLETE_INVENTORY_ROOTS_WITH_RETAINED_FAILED_STAGED
           and manifest.get('retained_preaccept_binding') == RETAINED_PREACCEPT_BINDING
           and manifest.get('retained_failed_staged_binding') == RETAINED_FAILED_STAGED_BINDING
           and manifest.get('retained_failed_staged_phone_originals') ==
               [RETAINED_FAILED_STAGED_PHONE,RETAINED_FAILED_STAGED_ARCHIVE,RETAINED_FAILED_STAGED_READER]
           and manifest.get('retained_failed_staged_role_count') == 0
           and manifest.get('retained_failed_staged_private_root_count') == 2
           and manifest.get('retained_failed_staged_fixture_is_inventory_root') is False
           and manifest.get('retained_preaccept_phone_originals') == [RETAINED_PREACCEPT_PHONE,RETAINED_PREACCEPT_ARCHIVE]
           and manifest.get('total_fixture_roots_with_retained_preaccept') == TOTAL_FIXTURE_ROOT_CAP_WITH_RETAINED_PREACCEPT
           and {k:index[RETAINED_STAGE_REFERENCE][k]for k in ('bytes','sha256')} ==
               {'bytes':RETAINED_STAGE_BYTES,'sha256':RETAINED_STAGE_SHA256}
           and manifest.get('component_role_cap') == COMPONENT_ROLE_CAP
           and manifest.get('native_chain_cap') == MAX_CHAIN
           and manifest.get('maximum_new_current_case_prefix') == 2
           and manifest.get('diagnostic_only') is False
           and manifest.get('maximum_native_calls_in_current_generation') == 2
           and manifest.get('historical_native_boundary_count') == HISTORICAL_FAILED_BOUNDARY_COUNT+SOURCE_PARENT_COUNT
           and manifest.get('current_policy_sha256') == REVIEWED_CURRENT_POLICY_SHA256
           and manifest.get('explicit_policy_adoption_sha256') == REVIEWED_CURRENT_POLICY_ADOPTION_SHA256
           and manifest.get('v3_runtime_diagnostic_ancestor') == reviewed_v3_runtime_diagnostic_ancestor(),
           'explicit current 38-member package and actual source-parent resource contract required')
    C.need(all(manifest.get(key)==value for key,value in manifest_source_parent_binding().items())
           and {k:index[SOURCE_PARENT_REFERENCE][k] for k in ('bytes','sha256')} ==
               {'bytes':SOURCE_PARENT_READER_BYTES,'sha256':SOURCE_PARENT_READER_SHA256},
           'manifest must preserve exact source-parent provenance without current tuple credit')
    C.need({k:index['source/component_common.py'][k] for k in ('bytes','sha256')} ==
           {'bytes':19138,'sha256':'1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}
           and index['source/late_boundary.py']['sha256'] == reviewed_source_sha256()
           and {k:index[DIAG02_VERIFIER_REFERENCE][k] for k in ('bytes','sha256')} ==
               {'bytes':DIAG02_VERIFIER_BYTES,'sha256':DIAG02_VERIFIER_SHA256},
           'current verifier, historical Common or exact typed diag02 source differs')
    record = reviewed_diag02_non_native_record()
    for key, name in DIAG02_REFERENCE_FILES.items():
        C.need({k:index[name][k] for k in ('bytes','sha256')} ==
               {k:record[key][k] for k in ('bytes','sha256')},
               'current package omitted an actual diag02 published original')
    return manifest


def verify_current_package(package, pin):
    """Only this exact new 38-member generation; historical Common remains C32."""
    reviewed_diag02_non_native_record()
    manifest = _verify_current_package38_original(package, pin)
    return validate_current_package_manifest(manifest)

# Source fragment: appended to the reviewed late module by author/build_runtime.py.
# This is deliberately unbound.  Only an actual reviewed phone publication record
# may replace this one literal; Mac inode/uid records are not substitutes.
REVIEWED_DIAG02_PUBLICATION = {'closure': {'bytes': 253127, 'metadata': [65086, 154861, 33152, 0, 0, 1, 253127, 1793914862787901919, 1793914862787901919], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/8daaaad6a322963e87973613c1fac762/CLOSURE.original.json', 'sha256': 'e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035'}, 'inventory': {'bytes': 1031582, 'metadata': [65086, 154530, 33152, 0, 0, 1, 1031582, 1793914862811901919, 1793914862811901919], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/8daaaad6a322963e87973613c1fac762/AFTER-INVENTORY.original.json', 'sha256': '10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d'}, 'nonce': '8daaaad6a322963e87973613c1fac762', 'proof': {'bytes': 8439, 'metadata': [65086, 136598, 33152, 0, 0, 1, 8439, 1793914865279901918, 1793914865279901918], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/8daaaad6a322963e87973613c1fac762/SIDE-PROOF.original.json', 'sha256': 'a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd'}, 'schema': 'hepta.native-guard.reviewed-non-native-attempt.v2', 'sources': {'capture': '7bb8e477a1b3d034e327ecdffdd5a3d0f6ac2308b7abed3758cb81f205605b4e', 'capture_driver': '2f3bd85ad40ad9d99f5994fbee38af238b4c7542291e3075daf6bb9f0ed78fb0', 'closer': 'c497377e6e52daf66c79ff5334573d98766e8ce192945157c247773f953399f4', 'publisher': '546d540c22c843a1cb61f4372fed1c393f04b3dee8a2695919c48ec9ae8cda15', 'sender_verifier': '59589436cc90361f98422f91178725a128e533fc118b3c17ec2838fe5b490a31', 'verifier': '296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6'}}
DIAG02_NONCE = '8daaaad6a322963e87973613c1fac762'
DIAG02_PACKAGE_SHA256 = '8e5ba081f1780da2ec73a3c103e7a27f6a0ba4e6e15ceab502fa8221ed410863'
DIAG02_VERIFIER_REFERENCE = 'reference/non_native_diag02.py'
DIAG02_VERIFIER_BYTES = 29504
DIAG02_VERIFIER_SHA256 = '296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6'
DIAG02_REFERENCE_FILES = {
    'proof': 'reference/diag02-SIDE-PROOF.original.json',
    'closure': 'reference/diag02-CLOSURE.original.json',
    'inventory': 'reference/diag02-AFTER-INVENTORY.original.json'}
DIAG02_CLOSED_PIN = {'bytes': 253127,
    'sha256': 'e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035'}
DIAG02_INVENTORY_PIN = {'bytes': 1031582,
    'sha256': '10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d'}
CURRENT_FIELDS = FIELDS | {'non_native_sidebranches'}
CURRENT_RETAINED_FIELDS = CURRENT_FIELDS | {'retained_unstarted_stage','retained_stage_parent_profiles'}


def reviewed_diag02_non_native_record():
    record = REVIEWED_DIAG02_PUBLICATION
    C.need(type(record) is dict and set(record) ==
           {'schema', 'nonce', 'proof', 'closure', 'inventory', 'sources'}
           and record['schema'] == 'hepta.native-guard.reviewed-non-native-attempt.v2'
           and record['nonce'] == DIAG02_NONCE,
           'actual phone diag02 publication record is not bound; no new admission')
    root = C.BASE/'native-guard-nonnative-boundaries-r10-r1'/DIAG02_NONCE
    for key, filename in NON_NATIVE_CAPTURE_FILES.items():
        exact_descriptor(record[key], expected_path=root/filename)
    C.need({k: record['closure'][k] for k in ('bytes', 'sha256')} == DIAG02_CLOSED_PIN
           and {k: record['inventory'][k] for k in ('bytes', 'sha256')} == DIAG02_INVENTORY_PIN,
           'phone publication reinterprets the actual host closed originals')
    sources = record['sources']
    C.need(type(sources) is dict and set(sources) ==
           {'capture', 'capture_driver', 'closer', 'publisher', 'sender_verifier', 'verifier'}
           and all(type(v) is str and C.HASH.fullmatch(v) for v in sources.values())
           and sources['verifier'] == DIAG02_VERIFIER_SHA256,
           'actual diag02 six-source publication identity differs')
    return record


def diag02_non_native_sidebranch(*, phone_originals=False):
    """Retain the exact second typed no-Send branch, never a native generation."""
    import types
    record = reviewed_diag02_non_native_record()
    package = Path(__file__).parent.parent
    supplied = globals().get('__reviewed_package_sources__')
    C.need(supplied is None or type(supplied) is dict, 'reviewed package source map differs')
    def package_raw(name, size, digest):
        C.need(type(size) is int and 0 < size <= 16*1024*1024
               and type(digest) is str and C.HASH.fullmatch(digest),
               'bounded diag02 package original required')
        if supplied is None:
            raw = C.read(package/name, 16*1024*1024, private=False)
        else:
            C.need(name in supplied, 'diag02 package original missing: '+name)
            raw = supplied[name]
        C.need(type(raw) is bytes and len(raw) == size and C.sha(raw) == digest,
               'diag02 package original bytes differ: '+name)
        return raw
    verifier_raw = package_raw(DIAG02_VERIFIER_REFERENCE, DIAG02_VERIFIER_BYTES,
                               DIAG02_VERIFIER_SHA256)
    raw = {key: package_raw(name, record[key]['bytes'], record[key]['sha256'])
           for key, name in DIAG02_REFERENCE_FILES.items()}
    verifier = types.ModuleType('reviewed_non_native_diag02')
    verifier.__file__ = str(package/DIAG02_VERIFIER_REFERENCE)
    verifier.__reviewed_source_sha256__ = DIAG02_VERIFIER_SHA256
    saved_path = sys.path[:]
    saved_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        exec(compile(verifier_raw, verifier.__file__, 'exec'), verifier.__dict__)
        inventory_composition = compose_current_sidebranch_inventory(verifier, verifier_raw)
        verified = verifier.verify_sidebranch(raw['proof'], raw['closure'], raw['inventory'],
                                             expected_record=record)
    finally:
        sys.path[:] = saved_path
        sys.dont_write_bytecode = saved_dwb
    binding = verified['binding']
    expected_fields = NON_NATIVE_BINDING_FIELDS | {'scope_profile', 'preserved_non_native_sidebranches'}
    C.need(type(binding) is dict and set(binding) == expected_fields
           and binding['schema'] == 'hepta.native-guard.non-native-sidebranch-binding.v2'
           and binding['scope_profile'] == 'diag02_ready_observed_no_send'
           and binding['nonce'] == DIAG02_NONCE
           and binding['preserved_non_native_sidebranches'] == [REVIEWED_NON_NATIVE_ATTEMPT05]
           and all(binding[key] == record[key] for key in DIAG02_REFERENCE_FILES)
           and binding['native_predecessor'] == reviewed_codec_diagnostic_parent_ancestor()['boundary']
           and type(binding['native_case_count']) is int and binding['native_case_count'] == 0
           and binding['component_qualified'] is False,
           'diag02 was reclassified or its complete two-sidebranch provenance changed')
    inv = C.strict(raw['inventory'])
    inventory_value(inv)
    C.need(binding['preserved_roots'] == inv['roots']
           and type(binding['private_roots']) is list and len(binding['private_roots']) == 3
           and len(set(binding['private_roots'])) == 3
           and set(binding['private_roots']) <= set(inv['roots']),
           'diag02 exact preserved/private roots differ')
    roles = binding['component_role_identities']
    C.need(type(roles) is dict and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(type(v) is list and len(v) == 4
                   and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3,
           'diag02 exact three ended role generations differ')
    rows = [record[k] for k in DIAG02_REFERENCE_FILES]
    if phone_originals:
        for key in DIAG02_REFERENCE_FILES:
            C.need(original(record[key]) == raw[key], 'phone diag02 original differs from reviewed copy')
    return {'binding': binding, 'inventory': inv, 'originals': rows, 'raw': raw,
            'verified': verified, 'verifier': verifier, 'current_inventory_composition': inventory_composition}


def non_native_sidebranches(*, phone_originals=False):
    """The only permitted order is old05 followed by actual no-Send diag02."""
    branches = [non_native_sidebranch(phone_originals=phone_originals),
                diag02_non_native_sidebranch(phone_originals=phone_originals)]
    bindings = [v['binding'] for v in branches]
    C.need([v['nonce'] for v in bindings] == [NON_NATIVE_ATTEMPT05_NONCE, DIAG02_NONCE]
           and all(type(v['native_case_count']) is int and v['native_case_count'] == 0
                   and v['component_qualified'] is False for v in bindings),
           'two fixed non-native branches cannot supply native case credit')
    roles = [tuple(role) for binding in bindings
             for role in binding['component_role_identities'].values()]
    C.need(len(roles) == len(set(roles)) == 6, 'non-native generations overlap')
    preserve_non_native_private(branches[1]['inventory'], branches[0])
    return branches


def preserve_non_native_sidebranches(current, branches):
    C.need(type(branches) is list and len(branches) == 2
           and [s['binding']['nonce'] for s in branches] ==
               [NON_NATIVE_ATTEMPT05_NONCE, DIAG02_NONCE], 'fixed two-sidebranch order differs')
    for sidebranch in branches:
        preserve_non_native_private(current, sidebranch)
    return True


def current_sidebranch_bindings(value, *, branches=None):
    branches = non_native_sidebranches() if branches is None else branches
    bindings = [s['binding'] for s in branches]
    C.need(value.get('non_native_sidebranch') == bindings[0]
           and value.get('non_native_sidebranches') == bindings
           and value.get('nonce') not in [s['nonce'] for s in bindings],
           'current native original omitted or reclassified a fixed non-native branch')
    return branches


def current_closure_sidebranches(closure, boundary, inventory_raw):
    if 'retained_preaccept_binding' in boundary:
        retained_r7=current_retained_preaccept_binding(boundary)
        current_retained_preaccept_binding(closure,retained_preaccept_value=retained_r7)
        preserve_retained_preaccept(C.strict(inventory_raw),retained_preaccept_value=retained_r7)
    if 'retained_failed_staged_binding' in boundary:
        retained_r8=current_retained_failed_staged_binding(boundary)
        current_retained_failed_staged_binding(closure,retained_failed_staged_value=retained_r8)
        preserve_retained_failed_staged(C.strict(inventory_raw),retained_failed_staged_value=retained_r8)
    if 'retained_failed_transport_binding' in boundary:
        r9=current_retained_failed_transport_binding(boundary)
        current_retained_failed_transport_binding(closure,retained_failed_transport_value=r9)
        preserve_retained_failed_transport(C.strict(inventory_raw),retained_failed_transport_value=r9)
    branches = current_sidebranch_bindings(boundary)
    current_sidebranch_bindings(closure, branches=branches)
    preserve_non_native_sidebranches(C.strict(inventory_raw), branches)
    if 'retained_unstarted_stage' in boundary:
        current_retained_stage_binding(boundary);current_retained_stage_binding(closure)
        retained=retained_unstarted_stage()
        preserve_retained_unstarted_stage(C.strict(inventory_raw),retained=retained)
        C.need(closure.get('retained_stage_parent_profiles')==boundary.get('retained_stage_parent_profiles'),
               'current boundary/closure shared-parent proof differs')
        validate_retained_stage_parent_profiles(retained,closure['retained_stage_parent_profiles'],C.strict(inventory_raw))
        validate_retained_fixture_observations(closure['retained_stage_fixture_absence'])


def effective_current_prior_inventory(boundary, inventory, branches, *, retained=None, read_pinned=None):
    """One fixed zero-role family extends actual v3 old39 to actual41."""
    require_r10_retained_transport()
    current_sidebranch_bindings(boundary, branches=branches)
    preserve_non_native_sidebranches(inventory, branches)
    retained=retained_unstarted_stage(read_pinned=read_pinned) if retained is None else retained
    C.need(retained['binding']==REVIEWED_RETAINED_STAGE_BINDING,'fixed retained-stage selection')
    if is_v3_runtime_diagnostic_ancestor(boundary):
        record=reviewed_v3_runtime_diagnostic_ancestor()
        C.need(boundary['inventory']==record['inventory']
               and C.descriptor(C.encoded(inventory))=={k:record['inventory'][k]for k in('bytes','sha256')},
               'fixed actual-v3 full inventory original required')
        return retained['inventory'],retained['binding']['inventory'],'fixed_native_actual_v3_plus_expired_unstarted_final02'
    if is_source_parent_ancestor(boundary):
        record=reviewed_source_parent_records()[0]
        C.need(C.descriptor(C.encoded(boundary))=={k:record['boundary'][k]for k in('bytes','sha256')}
               and boundary['inventory']==record['inventory']
               and C.descriptor(C.encoded(inventory))=={k:record['inventory'][k]for k in('bytes','sha256')},
               'only the exact newest source-parent complete inventory can be selected')
        source_parent_boundary_from_original(C.encoded(boundary),original_descriptor=record['boundary'])
        current_retained_stage_binding(boundary)
        preserve_retained_unstarted_stage(inventory,retained=retained)
        retained_r7=retained_preaccept()
        C.need(retained_r7['original_native_predecessor']==record['boundary']
               and set(inventory['roots'])|set(retained_r7['private_roots'])==set(retained_r7['inventory_roots'])
               and all(retained_r7['inventory_value']['entries'].get(k)==v for k,v in inventory['entries'].items()),
               'exact native44 source parent plus separately retained failed R7 roots')
        preserve_retained_preaccept(retained_r7['inventory_value'],retained_preaccept_value=retained_r7)
        retained_r8=retained_failed_staged()
        C.need(retained_r8['original_native_predecessor']==record['boundary']
               and set(retained_r7['inventory_roots'])|set(retained_r8['private_roots'])==set(retained_r8['inventory_roots'])
               and all(retained_r8['inventory_value']['entries'].get(k)==v for k,v in retained_r7['inventory_value']['entries'].items()),
               'exact native44 plus separately verified failed R7 three and failed staged R8 two roots')
        preserve_retained_preaccept(retained_r8['inventory_value'],retained_preaccept_value=retained_r7)
        preserve_retained_failed_staged(retained_r8['inventory_value'],retained_failed_staged_value=retained_r8)
        return retained_failed_transport_adapter().source_parent_inventory(retained_r7,retained_r8)
    current_context(boundary['combination_sha256'],boundary['package_sha256'])
    current_retained_stage_binding(boundary)
    preserve_retained_unstarted_stage(inventory,retained=retained)
    retained_r7=current_retained_preaccept_binding(boundary)
    preserve_retained_preaccept(inventory,retained_preaccept_value=retained_r7)
    retained_r8=current_retained_failed_staged_binding(boundary)
    preserve_retained_failed_staged(inventory,retained_failed_staged_value=retained_r8)
    r9=current_retained_failed_transport_binding(boundary)
    preserve_retained_failed_transport(inventory,retained_failed_transport_value=r9)
    C.need(len(inventory['roots'])=={'NEG-01':52,'NEG-02':55}[boundary['case_id']],
           'exact current cumulative retained R7 and staged R8 root count')
    return inventory,boundary['inventory'],'current_r10_native_head_with_separate_retained_failed_r7_r8_r9'


def require_component_role_budget(roles):
    C.need(type(roles) is list and len(roles) <= COMPONENT_ROLE_CAP
           and all(type(v) is list and len(v) == 4
                   and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles)
           and len({tuple(v) for v in roles}) == len(roles),
           'reviewed finite current native lane plus two fixed non-native branches role bound differs')
    return roles


def reviewed_source_parent_records():
    """The exact closed prefix from the preceding source tuple, newest first."""
    C.need(type(SOURCE_PARENT_RECORDS) is tuple and len(SOURCE_PARENT_RECORDS) == SOURCE_PARENT_COUNT
           and 1 <= SOURCE_PARENT_COUNT <= 2,
           'only the explicitly reviewed preceding source prefix is admitted')
    rows = C.strict(C.encoded(list(SOURCE_PARENT_RECORDS)))
    expected_keys = {'boundary', 'inventory', 'closure', 'closed_previous', 'label', 'home',
        'case_id', 'nonce', 'scope', 'roots', 'private_roots', 'prior_boundary',
        'component_qualified', 'native_status', 'actual_native_calls', 'owner_request_sha256',
        'closure_source_sha256'}
    seen_nonce = set(); seen_scope = set(); seen_homes = set()
    for index, row in enumerate(rows):
        C.need(type(row) is dict and set(row) == expected_keys,
               'source-parent record fields differ from the actual published record')
        C.need(type(row['nonce']) is str and re.fullmatch('[0-9a-f]{32}', row['nonce'])
               and type(row['label']) is str and re.fullmatch('[a-zA-Z0-9_.-]+', row['label'])
               and row['case_id'] in ('NEG-01', 'NEG-02'), 'exact source-parent identity required')
        C.scope(row['scope'])
        key = tuple(row['scope'][name] for name in C.SCOPE)
        C.need(row['nonce'] not in seen_nonce and key not in seen_scope
               and row['home'] not in seen_homes, 'source-parent identities repeat')
        seen_nonce.add(row['nonce']); seen_scope.add(key); seen_homes.add(row['home'])
        home = C.BASE/'native-guard-r10-r1'/row['label']
        expected_roots = [str(C.ANDROID/'data/trillionnium/owner-open/state/phone-local-v150'
                              /'native-guard-r10-r1'/row['label']/'executor'),
                          str(home), str(C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+row['nonce']))]
        C.need(row['home'] == str(home) and row['private_roots'] == expected_roots
               and type(row['roots']) is list and len(row['roots']) == len(set(row['roots']))
               and set(expected_roots) <= set(row['roots'])
               and len(row['roots']) == RETAINED_BASE_ROOT_COUNT + 3*(SOURCE_PARENT_COUNT-index),
               'source-parent cumulative roots differ from its actual three-root growth')
        for kind, name in (('boundary', row['nonce']+'.json'),
                           ('inventory', row['nonce']+'/AFTER-INVENTORY.original.json'),
                           ('closure', row['nonce']+'/CLOSURE.original.json')):
            exact_descriptor(row[kind], expected_path=ROOT/name)
        expected_prior = (rows[index+1]['boundary'] if index+1 < len(rows)
                          else reviewed_v3_runtime_diagnostic_ancestor()['boundary'])
        C.need(row['prior_boundary'] == expected_prior,
               'source-parent prefix must retain the exact preceding full original descriptor')
        cp = row['closed_previous']
        C.need(type(cp) is dict and set(cp) == {'path', 'bytes', 'sha256'}
               and type(cp['bytes']) is int and 0 < cp['bytes'] <= 65536
               and type(cp['path']) is str and Path(cp['path']).is_absolute()
               and str(Path(cp['path'])) == cp['path'] and '..' not in Path(cp['path']).parts
               and type(cp['sha256']) is str and C.HASH.fullmatch(cp['sha256']),
               'exact prior host publication input pin required')
        C.need(type(row['component_qualified']) is bool
               and row['native_status'] in ('completed', 'provider_failed', 'cancelled')
               and type(row['actual_native_calls']) is int and 0 <= row['actual_native_calls'] <= 2
               and (not row['component_qualified'] or
                    (row['native_status'] == 'completed' and row['actual_native_calls'] == 2))
               and row['closure_source_sha256'] == SOURCE_PARENT_CLOSURE_SHA256
               and type(row['owner_request_sha256']) is str
               and C.HASH.fullmatch(row['owner_request_sha256']),
               'source-parent outcome or closure source was reinterpreted')
    C.need(len(seen_homes) == SOURCE_PARENT_HOME_COUNT
           and len(rows[0]['roots']) == SOURCE_PARENT_INVENTORY_ROOT_COUNT
           and SOURCE_PARENT_INVENTORY_ROOT_COUNT == RETAINED_BASE_ROOT_COUNT+3*SOURCE_PARENT_HOME_COUNT,
           'actual preceding source homes and inventory resource accounting differ')
    return rows


def source_parent_private_roots():
    return [root for row in reviewed_source_parent_records() for root in row['private_roots']]


def source_parent_homes():
    return sorted(row['home'] for row in reviewed_source_parent_records())


def is_source_parent_ancestor(value):
    if type(value) is not dict:
        return False
    pin = C.descriptor(C.encoded(value))
    return any(pin == {key:row['boundary'][key] for key in ('bytes', 'sha256')}
               for row in reviewed_source_parent_records())


def _source_parent_original(raw, original_descriptor):
    C.need(type(raw) is bytes, 'source-parent classification requires original bytes')
    pin = C.descriptor(raw)
    for row in reviewed_source_parent_records():
        if pin == {key:row['boundary'][key] for key in ('bytes', 'sha256')}:
            C.need(original_descriptor == row['boundary'],
                   'source-parent bytes require their exact path and all nine metadata integers')
            return row
    return None


_SOURCE_PARENT_READER_METHODS = ('boundary_from_original', 'closed_boundary_originals',
                                 'require_failed_ancestor_tail')


class SourceParentReader:
    """Only original R4 pure entrypoints, with their own original module globals."""
    __slots__ = ('_methods', '_provenance')

    def __init__(self, methods, provenance):
        from types import MappingProxyType
        C.need(set(methods) == set(_SOURCE_PARENT_READER_METHODS)
               and all(callable(method) for method in methods.values()),
               'the three exact source-parent reader methods are required')
        object.__setattr__(self, '_methods', MappingProxyType(dict(methods)))
        object.__setattr__(self, '_provenance', C.encoded(provenance))

    def __getattr__(self, name):
        try:
            return self._methods[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name, value):
        raise AttributeError('source-parent reader is immutable')

    def provenance(self):
        return C.strict(self._provenance)


def source_parent_reader():
    """Load byte-exact old sources; never bind old publisher identity to new code."""
    import types
    package = Path(__file__).parent.parent
    supplied = globals().get('__reviewed_package_sources__')
    C.need(supplied is None or type(supplied) is dict,
           'reviewed source-parent package overlay must be an explicit byte map')
    sources = {}
    for name, descriptor in SOURCE_PARENT_READER_DEPENDENCIES.items():
        raw = (C.read(package/name, 16*1024*1024, private=False) if supplied is None
               else supplied.get(name))
        C.need(type(raw) is bytes and C.descriptor(raw) == descriptor,
               'exact original source-parent reader dependency differs: '+name)
        sources[name] = raw
    old_raw = sources[SOURCE_PARENT_REFERENCE]
    # All nested readers consult this old source slot for code provenance.
    # A new source/late_boundary.py must never be visible through this overlay.
    overlay = dict(sources)
    overlay['source/late_boundary.py'] = old_raw
    present = 'component_common' in sys.modules
    saved = sys.modules.get('component_common')
    old_path = sys.path[:]; old_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        common = types.ModuleType('component_common')
        common.__file__ = str(package/'source/component_common.py')
        common.__reviewed_source_sha256__ = SOURCE_PARENT_COMMON_SHA256
        sys.modules['component_common'] = common
        exec(compile(sources['source/component_common.py'], common.__file__, 'exec'), common.__dict__)
        old = types.ModuleType('reviewed_source_parent_late_boundary_r4')
        old.__file__ = str(package/SOURCE_PARENT_REFERENCE)
        old.__reviewed_source_sha256__ = SOURCE_PARENT_READER_SHA256
        old.__reviewed_package_sources__ = overlay
        callback = globals().get('__retained_stage_read_pinned__')
        if callback is not None:
            C.need(callable(callback), 'explicit retained original callback must be callable')
            old.__retained_stage_read_pinned__ = callback
        exec(compile(old_raw, old.__file__, 'exec'), old.__dict__)
        C.need(old.C is common
               and old.reviewed_source_sha256() == SOURCE_PARENT_READER_SHA256
               and old.REVIEWED_CURRENT_COMBINATION_SHA256 == SOURCE_PARENT_COMBINATION_SHA256
               and old.REVIEWED_CURRENT_POLICY_SHA256 == SOURCE_PARENT_POLICY_SHA256
               and old.REVIEWED_CURRENT_POLICY_ADOPTION_SHA256 == SOURCE_PARENT_POLICY_ADOPTION_SHA256
               and old.MAX_CHAIN == 11
               and old.REVIEWED_RETAINED_STAGE_BINDING == REVIEWED_RETAINED_STAGE_BINDING,
               'source-parent original module globals or published identity changed')
        for name in _SOURCE_PARENT_READER_METHODS:
            C.need(getattr(old, name).__globals__ is old.__dict__,
                   'source-parent method lost its original module globals')
        C.need(old.__reviewed_package_sources__['source/late_boundary.py'] == old_raw
               and C.descriptor(old_raw) == {'bytes': SOURCE_PARENT_READER_BYTES,
                                            'sha256': SOURCE_PARENT_READER_SHA256},
               'source-parent self-source overlay differs')
        for name in ('main', 'publish', 'verify_current'):
            old.__dict__.pop(name, None)
        provenance = {'schema': 'hepta.native-guard.exact-source-parent-reader.v1',
            'source': {'bytes': SOURCE_PARENT_READER_BYTES, 'sha256': SOURCE_PARENT_READER_SHA256},
            'common': {'bytes': 19138, 'sha256': SOURCE_PARENT_COMMON_SHA256},
            'combination_sha256': SOURCE_PARENT_COMBINATION_SHA256,
            'package_sha256': SOURCE_PARENT_PACKAGE_SHA256,
            'original_module_globals': True, 'old_source_slot_overlay': True,
            'historical_reader_functions_changed': False,
            'historical_publisher_identity_changed': False,
            'validation_result_cache': False, 'current_tuple_credit': False,
            'methods': list(_SOURCE_PARENT_READER_METHODS)}
        return SourceParentReader({name:getattr(old, name) for name in _SOURCE_PARENT_READER_METHODS},
                                  provenance)
    finally:
        sys.path[:] = old_path; sys.dont_write_bytecode = old_dwb
        if present:
            sys.modules['component_common'] = saved
        else:
            sys.modules.pop('component_common', None)


def source_parent_boundary_from_original(raw, *, original_descriptor):
    record = _source_parent_original(raw, original_descriptor)
    C.need(record is not None, 'only an exact explicitly reviewed source-parent original is admitted')
    value = source_parent_reader().boundary_from_original(raw, original_descriptor=original_descriptor,
        combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)
    for key in ('inventory', 'closure', 'case_id', 'nonce', 'scope', 'roots', 'prior_boundary',
                'component_qualified', 'native_status', 'actual_native_calls', 'owner_request_sha256'):
        C.need(value[key] == record[key], 'source-parent original field differs: '+key)
    C.need(value['publisher_source_sha256'] == SOURCE_PARENT_READER_SHA256
           and value['package_sha256'] == SOURCE_PARENT_PACKAGE_SHA256
           and value['combination_sha256'] == SOURCE_PARENT_COMBINATION_SHA256
           and value['retained_stage_parent_profiles']['allowed_new_homes'] ==
               sorted(row['home'] for row in reviewed_source_parent_records()
                      if row['home'] in value['roots']),
           'source-parent source tuple or actual home accounting changed')
    return value


def source_parent_closed_boundary_originals(raw, inventory_raw, closure_raw, *, original_descriptor):
    value = source_parent_boundary_from_original(raw, original_descriptor=original_descriptor)
    checked, inventory, closure = source_parent_reader().closed_boundary_originals(
        raw, inventory_raw, closure_raw, original_descriptor=original_descriptor,
        combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)
    C.need(checked == value and closure.get('closure_source_sha256') == SOURCE_PARENT_CLOSURE_SHA256,
           'source-parent closed result or original closure source changed')
    C.need(inventory['roots'] == value['roots'], 'source-parent complete roots changed')
    return checked, inventory, closure


def manifest_source_parent_binding():
    """Exact manifest fields derived from the actual retained source prefix."""
    rows = reviewed_source_parent_records()
    return {'runtime_file_count': 38,
        'source_parent_reader': {'path': SOURCE_PARENT_REFERENCE, 'bytes': SOURCE_PARENT_READER_BYTES,
                                 'sha256': SOURCE_PARENT_READER_SHA256},
        'source_parent_records': rows,
        'source_parent_combination_sha256': SOURCE_PARENT_COMBINATION_SHA256,
        'source_parent_package_sha256': SOURCE_PARENT_PACKAGE_SHA256,
        'source_parent_native_boundary_count': SOURCE_PARENT_COUNT,
        'source_parent_home_count': SOURCE_PARENT_HOME_COUNT,
        'source_parent_private_roots': source_parent_private_roots(),
        'historical_failed_native_boundary_count': HISTORICAL_FAILED_BOUNDARY_COUNT,
        'historical_native_boundary_count': HISTORICAL_FAILED_BOUNDARY_COUNT+SOURCE_PARENT_COUNT,
        'source_parent_qualification_is_current_tuple_credit': False,
        'component_role_cap': COMPONENT_ROLE_CAP, 'native_chain_cap': MAX_CHAIN,
        'fixture_root_cap': MAX_FIXTURE_ROOTS,
        'maximum_new_current_case_prefix': MAX_NEW_CURRENT_CASE_PREFIX,
        'current_complete_inventory_root_count': EFFECTIVE_INITIAL_INVENTORY_ROOT_COUNT,
        'maximum_complete_inventory_roots_after_two_final_NEG_cases': MAX_COMPLETE_INVENTORY_ROOTS_WITH_RETAINED_FAILED_STAGED}



RETAINED_PREACCEPT_READER={'bytes': 37404, 'sha256': '5935f4d4b3f00d914c6e0f9aec4429cf424a0601685061fe9277de3df5403b21', 'zlib_base64': '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'}
RETAINED_PREACCEPT_PHONE={'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/4808fbf1e81fd1542e7ffb60d7f57ca6/RETENTION-INPUTS.json', 'bytes': 413, 'sha256': '4a3cb5afc08092f6a30ccf92e443b664ac511c7f764d9ef8aab86955e1aaa4ab'}
RETAINED_PREACCEPT_ARCHIVE={'bytes': 3000200, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/4808fbf1e81fd1542e7ffb60d7f57ca6/ORIGINALS.zlib', 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}
RETAINED_PREACCEPT_HOST={'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-preaccept-r7-failed01/RETENTION-INPUTS.json', 'bytes': 423, 'sha256': '0878279ffce3ecf3e541063ab8ce845950b904e0d46b9a81f6c2bf451bec4b29'}
RETAINED_PREACCEPT_HOST_ARCHIVE={'bytes': 3000200, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-preaccept-r7-failed01/ORIGINALS.zlib', 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}
RETAINED_PREACCEPT_PHONE_MANIFEST_BASE64='eyJhcmNoaXZlIjp7ImJ5dGVzIjozMDAwMjAwLCJwYXRoIjoiL3Zhci9saWIvdHJpbGxpb25uaXVtL293bmVyLW9wZW4vcGhvbmUtbG9jYWwtdjE1MC9uYXRpdmUtZ3VhcmQtbm9ubmF0aXZlLWJvdW5kYXJpZXMtcjEwLXIxLzQ4MDhmYmYxZTgxZmQxNTQyZTdmZmI2MGQ3ZjU3Y2E2L09SSUdJTkFMUy56bGliIiwic2hhMjU2IjoiNDAxMDc3OWI5YTM4MTBkYzdkMGQ1MTA3MmRjNzZkZDUyYmUyMzI3MzAxYjg1N2RmMmIwNGRkYjAwNGE1ZWRjYSJ9LCJyYXdfYXJjaGl2ZSI6eyJieXRlcyI6MTE0Mjc4NDAsInNoYTI1NiI6ImE1MGFiZWQyZmVhNDQzOTM0NjhiZDA1OGM5Yzk3ZDcyMzMwZTliZjBiOThlMzZhYTE5NmYwYTBkMDVhZmZjZGQifSwic2NoZW1hIjoiaGVwdGEucjcucmV0YWluZWQtcHJlYWNjZXB0LWFyY2hpdmUudjEifQo='
RETAINED_PREACCEPT_BINDING={'schema': 'hepta.r7.retained-preaccept-binding.v1', 'label': 'root-r10-neg01-fc33-r7-bound01', 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'component_role_identities': {'supervisor': [12513, 12513, 12513, 39102689], 'sidecar': [14026, 14026, 14026, 39106597]}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'native_case_credit': 0, 'component_qualified': False}
CURRENT_RETAINED_FIELDS=CURRENT_RETAINED_FIELDS|{'retained_preaccept_binding'}
EFFECTIVE_INITIAL_INVENTORY_ROOT_COUNT=49
MAX_COMPLETE_INVENTORY_ROOTS_WITH_RETAINED_PREACCEPT=53
TOTAL_FIXTURE_ROOT_CAP_WITH_RETAINED_PREACCEPT=15

def retained_preaccept_reader():
    """Load the exact independently reviewed reader without a package member."""
    import base64, types, zlib
    packed = base64.b64decode(RETAINED_PREACCEPT_READER['zlib_base64'], validate=True)
    codec = zlib.decompressobj()
    raw = codec.decompress(packed, 128*1024+1)
    C.need(codec.eof and not codec.unused_data and not codec.unconsumed_tail
           and len(raw) <= 128*1024
           and C.descriptor(raw) == {k:RETAINED_PREACCEPT_READER[k] for k in ('bytes','sha256')},
           'exact complete retained preaccept reader source required')
    reader = types.ModuleType('r8_exact_retained_preaccept_reader')
    reader.__file__ = '<pinned retained R7 preaccept reader>'
    exec(compile(raw, reader.__file__, 'exec'), reader.__dict__)
    return reader


def retained_preaccept_read_pinned(row):
    reader = retained_preaccept_reader()
    reader.original_descriptor(row)
    C.need(row == RETAINED_PREACCEPT_PHONE or row == RETAINED_PREACCEPT_ARCHIVE,
           'only the exact independently published retained proof originals')
    injected = globals().get('__retained_preaccept_read_pinned__')
    raw = (injected(row) if injected is not None else
           C.pinned(row['path'], {k:row[k] for k in ('bytes','sha256')}, 4*1024*1024))
    C.need(C.descriptor(raw) == {k:row[k] for k in ('bytes','sha256')},
           'same retained proof byte pins on host and phone')
    return raw


def install_retained_preaccept_host_reader(read_pinned):
    """Map two exact phone originals to their independently pinned Mac copies.

    The phone manifest is the frozen original byte string, not the differently
    sized Mac manifest. Only its archive path differs. This is a pure host
    verification adapter and makes no assertion that phone publication occurred.
    """
    import base64
    reader = retained_preaccept_reader()
    phone_raw = base64.b64decode(RETAINED_PREACCEPT_PHONE_MANIFEST_BASE64, validate=True)
    C.need(C.descriptor(phone_raw) == {k:RETAINED_PREACCEPT_PHONE[k] for k in ('bytes','sha256')},
           'exact original phone manifest bytes required')
    def host_read(row):
        C.need(row in (RETAINED_PREACCEPT_HOST, RETAINED_PREACCEPT_HOST_ARCHIVE),
               'only the exact two retained Mac originals')
        raw = read_pinned(row)
        C.need(C.descriptor(raw) == {k:row[k] for k in ('bytes','sha256')},
               'retained Mac original pin differs')
        return raw
    def manifest_pair():
        host_raw = host_read(RETAINED_PREACCEPT_HOST)
        host = C.strict(host_raw); phone = C.strict(phone_raw)
        C.need(host['archive'] == RETAINED_PREACCEPT_HOST_ARCHIVE
               and phone['archive'] == RETAINED_PREACCEPT_ARCHIVE
               and {k:host['archive'][k] for k in ('bytes','sha256')} ==
                   {k:phone['archive'][k] for k in ('bytes','sha256')},
               'same exact archive bytes at the two fixed original paths')
        host['archive'] = phone['archive']
        C.need(host == phone, 'retained host/phone manifests differ beyond the fixed archive path')
        return host_raw
    before = manifest_pair()
    verified = reader.verify_retained_preaccept_archive(RETAINED_PREACCEPT_HOST, read_pinned=host_read)
    C.need(verified['retained_preaccept_binding'] == RETAINED_PREACCEPT_BINDING
           and manifest_pair() == before, 'actual Mac retained proof or manifest bookend differs')
    def phone_read(row):
        before = manifest_pair()
        if row == RETAINED_PREACCEPT_PHONE:
            return phone_raw
        C.need(row == RETAINED_PREACCEPT_ARCHIVE, 'only the exact two mapped phone originals')
        raw = host_read(RETAINED_PREACCEPT_HOST_ARCHIVE)
        C.need(manifest_pair() == before, 'retained Mac manifest changed during archive read')
        return raw
    globals()['__retained_preaccept_read_pinned__'] = phone_read
    return verified


def retained_preaccept():
    """Revalidate a failed scope separately; it never becomes a native prior."""
    reader = retained_preaccept_reader()
    verified = reader.verify_retained_preaccept_archive(
        RETAINED_PREACCEPT_PHONE, read_pinned=retained_preaccept_read_pinned)
    C.need(verified['retained_preaccept_binding'] == RETAINED_PREACCEPT_BINDING
           and verified['native_case_credit'] == 0
           and verified['original_roles_joined_and_groups_absent'] is False
           and verified['native_terminal'] is None
           and verified['global_unknown_effect_count'] is None
           and verified['supervisor_wait_exit_code'] is None
           and verified['standalone_execution_authorized'] is False,
           'retained failure cannot acquire a terminal, global count, or case credit')
    inventory_value(verified['inventory_value'])
    C.need(len(verified['inventory_roots']) == 47
           and len(verified['private_roots']) == 3
           and len(verified['component_role_identities']) == 2,
           'the one exact retained preaccept family is required')
    return verified


def preserve_retained_preaccept(inventory, *, retained_preaccept_value=None):
    retained = retained_preaccept() if retained_preaccept_value is None else retained_preaccept_value
    C.need(retained['retained_preaccept_binding'] == RETAINED_PREACCEPT_BINDING,
           'same exact typed retained family')
    return retained_preaccept_reader().validate_private_preservation(
        retained, inventory, inventory_reader=inventory_value)


def current_retained_preaccept_binding(value, *, retained_preaccept_value=None):
    retained = retained_preaccept() if retained_preaccept_value is None else retained_preaccept_value
    C.need(value.get('retained_preaccept_binding') == retained['retained_preaccept_binding']
           and value.get('nonce') != retained['nonce'],
           'current result omitted the separately retained failed R7 scope')
    return retained


def retained_preaccept_roles():
    retained = retained_preaccept()
    roles = list(retained['component_role_identities'].values())
    C.need(len(roles) == 2 and all(type(v) is list and len(v) == 4
           and v[:3] == [v[0]]*3 and all(type(n) is int and n > 1 for n in v) for v in roles)
           and len({tuple(v) for v in roles}) == 2,
           'only the two original retained R7 generations')
    return roles






def validate_retained_preaccept_observation(value, *, retained_preaccept_value=None):
    retained = retained_preaccept() if retained_preaccept_value is None else retained_preaccept_value
    C.need(type(value) is dict and set(value) == {'schema','binding','proof_originals','absence_observations',
           'native_case_credit','native_terminal','global_unknown_effect_count','original_two_role_success'}
           and value['schema'] == 'hepta.r8.retained-preaccept-observation.v1'
           and value['binding'] == retained['retained_preaccept_binding']
           and value['proof_originals'] == [RETAINED_PREACCEPT_PHONE, RETAINED_PREACCEPT_ARCHIVE]
           and type(value['native_case_credit']) is int and value['native_case_credit'] == 0
           and value['native_terminal'] is None and value['global_unknown_effect_count'] is None
           and value['original_two_role_success'] is False,
           'retained observation cannot rewrite the original failure')
    observations = value['absence_observations']
    C.need(type(observations) is list and len(observations) == 2
           and all(type(v) is dict and set(v) == {'numeric_pids','members','kernel_group_absence','observed_monotonic_ns'}
                   and type(v['numeric_pids']) is int and 0 < v['numeric_pids'] <= 4096
                   and v['members'] == [] and v['kernel_group_absence'] is True
                   and type(v['observed_monotonic_ns']) is int and v['observed_monotonic_ns'] > 0 for v in observations)
           and observations[0]['observed_monotonic_ns'] <= observations[1]['observed_monotonic_ns'],
           'two actual retained group absence observations required')
    return value


# R9 diagnostic-only addition. The original Common absence implementation and
# its 2-second / 4096-PID decision remain the sole decision maker.
R10_CURRENT_ADMISSION_DIAGNOSTIC_SLOTS=('current-admission-01','current-admission-02')
R10_MAX_FAILURE_DIAGNOSTIC_BYTES=2*1024*1024


def r10_original_group_failure_snapshot(error, identities):
    """Copy parsed rows from this failing original call, without another /proc read."""
    import math
    import time
    frames=[];found=[];tb=error.__traceback__
    while tb is not None:
        C.need(len(frames)<32,'bounded original failure traceback required')
        code=tb.tb_frame.f_code
        frames.append({'source':str(code.co_filename)[:1024],'function':str(code.co_name)[:128],
                       'line':tb.tb_lineno})
        if code is C.absent_groups.__code__:
            found.append((tb.tb_frame.f_locals,tb.tb_lineno))
        tb=tb.tb_next
    C.need(len(found)==1,'one frame from the same original Common absence function required')
    local,line=found[0]
    def role(value):
        C.need(type(value)is list and len(value)==4
               and all(type(n)is int and 1<n<2**64 for n in value)
               and value[:3]==[value[0]]*3,'bounded original role identity fields')
        return list(value)
    C.need(type(identities)is list and 1<=len(identities)<=64,'original role-input list required')
    requested=[role(value) for value in identities]
    C.need(type(local.get('identities'))is list and local['identities']==identities,
           'same failing call role inputs required')
    expected={value[0]:value for value in requested};ids=set(expected)
    C.need(local.get('expected')==expected and local.get('ids')==ids,
           'same original failing call expected map and ID set required')
    names=local.get('names')
    C.need(type(names)is list and len(names)<=4096
           and all(type(name)is str and 0<len(name)<=64 and name.isdecimal() for name in names),
           'bounded original census names required')
    members=local.get('members')
    C.need(type(members)is list and len(members)<=4096,'bounded original parsed members required')
    rows=[]
    for value in members:
        C.need(type(value)is dict and set(value)=={'pid','state','ppid','pgid','sid','start_ticks'},
               'only the original Common parsed-stat fields may be copied')
        C.need(all(type(value[k])is int and 0<=value[k]<2**64 for k in ('pid','ppid','pgid','sid','start_ticks'))
               and value['pid']>0 and type(value['state'])is str and len(value['state'])==1
               and value['state'].isascii(),'bounded original parsed member values')
        parsed={key:value[key] for key in ('pid','state','ppid','pgid','sid','start_ticks')}
        generation=[value[k] for k in ('pid','pgid','sid','start_ticks')]
        reasons={'same_original_pid_generation':value['pid'] in expected and generation==expected[value['pid']],
                 'numeric_pgid_matches_original_leader':value['pgid'] in ids,
                 'numeric_sid_matches_original_leader':value['sid'] in ids}
        C.need(any(reasons.values()),'copied member must satisfy the unchanged original predicate')
        rows.append({'parsed_same_failure_frame':parsed,'original_predicate_reasons':reasons,
                     'process_ownership_established':False,'raw_proc_stat_retained':False})
    deadline=local.get('deadline')
    C.need(type(deadline)in(int,float) and math.isfinite(deadline) and deadline>0,
           'original census deadline must be retained exactly')
    reason=str(error)
    completed=(type(error)is ValueError and reason=='owned group/session still observed' and bool(rows))
    return {'schema':'hepta.r10.original-group-failure-frame.v1',
        'evidence_kind':'parsed_same_failure_frame','original_common_sha256':SOURCE_PARENT_COMMON_SHA256,
        'original_function':'component_common.absent_groups','original_function_first_line':C.absent_groups.__code__.co_firstlineno,
        'original_failure_line':line,'traceback':frames,'error_type':type(error).__name__,'error_message':reason[:1024],
        'original_role_identities':requested,'original_expected':{str(k):v for k,v in expected.items()},
        'original_numeric_group_ids':sorted(ids),'original_census_names':list(names),
        'original_census_deadline_monotonic':deadline,'failure_observed_monotonic_ns':time.monotonic_ns(),
        'members':rows,'original_members_count':len(rows),
        'complete_census_reached_members_rejection':completed,
        'kernel_group_query_not_reached_for_members_rejection':True if completed else None,
        'raw_proc_stat_retained':False,'subsequent_proc_reads':0,'process_ownership_established':False,
        'absence_or_fencing_accepted':False,'original_failure_replaced':False}


def r10_save_current_admission_failure(lease,slot,snapshot):
    """One create-only private diagnostic, after failure and before lock/fork."""
    import time
    C.need(slot in R10_CURRENT_ADMISSION_DIAGNOSTIC_SLOTS,'one fixed current-admission diagnostic slot')
    C.need(type(lease)is dict and type(lease.get('label'))is str
           and re.fullmatch(r'root-r10-neg0[12]-fc33-r10-bound01',lease['label'])
           and type(lease.get('nonce'))is str and re.fullmatch('[0-9a-f]{32}',lease['nonce']),
           'diagnostic may only belong to the new fixed R10 lane')
    home=C.BASE/'native-guard-r10-r1'/lease['label'];C.private_dir(home)
    package=home/'package';manifest_path=package/'MANIFEST.json'
    lease_raw=C.read(home/'LEASE.json',262144)
    C.need(C.strict(lease_raw)==lease,'same live attempt lease bytes required for diagnostic')
    manifest_raw=C.read(manifest_path,262144)
    C.need(C.sha(manifest_raw)==lease['package_sha256'],'same actual package manifest required for diagnostic')
    manifest=C.strict(manifest_raw);members={row['path']:row for row in manifest['files']}
    C.need(len(members)==len(manifest['files']),'unique exact package member set')
    sources={}
    for name,path in [('source/component_common.py',Path(C.__file__)),('source/late_boundary.py',Path(__file__))]:
        C.need(path==package/name and name in members,'diagnostic source belongs to this exact package')
        row=members[name];before=C.metadata(path.lstat());raw=C.read(path,262144)
        C.need(before==C.metadata(path.lstat()),'diagnostic source changed after its pinned read')
        C.need(C.descriptor(raw)=={k:row[k] for k in ('bytes','sha256')},'diagnostic executing source pin differs')
        sources[name]={'path':str(path),**C.descriptor(raw),'metadata':before}
    C.need(sources['source/component_common.py']['sha256']==SOURCE_PARENT_COMMON_SHA256,
           'the original Common implementation must remain unchanged')
    value={'schema':'hepta.r10.current-admission-group-failure-diagnostic.v1',
        'state':'ORIGINAL_ABSENCE_CALL_FAILED_DIAGNOSTIC_ONLY','slot':slot,
        'label':lease['label'],'nonce':lease['nonce'],'boot_id':lease['boot_id'],
        'case_id':lease['case_id'],'lease':{'path':str(home/'LEASE.json'),**C.descriptor(lease_raw)},
        'package':{'path':str(manifest_path),**C.descriptor(manifest_raw)},'sources':sources,
        'original_failure_observation':snapshot,'recorded_unix_ns':time.time_ns(),
        'same_original_exception_will_be_reraised':True,'subsequent_proc_reads':0,'signals_sent':0,
        'locks_acquired_by_diagnostic':0,'child_roles_created_by_diagnostic':0,'new_nonces':0,
        'runtime_admission':False,'retirement_accepted':False,'native_case_credit':0,
        'global_unknown_effect_count':None,'original_predicate_relaxed':False,'automatic_retry':False}
    raw=C.encoded(value)
    C.need(len(raw)<=R10_MAX_FAILURE_DIAGNOSTIC_BYTES,'bounded original failure diagnostic bytes')
    path=home/('GROUP-ABSENCE-FAILURE.'+slot+'.original.json')
    # C.put is unchanged O_EXCL/NOFOLLOW/0600, fsyncs file and parent, and never overwrites.
    C.put(path,raw)
    return {'path':str(path),**C.descriptor(raw)}


def r10_current_admission_absence(lease,identities,slot):
    """The unchanged original call decides; every failure remains a failure."""
    try:
        return C.absent_groups(identities)
    except (OSError,ValueError) as original_error:
        try:
            # Copy its own traceback locals before any diagnostic source/file read.
            snapshot=r10_original_group_failure_snapshot(original_error,identities)
            r10_save_current_admission_failure(lease,slot,snapshot)
        except Exception as diagnostic_error:
            # Missing frames, malformed locals, existing slots, or write failures
            # cannot change the original result or advance toward lock/fork.
            try:
                os.write(2,C.encoded({'schema':'hepta.r10.failure-diagnostic-unavailable.v1',
                    'slot':slot,'error_type':type(diagnostic_error).__name__,
                    'detail':str(diagnostic_error)[:512],'original_exception_preserved':True,
                    'runtime_admission':False,'automatic_retry':False}))
            except Exception:
                pass
        raise


# Fixed R8 failed-staged scope is retained separately from every native case.
CURRENT_RETAINED_FIELDS=CURRENT_RETAINED_FIELDS|{'retained_failed_staged_binding','retained_failed_transport_binding'}
MAX_COMPLETE_INVENTORY_ROOTS_WITH_RETAINED_FAILED_STAGED=55
RETAINED_FAILED_STAGED_PHONE={'bytes': 409, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/RETENTION-INPUTS.json', 'sha256': '247ebf979d69cfd5b9b55b5cdbe55b2d1a57c481d3ceb67ef5e4ece91f7d78f6'}
RETAINED_FAILED_STAGED_ARCHIVE={'bytes': 2066079, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/ORIGINALS.zlib', 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}
RETAINED_FAILED_STAGED_READER={'bytes': 96088, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/verify_retained_staged_r8.py', 'sha256': '614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae'}
RETAINED_FAILED_STAGED_HOST={'bytes': 422, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-staged-r8-failed01-ast02/RETENTION-INPUTS.json', 'sha256': 'b005ba692ea1f31e93858628eb9ae64c936c83193c632002eafa1dfb84f7f7f0'}
RETAINED_FAILED_STAGED_HOST_ARCHIVE={'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-staged-r8-failed01-ast02/ORIGINALS.zlib', 'bytes': 2066079, 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}
RETAINED_FAILED_STAGED_HOST_READER={'bytes': 96088, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-staged-r8-failed01-ast02/verify_retained_staged_r8.py', 'sha256': '614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae'}
RETAINED_FAILED_STAGED_PHONE_MANIFEST_BASE64='eyJhcmNoaXZlIjp7ImJ5dGVzIjoyMDY2MDc5LCJwYXRoIjoiL3Zhci9saWIvdHJpbGxpb25uaXVtL293bmVyLW9wZW4vcGhvbmUtbG9jYWwtdjE1MC9uYXRpdmUtZ3VhcmQtbm9ubmF0aXZlLWJvdW5kYXJpZXMtcjEwLXIxL2FhMDZjM2I4ZDAzNWRjZDBjMDA0NzEwNWY2MjBiM2JmL09SSUdJTkFMUy56bGliIiwic2hhMjU2IjoiZDY2ZDI4NmJmYjc4OTBlMGIzMjM1ODMyNmI2NjlhYzRhNDdkNWY0YmE0M2M1MjRiYzNmMTI5ZjViZjYzMWU5MyJ9LCJyYXdfYXJjaGl2ZSI6eyJieXRlcyI6NjM4OTc2MCwic2hhMjU2IjoiMmYwZTk4ZjQ4ZjBmMTQ0OWNmMWZlNTg4ZmZlNmI1YTMwZjY5ZjI1MmZhZTY3ZTVmZDE2ODJhMjViNzEzYTIxMyJ9LCJzY2hlbWEiOiJoZXB0YS5yOC5yZXRhaW5lZC1zdGFnZWQtYXJjaGl2ZS52MSJ9Cg=='
RETAINED_FAILED_STAGED_BINDING={'absent_fixture_path': '/proc/1/root/data/local/tmp/hepta-native-guard-aa06c3b8d035dcd0c0047105f620b3bf', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {}, 'evidence_archive': {'archive': {'bytes': 2066079, 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}, 'raw_archive': {'bytes': 6389760, 'sha256': '2f0e98f48f0f1449cf1fe588ffe6b5a30f69f252fae67e5fd1682a25b713a213'}}, 'fixture_is_inventory_root': False, 'global_unknown_effect_count': None, 'inventory': {'bytes': 1403291, 'sha256': '2008db913728ff0c3836cb6edb361e37f427d7663f2832163fe93b2adb18f432'}, 'label': 'root-r10-neg01-fc33-r8-bound01', 'lease': {'bytes': 2506, 'sha256': 'f05ee53a7609972c18f6bab2263008a4c3de3b49b12b8654df94790b25c30a44'}, 'native_case_credit': 0, 'native_terminal': None, 'nonce': 'aa06c3b8d035dcd0c0047105f620b3bf', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_nonce_consumed': True, 'original_remote_cleanup_boolean': False, 'original_root_namespace_anchor': {'bytes': 12992, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r8-bound01/ROOT-FAILURE.json', 'sha256': 'ab8c85f7d403c6427931db66acfecb12137143cf3b78573a654346584dab7a31'}, 'package': {'bytes': 65655, 'sha256': '654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01/executor'], 'retained_preaccept_binding': {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {'sidecar': [14026, 14026, 14026, 39106597], 'supervisor': [12513, 12513, 12513, 39102689]}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'label': 'root-r10-neg01-fc33-r7-bound01', 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'native_case_credit': 0, 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'schema': 'hepta.r7.retained-preaccept-binding.v1'}, 'schema': 'hepta.r8.retained-staged-failure-binding.v1', 'standalone_execution_authorized': False}

def retained_failed_staged_read_pinned(row):
    if row==RETAINED_PREACCEPT_ARCHIVE:
        return retained_preaccept_read_pinned(row)
    C.need(row in (RETAINED_FAILED_STAGED_PHONE,RETAINED_FAILED_STAGED_ARCHIVE,RETAINED_FAILED_STAGED_READER),
           'only the three exact R8 proof files and original R7 archive')
    hook=globals().get('__retained_failed_staged_read_pinned__')
    if hook is not None:
        C.need(callable(hook),'explicit pinned retained R8 reader')
        raw=hook(row)
    else:
        path=Path(row['path']);before=C.metadata(path.lstat())
        raw=C.read(path,4*1024*1024)
        C.need(before==C.metadata(path.lstat()),'retained R8 source/proof full9 changed')
    C.need(C.descriptor(raw)=={k:row[k]for k in ('bytes','sha256')},'complete same retained R8 proof byte pin')
    return raw

def install_retained_failed_staged_host_reader(read_pinned):
    """Same actual phone proof, read from separately pinned Mac originals."""
    import base64
    C.need(callable(read_pinned),'bounded bookended host reader required')
    phone_raw=base64.b64decode(RETAINED_FAILED_STAGED_PHONE_MANIFEST_BASE64,validate=True)
    C.need(C.descriptor(phone_raw)=={k:RETAINED_FAILED_STAGED_PHONE[k]for k in ('bytes','sha256')},
           'actual 409-byte phone manifest original')
    phone=C.strict(phone_raw)
    def host_manifest():
        raw=read_pinned(RETAINED_FAILED_STAGED_HOST)
        C.need(C.descriptor(raw)=={k:RETAINED_FAILED_STAGED_HOST[k]for k in ('bytes','sha256')},
               'separate actual Mac retained R8 manifest original')
        value=C.strict(raw)
        C.need(set(value)==set(phone)=={'schema','archive','raw_archive'}
               and value['schema']==phone['schema']=='hepta.r8.retained-staged-archive.v1'
               and value['raw_archive']==phone['raw_archive']
               and value['archive']==RETAINED_FAILED_STAGED_HOST_ARCHIVE
               and phone['archive']==RETAINED_FAILED_STAGED_ARCHIVE,
               'same original archive with explicit different host/phone canonical paths')
        return raw
    host_manifest()
    def supplied(row):
        if row==RETAINED_FAILED_STAGED_PHONE:
            host_manifest();return phone_raw
        if row==RETAINED_FAILED_STAGED_ARCHIVE:
            target=RETAINED_FAILED_STAGED_HOST_ARCHIVE
        elif row==RETAINED_FAILED_STAGED_READER:
            target=RETAINED_FAILED_STAGED_HOST_READER
        else:
            raise ValueError('host R8 mapping left the three fixed original descriptors')
        raw=read_pinned(target)
        C.need(C.descriptor(raw)=={k:row[k]for k in ('bytes','sha256')},'host original is byte-identical to canonical phone proof')
        return raw
    globals()['__retained_failed_staged_read_pinned__']=supplied

def retained_failed_staged_reader():
    import types
    source=retained_failed_staged_read_pinned(RETAINED_FAILED_STAGED_READER)
    C.need(len(source)<=128*1024,'fixed external reader stays within original source read bound')
    module=types.ModuleType('fixed_failed_staged_r8');module.__file__=RETAINED_FAILED_STAGED_READER['path']
    exec(compile(source,module.__file__,'exec'),module.__dict__)
    return module

def retained_failed_staged():
    reader=retained_failed_staged_reader()
    verified=reader.verify_retained_staged_archive(RETAINED_FAILED_STAGED_PHONE,read_pinned=retained_failed_staged_read_pinned)
    C.need(verified['retained_failed_staged_binding']==RETAINED_FAILED_STAGED_BINDING
           and verified['state']=='ACTUAL_FAILED_STAGED_BEFORE_DETACHED_FORK_SCOPE_RETIRED_ORIGINALS_RETAINED'
           and verified['component_role_identities']=={} and verified['spawned_component_roles']==[]
           and verified['original_remote_cleanup_boolean']is False and verified['original_nonce_consumed']is True
           and verified['native_terminal']is None and verified['global_unknown_effect_count']is None
           and verified['historical_gate_failure_cause']=='UNKNOWN'
           and verified['original_failure_offender_identified']is False
           and verified['current_kernel_ESRCH_asserted']is False
           and type(verified['native_case_credit'])is int and verified['native_case_credit']==0
           and verified['standalone_execution_authorized']is False,
           'retained R8 failure cannot acquire a role, terminal, count, cause or execution credit')
    inventory_value(verified['inventory_value'])
    C.need(len(verified['inventory_roots'])==49 and len(verified['private_roots'])==2
           and verified['retained_preaccept_binding']==RETAINED_PREACCEPT_BINDING
           and verified['separate_absent_fixture']['path']==reader.FIXTURE
           and verified['separate_absent_fixture']['included_as_inventory_root']is False,
           'only the exact actual R7 old47 plus two retained failed R8 roots')
    return verified

def preserve_retained_failed_staged(inventory,*,retained_failed_staged_value=None):
    retained=retained_failed_staged()if retained_failed_staged_value is None else retained_failed_staged_value
    C.need(retained['retained_failed_staged_binding']==RETAINED_FAILED_STAGED_BINDING,'same fixed retained R8 family')
    return retained_failed_staged_reader().validate_private_preservation(retained,inventory,inventory_reader=inventory_value)

def current_retained_failed_staged_binding(value,*,retained_failed_staged_value=None):
    retained=retained_failed_staged()if retained_failed_staged_value is None else retained_failed_staged_value
    C.need(value.get('retained_failed_staged_binding')==retained['retained_failed_staged_binding']
           and value.get('nonce')!=retained['nonce'],'current result must retain the separately consumed failed R8 scope')
    return retained

def fresh_retained_failed_staged_fixture_absence(*,retained_failed_staged_value=None):
    import component_lifecycle as LIFE
    retained=retained_failed_staged()if retained_failed_staged_value is None else retained_failed_staged_value
    C.need(retained['retained_failed_staged_binding']==RETAINED_FAILED_STAGED_BINDING,'exact fixed R8 absent fixture family')
    fixture=Path(retained['separate_absent_fixture']['path'])
    row=LIFE.fixture_absence(fixture)
    C.need(row['path']==str(fixture) and row['absence']=='ENOENT'
           and row['canonical_parent_identity']==retained['separate_absent_fixture']['captured_observation']['parent_metadata'][:5],
           'same retained R8 fixture parent and actual current explicit ENOENT')
    return row

def validate_retained_failed_staged_fixture_observations(rows,*,retained_failed_staged_value=None):
    retained=retained_failed_staged()if retained_failed_staged_value is None else retained_failed_staged_value
    C.need(retained['retained_failed_staged_binding']==RETAINED_FAILED_STAGED_BINDING,'same fixed fixture proof')
    expected=retained['separate_absent_fixture']
    C.need(type(rows)is list and len(rows)==2,'two current retained R8 fixture observations')
    for row in rows:
        C.need(type(row)is dict and set(row)=={'schema','path','absence','canonical_parent_identity','observed_monotonic_ns','ui_actions'}
               and row['schema']=='hepta.native-guard.fixture-absence.v1'
               and row['path']==expected['path']and row['absence']=='ENOENT'
               and row['canonical_parent_identity']==expected['captured_observation']['parent_metadata'][:5]
               and type(row['observed_monotonic_ns'])is int and row['observed_monotonic_ns']>0
               and type(row['ui_actions'])is int and row['ui_actions']==0,
               'complete original same-parent R8 fixture ENOENT; no historical inference')
    C.need(rows[0]['observed_monotonic_ns']<=rows[1]['observed_monotonic_ns'],'ordered actual fixture observations')
    return rows

def validate_retained_failed_staged_observation(value,*,retained_failed_staged_value=None):
    retained=retained_failed_staged()if retained_failed_staged_value is None else retained_failed_staged_value
    C.need(type(value)is dict and set(value)=={'schema','binding','proof_originals','fixture_absence_observations',
        'component_role_identities','native_case_credit','native_terminal','global_unknown_effect_count',
        'original_remote_cleanup_boolean','historical_gate_failure_cause','past_failure_offender_identified',
        'current_kernel_ESRCH_asserted'}
        and value['schema']=='hepta.r9.retained-staged-observation.v1'
        and value['binding']==retained['retained_failed_staged_binding']
        and value['proof_originals']==[RETAINED_FAILED_STAGED_PHONE,RETAINED_FAILED_STAGED_ARCHIVE,RETAINED_FAILED_STAGED_READER]
        and value['component_role_identities']=={} and type(value['native_case_credit'])is int and value['native_case_credit']==0
        and value['native_terminal']is None and value['global_unknown_effect_count']is None
        and value['original_remote_cleanup_boolean']is False and value['historical_gate_failure_cause']=='UNKNOWN'
        and value['past_failure_offender_identified']is False and value['current_kernel_ESRCH_asserted']is False,
        'retained R8 observation preserves the zero-role failure and all original unknowns')
    validate_retained_failed_staged_fixture_observations(value['fixture_absence_observations'],retained_failed_staged_value=retained)
    return value

def validate_r10_prior_selection(boundary,original_inventory,selected,selected_pin,selection,*,next_case):
    require_r10_retained_transport()
    inventory_value(original_inventory);inventory_value(selected)
    r7=retained_preaccept();r8=retained_failed_staged();r9=retained_failed_transport();record=reviewed_source_parent_records()[0]
    C.need(SOURCE_PARENT_INVENTORY_ROOT_COUNT==44 and len(record['roots'])==44
           and r7['original_native_predecessor']==r8['original_native_predecessor']==record['boundary']
           and len(r7['private_roots'])==3 and len(r8['private_roots'])==2
           and set(record['roots']).isdisjoint(r7['private_roots'])
           and set(r7['inventory_roots']).isdisjoint(r8['private_roots'])
           and set(record['roots'])|set(r7['private_roots'])==set(r7['inventory_roots'])
           and set(r7['inventory_roots'])|set(r8['private_roots'])==set(r8['inventory_roots']),
           'actual native44 plus exact separately verified R7 three and R8 two roots')
    preserve_retained_preaccept(selected,retained_preaccept_value=r7)
    preserve_retained_failed_staged(selected,retained_failed_staged_value=r8)
    preserve_retained_failed_transport(selected,retained_failed_transport_value=r9)
    if is_source_parent_ancestor(boundary):
        C.need(next_case=='NEG-01'and len(original_inventory['roots'])==44
               and C.descriptor(C.encoded(original_inventory))=={k:record['inventory'][k]for k in ('bytes','sha256')}
               and selected_pin==r9['inventory']and C.descriptor(C.encoded(selected))==r9['inventory']
               and all(selected['entries'].get(k)==v for k,v in original_inventory['entries'].items())
               and selection=='exact_source_parent44_plus_retained_failed_r7_r8_r9_49'
               and len(selected['roots'])==49,
               'R10 NEG01 requires actual native44 original and independently retained49')
        return 49
    current_retained_preaccept_binding(boundary,retained_preaccept_value=r7)
    current_retained_failed_staged_binding(boundary,retained_failed_staged_value=r8)
    current_retained_failed_transport_binding(boundary,retained_failed_transport_value=r9)
    C.need(next_case=='NEG-02'and boundary['case_id']=='NEG-01'
           and len(original_inventory['roots'])==len(selected['roots'])==52
           and original_inventory==selected and selected_pin==boundary['inventory']
           and selection=='current_r10_native_head_with_separate_retained_failed_r7_r8_r9',
           'R10 NEG02 requires its actual current NEG01 full52 predecessor')
    return 52

def r10_bound_private_roots(lease):
    require_r10_retained_transport()
    case=lease.get('case_id');label=lease.get('label');nonce=lease.get('nonce')
    C.need(case in ('NEG-01','NEG-02')and label=={'NEG-01':'root-r10-neg01-fc33-r10-bound01',
           'NEG-02':'root-r10-neg02-fc33-r10-bound01'}[case]
           and type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce)
           and nonce not in (RETAINED_PREACCEPT_BINDING['nonce'],RETAINED_FAILED_STAGED_BINDING['nonce'],'299483481a678cbd589aeba54ed8b68f'),
           'one exact new bound R10 case scope; all three failed nonces stay consumed')
    current_context(lease['combination']['sha256'],lease['package_sha256'])
    C.need(lease['boot_id']==RETAINED_FAILED_STAGED_BINDING['boot_id']
           and lease['android_journal']=='/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+label+'/executor',
           'same boot and exact current Android executor')
    return {C.BASE/'native-guard-r10-r1'/label,
        C.ANDROID/('data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+label+'/executor'),
        C.ANDROID/('data/local/tmp/hepta-native-guard-'+nonce)}

def r10_neg01_boundary_roots(boundary,*,retained_failed_staged_value):
    require_r10_retained_transport()
    r8=retained_failed_staged_value
    C.need(boundary.get('schema')==SCHEMA and boundary.get('state')==STATE
           and boundary.get('case_id')=='NEG-01'and boundary.get('boot_id')==r8['boot_id']
           and type(boundary.get('nonce'))is str and re.fullmatch('[0-9a-f]{32}',boundary['nonce'])
           and boundary['nonce']not in (r8['nonce'],RETAINED_PREACCEPT_BINDING['nonce'],'299483481a678cbd589aeba54ed8b68f')
           and boundary['prior_boundary']==r8['original_native_predecessor'],
           'the actual bound R10 NEG01 native predecessor family')
    current_context(boundary['combination_sha256'],boundary['package_sha256'])
    current_retained_failed_staged_binding(boundary,retained_failed_staged_value=r8)
    C.need(boundary.get('retained_failed_transport_binding')==retained_failed_transport_adapter().binding,
           'current R10 NEG01 retains exactly the separately verified R9 failed transport')
    C.need(boundary.get('retained_preaccept_binding')==RETAINED_PREACCEPT_BINDING
           and boundary.get('publisher_source_sha256')==reviewed_source_sha256()
           and boundary.get('component_qualified')is True and boundary.get('native_status')=='completed'
           and boundary.get('actual_native_calls')==2,
           'complete current R10 NEG01 success and both retained bindings are required')
    label='root-r10-neg01-fc33-r10-bound01';nonce=boundary['nonce']
    extra={C.BASE/'native-guard-r10-r1'/label,
        C.ANDROID/('data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+label+'/executor'),
        C.ANDROID/('data/local/tmp/hepta-native-guard-'+nonce)}
    roots=set(map(Path,r8['inventory_roots']))|extra
    C.need(len(roots)==52 and len(boundary['roots'])==52 and set(map(Path,boundary['roots']))==roots,
           'actual retained49 plus exactly this completed R10 NEG01 three roots')
    return roots

def retained_failed_staged_inventory(roots,*,fixture_roots,current_lease=None,prior_boundary=None):
    """Original scanner14/30s/512MiB; R7 absent root and R8 absent non-root are typed."""
    require_r10_retained_transport()
    import time
    import component_lifecycle as LIFE
    started=time.monotonic()
    r7=retained_preaccept();r8=retained_failed_staged();r9=retained_failed_transport()
    before9=fresh_retained_failed_transport_absence(deadline=started+30)
    selected=list(map(Path,roots));fixtures=list(map(Path,fixture_roots))
    old=set(map(Path,r8['inventory_roots']));r7_fixture=Path(retained_preaccept_reader().FIXTURE)
    C.need(len(selected)==len(set(selected))and len(selected)in (49,52,55)
           and len(fixtures)==len(set(fixtures))and len(fixtures)<=15
           and r7_fixture in selected and r7_fixture in fixtures
           and r7['inventory_value']['entries'].get(str(r7_fixture))=={'kind':'absent','absence':'ENOENT'}
           and Path(r8['separate_absent_fixture']['path'])not in selected,
           'only exact typed R10 cumulative49/52/55 with separate absent fixtures')
    if len(selected)==49:
        C.need(set(selected)==old,'initial complete inventory is exactly the retained49')
        if prior_boundary is not None:
            record=reviewed_source_parent_records()[0]
            C.need(is_source_parent_ancestor(prior_boundary)
                   and C.descriptor(C.encoded(prior_boundary))=={k:record['boundary'][k]for k in ('bytes','sha256')},
                   'initial49 preserves the actual native44 predecessor identity')
    elif prior_boundary is not None:
        C.need(len(selected)==52 and type(current_lease)is dict and current_lease.get('case_id')=='NEG-02',
               'only exact R10 NEG02 admission may scan its actual NEG01 full52')
        r10_bound_private_roots(current_lease)
        C.need(set(selected)==r10_neg01_boundary_roots(prior_boundary,retained_failed_staged_value=r8)
               and current_lease['prior_boundary']['sha256']==C.sha(C.encoded(prior_boundary)),
               'actual complete published R10 NEG01 predecessor is the selected52')
    else:
        C.need(type(current_lease)is dict,'new current roots require the actual bound R9 lease')
        extra=r10_bound_private_roots(current_lease)
        if current_lease['case_id']=='NEG-01':
            C.need(len(selected)==52 and current_lease['prior_boundary']==r8['original_native_predecessor']
                   and set(selected)==old|extra,'R10 NEG01 captures exactly49 plus its own3')
        else:
            C.need(len(selected)==55,'55 roots are reserved for actual bound R10 NEG02')
            raw=original(current_lease['prior_boundary']);previous=C.strict(raw)
            previous_roots=r10_neg01_boundary_roots(previous,retained_failed_staged_value=r8)
            C.need(set(selected)==previous_roots|extra and len(previous_roots|extra)==55,
                   'R10 NEG02 captures the actual first52 plus exactly its own3')
    C.need(fixtures==[p for p in selected if re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',str(p))],
           'complete ordered fixture root census')
    first7=LIFE.fixture_absence(r7_fixture)
    first8=fresh_retained_failed_staged_fixture_absence(retained_failed_staged_value=r8)
    observed=LIFE.inventory([p for p in selected if p!=r7_fixture],fixture_roots=[p for p in fixtures if p!=r7_fixture])
    last7=LIFE.fixture_absence(r7_fixture)
    last8=fresh_retained_failed_staged_fixture_absence(retained_failed_staged_value=r8)
    C.need(first7['path']==last7['path']==str(r7_fixture)and first7['absence']==last7['absence']=='ENOENT'
           and first7['canonical_parent_identity']==last7['canonical_parent_identity'],
           'retained R7 fixture appeared or canonical parent changed')
    validate_retained_failed_staged_fixture_observations([first8,last8],retained_failed_staged_value=r8)
    C.need(str(r7_fixture)not in observed['entries'],'R7 absent fixture was independently observed')
    observed['roots']=list(map(str,selected));observed['entries'][str(r7_fixture)]={'kind':'absent','absence':'ENOENT'}
    inventory_value(observed)
    preserve_retained_preaccept(observed,retained_preaccept_value=r7)
    preserve_retained_failed_staged(observed,retained_failed_staged_value=r8)
    preserve_retained_failed_transport(observed,retained_failed_transport_value=r9)
    validate_retained_failed_transport_absence([before9,fresh_retained_failed_transport_absence(deadline=started+30)],
        retained_failed_transport_value=r9)
    observed['elapsed_seconds']=time.monotonic()-started
    C.need(observed['elapsed_seconds']<30 and len(observed['entries'])<=30000
           and observed['file_bytes_hashed']<=512*1024*1024,
           'whole typed inventory remains inside the unchanged total time/count/byte limits')
    return observed

def retained_failed_staged_external_originals():
    """Phone-only full9 bookends for the fixed R8 source/proof and its exact R7 input."""
    result=[]
    rows=[RETAINED_PREACCEPT_PHONE,RETAINED_PREACCEPT_ARCHIVE,
          RETAINED_FAILED_STAGED_PHONE,RETAINED_FAILED_STAGED_ARCHIVE,RETAINED_FAILED_STAGED_READER]
    for expected in rows:
        path=Path(expected['path']);before=C.metadata(path.lstat())
        reader=retained_preaccept_read_pinned if expected in rows[:2]else retained_failed_staged_read_pinned
        raw=reader(expected);row=describe(path,raw)
        C.need(row['metadata']==before
               and {k:row[k]for k in('path','bytes','sha256')}==expected,
               'same complete external proof/source generation before late admission')
        result.append(row)
    return result


# R10 independent uncompressed source; all large actual R9 pins live in that source.
RETAINED_FAILED_TRANSPORT_ADAPTER={'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-runtime-dependencies-r10-r1/fc33-r10-01/retained_transport_r9_adapter.py', 'bytes': 23623, 'sha256': 'eaf52438100706edb6734efea64299f6ff1b414485c2c353c9172f7c6f670857'}
RETAINED_FAILED_TRANSPORT_HOST_ADAPTER={'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r10/dependencies/runtime/retained_transport_r9_adapter.py', 'bytes': 23623, 'sha256': 'eaf52438100706edb6734efea64299f6ff1b414485c2c353c9172f7c6f670857'}
RETAINED_FAILED_TRANSPORT_INPUTS_SHA256='05b024024f8ab96f4a551af441fcd1b196f0c4401bbff6f3b92d46b4ec3376d4'

def require_retained_failed_transport_sources():
    rows=(RETAINED_FAILED_TRANSPORT_ADAPTER,RETAINED_FAILED_TRANSPORT_HOST_ADAPTER)
    C.need(all(type(r)is dict and set(r)=={'path','bytes','sha256'}for r in rows)
           and type(RETAINED_FAILED_TRANSPORT_INPUTS_SHA256)is str
           and C.HASH.fullmatch(RETAINED_FAILED_TRANSPORT_INPUTS_SHA256),
           'bind complete exact R9 proof inputs and separate R10 source before any read')
    C.need(all(type(r['path'])is str and Path(r['path']).is_absolute()
           and type(r['bytes'])is int and 0<r['bytes']<=32768
           and type(r['sha256'])is str and C.HASH.fullmatch(r['sha256'])for r in rows)
           and all(rows[0][k]==rows[1][k]for k in ('bytes','sha256')),
           'one bounded exact uncompressed source in two explicit dependency namespaces')

def retained_failed_transport_adapter(*,host_read_pinned=None):
    import types
    require_retained_failed_transport_sources()
    row=RETAINED_FAILED_TRANSPORT_ADAPTER
    if host_read_pinned is not None:
        C.need(callable(host_read_pinned),'bounded exact original host adapter reader')
        raw=host_read_pinned(RETAINED_FAILED_TRANSPORT_HOST_ADAPTER)
    else:
        hook=globals().get('__retained_failed_transport_adapter_read_pinned__')
        if hook is not None:
            C.need(callable(hook),'explicit pinned runtime dependency reader');raw=hook(row)
        else:
            path=Path(row['path']);before=C.metadata(path.lstat());raw=C.read(path,32768)
            C.need(before==C.metadata(path.lstat()),'same runtime dependency source full9')
    C.need(type(raw)is bytes and C.descriptor(raw)=={k:row[k]for k in ('bytes','sha256')},
           'complete fixed uncompressed adapter source pin')
    mod=types.ModuleType('fixed_runtime_retained_transport_adapter')
    mod.__file__=row['path'];exec(compile(raw,mod.__file__,'exec'),mod.__dict__)
    return mod.Adapter(common=C,expected_inputs_sha256=RETAINED_FAILED_TRANSPORT_INPUTS_SHA256,
        adapter_source=row,prior={
            'preaccept_archive':RETAINED_PREACCEPT_ARCHIVE,'staged_phone':RETAINED_FAILED_STAGED_PHONE,
            'staged_archive':RETAINED_FAILED_STAGED_ARCHIVE,'staged_reader':RETAINED_FAILED_STAGED_READER,
            'preaccept_binding':RETAINED_PREACCEPT_BINDING,'staged_binding':RETAINED_FAILED_STAGED_BINDING},
        old_read_pinned=retained_failed_staged_read_pinned,inventory_reader=inventory_value,
        supplied=globals().get('__retained_failed_transport_read_pinned__'))

def retained_failed_transport_sources():
    return retained_failed_transport_adapter().proof

def install_retained_failed_transport_host_reader(read_pinned):
    adapter=retained_failed_transport_adapter(host_read_pinned=read_pinned)
    def source(row):
        C.need(row==RETAINED_FAILED_TRANSPORT_ADAPTER,'one exact external runtime dependency')
        raw=read_pinned(RETAINED_FAILED_TRANSPORT_HOST_ADAPTER)
        C.need(C.descriptor(raw)=={k:row[k]for k in ('bytes','sha256')},'same host adapter source')
        return raw
    supplied=adapter.host_reader(read_pinned)
    globals()['__retained_failed_transport_adapter_read_pinned__']=source
    globals()['__retained_failed_transport_read_pinned__']=supplied

def retained_failed_transport_read_pinned(row):
    return retained_failed_transport_adapter().read_pinned(row)

def retained_failed_transport_reader():
    return retained_failed_transport_adapter().reader()

def retained_failed_transport():
    return retained_failed_transport_adapter().verify()

def current_retained_failed_transport_binding(value,*,retained_failed_transport_value=None):
    return retained_failed_transport_adapter().current_binding(value,retained_failed_transport_value=retained_failed_transport_value)

def preserve_retained_failed_transport(inventory,*,retained_failed_transport_value=None):
    return retained_failed_transport_adapter().preserve(inventory,retained_failed_transport_value=retained_failed_transport_value)

def fresh_retained_failed_transport_absence(*,deadline):
    return retained_failed_transport_adapter().fresh_absence(deadline=deadline)

def validate_retained_failed_transport_absence(observations,*,retained_failed_transport_value=None):
    return retained_failed_transport_adapter().validate_absence(observations,retained_failed_transport_value=retained_failed_transport_value)

def validate_retained_failed_transport_observation(value,*,retained_failed_transport_value=None):
    return retained_failed_transport_adapter().validate_observation(value,retained_failed_transport_value=retained_failed_transport_value)

def retained_failed_transport_external_originals():
    require_retained_failed_transport_sources()
    row=RETAINED_FAILED_TRANSPORT_ADAPTER;path=Path(row['path'])
    before=C.metadata(path.lstat());adapter=retained_failed_transport_adapter()
    C.need(before==C.metadata(path.lstat()),'runtime dependency source full9 changed')
    return adapter.external_originals()+[dict(row,metadata=before)]

def require_r10_retained_transport():
    require_retained_failed_transport_sources()

if __name__ == '__main__':
    raise SystemExit(main())

