#!/usr/bin/env python3
"""Read-only cumulative component boundary verification, plus explicit publish.

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
MAX_CHAIN = 8
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
    C.need(isinstance(value, dict) and set(value) == FIELDS
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
REVIEWED_CURRENT_COMBINATION_SHA256='7616a1995a9bc346924db48560ff5b2d5de3b6b7836817c1674bedd1e723cfd0'
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
REVIEWED_CURRENT_POLICY_SHA256='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
REVIEWED_CURRENT_POLICY_ADOPTION_SHA256='527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'


def require_current_revision():
    for name, value, previous in (
            ('combination', REVIEWED_CURRENT_COMBINATION_SHA256, PROPERTY_PARENT_COMBINATION_SHA256),
            ('policy', REVIEWED_CURRENT_POLICY_SHA256, PROPERTY_PARENT_POLICY_SHA256),
            ('adoption', REVIEWED_CURRENT_POLICY_ADOPTION_SHA256, PROPERTY_PARENT_ADOPTION_SHA256)):
        C.need(isinstance(value, str) and C.HASH.fullmatch(value) and value != previous,
               'new current '+name+' has not been explicitly frozen and adopted')
    C.need(REVIEWED_CURRENT_COMBINATION_SHA256 != LEGACY_COMBINATION_SHA256,
           'a retained historical combination cannot become the current revision')
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
    C.need(combination_sha256 == REVIEWED_CURRENT_COMBINATION_SHA256
           and isinstance(package_sha256, str) and C.HASH.fullmatch(package_sha256)
           and package_sha256 not in (PROPERTY_PARENT_PACKAGE_SHA256,
               POLICY_PARENT_PACKAGE_SHA256, LEGACY_PACKAGE_SHA256,
               ENVIRONMENT_PARENT_PACKAGE_SHA256, CODEC_PARENT_PACKAGE_SHA256),
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



# Exact previous-generation source and original records. These are references
# to existing originals, not a replacement historical publication or main.
CODEC_PARENT_PACKAGE_SHA256 = '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'
CODEC_PARENT_COMBINATION_SHA256 = '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'
CODEC_PARENT_READER_SHA256 = '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'
CODEC_PARENT_CLOSURE_SHA256 = '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'
CODEC_PARENT_NONCE = '902e851c3ca1f90deab3d880ab993774'
CODEC_PARENT_RECORD = {'boundary': {'bytes': 9686, 'metadata': [65086, 156280, 33152, 0, 0, 1, 9686, 1793882486435914270, 1793882486435914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774.json', 'sha256': '6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'}, 'inventory': {'bytes': 923078, 'metadata': [65086, 156601, 33152, 0, 0, 1, 923078, 1793882485267914270, 1793882485267914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774/AFTER-INVENTORY.original.json', 'sha256': 'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d'}, 'closure': {'bytes': 55124, 'metadata': [65086, 156890, 33152, 0, 0, 1, 55124, 1793882485259914270, 1793882485259914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774/CLOSURE.original.json', 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'}}
CODEC_PARENT_READSET = [{'bytes': 16808, 'metadata': [65086, 155722, 33152, 0, 0, 1, 16808, 1793878948699915619, 1793878948699915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/MANIFEST.json', 'sha256': '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'}, {'bytes': 1438, 'metadata': [65086, 155556, 33152, 0, 0, 1, 1438, 1793878948703915619, 1793878948703915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/REVIEWED-PRODUCTION-PINS.json', 'sha256': '73963fdcea527cdbc3628bdeff5918f7106afbaf095fb183e4b199391e46a7a5'}, {'bytes': 664638, 'metadata': [65086, 151407, 33152, 0, 0, 1, 664638, 1793878948707915619, 1793878948707915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/attempt05-AFTER-INVENTORY.original.json', 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}, {'bytes': 164095, 'metadata': [65086, 157093, 33152, 0, 0, 1, 164095, 1793878948711915619, 1793878948711915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/attempt05-CLOSURE.original.json', 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, {'bytes': 4650, 'metadata': [65086, 157359, 33152, 0, 0, 1, 4650, 1793878948723915619, 1793878948723915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/attempt05-SIDE-PROOF.original.json', 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, {'bytes': 18133, 'metadata': [65086, 154681, 33152, 0, 0, 1, 18133, 1793878948723915619, 1793878948723915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/component_common_r5.py', 'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'}, {'bytes': 13238, 'metadata': [65086, 148588, 33152, 0, 0, 1, 13238, 1793878948723915619, 1793878948723915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/component_core.py', 'sha256': '705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'}, {'bytes': 30647, 'metadata': [65086, 157422, 33152, 0, 0, 1, 30647, 1793878948723915619, 1793878948723915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/component_once_r9.py', 'sha256': '1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'}, {'bytes': 4116, 'metadata': [65086, 156249, 33152, 0, 0, 1, 4116, 1793878948727915619, 1793878948727915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/decode_client_state.py', 'sha256': 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'}, {'bytes': 53502, 'metadata': [65086, 155143, 33152, 0, 0, 1, 53502, 1793878948727915619, 1793878948727915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/environment_parent_late_boundary_r6.py', 'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'}, {'bytes': 28109, 'metadata': [65086, 155278, 33152, 0, 0, 1, 28109, 1793878948727915619, 1793878948727915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/native_guard_session.py', 'sha256': '77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b'}, {'bytes': 6701, 'metadata': [65086, 155476, 33152, 0, 0, 1, 6701, 1793878948727915619, 1793878948727915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/native_journal_audit.py', 'sha256': 'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'}, {'bytes': 19740, 'metadata': [65086, 156732, 33152, 0, 0, 1, 19740, 1793878948731915619, 1793878948731915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/non_native_attempt05.py', 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}, {'bytes': 35730, 'metadata': [65086, 157722, 33152, 0, 0, 1, 35730, 1793878948731915619, 1793878948731915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/policy_parent_late_boundary_r4.py', 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'}, {'bytes': 62434, 'metadata': [65086, 157486, 33152, 0, 0, 1, 62434, 1793878948731915619, 1793878948731915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/property_parent_late_boundary_r7.py', 'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'}, {'bytes': 40788, 'metadata': [65086, 153747, 33152, 0, 0, 1, 40788, 1793878948731915619, 1793878948731915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/send_new_native_task_r5.py', 'sha256': '5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}, {'bytes': 17390, 'metadata': [65086, 155049, 33152, 0, 0, 1, 17390, 1793878948731915619, 1793878948731915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/reference/tool_client_r6.py', 'sha256': '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'}, {'bytes': 99120, 'metadata': [65086, 157373, 33152, 0, 0, 1, 99120, 1793878948735915619, 1793878948735915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/close_component.py', 'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'}, {'bytes': 19138, 'metadata': [65086, 155521, 33152, 0, 0, 1, 19138, 1793878948735915619, 1793878948735915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/component_common.py', 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, {'bytes': 40261, 'metadata': [65086, 151651, 33152, 0, 0, 1, 40261, 1793878948735915619, 1793878948735915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/component_lifecycle.py', 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, {'bytes': 38823, 'metadata': [65086, 156231, 33152, 0, 0, 1, 38823, 1793878948739915619, 1793878948739915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/component_listener.py', 'sha256': 'ad345c0080cbfd89f1378bb6e8583f43e1fa4af0a5928d7ecbf4ccc8d4f04c52'}, {'bytes': 24187, 'metadata': [65086, 157625, 33152, 0, 0, 1, 24187, 1793878948739915619, 1793878948739915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/component_snapshot.py', 'sha256': '2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa'}, {'bytes': 74287, 'metadata': [65086, 154341, 33152, 0, 0, 1, 74287, 1793878948739915619, 1793878948739915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/late_boundary.py', 'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}, {'bytes': 28878, 'metadata': [65086, 156951, 33152, 0, 0, 1, 28878, 1793878948739915619, 1793878948739915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/native_guard_session_r2.py', 'sha256': '5fe50be4dccbe655a39124876d1f9c2199de20d80ec0a84f08a63d88e7f1a931'}, {'bytes': 4633, 'metadata': [65086, 154657, 33152, 0, 0, 1, 4633, 1793878948743915619, 1793878948743915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/native_proc_profile.py', 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, {'bytes': 14259, 'metadata': [65086, 154762, 33152, 0, 0, 1, 14259, 1793878948743915619, 1793878948743915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/prepare_component.py', 'sha256': '46a28fd77dc64d94ccdd4c1f3e12912e22ebb39defc29b69991df831d75afc7d'}, {'bytes': 18728, 'metadata': [65086, 154801, 33152, 0, 0, 1, 18728, 1793878948743915619, 1793878948743915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/root_fixture_once.py', 'sha256': 'bb70017c4f184efc0c9372ab072fa2d11a1cf7cbd3276257fa7b3605a426e0d1'}, {'bytes': 39149, 'metadata': [65086, 156369, 33152, 0, 0, 1, 39149, 1793878948743915619, 1793878948743915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/root_fixture_originals.py', 'sha256': 'c1cd1402888de5bc4176255269014995e9d39dc658912d3c28a117ec51010f9e'}, {'bytes': 10498, 'metadata': [65086, 155015, 33152, 0, 0, 1, 10498, 1793878948747915619, 1793878948747915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/run_root_fixture_phase.py', 'sha256': 'bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2'}, {'bytes': 40952, 'metadata': [65086, 150663, 33152, 0, 0, 1, 40952, 1793878948747915619, 1793878948747915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/send_new_native_guard_task_r10_r4.py', 'sha256': 'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad'}, {'bytes': 18666, 'metadata': [65086, 156927, 33152, 0, 0, 1, 18666, 1793878948747915619, 1793878948747915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/sender_native_guard_ready_r10_r4.py', 'sha256': 'f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99'}, {'bytes': 19116, 'metadata': [65086, 142992, 33152, 0, 0, 1, 19116, 1793878948747915619, 1793878948747915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/stage_component.py', 'sha256': '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340'}, {'bytes': 18137, 'metadata': [65086, 155671, 33152, 0, 0, 1, 18137, 1793878948751915619, 1793878948751915619], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package/source/witness_bundle.py', 'sha256': 'f949ae3d6cec26bf98448fd0ac20b1f46472190be022d6532b1973177e0edfca'}]
CODEC_PARENT_PACKAGE_PATHS = {'phone': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/package', 'mac': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime', 'p4': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package'}


def reviewed_codec_parent_ancestor():
    record = CODEC_PARENT_RECORD
    C.need(type(record) is dict and set(record) == {'boundary', 'inventory', 'closure'},
           'one exact previous codec-generation record is required')
    exact_descriptor(record['boundary'], expected_path=ROOT/(CODEC_PARENT_NONCE+'.json'))
    for key, name in (('inventory', 'AFTER-INVENTORY.original.json'),
                      ('closure', 'CLOSURE.original.json')):
        exact_descriptor(record[key], expected_path=ROOT/CODEC_PARENT_NONCE/name)
    C.need(record['boundary']['bytes'] == 9686
           and record['boundary']['sha256'] == '6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'
           and record['closure']['bytes'] == 55124
           and record['closure']['sha256'] == 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'
           and record['inventory']['bytes'] == 923078
           and record['inventory']['sha256'] == 'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d',
           'previous codec-generation fixed originals differ')
    return record


def is_codec_parent_ancestor(value):
    return (type(value) is dict and C.descriptor(C.encoded(value))
            == {k: reviewed_codec_parent_ancestor()['boundary'][k] for k in ('bytes', 'sha256')})


def _codec_parent_original(raw, original_descriptor):
    record = reviewed_codec_parent_ancestor()
    if C.descriptor(raw) == {k: record['boundary'][k] for k in ('bytes', 'sha256')}:
        C.need(C.encoded(original_descriptor) == C.encoded(record['boundary']),
               'previous codec-generation full original identity differs')
        return record
    return None


def _codec_parent_directory(path):
    parent, name = C.parent_fd(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = C.metadata(os.fstat(fd))
            names = sorted(os.listdir(fd))
            C.need(before == C.metadata(os.fstat(fd))
                   == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                   'previous codec-generation source directory changed')
            return {'path': str(path), 'metadata': before, 'names': names}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _codec_parent_read(path, pin, private, expected_metadata=None):
    # O_NONBLOCK closes the stat-to-open FIFO race before a regular-file check.
    # A received original is still required to be the same held and named inode.
    C.need(type(pin) is dict and set(pin) == {'bytes', 'sha256'}
           and type(pin['bytes']) is int and 0 < pin['bytes'] <= 16*1024*1024
           and isinstance(pin['sha256'], str) and C.HASH.fullmatch(pin['sha256']),
           'bounded exact previous source pin required')
    parent, name = C.parent_fd(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            identity = C.metadata(before)
            C.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                   and before.st_size == pin['bytes'],
                   'previous source is not its bounded regular original')
            if private:
                C.need(before.st_uid == before.st_gid == 0
                       and stat.S_IMODE(before.st_mode) == 0o600
                       and expected_metadata is not None,
                       'private previous source metadata binding required')
            C.need(expected_metadata is None or identity == expected_metadata,
                   'previous source held identity differs before read')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(pin['bytes'] + 1)
            C.need(C.descriptor(raw) == pin
                   and identity == C.metadata(os.fstat(fd))
                       == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
                       == C.metadata(Path(path).lstat()),
                   'previous source bytes or held/canonical identity changed')
            return raw, identity
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _codec_parent_recheck(observed, directories, private, *, budget_check=None):
    for row in observed:
        if budget_check is not None: budget_check()
        _codec_parent_read(Path(row['path']), {k: row[k] for k in ('bytes', 'sha256')},
                           private, expected_metadata=row['metadata'])
    for row in directories:
        if budget_check is not None: budget_check()
        C.need(_codec_parent_directory(Path(row['path'])) == row,
               'previous codec-generation complete source set changed')


class ReadOnlyCodecParentReader:
    """Expose only unmodified original31da pure verification functions."""
    __slots__ = ('_methods', '_provenance', '_source_recheck')

    def __init__(self, methods, provenance, source_recheck):
        from types import MappingProxyType
        C.need(set(methods) == {'boundary_from_original', 'closed_boundary_originals',
                              'require_failed_ancestor_tail'}, 'exact previous reader API required')
        object.__setattr__(self, '_methods', MappingProxyType(dict(methods)))
        object.__setattr__(self, '_provenance', C.encoded(provenance))
        C.need(callable(source_recheck), 'owned actual-source bookend required')
        object.__setattr__(self, '_source_recheck', source_recheck)

    def __getattr__(self, name):
        try:
            return self._methods[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name, value):
        raise AttributeError('previous codec-generation reader is immutable')

    def provenance(self):
        return C.strict(self._provenance)

    def recheck_actual_sources(self):
        self._source_recheck()
        return self.provenance()


def codec_parent_reader(*, budget_check=None):
    """Read actual fixed old files, then compile their exact unchanged bytes.

    Explicit phone context selects the preserved old CASE_HOME/package and must
    retain all thirty-three historical file identities. Reviewed host loaders
    select their one explicit Mac or P4 original package. Host full9 values are
    freshly observed at those real paths; phone metadata is never substituted.
    No old main, publisher, live observation, or model/action entry is exposed.
    """
    import types
    context = C.epoch_actual_context(globals())
    C.need(C.epoch_actual_context(C.__dict__) == context,
           'previous reader/common actual context differs')
    C.need(budget_check is None or callable(budget_check), 'invalid enclosing source-read budget')
    if budget_check is not None: budget_check()
    C.need(type(CODEC_PARENT_PACKAGE_PATHS) is dict
           and set(CODEC_PARENT_PACKAGE_PATHS) == {'phone', 'mac', 'p4'},
           'fixed previous-generation package namespaces are required')
    package = Path(CODEC_PARENT_PACKAGE_PATHS[context])
    phone_package = Path(CODEC_PARENT_PACKAGE_PATHS['phone'])
    C.need(type(CODEC_PARENT_READSET) is list and len(CODEC_PARENT_READSET) == 33,
           'complete previous codec-generation package originals are required')
    originals = {}; observed = []; private = context == 'phone'
    for fixed in CODEC_PARENT_READSET:
        if budget_check is not None: budget_check()
        relative = Path(fixed['path']).relative_to(phone_package)
        C.need(str(relative) not in originals and not relative.is_absolute()
               and '..' not in relative.parts and 0 < fixed['bytes'] <= 16*1024*1024,
               'previous source relative path/size differs')
        path = package / relative
        raw, after = _codec_parent_read(path, {k: fixed[k] for k in ('bytes', 'sha256')},
            private, expected_metadata=fixed['metadata'] if private else None)
        originals[str(relative)] = raw
        observed.append({'path': str(path), **C.descriptor(raw), 'metadata': after})
    C.need(sum(len(raw) for raw in originals.values()) <= 16*1024*1024,
           'previous codec-generation source bytes exceed existing original budget')
    manifest_raw = originals.pop('MANIFEST.json')
    C.need(len(manifest_raw) == 16808 and C.sha(manifest_raw) == CODEC_PARENT_PACKAGE_SHA256,
           'actual previous codec-generation manifest differs')
    manifest = C.strict(manifest_raw)
    C.need(manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
           and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
           and len(manifest['files']) == 32 and len(originals) == 32
           and {r['path'] for r in manifest['files']} == set(originals),
           'actual previous codec-generation full32 member set differs')
    for row in manifest['files']:
        C.need(set(row) == {'path', 'bytes', 'sha256'}
               and C.descriptor(originals[row['path']]) == {k: row[k] for k in ('bytes', 'sha256')},
               'actual previous codec-generation member binding differs')
    expected_directories = {'.': ['MANIFEST.json', 'reference', 'source']}
    for name in ('reference', 'source'):
        expected_directories[name] = sorted(Path(key).name for key in originals if Path(key).parent == Path(name))
    C.need(all(len(Path(key).parts) == 2 and Path(key).parts[0] in ('reference', 'source') for key in originals),
           'previous package source topology changed')
    directories = []
    for name, names in expected_directories.items():
        if budget_check is not None: budget_check()
        row = _codec_parent_directory(package / name)
        C.need(row['names'] == sorted(names), 'previous source directory omitted or added a member')
        directories.append(row)
    present = 'component_common' in sys.modules
    saved = sys.modules.get('component_common')
    previous_path = list(sys.path)
    previous_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        old_common = types.ModuleType('component_common')
        old_common.__file__ = str(package/'source/component_common.py')
        old_common.__reviewed_source_sha256__ = C.sha(originals['source/component_common.py'])
        sys.modules['component_common'] = old_common
        exec(compile(originals['source/component_common.py'], old_common.__file__, 'exec'), old_common.__dict__)
        old = types.ModuleType('reviewed_codec_parent_late_boundary_31da')
        old.__file__ = str(package/'source/late_boundary.py')
        old.__reviewed_source_sha256__ = CODEC_PARENT_READER_SHA256
        old.__reviewed_package_sources__ = dict(originals)
        exec(compile(originals['source/late_boundary.py'], old.__file__, 'exec'), old.__dict__)
        C.need(C.sha(originals['source/late_boundary.py']) == CODEC_PARENT_READER_SHA256
               and old.reviewed_source_sha256() == CODEC_PARENT_READER_SHA256
               and old.REVIEWED_CURRENT_COMBINATION_SHA256 == CODEC_PARENT_COMBINATION_SHA256
               and old.REVIEWED_CURRENT_POLICY_SHA256 == REVIEWED_CURRENT_POLICY_SHA256
               and old.REVIEWED_CURRENT_POLICY_ADOPTION_SHA256 == REVIEWED_CURRENT_POLICY_ADOPTION_SHA256
               and old.property_parent_records() == property_parent_records()
               and old.REVIEWED_NON_NATIVE_ATTEMPT05 == REVIEWED_NON_NATIVE_ATTEMPT05,
               'previous actual reader changes its source, policy or historical originals')
        _codec_parent_recheck(observed, directories, private, budget_check=budget_check)
    finally:
        sys.path[:] = previous_path
        sys.dont_write_bytecode = previous_dwb
        if present:
            sys.modules['component_common'] = saved
        else:
            sys.modules.pop('component_common', None)
    def guarded(function):
        def call(*args, **kwargs):
            value = function(*args, **kwargs)
            _codec_parent_recheck(observed, directories, private, budget_check=budget_check)
            if budget_check is not None: budget_check()
            return value
        return call
    return ReadOnlyCodecParentReader({name: guarded(getattr(old, name)) for name in
        ('boundary_from_original', 'closed_boundary_originals', 'require_failed_ancestor_tail')},
        {'schema': 'hepta.native-guard.codec-parent-reader-provenance.v1',
         'context': context, 'package_path': str(package), 'package_sha256': CODEC_PARENT_PACKAGE_SHA256,
         'reader_sha256': CODEC_PARENT_READER_SHA256, 'actual_sources': observed,
         'actual_source_directories': directories, 'source_bytes_unchanged': True,
         'source_full9_is_actual_context_not_phone_substitution': True,
         'historical_main_called': False, 'historical_publication_called': False,
         'original31da_function_bodies_changed': False,
         'original31da_functions_rebound_after_exec': False,
         'original31da_admitted_loader_source_map_injected': True,
         'nested_reader_behavior_is_exact_original396d': True,
         'model_requests': 0, 'native_dispatches': 0},
        lambda: _codec_parent_recheck(observed, directories, private, budget_check=budget_check))


def boundary_from_original(raw, *, original_descriptor, combination_sha256, package_sha256):
    """Read one current original or one of five exact retained failed originals."""
    current_context(combination_sha256, package_sha256)
    C.need(type(raw) is bytes and 0 < len(raw) <= 16*1024*1024,
           'bounded original boundary bytes required')
    exact_descriptor(original_descriptor)
    C.need(C.descriptor(raw) == {k:original_descriptor[k] for k in ('bytes','sha256')},
           'boundary bytes differ from their actual original descriptor')
    codec_parent = _codec_parent_original(raw, original_descriptor)
    if codec_parent is not None:
        old = codec_parent_reader()
        value = old.boundary_from_original(raw, original_descriptor=original_descriptor,
            combination_sha256=CODEC_PARENT_COMBINATION_SHA256,
            package_sha256=CODEC_PARENT_PACKAGE_SHA256)
        C.need(is_codec_parent_ancestor(value)
               and value['nonce'] == CODEC_PARENT_NONCE
               and value['package_sha256'] == CODEC_PARENT_PACKAGE_SHA256
               and value['combination_sha256'] == CODEC_PARENT_COMBINATION_SHA256
               and value['publisher_source_sha256'] == CODEC_PARENT_READER_SHA256
               and value['closure'] == codec_parent['closure']
               and value['inventory'] == codec_parent['inventory']
               and value['prior_boundary'] == property_parent_records()[0]['boundary']
               and value['component_qualified'] is False and value['native_status'] == 'provider_failed'
               and type(value['actual_native_calls']) is int and value['actual_native_calls'] == 1,
               'fixed previous codec-generation failure was reinterpreted')
        return value
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
    C.need(checked['nonce'] not in (*PROPERTY_PARENT_NONCES, POLICY_PARENT_NONCE,
                                  LEGACY_NONCE, ENVIRONMENT_PARENT_NONCE, CODEC_PARENT_NONCE),
           'a historical nonce cannot be relabeled as current')
    return checked



def closed_boundary_originals(raw, inventory_raw, closure_raw, *, original_descriptor,
                             combination_sha256, package_sha256):
    value = boundary_from_original(raw, original_descriptor=original_descriptor,
        combination_sha256=combination_sha256, package_sha256=package_sha256)
    codec_parent = _codec_parent_original(raw, original_descriptor)
    if codec_parent is not None:
        old = codec_parent_reader()
        checked, inv, closed = old.closed_boundary_originals(raw, inventory_raw, closure_raw,
            original_descriptor=original_descriptor,
            combination_sha256=CODEC_PARENT_COMBINATION_SHA256,
            package_sha256=CODEC_PARENT_PACKAGE_SHA256)
        C.need(checked == value and C.descriptor(closure_raw)
                   == {k: codec_parent['closure'][k] for k in ('bytes', 'sha256')}
               and C.descriptor(inventory_raw)
                   == {k: codec_parent['inventory'][k] for k in ('bytes', 'sha256')}
               and closed.get('closure_source_sha256') == CODEC_PARENT_CLOSURE_SHA256
               and closed.get('state') == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
               and closed.get('component_qualified') is False
               and closed.get('native_status') == 'provider_failed'
               and type(closed.get('actual_native_calls')) is int and closed['actual_native_calls'] == 1
               and type(closed.get('unknown_effects')) is int and closed['unknown_effects'] == 0,
               'fixed previous codec-generation closure origin or failure semantics differ')
        return checked, inv, closed
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
    return value, inv, closed



def require_failed_ancestor_tail(values):
    records = property_parent_records()
    C.need(isinstance(values, list) and 6 <= len(values) <= MAX_CHAIN,
           'the complete chain must retain exact902 then08 then07 then06 then04 then03')
    old = property_parent_reader()
    originals = []
    for value, record in zip(values[-5:], records):
        raw = C.encoded(value)
        C.need(C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')},
               'fixed property-parent tail was omitted, reordered, altered or duplicated')
        originals.append(old.boundary_from_original(raw,
            original_descriptor=record['boundary'],
            combination_sha256=PROPERTY_PARENT_COMBINATION_SHA256,
            package_sha256=PROPERTY_PARENT_PACKAGE_SHA256))
    old.require_failed_ancestor_tail(originals)
    C.need([v['actual_native_calls'] for v in originals] == [1,0,1,1,0]
           and all(v['component_qualified'] is False and v['native_status'] == 'provider_failed'
                   for v in originals),
           'historical failed-case qualification or native call accounting differs')
    for index in range(4):
        C.need(originals[index]['prior_boundary'] == records[index+1]['boundary'],
               'fixed historical full original predecessor identity differs')
    seen_nonce = set(); seen_scope = set(); current_package = None
    for index, value in enumerate(values):
        key = tuple(value['scope'][name] for name in C.SCOPE)
        C.need(value['nonce'] not in seen_nonce and key not in seen_scope,
               'closed boundary repeats a nonce or native scope')
        seen_nonce.add(value['nonce']); seen_scope.add(key)
        if index < len(values)-6:
            if current_package is None:
                current_package = value['package_sha256']
            C.need(value['package_sha256'] == current_package,
                   'current boundary prefix changes package generation')
            boundary_value(value, combination_sha256=REVIEWED_CURRENT_COMBINATION_SHA256,
                           package_sha256=current_package)
            following = values[index+1]; prior = value['prior_boundary']
            C.need(prior is not None
                   and prior['path'] == str(ROOT/(following['nonce']+'.json'))
                   and {k:prior[k] for k in ('bytes','sha256')} == C.descriptor(C.encoded(following)),
                   'current component prefix is not a complete continuous original chain')
            if index == len(values)-7:
                C.need(prior == reviewed_codec_parent_ancestor()['boundary'],
                       'current prefix must point at exact902 original identity')
        elif index == len(values)-6:
            C.need(is_codec_parent_ancestor(value),
                   'the exact902 failed predecessor is required once before the unchanged five-case tail')
            old = codec_parent_reader()
            checked = old.boundary_from_original(C.encoded(value),
                original_descriptor=reviewed_codec_parent_ancestor()['boundary'],
                combination_sha256=CODEC_PARENT_COMBINATION_SHA256,
                package_sha256=CODEC_PARENT_PACKAGE_SHA256)
            C.need(checked == value, 'old reader changed exact902 original')
            old.require_failed_ancestor_tail(values[index:])


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


def current_inventory(expected):
    import component_lifecycle as LIFE
    fixtures = [p for p in expected['roots'] if re.fullmatch(
        r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}', p)]
    observed = LIFE.inventory(expected['roots'], fixture_roots=fixtures)
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
            'verified': verified, 'verifier': verifier}


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
    C.need(lease.get('prior_boundary') is not None
           and lease.get('combination', {}).get('sha256') == combination_sha256
           and lease.get('package_sha256') == package_sha256, 'next lease late-boundary binding differs')
    C.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == lease['boot_id'],
           'boot changed since the closed component')
    chain, originals = chain_originals(lease['prior_boundary'], combination_sha256=combination_sha256,
        package_sha256=package_sha256, boot_id=lease['boot_id'], retirement=lease['retirement'])
    sidebranch = non_native_sidebranch(phone_originals=True)
    C.need(all(lease['nonce'] != row[0]['nonce'] for row in chain)
           and lease['nonce'] != sidebranch['binding']['nonce'], 'closed native/non-native nonce cannot be reused')
    _proof, roles = retired_originals(lease['retirement'], lease['boot_id'])
    for boundary, _inventory, _closure in chain:
        roles.extend(boundary['component_role_identities'].values())
    roles.extend(sidebranch['binding']['component_role_identities'].values())
    C.need(len({tuple(x) for x in roles}) == len(roles), 'closed role identities repeat')
    selected = effective_prior_inventory(chain[0][0], chain[0][1], sidebranch)
    observed = current_inventory(selected)
    preserve_non_native_private(observed, sidebranch)
    absence = [C.absent_groups(roles), C.absent_groups(roles)]
    from component_snapshot import endpoint_absence
    _tables, endpoints = endpoint_absence()
    recheck_originals(originals + list(lease['retirement'].values()) + sidebranch['originals'])
    initial = is_pre_policy_ancestor(chain[0][0])
    selected_pin = sidebranch['binding']['inventory'] if initial else chain[0][0]['inventory']
    return {'schema': 'hepta.native-guard.late-boundary-verification.v1',
        'state': 'EXACT_CLOSED_CUMULATIVE_ORIGINALS_UNCHANGED',
        'previous_boundary': lease['prior_boundary'], 'closed_components': len(chain),
        'inventory_sha256': selected_pin['sha256'], 'roots': observed['roots'],
        'inventory_selection': 'fixed_non_native_attempt05_after' if initial else 'current_native_head',
        'non_native_sidebranch': sidebranch['binding'],
        'entries': len(observed['entries']), 'file_bytes_hashed': observed['file_bytes_hashed'],
        'original_retirement_sha256': lease['retirement']['proof']['sha256'],
        'absence_observations': absence, 'endpoints': endpoints,
        'old_retirement_current_equality_claimed': False, 'original_retirement_rewritten': False,
        'phone_tool_calls': 0, 'model_requests': 0, 'signals': 0, 'writes': 0}


def publish(a):
    require_current_revision()
    import component_lifecycle as LIFE
    os.umask(0o077)
    home = C.private_dir(Path(a.lease)); lease, lease_raw = LIFE.load_lease(home, a.lease_sha256, require_live=False)
    current_context(lease['combination']['sha256'], lease['package_sha256'])
    C.need(lease['prior_boundary'] is not None, 'policy transition cannot restart the original chain')
    LIFE.native_root(lease['boot_id'])
    C.need(Path(__file__) == home/'package/source/late_boundary.py', 'publish must use staged pinned source')
    C.verify_package(home/'package/MANIFEST.json', lease['package_sha256'])
    raw = {}
    for key in ('closure', 'inventory'):
        p = Path(getattr(a, key)); body = C.read(p, 16*1024*1024)
        C.need(C.sha(body) == getattr(a, key+'_sha256'), 'approved host original pin differs: '+key)
        raw[key] = body
    closed, inv = C.strict(raw['closure']), C.strict(raw['inventory'])
    inventory_value(inv)
    sidebranch = non_native_sidebranch(phone_originals=True)
    preserve_non_native_private(inv, sidebranch)
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
        non_native_sidebranch=sidebranch['binding'],
        original_retirement_rewritten=False, business_qualified=False, model_requests=0,
        automatic_replay=False)
    # closure_matches checks the actual fields, independently of staged filenames.
    closure_matches(closed, base, raw['inventory'])
    _proof, roles = retired_originals(lease['retirement'], lease['boot_id'])
    prior_originals = []
    if lease['prior_boundary'] is not None:
        previous, prior_originals = chain_originals(lease['prior_boundary'],
            combination_sha256=base['combination_sha256'], package_sha256=base['package_sha256'],
            boot_id=base['boot_id'], retirement=base['retirement'])
        C.need(set(previous[0][0]['roots']) <= set(inv['roots']), 'new boundary omitted prior original roots')
        C.need(all(row[0]['nonce'] != base['nonce'] and row[0]['scope'] != base['scope'] for row in previous),
               'new boundary reuses a closed scope/nonce')
        for boundary, _i, _c in previous:
            roles.extend(boundary['component_role_identities'].values())
    roles.extend(base['component_role_identities'].values())
    roles.extend(sidebranch['binding']['component_role_identities'].values())
    C.need(len({tuple(x) for x in roles}) == len(roles), 'closed role identities repeat')
    current_inventory(inv)
    C.absent_groups(roles); C.absent_groups(roles)
    from component_snapshot import endpoint_absence
    endpoint_absence()
    recheck_originals(prior_originals + list(lease['retirement'].values()) + sidebranch['originals'])
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
    current_inventory(inv)
    recheck_originals(prior_originals + list(lease['retirement'].values()) + sidebranch['originals'])
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


# Appended to the current late_boundary.py. This is an explicit new reader
# adapter, not a replacement for the frozen original31da source or its globals.
# The protocol replay functions referenced below are mandatory separate gates.

def _epoch_captured_original(pin, manifest_index, originals_by_path):
    C._ep_pin(pin, original=True)
    C.need(pin['path'] in manifest_index['files']
           and C._ep_same(manifest_index['files'][pin['path']], pin),
           'an exact original was omitted or substituted in the epoch capture')
    raw = originals_by_path[pin['path']]
    C.need(type(raw) is bytes and C.descriptor(raw) ==
           {key:pin[key] for key in ('bytes','sha256')},
           'captured historical original bytes differ')
    return raw


def _epoch_retired_from_capture(retirement, boot_id, manifest_index, originals_by_path):
    # All semantic predicates below are the original retired_originals body.
    # The one I/O expression is explicitly replaced by the exact captured-byte
    # reader; the immutable original function remains byte-identical.
    C.need(isinstance(retirement, dict) and set(retirement) == {
        'proof', 'preflight', 'probe', 'bound_inputs', 'disabled_flag'}, 'retirement original set differs')
    out = C.BASE / 'module-retire-r9-r2-for-r10-r1-01'
    code = C.BASE / 'module-r10-r1-retirement-code-r1'
    paths = {'proof': out/'RETIREMENT.json', 'preflight': out/'PREFLIGHT.json',
             'probe': code/'retirement_probe.py', 'bound_inputs': code/'BOUND-INPUTS.json',
             'disabled_flag': C.ANDROID/'data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable'}
    C.need(all(retirement[key]['path'] == str(path) for key,path in paths.items()),
           'captured retirement is not at its exact original phone path')
    raw = {key: _epoch_captured_original(retirement[key], manifest_index, originals_by_path)
           for key in paths}
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


def _epoch_verified_legacy_context(lease, manifest, originals_by_path, verified, *, mode, budget_check):
    """Recheck all six original native records and the separate attempt05.

    Original31da is loaded from the actual explicitly selected phone/Mac/P4
    source location and guarded by complete byte/full9/directory bookends. Its
    unchanged pure functions verify the original records. Phone evidence is
    always read from the capture map with its actual phone full9; observing a
    host source file never substitutes host metadata for a phone original.

    This deliberately performs no current inventory, process, endpoint, policy
    or task operation. Those admission gates remain separate and mandatory.
    """
    C.need(callable(budget_check), 'the enclosing operation budget check is mandatory')
    budget_check()
    context = C.epoch_actual_context(globals())
    C.need(C.epoch_actual_context(C.__dict__) == context,
           'epoch legacy reader and common actual contexts differ')
    fixed = C.epoch_binding_value()
    C.need(mode in ('preclose','published'), 'explicit legacy protocol mode required')
    if mode=='published':
        C.need(lease is None,'published legacy frontier cannot fabricate a current lease')
        replayed=verify_epoch_publication_inputs(manifest,originals_by_path)
    else:
        C.epoch_lease_protocol_value(lease)
        replayed=verify_epoch_capture_inputs(lease,manifest,originals_by_path)
    C.need(C._ep_same(replayed, verified), 'epoch capture replay changed before legacy verification')
    index = C.epoch_manifest_value(manifest, originals_by_path, binding=fixed)
    legacy = verified['legacy']
    C._ep_exact(legacy, {'schema','boot_id','native_chain','retirement',
        'non_native_sidebranch','native_components','fixture_roots'},
        'complete separate legacy domain required')
    C.need(legacy['schema'] == 'hepta.native-guard.epoch-legacy-domain.v1'
           and legacy['boot_id'] == fixed['boot_id']
           and (lease is None or legacy['boot_id'] == lease['boot_id'])
           and type(legacy['native_components']) is int and legacy['native_components'] == 6
           and type(legacy['fixture_roots']) is int and legacy['fixture_roots'] == 7,
           'fixed legacy boot or domain counts differ')
    records = [reviewed_codec_parent_ancestor()] + property_parent_records()
    C.need(len(records) == 6 and C._ep_same(legacy['native_chain'], records),
           'legacy domain must retain exact902,08,07,06,04,03 once in order')
    expected_side = {key: REVIEWED_NON_NATIVE_ATTEMPT05[key]
                     for key in ('proof','closure','inventory')}
    C.need(C._ep_same(legacy['non_native_sidebranch'], expected_side)
           and (lease is None or C._ep_same(legacy['retirement'], lease['retirement'])),
           'legacy sidebranch or original retirement identity changed')

    old = codec_parent_reader(budget_check=budget_check)
    source_observation = old.provenance()
    C.need(source_observation['context'] == context
           and source_observation['package_sha256'] == CODEC_PARENT_PACKAGE_SHA256
           and source_observation['reader_sha256'] == CODEC_PARENT_READER_SHA256,
           'legacy semantic reader is not the actual fixed original31da source')
    rows = []; nonces = set(); scopes = set()
    for position,record in enumerate(records):
        budget_check()
        boundary_raw = _epoch_captured_original(record['boundary'], index, originals_by_path)
        inventory_raw = _epoch_captured_original(record['inventory'], index, originals_by_path)
        closure_raw = _epoch_captured_original(record['closure'], index, originals_by_path)
        value, inventory, closure = old.closed_boundary_originals(
            boundary_raw, inventory_raw, closure_raw, original_descriptor=record['boundary'],
            combination_sha256=CODEC_PARENT_COMBINATION_SHA256,
            package_sha256=CODEC_PARENT_PACKAGE_SHA256)
        C.need(value['boot_id'] == legacy['boot_id']
               and C._ep_same(value['retirement'], legacy['retirement'])
               and C._ep_same(value['inventory'], record['inventory'])
               and C._ep_same(value['closure'], record['closure']),
               'an original legacy closure changed boot, retirement or its full originals')
        expected_prior = None if position == len(records)-1 else records[position+1]['boundary']
        C.need(C._ep_same(value['prior_boundary'], expected_prior),
               'legacy predecessor order or exact full identity differs')
        semantic_scope = C._ep_scope(value['scope'])
        C.need(value['nonce'] not in nonces and semantic_scope not in scopes,
               'legacy records repeat an actual nonce or native scope')
        nonces.add(value['nonce']); scopes.add(semantic_scope)
        C.need(value['component_qualified'] is False and value['native_status'] == 'provider_failed'
               and closure['component_qualified'] is False,
               'a retained legacy failure was relabeled as a qualification')
        rows.append((value, inventory, closure))
        budget_check()
    old.require_failed_ancestor_tail([row[0] for row in rows])
    C.need([row[0]['actual_native_calls'] for row in rows] == [1,1,0,1,1,0],
           'legacy native action accounting differs from exact original failures')
    for later, earlier in zip(rows, rows[1:]):
        C.need(set(earlier[0]['roots']) <= set(later[0]['roots']),
               'a legacy boundary omitted an earlier cumulative original root')

    side = non_native_sidebranch(phone_originals=False)
    for key,pin in expected_side.items():
        C.need(_epoch_captured_original(pin, index, originals_by_path) == side['raw'][key],
               'actual captured attempt05 differs from the unchanged pure source reference')
    C.need(side['binding']['nonce'] not in nonces
           and C._ep_same(rows[0][0].get('non_native_sidebranch'), side['binding']),
           'legacy native head omitted or reused its separate non-native attempt')
    selected = effective_prior_inventory(rows[0][0], rows[0][1], side)
    C.need(C._ep_same(selected, rows[0][1]),
           'exact902 preservation must remain its original cumulative inventory')
    retired, roles = _epoch_retired_from_capture(legacy['retirement'], legacy['boot_id'],
                                                index, originals_by_path)
    for value,_inventory,_closure in rows:
        roles.extend(value['component_role_identities'].values())
    roles.extend(side['binding']['component_role_identities'].values())
    C.need(len(roles) == 25 and len({tuple(role) for role in roles}) == 25
           and all(type(role) is list and len(role) == 4
                   and all(type(number) is int and number > 1 for number in role)
                   for role in roles), 'exact legacy retired/native/non-native roles differ')
    C.need(set(fixed['legacy_nonces']) == nonces | {side['binding']['nonce']},
           'permanently forbidden historical nonce domain differs')
    # Close the actual-source observation interval after sidebranch/retirement
    # processing without repeating an already verified historical chain.
    old.recheck_actual_sources()
    budget_check()
    C.need(C._ep_same(old.provenance(), source_observation),
           'legacy source provenance object changed during semantic verification')
    semantic = {'schema':'hepta.native-guard.epoch-legacy-semantics.v1',
        'epoch_anchor':fixed['anchor'], 'boot_id':legacy['boot_id'],
        'native_chain':records, 'native_components':6, 'fixture_roots':7,
        'native_nonces':[row[0]['nonce'] for row in rows],
        'native_scopes':[row[0]['scope'] for row in rows],
        'native_call_counts':[row[0]['actual_native_calls'] for row in rows],
        'non_native_sidebranch':side['binding'], 'retirement':legacy['retirement'],
        'original_retired_role_identities':retired['original_role_identities'],
        'all_retired_role_identities':roles,
        'preservation_inventory_original':records[0]['inventory'],
        'original31da_package_sha256':CODEC_PARENT_PACKAGE_SHA256,
        'original31da_reader_sha256':CODEC_PARENT_READER_SHA256,
        'original_combination_sha256':CODEC_PARENT_COMBINATION_SHA256,
        'all_original_failures_retained':True, 'full_legacy_tail_verified':True,
        'sidebranch_semantics_verified_separately':True,
        'original_retirement_current_equality_claimed':False,
        'live_inventory_verified_here':False, 'role_absence_verified_here':False,
        'endpoints_verified_here':False, 'component_qualified':False,
        'business_qualified':False, 'native_boundary_created':False}
    return {'schema':'hepta.native-guard.epoch-legacy-semantic-proof.v1',
        'actual_context':context, 'source_observation':source_observation,
        'semantic':semantic}


def epoch_verified_legacy_context(lease,manifest,originals_by_path,verified,*,budget_check):
    return _epoch_verified_legacy_context(lease,manifest,originals_by_path,verified,
        mode='preclose',budget_check=budget_check)


def epoch_verified_legacy_frontier_context(manifest,originals_by_path,verified,*,budget_check):
    return _epoch_verified_legacy_context(None,manifest,originals_by_path,verified,
        mode='published',budget_check=budget_check)




def verify_epoch_phone_legacy_source_observation(value, manifest, originals_by_path, verified):
    """Pure verification of the phone source identities in a retained proof.

    The current host reader observes its own source location separately. This
    function never translates host metadata into phone metadata and never
    claims that validating a record itself executes those historical sources.
    """
    fields={'schema','context','package_path','package_sha256','reader_sha256',
        'actual_sources','actual_source_directories','source_bytes_unchanged',
        'source_full9_is_actual_context_not_phone_substitution','historical_main_called',
        'historical_publication_called','original31da_function_bodies_changed',
        'original31da_functions_rebound_after_exec',
        'original31da_admitted_loader_source_map_injected',
        'nested_reader_behavior_is_exact_original396d','model_requests','native_dispatches'}
    C._ep_exact(value,fields,'complete original phone legacy-source observation required')
    C.need(value['schema']=='hepta.native-guard.codec-parent-reader-provenance.v1'
           and value['context']=='phone'
           and value['package_path']==CODEC_PARENT_PACKAGE_PATHS['phone']
           and value['package_sha256']==CODEC_PARENT_PACKAGE_SHA256
           and value['reader_sha256']==CODEC_PARENT_READER_SHA256,
           'retained legacy source proof is not the fixed actual phone package')
    for key in ('source_bytes_unchanged','source_full9_is_actual_context_not_phone_substitution',
                'original31da_admitted_loader_source_map_injected',
                'nested_reader_behavior_is_exact_original396d'):
        C.need(value[key] is True,'phone source observation affirmative flag differs: '+key)
    for key in ('historical_main_called','historical_publication_called',
                'original31da_function_bodies_changed','original31da_functions_rebound_after_exec'):
        C.need(value[key] is False,'phone source observation has an unreviewed effect: '+key)
    for key in ('model_requests','native_dispatches'):
        C.need(type(value[key]) is int and value[key]==0,'phone source proof invents an effect count')
    C.need(C._ep_same(value['actual_sources'],CODEC_PARENT_READSET),
           'all thirty-three phone source bytes and full9 must remain exact')
    fixed=C.epoch_binding_value()
    index=C.epoch_manifest_value(manifest,originals_by_path,binding=fixed)
    legacy=verified['legacy']
    C.need(C._ep_same(legacy['native_chain'][0],reviewed_codec_parent_ancestor()),
           'phone source proof changed the original902 inventory authority')
    inventory=C.strict(_epoch_captured_original(
        legacy['native_chain'][0]['inventory'],index,originals_by_path))
    package=CODEC_PARENT_PACKAGE_PATHS['phone']
    expected=[]
    for suffix in ('','/reference','/source'):
        path=package+suffix
        row=inventory['entries'].get(path)
        C.need(type(row) is dict and row.get('kind')=='directory',
               'actual902 inventory lacks a complete original source directory')
        expected.append({'path':path,'metadata':row['metadata'],'names':row['names']})
    C.need(C._ep_same(value['actual_source_directories'],expected),
           'phone legacy package directory full9 or complete member names changed')
    for original in CODEC_PARENT_READSET:
        row=inventory['entries'].get(original['path'])
        C.need(type(row) is dict and row.get('kind')=='file'
               and C._ep_same({k:row[k] for k in ('bytes','sha256','metadata')},
                              {k:original[k] for k in ('bytes','sha256','metadata')}),
               'source-bound original phone identity differs from the retained902 inventory')
    return C.strict(C.encoded(value))


# Thin current-generation epoch API. Heavy structural replay stays in the
# existing prepare_component member; no additional runtime member is added.

def _epoch_prepare_api():
    import prepare_component as prepared
    import component_lifecycle as lifecycle
    context = C.epoch_actual_context(globals())
    C.need(C.epoch_actual_context(C.__dict__) == context
           and C.epoch_actual_context(prepared.__dict__) == context
           and C.epoch_actual_context(lifecycle.__dict__) == context,
           'explicit common/lifecycle/prepare/late actual contexts differ')
    raw = getattr(C, '__reviewed_package_manifest_raw__', None)
    C.need(type(raw) is bytes and globals().get('__reviewed_package_manifest_raw__') == raw
           and getattr(prepared, '__reviewed_package_manifest_raw__', None) == raw
           and getattr(lifecycle, '__reviewed_package_manifest_raw__', None) == raw,
           'secondary epoch loaders must preserve the same original runtime manifest bytes')
    return prepared


def verify_epoch_capture_inputs(lease, manifest, originals_by_path):
    return _epoch_prepare_api().epoch_verify_capture_protocol(lease, manifest,
        originals_by_path, inventory_validator=inventory_value)


def verify_epoch_publication_inputs(manifest, originals_by_path):
    return _epoch_prepare_api().epoch_verify_publication_protocol(manifest,
        originals_by_path, inventory_validator=inventory_value)


def build_epoch_inventory_spec(anchor, exactregistry, failureinputs):
    return _epoch_prepare_api().epoch_planned_inventory_from_protocol(
        anchor, exactregistry, failureinputs)


def epoch_capture_preservation_context(lease, verified, *, manifest, originals_by_path):
    return _epoch_prepare_api().epoch_preservation_context_from_protocol(lease, verified,
        manifest=manifest, originals_by_path=originals_by_path, inventory_validator=inventory_value)


def publication_inputs_from_original(raw, *, original_from):
    return C.publication_inputs_from_original(raw, original_from=original_from)




# Explicit thin adapters. The caller's original budget passes unchanged.

def epoch_verified_active_context(lease, manifest, originals_by_path, verified, *, budget_check):
    import sys
    return _epoch_prepare_api().epoch_verify_active_semantics(lease,manifest,originals_by_path,verified,
        late_module=sys.modules[__name__],budget_check=budget_check)


def closed_epoch_boundary_originals(raw, inventory_raw, closure_raw, *, original_descriptor,
        registry_originals, combination_sha256, package_sha256, budget_check):
    import sys
    return _epoch_prepare_api().epoch_closed_boundary_from_originals(raw,inventory_raw,closure_raw,
        original_descriptor=original_descriptor,registry_originals=registry_originals,
        combination_sha256=combination_sha256,package_sha256=package_sha256,
        late_module=sys.modules[__name__],budget_check=budget_check)


def epoch_publish_result_from_original(raw, *, registry_originals, budget_check):
    import sys
    return _epoch_prepare_api().epoch_publish_result_from_originals(raw,registry_originals=registry_originals,
        late_module=sys.modules[__name__],budget_check=budget_check)


if __name__ == '__main__':
    raise SystemExit(main())


def load_epoch_capture_inputs(lease, *, budget_check):
    return _epoch_prepare_api().epoch_collect_original_inputs(lease, mode='preclose',
        budget_check=budget_check, inventory_validator=inventory_value)


def load_epoch_publication_inputs(lease=None, *, budget_check):
    inputs=_epoch_prepare_api().epoch_collect_original_inputs(None,mode='published',
        budget_check=budget_check,inventory_validator=inventory_value)
    if lease is not None:
        C.epoch_lease_protocol_value(lease)
        slots=inputs['verified']['registry']['slots']
        C._ep_need(slots and slots[-1]['identity'] is not None and slots[-1]['stage'] is not None
            and C._ep_same(slots[-1]['identity']['original'],lease['epoch']['identity'])
            and slots[-1]['identity']['value']['nonce']==lease['nonce'],
            'provided publication lease is not the actual highest committed identity')
        original=slots[-1]['stage']['value']['lease']
        index=C.epoch_manifest_value(inputs['manifest'],inputs['originals_by_path'],binding=C.epoch_binding_value())
        raw=C._ep_manifest_raw(original,index,inputs['originals_by_path'])
        C._ep_need(C._ep_same(C._ep_strict(raw),lease),
            'provided publication lease differs from its complete actual immutable original')
    budget_check()
    return inputs


def recheck_epoch_capture_inputs(manifest, *, budget_check):
    return _epoch_prepare_api().epoch_recheck_input_originals(manifest,
        budget_check=budget_check)


def verify_epoch_phone_active_source_observation(value, manifest, originals_by_path, verified):
    return _epoch_prepare_api().epoch_verify_phone_active_source_observation(
        value, manifest, originals_by_path, verified)
