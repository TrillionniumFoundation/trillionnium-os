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
MAX_CHAIN = 11
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
REVIEWED_CURRENT_COMBINATION_SHA256 = '02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'
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
    C.need(REVIEWED_CURRENT_COMBINATION_SHA256 != LEGACY_COMBINATION_SHA256,
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
           and package_sha256 not in (V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256, STACK_DIAGNOSTIC_PARENT_PACKAGE_SHA256, DIAG02_PACKAGE_SHA256, CODEC_DIAGNOSTIC_PARENT_PACKAGE_SHA256, DIAGNOSTIC_PARENT_PACKAGE_SHA256, PROPERTY_PARENT_PACKAGE_SHA256,
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
    """Read one current final component or one of nine exact retained failed originals."""
    current_context(combination_sha256, package_sha256)
    C.need(type(raw) is bytes and 0 < len(raw) <= 16*1024*1024,
           'bounded original boundary bytes required')
    exact_descriptor(original_descriptor)
    C.need(C.descriptor(raw) == {k:original_descriptor[k] for k in ('bytes','sha256')},
           'boundary bytes differ from their actual original descriptor')
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
    C.need(checked['nonce'] not in (V3_RUNTIME_DIAGNOSTIC_NONCE, STACK_DIAGNOSTIC_PARENT_NONCE, DIAG02_NONCE, CODEC_DIAGNOSTIC_PARENT_NONCE, DIAGNOSTIC_PARENT_NONCE, *PROPERTY_PARENT_NONCES, POLICY_PARENT_NONCE,
                                  LEGACY_NONCE, ENVIRONMENT_PARENT_NONCE),
           'a historical nonce cannot be relabeled as current')
    return checked



def closed_boundary_originals(raw, inventory_raw, closure_raw, *, original_descriptor,
                             combination_sha256, package_sha256):
    value = boundary_from_original(raw, original_descriptor=original_descriptor,
        combination_sha256=combination_sha256, package_sha256=package_sha256)
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
    records = property_parent_records()
    C.need(isinstance(values, list) and 9 <= len(values) <= MAX_CHAIN,
           'the complete chain must retain actual v3 diagnostic then exact failed820 then6077 then902 then08 then07 then06 then04 then03')
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
    diagnostic_record = reviewed_diagnostic_parent_ancestor()
    diagnostic = diagnostic_parent_from_original(C.encoded(values[-6]), diagnostic_record['boundary'])
    C.need(diagnostic['prior_boundary'] == records[0]['boundary'],
           'fixed diagnostic predecessor does not point to original actual08')
    codec_record = reviewed_codec_diagnostic_parent_ancestor()
    codec = codec_diagnostic_parent_from_original(C.encoded(values[-7]), codec_record['boundary'])
    C.need(codec['prior_boundary'] == diagnostic_record['boundary'],
           'fixed failed6077 does not point to original failed902')
    stack_record = reviewed_stack_diagnostic_parent_ancestor()
    stack = stack_diagnostic_parent_from_original(C.encoded(values[-8]), stack_record['boundary'])
    C.need(stack['prior_boundary'] == codec_record['boundary'],
           'fixed failed820 does not point to original failed6077')
    v3_record = reviewed_v3_runtime_diagnostic_ancestor()
    v3 = v3_runtime_diagnostic_from_original(C.encoded(values[-9]), v3_record['boundary'])
    C.need(v3['prior_boundary'] == stack_record['boundary'],
           'actual v3 diagnostic must retain exact failed820 predecessor')
    seen_nonce = set(); seen_scope = set(); current_package = None
    for index, value in enumerate(values):
        key = tuple(value['scope'][name] for name in C.SCOPE)
        C.need(value['nonce'] not in seen_nonce and key not in seen_scope,
               'closed boundary repeats a nonce or native scope')
        seen_nonce.add(value['nonce']); seen_scope.add(key)
        if index < len(values)-9:
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
            if index == len(values)-10:
                C.need(prior == v3_record['boundary'],
                       'current prefix must point at exact actual v3 diagnostic identity')


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
    C.need(len(chain) < MAX_CHAIN and len(component_roles)+3 <= 39,
           'no capacity for another native generation; fixed history cannot be discarded')
    roles.extend(component_roles)
    C.need(len({tuple(x) for x in roles}) == len(roles), 'closed role identities repeat')
    retained=retained_unstarted_stage()
    C.need(lease['nonce']!=retained['binding']['nonce'],'expired unstarted nonce is permanently consumed')
    selected, selected_pin, selection = effective_current_prior_inventory(chain[0][0], chain[0][1], branches,retained=retained)
    retained_transport=retained_stage_external_originals(retained)
    parent_before=retained_stage_parent_aliases();fixture_before=fresh_retained_fixture_absence()
    observed = current_inventory(selected)
    preserve_non_native_sidebranches(observed, branches)
    preserve_retained_unstarted_stage(observed,retained=retained)
    fixture_after=fresh_retained_fixture_absence();validate_retained_fixture_observations([fixture_before,fixture_after])
    current_home=retained_stage_current_home(lease,parent_before,lstat=os.lstat,read_private=C.read)
    parent_profiles=retained_stage_parent_profiles(retained,observed,parent_before,retained_stage_parent_aliases(),
        additional_home=current_home)
    absence = [C.absent_groups(roles), C.absent_groups(roles)]
    from component_snapshot import endpoint_absence
    _tables, endpoints = endpoint_absence()
    recheck_originals(originals + list(lease['retirement'].values()) +
                      [row for branch in branches for row in branch['originals']] + retained_transport)
    return {'schema': 'hepta.native-guard.late-boundary-verification.v1',
        'state': 'EXACT_CLOSED_CUMULATIVE_ORIGINALS_UNCHANGED',
        'previous_boundary': lease['prior_boundary'], 'closed_components': len(chain),
        'inventory_sha256': selected_pin['sha256'], 'roots': observed['roots'],
        'inventory_selection': selection,
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
    branches = non_native_sidebranches(phone_originals=True)
    sidebranch = branches[0]
    preserve_non_native_sidebranches(inv, branches)
    retained=retained_unstarted_stage();preserve_retained_unstarted_stage(inv,retained=retained)
    retained_transport=retained_stage_external_originals(retained)
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
    C.need(len({tuple(x) for x in roles}) == len(roles), 'closed role identities repeat')
    current_inventory(inv)
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
    current_inventory(inv)
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
    """Pure validation against this complete admitted native prefix, at most two homes."""
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
    C.need(0<=len(homes)<=2 and len(current['roots'])==41+3*counted
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


CURRENT_RUNTIME_PATHS = frozenset(['reference/REVIEWED-PRODUCTION-PINS.json', 'reference/attempt05-AFTER-INVENTORY.original.json', 'reference/attempt05-CLOSURE.original.json', 'reference/attempt05-SIDE-PROOF.original.json', 'reference/component_common_r5.py', 'reference/component_core.py', 'reference/component_once_r9.py', 'reference/decode_client_state.py', 'reference/diag02-AFTER-INVENTORY.original.json', 'reference/diag02-CLOSURE.original.json', 'reference/diag02-SIDE-PROOF.original.json', 'reference/environment_parent_late_boundary_r6.py', 'reference/native_guard_session.py', 'reference/native_journal_audit.py', 'reference/non_native_attempt05.py', 'reference/non_native_diag02.py', 'reference/policy_parent_late_boundary_r4.py', 'reference/property_parent_late_boundary_r7.py', 'reference/send_new_native_task_r5.py', 'reference/tool_client_r6.py', 'source/close_component.py', 'source/component_common.py', 'source/component_lifecycle.py', 'source/component_listener.py', 'source/component_snapshot.py', 'source/late_boundary.py', 'source/native_guard_session_r2.py', 'source/native_proc_profile.py', 'source/prepare_component.py', 'source/root_fixture_once.py', 'source/root_fixture_originals.py', 'source/run_root_fixture_phase.py', 'source/send_new_native_guard_task_r10_r4.py', 'source/sender_native_guard_ready_r10_r4.py', 'source/stage_component.py', 'source/witness_bundle.py', 'reference/retained_unstarted_stage_final02.py'])

def _verify_current_package37_original(package, pin):
    package = Path(package)
    raw = read(package, 262144); need(sha(raw) == pin, 'adapter package pin differs')
    m = strict(raw)
    need(m.get('schema') == 'hepta.native-guard.adapter-package.v1'
         and m.get('state') == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED', 'explicit adapter package required')
    files = m['files']; names = [x['path'] for x in files]
    need(len(names) == len(set(names)) and 5 <= len(names) <= 37, 'package inventory bound')
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
    rows = manifest['files']; index = {row['path']: row for row in rows}
    C.need(len(rows) == 37 and set(index) == CURRENT_RUNTIME_PATHS
           and manifest.get('runtime_file_count') == 37
           and manifest.get('retained_unstarted_stage') == REVIEWED_RETAINED_STAGE_BINDING
           and manifest.get('retained_unstarted_stage_count') == 1
           and manifest.get('current_complete_inventory_root_count') == 41
           and manifest.get('maximum_complete_inventory_roots_after_two_final_NEG_cases') == 47
           and {k:index[RETAINED_STAGE_REFERENCE][k]for k in ('bytes','sha256')} ==
               {'bytes':RETAINED_STAGE_BYTES,'sha256':RETAINED_STAGE_SHA256}
           and manifest.get('component_role_cap') == 39
           and manifest.get('native_chain_cap') == 11
           and manifest.get('maximum_new_current_case_prefix') == 2
           and manifest.get('diagnostic_only') is False
           and manifest.get('maximum_native_calls_in_current_generation') == 2
           and manifest.get('historical_native_boundary_count') == 9
           and manifest.get('current_policy_sha256') == REVIEWED_CURRENT_POLICY_SHA256
           and manifest.get('explicit_policy_adoption_sha256') == REVIEWED_CURRENT_POLICY_ADOPTION_SHA256
           and manifest.get('v3_runtime_diagnostic_ancestor') == reviewed_v3_runtime_diagnostic_ancestor(),
           'explicit current 37-member package and finite resource contract required')
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
    """Only this exact new 37-member generation; historical Common remains C32."""
    reviewed_diag02_non_native_record()
    manifest = _verify_current_package37_original(package, pin)
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
    current_context(boundary['combination_sha256'],boundary['package_sha256'])
    current_retained_stage_binding(boundary)
    preserve_retained_unstarted_stage(inventory,retained=retained)
    return inventory,boundary['inventory'],'current_final_native_component_head_with_retained_unstarted_stage'


def require_component_role_budget(roles):
    C.need(type(roles) is list and len(roles) <= 39
           and all(type(v) is list and len(v) == 4
                   and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles)
           and len({tuple(v) for v in roles}) == len(roles),
           'reviewed finite current native lane plus two fixed non-native branches role bound differs')
    return roles


if __name__ == '__main__':
    raise SystemExit(main())
