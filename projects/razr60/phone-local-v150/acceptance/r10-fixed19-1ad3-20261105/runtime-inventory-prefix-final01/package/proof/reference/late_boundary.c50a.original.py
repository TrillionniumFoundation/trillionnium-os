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
    children = {}
    for name in entries:
        p = Path(name)
        children.setdefault(str(p.parent), []).append(p.name)
    total = 0
    for name, row in entries.items():
        p = Path(name)
        C.need(p.is_absolute() and str(p) == name and '..' not in p.parts
               and sum(p == q or q in p.parents for q in paths) == 1,
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
REVIEWED_CURRENT_COMBINATION_SHA256='54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'
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


def property_parent_reader():
    """Raw-load the exact R7 reader and common under the old combination."""
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
        return old
    finally:
        sys.path[:] = previous_path
        sys.dont_write_bytecode = previous_dwb
        if saved is None:
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
    """Read one current original or one of five exact retained failed originals."""
    current_context(combination_sha256, package_sha256)
    C.need(type(raw) is bytes and 0 < len(raw) <= 16*1024*1024,
           'bounded original boundary bytes required')
    exact_descriptor(original_descriptor)
    C.need(C.descriptor(raw) == {k:original_descriptor[k] for k in ('bytes','sha256')},
           'boundary bytes differ from their actual original descriptor')
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
    return value, inv, closed



def require_failed_ancestor_tail(values):
    records = property_parent_records()
    C.need(isinstance(values, list) and 5 <= len(values) <= MAX_CHAIN,
           'the complete chain must retain exact actual08 then07 then06 then04 then03')
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
        if index < len(values)-5:
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
            if index == len(values)-6:
                C.need(prior == records[0]['boundary'],
                       'current prefix must point at exact actual08 identity')


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


if __name__ == '__main__':
    raise SystemExit(main())
