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
          'model_requests', 'automatic_replay'}


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


def boundary_from_original(raw, *, original_descriptor, combination_sha256, package_sha256):
    """One raw-byte reader for live admission, snapshot and offline closure.

    Ordinary current-package boundaries retain the original validation exactly.
    The only external predecessor is the whole independently published original;
    it is never normalized into an ordinary current-package success record.
    """
    C.need(type(raw) is bytes and 0 < len(raw) <= 16*1024*1024,
           'bounded original boundary bytes required')
    exact_descriptor(original_descriptor)
    C.need(C.descriptor(raw) == {k: original_descriptor[k] for k in ('bytes', 'sha256')},
           'boundary bytes differ from their actual original descriptor')
    value = C.strict(raw)
    if value.get('schema') == SCHEMA:
        checked = boundary_value(value, combination_sha256=combination_sha256,
                                 package_sha256=package_sha256)
        C.need(original_descriptor['path'] == str(ROOT/(checked['nonce']+'.json')),
               'ordinary boundary filename does not bind its nonce')
        return checked
    p = reviewed_failed_ancestor()
    C.need(original_descriptor == p['boundary']
           and C.descriptor(raw) == {k: p['boundary'][k] for k in ('bytes', 'sha256')},
           'external boundary is not the one reviewed published raw original')
    C.need(set(value) == FIELDS | {'external_reconciliation'}
           and value['schema'] == LEGACY_SCHEMA and value['state'] == LEGACY_STATE,
           'external predecessor schema is not the fixed failed-case schema')
    C.need(isinstance(package_sha256, str) and C.HASH.fullmatch(package_sha256)
           and package_sha256 != LEGACY_PACKAGE_SHA256
           and combination_sha256 == value['combination_sha256'] == LEGACY_COMBINATION_SHA256,
           'new adapter or unchanged production combination differs')
    C.need(value['nonce'] == LEGACY_NONCE and value['case_id'] == 'NEG-01'
           and value['package_sha256'] == LEGACY_PACKAGE_SHA256
           and value['boot_id'] == LEGACY_BOOT_ID and value['scope'] == LEGACY_SCOPE
           and value['retirement'] == LEGACY_RETIREMENT and value['prior_boundary'] is None,
           'external predecessor is not the fixed actual failed native identity')
    C.scope(value['scope'])
    C.need(isinstance(value['owner_request_sha256'], str)
           and C.HASH.fullmatch(value['owner_request_sha256'])
           and value['publisher_source_sha256'] == p['publisher_source_sha256']
           and value['inventory'] == p['inventory'] and value['closure'] == p['closure'],
           'external predecessor original source/closure/inventory differs')
    C.need(value['component_qualified'] is False and value['business_qualified'] is False
           and value['native_status'] == 'provider_failed'
           and type(value['actual_native_calls']) is int and value['actual_native_calls'] == 0
           and type(value['model_requests']) is int and value['model_requests'] == 0
           and value['automatic_replay'] is False and value['original_retirement_rewritten'] is False,
           'failed predecessor was promoted to credit or replay')
    roles = value['component_role_identities']
    C.need(isinstance(roles, dict) and set(roles) == {'supervisor', 'provider', 'sidecar'}
           and all(isinstance(v, list) and len(v) == 4 and all(type(n) is int and n > 1 for n in v)
                   and v[:3] == [v[0]]*3 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3,
           'fixed failed component role generations differ')
    C.need(value['external_reconciliation'] == {
        'schema': 'hepta.native-guard.external-closure-origin.v1',
        'original_executed_package_sha256': LEGACY_PACKAGE_SHA256,
        'original_frozen_closure_source_sha256': LEGACY_PARENT_CLOSURE_SHA256,
        'actual_external_closure_source_sha256': p['external_closure_source_sha256'],
        'fixed_fixture_reconciler_source_sha256': LEGACY_FIXTURE_RECONCILER_SHA256,
        'external_capture_verifier_source_sha256': p['external_capture_verifier_source_sha256'],
        'external_reconciliation_sha256': p['external_reconciliation_sha256'],
        'ordinary_package_compatibility_claimed': False,
        'future_admission_requires_exact_published_boundary_pin': True},
        'external predecessor source origin differs')
    return value


def closed_boundary_originals(raw, inventory_raw, closure_raw, *, original_descriptor,
                             combination_sha256, package_sha256):
    value = boundary_from_original(raw, original_descriptor=original_descriptor,
        combination_sha256=combination_sha256, package_sha256=package_sha256)
    C.need(type(inventory_raw) is bytes and type(closure_raw) is bytes
           and C.descriptor(inventory_raw) == {k: value['inventory'][k] for k in ('bytes', 'sha256')}
           and C.descriptor(closure_raw) == {k: value['closure'][k] for k in ('bytes', 'sha256')},
           'closed boundary inventory/closure original bytes differ')
    inv, closed = C.strict(inventory_raw), C.strict(closure_raw)
    inventory_value(inv)
    C.need(inv['roots'] == value['roots'], 'closed boundary omitted cumulative original roots')
    closure_matches(closed, value, inventory_raw)
    if value['schema'] == LEGACY_SCHEMA:
        p = reviewed_failed_ancestor(); proof = closed.get('external_reconciliation')
        C.need(isinstance(proof, dict)
               and C.sha(C.encoded(proof)) == p['external_reconciliation_sha256']
               and closed.get('closure_source_sha256') == p['external_closure_source_sha256']
               and proof.get('schema') == 'hepta.native-guard.attempt03.external-reconciliation.v1'
               and proof.get('actual_executed_package_sha256') == LEGACY_PACKAGE_SHA256
               and proof.get('original_closure_source_sha256') == LEGACY_PARENT_CLOSURE_SHA256
               and proof.get('external_fixture_source_sha256') == LEGACY_FIXTURE_RECONCILER_SHA256
               and proof.get('external_capture_verifier_source_sha256') == p['external_capture_verifier_source_sha256']
               and proof.get('external_closure_source_sha256') == p['external_closure_source_sha256']
               and proof.get('original_closure_source_loaded_and_pure_verifiers_reused') is True
               and proof.get('original_complete_closure_entry_called') is False
               and proof.get('original_complete_closure_entry_claimed_passed') is False
               and proof.get('original_fixture_verifier_accepted') is False
               and proof.get('all_six_p4_originals_retained') is True
               and proof.get('actor_directory_claimed_absent') is False,
               'fixed failed reconciliation was omitted or presented as frozen closure success')
    return value, inv, closed


def require_failed_ancestor_tail(values):
    reviewed_failed_ancestor()
    C.need(isinstance(values, list) and 1 <= len(values) <= MAX_CHAIN
           and values[-1]['schema'] == LEGACY_SCHEMA and values[-1]['nonce'] == LEGACY_NONCE
           and values[-1]['prior_boundary'] is None
           and all(v['schema'] == SCHEMA for v in values[:-1]),
           'current chain must retain exactly the one published failed ancestor at its tail')



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


def verify_current(lease, *, combination_sha256, package_sha256):
    """Read-only admission for a subsequent explicit component lease."""
    C.need(lease.get('prior_boundary') is not None
           and lease.get('combination', {}).get('sha256') == combination_sha256
           and lease.get('package_sha256') == package_sha256, 'next lease late-boundary binding differs')
    C.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == lease['boot_id'],
           'boot changed since the closed component')
    chain, originals = chain_originals(lease['prior_boundary'], combination_sha256=combination_sha256,
        package_sha256=package_sha256, boot_id=lease['boot_id'], retirement=lease['retirement'])
    C.need(all(lease['nonce'] != row[0]['nonce'] for row in chain), 'closed nonce cannot be reused')
    _proof, roles = retired_originals(lease['retirement'], lease['boot_id'])
    for boundary, _inventory, _closure in chain:
        roles.extend(boundary['component_role_identities'].values())
    C.need(len({tuple(x) for x in roles}) == len(roles), 'closed role identities repeat')
    observed = current_inventory(chain[0][1])
    absence = [C.absent_groups(roles), C.absent_groups(roles)]
    from component_snapshot import endpoint_absence
    _tables, endpoints = endpoint_absence()
    recheck_originals(originals + list(lease['retirement'].values()))
    return {'schema': 'hepta.native-guard.late-boundary-verification.v1',
        'state': 'EXACT_CLOSED_CUMULATIVE_ORIGINALS_UNCHANGED',
        'previous_boundary': lease['prior_boundary'], 'closed_components': len(chain),
        'inventory_sha256': chain[0][0]['inventory']['sha256'], 'roots': observed['roots'],
        'entries': len(observed['entries']), 'file_bytes_hashed': observed['file_bytes_hashed'],
        'original_retirement_sha256': lease['retirement']['proof']['sha256'],
        'absence_observations': absence, 'endpoints': endpoints,
        'old_retirement_current_equality_claimed': False, 'original_retirement_rewritten': False,
        'phone_tool_calls': 0, 'model_requests': 0, 'signals': 0, 'writes': 0}


def publish(a):
    import component_lifecycle as LIFE
    os.umask(0o077)
    home = C.private_dir(Path(a.lease)); lease, lease_raw = LIFE.load_lease(home, a.lease_sha256, require_live=False)
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
    current_inventory(inv)
    C.absent_groups(roles); C.absent_groups(roles)
    from component_snapshot import endpoint_absence
    endpoint_absence()
    recheck_originals(prior_originals + list(lease['retirement'].values()))
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
    recheck_originals(prior_originals + list(lease['retirement'].values()))
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
