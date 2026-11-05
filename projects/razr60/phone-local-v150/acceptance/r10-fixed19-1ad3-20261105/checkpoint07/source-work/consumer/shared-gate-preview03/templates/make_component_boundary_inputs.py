#!/usr/bin/env python3
"""Construct an explicit final component input from already closed host originals.

Reads existing files only until --execute-host-inputs. No phone, nonce, lease,
signal, parser, policy operation, role startup, replay, or qualification grant.
The full final consumer validates the actual closed component chain and the
separate Root policy adoption before a new input directory can be created.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import types

BASE = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
HELPER = None
# Source-only until the actual external publication and current runtime have
# been independently reviewed. No caller-provided pin can enable this candidate.
HELPER_SHA = None
HELPER_BYTES = None
PACKAGE_SHA = None
RETIREMENT_SHA = 'e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999'
SHARED_SHA = '121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f'
SCHEMA = 'hepta.r10.component-boundary-construction-plan.v7'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def meta(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def bootstrap(path, expected, maximum):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical original path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= maximum, 'bounded original file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and sha(raw) == expected
             and meta(before) == meta(os.fstat(fd)) == meta(path.lstat()), 'original changed or pin differs')
        return raw, meta(before)
    finally:
        os.close(fd)


def helper():
    need(isinstance(HELPER_SHA, str) and len(HELPER_SHA) == 64
         and type(HELPER_BYTES) is int and 0 < HELPER_BYTES <= 131072,
         'final current-package consumer has not been frozen and reviewed')
    raw, identity = bootstrap(HELPER, HELPER_SHA, HELPER_BYTES)
    need(len(raw) == HELPER_BYTES, 'reviewed consumer size differs')
    module = types.ModuleType('reviewed_component_input_consumer')
    module.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), 'exec'), module.__dict__)
    return module, identity



def collect_pre_policy_ancestor(h, item, collect, originals, package_state, combination_sha256):
    """Retain actual04 under its original combination/package, outside new cases."""
    need(isinstance(item, dict) and set(item) == {'root_result', 'package_manifest'},
         'explicit fixed pre-policy ancestor input required')
    home = BASE/'native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04'
    need(item['root_result'] == {'path':str(home/'ROOT-RESULT.json'), 'bytes':10980,
        'sha256':'c92382e0841375fc0a1fb19ff0271381ac044f1dad01427342fca4e4f6e9c638'},
        'only the actual04 Root original is the reviewed pre-policy ancestor')
    result_raw = collect(item['root_result']); result = h.strict(result_raw)
    manifest_raw = collect(item['package_manifest']); manifest = h.strict(manifest_raw)
    need(h.descriptor(manifest_raw) == {'bytes':5284,
         'sha256':'1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996'}
         and manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
         and len(manifest['files']) == 24,
         'the historical actual04 package is not its exact original 24-file manifest')
    oldpins = {row['path']:row for row in manifest['files']}
    need(len(oldpins) == 24, 'historical manifest duplicates an original source')
    expected = {
        'source/late_boundary.py':(35730,'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'),
        'source/component_common.py':(18133,'8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'),
        'source/close_component.py':(94190,'0261ed0e13ea35987765a99d6cefb394fb6825d49ac1870e49e805ec01029d69')}
    for name,(size,digest) in expected.items():
        need(oldpins[name] == {'path':name,'bytes':size,'sha256':digest},
             'historical source row differs from the exact executed package')
    with h.component_modules(package_state, actual_context='mac') as modules:
        late = modules['late_boundary']; reviewed = late.reviewed_pre_policy_ancestor()
        phone = reviewed['boundary']
        need(result['late_boundary'] == phone
             and result['state'] == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
             and result['component_qualified'] is False and result['native_status'] == 'provider_failed'
             and result['automatic_retry'] is False and result['business_qualified'] is False
             and type(result['model_requests']) is int and result['model_requests'] == 0
             and result['four_role_qualification'] is False,
             'historical Root result changed or was upgraded')
        copies = {}
        for key,filename in [('boundary','LATE-BOUNDARY.original.json'),
                             ('closure','CLOSURE.json'),('inventory','INVENTORY.json')]:
            row = reviewed[key]
            copy = {'path':str(home/filename),'bytes':row['bytes'],'sha256':row['sha256']}
            copies[key] = collect(copy); originals.append({'phone':row,'copy':copy})
        boundary, _inventory, closed = late.closed_boundary_originals(
            copies['boundary'], copies['inventory'], copies['closure'], original_descriptor=phone,
            combination_sha256=combination_sha256, package_sha256=PACKAGE_SHA)
        need(late.is_pre_policy_ancestor(boundary)
             and result['scope'] == boundary['scope']
             and closed['component_qualified'] is False and closed['unknown_effects'] == 0,
             'historical failed closure or original native scope differs')
        combo = {'path':str(home/'material/tree/inputs/COMBINATION.json'), 'bytes':4702,
            'sha256':late.LEGACY_COMBINATION_SHA256}
        combo_raw = collect(combo); oldcombo = h.strict(combo_raw)
        need(boundary['combination_sha256'] == sha(combo_raw)
             and oldcombo['schema'] == 'hepta.native-guard.component-combination.v150.r10.1'
             and oldcombo['live_policy_sha256'] == '296b09d9c844d2916b0dbdb0765c71cbcb8411790b58f5823798aa872205b659'
             and sha(combo_raw) != combination_sha256,
             'historical component must retain its original policy combination')
        previous = {'path':str(home/'ACTUAL-PREVIOUS-INPUT.json'),'bytes':1428,
            'sha256':'7ed4ccc75cc4ebc999af0da37e10e3d10173c2bf93e66f01b01042b890a4d9a4'}
        prior = h.strict(collect(previous))
        need(prior['identity'] == boundary['scope'] and prior['late_boundary'] == phone
             and prior['component_qualified'] is False and prior['terminal']['status'] == 'provider_failed'
             and prior['known_all_dispatched_tools_confirmed_terminal'] is True
             and prior['automatic_replay'] is False and h.HASH.fullmatch(prior['request_sha256']),
             'historical latest native predecessor was dropped or changed')
        steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
        need(len(steps) == 1 and type(steps[0]['returncode']) is int and steps[0]['returncode'] == 0,
             'the actual04 original publication terminal is absent')
        step = steps[0]
        need(step['stdout']['path'] == str(home/'phone-late-publish/stdout.original')
             and step['stderr']['path'] == str(home/'phone-late-publish/stderr.original'),
             'historical publication original paths differ')
        operation = h.strict(collect(step['stdout'])); stderr = collect(step['stderr'])
        need(stderr == b'' and type(operation['actor_rc']) is int and operation['actor_rc'] == 0
             and type(operation['wrapper']['phone']['rc']) is int
             and operation['wrapper']['phone']['rc'] == 0,
             'historical actual publication was not fully successful')
        stdout = operation['wrapper']['phone']['stdout']
        need(isinstance(stdout,str), 'historical publication stdout bytes absent')
        pub = h.strict(stdout.encode('utf-8'))
        need(pub['schema'] == 'hepta.native-guard.boundary-publish-result.v1'
             and pub['state'] == 'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED'
             and pub['boundary'] == phone and pub['original_retirement_rewritten'] is False,
             'historical actual published boundary differs')
    proof = {'schema':'hepta.r10.fixed-pre-policy-component-ancestor.v1',
        'boundary':phone, 'root_result':item['root_result'],
        'package_manifest':item['package_manifest'], 'combination':combo, 'previous':previous,
        'publication_operation':step['stdout'], 'publication_stderr':step['stderr']}
    return proof, boundary


def collect_environment_parent_ancestor(h, item, collect, originals, package_state, combination_sha256):
    """Collect fixed failed06 and its original R6 generation outside new cases."""
    need(isinstance(item, dict) and set(item) == {'root_result','package_manifest'},
         'explicit fixed environment-parent ancestor input required')
    home = BASE/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06'
    root = {'path':str(home/'ROOT-RESULT.json'),'bytes':32600,
            'sha256':'ed2e22f27b72951621802add6a1d68950ea94721d052b25dd5d59ebc95be5c93'}
    need(item['root_result'] == root, 'only actual06 is the reviewed environment-parent ancestor')
    result = h.strict(collect(root))
    manifest_raw = collect(item['package_manifest']); manifest = h.strict(manifest_raw)
    need(h.descriptor(manifest_raw) == {'bytes':11495,
             'sha256':'4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e'}
         and manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
         and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
         and len(manifest['files']) == 30
         and len({row['path'] for row in manifest['files']}) == 30,
         'the historical actual06 package is not the exact original R6 manifest')
    with h.component_modules(package_state, actual_context='mac') as modules:
        late = modules['late_boundary']; reviewed = late.reviewed_environment_parent_ancestor()
        phone = reviewed['boundary']
        need(result['late_boundary'] == phone and result['component_qualified'] is False
             and result['native_status'] == 'provider_failed', 'actual06 Root failure semantics differ')
        copies = {}
        for key,filename in [('boundary','LATE-BOUNDARY.original.json'),
                             ('closure','CLOSURE.json'),('inventory','INVENTORY.json')]:
            row = reviewed[key]
            copy = {'path':str(home/filename),'bytes':row['bytes'],'sha256':row['sha256']}
            copies[key] = collect(copy); originals.append({'phone':row,'copy':copy})
        boundary, _inventory, closed = late.closed_boundary_originals(
            copies['boundary'], copies['inventory'], copies['closure'], original_descriptor=phone,
            combination_sha256=combination_sha256, package_sha256=PACKAGE_SHA)
        need(late.is_environment_parent_ancestor(boundary)
             and boundary['prior_boundary'] == late.reviewed_pre_policy_ancestor()['boundary']
             and result['scope'] == boundary['scope'] and closed['component_qualified'] is False
             and type(closed['unknown_effects']) is int and closed['unknown_effects'] == 0
             and type(closed['actual_native_calls']) is int and closed['actual_native_calls'] == 1,
             'actual06 original failed closure or scope differs')
    combo = {'path':str(home/'material/tree/inputs/COMBINATION.json'),'bytes':4702,
             'sha256':'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'}
    need(sha(collect(combo)) == late.PROPERTY_PARENT_COMBINATION_SHA256,
         'historical actual06 must retain its original ba5 policy combination')
    previous = {'path':str(home/'ACTUAL-PREVIOUS-INPUT.json'),'bytes':1428,
                'sha256':'5ef37523f24a78dbce66da496c7f61897d989630a18739945279b8d0383415e9'}
    collect(previous)
    steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
    need(len(steps) == 1, 'actual06 original publication phase is absent or duplicated')
    step = steps[0]
    for key in ('stdout','stderr'):
        collect(step[key])
    provenance = {
        'recovery_result':{'path':str(home/'RECOVERY-RESULT.json'),'bytes':2724,
            'sha256':'ea74dc212a1edf1c9f4395ce72a8be8ec7a7f184b9f28321d68ece270fc4aa12'},
        'recovery_source':{'path':str(BASE/'native-guard-attempt06-recovery-source-r1/source/resume_failed_component06.py'),
            'bytes':26606,'sha256':'50a4e759486632d0fc129bb08e0101f526542a8a577b47d3474497da3d9b6237'},
        'recovery_intent':{'path':str(home/'RECOVERY-INTENT.json'),'bytes':90530,
            'sha256':'2db02625a51939dfbcaa1127d10976f253aa12e8ee9fa8c8c95c196f73ceefa2'},
        'original_root_failure':{'path':str(home/'ROOT-FAILURE.json'),'bytes':17357,
            'sha256':'4db667e2036cfcfee95f48ee3a58ed7f930cd0807402433afc7ad220da83fc7d'}}
    for row in provenance.values():
        collect(row)
    proof = {'schema':'hepta.r10.fixed-environment-parent-component-ancestor.v1',
        'boundary':phone,'root_result':root,'package_manifest':item['package_manifest'],
        'combination':combo,'previous':previous,'publication_operation':step['stdout'],
        'publication_stderr':step['stderr'],**provenance}
    # The final bundle consumer independently reads every original in this
    # proof, including the recovery result/source/intent and original failure.
    return proof, boundary


def collect_property_parent_ancestors(h, items, collect, originals, package_state):
    """Collect fixed actual08/07 outside the current-case prefix."""
    need(isinstance(items, list) and len(items) == 2,
         'the two explicit property-parent ancestors are required latest first')
    proofs = []; boundaries = []
    with h.component_modules(package_state, actual_context='mac') as modules:
        late = modules['late_boundary']
        reviewed = late.reviewed_property_parent_ancestors()
        old_reader = late.property_parent_reader()
        for index, (attempt, item) in enumerate(zip(('attempt08','attempt07'), items)):
            spec = h.property_parent_proof_spec(attempt)
            need(isinstance(item,dict) and set(item) == {'root_result','package_manifest'}
                 and all(item[key] == spec[key] for key in item),
                 'fixed actual08/07 original input descriptors differ or were reordered')
            for row in spec.values():
                collect(row)
            home = Path(spec['root_result']['path']).parent
            raw = {}
            for key,filename in (('boundary','LATE-BOUNDARY.original.json'),
                                 ('inventory','INVENTORY.json'),('closure','CLOSURE.json')):
                phone = reviewed[index][key]
                row = {'path':str(home/filename),'bytes':phone['bytes'],'sha256':phone['sha256']}
                raw[key] = collect(row)
                originals.append({'phone':phone,'copy':row})
            boundary, _inventory, closed = old_reader.closed_boundary_originals(
                raw['boundary'],raw['inventory'],raw['closure'],
                original_descriptor=reviewed[index]['boundary'],
                combination_sha256=late.PROPERTY_PARENT_COMBINATION_SHA256,
                package_sha256=late.PROPERTY_PARENT_PACKAGE_SHA256)
            need(late.is_property_parent_ancestor(boundary)
                 and closed['component_qualified'] is False
                 and type(closed['unknown_effects']) is int and closed['unknown_effects'] == 0
                 and type(closed['actual_native_calls']) is int
                 and closed['actual_native_calls'] == late.PROPERTY_PARENT_CALL_COUNTS[index],
                 'retained property-parent native failure differs')
            proofs.append({'schema':'hepta.r10.fixed-property-parent-component-ancestor.v1',
                 'attempt':attempt,'boundary':reviewed[index]['boundary'],**spec})
            boundaries.append(boundary)
    return proofs, boundaries


def build(h, plan, output):
    need(isinstance(PACKAGE_SHA, str) and h.HASH.fullmatch(PACKAGE_SHA)
         and PACKAGE_SHA == h.PACKAGE_SHA, 'current package trust pin is not frozen')
    need(set(plan) == {'schema', 'package_manifest', 'combination', 'retirement_descriptor',
            'retirement_originals', 'shared_materials', 'policy_adoption', 'cases',
            'legacy_ancestor', 'pre_policy_ancestor', 'environment_parent_ancestor', 'property_parent_ancestors'}
         and plan['schema'] == SCHEMA, 'exact construction plan fields required')
    need(isinstance(plan['cases'], list) and 1 <= len(plan['cases']) <= 3,
         'one to three current cases plus the exact actual08-to07-to06-to04-to-external03 tail required')
    need(output.is_absolute() and str(output) == str(output.absolute())
         and output.parent.resolve(strict=True) == output.parent
         and not output.exists() and not output.is_symlink(), 'new canonical host output directory required')
    observed = {}; bodies = {}; declared = {}; decoded_total = 0

    def collect(row):
        nonlocal decoded_total
        h.file_descriptor(row)
        old_size = declared.get(row['sha256'])
        need(old_size is None or old_size == row['bytes'], 'original digest declared with different sizes')
        if old_size is None:
            decoded_total += row['bytes']
            need(decoded_total <= h.MAX_BUNDLE, 'complete constructor original pool exceeds fixed decoded budget')
            declared[row['sha256']] = row['bytes']
        raw, identity = h.read_pinned(row)
        old = observed.get(row['path'])
        need(old is None or old == (row, identity), 'same original path has different identity')
        observed[row['path']] = (row, identity)
        previous = bodies.get(row['sha256'])
        need(previous is None or previous == raw, 'different bytes under one original hash')
        bodies[row['sha256']] = raw
        return raw

    def copy_at(path, phone):
        row = dict(path=str(path), bytes=phone['bytes'], sha256=phone['sha256'])
        return row, collect(row)

    manifest_raw = collect(plan['package_manifest'])
    need(sha(manifest_raw) == PACKAGE_SHA, 'reviewed frozen component package required')
    manifest = h.strict(manifest_raw)
    package_dir = Path(plan['package_manifest']['path']).parent
    package_files = []
    for item in manifest['files']:
        relative = Path(item['path'])
        need(not relative.is_absolute() and '..' not in relative.parts
             and str(relative) == item['path'], 'unsafe frozen package member')
        row = dict(path=str(package_dir/relative), bytes=item['bytes'], sha256=item['sha256'])
        collect(row); package_files.append(dict(name=item['path'], copy=row))
    combination_copy = plan['combination']
    combination_raw = collect(combination_copy)
    need(sha(combination_raw) == h.CURRENT_COMBINATION_SHA,
         'the explicitly reviewed current combination must be known before runtime loading')
    shared_raw = collect(plan['shared_materials'])
    need(sha(shared_raw) == SHARED_SHA == h.SHARED_MATERIALS_SHA,
         'actual original shared17 manifest required')
    shared = h.strict(shared_raw); shared_dir = Path(plan['shared_materials']['path']).parent
    need(type(shared) is dict and shared['schema'] == 'hepta.r10.shared-production-materials.v1'
         and type(shared['files']) is list and len(shared['files']) == 17,
         'actual shared material manifest schema/count differs')
    shared_files = {}; shared_package_files = []
    for entry in shared['files']:
        need(type(entry) is dict and set(entry) == {'path', 'bytes', 'sha256'},
             'exact shared original descriptor required')
        relative = Path(entry['path'])
        need(not relative.is_absolute() and '..' not in relative.parts and str(relative) == entry['path'],
             'unsafe shared material path')
        need(entry['path'] not in shared_files, 'duplicate shared material original')
        row = dict(path=str(shared_dir/relative), bytes=entry['bytes'], sha256=entry['sha256'])
        shared_files[entry['path']] = collect(row)
        shared_package_files.append(dict(name=entry['path'], copy=row))
    runtime_files = {item['path']: bodies[item['sha256']] for item in manifest['files']}
    reviewed_production = h.strict(runtime_files['reference/REVIEWED-PRODUCTION-PINS.json'])
    h.verify_shared_runtime_originals(shared_raw, shared_files, reviewed_production)
    # The final four-argument epoch capsule must be inserted before this source can run.
    # Every new runtime byte, combination and shared17 original precedes the first exec.
    h.verify_epoch_runtime_increment(manifest_raw, runtime_files, combination_raw, shared_files)
    retirement_raw = collect(plan['retirement_descriptor'])
    need(sha(retirement_raw) == RETIREMENT_SHA, 'original actual retirement descriptor differs')
    retirement = h.strict(retirement_raw)['files']
    need(set(retirement) == set(plan['retirement_originals']) ==
         {'proof', 'preflight', 'probe', 'bound_inputs', 'disabled_flag'}, 'five original retirement files required')
    originals = []
    for name, phone in retirement.items():
        row = plan['retirement_originals'][name]
        raw = collect(row)
        need(h.descriptor(raw) == {key: phone[key] for key in ('bytes', 'sha256')},
             'retirement copy differs from the original exact phone descriptor')
        originals.append(dict(phone=phone, copy=row))

    results = []; boundary_rows = []; publish_raw = None
    for index, item in enumerate(plan['cases']):
        need(set(item) == {'root_result'}, 'each closed case needs its explicit original Root result')
        result_raw = collect(item['root_result']); result = h.strict(result_raw)
        need(result['state'] == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
             and result['automatic_retry'] is False and result['business_qualified'] is False
             and result['model_requests'] == 0 and result['four_role_qualification'] is False,
             'Root case is not an actually closed and published component')
        home = Path(item['root_result']['path']).parent
        need(Path(item['root_result']['path']).name == 'ROOT-RESULT.json', 'exact original Root result filename required')
        phone = result['late_boundary']
        copy, raw = copy_at(home/'LATE-BOUNDARY.original.json', phone)
        boundary = h.strict(raw); boundary_rows.append(phone)
        need(result['scope'] == boundary['scope']
             and result['component_qualified'] is boundary['component_qualified']
             and result['native_status'] == boundary['native_status'], 'Root result and actual published boundary differ')
        originals.append(dict(phone=phone, copy=copy))
        for key, filename in (('closure', 'CLOSURE.json'), ('inventory', 'INVENTORY.json')):
            copy, raw = copy_at(home/filename, boundary[key])
            originals.append(dict(phone=boundary[key], copy=copy))
        combo_path = home/'material/tree/inputs/COMBINATION.json'
        # Size is bounded before reading; the actual published boundary supplies
        # the independently expected hash, never the current file's own digest.
        combo = dict(path=str(combo_path), bytes=combo_path.lstat().st_size,
                     sha256=boundary['combination_sha256'])
        combo_raw = collect(combo)
        need(combo_raw == combination_raw,
             'closed case combination differs from the original reviewed pre-exec combination')
        if index == 0:
            matches = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
            need(len(matches) == 1 and matches[0]['returncode'] == 0,
                 'one actual original publish process result required')
            step = matches[0]
            need(step['stdout']['path'] == str(home/'phone-late-publish/stdout.original')
                 and step['stderr']['path'] == str(home/'phone-late-publish/stderr.original'),
                 'original publish streams belong to another case')
            transport = h.strict(collect(step['stdout'])); collect(step['stderr'])
            need(type(transport['actor_rc']) is int and transport['actor_rc'] == 0
                 and type(transport['wrapper']['phone']['rc']) is int
                 and transport['wrapper']['phone']['rc'] == 0, 'actual publish actor/phone result was not zero')
            text = transport['wrapper']['phone']['stdout']
            need(isinstance(text, str), 'original publish stdout bytes required')
            publish_raw = text.encode('utf-8')
            pub = h.strict(publish_raw)
            need(pub['boundary'] == phone, 'raw original publish result names another boundary')
        results.append((result, boundary))

    package_state = {'package_sources': {item['name']: bodies[item['copy']['sha256']]
                                       for item in package_files}}
    property_proofs, property_boundaries = collect_property_parent_ancestors(
        h, plan['property_parent_ancestors'], collect, originals, package_state)
    environment_proof, environment_boundary = collect_environment_parent_ancestor(
        h, plan['environment_parent_ancestor'], collect, originals, package_state, sha(combination_raw))
    pre_policy_proof, pre_policy_boundary = collect_pre_policy_ancestor(
        h, plan['pre_policy_ancestor'], collect, originals, package_state, sha(combination_raw))

    legacy = plan['legacy_ancestor']
    need(isinstance(legacy, dict) and set(legacy) == {'boundary_descriptor',
        'boundary_original', 'closure_original', 'inventory_original',
        'publication_operation'}, 'explicit legacy original descriptors required')
    legacy_phone = h.strict(collect(legacy['boundary_descriptor']))
    legacy_raw = collect(legacy['boundary_original'])
    inventory_raw = collect(legacy['inventory_original'])
    closure_raw = collect(legacy['closure_original'])
    package_state = {'package_sources': {item['name']: bodies[item['copy']['sha256']]
                                       for item in package_files}}
    with h.component_modules(package_state, actual_context='mac') as modules:
        late = modules['late_boundary']
        sidebranch = late.non_native_sidebranch()
        need(all(h.encode(boundary.get('non_native_sidebranch')) == h.encode(sidebranch['binding'])
                 for _result, boundary in results),
             'current cases omitted or changed the fixed non-native attempt05 binding')
        legacy_boundary, _legacy_inventory, legacy_closure = late.closed_boundary_originals(
            legacy_raw, inventory_raw, closure_raw, original_descriptor=legacy_phone,
            combination_sha256=sha(combination_raw), package_sha256=PACKAGE_SHA)
        need(legacy_boundary['schema'] == late.LEGACY_SCHEMA
             and legacy_boundary['component_qualified'] is False,
             'external failed ancestor cannot supply component qualification')
        need(all(row[1]['package_sha256'] == PACKAGE_SHA
                 and row[1]['combination_sha256'] == sha(combination_raw) for row in results),
             'only current-package cases may appear in the new-case prefix')
        need(environment_boundary['prior_boundary'] == pre_policy_proof['boundary'],
             'fixed historical actual06-to-actual04 link differs')
        need(pre_policy_boundary['prior_boundary'] == legacy_phone,
             'fixed historical actual04-to-external03 link differs')
        late.require_failed_ancestor_tail([row[1] for row in results]
                                          + property_boundaries + [environment_boundary, pre_policy_boundary, legacy_boundary])
    for name, phone in (('boundary_original', legacy_phone),
                        ('closure_original', legacy_boundary['closure']),
                        ('inventory_original', legacy_boundary['inventory'])):
        row = legacy[name]
        need({key: row[key] for key in ('bytes', 'sha256')} ==
             {key: phone[key] for key in ('bytes', 'sha256')},
             'legacy host copy differs from its reviewed original descriptor')
        originals.append(dict(phone=phone, copy=row))
    operation = h.strict(collect(legacy['publication_operation']))
    need(type(operation['actor_rc']) is int and operation['actor_rc'] == 0
         and type(operation['wrapper']['phone']['rc']) is int
         and operation['wrapper']['phone']['rc'] == 0,
         'actual external publication actor/phone result was not zero')
    publication_stdout = operation['wrapper']['phone']['stdout']
    need(isinstance(publication_stdout, str), 'external publication raw stdout required')
    external_publish = h.strict(publication_stdout.encode('utf-8'))
    need(external_publish == {
        'schema':'hepta.native-guard.external-boundary-publish-result.v1',
        'state':'CREATE_ONLY_EXTERNAL_LEGACY_FAILED_BOUNDARY_PUBLISHED',
        'boundary':legacy_phone, 'component_qualified':False,
        'business_qualified':False, 'actual_old_package_sha256':late.LEGACY_PACKAGE_SHA256,
        'actual_native_calls':0, 'native_status':'provider_failed',
        'old_retirement_current_equality_claimed':False,
        'original_retirement_rewritten':False, 'phone_tool_calls':0,
        'model_requests':0, 'signals':0, 'automatic_retry':False},
        'external publication is not the original fixed failed-boundary result')
    for index, (_result, boundary) in enumerate(results):
        expected = boundary_rows[index+1] if index+1 < len(boundary_rows) else property_proofs[0]['boundary']
        need(boundary['prior_boundary'] == expected, 'complete actual boundary chain must be supplied latest first')
    publish_copy = dict(path=str(output/'PUBLISH-RESULT.original.json'), **h.descriptor(publish_raw))
    bodies[publish_copy['sha256']] = publish_raw
    value = dict(schema='hepta.r10.component-boundary-inputs.v6', release_id=h.RELEASE, boot_id=h.BOOT,
        component_package_manifest=plan['package_manifest'], component_package_files=package_files,
        component_shared_material_manifest=plan['shared_materials'],
        component_shared_material_files=shared_package_files,
        component_combination=combination_copy, latest_boundary=boundary_rows[0],
        publish_result=publish_copy, retirement=retirement, originals=originals,
        pre_policy_ancestor=pre_policy_proof, non_native_sidebranch=sidebranch['binding'],
        environment_parent_ancestor=environment_proof, property_parent_ancestors=property_proofs)
    raw = h.encode(value)
    component_copy = dict(path=str(output/'COMPONENT-BOUNDARY-INPUTS.json'), **h.descriptor(raw))
    policy_raw = collect(plan['policy_adoption'])
    policy = h.strict(policy_raw)
    wanted = set()
    for record in (value, policy):
        for row in h.descriptors(record):
            wanted.add(row['sha256'])
            if row == publish_copy:
                continue
            collect(row)
    bundle = dict(schema='hepta.r10.release-boundary-bundle.v2',
        inputs={'component': {'descriptor':component_copy, 'raw_b64':base64.b64encode(raw).decode()},
                'policy': {'descriptor':plan['policy_adoption'], 'raw_b64':base64.b64encode(policy_raw).decode()}},
        originals={pin:h.pack_original(bodies[pin])
                   for pin in wanted})
    bundle_raw = h.encode(bundle)
    state = h.validate_bundle(bundle_raw, sha(bundle_raw), actual_context='mac')
    sources = {Path(name).name: body for name, body in shared_files.items() if name.startswith('provider/source/')}
    config = shared_files['local-config-r10-r1.json']; service = shared_files['PHONE-SERVICE-INPUTS-v150-r10-r1.json']
    material_binding = h.validate_shared_materials(state, sources, config, service)
    external = h.external_artifact_bindings(state, sources, service)
    for row, identity in observed.values():
        _body, after = h.read_pinned(row)
        need(after == identity, 'host original changed before input publication')
    return raw, publish_raw, observed, {
        'schema':'hepta.r10.component-boundary-construction-result.v6',
        'state':'ACTUAL_CLOSED_COMPONENT_ORIGINALS_AND_ROOT_ADOPTION_VERIFIED',
        'component_input':component_copy, 'original_root_results':[item['root_result'] for item in plan['cases']],
        'component_case_count':len(results),
        'non_native_attempt_count':1, 'non_native_sidebranch':sidebranch['binding'],
        'non_native_sidebranch_native_case_count':0,
        'property_parent_failed_ancestor_count':2, 'property_parent_ancestors':property_proofs,
        'property_parent_component_qualification':False,
        'environment_parent_failed_ancestor_count':1, 'environment_parent_ancestor':environment_proof,
        'environment_parent_component_qualification':False,
        'pre_policy_failed_ancestor_count':1, 'pre_policy_ancestor':pre_policy_proof,
        'legacy_failed_ancestor_count':1, 'legacy_ancestor':legacy_phone,
        'legacy_publication_operation':legacy['publication_operation'],
        'legacy_original_descriptors':legacy,
        'legacy_ancestor_component_qualification':False,
        'qualified_component_cases':[boundary['case_id'] for _result,boundary in results if boundary['component_qualified']],
        'latest_boundary':boundary_rows[0],
        'policy_adoption':plan['policy_adoption'], 'actual_runtime_policy':state['runtime_policy'],
        'release_bundle_preview':h.descriptor(bundle_raw), 'shared_materials':plan['shared_materials'],
        'reviewed_combination_before_runtime_loading':combination_copy,
        'shared_material_binding':material_binding, 'component_external_artifacts':external,
        'retirement_original_rewritten':False, 'component_qualification_granted_by_this_constructor':False,
        'phone_calls':0, 'policy_operations':0, 'service_starts':0, 'automatic_retry':False}


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    syncdir(path.parent)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', type=Path, required=True); p.add_argument('--plan-sha256', required=True)
    p.add_argument('--out', type=Path, required=True); p.add_argument('--execute-host-inputs', action='store_true')
    a = p.parse_args(); h, identity = helper()
    plan_raw, plan_identity = bootstrap(a.plan, a.plan_sha256, 262144)
    raw, publish_raw, observed, report = build(h, h.strict(plan_raw), a.out)
    _source, after = bootstrap(HELPER, HELPER_SHA, HELPER_BYTES)
    _plan, final_plan = bootstrap(a.plan, a.plan_sha256, 262144)
    need(after == identity and final_plan == plan_identity, 'reviewed constructor inputs changed')
    report.update(plan_sha256=a.plan_sha256, consumer_sha256=HELPER_SHA,
                  output_created=False, component_input_recorded=False, bundle_written=False)
    if a.execute_host_inputs:
        os.umask(0o077); a.out.mkdir(mode=0o700); syncdir(a.out.parent)
        put(a.out/'PUBLISH-RESULT.original.json', publish_raw)
        put(a.out/'COMPONENT-BOUNDARY-INPUTS.json', raw)
        report.update(output_created=True, component_input_recorded=True)
        put(a.out/'PREPARATION-RESULT.json', h.encode(report))
    print(json.dumps(report,sort_keys=True))


if __name__ == '__main__':
    main()
