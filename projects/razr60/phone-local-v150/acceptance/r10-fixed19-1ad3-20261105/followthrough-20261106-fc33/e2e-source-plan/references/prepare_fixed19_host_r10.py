#!/usr/bin/env python3
"""Prepare the original six host-only fixed19 cases for an actual sealed r10.

No test execution, phone, SSH, socket, subprocess, task or nonce is created by
this program. Explicit execution writes one fresh host output directory. The
P4 harness retains the original private mount/PID/network namespace boundary.
"""
import argparse
import ast
import base64
import copy
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / 'reference' / 'parent-r9'
ORIGINAL = 'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0'
SHARED = '121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f'
ADOPTION = None
POLICY = None
RETIREMENT = 'b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'
CLIENT = '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
BIND_HELPER = '1d2df87be1377e9c8ae1b186121b94843db125d5ece1350cb6e6399cc7a24535'
# Fixed after the actual reviewed r4 consumer/acceptance cascade, never accepted
# from a caller plan merely because an arbitrary materializer can be re-sealed.
MATERIALIZER = None
CONSUMER_MANIFEST = None
CONSUMER = None
READINESS = None
CONSUMER_SCHEMA = None
IMPORT_GUARD = 'ef468183f4a32063a98c30336460a7362524be8080cdeaf345fc0553d9b061d0'
DAILY = 'f42fa1f3268d2a2c00e49610d356b440d1e32722fbe2af877580fb6eb180f712'
IDS = ('NEG-06', 'NEG-10', 'NEG-11', 'NEG-12', 'NEG-13', 'NEG-14')
OLD_P4 = '/home/alex/razr60-local-model-v150/host-fixed19-r9-r2-20261104-r1'
ASSETS = {
    'synthetic.png': (1191, '4318a71128144b0e7da041731c3014192fffb4f1a15495eda8864a774c831d13'),
    'synthetic.jpg': (19356, 'e8e0d7d851b6079e29e86c69f176056bee2ed849540620f0505a34ddf0438521'),
}
PARENTS = {
    'component/execute_namespace_once.py': (6936, '67449b38ce232e295dcbf4100fc451fb57a7b1109aea2bbc48f5da625c243be4'),
    'component/host_negative_runner.py': (30154, '32dd8e70d3b253748f6bfa1b068dd26497cb9ef530dcf5bad49caa5ba5d75d5f'),
    'service/binding_adapter.py': (6492, '57ee4c4d377de692f78938f39c74219a4bfabf3a5479c4efdfad3c9cee68e0fd'),
    'service/execute_namespace_once.py': (7271, '5d330285f5b0444307b795b9c62bfbd7c74752e39b456999e7c9b2f1e1112292'),
    'service/fixture_server.py': (14704, '80a859b0b00f7dc95932d32f06e0eccba3d3031b4e5e2fc5d2dde22af526988b'),
    'service/service_negative_runner.py': (23719, 'c7b3ff0a7ed1204535fffd7a7fba5fc1a7dc5942bcf54e0e1b576455e1f73019'),
    'inputs/original-protocol.json': (37318, ORIGINAL),
    'inputs/historical-protocol-binding-r7-r3.json': (38377, '47ef681e8add5cecd3d69ca211054f0cf04d6510ba9865768a4815e46890c172'),
    'inputs/protocol.json': (38620, '4ccba1f9683b004ac7e1f0b0bfb06a519d37ba4d24f73462f526f07ca54ce0ef'),
}
PIN_REPLACEMENTS = {
    'SEAL_SHA': '3ec84e70ace3a2736cc5233482dc96304d0af350cb1cb0318f2b6c010b062a96',
    'COMBO_SHA': 'e613148932ee584454c6e357559d764effdbc62fbf41a4ebe6f79d3e74c0548d',
    'COMBO_CANONICAL': 'c77fabcaf2fa703bcdb6bb1cdb232c7a481bf9217ddc43ecd953379ddf2bfc84',
    'PROTOCOL_SHA': '4ccba1f9683b004ac7e1f0b0bfb06a519d37ba4d24f73462f526f07ca54ce0ef',
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2,
                       allow_nan=False) + '\n').encode()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def meta(s):
    return [getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
            'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self, path, expected=None, maximum=16*1024*1024):
        path = Path(path).absolute()
        need(path.parent.resolve() == path.parent and '..' not in path.parts,
             'canonical input path required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= maximum, 'bounded single-link input required')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(maximum + 1)
            need(len(raw) == before.st_size and meta(before) == meta(os.fstat(fd))
                 == meta(path.lstat()), 'input changed while reading')
        finally:
            os.close(fd)
        if expected is not None:
            need(set(expected) == {'bytes', 'sha256'} and type(expected['bytes']) is int
                 and expected == pin(raw), 'input byte pin differs: ' + str(path))
        identity = (meta(before), pin(raw))
        need(str(path) not in self.seen or self.seen[str(path)] == identity,
             'input path changed between reads')
        self.seen[str(path)] = identity
        return raw

    def descriptor(self, row, maximum=16*1024*1024):
        need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'},
             'explicit path/bytes/hash input required')
        return self.read(row['path'], {k: row[k] for k in ('bytes', 'sha256')}, maximum)

    def stream_pin(self, row):
        path = Path(row['path']).absolute()
        need(path.parent.resolve() == path.parent and type(row['bytes']) is int
             and 0 < row['bytes'] <= 64*1024*1024, 'bounded release archive required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size == row['bytes'], 'archive metadata differs')
            h = hashlib.sha256(); total = 0
            while total <= row['bytes']:
                data = os.read(fd, min(1024*1024, row['bytes'] + 1 - total))
                if not data:
                    break
                total += len(data); h.update(data)
            need(total == row['bytes'] and h.hexdigest() == row['sha256']
                 and meta(before) == meta(os.fstat(fd)) == meta(path.lstat()),
                 'archive byte identity differs')
        finally:
            os.close(fd)
        self.seen[str(path)] = (meta(before), {'bytes': total, 'sha256': h.hexdigest()})

    def recheck(self):
        for name, (identity, record) in tuple(self.seen.items()):
            need(meta(Path(name).lstat()) == identity, 'original metadata changed before output')
            if record['bytes'] > 16*1024*1024:
                self.stream_pin(dict(path=name, **record))
            else:
                self.read(name, record)


def module(raw, path, name):
    value = types.ModuleType(name); value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', optimize=0), value.__dict__)
    return value


def require_final_dependencies():
    need(all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
             for value in (ADOPTION, POLICY, MATERIALIZER, CONSUMER_MANIFEST, CONSUMER, READINESS))
         and isinstance(CONSUMER_SCHEMA, str) and CONSUMER_SCHEMA.startswith('hepta.r10.final-boundary-consumers.'),
         'future Native5 policy/adoption/consumer/readiness dependencies have not been frozen')


def import_guard(originals):
    path = HERE/'harness_import_provenance.py'
    raw = originals.read(path, maximum=65536)
    need(sha(raw) == IMPORT_GUARD, 'reviewed import provenance derivation differs')
    return module(raw, path, 'fixed19_import_provenance_preparer')


def source_manifest(originals, row):
    need(row.get('sha256') == CONSUMER_MANIFEST, 'only the reviewed final Native5 consumer package is allowed')
    raw = originals.descriptor(row, 262144); value = strict(raw)
    need(value.get('schema') == CONSUMER_SCHEMA,
        'reviewed final consumer manifest required')
    rows = value['files']; names = [x['path'] for x in rows]
    need(len(names) == len(set(names)) and 'source/release_boundaries.py' in names,
         'consumer source manifest incomplete')
    root = Path(row['path']).parent; result = {}
    for entry in rows:
        name = entry['path']; rel = Path(name)
        need(str(rel) == name and not rel.is_absolute() and '..' not in rel.parts,
             'consumer source path differs')
        if name.startswith('source/'):
            result[name] = originals.read(root/rel, {k: entry[k] for k in ('bytes', 'sha256')})
    need(sha(result['source/release_boundaries.py']) == CONSUMER
         and sha(result['source/collect_r10_readiness.py']) == READINESS,
         'final reviewed consumer/readiness source differs')
    return value, result


def prepare(plan, original_plan, originals):
    require_final_dependencies()
    need(set(plan) == {'schema', 'preparer_sha256', 'release', 'consumer_manifest',
        'materializer', 'shared_materials', 'policy_adoption', 'policy_history_input', 'component_boundary_inputs',
        'client', 'assets', 'p4_root', 'output'}, 'host preparation plan fields differ')
    need(plan['schema'] == 'hepta.fixed19.r10.host-preparation-plan.v2'
         and plan['preparer_sha256'] == sha(originals.read(__file__, maximum=131072)),
         'reviewed host preparer source differs')
    need(isinstance(plan['p4_root'], str) and re.fullmatch(
        r'/home/alex/razr60-local-model-v150/host-fixed19-r10-r1-[a-z0-9-]{3,64}',
        plan['p4_root']), 'explicit new P4 host-only root required')
    destination = Path(plan['output']).absolute()
    need(destination.parent.resolve() == destination.parent and not destination.exists()
         and not destination.is_symlink(), 'fresh canonical host output required')
    materializer_raw = originals.descriptor(plan['materializer'], 65536)
    need(sha(materializer_raw) == MATERIALIZER, 'reviewed exact-boundary materializer required')
    m = module(materializer_raw, plan['materializer']['path'], 'host_fixed19_materializer')
    release_dir = Path(plan['release']['path']).absolute()
    need(set(plan['release']) == {'path', 'build_result_sha256'}, 'explicit sealed release required')
    result = m.validate_release(release_dir, plan['release']['build_result_sha256'])
    report = result['report']; binding = result['binding']; source = result['source']
    need(report['retirement_sha256'] == RETIREMENT and report['policy_sha256'] == POLICY,
         'actual retirement and Root-adopted policy required')
    consumer_manifest, consumers = source_manifest(originals, plan['consumer_manifest'])
    helper_raw = consumers['source/release_boundaries.py']
    helper = module(helper_raw, Path(plan['consumer_manifest']['path']).parent/'source/release_boundaries.py',
                    'host_fixed19_boundary_consumer')
    seal = strict(result['source_seal_raw']); operators = {x['path']: x for x in seal['operator_helpers']}
    for name in ('release_boundaries.py', 'collect_r10_readiness.py'):
        need(name in operators and operators[name] == dict(path=name, **pin(consumers['source/'+name])),
             'final release did not seal the explicit reviewed consumer: ' + name)
        originals.read(release_dir/'provider'/name, pin(consumers['source/'+name]))
    module_manifest_raw = originals.read(release_dir/'module/MODULE-MANIFEST-v150-r10-r1.json',
                                         maximum=1048576)
    need(sha(module_manifest_raw) == report['module_manifest_sha256'],
         'actual sealed module manifest differs')
    bundle_rows = [row for row in strict(module_manifest_raw)['files']
                   if row['path'] == 'evidence/RELEASE-BOUNDARIES.json']
    need(len(bundle_rows) == 1 and type(bundle_rows[0]['bytes']) is int
         and 0 < bundle_rows[0]['bytes'] <= 32*1024*1024
         and bundle_rows[0]['sha256'] == binding['release_boundary_bundle_sha256'],
         'one exact bounded release-boundary member required')
    bundle = originals.read(release_dir/'module/evidence/RELEASE-BOUNDARIES.json',
                            {k: bundle_rows[0][k] for k in ('bytes', 'sha256')},
                            maximum=bundle_rows[0]['bytes'])
    state = helper.validate_bundle(bundle, binding['release_boundary_bundle_sha256'], actual_context='mac')
    need(consumer_manifest['component_package_sha256'] == helper.PACKAGE_SHA,
         'component runtime and final consumer differ')
    component = originals.descriptor(plan['component_boundary_inputs'])
    adoption = originals.descriptor(plan['policy_adoption'])
    history_input = originals.descriptor(plan['policy_history_input'], 65536)
    history_value = strict(history_input)
    need(history_value['schema']=='hepta.native-guard.epoch-policy-history-input.v1'
         and enc(history_value['original_adoption'])==enc(plan['policy_adoption'])
         and state['epoch_policy_history']['input']==pin(history_input),
         'the exact new history input must retain the original adoption identity')
    shared = originals.descriptor(plan['shared_materials'])
    need(sha(adoption) == ADOPTION and sha(shared) == SHARED,
         'only actual reviewed shared bytes and explicit adopted export allowed')
    bundled = strict(bundle)
    need(strict(bundle)['inputs']['policy']['descriptor']==plan['policy_history_input'],
         'the sealed history input descriptor differs from the explicit host plan')
    for key, body in (('component', component), ('policy', history_input)):
        need(base64.b64decode(bundled['inputs'][key]['raw_b64'], validate=True) == body,
             'explicit original input differs from final release bundle')
    expected = {
        'component_boundary_inputs_sha256': sha(component),
        'policy_adoption_inputs_sha256': sha(adoption),
        'component_boundary_sha256': state['component_boundary_sha256'],
        'release_boundary_bundle_sha256': sha(bundle),
        'shared_materials_sha256': sha(shared), 'policy_sha256': POLICY,
    }
    need(all(binding.get(k) == report.get(k) == v for k, v in expected.items()),
         'actual final report and integration boundary fields differ')
    helper.validate_shared_materials(state, source, result['config_raw'], result['service_raw'])
    dependencies = helper.external_artifact_bindings(state, source, result['service_raw'])
    shared_value = strict(shared)
    material_bytes = {'provider/source/'+name: raw for name, raw in source.items()}
    material_bytes.update({'local-config-r10-r1.json': result['config_raw'],
        'PHONE-SERVICE-INPUTS-v150-r10-r1.json': result['service_raw']})
    need(len(shared_value['files']) == len(material_bytes) == 17
         and {x['path']: {k: x[k] for k in ('bytes', 'sha256')} for x in shared_value['files']}
            == {name: pin(body) for name, body in material_bytes.items()},
         'all final 17 material bytes must equal actual component shared materials')
    for entry in shared_value['files']:
        originals.read(Path(plan['shared_materials']['path']).parent/entry['path'],
                       {k: entry[k] for k in ('bytes', 'sha256')})
    actual_release = strict(originals.read(release_dir/'release.json', maximum=1048576))
    need(actual_release['boundary_consumer_sha256'] == sha(helper_raw)
         and actual_release['release_boundary_bundle']['sha256'] == sha(bundle)
         and actual_release['release_boundary_bundle']['bytes'] == len(bundle)
         and all(actual_release.get(k) == expected[k] for k in (
             'component_boundary_inputs_sha256', 'policy_adoption_inputs_sha256',
             'component_boundary_sha256', 'shared_materials_sha256', 'policy_sha256')),
         'install manifest boundary differs')
    helper.validate_external_inventory(dependencies, actual_release['verify_existing'], path_key='target')
    archive = report['archive']
    need(archive['path'] == str(release_dir/'phone-release-v150-r10-r1.tar.gz'),
         'final release archive path differs')
    originals.stream_pin(archive)
    client = originals.descriptor(plan['client'], 65536)
    need(pin(client) == {'bytes': 17390, 'sha256': CLIENT}, 'frozen client input differs')
    bind = originals.read(release_dir/'provider/bind_slot_cleanup.py',
                         {'bytes': 5669, 'sha256': BIND_HELPER}, 65536)
    need(operators['bind_slot_cleanup.py'] == dict(path='bind_slot_cleanup.py', **pin(bind)),
         'actual slot binding helper is not sealed')
    parents = {name: originals.read(REFERENCE/name, {'bytes': size, 'sha256': digest}, 65536)
               for name, (size, digest) in PARENTS.items()}
    protocol = strict(parents['inputs/protocol.json']); old = strict(parents['inputs/original-protocol.json'])
    need(all(protocol[k] == old[k] for k in ('cases', 'limits', 'qualified_geometry')),
         'retained fixed19 protocol cases drifted')
    cases = [x for x in old['cases'] if x['id'] in IDS]
    need(len(old['cases']) == 19 and len(cases) == 6
         and all(x['layer'] == 'host_isolated' for x in cases), 'official host-only case set differs')
    parent_binding = protocol.pop('r9_binding')
    protocol.update(set_id='stock16-phone-local-fixed-set-r10-r1',
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        candidate_manifest_sha256=sha(result['source_seal_raw']), executed_cases=0,
        current_global_blocker='Fresh final r10 fixed19 evidence required; no historical PASS inherited.')
    protocol['r10_binding'] = dict(schema='hepta.fixed19-metadata-binding.v150.r10.1',
        original_protocol_sha256=ORIGINAL, parent_public_protocol_sha256=PARENTS['inputs/historical-protocol-binding-r7-r3.json'][1],
        parent_r9_binding_original=parent_binding, actual_build_result_sha256=sha(result['report_raw']),
        combination_manifest_sha256=sha(result['binding_raw']), combination_sha256=result['combination_sha256'],
        provider_source_seal_sha256=sha(result['source_seal_raw']),
        module_manifest_sha256=report['module_manifest_sha256'],
        provider_config_sha256=sha(result['config_raw']), service_inputs_sha256=sha(result['service_raw']),
        **expected, full_production_combination_required=True,
        case_objects_limits_geometry_and_pass_conditions_unchanged=True, old_passes_inherited=False)
    protocol['adaptations'].append('R10 repeats the original six host_isolated cases against the exact final sealed 15-source/config/service combination. Legacy NEG12/13 template schemas remain unchanged; no new v150.3 scope credit is implied.')
    need(all(protocol[k] == old[k] for k in ('cases', 'limits', 'qualified_geometry')),
         'case contract changed while binding final release')
    protocol_raw = enc(protocol)
    inputs = {
        'BUILD-RESULT.json': result['report_raw'], 'client/tool_client_r6.py': client,
        'combination.json': result['binding_raw'], 'module-manifest.json': module_manifest_raw,
        'original-protocol.json': parents['inputs/original-protocol.json'],
        'historical-protocol-binding-r7-r3.json': parents['inputs/historical-protocol-binding-r7-r3.json'],
        'historical-host-protocol-r9-r2.json': parents['inputs/protocol.json'],
        'production-config.json': result['config_raw'], 'production-service-inputs.json': result['service_raw'],
        'protocol.json': protocol_raw, 'provider/SOURCE-SEAL.json': result['source_seal_raw'],
        'provider/bind_slot_cleanup.py': bind, 'SHARED-MATERIALS.json': shared,
    }
    inputs.update({'provider/source/'+name: raw for name, raw in source.items()})
    binding_summary = dict(schema='hepta.fixed19.r10.final-boundary-preflight.v1',
        state='ACTUAL_SEALED_INPUTS_VERIFIED_HOST_CASES_NOT_RUN',
        plan_sha256=sha(original_plan), preparer_sha256=plan['preparer_sha256'],
        consumer_manifest=plan['consumer_manifest'], actual_build_result_sha256=sha(result['report_raw']),
        production_source_count=15, all_17_shared_bytes_equal=True,
        combination_sha256=result['combination_sha256'], **expected,
        external_artifact_originals=dependencies, final_archive=archive,
        component_claim_ceiling='Closed component identities only; no four-role readiness inferred.',
        current_phone_state_observed=False, final_boundary_bundle_copied_to_p4=False,
        historical_passes_inherited=False, phone_calls=0, test_processes_started=0)
    inputs['FINAL-BOUNDARY-PREFLIGHT.json'] = enc(binding_summary)
    input_manifest = dict(schema='hepta.host-fixed19-r10-r1.inputs.v1',
        actual_build_result_sha256=sha(result['report_raw']), source_seal_sha256=sha(result['source_seal_raw']),
        combination_sha256=result['combination_sha256'], phone_calls=0,
        actual_model_inference=False, old_passes_inherited=False,
        files=[dict(name=name, **pin(body)) for name, body in sorted(inputs.items())])
    input_manifest_raw = enc(input_manifest)
    files = {'inputs/'+name: body for name, body in inputs.items()}
    files['inputs/MANIFEST.json'] = input_manifest_raw
    values = {'SEAL_SHA': sha(result['source_seal_raw']), 'COMBO_SHA': sha(result['binding_raw']),
              'COMBO_CANONICAL': result['combination_sha256'], 'PROTOCOL_SHA': sha(protocol_raw)}
    translations = []; patch = []
    for name in PARENTS:
        if not name.endswith('.py'):
            continue
        original = parents[name]; text = original.decode(); changes = []
        if name.endswith('/execute_namespace_once.py'):
            changes.extend([(OLD_P4, plan['p4_root'], 1),
                ('f81222a661c51f3efb732089ff3120202622d45d42f69dbf0bfe1bcc82d86514',
                 sha(input_manifest_raw), 1)])
        elif name.endswith(('host_negative_runner.py', 'service_negative_runner.py')):
            for key, previous in PIN_REPLACEMENTS.items():
                changes.append((key+"='"+previous+"'", key+"='"+values[key]+"'", 1))
        if name == 'service/service_negative_runner.py':
            need(sha(source['daily_phone_local.py']) == DAILY, 'actual final daily source differs')
            changes.append(('d0fbf365bc00101ab850f6147f7aa926a02aba085815064107dce577e2fd3baf', DAILY, 1))
        if 'v150.r9-r2.host-fixture.1' in text:
            changes.append(('v150.r9-r2.host-fixture.1', 'v150.r10-r1.host-fixture.1',
                            text.count('v150.r9-r2.host-fixture.1')))
        if name == 'component/host_negative_runner.py':
            changes.append(('Invoke frozen r9-r2 functions', 'Invoke frozen r10-r1 functions', 1))
        for old_text, new_text, count in changes:
            need(text.count(old_text) == count and old_text != new_text,
                 'exact parent source replacement count differs: '+name)
            text = text.replace(old_text, new_text)
        reverse = text
        for old_text, new_text, count in reversed(changes):
            need(reverse.count(new_text) == count, 'reverse source replacement ambiguous: '+name)
            reverse = reverse.replace(new_text, old_text)
        need(reverse.encode() == original, 'unreviewed harness logic change: '+name)
        compile(text, name, 'exec')
        files[name] = text.encode()
        translations.append(dict(path=name, parent=pin(original), derived=pin(files[name]),
                                 changed_literals=len(changes), reverse_exact=True))
        patch.extend(difflib.unified_diff(original.decode().splitlines(True), text.splitlines(True),
                                         fromfile='parent-r9/'+name, tofile='final-r10/'+name))
    need(set(plan['assets']) == set(ASSETS), 'two original synthetic fixture assets required')
    for name, (size, digest) in ASSETS.items():
        raw = originals.descriptor(plan['assets'][name], 65536)
        need(pin(raw) == {'bytes': size, 'sha256': digest}, 'original synthetic asset changed')
        files['component/assets/'+name] = raw
    guard = import_guard(originals)
    guarded, import_changes = guard.derive(files)
    for row in translations:
        name = row['path']; row['pin_translation_derived'] = row['derived']
        row['derived'] = pin(guarded[name]); row['import_only_changes'] = import_changes[name]
        row['import_only_reverse_exact'] = True
    files.update(guarded)
    patch = []
    for name in guard.SOURCE_NAMES:
        patch.extend(difflib.unified_diff(parents[name].decode().splitlines(True), files[name].decode().splitlines(True),
                     fromfile='parent-r9/'+name, tofile='final-r10-closed-imports/'+name))
    files['PARENT-TO-FINAL-INCREMENT.patch'] = ''.join(patch).encode()
    files['DERIVATION.json'] = enc(dict(schema='hepta.fixed19.r10.host-harness-derivation.v2',
        state='FINAL_PIN_AND_IMPORT_PROVENANCE_DERIVATION_NOT_TEST_RESULTS', translations=translations,
        cases=list(IDS), original_protocol_sha256=ORIGINAL,
        conditions_and_case_assertions_unchanged=True, original_namespace_isolation_flags_unchanged=True,
        case_python_child_arguments_changed_only_for_fresh_unused_cache=True,
        original_case_functions_replaced=False, import_guard_source_sha256=IMPORT_GUARD,
        controlled_import_trees=['inputs', 'component', 'service'],
        unindexed_entries_rejected=True, unused_bytecode_prefix=guard.PREFIX,
        legacy_template_schema_unchanged=True, production_sources_modified=False,
        phone_calls=0, tests_executed=0, prior_results_copied=False))
    files['EXECUTION-PLAN.json'] = enc(dict(schema='hepta.fixed19.r10.host-execution-plan.v1',
        p4_root=plan['p4_root'], automatic_execution=False, phone_calls=0,
        steps=[dict(group=group, cases=case_ids, argv=['/usr/bin/python3','-I','-B',
            plan['p4_root']+'/'+group+'/execute_namespace_once.py','--execute-once',
            '--attempt',group+'-attempt-01','--expected-runner-sha256',sha(files[group+'/'+runner])]
            + (['--expected-server-sha256',sha(files['service/fixture_server.py'])] if group=='service' else []),
            maximum_outer_seconds=60, automatic_retry=False)
            for group, runner, case_ids in [('component','host_negative_runner.py',list(IDS[1:5])),
                                           ('service','service_negative_runner.py',['NEG-06','NEG-14'])]],
        evidence_required=['original direct-child wait','namespace identity','source pins before/after',
            'all inner case receipts','bounded process cleanup and kernel ESRCH',
            'complete stdout/stderr and original file manifest',
            'IMPORT-TREE-PROVENANCE.json with closed trees and actual module origins'],
        qualification_scope='Six host_isolated layers only; no physical fault/model/business qualification.'))
    originals.recheck()
    return destination, files, binding_summary


def publish(destination, files):
    def sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    destination.mkdir(mode=0o700); sync(destination.parent)
    rows = []
    for name, raw in sorted(files.items()):
        rel = Path(name)
        need(str(rel) == name and not rel.is_absolute() and '..' not in rel.parts,
             'output path is not package relative')
        target = destination/rel; missing = []; parent = target.parent
        while parent != destination:
            missing.append(parent); parent = parent.parent
        for parent in reversed(missing):
            try: parent.mkdir(mode=0o700); sync(parent.parent)
            except FileExistsError:
                s=parent.lstat(); need(stat.S_ISDIR(s.st_mode) and not parent.is_symlink(),
                                     'output directory changed')
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        sync(target.parent)
        need(target.read_bytes() == raw and target.lstat().st_nlink == 1, 'output readback differs')
        rows.append(dict(path=name, **pin(raw)))
    manifest = enc(dict(schema='hepta.fixed19.r10.host-package.v2', files=rows,
        prepared_for_actual_final_release=True, production_sources_modified=False,
        phone_calls=0, tests_executed=0, historical_passes_inherited=False))
    fd = os.open(destination/'MANIFEST.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(manifest); stream.flush(); os.fsync(stream.fileno())
    sync(destination)
    return dict(path=str(destination/'MANIFEST.json'), **pin(manifest))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True); parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--execute-host-preparation', action='store_true')
    args = parser.parse_args(); os.umask(0o077)
    originals = Originals(); raw = originals.read(args.plan, maximum=65536)
    need(sha(raw) == args.plan_sha256, 'explicit plan SHA required')
    destination, files, binding = prepare(strict(raw), raw, originals)
    manifest = publish(destination, files) if args.execute_host_preparation else None
    print(json.dumps(dict(schema='hepta.fixed19.r10.host-preparation-result.v1',
        state='HOST_PACKAGE_PREPARED' if manifest else 'VALIDATED_PREVIEW_NO_OUTPUT',
        output_created=manifest is not None, manifest=manifest, file_count=len(files),
        binding=binding, fixed19_cases_executed=0, phone_calls=0,
        model_requests=0, native_tasks=0, automatic_retry=False), sort_keys=True))


if __name__ == '__main__':
    main()
