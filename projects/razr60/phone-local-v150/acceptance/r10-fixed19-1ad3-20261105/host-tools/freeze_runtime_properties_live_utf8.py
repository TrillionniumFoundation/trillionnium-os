#!/usr/bin/env python3
"""Freeze reviewed dependency literals plus the strict UTF-8 stage codec increment.

Host files only: no subprocess, network, phone, policy parser, policy load, or
production main is called.  Default previews all checks; --execute-host-freeze
creates one new directory.  Existing source and evidence are never overwritten.
"""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

BASE = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
SOURCE_NAME = 'policy-runtime-properties-r10-live-operator-r1-candidate01'
MIRROR_NAME = 'root-fixed19-1ad3-20261105-r1/offline'
OLD_TRANSPORT = {'bytes': 43438, 'sha256': '860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'}
SOURCE_MANIFEST = (3097, '64e8691043191bcfe98d79567cffcfe826996ce6497a7bcb036de68147aba7d0')
SOURCE_PINS = {
 'apply_runtime_properties_once.template.sh': (2444, 'b4425ff52a2db80621294a245c2675ade7f54bd77831765ce664443a5478d291'),
 'capture_runtime_properties_originals.py': (12901, 'cc08f1dac1a65326f638b2fc6633dba394646fae6427aa3b411828d2c0f8989e'),
 'guard_live_runtime_properties.py': (44161, '08f3285523b7aa58300d2eb86f9074796358ca8b9cf7c2f7709155ded565f515'),
 'make_runtime_properties_adoption.py': (2874, 'c6b9e5ca36912110056fd1052c037d4e3e11c39a70231e1e04123c6b5a12b25b'),
 'make_runtime_properties_adoption_inputs.py': (5891, '014cff239d95be5996f34920f459ccc3caa7f2bdac48957d2c6242fd84853fce'),
 'make_runtime_properties_expectation.py': (2542, '0be68bd31cf3cbca819eaeba1b88d9860bc11290b51dd2bcca1db1ef8cfa0f9f'),
 'runtime_properties_host_originals.py': (3276, '4ac6ab61989ed541b9f690bdcee8418cf5457b4da389cca03ab3acdc86dfb487'),
 'policy_runtime_properties_verifier.py': (103498, '417a81e312babb8ae12ddb98fd4ae9f4d7ba348cf2fc4180964800f53e65fcd3'),
 'prepare_live_runtime_properties.py': (19062, 'e2f6b6bc3ca60f53ace8259ce8d610423a454d3279df5f596313c56626077b7d'),
}
REPORT_PIN = (378604, '149c5063d98b3b7674364e34b98465c387d8f187fe1f26d3060ebf0e75c739cf')
EXECUTION_PIN = (2800, 'e3ccc2b642900e9e1be62bd25bded6d74889249c5c8273cc438b2e9ceaa0f559')
CANDIDATE_PIN = {'bytes': 2667740, 'sha256': '105ee3f837cd2225a5528eab18bad63f4efa31244b22ec02259acd21d8a5c1ee'}
POST_PIN = (64188, '151a1d724a82d611202054eb0dd5326fe4f4311ff78599b61c6bf58d68a2cf8f')
RUNNER_PIN = (21915, '434f954b493c1aadc90929dbc8bba894ffec8acb5f17420746cc520aecac94e9')
POST_RUNNER_PIN = (9767, '0f6cb3d1a73a59f880566f5adc1afaa285fcb5366ceebf3a5373caf3167518a1')
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def bp(value):
    return {key: value[key] for key in ('bytes', 'sha256')}


def desc(path, pin):
    return {'path': str(path), 'bytes': pin[0], 'sha256': pin[1]}


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self, row):
        need(type(row) is dict and set(row) == {'path','bytes','sha256'}, 'exact descriptor required')
        p = Path(row['path'])
        need(p.is_absolute() and '..' not in p.parts and p.resolve(strict=True) == p, 'canonical input path')
        need(type(row['bytes']) is int and 0 <= row['bytes'] <= 32*1024*1024
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'bounded input descriptor')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            start = os.fstat(fd)
            need(stat.S_ISREG(start.st_mode) and start.st_nlink == 1 and start.st_size == row['bytes'], 'original file kind/size')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes'] + 1)
            after, named = os.fstat(fd), p.lstat()
            identity = [getattr(start, k) for k in META]
            need(identity == [getattr(after,k) for k in META] == [getattr(named,k) for k in META], 'original read raced')
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'original bytes differ: ' + str(p))
        finally:
            os.close(fd)
        record = {'descriptor': row, 'metadata': identity}
        need(str(p) not in self.seen or self.seen[str(p)] == record, 'original changed across reads')
        self.seen[str(p)] = record
        return raw

    def check(self):
        for value in list(self.seen.values()):
            self.read(value['descriptor'])


def literal(source, name):
    rows = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name]
    need(len(rows) == 1, 'one top-level literal required: ' + name)
    return ast.literal_eval(rows[0].value)


def replace_once(source, old, new, edits):
    need(source.count(old) == 1 and old != new, 'one exact source increment required')
    edits.append((old, new))
    return source.replace(old, new, 1)


def fill(source, name, value, edits, expected=None):
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, 'unique fixed declaration: ' + name)
    node = nodes[0]
    need(node.lineno == node.end_lineno and ast.literal_eval(node.value) == expected,
         'unreviewed declaration or already-filled literal: ' + name)
    line = source.splitlines(keepends=True)[node.lineno-1]
    new = line[:node.value.col_offset] + repr(value) + line[node.value.end_col_offset:]
    return replace_once(source, line, new, edits)


def upgrade_stage_codec(final, edits, *, literal, replace_once, fill, need):
    pname = 'prepare_live_runtime_properties.py'
    vname = 'policy_runtime_properties_verifier.py'
    old_final = literal(final[pname], 'STAGE_FINAL')
    need(literal(final[vname], 'STAGE_FINAL') == old_final,
         'prepare and verifier original stage-final programs differ')
    before = "    env=encoded({k:base64.b64encode(v).decode('ascii') for k,v in sorted(files.items())})\n"
    after = ("    text_files={k:v.decode('utf-8',errors='strict') for k,v in sorted(files.items())}\n"
             "    need(all(text_files[k].encode('utf-8',errors='strict')==v for k,v in files.items()),\n"
             "        'strict UTF-8 staged originals must round-trip byte exactly')\n"
             "    env=encoded(text_files)\n")
    final[pname] = replace_once(final[pname], before, after, edits[pname])
    before = "    stage={'schema':'hepta.runtime-properties-r10.code-stage-intent.v1','binding_sha256':binding_sha,\n"
    after = before + "        'envelope_encoding':'strict-utf8-json-v1',\n"
    final[pname] = replace_once(final[pname], before, after, edits[pname])
    before = ("value=json.loads(raw,object_pairs_hook=pairs)\n"
              "need(set(value)==set(STAGE['files']),'exact reviewed staged file set')\n"
              "files={k:base64.b64decode(v,validate=True) for k,v in value.items()}\n")
    after = ("need(STAGE.get('envelope_encoding')=='strict-utf8-json-v1','exact stage envelope encoding')\n"
             "value=json.loads(raw.decode('utf-8',errors='strict'),object_pairs_hook=pairs)\n"
             "need(type(value) is dict and all(type(v) is str for v in value.values())\n"
             " and set(value)==set(STAGE['files']),'exact reviewed UTF-8 staged file set')\n"
             "files={k:v.encode('utf-8',errors='strict') for k,v in value.items()}\n")
    final[pname] = replace_once(final[pname], before, after, edits[pname])
    new_final = literal(final[pname], 'STAGE_FINAL')
    final[vname] = fill(final[vname], 'STAGE_FINAL', new_final, edits[vname], expected=old_final)
    before = "    stage_raw=files['STAGE-INTENT.original.json'];stage=strict(stage_raw);complete=strict(files['STAGE-COMPLETE.original.json'])\n"
    after = before + "    need(stage.get('envelope_encoding')=='strict-utf8-json-v1','exact stage envelope encoding')\n"
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    before = "    bytes_match(plain,stage['plain']);envelope=strict(plain)\n"
    after = "    bytes_match(plain,stage['plain']);plain.decode('utf-8',errors='strict');envelope=strict(plain)\n"
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    before = "    need(set(envelope)==set(stage['files'])==expected_names and complete['files']==stage['files'],\n"
    after = ("    need(type(envelope) is dict and all(type(value) is str for value in envelope.values())\n"
             "        and set(envelope)==set(stage['files'])==expected_names and complete['files']==stage['files'],\n")
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    before = "        raw=base64.b64decode(value,validate=True);bytes_match(raw,stage['files'][name])\n"
    after = "        raw=value.encode('utf-8',errors='strict');bytes_match(raw,stage['files'][name])\n"
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    need(literal(final[pname], 'STAGE_FINAL') == literal(final[vname], 'STAGE_FINAL'),
         'new prepare and verifier stage-final programs differ')
    for name in ('STAGE_BASE', 'STAGE_PART'):
        need(literal(final[pname], name) == literal(final[vname], name),
             'unchanged stage prefix/part verifier program differs')


def preparation_inputs(B, V, report_desc, reader):
    locations = {
      'root_scope_decision': (B/'policy-runtime-properties-r10-r1-root-decision01/DECISION.json', V.DECISION),
      'parent_adoption_history': (B/'policy-native5-r10-live-root-02/POLICY-ADOPTION.json', V.PARENT_ADOPTION),
      'retirement_descriptor': (B/'module-r10-r1-retirement-reconciliation-01/ACTUAL-RETIREMENT-INPUTS.json', V.RETIREMENT_DESCRIPTOR),
      'retirement_host_closure': (B/'module-r10-r1-retirement-reconciliation-01/HOST-CLOSURE.json', V.RETIREMENT_HOST_CLOSURE),
      'latest_boundary_descriptor': (B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/LATE-BOUNDARY-DESCRIPTOR.json', V.BOUNDARY_DESCRIPTOR),
      'component_package': (B/'native-guard-r10-r1-operator-r7/runtime/MANIFEST.json', V.PACKAGE),
      'parent_rule': (B/'policy-native5-r10-live-root-02/capture/originals/full-candidate.rule', V.PARENT_RULE),
      'full_rule': (B/'policy-runtime-properties-r10-r1-source-final02/rules/full.rule', V.FULL_RULE),
    }
    plan = {'schema': 'hepta.runtime-properties-r10.live-preparation-inputs.v1',
            'complete_offline_comparison': report_desc}
    for key, (path, pin) in locations.items():
        row = {'path': str(path), **bp(pin)}
        reader.read(row)
        plan[key] = row
    package_root = Path(plan['component_package']['path']).parent
    for name, pin in V.COMPONENT_SOURCE_PINS.items():
        reader.read({'path': str(package_root/name), **bp(pin)})
    history = []
    for record in V.CLOSED_HISTORY:
        attempt = record['attempt']
        if attempt == '03':
            directory = B/'native-guard-attempt03-external-publication-r1/actual-02/originals'
            names = {'boundary': 'BOUNDARY.original.json', 'closure': 'CLOSURE.original.json',
                     'inventory': 'AFTER-INVENTORY.original.json'}
        else:
            day = '20261104' if attempt == '04' else '20261105'
            directory = B/'native-guard-root-chains-r10-r1'/('root-r10-neg01-'+day+'-'+attempt)
            names = {'boundary': 'LATE-BOUNDARY.original.json', 'closure': 'CLOSURE.json', 'inventory': 'INVENTORY.json'}
        item = {key: {'path': str(directory/name), **bp(record[key])} for key, name in names.items()}
        for row in item.values():
            reader.read(row)
        history.append(item)
    plan['native_history'] = history
    side_names = {'proof': 'attempt05-SIDE-PROOF.original.json', 'closure': 'attempt05-CLOSURE.original.json',
                  'inventory': 'attempt05-AFTER-INVENTORY.original.json'}
    plan['non_native_originals'] = {key: {'path': str(package_root/'reference'/name), **bp(V.NON_NATIVE_BINDING[key])}
                                    for key, name in side_names.items()}
    for row in plan['non_native_originals'].values():
        reader.read(row)
    return plan


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=Path(BASE))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--root-transport-desc', required=True, help='reviewed final JSON path/bytes/sha256 descriptor')
    parser.add_argument('--root-driver-desc', required=True, help='reviewed final JSON descriptor for the two-loader driver')
    parser.add_argument('--root-source-package-desc', required=True, help='reviewed final JSON descriptor for the exact three-source manifest')
    parser.add_argument('--execute-host-freeze', action='store_true')
    args = parser.parse_args(argv)
    B, out = args.base, args.out
    need(B.is_absolute() and B.resolve(strict=True) == B, 'canonical existing project root')
    need(out.is_absolute() and out.parent.resolve(strict=True) == out.parent and not out.exists()
         and not out.is_symlink(), 'one new canonical candidate output')
    reader = Originals()
    source_manifest_desc = desc(B/SOURCE_NAME/'SOURCE-MANIFEST.json', SOURCE_MANIFEST)
    source_manifest_raw = reader.read(source_manifest_desc)
    old_manifest = strict(source_manifest_raw)
    need({r['path']: bp(r) for r in old_manifest['files']} == {
        'source/'+n: {'bytes': p[0], 'sha256': p[1]} for n,p in SOURCE_PINS.items()}, 'reviewed original nine-source inventory')
    original = {n: reader.read(desc(B/SOURCE_NAME/'source'/n, pin)) for n,pin in SOURCE_PINS.items()}
    final = {n: raw.decode('utf-8') for n,raw in original.items()}
    edits = {n: [] for n in final}
    report_desc = desc(B/MIRROR_NAME/'OFFLINE-COMPLETE-COMPARISON.original.json', REPORT_PIN)
    report_raw = reader.read(report_desc); report = strict(report_raw)
    execution_desc = desc(B/MIRROR_NAME/'OFFLINE-EXECUTION.original.json', EXECUTION_PIN)
    execution = strict(reader.read(execution_desc))
    need(bp(report['candidate']) == CANDIDATE_PIN and execution['candidate'] == report['candidate']
         and bp(execution['report']) == bp(report_desc) and execution['check_count'] == execution['passed_count'] == 16,
         'actual report/execution/candidate relationship differs')
    refs = B/'policy-runtime-properties-r10-r1-source-final02/source'
    post_desc = desc(refs/'post_live_compare_runtime_properties.py', POST_PIN)
    runner_desc = desc(refs/'run_runtime_properties_actual.py', RUNNER_PIN)
    post_runner_desc = desc(refs/'run_post_live_actual.py', POST_RUNNER_PIN)
    for row in (post_desc, runner_desc, post_runner_desc):
        reader.read(row)
    need(bp(execution['source']) == bp(runner_desc), 'actual offline runner source differs')
    root_transport = strict(args.root_transport_desc)
    root_driver = strict(args.root_driver_desc)
    root_manifest_desc = strict(args.root_source_package_desc)
    root_manifest = strict(reader.read(root_manifest_desc)); root_dir = Path(root_manifest_desc['path']).parent
    expected = {'source/run_runtime_properties_policy_once.py': bp(root_driver),
                'source/run_component_root_once.py': bp(root_transport),
                'reference/run_component_root_once.r4.original.py': OLD_TRANSPORT}
    need(root_manifest['schema'] == 'hepta.root.runtime-properties-live-source-package.v1'
         and len(root_manifest['files']) == 3 and {r['path']: bp(r) for r in root_manifest['files']} == expected,
         'exact original validator plus new execution transport package required')
    need(Path(root_driver['path']) == root_dir/'source/run_runtime_properties_policy_once.py'
         and Path(root_transport['path']) == root_dir/'source/run_component_root_once.py', 'Root package source locations differ')
    for name,pin in expected.items():
        raw = reader.read({'path': str(root_dir/name), **pin})
        compile(raw, str(root_dir/name), 'exec')
    vname = 'policy_runtime_properties_verifier.py'
    replacements = {
        'REVIEWED_OFFLINE_COMPARISON': bp(report_desc),
        'REVIEWED_COMPARISON_SOURCES': report['sources'],
        'REVIEWED_POST_COMPARATOR_SOURCE': bp(post_desc),
        'REVIEWED_COMPARISON_RUNNERS': {'offline_candidate': bp(runner_desc), 'post_live_export': bp(post_runner_desc)},
        'REVIEWED_PARENT_READ_AV_PINS': [r['sha256'] for r in report['full_av_checks']['parent_original_compute_av']],
        'REVIEWED_PARENT_SET_AV_PINS': [r['sha256'] for r in report['full_av_checks']['parent_original_set_av']],
        'ROOT_DRIVER': bp(root_driver), 'ROOT_SOURCE_PACKAGE': bp(root_manifest_desc),
    }
    for key,value in replacements.items():
        final[vname] = fill(final[vname], key, value, edits[vname])
    final[vname] = fill(final[vname], 'ROOT_TRANSPORT_SOURCE', bp(root_transport), edits[vname], expected=OLD_TRANSPORT)
    before = ("    expected={'source/run_runtime_properties_policy_once.py':ROOT_DRIVER,\n"
              "        'reference/run_component_root_once.r4.original.py':ROOT_TRANSPORT_SOURCE}\n"
              "    need(len(source_package['files'])==2 and {r['path'] for r in source_package['files']}==set(expected),")
    after = ("    expected={'source/run_runtime_properties_policy_once.py':ROOT_DRIVER,\n"
             "        'source/run_component_root_once.py':ROOT_TRANSPORT_SOURCE,\n"
             "        'reference/run_component_root_once.r4.original.py':" + repr(OLD_TRANSPORT) + "}\n"
             "    need(len(source_package['files'])==3 and {r['path'] for r in source_package['files']}==set(expected),")
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    upgrade_stage_codec(final, edits, literal=literal, replace_once=replace_once, fill=fill, need=need)
    verifier_hash = sha(final[vname].encode())
    for name in ('guard_live_runtime_properties.py', 'runtime_properties_host_originals.py'):
        final[name] = fill(final[name], 'VERIFIER_SHA256', verifier_hash, edits[name])
    guard_hash = sha(final['guard_live_runtime_properties.py'].encode())
    support_hash = sha(final['runtime_properties_host_originals.py'].encode())
    for name in ('prepare_live_runtime_properties.py', 'capture_runtime_properties_originals.py'):
        final[name] = fill(final[name], 'GUARD_SHA256', guard_hash, edits[name])
    for name in ('make_runtime_properties_expectation.py', 'make_runtime_properties_adoption.py',
                 'make_runtime_properties_adoption_inputs.py'):
        final[name] = fill(final[name], 'HOST_SUPPORT_SHA256', support_hash, edits[name])
    for name, text in final.items():
        if name.endswith('.py'):
            compile(text, str(out/'source'/name), 'exec')
        restored = text
        for old,new in reversed(edits[name]):
            need(restored.count(new) == 1, 'exact reverse increment is ambiguous')
            restored = restored.replace(new, old, 1)
        need(restored.encode() == original[name], 'source increment differs from the exact reviewed reversible edits')
    need(len(final[vname].encode()) <= 131072, 'frozen verifier exceeds existing smallest consumer limit')
    V = types.ModuleType('reviewed_final_runtime_property_pure_verifier')
    V.__file__ = str(out/'source'/vname); V.__reviewed_source_sha256__ = verifier_hash
    exec(compile(final[vname], V.__file__, 'exec'), V.__dict__)
    decision_raw = reader.read(old_manifest['root_scope_decision'])
    V.verified_offline(report_raw, decision_raw)
    prep = preparation_inputs(B, V, report_desc, reader)
    reader.check()
    new_files = [{'path': 'source/'+n, 'bytes': len(t.encode()), 'sha256': sha(t.encode())}
                 for n,t in sorted(final.items())]
    summary = {'state': 'REVIEWED_LITERAL_FREEZE_READY_HOST_ONLY', 'source_files': new_files,
               'verifier_sha256': verifier_hash, 'guard_sha256': guard_hash,
               'root_source_count': 3, 'literal_and_exact_package_binding_increment_only': False,
               'source_increment_scope': ['reviewed_dependency_literals', 'exact_three_source_package', 'strict_utf8_stage_codec'],
               'stage_envelope_encoding': 'strict-utf8-json-v1',
               'stage_budget_increase': False,
               'exact_reverse_source_check': True, 'offline_report_pure_validation_passed': True,
               'preparation_inputs': {'bytes': len(enc(prep)), 'sha256': sha(enc(prep))},
               'phone_calls': 0, 'policy_parser_calls': 0, 'policy_writes': 0,
               'host_preparation_executed': False, 'native_or_business_qualification': False}
    if not args.execute_host_freeze:
        print(json.dumps(summary, sort_keys=True)); return 0
    os.umask(0o077); out.mkdir(mode=0o700)
    for directory in ('source','reference','validation'):
        (out/directory).mkdir(mode=0o700)
    create(out/'reference/PARENT-SOURCE-MANIFEST.original.json', source_manifest_raw)
    for name,text in final.items():
        create(out/'source'/name, text.encode())
    patch = ''.join(''.join(difflib.unified_diff(original[n].decode().splitlines(True), final[n].splitlines(True),
                     fromfile='candidate01/source/'+n, tofile='frozen/source/'+n)) for n in sorted(final)).encode()
    patch_desc = create(out/'validation/LITERAL-INCREMENT.patch', patch)
    manifest = dict(old_manifest)
    manifest.update(state='EXACT_REVIEWED_LITERAL_DEPENDENCIES_AND_UTF8_STAGE_FROZEN_HOST_ONLY', files=new_files,
                    stage_envelope_encoding='strict-utf8-json-v1', stage_budget_increase=False,
                    future_comparison_driver_source_pins={**replacements, 'ROOT_TRANSPORT_SOURCE': bp(root_transport)},
                    increment=patch_desc)
    manifest_desc = create(out/'SOURCE-MANIFEST.json', enc(manifest))
    prep_desc = create(out/'PREPARATION-INPUTS.json', enc(prep))
    entry = {'schema': 'hepta.runtime-properties.host-preparation-entry.v1', 'executable': '/usr/bin/python3',
             'argv': ['-I','-B',str(out/'source/prepare_live_runtime_properties.py'),
                      '--inputs',prep_desc['path'],'--inputs-sha256',prep_desc['sha256'],
                      '--out',str(out/'prepared-01'),'--execute-host-preparation'],
             'phone_calls': 0, 'policy_writes': 0, 'automatic_retry': False}
    create(out/'PREPARATION-ENTRY.json', enc(entry))
    reader.check()
    result = {**summary, 'state': 'EXACT_LITERAL_SOURCE_FREEZE_AND_PREPARATION_INPUTS_WRITTEN_HOST_ONLY',
              'source_manifest': manifest_desc, 'preparation_inputs': prep_desc,
              'root_driver_source': root_driver, 'root_transport_source': root_transport,
              'root_source_package': root_manifest_desc, 'offline_comparison': report_desc,
              'offline_execution': execution_desc, 'original_bookends': list(reader.seen.values())}
    result_desc = create(out/'validation/FREEZE-RESULT.json', enc(result))
    print(json.dumps({'state': result['state'], 'source_manifest': manifest_desc,
                      'preparation_inputs': prep_desc, 'result': result_desc, 'entry': entry,
                      'phone_calls': 0, 'policy_writes': 0}, sort_keys=True)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
