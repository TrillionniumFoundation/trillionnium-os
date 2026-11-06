#!/usr/bin/env python3
"""Explicit r10 preservation and policy inputs; imports perform no phone work.

The builder embeds exact reviewed originals in a bounded bundle. Runtime readers
verify that same bundle and compare observations with its adopted values. No
function discovers an acceptable policy hash, changes policy, publishes a late
boundary, sends a signal, starts a service or supplies a component qualification.
"""
import ast
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
import zlib

BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
RELEASE = 'v150-r10-r1'
PARENT_POLICY = 'bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38'
CANDIDATE_POLICY = '1b1513ced8c62f4ac592ae955fe1eaf385b98db06a4e30add741255e24e9be16'
PARENT_RULE = '30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8'
DELTA_RULE = 'ecf74e374f1e34dea958e9ce7298358dbf2e0fd1e1a988994da16f776411d120'
FULL_RULE = 'dd9303a46c0016c98cce26b8a2fa199e045038f70148817d72fa6034e86dd0e3'
ATOM = ['allow', 'trillionnium_owner_open_phone_worker', 'hal_graphics_allocator_default', 'fd', 'use']
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
ANDROID_BASE = '/data/trillionnium/owner-open/state/phone-local-v150'
MODULE = '/data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
INSTALL_DIRECTORY = BASE + '/executor-r6/module-history-r10-r1'
INSTALL_LABEL = 'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0'
# Source-only candidate. Finalization must bind the independently reviewed
# current runtime, including its one exact published failed ancestor record.
# Caller inputs cannot supply this trust pin.
PACKAGE_SHA = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'
PACKAGE_FILE_COUNT = 37
CURRENT_COMBINATION_SHA = '02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'
POLICY_VERIFIER_SHA = '6a3a9f8278ccf4b29724d9d034b4a349127a77d0adfd4daa8066ef6aa8d6c35b'
POLICY_VERIFIER_BYTES = 65591
MAX_ORIGINAL = 16 * 1024 * 1024
MAX_BUNDLE = 32 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMPONENT_FIELDS = {'schema', 'release_id', 'boot_id', 'component_package_manifest',
    'component_package_files', 'component_combination', 'latest_boundary',
    'publish_result', 'retirement', 'originals', 'pre_policy_ancestor', 'non_native_sidebranch',
    'environment_parent_ancestor', 'property_parent_ancestors', 'diagnostic_parent_ancestor', 'codec_diagnostic_parent_ancestor', 'non_native_sidebranches', 'stack_diagnostic_parent_ancestor', 'v3_runtime_diagnostic_ancestor', 'retained_unstarted_stage'}
POLICY_FIELDS = {'schema', 'release_id', 'boot_id', 'comparison_route', 'parent',
    'candidate', 'actual_export', 'parent_rule', 'delta_rule', 'full_rule',
    'offline_result', 'offline_comparison', 'pre_live_expectation',
    'live_operation', 'live_originals', 'post_live_comparison', 'retirement_sha256',
    'prior_boundary_sha256', 'root_decision'}
LIVE_GUARD_SHA = '2f657aea0712db933ffe3a2e3c86fdc488fdad98576289defb4c79dfa320d67d'
LIVE_OPERATION_DIRECTORY = BASE + '/policy-fd-use-r10-live-01'
LIVE_ARGV = ['/data/adb/magisk/magiskpolicy', '--live', '--apply',
             ANDROID_BASE + '/policy-fd-use-r10-live-01/fd-use.delta.rule']


PROPERTY_PARENT_HOST_ORIGINALS = {'attempt08': {'root_result': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ROOT-RESULT.json', 'bytes': 33037, 'sha256': '077464376f2bf749b107587357df1c155a35f060b1f9a35a4865866af46b449d'}, 'package_manifest': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r7/runtime/MANIFEST.json', 'bytes': 13446, 'sha256': '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'}, 'combination': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/material/tree/inputs/COMBINATION.json', 'bytes': 4702, 'sha256': 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'}, 'previous': {'bytes': 1428, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ACTUAL-PREVIOUS-INPUT.json', 'sha256': '9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4'}, 'publication_operation': {'bytes': 2247, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phone-late-publish/stdout.original', 'sha256': '4711eac0b44f3b27fab0087673025106a9f72c06c5ffc4a74f2b3b767e265b27'}, 'publication_stderr': {'bytes': 0, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phone-late-publish/stderr.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'recovery_result': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/RECOVERY-RESULT.json', 'bytes': 3542, 'sha256': '05393775027b5f5356bcc13d8a55fe294d4f4d1caebaec7b9c14240bb980b95d'}, 'recovery_source': {'bytes': 57649, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt08-recovery-source-r2/source/resume_failed_component08.py', 'sha256': 'fbbcebafa882c827e5afd9bed42f89a0c9490c179df6d397a1febe1a5478ba54'}, 'recovery_intent': {'bytes': 153632, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/RECOVERY-INTENT.json', 'sha256': '7dd15cffd64c9cbeba38ae033c7b4d17cc8c16e4d3acb3946f8a23bf88178983'}, 'original_root_failure': {'bytes': 9217, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ROOT-FAILURE.json', 'sha256': 'eb6cd1bc8cb41987a4f8aee655217dfb57a18592788f1f7bd15276f44225a411'}, 'original_continuation_failure': {'bytes': 8876, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phase-continuation-01/FAILURE.json', 'sha256': '80230e449a68dec9cac8842b8cd7bcb2a589fc0c8d22ed86018915e5e9c8e2b6'}, 'original_capture_failure_observation': {'bytes': 35850, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/capture-originals-01/SUMMARY.json', 'sha256': '58abff5d3f9812628f67eb73c7ea1cd38dfc08d059ffed2e11af1fa3de0e7547'}}, 'attempt07': {'root_result': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/ROOT-RESULT.json', 'bytes': 25619, 'sha256': 'd55f69da18d973593bc04364960a649d3ab3b8916603dd6ab503024f8d66d6ce'}, 'package_manifest': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r7/runtime/MANIFEST.json', 'bytes': 13446, 'sha256': '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'}, 'combination': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/material/tree/inputs/COMBINATION.json', 'bytes': 4702, 'sha256': 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'}, 'previous': {'bytes': 1428, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/ACTUAL-PREVIOUS-INPUT.json', 'sha256': 'a336af9970df89ea757b4135852060bb98eea76adfe9be103adaa29bcaf7d17e'}, 'publication_operation': {'bytes': 2247, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/phone-late-publish/stdout.original', 'sha256': '333ad2d0a08f8bc317579e02d5c20beb0f91e68de28a8347be0b8ad654f81d64'}, 'publication_stderr': {'bytes': 0, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/phone-late-publish/stderr.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'recovery_result': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/RECOVERY-RESULT.json', 'bytes': 2753, 'sha256': '7d5f5afa93214810253fcb11112fdf2a8c0cbf1b5614cf2f1054a9d73c0b18c7'}, 'recovery_source': {'bytes': 34181, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt07-recovery-source-r1/source/resume_failed_component07.py', 'sha256': '9d7aa01ef0f5940112cf52bb994bc8cd01ab7bfde7875f457ec91962c3b4e092'}, 'recovery_intent': {'bytes': 83179, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/RECOVERY-INTENT.json', 'sha256': '8ba684c287a337be0bf141b3cb046c423c6b01532503b989e94b2c44ef6f4e7a'}, 'original_root_failure': {'bytes': 10055, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/ROOT-FAILURE.json', 'sha256': 'a7a3ca03472a435ce3595c3a688ff339b7786a08c1bfbd5c1bd8552f369683f0'}}}
CURRENT_POLICY_SHA = '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
CURRENT_POLICY_ADOPTION_SHA = '98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'
CURRENT_SCOPE_DECISION_SHA = 'b9d163938dca91171a8eeb8d9ddd6b394580effd2987f34a661d3687c1ee4ba9'

def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _v: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def descriptor(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def meta(value):
    return [getattr(value, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def file_descriptor(row):
    need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'},
         'exact host original descriptor required')
    p = Path(row['path'])
    need(p.is_absolute() and str(p) == row['path'] and '..' not in p.parts,
         'canonical original path required')
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_ORIGINAL
         and isinstance(row['sha256'], str) and HASH.fullmatch(row['sha256']),
         'bounded original bytes/hash required')
    return row


def read_pinned(row):
    file_descriptor(row)
    p = Path(row['path'])
    need(p.resolve(strict=True) == p, 'host original path is not canonical')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == row['bytes'], 'host original metadata differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(row['bytes'] + 1)
        need(meta(before) == meta(os.fstat(fd)) == meta(p.lstat())
             and descriptor(raw) == {k: row[k] for k in ('bytes', 'sha256')},
             'host original changed or differs')
        return raw, meta(before)
    finally:
        os.close(fd)


def descriptors(value):
    """Walk only the separately pinned input descriptor, not arbitrary reports."""
    if isinstance(value, dict):
        if set(value) == {'path', 'bytes', 'sha256'}:
            yield file_descriptor(value)
        else:
            for child in value.values():
                yield from descriptors(child)
    elif isinstance(value, list):
        for child in value:
            yield from descriptors(child)


def pack_original(raw):
    """Lossless host encoding; raw byte identity and all size bounds stay explicit."""
    need(type(raw) is bytes and len(raw) <= MAX_ORIGINAL, 'bounded original bytes required')
    compressed = zlib.compress(raw, 9)
    smaller = 4 * ((len(compressed) + 2) // 3) + 1 < 4 * ((len(raw) + 2) // 3)
    field, body = ('zlib_b64', compressed) if smaller else ('raw_b64', raw)
    return {'bytes': len(raw), field: base64.b64encode(body).decode()}


def original_from(bundle, row):
    file_descriptor(row)
    item = bundle['originals'].get(row['sha256'])
    need(type(item) is dict and set(item) in ({'bytes', 'raw_b64'}, {'bytes', 'zlib_b64'}),
         'original is missing or its encoding fields differ')
    need(type(item['bytes']) is int and item['bytes'] == row['bytes'],
         'bundled original declared byte count differs')
    field = 'zlib_b64' if 'zlib_b64' in item else 'raw_b64'
    encoded = item[field]
    need(type(encoded) is str and len(encoded) <= 4 * ((row['bytes'] + 2) // 3),
         'original encoding exceeds its declared raw byte bound')
    body = base64.b64decode(encoded, validate=True)
    need(base64.b64encode(body).decode() == encoded, 'noncanonical original encoding')
    if field == 'zlib_b64':
        need(0 < len(body) < row['bytes'], 'compressed original must be smaller than its raw bytes')
        decoder = zlib.decompressobj()
        raw = decoder.decompress(body, row['bytes'] + 1)
        need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
             'compressed original must be one complete stream without extra data')
    else:
        raw = body
    need(item['bytes'] == len(raw) == row['bytes'] and sha(raw) == row['sha256'],
         'bundled original bytes/hash differ')
    return raw


def prepare_bundle(component_input, policy_input):
    """Host-only: collect exact originals, then run the shared pure checks."""
    inputs = {}; originals = {}; observed = {}
    for name, row in (('component', component_input), ('policy', policy_input)):
        raw, metadata = read_pinned(row)
        observed[row['path']] = (row, metadata)
        value = strict(raw)
        inputs[name] = {'descriptor': row, 'raw_b64': base64.b64encode(raw).decode()}
        for source in descriptors(value):
            body, identity = read_pinned(source)
            previous = observed.get(source['path'])
            need(previous is None or previous == (source, identity), 'input path changed between references')
            observed[source['path']] = (source, identity)
            item = pack_original(body)
            need(source['sha256'] not in originals or originals[source['sha256']] == item,
                 'duplicate digest has different original bytes')
            originals[source['sha256']] = item
    value = {'schema': 'hepta.r10.release-boundary-bundle.v2',
             'inputs': inputs, 'originals': originals}
    raw = encode(value)
    need(len(raw) <= MAX_BUNDLE, 'reviewed release evidence bundle exceeds fixed bound')
    state = validate_bundle(raw, sha(raw))
    for row, identity in observed.values():
        _body, after = read_pinned(row)
        need(identity == after, 'host original changed while preparing bundle')
    return raw, state


def input_value(bundle, name):
    row = bundle['inputs'][name]
    need(set(row) == {'descriptor', 'raw_b64'}, 'input bundle fields differ')
    file_descriptor(row['descriptor'])
    raw = base64.b64decode(row['raw_b64'], validate=True)
    need(base64.b64encode(raw).decode() == row['raw_b64']
         and descriptor(raw) == {k: row['descriptor'][k] for k in ('bytes', 'sha256')},
         'explicit input original bytes differ')
    return strict(raw)


@contextmanager
def component_modules(state, *, runtime=False):
    """Evaluate only reviewed package originals; restore import state on exit."""
    names = ['component_common', 'late_boundary']
    if runtime:
        names = ['component_common', 'native_proc_profile', 'component_lifecycle',
                 'component_snapshot', 'late_boundary']
    prior = {name: sys.modules.get(name) for name in names}
    path_before = sys.path[:]
    modules = {}
    try:
        for name in names:
            raw = state['package_sources']['source/' + name + '.py']
            module = types.ModuleType(name)
            module.__file__ = '/reviewed-r10-component-package/source/' + name + '.py'
            module.__reviewed_source_sha256__ = sha(raw)
            module.__reviewed_package_sources__ = state['package_sources']
            modules[name] = module
            sys.modules[name] = module
            exec(compile(raw, module.__file__, 'exec', optimize=0), module.__dict__)
        yield modules
    finally:
        sys.path[:] = path_before
        for name, old in prior.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def validate_pre_policy_ancestor(bundle, proof, state, boundary, late):
    fields={'schema','boundary','root_result','package_manifest','combination',
            'previous','publication_operation','publication_stderr'}
    need(isinstance(proof,dict) and set(proof)==fields
         and proof['schema']=='hepta.r10.fixed-pre-policy-component-ancestor.v1',
         'explicit fixed pre-policy ancestor proof is required')
    reviewed=late.reviewed_pre_policy_ancestor()
    need(proof['boundary']==reviewed['boundary'] and late.is_pre_policy_ancestor(boundary),
         'pre-policy proof is not the exact retained actual04 original')
    home='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04'
    need(proof['root_result']=={'path':home+'/ROOT-RESULT.json','bytes':10980,
         'sha256':'c92382e0841375fc0a1fb19ff0271381ac044f1dad01427342fca4e4f6e9c638'},
         'fixed actual04 Root original differs')
    result=strict(original_from(bundle,proof['root_result']))
    manifest_raw=original_from(bundle,proof['package_manifest']);manifest=strict(manifest_raw)
    need(descriptor(manifest_raw)=={'bytes':5284,
         'sha256':'1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996'}
         and manifest['schema']=='hepta.native-guard.adapter-package.v1'
         and len(manifest['files'])==24,'exact historical actual04 package is required')
    need(result['late_boundary']==reviewed['boundary']
         and result['scope']==boundary['scope']
         and result['state']=='ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
         and result['component_qualified'] is False and result['native_status']=='provider_failed'
         and result['automatic_retry'] is False and result['business_qualified'] is False
         and type(result['model_requests']) is int and result['model_requests']==0
         and result['four_role_qualification'] is False,
         'historical failed result was changed or upgraded')
    need(proof['combination']=={'path':home+'/material/tree/inputs/COMBINATION.json','bytes':4702,
         'sha256':late.LEGACY_COMBINATION_SHA256},'fixed historical combination original differs')
    combo_raw=original_from(bundle,proof['combination']);oldcombo=strict(combo_raw)
    need(boundary['combination_sha256']==sha(combo_raw)
         and oldcombo['schema']=='hepta.native-guard.component-combination.v150.r10.1'
         and oldcombo['live_policy_sha256']=='296b09d9c844d2916b0dbdb0765c71cbcb8411790b58f5823798aa872205b659'
         and sha(combo_raw)!=CURRENT_COMBINATION_SHA,
         'historical policy identity must remain separate from the current combination')
    need(proof['previous']=={'path':home+'/ACTUAL-PREVIOUS-INPUT.json','bytes':1428,
         'sha256':'7ed4ccc75cc4ebc999af0da37e10e3d10173c2bf93e66f01b01042b890a4d9a4'},
         'exact actual04 native predecessor original differs')
    previous=strict(original_from(bundle,proof['previous']))
    need(previous['identity']==boundary['scope'] and previous['late_boundary']==reviewed['boundary']
         and previous['component_qualified'] is False and previous['terminal']['status']=='provider_failed'
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True
         and previous['automatic_replay'] is False,
         'historical terminal scope or closure semantics differs')
    steps=[row for row in result['steps'] if row.get('phase')=='phone-late-publish']
    need(len(steps)==1 and type(steps[0]['returncode']) is int and steps[0]['returncode']==0,
         'actual04 original publication terminal is absent')
    step=steps[0]
    need(proof['publication_operation']==step['stdout']
         and proof['publication_stderr']==step['stderr']
         and step['stdout']['path']==home+'/phone-late-publish/stdout.original'
         and step['stderr']['path']==home+'/phone-late-publish/stderr.original',
         'fixed actual04 publication original paths differ')
    operation=strict(original_from(bundle,proof['publication_operation']))
    need(original_from(bundle,proof['publication_stderr'])==b''
         and type(operation['actor_rc']) is int and operation['actor_rc']==0
         and type(operation['wrapper']['phone']['rc']) is int
         and operation['wrapper']['phone']['rc']==0,
         'actual04 publication was not fully successful')
    raw=operation['wrapper']['phone']['stdout'];need(isinstance(raw,str),'actual04 publication stdout missing')
    published=strict(raw.encode('utf-8'))
    need(published['schema']=='hepta.native-guard.boundary-publish-result.v1'
         and published['state']=='CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED'
         and published['boundary']==reviewed['boundary']
         and published['original_retirement_rewritten'] is False,
         'retained actual04 publication does not match its original boundary')
    return proof


def validate_environment_parent_ancestor(bundle, proof, state, boundary, late):
    """Retain the one actually closed R6 failure; it is never a current case."""
    fields = {'schema', 'boundary', 'root_result', 'package_manifest', 'combination',
              'previous', 'publication_operation', 'publication_stderr',
              'recovery_result', 'recovery_source', 'recovery_intent', 'original_root_failure'}
    need(isinstance(proof, dict) and set(proof) == fields
         and proof['schema'] == 'hepta.r10.fixed-environment-parent-component-ancestor.v1',
         'explicit fixed environment-parent ancestor proof is required')
    reviewed = late.reviewed_environment_parent_ancestor()
    need(proof['boundary'] == reviewed['boundary']
         and late.is_environment_parent_ancestor(boundary),
         'environment-parent proof is not the exact retained actual06 original')
    home = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06'
    root = {'path':home+'/ROOT-RESULT.json', 'bytes':32600,
            'sha256':'ed2e22f27b72951621802add6a1d68950ea94721d052b25dd5d59ebc95be5c93'}
    need(proof['root_result'] == root, 'fixed actual06 Root result differs')
    result = strict(original_from(bundle, proof['root_result']))
    manifest_raw = original_from(bundle, proof['package_manifest'])
    manifest = strict(manifest_raw)
    need(descriptor(manifest_raw) == {'bytes':11495,
             'sha256':'4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e'}
         and manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
         and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
         and len(manifest['files']) == 30,
         'actual06 must retain its exact original 30-file R6 package')
    pins = {row['path']:row for row in manifest['files']}
    need(len(pins) == 30, 'historical R6 package duplicates a source')
    for name, size, digest in (
        ('source/late_boundary.py',53502,late.ENVIRONMENT_PARENT_READER_SHA256),
        ('source/component_common.py',19138,late.ENVIRONMENT_PARENT_COMMON_SHA256),
        ('source/close_component.py',99120,late.ENVIRONMENT_PARENT_CLOSURE_SHA256)):
        need(pins[name] == {'path':name,'bytes':size,'sha256':digest},
             'actual06 executed source identity differs')
    need(result['late_boundary'] == reviewed['boundary']
         and result['scope'] == boundary['scope']
         and result['state'] == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
         and result['component_qualified'] is False and result['native_status'] == 'provider_failed'
         and result['automatic_retry'] is False and result['business_qualified'] is False
         and type(result['model_requests']) is int and result['model_requests'] == 0
         and result['four_role_qualification'] is False
         and boundary['package_sha256'] == late.ENVIRONMENT_PARENT_PACKAGE_SHA256
         and boundary['publisher_source_sha256'] == late.ENVIRONMENT_PARENT_READER_SHA256
         and boundary['prior_boundary'] == late.reviewed_pre_policy_ancestor()['boundary']
         and type(boundary['actual_native_calls']) is int and boundary['actual_native_calls'] == 1,
         'actual06 failure was reinterpreted as a current or qualified case')
    need(proof['combination'] == {'path':home+'/material/tree/inputs/COMBINATION.json',
             'bytes':4702,'sha256':'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'},
         'actual06 original combination descriptor differs')
    combo_raw = original_from(bundle, proof['combination']); combo = strict(combo_raw)
    need(boundary['combination_sha256'] == sha(combo_raw) == late.PROPERTY_PARENT_COMBINATION_SHA256
         and combo['schema'] == 'hepta.native-guard.component-combination.v150.r10.1'
         and combo['live_policy_sha256'] == '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7',
         'historical actual06 retains its original policy combination independently of current')
    need(proof['previous'] == {'path':home+'/ACTUAL-PREVIOUS-INPUT.json','bytes':1428,
             'sha256':'5ef37523f24a78dbce66da496c7f61897d989630a18739945279b8d0383415e9'},
         'fixed actual06 latest native predecessor differs')
    previous = strict(original_from(bundle, proof['previous']))
    closure_copy = {'path':home+'/CLOSURE.json', **{k:reviewed['closure'][k] for k in ('bytes','sha256')}}
    boundary_copy = {'path':home+'/LATE-BOUNDARY.original.json',
                     **{k:reviewed['boundary'][k] for k in ('bytes','sha256')}}
    need(previous['identity'] == boundary['scope'] and previous['late_boundary'] == reviewed['boundary']
         and previous['closed_component'] == closure_copy and result['previous'] == proof['previous']
         and previous['component_qualified'] is False and previous['terminal']['status'] == 'provider_failed'
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True
         and previous['complete_business_success'] is False
         and previous['automatic_replay'] is False and HASH.fullmatch(previous['request_sha256']),
         'actual06 native predecessor semantics or original scope changed')
    steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
    need(len(steps) == 1 and steps[0]['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
         and type(steps[0]['returncode']) is int and steps[0]['returncode'] == 0
         and steps[0]['automatic_retry'] is False,
         'actual06 original publication terminal is absent')
    step = steps[0]
    need(proof['publication_operation'] == step['stdout'] and proof['publication_stderr'] == step['stderr']
         and step['stdout']['path'] == home+'/phone-late-publish/stdout.original'
         and step['stderr']['path'] == home+'/phone-late-publish/stderr.original',
         'actual06 publication original paths differ')
    operation = strict(original_from(bundle, proof['publication_operation']))
    need(original_from(bundle, proof['publication_stderr']) == b''
         and type(operation['actor_rc']) is int and operation['actor_rc'] == 0
         and type(operation['wrapper']['phone']['rc']) is int and operation['wrapper']['phone']['rc'] == 0,
         'actual06 publication was not fully successful')
    stdout = operation['wrapper']['phone']['stdout']
    need(isinstance(stdout,str), 'actual06 original publication stdout missing')
    pub = strict(stdout.encode('utf-8'))
    need(pub['schema'] == 'hepta.native-guard.boundary-publish-result.v1'
         and pub['state'] == 'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED'
         and pub['boundary'] == reviewed['boundary'] and pub['original_retirement_rewritten'] is False,
         'actual06 original publication names another boundary')
    fixed = {
        'recovery_result':{'path':home+'/RECOVERY-RESULT.json','bytes':2724,
            'sha256':'ea74dc212a1edf1c9f4395ce72a8be8ec7a7f184b9f28321d68ece270fc4aa12'},
        'recovery_source':{'path':'/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt06-recovery-source-r1/source/resume_failed_component06.py',
            'bytes':26606,'sha256':'50a4e759486632d0fc129bb08e0101f526542a8a577b47d3474497da3d9b6237'},
        'recovery_intent':{'path':home+'/RECOVERY-INTENT.json','bytes':90530,
            'sha256':'2db02625a51939dfbcaa1127d10976f253aa12e8ee9fa8c8c95c196f73ceefa2'},
        'original_root_failure':{'path':home+'/ROOT-FAILURE.json','bytes':17357,
            'sha256':'4db667e2036cfcfee95f48ee3a58ed7f930cd0807402433afc7ad220da83fc7d'}}
    for key, row in fixed.items():
        need(proof[key] == row, 'actual06 original recovery provenance differs: '+key)
        original_from(bundle, row)
    recovery = strict(original_from(bundle, proof['recovery_result']))
    need(recovery['schema'] == 'hepta.native-guard.attempt06-recovery-result.v1'
         and recovery['state'] == 'ORIGINAL_FAILED_COMPONENT_NORMAL_TAIL_CLOSED_AND_PUBLISHED'
         and recovery['source'] == proof['recovery_source']
         and recovery['original_root_failure'] == proof['original_root_failure']
         and recovery['recovery_intent'] == proof['recovery_intent']
         and recovery['root_result'] == root and recovery['closure'] == closure_copy
         and recovery['boundary'] == boundary_copy and recovery['previous'] == proof['previous']
         and recovery['malformed_original_preserved'] is True
         and recovery['original_sender_wait_fabricated'] is False
         and recovery['original_lease_expiry_unchanged'] is True
         and all(recovery[key] is False for key in ('component_qualified','business_qualified',
             'new_nonce','new_send','new_fixture','new_launch','automatic_retry'))
         and type(recovery['model_requests']) is int and recovery['model_requests'] == 0,
         'actual06 recovery provenance was dropped, replayed or upgraded')
    return proof


def property_parent_proof_spec(attempt):
    """Exact retained host provenance; it does not read or admit a new case."""
    need(attempt in ('attempt08', 'attempt07'), 'only the two fixed R7 property parents exist')
    need(isinstance(PROPERTY_PARENT_HOST_ORIGINALS, dict)
         and set(PROPERTY_PARENT_HOST_ORIGINALS) == {'attempt08','attempt07'},
         'actual R7 property-parent host originals are not reviewed')
    return strict(encode(PROPERTY_PARENT_HOST_ORIGINALS[attempt]))


def validate_property_parent_ancestors(bundle, proofs, state, boundaries, late):
    """Recheck actual08/07 with their original R7 package, reader and policy."""
    need(isinstance(proofs, list) and len(proofs) == 2
         and isinstance(boundaries, list) and len(boundaries) == 2,
         'the two fixed property-parent proofs must appear latest first')
    reviewed = late.reviewed_property_parent_ancestors()
    old_reader = late.property_parent_reader()
    # The current and historical encoders are the same exact common source.
    # Keep the historical reader facade limited to its four pure methods.
    need(descriptor(state['package_sources']['source/component_common.py']) ==
         {'bytes':19138, 'sha256':late.PROPERTY_PARENT_COMMON_SHA256},
         'current and historical canonical encoders require the same exact common source')
    for index, (attempt, proof, boundary) in enumerate(zip(
            ('attempt08','attempt07'), proofs, boundaries)):
        spec = property_parent_proof_spec(attempt)
        need(isinstance(proof, dict)
             and set(proof) == set(spec) | {'schema','attempt','boundary'}
             and proof['schema'] == 'hepta.r10.fixed-property-parent-component-ancestor.v1'
             and proof['attempt'] == attempt
             and proof['boundary'] == reviewed[index]['boundary']
             and all(proof[key] == row for key,row in spec.items()),
             'fixed property-parent host proof fields or generation differ')
        originals = {key:original_from(bundle,row) for key,row in spec.items()}
        result = strict(originals['root_result'])
        canonical = late.C.encoded(boundary)
        need(late.is_property_parent_ancestor(boundary)
             and descriptor(canonical) == {k:reviewed[index]['boundary'][k]
                                                   for k in ('bytes','sha256')}
             and boundary['nonce'] == late.PROPERTY_PARENT_NONCES[index]
             and boundary['package_sha256'] == late.PROPERTY_PARENT_PACKAGE_SHA256
             and boundary['combination_sha256'] == late.PROPERTY_PARENT_COMBINATION_SHA256
             and boundary['publisher_source_sha256'] == late.PROPERTY_PARENT_READER_SHA256
             and boundary['component_qualified'] is False
             and boundary['native_status'] == 'provider_failed'
             and type(boundary['actual_native_calls']) is int
             and boundary['actual_native_calls'] == late.PROPERTY_PARENT_CALL_COUNTS[index],
             'retained R7 failure was changed or credited to the new generation')
        need(boundary['prior_boundary'] == (reviewed[1]['boundary'] if index == 0
             else late.reviewed_environment_parent_ancestor()['boundary']),
             'fixed actual08-to-07-to-06 suffix is not continuous')
        manifest = strict(originals['package_manifest'])
        need(descriptor(originals['package_manifest']) == {'bytes':13446,
                  'sha256':late.PROPERTY_PARENT_PACKAGE_SHA256}
             and manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
             and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
             and len(manifest['files']) == 31,
             'actual08/07 must retain the exact original 31-file R7 package')
        pins = {row['path']:row for row in manifest['files']}
        need(len(pins) == 31, 'historical R7 manifest duplicates a member')
        for name,size,digest in (
                ('source/late_boundary.py',62434,late.PROPERTY_PARENT_READER_SHA256),
                ('source/component_common.py',19138,late.PROPERTY_PARENT_COMMON_SHA256),
                ('source/close_component.py',99120,late.PROPERTY_PARENT_CLOSURE_SHA256)):
            need(pins[name] == {'path':name,'bytes':size,'sha256':digest},
                 'historical R7 executed source differs')
        combo = strict(originals['combination'])
        need(sha(originals['combination']) == late.PROPERTY_PARENT_COMBINATION_SHA256
             and combo['live_policy_sha256'] == late.PROPERTY_PARENT_POLICY_SHA256
             and combo['schema'] == 'hepta.native-guard.component-combination.v150.r10.1',
             'historical R7 combination must use its old adopted policy')
        need(result['late_boundary'] == reviewed[index]['boundary']
             and result['scope'] == boundary['scope']
             and result['state'] == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
             and result['component_qualified'] is False and result['native_status'] == 'provider_failed'
             and result['automatic_retry'] is False and result['business_qualified'] is False
             and type(result['model_requests']) is int and result['model_requests'] == 0
             and result['four_role_qualification'] is False,
             'actual R7 Root result changed its terminal or qualification')
        home = Path(spec['root_result']['path']).parent
        closure_copy = {'path':str(home/'CLOSURE.json'),
                        **{k:reviewed[index]['closure'][k] for k in ('bytes','sha256')}}
        boundary_copy = {'path':str(home/'LATE-BOUNDARY.original.json'),
                         **{k:reviewed[index]['boundary'][k] for k in ('bytes','sha256')}}
        previous = strict(originals['previous'])
        need(previous['identity'] == boundary['scope']
             and previous['late_boundary'] == reviewed[index]['boundary']
             and previous['closed_component'] == closure_copy
             and result['previous'] == spec['previous']
             and previous['component_qualified'] is False
             and previous['terminal']['status'] == 'provider_failed'
             and previous['known_all_dispatched_tools_confirmed_terminal'] is True
             and previous['complete_business_success'] is False
             and previous['automatic_replay'] is False and HASH.fullmatch(previous['request_sha256']),
             'actual R7 previous input changed its original native scope')
        steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
        need(len(steps) == 1 and steps[0]['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
             and type(steps[0]['returncode']) is int and steps[0]['returncode'] == 0
             and steps[0]['automatic_retry'] is False
             and steps[0]['stdout'] == spec['publication_operation']
             and steps[0]['stderr'] == spec['publication_stderr'],
             'actual R7 publication terminal or original stream differs')
        operation = strict(originals['publication_operation'])
        need(originals['publication_stderr'] == b''
             and type(operation['actor_rc']) is int and operation['actor_rc'] == 0
             and type(operation['wrapper']['phone']['rc']) is int
             and operation['wrapper']['phone']['rc'] == 0,
             'actual R7 publication actor/phone did not both succeed')
        text = operation['wrapper']['phone']['stdout']
        need(isinstance(text,str), 'actual R7 publication stdout is absent')
        published = strict(text.encode('utf-8'))
        need(published == {'schema':'hepta.native-guard.boundary-publish-result.v1',
              'state':'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED',
              'boundary':reviewed[index]['boundary'], 'old_retirement_current_equality_claimed':False,
              'original_retirement_rewritten':False, 'phone_tool_calls':0,
              'model_requests':0, 'signals':0, 'automatic_retry':False},
             'actual R7 original publication named another boundary')
        recovery = strict(originals['recovery_result'])
        need(recovery['schema'] == 'hepta.native-guard.'+attempt+'-recovery-result.v1'
             and recovery['state'] == 'ORIGINAL_FAILED_COMPONENT_NORMAL_TAIL_CLOSED_AND_PUBLISHED'
             and recovery['source'] == spec['recovery_source']
             and recovery['root_result'] == spec['root_result']
             and recovery['closure'] == closure_copy and recovery['boundary'] == boundary_copy
             and recovery['previous'] == spec['previous']
             and recovery['recovery_intent'] == spec['recovery_intent']
             and recovery['original_root_failure'] == spec['original_root_failure']
             and recovery['original_sender_wait_fabricated'] is False
             and recovery['original_lease_expiry_unchanged'] is True
             and all(recovery[key] is False for key in ('component_qualified','business_qualified',
                  'new_nonce','new_send','new_fixture','new_launch','automatic_retry'))
             and type(recovery['model_requests']) is int and recovery['model_requests'] == 0,
             'actual R7 recovery provenance was dropped, replayed or upgraded')
        if attempt == 'attempt08':
            need(recovery['original_continuation_failure'] == spec['original_continuation_failure']
                 and recovery['original_capture_failure_observation'] == spec['original_capture_failure_observation']
                 and recovery['original_launch_timeout_and_continuation_failure_preserved'] is True
                 and type(recovery['original_setup_attempt_count']) is int
                 and recovery['original_setup_attempt_count'] == 1
                 and type(recovery['original_capture_call_count']) is int
                 and recovery['original_capture_call_count'] == 1,
                 'actual08 launch timeout, one setup or failed capture provenance differs')
        else:
            need(recovery['original_setup_wait_failure_and_unconsumed_plan_preserved'] is True,
                 'actual07 setup wait failure provenance was discarded')
        # This independent check uses only the old original combination. The
        # current-generation reader has already rechecked the full chain.
        old_reader.boundary_from_original(canonical,
             original_descriptor=reviewed[index]['boundary'],
             combination_sha256=late.PROPERTY_PARENT_COMBINATION_SHA256,
             package_sha256=late.PROPERTY_PARENT_PACKAGE_SHA256)
    return proofs


DIAGNOSTIC_PARENT_HOST_ORIGINALS = {'boundary_copy': {'bytes': 9686, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/LATE-BOUNDARY.original.json', 'sha256': '6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'}, 'closed_previous': {'bytes': 1428, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/ACTUAL-PREVIOUS-INPUT.json', 'sha256': '7c9fc15c9461613c4fb20950ad6762b0c88ab8a7be442acfe589f6f2da93f870'}, 'closure_copy': {'bytes': 55124, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/CLOSURE.json', 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'}, 'combination': {'bytes': 4702, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/COMBINATION.json', 'sha256': '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'}, 'inventory_copy': {'bytes': 923078, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/INVENTORY.json', 'sha256': 'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d'}, 'original_root_failure': {'bytes': 20867, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/ROOT-FAILURE.json', 'sha256': '25f7bca3dfd2f10308e2d430704db54e393c12bd0add116065ff8666be85320b'}, 'original_root_plan': {'bytes': 4783, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/ROOT-PLAN.original.json', 'sha256': '9a94108ffc737133ba879bd9cccd70c7ec3ae2f3da17eb689e5b1d5610789d58'}, 'original_sender_result': {'bytes': 699, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-01.send-result.json', 'sha256': '97f1d13685636c03681120916abc20b357d0e47dfa594f1edfc22d40f68c24f5'}, 'package_manifest': {'bytes': 16808, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/MANIFEST.json', 'sha256': '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'}, 'publication_operation': {'bytes': 2247, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/phone-late-publish/stdout.original', 'sha256': 'd4eb412d71a6ec297d9d884ce666cf0b8ae9d7303d4a85c5422dc187af4c20a3'}, 'publication_stderr': {'bytes': 0, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/phone-late-publish/stderr.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'published_boundary_descriptor_file': {'bytes': 367, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/LATE-BOUNDARY-DESCRIPTOR.json', 'sha256': '75297d65abdafe151bd94fb5e80d9db8153bc9975b05e15b3aff4f12cd99805c'}, 'recovery_admission': {'bytes': 1740, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/RECOVERY-ADMISSION.json', 'sha256': '9cf8d41b4653e2ef38c7c6e893bc92a7438aaef5b1778559b3c480a475cf360f'}, 'recovery_intent': {'bytes': 448224, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/RECOVERY-INTENT.json', 'sha256': '062c26927ac46082fe1bb92072daa0b92ad7db039887057331ef3203d7b8e81f'}, 'recovery_result': {'bytes': 3409, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/RECOVERY-RESULT.json', 'sha256': 'ab6949a13c11dc22d0793b21aa7f3eb550cf8efb004f322ebf12dcec9bb30d57'}, 'recovery_source': {'bytes': 41540, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-current-scope-recovery-7c907661-r1-candidate01/source/resume_current_failed_scope.py', 'sha256': 'f696274430bef72143e0d791c885393d9a624ce197fb8f136d3c6e52fbe1e545'}, 'root_result': {'bytes': 36124, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/ROOT-RESULT.json', 'sha256': '3c97cab5fec963c23f850564bd856ed41edf912fca7c4d34bc5af0d5e6ef2907'}, 'package_files': [{'name': 'reference/REVIEWED-PRODUCTION-PINS.json', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/REVIEWED-PRODUCTION-PINS.json', 'bytes': 1438, 'sha256': '73963fdcea527cdbc3628bdeff5918f7106afbaf095fb183e4b199391e46a7a5'}}, {'name': 'reference/attempt05-AFTER-INVENTORY.original.json', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/attempt05-AFTER-INVENTORY.original.json', 'bytes': 664638, 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}}, {'name': 'reference/attempt05-CLOSURE.original.json', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/attempt05-CLOSURE.original.json', 'bytes': 164095, 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}}, {'name': 'reference/attempt05-SIDE-PROOF.original.json', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/attempt05-SIDE-PROOF.original.json', 'bytes': 4650, 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}}, {'name': 'reference/component_common_r5.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/component_common_r5.py', 'bytes': 18133, 'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'}}, {'name': 'reference/component_core.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/component_core.py', 'bytes': 13238, 'sha256': '705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'}}, {'name': 'reference/component_once_r9.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/component_once_r9.py', 'bytes': 30647, 'sha256': '1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'}}, {'name': 'reference/decode_client_state.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/decode_client_state.py', 'bytes': 4116, 'sha256': 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'}}, {'name': 'reference/environment_parent_late_boundary_r6.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/environment_parent_late_boundary_r6.py', 'bytes': 53502, 'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'}}, {'name': 'reference/native_guard_session.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/native_guard_session.py', 'bytes': 28109, 'sha256': '77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b'}}, {'name': 'reference/native_journal_audit.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/native_journal_audit.py', 'bytes': 6701, 'sha256': 'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'}}, {'name': 'reference/non_native_attempt05.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/non_native_attempt05.py', 'bytes': 19740, 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}}, {'name': 'reference/policy_parent_late_boundary_r4.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/policy_parent_late_boundary_r4.py', 'bytes': 35730, 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'}}, {'name': 'reference/property_parent_late_boundary_r7.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/property_parent_late_boundary_r7.py', 'bytes': 62434, 'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'}}, {'name': 'reference/send_new_native_task_r5.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/send_new_native_task_r5.py', 'bytes': 40788, 'sha256': '5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}}, {'name': 'reference/tool_client_r6.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/reference/tool_client_r6.py', 'bytes': 17390, 'sha256': '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'}}, {'name': 'source/close_component.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/close_component.py', 'bytes': 99120, 'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'}}, {'name': 'source/component_common.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/component_common.py', 'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}}, {'name': 'source/component_lifecycle.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/component_lifecycle.py', 'bytes': 40261, 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}}, {'name': 'source/component_listener.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/component_listener.py', 'bytes': 38823, 'sha256': 'ad345c0080cbfd89f1378bb6e8583f43e1fa4af0a5928d7ecbf4ccc8d4f04c52'}}, {'name': 'source/component_snapshot.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/component_snapshot.py', 'bytes': 24187, 'sha256': '2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa'}}, {'name': 'source/late_boundary.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/late_boundary.py', 'bytes': 74287, 'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}}, {'name': 'source/native_guard_session_r2.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/native_guard_session_r2.py', 'bytes': 28878, 'sha256': '5fe50be4dccbe655a39124876d1f9c2199de20d80ec0a84f08a63d88e7f1a931'}}, {'name': 'source/native_proc_profile.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/native_proc_profile.py', 'bytes': 4633, 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}}, {'name': 'source/prepare_component.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/prepare_component.py', 'bytes': 14259, 'sha256': '46a28fd77dc64d94ccdd4c1f3e12912e22ebb39defc29b69991df831d75afc7d'}}, {'name': 'source/root_fixture_once.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/root_fixture_once.py', 'bytes': 18728, 'sha256': 'bb70017c4f184efc0c9372ab072fa2d11a1cf7cbd3276257fa7b3605a426e0d1'}}, {'name': 'source/root_fixture_originals.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/root_fixture_originals.py', 'bytes': 39149, 'sha256': 'c1cd1402888de5bc4176255269014995e9d39dc658912d3c28a117ec51010f9e'}}, {'name': 'source/run_root_fixture_phase.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/run_root_fixture_phase.py', 'bytes': 10498, 'sha256': 'bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2'}}, {'name': 'source/send_new_native_guard_task_r10_r4.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/send_new_native_guard_task_r10_r4.py', 'bytes': 40952, 'sha256': 'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad'}}, {'name': 'source/sender_native_guard_ready_r10_r4.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/sender_native_guard_ready_r10_r4.py', 'bytes': 18666, 'sha256': 'f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99'}}, {'name': 'source/stage_component.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/stage_component.py', 'bytes': 19116, 'sha256': '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340'}}, {'name': 'source/witness_bundle.py', 'copy': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-membership-733d-01/runtime/source/witness_bundle.py', 'bytes': 18137, 'sha256': 'f949ae3d6cec26bf98448fd0ac20b1f46472190be022d6532b1973177e0edfca'}}], 'production_files': [{'name': 'action_ledger.py', 'copy': {'bytes': 15587, 'sha256': '50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/action_ledger.py'}}, {'name': 'daily_phone_local.py', 'copy': {'bytes': 22059, 'sha256': 'f42fa1f3268d2a2c00e49610d356b440d1e32722fbe2af877580fb6eb180f712', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/daily_phone_local.py'}}, {'name': 'health_contracts.py', 'copy': {'bytes': 11439, 'sha256': '00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/health_contracts.py'}}, {'name': 'ledger_round_evidence.py', 'copy': {'bytes': 15135, 'sha256': '87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/ledger_round_evidence.py'}}, {'name': 'model_health.py', 'copy': {'bytes': 8251, 'sha256': '105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/model_health.py'}}, {'name': 'model_slot_cleanup.py', 'copy': {'bytes': 37375, 'sha256': '9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/model_slot_cleanup.py'}}, {'name': 'phone_local_http_worker.py', 'copy': {'bytes': 10453, 'sha256': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/phone_local_http_worker.py'}}, {'name': 'phone_local_tools.py', 'copy': {'bytes': 13813, 'sha256': '0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/phone_local_tools.py'}}, {'name': 'phone_observation_tools.py', 'copy': {'bytes': 38774, 'sha256': 'f16c77c1b4509babcea5fc2e8d0a7ae8ab43b3cd58e6640441b44ecd4bccb6df', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/phone_observation_tools.py'}}, {'name': 'phone_task_guards.py', 'copy': {'bytes': 22825, 'sha256': '87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/phone_task_guards.py'}}, {'name': 'provider_codex_host.py', 'copy': {'bytes': 41510, 'sha256': 'cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/provider_codex_host.py'}}, {'name': 'provider_openai_compatible.py', 'copy': {'bytes': 17730, 'sha256': '337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/provider_openai_compatible.py'}}, {'name': 'provider_phone_local.py', 'copy': {'bytes': 70237, 'sha256': '082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/provider_phone_local.py'}}, {'name': 'retirement_recovery.py', 'copy': {'bytes': 9802, 'sha256': 'c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/retirement_recovery.py'}}, {'name': 'task_postconditions.py', 'copy': {'bytes': 23211, 'sha256': 'd4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/production/task_postconditions.py'}}], 'source_seal': {'bytes': 2341, 'sha256': 'a41a317d9ba3317b4c3bf66b66fb574f47f9bf15b1dc67201cea30d9ae0a9229', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/SOURCE-SEAL.original.json'}, 'configuration': {'bytes': 1493, 'sha256': '780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/configuration.original.json'}, 'service_inputs': {'bytes': 10635, 'sha256': '2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/tree/inputs/service-inputs.original.json'}}

CODEC_DIAGNOSTIC_PARENT_HOST_ORIGINALS = {'boundary_copy': {'bytes': 9998, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/LATE-BOUNDARY.original.json', 'sha256': '621f82a3c071c755f4460f591ac1faa92ec6940b2a19c7a4d76948668abf669e'}, 'closed_previous': {'bytes': 1432, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/ACTUAL-PREVIOUS-INPUT.json', 'sha256': '0f8cf33cf9e6d92c92a7bf465d65bafe537101bc4ee77b1b8faf79e63d39e1e5'}, 'closure_copy': {'bytes': 55184, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/CLOSURE.json', 'sha256': '35af6a58a84413770bb14ede44eca83ac2774cd4591c7df1501b501cb1643335'}, 'combination': {'bytes': 4702, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/COMBINATION.json', 'sha256': 'b4d4a221a4a516177cecf8e182a7ee9a494fc65feb85277cfdf10d28396d5709'}, 'configuration': {'bytes': 1493, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/configuration.original.json', 'sha256': 'c155d1233e6a757d7f2b6342b1907a3406f4237006cfbdab0dcdcd51e03b89e5'}, 'inventory_copy': {'bytes': 996847, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/INVENTORY.json', 'sha256': '4d64153c7cecf0782bb804791cf272e01ca83ae0b36d9927096762cc3fafc228'}, 'original_root_failure': {'bytes': 21023, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/ROOT-FAILURE.json', 'sha256': '3c9524d09ed5643308ed2d7d4fe20d090265c66797bff7a46c3815041d50db96'}, 'original_root_plan': {'bytes': 4831, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/ROOT-PLAN.original.json', 'sha256': 'ea001805933ac55aed029b0c6d9429c516866f76bb9a9687284c978af02bd582'}, 'original_sender_result': {'bytes': 703, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-diag01.send-result.json', 'sha256': 'e61b442e9040f8775d879c54756b2ea523440578f46c814fbda972b247c231b7'}, 'package_files': [{'copy': {'bytes': 1438, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/REVIEWED-PRODUCTION-PINS.json', 'sha256': '4abc794b0469983ad7c255a2eb73b0d58d8cdd69a32c21d005a04a317f32ab01'}, 'name': 'reference/REVIEWED-PRODUCTION-PINS.json'}, {'copy': {'bytes': 664638, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/attempt05-AFTER-INVENTORY.original.json', 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}, 'name': 'reference/attempt05-AFTER-INVENTORY.original.json'}, {'copy': {'bytes': 164095, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/attempt05-CLOSURE.original.json', 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, 'name': 'reference/attempt05-CLOSURE.original.json'}, {'copy': {'bytes': 4650, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/attempt05-SIDE-PROOF.original.json', 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, 'name': 'reference/attempt05-SIDE-PROOF.original.json'}, {'copy': {'bytes': 18133, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/component_common_r5.py', 'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'}, 'name': 'reference/component_common_r5.py'}, {'copy': {'bytes': 13238, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/component_core.py', 'sha256': '705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'}, 'name': 'reference/component_core.py'}, {'copy': {'bytes': 30647, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/component_once_r9.py', 'sha256': '1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'}, 'name': 'reference/component_once_r9.py'}, {'copy': {'bytes': 4116, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/decode_client_state.py', 'sha256': 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'}, 'name': 'reference/decode_client_state.py'}, {'copy': {'bytes': 53502, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/environment_parent_late_boundary_r6.py', 'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'}, 'name': 'reference/environment_parent_late_boundary_r6.py'}, {'copy': {'bytes': 28109, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/native_guard_session.py', 'sha256': '77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b'}, 'name': 'reference/native_guard_session.py'}, {'copy': {'bytes': 6701, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/native_journal_audit.py', 'sha256': 'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'}, 'name': 'reference/native_journal_audit.py'}, {'copy': {'bytes': 19740, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/non_native_attempt05.py', 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}, 'name': 'reference/non_native_attempt05.py'}, {'copy': {'bytes': 35730, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/policy_parent_late_boundary_r4.py', 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'}, 'name': 'reference/policy_parent_late_boundary_r4.py'}, {'copy': {'bytes': 62434, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/property_parent_late_boundary_r7.py', 'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'}, 'name': 'reference/property_parent_late_boundary_r7.py'}, {'copy': {'bytes': 40788, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/send_new_native_task_r5.py', 'sha256': '5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}, 'name': 'reference/send_new_native_task_r5.py'}, {'copy': {'bytes': 17390, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/reference/tool_client_r6.py', 'sha256': '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'}, 'name': 'reference/tool_client_r6.py'}, {'copy': {'bytes': 99120, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/close_component.py', 'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'}, 'name': 'source/close_component.py'}, {'copy': {'bytes': 19138, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/component_common.py', 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'name': 'source/component_common.py'}, {'copy': {'bytes': 40261, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/component_lifecycle.py', 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, 'name': 'source/component_lifecycle.py'}, {'copy': {'bytes': 38823, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/component_listener.py', 'sha256': 'ad345c0080cbfd89f1378bb6e8583f43e1fa4af0a5928d7ecbf4ccc8d4f04c52'}, 'name': 'source/component_listener.py'}, {'copy': {'bytes': 24187, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/component_snapshot.py', 'sha256': '2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa'}, 'name': 'source/component_snapshot.py'}, {'copy': {'bytes': 84038, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/late_boundary.py', 'sha256': 'f220f25fe355e5c6591d6fe6f420fb474e166404fcdb4828799e446ae3d46646'}, 'name': 'source/late_boundary.py'}, {'copy': {'bytes': 28878, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/native_guard_session_r2.py', 'sha256': '5fe50be4dccbe655a39124876d1f9c2199de20d80ec0a84f08a63d88e7f1a931'}, 'name': 'source/native_guard_session_r2.py'}, {'copy': {'bytes': 4633, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/native_proc_profile.py', 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, 'name': 'source/native_proc_profile.py'}, {'copy': {'bytes': 14259, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/prepare_component.py', 'sha256': '46a28fd77dc64d94ccdd4c1f3e12912e22ebb39defc29b69991df831d75afc7d'}, 'name': 'source/prepare_component.py'}, {'copy': {'bytes': 18728, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/root_fixture_once.py', 'sha256': 'bb70017c4f184efc0c9372ab072fa2d11a1cf7cbd3276257fa7b3605a426e0d1'}, 'name': 'source/root_fixture_once.py'}, {'copy': {'bytes': 39149, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/root_fixture_originals.py', 'sha256': 'c1cd1402888de5bc4176255269014995e9d39dc658912d3c28a117ec51010f9e'}, 'name': 'source/root_fixture_originals.py'}, {'copy': {'bytes': 10498, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/run_root_fixture_phase.py', 'sha256': 'bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2'}, 'name': 'source/run_root_fixture_phase.py'}, {'copy': {'bytes': 40952, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/send_new_native_guard_task_r10_r4.py', 'sha256': 'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad'}, 'name': 'source/send_new_native_guard_task_r10_r4.py'}, {'copy': {'bytes': 18666, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/sender_native_guard_ready_r10_r4.py', 'sha256': 'f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99'}, 'name': 'source/sender_native_guard_ready_r10_r4.py'}, {'copy': {'bytes': 19116, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/stage_component.py', 'sha256': '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340'}, 'name': 'source/stage_component.py'}, {'copy': {'bytes': 18137, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/source/witness_bundle.py', 'sha256': 'f949ae3d6cec26bf98448fd0ac20b1f46472190be022d6532b1973177e0edfca'}, 'name': 'source/witness_bundle.py'}], 'package_manifest': {'bytes': 18864, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-capture-diagnostic-8ee-01/runtime/MANIFEST.json', 'sha256': '8b9a3b24f2449022120f7f1ef15905ee9a07edac8062fcf46cf7bb0b0c8e7302'}, 'production_files': [{'copy': {'bytes': 15587, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/action_ledger.py', 'sha256': '50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907'}, 'name': 'action_ledger.py'}, {'copy': {'bytes': 22059, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/daily_phone_local.py', 'sha256': 'bd4a292ab54ae890b8dc0d610c5891c32201ffcfe0cca54365455765094476c0'}, 'name': 'daily_phone_local.py'}, {'copy': {'bytes': 11439, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/health_contracts.py', 'sha256': '00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d'}, 'name': 'health_contracts.py'}, {'copy': {'bytes': 15135, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/ledger_round_evidence.py', 'sha256': '87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d'}, 'name': 'ledger_round_evidence.py'}, {'copy': {'bytes': 8251, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/model_health.py', 'sha256': '105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80'}, 'name': 'model_health.py'}, {'copy': {'bytes': 37375, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/model_slot_cleanup.py', 'sha256': '9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183'}, 'name': 'model_slot_cleanup.py'}, {'copy': {'bytes': 10453, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/phone_local_http_worker.py', 'sha256': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d'}, 'name': 'phone_local_http_worker.py'}, {'copy': {'bytes': 13813, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/phone_local_tools.py', 'sha256': '0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54'}, 'name': 'phone_local_tools.py'}, {'copy': {'bytes': 43452, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/phone_observation_tools.py', 'sha256': '8ee1782227472737ebb5854bef959f899f3c873714d85eff4f9360f995b18040'}, 'name': 'phone_observation_tools.py'}, {'copy': {'bytes': 22825, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/phone_task_guards.py', 'sha256': '87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86'}, 'name': 'phone_task_guards.py'}, {'copy': {'bytes': 41510, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/provider_codex_host.py', 'sha256': 'cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039'}, 'name': 'provider_codex_host.py'}, {'copy': {'bytes': 17730, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/provider_openai_compatible.py', 'sha256': '337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc'}, 'name': 'provider_openai_compatible.py'}, {'copy': {'bytes': 70237, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/provider_phone_local.py', 'sha256': '082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6'}, 'name': 'provider_phone_local.py'}, {'copy': {'bytes': 9802, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/retirement_recovery.py', 'sha256': 'c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827'}, 'name': 'retirement_recovery.py'}, {'copy': {'bytes': 23211, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/production/task_postconditions.py', 'sha256': 'd4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3'}, 'name': 'task_postconditions.py'}], 'publication_operation': {'bytes': 2262, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/phone-late-publish/stdout.original', 'sha256': '15a7ce24c58049f9dbc3c200b4bf05e34691829e29543b0675b90e5f8e86530f'}, 'publication_stderr': {'bytes': 0, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/phone-late-publish/stderr.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'published_boundary_descriptor_file': {'bytes': 367, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/LATE-BOUNDARY-DESCRIPTOR.json', 'sha256': 'ced62ee85980e431f52bd89b8f33301684e1415c3f99f435703190da74e6ab2d'}, 'recovery_admission': {'bytes': 1752, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/RECOVERY-ADMISSION.json', 'sha256': 'cd6923b3d438d1f492a4afaf53ced674125a816e70bbf08d769c400383bad652'}, 'recovery_intent': {'bytes': 449528, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/RECOVERY-INTENT.json', 'sha256': 'd4ce63a8d182a2dd70afb8a1daad0a0faaed5b328379f29560651ba641364d7a'}, 'recovery_result': {'bytes': 3445, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/RECOVERY-RESULT.json', 'sha256': 'b3a34cc0d1dcbf5dee9565159070ee98a201355a393b0d5b59d5135957a63caa'}, 'recovery_source': {'bytes': 41540, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-current-scope-recovery-7c907661-diag01-candidate01/source/resume_current_failed_scope.py', 'sha256': '4ff2b43dd3c0a1fc1439fd9aad2c8ea45b109b851399961a6192b18015301625'}, 'root_result': {'bytes': 36448, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/ROOT-RESULT.json', 'sha256': 'febdb4a0cdd667ec7e492f87b569e7bfd23f8cf585c2c5dc88d0b7ca3cc91fa3'}, 'service_inputs': {'bytes': 10635, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/service-inputs.original.json', 'sha256': '0b05084f0cc347b8c0a75e3a7b7c62985530f2cc0060c15ee93c5d98877bbf0d'}, 'source_seal': {'bytes': 2341, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/material/tree/inputs/SOURCE-SEAL.original.json', 'sha256': '546870e48564266d222eb9a8f905e897e960dd8281e2d8af0ca89dcb86fca022'}}

DIAGNOSTIC_PARENT_VALIDATION_PROFILES = {'failed6077': {'closer': {'bytes': 99120,
                           'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'},
                'combination_sha256': 'b4d4a221a4a516177cecf8e182a7ee9a494fc65feb85277cfdf10d28396d5709',
                'common': {'bytes': 19138,
                           'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'},
                'input_previous_sha256': '7c9fc15c9461613c4fb20950ad6762b0c88ab8a7be442acfe589f6f2da93f870',
                'mapper': {'bytes': 43452,
                           'sha256': '8ee1782227472737ebb5854bef959f899f3c873714d85eff4f9360f995b18040'},
                'nonce': '6077fc8f045572edc4acfb13ed7e09a8',
                'package_manifest': {'bytes': 18864,
                                     'sha256': '8b9a3b24f2449022120f7f1ef15905ee9a07edac8062fcf46cf7bb0b0c8e7302'},
                'publisher': {'bytes': 84038,
                              'sha256': 'f220f25fe355e5c6591d6fe6f420fb474e166404fcdb4828799e446ae3d46646'}},
 'failed902': {'closer': {'bytes': 99120,
                          'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'},
               'combination_sha256': '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e',
               'common': {'bytes': 19138,
                          'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'},
               'input_previous_sha256': '9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4',
               'mapper': {'bytes': 38774,
                          'sha256': 'f16c77c1b4509babcea5fc2e8d0a7ae8ab43b3cd58e6640441b44ecd4bccb6df'},
               'nonce': '902e851c3ca1f90deab3d880ab993774',
               'package_manifest': {'bytes': 16808,
                                    'sha256': '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'},
               'publisher': {'bytes': 74287,
                             'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}}}


def diagnostic_parent_proof_spec(name='failed902'):
    """Return a fresh, complete spec for exactly one of two retained generations."""
    need(type(name) is str and name in ('failed902', 'failed6077'),
         'only the fixed failed902 and failed6077 historical profiles are allowed')
    value = (DIAGNOSTIC_PARENT_HOST_ORIGINALS if name == 'failed902'
             else CODEC_DIAGNOSTIC_PARENT_HOST_ORIGINALS)
    return strict(encode(value))


def diagnostic_parent_validation_profile(name, late):
    """Select only source-fixed identities and reviewed reader accessors."""
    need(type(name) is str and name in ('failed902', 'failed6077'),
         'only the fixed failed902 and failed6077 historical profiles are allowed')
    profile = strict(encode(DIAGNOSTIC_PARENT_VALIDATION_PROFILES[name]))
    if name == 'failed902':
        prefix = 'DIAGNOSTIC_PARENT_'
        reader = late.reviewed_diagnostic_parent_ancestor
        predicate = late.is_diagnostic_parent_ancestor
        prior = lambda: late.reviewed_property_parent_ancestors()[0]['boundary']
        provenance = late.diagnostic_parent_reader_provenance
    else:
        prefix = 'CODEC_DIAGNOSTIC_PARENT_'
        reader = late.reviewed_codec_diagnostic_parent_ancestor
        predicate = late.is_codec_diagnostic_parent_ancestor
        prior = lambda: late.reviewed_diagnostic_parent_ancestor()['boundary']
        provenance = late.codec_diagnostic_parent_reader_provenance
    expected = {'NONCE': profile['nonce'],
        'PACKAGE_SHA256': profile['package_manifest']['sha256'],
        'PUBLISHER_SHA256': profile['publisher']['sha256'],
        'COMMON_SHA256': profile['common']['sha256'],
        'CLOSURE_SHA256': profile['closer']['sha256'],
        'MAPPER_SHA256': profile['mapper']['sha256'],
        'COMBINATION_SHA256': profile['combination_sha256']}
    need(all(getattr(late, prefix+key) == value for key,value in expected.items()),
         'fixed historical profile differs from the reviewed current reader')
    return profile, reader, predicate, prior, provenance


def validate_diagnostic_parent_ancestor(bundle, proof, state, boundary, late, name='failed902'):
    """Retain one of two fixed failed generations without current-case credit."""
    spec = diagnostic_parent_proof_spec(name)
    profile, reader, predicate, prior, provenance_reader = diagnostic_parent_validation_profile(name, late)
    record = reader()
    need(type(proof) is dict and set(proof) == set(spec) | {'schema','boundary'}
         and proof['schema'] == 'hepta.r10.fixed-diagnostic-parent-component-ancestor.v1'
         and proof['boundary'] == record['boundary']
         and all(proof[key] == row for key,row in spec.items()),
         'fixed ' + name + ' host original proof differs')
    raw = {key:original_from(bundle,row) for key,row in spec.items()
           if type(row) is dict and set(row) == {'path','bytes','sha256'}}
    package = strict(raw['package_manifest'])
    need(descriptor(raw['package_manifest']) == profile['package_manifest']
         and package['schema'] == 'hepta.native-guard.adapter-package.v1'
         and package['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
         and type(package['files']) is list and len(package['files']) == 32,
         name + ' requires the actual original32 package')
    pins = {row['path']:row for row in package['files']}
    need(len(pins) == 32 and type(proof['package_files']) is list
         and len(proof['package_files']) == 32, name + ' package member set differs')
    source = {}
    root = Path(spec['package_manifest']['path']).parent
    for item in proof['package_files']:
        need(type(item) is dict and set(item) == {'name','copy'}
             and item['name'] in pins and item['name'] not in source,
             name + ' package member is absent or repeated')
        row = pins[item['name']]
        need(item['copy'] == dict(path=str(root/item['name']),
              **{k:row[k] for k in ('bytes','sha256')}),
             name + ' package member path or pin differs')
        source[item['name']] = original_from(bundle,item['copy'])
    need(set(source) == set(pins)
         and descriptor(source['source/late_boundary.py']) ==
             profile['publisher']
         and descriptor(source['source/component_common.py']) ==
             profile['common']
         and source['source/component_common.py'] == state['package_sources']['source/component_common.py']
         and descriptor(source['source/close_component.py']) ==
             profile['closer'],
         name + ' publisher/common/closer differs from its executed generation')
    production = {item['name']:original_from(bundle,item['copy'])
                  for item in proof['production_files']}
    old_pins = strict(source['reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(proof['production_files']) == len(production) == len(old_pins) == 15
         and set(production) == set(old_pins)
         and all(sha(body) == old_pins[name] for name,body in production.items())
         and descriptor(production['phone_observation_tools.py']) ==
             profile['mapper'],
         name + ' must retain its old ' + ('f16c' if name == 'failed902' else '8ee')
         + ' mapper and exact other14 production sources')
    combination = strict(raw['combination'])
    need(sha(raw['combination']) == profile['combination_sha256']
         and late.C.encoded(combination) == raw['combination']
         and combination['schema'] == 'hepta.native-guard.component-combination.v150.r10.1'
         and combination['live_policy_sha256'] == HISTORICAL_F821_POLICY_SHA
         and combination['production_files'] == [dict(path='production/'+name,
              **descriptor(body)) for name,body in sorted(production.items())]
         and combination['configuration'] == descriptor(raw['configuration'])
         and combination['service_inputs'] == descriptor(raw['service_inputs'])
         and strict(raw['configuration'])['service_manifest_sha256'] == sha(raw['service_inputs']),
         name + ' original combination or shared17 binding differs')
    seal = dict(schema='hepta.native-guard.component-source-seal.v150.r10.1',
        state='REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE', intended_module_release=RELEASE,
        configuration=descriptor(raw['configuration']),
        phone_service_inputs_sha256=sha(raw['service_inputs']),
        production_files=[dict(path='source/'+name,**descriptor(body))
                          for name,body in sorted(production.items())])
    need(late.C.encoded(seal) == raw['source_seal']
         and combination['source_seal'] == descriptor(raw['source_seal']),
         name + ' source seal must be reconstructed only from its old source bytes')
    checked, inventory, closure = late.closed_boundary_originals(
        raw['boundary_copy'],raw['inventory_copy'],raw['closure_copy'],
        original_descriptor=record['boundary'],
        combination_sha256=CURRENT_COMBINATION_SHA,package_sha256=PACKAGE_SHA)
    need(checked == boundary and predicate(boundary)
         and strict(raw['published_boundary_descriptor_file']) == record['boundary']
         and boundary['prior_boundary'] == prior()
         and boundary['component_qualified'] is False and boundary['actual_native_calls'] == 1
         and closure['unknown_effects'] == 0 and closure['native_status'] == 'provider_failed',
         'fixed ' + name + ' closure was omitted, reinterpreted or credited to the current generation')
    result = strict(raw['root_result']); previous = strict(raw['closed_previous'])
    need(result['state'] == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
         and result['scope'] == boundary['scope'] and result['late_boundary'] == record['boundary']
         and result['previous'] == spec['closed_previous']
         and result['component_qualified'] is False and result['native_status'] == 'provider_failed'
         and result['automatic_retry'] is False and result['business_qualified'] is False
         and type(result['model_requests']) is int and result['model_requests'] == 0
         and result['four_role_qualification'] is False,
         name + ' original Root result changed its closure or qualification')
    need(previous['identity'] == boundary['scope'] and previous['late_boundary'] == record['boundary']
         and previous['closed_component'] == spec['closure_copy']
         and previous['component_qualified'] is False and previous['terminal']['status'] == 'provider_failed'
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True
         and previous['complete_business_success'] is False and previous['automatic_replay'] is False,
         name + ' recovered previous is not its exact closed native scope')
    steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
    need(len(steps) == 1 and steps[0]['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
         and type(steps[0]['returncode']) is int and steps[0]['returncode'] == 0
         and steps[0]['automatic_retry'] is False
         and steps[0]['stdout'] == spec['publication_operation']
         and steps[0]['stderr'] == spec['publication_stderr'],
         name + ' publication original process terminal differs')
    operation = strict(raw['publication_operation'])
    need(raw['publication_stderr'] == b''
         and type(operation['actor_rc']) is int and operation['actor_rc'] == 0
         and type(operation['wrapper']['phone']['rc']) is int and operation['wrapper']['phone']['rc'] == 0
         and type(operation['wrapper']['phone']['stdout']) is str,
         name + ' publication actor/phone terminal differs')
    need(strict(operation['wrapper']['phone']['stdout'].encode('utf-8')) ==
         {'schema':'hepta.native-guard.boundary-publish-result.v1',
          'state':'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED','boundary':record['boundary'],
          'old_retirement_current_equality_claimed':False,'original_retirement_rewritten':False,
          'phone_tool_calls':0,'model_requests':0,'signals':0,'automatic_retry':False},
         name + ' publication body names another original')
    recovery = strict(raw['recovery_result'])
    need(recovery['schema'] == 'hepta.native-current.same-scope-recovery-result.v1'
         and recovery['state'] == 'ORIGINAL_NORMAL_TAIL_CLOSED_AND_PUBLISHED'
         and recovery['source'] == spec['recovery_source']
         and recovery['root_result'] == spec['root_result']
         and recovery['boundary'] == spec['boundary_copy'] and recovery['closure'] == spec['closure_copy']
         and recovery['previous'] == spec['closed_previous']
         and recovery['recovery_intent'] == spec['recovery_intent']
         and recovery['recovery_admission'] == spec['recovery_admission']
         and recovery['original_root_failure'] == spec['original_root_failure']
         and recovery['original_sender_result'] == spec['original_sender_result']
         and recovery['original_sender_wait_fabricated'] is False
         and recovery['original_lease_expiry_unchanged'] is True
         and type(recovery['unknown_effects']) is int and recovery['unknown_effects'] == 0
         and type(recovery['actual_native_calls']) is int and recovery['actual_native_calls'] == 1
         and recovery['native_status'] == 'provider_failed'
         and all(recovery[k] is False for k in ('component_qualified','business_qualified',
              'new_nonce','new_send','new_fixture','new_launch','automatic_retry'))
         and type(recovery['model_requests']) is int and recovery['model_requests'] == 0,
         name + ' same-scope recovery was replayed, reassigned or upgraded')
    plan = strict(raw['original_root_plan'])
    need(plan['nonce'] == profile['nonce'] and plan['case_id'] == 'NEG-01'
         and plan['package'] == spec['package_manifest']
         and plan['previous']['sha256'] == profile['input_previous_sha256']
         and plan['previous'] != spec['closed_previous'],
         name + ' input ' + ('actual08' if name == 'failed902' else 'failed902')
         + ' predecessor was confused with its closed output previous')
    provenance = provenance_reader()
    need(provenance['implementation_source_sha256'] == sha(state['package_sources']['source/late_boundary.py'])
         and provenance['historical_publisher_source_sha256'] == sha(source['source/late_boundary.py'])
         and provenance['historical_mapper_sha256'] == sha(production['phone_observation_tools.py'])
         and provenance['historical_publisher_executed_unchanged'] is False
         and provenance['historical_mapper_recomputed_with_current_source'] is False,
         'historical publisher and current reader implementation provenance differ')
    return proof



NEW_DIAGNOSTIC_HISTORY_PROFILES = json.loads("{\n  \"phone_calls\": 0,\n  \"profiles\": {\n    \"failed820\": {\n      \"input_previous\": {\n        \"bytes\": 1432,\n        \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/ACTUAL-PREVIOUS-INPUT.json\",\n        \"sha256\": \"0f8cf33cf9e6d92c92a7bf465d65bafe537101bc4ee77b1b8faf79e63d39e1e5\"\n      },\n      \"nonce\": \"82012c7447c5f35d97c832d1d9481860\",\n      \"package_state\": \"HOST_REVIEWED_NOT_PHONE_QUALIFIED\",\n      \"record\": {\n        \"boundary\": {\n          \"bytes\": 21002,\n          \"metadata\": [\n            65086,\n            159031,\n            33152,\n            0,\n            0,\n            1,\n            21002,\n            1793920477083899777,\n            1793920477083899777\n          ],\n          \"path\": \"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/82012c7447c5f35d97c832d1d9481860.json\",\n          \"sha256\": \"2433dd817e470e9536ec314b6a8e9d395a47053f7c1aba1cd7adee35635843fc\"\n        },\n        \"closure\": {\n          \"bytes\": 66879,\n          \"metadata\": [\n            65086,\n            158937,\n            33152,\n            0,\n            0,\n            1,\n            66879,\n            1793920473643899779,\n            1793920473643899779\n          ],\n          \"path\": \"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/82012c7447c5f35d97c832d1d9481860/CLOSURE.original.json\",\n          \"sha256\": \"d2671a0f936f3c1c7e4846117050880bb3140e13fe4fb7723be7786d83d66ccf\"\n        },\n        \"inventory\": {\n          \"bytes\": 1107000,\n          \"metadata\": [\n            65086,\n            158938,\n            33152,\n            0,\n            0,\n            1,\n            1107000,\n            1793920473643899779,\n            1793920473643899779\n          ],\n          \"path\": \"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/82012c7447c5f35d97c832d1d9481860/AFTER-INVENTORY.original.json\",\n          \"sha256\": \"115893679cea5f3606f4adef61c4b01ecdc65870b6aa0c8c862df4e0313f90aa\"\n        }\n      },\n      \"root_package_state\": \"HOST_REVIEWED_DIAG02_TWO_SIDEBRANCH_SOURCES_FROZEN_NOT_PHONE_QUALIFIED\",\n      \"spec\": {\n        \"boundary_copy\": {\n          \"bytes\": 21002,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/LATE-BOUNDARY.original.json\",\n          \"sha256\": \"2433dd817e470e9536ec314b6a8e9d395a47053f7c1aba1cd7adee35635843fc\"\n        },\n        \"closed_previous\": {\n          \"bytes\": 1435,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/ACTUAL-PREVIOUS-INPUT.json\",\n          \"sha256\": \"9d841e878f6a967d039fe559e68a2974dad497570f3692e22c324ed99865d9dc\"\n        },\n        \"closure_copy\": {\n          \"bytes\": 66879,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/CLOSURE.json\",\n          \"sha256\": \"d2671a0f936f3c1c7e4846117050880bb3140e13fe4fb7723be7786d83d66ccf\"\n        },\n        \"combination\": {\n          \"bytes\": 4695,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/COMBINATION.json\",\n          \"sha256\": \"765e66acedee58e41de0ef45b6ea8061709e5b63a7aef43437876349289e86ec\"\n        },\n        \"configuration\": {\n          \"bytes\": 1493,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/local-config-r10-r1.json\",\n          \"sha256\": \"99f98a4898e5d83d7cda3b56f919f694010d6490c0840b538190e89e9f6f63e2\"\n        },\n        \"inventory_copy\": {\n          \"bytes\": 1107000,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/INVENTORY.json\",\n          \"sha256\": \"115893679cea5f3606f4adef61c4b01ecdc65870b6aa0c8c862df4e0313f90aa\"\n        },\n        \"original_root_failure\": {\n          \"bytes\": 21062,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/ROOT-FAILURE.json\",\n          \"sha256\": \"bbd8b55f401aae3fb9695ccb04085406fac76de125ceb4474778ec0c468d3582\"\n        },\n        \"original_root_plan\": {\n          \"bytes\": 4816,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/ROOT-PLAN.original.json\",\n          \"sha256\": \"15399913b9d80e94ac44971ba99116ebb9f2d0042eab9fa327fb92f8f5805400\"\n        },\n        \"original_sender_result\": {\n          \"bytes\": 704,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-sides01.send-result.json\",\n          \"sha256\": \"daa9f8f7874b37470d9d748dd8f99e439b03deec57079a32a1586a6b9bfaec40\"\n        },\n        \"package_files\": [\n          {\n            \"copy\": {\n              \"bytes\": 1438,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/REVIEWED-PRODUCTION-PINS.json\",\n              \"sha256\": \"4b8f1f94f08f33ea385b418d4ab95d6224cb75847ad71536c2135716428d60dc\"\n            },\n            \"name\": \"reference/REVIEWED-PRODUCTION-PINS.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 664638,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/attempt05-AFTER-INVENTORY.original.json\",\n              \"sha256\": \"87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e\"\n            },\n            \"name\": \"reference/attempt05-AFTER-INVENTORY.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 164095,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/attempt05-CLOSURE.original.json\",\n              \"sha256\": \"d464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6\"\n            },\n            \"name\": \"reference/attempt05-CLOSURE.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 4650,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/attempt05-SIDE-PROOF.original.json\",\n              \"sha256\": \"1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c\"\n            },\n            \"name\": \"reference/attempt05-SIDE-PROOF.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 18133,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/component_common_r5.py\",\n              \"sha256\": \"8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02\"\n            },\n            \"name\": \"reference/component_common_r5.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 13238,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/component_core.py\",\n              \"sha256\": \"705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f\"\n            },\n            \"name\": \"reference/component_core.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 30647,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/component_once_r9.py\",\n              \"sha256\": \"1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2\"\n            },\n            \"name\": \"reference/component_once_r9.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 4116,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/decode_client_state.py\",\n              \"sha256\": \"a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073\"\n            },\n            \"name\": \"reference/decode_client_state.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 1031582,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/diag02-AFTER-INVENTORY.original.json\",\n              \"sha256\": \"10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d\"\n            },\n            \"name\": \"reference/diag02-AFTER-INVENTORY.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 253127,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/diag02-CLOSURE.original.json\",\n              \"sha256\": \"e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035\"\n            },\n            \"name\": \"reference/diag02-CLOSURE.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 8439,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/diag02-SIDE-PROOF.original.json\",\n              \"sha256\": \"a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd\"\n            },\n            \"name\": \"reference/diag02-SIDE-PROOF.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 53502,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/environment_parent_late_boundary_r6.py\",\n              \"sha256\": \"1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c\"\n            },\n            \"name\": \"reference/environment_parent_late_boundary_r6.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 28109,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/native_guard_session.py\",\n              \"sha256\": \"77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b\"\n            },\n            \"name\": \"reference/native_guard_session.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 6701,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/native_journal_audit.py\",\n              \"sha256\": \"da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf\"\n            },\n            \"name\": \"reference/native_journal_audit.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 19740,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/non_native_attempt05.py\",\n              \"sha256\": \"a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4\"\n            },\n            \"name\": \"reference/non_native_attempt05.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 29504,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/non_native_diag02.py\",\n              \"sha256\": \"296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6\"\n            },\n            \"name\": \"reference/non_native_diag02.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 35730,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/policy_parent_late_boundary_r4.py\",\n              \"sha256\": \"bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b\"\n            },\n            \"name\": \"reference/policy_parent_late_boundary_r4.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 62434,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/property_parent_late_boundary_r7.py\",\n              \"sha256\": \"3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd\"\n            },\n            \"name\": \"reference/property_parent_late_boundary_r7.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 40788,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/send_new_native_task_r5.py\",\n              \"sha256\": \"5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281\"\n            },\n            \"name\": \"reference/send_new_native_task_r5.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 17390,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/reference/tool_client_r6.py\",\n              \"sha256\": \"500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f\"\n            },\n            \"name\": \"reference/tool_client_r6.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 103014,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/close_component.py\",\n              \"sha256\": \"5cf82a59264f87ea565581a8d29790dacdad9a17ec67b3b17e15cd4762494f87\"\n            },\n            \"name\": \"source/close_component.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 19138,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/component_common.py\",\n              \"sha256\": \"1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab\"\n            },\n            \"name\": \"source/component_common.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 40451,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/component_lifecycle.py\",\n              \"sha256\": \"ac2fab650064150c77368fd64b1e6c7ff178967887f8815c690a6cb539e42b64\"\n            },\n            \"name\": \"source/component_lifecycle.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 39012,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/component_listener.py\",\n              \"sha256\": \"6db4eb9f55bc3313b635bdd05584901706213a9d47ac2f48b81a28cdb91313ec\"\n            },\n            \"name\": \"source/component_listener.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 25514,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/component_snapshot.py\",\n              \"sha256\": \"db440a1676e69e9d26b95be6a5046639aff26786f75fb2b06aa21919fca7cdb4\"\n            },\n            \"name\": \"source/component_snapshot.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 111262,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/late_boundary.py\",\n              \"sha256\": \"7b085c88e5e4bfd78ddfaa41f9db47b8476644127e798fcd918599ca32652980\"\n            },\n            \"name\": \"source/late_boundary.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 28878,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/native_guard_session_r2.py\",\n              \"sha256\": \"5fe50be4dccbe655a39124876d1f9c2199de20d80ec0a84f08a63d88e7f1a931\"\n            },\n            \"name\": \"source/native_guard_session_r2.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 4633,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/native_proc_profile.py\",\n              \"sha256\": \"12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b\"\n            },\n            \"name\": \"source/native_proc_profile.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 14256,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/prepare_component.py\",\n              \"sha256\": \"7f83fcf44add56911d11d7aa29f1d51b2e1ea1b4ee4d6b2b9f267a639d85ed0d\"\n            },\n            \"name\": \"source/prepare_component.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 18725,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/root_fixture_once.py\",\n              \"sha256\": \"be9fe6b49c0575ec25b7c4aea36ace01849edc018942d41fcd44228d3e4340a8\"\n            },\n            \"name\": \"source/root_fixture_once.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 39144,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/root_fixture_originals.py\",\n              \"sha256\": \"15327d33c68ed60d48afc46757e1dfd1bd8b4bf9d666607bde9f5150e123826c\"\n            },\n            \"name\": \"source/root_fixture_originals.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 10498,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/run_root_fixture_phase.py\",\n              \"sha256\": \"bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2\"\n            },\n            \"name\": \"source/run_root_fixture_phase.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 41080,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/send_new_native_guard_task_r10_r4.py\",\n              \"sha256\": \"2ed23a550e3afba234c1cc6c21f310384a3f152b00158af5d756cc35daaeb71d\"\n            },\n            \"name\": \"source/send_new_native_guard_task_r10_r4.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 25040,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/sender_native_guard_ready_r10_r4.py\",\n              \"sha256\": \"55cbea1970c0ada854fddb8ad11adc1938d00a82c940a6161731b46cfb1d32cf\"\n            },\n            \"name\": \"source/sender_native_guard_ready_r10_r4.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 19085,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/stage_component.py\",\n              \"sha256\": \"4e781cd6431d71631cb0c01f8f35845b289f8c74f8cf2a3de229dbbb31c18374\"\n            },\n            \"name\": \"source/stage_component.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 18143,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/source/witness_bundle.py\",\n              \"sha256\": \"8e8e1aa967ba9fd96d9bae80eb40c6322763ba1109b015b399e4c08ad14d5557\"\n            },\n            \"name\": \"source/witness_bundle.py\"\n          }\n        ],\n        \"package_manifest\": {\n          \"bytes\": 38094,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/runtime/MANIFEST.json\",\n          \"sha256\": \"5efc7e38d40cb74111001a961e9060eac72050fd5aca9d5bf6fcc08c5d017f47\"\n        },\n        \"production_files\": [\n          {\n            \"copy\": {\n              \"bytes\": 15587,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/action_ledger.py\",\n              \"sha256\": \"50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907\"\n            },\n            \"name\": \"action_ledger.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 22059,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/daily_phone_local.py\",\n              \"sha256\": \"07cd44148050e48b972a992a47c8422da81b334298fc684be9909795a1ece812\"\n            },\n            \"name\": \"daily_phone_local.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 11439,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/health_contracts.py\",\n              \"sha256\": \"00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d\"\n            },\n            \"name\": \"health_contracts.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 15135,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/ledger_round_evidence.py\",\n              \"sha256\": \"87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d\"\n            },\n            \"name\": \"ledger_round_evidence.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 8251,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/model_health.py\",\n              \"sha256\": \"105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80\"\n            },\n            \"name\": \"model_health.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 37375,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/model_slot_cleanup.py\",\n              \"sha256\": \"9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183\"\n            },\n            \"name\": \"model_slot_cleanup.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 10453,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/phone_local_http_worker.py\",\n              \"sha256\": \"a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d\"\n            },\n            \"name\": \"phone_local_http_worker.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 13813,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/phone_local_tools.py\",\n              \"sha256\": \"0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54\"\n            },\n            \"name\": \"phone_local_tools.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 43445,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/phone_observation_tools.py\",\n              \"sha256\": \"5f65cc1ac383eca37f1081fae775be8d4243eae91169ba958a72c85b24476eb7\"\n            },\n            \"name\": \"phone_observation_tools.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 22825,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/phone_task_guards.py\",\n              \"sha256\": \"87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86\"\n            },\n            \"name\": \"phone_task_guards.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 41510,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/provider_codex_host.py\",\n              \"sha256\": \"cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039\"\n            },\n            \"name\": \"provider_codex_host.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 17730,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/provider_openai_compatible.py\",\n              \"sha256\": \"337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc\"\n            },\n            \"name\": \"provider_openai_compatible.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 70237,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/provider_phone_local.py\",\n              \"sha256\": \"082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6\"\n            },\n            \"name\": \"provider_phone_local.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 9802,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/retirement_recovery.py\",\n              \"sha256\": \"c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827\"\n            },\n            \"name\": \"retirement_recovery.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 23211,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/provider/source/task_postconditions.py\",\n              \"sha256\": \"d4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3\"\n            },\n            \"name\": \"task_postconditions.py\"\n          }\n        ],\n        \"publication_operation\": {\n          \"bytes\": 2268,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/phone-late-publish/stdout.original\",\n          \"sha256\": \"2426afb229ca9cbde2f99f43eed8745598e243fc15638aadfa090f2ce57c4214\"\n        },\n        \"publication_stderr\": {\n          \"bytes\": 0,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/phone-late-publish/stderr.original\",\n          \"sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n        },\n        \"published_boundary_descriptor_file\": {\n          \"bytes\": 369,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/LATE-BOUNDARY-DESCRIPTOR.json\",\n          \"sha256\": \"f7d7f662ee9aba82713d4d7c16384b5435061c8dfb39362c88b4ab6afd8cb7dd\"\n        },\n        \"recovery_admission\": {\n          \"bytes\": 9617,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/RECOVERY-ADMISSION.json\",\n          \"sha256\": \"f3de981ca591107336c49f5f295dcb09a86352a006f49c64279518dd1c47c0c4\"\n        },\n        \"recovery_intent\": {\n          \"bytes\": 454027,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/RECOVERY-INTENT.json\",\n          \"sha256\": \"4d4d8118f95e160eaf3a794d8755140d21e1575aacc62e94e436bc29a160d096\"\n        },\n        \"recovery_result\": {\n          \"bytes\": 3455,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/RECOVERY-RESULT.json\",\n          \"sha256\": \"6b4bd0fcf6ecf94913d9560f20c0ec0fdf113c2a7b32064f2f01ab9073e1bd2e\"\n        },\n        \"recovery_source\": {\n          \"bytes\": 44576,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-current-scope-recovery-7c907661-sides01-candidate01/source/resume_current_failed_scope.py\",\n          \"sha256\": \"c94854b04150fc2bc772998d19bc7c904287044aa6f3af3a8d07eaaaf16b1f8f\"\n        },\n        \"root_result\": {\n          \"bytes\": 37375,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/ROOT-RESULT.json\",\n          \"sha256\": \"b3287cfe4862f2f4cf4c384a2e961b0cdf7a5a7313cf5f43562c49307d940982\"\n        },\n        \"root_sources\": [\n          {\n            \"copy\": {\n              \"bytes\": 126796,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/root-chain/reference/policy_native5_verifier.py\",\n              \"sha256\": \"74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152\"\n            },\n            \"name\": \"reference/policy_native5_verifier.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 8098,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/root-chain/source/phone_chain_bridge.py\",\n              \"sha256\": \"a0f12f8e55e055704db765ecb2d6556f8cca05b2031d1f231713aa93c3a490f5\"\n            },\n            \"name\": \"source/phone_chain_bridge.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 72674,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/root-chain/source/run_component_root_once.py\",\n              \"sha256\": \"dcb380efb71ddf76db046eeac34be745928c773b2071da82776a39956bce215b\"\n            },\n            \"name\": \"source/run_component_root_once.py\"\n          }\n        ],\n        \"sender_phase_originals\": {\n          \"CHILD.json\": {\n            \"bytes\": 906,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/sender-execute/CHILD.json\",\n            \"sha256\": \"683f1fb69d7012fc2c56d53baf01eaeffbc895f44582c58325d3f8268e26ddf9\"\n          },\n          \"INTENT.json\": {\n            \"bytes\": 2303,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/sender-execute/INTENT.json\",\n            \"sha256\": \"4420c35994d9399eac274fe479c93bb2ba3ebbb84f5bb478cf06036b598c9909\"\n          },\n          \"OUTPUT-CAPTURE.json\": {\n            \"bytes\": 2565,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/sender-execute/OUTPUT-CAPTURE.json\",\n            \"sha256\": \"4a9457b5bc13c7b992db5a532aa44445b5312832cca7957fd99268e41f2828f6\"\n          },\n          \"stderr.original\": {\n            \"bytes\": 0,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/sender-execute/stderr.original\",\n            \"sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n          },\n          \"stdout.original\": {\n            \"bytes\": 0,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/sender-execute/stdout.original\",\n            \"sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n          }\n        },\n        \"service_inputs\": {\n          \"bytes\": 10671,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json\",\n          \"sha256\": \"edf6eef13a765abcacf9eaeae814daf6d2247de88564c6103cfc911a152b7870\"\n        },\n        \"shared_manifest\": {\n          \"bytes\": 3519,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/shared/SHARED-MATERIALS.json\",\n          \"sha256\": \"f49404a413d11445f21287147a71fd3fd1e3173c78722ef6ca1957a9b8487b26\"\n        },\n        \"source_package\": {\n          \"bytes\": 31577,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/root-chain/SOURCE-MANIFEST.json\",\n          \"sha256\": \"bed573c476c0bad857359de2a61eeabab22809a51e7016d3edba64473291031d\"\n        },\n        \"source_seal\": {\n          \"bytes\": 2341,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-diag02-sides-r1/SOURCE-SEAL.json\",\n          \"sha256\": \"cf07025b1124c8ec2a4d2c79d475a8aec4375731b23ac56aeb361e0225de7a88\"\n        }\n      }\n    },\n    \"v3runtime\": {\n      \"input_previous\": {\n        \"bytes\": 1435,\n        \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/ACTUAL-PREVIOUS-INPUT.json\",\n        \"sha256\": \"9d841e878f6a967d039fe559e68a2974dad497570f3692e22c324ed99865d9dc\"\n      },\n      \"nonce\": \"a493b853566d68099f7dbc0a124aff50\",\n      \"package_state\": \"HOST_REVIEWED_NOT_PHONE_QUALIFIED\",\n      \"record\": {\n        \"boundary\": {\n          \"bytes\": 21325,\n          \"metadata\": [\n            65086,\n            158182,\n            33152,\n            0,\n            0,\n            1,\n            21325,\n            1793928633271896666,\n            1793928633271896666\n          ],\n          \"path\": \"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50.json\",\n          \"sha256\": \"fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66\"\n        },\n        \"closure\": {\n          \"bytes\": 70349,\n          \"metadata\": [\n            65086,\n            156987,\n            33152,\n            0,\n            0,\n            1,\n            70349,\n            1793928630371896667,\n            1793928630371896667\n          ],\n          \"path\": \"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50/CLOSURE.original.json\",\n          \"sha256\": \"ed3163d67036a437bc3855bad22543bc5bb9d8ecf71e1952b704f1dfa3eac7f2\"\n        },\n        \"inventory\": {\n          \"bytes\": 1182289,\n          \"metadata\": [\n            65086,\n            158128,\n            33152,\n            0,\n            0,\n            1,\n            1182289,\n            1793928630371896667,\n            1793928630371896667\n          ],\n          \"path\": \"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/a493b853566d68099f7dbc0a124aff50/AFTER-INVENTORY.original.json\",\n          \"sha256\": \"bd880b6dbfe1a870eab9d0dc6e3916e8bc539d115975c5b983c65742fbab6242\"\n        }\n      },\n      \"root_package_state\": \"HOST_REVIEWED_DIAGNOSTIC_ONLY_V3_F821_NOT_PHONE_QUALIFIED\",\n      \"spec\": {\n        \"archive_original\": {\n          \"bytes\": 3326734,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/ORIGINALS.tar.gz\",\n          \"sha256\": \"e6c1898696b1eb7af86e058867ed0276bb32ab2a48a7026894bc2bcbe8562d6a\"\n        },\n        \"boundary_copy\": {\n          \"bytes\": 21325,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/LATE-BOUNDARY.original.json\",\n          \"sha256\": \"fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66\"\n        },\n        \"capture_proof\": {\n          \"bytes\": 6483,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/CONTINUATION-CAPTURE-PROOF.json\",\n          \"sha256\": \"4b4e52d5899b995d7861264d0b070399a039cdb1e5ce9ffeb64ff632bacda695\"\n        },\n        \"closed_previous\": {\n          \"bytes\": 1434,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/ACTUAL-PREVIOUS-INPUT.json\",\n          \"sha256\": \"35cc7f4b24379781dae7f181704218b612d9a42313b7efee9a52d649f37e1099\"\n        },\n        \"closure_copy\": {\n          \"bytes\": 70349,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/CLOSURE.json\",\n          \"sha256\": \"ed3163d67036a437bc3855bad22543bc5bb9d8ecf71e1952b704f1dfa3eac7f2\"\n        },\n        \"combination\": {\n          \"bytes\": 4695,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/COMBINATION.json\",\n          \"sha256\": \"f265d39c001aa09a813a03b92b0a96689ab1bcc431c8e408c8ce4da80693a945\"\n        },\n        \"configuration\": {\n          \"bytes\": 1493,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/local-config-r10-r1.json\",\n          \"sha256\": \"22f57380a8bf92d88f0a0d7eda700adc7c711464975d7184b0dce48b3bdd5d3e\"\n        },\n        \"continuation_admission\": {\n          \"bytes\": 417432,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/CONTINUATION-ADMISSION.json\",\n          \"sha256\": \"6aa7965e5664a9c84ab4ca4d38956e8f04b6198d6b229e06ed854c06a6b3bc02\"\n        },\n        \"continuation_inputs\": {\n          \"bytes\": 74100,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-v3-closure-continuation-a1055-r1.inputs.json\",\n          \"sha256\": \"e074f2f1970e6eb3ac0134f65acc3fdef4590f385bd9ba058940b5460d251475\"\n        },\n        \"continuation_intent\": {\n          \"bytes\": 1879,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/CONTINUATION-INTENT.json\",\n          \"sha256\": \"394e16da6989acf1925de01c7d65ecb00b268b4b6895516165088dcda6b8b9e4\"\n        },\n        \"continuation_result\": {\n          \"bytes\": 3608,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/CONTINUATION-RESULT.json\",\n          \"sha256\": \"11693650d909a18ec94127571e18614e1feb8eba6cef53d06edb703e733cea35\"\n        },\n        \"diagnostic_cause_evidence\": {\n          \"bytes\": 4540,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/DIAGNOSTIC-CAUSE-EVIDENCE.json\",\n          \"sha256\": \"3e63f7141a796874f02aff8fa699406fc35eae56c50ac37bba16ab33ae137840\"\n        },\n        \"inventory_copy\": {\n          \"bytes\": 1182289,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/INVENTORY.json\",\n          \"sha256\": \"bd880b6dbfe1a870eab9d0dc6e3916e8bc539d115975c5b983c65742fbab6242\"\n        },\n        \"lease\": {\n          \"bytes\": 2506,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/material/tree/LEASE.json\",\n          \"sha256\": \"bce28bcc461081e1558a92f17e11a2330b061ff4917f72cacc30c1761775d3ef\"\n        },\n        \"original_root_failure\": {\n          \"bytes\": 18412,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/ROOT-FAILURE.json\",\n          \"sha256\": \"753771fc1bf4e243c0a3648fa19acf5aa32e7a54619f1a7b9319e636b69f135f\"\n        },\n        \"original_root_plan\": {\n          \"bytes\": 4847,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/ROOT-PLAN.original.json\",\n          \"sha256\": \"a05482b2e5b973de801038613b6448d8ba0aef0fe2dfa38d2936e7bf732f269c\"\n        },\n        \"original_snapshot_operation\": {\n          \"bytes\": 3876,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/phone-snapshot/stdout.original\",\n          \"sha256\": \"aff7b0460ebb2dbcd90779f3967e1734ba52ddc2f88290745688dadd4381b8bc\"\n        },\n        \"original_snapshot_stderr\": {\n          \"bytes\": 0,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/phone-snapshot/stderr.original\",\n          \"sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n        },\n        \"package_files\": [\n          {\n            \"copy\": {\n              \"bytes\": 1438,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/REVIEWED-PRODUCTION-PINS.json\",\n              \"sha256\": \"970e33dedeebcf4d996160374df04d4e8dc42a3ea3895c368152f6c608e4c2ab\"\n            },\n            \"name\": \"reference/REVIEWED-PRODUCTION-PINS.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 664638,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/attempt05-AFTER-INVENTORY.original.json\",\n              \"sha256\": \"87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e\"\n            },\n            \"name\": \"reference/attempt05-AFTER-INVENTORY.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 164095,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/attempt05-CLOSURE.original.json\",\n              \"sha256\": \"d464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6\"\n            },\n            \"name\": \"reference/attempt05-CLOSURE.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 4650,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/attempt05-SIDE-PROOF.original.json\",\n              \"sha256\": \"1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c\"\n            },\n            \"name\": \"reference/attempt05-SIDE-PROOF.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 18133,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/component_common_r5.py\",\n              \"sha256\": \"8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02\"\n            },\n            \"name\": \"reference/component_common_r5.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 13238,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/component_core.py\",\n              \"sha256\": \"705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f\"\n            },\n            \"name\": \"reference/component_core.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 30647,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/component_once_r9.py\",\n              \"sha256\": \"1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2\"\n            },\n            \"name\": \"reference/component_once_r9.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 4116,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/decode_client_state.py\",\n              \"sha256\": \"a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073\"\n            },\n            \"name\": \"reference/decode_client_state.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 1031582,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/diag02-AFTER-INVENTORY.original.json\",\n              \"sha256\": \"10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d\"\n            },\n            \"name\": \"reference/diag02-AFTER-INVENTORY.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 253127,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/diag02-CLOSURE.original.json\",\n              \"sha256\": \"e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035\"\n            },\n            \"name\": \"reference/diag02-CLOSURE.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 8439,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/diag02-SIDE-PROOF.original.json\",\n              \"sha256\": \"a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd\"\n            },\n            \"name\": \"reference/diag02-SIDE-PROOF.original.json\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 53502,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/environment_parent_late_boundary_r6.py\",\n              \"sha256\": \"1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c\"\n            },\n            \"name\": \"reference/environment_parent_late_boundary_r6.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 28109,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/native_guard_session.py\",\n              \"sha256\": \"77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b\"\n            },\n            \"name\": \"reference/native_guard_session.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 6701,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/native_journal_audit.py\",\n              \"sha256\": \"da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf\"\n            },\n            \"name\": \"reference/native_journal_audit.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 19740,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/non_native_attempt05.py\",\n              \"sha256\": \"a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4\"\n            },\n            \"name\": \"reference/non_native_attempt05.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 29504,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/non_native_diag02.py\",\n              \"sha256\": \"296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6\"\n            },\n            \"name\": \"reference/non_native_diag02.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 35730,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/policy_parent_late_boundary_r4.py\",\n              \"sha256\": \"bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b\"\n            },\n            \"name\": \"reference/policy_parent_late_boundary_r4.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 62434,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/property_parent_late_boundary_r7.py\",\n              \"sha256\": \"3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd\"\n            },\n            \"name\": \"reference/property_parent_late_boundary_r7.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 40788,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/send_new_native_task_r5.py\",\n              \"sha256\": \"5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281\"\n            },\n            \"name\": \"reference/send_new_native_task_r5.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 17390,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/reference/tool_client_r6.py\",\n              \"sha256\": \"500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f\"\n            },\n            \"name\": \"reference/tool_client_r6.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 113943,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/close_component.py\",\n              \"sha256\": \"f88efe8b7fb73151ec1598ba556379c53c0aadd1073ad6da03a9ff0cbd04a2c4\"\n            },\n            \"name\": \"source/close_component.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 19138,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/component_common.py\",\n              \"sha256\": \"1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab\"\n            },\n            \"name\": \"source/component_common.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 40451,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/component_lifecycle.py\",\n              \"sha256\": \"ac2fab650064150c77368fd64b1e6c7ff178967887f8815c690a6cb539e42b64\"\n            },\n            \"name\": \"source/component_lifecycle.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 39012,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/component_listener.py\",\n              \"sha256\": \"6db4eb9f55bc3313b635bdd05584901706213a9d47ac2f48b81a28cdb91313ec\"\n            },\n            \"name\": \"source/component_listener.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 25514,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/component_snapshot.py\",\n              \"sha256\": \"db440a1676e69e9d26b95be6a5046639aff26786f75fb2b06aa21919fca7cdb4\"\n            },\n            \"name\": \"source/component_snapshot.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 121238,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/late_boundary.py\",\n              \"sha256\": \"311cfa163ba7ae603ef3483846abb52a958342ac1149cc59c842c63a79f3ab15\"\n            },\n            \"name\": \"source/late_boundary.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 29129,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/native_guard_session_r2.py\",\n              \"sha256\": \"f4fa1acc951bb7f4347cb2b55ed2e452a992b639ace9f15abcda9de8afd70881\"\n            },\n            \"name\": \"source/native_guard_session_r2.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 4633,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/native_proc_profile.py\",\n              \"sha256\": \"12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b\"\n            },\n            \"name\": \"source/native_proc_profile.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 14256,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/prepare_component.py\",\n              \"sha256\": \"7f83fcf44add56911d11d7aa29f1d51b2e1ea1b4ee4d6b2b9f267a639d85ed0d\"\n            },\n            \"name\": \"source/prepare_component.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 18725,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/root_fixture_once.py\",\n              \"sha256\": \"be9fe6b49c0575ec25b7c4aea36ace01849edc018942d41fcd44228d3e4340a8\"\n            },\n            \"name\": \"source/root_fixture_once.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 39144,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/root_fixture_originals.py\",\n              \"sha256\": \"15327d33c68ed60d48afc46757e1dfd1bd8b4bf9d666607bde9f5150e123826c\"\n            },\n            \"name\": \"source/root_fixture_originals.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 10498,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/run_root_fixture_phase.py\",\n              \"sha256\": \"bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2\"\n            },\n            \"name\": \"source/run_root_fixture_phase.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 41080,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/send_new_native_guard_task_r10_r4.py\",\n              \"sha256\": \"2ed23a550e3afba234c1cc6c21f310384a3f152b00158af5d756cc35daaeb71d\"\n            },\n            \"name\": \"source/send_new_native_guard_task_r10_r4.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 25040,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/sender_native_guard_ready_r10_r4.py\",\n              \"sha256\": \"55cbea1970c0ada854fddb8ad11adc1938d00a82c940a6161731b46cfb1d32cf\"\n            },\n            \"name\": \"source/sender_native_guard_ready_r10_r4.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 19085,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/stage_component.py\",\n              \"sha256\": \"4e781cd6431d71631cb0c01f8f35845b289f8c74f8cf2a3de229dbbb31c18374\"\n            },\n            \"name\": \"source/stage_component.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 18143,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/source/witness_bundle.py\",\n              \"sha256\": \"8e8e1aa967ba9fd96d9bae80eb40c6322763ba1109b015b399e4c08ad14d5557\"\n            },\n            \"name\": \"source/witness_bundle.py\"\n          }\n        ],\n        \"package_manifest\": {\n          \"bytes\": 39790,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/MANIFEST.json\",\n          \"sha256\": \"d30e58c42205fa99cdb9367d7f1186532d27a1d20a2bfe20a1c41c387ddffc70\"\n        },\n        \"production_files\": [\n          {\n            \"copy\": {\n              \"bytes\": 15587,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/action_ledger.py\",\n              \"sha256\": \"50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907\"\n            },\n            \"name\": \"action_ledger.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 22059,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/daily_phone_local.py\",\n              \"sha256\": \"ca23c60bbb4114960c6a571492cacd9e0bdc3404191409ac78bcf0c34a06c1d0\"\n            },\n            \"name\": \"daily_phone_local.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 11439,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/health_contracts.py\",\n              \"sha256\": \"00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d\"\n            },\n            \"name\": \"health_contracts.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 15135,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/ledger_round_evidence.py\",\n              \"sha256\": \"87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d\"\n            },\n            \"name\": \"ledger_round_evidence.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 8251,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/model_health.py\",\n              \"sha256\": \"105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80\"\n            },\n            \"name\": \"model_health.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 37375,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/model_slot_cleanup.py\",\n              \"sha256\": \"9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183\"\n            },\n            \"name\": \"model_slot_cleanup.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 10453,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/phone_local_http_worker.py\",\n              \"sha256\": \"a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d\"\n            },\n            \"name\": \"phone_local_http_worker.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 13813,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/phone_local_tools.py\",\n              \"sha256\": \"0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54\"\n            },\n            \"name\": \"phone_local_tools.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 43445,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/phone_observation_tools.py\",\n              \"sha256\": \"2c5ebb75e34fcce4c14638939809dade1f6d129504270930c8f94e2c2ce15b66\"\n            },\n            \"name\": \"phone_observation_tools.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 22825,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/phone_task_guards.py\",\n              \"sha256\": \"87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86\"\n            },\n            \"name\": \"phone_task_guards.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 41510,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/provider_codex_host.py\",\n              \"sha256\": \"cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039\"\n            },\n            \"name\": \"provider_codex_host.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 17730,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/provider_openai_compatible.py\",\n              \"sha256\": \"337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc\"\n            },\n            \"name\": \"provider_openai_compatible.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 70237,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/provider_phone_local.py\",\n              \"sha256\": \"082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6\"\n            },\n            \"name\": \"provider_phone_local.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 9802,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/retirement_recovery.py\",\n              \"sha256\": \"c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827\"\n            },\n            \"name\": \"retirement_recovery.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 23211,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/provider/source/task_postconditions.py\",\n              \"sha256\": \"d4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3\"\n            },\n            \"name\": \"task_postconditions.py\"\n          }\n        ],\n        \"publication_operation\": {\n          \"bytes\": 2264,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/phone-late-publish/stdout.original\",\n          \"sha256\": \"c410bf9db5d052ca11aec4b4b239b89df6a9a8c6b9dfd45be7780ce9204da2bd\"\n        },\n        \"publication_stderr\": {\n          \"bytes\": 0,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/phone-late-publish/stderr.original\",\n          \"sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n        },\n        \"published_boundary_descriptor_file\": {\n          \"bytes\": 369,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/LATE-BOUNDARY-DESCRIPTOR.json\",\n          \"sha256\": \"6bde211aa8dba3caebea3ec4228a31851267c22c875f52f953b7144577428eb5\"\n        },\n        \"recovery_source\": {\n          \"bytes\": 35149,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-v3-closure-continuation-a1055-r1.py\",\n          \"sha256\": \"140e702242ae79829d47cdaf663efe5bf890e589a33b693e7bc04d5869caab25\"\n        },\n        \"root_result\": {\n          \"bytes\": 35980,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/ROOT-RESULT.json\",\n          \"sha256\": \"d3a104c26dc8becc607cf1876063d5670939a1b1331923a4c7ee22232c6a857c\"\n        },\n        \"root_sources\": [\n          {\n            \"copy\": {\n              \"bytes\": 126796,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/root-chain/reference/policy_native5_verifier.py\",\n              \"sha256\": \"74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152\"\n            },\n            \"name\": \"reference/policy_native5_verifier.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 8100,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/root-chain/source/phone_chain_bridge.py\",\n              \"sha256\": \"cc3f417e8650f70d1760cba9e1b13bed21af84aaccb01eec5af5c7ca7660a690\"\n            },\n            \"name\": \"source/phone_chain_bridge.py\"\n          },\n          {\n            \"copy\": {\n              \"bytes\": 73648,\n              \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/root-chain/source/run_component_root_once.py\",\n              \"sha256\": \"4ecae57f6b5045c269f4a59bf4c2385372b67d94dffece2aa0de9785b903961e\"\n            },\n            \"name\": \"source/run_component_root_once.py\"\n          }\n        ],\n        \"sender_joined\": {\n          \"bytes\": 91,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/sender-execute/JOINED.json\",\n          \"sha256\": \"23a73841a89e1101e063fa1b52892988330616c68c6246f56ad5c13140a6b18b\"\n        },\n        \"sender_phase_originals\": {\n          \"CHILD.json\": {\n            \"bytes\": 907,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/sender-execute/CHILD.json\",\n            \"sha256\": \"afc18c6834bc24faf3403d4caa4dc3b9fdccbd0b4ea87104d6bdb93c0f2f8a6c\"\n          },\n          \"INTENT.json\": {\n            \"bytes\": 2313,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/sender-execute/INTENT.json\",\n            \"sha256\": \"78bfa6048691fb0115861d831f0c28cdec2b62e73b13039b34d00c2e1a4b2b1f\"\n          },\n          \"JOINED.json\": {\n            \"bytes\": 91,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/sender-execute/JOINED.json\",\n            \"sha256\": \"23a73841a89e1101e063fa1b52892988330616c68c6246f56ad5c13140a6b18b\"\n          },\n          \"OUTPUT-CAPTURE.json\": {\n            \"bytes\": 2516,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/sender-execute/OUTPUT-CAPTURE.json\",\n            \"sha256\": \"5a9346b957919792cf6b8519dfac99e66ad2a948353bc8aaa7bfa6ecb0aecaf5\"\n          },\n          \"stderr.original\": {\n            \"bytes\": 0,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/sender-execute/stderr.original\",\n            \"sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n          },\n          \"stdout.original\": {\n            \"bytes\": 703,\n            \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01/sender-execute/stdout.original\",\n            \"sha256\": \"deb596a12c456fb2e8ad7ebe844d01bf4b2e07d0b72d8a29eafaca8b0c3aec07\"\n          }\n        },\n        \"sender_result\": {\n          \"bytes\": 703,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-a1055-v3stack01.send-result.json\",\n          \"sha256\": \"deb596a12c456fb2e8ad7ebe844d01bf4b2e07d0b72d8a29eafaca8b0c3aec07\"\n        },\n        \"service_inputs\": {\n          \"bytes\": 10654,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json\",\n          \"sha256\": \"e0522c5d743fd9bdc30343d93200a894d58016f935f564284bb6b0d924ba898a\"\n        },\n        \"shared_manifest\": {\n          \"bytes\": 3519,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/SHARED-MATERIALS.json\",\n          \"sha256\": \"2ea9a478b366d6a69fdb8942699b6241d72330cfa789baa4b3132fdaca169e68\"\n        },\n        \"source_package\": {\n          \"bytes\": 33063,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/root-chain/SOURCE-MANIFEST.json\",\n          \"sha256\": \"720b30e2828d8b3a2170b558fe525018f4851724187416e9ac67284d38752664\"\n        },\n        \"source_seal\": {\n          \"bytes\": 2341,\n          \"path\": \"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/SOURCE-SEAL.json\",\n          \"sha256\": \"78c39b4cc4afd438bb149013fff20bbecc0a78241c3ed979e101320736eadcc0\"\n        }\n      }\n    }\n  },\n  \"schema\": \"hepta.final-release.fixed-historical-source-profiles.v1\",\n  \"source_only\": true,\n  \"state\": \"READ_EXISTING_ORIGINALS_ONLY_NOT_QUALIFICATION\"\n}\n")['profiles']

# These two generations are immutable failed history. Their exact raw profiles
# are source selected, separate from the final success prefix.
HISTORICAL_F821_POLICY_SHA = 'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'

def current_diagnostic_proof_spec(name):
    need(name in ('failed820','v3runtime'), 'only exact failed820 and actual v3 history are supported')
    return strict(encode(NEW_DIAGNOSTIC_HISTORY_PROFILES[name]['spec']))

def current_diagnostic_reader_profile(name, late):
    profile = NEW_DIAGNOSTIC_HISTORY_PROFILES[name]
    if name == 'failed820':
        record = late.reviewed_stack_diagnostic_parent_ancestor()
        predicate = late.is_stack_diagnostic_parent_ancestor
        prior = late.reviewed_codec_diagnostic_parent_ancestor()['boundary']
        provenance = late.stack_diagnostic_parent_reader_provenance()
    else:
        record = late.reviewed_v3_runtime_diagnostic_ancestor()
        predicate = late.is_v3_runtime_diagnostic_ancestor
        prior = late.reviewed_stack_diagnostic_parent_ancestor()['boundary']
        provenance = late.v3_runtime_diagnostic_reader_provenance()
    need(record == profile['record'], 'fixed original history differs from exact current typed reader')
    return profile,record,predicate,prior,provenance

def validate_current_diagnostic_history(bundle, proof, state, boundary, late, name):
    profile,record,predicate,prior,provenance = current_diagnostic_reader_profile(name,late)
    spec = current_diagnostic_proof_spec(name)
    need(type(proof) is dict and set(proof) == set(spec)|{'schema','boundary'}
         and proof['schema'] == 'hepta.r10.fixed-current-diagnostic-history.v1'
         and proof['boundary'] == record['boundary']
         and all(proof[k] == v for k,v in spec.items()),
         'exact fixed current diagnostic host originals required')
    # Every retained raw is read, including the original failure and original
    # unknown wait. Embedded descriptor-shaped text is never fetched recursively.
    for row in descriptors(spec):
        original_from(bundle,row)
    raw={k:original_from(bundle,v) for k,v in spec.items()
         if type(v) is dict and set(v)=={'path','bytes','sha256'}}
    package=strict(raw['package_manifest']);root_package=strict(raw['source_package'])
    need(package['schema']=='hepta.native-guard.adapter-package.v1'
         and package['state']==profile['package_state']
         and len(package['files'])==len(spec['package_files'])==36,
         'historical exact36 package differs')
    sources={}
    for entries,manifest,manifest_row,count in (
            (spec['package_files'],package,spec['package_manifest'],36),
            (spec['root_sources'],root_package,spec['source_package'],3)):
        pins={row['path']:row for row in manifest['files']}
        need(len(pins)==len(entries)==count,'historical complete member set differs')
        seen=set()
        for item in entries:
            need(set(item)=={'name','copy'} and item['name'] in pins and item['name'] not in seen,
                 'historical source member omitted or repeated')
            seen.add(item['name']);row=pins[item['name']]
            need(item['copy']==dict(path=str(Path(manifest_row['path']).parent/item['name']),
                 **{k:row[k] for k in ('bytes','sha256')}), 'historical source member path/pin differs')
            body=original_from(bundle,item['copy'])
            if count==36:sources[item['name']]=body
        need(seen==set(pins),'historical member census incomplete')
    need(sources['source/component_common.py']==state['package_sources']['source/component_common.py'],
         'historical/current common reader bytes differ')
    production={v['name']:original_from(bundle,v['copy']) for v in spec['production_files']}
    pins=strict(sources['reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(production)==len(spec['production_files'])==len(pins)==15 and set(production)==set(pins)
         and all(sha(v)==pins[k] for k,v in production.items()),'historical full15 production sources differ')
    combination=strict(raw['combination'])
    need(late.C.encoded(combination)==raw['combination']
         and sha(raw['combination'])==boundary['combination_sha256']
         and sha(raw['package_manifest'])==boundary['package_sha256']
         and combination['live_policy_sha256']==HISTORICAL_F821_POLICY_SHA
         and combination['production_files']==[dict(path='production/'+n,**descriptor(b)) for n,b in sorted(production.items())]
         and combination['configuration']==descriptor(raw['configuration'])
         and combination['service_inputs']==descriptor(raw['service_inputs'])
         and strict(raw['configuration'])['service_manifest_sha256']==sha(raw['service_inputs']),
         'old f821 combination and actual source bytes must remain separate from final policy')
    material={'provider/source/'+n:b for n,b in production.items()}
    material.update({'local-config-r10-r1.json':raw['configuration'],
                     'PHONE-SERVICE-INPUTS-v150-r10-r1.json':raw['service_inputs']})
    shared=strict(raw['shared_manifest'])
    need(shared['schema']=='hepta.r10.shared-production-materials.v1'
         and len(shared['files'])==len({row['path'] for row in shared['files']})==17
         and {row['path']:row for row in shared['files']}=={n:dict(path=n,**descriptor(b)) for n,b in material.items()},
         'historical shared17 original differs')
    seal=dict(schema='hepta.native-guard.component-source-seal.v150.r10.1',
        state='REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE',intended_module_release=RELEASE,
        configuration=descriptor(raw['configuration']),phone_service_inputs_sha256=sha(raw['service_inputs']),
        production_files=[dict(path='source/'+n,**descriptor(b)) for n,b in sorted(production.items())])
    need(late.C.encoded(seal)==raw['source_seal'] and combination['source_seal']==descriptor(raw['source_seal']),
         'historical source seal must match its actual17 bytes')
    checked,inventory,closure=late.closed_boundary_originals(
        raw['boundary_copy'],raw['inventory_copy'],raw['closure_copy'],original_descriptor=record['boundary'],
        combination_sha256=CURRENT_COMBINATION_SHA,package_sha256=PACKAGE_SHA)
    need(checked==boundary and predicate(boundary) and boundary['prior_boundary']==prior
         and boundary['nonce']==profile['nonce'] and boundary['component_qualified'] is False
         and boundary['native_status']=='provider_failed' and boundary['actual_native_calls']==1
         and closure['unknown_effects']==0 and closure['component_qualified'] is False
         and strict(raw['published_boundary_descriptor_file'])==record['boundary'],
         'fixed failed native generation cannot gain final component credit')
    result=strict(raw['root_result']);previous=strict(raw['closed_previous']);plan=strict(raw['original_root_plan'])
    need(result['state']=='ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
         and result['scope']==boundary['scope'] and result['late_boundary']==record['boundary']
         and result['previous']==spec['closed_previous'] and result['native_status']=='provider_failed'
         and all(result[k] is False for k in ('automatic_retry','component_qualified','business_qualified','four_role_qualification'))
         and type(result['model_requests']) is int and result['model_requests']==0,
         'historical original Root result was upgraded')
    need(previous['identity']==boundary['scope'] and previous['late_boundary']==record['boundary']
         and previous['closed_component']==spec['closure_copy']
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True
         and previous['component_qualified'] is False and previous['terminal']=={'status':'provider_failed'}
         and previous['complete_business_success'] is False and previous['automatic_replay'] is False,
         'historical closed previous differs')
    need(plan['nonce']==profile['nonce'] and plan['case_id']=='NEG-01' and plan['boot_id']==BOOT
         and plan['package']==spec['package_manifest'] and plan['source_package']==spec['source_package']
         and plan['previous']==profile['input_previous'] and plan['previous']!=spec['closed_previous']
         and plan['live_policy_sha256']==HISTORICAL_F821_POLICY_SHA,
         'historical input predecessor or actual executed source differs')
    steps=[v for v in result['steps'] if v.get('phase')=='phone-late-publish']
    need(len(steps)==1 and steps[0]['state']=='ORIGINAL_HOST_CHILD_JOINED'
         and type(steps[0]['returncode']) is int and steps[0]['returncode']==0
         and steps[0]['automatic_retry'] is False and steps[0]['stdout']==spec['publication_operation']
         and steps[0]['stderr']==spec['publication_stderr'],'historical publication original wait differs')
    operation=strict(raw['publication_operation'])
    need(raw['publication_stderr']==b'' and type(operation['actor_rc']) is int and operation['actor_rc']==0
         and type(operation['wrapper']['phone']['rc']) is int and operation['wrapper']['phone']['rc']==0,
         'historical publication actor or phone terminal differs')
    published=strict(operation['wrapper']['phone']['stdout'].encode())
    need(published==dict(schema='hepta.native-guard.boundary-publish-result.v1',
         state='CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED',boundary=record['boundary'],
         old_retirement_current_equality_claimed=False,original_retirement_rewritten=False,
         phone_tool_calls=0,model_requests=0,signals=0,automatic_retry=False),
         'historical publication body differs')
    phase={k:original_from(bundle,v) for k,v in spec['sender_phase_originals'].items()}
    intent=strict(phase['INTENT.json']);child=strict(phase['CHILD.json']);capture=strict(phase['OUTPUT-CAPTURE.json'])
    need(child['pid']==capture['pid'] and child['source_intent_sha256']==capture['source_intent_sha256']==sha(phase['INTENT.json'])
         and intent['maximum_starts']==1 and intent['automatic_retry'] is False
         and capture['captured']=={k:descriptor(phase[k+'.original']) for k in ('stdout','stderr')},
         'original sender source or raw output binding differs')
    failure=strict(raw['original_root_failure'])
    need(failure['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and all(failure[k] is False for k in ('automatic_retry','business_qualified','component_qualified','new_identity_retry','send_again'))
         and failure['signals_sent_by_coordinator']==failure['policy_changes']==failure['model_requests']==0,
         'original failure must remain an original failed record')
    if name=='failed820':
        recovery=strict(raw['recovery_result']);admission=strict(raw['recovery_admission'])
        need(recovery['schema']=='hepta.native-current.same-scope-recovery-result.v1'
             and recovery['state']=='ORIGINAL_NORMAL_TAIL_CLOSED_AND_PUBLISHED'
             and recovery['source']==spec['recovery_source'] and recovery['root_result']==spec['root_result']
             and recovery['boundary']==spec['boundary_copy'] and recovery['closure']==spec['closure_copy']
             and recovery['previous']==spec['closed_previous']
             and all(recovery[k]==spec[k] for k in ('recovery_intent','recovery_admission','original_root_failure','original_sender_result'))
             and recovery['original_lease_expiry_unchanged'] is True and recovery['original_sender_wait_fabricated'] is False
             and recovery['unknown_effects']==0 and recovery['actual_native_calls']==1
             and recovery['native_status']=='provider_failed' and recovery['model_requests']==0
             and all(recovery[k] is False for k in ('automatic_retry','new_fixture','new_launch','new_nonce','new_send','business_qualified','component_qualified')),
             'failed820 recovery was replayed, reassigned or upgraded')
        need(admission['original_parent_wait_claimed'] is False and capture['child_wait_returned'] is False
             and capture['child_returncode'] is None and capture['prefix_only_or_unknown'] is True
             and capture['stdout_eof'] is False and capture['stderr_eof'] is False
             and 'JOINED.json' not in phase,
             'failed820 original sender wait UNKNOWN must never be backfilled')
    else:
        continuation=strict(raw['continuation_result']);admission=strict(raw['continuation_admission'])
        need(continuation['schema']=='hepta.native-guard.capture02-closure-continuation-result.v1'
             and continuation['state']=='ORIGINAL_SCOPE_CLOSED_AFTER_DECLARED_CAPTURE02_RECOVERY'
             and continuation['source']==spec['recovery_source'] and continuation['inputs']==spec['continuation_inputs']
             and continuation['admission']==spec['continuation_admission'] and continuation['intent']==spec['continuation_intent']
             and continuation['capture_proof']==spec['capture_proof']
             and continuation['original_root_result']==spec['root_result']
             and continuation['original_root_failure']==spec['original_root_failure']
             and continuation['scope']==boundary['scope'] and continuation['diagnostic_only'] is True
             and continuation['original_failure_preserved'] is True and continuation['actual_sender_wait_returned'] is True
             and continuation['historic_other_sender_wait_rewritten'] is False
             and continuation['original_supervisor_parent_wait_claimed'] is False
             and all(continuation[k] is False for k in ('automatic_retry','business_qualified','component_qualified'))
             and all(type(continuation[k]) is int and continuation[k]==0 for k in
                     ('model_requests','new_fixture_operations','new_native_submissions','new_role_launches')),
             'v3 continuation must preserve original failure, sender identity and no replay')
        joined=strict(raw['sender_joined'])
        need(phase['JOINED.json']==raw['sender_joined'] and joined==dict(automatic_retry=False,pid=capture['pid'],returncode=0,wait_returned=True)
             and capture['child_wait_returned'] is True and type(capture['child_returncode']) is int and capture['child_returncode']==0
             and capture['stdout_eof'] is True and capture['stderr_eof'] is True and capture['worker_joined'] is True
             and capture['prefix_only_or_unknown'] is False and capture['persist_errors']==capture['pipe_close_errors']==[]
             and phase['stdout.original']==raw['sender_result'],'actual v3 original sender wait or dual EOF differs')
        old_operation=strict(raw['original_snapshot_operation'])
        need(old_operation['actor_rc']==0 and old_operation['wrapper']['phone']['rc']==1
             and old_operation['wrapper_sha256']=='785ccb8b1cc05d033a5973f1aed6d2359faf39cb61884d8b3f60fc9dcfa1dedf'
             and 'complete original inventory schema differs' in old_operation['wrapper']['phone']['stderr'],
             'original failed snapshot may not be replaced by recovery success')
        reader=types.ModuleType('exact_historical_capture02_reader');reader.__file__=spec['recovery_source']['path']
        exec(compile(raw['recovery_source'],reader.__file__,'exec'),reader.__dict__)
        data=strict(raw['continuation_inputs'])
        recovery_plan,recovered,_chunk,_operation=reader.validate_recovery(data)
        need(reader.validate_archive(raw['archive_original'],recovery_plan,recovered)==strict(raw['capture_proof'])
             and data['scope']==boundary['scope'] and data['sender_joined']==spec['sender_joined']
             and data['sender_result']==spec['sender_result'] and data['lease']==spec['lease']
             and admission['actual_sender_original_wait_returned'] is True
             and admission['actual_sender_pid']==capture['pid']
             and admission['actual_recovery_original_job_exit_code']==admission['actual_recovery_phone_exit_code']==0,
             'complete original capture02 archive, actual recovery job or source provenance differs')
    need(provenance['implementation_source_sha256']==sha(state['package_sources']['source/late_boundary.py'])
         and provenance['historical_publisher_source_sha256']==sha(sources['source/late_boundary.py'])
         and provenance['historical_package_sha256']==sha(raw['package_manifest'])
         and provenance['historical_combination_sha256']==sha(raw['combination'])
         and provenance['historical_publisher_executed_unchanged'] is False
         and provenance['historical_mapper_recomputed_with_current_source'] is False,
         'new reader implementation must not masquerade as historical execution')
    return proof

def validate_final_component_prefix(chain, late, retained):
    need(len(chain)==11,'production release requires exact two current cases and nine fixed failed ancestors')
    prefix=chain[:2]
    need([row[0]['case_id'] for row in prefix]==['NEG-02','NEG-01'],
         'closed current cases must be supplied latest-first after actual NEG01 then NEG02')
    for prefix_index,(boundary,inventory,closure) in enumerate(prefix):
        need(boundary['schema']==late.SCHEMA and boundary['package_sha256']==PACKAGE_SHA
             and boundary['combination_sha256']==CURRENT_COMBINATION_SHA
             and boundary['component_qualified'] is True and boundary['native_status']=='completed'
             and closure['component_qualified'] is True and closure['native_status']=='completed'
             and closure['unknown_effects']==0,
             'both exact current NEG component cases must actually qualify')
        late.current_retained_stage_binding(boundary);late.current_retained_stage_binding(closure)
        late.preserve_retained_unstarted_stage(inventory,retained=retained)
        late.validate_retained_stage_parent_profiles(retained,closure['retained_stage_parent_profiles'],inventory)
        need(len(inventory['roots'])==(47,44)[prefix_index]
             and boundary['retained_stage_parent_profiles']==closure['retained_stage_parent_profiles'],
             'current final cases require complete47 then44 inventories and fresh bound parent aliases')
    need(all(row[0]['component_qualified'] is False and row[0]['native_status']=='provider_failed' for row in chain[2:]),
         'fixed historical failures do not provide new component qualification')


def validate_retained_stage_input(value, manifest, late, *, read_pinned):
    """Pure current-family proof; only the fixed original old39 reader is injected."""
    retained=late.retained_unstarted_stage(read_pinned=read_pinned)
    need(value.get('retained_unstarted_stage')==manifest.get('retained_unstarted_stage')==retained['binding']
         and retained['binding']['native_case_count']==0
         and retained['binding']['component_role_identities']=={}
         and retained['binding']['fixture_root_count']==0
         and retained['original_sender_wait']=='UNKNOWN_UNCHANGED',
         'final component input omitted or reclassified the separately retained unstarted stage')
    return retained


def validate_component(bundle, value):
    need(isinstance(PACKAGE_SHA,str) and HASH.fullmatch(PACKAGE_SHA)
         and type(PACKAGE_FILE_COUNT) is int and PACKAGE_FILE_COUNT == 37
         and isinstance(CURRENT_COMBINATION_SHA,str) and HASH.fullmatch(CURRENT_COMBINATION_SHA),
         'current policy component runtime has not been frozen and reviewed')
    need(isinstance(value, dict) and set(value) == COMPONENT_FIELDS
         and value['schema'] == 'hepta.r10.component-boundary-inputs.v10'
         and value['release_id'] == RELEASE and value['boot_id'] == BOOT,
         'explicit component input schema/identity differs')
    manifest_raw = original_from(bundle, value['component_package_manifest'])
    need(sha(manifest_raw) == PACKAGE_SHA, 'component package is not the reviewed frozen runtime')
    manifest = strict(manifest_raw)
    need(manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
         and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED',
         'component package schema differs')
    files = value['component_package_files']
    need(isinstance(files, list) and len(files) == len(manifest['files']) == PACKAGE_FILE_COUNT,
         'complete frozen component package required')
    source = {}
    pins = {row['path']: row for row in manifest['files']}
    for item in files:
        need(set(item) == {'name', 'copy'} and item['name'] in pins
             and item['name'] not in source, 'component package file set differs')
        raw = original_from(bundle, item['copy'])
        need(descriptor(raw) == {k: pins[item['name']][k] for k in ('bytes', 'sha256')},
             'component package original differs')
        source[item['name']] = raw
    need(set(source) == set(pins), 'component package omitted a file')
    combination_raw = original_from(bundle, value['component_combination'])
    need(sha(combination_raw)==CURRENT_COMBINATION_SHA,'current reviewed policy combination differs')
    combination = strict(combination_raw)
    need(set(combination) == {'schema', 'state', 'source_seal', 'configuration',
            'service_inputs', 'production_files', 'artifacts', 'live_policy_sha256'}
         and combination.get('schema') == 'hepta.native-guard.component-combination.v150.r10.1'
         and combination.get('state') == 'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY',
         'component combination is not an explicit component source set')
    reviewed_production = strict(source['reference/REVIEWED-PRODUCTION-PINS.json'])
    production = combination['production_files']
    need(len(reviewed_production) == len(production) == 15
         and len({row['path'] for row in production}) == 15
         and {row['path'] for row in production} == {'production/' + name for name in reviewed_production},
         'component combination omitted a reviewed production source')
    for row in production:
        name = Path(row['path']).name
        need(set(row) == {'path', 'bytes', 'sha256'}
             and type(row['bytes']) is int and 0 < row['bytes'] <= 262144
             and row['sha256'] == reviewed_production[name],
             'component combination production pin differs')
    need(set(combination['artifacts']) == {'client', 'sidecar', 'worker', 'screen_helper',
            'focus_helper', 'unicode_helper', 'busybox', 'python'}
         and isinstance(combination['live_policy_sha256'], str)
         and HASH.fullmatch(combination['live_policy_sha256']),
         'component combination artifact or explicit policy identity differs')
    copies = {}
    for item in value['originals']:
        need(set(item) == {'phone', 'copy'}, 'component original transport entry differs')
        phone = item['phone']; raw = original_from(bundle, item['copy'])
        need(phone['path'] not in copies and descriptor(raw) == {k: phone[k] for k in ('bytes', 'sha256')},
             'phone original duplicate or host copy differs')
        copies[phone['path']] = (phone, raw)
    state = {'package_sources': source, 'component_input': value,
             'component_combination': combination, 'component_originals': copies}
    used = set(); chain = []; seen_nonce = set(); seen_scope = set()
    with component_modules(state) as modules:
        late = modules['late_boundary']; common = modules['component_common']
        late.validate_current_package_manifest(manifest)
        sidebranches = late.non_native_sidebranches()
        sidebranch = sidebranches[0]
        need(encode(value['non_native_sidebranch']) == encode(sidebranch['binding'])
             and encode(value['non_native_sidebranches']) == encode([s['binding'] for s in sidebranches]),
             'component input omitted or changed the exact old05 and diag02 non-native bindings')
        def body(row):
            late.exact_descriptor(row)
            need(row['path'] in copies and copies[row['path']][0] == row,
                 'exact phone file identity was omitted or changed')
            used.add(row['path'])
            return copies[row['path']][1]
        late.__retained_stage_read_pinned__=body
        retained=validate_retained_stage_input(value,manifest,late,read_pinned=body)
        current = value['latest_boundary']
        while current is not None:
            need(len(chain) < late.MAX_CHAIN, 'closed boundary chain is too long')
            boundary_raw = body(current)
            boundary = late.boundary_from_original(boundary_raw,
                original_descriptor=current, combination_sha256=sha(combination_raw),
                package_sha256=PACKAGE_SHA)
            need(current['path'] == str(late.ROOT / (boundary['nonce'] + '.json')),
                 'boundary filename differs from its nonce')
            key = tuple(boundary['scope'][field] for field in common.SCOPE)
            need(boundary['nonce'] not in seen_nonce and key not in seen_scope,
                 'duplicate component nonce or scope')
            seen_nonce.add(boundary['nonce']); seen_scope.add(key)
            need(boundary['boot_id'] == BOOT and boundary['retirement'] == value['retirement'],
                 'component boundary changed the retirement or boot')
            inventory_raw = body(boundary['inventory'])
            closure_raw = body(boundary['closure'])
            checked, inventory, closure = late.closed_boundary_originals(
                boundary_raw, inventory_raw, closure_raw, original_descriptor=current,
                combination_sha256=sha(combination_raw), package_sha256=PACKAGE_SHA)
            need(checked == boundary, 'closed original boundary changed during validation')
            if (boundary['schema'] == late.SCHEMA
                    and not late.is_pre_policy_ancestor(boundary)
                    and not late.is_environment_parent_ancestor(boundary)
                    and not late.is_property_parent_ancestor(boundary)
                    and not late.is_diagnostic_parent_ancestor(boundary)
                    and not late.is_codec_diagnostic_parent_ancestor(boundary)
                    and not late.is_stack_diagnostic_parent_ancestor(boundary)
                    and not late.is_v3_runtime_diagnostic_ancestor(boundary)):
                need(closure['closure_source_sha256'] == sha(source['source/close_component.py']),
                     'current component closure source differs')
                late.current_sidebranch_bindings(boundary, branches=sidebranches)
                late.current_sidebranch_bindings(closure, branches=sidebranches)
                late.preserve_non_native_sidebranches(inventory, sidebranches)
            # The external branch is checked against the immutable published
            # raw descriptor and its actual external verifier source by the
            # same reviewed runtime reader. It never gains current-case credit.
            chain.append((boundary, inventory, closure))
            current = boundary['prior_boundary']
        need(chain, 'explicit actual closed component boundary is required')
        late.require_failed_ancestor_tail([row[0] for row in chain])
        validate_final_component_prefix(chain, late,retained)
        v3_runtime_diagnostic=validate_current_diagnostic_history(
            bundle,value['v3_runtime_diagnostic_ancestor'],state,chain[-9][0],late,'v3runtime')
        stack_diagnostic_parent=validate_current_diagnostic_history(
            bundle,value['stack_diagnostic_parent_ancestor'],state,chain[-8][0],late,'failed820')
        codec_diagnostic_parent=validate_diagnostic_parent_ancestor(
            bundle,value['codec_diagnostic_parent_ancestor'],state,chain[-7][0],late,name='failed6077')
        diagnostic_parent=validate_diagnostic_parent_ancestor(
            bundle,value['diagnostic_parent_ancestor'],state,chain[-6][0],late)
        property_parents=validate_property_parent_ancestors(
            bundle,value['property_parent_ancestors'],state,
            [row[0] for row in chain[-5:-3]],late)
        environment_parent=validate_environment_parent_ancestor(
            bundle,value['environment_parent_ancestor'],state,chain[-3][0],late)
        pre_policy=validate_pre_policy_ancestor(bundle,value['pre_policy_ancestor'],state,chain[-2][0],late)
        for later, earlier in zip(chain, chain[1:]):
            need(set(earlier[0]['roots']) <= set(later[0]['roots']), 'later boundary dropped old roots')
        retirement = value['retirement']
        need(set(retirement) == {'proof', 'preflight', 'probe', 'bound_inputs', 'disabled_flag'},
             'original retirement set differs')
        retired_raw = {key: body(row) for key, row in retirement.items()}
        retired = strict(retired_raw['proof']); before = strict(retired_raw['preflight'])
        bound = strict(retired_raw['bound_inputs'])
        need(retired['schema'] == 'hepta.r9-r2-retirement-observation.v1'
             and retired['state'] == 'ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED'
             and retired['boot_id'] == BOOT and retired['global_pending_clear'] is True
             and retired['server_lock_now_unheld'] is True and retired['old_claims_deleted'] is False
             and retired['old_task_terminal_rewritten'] is False and retired['automatic_replay'] is False,
             'actual original retirement is not closed')
        need(before['schema'] == 'hepta.r9-r2-retirement-preflight.v1'
             and before['state'] == 'READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
             and before['groups'] == retired['original_role_identities']
             and before['preserved_state'] == retired['preserved_state']
             and bound['complete_current_accepted_case_union_verified'] is True
             and retired_raw['disabled_flag'] == b'', 'original retirement lineage differs')
        need(used == set(copies), 'unused or missing original in component boundary input')
        publish = strict(original_from(bundle, value['publish_result']))
        need(publish['schema'] == 'hepta.native-guard.boundary-publish-result.v1'
             and publish['state'] == 'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED'
             and publish['boundary'] == value['latest_boundary']
             and publish['original_retirement_rewritten'] is False,
             'explicit original boundary publication differs')
        roles = list(before['groups'].values())
        component_roles = []
        for boundary, _inventory, _closure in chain:
            component_roles.extend(boundary['component_role_identities'].values())
        for branch in sidebranches:
            component_roles.extend(branch['binding']['component_role_identities'].values())
        late.require_component_role_budget(component_roles)
        roles.extend(component_roles)
        need(len(roles) <= 64 and len({tuple(row) for row in roles}) == len(roles),
             'closed role generation identities repeat or exceed bound')
    state.update(chain=chain, current_inventory=chain[0][1], retired=retired,
        retirement_sha256=retirement['proof']['sha256'], roles=roles,
        component_roles=component_roles, component_boundary_sha256=value['latest_boundary']['sha256'],
        retained_unstarted_stage=retained['binding'],
        pre_policy_ancestor=pre_policy, non_native_sidebranch=sidebranch['binding'],
        non_native_sidebranches=[s['binding'] for s in sidebranches],
        environment_parent_ancestor=environment_parent, property_parent_ancestors=property_parents,
        diagnostic_parent_ancestor=diagnostic_parent, codec_diagnostic_parent_ancestor=codec_diagnostic_parent,
        stack_diagnostic_parent_ancestor=stack_diagnostic_parent, v3_runtime_diagnostic_ancestor=v3_runtime_diagnostic)
    return state


def validate_shared_materials(state, sources, config_raw, service_raw):
    """Bind the actual closed component to the final 17 computed byte strings."""
    combination = state['component_combination']
    need(isinstance(sources, dict) and len(sources) == 15
         and all(isinstance(raw, bytes) for raw in sources.values()),
         'exact final production byte set required')
    production = [dict(path='production/' + name, **descriptor(raw))
                  for name, raw in sorted(sources.items())]
    config = strict(config_raw)
    need(combination['production_files'] == production
         and combination['configuration'] == descriptor(config_raw)
         and combination['service_inputs'] == descriptor(service_raw)
         and config['service_manifest_sha256'] == sha(service_raw),
         'closed component and final source/config/service bytes differ')
    source_seal = dict(schema='hepta.native-guard.component-source-seal.v150.r10.1',
        state='REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE', intended_module_release=RELEASE,
        configuration=descriptor(config_raw), phone_service_inputs_sha256=sha(service_raw),
        production_files=[dict(path='source/' + name, **descriptor(raw))
                          for name, raw in sorted(sources.items())])
    # The frozen component producer serializes this original with its compact
    # encoder. Its byte identity is not interchangeable with pretty JSON.
    with component_modules(state) as modules:
        source_seal_raw = modules['component_common'].encoded(source_seal)
    need(combination['source_seal'] == descriptor(source_seal_raw)
         and combination['live_policy_sha256'] == state['runtime_policy']['sha256'],
         'closed component seal or explicitly adopted runtime policy differs')
    return {'production_source_count': 15, 'configuration': descriptor(config_raw),
            'service_inputs': descriptor(service_raw),
            'component_source_seal': descriptor(source_seal_raw)}


def external_artifact_bindings(state, sources, service_raw):
    """Bind eight component dependencies to the final service and source bytes.

    This is a pure comparison. Metadata comes from the explicitly closed
    component combination; runtime consumers independently re-read it. The
    Python and BusyBox pins are the already observed stock dependencies.
    """
    service = strict(service_raw)
    need(service['schema'] == 'hepta.phone-local.service-inputs.v150.r10.1',
         'final r10 service inputs required for external dependencies')
    artifacts = state['component_combination']['artifacts']
    names = {'client', 'sidecar', 'worker', 'screen_helper', 'focus_helper',
             'unicode_helper', 'busybox', 'python'}
    need(set(artifacts) == names, 'exact eight component dependencies required')
    expected = {}
    with component_modules(state) as modules:
        common = modules['component_common']
        client = service['executor']['client']
        need(client['gnu_path'] == str(common.CLIENT)
             and client['host_state_path'] == ANDROID_BASE + '/tool_client_r6.py'
             and client['sha256'] == common.CLIENT_SHA, 'final native client binding differs')
        expected['client'] = (str(common.CLIENT), client['bytes'], common.CLIENT_SHA,
                              client['host_state_path'])
        for name, field, path, pin in (
                ('sidecar', 'binary', common.SIDECAR, common.SIDECAR_SHA),
                ('worker', 'worker', common.WORKER, common.WORKER_SHA)):
            row = service['executor'][field]
            need(row['path'] == path and row['sha256'] == pin,
                 'final native executor binding differs: ' + name)
            expected[name] = (path, row['bytes'], pin, path)
    wanted = {'SCREEN_JAR', 'SCREEN_JAR_SHA256', 'FOCUS_INPUT_JAR',
              'FOCUS_INPUT_JAR_SHA256', 'INPUT_JAR', 'INPUT_JAR_SHA256'}
    constants = {}
    for node in ast.parse(sources['phone_observation_tools.py']).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted:
            name = node.targets[0].id
            need(name not in constants, 'duplicate typed helper constant')
            constants[name] = ast.literal_eval(node.value)
    need(set(constants) == wanted, 'complete typed helper source constants required')
    helper_rows = {row['path']: row for row in service['helpers']}
    need(len(helper_rows) == len(service['helpers']) == 3, 'final helper inventory differs')
    for name, stem in (('screen_helper', 'SCREEN_JAR'), ('focus_helper', 'FOCUS_INPUT_JAR'),
                       ('unicode_helper', 'INPUT_JAR')):
        path, pin = constants[stem], constants[stem + '_SHA256']
        need(path in helper_rows and helper_rows[path]['sha256'] == pin,
             'final service and typed helper source differ: ' + name)
        expected[name] = (path, helper_rows[path]['bytes'], pin, path)
    expected['python'] = ('/usr/bin/python3', 7843560,
        'f7ad87c414fc6a5126571b2ecca19351119ac10e54d0539de6a0a9300d81087f',
        '/data/trillionnium/owner-open/root/usr/bin/python3')
    expected['busybox'] = ('/data/adb/magisk/busybox', 1710600,
        '4d60ab3f5a59ebb2ca863f2f514e6924401b581e9b64f602665c008177626651',
        '/data/adb/magisk/busybox')
    result = []
    for name in sorted(names):
        row = artifacts[name]; path, size, pin, target = expected[name]
        need(set(row) == {'path', 'bytes', 'sha256', 'uid', 'gid', 'mode', 'selinux'}
             and type(row['bytes']) is int and row['bytes'] == size > 0
             and row['path'] == path and row['sha256'] == pin,
             'closed component and final external artifact differ: ' + name)
        need(type(row['uid']) is int and type(row['gid']) is int
             and 0 <= row['uid'] < 2**32 and 0 <= row['gid'] < 2**32
             and type(row['mode']) is int and 0 <= row['mode'] <= 0o777
             and isinstance(row['selinux'], str)
             and re.fullmatch(r'u:object_r:[a-zA-Z0-9_]+:s0', row['selinux']),
             'explicit external artifact metadata required: ' + name)
        result.append(dict(name=name, target=target, **row))
    need(len({row['target'] for row in result}) == 8, 'external target mapping is not unique')
    return result


def validate_external_inventory(bindings, inventory, *, path_key):
    need(path_key in ('path', 'target') and isinstance(inventory, list),
         'explicit installed dependency inventory required')
    rows = {row[path_key]: row for row in inventory}
    need(len(rows) == len(inventory), 'duplicate dependency inventory path')
    for binding in bindings:
        row = rows.get(binding['target'])
        need(row is not None and all(row[k] == binding[k] for k in ('bytes', 'sha256')),
             'component dependency omitted or changed in final payload: ' + binding['name'])
    return True


def current_external_artifacts(state):
    """Read-only exact eight bytes/metadata and explicitly adopted policy."""
    with component_modules(state) as modules:
        return modules['component_common'].verify_external(state['component_combination'])


def image_descriptor(value, expected=None):
    file_descriptor(value)
    need(0 < value['bytes'] <= 8 * 1024 * 1024
         and (expected is None or value['sha256'] == expected), 'policy image descriptor differs')
    return {k: value[k] for k in ('bytes', 'sha256')}


def complete_comparison(report, parent, candidate, *, kind):
    need(report.get('schema') == 'hepta.fd-use-r10.complete-policy-comparison.v1'
         and report.get('state') == 'EXACT_ONE_APPROVED_PERMISSION_DELTA_VERIFIED'
         and report.get('comparison_kind') == kind
         and image_descriptor(report['parent']) == image_descriptor(parent)
         and image_descriptor(report['candidate']) == image_descriptor(candidate)
         and report.get('approved_rule_atoms') == [ATOM], 'complete policy comparison identity differs')
    delta = report['semantic_delta']; coverage = report['coverage']
    need(delta['added_atoms'] == [ATOM] and delta['removed_atoms'] == []
         and delta['all_raw_TE_counter_delta_bound'] is True and delta['unconditional_only'] is True,
         'policy comparison is not exactly the approved atom')
    for name in ('all_TE_rules_enumerated', 'multiplicity_preserved',
                 'conditional_expression_and_branch_preserved', 'explicit_xperm_type_and_all_integers'):
        need(coverage.get(name) is True, 'incomplete semantic comparison: ' + name)
    need(coverage['unsupported_rule_kinds'] == [] and coverage['errors'] == []
         and coverage['actual_conditional_list_empty'] is True
         and type(coverage['actual_conditional_avtab_count']) is int
         and coverage['actual_conditional_avtab_count'] == 0,
         'policy comparison has unsupported or incomplete coverage')
    expected_tables = {'categories', 'commons', 'classes', 'constraints', 'defaults', 'bounds',
        'ibendportcons', 'ibpkeycons', 'levels', 'mlsrules', 'netifcons', 'nodecons',
        'polcaps', 'portcons', 'rbacrules', 'sensitivities'}
    extra_tables = {'types', 'type_attributes', 'booleans', 'classes_with_common',
        'common_permissions', 'conditionals', 'roles', 'users', 'initialsids',
        'fs_uses', 'unlabeled_filesystems', 'genfs'}
    need(set(coverage['non_TE_tables']) == expected_tables
         and len(coverage['non_TE_tables']) == len(expected_tables)
         and set(coverage['additional_complete_tables']) == extra_tables
         and len(coverage['additional_complete_tables']) == len(extra_tables),
         'complete policy tables differ')
    image = report['full_image_comparison']
    need(image['all_enumerated_roundtrip_semantics_preserved'] is True
         and image['all_orbit_members_structurally_and_semantically_verified'] is True,
         'original-to-normalized semantic preservation missing')
    for name in ('complete_input_consumption', 'baseline_conditional_list_empty',
        'candidate_conditional_list_empty', 'all_cycles_close_at_first_image',
        'all_cycle_representatives_stable',
        'only_approved_delta_full_image_equal', 'negative_missing_atom_rejected',
        'negative_unapproved_binder_change_rejected', 'negative_unknown_handling_rejected'):
        need(image['result'].get(name) is True, 'complete policy image gate missing: ' + name)
    result = image['result']
    need(result['schema'] == 'hepta.official-libsepol-one-atom-full-image-comparison.v2'
         and type(result['cycle_bound']) is int and result['cycle_bound'] == 4
         and result['normalization'] == 'lexicographic-minimum-complete-official-serialization-cycle',
         'complete official serializer normalization differs')
    names = ['parent', 'candidate', 'expected', 'negative-handle-unknown', 'negative-binder-change']
    orbits = result['serialization_orbits']
    need(isinstance(orbits, list) and [row.get('name') for row in orbits] == names,
         'complete exact official serializer orbit set differs')
    for row in orbits:
        need(set(row) == {'name', 'length', 'selected_index'}
             and type(row['length']) is int and 1 <= row['length'] <= 4
             and type(row['selected_index']) is int and 1 <= row['selected_index'] <= row['length'],
             'official serializer orbit exceeded reviewed bound')
    need(type(result['raw_serializer_idempotent']) is bool
         and result['raw_serializer_idempotent'] == all(row['length'] == 1 for row in orbits),
         'actual serializer non-idempotence was hidden')
    members = image['serialization_orbits']
    need(isinstance(members, list) and [row.get('name') for row in members] == names,
         'retained whole-orbit semantic evidence missing')
    for orbit, row in zip(orbits, members):
        need(row['length'] == orbit['length'] and row['selected_index'] == orbit['selected_index']
             and row['all_members_complete_tables_and_supplemental_readers_equal'] is True
             and len(row['original_images']) == orbit['length']
             and len({x['sha256'] for x in row['original_images']}) == orbit['length']
             and HASH.fullmatch(row['complete_table_semantics_sha256']),
             'retained orbit semantics or image inventory differs')
        for original in row['original_images']:
            image_descriptor(original)
    checks = report['checks']
    need(isinstance(checks, list) and len(checks) >= 10
         and report['check_count'] == report['passed_count'] == len(checks)
         and all(row.get('passed') is True for row in checks), 'a complete comparison check failed')
    av = report['full_av_checks']
    need(av['all_compiled_AV_nodes_validated'] is True
         and av['all_symbolic_AV_permission_atoms_compared'] is True
         and av['candidate_complete_compute_av_verified'] is True
         and av['candidate_effective_expanded_fd_permissions'] == ['use'],
         'full AV proof missing')
    effective = av['candidate_complete_compute_av']
    need(effective['policy']['sha256'] == candidate['sha256']
         and effective['policy']['bytes'] == candidate['bytes']
         and effective['policy']['input_unchanged'] is True
         and effective['requested'] == effective['allowed'] == '0x00000001'
         and effective['denied_requested'] == '0x00000000'
         and effective['denial_reason_mask'] == 0, 'actual complete AV result differs')
    need(report['phone_operations'] == 0 and report['active_policy_writes'] == 0
         and report['live_policy_adoption_authorized'] is False,
         'comparison cannot itself authorize runtime adoption')


def validate_policy(bundle, value, component):
    need(isinstance(POLICY_VERIFIER_SHA,str) and HASH.fullmatch(POLICY_VERIFIER_SHA)
         and type(POLICY_VERIFIER_BYTES) is int and 0<POLICY_VERIFIER_BYTES<=131072
         and all(isinstance(pin,str) and HASH.fullmatch(pin) for pin in
             (CURRENT_POLICY_SHA,CURRENT_POLICY_ADOPTION_SHA,CURRENT_SCOPE_DECISION_SHA))
         and CURRENT_POLICY_SHA != '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
         and CURRENT_POLICY_ADOPTION_SHA != 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
         'new property-policy adoption, scope and verifier have not been frozen and reviewed')
    need(isinstance(value,dict) and isinstance(value.get('verification_originals'),list),
         'explicit new property-policy adoption original inventory required')
    verifier_rows=[row for row in value['verification_originals']
                   if isinstance(row,dict) and row.get('sha256')==POLICY_VERIFIER_SHA
                   and row.get('bytes')==POLICY_VERIFIER_BYTES]
    need(len(verifier_rows)==1,'one exact reviewed property-policy verifier original required')
    verifier_raw=original_from(bundle,verifier_rows[0])
    verifier=types.ModuleType('reviewed_property_policy_adoption')
    verifier.__file__='/reviewed-property-adoption/policy_native5_verifier.py'
    verifier.__reviewed_source_sha256__=sha(verifier_raw)
    exec(compile(verifier_raw,verifier.__file__,'exec',optimize=0),verifier.__dict__)
    raw=base64.b64decode(bundle['inputs']['policy']['raw_b64'],validate=True)
    summary=verifier.verify_adoption(raw,read_pinned=lambda row:original_from(bundle,row))
    need(summary['current_adoption_sha256']==sha(raw)==bundle['inputs']['policy']['descriptor']['sha256']
         == CURRENT_POLICY_ADOPTION_SHA,
         'actual property-policy adoption is not the explicitly reviewed original')
    need(summary['retirement_sha256']==component['retirement_sha256']
         and summary['prior_boundary_sha256']==component['v3_runtime_diagnostic_ancestor']['boundary']['sha256']
         and summary['prior_boundary_sha256']=='fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66',
         'property-policy transition is outside the exact retained actual08 lineage')
    need(summary['root_scope_decision_sha256']==CURRENT_SCOPE_DECISION_SHA
         and summary['parent_adoption_sha256']=='527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
         and summary['actual_live_binding_sha256']=='c9053279b561296e67de6ed0acc8b233fcc64ae8600ab21a58b772cddfe6eeed',
         'property-policy transition changed its exact reviewed parent or new scope')
    actual=original_from(bundle,value['actual_export']);full=original_from(bundle,value['full_rule'])
    need(summary['runtime_policy']==descriptor(actual) and summary['full_rule']==value['full_rule']
         and component['component_combination']['live_policy_sha256']==sha(actual)==CURRENT_POLICY_SHA,
         'current component policy and complete adopted property-policy rules differ')
    return {'runtime_policy':descriptor(actual),'full_rule':full,
            'policy_adoption_sha256':summary['current_adoption_sha256'],
            'policy_transition':summary}



def validate_bundle(raw, expected_sha256):
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BUNDLE and sha(raw) == expected_sha256,
         'explicit release-boundary bundle pin differs')
    bundle = strict(raw)
    need(set(bundle) == {'schema', 'inputs', 'originals'}
         and bundle['schema'] == 'hepta.r10.release-boundary-bundle.v2'
         and set(bundle['inputs']) == {'component', 'policy'}, 'release-boundary bundle schema differs')
    component_value = input_value(bundle, 'component'); policy_value = input_value(bundle, 'policy')
    wanted = {row['sha256'] for value in (component_value, policy_value) for row in descriptors(value)}
    need(set(bundle['originals']) == wanted, 'bundled original inventory differs')
    state = validate_component(bundle, component_value)
    state.update(validate_policy(bundle, policy_value, state))
    state.update(bundle_sha256=expected_sha256,
        component_input_sha256=bundle['inputs']['component']['descriptor']['sha256'])
    return state


def inventory_value(state, inventory):
    with component_modules(state) as modules:
        return modules['late_boundary'].inventory_value(inventory)


def current_preservation(state):
    """Phone read-only; old common/retire/census entrypoints are never invoked."""
    with component_modules(state, runtime=True) as modules:
        late = modules['late_boundary']; common = modules['component_common']
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT,
             'component preservation boot differs')
        external = common.verify_external(state['component_combination'])
        retained=late.retained_unstarted_stage()
        need(retained['binding']==state['retained_unstarted_stage'],'fresh retained-stage binding differs')
        retained_transport=late.retained_stage_external_originals(retained)
        retained_parent_before=late.retained_stage_parent_aliases()
        retained_fixture_before=late.fresh_retained_fixture_absence()
        sidebranches = late.non_native_sidebranches(phone_originals=True)
        need(encode(sidebranches[0]['binding']) == encode(state['non_native_sidebranch'])
             and encode([s['binding'] for s in sidebranches]) == encode(state['non_native_sidebranches']),
             'actual two non-native branches differ from the sealed original bindings')
        retirement = state['component_input']['retirement']
        late.retired_originals(retirement, BOOT)
        chain, originals = late.chain_originals(state['component_input']['latest_boundary'],
            combination_sha256=state['component_input']['component_combination']['sha256'],
            package_sha256=PACKAGE_SHA, boot_id=BOOT, retirement=retirement)
        need(chain[0][0]['inventory']['sha256'] == state['chain'][0][0]['inventory']['sha256'],
             'component current boundary differs from sealed original')
        roots = state['current_inventory']['roots']
        fixtures = [p for p in roots if re.fullmatch(
            r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}', p)]
        observed = modules['component_lifecycle'].inventory(roots, fixture_roots=fixtures)
        late.preserve_non_native_sidebranches(observed, sidebranches)
        late.preserve_retained_unstarted_stage(observed,retained=retained)
        retained_fixtures=[retained_fixture_before,late.fresh_retained_fixture_absence()]
        late.validate_retained_fixture_observations(retained_fixtures)
        retained_parents=late.retained_stage_parent_profiles(retained,observed,
            retained_parent_before,late.retained_stage_parent_aliases())
        need(retained_parents==chain[0][2]['retained_stage_parent_profiles'],
             'current parent aliases differ from the independently closed final prefix')
        absence = [common.absent_groups(state['roles']), common.absent_groups(state['roles'])]
        _tables, endpoints = modules['component_snapshot'].endpoint_absence()
        late.recheck_originals(originals + list(retirement.values())
                               + [row for side in sidebranches for row in side['originals']] + retained_transport)
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT,
             'boot changed during component preservation')
        return observed, {'role_absence': absence, 'endpoints': endpoints,
            'retained_unstarted_stage':retained['binding'],
            'retained_stage_parent_profiles':retained_parents,'retained_stage_fixture_absence':retained_fixtures,
            'external_artifacts': external,
            'component_boundary_sha256': state['component_boundary_sha256'],
            'retirement_sha256': state['retirement_sha256'],
            'old_retirement_current_equality_claimed': False}


def inventory_path(android_path):
    p = Path(android_path)
    need(p.is_absolute() and str(p) == android_path and '..' not in p.parts,
         'canonical release target required')
    if android_path == ANDROID_BASE or android_path.startswith(ANDROID_BASE + '/'):
        return BASE + android_path[len(ANDROID_BASE):]
    return '/proc/1/root' + android_path


def validate_install_layout(state, manifest):
    roots = list(map(Path, state['current_inventory']['roots']))
    observed = []
    for row in manifest['writes']:
        p = Path(inventory_path(row['target']))
        need(not any(p == root or root in p.parents or p in root.parents for root in roots),
             'release file write overlaps preserved component inventory')
    for row in manifest['runtime_directories']:
        p = Path(inventory_path(row['path']))
        if any(p == root or root in p.parents or p in root.parents for root in roots):
            need(str(p) == INSTALL_DIRECTORY and row.get('selinux') == INSTALL_LABEL,
                 'unreviewed runtime directory overlaps preserved originals')
            observed.append(str(p))
    need(observed == [INSTALL_DIRECTORY], 'one exact installation-owned empty directory required')
    need(INSTALL_DIRECTORY not in state['current_inventory']['entries']
         and str(Path(INSTALL_DIRECTORY).parent) in state['current_inventory']['entries'],
         'new installation directory already exists or its preserved parent is absent')


def validate_install_delta(before, after):
    """Only the actual stage source's mkdir/chown/chmod/label/fsync is admitted.

    No stage source opens a file under this directory. Its per-boot child and
    sidecar log files are created later by service.sh, after the start boundary.
    """
    need(before['schema'] == after['schema'] == 'hepta.native-guard.complete-inventory.v1'
         and before['roots'] == after['roots']
         and before['file_bytes_hashed'] == after['file_bytes_hashed']
         and before['inventory_is_closure_or_retirement'] is False
         and after['inventory_is_closure_or_retirement'] is False, 'stage inventory envelope changed')
    b, a = before['entries'], after['entries']
    parent = str(Path(INSTALL_DIRECTORY).parent); name = Path(INSTALL_DIRECTORY).name
    need(INSTALL_DIRECTORY not in b and set(a) == set(b) | {INSTALL_DIRECTORY}
         and parent in b, 'stage changed an unreviewed inventory path')
    new = a[INSTALL_DIRECTORY]
    need(set(new) == {'kind', 'metadata', 'names'} and new['kind'] == 'directory'
         and new['names'] == [], 'installation-owned directory is not exactly empty')
    bm, am, nm = b[parent]['metadata'], a[parent]['metadata'], new['metadata']
    need(len(bm) == len(am) == len(nm) == 9
         and all(type(v) is int for v in bm + am + nm), 'stage metadata shape differs')
    need(nm[0] == bm[0] and nm[1] > 0 and nm[2] == stat.S_IFDIR | 0o700
         and nm[3:6] == [0, 0, 2] and nm[6] >= 0,
         'installation-owned empty directory metadata differs')
    need(set(b[parent]) == set(a[parent]) == {'kind', 'metadata', 'names'}
         and b[parent]['kind'] == a[parent]['kind'] == 'directory'
         and a[parent]['names'] == sorted(b[parent]['names'] + [name])
         and name not in b[parent]['names'], 'preserved parent gained a different name')
    need(am[:5] == bm[:5] and am[5] == bm[5] + 1 and am[6] >= bm[6]
         and am[7] >= bm[7] and am[8] >= bm[8]
         and nm[7] >= bm[7] and nm[8] >= bm[8],
         'preserved parent identity or mkdir-attributable metadata differs')
    for path in b:
        if path != parent:
            need(a[path] == b[path], 'pre-existing original changed during install: ' + path)
    return {'added_directory': INSTALL_DIRECTORY, 'added_directory_metadata': nm,
        'parent': parent, 'parent_before_metadata': bm, 'parent_after_metadata': am,
        'parent_added_name': name, 'all_old_file_bytes_and_identities_unchanged': True,
        'other_directory_entries_unchanged': True,
        'old_retirement_current_equality_claimed': False}
