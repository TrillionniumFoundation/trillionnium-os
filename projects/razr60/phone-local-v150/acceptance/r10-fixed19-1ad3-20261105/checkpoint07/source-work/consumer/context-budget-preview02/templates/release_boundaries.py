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
PACKAGE_SHA = None
PACKAGE_FILE_COUNT = 32
CURRENT_COMBINATION_SHA = None
POLICY_VERIFIER_SHA = None
POLICY_VERIFIER_BYTES = None
MAX_ORIGINAL = 16 * 1024 * 1024
MAX_BUNDLE = 32 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMPONENT_FIELDS = {'schema', 'release_id', 'boot_id', 'component_package_manifest',
    'component_package_files', 'component_combination', 'latest_boundary',
    'publish_result', 'retirement', 'originals', 'pre_policy_ancestor', 'non_native_sidebranch',
    'environment_parent_ancestor', 'property_parent_ancestors'}
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
CURRENT_POLICY_SHA = None
CURRENT_POLICY_ADOPTION_SHA = None
CURRENT_SCOPE_DECISION_SHA = None

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
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
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


def checked_actual_context(value):
    need(type(value) is str and value in ('phone', 'mac', 'p4'),
         'explicit actual phone/mac/p4 execution context required')
    return value


def decoded_bundle_budget(bundle):
    """Charge all decoded payloads before any body decode or source execution."""
    need(type(bundle['originals']) is dict, 'exact original byte pool required')
    total = 0
    for name in ('component', 'policy'):
        row = bundle['inputs'][name]
        need(type(row) is dict and set(row) == {'descriptor', 'raw_b64'},
             'input payload fields differ')
        descriptor = file_descriptor(row['descriptor'])
        need(type(row['raw_b64']) is str
             and len(row['raw_b64']) <= 4 * ((descriptor['bytes'] + 2) // 3),
             'input payload exceeds its exact decoded bound')
        total += descriptor['bytes']
    need(total <= MAX_BUNDLE, 'decoded input payloads exceed fixed shared bundle budget')
    for digest, item in bundle['originals'].items():
        need(type(digest) is str and HASH.fullmatch(digest)
             and type(item) is dict
             and set(item) in ({'bytes', 'raw_b64'}, {'bytes', 'zlib_b64'})
             and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_ORIGINAL,
             'bounded decoded original pool entry required')
        total += item['bytes']
        need(total <= MAX_BUNDLE, 'decoded originals exceed one fixed shared bundle budget')
    return total


def prepare_bundle(component_input, policy_input, *, actual_context):
    """Host-only: collect exact originals, then run the shared pure checks."""
    actual_context = checked_actual_context(actual_context)
    need(actual_context == 'mac', 'this fixed host constructor requires actual Mac context')
    inputs = {}; originals = {}; observed = {}; declared = {}
    decoded_total = sum(file_descriptor(row)['bytes'] for row in (component_input, policy_input))
    need(decoded_total <= MAX_BUNDLE, 'input originals exceed fixed shared decoded budget')
    for name, row in (('component', component_input), ('policy', policy_input)):
        raw, metadata = read_pinned(row)
        observed[row['path']] = (row, metadata)
        value = strict(raw)
        inputs[name] = {'descriptor': row, 'raw_b64': base64.b64encode(raw).decode()}
        for source in descriptors(value):
            previous_size = declared.get(source['sha256'])
            need(previous_size is None or previous_size == source['bytes'],
                 'same original digest has different declared size')
            if previous_size is None:
                decoded_total += source['bytes']
                need(decoded_total <= MAX_BUNDLE, 'originals exceed one shared decoded budget before reading')
                declared[source['sha256']] = source['bytes']
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
    state = validate_bundle(raw, sha(raw), actual_context=actual_context)
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
def component_modules(state, *, actual_context, runtime=False):
    """Evaluate only reviewed package originals; restore import state on exit."""
    actual_context = checked_actual_context(actual_context)
    need('actual_context' not in state or state['actual_context'] == actual_context,
         'actual execution context changed between validation and module loading')
    need(not runtime or actual_context == 'phone', 'live runtime modules require actual phone context')
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
            module.__actual_context__ = actual_context
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
        canonical = old_reader.C.encoded(boundary)
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


RUNTIME_SOURCE_INCREMENT = {'base_freeze_result': {'bytes': 22392,
                        'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/FREEZE-RESULT.json',
                        'sha256': 'f1e9f063468d1bfdbed0f1e877afb70acafcddf78bbc872dc4078d472afddc67'},
 'base_freezer_source': {'bytes': 36899,
                         'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-property-r8-freeze-final01/source/freeze_property_runtime.py',
                         'sha256': '70e0ccc9844438aeee54ba4e734e886c81c2e640f92a997a766015e7bb5b285d'},
 'base_runtime_manifest': {'bytes': 16808,
                           'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/runtime/MANIFEST.json',
                           'sha256': '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'},
 'changed_member': {'parent': {'bytes': 66996,
                               'sha256': 'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'},
                    'path': 'source/late_boundary.py',
                    'successor': {'bytes': 67005,
                                  'sha256': '147cf49e91fb4bcbddeba6591d48c8782efe20452db2b2d6179e7addd68c27e4'}},
 'inherited_metadata_scope': 'original_r7_to_r8_generation_preserved_not_successor_actions',
 'runtime_member_count': 32,
 'schema': 'hepta.native-guard.runtime-source-increment.v1',
 'state': 'EXACT_RUNTIME32_SINGLE_EXPRESSION_SUCCESSOR_SOURCE_ONLY',
 'successor_actions': {'historical_reference_changes': 0,
                       'host_source_derivation': True,
                       'new_nonces': 0,
                       'phone_operations': 0,
                       'policy_adoptions_created': 0,
                       'policy_applications': 0},
 'transformation': {'accepted_path_domain': 'canonical_absolute_posix_without_dotdot',
                    'function': 'inventory_value',
                    'new_utf8': 'sum(p.parts[:len(q.parts)] == q.parts for q in paths) == 1',
                    'old_utf8': 'sum(p == q or q in p.parents for q in paths) == 1',
                    'whole_source_inverse_required': True},
 'unchanged_member_count': 31}


def verify_runtime_source_increment(manifest_raw, source_files):
    """Pure exact32/source-and-manifest inverse; never opens or executes a file.

    Dependencies are only this module's fixed RUNTIME_SOURCE_INCREMENT object
    and the standard json/hashlib modules. All parsing/encoding helpers are
    local to prevent caller strict/encode implementations changing semantics.
    The caller still performs its original proof, filesystem and case gates.
    """
    def require(value, reason):
        if not value:
            raise ValueError('runtime source increment: ' + reason)

    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def encode(value):
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')

    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError('runtime source increment: nonfinite JSON')

    require(type(manifest_raw) is bytes and 0 < len(manifest_raw) <= 65536,
            'bounded exact manifest bytes required')
    manifest = json.loads(manifest_raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    require(type(manifest) is dict and encode(manifest) == manifest_raw,
            'original manifest encoding differs')
    require(type(manifest.get('runtime_source_increment')) is dict
            and encode(manifest['runtime_source_increment']) == encode(RUNTIME_SOURCE_INCREMENT),
            'one exact-typed fixed reviewed runtime increment required')
    require(type(source_files) is dict and type(manifest.get('files')) is list
            and len(manifest['files']) == len(source_files) == 32,
            'exact32 source container required')
    rows = {}
    for row in manifest['files']:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
                and type(row['path']) is str and row['path'] not in rows
                and type(row['bytes']) is int and 0 <= row['bytes'] <= 8 * 1024 * 1024
                and type(row['sha256']) is str,
                'exact bounded unique source row required')
        rows[row['path']] = row
    require(set(rows) == set(source_files), 'complete32 source names differ')
    for name, row in rows.items():
        body = source_files[name]
        require(type(body) is bytes and len(body) == row['bytes']
                and digest(body) == row['sha256'], 'source bytes differ: ' + name)
    change = RUNTIME_SOURCE_INCREMENT['changed_member']
    name = change['path']
    require(name in rows and rows[name] == dict(path=name, **change['successor']),
            'only the exact reviewed current reader can be changed')
    candidate = source_files[name]
    transformation = RUNTIME_SOURCE_INCREMENT['transformation']
    before = transformation['old_utf8'].encode('ascii')
    after = transformation['new_utf8'].encode('ascii')
    require(candidate.count(after) == 1, 'one exact successor expression required')
    restored_source = candidate.replace(after, before, 1)
    require(restored_source.count(before) == 1
            and {'bytes': len(restored_source), 'sha256': digest(restored_source)} == change['parent'],
            'complete current reader inverse differs from actual c50a')
    retained_increment = manifest.pop('runtime_source_increment')
    restored_rows = []
    for row in manifest['files']:
        restored_rows.append(dict(path=name, **change['parent']) if row['path'] == name else row)
    manifest['files'] = restored_rows
    restored_manifest = encode(manifest)
    parent = RUNTIME_SOURCE_INCREMENT['base_runtime_manifest']
    require({'bytes': len(restored_manifest), 'sha256': digest(restored_manifest)}
            == {key: parent[key] for key in ('bytes', 'sha256')},
            'whole manifest inverse differs from actual16808/67dc')
    return {'schema': 'hepta.native-guard.runtime-source-increment-proof.v1',
            'state': 'EXACT_RUNTIME32_SINGLE_EXPRESSION_AND_PARENT_INVERSES_VERIFIED',
            'runtime_manifest': {'bytes': len(manifest_raw), 'sha256': digest(manifest_raw)},
            'base_runtime_manifest': dict(parent), 'runtime_source_increment': retained_increment,
            'member_count': 32, 'unchanged_member_count': 31,
            'all32_source_bytes_verified': True, 'whole_source_inverse_verified': True,
            'whole_manifest_inverse_verified': True,
            'target_source_executed': False, 'historical_reference_changes': 0,
            'phone_calls': 0, 'component_qualified': False, 'business_qualified': False}


def validate_component(bundle, value, *, actual_context):
    actual_context = checked_actual_context(actual_context)
    need(isinstance(PACKAGE_SHA,str) and HASH.fullmatch(PACKAGE_SHA)
         and type(PACKAGE_FILE_COUNT) is int and 24<PACKAGE_FILE_COUNT<=32
         and isinstance(CURRENT_COMBINATION_SHA,str) and HASH.fullmatch(CURRENT_COMBINATION_SHA),
         'current policy component runtime has not been frozen and reviewed')
    need(isinstance(value, dict) and set(value) == COMPONENT_FIELDS
         and value['schema'] == 'hepta.r10.component-boundary-inputs.v5'
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
    # Validate every new runtime byte before any component source is executed.
    verify_runtime_source_increment(manifest_raw, source)
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
    state = {'actual_context': actual_context, 'package_sources': source, 'component_input': value,
             'component_combination': combination, 'component_originals': copies}
    used = set(); chain = []; seen_nonce = set(); seen_scope = set()
    with component_modules(state, actual_context=state['actual_context']) as modules:
        late = modules['late_boundary']; common = modules['component_common']
        sidebranch = late.non_native_sidebranch()
        need(encode(value['non_native_sidebranch']) == encode(sidebranch['binding']),
             'component input omitted or changed the exact non-native attempt05 binding')
        def body(row):
            late.exact_descriptor(row)
            need(row['path'] in copies and copies[row['path']][0] == row,
                 'exact phone file identity was omitted or changed')
            used.add(row['path'])
            return copies[row['path']][1]
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
                    and not late.is_property_parent_ancestor(boundary)):
                need(closure['closure_source_sha256'] == sha(source['source/close_component.py']),
                     'current component closure source differs')
                need(encode(boundary.get('non_native_sidebranch')) == encode(sidebranch['binding'])
                     and encode(closure.get('non_native_sidebranch')) == encode(sidebranch['binding']),
                     'current native originals changed the independently closed non-native binding')
                late.preserve_non_native_private(inventory, sidebranch)
            # The external branch is checked against the immutable published
            # raw descriptor and its actual external verifier source by the
            # same reviewed runtime reader. It never gains current-case credit.
            chain.append((boundary, inventory, closure))
            current = boundary['prior_boundary']
        need(chain, 'explicit actual closed component boundary is required')
        late.require_failed_ancestor_tail([row[0] for row in chain])
        need(len(chain)>=6 and chain[0][0]['schema']==late.SCHEMA
             and chain[0][0]['package_sha256']==PACKAGE_SHA
             and chain[0][0]['combination_sha256']==CURRENT_COMBINATION_SHA
             and not late.is_pre_policy_ancestor(chain[0][0])
             and not late.is_environment_parent_ancestor(chain[0][0])
             and not late.is_property_parent_ancestor(chain[0][0]),
             'a new current-package component must precede the fixed actual08-to07-to06-to04-to03 tail')
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
        component_roles.extend(sidebranch['binding']['component_role_identities'].values())
        roles.extend(component_roles)
        need(len(roles) <= 64 and len({tuple(row) for row in roles}) == len(roles),
             'closed role generation identities repeat or exceed bound')
    state.update(chain=chain, current_inventory=chain[0][1], retired=retired,
        retirement_sha256=retirement['proof']['sha256'], roles=roles,
        component_roles=component_roles, component_boundary_sha256=value['latest_boundary']['sha256'],
        pre_policy_ancestor=pre_policy, non_native_sidebranch=sidebranch['binding'],
        environment_parent_ancestor=environment_parent, property_parent_ancestors=property_parents)
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
    with component_modules(state, actual_context=state['actual_context']) as modules:
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
    with component_modules(state, actual_context=state['actual_context']) as modules:
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
    need(checked_actual_context(state['actual_context']) == 'phone',
         'current external artifacts require actual phone context')
    with component_modules(state, actual_context=state['actual_context']) as modules:
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
         and summary['prior_boundary_sha256']==component['property_parent_ancestors'][0]['boundary']['sha256']
         and summary['prior_boundary_sha256']=='eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
         'property-policy transition is outside the exact retained actual08 lineage')
    need(summary['root_scope_decision_sha256']==CURRENT_SCOPE_DECISION_SHA
         and summary['parent_adoption_sha256']=='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
         'property-policy transition changed its exact reviewed parent or new scope')
    actual=original_from(bundle,value['actual_export']);full=original_from(bundle,value['full_rule'])
    need(summary['runtime_policy']==descriptor(actual) and summary['full_rule']==value['full_rule']
         and component['component_combination']['live_policy_sha256']==sha(actual)==CURRENT_POLICY_SHA,
         'current component policy and complete adopted property-policy rules differ')
    return {'runtime_policy':descriptor(actual),'full_rule':full,
            'policy_adoption_sha256':summary['current_adoption_sha256'],
            'policy_transition':summary}



def validate_bundle(raw, expected_sha256, *, actual_context):
    actual_context = checked_actual_context(actual_context)
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BUNDLE and sha(raw) == expected_sha256,
         'explicit release-boundary bundle pin differs')
    bundle = strict(raw)
    need(set(bundle) == {'schema', 'inputs', 'originals'}
         and bundle['schema'] == 'hepta.r10.release-boundary-bundle.v2'
         and set(bundle['inputs']) == {'component', 'policy'}, 'release-boundary bundle schema differs')
    decoded_bundle_budget(bundle)
    component_value = input_value(bundle, 'component'); policy_value = input_value(bundle, 'policy')
    wanted = {row['sha256'] for value in (component_value, policy_value) for row in descriptors(value)}
    need(set(bundle['originals']) == wanted, 'bundled original inventory differs')
    state = validate_component(bundle, component_value, actual_context=actual_context)
    state.update(validate_policy(bundle, policy_value, state))
    state.update(bundle_sha256=expected_sha256,
        component_input_sha256=bundle['inputs']['component']['descriptor']['sha256'])
    return state


def inventory_value(state, inventory):
    with component_modules(state, actual_context=state['actual_context']) as modules:
        return modules['late_boundary'].inventory_value(inventory)


def current_preservation(state):
    """Phone read-only; old common/retire/census entrypoints are never invoked."""
    with component_modules(state, runtime=True, actual_context=state['actual_context']) as modules:
        late = modules['late_boundary']; common = modules['component_common']
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT,
             'component preservation boot differs')
        external = common.verify_external(state['component_combination'])
        sidebranch = late.non_native_sidebranch(phone_originals=True)
        need(encode(sidebranch['binding']) == encode(state['non_native_sidebranch']),
             'actual non-native sidebranch differs from the sealed original binding')
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
        late.preserve_non_native_private(observed, sidebranch)
        absence = [common.absent_groups(state['roles']), common.absent_groups(state['roles'])]
        _tables, endpoints = modules['component_snapshot'].endpoint_absence()
        late.recheck_originals(originals + list(retirement.values()) + sidebranch['originals'])
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT,
             'boot changed during component preservation')
        return observed, {'role_absence': absence, 'endpoints': endpoints,
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
