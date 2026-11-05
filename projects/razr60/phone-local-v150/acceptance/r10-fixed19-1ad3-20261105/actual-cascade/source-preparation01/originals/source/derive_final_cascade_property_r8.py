#!/usr/bin/env python3
"""Reviewed host-only R8 FC8 / AC9 / C8 property-policy source cascade.

Default is zero-I/O preview. Future trust pins remain None until a new reviewed
source revision fixes the actual runtime, combination, policy export, adoption
and verifier. This entry creates source packages only: no nonce, case, release,
build, seal, install, phone, policy load or qualification is produced.
"""
import argparse
import ast
import base64
import copy
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
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
FINALIZATION = {'schema': 'hepta.property-policy.final-pin-freeze.v1', 'runtime_manifest': {'bytes': 16808, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/runtime/MANIFEST.json', 'sha256': '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'}, 'component_combination': {'bytes': 4702, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/COMBINATION.json', 'sha256': '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'}, 'policy_adoption': {'bytes': 208226, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-02/POLICY-ADOPTION.json', 'sha256': '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'}, 'policy_verifier': {'bytes': 126796, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/source/policy_runtime_properties_verifier.py', 'sha256': '74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}, 'actual_policy': {'bytes': 2667740, 'sha256': 'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'}, 'scope_decision': {'bytes': 24830, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-02/capture/originals/ROOT-SCOPE-DECISION.original.json', 'sha256': '5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'}, 'full_rule': {'bytes': 17284, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-02/capture/originals/full-candidate.rule', 'sha256': '424e1c680d37583f039c8cc5e2727200b3f9ad8fd29d35616173a5102b0218d1'}}
REVIEWED_MODULE_INPUT_REPLACEMENT = {'path':str(B/'module-sidecar-android-environment-r7-candidate01/MODULE-INPUT-REPLACEMENT.json'), 'bytes':5897, 'sha256':'223801205cfaba915c88b76fb291f888043c0f75fe0ae22be10ff13b19931374'}
FC_PARENT = B/'r10-boundary-consumers-final-r7'
FC_PARENT_SHA = 'e4c1c351a363aed80968fa9a952f3ad3bb1291c9dd8cb2d1e7591c448f1efb41'
AC_PARENT = B/'scoped-acceptance-v150-r10-r1-readiness-r8'
AC_PARENT_SHA = '12f0ccf601b37d8e5e08b162ac1e8e2fcd4a1e7639e30d71afbf068d9f39293b'
CC_PARENT = B/'r10-component-boundary-input-entry-r7'
CC_PARENT_SHA = 'e6795b9c7e31342943d17596a8c3a86177073bc36c8990de083642cd6fa0e649'
FC = B/'r10-boundary-consumers-final-r8'
AC = B/'scoped-acceptance-v150-r10-r1-readiness-r9'
CC = B/'r10-component-boundary-input-entry-r8'
RUNTIME_PARENT = B/'native-guard-r10-r1-operator-r7/runtime'
RUNTIME_PARENT_SHA = '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
HISTORICAL_RUNTIME = B/'native-guard-r10-r1-operator-r4/runtime'
HISTORICAL_RUNTIME_SHA = '1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996'
NON_NATIVE_REFERENCES = {
    'proof': 'reference/attempt05-SIDE-PROOF.original.json',
    'closure': 'reference/attempt05-CLOSURE.original.json',
    'inventory': 'reference/attempt05-AFTER-INVENTORY.original.json'}
ENVIRONMENT_PARENT_REFERENCE = 'reference/environment_parent_late_boundary_r6.py'
# R8 exact path sets are declared below; no R7 generation is replayed.
# Only the current late reader changes; all30 other parent members are retained.
ENVIRONMENT_PARENT_BOUNDARY_SHA = 'eca628a18327146b7710a478fc2c2f716f79d55907b2821666828a0795e2060f'
PROPERTY_PARENT_REFERENCE = 'reference/property_parent_late_boundary_r7.py'
R8_ADDED_PATHS = {PROPERTY_PARENT_REFERENCE}
R8_CHANGED_PATHS = {'source/late_boundary.py'}
ENVIRONMENT_RUNTIME = B/'native-guard-r10-r1-operator-r6/runtime'
ENVIRONMENT_RUNTIME_SHA = '4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e'
PROPERTY_PARENT_BOUNDARY_SHAS = ['eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
    '46b03cd66426395198b4a3093117659d5cfb128cc981815934fc1ea695c97be0']
POLICY_PARENT_COMBINATION_SHA = 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
HISTORICAL_POLICY_SHA = '296b09d9c844d2916b0dbdb0765c71cbcb8411790b58f5823798aa872205b659'
HISTORICAL_ADOPTION_SHA = '7899e446ef77d9f05aab7f22298ff9470e04a5253c2397ec6cf292543daac87e'
PARENT_VERIFIER_SHA = '8f7377016d94c1cda70dbd4d6f68f5aa95f30633487c4f9d2abb12e7a636cd5c'
OLD_READER_REFERENCE = 'reference/policy_parent_late_boundary_r4.py'
PUBLICATION = B/'native-guard-attempt03-external-publication-r1/actual-02'
PUBLICATION_SHA = '5799fac9fcc837c61e2990b56d0feab9140affd97b988f80419feeefeb7167ce'
BOUNDARY_SHA = 'ee008c3b2adec701be4c0bdfd38ca7ac0d650da9b7783f51d3fe4638bfdc5b58'
CLOSURE_SHA = 'b8a27617eaff8dda0f1c61b5aa14a89d7014a157e0b33280b14162c7591bcaa3'
INVENTORY_SHA = '145d5937cd328ed568b1af9c73f7d331211d1c44cfad8ecf960b47d91f308eee'
COMBINATION_SHA = '7f5929ae709239f8a5d92314146d2b63151bb06746d160da7961a3de29c486af'
PUBLISHER_SHA = '234e248d4db6aff6125071a62f92e48360df1bab839250b26699c8af63067b07'
PRE_POLICY_BOUNDARY_SHA = '3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'
POLICY_PARENT_SHA = '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PARENT_ADOPTION_SHA = 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
PARENT_ROOT_SCOPE_DECISION_SHA = '3a30afe60a37c224114e9414b8d290c574eb56185820ebe4584156d2d10a13fb'
PARENT_FULL_RULE_SHA = 'aeda92123f1d043de2c53dd345dd7372b98da7b776299d57bda531dda868e4a1'
SHARED_CONFIGURATION_SHA = '780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'
SHARED_SERVICE_SHA = '2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'
FROZEN_READINESS_SHA = '345723406df0c523ab55b167bb52f5ceb9432d387ffe3b4aa5b1e5442465e392'
RUNTIME_NAMES = ('release_boundaries.py', 'collect_r10_readiness.py',
                 'build_release_r10.py', 'install_phone_release_r10.py',
                 'component_activation_gate.fragment.py')
UNCHANGED_CHAIN = ('capture_originals_r10.py', 'close_original_r10.py',
                   'export_originals_r10.py', 'read_archive_chunk_r10.py',
                   'registration_phone_r10.py')
OBSERVED = {}
TEMPLATE_PINS = {
  "build_release_r10.py": {
    "bytes": 40822,
    "sha256": "79f1788977d8d2f06168351e61969eda8f557ea339df1a4987455c002b8e3be9"
  },
  "close_component.py": {
    "bytes": 99120,
    "sha256": "9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1"
  },
  "collect_r10_readiness.py": {
    "bytes": 16343,
    "sha256": "f17198b30d287ede04665179522a81d010839a60e1549c959410daf0605628af"
  },
  "component_activation_gate.fragment.py": {
    "bytes": 4492,
    "sha256": "140b7591781a3e487ef7b3ee5b7187fc95058a8b49c28eb3db0c7d8b630fa922"
  },
  "component_common.py": {
    "bytes": 19138,
    "sha256": "1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab"
  },
  "component_common_r5.py": {
    "bytes": 18133,
    "sha256": "8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02"
  },
  "component_lifecycle.py": {
    "bytes": 40261,
    "sha256": "144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2"
  },
  "component_snapshot.py": {
    "bytes": 24187,
    "sha256": "2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa"
  },
  "environment_parent_late_boundary_r6.py": {
    "bytes": 53502,
    "sha256": "1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c"
  },
  "install_phone_release_r10.py": {
    "bytes": 34038,
    "sha256": "3ce2207e1f195c95b7424690a870e4c556e9eccc802e2265c00af78a464f38b1"
  },
  "late_boundary.py": {
    "bytes": 66816,
    "sha256": "f42cf7da63df8e3ecd31e984b2deac5d5fc7e1ee0f2bdbb095a8268243a133d4"
  },
  "make_component_boundary_inputs.py": {
    "bytes": 34626,
    "sha256": "ed12bbeb717c19a4608ee402fa45b575a78ecbd664cb24eef1bf29bbe331f5fc"
  },
  "materialize_case_r10.py": {
    "bytes": 24834,
    "sha256": "b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290"
  },
  "non_native_attempt05.py": {
    "bytes": 19740,
    "sha256": "a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4"
  },
  "policy_parent_late_boundary_r4.py": {
    "bytes": 35730,
    "sha256": "bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b"
  },
  "property_parent_late_boundary_r7.py": {
    "bytes": 62434,
    "sha256": "3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd"
  },
  "release_boundaries.py": {
    "bytes": 77700,
    "sha256": "619589ce59c209d491f1994d67008327604ce07894d101a278c3ebc06052a5f1"
  },
  "root_acceptance_r10.py": {
    "bytes": 27473,
    "sha256": "70ea657a6a3f1149fd6840b7d1497336f75275e5e7a0661549e4d4e5c1432c4d"
  },
  "stage_component.py": {
    "bytes": 19116,
    "sha256": "4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340"
  }
}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def descriptor(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False)+'\n').encode()

def combination_encode(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate original JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite original JSON'))


def metadata(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, digest, size=None, *, remember=True):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical host original required')
    need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'explicit SHA required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= 16*1024*1024, 'bounded original regular file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(before.st_size+1)
        need(metadata(before) == metadata(os.fstat(fd)) == metadata(path.lstat())
             and len(raw) == before.st_size and sha(raw) == digest
             and (size is None or type(size) is int and len(raw) == size),
             'original bytes or stable metadata differ: '+str(path))
    finally:
        os.close(fd)
    if remember:
        row = (digest, len(raw), metadata(before))
        need(str(path) not in OBSERVED or OBSERVED[str(path)] == row, 'original changed between reads')
        OBSERVED[str(path)] = row
    return raw


def original(row):
    need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'}, 'exact host descriptor required')
    return read(row['path'], row['sha256'], row['bytes'])


def package(root, digest, size=None):
    raw = read(root/'MANIFEST.json', digest, size)
    value = strict(raw)
    rows = value['files']
    need(isinstance(rows, list) and len(rows) == len({r['path'] for r in rows}), 'complete unique manifest rows required')
    files = {}
    for row in rows:
        need(set(row) == {'path', 'bytes', 'sha256'}, 'exact source manifest row required')
        rel = Path(row['path'])
        need(not rel.is_absolute() and '..' not in rel.parts and str(rel) == row['path'], 'unsafe source manifest path')
        files[row['path']] = read(root/rel, row['sha256'], row['bytes'])
    return raw, value, files


def replace(raw, before, after):
    before, after = before.encode(), after.encode()
    need(raw.count(before) == 1 and after not in raw, 'unique source placeholder required')
    result = raw.replace(before, after, 1)
    need(result.replace(after, before, 1) == raw, 'pin substitution must reverse byte exactly')
    return result


def difference(parent, changed, prefix):
    result = []
    for name, raw in sorted(changed.items()):
        if name in parent and raw != parent[name] and name.endswith('.py'):
            result.extend(difflib.unified_diff(parent[name].decode().splitlines(True),
                raw.decode().splitlines(True), fromfile='parent/'+name, tofile=prefix+'/'+name))
    return ''.join(result).encode()


def recheck():
    for path, (digest, size, identity) in OBSERVED.items():
        read(path, digest, size, remember=False)
        need(metadata(Path(path).lstat()) == identity, 'original metadata changed before host publication')


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    syncdir(path.parent)
    need(read(path, sha(raw), len(raw), remember=False) == raw, 'new host source readback differs')


def publish(root, files):
    need(root.parent.resolve(strict=True) == root.parent, 'canonical output parent required')
    root.mkdir(mode=0o700); syncdir(root.parent)
    for name, raw in sorted(files.items()):
        path = root/name
        missing = []
        current = path.parent
        while current != root:
            missing.append(current); current = current.parent
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700); syncdir(directory.parent)
            except FileExistsError:
                need(directory.resolve(strict=True) == directory and directory.is_dir(), 'output ancestor differs')
        put(path, raw)


def add_manifest(files, value):
    need('MANIFEST.json' not in files, 'manifest cannot contain itself')
    value = dict(value, files=[dict(path=name, **descriptor(raw)) for name, raw in sorted(files.items())])
    files['MANIFEST.json'] = encode(value)


def actual_tail_check(helper_raw, constructor_raw, runtime_files, package_sha, combination_sha):
    raw = read(PUBLICATION/'PUBLICATION-RESULT.json', PUBLICATION_SHA, 13450)
    publication = strict(raw)
    need(publication['state'] == 'EXTERNAL_FAILED_BOUNDARY_PUBLISHED_AND_THREE_ORIGINALS_EXPORTED'
         and publication['component_qualified'] is False and publication['business_qualified'] is False
         and publication['native_submissions'] == publication['phone_tools'] == publication['model_requests'] == 0,
         'actual failed publication result differs')
    raw_files = {}
    for key, pin, size, filename in (
        ('boundary', BOUNDARY_SHA, 5003, 'BOUNDARY.original.json'),
        ('closure', CLOSURE_SHA, 119753, 'CLOSURE.original.json'),
        ('inventory', INVENTORY_SHA, 563365, 'AFTER-INVENTORY.original.json')):
        row = publication['originals'][key]
        need(row['host'] == {'path': str(PUBLICATION/'originals'/filename), 'bytes': size, 'sha256': pin},
             'original host export path or exact descriptor differs')
        raw_files[key] = original(row['host'])
        need({k: row['phone'][k] for k in ('bytes', 'sha256')} == descriptor(raw_files[key]),
             'original phone descriptor does not bind actual exported bytes')
    host_raw = original(publication['publication_host_result'])
    host = strict(host_raw)
    need(host['state'] == 'ORIGINAL_HOST_CHILD_JOINED' and host['returncode'] == 0
         and host['phase'] == 'phone-external-publish' and host['automatic_retry'] is False,
         'actual original publisher host terminal differs')
    operation = original(host['stdout'])
    need(original(host['stderr']) == b'' and original(publication['publication_operation']) == operation,
         'alias and original publisher stdout bytes differ')
    envelope = strict(operation)
    need(type(envelope['actor_rc']) is int and envelope['actor_rc'] == 0
         and type(envelope['wrapper']['phone']['rc']) is int and envelope['wrapper']['phone']['rc'] == 0
         and envelope['wrapper']['phone']['stderr'] == '', 'actual publisher actor or phone failed')
    emitted = strict(envelope['wrapper']['phone']['stdout'])
    need(emitted['boundary'] == publication['boundary'] == publication['originals']['boundary']['phone']
         and emitted['state'] == 'CREATE_ONLY_EXTERNAL_LEGACY_FAILED_BOUNDARY_PUBLISHED',
         'publisher original boundary descriptor differs')
    helper = types.ModuleType('reviewed_final_consumer_native5')
    helper.__file__ = str(FC/'source/release_boundaries.py')
    exec(compile(helper_raw, helper.__file__, 'exec'), helper.__dict__)
    constructor = types.ModuleType('reviewed_native5_input_constructor')
    constructor.__file__ = str(CC/'source/make_component_boundary_inputs.py')
    exec(compile(constructor_raw, constructor.__file__, 'exec'), constructor.__dict__)
    prior_input = {
        'root_result': {'path':str(B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04/ROOT-RESULT.json'),
                        'bytes':10980,'sha256':'c92382e0841375fc0a1fb19ff0271381ac044f1dad01427342fca4e4f6e9c638'},
        'package_manifest':{'path':str(HISTORICAL_RUNTIME/'MANIFEST.json'),'bytes':5284,'sha256':HISTORICAL_RUNTIME_SHA}}
    retained_originals = []
    prior_proof, prior_value = constructor.collect_pre_policy_ancestor(helper, prior_input,
        original, retained_originals, {'package_sources':runtime_files}, combination_sha)
    environment_pool={}
    def collect_environment(row):
        body=original(row)
        item={'bytes':len(body),'raw_b64':base64.b64encode(body).decode('ascii')}
        need(row['sha256'] not in environment_pool or environment_pool[row['sha256']]==item,
             'environment original hash collision')
        environment_pool[row['sha256']]=item
        return body
    environment_input={
        'root_result':{'path':str(B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/ROOT-RESULT.json'),
            'bytes':32600,'sha256':'ed2e22f27b72951621802add6a1d68950ea94721d052b25dd5d59ebc95be5c93'},
        'package_manifest':{'path':str(ENVIRONMENT_RUNTIME/'MANIFEST.json'),'bytes':11495,'sha256':ENVIRONMENT_RUNTIME_SHA}}
    environment_originals=[]
    environment_proof,environment_value=constructor.collect_environment_parent_ancestor(
        helper,environment_input,collect_environment,environment_originals,
        {'package_sources':runtime_files},combination_sha)
    property_inputs = []
    for attempt in ('attempt08','attempt07'):
        spec = helper.property_parent_proof_spec(attempt)
        property_inputs.append({key:spec[key] for key in ('root_result','package_manifest')})
    property_originals = []
    property_proofs, property_values = constructor.collect_property_parent_ancestors(
        helper, property_inputs, collect_environment, property_originals,
        {'package_sources':runtime_files})
    with helper.component_modules({'package_sources': runtime_files}) as modules:
        late = modules['late_boundary']
        helper.validate_environment_parent_ancestor({'originals':environment_pool},
            environment_proof,{'package_sources':runtime_files},environment_value,late)
        helper.validate_property_parent_ancestors({'originals':environment_pool},
            property_proofs, {'package_sources':runtime_files}, property_values, late)
        value, inventory, closure = late.closed_boundary_originals(
            raw_files['boundary'], raw_files['inventory'], raw_files['closure'],
            original_descriptor=publication['boundary'], combination_sha256=combination_sha,
            package_sha256=package_sha)
        all_values = property_values+[environment_value, prior_value, value]
        late.require_failed_ancestor_tail(all_values)
        sidebranch = late.non_native_sidebranch()
        need(sidebranch['binding']['native_predecessor'] == prior_proof['boundary']
             and sidebranch['binding']['native_case_count'] == 0
             and sidebranch['binding']['component_qualified'] is False
             and len(sidebranch['binding']['component_role_identities']) == 3,
             'separate non-native original proof changed the fixed native predecessor')
        late.preserve_non_native_private(sidebranch['inventory'], sidebranch)
        roles = [tuple(row) for item in all_values for row in item['component_role_identities'].values()]
        roles.extend(tuple(row) for row in sidebranch['binding']['component_role_identities'].values())
        need(len(roles) == len(set(roles)) == 18 and len(roles) <= 24,
             'the exact five old failures and separate05 role identities differ')
        sidebranch_sources = {name:descriptor(runtime_files[name]) for name in
            ('reference/non_native_attempt05.py', *NON_NATIVE_REFERENCES.values())}
        need(value['schema'] == late.LEGACY_SCHEMA and value['publisher_source_sha256'] == PUBLISHER_SHA
             and value['component_qualified'] is False and closure['component_qualified'] is False,
             'actual legacy reader granted qualification or changed source identity')
    return raw, {
        'state': 'ACTUAL_FIXED_FAILED_08_THEN07_THEN06_THEN04_THEN_EXTERNAL03_TAIL_ACCEPTED_BY_EXACT_FINAL_READER',
        'property_parent_ancestors':property_proofs,
        'retained_property_parent_originals':property_originals,
        'distinct_retained_component_roles':[list(row) for row in roles],
        'historical_native_case_count':5, 'current_native_case_count':0,
        'environment_parent_ancestor':environment_proof,
        'retained_environment_parent_originals':environment_originals,
        'pre_policy_ancestor':prior_proof, 'retained_pre_policy_originals':retained_originals,
        'non_native_sidebranch':sidebranch['binding'],
        'non_native_original_references':sidebranch_sources,
        'non_native_attempt_count':1, 'non_native_case_count':0,
        'current_combination_sha256':combination_sha, 'constructor':descriptor(constructor_raw),
        'publication': descriptor(raw), 'boundary': descriptor(raw_files['boundary']),
        'closure': descriptor(raw_files['closure']), 'inventory': descriptor(raw_files['inventory']),
        'runtime_package_sha256': package_sha, 'helper': descriptor(helper_raw),
        'source_modules_evaluated': ['component_common', 'late_boundary'],
        'original_phone_descriptor_parsed_in_python': True,
        'original_publication_stdout_and_alias_bytes_equal': True,
        'original_publication_stdout_and_alias_descriptors_conflated': False,
        'phone_calls': 0, 'new_component_qualification': False}


def finalization():
    """A separately reviewed source revision must bind every actual new generation."""
    value = FINALIZATION
    need(isinstance(value, dict) and set(value) == {'schema', 'runtime_manifest',
         'component_combination', 'policy_adoption', 'policy_verifier', 'actual_policy',
         'scope_decision', 'full_rule'}
         and value['schema'] == 'hepta.property-policy.final-pin-freeze.v1',
         'new property-policy runtime, adoption, scope and rule pins are not frozen')
    for key in ('runtime_manifest', 'component_combination', 'policy_adoption',
                'policy_verifier', 'scope_decision', 'full_rule'):
        row = value[key]
        need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'}
             and isinstance(row['path'], str) and Path(row['path']).is_absolute()
             and type(row['bytes']) is int and 0 < row['bytes'] <= 16*1024*1024
             and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'explicit future original descriptor required: '+key)
    need(value['runtime_manifest']['bytes'] <= 65536
         and value['policy_verifier']['bytes'] <= 131072,
         'future manifest or verifier source exceeds its reviewed source bound')
    policy = value['actual_policy']
    need(isinstance(policy, dict) and set(policy) == {'bytes', 'sha256'}
         and type(policy['bytes']) is int and 0 < policy['bytes'] <= 16*1024*1024
         and isinstance(policy['sha256'], str) and re.fullmatch('[0-9a-f]{64}', policy['sha256'])
         and policy['sha256'] not in (POLICY_PARENT_SHA, HISTORICAL_POLICY_SHA)
         and value['policy_adoption']['sha256'] not in (PARENT_ADOPTION_SHA, HISTORICAL_ADOPTION_SHA)
         and value['runtime_manifest']['sha256'] != RUNTIME_PARENT_SHA
         and value['component_combination']['sha256'] not in (POLICY_PARENT_COMBINATION_SHA, COMBINATION_SHA)
         and value['policy_verifier']['sha256'] != PARENT_VERIFIER_SHA
         and value['scope_decision']['sha256'] != PARENT_ROOT_SCOPE_DECISION_SHA
         and value['full_rule']['sha256'] != PARENT_FULL_RULE_SHA,
         'an old policy generation or old twelve-atom rule cannot be the new current generation')
    return value


def source_templates():
    root = Path(__file__).resolve(strict=True).parent.parent/'templates'
    need(set(TEMPLATE_PINS) == set(RUNTIME_NAMES) | {
        'make_component_boundary_inputs.py', 'materialize_case_r10.py',
        'root_acceptance_r10.py', 'late_boundary.py', 'stage_component.py',
        'policy_parent_late_boundary_r4.py', 'component_common.py',
        'component_snapshot.py', 'close_component.py', 'component_common_r5.py',
        'non_native_attempt05.py', 'component_lifecycle.py',
        'environment_parent_late_boundary_r6.py', 'property_parent_late_boundary_r7.py'},
        'exact reviewed property-generation template paths required')
    return {name: read(root/name, row['sha256'], row['bytes'])
            for name, row in TEMPLATE_PINS.items()}


def reviewed_runtime(frozen, templates, parent_manifest, parent_files):
    row = frozen['runtime_manifest']
    root = Path(row['path']).parent
    need(Path(row['path']).name == 'MANIFEST.json', 'exact runtime manifest filename required')
    raw, value, files = package(root, row['sha256'], row['bytes'])
    old_rows = parent_manifest['files']
    old_names = {item['path'] for item in old_rows}
    need(old_names == set(parent_files) and len(old_names) == len(old_rows) == 31
         and OLD_READER_REFERENCE in old_names and ENVIRONMENT_PARENT_REFERENCE in old_names
         and not (old_names & R8_ADDED_PATHS) and R8_CHANGED_PATHS <= old_names,
         'actual immutable R7 path set differs')
    need(set(files) == old_names | R8_ADDED_PATHS and len(files) == 32,
         'R8 must retain all31 paths and add only the exact R7 reader reference')
    def literal(body, name):
        nodes = [n for n in ast.parse(body).body if isinstance(n, ast.Assign)
            and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
        need(len(nodes) == 1, 'one reviewed literal required: '+name)
        return ast.literal_eval(nodes[0].value), nodes[0].value
    late_raw = files['source/late_boundary.py']
    slots = {'REVIEWED_CURRENT_COMBINATION_SHA256':frozen['component_combination']['sha256'],
             'REVIEWED_CURRENT_POLICY_SHA256':frozen['actual_policy']['sha256'],
             'REVIEWED_CURRENT_POLICY_ADOPTION_SHA256':frozen['policy_adoption']['sha256']}
    expected_late = templates['late_boundary.py']; changed_lines = []
    for name, expected_value in slots.items():
        old_value, node = literal(expected_late, name)
        need(old_value is None and node.lineno == node.end_lineno,
             'one unfrozen single-line reader literal required: '+name)
        before_line = expected_late.splitlines(keepends=True)[node.lineno-1]
        code_line = before_line.split(b'#',1)[0].rstrip()
        # Exactly the reviewed R8 freezer.fill producer format. No other
        # whitespace, statement or source-body normalization is accepted.
        after_line = (name+'='+repr(expected_value)).encode('ascii')+before_line[len(code_line):]
        need(expected_late.count(before_line) == 1, 'one exact reviewed assignment line required')
        expected_late = expected_late.replace(before_line, after_line, 1)
        changed_lines.append((before_line, after_line))
    need(late_raw == expected_late,
         'actual R8 reader differs from the reviewed freezer three-literal output')
    reverse = late_raw
    for before_line, after_line in reversed(changed_lines):
        need(reverse.count(after_line) == 1, 'one exact actual assignment line required')
        reverse = reverse.replace(after_line, before_line, 1)
    need(reverse == templates['late_boundary.py'],
         'the actual three-literal reader must reverse to every reviewed template byte')
    expected = dict(parent_files)
    expected['source/late_boundary.py'] = late_raw
    expected[PROPERTY_PARENT_REFERENCE] = templates['property_parent_late_boundary_r7.py']
    need(expected[PROPERTY_PARENT_REFERENCE] == parent_files['source/late_boundary.py']
         and files == expected and len(old_names - R8_CHANGED_PATHS) == 30,
         'runtime differs beyond the reviewed current reader and one exact old R7 reference')
    for name, template_name in (
        (OLD_READER_REFERENCE, 'policy_parent_late_boundary_r4.py'),
        (ENVIRONMENT_PARENT_REFERENCE, 'environment_parent_late_boundary_r6.py'),
        ('source/stage_component.py', 'stage_component.py'),
        ('source/component_common.py', 'component_common.py'),
        ('source/component_lifecycle.py', 'component_lifecycle.py'),
        ('source/component_snapshot.py', 'component_snapshot.py'),
        ('source/close_component.py', 'close_component.py'),
        ('reference/component_common_r5.py', 'component_common_r5.py'),
        ('reference/non_native_attempt05.py', 'non_native_attempt05.py')):
        need(files[name] == templates[template_name], 'a retained source changed: '+name)
    record, _ = literal(late_raw, 'REVIEWED_NON_NATIVE_ATTEMPT05')
    old_record, _ = literal(parent_files['source/late_boundary.py'], 'REVIEWED_NON_NATIVE_ATTEMPT05')
    need(record == old_record and record['schema'] == 'hepta.native-guard.reviewed-non-native-attempt.v1'
         and record['nonce'] == 'e4c3ccb0b2d706be3b7bf105ae772405',
         'the separately published original05 record changed')
    for key, name in NON_NATIVE_REFERENCES.items():
        entry = record[key]
        need(set(entry) == {'path','bytes','sha256','metadata'}
             and descriptor(files[name]) == {k:entry[k] for k in ('bytes','sha256')}
             and files[name] == parent_files[name], 'the original05 raw reference changed')
    need(value['schema'] == 'hepta.native-guard.adapter-package.v1'
         and value['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
         and value['component_qualified'] is False and value['business_qualified'] is False
         and value['phone_calls'] == 0 and value['parent_package_sha256'] == RUNTIME_PARENT_SHA
         and value['current_combination_sha256'] == frozen['component_combination']['sha256']
         and value['current_policy_sha256'] == frozen['actual_policy']['sha256']
         and value['explicit_policy_adoption_sha256'] == frozen['policy_adoption']['sha256']
         and value['full_historical_tail_is_exact_actual08_then07_then06_then04_then_external03'] is True
         and value['retained_environment_suffix_is_exact_actual06_then04_then_external03'] is True
         and value['exact_environment_parent_ancestor']['sha256'] == ENVIRONMENT_PARENT_BOUNDARY_SHA
         and value['environment_root_observation_is_worker_qualification'] is False
         and value['android_sidecar_environment_added_keys'] == [
             'ANDROID_ART_ROOT','ANDROID_I18N_ROOT','ANDROID_TZDATA_ROOT','BOOTCLASSPATH','DEX2OATBOOTCLASSPATH'],
         'source manifest changed the old history or claimed actual worker or case qualification')
    return raw, value, files


def actual_adoption_check(frozen):
    """Recheck only an explicit new transition whose retained parent is 50f/a5f/08."""
    adoption_raw = original(frozen['policy_adoption'])
    verifier_raw = original(frozen['policy_verifier'])
    scope_raw = original(frozen['scope_decision'])
    full_rule_raw = original(frozen['full_rule'])
    original({'path':str(B/'policy-native5-r10-live-root-02/POLICY-ADOPTION.json'),
              'bytes':146368,'sha256':PARENT_ADOPTION_SHA})
    module = types.ModuleType('reviewed_property_cascade_policy_verifier')
    module.__file__ = frozen['policy_verifier']['path']
    module.__reviewed_source_sha256__ = sha(verifier_raw)
    exec(compile(verifier_raw, module.__file__, 'exec', optimize=0), module.__dict__)
    summary = module.verify_adoption(adoption_raw, read_pinned=original)
    value = strict(adoption_raw)
    actual = original(value['actual_export'])
    need(summary['current_adoption_sha256'] == frozen['policy_adoption']['sha256']
         and summary['runtime_policy'] == frozen['actual_policy'] == descriptor(actual)
         and summary['prior_boundary_sha256'] == PROPERTY_PARENT_BOUNDARY_SHAS[0]
         and summary['root_scope_decision_sha256'] == sha(scope_raw)
         and summary['parent_adoption_sha256'] == PARENT_ADOPTION_SHA
         and summary['parent_policy'] == {'bytes':2667608,'sha256':POLICY_PARENT_SHA},
         'actual current adoption must retain exact50f/a5f/08, never the older296b/7899/04 transition')
    verifier_rows = [r for r in value['verification_originals']
                    if {k:r[k] for k in ('bytes','sha256')} == descriptor(verifier_raw)]
    need(len(verifier_rows) == 1 and original(verifier_rows[0]) == verifier_raw,
         'adoption must retain the same exact reviewed new verifier original')
    need(summary['full_rule'] == value['full_rule'] == frozen['full_rule']
         and original(value['full_rule']) == full_rule_raw
         and sha(full_rule_raw) != PARENT_FULL_RULE_SHA,
         'the full rule must be the explicitly reviewed new original, not the old Native5 rule')
    combo_raw = original(frozen['component_combination'])
    combo = strict(combo_raw)
    parent_raw = read(RUNTIME_PARENT.parent/'COMBINATION.json', POLICY_PARENT_COMBINATION_SHA, 4702)
    parent_combo = strict(parent_raw)
    reversed_combo = copy.deepcopy(combo)
    reversed_combo['live_policy_sha256'] = POLICY_PARENT_SHA
    need(combination_encode(parent_combo) == parent_raw and combination_encode(combo) == combo_raw
         and combination_encode(reversed_combo) == parent_raw
         and combo['schema'] == 'hepta.native-guard.component-combination.v150.r10.1'
         and sha(combo_raw) != POLICY_PARENT_COMBINATION_SHA
         and combo['live_policy_sha256'] == frozen['actual_policy']['sha256']
         and combo['configuration']['sha256'] == SHARED_CONFIGURATION_SHA
         and combo['service_inputs']['sha256'] == SHARED_SERVICE_SHA,
         'only the actual current policy pin may change in the retained R7 combination')
    return adoption_raw, combo_raw, summary


def finalized_sources(templates, frozen, runtime_files):
    names = (*RUNTIME_NAMES, 'make_component_boundary_inputs.py',
             'materialize_case_r10.py', 'root_acceptance_r10.py')
    final = {name:templates[name] for name in names}
    changes = {name:[] for name in names}
    def bind(name, before, after):
        final[name] = replace(final[name], before, after)
        changes[name].append((before.encode(), after.encode()))
    helper_pins = {
        'PACKAGE_SHA':frozen['runtime_manifest']['sha256'],
        'CURRENT_COMBINATION_SHA':frozen['component_combination']['sha256'],
        'POLICY_VERIFIER_SHA':frozen['policy_verifier']['sha256'],
        'POLICY_VERIFIER_BYTES':frozen['policy_verifier']['bytes'],
        'CURRENT_POLICY_SHA':frozen['actual_policy']['sha256'],
        'CURRENT_POLICY_ADOPTION_SHA':frozen['policy_adoption']['sha256'],
        'CURRENT_SCOPE_DECISION_SHA':frozen['scope_decision']['sha256']}
    counts = [ast.literal_eval(n.value) for n in ast.parse(final['release_boundaries.py']).body
        if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'PACKAGE_FILE_COUNT']
    need(counts == [32] and len(runtime_files) == 32, 'exact32 runtime source container required')
    for name, value in helper_pins.items():
        bind('release_boundaries.py', name+' = None\n', name+' = '+repr(value)+'\n')
    helper = final['release_boundaries.py']; helper_sha = sha(helper)
    need(0 < len(helper) <= 131072, 'exact final helper exceeds its separately reviewed source bound')
    bind('collect_r10_readiness.py',
        'BOUNDARY_CONSUMER_SHA256=None\n', 'BOUNDARY_CONSUMER_SHA256='+repr(helper_sha)+'\n')
    bind('install_phone_release_r10.py',
        'BOUNDARY_CONSUMER_SHA256 = None\n', 'BOUNDARY_CONSUMER_SHA256 = '+repr(helper_sha)+'\n')
    bind('component_activation_gate.fragment.py',
        '    reviewed_component_package_sha256 = None\n',
        '    reviewed_component_package_sha256 = '+repr(frozen['runtime_manifest']['sha256'])+'\n')
    for name, digest in [('BOUNDARY_CONSUMER_SHA256', helper_sha),
        ('READINESS_SOURCE_SHA256', sha(final['collect_r10_readiness.py'])),
        ('COMPONENT_FRAGMENT_SHA256', sha(final['component_activation_gate.fragment.py']))]:
        bind('build_release_r10.py', name+'=None\n', name+'='+repr(digest)+'\n')
    bind('make_component_boundary_inputs.py', 'HELPER = None\n',
         'HELPER = Path('+repr(str(FC/'source/release_boundaries.py'))+')\n')
    for name, value in [('HELPER_SHA', helper_sha), ('HELPER_BYTES', len(helper)),
                        ('PACKAGE_SHA', frozen['runtime_manifest']['sha256'])]:
        bind('make_component_boundary_inputs.py', name+' = None\n', name+' = '+repr(value)+'\n')
    bind('root_acceptance_r10.py', 'READINESS_SHA=None\n',
         'READINESS_SHA='+repr(sha(final['collect_r10_readiness.py']))+'\n')
    for name, body in final.items():
        reverse = body
        for before, after in reversed(changes[name]):
            need(reverse.count(after) == 1, 'one exact inverse source literal required')
            reverse = reverse.replace(after, before, 1)
        need(reverse == templates[name], 'all finalized literals must reverse to the complete reviewed template')
        ast.parse(body); compile(body, name, 'exec')
    return final


def module_input_replacement(formal, original_formal_raw):
    """Retain the already adopted R7 sidecar row; no second replacement occurs."""
    row = REVIEWED_MODULE_INPUT_REPLACEMENT
    need(row == {'path':str(B/'module-sidecar-android-environment-r7-candidate01/MODULE-INPUT-REPLACEMENT.json'),
         'bytes':5897,'sha256':'223801205cfaba915c88b76fb291f888043c0f75fe0ae22be10ff13b19931374'},
         'the fixed already adopted R7 module history differs')
    raw = original(row); value = strict(raw)
    need(value['schema'] == 'hepta.r7.module-sidecar-source-input-replacement.v1'
         and value['state'] == 'REVIEW_REQUIRED_NOT_ADOPTED_IN_FINAL_INPUTS'
         and value['module_source_name'] == 'launch-sidecar.sh'
         and value['parent_formal_inputs']['path'] == str(
             B/'r10-boundary-consumers-final-r6/inputs/FINAL-INTEGRATION-INPUTS.json')
         and value['automatic_application_to_formal_inputs'] is False
         and all(value[k] is False for k in ('artifact_bytes_changed','current_combination_changed',
             'policy_or_adoption_changed','production_sources_changed','shared17_changed')),
         'original R7 module replacement provenance differs')
    rows = formal['module_sources']
    need(len(rows) == 14 and len({r['name'] for r in rows}) == 14,
         'exact fourteen retained module source rows required')
    selected = [r for r in rows if r['name'] == 'launch-sidecar.sh']
    need(len(selected) == 1 and selected[0] == value['candidate_module_source']
         and [r for r in rows if r['name'] != 'launch-sidecar.sh'] ==
             value['other_thirteen_module_source_rows_unchanged']
         and strict(original_formal_raw)['module_sources'] == rows,
         'the actual parent must already contain the adopted R7 row and unchanged other13')
    old = value['original_module_source']; new = value['candidate_module_source']
    need(set(old) == set(new) == {'name','path','bytes','sha256'}
         and old['name'] == new['name'] == 'launch-sidecar.sh'
         and old['bytes'] == 360 and old['sha256'] == '5da0ade34a0294c73da935487e5617ec46959f152804f49f754bb546bb3f9fa2'
         and new['bytes'] == 7827 and new['sha256'] == 'f54a19c86386c93c51cbc7583c956b6f0bcbd746a811164e55506cdc9e8f54d3',
         'the retained module source is not the reviewed single-file environment increment')
    for entry in (old, new):
        original({k:entry[k] for k in ('path','bytes','sha256')})
    return raw, value

def derive(args):
    frozen = finalization()  # No filesystem access or source loading before this gate.
    os.umask(0o077)
    for path in (FC, AC, CC):
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ValueError('create-only final output already exists: '+str(path))
    templates = source_templates()
    runtime_parent_raw, runtime_parent, runtime_parent_files = package(
        RUNTIME_PARENT, RUNTIME_PARENT_SHA, 13446)
    runtime_raw, runtime, runtime_files = reviewed_runtime(
        frozen, templates, runtime_parent, runtime_parent_files)
    fc_raw, fc_value, fc_parent = package(FC_PARENT, FC_PARENT_SHA, 17923)
    ac_raw, ac_value, ac_parent = package(AC_PARENT, AC_PARENT_SHA, 19044)
    cc_raw, cc_value, cc_parent = package(CC_PARENT, CC_PARENT_SHA, 4307)
    adoption_raw, combo_raw, policy_summary = actual_adoption_check(frozen)
    final = finalized_sources(templates, frozen, runtime_files)
    h = final['release_boundaries.py']; hs = sha(h)
    publication_raw, tail_result = actual_tail_check(h,
        final['make_component_boundary_inputs.py'], runtime_files,
        frozen['runtime_manifest']['sha256'], frozen['component_combination']['sha256'])
    checks = {'schema':'hepta.property-policy.final-source-original-checks.v1',
        'actual_policy_adoption':policy_summary, 'actual_tail':tail_result,
        'runtime_exact_paths':sorted(runtime_files), 'runtime_file_count':len(runtime_files),
        'property_parent_ancestors':tail_result['property_parent_ancestors'],
        'property_parent_boundary_sha256':PROPERTY_PARENT_BOUNDARY_SHAS[0],
        'property_parent_failed_ancestor_count':2,
        'historical_native_failed_case_count':5,
        'environment_parent_ancestor':tail_result['environment_parent_ancestor'],
        'environment_parent_ancestor_sha256':ENVIRONMENT_PARENT_BOUNDARY_SHA,
        'non_native_sidebranch':tail_result['non_native_sidebranch'],
        'non_native_attempt_count':1, 'non_native_case_count':0,
        'non_native_roles_in_component_activation':True,
        'original_parent_policy_is_migration_baseline':True,
        'old_ancestors_component_credit':False, 'current_case_credit':False,
        'actual_complete_component_and_policy_union_bytes':None,
        'exact_boundary_member_maximum_bytes':32*1024*1024,
        'capacity_pending_actual_current_component_originals':True,
        'exact_current_policy_parent':{'bytes':2667608,'sha256':POLICY_PARENT_SHA},
        'scope_decision':frozen['scope_decision'], 'full_rule':frozen['full_rule'],
        'phone_calls':0, 'case_or_nonce_generated':False}
    checks_raw = encode(checks)
    finalized_pin_diff = difference({'source/'+n:templates[n] for n in final},
                                   {'source/'+n:body for n,body in final.items()}, 'final-property-policy')

    fc = dict(fc_parent)
    for name in RUNTIME_NAMES:
        fc['source/'+name] = final[name]
    formal = strict(fc_parent['inputs/FINAL-INTEGRATION-INPUTS.json'])
    before_formal = copy.deepcopy(formal)
    selected = [r for r in formal['provider_helpers'] if r['name'] == 'collect_r10_readiness.py']
    need(len(selected) == 1 and selected[0]['sha256'] == FROZEN_READINESS_SHA,
         'formal parent readiness differs')
    selected[0].update(path=str(FC/'source/collect_r10_readiness.py'),
                       **descriptor(final['collect_r10_readiness.py']))
    module_replacement_raw,module_replacement = module_input_replacement(
        formal,fc_parent['inputs/FINAL-INTEGRATION-INPUTS.json'])
    restored = copy.deepcopy(formal)
    next(r for r in restored['provider_helpers'] if r['name'] == 'collect_r10_readiness.py').update(
        next(r for r in before_formal['provider_helpers'] if r['name'] == 'collect_r10_readiness.py'))
    need(restored == before_formal,
         'formal input changed beyond readiness; all14 module sources must remain byte-identical')
    fc['inputs/FINAL-INTEGRATION-INPUTS.json'] = encode(formal)
    need(fc['reference/MODULE-INPUT-REPLACEMENT.original.json'] == module_replacement_raw
         and fc['MODULE-SOURCE-ONLY-INCREMENT.patch'] == fc_parent['MODULE-SOURCE-ONLY-INCREMENT.patch'],
         'the original R7 module adoption and its source patch must be preserved, not reapplied')
    fc['reference/PARENT-FC7-MANIFEST.original.json'] = fc_raw
    fc['reference/PARENT-R7-RUNTIME-MANIFEST.original.json'] = runtime_parent_raw
    fc['reference/REVIEWED-CURRENT-RUNTIME-MANIFEST.original.json'] = runtime_raw
    fc['reference/REVIEWED-R8-PROPERTY-CANDIDATE.original.py'] = templates['release_boundaries.py']
    fc['reference/ACTUAL-PROPERTY-POLICY-ADOPTION.original.json'] = adoption_raw
    fc['reference/ACTUAL-CURRENT-COMBINATION.original.json'] = combo_raw
    fc['reference/ACTUAL-EXTERNAL03-PUBLICATION.original.json'] = publication_raw
    fc['reference/ROOT-REVIEWED-FINALIZATION.json'] = encode(frozen)
    fc['PIN-CASCADE-INCREMENT.patch'] = difference(fc_parent, fc, 'final-r8')
    fc['FINAL-R8-PIN-ONLY-INCREMENT.patch'] = finalized_pin_diff
    fc['validation/ACTUAL-POLICY-AND-TAIL-RECHECK.json'] = checks_raw
    fc['FINAL-INPUT-PROVENANCE.json'] = encode({
        'schema':'hepta.r10.final-input-pin-cascade.v8', 'parent_manifest_sha256':FC_PARENT_SHA,
        'component_package':frozen['runtime_manifest'], 'actual_new_adoption':frozen['policy_adoption'],
        'pre_policy_ancestor_sha256':PRE_POLICY_BOUNDARY_SHA, 'external_ancestor_sha256':BOUNDARY_SHA,
        'integration_input':descriptor(fc['inputs/FINAL-INTEGRATION-INPUTS.json']),
        'integration_input_changes':['provider_helpers/collect_r10_readiness.py exact descriptor'],
        'all_fourteen_module_source_rows_unchanged':True,
        'module_input_replacement':REVIEWED_MODULE_INPUT_REPLACEMENT,
        'module_replacement_reapplied':False,
        'builder_rule_change':'sha of consumer-verified complete full_rule bytes',
        'builder_activation_package':'manifest SHA from the consumer-verified component_input',
        'property_parent_ancestors':tail_result['property_parent_ancestors'],
        'property_parent_boundary_sha256':PROPERTY_PARENT_BOUNDARY_SHAS[0],
        'property_parent_failed_ancestor_count':2,
        'historical_native_failed_case_count':5,
        'environment_parent_ancestor':tail_result['environment_parent_ancestor'],
        'environment_parent_ancestor_sha256':ENVIRONMENT_PARENT_BOUNDARY_SHA,
        'non_native_sidebranch':tail_result['non_native_sidebranch'],
        'non_native_case_count':0,
        'original_migration_parent_policy_unchanged':True, 'actual_shared17_unchanged':True,
        'actual_complete_component_and_policy_union_bytes':None,
        'exact_boundary_member_maximum_bytes':32*1024*1024,
        'final_seal_generated':False, 'phone_calls':0})
    add_manifest(fc, {'schema':'hepta.r10.final-boundary-consumers.v8',
        'state':'HOST_SOURCE_READY_WAITING_ACTUAL_CURRENT_COMPONENT_ORIGINALS',
        'parent_manifest_sha256':FC_PARENT_SHA,
        'component_package_sha256':frozen['runtime_manifest']['sha256'],
        'actual_policy_adoption_sha256':frozen['policy_adoption']['sha256'],
        'pre_policy_ancestor_sha256':PRE_POLICY_BOUNDARY_SHA, 'external_ancestor_sha256':BOUNDARY_SHA,
        'component_input_schema':'hepta.r10.component-boundary-inputs.v5',
        'property_parent_ancestors':tail_result['property_parent_ancestors'],
        'property_parent_boundary_sha256':PROPERTY_PARENT_BOUNDARY_SHAS[0],
        'property_parent_failed_ancestor_count':2,
        'historical_native_failed_case_count':5,
        'environment_parent_ancestor':tail_result['environment_parent_ancestor'],
        'environment_parent_ancestor_sha256':ENVIRONMENT_PARENT_BOUNDARY_SHA,
        'non_native_sidebranch':tail_result['non_native_sidebranch'],
        'non_native_case_count':0,
        'actual_original_checks':descriptor(checks_raw), 'old_tests_reexecuted':False,
        'actual_complete_component_and_policy_union_bytes':None,
        'exact_boundary_member_maximum_bytes':32*1024*1024,
        'phone_calls':0, 'new_component_qualification':False})

    ac = dict(ac_parent)
    need(final['materialize_case_r10.py'] == ac_parent['operator/materialize_case_r10.py'],
         'unchanged exact-boundary materializer must remain byte identical')
    ac['operator-chain/root_acceptance_r10.py'] = final['root_acceptance_r10.py']
    for name in UNCHANGED_CHAIN:
        need(ac['operator-chain/'+name] == ac_parent['operator-chain/'+name],
             'unrelated acceptance source changed')
    ac['reference-readiness-r8/MANIFEST.original.json'] = ac_raw
    ac['reference-readiness-r8/SOURCE-MANIFEST.original.json'] = ac_parent['operator-chain/SOURCE-MANIFEST.json']
    ac['reference-readiness-r8/root_acceptance_r10.original.py'] = ac_parent['operator-chain/root_acceptance_r10.py']
    ac['R9-R8-PROPERTY-READINESS-INCREMENT.patch'] = difference(ac_parent, ac, 'readiness-r9')
    source_manifest = strict(ac_parent['operator-chain/SOURCE-MANIFEST.json'])
    for row in source_manifest['files']:
        row.update(descriptor(ac['operator-chain/'+row['path']]))
    source_manifest['reviewed_readiness_helper_sha256'] = sha(final['collect_r10_readiness.py'])
    source_manifest['parent_operator_manifest_sha256'] = sha(ac_parent['operator-chain/SOURCE-MANIFEST.json'])
    ac['operator-chain/SOURCE-MANIFEST.json'] = encode(source_manifest)
    ac['READINESS-R9-FINAL.json'] = encode({
        'schema':'hepta.r10.scoped-acceptance-readiness-increment.v9',
        'parent_package_sha256':AC_PARENT_SHA,
        'component_package_sha256':frozen['runtime_manifest']['sha256'],
        'final_consumer_manifest_sha256':sha(fc['MANIFEST.json']),
        'final_readiness_helper':descriptor(final['collect_r10_readiness.py']),
        'materializer':descriptor(final['materialize_case_r10.py']),
        'exact_boundary_member_maximum_bytes':32*1024*1024,
        'all_other_module_member_maximum_bytes':8*1024*1024,
        'six_release_pin_capture_gate_unchanged':True,
        'materializer_and_other_five_sources_byte_exact':True,
        'actual_complete_component_and_policy_union_bytes':None,
        'old_tests_not_relabelled_or_rerun':True,
        'phone_calls':0, 'actual_final_release_generated':False})
    ac_manifest = copy.deepcopy(ac_value); ac_manifest.pop('files')
    ac_manifest['operator_manifest_sha256'] = sha(ac['operator-chain/SOURCE-MANIFEST.json'])
    ac_manifest['derivation'].update(parent_readiness_r8_package_sha256=AC_PARENT_SHA,
        component_package_sha256=frozen['runtime_manifest']['sha256'],
        final_consumer_manifest_sha256=sha(fc['MANIFEST.json']),
        final_readiness_helper_sha256=sha(final['collect_r10_readiness.py']),
        materializer_exact_boundary_maximum_bytes=32*1024*1024)
    add_manifest(ac, ac_manifest)

    cc = dict(cc_parent)
    cc['source/make_component_boundary_inputs.py'] = final['make_component_boundary_inputs.py']
    cc['reference/PARENT-C7-MANIFEST.original.json'] = cc_raw
    cc['reference/PARENT-C7-SOURCE.original.py'] = cc_parent['source/make_component_boundary_inputs.py']
    cc['reference/REVIEWED-R8-CONSTRUCTOR-CANDIDATE.original.py'] = templates['make_component_boundary_inputs.py']
    cc['reference/REVIEWED-CURRENT-RUNTIME-MANIFEST.original.json'] = runtime_raw
    cc['PIN-CASCADE-INCREMENT.patch'] = difference(cc_parent, cc, 'constructor-r8')
    cc['DERIVATION.json'] = encode({
        'schema':'hepta.r10.component-input-constructor-pin-cascade.v8',
        'parent_manifest_sha256':CC_PARENT_SHA,
        'source':descriptor(final['make_component_boundary_inputs.py']),
        'boundary_consumer':descriptor(h),
        'component_package_sha256':frozen['runtime_manifest']['sha256'],
        'pre_policy_ancestor_sha256':PRE_POLICY_BOUNDARY_SHA, 'external_ancestor_sha256':BOUNDARY_SHA,
        'plan_schema':'hepta.r10.component-boundary-construction-plan.v6',
        'output_schema':'hepta.r10.component-boundary-inputs.v5',
        'actual_new_case_inputs_still_required':True,
        'old_failed_tail_counts_as_new_case_credit':False,
        'property_parent_ancestors':tail_result['property_parent_ancestors'],
        'property_parent_boundary_sha256':PROPERTY_PARENT_BOUNDARY_SHAS[0],
        'property_parent_failed_ancestor_count':2,
        'historical_native_failed_case_count':5,
        'environment_parent_ancestor':tail_result['environment_parent_ancestor'],
        'environment_parent_ancestor_sha256':ENVIRONMENT_PARENT_BOUNDARY_SHA,
        'non_native_sidebranch':tail_result['non_native_sidebranch'],
        'non_native_case_count':0, 'phone_calls':0, 'real_case_inputs_created':False})
    add_manifest(cc, {'schema':'hepta.r10.component-boundary-input-entry.v8',
        'state':'HOST_SOURCE_ONLY_WAITING_ACTUAL_CURRENT_COMPONENT_ORIGINALS',
        'component_package_sha256':frozen['runtime_manifest']['sha256'],
        'boundary_consumer_sha256':hs,
        'plan_schema':'hepta.r10.component-boundary-construction-plan.v6',
        'output_schema':'hepta.r10.component-boundary-inputs.v5',
        'phone_calls':0, 'real_case_inputs_created':False})
    recheck()
    publish(FC, fc); publish(AC, ac); publish(CC, cc)
    result = {'schema':'hepta.property-policy.final-boundary-cascade-delivery.v1', 'state':'HOST_ONLY_PUBLISHED',
        'reviewed_finalization':frozen,
        'policy_parent_sha256':POLICY_PARENT_SHA,
        'parent_adoption_sha256':PARENT_ADOPTION_SHA,
        'root_scope_decision':frozen['scope_decision'], 'full_rule':frozen['full_rule'],
        'module_replacement_reapplied':False,
        'module_input_replacement':REVIEWED_MODULE_INPUT_REPLACEMENT,
        'property_parent_ancestors':tail_result['property_parent_ancestors'],
        'property_parent_boundary_sha256':PROPERTY_PARENT_BOUNDARY_SHAS[0],
        'property_parent_failed_ancestor_count':2,
        'historical_native_failed_case_count':5,
        'environment_parent_ancestor':tail_result['environment_parent_ancestor'],
        'environment_parent_ancestor_sha256':ENVIRONMENT_PARENT_BOUNDARY_SHA,
        'non_native_sidebranch':tail_result['non_native_sidebranch'],
        'non_native_attempt_count':1, 'non_native_case_count':0,
        'pre_policy_ancestor_sha256':PRE_POLICY_BOUNDARY_SHA, 'external_ancestor_sha256':BOUNDARY_SHA,
        'consumer':dict(path=str(FC/'MANIFEST.json'), **descriptor(fc['MANIFEST.json'])),
        'acceptance':dict(path=str(AC/'MANIFEST.json'), **descriptor(ac['MANIFEST.json'])),
        'operator_manifest':dict(path=str(AC/'operator-chain/SOURCE-MANIFEST.json'), **descriptor(ac['operator-chain/SOURCE-MANIFEST.json'])),
        'constructor':dict(path=str(CC/'MANIFEST.json'), **descriptor(cc['MANIFEST.json'])),
        'formal_input':dict(path=str(FC/'inputs/FINAL-INTEGRATION-INPUTS.json'), **descriptor(fc['inputs/FINAL-INTEGRATION-INPUTS.json'])),
        'runtime_sources':{name:descriptor(final[name]) for name in RUNTIME_NAMES},
        'constructor_source':descriptor(final['make_component_boundary_inputs.py']),
        'materializer':descriptor(final['materialize_case_r10.py']),
        'core':descriptor(final['root_acceptance_r10.py']), 'actual_original_checks':descriptor(checks_raw),
        'actual_complete_component_and_policy_union_bytes':None,
        'exact_boundary_member_maximum_bytes':32*1024*1024,
        'old_tests_reexecuted_or_relabelled':False, 'new_component_qualification':False,
        'phone_calls':0, 'nonce_generated':False, 'final_release_generated':False}
    raw = encode(result)
    put(FC/'DELIVERY-RESULT.json', raw)
    print(json.dumps(dict(path=str(FC/'DELIVERY-RESULT.json'), **descriptor(raw), result=result), sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-host-cascade-once', action='store_true')
    args = parser.parse_args()
    if not args.execute_host_cascade_once:
        print(json.dumps({'state':'PROPERTY_POLICY_FINAL_CASCADE_PREVIEW_NO_IO', 'phone_calls':0,
            'host_reads':0, 'host_writes':0, 'future_pins_frozen':False,
            'final_release_generated':False}, sort_keys=True))
        return 0
    derive(args)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
