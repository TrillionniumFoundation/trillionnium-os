#!/usr/bin/env python3
"""Assemble v36-r2 on Pocket4 using cached runtimes and the existing key only.

This runner never invokes adb, contacts a phone, downloads dependencies, creates
a signing key, or edits source files. The original assembler may create its
empty source/keys directory; no file is permitted there. Outputs are exclusive.
"""
import sys
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path('/home/alex/razr-background-bff66-20261110/v36-r2')
SOURCE = ROOT / 'source'
OUT = ROOT / 'out'
COMMIT = '1af05baf1e5313a0f5f7eb65107fb3bee305d65b'
VERSION_CODE = 36
VERSION_NAME = '0.36.0-local-background-display'
INVENTORY_SHA256 = '0c0a493f424168860535f4585585633af2556f7b56a91ac10b88319df2de3f7b'
SOURCE_FILE_COUNT = 434
ARCHIVE_BYTES = 355230
ARCHIVE_SHA256 = 'e2786c8059157fd3232a0508abc7fa83f008a9b94562e72e7e15c7d94b1cec2c'
COMPILER_INPUT_COUNT = 167
SIGNER_PROOF = Path('/home/alex/hepta-v35-task-authorization-e59-r1/SIGNER-PROOF.json')
SIGNER_PROOF_SHA256 = '97e3aba44ec7a303a935965c1d608692ac06007a33bb859fec481486c1a239fe'
CERT = '202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5'
JDK_PROOF = Path('/home/alex/hepta-v31-nanbeige42-e59-r1/toolchains/old-jdk17-revalidation-r1/RESULT.json')
JDK_PROOF_SHA256 = '349939390c8b19e8cea03e28ce6c5bc2c1d010dd06d3a435b7f1517221f0dd1c'
MEMBERS = {'out/base.apk', 'out/dex/classes.dex', 'out/libhepta_local_runner.so',
           'out/mac-build-receipt.json', 'out/worker-appuid.c', 'out/native-sha256-disassembly.txt'}
HOST_NAMES = '''java-compile ActionFreshnessHostTest AppCatalogueHostTest BudgetHostTest CompactEvidenceHostTest CompactSequenceHostTest CompactTaskHistoryHostTest DiagnosticStartupGateHostTest DispatchedActionSequenceHostTest Gemma4ProfileHostTest ImeObservationHostTest Lfm25MoeProfileHostTest LocalPolicyHostTest MemoryAvailabilityHostTest MobiMindContractHostTest MobiMindSessionContractHostTest MobileAgentProfilesHostTest ModelProfileHostTest Nanbeige42ProfileHostTest ObservationStabilityHostTest ObservedAppLabelsHostTest ObservedChildTextHostTest ObservedScrollActionsHostTest ObservedTargetLabelsHostTest ObservedTextProjectionHostTest ObservedTransitionProjectionHostTest ObservedWindowMetadataHostTest PersistentActionPolicyHostTest PromptActionDomainHostTest PromptCapabilityProjectionHostTest Qwen35ProfileHostTest ReadableActionHistoryHostTest RecentActionProjectionHostTest RecoveryAcknowledgementHostTest RecoveryDispatchHostTest RecoverySlotHandoffHostTest RepeatActionGuardHostTest RepeatClickProjectionHostTest SameStateNoEffectGuardHostTest ScrollGrammarHostTest SessionRecoveryHostTest UiVenusContractHostTest UiVenusInputContractHostTest UiVenusProcessContractHostTest UiVenusRequestContractHostTest UiVenusSessionContractHostTest WarmProcessSessionHostTest ActionDecisionHostTest DecisionGrammarHostTest grammar-recognition app-label-grammar-recognition scroll-grammar-recognition completion-protocol same-state-no-effect-grammar background-client qualification-scope owner-authorization owner-grammar background-broker python-tools mobimind-private-staging ui-venus-q4_0-provenance lfm25_profile_contract-compile lfm25_profile_contract mobile_agent_profiles_contract-compile mobile_agent_profiles_contract model_profile_contract-compile model_profile_contract nanbeige42_profile_contract-compile nanbeige42_profile_contract parent_death_contract-compile parent_death_contract phase_timing_contract-compile phase_timing_contract prompt_budget_contract-compile prompt_budget_contract publish_contract-compile publish_contract qwen35_profile_contract-compile qwen35_profile_contract sha256_probe-compile sha256_probe sha256-hashlib-differential native-adapter-syntax private-prompt-evidence task-worker-native-lifecycle profile-sampler'''.split()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            value.update(chunk)
    return value.hexdigest()


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Independent regular file required: ' + str(path))
    return info


def put(path, content):
    with path.open('xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(path, value):
    put(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def read_json(path):
    regular(path)
    return json.loads(path.read_text())


def source_check():
    path = ROOT / 'SOURCE-INVENTORY.json'
    regular(path)
    if sha(path) != INVENTORY_SHA256:
        raise RuntimeError('Pinned complete source inventory changed')
    inventory = read_json(path)
    if len(inventory) != SOURCE_FILE_COUNT:
        raise RuntimeError('Complete source file count differs')
    actual = []
    if SOURCE.is_symlink() or not SOURCE.is_dir():
        raise RuntimeError('Source directory must be real')
    for member in sorted(SOURCE.rglob('*')):
        if member.is_symlink():
            raise RuntimeError('Linked source member: ' + str(member))
        if member.is_dir():
            continue
        info = regular(member)
        actual.append({'path': str(member.relative_to(SOURCE)), 'size': info.st_size, 'sha256': sha(member)})
    if actual != inventory:
        raise RuntimeError('Complete source file membership or content changed')
    keys = SOURCE / 'keys'
    if keys.exists() and (not keys.is_dir() or any(keys.iterdir())):
        raise RuntimeError('Assembler source/keys must remain an empty directory')
    manifest = ET.fromstring((SOURCE / 'AndroidManifest.xml').read_bytes())
    android = '{http://schemas.android.com/apk/res/android}'
    if (manifest.get('package'), manifest.get(android + 'versionCode'), manifest.get(android + 'versionName')) != (
            'org.trillionnium.hepta.local', str(VERSION_CODE), VERSION_NAME):
        raise RuntimeError('Pinned manifest identity differs')
    return inventory


def qualify_host():
    stage_path = ROOT / 'STAGE-RESULT.json'
    stage = read_json(stage_path)
    if (stage.get('schema') != 'hepta.background-host-stage.v1' or stage.get('host') != 'pocket4'
            or stage.get('source_commit') != COMMIT or stage.get('all_pass') is not True
            or stage.get('source_file_count') != SOURCE_FILE_COUNT or stage.get('host_check_records') != 87
            or stage.get('java8_release_gate') is not True or stage.get('phone_contacted') is not False
            or stage.get('phone_tested') is not False or stage.get('installed_on_phone') is not False):
        raise RuntimeError('Actual v36-r2 Pocket4 host stage is not qualified')
    steps = stage.get('steps', [])
    if len(steps) != 1 or steps[0].get('name') != 'full-host-checks' or type(steps[0].get('exit_code')) is not int or steps[0]['exit_code'] != 0:
        raise RuntimeError('Original full host stage receipt incomplete')
    for suffix in ('stdout', 'stderr'):
        path = ROOT / ('full-host-checks.' + suffix)
        regular(path)
        if sha(path) != steps[0][suffix + '_sha256']:
            raise RuntimeError('Original stage log changed')
    full_path = ROOT / 'host-checks/HOST-CHECKS.json'
    full = read_json(full_path)
    if full.get('schema') != 'hepta.host-checks.v3' or full.get('scope') != 'host_only' or full.get('all_pass') is not True:
        raise RuntimeError('Actual complete host gate did not pass')
    checks = full.get('checks', [])
    if len(HOST_NAMES) != 87 or [row.get('name') for row in checks] != HOST_NAMES:
        raise RuntimeError('Original 87 host check names/order differ')
    for row in checks:
        if type(row.get('exit_code')) is not int or row['exit_code'] != 0:
            raise RuntimeError('Nonzero or malformed host check result')
        for suffix in ('stdout', 'stderr'):
            path = ROOT / 'host-checks' / (row['name'] + '.' + suffix)
            regular(path)
            if sha(path) != row[suffix + '_sha256']:
                raise RuntimeError('Host log changed: ' + row['name'])
    paths = set(SOURCE.glob('*.py'))
    for directory, extensions in (('src', ('*.java',)), ('tests', ('*.java', '*.py')),
                                  ('native', ('*.c', '*.h', '*.inc', '*.py')), ('tools', ('*.py',))):
        for extension in extensions:
            paths.update((SOURCE / directory).rglob(extension))
    inputs = [{'path': str(path.relative_to(SOURCE)), 'sha256': sha(path)} for path in sorted(paths)]
    if full.get('source_inputs') != inputs:
        raise RuntimeError('Host gate inputs differ from exact current source')
    return {'stage_result_sha256': sha(stage_path), 'host_checks_sha256': sha(full_path),
            'host_check_records': len(checks), 'host_input_count': len(inputs),
            'java_home': stage['java_home']}


def existing_signer_and_jdk():
    if sha(SIGNER_PROOF) != SIGNER_PROOF_SHA256:
        raise RuntimeError('Existing public signer proof changed')
    signer = read_json(SIGNER_PROOF)
    if signer.get('public_certificate_sha256') != CERT or signer.get('new_key_created') is not False:
        raise RuntimeError('Existing signer identity differs')
    key = Path(signer['key_path'])
    if not key.is_absolute():
        raise RuntimeError('Existing signing key path must be absolute')
    def key_metadata():
        for path in (key, *key.parents):
            if path.is_symlink():
                raise RuntimeError('Existing signer path is linked')
        info = regular(key)
        return dict(bytes=info.st_size, device=info.st_dev, inode=info.st_ino,
                    mode=oct(stat.S_IMODE(info.st_mode)), mtime_ns=info.st_mtime_ns, uid=info.st_uid)
    if key_metadata() != signer['key_metadata']:
        raise RuntimeError('Existing signer metadata changed')
    if sha(JDK_PROOF) != JDK_PROOF_SHA256:
        raise RuntimeError('Qualified complete JDK receipt changed')
    jdk = read_json(JDK_PROOF)
    home = Path(jdk['java_home'])
    if jdk['status'] != 'ready' or jdk['release8_positive_exit'] != 0 or jdk['release8_negative_exit'] == 0:
        raise RuntimeError('Qualified JDK release 8 evidence missing')
    for name, pin in jdk['member_pins'].items():
        path = home / name
        if path.is_symlink() or path.stat().st_size != pin['bytes'] or sha(path) != pin['sha256']:
            raise RuntimeError('Qualified JDK member changed: ' + name)
    return key, key_metadata, signer['key_metadata'], home


def load_identity():
    spec = importlib.util.spec_from_file_location('actual_v36_build_identity', SOURCE / 'tools/build_identity.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract(identity, report_dir):
    archive = ROOT / 'mac-artifacts.tar.gz'
    info = regular(archive)
    if info.st_size != ARCHIVE_BYTES or sha(archive) != ARCHIVE_SHA256:
        raise RuntimeError('Actual Mac transfer archive differs')
    if OUT.exists() or OUT.is_symlink():
        raise RuntimeError('Fresh absent output directory required')
    blobs = {}
    with tarfile.open(archive, 'r:gz') as packed:
        for member in packed.getmembers():
            name = PurePosixPath(member.name)
            if (member.name not in MEMBERS or member.name in blobs or not member.isfile()
                    or member.size < 0 or member.size > 16 * 1024**2 or name.is_absolute() or '..' in name.parts):
                raise RuntimeError('Unsafe or duplicate compiled archive member')
            stream = packed.extractfile(member)
            if stream is None:
                raise RuntimeError('Compiled archive member has no payload')
            with stream:
                payload = stream.read(member.size + 1)
            if len(payload) != member.size:
                raise RuntimeError('Truncated compiled archive member')
            blobs[member.name] = payload
    if set(blobs) != MEMBERS:
        raise RuntimeError('Exactly six compiled archive members required')
    build = json.loads(blobs['out/mac-build-receipt.json'])
    actual_inputs = identity.source_inputs(SOURCE)
    if (build.get('schema') != 'hepta.local-model.mac-build.v2' or build.get('source_head_from_ci') != COMMIT
            or build.get('source_inputs') != actual_inputs or len(actual_inputs) != COMPILER_INPUT_COUNT
            or build.get('runtime') != 'llama_cpp'):
        raise RuntimeError('Complete 167-input compiler receipt does not bind current source')
    outputs = {'base.apk': 'out/base.apk', 'classes.dex': 'out/dex/classes.dex',
               'libhepta_local_runner.so': 'out/libhepta_local_runner.so'}
    seen = set()
    for row in build['artifacts']:
        name = Path(row['path']).name
        if (name not in outputs or name in seen or row['bytes'] != len(blobs[outputs[name]])
                or row['sha256'] != digest(blobs[outputs[name]])):
            raise RuntimeError('Actual compiled artifact binding differs')
        seen.add(name)
    if seen != set(outputs) or digest(blobs['out/worker-appuid.c']) != build['worker_adapter']['adapted_sha256']:
        raise RuntimeError('Actual generated worker binding differs')
    if digest(blobs['out/native-sha256-disassembly.txt']) != build['sha256_instruction_gate']['disassembly_sha256']:
        raise RuntimeError('Actual disassembly binding differs')
    OUT.mkdir(mode=0o700, exist_ok=False)
    (OUT / 'dex').mkdir(mode=0o700)
    for name, payload in blobs.items():
        put(ROOT / name, payload)
    proof = dict(schema='hepta.mac-artifact-transfer.v1', all_pass=True, source_commit=COMMIT,
                 compiled_source_inputs=len(actual_inputs), archive_bytes=ARCHIVE_BYTES,
                 archive_sha256=ARCHIVE_SHA256, receipt_sha256=digest(blobs['out/mac-build-receipt.json']),
                 phone_contacted=False, signed=False, installed=False,
                 files={name: dict(bytes=len(raw), sha256=digest(raw)) for name, raw in blobs.items()})
    write_json(report_dir / 'MAC-ARTIFACT-TRANSFER.json', proof)
    return build, proof


def compiled_visibility(text):
    stack, tree, namespace = [], None, {}
    uri = 'http://schemas.android.com/apk/res/android'
    for line in text.splitlines():
        match = re.match(r'^\s*N: ([A-Za-z_][A-Za-z0-9_.-]*)=([^\s]+)(?:\s|$)', line)
        if match:
            prefix, value = match.groups()
            if prefix in namespace and namespace[prefix] != value:
                raise RuntimeError('Conflicting compiled namespace')
            namespace[prefix] = value
            continue
        match = re.match(r'^(\s*)E: ([^\s(]+)', line)
        if match:
            indent = len(match.group(1))
            node = {'tag': match.group(2), 'attributes': {}, 'children': []}
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1]['children'].append(node)
            elif tree is None:
                tree = node
            else:
                raise RuntimeError('Multiple compiled manifest roots')
            stack.append((indent, node))
            continue
        match = re.match(r'^\s*A: ([^\s=()]+)(?:\([^)]*\))?="([^"]*)"(?:\s|$)', line)
        if match and stack:
            name, value = match.groups()
            if name.startswith(uri + ':'):
                name = 'android:' + name[len(uri) + 1:]
            elif name.startswith('android:') and namespace.get('android') != uri:
                raise RuntimeError('Unbound compiled Android namespace')
            if name in stack[-1][1]['attributes']:
                raise RuntimeError('Duplicate compiled manifest attribute')
            stack[-1][1]['attributes'][name] = value
    if tree is None or tree['tag'] != 'manifest':
        raise RuntimeError('Compiled manifest root missing')
    queries = [node for node in tree['children'] if node['tag'] == 'queries']
    if len(queries) != 1:
        raise RuntimeError('Compiled visibility queries missing or duplicate')
    packages, intents = [], []
    for node in queries[0]['children']:
        if node['tag'] == 'package':
            name = node['attributes'].get('android:name')
            if not isinstance(name, str) or not name or node['children']:
                raise RuntimeError('Malformed compiled visibility package')
            packages.append(name)
        elif node['tag'] == 'intent':
            entries = []
            for child in node['children']:
                name = child['attributes'].get('android:name')
                if child['tag'] not in ('action', 'category') or not isinstance(name, str) or not name or child['children']:
                    raise RuntimeError('Malformed compiled visibility intent')
                entries.append((child['tag'], name))
            if not entries or len(entries) != len(set(entries)):
                raise RuntimeError('Empty or duplicate compiled visibility intent')
            intents.append(sorted(entries))
        else:
            raise RuntimeError('Unexpected compiled visibility query')
    if not packages or len(packages) != len(set(packages)) or len(intents) != len({tuple(row) for row in intents}):
        raise RuntimeError('Missing or duplicate compiled visibility entries')
    return {'packages': sorted(packages), 'intents': sorted(intents)}


def main():
    report_dir = ROOT / 'assembly-r1'
    report_dir.mkdir(mode=0o700, exist_ok=False)
    result = dict(schema='hepta.isolated-v36-assembly.v1', all_pass=False, source_commit=COMMIT,
                  source_file_count=SOURCE_FILE_COUNT, source_inventory_sha256=INVENTORY_SHA256,
                  mac_archive_sha256=ARCHIVE_SHA256, mac_archive_bytes=ARCHIVE_BYTES,
                  actual_compiler_source_inputs=COMPILER_INPUT_COUNT, phone_contacted=False,
                  installed_on_phone=False, dependencies_downloaded=False, new_key_created=False,
                  started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    key_metadata = None
    expected_key_metadata = None
    before = None
    try:
        script = globals().get('__runner_source__')
        script_bytes = script.encode() if isinstance(script, str) else Path(__file__).read_bytes()
        put(report_dir / 'runner.py', script_bytes)
        result['runner_sha256'] = digest(script_bytes)
        before = source_check()
        write_json(report_dir / 'SOURCE-BEFORE.json', before)
        result.update(qualify_host())
        key, key_metadata, expected_key_metadata, java_home = existing_signer_and_jdk()
        if result['java_home'] != str(java_home):
            raise RuntimeError('Assembly JDK differs from actual qualified host gate')
        result.update(signer_proof_path=str(SIGNER_PROOF), signer_proof_sha256=SIGNER_PROOF_SHA256,
                      complete_jdk_receipt_sha256=JDK_PROOF_SHA256)
        identity = load_identity()
        build, transfer = extract(identity, report_dir)
        result['mac_build_receipt_sha256'] = transfer['receipt_sha256']
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SOURCE_HEAD_SHA=COMMIT,
                   JAVA_HOME=str(java_home), PATH=str(java_home / 'bin') + ':' + os.environ.get('PATH', ''),
                   HEPTA_BUILD_OUT=str(OUT), HEPTA_SIGNING_KEY_PATH=str(key), HEPTA_REQUIRE_EXISTING_KEY='1',
                   GENIEX_ANDROID_LIB_DIR='/home/alex/razr60-local-model-v150/offline-gpu-integration-20261108/geniex-npu-v0.10.0/package/geniex-bench-android-arm64-v0.10.0/lib',
                   GENIEX_ANDROID_ARCHIVE='/home/alex/razr60-local-model-v150/offline-gpu-integration-20261108/geniex-npu-v0.10.0/geniex-bench-android-arm64-v0.10.0.tar.gz',
                   MOBIMIND_ANDROID_RUNTIME_DIR='/home/alex/razr-local-ai-20261108-dda84ccf/mobiinfer-opencl-build-r4/runtime',
                   UI_VENUS_ANDROID_RUNTIME_DIR='/home/alex/razr-local-ai-20261108-dda84ccf/ui-venus-q4_0-app-native-build-r1/build',
                   APKSIGNER='/usr/bin/apksigner', AAPT2='/usr/bin/aapt2', READELF='/usr/bin/readelf')
        with (report_dir / 'stdout').open('xb') as stdout, (report_dir / 'stderr').open('xb') as stderr:
            completed = subprocess.run([sys.executable, '-B', str(SOURCE / 'assemble_pocket4.py')],
                                       cwd=SOURCE, env=env, stdout=stdout, stderr=stderr, timeout=600)
        result['exit_code'] = completed.returncode
        if completed.returncode:
            raise RuntimeError('Original v36-r2 assembler failed; original logs retained')
        source_check()
        static_dir = OUT / 'control-v36-static'
        static_path = static_dir / 'STATIC-ACCEPTANCE.json'
        static = read_json(static_path)
        apk = OUT / 'hepta-local-0.36.0.apk'
        regular(apk)
        signatures = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$',
                                (static_dir / 'apk-signature.txt').read_text(), re.M)
        if [value.lower() for value in signatures] != [CERT]:
            raise RuntimeError('Signed APK certificate differs from original installed signer proof')
        if (static.get('schema') != 'hepta.local-model.static-acceptance.v3'
                or static.get('package') != 'org.trillionnium.hepta.local' or static.get('apk') != str(apk)
                or static.get('apk_sha256') != sha(apk) or static.get('apk_bytes') != apk.stat().st_size
                or static.get('version_code') != VERSION_CODE or static.get('version_name') != VERSION_NAME
                or static.get('permissions') != [] or static.get('new_development_signing_key_created') is not False
                or static.get('installed_on_phone') is not False or static.get('ordinary_app_uid_accelerator_qualified') is not False
                or static.get('abi') != ['arm64-v8a'] or static.get('dsp_arch') != 'v79'
                or static.get('all_packaged_runtime_libraries_bound_to_independent_pins') is not True):
            raise RuntimeError('Signed APK static identity or scope claims differ')
        asset = identity.actual_build_identity(SOURCE, build)
        with zipfile.ZipFile(apk) as packed:
            if len(packed.namelist()) != len(set(packed.namelist())):
                raise RuntimeError('Duplicate signed APK member')
            dex_sha = next(row['sha256'] for row in build['artifacts'] if Path(row['path']).name == 'classes.dex')
            if digest(packed.read('classes.dex')) != dex_sha or packed.read('assets/hepta-build-identity.json') != asset:
                raise RuntimeError('Signed DEX or embedded exact compiler identity differs')
        if static.get('actual_build_identity_sha256') != digest(asset):
            raise RuntimeError('Static embedded build identity hash differs')
        manifest = ET.fromstring((SOURCE / 'AndroidManifest.xml').read_bytes())
        name = '{http://schemas.android.com/apk/res/android}name'
        queries = manifest.find('queries')
        wanted = dict(packages=sorted(row.get(name) for row in queries.findall('package')),
                      intents=sorted(sorted((row.tag, row.get(name)) for row in entry) for entry in queries.findall('intent')))
        actual = compiled_visibility((static_dir / 'apk-manifest.txt').read_text())
        if actual != wanted:
            raise RuntimeError('Signed package visibility differs from exact source manifest')
        put(report_dir / 'ACTUAL-BUILD-IDENTITY-ASSET.json', asset)
        result.update(all_pass=True, apk=str(apk), apk_bytes=apk.stat().st_size, apk_sha256=sha(apk),
                      version_code=VERSION_CODE, version_name=VERSION_NAME, permissions=[], abi=['arm64-v8a'],
                      signer_certificate_sha256=CERT, matches_previously_recorded_signer=True,
                      fresh_phone_signer_inspected=False, static_acceptance_sha256=sha(static_path),
                      actual_build_identity_sha256=digest(asset), actual_compiler_inputs_bound_to_signed_asset=True,
                      manifest_explicit_queries=actual, packaged_library_count=len(static['libraries']),
                      library_pins={row['name']: row['sha256'] for row in static['libraries']},
                      ordinary_app_uid_accelerator_qualified=False, android_runtime_tested=False)
    except Exception as error:
        result.update(all_pass=False, error_type=type(error).__name__, error=str(error))
    finally:
        for name in ('stdout', 'stderr'):
            path = report_dir / name
            if path.exists():
                result[name + '_sha256'] = sha(path)
        try:
            if before is not None:
                after = source_check()
                write_json(report_dir / 'SOURCE-AFTER.json', after)
                if after != before:
                    raise RuntimeError('Complete source inventory changed during assembly')
                result['source_files_unchanged'] = True
                result['empty_source_keys_directory_present'] = (SOURCE / 'keys').is_dir()
            if key_metadata is not None:
                if key_metadata() != expected_key_metadata:
                    raise RuntimeError('Signing changed original key metadata')
                result['existing_key_metadata_unchanged'] = True
        except Exception as error:
            result.update(all_pass=False, final_integrity_error_type=type(error).__name__, final_integrity_error=str(error))
        result['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        write_json(report_dir / 'RESULT.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
