#!/usr/bin/env python3
"""Assemble cached arm64 SDK libraries, sign a debug APK, and statically verify it."""
from pathlib import Path
import hashlib, json, os, subprocess, zipfile, struct, shutil, sys
import re
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from build_identity import verify_source_inputs, actual_build_identity
from model_profiles import PROFILES,DEFAULT_PROFILE,LLAMA_COMMIT
from verify_runtime import verify_runtime_archive
from verify_mobimind_runtime import verify_mobimind_runtime,verify_worker_linker_policy
from verify_ui_venus_runtime import verify_ui_venus_runtime,verify_worker_dynamic
OUT=Path(os.environ.get('HEPTA_BUILD_OUT', str(ROOT/'out'))).expanduser().resolve()
KEYS=ROOT/'keys'
sdk_directory=os.environ.get('GENIEX_ANDROID_LIB_DIR')
if not sdk_directory: raise RuntimeError('Set GENIEX_ANDROID_LIB_DIR to the pinned GenieX 0.10.0 Android arm64 lib directory')
SDK=Path(sdk_directory).expanduser().resolve(strict=True)

def tool(name, environment_name):
    value=os.environ.get(environment_name) or shutil.which(name)
    if not value: raise RuntimeError('Set '+environment_name+' or install '+name+' on PATH')
    return value

APKSIGNER=tool('apksigner','APKSIGNER')
AAPT2=tool('aapt2','AAPT2')
READELF=tool('readelf','READELF')
manifest_root=ET.parse(ROOT/'AndroidManifest.xml').getroot()
version_code=int(manifest_root.get('{http://schemas.android.com/apk/res/android}versionCode'))
version_name=manifest_root.get('{http://schemas.android.com/apk/res/android}versionName')
control=manifest_root.find('application/service') is not None
# The local controller remains offline. Only the same-signer helper binding
# permission is present from v53 onward; older packages retain an empty set.
expected_permissions=['org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE'] if control and version_code>=53 else []
permission_nodes=[node for node in manifest_root if node.tag.startswith('uses-permission')]
permission_name='{http://schemas.android.com/apk/res/android}name'
if (any(node.tag!='uses-permission' or set(node.attrib)!={permission_name} for node in permission_nodes)
        or sorted(node.get(permission_name) for node in permission_nodes)!=expected_permissions):
    raise RuntimeError('Source permissions must equal the exact version-bound offline controller set')
APK=OUT/(('hepta-local-'+version_name.split('-')[0]+'.apk') if control else 'hepta-localprobe-0.1.%d.apk'%(version_code-1))
UNSIGNED=OUT/('hepta-local-control-unsigned.apk' if control else 'hepta-localprobe-unsigned.apk')
REPORT=OUT/('control-v%d-static'%version_code) if control else OUT/('probe-v%d-static'%version_code) if version_code>1 else OUT
REPORT.mkdir(exist_ok=True)
KEYS.mkdir(exist_ok=True,mode=0o700)

def run(args):
    print('RUN', ' '.join(map(str,args)),flush=True)
    p=subprocess.run(list(map(str,args)),check=True,capture_output=True,text=True,timeout=180)
    print(p.stdout,end='',flush=True)
    if p.stderr: print(p.stderr,end='',flush=True)
    return p.stdout

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
if sha(SDK/'libgeniex.so') != '99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56':
    raise RuntimeError('Pinned GenieX Android library identity mismatch')
if sha(ROOT/'native/vendor/geniex.h') != 'c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40':
    raise RuntimeError('Pinned GenieX header identity mismatch')
libraries={'libhepta_local_runner.so':OUT/'libhepta_local_runner.so','libgeniex.so':SDK/'libgeniex.so'}
for f in sorted((SDK/'llama_cpp').glob('*.so')):
    if f.name.startswith('libggml-htp-v') and f.name!='libggml-htp-v79.so': continue
    libraries['libgeniex_plugin_llama_cpp.so' if f.name=='libgeniex_plugin.so' else f.name]=f
required={'libgeniex_plugin_llama_cpp.so','libggml.so','libggml-base.so','libggml-cpu.so',
    'libggml-opencl.so','libggml-hexagon.so','libggml-htp-v79.so','libllama.so','libllama-common.so','libmtmd.so','libomp.so'}
missing=required-set(libraries)
if missing: raise RuntimeError('Incomplete pinned llama_cpp runtime: '+str(sorted(missing)))
if any('qairt' in name.lower() or 'qnn' in name.lower() for name in libraries):
    raise RuntimeError('QAIRT binaries cannot substitute for this GGUF runtime')
runtime_archive=Path(os.environ.get('GENIEX_ANDROID_ARCHIVE',str(SDK.parent/'geniex-android-v0.10.0.tar.gz'))).expanduser().resolve()
runtime_relative={name:str(path.relative_to(SDK)) for name,path in libraries.items() if name!='libhepta_local_runner.so'}
runtime_expected=verify_runtime_archive(runtime_archive,SDK,runtime_relative.values())
mobi_directory=os.environ.get('MOBIMIND_ANDROID_RUNTIME_DIR')
if not mobi_directory:
    raise RuntimeError('Set MOBIMIND_ANDROID_RUNTIME_DIR to the separately pinned r4 Android worker/runtime')
mobimind_expected=verify_mobimind_runtime(ROOT,Path(mobi_directory).expanduser().resolve(strict=True))
if set(mobimind_expected)&set(libraries):
    raise RuntimeError('MNN members must not replace any original GenieX runtime member')
libraries.update({name:item['path'] for name,item in mobimind_expected.items()})
venus_directory=os.environ.get('UI_VENUS_ANDROID_RUNTIME_DIR')
if not venus_directory:
    raise RuntimeError('Set UI_VENUS_ANDROID_RUNTIME_DIR to the independently built ordinary-App UI-Venus worker')
ui_venus_expected=verify_ui_venus_runtime(ROOT,Path(venus_directory).expanduser().resolve(strict=True))
if set(ui_venus_expected)&set(libraries):
    raise RuntimeError('UI-Venus worker must not replace any original GenieX/MNN member')
libraries.update({name:item['path'] for name,item in ui_venus_expected.items()})
build=json.loads((OUT/'mac-build-receipt.json').read_text())
verify_source_inputs(ROOT,build)
actual_build_asset=actual_build_identity(ROOT,build)
actual_build_asset_name='assets/hepta-build-identity.json'
expected_outputs={'classes.dex':OUT/'dex/classes.dex','base.apk':OUT/'base.apk','libhepta_local_runner.so':OUT/'libhepta_local_runner.so'}
seen=set()
expected_artifact_sha={}
for item in build['artifacts']:
    name=Path(item['path']).name
    if name not in expected_outputs or name in seen or sha(expected_outputs[name])!=item['sha256']:
        raise RuntimeError('Mac build artifact binding failed: '+name)
    seen.add(name)
    expected_artifact_sha[name]=item['sha256']
if seen!=set(expected_outputs) or build.get('runtime')!='llama_cpp':
    raise RuntimeError('Expected the complete LFM3 Mac build')
# Verify host ELF dependencies without confusing Hexagon DSP ELF dependencies
# with Android linker libraries. System/vendor libraries are never copied in.
platform_libraries={'libc.so','libm.so','libdl.so','liblog.so','libandroid.so',
    'libOpenCL.so','libcdsprpc.so','libadsprpc.so','libz.so'}
dependencies={}
mobimind_linker_policy=None
ui_venus_linker_policy=None
for name,path in libraries.items():
    with path.open('rb') as binary: header=binary.read(20)
    if header[:4]!=b'\x7fELF' or len(header)<20 or header[5]!=1: raise RuntimeError('Not a little-endian ELF library: '+name)
    machine=struct.unpack_from('<H',header,18)[0]
    if name=='libggml-htp-v79.so':
        if machine!=164: raise RuntimeError('HTP v79 library is not Hexagon ELF')
        continue
    if machine!=183 or header[4]!=2: raise RuntimeError('Android host library is not ELF64 AArch64: '+name)
    dynamic=subprocess.run([READELF,'-d',str(path)],check=True,capture_output=True,text=True,timeout=30).stdout
    needed=re.findall(r'\(NEEDED\).*?\[([^]]+)\]',dynamic)
    if name in mobimind_expected and needed!=mobimind_expected[name]['needed']:
        raise RuntimeError('Actual MNN ELF dependencies differ from the pinned Android build: '+name)
    if name=='libhepta_mobimind_runner.so':
        mobimind_linker_policy=verify_worker_linker_policy(dynamic)
    if name in ui_venus_expected:
        ui_venus_linker_policy=verify_worker_dynamic(dynamic,ui_venus_expected[name])
    unresolved=set(needed)-set(libraries)-platform_libraries
    if unresolved: raise RuntimeError('Unresolved Android library dependencies for '+name+': '+str(sorted(unresolved)))
    dependencies[name]=needed
if mobimind_linker_policy is None:
    raise RuntimeError('Pinned MNN worker linker policy was not verified')
if ui_venus_linker_policy is None:
    raise RuntimeError('Independent UI-Venus App worker linker policy was not verified')

with zipfile.ZipFile(OUT/'base.apk') as base, zipfile.ZipFile(UNSIGNED,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    if actual_build_asset_name in base.namelist(): raise RuntimeError('Unexpected preexisting build identity asset')
    z.writestr(actual_build_asset_name,actual_build_asset)
    for info in base.infolist():
        if info.filename=='resources.arsc':
            resource=zipfile.ZipInfo(info.filename,(2026,11,8,0,0,0))
            resource.compress_type=zipfile.ZIP_STORED
            resource.external_attr=(0o100644<<16)
            padding=(-(z.fp.tell()+30+len(info.filename.encode('utf-8'))+4))%4
            resource.extra=struct.pack('<HH',0xffff,padding)+b'\0'*padding
            z.writestr(resource,base.read(info.filename))
        else:
            z.writestr(info.filename,base.read(info.filename))
    z.write(OUT/'dex/classes.dex','classes.dex')
    for name,path in libraries.items():
        info=zipfile.ZipInfo('lib/arm64-v8a/'+name,(2026,11,8,0,0,0))
        info.compress_type=zipfile.ZIP_DEFLATED
        info.external_attr=(0o100755<<16)
        z.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)

key=Path(os.environ.get('HEPTA_SIGNING_KEY_PATH',str(KEYS/'hepta-local-debug.jks'))).expanduser().resolve()
created_signing_key=False
if not key.exists():
    if os.environ.get('HEPTA_REQUIRE_EXISTING_KEY')=='1':
        raise RuntimeError('An existing installation must be upgraded with its original signing key; no new key created')
    if 'HEPTA_SIGNING_KEY_PATH' in os.environ:
        raise RuntimeError('Explicit signing key does not exist; refusing to create a substitute')
    keytool=os.environ.get('KEYTOOL') or shutil.which('keytool')
    if keytool is None: raise RuntimeError('keytool unavailable; generate debug key with cached Mac JDK')
    run([keytool,'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','hepta-local-debug',
        '-dname','CN=Hepta Local Debug,O=Local Development,C=CN','-keyalg','RSA','-keysize','3072','-validity','3650','-noprompt'])
    key.chmod(0o600)
    created_signing_key=True
run([APKSIGNER,'sign','--ks',key,'--ks-key-alias','hepta-local-debug','--ks-pass','pass:android',
    '--key-pass','pass:android','--min-sdk-version','30','--out',APK,UNSIGNED])
verify=run([APKSIGNER,'verify','--verbose','--print-certs',APK])
badging=run([AAPT2,'dump','badging',APK])
permissions=run([AAPT2,'dump','permissions',APK])
manifest=run([AAPT2,'dump','xmltree',APK,'--file','AndroidManifest.xml'])
actual_permissions=[]
for line in permissions.splitlines():
    if line.strip().startswith('uses-permission'):
        entry=re.fullmatch(r"uses-permission: name='([^']+)'",line.strip())
        if entry is None:raise RuntimeError('Unexpected compiled permission record')
        actual_permissions.append(entry.group(1))
actual_permissions.sort()
if actual_permissions!=expected_permissions or 'android.permission.INTERNET' in manifest:
    raise RuntimeError('Compiled permissions must equal the exact offline controller set; INTERNET is forbidden')
if "package: name='org.trillionnium.hepta.local'" not in badging: raise RuntimeError('package mismatch')
actual_identity=re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'",badging,re.MULTILINE)
if not actual_identity or actual_identity.groups()!=('org.trillionnium.hepta.local',str(version_code),version_name):
    raise RuntimeError('Actual APK identity/version differs from the current source manifest')
if "native-code: 'arm64-v8a'" not in badging: raise RuntimeError('ABI mismatch')
for expected in ['libadsprpc.so','libcdsprpc.so','libOpenCL.so']:
    if expected not in manifest: raise RuntimeError('vendor native library declaration missing: '+expected)
if control:
    service=manifest_root.find('application/service')
    if service.get('{http://schemas.android.com/apk/res/android}permission')!='android.permission.BIND_ACCESSIBILITY_SERVICE':
        raise RuntimeError('Accessibility service must have the platform binding guard')
    if manifest_root.findall('application/provider') or manifest_root.findall('application/receiver'):
        raise RuntimeError('No external providers or action receivers are allowed')
    if 'android.permission.BIND_ACCESSIBILITY_SERVICE' not in manifest or 'android.intent.category.LAUNCHER' not in manifest:
        raise RuntimeError('Accessibility/launcher metadata missing from actual APK')
    metadata=run([AAPT2,'dump','xmltree',APK,'--file','res/xml/hepta_accessibility_service.xml'])
    for capability in ['canTakeScreenshot','canRetrieveWindowContent','canPerformGestures']:
        if capability not in metadata: raise RuntimeError('Accessibility capability absent: '+capability)
    (REPORT/'accessibility-metadata.txt').write_text(metadata)
(REPORT/'apk-badging.txt').write_text(badging)
(REPORT/'apk-permissions.txt').write_text(permissions)
(REPORT/'apk-manifest.txt').write_text(manifest)
(REPORT/'apk-signature.txt').write_text(verify)
elf=run([READELF,'-h','-l','-d',OUT/'libhepta_local_runner.so'])
if 'DYN (Position-Independent Executable file)' not in elf: raise RuntimeError('runner must be PIE')
(REPORT/'runner-elf.txt').write_text(elf)
mobi_elf=run([READELF,'-h','-l','-d',libraries['libhepta_mobimind_runner.so']])
if 'DYN (Position-Independent Executable file)' not in mobi_elf or '/system/bin/linker64' not in mobi_elf:
    raise RuntimeError('MobiMind runner must be the unchanged Android PIE executable')
(REPORT/'mobimind-runner-elf.txt').write_text(mobi_elf)
venus_elf=run([READELF,'-h','-l','-d',libraries['libhepta_ui_venus_runner.so']])
if 'DYN (Position-Independent Executable file)' not in venus_elf or '/system/bin/linker64' not in venus_elf:
    raise RuntimeError('UI-Venus App runner must be its independently pinned Android PIE')
(REPORT/'ui-venus-runner-elf.txt').write_text(venus_elf)
with zipfile.ZipFile(APK) as z:
    if len(z.namelist())!=len(set(z.namelist())): raise RuntimeError('Duplicate APK member')
    if z.read(actual_build_asset_name)!=actual_build_asset: raise RuntimeError('Packaged build identity differs from verified compiler inputs')
    resource=z.getinfo('resources.arsc')
    with APK.open('rb') as raw_apk:
        raw_apk.seek(resource.header_offset)
        header=raw_apk.read(30)
    name_len,extra_len=struct.unpack_from('<HH',header,26)
    resource_data_offset=resource.header_offset+30+name_len+extra_len
    if resource.compress_type!=zipfile.ZIP_STORED or resource_data_offset%4:
        raise RuntimeError('resources.arsc must be uncompressed and aligned to 4 bytes')
    packaged={Path(n).name:n for n in z.namelist() if n.startswith('lib/')}
    if set(packaged)!=set(libraries): raise RuntimeError('unexpected packaged library list')
    lib_receipts=[]
    for name,path in libraries.items():
        payload=z.read(packaged[name])
        if name=='libhepta_local_runner.so':
            expected=expected_artifact_sha[name]; provenance='fresh_frozen_source_android_build'
        elif name in mobimind_expected:
            expected=mobimind_expected[name]['sha256']; provenance=mobimind_expected[name]['provenance']
            if len(payload)!=mobimind_expected[name]['bytes']: raise RuntimeError('MNN packaged member size differs: '+name)
        elif name in ui_venus_expected:
            expected=ui_venus_expected[name]['sha256'];provenance=ui_venus_expected[name]['provenance']
            if len(payload)!=ui_venus_expected[name]['bytes']: raise RuntimeError('UI-Venus packaged member size differs: '+name)
        else:
            expected=runtime_expected[runtime_relative[name]]['sha256']; provenance='pinned_geniex_release_archive'
        if hashlib.sha256(payload).hexdigest()!=expected: raise RuntimeError('library hash mismatch: '+name)
        lib_receipts.append({'name':name,'bytes':len(payload),'sha256':expected,'source':str(path),'provenance':provenance})
receipt={'schema':'hepta.local-model.static-acceptance.v3','apk':str(APK),'apk_bytes':APK.stat().st_size,'apk_sha256':sha(APK),
    'new_development_signing_key_created':created_signing_key,'existing_installation_signer_match_proven':False,
    'package':'org.trillionnium.hepta.local','permissions':actual_permissions,'abi':['arm64-v8a'],
    'version_code':version_code, 'version_name':version_name,
    'actual_build_identity_asset':actual_build_asset_name,'actual_build_identity_sha256':hashlib.sha256(actual_build_asset).hexdigest(),
    'debuggable':True,'extract_native_libs':True,'compile_sdk':34,'min_sdk':30,'target_sdk':35,
    'uses_native_libraries_optional':['libadsprpc.so','libcdsprpc.so','libOpenCL.so'],
    'runtime':'llama_cpp','model':'LiquidAI/LFM3-1.7B-GGUF','default_compute':'npu','default_context':8192,
    'model_profile_default':DEFAULT_PROFILE,'model_profiles':PROFILES,'llama_source_commit':LLAMA_COMMIT,
    'all_packaged_runtime_libraries_bound_to_pinned_archive':False,
    'all_packaged_geniex_libraries_bound_to_pinned_archive':True,
    'all_packaged_runtime_libraries_bound_to_independent_pins':True,
    'mobimind_runtime':{'version':'r4','libraries':[{k:v for k,v in item.items() if k!='path'} for item in mobimind_expected.values()],
        'three_unchanged_pinned_elf_members':True,'elf_dependencies_match_prior_android_build':True,
        'linker_policy':mobimind_linker_policy,
        'installed_runner_is_pie':True,'shared_model_slot':True,'private_one_use_request':True,
        'ordinary_app_runtime_qualified':False,'phone_action_dispatch_connected':False,'model_in_apk':False},
    'ui_venus_runtime':{'libraries':[{k:v for k,v in item.items() if k!='path'} for item in ui_venus_expected.values()],
        'original_geniex_mnn_members_unchanged':True,'linker_policy':ui_venus_linker_policy,'installed_runner_is_pie':True,
        'shared_model_slot':True,'aggregate_three_session_recovery':True,'private_one_use_request':True,
        'ordinary_app_runtime_qualified':False,'phone_action_dispatch_connected':False,'model_in_apk':False,
        'full_multimodal_input_qualified':False,'no_context_shift_proven':False},
    'fallback_allowed':False,'dsp_arch':'v79','host_library_dependencies':dependencies,
    'installed_on_phone':False,'ordinary_app_uid_accelerator_qualified':False,'phone_actions_supported':control,
    'accessibility_service_guarded_by_bind_permission':control,'task_trigger_private_nonce':control,
    'application_shared_engine_and_session':True,'process_wide_single_request':True,
    'native_runner_is_installed_pie':True,'model_in_apk':False,'libraries':lib_receipts,
    'resources_arsc_uncompressed':True,'resources_arsc_data_offset':resource_data_offset,'resources_arsc_alignment':4,
    'artifacts':{'badging':'apk-badging.txt','permissions':'apk-permissions.txt','manifest':'apk-manifest.txt','signature':'apk-signature.txt','runner_elf':'runner-elf.txt','mobimind_runner_elf':'mobimind-runner-elf.txt','ui_venus_runner_elf':'ui-venus-runner-elf.txt'}}
(REPORT/'STATIC-ACCEPTANCE.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k!='libraries'},indent=2),flush=True)
