#!/usr/bin/env python3
"""Assemble cached arm64 SDK libraries, sign a debug APK, and statically verify it."""
from pathlib import Path
import hashlib, json, os, subprocess, zipfile, struct, shutil
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'out'
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
assert sha(SDK/'libgeniex.so') == '99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56'
assert sha(ROOT/'native/vendor/geniex.h') == 'c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40'
libraries={'libhepta_probe_runner.so':OUT/'libhepta_probe_runner.so','libgeniex.so':SDK/'libgeniex.so'}
for f in sorted((SDK/'qairt').glob('*.so')):
    libraries['libgeniex_plugin_qairt.so' if f.name=='libgeniex_plugin.so' else f.name]=f
for f in sorted((SDK/'qairt/htp-files').glob('*.so')):
    if 'V81' not in f.name: libraries[f.name]=f

with zipfile.ZipFile(OUT/'base.apk') as base, zipfile.ZipFile(UNSIGNED,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
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

key=KEYS/'probe-debug.jks'
if not key.exists():
    keytool=os.environ.get('KEYTOOL') or shutil.which('keytool')
    if keytool is None: raise RuntimeError('keytool unavailable; generate debug key with cached Mac JDK')
    run([keytool,'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','hepta-localprobe-debug',
        '-dname','CN=Hepta Local Probe Debug,O=Local Development,C=CN','-keyalg','RSA','-keysize','3072','-validity','3650','-noprompt'])
    key.chmod(0o600)
run([APKSIGNER,'sign','--ks',key,'--ks-key-alias','hepta-localprobe-debug','--ks-pass','pass:android',
    '--key-pass','pass:android','--min-sdk-version','30','--out',APK,UNSIGNED])
verify=run([APKSIGNER,'verify','--verbose','--print-certs',APK])
badging=run([AAPT2,'dump','badging',APK])
permissions=run([AAPT2,'dump','permissions',APK])
manifest=run([AAPT2,'dump','xmltree',APK,'--file','AndroidManifest.xml'])
if 'uses-permission:' in permissions or 'android.permission.INTERNET' in manifest:
    raise RuntimeError('probe must declare no Android permissions')
if "package: name='org.trillionnium.hepta.localprobe'" not in badging: raise RuntimeError('package mismatch')
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
elf=run([READELF,'-h','-l','-d',OUT/'libhepta_probe_runner.so'])
if 'DYN (Position-Independent Executable file)' not in elf: raise RuntimeError('runner must be PIE')
(REPORT/'runner-elf.txt').write_text(elf)
with zipfile.ZipFile(APK) as z:
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
        payload=z.read(packaged[name]); expected=sha(path)
        if hashlib.sha256(payload).hexdigest()!=expected: raise RuntimeError('library hash mismatch: '+name)
        lib_receipts.append({'name':name,'bytes':len(payload),'sha256':expected,'source':str(path)})
receipt={'schema':'hepta.appuid-probe.static-acceptance.v1','apk':str(APK),'apk_bytes':APK.stat().st_size,'apk_sha256':sha(APK),
    'package':'org.trillionnium.hepta.localprobe','permissions':[],'abi':['arm64-v8a'],
    'version_code':version_code,
    'debuggable':True,'extract_native_libs':True,'compile_sdk':34,'min_sdk':30,'target_sdk':35,
    'uses_native_libraries_optional':['libadsprpc.so','libcdsprpc.so','libOpenCL.so'],
    'installed_on_phone':False,'ordinary_app_uid_npu_qualified':False,'phone_actions_supported':control,
    'accessibility_service_guarded_by_bind_permission':control,'task_trigger_private_nonce':control,
    'application_shared_engine_and_session':True,'process_wide_single_request':True,
    'native_runner_is_installed_pie':True,'model_in_apk':False,'libraries':lib_receipts,
    'resources_arsc_uncompressed':True,'resources_arsc_data_offset':resource_data_offset,'resources_arsc_alignment':4,
    'artifacts':{'badging':'apk-badging.txt','permissions':'apk-permissions.txt','manifest':'apk-manifest.txt','signature':'apk-signature.txt','runner_elf':'runner-elf.txt'}}
(REPORT/'STATIC-ACCEPTANCE.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k!='libraries'},indent=2),flush=True)
