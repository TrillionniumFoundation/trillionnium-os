#!/usr/bin/env python3
"""Assemble and verify the independent diagnostic APK with 31 exact cached libraries."""
from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess,zipfile
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'out'
REPORT=OUT/'static-acceptance'
PACKAGE='org.trillionnium.hepta.internprobe'
APK=OUT/'hepta-intern-npu-probe-0.1.0.apk'
UNSIGNED=OUT/'hepta-intern-npu-probe-unsigned.apk'
value=os.environ.get('GENIEX_ANDROID_LIB_DIR')
if not value:raise RuntimeError('Set GENIEX_ANDROID_LIB_DIR to the pinned GenieX 0.10.0 Android arm64 lib directory')
SDK=Path(value).expanduser().resolve(strict=True)

def tool(name,environment):
    value=os.environ.get(environment) or shutil.which(name)
    if not value:raise RuntimeError('Set '+environment+' or install '+name+' on PATH')
    return value

APKSIGNER=tool('apksigner','APKSIGNER');AAPT2=tool('aapt2','AAPT2');READELF=tool('readelf','READELF')
REPORT.mkdir(exist_ok=False)
commands=[]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda:source.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def run(argv,name):
    result=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=180)
    (REPORT/(name+'.stdout')).write_text(result.stdout);(REPORT/(name+'.stderr')).write_text(result.stderr)
    commands.append({'name':name,'exit_code':result.returncode})
    if result.returncode:raise RuntimeError(name+' failed: '+result.stderr)
    return result.stdout

manifest_root=ET.parse(ROOT/'AndroidManifest.xml').getroot()
if manifest_root.get('package')!=PACKAGE:raise RuntimeError('Source package mismatch')
if manifest_root.findall('uses-permission') or any(manifest_root.findall('application/'+tag) for tag in ['service','receiver','provider']) or manifest_root.findall('instrumentation'):
    raise RuntimeError('Diagnostic must have no permission, control component or instrumentation')
expected=json.loads((ROOT/'runtime-libraries.json').read_text())['libraries']
if len(expected)!=31 or len({x['name'] for x in expected})!=31:raise RuntimeError('Runtime pin must contain 31 unique libraries')
libraries={}
for item in expected:
    relative=item['source_relative'];path=OUT/'libhepta_probe_runner.so' if relative=='@runner' else SDK/relative
    if path.stat().st_size!=item['bytes'] or sha(path)!=item['sha256']:raise RuntimeError('Cached native library differs: '+item['name'])
    libraries[item['name']]=path
if sha(ROOT/'native/vendor/geniex.h')!='c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40':
    raise RuntimeError('Public C ABI header differs from pinned 0.10.0')
with zipfile.ZipFile(OUT/'base.apk') as base,zipfile.ZipFile(UNSIGNED,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as out:
    for item in base.infolist():
        if item.filename=='resources.arsc':
            resource=zipfile.ZipInfo(item.filename,(2026,11,8,0,0,0));resource.compress_type=zipfile.ZIP_STORED;resource.external_attr=0o100644<<16
            padding=(-(out.fp.tell()+30+len(item.filename.encode('utf-8'))+4))%4
            resource.extra=struct.pack('<HH',0xffff,padding)+b'\0'*padding
            out.writestr(resource,base.read(item.filename))
        else:out.writestr(item.filename,base.read(item.filename))
    out.write(OUT/'dex/classes.dex','classes.dex')
    for name,path in libraries.items():
        info=zipfile.ZipInfo('lib/arm64-v8a/'+name,(2026,11,8,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100755<<16
        out.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)
key=ROOT/'keys/intern-probe-debug.jks'
if not key.is_file():raise RuntimeError('Dedicated diagnostic signing key from Mac build is missing')
run([APKSIGNER,'sign','--ks',key,'--ks-key-alias','hepta-internprobe-debug','--ks-pass','pass:android','--key-pass','pass:android',
     '--min-sdk-version','30','--out',APK,UNSIGNED],'sign')
run([APKSIGNER,'verify','--verbose','--print-certs',APK],'signature')
badging=run([AAPT2,'dump','badging',APK],'badging')
permissions=run([AAPT2,'dump','permissions',APK],'permissions')
manifest=run([AAPT2,'dump','xmltree',APK,'--file','AndroidManifest.xml'],'manifest')
if "package: name='"+PACKAGE+"'" not in badging or "native-code: 'arm64-v8a'" not in badging:raise RuntimeError('Actual APK identity/ABI differs')
if 'uses-permission:' in permissions or any(word in manifest for word in ['android.permission.INTERNET','BIND_ACCESSIBILITY_SERVICE','HeptaAccessibilityService','E: service','E: receiver','E: provider','E: instrumentation']):
    raise RuntimeError('Actual APK contains a forbidden diagnostic permission/component')
for name in ['libadsprpc.so','libcdsprpc.so','libOpenCL.so']:
    if name not in manifest:raise RuntimeError('Optional vendor native library declaration missing: '+name)
elf=run([READELF,'-h','-l','-d',OUT/'libhepta_probe_runner.so'],'runner-elf')
if 'DYN (Position-Independent Executable file)' not in elf or 'AArch64' not in elf:raise RuntimeError('Installed runner must be an AArch64 PIE')
with zipfile.ZipFile(APK) as archive:
    resource=archive.getinfo('resources.arsc')
    with APK.open('rb') as stream:stream.seek(resource.header_offset);header=stream.read(30)
    name_length,extra_length=struct.unpack_from('<HH',header,26)
    offset=resource.header_offset+30+name_length+extra_length
    if resource.compress_type!=zipfile.ZIP_STORED or offset%4:raise RuntimeError('resources.arsc must be stored and 4-byte aligned')
    packaged={Path(name).name:name for name in archive.namelist() if name.startswith('lib/')}
    if set(packaged)!=set(libraries):raise RuntimeError('APK runtime set differs from the 31 pinned libraries')
    for item in expected:
        raw=archive.read(packaged[item['name']])
        if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('Packaged library changed: '+item['name'])
receipt={'schema':'hepta.internprobe.static-acceptance.v1','package':PACKAGE,'apk':str(APK),'apk_sha256':sha(APK),'apk_bytes':APK.stat().st_size,
    'compile_sdk':34,'target_sdk':35,'min_sdk':30,'version_code':1,'permissions':[],'abi':['arm64-v8a'],'native_library_count':31,
    'runtime_libraries_match_qualified_code6':True,'resources_arsc_uncompressed':True,'resources_arsc_data_offset':offset,
    'phone_actions_supported':False,'accessibility_service':False,'model_in_apk':False,'installed_on_phone':False,
    'ordinary_app_uid_intern_npu_qualified':False,'input_context_admission_verified':False,'commands':commands,'libraries':expected}
(REPORT/'STATIC-ACCEPTANCE.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k!='libraries'},indent=2),flush=True)
