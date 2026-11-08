#!/usr/bin/env python3
"""Build/sign the isolated observer with cached Mac SDK/JDK. No adb or downloads."""
from pathlib import Path
import hashlib,json,os,subprocess,zipfile

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'out'
def required_path(name,alternate=None):
    value=os.environ.get(name) or (os.environ.get(alternate) if alternate else None)
    if not value:raise RuntimeError('Set '+name+(' or '+alternate if alternate else ''))
    return Path(value).expanduser().resolve(strict=True)

SDK=required_path('ANDROID_SDK_ROOT','ANDROID_HOME')
JDK=required_path('JAVA_HOME')
BT=SDK/'build-tools/34.0.0'
ANDROID_JAR=SDK/'platforms/android-34/android.jar'
OUT.mkdir(exist_ok=False)
(OUT/'classes').mkdir();(OUT/'dex').mkdir()
commands=[]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(argv):
    argv=list(map(str,argv))
    result=subprocess.run(argv,capture_output=True,text=True,timeout=90)
    name=f'{len(commands):02d}'
    (OUT/(name+'.stdout')).write_text(result.stdout)
    (OUT/(name+'.stderr')).write_text(result.stderr)
    commands.append({'argv':argv,'exit_code':result.returncode,'stdout':name+'.stdout','stderr':name+'.stderr'})
    print(json.dumps({'command':name,'executable':argv[0],'exit_code':result.returncode}),flush=True)
    if result.returncode:
        print(result.stderr,flush=True)
        raise RuntimeError('build command failed: '+name)
    return result.stdout

sources=sorted((ROOT/'src').rglob('*.java'))
run([JDK/'bin/javac','-encoding','UTF-8','--release','8','-classpath',ANDROID_JAR,'-d',OUT/'classes',*sources])
classes=sorted((OUT/'classes').rglob('*.class'))
run([JDK/'bin/java','-cp',BT/'lib/d8.jar','com.android.tools.r8.D8','--lib',ANDROID_JAR,'--min-api','30','--output',OUT/'dex',*classes])
run([BT/'aapt2','link','-I',ANDROID_JAR,'--manifest',ROOT/'AndroidManifest.xml','-o',OUT/'base.apk'])
with zipfile.ZipFile(OUT/'base.apk') as source,zipfile.ZipFile(OUT/'unsigned.apk','x',compression=zipfile.ZIP_STORED) as out:
    for info in source.infolist():out.writestr(info.filename,source.read(info.filename),compress_type=zipfile.ZIP_STORED)
    out.write(OUT/'dex/classes.dex','classes.dex',compress_type=zipfile.ZIP_STORED)
run([BT/'zipalign','-p','4',OUT/'unsigned.apk',OUT/'aligned.apk'])
# This key signs only this disposable test package; it is not a production key.
run([JDK/'bin/keytool','-genkeypair','-keystore',OUT/'observer-test.jks','-storepass','android','-keypass','android',
     '-alias','observer-test','-dname','CN=Hepta Stop Observer Test','-keyalg','RSA','-keysize','2048','-validity','10000','-noprompt'])
apk=OUT/'hepta-stop-observer-test-0.1.apk'
run([JDK/'bin/java','-jar',BT/'lib/apksigner.jar','sign','--ks',OUT/'observer-test.jks','--ks-key-alias','observer-test',
     '--ks-pass','pass:android','--key-pass','pass:android','--out',apk,OUT/'aligned.apk'])
run([JDK/'bin/java','-jar',BT/'lib/apksigner.jar','verify','--verbose','--print-certs',apk])
run([BT/'zipalign','-c','-p','4',apk])
badging=run([BT/'aapt2','dump','badging',apk])
manifest=run([BT/'aapt2','dump','xmltree',apk,'--file','AndroidManifest.xml'])
disassembly=run([JDK/'bin/javap','-c','-p','-classpath',OUT/'classes','org.trillionnium.hepta.stopobserver.StopObserverInstrumentation'])
for required in ['org.trillionnium.hepta.stopobserver','StopObserverInstrumentation']:
    if required not in manifest:raise RuntimeError('compiled manifest missing expected identity')
if 'org.trillionnium.hepta.localprobe' in manifest:raise RuntimeError('instrumentation must not target Hepta')
if any(word in manifest for word in ['uses-permission','android.permission.INTERNET']):raise RuntimeError('unexpected manifest permission')
if disassembly.count('Method getUiAutomation:(I)Landroid/app/UiAutomation;')!=1:
    raise RuntimeError('expected exactly one explicit-flags UiAutomation call')
if 'getUiAutomation:()Landroid/app/UiAutomation;' in disassembly:raise RuntimeError('default UiAutomation call forbidden')
receipt={'schema':'hepta.stop-observer.build.v1','package':'org.trillionnium.hepta.stopobserver','target_package':'org.trillionnium.hepta.stopobserver',
    'compile_sdk':34,'target_sdk':35,'min_sdk':30,'java_release':8,'android_or_phone_tested':False,'ui_automation_flags':1,
    'source_files':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in [ROOT/'AndroidManifest.xml',ROOT/'build_mac.py',*sources]],
    'apk':{'path':str(apk),'sha256':sha(apk),'bytes':apk.stat().st_size},'commands':commands}
(OUT/'BUILD-RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2),flush=True)
