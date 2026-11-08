#!/usr/bin/env python3
"""Compile the isolated diagnostic app and reuse the exact qualified native runner.

Only preinstalled tools are used. This script performs no download or phone action.
"""
from pathlib import Path
import hashlib,json,os,shutil,subprocess

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'out'

def required_path(name,alternate=None):
    value=os.environ.get(name) or (os.environ.get(alternate) if alternate else None)
    if not value:raise RuntimeError('Set '+name+(' or '+alternate if alternate else ''))
    return Path(value).expanduser().resolve(strict=True)

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda:source.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

SDK=required_path('ANDROID_SDK_ROOT','ANDROID_HOME')
JDK=required_path('JAVA_HOME')
RUNNER=required_path('HEPTA_QUALIFIED_RUNNER')
BT=SDK/'build-tools/34.0.0'
ANDROID_JAR=SDK/'platforms/android-34/android.jar'
runtime=json.loads((ROOT/'runtime-libraries.json').read_text())
runner_pin=next(x for x in runtime['libraries'] if x['source_relative']=='@runner')
if sha(RUNNER)!=runner_pin['sha256'] or RUNNER.stat().st_size!=runner_pin['bytes']:
    raise RuntimeError('Qualified runner differs from the pinned ordinary-UID build')
OUT.mkdir(exist_ok=False)
(OUT/'classes').mkdir();(OUT/'dex').mkdir()
commands=[]

def run(argv):
    argv=list(map(str,argv));result=subprocess.run(argv,capture_output=True,text=True,timeout=180)
    index=f'{len(commands):02d}';(OUT/(index+'.stdout')).write_text(result.stdout);(OUT/(index+'.stderr')).write_text(result.stderr)
    commands.append({'argv':argv,'exit_code':result.returncode,'stdout':index+'.stdout','stderr':index+'.stderr'})
    print(json.dumps({'command':index,'exit_code':result.returncode}),flush=True)
    if result.returncode:raise RuntimeError('Build command failed: '+index+' '+result.stderr)

sources=sorted((ROOT/'src').rglob('*.java'))
if len(sources)!=3:raise RuntimeError('Unexpected diagnostic Java source set')
run([JDK/'bin/javac','-encoding','UTF-8','--release','8','-classpath',ANDROID_JAR,'-d',OUT/'classes',*sources])
classes=sorted((OUT/'classes').rglob('*.class'))
run([JDK/'bin/java','-cp',BT/'lib/d8.jar','com.android.tools.r8.D8','--lib',ANDROID_JAR,'--min-api','30','--output',OUT/'dex',*classes])
run([BT/'aapt2','compile','--dir',ROOT/'res','-o',OUT/'resources.zip'])
run([BT/'aapt2','link','-I',ANDROID_JAR,'--manifest',ROOT/'AndroidManifest.xml','-o',OUT/'base.apk',OUT/'resources.zip'])
shutil.copyfile(RUNNER,OUT/'libhepta_probe_runner.so');(OUT/'libhepta_probe_runner.so').chmod(0o755)
keys=ROOT/'keys';keys.mkdir(mode=0o700,exist_ok=False)
key=keys/'intern-probe-debug.jks'
run([JDK/'bin/keytool','-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','hepta-internprobe-debug',
     '-dname','CN=Hepta Intern NPU Probe Debug','-keyalg','RSA','-keysize','3072','-validity','3650','-noprompt'])
key.chmod(0o600)
receipt={'schema':'hepta.internprobe.mac-build.v1','package':'org.trillionnium.hepta.internprobe','compile_sdk':34,'target_sdk':35,'min_sdk':30,
    'java_release':8,'runner_rebuilt':False,'runner_reused_from_qualified_code6':True,'runner_sha256':sha(OUT/'libhepta_probe_runner.so'),
    'android_apk_assembled':False,'model_included':False,'model_identity_verified':False,'phone_tested':False,'commands':commands,
    'artifacts':[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)} for p in [OUT/'base.apk',OUT/'dex/classes.dex',OUT/'libhepta_probe_runner.so']]}
(OUT/'MAC-BUILD-RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2),flush=True)
