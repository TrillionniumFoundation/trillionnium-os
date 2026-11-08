#!/usr/bin/env python3
"""Build Android artifacts with cached JDK/SDK/NDK on macOS or Linux; no downloads."""
from pathlib import Path
import hashlib, json, os, subprocess, sys, shutil

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from build_identity import source_inputs
OUT = Path(os.environ.get('HEPTA_BUILD_OUT', str(ROOT / 'out'))).expanduser().resolve()
def required_path(name, alternate=None):
    value = os.environ.get(name) or (os.environ.get(alternate) if alternate else None)
    if not value:
        raise RuntimeError('Set ' + name + (' or ' + alternate if alternate else '') + ' to the installed tool directory')
    return Path(value).expanduser().resolve(strict=True)

SDK = required_path('ANDROID_SDK_ROOT', 'ANDROID_HOME')
JDK = required_path('JAVA_HOME')
BT = SDK / 'build-tools/34.0.0'
ANDROID_JAR = SDK / 'platforms/android-34/android.jar'
NDK_ROOT = Path(os.environ.get('ANDROID_NDK_ROOT', str(SDK / 'ndk/28.2.13676358'))).expanduser()
host_tag = {'darwin':'darwin-x86_64', 'linux':'linux-x86_64'}.get(sys.platform)
if host_tag is None: raise RuntimeError('Only macOS and Linux Android build hosts are supported')
NDK = NDK_ROOT / 'toolchains/llvm/prebuilt' / host_tag / 'bin'
GENIEX = required_path('GENIEX_ANDROID_LIB_DIR')
OUT.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(ROOT/'native'))
from generate_adapter import generate
source_before=source_inputs(ROOT)
adapter_receipt=generate(ROOT,OUT)
for directory in [OUT/'classes',OUT/'dex']:
    if directory.exists(): shutil.rmtree(directory)
(OUT / 'classes').mkdir(exist_ok=True)
(OUT / 'dex').mkdir(exist_ok=True)

def run(args):
    print('RUN', ' '.join(map(str,args)), flush=True)
    subprocess.run(list(map(str,args)), check=True, timeout=180)

sources = sorted((ROOT / 'src').rglob('*.java'))
run([JDK/'bin/javac','-encoding','UTF-8','--release','8','-classpath',ANDROID_JAR,'-d',OUT/'classes',*sources])
classes = sorted((OUT/'classes').rglob('*.class'))
run([JDK/'bin/java','-cp',BT/'lib/d8.jar','com.android.tools.r8.D8','--lib',ANDROID_JAR,'--min-api','30','--output',OUT/'dex',*classes])
resources=[]
if (ROOT/'res').is_dir():
    run([BT/'aapt2','compile','--dir',ROOT/'res','-o',OUT/'resources.zip'])
    resources=[OUT/'resources.zip']
run([BT/'aapt2','link','-I',ANDROID_JAR,'--manifest',ROOT/'AndroidManifest.xml','-o',OUT/'base.apk',*resources])
run([NDK/'aarch64-linux-android30-clang','-std=c11','-O2','-fPIE','-pie','-Wall','-Wextra',
    '-I'+str(ROOT/'native/vendor'),'-I'+str(OUT),ROOT/'native/probe-worker.c','-L'+str(GENIEX),'-lgeniex','-ldl','-lm',
    '-Wl,-rpath,$ORIGIN','-Wl,-z,max-page-size=16384','-o',OUT/'libhepta_local_runner.so'])
run([NDK/'llvm-strip',OUT/'libhepta_local_runner.so'])
files = [OUT/'dex/classes.dex',OUT/'base.apk',OUT/'libhepta_local_runner.so']
if source_inputs(ROOT)!=source_before:
    raise RuntimeError('Source changed during compilation; no successful build receipt published')
receipt={'schema':'hepta.local-model.mac-build.v2','compile_sdk':34,'target_sdk':35,'min_sdk':30,'java_target':8,
    'build_host_platform':sys.platform,'ndk_host_tag':host_tag,
    'source_head_from_ci':os.environ.get('SOURCE_HEAD_SHA'),
    'source_inputs':source_before,
    'source_root':str(ROOT),'sdk':str(SDK),'ndk_compiler':str(NDK/'aarch64-linux-android30-clang'),
    'geniex_version':'0.10.0','geniex_source_commit':'071f609995470bdb0e0769ab964754adfaab7e47',
    'runtime':'llama_cpp','model':'LiquidAI/LFM3-1.7B-GGUF','model_sha256':'43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452',
    'compute_default':'npu','context_default':4096,
    'worker_adapter':adapter_receipt,
    'artifacts':[{ 'path':str(f),'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]}
(OUT/'mac-build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2),flush=True)
