#!/usr/bin/env python3
"""Build Android artifacts with cached JDK/SDK/NDK on macOS or Linux; no downloads."""
from pathlib import Path
import hashlib, json, os, re, subprocess, sys, shutil

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from build_identity import source_inputs
from verify_mobimind_runtime import load_pins, _verify_payload
from model_profiles import PROFILES,DEFAULT_PROFILE,LLAMA_COMMIT
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
# Compilation needs only this exact already-packaged C++ payload. The assembler
# still verifies the complete independent Mobi runtime and build provenance.
CPP_PIN = next(item for item in load_pins(ROOT)['libraries'] if item['apk_name']=='libc++_shared.so')
CPP_PATH = required_path('MOBIMIND_ANDROID_RUNTIME_DIR')/CPP_PIN['source_name']
_verify_payload(CPP_PATH,CPP_PIN)
llama_headers=ROOT/'native/vendor/llama'
llama_pin=json.loads((llama_headers/'PIN.json').read_text())
if llama_pin.get('commit')!=LLAMA_COMMIT:raise RuntimeError('llama header source pin differs')
for member in llama_pin['files']:
    if Path(member['path']).name!=member['path']:raise RuntimeError('invalid vendored header member')
    data=(llama_headers/member['path']).read_bytes()
    if len(data)!=member['bytes'] or hashlib.sha256(data).hexdigest()!=member['sha256']:
        raise RuntimeError('vendored llama ABI header changed: '+member['path'])
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
worker_object=OUT/'hepta-worker-c.o';boundary_object=OUT/'hepta-sdk-exception.o'
run([NDK/'aarch64-linux-android30-clang','-std=c11','-O2','-fPIE','-fexceptions','-Wall','-Wextra',
    '-DHEPTA_SDK_EXCEPTION_BOUNDARY=1','-I'+str(ROOT/'native/vendor'),'-I'+str(ROOT/'native'),'-I'+str(OUT),
    '-c',ROOT/'native/probe-worker.c','-o',worker_object])
run([NDK/'aarch64-linux-android30-clang++','-std=c++11','-O2','-fPIC','-fexceptions','-Wall','-Wextra',
    '-DHEPTA_SDK_EXCEPTION_BOUNDARY=1','-I'+str(ROOT/'native'),
    '-c',ROOT/'native/sdk-exception-boundary.cpp','-o',boundary_object])
# This checks the actual production C object, so a missing build define cannot
# silently use the pure-C test compatibility path.
undefined=subprocess.check_output([str(NDK/'llvm-nm'),'-u',str(worker_object)],timeout=30).decode()
(OUT/'native-exception-c-object-symbols.txt').write_text(undefined)
symbols={line.split()[-1] for line in undefined.splitlines() if line.split()}
if 'hepta_guarded_llm_generate' not in symbols or 'hepta_sdk_generate_exception' not in symbols or 'geniex_llm_generate' in symbols:
    raise RuntimeError('Actual Android C object did not use the SDK exception boundary')
run([NDK/'aarch64-linux-android30-clang++','-fPIE','-pie','-nostdlib++',worker_object,boundary_object,
    '-L'+str(GENIEX),'-L'+str(GENIEX/'llama_cpp'),'-lgeniex','-lllama',CPP_PATH,'-ldl','-lm',
    '-Wl,-rpath,$ORIGIN','-Wl,-rpath-link,'+str(GENIEX/'llama_cpp'),'-Wl,-z,max-page-size=16384','-o',OUT/'libhepta_local_runner.so'])
dynamic=subprocess.check_output([str(NDK/'llvm-readelf'),'-d',str(OUT/'libhepta_local_runner.so')],timeout=30).decode()
(OUT/'native-exception-dynamic.txt').write_text(dynamic)
if re.findall(r'\(NEEDED\).*?\[([^]]+)\]',dynamic).count('libc++_shared.so')!=1:
    raise RuntimeError('The actual Android worker must directly need the pinned shared C++ runtime exactly once')
_verify_payload(CPP_PATH,CPP_PIN)
# The baseline dispatcher must remain runnable without SHA2. Inspect the actual
# unstripped Android ELF, not an inferred compiler configuration or host stub.
disassembly=subprocess.check_output([str(NDK/'llvm-objdump'),'-d','--no-show-raw-insn',str(OUT/'libhepta_local_runner.so')],timeout=30).decode()
(OUT/'native-sha256-disassembly.txt').write_text(disassembly)
sha_owner=None;sha_owners={}
for line in disassembly.splitlines():
    symbol=re.search(r'<([^>]+)>:$',line)
    if symbol:sha_owner=symbol.group(1)
    if re.search(r'\bsha256(?:h2|h|su0|su1)\b',line):sha_owners[sha_owner]=sha_owners.get(sha_owner,0)+1
if sum(sha_owners.values())<4 or any(not owner or not owner.startswith('hepta_sha256_armv8_blocks') for owner in sha_owners):
    raise RuntimeError('SHA256 instructions escaped the HWCAP-gated target function')
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
    'compute_default':'npu','context_default':8192,
    'model_profile_default':DEFAULT_PROFILE,'model_profiles':PROFILES,'llama_source_commit':LLAMA_COMMIT,
    'worker_adapter':adapter_receipt,
    'sdk_exception_boundary':{'production_c_object_verified':True,'cpp_runtime_path':str(CPP_PATH),
        'cpp_runtime_bytes':CPP_PIN['bytes'],'cpp_runtime_sha256':CPP_PIN['sha256'],
        'cpp_runtime_provenance':'existing_apk_mobimind_r4_cpp_pin','vendor_sdk_or_abi_changed':False,
        'c_object_symbols_sha256':hashlib.sha256(undefined.encode()).hexdigest(),
        'actual_elf_dynamic_sha256':hashlib.sha256(dynamic.encode()).hexdigest(),
        'phone_or_sdk_exception_health_verified':False},
    'sha256_instruction_gate':{'verified_actual_android_elf':True,'global_crypto_flag':False,
        'runtime_gate':'getauxval(AT_HWCAP) & HWCAP_SHA2','instruction_owners':sha_owners,
        'disassembly_sha256':hashlib.sha256(disassembly.encode()).hexdigest()},
    'artifacts':[{ 'path':str(f),'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]}
(OUT/'mac-build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2),flush=True)
