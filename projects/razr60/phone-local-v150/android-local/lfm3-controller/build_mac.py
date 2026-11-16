#!/usr/bin/env python3
"""Build Android artifacts with cached JDK/SDK/NDK on macOS or Linux; no downloads."""
from pathlib import Path
import hashlib, json, os, re, subprocess, sys, shutil, stat

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from build_identity import source_inputs, selected_variant, build_configuration, claim_build_output
from fetch_pinned_runtime import SHA256 as GENIEX_ARCHIVE_SHA256
from model_profiles import PROFILES,DEFAULT_PROFILE,LLAMA_COMMIT
VARIANT = selected_variant(os.environ)
CONFIGURATION = build_configuration(ROOT, VARIANT)
OUT, OUTPUT_MARKER = claim_build_output(ROOT, VARIANT, os.environ)
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
# GenieX already exports its C++ exception ABI from this fixed SDK library.
# Adding Mobi's independently built libc++ changes global locale/exception symbol
# resolution during plugin dlopen (observed bad_cast in its IOS constructors).
# Reuse the existing SDK runtime; the assembler still verifies both full runtimes.
SDK_CPP_PIN = {'source_name':'llama_cpp/libggml-base.so','bytes':3534496,
    'sha256':'bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40'}
SDK_CPP_PATH = GENIEX/SDK_CPP_PIN['source_name']
SDK_CPP_ABI = {'__cxa_begin_catch','__cxa_end_catch','__gxx_personality_v0','_ZTISt9exception'}
BOUNDARY_UNDEFINED = SDK_CPP_ABI | {'fflush','fprintf','geniex_llm_generate','memset','stderr'}
def verify_sdk_cpp():
    descriptor=os.open(SDK_CPP_PATH,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size!=SDK_CPP_PIN['bytes']:
            raise RuntimeError('SDK C++ ABI provider is not the pinned regular file')
        data=stream.read(SDK_CPP_PIN['bytes']+1)
        after=os.fstat(stream.fileno())
    fields=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    if fields(before)!=fields(after) or len(data)!=SDK_CPP_PIN['bytes'] or hashlib.sha256(data).hexdigest()!=SDK_CPP_PIN['sha256']:
        raise RuntimeError('SDK C++ ABI provider changed or differs from the pinned release')
verify_sdk_cpp()
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
run([BT/'aapt2','link','-I',ANDROID_JAR,'--manifest',ROOT/'AndroidManifest.xml','-o',OUT/'base.apk',*CONFIGURATION['aapt2_link_flags'],*resources])
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
# Inspect the actual production boundary object and actual fixed SDK exports.
# An unexpected C++ ABI requirement must not silently pull in another runtime.
boundary_undefined=subprocess.check_output([str(NDK/'llvm-nm'),'-u',str(boundary_object)],timeout=30).decode()
(OUT/'native-exception-boundary-object-symbols.txt').write_text(boundary_undefined)
boundary_symbols={line.split()[-1] for line in boundary_undefined.splitlines() if line.split()}
if boundary_symbols!=BOUNDARY_UNDEFINED:
    raise RuntimeError('Actual Android exception boundary has an unreviewed undefined-symbol closure')
sdk_cpp_exports=subprocess.check_output([str(NDK/'llvm-nm'),'--dynamic','--defined-only',str(SDK_CPP_PATH)],timeout=30).decode()
(OUT/'native-exception-sdk-abi-exports.txt').write_text(sdk_cpp_exports)
export_symbols={line.split()[-1] for line in sdk_cpp_exports.splitlines() if line.split()}
if not SDK_CPP_ABI.issubset(export_symbols):
    raise RuntimeError('Pinned SDK does not export the complete exception ABI needed by the boundary')
verify_sdk_cpp()
run([NDK/'aarch64-linux-android30-clang++','-fPIE','-pie','-nostdlib++',worker_object,boundary_object,
    '-L'+str(GENIEX),'-L'+str(GENIEX/'llama_cpp'),'-lgeniex','-lllama',SDK_CPP_PATH,'-ldl','-lm',
    '-Wl,-rpath,$ORIGIN','-Wl,-rpath-link,'+str(GENIEX/'llama_cpp'),'-Wl,-z,max-page-size=16384','-o',OUT/'libhepta_local_runner.so'])
dynamic=subprocess.check_output([str(NDK/'llvm-readelf'),'-d',str(OUT/'libhepta_local_runner.so')],timeout=30).decode()
(OUT/'native-exception-dynamic.txt').write_text(dynamic)
needed=re.findall(r'\(NEEDED\).*?\[([^]]+)\]',dynamic)
if needed!=['libgeniex.so','libllama.so','libggml-base.so','libdl.so','libm.so','libc.so']:
    raise RuntimeError('Actual Android worker dependencies must retain the SDK runtime without a second C++ runtime')
verify_sdk_cpp()
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
if build_configuration(ROOT, VARIANT)!=CONFIGURATION:
    raise RuntimeError('Build configuration changed during compilation')
receipt={'schema':'hepta.local-model.mac-build.v2','compile_sdk':34,'target_sdk':35,'min_sdk':30,'java_target':8,
    'build_configuration':CONFIGURATION,'build_output_marker':OUTPUT_MARKER,
    'build_host_platform':sys.platform,'ndk_host_tag':host_tag,
    'source_head_from_ci':os.environ.get('SOURCE_HEAD_SHA'),
    'source_inputs':source_before,
    'source_root':str(ROOT),'sdk':str(SDK),'ndk_compiler':str(NDK/'aarch64-linux-android30-clang'),
    'geniex_version':'0.10.0','geniex_source_commit':'071f609995470bdb0e0769ab964754adfaab7e47',
    'runtime':'llama_cpp','model':'LiquidAI/LFM3-1.7B-GGUF','model_sha256':'43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452',
    'compute_default':'npu','context_default':8192,
    'model_profile_default':DEFAULT_PROFILE,'model_profiles':PROFILES,'llama_source_commit':LLAMA_COMMIT,
    'worker_adapter':adapter_receipt,
    'sdk_exception_boundary':{'production_c_object_verified':True,'cpp_runtime_path':str(SDK_CPP_PATH),
        'cpp_runtime_bytes':SDK_CPP_PIN['bytes'],'cpp_runtime_sha256':SDK_CPP_PIN['sha256'],
        'cpp_runtime_provenance':'existing_pinned_geniex_0_10_0_libggml_base_exports',
        'geniex_archive_sha256':GENIEX_ARCHIVE_SHA256,'vendor_sdk_or_abi_changed':False,
        'boundary_undefined_symbols':sorted(boundary_symbols),'sdk_exception_abi_symbols':sorted(SDK_CPP_ABI),
        'sdk_exception_abi_exports_verified':True,'additional_cpp_runtime_linked':False,
        'actual_elf_needed':needed,
        'c_object_symbols_sha256':hashlib.sha256(undefined.encode()).hexdigest(),
        'boundary_object_symbols_sha256':hashlib.sha256(boundary_undefined.encode()).hexdigest(),
        'sdk_abi_exports_sha256':hashlib.sha256(sdk_cpp_exports.encode()).hexdigest(),
        'actual_elf_dynamic_sha256':hashlib.sha256(dynamic.encode()).hexdigest(),
        'phone_or_sdk_exception_health_verified':False},
    'sha256_instruction_gate':{'verified_actual_android_elf':True,'global_crypto_flag':False,
        'runtime_gate':'getauxval(AT_HWCAP) & HWCAP_SHA2','instruction_owners':sha_owners,
        'disassembly_sha256':hashlib.sha256(disassembly.encode()).hexdigest()},
    'artifacts':[{ 'path':str(f),'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]}
(OUT/'mac-build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2),flush=True)
