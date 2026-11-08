#!/usr/bin/env python3
"""Build an isolated upstream llama.cpp Android/Adreno OpenCL candidate.
Does not install on, start, stop, or otherwise modify the phone.
"""
import hashlib,json,os,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
SRC=ROOT/'llama.cpp'
BUILD=ROOT/'build-opencl'
NDK=Path('/Users/qianqi/Library/Android/sdk/ndk/28.2.13676358')
CMAKE='/opt/homebrew/bin/cmake'
ENV={**os.environ,'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0','CMAKE_BUILD_PARALLEL_LEVEL':'4'}
def capture(args,cwd=None):
 return subprocess.check_output(args,cwd=cwd,env=ENV,text=True).strip()
def run_log(args,name,timeout):
 log=ROOT/'logs'/name
 with log.open('xb') as stream:
  stream.write((json.dumps({'argv':args})+'\n').encode());stream.flush()
  result=subprocess.run(args,stdout=stream,stderr=subprocess.STDOUT,env=ENV,timeout=timeout)
 if result.returncode:
  print(json.dumps({'phase':name,'exit':result.returncode,'log':str(log)}),flush=True)
  print(log.read_text(errors='replace')[-12000:],flush=True)
  sys.exit(result.returncode)
 print(json.dumps({'phase':name,'exit':0,'log':str(log)}),flush=True)
def sha(p):
 return hashlib.sha256(p.read_bytes()).hexdigest()
assert SRC.joinpath('ggml/src/ggml-opencl/CMakeLists.txt').is_file()
assert ROOT.joinpath('OpenCL-Headers/CL/cl.h').is_file()
assert sha(ROOT/'vendor-link/libOpenCL.so')=='cd35cf1ecbfb2053e45566421aa605f819b69ceb5264706ed4feb15bed0942f9'
llama_pin=json.loads((ROOT/'llama.cpp-source.json').read_text())
headers_pin=json.loads((ROOT/'OpenCL-Headers-source.json').read_text())
def tree_digest(path):
 h=hashlib.sha256()
 for p in sorted(path.rglob('*')):
  if p.is_file():
   h.update(p.relative_to(path).as_posix().encode()+b'\\0')
   h.update(hashlib.sha256(p.read_bytes()).digest())
 return h.hexdigest()
assert llama_pin['unmodified_upstream_archive'] is True
archive=ROOT/('llama.cpp-'+llama_pin['commit']+'.tar.gz')
assert sha(archive)==llama_pin['archive_sha256']
source_tree_before=tree_digest(SRC)
assert capture(['/usr/bin/git','-C',str(ROOT/'OpenCL-Headers'),'rev-parse','HEAD'])==headers_pin['commit']
args=[CMAKE,'-S',str(SRC),'-B',str(BUILD),'-G','Unix Makefiles',
 '-DCMAKE_MAKE_PROGRAM=/usr/bin/make',
 '-DCMAKE_TOOLCHAIN_FILE='+str(NDK/'build/cmake/android.toolchain.cmake'),
 '-DANDROID_ABI=arm64-v8a','-DANDROID_PLATFORM=android-28','-DANDROID_STL=c++_static',
 '-DCMAKE_BUILD_TYPE=Release','-DBUILD_SHARED_LIBS=OFF',
 '-DGGML_NATIVE=OFF','-DGGML_OPENMP=OFF','-DGGML_OPENCL=ON',
 '-DGGML_OPENCL_USE_ADRENO_KERNELS=ON','-DGGML_OPENCL_EMBED_KERNELS=ON',
 '-DGGML_OPENCL_USE_ADRENO_BIN_KERNELS=OFF',
 '-DOpenCL_INCLUDE_DIR='+str(ROOT/'OpenCL-Headers'),
 '-DOpenCL_LIBRARY='+str(ROOT/'vendor-link/libOpenCL.so'),
 '-DPython3_EXECUTABLE=/usr/bin/python3',
 '-DLLAMA_OPENSSL=OFF','-DLLAMA_SUBPROCESS=OFF',
 '-DLLAMA_BUILD_TESTS=OFF','-DLLAMA_BUILD_EXAMPLES=OFF',
 '-DLLAMA_BUILD_TOOLS=ON','-DLLAMA_BUILD_SERVER=ON',
 '-DLLAMA_BUILD_APP=OFF','-DLLAMA_BUILD_UI=OFF','-DLLAMA_USE_PREBUILT_UI=OFF',
 '-DLLAMA_BUILD_COMMIT='+llama_pin['commit']]
manifest={'status':'configuring','scope':'isolated Android OpenCL candidate; no phone installation or execution',
 'upstream_unmodified':True,'hepta_cancel_receipt_patches_included':False,
 'llama':llama_pin,'OpenCL-Headers':headers_pin,
 'ndk_path':str(NDK),'ndk_properties':(NDK/'source.properties').read_text(),
 'cmake_version':capture([CMAKE,'--version']),'target':'Android arm64-v8a API28','jobs':4,
 'link_only_phone_vendor_lib':{'path':'/vendor/lib64/libOpenCL.so','bytes':87504,'sha256':sha(ROOT/'vendor-link/libOpenCL.so'),'redistributed':False},
 'configure_argv':args,'build_argv':[CMAKE,'--build',str(BUILD),'--target','llama-server','llama-bench','llama-mtmd-cli','--parallel','4'],
 'phone_validation':'not run; parent owns phone deployment and GPU verification',
 'host_help_validation':'Android ELF cannot execute natively on macOS; --help must be executed on Android after isolated deployment'}
mp=ROOT/'BUILD-MANIFEST.json'
assert not mp.exists()
mp.write_text(json.dumps(manifest,indent=2)+'\n')
run_log(args,'configure-opencl.log',180)
manifest['status']='building';mp.write_text(json.dumps(manifest,indent=2)+'\n')
run_log(manifest['build_argv'],'build-opencl.log',1800)
artifacts=[]
readelf=NDK/'toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf'
for name in ['llama-server','llama-bench','llama-mtmd-cli']:
 src=BUILD/'bin'/name; dst=ROOT/'artifacts'/name
 assert src.is_file() and not dst.exists()
 shutil.copy2(src,dst)
 info=capture([str(readelf),'-h','-d',str(dst)])
 (ROOT/'artifacts'/(name+'.elf.txt')).write_text(info+'\n')
 assert 'AArch64' in info and 'libOpenCL.so' in info
 artifacts.append({'path':str(dst),'bytes':dst.stat().st_size,'sha256':sha(dst)})
manifest['status']='build_complete_static_inspection_passed';manifest['artifacts']=artifacts
manifest['completed_unix']=time.time()
manifest['source_tree_sha256_before']=source_tree_before
manifest['source_tree_sha256_after']=tree_digest(SRC)
assert manifest['source_tree_sha256_after']==source_tree_before
mp.write_text(json.dumps(manifest,indent=2)+'\n')
(ROOT/'artifacts'/'SHA256SUMS').write_text(''.join(a['sha256']+'  '+Path(a['path']).name+'\n' for a in artifacts))
print(json.dumps(manifest,indent=2),flush=True)
