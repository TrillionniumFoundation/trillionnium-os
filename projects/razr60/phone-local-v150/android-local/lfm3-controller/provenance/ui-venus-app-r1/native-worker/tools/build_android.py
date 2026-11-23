#!/usr/bin/env python3
"""Compile only the isolated ordinary-App UI-Venus PIE; no APK, deployment or phone commands."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent
def sha_file(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()

def run(command,out,name,timeout=180):
    p=subprocess.run([str(x) for x in command],capture_output=True,timeout=timeout)
    (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
    if p.returncode:raise RuntimeError(name+' failed exit '+str(p.returncode))
    return p.stdout.decode('utf-8','strict')

def build(args):
    source=args.source.resolve(strict=True);ndk=args.ndk.resolve(strict=True);libs=args.sdk_libs.resolve(strict=True)
    out=args.output.resolve()
    if out.exists() or source==out or source in out.parents:raise ValueError('new output outside prepared source required')
    out.mkdir(parents=True)
    recipe=json.loads((source/'SOURCE-GENERATION.json').read_text())
    if recipe.get('schema')!='hepta.ui-venus.app-native-source.v1' or recipe.get('mode')!='vlm' or recipe.get('phone_contacted') is not False or recipe.get('actions_dispatched') is not False:
        raise ValueError('exact VLM source recipe required')
    for m in recipe['files']:
        p=source/m['path']
        if p.is_symlink() or p.stat().st_size!=m['bytes'] or sha_file(p)!=m['sha256']:raise ValueError('prepared source changed')
    boundary=json.loads(run([sys.executable,source/'verify_source_boundary.py'],out,'source-boundary'))
    if boundary.get('passed') is not True or boundary.get('original_files_unchanged')!=18 or boundary.get('original_files_changed')!=['native/venus-runtime.inc'] or boundary.get('only_model_identity_literals_changed') is not True:
        raise ValueError('App thin-wrapper source boundary differs')
    pins=json.loads((ROOT/'sdk-runtime-pins.json').read_text())
    verified=[]
    for m in pins['files']:
        # Existing APK assembly renames this one upstream plugin member.
        source_name='libgeniex_plugin.so' if m['name']=='libgeniex_plugin_llama_cpp.so' else m['name']
        rel=source_name if m['name']=='libgeniex.so' else 'llama_cpp/'+source_name;p=libs/rel
        if p.is_symlink() or p.stat().st_size!=m['bytes'] or sha_file(p)!=m['sha256']:raise ValueError('SDK runtime differs: '+rel)
        verified.append(dict(m,source_path=str(p)))
    props=(ndk/'source.properties').read_text()
    if not re.search(r'^Pkg.Revision\s*=\s*28\.1\.13356709\s*$',props,re.M):raise ValueError('actual NDK r28b revision required')
    host={'darwin':'darwin-x86_64','linux':'linux-x86_64'}[sys.platform]
    bin=ndk/'toolchains/llvm/prebuilt'/host/'bin';cc=bin/'aarch64-linux-android30-clang'
    version=run([cc,'--version'],out,'compiler-version')
    if '13324770' not in version or '19.0.0' not in version:raise ValueError('compiler family differs')
    if host!='darwin-x86_64' or sha_file(cc.resolve())!='cf2d40be93fb6051d3a66f5d6bdd24ccbe6595913040460f3607a241d562af76' or sha_file(ndk/'source.properties')!='84bef2c605bb263571c299f1eef3307ff58f741710f8cce514cb525b28567f41':
        raise ValueError('previously recorded actual Mac compiler/source.properties bytes differ')
    native=source/'native';target=out/'libhepta_ui_venus_runner.so'
    command=[cc,'-std=c11','-O2','-fPIE','-pie','-Wall','-Wextra','-Werror',
             '-I'+str(native/'vendor'),'-I'+str(native),native/'probe-worker.c',
             '-L'+str(libs),'-L'+str(libs/'llama_cpp'),'-lgeniex','-lllama','-ldl','-lm',
             '-Wl,-rpath,$ORIGIN','-Wl,-rpath-link,'+str(libs/'llama_cpp'),'-Wl,-z,max-page-size=16384','-o',target]
    started=time.monotonic();run(command,out,'compile-link')
    dis=run([bin/'llvm-objdump','-d','--no-show-raw-insn',target],out,'disassembly')
    owners={};owner=None
    for line in dis.splitlines():
        m=re.search(r'<([^>]+)>:$',line)
        if m:owner=m.group(1)
        if re.search(r'\bsha256(?:h2|h|su0|su1)\b',line):owners[owner]=owners.get(owner,0)+1
    if sum(owners.values())<4 or any(not x or not x.startswith('hepta_sha256_armv8_blocks') for x in owners):raise ValueError('SHA instructions escaped runtime gate')
    run([bin/'llvm-strip',target],out,'strip')
    elf=run([bin/'llvm-readelf','-h','-l','-d',target],out,'readelf')
    deps=re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',elf)
    paths=re.findall(r'\((?:RUNPATH|RPATH)\).*?\[([^\]]+)\]',elf)
    if 'AArch64' not in elf or 'DYN' not in elf or 'PIE' not in elf or paths!=['$ORIGIN'] or '(RPATH)' in elf:raise ValueError('PIE architecture/runpath differs')
    if deps!=['libgeniex.so','libllama.so','libdl.so','libm.so','libc.so']:raise ValueError('direct SDK import closure differs')
    symbols=run([bin/'llvm-readelf','-Ws',target],out,'dynamic-symbols')
    required=['geniex_vlm_create','geniex_vlm_get_capabilities','geniex_vlm_apply_chat_template','geniex_vlm_generate','geniex_vlm_destroy']
    for symbol in required:
        if not re.search(r'\bUND\s+'+re.escape(symbol)+r'(?:\s|$)',symbols):raise ValueError('actual VLM API import absent: '+symbol)
    for m in recipe['files']:
        if sha_file(source/m['path'])!=m['sha256']:raise ValueError('prepared source changed during compile')
    receipt={'schema':'hepta.ui-venus.app-native-android-build.v1','compile_command':list(map(str,command)),
             'actual_ndk_revision':'28.1.13356709','ndk_directory':str(ndk),'compiler_version':version,
             'compiler_sha256':sha_file(cc.resolve()),'source_properties_sha256':sha_file(ndk/'source.properties'),
             'source_generation_sha256':sha_file(source/'SOURCE-GENERATION.json'),
             'worker_source_sha256':recipe['worker_source_sha256'],'wrapper_source_sha256':recipe['wrapper_source_sha256'],
             'entry_guard_sha256':recipe['entry_guard_sha256'],'sdk_source_commit':recipe['sdk_source_commit'],
             'llama_source_commit':recipe['llama_source_commit'],'source_boundary':boundary,
             'original_core_byte_unchanged':False,'original_shell_candidate_modified':False,
             'only_model_identity_literals_changed':True,'profile':recipe['profile'],
             'runtime_core_source_sha256':sha_file(source/'native/venus-runtime.inc'),
             'baseline_app_source_generation_sha256':recipe['baseline_app_source_generation_sha256'],
             'build_helper_sha256':sha_file(Path(__file__)),
             'sdk_runtime_pins_sha256':sha_file(ROOT/'sdk-runtime-pins.json'),
             'model':recipe['model'],'mmproj':recipe['mmproj'],
             'context_tokens':8192,'max_tokens':1024,'deadline_ms':300000,'enable_thinking':True,
             'full_multimodal_token_admission_proven':False,'no_context_shift_proven':False,
             'required_vlm_imports':required,
             'worker':{'name':target.name,'bytes':target.stat().st_size,'sha256':sha_file(target),
                       'elf_machine':'AArch64','elf_type':'DYN-PIE','dt_needed':deps,'runpath':paths},
             'sdk_libraries':verified,'dt_needed':deps,'runpath':paths,'sha2_instruction_owners':owners,
             'elapsed_seconds':time.monotonic()-started,'same_directory_bootstrap_unchanged':True,
             'android_executed':False,'model_inference_performed':False,'ordinary_app_qualified':False,
             'dispatcher_connected':False,'phone_contacted':False,'installed_runtime_modified':False,
             'app_entry_policy':{'expected_uid_argument':True,'minimum_uid':10000,'real_and_effective_uid_match':True,
                 'parent_package':'org.trillionnium.hepta.local','direct_parent_before_after':True,
                 'selinux_domain_proven':False,'private_files_root_argument':True,'shell_fallback':False}}
    (out/'BUILD-RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--ndk',type=Path,required=True)
    p.add_argument('--sdk-libs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=build(a);print(json.dumps({'worker':r['worker'],'android_executed':False,'phone_contacted':False}))
