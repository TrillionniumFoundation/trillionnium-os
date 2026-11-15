#!/usr/bin/env python3
"""Isolated Android native build only. No phone, APK, installation, or signing."""
from pathlib import Path
import argparse, hashlib, json, re, subprocess, sys, time

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def run(cmd,out,name):
    p=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=180)
    (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
    if p.returncode:raise RuntimeError(name+' failed: '+p.stderr.decode('utf-8','replace')[-12000:])
    return p.stdout.decode('utf-8','strict')

def build(source,ndk,libs,out):
    source=source.resolve(strict=True);ndk=ndk.resolve(strict=True);libs=libs.resolve(strict=True);out=out.resolve()
    if out.exists() or source==out or source in out.parents:raise ValueError('new output outside source required')
    out.mkdir(mode=0o700,parents=True)
    recipe=json.loads((source/'SOURCE.json').read_text())
    def check_source():
        for m in recipe['files']:
            p=source/m['path']
            if p.is_symlink() or p.stat().st_size!=m['bytes'] or sha(p)!=m['sha256']:raise ValueError('source changed: '+m['path'])
    check_source()
    props=(ndk/'source.properties').read_text()
    if not re.search(r'^Pkg.Revision\s*=\s*28\.1\.13356709\s*$',props,re.M):raise ValueError('NDK r28b required')
    host={'darwin':'darwin-x86_64','linux':'linux-x86_64'}[sys.platform]
    bindir=ndk/'toolchains/llvm/prebuilt'/host/'bin'
    cc=bindir/'aarch64-linux-android30-clang';cxx=bindir/'aarch64-linux-android30-clang++'
    version=run([cxx,'--version'],out,'compiler-version')
    if '13324770' not in version or '19.0.0' not in version:raise ValueError('compiler family differs')
    runtime=[]
    for m in recipe['runtime']:
        p=libs/m['name']
        if p.is_symlink() or p.stat().st_size!=m['bytes'] or sha(p)!=m['sha256']:raise ValueError('runtime changed: '+m['name'])
        runtime.append(dict(m,path=str(p)))
    native=source/'native';obj=out/'generation-bridge.o';target=out/'libhepta_local_vlm_runner.so'
    flags=['-O2','-fPIE','-Wall','-Wextra','-Werror','-fvisibility=hidden',
        '-ffile-prefix-map='+str(source)+'=hepta-vlm-worker']
    ccmd=[cc,'-std=c11',*flags,'-c',native/'generation-bridge.c','-o',obj]
    cppcmd=[cxx,'-std=c++17',*flags,'-pie','-nostdlib++',
        '-isystem'+str(source/'vendor/llama'),'-isystem'+str(source/'vendor/llama/common'),
        native/'vlm-worker.cpp',obj,'-L'+str(libs),'-lllama-common','-lmtmd','-lllama','-lggml','-lggml-base','-ldl','-lm',
        '-Wl,-rpath,$ORIGIN','-Wl,-rpath-link,'+str(libs),'-Wl,-z,max-page-size=16384',
        '-Wl,-z,now','-Wl,-z,relro','-Wl,--no-undefined','-o',target]
    began=time.monotonic();run(ccmd,out,'compile-guards');run(cppcmd,out,'compile-link')
    elf=run([bindir/'llvm-readelf','-h','-l','-d','-W',target],out,'readelf')
    needed=re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',elf);paths=re.findall(r'\((?:RUNPATH|RPATH)\).*?\[([^\]]+)\]',elf)
    expected=['libllama-common.so','libmtmd.so','libllama.so','libggml.so','libggml-base.so','libdl.so','libm.so','libc.so']
    if needed!=expected or paths!=['$ORIGIN'] or '(RPATH)' in elf or 'AArch64' not in elf or 'PIE' not in elf:raise ValueError('ELF contract differs')
    inspected={};vendor_needed=[];vendor_symbols=[]
    pending=[target]+[Path(m['path']) for m in runtime if m['name']!='libggml-htp-v79.so']
    sysroot=bindir.parent/'sysroot/usr/lib/aarch64-linux-android'
    while pending:
        p=pending.pop(0)
        if p.name in inspected:continue
        data=run([bindir/'llvm-readelf','-d','--dyn-syms','-W',p],out,'symbols-'+p.name)
        imports=[];exports=set()
        for line in data.splitlines():
            parts=line.split()
            if len(parts)<8 or not re.match(r'^\d+:$',parts[0]):continue
            name=parts[7].split('@')[0]
            if parts[6]=='UND' and parts[4]=='GLOBAL':imports.append(name)
            elif parts[6]!='UND' and parts[4] in ('GLOBAL','WEAK'):exports.add(name)
            if p.name=='libggml-opencl.so' and parts[6]=='UND' and parts[4]=='GLOBAL' and '@OPENCL_' in parts[7]:
                vendor_symbols.append(parts[7])
        deps=re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',data)
        inspected[p.name]={'path':str(p),'sha256':sha(p),'imports':imports,'exports':exports,'dt_needed':deps}
        for dep in deps:
            if dep in inspected or any(x.name==dep for x in pending):continue
            found=next((x for x in [libs/dep,sysroot/'30'/dep,sysroot/dep] if x.is_file()),None)
            if not found and p.name=='libggml-opencl.so' and dep=='libOpenCL.so':
                vendor_needed.append({'from':p.name,'needed':dep,'device_namespace_verified':False})
                continue
            if not found:raise ValueError('unresolved DT_NEEDED: '+p.name+' -> '+dep)
            pending.append(found)
    all_exports=set().union(*(x['exports'] for x in inspected.values()))
    unresolved={name:sorted(set(info['imports'])-all_exports) for name,info in inspected.items()}
    unresolved={k:v for k,v in unresolved.items() if v}
    sdk_unresolved={k:[x for x in v if not(k=='libggml-opencl.so' and x in {s.split('@')[0] for s in vendor_symbols})] for k,v in unresolved.items()}
    sdk_unresolved={k:v for k,v in sdk_unresolved.items() if v}
    closure={name:{k:sorted(v) if isinstance(v,set) else v for k,v in info.items()} for name,info in inspected.items()}
    (out/'SYMBOL-CLOSURE.json').write_text(json.dumps({'files':closure,'unresolved':unresolved,
        'sdk_cpp_unresolved':sdk_unresolved,'vendor_needed':vendor_needed,'vendor_versioned_symbols':sorted(vendor_symbols)},indent=2)+'\n')
    if sdk_unresolved:raise ValueError('undefined SDK/C++ ABI closure differs: '+json.dumps(sdk_unresolved))
    required=['mtmd_tokenize_from_parts','mtmd_helper_get_n_tokens','mtmd_helper_get_n_pos','mtmd_helper_eval_chunks',
        'llama_sampler_init_grammar','llama_model_load_from_file','mtmd_init_from_file']
    imports=inspected[target.name]['imports']
    if any(x not in imports for x in required):raise ValueError('required direct API import missing')
    if not any('common_chat_templates_apply' in x for x in imports):raise ValueError('matching Jinja API import missing')
    if any('geniex_' in x for x in imports):raise ValueError('opaque SDK boundary unexpectedly used')
    dis=run([bindir/'llvm-objdump','-d','--no-show-raw-insn',target],out,'disassembly')
    owners={};owner=None
    for line in dis.splitlines():
        match=re.search(r'<([^>]+)>:$',line)
        if match:owner=match.group(1)
        if re.search(r'\bsha256(?:h2|h|su0|su1)\b',line):owners[owner]=owners.get(owner,0)+1
    if sum(owners.values())<4 or any(not x or not x.startswith('hepta_sha256_armv8_blocks') for x in owners):raise ValueError('SHA instruction guard differs')
    run([bindir/'llvm-strip',target],out,'strip');check_source()
    receipt={'schema':'hepta.vlm.android-build.v1','commands':[list(map(str,ccmd)),list(map(str,cppcmd))],
        'compiler_version':version,'compiler_path':str(cxx),'compiler_wrapper_sha256':sha(cxx.resolve()),
        'source_properties_sha256':sha(ndk/'source.properties'),'source_manifest_sha256':sha(source/'SOURCE.json'),
        'runtime':runtime,'dt_needed':needed,'runpath':paths,'strong_undefined_closure_complete':not unresolved,
        'sdk_cpp_undefined_closure_complete':True,'vendor_needed':vendor_needed,
        'vendor_opencl_verification_pending':bool(vendor_needed),'vendor_versioned_symbols':sorted(vendor_symbols),
        'new_cpp_runtime_added':False,'symbol_closure_sha256':sha(out/'SYMBOL-CLOSURE.json'),
        'required_api_imports':required,'sha2_instruction_owners':owners,
        'worker':{'path':str(target),'bytes':target.stat().st_size,'sha256':sha(target)},
        'elapsed_seconds':time.monotonic()-began,'android_executed':False,'phone_contacted':False,
        'model_inference_performed':False,'ordinary_app_qualified':False,'dispatcher_connected':False}
    (out/'BUILD-RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:receipt[k] for k in ['worker','strong_undefined_closure_complete','new_cpp_runtime_added','phone_contacted']}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source','ndk','libs','out']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    try:build(a.source,a.ndk,a.libs,a.out)
    except Exception as error:print(str(error),file=sys.stderr);sys.exit(1)
