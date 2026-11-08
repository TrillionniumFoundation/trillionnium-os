#!/usr/bin/env python3
"""Build only the reviewed VLM DSO, against unchanged R2/official imports."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    req=json.load(sys.stdin)
    root=Path(req["workdir"]);root.mkdir(mode=0o700,parents=True,exist_ok=False)
    for n in ("logs","source","reference","artifacts","abi"): (root/n).mkdir()
    old=Path(req["r2_build"])
    input_manifest=old/"inputs/INPUTS-MANIFEST.json"
    assert sha(input_manifest)=="45c6f4e58ed9d14e1c687ca05b687571ed00059530927f6125e9590b7ee34779"
    manifest=json.loads(input_manifest.read_text())
    for row in manifest["files"]:
        if row["input"] in ("qairt","proc"):
            p=old/"inputs"/row["input"]/row["path"]
            assert p.stat().st_size==row["bytes"] and sha(p)==row["sha256"]
    shutil.copytree(old/"inputs/qairt",root/"source/qairt")
    source=root/"source/qairt"
    original=source/"core/src/pipeline/vlm_pipeline.cpp"
    assert sha(original)=="5521c482190254af65e3070d1413d3d919a8e6b8f80bf3ddb7125d8ef676807d"
    for row in req["review_files"]:
        raw=row["content"].encode();assert len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
        p=root/"review"/row["path"];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
    candidate=root/"review/candidate/vlm_pipeline.cpp"
    assert sha(candidate)=="cfee2c080b42b59e4edcf7e8313b5e52297539ed70c38aa405fd948042d74866"
    original.write_bytes(candidate.read_bytes())
    imports=[
      ("libgeniex_core.so",old/"artifacts/libgeniex_core.so","06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d"),
      ("libgeniex-proc.so",old/"inputs/prebuilt/libgeniex-proc.so","7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d")]
    for name,p,pin in imports:assert sha(p)==pin;shutil.copyfile(p,root/"reference"/name)
    steps=[]
    def run(label,args,timeout=90):
        start=time.monotonic()
        p=subprocess.run([str(x) for x in args],capture_output=True,timeout=timeout,env=env)
        (root/"logs"/(label+".stdout")).write_bytes(p.stdout);(root/"logs"/(label+".stderr")).write_bytes(p.stderr)
        steps.append({"stage":label,"argv":[str(x) for x in args],"rc":p.returncode,"seconds":time.monotonic()-start})
        (root/"STEPS.json").write_text(json.dumps(steps,indent=2)+"\n")
        print(json.dumps({"stage":label,"rc":p.returncode,"seconds":round(time.monotonic()-start,3)}),flush=True)
        if p.returncode:raise RuntimeError(label+" failed: "+p.stderr.decode(errors="replace")[-6000:])
        return p.stdout.decode(errors="replace")
    env=dict(os.environ);env["ANDROID_NDK_ROOT"]=req["ndk"]
    ndk=Path(req["ndk"]);tool=ndk/"toolchains/llvm/prebuilt/darwin-x86_64/bin"
    scp=["/usr/bin/scp","-p","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","StrictHostKeyChecking=yes"]
    ref=root/"reference/libgeniex-proc-vision.so"
    run("copy-official-proc-vision",scp+["hepta-pocket4:"+req["official_package"]+"/lib/qairt/libgeniex-proc-vision.so",ref])
    assert sha(ref)=="5517a4ca8e754e6df46859f914ce779dd30831e5a33bc457d40bec744d699be9"
    refs=Path(req["sdk_analysis"])
    for src,dst,pin in [
       ("vlm.so","original-libgeniex_vlm.so","8afccd775a6a6a2cef0521d30aa30df824a85d3617d913fc3cf49fe32795cb87"),
       ("qairt-plugin.so","original-libgeniex_plugin.so","384eaaeaa1254126f4a07ef2a8e28bb5df9ee20d0b0bc54bc0d4874e02d9eab3"),
       ("sdk.so","libgeniex.so","99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56")]:
        p=refs/src;assert sha(p)==pin;shutil.copyfile(p,root/"reference"/dst)
    proc=old/"inputs/proc"
    sources=[str(p.relative_to(source)) for p in (source/"core/src/vlm").glob("*.cpp")]
    sources+=["core/src/pipeline/vlm_pipeline.cpp","models/qwen2_5_vl/qwen2_5_vl.cpp","models/qwen3_vl/qwen3_vl.cpp","models/intern3_5_vl/intern3_5_vl.cpp","models/gemma4/gemma4.cpp"]
    assert len(sources)==10 and len(set(sources))==10
    cmake='''cmake_minimum_required(VERSION 3.16)
project(geniex_vlm_repair C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_library(geniex_core SHARED IMPORTED)
add_library(geniex-proc SHARED IMPORTED)
add_library(geniex-proc-vision SHARED IMPORTED)
'''
    for n in ("geniex_core","geniex-proc","geniex-proc-vision"):
        cmake+='set_target_properties('+n+' PROPERTIES IMPORTED_LOCATION "'+str(root/"reference"/("lib"+n+".so"))+'")\n'
    cmake+='add_library(geniex_vlm SHARED\n'+"\n".join(' "'+str(source/p)+'"' for p in sources)+'\n)\n'
    includes=[source/"core/include",source/"models",source/"qnn-api/include",source/"qnn-api/include/HTP",source/"qnn-api/include/System",source/"qnn-api/src",source/"qnn-api/src/config",proc/"include"]+[proc/"third-party"/n/"include" for n in ("xtl","xtensor","xtensor-io","xtensor-blas")]
    cmake+='target_include_directories(geniex_vlm PRIVATE\n'+"\n".join(' "'+str(p)+'"' for p in includes)+'\n)\n'
    cmake+='''target_compile_definitions(geniex_vlm PRIVATE qualla_EXPORTS GENIE_API= NOMINMAX NOGDI SPILLFILL QUALLA_APPS=OFF FMT_HEADER_ONLY=1 FMT_CONSTEVAL=constexpr QUALLA_INTERNAL_QNN_SDK QUALLA_ENGINE_QNN_HTP GENIE_SSD_FEATURE GENIE_SPD_FEATURE GENIE_LADE_FEATURE GENIE_MULTISTREAM_FEATURE GENIE_LORA_FEATURE GENIE_E2T_FEATURE JSON_HAS_THREE_WAY_COMPARISON=0 GENIEX_QAIRT_VERSION="2.50")
target_compile_options(geniex_vlm PRIVATE -march=armv8.7a+fp16+dotprod+i8mm -fvectorize -ffp-model=fast -fno-finite-math-only -flto -D_GNU_SOURCE)
target_link_options(geniex_vlm PRIVATE -flto -Wl,--no-undefined)
target_link_libraries(geniex_vlm PRIVATE geniex_core geniex-proc-vision geniex-proc log dl atomic m)
'''
    (root/"CMakeLists.txt").write_text(cmake)
    compiler=run("compiler-version",[tool/"clang++","--version"])
    configure=["/opt/homebrew/bin/cmake","-S",root,"-B",root/"build","-G","Unix Makefiles","-DCMAKE_MAKE_PROGRAM=/usr/bin/make","-DCMAKE_TOOLCHAIN_FILE="+str(old/"inputs/arm64-android-llvm.cmake"),"-DANDROID_ABI=arm64-v8a","-DANDROID_PLATFORM=android-31","-DANDROID_STL=c++_static","-DCMAKE_BUILD_TYPE=Release","-DCMAKE_EXPORT_COMPILE_COMMANDS=ON","-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-rpath,$ORIGIN","-DCMAKE_CXX_STANDARD_LIBRARIES=-llog -ldl -latomic -lm"]
    run("configure",configure)
    run("build",["/opt/homebrew/bin/cmake","--build",root/"build","--target","geniex_vlm","-j","4"])
    unstripped=root/"build/libgeniex_vlm.so";artifact=root/"artifacts/libgeniex_vlm.so";shutil.copyfile(unstripped,artifact)
    run("strip",[tool/"llvm-strip","--strip-unneeded",artifact])
    def elf(name,p):
        dyn=run(name+"-dynamic",[tool/"llvm-readelf","-d",p])
        syms=run(name+"-symbols",[tool/"llvm-readelf","--dyn-syms","--wide",p])
        definitions={};undefined=set()
        for line in syms.splitlines():
            parts=line.split()
            if len(parts)<8 or not parts[0].endswith(":") or not parts[0][:-1].isdigit():continue
            sym=parts[7].split("@")[0]
            if parts[6]=="UND":undefined.add(sym)
            elif parts[4] in ("GLOBAL","WEAK"):definitions[sym]={"binding":parts[4],"visibility":parts[5],"type":parts[3]}
        data={"sha256":sha(p),"defined":definitions,"undefined":sorted(undefined),"needed":re.findall(r"\(NEEDED\).*?\[(.*?)\]",dyn),"soname":re.findall(r"\(SONAME\).*?\[(.*?)\]",dyn),"runpath":re.findall(r"\(RUNPATH\).*?\[(.*?)\]",dyn)}
        assert data["needed"] and data["soname"],name
        (root/"abi"/(name+".json")).write_text(json.dumps(data,indent=2)+"\n")
        return data
    original=elf("original-vlm",root/"reference/original-libgeniex_vlm.so")
    candidate=elf("candidate-vlm",artifact)
    imported={}
    for name in ("libgeniex_core.so","libgeniex-proc.so","libgeniex-proc-vision.so","libgeniex.so","original-libgeniex_plugin.so"):
        imported[name]=elf(name,root/"reference"/name)
    od,nd=set(original["defined"]),set(candidate["defined"])
    consumers={}
    for name,data in imported.items():
        reqs=set(data["undefined"])&od
        if reqs:consumers[name]={"required":sorted(reqs),"missing":sorted(reqs-nd)}
    new_undefined=set(candidate["undefined"])-set(original["undefined"])
    resolutions={s:[n for n,v in imported.items() if s in v["defined"]] for s in sorted(new_undefined)}
    abi={"schema":"hepta.vlm-r3-abi.v1","original_sha256":original["sha256"],"candidate_sha256":candidate["sha256"],"soname":candidate["soname"],"original_soname":original["soname"],"needed":candidate["needed"],"original_needed":original["needed"],"runpath":candidate["runpath"],"original_runpath":original["runpath"],"missing_original_definitions":{s:original["defined"][s] for s in sorted(od-nd)},"new_definitions":sorted(nd-od),"consumers":consumers,"new_undefined_resolution":resolutions,"source_or_abi_qualification_only":True,"phone_tested":False}
    (root/"ABI-COMPARISON.json").write_text(json.dumps(abi,indent=2)+"\n")
    build={"schema":"hepta.vlm-r3-build.v1","candidate_only":True,"phone_accessed":False,"upstream_manifest_sha256":sha(input_manifest),"patch_sha256":sha(root/"review/vlm-grammar-error.patch"),"source_sha256":sha(source/"core/src/pipeline/vlm_pipeline.cpp"),"source_files":[{"path":p,"bytes":(source/p).stat().st_size,"sha256":sha(source/p)} for p in sources],"imports":{p.name:sha(p) for p in (root/"reference").iterdir()},"compiler":compiler,"ndk_properties":(ndk/"source.properties").read_text(),"cmake_sha256":sha(root/"CMakeLists.txt"),"compile_commands_sha256":sha(root/"build/compile_commands.json"),"unstripped":{"bytes":unstripped.stat().st_size,"sha256":sha(unstripped)},"stripped":{"bytes":artifact.stat().st_size,"sha256":sha(artifact)},"steps":steps,"abi_comparison_sha256":sha(root/"ABI-COMPARISON.json")}
    (root/"BUILD-MANIFEST.json").write_text(json.dumps(build,indent=2)+"\n")
    remote=req["p4dir"];ssh=["/usr/bin/ssh","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","StrictHostKeyChecking=yes","hepta-pocket4"]
    run("mkdir-remote",ssh+[shlex.join(["/usr/bin/python3","-c","import pathlib;pathlib.Path("+repr(remote)+").mkdir(mode=0o700,parents=True,exist_ok=False)"])])
    run("transfer",scp+[artifact,root/"BUILD-MANIFEST.json",root/"ABI-COMPARISON.json","hepta-pocket4:"+remote+"/"])
    print(json.dumps({"p4dir":remote,"candidate":build["stripped"],"build_manifest_sha256":sha(root/"BUILD-MANIFEST.json"),"abi_sha256":sha(root/"ABI-COMPARISON.json"),"missing_consumer_symbols":{k:v["missing"] for k,v in consumers.items()},"new_undefined_resolution":resolutions}),flush=True)
if __name__=="__main__":main()
