import hashlib,json,os,pathlib,shlex,subprocess,sys,time
req=json.load(sys.stdin)
root=pathlib.Path(req["workdir"]);root.mkdir(mode=0o700,parents=True,exist_ok=False)
(root/"logs").mkdir(); (root/"artifacts").mkdir()
old=pathlib.Path(req["old_build"])
tool=pathlib.Path(req["ndk"])/"toolchains/llvm/prebuilt/darwin-x86_64/bin"
proc=old/"inputs/prebuilt/libgeniex-proc.so"
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
assert sha(proc)=="7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d"
assert sha(old/"inputs/INPUTS-MANIFEST.json")=="45c6f4e58ed9d14e1c687ca05b687571ed00059530927f6125e9590b7ee34779"
for row in req["files"]:
 data=row["content"].encode(); assert len(data)==row["bytes"] and hashlib.sha256(data).hexdigest()==row["sha256"]
 (root/row["path"]).parent.mkdir(parents=True,exist_ok=True)
 (root/row["path"]).write_bytes(data)
steps=[]
def run(label,argv,timeout=45):
 t=time.monotonic()
 p=subprocess.run([str(x) for x in argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 (root/"logs"/(label+".stdout")).write_bytes(p.stdout)
 (root/"logs"/(label+".stderr")).write_bytes(p.stderr)
 steps.append({"label":label,"argv":[str(x) for x in argv],"rc":p.returncode,"seconds":time.monotonic()-t})
 (root/"STEPS.json").write_text(json.dumps(steps,indent=2)+"\n")
 print(json.dumps({"label":label,"rc":p.returncode,"seconds":round(time.monotonic()-t,3)}),flush=True)
 if p.returncode: raise RuntimeError(label+" failed: "+p.stderr.decode(errors="replace")[-5000:])
 return p.stdout
includes=[]
for d in [old/"inputs/proc/include"]+[old/"inputs/proc/third-party"/n/"include" for n in ["xtl","xtensor","xtensor-io","xtensor-blas"]]:
 assert d.is_dir();includes+=["-isystem",str(d)]
includes+=["-isystem",str(root/"vendor")]
sdk=pathlib.Path(req["sdk"])
assert sha(sdk)=="99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56"
flags=["-std=c++20","-O3","-DNDEBUG","-fPIC","-fexceptions","-frtti","-static-libstdc++","-Wall","-Wextra","-Wpedantic","-Werror","-march=armv8.7a+fp16+dotprod+i8mm","-fvectorize","-ffp-model=fast","-fno-finite-math-only","-flto","-D_GNU_SOURCE"]
links=[str(sdk),"-L"+str(proc.parent),"-lgeniex-proc","-llog","-ldl","-latomic","-lm","-Wl,-rpath,$ORIGIN"]
compiler=tool/"aarch64-linux-android31-clang++"
version=run("compiler-version",[compiler,"--version"]).decode()
run("direct",[compiler]+flags+includes+[root/"probe.cpp"]+links+["-o",root/"artifacts/grammar-sdk-boundary-direct"])
run("dso",[compiler]+flags+["-DGRAMMAR_BOUNDARY_PROBE_DSO","-shared","-Wl,-soname,libgrammar_sdk_boundary_probe.so"]+includes+[root/"probe.cpp"]+links+["-o",root/"artifacts/libgrammar_sdk_boundary_probe.so"])
run("loader",[tool/"aarch64-linux-android31-clang","-std=c11","-O2","-fPIE","-pie","-Wall","-Wextra","-Wpedantic","-Werror",root/"loader.c","-ldl","-o",root/"artifacts/grammar-sdk-boundary-loader"])
artifacts=[]
for p in sorted((root/"artifacts").iterdir()):
 run("strip-"+p.name,[tool/"llvm-strip","--strip-unneeded",p])
 dyn=run("elf-"+p.name,[tool/"llvm-readelf","-h","-d",p])
 artifacts.append({"path":p.name,"bytes":p.stat().st_size,"sha256":sha(p),"elf_text":dyn.decode()})
manifest={"schema":"hepta.grammar-sdk-boundary-probe-build.v1","sdk_sha256":sha(sdk),"diagnostic_only":True,"model_loaded":False,"npu_loaded":False,"source_files":[{k:v for k,v in row.items() if k!="content"} for row in req["files"]],"compiler":version,"ndk_properties":(pathlib.Path(req["ndk"])/"source.properties").read_text(),"api":31,"stl":"c++_static","proc_sha256":sha(proc),"upstream_source_manifest_sha256":sha(old/"inputs/INPUTS-MANIFEST.json"),"build_steps":steps,"artifacts":artifacts}
(root/"BUILD-MANIFEST.json").write_text(json.dumps(manifest,indent=2)+"\n")
remote=req["p4dir"]
ssh=["/usr/bin/ssh","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","StrictHostKeyChecking=yes","hepta-pocket4"]
py="import pathlib;pathlib.Path("+repr(remote)+").mkdir(mode=0o700,parents=True,exist_ok=False)"
run("remote-directory",ssh+[shlex.join(["/usr/bin/python3","-c",py])])
scp=["/usr/bin/scp","-p","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","StrictHostKeyChecking=yes"]
run("transfer",scp+[str(root/"artifacts"/r["path"]) for r in artifacts]+[str(root/"BUILD-MANIFEST.json"),str(root/"probe.cpp"),str(root/"loader.c"),"hepta-pocket4:"+remote+"/"],60)
print(json.dumps({"build_manifest":str(root/"BUILD-MANIFEST.json"),"build_manifest_sha256":sha(root/"BUILD-MANIFEST.json"),"p4dir":remote,"artifacts":[{k:v for k,v in x.items() if k!="elf_text"} for x in artifacts]}),flush=True)
