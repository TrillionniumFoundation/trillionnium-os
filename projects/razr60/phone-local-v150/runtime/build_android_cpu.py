#!/usr/bin/env python3
"""Rebuild the pinned CPU runtime in a new operator directory. No phone operations.
The delivered hashes identify the original build; relocated paths may change bytes.
"""
import argparse,hashlib,json,os,shutil,signal,subprocess,time
from pathlib import Path
COMMIT="8642541b255bfb5dc39cd351a178be09013a55d6"
ARCHIVE_SHA="1688a167a8edd9499cdd0c19b8bd044f0fa184b466981977bbf2222d884953a4"
SOURCE_MANIFEST_SHA="26cfb57a895fe5965ce9684fac254dec1a165d044d8f056f3e5b50f2cdce46f5"
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--source",type=Path,required=True)
p.add_argument("--source-archive",type=Path,required=True)
p.add_argument("--ndk",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
p.add_argument("--cmake",default="cmake")
p.add_argument("--make",default="/usr/bin/make")
a=p.parse_args()
base=Path(__file__).resolve().parent
def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda:stream.read(1048576),b""):h.update(block)
    return h.hexdigest()
source=a.source.resolve(strict=True);ndk=a.ndk.resolve(strict=True)
assert sha(a.source_archive)==ARCHIVE_SHA,"upstream archive differs"
pins=[{"path":str(f.relative_to(source)),"size":f.stat().st_size,"sha256":sha(f)}
      for f in sorted(source.rglob("*")) if f.is_file()]
assert hashlib.sha256(json.dumps(pins,indent=2).encode()).hexdigest()==SOURCE_MANIFEST_SHA,"source tree differs"
assert "Pkg.Revision = 28.1.13356709" in (ndk/"source.properties").read_text(),"actual NDK differs"
inventory=json.loads((base/"provenance/TOOLCHAIN-INVENTORY.json").read_bytes())
for item in inventory["inputs"]:
    assert sha(ndk/item["relative_path"])==item["sha256"],"NDK input differs: "+item["relative_path"]
cmake=shutil.which(a.cmake);make=shutil.which(a.make)
assert cmake and make
observed=subprocess.run([cmake,"--version"],capture_output=True,text=True,timeout=10)
assert observed.returncode==0 and observed.stdout.startswith("cmake version 4.3.2\n"),"CMake version differs"
out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
build=out/"build";dist=out/"dist"
original=json.loads((base/"provenance/CPU-BUILD-R2-RESULT.json").read_bytes())
args=[]
for value in original["configure_argv"]:
    if value=="/opt/homebrew/bin/cmake":value=cmake
    elif value=="@RUNTIME_BUILD_ROOT@/llama.cpp-"+COMMIT:value=str(source)
    elif value=="@RUNTIME_BUILD_ROOT@/build-android-cpu-r2":value=str(build)
    elif value=="-DCMAKE_MAKE_PROGRAM=/usr/bin/make":value="-DCMAKE_MAKE_PROGRAM="+make
    elif value.startswith("-DCMAKE_TOOLCHAIN_FILE=@NDK_ROOT@/"):
        value="-DCMAKE_TOOLCHAIN_FILE="+str(ndk/"build/cmake/android.toolchain.cmake")
    assert "@" not in value,value
    args.append(value)
receipt={"scope":"owned-host Android CPU rebuild only","phone_operations":0,
         "upstream_commit":COMMIT,"source_archive_sha256":ARCHIVE_SHA,
         "source_manifest_sha256":SOURCE_MANIFEST_SHA,"steps":[],"artifacts":[]}
def save():
    (out/"RESULT.json").write_text(json.dumps(receipt,indent=2)+"\n")
def run(argv,name,timeout):
    started=time.monotonic()
    with (out/(name+".log")).open("xb") as log:
        process=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try:rc=process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
            rc=124
    receipt["steps"].append({"argv":argv,"returncode":rc,"seconds":time.monotonic()-started,
                              "log_sha256":sha(out/(name+".log"))})
    save()
    if rc:raise RuntimeError(name+" failed")
run(args,"configure",180)
run([cmake,"--build",str(build),"--target","llama-server","llama-mtmd-cli","llama-cli","--parallel","6"],"build",1200)
dist.mkdir()
ndk_bin=ndk/"toolchains/llvm/prebuilt/darwin-x86_64/bin"
for expected in original["artifacts"]:
    name=expected["name"];dst=dist/name
    shutil.copyfile(build/"bin"/name,dst);dst.chmod(0o755)
    run([str(ndk_bin/"llvm-strip"),"--strip-unneeded",str(dst)],"strip-"+name,30)
    elf=subprocess.run([str(ndk_bin/"llvm-readelf"),"-h","-d","-l",str(dst)],capture_output=True,text=True,timeout=30)
    assert elf.returncode==0 and "AArch64" in elf.stdout and "/system/bin/linker64" in elf.stdout
    assert "libc++_shared.so" not in elf.stdout
    (out/(name+".readelf.txt")).write_text(elf.stdout+elf.stderr)
    actual=sha(dst)
    receipt["artifacts"].append({"name":name,"bytes":dst.stat().st_size,"sha256":actual,
                                "delivered_sha256":expected["sha256"],
                                "matches_delivered_bytes":actual==expected["sha256"]})
assert all((source/item["path"]).stat().st_size==item["size"] and sha(source/item["path"])==item["sha256"] for item in pins)
receipt["source_unchanged"]=True
receipt["status"]="BUILT_NOT_PHONE_QUALIFIED"
receipt["relocation_note"]="Build-path-dependent bytes may differ; report comparison rather than claim bit identity."
save();print(json.dumps(receipt,indent=2))
