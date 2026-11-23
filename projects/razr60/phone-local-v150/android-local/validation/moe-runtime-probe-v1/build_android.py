#!/usr/bin/env python3
"""Build Android arm64 runner; never runs ADB or executes the Android binary."""
import argparse,hashlib,json,pathlib,re,subprocess,sys
root=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument("--ndk",required=True,type=pathlib.Path)
p.add_argument("--runtime-lib-dir",required=True,type=pathlib.Path)
a=p.parse_args()
ndk=a.ndk.resolve()
props_path=ndk/"source.properties"
props_text=props_path.read_text()
props=dict(line.split("=",1) for line in props_text.splitlines() if "=" in line)
props={k.strip():v.strip() for k,v in props.items()}
assert props.get("Pkg.Revision"),"NDK actual Pkg.Revision missing"
host="darwin-x86_64" if sys.platform=="darwin" else "linux-x86_64"
tool=ndk/"toolchains/llvm/prebuilt"/host/"bin"
cc=tool/"aarch64-linux-android31-clang"
readelf=tool/"llvm-readelf"
header=root/"vendor/geniex.h"
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(header)=="c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40","public ABI header changed"
public=json.loads((root/"provenance.json").read_text())
core=a.runtime_lib_dir/"libgeniex.so"
assert core.stat().st_size==19781824
assert sha(core)=="99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56","unmatched GenieX core"
needed_api=["geniex_init","geniex_deinit","geniex_set_log","geniex_set_log_level","geniex_version","geniex_get_plugin_version","geniex_free","geniex_resolve_device","geniex_get_device_list","geniex_llm_create","geniex_llm_destroy","geniex_llm_get_model_info","geniex_llm_generate"]
symbols=subprocess.check_output([str(readelf),"--dyn-syms",str(core)],text=True)
missing=[s for s in needed_api if not re.search(r"\b"+s+r"\b",symbols)]
assert not missing,missing
out=root/"bin";out.mkdir(exist_ok=True)
binary=out/"moe-runtime-probe-android-arm64"
assert not binary.exists(),"refusing to overwrite a prior runner; use a new build directory"
cmd=[str(cc),"-std=c11","-O2","-Wall","-Wextra","-Werror","-fstack-protector-strong","-D_FORTIFY_SOURCE=2","-fPIE","-pie","-Wl,-z,relro,-z,now,--build-id=sha1",str(root/"probe.c"),"-ldl","-o",str(binary)]
subprocess.run(cmd,check=True)
elf=subprocess.check_output([str(readelf),"-h",str(binary)],text=True)
dynamic=subprocess.check_output([str(readelf),"-d",str(binary)],text=True)
assert "AArch64" in elf and "DYN" in elf
assert "libgeniex.so" not in dynamic,"SDK must only be dlopened after preflight"
receipt={"schema":"hepta.moe-probe.android-build.v1","compiled":True,"phone_contacted":False,"android_binary_executed":False,"apk_changed":False,"ndk_directory":str(ndk),"ndk_source_properties":props,"ndk_source_properties_sha256":sha(props_path),"compiler_version":subprocess.check_output([str(cc),"--version"],text=True),"compile_argv":cmd,"source_sha256":sha(root/"probe.c"),"public_header_sha256":sha(header),"runtime_core_sha256":sha(core),"sdk_required_exports_verified":needed_api,"binary":{"path":str(binary),"bytes":binary.stat().st_size,"sha256":sha(binary)},"elf_header":elf,"elf_dynamic":dynamic,"sdk_loaded_at_program_start":False,"actual_device_qualification":False}
(root/"BUILD-RECEIPT.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps({"compiled":True,"actual_ndk_revision":props["Pkg.Revision"],"actual_ndk_release":props.get("Pkg.ReleaseName"),"binary":receipt["binary"],"android_binary_executed":False}))
