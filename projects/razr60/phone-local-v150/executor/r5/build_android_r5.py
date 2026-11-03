#!/usr/bin/env python3
"""Rebuild the Android executor in an owned directory, never touches a phone."""
from pathlib import Path
import argparse, subprocess, json, hashlib, time
p=argparse.ArgumentParser()
p.add_argument("--ndk",required=True)
p.add_argument("--out",required=True)
a=p.parse_args()
base=Path(__file__).resolve().parent
out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
n=Path(a.ndk).resolve()/"toolchains/llvm/prebuilt/darwin-x86_64/bin"
commands=[
[str(n/"aarch64-linux-android28-clang"),"-O2","-c",str(base/"vendor/hash/sha256/sha256.c"),"-I"+str(base/"vendor/hash"),"-o",str(out/"sha256.o")],
[str(n/"aarch64-linux-android28-clang++"),"-std=c++17","-O2","-pthread","-static-libstdc++","-I"+str(base/"vendor"),str(base/"phone_tool_sidecar.cpp"),str(base/"vendor/hash/hash.cpp"),str(out/"sha256.o"),"-o",str(out/"phone-tool-sidecar-r5")],
[str(n/"llvm-strip"),"--strip-unneeded",str(out/"phone-tool-sidecar-r5")],
]
receipts=[]
for i,cmd in enumerate(commands):
    start=time.monotonic()
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
    (out/("step-"+str(i)+".log")).write_text(r.stdout+r.stderr)
    receipts.append({"argv":cmd,"returncode":r.returncode,"seconds":time.monotonic()-start})
    if r.returncode:
        (out/"RESULT.json").write_text(json.dumps({"steps":receipts,"status":"FAILED"},indent=2))
        raise SystemExit(r.returncode)
binary=out/"phone-tool-sidecar-r5"
result={"steps":receipts,"status":"BUILT_NOT_DEVICE_VALIDATED","bytes":binary.stat().st_size,
        "sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
        "source_sha256":hashlib.sha256((base/"phone_tool_sidecar.cpp").read_bytes()).hexdigest()}
(out/"RESULT.json").write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
