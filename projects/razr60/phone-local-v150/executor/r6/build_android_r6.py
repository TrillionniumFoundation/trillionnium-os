#!/usr/bin/env python3
"""Build frozen r6 Android entries in a new owned output directory; no device operations."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
p=argparse.ArgumentParser();p.add_argument('--ndk',required=True);p.add_argument('--out',required=True)
a=p.parse_args();B=Path(__file__).resolve().parent;O=Path(a.out).resolve();O.mkdir(parents=True,exist_ok=False)
N=Path(a.ndk).resolve()/'toolchains/llvm/prebuilt/darwin-x86_64/bin'
commands=[
[str(N/'aarch64-linux-android28-clang'),'-O2','-c',str(B/'vendor/hash/sha256/sha256.c'),'-I'+str(B/'vendor/hash'),'-o',str(O/'sha256.o')],
[str(N/'aarch64-linux-android28-clang++'),'-std=c++17','-O2','-pthread','-static-libstdc++','-I'+str(B/'vendor'),str(B/'phone_tool_sidecar.cpp'),str(B/'vendor/hash/hash.cpp'),str(O/'sha256.o'),'-o',str(O/'phone-tool-sidecar-r6')],
[str(N/'aarch64-linux-android28-clang++'),'-std=c++17','-O2','-static-libstdc++',str(B/'phone_tool_worker.cpp'),'-o',str(O/'phone-tool-worker-r6')],
[str(N/'llvm-strip'),'--strip-unneeded',str(O/'phone-tool-sidecar-r6'),str(O/'phone-tool-worker-r6')]]
steps=[]
for i,argv in enumerate(commands):
 start=time.monotonic();r=subprocess.run(argv,capture_output=True,timeout=120)
 (O/(str(i)+'.stdout')).write_bytes(r.stdout);(O/(str(i)+'.stderr')).write_bytes(r.stderr)
 steps.append({'argv':argv,'rc':r.returncode,'seconds':time.monotonic()-start})
 if r.returncode:raise SystemExit(r.returncode)
result={'status':'BUILT_NOT_DEVICE_QUALIFIED','steps':steps,'outputs':[{'name':n,'bytes':(O/n).stat().st_size,'sha256':hashlib.sha256((O/n).read_bytes()).hexdigest()} for n in ('phone-tool-sidecar-r6','phone-tool-worker-r6')]}
(O/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
