#!/usr/bin/env python3
"""Build an Android javac system image from a pinned core stub JAR.

Follows AOSP build/soong/java/system_modules.go: synthesize java.base exports,
javac --system=none, combine classes, jmod, jlink with system-modules disabled.
No downloaded inputs, source mutation, or target program execution.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jdk", type=Path, required=True)
    ap.add_argument("--core-jar", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a=ap.parse_args()
    jdk=a.jdk.resolve(strict=True);core=a.core_jar.resolve(strict=True)
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    (out/"jmod").mkdir()
    env=dict(os.environ)
    for k in ("JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS"):env.pop(k,None)
    receipt={"schema":"razr60-android-system-modules-build-v1",
             "started_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
             "inputs":{str(core):sha(core)},"commands":[],"phone_operations":0}
    def run(label, argv):
        p=subprocess.run([str(x) for x in argv],env=env,capture_output=True,text=True,timeout=120)
        (out/(label+".stdout.txt")).write_text(p.stdout)
        (out/(label+".stderr.txt")).write_text(p.stderr)
        receipt["commands"].append({"label":label,"argv":[str(x) for x in argv],"returncode":p.returncode})
        if p.returncode:raise RuntimeError(label+" failed; inspect retained logs")
        return p.stdout.strip()
    try:
        for n in ("javac","jmod","jlink"):receipt["inputs"][str(jdk/"bin"/n)]=sha(jdk/"bin"/n)
        with zipfile.ZipFile(core) as z:
            packages=sorted({n.rsplit("/",1)[0].replace("/",".") for n in z.namelist()
                             if "/" in n and n.endswith(".class")})
        module=out/"module-info.java"
        module.write_text("module java.base {\n"+"".join("    exports "+p+";\n" for p in packages)+"}\n")
        run("javac-module",[jdk/"bin/javac","-J-XX:ActiveProcessorCount=2","--system=none",
                            "--patch-module=java.base="+str(core),module])
        merged=out/"module.jar"
        with zipfile.ZipFile(core) as src, zipfile.ZipFile(merged,"x") as dst:
            for info in src.infolist():
                if not info.filename.startswith("META-INF/"):dst.writestr(info,src.read(info))
            dst.write(out/"module-info.class","module-info.class")
        version=run("jlink-version",[jdk/"bin/jlink","--version"])
        run("jmod",[jdk/"bin/jmod","create","--module-version",version,
                    "--target-platform","LINUX-OTHER","--class-path",merged,out/"jmod/java.base.jmod"])
        run("jlink",[jdk/"bin/jlink","-J-XX:ActiveProcessorCount=2","--module-path",out/"jmod",
                     "--add-modules","java.base","--output",out/"system","--disable-plugin","system-modules"])
        shutil.copyfile(jdk/"lib/jrt-fs.jar",out/"system/lib/jrt-fs.jar")
        receipt.update(success=True,system=str(out/"system"),
                       system_modules_sha256=sha(out/"system/lib/modules"),
                       package_count=len(packages),core_jar_unchanged=sha(core)==receipt["inputs"][str(core)])
    except BaseException as exc:
        receipt.update(success=False,error=type(exc).__name__+": "+str(exc))
    receipt["finished_utc"]=dt.datetime.now(dt.timezone.utc).isoformat()
    (out/"SYSTEM-MODULES-RECEIPT.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps(receipt),flush=True)
    return 0 if receipt["success"] else 1

if __name__=="__main__":raise SystemExit(main())

