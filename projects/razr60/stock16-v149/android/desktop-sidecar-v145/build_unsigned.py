#!/usr/bin/env python3
"""Build an unsigned ordinary entry APK on this host only. No signing/device calls."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    sdk, jdk, out = args.sdk_root.resolve(strict=True), args.jdk.resolve(strict=True), args.out.resolve()
    android = sdk / "platforms/android-34/android.jar"
    tools = sdk / "build-tools/34.0.0"
    out.mkdir(mode=0o700, exist_ok=False)
    for name in ["source", "generated", "classes", "dex"]:
        (out / name).mkdir()
    shutil.copytree(ROOT / "source", out / "source", dirs_exist_ok=True)
    env = dict(os.environ)
    for key in ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"]:
        env.pop(key, None)
    receipt = {"schema": "hepta.entry-sidecar.host-build.v1", "package": "org.trillionnium.hepta.entry", "compile_sdk": 34,
               "min_sdk": 36, "target_sdk": 36, "signed": False, "installed": False, "phone_operations": 0,
               "existing_HEPTA_or_Moto_APK_modified": False, "steps": []}
    def run(name, argv):
        result = subprocess.run([str(x) for x in argv], env=env, capture_output=True, timeout=120)
        (out / (name + ".stdout.txt")).write_bytes(result.stdout)
        (out / (name + ".stderr.txt")).write_bytes(result.stderr)
        receipt["steps"].append({"name": name, "rc": result.returncode, "argv": [str(x) for x in argv]})
        (out / "BUILD-RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(name + " failed; retained logs")
    run("aapt2-compile", [tools / "aapt2", "compile", "--dir", out / "source/res", "-o", out / "compiled-res.zip"])
    run("aapt2-link", [tools / "aapt2", "link", "-I", android, "--manifest", out / "source/AndroidManifest.xml",
                       "-R", out / "compiled-res.zip", "--java", out / "generated", "-o", out / "resources.apk",
                       "--min-sdk-version", "36", "--target-sdk-version", "36", "--version-code", "1", "--version-name", "1.0", "--auto-add-overlay"])
    sources = sorted((out / "source/src").rglob("*.java")) + sorted((out / "generated").rglob("*.java"))
    run("javac", [jdk / "bin/javac", "-J-XX:ActiveProcessorCount=2", "-J-Xmx1g", "-encoding", "UTF-8",
                  "-source", "8", "-target", "8", "-bootclasspath", android, "-classpath", android,
                  "-d", out / "classes", *sources])
    with zipfile.ZipFile(out / "classes.jar", "x") as archive:
        for p in sorted((out / "classes").rglob("*.class")):
            archive.write(p, p.relative_to(out / "classes"))
    run("d8", [jdk / "bin/java", "-XX:ActiveProcessorCount=2", "-Xmx1g", "-cp", tools / "lib/d8.jar",
               "com.android.tools.r8.D8", "--release", "--min-api", "36", "--lib", android,
               "--output", out / "dex", out / "classes.jar"])
    with zipfile.ZipFile(out / "resources.apk") as resources, zipfile.ZipFile(out / "unaligned.apk", "x") as target:
        for info in resources.infolist():
            target.writestr(info, resources.read(info))
        for p in sorted((out / "dex").glob("classes*.dex")):
            target.write(p, p.name, compress_type=zipfile.ZIP_STORED)
    apk = out / "HEPTA-Desktop-Entry-v1-unsigned.apk"
    run("zipalign", [tools / "zipalign", "-p", "4", out / "unaligned.apk", apk])
    run("zipalign-check", [tools / "zipalign", "-c", "-p", "4", apk])
    run("badging", [tools / "aapt2", "dump", "badging", apk])
    receipt.update(status="UNSIGNED_HOST_BUILD_COMPLETE_NOT_INSTALLED",
                   apk={"path": str(apk), "sha256": hashlib.sha256(apk.read_bytes()).hexdigest(), "bytes": apk.stat().st_size})
    (out / "BUILD-RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
