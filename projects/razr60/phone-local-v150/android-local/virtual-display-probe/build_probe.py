#!/usr/bin/env python3
"""Build the unchanged, bounded Android display probe; never contacts a device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

SOURCE_SHA256 = "8e1e905c0eac4e7412e8657aff672f3d4baa4907c2fff82db7b3662de6d363b8"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv):
    result = subprocess.run([str(arg) for arg in argv], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            check=True)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, required=True, help="JDK 17 home")
    parser.add_argument("--sdk", type=Path, required=True,
                        help="Android SDK root or platform-34 android.jar")
    parser.add_argument("--d8-jar", type=Path, required=True,
                        help="D8/R8 jar containing com.android.tools.r8.D8")
    parser.add_argument("--out", type=Path, required=True,
                        help="New output directory; existing paths are refused")
    parser.add_argument("--expect-dex-sha256",
                        help="Optional exact DEX digest to require after compilation")
    args = parser.parse_args()
    source = Path(__file__).resolve().with_name("VirtualDisplayProbe.java")
    if not source.is_file() or digest(source) != SOURCE_SHA256:
        parser.error("VirtualDisplayProbe.java differs from the device-tested source")
    java, javac = (args.jdk.resolve() / "bin" / name for name in ("java", "javac"))
    android_jar = args.sdk.resolve()
    if android_jar.is_dir():
        android_jar = android_jar / "platforms" / "android-34" / "android.jar"
    d8_jar = args.d8_jar.resolve()
    output = args.out.absolute()
    for tool in (java, javac):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            parser.error("JDK executable missing or not executable: " + str(tool))
    for dependency in (android_jar, d8_jar):
        if not dependency.is_file():
            parser.error("Dependency is not a regular file: " + str(dependency))
    if output.exists() or output.is_symlink():
        parser.error("--out must not already exist")
    expected = args.expect_dex_sha256
    if expected and not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        parser.error("--expect-dex-sha256 must contain 64 hexadecimal characters")
    javac_version = run([javac, "-version"])
    java_version = run([java, "-version"])
    if not re.match(r"javac 17(?:[.\s]|$)", javac_version):
        parser.error("--jdk must provide javac 17")
    if not re.search(r'version "17(?:[."]|$)', java_version):
        parser.error("--jdk must provide java 17")
    d8_version = run([java, "-cp", d8_jar, "com.android.tools.r8.D8", "--version"])
    output.mkdir(parents=True)
    classes, dex_dir = output / "classes", output / "dex"
    classes.mkdir()
    dex_dir.mkdir()
    compile_log = run([javac, "-source", "8", "-target", "8", "-encoding", "UTF-8",
                       "-classpath", android_jar, "-d", classes, source])
    class_files = sorted(classes.rglob("*.class"))
    if not class_files:
        raise RuntimeError("javac did not create any class files")
    dex_log = run([java, "-cp", d8_jar, "com.android.tools.r8.D8",
                   "--min-api", "30", "--lib", android_jar,
                   "--output", dex_dir, *class_files])
    dex_files = sorted(dex_dir.glob("*.dex"))
    if [path.name for path in dex_files] != ["classes.dex"]:
        raise RuntimeError("Expected exactly one classes.dex output")
    dex = output / "probe.dex"
    shutil.copyfile(dex_files[0], dex)
    actual = digest(dex)
    manifest = {
        "schema": "hepta.virtual-display-probe.build.v1",
        "source_sha256": SOURCE_SHA256,
        "android_api": 34,
        "java_source": 8,
        "java_target": 8,
        "dex_min_api": 30,
        "javac_version": javac_version,
        "java_version": java_version,
        "d8_version": d8_version,
        "android_jar_sha256": digest(android_jar),
        "d8_jar_sha256": digest(d8_jar),
        "dex_file": "probe.dex",
        "dex_bytes": dex.stat().st_size,
        "dex_sha256": actual,
        "expected_dex_sha256": expected.lower() if expected else None,
        "expected_dex_matches": actual == expected.lower() if expected else None,
        "device_contacted": False,
    }
    (output / "javac.log").write_text(compile_log + "\n", encoding="utf-8")
    (output / "d8.log").write_text(dex_log + "\n", encoding="utf-8")
    (output / "build.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    if expected and actual != expected.lower():
        raise SystemExit("DEX digest differs from --expect-dex-sha256")


if __name__ == "__main__":
    main()
