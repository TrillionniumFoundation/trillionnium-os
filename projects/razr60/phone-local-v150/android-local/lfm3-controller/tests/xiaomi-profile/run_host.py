#!/usr/bin/env python3
"""Real profile identity, PM adapter, catalogue and ownership policy; no phone IO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from android_ports import PORTS

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def actual_method(text, signature):
    """Copy the exact method; comments/literals do not affect brace matching."""
    if text.count(signature) != 1:
        raise AssertionError("method seam must be unique: " + signature)
    start = text.index(signature)
    begin = text.index("{", start)
    level = 0
    quote = None
    comment = None
    escaped = False
    i = begin
    while i < len(text):
        c = text[i]
        next_char = text[i + 1] if i + 1 < len(text) else ""
        if comment == "line":
            if c == "\n":
                comment = None
        elif comment == "block":
            if c == "*" and next_char == "/":
                comment = None
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == quote:
                quote = None
        elif c == "/" and next_char in ("/", "*"):
            comment = "line" if next_char == "/" else "block"
            i += 1
        elif c in ("'", '"'):
            quote = c
        elif c == "{":
            level += 1
        elif c == "}":
            level -= 1
            if level == 0:
                return text[start:i + 1]
        i += 1
    raise AssertionError("method body incomplete: " + signature)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    jar = args.json_jar.resolve()
    if digest(jar) != JSON_SHA:
        raise AssertionError("JSON dependency changed")
    output.mkdir(parents=True, exist_ok=False)
    ports = output / "ports"
    files = []
    for relative, text in PORTS.items():
        path = ports / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")
        files.append(path)
    bg = source / "src/org/trillionnium/hepta/background"
    local = source / "src/org/trillionnium/hepta/local"
    organizer = bg / "BackgroundTaskOrganizer.java"
    methods = [actual_method(organizer.read_text(), signature) for signature in (
        "    static Intent nativeHome(Context context, Intent launcher) throws Exception {",
        "    private static ActivityInfo registeredHome(Context context) throws Exception {")]
    organizer_port = ports / "org/trillionnium/hepta/background/BackgroundTaskOrganizer.java"
    organizer_port.parent.mkdir(parents=True, exist_ok=True)
    organizer_port.write_text("package org.trillionnium.hepta.background;\n"
        "import android.content.*;import android.content.pm.*;import java.io.IOException;import java.util.List;\n"
        "final class BackgroundTaskOrganizer {\n" + "\n".join(methods) + "\n}\n")
    files.append(organizer_port)
    names = ("ProfileIdentity", "ProfileTarget", "WindowOwnership", "BrokerProtocol", "PublicPermissionControllerUi",
        "PublicOwnGroupPolicy", "FixedIntentTools", "BackgroundOwnedTaskPolicy", "BackgroundOwnedSingleTask",
        "ProfileTaskPolicy", "ProfileOwnedTask", "ProfilePermissionTransient", "ProfileDisplayCustody", "ProfilePackages")
    files += [bg / (name + ".java") for name in names]
    files += [local / "ProfileCatalogueClient.java", source / "tests/profile-broker/ProfileBrokerHostTest.java",
        source / "tests/profile-identity/ProfileIdentityHostTest.java",
        Path(__file__).with_name("ProfileCatalogueHostTest.java"), Path(__file__).with_name("ProfilePackagesHostTest.java"),
        Path(__file__).with_name("XiaomiProfileBrokerHostTest.java")]
    tracked = files + [organizer, Path(__file__), Path(__file__).with_name("android_ports.py")]
    pins = {str(p): digest(p) for p in tracked}
    classes = output / "classes"
    classes.mkdir()
    jdk = args.java_home.resolve() / "bin"
    cp = str(classes) + os.pathsep + str(jar)
    commands = [
        ("compile", [jdk / "javac", "--release", "8", "-Xlint:all,-options", "-Werror", "-proc:none", "-encoding", "UTF-8",
            "-cp", jar, "-d", classes, *files]),
        ("catalogue", [jdk / "java", "-cp", cp, "org.trillionnium.hepta.local.ProfileCatalogueHostTest"]),
        ("target-user-package-reader", [jdk / "java", "-cp", cp, "org.trillionnium.hepta.background.ProfilePackagesHostTest", output / "pm-work"]),
        ("ctrip-identity-regression", [jdk / "java", "-cp", cp, "org.trillionnium.hepta.background.ProfileIdentityHostTest", output / "identity-cases.json"]),
        ("ctrip-owned-lifecycle", [jdk / "java", "-cp", cp, "org.trillionnium.hepta.background.ProfileBrokerHostTest"]),
        ("xiaomi-owned-lifecycle", [jdk / "java", "-cp", cp, "org.trillionnium.hepta.background.XiaomiProfileBrokerHostTest", "xiaomi"]),
    ]
    result = {"schema": "hepta.xiaomi-profile-host.v1", "all_pass": False, "source_inputs": pins, "stages": [],
        "actual_profile_packages": True, "actual_catalogue_decoder": True,
        "actual_native_home_methods_sha256": [hashlib.sha256(m.encode()).hexdigest() for m in methods],
        "android_pm_clock_stat_and_taskinfo_are_explicit_synthetic_ports": True,
        "actual_android_package_or_launch_qualified": False, "phone_actions": 0}
    for name, command in commands:
        started = time.monotonic()
        run = subprocess.run(list(map(str, command)), capture_output=True, timeout=180, cwd=output)
        (output / (name + ".stdout")).write_bytes(run.stdout)
        (output / (name + ".stderr")).write_bytes(run.stderr)
        stage = {"name": name, "exit_code": run.returncode, "elapsed_seconds": time.monotonic() - started,
            "stdout_sha256": hashlib.sha256(run.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(run.stderr).hexdigest()}
        if name != "compile" and run.returncode == 0:
            stage["cases"] = json.loads(run.stdout.decode().splitlines()[0])
        result["stages"].append(stage)
        if run.returncode:
            result["error"] = name + " failed"
            print(run.stderr.decode(errors="replace")[-10000:])
            break
    result["source_inputs_unchanged"] = pins == {str(p): digest(p) for p in tracked}
    result["all_pass"] = len(result["stages"]) == len(commands) and all(s["exit_code"] == 0 for s in result["stages"]) and result["source_inputs_unchanged"]
    (output / "RESULT.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"all_pass": result["all_pass"], "stages": result["stages"], "phone_actions": 0}, ensure_ascii=False))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

