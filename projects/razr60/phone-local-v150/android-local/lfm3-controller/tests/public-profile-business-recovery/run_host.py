#!/usr/bin/env python3
"""Real pure Policy with complete external originals; synthetic current runtime facts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()

def write(path, value):
    with path.open("xb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(encoded(value))

def ref(path):
    path = Path(path).resolve(strict=True)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError("regular file required")
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), mode=stat.S_IMODE(st.st_mode))

def inventory(source):
    result = {}
    for path in sorted(source.rglob("*")):
        if any(part in (".git", "__pycache__") for part in path.relative_to(source).parts):
            continue
        if path.is_symlink():
            raise RuntimeError("source symlink")
        if path.is_file():
            r = ref(path)
            r.pop("path")
            result[path.relative_to(source).as_posix()] = r
    return result

def external_refs(manifest, paths):
    mapping = json.loads(paths.read_bytes())
    result = {"manifest": ref(manifest), "path_map": ref(paths)}
    for relative, path in sorted(mapping.items()):
        result[relative] = ref(path)
    return result

def stage(name, argv, output, cwd):
    before = time.monotonic()
    error = None
    try:
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, timeout=120)
        code, stdout, stderr = p.returncode, p.stdout, p.stderr
    except Exception as exc:
        code, stdout, stderr = None, b"", str(exc).encode()
        error = repr(exc)
    for suffix, data in (("stdout", stdout), ("stderr", stderr)):
        path = output / (name + "." + suffix)
        with path.open("xb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
    return dict(name=name, argv=argv, cwd=str(cwd), exit_code=code, error=error,
                elapsed_seconds=time.monotonic()-before,
                stdout=ref(output/(name+".stdout")), stderr=ref(output/(name+".stderr")))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--original-paths", required=True, type=Path)
    ap.add_argument("--java-home", required=True, type=Path)
    ap.add_argument("--json-jar", required=True, type=Path)
    args = ap.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    manifest = args.manifest.resolve(strict=True)
    original_paths = args.original_paths.resolve(strict=True)
    java = args.java_home.resolve(strict=True)/"bin/java"
    javac = args.java_home.resolve(strict=True)/"bin/javac"
    jar = args.json_jar.resolve(strict=True)
    script = Path(__file__).resolve(strict=True)
    host_test = source/"tests/public-profile-business-recovery/PublicProfileBusinessRecoveryHostTest.java"
    before = inventory(source)
    tools_before = {n: ref(p) for n,p in (("java",java),("javac",javac),("json_jar",jar),("runner",script))}
    originals_before = external_refs(manifest, original_paths)
    write(output/"SOURCE-BEFORE.json", before)
    write(output/"ORIGINALS-BEFORE.json", originals_before)
    classes = output/"classes"
    classes.mkdir(mode=0o700)
    argv = [str(javac), "--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror",
            "-cp", str(jar), "-sourcepath", str(source/"src"), "-d", str(classes), str(host_test)]
    stages = [stage("compile", argv, output, source)]
    if stages[0]["exit_code"] == 0:
        stages.append(stage("policy", [str(java), "-Xmx512m", "-cp", str(classes)+os.pathsep+str(jar),
            "org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest", str(manifest),
            str(original_paths), str(output/"POLICY-RESULT.json")], output, source))
    after = inventory(source)
    originals_after = external_refs(manifest, original_paths)
    tools_after = {n: ref(p) for n,p in (("java",java),("javac",javac),("json_jar",jar),("runner",script))}
    write(output/"SOURCE-AFTER.json", after)
    write(output/"ORIGINALS-AFTER.json", originals_after)
    used = set()
    for compiled in classes.rglob("*.class"):
        relative = compiled.relative_to(classes).as_posix().split("$")[0]
        if relative.endswith(".class"):
            relative=relative[:-6]
        candidate = source/"src"/(relative+".java")
        if candidate.is_file():
            used.add(candidate.relative_to(source).as_posix())
    used.add(host_test.relative_to(source).as_posix())
    inputs = {}
    for relative in sorted(used):
        inputs[relative] = ref(source/relative)
    report = output/"POLICY-RESULT.json"
    assertions = json.loads(report.read_bytes()) if report.exists() else None
    passed = (len(stages)==2 and all(row["exit_code"]==0 for row in stages)
        and assertions is not None and assertions["status"]=="PASS"
        and before==after and originals_before==originals_after and tools_before==tools_after)
    result = dict(schema="hepta.public-profile-business-recovery-host.v1", all_pass=passed,
        source=str(source), stages=stages, inputs=inputs, input_count=len(inputs),
        source_before=ref(output/"SOURCE-BEFORE.json"), source_after=ref(output/"SOURCE-AFTER.json"),
        source_unchanged=before==after, tools_before=tools_before, tools_after=tools_after,
        tools_unchanged=tools_before==tools_after, external_originals_before=ref(output/"ORIGINALS-BEFORE.json"),
        external_originals_after=ref(output/"ORIGINALS-AFTER.json"), external_originals_unchanged=originals_before==originals_after,
        original_refs=originals_before, report=ref(report) if report.exists() else None,
        counts=({"cases":assertions["cases"],"assertions":assertions["assertions"]} if assertions else None),
        actual_pure_policy_executed=True, actual_session_recovery_decision_executed=True,
        fixture_boundary="actual original bytes; synthetic current controller/stat/clock/root samples/archive-root; no Android IO/root census/CAS",
        phone_commands=0, production_source_writes=0)
    write(output/"RESULT.json", result)
    print(json.dumps(dict(all_pass=passed,counts=result["counts"],input_count=len(inputs),
        result=ref(output/"RESULT.json"),stages=[dict(name=x["name"],exit_code=x["exit_code"])for x in stages])))
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
