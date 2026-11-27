#!/usr/bin/env python3
"""Pure ordinary-capture regression; synthetic data and no Android or phone IO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
EXPECTED = [
    "synthetic_normal_complete_equal_phase_capture",
    "synthetic_normal_phase_only_difference_refused_before_projection",
    "synthetic_normal_equal_invalid_phase_unknown",
    "synthetic_normal_equal_invalid_phase_failed",
    "synthetic_normal_equal_invalid_phase_last_sample_started_elapsed_ms",
    "synthetic_normal_equal_invalid_phase_business_admission_restored",
    "synthetic_normal_equal_invalid_phase_serialized_evidence_is_authority",
    "synthetic_normal_full_equality_profile_last_leaf_validation",
    "synthetic_normal_full_equality_public_surface_detach",
]
EXPECTED_NAMES_SHA = "087d4418ea7a3702f9ba876a3c43f8dad07e92e535c5551e91c801481124585f"


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def ref(path):
    path = Path(path)
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode), "regular unchanged input required")
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                mode=stat.S_IMODE(st.st_mode))


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def write(path, value):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(encoded(value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    need(not output.exists() and source != output and source not in output.parents,
         "new output outside source required")
    java_home = args.java_home.resolve(strict=True)
    java, javac = java_home / "bin/java", java_home / "bin/javac"
    jar = args.json_jar.resolve(strict=True)
    need(ref(jar)["sha256"] == JSON_SHA and ref(jar)["bytes"] == 78332,
         "pinned org.json 20240303 required")
    harness = source / "tests/public-profile-business-recovery/PublicProfileNormalCaptureHostTest.java"
    runner = Path(__file__).resolve(strict=True)
    production = sorted((source / "src").rglob("*.java"))
    tracked = production + [harness, runner]
    before = {str(path): ref(path) for path in tracked}
    tools_before = {name: ref(path) for name, path in (("java", java), ("javac", javac), ("json_jar", jar))}
    output.mkdir(mode=0o700)
    write(output / "INPUTS-BEFORE.json", before)
    write(output / "TOOLS-BEFORE.json", tools_before)
    result = dict(schema="hepta.public-profile-normal-capture-run.v1", all_pass=False,
                  source=str(source), source_inputs=before, tools_before=tools_before,
                  fixture_kind="synthetic_normal_retained_capture", private_originals_used=False,
                  complete_request_executed=False, legacy_path_replayed=False,
                  actual_comparator_executed=False, phone_operations=0, stages=[])

    def stage(name, argv):
        started = time.monotonic()
        try:
            process = subprocess.run([str(x) for x in argv], cwd=source, capture_output=True, timeout=60)
            code, stdout, stderr, error = process.returncode, process.stdout, process.stderr, None
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr, error = None, exc.stdout or b"", exc.stderr or b"", "timeout after 60 seconds"
        except Exception as exc:
            code, stdout, stderr, error = None, b"", b"", repr(exc)
        for suffix, raw in (("stdout", stdout), ("stderr", stderr)):
            with (output / (name + "." + suffix)).open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
        result["stages"].append(dict(name=name, argv=[str(x) for x in argv], cwd=str(source),
            exit_code=code, error=error, elapsed_seconds=time.monotonic()-started,
            stdout=ref(output/(name+".stdout")), stderr=ref(output/(name+".stderr"))))
        need(code == 0, name + " failed")
        return stdout

    try:
        classes = output / "classes"
        classes.mkdir(mode=0o700)
        stage("compile", [javac, "--release", "8", "-proc:none", "-Xlint:all,-options", "-Werror",
            "-encoding", "UTF-8", "-cp", jar, "-sourcepath", source/"src", "-d", classes, harness])
        raw = stage("normal-capture", [java, "-Xmx512m", "-cp", str(classes)+os.pathsep+str(jar),
            "org.trillionnium.hepta.background.PublicProfileNormalCaptureHostTest"])
        cases = json.loads(raw)
        names = cases.get("case_names")
        need(cases.get("schema") == "hepta.public-profile-normal-capture-host.v1"
             and cases.get("passed") is True and cases.get("cases") == 9 and cases.get("assertions") == 11
             and names == EXPECTED and len(set(names)) == 9
             and hashlib.sha256(json.dumps(names, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest() == EXPECTED_NAMES_SHA
             and cases.get("fixture_kind") == "synthetic_normal_retained_capture"
             and cases.get("actual_comparator_executed") is True and cases.get("complete_request_executed") is False
             and cases.get("private_originals_used") is False and cases.get("phone_commands") == 0,
             "complete ordinary capture case contract differs")
        write(output / "CASES.json", cases)
        result["cases"] = cases
        result["case_result"] = ref(output / "CASES.json")
        result["case_names_sha256"] = EXPECTED_NAMES_SHA
        result["actual_comparator_executed"] = True
        result["all_pass"] = True
    except Exception as exc:
        result["error"] = repr(exc)
    finally:
        after = {str(path): ref(path) for path in sorted((source / "src").rglob("*.java")) + [harness, runner]}
        tools_after = {name: ref(path) for name, path in (("java", java), ("javac", javac), ("json_jar", jar))}
        write(output / "INPUTS-AFTER.json", after)
        write(output / "TOOLS-AFTER.json", tools_after)
        result["source_inputs_unchanged"] = before == after
        result["tools_unchanged"] = tools_before == tools_after
        result["all_pass"] = result["all_pass"] and result["source_inputs_unchanged"] and result["tools_unchanged"]
        result["tools_after"] = tools_after
        write(output / "RESULT.json", result)
        print(json.dumps(dict(all_pass=result["all_pass"], result=ref(output/"RESULT.json"),
                             cases=result.get("cases"), phone_operations=0)))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
