#!/usr/bin/env python3
"""Complete production after-release Notes reader gate; synthetic Android I/O, no device operations."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time

sys.dont_write_bytecode = True
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
SYNTHETIC_SHA = "8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201"
READER_OLD_SHA = "38089d685875781319cec9b159822470d7b507c0fa8df6ceb13a00be158ee46f"
READER_NEW_SHA = "eb966bf1cb76822b6c694aa11d6f772158448abc3396f86152ec97ba28ab390c"
CUSTODY_OLD_SHA = "e39a101f7932d513e80b82799819ccd47b50aaef2d4d0cb5e7b63b9189eb8ccb"
BROKER_CTRIP_SHA = "2b4d591d05776046c74945220c6639da57acd87bc23aeaf55422924c1bf70f81"
LEGACY_RUNNER_SHA = "900d42feace5f1ce5af47e58a31eedcab991ac6925b51be84e57278b57287772"
RETAINED_INPUTS = {
    "src/org/trillionnium/hepta/background/BackgroundTaskOrganizer.java": "70eeb8e550dc77638687d5fa224fc2cd014f20991a1df94a232685244d9904ec",
    "tests/notes-task-info-reader/NotesTaskInfoReaderHostTest.java": "58e8222fc154eb4bb8ae69d64c19171587c24cea5124dbccd8c3f85854723c90",
    "tests/notes-task-info-reader/prepare_fixture.py": "884478f84b67f4c8679f60997d96ad6ea5389a657d2e39585854f078f453686d",
    "tests/notes-task-info-reader/synthetic-notes-census.json": "8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201",
    "tests/public-own-group-policy/PublicPhysicalAuditHostTest.java": "f5e1c8699e39f22fbb13eb7d2a007f85f38a4feeb34941556e6b6182f736fa72"
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    return digest(path.read_bytes())


# Proof-only inverse of the exact reviewed calendar additions. Actual source
# and actual method extraction below always remain the current broker bytes.
def reviewed_calendar_broker_inverse(text):
    raw = text.encode("utf-8")
    actual = digest(raw)
    # Proof-only reverse of the exact reviewed first-error preservation block.
    # Actual broker compilation and method extraction below still use current source.
    if actual == "f21aa2b52ecb77b253db4b6a0edb421e4554ff1f83779c7e7bd5f8a0eb9ea888":
        if len(raw) != 137047:
            raise RuntimeError("Reviewed first-error broker byte length changed")
        addition = b'                    String firstError=retired.optString("error","");\n                    boolean keepCalendarFailure=("calendar_probe".equals(request.operation)||"calendar_date".equals(request.operation))\n                            &&Boolean.FALSE.equals(retired.opt("ok"))&&!firstError.isEmpty();\n                    retired.put("ok",false).put("error",keepCalendarFailure?firstError:"PUBLIC_SCOPE_RETIRED").put("state",state)\n                        .put("public_scope_admission_retired",true).put("public_scope_closing",true)\n                        .put("public_own_group_readback_wire",JSONObject.NULL).put("public_surface_detach",publicDetachEvidence());\n                    if(keepCalendarFailure)retired.put("public_scope_retirement_error","PUBLIC_SCOPE_RETIRED");\n'
        original = b'                    retired.put("ok",false).put("error","PUBLIC_SCOPE_RETIRED").put("state",state)\n                        .put("public_scope_admission_retired",true).put("public_scope_closing",true)\n                        .put("public_own_group_readback_wire",JSONObject.NULL).put("public_surface_detach",publicDetachEvidence());\n'
        if raw.count(addition) != 1 or digest(addition) != "399d66e1eb1a16869e62d579c95c37c03459e4f45fba51bae33aa40d59388279":
            raise RuntimeError("Reviewed first-error broker block changed")
        restored = raw.replace(addition, original, 1)
        if len(restored) != 136605 or digest(restored) != "345469e3212a99d8fbb973316ade9198f9b8abeb0f40a10ddb3de8c84b36d708":
            raise RuntimeError("First-error inverse did not restore exact reviewed broker")
        projected, prior = reviewed_calendar_broker_inverse(restored.decode("utf-8"))
        if prior.get("applied") is not True:
            raise RuntimeError("Original calendar inverse is still required")
        proof = dict(prior)
        proof.update(actual_sha256=actual, actual_bytes=len(raw),
                     exact_changed_blocks=prior["exact_changed_blocks"] + 1,
                     first_error_inverse={
                         "current_sha256": actual, "current_bytes": len(raw),
                         "block_sha256": "399d66e1eb1a16869e62d579c95c37c03459e4f45fba51bae33aa40d59388279", "block_bytes": len(addition),
                         "restored_sha256": "345469e3212a99d8fbb973316ade9198f9b8abeb0f40a10ddb3de8c84b36d708", "restored_bytes": len(restored),
                         "proof_only_not_compiled_or_executed": True,
                     }, calendar_inverse=prior)
        return projected, proof
    current = "345469e3212a99d8fbb973316ade9198f9b8abeb0f40a10ddb3de8c84b36d708"
    previous = "d3e4e57392fe641dbe68bd04453213522b2d88c41d6ba9dc2cda08e69ae8632b"
    if actual != current:
        return text, {"applied": False, "actual_sha256": actual}
    if len(raw) != 136605:
        raise RuntimeError("Reviewed calendar broker byte length changed")
    # Exact current-byte offsets, whole block SHA256, and original replacement.
    changes = (
    (963, 996, '6ab58abc9ea23897f61187e8a9d150de0bc48865b9de7059aa0d797322f5010a', b''),
    (2593, 3016, '645bffcfbd6e26324c915a8d2604ce58fa10d599de360ff5ef8986a71eec9bad', b''),
    (31469, 31904, 'c4b97d391d7464919cde1cfc14bba94ae30486f98c597eb9bddf5d518101c5df', b''),
    (51743, 75631, '319070e008988c92bb2cce70e9302b4d6cad05a21755acd3620fd38fc3547f10', b''),
    (102689, 102867, 'adf0494b63360b2c8454ccd50d61f7250979f204504d7a04ec8dbdc0a1013b22', b'        return bootReadRetirementFailure==null?"RELEASED":"CLEANUP_UNKNOWN";\n'),
    (103284, 103391, '44e26acb5017bc8c51bf1b8a7b4e54475b4ed78cbce5ecf226136674adf01de3', b''),
    (122636, 123007, '56172ed729d4859ac311b1e2320dc9c3f92aa3f75349d5d24a282b682f1698cb', b''),
    (135712, 135825, 'b4b93e7fe9acf03959d291058367a9ee58d53e1d6989ef26916bbc2b8ab0d07f', b''),
    )
    for start, end, expected, original in reversed(changes):
        if not (0 <= start < end <= len(raw)) or digest(raw[start:end]) != expected:
            raise RuntimeError("Reviewed calendar broker delta changed")
        raw = raw[:start] + original + raw[end:]
    if len(raw) != 111134 or digest(raw) != previous:
        raise RuntimeError("Reviewed calendar broker did not restore exact prior source")
    return raw.decode("utf-8"), {
        "applied": True, "actual_sha256": current, "actual_bytes": 136605,
        "prior_sha256": previous, "prior_bytes": 111134,
        "exact_changed_blocks": len(changes),
        "proof_only_not_compiled_or_executed": True,
        "original_full_source_pin_still_required": True,
    }


def remove_addition(text, begin, end):
    if text.count(begin) != 1 or text.count(end) != 1:
        raise RuntimeError("Exact additive source boundaries changed")
    first = text.index(begin)
    last = text.index(end, first)
    return text[:first] + text[last:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "java-home", "json-jar", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    jdk = args.java_home.resolve(strict=True)
    jar = args.json_jar.resolve(strict=True)
    output = args.output.absolute()
    if output == source or source in output.parents:
        raise RuntimeError("Output must remain outside source")
    output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    if here != source / "tests/notes-after-release-reader":
        raise RuntimeError("Runner does not belong to supplied source")
    original = source / "tests/notes-task-info-reader"
    background = source / "src/org/trillionnium/hepta/background"
    fixture = original / "synthetic-notes-census.json"
    names = ["BrokerProtocol", "PublicPermissionControllerUi", "FixedIntentTools", "FixedIntentTarget",
             "ProfileIdentity", "ProfileTarget", "BackgroundOwnedTaskPolicy", "BackgroundOwnedSingleTask",
             "ProfileTaskPolicy", "PublicOwnGroupTaskFence", "PublicOwnGroupPolicy", "PublicOwnGroupPhysicalFence",
             "PublicPersonalNotesCustody", "BackgroundTaskOrganizer", "PublicPersonalNotesReader"]
    files = [background / (name + ".java") for name in names]
    files += [source / "tests/public-own-group-policy/PublicPhysicalAuditHostTest.java",
              original / "NotesTaskInfoReaderHostTest.java", here / "NotesAfterReleaseReaderHostTest.java"]
    broker = background / "BackgroundDisplayBroker.java"
    tracked = set(files + [broker, fixture, original / "run_host.py", original / "prepare_fixture.py",
                          original / "README.md", here / "run_host.py", here / "README.md"])
    tools = [jar, jdk / "bin/javac", jdk / "bin/java", jdk / "lib/ct.sym"]
    result = {"schema": "hepta.notes-after-release-reader-gate.v1", "all_pass": False,
              "phone_operations": 0, "android_runtime": False, "hardware_qualification_claimed": False,
              "framework_and_binder_fixtures_synthetic": True, "stages": []}
    pins, tool_pins = {}, {}
    env = dict(os.environ)
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "PYTHONPATH"):
        env.pop(key, None)
    env.update(JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin",
               PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")

    def run(name, argv):
        began = time.monotonic()
        process = subprocess.run(list(map(str, argv)), cwd=source, env=env, capture_output=True, timeout=120)
        (output / (name + ".stdout")).write_bytes(process.stdout)
        (output / (name + ".stderr")).write_bytes(process.stderr)
        result["stages"].append({"name": name, "exit_code": process.returncode,
                                 "elapsed_seconds": time.monotonic() - began,
                                 "stdout_sha256": digest(process.stdout), "stderr_sha256": digest(process.stderr)})
        if process.returncode or process.stderr:
            raise RuntimeError(name + " failed; inspect exact stage outputs")
        return process.stdout

    try:
        pins = {str(path.relative_to(source)): sha(path) for path in sorted(tracked)}
        tool_pins = {str(path): sha(path) for path in tools}
        result["source_inputs"] = pins
        result["tool_inputs"] = tool_pins
        if jar.stat().st_size != 78332 or sha(jar) != JSON_SHA:
            raise RuntimeError("Pinned JSON dependency differs")
        if fixture.stat().st_size != 18714 or sha(fixture) != SYNTHETIC_SHA:
            raise RuntimeError("Synthetic derived fixture changed")
        for relative, expected in RETAINED_INPUTS.items():
            if sha(source / relative) != expected:
                raise RuntimeError("Retained fixture or organizer changed: " + relative)
        result["retained_inputs_unchanged"] = dict(RETAINED_INPUTS)
        reader = (background / "PublicPersonalNotesReader.java").read_text()
        projected_reader = remove_addition(reader,
                "    /** Post-release sampling keeps the actual custody snapshot.",
                "    private Map<Integer,BackgroundOwnedSingleTask.Task> index(")
        custody = (background / "PublicPersonalNotesCustody.java").read_text()
        projected_custody = remove_addition(custody,
                "    /** A private-constructor snapshot of actual released custody, never a wire",
                "    synchronized boolean needsActualTasks(")
        if digest(projected_reader.encode()) != READER_OLD_SHA or digest(projected_custody.encode()) != CUSTODY_OLD_SHA:
            raise RuntimeError("Existing runtime reader/custody behavior changed")
        old_call = "remaining=publicNotesReader.frame();live=remaining.global;"
        new_call = "remaining=publicNotesReader.frameAfterRelease(custody.releasedRead());live=remaining.global;"
        broker_text = broker.read_text()
        prior_broker, calendar_inverse = reviewed_calendar_broker_inverse(broker_text)
        result["reviewed_calendar_broker_inverse"] = calendar_inverse
        if (broker_text.count(new_call) != 1
                or digest(prior_broker.replace(new_call, old_call, 1).encode()) != BROKER_CTRIP_SHA):
            raise RuntimeError("Broker differs beyond the reviewed after-release read")
        cleanup = broker_text[broker_text.index("    private void beginPublicNotesCleanup(){"):
                              broker_text.index("    private boolean publicOwnedDisplayAbsent()")]
        if not (cleanup.index("custody.enterRelease();virtual.release();custody.releaseReturned();")
                < cleanup.index("if(!publicOwnedDisplayAbsent())")
                < cleanup.index(new_call)
                < cleanup.index("custody.observeAbsence(live,recents,remaining,publicOwnedDisplayAbsent()")
                < cleanup.index("if(custody.known())")):
            raise RuntimeError("Release/display/custody guard order changed")
        if broker_text.count(".frameAfterRelease(") != 1:
            raise RuntimeError("After-release reader gained another broker call")
        legacy_runner = (original / "run_host.py").read_text()
        if (legacy_runner.count(READER_NEW_SHA) != 1
                or digest(legacy_runner.replace(READER_NEW_SHA, READER_OLD_SHA, 1).encode()) != LEGACY_RUNNER_SHA):
            raise RuntimeError("Original reader gate changed beyond the exact new-reader pin")
        result["static_scope"] = {"ordinary_reader_and_custody_exact_projection": True,
                                  "broker_exact_single_call_projection": True,
                                  "legacy_runner_only_reader_pin_changed": True,
                                  "after_actual_release_return_and_display_absence_only": True,
                                  "original_two_absence_cleanup_gate_unchanged": True,
                                  "android_broker_wiring_static_only": True}
        run("retained-notes-reader", [sys.executable, "-B", original / "run_host.py",
                                     "--source", source, "--java-home", jdk, "--json-jar", jar,
                                     "--output", output / "retained-notes-reader"])
        legacy = json.loads((output / "retained-notes-reader/RESULT.json").read_text())
        if not (legacy.get("all_pass") is True and legacy.get("inputs_unchanged") is True
                and legacy["reflection_cases"]["cases"] == 71
                and legacy["reflection_cases"]["assertions"] == 238
                and legacy["reflection_cases"]["empty_activity"]["cases"] == 14
                and legacy["reflection_cases"]["empty_activity"]["assertions"] == 59
                and legacy["reflection_cases"]["taskinfo_stability"]["cases"] == 12
                and legacy["reflection_cases"]["taskinfo_stability"]["assertions"] == 60
                and legacy["original_private_cases"]["cases"] == 47
                and legacy["original_private_cases"]["assertions"] == 449):
            raise RuntimeError("Original reader/custody/private cases not fully retained")
        result["retained_gate"] = {"path": str(output / "retained-notes-reader/RESULT.json"),
                                  "sha256": sha(output / "retained-notes-reader/RESULT.json"),
                                  "all_pass": True, "cases": 144, "assertions": 806}
        spec = importlib.util.spec_from_file_location("retained_notes_android_io_ports", original / "prepare_fixture.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        stubs = helper.prepare(output / "android-host-ports")
        classes = output / "classes"
        flags = ["--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror", "-proc:none"]
        run("compile-after-release", [jdk / "bin/javac", *flags, "-cp", jar, "-d", classes, *files, *stubs])
        stdout = run("after-release-cases", [jdk / "bin/java", "-ea", "-cp", str(classes) + os.pathsep + str(jar),
                                           "org.trillionnium.hepta.background.NotesAfterReleaseReaderHostTest", fixture])
        summary = json.loads(stdout.decode().splitlines()[-1])
        names = summary.get("case_names")
        if not (summary.get("schema") == "hepta.notes-after-release-reader-host.v1"
                and summary.get("all_pass") is True and summary.get("cases") == 112
                and type(names) is list and len(names) == len(set(names)) == 112
                and type(summary.get("assertions")) is int and summary["assertions"] > 0
                and summary.get("complete_production_reader_organizer_custody") is True
                and summary.get("framework_and_binder_fixtures_synthetic") is True
                and summary.get("fixture_sha256") == SYNTHETIC_SHA
                and type(summary.get("phone_operations")) is int and summary["phone_operations"] == 0
                and summary.get("android_runtime") is False
                and summary.get("hardware_qualification_claimed") is False):
            raise RuntimeError("After-release result contract differs")
        result["after_release_summary"] = summary
        result["source_inputs_unchanged"] = pins == {
            str(path.relative_to(source)): sha(path) for path in sorted(tracked)}
        result["tool_inputs_unchanged"] = tool_pins == {str(path): sha(path) for path in tools}
        result["all_pass"] = (len(result["stages"]) == 3 and result["source_inputs_unchanged"]
                              and result["tool_inputs_unchanged"])
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
    (output / "RESULT.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"all_pass": result["all_pass"], "error": result.get("error"),
                      "summary": result.get("after_release_summary"),
                      "result": str(output / "RESULT.json"), "result_sha256": sha(output / "RESULT.json")}))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
