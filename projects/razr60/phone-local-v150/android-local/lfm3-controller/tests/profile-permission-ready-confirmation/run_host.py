#!/usr/bin/env python3
"""Pure-JVM ready-confirmation gate using real production ownership and pair-read methods."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
SYNTHETIC_SHA = "7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0"
PROTECTED_METHODS = {
    "src/org/trillionnium/hepta/background/ProfileOwnedTask.java": {
        "private BackgroundOwnedSingleTask.Task observeStateSample(": "db9f4e1195dd432eb2c27e01139ae708a5aecdd30b06ba873d529bbcf1d890ae",
        "private BackgroundOwnedSingleTask.Task observeTree(boolean visible)": "368f5de1dadd0ccdbd788b0330db9e1c55e4ac61f191475230819f7410c15ad9",
        "private BackgroundOwnedSingleTask.Task observeTreeSample(boolean visible)": "c61dd8b4ad614ed5f20ee4308cfd939c630d784d2dfdcdb5a48d6126647dd048",
        "private BackgroundOwnedSingleTask.Task observeTreeSample(boolean visible,": "141f1b5420bd8df57b4d003b065c798adb82d4639284b40a05d7749de6b14718",
        "private ProfilePermissionTransient.Proof permissionForOwnedPair(": "f533d19ba55dccda1e0c52eb750aa7a3967d03e8febf2fcdc4ce2b778833ca10",
        "public synchronized PermissionRead permissionForInitialization(": "08af957773c0a6ad1a66870d1216a782e1b561528e6c62924a00bfc704598075",
        "public synchronized String initializationState(long deadline)": "88ae0773bb13bc1ce75217aa99c8190d3e6d6f3dfaf3a3ecd538ac07ed369ffb",
        "public synchronized WindowOwnership window(": "64e4b9138e86b0f0678528cc882418bcb642d2dbf03b1c53dc8bb7b4fa5e466a",
        "public synchronized boolean observe()": "fb414f8409ff540850ce005ec8cc19ce84d65aaeed9279ad251ed25cf47fdacd",
        "public synchronized boolean observeStateUntil(long deadline)": "720585edb5daf797d9281b4a9ee2c9afc216000a6388444f8f9799e32a3e9eb3",
        "public synchronized void retire(long deadline)": "d41308e38a24eaed85586c44eec9e129d8bc318f91fbe4d3c00f0d62bc258d8f"
    },
    "src/org/trillionnium/hepta/background/ProfilePermissionTransient.java": {
        "private static boolean permissionToTarget(": "9204f668ffac62febcf25e0bdf56f4d9ec25a9af677460f6d8a2bef0b8224aac",
        "static boolean mayReadCookieExitLeaf(": "2db2d3f465d654d26b68bfaa6aa18d59912d5bdbe943953af2270855caad02e1",
        "static boolean sameReadIdentity(": "60338e3f1bdabc9cf92c48856ea16dae7876178084f4cc1040d17eb2fc4254f2",
        "static boolean sameTaskInfo(": "8542c0b6dca16d5d9cc26d23790e163798598c0941c34aab624e2e86fad60e54",
        "static void requireCookieExitRead(": "96b1fe66f38592b73f8e3af7035dc7a7bf46677ccf698e5956b82a681ccbf7c5"
    }
}
RETAINED_FILES = {
    "src/org/trillionnium/hepta/background/ProfileTaskPlatform.java": "ecdd2e0ee3153456042bc8c76dda9d122d8617ee432aaf551e1b0cdfb9f4ac84",
    "tests/profile-broker/ProfileBrokerHostTest.java": "5880a651260aa18566364f4dbca427c5adbba8048eee7f1b8a3d55f4a6f69e04",
    "tests/profile-permission-transient/ProfilePermissionTransientHostTest.java": "7ac5d394010ca7e42e87ea7902bd96dd425530df3eaf4f485a8ce5efb529f162",
    "tests/profile-permission-transient/ProfileStateSettleHostTest.java": "e1b13341ce3db24921f78b4c378c7635253d659abb44027b3d582a0d808a2cf1",
    "tests/profile-permission-transient/README.md": "3fd9faa14bb74fdc8a6c660774750a78717043c0ba46b0c6271566365a449a80",
    "tests/profile-permission-transient/fixtures/synthetic-activities.txt": "7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0",
    "tests/profile-permission-transient/run_host.py": "b02634c4bf63b028213bab70cd3abed2bd26960f911064a8c2b9762df78ec939"
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


def method(text, marker):
    if text.count(marker) != 1:
        raise RuntimeError("Method marker not unique: " + marker)
    start = text.index(marker)
    first = text.index("{", start)
    depth, index, state = 0, first, "code"
    while index < len(text):
        char = text[index]
        pair = text[index:index + 2]
        if state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if pair == "*/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if char == "\\":
                index += 1
            elif char == ('"' if state == "string" else "'"):
                state = "code"
        elif pair == "//":
            state = "line"
            index += 1
        elif pair == "/*":
            state = "block"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
        index += 1
    raise RuntimeError("Method block not complete: " + marker)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "java-home", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    if output == source or source in output.parents:
        raise RuntimeError("Test output must remain outside source")
    output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    if here != source / "tests/profile-permission-ready-confirmation":
        raise RuntimeError("Runner does not belong to the supplied source")
    original = source / "tests/profile-permission-transient"
    background = source / "src/org/trillionnium/hepta/background"
    fixture = original / "fixtures/synthetic-activities.txt"
    names = ["ProfileIdentity", "ProfileTarget", "WindowOwnership", "BrokerProtocol",
             "PublicPermissionControllerUi", "PublicOwnGroupPolicy", "FixedIntentTools",
             "BackgroundOwnedTaskPolicy", "BackgroundOwnedSingleTask", "ProfileTaskPolicy",
             "ProfileOwnedTask", "ProfilePermissionTransient", "ProfileDisplayCustody"]
    files = [background / (name + ".java") for name in names]
    files += [source / "tests/profile-broker/ProfileBrokerHostTest.java",
              original / "ProfilePermissionTransientHostTest.java",
              here / "ProfileReadyConfirmationHostTest.java"]
    platform = background / "ProfileTaskPlatform.java"
    broker = background / "BackgroundDisplayBroker.java"
    tracked = set(files + [platform, broker, fixture, here / "run_host.py", here / "README.md",
                          original / "run_host.py", original / "ProfileStateSettleHostTest.java",
                          original / "README.md", source / "src/org/trillionnium/hepta/local/BackgroundSession.java"])
    result = {"schema": "hepta.profile-ready-confirmation-canonical-host.v1",
              "all_pass": False, "phone_contacted": False, "android_build": False,
              "android_adapters_compiled": False, "java_release": 8,
              "taskinfo_fixtures_synthetic": True, "source_inputs": {}, "stages": []}
    pins = {}

    def run(name, argv):
        started = time.monotonic()
        completed = subprocess.run(argv, capture_output=True, timeout=120)
        (output / (name + ".stdout")).write_bytes(completed.stdout)
        (output / (name + ".stderr")).write_bytes(completed.stderr)
        result["stages"].append({"name": name, "exit_code": completed.returncode,
                                 "elapsed_seconds": time.monotonic() - started,
                                 "stdout_sha256": digest(completed.stdout),
                                 "stderr_sha256": digest(completed.stderr)})
        if completed.returncode or completed.stderr:
            raise RuntimeError(name + " failed; see stage stdout/stderr")
        return completed.stdout

    try:
        pins = {str(path.relative_to(source)): sha(path) for path in sorted(tracked)}
        result["source_inputs"] = pins
        retained = {}
        for relative, expected in RETAINED_FILES.items():
            actual = sha(source / relative)
            if actual != expected:
                raise RuntimeError("Retained baseline fixture changed: " + relative)
            retained[relative] = actual
        result["retained_328a_files_unchanged"] = retained
        checks = []
        for relative, methods in PROTECTED_METHODS.items():
            current = (source / relative).read_text()
            for marker, expected in methods.items():
                actual = digest(method(current, marker).encode())
                if actual != expected:
                    raise RuntimeError("Ordinary method changed: " + relative + ": " + marker)
                checks.append({"path": relative, "marker": marker, "sha256": actual})
        result["protected_original_methods"] = checks
        broker_text = broker.read_text()
        ready_call = "profileOwnedTask.confirmInitializationReady(Math.min(r.deadline,expires))"
        begin = broker_text.index('} else if(config.profileTarget!=null&&"prepare_done".equals(r.operation)) {')
        end = broker_text.index('} else if(config.profileTarget!=null&&"launch".equals(r.operation)) {', begin)
        branch = broker_text[begin:end]
        if (broker_text.count(".confirmInitializationReady(") != 1 or branch.count(ready_call) != 1
                or branch.index("initializationState(") >= branch.index("requirePermissionPhysicalUnchanged(")
                or branch.index("requirePermissionPhysicalUnchanged(") >= branch.index(ready_call)
                or branch.index(ready_call) >= branch.index('profilePreparationState="COMPLETE"')):
            raise RuntimeError("Ready confirmation is not exactly the final preparation read")
        calls = []
        for path in sorted((source / "src").rglob("*.java")):
            count = path.read_text().count(".confirmInitializationReady(")
            if count:
                calls.append({"path": str(path.relative_to(source)), "count": count})
        if calls != [{"path": str(broker.relative_to(source)), "count": 1}]:
            raise RuntimeError("Ready confirmation gained another production call site")
        notes_old_call = "remaining=publicNotesReader.frame();live=remaining.global;"
        notes_new_call = "remaining=publicNotesReader.frameAfterRelease(custody.releasedRead());live=remaining.global;"
        if broker_text.count(notes_new_call) != 1:
            raise RuntimeError("Exact independent Notes cleanup call differs")
        prior_broker, calendar_inverse = reviewed_calendar_broker_inverse(broker_text)
        result["reviewed_calendar_broker_inverse"] = calendar_inverse
        ready_broker = prior_broker.replace(notes_new_call, notes_old_call, 1)
        old_call = 'if(!profileOwnedTask.observe())throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_OBSERVED");'
        new_call = 'if(!' + ready_call + ')throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_OBSERVED");'
        if (broker_text.count(new_call) != 1 or digest(ready_broker.replace(new_call, old_call, 1).encode())
                != "ddc76c3a6ba7fb74ae1ec2b3552a59e47957c28a8149bced34cf49fbe31c1c5a"):
            raise RuntimeError("Broker differs beyond the one authorized preparation call")
        result["ready_wiring"] = {"only_prepare_done_second_confirmation": True,
                                  "original_request_and_lease_deadline_preserved": True,
                                  "physical_fence_before_confirmation": True,
                                  "calls": calls, "android_broker_wiring_static_only": True}
        if fixture.stat().st_size != 2306 or sha(fixture) != SYNTHETIC_SHA:
            raise RuntimeError("Authored synthetic fixture differs")
        result["synthetic_fixture"] = {"bytes": 2306, "sha256": SYNTHETIC_SHA,
                                      "kind": "authored_synthetic_not_phone_original"}
        run("retained-permission-state", [sys.executable, "-B", str(original / "run_host.py"),
                                         "--source", str(source), "--java-home", str(args.java_home),
                                         "--output", str(output / "retained-permission-state")])
        previous = json.loads((output / "retained-permission-state/RESULT.json").read_text())
        if not (previous.get("all_pass") is True and previous.get("source_inputs_unchanged") is True
                and previous["synthetic_summary"]["cases"] == 16
                and previous["state_settle_summary"]["cases"] == 29):
            raise RuntimeError("Original 16 permission and 29 state cases did not pass")
        result["retained_gate"] = {"result_path": str(output / "retained-permission-state/RESULT.json"),
                                  "sha256": sha(output / "retained-permission-state/RESULT.json"),
                                  "all_pass": True, "permission_cases": 16, "state_cases": 29}
        spec = importlib.util.spec_from_file_location("retained_permission_pair_extractor", original / "run_host.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        generated, receipt = helper.prepare_permission_pair_adapters(platform, output)
        result["permission_pair_adapter"] = receipt
        classes = output / "classes"
        run("compile-ready", [str(args.java_home / "bin/javac"), "--release", "8", "-encoding", "UTF-8",
                              "-Xlint:all,-options", "-Werror", "-proc:none", "-d", str(classes)]
            + [str(path) for path in files + generated])
        stdout = run("ready-confirmation", [str(args.java_home / "bin/java"), "-cp", str(classes),
                                           "org.trillionnium.hepta.background.ProfileReadyConfirmationHostTest",
                                           str(fixture)])
        summaries = [json.loads(line) for line in stdout.decode().splitlines() if line.startswith("{")]
        if len(summaries) != 1:
            raise RuntimeError("Ready summary missing or duplicated")
        ready = summaries[0]
        case_names = ready.get("case_names")
        if not (ready.get("schema") == "hepta.profile-ready-confirmation-host-tests.v1"
                and ready.get("passed") is True and type(ready.get("cases")) is int
                and ready["cases"] == 114
                and type(case_names) is list and len(case_names) == ready["cases"]
                and len(set(case_names)) == ready["cases"]
                and type(ready.get("assertions")) is int and ready["assertions"] > 0
                and ready.get("fixture_sha256") == SYNTHETIC_SHA
                and ready.get("real_ready_coordinator_executed") is True
                and ready.get("real_pair_read_method_executed") is True
                and ready.get("framework_clock_and_history_port_synthetic") is True
                and ready.get("phone_contacted") is False and ready.get("android_build") is False):
            raise RuntimeError("Ready result contract differs")
        result["ready_summary"] = ready
        result["source_inputs_unchanged"] = pins == {
            str(path.relative_to(source)): sha(path) for path in sorted(tracked)}
        result["all_pass"] = len(result["stages"]) == 3 and result["source_inputs_unchanged"]
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
    (output / "RESULT.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
