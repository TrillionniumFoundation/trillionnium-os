#!/usr/bin/env python3
"""Real native session + profile installed capture; explicit Android IO ports only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    jdk, jar = args.java_home.resolve(), args.json_jar.resolve()
    assert sha(jar.read_bytes()) == JSON_SHA
    assert not output.exists() and source not in output.parents
    output.mkdir(mode=0o700)
    query = module(source / "tests/web-flight/run_query_host_tests.py", "xiaomi_native_query")
    background = module(source / "tests/background-session/prepare_fixture.py", "xiaomi_native_background")
    bgfiles, extraction = background.prepare(source, output / "ports", include_terminal=False)
    bgfiles = [p for p in bgfiles if not (p.parent.name == "json" and p.parent.parent.name == "org")]
    # New typed search signatures need only this refusing result type in the
    # retained profile-identity fixture. No search authority/effect is modeled.
    service_port = output / "ports/org/trillionnium/hepta/local/HeptaAccessibilityService.java"
    service_before = service_port.read_bytes()
    service_text = service_before.decode("utf-8")
    assert bgfiles.count(service_port) == 1 and service_text.endswith("}")
    assert "class ActionOutcome" not in service_text
    outcome_port = """    public static final class ActionOutcome {
        public final boolean accepted=false,dispatched=false,stale=true;
        public final org.json.JSONObject taskAuthorization=null,actionExecution=null;
        private ActionOutcome(){throw new AssertionError("native search dispatch is outside the legacy profile fixture");}
    }"""
    service_after = (service_text[:-1] + chr(10) + outcome_port + chr(10) + "}").encode("utf-8")
    assert service_after.decode("utf-8").replace(chr(10) + outcome_port + chr(10), "", 1) == service_text
    service_port.write_bytes(service_after)
    search_type_boundary = {"original_service_sha256": sha(service_before),
        "compiled_service_sha256": sha(service_after), "type_block_sha256": sha(outcome_port.encode()),
        "original_service_bytes_reversible": True, "constructor_always_throws": True,
        "accepted_and_dispatched_always_false": True, "authority_and_execution_always_null": True,
        "new_search_path_executed": False}
    config_path = output / "ports/org/trillionnium/hepta/local/QualificationScopeConfig.java"
    config_source = source / "src/org/trillionnium/hepta/local/QualificationScopeConfig.java"
    actual_completion = query.java_block(config_source.read_bytes(), "static final class CompletionInstalledIdentity {")
    config = config_path.read_text()
    assert config.endswith("}\n") and "CompletionInstalledIdentity" not in config
    # The complete production identity class is copied byte-for-byte. Ordinary
    # PackageManager/Apk endpoints are unavailable in this profile-only gate.
    ports = '''
    private static final class Installed {
        String packageName,apkSetSha256;int uid;long version;
        Map<String,Apk> apks;
        static Installed capture(Context c,String pkg){throw new AssertionError("ordinary PackageManager fallback forbidden in profile gate");}
        void verify(Context c){throw new AssertionError("ordinary installation verifier forbidden in profile gate");}
    }
    private static final class Apk {String sha256;}
'''
    config_path.write_text(config[:-2].replace("import java.io.File;", "import java.io.File;import java.util.*;")
                           + actual_completion + "\n" + ports + "}\n")
    calculator = output / "ports/org/trillionnium/hepta/local/CalculatorGoalContract.java"
    calculator.write_text('package org.trillionnium.hepta.local;final class CalculatorGoalContract {static final String PACKAGE="com.google.android.calculator";}\n')
    bgfiles.append(calculator)
    fixture_source = source / "tests/background-session/BackgroundSessionHostTest.java"
    signatures = ("static Object invoke(", "static JSONObject decode(", "static byte[] frame(",
                  "static JSONObject policy(", "static byte[] response(")
    fixture_methods = [query.java_block(fixture_source.read_bytes(), s) for s in signatures]
    client = output / "ports/org/trillionnium/hepta/local/ProfileClientPort.java"
    client.write_text("package org.trillionnium.hepta.local;\nimport java.io.*;import java.lang.reflect.*;"
                      "import java.nio.charset.StandardCharsets;import java.util.*;import org.json.*;"
                      "import android.os.SystemClock;\nfinal class ProfileClientPort {\n"
                      + "\n".join(fixture_methods) + "\n}\n")
    bgfiles.append(client)
    excluded = {"tests/web-flight/WebFlightQueryHostTest.java", "tests/native-app/legacy-boundary/NativeAppSession.java"}
    paths = [source / p for p in query.PURE_PATHS if p not in excluded] + bgfiles
    paths += [source / ("src/org/trillionnium/hepta/local/" + name + ".java") for name in
              ('ObservationCaptureEvidence', "NativeSearchRole", "NativeSearchPlanning", "NativeSearchDecision", "NativeSearchSession", "PromptActionDomain", "NativeAppEvidence", "NativeAppDomain", "NativeAppSession",
               "NativeActionSnapshotCheck", "NativeAppObservation", "NativeCtripFlightPage", "NativeXiaomiProductPage")]
    paths.append(Path(__file__).resolve().with_name("NativeProfileIdentityHostTest.java"))
    paths = list(dict.fromkeys(p.resolve() for p in paths))
    original_paths = [p for p in paths if source in p.parents] + [config_source, fixture_source,
        Path(__file__).resolve(), source / "tests/background-session/prepare_fixture.py",
        source / "tests/web-flight/run_query_host_tests.py"]
    original_paths = list(dict.fromkeys(original_paths))
    originals = [record(p) for p in original_paths]
    tools_before = [record(p) for p in (jdk / "bin/javac", jdk / "bin/java", jdk / "lib/modules", jar)]
    report = {"schema": "hepta.xiaomi-profile-native-identity-gate.v1", "all_pass": False,
              "source": str(source), "production_inputs": originals, "compile_inputs": [record(p) for p in paths],
              "background_fixture": extraction, "native_search_legacy_type_boundary": search_type_boundary, "tools_before": tools_before, "stages": [],
              "exact_completion_installed_identity_sha256": sha(actual_completion.encode()),
              "client_port_methods": [{"signature": s, "sha256": sha(v.encode())} for s, v in zip(signatures, fixture_methods)],
              "boundary": "Actual full NativeAppSession/BackgroundSession. Exact complete CompletionInstalledIdentity; ordinary PM/Apk endpoints throw. Existing Android display/socket/clock test ports are synthetic. No phone, root process, model or business result.",
              "phone_actions": 0, "device_qualified": False, "business_verified": False}
    env = dict(os.environ)
    env["PATH"] = str(jdk / "bin") + ":/usr/bin:/bin"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(name, None)
    classes = output / "classes"
    classes.mkdir()
    commands = [
        ("compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                     "-Xlint:all,-options", "-Werror", "-classpath", jar, "-d", classes, *paths]),
        ("native-profile", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + str(jar),
                            "org.trillionnium.hepta.local.NativeProfileIdentityHostTest", output / "CASES.json", output / "work"])]
    try:
        for name, argv in commands:
            started = time.monotonic()
            result = subprocess.run(list(map(str, argv)), cwd=output, env=env, capture_output=True, timeout=120)
            for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
                (output / (name + "." + suffix)).write_bytes(data)
            report["stages"].append({"name": name, "argv": list(map(str, argv)), "exit_code": result.returncode,
                                     "seconds": time.monotonic() - started,
                                     "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)})
            if result.returncode:
                raise RuntimeError("stage failed: " + name)
        report["cases"] = json.loads((output / "CASES.json").read_text())
        assert report["cases"]["all_pass"] and report["cases"]["cases"] == 22
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["originals_after"] = [record(p) for p in original_paths]
        report["originals_unchanged"] = originals == report["originals_after"]
        report["tools_after"] = [record(p) for p in (jdk / "bin/javac", jdk / "bin/java", jdk / "lib/modules", jar)]
        report["tools_unchanged"] = tools_before == report["tools_after"]
        report["all_pass"] = report["all_pass"] and report["originals_unchanged"] and report["tools_unchanged"]
        (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"all_pass": report["all_pass"], "error": report.get("error"),
                          "cases": report.get("cases", {}).get("cases"),
                          "assertions": report.get("cases", {}).get("assertions"),
                          "result": str(output / "RESULT.json")}))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
