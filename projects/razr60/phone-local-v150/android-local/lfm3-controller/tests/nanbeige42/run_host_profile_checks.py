#!/usr/bin/env python3
"""Host-only profile/consumer regression against unchanged ec9 admission guards.

Compiles test binaries on the host. It does not build an Android APK, load a
model, execute ADB, contact a phone, or qualify either accelerator.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
UNCHANGED = {
    "src/org/trillionnium/hepta/local/LocalRuntimeConfig.java": "81447620dbc2a789bba8c22d561c768144f4d5619859b202d07cd83660a05dce",
    "src/org/trillionnium/hepta/local/ConservativeTokenBudget.java": "63430401d14d944a03f00c23aad7373e95997c0f409f5837e191f6d169b140ea",
    "src/org/trillionnium/hepta/local/NativeBudgetVerifier.java": "1a03857c440ea1349fd35f875395c66a58f12aaa9daa6e59d72eafa6cb30c13d",
    "src/org/trillionnium/hepta/local/LocalModelEngine.java": "8c1605a56eb9d5fb9cb0101cc2f5493bb33f5c10b8fcb1d74277e1b7dc2df6d2",
    "src/org/trillionnium/hepta/local/LocalTaskController.java": "da3455080e441e18c9e4ed8f96d77891feff35b3faea0bf55664cd434ec387a9",
    "src/org/trillionnium/hepta/local/MainActivity.java": "da87217316db9493b665d35c332a53be7f7b3a9399fed90d8e97bc1307c1b1f3",
    "native/model-runtime.inc": "2e8c514c30b0689e3527e9687b6fdc5bae81583a7deb23a313ddc33e7a91ffab",
    "native/prompt-budget.h": "47e8587a9762b6018748d3560344024fcbd875da280df93afb57976c5eee8c3e",
    "native/generate_adapter.py": "d5bc2ec3c5d11e9e55a7323e07868c36fcfe1492883559ed0c9e7a27df958daf",
    "native/probe-worker.c": "bdf0e6b6760a5f53f68446d12f1904e30bf708e74b1741fe010fc3cbd6c68a89",
    "native/warm-protocol.inc": "5766de2194fd35cce08c6061db369420234acb2c993d7cf91c058c3ca593a86b",
    "native/worker-upstream.c": "07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e",
    "tools/phone_acceptance.py": "c5398a4cba3379b0618eae2c7021a66d23a4da35fa7343cf5dcfa84b612ffe76",
    "tools/phone_suite.py": "9be00e301c1fd5986e2f64c7ccf4033ca608d9a1874d42663b5d708990fd2f79",
    "tools/phone_inventory.py": "d25889ef9fffb22e08871f7a3b57a57e28d5f48977d4e42929364434599ea58e",
    "build_mac.py": "dca1f29ff9978ff3e99e0f9c02055247140bf01f086ac3231f6b63f160da706a",
    "assemble_pocket4.py": "1e90fd239610ae2c0e0ae042307998590d0234c4b519799c19971b629a2c9156",
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.nanbeige42-host-profile-checks.v1", "all_passed": False,
              "baseline_commit": "ec9b4106bf0d4d46267831c14f1102090a3137f6", "steps": [],
              "phone_tested": False, "model_loaded": False, "android_build": False,
              "synthetic_fixtures_only": True,
              "java_scope": "Host Java compiler source/target 8 syntax only; no Java 8 API or Android runtime claim."}
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    def run(name, command, cwd=source):
        result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, timeout=60)
        stdout = output / (name + ".stdout")
        stderr = output / (name + ".stderr")
        stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
        row = {"name": name, "exit_code": result.returncode,
               "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
               "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
        report["steps"].append(row)
        if result.returncode:
            raise RuntimeError(name + " failed: " + result.stderr.decode(errors="replace"))
        return result.stdout.decode(errors="replace")
    try:
        for relative, expected in UNCHANGED.items():
            path = source / relative
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise AssertionError("ec9 guard/source changed: " + relative)
        report["unchanged_guard_sha256"] = UNCHANGED
        inputs = ["src/org/trillionnium/hepta/local/ModelProfile.java", "native/model-profile.h", "tools/model_profiles.py"]
        report["candidate_registry_sha256"] = {name: hashlib.sha256((source/name).read_bytes()).hexdigest() for name in inputs}
        run("python-consumers", [sys.executable, "-B", "-m", "unittest", "-v", "test_model_profiles",
            "test_mobile_agent_profiles", "test_profile_registry_consumers", "test_nanbeige42_profile"], source / "tools")
        java = os.environ.get("HEPTA_TEST_JAVA") or shutil.which("java")
        if not java:
            raise RuntimeError("existing Java required; installation is not attempted")
        javac = os.environ.get("HEPTA_TEST_JAVAC") or shutil.which("javac")
        compiler = [javac] if javac else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
        run("java-version", [java, "-version"])
        classes = output / "profile-classes"; classes.mkdir()
        package = source / "src/org/trillionnium/hepta/local"
        dependencies = [package / (name + ".java") for name in
                        ("ModelProfile", "LocalRuntimeConfig", "ConservativeTokenBudget", "NativeBudgetVerifier")]
        tests = ("Nanbeige42ProfileHostTest", "ModelProfileHostTest", "MobileAgentProfilesHostTest",
                 "Gemma4ProfileHostTest", "Qwen35ProfileHostTest", "Lfm25MoeProfileHostTest", "BudgetHostTest")
        compile_flags = ["-source", "8", "-target", "8", "-encoding", "UTF-8", "-Xlint:all,-options", "-Werror"]
        run("java-profile-compile", compiler + compile_flags + ["-d", str(classes)] +
            [str(p) for p in dependencies] + [str(source/"tests"/(name+".java")) for name in tests])
        for name in tests:
            run(name, [java, "-cp", str(classes), name])
        # Preserve and exercise the existing exact production prompt/await/input
        # extraction. Its unrelated WarmProcessSession class is not part of this
        # admission test; excluding it avoids a newer-JDK serial warning without
        # editing that production class or relaxing compiler warnings.
        helper = load_module("nanbeige_exact_fixture", source / "tests/exact-admission/prepare_fixture.py")
        exact_sources, extraction = helper.prepare(source, output / "exact-fixture")
        exact_sources = [path for path in exact_sources if path.name != "WarmProcessSession.java"]
        exact_sources += sorted((source / "tests/exact-admission").rglob("*.java"))
        exact_classes = output / "exact-classes"; exact_classes.mkdir()
        run("exact-admission-compile", compiler + compile_flags + ["-d", str(exact_classes)] + [str(path) for path in exact_sources])
        run("exact-admission", [java, "-cp", str(exact_classes), "org.trillionnium.hepta.local.PromptAdmissionHostTest"])
        report["exact_extraction"] = extraction
        cc = os.environ.get("CC") or shutil.which("cc")
        if not cc:
            raise RuntimeError("existing host C compiler required")
        run("cc-version", [cc, "--version"])
        for name in ("nanbeige42_profile_contract", "model_profile_contract", "mobile_agent_profiles_contract",
                     "qwen35_profile_contract", "lfm25_profile_contract"):
            binary = output / name
            run(name + "-compile", [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-I" + str(source/"native"),
                                    str(source/"native/tests"/(name+".c")), "-o", str(binary)])
            run(name, [str(binary)])
        native = source / "native"; sys.path.insert(0, str(native))
        generator = load_module("nanbeige_unchanged_generator", native / "generate_adapter.py")
        generated = output / "generated"; generated.mkdir()
        adapter = generator.generate(source, generated)
        expected = "b2276da3b7066d1da2a48097c58681e6f3b37bb786660c5bb7dc680b03910d0f"
        if adapter["adapted_sha256"] != expected:
            raise AssertionError("generated request logic changed from ec9")
        report["generated_worker_sha256"] = adapter["adapted_sha256"]
        report["all_passed"] = True
    except Exception as error:
        report["error"] = repr(error)
        raise
    finally:
        (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"all_passed": True, "steps": len(report["steps"]), "scope": "host-only profile and consumer contracts"}))


if __name__ == "__main__":
    main()
