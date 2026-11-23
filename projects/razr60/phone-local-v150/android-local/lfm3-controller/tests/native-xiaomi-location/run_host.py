#!/usr/bin/env python3
"""Public derived complete location-popup shape + unchanged provider regressions; host only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(p):
    raw = p.read_bytes()
    return {"path": str(p), "bytes": len(raw), "sha256": sha(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    jdk, jar = args.java_home.resolve(), args.json_jar.resolve()
    assert not output.exists() and source not in output.parents
    output.mkdir(mode=0o700)
    inputs = [p for p in source.rglob("*") if p.is_file()]
    before = {str(p.relative_to(source)): identity(p) for p in inputs}
    tools = {str(p): identity(p) for p in (jdk / "bin/java", jdk / "bin/javac", jdk / "lib/modules", jar)}
    assert sha(jar.read_bytes()) == "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
    env = dict(os.environ)
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    env["PATH"] = str(jdk / "bin") + ":/usr/bin:/bin"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    report = {"schema": "hepta.xiaomi-location-host-gate.v1", "all_pass": False,
              "source": str(source), "phone_operations": 0, "model_executed": False,
              "platform_dispatch_executed": False, "phone_runtime_qualified": False,
              "business_verified": False, "stages": []}

    def run(name, argv):
        argv = [str(x) for x in argv]
        started = time.monotonic()
        with (output / (name + ".stdout")).open("wb") as stdout, (output / (name + ".stderr")).open("wb") as stderr:
            result = subprocess.run(argv, env=env, cwd=str(source), stdout=stdout, stderr=stderr, timeout=300)
        row = {"name": name, "argv": argv, "exit_code": result.returncode,
               "elapsed_seconds": time.monotonic() - started,
               "stdout": identity(output / (name + ".stdout")), "stderr": identity(output / (name + ".stderr"))}
        report["stages"].append(row)
        assert result.returncode == 0, name + " failed; original logs retained"

    try:
        provenance = json.loads((source / "tests/native-xiaomi-location/fixtures/PROVENANCE.json").read_text())
        assert provenance["schema"] == "hepta.xiaomi-location-public-derived-fixtures.v1"
        assert provenance["public_derived_fixtures"] is True
        assert provenance["exact_original_capture"] is False
        for row in provenance["files"]:
            path = source / "tests/native-xiaomi-location/fixtures" / row["path"]
            actual = identity(path)
            assert actual["bytes"] == row["bytes"] and actual["sha256"] == row["sha256"]
            assert row["derived_fixture"] is True and row["exact_original_capture"] is False
        report["public_derived_fixture_provenance"] = provenance
        original = source / "tests/native-app-provider/run_host.py"
        original_bytes = original.read_bytes()
        # Verify only the reviewed source-list/refusing-type additions on a
        # proof copy. The actual current provider below remains unmodified.
        legacy_provider_bytes = original_bytes
        # Reverse only the exact reviewed runtime/final-census type additions
        # for the historical proof. Compile the actual current provider below.
        if sha(legacy_provider_bytes) == "580b6b1aa33bc3e52c6b358c47b7fa1e829648256c845eec79e5f8d98e6eb95e":
            assert len(legacy_provider_bytes) == 62522
            runtime_census_type_inverse = [(b'"CalendarFreshObservation", "CalendarActionResult", "CalendarSelectionObservation", "NativeSearchFinalCensusResampleProof")):', b'"CalendarFreshObservation", "CalendarActionResult", "CalendarSelectionObservation")):'), (b'    calendar_types = """\n    static final class NativeSearchFinalCensusResampleProof {\n        private NativeSearchFinalCensusResampleProof(){throw new AssertionError("actual final-census producer unavailable in this pure gate");}\n        void consume(NativeSearchSession.Attempt attempt,NativeSearchRole role,long now){throw new AssertionError("no final-census replacement authority");}\n    }\n', b'    calendar_types = """\n'), (b'    runtime_port = """package org.trillionnium.hepta.local;\nfinal class RuntimeInferenceAdapter implements LocalInference {\n    private RuntimeInferenceAdapter(){throw new AssertionError("runtime router is outside this legacy fixture");}\n    public LocalRuntimeConfig configuration(){throw new AssertionError("no runtime configuration authority");}\n    public Handle generate(String prompt,String system,java.io.File image,DecisionGrammar grammar,int tokens,long timeout,Callback callback){throw new AssertionError("no runtime model execution");}\n    final class CalendarModelBinding {\n        private CalendarModelBinding(){throw new AssertionError("no runtime calendar binding in legacy fixture");}\n        VlmInferenceAdapter requireCurrent(String taskId,LocalRuntimeConfig config){throw new AssertionError("no runtime calendar producer authority");}\n    }\n    synchronized CalendarModelBinding bindCalendarModel(String taskId,LocalRuntimeConfig config){throw new AssertionError("no runtime calendar binding authority");}\n}\n"""\n    controller_port = """package org.trillionnium.hepta.local;\n', b'    controller_port = """package org.trillionnium.hepta.local;\n'), (b'(("VlmInferenceAdapter.java", model_port), ("LocalTaskController.java", controller_port), ("RuntimeInferenceAdapter.java", runtime_port))', b'(("VlmInferenceAdapter.java", model_port), ("LocalTaskController.java", controller_port))')]
            for current, previous in runtime_census_type_inverse:
                assert legacy_provider_bytes.count(current) == 1
                legacy_provider_bytes = legacy_provider_bytes.replace(current, previous, 1)
            assert sha(legacy_provider_bytes) == "14c341055b75c6b25924327d97da04d343fa6d7a408000ab1a5786d7543169a0"
            report["retained_provider_runtime_census_type_additions_exactly_reversible"] = True
        # The current calendar carrier is reversed only on this proof copy.
        # The actual provider command below still compiles its untouched current bytes.
        if sha(legacy_provider_bytes) == "14c341055b75c6b25924327d97da04d343fa6d7a408000ab1a5786d7543169a0":
            calendar_start = b"\ndef calendar_legacy_closure(source, service_port):\n"
            assert legacy_provider_bytes.count(calendar_start) == 1
            calendar_at = legacy_provider_bytes.index(calendar_start)
            calendar_helper = legacy_provider_bytes[calendar_at:calendar_at + 8310]
            assert sha(calendar_helper) == "171abb5c88060ec41e423d288e2f3eb427cf610c6804bdc89ff2336e876ed243"
            assert legacy_provider_bytes.count(calendar_helper) == 1
            legacy_provider_bytes = legacy_provider_bytes.replace(calendar_helper, b"", 1)
            calendar_hooks = [b'        calendar_paths,calendar_boundary=calendar_legacy_closure(source,service_port)\n        report["native_calendar_legacy_type_boundary"]=calendar_boundary\n', b'        actual_calendar_files={p.name for p in calendar_paths if source in p.parents}\n        paths=[p for p in paths if not (p.parent==service_port.parent and (p.name in actual_calendar_files or p.name=="NativeAppSession.java"))]\n        paths += calendar_paths\n']
            for current in calendar_hooks:
                assert legacy_provider_bytes.count(current) == 1
                legacy_provider_bytes = legacy_provider_bytes.replace(current, b"", 1)
            assert sha(legacy_provider_bytes) == "72cfa0936e14eca98c2e15db4caa9bf255d0d98f201c91348e380755e68e09e0"
            report["retained_provider_calendar_type_additions_exactly_reversible"] = True
        # Exact current sampling type-only inverse on a proof copy; compile the
        # untouched current provider below. Every older pin remains required.
        if sha(legacy_provider_bytes) == "72cfa0936e14eca98c2e15db4caa9bf255d0d98f201c91348e380755e68e09e0":
            sampling_type_inverse = [b' and "class NativeSearchSamplingExhaustionProof" not in service_text', b'\n    public static final class NativeSearchSamplingExhaustionProof {\n        private NativeSearchSamplingExhaustionProof(){throw new AssertionError("native sampling successor is outside this legacy fixture");}\n        public void close(){throw new AssertionError("no sampling successor authority in this legacy fixture");}\n    }']
            for current in sampling_type_inverse:
                assert legacy_provider_bytes.count(current) == 1
                legacy_provider_bytes = legacy_provider_bytes.replace(current, b"", 1)
            assert sha(legacy_provider_bytes) == "7fb8fea5ca9a2f58e749810cd5f5a38e9b9026ea65d2cdf8a852419f387e7ea0"
            report["retained_provider_sampling_type_exactly_reversible"] = True
        # Reverse only the exact reviewed no-effect proof type on a proof copy.
        # The actual current provider is compiled below without this projection.
        if sha(legacy_provider_bytes) == "7fb8fea5ca9a2f58e749810cd5f5a38e9b9026ea65d2cdf8a852419f387e7ea0":
            successor_type_inverse = [
                (b' and "class NativeSearchNoEffectReplanProof" not in service_text', b''),
                (b'\n    public static final class NativeSearchNoEffectReplanProof {\n        private NativeSearchNoEffectReplanProof(){throw new AssertionError("native search no-effect successor is outside this legacy fixture");}\n        public void requireOriginal(NativeSearchSession session,NativeSearchSession.Attempt attempt,long now,boolean live){throw new AssertionError("no successor authority in this legacy fixture");}\n        public void requireOutcome(ActionOutcome outcome){throw new AssertionError("no successor authority in this legacy fixture");}\n        public void requirePublishedPlanning(NativeSearchSession session,NativeSearchPlanning planning){throw new AssertionError("no successor authority in this legacy fixture");}\n        public java.util.Map<String,Object> evidence(){throw new AssertionError("no successor evidence in this legacy fixture");}\n    }', b''),
                (b', "no_effect_successor_proof_constructor_and_methods_always_throw":True, "no_effect_successor_proof_minted":False', b''),
            ]
            for current, previous in successor_type_inverse:
                assert legacy_provider_bytes.count(current) == 1
                legacy_provider_bytes = legacy_provider_bytes.replace(current, previous, 1)
            assert sha(legacy_provider_bytes) == "726b8bf8a77d28ab694f662b0e3fb1e32ecff67568c87e06fd85cce9782350c6"
            report["retained_provider_no_effect_type_additions_exactly_reversible"] = True
        # Strip only the fixed new refusing retry type on this proof copy.
        # Compilation below continues to use the actual current provider bytes.
        if sha(legacy_provider_bytes) == "726b8bf8a77d28ab694f662b0e3fb1e32ecff67568c87e06fd85cce9782350c6":
            retry_type_comment = b'        # The retained provider cases do not construct a new search Session or\n        # dispatch its intent.  Its signature needs only an unconstructible\n        # outcome and loading-read-retry proof types here; both constructors\n        # always throw. No accepting action/authorization fixture is added.\n'
            assert legacy_provider_bytes.count(retry_type_comment) == 1
            legacy_provider_bytes = legacy_provider_bytes.replace(retry_type_comment, b'        # The retained provider cases do not construct a new search Session or\n        # dispatch its intent.  Its signature needs only an unconstructible\n        # outcome type here; no accepting action/authorization fixture is added.\n', 1)
            retry_type_guard = b'        require(bgfiles.count(service_port)==1 and service_text.endswith("}")\n                and "class ActionOutcome" not in service_text and "class NativeSearchReadRetryProof" not in service_text,\n                "one original Service type port required")\n'
            assert legacy_provider_bytes.count(retry_type_guard) == 1
            legacy_provider_bytes = legacy_provider_bytes.replace(retry_type_guard, b'        require(bgfiles.count(service_port)==1 and service_text.endswith("}")\n                and "class ActionOutcome" not in service_text,"one original Service type port required")\n', 1)
            retry_type_declaration = b'\n    public static final class NativeSearchReadRetryProof {\n        private NativeSearchReadRetryProof(){throw new AssertionError("native loading read retry is outside the legacy provider fixture");}\n    }'
            assert legacy_provider_bytes.count(retry_type_declaration) == 1
            legacy_provider_bytes = legacy_provider_bytes.replace(retry_type_declaration, b'', 1)
            retry_type_metadata = b'        report["native_search_legacy_type_boundary"]={"schema":"hepta.native-search-legacy-type-boundary.v1",\n            "generated_service":str(service_port),"original_service_sha256":sha(service_before),\n            "compiled_service_sha256":sha(service_after),"type_block_sha256":sha(outcome_port.encode("utf-8")),\n            "original_service_bytes_reversible":True,"constructor_always_throws":True,\n            "accepted_and_dispatched_always_false":True,"authority_and_execution_always_null":True,\n            "new_search_path_executed":False,"loading_read_retry_proof_constructor_always_throws":True,\n            "loading_read_retry_proof_minted":False,"phone_operations":0}\n'
            assert legacy_provider_bytes.count(retry_type_metadata) == 1
            legacy_provider_bytes = legacy_provider_bytes.replace(retry_type_metadata, b'        report["native_search_legacy_type_boundary"]={"schema":"hepta.native-search-legacy-type-boundary.v1",\n            "generated_service":str(service_port),"original_service_sha256":sha(service_before),\n            "compiled_service_sha256":sha(service_after),"type_block_sha256":sha(outcome_port.encode("utf-8")),\n            "original_service_bytes_reversible":True,"constructor_always_throws":True,\n            "accepted_and_dispatched_always_false":True,"authority_and_execution_always_null":True,\n            "new_search_path_executed":False,"phone_operations":0}\n', 1)
            assert sha(legacy_provider_bytes) == "91934e3e55b488f7ffbd172aeacb28530165404a4671b80869c8855c0902da3a"
            report["retained_provider_loading_retry_type_additions_exactly_reversible"] = True
        # Normalize only the exact reviewed null detail field on the proof copy.
        # The real provider below still compiles the unchanged current driver.
        if sha(legacy_provider_bytes) == "91934e3e55b488f7ffbd172aeacb28530165404a4671b80869c8855c0902da3a":
            detail_port = b"        public final String detail=null;\n"
            assert legacy_provider_bytes.count(detail_port) == 1
            legacy_provider_bytes = legacy_provider_bytes.replace(detail_port, b"", 1)
            assert sha(legacy_provider_bytes) == "dee48aa5a628e67b8f6813fa947e595b4d891719b1ab1782f95593267044a75d"
            report["retained_provider_null_detail_addition_exactly_reversible"] = True
        if sha(legacy_provider_bytes) == "dee48aa5a628e67b8f6813fa947e595b4d891719b1ab1782f95593267044a75d":
            search_sources = b'"NativeSearchRole","NativeSearchPlanning","NativeSearchDecision","NativeSearchSession",'
            refusing_type_block = b'        # The retained provider cases do not construct a new search Session or\n        # dispatch its intent.  Its signature needs only an unconstructible\n        # outcome type here; no accepting action/authorization fixture is added.\n        service_port=out/"platform-fixture/org/trillionnium/hepta/local/HeptaAccessibilityService.java"\n        service_before=service_port.read_bytes()\n        service_text=service_before.decode("utf-8")\n        require(bgfiles.count(service_port)==1 and service_text.endswith("}")\n                and "class ActionOutcome" not in service_text,"one original Service type port required")\n        outcome_port="""    public static final class ActionOutcome {\n        public final boolean accepted=false,dispatched=false,stale=true;\n        public final org.json.JSONObject taskAuthorization=null,actionExecution=null;\n        private ActionOutcome(){throw new AssertionError("native search dispatch is outside the legacy provider fixture");}\n    }"""\n        service_after=(service_text[:-1]+chr(10)+outcome_port+chr(10)+"}").encode("utf-8")\n        require(service_after.decode("utf-8").replace(chr(10)+outcome_port+chr(10),"",1)==service_text,\n                "original Service port changed outside the refusing type boundary")\n        service_port.write_bytes(service_after)\n        report["native_search_legacy_type_boundary"]={"schema":"hepta.native-search-legacy-type-boundary.v1",\n            "generated_service":str(service_port),"original_service_sha256":sha(service_before),\n            "compiled_service_sha256":sha(service_after),"type_block_sha256":sha(outcome_port.encode("utf-8")),\n            "original_service_bytes_reversible":True,"constructor_always_throws":True,\n            "accepted_and_dispatched_always_false":True,"authority_and_execution_always_null":True,\n            "new_search_path_executed":False,"phone_operations":0}\n'
            assert legacy_provider_bytes.count(search_sources) == 1
            assert legacy_provider_bytes.count(refusing_type_block) == 1
            legacy_provider_bytes = legacy_provider_bytes.replace(search_sources, b"", 1).replace(refusing_type_block, b"", 1)
            report["retained_provider_search_signature_additions_exactly_reversible"] = True
        assert sha(legacy_provider_bytes) == '7f57be43bbbf43ae0cbaca63569c723b42199b98d6819f5707981dcc978e7a4f'
        helper_source_entry = b"'ObservationCaptureEvidence', "
        assert legacy_provider_bytes.count(helper_source_entry) == 1
        assert sha(legacy_provider_bytes.replace(helper_source_entry, b"", 1)) == "8f98d2f335f1a4b2dd659a9b0c5478a87e313247b261a1d32c8ce0535fa32064"
        report["retained_provider_original_bytes_restored_without_only_helper_source_entry"] = True
        retained = output / "retained-provider"
        run("retained-provider", [sys.executable, original, "--source", source, "--output", retained,
                                  "--java-home", jdk, "--json-jar", jar])
        previous = json.loads((retained / "RESULT.json").read_text())
        assert previous["all_pass"] is True and previous["inputs_unchanged"] is True and previous["tools_unchanged"] is True
        report["retained_provider_result"] = identity(retained / "RESULT.json")
        report["retained_provider_cases"] = previous["cases"]["cases"]
        report["retained_provider_assertions"] = previous["cases"]["assertions"]
        classes = output / "classes"
        classes.mkdir()
        test = source / "tests/native-xiaomi-location/NativeXiaomiLocationHostTest.java"
        cp = str(retained / "classes") + os.pathsep + str(jar)
        run("location-compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                                 "-Xlint:all,-options", "-Werror", "-classpath", cp, "-d", classes, test])
        report["new_test_input"] = identity(test)
        run("location-cases", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + cp,
                               "org.trillionnium.hepta.local.NativeXiaomiLocationHostTest", source, output / "CASES.json"])
        cases = json.loads((output / "CASES.json").read_text())
        assert cases["all_pass"] is True and cases["schema"] == "hepta.native-xiaomi-location-host.v1"
        assert cases["private_originals_modified"] is False and cases["public_fixture_is_exact_capture"] is False and cases["synthetic_record_identity"] is True and cases["phone_operations"] == 0
        assert cases["phone_runtime_qualified"] is False and cases["business_verified"] is False
        assert cases["model_executed"] is False and cases["platform_dispatch_executed"] is False
        assert cases["cases"] == len(cases["case_names"]) and len(set(cases["case_names"])) == cases["cases"]
        report["cases"] = cases
        report["all_pass"] = True
    except Exception as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        after = {str(p.relative_to(source)): identity(p) for p in source.rglob("*") if p.is_file()}
        report["source_unchanged"] = before == after
        report["tools_unchanged"] = tools == {p: identity(Path(p)) for p in tools}
        report["all_pass"] = report["all_pass"] and report["source_unchanged"] and report["tools_unchanged"]
        report["production"] = [identity(source / "src/org/trillionnium/hepta/local" / name)
                                for name in ("NativeXiaomiProductPage.java", "NativeAppSession.java", "NativeAppDomain.java", "HeptaAccessibilityService.java")]
        raw = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
        (output / "RESULT.json").write_bytes(raw)
        print(json.dumps({"all_pass": report["all_pass"], "cases": report.get("cases", {}).get("cases"),
                          "assertions": report.get("cases", {}).get("assertions"), "failure": report.get("failure"),
                          "result": str(output / "RESULT.json"), "sha256": sha(raw)}))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
