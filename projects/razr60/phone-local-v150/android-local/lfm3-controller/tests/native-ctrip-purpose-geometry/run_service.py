#!/usr/bin/env python3
"""Actual purpose-limited Ctrip Session + verbatim Service final use with explicit Android IO."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def ref(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw), mode=path.stat().st_mode & 0o777)

def need(value, reason):
    if not value:
        raise RuntimeError(reason)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "output", "java-home", "json-jar"):
        p.add_argument("--" + key, type=Path, required=True)
    a = p.parse_args()
    source, out, jdk, jar = [getattr(a, k).resolve() for k in ("source", "output", "java_home", "json_jar")]
    need(not out.exists() and source not in out.parents, "fresh output outside source required")
    out.mkdir(parents=True, mode=0o700)
    own = source / "tests/native-ctrip-purpose-geometry"
    base = load(source / "tests/native-action-integration/run_host.py", "query_actual_integration_base")
    adapter = load(own / "bridge_adapters.py", "ctrip_explicit_android_ports")
    product = load(source / "tests/native-xiaomi-query-stability/bridge_adapters.py", "retained_actual_profile_ports")
    before = base.inventory(source)
    tools = [jdk / "bin/java", jdk / "bin/javac", jdk / "lib/modules", jdk / "lib/ct.sym", jar]
    expected_service_cases = ['equal_tree_YEAR_runs_actual_final_census_claim_and_effect', 'equal_tree_QUERY_uses_actual_calendar_roundtrip_and_final_claim', 'recorded_header_motion_is_rechecked_at_actual_final_use', 'qualified_expected_without_private_guard_is_refused', 'unqualified_guard_cannot_borrow_qualified_pixel_metadata', 'pixel_metadata_original_census_substitution_is_refused', 'same_value_replacement_NodeRef_is_refused', 'final_query_date_semantics_change_is_refused', 'final_selected_trip_change_is_refused', 'final_header_descendant_target_overlap_is_refused', 'equal_tree_preclaimed_guard_cannot_repeat_effect', 'equal_tree_expired_original_deadline_refuses', 'final_reported_window_change_refuses_before_claim', 'installed_identity_change_refuses_before_final_effect', 'full_strict_pre_capture_lossless_actual_phone_and_permit', 'full_strict_post_capture_lossless_actual_phone_and_permit', 'full_purpose_pre_capture_lossless_actual_phone_and_permit', 'full_purpose_post_capture_lossless_actual_phone_and_permit']
    report = dict(schema="hepta.ctrip-purpose-integration-host.v1", all_pass=False, stages=[],
                  source=str(source), input_before=before, tools_before=[ref(x) for x in tools],
                  actual_production_session=True, actual_service_bodies_verbatim=True,
                  explicit_android_profile_capture_ports=True, android_runtime=False,
                  phone_operations=0, model_executed=False, business_completion_verified=False)
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    def stage(name, argv):
        start = time.monotonic()
        r = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=240)
        so, se = out / (name + ".stdout"), out / (name + ".stderr")
        so.write_bytes(r.stdout); se.write_bytes(r.stderr)
        report["stages"].append(dict(name=name, argv=list(map(str, argv)), exit_code=r.returncode,
                                    elapsed_seconds=time.monotonic()-start, stdout=ref(so), stderr=ref(se)))
        need(r.returncode == 0, name + " failed; exact stdout/stderr retained")
    try:
        need(ref(jar)["sha256"] == base.JSON_SHA, "original pinned JSON dependency required")
        generated = out / "generated"; generated.mkdir()
        service, controller, parts, methods, old_xiaomi, old_main = base.generate(source, generated)
        original = (generated / "NativeActionBridgeHost.java").read_text()
        adapted = adapter.adapt(original, (own / "PurposeBridgeCases.fragment").read_text(), product)
        extractor=load(source/"tests/observation-diagnostics/run_host.py", "ctrip_capture_method_extractor")
        capture_method=extractor.body(service, "        Map<String,Object> captureEvidence(long publishedAt){")
        adapted=base.replace(adapted,"        {{actual_capture_evidence}}",capture_method)
        methods["full_capture_evidence"]=capture_method
        for name, body in {**parts, **methods}.items():
            # Main/body projections used only by old secondary fixtures may live
            # in XiaomiActionGuardHost rather than the Service wrapper.
            if body in original:
                need(body in adapted, "production extracted body altered: " + name)
        new_source = generated / "NativeProductQueryBridgeHost.java"
        new_source.write_text(adapted)
        extraction = dict(schema="hepta.product-query-service-extraction.v1", service=ref(source/base.PKG/"HeptaAccessibilityService.java"),
                          session=ref(source/base.PKG/"NativeAppSession.java"),
                          methods={name:dict(bytes=len(body.encode()), sha256=sha(body.encode())) for name,body in {**parts, **methods}.items()},
                          original_generated=ref(generated/"NativeActionBridgeHost.java"), product_generated=ref(new_source),
                          adapter=ref(own/"bridge_adapters.py"), cases=ref(own/"PurposeBridgeCases.fragment"),
                          fixture=ref(own/"recorded-060c-pair.json"), production_bodies_verbatim=True,
                          android_profile_capture_and_clock_are_host_ports=True,
                          original_device_capture_replayed=False)
        (out / "EXTRACTION.json").write_text(json.dumps(extraction, ensure_ascii=False, indent=2)+"\n")
        paths, boundary = base.sources(source, out)
        need(new_source.resolve() in paths, "new actual-Service fixture must be a compile input")
        report["compile_inputs"] = [ref(x) for x in paths]
        report["background_fixture"] = boundary
        classes = out / "classes"; classes.mkdir()
        stage("jdk-version", [jdk/"bin/javac", "-version"])
        need((out/"jdk-version.stdout").read_text().startswith("javac 17.")
             or (out/"jdk-version.stderr").read_text().startswith("javac 17."), "JDK 17 required")
        stage("compile", [jdk/"bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none", "-Xlint:all,-options", "-Werror",
                          "-cp", jar, "-d", classes, *paths])
        stage("service-and-session", [jdk/"bin/java", "-ea", "-cp", str(classes)+os.pathsep+str(jar),
                                     "org.trillionnium.hepta.local.NativeProductQueryBridgeHost", source, own/"recorded-060c-pair.json",
                                     out/"SERVICE-CASES.json"])
        report["named_reports"] = {}
        for kind in ("SERVICE",):
            path = out / (kind+"-CASES.json")
            result = json.loads(path.read_bytes())
            need(result.get("all_pass") is True and result["cases"] == len(result["results"]) == len(result["case_names"])
                 == len(set(result["case_names"])) and result["case_names"] == expected_service_cases and result["cases"] == len(expected_service_cases)
                 and all(row.get("passed") is True for row in result["results"]), "complete "+kind+" named report required")
            report["named_reports"][kind.lower()] = dict(file=ref(path), cases=result["cases"], assertions_total=result["assertions_total"])
        report["transport_measurements"] = ref(out/"TRANSPORT-MEASUREMENTS.json")
        report["expected_service_cases"] = expected_service_cases
        report["extraction"] = ref(out/"EXTRACTION.json")
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["input_after"] = base.inventory(source)
        report["inputs_unchanged"] = report["input_after"] == before
        report["tools_after"] = [ref(x) for x in tools]
        report["tools_unchanged"] = report["tools_before"] == report["tools_after"]
        report["all_pass"] = report["all_pass"] and report["inputs_unchanged"] and report["tools_unchanged"]
        target = out/"RESULT.json"
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")
        print(json.dumps(dict(all_pass=report["all_pass"], error=report.get("error"), result=ref(target),
                             named_reports=report.get("named_reports"))))
    return 0 if report["all_pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
