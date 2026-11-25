#!/usr/bin/env python3
"""Compare whole old/new AX capture classes and count only full-receipt encodes.
Normal variants compile unmodified production. Counter variants add a single
entry counter to independent copies, never replace canonicalization or validation.
No Android or phone execution; this does not measure phone latency.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import time

PKG = Path("src/org/trillionnium/hepta/local")
TEST = Path("tests/native-ax-canonical-reuse")
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
FIXTURE_SHA = "a7680b4a53cc702c98da44439543984a933e67e0193e774df23ff07a8c569644"
BASE_SHA = "96a0099759222c59b78950230eae842ebd274e42035746ece4b9e0cf50e94a19"
CURRENT_SHA = "9a1677456b4f1435416649fe01d2d4690af9ffe072946f8688a54bce81fc8d86"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def meta(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("ordinary direct source required: " + str(path))
    data = path.read_bytes()
    after = path.lstat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise RuntimeError("input changed while reading")
    return dict(path=str(path), bytes=len(data), sha256=sha(data), mode=stat.S_IMODE(before.st_mode))

def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")

def instrument(raw):
    old = "    static byte[] canonicalBytes(Object v){\n"
    new = """    private static int hostFullReceiptCanonicalCalls;
    static byte[] canonicalBytes(Object v){
        if(v instanceof Map){
            Object schema=((Map<?,?>)v).get("schema");
            if(SCHEMA.equals(schema)||FORM_SCHEMA.equals(schema)||INPUT_SCHEMA.equals(schema))
                hostFullReceiptCanonicalCalls++;
        }
"""
    text = raw.decode("utf-8")
    need(text.count(old) == 1, "one exact full canonical entry required")
    return text.replace(old, new, 1).encode("utf-8")

def semantic(report):
    value = json.loads(json.dumps(report))
    value.pop("counter_instrumented_host_copy")
    for row in value["results"]:
        row.pop("full_receipt_canonical_calls_prewrite", None)
        row.pop("full_receipt_canonical_calls_roundtrip", None)
    return value

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    source, out, jdk, jar = [getattr(args, k).resolve() for k in ("source", "output", "java_home", "json_jar")]
    need(not out.exists() and source != out and source not in out.parents, "fresh output outside source")
    helper = source / "tests/native-ax-observation/protected_publication.py"
    capture = source / PKG / "ObservationCaptureEvidence.java"
    fixture = source / "tests/native-xiaomi-search-input/real-censuses.json"
    need(meta(capture)["sha256"] == CURRENT_SHA, "exact reviewed current capture source")
    need(meta(jar)["sha256"] == JSON_SHA and meta(jar)["bytes"] == 78332, "actual JSON dependency pin")
    need(meta(fixture)["sha256"] == FIXTURE_SHA, "exact existing non-private recorded fixture")
    predecessor = runpy.run_path(str(helper))["without_canonical"]
    current = capture.read_bytes()
    baseline = predecessor(current)
    need(sha(baseline) == BASE_SHA and predecessor(baseline) == baseline, "complete baseline inverse")
    try:
        predecessor(b"?" + current[1:])
    except RuntimeError:
        pass
    else:
        raise RuntimeError("unknown capture byte change was accepted")
    names = ("NativeCtripFormObservation", "NativeActionSnapshotCheck",
             "NativeXiaomiSearchInputObservation", "ObservedChildText", "ObservedTargetLabels",
             "ObservedScrollActions", "ObservedImeEnter")
    shared = [source / PKG / (n + ".java") for n in names]
    shared += [source / "tests/native-action-integration/NativeActionSnapshotCheckHostTest.java",
               source / "tests/native-ctrip-form-observation/FormPairHostTest.java",
               source / "tests/native-xiaomi-search-input/NativeXiaomiSearchInputHostTest.java",
               source / TEST / "AxCanonicalReuseHost.java"]
    paths = [capture, helper, fixture, source / TEST / "run_host.py", *shared]
    tools = [jdk / "bin/java", jdk / "bin/javac", jdk / "lib/modules", jdk / "lib/ct.sym", jar]
    before, tool_before = [meta(p) for p in paths], [meta(p) for p in tools]
    out.mkdir(mode=0o700)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", JAVA_HOME=str(jdk))
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    result = dict(schema="hepta.ax-canonical-reuse-host-gate.v1", all_pass=False,
                  source=str(source), input_before=before, tools_before=tool_before, stages=[], variants={},
                  phone_operations=0, android_execution=False, model_executed=False,
                  phone_latency_improvement_claimed=False, deadline_changed=False, durability_changed=False,
                  publication_fences_changed=False, full_census_checks_removed=False,
                  instrumentation="Only independent counter copies get one extra private test counter at the actual canonicalBytes entry; normal old/new classes are unmodified.")
    try:
        for label, raw, counted in (("baseline", baseline, False), ("candidate", current, False),
                                    ("baseline-counted", baseline, True), ("candidate-counted", current, True)):
            vdir = out / label
            vdir.mkdir()
            classes, evidence_dir = vdir / "classes", vdir / "evidence"
            classes.mkdir()
            evidence_dir.mkdir()
            actual = capture
            if label != "candidate":
                actual = evidence_dir / "ObservationCaptureEvidence.java"
                actual.write_bytes(instrument(raw) if counted else raw)
                actual.chmod(0o644)
            commands = [
                ("compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none", "-Xlint:all", "-Werror",
                             "-cp", jar, "-d", classes, actual, *shared]),
                ("cases", [jdk / "bin/java", "-ea", "-cp", str(classes) + os.pathsep + str(jar),
                           "org.trillionnium.hepta.local.AxCanonicalReuseHost", fixture, vdir]),
            ]
            for stage, argv in commands:
                started = time.monotonic()
                proc = subprocess.run(list(map(str, argv)), cwd=vdir, env=env, capture_output=True, timeout=180)
                (vdir / (stage + ".stdout")).write_bytes(proc.stdout)
                (vdir / (stage + ".stderr")).write_bytes(proc.stderr)
                result["stages"].append(dict(name=label + "-" + stage, argv=list(map(str, argv)),
                    exit_code=proc.returncode, elapsed_seconds=time.monotonic() - started,
                    stdout=meta(vdir / (stage + ".stdout")), stderr=meta(vdir / (stage + ".stderr"))))
                need(proc.returncode == 0, label + " actual whole capture " + stage + " failed")
            report = json.loads((vdir / "CASES.json").read_text())
            need(report["all_pass"] is True and report["cases"] == 23 and report["assertions"] == 45, "exact equivalence matrix")
            need(report["counter_instrumented_host_copy"] == counted and report["phone_operations"] == 0, "execution boundary")
            result["variants"][label] = dict(capture_compile_input=meta(actual), source_parent_sha256=sha(raw),
                                              instrumented=counted, cases=meta(vdir / "CASES.json"), report=report)
        base = result["variants"]["baseline"]["report"]
        comparisons = []
        for label in ("candidate", "baseline-counted", "candidate-counted"):
            report = result["variants"][label]["report"]
            need(semantic(report) == semantic(base), "exact old/new outcomes and refusal reasons differ: " + label)
            for row in base["results"]:
                if "canonical_file" not in row:
                    continue
                old_file = out / "baseline" / row["canonical_file"]
                new_file = out / label / row["canonical_file"]
                need(old_file.read_bytes() == new_file.read_bytes(), "full canonical byte mismatch")
                comparisons.append(dict(variant=label, case=row["name"], baseline=meta(old_file),
                                        actual=meta(new_file), byte_for_byte_equal=True))
        counts = []
        for old, new in zip(result["variants"]["baseline-counted"]["report"]["results"],
                            result["variants"]["candidate-counted"]["report"]["results"]):
            need(old["name"] == new["name"], "case ordering")
            if "canonical_file" not in old:
                continue
            need(old["full_receipt_canonical_calls_prewrite"] == 2 and old["full_receipt_canonical_calls_roundtrip"] == 4,
                 "actual baseline full-receipt canonical invocation count")
            need(new["full_receipt_canonical_calls_prewrite"] == 1 and new["full_receipt_canonical_calls_roundtrip"] == 2,
                 "actual current full-receipt canonical invocation count")
            counts.append(dict(case=old["name"], baseline_prewrite=2, candidate_prewrite=1,
                               baseline_roundtrip=4, candidate_roundtrip=2))
        result.update(all_pass=True, distinct_cases=23, assertions_per_variant=45, variants_executed=4,
                      exact_byte_comparisons=comparisons, actual_counted_full_receipt_calls=counts,
                      all_old_new_refusal_reasons_identical=True, unknown_source_inverse_refused=True)
    except Exception as error:
        result["error"] = dict(type=type(error).__name__, message=str(error))
    finally:
        result["input_after"], result["tools_after"] = [meta(p) for p in paths], [meta(p) for p in tools]
        result["inputs_unchanged"] = result["input_after"] == before
        result["tools_unchanged"] = result["tools_after"] == tool_before
        result["all_pass"] = result["all_pass"] and result["inputs_unchanged"] and result["tools_unchanged"]
        save(out / "RESULT.json", result)
        print(json.dumps(dict(all_pass=result["all_pass"], error=result.get("error"),
                              distinct_cases=result.get("distinct_cases"), result=meta(out / "RESULT.json"))))
    return 0 if result["all_pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
