#!/usr/bin/env python3
"""Real archived date DOM/AX values, original v62 regression, and fatal capture method.

The original query40 runner must already pass on the same source. This gate verifies
its input closure, recompiles the current domain, and records explicit value-carrier
boundaries. No Android/IPC/native action or business result is executed here.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import time


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def read(path):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), "unlinked absolute input")
    a = path.stat()
    need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and 0 <= a.st_size <= 4 << 20, "bounded ordinary input")
    value = path.read_bytes()
    b = path.stat()
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(key(a) == key(b) and len(value) == a.st_size, "input changed while read")
    return value


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    need(read(path) == value, "new output differs")


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "output", "query-output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    for value in vars(args).values():
        need(value.is_absolute(), "absolute paths required")
    args.output.mkdir(exist_ok=False)
    result = {"schema": "hepta.flight-date-fatal-host-gate.v1", "all_pass": False,
              "started_epoch": time.time(), "steps": [], "phone_operations": 0,
              "business_verified": False, "authenticated_ipc_replayed": False,
              "live_native_authority_reconstructed": False, "android_cleanup_executed": False}
    inputs = {}
    def take(path):
        value = read(path)
        if path in inputs:
            need(inputs[path] == value, "input changed between reads")
        inputs[path] = value
        return value
    def run(name, argv):
        command = [str(x) for x in argv]
        p = subprocess.run(command, capture_output=True, timeout=120)
        put(args.output / (name + ".stdout"), p.stdout)
        put(args.output / (name + ".stderr"), p.stderr)
        result["steps"].append({"name": name, "argv": command, "exit_code": p.returncode,
                                 "stdout_sha256": sha(p.stdout), "stderr_sha256": sha(p.stderr)})
        need(p.returncode == 0, name + " failed: " + p.stderr.decode(errors="replace"))
    try:
        source = args.source
        query = json.loads(take(args.query_output / "RESULT.json"))
        need(query.get("all_pass") is True and query["cases"].get("cases") == 40
             and query["cases"].get("assertions") == 187, "original query40/187 must pass first")
        result["query_receipt_sha256"] = sha(inputs[args.query_output / "RESULT.json"])
        query_rows = query["source_inputs"]
        for row in query_rows:
            p = pathlib.Path(row["path"])
            value = take(p)
            need(len(value) == row["bytes"] and sha(value) == row["sha256"], "query input closure changed: " + str(p))
        domain_path = source / "src/org/trillionnium/hepta/local/WebFlightDomain.java"
        session_path = source / "src/org/trillionnium/hepta/local/WebFlightSession.java"
        for path in (domain_path, session_path):
            need(sum(row["path"] == str(path) for row in query_rows) == 1, "query source is from another component")
        domain = take(domain_path)
        session = take(session_path)
        test_dir = source / "tests/web-flight"
        test = test_dir / "WebFlightDateValueHostTest.java"
        take(test)
        original_runner = test_dir / "run_query_host_tests.py"
        runner_bytes = take(original_runner)
        spec = importlib.util.spec_from_file_location("original_query_gate", original_runner)
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        method = original.java_block(session, "private PhoneObservation publishWaiting(")
        need("private evidence storage budget reached" in method, "fatal production method missing")
        observe = original.java_block(session, "PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline)throws Exception")
        early = 'if("state_changed".equals(first.status)&&"private evidence storage budget reached".equals(first.callback().opt("reason")))'
        need(observe.count(early) == 1 and observe.index(early) < observe.index('if("state_changed".equals(first.status)){'),
             "state_changed permanent refusal must precede original reread")
        result["source_contract_early_state_changed_before_reread"] = True
        result["source_contract_is_not_live_observe_replay"] = True
        template = take(test_dir / "WebFatalCaptureHostTest.java.template").decode("utf-8")
        marker = "/*__ACTUAL_PUBLISH_WAITING__*/"
        need(template.count(marker) == 1, "one exact production-method insertion")
        projected = template.replace(marker, method).encode("utf-8")
        projected_path = args.output / "generated/org/trillionnium/hepta/local/WebFatalCaptureHostTest.java"
        put(projected_path, projected)
        result["production_method_sha256"] = sha(method.encode("utf-8"))
        result["projection_sha256"] = sha(projected)
        result["original_extractor_sha256"] = sha(runner_bytes)
        fixtures = test_dir / "date-actual-fixtures"
        provenance = json.loads(take(fixtures / "PROVENANCE.json"))
        need(provenance.get("original_bytes_unchanged") is True and len(provenance["files"]) == 4,
             "original four evidence files required")
        originals = args.output / "originals"
        originals.mkdir()
        for row in provenance["files"]:
            name = row["name"]
            need(pathlib.PurePosixPath(name).name == name and name.endswith(".json.gz"), "bounded fixture name")
            packed = take(fixtures / name)
            need(len(packed) == row["bytes"] and sha(packed) == row["sha256"], "packed original differs")
            value = gzip.decompress(packed)
            need(len(value) == row["source_bytes"] and sha(value) == row["source_sha256"], "expanded original differs")
            put(originals / name[:-3], value)
        legacy = gzip.decompress(take(fixtures / "legacy-v62-WebFlightDomain.java.gz"))
        need(len(legacy) == 47213 and sha(legacy) == "ed6d080063937f428d14f3cabc70b1333feaf32ec53ab9cf572bae8ec0476a3f",
             "exact original v62 domain required")
        legacy_path = args.output / "legacy/org/trillionnium/hepta/local/WebFlightDomain.java"
        put(legacy_path, legacy)
        classes = args.query_output / "classes"
        need(classes.is_dir() and not classes.is_symlink(), "original query classes required")
        class_paths = sorted(classes.rglob("*.class"))
        need(class_paths, "query classes empty")
        for p in class_paths:
            take(p)
        take(args.json_jar)
        java, javac = args.java_home / "bin/java", args.java_home / "bin/javac"
        take(java); take(javac)
        new = args.output / "classes"; new.mkdir()
        old = args.output / "legacy-classes"; old.mkdir()
        cp = str(classes) + os.pathsep + str(args.json_jar)
        flags = [javac, "--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror"]
        run("compile-current", flags + ["-cp", cp, "-d", new, domain_path, test, projected_path])
        run("current-date", [java, "-cp", str(new) + os.pathsep + cp,
                             "org.trillionnium.hepta.local.WebFlightDateValueHostTest", originals, args.output / "CURRENT.json"])
        run("fatal-capture", [java, "-cp", str(new) + os.pathsep + cp,
                              "org.trillionnium.hepta.local.WebFatalCaptureHostTest", originals / "actual-fatal-frame.json", args.output / "FATAL.json"])
        run("compile-legacy", flags + ["-cp", cp, "-d", old, legacy_path])
        run("legacy-date", [java, "-cp", str(old) + os.pathsep + str(new) + os.pathsep + cp,
                            "org.trillionnium.hepta.local.WebFlightDateValueHostTest", originals, args.output / "LEGACY.json", "legacy"])
        result["current"] = json.loads(read(args.output / "CURRENT.json"))
        result["fatal"] = json.loads(read(args.output / "FATAL.json"))
        result["legacy"] = json.loads(read(args.output / "LEGACY.json"))
        for key, count in (("current", 17), ("fatal", 7), ("legacy", 1)):
            need(result[key].get("all_pass") is True and result[key].get("cases") == count, "actual case count differs: " + key)
        result["all_pass"] = True
    except Exception as error:
        result["error"] = str(error)
    finally:
        result["inputs_unchanged"] = all(read(path) == value for path, value in inputs.items())
        result["all_pass"] = result["all_pass"] and result["inputs_unchanged"]
        result["source_inputs"] = [{"path": str(path), "bytes": len(value), "sha256": sha(value)}
                                   for path, value in inputs.items()]
        result["finished_epoch"] = time.time()
        put(args.output / "RESULT.json", enc(result))
        print(json.dumps({"all_pass": result["all_pass"], "error": result.get("error"),
                          "counts": {k: result.get(k, {}).get("cases") for k in ("current", "fatal", "legacy")},
                          "result": str(args.output / "RESULT.json"), "result_sha256": sha(enc(result))}, ensure_ascii=False), flush=True)
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
