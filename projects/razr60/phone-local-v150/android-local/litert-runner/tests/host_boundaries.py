#!/usr/bin/env python3
"""Run the real runner against an explicit C API test double; never a model test."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path(__file__).resolve().parents[1]
out = root / "build" / "host-fixture"
out.mkdir(parents=True, exist_ok=True)
exe = out / "hepta-litert-FAKE-SDK"
command = [os.environ.get("CC", "cc"), "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-pthread",
    "-DYYJSON_DISABLE_NON_STANDARD=1", "-DYYJSON_READER_DEPTH_LIMIT=32", "-DYYJSON_WRITER_DEPTH_LIMIT=40",
    "-I" + str(root / "vendor/litert"), "-I" + str(root / "vendor/litert/c"),
    "-I" + str(root / "vendor/yyjson"), str(root / "runner.c"),
    str(root / "vendor/yyjson/yyjson.c"), str(root / "tests/fake_sdk.c"), "-o", str(exe)]
subprocess.run(command, check=True)
model = out / "fixture-is-NOT-a-model.litertlm"
model.write_bytes(b"fixture only; fake SDK does not parse weights")
base = {"schema":"hepta.litert-once.request.v1", "request_id":"fixture-1", "model_path":str(model),
    "prompt":"fixture only", "deadline_ms":3000, "constraint":{"type":"json_schema", "value":{"type":"object"}}}
rows = []

def run(name, data=None, scenario="normal", timeout=5):
    env = dict(os.environ, HEPTA_FAKE_SCENARIO=scenario)
    started = time.monotonic()
    result = subprocess.run([str(exe)], input=data if data is not None else json.dumps(base).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env)
    decoded = json.loads(result.stdout)
    row = {"case":name, "exit_code_observed":result.returncode, "elapsed_s":time.monotonic()-started,
        "stdout_bytes":len(result.stdout), "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),
        "status":decoded["status"], "result":decoded}
    rows.append(row)
    assert decoded["process_exit_observed"] is False
    assert decoded["tools_executed"] is False and decoded["business_success_verified"] is False
    return result, decoded

r, j = run("normal_raw_preservation")
assert r.returncode == 0 and j["status"] == "response_received"
assert j["cleanup"] == "sdk_delete_returned" and j["inference_completed"] is True
assert json.loads(j["raw_response_json"]) == j["response"]
assert j["response"]["tool_calls"][0]["function"]["name"] == "not_executed"
assert b"FAKE_SDK_STDOUT_MARKER" in r.stderr and b"FAKE_SDK_STDOUT_MARKER" not in r.stdout
for name, data in [("duplicate_request_key", b'{"schema":"x","schema":"y"}'),
    ("invalid_utf8", b'{"prompt":"\xff"}'), ("trailing_document", b'{}{}'),
    ("request_over_1mib", b'x' * (1024*1024+1))]:
    r, j = run(name, data)
    assert r.returncode == 64 and j["status"] == "invalid_request"
for scenario in ["generation_hang", "cleanup_hang", "load_hang"]:
    req = dict(base, deadline_ms=1000)
    r, j = run(scenario, json.dumps(req).encode(), scenario)
    assert r.returncode == 124 and j["status"] == "deadline_exceeded" and j["cleanup"] == "incomplete"
    assert rows[-1]["elapsed_s"] < 2.5
r, j = run("duplicate_native_response", scenario="duplicate_response")
assert r.returncode == 70 and j["status"] == "response_invalid"

started = time.monotonic()
p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
p.stdin.write(json.dumps(base).encode()); p.stdin.flush()
p.wait(timeout=12)
raw = p.stdout.read(); err = p.stderr.read(); p.stdin.close()
j = json.loads(raw)
assert p.returncode == 124 and j["phase"] == "input" and j["cleanup"] == "incomplete"
rows.append({"case":"stdin_never_closed", "exit_code_observed":p.returncode, "elapsed_s":time.monotonic()-started, "result":j})

env = dict(os.environ, HEPTA_FAKE_SCENARIO="generation_hang")
p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
p.stdin.write(json.dumps(dict(base, deadline_ms=10000)).encode()); p.stdin.close(); p.stdin=None
assert b"FAKE_SDK_STDOUT_MARKER" in p.stderr.readline()
p.send_signal(signal.SIGTERM)
raw, err = p.communicate(timeout=2)
j = json.loads(raw)
assert p.returncode == 143 and j["status"] == "cancelled" and j["cleanup"] == "incomplete"
rows.append({"case":"sigterm", "exit_code_observed":p.returncode, "result":j})

env = dict(os.environ, HEPTA_FAKE_SCENARIO="large_response")
started = time.monotonic()
p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
p.stdin.write(json.dumps(base).encode()); p.stdin.close(); p.stdin=None
p.wait(timeout=3)
raw = p.stdout.read(); err = p.stderr.read()
assert p.returncode == 74 and len(raw) <= 1024*1024
rows.append({"case":"stdout_backpressure", "exit_code_observed":p.returncode,
    "elapsed_s":time.monotonic()-started, "stdout_bytes":len(raw), "complete_json_required_by_caller":True})

report = {"schema":"hepta.litert-runner-host-fixtures.v1", "real_model_inference":False,
    "gpu_or_npu_execution":False, "sdk":"explicit fake_sdk.c test double with real C API headers",
    "runner_sha256":hashlib.sha256((root/"runner.c").read_bytes()).hexdigest(),
    "compiler_command":command, "cases":rows, "passed":len(rows)}
(out/"RESULT.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"passed":len(rows),"report":str(out/"RESULT.json"),"real_model_inference":False}))
