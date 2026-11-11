#!/usr/bin/env python3
"""Independent process tests of the exact runner with an explicit fake SDK.

No phone, real model, GPU, NPU, or Hepta tool is involved. The optional scheduling
shim delays real clock-call returns and writes; it never fabricates clock values.

Run on a Linux host with a GNU-compatible linker:
    python3 tests/review_boundaries.py
Use --out /absolute/new/directory to preserve a separate repeat run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate output key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


SHIM = r'''
/* TEST SCHEDULING SHIM ONLY. Never package with the runner. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static _Thread_local unsigned clock_calls;
static _Thread_local int write_recorded;
static int main_thread(void) { return syscall(SYS_gettid) == (long)getpid(); }
static void pause_ms(long ms) {
    struct timespec t={ms/1000,(ms%1000)*1000000};
    while(nanosleep(&t,&t) && errno==EINTR) {}
}
int __real_clock_gettime(clockid_t id,struct timespec *value);
int __wrap_clock_gettime(clockid_t id,struct timespec *value) {
    int result=__real_clock_gettime(id,value);
    if(id==CLOCK_MONOTONIC && main_thread()) {
        ++clock_calls;
        const char *at=getenv("HEPTA_REVIEW_DELAY_CLOCK_ORDINAL");
        if(at && clock_calls==(unsigned)strtoul(at,NULL,10)) pause_ms(1050);
    }
    return result;
}
ssize_t __real_write(int fd,const void *buf,size_t length);
ssize_t __wrap_write(int fd,const void *buf,size_t length) {
    if(length && ((const char *)buf)[0]=='{' && !write_recorded) {
        write_recorded=1;
        if(main_thread()) {
            char line[100];int n=snprintf(line,sizeof(line),"REVIEW_MAIN_FIRST_WRITE_CLOCK=%u\n",clock_calls);
            (void)syscall(SYS_write,2,line,(size_t)n);
        }
        const char *delay=getenv(main_thread()?"HEPTA_REVIEW_MAIN_WRITE_DELAY_MS":"HEPTA_REVIEW_WATCHDOG_WRITE_DELAY_MS");
        if(delay) pause_ms(strtol(delay,NULL,10));
    }
    return __real_write(fd,buf,length);
}
'''


def main():
    root = Path(__file__).resolve().parents[1]
    if platform.system() != "Linux":
        raise SystemExit("This scheduling fixture requires Linux and a GNU-compatible --wrap linker")
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=root)
    parser.add_argument("--runner-sha256", default="3978dc122263bbc23a4c30983748620381a9eb95f3c1e6d976336676644ffb5e")
    parser.add_argument("--out", type=Path, default=root / "build" / "review-boundaries")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out
    assert out.is_absolute() and not out.exists()
    assert sha((source / "runner.c").read_bytes()) == args.runner_sha256
    out.mkdir(parents=True)
    rows = []
    shim = out / "review_schedule_shim.c"
    shim.write_text(SHIM)
    fake = (source / "tests/fake_sdk.c").read_text()
    anchor = '    if(is_case("generation_hang"))hang();'
    assert fake.count(anchor) == 1
    injected = '''    if(is_case("review_interrupt_return")) {
        fputs("REVIEW_GENERATION_READY\\n",stderr);fflush(stderr);
        struct timespec t={5,0};(void)nanosleep(&t,NULL);
    }
'''
    fake = fake.replace(anchor, injected + anchor)
    fake_path = out / "review_fake_sdk.c"
    fake_path.write_text(fake)
    exe = out / "runner-FAKE-SDK-schedule-test"
    command = ["/usr/bin/cc", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-pthread",
               "-DYYJSON_DISABLE_NON_STANDARD=1", "-DYYJSON_DISABLE_UTF8_VALIDATION=0",
               "-DYYJSON_READER_DEPTH_LIMIT=32", "-DYYJSON_WRITER_DEPTH_LIMIT=40",
               "-I" + str(source / "vendor/litert"), "-I" + str(source / "vendor/litert/c"),
               "-I" + str(source / "vendor/yyjson"), str(source / "runner.c"),
               str(source / "vendor/yyjson/yyjson.c"), str(fake_path), str(shim),
               "-Wl,--wrap=clock_gettime", "-Wl,--wrap=write", "-o", str(exe)]
    built = subprocess.run(command, capture_output=True, timeout=30)
    (out / "compile.stdout").write_bytes(built.stdout)
    (out / "compile.stderr").write_bytes(built.stderr)
    assert built.returncode == 0, built.stderr.decode(errors="replace")
    model = out / "NOT-a-real-model.litertlm"
    model.write_bytes(b"explicit host fixture only")
    base = {"schema": "hepta.litert-once.request.v1", "request_id": "review-1",
            "model_path": str(model), "prompt": "fixture only", "deadline_ms": 3000,
            "constraint": {"type": "json_schema", "value": {"type": "object"}}}
    def run(name, value=None, raw=None, expected=64, status="invalid_request", extra_env=None):
        encoded = raw if raw is not None else json.dumps(value or base, ensure_ascii=True).encode()
        environment = dict(os.environ, **(extra_env or {}))
        start = time.monotonic()
        process = subprocess.run([str(exe)], input=encoded, capture_output=True,
                                 timeout=5, env=environment)
        elapsed = time.monotonic() - start
        row = {"case": name, "exit_code_observed": process.returncode, "elapsed_s": elapsed,
               "stdout_sha256": sha(process.stdout), "stderr_sha256": sha(process.stderr)}
        (out / (name + ".stdout")).write_bytes(process.stdout)
        (out / (name + ".stderr")).write_bytes(process.stderr)
        try:
            decoded = strict(process.stdout)
        except (ValueError, UnicodeError) as error:
            decoded = {}
            row["json_error"] = str(error)
        row["status"] = decoded.get("status")
        row["passed"] = process.returncode == expected and decoded.get("status") == status
        row["passed"] &= decoded.get("process_exit_observed") is False and decoded.get("tools_executed") is False
        row["passed"] &= decoded.get("business_success_verified") is False
        if expected == 64:
            row["passed"] &= b"FAKE_SDK_STDOUT_MARKER" not in process.stderr
        rows.append(row)
        return row, decoded, process
    run("decoded_duplicate_key", raw=b'{"schema":"a","\\u0073chema":"b"}')
    run("decoded_nul", value=dict(base, prompt="x\0y"))
    run("lone_surrogate", value=dict(base, prompt="\ud800"))
    run("utf8_overlong", raw=b'{"prompt":"\xc0\xaf"}')
    run("json_comment", raw=b'{/*comment*/}')
    run("json_trailing_comma", raw=b'{"a":1,}')
    run("nested_duplicate", raw=json.dumps(base).replace('"type": "object"', '"type":"object","type":"array"').encode())
    run("unknown_root_field", value=dict(base, execute_tools=True))
    run("unsupported_backend", value=dict(base, backend="npu"))
    run("float_deadline", value=dict(base, deadline_ms=1000.0))
    run("overflow_deadline", value=dict(base, deadline_ms=2**64))
    run("negative_output_count", value=dict(base, max_output_tokens=-1))
    run("output_not_below_context", value=dict(base, max_context_tokens=512, max_output_tokens=512))
    run("prompt_size_limit", value=dict(base, prompt="x" * 262145))
    run("external_schema_ref", value=dict(base, constraint={"type": "json_schema", "value": {"$ref": "https://example.invalid/schema"}}))
    run("regex_nul", value=dict(base, constraint={"type": "regex", "value": "a\0b"}))
    run("regex_size_limit", value=dict(base, constraint={"type": "regex", "value": "x" * 65537}))
    deep = {}
    for _ in range(34):
        deep = {"a": deep}
    run("depth_limit", value=dict(base, constraint={"type": "json_schema", "value": deep}))
    run("relative_model", value=dict(base, model_path="relative.litertlm"))
    link = out / "symlink.litertlm"
    link.symlink_to(model)
    run("symlink_model", value=dict(base, model_path=str(link)))
    directory = out / "directory.litertlm"
    directory.mkdir()
    run("directory_model", value=dict(base, model_path=str(directory)))
    fifo = out / "fifo.litertlm"
    os.mkfifo(fifo)
    row, _, _ = run("fifo_rejected_without_waiting", value=dict(base, model_path=str(fifo), deadline_ms=1000))
    row["passed"] &= row["elapsed_s"] < 0.5
    normal = json.dumps(base).encode()
    run("exact_input_limit", raw=normal + b" " * (1024 * 1024 - len(normal)), expected=0, status="response_received")
    run("sdk_generation_error", extra_env={"HEPTA_FAKE_SCENARIO": "generation_error"}, expected=70, status="sdk_error")
    row, _, calibration = run("calibration", expected=0, status="response_received")
    match = re.search(rb"REVIEW_MAIN_FIRST_WRITE_CLOCK=(\d+)", calibration.stderr)
    assert match is not None
    final_check_ordinal = int(match.group(1)) - 2
    run("watchdog_wins_main_final_claim", value=dict(base, deadline_ms=1000), expected=124,
        status="deadline_exceeded", extra_env={"HEPTA_REVIEW_DELAY_CLOCK_ORDINAL": str(final_check_ordinal),
        "HEPTA_REVIEW_WATCHDOG_WRITE_DELAY_MS": "200"})
    for signo in (signal.SIGTERM, signal.SIGINT):
        name = "signal_main_publisher_" + signo.name.lower()
        env = dict(os.environ, HEPTA_FAKE_SCENARIO="review_interrupt_return",
                   HEPTA_REVIEW_MAIN_WRITE_DELAY_MS="100")
        process = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env)
        process.stdin.write(json.dumps(base).encode())
        process.stdin.close()
        process.stdin = None
        prefix = bytearray()
        while b"REVIEW_GENERATION_READY\n" not in prefix:
            line = process.stderr.readline()
            assert line, "fake SDK did not reach controlled generation wait"
            prefix.extend(line)
        time.sleep(0.03)
        start = time.monotonic()
        process.send_signal(signo)
        stdout, stderr = process.communicate(timeout=3)
        decoded = strict(stdout)
        (out / (name + ".stdout")).write_bytes(stdout)
        (out / (name + ".stderr")).write_bytes(bytes(prefix) + stderr)
        rows.append({"case": name, "exit_code_observed": process.returncode,
                     "elapsed_after_signal_s": time.monotonic() - start,
                     "status": decoded["status"], "stdout_sha256": sha(stdout),
                     "passed": process.returncode == 128 + signo and decoded["status"] == "cancelled"
                     and decoded["cleanup"] == "incomplete" and decoded["process_exit_observed"] is False})
    record = {"schema": "hepta.litert-independent-boundaries.v1", "runner_sha256": args.runner_sha256,
              "runner_modified_for_test": False, "compiler_argv": command,
              "test_double_sha256": sha(fake_path.read_bytes()), "schedule_shim_sha256": sha(shim.read_bytes()),
              "test_driver_sha256": sha(Path(__file__).read_bytes()),
              "source_inputs": {str(path.relative_to(source)): sha(path.read_bytes()) for path in
                  [source / "runner.c", source / "vendor/yyjson/yyjson.c", source / "vendor/yyjson/yyjson.h",
                   source / "tests/fake_sdk.c", *sorted((source / "vendor/litert/c").glob("*.h"))]},
              "cases": rows,
              "passed": sum(item["passed"] for item in rows), "total": len(rows),
              "phone_contacted": False, "real_model_or_gpu_inference": False,
              "final_check_ordinal_calibrated": final_check_ordinal}
    (out / "RESULT.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({key: record[key] for key in ("passed", "total", "runner_sha256", "phone_contacted")}))
    assert record["passed"] == record["total"], [r for r in rows if not r["passed"]]


if __name__ == "__main__":
    main()
