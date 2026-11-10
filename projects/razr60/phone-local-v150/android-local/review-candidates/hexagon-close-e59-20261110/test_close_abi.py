#!/usr/bin/env python3
"""Offline ABI regression over exact external llama.cpp and FastRPC inputs.

This runner never patches its inputs, downloads code, loads a FastRPC library,
builds Android/DSP code, or contacts a device. Only small production declarations
and the production forwarding wrapper are extracted into host test fixtures.
Upstream licenses and attribution are retained beside this runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

DRIVER_SHA = "8b93060b8f5a0aceb77c708d1772c56699810e901a52ab0ae1a4826f9f3e6854"
PATCHED_SHA = "926f4a49fa4b5f840c9ec424add67b509b2171e03d537409f02662bc9b35d273"
REMOTE_SHA = "f9d0690cfd8953697d6fc3163c2be448a7b5b801148808c9b1b360857aeabc44"
OLD = "typedef int (*remote_handle64_close_pfn_t)(remote_handle h);"
NEW = "typedef int (*remote_handle64_close_pfn_t)(remote_handle64 h);"
FLAGS = ["-std=c++17", "-O0", "-fno-lto", "-Wall", "-Wextra", "-Wconversion", "-Werror", "-pedantic-errors"]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def one(pattern, text, label):
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    require(len(matches) == 1, "missing or ambiguous production " + label)
    return matches[0].group(0)


def inputs(path, expected, limit):
    path = path.resolve(strict=True)
    require(path.is_file() and 0 < path.stat().st_size <= limit, "input file size is invalid")
    raw = path.read_bytes()
    require(sha(raw) == expected, "input SHA256 differs from the reviewed exact source")
    return path, raw


def extract_driver(text):
    typedef = one(r"^typedef int \(\*remote_handle64_close_pfn_t\)\(remote_handle(?:64)? h\);$", text, "close typedef")
    pointer = one(r"^remote_handle64_close_pfn_t\s+remote_handle64_close_pfn\s*=\s*nullptr;$", text, "pointer storage")
    wrapper = one(r"^HTPDRV_API int remote_handle64_close\(remote_handle64 h\) \{\n    return remote_handle64_close_pfn\(h\);\n\}", text, "close wrapper")
    return {"typedef": typedef, "pointer_storage": pointer, "wrapper": wrapper}


def extract_api(text):
    return {
        "handle32": one(r"^typedef uint32_t remote_handle;$", text, "FastRPC 32-bit handle"),
        "handle64": one(r"^typedef uint64_t remote_handle64;$", text, "FastRPC 64-bit handle"),
        "close_prototype": one(r"^__QAIC_REMOTE_EXPORT __QAIC_RETURN int __QAIC_REMOTE\(remote_handle64_close\)\(__QAIC_IN remote_handle64 h\) __QAIC_REMOTE_ATTRIBUTE;$", text, "FastRPC close prototype"),
    }


def api_header(api):
    return """// Host-only extraction from Qualcomm FastRPC remote.h.
// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
#pragma once
#include <stdint.h>
// Platform export/annotation macros are empty in this Linux host fixture.
#define __QAIC_REMOTE_EXPORT
#define __QAIC_RETURN
#define __QAIC_REMOTE(name) name
#define __QAIC_IN
#define __QAIC_REMOTE_ATTRIBUTE
extern "C" {
""" + "\n".join(api.values()) + "\n}\n"


def driver_fixture(parts):
    return """// Extracted llama.cpp members; MIT License, The ggml authors, 2023-2026.
// No complete driver, dynamic loader or DSP implementation is compiled here.
#include "api-fragment.h"
#include <type_traits>
#define HTPDRV_API extern "C"
""" + parts["typedef"] + "\n" + parts["pointer_storage"] + "\n" + parts["wrapper"] + """
using FastRpcClosePrototype = decltype(&remote_handle64_close);
static_assert(sizeof(remote_handle) == 4, "FAST_RPC_HANDLE32_WIDTH");
static_assert(sizeof(remote_handle64) == 8, "FAST_RPC_HANDLE64_WIDTH");
static_assert(std::is_same<remote_handle64_close_pfn_t, FastRpcClosePrototype>::value,
              "FAST_RPC64_CLOSE_ABI_MISMATCH");
void install_close_stub(FastRpcClosePrototype pointer) {
    // No cast may hide an incompatible API function-pointer assignment.
    remote_handle64_close_pfn = pointer;
}
"""


MAIN = r'''// Synthetic host peer: this is not a real or simulated DSP/FastRPC driver.
#include "api-fragment.h"
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>

void install_close_stub(decltype(&remote_handle64_close));
static remote_handle64 observed = 0;
static unsigned calls = 0;
static int peer_return = 0;
extern "C" int close_stub(remote_handle64 handle) {
    observed = handle;
    ++calls;
    return peer_return;
}

int main() {
    struct TestCase { remote_handle64 handle; int result; };
    const TestCase cases[] = {
        {UINT64_C(0x0000000000000001), 0},
        {UINT64_C(0x0000000112345678), 44},
        {UINT64_C(0x123456789abcdef0), -17},
        {UINT64_C(0xffffffff00000001), 0},
        {UINT64_C(0x8000000000000000), 44},
        {UINT64_C(0xffffffffffffffff), -17},
    };
    install_close_stub(&close_stub);
    unsigned high_bit_cases = 0;
    for (const TestCase &test : cases) {
        const unsigned previous_calls = calls;
        peer_return = test.result;
        const int returned = remote_handle64_close(test.handle);
        if (observed != test.handle || calls != previous_calls + 1 || returned != test.result) {
            std::cerr << "FAIL: production forwarding wrapper changed the handle, call count or return value\n";
            return 1;
        }
        if ((test.handle >> 32) != 0) { ++high_bit_cases; }
        std::cout << "handle=0x" << std::hex << std::setw(16) << std::setfill('0') << test.handle
                  << " observed=0x" << std::setw(16) << observed << std::dec
                  << " return=" << returned << " PASS\n";
    }
    if (calls != 6 || high_bit_cases != 5) { return 2; }
    std::cout << "PASS cases=6 high32_nonzero_cases=5 actual_stub_dispatches=6 return_values_preserved=true\n";
    std::cout << "SCOPE host-only extracted production typedef/storage/wrapper; no Android, DSP or device validation\n";
    return 0;
}
'''


def invoke(argv, cwd, label, timeout):
    completed = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout, check=False)
    for stream in ("stdout", "stderr"):
        (cwd / (label + "." + stream)).write_bytes(getattr(completed, stream))
    return completed, {
        "command": ["c++" if i == 0 and label == "compile" else arg for i, arg in enumerate(argv)],
        "exit_code": completed.returncode,
        "stdout_sha256": sha(completed.stdout), "stderr_sha256": sha(completed.stderr),
        "stdout_bytes": len(completed.stdout), "stderr_bytes": len(completed.stderr),
    }


def run(args):
    source_path, baseline = inputs(args.driver_source, DRIVER_SHA, 131072)
    header_path, header = inputs(args.fastrpc_header, REMOTE_SHA, 131072)
    text = baseline.decode("utf-8")
    require(text.count(OLD) == 1 and NEW not in text, "one reviewed baseline typedef is required")
    patched = text.replace(OLD, NEW).encode("utf-8")
    require(sha(patched) == PATCHED_SHA, "in-memory one-line candidate differs from the reviewed patch")
    api = extract_api(header.decode("utf-8"))
    old_parts, new_parts = extract_driver(text), extract_driver(patched.decode("utf-8"))
    require(old_parts["pointer_storage"] == new_parts["pointer_storage"]
            and old_parts["wrapper"] == new_parts["wrapper"], "unrelated production members changed")
    compiler = shutil.which(args.compiler)
    require(compiler is not None, "requested host compiler is unavailable")
    version = subprocess.run([compiler, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             check=True, timeout=10).stdout.decode("utf-8", "replace").splitlines()[0]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": "hepta.hexagon-close-host-abi.v1",
        "scope": "Host-only exact source extraction and synthetic C++ ABI peer; no driver loading or DSP",
        "compiler": version, "machine": platform.machine(), "compiler_flags": FLAGS,
        "inputs": {"driver_baseline_sha256": DRIVER_SHA, "driver_one_line_candidate_sha256": PATCHED_SHA,
                   "fastrpc_header_sha256": REMOTE_SHA, "runner_sha256": sha(Path(__file__).read_bytes())},
        "extracted_member_sha256": {"baseline": {k: sha(v.encode()) for k, v in old_parts.items()},
                                    "patched": {k: sha(v.encode()) for k, v in new_parts.items()},
                                    "api": {k: sha(v.encode()) for k, v in api.items()}},
        "checks": [], "baseline_binary_executed": False, "input_files_modified": False,
        "android_built": False, "fastrpc_library_loaded": False, "dsp_contacted": False,
        "phone_contacted": False, "model_inference_tested": False, "deployed": False,
    }
    for phase, parts in (("baseline", old_parts), ("patched", new_parts)):
        directory = out / phase
        directory.mkdir()
        generated = {"api-fragment.h": api_header(api), "driver.cpp": driver_fixture(parts), "main.cpp": MAIN}
        for name, content in generated.items():
            (directory / name).write_text(content, encoding="utf-8")
        completed, check = invoke([compiler, *FLAGS, "driver.cpp", "main.cpp", "-o", "abi-test"],
                                  directory, "compile", 30)
        check.update(name=phase + "-compile", generated_file_sha256={k: sha(v.encode()) for k, v in generated.items()})
        result["checks"].append(check)
        if phase == "baseline":
            check["expected_rejection_observed"] = (completed.returncode != 0
                and b"FAST_RPC64_CLOSE_ABI_MISMATCH" in completed.stderr)
        elif completed.returncode == 0:
            executed, behavior = invoke(["./abi-test"], directory, "behavior", 10)
            behavior.update(name="patched-behavior", cases=6, high32_nonzero_cases=5,
                            actual_stub_dispatches=6, separate_translation_units=True)
            behavior["expected_pass_observed"] = (executed.returncode == 0
                and b"PASS cases=6 high32_nonzero_cases=5 actual_stub_dispatches=6 return_values_preserved=true" in executed.stdout)
            result["checks"].append(behavior)
    result["input_files_unchanged_verified"] = (sha(source_path.read_bytes()) == DRIVER_SHA
        and sha(header_path.read_bytes()) == REMOTE_SHA)
    result["all_expected_outcomes"] = (len(result["checks"]) == 3
        and result["checks"][0].get("expected_rejection_observed") is True
        and result["checks"][1]["exit_code"] == 0
        and result["checks"][2].get("expected_pass_observed") is True
        and result["input_files_unchanged_verified"])
    (out / "RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"all_expected_outcomes": result["all_expected_outcomes"],
                      "checks": [{"name": c["name"], "exit_code": c["exit_code"]} for c in result["checks"]],
                      "host_only": True}, indent=2))
    return 0 if result["all_expected_outcomes"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver-source", type=Path, required=True)
    parser.add_argument("--fastrpc-header", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new directory; existing output is refused")
    parser.add_argument("--compiler", default="c++")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("ABI regression did not qualify: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
