#!/usr/bin/env python3
"""Test exact setup+sampling methods against the pinned processor API semantics.

Original: prompt-to-grammar failure. R1 setup-only: duplicate generated-token
acceptance failure. R2: required behaviors pass. Processor/graph fakes make this
a control-flow regression, not Android, tokenizer or NPU numerical validation.
"""
from pathlib import Path
import argparse
import hashlib
import json
import resource
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--upstream-root", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--result", type=Path, required=True)
    args = ap.parse_args()
    raw = (args.upstream_root / "core/src/llm/llm_model.cpp").read_bytes()
    assert sha(raw) == "d164374f843ab3918134e1f7f0e6b1e436f212ba2e574dcc1be03ebf074a6eb8"
    text = raw.decode()
    boundaries = {
        "prepare_sampler.inc": ("void LLMModel::prepareSampler(", "\nvoid LLMModel::resolveKVLayout()"),
        "sample_next_token.inc": ("int32_t LLMModel::sampleNextToken(", "\nvoid LLMModel::readLastLogits("),
    }
    original, candidate = {}, {}
    manifest = json.loads((HERE / "review-r2/PATCH-MANIFEST.json").read_text())
    for name, (begin, end) in boundaries.items():
        start = text.index(begin)
        finish = text.index(end, start)
        original[name] = (text[start:finish].rstrip() + "\n").encode()
        candidate[name] = (HERE / name).read_bytes()
        assert sha(candidate[name]) == manifest["replacement_functions_sha256"][name]
    setup_only = dict(original, **{"prepare_sampler.inc": candidate["prepare_sampler.inc"]})
    compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    assert compiler, "existing host C++ compiler required"
    args.work.mkdir(parents=False, exist_ok=False)
    source = (HERE / "tests/sampler_setup_test.cpp").read_bytes()
    result = {"schema": "hepta.qairt-grammar-host-behavior.v2", "Android_compiler_invoked": False,
              "processor_and_graph_runtime_faked": True, "sample_accepts_internally_like_pinned_proc": True,
              "phone_or_NPU_tested": False, "candidate_functions_sha256": {k: sha(v) for k, v in candidate.items()},
              "harness_sha256": sha(source), "compiler_basename": Path(compiler).name,
              "started_unix": time.time(), "runs": []}
    for name, functions in (("pinned-upstream", original), ("r1-setup-only", setup_only), ("r2-candidate", candidate)):
        folder = args.work / name
        (folder / "tests").mkdir(parents=True)
        for filename, contents in functions.items():
            (folder / filename).write_bytes(contents)
        (folder / "tests/sampler_setup_test.cpp").write_bytes(source)
        binary = folder / "host-test"
        flags = ["-std=c++20", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
        built = subprocess.run([compiler, *flags, str(folder / "tests/sampler_setup_test.cpp"), "-o", str(binary)],
                               capture_output=True, timeout=30)
        (folder / "build.stderr").write_bytes(built.stderr)
        assert built.returncode == 0, built.stderr.decode(errors="replace")
        ran = subprocess.run([str(binary)], capture_output=True, timeout=10, preexec_fn=no_core)
        (folder / "stdout.raw").write_bytes(ran.stdout)
        (folder / "stderr.raw").write_bytes(ran.stderr)
        result["runs"].append({"name": name, "flags": flags, "compile_exit": built.returncode,
                               "process_exit": ran.returncode, "stdout": ran.stdout.decode(errors="replace"),
                               "stderr": ran.stderr.decode(errors="replace"),
                               "functions_sha256": {k: sha(v) for k, v in functions.items()}})
    result["original_prompt_failure_reproduced"] = (result["runs"][0]["process_exit"] != 0 and
                                                   "grammar rejected token" in result["runs"][0]["stderr"])
    result["r1_generated_double_accept_failure_reproduced"] = (result["runs"][1]["process_exit"] != 0 and
                                                              "grammar rejected token" in result["runs"][1]["stderr"])
    result["r2_behavioral_checks_pass"] = (result["runs"][2]["process_exit"] == 0 and
                                         result["runs"][2]["stdout"].startswith("PASS:"))
    result["all_pass"] = (result["original_prompt_failure_reproduced"] and
                          result["r1_generated_double_accept_failure_reproduced"] and result["r2_behavioral_checks_pass"])
    result["finished_unix"] = time.time()
    with args.result.open("x") as stream:
        print(json.dumps(result, indent=2), file=stream)
    print(json.dumps(result, indent=2))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
