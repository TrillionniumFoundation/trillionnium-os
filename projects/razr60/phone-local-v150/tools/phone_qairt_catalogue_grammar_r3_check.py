#!/usr/bin/env python3
"""Check two frozen complete-schema catalogue prompts on approved R3 runtime.

This independent runner never dispatches generated actions. It requires the
SHA-bound, completed R3 five-case gate before any phone access, then verifies
all official/R2/R3 runtime files and the model. Both exact tokenizer gates must
pass before at most two model requests. Root/magisk inference does not qualify
the production UID2000/phone_worker domain or the phone control loop.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import importlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
import uuid

RUNTIME = "/data/local/tmp/hepta-geniex-vlm-r3-20261108"
R2_RUNTIME = "/data/local/tmp/hepta-geniex-core-r2-20261108"
OLD_RUNTIME = "/data/local/tmp/hepta-geniex-npu-v0100-20261108"
WORKER_NAME = "hepta-geniex-once-r2"
WORKER = RUNTIME + "/" + WORKER_NAME
WORKER_SHA = "67d4e368da136f74a7ab1022013cf1def64f75ebb32d91962772e28a2363864f"
CORE_SHA = "06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d"
VLM_SHA = "773e23de3f892d2cd9c468e7b0af32e6c254af341d4ed0e7ef0eda95f6ee1d73"
RUNTIME_PROFILE = "qairt-output-grammar-core-r2-vlm-r3-v1"
RUNTIME_MANIFEST_SHA = "cba2dba9d5b728cee9206af901493a987478babf0c072503972c4a1f2a2a6ca6"
R2_MANIFEST_SHA = "c4551f10e683382fc1e2285b21c67482d006223ace13c0ddcc6faebbe71b85d8"
RUNTIME_GATE_SHA = "8af9108bdbbe67d81f4c2b2efcde8ebe0d40f80a1e7e5047ec732aa0b171cfad"
FIXTURE_SHA = "9cb73dfc1008c4e27a2474464fa81a67b7a47bae389e7ea325b9e163119fce98"
MODEL_PINS_SHA = "1676a2ff35b577da6426cbe9790e2a5d1dbcfdeae1dc7c0e8898554f11026a6b"
COMPILER_SHA = "c230e076ae61c87a744c49b160a456c039d47441784ad3ccc2c6465bc67453a8"
STOP = "/data/trillionnium/owner-open/state/emergency-stop"
STOP_SHA = "ff6401f96ef8d2206e61e9fdf6d75d1dd11fe25f5696d7f6996b6647023fdb07"
CLAIMS = "/data/trillionnium/owner-open/state/phone-local-v150/retained-claims.json"
CLAIMS_SHA = "7feecc970e6499cd1735e5b0bf2c68386c669462a89a76d84f5bfc8b2225dd8c"
SDK_KEYS = {"resolve", "set_log_level", "init", "create", "template", "generate", "destroy", "deinit"}

MODEL = "/data/local/tmp/hepta-qwen3vl4b-qairt-r1-20261108/model"
CONFIG_SHA = "6b2a0b846974340c2bdc7d3ccea9a69a4410e07946738386b76204cb804c15d3"
TOKENIZER_SHA = "be75606093db2094d7cd20f3c2f385c212750648bd6ea4fb2bf507a6a4c55506"
LIBRARY_SHA = "7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d"
COUNTER_ROOT = "/data/local/tmp/hepta-token-counter-r2-20261108"
COUNTER_SHA = "09c2c8fb4b0c0095ffe612be82bc1b2124d47f9351c53fd0a77384c74395589c"
HEAD = b"<|im_start|>system\n"
MIDDLE = b"<|im_end|>\n<|im_start|>user\n"
TAIL = b"<|im_end|>\n<|im_start|>assistant\n"
CASE_NAMES = ["01-first-open", "02-after-three-actions-click"]


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def clean(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def pinned_file(info, maximum=1048576):
    path = Path(info["path"])
    require(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical fixture path")
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= maximum, "invalid fixture file")
    raw = path.read_bytes()
    require(len(raw) == info["bytes"] and digest(raw) == info["sha256"], "fixture file hash differs")
    return raw


def isolated(raw):
    text = raw.decode(errors="replace")
    parent = re.search(r"HEPTA_PARENT_NET=(.+)", text)
    child = re.search(r"HEPTA_CHILD_NET=(.+)", text)
    return bool(parent and child and parent.group(1) != child.group(1) and "HEPTA_ROUTES=\n" in text and "HEPTA_ROUTES6=\n" in text)


def ns_header():
    return ["#!/system/bin/sh", "set -eu", "umask 077", "ulimit -c 0", '[ "$(id -u)" = 0 ] || exit 87',
            'parent_ns="$(readlink /proc/1/ns/net)"', 'child_ns="$(readlink /proc/self/ns/net)"',
            'printf "HEPTA_PARENT_NET=%s\\nHEPTA_CHILD_NET=%s\\n" "$parent_ns" "$child_ns"',
            '[ "$parent_ns" != "$child_ns" ] || exit 88', 'routes="$(ip route)"',
            'printf "HEPTA_ROUTES=%s\\n" "$routes"', '[ -z "$routes" ] || exit 89',
            'routes6="$(ip -6 route)"', 'printf "HEPTA_ROUTES6=%s\\n" "$routes6"', '[ -z "$routes6" ] || exit 89',
            'printf "HEPTA_WRAPPER_ID="; id',
            'printf "HEPTA_WRAPPER_SELINUX="; cat /proc/self/attr/current; echo']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixture-manifest", type=Path, required=True)
    ap.add_argument("--fixture-sha256", required=True)
    ap.add_argument("--runtime-manifest", type=Path, required=True)
    ap.add_argument("--runtime-gate-result", type=Path, required=True)
    ap.add_argument("--model-pins", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--phone-root", required=True)
    ap.add_argument("--adb", default="/home/alex/.local/bin/adb")
    ap.add_argument("--adb-port", type=int, default=5061)
    ap.add_argument("--serial", required=True)
    args = ap.parse_args()
    os.umask(0o077)
    require(re.fullmatch(r"/data/local/tmp/hepta-qairt-catalogue-r3-[A-Za-z0-9_-]+", args.phone_root), "new isolated phone root required")
    runtime_raw = args.runtime_manifest.read_bytes()
    model_raw = args.model_pins.read_bytes()
    gate_raw = args.runtime_gate_result.read_bytes()
    require(digest(runtime_raw) == RUNTIME_MANIFEST_SHA and digest(model_raw) == MODEL_PINS_SHA,
            "runtime/model manifest pins differ")
    require(digest(gate_raw) == RUNTIME_GATE_SHA, "approved runtime gate result differs")
    gate = strict_json(gate_raw)
    require(gate["schema"] == "hepta.qairt-vlm-r3-grammar-smoke.v1"
            and gate["all_pass"] is True and gate["positive_cases_pass"] is True
            and gate["negative_graceful_error_contract_pass"] is True
            and gate["worker_sha256"] == WORKER_SHA and gate["core_sha256"] == CORE_SHA
            and gate["vlm_sha256"] == VLM_SHA and gate["runtime_profile"] == RUNTIME_PROFILE
            and gate["phone_runtime"] == RUNTIME and gate["model_pins_sha256"] == MODEL_PINS_SHA
            and gate["finished_unix"] > gate["started_unix"]
            and all(gate[key] is True for key in ("terminal_no_model_process", "owner_stop_unchanged",
                "retained_claims_unchanged", "original_and_r2_runtime_unchanged",
                "model_files_unchanged", "candidate_runtime_unchanged"))
            and len(gate["cases"]) == 5 and all(case["pass"] is True for case in gate["cases"]),
            "R3 five-case gate or its final verification is not qualified")
    runtime_manifest, model_manifest = strict_json(runtime_raw), strict_json(model_raw)
    original_libs, r2_libs, candidate_libs = (runtime_manifest["original_files"],
        runtime_manifest["r2_files"], runtime_manifest["candidate_files"])
    require(len(original_libs) == len(r2_libs) == len(candidate_libs) == 52
            and set(original_libs) == set(r2_libs) == set(candidate_libs), "incomplete runtime closure")
    require({key for key in original_libs if original_libs[key] != r2_libs[key]} == {"lib/qairt/libgeniex_core.so"}
            and {key for key in r2_libs if r2_libs[key] != candidate_libs[key]} == {"lib/qairt/libgeniex_vlm.so"}
            and r2_libs["lib/qairt/libgeniex_core.so"] == candidate_libs["lib/qairt/libgeniex_core.so"] == CORE_SHA
            and candidate_libs["lib/qairt/libgeniex_vlm.so"] == VLM_SHA
            and runtime_manifest["parent_r2_manifest_sha256"] == R2_MANIFEST_SHA
            and runtime_manifest["worker_sha256"] == WORKER_SHA, "R3 two-DSO closure differs")
    require(model_manifest["archive_sha256"] == "9053855d9b45d2dc1c41b8cc5d7d792887dd1549b8ebf3a7f3dfb0ef5b762599"
            and len(model_manifest["files"]) == 24, "wrong or incomplete official model closure")
    for rel in list(original_libs) + [item["path"] for item in model_manifest["files"]]:
        parsed = PurePosixPath(rel)
        require(not parsed.is_absolute() and ".." not in parsed.parts and str(parsed) == rel, "unsafe artifact path")
    raw_manifest = args.fixture_manifest.read_bytes()
    require(digest(raw_manifest) == args.fixture_sha256 == FIXTURE_SHA, "fixture manifest hash differs")
    manifest = strict_json(raw_manifest)
    require(manifest["grammar_profile"] == RUNTIME_PROFILE
            and manifest["schema_compiler_sha256"] == COMPILER_SHA, "explicit R3 fixture profile differs")
    require(manifest["schema"] == "hepta.catalogue-model-prompt-fixture.v1" and manifest["all_inputs_generated"] is True,
            "fixture composition did not pass")
    require(manifest["scope"] == "host_semantic_fixture_not_phone_evidence"
            and manifest["phone_actions_executed"] == 0 and manifest["model_inference_executed"] is False,
            "unexpected fixture scope")
    require([case["name"] for case in manifest["cases"]] == CASE_NAMES, "exactly the two authorized cases required")
    require(manifest["registered_entries"] == 53 and manifest["source_compose_max_prompt_bytes"] == 24576,
            "fixture catalogue/composition gate differs")
    for pin in manifest["source_pins"].values():
        path = Path(pin["path"])
        require(path.resolve(strict=True) == path and digest(path.read_bytes()) == pin["sha256"], "provider source pin changed")
    provider_path = Path(manifest["source_pins"]["provider_phone_local.py"]["path"])
    sys.path.insert(0, str(provider_path.parent))
    provider = importlib.import_module("provider_phone_local")
    require(Path(provider.__file__).resolve() == provider_path, "wrong strict parser provider imported")
    compiler_pin = manifest["source_pins"]["schema_grammar.py"]
    require(compiler_pin["sha256"] == COMPILER_SHA, "wrong schema compiler source")
    compiler = importlib.import_module("schema_grammar")
    require(Path(compiler.__file__).resolve() == Path(compiler_pin["path"]), "wrong schema compiler imported")
    loaded = []
    for case in manifest["cases"]:
        require(case["status"] == "INPUTS_GENERATED_NOT_MODEL_TESTED" and case["semantic_preservation_assertions"] is True,
                "fixture semantic-preservation assertions absent")
        files = {name: pinned_file(info, 2 * 1024 * 1024) for name, info in case["files"].items()}
        case_bytes = pinned_file(case["case_manifest"])
        require(strict_json(case_bytes) == {k: v for k, v in case.items() if k != "case_manifest"}, "case manifest differs")
        legacy = strict_json(files["legacy-schema.json"])
        require(provider.mobile_use_schema(legacy) == strict_json(files["model-schema.json"]), "original schema mapping differs")
        regenerated, conversion = compiler.convert_schema(files["model-schema.json"], compiler_source_sha256=COMPILER_SHA)
        require(0 < len(files["grammar.gbnf"]) <= 65536 and regenerated == files["grammar.gbnf"]
                and conversion == strict_json(files["schema-conversion.json"])
                and conversion["root_schema_kind"] == "mobile_use", "complete original schema/grammar binding differs")
        system, prompt = files["system.txt"], files["prompt.txt"]
        segments = ([HEAD + system + MIDDLE, prompt + TAIL] if case["image_present"]
                    else [HEAD + system + MIDDLE + prompt + TAIL])
        formatted = b"<__image__>".join(segments)
        loaded.append({"case": case, "files": files, "legacy": legacy, "segments": segments,
                       "formatted_sha256": digest(formatted)})
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    out.chmod(0o700)
    adb = [args.adb, "-P", str(args.adb_port), "-s", args.serial]
    report = {"schema": "hepta.qairt-catalogue-grammar-r3-check.v1", "candidate_only": True,
              "scope": "actual_NPU_model_with_synthetic_history_no_phone_action",
              "production_domain_tested": False, "root_magisk_only": True,
              "ui_actions_executed": 0, "production_runtime_changed": False,
              "fixture_manifest_sha256": args.fixture_sha256, "catalogue_sha256": manifest["catalogue_sha256"],
              "registered_entries": manifest["registered_entries"], "worker_sha256": WORKER_SHA,
              "counter_sha256": COUNTER_SHA, "grammar_requested": True,
              "core_sha256": CORE_SHA, "vlm_sha256": VLM_SHA, "runtime_profile": RUNTIME_PROFILE,
              "compiler_source_sha256": COMPILER_SHA, "runtime_gate_sha256": RUNTIME_GATE_SHA,
              "runtime_manifest_sha256": RUNTIME_MANIFEST_SHA, "model_pins_sha256": MODEL_PINS_SHA,
              "r2_negative_graceful_error_contract_pass": False,
              "r3_negative_graceful_error_contract_pass": True, "r3_standalone_five_case_gate_pass": True,
              "production_runtime_qualified": False,
              "worker_timeout_ms": 55000, "phone_timeout_seconds": 60, "phone_kill_grace_seconds": 5,
              "max_generated_tokens": 256, "max_prompt_tokens": 3584, "context_tokens": 4096,
              "reserved_tokens": 256, "cases": [], "all_pass": False, "positive_cases_pass": False,
              "started_unix": time.time()}

    def save():
        (out / "PRIVATE-RESULT.json").write_bytes(canonical(report) + b"\n")
        public = {key: value for key, value in report.items() if key not in {"cases", "error", "active_case", "dac_inventory"}}
        public["cases"] = [{key: row.get(key) for key in (
            "case", "expected_action", "input_sha256", "formatted_sha256", "counter_pass", "counter_upper",
            "counter_elapsed_seconds", "counter_result_sha256", "counter_network_isolated", "model_attempted", "process_exit",
            "elapsed_seconds", "raw_sha256", "raw_bytes", "worker_result_sha256", "profile", "stop_reason",
            "prompt_count_delta", "model_network_isolated", "grammar_sha256", "grammar_bytes", "no_residual_model_process",
            "worker_pid_absent", "counter_pid_absent", "runtime_pass", "strict_parser_pass", "semantic_pass", "pass", "failure_kind")}
            for row in report["cases"]]
        if "error" in report:
            public["error_type"] = report["error"]["type"]
        (out / "PUBLIC-SUMMARY.json").write_bytes(canonical(public) + b"\n")

    def run(name, argv, timeout=30, check=True):
        start = time.monotonic()
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (out / (name + ".stdout.raw")).write_bytes(error.stdout or b"")
            (out / (name + ".stderr.raw")).write_bytes(error.stderr or b"")
            raise
        (out / (name + ".stdout.raw")).write_bytes(proc.stdout)
        (out / (name + ".stderr.raw")).write_bytes(proc.stderr)
        if check:
            require(proc.returncode == 0, name + " process failed: " + str(proc.returncode))
        return proc, time.monotonic() - start

    def shell(name, command, **kwargs):
        return run(name, adb + ["shell", command], **kwargs)

    def root_shell(name, command, **kwargs):
        return shell(name, "su -c " + shlex.quote(command), **kwargs)

    def phone_hashes(name, pins, timeout=180):
        proc, _ = root_shell(name, shlex.join(["sha256sum", *pins]), timeout=timeout)
        observed = {line.split(maxsplit=1)[1]: line.split(maxsplit=1)[0]
                    for line in proc.stdout.decode("utf-8", "strict").splitlines()}
        require(observed == pins, name + " artifact hashes differ")

    def no_model_processes(name):
        proc, _ = root_shell(name, "ps -A -o PID,ARGS")
        selected = []
        for line in proc.stdout.decode(errors="replace").splitlines()[1:]:
            fields = line.split(None, 1)
            if len(fields) != 2:
                continue
            executable = fields[1].split(None, 1)[0].rsplit("/", 1)[-1]
            if executable in {WORKER_NAME, "hepta-token-count", "geniex-bench", "llama-cli", "llama-server", "llama-mtmd-cli"}:
                selected.append(line)
        # The full process listing is not needed as a public artifact.
        (out / (name + ".stdout.raw")).write_text("\n".join(selected) + "\n")
        return not selected

    def pid_absent(name, pid):
        if type(pid) is not int or pid <= 1:
            return False
        proc, _ = root_shell(name, shlex.join(["test", "!", "-e", "/proc/" + str(pid)]), check=False)
        return proc.returncode == 0

    def read_result(name, path):
        proc, _ = root_shell(name, shlex.join(["cat", path]), check=False)
        return proc.stdout if proc.returncode == 0 else None

    def script_run(name, lines, timeout):
        script = out / (name + ".sh")
        script.write_text("\n".join(lines) + "\n")
        subprocess.run(["/bin/sh", "-n", str(script)], check=True)
        remote = args.phone_root + "/" + script.name
        run("push-" + name, adb + ["push", str(script), remote])
        return root_shell(name, shlex.join(["/system/bin/unshare", "-n", "/system/bin/sh", remote]), timeout=timeout, check=False)

    pins = {RUNTIME + "/" + path: value for path, value in candidate_libs.items()}
    pins.update({OLD_RUNTIME + "/" + path: value for path, value in original_libs.items()})
    pins.update({R2_RUNTIME + "/" + path: value for path, value in r2_libs.items()})
    pins.update({MODEL + "/" + item["path"]: item["sha256"] for item in model_manifest["files"]})
    pins.update({WORKER: WORKER_SHA, OLD_RUNTIME + "/" + WORKER_NAME: WORKER_SHA,
                     R2_RUNTIME + "/" + WORKER_NAME: WORKER_SHA, MODEL + "/genie_config.json": CONFIG_SHA,
                     MODEL + "/tokenizer.json": TOKENIZER_SHA,
                     COUNTER_ROOT + "/hepta-token-count": COUNTER_SHA,
                     COUNTER_ROOT + "/assets/libgeniex-proc.so": LIBRARY_SHA,
                     COUNTER_ROOT + "/assets/tokenizer.json": TOKENIZER_SHA,
                 RUNTIME + "/lib/qairt/libgeniex-proc.so": LIBRARY_SHA, STOP: STOP_SHA, CLAIMS: CLAIMS_SHA})
    save()
    try:
        require(no_model_processes("processes-before"), "another model/counter process is active")
        phone_hashes("all-artifacts-before", pins)
        proc, _ = root_shell("candidate-lib-file-inventory", shlex.join(["find", RUNTIME + "/lib", "-type", "f", "-print"]))
        require(set(proc.stdout.decode().splitlines()) == {RUNTIME + "/" + rel for rel in candidate_libs},
                "unmanifested candidate runtime library")
        proc, _ = root_shell("candidate-lib-link-inventory", shlex.join(["find", RUNTIME + "/lib", "-type", "l", "-print"]))
        require(not proc.stdout.strip(), "candidate runtime library symlink")
        dac_paths = ["/data", "/data/local", "/data/local/tmp", str(Path(MODEL).parent), MODEL,
                     MODEL + "/genie_config.json", MODEL + "/tokenizer.json", MODEL + "/part1_of_4.bin",
                     RUNTIME, RUNTIME + "/lib", RUNTIME + "/lib/qairt", RUNTIME + "/lib/qairt/htp-files",
                     RUNTIME + "/lib/libgeniex.so", WORKER]
        proc, _ = root_shell("artifact-dac", shlex.join(["stat", "-c", "%n|%u|%g|%a|%F"] + dac_paths))
        report["dac_inventory"] = proc.stdout.decode(errors="replace")
        shell("absent-phone-root", shlex.join(["test", "!", "-e", args.phone_root]))
        shell("create-phone-root", shlex.join(["mkdir", "-m", "700", args.phone_root]))

        # All input bytes and the counter are verified before any model request.
        for item in loaded:
            case, files = item["case"], item["files"]
            name = case["name"]
            private = args.phone_root + "/" + name
            uploaded = args.phone_root + "/upload-" + name
            shell("mkdir-upload-" + name, shlex.join(["mkdir", "-m", "700", uploaded]))
            names = ["system.txt", "prompt.txt", "grammar.gbnf"] + (["current.png"] if case["image_present"] else [])
            for filename in names:
                run("push-" + name + "-" + filename, adb + ["push", case["files"][filename]["path"], uploaded + "/" + filename])
            req = uuid.uuid4().hex
            counter = ["/system/bin/timeout", "-k", "1", "8", COUNTER_ROOT + "/hepta-token-count",
                       "--request-id", req, "--library", COUNTER_ROOT + "/assets/libgeniex-proc.so",
                       "--library-sha256", LIBRARY_SHA, "--tokenizer", COUNTER_ROOT + "/assets/tokenizer.json",
                       "--tokenizer-sha256", TOKENIZER_SHA, "--prompt-file", private + "/prompt.txt",
                       "--system-file", private + "/system.txt", "--result-file", private + "/count.json", "--max-prompt", "3584"]
            if case["image_present"]:
                counter += ["--image", private + "/current.png"]
            lines = ns_header() + ["export LD_LIBRARY_PATH=/system/lib64", shlex.join(["mkdir", "-m", "700", private])]
            for filename in names:
                lines += [shlex.join(["cp", uploaded + "/" + filename, private + "/" + filename]),
                          shlex.join(["chmod", "600", private + "/" + filename])]
            proc, elapsed = script_run("count-" + name, lines + ["exec " + shlex.join(counter)], 15)
            raw = read_result("read-count-" + name, private + "/count.json")
            counted = strict_json(raw) if raw is not None else {}
            if raw is not None:
                (out / (name + ".count.json")).write_bytes(raw)
            counter_absent = pid_absent("counter-pid-absent-" + name, counted.get("pid"))
            require(no_model_processes("after-counter-" + name), "counter or model remains active")
            phone_hashes("staged-input-hashes-" + name, {private + "/" + filename: digest(files[filename]) for filename in names})
            input_hash = {"prompt": digest(files["prompt.txt"]), "system": digest(files["system.txt"]),
                          "image": digest(files["current.png"]) if case["image_present"] else None}
            row = {"case": name, "expected_action": case["expected"]["action"], "input_sha256": input_hash,
                   "formatted_sha256": item["formatted_sha256"], "counter_argv": counter, "counter_result": counted,
                   "counter_process_exit": proc.returncode, "counter_elapsed_seconds": elapsed,
                   "counter_pid_absent": counter_absent,
                   "counter_network_isolated": isolated(proc.stdout),
                   "counter_result_sha256": digest(raw) if raw is not None else None,
                   "counter_upper": counted.get("prompt_tokens_upper_bound"), "model_attempted": False,
                   "grammar_sha256": digest(files["grammar.gbnf"]), "grammar_bytes": len(files["grammar.gbnf"]), "pass": False}
            segment_counts = counted.get("segment_token_counts")
            count_arithmetic = (isinstance(segment_counts, list) and len(segment_counts) == len(item["segments"])
                and all(type(value) is int and value >= 0 for value in segment_counts)
                and counted.get("formatted_text_tokens") == sum(segment_counts)
                and counted.get("prompt_tokens_upper_bound") == sum(segment_counts) + (258 if case["image_present"] else 0) + 1)
            row["counter_pass"] = bool(proc.returncode == 0 and isolated(proc.stdout) and counted.get("success") is True
                and counted.get("input_unchanged") is True and counted.get("request_id") == req
                and counted.get("raw_input_preserved") is True and counted.get("status") == "success" and count_arithmetic
                and counted.get("input_sha256") == input_hash
                and counted.get("segment_sha256") == [digest(segment) for segment in item["segments"]]
                and counted.get("segment_utf8_bytes") == [len(segment) for segment in item["segments"]]
                and counted.get("library_sha256") == LIBRARY_SHA and counted.get("tokenizer_sha256") == TOKENIZER_SHA
                and counted.get("context_tokens") == 4096 and counted.get("max_prompt_tokens") == 3584
                and counted.get("generation_tokens") == 256 and counted.get("reserved_tokens") == 256
                and counted.get("ffi_add_special_tokens") is False and counted.get("bos_token_upper_bound") == 1
                and counted.get("image_pad_tokens") == (256 if case["image_present"] else 0)
                and counted.get("vision_boundary_tokens") == (2 if case["image_present"] else 0)
                and counter_absent and type(row["counter_upper"]) is int and 0 < row["counter_upper"] <= 3584)
            report["cases"].append(row)
            item["private"] = private
            save()
            print(json.dumps({"case": name, "counter_pass": row["counter_pass"], "counter_upper": row["counter_upper"]}), flush=True)
            require(row["counter_pass"], "tokenizer gate failed")

        for item, row in zip(loaded, report["cases"]):
            case, private, name = item["case"], item["private"], row["case"]
            req = uuid.uuid4().hex
            command = ["/system/bin/timeout", "-k", "5", "60", WORKER, "--request-id", req,
                       "--mode", "vlm", "--runtime", "qairt", "--compute", "npu",
                       "--model", MODEL + "/genie_config.json", "--tokenizer", MODEL + "/tokenizer.json",
                       "--ctx-size", "0", "--threads", "4", "--max-tokens", "256", "--timeout-ms", "55000",
                       "--log-level", "info", "--prompt-file", private + "/prompt.txt", "--system-file", private + "/system.txt",
                       "--grammar-file", private + "/grammar.gbnf",
                       "--result-file", private + "/result.json", "--text-file", private + "/generated.txt"]
            if case["image_present"]:
                command += ["--image", private + "/current.png"]
            lines = ns_header() + ["cd " + shlex.quote(MODEL),
                "export LD_LIBRARY_PATH=" + shlex.quote(RUNTIME + "/lib:" + RUNTIME + "/lib/llama_cpp:" + RUNTIME + "/lib/qairt:" + RUNTIME + "/lib/qairt/htp-files:/system/lib64:/vendor/lib64"),
                "export GENIEX_PLUGIN_PATH=" + shlex.quote(RUNTIME + "/lib"),
                "export GENIEX_QAIRT_LIB=" + shlex.quote(RUNTIME + "/lib/qairt/htp-files"),
                "export ADSP_LIBRARY_PATH=" + shlex.quote(RUNTIME + "/lib/qairt/htp-files;/vendor/lib/rfsa/adsp"),
                "export GGML_HEXAGON_PROFILE=0", "export GGML_HEXAGON_VERBOSE=0"]
            # Recheck the exact private input files immediately before this
            # request, including GBNF; no model request may use uncounted text.
            for filename in ["prompt.txt", "system.txt", "grammar.gbnf"] + (["current.png"] if case["image_present"] else []):
                path = private + "/" + filename
                lines.append('test "$(sha256sum ' + shlex.quote(path) + ')" = ' +
                             shlex.quote(digest(item["files"][filename]) + "  " + path))
            lines.append("exec " + shlex.join(command))
            row.update(model_attempted=True, request_id=req, argv=command)
            report["active_case"] = name
            save()
            print(json.dumps({"model_starting": name, "ui_actions_executed": 0}), flush=True)
            proc, elapsed = script_run("model-" + name, lines, 75)
            terminated = no_model_processes("after-model-" + name)
            raw = read_result("read-output-" + name, private + "/generated.txt")
            metadata = read_result("read-worker-" + name, private + "/result.json")
            wr = strict_json(metadata) if metadata is not None else {}
            worker_absent = pid_absent("worker-pid-absent-" + name, wr.get("pid"))
            if raw is not None:
                (out / (name + ".generated.raw")).write_bytes(raw)
            if metadata is not None:
                (out / (name + ".result.json")).write_bytes(metadata)
            row.update(process_exit=proc.returncode, elapsed_seconds=elapsed, worker_result=wr,
                       model_network_isolated=isolated(proc.stdout),
                       raw_sha256=digest(raw) if raw is not None else None, raw_bytes=len(raw) if raw is not None else None,
                       worker_result_sha256=digest(metadata) if metadata is not None else None,
                       profile=wr.get("profile"), stop_reason=wr.get("stop_reason"),
                       no_residual_model_process=terminated, worker_pid_absent=worker_absent)
            profile = wr.get("profile") or {}
            tokens = profile.get("prompt_tokens")
            row["prompt_count_delta"] = row["counter_upper"] - tokens if type(tokens) is int else None
            power_errors = [line for line in clean(proc.stderr.decode(errors="replace")).splitlines()
                            if re.search(r"(?:Failure in|failed).*(?:setPowerConfig|createPowerConfigId|deviceGetInfrastructure)", line, re.I)]
            row["power_error_lines"] = power_errors
            grammar_errors = [line for line in clean(proc.stderr.decode(errors="replace")).splitlines()
                              if "grammar" in line.lower() and re.search(r"fail|invalid|error|disabl|without|unable|no tokenizer", line, re.I)]
            row["grammar_error_lines"] = grammar_errors
            expected_inputs = dict(row["input_sha256"], grammar=row["grammar_sha256"])
            sdk_rc = wr.get("sdk_rc", {})
            row["runtime_pass"] = bool(proc.returncode == 0 and isolated(proc.stdout) and raw is not None
                and terminated and worker_absent
                and wr.get("request_id") == req and wr.get("runtime") == "qairt" and wr.get("device_resolved") == "NPU"
                and wr.get("generation_complete") is True and wr.get("stop_reason") == "eos"
                and wr.get("worker_outcome") == "completed" and wr.get("worker_exit_status_planned") == 0
                and wr.get("raw_text_source") == "sdk_full_text" and wr.get("raw_text_present") is True
                and wr.get("raw_text_utf8") is True and wr.get("raw_text_truncated") is False
                and wr.get("raw_text_bytes") == len(raw) and wr.get("raw_text_sha256") == row["raw_sha256"]
                and wr.get("input_metadata_unchanged") is True and wr.get("input_sha256") == expected_inputs
                and wr.get("formatted_prompt_sha256") == row["formatted_sha256"]
                and wr.get("n_ctx_create") == 0 and wr.get("n_gpu_layers_create") == 0
                and wr.get("power_mode_create") == 6 and not power_errors and not grammar_errors
                and wr.get("generate_attempt_count") == 1 and wr.get("automatic_retry") is False
                and set(sdk_rc) == SDK_KEYS and all(type(value) is int and value == 0 for value in sdk_rc.values())
                and wr.get("max_tokens") == 256 and wr.get("signal_observed") == 0 and wr.get("deadline_observed") is False
                and wr.get("callback_limit_observed") is False
                and type(profile.get("generated_tokens")) is int and 0 < profile["generated_tokens"] <= 256
                and type(tokens) is int and tokens > 0
                and type(row["prompt_count_delta"]) is int and 0 <= row["prompt_count_delta"] <= 1
                and tokens + 256 + 256 <= 4096)
            row.update(strict_parser_pass=False, semantic_pass=False)
            try:
                require(raw is not None, "no model output")
                obj = provider.strict_json(raw.decode("utf-8", errors="strict"))
                decision = provider.normalize_mobile_use(obj, item["legacy"], case["allowed_call_id"])
                row.update(strict_parser_pass=True, parsed_action=obj, normalized_decision=decision)
                expected, action = case["expected"], obj["arguments"]
                if expected["action"] == "open":
                    row["semantic_pass"] = bool(action.get("action") == "open" and action.get("text") == expected["text"]
                        and decision["tool"] == "phone.open_app" and decision["argv"] == [expected["text"]])
                else:
                    xy, box, size = action.get("coordinate"), expected["target_bbox_pixels"], expected["image_size"]
                    valid = isinstance(xy, list) and len(xy) == 2 and all(type(x) is int and 0 <= x <= 1000 for x in xy)
                    hit = bool(valid and box[0] <= xy[0] * size[0] / 1000 <= box[2] and box[1] <= xy[1] * size[1] / 1000 <= box[3])
                    row["semantic_pass"] = bool(action.get("action") == "click" and action.get("screenshot_id") == expected["screenshot_id"]
                        and hit and decision["tool"] == "phone.tap" and decision["argv"] == [expected["screenshot_id"], str(xy[0]), str(xy[1])])
            except Exception as error:
                row["parser_error"] = {"type": type(error).__name__, "message": str(error)}
            row["pass"] = bool(row["runtime_pass"] and row["strict_parser_pass"] and row["semantic_pass"])
            row["failure_kind"] = (None if row["pass"] else "runtime" if not row["runtime_pass"] else
                                   "strict_format_or_schema" if not row["strict_parser_pass"] else "semantic")
            report["active_case"] = None
            save()
            print(json.dumps({"case": name, "pass": row["pass"], "failure_kind": row["failure_kind"],
                              "counter_upper": row["counter_upper"], "sdk_prompt_tokens": tokens,
                              "generated_tokens": profile.get("generated_tokens"), "elapsed_seconds": elapsed}), flush=True)
            require(terminated, "model process remains active; stop queue")
            if not row["pass"]:
                break
        report["all_pass"] = len(report["cases"]) == 2 and all(row["pass"] for row in report["cases"])
        report["positive_cases_pass"] = report["all_pass"]
    except Exception as error:
        report["all_pass"] = False
        report["positive_cases_pass"] = False
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        try:
            report["terminal_no_model_process"] = no_model_processes("processes-final")
            phone_hashes("all-artifacts-after", pins)
            report["owner_stop_unchanged"] = True
            report["retained_claims_unchanged"] = True
            report["original_r2_and_r3_runtime_unchanged"] = True
            report["model_files_unchanged"] = True
            require(report["terminal_no_model_process"], "terminal process inventory not empty")
        except Exception as error:
            report["all_pass"] = False
            report["positive_cases_pass"] = False
            report["final_verification_error"] = {"type": type(error).__name__, "message": str(error)}
        report["finished_unix"] = time.time()
        save()
    print(json.dumps({"all_pass": report["all_pass"], "output": str(out), "ui_actions_executed": 0}), flush=True)
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
