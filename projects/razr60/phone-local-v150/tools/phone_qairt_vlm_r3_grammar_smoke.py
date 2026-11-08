#!/usr/bin/env python3
"""Qualify isolated R2 core + R3 VLM error containment; no services or UI.

The frozen worker uses exit 70 for a normal SDK failure. R2's old exit-1
expectation is retained in its historical harness; its actual abort remains FAIL.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import time
import uuid

OLD_RUNTIME = "/data/local/tmp/hepta-geniex-npu-v0100-20261108"
R2_RUNTIME = "/data/local/tmp/hepta-geniex-core-r2-20261108"
MODEL = "/data/local/tmp/hepta-qwen3vl4b-qairt-r1-20261108/model"
WORKER_NAME = "hepta-geniex-once-r2"
WORKER_SHA = "67d4e368da136f74a7ab1022013cf1def64f75ebb32d91962772e28a2363864f"
CORE_SHA = "06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d"
R2_MANIFEST_SHA = "c4551f10e683382fc1e2285b21c67482d006223ace13c0ddcc6faebbe71b85d8"
MODEL_PINS_SHA = "1676a2ff35b577da6426cbe9790e2a5d1dbcfdeae1dc7c0e8898554f11026a6b"
VLM_SHA = "773e23de3f892d2cd9c468e7b0af32e6c254af341d4ed0e7ef0eda95f6ee1d73"
NORMAL_WORKER_FAILURE_EXIT = 70
SDK_VLM_GENERATION_FAILED = -201201
ARCHIVE_SHA = "248b49c83bc74238babc0d9ebf46f0c8b6d2e9b6de3ffb90c2a5a2042523831f"
STOP = "/data/trillionnium/owner-open/state/emergency-stop"
STOP_SHA = "ff6401f96ef8d2206e61e9fdf6d75d1dd11fe25f5696d7f6996b6647023fdb07"
CLAIMS = "/data/trillionnium/owner-open/state/phone-local-v150/retained-claims.json"
CLAIMS_SHA = "7feecc970e6499cd1735e5b0bf2c68386c669462a89a76d84f5bfc8b2225dd8c"
GRAMMAR_PINS = {
    "discriminator_b.gbnf": "02fbe017514182201f1392001c86aafa7f9ba4289b25fadcb78279db6fbd63b1",
    "mobile_click.gbnf": "dedddd1069b3917805e7299f9f8e182c084c1644162ecd72ab40242124840c2c",
}
FIXTURES = [
    (OLD_RUNTIME + "/fixture_1_2x.png", "3884af3cf4b76e45a6cd8a38084423241863079b48fa2b1fc437069b89591459", [84,260,684,490]),
    (OLD_RUNTIME + "/fixture_2_2x.png", "2e08fa22606640ad6da655e406eeb801cfb7cb297f0e276f19efb7348d37c4a6", [84,980,684,1210]),
]
SYSTEM = (
    "只输出一个完整的JSON对象，不要Markdown或解释。每个对象和数组都必须闭合。"
    "下面是与当前图片无关的完整格式示例："
    '{"name":"mobile_use","arguments":{"action":"open","text":"settings","summary":"打开设置"}}。'
    "当前点击任务的arguments应包含action、screenshot_id、coordinate和summary。"
    "action为click，coordinate是0到1000的两个整数，按原始完整图片的宽高归一化。"
    "必须闭合arguments对象和最外层对象。\n"
)
SDK_KEYS = {"resolve", "set_log_level", "init", "create", "template", "generate", "destroy", "deinit"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    def constant(value):
        raise ValueError("invalid JSON constant " + value)
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=constant)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--r2-manifest", required=True, type=Path)
    ap.add_argument("--model-pins", required=True, type=Path)
    ap.add_argument("--vlm", required=True, type=Path)
    ap.add_argument("--grammar-dir", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--phone-root", required=True)
    ap.add_argument("--serial", required=True)
    args = ap.parse_args()
    require(bool(re.fullmatch(r"/data/local/tmp/hepta-geniex-vlm-r3-[A-Za-z0-9_-]+", args.phone_root)), "new isolated runtime path required")
    require(sha(args.r2_manifest) == R2_MANIFEST_SHA, "R2 runtime manifest SHA mismatch")
    require(sha(args.vlm) == VLM_SHA, "reviewed VLM SHA mismatch")
    require(sha(args.model_pins) == MODEL_PINS_SHA, "model pins SHA mismatch")
    model_pins = strict_json(args.model_pins.read_bytes())
    require(model_pins["archive_sha256"] == "9053855d9b45d2dc1c41b8cc5d7d792887dd1549b8ebf3a7f3dfb0ef5b762599", "wrong model bundle")
    require(len(model_pins["files"]) == 24, "incomplete model pins")
    r2 = strict_json(args.r2_manifest.read_bytes())
    require(r2["archive_sha256"] == ARCHIVE_SHA and r2["worker_sha256"] == WORKER_SHA, "wrong R2 provenance")
    old_libs, r2_libs = r2["original_files"], r2["candidate_files"]
    for collection in (old_libs, r2_libs):
        require(isinstance(collection, dict) and len(collection) == 52, "incomplete runtime manifest")
        for rel, pin in collection.items():
            require(rel.startswith("lib/") and not PurePosixPath(rel).is_absolute()
                    and ".." not in PurePosixPath(rel).parts and re.fullmatch(r"[0-9a-f]{64}", pin), "unsafe runtime pin")
    require(set(old_libs) == set(r2_libs), "R2 runtime file set differs")
    require([rel for rel in old_libs if old_libs[rel] != r2_libs[rel]] == ["lib/qairt/libgeniex_core.so"], "R2 changed more than core")
    require(r2_libs["lib/qairt/libgeniex_core.so"] == CORE_SHA, "wrong R2 core")
    new_libs = dict(r2_libs)
    new_libs["lib/qairt/libgeniex_vlm.so"] = VLM_SHA
    require([rel for rel in r2_libs if r2_libs[rel] != new_libs[rel]] == ["lib/qairt/libgeniex_vlm.so"], "R3 changed more than VLM")
    model_expected = {}
    for row in model_pins["files"]:
        rel = row["path"]
        require(not PurePosixPath(rel).is_absolute() and ".." not in PurePosixPath(rel).parts, "unsafe model path")
        require(rel not in model_expected and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "invalid model pin")
        model_expected[rel] = row["sha256"]
    require(len(model_expected) == 24, "duplicate model pins")
    grammars = {}
    for name, pin in GRAMMAR_PINS.items():
        p = args.grammar_dir / name
        require(sha(p) == pin, "grammar hash mismatch")
        grammars[name] = p.read_bytes()
    grammars["invalid.gbnf"] = b'root ::= "unterminated\n'
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    adb = ["/home/alex/.local/bin/adb", "-P", "5061", "-s", args.serial]
    worker = args.phone_root + "/" + WORKER_NAME
    report = {"schema": "hepta.qairt-vlm-r3-grammar-smoke.v1", "candidate_only": True,
              "production_runtime_changed": False, "production_domain_tested": False,
              "root_magisk_only": True, "ui_actions_executed": 0,
              "worker_sha256": WORKER_SHA, "core_sha256": CORE_SHA, "vlm_sha256": VLM_SHA,
              "runtime_profile": "qairt-output-grammar-core-r2-vlm-r3-v1",
              "normal_worker_failure_exit": NORMAL_WORKER_FAILURE_EXIT,
              "expected_invalid_grammar_sdk_rc": SDK_VLM_GENERATION_FAILED,
              "official_runtime_archive_sha256": ARCHIVE_SHA, "r2_runtime_manifest_sha256": R2_MANIFEST_SHA,
              "model_pins_sha256": MODEL_PINS_SHA, "model_path": MODEL,
              "phone_runtime": args.phone_root, "n_ctx_create": 0, "n_gpu_layers_create": 0,
              "worker_timeout_ms": 55000, "phone_timeout_seconds": 60, "kill_grace_seconds": 5,
              "cases": [], "all_pass": False, "positive_cases_pass": False,
              "negative_graceful_error_contract_pass": False, "stage_completed": False, "started_unix": time.time()}
    (out / "RUNTIME-CANDIDATE-MANIFEST.json").write_text(json.dumps({"archive_sha256": ARCHIVE_SHA,
        "parent_r2_manifest_sha256": R2_MANIFEST_SHA, "original_files": old_libs,
        "r2_files": r2_libs, "candidate_files": new_libs,
        "changed_from_r2": ["lib/qairt/libgeniex_vlm.so"],
        "changed_from_official": ["lib/qairt/libgeniex_core.so", "lib/qairt/libgeniex_vlm.so"],
        "worker_sha256": WORKER_SHA}, indent=2) + "\n")
    immutable_pins = {STOP: STOP_SHA, CLAIMS: CLAIMS_SHA,
        OLD_RUNTIME + "/" + WORKER_NAME: WORKER_SHA, R2_RUNTIME + "/" + WORKER_NAME: WORKER_SHA,
        **{OLD_RUNTIME + "/" + rel: pin for rel, pin in old_libs.items()},
        **{R2_RUNTIME + "/" + rel: pin for rel, pin in r2_libs.items()},
        **{MODEL + "/" + rel: pin for rel, pin in model_expected.items()},
        **{f[0]: f[1] for f in FIXTURES}}

    def save():
        pending = out / "RESULT.json.tmp"
        pending.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        pending.replace(out / "RESULT.json")

    def run(name, command, timeout=30, check=True, save_stdout=True):
        begin = time.monotonic()
        try:
            p = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (out / (name + ".stdout.raw")).write_bytes(error.stdout or b"")
            (out / (name + ".stderr.raw")).write_bytes(error.stderr or b"")
            raise
        if save_stdout:
            (out / (name + ".stdout.raw")).write_bytes(p.stdout)
        (out / (name + ".stderr.raw")).write_bytes(p.stderr)
        require(not check or p.returncode == 0, name + " returned " + str(p.returncode))
        return p, time.monotonic() - begin

    def shell(name, command, **kw):
        return run(name, adb + ["shell", command], **kw)

    def root(name, command, **kw):
        return shell(name, "su -c " + shlex.quote(command), **kw)

    def phone_hashes(name, expected, timeout=180):
        p, _ = root(name, shlex.join(["sha256sum", *expected]), timeout=timeout)
        actual = {line.split(maxsplit=1)[1]: line.split(maxsplit=1)[0]
                  for line in p.stdout.decode("utf-8", "strict").splitlines()}
        require(actual == expected, name + " phone hash mismatch")

    def no_model_processes(name):
        p, _ = root(name, "ps -A -o PID,ARGS", save_stdout=False)
        selected = []
        for line in p.stdout.decode(errors="replace").splitlines()[1:]:
            fields = line.split(None, 1)
            if len(fields) != 2:
                continue
            executable = fields[1].split(None, 1)[0].rsplit("/", 1)[-1]
            if executable in {WORKER_NAME, "geniex-bench", "llama-cli", "llama-server", "llama-mtmd-cli"}:
                selected.append(line)
        (out / (name + ".stdout.raw")).write_text("\n".join(selected) + "\n")
        return not selected

    def pid_absent(name, pid):
        if type(pid) is not int or pid <= 1:
            return False
        p, _ = root(name, shlex.join(["test", "!", "-e", "/proc/" + str(pid)]), check=False)
        return p.returncode == 0

    def read_private(name, path):
        p, _ = root(name, shlex.join(["cat", path]), check=False)
        return p.stdout if p.returncode == 0 else None

    save()
    try:
        require(no_model_processes("processes-before"), "another model process is active")
        phone_hashes("all-immutable-artifacts-before", immutable_pins)
        report["baseline_artifacts_verified"] = True
        shell("new-runtime-absent", shlex.join(["test", "!", "-e", args.phone_root]))
        shell("make-new-runtime", shlex.join(["mkdir", "-m", "755", args.phone_root]))
        run("push-reviewed-vlm", adb + ["push", str(args.vlm), args.phone_root + "/reviewed-vlm.so"])
        setup = "\n".join(["set -eu", shlex.join(["cp", "-R", R2_RUNTIME + "/lib", args.phone_root + "/lib"]),
            shlex.join(["cp", R2_RUNTIME + "/" + WORKER_NAME, worker]),
            shlex.join(["cp", args.phone_root + "/reviewed-vlm.so", args.phone_root + "/lib/qairt/libgeniex_vlm.so"]),
            shlex.join(["chmod", "755", worker])])
        root("clone-r2-runtime-replace-only-vlm", setup, timeout=90)
        phone_hashes("candidate-runtime-all-hashes", {args.phone_root + "/" + rel: pin for rel, pin in new_libs.items()})
        phone_hashes("candidate-worker-hash", {worker: WORKER_SHA})
        p, _ = root("candidate-runtime-file-inventory", shlex.join(["find", args.phone_root + "/lib", "-type", "f", "-print"]))
        require(set(p.stdout.decode().splitlines()) == {args.phone_root + "/" + r for r in new_libs}, "unmanifested candidate runtime file")
        p, _ = root("candidate-runtime-link-inventory", shlex.join(["find", args.phone_root + "/lib", "-type", "l", "-print"]))
        require(not p.stdout.strip(), "candidate runtime contains symlink")
        report["stage_completed"] = True
        save()
        cases = [
            ("01-invalid-grammar", "只输出用户指定的一个大写英文字母。\n", "只输出A，不要解释。\n", "invalid.gbnf", None, 8),
            ("02-no-grammar-recovery", "只输出答案，不要解释。\n", "只回答一个整数：6乘7等于多少？\n", None, None, 24),
            ("03-discriminator", "只输出用户指定的一个大写英文字母。\n", "只输出A，不要解释。\n", "discriminator_b.gbnf", None, 8),
        ]
        for i, fixture in enumerate(FIXTURES, 1):
            cases.append(("0%d-nested-click%d" % (i+3, i), SYSTEM,
                "当前截图ID为fixture_%d。点击蓝色按钮。输出完整的mobile_use JSON，所有括号必须闭合。\n" % i,
                "mobile_click.gbnf", fixture, 160))
        for index, (name, system, prompt, grammar_name, fixture, max_tokens) in enumerate(cases):
            request_id = uuid.uuid4().hex
            private = args.phone_root + "/" + name
            inputs = {"prompt.txt": prompt.encode(), "system.txt": system.encode()}
            if grammar_name:
                inputs["grammar.gbnf"] = grammars[grammar_name]
            expected_inputs = {"prompt": digest(inputs["prompt.txt"]), "system": digest(inputs["system.txt"]),
                               "grammar": digest(inputs["grammar.gbnf"]) if grammar_name else None,
                               "image": fixture[1] if fixture else None}
            prepare = [shlex.join(["mkdir", "-m", "700", private])]
            for filename, data in inputs.items():
                local = out / (name + "-" + filename)
                local.write_bytes(data)
                staged = args.phone_root + "/" + local.name
                run("push-" + local.name, adb + ["push", str(local), staged])
                prepare += [shlex.join(["cp", staged, private + "/" + filename]),
                            shlex.join(["chmod", "600", private + "/" + filename])]
            if fixture:
                prepare += [shlex.join(["cp", fixture[0], private + "/image.png"]),
                            shlex.join(["chmod", "600", private + "/image.png"])]
            command = ["/system/bin/timeout", "-k", "5", "60", worker,
                       "--request-id", request_id, "--mode", "vlm", "--runtime", "qairt", "--compute", "npu",
                       "--model", MODEL + "/genie_config.json", "--tokenizer", MODEL + "/tokenizer.json",
                       "--ctx-size", "0", "--threads", "4", "--max-tokens", str(max_tokens),
                       "--timeout-ms", "55000", "--log-level", "info", "--prompt-file", private + "/prompt.txt",
                       "--system-file", private + "/system.txt", "--result-file", private + "/result.json",
                       "--text-file", private + "/generated.txt"]
            if grammar_name:
                command += ["--grammar-file", private + "/grammar.gbnf"]
            if fixture:
                command += ["--image", private + "/image.png"]
            header = ["#!/system/bin/sh", "set -eu", "ulimit -c 0", '[ "$(id -u)" = 0 ] || exit 87',
                'parent_ns="$(readlink /proc/1/ns/net)"', 'child_ns="$(readlink /proc/self/ns/net)"',
                'printf "HEPTA_PARENT_NET=%s\\nHEPTA_CHILD_NET=%s\\n" "$parent_ns" "$child_ns"',
                '[ "$parent_ns" != "$child_ns" ] || exit 88',
                'routes="$(ip route)"', 'printf "HEPTA_ROUTES=%s\\n" "$routes"', '[ -z "$routes" ] || exit 89',
                'routes6="$(ip -6 route)"', 'printf "HEPTA_ROUTES6=%s\\n" "$routes6"', '[ -z "$routes6" ] || exit 90',
                'printf "HEPTA_WRAPPER_ID="; id', 'printf "HEPTA_WRAPPER_SELINUX="; cat /proc/self/attr/current; echo',
                "cd " + shlex.quote(MODEL),
                "export LD_LIBRARY_PATH=" + shlex.quote(args.phone_root + "/lib:" + args.phone_root + "/lib/llama_cpp:" + args.phone_root + "/lib/qairt:" + args.phone_root + "/lib/qairt/htp-files:/system/lib64:/vendor/lib64"),
                "export GENIEX_PLUGIN_PATH=" + shlex.quote(args.phone_root + "/lib"),
                "export GENIEX_QAIRT_LIB=" + shlex.quote(args.phone_root + "/lib/qairt/htp-files"),
                "export ADSP_LIBRARY_PATH=" + shlex.quote(args.phone_root + "/lib/qairt/htp-files;/vendor/lib/rfsa/adsp"),
                "export GGML_HEXAGON_PROFILE=0", "export GGML_HEXAGON_VERBOSE=0"]
            phone_inputs = {private + "/prompt.txt": expected_inputs["prompt"],
                            private + "/system.txt": expected_inputs["system"]}
            if grammar_name:
                phone_inputs[private + "/grammar.gbnf"] = expected_inputs["grammar"]
            if fixture:
                phone_inputs[private + "/image.png"] = expected_inputs["image"]
            script = out / (name + ".sh")
            script.write_text("\n".join(header + prepare + [shlex.join(["sha256sum", *phone_inputs]),
                "exec " + shlex.join(command)]) + "\n")
            subprocess.run(["/bin/sh", "-n", str(script)], check=True)
            run("push-" + name + "-script", adb + ["push", str(script), args.phone_root + "/" + script.name])
            report["active_case"] = name
            save()
            print(json.dumps({"starting": name, "max_tokens": max_tokens, "ui_actions": 0}), flush=True)
            p, elapsed = root(name, shlex.join(["/system/bin/unshare", "-n", "/system/bin/sh", args.phone_root + "/" + script.name]), timeout=85, check=False)
            terminated = no_model_processes(name + "-processes-after")
            raw = read_private(name + "-text", private + "/generated.txt")
            meta_raw = read_private(name + "-metadata", private + "/result.json")
            metadata_error = None
            try:
                wr = strict_json(meta_raw) if meta_raw else {}
                require(isinstance(wr, dict), "worker metadata must be an object")
            except (ValueError, UnicodeError) as error:
                wr = {}
                metadata_error = {"type": type(error).__name__, "message": str(error)}
            if raw is not None:
                (out / (name + ".generated.raw")).write_bytes(raw)
            if meta_raw is not None:
                (out / (name + ".result.json")).write_bytes(meta_raw)
            worker_absent = pid_absent(name + "-worker-pid-absent", wr.get("pid"))
            stdout = p.stdout.decode(errors="replace")
            stderr = re.sub(r"\x1b\[[0-9;]*m", "", p.stderr.decode(errors="replace"))
            parent = re.search(r"HEPTA_PARENT_NET=(.+)", stdout)
            child = re.search(r"HEPTA_CHILD_NET=(.+)", stdout)
            isolated = bool(parent and child and parent.group(1) != child.group(1) and "HEPTA_ROUTES=\n" in stdout and "HEPTA_ROUTES6=\n" in stdout)
            observed_inputs = {match.group(2): match.group(1) for line in stdout.splitlines()
                               if (match := re.fullmatch(r"([0-9a-f]{64})  (.+)", line))}
            input_hashes_match = observed_inputs == phone_inputs
            grammar_lines = [line for line in stderr.splitlines() if "grammar" in line.lower()]
            grammar_errors = [line for line in grammar_lines if re.search(r"fail|invalid|error|disabl|without|unable|no tokenizer", line, re.I)]
            power_errors = [line for line in stderr.splitlines() if re.search(r"(?:Failure in|failed).*(?:setPowerConfig|createPowerConfigId|deviceGetInfrastructure)", line, re.I)]
            row = {"case": name, "request_id": request_id, "argv": command, "process_exit": p.returncode,
                "elapsed_seconds": elapsed, "no_residual_model_process": terminated, "worker_pid_absent": worker_absent, "isolated": isolated,
                "worker_metadata_sha256": digest(meta_raw) if meta_raw is not None else None,
                "worker_metadata_error": metadata_error,
                "input_sha256": expected_inputs, "input_hashes_match_on_phone": input_hashes_match,
                "observed_phone_input_sha256": observed_inputs, "worker_result": wr,
                "raw_text": raw.decode(errors="replace") if raw is not None else None,
                "raw_bytes": len(raw) if raw is not None else None, "raw_sha256": digest(raw) if raw is not None else None,
                "grammar_log_lines": grammar_lines, "grammar_error_lines": grammar_errors,
                "power_error_lines": power_errors, "pass": False}
            if name == "01-invalid-grammar":
                row["expected_negative"] = True
                row["explicit_grammar_rejection"] = bool(grammar_errors)
                row["no_accepted_output"] = (wr.get("generation_complete") is False
                    and wr.get("worker_outcome") == "not_completed"
                    and wr.get("worker_exit_status_planned") == NORMAL_WORKER_FAILURE_EXIT)
                row["failed_output_retained_only_as_diagnostic"] = raw not in (None, b"")
                rc = wr.get("sdk_rc", {})
                formatter = "<|im_start|>system\n" + system + "<|im_end|>\n<|im_start|>user\n" + prompt + "<|im_end|>\n<|im_start|>assistant\n"
                # Normal SDK failure is exit 70 in frozen worker 07cd434b... .
                # No process crash, timeout, absent metadata or valid-looking
                # partial text can substitute for this exact error contract.
                normal_failure = (p.returncode == NORMAL_WORKER_FAILURE_EXIT
                    and isolated and terminated and worker_absent and input_hashes_match
                    and row["no_accepted_output"] and bool(grammar_errors) and not power_errors
                    and wr.get("schema") == "hepta.geniex-once.result.v1"
                    and wr.get("request_id") == request_id and wr.get("input_sha256") == expected_inputs
                    and wr.get("formatted_prompt_sha256") == digest(formatter.encode())
                    and wr.get("input_metadata_unchanged") is True and wr.get("runtime") == "qairt"
                    and wr.get("mode") == "vlm" and wr.get("compute_requested") == "npu"
                    and wr.get("device_resolved") == "NPU" and wr.get("n_ctx_create") == 0
                    and wr.get("n_gpu_layers_create") == 0 and wr.get("power_mode_create") == 6
                    and wr.get("generate_attempt_count") == 1 and wr.get("automatic_retry") is False
                    and wr.get("max_tokens") == max_tokens and wr.get("error") == "sdk_generate_failed"
                    and wr.get("signal_observed") == 0 and wr.get("deadline_observed") is False
                    and wr.get("callback_limit_observed") is False
                    and raw is not None and wr.get("raw_text_bytes") == len(raw)
                    and wr.get("raw_text_sha256") == digest(raw)
                    and set(rc) == SDK_KEYS and type(rc.get("generate")) is int
                    and rc["generate"] == SDK_VLM_GENERATION_FAILED
                    and all(type(value) is int and value == 0 for key, value in rc.items() if key != "generate"))
                diagnosed_abort = (p.returncode == 134 and isolated and terminated and input_hashes_match
                    and raw in (None, b"") and bool(grammar_errors)
                    and re.search(r"(?:uncaught exception of type|throwing an instance of).*std::(?:invalid_argument|runtime_error)", stderr) is not None)
                row["rejection_status"] = ("PASS_GRACEFUL_ERROR_CONTRACT" if normal_failure else
                    "REJECTED_BY_ABORT" if diagnosed_abort else "FAIL_NO_GRACEFUL_REJECTION")
                row["graceful_error_contract_pass"] = bool(normal_failure)
                row["pass"] = bool(normal_failure)
                report["negative_graceful_error_contract_pass"] = bool(normal_failure)
            else:
                rc = wr.get("sdk_rc", {})
                formatter = "<|im_start|>system\n" + system + "<|im_end|>\n<|im_start|>user\n" + ("<__image__>" if fixture else "") + prompt + "<|im_end|>\n<|im_start|>assistant\n"
                runtime_ok = (p.returncode == 0 and isolated and terminated and worker_absent and input_hashes_match and raw is not None
                    and wr.get("worker_outcome") == "completed" and wr.get("schema") == "hepta.geniex-once.result.v1"
                    and wr.get("raw_text_source") == "sdk_full_text" and wr.get("raw_text_present") is True
                    and wr.get("mode") == "vlm" and wr.get("compute_requested") == "npu" and wr.get("max_tokens") == max_tokens
                    and wr.get("request_id") == request_id and wr.get("generation_complete") is True
                    and wr.get("worker_exit_status_planned") == 0 and wr.get("stop_reason") == "eos"
                    and wr.get("raw_text_utf8") is True and wr.get("raw_text_truncated") is False
                    and wr.get("raw_text_bytes") == len(raw) and wr.get("raw_text_sha256") == digest(raw)
                    and wr.get("input_sha256") == expected_inputs and wr.get("input_metadata_unchanged") is True
                    and wr.get("formatted_prompt_sha256") == digest(formatter.encode())
                    and wr.get("runtime") == "qairt" and wr.get("device_resolved") == "NPU"
                    and wr.get("n_ctx_create") == 0 and wr.get("n_gpu_layers_create") == 0
                    and wr.get("power_mode_create") == 6 and wr.get("generate_attempt_count") == 1
                    and wr.get("automatic_retry") is False and wr.get("signal_observed") == 0
                    and wr.get("deadline_observed") is False and wr.get("callback_limit_observed") is False
                    and set(rc) == SDK_KEYS and all(type(value) is int and value == 0 for value in rc.values())
                    and 0 < wr.get("profile", {}).get("prompt_tokens", 0) <= 3584
                    and 0 < wr.get("profile", {}).get("generated_tokens", 0) <= max_tokens
                    and not grammar_errors and not power_errors)
                row["runtime_pass"] = bool(runtime_ok)
                if name == "03-discriminator":
                    row["semantic_pass"] = raw == b"B"
                elif name == "02-no-grammar-recovery":
                    row["semantic_pass"] = raw is not None and raw.strip() == b"42"
                else:
                    obj = None
                    try:
                        obj = strict_json(raw) if raw is not None else None
                    except (ValueError, UnicodeError) as error:
                        row["json_error"] = str(error)
                    row["parsed_json"] = obj
                    action = obj.get("arguments") if isinstance(obj, dict) else None
                    xy = action.get("coordinate") if isinstance(action, dict) else None
                    valid = isinstance(xy, list) and len(xy) == 2 and all(type(v) is int and 0 <= v <= 1000 for v in xy)
                    box = fixture[2]
                    hit = bool(valid and box[0] <= xy[0] * 768 / 1000 <= box[2] and box[1] <= xy[1] * 1536 / 1000 <= box[3])
                    row["blue_hit"] = hit
                    row["blue_pixel_box"] = box
                    row["semantic_pass"] = bool(isinstance(obj, dict) and set(obj) == {"name", "arguments"}
                        and obj.get("name") == "mobile_use" and isinstance(action, dict)
                        and set(action) == {"action", "screenshot_id", "coordinate", "summary"}
                        and action.get("action") == "click" and action.get("screenshot_id") == "fixture_" + str(index - 2)
                        and isinstance(action.get("summary"), str) and action["summary"].strip() and hit)
                row["pass"] = bool(runtime_ok and row["semantic_pass"])
            report["cases"].append(row)
            report["active_case"] = None
            save()
            print(json.dumps({k: row.get(k) for k in ("case", "process_exit", "elapsed_seconds", "no_residual_model_process", "runtime_pass", "semantic_pass", "pass", "raw_text")}, ensure_ascii=False), flush=True)
            require(terminated, "model process remains active; stop queue")
            if name == "01-invalid-grammar":
                continue  # Always perform the required no-grammar recovery after this negative case.
            if not row["pass"]:
                break
        report["all_pass"] = len(report["cases"]) == 5 and all(row["pass"] for row in report["cases"])
        positives = [row for row in report["cases"] if not row.get("expected_negative")]
        report["positive_cases_pass"] = len(positives) == 4 and all(row["pass"] for row in positives)
    except Exception as error:
        report["all_pass"] = False
        report["positive_cases_pass"] = False
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        try:
            report["terminal_no_model_process"] = no_model_processes("processes-final")
            phone_hashes("all-immutable-artifacts-after", immutable_pins)
            report["owner_stop_unchanged"] = True
            report["retained_claims_unchanged"] = True
            report["original_and_r2_runtime_unchanged"] = True
            report["model_files_unchanged"] = True
            if report["stage_completed"]:
                phone_hashes("candidate-runtime-final-hashes", {worker: WORKER_SHA,
                    **{args.phone_root + "/" + rel: pin for rel, pin in new_libs.items()}})
                report["candidate_runtime_unchanged"] = True
            require(report["terminal_no_model_process"], "terminal process inventory not empty")
        except Exception as error:
            report["all_pass"] = False
            report["positive_cases_pass"] = False
            report["final_verification_error"] = {"type": type(error).__name__, "message": str(error)}
        report["finished_unix"] = time.time()
        save()
    print(json.dumps({"all_pass": report["all_pass"], "output": str(out), "ui_actions": 0}), flush=True)
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
