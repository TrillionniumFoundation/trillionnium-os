#!/usr/bin/env python3
"""Stage a fully verified QAIRT bundle and run isolated, fail-closed inference gates.

No UI actions are executed. A complete ready-manifest is required; partial
downloads are never staged. Uses the separately pinned GenieX v0.10.0 runtime.
"""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, math, re, shlex, subprocess, time, uuid

RUNTIME = "/data/local/tmp/hepta-geniex-npu-v0100-20261108"
WORKER = RUNTIME + "/hepta-geniex-once-r2"
MODEL_ROOT_NAME = "qwen3_vl_4b_instruct-geniex_qairt-w4a16-qualcomm_snapdragon_8_elite_for_galaxy"
WORKER_SHA = "67d4e368da136f74a7ab1022013cf1def64f75ebb32d91962772e28a2363864f"
RUNTIME_HASHES = {
    "lib/libgeniex.so": "99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56",
    "lib/qairt/htp-files/libQnnHtp.so": "d299323d79868adbb18997c8e99ae18f961005589ab137f56a51d27e67d6bf0f",
    "lib/qairt/htp-files/libQnnHtpV79Skel.so": "53ad8cde08c1ca2c95bdde7f6f10ab8855f5423edb16e1e7fd6e724ffc27c32b",
    "lib/qairt/htp-files/libQnnHtpV79Stub.so": "166a3bb724c448e9425aa8f98f16b25aa1465eae6334553e408da7256d76fc99",
}
FIXTURES = [
    (RUNTIME + "/fixture_1_2x.png", "3884af3cf4b76e45a6cd8a38084423241863079b48fa2b1fc437069b89591459", [84,260,684,490]),
    (RUNTIME + "/fixture_2_2x.png", "2e08fa22606640ad6da655e406eeb801cfb7cb297f0e276f19efb7348d37c4a6", [84,980,684,1210]),
]
POSITION_PROMPT = "只看图片。三个按钮竖直排列。蓝色按钮位于上方、中间还是下方？只输出一个字：上、中、下。\n"
ACTION_SYSTEM = (
    "你是手机界面操作助手。根据截图选择动作，只输出一个JSON对象，不要Markdown、解释或思考过程。"
    "点击格式必须是{\"name\":\"mobile_use\",\"arguments\":{\"action\":\"click\","
    "\"screenshot_id\":\"当前截图ID\",\"coordinate\":[x,y],\"summary\":\"简短说明\"}}。"
    "坐标x和y必须是0到1000的整数，对应整张原图宽高归一化。选择目标中心。"
    "输出是纯决策，宿主程序不会在本测试中执行它。\n"
)

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda: f.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()

def clean(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ready-manifest", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--phone-root", required=True)
    ap.add_argument("--adb", default="/home/alex/.local/bin/adb")
    ap.add_argument("--adb-port", type=int, default=5061)
    ap.add_argument("--serial", required=True)
    args = ap.parse_args()
    if not re.fullmatch(r"/data/local/tmp/hepta-qwen3vl4b-qairt-[A-Za-z0-9_-]+", args.phone_root):
        ap.error("a new isolated QAIRT phone directory is required")
    ready = json.loads(args.ready_manifest.read_text())
    assert ready["schema"] == "hepta.qairt-bundle-ready.v1"
    assert ready["download_complete"] is True and ready["all_zip_members_crc_pass"] is True
    assert ready["zip_member_count"] == 26
    assert re.fullmatch(r"[a-f0-9]{64}", ready["archive_sha256"])
    assert ready["archive_bytes"] == 3029730149
    bundle = Path(ready["bundle_dir"]).resolve()
    assert bundle.name == MODEL_ROOT_NAME and bundle.is_dir()
    assert ready["soc_model"] == 69 and ready["htp_version"] == 79
    files = ready["files"]
    assert 20 <= len(files) <= 40
    expected = {}
    for entry in files:
        rel = PurePosixPath(entry["path"])
        assert not rel.is_absolute() and ".." not in rel.parts and str(rel) not in expected
        f = bundle / str(rel)
        assert f.is_file() and not f.is_symlink() and f.stat().st_size == entry["bytes"]
        assert re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])
        expected[str(rel)] = entry["sha256"]
    required = ["genie_config.json", "metadata.json", "tokenizer.json", "vision_encoder.bin",
                "embedding_weights.raw", "part1_of_4.bin", "part2_of_4.bin",
                "part3_of_4.bin", "part4_of_4.bin", "htp_backend_ext_config.json"]
    assert all(name in expected for name in required)
    gc = json.loads((bundle / "genie_config.json").read_text())
    assert gc["dialog"]["context"]["size"] == 4096
    assert gc["dialog"]["engine"]["model"]["binary"]["ctx-bins"] == [
        "part1_of_4.bin", "part2_of_4.bin", "part3_of_4.bin", "part4_of_4.bin"]
    hc = json.loads((bundle / "htp_backend_ext_config.json").read_text())
    assert hc["devices"][0]["soc_model"] == 69 and hc["devices"][0]["dsp_arch"] == "v79"
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "BUNDLE-READY.json").write_text(json.dumps(ready, indent=2) + "\n")
    adb = [args.adb, "-P", str(args.adb_port), "-s", args.serial]
    report = {
        "schema": "hepta.qairt-inference-acceptance.v1", "candidate_only": True,
        "production_runtime_changed": False, "ui_actions_executed": False,
        "ready_manifest_sha256": sha(args.ready_manifest),
        "geniex_version": "v0.10.0", "worker_sha256": WORKER_SHA,
        "n_ctx_create": 0, "n_gpu_layers_create": 0, "compiled_max_context": 4096,
        "vision_compiled_size": [512,512], "vision_tokens": 256,
        "power_mode_requested": "sustained_high_performance",
        "power_mode_source": "071f6099 power_mode_utils.h and ab24abb1 resolveHtpPerfConfig; override wins over bundle burst",
        "cases": [], "stage_completed": False, "all_gates_pass": False,
    }
    def checkpoint():
        (out / "ACCEPTANCE.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    def call(name, command, timeout=30, check=True):
        started = time.monotonic()
        try:
            p = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (out / (name + ".stdout.raw")).write_bytes(error.stdout or b"")
            (out / (name + ".stderr.raw")).write_bytes(error.stderr or b"")
            (out / (name + ".host-timeout.json")).write_text(json.dumps({"host_timeout_seconds":timeout,"phone_inference_has_its_own_deadline":name.startswith(("text42","position","click"))})+"\n")
            raise
        durable_stdout = p.stdout
        if name == "process-contexts":
            durable_stdout = b"\n".join(line for line in p.stdout.splitlines()
                if re.search(rb"hepta|native.worker|geniex", line, re.I)) + b"\n"
        elif name == "keyguard-before":
            durable_stdout = b"\n".join(line for line in p.stdout.splitlines()
                if re.search(rb"keyguard|lockscreen|mShowingLockscreen", line, re.I)) + b"\n"
        elif name == "owner-root-mountinfo":
            durable_stdout = b"\n".join(line for line in p.stdout.splitlines()
                if b"/data/trillionnium/owner-open" in line) + b"\n"
        (out / (name + ".stdout.raw")).write_bytes(durable_stdout)
        (out / (name + ".stderr.raw")).write_bytes(p.stderr)
        if check and p.returncode:
            raise RuntimeError(name + ": rc=" + str(p.returncode) + " " + p.stderr.decode(errors="replace")[-1800:])
        return p, time.monotonic() - started
    def shell(name, command, **kwargs):
        return call(name, adb + ["shell", command], **kwargs)
    def hash_phone(name, paths):
        p, _ = shell(name, shlex.join(["sha256sum"] + list(paths)), timeout=180)
        actual = {}
        for line in p.stdout.decode().splitlines():
            digest, path = line.split(maxsplit=1)
            actual[path] = digest
        assert actual == paths, name + " digest mismatch"
    checkpoint()
    try:
        p, _ = shell("device-soc", "getprop ro.soc.model")
        assert p.stdout.decode().strip() == "SM8750"
        p, _ = shell("fastrpc-permissions", "ls -lZ /dev/fastrpc-*", check=False)
        report["fastrpc_permission_read_only"] = p.stdout.decode(errors="replace")
        p, _ = shell("process-contexts", "ps -AZ -o USER,PID,PPID,ARGS", check=False)
        selected = [x for x in p.stdout.decode(errors="replace").splitlines()
                    if re.search(r"hepta|native.worker|geniex", x, re.I)]
        report["selected_process_contexts_before"] = selected
        # Keep only relevant process rows in the durable artifact.
        (out / "process-contexts.stdout.raw").write_text("\n".join(selected) + "\n")
        report["baseline_unix"] = time.time()
        p, _ = shell("keyguard-before", "dumpsys window policy", check=False)
        report["keyguard_before"] = [line for line in p.stdout.decode(errors="replace").splitlines()
            if re.search(r"keyguard|lockscreen|mShowingLockscreen", line, re.I)]
        stop = "/data/trillionnium/owner-open/state/emergency-stop"
        stop_read = "if [ -e " + shlex.quote(stop) + " ]; then echo HEPTA_OWNER_STOP_EXISTS=1; sha256sum " + shlex.quote(stop) + "; else echo HEPTA_OWNER_STOP_EXISTS=0; fi"
        p, _ = shell("owner-stop-before", "su -c " + shlex.quote(stop_read), check=False)
        report["owner_stop_before_read_only"] = p.stdout.decode(errors="replace")
        p, _ = shell("owner-root-mountinfo", "su -c " + shlex.quote("cat /proc/1/mountinfo"), check=False)
        report["owner_root_mounts_before"] = [line for line in p.stdout.decode(errors="replace").splitlines()
            if "/data/trillionnium/owner-open" in line]
        p, _ = shell("memory-before", "cat /proc/meminfo")
        mem_available = re.search(rb"^MemAvailable:\s+(\d+)\s+kB$", p.stdout, re.M)
        report["mem_available_before_kib"] = int(mem_available.group(1)) if mem_available else None
        p, _ = shell("space-before", "df -Pk /data/local/tmp")
        available = int(p.stdout.decode().splitlines()[-1].split()[3]) * 1024
        report["data_available_before_bytes"] = available
        assert available > sum((bundle / n).stat().st_size for n in expected) + 512*1024*1024
        critical = {RUNTIME + "/" + n: h for n,h in RUNTIME_HASHES.items()}
        critical[WORKER] = WORKER_SHA
        critical.update({image: h for image,h,_ in FIXTURES})
        hash_phone("runtime-and-fixture-sha256", critical)
        shell("new-phone-directory", shlex.join(["test","!","-e",args.phone_root]))
        shell("make-phone-directory", shlex.join(["mkdir","-m","755",args.phone_root]))
        model = args.phone_root + "/model"
        print(json.dumps({"stage":"pushing complete verified bundle","bytes":sum((bundle/n).stat().st_size for n in expected)}), flush=True)
        call("push-complete-bundle", adb + ["push", str(bundle), model], timeout=480)
        hash_phone("phone-model-sha256", {model + "/" + n: h for n,h in expected.items()})
        report["stage_completed"] = True
        report["phone_model_entry"] = model + "/genie_config.json"
        checkpoint()
        common_header = "\n".join([
            "#!/system/bin/sh", "set -eu",
            'parent_ns="$(readlink /proc/1/ns/net)"',
            'child_ns="$(readlink /proc/self/ns/net)"',
            'printf "HEPTA_PARENT_NET=%s\\nHEPTA_CHILD_NET=%s\\n" "$parent_ns" "$child_ns"',
            '[ "$parent_ns" != "$child_ns" ] || exit 88',
            'routes="$(ip route)"', 'printf "HEPTA_ROUTES=%s\\n" "$routes"',
            '[ -z "$routes" ] || exit 89',
            'printf "HEPTA_WRAPPER_ID="; id',
            'printf "HEPTA_WRAPPER_SELINUX="; cat /proc/self/attr/current; echo',
            "cd " + shlex.quote(model),
            "export LD_LIBRARY_PATH=" + shlex.quote(RUNTIME+"/lib:"+RUNTIME+"/lib/llama_cpp:"+RUNTIME+"/lib/qairt:"+RUNTIME+"/lib/qairt/htp-files:/system/lib64:/vendor/lib64"),
            "export GENIEX_PLUGIN_PATH=" + shlex.quote(RUNTIME+"/lib"),
            "export GENIEX_QAIRT_LIB=" + shlex.quote(RUNTIME+"/lib/qairt/htp-files"),
            "export ADSP_LIBRARY_PATH=" + shlex.quote(RUNTIME+"/lib/qairt/htp-files;/vendor/lib/rfsa/adsp"),
            "export GGML_HEXAGON_PROFILE=0", "export GGML_HEXAGON_VERBOSE=0", "",
        ])
        cases = [("text42", "只回答一个整数，不要解释：6乘7等于多少？\n", None, None, "42", 24)]
        for i in range(2):
            cases.append(("position"+str(i+1), POSITION_PROMPT, None, FIXTURES[i], ("上","下")[i], 16))
        for i in range(2):
            prompt = "当前截图ID为fixture_%d。点击蓝色按钮。只输出要求的mobile_use JSON。\n" % (i+1)
            cases.append(("click"+str(i+1), prompt, ACTION_SYSTEM, FIXTURES[i], "fixture_"+str(i+1), 160))
        for case,prompt,system,fixture,want,max_tokens in cases:
            req = uuid.uuid4().hex
            private = args.phone_root + "/case-" + case
            source_inputs = {"prompt.txt":prompt}
            if system: source_inputs["system.txt"] = system
            for name,content in source_inputs.items():
                p = out / (case+"-"+name); p.write_text(content)
                call("push-"+case+"-"+name, adb+["push",str(p),args.phone_root+"/"+p.name])
            setup = [shlex.join(["mkdir","-m","700",private])]
            for name in source_inputs:
                setup += [shlex.join(["cp",args.phone_root+"/"+case+"-"+name,private+"/"+name]),
                          shlex.join(["chmod","600",private+"/"+name])]
            if fixture:
                setup += [shlex.join(["cp",fixture[0],private+"/fixture.png"]),
                          shlex.join(["chmod","600",private+"/fixture.png"])]
            # Source pin rejects LLM mode for this multimodal bundle, including a text-only request.
            command = ["/system/bin/timeout","-k","5","180",WORKER,
                       "--request-id",req,"--mode","vlm","--runtime","qairt","--compute","npu",
                       "--model",model+"/genie_config.json","--tokenizer",model+"/tokenizer.json",
                       "--ctx-size","0","--threads","4","--max-tokens",str(max_tokens),
                       "--timeout-ms","150000","--log-level","debug" if case=="text42" else "info",
                       "--prompt-file",private+"/prompt.txt","--result-file",private+"/result.json",
                       "--text-file",private+"/generated.txt"]
            if system: command += ["--system-file",private+"/system.txt"]
            if fixture: command += ["--image",private+"/fixture.png"]
            script = out / (case+".sh")
            script.write_text(common_header+"\n".join(setup)+"\nexec "+shlex.join(command)+"\n")
            subprocess.run(["/bin/sh","-n",str(script)],check=True)
            call("push-"+case+"-script",adb+["push",str(script),args.phone_root+"/"+script.name])
            remote = "su -c " + shlex.quote("/system/bin/unshare -n /system/bin/sh "+args.phone_root+"/"+script.name)
            print(json.dumps({"starting_case":case,"phone_timeout":180,"kill_grace":5,"execute_ui":False}),flush=True)
            report["active_case"] = case
            checkpoint()
            p, elapsed = shell(case,remote,timeout=210,check=False)
            stdout = p.stdout.decode(errors="replace")
            stderr = p.stderr.decode(errors="replace")
            power_errors = [line for line in clean(stderr).splitlines()
                if re.search(r"(?:Failure in|failed).*(?:setPowerConfig|createPowerConfigId|deviceGetInfrastructure)", line, re.I)]
            parent = re.search(r"HEPTA_PARENT_NET=(.+)",stdout); child = re.search(r"HEPTA_CHILD_NET=(.+)",stdout)
            isolated = bool(parent and child and parent.group(1)!=child.group(1) and "HEPTA_ROUTES=\n" in stdout)
            row = {"case":case,"request_id":req,"process_exit":p.returncode,"elapsed_seconds":elapsed,
                   "isolation_asserted":isolated,"argv":command,"generation_text":None,
                   "input_sha256":{"prompt":hashlib.sha256(prompt.encode()).hexdigest(),
                                   "system":hashlib.sha256(system.encode()).hexdigest() if system else None,
                                   "image":fixture[1] if fixture else None},
                   "phone_timeout_seconds":180,"kill_grace_seconds":5}
            row["power_configuration_error_lines"] = power_errors
            row["successful_power_vote_log_available_in_pinned_build"] = False
            row["power_configuration_evidence"] = "Requested enum6 and fixed source override; QNN_INFO success log is compiled out. No clock or watt measurement."
            for remote_name, suffix in [("result.json",".result.json"),("generated.txt",".generated.raw")]:
                q,_ = shell("read-"+case+"-"+remote_name,
                            "su -c "+shlex.quote(shlex.join(["cat",private+"/"+remote_name])),check=False)
                if q.returncode==0:
                    (out/(case+suffix)).write_bytes(q.stdout)
                    if remote_name=="result.json": row["worker_result"] = json.loads(q.stdout)
                    else: row["generation_text"] = q.stdout.decode(errors="replace")
            wr = row.get("worker_result",{})
            runtime_ok = (p.returncode==0 and isolated and wr.get("generation_complete") is True
                          and wr.get("stop_reason")=="eos" and wr.get("raw_text_utf8") is True
                          and wr.get("raw_text_truncated") is False
                          and wr.get("n_ctx_create")==0 and wr.get("n_gpu_layers_create")==0
                          and wr.get("power_mode_create")==6 and wr.get("sdk_rc",{}).get("generate")==0
                          and not power_errors)
            text = (row.get("generation_text") or "").strip()
            if case=="text42" or case.startswith("position"):
                semantic = text==want
            else:
                obj = None
                try: obj=json.loads(text)
                except ValueError: pass
                row["parsed_action"] = obj
                arguments = obj.get("arguments",{}) if isinstance(obj,dict) else {}
                if not isinstance(arguments,dict): arguments = {}
                xy = arguments.get("coordinate")
                valid = isinstance(xy,list) and len(xy)==2 and all(type(v) is int and 0<=v<=1000 for v in xy)
                box = fixture[2]
                hit = bool(valid and box[0]<=xy[0]*768/1000<=box[2] and box[1]<=xy[1]*1536/1000<=box[3])
                semantic = (isinstance(obj,dict) and obj.get("name")=="mobile_use"
                            and arguments.get("action")=="click" and arguments.get("screenshot_id")==want
                            and isinstance(arguments.get("summary"),str) and bool(arguments["summary"].strip()) and hit)
                row["blue_pixel_box"] = box; row["blue_hit"] = hit
            if case=="text42":
                cl = re.findall(r"LLMModel initialized:.*?CL variants \[([0-9, ]+)\]",clean(stderr))
                row["actual_loaded_context_variants"] = [[int(x) for x in v.split(",")] for v in cl]
                row["actual_4096_context_observed"] = any(4096 in v for v in row["actual_loaded_context_variants"])
                runtime_ok = runtime_ok and row["actual_4096_context_observed"]
            profile = wr.get("profile",{})
            row["actual_token_budget_with_max_output"] = profile.get("prompt_tokens",4097)+max_tokens
            row["within_4096_token_budget"] = row["actual_token_budget_with_max_output"]<=4096
            row["runtime_gate_pass"] = runtime_ok
            row["semantic_gate_pass"] = bool(semantic)
            row["pass"] = runtime_ok and semantic and row["within_4096_token_budget"]
            report["cases"].append(row)
            report["active_case"] = None
            checkpoint()
            print(json.dumps(row,ensure_ascii=False),flush=True)
            if not row["pass"]:
                print("STOP_AFTER_FIRST_NONPASS",flush=True)
                break
        report["all_gates_pass"] = len(report["cases"])==5 and all(x["pass"] for x in report["cases"])
        report["note"] = "Passing these synthetic pure-inference gates does not authorize or prove UI execution."
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        report["finished_unix"] = time.time()
        checkpoint()
    print(json.dumps({"all_gates_pass":report["all_gates_pass"],"output":str(out)},ensure_ascii=False),flush=True)

if __name__ == "__main__":
    main()
