#!/usr/bin/env python3
"""Two isolated strict-JSON checks after a verified QAIRT staging run; no UI effects."""
from pathlib import Path
import argparse, hashlib, json, re, shlex, subprocess, time, uuid
from phone_qairt_acceptance import RUNTIME, WORKER, WORKER_SHA, RUNTIME_HASHES, FIXTURES, sha, clean

SYSTEM = (
    "只输出一个完整的JSON对象，不要Markdown或解释。每个对象和数组都必须闭合。"
    "下面是与当前图片无关的完整格式示例："
    '{"name":"mobile_use","arguments":{"action":"open","text":"settings","summary":"打开设置"}}。'
    "当前点击任务的arguments应包含action、screenshot_id、coordinate和summary。"
    "action为click，coordinate是0到1000的两个整数，按原始完整图片的宽高归一化。"
    "必须闭合arguments对象和最外层对象。\n"
)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prior-report", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--phone-root", required=True)
    ap.add_argument("--adb", default="/home/alex/.local/bin/adb")
    ap.add_argument("--adb-port", type=int, default=5061)
    ap.add_argument("--serial", required=True)
    args = ap.parse_args()
    assert re.fullmatch(r"/data/local/tmp/hepta-qwen3vl4b-qairt-[A-Za-z0-9_-]+", args.phone_root)
    prior = json.loads(args.prior_report.read_text())
    assert prior["stage_completed"] is True
    assert [c["case"] for c in prior["cases"][:3]] == ["text42", "position1", "position2"]
    assert all(c["pass"] for c in prior["cases"][:3])
    model_entry = prior["phone_model_entry"]
    assert re.fullmatch(r"/data/local/tmp/hepta-qwen3vl4b-qairt-[A-Za-z0-9_-]+/model/genie_config.json", model_entry)
    model = str(Path(model_entry).parent)
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    adb = [args.adb,"-P",str(args.adb_port),"-s",args.serial]
    report = {"schema":"hepta.qairt-protocol-check.v1","candidate_only":True,
              "ui_actions_executed":False,"production_runtime_changed":False,
              "prior_report_sha256":sha(args.prior_report),"phone_model_entry":model_entry,
              "worker_sha256":WORKER_SHA,"protocol":"nested-mobile-use-complete-example-r2",
              "grammar_requested":False,"cases":[],"all_pass":False,"started_unix":time.time()}
    def save():
        (out/"PROTOCOL-CHECK.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    def run(name,command,timeout=30,check=True):
        start=time.monotonic()
        try: p=subprocess.run(command,capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as e:
            (out/(name+".stdout.raw")).write_bytes(e.stdout or b"")
            (out/(name+".stderr.raw")).write_bytes(e.stderr or b"")
            raise
        stdout=p.stdout
        if name=="keyguard-fresh":
            lines=stdout.decode(errors="replace").splitlines(); keep=set()
            for i,line in enumerate(lines):
                if re.search(r"KeyguardServiceDelegate|KeyguardStateMonitor",line):
                    keep.update(range(i,min(len(lines),i+24)))
                elif re.search(r"keyguard|isStatusBarKeyguard|mShowingLockscreen",line,re.I): keep.add(i)
            stdout=("\n".join(lines[i] for i in sorted(keep))+"\n").encode()
        (out/(name+".stdout.raw")).write_bytes(stdout)
        (out/(name+".stderr.raw")).write_bytes(p.stderr)
        if check and p.returncode: raise RuntimeError(name+" rc="+str(p.returncode))
        return p,time.monotonic()-start
    def shell(name,command,**kw): return run(name,adb+["shell",command],**kw)
    def read_private(name,path):
        p,_=shell(name,"su -c "+shlex.quote(shlex.join(["cat",path])),check=False)
        return p.stdout if p.returncode==0 else None
    save()
    try:
        # Read-only fresh keyguard state, with complete value blocks retained.
        shell("keyguard-fresh","dumpsys window policy",check=False)
        critical={RUNTIME+"/"+k:v for k,v in RUNTIME_HASHES.items()}
        critical[WORKER]=WORKER_SHA; critical.update({f[0]:f[1] for f in FIXTURES})
        p,_=shell("runtime-fixture-hashes",shlex.join(["sha256sum"]+list(critical)),timeout=90)
        actual={line.split(maxsplit=1)[1]:line.split(maxsplit=1)[0] for line in p.stdout.decode().splitlines()}
        assert actual==critical
        shell("new-root",shlex.join(["test","!","-e",args.phone_root]))
        shell("make-root",shlex.join(["mkdir","-m","755",args.phone_root]))
        (out/"system.txt").write_text(SYSTEM)
        run("push-system",adb+["push",str(out/"system.txt"),args.phone_root+"/system.txt"])
        for i,fixture in enumerate(FIXTURES,1):
            case="nested-click"+str(i); req=uuid.uuid4().hex
            private=args.phone_root+"/"+case
            prompt="当前截图ID为fixture_%d。点击蓝色按钮。输出完整的mobile_use JSON，所有括号必须闭合。\n"%i
            (out/(case+".prompt.txt")).write_text(prompt)
            run("push-"+case+"-prompt",adb+["push",str(out/(case+".prompt.txt")),args.phone_root+"/"+case+".prompt.txt"])
            command=["/system/bin/timeout","-k","5","180",WORKER,"--request-id",req,
                     "--mode","vlm","--runtime","qairt","--compute","npu",
                     "--model",model_entry,"--tokenizer",model+"/tokenizer.json",
                     "--ctx-size","0","--threads","4","--max-tokens","160",
                     "--timeout-ms","150000","--log-level","info",
                     "--prompt-file",private+"/prompt.txt","--system-file",private+"/system.txt",
                     "--image",private+"/image.png","--result-file",private+"/result.json",
                     "--text-file",private+"/generated.txt"]
            header=["#!/system/bin/sh","set -eu",
                    'parent_ns="$(readlink /proc/1/ns/net)"','child_ns="$(readlink /proc/self/ns/net)"',
                    'printf "HEPTA_PARENT_NET=%s\\nHEPTA_CHILD_NET=%s\\n" "$parent_ns" "$child_ns"',
                    '[ "$parent_ns" != "$child_ns" ] || exit 88',
                    'routes="$(ip route)"','printf "HEPTA_ROUTES=%s\\n" "$routes"','[ -z "$routes" ] || exit 89',
                    'printf "HEPTA_WRAPPER_ID="; id','printf "HEPTA_WRAPPER_SELINUX="; cat /proc/self/attr/current; echo',
                    "cd "+shlex.quote(model),
                    "export LD_LIBRARY_PATH="+shlex.quote(RUNTIME+"/lib:"+RUNTIME+"/lib/llama_cpp:"+RUNTIME+"/lib/qairt:"+RUNTIME+"/lib/qairt/htp-files:/system/lib64:/vendor/lib64"),
                    "export GENIEX_PLUGIN_PATH="+shlex.quote(RUNTIME+"/lib"),
                    "export GENIEX_QAIRT_LIB="+shlex.quote(RUNTIME+"/lib/qairt/htp-files"),
                    "export ADSP_LIBRARY_PATH="+shlex.quote(RUNTIME+"/lib/qairt/htp-files;/vendor/lib/rfsa/adsp"),
                    "export GGML_HEXAGON_PROFILE=0","export GGML_HEXAGON_VERBOSE=0",
                    shlex.join(["mkdir","-m","700",private]),
                    shlex.join(["cp",args.phone_root+"/"+case+".prompt.txt",private+"/prompt.txt"]),
                    shlex.join(["cp",args.phone_root+"/system.txt",private+"/system.txt"]),
                    shlex.join(["cp",fixture[0],private+"/image.png"]),
                    shlex.join(["chmod","600",private+"/prompt.txt",private+"/system.txt",private+"/image.png"]),
                    "exec "+shlex.join(command)]
            script=out/(case+".sh");script.write_text("\n".join(header)+"\n")
            subprocess.run(["/bin/sh","-n",str(script)],check=True)
            run("push-"+case+"-script",adb+["push",str(script),args.phone_root+"/"+script.name])
            report["active_case"]=case;save();print(json.dumps({"starting":case,"no_ui":True}),flush=True)
            remote="su -c "+shlex.quote("/system/bin/unshare -n /system/bin/sh "+args.phone_root+"/"+script.name)
            p,elapsed=shell(case,remote,timeout=210,check=False)
            raw=read_private("read-"+case+"-text",private+"/generated.txt")
            metadata=read_private("read-"+case+"-result",private+"/result.json")
            wr=json.loads(metadata) if metadata else {}
            if raw is not None:(out/(case+".generated.raw")).write_bytes(raw)
            if metadata is not None:(out/(case+".result.json")).write_bytes(metadata)
            row={"case":case,"request_id":req,"argv":command,"process_exit":p.returncode,"elapsed_seconds":elapsed,
                 "worker_result":wr,"raw_text":raw.decode(errors="replace") if raw is not None else None,
                 "raw_bytes":len(raw) if raw is not None else None,"raw_sha256":hashlib.sha256(raw).hexdigest() if raw is not None else None,
                 "prompt_sha256":hashlib.sha256(prompt.encode()).hexdigest(),"system_sha256":hashlib.sha256(SYSTEM.encode()).hexdigest(),
                 "image_sha256":fixture[1],"phone_hard_timeout_seconds":180,"kill_grace_seconds":5}
            stdout=p.stdout.decode(errors="replace"); stderr=p.stderr.decode(errors="replace")
            parent=re.search(r"HEPTA_PARENT_NET=(.+)",stdout);child=re.search(r"HEPTA_CHILD_NET=(.+)",stdout)
            row["isolated"]=bool(parent and child and parent.group(1)!=child.group(1) and "HEPTA_ROUTES=\n" in stdout)
            row["power_error_lines"]=[s for s in clean(stderr).splitlines() if re.search(r"(?:Failure in|failed).*(?:setPowerConfig|createPowerConfigId|deviceGetInfrastructure)",s,re.I)]
            row["raw_matches_worker"]=bool(raw is not None and wr.get("raw_text_bytes")==len(raw) and wr.get("raw_text_sha256")==row["raw_sha256"])
            row["runtime_pass"]=(p.returncode==0 and row["isolated"] and row["raw_matches_worker"]
                and wr.get("request_id")==req and wr.get("generation_complete") is True and wr.get("stop_reason")=="eos"
                and wr.get("raw_text_utf8") is True and wr.get("raw_text_truncated") is False and wr.get("input_metadata_unchanged") is True
                and wr.get("n_ctx_create")==0 and wr.get("n_gpu_layers_create")==0 and wr.get("power_mode_create")==6
                and wr.get("sdk_rc",{}).get("generate")==0 and not row["power_error_lines"]
                and wr.get("profile",{}).get("prompt_tokens",4097)+160<=4096)
            obj=None
            try:obj=json.loads(raw.decode("utf-8")) if raw is not None else None
            except (ValueError,UnicodeError) as error:row["json_error"]=str(error)
            row["parsed_json"]=obj
            a=obj.get("arguments",{}) if isinstance(obj,dict) else {}
            if not isinstance(a,dict):a={}
            xy=a.get("coordinate");valid=isinstance(xy,list) and len(xy)==2 and all(type(v) is int and 0<=v<=1000 for v in xy)
            box=fixture[2]
            hit=bool(valid and box[0]<=xy[0]*768/1000<=box[2] and box[1]<=xy[1]*1536/1000<=box[3])
            row["blue_pixel_box"]=box;row["blue_hit"]=hit
            row["protocol_pass"]=(isinstance(obj,dict) and set(obj)=={"name","arguments"} and obj.get("name")=="mobile_use"
                and a.get("action")=="click" and a.get("screenshot_id")=="fixture_"+str(i)
                and isinstance(a.get("summary"),str) and bool(a["summary"].strip()) and hit)
            row["pass"]=bool(row["runtime_pass"] and row["protocol_pass"])
            report["cases"].append(row);report["active_case"]=None;save();print(json.dumps(row,ensure_ascii=False),flush=True)
            if not row["runtime_pass"]:break
        report["all_pass"]=len(report["cases"])==2 and all(c["pass"] for c in report["cases"])
    except Exception as error:
        report["error"]=type(error).__name__+": "+str(error);raise
    finally:
        report["finished_unix"]=time.time();save()
    print(json.dumps({"all_pass":report["all_pass"],"output":str(out)}),flush=True)

if __name__=="__main__":main()
