#!/usr/bin/env python3
"""Host-only guard/argument tests. Never loads GenieX or contacts a device."""
import hashlib,json,os,pathlib,signal,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parent
CC=os.environ.get("PROBE_HOST_CC","cc")
reports=[]
with tempfile.TemporaryDirectory(prefix="moe-probe-tests-") as tmp:
    td=pathlib.Path(tmp)
    prod=td/"probe-host"
    test=td/"probe-test-only"
    flags=["-std=c11","-O2","-Wall","-Wextra","-Werror","-fstack-protector-strong","-D_FORTIFY_SOURCE=2"]
    subprocess.run([CC,*flags,str(ROOT/"probe.c"),"-ldl","-o",str(prod)],check=True)
    subprocess.run([CC,*flags,"-DPROBE_TEST_BUILD","-DPROBE_WALL_SECONDS=1",str(ROOT/"probe.c"),"-ldl","-o",str(test)],check=True)
    def call(name,args,code):
        p=subprocess.run(args,text=True,capture_output=True,timeout=8)
        assert p.returncode==code,(name,p.returncode,p.stdout,p.stderr)
        reports.append({"name":name,"exit_code":p.returncode,"passed":True})
        return p
    call("sha256-empty-abc-million-a",[str(prod),"--self-test"],0)
    def args(out,model,sha,sz=4):
        return [str(prod),"--runtime-lib-dir",str(td/"absent-runtime"),"--model",str(model),"--model-bytes",str(sz),"--model-sha256",sha,"--model-source","host-test-only-not-a-model","--output",str(out)]
    missing=td/"missing"
    call("missing-model-preflight",args(missing,td/"absent.gguf","0"*64),66)
    s=json.loads((missing/"supervisor.json").read_text())
    assert s["status"]=="preflight_blocked_model" and s["child_reaped"]
    assert not any(json.loads(l).get("stage")=="runtime_load" for l in (missing/"events.jsonl").read_text().splitlines())
    fixture=td/"fixture.gguf";fixture.write_bytes(b"GGUF")
    wrong=td/"wrong-sha"
    call("wrong-sha-before-runtime",args(wrong,fixture,"0"*64)+["--run"],65)
    badlib=td/"missing-runtime"
    call("missing-runtime-before-dlopen",args(badlib,fixture,hashlib.sha256(b"GGUF").hexdigest())+["--run"],65)
    assert not any(json.loads(l).get("stage")=="runtime_load" for l in (badlib/"events.jsonl").read_text().splitlines())
    call("no-output-overwrite",args(missing,fixture,"0"*64),73)
    call("no-unbounded-memory-cli",args(td/"bad-option",fixture,"0"*64)+["--reserve-mib","0"],64)
    wd=td/"watchdog"
    start=time.monotonic()
    call("watchdog-owned-child-reaped",[str(test),"--test-watchdog","--output",str(wd)],124)
    w=json.loads((wd/"supervisor.json").read_text())
    assert w["watchdog_reason"]=="wall_deadline" and w["child_reaped"] and w["child_signal"]==signal.SIGKILL
    assert time.monotonic()-start<4
    try:os.kill(w["child_pid"],0)
    except ProcessLookupError:pass
    else:raise AssertionError("watchdog child survived")
    reports.append({"name":"watchdog-no-orphan","passed":True})
    parser=td/"parameters.c"
    parser.write_text('#define main probe_cli_main\n#include "'+str(ROOT/"probe.c")+'"\n#undef main\nint main(void){epoch=now();events=tmpfile();if(!events)return 1;sdk_log(GENIEX_LOG_LEVEL_INFO,"[Optimise] context params: n_ctx=2048, n_batch=128, n_ubatch=128, n_seq_max=1, n_threads=4, n_threads_batch=4");if(atomic_load(&observed_context)!=1)return 2;sdk_log(GENIEX_LOG_LEVEL_INFO,"[Optimise] model params: n_gpu_layers=-1, load_mode=none");if(atomic_load(&observed_model)!=1)return 3;sdk_log(GENIEX_LOG_LEVEL_INFO,"[Optimise] context params: n_ctx=2048, n_batch=128, n_ubatch=1024, n_seq_max=1, n_threads=4, n_threads_batch=4");if(atomic_load(&observed_context)!=-1)return 4;fclose(events);return 0;}\n')
    parserbin=td/"parameters"
    subprocess.run([CC,*flags,str(parser),"-ldl","-o",str(parserbin)],check=True)
    call("actual-parameter-log-mismatch-detected",[str(parserbin)],0)
result={"schema":"hepta.moe-probe.host-validation.v1","all_pass":True,"phone_contacted":False,"sdk_loaded":False,"device_inference_executed":False,"tests":reports,"source_sha256":hashlib.sha256((ROOT/"probe.c").read_bytes()).hexdigest(),"header_sha256":hashlib.sha256((ROOT/"vendor/geniex.h").read_bytes()).hexdigest()}
(ROOT/"HOST-VALIDATION.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps(result))

