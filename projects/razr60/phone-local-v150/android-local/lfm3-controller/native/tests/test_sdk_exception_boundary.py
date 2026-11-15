#!/usr/bin/env python3
"""Exercise the actual C worker + C++ SDK exception boundary with a throwing fake SDK.
No model, Android, accelerator or real SDK-health qualification is established.
"""
import argparse,hashlib,importlib.util,json,os,signal,subprocess,sys,tempfile
from pathlib import Path

def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

THROWER=r'''
#include "vendor/geniex.h"
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <stdexcept>
#include <string>
extern "C" int32_t hepta_test_sdk_throw(const geniex_LlmGenerateInput *input,int call) {
    const char *mode=std::getenv("HEPTA_TEST_CPP_THROW");
    const char *at=std::getenv("HEPTA_TEST_CPP_THROW_AT");
    if(!mode||call!=(at?std::atoi(at):2))return 0;
    if(!std::strcmp(mode,"return_error"))return GENIEX_ERROR_LLM_GENERATION_FAILED;
    if(!std::strcmp(mode,"other"))throw 17;
    if(!std::strcmp(mode,"prefix")){
        if(!input->on_token("x",input->user_data))throw std::runtime_error("fake prefix callback refused");
    }
    if(!std::strcmp(mode,"signal"))std::raise(SIGTERM);
    if(!std::strcmp(mode,"long"))throw std::runtime_error(std::string(900,'X'));
    if(!std::strcmp(mode,"non_ascii"))throw std::runtime_error("test diagnostic \xc3\xa9");
    throw std::runtime_error("Unexpected empty grammar stack after accepting piece: ! (0)");
}
'''

def sha(raw):return hashlib.sha256(raw).hexdigest()
def exercise_exception(base,binary,root,mode,once=False,broken_pipe=False):
    root.mkdir(mode=0o700);(root/"runs").mkdir(mode=0o700);(root/"runs"/base.G).mkdir(mode=0o700)
    model=root/"fixture.gguf";model.write_bytes(base.WEIGHT);model.chmod(0o600)
    C="c"*32
    for rid,prompt in ((base.A,"first full prompt"),(base.B,"second independent full prompt"),(C,"must not run after SDK failure")):
        base.request_files(root,rid,prompt)
    first=root/"runs"/base.A
    argv=[str(binary),"--request-id",base.A,"--mode","llm","--runtime","llama_cpp","--compute","npu",
      "--model",str(model),"--prompt-file",str(first/"prompt.txt"),"--system-file",str(first/"system.txt"),
      "--grammar-file",str(first/"grammar.gbnf"),"--result-file",str(first/"native-result.json"),
      "--text-file",str(first/"raw-text.txt"),"--ctx-size","4096","--max-tokens","32","--threads","2",
      "--timeout-ms","5000","--log-level","debug"]
    if not once:argv+=["--warm-generation",base.G,"--warm-task-id",base.T,"--warm-session-dir",str(root/"runs"/base.G)]
    env=dict(os.environ);env["HEPTA_TEST_CPP_THROW"]=mode;env["HEPTA_TEST_CPP_THROW_AT"]="1" if once else "2"
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    before=None;protocol=[]
    try:
        if once:
            stdout,stderr=process.communicate(timeout=10);code=process.returncode
        else:
            ready=base.line(process);protocol.append(ready)
            assert ready==f"HEPTA_WARM_READY {base.G} {base.T} {process.pid}"
            process.stdin.write(f"RUN {base.G} {base.T} {base.A} 1 32 5000\n".encode());process.stdin.flush()
            done=base.line(process);protocol.append(done)
            assert done==f"HEPTA_WARM_DONE {base.G} {base.T} {base.A} 1 0"
            before=(first/"native-result.json").read_bytes()
            first_receipt=json.loads(before)
            assert first_receipt["generation_complete"] is True
            assert first_receipt["sdk_exception_boundary"]["enabled"] is True
            assert first_receipt["sdk_exception_boundary"]["caught"] is False
            if broken_pipe:process.stdout.close()
            # The next RUN and CLOSE are already queued. A failed generation
            # must still terminate this owner without consuming either frame.
            process.stdin.write((f"RUN {base.G} {base.T} {base.B} 2 32 5000\n"+
                f"RUN {base.G} {base.T} {C} 3 32 5000\nCLOSE {base.G} {base.T}\n").encode());process.stdin.flush()
            if not broken_pipe:
                done=base.line(process);protocol.append(done)
                assert done==f"HEPTA_WARM_DONE {base.G} {base.T} {base.B} 2 70"
            process.stdin.close();code=process.wait(timeout=10);stderr=process.stderr.read();stdout=b""
        assert code==(74 if broken_pipe else 70),(code,stderr.decode())
        failed=first if once else root/"runs"/base.B
        raw=(failed/"native-result.json").read_bytes();request=json.loads(raw)
        assert request["generation_complete"] is False
        assert request["sdk_rc"]["generate"]==-200101
        assert request.get("request_status",request.get("worker_exit_status_planned"))==70
        boundary=request["sdk_exception_boundary"]
        assert boundary["enabled"] is True and boundary["automatic_retry"] is False
        caught=mode!="return_error"
        assert boundary["caught"] is caught
        assert request["worker_outcome"]==("sdk_exception" if caught else "not_completed")
        assert request["error"]==("sdk_cpp_exception" if caught else "sdk_generate_failed")
        assert request["signal_observed"]==(signal.SIGTERM if mode=="signal" else 0)
        if caught:
            assert boundary["kind"]==("other_cpp_exception" if mode=="other" else "std_exception")
            assert boundary["message_truncated"] is (mode=="long")
            assert boundary["message_non_ascii_replaced"] is (mode=="non_ascii")
            assert len(boundary["message_ascii"])<=511
            assert "HEPTA_SDK_GENERATE_EXCEPTION" in stderr.decode()
        text=(failed/"raw-text.txt").read_bytes()
        assert text==(b"x" if mode=="prefix" else b"")
        if mode=="prefix":
            assert request["raw_text_truncated"] is True and request["raw_text_source"]=="callback_prefix"
        assert not (root/"runs"/C/"native-result.json").exists(),"subsequent RUN was consumed"
        assert not (root/"runs"/C/"raw-text.txt").exists()
        terminal=None
        if once:
            assert request["sdk_rc"]["destroy"]==request["sdk_rc"]["deinit"]==0
            assert "init=1 create=1 reset=0 generate=1 destroy=1 deinit=1 vocab=1 vocab_free=1" in stderr.decode()
        else:
            terminal=json.loads((root/"runs"/base.G/"native-session-result.json").read_bytes())
            assert terminal["sdk_destroy_attempted"] is terminal["sdk_deinit_attempted"] is True
            assert terminal["sdk_destroy_rc"]==terminal["sdk_deinit_rc"]==0
            assert terminal["requests_received"]==2 and terminal["requests_completed"]==1
            assert terminal["last_request_return_status"]==70 and terminal["last_request_status"]==code
            assert terminal["close_requested"] is False and terminal["process_exit_observed"] is False
            assert terminal["sdk_exception_boundary"]==boundary
            assert terminal["control_channel_write_failed"] is broken_pipe
            assert (first/"native-result.json").read_bytes()==before,"first successful receipt changed"
            assert "init=1 create=1 reset=2 generate=2 destroy=1 deinit=1 vocab=1 vocab_free=1" in stderr.decode()
        (root/"stderr.log").write_bytes(stderr)
        report={"mode":mode,"one_shot":once,"parent_control_pipe_closed":broken_pipe,
          "physical_exit_observed_by_host":True,"physical_exit_code":code,"protocol":protocol,
          "request_receipt_sha256":sha(raw),"request_receipt":request,"session_receipt":terminal,
          "stderr_sha256":sha(stderr),"subsequent_run_consumed":False,"original_receipt_unchanged":before is not None,
          "real_sdk_executed":False,"phone_tested":False}
        (root/"RESULT.json").write_text(json.dumps(report,indent=2)+"\n")
        return report
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=10)
        for stream in (process.stdin,process.stdout,process.stderr):
            if stream is not None and not stream.closed:stream.close()

def run(root):
    source=Path(__file__).resolve().parents[2];native=source/"native"
    sys.path.insert(0,str(native))
    base=module("boundary_original_harness",native/"tests/test_warm_runtime.py")
    generator=module("boundary_actual_generator",native/"generate_adapter.py")
    generated=root/"generated";generated.mkdir();generator.generate(source,generated)
    code=base.HARNESS.replace("TEST_MODEL_SHA",sha(base.WEIGHT)).replace("TEST_MODEL_BYTES",str(len(base.WEIGHT)))
    marker='int32_t geniex_llm_generate(geniex_LLM *handle,const geniex_LlmGenerateInput *in,geniex_LlmGenerateOutput *out){'
    assert code.count(marker)==1
    code=code.replace(marker,'extern int32_t hepta_test_sdk_throw(const geniex_LlmGenerateInput *,int);\n'+marker+
      '\n    calls_generate++;int32_t injected=hepta_test_sdk_throw(in,calls_generate);if(injected)return injected;')
    old='dirty=1;calls_generate++;out->full_text=strdup("x");'
    assert code.count(old)==1;code=code.replace(old,'dirty=1;out->full_text=strdup("x");')
    harness=root/"harness.c";harness.write_text(code)
    thrower=root/"throwing_sdk.cpp";thrower.write_text(THROWER)
    binary=root/"contract";cobj=root/"harness.o";boundaryobj=root/"boundary.o";throwobj=root/"thrower.o"
    include=["-I"+str(generated),"-I"+str(native),"-I"+str(native/"vendor"),"-I"+str(native/"vendor/llama")]
    commands=[
      ["cc","-std=c11","-Wall","-Wextra","-Werror","-O1","-fexceptions","-DHEPTA_SDK_EXCEPTION_BOUNDARY=1",*include,"-c",str(harness),"-o",str(cobj)],
      ["c++","-std=c++11","-Wall","-Wextra","-Werror","-O1","-fexceptions","-DHEPTA_SDK_EXCEPTION_BOUNDARY=1",*include,"-c",str(native/"sdk-exception-boundary.cpp"),"-o",str(boundaryobj)],
      ["c++","-std=c++11","-Wall","-Wextra","-Werror","-O1","-fexceptions",*include,"-c",str(thrower),"-o",str(throwobj)],
      ["c++",str(cobj),str(boundaryobj),str(throwobj),"-o",str(binary)]]
    command_rows=[]
    for i,command in enumerate(commands):
        p=subprocess.run(command,capture_output=True)
        (root/f"compile-{i}.stdout").write_bytes(p.stdout);(root/f"compile-{i}.stderr").write_bytes(p.stderr)
        command_rows.append({"argv":command,"exit":p.returncode,"stdout_sha256":sha(p.stdout),"stderr_sha256":sha(p.stderr)})
        if p.returncode:raise RuntimeError(p.stderr.decode())
    symbols=subprocess.check_output(["nm","-u",str(cobj)]).decode()
    (root/"actual-c-object-undefined-symbols.txt").write_text(symbols)
    assert " U hepta_guarded_llm_generate" in symbols and " U geniex_llm_generate" not in symbols
    assert " U hepta_sdk_generate_exception" in symbols
    # All six original actual-worker/return-code lifecycle cases remain intact,
    # now additionally compiled through the production C++ boundary.
    original=[]
    for mode in ("normal","changed_model","stale","duplicate","reset_failure","once"):
        base.exercise(binary,root/("original-"+mode),mode);original.append(mode)
    rows=[]
    for mode in ("std","other","prefix","signal","long","non_ascii","return_error"):
        rows.append(exercise_exception(base,binary,root/("throw-"+mode),mode))
    rows.append(exercise_exception(base,binary,root/"throw-once","std",once=True))
    rows.append(exercise_exception(base,binary,root/"throw-broken-pipe","std",broken_pipe=True))
    summary={"schema":"hepta.sdk-generate-exception.host.v1","all_pass":True,
      "original_lifecycle_cases":original,"exception_and_error_cases":rows,"commands":command_rows,
      "actual_generated_worker":True,"actual_cpp_throw_caught":True,"existing_failure_receipts_preserved":True,
      "scope":"host throwing fake SDK only","real_sdk_executed":False,"phone_tested":False}
    (root/"RESULT.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary,sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--out",type=Path);a=p.parse_args()
    if a.out:
        root=a.out.resolve();root.mkdir(parents=True,exist_ok=False);run(root)
    else:
        with tempfile.TemporaryDirectory(prefix="hepta-sdk-exception-") as d:run(Path(d).resolve())
if __name__=="__main__":main()
