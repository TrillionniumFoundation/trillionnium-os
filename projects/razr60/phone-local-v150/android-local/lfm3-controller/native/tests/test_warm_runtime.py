#!/usr/bin/env python3
"""Run the generated native request/IPC/receipt code with an explicit fake SDK.

This exercises actual held-FD hashing, metadata fences, publication and worker
lifetime. SDK and vocabulary functions are test doubles; no model, NPU/GPU,
Android runtime, model capability or phone qualification is established.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import tempfile

G, T, A, B = "1" * 32, "2" * 32, "a" * 32, "b" * 32
WEIGHT = b"host-only fake model bytes\n"
SYSTEM = "host-test system"
HARNESS = r'''
#define _GNU_SOURCE 1
#include "geniex.h"
#include "llama.h"
#include <assert.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include "prompt-budget.h"
#include "model-profile.h"
#define main upstream_worker_main
#include "worker-appuid.c"
#undef main
#include "warm-protocol.inc"
static int calls_init,calls_create,calls_reset,calls_generate,calls_destroy,calls_deinit,calls_vocab,calls_vocab_free;
static int fake_handle,dirty;
static const char *last_formatted;
static HeptaModelProfile test_profile={"host-test-only","fixture.gguf","TEST_MODEL_SHA","host-test",TEST_MODEL_BYTES,false};
const char *geniex_version(void){return "0.10.0";}
void geniex_free(void *p){free(p);}
int32_t geniex_set_log_level(geniex_LogLevel level){(void)level;return 0;}
int32_t geniex_init(void){assert(++calls_init==1);return 0;}
int32_t geniex_deinit(void){assert(++calls_deinit==1&&calls_destroy==1);return 0;}
int32_t geniex_resolve_device(const geniex_ResolveDeviceInput *in,geniex_ResolveDeviceOutput *out){
    assert(!strcmp(in->plugin_id,"llama_cpp")&&!strcmp(in->mode,"npu"));out->device_id=strdup("HTP0");out->ngl=-1;return 0;
}
int32_t geniex_llm_create(const geniex_LlmCreateInput *in,geniex_LLM **out){
    assert(++calls_create==1&&in->config.n_ctx==4096&&!strncmp(in->model_path,"/proc/self/fd/",14));
    *out=(geniex_LLM *)&fake_handle;return 0;
}
int32_t geniex_llm_reset(geniex_LLM *handle){
    assert(handle==(geniex_LLM *)&fake_handle);calls_reset++;
    if(getenv("HEPTA_TEST_RESET_FAIL")&&calls_reset==2)return -1;
    dirty=0;return 0;
}
int32_t geniex_llm_destroy(geniex_LLM *handle){assert(handle==(geniex_LLM *)&fake_handle);assert(++calls_destroy==1);return 0;}
int32_t geniex_llm_apply_chat_template(geniex_LLM *handle,const geniex_LlmApplyChatTemplateInput *in,geniex_LlmApplyChatTemplateOutput *out){
    assert(handle==(geniex_LLM *)&fake_handle&&in->message_count==2&&!in->enable_thinking&&in->add_generation_prompt);
    if(!strcmp(in->messages[1].content,"test overlarge rendered prompt")){
        size_t n=4u*INPUT_LIMIT+1u;out->formatted_text=malloc(n+1u);assert(out->formatted_text);
        memset(out->formatted_text,'x',n);out->formatted_text[n]='\0';
    }else{
        int n=asprintf(&out->formatted_text,"%s\n%s",in->messages[0].content,in->messages[1].content);assert(n>0);
    }
    last_formatted=out->formatted_text;return 0;
}
int32_t geniex_llm_generate(geniex_LLM *handle,const geniex_LlmGenerateInput *in,geniex_LlmGenerateOutput *out){
    assert(handle==(geniex_LLM *)&fake_handle&&!dirty&&in->input_ids&&in->input_ids_count>0&&!in->prompt_utf8);
    assert(in->input_ids==hepta_input_ids&&in->input_ids_count==hepta_input_count);
    assert(last_formatted&&in->input_ids_count==(int32_t)strlen(last_formatted)+1&&in->input_ids[0]==1);
    for(int32_t i=1;i<in->input_ids_count;i++)assert(in->input_ids[i]==((unsigned char)last_formatted[i-1])+2);
    assert(in->config&&in->config->sampler_config&&in->config->sampler_config->grammar_string&&in->on_token("x",in->user_data));
    dirty=1;calls_generate++;out->full_text=strdup("x");out->profile_data.prompt_tokens=in->input_ids_count;
    out->profile_data.generated_tokens=1;out->profile_data.stop_reason="eos";return 0;
}
int32_t geniex_vlm_create(const geniex_VlmCreateInput *a,geniex_VLM **b){(void)a;(void)b;assert(0);return -1;}
int32_t geniex_vlm_destroy(geniex_VLM *a){(void)a;assert(0);return -1;}
int32_t geniex_vlm_apply_chat_template(geniex_VLM *a,const geniex_VlmApplyChatTemplateInput *b,geniex_VlmApplyChatTemplateOutput *c){(void)a;(void)b;(void)c;assert(0);return -1;}
int32_t geniex_vlm_generate(geniex_VLM *a,const geniex_VlmGenerateInput *b,geniex_VlmGenerateOutput *c){(void)a;(void)b;(void)c;assert(0);return -1;}
struct llama_model_params llama_model_default_params(void){return (struct llama_model_params){0};}
struct llama_model *llama_model_load_from_file(const char *path,struct llama_model_params params){
    assert(!strncmp(path,"/proc/self/fd/",14)&&params.vocab_only&&params.n_gpu_layers==0);calls_vocab++;
    return (struct llama_model *)&fake_handle;
}
void llama_model_free(struct llama_model *model){assert(model==(struct llama_model *)&fake_handle);calls_vocab_free++;}
int32_t llama_model_meta_val_str(const struct llama_model *model,const char *key,char *buf,size_t size){
    (void)model;assert(!strcmp(key,"general.architecture"));return snprintf(buf,size,"host-test");
}
const char *llama_model_chat_template(const struct llama_model *model,const char *name){(void)model;(void)name;return "host-only fake template";}
const struct llama_vocab *llama_model_get_vocab(const struct llama_model *model){assert(model);return (const struct llama_vocab *)&fake_handle;}
int32_t llama_vocab_n_tokens(const struct llama_vocab *vocab){assert(vocab);return 512;}
int32_t llama_tokenize(const struct llama_vocab *vocab,const char *text,int32_t len,llama_token *tokens,int32_t maximum,bool add_special,bool parse_special){
    assert(vocab&&add_special&&parse_special);int32_t count=len+1;if(maximum<count)return -count;
    tokens[0]=1;for(int32_t i=0;i<len;i++)tokens[i+1]=((unsigned char)text[i])+2;
    return strstr(text,"tokenizer-second-pass-mismatch")?count-1:count;
}
int main(int argc,char **argv){
    (void)hepta_take_model_profile;
    const HeptaModelProfile *production=hepta_find_profile("lfm3-1.7b-qad-q4_0");
    assert(production&&production->exact_tokens);
    test_profile.exact_tokens=production->exact_tokens;hepta_model_profile=&test_profile;
    assert(hepta_take_warm_arguments(&argc,argv)==0);assert(hepta_warm_prepare_control());
    hepta_prompt_budget=(HeptaPromptBudget){.exact=true,.model_sha256=test_profile.sha256};
    int rc=hepta_warm_enabled?hepta_warm_loop(argc,argv):upstream_worker_main(argc,argv);
    fprintf(stderr,"HOST_FAKE_SDK init=%d create=%d reset=%d generate=%d destroy=%d deinit=%d vocab=%d vocab_free=%d\n",
        calls_init,calls_create,calls_reset,calls_generate,calls_destroy,calls_deinit,calls_vocab,calls_vocab_free);
    return rc;
}
'''


def line(process):
    ready, _, _ = select.select([process.stdout], [], [], 5)
    if not ready:
        raise AssertionError("native control reply deadline")
    value = process.stdout.readline().decode("ascii").strip()
    if not value:
        raise AssertionError("native control ended: " + process.stderr.read().decode())
    return value


def request_files(root, request, prompt):
    directory = root / "runs" / request
    directory.mkdir(mode=0o700)
    for name, content in (("prompt.txt", prompt), ("system.txt", SYSTEM), ("grammar.gbnf", 'root ::= "x"\n')):
        path = directory / name
        path.write_text(content)
        path.chmod(0o600)


def verify_counted_ids(directory, receipt):
    """Independent encoding/hash check of the test-double tokenizer's exact IDs."""
    formatted = (directory / "formatted-prompt.txt").read_bytes()
    expected = b"".join(struct.pack("<i", value) for value in [1] + [value + 2 for value in formatted])
    ids = (directory / "formatted-input-ids.le32").read_bytes()
    assert ids == expected
    evidence = json.loads((directory / "prompt-evidence.json").read_bytes())
    budget = receipt["prompt_budget"]
    count = len(expected) // 4
    assert budget["method"] == "llama_tokenize_exact_same_input_ids"
    assert budget["input_ids_passed_directly"] is True
    assert count == budget["prompt_tokens_exact"] == budget["input_ids_count"] == receipt["profile"]["prompt_tokens"]
    assert hashlib.sha256(ids).hexdigest() == budget["input_ids_sha256"] == evidence["input_ids_sha256"]
    assert evidence["input_ids_will_be_passed_directly"] is True
    assert evidence["input_ids_count"] == count and evidence["input_ids_bytes"] == len(ids)
    return budget["input_ids_sha256"]


def exercise(binary, root, mode):
    root.mkdir(mode=0o700); (root / "runs").mkdir(mode=0o700); (root / "runs" / G).mkdir(mode=0o700)
    model = root / "fixture.gguf"; model.write_bytes(WEIGHT); model.chmod(0o600)
    first_prompt = "first full prompt 中文😀"
    second_prompt = "second independent full prompt"
    if mode == "repeat": second_prompt = first_prompt
    if mode in ("boundary", "overflow"):
        # Fake tokenizer adds one ID and one for every UTF-8 byte. This is
        # an exact fixture boundary, not a count claimed for the real model.
        length = 4096 - 32 - 256 - len(SYSTEM.encode()) - 1 - 1
        second_prompt = "x" * (length + (mode == "overflow"))
    if mode == "tokenizer_mismatch": second_prompt = "tokenizer-second-pass-mismatch"
    if mode == "formatted_oversize": second_prompt = "test overlarge rendered prompt"
    success = mode in ("normal", "repeat", "boundary")
    admission_failure = mode in ("overflow", "tokenizer_mismatch", "formatted_oversize")
    request_files(root, A, first_prompt); request_files(root, B, second_prompt)
    first = root / "runs" / A
    argv = [str(binary), "--request-id", A, "--mode", "llm", "--runtime", "llama_cpp", "--compute", "npu",
        "--model", str(model), "--prompt-file", str(first / "prompt.txt"), "--system-file", str(first / "system.txt"),
        "--grammar-file", str(first / "grammar.gbnf"), "--result-file", str(first / "native-result.json"),
        "--text-file", str(first / "raw-text.txt"), "--ctx-size", "4096", "--max-tokens", "32", "--threads", "2",
        "--timeout-ms", "5000", "--log-level", "debug"]
    if mode != "once":
        argv += ["--warm-generation", G, "--warm-task-id", T, "--warm-session-dir", str(root / "runs" / G)]
    env = dict(os.environ)
    if mode == "reset_failure":
        env["HEPTA_TEST_RESET_FAIL"] = "1"
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        if mode == "once":
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr.decode()
            receipt = json.loads((first / "native-result.json").read_bytes())
            assert receipt["schema"] == "hepta.geniex-once.result.v1" and receipt["generation_complete"] is True
            verify_counted_ids(first, receipt)
            assert "init=1 create=1 reset=0 generate=1 destroy=1 deinit=1 vocab=1 vocab_free=1" in stderr.decode()
            return
        assert line(process) == f"HEPTA_WARM_READY {G} {T} {process.pid}"
        def send(value):
            process.stdin.write((value + "\n").encode("ascii")); process.stdin.flush()
        send(f"RUN {G} {T} {A} 1 32 5000")
        assert line(process) == f"HEPTA_WARM_DONE {G} {T} {A} 1 0"
        first_bytes = (first / "native-result.json").read_bytes()
        first_receipt = json.loads(first_bytes)
        assert first_receipt["process_exit_observed"] is False and process.poll() is None
        assert first_receipt["model_create_count"] == first_receipt["model_hash_count"] == first_receipt["model_reset_count"] == 1
        first_ids_sha = verify_counted_ids(first, first_receipt)
        if mode == "changed_model":
            before = model.stat(); os.utime(model, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000))
        if mode == "stale":
            send(f"RUN {'3' * 32} {T} {B} 2 32 5000")
        elif mode == "duplicate":
            send(f"RUN {G} {T} {A} 2 32 5000")
        else:
            send(f"RUN {G} {T} {B} 2 32 5000")
            expected = 0 if success else 70
            assert line(process) == f"HEPTA_WARM_DONE {G} {T} {B} 2 {expected}"
            second = json.loads((root / "runs" / B / "native-result.json").read_bytes())
            assert second["model_hash_count"] == second["model_create_count"] == 1
            assert second["model_hash_performed_this_request"] is False
            if success:
                assert process.poll() is None and second["generation_complete"] is True
                assert second["model_reset_count"] == 2 and second["model_reset_rc"] == 0
                second_ids_sha = verify_counted_ids(root / "runs" / B, second)
                assert (first_receipt["formatted_prompt_sha256"] == second["formatted_prompt_sha256"]) == (mode == "repeat")
                assert (first_receipt["input_sha256"]["prompt"] == second["input_sha256"]["prompt"]) == (mode == "repeat")
                assert (first_ids_sha == second_ids_sha) == (mode == "repeat")
                if mode == "boundary": assert second["prompt_budget"]["total_context_tokens"] == 4096
                assert second["sdk_rc"]["create"] is None and second["sdk_rc"]["init"] is None
                send(f"CLOSE {G} {T}")
            elif mode == "reset_failure":
                assert second["generation_complete"] is False and second["model_reset_rc"] == -1
            elif admission_failure:
                assert second["generation_complete"] is False and second["sdk_rc"]["generate"] is None
                assert second["model_reset_count"] == 1 and second["model_metadata_unchanged"] is True
                assert not (root / "runs" / B / "prompt-evidence.json").exists()
                expected_error = "formatted_prompt_invalid_or_oversized" if mode == "formatted_oversize" else "formatted_prompt_exceeds_fixed_context"
                assert second["error"] == expected_error
            else:
                assert second["generation_complete"] is False and second["model_metadata_unchanged"] is False
        process.stdin.close()
        code = process.wait(timeout=10)
        stderr = process.stderr.read().decode()
        assert code == (0 if success else 64 if mode in ("stale", "duplicate") else 70), stderr
        terminal = json.loads((root / "runs" / G / "native-session-result.json").read_bytes())
        assert terminal["pid"] == process.pid and terminal["process_exit_observed"] is False
        assert terminal["sdk_destroy_attempted"] is True and terminal["sdk_deinit_attempted"] is True
        assert terminal["sdk_destroy_rc"] == terminal["sdk_deinit_rc"] == 0
        assert "init=1 create=1" in stderr and "destroy=1 deinit=1 vocab=1 vocab_free=1" in stderr
        assert (first / "native-result.json").read_bytes() == first_bytes, "create-only original output changed"
        if success:
            assert terminal["close_requested"] is True and terminal["requests_completed"] == 2
            assert "reset=2 generate=2" in stderr
        elif mode == "reset_failure":
            assert "reset=2 generate=1" in stderr and terminal["requests_completed"] == 1
        elif mode == "changed_model":
            assert "reset=1 generate=1" in stderr and terminal["model_metadata_unchanged_before_close"] is False
        elif admission_failure:
            assert "reset=1 generate=1" in stderr and terminal["requests_completed"] == 1
        else:
            assert "reset=1 generate=1" in stderr and terminal["requests_received"] == 1
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def main():
    base = Path(__file__).resolve().parents[2]
    native = base / "native"
    sys.path.insert(0, str(native))
    spec = importlib.util.spec_from_file_location("warm_test_generator", native / "generate_adapter.py")
    generator = importlib.util.module_from_spec(spec); spec.loader.exec_module(generator)
    with tempfile.TemporaryDirectory(prefix="hepta-warm-native-") as directory:
        root = Path(directory).resolve(); generator.generate(base, root)
        code = HARNESS.replace("TEST_MODEL_SHA", hashlib.sha256(WEIGHT).hexdigest()).replace("TEST_MODEL_BYTES", str(len(WEIGHT)))
        (root / "test.c").write_text(code)
        binary = root / "contract"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
            "-I" + str(root), "-I" + str(native), "-I" + str(native / "vendor"), "-I" + str(native / "vendor/llama"),
            str(root / "test.c"), "-o", str(binary)], check=True)
        for mode in ("normal", "repeat", "boundary", "overflow", "tokenizer_mismatch", "formatted_oversize",
                     "changed_model", "stale", "duplicate", "reset_failure", "once"):
            exercise(binary, root / mode, mode)
    print("PASS: 11 generated worker/protocol cases; LFM3 registry exact path; counted/generated/exported ID equality and SHA; repeat/reset consistency; boundary accepted; overflow/tokenizer mismatch/rendered byte cap rejected before generate; lifecycle and one-shot preserved. Fake SDK/tokenizer only; no model/phone/acceleration claim.")


if __name__ == "__main__":
    main()
