#!/usr/bin/env python3
"""Compile the real generated C and exercise private publication with fake text.

Only the GGUF metadata getter is stubbed; no model is loaded or generated.
Unused SDK-call sections are discarded by the host linker.
"""
import argparse
import importlib.util
import json
import subprocess
import tempfile
import sys
from pathlib import Path


def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


HARNESS=r'''
#define _GNU_SOURCE 1
#include "geniex.h"
#include "llama.h"
#include <assert.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include "prompt-budget.h"
#include "model-profile.h"
#define main unused_native_worker_main
#include "worker-appuid.c"
#undef main
const char *llama_model_chat_template(const struct llama_model *model,const char *name){
    (void)model;(void)name;return "test-only template";
}
static void reset_test(void){
    hepta_prompt_evidence_complete=false;
    hepta_model_profile=&hepta_profiles[1];hepta_model_verified=true;
    strcpy(hepta_verified_model_sha,hepta_model_profile->sha256);
    hepta_vocabulary_model=(struct llama_model *)(uintptr_t)1;
    static llama_token tokens[]={1,42};hepta_input_ids=tokens;hepta_input_count=2;
    const unsigned char encoded[]={1,0,0,0,42,0,0,0};
    hash_bytes(encoded,sizeof(encoded),hepta_prompt_budget.input_ids_sha256);
    start_ns=monotonic_ns();deadline_ns=start_ns+UINT64_C(30000000000);cancel_signal=0;deadline_hit=false;
}
static void assert_contents(const char *path,const char *data,size_t length){
    int fd=open(path,O_RDONLY|O_CLOEXEC);assert(fd>=0);char actual[256];ssize_t n=read(fd,actual,sizeof actual);
    assert(n==(ssize_t)length&&!memcmp(actual,data,length));close(fd);
}
int main(int argc,char **argv){
    (void)hepta_take_model_profile;
    assert(argc==3);assert(!mkdir(argv[1],0700));
    char result[PATH_MAX];assert(snprintf(result,sizeof result,"%s/native-result.json",argv[1])<(int)sizeof result);
    Options o={.id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.result=result,.ctx=4096};
    Input inputs[4]={{0}};const char *prompt="test-only prompt\n";char sha[65];hash_bytes(prompt,strlen(prompt),sha);
    reset_test();
    if(!strcmp(argv[2],"normal")){
        assert(hepta_capture_prompt_evidence(&o,inputs,prompt,strlen(prompt),sha));assert(hepta_prompt_evidence_complete);
        assert_contents(hepta_prompt_evidence_formatted_path,prompt,strlen(prompt));
        const char encoded[]={1,0,0,0,42,0,0,0};assert_contents(hepta_prompt_evidence_ids_path,encoded,sizeof encoded);
        assert(!hepta_capture_prompt_evidence(&o,inputs,prompt,strlen(prompt),sha));
        assert_contents(hepta_prompt_evidence_formatted_path,prompt,strlen(prompt));
    }else if(!strcmp(argv[2],"symlink")){
        char path[PATH_MAX];snprintf(path,sizeof path,"%s/formatted-prompt.txt",argv[1]);assert(!symlink("unchanged",path));
        assert(!hepta_capture_prompt_evidence(&o,inputs,prompt,strlen(prompt),sha));assert(!hepta_prompt_evidence_complete);
        struct stat st;assert(!lstat(path,&st)&&S_ISLNK(st.st_mode));
    }else if(!strcmp(argv[2],"token_hash")){
        hepta_prompt_budget.input_ids_sha256[0]='0';
        assert(!hepta_capture_prompt_evidence(&o,inputs,prompt,strlen(prompt),sha));assert(!hepta_prompt_evidence_complete);
        assert(access(hepta_prompt_evidence_meta_path,F_OK)<0);
    }else if(!strcmp(argv[2],"prompt_hash")){
        sha[0]=sha[0]=='0'?'1':'0';
        assert(!hepta_capture_prompt_evidence(&o,inputs,prompt,strlen(prompt),sha));assert(!hepta_prompt_evidence_complete);
    }else if(!strcmp(argv[2],"original_lfm")){
        hepta_model_profile=&hepta_profiles[0];hepta_input_ids=NULL;hepta_input_count=0;
        assert(hepta_capture_prompt_evidence(&o,inputs,prompt,strlen(prompt),sha));
        assert_contents(hepta_prompt_evidence_ids_path,"",0);
    }else assert(0);
    return 0;
}
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--base",type=Path,default=Path(__file__).resolve().parents[2])
    args=parser.parse_args()
    here=args.base/"native"
    sys.path.insert(0,str(here))
    generator=module("base_generator",args.base/"native/generate_adapter.py")
    adapter=module("prompt_adapter",here/"prompt_evidence_adapter.py")
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);generator.generate(args.base,root)
        source=(root/"worker-appuid.c").read_text()
        assert '#include "prompt-evidence.inc"' in source
        try:adapter.adapt(source)
        except ValueError:pass
        else:raise AssertionError("duplicate adaptation accepted")
        (root/"worker-appuid.c").write_text(source)
        (root/"test.c").write_text(HARNESS)
        flags=["gcc","-std=c11","-Wall","-Wextra","-Werror","-ffunction-sections","-fdata-sections"]
        includes=[]
        for path in [root,here,args.base/"native",args.base/"native/vendor",args.base/"native/vendor/llama"]:
            includes += ["-I",str(path)]
        subprocess.run(flags+includes+["-fsyntax-only",str(args.base/"native/probe-worker.c")],check=True)
        binary=root/"contract"
        subprocess.run(flags+includes+[str(root/"test.c"),"-Wl,--gc-sections","-o",str(binary)],check=True)
        for case in ["normal","symlink","token_hash","prompt_hash","original_lfm"]:
            subprocess.run([str(binary),str(root/case),case],check=True)
        metadata=json.loads((root/"normal/prompt-evidence.json").read_text())
        assert metadata["input_ids_count"]==2 and metadata["input_ids_will_be_passed_directly"] is True
        old=json.loads((root/"original_lfm/prompt-evidence.json").read_text())
        assert old["input_ids_count"]==0 and old["input_ids_will_be_passed_directly"] is False
    print("PASS: full generated C syntax; exact bytes/IDs; no overwrite; symlink rejection; bad prompt/token hashes; original LFM semantics; duplicate adapter rejection")


if __name__=="__main__":
    main()
