#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "model-profile.h"

int main(void){
    const HeptaModelProfile *p=hepta_find_profile("qwen35-4b-q4_0");
    assert(p&&p->bytes==UINT64_C(2583221408)&&p->bytes>INT32_MAX);
    assert(!strcmp(p->filename,"Qwen3.5-4B-Q4_0.gguf"));
    assert(!strcmp(p->sha256,"298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb"));
    assert(!strcmp(p->architecture,"qwen35")&&p->exact_tokens);
    assert(!hepta_find_profile("qwen35")&&!hepta_find_profile("../Qwen3.5-4B-Q4_0.gguf"));
    assert(hepta_find_profile("lfm2.5-8b-a1b-q4_0")&&!hepta_find_profile("lfm25-8b-a1b-q4_0"));
    char *args[]={"runner","--model-profile","qwen35-4b-q4_0","--compute","npu",NULL};int argc=5;
    assert(hepta_take_model_profile(&argc,args)==0&&hepta_model_profile==p&&argc==3&&args[3]==NULL);
    assert(!strcmp(args[1],"--compute")&&!strcmp(args[2],"npu"));
    char *duplicate[]={"runner","--model-profile","qwen35-4b-q4_0","--model-profile","lfm2.5-8b-a1b-q4_0",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,duplicate)!=0);
    assert(sizeof(hepta_profiles)/sizeof(hepta_profiles[0])==8);
    puts("PASS native Qwen exact artifact, eight-profile set and unique argument; inference=false");
    return 0;
}
