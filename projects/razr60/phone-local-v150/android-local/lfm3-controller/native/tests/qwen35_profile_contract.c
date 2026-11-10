#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "model-profile.h"

int main(void){
    const HeptaModelProfile *profile=hepta_find_profile("qwen3.5-4b-q4_0");
    assert(profile&&profile->bytes==UINT64_C(2583221408)&&profile->bytes>INT32_MAX);
    assert(profile->exact_tokens&&!strcmp(profile->architecture,"qwen35"));
    assert(!strcmp(profile->filename,"Qwen3.5-4B-Q4_0.gguf"));
    assert(!strcmp(profile->sha256,"298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb"));
    const char *legacy[]={"lfm3-1.7b-qad-q4_0","minicpm5-2b-q4_k_m","spark-x2.6-4b-q4_k_m",
      "gemma4-e4b-qat-q4_0","gemma4-e2b-qat-q4_0","nemotron-3.5-bolt-e4b-q4_k_m","lfm2.5-8b-a1b-q4_0"};
    assert(sizeof(hepta_profiles)/sizeof(hepta_profiles[0])==11);
    for(size_t i=0;i<sizeof(legacy)/sizeof(legacy[0]);i++){
        assert(!strcmp(hepta_profiles[i].id,legacy[i]));
        assert(hepta_find_profile(legacy[i])==&hepta_profiles[i]);
    }
    assert(profile==&hepta_profiles[7]&&!hepta_profiles[0].exact_tokens);
    assert(!hepta_find_profile("qwen35")&&!hepta_find_profile("qwen3.5-14b-q4_0"));
    assert(!hepta_find_profile("../Qwen3.5-4B-Q4_0.gguf"));
    char *args[]={"runner","--model-profile","qwen3.5-4b-q4_0","--compute","npu",NULL};int argc=5;
    assert(hepta_take_model_profile(&argc,args)==0&&hepta_model_profile==profile&&argc==3&&args[3]==NULL);
    assert(!strcmp(args[1],"--compute")&&!strcmp(args[2],"npu"));
    char *duplicate[]={"runner","--model-profile","qwen3.5-4b-q4_0","--model-profile","lfm3-1.7b-qad-q4_0",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,duplicate)!=0);
    const HeptaModelProfile *large=hepta_find_profile("qwen3.5-9b-q4_0");
    assert(large==&hepta_profiles[8]&&large!=profile&&large->bytes==UINT64_C(5379417312)&&large->bytes>UINT32_MAX);
    assert(large->exact_tokens&&!strcmp(large->architecture,"qwen35"));
    assert(!strcmp(large->filename,"Qwen3.5-9B-Q4_0.gguf"));
    assert(!strcmp(large->sha256,"17670346b4260ddcb0173965145155885024f3c9a4a24389a3370751edbcde24"));
    char *large_args[]={"runner","--model-profile","qwen3.5-9b-q4_0","--compute","npu",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,large_args)==0&&hepta_model_profile==large&&argc==3&&large_args[3]==NULL);
    puts("PASS Qwen closed native identity, legacy indices and unique argument selection; inference=false");
    return 0;
}
