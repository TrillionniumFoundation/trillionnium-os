#include <assert.h>
#include <stdio.h>
#include "../model-profile.h"
int main(void){
    const HeptaModelProfile *lfm3=hepta_find_profile("lfm3-1.7b-qad-q4_0");
    assert(lfm3==&hepta_profiles[0]&&lfm3->exact_tokens&&lfm3->bytes==UINT64_C(1049615680));
    assert(!strcmp(lfm3->architecture,"lfm3")&&!strcmp(lfm3->filename,"LFM3-1.7B-QAD-Q4_0.gguf"));
    assert(!strcmp(lfm3->sha256,"43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452"));
    for(size_t i=0;i<sizeof(hepta_profiles)/sizeof(hepta_profiles[0]);i++)assert(hepta_profiles[i].exact_tokens);
    assert(hepta_find_profile("minicpm5-2b-q4_k_m")->bytes==1561318368u);
    assert(!hepta_find_profile("llama"));assert(!hepta_find_profile(NULL));
    char *args[]={"runner","--model-profile","minicpm5-2b-q4_k_m","--compute","npu",NULL};int argc=5;
    assert(hepta_take_model_profile(&argc,args)==0&&argc==3&&!strcmp(args[1],"--compute")&&args[3]==NULL);
    assert(hepta_model_profile->exact_tokens);
    const HeptaModelProfile *e4b=hepta_find_profile("gemma4-e4b-qat-q4_0");
    assert(e4b&&e4b->bytes==UINT64_C(5154941280)&&e4b->bytes>UINT32_MAX&&e4b->exact_tokens);
    assert(!strcmp(e4b->architecture,"gemma4"));
    const HeptaModelProfile *e2b=hepta_find_profile("gemma4-e2b-qat-q4_0");
    assert(e2b&&e2b->bytes==UINT64_C(3349516256)&&e2b->exact_tokens);
    assert(strcmp(e2b->sha256,e4b->sha256)&&strcmp(e2b->filename,e4b->filename));
    const HeptaModelProfile *bolt=hepta_find_profile("nemotron-3.5-bolt-e4b-q4_k_m");
    assert(bolt&&bolt->bytes==UINT64_C(6180446208)&&bolt->bytes>UINT32_MAX&&bolt->exact_tokens);
    assert(!strcmp(bolt->architecture,"gemma4")&&strcmp(bolt->sha256,e4b->sha256));
    char *gemma[]={"runner","--model-profile","gemma4-e4b-qat-q4_0","--compute","gpu",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,gemma)==0&&argc==3&&hepta_model_profile==e4b);
    char *duplicate[]={"runner","--model-profile","lfm3-1.7b-qad-q4_0","--model-profile","minicpm5-2b-q4_k_m",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,duplicate)!=0);
    puts("PASS closed profile allowlist and duplicate-safe argument consumption");return 0;
}
