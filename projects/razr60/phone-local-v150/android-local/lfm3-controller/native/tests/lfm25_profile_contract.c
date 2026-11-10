#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "model-profile.h"

int main(void){
    const HeptaModelProfile *profile=hepta_find_profile("lfm2.5-8b-a1b-q4_0");
    if(!profile){fputs("LFM25_PROFILE_NOT_REGISTERED\n",stderr);return 3;}
    assert(profile->bytes==UINT64_C(4844678368)&&profile->bytes>UINT32_MAX);
    assert(profile->exact_tokens&&!strcmp(profile->architecture,"lfm2moe"));
    assert(!strcmp(profile->filename,"LFM2.5-8B-A1B-Q4_0.gguf"));
    assert(!strcmp(profile->sha256,"48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715"));
    assert(!hepta_find_profile("lfm2moe")&&!hepta_find_profile("../LFM2.5-8B-A1B-Q4_0.gguf"));
    char *args[]={"runner","--model-profile","lfm2.5-8b-a1b-q4_0","--compute","npu",NULL};int argc=5;
    assert(hepta_take_model_profile(&argc,args)==0&&hepta_model_profile==profile&&argc==3&&args[3]==NULL);
    assert(!strcmp(args[1],"--compute")&&!strcmp(args[2],"npu"));
    char *duplicate[]={"runner","--model-profile","lfm2.5-8b-a1b-q4_0","--model-profile","lfm3-1.7b-qad-q4_0",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,duplicate)!=0);
    const HeptaModelProfile *legacy=hepta_find_profile("lfm3-1.7b-qad-q4_0");
    assert(legacy&&legacy->exact_tokens&&legacy->bytes==UINT64_C(1049615680));
    puts("PASS native MoE profile identity, uint64 size and unique argument selection; inference=false");
    return 0;
}
