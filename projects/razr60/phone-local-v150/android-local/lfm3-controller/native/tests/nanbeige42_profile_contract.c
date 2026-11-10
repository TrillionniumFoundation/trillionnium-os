#include <assert.h>
#include <string.h>
#include "../model-profile.h"
int main(void){
    const HeptaModelProfile *p=hepta_find_profile("nanbeige4.2-3b-q4_k_m");
    assert(p&&p->exact_tokens&&p->bytes==UINT64_C(2684023968)&&p->bytes>INT32_MAX);
    assert(!strcmp(p->filename,"Nanbeige_Nanbeige4.2-3B-Q4_K_M.gguf"));
    assert(!strcmp(p->architecture,"nanbeige"));
    assert(!strcmp(p->sha256,"b92d2e35c9876b0c4bc671996360204f4149d0546c23d5954d5eb3b106c81f24"));
    assert(!hepta_find_profile("nanbeige")&&!hepta_find_profile("Nanbeige4.2-3B"));
    assert(!hepta_find_profile("../Nanbeige_Nanbeige4.2-3B-Q4_K_M.gguf")&&!hepta_find_profile(NULL));
    char *args[]={"runner","--model-profile","nanbeige4.2-3b-q4_k_m","--compute","npu",NULL};int argc=5;
    assert(hepta_take_model_profile(&argc,args)==0&&hepta_model_profile==p&&argc==3&&args[3]==NULL);
    assert(!strcmp(args[1],"--compute")&&!strcmp(args[2],"npu"));
    char *duplicate[]={"runner","--model-profile","nanbeige4.2-3b-q4_k_m","--model-profile","orvena-4b-q4_k_m",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,duplicate)!=0);
    char *missing[]={"runner","--model-profile",NULL};argc=2;assert(hepta_take_model_profile(&argc,missing)!=0);
    assert(!strcmp(hepta_profiles[0].id,"lfm3-1.7b-qad-q4_0")&&!hepta_profiles[0].exact_tokens);
    assert(sizeof(hepta_profiles)/sizeof(hepta_profiles[0])==12);
    return 0;
}
