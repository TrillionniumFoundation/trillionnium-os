#include <assert.h>
#include <stdio.h>
#include "../model-profile.h"
int main(void){
    assert(hepta_find_profile("minicpm5-2b-q4_k_m")->bytes==1561318368u);
    assert(!hepta_find_profile("llama"));assert(!hepta_find_profile(NULL));
    char *args[]={"runner","--model-profile","minicpm5-2b-q4_k_m","--compute","npu",NULL};int argc=5;
    assert(hepta_take_model_profile(&argc,args)==0&&argc==3&&!strcmp(args[1],"--compute")&&args[3]==NULL);
    assert(hepta_model_profile->exact_tokens);
    char *duplicate[]={"runner","--model-profile","lfm3-1.7b-qad-q4_0","--model-profile","minicpm5-2b-q4_k_m",NULL};argc=5;
    assert(hepta_take_model_profile(&argc,duplicate)!=0);
    puts("PASS closed profile allowlist and duplicate-safe argument consumption");return 0;
}
