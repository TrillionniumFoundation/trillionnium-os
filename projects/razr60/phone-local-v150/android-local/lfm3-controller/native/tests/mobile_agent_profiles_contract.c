#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "model-profile.h"
int main(void){
 const HeptaModelProfile *a=hepta_find_profile("bonsai2-9b-q2_0"),*b=hepta_find_profile("orvena-4b-q4_k_m");
 assert(a&&b&&a!=b&&a->bytes==UINT64_C(2556640128)&&b->bytes==UINT64_C(2783447904));
 assert(a->bytes>INT32_MAX&&b->bytes>INT32_MAX&&a->exact_tokens&&b->exact_tokens);
 assert(!strcmp(a->architecture,"qwen35")&&!strcmp(b->architecture,"qwen35"));
 assert(strcmp(a->sha256,b->sha256)&&strcmp(a->filename,b->filename));
 assert(!hepta_find_profile("bonsai2")&&!hepta_find_profile("orvena"));
 char *args[]={"runner","--model-profile","bonsai2-9b-q2_0","--compute","npu",NULL};int argc=5;
 assert(hepta_take_model_profile(&argc,args)==0&&hepta_model_profile==a&&argc==3&&args[3]==NULL);
 char *other[]={"runner","--model-profile","orvena-4b-q4_k_m",NULL};argc=3;
 assert(hepta_take_model_profile(&argc,other)==0&&hepta_model_profile==b&&argc==1&&other[1]==NULL);
 char *twice[]={"runner","--model-profile","bonsai2-9b-q2_0","--model-profile","orvena-4b-q4_k_m",NULL};argc=5;
 assert(hepta_take_model_profile(&argc,twice)!=0);
 puts("PASS closed mobile profile identity and argv binding; inference=false");return 0;
}
