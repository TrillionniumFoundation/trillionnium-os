#ifndef HEPTA_MODEL_PROFILE_H
#define HEPTA_MODEL_PROFILE_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define HEPTA_LLAMA_COMMIT "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
typedef struct {
    const char *id,*filename,*sha256,*architecture;
    uint64_t bytes;
    bool exact_tokens;
} HeptaModelProfile;
static const HeptaModelProfile hepta_profiles[]={
    {"lfm3-1.7b-qad-q4_0","LFM3-1.7B-QAD-Q4_0.gguf","43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452","lfm3",1049615680u,false},
    {"minicpm5-2b-q4_k_m","MiniCPM5-2B-Q4_K_M.gguf","ec2d5801640099e97d8d7e8003ad4d81f336e757811f03a26173dddf386602fd","llama",1561318368u,true},
    {"spark-x2.6-4b-q4_k_m","Spark-X2.6-4B-Q4_K_M.gguf","91cb2811aebb47ac916aa619d27d4cdd7f4143106b7917accb8ead4cd7f5cbd9","spark2_5",3543441312u,true},
    {"gemma4-e4b-qat-q4_0","gemma-4-E4B_q4_0-it.gguf","676c35070db6dbe52f93e9c864ee0fba4eddea94b9c875d9cb10daff453fbaee","gemma4",UINT64_C(5154941280),true},
    {"gemma4-e2b-qat-q4_0","gemma-4-E2B_q4_0-it.gguf","fa401b55b07ee70a54c6dae3903c783a6e65064312529ea57175cb5f8dec6634","gemma4",UINT64_C(3349516256),true},
    {"nemotron-3.5-bolt-e4b-q4_k_m","Nemotron-3.5-Bolt-E4B-Q4_K_M.gguf","c8af2b8aea10a690a1d9491db744a9446660173cb38fc489612b556615a69612","gemma4",UINT64_C(6180446208),true},
    {"lfm2.5-8b-a1b-q4_0","LFM2.5-8B-A1B-Q4_0.gguf","48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715","lfm2moe",UINT64_C(4844678368),true},
    {"qwen3.5-4b-q4_0","Qwen3.5-4B-Q4_0.gguf","298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb","qwen35",UINT64_C(2583221408),true},
    {"qwen3.5-9b-q4_0","Qwen3.5-9B-Q4_0.gguf","17670346b4260ddcb0173965145155885024f3c9a4a24389a3370751edbcde24","qwen35",UINT64_C(5379417312),true},
    {"bonsai2-9b-q2_0","Ternary-Bonsai-2-9B-Q2_0.gguf","1f884aa56aacd2bbbb2e4b7abaead2b1102b74a9c75a23fc33dab916813a384d","qwen35",UINT64_C(2556640128),true},
    {"orvena-4b-q4_k_m","Orvena-4B.Q4_K_M.gguf","c5d6df6e9a0828fa3068dfc6f6ca2ff6c4d950adc7e60e4b7202ece61595aa57","qwen35",UINT64_C(2783447904),true}
};
static const HeptaModelProfile *hepta_model_profile;
static const HeptaModelProfile *hepta_find_profile(const char *id){
    if(!id)return NULL;
    for(size_t i=0;i<sizeof(hepta_profiles)/sizeof(hepta_profiles[0]);i++)
        if(!strcmp(id,hepta_profiles[i].id))return &hepta_profiles[i];
    return NULL;
}
/* Consume exactly one explicit profile; never infer a model from a filename. */
static int hepta_take_model_profile(int *argc,char **argv){
    int found=0;
    for(int i=1;i<*argc;i++){
        if(strcmp(argv[i],"--model-profile"))continue;
        if(found||i+1>=*argc)return -1;
        hepta_model_profile=hepta_find_profile(argv[i+1]);if(!hepta_model_profile)return -1;
        found=1;
        for(int j=i;j+2<=*argc;j++)argv[j]=argv[j+2];
        *argc-=2;i--;
    }
    return found?0:-1;
}
#endif
