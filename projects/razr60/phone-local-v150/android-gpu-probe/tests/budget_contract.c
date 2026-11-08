#define _GNU_SOURCE 1
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "vendor/geniex.h"
#include "vendor/llama/llama.h"
#include "vendor/llama/mtmd.h"
typedef struct {const char *id,*mode,*runtime,*compute,*vit,*model,*mmproj,*tokenizer,*prompt,*system,*grammar,*image,*result,*text;int ctx,max_tokens,threads,timeout_ms;geniex_LogLevel log_level;} Options;
typedef struct {const char *path;int fd;struct stat before;unsigned char *bytes;size_t size;char digest[65];} Input;
static void json_string(FILE *f,const char *v){if(v)fprintf(f,"\"%s\"",v);else fputs("null",f);}
static void *test_dlsym(void *handle,const char *name);
#define dlsym test_dlsym
#include "gpu-budget.inc"
#undef dlsym

static int assertions,model_loads,model_frees,mtmd_loads,mtmd_frees,bitmap_frees,chunks_frees;
static int32_t simulated_tokens=120,training_context=32768,tokenize_return;
static size_t max_alloc=((size_t)1<<30),chunk_counts[3]={100,256,20};
static const char *expected_prompt="preserve this owner exactly";
static const char *missing_symbol;
static enum mtmd_input_chunk_type chunk_types[3]={MTMD_INPUT_CHUNK_TYPE_TEXT,MTMD_INPUT_CHUNK_TYPE_IMAGE,MTMD_INPUT_CHUNK_TYPE_TEXT};
static unsigned char handles[8];
#define CHECK(condition) do{assertions++;if(!(condition)){fprintf(stderr,"CONTRACT FAILED line %d: %s\n",__LINE__,#condition);exit(1);}}while(0)
static struct llama_model_params mock_llama_model_default_params(void){struct llama_model_params p={0};return p;}
static struct llama_model *mock_llama_model_load_from_file(const char *path,struct llama_model_params p){CHECK(!strcmp(path,"model.gguf"));CHECK(p.vocab_only);CHECK(p.n_gpu_layers==0);CHECK(p.devices&&p.devices[0]&&!p.devices[1]);model_loads++;return (struct llama_model *)&handles[0];}
static void mock_llama_model_free(struct llama_model *m){CHECK(m==(struct llama_model *)&handles[0]);model_frees++;}
static const struct llama_vocab *mock_llama_model_get_vocab(const struct llama_model *m){CHECK(m!=(void *)0);return (struct llama_vocab *)&handles[1];}
static int32_t mock_llama_model_n_ctx_train(const struct llama_model *m){CHECK(m!=(void *)0);return training_context;}
static int32_t mock_llama_tokenize(const struct llama_vocab *v,const char *text,int32_t length,llama_token *out,int32_t count,bool add_special,bool parse_special){CHECK(v!=(void *)0);CHECK(!strcmp(text,expected_prompt));CHECK(length==(int32_t)strlen(expected_prompt));CHECK(!out&&count==0&&add_special&&parse_special);return simulated_tokens==INT32_MIN?INT32_MIN:-simulated_tokens;}
static ggml_backend_dev_t mock_ggml_backend_dev_by_name(const char *name){if(!strcmp(name,"CPU"))return (ggml_backend_dev_t)&handles[2];if(!strcmp(name,"GPUOpenCL"))return (ggml_backend_dev_t)&handles[3];return NULL;}
static const char *mock_ggml_backend_dev_name(ggml_backend_dev_t device){return device==(ggml_backend_dev_t)&handles[2]?"CPU":"GPUOpenCL";}
static ggml_backend_buffer_type_t mock_ggml_backend_dev_buffer_type(ggml_backend_dev_t d){CHECK(d!=(void *)0);return (ggml_backend_buffer_type_t)&handles[4];}
static size_t mock_ggml_backend_buft_get_max_size(ggml_backend_buffer_type_t b){CHECK(b!=(void *)0);return max_alloc;}
static struct mtmd_context_params observed_mtmd;
static struct mtmd_context_params mock_mtmd_context_params_default(void){struct mtmd_context_params p={0};p.warmup=true;p.image_min_tokens=-1;p.image_max_tokens=-1;return p;}
static mtmd_context *mock_mtmd_init_from_file(const char *path,const struct llama_model *m,const struct mtmd_context_params p){CHECK(!strcmp(path,"mmproj.gguf"));CHECK(m!=(void *)0);CHECK(!p.warmup&&!p.use_gpu&&!p.device);CHECK(p.flash_attn_type==LLAMA_FLASH_ATTN_TYPE_DISABLED);observed_mtmd=p;mtmd_loads++;return (mtmd_context *)&handles[5];}
static void mock_mtmd_free(mtmd_context *c){CHECK(c==(mtmd_context *)&handles[5]);mtmd_frees++;}
static mtmd_bitmap *mock_mtmd_bitmap_init(uint32_t w,uint32_t h,const unsigned char *data){CHECK(w==512&&h==512);CHECK(data==NULL);return (mtmd_bitmap *)&handles[6];}
static void mock_mtmd_bitmap_free(mtmd_bitmap *p){CHECK(p==(mtmd_bitmap *)&handles[6]);bitmap_frees++;}
static mtmd_input_chunks *mock_mtmd_input_chunks_init(void){return (mtmd_input_chunks *)&handles[7];}
static void mock_mtmd_input_chunks_free(mtmd_input_chunks *c){CHECK(c==(mtmd_input_chunks *)&handles[7]);chunks_frees++;}
static size_t mock_mtmd_input_chunks_size(const mtmd_input_chunks *c){CHECK(c!=(void *)0);return 3;}
static const mtmd_input_chunk *mock_mtmd_input_chunks_get(const mtmd_input_chunks *c,size_t i){CHECK(c!=(void *)0&&i<3);return (const mtmd_input_chunk *)&chunk_counts[i];}
static size_t mock_mtmd_input_chunk_get_n_tokens(const mtmd_input_chunk *c){return *(const size_t *)c;}
static enum mtmd_input_chunk_type mock_mtmd_input_chunk_get_type(const mtmd_input_chunk *c){return chunk_types[(const size_t *)c-chunk_counts];}
static int32_t mock_mtmd_tokenize(const mtmd_context *c,mtmd_input_chunks *out,const mtmd_input_text *t,const mtmd_bitmap *const *images,size_t n){CHECK(c&&out&&images&&n==1);CHECK(!strcmp(t->text,expected_prompt)&&t->text_len==strlen(expected_prompt));CHECK(t->add_special&&t->parse_special);return tokenize_return;}
#define SYMBOL(name) if(!strcmp(name_string,#name))return (void *)&mock_##name
static void *test_dlsym(void *handle,const char *name_string){(void)handle;if(missing_symbol&&!strcmp(missing_symbol,name_string))return NULL;
 SYMBOL(llama_model_default_params);SYMBOL(llama_model_load_from_file);SYMBOL(llama_model_free);SYMBOL(llama_model_get_vocab);SYMBOL(llama_model_n_ctx_train);SYMBOL(llama_tokenize);
 SYMBOL(ggml_backend_dev_by_name);SYMBOL(ggml_backend_dev_name);SYMBOL(ggml_backend_dev_buffer_type);SYMBOL(ggml_backend_buft_get_max_size);
 SYMBOL(mtmd_context_params_default);SYMBOL(mtmd_init_from_file);SYMBOL(mtmd_free);SYMBOL(mtmd_bitmap_init);SYMBOL(mtmd_bitmap_free);SYMBOL(mtmd_input_chunks_init);SYMBOL(mtmd_input_chunks_free);SYMBOL(mtmd_input_chunks_size);SYMBOL(mtmd_input_chunks_get);SYMBOL(mtmd_input_chunk_get_n_tokens);SYMBOL(mtmd_input_chunk_get_type);SYMBOL(mtmd_tokenize);return NULL;}
#undef SYMBOL
static void reset(void){memset(&gpu_budget,0,sizeof gpu_budget);model_loads=model_frees=mtmd_loads=mtmd_frees=bitmap_frees=chunks_frees=0;training_context=32768;simulated_tokens=120;tokenize_return=0;missing_symbol=NULL;max_alloc=(size_t)1<<30;chunk_counts[0]=100;chunk_counts[1]=256;chunk_counts[2]=20;chunk_types[1]=MTMD_INPUT_CHUNK_TYPE_IMAGE;}
static void balanced(void){CHECK(model_loads==model_frees);CHECK(mtmd_loads==mtmd_frees);CHECK(mtmd_loads==bitmap_frees);CHECK(mtmd_loads==chunks_frees);}
int main(void){
 Options text={.runtime="llama_cpp",.compute="gpu",.mode="llm",.model="model.gguf",.ctx=8192,.max_tokens=128,.threads=4};Input empty={0};size_t size=strlen(expected_prompt);
 reset();CHECK(gpu_count_input(&text,&empty,expected_prompt,size));CHECK(gpu_budget.input_tokens==120&&!gpu_budget.image_present&&gpu_budget.checked&&gpu_budget.admitted);balanced();
 geniex_ProfileData profile={.prompt_tokens=120};CHECK(gpu_check_profile(&profile));profile.prompt_tokens=119;CHECK(!gpu_check_profile(&profile));profile.prompt_tokens=121;CHECK(!gpu_check_profile(&profile));
 reset();simulated_tokens=8000;CHECK(gpu_count_input(&text,&empty,expected_prompt,size));CHECK(gpu_budget.input_tokens+text.max_tokens+64==8192);balanced();
 reset();simulated_tokens=8001;CHECK(!gpu_count_input(&text,&empty,expected_prompt,size));CHECK(gpu_budget.checked&&!gpu_budget.admitted&&!strcmp(gpu_budget.error,"input_budget_exceeds_context"));balanced();
 reset();simulated_tokens=INT32_MIN;CHECK(!gpu_count_input(&text,&empty,expected_prompt,size));balanced();
 reset();training_context=4096;CHECK(!gpu_count_input(&text,&empty,expected_prompt,size));balanced();
 reset();missing_symbol="llama_tokenize";CHECK(!gpu_count_input(&text,&empty,expected_prompt,size));CHECK(model_loads==0);
 reset();Options wrong=text;wrong.ctx=8193;CHECK(!gpu_count_input(&wrong,&empty,expected_prompt,size));CHECK(model_loads==0);
 reset();wrong=text;wrong.compute="cpu";CHECK(!gpu_count_input(&wrong,&empty,expected_prompt,size));CHECK(model_loads==0);
 unsigned char png[33]={137,80,78,71,13,10,26,10,0,0,0,13,'I','H','D','R',0,0,2,0,0,0,2,0};Input image={.bytes=png,.size=sizeof png};Options vlm=text;vlm.mode="vlm";vlm.vit="GPUOpenCL";vlm.mmproj="mmproj.gguf";vlm.image="image.png";
 reset();CHECK(gpu_count_input(&vlm,&image,expected_prompt,size));CHECK(gpu_budget.input_tokens==376&&gpu_budget.text_tokens==120&&gpu_budget.image_tokens==256);CHECK(observed_mtmd.image_min_tokens==-1&&observed_mtmd.image_max_tokens==1024&&gpu_budget.small_alloc_override);balanced();
 profile.prompt_tokens=376;CHECK(gpu_check_profile(&profile));char *json=NULL;size_t json_size=0;FILE *stream=open_memstream(&json,&json_size);CHECK(stream!=NULL);gpu_budget_json(stream);CHECK(fclose(stream)==0);CHECK(json_size>0&&strstr(json,"\"profile_exact_count_match\":true")&&strstr(json,"\"input_tokens\":376")&&strstr(json,"\"counter_placeholder_encode_called\":false"));free(json);
 reset();max_alloc=((size_t)1<<30)+1;CHECK(gpu_count_input(&vlm,&image,expected_prompt,size));CHECK(observed_mtmd.image_max_tokens==-1&&!gpu_budget.small_alloc_override);balanced();
 reset();vlm.vit="CPU";CHECK(gpu_count_input(&vlm,&image,expected_prompt,size));CHECK(observed_mtmd.image_max_tokens==-1&&!gpu_budget.small_alloc_override);balanced();vlm.vit="GPUOpenCL";
 reset();tokenize_return=2;CHECK(!gpu_count_input(&vlm,&image,expected_prompt,size));CHECK(!gpu_budget.checked&&!gpu_budget.admitted);balanced();
 reset();chunk_counts[1]=SIZE_MAX;CHECK(!gpu_count_input(&vlm,&image,expected_prompt,size));balanced();
 reset();chunk_types[1]=MTMD_INPUT_CHUNK_TYPE_AUDIO;CHECK(!gpu_count_input(&vlm,&image,expected_prompt,size));balanced();
 reset();png[16]=1;CHECK(!gpu_count_input(&vlm,&image,expected_prompt,size));CHECK(mtmd_loads==0);balanced();png[16]=0;
 reset();png[0]=0;CHECK(!gpu_count_input(&vlm,&image,expected_prompt,size));CHECK(mtmd_loads==0);balanced();
 printf("{\"schema\":\"hepta.gpu-budget.host-contract.v1\",\"assertions\":%d,\"backend_is_mocked\":true,\"actual_tokenizer_tested\":false,\"phone_or_gpu_qualified\":false,\"result\":\"passed\"}\n",assertions);
 return 0;
}
